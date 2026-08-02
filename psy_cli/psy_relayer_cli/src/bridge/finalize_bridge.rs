use std::{fs, path::PathBuf, str::FromStr};

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::{Context, Result};
use clap::Args;
use serde::Deserialize;
use tokio::time::{timeout, Duration};

use crate::bridge::constants::{
    DEFAULT_DEPLOYMENTS_NETWORK, DEFAULT_L1_RPC_URL, L1_TX_RECEIPT_TIMEOUT_SECS,
    L1_TX_SEND_TIMEOUT_SECS,
};
use crate::bridge::l1_provider::connect_l1_with_wallet;
use crate::bridge::l1_signer::load_l1_wallet;
sol! {
    function batchAppend(
        uint256[8] proof,
        uint256[] publicInputs,
        uint256[1312] slotData
    );
    function finalize(
        bytes proof,
        bytes32 depositTreeRoot,
        bytes32[2] checkpointRoots,
        bytes32 withdrawalTreeRoot,
        uint8 provenChainIndex,
        uint64 newCheckpointId,
        bytes32[9] depositMerkleProof,
        bytes32[9] withdrawalMerkleProof
    );
    function provedDepositCount() external view returns (uint256);
}

#[derive(Clone, Args)]
pub struct FinalizeBridgeAggArgs {
    #[arg(long)]
    pub proof_json: PathBuf,
    #[arg(long)]
    pub to_checkpoint: u64,
    #[arg(long, default_value = "config.json")]
    pub rpc_config: String,
    #[arg(long, default_value = DEFAULT_L1_RPC_URL)]
    pub l1_rpc_url: String,
    #[arg(long, default_value = DEFAULT_DEPLOYMENTS_NETWORK)]
    pub deployments_network: String,
    #[arg(long)]
    pub state_manager: Option<String>,
    #[arg(long)]
    pub bridge_address: Option<String>,
    #[arg(long)]
    pub batch_append_proof_json: Option<PathBuf>,
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
    #[arg(long, env = "KEYSTORE_PATH")]
    pub keystore_path: Option<PathBuf>,
    #[arg(long, env = "KEYSTORE_PASSWORD_ENV", default_value = "WALLET_PASSWORD")]
    pub password_env: String,
}

#[derive(Deserialize)]
struct ProveBridgeAggOutputJson {
    from_checkpoint: Option<u64>,
    to_checkpoint: Option<u64>,
    num_checkpoints_aggregated: Option<u64>,
    solidity_proof: [String; 8],
    checkpoint_roots: Vec<String>,
    deposit_tree_root: String,
    deposit_subtree_root: Option<String>,
    deposit_merkle_proof: Option<[String; 9]>,
    withdrawal_tree_root: String,
    withdrawal_subtree_root: Option<String>,
    withdrawal_merkle_proof: Option<[String; 9]>,
    #[serde(default)]
    l1_chain_index: Option<u8>,
}

async fn resolve_proven_chain_index<P: Provider>(
    proof_json: &ProveBridgeAggOutputJson,
    provider: &P,
    deployments_network: &str,
    state_manager: Address,
) -> Result<u8> {
    if let Some(index) = proof_json.l1_chain_index {
        return Ok(index);
    }
    crate::bridge::api_client::resolve_l1_chain_index(provider, deployments_network, state_manager).await
}

#[derive(Deserialize)]
struct DeployedContracts {
    core: std::collections::HashMap<String, String>,
    contracts: std::collections::HashMap<String, String>,
}

fn parse_b256(label: &str, s: &str) -> Result<B256> {
    B256::from_str(s).with_context(|| format!("invalid {}: {}", label, s))
}

fn resolve_contract_address(
    explicit: Option<&str>,
    deployments_network: &str,
    contract_name: &str,
    arg_label: &str,
) -> Result<Address> {
    if let Some(addr) = explicit {
        return Address::from_str(addr)
            .with_context(|| format!("invalid --{}: {}", arg_label, addr));
    }
    crate::bridge::api_client::resolve_contract_address_from_deployments(deployments_network, contract_name)
        .with_context(|| format!("failed to resolve {}", contract_name))
}

fn build_proof_bytes(solidity_proof: &[String; 8]) -> Result<Bytes> {
    let mut out = Vec::with_capacity(8 * 32);
    for (i, word) in solidity_proof.iter().enumerate() {
        let parsed = parse_b256(&format!("solidity_proof[{}]", i), word)?;
        out.extend_from_slice(parsed.as_slice());
    }
    Ok(Bytes::from(out))
}

fn parse_u256(label: &str, s: &str) -> Result<U256> {
    U256::from_str(s).with_context(|| format!("invalid {}: {}", label, s))
}

fn build_proof_words(solidity_proof: &[String; 8]) -> Result<[U256; 8]> {
    let mut out = [U256::ZERO; 8];
    for (i, word) in solidity_proof.iter().enumerate() {
        out[i] = parse_u256(&format!("solidity_proof[{i}]"), word)?;
    }
    Ok(out)
}

fn build_public_inputs(values: &[String]) -> Result<Vec<U256>> {
    values
        .iter()
        .enumerate()
        .map(|(i, value)| parse_u256(&format!("public_inputs[{i}]"), value))
        .collect()
}

fn build_slot_data(values: &[String]) -> Result<[U256; 1312]> {
    let words = values
        .iter()
        .enumerate()
        .map(|(i, value)| parse_u256(&format!("slot_data[{i}]"), value))
        .collect::<Result<Vec<_>>>()?;
    words
        .try_into()
        .map_err(|v: Vec<U256>| anyhow::anyhow!("invalid slot_data length: {}", v.len()))
}

fn checkpoint_roots_for_finalize(old_root: B256, new_root: B256) -> [B256; 2] {
    let mut roots = [B256::ZERO; 2];
    roots[0] = old_root;
    roots[1] = new_root;
    roots
}

fn parse_b256_array9(label: &str, values: &[String; 9]) -> Result<[B256; 9]> {
    let mut out = [B256::ZERO; 9];
    for (i, value) in values.iter().enumerate() {
        out[i] = parse_b256(&format!("{label}[{i}]"), value)?;
    }
    Ok(out)
}

fn zero_top_proof() -> [B256; 9] {
    [B256::ZERO; 9]
}

fn load_top_proof(
    label: &str,
    expected_root: B256,
    subtree_root: Option<String>,
    proof: Option<[String; 9]>,
) -> Result<(B256, [B256; 9])> {
    if expected_root == B256::ZERO {
        return Ok((B256::ZERO, zero_top_proof()));
    }

    let subtree_root = parse_b256(
        &format!("{label}_subtree_root"),
        subtree_root
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing {}_subtree_root in proof json", label))?,
    )?;
    let proof = parse_b256_array9(
        &format!("{label}_merkle_proof"),
        proof.as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing {}_merkle_proof in proof json", label))?,
    )?;
    Ok((subtree_root, proof))
}

pub async fn run(args: FinalizeBridgeAggArgs) -> Result<()> {
    let raw = fs::read_to_string(&args.proof_json)
        .with_context(|| format!("failed to read {}", args.proof_json.display()))?;
    let proof_json: ProveBridgeAggOutputJson = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", args.proof_json.display()))?;

    anyhow::ensure!(
        proof_json.checkpoint_roots.len() >= 2,
        "proof json must contain at least two checkpoint roots"
    );
    if let Some(proof_to_checkpoint) = proof_json.to_checkpoint {
        anyhow::ensure!(
            proof_to_checkpoint == args.to_checkpoint,
            "proof json to_checkpoint mismatch: args={} proof={}",
            args.to_checkpoint,
            proof_to_checkpoint
        );
    }
    if let Some(num_checkpoints_aggregated) = proof_json.num_checkpoints_aggregated {
        let expected = args
            .to_checkpoint
            .checked_sub(proof_json.from_checkpoint.unwrap_or(args.to_checkpoint))
            .map(|delta| delta + 1)
            .unwrap_or(1);
        anyhow::ensure!(
            num_checkpoints_aggregated == expected,
            "proof json num_checkpoints_aggregated mismatch: expected={} proof={}",
            expected,
            num_checkpoints_aggregated
        );
    }
    let old_checkpoint_root = parse_b256("checkpoint_roots[0]", &proof_json.checkpoint_roots[0])?;
    let new_checkpoint_root = parse_b256("checkpoint_roots[1]", &proof_json.checkpoint_roots[1])?;
    let deposit_tree_root = parse_b256("deposit_tree_root", &proof_json.deposit_tree_root)?;
    let withdrawal_tree_root = parse_b256("withdrawal_tree_root", &proof_json.withdrawal_tree_root)?;

    let state_manager = resolve_contract_address(
        args.state_manager.as_deref(),
        &args.deployments_network,
        "StateManager",
        "state-manager",
    )?;
    let bridge = resolve_contract_address(
        args.bridge_address.as_deref(),
        &args.deployments_network,
        "Bridge",
        "bridge-address",
    )?;
    let (deposit_subtree_root, deposit_merkle_proof) = load_top_proof(
        "deposit",
        deposit_tree_root,
        proof_json.deposit_subtree_root.clone(),
        proof_json.deposit_merkle_proof.clone(),
    )?;
    let (withdrawal_subtree_root, withdrawal_merkle_proof) = load_top_proof(
        "withdrawal",
        withdrawal_tree_root,
        proof_json.withdrawal_subtree_root.clone(),
        proof_json.withdrawal_merkle_proof.clone(),
    )?;

    let checkpoint_roots = checkpoint_roots_for_finalize(old_checkpoint_root, new_checkpoint_root);
    anyhow::ensure!(
        deposit_merkle_proof[0] == deposit_subtree_root,
        "deposit_merkle_proof[0] must equal deposit_subtree_root"
    );
    anyhow::ensure!(
        withdrawal_tree_root == B256::ZERO || withdrawal_merkle_proof[0] == withdrawal_subtree_root,
        "withdrawal_merkle_proof[0] must equal withdrawal_subtree_root"
    );
    let proof_bytes = build_proof_bytes(&proof_json.solidity_proof)?;

    let wallet = load_l1_wallet(
        args.private_key.as_deref(),
        args.keystore_path.as_deref(),
        Some(&args.password_env),
        None,
        "L1 finalize signer",
    )?;
    let rpc_url = args
        .l1_rpc_url
        .parse()
        .with_context(|| format!("invalid L1 rpc url: {}", args.l1_rpc_url))?;
    let provider = connect_l1_with_wallet(rpc_url, wallet)?;
    tracing::info!(
        state_manager = %state_manager,
        bridge = %bridge,
        to_checkpoint = args.to_checkpoint,
        "bridge finalize starting"
    );
    let proven_chain_index =
        resolve_proven_chain_index(&proof_json, &provider, &args.deployments_network, state_manager).await?;
    let on_chain_l1_chain_index =
        crate::bridge::api_client::resolve_l1_chain_index(&provider, &args.deployments_network, state_manager).await?;
    anyhow::ensure!(
        proven_chain_index == on_chain_l1_chain_index,
        "proven l1_chain_index mismatch: proof={} state_manager={}",
        proven_chain_index,
        on_chain_l1_chain_index
    );

    anyhow::ensure!(
        args.batch_append_proof_json.is_none(),
        "manual batch append finalize via proof json is no longer supported; use the bridge daemon path that ABI-encodes slotData directly"
    );

    let call = finalizeCall {
        proof: proof_bytes.clone(),
        depositTreeRoot: deposit_tree_root,
        checkpointRoots: checkpoint_roots,
        withdrawalTreeRoot: withdrawal_tree_root,
        provenChainIndex: proven_chain_index,
        newCheckpointId: args.to_checkpoint,
        depositMerkleProof: deposit_merkle_proof,
        withdrawalMerkleProof: withdrawal_merkle_proof,
    };

    let tx = TransactionRequest::default()
        .to(state_manager)
        .input(call.abi_encode().into());
    tracing::info!(
        state_manager = %state_manager,
        bridge = %bridge,
        proven_chain_index,
        "sending finalize transaction"
    );
    let pending = timeout(
        Duration::from_secs(L1_TX_SEND_TIMEOUT_SECS),
        provider.send_transaction(tx),
    )
    .await
    .context("send finalize transaction timed out")?
    .context("send finalize transaction failed")?;
    tracing::info!(
        tx_hash = %pending.tx_hash(),
        "finalize transaction submitted; waiting for receipt"
    );
    let receipt = timeout(
        Duration::from_secs(L1_TX_RECEIPT_TIMEOUT_SECS),
        pending.get_receipt(),
    )
    .await
    .context("wait finalize receipt timed out")?
    .context("wait finalize receipt failed")?;
    anyhow::ensure!(
        receipt.status(),
        "finalize transaction reverted: tx_hash={}",
        receipt.transaction_hash
    );

    tracing::info!(
        "bridge finalized: state_manager={} bridge={} tx_hash={} block_number={:?}",
        state_manager,
        bridge,
        receipt.transaction_hash,
        receipt.block_number
    );
    Ok(())
}
