use std::{collections::HashMap, fs, path::{Path, PathBuf}, str::FromStr};

use alloy_primitives::{Address, Bytes, U256, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::{Context, Result};
use clap::Args;
use parth_core::pgoldilocks::QHashOut;
use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    hash::hash_types::HashOut,
    plonk::config::PoseidonGoldilocksConfig,
};
use psy_plonky2_circuits::bridge::circuits::bridge_wrap::WithdrawalClaimWrapCircuit;
use psy_plonky2_common_circuits::bridge::withdrawal_batch_claim_circuit::{
    WithdrawalBatchClaimCircuit, WithdrawalBatchClaimInputs, WithdrawalBatchClaimSlotInputs,
    MAX_WITHDRAWAL_CLAIM_BATCH_SIZE, WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
    WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS,
};
use serde::Deserialize;
use tokio::time::{timeout, Duration};

use crate::bridge::api_client::{ApiResponse, DeployedContracts, build_default_http_client, get_services_json, resolve_contract_address_from_deployments};
use crate::bridge::prove_proxy_client::{BridgeWithdrawalBatchWitnessInput, BridgeWithdrawalWitnessInput as ProxyWithdrawalWitnessInput, ProveProxyClient};
use crate::bridge::constants::{
    BRIDGE_USER_ID_U32, DEFAULT_L1_RPC_URL, L1_GROTH16_CALL_GAS_FALLBACK,
    L1_TX_RECEIPT_TIMEOUT_SECS, L1_TX_SEND_TIMEOUT_SECS, MAX_CONCURRENT_PROXY_PROOFS,
};
use crate::bridge::l1_provider::connect_l1_with_wallet;
use crate::bridge::l1_signer::load_l1_wallet;
use crate::bridge::propose_withdrawals::PendingWithdrawal;

type C = PoseidonGoldilocksConfig;
type F = GoldilocksField;

sol! {
    function batchClaimWithdrawal(
        uint256[8] proof,
        uint256[18] publicInputs,
        uint256[832] slotData
    );

    function claimedNullifiers(bytes32 nullifier) view returns (bool);

    function balanceOf(address account) view returns (uint256);
}

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofResult {
    pub found: bool,
    pub leaf_index: Option<u32>,
    pub withdrawal_root: Option<String>,
    pub siblings: Option<Vec<String>>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchWithdrawalsReport {
    pub requested: usize,
    pub submitted_count: usize,
    pub already_claimed_count: usize,
    #[serde(default)]
    pub resolved_leaf_hashes: Vec<String>,
    #[serde(default)]
    pub failure_reasons: HashMap<String, String>,
}

#[derive(Clone, Args)]
pub struct BatchWithdrawalsArgs {
    #[arg(long)]
    pub input_json: PathBuf,
    #[arg(long)]
    pub services_url: String,
    #[arg(long, default_value = DEFAULT_L1_RPC_URL)]
    pub l1_rpc_url: String,
    #[arg(long)]
    pub bridge_address: String,
    #[arg(long)]
    pub multicall3_address: Option<String>,
    #[arg(long, default_value = crate::bridge::constants::DEFAULT_DEPLOYMENTS_NETWORK)]
    pub deployments_network: String,
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
    #[arg(long, env = "KEYSTORE_PATH")]
    pub keystore_path: Option<PathBuf>,
    #[arg(long, env = "KEYSTORE_PASSWORD_ENV", default_value = "WALLET_PASSWORD")]
    pub password_env: String,
}

fn parse_solidity_qhash(hex: &str) -> anyhow::Result<QHashOut<F>> {
    let hex = hex.trim_start_matches("0x");
    anyhow::ensure!(hex.len() == 64, "expected 64 hex chars, got {}", hex.len());
    let bytes = hex::decode(hex)?;
    let mut elems = [0u64; 4];
    for i in 0..4 {
        let reverse_i = 3 - i;
        let hi = u32::from_be_bytes(bytes[reverse_i * 8..reverse_i * 8 + 4].try_into()?);
        let lo = u32::from_be_bytes(bytes[reverse_i * 8 + 4..reverse_i * 8 + 8].try_into()?);
        elems[i] = ((hi as u64) << 32) | (lo as u64);
    }
    Ok(QHashOut(HashOut {
        elements: elems.map(F::from_canonical_u64),
    }))
}

fn u32x8_to_hex(words: [u32; 8]) -> String {
    let mut b = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    format!("0x{}", hex::encode(b))
}

fn u32x8_to_address(words: [u32; 8]) -> Address {
    let mut b = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    Address::from_slice(&b[12..32])
}

fn u32x8_to_u256(words: [u32; 8]) -> U256 {
    let mut b = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        b[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    U256::from_be_slice(&b)
}

fn address_high_bits_are_zero(words: [u32; 8]) -> bool {
    words[0] == 0 && words[1] == 0 && words[2] == 0
}

const CLAIM_PROOF_FETCH_MAX_ATTEMPTS: usize = 12;
const CLAIM_PROOF_FETCH_RETRY_DELAY_SECS: u64 = 5;

async fn fetch_claim_proof(
    http: &reqwest::Client,
    services_url: &str,
    withdrawal: &PendingWithdrawal,
) -> Result<WithdrawalClaimProofResult> {
    let recipient_hex = u32x8_to_hex(withdrawal.recipient);
    let token_hex = u32x8_to_hex(withdrawal.token_address);
    let amount_hex = u32x8_to_hex(withdrawal.amount);

    let url = format!(
        "{}/api/v1/bridge/withdrawal-claim-proof?recipient={}&token_address={}&amount={}&nonce={}&destination_chain_id={}",
        services_url.trim_end_matches('/'),
        recipient_hex,
        token_hex,
        amount_hex,
        withdrawal.nonce,
        withdrawal.destination_chain_id,
    );
    tracing::debug!(url = %url, "fetching withdrawal claim proof");

    let resp: ApiResponse<WithdrawalClaimProofResult> =
        get_services_json(http, &url, "withdrawal_claim_proof").await?;

    if !resp.success {
        anyhow::bail!("psy-services error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
    }
    resp.data.ok_or_else(|| anyhow::anyhow!("psy-services returned success but no data"))
}

/// Normalize L1 withdrawalSubtreeRoot (big-endian bytes32, u32 words MSB-first)
/// to the services u32x8 little-endian word order (LSB-first) for comparison.
///
/// L1 stores the 8 × u32 limbs as bytes32 with word 7 (most significant) first.
/// psy-services returns the same 8 limbs with word 0 (least significant) first.
/// The two formats differ only by word-order reversal.
pub(crate) fn normalize_l1_root_for_services(l1_hex: &str) -> String {
    let raw = l1_hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.len() != 64 {
        return l1_hex.to_string();
    }
    // Split into 8 × 8-char u32 words, emit in reverse order
    let mut out = String::with_capacity(66);
    out.push_str("0x");
    for i in (0..64).step_by(8).rev() {
        out.push_str(&raw[i..i + 8]);
    }
    out
}

async fn read_l1_withdrawal_subtree_root<P: Provider>(provider: &P, state_manager: Address) -> Result<String> {
    let raw = provider.call(
        TransactionRequest::default()
            .to(state_manager)
            .input(alloy_primitives::Bytes::from(hex::decode("7cd34bf4").unwrap()).into()),
    ).await?;
    anyhow::ensure!(raw.len() >= 32, "withdrawalSubtreeRoot returned {} bytes", raw.len());
    Ok(format!("0x{}", hex::encode(&raw[..32])))
}

async fn withdrawal_already_claimed<P: Provider>(
    provider: &P,
    bridge: Address,
    withdrawal: &PendingWithdrawal,
) -> Result<bool> {
    let nonce_u32 = u32::try_from(withdrawal.nonce)
        .with_context(|| format!("withdrawal nonce {} exceeds uint32 bridge encoding", withdrawal.nonce))?;
    let dest_chain_u32 = u32::try_from(withdrawal.destination_chain_id).with_context(|| {
        format!(
            "withdrawal destination_chain_id {} exceeds uint32 bridge encoding",
            withdrawal.destination_chain_id
        )
    })?;
    let mut leaf_preimage = Vec::with_capacity(32 + 32 + 32 + 4 + 4);
    for word in withdrawal.recipient {
        leaf_preimage.extend_from_slice(&word.to_be_bytes());
    }
    for word in withdrawal.token_address {
        leaf_preimage.extend_from_slice(&word.to_be_bytes());
    }
    for word in withdrawal.amount {
        leaf_preimage.extend_from_slice(&word.to_be_bytes());
    }
    leaf_preimage.extend_from_slice(&nonce_u32.to_be_bytes());
    leaf_preimage.extend_from_slice(&dest_chain_u32.to_be_bytes());
    let nullifier = keccak256(leaf_preimage);
    let call = claimedNullifiersCall { nullifier };
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("claimedNullifiers eth_call failed")?;
    claimedNullifiersCall::abi_decode_returns(&raw).context("failed to decode claimedNullifiers return")
}

async fn erc20_balance_of<P: Provider>(provider: &P, token: Address, owner: Address) -> Result<U256> {
    let call = balanceOfCall { account: owner };
    let tx = TransactionRequest::default().to(token).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("ERC20 balanceOf eth_call failed")?;
    balanceOfCall::abi_decode_returns(&raw).context("failed to decode ERC20 balanceOf return")
}

pub(crate) fn resolve_multicall3_address(
    explicit: Option<&str>,
    deployments_network: &str,
) -> Result<Option<Address>> {
    if let Some(addr) = explicit {
        let parsed = Address::from_str(addr)
            .with_context(|| format!("invalid multicall3 address: {}", addr))?;
        return Ok(Some(parsed));
    }

    let path = PathBuf::from(format!(
        "psy-contracts/deployments/{}/deployed-contracts.json",
        deployments_network
    ));
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    let deployed: DeployedContracts = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let resolved_from_summary = deployed
        .core
        .get("Multicall3")
        .or_else(|| deployed.contracts.get("Multicall3"))
        .cloned();

    if let Some(addr) = resolved_from_summary {
        let parsed = Address::from_str(&addr)
            .with_context(|| format!("invalid Multicall3 address in {}: {}", path.display(), addr))?;
        return Ok(Some(parsed));
    }

    // Fallback: read the hardhat-deploy artifact directly when summary is stale/incomplete.
    let multicall_artifact_path = PathBuf::from(format!(
        "psy-contracts/deployments/{}/Multicall3.json",
        deployments_network
    ));
    let artifact_raw = match fs::read_to_string(&multicall_artifact_path) {
        Ok(raw) => raw,
        Err(_) => return Ok(None),
    };
    #[derive(serde::Deserialize)]
    struct AddressArtifact {
        address: String,
    }
    let artifact: AddressArtifact = serde_json::from_str(&artifact_raw)
        .with_context(|| format!("failed to parse {}", multicall_artifact_path.display()))?;
    let parsed = Address::from_str(&artifact.address).with_context(|| {
        format!(
            "invalid Multicall3 address in {}: {}",
            multicall_artifact_path.display(),
            artifact.address
        )
    })?;
    Ok(Some(parsed))
}

#[derive(Clone)]
struct PendingProof {
    index: usize,
    withdrawal: PendingWithdrawal,
    leaf_index: u32,
    withdrawal_root: QHashOut<F>,
    siblings: Vec<QHashOut<F>>,
}

async fn generate_withdrawal_batch_proof(batch: &[PendingProof], proxy_client: Option<&ProveProxyClient>) -> anyhow::Result<Bytes> {
    anyhow::ensure!(!batch.is_empty(), "empty withdrawal batch");
    anyhow::ensure!(batch.len() <= MAX_WITHDRAWAL_CLAIM_BATCH_SIZE, "withdrawal batch exceeds 32 slots");

    let root = batch[0].withdrawal_root;

    // ── Remote Prove Proxy path (disabled via never-true constant) ──
    if let Some(client) = proxy_client {
        let withdrawals = batch.iter().map(|p| {
            let nonce_u32 = u32::try_from(p.withdrawal.nonce)
                .map_err(|_| anyhow::anyhow!("withdrawal nonce {} exceeds u32", p.withdrawal.nonce))?;
            let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_id)
                .map_err(|_| anyhow::anyhow!(
                    "destination_chain_id {} exceeds u32",
                    p.withdrawal.destination_chain_id
                ))?;
            Ok::<_, anyhow::Error>(ProxyWithdrawalWitnessInput {
                withdrawal_root: qhash_to_solidity_hex(p.withdrawal_root),
                recipient: p.withdrawal.recipient,
                token: p.withdrawal.token_address,
                amount: p.withdrawal.amount,
                nonce: nonce_u32,
                dest_chain_id: dest_chain_u32,
                leaf_index: p.leaf_index,
                bridge_user_id: BRIDGE_USER_ID_U32,
                siblings: p.siblings.iter().map(|s| {
                    qhash_to_solidity_hex(*s)
                }).collect(),
            })
        }).collect::<anyhow::Result<Vec<_>>>()?;
        let input = BridgeWithdrawalBatchWitnessInput {
            bridge_user_id: BRIDGE_USER_ID_U32,
            withdrawals,
        };
        let proof = client.prove_withdrawal_batch_claim_groth16(input).await?;
        let mut proof_u256 = [U256::ZERO; 8];
        for (j, s) in proof.solidity_proof.iter().enumerate() {
            proof_u256[j] = U256::from_str_radix(s.trim_start_matches("0x"), 16)
                .with_context(|| format!("invalid proof[{}]: {}", j, s))?;
        }
        anyhow::ensure!(
            proof.public_inputs.len() == WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
            "expected {} public inputs, got {}",
            WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
            proof.public_inputs.len()
        );
        let mut pi_u256 = [U256::ZERO; WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS];
        for (j, &v) in proof.public_inputs.iter().enumerate() {
            pi_u256[j] = U256::from(v);
        }
        let mut slot_data_u256 = [U256::ZERO; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS];
        for (slot_index, p) in batch.iter().enumerate() {
            let slot_offset = slot_index * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
            for (j, word) in p.withdrawal.recipient.iter().enumerate() {
                slot_data_u256[slot_offset + j] = U256::from(*word);
            }
            for (j, word) in p.withdrawal.token_address.iter().enumerate() {
                slot_data_u256[slot_offset + 8 + j] = U256::from(*word);
            }
            for (j, word) in p.withdrawal.amount.iter().enumerate() {
                slot_data_u256[slot_offset + 16 + j] = U256::from(*word);
            }
            let nonce_u32 = u32::try_from(p.withdrawal.nonce)
                .map_err(|_| anyhow::anyhow!("withdrawal nonce {} exceeds u32", p.withdrawal.nonce))?;
            let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_id)
                .map_err(|_| anyhow::anyhow!("destination_chain_id {} exceeds u32", p.withdrawal.destination_chain_id))?;
            slot_data_u256[slot_offset + 24] = U256::from(nonce_u32);
            slot_data_u256[slot_offset + 25] = U256::from(dest_chain_u32);
        }
        // ── Debug: batch commit verification ──
        {
            let mut slot_bytes = Vec::with_capacity(slot_data_u256.len() * 4);
            for &g in &slot_data_u256 {
                let be: [u8; 32] = g.to_be_bytes();
                slot_bytes.extend_from_slice(&be[28..32]);
            }
            let c_keccak = keccak256(&slot_bytes);
            let mut pi_10_17: Vec<u64> = Vec::new();
            for &v in proof.public_inputs[10..18].iter() { pi_10_17.push(v); }
            let mut pk_bytes = [0u8; 32];
            for (i, &v) in proof.public_inputs[10..18].iter().enumerate() {
                pk_bytes[i*4..(i+1)*4].copy_from_slice(&(v as u32).to_be_bytes());
            }
            let p_commit = alloy_primitives::B256::from(pk_bytes);
            let s0: Vec<u64> = proof.slot_data.iter().take(26).copied().collect();
            tracing::debug!(
                pi10_17 = ?pi_10_17,
                slot0 = ?s0,
                computed_keccak = %c_keccak,
                proof_commit = %p_commit,
                match_ = %(c_keccak == p_commit),
                "proxy batchCommit debug"
            );
        }
        let call = batchClaimWithdrawalCall {
            proof: proof_u256,
            publicInputs: pi_u256,
            slotData: slot_data_u256,
        };
        return Ok(Bytes::from(call.abi_encode()));
    }

    // ── Local proof generation (fallback) ────────────────────────────
    let inputs = WithdrawalBatchClaimInputs::<F> {
        withdrawal_root: root,
        bridge_user_id: BRIDGE_USER_ID_U32,
        withdrawals: batch
            .iter()
            .map(|p| {
                let nonce_u32 = u32::try_from(p.withdrawal.nonce)
                    .map_err(|_| anyhow::anyhow!("withdrawal nonce {} exceeds u32", p.withdrawal.nonce))?;
                let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_id).map_err(|_| {
                    anyhow::anyhow!("destination_chain_id {} exceeds u32", p.withdrawal.destination_chain_id)
                })?;
                Ok::<_, anyhow::Error>(WithdrawalBatchClaimSlotInputs::<F> {
                    recipient: p.withdrawal.recipient,
                    token: p.withdrawal.token_address,
                    amount: p.withdrawal.amount,
                    nonce: nonce_u32,
                    dest_chain_id: dest_chain_u32,
                    leaf_index: p.leaf_index,
                    siblings: p.siblings.clone(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?,
    };

    let circuit = WithdrawalBatchClaimCircuit::<C, 2>::build(32);
    let proof = circuit
        .generate_proof(&inputs)
        .map_err(|e| anyhow::anyhow!("withdrawal claim proof generation failed: {:?}", e))?;
    let fingerprint = QHashOut(psy_plonky2_circuits::proof_minifier::pm_core::get_circuit_fingerprint_generic(
        &circuit.circuit_data.verifier_only,
    ));
    let wrap_circuit = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    );
    let groth16_wrapper = WithdrawalClaimWrapCircuit::new(
        &circuit.circuit_data.common,
        fingerprint,
        circuit.circuit_data.verifier_only.constants_sigmas_cap.height(),
    )
    .into_shared_groth16_wrapper(format!("{}/.psy/keystore/withdrawal_claim/", home::home_dir().unwrap().display()));
    let groth16 = wrap_circuit.prove_groth16_with_shared_wrapper(&groth16_wrapper, &circuit.circuit_data.verifier_only, &proof)
        .map_err(|e| anyhow::anyhow!("withdrawal claim G16 wrapping failed: {:?}", e))?;

    let with_0x = |s: &str| -> String {
        if s.starts_with("0x") { s.to_string() } else { format!("0x{}", s) }
    };
    let proof_strs = [
        with_0x(&groth16.pi_a[0]),
        with_0x(&groth16.pi_a[1]),
        with_0x(&groth16.pi_b[0][1]),
        with_0x(&groth16.pi_b[0][0]),
        with_0x(&groth16.pi_b[1][1]),
        with_0x(&groth16.pi_b[1][0]),
        with_0x(&groth16.pi_c[0]),
        with_0x(&groth16.pi_c[1]),
    ];
    let mut proof_u256 = [U256::ZERO; 8];
    for (j, s) in proof_strs.iter().enumerate() {
        proof_u256[j] = U256::from_str_radix(s.trim_start_matches("0x"), 16)
            .with_context(|| format!("invalid proof[{}]: {}", j, s))?;
    }

    let public_inputs: Vec<u64> = proof.public_inputs.iter().map(|x| x.to_noncanonical_u64()).collect();
    anyhow::ensure!(
        public_inputs.len() == WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
        "expected {} public inputs, got {}",
        WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS,
        public_inputs.len()
    );
    let mut pi_u256 = [U256::ZERO; WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS];
    for (j, &v) in public_inputs.iter().enumerate() {
        pi_u256[j] = U256::from(v);
    }

    let mut slot_data_u256 =
        [U256::ZERO; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS];
    for (slot_index, pending) in batch.iter().enumerate() {
        let slot_offset = slot_index * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
        for (j, word) in pending.withdrawal.recipient.iter().enumerate() {
            slot_data_u256[slot_offset + j] = U256::from(*word);
        }
        for (j, word) in pending.withdrawal.token_address.iter().enumerate() {
            slot_data_u256[slot_offset + 8 + j] = U256::from(*word);
        }
        for (j, word) in pending.withdrawal.amount.iter().enumerate() {
            slot_data_u256[slot_offset + 16 + j] = U256::from(*word);
        }
        let nonce_u32 = u32::try_from(pending.withdrawal.nonce)
            .map_err(|_| anyhow::anyhow!("withdrawal nonce {} exceeds u32", pending.withdrawal.nonce))?;
        let dest_chain_u32 = u32::try_from(pending.withdrawal.destination_chain_id)
            .map_err(|_| anyhow::anyhow!("destination_chain_id {} exceeds u32", pending.withdrawal.destination_chain_id))?;
        slot_data_u256[slot_offset + 24] = U256::from(nonce_u32);
        slot_data_u256[slot_offset + 25] = U256::from(dest_chain_u32);
    }

    let call = batchClaimWithdrawalCall {
        proof: proof_u256,
        publicInputs: pi_u256,
        slotData: slot_data_u256,
    };
    Ok(Bytes::from(call.abi_encode()))
}

pub async fn submit_batch(
    withdrawals: &[PendingWithdrawal],
    services_url: &str,
    l1_rpc_url: &str,
    bridge_address: &str,
    multicall3_address: Option<&str>,
    deployments_network: &str,
    private_key: Option<&str>,
    keystore_path: Option<&Path>,
    password_env: &str,
    prove_proxy_url: Option<&str>,
) -> Result<BatchWithdrawalsReport> {
    let _phantom_c: std::marker::PhantomData<C> = std::marker::PhantomData;
    if withdrawals.is_empty() {
        return Ok(BatchWithdrawalsReport {
            requested: 0,
            submitted_count: 0,
            already_claimed_count: 0,
            resolved_leaf_hashes: Vec::new(),
            failure_reasons: HashMap::new(),
        });
    }

    tracing::info!(withdrawal_count = withdrawals.len(), "submitting withdrawal batch via G16 proofs");

    let bridge = Address::from_str(bridge_address)
        .with_context(|| format!("invalid bridge address: {}", bridge_address))?;
    let wallet = load_l1_wallet(
        private_key,
        keystore_path,
        Some(password_env),
        None,
        "L1 claim signer",
    )?;
    let rpc_url = l1_rpc_url
        .parse()
        .with_context(|| format!("invalid L1 rpc url: {}", l1_rpc_url))?;
    let provider = connect_l1_with_wallet(rpc_url, wallet)?;
    let http = build_default_http_client()?;

    let mut submitted_count = 0usize;
    let mut already_claimed_count = 0usize;
    let mut resolved_leaf_hashes = Vec::new();
    let mut failure_reasons = HashMap::new();
    let mut bridge_erc20_liquidity_remaining: HashMap<Address, U256> = HashMap::new();
    if multicall3_address.is_some() || !deployments_network.is_empty() {
        let _ = (multicall3_address, deployments_network);
    }

    // Phase 1: validate and fetch claim proofs.
    let mut pending_proofs: Vec<PendingProof> = Vec::new();
    for (i, w) in withdrawals.iter().enumerate() {
        let recipient_addr = u32x8_to_address(w.recipient);
        if !address_high_bits_are_zero(w.recipient) {
            tracing::warn!(
                index = i,
                recipient = %recipient_addr,
                recipient_words = ?w.recipient,
                "withdrawal recipient has non-zero high bits, skipping"
            );
            failure_reasons.insert(w.leaf_hash.clone(), "withdrawal recipient has non-zero high bits".to_string());
            continue;
        }
        if !address_high_bits_are_zero(w.token_address) {
            tracing::warn!(
                index = i,
                token_words = ?w.token_address,
                "withdrawal token address has non-zero high bits, skipping"
            );
            failure_reasons.insert(w.leaf_hash.clone(), "withdrawal token address has non-zero high bits".to_string());
            continue;
        }

        let state_manager: Address = resolve_contract_address_from_deployments(&deployments_network, "StateManager")
            .context("failed to resolve StateManager address from deployments")?;

        match withdrawal_already_claimed(&provider, bridge, w).await {
            Ok(true) => {
                tracing::info!(
                    index = i,
                    recipient = %recipient_addr,
                    leaf_hash = %w.leaf_hash,
                    "withdrawal already claimed on L1; counting as covered"
                );
                already_claimed_count += 1;
                resolved_leaf_hashes.push(w.leaf_hash.clone());
                continue;
            }
            Ok(false) => {}
            Err(err) => {
                failure_reasons.insert(w.leaf_hash.clone(), format!("claimed nullifier check failed: {err}"));
                tracing::error!(
                    index = i,
                    recipient = %recipient_addr,
                    error = %err,
                    "failed to check claimed nullifier, skipping"
                );
                continue;
            }
        }

        let token_addr = u32x8_to_address(w.token_address);
        let amount = u32x8_to_u256(w.amount);
        if amount == U256::ZERO {
            failure_reasons.insert(w.leaf_hash.clone(), "withdrawal amount is zero".to_string());
            tracing::warn!(
                index = i,
                recipient = %recipient_addr,
                leaf_hash = %w.leaf_hash,
                "withdrawal amount is zero, skipping"
            );
            continue;
        }
        tracing::debug!(
            index = i,
            token_addr = %token_addr,
            token_words = ?w.token_address,
            leaf_hash = %w.leaf_hash,
            "claim liquidity check"
        );
        if token_addr != Address::ZERO {
            if !bridge_erc20_liquidity_remaining.contains_key(&token_addr) {
                let balance = erc20_balance_of(&provider, token_addr, bridge)
                    .await
                    .with_context(|| format!("failed to read bridge ERC20 liquidity for token {token_addr}"))?;
                bridge_erc20_liquidity_remaining.insert(token_addr, balance);
            }
            let remaining = bridge_erc20_liquidity_remaining
                .get_mut(&token_addr)
                .expect("bridge liquidity inserted above");
            if *remaining < amount {
                let reason = format!(
                    "bridge ERC20 liquidity insufficient for token {token_addr}: available={}, required={}",
                    *remaining, amount
                );
                failure_reasons.insert(w.leaf_hash.clone(), reason);
                tracing::warn!(
                    index = i,
                    recipient = %recipient_addr,
                    token = %token_addr,
                    available = %*remaining,
                    required = %amount,
                    leaf_hash = %w.leaf_hash,
                    "bridge ERC20 liquidity insufficient; deferring withdrawal claim"
                );
                continue;
            }
            *remaining -= amount;
            // NOTE: this deduction is not rolled back if the batch later fails
            // (reverted/timed out). Per-chunk rollback would be more precise but
            // the on-chain liquidity check provides the authoritative guard.
        }

        let proof_result = {
            let mut last_err: Option<anyhow::Error> = None;
            let mut final_result: Option<WithdrawalClaimProofResult> = None;
            for attempt in 1..=CLAIM_PROOF_FETCH_MAX_ATTEMPTS {
                match fetch_claim_proof(&http, services_url, w).await {
                    Ok(r) => {
                        if !r.found {
                            tracing::debug!(
                                index = i,
                                attempt,
                                max_attempts = CLAIM_PROOF_FETCH_MAX_ATTEMPTS,
                                retry_delay_secs = CLAIM_PROOF_FETCH_RETRY_DELAY_SECS,
                                recipient = %recipient_addr,
                                "withdrawal claim proof not ready yet; will retry"
                            );
                        } else if let Some(ref root_hex) = r.withdrawal_root {
                            match read_l1_withdrawal_subtree_root(&provider, state_manager).await {
                                Ok(l1_root) => {
                                    let normalized_l1 = normalize_l1_root_for_services(&l1_root);
                                    let root_match = normalized_l1.trim_start_matches("0x").eq_ignore_ascii_case(
                                        root_hex.trim_start_matches("0x")
                                    );
                                    tracing::debug!(
                                        services_root = %root_hex,
                                        l1_root = %l1_root,
                                        root_match,
                                        attempt,
                                        max_attempts = CLAIM_PROOF_FETCH_MAX_ATTEMPTS,
                                        retry_delay_secs = CLAIM_PROOF_FETCH_RETRY_DELAY_SECS,
                                        "claim proof root comparison"
                                    );
                                    if root_match {
                                        final_result = Some(r);
                                        break;
                                    }
                                    final_result = Some(r);
                                }
                                Err(err) => {
                                    last_err = Some(err.context("read L1 withdrawalSubtreeRoot failed"));
                                }
                            }
                        } else {
                            final_result = Some(r);
                            break;
                        }
                    }
                    Err(err) => {
                        last_err = Some(err);
                    }
                }
                if attempt < CLAIM_PROOF_FETCH_MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(CLAIM_PROOF_FETCH_RETRY_DELAY_SECS)).await;
                }
            }
            if let Some(r) = final_result {
                r
            } else {
                let err = last_err.unwrap_or_else(|| anyhow::anyhow!("claim proof fetch exhausted without response"));
                failure_reasons.insert(w.leaf_hash.clone(), format!("fetch claim proof failed: {err}"));
                tracing::error!(index = i, recipient = %recipient_addr, error = %err, "fetch claim proof failed, skipping");
                continue;
            }
        };

        if !proof_result.found {
            failure_reasons.insert(w.leaf_hash.clone(), "withdrawal claim proof not available yet; L1 root not finalized".to_string());
            tracing::info!(index = i, recipient = %recipient_addr, "withdrawal claim proof not available yet (L1 root not finalized); deferring to next round");
            continue;
        }
        if let Some(ref root_hex) = proof_result.withdrawal_root {
            let l1_root = match read_l1_withdrawal_subtree_root(&provider, state_manager).await {
                Ok(r) => r,
                Err(err) => {
                    failure_reasons.insert(w.leaf_hash.clone(), format!("failed to read L1 withdrawal root: {err}"));
                    tracing::error!(index = i, recipient = %recipient_addr, error = %err, "failed to read L1 withdrawal root, skipping");
                    continue;
                }
            };
            let root_match = normalize_l1_root_for_services(&l1_root)
                .trim_start_matches("0x")
                .eq_ignore_ascii_case(root_hex.trim_start_matches("0x"));
            if !root_match {
                failure_reasons.insert(w.leaf_hash.clone(), format!("withdrawal root still mismatched after retries: services={} l1={}", root_hex, l1_root));
                tracing::warn!(index = i, recipient = %recipient_addr, services_root = %root_hex, l1_root = %l1_root, "withdrawal root mismatch after retries, skipping");
                continue;
            }
        }

        let leaf_index = match proof_result.leaf_index {
            Some(idx) => idx,
            None => {
                failure_reasons.insert(w.leaf_hash.clone(), "claim proof missing leaf_index".to_string());
                tracing::warn!(index = i, "claim proof missing leaf_index, skipping");
                continue;
            }
        };

        let withdrawal_root_hex = match proof_result.withdrawal_root.as_deref() {
            Some(s) => s.to_string(),
            None => {
                failure_reasons.insert(w.leaf_hash.clone(), "claim proof missing withdrawal_root".to_string());
                tracing::warn!(index = i, "claim proof missing withdrawal_root, skipping");
                continue;
            }
        };

        let siblings_hex = match proof_result.siblings.as_ref() {
            Some(s) if s.len() == 32 => s.clone(),
            _ => {
                failure_reasons.insert(w.leaf_hash.clone(), "claim proof has invalid siblings".to_string());
                tracing::warn!(index = i, "claim proof has invalid siblings (need 32), skipping");
                continue;
            }
        };

        let withdrawal_root = match parse_solidity_qhash(&withdrawal_root_hex) {
            Ok(r) => r,
            Err(err) => {
                failure_reasons.insert(w.leaf_hash.clone(), format!("failed to parse withdrawal_root: {err}"));
                tracing::error!(index = i, error = %err, "failed to parse withdrawal_root, skipping");
                continue;
            }
        };

        let siblings: Vec<QHashOut<F>> = match siblings_hex
            .iter()
            .map(|h| parse_solidity_qhash(h))
            .collect::<Result<Vec<_>>>()
        {
            Ok(s) => s,
            Err(err) => {
                failure_reasons.insert(w.leaf_hash.clone(), format!("failed to parse siblings: {err}"));
                tracing::error!(index = i, error = %err, "failed to parse siblings, skipping");
                continue;
            }
        };

        pending_proofs.push(PendingProof {
            index: i,
            withdrawal: w.clone(),
            leaf_index,
            withdrawal_root,
            siblings,
        });
    }

    // Phase 2 + 3: group by root, prove fixed-shape batches, submit one batchClaimWithdrawal per chunk.
    let mut groups: HashMap<String, Vec<PendingProof>> = HashMap::new();
    for pending in pending_proofs {
        let root_hex = format!("0x{}", hex::encode(u32x8_internal_words_from_qhash(pending.withdrawal_root)));
        groups.entry(root_hex).or_default().push(pending);
    }

    let mut ordered_groups: Vec<(String, Vec<PendingProof>)> = groups.into_iter().collect();
    ordered_groups.sort_by(|a, b| a.0.cmp(&b.0));

    // ── Phase 1: collect all chunks into an ordered list ──────────────
    struct WithdrawalChunkMeta {
        root_hex: String,
        chunk: Vec<PendingProof>,
        leaf_hashes: Vec<String>,
    }
    let mut all_chunks: Vec<WithdrawalChunkMeta> = Vec::new();
    for (root_hex, mut group) in ordered_groups {
        group.sort_by_key(|p| p.leaf_index);
        for chunk in group.chunks(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE) {
            let leaf_hashes = chunk.iter().map(|p| p.withdrawal.leaf_hash.clone()).collect::<Vec<_>>();
            all_chunks.push(WithdrawalChunkMeta {
                root_hex: root_hex.clone(),
                chunk: chunk.to_vec(),
                leaf_hashes,
            });
        }
    }

    // ── Phase 2: fetch all proxy proofs concurrently (FuturesUnordered, max 4) ──
    let mut chunk_proofs: Vec<Option<anyhow::Result<Bytes>>> = (0..all_chunks.len()).map(|_| None).collect();

    if let Some(proxy_url) = prove_proxy_url {
        use futures::stream::FuturesUnordered;
        use futures::StreamExt;
        use std::sync::Arc;

        let proxy_arc = Arc::new(ProveProxyClient::new(proxy_url));

        let mut pending = FuturesUnordered::new();
        let mut outstanding: usize = 0;
        let mut prep_idx: usize = 0;
        loop {
            while outstanding < MAX_CONCURRENT_PROXY_PROOFS && prep_idx < all_chunks.len() {
                let meta = &all_chunks[prep_idx];
                let client = Arc::clone(&proxy_arc);
                let chunk_clone = meta.chunk.clone();
                let idx = prep_idx;
                pending.push(async move {
                    let result = generate_withdrawal_batch_proof(&chunk_clone, Some(client.as_ref())).await;
                    (idx, result)
                });
                outstanding += 1;
                prep_idx += 1;
            }
            if outstanding == 0 {
                break;
            }
            if let Some((idx, result)) = pending.next().await {
                outstanding -= 1;
                chunk_proofs[idx] = Some(result);
            }
        }
    } else {
        // Local fallback: sequential
        for (idx, meta) in all_chunks.iter().enumerate() {
            let result = generate_withdrawal_batch_proof(&meta.chunk, None).await;
            chunk_proofs[idx] = Some(result);
        }
    }

    // ── Phase 3: process results in order, submit L1 txs sequentially ──
    for (idx, meta) in all_chunks.iter().enumerate() {
        let root_hex = &meta.root_hex;
        let leaf_hashes = &meta.leaf_hashes;
        let call_data = match chunk_proofs[idx].take()
            .ok_or_else(|| anyhow::anyhow!("missing proof result for chunk {}", idx))?
        {
            Ok(cd) => cd,
            Err(err) => {
                for claim in &meta.chunk {
                    failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                        format!("withdrawal batch proof generation failed: {err}")
                    });
                }
                tracing::error!(
                    root = %root_hex,
                    count = meta.chunk.len(),
                    error = %err,
                    "withdrawal batch proof generation failed"
                );
                continue;
            }
        };

        let tx = TransactionRequest::default().to(bridge).input(call_data.clone().into());
        let gas = match provider.estimate_gas(tx.clone()).await {
            Ok(gas) => gas,
            Err(err) => {
                tracing::warn!(
                    root = %root_hex,
                    count = meta.chunk.len(),
                    error = ?err,
                    fallback_gas = L1_GROTH16_CALL_GAS_FALLBACK,
                    "L1 batch withdrawal gas estimation failed; continuing with fallback assumption"
                );
                L1_GROTH16_CALL_GAS_FALLBACK
            }
        };

        tracing::info!(
            root = %root_hex,
            count = meta.chunk.len(),
            estimated_gas = gas,
            "sending batchClaimWithdrawal tx"
        );

        match timeout(
            Duration::from_secs(L1_TX_SEND_TIMEOUT_SECS),
            provider.send_transaction(tx),
        )
        .await
        {
            Ok(Ok(pending)) => {
                tracing::info!(
                    root = %root_hex,
                    tx_hash = %pending.tx_hash(),
                    count = meta.chunk.len(),
                    "batchClaimWithdrawal submitted; waiting for receipt"
                );
                match timeout(
                    Duration::from_secs(L1_TX_RECEIPT_TIMEOUT_SECS),
                    pending.get_receipt(),
                )
                .await
                {
                    Ok(Ok(receipt)) => {
                        if receipt.status() {
                            submitted_count += meta.chunk.len();
                            resolved_leaf_hashes.extend(leaf_hashes.iter().cloned());
                            tracing::info!(
                                tx_hash = %receipt.transaction_hash,
                                root = %root_hex,
                                submitted_count,
                                already_claimed_count,
                                "batchClaimWithdrawal confirmed"
                            );
                        } else {
                            for claim in &meta.chunk {
                                failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                                    "batchClaimWithdrawal reverted on-chain".to_string()
                                });
                            }
                            tracing::error!(tx_hash = %receipt.transaction_hash, root = %root_hex, "batchClaimWithdrawal reverted on-chain");
                        }
                    }
                    Ok(Err(err)) => {
                        for claim in &meta.chunk {
                            failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                                format!("batchClaimWithdrawal receipt failed: {err}")
                            });
                        }
                        tracing::error!(root = %root_hex, error = ?err, "batchClaimWithdrawal receipt failed");
                    }
                    Err(_) => {
                        for claim in &meta.chunk {
                            failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                                format!("batchClaimWithdrawal receipt timed out after {}s", L1_TX_RECEIPT_TIMEOUT_SECS)
                            });
                        }
                        tracing::error!(root = %root_hex, timeout_secs = L1_TX_RECEIPT_TIMEOUT_SECS, "batchClaimWithdrawal receipt timed out");
                    }
                }
            }
            Ok(Err(err)) => {
                for claim in &meta.chunk {
                    failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                        format!("send batchClaimWithdrawal tx failed: {err}")
                    });
                }
                tracing::error!(root = %root_hex, error = ?err, "send batchClaimWithdrawal tx failed");
            }
            Err(_) => {
                for claim in &meta.chunk {
                    failure_reasons.entry(claim.withdrawal.leaf_hash.clone()).or_insert_with(|| {
                        format!("send batchClaimWithdrawal tx timed out after {}s", L1_TX_SEND_TIMEOUT_SECS)
                    });
                }
                tracing::error!(root = %root_hex, timeout_secs = L1_TX_SEND_TIMEOUT_SECS, "send batchClaimWithdrawal tx timed out");
            }
        }
    }

    Ok(BatchWithdrawalsReport {
        requested: withdrawals.len(),
        submitted_count,
        already_claimed_count,
        resolved_leaf_hashes,
        failure_reasons,
    })
}

fn u32x8_internal_words_from_qhash(hash: QHashOut<F>) -> [u8; 32] {
    let elems = hash.0.elements;
    let words = [
        elems[0].to_canonical_u64() as u32,
        (elems[0].to_canonical_u64() >> 32) as u32,
        elems[1].to_canonical_u64() as u32,
        (elems[1].to_canonical_u64() >> 32) as u32,
        elems[2].to_canonical_u64() as u32,
        (elems[2].to_canonical_u64() >> 32) as u32,
        elems[3].to_canonical_u64() as u32,
        (elems[3].to_canonical_u64() >> 32) as u32,
    ];
    let mut out = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
    }
    out
}

fn qhash_to_solidity_hex(hash: QHashOut<F>) -> String {
    let elems = hash.0.elements;
    let mut out = [0u8; 32];
    for i in 0..4 {
        let v = elems[3 - i].to_canonical_u64();
        out[i * 8..(i + 1) * 8].copy_from_slice(&v.to_be_bytes());
    }
    format!("0x{}", hex::encode(out))
}

pub async fn run(args: BatchWithdrawalsArgs) -> Result<()> {
    let raw = fs::read_to_string(&args.input_json)
        .with_context(|| format!("failed to read {}", args.input_json.display()))?;
    let withdrawals: Vec<PendingWithdrawal> = serde_json::from_str(&raw)
        .with_context(|| format!("failed to parse {}", args.input_json.display()))?;

    let report = submit_batch(
        &withdrawals,
        &args.services_url,
        &args.l1_rpc_url,
        &args.bridge_address,
        args.multicall3_address.as_deref(),
        &args.deployments_network,
        args.private_key.as_deref(),
        args.keystore_path.as_deref(),
        &args.password_env,
        None,
    )
    .await?;

    println!(
        "batch withdrawals: requested={}, submitted_count={}, already_claimed_count={}, resolved={}, failed={}",
        report.requested,
        report.submitted_count,
        report.already_claimed_count,
        report.resolved_leaf_hashes.len(),
        report.failure_reasons.len()
    );
    Ok(())
}
