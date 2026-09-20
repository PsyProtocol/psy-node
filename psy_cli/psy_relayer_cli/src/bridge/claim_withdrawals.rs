use std::{collections::HashMap, fs, path::{Path, PathBuf}, str::FromStr};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
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
        uint256[1088] slotData
    );

    function claimedNullifiers(bytes32 nullifier) view returns (bool);

    function balanceOf(address account) view returns (uint256);

    function withdrawalSubtreeRoot() view returns (bytes32);

    function knownWithdrawalSubtreeRoots(bytes32 root) view returns (bool);
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
    /// Withdrawals held back for a reason that resolves on its own, and that
    /// therefore must not spend one of the claim's limited attempts: waiting
    /// for a services proof that is not found yet, or waiting for bridge
    /// liquidity. Unauthorized withdrawal roots are failures, not deferrals.
    #[serde(default)]
    pub deferrals: HashMap<String, String>,
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
    let nonce_hex = u32x8_to_hex(withdrawal.nonce);

    let url = format!(
        "{}/api/v1/bridge/withdrawal-claim-proof?recipient={}&token_address={}&amount={}&nonce={}&destination_chain_index={}&sender_user_id={}",
        services_url.trim_end_matches('/'),
        recipient_hex,
        token_hex,
        amount_hex,
        nonce_hex,
        withdrawal.destination_chain_index,
        withdrawal.sender_user_id,
    );
    tracing::debug!(url = %url, "fetching withdrawal claim proof");

    let resp: ApiResponse<WithdrawalClaimProofResult> =
        get_services_json(http, &url, "withdrawal_claim_proof").await?;

    if !resp.success {
        anyhow::bail!("psy-services error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
    }
    resp.data.ok_or_else(|| anyhow::anyhow!("psy-services returned success but no data"))
}

fn reverse_u32x8_root_hex(hex: &str) -> Result<[u8; 32]> {
    let raw = hex.trim().trim_start_matches("0x").trim_start_matches("0X");
    anyhow::ensure!(raw.len() == 64, "expected 64 hex chars, got {}", raw.len());
    let bytes = hex::decode(raw).context("invalid root hex")?;
    anyhow::ensure!(bytes.len() == 32, "expected 32 root bytes, got {}", bytes.len());
    let mut out = [0u8; 32];
    for i in 0..8 {
        let src = (7 - i) * 4;
        out[i * 4..i * 4 + 4].copy_from_slice(&bytes[src..src + 4]);
    }
    Ok(out)
}

async fn read_l1_withdrawal_subtree_root<P: Provider>(provider: &P, state_manager: Address) -> Result<B256> {
    let call = withdrawalSubtreeRootCall {};
    let tx = TransactionRequest::default().to(state_manager).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("withdrawalSubtreeRoot eth_call failed")?;
    withdrawalSubtreeRootCall::abi_decode_returns(&raw).context("failed to decode withdrawalSubtreeRoot return")
}

async fn read_known_withdrawal_subtree_root<P: Provider>(
    provider: &P,
    state_manager: Address,
    root: B256,
) -> Result<bool> {
    let call = knownWithdrawalSubtreeRootsCall { root };
    let tx = TransactionRequest::default().to(state_manager).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("knownWithdrawalSubtreeRoots eth_call failed")?;
    knownWithdrawalSubtreeRootsCall::abi_decode_returns(&raw)
        .context("failed to decode knownWithdrawalSubtreeRoots return")
}

async fn check_withdrawal_root_on_l1<P: Provider>(
    provider: &P,
    state_manager: Address,
    services_root_hex: &str,
) -> Result<(bool, String)> {
    let proof_root = B256::from(
        reverse_u32x8_root_hex(services_root_hex).context("invalid withdrawal_root encoding")?,
    );
    let current = read_l1_withdrawal_subtree_root(provider, state_manager).await?;
    let current_root_hex = format!("0x{}", hex::encode(current));
    if proof_root == current {
        return Ok((true, current_root_hex));
    }
    let known = read_known_withdrawal_subtree_root(provider, state_manager, proof_root).await?;
    Ok((
        withdrawal_root_is_authorized(proof_root, current, known),
        current_root_hex,
    ))
}

fn withdrawal_root_is_authorized(proof_root: B256, current_root: B256, historically_known: bool) -> bool {
    proof_root == current_root || historically_known
}


async fn poll_claim_proof<P: Provider>(
    http: &reqwest::Client,
    services_url: &str,
    provider: &P,
    state_manager: Address,
    withdrawal: &PendingWithdrawal,
    max_attempts: usize,
    retry_delay: Duration,
) -> Result<WithdrawalClaimProofResult> {
    anyhow::ensure!(max_attempts > 0, "claim proof fetch requires at least one attempt");
    let mut latest: Result<WithdrawalClaimProofResult> =
        Err(anyhow::anyhow!("claim proof fetch exhausted without response"));
    for attempt in 1..=max_attempts {
        latest = match fetch_claim_proof(http, services_url, withdrawal).await {
            Ok(r) if !r.found => Ok(r),
            Ok(r) => {
                if let Some(root_hex) = r.withdrawal_root.clone() {
                    match check_withdrawal_root_on_l1(provider, state_manager, &root_hex).await {
                        Ok((true, _)) => return Ok(r),
                        Ok((false, l1_root)) => {
                            tracing::debug!(
                                services_root = %root_hex,
                                l1_root = %l1_root,
                                attempt,
                                max_attempts,
                                "claim proof root is not current or known; will retry"
                            );
                            Ok(r)
                        }
                        Err(err) => Err(err.context("check L1 withdrawal root failed")),
                    }
                } else {
                    return Ok(r);
                }
            }
            Err(err) => Err(err),
        };
        if attempt < max_attempts {
            tokio::time::sleep(retry_delay).await;
        }
    }
    latest
}



async fn withdrawal_already_claimed<P: Provider>(
    provider: &P,
    bridge: Address,
    withdrawal: &PendingWithdrawal,
) -> Result<bool> {
    let nullifier = withdrawal_nullifier_from_nonce(withdrawal.nonce);
    let call = claimedNullifiersCall { nullifier };
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("claimedNullifiers eth_call failed")?;
    claimedNullifiersCall::abi_decode_returns(&raw).context("failed to decode claimedNullifiers return")
}

fn withdrawal_nullifier_from_nonce(nonce: [u32; 8]) -> B256 {
    let mut nonce_bytes = [0u8; 32];
    for (i, word) in nonce.iter().enumerate() {
        nonce_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    B256::from(nonce_bytes)
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

    let path = crate::bridge::api_client::resolve_deployments_file(
        deployments_network,
        "deployed-contracts.json",
    );
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
    let multicall_artifact_path =
        crate::bridge::api_client::resolve_deployments_file(deployments_network, "Multicall3.json");
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
            let sender_user_id_u32 = u32::try_from(p.withdrawal.sender_user_id)
                .map_err(|_| anyhow::anyhow!("sender_user_id {} exceeds u32", p.withdrawal.sender_user_id))?;
            let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_index)
                .map_err(|_| anyhow::anyhow!(
                    "destination_chain_index {} exceeds u32",
                    p.withdrawal.destination_chain_index
                ))?;
            Ok::<_, anyhow::Error>(ProxyWithdrawalWitnessInput {
                withdrawal_root: qhash_to_solidity_hex(p.withdrawal_root),
                sender_user_id: sender_user_id_u32,
                recipient: p.withdrawal.recipient,
                token: p.withdrawal.token_address,
                amount: p.withdrawal.amount,
                nonce: p.withdrawal.nonce,
                destination_chain_index: dest_chain_u32,
                leaf_index: p.leaf_index,
                bridge_user_id: BRIDGE_USER_ID_U32,
                siblings: p.siblings.iter().map(|s| qhash_to_solidity_hex(*s)).collect(),
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
            let sender_user_id_u32 = u32::try_from(p.withdrawal.sender_user_id)
                .map_err(|_| anyhow::anyhow!("sender_user_id {} exceeds u32", p.withdrawal.sender_user_id))?;
            slot_data_u256[slot_offset] = U256::from(sender_user_id_u32);
            for (j, word) in p.withdrawal.recipient.iter().enumerate() {
                slot_data_u256[slot_offset + 1 + j] = U256::from(*word);
            }
            for (j, word) in p.withdrawal.token_address.iter().enumerate() {
                slot_data_u256[slot_offset + 9 + j] = U256::from(*word);
            }
            for (j, word) in p.withdrawal.amount.iter().enumerate() {
                slot_data_u256[slot_offset + 17 + j] = U256::from(*word);
            }
            // nonce occupies words 25..32 (8 words); destination_chain_index at 33.
            for (j, word) in p.withdrawal.nonce.iter().enumerate() {
                slot_data_u256[slot_offset + 25 + j] = U256::from(*word);
            }
            let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_index)
                .map_err(|_| anyhow::anyhow!("destination_chain_index {} exceeds u32", p.withdrawal.destination_chain_index))?;
            slot_data_u256[slot_offset + 33] = U256::from(dest_chain_u32);
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
            let s0: Vec<u64> = proof.slot_data.iter().take(WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS).copied().collect();
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
                let sender_user_id_u32 = u32::try_from(p.withdrawal.sender_user_id)
                    .map_err(|_| anyhow::anyhow!("sender_user_id {} exceeds u32", p.withdrawal.sender_user_id))?;
                let dest_chain_u32 = u32::try_from(p.withdrawal.destination_chain_index).map_err(|_| {
                    anyhow::anyhow!("destination_chain_index {} exceeds u32", p.withdrawal.destination_chain_index)
                })?;
                Ok::<_, anyhow::Error>(WithdrawalBatchClaimSlotInputs::<F> {
                    sender_user_id: sender_user_id_u32,
                    recipient: p.withdrawal.recipient,
                    token: p.withdrawal.token_address,
                    amount: p.withdrawal.amount,
                    nonce: p.withdrawal.nonce,
                    destination_chain_index: dest_chain_u32,
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
        let sender_user_id_u32 = u32::try_from(pending.withdrawal.sender_user_id)
            .map_err(|_| anyhow::anyhow!("sender_user_id {} exceeds u32", pending.withdrawal.sender_user_id))?;
        slot_data_u256[slot_offset] = U256::from(sender_user_id_u32);
        for (j, word) in pending.withdrawal.recipient.iter().enumerate() {
            slot_data_u256[slot_offset + 1 + j] = U256::from(*word);
        }
        for (j, word) in pending.withdrawal.token_address.iter().enumerate() {
            slot_data_u256[slot_offset + 9 + j] = U256::from(*word);
        }
        for (j, word) in pending.withdrawal.amount.iter().enumerate() {
            slot_data_u256[slot_offset + 17 + j] = U256::from(*word);
        }
        // nonce occupies words 25..32 (8 words); destination_chain_index at 33.
        for (j, word) in pending.withdrawal.nonce.iter().enumerate() {
            slot_data_u256[slot_offset + 25 + j] = U256::from(*word);
        }
        let dest_chain_u32 = u32::try_from(pending.withdrawal.destination_chain_index)
            .map_err(|_| anyhow::anyhow!("destination_chain_index {} exceeds u32", pending.withdrawal.destination_chain_index))?;
        slot_data_u256[slot_offset + 33] = U256::from(dest_chain_u32);
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
            deferrals: HashMap::new(),
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
    let mut deferrals: HashMap<String, String> = HashMap::new();
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
                deferrals.insert(w.leaf_hash.clone(), reason);
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

        let proof_result = match poll_claim_proof(
            &http,
            services_url,
            &provider,
            state_manager,
            w,
            CLAIM_PROOF_FETCH_MAX_ATTEMPTS,
            Duration::from_secs(CLAIM_PROOF_FETCH_RETRY_DELAY_SECS),
        ).await {
            Ok(r) => r,
            Err(err) => {
                failure_reasons.insert(w.leaf_hash.clone(), format!("fetch claim proof failed: {err}"));
                tracing::error!(index = i, recipient = %recipient_addr, error = %err, "fetch claim proof failed, skipping");
                continue;
            }
        };

        if !proof_result.found {
            deferrals.insert(w.leaf_hash.clone(), "withdrawal claim proof not available yet; L1 root not finalized".to_string());
            tracing::info!(index = i, recipient = %recipient_addr, "withdrawal claim proof not available yet (L1 root not finalized); deferring to next round");
            continue;
        }
        if let Some(root_hex) = &proof_result.withdrawal_root {
            match check_withdrawal_root_on_l1(&provider, state_manager, root_hex).await {
                Ok((true, _)) => {}
                Ok((false, l1_root)) => {
                    failure_reasons.insert(w.leaf_hash.clone(), format!("withdrawal root is not current or known: services={} l1={}", root_hex, l1_root));
                    tracing::warn!(index = i, recipient = %recipient_addr, services_root = %root_hex, l1_root = %l1_root, "withdrawal root is not current or known after retries, skipping");
                    continue;
                }
                Err(err) => {
                    failure_reasons.insert(w.leaf_hash.clone(), format!("failed to read L1 withdrawal root: {err}"));
                    tracing::error!(index = i, recipient = %recipient_addr, error = %err, "failed to read L1 withdrawal root, skipping");
                    continue;
                }
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
        deferrals,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_u32x8_root_hex_reverses_word_order() {
        let display =
            "0x1111111122222222333333334444444455555555666666667777777788888888";
        assert_eq!(
            hex::encode(reverse_u32x8_root_hex(display).expect("valid 32-byte root")),
            "8888888877777777666666665555555544444444333333332222222211111111"
        );
    }

    #[test]
    fn reverse_u32x8_root_hex_rejects_malformed_input() {
        assert!(reverse_u32x8_root_hex("0x11").is_err());
        assert!(reverse_u32x8_root_hex("0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn withdrawal_root_is_authorized_for_current_or_known_history() {
        let current = B256::from([0x11; 32]);
        let historical = B256::from([0x22; 32]);
        let unknown = B256::from([0x33; 32]);
        assert!(withdrawal_root_is_authorized(current, current, false));
        assert!(withdrawal_root_is_authorized(historical, current, true));
        assert!(!withdrawal_root_is_authorized(unknown, current, false));
        assert!(!withdrawal_root_is_authorized(historical, current, false));
    }

    #[test]
    fn withdrawal_nullifier_from_nonce_concatenates_big_endian_u32_words() {
        let nonce = [
            0x01020304,
            0x11121314,
            0x21222324,
            0x31323334,
            0x41424344,
            0x51525354,
            0x61626364,
            0x71727374,
        ];
        assert_eq!(
            format!("0x{}", hex::encode(withdrawal_nullifier_from_nonce(nonce))),
            "0x0102030411121314212223243132333441424344515253546162636471727374"
        );
    }

    #[test]
    fn u32x8_to_address_uses_low_20_bytes() {
        let words = [
            0x00000000,
            0x00000000,
            0x00000000,
            0x11111111,
            0x22222222,
            0x33333333,
            0x44444444,
            0x55555555,
        ];
        assert_eq!(
            u32x8_to_address(words).to_string(),
            "0x1111111122222222333333334444444455555555"
        );
    }

    #[test]
    fn address_high_bits_are_zero_requires_zero_prefix_words() {
        assert!(address_high_bits_are_zero([0, 0, 0, 1, 2, 3, 4, 5]));
        assert!(!address_high_bits_are_zero([1, 0, 0, 1, 2, 3, 4, 5]));
    }

    use alloy_provider::ProviderBuilder;
    use serde_json::{json, Value};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    const STATE_MANAGER: Address = Address::repeat_byte(0x53);
    const DISPLAY_ROOT: &str =
        "0x1111111122222222333333334444444455555555666666667777777788888888";

    fn dummy_withdrawal() -> PendingWithdrawal {
        PendingWithdrawal {
            event_id: 1,
            checkpoint_id: 1,
            user_id: 1,
            sender_user_id: 1,
            contract_id: 0,
            destination_chain_index: 0,
            token_address: [0; 8],
            amount: [0, 0, 0, 0, 0, 0, 0, 1],
            recipient: [0; 8],
            nonce: [0; 8],
            leaf_hash: "leaf".to_string(),
        }
    }

    fn l1_bytes_from_display(display: &str) -> [u8; 32] {
        reverse_u32x8_root_hex(display).expect("valid display root")
    }

    fn abi_word(bytes: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(bytes))
    }

    fn abi_bool(value: bool) -> String {
        let mut word = [0u8; 32];
        if value {
            word[31] = 1;
        }
        abi_word(&word)
    }

    fn services_body(found: bool, root: Option<&str>) -> String {
        json!({
            "success": true,
            "data": {
                "found": found,
                "leaf_index": 7,
                "withdrawal_root": root,
                "siblings": Value::Null,
            }
        })
        .to_string()
    }

    async fn read_http_exchange(
        listener: &TcpListener,
    ) -> (Value, tokio::io::BufReader<tokio::net::TcpStream>, bool) {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut line = String::new();
        let mut length = 0;
        let mut is_get = false;
        loop {
            line.clear();
            assert!(socket.read_line(&mut line).await.unwrap() > 0);
            if line.starts_with("GET ") {
                is_get = true;
            }
            if line == "\r\n" {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
        }
        let mut body = vec![0; length];
        if length > 0 {
            socket.read_exact(&mut body).await.unwrap();
        }
        let actual = if is_get {
            json!({"method": "GET"})
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        (actual, socket, is_get)
    }

    async fn write_http(socket: &mut BufReader<tokio::net::TcpStream>, status: &str, body: &str) {
        let response = format!(
            "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            status,
            body.len(),
            body
        );
        socket.get_mut().write_all(response.as_bytes()).await.unwrap();
    }

    fn call_input(actual: &Value) -> String {
        let params = &actual["params"][0];
        params
            .get("data")
            .or_else(|| params.get("input"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_lowercase()
    }

    enum EthCall {
        Current([u8; 32]),
        Known { expected_root: [u8; 32], known: bool },
        RpcError(&'static str),
    }

    async fn serve_eth_calls(listener: TcpListener, calls: Vec<EthCall>) {
        let current_sel = hex::encode(withdrawalSubtreeRootCall {}.abi_encode());
        let known_sel = hex::encode(knownWithdrawalSubtreeRootsCall { root: B256::ZERO }.abi_encode());
        let current_sel = &current_sel[..8];
        let known_sel = &known_sel[..8];
        let mut remaining = calls;
        while !remaining.is_empty() {
            let (actual, mut socket, _) = read_http_exchange(&listener).await;
            let method = actual["method"].as_str().unwrap_or("");
            if method != "eth_call" {
                let body = json!({"jsonrpc":"2.0","id": actual["id"], "result": "0x1"}).to_string();
                write_http(&mut socket, "200 OK", &body).await;
                continue;
            }
            let input = call_input(&actual);
            let selector = input.trim_start_matches("0x").get(..8).unwrap_or("");
            let scripted = remaining.remove(0);
            let body = match scripted {
                EthCall::Current(root) => {
                    assert_eq!(selector, current_sel, "expected withdrawalSubtreeRoot, got {input}");
                    json!({"jsonrpc":"2.0","id": actual["id"], "result": abi_word(&root)}).to_string()
                }
                EthCall::Known { expected_root, known } => {
                    assert_eq!(selector, known_sel, "expected knownWithdrawalSubtreeRoots, got {input}");
                    let arg = input.trim_start_matches("0x").get(8..).unwrap_or("");
                    assert_eq!(arg, hex::encode(expected_root), "mapping must receive reversed L1 bytes32");
                    json!({"jsonrpc":"2.0","id": actual["id"], "result": abi_bool(known)}).to_string()
                }
                EthCall::RpcError(message) => {
                    json!({"jsonrpc":"2.0","id": actual["id"], "error": {"code": -32000, "message": message}}).to_string()
                }
            };
            write_http(&mut socket, "200 OK", &body).await;
        }
    }

    async fn serve_services(listener: TcpListener, bodies: Vec<Result<String, u16>>) {
        for body in bodies {
            let (_, mut socket, is_get) = read_http_exchange(&listener).await;
            assert!(is_get, "services proof is fetched with GET");
            match body {
                Ok(json_body) => write_http(&mut socket, "200 OK", &json_body).await,
                Err(503) => write_http(&mut socket, "503 Service Unavailable", "{\"error\":\"RPC 503 upstream\"}").await,
                Err(code) => write_http(&mut socket, &format!("{code} Error"), "{}").await,
            }
        }
    }

    async fn join_fixture(mut server: tokio::task::JoinHandle<()>) {
        let joined = tokio::time::timeout(Duration::from_secs(2), &mut server).await;
        server.abort();
        joined.expect("unused fixture requests").expect("fixture assertion failed");
    }

    async fn with_l1<T, F, Fut>(calls: Vec<EthCall>, f: F) -> T
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(serve_eth_calls(listener, calls));
        let out = f(url).await;
        join_fixture(server).await;
        out
    }

    async fn with_services_and_l1<T, F, Fut>(
        services: Vec<Result<String, u16>>,
        calls: Vec<EthCall>,
        f: F,
    ) -> T
    where
        F: FnOnce(String, String) -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let services_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services_url = format!("http://{}", services_listener.local_addr().unwrap());
        let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
        let services_server = tokio::spawn(serve_services(services_listener, services));
        let rpc_server = tokio::spawn(serve_eth_calls(rpc_listener, calls));
        let out = f(services_url, rpc_url).await;
        join_fixture(services_server).await;
        join_fixture(rpc_server).await;
        out
    }

    #[tokio::test]
    async fn current_withdrawal_root_is_authorized_on_l1() {
        let l1_root = l1_bytes_from_display(DISPLAY_ROOT);
        let (authorized, _) = with_l1(vec![EthCall::Current(l1_root)], |url| async move {
            let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
            check_withdrawal_root_on_l1(&provider, STATE_MANAGER, DISPLAY_ROOT).await.unwrap()
        })
        .await;
        assert!(authorized);
    }

    #[tokio::test]
    async fn historically_known_withdrawal_root_is_authorized_on_l1() {
        let proof_l1 = l1_bytes_from_display(DISPLAY_ROOT);
        let current = [0xaau8; 32];
        let (authorized, _) = with_l1(
            vec![
                EthCall::Current(current),
                EthCall::Known { expected_root: proof_l1, known: true },
            ],
            |url| async move {
                let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
                check_withdrawal_root_on_l1(&provider, STATE_MANAGER, DISPLAY_ROOT).await.unwrap()
            },
        )
        .await;
        assert!(authorized);
    }

    #[tokio::test]
    async fn unknown_withdrawal_root_is_rejected_on_l1() {
        let proof_l1 = l1_bytes_from_display(DISPLAY_ROOT);
        let (authorized, _) = with_l1(
            vec![
                EthCall::Current([0xaau8; 32]),
                EthCall::Known { expected_root: proof_l1, known: false },
            ],
            |url| async move {
                let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
                check_withdrawal_root_on_l1(&provider, STATE_MANAGER, DISPLAY_ROOT).await.unwrap()
            },
        )
        .await;
        assert!(!authorized);
    }

    #[tokio::test]
    async fn history_mapping_rpc_error_is_a_failure() {
        let err = with_l1(
            vec![EthCall::Current([0xaau8; 32]), EthCall::RpcError("RPC 503 upstream")],
            |url| async move {
                let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
                check_withdrawal_root_on_l1(&provider, STATE_MANAGER, DISPLAY_ROOT).await.unwrap_err()
            },
        )
        .await;
        assert!(err.to_string().contains("RPC 503 upstream") || err.to_string().contains("eth_call"));
    }

    #[test]
    fn malformed_withdrawal_root_hex_is_a_failure() {
        assert!(reverse_u32x8_root_hex("0x11").is_err());
    }

    #[tokio::test]
    async fn poll_replaces_unauthorized_root_with_later_rpc_error() {
        let proof_l1 = l1_bytes_from_display(DISPLAY_ROOT);
        let err = with_services_and_l1(
            vec![
                Ok(services_body(true, Some(DISPLAY_ROOT))),
                Err(503),
            ],
            vec![
                EthCall::Current([0xaau8; 32]),
                EthCall::Known { expected_root: proof_l1, known: false },
            ],
            |services_url, rpc_url| async move {
                let http = reqwest::Client::new();
                let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
                poll_claim_proof(
                    &http,
                    &services_url,
                    &provider,
                    STATE_MANAGER,
                    &dummy_withdrawal(),
                    2,
                    Duration::from_millis(1),
                )
                .await
                .unwrap_err()
            },
        )
        .await;
        assert!(
            err.to_string().contains("503") || err.to_string().contains("RPC 503"),
            "later services RPC error must replace earlier unauthorized Ok, got: {err}"
        );
    }

    #[tokio::test]
    async fn poll_replaces_not_ready_with_later_rpc_error() {
        let err = with_services_and_l1(
            vec![Ok(services_body(false, None)), Err(503)],
            vec![],
            |services_url, rpc_url| async move {
                let http = reqwest::Client::new();
                let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
                poll_claim_proof(
                    &http,
                    &services_url,
                    &provider,
                    STATE_MANAGER,
                    &dummy_withdrawal(),
                    2,
                    Duration::from_millis(1),
                )
                .await
                .unwrap_err()
            },
        )
        .await;
        assert!(
            err.to_string().contains("503") || err.to_string().contains("RPC 503"),
            "later services RPC error must replace earlier found=false, got: {err}"
        );
    }

    #[tokio::test]
    async fn poll_accepts_historically_known_root() {
        let proof_l1 = l1_bytes_from_display(DISPLAY_ROOT);
        let proof = with_services_and_l1(
            vec![Ok(services_body(true, Some(DISPLAY_ROOT)))],
            vec![
                EthCall::Current([0xaau8; 32]),
                EthCall::Known { expected_root: proof_l1, known: true },
            ],
            |services_url, rpc_url| async move {
                let http = reqwest::Client::new();
                let provider = ProviderBuilder::new().connect_http(rpc_url.parse().unwrap());
                poll_claim_proof(
                    &http,
                    &services_url,
                    &provider,
                    STATE_MANAGER,
                    &dummy_withdrawal(),
                    1,
                    Duration::from_millis(1),
                )
                .await
                .unwrap()
            },
        )
        .await;
        assert!(proof.found);
        assert_eq!(proof.withdrawal_root.as_deref(), Some(DISPLAY_ROOT));
    }


}
