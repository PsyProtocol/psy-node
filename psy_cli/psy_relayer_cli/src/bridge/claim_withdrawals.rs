use std::{collections::HashMap, fs, path::{Path, PathBuf}, str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall, SolValue};
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

    function pendingWithdrawals(bytes32 nonce) view returns (
        address token,
        address recipient,
        uint256 amount,
        uint64 claimableAt
    );

    function claimPendingWithdrawal(bytes32 nonce);
}

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofResult {
    pub found: bool,
    pub leaf_index: Option<u32>,
    pub withdrawal_root: Option<String>,
    pub siblings: Option<Vec<String>>,
}

fn select_claim_proof_poll_result(
    final_result: Option<WithdrawalClaimProofResult>,
    last_not_ready: Option<WithdrawalClaimProofResult>,
    last_err: Option<anyhow::Error>,
) -> Result<WithdrawalClaimProofResult> {
    final_result
        .or(last_not_ready)
        .ok_or_else(|| last_err.unwrap_or_else(|| anyhow::anyhow!("claim proof fetch exhausted without response")))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BatchWithdrawalsReport {
    pub requested: usize,
    /// Proof registrations confirmed by `batchClaimWithdrawal`. These remain
    /// in the durable pending set until settlement succeeds.
    pub submitted_count: usize,
    /// Withdrawals observed as fully settled on L1.
    pub already_claimed_count: usize,
    /// Durable entries safe to delete because settlement completed.
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
    let nullifier = withdrawal_nullifier_from_nonce(withdrawal.nonce);
    let call = claimedNullifiersCall { nullifier };
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("claimedNullifiers eth_call failed")?;
    claimedNullifiersCall::abi_decode_returns(&raw).context("failed to decode claimedNullifiers return")
}

#[derive(Debug)]
struct OnChainPendingWithdrawal {
    amount: U256,
    claimable_at: u64,
}

#[derive(Debug, PartialEq, Eq)]
enum PendingSettlement {
    AlreadySettled,
    Timelocked { claimable_at: u64, now: u64 },
    Claimable,
}

fn classify_pending_settlement(amount: U256, claimable_at: u64, now: u64) -> PendingSettlement {
    if amount == U256::ZERO {
        return PendingSettlement::AlreadySettled;
    }
    if now < claimable_at {
        return PendingSettlement::Timelocked { claimable_at, now };
    }
    PendingSettlement::Claimable
}

async fn read_pending_withdrawal<P: Provider>(
    provider: &P,
    bridge: Address,
    nonce: B256,
) -> Result<OnChainPendingWithdrawal> {
    let call = pendingWithdrawalsCall { nonce };
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("pendingWithdrawals eth_call failed")?;
    let pending = pendingWithdrawalsCall::abi_decode_returns(&raw)
        .context("failed to decode pendingWithdrawals return")?;
    Ok(OnChainPendingWithdrawal {
        amount: pending.amount,
        claimable_at: pending.claimableAt,
    })
}

async fn settle_registered_withdrawal<P: Provider>(
    provider: &P,
    bridge: Address,
    withdrawal: &PendingWithdrawal,
) -> Result<()> {
    let nonce = withdrawal_nullifier_from_nonce(withdrawal.nonce);
    let pending = read_pending_withdrawal(provider, bridge, nonce).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?
        .as_secs();
    match classify_pending_settlement(pending.amount, pending.claimable_at, now) {
        PendingSettlement::AlreadySettled => return Ok(()),
        PendingSettlement::Timelocked { claimable_at, now } => {
            anyhow::bail!(
                "pending withdrawal is timelocked until {} ({} seconds remaining)",
                claimable_at,
                claimable_at - now
            );
        }
        PendingSettlement::Claimable => {}
    }

    let call = claimPendingWithdrawalCall { nonce };
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    provider
        .call(tx.clone())
        .await
        .context("claimPendingWithdrawal is not currently executable")?;
    let pending_tx = timeout(
        Duration::from_secs(L1_TX_SEND_TIMEOUT_SECS),
        provider.send_transaction(tx),
    )
    .await
    .context("claimPendingWithdrawal send timed out")?
    .context("claimPendingWithdrawal send failed")?;
    let receipt = timeout(
        Duration::from_secs(L1_TX_RECEIPT_TIMEOUT_SECS),
        pending_tx.get_receipt(),
    )
    .await
    .context("claimPendingWithdrawal receipt timed out")?
    .context("claimPendingWithdrawal receipt failed")?;
    anyhow::ensure!(receipt.status(), "claimPendingWithdrawal reverted on-chain");

    tracing::info!(
        leaf_hash = %withdrawal.leaf_hash,
        tx_hash = %receipt.transaction_hash,
        "pending withdrawal settlement confirmed"
    );
    Ok(())
}

fn withdrawal_nullifier_from_nonce(nonce: [u32; 8]) -> B256 {
    let mut nonce_bytes = [0u8; 32];
    for (i, word) in nonce.iter().enumerate() {
        nonce_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    B256::from(nonce_bytes)
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
    if multicall3_address.is_some() || !deployments_network.is_empty() {
        let _ = (multicall3_address, deployments_network);
    }

    // Phase 1: settle already-registered withdrawals and fetch proofs only for
    // unregistered ones. A consumed nullifier means registration succeeded; it
    // does not mean the recipient has received the full amount.
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
                match settle_registered_withdrawal(&provider, bridge, w).await {
                    Ok(()) => {
                        already_claimed_count += 1;
                        resolved_leaf_hashes.push(w.leaf_hash.clone());
                        tracing::info!(
                            index = i,
                            recipient = %recipient_addr,
                            leaf_hash = %w.leaf_hash,
                            "withdrawal is fully settled on L1"
                        );
                    }
                    Err(err) => {
                        failure_reasons.insert(
                            w.leaf_hash.clone(),
                            format!("pending withdrawal settlement deferred: {err}"),
                        );
                    }
                }
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
            amount = %amount,
            leaf_hash = %w.leaf_hash,
            "preparing pending withdrawal registration proof"
        );

        let proof_result = {
            let mut last_err: Option<anyhow::Error> = None;
            let mut last_not_ready: Option<WithdrawalClaimProofResult> = None;
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
                            last_not_ready = Some(r);
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
            match select_claim_proof_poll_result(final_result, last_not_ready, last_err) {
                Ok(r) => r,
                Err(err) => {
                    failure_reasons.insert(w.leaf_hash.clone(), format!("fetch claim proof failed: {err}"));
                    tracing::error!(index = i, recipient = %recipient_addr, error = %err, "fetch claim proof failed, skipping");
                    continue;
                }
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
    }
    let mut all_chunks: Vec<WithdrawalChunkMeta> = Vec::new();
    for (root_hex, mut group) in ordered_groups {
        group.sort_by_key(|p| p.leaf_index);
        for chunk in group.chunks(MAX_WITHDRAWAL_CLAIM_BATCH_SIZE) {
            all_chunks.push(WithdrawalChunkMeta {
                root_hex: root_hex.clone(),
                chunk: chunk.to_vec(),
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
                            tracing::info!(
                                tx_hash = %receipt.transaction_hash,
                                root = %root_hex,
                                submitted_count,
                                already_claimed_count,
                                "batchClaimWithdrawal registration confirmed; settlement remains pending"
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_l1_root_for_services_reverses_u32_word_order() {
        let root =
            "0x1111111122222222333333334444444455555555666666667777777788888888";
        assert_eq!(
            normalize_l1_root_for_services(root),
            "0x8888888877777777666666665555555544444444333333332222222211111111"
        );
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
    fn claim_pending_withdrawal_calldata_has_only_nonce_argument() {
        let calldata = claimPendingWithdrawalCall { nonce: B256::repeat_byte(0x5a) }.abi_encode();
        assert_eq!(calldata.len(), 4 + 32);
        assert_eq!(&calldata[..4], &keccak256("claimPendingWithdrawal(bytes32)")[..4]);
        assert_eq!(&calldata[4..], B256::repeat_byte(0x5a).as_slice());
    }

    #[test]
    fn pending_settlement_classifies_completion_and_eta_boundaries() {
        assert_eq!(
            classify_pending_settlement(U256::ZERO, 100, 0),
            PendingSettlement::AlreadySettled
        );
        assert_eq!(
            classify_pending_settlement(U256::from(1), 100, 99),
            PendingSettlement::Timelocked { claimable_at: 100, now: 99 }
        );
        assert_eq!(
            classify_pending_settlement(U256::from(1), 100, 100),
            PendingSettlement::Claimable
        );
        assert_eq!(
            classify_pending_settlement(U256::from(1), 100, 101),
            PendingSettlement::Claimable
        );
    }

    #[test]
    fn pending_withdrawal_return_decodes_one_shot_abi_shape() {
        let token = Address::repeat_byte(0x11);
        let recipient = Address::repeat_byte(0x22);
        let amount = U256::from(123456u64);
        let claimable_at = 987654u64;
        let encoded = (token, recipient, amount, claimable_at).abi_encode();
        let decoded = pendingWithdrawalsCall::abi_decode_returns(&encoded).unwrap();
        assert_eq!(decoded.token, token);
        assert_eq!(decoded.recipient, recipient);
        assert_eq!(decoded.amount, amount);
        assert_eq!(decoded.claimableAt, claimable_at);
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

    // ── claim-scheduling fix (commit 7522ca93): poll-result classification ─

    /// Build a `WithdrawalClaimProofResult` with only the fields the
    /// classification tests need. `leaf_index` is the discriminator used to
    /// tell which candidate a call returned.
    fn proof_result(found: bool, leaf_index: Option<u32>) -> WithdrawalClaimProofResult {
        WithdrawalClaimProofResult {
            found,
            leaf_index,
            withdrawal_root: None,
            siblings: None,
        }
    }

    #[test]
    fn select_claim_proof_poll_result_prefers_final_over_not_ready_and_error() {
        // Defends the poll-result priority contract: a found=true final result
        // is preferred over a found=false not-ready result AND over a fetch
        // error (final > not_ready > err). A regression that swaps the `.or()`
        // ordering (preferring not_ready, or surfacing the error when a final
        // result exists) reddens this test. We distinguish the two results by
        // leaf_index so the assertion proves the final one was returned.
        let final_r = proof_result(true, Some(111));
        let not_ready = proof_result(false, Some(222));
        let chosen = select_claim_proof_poll_result(
            Some(final_r),
            Some(not_ready),
            Some(anyhow::anyhow!("transient fetch error")),
        )
        .expect("final result must win over not-ready and error");
        assert!(chosen.found, "final found=true must be returned, not the not-ready");
        assert_eq!(
            chosen.leaf_index,
            Some(111),
            "must return the final result, not the not-ready one"
        );
    }

    #[test]
    fn select_claim_proof_poll_result_returns_not_ready_when_no_final_so_caller_defers() {
        // Defends the found=false classification contract: when only a
        // not-ready (found=false) response was seen, the function must return
        // it — so the caller's `!proof_result.found` branch defers to the next
        // round — rather than erroring. A regression that errors on found=false
        // (the pre-fix behaviour, which misreported a not-yet-finalized root
        // as a fetch failure) would surface an error string instead and fail.
        let not_ready = proof_result(false, Some(222));
        let chosen = select_claim_proof_poll_result(None, Some(not_ready), None)
            .expect("not-ready result must be returned, not errored");
        assert!(!chosen.found);
        assert_eq!(chosen.leaf_index, Some(222));
    }

    #[test]
    fn select_claim_proof_poll_result_surfaces_real_error_when_no_response() {
        // Defends the error-surfacing contract: with no final and no not-ready
        // result but a real fetch error present, the function must surface
        // THAT error — not the generic "exhausted without response" string —
        // so the caller logs the actual failure cause. A regression that
        // discards last_err in favour of the generic message reddens this.
        let err = select_claim_proof_poll_result(None, None, Some(anyhow::anyhow!("RPC 503 upstream")))
            .unwrap_err();
        assert!(
            err.to_string().contains("RPC 503 upstream"),
            "must surface the real error, got: {err}"
        );
        assert!(
            !err.to_string().contains("without response"),
            "must not use the generic exhausted message when a real error exists: {err}"
        );
    }

}
