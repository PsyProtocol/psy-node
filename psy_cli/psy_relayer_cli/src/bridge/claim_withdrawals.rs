use std::{collections::HashMap, fs, future::Future, path::{Path, PathBuf}, pin::Pin, str::FromStr, sync::Arc};

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_network::TransactionBuilder;
use alloy_provider::{Provider, WalletProvider};
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, TransactionRequest};
use alloy_sol_types::{sol, SolCall, SolEvent};
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
    // Return values were added without touching the input types, so the
    // selector stays keccak256("batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])").
    // eth_call sees the arrays; a mined transaction is accounted from its
    // receipt events, which are the only outcome record a receipt carries.
    function batchClaimWithdrawal(
        uint256[8] proof,
        uint256[18] publicInputs,
        uint256[1088] slotData
    ) returns (uint8[] failedSlotIndexes, uint8[] failureReasons);

    event WithdrawalClaimItemFailed(bytes32 indexed nonce, uint8 indexed slotIndex, uint8 reason);
    event WithdrawalClaimBatchResult(
        bytes32 indexed batchCommit,
        uint8 realCount,
        uint8 succeededCount,
        uint8 failedCount
    );
    event WithdrawalPendingCreated(
        bytes32 indexed nonce,
        address indexed token,
        address indexed recipient,
        uint256 amount,
        uint64 claimableAt
    );


    struct TokenFlowConfig {
        uint128 minDepositAmount;
        uint128 depositCap;
        uint128 smallWithdrawalMax;
        uint128 mediumWithdrawalMax;
        uint128 totalWithdrawalCap;
        uint32 smallWithdrawalDelay;
        uint32 mediumWithdrawalDelay;
        uint32 largeWithdrawalDelay;
        bool configured;
    }

    function getTokenFlowConfig(address token) view returns (TokenFlowConfig);

    function totalWithdrawalAmount(address token) view returns (uint256);

    function getPauseFlags(address token) view returns (uint8 globalFlags, uint8 tokenFlags, uint8 effectiveFlags);

    function balanceOf(address account) view returns (uint256);

    function withdrawalSubtreeRoot() view returns (bytes32);

    function knownWithdrawalSubtreeRoots(bytes32 root) view returns (bool);
}

/// Per-slot skip reasons the contract emits. Anything outside this range makes
/// the receipt uninterpretable, so the whole chunk fails closed.
const REASON_HIGH_ADDRESS: u8 = 1;
const REASON_WRONG_CHAIN: u8 = 2;
const REASON_ZERO_ADDRESS: u8 = 3;
const REASON_ZERO_AMOUNT: u8 = 4;
const REASON_ALREADY_CLAIMED: u8 = 5;
const REASON_TOKEN_NOT_CONFIGURED: u8 = 6;
const REASON_REGISTRATION_PAUSED: u8 = 7;
const REASON_AMOUNT_OUT_OF_RANGE: u8 = 8;
const REASON_TOTAL_OVERFLOW: u8 = 9;
const REASON_CLAIMABLE_TIME_OVERFLOW: u8 = 10;
const CLAIM_FAILURE_REASON_MIN: u8 = REASON_HIGH_ADDRESS;
const CLAIM_FAILURE_REASON_MAX: u8 = REASON_CLAIMABLE_TIME_OVERFLOW;

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
    /// Broadcast-confirmed count: slots included in batchClaimWithdrawal
    /// transactions whose receipt came back status-success. Derived over
    /// `outcomes`.
    pub submitted_count: usize,
    /// The authoritative outcome for every attempted slot, in request order.
    /// Identical duplicate input rows keep one entry each — a later slot's
    /// outcome never overwrites or hides an earlier one, so a same-leaf
    /// registration and a same-leaf reason-5 failure both stay present.
    pub outcomes: Vec<ClaimOutcome>,
}

impl BatchWithdrawalsReport {
    pub fn resolved_count(&self) -> usize {
        self.submitted_count
    }

    pub fn count_by_action(&self, action: ClaimAction) -> usize {
        self.outcomes.iter().filter(|outcome| outcome.kind.action() == action).count()
    }
}

/// One outcome for one attempted slot. Identity detail comes from the
/// consumer's own pending-map entry keyed by `leaf_hash`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClaimOutcome {
    pub leaf_hash: String,
    pub kind: ClaimOutcomeKind,
    /// Known signed-transaction hash; `Some` exactly for
    /// [`ClaimOutcomeKind::Failed`]([`ClaimCode::ReceiptUnknown`]), `None`
    /// for everything else.
    pub tx_hash: Option<B256>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClaimOutcomeKind {
    /// Registered as a pending withdrawal this round.
    Registered,
    /// Not resolved; the code explains why and [`ClaimCode::action`] decides.
    Failed(ClaimCode),
}

impl ClaimOutcomeKind {
    pub fn action(self) -> ClaimAction {
        match self {
            Self::Registered => ClaimAction::Resolved,
            Self::Failed(code) => code.action(),
        }
    }
}

/// Why a leaf's claim attempt ended the way it did.
///
/// Contract variants mirror the on-chain `CLAIM_REASON_*` values 1..=10; the
/// numbers live only in `contract_reason`. Relayer-side variants are named
/// facts with no external numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClaimCode {
    /// Recipient or token address carries non-zero high bits.
    HighAddress,
    /// Destination chain is not this chain.
    WrongChain,
    ZeroAddress,
    ZeroAmount,
    /// Token has no flow configuration. Recheck: token flow config on L1.
    TokenNotConfigured,
    /// Withdrawal registration is paused. Recheck: token/global pause flags.
    RegistrationPaused,
    /// Amount outside the configured flow range.
    AmountOutOfRange,
    /// Token totals would overflow the cap. Recheck: token totals and cap.
    TotalOverflow,
    /// Claimable timestamp would overflow. Recheck: the claimable window.
    ClaimableOverflow,
    /// The nonce is consumed or registered by a withdrawal with a different
    /// tuple. A consumed nonce is consumed forever, so this payload can never
    /// claim through it.
    NonceConflict,
    /// Services proof missing; the L1 root is not finalized yet.
    ProofNotReady,
    /// A services or L1 read failed. Query first, then retry.
    RpcUnavailable,
    /// The transaction's landing is unknown. Query receipts/nullifiers/
    /// account nonce before any rebroadcast; never rebroadcast blindly.
    ReceiptUnknown,
    /// The guarded fee policy refused the pre-broadcast quote.
    FeeRefused,
    /// Bridge token liquidity is short.
    LiquidityShort,
    /// The receipt is missing, malformed, or self-inconsistent.
    MalformedReceipt,
    /// The withdrawal root is neither current nor historically known.
    RootUnauthorized,
    /// Services proof data is missing or malformed.
    ProofDataInvalid,
    ProofGenerationFailed,
    /// The broadcast was rejected (not a timeout).
    SendFailed,
    /// The transaction reverted on-chain; nothing was registered.
    BatchReverted,
}

/// What may happen next round. Derived from [`ClaimCode::action`] only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ClaimAction {
    /// Registered this round: clear attempts and drop the leaf from the
    /// pending set.
    Resolved,
    /// This exact payload can never succeed: retire with the code's label
    /// without burning more attempts.
    Terminal,
    /// Operator action or chain-state change required; the code names the
    /// recheck condition. Attempts are not spent and the leaf does not
    /// exhaust.
    OperatorPending,
    /// Held for a bounded retry/query cycle without spending an attempt.
    /// Receipt-unknown leaves must be queried through their recorded
    /// transaction hash before any rebroadcast.
    Held,
    /// A genuine failed attempt; counts toward the claim's 3-strike retirement.
    AttemptSpent,
}

impl ClaimCode {
    /// The one decision table. Nothing else may classify a code.
    pub fn action(self) -> ClaimAction {
        match self {
            Self::HighAddress
            | Self::WrongChain
            | Self::ZeroAddress
            | Self::ZeroAmount
            | Self::AmountOutOfRange
            | Self::NonceConflict => ClaimAction::Terminal,
            Self::TokenNotConfigured
            | Self::RegistrationPaused
            | Self::TotalOverflow
            | Self::ClaimableOverflow => ClaimAction::OperatorPending,
            | Self::MalformedReceipt
            | Self::RootUnauthorized
            | Self::ProofDataInvalid
            | Self::ProofGenerationFailed
            | Self::SendFailed
            | Self::BatchReverted => ClaimAction::AttemptSpent,
            Self::ProofNotReady
            | Self::RpcUnavailable
            | Self::ReceiptUnknown
            | Self::FeeRefused
            | Self::LiquidityShort => ClaimAction::Held,
        }
    }

    /// Human label for logs and retirement records, rendered from the same
    /// table — never a second classification.
    pub fn label(self) -> &'static str {
        match self {
            Self::HighAddress => "recipient or token address has non-zero high bits",
            Self::WrongChain => "wrong destination chain",
            Self::ZeroAddress => "zero address",
            Self::ZeroAmount => "withdrawal amount is zero",
            Self::TokenNotConfigured => "token not configured",
            Self::RegistrationPaused => "withdrawal registration paused",
            Self::AmountOutOfRange => "withdrawal amount is out of range",
            Self::TotalOverflow => "total withdrawal amount overflow",
            Self::ClaimableOverflow => "claimable time overflow",
            Self::NonceConflict => "nonce is registered for a different withdrawal",
            Self::ProofNotReady => "withdrawal claim proof not available yet; L1 root not finalized",
            Self::RpcUnavailable => "claim state read failed",
            Self::ReceiptUnknown => "claim transaction outcome unknown; query before rebroadcast",
            Self::FeeRefused => "pre-broadcast fee quote refused",
            Self::LiquidityShort => "bridge ERC20 liquidity insufficient",
            Self::MalformedReceipt => "claim receipt is missing, malformed, or inconsistent",
            Self::RootUnauthorized => "withdrawal root is not current or known",
            Self::ProofDataInvalid => "claim proof data from services is missing or malformed",
            Self::ProofGenerationFailed => "withdrawal batch proof generation failed",
            Self::SendFailed => "batchClaimWithdrawal send failed",
            Self::BatchReverted => "batchClaimWithdrawal reverted on-chain",
        }
    }
}

/// Map a contract `WithdrawalClaimItemFailed` reason to its code. Reason 5
/// never lands here: the caller maps it to `NonceConflict` directly.
fn contract_reason(reason: u8) -> ClaimCode {
    match reason {
        1 => ClaimCode::HighAddress,
        2 => ClaimCode::WrongChain,
        3 => ClaimCode::ZeroAddress,
        4 => ClaimCode::ZeroAmount,
        6 => ClaimCode::TokenNotConfigured,
        7 => ClaimCode::RegistrationPaused,
        8 => ClaimCode::AmountOutOfRange,
        9 => ClaimCode::TotalOverflow,
        10 => ClaimCode::ClaimableOverflow,
        other => unreachable!(
            "reason {other} is outside the parser's 1..=10 range and not the tuple-resolved reason 5"
        ),
    }
}

/// One outcome slot per requested row: pre-send failures write their own
/// row; chunk outcomes write through `PendingProof.index`. Nothing here
/// deduplicates — identical duplicate rows keep their own entries.
type OutcomeSlots = Vec<Option<ClaimOutcome>>;

fn fail_row(outcomes: &mut OutcomeSlots, index: usize, leaf_hash: &str, code: ClaimCode) {
    outcomes[index] = Some(ClaimOutcome {
        leaf_hash: leaf_hash.to_string(),
        kind: ClaimOutcomeKind::Failed(code),
        tx_hash: None,
    });
}

#[derive(Clone, Args)]
pub struct BatchWithdrawalsArgs {
    /// Optional guarded BSC fee policy as JSON (all prices in wei).
    #[arg(long)]
    pub l1_fee_policy: Option<super::l1_fees::BscFeePolicy>,
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

pub(crate) fn nonce_hex(words: [u32; 8]) -> String {
    u32x8_to_hex(words)
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

fn withdrawal_nullifier_from_nonce(nonce: [u32; 8]) -> B256 {
    let mut nonce_bytes = [0u8; 32];
    for (i, word) in nonce.iter().enumerate() {
        nonce_bytes[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    B256::from(nonce_bytes)
}


/// keccak256 over the low 4 bytes of every slot word: the exact preimage
/// `_computeWithdrawalBatchSlotDataCommit` hashes on-chain.
fn batch_commit_from_slot_data(
    slot_data: &[U256; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS],
) -> B256 {
    let mut buf = Vec::with_capacity(slot_data.len() * 4);
    for word in slot_data {
        let be = word.to_be_bytes::<32>();
        buf.extend_from_slice(&be[28..32]);
    }
    keccak256(&buf)
}

struct SentClaimBatch {
    batch_commit: B256,
}

fn sent_claim_batch(call_data: &[u8], chunk_len: usize) -> Result<SentClaimBatch> {
    let decoded = batchClaimWithdrawalCall::abi_decode(call_data)
        .context("failed to decode batchClaimWithdrawal calldata")?;
    anyhow::ensure!(
        decoded.publicInputs[8] == U256::from(chunk_len),
        "proof realCount {} does not match the {} withdrawals sent",
        decoded.publicInputs[8],
        chunk_len
    );
    Ok(SentClaimBatch {
        batch_commit: batch_commit_from_slot_data(&decoded.slotData),
    })
}

pub(crate) fn recorded_claim_batch(call_data: &[u8]) -> Result<(Vec<PendingWithdrawal>, Vec<u8>)> {
    let decoded = batchClaimWithdrawalCall::abi_decode(call_data).context("recorded claim input is not batchClaimWithdrawal")?;
    let count = usize::try_from(decoded.publicInputs[8]).context("recorded claim realCount does not fit")?;
    anyhow::ensure!((1..=MAX_WITHDRAWAL_CLAIM_BATCH_SIZE).contains(&count), "recorded claim realCount is outside the batch");
    let mut batch = Vec::with_capacity(count);
    for slot in 0..count {
        let offset = slot * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
        let sender = u64::try_from(decoded.slotData[offset]).context("recorded sender does not fit")?;
        let recipient = slot_words(&decoded.slotData, offset + 1).context("recorded recipient words")?;
        let token = slot_words(&decoded.slotData, offset + 9).context("recorded token words")?;
        let amount = slot_words(&decoded.slotData, offset + 17).context("recorded amount words")?;
        let nonce = slot_words(&decoded.slotData, offset + 25).context("recorded nonce words")?;
        let destination = u64::try_from(decoded.slotData[offset + 33]).context("recorded destination does not fit")?;
        let leaf_hash = crate::bridge::propose_withdrawals::compute_withdrawal_leaf_hash(sender, recipient, token, amount, nonce, destination)?;
        batch.push(PendingWithdrawal {
            event_id: 0, checkpoint_id: 0, user_id: sender, sender_user_id: sender, contract_id: 0,
            destination_chain_index: destination, token_address: token, amount, recipient, nonce, leaf_hash,
        });
    }
    Ok((batch, call_data.to_vec()))
}

/// Recorded calldata is self-recorded output, so every slot word must fit
/// u32 exactly; set high bits mean the input is not what this relayer
/// produced — fail closed instead of silently truncating.
fn slot_words(slot_data: &[U256], offset: usize) -> Result<[u32; 8]> {
    let mut words = [0u32; 8];
    for (index, word) in words.iter_mut().enumerate() {
        let bytes = slot_data[offset + index].to_be_bytes::<32>();
        anyhow::ensure!(
            bytes[..28].iter().all(|byte| *byte == 0),
            "recorded slot word {} carries high bits; refusing to truncate",
            offset + index
        );
        *word = u32::from_be_bytes(bytes[28..32].try_into().expect("four bytes"));
    }
    Ok(words)
}

struct ClaimSlotIdentity {
    nonce: B256,
    token: Address,
    recipient: Address,
    amount: U256,
}

fn claim_slot_identity(withdrawal: &PendingWithdrawal) -> ClaimSlotIdentity {
    ClaimSlotIdentity {
        nonce: withdrawal_nullifier_from_nonce(withdrawal.nonce),
        token: u32x8_to_address(withdrawal.token_address),
        recipient: u32x8_to_address(withdrawal.recipient),
        amount: u32x8_to_u256(withdrawal.amount),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimSlotOutcome {
    Registered,
    /// The receipt ties this slot's nonce to a withdrawal with a different
    /// token, recipient, or amount. A different leaf owns that nonce, so this
    /// slot is failed on its own and its chunk-mates stay resolvable.
    NonceConflict,
    Failed { reason: u8 },
}

struct ParsedClaimReceipt {
    outcomes: Vec<ClaimSlotOutcome>,
}

/// The nonce is the map key, so identity is token, recipient, and amount.
fn registration_matches(event: &WithdrawalPendingCreated, identity: &ClaimSlotIdentity) -> bool {
    event.token == identity.token
        && event.recipient == identity.recipient
        && event.amount == identity.amount
}

/// Account one confirmed batch from its receipt.
///
/// Only logs emitted by `bridge` count. The batch summary must name the commit
/// and real count of the calldata actually sent, and the failed-slot events
/// must reproduce that summary with each slot's own nonce; breaking any of
/// that makes the whole receipt unusable. A succeeded slot whose registration
/// names different content is a per-slot nonce conflict, not a chunk failure:
/// nonces are not unique across slots, so slots are joined by index.
fn parse_claim_receipt(
    logs: &[alloy_rpc_types_eth::Log],
    bridge: Address,
    expected_batch_commit: B256,
    slots: &[ClaimSlotIdentity],
) -> Result<ParsedClaimReceipt> {
    anyhow::ensure!(
        !slots.is_empty() && slots.len() <= MAX_WITHDRAWAL_CLAIM_BATCH_SIZE,
        "real count {} is outside 1..={}",
        slots.len(),
        MAX_WITHDRAWAL_CLAIM_BATCH_SIZE
    );

    let mut summary = None;
    let mut failed_events = Vec::new();
    let mut pending_created = Vec::new();
    for log in logs {
        let log = &log.inner;
        if log.address != bridge {
            continue;
        }
        let Some(topic0) = log.topics().first() else { continue };
        if topic0 == &WithdrawalClaimBatchResult::SIGNATURE_HASH {
            let decoded = WithdrawalClaimBatchResult::decode_log_data(&log.data)
                .context("failed to decode WithdrawalClaimBatchResult")?;
            anyhow::ensure!(summary.is_none(), "receipt has two WithdrawalClaimBatchResult events");
            summary = Some(decoded);
        } else if topic0 == &WithdrawalClaimItemFailed::SIGNATURE_HASH {
            failed_events.push(
                WithdrawalClaimItemFailed::decode_log_data(&log.data)
                    .context("failed to decode WithdrawalClaimItemFailed")?,
            );
        } else if topic0 == &WithdrawalPendingCreated::SIGNATURE_HASH {
            pending_created.push(
                WithdrawalPendingCreated::decode_log_data(&log.data)
                    .context("failed to decode WithdrawalPendingCreated")?,
            );
        }
    }

    let summary = summary.context("receipt is missing WithdrawalClaimBatchResult")?;
    anyhow::ensure!(
        summary.batchCommit == expected_batch_commit,
        "receipt batch commit {} does not match the sent batch",
        summary.batchCommit
    );
    let real_count = usize::from(summary.realCount);
    anyhow::ensure!(
        real_count == slots.len(),
        "receipt realCount {real_count} does not match the sent batch"
    );
    let succeeded = usize::from(summary.succeededCount);
    let failed = usize::from(summary.failedCount);
    anyhow::ensure!(
        succeeded + failed == real_count,
        "receipt counts {succeeded} succeeded + {failed} failed != realCount {real_count}"
    );
    anyhow::ensure!(
        failed_events.len() == failed,
        "receipt has {} WithdrawalClaimItemFailed events, summary says {failed}",
        failed_events.len()
    );

    let mut registrations: HashMap<B256, WithdrawalPendingCreated> = HashMap::new();
    for event in pending_created {
        let nonce = event.nonce;
        anyhow::ensure!(
            slots.iter().any(|slot| slot.nonce == nonce),
            "receipt registers nonce {nonce} which this batch did not send"
        );
        anyhow::ensure!(
            registrations.insert(nonce, event).is_none(),
            "receipt registers nonce {nonce} twice"
        );
    }
    anyhow::ensure!(
        registrations.len() == succeeded,
        "receipt has {} registrations, summary says {succeeded} succeeded",
        registrations.len()
    );

    let mut outcomes = vec![ClaimSlotOutcome::Registered; real_count];
    let mut seen_failed = vec![false; real_count];
    for event in &failed_events {
        let slot = usize::from(event.slotIndex);
        anyhow::ensure!(slot < real_count, "failed slot index {slot} is outside the batch");
        anyhow::ensure!(!seen_failed[slot], "slot {slot} failed twice in one receipt");
        seen_failed[slot] = true;
        anyhow::ensure!(
            event.nonce == slots[slot].nonce,
            "failed slot {slot} names nonce {}, not the nonce sent in that slot",
            event.nonce
        );
        anyhow::ensure!(
            (CLAIM_FAILURE_REASON_MIN..=CLAIM_FAILURE_REASON_MAX).contains(&event.reason),
            "failed slot {slot} has unknown reason {}",
            event.reason
        );
        outcomes[slot] = ClaimSlotOutcome::Failed { reason: event.reason };
    }

    for (slot_index, slot) in slots.iter().enumerate() {
        if seen_failed[slot_index] {
            continue;
        }
        let event = registrations.get(&slot.nonce).with_context(|| {
            format!("summary counts slot {slot_index} as succeeded but no WithdrawalPendingCreated carries its nonce")
        })?;
        if !registration_matches(event, slot) {
            outcomes[slot_index] = ClaimSlotOutcome::NonceConflict;
        }
    }

    Ok(ParsedClaimReceipt { outcomes })
}

/// Post-send reads pin to the receipt's own block after its hash has been
/// verified, so a reorged block or a drifting head cannot poison a read.
pub(crate) struct ReadPin {
    block_hash: B256,
    block_number: u64,
}

pub(crate) async fn verify_receipt_pin<P: Provider>(
    provider: &P,
    block_number: u64,
    block_hash: B256,
    tx_hash: B256,
) -> Result<ReadPin> {
    let pin = read_pin(provider, block_number, block_hash).await?;
    anyhow::ensure!(canonical_receipt(provider, &pin, tx_hash).await?, "claim receipt is not in its canonical block");
    Ok(pin)
}

async fn read_pin<P: Provider>(
    provider: &P,
    block_number: u64,
    block_hash: B256,
) -> Result<ReadPin> {
    let block = provider
        .get_block(BlockId::Number(BlockNumberOrTag::Number(block_number)))
        .await
        .context("failed to read the claim receipt block")?
        .with_context(|| format!("claim receipt block {block_number} not found"))?;
    anyhow::ensure!(
        block.header.hash == block_hash,
        "claim receipt block {block_number} does not carry the receipt's block hash; the receipt may be from a reorged block"
    );
    Ok(ReadPin { block_hash, block_number })
}

#[derive(serde::Deserialize)]
struct BridgeProxyDeployment {
    receipt: BridgeProxyReceipt,
}

#[derive(serde::Deserialize)]
struct BridgeProxyReceipt {
    #[serde(rename = "blockNumber")]
    block_number: u64,
}

/// Bridge deployment block for bounded historical scans, from the deployment
/// artifact. A missing or unreadable artifact falls back to the earliest
/// block with a warning; it never invents a block number.
pub(crate) fn bridge_deployment_block(deployments_network: &str) -> u64 {
    let path =
        crate::bridge::api_client::resolve_deployments_file(deployments_network, "Bridge_Proxy.json");
    match fs::read_to_string(&path) {
        Ok(raw) => match serde_json::from_str::<BridgeProxyDeployment>(&raw) {
            Ok(artifact) => artifact.receipt.block_number,
            Err(_) => {
                tracing::warn!(
                    path = %path.display(),
                    "Bridge_Proxy.json parse failed; registration history scans start at the earliest block"
                );
                1
            }
        },
        Err(_) => {
            tracing::warn!(
                path = %path.display(),
                "Bridge_Proxy.json missing; registration history scans start at the earliest block"
            );
            1
        }
    }
}

fn fail_chunk(chunk: &[PendingProof], outcomes: &mut OutcomeSlots, code: ClaimCode) {
    for claim in chunk {
        outcomes[claim.index] = Some(ClaimOutcome {
            leaf_hash: claim.withdrawal.leaf_hash.clone(),
            kind: ClaimOutcomeKind::Failed(code),
            tx_hash: None,
        });
    }
}


/// Apply one mined, status-successful claim transaction.
///
/// A missing or malformed receipt fails the whole chunk closed with nothing
/// resolved. Per-slot content conflicts — a nonce another withdrawal consumed
/// or registered — fail only their own leaf, and the chunk's good slots stay
/// resolved. A reverted transaction never reaches here. The result is one
/// outcome per slot, aligned with `chunk`; the caller owns row placement.
fn apply_confirmed_claim_receipt(
    bridge: Address,
    logs: &[alloy_rpc_types_eth::Log],
    call_data: &[u8],
    chunk: &[PendingProof],
) -> Vec<ClaimOutcome> {
    let chunk_failure = |code: ClaimCode| {
        chunk
            .iter()
            .map(|claim| ClaimOutcome {
                leaf_hash: claim.withdrawal.leaf_hash.clone(),
                kind: ClaimOutcomeKind::Failed(code),
                tx_hash: None,
            })
            .collect::<Vec<_>>()
    };
    let sent = match sent_claim_batch(call_data, chunk.len()) {
        Ok(sent) => sent,
        Err(error) => {
            tracing::error!(error = %error, "claim calldata could not be re-decoded");
            return chunk_failure(ClaimCode::MalformedReceipt);
        }
    };
    let identities: Vec<ClaimSlotIdentity> =
        chunk.iter().map(|pending| claim_slot_identity(&pending.withdrawal)).collect();
    let parsed = match parse_claim_receipt(logs, bridge, sent.batch_commit, &identities) {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::error!(error = %error, "claim receipt is malformed or inconsistent");
            return chunk_failure(ClaimCode::MalformedReceipt);
        }
    };

    parsed
        .outcomes
        .iter()
        .enumerate()
        .map(|(slot, slot_outcome)| {
            let leaf_hash = chunk[slot].withdrawal.leaf_hash.clone();
            let kind = match *slot_outcome {
                ClaimSlotOutcome::Registered => ClaimOutcomeKind::Registered,
                ClaimSlotOutcome::NonceConflict => {
                    tracing::warn!(
                        leaf_hash,
                        nonce = %identities[slot].nonce,
                        "slot's nonce is tied to a different withdrawal"
                    );
                    ClaimOutcomeKind::Failed(ClaimCode::NonceConflict)
                }
                ClaimSlotOutcome::Failed { reason: REASON_ALREADY_CLAIMED } => {
                    // The nonce is consumed. L1 registration events omit the
                    // sender, and registration history is not authoritative for
                    // this leaf, so reason 5 is always a consumed nonce here.
                    ClaimOutcomeKind::Failed(ClaimCode::NonceConflict)
                }
                ClaimSlotOutcome::Failed { reason } => ClaimOutcomeKind::Failed(contract_reason(reason)),
            };
            ClaimOutcome { leaf_hash, kind, tx_hash: None }
        })
        .collect()
}

/// Pause flag `PAUSE_WITHDRAWAL_REGISTRATION` in Bridge.sol.
const PAUSE_WITHDRAWAL_REGISTRATION: u8 = 1 << 1;

fn flow_delay(config: &TokenFlowConfig, amount: U256, next_total: U256) -> u32 {
    if amount > U256::from(config.mediumWithdrawalMax) || next_total > U256::from(config.totalWithdrawalCap) {
        config.largeWithdrawalDelay
    } else if amount > U256::from(config.smallWithdrawalMax) {
        config.mediumWithdrawalDelay
    } else {
        config.smallWithdrawalDelay
    }
}

async fn view_call<P: Provider, C: SolCall>(provider: &P, bridge: Address, call: C) -> Result<C::Return> {
    let tx = TransactionRequest::default().to(bridge).input(call.abi_encode().into());
    let raw = provider.call(tx).await.context("bridge view call failed")?;
    C::abi_decode_returns(&raw).context("bridge view return did not decode")
}

/// Whether the chain condition named by an operator hold has cleared.
///
/// A read that fails is an error, and the caller keeps the hold. The checks
/// are the contract's own: pause flags for registration, `configured` for the
/// token, the addition overflow for the running total, and the claimable
/// timestamp overflow. A total above the cap is not one of them — the contract
/// registers that withdrawal with the large delay.
pub(crate) async fn operator_condition_cleared<P: Provider>(
    provider: &P,
    bridge: Address,
    withdrawal: &PendingWithdrawal,
    code: ClaimCode,
) -> Result<bool> {
    let identity = claim_slot_identity(withdrawal);
    match code {
        ClaimCode::RegistrationPaused => {
            let flags = view_call(provider, bridge, getPauseFlagsCall { token: identity.token }).await?;
            Ok(flags.effectiveFlags & PAUSE_WITHDRAWAL_REGISTRATION == 0)
        }
        ClaimCode::TokenNotConfigured => {
            let config = view_call(provider, bridge, getTokenFlowConfigCall { token: identity.token }).await?;
            Ok(config.configured)
        }
        ClaimCode::TotalOverflow => {
            let total = view_call(provider, bridge, totalWithdrawalAmountCall { token: identity.token }).await?;
            Ok(identity.amount <= U256::MAX - total)
        }
        ClaimCode::ClaimableOverflow => {
            let config = view_call(provider, bridge, getTokenFlowConfigCall { token: identity.token }).await?;
            let total = view_call(provider, bridge, totalWithdrawalAmountCall { token: identity.token }).await?;
            if identity.amount > U256::MAX - total {
                return Ok(false);
            }
            let next_total = total + identity.amount;
            let block = provider
                .get_block(alloy_rpc_types_eth::BlockId::latest())
                .await
                .context("latest block read failed")?
                .context("latest block missing")?;
            let timestamp = U256::from(block.header.timestamp);
            let delay = U256::from(flow_delay(&config, identity.amount, next_total));
            Ok(timestamp <= U256::from(u64::MAX) - delay)
        }
        _ => Ok(false),
    }
}

fn single_leaf_report(
    withdrawal: &PendingWithdrawal,
    kind: ClaimOutcomeKind,
    tx_hash: Option<B256>,
) -> BatchWithdrawalsReport {
    BatchWithdrawalsReport {
        requested: 1,
        submitted_count: usize::from(kind == ClaimOutcomeKind::Registered),
        outcomes: vec![ClaimOutcome { leaf_hash: withdrawal.leaf_hash.clone(), kind, tx_hash }],
    }
}

/// The recorded transaction reverted. One attempt is spent and nothing is sent
/// in its place.
pub(crate) fn reverted_claim_report(withdrawal: &PendingWithdrawal) -> BatchWithdrawalsReport {
    single_leaf_report(withdrawal, ClaimOutcomeKind::Failed(ClaimCode::BatchReverted), None)
}

/// Account one leaf from a transaction whose receipt came back later.
///
/// `batch` is the chunk that was signed, in submitted order, so the receipt is
/// classified by the same commit, counts, failed-slot nonce, and registration
/// tuple as an immediate receipt. `withdrawal` is one leaf of that batch. The
/// returned report covers the whole batch: every slot keeps its own leaf and
/// typed reason, in submitted order, and this leaf's unresolved slots carry
/// `known_tx`. `scan_start` and `pin` are carried for the caller's signature;
/// no historical ownership scan runs here.
pub(crate) async fn apply_recorded_claim_receipt<P: Provider>(
    _provider: &P,
    bridge: Address,
    receipt: &alloy_rpc_types_eth::TransactionReceipt,
    batch: &[PendingWithdrawal],
    withdrawal: &PendingWithdrawal,
    call_data: &[u8],
    _scan_start: u64,
    _pin: Option<&ReadPin>,
    known_tx: B256,
) -> BatchWithdrawalsReport {
    let chunk: Vec<PendingProof> = batch.iter().cloned().map(pending_proof_shell).collect();
    let mut outcomes = apply_confirmed_claim_receipt(bridge, receipt.logs(), call_data, &chunk);
    for outcome in &mut outcomes {
        // The receipt cannot be interpreted for this slot; the recorded
        // transaction's landing stays unknown until it is queried again.
        if matches!(outcome.kind, ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt | ClaimCode::RpcUnavailable)) {
            outcome.kind = ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown);
        }
    }
    if !outcomes.iter().any(|outcome| outcome.leaf_hash == withdrawal.leaf_hash) {
        outcomes.push(ClaimOutcome {
            leaf_hash: withdrawal.leaf_hash.clone(),
            kind: ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown),
            tx_hash: None,
        });
    }
    for outcome in &mut outcomes {
        if outcome.leaf_hash == withdrawal.leaf_hash
            && outcome.kind == ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown)
        {
            outcome.tx_hash = Some(known_tx);
        }
    }
    let submitted_count = outcomes
        .iter()
        .filter(|outcome| outcome.kind == ClaimOutcomeKind::Registered)
        .count();
    BatchWithdrawalsReport {
        requested: batch.len(),
        submitted_count,
        outcomes,
    }
}

fn pending_proof_shell(withdrawal: PendingWithdrawal) -> PendingProof {
    PendingProof {
        index: 0,
        withdrawal,
        leaf_index: 0,
        withdrawal_root: QHashOut::default(),
        siblings: Vec::new(),
    }
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

enum ClaimSend {
    Rejected(alloy_json_rpc::RpcError<alloy_transport::TransportErrorKind>),
    Unknown(alloy_json_rpc::RpcError<alloy_transport::TransportErrorKind>),
}

fn broadcast_was_rejected(error: &alloy_json_rpc::RpcError<alloy_transport::TransportErrorKind>) -> bool {
    matches!(error, alloy_json_rpc::RpcError::LocalUsageError(_))
}

async fn sign_claim(provider: &crate::bridge::l1_provider::ClaimWalletProvider, tx: TransactionRequest) -> std::result::Result<alloy_consensus::TxEnvelope, ClaimSend> {
    match provider.fill(tx).await.map_err(|error| {
        if broadcast_was_rejected(&error) { ClaimSend::Rejected(error) } else { ClaimSend::Unknown(error) }
    })? {
        alloy_provider::SendableTx::Envelope(envelope) => Ok(envelope),
        alloy_provider::SendableTx::Builder(_) => Err(ClaimSend::Rejected(alloy_json_rpc::RpcError::local_usage_str("claim fill did not sign the transaction"))),
    }
}

/// A chunk whose broadcast landing is unknown: every member carries the same
/// signed hash — that one transaction's outcome is unknown for all of them —
/// and the hash is recorded so no later chunk re-signs any of these leaves.
fn hold_unknown(
    chunk: &[PendingProof],
    outcomes: &mut OutcomeSlots,
    hashes: &mut HashMap<String, B256>,
    tx_hash: B256,
) {
    for claim in chunk {
        outcomes[claim.index] = Some(ClaimOutcome {
            leaf_hash: claim.withdrawal.leaf_hash.clone(),
            kind: ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown),
            tx_hash: Some(tx_hash),
        });
        hashes.entry(claim.withdrawal.leaf_hash.clone()).or_insert(tx_hash);
    }
}

async fn canonical_receipt<P: Provider>(provider: &P, pin: &ReadPin, tx_hash: B256) -> Result<bool> {
    let block = provider.get_block(BlockId::Hash(pin.block_hash.into())).hashes().await?.context("receipt block missing")?;
    let listed = block.transactions.as_hashes().context("receipt block did not return transaction hashes")?.contains(&tx_hash);
    if !listed || block.header.number != pin.block_number { return Ok(false); }
    let again = provider.get_block(BlockId::Number(BlockNumberOrTag::Number(pin.block_number))).await?.context("receipt block number missing")?;
    Ok(again.header.hash == pin.block_hash)
}
pub(crate) type BeforeBroadcast = Arc<
    dyn Fn(&[PendingWithdrawal], B256) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync,
>;

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
    fee_policy: Option<&super::l1_fees::BscFeePolicy>,
) -> Result<BatchWithdrawalsReport> {
    submit_batch_with_hook(
        withdrawals, services_url, l1_rpc_url, bridge_address, multicall3_address, deployments_network,
        private_key, keystore_path, password_env, prove_proxy_url, fee_policy, None,
    ).await
}

pub async fn submit_batch_with_hook(
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
    fee_policy: Option<&super::l1_fees::BscFeePolicy>,
    before_broadcast: Option<BeforeBroadcast>,
) -> Result<BatchWithdrawalsReport> {
    let _phantom_c: std::marker::PhantomData<C> = std::marker::PhantomData;
    if withdrawals.is_empty() {
        return Ok(BatchWithdrawalsReport {
            requested: 0,
            submitted_count: 0,
            outcomes: Vec::new(),
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
    // All fee preparation failures occur before broadcast, so preserve claims
    // without spending their limited attempts, even during an RPC outage.
    if let Err(error) = super::l1_fees::prepare_l1_fees(
        &provider, &mut TransactionRequest::default(), fee_policy,
    ).await {
        tracing::warn!(%error, "withdrawal fees held before proof generation");
        return Ok(BatchWithdrawalsReport {
            requested: withdrawals.len(),
            submitted_count: 0,
            outcomes: withdrawals
                .iter()
                .map(|w| ClaimOutcome {
                    leaf_hash: w.leaf_hash.clone(),
                    kind: ClaimOutcomeKind::Failed(ClaimCode::FeeRefused),
                    tx_hash: None,
                })
                .collect(),
        });
    }
    let http = build_default_http_client()?;
    // One outcome slot per requested row, in request order.
    let mut outcomes: OutcomeSlots = vec![None; withdrawals.len()];
    let mut unknown_tx_hashes: HashMap<String, B256> = HashMap::new();
    if multicall3_address.is_some() || !deployments_network.is_empty() {
        let _ = (multicall3_address, deployments_network);
    }
    let mut pending_proofs: Vec<PendingProof> = Vec::new();
    for (i, w) in withdrawals.iter().enumerate() {
        let state_manager: Address = resolve_contract_address_from_deployments(&deployments_network, "StateManager")
            .context("failed to resolve StateManager address from deployments")?;
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
                tracing::error!(index = i, leaf_hash = %w.leaf_hash, error = %err, "fetch claim proof failed, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::RpcUnavailable);
                continue;
            }
        };

        if !proof_result.found {
            tracing::info!(index = i, leaf_hash = %w.leaf_hash, "withdrawal claim proof not available yet (L1 root not finalized); holding to next round");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofNotReady);
            continue;
        }
        if let Some(root_hex) = &proof_result.withdrawal_root {
            match check_withdrawal_root_on_l1(&provider, state_manager, root_hex).await {
                Ok((true, _)) => {}
                Ok((false, l1_root)) => {
                    tracing::warn!(index = i, leaf_hash = %w.leaf_hash, services_root = %root_hex, l1_root = %l1_root, "withdrawal root is not current or known after retries, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::RootUnauthorized);
                    continue;
                }
                Err(err) => {
                    tracing::error!(index = i, leaf_hash = %w.leaf_hash, error = %err, "failed to read L1 withdrawal root, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::RpcUnavailable);
                    continue;
                }
            }
        }

        let leaf_index = match proof_result.leaf_index {
            Some(idx) => idx,
            None => {
                tracing::warn!(index = i, "claim proof missing leaf_index, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofDataInvalid);
                continue;
            }
        };

        let withdrawal_root_hex = match proof_result.withdrawal_root.as_deref() {
            Some(s) => s.to_string(),
            None => {
                tracing::warn!(index = i, "claim proof missing withdrawal_root, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofDataInvalid);
                continue;
            }
        };

        let siblings_hex = match proof_result.siblings.as_ref() {
            Some(s) if s.len() == 32 => s.clone(),
            _ => {
                tracing::warn!(index = i, "claim proof has invalid siblings (need 32), skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofDataInvalid);
                continue;
            }
        };

        let withdrawal_root = match parse_solidity_qhash(&withdrawal_root_hex) {
            Ok(r) => r,
            Err(err) => {
                tracing::error!(index = i, error = %err, "failed to parse withdrawal_root, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofDataInvalid);
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
                tracing::error!(index = i, error = %err, "failed to parse siblings, skipping");
                fail_row(&mut outcomes, i, &w.leaf_hash, ClaimCode::ProofDataInvalid);
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

    // ── Phase 3: collect ready chunks in order, then sign and submit ──
    let mut ready_chunks: Vec<ReadyChunk> = Vec::new();
    for (idx, meta) in all_chunks.into_iter().enumerate() {
        let call_data = match chunk_proofs[idx]
            .take()
            .ok_or_else(|| anyhow::anyhow!("missing proof result for chunk {}", idx))?
        {
            Ok(call_data) => call_data,
            Err(err) => {
                fail_chunk(&meta.chunk, &mut outcomes, ClaimCode::ProofGenerationFailed);
                tracing::error!(
                    root = %meta.root_hex,
                    count = meta.chunk.len(),
                    error = %err,
                    "withdrawal batch proof generation failed"
                );
                continue;
            }
        };
        ready_chunks.push(ReadyChunk { root_hex: meta.root_hex, chunk: meta.chunk, call_data });
    }

    submit_chunks(
        &provider,
        bridge,
        &ready_chunks,
        fee_policy,
        before_broadcast.as_ref(),
        &mut outcomes,
        &mut unknown_tx_hashes,
    )
    .await;

    let ordered: Vec<ClaimOutcome> = outcomes.into_iter().flatten().collect();
    let submitted_count = ordered
        .iter()
        .filter(|outcome| outcome.kind == ClaimOutcomeKind::Registered)
        .count();

    Ok(BatchWithdrawalsReport {
        requested: withdrawals.len(),
        submitted_count,
        outcomes: ordered,
    })
}

/// A chunk with its generated proof calldata, ready to sign and broadcast.
struct ReadyChunk {
    root_hex: String,
    chunk: Vec<PendingProof>,
    call_data: Bytes,
}

/// Phase 3: sign and broadcast ready chunks sequentially, in order.
///
/// Every failure path records one outcome per chunk row before moving on, so
/// later chunks always produce their own verdicts and the report keeps
/// per-slot facts in request order.
///
/// The unresolved-leaf gate runs BEFORE signing and before the persistence
/// hook: the hook writes signed hashes durably, so a gate placed after it
/// would overwrite a leaf's recorded unresolved hold with a never-broadcast
/// hash. Affected rows stay held on their recorded hash; safe chunk-mates are
/// deferred with `RpcUnavailable` — nothing was spent and no fake unknown is
/// recorded for them.
async fn submit_chunks(
    provider: &crate::bridge::l1_provider::ClaimWalletProvider,
    bridge: Address,
    chunks: &[ReadyChunk],
    fee_policy: Option<&super::l1_fees::BscFeePolicy>,
    before_broadcast: Option<&BeforeBroadcast>,
    outcomes: &mut OutcomeSlots,
    unknown_tx_hashes: &mut HashMap<String, B256>,
) {
    for ReadyChunk { root_hex, chunk, call_data } in chunks {
        if chunk.iter().any(|claim| unknown_tx_hashes.contains_key(&claim.withdrawal.leaf_hash)) {
            for claim in chunk {
                match unknown_tx_hashes.get(&claim.withdrawal.leaf_hash) {
                    Some(&hash) => {
                        outcomes[claim.index] = Some(ClaimOutcome {
                            leaf_hash: claim.withdrawal.leaf_hash.clone(),
                            kind: ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown),
                            tx_hash: Some(hash),
                        });
                    }
                    None => {
                        fail_row(
                            outcomes,
                            claim.index,
                            &claim.withdrawal.leaf_hash,
                            ClaimCode::RpcUnavailable,
                        );
                    }
                }
            }
            tracing::error!(
                root = %root_hex,
                "a chunk leaf already has an unresolved claim transaction; chunk skipped before signing, no second send"
            );
            continue;
        }

        let mut tx = TransactionRequest::default().to(bridge).input(call_data.clone().into());
        if let Err(error) = super::l1_fees::prepare_l1_fees(provider, &mut tx, fee_policy).await {
            tracing::warn!(%error, "withdrawal fee policy deferred chunk before broadcast");
            fail_chunk(chunk, outcomes, ClaimCode::FeeRefused);
            continue;
        }
        let gas = match provider.estimate_gas(tx.clone()).await {
            Ok(gas) => gas,
            Err(err) => {
                tracing::warn!(
                    root = %root_hex,
                    count = chunk.len(),
                    error = ?err,
                    fallback_gas = L1_GROTH16_CALL_GAS_FALLBACK,
                    "L1 batch withdrawal gas estimation failed; continuing with fallback assumption"
                );
                L1_GROTH16_CALL_GAS_FALLBACK
            }
        };

        tx.set_gas_limit(gas);
        let signed = match sign_claim(provider, tx).await {
            Ok(envelope) => envelope,
            Err(ClaimSend::Rejected(error)) => {
                fail_chunk(chunk, outcomes, ClaimCode::SendFailed);
                tracing::error!(root = %root_hex, error = %error, "claim was rejected before broadcast");
                continue;
            }
            Err(ClaimSend::Unknown(error)) => {
                fail_chunk(chunk, outcomes, ClaimCode::RpcUnavailable);
                tracing::error!(root = %root_hex, error = %error, "claim fill failed before broadcast; no send");
                continue;
            }
        };
        let tx_hash = *signed.tx_hash();
        let leaves: Vec<PendingWithdrawal> = chunk.iter().map(|claim| claim.withdrawal.clone()).collect();
        if let Some(hook) = before_broadcast {
            if let Err(error) = hook(&leaves, tx_hash).await {
                fail_chunk(chunk, outcomes, ClaimCode::RpcUnavailable);
                tracing::error!(root = %root_hex, error = %error, "signed claim was not persisted; broadcast aborted");
                continue;
            }
        }
        tracing::info!(root = %root_hex, tx_hash = %tx_hash, count = chunk.len(), "sending signed batchClaimWithdrawal");
        let pending = match timeout(Duration::from_secs(L1_TX_SEND_TIMEOUT_SECS), provider.send_tx_envelope(signed)).await {
            Ok(Ok(pending)) => pending,
            Ok(Err(error)) if broadcast_was_rejected(&error) => {
                fail_chunk(chunk, outcomes, ClaimCode::SendFailed);
                tracing::error!(root = %root_hex, tx_hash = %tx_hash, error = %error, "signed claim broadcast was rejected");
                continue;
            }
            Ok(Err(error)) => {
                hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                tracing::error!(root = %root_hex, tx_hash = %tx_hash, error = %error, "signed claim broadcast outcome is unknown");
                continue;
            }
            Err(_) => {
                hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                tracing::error!(root = %root_hex, tx_hash = %tx_hash, "signed claim broadcast timed out");
                continue;
            }
        };
        tracing::info!(root = %root_hex, tx_hash = %tx_hash, "batchClaimWithdrawal submitted; waiting for receipt");
        match timeout(Duration::from_secs(L1_TX_RECEIPT_TIMEOUT_SECS), pending.get_receipt()).await {
            Ok(Ok(receipt)) => {
                if receipt.transaction_hash != tx_hash {
                    hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                    tracing::error!(root = %root_hex, tx_hash = %tx_hash, "receipt names a different transaction");
                    continue;
                }
                let canonical = match (receipt.block_number, receipt.block_hash) {
                    (Some(number), Some(hash)) => match read_pin(provider, number, hash).await {
                        Ok(pin) => match canonical_receipt(provider, &pin, tx_hash).await {
                            Ok(true) => Some(pin),
                            Ok(false) | Err(_) => {
                                hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                                continue;
                            }
                        },
                        Err(_) => { hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash); continue; }
                    },
                    _ => { hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash); continue; }
                };
                if receipt.status() {
                    for (slot, outcome) in
                        apply_confirmed_claim_receipt(bridge, receipt.logs(), call_data, chunk)
                            .into_iter()
                            .enumerate()
                    {
                        outcomes[chunk[slot].index] = Some(outcome);
                    }
                } else {
                    fail_chunk(chunk, outcomes, ClaimCode::BatchReverted);
                }
            }
            Ok(Err(error)) => {
                hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                tracing::error!(tx_hash = %tx_hash, root = %root_hex, error = %error, "batchClaimWithdrawal receipt read failed");
            }
            Err(_) => {
                hold_unknown(chunk, outcomes, unknown_tx_hashes, tx_hash);
                tracing::error!(tx_hash = %tx_hash, root = %root_hex, "batchClaimWithdrawal receipt timed out");
            }
        }
    }
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
        args.l1_fee_policy.as_ref(),
    )
    .await?;

    println!(
        "batch withdrawals: requested={}, submitted_count={}, resolved={}, failed={}, held={}",
        report.requested,
        report.submitted_count,
        report.resolved_count(),
        report.count_by_action(ClaimAction::AttemptSpent),
        report.count_by_action(ClaimAction::Held),
    );
    anyhow::ensure!(
        args.l1_fee_policy.is_none()
            || !report
                .outcomes
                .iter()
                .any(|o| matches!(o.kind, ClaimOutcomeKind::Failed(ClaimCode::FeeRefused))),
        "withdrawal claims held on refused fee quotes; not all requested claims were submitted"
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
        SendError(&'static str),
        RpcError(&'static str),
    }

    async fn serve_eth_calls(
        listener: TcpListener,
        calls: Vec<EthCall>,
        seen: Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        let current_sel = hex::encode(withdrawalSubtreeRootCall {}.abi_encode());
        let known_sel = hex::encode(knownWithdrawalSubtreeRootsCall { root: B256::ZERO }.abi_encode());
        let current_sel = &current_sel[..8];
        let known_sel = &known_sel[..8];
        let mut remaining = calls;
        while !remaining.is_empty() {
            let (actual, mut socket, _) = read_http_exchange(&listener).await;
            let method = actual["method"].as_str().unwrap_or("");
            seen.lock().expect("fixture seen lock").push(method.to_string());
            if method != "eth_call" {
                if method == "eth_sendRawTransaction"
                    && matches!(remaining.first(), Some(EthCall::SendError(_)))
                {
                    let EthCall::SendError(message) = remaining.remove(0)
                    else {
                        unreachable!("checked above")
                    };
                    let body = json!({"jsonrpc":"2.0","id": actual["id"], "error": {"code": -32000, "message": message}}).to_string();
                    write_http(&mut socket, "200 OK", &body).await;
                    continue;
                }
                let result = match method {
                    // GasFiller's EIP-1559 path reads fee history; a zero base
                    // fee would send it after the block itself.
                    "eth_feeHistory" => json!({"oldestBlock": "0x1", "baseFeePerGas": ["0x1"], "reward": [["0x1"]], "gasUsedRatio": [0.5]}),
                    // The estimator's latest-block fallback must deserialize as
                    // a real alloy Block; same shape the l1_fees tests use.
                    "eth_getBlockByNumber" => {
                        let mut block: alloy_rpc_types_eth::Block = Default::default();
                        block.header.inner.base_fee_per_gas = Some(1);
                        serde_json::to_value(block).expect("block serializes")
                    }
                    _ => json!("0x1"),
                };
                let body = json!({"jsonrpc":"2.0","id": actual["id"], "result": result}).to_string();
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
                EthCall::SendError(message) => {
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

    /// `with_l1` variant that reports every RPC method the fixture saw and
    /// leaves the server reaping to the caller, so a test can validate its
    /// flow before the join's timeout can mask the real verdict.
    async fn with_l1_seen<T, F, Fut>(
        calls: Vec<EthCall>,
        f: F,
    ) -> (T, tokio::task::JoinHandle<()>, Vec<String>)
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = T>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let server = tokio::spawn(serve_eth_calls(listener, calls, Arc::clone(&seen)));
        let out = f(url).await;
        let seen = seen.lock().expect("fixture seen lock").clone();
        (out, server, seen)
    }

    async fn with_l1<T, F, Fut>(calls: Vec<EthCall>, f: F) -> T
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = T>,
    {
        let (out, server, _) = with_l1_seen(calls, f).await;
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
        Fut: Future<Output = T>,
    {
        let services_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let services_url = format!("http://{}", services_listener.local_addr().unwrap());
        let rpc_url = format!("http://{}", rpc_listener.local_addr().unwrap());
        let services_server = tokio::spawn(serve_services(services_listener, services));
        let rpc_server = tokio::spawn(serve_eth_calls(
            rpc_listener,
            calls,
            Arc::new(std::sync::Mutex::new(Vec::new())),
        ));
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

    const RECEIPT_BRIDGE: Address = Address::repeat_byte(0xb1);

    fn nonce_words(tag: u8) -> [u32; 8] {
        [u32::from_be_bytes([tag, tag, tag, tag]); 8]
    }

    fn tagged_withdrawal(leaf_hash: &str, tag: u8) -> PendingWithdrawal {
        let mut withdrawal = dummy_withdrawal();
        withdrawal.leaf_hash = leaf_hash.to_string();
        withdrawal.nonce = nonce_words(tag);
        withdrawal.token_address = nonce_words(0x10 + tag);
        withdrawal.recipient = nonce_words(0x20 + tag);
        withdrawal.amount = nonce_words(0x30 + tag);
        withdrawal
    }

    fn pending_proof(withdrawal: PendingWithdrawal) -> PendingProof {
        PendingProof {
            index: 0,
            withdrawal,
            leaf_index: 0,
            withdrawal_root: QHashOut(HashOut { elements: [F::ZERO; 4] }),
            siblings: Vec::new(),
        }
    }

    fn claim_calldata(chunk: &[PendingProof]) -> (Bytes, B256) {
        let mut slot_data =
            [U256::ZERO; MAX_WITHDRAWAL_CLAIM_BATCH_SIZE * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS];
        for (slot, pending) in chunk.iter().enumerate() {
            let offset = slot * WITHDRAWAL_BATCH_CLAIM_SLOT_WORDS;
            for (word, value) in pending.withdrawal.nonce.iter().enumerate() {
                slot_data[offset + 25 + word] = U256::from(*value);
            }
        }
        let mut public_inputs = [U256::ZERO; WITHDRAWAL_BATCH_CLAIM_PUBLIC_INPUTS_WORDS];
        public_inputs[8] = U256::from(chunk.len());
        let commit = batch_commit_from_slot_data(&slot_data);
        let call = batchClaimWithdrawalCall {
            proof: [U256::ZERO; 8],
            publicInputs: public_inputs,
            slotData: slot_data,
        };
        (Bytes::from(call.abi_encode()), commit)
    }

    fn bridge_log<E: alloy_sol_types::SolEvent>(event: &E) -> alloy_rpc_types_eth::Log {
        alloy_rpc_types_eth::Log {
            inner: alloy_primitives::Log {
                address: RECEIPT_BRIDGE,
                data: event.encode_log_data(),
            },
            block_hash: None,
            block_number: None,
            block_timestamp: None,
            transaction_hash: None,
            transaction_index: None,
            log_index: None,
            removed: false,
        }
    }

    fn summary(commit: B256, real: u8, succeeded: u8, failed: u8) -> WithdrawalClaimBatchResult {
        WithdrawalClaimBatchResult {
            batchCommit: commit,
            realCount: real,
            succeededCount: succeeded,
            failedCount: failed,
        }
    }

    fn registered(pending: &PendingProof) -> WithdrawalPendingCreated {
        let identity = claim_slot_identity(&pending.withdrawal);
        WithdrawalPendingCreated {
            nonce: identity.nonce,
            token: identity.token,
            recipient: identity.recipient,
            amount: identity.amount,
            claimableAt: 1_700_000_000,
        }
    }

    fn failed_slot(pending: &PendingProof, slot: u8, reason: u8) -> WithdrawalClaimItemFailed {
        WithdrawalClaimItemFailed {
            nonce: withdrawal_nullifier_from_nonce(pending.withdrawal.nonce),
            slotIndex: slot,
            reason,
        }
    }

    struct AppliedReceipt {
        submitted_count: usize,
        outcomes: Vec<ClaimOutcome>,
    }

    impl AppliedReceipt {
        fn kind_of(&self, leaf_hash: &str) -> Option<ClaimOutcomeKind> {
            self.outcomes
                .iter()
                .find(|outcome| outcome.leaf_hash == leaf_hash)
                .map(|outcome| outcome.kind)
        }
    }

    fn apply_receipt(logs: &[alloy_rpc_types_eth::Log], chunk: &[PendingProof]) -> AppliedReceipt {
        let (call_data, _) = claim_calldata(chunk);
        let outcomes = apply_confirmed_claim_receipt(RECEIPT_BRIDGE, logs, &call_data, chunk);
        AppliedReceipt {
            submitted_count: outcomes
                .iter()
                .filter(|outcome| outcome.kind == ClaimOutcomeKind::Registered)
                .count(),
            outcomes,
        }
    }

    #[test]
    fn batch_claim_abi_stays_frozen() {
        let selector = &keccak256(
            b"batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])",
        )[..4];
        assert_eq!(batchClaimWithdrawalCall::SELECTOR.as_slice(), selector);
        assert_eq!(
            WithdrawalClaimItemFailed::SIGNATURE_HASH,
            keccak256(b"WithdrawalClaimItemFailed(bytes32,uint8,uint8)")
        );
        assert_eq!(
            WithdrawalClaimBatchResult::SIGNATURE_HASH,
            keccak256(b"WithdrawalClaimBatchResult(bytes32,uint8,uint8,uint8)")
        );
    }

    fn flow(medium_max: u128, cap: u128, large: u32) -> TokenFlowConfig {
        TokenFlowConfig {
            minDepositAmount: 1, depositCap: 1, smallWithdrawalMax: 10, mediumWithdrawalMax: medium_max,
            totalWithdrawalCap: cap, smallWithdrawalDelay: 1, mediumWithdrawalDelay: 2, largeWithdrawalDelay: large, configured: true,
        }
    }

    #[test]
    fn next_total_above_the_cap_selects_the_large_delay() {
        let config = flow(100, 150, 9);
        assert_eq!(flow_delay(&config, U256::from(40), U256::from(151)), 9);
        assert_eq!(flow_delay(&config, U256::from(40), U256::from(150)), 2);
        let timestamp = U256::from(u64::MAX) - U256::from(8);
        let delay = U256::from(flow_delay(&config, U256::from(40), U256::from(151)));
        assert!(timestamp > U256::from(u64::MAX) - delay);
    }

    #[test]
    fn repeated_indexed_rows_stay_distinct_slots() {
        let rows = [
            tagged_withdrawal("leaf-a", 1),
            tagged_withdrawal("leaf-a", 1),
            tagged_withdrawal("leaf-b", 1),
            tagged_withdrawal("leaf-c", 3),
        ];
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0].leaf_hash, rows[1].leaf_hash);
        assert_ne!(rows[0].leaf_hash, rows[2].leaf_hash);
        assert_ne!(rows[2].nonce, rows[3].nonce);
    }

    #[tokio::test]
    async fn partial_receipt_resolves_only_the_slots_that_registered() {
        let good = pending_proof(tagged_withdrawal("leaf-good", 1));
        let bad = pending_proof(tagged_withdrawal("leaf-bad", 2));
        let chunk = [good, bad];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_TOKEN_NOT_CONFIGURED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(applied.submitted_count, 1);
        assert_eq!(applied.kind_of("leaf-good"), Some(ClaimOutcomeKind::Registered));
        assert_eq!(
            applied.kind_of("leaf-bad"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::TokenNotConfigured))
        );
    }

    #[tokio::test]
    async fn a_consumed_nonce_does_not_resolve_another_leaf_with_the_same_payout_tuple() {
        let fresh = pending_proof(tagged_withdrawal("leaf-fresh", 1));
        let prior = pending_proof(tagged_withdrawal("leaf-prior", 2));
        let chunk = [fresh, prior];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_ALREADY_CLAIMED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(applied.submitted_count, 1);
        assert_eq!(applied.kind_of("leaf-fresh"), Some(ClaimOutcomeKind::Registered));
        assert_eq!(applied.kind_of("leaf-prior"), Some(ClaimOutcomeKind::Failed(ClaimCode::NonceConflict)));
    }

    #[tokio::test]
    async fn reason_five_without_this_slots_registration_is_a_consumed_nonce() {
        let fresh = pending_proof(tagged_withdrawal("leaf-fresh", 1));
        let prior = pending_proof(tagged_withdrawal("leaf-prior", 2));
        let chunk = [fresh, prior];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_ALREADY_CLAIMED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.kind_of("leaf-fresh"),
            Some(ClaimOutcomeKind::Registered),
            "a valid receipt must still resolve the good slot"
        );
        assert_eq!(applied.submitted_count, 1);
        assert_eq!(
            applied.kind_of("leaf-prior"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::NonceConflict))
        );
    }

    #[tokio::test]
    async fn paused_registration_is_deferred_per_slot() {
        let good = pending_proof(tagged_withdrawal("leaf-good", 1));
        let paused = pending_proof(tagged_withdrawal("leaf-paused", 2));
        let chunk = [good, paused];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_REGISTRATION_PAUSED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(applied.kind_of("leaf-good"), Some(ClaimOutcomeKind::Registered));
        assert_eq!(
            applied.kind_of("leaf-paused"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::RegistrationPaused))
        );
    }

    #[tokio::test]
    async fn same_batch_duplicate_nonce_with_a_different_tuple_fails_only_that_slot() {
        let first = pending_proof(tagged_withdrawal("leaf-first", 7));
        let mut duplicate_withdrawal = tagged_withdrawal("leaf-duplicate", 7);
        duplicate_withdrawal.token_address = nonce_words(0x41);
        duplicate_withdrawal.recipient = nonce_words(0x51);
        duplicate_withdrawal.amount = nonce_words(0x61);
        let duplicate = pending_proof(duplicate_withdrawal);
        let chunk = [first, duplicate];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_ALREADY_CLAIMED)),
        ];

        // The receipt's own registration event carries the first slot's tuple,
        // so the conflicting leaf fails without any chain lookup.
        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.kind_of("leaf-first"),
            Some(ClaimOutcomeKind::Registered),
            "a different leaf must not be resolved by a nonce it does not own"
        );
        assert_eq!(applied.submitted_count, 1);
        assert_eq!(
            applied.kind_of("leaf-duplicate"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::NonceConflict))
        );
    }

    #[tokio::test]
    async fn events_from_another_contract_do_not_count() {
        let good = pending_proof(tagged_withdrawal("leaf-good", 1));
        let bad = pending_proof(tagged_withdrawal("leaf-bad", 2));
        let chunk = [good, bad];
        let (_, commit) = claim_calldata(&chunk);
        let mut foreign_summary = bridge_log(&summary(commit, 2, 1, 1));
        foreign_summary.inner.address = Address::repeat_byte(0xee);
        let logs = vec![
            foreign_summary,
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_TOKEN_NOT_CONFIGURED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(applied.submitted_count, 0);
        assert_eq!(
            applied.kind_of("leaf-good"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
        assert_eq!(
            applied.kind_of("leaf-bad"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
    }

    #[tokio::test]
    async fn missing_batch_summary_resolves_nothing() {
        let only = pending_proof(tagged_withdrawal("leaf-only", 1));
        let chunk = [only];
        let logs = vec![bridge_log(&registered(&chunk[0]))];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.kind_of("leaf-only"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
    }

    #[tokio::test]
    async fn summary_for_a_different_batch_commit_resolves_nothing() {
        let only = pending_proof(tagged_withdrawal("leaf-only", 1));
        let chunk = [only];
        let logs = vec![
            bridge_log(&summary(B256::repeat_byte(0x42), 1, 1, 0)),
            bridge_log(&registered(&chunk[0])),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.kind_of("leaf-only"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
    }

    #[tokio::test]
    async fn succeeded_slot_with_a_conflicting_registration_fails_only_that_slot() {
        let first = pending_proof(tagged_withdrawal("leaf-first", 1));
        let second = pending_proof(tagged_withdrawal("leaf-second", 2));
        let chunk = [first, second];
        let (_, commit) = claim_calldata(&chunk);
        let mut wrong_amount = registered(&chunk[1]);
        wrong_amount.amount += U256::from(1);
        let logs = vec![
            bridge_log(&summary(commit, 2, 2, 0)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&wrong_amount),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.kind_of("leaf-first"),
            Some(ClaimOutcomeKind::Registered),
            "one conflicting nonce must not sink the chunk's good slots"
        );
        assert_eq!(
            applied.kind_of("leaf-second"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::NonceConflict))
        );
    }

    #[tokio::test]
    async fn failed_event_naming_another_slots_nonce_resolves_nothing() {
        let good = pending_proof(tagged_withdrawal("leaf-good", 1));
        let bad = pending_proof(tagged_withdrawal("leaf-bad", 2));
        let chunk = [good, bad];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[0], 1, REASON_ZERO_AMOUNT)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(applied.submitted_count, 0);
        assert_eq!(
            applied.kind_of("leaf-good"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
        assert_eq!(
            applied.kind_of("leaf-bad"),
            Some(ClaimOutcomeKind::Failed(ClaimCode::MalformedReceipt))
        );
    }
    #[test]
    fn identical_duplicate_rows_keep_their_own_slot_outcomes() {
        let first = pending_proof(tagged_withdrawal("leaf-dup", 1));
        let second = pending_proof(tagged_withdrawal("leaf-dup", 1));
        let chunk = [first, second];
        let (_, commit) = claim_calldata(&chunk);
        let logs = vec![
            bridge_log(&summary(commit, 2, 1, 1)),
            bridge_log(&registered(&chunk[0])),
            bridge_log(&failed_slot(&chunk[1], 1, REASON_ALREADY_CLAIMED)),
        ];

        let applied = apply_receipt(&logs, &chunk);

        assert_eq!(
            applied.outcomes.len(),
            2,
            "identical duplicate rows must not collapse; both slot outcomes stay"
        );
        assert_eq!(applied.outcomes[0].leaf_hash, "leaf-dup");
        assert_eq!(applied.outcomes[0].kind, ClaimOutcomeKind::Registered);
        assert_eq!(applied.outcomes[1].leaf_hash, "leaf-dup");
        assert_eq!(
            applied.outcomes[1].kind,
            ClaimOutcomeKind::Failed(ClaimCode::NonceConflict),
            "reason 5 never upgrades through a sibling slot or history"
        );
    }

    #[test]
    fn all_ten_contract_reasons_map_to_typed_codes() {
        let chunk: Vec<PendingProof> = (1..=10u8)
            .map(|tag| pending_proof(tagged_withdrawal(&format!("leaf-{tag}"), tag)))
            .collect();
        let (_, commit) = claim_calldata(&chunk);
        let mut logs = vec![bridge_log(&summary(commit, 10, 0, 10))];
        for (slot, pending) in chunk.iter().enumerate() {
            logs.push(bridge_log(&failed_slot(pending, slot as u8, slot as u8 + 1)));
        }

        let applied = apply_receipt(&logs, &chunk);

        let expected = [
            ClaimCode::HighAddress,
            ClaimCode::WrongChain,
            ClaimCode::ZeroAddress,
            ClaimCode::ZeroAmount,
            ClaimCode::NonceConflict,
            ClaimCode::TokenNotConfigured,
            ClaimCode::RegistrationPaused,
            ClaimCode::AmountOutOfRange,
            ClaimCode::TotalOverflow,
            ClaimCode::ClaimableOverflow,
        ];
        assert_eq!(applied.outcomes.len(), 10);
        for (slot, code) in expected.iter().enumerate() {
            assert_eq!(
                applied.outcomes[slot],
                ClaimOutcome {
                    leaf_hash: format!("leaf-{}", slot + 1),
                    kind: ClaimOutcomeKind::Failed(*code),
                    tx_hash: None,
                }
            );
        }
    }

    #[tokio::test]
    async fn unresolved_leaf_chunk_is_gated_before_sign_and_hook() {
        // Chunk A is broadcast with an unknown outcome; chunk B repeats leaf-a
        // (plus one safe leaf) and must be gated BEFORE signing: the hook is
        // never called again, so the recorded hash of A survives untouched.
        let leaf_a = tagged_withdrawal("leaf-a", 1);
        let leaf_b = tagged_withdrawal("leaf-b", 2);
        let proof = |index: usize, withdrawal: PendingWithdrawal| PendingProof {
            index,
            withdrawal,
            leaf_index: 0,
            withdrawal_root: QHashOut(HashOut { elements: [F::ZERO; 4] }),
            siblings: Vec::new(),
        };
        let chunk_a = vec![proof(0, leaf_a.clone())];
        let chunk_b = vec![proof(1, leaf_a.clone()), proof(2, leaf_b.clone())];
        let (call_data_a, _) = claim_calldata(&chunk_a);
        let (call_data_b, _) = claim_calldata(&chunk_b);
        let chunks = vec![
            ReadyChunk { root_hex: "0xa".into(), chunk: chunk_a, call_data: call_data_a },
            ReadyChunk { root_hex: "0xb".into(), chunk: chunk_b, call_data: call_data_b },
        ];

        let hook_hashes: Arc<std::sync::Mutex<Vec<B256>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&hook_hashes);
        let hook: BeforeBroadcast = Arc::new(move |_leaves: &[PendingWithdrawal], tx_hash: B256| {
            let sink = Arc::clone(&sink);
            Box::pin(async move {
                sink.lock().unwrap().push(tx_hash);
                Ok(())
            })
        });

        let (outcomes, server, seen_methods) =
            with_l1_seen(vec![EthCall::SendError("wire dropped")], |url| async move {
                let wallet = load_l1_wallet(
                    Some("0x4646464646464646464646464646464646464646464646464646464646464646"),
                    None,
                    None,
                    None,
                    "gate test",
                )
                .expect("test key loads");
                let provider = connect_l1_with_wallet(url.parse().unwrap(), wallet)
                    .expect("provider connects");
                let mut outcomes: OutcomeSlots = vec![None; 3];
                let mut unknown_tx_hashes: HashMap<String, B256> = HashMap::new();
                submit_chunks(
                    &provider,
                    RECEIPT_BRIDGE,
                    &chunks,
                    None,
                    Some(&hook),
                    &mut outcomes,
                    &mut unknown_tx_hashes,
                )
                .await;
                outcomes
            })
            .await;

        // The fixture join's timeout must never mask the real verdict: print
        // what the fixture saw and check the flow's outcome first, with safe
        // labels only, and reap the server last.
        eprintln!("gate fixture methods: [{}]", seen_methods.join(", "));
        eprintln!(
            "gate outcome kinds: {}",
            outcomes
                .iter()
                .map(|slot| match slot {
                    Some(outcome) => match outcome.kind {
                        ClaimOutcomeKind::Registered => "Registered".to_string(),
                        ClaimOutcomeKind::Failed(code) => format!("Failed({})", code.label()),
                    },
                    None => "unset".to_string(),
                })
                .collect::<Vec<_>>()
                .join(" | ")
        );

        let hashes = hook_hashes.lock().unwrap().clone();
        assert_eq!(
            hashes.len(),
            1,
            "chunk B must be gated before signing: the hook never sees a second hash"
        );
        let hash_a = hashes[0];
        assert_eq!(
            outcomes[0].as_ref().unwrap(),
            &ClaimOutcome {
                leaf_hash: "leaf-a".to_string(),
                kind: ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown),
                tx_hash: Some(hash_a),
            }
        );
        assert_eq!(
            outcomes[1].as_ref().unwrap(),
            &ClaimOutcome {
                leaf_hash: "leaf-a".to_string(),
                kind: ClaimOutcomeKind::Failed(ClaimCode::ReceiptUnknown),
                tx_hash: Some(hash_a),
            },
            "the affected leaf stays held on the recorded hash of A"
        );
        assert_eq!(
            outcomes[2].as_ref().unwrap(),
            &ClaimOutcome {
                leaf_hash: "leaf-b".to_string(),
                kind: ClaimOutcomeKind::Failed(ClaimCode::RpcUnavailable),
                tx_hash: None,
            },
            "the safe chunk-mate is deferred retryable, not faked unknown"
        );
        join_fixture(server).await;
    }





}
