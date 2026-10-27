//! Subcommand: claim-withdrawal — get withdrawal Merkle proof from
//! psy-services, optionally generate a Groth16 proof via prove-proxy, and
//! submit to L1 Bridge.
//!
//! If --prove-proxy-url is provided, the subcommand will attempt to generate a
//! Groth16 proof and call Bridge.batchClaimWithdrawal on L1.
//! Otherwise, it prints the Merkle proof for manual relay.

use alloy_primitives::{keccak256, Address, U256};
use alloy_signer_local::PrivateKeySigner;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use reqwest::Client;
use serde::Deserialize;

use super::args::ClaimWithdrawalArgs;
use crate::result::{CommandResult, L1TransactionResult, L1TransactionStatus};

const WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS: usize = 1088;
const WITHDRAWAL_BATCH_CLAIM_SIGNATURE: &str = "batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])";
#[cfg(test)]
const LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE: &str = "batchClaimWithdrawal(uint256[8],uint256[18],uint256[864])";

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofPayload {
    sender_user_id: Option<u64>,
    withdrawal_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofResponse {
    found: bool,
    leaf_index: Option<u64>,
    leaf_hash: Option<String>,
    #[serde(rename = "siblings")]
    subtree_proof: Option<Vec<String>>,
    withdrawal_root: Option<String>,
    checkpoint_id: Option<u64>,
    withdrawal: Option<WithdrawalClaimProofPayload>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

fn compute_withdrawal_leaf_hash(
    sender_user_id: u64,
    recipient: &str,
    token_address: &str,
    amount: &str,
    nonce_hex: &str,
    destination_chain_index: u64,
) -> anyhow::Result<String> {
    let sender_user_id_u32 = u32::try_from(sender_user_id).map_err(|_| anyhow::anyhow!("sender_user_id exceeds u32"))?;
    let recipient_words = hex_to_u32x8_be(recipient)?;
    let token_words = hex_to_u32x8_be(token_address)?;
    let amount_words = u256_to_u32x8_be(amount)?;
    let nonce_words = bytes32_hex_to_u32x8_be(nonce_hex, "nonce")?;
    let chain_u32 = u32::try_from(destination_chain_index).map_err(|_| anyhow::anyhow!("destination_chain_index exceeds u32"))?;

    let felts: Vec<GoldilocksField> = std::iter::once(GoldilocksField::from_canonical_u64(sender_user_id_u32 as u64))
        .chain(recipient_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(token_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(amount_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(nonce_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(std::iter::once(GoldilocksField::from_canonical_u64(chain_u32 as u64)))
        .collect();
    let leaf_hash = PoseidonHash::hash_no_pad(&felts);
    let elems = leaf_hash.elements;
    let words: [u32; 8] = [
        (elems[0].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[0].to_canonical_u64() >> 32) as u32,
        (elems[1].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[1].to_canonical_u64() >> 32) as u32,
        (elems[2].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[2].to_canonical_u64() >> 32) as u32,
        (elems[3].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[3].to_canonical_u64() >> 32) as u32,
    ];
    let mut hex_str = String::with_capacity(66);
    hex_str.push_str("0x");
    for w in &words {
        hex_str.push_str(&format!("{:08x}", w));
    }
    Ok(hex_str)
}

fn resolve_bridge_address_for_network(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Bridge_Proxy", "Bridge", "Bridge_Proxy.json")
}

fn resolve_current_deployments_network(rpc_config_path: &str) -> anyhow::Result<String> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(rpc_config_path)?;
    Ok(psy_config.current_network_name().to_string())
}

pub(crate) async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let client = reqwest::Client::new();
    let resp = client.post(url).json(&body).send().await?;
    let result: serde_json::Value = resp.json().await?;
    if let Some(err) = result.get("error") {
        anyhow::bail!(
            "RPC error ({}): {} - data: {:?}",
            method,
            err["message"].as_str().unwrap_or("unknown"),
            err.get("data")
        );
    }
    Ok(result["result"].clone())
}

fn hex_to_u32x8_be(hex_str: &str) -> anyhow::Result<Vec<u64>> {
    let raw = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(raw)?;
    let padded = match bytes.len() {
        20 => {
            let mut b = vec![0u8; 32];
            b[12..].copy_from_slice(&bytes);
            b
        }
        32 => bytes.to_vec(),
        n => anyhow::bail!("expected 20 or 32 bytes, got {}", n),
    };
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let start = i * 4;
        let val = u32::from_be_bytes(padded[start..start + 4].try_into().unwrap());
        words.push(val as u64);
    }
    Ok(words)
}

fn normalize_u256_hex_32bytes(value: &str) -> anyhow::Result<String> {
    let raw = value.trim();
    let parsed = if raw.starts_with("0x") || raw.starts_with("0X") {
        U256::from_str_radix(raw.trim_start_matches("0x").trim_start_matches("0X"), 16)?
    } else {
        raw.parse::<U256>()
            .or_else(|_| U256::from_str_radix(raw, 16))
            .map_err(|e| anyhow::anyhow!("invalid uint256 '{}': {}", value, e))?
    };
    Ok(format!("0x{}", hex::encode(parsed.to_be_bytes::<32>())))
}

fn bytes32_hex_to_u32x8_be(hex_str: &str, field: &str) -> anyhow::Result<[u32; 8]> {
    let normalized = normalize_u256_hex_32bytes(hex_str)?;
    let raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let bytes = hex::decode(raw)?;
    anyhow::ensure!(bytes.len() == 32, "{} must encode exactly 32 bytes", field);
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    Ok(words)
}

fn u256_to_u32x8_be(s: &str) -> anyhow::Result<Vec<u64>> {
    let val: alloy_primitives::U256 = s.parse().map_err(|e| anyhow::anyhow!("invalid uint256: {}", e))?;
    let bytes = val.to_be_bytes::<32>();
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let start = i * 4;
        let v = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap());
        words.push(v as u64);
    }
    Ok(words)
}

fn urlencoding(s: &str) -> String {
    s.to_string()
}

fn to_32byte_hex(hex_str: &str) -> String {
    let raw = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if raw.len() <= 40 {
        format!("0x{:0>64}", raw.to_lowercase())
    } else {
        format!("0x{:0>64}", raw.to_lowercase())
    }
}

fn decimal_amount_to_hex(dec_str: &str) -> String {
    let val: U256 = dec_str.parse().unwrap_or_else(|_| U256::from_str_radix(dec_str, 16).unwrap_or_default());
    let bytes = val.to_be_bytes::<32>();
    format!("0x{}", hex::encode(bytes))
}

/// A mined receipt's canonical identity: height plus the 32-byte block hash.
/// State reads stay bound to this hash; a bare block number is never enough
/// to attribute logs or claimedNullifiers.
struct ReceiptBlockIdentity {
    number: u64,
    hash: String,
}

/// EIP-1898 block parameter. Mined state reads require this form; a provider
/// rejection is an error and is not retried by block number.
fn canonical_block_param(block_hash: &str) -> serde_json::Value {
    serde_json::json!({ "blockHash": block_hash, "requireCanonical": true })
}

fn parse_block_hash(value: &serde_json::Value, context: &str) -> anyhow::Result<String> {
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("{context} is missing a block hash"))?;
    let hex_body = raw.strip_prefix("0x").unwrap_or(raw);
    anyhow::ensure!(
        hex_body.len() == 64 && hex_body.chars().all(|ch| ch.is_ascii_hexdigit()),
        "{context} block hash is not 32 bytes: {raw}"
    );
    Ok(format!("0x{}", hex_body.to_ascii_lowercase()))
}

fn parse_block_number(value: &str, context: &str) -> anyhow::Result<u64> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    u64::from_str_radix(raw, 16).map_err(|err| anyhow::anyhow!("{context} block number {value:?} is invalid: {err}"))
}

/// One pinned eth_call. EIP-1898 `requireCanonical` is required. A provider
/// that rejects it cannot be told apart from a reorg or an execution error, so
/// there is no number-only fallback.
async fn eth_call_at_receipt(rpc_url: &str, to: &str, data: &[u8], receipt: &ReceiptBlockIdentity) -> anyhow::Result<String> {
    let call = serde_json::json!({ "to": to, "data": format!("0x{}", hex::encode(data)) });
    let value = rpc_call(rpc_url, "eth_call", serde_json::json!([call, canonical_block_param(&receipt.hash)])).await?;
    serde_json::from_value(value).map_err(|err| anyhow::anyhow!("eth_call result is not a string: {err}"))
}

/// Reads Bridge.claimedNullifiers(nonce). `block` is "latest" for pre-send
/// checks; mined attribution uses `eth_call_at_receipt`.
async fn read_claimed_withdrawal_nonce(rpc_url: &str, bridge_address: &str, nonce_hex: &str, block: &str) -> anyhow::Result<bool> {
    let data = build_claimed_withdrawal_nonce_call_data(nonce_hex)?;
    let result: String = serde_json::from_value(
        rpc_call(
            rpc_url,
            "eth_call",
            serde_json::json!([{
                "to": bridge_address,
                "data": format!("0x{}", hex::encode(&data)),
            }, block]),
        )
        .await?,
    )?;
    parse_abi_bool_word(&result, "claimedNullifiers")
}

async fn read_claimed_withdrawal_nonce_at_receipt(
    rpc_url: &str,
    bridge_address: &str,
    nonce_hex: &str,
    receipt: &ReceiptBlockIdentity,
) -> anyhow::Result<bool> {
    let data = build_claimed_withdrawal_nonce_call_data(nonce_hex)?;
    let raw = eth_call_at_receipt(rpc_url, bridge_address, &data, receipt).await?;
    parse_abi_bool_word(&raw, "claimedNullifiers")
}

/// Decodes an ABI-encoded `bool` return word: exactly 32 bytes, canonical 0 or
/// 1 in the last byte with the upper 31 bytes zero. A malformed, short, or
/// non-canonical word is an error — never a silent false (or nonzero-true).
fn parse_abi_bool_word(hex_str: &str, context: &str) -> anyhow::Result<bool> {
    let raw = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(raw).map_err(|err| anyhow::anyhow!("{context} returned a non-hex word: {err}"))?;
    anyhow::ensure!(
        bytes.len() == 32,
        "{context} returned a {}-byte bool word, expected exactly 32",
        bytes.len()
    );
    anyhow::ensure!(
        bytes[..31].iter().all(|&byte| byte == 0),
        "{context} returned a non-canonical bool word"
    );
    match bytes[31] {
        0 => Ok(false),
        1 => Ok(true),
        other => anyhow::bail!("{context} returned invalid bool value {other}"),
    }
}

fn build_claimed_withdrawal_nonce_call_data(nonce_hex: &str) -> anyhow::Result<Vec<u8>> {
    let normalized = normalize_u256_hex_32bytes(nonce_hex)?;
    let nonce_raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let nonce_bytes = hex::decode(nonce_raw)?;
    anyhow::ensure!(nonce_bytes.len() == 32, "nonce must be 32 bytes");

    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&keccak256("claimedNullifiers(bytes32)".as_bytes())[..4]);
    data.extend_from_slice(&nonce_bytes);
    Ok(data)
}

/// Frozen `event WithdrawalClaimItemFailed(bytes32 indexed nonce, uint8 indexed slotIndex, uint8 reason)`
/// from Bridge.sol: item-local failures skip the slot instead of reverting.
const WITHDRAWAL_CLAIM_ITEM_FAILED_EVENT: &str = "WithdrawalClaimItemFailed(bytes32,uint8,uint8)";

/// Frozen `event WithdrawalPendingCreated(bytes32 indexed nonce, address indexed token, address indexed recipient, uint256 amount, uint64 claimableAt)`
/// from Bridge.sol, emitted by `_registerPendingWithdrawal`; the only canonical
/// per-nonce registration evidence, and it survives settlement.
const WITHDRAWAL_CLAIMED_EVENT: &str = "WithdrawalClaimed(bytes32,address,address,uint256)";
const WITHDRAWAL_PENDING_CREATED_EVENT: &str = "WithdrawalPendingCreated(bytes32,address,address,uint256,uint64)";

/// Outcome tuple carried by WithdrawalPendingCreated or WithdrawalClaimed: (token, recipient, amount).
type WithdrawalRegistrationTuple = ([u8; 32], [u8; 32], [u8; 32]);

/// Frozen Bridge.sol CLAIM_REASON_* codes; 0 means valid and 11..=255 are reserved.
fn describe_withdrawal_claim_failure_reason(reason: u8) -> String {
    match reason {
        1 => "address high bits nonzero (1)".to_string(),
        2 => "wrong destination chain (2)".to_string(),
        3 => "zero recipient (3)".to_string(),
        4 => "zero amount (4)".to_string(),
        5 => "nullifier already claimed (5)".to_string(),
        6 => "token not configured (6)".to_string(),
        7 => "registration paused (7)".to_string(),
        8 => "amount out of range (8)".to_string(),
        9 => "total overflow (9)".to_string(),
        10 => "claimable-at overflow (10)".to_string(),
        other => format!("unknown failure reason {other}"),
    }
}

fn hex_word_bytes(value: &str) -> Option<Vec<u8>> {
    hex::decode(value.strip_prefix("0x").unwrap_or(value)).ok()
}

fn hex_word_bytes32(value: &str) -> Option<[u8; 32]> {
    hex_word_bytes(value).and_then(|bytes| bytes.try_into().ok())
}

fn log_emitter_matches(log: &serde_json::Value, bridge_address: &str) -> bool {
    log.get("address")
        .and_then(|v| v.as_str())
        .is_some_and(|a| a.eq_ignore_ascii_case(bridge_address))
}

/// A log flagged `removed: true` was reorged out and is never evidence. The
/// flag must be absent or a JSON bool — `"true"`, `1`, or `null` is malformed
/// and cannot be treated as still canonical.
fn log_removed_flag(log: &serde_json::Value) -> anyhow::Result<bool> {
    match log.get("removed") {
        None => Ok(false),
        Some(value) => value
            .as_bool()
            .ok_or_else(|| anyhow::anyhow!("log removed flag is not a boolean: {value}")),
    }
}

fn log_is_reorg_removed(log: &serde_json::Value) -> bool {
    matches!(log_removed_flag(log), Ok(true))
}

/// Returns the first log in a JSON log array accepted by `matcher`.
fn find_matching_log<T>(logs: &serde_json::Value, matcher: impl Fn(&serde_json::Value) -> Option<T>) -> Option<T> {
    for log in logs.as_array()? {
        if let Some(parsed) = matcher(log) {
            return Some(parsed);
        }
    }
    None
}

/// `WithdrawalClaimItemFailed(bytes32 indexed nonce, uint8 indexed slotIndex, uint8 reason)`:
/// topics [sig, nonce, slotIndex], reason non-indexed in the data word. The full
/// emitter tuple must match (contract address, event topic, indexed nonce, and —
/// for this single-slot submitter — slot 0), and the reason word must be exactly
/// 32 bytes with the upper 31 zero. Malformed or unrelated logs are ignored;
/// an undecodable event can never affect the classification, which is decided
/// by the pinned claimedNullifiers read.
fn parse_withdrawal_claim_item_failed_log(
    log: &serde_json::Value,
    bridge_address: &str,
    nonce_bytes: &[u8; 32],
) -> Option<u8> {
    if log_is_reorg_removed(log) || !log_emitter_matches(log, bridge_address) {
        return None;
    }
    let topics = log.get("topics")?.as_array()?;
    if topics.len() != 3 {
        return None;
    }
    let failed_topic0 = hex_word_bytes32(topics[0].as_str()?)?;
    if failed_topic0.as_slice() != &keccak256(WITHDRAWAL_CLAIM_ITEM_FAILED_EVENT.as_bytes())[..] {
        return None;
    }
    if hex_word_bytes32(topics[1].as_str()?)?.as_slice() != nonce_bytes.as_slice() {
        return None;
    }
    if hex_word_bytes32(topics[2].as_str()?)? != [0u8; 32] {
        return None;
    }
    let data = hex_word_bytes(log.get("data")?.as_str()?)?;
    if data.len() == 32 && data[..31].iter().all(|&byte| byte == 0) {
        Some(data[31])
    } else {
        None
    }
}

/// CLAIM_REASON_* code from the WithdrawalClaimItemFailed log for this nonce
/// in the receipt's `logs` array.
fn extract_withdrawal_claim_item_failure_reason(
    logs: &serde_json::Value,
    bridge_address: &str,
    nonce_bytes: &[u8; 32],
) -> Option<u8> {
    find_matching_log(logs, |log| parse_withdrawal_claim_item_failed_log(log, bridge_address, nonce_bytes))
}

/// `WithdrawalPendingCreated(bytes32 indexed nonce, address indexed token,
/// address indexed recipient, uint256 amount, uint64 claimableAt)`: topics
/// [sig, nonce, token, recipient], data carries the 32-byte amount word then the
/// claimable-at word (uint64, upper 24 bytes zero). Decodes the (token,
/// recipient, amount) words of this bridge's event for the given nonce.
/// Reorg-removed logs are never evidence; a present non-boolean `removed` flag
/// is an error. Once topic0 identifies this event, the frozen ABI fixes four
/// topics: a wrong count or malformed nonce topic is malformed evidence and an
/// error, while a well-formed event for a different nonce stays irrelevant.
fn parse_withdrawal_pending_created_log(
    log: &serde_json::Value,
    bridge_address: &str,
    nonce_bytes: &[u8; 32],
) -> anyhow::Result<Option<WithdrawalRegistrationTuple>> {
    if log_removed_flag(log)? || !log_emitter_matches(log, bridge_address) {
        return Ok(None);
    }
    let Some(topics) = log.get("topics").and_then(|value| value.as_array()) else {
        return Ok(None);
    };
    let Some(created_topic0) = topics.first().and_then(|topic| topic.as_str()).and_then(hex_word_bytes32) else {
        return Ok(None);
    };
    let paid = created_topic0.as_slice() == &keccak256(WITHDRAWAL_CLAIMED_EVENT.as_bytes())[..];
    if !paid && created_topic0.as_slice() != &keccak256(WITHDRAWAL_PENDING_CREATED_EVENT.as_bytes())[..] {
        return Ok(None);
    }
    // Recognized event: the frozen ABI fixes four topics. A malformed count —
    // including a missing nonce topic — is malformed evidence, never an
    // ignored log; a well-formed event for a different nonce stays irrelevant.
    anyhow::ensure!(topics.len() == 4, "WithdrawalPendingCreated log has {} topics, expected 4", topics.len());
    let Some(topic_nonce) = topics.get(1).and_then(|topic| topic.as_str()).and_then(hex_word_bytes32) else {
        anyhow::bail!("WithdrawalPendingCreated log has a malformed nonce topic");
    };
    if topic_nonce.as_slice() != nonce_bytes.as_slice() {
        return Ok(None);
    }
    let (Some(token), Some(recipient)) = (
        topics[if paid { 3 } else { 2 }].as_str().and_then(hex_word_bytes32),
        topics[if paid { 2 } else { 3 }].as_str().and_then(hex_word_bytes32),
    ) else {
        anyhow::bail!("WithdrawalPendingCreated log has a malformed token or recipient topic");
    };
    let Some(data) = log.get("data").and_then(|value| value.as_str()).and_then(hex_word_bytes) else {
        anyhow::bail!("WithdrawalPendingCreated log has malformed data");
    };
    if (paid && data.len() != 32) || (!paid && (data.len() != 64 || data[32..56].iter().any(|&byte| byte != 0))) {
        anyhow::bail!("WithdrawalPendingCreated log has a non-canonical amount or claimableAt word");
    }
    let mut amount = [0u8; 32];
    amount.copy_from_slice(&data[..32]);
    Ok(Some((token, recipient, amount)))
}

/// Every canonical WithdrawalPendingCreated for this nonce in a receipt's
/// `logs` array — for the submitted transaction this is its own registration
/// evidence. A non-array `logs` value or a malformed `removed` flag is an
/// error — never an empty list.
fn extract_withdrawal_pending_created_tuples(
    logs: &serde_json::Value,
    bridge_address: &str,
    nonce_bytes: &[u8; 32],
) -> anyhow::Result<Vec<WithdrawalRegistrationTuple>> {
    let array = logs
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("registration log response is not an array"))?;
    let mut tuples = Vec::new();
    for log in array {
        if let Some(tuple) = parse_withdrawal_pending_created_log(log, bridge_address, nonce_bytes)? {
            tuples.push(tuple);
        }
    }
    Ok(tuples)
}

/// The raw 32-byte nonce from the claimedNullifiers calldata builder.
fn claimed_nonce_bytes(nonce_hex: &str) -> anyhow::Result<[u8; 32]> {
    let call_data = build_claimed_withdrawal_nonce_call_data(nonce_hex)?;
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&call_data[4..]);
    Ok(bytes)
}

fn parse_u256_word_array(proof_data: &serde_json::Value, field: &str, expected_len: usize) -> anyhow::Result<Vec<String>> {
    let values = proof_data[field]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("prove-proxy result missing {}", field))?;
    anyhow::ensure!(
        values.len() == expected_len,
        "prove-proxy {} length mismatch: expected {}, got {}",
        field,
        expected_len,
        values.len()
    );
    values
        .iter()
        .map(|value| {
            if let Some(n) = value.as_u64() {
                Ok(n.to_string())
            } else if let Some(s) = value.as_str() {
                Ok(s.to_string())
            } else {
                anyhow::bail!("prove-proxy {} contains non-u256 value: {}", field, value)
            }
        })
        .collect()
}

pub async fn run(args: ClaimWithdrawalArgs) -> anyhow::Result<CommandResult> {
    let services_url = args.services_url.trim_end_matches('/');
    let sender_user_id_q = args.sender_user_id.map(|v| format!("&sender_user_id={}", v)).unwrap_or_default();
    let nonce_hex = normalize_u256_hex_32bytes(&args.nonce)?;
    let proof_url = format!(
        "{}/api/v1/bridge/withdrawal-claim-proof?recipient={}&token_address={}&amount={}&nonce={}&destination_chain_index={}{}",
        services_url,
        urlencoding(&to_32byte_hex(&args.recipient)),
        urlencoding(&to_32byte_hex(&args.token_address)),
        decimal_amount_to_hex(&args.amount),
        nonce_hex,
        args.destination_chain_index,
        sender_user_id_q,
    );

    tracing::info!("Fetching proof from: {}", proof_url);
    let http_client = Client::new();
    let resp = http_client
        .get(&proof_url)
        .send()
        .await?
        .json::<ApiResponse<WithdrawalClaimProofResponse>>()
        .await?;

    if !resp.success {
        anyhow::bail!("psy-services error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
    }
    let proof = resp.data.ok_or_else(|| anyhow::anyhow!("psy-services returned success but no data"))?;

    if !proof.found {
        println!("Withdrawal not found in tree. Is the withdrawal event indexed by psy-services?");
        return Ok(CommandResult::L1Transaction(L1TransactionResult {
            transaction_hash: None,
            status: L1TransactionStatus::NotFound,
            chain_id: None,
        }));
    }

    let leaf_index = proof.leaf_index.unwrap_or(0);
    let leaf_hash = proof.leaf_hash.unwrap_or_default();
    let siblings = proof.subtree_proof.unwrap_or_default();
    let withdrawal_root = proof.withdrawal_root.unwrap_or_default();

    println!("=== Withdrawal Claim Proof ===");
    println!("leaf_index:     {}", leaf_index);
    println!("leaf_hash:      {}", leaf_hash);
    println!("withdrawal_root: {}", withdrawal_root);
    println!("siblings:       [");
    for (i, s) in siblings.iter().enumerate() {
        println!("  {}: {}", i, s);
    }
    println!("]");
    println!("sibling_count:  {}", siblings.len());

    let sender_user_id = proof
        .withdrawal
        .as_ref()
        .and_then(|w| w.sender_user_id)
        .or(args.sender_user_id)
        .ok_or_else(|| anyhow::anyhow!("withdrawal proof response missing sender_user_id; re-run with --sender-user-id"))?;
    let expected_leaf_hash = compute_withdrawal_leaf_hash(
        sender_user_id,
        &args.recipient,
        &args.token_address,
        &args.amount,
        &nonce_hex,
        args.destination_chain_index,
    )?;
    tracing::info!("Expected leaf hash: {}", expected_leaf_hash);
    anyhow::ensure!(
        leaf_hash.eq_ignore_ascii_case(&expected_leaf_hash),
        "withdrawal leaf hash mismatch: expected {}, got {}",
        expected_leaf_hash,
        leaf_hash
    );

    // Bridge.claimedNullifiers is keyed by the raw bytes32 withdrawal nonce.
    if let Some(prove_proxy_url) = &args.prove_proxy_url {
        let deployments_network = resolve_current_deployments_network(&args.rpc_config)?;
        let bridge_addr = resolve_bridge_address_for_network(&deployments_network)?;
        // A consumed nonce can never register again: the item would be skipped
        // with reason 5 no matter which withdrawal consumed it. Advisory
        // preflight at the provider's canonical head; mined attribution below
        // stays pinned to the receipt.
        if read_claimed_withdrawal_nonce(&args.l1_rpc_url, &bridge_addr, &nonce_hex, "latest").await? {
            anyhow::bail!(
                "withdrawal nonce {} is already consumed (claimedNullifiers is true); refusing to submit",
                nonce_hex
            );
        }

        tracing::info!("Generating Groth16 proof via prove-proxy: {}", prove_proxy_url);

        let recipient_u32x8 = hex_to_u32x8_be(&args.recipient)?;
        let token_u32x8 = hex_to_u32x8_be(&args.token_address)?;
        let amount_u32x8 = u256_to_u32x8_be(&args.amount)?;
        let nonce_u32x8 = bytes32_hex_to_u32x8_be(&nonce_hex, "nonce")?;
        let dest_chain_u32 = args.destination_chain_index as u32;
        let bridge_user_id: u32 = 524288;

        let witness = serde_json::json!({
            "bridge_user_id": bridge_user_id,
            "withdrawals": [{
                "withdrawal_root": withdrawal_root,
                "sender_user_id": sender_user_id as u32,
                "recipient": recipient_u32x8,
                "token": token_u32x8,
                "amount": amount_u32x8,
                "nonce": nonce_u32x8,
                "destination_chain_index": dest_chain_u32,
                "leaf_index": leaf_index as u32,
                "bridge_user_id": bridge_user_id,
                "siblings": siblings,
            }]
        });

        let req_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "psy_prove_withdrawal_batch_claim_groth16",
            "params": [witness],
        });

        let mut req = http_client.post(prove_proxy_url).json(&req_body);
        if let Some(token) = &args.prove_proxy_token {
            req = req.bearer_auth(token);
        }

        let prove_resp = req.send().await?;
        let prove_result: serde_json::Value = prove_resp.json().await?;

        if let Some(err) = prove_result.get("error") {
            if let Some(message) = err.get("message").and_then(|v| v.as_str()) {
                let data = err.get("data").cloned().unwrap_or(serde_json::Value::Null);
                anyhow::bail!("prove-proxy error: {} data={}", message, data);
            }
            anyhow::bail!("prove-proxy error: {}", err);
        }

        let proof_data = &prove_result["result"];
        tracing::info!("Groth16 proof generated successfully");

        let signer: PrivateKeySigner = args.private_key.parse()?;
        let bridge: Address = bridge_addr.parse()?;
        let sol_proof = parse_u256_word_array(proof_data, "solidity_proof", 8)?;
        let public_inputs = parse_u256_word_array(proof_data, "public_inputs", 18)?;
        let slot_data = parse_u256_word_array(proof_data, "slot_data", WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS)?;

        println!("\n=== L1 Claim Data ===");
        println!("bridge_address: {}", bridge_addr);
        println!("public_inputs count: {}", public_inputs.len());
        println!("slot_data count: {}", slot_data.len());

        // Build calldata for batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])
        let selector = alloy_primitives::keccak256(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes());
        let mut data = Vec::with_capacity(4 + (8 + 18 + WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS) * 32);
        data.extend_from_slice(&selector[..4]);
        let encode_u256_arr = |data: &mut Vec<u8>, arr: &[&str]| -> anyhow::Result<()> {
            for val in arr {
                let u: U256 = val.parse()?;
                data.extend_from_slice(&u.to_be_bytes::<32>());
            }
            Ok(())
        };
        let sol_proof_refs: Vec<&str> = sol_proof.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &sol_proof_refs)?;
        let pi_refs: Vec<&str> = public_inputs.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &pi_refs)?;
        let sd_refs: Vec<&str> = slot_data.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &sd_refs)?;

        let rpc_url = &args.l1_rpc_url;
        let from_addr = signer.address();
        use alloy_signer::Signer;

        let chain_id_hex: String = serde_json::from_value(rpc_call(rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
        let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)?;

        let account_nonce_hex: String = serde_json::from_value(
            rpc_call(
                rpc_url,
                "eth_getTransactionCount",
                serde_json::json!([format!("0x{}", hex::encode(from_addr)), "latest"]),
            )
            .await?,
        )?;
        let nonce = u64::from_str_radix(account_nonce_hex.trim_start_matches("0x"), 16)?;

        // An estimate failure must not invent success or trigger a retry.
        let gas_estimate = rpc_call(
            rpc_url,
            "eth_estimateGas",
            serde_json::json!([{
                "from": format!("0x{}", hex::encode(from_addr)),
                "to": format!("0x{}", hex::encode(bridge)),
                "data": format!("0x{}", hex::encode(&data)),
            }]),
        )
        .await?;
        let gas_hex: String = serde_json::from_value(gas_estimate)?;
        let gas_limit = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
        let gas_limit = (gas_limit as f64 * 1.2) as u64;

        let fee_history = rpc_call(rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
        let base_fee_str = fee_history["baseFeePerGas"][0].as_str().unwrap_or("0x0");
        let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).unwrap_or(1_000_000_000u128);
        let max_priority_fee = u128::from_str_radix(fee_history["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"), 16)
            .unwrap_or(1_500_000_000u128);
        let max_fee_per_gas = base_fee * 2 + max_priority_fee;

        let tx = alloy_consensus::TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas: max_priority_fee,
            gas_limit,
            to: alloy_primitives::TxKind::Call(bridge),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(data),
            access_list: Default::default(),
        };
        use alloy_consensus::SignableTransaction;
        let sig = signer.sign_hash(&tx.signature_hash()).await?;
        let signed = tx.into_signed(sig);
        use alloy_eips::Encodable2718;
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);

        // A send failure leaves the transaction outcome unknown: it is never
        // retried here and never reported as success.
        let tx_hash_raw: String = serde_json::from_value(
            rpc_call(
                rpc_url,
                "eth_sendRawTransaction",
                serde_json::json!([format!("0x{}", hex::encode(&encoded))]),
            )
            .await?,
        )?;
        let tx_hash: alloy_primitives::TxHash = tx_hash_raw.parse()?;
        tracing::info!("claim_withdrawal tx submitted: {}", tx_hash);
        println!("claim_withdrawal tx: {}", tx_hash);

        let receipt = loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let result = rpc_call(rpc_url, "eth_getTransactionReceipt", serde_json::json!([format!("{:#x}", tx_hash)])).await;
            match result {
                Ok(val) if !val.is_null() => break val,
                _ => continue,
            }
        };
        let status_str = receipt["status"].as_str().unwrap_or("0x0");
        let status = u64::from_str_radix(status_str.trim_start_matches("0x"), 16).unwrap_or(0);
        if status != 1 {
            println!("status: failed");
            let trace = rpc_call(
                rpc_url,
                "debug_traceTransaction",
                serde_json::json!([format!("{:#x}", tx_hash), {"tracer": "callTracer"}]),
            )
            .await;
            let revert_reason = trace
                .ok()
                .and_then(|value| value["revertReason"].as_str().map(str::to_owned));
            anyhow::bail!(
                "L1 claim-withdrawal transaction reverted: tx_hash={:#x}, reason={}",
                tx_hash,
                revert_reason.as_deref().unwrap_or("unknown")
            );
        }

        // A status-1 receipt does not prove this nonce registered. Bind the
        // receipt's block hash first, then read claimedNullifiers there.
        let receipt_block = parse_block_number(
            receipt["blockNumber"].as_str().unwrap_or_default(),
            "claim-withdrawal receipt",
        )
        .map_err(|err| anyhow::anyhow!("claim-withdrawal receipt missing valid blockNumber: tx_hash={:#x}: {err}", tx_hash))?;
        let receipt_hash = parse_block_hash(&receipt["blockHash"], "claim-withdrawal receipt")
            .map_err(|err| anyhow::anyhow!("claim-withdrawal receipt missing valid blockHash: tx_hash={:#x}: {err}", tx_hash))?;
        let receipt_identity = ReceiptBlockIdentity { number: receipt_block, hash: receipt_hash };
        let registered = read_claimed_withdrawal_nonce_at_receipt(rpc_url, &bridge_addr, &nonce_hex, &receipt_identity)
            .await
            .map_err(|err| {
                anyhow::anyhow!(
                    "could not verify claimedNullifiers for nonce {} at receipt block {:#x} {}: {}",
                    nonce_hex, receipt_block, receipt_identity.hash, err
                )
            })?;
        let nonce_bytes = claimed_nonce_bytes(&nonce_hex)?;
        let receipt_logs = receipt
            .get("logs")
            .ok_or_else(|| anyhow::anyhow!("claim-withdrawal receipt missing logs: tx_hash={:#x}", tx_hash))?;
        let own_tuples = extract_withdrawal_pending_created_tuples(receipt_logs, &bridge_addr, &nonce_bytes)
            .map_err(|err| anyhow::anyhow!("claim-withdrawal receipt logs are malformed: tx_hash={:#x}: {err}", tx_hash))?;

        let reason_code = extract_withdrawal_claim_item_failure_reason(receipt_logs, &bridge_addr, &nonce_bytes);
        // A slot-0 failure for this nonce is authoritative and can never
        // coexist with a registration of the same item; it is parsed before any
        // success verdict so contradictory logs never confirm.
        if let Some(reason) = reason_code {
            anyhow::bail!(
                "L1 claim-withdrawal failed: nonce {} item skipped with {}; the WithdrawalClaimItemFailed event for this nonce and slot 0 is authoritative and refuses success",
                nonce_hex,
                describe_withdrawal_claim_failure_reason(reason)
            );
        }

        // This transaction's own WithdrawalPendingCreated for the nonce is the
        // only registration evidence for the submitted call.
        if registered && !own_tuples.is_empty() {
            println!("status: success");
            return Ok(CommandResult::L1Transaction(L1TransactionResult {
                transaction_hash: Some(format!("{:#x}", tx_hash)),
                status: L1TransactionStatus::Confirmed,
                chain_id: Some(chain_id),
            }));
        }

        let reason = if registered {
            "claimedNullifiers is true but no WithdrawalClaimItemFailed event decoded".to_string()
        } else {
            "claimedNullifiers is false and no WithdrawalClaimItemFailed event decoded".to_string()
        };
        println!(
            "claim not registered: nonce {} skipped at receipt block {:#x} ({})",
            nonce_hex, receipt_block, reason
        );
        anyhow::bail!(
            "L1 claim-withdrawal transaction succeeded but withdrawal nonce {} was not registered at receipt block {:#x}: {}",
            nonce_hex, receipt_block, reason
        );
    } else {
        Ok(CommandResult::L1Transaction(L1TransactionResult {
            transaction_hash: None,
            status: L1TransactionStatus::ProofOnly,
            chain_id: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeMap,
        io::{Read, Write},
        net::TcpListener,
        sync::{Arc, Mutex},
        thread,
    };

    use super::{
        build_claimed_withdrawal_nonce_call_data, bytes32_hex_to_u32x8_be, claimed_nonce_bytes, compute_withdrawal_leaf_hash,
        decimal_amount_to_hex, describe_withdrawal_claim_failure_reason, extract_withdrawal_claim_item_failure_reason,
        extract_withdrawal_pending_created_tuples, hex_to_u32x8_be, keccak256, normalize_u256_hex_32bytes, parse_u256_word_array,
        resolve_bridge_address_for_network, run, to_32byte_hex, LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE,
        WITHDRAWAL_BATCH_CLAIM_SIGNATURE, WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS, WITHDRAWAL_CLAIM_ITEM_FAILED_EVENT,
        WITHDRAWAL_PENDING_CREATED_EVENT, WITHDRAWAL_CLAIMED_EVENT,
    };
    use crate::result::{CommandResult, L1TransactionStatus};
    use crate::subcommand::args::ClaimWithdrawalArgs;

    fn spawn_single_response_server(body: serde_json::Value) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{}", addr)
    }

    #[test]
    fn claim_withdrawal_helpers_left_pad_20_byte_addresses() {
        let addr20 = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let addr32 = "0x0000000000000000000000001f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        assert_eq!(to_32byte_hex(addr20), addr32);
        assert_eq!(hex_to_u32x8_be(addr20).unwrap(), hex_to_u32x8_be(addr32).unwrap());
    }

    #[test]
    fn claim_withdrawal_nonce_normalization_matches_decimal_and_hex() {
        let decimal = normalize_u256_hex_32bytes("13").unwrap();
        let hex = normalize_u256_hex_32bytes("0x0d").unwrap();
        assert_eq!(decimal, hex);
        assert_eq!(bytes32_hex_to_u32x8_be(&decimal, "nonce").unwrap(), [0, 0, 0, 0, 0, 0, 0, 13]);
    }

    #[test]
    fn claim_withdrawal_signature_matches_current_slot_width() {
        assert_eq!(WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS, 1088);
        assert!(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.contains("[1088]"));
        assert_ne!(
            keccak256(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes())[..4],
            keccak256(LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes())[..4]
        );
    }

    #[test]
    fn claim_withdrawal_claimed_precheck_uses_raw_bytes32_nonce() {
        let nonce = "13";
        let normalized = normalize_u256_hex_32bytes(nonce).unwrap();
        let expected_nonce = hex::decode(normalized.trim_start_matches("0x")).unwrap();
        let calldata = build_claimed_withdrawal_nonce_call_data(nonce).unwrap();
        assert_eq!(&calldata[..4], &keccak256("claimedNullifiers(bytes32)".as_bytes())[..4]);
        assert_eq!(&calldata[4..], expected_nonce.as_slice());
    }

    #[test]
    fn claim_withdrawal_rejects_wrong_prove_proxy_array_lengths() {
        let proof_data = serde_json::json!({
            "solidity_proof": ["1", "2"],
        });
        let err = parse_u256_word_array(&proof_data, "solidity_proof", 8).unwrap_err();
        assert!(err.to_string().contains("prove-proxy solidity_proof length mismatch: expected 8, got 2"));
    }

    #[tokio::test]
    async fn claim_withdrawal_proof_only_mode_does_not_touch_l1_or_rpc_config() {
        let recipient = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let token_address = "0xd970407ff0af85d90d936c1c457504e5415af424";
        let amount = "990000000";
        let nonce = "13";
        let destination_chain_index = 0u64;
        let sender_user_id = 42u64;
        let normalized_nonce = normalize_u256_hex_32bytes(nonce).unwrap();
        let leaf_hash = compute_withdrawal_leaf_hash(
            sender_user_id,
            recipient,
            token_address,
            amount,
            &normalized_nonce,
            destination_chain_index,
        )
        .unwrap();
        let services_url = spawn_single_response_server(serde_json::json!({
            "success": true,
            "data": {
                "found": true,
                "leaf_index": 0,
                "leaf_hash": leaf_hash,
                "siblings": [],
                "withdrawal_root": "0x1234",
                "withdrawal": {
                    "sender_user_id": sender_user_id
                }
            }
        }));

        let args = ClaimWithdrawalArgs {
            rpc_config: "definitely-missing-config.json".to_string(),
            services_url,
            l1_rpc_url: "http://127.0.0.1:9".to_string(),
            private_key: "unused-in-proof-only-mode".to_string(),
            recipient: recipient.to_string(),
            token_address: token_address.to_string(),
            amount: amount.to_string(),
            nonce: nonce.to_string(),
            destination_chain_index,
            sender_user_id: None,
            prove_proxy_url: None,
            prove_proxy_token: None,
        };

        let result = run(args).await.unwrap();
        let CommandResult::L1Transaction(result) = result else {
            panic!("expected L1 transaction result");
        };
        assert!(matches!(result.status, L1TransactionStatus::ProofOnly));
        assert_eq!(result.transaction_hash, None);
        assert_eq!(result.chain_id, None);
    }

    #[test]
    fn claim_withdrawal_resolves_localhost_bridge_from_checked_in_deployments() {
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        let summary_path = super::super::deployments::resolve_deployments_file("localhost", "deployed-contracts.json");
        let summary: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(summary_path).unwrap()).unwrap();
        let expected = summary["proxies"]["Bridge_Proxy"]
            .as_str()
            .or_else(|| summary["core"]["Bridge"].as_str())
            .unwrap();
        assert_eq!(bridge, expected);
    }

    type RpcRequestLog = Arc<Mutex<Vec<(String, serde_json::Value)>>>;

    const L1_TEST_RPC_CONFIG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../../psy-genesis/config.json");
    /// Well-known anvil devnet key #0 — public test fixture, not a secret.
    const L1_TEST_PRIVATE_KEY: &str =
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";

    fn u256_word(value: u64) -> serde_json::Value {
        serde_json::json!(format!("0x{:064x}", value))
    }

    fn repeat_words(count: usize) -> serde_json::Value {
        serde_json::Value::Array((0..count).map(|_| serde_json::json!("0")).collect())
    }

    fn read_http_request_body(stream: &mut std::net::TcpStream) -> Option<String> {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let n = stream.read(&mut chunk).ok()?;
            buf.extend_from_slice(&chunk[..n]);
            if let Some(header_end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..header_end]);
                let mut content_length = 0usize;
                for line in head.lines() {
                    if let Some((name, value)) = line.split_once(':') {
                        if name.trim().eq_ignore_ascii_case("content-length") {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let body_start = header_end + 4;
                if buf.len() >= body_start + content_length {
                    return Some(String::from_utf8_lossy(&buf[body_start..body_start + content_length]).into_owned());
                }
            }
            if n == 0 {
                return None;
            }
        }
    }

    fn write_http_json_response(stream: &mut std::net::TcpStream, body: &serde_json::Value) {
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).unwrap();
    }

    /// JSON-RPC node for the full claim flow. `eth_call` responses are keyed by
    /// `<block tag>:<selector hex>` (see `call_key`) so the pre-send "latest"
    /// read and the receipt-hash pinned reads are canned independently; every
    /// request is recorded so tests can assert pinned blocks and call counts.
    fn spawn_rpc_router(
        methods: BTreeMap<&'static str, serde_json::Value>,
        calls_by_block: BTreeMap<String, serde_json::Value>,
        requests: RpcRequestLog,
    ) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        let methods = Arc::new(methods);
        let calls_by_block = Arc::new(calls_by_block);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(body) = read_http_request_body(&mut stream) else { continue };
                let Ok(request) = serde_json::from_str::<serde_json::Value>(&body) else { continue };
                let method = request["method"].as_str().unwrap_or("").to_string();
                let params = request["params"].clone();
                requests.lock().unwrap().push((method.clone(), params));
                let id = request["id"].clone();
                let canned = if method == "eth_call" {
                    let block_param = &request["params"][1];
                    let block_tag = block_param["blockHash"].as_str().or_else(|| block_param.as_str()).unwrap_or("");
                    let selector = request["params"][0]["data"].as_str().and_then(|data| data.get(2..10)).unwrap_or("");
                    calls_by_block.get(&format!("{block_tag}:{selector}")).cloned()
                } else {
                    methods.get(method.as_str()).cloned()
                };
                let response = match canned {
                    Some(value) if value.get("rpc_error").is_some() => serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": {
                            "code": value["rpc_code"].as_i64().unwrap_or(-32000),
                            "message": value["rpc_error"].as_str().unwrap_or("test rpc error")
                        }
                    }),
                    Some(value) => serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": value }),
                    None => serde_json::json!({
                        "jsonrpc": "2.0", "id": id,
                        "error": { "code": -32601, "message": format!("test server has no canned response for {method}") }
                    }),
                };
                write_http_json_response(&mut stream, &response);
            }
        });
        format!("http://{}", addr)
    }

    const FIXTURE_BLOCK_HASH: &str = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn mined_status1_receipt(block_number: &str, logs: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "status": "0x1",
            "blockNumber": block_number,
            "blockHash": FIXTURE_BLOCK_HASH,
            "logs": logs
        })
    }

    /// eth_call canned-response key: block tag plus the 4-byte selector hex, so
    /// different getters at the same block can be canned independently.
    fn call_key(block: &str, signature: &str) -> String {
        format!("{}:{}", block, hex::encode(&keccak256(signature.as_bytes())[..4]))
    }

    fn claimed_key(block: &str) -> String {
        call_key(block, "claimedNullifiers(bytes32)")
    }

    fn recorded_calls(requests: &RpcRequestLog) -> Vec<serde_json::Value> {
        requests
            .lock()
            .unwrap()
            .iter()
            .filter(|(method, _)| method == "eth_call")
            .map(|(_, params)| params.clone())
            .collect()
    }

    fn assert_eth_call_targets_claimed_nullifiers(params: &serde_json::Value) {
        let data = params[0]["data"].as_str().unwrap();
        let selector = format!("0x{}", hex::encode(&keccak256("claimedNullifiers(bytes32)".as_bytes())[..4]));
        assert!(data.starts_with(&selector), "eth_call must target claimedNullifiers: {data}");
        assert_eq!(hex::decode(&data[2 + selector.len() - 2..]).unwrap().len(), 32, "nonce word must be 32 bytes");
    }

    /// WithdrawalPendingCreated log for the fixture's withdrawal (nonce 13,
    /// token 0xd970…, recipient 0x1f1a…). The amount word is opaque to the
    /// submitter, which never compares payout fields.
    fn pending_created_log(amount_word: &str) -> serde_json::Value {
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        serde_json::json!([{
            "address": bridge,
            "topics": [
                format!("0x{}", hex::encode(&keccak256(WITHDRAWAL_PENDING_CREATED_EVENT.as_bytes())[..])),
                normalize_u256_hex_32bytes("13").unwrap(),
                to_32byte_hex("0xd970407ff0af85d90d936c1c457504e5415af424"),
                to_32byte_hex("0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9"),
            ],
            "data": format!("0x{}{}", &amount_word[2..], format!("{:064x}", 0u64)),
        }])
    }

    #[test]
    fn direct_payment_receipt_decodes_recipient_and_token_in_claimed_event_order() {
        let amount = normalize_u256_hex_32bytes("123").unwrap();
        let mut logs = pending_created_log(&amount);
        let topics = logs[0]["topics"].as_array_mut().unwrap();
        topics[0] = serde_json::json!(format!("0x{}", hex::encode(keccak256(WITHDRAWAL_CLAIMED_EVENT.as_bytes()))));
        topics.swap(2, 3);
        logs[0]["data"] = serde_json::json!(amount);
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        let nonce = claimed_nonce_bytes("13").unwrap();
        let tuples = extract_withdrawal_pending_created_tuples(&logs, &bridge, &nonce).unwrap();
        let pending = extract_withdrawal_pending_created_tuples(&pending_created_log(&amount), &bridge, &nonce).unwrap();
        assert_eq!(tuples, pending);
        logs[0]["data"] = serde_json::json!("0x01");
        assert!(extract_withdrawal_pending_created_tuples(&logs, &bridge, &nonce).is_err());
    }

    /// WithdrawalClaimItemFailed log for nonce 13, slot 0, with a numeric reason.
    fn item_failed_log(reason: u8) -> serde_json::Value {
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        serde_json::json!([{
            "address": bridge,
            "topics": [
                format!("0x{}", hex::encode(&keccak256(WITHDRAWAL_CLAIM_ITEM_FAILED_EVENT.as_bytes())[..])),
                normalize_u256_hex_32bytes("13").unwrap(),
                format!("0x{:064x}", 0u64),
            ],
            "data": format!("0x{:064x}", reason as u64),
        }])
    }

    /// The amount word the fixture's args decode to (matches prod's
    /// decimal_amount_to_hex path).
    fn fixture_amount_word() -> String {
        decimal_amount_to_hex("990000000")
    }

    /// Full claim flow: services proof, prove-proxy proof, and a canned L1 node.
    /// Receipt-block eth_call entries are inserted as
    /// `claimed_key("<receipt number hex>")` and mirrored onto the receipt hash
    /// the pinned read uses; the pre-send "latest" read defaults to unclaimed
    /// unless the test overrides it. `method_overrides` replaces canned
    /// non-call methods (e.g. an rpc_error for eth_estimateGas).
    fn l1_claim_flow_fixture(
        receipt: serde_json::Value,
        mut calls_by_block: BTreeMap<String, serde_json::Value>,
        method_overrides: BTreeMap<&'static str, serde_json::Value>,
    ) -> (ClaimWithdrawalArgs, RpcRequestLog) {
        let recipient = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let token_address = "0xd970407ff0af85d90d936c1c457504e5415af424";
        let amount = "990000000";
        let nonce = "13";
        let sender_user_id = 42u64;
        let normalized_nonce = normalize_u256_hex_32bytes(nonce).unwrap();
        let leaf_hash = compute_withdrawal_leaf_hash(sender_user_id, recipient, token_address, amount, &normalized_nonce, 0).unwrap();

        let services_url = spawn_single_response_server(serde_json::json!({
            "success": true,
            "data": {
                "found": true,
                "leaf_index": 0,
                "leaf_hash": leaf_hash,
                "siblings": [],
                "withdrawal_root": "0x1234",
                "withdrawal": { "sender_user_id": sender_user_id }
            }
        }));

        let prove_proxy_url = spawn_single_response_server(serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "solidity_proof": repeat_words(8),
                "public_inputs": repeat_words(18),
                "slot_data": repeat_words(WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS),
            }
        }));

        let mut methods = BTreeMap::new();
        methods.insert("eth_chainId", serde_json::json!("0x7a69"));
        methods.insert("eth_getTransactionCount", serde_json::json!("0x0"));
        methods.insert("eth_estimateGas", serde_json::json!("0x186a0"));
        methods.insert("eth_feeHistory", serde_json::json!({ "baseFeePerGas": ["0x1"], "reward": [["0x1"]] }));
        methods.insert(
            "eth_sendRawTransaction",
            serde_json::json!("0x9f8c3f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e"),
        );
        methods.insert("eth_getTransactionReceipt", receipt);
        for (method, value) in method_overrides {
            methods.insert(method, value);
        }

        calls_by_block
            .entry(claimed_key("latest"))
            .or_insert_with(|| u256_word(0));
        let receipt_number = methods
            .get("eth_getTransactionReceipt")
            .and_then(|receipt| receipt["blockNumber"].as_str())
            .unwrap_or("")
            .to_string();
        let receipt_hash = methods
            .get("eth_getTransactionReceipt")
            .and_then(|receipt| receipt["blockHash"].as_str())
            .unwrap_or(FIXTURE_BLOCK_HASH)
            .to_string();
        let mirrored: Vec<(String, serde_json::Value)> = calls_by_block
            .iter()
            .filter_map(|(key, value)| {
                key.strip_prefix(&format!("{receipt_number}:"))
                    .map(|selector| (format!("{receipt_hash}:{selector}"), value.clone()))
            })
            .collect();
        for (key, value) in mirrored {
            calls_by_block.entry(key).or_insert(value);
        }

        let requests: RpcRequestLog = Arc::new(Mutex::new(Vec::new()));
        let l1_rpc_url = spawn_rpc_router(methods, calls_by_block, requests.clone());

        let args = ClaimWithdrawalArgs {
            rpc_config: L1_TEST_RPC_CONFIG.to_string(),
            services_url,
            l1_rpc_url,
            private_key: L1_TEST_PRIVATE_KEY.to_string(),
            recipient: recipient.to_string(),
            token_address: token_address.to_string(),
            amount: amount.to_string(),
            nonce: nonce.to_string(),
            destination_chain_index: 0,
            sender_user_id: None,
            prove_proxy_url: Some(prove_proxy_url),
            prove_proxy_token: None,
        };
        (args, requests)
    }

    #[tokio::test]
    async fn claim_withdrawal_pre_send_consumed_nonce_refuses_to_submit() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("latest"), u256_word(1));
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("a consumed nonce must not be submitted"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("already consumed"), "{err}");
        assert!(requests.lock().unwrap().iter().all(|(method, _)| method != "eth_sendRawTransaction"));
    }

    #[tokio::test]
    async fn claim_withdrawal_own_registration_event_returns_confirmed() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(1));
        let receipt = mined_status1_receipt("0x10", pending_created_log(&fixture_amount_word()));
        let (args, requests) = l1_claim_flow_fixture(receipt, calls_by_block, BTreeMap::new());

        let result = run(args).await.unwrap();
        let CommandResult::L1Transaction(result) = result else {
            panic!("expected L1 transaction result");
        };
        assert!(matches!(result.status, L1TransactionStatus::Confirmed));
        assert!(result.transaction_hash.is_some());
        assert_eq!(result.chain_id, Some(31337));

        // One pre-send read at "latest", then claimedNullifiers pinned to the
        // receipt hash; status 1 alone never confirms.
        let calls = recorded_calls(&requests);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], serde_json::json!("latest"));
        assert_eq!(calls[1][1]["blockHash"], serde_json::json!(FIXTURE_BLOCK_HASH));
        assert_eq!(calls[1][1]["requireCanonical"], serde_json::json!(true));
        for params in &calls {
            assert_eth_call_targets_claimed_nullifiers(params);
        }
    }

    #[tokio::test]
    async fn claim_withdrawal_unregistered_nonce_fails_closed() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(0));
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("expected claim-withdrawal to fail closed"),
            Err(error) => error,
        };
        let normalized_nonce = normalize_u256_hex_32bytes("13").unwrap();
        let message = err.to_string();
        assert!(message.contains(&normalized_nonce), "error must name the nonce: {message}");
        assert!(message.contains("not registered"), "error must state the skip: {message}");
        assert!(message.contains("claimedNullifiers is false"), "error must name the mapping state: {message}");

        let calls = recorded_calls(&requests);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], serde_json::json!("latest"));
        assert_eq!(calls[1][1]["blockHash"], serde_json::json!(FIXTURE_BLOCK_HASH));
        assert_eth_call_targets_claimed_nullifiers(&calls[1]);
    }

    #[tokio::test]
    async fn claim_withdrawal_registered_without_own_event_fails_closed() {
        // claimedNullifiers is true at the receipt but this transaction's logs
        // carry no WithdrawalPendingCreated for the nonce: nothing confirms and
        // the nonce is never labeled as belonging to this withdrawal.
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(1));
        let (args, _) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("registration without this tx's own event must not confirm"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("not registered"), "{message}");
        assert!(message.contains("no WithdrawalClaimItemFailed event decoded"), "{message}");
    }

    #[tokio::test]
    async fn claim_withdrawal_reason5_item_failed_is_authoritative() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(0));
        let (args, _) = l1_claim_flow_fixture(mined_status1_receipt("0x10", item_failed_log(5)), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("reason 5 must fail"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("nullifier already claimed (5)"), "error must carry the frozen reason: {message}");
        assert!(message.contains("skipped"), "{message}");
        assert!(!message.contains("not registered"), "reason 5 is reported verbatim: {message}");
    }

    #[tokio::test]
    async fn claim_withdrawal_item_failed_surfaces_frozen_reason() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(0));
        let (args, _) = l1_claim_flow_fixture(mined_status1_receipt("0x10", item_failed_log(8)), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("expected claim-withdrawal to fail closed"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("amount out of range (8)"), "error must carry the frozen reason: {message}");
        assert!(message.contains("authoritative"), "the failure event refuses success: {message}");
    }

    #[tokio::test]
    async fn claim_withdrawal_conflicting_created_and_failed_logs_fail_closed() {
        // A receipt carrying both this nonce's WithdrawalPendingCreated and a
        // slot-0 WithdrawalClaimItemFailed is contradictory evidence: the
        // failure event is parsed before any success verdict and refuses
        // confirmation.
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(1));
        let mut both = pending_created_log(&fixture_amount_word());
        both.as_array_mut().unwrap().push(item_failed_log(5)[0].clone());
        let (args, _) = l1_claim_flow_fixture(mined_status1_receipt("0x10", both), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("contradictory created+failed logs must never confirm"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("nullifier already claimed (5)"), "{message}");
        assert!(message.contains("authoritative"), "{message}");
    }

    #[tokio::test]
    async fn claim_withdrawal_claimed_read_error_fails_closed() {
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), serde_json::json!({ "rpc_error": "node unavailable" }));
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("expected claim-withdrawal to fail closed"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(message.contains("could not verify claimedNullifiers"), "unexpected error: {message}");
        assert!(message.contains("receipt block 0x10"), "error must pin the receipt block: {message}");

        let calls = recorded_calls(&requests);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], serde_json::json!("latest"));
        assert_eq!(calls[1][1]["blockHash"], serde_json::json!(FIXTURE_BLOCK_HASH));
    }

    #[tokio::test]
    async fn claim_withdrawal_malformed_bool_word_fails_closed() {
        // One-byte word: not a valid ABI bool return, must never decode as false.
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), serde_json::json!("0x01"));
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("expected claim-withdrawal to fail closed"),
            Err(error) => error,
        };
        let message = err.to_string();
        assert!(
            message.contains("could not verify claimedNullifiers"),
            "unexpected error: {message}"
        );
        assert!(
            message.contains("claimedNullifiers returned a 1-byte bool word, expected exactly 32"),
            "error must name the malformed word: {message}"
        );

        let calls = recorded_calls(&requests);
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0][1], serde_json::json!("latest"));
        assert_eq!(calls[1][1]["blockHash"], serde_json::json!(FIXTURE_BLOCK_HASH));
    }

    #[tokio::test]
    async fn claim_withdrawal_noncanonical_bool_word_fails_closed() {
        // 32 bytes but value 2: neither canonical true nor false.
        let mut calls_by_block = BTreeMap::new();
        calls_by_block.insert(claimed_key("0x10"), u256_word(2));
        let (args, _requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), calls_by_block, BTreeMap::new());

        let err = match run(args).await {
            Ok(_) => panic!("expected claim-withdrawal to fail closed"),
            Err(error) => error,
        };
        assert!(
            err.to_string().contains("claimedNullifiers returned invalid bool value 2"),
            "error must reject the non-canonical word"
        );
    }

    #[tokio::test]
    async fn claim_withdrawal_estimate_error_fails_closed_without_send() {
        let mut overrides = BTreeMap::new();
        overrides.insert("eth_estimateGas", serde_json::json!({ "rpc_error": "gas required exceeds allowance" }));
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), BTreeMap::new(), overrides);

        let err = match run(args).await {
            Ok(_) => panic!("an estimate failure must not invent success"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("eth_estimateGas"), "{err}");
        assert!(requests.lock().unwrap().iter().all(|(method, _)| method != "eth_sendRawTransaction"));
    }

    #[tokio::test]
    async fn claim_withdrawal_send_error_fails_closed_without_retry() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "eth_sendRawTransaction",
            serde_json::json!({ "rpc_error": "replacement transaction underpriced" }),
        );
        let (args, requests) =
            l1_claim_flow_fixture(mined_status1_receipt("0x10", serde_json::json!([])), BTreeMap::new(), overrides);

        let err = match run(args).await {
            Ok(_) => panic!("a send failure must not invent success"),
            Err(error) => error,
        };
        assert!(err.to_string().contains("eth_sendRawTransaction"), "{err}");
        let requests = requests.lock().unwrap();
        assert_eq!(
            requests.iter().filter(|(method, _)| method == "eth_sendRawTransaction").count(),
            1,
            "the unknown-outcome transaction is never resubmitted"
        );
        assert!(requests.iter().all(|(method, _)| method != "eth_getTransactionReceipt"));
    }

    #[test]
    fn claim_withdrawal_item_failed_event_requires_emitter_tuple() {
        let normalized_nonce = normalize_u256_hex_32bytes("13").unwrap();
        let nonce_bytes: [u8; 32] = hex::decode(normalized_nonce.trim_start_matches("0x")).unwrap().try_into().unwrap();
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        let topic0 = format!("0x{}", hex::encode(&keccak256(WITHDRAWAL_CLAIM_ITEM_FAILED_EVENT.as_bytes())[..]));
        let zero_word = format!("0x{:064x}", 0u64);
        let log_with = |address: &str, nonce_topic: &str, slot_topic: &str, data: &str| {
            serde_json::json!([{
                "address": address,
                "topics": [topic0.clone(), nonce_topic, slot_topic],
                "data": data,
            }])
        };
        let reason_word = format!("0x{:064x}", 8u64);

        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(&log_with(&bridge, &normalized_nonce, &zero_word, &reason_word), &bridge, &nonce_bytes),
            Some(8)
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(&log_with(&bridge, &normalized_nonce, &zero_word, &reason_word), &bridge, &[0u8; 32]),
            None,
            "a Failed event for a different nonce must be ignored"
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(
                &log_with("0x000000000000000000000000000000000000dead", &normalized_nonce, &zero_word, &reason_word),
                &bridge,
                &nonce_bytes
            ),
            None,
            "a Failed event from another emitter must be ignored"
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(
                &log_with(&bridge, &normalized_nonce, &format!("0x{:064x}", 1u64), &reason_word),
                &bridge,
                &nonce_bytes
            ),
            None,
            "a Failed event for a nonzero slot must be ignored (single-slot submitter)"
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(&log_with(&bridge, &normalized_nonce, &zero_word, "0x08"), &bridge, &nonce_bytes),
            None,
            "a malformed reason data word must be undecodable, not a reason"
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(
                &log_with(&bridge, &normalized_nonce, &zero_word, &format!("0x{:063x}08", 1u64)),
                &bridge,
                &nonce_bytes
            ),
            None,
            "a non-canonical reason word (upper bytes set) must be undecodable"
        );
        assert_eq!(
            extract_withdrawal_claim_item_failure_reason(&serde_json::json!({}), &bridge, &nonce_bytes),
            None
        );
    }

    #[test]
    fn claim_withdrawal_pending_created_log_presence_and_validation() {
        let nonce_bytes = claimed_nonce_bytes("13").unwrap();
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        let amount_word = fixture_amount_word();
        let log = pending_created_log(&amount_word);

        // This tx's own event for the nonce is registration evidence; presence
        // is all the submitter reads — payout fields are never compared.
        let tuples = extract_withdrawal_pending_created_tuples(&log, &bridge, &nonce_bytes).unwrap();
        assert_eq!(tuples.len(), 1);
        let expected_token = hex::decode(to_32byte_hex("0xd970407ff0af85d90d936c1c457504e5415af424").trim_start_matches("0x")).unwrap();
        assert_eq!(tuples[0].0.as_slice(), expected_token.as_slice());

        // A reorg-removed log is never evidence.
        let mut removed = pending_created_log(&amount_word);
        removed[0]["removed"] = serde_json::json!(true);
        assert!(extract_withdrawal_pending_created_tuples(&removed, &bridge, &nonce_bytes).unwrap().is_empty());

        // Wrong nonce / wrong emitter must not decode.
        assert!(extract_withdrawal_pending_created_tuples(&log, &bridge, &[0u8; 32]).unwrap().is_empty());
        assert!(
            extract_withdrawal_pending_created_tuples(&log, "0x000000000000000000000000000000000000dead", &nonce_bytes)
                .unwrap()
                .is_empty()
        );

        // A malformed `removed` flag is an error, never a silent skip.
        for flag in [serde_json::json!("true"), serde_json::json!(1), serde_json::json!(null)] {
            let mut bad = pending_created_log(&amount_word);
            bad[0]["removed"] = flag;
            let err = extract_withdrawal_pending_created_tuples(&bad, &bridge, &nonce_bytes).unwrap_err();
            assert!(err.to_string().contains("not a boolean"), "{err}");
        }

        // A recognized event with a wrong topic count is an error, not an ignored log.
        let mut short_topics = pending_created_log(&amount_word);
        short_topics[0]["topics"] = serde_json::json!([short_topics[0]["topics"][0]]);
        assert!(extract_withdrawal_pending_created_tuples(&short_topics, &bridge, &nonce_bytes).is_err());
    }

    #[test]
    fn claim_withdrawal_failure_reason_names_are_frozen() {
        assert_eq!(describe_withdrawal_claim_failure_reason(5), "nullifier already claimed (5)");
        assert_eq!(describe_withdrawal_claim_failure_reason(10), "claimable-at overflow (10)");
        assert!(describe_withdrawal_claim_failure_reason(11).contains("unknown"), "reserved codes stay unnamed");
    }
}
