//! Subcommand: deposit — initiate an L1→L2 deposit via the Router contract.
//!
//! Calls Router.deposit(token, amount, shieldAddress, noteCommitment) on L1.
//! The Router forwards the call to the appropriate Gateway (ERC20 or ETH),
//! which then calls Bridge.recordDepositFromGateway.
//!
//! Usage:
//!   psy_user_cli deposit \
//!     --private-key <key> \
//!     --router-address <addr> \
//!     --token <addr> --amount <wei> \
//!     --shield-address <hex> --note-commitment <hex>
//!
//! Or with r0/r1 (auto-derives shield_address):
//!   psy_user_cli deposit \
//!     --private-key <key> \
//!     --router-address <addr> \
//!     --token <addr> --amount <wei> \
//!     --note-commitment <hex> \
//!     --r0 <n> --r1 <n> --user-id <id>

use std::str::FromStr;

use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_primitives::{Address, TxHash, B256, U256};
use alloy_signer::Signer;
use alloy_signer_local::PrivateKeySigner;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use futures_util::{SinkExt, StreamExt};
use nostr_sdk::{prelude::*, UnsignedEvent};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    plonk::config::PoseidonGoldilocksConfig,
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    config::store_config::F,
    privacy::deposit_inclusion::DepositInclusionInput,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_crypto::{
    hash::{
        merkle::core::MerkleProofCore,
        traits::hasher::{FieldQHasher, PoseidonHasher},
    },
    shield_address::{derive_note_commitment, derive_nullifier_hash, derive_shield_address, qhashout_to_u32x8_be, shield_address_to_bytes32},
};
use psy_dpn_circuit::circuits::privacy::deposit_inclusion::DepositInclusionCircuit;
use psy_provider::provider::RpcProvider;
use serde::Deserialize;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use super::{args::DepositArgs, note_proof_common::qhash_to_u64x4};
use crate::result::{CommandResult, L1TransactionResult, L1TransactionStatus};

const BRIDGE_USER_ID_U64: u64 = 524288;
const DEPOSIT_TREE_CONTRACT_ID: u32 = 2;
const DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE: u64 = 8 + (8192 * 8);

fn resolve_shield_address(args: &DepositArgs) -> anyhow::Result<String> {
    match (args.r0, args.r1, args.user_id) {
        (Some(r0), Some(r1), Some(user_id)) => {
            let shield = derive_shield_address(user_id, r0, r1);
            let shield_bytes32 = shield_address_to_bytes32(shield);
            let shield_hex = format!("0x{}", hex::encode(shield_bytes32));
            tracing::info!(
                user_id = user_id, r0 = r0, r1 = r1,
                shield_address_display = %shield,
                shield_address_bytes32 = %shield_hex,
                "shield address derived from r0/r1"
            );
            Ok(shield_hex)
        }
        _ => {
            let sa = args.shield_address.trim();
            if sa.is_empty() || sa == "0x" || sa == "0x0" {
                anyhow::bail!("either --shield-address or (--r0 --r1 --user-id) is required");
            }
            Ok(sa.to_string())
        }
    }
}

fn parse_u64x4_arg(name: &str, raw: &str) -> anyhow::Result<[u64; 4]> {
    let cleaned = raw.trim().trim_start_matches('[').trim_end_matches(']').replace(['"', '\''], "");
    let parts: Vec<&str> = cleaned.split(',').map(str::trim).filter(|part| !part.is_empty()).collect();
    if parts.len() != 4 {
        anyhow::bail!("{} must contain exactly four comma-separated u64 limbs", name);
    }
    let mut out = [0u64; 4];
    for (idx, part) in parts.iter().enumerate() {
        out[idx] = if let Some(hex) = part.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)?
        } else {
            part.parse::<u64>()?
        };
    }
    Ok(out)
}

fn bytes32_hex_to_u64x4(raw: &str) -> anyhow::Result<[u64; 4]> {
    let bytes: [u8; 32] = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32-byte hex value"))?;
    Ok(std::array::from_fn(|i| {
        let start = i * 8;
        u64::from_be_bytes(bytes[start..start + 8].try_into().expect("fixed 8-byte chunk"))
    }))
}

fn u64x4_to_bytes32_hex(words: [u64; 4]) -> String {
    let mut bytes = [0u8; 32];
    for (idx, word) in words.iter().enumerate() {
        bytes[idx * 8..(idx + 1) * 8].copy_from_slice(&word.to_be_bytes());
    }
    format!("0x{}", hex::encode(bytes))
}

#[derive(Clone)]
struct DepositBackupInput {
    recipient_npub: Option<String>,
    note_secret: [u64; 4],
    nullifier_secret: [u64; 4],
}

struct DepositBackupPublishResult {
    proof_event_id: String,
    secrets_event_id: String,
}

fn resolve_note_commitment(args: &DepositArgs) -> anyhow::Result<(String, Option<DepositBackupInput>)> {
    let note_secret = args.note_secret.as_deref().map(|raw| parse_u64x4_arg("--note-secret", raw)).transpose()?;
    let nullifier_secret = args
        .nullifier_secret
        .as_deref()
        .map(|raw| parse_u64x4_arg("--nullifier-secret", raw))
        .transpose()?;

    if note_secret.is_some() != nullifier_secret.is_some() {
        anyhow::bail!("--note-secret and --nullifier-secret must be provided together");
    }

    let derived_commitment = match (note_secret, nullifier_secret) {
        (Some(note), Some(nullifier)) => {
            let commitment = u64x4_to_bytes32_hex(qhash_to_u64x4(derive_note_commitment(nullifier, note)));
            if let Some(explicit) = args.note_commitment.as_deref() {
                let explicit_norm = format!("0x{}", explicit.trim_start_matches("0x").to_ascii_lowercase());
                if explicit_norm != commitment {
                    anyhow::bail!(
                        "--note-commitment {} does not match hash(nullifier_secret, note_secret) {}",
                        explicit,
                        commitment
                    );
                }
            }
            let backup = Some(DepositBackupInput {
                recipient_npub: args.recipient_npub.clone(),
                note_secret: note,
                nullifier_secret: nullifier,
            });
            (commitment, backup)
        }
        (None, None) => {
            if args.recipient_npub.is_some() || args.deposit_proof_output.is_some() {
                anyhow::bail!("--recipient-npub and --deposit-proof-output require --note-secret and --nullifier-secret");
            }
            let commitment = args
                .note_commitment
                .clone()
                .ok_or_else(|| anyhow::anyhow!("--note-commitment is required unless note/nullifier secrets are provided"))?;
            (commitment, None)
        }
        _ => unreachable!("matched by paired-secret validation above"),
    };

    Ok(derived_commitment)
}

/// Selector for Router.deposit(address,uint256,bytes32,bytes32)
const DEPOSIT_SELECTOR: [u8; 4] = [0x7d, 0xcc, 0x9f, 0x07];

fn encode_deposit_call(token: &str, amount: &str, shield_address: &str, note_commitment: &str) -> anyhow::Result<Vec<u8>> {
    let token_addr: Address = token.parse().map_err(|e| anyhow::anyhow!("invalid token address: {}", e))?;
    let amount_val: U256 = amount.parse::<U256>().map_err(|e| anyhow::anyhow!("invalid amount: {}", e))?;
    let shield: [u8; 32] = hex::decode(shield_address.strip_prefix("0x").unwrap_or(shield_address))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("shield_address must be 32 bytes"))?;
    let note_commitment_bytes: [u8; 32] = hex::decode(note_commitment.strip_prefix("0x").unwrap_or(note_commitment))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("note_commitment must be 32 bytes"))?;

    let mut data = Vec::with_capacity(4 + 32 * 4);
    data.extend_from_slice(&DEPOSIT_SELECTOR);
    let mut addr_padded = [0u8; 32];
    addr_padded[12..].copy_from_slice(token_addr.as_slice());
    data.extend_from_slice(&addr_padded);
    let amount_bytes = amount_val.to_be_bytes::<32>();
    data.extend_from_slice(&amount_bytes);
    data.extend_from_slice(&shield);
    data.extend_from_slice(&note_commitment_bytes);
    Ok(data)
}

fn resolve_router_address(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Router_Proxy", "Router", "Router_Proxy.json")
}

fn resolve_bridge_address(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Bridge_Proxy", "Bridge", "Bridge_Proxy.json")
}

async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
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

fn u256_to_hex(v: U256) -> String {
    if v.is_zero() {
        return "0x0".into();
    }
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    format!("0x{}", hex::encode(&bytes[start..]))
}

fn decimal_limbs(values: [u64; 4]) -> [String; 4] {
    [values[0].to_string(), values[1].to_string(), values[2].to_string(), values[3].to_string()]
}

fn canonical_shield_address_metadata(raw: &str) -> anyhow::Result<String> {
    Ok(decimal_limbs(bytes32_hex_to_u64x4(raw)?).join(":"))
}

fn parse_eth_call_u64(result: &serde_json::Value) -> anyhow::Result<u64> {
    let raw = result.as_str().ok_or_else(|| anyhow::anyhow!("expected string result from eth_call"))?;
    let raw = raw.trim().trim_start_matches("0x").trim_start_matches('0');
    if raw.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(raw, 16).map_err(|e| anyhow::anyhow!("failed to parse eth_call u64 result: {}", e))
}

async fn fetch_proved_deposit_count(l1_rpc_url: &str, bridge_address: &str) -> anyhow::Result<u64> {
    let result = rpc_call(
        l1_rpc_url,
        "eth_call",
        serde_json::json!([{
            "to": bridge_address,
            "data": "0x939497f0"
        }, "latest"]),
    )
    .await?;
    parse_eth_call_u64(&result)
}

fn read_single_felt_from_packed_leaf(leaf: QHashOut<GoldilocksField>, sub_slot_index: u64) -> anyhow::Result<u64> {
    let offset = (sub_slot_index % 4) as usize;
    let value = leaf.0.elements[offset].to_canonical_u64();
    anyhow::ensure!(
        value <= u32::MAX as u64,
        "packed contract-state value exceeds u32 range: sub_slot={} value={}",
        sub_slot_index,
        value
    );
    Ok(value)
}

async fn fetch_deposit_tree_next_index(provider: &RpcProvider, checkpoint_id: u64, chain_index: u64) -> anyhow::Result<u64> {
    let sub_slot_index = DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE + chain_index;
    let leaf_index = sub_slot_index / 4;
    let next_index_leaf = provider
        .get_user_contract_state_tree_leaf_hash(
            checkpoint_id,
            BRIDGE_USER_ID_U64,
            DEPOSIT_TREE_CONTRACT_ID,
            psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT,
            leaf_index,
        )
        .await?;
    read_single_felt_from_packed_leaf(next_index_leaf, sub_slot_index)
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DepositClaimProofDeposit {
    shield_address: String,
    token_address: String,
    l2_token_contract_id: String,
    amount: String,
    note_commitment: String,
    source_chain_id: u32,
}

#[derive(Debug, Deserialize)]
struct DepositClaimProofResponse {
    found: bool,
    reason: Option<String>,
    checkpoint_id: Option<u64>,
    deposit_index: Option<u64>,
    chain_local_deposit_index: Option<u64>,
    snapshot_deposit_count: Option<u64>,
    proved_deposit_count: Option<u64>,
    tree_count: Option<u64>,
    proved_count: Option<u64>,
    proved_root: Option<String>,
    deposit_root: Option<String>,
    leaf_hash: Option<String>,
    siblings: Option<Vec<String>>,
    deposit: Option<DepositClaimProofDeposit>,
}

struct ReadyDepositProof {
    deposit_root: QHashOut<F>,
    deposit_proof: MerkleProofCore<QHashOut<F>>,
    deposit: DepositClaimProofDeposit,
    proved_deposit_count: u64,
    checkpoint_id: Option<u64>,
}

fn u64x4_to_u32x8_be(words: [u64; 4]) -> [u32; 8] {
    [
        (words[0] >> 32) as u32,
        (words[0] & 0xffff_ffff) as u32,
        (words[1] >> 32) as u32,
        (words[1] & 0xffff_ffff) as u32,
        (words[2] >> 32) as u32,
        (words[2] & 0xffff_ffff) as u32,
        (words[3] >> 32) as u32,
        (words[3] & 0xffff_ffff) as u32,
    ]
}

fn parse_decimal_uint_to_u32x8(value: &str) -> anyhow::Result<[u32; 8]> {
    let s = value.trim();
    anyhow::ensure!(!s.is_empty(), "decimal amount is empty");
    let mut words = [0u32; 8];
    for byte in s.bytes() {
        anyhow::ensure!(byte.is_ascii_digit(), "amount must be an unsigned decimal string");
        let mut carry = (byte - b'0') as u64;
        for word in words.iter_mut().rev() {
            let next = (*word as u64) * 10 + carry;
            *word = next as u32;
            carry = next >> 32;
        }
        anyhow::ensure!(carry == 0, "amount exceeds uint256");
    }
    Ok(words)
}

fn parse_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    anyhow::ensure!(raw.len() == 64, "expected 32-byte hex, got {} hex chars", raw.len());
    let bytes = hex::decode(raw)?;
    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(out)
}

fn parse_evm_addr_or_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let raw = hex_str.trim();
    if !raw.starts_with("0x") && raw.len() <= 20 && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return parse_decimal_uint_to_u32x8(raw);
    }

    let bytes = hex::decode(raw.strip_prefix("0x").unwrap_or(raw))?;
    let bytes = match bytes.len() {
        20 => {
            let mut out = [0u8; 32];
            out[12..32].copy_from_slice(&bytes);
            out
        }
        32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            out
        }
        n => anyhow::bail!("expected 20-byte address or 32-byte bytes32 hex, got {} bytes", n),
    };

    let mut out = [0u32; 8];
    for i in 0..8 {
        out[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_contract_id_as_uint256_words() {
        assert_eq!(parse_evm_addr_or_bytes32_to_u32x8("4").unwrap(), [0, 0, 0, 0, 0, 0, 0, 4],);
    }

    #[test]
    fn parses_evm_address_as_left_padded_uint256_words() {
        assert_eq!(
            parse_evm_addr_or_bytes32_to_u32x8("0x0000000000000000000000000000000000000004").unwrap(),
            [0, 0, 0, 0, 0, 0, 0, 4],
        );
    }

    #[test]
    fn deposit_backup_shield_metadata_uses_decimal_limbs() {
        assert_eq!(
            canonical_shield_address_metadata(
                "0x112233445566778899aabbccddeeff00123456789abcdef0fedcba9876543210",
            )
            .unwrap(),
            "1234605616436508552:11072869122414935808:1311768467463790320:18364758544493064720",
        );
    }

    #[test]
    fn deposit_claim_proof_url_uses_l1_proved_count_without_zero_snapshot() {
        assert_eq!(
            build_deposit_claim_proof_url("http://127.0.0.1:3000/", 7, Some(9), None, 0),
            "http://127.0.0.1:3000/api/v1/bridge/deposit-claim-proof?deposit_index=7&source_chain_index=0&proved_deposit_count=9",
        );
    }

    #[test]
    fn deposit_claim_proof_url_can_request_explicit_snapshot() {
        assert_eq!(
            build_deposit_claim_proof_url("http://127.0.0.1:3000", 7, Some(12), Some(9), 3),
            "http://127.0.0.1:3000/api/v1/bridge/deposit-claim-proof?deposit_index=7&source_chain_index=3&proved_deposit_count=12&snapshot_deposit_count=9",
        );
    }
}

fn parse_qhash_display_hex(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
    QHashOut::<F>::from_str(hex_str.trim().trim_start_matches("0x").trim_start_matches("0X"))
        .map_err(|e| anyhow::anyhow!("invalid qhash hex '{}': {}", hex_str, e))
}

fn parse_qhash_internal_bytes_hex(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
    let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    anyhow::ensure!(raw.len() == 64, "expected 32-byte hex for qhash, got {} hex chars", raw.len());
    let bytes = hex::decode(raw)?;
    let mut words = [0u32; 8];
    for i in 0..8 {
        words[i] = u32::from_be_bytes(bytes[i * 4..(i + 1) * 4].try_into().unwrap());
    }
    Ok(QHashOut::from_values(
        (words[0] as u64) | ((words[1] as u64) << 32),
        (words[2] as u64) | ((words[3] as u64) << 32),
        (words[4] as u64) | ((words[5] as u64) << 32),
        (words[6] as u64) | ((words[7] as u64) << 32),
    ))
}

fn parse_qhash_bytes32_be(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
    let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    anyhow::ensure!(raw.len() == 64, "expected 32-byte hex for qhash bytes32, got {} hex chars", raw.len());
    let bytes = hex::decode(raw)?;
    Ok(QHashOut::from_values(
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
    ))
}

fn qhash_from_u64x4(words: [u64; 4]) -> QHashOut<F> {
    QHashOut::from_values(words[0], words[1], words[2], words[3])
}

fn string_words_u64x4(hash: QHashOut<F>) -> [String; 4] {
    decimal_limbs(qhash_to_u64x4(hash))
}

fn string_words_u32x8(words: [u32; 8]) -> [String; 8] {
    words.map(|word| word.to_string())
}

fn derive_deposit_commitment_from_words(
    shield_words: [u32; 8],
    token: [u32; 8],
    l2_token_contract_id: [u32; 8],
    amount: [u32; 8],
    source_chain_index: u32,
    note_commitment_words: [u32; 8],
) -> QHashOut<F> {
    let mut felts = Vec::with_capacity(41);
    felts.extend(shield_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(token.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(l2_token_contract_id.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(amount.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.push(F::from_canonical_u64(source_chain_index as u64));
    felts.extend(note_commitment_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
    PoseidonHasher::q_hash_many(&felts)
}

fn resolve_services_url(psy_config: &psy_config::PsyConfigGoldilocks) -> anyhow::Result<String> {
    let network = psy_config.get_current_network()?;
    if let Some(urls) = &network.api_services_url {
        if let Some(first) = urls.first() {
            return Ok(first.trim_end_matches('/').to_string());
        }
    }
    anyhow::bail!("no psy-services URL configured in api_services_url")
}

fn build_deposit_claim_proof_url(
    services_url: &str,
    deposit_index: u64,
    proved_deposit_count: Option<u64>,
    snapshot_deposit_count: Option<u64>,
    source_chain_index: u64,
) -> String {
    let mut url = format!(
        "{}/api/v1/bridge/deposit-claim-proof?deposit_index={}&source_chain_index={}",
        services_url.trim_end_matches('/'),
        deposit_index,
        source_chain_index,
    );
    if let Some(proved_deposit_count) = proved_deposit_count {
        url.push_str(&format!("&proved_deposit_count={}", proved_deposit_count));
    }
    if let Some(snapshot_deposit_count) = snapshot_deposit_count {
        url.push_str(&format!("&snapshot_deposit_count={}", snapshot_deposit_count));
    }
    url
}

async fn fetch_deposit_claim_proof(
    services_url: &str,
    deposit_index: u64,
    proved_deposit_count: Option<u64>,
    snapshot_deposit_count: Option<u64>,
    source_chain_index: u64,
) -> anyhow::Result<Option<ReadyDepositProof>> {
    let url = build_deposit_claim_proof_url(
        services_url,
        deposit_index,
        proved_deposit_count,
        snapshot_deposit_count,
        source_chain_index,
    );
    let response = reqwest::Client::new().get(&url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(status.is_success(), "deposit claim proof request failed ({}): {}", status, body);

    let envelope: ApiResponse<DepositClaimProofResponse> = serde_json::from_str(&body)?;
    anyhow::ensure!(
        envelope.success,
        "deposit claim proof request unsuccessful: {}",
        envelope.error.unwrap_or_else(|| "unknown error".to_string())
    );
    let parsed = envelope
        .data
        .ok_or_else(|| anyhow::anyhow!("deposit claim proof response missing data"))?;
    if !parsed.found {
        tracing::info!(
            deposit_index,
            source_chain_index,
            requested_proved_deposit_count = proved_deposit_count,
            requested_snapshot_deposit_count = snapshot_deposit_count,
            available_proved_deposit_count = parsed.proved_deposit_count.or(parsed.proved_count),
            available_snapshot_deposit_count = parsed.snapshot_deposit_count.or(parsed.tree_count),
            reason = parsed.reason.as_deref().unwrap_or("no reason given"),
            "deposit claim proof not ready yet"
        );
        return Ok(None);
    }

    let deposit_root_hex = parsed
        .proved_root
        .as_deref()
        .or(parsed.deposit_root.as_deref())
        .ok_or_else(|| anyhow::anyhow!("deposit proof missing deposit_root"))?;
    let deposit_root = parse_qhash_internal_bytes_hex(deposit_root_hex)?;
    let leaf_hash = parse_qhash_display_hex(
        parsed
            .leaf_hash
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("deposit proof missing leaf_hash"))?,
    )?;
    let siblings: Vec<QHashOut<F>> = parsed
        .siblings
        .ok_or_else(|| anyhow::anyhow!("deposit proof missing siblings"))?
        .into_iter()
        .map(|s| parse_qhash_internal_bytes_hex(&s))
        .collect::<Result<_, _>>()?;
    let deposit = parsed.deposit.ok_or_else(|| anyhow::anyhow!("deposit proof missing deposit payload"))?;
    let proof_index = parsed.chain_local_deposit_index.or(parsed.deposit_index).unwrap_or(deposit_index);
    let proof = MerkleProofCore {
        root: deposit_root,
        value: leaf_hash,
        index: proof_index,
        siblings,
    };
    Ok(Some(ReadyDepositProof {
        deposit_root,
        deposit_proof: proof,
        deposit,
        proved_deposit_count: parsed
            .snapshot_deposit_count
            .or(parsed.tree_count)
            .or(parsed.proved_deposit_count)
            .or(parsed.proved_count)
            .or(snapshot_deposit_count)
            .or(proved_deposit_count)
            .unwrap_or(deposit_index.saturating_add(1)),
        checkpoint_id: parsed.checkpoint_id,
    }))
}

async fn wait_for_deposit_proof(
    args: &DepositArgs,
    services_url: &str,
    bridge_address: &str,
    deposit_index: u64,
) -> anyhow::Result<ReadyDepositProof> {
    const POLL_INTERVAL_SECS: u64 = 3;
    const POLL_TIMEOUT_SECS: u64 = 600;

    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
    let start = std::time::Instant::now();
    loop {
        let elapsed = start.elapsed().as_secs();
        let checkpoint_id = provider.get_latest_block_state().await?.checkpoint_id;
        let tree_count = fetch_deposit_tree_next_index(&provider, checkpoint_id, args.source_chain_index as u64).await?;
        let l1_proved_deposit_count = fetch_proved_deposit_count(&args.l1_rpc_url, bridge_address).await.ok();
        if l1_proved_deposit_count.is_some_and(|count| count > deposit_index) {
            if let Some(proof) =
                fetch_deposit_claim_proof(services_url, deposit_index, l1_proved_deposit_count, None, args.source_chain_index as u64).await?
            {
                tracing::info!(
                    deposit_index,
                    source_chain_index = args.source_chain_index,
                    l1_proved_deposit_count,
                    tree_count,
                    elapsed_secs = elapsed,
                    "deposit inclusion proof material ready"
                );
                return Ok(proof);
            }
        }
        if elapsed >= POLL_TIMEOUT_SECS {
            anyhow::bail!(
                "timeout waiting for deposit claim proof for deposit_index={} source_chain_index={} (elapsed={}s)",
                deposit_index,
                args.source_chain_index,
                elapsed
            );
        }
        tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
    }
}

fn build_deposit_inclusion_proof_payload(
    args: &DepositArgs,
    backup: &DepositBackupInput,
    shield_address: &str,
    note_commitment: &str,
    ready: ReadyDepositProof,
) -> anyhow::Result<serde_json::Value> {
    let proof_token_address = parse_evm_addr_or_bytes32_to_u32x8(&ready.deposit.token_address)?;
    let proof_l2_token_contract_id = parse_evm_addr_or_bytes32_to_u32x8(&ready.deposit.l2_token_contract_id)?;
    let proof_amount = parse_decimal_uint_to_u32x8(&ready.deposit.amount)?;
    let proof_note_commitment = parse_qhash_bytes32_be(&ready.deposit.note_commitment)?;
    let proof_shield_address = parse_qhash_bytes32_be(&ready.deposit.shield_address)?;
    let local_shield_address = parse_qhash_bytes32_be(shield_address)?;
    let local_note_commitment = parse_qhash_bytes32_be(note_commitment)?;
    let local_token_address = parse_evm_addr_or_bytes32_to_u32x8(&args.token)?;
    let local_amount = parse_decimal_uint_to_u32x8(&args.amount)?;
    let local_l2_token_contract_id = parse_evm_addr_or_bytes32_to_u32x8(&args.l2_token_contract_id)?;

    anyhow::ensure!(proof_shield_address == local_shield_address, "shield_address mismatch vs services proof");
    anyhow::ensure!(
        proof_note_commitment == local_note_commitment,
        "note_commitment mismatch vs services proof"
    );
    anyhow::ensure!(proof_token_address == local_token_address, "token address mismatch vs services proof");
    anyhow::ensure!(proof_amount == local_amount, "amount mismatch vs services proof");
    anyhow::ensure!(
        proof_l2_token_contract_id == local_l2_token_contract_id,
        "l2_token_contract_id mismatch vs services proof"
    );
    anyhow::ensure!(
        ready.deposit.source_chain_id == args.source_chain_index,
        "source_chain_index mismatch vs services proof"
    );

    let note_commitment_words = parse_bytes32_to_u32x8(&ready.deposit.note_commitment)?;
    let deposit_leaf = derive_deposit_commitment_from_words(
        qhashout_to_u32x8_be(proof_shield_address),
        proof_token_address,
        proof_l2_token_contract_id,
        proof_amount,
        args.source_chain_index,
        note_commitment_words,
    );
    anyhow::ensure!(
        deposit_leaf == ready.deposit_proof.value,
        "services leaf_hash mismatch vs derived deposit leaf"
    );

    let nullifier_hash = derive_nullifier_hash(backup.nullifier_secret);
    let input = DepositInclusionInput::<GoldilocksField> {
        nullifier_secret: backup.nullifier_secret.map(GoldilocksField::from_canonical_u64),
        note_secret: backup.note_secret.map(GoldilocksField::from_canonical_u64),
        shield_address: proof_shield_address,
        deposit_index: ready.deposit_proof.index,
        token_address: proof_token_address,
        l2_token_contract_id: proof_l2_token_contract_id,
        amount: proof_amount,
        source_chain_index: args.source_chain_index,
        deposit_root: ready.deposit_root,
        deposit_proof: ready.deposit_proof.clone(),
    };

    let circuit = DepositInclusionCircuit::<PoseidonGoldilocksConfig, 2>::new();
    let proof = circuit.prove(&input)?;
    let proof_b64 = BASE64.encode(proof.to_bytes());

    Ok(serde_json::json!({
        "type": "deposit_inclusion_proof",
        "version": 1,
        "shield_address": string_words_u64x4(proof_shield_address),
        "amount_u32x8": string_words_u32x8(proof_amount),
        "token_address_u32x8": string_words_u32x8(proof_token_address),
        "l2_token_contract_id": string_words_u32x8(proof_l2_token_contract_id),
        "source_chain_index": args.source_chain_index.to_string(),
        "deposit_index": ready.deposit_proof.index.to_string(),
        "deposit_root": string_words_u64x4(ready.deposit_root),
        "nullifier": string_words_u64x4(nullifier_hash),
        "nullifier_hash": string_words_u64x4(nullifier_hash),
        "note_commitment": string_words_u64x4(proof_note_commitment),
        "deposit_leaf": string_words_u64x4(deposit_leaf),
        "proved_deposit_count": ready.proved_deposit_count.to_string(),
        "checkpoint_id": ready.checkpoint_id.map(|id| id.to_string()),
        "deposit_proof_fingerprint": string_words_u64x4(circuit.get_fingerprint()),
        "deposit_proof_bincode_b64": proof_b64,
    }))
}

async fn publish_event_to_relay(relay_url: &str, event: &Event) -> anyhow::Result<String> {
    let payload = serde_json::json!(["EVENT", serde_json::from_str::<serde_json::Value>(&event.as_json())?]);
    let (mut ws, _) = connect_async(relay_url).await?;
    ws.send(Message::Text(payload.to_string())).await?;

    let expected_id = event.id.to_string();
    tokio::time::timeout(std::time::Duration::from_secs(15), async {
        while let Some(msg) = ws.next().await {
            let msg = msg?;
            let text = match msg {
                Message::Text(t) => t,
                Message::Binary(b) => String::from_utf8(b.to_vec())?,
                _ => continue,
            };
            let value: serde_json::Value = serde_json::from_str(&text)?;
            let Some(items) = value.as_array() else { continue };
            if items.first().and_then(|v| v.as_str()) != Some("OK") {
                continue;
            }
            if items.get(1).and_then(|v| v.as_str()) != Some(expected_id.as_str()) {
                continue;
            }
            let accepted = items.get(2).and_then(|v| v.as_bool()).unwrap_or(false);
            if !accepted {
                let reason = items.get(3).and_then(|v| v.as_str()).unwrap_or("relay rejected event");
                anyhow::bail!(reason.to_string());
            }
            return Ok::<(), anyhow::Error>(());
        }
        anyhow::bail!("relay closed before acknowledging event")
    })
    .await??;

    Ok(expected_id)
}

async fn publish_deposit_backup(
    args: &DepositArgs,
    backup: &DepositBackupInput,
    shield_address: &str,
    tx_hash: &str,
    note_commitment: &str,
    global_deposit_index: Option<u32>,
    deposit_proof: serde_json::Value,
) -> anyhow::Result<DepositBackupPublishResult> {
    let recipient_npub = backup
        .recipient_npub
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("--recipient-npub is required to publish the Nostr deposit backup"))?;
    let recipient_pk = PublicKey::parse(recipient_npub)?;
    let sender_keys = Keys::generate();
    let shield_limbs = bytes32_hex_to_u64x4(shield_address)?;
    let nullifier_limbs = qhash_to_u64x4(derive_nullifier_hash(backup.nullifier_secret));
    let backup_id = note_commitment.trim_start_matches("0x").to_ascii_lowercase();
    if backup_id.len() != 64 {
        anyhow::bail!("note_commitment must be a 32-byte hex string");
    }

    let chain_local_deposit_index = deposit_proof
        .get("deposit_index")
        .and_then(|value| value.as_u64().or_else(|| value.as_str().and_then(|raw| raw.parse::<u64>().ok())))
        .ok_or_else(|| anyhow::anyhow!("deposit proof missing chain-local deposit_index"))?;
    let proof_content = serde_json::json!({
        "type": "psy_deposit_proof",
        "version": 2,
        "backup_id": backup_id,
        "timestamp": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_millis(),
        "deposit_proof": deposit_proof,
        "metadata": {
            "note_commitment": backup_id,
            "shield_address": canonical_shield_address_metadata(shield_address)?,
            "token_address": args.token,
            "amount": args.amount,
            "source_chain_index": args.source_chain_index,
            "tx_hash": tx_hash,
            "global_deposit_index": global_deposit_index,
            "chain_local_deposit_index": chain_local_deposit_index,
            "deposit_index": chain_local_deposit_index,
            "contract_id": args.l2_token_contract_id,
            "token_contract_id": args.l2_token_contract_id,
        }
    })
    .to_string();

    let created_at = Timestamp::from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs());
    let unsigned = UnsignedEvent::new(
        sender_keys.public_key(),
        created_at,
        Kind::GiftWrap,
        {
            let mut tags = vec![
                Tag::custom(TagKind::p(), [recipient_pk.to_hex()]),
                Tag::custom(TagKind::t(), ["psy_deposit_proof".to_string()]),
                Tag::custom(TagKind::custom("backup_id"), [backup_id.clone()]),
                Tag::custom(TagKind::custom("shield_address"), decimal_limbs(shield_limbs)),
                Tag::custom(TagKind::custom("nullifier"), decimal_limbs(nullifier_limbs)),
            ];
            if let Some(index) = global_deposit_index {
                tags.push(Tag::custom(TagKind::custom("deposit_index"), [index.to_string()]));
                tags.push(Tag::custom(TagKind::custom("global_deposit_index"), [index.to_string()]));
            }
            tags.push(Tag::custom(
                TagKind::custom("chain_local_deposit_index"),
                [chain_local_deposit_index.to_string()],
            ));
            tags
        },
        proof_content,
    );
    let proof_event = unsigned.sign_with_keys(&sender_keys)?;

    let secrets_content = serde_json::json!({
        "type": "psy_deposit_secrets",
        "version": 2,
        "backup_id": backup_id,
        "nullifier_secret": decimal_limbs(backup.nullifier_secret),
        "note_secret": decimal_limbs(backup.note_secret),
    })
    .to_string();
    let rumor = EventBuilder::text_note(secrets_content).build(sender_keys.public_key());
    let secrets_event = EventBuilder::gift_wrap(
        &sender_keys,
        &recipient_pk,
        rumor,
        [
            Tag::custom(TagKind::t(), ["psy_deposit_secrets".to_string()]),
            Tag::custom(TagKind::custom("backup_id"), [backup_id]),
        ],
    )
    .await?;

    let proof_event_id = publish_event_to_relay(&args.nostr_relay, &proof_event).await?;
    let secrets_event_id = publish_event_to_relay(&args.nostr_relay, &secrets_event).await?;

    Ok(DepositBackupPublishResult {
        proof_event_id,
        secrets_event_id,
    })
}

pub async fn run(args: DepositArgs) -> anyhow::Result<CommandResult> {
    let shield_address = resolve_shield_address(&args)?;
    let (note_commitment, backup) = resolve_note_commitment(&args)?;
    if let Some(recipient_npub) = backup.as_ref().and_then(|b| b.recipient_npub.as_deref()) {
        PublicKey::parse(recipient_npub).map_err(|e| anyhow::anyhow!("invalid --recipient-npub: {}", e))?;
    }
    let router_addr = if !args.router_address.is_empty() && args.router_address != "auto" {
        args.router_address.clone()
    } else {
        resolve_router_address("localhost")?
    };
    tracing::info!("Router address: {}", router_addr);

    let signer: PrivateKeySigner = args.private_key.parse()?;
    let from_addr = signer.address();
    let router: Address = router_addr.parse()?;
    let data = encode_deposit_call(&args.token, &args.amount, &shield_address, &note_commitment)?;

    let is_native = args.token == "0x0000000000000000000000000000000000000000" || args.token == "0x0" || args.token == "0x";
    let value = if is_native { args.amount.parse::<U256>()? } else { U256::ZERO };

    let rpc_url = &args.l1_rpc_url;

    // 1. Chain ID
    let chain_id_hex: String = serde_json::from_value(rpc_call(rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)?;
    tracing::debug!("chain_id: {}", chain_id);

    // 2. Nonce
    let nonce_hex: String = serde_json::from_value(
        rpc_call(
            rpc_url,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(from_addr)), "latest"]),
        )
        .await?,
    )?;
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;
    tracing::debug!("nonce: {}", nonce);

    // 3. Gas estimation
    let gas_estimate = rpc_call(
        rpc_url,
        "eth_estimateGas",
        serde_json::json!([{
            "from": format!("0x{}", hex::encode(from_addr)),
            "to": format!("0x{}", hex::encode(router)),
            "data": format!("0x{}", hex::encode(&data)),
            "value": u256_to_hex(value),
        }]),
    )
    .await?;
    let gas_hex: String = serde_json::from_value(gas_estimate)?;
    let gas_limit = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
    let gas_limit = (gas_limit as f64 * 1.2) as u64;
    tracing::debug!("gas_limit: {}", gas_limit);

    // 4. Fee data (EIP-1559)
    let fee_history = rpc_call(rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
    let base_fee_str = fee_history["baseFeePerGas"][0].as_str().unwrap_or("0x0");
    let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).unwrap_or(1_000_000_000u128);
    let max_priority_fee =
        u128::from_str_radix(fee_history["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"), 16).unwrap_or(1_500_000_000u128);
    let max_fee_per_gas = base_fee * 2 + max_priority_fee;
    tracing::debug!(
        "base_fee={}, max_priority_fee={}, max_fee={}",
        base_fee,
        max_priority_fee,
        max_fee_per_gas
    );

    // 5. Build & sign EIP-1559 tx
    use alloy_consensus::TxEnvelope;
    use alloy_primitives::TxKind;

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas: max_priority_fee,
        gas_limit,
        to: TxKind::Call(router),
        value,
        input: alloy_primitives::Bytes::from(data.clone()),
        access_list: Default::default(),
    };

    let sig = signer.sign_hash(&tx.signature_hash()).await?;
    let signed = tx.into_signed(sig);

    // EIP-2718 encode: 0x02 || rlp([chain_id, nonce, ... , y_parity, r, s])
    use alloy_eips::Encodable2718;
    let mut encoded = Vec::new();
    signed.encode_2718(&mut encoded);
    tracing::debug!("encoded tx len: {}", encoded.len());

    // 6. Send raw transaction
    let tx_hash_raw: String = serde_json::from_value(
        rpc_call(
            rpc_url,
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(&encoded))]),
        )
        .await?,
    )?;
    let tx_hash: TxHash = tx_hash_raw.parse()?;
    tracing::info!("Deposit tx submitted: {}", tx_hash);
    println!("deposit tx: {}", tx_hash);

    // 7. Wait for receipt
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
    println!("status: {}", if status == 1 { "success" } else { "failed" });
    println!("gas_used: {}", receipt["gasUsed"].as_str().unwrap_or("?"));

    if status != 1 {
        // Try to extract revert reason
        let tx_hash_str = format!("{:#x}", tx_hash);
        let trace = rpc_call(
            rpc_url,
            "debug_traceTransaction",
            serde_json::json!([tx_hash_str, {"tracer": "callTracer"}]),
        )
        .await;
        if let Ok(t) = trace {
            if let Some(revert) = t["revertReason"].as_str() {
                tracing::error!("Revert: {}", revert);
            }
        }
        anyhow::bail!("L1 deposit transaction reverted: tx_hash={:#x}", tx_hash);
    }

    // 8. Parse DepositRecorded event
    let record_topic: B256 = "0xc6a707652dc6aea1d40642451dfaa5afbdf8ab6a176ebacd33dee14dc3ace472".parse()?;
    let mut recorded_deposit_index: Option<u32> = None;
    if let Some(logs) = receipt["logs"].as_array() {
        for log in logs {
            let topics = log["topics"].as_array().map(|a| a.clone()).unwrap_or_default();
            if topics.first().and_then(|t| t.as_str()) == Some(&format!("{:#x}", record_topic)) {
                let t1 = topics.get(1).and_then(|t| t.as_str()).unwrap_or("0x0");
                let t1b = hex::decode(t1.strip_prefix("0x").unwrap_or("0")).unwrap_or_default();
                let deposit_index = if t1b.len() >= 32 {
                    u32::from_be_bytes([t1b[28], t1b[29], t1b[30], t1b[31]])
                } else {
                    0
                };
                let raw_data = log["data"].as_str().unwrap_or("0x");
                let log_data = hex::decode(raw_data.strip_prefix("0x").unwrap_or("0")).unwrap_or_default();
                if log_data.len() >= 192 {
                    recorded_deposit_index = Some(deposit_index);
                    println!("deposit_index: {}", deposit_index);
                    println!("leaf_hash: 0x{}", hex::encode(&log_data[160..192]));
                }
            }
        }
    }

    let should_generate_deposit_proof = backup
        .as_ref()
        .is_some_and(|b| args.deposit_proof_output.is_some() || b.recipient_npub.is_some());
    if let Some(backup) = backup.as_ref().filter(|_| should_generate_deposit_proof) {
        let deposit_index = recorded_deposit_index
            .ok_or_else(|| anyhow::anyhow!("DepositRecorded event missing deposit_index; cannot generate deposit backup proof"))?;
        let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
        let services_url = resolve_services_url(&psy_config)?;
        let bridge_address = resolve_bridge_address("localhost")?;
        let ready_proof = wait_for_deposit_proof(&args, &services_url, &bridge_address, deposit_index as u64).await?;
        let deposit_proof = build_deposit_inclusion_proof_payload(&args, backup, &shield_address, &note_commitment, ready_proof)?;
        if let Some(path) = args.deposit_proof_output.as_deref() {
            let path_ref = std::path::Path::new(path);
            if let Some(parent) = path_ref.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path_ref, serde_json::to_string_pretty(&deposit_proof)?)?;
            println!("deposit_proof_file: {}", path);
        }
        if backup.recipient_npub.is_some() {
            let event_ids = publish_deposit_backup(
                &args,
                backup,
                &shield_address,
                &tx_hash_raw,
                &note_commitment,
                Some(deposit_index),
                deposit_proof,
            )
            .await?;
            println!(
                "deposit backup sent via Nostr relay {}: proof={}, secrets={}",
                args.nostr_relay, event_ids.proof_event_id, event_ids.secrets_event_id
            );
        }
    }

    Ok(CommandResult::L1Transaction(L1TransactionResult {
        transaction_hash: Some(format!("{:#x}", tx_hash)),
        status: L1TransactionStatus::Confirmed,
        chain_id: Some(chain_id),
    }))
}
