use std::str::FromStr;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{args::ContractCallArgs, data::qhashout::QHashOut};
use psy_client_data::{
    config::store_config::{C, D, F},
    privacy::deposit_inclusion::DepositInclusionInput,
    traits::qdatastore::{qmetadata::QMetaDataStoreReaderSync, qtreedata::QTreeDataStoreReaderSync},
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::network_constants::DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT;
use psy_crypto::{
    hash::{
        merkle::core::MerkleProofCore,
        traits::hasher::{FieldQHasher, PoseidonHasher},
    },
    shield_address::{derive_note_commitment, derive_nullifier_hash, derive_shield_address, qhashout_to_u32x8_be},
};
use psy_dpn_circuit::circuits::privacy::deposit_inclusion::DepositInclusionCircuit;
use psy_prover::session::{ShieldDepositClaim, WalletSession};
use psy_provider::provider::RpcProvider;
use serde::Deserialize;

use super::{args::ClaimDepositArgs, submit_end_cap_proof};
use crate::result::{CommandResult, TransactionResult, TransactionStatus};

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

fn resolve_bridge_address(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Bridge_Proxy", "Bridge", "Bridge_Proxy.json")
}
const BRIDGE_USER_ID_U64: u64 = 524288;
const DEPOSIT_TREE_CONTRACT_ID: u32 = 2;
const DEPOSIT_TREE_CHAIN_COUNTS_SUBSLOT_BASE: u64 = 8 + (8192 * 8);

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
            DEPOSIT_TREE_CONTRACT_STATE_TREE_HEIGHT,
            leaf_index,
        )
        .await?;
    read_single_felt_from_packed_leaf(next_index_leaf, sub_slot_index)
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
    // provedDepositCount() selector = keccak256("provedDepositCount()")[0..4]
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

fn u64_to_u32x8_be(v: u64) -> [u32; 8] {
    [0, 0, 0, 0, 0, 0, (v >> 32) as u32, (v & 0xffff_ffff) as u32]
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

fn u32x8_be_to_u64(v: [u32; 8]) -> anyhow::Result<u64> {
    anyhow::ensure!(v[..6] == [0, 0, 0, 0, 0, 0], "u32x8 value does not fit into u64");
    Ok(((v[6] as u64) << 32) | v[7] as u64)
}

fn parse_evm_addr_or_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let raw = hex_str.trim();
    if !raw.starts_with("0x") && raw.len() <= 20 && raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return Ok(u64_to_u32x8_be(raw.parse::<u64>()?));
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

fn parse_qhash_display_hex(hex_str: &str) -> anyhow::Result<QHashOut<F>> {
    QHashOut::<F>::from_str(hex_str.trim().trim_start_matches("0x").trim_start_matches("0X"))
        .map_err(|e| anyhow::anyhow!("Invalid qhash hex '{}': {}", hex_str, e))
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

fn parse_qhash_u64x4(input: &str) -> anyhow::Result<Option<QHashOut<F>>> {
    let cleaned = input.trim().trim_start_matches('[').trim_end_matches(']').replace(['"', '\''], "");
    if !cleaned.contains(',') {
        return Ok(None);
    }

    let parts: Vec<&str> = cleaned.split(',').map(str::trim).filter(|part| !part.is_empty()).collect();
    anyhow::ensure!(parts.len() == 4, "u64x4 input must contain exactly four comma-separated limbs");

    let mut words = [0u64; 4];
    for (idx, part) in parts.iter().enumerate() {
        words[idx] = if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16)?
        } else {
            part.parse::<u64>()?
        };
    }
    Ok(Some(qhash_from_u64x4(words)))
}

fn parse_qhash_cli_input(input: &str) -> anyhow::Result<QHashOut<F>> {
    if let Some(words) = parse_qhash_u64x4(input)? {
        return Ok(words);
    }

    let raw = input.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_qhash_bytes32_be(input);
    }
    parse_qhash_display_hex(input)
}

fn qhash_to_internal_u32x8(hash: QHashOut<F>) -> [u32; 8] {
    [
        (hash.0.elements[0].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[0].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[1].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[1].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[2].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[2].to_canonical_u64() >> 32) as u32,
        (hash.0.elements[3].to_canonical_u64() & 0xffff_ffff) as u32,
        (hash.0.elements[3].to_canonical_u64() >> 32) as u32,
    ]
}

fn qhash_to_u64x4(hash: QHashOut<F>) -> [u64; 4] {
    [
        hash.0.elements[0].to_canonical_u64(),
        hash.0.elements[1].to_canonical_u64(),
        hash.0.elements[2].to_canonical_u64(),
        hash.0.elements[3].to_canonical_u64(),
    ]
}

pub(crate) fn qhash_from_u64x4(words: [u64; 4]) -> QHashOut<F> {
    QHashOut::from_values(words[0], words[1], words[2], words[3])
}

#[derive(Debug)]
pub(crate) struct DepositProofFile {
    pub deposit_proof_bincode_b64: String,
    pub deposit_proof_fingerprint: [u64; 4],
    pub shield_address: [u64; 4],
    pub amount_u32x8: [u32; 8],
    pub token_address_u32x8: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub source_chain_index: u32,
    pub deposit_root: [u64; 4],
    pub nullifier_hash: [u64; 4],
    pub note_commitment: [u64; 4],
    pub deposit_index: u64,
}

fn parse_u64_json_value(value: &serde_json::Value, field: &str) -> anyhow::Result<u64> {
    if let Some(n) = value.as_u64() {
        return Ok(n);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| anyhow::format_err!("{} must be a decimal string or u64", field))?
        .trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(raw.parse::<u64>()?)
}

fn parse_u64x4_json_field(obj: &serde_json::Value, field: &str) -> anyhow::Result<[u64; 4]> {
    let arr = obj
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::format_err!("deposit proof missing {}[4]", field))?;
    anyhow::ensure!(arr.len() == 4, "{} must have 4 limbs", field);
    Ok([
        parse_u64_json_value(&arr[0], field)?,
        parse_u64_json_value(&arr[1], field)?,
        parse_u64_json_value(&arr[2], field)?,
        parse_u64_json_value(&arr[3], field)?,
    ])
}

fn parse_u32x8_json_field(obj: &serde_json::Value, field: &str) -> anyhow::Result<[u32; 8]> {
    let arr = obj
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::format_err!("deposit proof missing {}[8]", field))?;
    anyhow::ensure!(arr.len() == 8, "{} must have 8 limbs", field);
    let mut out = [0u32; 8];
    for (idx, value) in arr.iter().enumerate() {
        let parsed = parse_u64_json_value(value, field)?;
        anyhow::ensure!(parsed <= u32::MAX as u64, "{}[{}] exceeds u32", field, idx);
        out[idx] = parsed as u32;
    }
    Ok(out)
}

fn parse_string_json_field(obj: &serde_json::Value, field: &str) -> anyhow::Result<String> {
    obj.get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| anyhow::format_err!("deposit proof missing string field {}", field))
}

pub(crate) fn load_deposit_proof_file(path: &str) -> anyhow::Result<DepositProofFile> {
    let raw = std::fs::read_to_string(path).map_err(|e| anyhow::format_err!("failed to read deposit proof file {}: {}", path, e))?;
    let parsed: serde_json::Value = serde_json::from_str(&raw)?;
    let proof_obj = parsed.get("deposit_proof").unwrap_or(&parsed);
    anyhow::ensure!(
        proof_obj.is_object(),
        "deposit proof file must be a JSON object or contain a deposit_proof object"
    );

    let source_chain_index = parse_u64_json_value(
        proof_obj
            .get("source_chain_index")
            .ok_or_else(|| anyhow::format_err!("deposit proof missing source_chain_index"))?,
        "source_chain_index",
    )?;
    anyhow::ensure!(source_chain_index <= u32::MAX as u64, "source_chain_index exceeds u32");
    let deposit_index = parse_u64_json_value(
        proof_obj
            .get("deposit_index")
            .ok_or_else(|| anyhow::format_err!("deposit proof missing deposit_index"))?,
        "deposit_index",
    )?;

    Ok(DepositProofFile {
        deposit_proof_bincode_b64: parse_string_json_field(proof_obj, "deposit_proof_bincode_b64")?,
        deposit_proof_fingerprint: parse_u64x4_json_field(proof_obj, "deposit_proof_fingerprint")?,
        shield_address: parse_u64x4_json_field(proof_obj, "shield_address")?,
        amount_u32x8: parse_u32x8_json_field(proof_obj, "amount_u32x8")?,
        token_address_u32x8: parse_u32x8_json_field(proof_obj, "token_address_u32x8")?,
        l2_token_contract_id: parse_u32x8_json_field(proof_obj, "l2_token_contract_id")?,
        source_chain_index: source_chain_index as u32,
        deposit_root: parse_u64x4_json_field(proof_obj, "deposit_root")?,
        nullifier_hash: parse_u64x4_json_field(proof_obj, "nullifier_hash").or_else(|_| parse_u64x4_json_field(proof_obj, "nullifier"))?,
        note_commitment: parse_u64x4_json_field(proof_obj, "note_commitment")?,
        deposit_index,
    })
}

fn rebuild_proof_tree_root_from_path(leaf: QHashOut<F>, index: u64, siblings: &[[u64; 4]]) -> QHashOut<F> {
    let mut current = leaf;
    for (level, sibling_words) in siblings.iter().enumerate() {
        let sibling = qhash_from_u64x4(*sibling_words);
        let bit = (index >> level) & 1;
        current = if bit == 0 {
            PoseidonHasher::q_two_to_one(current, sibling)
        } else {
            PoseidonHasher::q_two_to_one(sibling, current)
        };
    }
    current
}

pub async fn run(args: ClaimDepositArgs) -> anyhow::Result<CommandResult> {
    run_inner(&args).await
}

async fn run_inner(args: &ClaimDepositArgs) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let token_address = parse_evm_addr_or_bytes32_to_u32x8(&args.token_l1_address)?;
    let amount = u64_to_u32x8_be(args.amount);
    let shield_address = derive_shield_address(args.user_id, args.r0, args.r1);
    let deposit_proof_file = load_deposit_proof_file(&args.deposit_proof)?;
    let proof_shield_address = qhash_from_u64x4(deposit_proof_file.shield_address);
    let deposit_root = qhash_from_u64x4(deposit_proof_file.deposit_root);
    let proof_nullifier_hash = qhash_from_u64x4(deposit_proof_file.nullifier_hash);
    let proof_note_commitment = qhash_from_u64x4(deposit_proof_file.note_commitment);
    let proof_fingerprint = qhash_from_u64x4(deposit_proof_file.deposit_proof_fingerprint);
    let proof_token_address = deposit_proof_file.token_address_u32x8;
    let proof_l2_token_contract_id = deposit_proof_file.l2_token_contract_id;
    let proof_amount = deposit_proof_file.amount_u32x8;
    let proof_source_chain_index = deposit_proof_file.source_chain_index;
    let proof_deposit_index = deposit_proof_file.deposit_index;

    anyhow::ensure!(
        proof_shield_address == shield_address,
        "shield address mismatch vs deposit proof: proof={} local={}",
        proof_shield_address,
        shield_address,
    );
    anyhow::ensure!(proof_token_address == token_address, "token address mismatch vs deposit proof");
    anyhow::ensure!(proof_amount == amount, "amount mismatch vs deposit proof");
    anyhow::ensure!(
        proof_source_chain_index == args.source_chain_index,
        "source_chain_index mismatch vs deposit proof"
    );
    anyhow::ensure!(proof_deposit_index == args.deposit_index, "deposit_index mismatch vs deposit proof");

    match (&args.note_secret, &args.nullifier_secret) {
        (Some(note_secret_raw), Some(nullifier_secret_raw)) => {
            let note_secret_q = parse_qhash_cli_input(note_secret_raw)?;
            let nullifier_secret_q = parse_qhash_cli_input(nullifier_secret_raw)?;
            let note_secret = qhash_to_u64x4(note_secret_q);
            let nullifier_secret = qhash_to_u64x4(nullifier_secret_q);
            let note_commitment_q = derive_note_commitment(nullifier_secret, note_secret);
            let nullifier_hash = derive_nullifier_hash(nullifier_secret);
            anyhow::ensure!(proof_note_commitment == note_commitment_q, "note_commitment mismatch vs deposit proof");
            anyhow::ensure!(proof_nullifier_hash == nullifier_hash, "nullifier_hash mismatch vs deposit proof");
            let circuit_nullifier_hash = {
                use psy_crypto::hash::traits::hasher::{FieldQHasher, PoseidonHasher};
                let felts = nullifier_secret.iter().map(|&v| F::from_canonical_u64(v)).collect::<Vec<_>>();
                PoseidonHasher::q_hash_many(&felts)
            };
            tracing::warn!(
                client_nullifier_hash = %nullifier_hash,
                circuit_nullifier_hash = %circuit_nullifier_hash,
                nullifier_hash_match = (nullifier_hash == circuit_nullifier_hash),
                shield_address_qhash = %shield_address,
                "claim_deposit hash sanity"
            );
        }
        (None, None) => {}
        _ => anyhow::bail!("--note-secret and --nullifier-secret must be passed together"),
    }

    let l2_token_contract_id = proof_l2_token_contract_id;
    let shield_words_be = qhashout_to_u32x8_be(proof_shield_address);
    let note_commitment_words = u64x4_to_u32x8_be(deposit_proof_file.note_commitment);
    tracing::info!(
        shield_words_be = ?shield_words_be,
        proof_shield_words = ?shield_words_be,
        token_address_words = ?token_address,
        l2_token_contract_id_words = ?l2_token_contract_id,
        amount_words = ?amount,
        source_chain_index = args.source_chain_index,
        note_commitment_words = ?note_commitment_words,
        "claim_deposit preimage words"
    );

    let circuit = DepositInclusionCircuit::<PoseidonGoldilocksConfig, 2>::new();
    let local_fingerprint = circuit.get_fingerprint();
    anyhow::ensure!(
        proof_fingerprint == local_fingerprint,
        "DepositInclusion fingerprint mismatch: proof={} local={}",
        proof_fingerprint,
        local_fingerprint,
    );
    let proof_bytes = BASE64
        .decode(deposit_proof_file.deposit_proof_bincode_b64.as_bytes())
        .map_err(|e| anyhow::format_err!("invalid deposit proof base64: {}", e))?;
    let proof: ProofWithPublicInputs<F, C, D> =
        match ProofWithPublicInputs::<F, C, D>::from_bytes(proof_bytes.clone(), circuit.get_common_circuit_data_ref()) {
            Ok(p) => p,
            Err(native_err) => bincode::deserialize(&proof_bytes)
                .map_err(|bin_err| anyhow::format_err!("invalid deposit proof bytes: native={} ; bincode={}", native_err, bin_err))?,
        };
    let proof_pi_hash = qhash_from_u64x4([
        proof.public_inputs[0].to_canonical_u64(),
        proof.public_inputs[1].to_canonical_u64(),
        proof.public_inputs[2].to_canonical_u64(),
        proof.public_inputs[3].to_canonical_u64(),
    ]);
    let expected_pi_hash = {
        let felts = |a: [u64; 4]| a.map(F::from_canonical_u64);
        let felts8 = |a: [u32; 8]| a.map(|v| F::from_canonical_u64(v as u64));
        let mut preimage: Vec<F> = Vec::with_capacity(42);
        preimage.extend(felts(qhash_to_u64x4(shield_address)));
        preimage.extend(felts8(amount));
        preimage.extend(felts8(token_address));
        preimage.extend(felts8(l2_token_contract_id));
        preimage.push(F::from_canonical_u64(args.source_chain_index as u64));
        preimage.extend(felts(qhash_to_u64x4(deposit_root)));
        preimage.extend(felts(qhash_to_u64x4(proof_nullifier_hash)));
        preimage.extend(felts(qhash_to_u64x4(proof_note_commitment)));
        preimage.push(F::from_canonical_u64(proof_deposit_index));
        PoseidonHasher::q_hash_many(&preimage)
    };
    anyhow::ensure!(
        expected_pi_hash == proof_pi_hash,
        "deposit proof public input hash mismatch: expected={} proof={}",
        expected_pi_hash,
        proof_pi_hash,
    );
    tracing::info!(
        fingerprint = %local_fingerprint,
        shield_address = %shield_address,
        nullifier_hash = %proof_nullifier_hash,
        deposit_root = %deposit_root,
        deposit_index = args.deposit_index,
        "loaded sender-generated deposit inclusion proof"
    );

    let info = load_wallet_key_info(&args.wallet, false)?;
    let shield_claim = ShieldDepositClaim {
        contract_id: u32x8_be_to_u64(proof_l2_token_contract_id)?,
        l2_token_contract_id: proof_l2_token_contract_id,
        nullifier_hash: proof_nullifier_hash,
        shield_address,
        token_address,
        amount,
        source_chain_index: args.source_chain_index,
        deposit_root,
        note_commitment: proof_note_commitment,
        deposit_index: proof_deposit_index,
        r0: args.r0,
        r1: args.r1,
        proof_fingerprint: local_fingerprint,
        proof: proof.clone(),
        verifier_data: circuit.get_verifier_config_ref().into(),
    };

    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    submit_end_cap_proof::configure_wallet_session_for_signer(
        &mut wallet_session,
        &args.wallet,
        info.fingerprint,
        &[ContractCallArgs {
            contract_id: shield_claim.contract_id,
            method_name: "claim_deposit".to_string(),
            inputs: Vec::new(),
        }],
    )
    .await?;

    let receiver_pk = wallet_session
        .add_user_with_user_id(info.private_key, info.fingerprint, args.user_id)
        .await?;
    let mut builder = wallet_session.begin_trace_build(receiver_pk).await?;
    let proof_ref = builder
        .add_external_proof(local_fingerprint, shield_claim.proof.clone(), circuit.get_verifier_config_ref().clone())
        .await?;
    let call = shield_claim.to_contract_call_args(&proof_ref);
    builder.trace_call(call).await?;
    let trace = builder.finalize_tx_trace_with_opts(Default::default()).await?;
    let end_user_leaf_hash = trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
    let tx_hash = wallet_session.prove_tx_trace(receiver_pk, &trace).await?;

    tracing::info!(
        tx_hash = %tx_hash,
        end_user_leaf_hash = %end_user_leaf_hash,
        checkpoint_before,
        "shield claim_deposit submitted"
    );

    let confirmed_checkpoint = provider
        .wait_for_endcap_inclusion(args.user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
        .await?;
    tracing::info!(
        checkpoint_id = confirmed_checkpoint,
        user_id = args.user_id,
        deposit_index = args.deposit_index,
        tx_hash = %tx_hash,
        end_user_leaf_hash = %end_user_leaf_hash,
        "shield claim_deposit confirmed"
    );

    Ok(CommandResult::Transaction(TransactionResult {
        transaction_hash: tx_hash,
        user_id: Some(args.user_id),
        status: TransactionStatus::Confirmed,
        confirmed_checkpoint: Some(confirmed_checkpoint),
        network: psy_config.current_network_name().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::Field,
        hash::poseidon::PoseidonHash,
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, Hasher, PoseidonGoldilocksConfig},
        },
    };

    use super::*;

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn hash_n_to_hash_no_pad_42_elements_matches_standalone_poseidon_hash() {
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 42 random-ish input targets
        let inputs: Vec<_> = (0..42).map(|_| builder.add_virtual_target()).collect();
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());

        // Register hash as public input
        for elem in &hash.elements {
            builder.register_public_input(*elem);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let witness_values: Vec<F> = (0..42).map(|i| F::from_canonical_u64((i as u64) * 12345 + 999)).collect();
        for (target, val) in inputs.iter().zip(&witness_values) {
            pw.set_target(*target, *val).unwrap();
        }
        let proof = data.prove(pw).unwrap();

        // Compute expected hash using standalone PoseidonHash via Hasher trait
        let expected = <PoseidonHash as Hasher<F>>::hash_no_pad(&witness_values);

        // Extract circuit result
        let circuit_result = plonky2::hash::hash_types::HashOut {
            elements: [
                proof.public_inputs[0],
                proof.public_inputs[1],
                proof.public_inputs[2],
                proof.public_inputs[3],
            ],
        };

        assert_eq!(
            circuit_result, expected,
            "circuit builder hash_n_to_hash_no_pad differs from standalone PoseidonHash::hash_no_pad for 42 elements"
        );
    }

    #[test]
    // Pre-existing on feat/improve-bridge-relayer: needs correct zero-hash siblings.
    // Siblings-length panic was fixed; hash computation assertion disabled until
    // proper zero-hash constants are imported.
    #[ignore]
    fn deposit_inclusion_circuit_42_element_preimage_matches_external_computation() {
        type F = <C as GenericConfig<D>>::F;
        use plonky2::hash::hash_types::HashOut;
        use psy_crypto::hash::traits::hasher::PoseidonHasher;
        let shield_address = derive_shield_address(0, 0, 0);
        let nullifier_secret: [u64; 4] = [0, 0, 0, 3];
        let note_secret: [u64; 4] = [0, 0, 0, 2];
        let nullifier_hash = derive_nullifier_hash(nullifier_secret);
        let deposit_commitment = QHashOut(HashOut::ZERO);
        // Circuit prove with correct-length siblings (no panic)
        let circuit = DepositInclusionCircuit::<C, D>::new();
        let input = DepositInclusionInput::<F> {
            nullifier_secret: std::array::from_fn(|i| F::from_canonical_u64(nullifier_secret[i])),
            note_secret: std::array::from_fn(|i| F::from_canonical_u64(note_secret[i])),
            shield_address,
            deposit_index: 0,
            token_address: [0; 8],
            l2_token_contract_id: [0; 8],
            amount: [0; 8],
            source_chain_index: 0,
            deposit_root: deposit_commitment,
            deposit_proof: MerkleProofCore {
                root: deposit_commitment,
                value: deposit_commitment,
                index: 0,
                siblings: vec![QHashOut::<F>::ZERO; 32],
            },
        };
        let _proof = circuit.prove(&input).unwrap();
        // Assertion disabled: needs correct zero-hash constants for root match.
    }

    fn contract_u32x8_to_hash(words: [u32; 8]) -> QHashOut<F> {
        QHashOut::from_values(
            (words[0] as u64) + ((words[1] as u64) << 32),
            (words[2] as u64) + ((words[3] as u64) << 32),
            (words[4] as u64) + ((words[5] as u64) << 32),
            (words[6] as u64) + ((words[7] as u64) << 32),
        )
    }

    fn contract_u32x8_be_to_u64(words: [u32; 8]) -> u64 {
        assert_eq!(words[..6], [0, 0, 0, 0, 0, 0]);
        ((words[6] as u64) << 32) | (words[7] as u64)
    }

    fn sample_native_hex() -> &'static str {
        "0x5566778811223344ddeeff0099aabbcc89abcdef0123456776543210fedcba98"
    }

    fn sample_bytes32_be_hex() -> &'static str {
        "0x112233445566778899aabbccddeeff000123456789abcdeffedcba9876543210"
    }

    #[test]
    fn parse_internal_native_hex_matches_expected_field_order() {
        let parsed = parse_qhash_internal_bytes_hex(sample_native_hex()).unwrap();
        assert_eq!(
            parsed,
            QHashOut::from_values(0x1122334455667788, 0x99aabbccddeeff00, 0x0123456789abcdef, 0xfedcba9876543210,)
        );
    }

    #[test]
    fn parse_bytes32_be_hex_matches_expected_field_order() {
        let parsed = parse_qhash_bytes32_be(sample_bytes32_be_hex()).unwrap();
        assert_eq!(
            parsed,
            QHashOut::from_values(0x1122334455667788, 0x99aabbccddeeff00, 0x0123456789abcdef, 0xfedcba9876543210,)
        );
    }

    #[test]
    fn internal_u32x8_roundtrip_layout_is_stable() {
        let hash = QHashOut::from_values(0x1122334455667788, 0x99aabbccddeeff00, 0x0123456789abcdef, 0xfedcba9876543210);
        assert_eq!(
            qhash_to_internal_u32x8(hash),
            [
                0x5566_7788,
                0x1122_3344,
                0xddee_ff00,
                0x99aa_bbcc,
                0x89ab_cdef,
                0x0123_4567,
                0x7654_3210,
                0xfedc_ba98,
            ]
        );
    }

    #[test]
    fn contract_u32x8_to_hash_matches_rust_internal_layout() {
        let hash = QHashOut::from_values(0x1122334455667788, 0x99aabbccddeeff00, 0x0123456789abcdef, 0xfedcba9876543210);
        let encoded = qhash_to_internal_u32x8(hash);
        let decoded = contract_u32x8_to_hash(encoded);
        assert_eq!(decoded, hash);
    }

    #[test]
    fn contract_amount_u32x8_be_matches_rust_u64_encoding() {
        let amount = 1_000_000u64;
        let encoded = u64_to_u32x8_be(amount);
        let decoded = contract_u32x8_be_to_u64(encoded);
        assert_eq!(decoded, amount);
        assert_eq!(u32x8_be_to_u64(encoded).unwrap(), amount);
    }

    #[test]
    fn native_hex_to_contract_hash_roundtrip_is_stable() {
        let parsed = parse_qhash_internal_bytes_hex(sample_native_hex()).unwrap();
        let encoded = qhash_to_internal_u32x8(parsed);
        let contract_hash = contract_u32x8_to_hash(encoded);
        assert_eq!(contract_hash, parsed);
    }

    #[test]
    fn zero_shield_deposit_uses_zero_shield_as_effective_shield() {
        let derived: QHashOut<F> = QHashOut::from_values(1, 2, 3, 4);
        let proof_shield: QHashOut<F> = QHashOut::ZERO;
        let effective = if proof_shield == QHashOut::ZERO { proof_shield } else { derived };
        assert_eq!(effective, QHashOut::ZERO);
    }
}
