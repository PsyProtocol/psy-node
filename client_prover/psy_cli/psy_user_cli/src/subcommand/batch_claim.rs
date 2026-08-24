use std::{fs, str::FromStr};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use plonky2::{
    field::types::{Field, PrimeField64},
    plonk::{config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::{
    args::{ContractCallArgs, ContractCallData, SignType},
    data::{alt::AltVerifierOnlyCircuitData, qhashout::QHashOut},
};
use psy_client_data::config::store_config::{C, D, F};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::network_constants::{
    GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, MAX_CONTRACT_STATE_TREE_HEIGHT, TOKEN_CONTRACT_STATE_TREE_HEIGHT,
};
use psy_crypto::shield_address::{derive_note_commitment, derive_nullifier_hash, derive_shield_address};
use psy_dpn_circuit::circuits::privacy::{deposit_inclusion::DepositInclusionCircuit, private_note_inclusion::PrivateNoteInclusionCircuit};
use psy_prover::{
    session::{PrivateTransferClaim, ShieldDepositClaim, WalletSession},
    trace::{GeneratedTxTraceJson, ProvedTxResultJson},
};
use psy_provider::provider::RpcProvider;
use serde::Deserialize;

use crate::subcommand::{
    args::BatchClaimArgs,
    claim_deposit::{load_deposit_proof_file, qhash_from_u64x4},
    note_proof_common::NoteProofOutput,
};
use crate::result::{CommandResult, TransactionResult, TransactionStatus, TxTraceResult};

const NOTE_TREE_HEIGHT: usize = 20;

#[derive(Debug, Deserialize)]
pub(crate) struct BatchClaimInput {
    pub version: u32,
    pub items: Vec<BatchClaimInputItem>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum BatchClaimInputItem {
    PublicCall {
        #[serde(default)]
        id: Option<String>,
        call: ContractCallArgs,
    },
    PrivateNoteClaim {
        #[serde(default)]
        id: Option<String>,
        contract_id: u64,
        note_proof_path: String,
        random0: u64,
        random1: u64,
    },
    ShieldDepositClaim {
        #[serde(default)]
        id: Option<String>,
        deposit_proof_path: String,
        token_l1_address: String,
        amount: u64,
        source_chain_index: u32,
        deposit_index: u64,
        r0: u64,
        r1: u64,
        note_secret: Option<String>,
        nullifier_secret: Option<String>,
    },
}

fn u64_to_u32x8_be(v: u64) -> [u32; 8] {
    [0, 0, 0, 0, 0, 0, (v >> 32) as u32, (v & 0xffff_ffff) as u32]
}

fn u32x8_be_to_u64(v: [u32; 8]) -> anyhow::Result<u64> {
    anyhow::ensure!(v[..6] == [0, 0, 0, 0, 0, 0], "u32x8 value does not fit into u64");
    Ok(((v[6] as u64) << 32) | v[7] as u64)
}

fn parse_evm_addr_or_bytes32_to_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let bytes = hex::decode(hex_str.strip_prefix("0x").unwrap_or(hex_str))?;
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

fn parse_qhash_cli_input(input: &str) -> anyhow::Result<QHashOut<F>> {
    let raw = input.trim().trim_start_matches("0x").trim_start_matches("0X");
    if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return parse_qhash_bytes32_be(input);
    }
    parse_qhash_display_hex(input)
}

fn qhash_to_u64x4(hash: QHashOut<F>) -> [u64; 4] {
    [
        hash.0.elements[0].to_canonical_u64(),
        hash.0.elements[1].to_canonical_u64(),
        hash.0.elements[2].to_canonical_u64(),
        hash.0.elements[3].to_canonical_u64(),
    ]
}


pub(crate) async fn run_items(
    rpc_config_path: &str,
    wallet: &psy_cli_common::key_utils::WalletSourceArgs,
    items: Vec<BatchClaimInputItem>,
    trace_out: Option<String>,
    generate_only: bool,
    wait: bool,
) -> anyhow::Result<CommandResult> {
    anyhow::ensure!(!(generate_only && wait), "batch claim cannot use --generate-only and --wait together");
    if generate_only {
        anyhow::ensure!(trace_out.is_some(), "batch claim --generate-only requires --trace-out");
    }
    anyhow::ensure!(!items.is_empty(), "batch claim input must contain at least one item");

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(rpc_config_path)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;
    let info = load_wallet_key_info(wallet, false)?;

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    match wallet.sign_type {
        SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            anyhow::ensure!(info.fingerprint == fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        SignType::SoftwareDefinedDPNSign => {
            let user_sdc: psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            anyhow::ensure!(info.fingerprint == fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        SignType::SDKeySign => {
            let fingerprint = wallet_session
                .register_sd_key_circuit(
                    &wallet.sd_key_allowed_contract_id,
                    &wallet.sd_key_allowed_method_id,
                    wallet.sd_key_expected_tx_count,
                )
                .await?;
            anyhow::ensure!(info.fingerprint == fingerprint, "sd-key fingerprint mismatch");
        }
        _ => {}
    };

    let user_pk_hash = wallet_session.add_user(info.private_key, info.fingerprint).await?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;

    let mut builder = wallet_session.begin_trace_build(user_pk_hash).await?;
    let mut ordered_calls: Vec<ContractCallArgs> = Vec::new();
    let note_circuit = PrivateNoteInclusionCircuit::<C, D>::new(
        GLOBAL_USER_TREE_HEIGHT as usize,
        GLOBAL_CONTRACT_TREE_HEIGHT as usize,
        TOKEN_CONTRACT_STATE_TREE_HEIGHT as usize,
        NOTE_TREE_HEIGHT,
    );

    for item in items {
        match item {
            BatchClaimInputItem::PublicCall { call, .. } => {
                builder.trace_call(call.clone()).await?;
                ordered_calls.push(call);
            }
            BatchClaimInputItem::PrivateNoteClaim {
                contract_id,
                note_proof_path,
                random0,
                random1,
                ..
            } => {
                let note_data: NoteProofOutput = serde_json::from_str(&fs::read_to_string(note_proof_path)?)?;
                let token_contract_id = note_data
                    .token_contract_id
                    .parse::<u64>()
                    .map_err(|e| anyhow::anyhow!("invalid token_contract_id in note proof: {}", e))?;
                anyhow::ensure!(
                    contract_id == token_contract_id,
                    "private transfer claim contract mismatch: item contract_id={}, proof token_contract_id={}",
                    contract_id,
                    token_contract_id
                );
                let proof_bytes = &note_data.note_proof;
                let proof: ProofWithPublicInputs<F, C, D> =
                    bincode::deserialize(proof_bytes).map_err(|e| anyhow::anyhow!("invalid bincode proof: {}", e))?;
                let fingerprint = QHashOut::<F>::from_values(
                    note_data.note_proof_fingerprint[0],
                    note_data.note_proof_fingerprint[1],
                    note_data.note_proof_fingerprint[2],
                    note_data.note_proof_fingerprint[3],
                );
                let verifier_data = if let Ok(info) = wallet_session.circuit_info.get_circuit_info_by_fingerprint(fingerprint) {
                    info.verifier_data.to_verifier_data::<C, D>()
                } else {
                    let local_fingerprint = note_circuit.get_fingerprint();
                    anyhow::ensure!(
                        local_fingerprint == fingerprint,
                        "local PrivateNoteInclusion fingerprint mismatch: payload={}, local={}",
                        fingerprint,
                        local_fingerprint
                    );
                    note_circuit.get_verifier_config_ref().clone()
                };
                let claim = PrivateTransferClaim {
                    nullifier: note_data.nullifier,
                    owner: note_data.owner,
                    amount: note_data.amount,
                    user_tree_root: note_data.user_tree_root,
                    checkpoint_id: note_data.checkpoint_id,
                    note_root_slot: note_data.note_root_slot,
                    token_contract_id,
                    random0,
                    random1,
                    note_proof_fingerprint: fingerprint,
                    note_proof: proof.clone(),
                    note_verifier_data: AltVerifierOnlyCircuitData::from(&verifier_data),
                };
                let proof_ref = builder.add_external_proof(fingerprint, proof, verifier_data).await?;
                let call = claim.to_contract_call_args(contract_id, &proof_ref)?;
                builder.trace_call(call.clone()).await?;
                ordered_calls.push(call);
            }
            BatchClaimInputItem::ShieldDepositClaim {
                deposit_proof_path,
                token_l1_address,
                amount,
                source_chain_index,
                deposit_index,
                r0,
                r1,
                note_secret,
                nullifier_secret,
                ..
            } => {
                let token_address = parse_evm_addr_or_bytes32_to_u32x8(&token_l1_address)?;
                let amount_words = u64_to_u32x8_be(amount);
                let deposit_proof_file = load_deposit_proof_file(&deposit_proof_path)?;
                let shield_address = derive_shield_address(user_id, r0, r1);
                let proof_shield_address = qhash_from_u64x4(deposit_proof_file.shield_address);
                let deposit_root = qhash_from_u64x4(deposit_proof_file.deposit_root);
                let proof_nullifier_hash = qhash_from_u64x4(deposit_proof_file.nullifier_hash);
                let proof_note_commitment = qhash_from_u64x4(deposit_proof_file.note_commitment);
                let proof_token_address = deposit_proof_file.token_address_u32x8;
                let proof_l2_token_contract_id = deposit_proof_file.l2_token_contract_id;
                let proof_amount = deposit_proof_file.amount_u32x8;
                let proof_source_chain_index = deposit_proof_file.source_chain_index;
                let proof_deposit_index = deposit_proof_file.deposit_index;
                anyhow::ensure!(proof_shield_address == shield_address, "shield address mismatch vs deposit proof");
                anyhow::ensure!(proof_token_address == token_address, "token address mismatch vs deposit proof");
                anyhow::ensure!(proof_amount == amount_words, "amount mismatch vs deposit proof");
                anyhow::ensure!(
                    proof_source_chain_index == source_chain_index,
                    "source_chain_index mismatch vs deposit proof"
                );
                anyhow::ensure!(proof_deposit_index == deposit_index, "deposit_index mismatch vs deposit proof");
                match (note_secret.as_deref(), nullifier_secret.as_deref()) {
                    (Some(note_secret_raw), Some(nullifier_secret_raw)) => {
                        let note_secret_q = parse_qhash_cli_input(note_secret_raw)?;
                        let nullifier_secret_q = parse_qhash_cli_input(nullifier_secret_raw)?;
                        let note_secret_u64x4 = qhash_to_u64x4(note_secret_q);
                        let nullifier_secret_u64x4 = qhash_to_u64x4(nullifier_secret_q);
                        let note_commitment_q = derive_note_commitment(nullifier_secret_u64x4, note_secret_u64x4);
                        let nullifier_hash = derive_nullifier_hash(nullifier_secret_u64x4);
                        anyhow::ensure!(proof_note_commitment == note_commitment_q, "note_commitment mismatch vs deposit proof");
                        anyhow::ensure!(proof_nullifier_hash == nullifier_hash, "nullifier_hash mismatch vs deposit proof");
                    }
                    (None, None) => {}
                    _ => anyhow::bail!("shield_deposit_claim note_secret and nullifier_secret must be provided together"),
                }
                let l2_token_contract_id = proof_l2_token_contract_id;
                let circuit = DepositInclusionCircuit::<PoseidonGoldilocksConfig, 2>::new();
                let fingerprint = circuit.get_fingerprint();
                let proof_fingerprint = qhash_from_u64x4(deposit_proof_file.deposit_proof_fingerprint);
                anyhow::ensure!(
                    proof_fingerprint == fingerprint,
                    "DepositInclusion fingerprint mismatch: proof={} local={}",
                    proof_fingerprint,
                    fingerprint,
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
                let claim = ShieldDepositClaim {
                    contract_id: u32x8_be_to_u64(proof_l2_token_contract_id)?,
                    l2_token_contract_id: proof_l2_token_contract_id,
                    nullifier_hash: proof_nullifier_hash,
                    shield_address,
                    token_address,
                    amount: amount_words,
                    source_chain_index,
                    deposit_root,
                    note_commitment: proof_note_commitment,
                    deposit_index: proof_deposit_index,
                    r0,
                    r1,
                    proof_fingerprint: fingerprint,
                    proof: proof.clone(),
                    verifier_data: circuit.get_verifier_config_ref().into(),
                };
                let proof_ref = builder
                    .add_external_proof(fingerprint, proof, circuit.get_verifier_config_ref().clone())
                    .await?;
                let call = claim.to_contract_call_args(&proof_ref);
                builder.trace_call(call.clone()).await?;
                ordered_calls.push(call);
            }
        }
    }

    let call_data = ContractCallData::new(ordered_calls);
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let trace = builder.finalize_tx_trace_with_opts(call_data.software_defined_call.clone()).await?;
    let end_user_leaf_hash = trace.finalization.submit_end_cap_input.core.state_transition.end_user_leaf_hash;
    let envelope = GeneratedTxTraceJson::from_trace(&trace, serde_json::to_value(&call_data)?)?;
    if let Some(path) = &trace_out {
        crate::result::write_json_atomically(std::path::Path::new(path), &envelope)?;
        tracing::info!(trace_out = %path, "batch claim trace envelope saved");
    }

    if generate_only {
        let output_path = trace_out.ok_or_else(|| anyhow::anyhow!("batch claim --generate-only requires --trace-out"))?;
        println!("generated batch claim trace: tx_hash={}, output={}", envelope.tx_hash, output_path);
        return Ok(CommandResult::TxTrace(TxTraceResult {
            user_id: envelope.user_id,
            pk_hash: envelope.pk_hash,
            sig_hash: envelope.sig_hash,
            tx_hash: envelope.tx_hash,
            tx_count: envelope.tx_count,
            output_path: Some(output_path),
        }));
    }

    let tx_hash = wallet_session.prove_tx_trace(user_pk_hash, &trace).await?;
    let result = ProvedTxResultJson::new(envelope.sig_hash.clone(), tx_hash.to_string(), None, "submitted".to_string());
    println!("{}", serde_json::to_string_pretty(&result)?);

    let (status, confirmed_checkpoint) = if wait {
        let confirmed_checkpoint = provider
            .wait_for_endcap_inclusion(user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
            .await?;
        tracing::info!(
            checkpoint_id = confirmed_checkpoint,
            user_id,
            tx_hash = %tx_hash,
            end_user_leaf_hash = %end_user_leaf_hash,
            "batch claim endcap included"
        );
        (TransactionStatus::Confirmed, Some(confirmed_checkpoint))
    } else {
        (TransactionStatus::Submitted, None)
    };
    Ok(CommandResult::Transaction(TransactionResult {
        transaction_hash: tx_hash,
        user_id: Some(user_id),
        status,
        confirmed_checkpoint,
        network: psy_config.current_network_name().to_string(),
    }))
}

pub async fn run(args: BatchClaimArgs) -> anyhow::Result<CommandResult> {
    let input_json = fs::read_to_string(&args.input)?;
    let request: BatchClaimInput = serde_json::from_str(&input_json)?;
    anyhow::ensure!(request.version == 1, "unsupported batch claim input version {}", request.version);
    run_items(
        &args.rpc_config,
        &args.wallet,
        request.items,
        args.trace_out,
        args.generate_only,
        args.wait,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_u32x8_round_trips() {
        let value = 0x0102_0304_0506_0708u64;
        let words = u64_to_u32x8_be(value);
        assert_eq!(words, [0, 0, 0, 0, 0, 0, 0x0102_0304, 0x0506_0708]);
        assert_eq!(u32x8_be_to_u64(words).unwrap(), value);
    }

    #[test]
    fn parse_evm_addr_or_bytes32_to_u32x8_left_pads_20_byte_addresses() {
        let words = parse_evm_addr_or_bytes32_to_u32x8("0x1111111122222222333333334444444455555555").unwrap();
        assert_eq!(words[0..3], [0, 0, 0]);
        assert_eq!(words[3..8], [0x11111111, 0x22222222, 0x33333333, 0x44444444, 0x55555555]);
    }

    #[test]
    fn shield_deposit_claim_uses_raw_secret_field_names() {
        let input = serde_json::json!({
            "version": 1,
            "items": [{
                "kind": "shield_deposit_claim",
                "deposit_proof_path": "deposit-proof.json",
                "token_l1_address": "0x1111111122222222333333334444444455555555",
                "amount": 42,
                "source_chain_index": 0,
                "deposit_index": 7,
                "r0": 11,
                "r1": 22,
                "note_secret": "0x1234",
                "nullifier_secret": "0x5678"
            }]
        });

        let parsed: BatchClaimInput = serde_json::from_value(input).unwrap();
        match &parsed.items[0] {
            BatchClaimInputItem::ShieldDepositClaim {
                deposit_proof_path,
                note_secret,
                nullifier_secret,
                ..
            } => {
                assert_eq!(deposit_proof_path, "deposit-proof.json");
                assert_eq!(note_secret.as_deref(), Some("0x1234"));
                assert_eq!(nullifier_secret.as_deref(), Some("0x5678"));
            }
            _ => panic!("expected shield deposit claim item"),
        }
    }

    #[test]
    fn shield_deposit_claim_rejects_legacy_note_secret_hash_field() {
        let input = serde_json::json!({
            "version": 1,
            "items": [{
                "kind": "shield_deposit_claim",
                "deposit_proof_path": "deposit-proof.json",
                "token_l1_address": "0x1111111122222222333333334444444455555555",
                "amount": 42,
                "source_chain_index": 0,
                "deposit_index": 7,
                "r0": 11,
                "r1": 22,
                "note_secret_hash": "0x1234",
                "nullifier_secret": "0x5678"
            }]
        });

        let err = serde_json::from_value::<BatchClaimInput>(input).unwrap_err();
        assert!(err.to_string().contains("note_secret"));
    }
}
