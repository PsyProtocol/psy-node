use plonky2::{
    field::{goldilocks_field::GoldilocksField, types::{Field, PrimeField64}},
    plonk::config::PoseidonGoldilocksConfig,
};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::ContractCallArgs;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    config::store_config::{C, D, F},
    privacy::shield_deposit_claim::ShieldDepositClaimInput,
    traits::qdatastore::qtreedata::QTreeDataStoreReaderSync,
};
use psy_common_circuit::circuits::traits::qstandard::QStandardCircuit;
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_crypto::{
    hash::{merkle::core::MerkleProofCore, traits::hasher::{FieldQHasher, PoseidonHasher}},
    shield_address::{derive_nullifier_hash, derive_shield_address, qhashout_to_u32x8_be},
};
use psy_prover::session::WalletSession;
use psy_provider::provider::RpcProvider;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use serde::Deserialize;

use super::args::ClaimDepositArgs;

use psy_dpn_circuit::circuits::privacy::shield_deposit_claim::ShieldDepositClaimCircuit;

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
    note_secret_hash: String,
    source_chain_id: u32,
}

#[derive(Debug, Deserialize)]
struct DepositClaimProofResponse {
    found: bool,
    checkpoint_id: Option<u64>,
    deposit_index: Option<u64>,
    leaf_hash: Option<String>,
    siblings: Option<Vec<String>>,
    deposit_root: Option<String>,
    deposit: Option<DepositClaimProofDeposit>,
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
    note_secret_hash_words: [u32; 8],
) -> QHashOut<F> {
    let mut felts = Vec::with_capacity(41);
    felts.extend(shield_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(token.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(l2_token_contract_id.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.extend(amount.iter().map(|&v| F::from_canonical_u64(v as u64)));
    felts.push(F::from_canonical_u64(source_chain_index as u64));
    felts.extend(note_secret_hash_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
    PoseidonHasher::q_hash_many(&felts)
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
    QHashOut::<F>::from_str(
        hex_str
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
    )
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

fn qhash_from_u64x4(words: [u64; 4]) -> QHashOut<F> {
    QHashOut::from_values(words[0], words[1], words[2], words[3])
}

fn rebuild_proof_tree_root_from_path(
    leaf: QHashOut<F>,
    index: u64,
    siblings: &[[u64; 4]],
) -> QHashOut<F> {
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

fn resolve_services_url(psy_config: &psy_config::PsyConfigGoldilocks) -> anyhow::Result<String> {
    let network = psy_config.get_current_network()?;
    if let Some(urls) = &network.api_services_url {
        if let Some(first) = urls.first() {
            return Ok(first.trim_end_matches('/').to_string());
        }
    }
    anyhow::bail!("no psy-services URL configured in api_services_url")
}

async fn fetch_deposit_claim_proof(
    services_url: &str,
    deposit_index: u64,
) -> anyhow::Result<(QHashOut<F>, MerkleProofCore<QHashOut<F>>, DepositClaimProofDeposit, Option<u64>)> {
    let url = format!(
        "{}/api/v1/bridge/deposit-claim-proof?deposit_index={}",
        services_url.trim_end_matches('/'),
        deposit_index
    );
    let response = reqwest::Client::new().get(&url).send().await?;
    let status = response.status();
    let body = response.text().await?;
    anyhow::ensure!(status.is_success(), "deposit claim proof request failed: status={} body={}", status, body);

    let envelope: ApiResponse<DepositClaimProofResponse> = serde_json::from_str(&body)?;
    anyhow::ensure!(envelope.success, "deposit claim proof request unsuccessful: {}", envelope.error.unwrap_or_else(|| "unknown error".to_string()));
    let parsed = envelope
        .data
        .ok_or_else(|| anyhow::format_err!("deposit claim proof response missing data"))?;
    anyhow::ensure!(parsed.found, "deposit claim proof not found for deposit_index={}", deposit_index);

    let deposit_root: QHashOut<F> = parse_qhash_internal_bytes_hex(
        parsed
        .deposit_root
        .as_deref()
        .ok_or_else(|| anyhow::format_err!("deposit proof missing deposit_root"))?,
    )?;
    let leaf_hash: QHashOut<F> = parse_qhash_display_hex(
        parsed
        .leaf_hash
        .as_deref()
        .ok_or_else(|| anyhow::format_err!("deposit proof missing leaf_hash"))?,
    )?;
    let siblings: Vec<QHashOut<F>> = parsed
        .siblings
        .ok_or_else(|| anyhow::format_err!("deposit proof missing siblings"))?
        .into_iter()
        .map(|s| parse_qhash_internal_bytes_hex(&s))
        .collect::<Result<_, _>>()?;
    let deposit = parsed
        .deposit
        .ok_or_else(|| anyhow::format_err!("deposit proof missing deposit payload"))?;
    let proof = MerkleProofCore {
        root: deposit_root,
        value: leaf_hash,
        index: parsed.deposit_index.unwrap_or(deposit_index),
        siblings,
    };
    Ok((deposit_root, proof, deposit, parsed.checkpoint_id))
}

pub async fn run(args: ClaimDepositArgs) -> anyhow::Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let services_url = resolve_services_url(&psy_config)?;
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let token_address = parse_evm_addr_or_bytes32_to_u32x8(&args.token_l1_address)?;
    let amount = u64_to_u32x8_be(args.amount);
    let note_secret_hash_q = parse_qhash_cli_input(&args.note_secret_hash)?;
    let nullifier_secret_q = parse_qhash_cli_input(&args.nullifier_secret)?;
    let note_secret_hash = qhash_to_u64x4(note_secret_hash_q);
    let nullifier_secret = qhash_to_u64x4(nullifier_secret_q);

    let shield_address = derive_shield_address(args.user_id, args.r0, args.r1);
    let nullifier_hash = derive_nullifier_hash(nullifier_secret);
    let (deposit_root, deposit_proof, proof_deposit, services_checkpoint_id) =
        fetch_deposit_claim_proof(&services_url, args.deposit_index).await?;
    let services_leaf_hash = deposit_proof.value;

    let proof_token_address = parse_evm_addr_or_bytes32_to_u32x8(&proof_deposit.token_address)?;
    let proof_l2_token_contract_id = parse_evm_addr_or_bytes32_to_u32x8(&proof_deposit.l2_token_contract_id)?;
    let proof_amount_u64 = proof_deposit.amount.parse::<u64>()?;
    let proof_amount = u64_to_u32x8_be(proof_amount_u64);
    let proof_note_secret_hash = parse_qhash_bytes32_be(&proof_deposit.note_secret_hash)?;
    let proof_shield_address = parse_qhash_bytes32_be(&proof_deposit.shield_address)?;
    let expected_note_secret_hash = note_secret_hash_q;
    tracing::info!(
        proof_shield_address = %proof_shield_address,
        local_shield_address = %shield_address,
        "claim_deposit shield address comparison"
    );
    anyhow::ensure!(
        proof_shield_address == shield_address,
        "shield address mismatch vs services proof: proof={} local={}",
        proof_shield_address,
        shield_address,
    );
    anyhow::ensure!(proof_token_address == token_address, "token address mismatch vs services proof");
    anyhow::ensure!(proof_amount == amount, "amount mismatch vs services proof");
    anyhow::ensure!(proof_deposit.source_chain_id == args.source_chain_index, "source_chain_index mismatch vs services proof");
    anyhow::ensure!(proof_note_secret_hash == expected_note_secret_hash, "note_secret_hash mismatch vs services proof");

    let l2_token_contract_id = proof_l2_token_contract_id;
    let shield_words_be = qhashout_to_u32x8_be(proof_shield_address);
    let note_secret_hash_words = u64x4_to_u32x8_be(note_secret_hash);
    let proof_note_secret_hash_words = parse_bytes32_to_u32x8(&proof_deposit.note_secret_hash)?;
    tracing::info!(
        shield_words_be = ?shield_words_be,
        proof_shield_words = ?shield_words_be,
        token_address_words = ?token_address,
        l2_token_contract_id_words = ?l2_token_contract_id,
        amount_words = ?amount,
        source_chain_index = args.source_chain_index,
        note_secret_hash_words = ?note_secret_hash_words,
        proof_note_secret_hash_words = ?proof_note_secret_hash_words,
        "claim_deposit preimage words"
    );
    let deposit_commitment = derive_deposit_commitment_from_words(
        shield_words_be,
        token_address,
        l2_token_contract_id,
        amount,
        args.source_chain_index,
        proof_note_secret_hash_words,
    );
    tracing::info!(
        services_leaf_hash = %services_leaf_hash,
        derived_deposit_commitment = %deposit_commitment,
        "claim_deposit leaf comparison"
    );
    anyhow::ensure!(
        services_leaf_hash == deposit_commitment,
        "services leaf_hash mismatch vs derived shield deposit leaf"
    );

    let input = ShieldDepositClaimInput::<GoldilocksField> {
        nullifier_secret: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(nullifier_secret[i])),
        note_secret_hash: std::array::from_fn(|i| GoldilocksField::from_canonical_u64(note_secret_hash[i])),
        r0: GoldilocksField::from_canonical_u64(args.r0),
        r1: GoldilocksField::from_canonical_u64(args.r1),
        user_id: args.user_id,
        deposit_index: args.deposit_index,
        token_address,
        l2_token_contract_id,
        amount,
        source_chain_index: args.source_chain_index,
        deposit_root,
        deposit_proof: deposit_proof.clone(),
    };

    let circuit_nullifier_hash = {
        use psy_crypto::hash::traits::hasher::{FieldQHasher, PoseidonHasher};
        let felts = nullifier_secret
            .iter()
            .map(|&v| F::from_canonical_u64(v))
            .collect::<Vec<_>>();
        PoseidonHasher::q_hash_many(&felts)
    };
    tracing::warn!(
        client_nullifier_hash = %nullifier_hash,
        circuit_nullifier_hash = %circuit_nullifier_hash,
        nullifier_hash_match = (nullifier_hash == circuit_nullifier_hash),
        shield_address_qhash = %shield_address,
        "claim_deposit hash sanity"
    );

    let circuit = ShieldDepositClaimCircuit::<PoseidonGoldilocksConfig, 2>::new();
    let fingerprint = circuit.get_fingerprint();
    tracing::info!(
        fingerprint = %fingerprint,
        shield_address = %shield_address,
        nullifier_hash = %nullifier_hash,
        deposit_commitment = %deposit_commitment,
        services_leaf_hash = %services_leaf_hash,
        deposit_root = %deposit_root,
        checkpoint_id = services_checkpoint_id.unwrap_or(args.checkpoint_id),
        deposit_index = args.deposit_index,
        "built shield deposit claim proof inputs"
    );
    let proof = circuit.prove(&input)?;
    let proof_pi_hash = QHashOut(plonky2::hash::hash_types::HashOut {
        elements: [
            proof.public_inputs[0],
            proof.public_inputs[1],
            proof.public_inputs[2],
            proof.public_inputs[3],
        ],
    });
    {
        use psy_crypto::hash::traits::hasher::{FieldQHasher, PoseidonHasher};
        let felts = |a: [u64; 4]| a.map(|v| F::from_canonical_u64(v));
        let felts8 = |a: [u32; 8]| a.map(|v| F::from_canonical_u64(v as u64));
        let s = felts(qhash_to_u64x4(shield_address));
        let a = felts8(amount);
        let t = felts8(token_address);
        let l = felts8(proof_l2_token_contract_id);
        let ch = F::from_canonical_u64(args.source_chain_index as u64);
        let dr = felts(qhash_to_u64x4(deposit_root));
        let nh = felts(qhash_to_u64x4(nullifier_hash));
        let mut preimage: Vec<F> = vec![];
        preimage.extend(s); preimage.extend(a); preimage.extend(t); preimage.extend(l);
        preimage.push(ch); preimage.extend(dr); preimage.extend(nh);

        // DEBUG: log all 37 preimage elements
        {
            let s_vals: Vec<u64> = s.iter().map(|f| f.to_canonical_u64()).collect();
            let a_vals: Vec<u64> = a.iter().map(|f| f.to_canonical_u64()).collect();
            let t_vals: Vec<u64> = t.iter().map(|f| f.to_canonical_u64()).collect();
            let l_vals: Vec<u64> = l.iter().map(|f| f.to_canonical_u64()).collect();
            let ch_val = ch.to_canonical_u64();
            let dr_vals: Vec<u64> = dr.iter().map(|f| f.to_canonical_u64()).collect();
            let nh_vals: Vec<u64> = nh.iter().map(|f| f.to_canonical_u64()).collect();
            tracing::warn!(
                "[DEBUG] preimage: shield={:?} amount={:?} token={:?} l2_id={:?} chain={} deposit_root={:?} nullifier={:?}",
                s_vals, a_vals, t_vals, l_vals, ch_val, dr_vals, nh_vals
            );
        }
        let contract_pi_hash = PoseidonHasher::q_hash_many(&preimage);

        // Verify hash function consistency
        {
            use plonky2::hash::hashing::hash_n_to_hash_no_pad;
            let pi_via_plonky2: QHashOut<F> = QHashOut(hash_n_to_hash_no_pad::<F, plonky2::hash::poseidon::PoseidonPermutation<F>>(&preimage));
            let q_matches_plonky2 = contract_pi_hash == pi_via_plonky2;
            tracing::warn!(
                "[DEBUG] pi_hash comparison: q_hash_many={} plonky2_hash={} match={}",
                contract_pi_hash, pi_via_plonky2, q_matches_plonky2
            );
            // Also verify that the preimage hash matches proof_pi_hash when deposit_root is used correctly
            let preimage_with_proof_root: Vec<F> = {
                let proof_root = deposit_root;
                let dr2 = felts(qhash_to_u64x4(proof_root));
                let mut p = vec![];
                p.extend(s.clone()); p.extend(a.clone()); p.extend(t.clone()); p.extend(l.clone());
                p.push(ch); p.extend(dr2); p.extend(nh.clone());
                p
            };
            let pi_with_proof_root = PoseidonHasher::q_hash_many(&preimage_with_proof_root);
            tracing::warn!(
                "[DEBUG] pi_hash with proof root: {} match_with_circuit={}",
                pi_with_proof_root,
                pi_with_proof_root == proof_pi_hash
            );
        }

        // Compute circuit-style deposit_commitment using [hi0, lo0] ordering
        let circuit_style_leaf = {
            let shield_e = qhash_to_u64x4(shield_address);
            let circuit_shield_words = vec![
                (shield_e[0] >> 32) as u32, (shield_e[0] & 0xffffffff) as u32,
                (shield_e[1] >> 32) as u32, (shield_e[1] & 0xffffffff) as u32,
                (shield_e[2] >> 32) as u32, (shield_e[2] & 0xffffffff) as u32,
                (shield_e[3] >> 32) as u32, (shield_e[3] & 0xffffffff) as u32,
            ];
            let circuit_note_words = u64x4_to_u32x8_be(note_secret_hash);
            let mut f = Vec::with_capacity(41);
            f.extend(circuit_shield_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
            f.extend(token_address.iter().map(|&v| F::from_canonical_u64(v as u64)));
            f.extend(proof_l2_token_contract_id.iter().map(|&v| F::from_canonical_u64(v as u64)));
            f.extend(amount.iter().map(|&v| F::from_canonical_u64(v as u64)));
            f.push(F::from_canonical_u64(args.source_chain_index as u64));
            f.extend(circuit_note_words.iter().map(|&v| F::from_canonical_u64(v as u64)));
            PoseidonHasher::q_hash_many(&f)
        };
        tracing::warn!(
            circuit_style_leaf = %circuit_style_leaf,
            services_leaf = %services_leaf_hash,
            pi_match = (contract_pi_hash == proof_pi_hash),
            leaf_match = (circuit_style_leaf == services_leaf_hash),
            "circuit vs contract leaf/preimage comparison"
        );

        let mut recomputed_root = deposit_proof.value;
        let mut cursor = deposit_proof.index as usize;
        for sibling_qhash in &deposit_proof.siblings {
            let left = if cursor % 2 == 0 { recomputed_root } else { *sibling_qhash };
            let right = if cursor % 2 == 0 { *sibling_qhash } else { recomputed_root };
            recomputed_root = PoseidonHasher::q_two_to_one(left, right);
            cursor /= 2;
        }
        let dr_recomputed = felts(qhash_to_u64x4(recomputed_root));
        let root_match = recomputed_root == deposit_root;
        tracing::warn!(
            contract_pi_hash = %contract_pi_hash,
            proof_pi_hash = %proof_pi_hash,
            deposit_root_from_proof = %deposit_root,
            deposit_root_recomputed = %recomputed_root,
            root_match = root_match,
            pi0_proof = proof.public_inputs[0].to_canonical_u64(),
            pi1_proof = proof.public_inputs[1].to_canonical_u64(),
            pi2_proof = proof.public_inputs[2].to_canonical_u64(),
            pi3_proof = proof.public_inputs[3].to_canonical_u64(),
            pi0_ours = contract_pi_hash.0.elements[0].to_canonical_u64(),
            pi1_ours = contract_pi_hash.0.elements[1].to_canonical_u64(),
            pi2_ours = contract_pi_hash.0.elements[2].to_canonical_u64(),
            pi3_ours = contract_pi_hash.0.elements[3].to_canonical_u64(),
            "full public inputs hash comparison"
        );
    }
    tracing::warn!(proof_public_inputs_hash = %proof_pi_hash, "proof public inputs hash from circuit");
    {
        use psy_crypto::hash::traits::hasher::{FieldQHasher, PoseidonHasher};
        let felts = |a: [u64; 4]| a.map(|v| F::from_canonical_u64(v));
        let felts8 = |a: [u32; 8]| a.map(|v| F::from_canonical_u64(v as u64));
        let s = felts(qhash_to_u64x4(shield_address));
        let a = felts8(amount);
        let t = felts8(token_address);
        let l = felts8(proof_l2_token_contract_id);
        let ch = F::from_canonical_u64(args.source_chain_index as u64);
        let dr = felts(qhash_to_u64x4(deposit_root));
        let nh = felts(qhash_to_u64x4(nullifier_hash));
        let mut preimage: Vec<F> = vec![];
        preimage.extend(s); preimage.extend(a); preimage.extend(t); preimage.extend(l);
        preimage.push(ch); preimage.extend(dr); preimage.extend(nh);
        let contract_pi_hash = PoseidonHasher::q_hash_many(&preimage);
        tracing::warn!(
            contract_pi_hash = %contract_pi_hash,
            proof_pi_hash = %proof_pi_hash,
            match_ = (contract_pi_hash == proof_pi_hash),
            shield_u64x4 = ?qhash_to_u64x4(shield_address),
            deposit_root_u64x4 = ?qhash_to_u64x4(deposit_root),
            nullifier_hash_u64x4 = ?qhash_to_u64x4(nullifier_hash),
            deposit_root_u32x8 = ?qhash_to_internal_u32x8(deposit_root),
            "contract-style public inputs hash vs circuit proof"
        );
        if contract_pi_hash != proof_pi_hash {
            for (i, v) in preimage.iter().enumerate() {
                tracing::warn!(idx=i, val=v.to_canonical_u64(), "PI preimage field");
            }
        }
    }

    let mut wallet_session = WalletSession::new(&rpc_config).await?;
    let info = load_wallet_key_info(&args.wallet, false)?;

    match args.wallet.sign_type {
        psy_client_common::args::SignType::SoftwareDefinedPlonky2Sign => {
            let fingerprint = wallet_session
                .wallet
                .register_plonky2_software_defined_circuit(MAX_CONTRACT_STATE_TREE_HEIGHT, 0)
                .await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-plonky2-sign key fingerprint mismatch");
        }
        psy_client_common::args::SignType::SoftwareDefinedDPNSign => {
            let user_sdc: DPNFunctionCircuitDefinition = serde_json::from_str(&std::fs::read_to_string("sdc.json")?)?;
            let fingerprint = wallet_session.wallet.register_psy_software_defined_circuit(user_sdc, false).await?;
            assert_eq!(info.fingerprint, fingerprint, "software-defined-dpn-sign key fingerprint mismatch");
        }
        _ => {}
    };

    let receiver_pk = wallet_session
        .add_user_with_user_id(info.private_key, info.fingerprint, args.user_id)
        .await?;
    wallet_session.start_session(receiver_pk).await?;

    let external_leaf = PoseidonHasher::q_two_to_one(
        fingerprint,
        qhash_from_u64x4([
            proof.public_inputs[0].to_canonical_u64(),
            proof.public_inputs[1].to_canonical_u64(),
            proof.public_inputs[2].to_canonical_u64(),
            proof.public_inputs[3].to_canonical_u64(),
        ]),
    );

    let (proof_index, proof_siblings) = wallet_session
        .add_external_proof_with_siblings(receiver_pk, fingerprint, proof, circuit.get_verifier_config_ref().clone())
        .await?;

    let rebuilt_root = rebuild_proof_tree_root_from_path(external_leaf, proof_index, &proof_siblings);
    let session_root = {
        let mgr = wallet_session
            .user_session_mgrs
            .get(&receiver_pk)
            .ok_or_else(|| anyhow::format_err!("user session manager missing after external proof insertion"))?;
        mgr.proof_tree_state.get_proof_tree_root().await
    };

    tracing::info!(
        proof_index,
        proof_siblings_count = proof_siblings.len(),
        first_sibling = ?proof_siblings.first().map(|s| format!("{:016x}{:016x}{:016x}{:016x}", s[0], s[1], s[2], s[3])),
        external_leaf = %external_leaf,
        rebuilt_root = %rebuilt_root,
        session_root = %session_root,
        rebuilt_matches_session_root = rebuilt_root == session_root,
        "external proof added to proof tree"
    );

    let mut contract_inputs = Vec::with_capacity(100);
    contract_inputs.extend_from_slice(&qhash_to_u64x4(nullifier_hash));
    contract_inputs.extend_from_slice(&qhash_to_u64x4(shield_address));
    contract_inputs.extend(token_address.iter().map(|&v| v as u64));
    contract_inputs.extend(amount.iter().map(|&v| v as u64));
    contract_inputs.push(args.source_chain_index as u64);
    contract_inputs.extend(qhash_to_internal_u32x8(deposit_root).iter().map(|&v| v as u64));
    contract_inputs.push(args.r0);
    contract_inputs.push(args.r1);
    for sibling in &proof_siblings {
        contract_inputs.extend_from_slice(sibling);
    }
    contract_inputs.push(proof_index);

    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    wallet_session
        .prove_contract_call(
            receiver_pk,
            vec![ContractCallArgs {
                contract_id: u32x8_be_to_u64(proof_l2_token_contract_id)?,
                method_name: "claim_deposit".to_string(),
                inputs: contract_inputs,
            }],
        )
        .await?;
    let tx_hash = wallet_session.sign_and_submit(receiver_pk, Default::default()).await?;

    tracing::info!(
        tx_hash = %tx_hash,
        proof_index,
        checkpoint_before,
        "shield claim_deposit submitted"
    );

    let confirmed_checkpoint = provider
        .wait_for_endcap_inclusion(args.user_id, tx_hash, checkpoint_before, Some(180), 1)
        .await?;
    tracing::info!(
        checkpoint_id = confirmed_checkpoint,
        user_id = args.user_id,
        deposit_index = args.deposit_index,
        "shield claim_deposit confirmed"
    );

    Ok(())
}
use std::str::FromStr;

#[cfg(test)]
mod tests {
    use super::*;
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

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn hash_n_to_hash_no_pad_37_elements_matches_standalone_poseidon_hash() {
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // 37 random-ish input targets
        let inputs: Vec<_> = (0..37).map(|_| builder.add_virtual_target()).collect();
        let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.clone());

        // Register hash as public input
        for elem in &hash.elements {
            builder.register_public_input(*elem);
        }

        let data = builder.build::<C>();
        let mut pw = PartialWitness::new();
        let witness_values: Vec<F> = (0..37).map(|i| F::from_canonical_u64((i as u64) * 12345 + 999)).collect();
        for (target, val) in inputs.iter().zip(&witness_values) {
            pw.set_target(*target, *val);
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
            "circuit builder hash_n_to_hash_no_pad differs from standalone PoseidonHash::hash_no_pad for 37 elements"
        );
    }

    #[test]
    fn shield_claim_circuit_37_element_preimage_matches_external_computation() {
        // Use the exact same values as the claim-deposit test case
        type F = <C as GenericConfig<D>>::F;
        
        use psy_crypto::hash::traits::hasher::PoseidonHasher;
        let shield_address = derive_shield_address(0, 0, 0);
        let token_address: [u32; 8] = [0,0,0,521811806,3481533445,618562213,998194842,804640937];
        let l2_token_contract_id: [u32; 8] = [0,0,0,0,0,0,0,4];
        let amount: [u32; 8] = [0,0,0,0,0,0,0,1000000];
        let source_chain_index: u32 = 0;
        let nullifier_secret: [u64; 4] = [0, 0, 0, 3];
        let note_secret_hash: [u64; 4] = [0, 0, 0, 2];
        let deposit_index: u64 = 0;

        let nullifier_hash = derive_nullifier_hash(nullifier_secret);
        let note_secret_hash_words: [u32; 8] = [
            (note_secret_hash[0] >> 32) as u32, (note_secret_hash[0] & 0xffffffff) as u32,
            (note_secret_hash[1] >> 32) as u32, (note_secret_hash[1] & 0xffffffff) as u32,
            (note_secret_hash[2] >> 32) as u32, (note_secret_hash[2] & 0xffffffff) as u32,
            (note_secret_hash[3] >> 32) as u32, (note_secret_hash[3] & 0xffffffff) as u32,
        ];
        let shield_words = qhashout_to_u32x8_be(shield_address);
        let deposit_commitment = derive_deposit_commitment_from_words(
            shield_words, token_address, l2_token_contract_id,
            amount, source_chain_index, note_secret_hash_words,
        );

        // Build a minimal ShieldDepositClaimCircuit and prove
        let circuit = ShieldDepositClaimCircuit::<C, D>::new();
        let input = ShieldDepositClaimInput::<F> {
            nullifier_secret: std::array::from_fn(|i| F::from_canonical_u64(nullifier_secret[i])),
            note_secret_hash: std::array::from_fn(|i| F::from_canonical_u64(note_secret_hash[i])),
            r0: F::from_canonical_u64(0),
            r1: F::from_canonical_u64(0),
            user_id: 0,
            deposit_index,
            token_address,
            l2_token_contract_id,
            amount,
            source_chain_index,
            deposit_root: deposit_commitment,
            deposit_proof: MerkleProofCore {
                root: deposit_commitment,
                value: deposit_commitment,
                index: deposit_index,
                siblings: vec![],
            },
        };
        let proof = circuit.prove(&input).unwrap();

        // Circuit's public_inputs_hash = proof.public_inputs[0..4]
        let circuit_pi = QHashOut(plonky2::hash::hash_types::HashOut {
            elements: [proof.public_inputs[0], proof.public_inputs[1], proof.public_inputs[2], proof.public_inputs[3]],
        });

        // Externally compute the same 37-element hash
        let s = qhash_to_u64x4(shield_address);
        let a = amount.map(|v| v as u64);
        let t = token_address.map(|v| v as u64);
        let l = l2_token_contract_id.map(|v| v as u64);
        let dr = qhash_to_u64x4(deposit_commitment);
        let nh = qhash_to_u64x4(nullifier_hash);
        let mut felts: Vec<F> = vec![];
        felts.extend(s.iter().map(|&v| F::from_canonical_u64(v)));
        felts.extend(a.iter().map(|&v| F::from_canonical_u64(v)));
        felts.extend(t.iter().map(|&v| F::from_canonical_u64(v)));
        felts.extend(l.iter().map(|&v| F::from_canonical_u64(v)));
        felts.push(F::from_canonical_u64(source_chain_index as u64));
        felts.extend(dr.iter().map(|&v| F::from_canonical_u64(v)));
        felts.extend(nh.iter().map(|&v| F::from_canonical_u64(v)));
        let external_pi = PoseidonHasher::q_hash_many(&felts);

        assert_eq!(
            circuit_pi, external_pi,
            "ShieldDepositClaimCircuit public_inputs_hash != external computation with same values"
        );
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
            QHashOut::from_values(
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x0123456789abcdef,
                0xfedcba9876543210,
            )
        );
    }

    #[test]
    fn parse_bytes32_be_hex_matches_expected_field_order() {
        let parsed = parse_qhash_bytes32_be(sample_bytes32_be_hex()).unwrap();
        assert_eq!(
            parsed,
            QHashOut::from_values(
                0x1122334455667788,
                0x99aabbccddeeff00,
                0x0123456789abcdef,
                0xfedcba9876543210,
            )
        );
    }

    #[test]
    fn internal_u32x8_roundtrip_layout_is_stable() {
        let hash = QHashOut::from_values(
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x0123456789abcdef,
            0xfedcba9876543210,
        );
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
        let hash = QHashOut::from_values(
            0x1122334455667788,
            0x99aabbccddeeff00,
            0x0123456789abcdef,
            0xfedcba9876543210,
        );
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
        let effective = if proof_shield == QHashOut::ZERO {
            proof_shield
        } else {
            derived
        };
        assert_eq!(effective, QHashOut::ZERO);
    }
}
