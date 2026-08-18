//! Realm P2P consensus helpers.
//!
//! Phase 1 wire-level operations shared by the scheduled proposer, the
//! sub-realm validators, and the coordinator over the frozen
//! [`psy_data::p2p`] types:
//!
//! - [`decode_proposal_body`]: strict decode of the three length-prefixed body
//!   sections (finalizer output, finalizer proof, state updates) with hash
//!   verification against the [`Proposal`] metadata. There are exactly three
//!   `u32` length prefixes and no other sections.
//! - [`sign_vote`]: produce a BLS [`Vote`] over the canonical `vote_message`.
//! - [`form_certificate`]: aggregate validator votes into a [`Certificate`].
//! - [`validate_certificate`]: enforce the `ceil(n/2)` replication threshold,
//!   require every signer bitmap bit to name a validator leaf,
//!   and run `FastAggregateVerify` over the reconstructed `vote_message`.
//!
//! A [`Vote`] attests that the signer verified the GUTA proof, commit output,
//! and in-band FFS state updates. This module performs no replay into local
//! state and keeps no per-validator tracking set.

use parth_core::{
    crypto::hash::traits::QFieldHashable,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier},
};
use psy_data::{
    guta::{
        header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
        realm_finalize::{
            protocol_decode_finalize_output, realm_finalize_guta_chain_domain,
            RealmFinalizeGUTAAction, RealmFinalizeGUTAPublicOutput,
        },
    },
    p2p::{
        aggregate_signatures, bitmap_get, bitmap_set, sha256, vote_message, BlsPublicKey,
        BlsSecretKey, BlsSignature, Certificate, ProtocolError, ProtocolReader, ProtocolResult,
        Proposal, Vote, MAX_BACKUP_BYTES, MAX_FINALIZER_OUTPUT_BYTES, MAX_FINALIZER_PROOF_BYTES,
        MAX_INCLUSION_LAG_CHECKPOINTS, MAX_PROPOSAL_BODY_BYTES, MAX_VALIDATORS_PER_REALM,
        MIN_VALIDATORS_PER_REALM, replication_threshold,
    },
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use std::collections::HashSet;

/// Decoded proposal body: the three length-prefixed sections in wire order.
///
/// `output` is exactly [`MAX_FINALIZER_OUTPUT_BYTES`] bytes; `proof` is the
/// opaque verifier proof; `state_updates` is the canonical encoding of
/// [`PsyPreparedRealmBlockStateUpdates`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedProposalBody {
    /// Finalizer public output (exactly `MAX_FINALIZER_OUTPUT_BYTES` bytes).
    pub output: Vec<u8>,
    /// Opaque finalizer proof bytes (`<= MAX_FINALIZER_PROOF_BYTES`).
    pub proof: Vec<u8>,
    /// Canonical `PsyPreparedRealmBlockStateUpdates` bytes (`<= MAX_BACKUP_BYTES`).
    pub state_updates: Vec<u8>,
}

/// Decode a proposal body into its three length-prefixed sections.
///
/// The wire layout is exactly `u32_le(output_len) || output ||
/// u32_le(proof_len) || proof || u32_le(state_updates_len) || state_updates`,
/// with no trailing bytes. `output_len` must equal
/// [`MAX_FINALIZER_OUTPUT_BYTES`]; `proof_len` and `state_updates_len` must
/// not exceed their frozen maxima. The decoded sections and the full body
/// are then checked against the matching hashes carried by `proposal`.
pub fn decode_proposal_body(
    proposal: &Proposal,
    body: &[u8],
) -> ProtocolResult<DecodedProposalBody> {
    if body.len() > MAX_PROPOSAL_BODY_BYTES {
        return Err(ProtocolError::LengthLimit {
            what: "proposal body",
            got: body.len() as u64,
            max: MAX_PROPOSAL_BODY_BYTES as u64,
        });
    }

    let mut reader = ProtocolReader::new(body);
    let output = reader.read_bytes_u32("finalizer output", MAX_FINALIZER_OUTPUT_BYTES as u32)?;
    if output.len() != MAX_FINALIZER_OUTPUT_BYTES {
        return Err(ProtocolError::InvalidLength {
            what: "finalizer output",
            got: output.len(),
            expected: MAX_FINALIZER_OUTPUT_BYTES,
        });
    }
    let proof = reader.read_bytes_u32("finalizer proof", MAX_FINALIZER_PROOF_BYTES as u32)?;
    let state_updates = reader.read_bytes_u32("state updates", MAX_BACKUP_BYTES as u32)?;
    reader.finish()?;

    if sha256(body) != proposal.body_hash {
        return Err(ProtocolError::Message("body_hash mismatch"));
    }
    if sha256(&output) != proposal.public_output_hash {
        return Err(ProtocolError::Message("public_output_hash mismatch"));
    }
    if sha256(&proof) != proposal.finalizer_proof_hash {
        return Err(ProtocolError::Message("finalizer_proof_hash mismatch"));
    }
    if sha256(&state_updates) != proposal.backup_hash {
        return Err(ProtocolError::Message("backup_hash mismatch"));
    }

    Ok(DecodedProposalBody { output, proof, state_updates })
}

/// Verify the in-band FFS roots against the decoded GUTA output.
pub fn verify_state_updates_match_guta_output<F, Hash>(
    state_updates: &PsyPreparedRealmBlockStateUpdates<Hash>,
    output: &RealmFinalizeGUTAPublicOutput<F, Hash>,
) -> anyhow::Result<()>
where
    Hash: Q256BitHash,
{
    anyhow::ensure!(
        state_updates.old_realm_root.into_owned_32bytes()
            == output
                .final_guta_header
                .state_transition
                .old_node_value
                .into_owned_32bytes(),
        "Realm state updates old_realm_root does not match GUTA old_node_value"
    );
    anyhow::ensure!(
        state_updates.new_realm_root.into_owned_32bytes()
            == output
                .final_guta_header
                .state_transition
                .new_node_value
                .into_owned_32bytes(),
        "Realm state updates new_realm_root does not match GUTA new_node_value"
    );
    Ok(())
}

pub fn decode_proposal_state_updates<Hash: Q256BitHash>(
    state_updates: &[u8],
) -> anyhow::Result<PsyPreparedRealmBlockStateUpdates<Hash>> {
    PsyPreparedRealmBlockStateUpdates::<Hash>::psy_ser_from_slice(state_updates)
}



/// Build the canonical unbound 410-byte finalize output for an ordinary GUTA submit.
pub fn build_bound_finalize_output<N>(
    chain_id: u32,
    realm_id: u32,
    proposer_sub_id: u16,
    validator_user_id: u64,
    validator_tree_root: N::QHash,
    submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
) -> RealmFinalizeGUTAPublicOutput<N::F, N::QHash>
where
    N: QNetworkTypesConfig,
{
    let chain_domain =
        realm_finalize_guta_chain_domain::<N::F, N::QHash, N::HasherBase>(chain_id);
    let checkpoint_id = N::F::from_u64_value(0);
    let realm_id_felt = N::F::from_u64_value(realm_id as u64);
    let root_guta_header_hash = submission.header.header.qfhash::<N::HasherBase>();
    let action = RealmFinalizeGUTAAction {
        chain_domain,
        checkpoint_id,
        realm_id: realm_id_felt,
        checkpoint_tree_root: submission.header.header.checkpoint_tree_root,
        validator_tree_root,
        root_guta_header_hash,
    };
    RealmFinalizeGUTAPublicOutput {
        chain_domain,
        checkpoint_id,
        realm_id: realm_id_felt,
        realm_sub_id: proposer_sub_id,
        checkpoint_tree_root: submission.header.header.checkpoint_tree_root,
        validator_tree_root,
        validator_user_id: N::F::from_u64_value(validator_user_id),
        root_guta_header_hash,
        root_guta_reward_tag: submission.header.new_tag_tree_node_value,
        action_hash: action.action_hash::<N::HasherBase>(),
        final_guta_header: submission.header.header,
    }
}

/// Verify a decoded Proposal against the ordinary submitted GUTA header/proof.
pub fn verify_proposal_submission<N>(
    proposal: &Proposal,
    body: &[u8],
    submission: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
    validator_user_id: u64,
    proof_verifier: &N::ZKVerifier,
) -> anyhow::Result<DecodedProposalBody>
where
    N: QNetworkTypesConfig,
{
    anyhow::ensure!(
        proposal.compute_proposal_id() == proposal.proposal_id,
        "proposal_id does not match canonical Proposal fields"
    );
    require_nonzero_validator_tree_root(&proposal.validator_tree_root)
        .map_err(|error| anyhow::anyhow!("{error}"))?;

    let decoded = decode_proposal_body(proposal, body)
        .map_err(|error| anyhow::anyhow!("invalid Proposal body: {error}"))?;
    let output: RealmFinalizeGUTAPublicOutput<N::F, N::QHash> =
        protocol_decode_finalize_output(&decoded.output)
            .map_err(|error| anyhow::anyhow!("invalid Realm finalize output: {error}"))?;
    let expected_output = build_bound_finalize_output::<N>(
        proposal.chain_id,
        proposal.realm_id,
        proposal.proposer_sub_id,
        validator_user_id,
        N::QHash::from_owned_32bytes(proposal.validator_tree_root),
        submission,
    );
    anyhow::ensure!(
        output == expected_output,
        "Realm finalize output does not match the canonical submitted GUTA binding"
    );
    anyhow::ensure!(
        output.validator_tree_root.into_owned_32bytes() == proposal.validator_tree_root,
        "Realm finalize output validator_tree_root mismatch"
    );
    let state_updates = decode_proposal_state_updates::<N::QHash>(&decoded.state_updates)?;
    verify_state_updates_match_guta_output(&state_updates, &output)?;
    let expected_public_inputs_hash = submission.qfhash::<N::HasherBase>();
    proof_verifier.verify_zk_proof_from_slice_check_public_inputs_hash(
        submission.job_type_u32,
        &decoded.proof,
        expected_public_inputs_hash,
    )?;
    Ok(decoded)
}

/// Sign a [`Vote`] for `proposal` with the local validator's BLS secret key.
///
/// `signer_sub_id` is the signer's own validator leaf sub-id and
/// must be in `0..=255` (it is the local node's committed identity, not a
/// value read from the network). The signature is over the canonical
/// `vote_message` derived from the proposal's `chain_id`, `realm_id`,
/// `validator_tree_root`, and `proposal_id`, which ties the vote to a single
/// network, Realm, and validator-tree identity and prevents replay across them.
pub fn sign_vote(secret: &BlsSecretKey, signer_sub_id: u16, proposal: &Proposal) -> Vote {
    let message = vote_message(
        proposal.chain_id,
        proposal.realm_id,
        &proposal.validator_tree_root,
        &proposal.proposal_id,
    );
    let signature = secret.sign_vote(&message);
    Vote {
        proposal_id: proposal.proposal_id,
        signer_sub_id,
        signature,
    }
}

/// Aggregate signed votes for `proposal` into a [`Certificate`].
///
/// Each entry is `(signer_sub_id, signature)`. Signer sub-ids must be unique
/// and in `0..=255`; a duplicate or out-of-range sub-id is rejected. The
/// returned certificate carries the proposal's identity and hash fields and a
/// 32-byte `signer_bitmap` whose bit `s` is set exactly when a vote for sub-id
/// `s` was aggregated. Threshold checking is performed by
/// [`validate_certificate`] (and by the coordinator); this helper only
/// aggregates what the caller collected.
pub fn form_certificate(
    proposal: &Proposal,
    votes: &[(u16, BlsSignature)],
) -> ProtocolResult<Certificate> {
    if votes.is_empty() {
        return Err(ProtocolError::EmptyAggregate);
    }
    let mut signer_bitmap = [0u8; 32];
    let mut signatures: Vec<BlsSignature> = Vec::with_capacity(votes.len());
    for (sub_id, signature) in votes {
        if *sub_id > 255 {
            return Err(ProtocolError::Message("signer sub_id exceeds 255"));
        }
        if bitmap_get(&signer_bitmap, *sub_id) {
            return Err(ProtocolError::Message("duplicate signer sub_id"));
        }
        bitmap_set(&mut signer_bitmap, *sub_id);
        signatures.push(*signature);
    }
    let aggregated_signature = aggregate_signatures(&signatures)?;
    Ok(Certificate {
        chain_id: proposal.chain_id,
        realm_id: proposal.realm_id,
        validator_tree_root: proposal.validator_tree_root,
        proposal_id: proposal.proposal_id,
        signer_bitmap,
        aggregated_signature,
    })
}

/// Validate a [`Certificate`] against a [`Proposal`] and the Realm validators.
///
/// `validator_sub_ids` is the ascending list of the Realm's validator leaf
/// sub-ids at the proof-base checkpoint, with
/// `n = validator_sub_ids.len()` satisfying
/// [`MIN_VALIDATORS_PER_REALM`] `<= n <=` [`MAX_VALIDATORS_PER_REALM`].
/// `leaf_bls_keys` must contain the authenticated BLS public key for every
/// sub-id in `validator_sub_ids`; the caller is responsible for reconstructing
/// each `ValidatorLeaf` against the checkpoint `validator_tree_root` so that
/// only keys anchored to the committed tree are supplied here.
///
/// Validation enforces, in order:
///
/// 1. The certificate's `chain_id`, `realm_id`, `validator_tree_root`, and
///    `proposal_id` tie it to `proposal`, so the reconstructed `vote_message`
///    is byte-identical for every signer.
/// 2. `popcount(signer_bitmap) >= ceil(n/2)` (the replication threshold, not a
///    BFT quorum).
/// 3. Every set bit names a validator leaf and has a supplied BLS key (no bit
///    names an empty or mismatching leaf). This also enforces `popcount <= n`,
///    since at most `n` distinct validator sub-ids can be set.
/// 4. `FastAggregateVerify` succeeds over the single `vote_message` using the
///    authenticated keys of the signers, in ascending sub-id order.
pub fn validate_certificate(
    proposal: &Proposal,
    certificate: &Certificate,
    validator_sub_ids: &[u16],
    leaf_bls_keys: &[(u16, BlsPublicKey)],
) -> ProtocolResult<()> {
    let n = validator_sub_ids.len();
    if !(MIN_VALIDATORS_PER_REALM..=MAX_VALIDATORS_PER_REALM).contains(&n) {
        return Err(ProtocolError::Message("validator sub-id count out of range"));
    }
    for &sub_id in validator_sub_ids {
        if sub_id > 255 {
            return Err(ProtocolError::Message("validator sub_id exceeds 255"));
        }
    }

    if certificate.chain_id != proposal.chain_id
        || certificate.realm_id != proposal.realm_id
        || certificate.validator_tree_root != proposal.validator_tree_root
        || certificate.proposal_id != proposal.proposal_id
    {
        return Err(ProtocolError::Message("certificate does not match proposal"));
    }
    require_nonzero_validator_tree_root(&proposal.validator_tree_root)?;
    require_nonzero_validator_tree_root(&certificate.validator_tree_root)?;


    let threshold = replication_threshold(n);
    let popcount = certificate
        .signer_bitmap
        .iter()
        .map(|byte| byte.count_ones() as usize)
        .sum::<usize>();
    if popcount < threshold {
        return Err(ProtocolError::Message("certificate below replication threshold"));
    }

    // Every set bit must name a validator leaf with a supplied,
    // authenticated BLS key. Collecting them in ascending sub-id order yields a
    // deterministic signer set for FastAggregateVerify.
    let mut keys: Vec<BlsPublicKey> = Vec::with_capacity(popcount);
    for sub_id in 0u16..256 {
        if !bitmap_get(&certificate.signer_bitmap, sub_id) {
            continue;
        }
        if !validator_sub_ids.contains(&sub_id) {
            return Err(ProtocolError::Message("signer bit names empty validator leaf"));
        }
        let key = leaf_bls_keys
            .iter()
            .find(|(s, _)| *s == sub_id)
            .map(|(_, key)| *key)
            .ok_or_else(|| ProtocolError::Message("missing BLS key for validator sub_id"))?;
        keys.push(key);
    }

    let message = vote_message(
        certificate.chain_id,
        certificate.realm_id,
        &certificate.validator_tree_root,
        &certificate.proposal_id,
    );
    certificate
        .aggregated_signature
        .fast_aggregate_verify(&message, &keys)?;
    Ok(())
}

/// Reject a GUTA Proposal whose `validator_tree_root` is all zeros: the zero
/// root is not a committed validator tree and must never be admitted as a
/// proof-base root.
pub fn require_nonzero_validator_tree_root(root: &[u8; 32]) -> Result<(), ProtocolError> {
    if root.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::Message("validator_tree_root is zero"));
    }
    Ok(())
}

/// True when the Proposal's `validator_tree_root` matches the validator tree
/// root authenticated at the proof-base checkpoint.
pub fn validator_tree_root_matches_proof_base(
    proposal_root: &[u8; 32],
    proof_base_root: &[u8; 32],
) -> bool {
    proposal_root == proof_base_root
}

/// Inclusion lag of a GUTA Proposal proof-base checkpoint against the
/// coordinator's inclusion checkpoint: the proof base must strictly precede
/// inclusion (`lag >= 1`) and must not be older than
/// [`MAX_INCLUSION_LAG_CHECKPOINTS`]. Returns `Some(lag)` when admissible.
pub fn inclusion_lag_within_limit(
    base_checkpoint_id: u64,
    inclusion_checkpoint_id: u64,
) -> Option<u64> {
    inclusion_checkpoint_id
        .checked_sub(base_checkpoint_id)
        .filter(|lag| (1..=MAX_INCLUSION_LAG_CHECKPOINTS).contains(lag))
}

/// True when the certificate's signer set includes the proposal's proposer.
pub fn certificate_includes_proposer(certificate: &Certificate, proposer_sub_id: u16) -> bool {
    certificate.signer_sub_ids().contains(&proposer_sub_id)
}

/// True when the collected votes satisfy the proposal's replication wait:
/// at least `replication_threshold(n)` distinct signers and — for realms with
/// two or more validators — at least one signer other than the proposer (a
/// proposal must not be certified by the proposer alone).
pub fn votes_meet_wait(n: usize, proposer_sub_id: u16, signer_sub_ids: &[u16]) -> bool {
    let unique: HashSet<u16> = signer_sub_ids.iter().copied().collect();
    if unique.len() < replication_threshold(n) {
        return false;
    }
    if n >= 2 && !unique.iter().any(|sub_id| *sub_id != proposer_sub_id) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::p2p::{encode_proposal_body, proposal_from_parts};

    /// Build a `Proposal` whose body/hashes are consistent with the given
    /// sections, reusing the canonical `psy_data` encoders.
    #[allow(clippy::too_many_arguments)]
    fn proposal_with_body(
        chain_id: u32,
        realm_id: u32,
        base_checkpoint_id: u64,
        proposer_sub_id: u16,
        validator_tree_root: [u8; 32],
        output: &[u8],
        proof: &[u8],
        state_updates: &[u8],
    ) -> (Proposal, Vec<u8>) {
        let body = encode_proposal_body(output, proof, state_updates).expect("encode body");
        let public_output_hash = sha256(output);
        let finalizer_proof_hash = sha256(proof);
        let backup_hash = sha256(state_updates);
        let body_hash = sha256(&body);
        let proposal = proposal_from_parts(
            chain_id,
            realm_id,
            base_checkpoint_id,
            proposer_sub_id,
            validator_tree_root,
            public_output_hash,
            finalizer_proof_hash,
            backup_hash,
            body_hash,
        );
        (proposal, body)
    }

    fn validator_key(seed: u8) -> BlsSecretKey {
        let mut ikm = [0u8; 32];
        ikm[0] = seed;
        BlsSecretKey::key_gen(&ikm).expect("key_gen")
    }

    fn sample_body_sections() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let output = vec![0u8; MAX_FINALIZER_OUTPUT_BYTES];
        let proof = vec![0xABu8; 128];
        let state_updates = vec![0xCDu8; 256];
        (output, proof, state_updates)
    }


    #[test]
    fn decode_proposal_body_roundtrips_canonical_body() {
        let (output, proof, state_updates) = sample_body_sections();
        let (proposal, body) =
            proposal_with_body(7, 3, 99, 1, [0u8; 32], &output, &proof, &state_updates);
        let decoded = decode_proposal_body(&proposal, &body).expect("decode");
        assert_eq!(decoded.output, output);
        assert_eq!(decoded.proof, proof);
        assert_eq!(decoded.state_updates, state_updates);
    }

    #[test]
    fn decode_proposal_body_rejects_trailing_bytes() {
        let (output, proof, state_updates) = sample_body_sections();
        let (mut proposal, mut body) =
            proposal_with_body(7, 3, 99, 1, [0u8; 32], &output, &proof, &state_updates);
        // Recompute body_hash over the tampered body so the only failure is
        // the trailing-bytes check, not the hash check.
        body.push(0);
        proposal.body_hash = sha256(&body);
        let err = decode_proposal_body(&proposal, &body).unwrap_err();
        assert_eq!(err, ProtocolError::TrailingBytes { remaining: 1 });
    }

    #[test]
    fn decode_proposal_body_rejects_wrong_output_length() {
        // Hand-roll a body whose output length prefix is not exactly 410.
        let (output, proof, state_updates) = sample_body_sections();
        let (proposal, _) =
            proposal_with_body(7, 3, 99, 1, [0u8; 32], &output, &proof, &state_updates);
        let mut body = Vec::new();
        body.extend_from_slice(&409u32.to_le_bytes());
        body.extend_from_slice(&output[..409]);
        body.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        body.extend_from_slice(&proof);
        body.extend_from_slice(&(state_updates.len() as u32).to_le_bytes());
        body.extend_from_slice(&state_updates);
        let err = decode_proposal_body(&proposal, &body).unwrap_err();
        assert!(matches!(err, ProtocolError::InvalidLength { .. }));
    }

    #[test]
    fn decode_proposal_body_rejects_hash_mismatch() {
        let (output, proof, state_updates) = sample_body_sections();
        let (mut proposal, body) =
            proposal_with_body(7, 3, 99, 1, [0u8; 32], &output, &proof, &state_updates);
        proposal.body_hash = [0xFF; 32];
        let err = decode_proposal_body(&proposal, &body).unwrap_err();
        assert_eq!(err, ProtocolError::Message("body_hash mismatch"));
    }

    fn build_validators(sub_ids: &[u16]) -> (Vec<BlsSecretKey>, Vec<(u16, BlsPublicKey)>) {
        let mut secrets = Vec::new();
        let mut keys = Vec::new();
        for (i, &s) in sub_ids.iter().enumerate() {
            let secret = validator_key((i + 1) as u8);
            keys.push((s, secret.public_key()));
            secrets.push(secret);
        }
        (secrets, keys)
    }

    fn signed_votes(
        secrets: &[BlsSecretKey],
        sub_ids: &[u16],
        proposal: &Proposal,
    ) -> Vec<(u16, BlsSignature)> {
        sub_ids
            .iter()
            .zip(secrets.iter())
            .map(|(&s, sk)| {
                let vote = sign_vote(sk, s, proposal);
                (s, vote.signature)
            })
            .collect()
    }

    #[test]
    fn certificate_threshold_is_ceil_half_n() {
        // n = 3 => ceil(3/2) = 2.
        let validator_sub_ids: [u16; 3] = [1, 2, 3];
        let (secrets, keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        // Two signers meets the threshold.
        let votes = signed_votes(&secrets[..2], &validator_sub_ids[..2], &proposal);
        let cert = form_certificate(&proposal, &votes).expect("form");
        validate_certificate(&proposal, &cert, &validator_sub_ids, &keys).expect("valid");

        // One signer is below ceil(3/2) = 2.
        let votes1 = signed_votes(&secrets[..1], &validator_sub_ids[..1], &proposal);
        let cert1 = form_certificate(&proposal, &votes1).expect("form");
        let err = validate_certificate(&proposal, &cert1, &validator_sub_ids, &keys).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::Message("certificate below replication threshold")
        );
    }

    #[test]
    fn certificate_rejects_signer_outside_validators() {
        let validator_sub_ids: [u16; 2] = [1, 2];
        let (secrets, keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        // Forge a vote from a sub-id that is not one of the validators and
        // aggregate it with the two honest votes.
        let outsider = validator_key(9);
        let outsider_vote = sign_vote(&outsider, 5, &proposal);
        let votes = signed_votes(&secrets, &validator_sub_ids, &proposal);
        let mut all_votes = votes.clone();
        all_votes.push((5, outsider_vote.signature));

        let cert = form_certificate(&proposal, &all_votes).expect("form");
        // Bit 5 names a leaf outside the validators; the per-bit validator-leaf
        // check must catch it.
        let err = validate_certificate(&proposal, &cert, &validator_sub_ids, &keys).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::Message("signer bit names empty validator leaf")
        );
    }

    #[test]
    fn certificate_rejects_mismatched_aggregate() {
        let validator_sub_ids: [u16; 3] = [1, 2, 3];
        let (secrets, keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        // Build a structurally valid aggregate (real G2 point) that signs the
        // same vote_message with three OUTSIDER keys, so it is a legitimate
        // aggregate but does not verify against the validators' keys.
        let outsiders = [
            validator_key(31),
            validator_key(32),
            validator_key(33),
        ];
        let outsider_sigs: Vec<BlsSignature> = outsiders
            .iter()
            .map(|sk| sign_vote(sk, 1, &proposal).signature)
            .collect();
        let mismatched_agg = aggregate_signatures(&outsider_sigs).expect("aggregate");

        let real_votes = signed_votes(&secrets, &validator_sub_ids, &proposal);
        let mut cert = form_certificate(&proposal, &real_votes).expect("form");
        cert.aggregated_signature = mismatched_agg;

        let err = validate_certificate(&proposal, &cert, &validator_sub_ids, &keys).unwrap_err();
        assert_eq!(err, ProtocolError::BlsVerifyFailed);
    }

    #[test]
    fn certificate_rejects_mismatched_proposal() {
        let validator_sub_ids: [u16; 3] = [1, 2, 3];
        let (secrets, keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        let votes = signed_votes(&secrets, &validator_sub_ids, &proposal);
        let cert = form_certificate(&proposal, &votes).expect("form");

        // A different proposal with the same body but a different proof-base checkpoint.
        let (other, _) = proposal_with_body(7, 3, 200, 1, [1u8; 32], &output, &proof, &backup);
        let err = validate_certificate(&other, &cert, &validator_sub_ids, &keys).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::Message("certificate does not match proposal")
        );
    }

    #[test]
    fn form_certificate_rejects_duplicate_and_out_of_range_sub_ids() {
        let validator_sub_ids: [u16; 2] = [1, 2];
        let (secrets, _keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        let v1 = sign_vote(&secrets[0], 1, &proposal);
        let dup = sign_vote(&secrets[1], 1, &proposal);
        let err =
            form_certificate(&proposal, &[(1, v1.signature), (1, dup.signature)]).unwrap_err();
        assert_eq!(err, ProtocolError::Message("duplicate signer sub_id"));

        let bad = sign_vote(&secrets[0], 300, &proposal);
        let err = form_certificate(&proposal, &[(300, bad.signature)]).unwrap_err();
        assert_eq!(err, ProtocolError::Message("signer sub_id exceeds 255"));
    }

    #[test]
    fn require_nonzero_validator_tree_root_rejects_zero_root() {
        let err = require_nonzero_validator_tree_root(&[0u8; 32]).unwrap_err();
        assert_eq!(err, ProtocolError::Message("validator_tree_root is zero"));

        let mut one_byte = [0u8; 32];
        one_byte[31] = 0x01;
        assert!(require_nonzero_validator_tree_root(&one_byte).is_ok());
        assert!(require_nonzero_validator_tree_root(&[1u8; 32]).is_ok());
    }

    #[test]
    fn validator_tree_root_matches_proof_base_checks_equality() {
        assert!(validator_tree_root_matches_proof_base(&[7u8; 32], &[7u8; 32]));
        assert!(!validator_tree_root_matches_proof_base(&[7u8; 32], &[8u8; 32]));
        // The all-zero root never matches a real committed proof-base root.
        assert!(!validator_tree_root_matches_proof_base(&[0u8; 32], &[7u8; 32]));
    }

    #[test]
    fn inclusion_lag_within_limit_accepts_one_to_max() {
        assert_eq!(inclusion_lag_within_limit(10, 11), Some(1));
        assert_eq!(inclusion_lag_within_limit(10, 26), Some(16));
    }

    #[test]
    fn inclusion_lag_within_limit_rejects_zero_lag() {
        // The proof base must strictly precede the inclusion checkpoint.
        assert_eq!(inclusion_lag_within_limit(10, 10), None);
    }

    #[test]
    fn inclusion_lag_within_limit_rejects_lag_beyond_max_and_underflow() {
        // lag 17 > MAX_INCLUSION_LAG_CHECKPOINTS (16).
        assert_eq!(inclusion_lag_within_limit(10, 27), None);
        // A proof base after the inclusion checkpoint cannot compute a lag.
        assert_eq!(inclusion_lag_within_limit(20, 10), None);
    }

    #[test]
    fn certificate_includes_proposer_requires_proposer_signature() {
        let validator_sub_ids: [u16; 3] = [1, 2, 3];
        let (secrets, _keys) = build_validators(&validator_sub_ids);
        let (output, proof, backup) = sample_body_sections();
        let (proposal, _body) =
            proposal_with_body(7, 3, 99, 1, [1u8; 32], &output, &proof, &backup);

        // Votes from sub-ids 2 and 3 only: the proposer (sub-id 1) is absent.
        let votes = signed_votes(&secrets[1..], &validator_sub_ids[1..], &proposal);
        let cert = form_certificate(&proposal, &votes).expect("form");
        assert!(!certificate_includes_proposer(&cert, 1));
        assert!(certificate_includes_proposer(&cert, 2));

        // All validators including the proposer.
        let all_votes = signed_votes(&secrets, &validator_sub_ids, &proposal);
        let full = form_certificate(&proposal, &all_votes).expect("form");
        assert!(certificate_includes_proposer(&full, 1));
    }

    #[test]
    fn votes_meet_wait_requires_non_proposer_signer_when_n_is_two() {
        // n = 2: the replication threshold is 1, but the proposer alone must
        // not certify its own proposal.
        assert!(!votes_meet_wait(2, 1, &[1]));
        assert!(!votes_meet_wait(2, 1, &[1, 1]));
        assert!(votes_meet_wait(2, 1, &[1, 2]));
    }

    #[test]
    fn votes_meet_wait_proposer_only_is_enough_when_n_is_one() {
        assert!(votes_meet_wait(1, 1, &[1]));
    }

    #[test]
    fn votes_meet_wait_enforces_replication_threshold() {
        // n = 3: ceil(3/2) = 2 distinct signers required.
        assert!(!votes_meet_wait(3, 1, &[1]));
        assert!(!votes_meet_wait(3, 1, &[1, 1])); // duplicates do not count twice
        assert!(votes_meet_wait(3, 1, &[1, 2]));
        assert!(votes_meet_wait(3, 1, &[2, 3]));
    }

    #[test]
    fn votes_meet_wait_duplicate_signer_does_not_count_twice() {
        // Three reported votes from two distinct signers still satisfy the
        // n = 3 wait (threshold 2) with a non-proposer signer.
        assert!(votes_meet_wait(3, 1, &[1, 1, 2]));
        // n = 2 with only duplicated proposer votes has no non-proposer signer.
        assert!(!votes_meet_wait(2, 1, &[1, 1]));
    }
}