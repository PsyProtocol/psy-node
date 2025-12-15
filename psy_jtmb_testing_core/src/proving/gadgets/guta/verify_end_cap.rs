use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::{MerkleHasher, QFieldHashable, ZeroableHash}},
    felt::FromPrimitiveValuesFelt,
};
use psy_data::{
    guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition},
    v1::qdata::user_end_cap_result::PUPSEndCapResultCompact,
};

use crate::{
    proof::{PsyTestJTMBProof, PsyTestJTMBProofVerifierData},
    proving::utils::connect::{jtmb_connect, jtmb_connect_ref},
    utils::jtmb_standard_circuit::JTMBCircuitConfig,
};

/// Replicates VerifyEndCapProofGadget constraints
pub fn verify_end_cap_proof<C: JTMBCircuitConfig>(
    end_cap_result: &PUPSEndCapResultCompact<C::F, C::Hash>,
    guta_stats: &GUTAStats<C::F>,
    checkpoint_historical_merkle_proof: &MerkleProofCore<C::Hash>,
    
    proof: &PsyTestJTMBProof<C::Hash>,
    verifier_data: &PsyTestJTMBProofVerifierData,

    checkpoint_tree_height: usize,
    global_user_tree_height: u8,
    known_end_cap_fingerprint: C::Hash,
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {
    // 1. Verify Checkpoint Historical Proof Structure
    jtmb_connect(
        checkpoint_historical_merkle_proof.siblings.len(),
        checkpoint_tree_height,
        "checkpoint historical merkle proof height mismatch",
    )?;

    // 2. Compute End Cap Public Inputs (Hash(StateTransition, Stats))
    let state_transition_pi_hash = end_cap_result.qfhash_with_guta_height::<C::Hasher>(global_user_tree_height);
    let guta_stats_pi_hash = guta_stats.qfhash::<C::Hasher>();
    let expected_public_inputs_hash = C::Hasher::two_to_one(&state_transition_pi_hash, &guta_stats_pi_hash);

    // 3. Constraint: Proof Public Inputs must match computed inputs
    jtmb_connect_ref(
        &expected_public_inputs_hash,
        &proof.public_inputs_hash,
        "end cap proof public inputs mismatch",
    )?;

    // 4. Constraint: Verify Proof Signature
    verifier_data.verify_proof::<C::Hasher, C::Hash, C::F>(proof)?;

    // 5. Constraint: Verify Fingerprint matches known End Cap fingerprint
    let calculated_fingerprint = verifier_data.get_fingerprint::<C::Hash, C::Hasher, C::F>();
    jtmb_connect_ref(&calculated_fingerprint, &known_end_cap_fingerprint, "end cap circuit fingerprint mismatch")?;

    if !checkpoint_historical_merkle_proof.verify::<C::Hasher>() {
        anyhow::bail!("checkpoint historical merkle proof verification failed");
    }
    // 6. Constraint: The User's claimed Checkpoint Root must exist in history
    let (computed_historical_root, computed_current_root) =
        parth_core::crypto::hash::merkle_proof::compute_historical_and_current_merkle_roots_core_gt::<C::Hash, C::Hasher>(
            checkpoint_historical_merkle_proof,
        );

    // Constraint: The proof provided must be valid for the Current Checkpoint Root
    jtmb_connect_ref(
        &computed_current_root,
        &checkpoint_historical_merkle_proof.root,
        "checkpoint historical proof invalid (current root mismatch)",
    )?;

    // Constraint: The computed historical root must match what the user claims they
    // synced to
    jtmb_connect_ref(
        &computed_historical_root,
        &end_cap_result.checkpoint_tree_root_hash,
        "user claimed checkpoint root is not a valid historical root",
    )?;

    // 7. Construct Resulting GUTA Header
    let state_transition = SubTreeNodeStateTransition {
        old_node_value: end_cap_result.start_user_leaf_hash,
        new_node_value: end_cap_result.end_user_leaf_hash,
        node_index: end_cap_result.user_id,
        node_level: C::F::from_u8_value(global_user_tree_height),
    };
    let guta_header = GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: C::Hash::get_zero_value(), // Initialized to zero, updated by parent circuit
        checkpoint_tree_root: checkpoint_historical_merkle_proof.root, // The current global checkpoint root
        state_transition,
        stats: guta_stats.clone(),
        total_aggregation_proofs_generated: C::F::from_u64_value(0),
    };
    println!("GUTA Header constructed: {:#?}", guta_header);

    Ok(guta_header)
}