use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
};
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

use crate::{
    proving::utils::connect::{jtmb_connect, jtmb_connect_ref},
    utils::jtmb_standard_circuit::JTMBCircuitConfig,
};

/// Replicates LeftLinearRightVariableHeightStateTransitionGadget constraints
pub fn verify_left_linear_right_variable_state_transition<C: JTMBCircuitConfig>(
    a_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    b_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    right_delta_proof: &DeltaMerkleProofCore<C::Hash>,
    max_merkle_proof_height: usize,
    tree_height: usize,
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {
    // 1. Context Matching
    jtmb_connect_ref(&a_header.checkpoint_tree_root, &b_header.checkpoint_tree_root, "checkpoint root mismatch")?;
    jtmb_connect_ref(&a_header.guta_circuit_whitelist, &b_header.guta_circuit_whitelist, "whitelist mismatch")?;

    // 2. Validate Right Delta Proof
    let proof_height = right_delta_proof.siblings.len();
    if proof_height > max_merkle_proof_height && proof_height > tree_height {
        anyhow::bail!("right delta proof height exceeds max");
    }
    if !right_delta_proof.verify::<C::Hasher>() {
        anyhow::bail!("right delta proof invalid");
    }

    // 3. Connect Right Proof to B Header
    jtmb_connect_ref(
        &right_delta_proof.old_value,
        &b_header.state_transition.old_node_value,
        "b old value mismatch",
    )?;
    jtmb_connect_ref(
        &right_delta_proof.new_value,
        &b_header.state_transition.new_node_value,
        "b new value mismatch",
    )?;
    jtmb_connect(
        C::F::from_u64_value(right_delta_proof.index),
        b_header.state_transition.node_index,
        "b index mismatch",
    )?;

    // 4. Calculate Right Parent Info & Connect to A
    let right_parent_index = right_delta_proof.index >> proof_height;

    // A is Linear, so A is the Left Sibling. B is Right Sibling.
    // A.index must equal Parent(B.index).
    jtmb_connect(
        C::F::from_u64_value(right_parent_index),
        a_header.state_transition.node_index,
        "a index mismatch",
    )?;

    // A.level must equal Parent(B.level)
    let b_level = b_header.state_transition.node_level.to_u64_value();
    if b_level < proof_height as u64 {
        anyhow::bail!("b level underflow");
    }
    let parent_level = b_level - proof_height as u64;
    jtmb_connect(
        C::F::from_u64_value(parent_level),
        a_header.state_transition.node_level,
        "a level mismatch",
    )?;

    // 5. Connect Chain: A.new_value == RightProof.old_root
    jtmb_connect_ref(
        &a_header.state_transition.new_node_value,
        &right_delta_proof.old_root,
        "chain continuity broken",
    )?;

    // 6. Compute New Header
    let mut new_stats = a_header.stats.clone();
    new_stats.add_from_mut(&b_header.stats);
    let one = C::F::from_u64_value(1);

    Ok(GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: a_header.guta_circuit_whitelist,
        checkpoint_tree_root: a_header.checkpoint_tree_root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: a_header.state_transition.old_node_value,
            new_node_value: right_delta_proof.new_root,
            node_index: a_header.state_transition.node_index,
            node_level: a_header.state_transition.node_level,
        },
        stats: new_stats,
        total_aggregation_proofs_generated: a_header.total_aggregation_proofs_generated + b_header.total_aggregation_proofs_generated + one,
    })
}
