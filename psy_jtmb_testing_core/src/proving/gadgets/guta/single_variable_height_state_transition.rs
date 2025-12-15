use parth_core::{
    crypto::hash::merkle_proof::DeltaMerkleProofCore,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
};
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

use crate::{
    proving::utils::connect::{jtmb_connect, jtmb_connect_ref},
    utils::jtmb_standard_circuit::JTMBCircuitConfig,
};
/// Replicates SingleVariableHeightStateTransitionGadget constraints
pub fn verify_single_variable_height_state_transition<C: JTMBCircuitConfig>(
    child_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    child_delta_proof: &DeltaMerkleProofCore<C::Hash>,
    max_merkle_proof_height: usize,
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {
    let proof_height = child_delta_proof.siblings.len();
    if proof_height > max_merkle_proof_height {
        anyhow::bail!("proof height exceeds max");
    }

    if !child_delta_proof.verify::<C::Hasher>() {
        anyhow::bail!("child delta proof invalid");
    }

    // Connect Child Proof to Header Values
    jtmb_connect_ref(
        &child_delta_proof.old_value,
        &child_header.state_transition.old_node_value,
        "old value mismatch",
    )?;
    jtmb_connect_ref(
        &child_delta_proof.new_value,
        &child_header.state_transition.new_node_value,
        "new value mismatch",
    )?;

    // Connect indices
    jtmb_connect(
        C::F::from_u64_value(child_delta_proof.index),
        child_header.state_transition.node_index,
        "index mismatch",
    )?;

    // Compute Parent Info
    let parent_index = child_delta_proof.index >> proof_height;

    let child_level = child_header.state_transition.node_level.to_u64_value();
    if child_level < proof_height as u64 {
        anyhow::bail!("level underflow");
    }
    let parent_level = child_level - proof_height as u64;

    let one = C::F::from_u64_value(1);

    Ok(GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: child_header.guta_circuit_whitelist,
        checkpoint_tree_root: child_header.checkpoint_tree_root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: child_delta_proof.old_root,
            new_node_value: child_delta_proof.new_root,
            node_index: C::F::from_u64_value(parent_index),
            node_level: C::F::from_u64_value(parent_level),
        },
        stats: child_header.stats.clone(),
        total_aggregation_proofs_generated: child_header.total_aggregation_proofs_generated + one,
    })
}
