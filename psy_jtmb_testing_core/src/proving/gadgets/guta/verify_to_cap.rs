use parth_core::{
    crypto::hash::merkle_proof::compute_root_merkle_proof_generic,
    felt::{FromPrimitiveValuesFelt, ToU64Value},
};
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

use crate::utils::jtmb_standard_circuit::JTMBCircuitConfig;

pub fn verify_guta_to_cap<C: JTMBCircuitConfig>(
    child_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    top_line_siblings: &[C::Hash],
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {
    let height = top_line_siblings.len();
    
    // 1. Reconstruct top line transition
    let index_u64 = child_header.state_transition.node_index.to_u64_value();
    
    let computed_old_root = compute_root_merkle_proof_generic::<C::Hash, C::Hasher>(
        child_header.state_transition.old_node_value,
        index_u64,
        top_line_siblings,
    );
    let computed_new_root = compute_root_merkle_proof_generic::<C::Hash, C::Hasher>(
        child_header.state_transition.new_node_value,
        index_u64,
        top_line_siblings,
    );

    // 2. Compute new index and level
    let new_node_index = C::F::from_u64_value(index_u64 >> height);
    
    let current_level = child_header.state_transition.node_level.to_u64_value();
    if current_level < height as u64 {
        anyhow::bail!("node level underflow in to-cap");
    }
    let new_level = current_level - height as u64;

    // 3. Increment Proof Count
    let one = C::F::from_u64_value(1);

    Ok(GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: child_header.guta_circuit_whitelist,
        checkpoint_tree_root: child_header.checkpoint_tree_root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: computed_old_root,
            new_node_value: computed_new_root,
            node_index: new_node_index,
            node_level: C::F::from_u64_value(new_level),
        },
        stats: child_header.stats.clone(),
        total_aggregation_proofs_generated: child_header.total_aggregation_proofs_generated + one,
    })
}