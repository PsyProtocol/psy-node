use parth_core::felt::FromPrimitiveValuesFelt;
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

use crate::{proving::utils::connect::{jtmb_connect, jtmb_connect_ref}, utils::jtmb_standard_circuit::JTMBCircuitConfig};

pub fn verify_guta_linear_transition<C: JTMBCircuitConfig>(
    a_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
    b_header: &GlobalUserTreeAggregatorHeader<C::F, C::Hash>,
) -> anyhow::Result<GlobalUserTreeAggregatorHeader<C::F, C::Hash>> {
    
    // 1. Context matching
    jtmb_connect_ref(&a_header.checkpoint_tree_root, &b_header.checkpoint_tree_root, "checkpoint root mismatch")?;
    jtmb_connect_ref(&a_header.guta_circuit_whitelist, &b_header.guta_circuit_whitelist, "whitelist mismatch")?;
    
    // 2. Linear constraints (Same node, back-to-back transition)
    jtmb_connect(a_header.state_transition.node_level, b_header.state_transition.node_level, "node level mismatch")?;
    jtmb_connect(a_header.state_transition.node_index, b_header.state_transition.node_index, "node index mismatch")?;
    jtmb_connect_ref(&a_header.state_transition.new_node_value, &b_header.state_transition.old_node_value, "chain continuity mismatch")?;

    // 3. Construct new header
    let mut new_stats = a_header.stats.clone();
    new_stats.add_from_mut(&b_header.stats);
    let one = C::F::from_u64_value(1);

    Ok(GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: a_header.guta_circuit_whitelist,
        checkpoint_tree_root: a_header.checkpoint_tree_root,
        state_transition: SubTreeNodeStateTransition {
            old_node_value: a_header.state_transition.old_node_value,
            new_node_value: b_header.state_transition.new_node_value,
            node_index: a_header.state_transition.node_index,
            node_level: a_header.state_transition.node_level,
        },
        stats: new_stats,
        total_aggregation_proofs_generated: a_header.total_aggregation_proofs_generated + b_header.total_aggregation_proofs_generated + one,
    })
}