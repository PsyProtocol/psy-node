use parth_core::pgoldilocks::QHashOut;
use plonky2::hash::hash_types::{HashOut, RichField};
use psy_data::guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition};

#[inline]
pub const fn convert_q_sub_tree_node_state_transition_to_hashout<F: RichField>(
    transition: SubTreeNodeStateTransition<F, QHashOut<F>>,
) -> SubTreeNodeStateTransition<F, HashOut<F>> {
    SubTreeNodeStateTransition {
        old_node_value: transition.old_node_value.0,
        new_node_value: transition.new_node_value.0,
        node_index: transition.node_index,
        node_level: transition.node_level,
    }
}

#[inline]
pub const fn convert_q_guta_header_to_hashout<F: RichField>(
    header: GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
) -> GlobalUserTreeAggregatorHeader<F, HashOut<F>> {
    GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: header.guta_circuit_whitelist.0,
        checkpoint_tree_root: header.checkpoint_tree_root.0,
        state_transition: convert_q_sub_tree_node_state_transition_to_hashout(header.state_transition),
        stats: header.stats,
    }
}


#[inline]
pub const fn convert_ho_sub_tree_node_state_transition_to_qhashout<F: RichField>(
    transition: SubTreeNodeStateTransition<F, HashOut<F>>,
) -> SubTreeNodeStateTransition<F, QHashOut<F>> {
    SubTreeNodeStateTransition {
        old_node_value: QHashOut(transition.old_node_value),
        new_node_value: QHashOut(transition.new_node_value),
        node_index: transition.node_index,
        node_level: transition.node_level,
    }
}
#[inline]
pub const fn convert_ho_guta_header_to_qhashout<F: RichField>(
    header: GlobalUserTreeAggregatorHeader<F, HashOut<F>>,
) -> GlobalUserTreeAggregatorHeader<F, QHashOut<F>> {
    GlobalUserTreeAggregatorHeader {
        guta_circuit_whitelist: QHashOut(header.guta_circuit_whitelist),
        checkpoint_tree_root: QHashOut(header.checkpoint_tree_root),
        state_transition: convert_ho_sub_tree_node_state_transition_to_qhashout(header.state_transition),
        stats: header.stats,
    }
}