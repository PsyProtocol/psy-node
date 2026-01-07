use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut, utils::math::log2_ceil};
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_plonky2_common_circuits::hash::merkle::gadgets::q_variable_height_delta_merkle_proof::QVariableHeightDeltaMerkleProofGadget;

use crate::{
    guta::gadgets::{guta_header::GlobalUserTreeAggregatorHeaderGadget, guta_stats::GUTAStatsGadget, helpers::ToGUTAHeader},
    treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget,
};

#[derive(Clone, Debug)]
pub struct SingleVariableHeightStateTransitionGadget {
    pub svh_delta_merkle_proof_gadget: QVariableHeightDeltaMerkleProofGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl SingleVariableHeightStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        child_header: GlobalUserTreeAggregatorHeaderGadget,
        max_merkle_proof_height: usize,
        tree_height: usize,
    ) -> Self {
        let svh_delta_merkle_proof_gadget = QVariableHeightDeltaMerkleProofGadget::add_virtual_to::<H, F, D>(
            builder,
            max_merkle_proof_height,
            tree_height,
            None,
            Some(child_header.state_transition.old_node_value),
            Some(child_header.state_transition.new_node_value),
            Some(child_header.state_transition.node_index),
        );

        // ensure svh_delta_merkle_proof_gadget.height is greater than or equal to
        // node_level
        let node_level = child_header.state_transition.node_level;
        // the "height" of the merkle proof, aka, how many levels the sub-root is above
        // child_header and b_header
        let transition_height = svh_delta_merkle_proof_gadget.height;

        // compute the new level of the transition node by subtracting the transition
        // height from the current node level
        let new_node_level = builder.sub(node_level, transition_height);
        // range check this to ensure node_level >= transition_height
        builder.range_check(new_node_level, log2_ceil(tree_height));

        // the index of the new node is equal to
        // child_header.state_transition.node_index >> transition_height this is
        // already computed in svh
        let new_node_index = svh_delta_merkle_proof_gadget.parent_index;

        let old_node_value = svh_delta_merkle_proof_gadget.old_root;
        let new_node_value = svh_delta_merkle_proof_gadget.new_root;

        // no change
        let new_stats = GUTAStatsGadget {
            guta_fees_collected: child_header.stats.guta_fees_collected,
            da_fees_collected: child_header.stats.da_fees_collected,
            user_ops_processed: child_header.stats.user_ops_processed,
            total_transactions: child_header.stats.total_transactions,
            slots_modified: child_header.stats.slots_modified,
        };

        let one = builder.one();
        let total_aggregation_proofs_generated = builder.add(child_header.total_aggregation_proofs_generated, one);

        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget {
            guta_circuit_whitelist: child_header.guta_circuit_whitelist,
            checkpoint_tree_root: child_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value,
                new_node_value,
                node_index: new_node_index,
                node_level: new_node_level,
            },
            stats: new_stats,
            total_aggregation_proofs_generated,
        };

        Self {
            svh_delta_merkle_proof_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        child_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.svh_delta_merkle_proof_gadget.set_witness(witness, child_delta_merkle_proof)
    }
}

impl<const D: usize> ToGUTAHeader<D> for SingleVariableHeightStateTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(
        &self,
        _builder: &mut CircuitBuilder<F, D>,
        _default_guta_circuit_whitelist: HashOutTarget,
    ) -> GlobalUserTreeAggregatorHeaderGadget {
        self.new_guta_header.to_owned()
    }
}
