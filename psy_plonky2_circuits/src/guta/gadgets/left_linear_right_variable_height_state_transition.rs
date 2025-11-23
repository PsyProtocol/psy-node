use parth_core::{crypto::hash::merkle_proof::DeltaMerkleProofCore, pgoldilocks::QHashOut};
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_plonky2_common_circuits::hash::merkle::gadgets::q_variable_height_delta_merkle_proof::QVariableHeightDeltaMerkleProofGadget;

use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};



#[derive(Clone, Debug)]
pub struct LeftLinearRightVariableHeightStateTransitionGadget {
    pub right_delta_merkle_proof_gadget: QVariableHeightDeltaMerkleProofGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl LeftLinearRightVariableHeightStateTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a_header: GlobalUserTreeAggregatorHeaderGadget,
        b_header: GlobalUserTreeAggregatorHeaderGadget,
        max_merkle_proof_height: usize,
        tree_height: usize,
    ) -> Self {
        tracing::debug!("🔗 a_header: {:?}, b_header: {:?}", a_header, b_header);

        let right_delta_merkle_proof_gadget = QVariableHeightDeltaMerkleProofGadget::add_virtual_to::<H,F,D>(
            builder, 
            max_merkle_proof_height,
            tree_height,
            None,
            Some(b_header.state_transition.old_node_value),
            Some(b_header.state_transition.new_node_value),
            Some(b_header.state_transition.node_index),
        );
        let right_parent_level = right_delta_merkle_proof_gadget.get_parent_level::<F, D>(
            builder,
            b_header.state_transition.node_level,
        );

        builder.connect_hashes(
            a_header.checkpoint_tree_root,
            b_header.checkpoint_tree_root,
        );

        builder.connect_hashes(
            a_header.guta_circuit_whitelist,
            b_header.guta_circuit_whitelist,
        );
        // ensure that the node for a_header matches the parent node of the right delta merkle proof
        builder.connect(
            a_header.state_transition.node_index,
            right_delta_merkle_proof_gadget.parent_index,
        );
        builder.connect(
            a_header.state_transition.node_level,
            right_parent_level,
        );
        let new_node_index = a_header.state_transition.node_index;
        // ensure dvh_delta_merkle_proof_gadget.height is greater than or equal to node_level
        let new_node_level = a_header.state_transition.node_level;
        // the "height" of the merkle proof, aka, how many levels the sub-root is above a_header and b_header 
        
        let old_node_value = a_header.state_transition.old_node_value;
        let new_node_value = right_delta_merkle_proof_gadget.new_root;


        let new_stats = a_header.stats.combine_with(builder, &b_header.stats);



        let total_aggregation_proofs_generated = builder.add(a_header.total_aggregation_proofs_generated, b_header.total_aggregation_proofs_generated);
        let one = builder.one();
        let total_aggregation_proofs_generated = builder.add(total_aggregation_proofs_generated, one);

        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: a_header.guta_circuit_whitelist,
            checkpoint_tree_root: a_header.checkpoint_tree_root,
            state_transition: SubTreeNodeStateTransitionGadget {
                old_node_value,
                new_node_value,
                node_index: new_node_index,
                node_level: new_node_level
            },
            stats: new_stats,
            total_aggregation_proofs_generated,
        };









        Self {
            right_delta_merkle_proof_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        right_delta_merkle_proof: &DeltaMerkleProofCore<QHashOut<F>>,
    ) -> anyhow::Result<()> {
        self.right_delta_merkle_proof_gadget.set_witness(witness,
            right_delta_merkle_proof,
        )
    }
}


impl<const D: usize> ToGUTAHeader<D> for LeftLinearRightVariableHeightStateTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
       self.new_guta_header.to_owned()
    }
}