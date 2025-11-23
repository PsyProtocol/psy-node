use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::RichField, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}, util::log2_ceil};
use psy_plonky2_common_circuits::hash::merkle::gadgets::q_variable_height_delta_merkle_proof::QVariableHeightDeltaMerkleProofGadget;


use super::subtree_core::SubTreeNodeStateTransitionGadget;


#[derive(Debug, Clone)]
pub struct SubTreeNodeTopLineGadget {
    pub top_line_height: Target,
    pub top_line_proof: QVariableHeightDeltaMerkleProofGadget,

    // computed
    pub new_state_transition: SubTreeNodeStateTransitionGadget,
}



impl SubTreeNodeTopLineGadget {
    pub fn add_virtual_to_full<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_merkle_proof_height: usize,
        tree_height: usize,
        child_transition: &SubTreeNodeStateTransitionGadget,
    ) -> Self {

        let top_line_height = builder.add_virtual_target();

        let top_line_proof = QVariableHeightDeltaMerkleProofGadget::add_virtual_to::<H,F,D>(
            builder,
            max_merkle_proof_height,
            tree_height,
            Some(top_line_height),
            Some(child_transition.old_node_value),
            Some(child_transition.new_node_value),
            Some(child_transition.node_index),
        );

        let node_index = top_line_proof.parent_index;

        let node_level = builder.sub(child_transition.node_level, top_line_height);
        // ensure node_level does not underflow by range checking
        builder.range_check(node_level, log2_ceil(tree_height));

        let new_state_transition = SubTreeNodeStateTransitionGadget {
            old_node_value: top_line_proof.old_root,
            new_node_value: top_line_proof.new_root,
            node_index,
            node_level,
        };

        tracing::debug!("🔝 SubTree Top Line - new_state_transition: {:?}", new_state_transition);

        Self {
            top_line_height,
            top_line_proof,
            new_state_transition,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        self.top_line_proof.set_witness_siblings(witness, siblings)?;
        witness.set_target(self.top_line_height, F::from_canonical_usize(siblings.len()))
    }
}
