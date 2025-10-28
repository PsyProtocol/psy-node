use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}, util::log2_ceil};
use psy_plonky2_common_circuits::hash::merkle::gadgets::variable_height_delta_merkle_proof_opt::VariableHeightDeltaMerkleProofOptGadget;


use super::subtree_core::SubTreeNodeStateTransitionGadget;


#[derive(Debug, Clone)]
pub struct SubTreeNodeTopLineGadget {
    pub top_line_height: Target,
    pub top_line_proof: VariableHeightDeltaMerkleProofOptGadget,

    // computed
    pub new_state_transition: SubTreeNodeStateTransitionGadget,
}



impl SubTreeNodeTopLineGadget {
    pub fn add_virtual_to_full<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        max_height: usize,
        max_level: usize,
        child_transition: &SubTreeNodeStateTransitionGadget,
    ) -> Self {

        let top_line_height = builder.add_virtual_target();

        let top_line_proof = VariableHeightDeltaMerkleProofOptGadget::add_virtual_to_full_with_subtree_root_index_known::<H,F,D>(
            builder,
            max_height,
            Some(top_line_height),
            child_transition.node_index,
            child_transition.old_node_value,
            child_transition.new_node_value,
        );

        let node_index = top_line_proof.bit_info.get_root_parent_index(builder);

        let node_level = builder.sub(child_transition.node_level, top_line_height);
        builder.range_check(node_level, log2_ceil(max_level));

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
        for (i, s) in self.top_line_proof.siblings.iter().enumerate() {
            if i < siblings.len() {
            witness.set_hash_target(
                *s,
                siblings[i].0,
            )?;
            }else{
                witness.set_hash_target(
                    *s,
                    HashOut::ZERO
                )?;
            }
        }

        witness.set_target(self.top_line_height, F::from_canonical_usize(siblings.len()))
    }
}
