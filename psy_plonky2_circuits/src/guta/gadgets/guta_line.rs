use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use parth_core::pgoldilocks::QHashOut;

use crate::treeprover::subtree::gadgets::sub_tree_top_line::SubTreeNodeTopLineGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};





#[derive(Clone, Debug)]
pub struct GUTAHeaderLineProofGadget{
    pub top_line_gadget: SubTreeNodeTopLineGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl GUTAHeaderLineProofGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        global_user_tree_realm_height: usize,
        global_user_tree_height: usize,
        child_proof_header: &GlobalUserTreeAggregatorHeaderGadget,
    ) -> Self {

        let top_line_gadget = SubTreeNodeTopLineGadget::add_virtual_to_full::<H,F,D>(
            builder, 
            global_user_tree_realm_height,
            global_user_tree_height,
            &child_proof_header.state_transition
        );

        let new_guta_header = GlobalUserTreeAggregatorHeaderGadget{
            guta_circuit_whitelist: child_proof_header.guta_circuit_whitelist,
            checkpoint_tree_root: child_proof_header.checkpoint_tree_root,
            state_transition: top_line_gadget.new_state_transition,
            stats: child_proof_header.stats,
        };

        tracing::debug!("📏 GUTA Line - new_guta_header: {:?}", new_guta_header);


        Self {
            top_line_gadget,
            new_guta_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        siblings: &[QHashOut<F>],
    ) -> anyhow::Result<()> {
        self.top_line_gadget.set_witness_params(witness, siblings)
    }

}

impl <const D: usize> ToGUTAHeader<D> for GUTAHeaderLineProofGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        self.new_guta_header
    }
}