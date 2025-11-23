use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;

use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_header::GlobalUserTreeAggregatorHeaderGadget, helpers::ToGUTAHeader};



#[derive(Clone, Debug)]
pub struct GUTALinearTransitionGadget {
    pub a_header: GlobalUserTreeAggregatorHeaderGadget,
    pub b_header: GlobalUserTreeAggregatorHeaderGadget,

    // computed
    pub new_guta_header: GlobalUserTreeAggregatorHeaderGadget,
}

impl GUTALinearTransitionGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        a_header: GlobalUserTreeAggregatorHeaderGadget,
        b_header: GlobalUserTreeAggregatorHeaderGadget,
    ) -> Self {

        // ensure a_header and b_header have the same checkpoint tree root
        builder.connect_hashes(
            a_header.checkpoint_tree_root,
            b_header.checkpoint_tree_root,
        );

        // ensure guta circuit whitelists are the same
        builder.connect_hashes(
            a_header.guta_circuit_whitelist,
            b_header.guta_circuit_whitelist,
        );

        // ensure the a header and b header have the same node level
        builder.connect(
            a_header.state_transition.node_level,
            b_header.state_transition.node_level,
        );

        // ensure the a header and b header have the same node index
        builder.connect(
            a_header.state_transition.node_index,
            b_header.state_transition.node_index,
        );
        let new_node_level = a_header.state_transition.node_level;
        let new_node_index = a_header.state_transition.node_index;
        


        // ensure the a header and b header have "back-to-back" state transitions
        builder.connect_hashes(
            a_header.state_transition.new_node_value,
            b_header.state_transition.old_node_value,
        );
        let old_node_value = a_header.state_transition.old_node_value;
        let new_node_value = b_header.state_transition.new_node_value;

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

        tracing::debug!("📊 new_guta_header: {:?}", new_guta_header);








        Self {
            new_guta_header,
            a_header,
            b_header,
        }
    }

    pub fn set_witness_params<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        child_a: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
        child_b: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,

    ) -> anyhow::Result<()> {
        self.a_header.set_witness(witness, child_a)?;
        self.b_header.set_witness(witness, child_b)?;
        Ok(())
    }
}


impl<const D: usize> ToGUTAHeader<D> for GUTALinearTransitionGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
       self.new_guta_header.to_owned()
    }
}