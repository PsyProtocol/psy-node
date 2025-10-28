use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::guta::sub_tree_transition::SubTreeNodeStateTransition;



#[derive(Debug, Clone, Copy)]
pub struct SubTreeNodeStateTransitionGadget {
    pub old_node_value: HashOutTarget,
    pub new_node_value: HashOutTarget,
    pub node_index: Target,
    pub node_level: Target,
}


impl SubTreeNodeStateTransitionGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let old_node_value = builder.add_virtual_hash();
        let new_node_value = builder.add_virtual_hash();
        let node_index = builder.add_virtual_target();
        let node_level = builder.add_virtual_target();

        Self {
            old_node_value,
            new_node_value,
            node_index,
            node_level,
        }
    }

    pub fn to_hash<
        H: AlgebraicHasher<F>,
        F: RichField + Extendable<D>,
        const D: usize,
    >(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {



        let node_change_combo = builder.hash_n_to_hash_no_pad::<H>(vec![
            self.node_index,

            self.old_node_value.elements[0],
            self.old_node_value.elements[1],
            self.old_node_value.elements[2],
            self.old_node_value.elements[3],

            self.new_node_value.elements[0],
            self.new_node_value.elements[1],
            self.new_node_value.elements[2],
            self.new_node_value.elements[3],

            self.node_level,
        ]);


        node_change_combo
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &SubTreeNodeStateTransition<F, QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.old_node_value,
            transition.old_node_value.0,
        )?;
        witness.set_hash_target(
            self.new_node_value,
            transition.new_node_value.0,
        )?;

        witness.set_target(self.node_index, transition.node_index)?;
        witness.set_target(self.node_level, transition.node_level)
    }


    pub fn set_witness_ho<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        transition: &SubTreeNodeStateTransition<F, HashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.old_node_value,
            transition.old_node_value,
        )?;
        witness.set_hash_target(
            self.new_node_value,
            transition.new_node_value,
        )?;

        witness.set_target(self.node_index, transition.node_index)?;
        witness.set_target(self.node_level, transition.node_level)
    }
}


