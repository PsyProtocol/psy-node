use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::guta::header::GlobalUserTreeAggregatorHeader;
use psy_plonky2_basic_helpers::{builder::hash::core::CircuitBuilderHashCore};
use crate::treeprover::subtree::gadgets::subtree_core::SubTreeNodeStateTransitionGadget;

use super::{guta_stats::GUTAStatsGadget, helpers::ToGUTAHeader};



#[derive(Clone, Copy, Debug)]
pub struct GlobalUserTreeAggregatorHeaderGadget {
    pub guta_circuit_whitelist: HashOutTarget,
    pub checkpoint_tree_root: HashOutTarget,
    pub state_transition: SubTreeNodeStateTransitionGadget,
    pub stats: GUTAStatsGadget,
    pub total_aggregation_proofs_generated: Target,
}

impl GlobalUserTreeAggregatorHeaderGadget {
    pub fn add_virtual_to< F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let guta_circuit_whitelist = builder.add_virtual_hash();
        let checkpoint_tree_root = builder.add_virtual_hash();
        let state_transition = SubTreeNodeStateTransitionGadget::add_virtual_to(builder);
        let stats = GUTAStatsGadget::add_virtual_to(builder);
        let total_aggregation_proofs_generated = builder.add_virtual_target();
        


        


        Self {
            guta_circuit_whitelist,
            checkpoint_tree_root,
            state_transition,
            stats,
            total_aggregation_proofs_generated,
        }
    }

    pub fn set_witness<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &GlobalUserTreeAggregatorHeader<F, QHashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.guta_circuit_whitelist, 
            target.guta_circuit_whitelist.0,
        )?;
        witness.set_hash_target(
            self.checkpoint_tree_root, 
            target.checkpoint_tree_root.0,
        )?;
        self.state_transition.set_witness(witness, &target.state_transition)?;
        self.stats.set_witness(witness, &target.stats)?;
        witness.set_target(
            self.total_aggregation_proofs_generated,
            target.total_aggregation_proofs_generated,
        )?;
        Ok(())
    }

    pub fn set_witness_ho<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        target: &GlobalUserTreeAggregatorHeader<F, HashOut<F>>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(
            self.guta_circuit_whitelist, 
            target.guta_circuit_whitelist,
        )?;
        witness.set_hash_target(
            self.checkpoint_tree_root, 
            target.checkpoint_tree_root,
        )?;
        self.state_transition.set_witness_ho(witness, &target.state_transition)?;
        self.stats.set_witness(witness, &target.stats)?;
        witness.set_target(
            self.total_aggregation_proofs_generated,
            target.total_aggregation_proofs_generated,
        )?;
        Ok(())
    }


    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {

        let state_transition_hash = self.state_transition.to_hash::<H, F, D>(builder);
        let stats_hash = self.stats.to_hash::<H, F, D>(builder);



        let state_transition_and_stats_hash = builder.hash_two_to_one::<H>(
            state_transition_hash,
            stats_hash,
        );
        let state_stats_checkpoint_hash = builder.hash_two_to_one::<H>(
            self.checkpoint_tree_root,
            state_transition_and_stats_hash,
        );

        let header_with_whitelist_hash = builder.hash_two_to_one::<H>(
            self.guta_circuit_whitelist,
            state_stats_checkpoint_hash,
        );
        builder.hash_n_to_hash_no_pad::<H>(vec![
            header_with_whitelist_hash.elements[0],
            header_with_whitelist_hash.elements[1],
            header_with_whitelist_hash.elements[2],
            header_with_whitelist_hash.elements[3],
            self.total_aggregation_proofs_generated,
        ])
    }
    pub fn get_public_inputs_hash_two_children<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        left_child_rewards_tree_value: HashOutTarget,
        right_child_rewards_tree_value: HashOutTarget,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {

        let children_combined = builder.hash_two_to_one::<H>(
            left_child_rewards_tree_value,
            right_child_rewards_tree_value,
        );
        let final_rewards_tree_hash = builder.hash_two_to_one::<H>(
            children_combined,
            rewards_tree_tag,
        );

        let header_hash = self.to_hash::<H, F, D>(builder);

        builder.hash_two_to_one::<H>(
            header_hash,
            final_rewards_tree_hash,
        )
    }
    pub fn get_expected_public_inputs_hash_from_guta_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        guta_hash: HashOutTarget,
        rewards_tree_value: HashOutTarget,
    ) -> HashOutTarget {
        builder.hash_two_to_one::<H>(
            guta_hash,
            rewards_tree_value,
        )
    }
    pub fn get_expected_public_inputs_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        rewards_tree_value: HashOutTarget,
    ) -> HashOutTarget {

        let header_hash = self.to_hash::<H, F, D>(builder);

        builder.hash_two_to_one::<H>(
            header_hash,
            rewards_tree_value,
        )
    }
    pub fn get_public_inputs_hash_left_end_cap<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        right_child_rewards_tree_value: HashOutTarget,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {
        let left_child_rewards_tree_value = builder.constant_qhash(QHashOut::ZERO);
        self.get_public_inputs_hash_two_children::<H, F, D>(builder, left_child_rewards_tree_value, right_child_rewards_tree_value, rewards_tree_tag)
    }
    pub fn get_public_inputs_hash_right_end_cap<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        left_child_rewards_tree_value: HashOutTarget,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {
        let right_child_rewards_tree_value = builder.constant_qhash(QHashOut::ZERO);
        self.get_public_inputs_hash_two_children::<H, F, D>(builder, left_child_rewards_tree_value, right_child_rewards_tree_value, rewards_tree_tag)
    }
    pub fn get_public_inputs_hash_two_end_cap<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);

        self.get_public_inputs_hash_two_children::<H, F, D>(builder, zero_hash, zero_hash, rewards_tree_tag)
    }
    pub fn get_public_inputs_hash_no_children<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {
        let zero_hash = builder.constant_qhash(QHashOut::ZERO);

        self.get_public_inputs_hash_two_children::<H, F, D>(builder, zero_hash, zero_hash, rewards_tree_tag)
    }
    // TODO: should we change how this is handled in the tag tree?
    pub fn get_public_inputs_hash_single_child<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        child_rewards_tree_value: HashOutTarget,
        rewards_tree_tag: HashOutTarget,
    ) -> HashOutTarget {
        let right_child_rewards_tree_value = builder.constant_qhash(QHashOut::ZERO);
        self.get_public_inputs_hash_two_children::<H, F, D>(builder, child_rewards_tree_value, right_child_rewards_tree_value, rewards_tree_tag)
    }
}

impl <const D: usize> ToGUTAHeader<D> for GlobalUserTreeAggregatorHeaderGadget {
    fn get_guta_header<H: AlgebraicHasher<F>, F: RichField + Extendable<D>>(&self, _builder: &mut CircuitBuilder<F, D>, _default_guta_circuit_whitelist: HashOutTarget) -> GlobalUserTreeAggregatorHeaderGadget {
        *self
    }
}

/* 
impl CreatableWithHasherTarget for GlobalUserTreeAggregatorHeaderGadget {
    fn create_virtual_with_hasher<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for GlobalUserTreeAggregatorHeaderGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl<F: RichField> WitnessValueFor<GlobalUserTreeAggregatorHeaderGadget, F, true>
    for UserProvingSessionHeader<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &GlobalUserTreeAggregatorHeaderGadget,
    ) {
        target.set_witness(witness, self);
    }
}

impl<F: RichField> WitnessValueFor<GlobalUserTreeAggregatorHeaderGadget, F, false>
    for UserProvingSessionHeader<F>
{
    fn set_for_witness(
        &self,
        witness: &mut impl Witness<F>,
        target: &GlobalUserTreeAggregatorHeaderGadget,
    ) {
        target.set_witness(witness, self);
    }
}
*/
