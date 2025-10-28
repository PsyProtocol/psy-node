use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOut, HashOutTarget, RichField}, iop::witness::Witness, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
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
}

impl GlobalUserTreeAggregatorHeaderGadget {
    pub fn add_virtual_to< F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let guta_circuit_whitelist = builder.add_virtual_hash();
        let checkpoint_tree_root = builder.add_virtual_hash();
        let state_transition = SubTreeNodeStateTransitionGadget::add_virtual_to(builder);
        let stats = GUTAStatsGadget::add_virtual_to(builder);
        


        


        Self {
            guta_circuit_whitelist,
            checkpoint_tree_root,
            state_transition,
            stats,
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
        self.stats.set_witness(witness, &target.stats)
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
        self.stats.set_witness(witness, &target.stats)
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

        builder.hash_two_to_one::<H>(
            self.guta_circuit_whitelist,
            state_stats_checkpoint_hash,
        )
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
