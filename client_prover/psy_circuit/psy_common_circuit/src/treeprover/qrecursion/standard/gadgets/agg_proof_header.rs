use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::common::witnesses::qrecursion::header::QRecursionAggStandardHeader;

use crate::builder::hash::core::CircuitBuilderHashCore;

#[derive(Debug, Clone, Copy)]
pub struct QRecursionAggStandardHeaderGadget {
    pub state_transition_start: HashOutTarget,
    pub state_transition_end: HashOutTarget,
    pub agg_circuit_whitelist_root: HashOutTarget,
}

impl QRecursionAggStandardHeaderGadget {
    pub fn add_virtual_to<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let state_transition_start = builder.add_virtual_hash();
        let state_transition_end = builder.add_virtual_hash();
        let agg_circuit_whitelist_root = builder.add_virtual_hash();

        Self {
            state_transition_start,
            state_transition_end,
            agg_circuit_whitelist_root,
        }
    }

    pub fn get_combined_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        let state_transition = builder.hash_two_to_one::<H>(self.state_transition_start, self.state_transition_end);
        builder.hash_two_to_one::<H>(self.agg_circuit_whitelist_root, state_transition)
    }

    pub fn set_witness<W: Witness<F>, F: RichField>(&self, witness: &mut W, transition: &QRecursionAggStandardHeader<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.state_transition_start, transition.state_transition_start.0)?;
        witness.set_hash_target(self.state_transition_end, transition.state_transition_end.0)?;

        witness.set_hash_target(self.agg_circuit_whitelist_root, transition.agg_circuit_whitelist_root.0)
    }
    pub fn set_witness_values<W: Witness<F>, F: RichField>(
        &self,
        witness: &mut W,
        state_transition_start: QHashOut<F>,
        state_transition_end: QHashOut<F>,
        agg_circuit_whitelist_root: QHashOut<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.state_transition_start, state_transition_start.0)?;
        witness.set_hash_target(self.state_transition_end, state_transition_end.0)?;
        witness.set_hash_target(self.agg_circuit_whitelist_root, agg_circuit_whitelist_root.0)
    }
}
