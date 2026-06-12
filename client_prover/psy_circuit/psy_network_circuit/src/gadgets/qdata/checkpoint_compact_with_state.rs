use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::witness::Witness,
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::checkpoint::{PsyCheckpointGlobalStateRoots, PsyCheckpointLeafCompactWithStateRoots};
use psy_common_circuit::traits::{AlgebraicHashableTarget, CreatableTarget, CreatableWithHasherTarget, WitnessValueFor};

use super::{checkpoint::PsyCheckpointLeafCompactGadget, checkpoint_state_roots::PsyCheckpointGlobalStateRootsGadget};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyCheckpointLeafCompactWithStateRootsGadget {
    pub checkpoint_leaf: PsyCheckpointLeafCompactGadget,
    pub global_state_roots: PsyCheckpointGlobalStateRootsGadget,

    // fully computed
    pub checkpoint_leaf_hash: HashOutTarget,
}

impl PsyCheckpointLeafCompactWithStateRootsGadget {
    pub fn add_virtual_to<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        // START: create targets that require witness
        let global_state_roots = PsyCheckpointGlobalStateRootsGadget::create_virtual(builder);
        let stats_hash = builder.add_virtual_hash();
        // END: create targets that require witness

        // START: setup computed targets
        let global_chain_root = global_state_roots.to_hash::<H, F, D>(builder);
        let checkpoint_leaf = PsyCheckpointLeafCompactGadget {
            global_chain_root,
            stats_hash,
        };
        // END: setup computed targets

        let checkpoint_leaf_hash = checkpoint_leaf.to_hash::<H, F, D>(builder);

        Self {
            checkpoint_leaf,
            global_state_roots,
            checkpoint_leaf_hash,
        }
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        global_state_roots: &PsyCheckpointGlobalStateRoots<F>,
        stats_hash: QHashOut<F>,
    ) -> anyhow::Result<()> {
        self.global_state_roots.set_witness(witness, &global_state_roots)?;
        witness.set_hash_target(self.checkpoint_leaf.stats_hash, stats_hash.0)
    }
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompactWithStateRoots<F>) -> anyhow::Result<()> {
        self.set_witness_params(witness, &target.global_state_roots, target.checkpoint_leaf.stats_hash)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, _builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        // note: we almost always need the hash anyways so might as well precompute it
        // self.checkpoint_leaf.to_hash::<H, F, D>(builder)
        self.checkpoint_leaf_hash
    }
}
impl AlgebraicHashableTarget for PsyCheckpointLeafCompactWithStateRootsGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableWithHasherTarget for PsyCheckpointLeafCompactWithStateRootsGadget {
    fn create_virtual_with_hasher<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        Self::add_virtual_to::<H, F, D>(builder)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafCompactWithStateRootsGadget, F, true> for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompactWithStateRootsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafCompactWithStateRootsGadget, F, false> for PsyCheckpointLeafCompactWithStateRoots<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompactWithStateRootsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
