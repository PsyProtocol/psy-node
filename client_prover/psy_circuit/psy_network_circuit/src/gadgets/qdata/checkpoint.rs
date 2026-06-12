use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::checkpoint::{PsyCheckpointLeaf, PsyCheckpointLeafCompact};
use psy_common_circuit::{
    builder::hash::core::CircuitBuilderHashCore,
    traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor},
};
use psy_config::network_constants::DA_CHALLENGE_WINDOW;

use super::{checkpoint_stats::PsyCheckpointLeafStatsGadget, pm_reward_commitment::PM_REWARD_COMMITMENT_TARGET_SIZE};

pub const PSY_CHECKPOINT_LEAF_GADGET_TARGET_SIZE: usize = 10 + PM_REWARD_COMMITMENT_TARGET_SIZE + DA_CHALLENGE_WINDOW + 4;
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyCheckpointLeafGadget {
    pub global_chain_root: HashOutTarget,
    pub stats: PsyCheckpointLeafStatsGadget,
}

impl PsyCheckpointLeafGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeaf<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.global_chain_root, target.global_chain_root.0)?;
        self.stats.set_witness(witness, &target.stats)
    }
    pub fn to_compact<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> PsyCheckpointLeafCompactGadget {
        let stats_hash = self.stats.to_hash::<H, F, D>(builder);
        PsyCheckpointLeafCompactGadget {
            global_chain_root: self.global_chain_root,
            stats_hash,
        }
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_compact::<H, F, D>(builder).to_hash::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for PsyCheckpointLeafGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyCheckpointLeafGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let global_chain_root = builder.add_virtual_hash();
        let stats = PsyCheckpointLeafStatsGadget::create_virtual(builder);
        Self { global_chain_root, stats }
    }
}
impl ToTargets for PsyCheckpointLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = Vec::with_capacity(PSY_CHECKPOINT_LEAF_GADGET_TARGET_SIZE);
        result.extend_from_slice(&self.global_chain_root.elements);
        result.extend_from_slice(&self.stats.to_targets());
        result
    }
}
impl FromTargets for PsyCheckpointLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != PSY_CHECKPOINT_LEAF_GADGET_TARGET_SIZE {
            panic!(
                "tried to create PsyCheckpointLeafGadget from an array of {} targets, but expected an array of {} targets",
                targets.len(),
                PSY_CHECKPOINT_LEAF_GADGET_TARGET_SIZE
            );
        }
        let global_chain_root = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let stats = PsyCheckpointLeafStatsGadget::from_targets(&targets[4..]);

        Self { global_chain_root, stats }
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafGadget, F, true> for PsyCheckpointLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafGadget, F, false> for PsyCheckpointLeaf<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyCheckpointLeafCompactGadget {
    pub global_chain_root: HashOutTarget,
    pub stats_hash: HashOutTarget,
}

impl PsyCheckpointLeafCompactGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompact<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.global_chain_root, target.global_chain_root.0)?;
        witness.set_hash_target(self.stats_hash, target.stats_hash.0)
    }
    pub fn set_witness_params<F: RichField>(
        &self,
        witness: &mut impl Witness<F>,
        global_chain_root: QHashOut<F>,
        stats_hash: QHashOut<F>,
    ) -> anyhow::Result<()> {
        witness.set_hash_target(self.global_chain_root, global_chain_root.0)?;
        witness.set_hash_target(self.stats_hash, stats_hash.0)
    }
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_two_to_one::<H>(self.global_chain_root, self.stats_hash)
    }
}
impl AlgebraicHashableTarget for PsyCheckpointLeafCompactGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyCheckpointLeafCompactGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let global_chain_root = builder.add_virtual_hash();
        let stats_hash = builder.add_virtual_hash();
        Self {
            global_chain_root,
            stats_hash,
        }
    }
}
impl ToTargets for PsyCheckpointLeafCompactGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = Vec::with_capacity(8);
        result.extend_from_slice(&self.global_chain_root.elements);
        result.extend_from_slice(&self.stats_hash.elements);
        result
    }
}
impl FromTargets for PsyCheckpointLeafCompactGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 8 {
            panic!(
                "tried to create PsyCheckpointLeafCompactGadget from an array of {} targets, but expected an array of {} targets",
                targets.len(),
                8
            );
        }
        let global_chain_root = HashOutTarget {
            elements: [targets[0], targets[1], targets[2], targets[3]],
        };
        let stats_hash = HashOutTarget {
            elements: [targets[4], targets[5], targets[6], targets[7]],
        };
        Self {
            global_chain_root,
            stats_hash,
        }
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafCompactGadget, F, true> for PsyCheckpointLeafCompact<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafCompactGadget, F, false> for PsyCheckpointLeafCompact<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
