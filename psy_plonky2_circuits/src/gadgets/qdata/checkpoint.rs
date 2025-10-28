use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use psy_data::v1::qdata::checkpoint::{PQEDCheckpointLeaf, PQEDCheckpointLeafCompact};
use psy_plonky2_basic_helpers::{builder::hash::core::CircuitBuilderHashCore};
use psy_plonky2_common_circuits::traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor};

use super::{checkpoint_stats::QEDCheckpointLeafStatsGadget, pm_reward_commitment::PM_REWARD_COMMITMENT_TARGET_SIZE};


pub const QED_CHECKPOINT_LEAF_GADGET_TARGET_SIZE: usize = 10 + PM_REWARD_COMMITMENT_TARGET_SIZE + DA_CHALLENGE_WINDOW + 4;
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct QEDCheckpointLeafGadget {
    pub global_chain_root: HashOutTarget,
    pub stats: QEDCheckpointLeafStatsGadget,
}

impl QEDCheckpointLeafGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PQEDCheckpointLeaf<F, QHashOut<F>>)  -> anyhow::Result<()>{
        witness.set_hash_target(self.global_chain_root, target.global_chain_root.0)?;
        self.stats.set_witness(witness, &target.stats)
    }
    pub fn to_compact<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> QEDCheckpointLeafCompactGadget {
        let stats_hash = self.stats.to_hash::<H, F, D>(builder);
        QEDCheckpointLeafCompactGadget {
            global_chain_root: self.global_chain_root,
            stats_hash,
        }
    }
    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_compact::<H, F, D>(builder).to_hash::<H, F, D>(builder)
    }
}
impl AlgebraicHashableTarget for QEDCheckpointLeafGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for QEDCheckpointLeafGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let global_chain_root = builder.add_virtual_hash();
        let stats = QEDCheckpointLeafStatsGadget::create_virtual(builder);
        Self {
            global_chain_root,
            stats,
        }
    }
}
impl ToTargets for QEDCheckpointLeafGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = Vec::with_capacity(QED_CHECKPOINT_LEAF_GADGET_TARGET_SIZE);
        result.extend_from_slice(&self.global_chain_root.elements);
        result.extend_from_slice(&self.stats.to_targets());
        result
    }
}
impl FromTargets for QEDCheckpointLeafGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != QED_CHECKPOINT_LEAF_GADGET_TARGET_SIZE {
            panic!("tried to create QEDCheckpointLeafGadget from an array of {} targets, but expected an array of {} targets", targets.len(), QED_CHECKPOINT_LEAF_GADGET_TARGET_SIZE);
        }
        let global_chain_root = HashOutTarget {
            elements: [
                targets[0],
                targets[1],
                targets[2],
                targets[3],
            ]
        };
        let stats = QEDCheckpointLeafStatsGadget::from_targets(&targets[4..]);

        Self {
            global_chain_root,
            stats,
        }
    }
}


impl<F: RichField> WitnessValueFor<QEDCheckpointLeafGadget, F, true> for PQEDCheckpointLeaf<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<QEDCheckpointLeafGadget, F, false> for PQEDCheckpointLeaf<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}




#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct QEDCheckpointLeafCompactGadget {
    pub global_chain_root: HashOutTarget,
    pub stats_hash: HashOutTarget,
}

impl QEDCheckpointLeafCompactGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PQEDCheckpointLeafCompact<QHashOut<F>>) -> anyhow::Result<()> {
        witness.set_hash_target(self.global_chain_root, target.global_chain_root.0)?;
        witness.set_hash_target(self.stats_hash, target.stats_hash.0)
    }
    pub fn set_witness_params<F: RichField>(&self, witness: &mut impl Witness<F>, global_chain_root: QHashOut<F>, stats_hash: QHashOut<F>) -> anyhow::Result<()> {
        witness.set_hash_target(self.global_chain_root, global_chain_root.0)?;
        witness.set_hash_target(self.stats_hash, stats_hash.0)
    }
    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_two_to_one::<H>(self.global_chain_root, self.stats_hash)
    }
}
impl AlgebraicHashableTarget for QEDCheckpointLeafCompactGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for QEDCheckpointLeafCompactGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let global_chain_root = builder.add_virtual_hash();
        let stats_hash = builder.add_virtual_hash();
        Self {
            global_chain_root,
            stats_hash,
        }
    }
}
impl ToTargets for QEDCheckpointLeafCompactGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = Vec::with_capacity(8);
        result.extend_from_slice(&self.global_chain_root.elements);
        result.extend_from_slice(&self.stats_hash.elements);
        result
    }
}
impl FromTargets for QEDCheckpointLeafCompactGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 8 {
            panic!("tried to create QEDCheckpointLeafCompactGadget from an array of {} targets, but expected an array of {} targets", targets.len(), 8);
        }
        let global_chain_root = HashOutTarget {
            elements: [
                targets[0],
                targets[1],
                targets[2],
                targets[3],
            ]
        };
        let stats_hash = HashOutTarget {
            elements: [
                targets[4],
                targets[5],
                targets[6],
                targets[7],
            ]
        };
        Self {
            global_chain_root,
            stats_hash,
        }
    }
}


impl<F: RichField> WitnessValueFor<QEDCheckpointLeafCompactGadget, F, true> for PQEDCheckpointLeafCompact<QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<QEDCheckpointLeafCompactGadget, F, false> for PQEDCheckpointLeafCompact<QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafCompactGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}


