use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::v1::qdata::pm_rewards_commitment::PPMRewardCommitment;
use psy_plonky2_common_circuits::traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor};



pub const PM_REWARD_COMMITMENT_TARGET_SIZE: usize = 12; // 3 QHashOut, each with 4 fields
#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PMRewardCommitmentGadget {
    pub register_users_root: HashOutTarget,
    pub gutas_root: HashOutTarget,
    pub deploy_contracts_root: HashOutTarget,
}

impl PMRewardCommitmentGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PPMRewardCommitment<QHashOut<F>>) -> anyhow::Result<()> {
        witness.set_hash_target(self.register_users_root, target.register_users_root.0)?;
        witness.set_hash_target(self.gutas_root, target.gutas_root.0)?;
        witness.set_hash_target(self.deploy_contracts_root, target.deploy_contracts_root.0)
    }
    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }
}
impl AlgebraicHashableTarget for PMRewardCommitmentGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PMRewardCommitmentGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let register_users_root = builder.add_virtual_hash();
        let gutas_root = builder.add_virtual_hash();
        let deploy_contracts_root = builder.add_virtual_hash();
        Self {
            register_users_root,
            gutas_root,
            deploy_contracts_root,
        }
    }
}
impl ToTargets for PMRewardCommitmentGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut targets = Vec::with_capacity(12);
        targets.extend_from_slice(&self.register_users_root.elements);
        targets.extend_from_slice(&self.gutas_root.elements);
        targets.extend_from_slice(&self.deploy_contracts_root.elements);
        targets
    }
}
impl FromTargets for PMRewardCommitmentGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != 12 {
            panic!("tried to create PMRewardCommitmentGadget from an array of {} targets, but expected an array of 12 targets", targets.len());
        }

        Self {
            register_users_root: HashOutTarget {
                elements: [targets[0], targets[1], targets[2], targets[3]],
            },
            gutas_root: HashOutTarget {
                elements: [targets[4], targets[5], targets[6], targets[7]],
            },
            deploy_contracts_root: HashOutTarget {
                elements: [targets[8], targets[9], targets[10], targets[11]],
            },
        }
    }
}


impl<F: RichField> WitnessValueFor<PMRewardCommitmentGadget, F, true> for PPMRewardCommitment<QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PMRewardCommitmentGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PMRewardCommitmentGadget, F, false> for PPMRewardCommitment<QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PMRewardCommitmentGadget) -> anyhow::Result<()>  {
        target.set_witness(witness, self)
    }
}
