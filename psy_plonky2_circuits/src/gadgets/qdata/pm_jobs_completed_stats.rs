use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_data::v1::qdata::pm_jobs_completed_stats::PPMJobsCompletedStats;
use psy_plonky2_common_circuits::traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor};

pub const PM_JOBS_COMPLETED_STATS_TARGET_SIZE: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PMJobsCompletedStatsGadget {
    pub deploy_contracts_completed: Target,
    pub register_users_completed: Target,
    pub gutas_completed: Target,
}

impl PMJobsCompletedStatsGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PPMJobsCompletedStats<F>) -> anyhow::Result<()> {
        witness.set_target(self.deploy_contracts_completed, target.deploy_contracts_completed)?;
        witness.set_target(self.register_users_completed, target.register_users_completed)?;
        witness.set_target(self.gutas_completed, target.gutas_completed)?;
        Ok(())
    }

    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }

    pub fn combine<F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>, other: &Self) -> Self {
        Self {
            deploy_contracts_completed: builder.add(self.deploy_contracts_completed, other.deploy_contracts_completed),
            register_users_completed: builder.add(self.register_users_completed, other.register_users_completed),
            gutas_completed: builder.add(self.gutas_completed, other.gutas_completed),
        }
    }

    pub fn new_empty<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let zero = builder.zero();
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: zero,
            gutas_completed: zero,
        }
    }

    pub fn new_deploy_contracts<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, count: Target) -> Self {
        let zero = builder.zero();
        Self {
            deploy_contracts_completed: count,
            register_users_completed: zero,
            gutas_completed: zero,
        }
    }

    pub fn new_register_users<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, count: Target) -> Self {
        let zero = builder.zero();
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: count,
            gutas_completed: zero,
        }
    }

    pub fn new_gutas<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>, count: Target) -> Self {
        let zero = builder.zero();
        Self {
            deploy_contracts_completed: zero,
            register_users_completed: zero,
            gutas_completed: count,
        }
    }
}

impl AlgebraicHashableTarget for PMJobsCompletedStatsGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}

impl CreatableTarget for PMJobsCompletedStatsGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            deploy_contracts_completed: builder.add_virtual_target(),
            register_users_completed: builder.add_virtual_target(),
            gutas_completed: builder.add_virtual_target(),
        }
    }
}

impl ToTargets for PMJobsCompletedStatsGadget {
    fn to_targets(&self) -> Vec<Target> {
        vec![
            self.deploy_contracts_completed,
            self.register_users_completed,
            self.gutas_completed,
        ]
    }
}

impl FromTargets for PMJobsCompletedStatsGadget {
    fn from_targets(targets: &[Target]) -> Self {
        if targets.len() != PM_JOBS_COMPLETED_STATS_TARGET_SIZE {
            panic!("Invalid number of targets for PMJobsCompletedStatsGadget, expected {} got {}", PM_JOBS_COMPLETED_STATS_TARGET_SIZE, targets.len());
        }
        Self {
            deploy_contracts_completed: targets[0],
            register_users_completed: targets[1],
            gutas_completed: targets[2],
        }
    }
}

impl<F: RichField> WitnessValueFor<PMJobsCompletedStatsGadget, F, true> for PPMJobsCompletedStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PMJobsCompletedStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PMJobsCompletedStatsGadget, F, false> for PPMJobsCompletedStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PMJobsCompletedStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
