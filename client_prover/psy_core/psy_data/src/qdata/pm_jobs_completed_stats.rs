use plonky2::{field::goldilocks_field::GoldilocksField, hash::hash_types::RichField};
use psy_client_common::traits::to_qfelts::{QFeltSized, ToQFelts};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

pub const PM_JOBS_COMPLETED_STATS_SIZE: usize = 3;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Copy, Default, TS)]
#[ts(export, concrete(F = GoldilocksField))]
#[serde(bound = "for<'de2> F: Deserialize<'de2>")]
pub struct PMJobsCompletedStats<F: RichField> {
    pub deploy_contracts_completed: F,
    pub register_users_completed: F,
    pub gutas_completed: F,
}

impl<F: RichField> PMJobsCompletedStats<F> {
    pub fn new_empty() -> Self {
        Self {
            deploy_contracts_completed: F::ZERO,
            register_users_completed: F::ZERO,
            gutas_completed: F::ZERO,
        }
    }

    pub fn new_deploy_contracts(count: F) -> Self {
        Self {
            deploy_contracts_completed: count,
            register_users_completed: F::ZERO,
            gutas_completed: F::ZERO,
        }
    }

    pub fn new_register_users(count: F) -> Self {
        Self {
            deploy_contracts_completed: F::ZERO,
            register_users_completed: count,
            gutas_completed: F::ZERO,
        }
    }

    pub fn new_gutas(count: F) -> Self {
        Self {
            deploy_contracts_completed: F::ZERO,
            register_users_completed: F::ZERO,
            gutas_completed: count,
        }
    }

    pub fn combine(&self, other: &Self) -> Self {
        Self {
            deploy_contracts_completed: self.deploy_contracts_completed + other.deploy_contracts_completed,
            register_users_completed: self.register_users_completed + other.register_users_completed,
            gutas_completed: self.gutas_completed + other.gutas_completed,
        }
    }

    pub fn total(&self) -> F {
        self.deploy_contracts_completed + self.register_users_completed + self.gutas_completed
    }
}

impl<F: RichField> QFeltSized for PMJobsCompletedStats<F> {
    fn q_felt_size() -> usize {
        PM_JOBS_COMPLETED_STATS_SIZE
    }
}

impl<F: RichField> ToQFelts<F> for PMJobsCompletedStats<F> {
    fn to_qfelts(&self) -> Vec<F> {
        vec![self.deploy_contracts_completed, self.register_users_completed, self.gutas_completed]
    }

    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != PM_JOBS_COMPLETED_STATS_SIZE {
            panic!(
                "Invalid number of elements for PMJobsCompletedStats, expected {} got {}",
                PM_JOBS_COMPLETED_STATS_SIZE,
                felts.len()
            );
        }
        PMJobsCompletedStats {
            deploy_contracts_completed: felts[0],
            register_users_completed: felts[1],
            gutas_completed: felts[2],
        }
    }
}
