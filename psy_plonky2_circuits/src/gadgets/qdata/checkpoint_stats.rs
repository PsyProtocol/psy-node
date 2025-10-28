use parth_core::pgoldilocks::QHashOut;
use plonky2::{field::extension::Extendable, hash::hash_types::{HashOutTarget, RichField}, iop::{target::Target, witness::Witness}, plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher}};
use psy_core::constants::protocol::DA_CHALLENGE_WINDOW;
use psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafStats;
use psy_plonky2_common_circuits::traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor};

use super::{pm_reward_commitment::PM_REWARD_COMMITMENT_TARGET_SIZE};


use super::pm_reward_commitment::{PMRewardCommitmentGadget};
use super::pm_jobs_completed_stats::{PMJobsCompletedStatsGadget, PM_JOBS_COMPLETED_STATS_TARGET_SIZE};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct QEDCheckpointLeafStatsGadget {
    pub fees_collected: Target,

    pub user_ops_processed: Target,
    pub total_transactions: Target,

    pub slots_modified: Target,
    pub pm_jobs_completed: PMJobsCompletedStatsGadget,

    pub block_time: Target,

    pub random_seed: HashOutTarget,
    pub pm_rewards_commitment: PMRewardCommitmentGadget,

    // data availability miner proofs successfully completed for the previous 16 blocks
    pub da_challenges_claimed: [Target; DA_CHALLENGE_WINDOW],
}

impl QEDCheckpointLeafStatsGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PQEDCheckpointLeafStats<F, QHashOut<F>>)  -> anyhow::Result<()>{
        witness.set_target(self.fees_collected, target.fees_collected)?;

        witness.set_target(self.user_ops_processed, target.user_ops_processed)?;
        witness.set_target(self.total_transactions, target.total_transactions)?;

        witness.set_target(self.slots_modified, target.slots_modified)?;
        self.pm_jobs_completed.set_witness(witness, &target.pm_jobs_completed)?;

        witness.set_target(self.block_time, target.block_time)?;

        witness.set_hash_target(self.random_seed, target.random_seed.0)?;
        self.pm_rewards_commitment.set_witness(witness, &target.pm_rewards_commitment)?;

        witness.set_target_arr(&self.da_challenges_claimed, &target.da_challenges_claimed)?;
        Ok(())
    }
    pub fn to_hash<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }
}
impl AlgebraicHashableTarget for QEDCheckpointLeafStatsGadget {
    fn to_hash_target<H:AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for QEDCheckpointLeafStatsGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let fees_collected = builder.add_virtual_target();
        let user_ops_processed = builder.add_virtual_target();
        let total_transactions = builder.add_virtual_target();
        let slots_modified = builder.add_virtual_target();
        let pm_jobs_completed = PMJobsCompletedStatsGadget::create_virtual(builder);
        let block_time = builder.add_virtual_target();



        let random_seed = builder.add_virtual_hash();
        let pm_rewards_commitment = PMRewardCommitmentGadget::create_virtual(builder);
        let da_challenges_claimed = builder.add_virtual_target_arr::<DA_CHALLENGE_WINDOW>();

        Self {
            fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
            pm_jobs_completed,
            block_time,
            random_seed,
            pm_rewards_commitment,
            da_challenges_claimed,
        }

    }
}
impl ToTargets for QEDCheckpointLeafStatsGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = vec![
            self.fees_collected,
            self.user_ops_processed,
            self.total_transactions,
            self.slots_modified,
        ];
        result.extend_from_slice(&self.pm_jobs_completed.to_targets());
        result.extend_from_slice(&[
            self.block_time,
            self.random_seed.elements[0],
            self.random_seed.elements[1],
            self.random_seed.elements[2],
            self.random_seed.elements[3],
        ]);
        result.extend_from_slice(&self.pm_rewards_commitment.to_targets());
        result.extend_from_slice(&self.da_challenges_claimed);
        result
    }
}
impl FromTargets for QEDCheckpointLeafStatsGadget {
    fn from_targets(targets: &[Target]) -> Self {
        let expected_len = 4 + PM_JOBS_COMPLETED_STATS_TARGET_SIZE + 5 + PM_REWARD_COMMITMENT_TARGET_SIZE + DA_CHALLENGE_WINDOW;
        if targets.len() != expected_len {
            panic!("Invalid number of elements for QEDCheckpointLeafStatsGadget, expected {} got {}", expected_len, targets.len());
        }

        let mut offset = 0;
        let fees_collected = targets[offset]; offset += 1;
        let user_ops_processed = targets[offset]; offset += 1;
        let total_transactions = targets[offset]; offset += 1;
        let slots_modified = targets[offset]; offset += 1;

        let pm_jobs_completed = PMJobsCompletedStatsGadget::from_targets(&targets[offset..offset + PM_JOBS_COMPLETED_STATS_TARGET_SIZE]);
        offset += PM_JOBS_COMPLETED_STATS_TARGET_SIZE;

        let block_time = targets[offset]; offset += 1;
        let random_seed = HashOutTarget {
            elements: [targets[offset], targets[offset+1], targets[offset+2], targets[offset+3]],
        };
        offset += 4;

        let pm_rewards_commitment = PMRewardCommitmentGadget::from_targets(&targets[offset..offset + PM_REWARD_COMMITMENT_TARGET_SIZE]);
        offset += PM_REWARD_COMMITMENT_TARGET_SIZE;

        let da_challenges_claimed = targets[offset..].try_into().unwrap();

        QEDCheckpointLeafStatsGadget {
            fees_collected,
            user_ops_processed,
            total_transactions,
            slots_modified,
            pm_jobs_completed,
            block_time,
            random_seed,
            pm_rewards_commitment,
            da_challenges_claimed,
        }
    }
}


impl<F: RichField> WitnessValueFor<QEDCheckpointLeafStatsGadget, F, true> for PQEDCheckpointLeafStats<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafStatsGadget) -> anyhow::Result<()>  {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<QEDCheckpointLeafStatsGadget, F, false> for PQEDCheckpointLeafStats<F, QHashOut<F>> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &QEDCheckpointLeafStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}



