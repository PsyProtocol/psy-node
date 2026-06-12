use plonky2::{
    field::extension::Extendable,
    hash::hash_types::{HashOutTarget, RichField},
    iop::{target::Target, witness::Witness},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_client_data::qdata::checkpoint::PsyCheckpointLeafStats;
use psy_common_circuit::traits::{AlgebraicHashableTarget, CreatableTarget, FromTargets, ToTargets, WitnessValueFor};
use psy_config::network_constants::DA_CHALLENGE_WINDOW;

use super::{
    pm_jobs_completed_stats::{PMJobsCompletedStatsGadget, PM_JOBS_COMPLETED_STATS_TARGET_SIZE},
    pm_reward_commitment::{PMRewardCommitmentGadget, PM_REWARD_COMMITMENT_TARGET_SIZE},
};

#[derive(Clone, Debug, PartialEq, Eq, Copy)]
pub struct PsyCheckpointLeafStatsGadget {
    pub guta_fees_collected: Target,
    pub da_fees_collected: Target,

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

impl PsyCheckpointLeafStatsGadget {
    pub fn set_witness<F: RichField>(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafStats<F>) -> anyhow::Result<()> {
        witness.set_target(self.guta_fees_collected, target.guta_fees_collected)?;
        witness.set_target(self.da_fees_collected, target.da_fees_collected)?;

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
    pub fn to_hash<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(&self, builder: &mut CircuitBuilder<F, D>) -> HashOutTarget {
        builder.hash_n_to_hash_no_pad::<H>(self.to_targets())
    }
}
impl AlgebraicHashableTarget for PsyCheckpointLeafStatsGadget {
    fn to_hash_target<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> HashOutTarget {
        self.to_hash::<H, F, D>(builder)
    }
}
impl CreatableTarget for PsyCheckpointLeafStatsGadget {
    fn create_virtual<F: RichField + Extendable<D>, const D: usize>(builder: &mut CircuitBuilder<F, D>) -> Self {
        let guta_fees_collected = builder.add_virtual_target();
        let da_fees_collected = builder.add_virtual_target();
        let user_ops_processed = builder.add_virtual_target();
        let total_transactions = builder.add_virtual_target();
        let slots_modified = builder.add_virtual_target();
        let pm_jobs_completed = PMJobsCompletedStatsGadget::create_virtual(builder);
        let block_time = builder.add_virtual_target();

        let random_seed = builder.add_virtual_hash();
        let pm_rewards_commitment = PMRewardCommitmentGadget::create_virtual(builder);
        let da_challenges_claimed = builder.add_virtual_target_arr::<DA_CHALLENGE_WINDOW>();

        Self {
            guta_fees_collected,
            da_fees_collected,
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
impl ToTargets for PsyCheckpointLeafStatsGadget {
    fn to_targets(&self) -> Vec<Target> {
        let mut result = vec![
            self.guta_fees_collected,
            self.da_fees_collected,
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
impl FromTargets for PsyCheckpointLeafStatsGadget {
    fn from_targets(targets: &[Target]) -> Self {
        let expected_len = 5 + PM_JOBS_COMPLETED_STATS_TARGET_SIZE + 5 + PM_REWARD_COMMITMENT_TARGET_SIZE + DA_CHALLENGE_WINDOW;
        if targets.len() != expected_len {
            panic!(
                "Invalid number of elements for PsyCheckpointLeafStatsGadget, expected {} got {}",
                expected_len,
                targets.len()
            );
        }

        let mut offset = 0;
        let guta_fees_collected = targets[offset];
        offset += 1;
        let da_fees_collected = targets[offset];
        offset += 1;
        let user_ops_processed = targets[offset];
        offset += 1;
        let total_transactions = targets[offset];
        offset += 1;
        let slots_modified = targets[offset];
        offset += 1;

        let pm_jobs_completed = PMJobsCompletedStatsGadget::from_targets(&targets[offset..offset + PM_JOBS_COMPLETED_STATS_TARGET_SIZE]);
        offset += PM_JOBS_COMPLETED_STATS_TARGET_SIZE;

        let block_time = targets[offset];
        offset += 1;
        let random_seed = HashOutTarget {
            elements: [targets[offset], targets[offset + 1], targets[offset + 2], targets[offset + 3]],
        };
        offset += 4;

        let pm_rewards_commitment = PMRewardCommitmentGadget::from_targets(&targets[offset..offset + PM_REWARD_COMMITMENT_TARGET_SIZE]);
        offset += PM_REWARD_COMMITMENT_TARGET_SIZE;

        let da_challenges_claimed = targets[offset..].try_into().unwrap();

        PsyCheckpointLeafStatsGadget {
            guta_fees_collected,
            da_fees_collected,
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

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafStatsGadget, F, true> for PsyCheckpointLeafStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}

impl<F: RichField> WitnessValueFor<PsyCheckpointLeafStatsGadget, F, false> for PsyCheckpointLeafStats<F> {
    fn set_for_witness(&self, witness: &mut impl Witness<F>, target: &PsyCheckpointLeafStatsGadget) -> anyhow::Result<()> {
        target.set_witness(witness, self)
    }
}
