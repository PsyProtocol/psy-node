
use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::{FieldQHasher, QFieldHashable}}, felt::QFelt64, protocol::core_types::QFHashBase};
use psy_core::constants::protocol::{DA_CHALLENGE_WINDOW, TODO_DEPOSIT_TREE_HEIGHT, TODO_WITHDRAWAL_TREE_HEIGHT};

use crate::v1::qdata::{checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats}, pm_jobs_completed_stats::PPMJobsCompletedStats, pm_rewards_commitment::PPMRewardCommitment};

use super::agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput;


#[pderive::serialize_clone_f_hash]
pub struct QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    pub part_1_header: QCAggUserRegistartionDeployContractsGUTAInput<F, Hash>,
    pub old_stats: PQEDCheckpointLeafStats<F, Hash>,
    pub block_time: F,
    pub final_random_seed_contribution: Hash,
    pub pm_rewards_commitment: PPMRewardCommitment<Hash>,
    pub pm_jobs_completed: PPMJobsCompletedStats<F>,
}
#[pderive::serialize_clone_f_hash]
pub struct QCQEDCheckpointStateTransitionInput<F, Hash> {
    pub partial: QCQEDCheckpointStateTransitionInputPartial<F, Hash>,
    pub append_checkpoint_tree_proof: DeltaMerkleProofCore<Hash>,
    pub previous_checkpoint_proof: MerkleProofCore<Hash>,
}

impl<F: QFelt64, Hash: QFHashBase<F>> QCQEDCheckpointStateTransitionInputPartial<F, Hash> {
    pub fn get_new_checkpoint_leaf<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeaf<F, Hash> {
        let new_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_end,
            deposit_tree_root: Hasher::get_zero_hash(TODO_DEPOSIT_TREE_HEIGHT as usize),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.new_node_value,
            withdrawal_tree_root:Hasher::get_zero_hash(TODO_WITHDRAWAL_TREE_HEIGHT as usize),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_end,
        };
        PQEDCheckpointLeaf {
            global_chain_root: new_state_roots.qfhash::<Hasher>(),
            stats: PQEDCheckpointLeafStats {
                fees_collected: self.part_1_header.guta_proof_header.stats.fees_collected,
                user_ops_processed: self.part_1_header.guta_proof_header.stats.user_ops_processed,
                total_transactions: self.part_1_header.guta_proof_header.stats.total_transactions,
                slots_modified: self.part_1_header.guta_proof_header.stats.slots_modified,
                pm_jobs_completed: self.pm_jobs_completed,
                block_time: self.block_time,
                random_seed: Hasher::two_to_one(&self.old_stats.random_seed, &self.final_random_seed_contribution),
                pm_rewards_commitment: self.pm_rewards_commitment.clone(),
                da_challenges_claimed: [F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
            }
        }

    }

    pub fn get_old_checkpoint_leaf<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointLeaf<F, Hash> {
        PQEDCheckpointLeaf {
            global_chain_root: self.get_old_state_roots::<Hasher>().qfhash::<Hasher>(),
            stats: self.old_stats,
        }
    }

    pub fn get_old_state_roots<Hasher: FieldQHasher<F, Hash>>(&self) -> PQEDCheckpointGlobalStateRoots<Hash> {
        let old_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.part_1_header.deploy_contracts_state_transition.state_transition_start,
            deposit_tree_root: Hasher::get_zero_hash(TODO_DEPOSIT_TREE_HEIGHT as usize),
            user_tree_root: self.part_1_header.guta_proof_header.state_transition.old_node_value,
            withdrawal_tree_root: Hasher::get_zero_hash(TODO_WITHDRAWAL_TREE_HEIGHT as usize),
            user_registration_tree_root: self.part_1_header.register_users_state_transition.state_transition_start,
        };
        old_state_roots
    }
}
