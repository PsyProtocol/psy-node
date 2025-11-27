use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{
        merkle_proof::{compute_root_merkle_proof_generic, DeltaMerkleProofCore},
        traits::{QFieldHashable, ZeroableHash},
    },
    felt::{FromPrimitiveValuesFelt, ZeroableFelt},
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::{
    constants::protocol::DA_CHALLENGE_WINDOW,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    agg::AggStateTransitionWithStats,
    config::network_config::PsyNodeCircuitFingerprintConfig,
    guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition},
    node::coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState},
    protocol::circuit_inputs::{
        agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
        checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial},
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats},
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        pm_rewards_commitment::PPMRewardCommitment,
    },
    worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::coordinator::processor::gatherers::{
    coordinator_guta_update_gatherer::CoordinatorGUTAUpdateGathererOutput, deploy_contract_gatherer::DeployContractGathererOutput,
    register_user_gatherer::RegisterUserGathererOutput,
};

fn get_current_block_time() -> u64 {
    let start = std::time::SystemTime::UNIX_EPOCH;
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(start).expect("Time went backwards");
    duration.as_secs()
}
pub struct CoordinatorOutputBuilderInput<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> {
    pub guta_gatherer_result: CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
    pub register_users_gatherer_result: RegisterUserGathererOutput<N::QHash, N::JobId>,
    pub deploy_contract_gatherer_result: DeployContractGathererOutput<N::QHash, N::JobId>,
}

pub struct CoordinatorOutputBuilder<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> {
    pub guta_gatherer_result: CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
    pub register_users_gatherer_result: RegisterUserGathererOutput<N::QHash, N::JobId>,
    pub deploy_contract_gatherer_result: DeployContractGathererOutput<N::QHash, N::JobId>,

    pub total_guta_jobs: usize,
    pub total_register_user_jobs: usize,
    pub total_deploy_contract_jobs: usize,

    pub root_guta_job_id: N::JobId,
    pub root_register_user_job_id: N::JobId,
    pub root_deploy_contract_job_id: N::JobId,

    pub agg_state_part_1_job_id: N::JobId,
    pub checkpoint_state_transition_job_id: N::JobId,
    pub last_checkpoint_state_transition_job_id: N::JobId,
}

impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID>> CoordinatorOutputBuilder<N> {
    pub fn new(
        coordinator_ids: &CoordinatorProcessorIdState,
        guta_gatherer_result: CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: RegisterUserGathererOutput<N::QHash, N::JobId>,
        deploy_contract_gatherer_result: DeployContractGathererOutput<N::QHash, N::JobId>,
    ) -> anyhow::Result<Self> {
        let root_guta_job = guta_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found at last level"))?;
        let root_register_user_job = register_users_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found at last level"))?;
        let root_deploy_contract_job = deploy_contract_gatherer_result
            .job_ids
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found at last level"))?;
        let total_guta_jobs = guta_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_register_user_jobs = register_users_gatherer_result.job_ids.iter().map(|level| level.len()).sum();
        let total_deploy_contract_jobs = deploy_contract_gatherer_result.job_ids.iter().map(|level| level.len()).sum();

        let last_checkpoint_state_transition_job_id = if coordinator_ids.checkpoint_id == 0 {
            QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0)
        } else {
            QProvingJobDataID::new_proof_job_id(
                coordinator_ids.unique_pending_id - 1,
                0,
                ProvingJobCircuitType::GenerateRollupStateTransitionProof,
                0,
                0,
            )
        }
        .get_output_id();
        let agg_state_part_1_job_id = QProvingJobDataID::block_agg_state_part_1_input_witness(coordinator_ids.unique_pending_id, 0).get_output_id();
        let checkpoint_state_transition_job_id = QProvingJobDataID::new_proof_job_id(
            coordinator_ids.unique_pending_id - 1,
            0,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof,
            0,
            0,
        )
        .get_output_id();
        Ok(Self {
            total_guta_jobs,
            total_register_user_jobs,
            total_deploy_contract_jobs,
            root_guta_job_id: root_guta_job.job_id,
            root_register_user_job_id: root_register_user_job.job_id,
            root_deploy_contract_job_id: root_deploy_contract_job.job_id,
            agg_state_part_1_job_id,
            checkpoint_state_transition_job_id,
            last_checkpoint_state_transition_job_id,
            guta_gatherer_result,
            register_users_gatherer_result,
            deploy_contract_gatherer_result,
        })
    }
    pub fn get_part_1_header(
        &self,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
    ) -> QCAggUserRegistartionDeployContractsGUTAInput<N::F, N::QHash> {
        let witness = QCAggUserRegistartionDeployContractsGUTAInput {
            register_users_state_transition: AggStateTransitionWithStats {
                state_transition_start: self.register_users_gatherer_result.db_output.start_user_registration_tree_hash,
                state_transition_end: self.register_users_gatherer_result.db_output.end_user_registration_tree_hash,
                total_proofs_generated: self.total_register_user_jobs as u64,
            },
            deploy_contracts_state_transition: AggStateTransitionWithStats {
                state_transition_start: self.deploy_contract_gatherer_result.db_output.start_global_contract_tree_root,
                state_transition_end: self.deploy_contract_gatherer_result.db_output.end_global_contract_tree_root,
                total_proofs_generated: self.total_deploy_contract_jobs as u64,
            },
            guta_proof_header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: circuit_fingerprint_config.guta_circuit_whitelist_root,
                checkpoint_tree_root: last_committed.checkpoint_root,
                stats: self.guta_gatherer_result.db_output.guta_stats,
                total_aggregation_proofs_generated: N::F::from_u64_value(self.total_guta_jobs as u64),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: self.guta_gatherer_result.db_output.start_global_user_tree_root,
                    new_node_value: self.guta_gatherer_result.db_output.end_global_user_tree_root,
                    node_index: N::F::from_u64_value(0),
                    node_level: N::F::from_u64_value(0),
                },
            },
        };
        witness
    }

    pub fn get_agg_guta_register_users_deploy_contracts_job(
        &self,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
    ) -> anyhow::Result<(PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>, (N::JobId, Vec<u8>))> {
        let witness = self.get_part_1_header(last_committed, circuit_fingerprint_config);

        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id: self.agg_state_part_1_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: witness.get_public_inputs_hash_no_rewards_tag::<N::HasherBase>(),
                reward_tree_node_index: 0,
                reward_tree_node_level: 1,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD,
                reward_tree_node_children: 3,
                dependencies: vec![self.root_guta_job_id, self.root_register_user_job_id, self.root_deploy_contract_job_id],
            },
        };

        Ok((
            job_metadata,
            (self.agg_state_part_1_job_id.get_input_witness_id(), witness.psy_ser_into_bytes_vec()?),
        ))
    }

    pub fn get_checkpoint_state_transition_witness(
        &self,
        checkpoint_id: u64,
        next_checkpoint_id: u64,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
        reward_tree_root: N::QHash,
        genesis_checkpoint_state_transition_hash: N::QHash,
    ) -> anyhow::Result<QCQEDCheckpointStateTransitionInput<N::F, N::QHash>> {
        let checkpoint_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: self.deploy_contract_gatherer_result.db_output.end_global_contract_tree_root,
            deposit_tree_root: last_committed.checkpoint_state_roots.deposit_tree_root,
            user_tree_root: self.guta_gatherer_result.db_output.end_global_user_tree_root,
            withdrawal_tree_root: last_committed.checkpoint_state_roots.withdrawal_tree_root,
            user_registration_tree_root: self.register_users_gatherer_result.db_output.end_user_registration_tree_hash,
        };
        let checkpoint_leaf_stats = PQEDCheckpointLeafStats {
            fees_collected: self.guta_gatherer_result.db_output.guta_stats.fees_collected,
            user_ops_processed: self.guta_gatherer_result.db_output.guta_stats.user_ops_processed,
            total_transactions: self.guta_gatherer_result.db_output.guta_stats.total_transactions,
            slots_modified: self.guta_gatherer_result.db_output.guta_stats.slots_modified,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: N::F::from_u64_value(self.total_deploy_contract_jobs as u64),
                register_users_completed: N::F::from_u64_value(self.total_register_user_jobs as u64),
                gutas_completed: N::F::from_u64_value(self.total_guta_jobs as u64),
            },
            block_time: N::F::from_u64_value(get_current_block_time()),
            random_seed: self.guta_gatherer_result.db_output.random_seed_guta,
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: reward_tree_root,
                gutas_root: reward_tree_root,
                deploy_contracts_root: reward_tree_root,
            },
            da_challenges_claimed: [N::F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        };
        let new_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: checkpoint_state_roots.qfhash::<N::HasherBase>(),
            stats: checkpoint_leaf_stats.clone(),
        };
        let new_checkpoint_leaf_hash = new_checkpoint_leaf.qfhash::<N::HasherBase>();
        let previous_checkpoint_proof = checkpoint_tree.get_leaf(checkpoint_id);
        let current_checkpoint_proof = checkpoint_tree.get_leaf(next_checkpoint_id);
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<N::QHash, N::HasherBase>(
            new_checkpoint_leaf_hash,
            next_checkpoint_id,
            &current_checkpoint_proof.siblings,
        );
        let append_checkpoint_tree_proof = DeltaMerkleProofCore {
            siblings: current_checkpoint_proof.siblings,
            old_root: current_checkpoint_proof.root,
            new_root: new_checkpoint_tree_root,
            old_value: N::QHash::get_zero_value(),
            new_value: new_checkpoint_leaf_hash,
            index: next_checkpoint_id,
        };
        let witness = QCQEDCheckpointStateTransitionInput::<N::F, N::QHash> {
            partial: QCQEDCheckpointStateTransitionInputPartial {
                pm_jobs_completed: PPMJobsCompletedStats {
                    deploy_contracts_completed: N::F::from_u64_value(self.total_deploy_contract_jobs as u64),
                    register_users_completed: N::F::from_u64_value(self.total_register_user_jobs as u64),
                    gutas_completed: N::F::from_u64_value(self.total_guta_jobs as u64),
                },
                part_1_header: self.get_part_1_header(last_committed, circuit_fingerprint_config),
                old_stats: last_committed.checkpoint_leaf_stats.clone(),
                block_time: N::F::from_u64_value(get_current_block_time()),
                final_random_seed_contribution: self.guta_gatherer_result.db_output.random_seed_guta,
            },
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            last_old_checkpoint_tree_leaf_hash: last_committed.checkpoint_state_transition.old_checkpoint_leaf_hash,
            last_old_checkpoint_tree_root_hash: last_committed.checkpoint_state_transition.old_checkpoint_tree_root,
            genesis_checkpoint_state_transition_hash: genesis_checkpoint_state_transition_hash,
        };
        Ok(witness)
    }

    pub fn get_checkpoint_state_transition_job(
        &self,
        checkpoint_id: u64,
        next_checkpoint_id: u64,
        checkpoint_tree: &PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>,
        last_committed: &CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
        circuit_fingerprint_config: &PsyNodeCircuitFingerprintConfig<N::QHash>,
        agg_part_1_reward_tree_value: N::QHash,
        genesis_checkpoint_state_transition_hash: N::QHash,
    ) -> anyhow::Result<(PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>, (N::JobId, Vec<u8>))> {
        let witness = self.get_checkpoint_state_transition_witness(
            checkpoint_id,
            next_checkpoint_id,
            checkpoint_tree,
            last_committed,
            circuit_fingerprint_config,
            agg_part_1_reward_tree_value,
            genesis_checkpoint_state_transition_hash,
        )?;
        let witness_bytes = witness.psy_ser_to_bytes_vec()?;
        let expected_public_inputs = witness
            .get_public_inputs_hash_with_fingerprint::<N::HasherBase>(circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint);
        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id: self.checkpoint_state_transition_job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_public_inputs,
                reward_tree_node_index: 0,
                reward_tree_node_level: 1,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                reward_tree_node_children: 2,
                dependencies: vec![self.agg_state_part_1_job_id, self.last_checkpoint_state_transition_job_id],
            },
        };

        Ok((
            job_metadata,
            (self.checkpoint_state_transition_job_id.get_input_witness_id(), witness_bytes),
        ))
    }
}
