use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
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
    guta::{header::GlobalUserTreeAggregatorHeader, sub_tree_transition::SubTreeNodeStateTransition},
    prepared_block::{common::PsyCoordinatorPendingCheckpointBase, coordinator::PsyPreparedCoordinatorBlockStateUpdates},
    proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput,
    protocol::{
        circuit_inputs::{
            agg_part_1::QCAggUserRegistartionDeployContractsGUTAInput,
            checkpoint_transition::{QCQEDCheckpointStateTransitionInput, QCQEDCheckpointStateTransitionInputPartial},
        },
        verifiable_checkpoint_transition::PsyVerifiableCheckpointTransitionWithProof,
    },
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState},
        pm_jobs_completed_stats::PPMJobsCompletedStats,
        pm_rewards_commitment::PPMRewardCommitment,
        populated_checkpoint::PsyCheckpointLeafPopulated,
    },
    worker::{
        metadata::{
            PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD, PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
            PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
        },
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::coordinator::{
    processor::{
        gatherers::{
            coordinator_guta_update_gatherer::CoordinatorGUTAUpdateGathererOutput, deploy_contract_gatherer::DeployContractGathererOutput,
            register_user_gatherer::RegisterUserGathererOutput,
        },
        PsyCoordinatorProcessor,
    },
    queue_key::CoordinatorProvingWorkQueueKey,
};
fn get_current_block_time() -> u64 {
    let start = std::time::SystemTime::UNIX_EPOCH;
    let now = std::time::SystemTime::now();
    let duration = now.duration_since(start).expect("Time went backwards");
    duration.as_secs()
}
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    >
{
    pub async fn publish_worker_jobs_if_exists(
        &self,
        queue_key: &CoordinatorProvingWorkQueueKey<N::QHash, N::JobId>,
        level: usize,
        jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<()> {
        if level < jobs.len() {
            self.db
                .proof_work_queue
                .publish_many_worker_queue_items(
                    queue_key,
                    self.db.ids.realm_id_u64,
                    self.db.ids.realm_sub_id_u64,
                    self.db.ids.proc_checkpoint_unique_id,
                    0,
                    &jobs[level],
                )
                .await?;
        }
        Ok(())
    }
    pub fn get_root_job_ids(
        &self,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<Option<(QProvingJobDataID, QProvingJobDataID, QProvingJobDataID)>> {
        let guta_root_job = guta_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No GUTA jobs found at last level"))?;
        let register_user_root_job = register_user_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Register User jobs found at last level"))?;
        let deploy_contract_root_job = deploy_contract_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Deploy Contract jobs found at last level"))?;

        if guta_root_job.job_id.circuit_type == ProvingJobCircuitType::GUTANoChange
            && register_user_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
            && deploy_contract_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyBatchDeployContractsAggregate
        {
            tracing::info!("No changes detected in GUTA, Register User, and Deploy Contract jobs.");
            return Ok(None);
        }
        Ok(Some((
            guta_root_job.job_id,
            register_user_root_job.job_id,
            deploy_contract_root_job.job_id,
        )))
    }
    pub async fn publish_jobs(
        &self,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        min_level: Option<usize>,
        max_level: Option<usize>,
        wait_for_jobs_completion: bool,
    ) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        let max_level = guta_jobs
            .len()
            .max(register_user_jobs.len())
            .max(deploy_contract_jobs.len())
            .min(max_level.unwrap_or(usize::MAX));
        let min_level = min_level.unwrap_or(0).min(max_level);

        for i in min_level..max_level {
            self.publish_worker_jobs_if_exists(&queue_key, i, guta_jobs).await?;
            self.publish_worker_jobs_if_exists(&queue_key, i, register_user_jobs).await?;
            self.publish_worker_jobs_if_exists(&queue_key, i, deploy_contract_jobs).await?;
            if wait_for_jobs_completion {
                self.db
                    .proof_work_queue
                    .wait_until_all_jobs_complete_or_timeout_worker(
                        &queue_key,
                        self.db.ids.realm_id_u64,
                        self.db.ids.realm_sub_id_u64,
                        self.db.ids.proc_checkpoint_unique_id,
                        0,
                        self.proof_worker_queue_max_time_ms,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    pub async fn wait_for_jobs_completion(&self) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        Ok(())
    }
    pub async fn publish_and_wait_for_job_completion(&self, job: &PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        self.db
            .proof_work_queue
            .publish_worker_queue_item_ref(
                &queue_key,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                job,
            )
            .await?;
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        Ok(())
    }

    pub async fn get_results_from_gatherers(
        &mut self,
    ) -> anyhow::Result<(
        CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        RegisterUserGathererOutput<N::QHash, N::JobId>,
        DeployContractGathererOutput<N::QHash, N::JobId>,
    )> {
        self.db.set_new_unique_ids().await?;
        self.db.shared_status.update_status(
            self.db.ids.gathering_unique_pending_id,
            self.db.ids.checkpoint_id,
            self.db.last_committed.checkpoint_leaf.clone(),
            self.db.last_committed.checkpoint_state_roots.clone(),
            self.db.last_committed.l2_state.clone(),
            self.db.needs_revert,
        )?;
        if self.db.needs_revert {
            self.db.needs_revert = false;
        }

        let (guta_result, register_users_result, deploy_contract_result) = tokio::try_join!(
            self.guta_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
            self.register_user_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
            self.deploy_contract_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
        )?;
        Ok((guta_result, register_users_result, deploy_contract_result))
    }
    pub async fn plan_agg_guta_register_users_deploy_contracts_job(
        &self,
        guta_gatherer_result: &CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: &RegisterUserGathererOutput<N::QHash, N::JobId>,
        deploy_contract_gatherer_result: &DeployContractGathererOutput<N::QHash, N::JobId>,
    ) -> anyhow::Result<(
        PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>,
        QCAggUserRegistartionDeployContractsGUTAInput<N::F, N::QHash>,
    )> {
        let total_guta_jobs = guta_gatherer_result.job_ids.iter().map(|level| level.len()).sum::<usize>();
        let total_register_user_jobs = register_users_gatherer_result.job_ids.iter().map(|level| level.len()).sum::<usize>();
        let total_deploy_contract_jobs = deploy_contract_gatherer_result.job_ids.iter().map(|level| level.len()).sum::<usize>();

        let witness = QCAggUserRegistartionDeployContractsGUTAInput {
            register_users_state_transition: AggStateTransitionWithStats {
                state_transition_start: register_users_gatherer_result.db_output.start_user_registration_tree_hash,
                state_transition_end: register_users_gatherer_result.db_output.end_user_registration_tree_hash,
                total_proofs_generated: total_register_user_jobs as u64,
            },
            deploy_contracts_state_transition: AggStateTransitionWithStats {
                state_transition_start: deploy_contract_gatherer_result.db_output.start_global_contract_tree_root,
                state_transition_end: deploy_contract_gatherer_result.db_output.end_global_contract_tree_root,
                total_proofs_generated: total_deploy_contract_jobs as u64,
            },
            guta_proof_header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: self.db.circuit_fingerprint_config.guta_circuit_whitelist_root,
                checkpoint_tree_root: self.db.last_committed.checkpoint_root,
                stats: guta_gatherer_result.db_output.guta_stats,
                total_aggregation_proofs_generated: N::F::from_u64_value(total_guta_jobs as u64),
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: guta_gatherer_result.db_output.start_global_user_tree_root,
                    new_node_value: guta_gatherer_result.db_output.end_global_user_tree_root,
                    node_index: N::F::from_u64_value(0),
                    node_level: N::F::from_u64_value(0),
                },
            },
        };

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

        let job_id = QProvingJobDataID::block_agg_state_part_1_input_witness(self.db.ids.unique_pending_id, 0).get_output_id();
        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: witness.get_public_inputs_hash_no_rewards_tag::<N::HasherBase>(),
                reward_tree_node_index: 0,
                reward_tree_node_level: 1,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD,
                reward_tree_node_children: 3,
                dependencies: vec![root_guta_job.job_id, root_register_user_job.job_id, root_deploy_contract_job.job_id],
            },
        };
        let witness_data = witness.psy_ser_to_bytes_vec()?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, vec![(job_id, witness_data)])
            .await?;
        Ok((job_metadata, witness))
    }

    pub async fn plan_checkpoint_state_transition(
        &self,
        guta_gatherer_result: CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
        register_users_gatherer_result: RegisterUserGathererOutput<N::QHash, N::JobId>,
        deploy_contract_gatherer_result: DeployContractGathererOutput<N::QHash, N::JobId>,
        part_1_header: QCAggUserRegistartionDeployContractsGUTAInput<N::F, N::QHash>,
    ) -> anyhow::Result<(PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>, Vec<u8>)> {
        let checkpoint_state_roots = PQEDCheckpointGlobalStateRoots {
            contract_tree_root: deploy_contract_gatherer_result.db_output.end_global_contract_tree_root,
            deposit_tree_root: self.db.last_committed.checkpoint_state_roots.deposit_tree_root,
            user_tree_root: guta_gatherer_result.db_output.end_global_user_tree_root,
            withdrawal_tree_root: self.db.last_committed.checkpoint_state_roots.withdrawal_tree_root,
            user_registration_tree_root: self.db.last_committed.checkpoint_state_roots.user_registration_tree_root,
        };
        let agg_part_1_job_id =
            QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0).get_output_id();

        let agg_part_1_reward_tree_value = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, agg_part_1_job_id)
            .await?;
        if agg_part_1_reward_tree_value.is_none() {
            anyhow::bail!("Missing reward tree value for agg part 1 job");
        }
        let agg_part_1_reward_tree_value = agg_part_1_reward_tree_value.unwrap();

        let mut checkpoint_leaf_stats = PQEDCheckpointLeafStats {
            fees_collected: guta_gatherer_result.db_output.guta_stats.fees_collected,
            user_ops_processed: guta_gatherer_result.db_output.guta_stats.user_ops_processed,
            total_transactions: guta_gatherer_result.db_output.guta_stats.total_transactions,
            slots_modified: guta_gatherer_result.db_output.guta_stats.slots_modified,
            pm_jobs_completed: PPMJobsCompletedStats {
                deploy_contracts_completed: N::F::from_u64_value(part_1_header.deploy_contracts_state_transition.total_proofs_generated),
                register_users_completed: N::F::from_u64_value(part_1_header.register_users_state_transition.total_proofs_generated),
                gutas_completed: part_1_header.guta_proof_header.total_aggregation_proofs_generated,
            },
            block_time: N::F::from_u64_value(get_current_block_time()),
            random_seed: guta_gatherer_result.db_output.random_seed_guta,
            pm_rewards_commitment: PPMRewardCommitment {
                register_users_root: agg_part_1_reward_tree_value,
                gutas_root: agg_part_1_reward_tree_value,
                deploy_contracts_root: agg_part_1_reward_tree_value,
            },
            da_challenges_claimed: [N::F::ZERO_VALUE; DA_CHALLENGE_WINDOW],
        };
        let new_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: checkpoint_state_roots.qfhash::<N::HasherBase>(),
            stats: checkpoint_leaf_stats.clone(),
        };
        let new_checkpoint_leaf_hash = new_checkpoint_leaf.qfhash::<N::HasherBase>();
        let previous_checkpoint_proof = self
            .db
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(self.db.ids.checkpoint_id);
        let current_checkpoint_proof = self
            .db
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(self.db.ids.next_checkpoint_id);
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<N::QHash, N::HasherBase>(
            new_checkpoint_leaf_hash,
            self.db.ids.next_checkpoint_id,
            &current_checkpoint_proof.siblings,
        );

        let append_checkpoint_tree_proof = DeltaMerkleProofCore {
            siblings: current_checkpoint_proof.siblings,
            old_root: current_checkpoint_proof.root,
            new_root: new_checkpoint_tree_root,
            old_value: N::QHash::get_zero_value(),
            new_value: new_checkpoint_leaf_hash,
            index: self.db.ids.next_checkpoint_id,
        };
        let witness = QCQEDCheckpointStateTransitionInput::<N::F, N::QHash> {
            partial: QCQEDCheckpointStateTransitionInputPartial {
                pm_jobs_completed: PPMJobsCompletedStats {
                    deploy_contracts_completed: N::F::from_u64_value(part_1_header.deploy_contracts_state_transition.total_proofs_generated),
                    register_users_completed: N::F::from_u64_value(part_1_header.register_users_state_transition.total_proofs_generated),
                    gutas_completed: part_1_header.guta_proof_header.total_aggregation_proofs_generated,
                },
                part_1_header: part_1_header,
                old_stats: self.db.last_committed.checkpoint_leaf_stats.clone(),
                block_time: N::F::from_u64_value(get_current_block_time()),
                final_random_seed_contribution: guta_gatherer_result.db_output.random_seed_guta,
            },
            append_checkpoint_tree_proof,
            previous_checkpoint_proof,
            last_old_checkpoint_tree_leaf_hash: self.db.last_committed.checkpoint_state_transition.old_checkpoint_leaf_hash,
            last_old_checkpoint_tree_root_hash: self.db.last_committed.checkpoint_state_transition.old_checkpoint_tree_root,
            genesis_checkpoint_state_transition_hash: self.db.genesis_checkpoint_state_transition_hash,
        };
        let witness_bytes = witness.psy_ser_to_bytes_vec()?;
        let expected_public_inputs = witness.get_public_inputs_hash_with_fingerprint::<N::HasherBase>(
            self.db.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        );
        let last_checkpoint_state_transition_proof_job_id = if self.db.ids.checkpoint_id == 0 {
            QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0)
        } else {
            QProvingJobDataID::new_proof_job_id(
                self.db.ids.unique_pending_id,
                0,
                ProvingJobCircuitType::GenerateRollupStateTransitionProof,
                0,
                0,
            )
        };
        if self.db.ids.checkpoint_id != 0 {
            let proof: PsyVerifiableCheckpointTransitionWithProof<N::F, N::QHash> = self
                .db
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(self.db.ids.checkpoint_id)
                .await?;
            self.db
                .proof_store
                .put_proof_bytes_for_job_id(last_checkpoint_state_transition_proof_job_id, &proof.zk_proof)
                .await?;
        }
        let job_id = QProvingJobDataID::new_proof_job_id(
            self.db.ids.unique_pending_id,
            0,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof,
            0,
            0,
        );

        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_public_inputs,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
                reward_tree_node_children: 0,
                dependencies: vec![last_checkpoint_state_transition_proof_job_id, agg_part_1_job_id],
            },
        };
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
                vec![(job_id, witness_bytes)],
            )
            .await?;
        self.publish_and_wait_for_job_completion(&job_metadata).await?;

        let reward_root: Option<N::QHash> = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, job_id)
            .await?;
        if reward_root.is_none() {
            anyhow::bail!("Missing reward tree value for checkpoint state transition job");
        }
        let reward_root = reward_root.unwrap();

        checkpoint_leaf_stats.pm_rewards_commitment = PPMRewardCommitment {
            register_users_root: reward_root,
            gutas_root: reward_root,
            deploy_contracts_root: reward_root,
        };
        let new_checkpoint_leaf = PQEDCheckpointLeaf {
            global_chain_root: new_checkpoint_leaf.global_chain_root,
            stats: checkpoint_leaf_stats,
        };
        let new_checkpoint_leaf_hash = new_checkpoint_leaf.qfhash::<N::HasherBase>();
        let new_checkpoint_tree_root = compute_root_merkle_proof_generic::<N::QHash, N::HasherBase>(
            new_checkpoint_leaf_hash,
            self.db.ids.checkpoint_id + 1,
            &witness.append_checkpoint_tree_proof.siblings,
        );

        let append_checkpoint_tree_proof = DeltaMerkleProofCore {
            siblings: witness.append_checkpoint_tree_proof.siblings,
            old_root: current_checkpoint_proof.root,
            new_root: new_checkpoint_tree_root,
            old_value: N::QHash::get_zero_value(),
            new_value: new_checkpoint_leaf_hash,
            index: self.db.ids.checkpoint_id + 1,
        };
        let checkpoint_zk_proof: Option<Vec<u8>> = self.db.proof_store.get_proof_bytes_by_job_id(job_id).await?;
        if checkpoint_zk_proof.is_none() {
            anyhow::bail!("Missing zk proof for checkpoint state transition job");
        }
        let checkpoint_zk_proof = checkpoint_zk_proof.unwrap();
        let output = PsyPreparedCoordinatorBlockStateUpdates {
            coordinator_id: self.db.ids.realm_id_u64,
            checkpoint_id: self.db.ids.checkpoint_id + 1,
            unique_pending_id: self.db.ids.unique_pending_id,
            proc_checkpoint_unique_id: self.db.ids.proc_checkpoint_unique_id,
            old_base: PsyCoordinatorPendingCheckpointBase {
                block_state: self.db.last_committed.l2_state.clone(),
                checkpoint_leaf: PsyCheckpointLeafPopulated {
                    global_state_roots: self.db.last_committed.checkpoint_state_roots,
                    stats: self.db.last_committed.checkpoint_leaf_stats.clone(),
                },
                checkpoint_leaf_hash: self.db.last_committed.checkpoint_leaf.qfhash::<N::HasherBase>(),
                checkpoint_tree_root: self.db.last_committed.checkpoint_root,
            },
            new_base: PsyCoordinatorPendingCheckpointBase {
                block_state: QEDL2BlockState {
                    checkpoint_id: self.db.ids.checkpoint_id + 1,
                    next_add_withdrawal_id: self.db.last_committed.l2_state.next_add_withdrawal_id,
                    next_process_withdrawal_id: self.db.last_committed.l2_state.next_process_withdrawal_id,
                    next_deposit_id: self.db.last_committed.l2_state.next_deposit_id,
                    total_deposits_claimed_epoch: self.db.last_committed.l2_state.total_deposits_claimed_epoch,

                    next_user_id: register_users_gatherer_result.db_output.next_user_id,
                    end_balance: self.db.last_committed.l2_state.end_balance,
                    next_contract_id: deploy_contract_gatherer_result.db_output.next_contract_id as u32,
                },
                checkpoint_leaf: PsyCheckpointLeafPopulated {
                    global_state_roots: checkpoint_state_roots,
                    stats: checkpoint_leaf_stats,
                },
                checkpoint_leaf_hash: new_checkpoint_leaf_hash,
                checkpoint_tree_root: new_checkpoint_tree_root,
            },

            update_global_contract_tree_nodes_ffs: deploy_contract_gatherer_result.db_output.update_global_contract_tree_nodes_ffs,
            update_contract_function_tree_nodes_ffs: deploy_contract_gatherer_result.db_output.update_contract_function_tree_nodes_ffs,
            new_contract_leaves_ffs: deploy_contract_gatherer_result.db_output.new_contract_leaves_ffs,
            new_contract_code_definitions: deploy_contract_gatherer_result.db_output.new_contract_code_definitions,

            update_global_user_tree_nodes_ffs: guta_gatherer_result.db_output.update_global_user_tree_nodes_ffs,

            update_user_registration_tree_nodes_ffs: register_users_gatherer_result.db_output.update_user_registration_tree_nodes_ffs,
            new_user_public_keys_ffs: register_users_gatherer_result.db_output.new_user_public_keys_ffs,
            new_public_key_hash_to_user_id_rows_ffs: register_users_gatherer_result.db_output.new_public_key_hash_to_user_id_rows_ffs,

            checkpoint_tree_update_proof: append_checkpoint_tree_proof,
        };

        Ok((output, checkpoint_zk_proof))
    }
    pub async fn plan_genesis_checkpoint_state_transition_proof(&self) -> anyhow::Result<()> {
        let witness = PsyCheckpointStateTransitionGenesisCircuitInput::<N::QHash> {
            genesis_checkpoint_state_transition_hash: self.db.genesis_checkpoint_state_transition_hash,
            checkpoint_state_transition_circuit_fingerprint: self.db.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        };
        let expected_public_inputs = witness.get_public_inputs_hash_no_rewards_tag::<N::HasherBase>();
        let job_id = QProvingJobDataID::new_proof_job_id(0, 0, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, 0, 0);
        let job_metadata = PsyProvingJobMetadataWithJobId {
            job_id,
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: expected_public_inputs,
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                reward_tree_node_children: 0,
                dependencies: vec![],
            },
        };
        let witness_data = witness.psy_ser_into_bytes_vec()?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, vec![(job_id, witness_data)])
            .await?;
        self.db
            .proof_work_queue
            .publish_worker_queue_item_ref(
                &self.db.get_proof_worker_queue_key(),
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                &job_metadata,
            )
            .await?;

        Ok(())
    }

    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        let (guta_gatherer_result, register_users_gatherer_result, deploy_contract_gatherer_result) = self.get_results_from_gatherers().await?;

        let has_jobs = self.get_root_job_ids(
            &guta_gatherer_result.job_ids,
            &register_users_gatherer_result.job_ids,
            &deploy_contract_gatherer_result.job_ids,
        )?;
        if has_jobs.is_none() {
            tracing::info!("No jobs to process in this block, skipping.");
            return Ok(());
        }

        // publish the first level of jobs
        self.publish_jobs(
            &guta_gatherer_result.job_ids,
            &register_users_gatherer_result.job_ids,
            &deploy_contract_gatherer_result.job_ids,
            Some(0),
            Some(1),
            false,
        )
        .await?;
        if self.db.ids.checkpoint_id == 0 {
            self.plan_genesis_checkpoint_state_transition_proof().await?;
        }

        // while the first level of jobs are processing, plan the agg job
        let (agg_job_metadata, part_1_witness) = self
            .plan_agg_guta_register_users_deploy_contracts_job(
                &guta_gatherer_result,
                &register_users_gatherer_result,
                &deploy_contract_gatherer_result,
            )
            .await?;

        // wait for the first level of jobs to finish
        self.wait_for_jobs_completion().await?;

        // publish the rest of the jobs and wait for them to finish
        self.publish_jobs(
            &guta_gatherer_result.job_ids,
            &register_users_gatherer_result.job_ids,
            &deploy_contract_gatherer_result.job_ids,
            Some(1),
            None,
            true,
        )
        .await?;

        // wait for the Aggregate GUTA, User Registation and Deploy Contracts Proof to
        // finish being proved
        self.publish_and_wait_for_job_completion(&agg_job_metadata).await?;
        let (coordinator_update, zk_proof) = self
            .plan_checkpoint_state_transition(
                guta_gatherer_result,
                register_users_gatherer_result,
                deploy_contract_gatherer_result,
                part_1_witness,
            )
            .await?;

        self.db
            .commit_state(coordinator_update, ProvingJobCircuitType::GenerateRollupStateTransitionProof, zk_proof)
            .await?;

        Ok(())
    }
}
