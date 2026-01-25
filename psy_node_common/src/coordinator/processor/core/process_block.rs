use cf_utils::timer::TraceTimer;
use parth_core::{
    data::queue::queue_key::QPBaseQueueType,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput,
    v1::qdata::{contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo},
    worker::{
        metadata::{PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    }
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

use crate::{
    backup::output::coordinator_output_builder::CoordinatorOutputBuilder,
    coordinator::{
        processor::PsyCoordinatorProcessor,
        queue_key::{
            CoordinatorProvingWorkQueueKey,
            CoordinatorSubmitRealmGUTAUpdateQueueKey,
            CoordinatorRegisterUserPublicKeyQueueKey,
            CoordinatorDeployContractQueueKey,
        },
    },
};
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
            println!("Publishing {} jobs at level {}", jobs[level].len(), level);
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
        proving_state: &mut PsyNodeProvingState,
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
            proving_state.set_current_proving_level(i as u8);
            self.db.temp_db.set_psy_node_proving_state(&self.db.ids.realm_identifier, &proving_state).await?;
            tokio::try_join!(
                self.publish_worker_jobs_if_exists(&queue_key, i, guta_jobs),
                self.publish_worker_jobs_if_exists(&queue_key, i, register_user_jobs),
                self.publish_worker_jobs_if_exists(&queue_key, i, deploy_contract_jobs),
            )?;
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
        println!("Publishing job id: {:?}", job.job_id);
        println!("self.db.ids.proc_checkpoint_unique_id: {:?}", self.db.ids.proc_checkpoint_unique_id);
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

    pub async fn get_results_from_gatherers(&mut self) -> anyhow::Result<(
        PsyNodeProvingState,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        CoordinatorOutputBuilder<N>
    )> {
        if self.db.ids.gathering_proc_checkpoint_unique_id == self.db.ids.proc_checkpoint_unique_id || self.db.ids.gathering_unique_pending_id == self.db.ids.unique_pending_id {
            tracing::info!("detected gathering unique ids: gathering_proc_checkpoint_unique_id = {}, current proc_checkpoint_unique_id = {}, gathering_unique_pending_id = {}, current unique_pending_id = {}. Updating unique ids before gathering results.", self.db.ids.gathering_proc_checkpoint_unique_id, self.db.ids.proc_checkpoint_unique_id, self.db.ids.gathering_unique_pending_id, self.db.ids.unique_pending_id);
            if self.db.ids.checkpoint_id == 0 {
                tracing::info!("At genesis checkpoint, setting unique ids ahead of genesis.");

                // Ensure streams exist first  
                self.db.guta_update_queue.ensure_stream().await?;
                self.db.register_user_queue.ensure_stream().await?;
                self.db.deploy_contract_queue.ensure_stream().await?;
                self.db.proof_work_queue.ensure_stream().await?;

                // Create consumers for both processing and gathering proc_checkpoint_unique_id in genesis
                let realm_id = self.db.ids.realm_id_u64;
                let realm_sub_id = self.db.ids.realm_sub_id_u64;
                let unique_id = self.db.ids.proc_checkpoint_unique_id;

                // Create keys for all queue types
                let guta_processing_key = CoordinatorSubmitRealmGUTAUpdateQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<N::F, N::QHash>>,
                };
                let user_reg_processing_key = CoordinatorRegisterUserPublicKeyQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PZKPublicKeyInfo<N::QHash>>,
                };
                let deploy_processing_key = CoordinatorDeployContractQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyDeployContractQueueItem<N::F, N::QHash>>,
                };
                let proof_processing_key = CoordinatorProvingWorkQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
                };

                // Create all consumers
                self.db.guta_update_queue.ensure_consumer(&guta_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.register_user_queue.ensure_consumer(&user_reg_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.deploy_contract_queue.ensure_consumer(&deploy_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.proof_work_queue.ensure_consumer(&proof_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;

                self.db.set_new_unique_ids().await?;
                self.db.shared_status.update_status(
                    self.db.ids.gathering_unique_pending_id,
                    self.db.ids.checkpoint_id,
                    self.db.last_committed.checkpoint_leaf.clone(),
                    self.db.last_committed.checkpoint_state_roots.clone(),
                    self.db.last_committed.l2_state.clone(),
                    self.db.needs_revert,
                )?;

                let (_, _, _) = tokio::try_join!(
                    self.guta_queue_gatherer
                        .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
                    self.register_user_queue_gatherer
                        .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
                    self.deploy_contract_queue_gatherer
                        .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
                )?;
            }else{
                anyhow::bail!("Cannot gather results when unique ids have not been updated.");
            }
        }
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

        /*
        tracing::info!("Gathering results from GUTA, Register Users, and Deploy Contracts gatherers...");
        let guta_result = self.guta_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("GUTA gatherer results obtained.");
        let deploy_contract_result = self.deploy_contract_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Deploy Contracts gatherer results obtained.");
        let register_users_result = self.register_user_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Register Users gatherer results obtained.");
        */

        Ok(CoordinatorOutputBuilder::new(
            &self.db.ids,
            guta_result,
            register_users_result,
            deploy_contract_result,
        )?)
    }
    pub async fn plan_agg_guta_register_users_deploy_contracts_job(
        &self,
        output_builder: &mut CoordinatorOutputBuilder<N>,
    ) -> anyhow::Result<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> {
        let (job_metadata, job_and_witness_bytes) =
            output_builder.get_agg_guta_register_users_deploy_contracts_job(&self.db.last_committed, &self.db.circuit_fingerprint_config)?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, vec![job_and_witness_bytes])
            .await?;
        Ok(job_metadata)
    }

    pub async fn plan_checkpoint_state_transition(
        &self,
        mut output_builder: CoordinatorOutputBuilder<N>,
    ) -> anyhow::Result<(PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>, Vec<u8>)> {
        let block_time = output_builder.register_users_gatherer_result.block_time;
        let agg_part_1_reward_root: Option<N::QHash> = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
                output_builder.agg_state_part_1_job_id.get_output_id(),
            )
            .await?;
        if agg_part_1_reward_root.is_none() {
            anyhow::bail!("Missing reward tree value for checkpoint state transition job");
        }
        let agg_part_1_reward_root = agg_part_1_reward_root.unwrap();
        let (job_metadata, job_and_witness_bytes) = output_builder.get_checkpoint_state_transition_job(
            self.db.ids.checkpoint_id,
            self.db.ids.checkpoint_id + 1,
            &self.db.checkpoint_tree_backup_manager.checkpoint_tree,
            &self.db.last_committed,
            &self.db.circuit_fingerprint_config,
            agg_part_1_reward_root,
            self.db.genesis_checkpoint_state_transition_hash,
            block_time,
        )?;

        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, self.db.ids.unique_pending_id, vec![job_and_witness_bytes])
            .await?;
        self.publish_and_wait_for_job_completion(&job_metadata).await?;
        tracing::info!("Checkpoint State Transition Proof job completed, retrieving results...");

        let reward_root: Option<N::QHash> = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
                job_metadata.job_id.get_output_id(),
            )
            .await?;
        if reward_root.is_none() {
            tracing::error!("Failed to retrieve reward root for checkpoint state transition job id: {:?}", job_metadata.job_id);
            anyhow::bail!("Missing reward tree value for checkpoint state transition job");
        }
        let reward_root = reward_root.unwrap();
        let checkpoint_zk_proof: Option<Vec<u8>> = self.db.proof_store.get_proof_bytes_by_job_id(job_metadata.job_id.get_output_id()).await?;
        if checkpoint_zk_proof.is_none() {
            tracing::error!("Failed to retrieve zk proof for checkpoint state transition job id: {:?}", job_metadata.job_id);
            anyhow::bail!("Missing zk proof for checkpoint state transition job");
        }
        let checkpoint_zk_proof = checkpoint_zk_proof.unwrap();
        tracing::info!("Retrieved checkpoint zk proof of size: {} bytes", checkpoint_zk_proof.len());
        let output = output_builder.finalize(&self.db.ids, &self.db.last_committed, reward_root, block_time)?;
        tracing::info!("Finalized coordinator block state updates.");
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
        let mut timer = TraceTimer::new("process_block");
        tracing::info!("Starting to process new coordinator block with checkpoint_id = {}...", self.db.ids.next_checkpoint_id);
        let (mut proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, mut output_builder) = self.get_results_from_gatherers().await?;

        timer.lap("get_results_from_gatherers");
        let has_jobs = self.get_root_job_ids(
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
        )?;
        timer.lap("get_root_job_ids");
        if self.db.ids.next_checkpoint_id > 1 && has_jobs.is_none() {
            tracing::info!("No jobs to process in this block, skipping.");
            return Ok(());
            // tracing::info!("No jobs to process in this block, but proceeding to create empty checkpoint state transition.");
        }


        // publish the first level of jobs
        self.publish_jobs(
            &mut proving_state,
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
            Some(0),
            Some(1),
            false,
        )
        .await?;
        timer.lap("publish_jobs_first_level");
        if self.db.ids.checkpoint_id == 0 {
            self.plan_genesis_checkpoint_state_transition_proof().await?;
            timer.lap("plan_genesis_checkpoint_state_transition_proof");
        }

        // while the first level of jobs are processing, plan the agg job
        let agg_job_metadata = self.plan_agg_guta_register_users_deploy_contracts_job(&mut output_builder).await?;
        timer.lap("plan_agg_guta_register_users_deploy_contracts_job");
        tracing::info!("Waiting for first level of jobs to complete...");
        // wait for the first level of jobs to finish
        self.wait_for_jobs_completion().await?;
        timer.lap("wait_for_jobs_completion_first_level");
        tracing::info!("First level of jobs completed!");

        // publish the rest of the jobs and wait for them to finish
        self.publish_jobs(
            &mut proving_state,
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
            Some(1),
            None,
            true,
        )
        .await?;
        timer.lap("publish_jobs_rest_levels");
        tracing::info!("Pre-agg jobs completed!");

        // wait for the Aggregate GUTA, User Registation and Deploy Contracts Proof to
        // finish being proved
        self.publish_and_wait_for_job_completion(&agg_job_metadata).await?;
        timer.lap("publish_and_wait_for_job_completion_agg");
        println!("Aggregate GUTA, User Registration and Deploy Contracts Proof completed!");
        proving_state.inc_current_proving_level();
        self.db.temp_db.set_psy_node_proving_state(&self.db.ids.realm_identifier, &proving_state).await?;
        let (coordinator_update, zk_proof) = self.plan_checkpoint_state_transition(output_builder).await?;
        timer.lap("plan_checkpoint_state_transition");
        tracing::info!("Checkpoint State Transition Proof completed!");
        proving_state.finish();
        self.db.temp_db.set_psy_node_proving_state(&self.db.ids.realm_identifier, &proving_state).await?;
        self.db
            .commit_state(coordinator_update, ProvingJobCircuitType::GenerateRollupStateTransitionProof, zk_proof)
            .await?;
        timer.lap("commit_state");
        tracing::info!("Committed new coordinator block with checkpoint_id = {}.", self.db.ids.checkpoint_id);
        self.db.print_coordinator_processor_state();

        Ok(())
    }
}
