use std::future::Future;

const JOB_PERSISTENCE_POLL_INTERVAL: Duration = Duration::from_millis(50);

async fn wait_for_job_ready<Proof, Reward, FetchProof, FetchProofFuture, FetchReward, FetchRewardFuture>(
    max_wait_ms: u64,
    timeout_message: String,
    mut fetch_proof: FetchProof,
    mut fetch_reward: FetchReward,
) -> anyhow::Result<(Proof, Reward)>
where
    FetchProof: FnMut() -> FetchProofFuture,
    FetchProofFuture: Future<Output = anyhow::Result<Option<Proof>>>,
    FetchReward: FnMut() -> FetchRewardFuture,
    FetchRewardFuture: Future<Output = anyhow::Result<Option<Reward>>>,
{
    let deadline = (max_wait_ms != u64::MAX).then(|| Instant::now() + Duration::from_millis(max_wait_ms));

    loop {
        if let Some(proof) = fetch_proof().await? {
            if let Some(reward) = fetch_reward().await? {
                return Ok((proof, reward));
            }
        }

        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            anyhow::bail!(timeout_message);
        }

        sleep(JOB_PERSISTENCE_POLL_INTERVAL).await;
    }
}

async fn publish_wait_for_queue_and_job_ready<
    Proof,
    Reward,
    Barrier,
    Publish,
    PublishFuture,
    WaitForQueue,
    WaitForQueueFuture,
    FetchProof,
    FetchProofFuture,
    FetchReward,
    FetchRewardFuture,
>(
    max_wait_ms: u64,
    timeout_message: String,
    publish: Publish,
    wait_for_queue: WaitForQueue,
    fetch_proof: FetchProof,
    fetch_reward: FetchReward,
) -> anyhow::Result<(Proof, Reward)>
where
    Publish: FnOnce() -> PublishFuture,
    PublishFuture: Future<Output = anyhow::Result<Barrier>>,
    WaitForQueue: FnOnce(Barrier) -> WaitForQueueFuture,
    WaitForQueueFuture: Future<Output = anyhow::Result<()>>,
    FetchProof: FnMut() -> FetchProofFuture,
    FetchProofFuture: Future<Output = anyhow::Result<Option<Proof>>>,
    FetchReward: FnMut() -> FetchRewardFuture,
    FetchRewardFuture: Future<Output = anyhow::Result<Option<Reward>>>,
{
    let barrier = publish().await?;
    wait_for_queue(barrier).await?;
    wait_for_job_ready(
        max_wait_ms,
        timeout_message,
        fetch_proof,
        fetch_reward,
    )
    .await
}

use cf_utils::timer::TraceTimer;
use parth_core::{
    data::queue::queue_key::QPBaseQueueType,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput,
    v1::qdata::{contract::{PsyDeployContractQueueItemV2, PsyUpdateContractQueueItem}, public_key::PZKPublicKeyInfo},
    worker::{
        metadata::{PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueue, QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use tokio::time::{sleep, Duration, Instant};

use crate::{
    backup::output::coordinator_output_builder::CoordinatorOutputBuilder,
    coordinator::{
        processor::PsyCoordinatorProcessor,
        queue_key::{
            CoordinatorProvingWorkQueueKey,
            CoordinatorSubmitRealmGUTAUpdateQueueKey,
            CoordinatorRegisterUserPublicKeyQueueKey,
            CoordinatorDeployContractQueueKey,
            CoordinatorUpdateContractQueueKey,
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
    ) -> anyhow::Result<Option<<ProofWorkQueue as QStandardWorkerQueue>::PublishBarrier>> {
        if level < jobs.len() && !jobs[level].is_empty() {
            let expected_root_job_id = jobs.last().and_then(|level| level.first()).map(|job| job.job_id);
            tracing::info!(
                realm_id = self.db.ids.realm_id_u64,
                realm_sub_id = self.db.ids.realm_sub_id_u64,
                checkpoint_id = self.db.ids.next_checkpoint_id,
                unique_pending_id = self.db.ids.unique_pending_id,
                proc_checkpoint_unique_id = self.db.ids.proc_checkpoint_unique_id,
                task_group = 0,
                level,
                job_count = jobs[level].len(),
                root_job_id = ?expected_root_job_id,
                "Publishing Coordinator worker jobs"
            );
            let barrier = self.db
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
            tracing::info!(
                realm_id = self.db.ids.realm_id_u64,
                realm_sub_id = self.db.ids.realm_sub_id_u64,
                checkpoint_id = self.db.ids.next_checkpoint_id,
                unique_pending_id = self.db.ids.unique_pending_id,
                proc_checkpoint_unique_id = self.db.ids.proc_checkpoint_unique_id,
                task_group = 0,
                level,
                job_count = jobs[level].len(),
                root_job_id = ?expected_root_job_id,
                publish_barrier = ?barrier,
                "Coordinator worker publication acknowledged"
            );
            return Ok(Some(barrier));
        }
        Ok(None)
    }
    pub fn get_root_job_ids(
        &self,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        update_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<Option<(QProvingJobDataID, QProvingJobDataID, QProvingJobDataID, QProvingJobDataID)>> {
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
        let update_contract_root_job = update_contract_jobs
            .last()
            .ok_or_else(|| anyhow::anyhow!("No Update Contract jobs found"))?
            .first()
            .ok_or_else(|| anyhow::anyhow!("No Update Contract jobs found at last level"))?;

        if guta_root_job.job_id.circuit_type == ProvingJobCircuitType::GUTANoChange
            && register_user_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
            && deploy_contract_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyBatchDeployContractsAggregate
            && update_contract_root_job.job_id.circuit_type == ProvingJobCircuitType::DummyBatchUpdateContractsAggregate
        {
            tracing::info!("No changes detected in GUTA, Register User, Deploy Contract, and Update Contract jobs.");
            return Ok(None);
        }
        Ok(Some((
            guta_root_job.job_id,
            register_user_root_job.job_id,
            deploy_contract_root_job.job_id,
            update_contract_root_job.job_id,
        )))
    }

    pub async fn publish_jobs(
        &self,
        proving_state: &mut PsyNodeProvingState,
        guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        register_user_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        deploy_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        update_contract_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
        min_level: Option<usize>,
        max_level: Option<usize>,
        wait_for_jobs_completion: bool,
    ) -> anyhow::Result<Vec<<ProofWorkQueue as QStandardWorkerQueue>::PublishBarrier>> {
        let queue_key = self.db.get_proof_worker_queue_key();
        let max_level = guta_jobs
            .len()
            .max(register_user_jobs.len())
            .max(deploy_contract_jobs.len())
            .max(update_contract_jobs.len())
            .min(max_level.unwrap_or(usize::MAX));
        let min_level = min_level.unwrap_or(0).min(max_level);

        let mut published_barriers = Vec::new();
        for i in min_level..max_level {
            proving_state.set_current_proving_level(i as u8);
            self.db.temp_db.set_psy_node_proving_state(&self.db.ids.realm_identifier, &proving_state).await?;
            let (guta_barrier, register_user_barrier, deploy_contract_barrier, update_contract_barrier) = tokio::try_join!(
                self.publish_worker_jobs_if_exists(&queue_key, i, guta_jobs),
                self.publish_worker_jobs_if_exists(&queue_key, i, register_user_jobs),
                self.publish_worker_jobs_if_exists(&queue_key, i, deploy_contract_jobs),
                self.publish_worker_jobs_if_exists(&queue_key, i, update_contract_jobs),
            )?;
            let level_barriers = [guta_barrier, register_user_barrier, deploy_contract_barrier, update_contract_barrier]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
            if wait_for_jobs_completion {
                self.wait_for_jobs_completion(&level_barriers).await?;
                self.wait_for_level_proofs(
                    i,
                    [guta_jobs, register_user_jobs, deploy_contract_jobs, update_contract_jobs],
                )
                .await?;
            }
            published_barriers.extend(level_barriers);
        }
        Ok(published_barriers)
    }

    async fn wait_for_level_proofs(
        &self,
        level: usize,
        job_groups: [&[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>]; 4],
    ) -> anyhow::Result<()> {
        let jobs = job_groups
            .into_iter()
            .filter_map(|levels| levels.get(level))
            .flatten()
            .collect::<Vec<_>>();
        if jobs.is_empty() {
            return Ok(());
        }

        let started = Instant::now();
        loop {
            let mut missing = Vec::new();
            for job in &jobs {
                if self
                    .db
                    .proof_store
                    .get_proof_bytes_by_job_id(
                        job.job_id.get_output_id(),
                        self.db.ids.unique_pending_id,
                    )
                    .await?
                    .is_none()
                {
                    missing.push(job.job_id);
                }
            }
            if missing.is_empty() {
                return Ok(());
            }

            if self.proof_worker_queue_max_time_ms != u64::MAX
                && started.elapsed()
                    >= Duration::from_millis(self.proof_worker_queue_max_time_ms)
            {
                anyhow::bail!(
                    "timed out waiting for level {level} proofs to become readable: {missing:?}"
                );
            }
            sleep(Duration::from_millis(25)).await;
        }
    }

    pub async fn wait_for_jobs_completion(
        &self,
        barriers: &[<ProofWorkQueue as QStandardWorkerQueue>::PublishBarrier],
    ) -> anyhow::Result<()> {
        let queue_key = self.db.get_proof_worker_queue_key();
        for barrier in barriers {
            self.db.proof_work_queue.wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                barrier,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        }
        Ok(())
    }
    pub async fn publish_and_wait_for_job_ready(
        &self,
        job: &PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>,
        job_context: &str,
    ) -> anyhow::Result<(Vec<u8>, N::QHash)> {
        let queue_key = self.db.get_proof_worker_queue_key();
        println!("Publishing job id: {:?}", job.job_id);
        println!("self.db.ids.proc_checkpoint_unique_id: {:?}", self.db.ids.proc_checkpoint_unique_id);
        let output_job_id = job.job_id.get_output_id();
        let unique_pending_id = self.db.ids.unique_pending_id;
        let barrier = self
            .db
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
        tracing::info!(
            realm_id = self.db.ids.realm_id_u64,
            realm_sub_id = self.db.ids.realm_sub_id_u64,
            checkpoint_id = self.db.ids.next_checkpoint_id,
            unique_pending_id,
            proc_checkpoint_unique_id = self.db.ids.proc_checkpoint_unique_id,
            task_group = 0,
            root_job_id = ?job.job_id,
            publish_barrier = ?barrier,
            %job_context,
            "Coordinator root worker publication acknowledged"
        );
        self.db
            .proof_work_queue
            .wait_until_all_jobs_complete_or_timeout_worker(
                &queue_key,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                self.db.ids.proc_checkpoint_unique_id,
                0,
                &barrier,
                self.proof_worker_queue_max_time_ms,
            )
            .await?;
        let (proof_bytes, reward_value) = wait_for_job_ready(
            self.proof_worker_queue_max_time_ms,
            format!(
                "Timed out waiting for persisted proof and reward tree value for {} {:?} at realm {:?}, unique_pending_id {}",
                job_context, output_job_id, self.db.ids.realm_identifier, unique_pending_id,
            ),
            || self.db.proof_store.get_proof_bytes_by_job_id(output_job_id, unique_pending_id),
            || {
                self.db.temp_db.get_proof_miner_rewards_tree_value_or_none(
                    &self.db.ids.realm_identifier,
                    unique_pending_id,
                    output_job_id,
                )
            },
        )
        .await?;

        tracing::info!(
            ?output_job_id,
            unique_pending_id,
            proof_bytes = proof_bytes.len(),
            %job_context,
            "Job proof and reward tree value persisted"
        );
        Ok((proof_bytes, reward_value))
    }


    pub async fn get_results_from_gatherers(&mut self) -> anyhow::Result<(
        PsyNodeProvingState,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
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
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyDeployContractQueueItemV2<N::F, N::QHash>>,
                };
                let update_processing_key = CoordinatorUpdateContractQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyUpdateContractQueueItem<N::F, N::QHash>>,
                };
                let proof_processing_key = CoordinatorProvingWorkQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
                };

                // Create all consumers
                self.db.guta_update_queue.ensure_consumer(&guta_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.register_user_queue.ensure_consumer(&user_reg_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.deploy_contract_queue.ensure_consumer(&deploy_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
                self.db.deploy_contract_queue.ensure_consumer(&update_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;
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
        let (guta_result, register_users_result, contract_gatherer_result) = tokio::try_join!(
            self.guta_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
            self.register_user_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
            self.deploy_contract_queue_gatherer
                .finalize_gathering_and_update_queue_key(self.db.ids.gathering_proc_checkpoint_unique_id),
        )?;

        let (proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, update_contract_jobs, output_builder) = CoordinatorOutputBuilder::new(
            &self.db.ids,
            guta_result,
            register_users_result,
            contract_gatherer_result,
        )?;
        Ok((proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, update_contract_jobs, output_builder))
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
        agg_part_1_reward_root: N::QHash,
    ) -> anyhow::Result<(PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>, Vec<u8>)> {
        let block_time = output_builder.register_users_gatherer_result.block_time;
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
        let (checkpoint_zk_proof, reward_root) = self
            .publish_and_wait_for_job_ready(&job_metadata, "checkpoint state transition root job")
            .await?;
        tracing::info!(
            job_id = ?job_metadata.job_id,
            proof_bytes = checkpoint_zk_proof.len(),
            "Checkpoint state transition root proof and reward value are ready"
        );
        tracing::info!("Retrieved checkpoint zk proof of size: {} bytes", checkpoint_zk_proof.len());
        let output = output_builder.finalize(&self.db.ids, &self.db.last_committed, reward_root, block_time)?;
        tracing::info!("Finalized coordinator block state updates.");
        Ok((output, checkpoint_zk_proof))
    }
    pub async fn plan_genesis_checkpoint_state_transition_proof(
        &self,
    ) -> anyhow::Result<<ProofWorkQueue as QStandardWorkerQueue>::PublishBarrier> {
        let genesis_fingerprint = self.db.circuit_fingerprint_config.genesis_checkpoint_state_transition_fingerprint;
        let witness = PsyCheckpointStateTransitionGenesisCircuitInput::<N::QHash> {
            checkpoint_tree_root: self.db.last_committed.checkpoint_state_transition.new_checkpoint_tree_root,
            checkpoint_leaf_hash: self.db.last_committed.checkpoint_state_transition.new_checkpoint_leaf_hash,
            genesis_fingerprint,
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
        let barrier = self.db
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

        Ok(barrier)
    }

    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        let mut timer = TraceTimer::new("process_block");
        tracing::info!("Starting to process new coordinator block with checkpoint_id = {}...", self.db.ids.next_checkpoint_id);
        let (mut proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, update_contract_jobs, mut output_builder) = self.get_results_from_gatherers().await?;
        let worker_queue_key_for_cleanup = self.db.get_proof_worker_queue_key();
        let worker_unique_id_for_cleanup = self.db.ids.proc_checkpoint_unique_id;

        timer.lap("get_results_from_gatherers");
        let has_jobs = self.get_root_job_ids(
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
            &update_contract_jobs,
        )?;
        timer.lap("get_root_job_ids");
        if self.db.ids.next_checkpoint_id > 1 && has_jobs.is_none() {
            tracing::info!("No jobs to process in this block; creating empty checkpoint state transition.");
        }


        // publish the first level of jobs
        let mut first_level_barriers = self.publish_jobs(
            &mut proving_state,
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
            &update_contract_jobs,
            Some(0),
            Some(1),
            false,
        )
        .await?;
        timer.lap("publish_jobs_first_level");
        if self.db.ids.checkpoint_id == 0 {
            first_level_barriers.push(self.plan_genesis_checkpoint_state_transition_proof().await?);
            timer.lap("plan_genesis_checkpoint_state_transition_proof");
        }

        // while the first level of jobs are processing, plan the agg job
        let agg_job_metadata = self.plan_agg_guta_register_users_deploy_contracts_job(&mut output_builder).await?;
        timer.lap("plan_agg_guta_register_users_deploy_contracts_job");
        tracing::info!("Waiting for first level of jobs to complete...");
        // wait for the first level of jobs to finish
        self.wait_for_jobs_completion(&first_level_barriers).await?;
        self.wait_for_level_proofs(
            0,
            [&guta_jobs, &register_user_jobs, &deploy_contract_jobs, &update_contract_jobs],
        )
        .await?;
        timer.lap("wait_for_jobs_completion_first_level");
        tracing::info!("First level of jobs completed!");

        // publish the rest of the jobs and wait for them to finish
        let _published_barriers = self.publish_jobs(
            &mut proving_state,
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
            &update_contract_jobs,
            Some(1),
            None,
            true,
        )
        .await?;
        timer.lap("publish_jobs_rest_levels");
        tracing::info!("Pre-agg jobs completed!");

        // wait for the Aggregate GUTA, User Registation and Deploy Contracts Proof to
        // finish being proved
        let (_, agg_part_1_reward_root) = self
            .publish_and_wait_for_job_ready(&agg_job_metadata, "checkpoint state transition dependency")
            .await?;
        timer.lap("publish_and_wait_for_job_completion_agg");
        println!("Aggregate GUTA, User Registration and Deploy Contracts Proof completed!");
        proving_state.inc_current_proving_level();
        self.db.temp_db.set_psy_node_proving_state(&self.db.ids.realm_identifier, &proving_state).await?;
        let (coordinator_update, zk_proof) = self
            .plan_checkpoint_state_transition(output_builder, agg_part_1_reward_root)
            .await?;
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
        if let Err(err) = self
            .db
            .proof_work_queue
            .delete_worker_queue_consumer(
                &worker_queue_key_for_cleanup,
                self.db.ids.realm_id_u64,
                self.db.ids.realm_sub_id_u64,
                worker_unique_id_for_cleanup,
                0,
            )
            .await
        {
            tracing::warn!(
                "Failed to delete coordinator worker queue consumer after checkpoint commit: {}",
                err
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };

    use super::{publish_wait_for_queue_and_job_ready, wait_for_job_ready};

    #[tokio::test]
    async fn polls_until_both_job_values_exist() -> anyhow::Result<()> {
        let proof_attempts = Arc::new(AtomicUsize::new(0));
        let observed_proof_attempts = Arc::clone(&proof_attempts);
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);

        let (proof, reward) = wait_for_job_ready(
            1_000,
            "job proof and reward were not persisted".to_string(),
            move || {
                let attempt = observed_proof_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok((attempt >= 2).then_some(vec![1_u8, 2, 3])) }
            },
            move || {
                let _attempt = observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok(Some(87_u64)) }
            },
        )
        .await?;

        assert_eq!(proof, vec![1, 2, 3]);
        assert_eq!(reward, 87);
        assert_eq!(proof_attempts.load(Ordering::SeqCst), 3);
        assert_eq!(reward_attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn immediate_queue_barrier_still_waits_for_keyed_job_values() -> anyhow::Result<()> {
        let phase = Arc::new(AtomicUsize::new(0));
        let publish_phase = Arc::clone(&phase);
        let barrier_phase = Arc::clone(&phase);
        let proof_phase = Arc::clone(&phase);
        let reward_phase = Arc::clone(&phase);
        let proof_attempts = Arc::new(AtomicUsize::new(0));
        let observed_proof_attempts = Arc::clone(&proof_attempts);
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);

        let (proof, reward) = publish_wait_for_queue_and_job_ready(
            1_000,
            "job proof and reward were not persisted".to_string(),
            move || async move {
                assert_eq!(publish_phase.swap(1, Ordering::SeqCst), 0);
                Ok(17_u64)
            },
            move |barrier| async move {
                assert_eq!(barrier, 17);
                assert_eq!(barrier_phase.swap(2, Ordering::SeqCst), 1);
                Ok(())
            },
            move || {
                assert_eq!(proof_phase.load(Ordering::SeqCst), 2);
                let attempt = observed_proof_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok((attempt >= 2).then_some(vec![4_u8, 5, 6])) }
            },
            move || {
                assert_eq!(reward_phase.load(Ordering::SeqCst), 2);
                let _attempt = observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok(Some(91_u64)) }
            },
        )
        .await?;

        assert_eq!(proof, vec![4, 5, 6]);
        assert_eq!(reward, 91);
        assert_eq!(phase.load(Ordering::SeqCst), 2);
        assert_eq!(proof_attempts.load(Ordering::SeqCst), 3);
        assert_eq!(reward_attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn regression_reward_not_stale_when_proof_delayed() -> anyhow::Result<()> {
        // Original checkpoint-367 corruption: reward-first polling read the reward
        // store while the proof was still pending and cached the first `Some` it
        // observed. When the claim-tag and the finalized reward shared a store, that
        // cached value was a stale claim-tag, later paired with a freshly-visible
        // proof -> proof/reward corruption.
        //
        // This test models the data flow against the proof-first helper:
        //   * The reward store exposes `Some(claim_tag = 41)` while the proof is still
        //     `None` (claim stage), then `Some(final = 99)` once the proof is visible.
        //   * The proof closure returns `None` for the first two polls, `Some` after,
        //     and flips a shared `proof_ready` flag the moment it first returns `Some`.
        //   * The reward closure returns `Some(claim = 41)` while `proof_ready` is
        //     false and `Some(final = 99)` once `proof_ready` is true.
        //
        // The proof-first helper only reads reward AFTER proof is `Some`, so its first
        // reward read sees the finalized 99. The old reward-first-with-cache helper
        // reads reward BEFORE proof is ready, caches 41, and returns the stale 41
        // paired with the later proof -- the exact corruption vector, so the value
        // assertion (`reward == 99`) mutation-kills the old implementation.
        let proof_ready = Arc::new(AtomicBool::new(false));
        let observed_proof_ready_for_proof = Arc::clone(&proof_ready);
        let observed_proof_ready_for_reward = Arc::clone(&proof_ready);
        let proof_attempts = Arc::new(AtomicUsize::new(0));
        let observed_proof_attempts = Arc::clone(&proof_attempts);
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);

        let (proof, reward) = wait_for_job_ready(
            1_000,
            "job proof and reward were not persisted".to_string(),
            move || {
                let attempt = observed_proof_attempts.fetch_add(1, Ordering::SeqCst);
                let ready = Arc::clone(&observed_proof_ready_for_proof);
                async move {
                    let is_ready = attempt >= 2;
                    if is_ready {
                        // Mark the proof as visible before yielding Some so that a
                        // proof-first reader, which fetches reward only after this
                        // point, observes the finalized reward.
                        ready.store(true, Ordering::SeqCst);
                    }
                    Ok(is_ready.then_some(vec![7_u8, 8, 9]))
                }
            },
            move || {
                let _attempt = observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                let ready = Arc::clone(&observed_proof_ready_for_reward);
                async move {
                    // While the proof is still pending the reward store holds the
                    // claim-tag (41); once the proof is visible the finalized reward
                    // (99) is present. A proof-first reader only reaches this branch
                    // after the proof is ready, so it must observe 99.
                    Ok(Some(if ready.load(Ordering::SeqCst) { 99_u64 } else { 41_u64 }))
                }
            },
        )
        .await?;

        assert_eq!(proof, vec![7, 8, 9]);
        assert_eq!(
            reward, 99,
            "must return the finalized reward, not the stale claim-tag cached before the proof was ready"
        );
        // Proof-first: proof is polled every iteration (3 polls); reward is read exactly
        // once, after the proof becomes Some.
        assert_eq!(proof_attempts.load(Ordering::SeqCst), 3);
        assert_eq!(reward_attempts.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test]
    async fn proof_and_reward_both_ready_on_first_poll_return_immediately() -> anyhow::Result<()> {
        // Early-return contract: when both proof and reward are Some on the very
        // first poll the helper must return at once -- no extra iteration, no
        // sleep. A regression that always sleeps before the first check, or that
        // polls a second time "to be sure", drives both counters past 1.
        let proof_attempts = Arc::new(AtomicUsize::new(0));
        let observed_proof_attempts = Arc::clone(&proof_attempts);
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);

        let (proof, reward) = wait_for_job_ready(
            1_000,
            "job proof and reward were not persisted".to_string(),
            move || {
                observed_proof_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok(Some(vec![1_u8, 2, 3])) }
            },
            move || {
                observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok(Some(87_u64)) }
            },
        )
        .await?;

        assert_eq!(proof, vec![1, 2, 3]);
        assert_eq!(reward, 87);
        assert_eq!(
            proof_attempts.load(Ordering::SeqCst),
            1,
            "must return on the first poll when both values are immediately ready"
        );
        assert_eq!(
            reward_attempts.load(Ordering::SeqCst),
            1,
            "reward must be fetched exactly once when already ready alongside the proof"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reward_never_appearing_while_proof_ready_times_out() -> anyhow::Result<()> {
        // Anti-corruption contract: a proof must NEVER be returned without its
        // finalized reward. The proof store reports Some on every poll while the
        // reward store reports None forever; the helper must keep polling until
        // the deadline and then bail, never returning Ok((proof, _)).
        //
        // Mutation-kills: `return Ok((proof, fetch_reward().await?.unwrap_or_default()))`
        // on None reward, or any early-return that pairs a ready proof with a
        // missing/default reward -- those return Ok, this test demands Err.
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);
        let timeout_message = "reward never materialized for ready proof".to_string();

        let result = wait_for_job_ready(
            150,
            timeout_message.clone(),
            move || {
                // Proof is always Some -- the temptation the bug class exploits.
                async move { Ok(Some(vec![7_u8, 8, 9])) }
            },
            move || {
                observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                async move { Ok(None::<u64>) }
            },
        )
        .await;

        let error = result.expect_err(
            "must time out, never return a proof without its finalized reward",
        );
        let error = error.to_string();
        assert!(
            error.contains(&timeout_message),
            "timeout must surface the configured message, got: {error}"
        );
        assert!(
            reward_attempts.load(Ordering::SeqCst) >= 1,
            "must have consulted the reward store before timing out, not short-circuited on a ready proof"
        );
        Ok(())
    }

    #[tokio::test]
    async fn reward_transitioning_after_proof_ready_is_retried_not_early_returned() -> anyhow::Result<()> {
        // After the proof becomes Some the reward may still be propagating
        // (None on the first post-proof poll, Some(final) on the next). The
        // helper must loop and re-fetch BOTH proof and reward, not early-return
        // the proof paired with a missing/default reward.
        //
        // Mutation-kills:
        //   * `return Ok((proof, fetch_reward().await?.unwrap_or_default()))`
        //     (returns a default reward instead of the finalized one).
        //   * any `break`/early-return triggered by None reward after a ready
        //     proof (drops the retry, returns default/missing reward).
        //   * caching the proof across iterations (proof_attempts would stay 1);
        //     the helper must re-fetch proof each loop.
        let proof_attempts = Arc::new(AtomicUsize::new(0));
        let observed_proof_attempts = Arc::clone(&proof_attempts);
        let reward_attempts = Arc::new(AtomicUsize::new(0));
        let observed_reward_attempts = Arc::clone(&reward_attempts);

        let (proof, reward) = wait_for_job_ready(
            1_000,
            "job proof and reward were not persisted".to_string(),
            move || {
                observed_proof_attempts.fetch_add(1, Ordering::SeqCst);
                // Proof is ready immediately and stays ready every iteration.
                async move { Ok(Some(vec![1_u8, 2, 3])) }
            },
            move || {
                let attempt = observed_reward_attempts.fetch_add(1, Ordering::SeqCst);
                async move {
                    // None on the first poll (reward still propagating after the
                    // proof became visible), Some(final) from the second poll on.
                    Ok((attempt >= 1).then_some(99_u64))
                }
            },
        )
        .await?;

        assert_eq!(proof, vec![1, 2, 3]);
        assert_eq!(
            reward, 99,
            "must return the finalized reward once it appears, not a default for the missing one"
        );
        // iter 1: proof Some, reward None -> continue; iter 2: proof Some, reward Some -> return.
        assert_eq!(
            proof_attempts.load(Ordering::SeqCst),
            2,
            "proof must be re-fetched on the retry, not cached from the first poll"
        );
        assert_eq!(
            reward_attempts.load(Ordering::SeqCst),
            2,
            "reward must be polled again after the first None, not early-returned"
        );
        Ok(())
    }
}

#[cfg(test)]
mod process_block_tests {
    use std::sync::Arc;

    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher, node::realm_identifier::QRealmIdentifier, PHash,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    };
    use psy_node_core::{
        psy_temp_db::{QTempDBNodeProvingStateReader, QTempDBRewardsTreeWriter},
        queue::worker_queue::QStandardWorkerQueueSubscriber,
        store::traits::proof_store::QParthProofStoreWriter,
    };

    use crate::coordinator::processor::core::startup::startup_tests::{CoordinatorProcessorTestEnv, N};

    use super::PsyCoordinatorProcessor;

    type TestJobs = Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>;

    fn zh(level: usize) -> PHash {
        parth_core::pgoldilocks::PoseidonHasher::get_zero_hash(level)
    }

    fn job(
        circuit: ProvingJobCircuitType,
        salt: u64,
    ) -> PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID> {
        PsyProvingJobMetadataWithJobId {
            job_id: QProvingJobDataID::new_proof_job_id(salt, 0, circuit, 0, 0),
            metadata: PsyProvingJobMetadata {
                expected_public_inputs_hash: zh(7),
                reward_tree_node_index: 0,
                reward_tree_node_level: 0,
                reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
                reward_tree_node_children: 0,
                dependencies: vec![],
            },
        }
    }

    fn one_level(circuit: ProvingJobCircuitType, salt: u64) -> TestJobs {
        vec![vec![job(circuit, salt)]]
    }

    fn realm_identifier() -> QRealmIdentifier {
        QRealmIdentifier::new(1, 2)
    }

    /// Drains the shared fake worker queue and persists a proof plus reward
    /// tree value for every published job, standing in for the proving
    /// workers. Artifacts are written under a range of pending ids so the
    /// daemon keeps working no matter how far the processor rotates its ids.
    async fn run_prover_daemon(
        env: &CoordinatorProcessorTestEnv,
        max_runtime_ms: u64,
    ) -> tokio::task::JoinHandle<()> {
        let queue_key = env.processor.db.get_proof_worker_queue_key();
        let proof_queue = Arc::clone(&env.proof_work_queue);
        let temp_db = Arc::clone(&env.temp_db);
        tokio::spawn(async move {
            let rid = realm_identifier();
            let deadline =
                tokio::time::Instant::now() + std::time::Duration::from_millis(max_runtime_ms);
            while tokio::time::Instant::now() < deadline {
                let items = proof_queue
                    .dump_entire_worker_queue::<
                        crate::coordinator::queue_key::CoordinatorProvingWorkQueueKey<
                            PHash,
                            QProvingJobDataID,
                        >,
                    >(&queue_key, 1, 2, 0, 0, 256)
                    .await
                    .unwrap_or_default();
                let had_items = !items.is_empty();
                for item in items {
                    let output_id = item.job_id.get_output_id();
                    for uid in 0u64..=4 {
                        let _ = temp_db
                            .put_proof_bytes_for_job_id(output_id, uid, b"coord test proof")
                            .await;
                        let _ = temp_db
                            .set_proof_miner_rewards_tree_value(&rid, uid, output_id, zh(9))
                            .await;
                    }
                }
                if !had_items {
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            }
        })
    }

    fn root_ids_of(
        guta: ProvingJobCircuitType,
        register: ProvingJobCircuitType,
        deploy: ProvingJobCircuitType,
        update: ProvingJobCircuitType,
    ) -> (
        PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>,
        PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>,
        PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>,
        PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>,
    ) {
        (job(guta, 1), job(register, 2), job(deploy, 3), job(update, 4))
    }

    #[tokio::test]
    async fn get_root_job_ids_errors_when_any_job_list_is_missing() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;

        // every list must exist and carry at least one root job
        let register = one_level(ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate, 2);
        let deploy = one_level(ProvingJobCircuitType::DummyBatchDeployContractsAggregate, 3);
        let update = one_level(ProvingJobCircuitType::DummyBatchUpdateContractsAggregate, 4);
        let guta = one_level(ProvingJobCircuitType::GUTANoChange, 1);
        let cases: [(&str, TestJobs, TestJobs, TestJobs, TestJobs); 4] = [
            ("No GUTA jobs found", vec![], register.clone(), deploy.clone(), update.clone()),
            ("No Register User jobs found", guta.clone(), vec![], deploy.clone(), update.clone()),
            ("No Deploy Contract jobs found", guta.clone(), register.clone(), vec![], update.clone()),
            ("No Update Contract jobs found", guta.clone(), register.clone(), deploy.clone(), vec![]),
        ];
        for (expected_message, guta, register, deploy, update) in cases {
            let error = match processor.get_root_job_ids(&guta, &register, &deploy, &update) {
                Err(e) => e.to_string(),
                Ok(_) => anyhow::bail!("a missing job list must fail root-job selection: {expected_message}"),
            };
            assert!(error.contains(expected_message), "unexpected error: {error}");
        }

        // a list that exists but has an empty last level is rejected too
        let error = match processor.get_root_job_ids(&vec![vec![]], &register, &deploy, &update) {
            Err(e) => e.to_string(),
            Ok(_) => anyhow::bail!("an empty last level must fail root-job selection"),
        };
        assert!(
            error.contains("No GUTA jobs found at last level"),
            "unexpected error: {error}"
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn get_root_job_ids_reports_no_changes_only_for_all_dummy_roots() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;

        let (guta, register, deploy, update) = root_ids_of(
            ProvingJobCircuitType::GUTANoChange,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::DummyBatchUpdateContractsAggregate,
        );
        let result = processor.get_root_job_ids(
            &vec![vec![guta]],
            &vec![vec![register]],
            &vec![vec![deploy]],
            &vec![vec![update]],
        )?;
        assert!(
            result.is_none(),
            "all-dummy roots must be reported as a no-change block"
        );

        // a single real GUTA root job is enough to consider the block real
        let (guta, register, deploy, update) = root_ids_of(
            ProvingJobCircuitType::GUTATwoEndCap,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::DummyBatchUpdateContractsAggregate,
        );
        let roots = processor
            .get_root_job_ids(
                &vec![vec![guta.clone()]],
                &vec![vec![register.clone()]],
                &vec![vec![deploy.clone()]],
                &vec![vec![update.clone()]],
            )?
            .expect("a real GUTA root must produce root job ids");
        assert_eq!(roots.0, guta.job_id);
        assert_eq!(roots.1, register.job_id);
        assert_eq!(roots.2, deploy.job_id);
        assert_eq!(roots.3, update.job_id);

        // likewise a single real update-contract root job
        let (guta, register, deploy, update) = root_ids_of(
            ProvingJobCircuitType::GUTANoChange,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            ProvingJobCircuitType::BatchUpdateContracts,
        );
        let roots = processor
            .get_root_job_ids(
                &vec![vec![guta]],
                &vec![vec![register]],
                &vec![vec![deploy]],
                &vec![vec![update]],
            )?
            .expect("a real update-contract root must produce root job ids");
        assert_eq!(roots.3.circuit_type, ProvingJobCircuitType::BatchUpdateContracts);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_worker_jobs_if_exists_skips_out_of_range_and_empty_levels() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;
        let queue_key = processor.db.get_proof_worker_queue_key();

        let jobs: TestJobs = vec![vec![], vec![job(ProvingJobCircuitType::GUTATwoEndCap, 11)]];
        let empty_level = processor.publish_worker_jobs_if_exists(&queue_key, 0, &jobs).await?;
        assert!(empty_level.is_none(), "an empty level must not be published");
        let out_of_range = processor.publish_worker_jobs_if_exists(&queue_key, jobs.len(), &jobs).await?;
        assert!(out_of_range.is_none(), "a level beyond the job lists must not be published");
        assert_eq!(*env.proof_work_queue.published_count.lock().unwrap(), 0);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_worker_jobs_if_exists_publishes_only_that_level() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;
        let queue_key = processor.db.get_proof_worker_queue_key();

        let level_zero = job(ProvingJobCircuitType::GUTATwoEndCap, 21);
        let level_one = job(ProvingJobCircuitType::GUTATwoEndCap, 22);
        let jobs: TestJobs = vec![vec![level_zero.clone()], vec![level_one]];
        let barrier = processor
            .publish_worker_jobs_if_exists(&queue_key, 0, &jobs)
            .await?
            .expect("a non-empty in-range level must be published");
        let _ = barrier;
        assert_eq!(*env.proof_work_queue.published_count.lock().unwrap(), 1);

        // the published item round-trips through the queue as the level-0 job
        let drained = env
            .proof_work_queue
            .dump_entire_worker_queue::<
                crate::coordinator::queue_key::CoordinatorProvingWorkQueueKey<PHash, QProvingJobDataID>,
            >(&queue_key, 1, 2, 0, 0, 16)
            .await?;
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].job_id, level_zero.job_id);
        assert_eq!(
            drained[0].metadata.expected_public_inputs_hash,
            level_zero.metadata.expected_public_inputs_hash
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_jobs_publishes_every_level_and_records_proving_state() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let CoordinatorProcessorTestEnv {
            processor,
            temp_db,
            proof_work_queue,
            guta_gatherer_handle,
            register_gatherer_handle,
            deploy_gatherer_handle,
            ..
        } = env;
        let mut processor = processor;
        let guta_jobs: TestJobs = vec![
            vec![job(ProvingJobCircuitType::GUTATwoEndCap, 31)],
            vec![job(ProvingJobCircuitType::GUTATwoEndCap, 32)],
        ];
        let register_jobs = one_level(ProvingJobCircuitType::AppendUserRegistrationTree, 33);
        let deploy_jobs = one_level(ProvingJobCircuitType::BatchDeployContracts, 34);
        let update_jobs = one_level(ProvingJobCircuitType::BatchUpdateContracts, 35);

        let mut proving_state = psy_data::node::node_proving_state::PsyNodeProvingState::new_standard_realm(
            1,
            2,
            processor.db.ids.unique_pending_id,
            processor.db.ids.checkpoint_id,
            0,
            6,
        );
        let barriers = processor
            .publish_jobs(
                &mut proving_state,
                &guta_jobs,
                &register_jobs,
                &deploy_jobs,
                &update_jobs,
                Some(0),
                None,
                false,
            )
            .await?;

        // level 0 publishes from all four lists, level 1 only from the
        // (longer) guta list: five publications, five barriers
        assert_eq!(*proof_work_queue.published_count.lock().unwrap(), 5);
        assert_eq!(barriers.len(), 5);
        assert_eq!(proving_state.current_proving_level, 1);

        // the last written proving state names the last published level
        let persisted = temp_db.get_psy_node_proving_state(&realm_identifier()).await?;
        assert_eq!(persisted.current_proving_level, 1);
        guta_gatherer_handle.abort();
        register_gatherer_handle.abort();
        deploy_gatherer_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn publish_jobs_clamps_level_range_to_available_levels() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let CoordinatorProcessorTestEnv {
            processor,
            proof_work_queue,
            guta_gatherer_handle,
            register_gatherer_handle,
            deploy_gatherer_handle,
            ..
        } = env;
        let processor = processor;
        let guta_jobs: TestJobs = vec![
            vec![job(ProvingJobCircuitType::GUTATwoEndCap, 41)],
            vec![job(ProvingJobCircuitType::GUTATwoEndCap, 42)],
        ];
        let register_jobs = one_level(ProvingJobCircuitType::AppendUserRegistrationTree, 43);
        let deploy_jobs = one_level(ProvingJobCircuitType::BatchDeployContracts, 44);
        let update_jobs = one_level(ProvingJobCircuitType::BatchUpdateContracts, 45);
        let mut proving_state = psy_data::node::node_proving_state::PsyNodeProvingState::new_standard_realm(
            1, 2, 0, 0, 0, 6,
        );

        // max_level clamps the range to just level 0
        let barriers = processor
            .publish_jobs(
                &mut proving_state,
                &guta_jobs,
                &register_jobs,
                &deploy_jobs,
                &update_jobs,
                Some(0),
                Some(1),
                false,
            )
            .await?;
        assert_eq!(*proof_work_queue.published_count.lock().unwrap(), 4);
        assert_eq!(barriers.len(), 4);

        // min_level beyond the longest list clamps to an empty range
        let barriers = processor
            .publish_jobs(
                &mut proving_state,
                &guta_jobs,
                &register_jobs,
                &deploy_jobs,
                &update_jobs,
                Some(9),
                None,
                false,
            )
            .await?;
        assert_eq!(barriers.len(), 0);
        assert_eq!(*proof_work_queue.published_count.lock().unwrap(), 4);
        guta_gatherer_handle.abort();
        register_gatherer_handle.abort();
        deploy_gatherer_handle.abort();
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_level_proofs_returns_immediately_without_jobs() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;
        let register_jobs = one_level(ProvingJobCircuitType::AppendUserRegistrationTree, 51);
        let empty: TestJobs = vec![];
        processor
            .wait_for_level_proofs(5, [&empty, &register_jobs, &empty, &empty])
            .await?;
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_level_proofs_times_out_when_proofs_never_appear() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        env.processor.proof_worker_queue_max_time_ms = 150;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;

        let missing = job(ProvingJobCircuitType::GUTATwoEndCap, 61);
        let jobs: TestJobs = vec![vec![missing]];
        let started = std::time::Instant::now();
        let error = processor
            .wait_for_level_proofs(0, [&jobs, &jobs, &jobs, &jobs])
            .await
            .expect_err("a level-0 job without a persisted proof must time out")
            .to_string();
        assert!(
            error.contains("timed out waiting for level 0 proofs"),
            "unexpected error: {error}"
        );
        assert!(started.elapsed() >= std::time::Duration::from_millis(150));
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_level_proofs_passes_once_proofs_are_persisted() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;

        let ready = job(ProvingJobCircuitType::GUTATwoEndCap, 71);
        env.temp_db
            .put_proof_bytes_for_job_id(ready.job_id.get_output_id(), processor.db.ids.unique_pending_id, b"proof")
            .await?;
        let jobs: TestJobs = vec![vec![ready]];
        processor.wait_for_level_proofs(0, [&jobs, &jobs, &jobs, &jobs]).await?;
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_and_wait_for_job_ready_requires_proof_and_reward() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        env.processor.proof_worker_queue_max_time_ms = 150;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;
        let unique_pending_id = processor.db.ids.unique_pending_id;
        let target = job(ProvingJobCircuitType::GenerateRollupStateTransitionProof, 81);
        let output_id = target.job_id.get_output_id();

        // nothing persisted: the helper must keep polling until the deadline
        let error = processor
            .publish_and_wait_for_job_ready(&target, "test job")
            .await
            .expect_err("a job without proof or reward must time out")
            .to_string();
        assert!(
            error.contains("Timed out waiting for persisted proof and reward tree value"),
            "unexpected error: {error}"
        );

        // a proof without its reward tree value must still not pass
        env.temp_db.put_proof_bytes_for_job_id(output_id, unique_pending_id, b"proof").await?;
        let error = processor
            .publish_and_wait_for_job_ready(&target, "test job")
            .await
            .expect_err("a proof without a reward value must time out")
            .to_string();
        assert!(
            error.contains("Timed out waiting for persisted proof and reward tree value"),
            "unexpected error: {error}"
        );

        // both artifacts present: the call resolves with the persisted pair
        let reward = zh(12);
        env.temp_db
            .set_proof_miner_rewards_tree_value(&realm_identifier(), unique_pending_id, output_id, reward)
            .await?;
        let (proof_bytes, reward_value) =
            processor.publish_and_wait_for_job_ready(&target, "test job").await?;
        assert_eq!(proof_bytes, b"proof".to_vec());
        assert_eq!(reward_value, reward);

        // each attempt published the job exactly once
        assert_eq!(*env.proof_work_queue.published_count.lock().unwrap(), 3);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn get_results_from_gatherers_bails_when_ids_undifferentiated_after_genesis() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        // model a processor past genesis whose ids were never rotated
        env.processor.db.ids.checkpoint_id = 1;
        env.processor.db.ids.next_checkpoint_id = 2;
        env.processor.db.ids.unique_pending_id = 0;
        env.processor.db.ids.proc_checkpoint_unique_id = 0;
        env.processor.db.ids.gathering_unique_pending_id = 0;
        env.processor.db.ids.gathering_proc_checkpoint_unique_id = 0;

        let error = match env.processor.get_results_from_gatherers().await {
            Err(e) => e.to_string(),
            Ok(_) => anyhow::bail!("undifferentiated ids past genesis must bail"),
        };
        assert!(
            error.contains("Cannot gather results when unique ids have not been updated."),
            "unexpected error: {error}"
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn get_results_from_gatherers_rotates_ids_and_yields_dummy_root_jobs() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        let unique_before = env.processor.db.ids.unique_pending_id;
        let gathering_before = env.processor.db.ids.gathering_unique_pending_id;

        let (proving_state, guta_jobs, register_jobs, deploy_jobs, update_jobs, _output_builder) =
            env.processor.get_results_from_gatherers().await?;

        // one rotation: the old gathering pair graduated to processing and
        // gathering advanced to the next pending id
        let ids = &env.processor.db.ids;
        assert_eq!(ids.unique_pending_id, gathering_before);
        assert_eq!(ids.gathering_unique_pending_id, gathering_before + 1);
        assert_ne!(ids.gathering_proc_checkpoint_unique_id, ids.proc_checkpoint_unique_id);
        assert!(ids.unique_pending_id >= unique_before);

        // with no queue items every gatherer finalizes to its dummy/no-change
        // root job
        assert_eq!(guta_jobs.len(), 1);
        assert_eq!(guta_jobs[0].len(), 1);
        assert_eq!(guta_jobs[0][0].job_id.circuit_type, ProvingJobCircuitType::GUTANoChange);
        assert_eq!(
            register_jobs[0][0].job_id.circuit_type,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate
        );
        assert_eq!(
            deploy_jobs[0][0].job_id.circuit_type,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate
        );
        assert_eq!(
            update_jobs[0][0].job_id.circuit_type,
            ProvingJobCircuitType::DummyBatchUpdateContractsAggregate
        );

        // the proving state starts at level zero and the needs_revert flag is
        // cleared
        assert_eq!(proving_state.current_proving_level, 0);
        assert!(!env.processor.db.needs_revert);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn plan_genesis_checkpoint_state_transition_proof_publishes_genesis_job() -> anyhow::Result<()> {
        let env = CoordinatorProcessorTestEnv::create().await?;
        let processor: &PsyCoordinatorProcessor<N, _, _, _, _, _, _, _, _, _> = &env.processor;
        let published_before = *env.proof_work_queue.published_count.lock().unwrap();

        processor.plan_genesis_checkpoint_state_transition_proof().await?;

        assert_eq!(*env.proof_work_queue.published_count.lock().unwrap(), published_before + 1);
        // the genesis job lands on the worker queue
        let queue_key = processor.db.get_proof_worker_queue_key();
        let drained = env
            .proof_work_queue
            .dump_entire_worker_queue::<
                crate::coordinator::queue_key::CoordinatorProvingWorkQueueKey<PHash, QProvingJobDataID>,
            >(&queue_key, 1, 2, 0, 0, 16)
            .await?;
        assert_eq!(drained.len(), 1);
        assert_eq!(
            drained[0].job_id.circuit_type,
            ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn process_block_drives_all_proving_phases_until_the_chain_commitment_check() -> anyhow::Result<()> {
        let mut env = CoordinatorProcessorTestEnv::create().await?;
        // bound every worker waits so a missed artifact fails fast instead of
        // hanging
        env.processor.proof_worker_queue_max_time_ms = 20_000;
        let daemon = run_prover_daemon(&env, 60_000).await;

        let CoordinatorProcessorTestEnv {
            processor,
            db,
            proof_work_queue,
            guta_gatherer_handle,
            register_gatherer_handle,
            deploy_gatherer_handle,
            ..
        } = env;
        let mut processor = processor;
        let unique_pending_id_after = processor.db.ids.unique_pending_id + 1;
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            processor.process_block(),
        )
        .await
        .expect("process_block must terminate within the test timeout");
        daemon.abort();
        guta_gatherer_handle.abort();
        register_gatherer_handle.abort();
        deploy_gatherer_handle.abort();

        // The full pipeline (gatherers -> dummy level-0 jobs -> genesis
        // transition proof -> aggregate part-1 job -> checkpoint state
        // transition job) runs against the fake proving infrastructure; the
        // last step, commit_state, verifies the checkpoint proof
        // public-input hash against the chain hash, and the test verifier's
        // fixed zero hash cannot match, so the run must end exactly there.
        let error = match result {
            Err(e) => e.to_string(),
            Ok(_) => anyhow::bail!("the chain commitment check must reject the fake proof"),
        };
        assert!(
            error.contains("Checkpoint proof public-input hash mismatch for checkpoint ID 1"),
            "unexpected error: {error}"
        );

        // the ids rotated for the block but the checkpoint stayed uncommitted
        assert_eq!(processor.db.ids.unique_pending_id, unique_pending_id_after);
        assert_eq!(processor.db.ids.checkpoint_id, 0);
        assert_eq!(db.get_latest_checkpoint_id().await?, 0);

        // every phase published its proving job: four gatherer dummy roots,
        // the genesis transition, the aggregate part-1 job and the checkpoint
        // state transition job
        let published = *proof_work_queue.published_count.lock().unwrap();
        assert!(published >= 7, "expected at least 7 published proving jobs, got {published}");

        // the worker-queue consumer cleanup only runs after a successful
        // commit
        assert!(proof_work_queue.deleted_consumers.lock().unwrap().is_empty());
        Ok(())
    }
}
