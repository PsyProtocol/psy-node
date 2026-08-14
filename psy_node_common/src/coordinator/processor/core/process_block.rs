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
    PublishFuture: Future<Output = anyhow::Result<()>>,
    WaitForQueue: FnOnce() -> WaitForQueueFuture,
    WaitForQueueFuture: Future<Output = anyhow::Result<()>>,
    FetchProof: FnMut() -> FetchProofFuture,
    FetchProofFuture: Future<Output = anyhow::Result<Option<Proof>>>,
    FetchReward: FnMut() -> FetchRewardFuture,
    FetchRewardFuture: Future<Output = anyhow::Result<Option<Reward>>>,
{
    publish().await?;
    wait_for_queue().await?;
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
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    proof_input::genesis::PsyCheckpointStateTransitionGenesisCircuitInput,
    v1::qdata::{contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo},
    worker::{
        metadata::{PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_io::tokio::TokioLikeFileSystem;
use tokio::time::{sleep, Duration, Instant};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        coordinator_processor_durable_capture::{
            CoordinatorProcessorDurableGenerationDigest,
            CoordinatorProcessorSourceKind,
        },
        coordinator_guta_durable_submission::CoordinatorGutaQueueItem,
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::{
    backup::output::coordinator_output_builder::CoordinatorOutputBuilder,
    coordinator::{
        processor::{
            PsyCoordinatorProcessor,
            CoordinatorNormalProcessingOwner,
        },
        queue_key::{
            CoordinatorProvingWorkQueueKey,
            CoordinatorSubmitRealmGUTAUpdateQueueKey,
            CoordinatorRegisterUserPublicKeyQueueKey,
            CoordinatorDeployContractQueueKey,
        },
    },
};

enum CoordinatorGatheringOutcome<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
> {
    Legacy(
        PsyNodeProvingState,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        CoordinatorOutputBuilder<N>,
    ),
    AwaitingDurableClose,
    BranchExactFinalized {
        proving_state: PsyNodeProvingState,
        guta_jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        register_user_jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        deploy_contract_jobs: Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>>,
        output_builder: CoordinatorOutputBuilder<N>,
        generation_digest: CoordinatorProcessorDurableGenerationDigest,
        registration_items: u64,
        deploy_items: u64,
        guta_items: u64,
    },
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2,
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
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_pending_id(
                &self.db.ids.realm_identifier,
                unique_pending_id,
            )
            .await?;
        let proof_address = self
            .db
            .proof_store
            .resolve_proof_address(&pending_context, &output_job_id)?;
        let (proof_bytes, reward_value) = publish_wait_for_queue_and_job_ready(
            self.proof_worker_queue_max_time_ms,
            format!(
                "Timed out waiting for persisted proof and reward tree value for {} {:?} at realm {:?}, unique_pending_id {}",
                job_context, output_job_id, self.db.ids.realm_identifier, unique_pending_id,
            ),
            || {
                self.db.proof_work_queue.publish_worker_queue_item_ref(
                    &queue_key,
                    self.db.ids.realm_id_u64,
                    self.db.ids.realm_sub_id_u64,
                    self.db.ids.proc_checkpoint_unique_id,
                    0,
                    job,
                )
            },
            || {
                self.db.proof_work_queue.wait_until_all_jobs_complete_or_timeout_worker(
                    &queue_key,
                    self.db.ids.realm_id_u64,
                    self.db.ids.realm_sub_id_u64,
                    self.db.ids.proc_checkpoint_unique_id,
                    0,
                    self.proof_worker_queue_max_time_ms,
                )
            },
            || self.db.proof_store.get_proof_bytes_exact(&proof_address),
            || {
                self.db.temp_db.get_proof_miner_rewards_tree_value_or_none(
                    &self.db.ids.realm_identifier,
                    &pending_context,
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


    async fn get_results_from_gatherers(
        &mut self,
    ) -> anyhow::Result<CoordinatorGatheringOutcome<N>> {
        let mut owner = self
            .normal_processing_owner
            .take()
            .ok_or_else(|| anyhow::anyhow!("Coordinator processing owner is already borrowed"))?;
        let result = match &mut owner {
            CoordinatorNormalProcessingOwner::Legacy => self
                .get_legacy_results_from_gatherers()
                .await
                .map(|(proving, guta, registration, deploy, output)| {
                    CoordinatorGatheringOutcome::Legacy(
                        proving,
                        guta,
                        registration,
                        deploy,
                        output,
                    )
                }),
            CoordinatorNormalProcessingOwner::BranchExact(branch_exact) => {
                self.get_branch_exact_results_from_gatherers(branch_exact)
                    .await
            }
        };
        self.normal_processing_owner = Some(owner);
        result
    }

    async fn get_branch_exact_results_from_gatherers(
        &mut self,
        owner: &mut psy_node_core::store::coordinator_processor_branch_exact_runtime::CoordinatorBranchExactProcessorOwner,
    ) -> anyhow::Result<CoordinatorGatheringOutcome<N>> {
        let mut iteration = owner.begin_iteration();
        let mut capture = iteration.open_capture().await?;
        let Some(generation) = capture.capture_or_replay().await? else {
            return Ok(CoordinatorGatheringOutcome::AwaitingDurableClose);
        };
        drop(capture);
        let total_items = generation.total_items();
        let (context, generation_digest, registration, deploy, guta) =
            generation.into_sources();
        if self.db.ids.unique_pending_id != context.processing().pending_id().get()
            || self.db.ids.proc_checkpoint_unique_id
                != context.processing().proc_checkpoint_id().as_u128()
        {
            anyhow::bail!(
                "durable Coordinator pipeline processing identity does not match the clean-boundary Processor state"
            );
        }
        let registration_items = registration.items().len() as u64;
        let deploy_items = deploy.items().len() as u64;
        let guta_items = guta.items().len() as u64;
        if registration_items
            .checked_add(deploy_items)
            .and_then(|count| count.checked_add(guta_items))
            != Some(total_items)
        {
            anyhow::bail!("Coordinator durable source counts do not match generation total");
        }

        let (registration_apply, deploy_apply, guta_apply) = tokio::try_join!(
            self.register_user_queue_gatherer
                .apply_coordinator_durable_source(generation_digest, registration),
            self.deploy_contract_queue_gatherer
                .apply_coordinator_durable_source(generation_digest, deploy),
            self.guta_queue_gatherer
                .apply_coordinator_durable_source(generation_digest, guta),
        )?;
        if registration_apply.source_kind()
                != CoordinatorProcessorSourceKind::Registration
            || deploy_apply.source_kind() != CoordinatorProcessorSourceKind::Deploy
            || guta_apply.source_kind() != CoordinatorProcessorSourceKind::Guta
            || registration_apply.generation_digest() != generation_digest
            || deploy_apply.generation_digest() != generation_digest
            || guta_apply.generation_digest() != generation_digest
        {
            anyhow::bail!("Coordinator command actors returned a mixed-generation receipt");
        }
        let (registration, deploy, guta) = tokio::try_join!(
            self.register_user_queue_gatherer
                .finalize_coordinator_durable_source(registration_apply),
            self.deploy_contract_queue_gatherer
                .finalize_coordinator_durable_source(deploy_apply),
            self.guta_queue_gatherer
                .finalize_coordinator_durable_source(guta_apply),
        )?;
        if registration.generation_digest() != generation_digest
            || deploy.generation_digest() != generation_digest
            || guta.generation_digest() != generation_digest
            || registration.source_kind()
                != CoordinatorProcessorSourceKind::Registration
            || deploy.source_kind() != CoordinatorProcessorSourceKind::Deploy
            || guta.source_kind() != CoordinatorProcessorSourceKind::Guta
        {
            anyhow::bail!("Coordinator command actor finalization mixed durable generations");
        }

        let (
            proving_state,
            guta_jobs,
            register_user_jobs,
            deploy_contract_jobs,
            output_builder,
        ) = CoordinatorOutputBuilder::<N>::new(
            &self.db.ids,
            guta.output().clone(),
            registration.output().clone(),
            deploy.output().clone(),
        )?;
        Ok(CoordinatorGatheringOutcome::BranchExactFinalized {
            proving_state,
            guta_jobs,
            register_user_jobs,
            deploy_contract_jobs,
            output_builder,
            generation_digest,
            registration_items,
            deploy_items,
            guta_items,
        })
    }

    async fn get_legacy_results_from_gatherers(&mut self) -> anyhow::Result<(
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
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<CoordinatorGutaQueueItem<N::F, N::QHash>>,
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

        let (proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, output_builder) = CoordinatorOutputBuilder::new(
            &self.db.ids,
            guta_result,
            register_users_result,
            deploy_contract_result,
        )?;
        Ok((proving_state, guta_jobs, register_user_jobs, deploy_contract_jobs, output_builder))
    }
    pub async fn plan_agg_guta_register_users_deploy_contracts_job(
        &self,
        output_builder: &mut CoordinatorOutputBuilder<N>,
    ) -> anyhow::Result<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> {
        let (job_metadata, job_and_witness_bytes) =
            output_builder.get_agg_guta_register_users_deploy_contracts_job(&self.db.last_committed, &self.db.circuit_fingerprint_config)?;
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_pending_id(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
            )
            .await?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, &pending_context, vec![job_and_witness_bytes])
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

        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_pending_id(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
            )
            .await?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, &pending_context, vec![job_and_witness_bytes])
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
    pub async fn plan_genesis_checkpoint_state_transition_proof(&self) -> anyhow::Result<()> {
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
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_pending_id(
                &self.db.ids.realm_identifier,
                self.db.ids.unique_pending_id,
            )
            .await?;
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&self.db.ids.realm_identifier, &pending_context, vec![(job_id, witness_data)])
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
        let gathering = self.get_results_from_gatherers().await?;
        let (
            mut proving_state,
            guta_jobs,
            register_user_jobs,
            deploy_contract_jobs,
            mut output_builder,
            branch_exact,
        ) = match gathering {
            CoordinatorGatheringOutcome::Legacy(
                proving_state,
                guta_jobs,
                register_user_jobs,
                deploy_contract_jobs,
                output_builder,
            ) => (
                proving_state,
                guta_jobs,
                register_user_jobs,
                deploy_contract_jobs,
                output_builder,
                false,
            ),
            CoordinatorGatheringOutcome::AwaitingDurableClose => {
                tracing::info!(
                    "Coordinator branch-exact capture is waiting for all three explicit source closes"
                );
                return Ok(());
            }
            CoordinatorGatheringOutcome::BranchExactFinalized {
                proving_state,
                guta_jobs,
                register_user_jobs,
                deploy_contract_jobs,
                output_builder,
                generation_digest,
                registration_items,
                deploy_items,
                guta_items,
            } => {
                tracing::info!(
                    generation_digest = %hex::encode(generation_digest.as_bytes()),
                    registration_items,
                    deploy_items,
                    guta_items,
                    "Coordinator branch-exact generation finalized; entering proof and exact full-commit path"
                );
                (
                    proving_state,
                    guta_jobs,
                    register_user_jobs,
                    deploy_contract_jobs,
                    output_builder,
                    true,
                )
            }
        };
        let worker_queue_key_for_cleanup = self.db.get_proof_worker_queue_key();
        let worker_unique_id_for_cleanup = self.db.ids.proc_checkpoint_unique_id;

        timer.lap("get_results_from_gatherers");
        let has_jobs = self.get_root_job_ids(
            &guta_jobs,
            &register_user_jobs,
            &deploy_contract_jobs,
        )?;
        timer.lap("get_root_job_ids");
        if self.db.ids.next_checkpoint_id > 1 && has_jobs.is_none() {
            tracing::info!("No jobs to process in this block; creating empty checkpoint state transition.");
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
        if branch_exact {
            let full_commit = self
                .branch_exact_full_commit
                .clone()
                .ok_or_else(|| anyhow::anyhow!(
                    "branch-exact Coordinator Processor has no full-commit store"
                ))?;
            self.db
                .commit_state_branch_exact(
                    full_commit.as_ref(),
                    coordinator_update,
                    ProvingJobCircuitType::GenerateRollupStateTransitionProof,
                    zk_proof,
                )
                .await?;
        } else {
            self.db
                .commit_state(
                    coordinator_update,
                    ProvingJobCircuitType::GenerateRollupStateTransitionProof,
                    zk_proof,
                )
                .await?;
        }
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

    #[test]
    fn branch_exact_coordinator_route_is_command_only_and_avoids_legacy_gathering() {
        let source = include_str!("process_block.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let branch_exact = production
            .split("async fn get_branch_exact_results_from_gatherers")
            .nth(1)
            .unwrap()
            .split("async fn get_legacy_results_from_gatherers")
            .next()
            .unwrap();
        assert!(branch_exact.contains("capture_or_replay"));
        assert_eq!(
            branch_exact
                .matches("apply_coordinator_durable_source")
                .count(),
            3
        );
        assert_eq!(
            branch_exact
                .matches("finalize_coordinator_durable_source")
                .count(),
            3
        );
        assert!(branch_exact.contains("CoordinatorOutputBuilder::<N>::new"));
        for forbidden in [
            "finalize_gathering_and_update_queue_key",
            "set_new_unique_ids",
            "commit_state",
            "publish_worker_queue_item_ref",
        ] {
            assert!(
                !branch_exact.contains(forbidden),
                "branch-exact Coordinator route must not call legacy authority path: {forbidden}"
            );
        }

        let handoff_arm = production
            .rsplit("CoordinatorGatheringOutcome::BranchExactFinalized")
            .next()
            .unwrap()
            .split("let worker_queue_key_for_cleanup")
            .next()
            .unwrap();
        assert!(handoff_arm.contains("true,"));
        assert!(!handoff_arm.contains("get_root_job_ids"));
        assert!(!handoff_arm.contains("publish_jobs"));
        assert!(!handoff_arm.contains("commit_state"));
    }

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
                Ok(())
            },
            move || async move {
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

    #[test]
    fn branch_exact_coordinator_uses_full_commit_and_legacy_keeps_commit_state() {
        let source = include_str!("process_block.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let process = production
            .split("pub async fn process_block")
            .nth(1)
            .unwrap();
        assert!(process.contains("if branch_exact"));
        assert!(process.contains("commit_state_branch_exact("));
        assert!(process.contains("full_commit.as_ref()"));
        assert!(process.contains(".commit_state("));
    }
}
