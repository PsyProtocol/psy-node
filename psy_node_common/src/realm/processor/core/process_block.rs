use cf_utils::timer::TraceTimer;
use parth_core::{
    crypto::hash::traits::ZeroableHash,
    data::queue::queue_key::QPBaseQueueType,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::{
        GlobalUserTreeAggregatorHeaderWithJobId,
        GlobalUserTreeAggregatorHeaderWithTagValue,
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
    },
    node::realm_processor::RealmProcessorCoreState,
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::realm::{
        PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate,
    },
    protocol::chain_context::AuthorityScope,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        realm_processor_actor_input::RealmProcessorActorInput,
        realm_processor_application_proof_work::{
            RealmProcessorApplicationProofWork,
            RealmProcessorApplicationProofWorkOutcome,
        },
        realm_processor_durable_capture::{
            RealmProcessorApplicationHandoffObservation,
            RealmProcessorDurableCaptureOutcome,
        },
        realm_processor_deferred_actor_input::RealmProcessorDeferredActorInputOutcome,
        realm_processor_generation_continuation::{
            RealmProcessorGenerationContinuation,
            RealmProcessorGenerationContinuationPhase,
        },
        realm_processor_narrow_writer::RealmProcessorVerifiedNarrowWriterEvidence,
        realm_processor_semantic_output::{
            RealmProcessorDeferredJob, RealmProcessorSemanticJob,
            RealmProcessorSemanticOutput, RealmProcessorSemanticOutputParts,
        },
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::{
        authority_commit::AuthorityClockSampleUs,
        pending_generation_identity::PendingGenerationContext,
        realm_proof_binding::SealedRealmProofBinding,
        realm_processor_quiescence::RealmProcessorIterationPermit,
        traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::realm::{
    processor::{
        commit_input::RealmCommitInput,
        core::{PsyRealmProcessor, RealmNormalCommitIteration},
        gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput,
    },
    queue_key::RealmProvingWorkQueueKey,
};

use crate::queue::gatherer::DurableTreeGathererFinalizeReceipt;

enum RealmGatheringOutcome<F, Hash, JobId> {
    Legacy(RealmGUTAEndCapGathererOutput<F, Hash, JobId>),
    BranchExactApplicationHandoff(RealmProcessorApplicationHandoffObservation),
    BranchExactGenerationContinuation(RealmProcessorGenerationContinuation),
    BranchExactAwaitingDeferredCarryover(RealmProcessorGenerationContinuation),
    BranchExactAwaitingClosedSource,
}

async fn observe_exact_coordinator_inclusion<F, Hash, CoordinatorClient>(
    coordinator_client: &CoordinatorClient,
    realm_id: u64,
    old_realm_root: Hash,
    new_realm_root: Hash,
) -> anyhow::Result<Option<PsyRealmCoordinatorUpdate<F, Hash>>>
where
    Hash: Copy + PartialEq + std::fmt::Debug,
    CoordinatorClient: RealmCoordinatorClient<F, Hash> + Send + Sync,
{
    let checkpoint_id = coordinator_client.rc_get_latest_checkpoint_id().await?;
    let realm_state = coordinator_client
        .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, realm_id)
        .await?;
    if realm_state.value == new_realm_root {
        return coordinator_client
            .rc_get_realm_sync_info(realm_state.checkpoint_id, realm_id)
            .await
            .map(Some);
    }
    if realm_state.value != old_realm_root {
        anyhow::bail!(
            "branch-exact Realm root diverged: expected {:?} -> {:?}, found {:?} at checkpoint {}",
            old_realm_root,
            new_realm_root,
            realm_state.value,
            realm_state.checkpoint_id,
        );
    }
    Ok(None)
}

async fn wait_for_exact_coordinator_inclusion<F, Hash, CoordinatorClient>(
    coordinator_client: &CoordinatorClient,
    realm_id: u64,
    old_realm_root: Hash,
    new_realm_root: Hash,
) -> anyhow::Result<PsyRealmCoordinatorUpdate<F, Hash>>
where
    Hash: Copy + PartialEq + std::fmt::Debug,
    CoordinatorClient: RealmCoordinatorClient<F, Hash> + Send + Sync,
{
    loop {
        if let Some(update) = observe_exact_coordinator_inclusion(
            coordinator_client,
            realm_id,
            old_realm_root,
            new_realm_root,
        )
        .await?
        {
            return Ok(update);
        }
        coordinator_client.rc_wait_for_next_checkpoint().await?;
    }
}

/// Submit one exact Realm proof, recovering an accepted submission by reading
/// the Coordinator before and after the RPC. This function is the sole
/// response-loss policy shared by the live Processor and the RF=3 transport
/// qualification; neither path retries a submission whose inclusion is
/// already durable.
async fn submit_or_recover_exact_coordinator_inclusion<
    F,
    Hash,
    CoordinatorClient,
>(
    coordinator_client: &CoordinatorClient,
    realm_id: u64,
    old_realm_root: Hash,
    new_realm_root: Hash,
    submission: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>,
    proof: Vec<u8>,
) -> anyhow::Result<PsyRealmCoordinatorUpdate<F, Hash>>
where
    Hash: Copy + PartialEq + std::fmt::Debug,
    CoordinatorClient: RealmCoordinatorClient<F, Hash> + Send + Sync,
{
    if let Some(coordinator) = observe_exact_coordinator_inclusion(
        coordinator_client,
        realm_id,
        old_realm_root,
        new_realm_root,
    )
    .await?
    {
        return Ok(coordinator);
    }

    match coordinator_client
        .rc_submit_guta_proof(submission, proof, realm_id)
        .await
    {
        Ok(()) => {
            wait_for_exact_coordinator_inclusion(
                coordinator_client,
                realm_id,
                old_realm_root,
                new_realm_root,
            )
            .await
        }
        Err(error) => match observe_exact_coordinator_inclusion(
            coordinator_client,
            realm_id,
            old_realm_root,
            new_realm_root,
        )
        .await?
        {
            Some(coordinator) => Ok(coordinator),
            None => Err(error),
        },
    }
}

#[cfg(feature = "rf3-test-support")]
pub async fn qualification_submit_or_recover_exact_coordinator_inclusion<
    F,
    Hash,
    CoordinatorClient,
>(
    coordinator_client: &CoordinatorClient,
    realm_id: u64,
    old_realm_root: Hash,
    new_realm_root: Hash,
    submission: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<F, Hash>,
    proof: Vec<u8>,
) -> anyhow::Result<PsyRealmCoordinatorUpdate<F, Hash>>
where
    Hash: Copy + PartialEq + std::fmt::Debug,
    CoordinatorClient: RealmCoordinatorClient<F, Hash> + Send + Sync,
{
    submit_or_recover_exact_coordinator_inclusion(
        coordinator_client,
        realm_id,
        old_realm_root,
        new_realm_root,
        submission,
        proof,
    )
    .await
}

async fn project_branch_exact_semantic_output<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
>(
    temp_db: &TempDatabase,
    state: &RealmProcessorCoreState<N::QHash>,
    processing: PendingGenerationContext,
    receipt: &DurableTreeGathererFinalizeReceipt<
        RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>,
    >,
) -> anyhow::Result<RealmProcessorSemanticOutput> {
    let output = receipt.output();
    let pending_context = temp_db
        .require_pending_context_for_generation(&state.realm_identifier, processing)
        .await?;
    let mut jobs = Vec::new();
    for (level, level_jobs) in output.job_ids.iter().enumerate() {
        let level = u16::try_from(level)?;
        for (ordinal, job) in level_jobs.iter().enumerate() {
            let witness = temp_db
                .get_tdb_proof_witness_bytes(
                    &state.realm_identifier,
                    &pending_context,
                    job.job_id,
                )
                .await?;
            jobs.push(RealmProcessorSemanticJob::try_new(
                level,
                u32::try_from(ordinal)?,
                job.psy_ser_to_bytes_vec()?,
                witness,
            )?);
        }
    }
    let deferred_jobs = output
        .deferred_jobs
        .iter()
        .enumerate()
        .map(|(ordinal, job)| {
            Ok(RealmProcessorDeferredJob::try_new(
                u32::try_from(ordinal)?,
                job.queue_item.psy_ser_to_bytes_vec()?,
                job.contract_updates.clone(),
            )?)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    RealmProcessorSemanticOutput::try_from_candidate_parts(
        RealmProcessorSemanticOutputParts {
            context_digest: receipt.context_digest(),
            generation_digest: receipt.generation_digest(),
            boundary_digest: receipt.boundary_digest(),
            item_count: receipt.item_count(),
            input_binding: psy_node_core::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::SuccessorQualified(
                receipt.actor_input_digest(),
            ),
            processing_checkpoint_id: state.processing_checkpoint_id,
            processing_checkpoint_root: state.processing_checkpoint_root.into_owned_32bytes(),
            processing_realm_start_root: state.processing_realm_start_root.into_owned_32bytes(),
            old_realm_root: output.db_output.old_realm_root.into_owned_32bytes(),
            new_realm_root: output.db_output.new_realm_root.into_owned_32bytes(),
            total_users_updated: output.db_output.total_users_updated,
            total_proofs_generated: output.db_output.total_proofs_generated,
            global_user_tree_nodes: output.db_output.update_global_user_tree_nodes_ffs.clone(),
            user_contract_tree_nodes: output.db_output.update_user_contract_tree_nodes_ffs.clone(),
            contract_state_tree_nodes: output.db_output.update_contract_state_tree_nodes_ffs.clone(),
            user_leaves: output.db_output.update_user_leaves_ffs.clone(),
            contract_state_imt_leaves: output.db_output.update_contract_state_imt_leaves_ffs.clone(),
            guta_header: output.db_output.guta_header.psy_ser_to_bytes_vec()?,
            jobs,
            deferred_jobs,
        },
    )
    .map_err(anyhow::Error::from)
}

/// RF=3 qualification uses the exact same semantic projection as the real
/// Processor without exposing the Processor owner or any storage receipt.
#[cfg(feature = "rf3-test-support")]
pub async fn qualification_project_branch_exact_semantic_output<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
>(
    temp_db: &TempDatabase,
    state: &RealmProcessorCoreState<N::QHash>,
    processing: PendingGenerationContext,
    receipt: &DurableTreeGathererFinalizeReceipt<
        RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>,
    >,
) -> anyhow::Result<RealmProcessorSemanticOutput> {
    project_branch_exact_semantic_output::<N, TempDatabase>(
        temp_db,
        state,
        processing,
        receipt,
    )
    .await
}

pub(super) enum RealmOwnedIterationError {
    MissingCommitOwner,
    Begin(anyhow::Error),
    Sync(anyhow::Error),
    Process(anyhow::Error),
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + QCanonicalProofStoreV2,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    FileSystem::File: Send + Sync,
{
    pub async fn publish_all_worker_jobs(
        &self,
        mut proving_state: PsyNodeProvingState,
        queue_key: &RealmProvingWorkQueueKey<N::QHash, N::JobId>,
        jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<()> {
        let mut timer = TraceTimer::new("publish_all_worker_jobs");

        let mut non_empty_levels = 0usize;
        for level in 0..jobs.len() {
            if jobs[level].is_empty() {
                continue;
            }

            proving_state.set_current_proving_level(non_empty_levels as u8);
            self.db.temp_db.set_psy_node_proving_state(&self.db.state.realm_identifier, &proving_state).await?;
            non_empty_levels+=1;

            tracing::info!("Publishing {} jobs at level {}", jobs[level].len(), level);
            self.db
                .proof_work_queue
                .publish_many_worker_queue_items(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    self.db.state.processing_proc_checkpoint_unique_id,
                    0,
                    &jobs[level],
                )
                .await?;
            timer.lap("published jobs");
            tracing::info!("Published all jobs at level {}", level);

            // We wait level-by-level because higher levels usually depend on the output of
            // lower levels.
            self.db
                .proof_work_queue
                .wait_until_all_jobs_complete_or_timeout_worker(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    self.db.state.processing_proc_checkpoint_unique_id,
                    0,
                    self.proof_worker_queue_max_time_ms,
                )
                .await?;
            timer.lap("waited for jobs to complete");
            tracing::info!("All jobs at level {} completed", level);
        }
        proving_state.finish();
        self.db.temp_db.set_psy_node_proving_state(&self.db.state.realm_identifier, &proving_state).await?;
        Ok(())
    }

    /// Publish proof work in the storage-selected pending/proc namespace.
    /// The legacy mutable processor singleton is deliberately not consulted.
    async fn publish_branch_exact_worker_jobs(
        &self,
        mut proving_state: PsyNodeProvingState,
        processing: PendingGenerationContext,
        queue_key: &RealmProvingWorkQueueKey<N::QHash, N::JobId>,
        jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>],
    ) -> anyhow::Result<()> {
        let worker_unique_id = processing.proc_checkpoint_id().as_u128();
        let mut non_empty_levels = 0usize;
        for (level, level_jobs) in jobs.iter().enumerate() {
            if level_jobs.is_empty() {
                continue;
            }
            proving_state.set_current_proving_level(u8::try_from(non_empty_levels)?);
            self.db
                .temp_db
                .set_psy_node_proving_state(
                    &self.db.state.realm_identifier,
                    &proving_state,
                )
                .await?;
            non_empty_levels += 1;
            self.db
                .proof_work_queue
                .publish_many_worker_queue_items(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    worker_unique_id,
                    0,
                    level_jobs,
                )
                .await?;
            self.db
                .proof_work_queue
                .wait_until_all_jobs_complete_or_timeout_worker(
                    queue_key,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    worker_unique_id,
                    0,
                    self.proof_worker_queue_max_time_ms,
                )
                .await?;
            tracing::info!(
                "Branch-exact proof level {} completed in pending={} proc={}",
                level,
                processing.pending_id().get(),
                worker_unique_id,
            );
        }
        proving_state.finish();
        self.db
            .temp_db
            .set_psy_node_proving_state(
                &self.db.state.realm_identifier,
                &proving_state,
            )
            .await?;
        Ok(())
    }

    async fn get_branch_exact_reward_tree_root(
        &self,
        processing: PendingGenerationContext,
        job_id: N::JobId,
    ) -> anyhow::Result<N::QHash> {
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_generation(
                &self.db.state.realm_identifier,
                processing,
            )
            .await?;
        if let Some(root) = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.db.state.realm_identifier,
                &pending_context,
                job_id,
            )
            .await?
        {
            if root != N::QHash::get_zero_value()
                || processing.pending_id().get() == 0
            {
                return Ok(root);
            }
        }
        let root = self
            .db
            .tag_tree_rewards_store
            .rewards_tag_tree_get_root_at_unique_pending_id(
                processing.pending_id().get(),
            )
            .await?;
        if root == N::QHash::get_zero_value()
            && processing.pending_id().get() != 0
        {
            anyhow::bail!(
                "branch-exact reward root is missing for pending {}",
                processing.pending_id().get()
            );
        }
        Ok(root)
    }

    fn branch_exact_clock_sample() -> anyhow::Result<AuthorityClockSampleUs> {
        let micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_micros();
        AuthorityClockSampleUs::try_from_i128(i128::try_from(micros)?)
            .map_err(anyhow::Error::from)
    }

    /// Resume `WorkCaptured` from immutable storage, execute the real proof
    /// protocol, bind the exact Coordinator response, and enter only the
    /// narrow mapping/reward-proof writer. Full writer/head/terminal/rotation
    /// remain later gates.
    async fn resume_branch_exact_await_writer(
        &mut self,
        iteration: &mut psy_node_core::store::realm_processor_branch_exact_runtime::RealmBranchExactCommitIteration<'_, N::QHash>,
    ) -> anyhow::Result<()> {
        let work = match iteration.prepare_application_proof_work().await? {
            RealmProcessorApplicationProofWorkOutcome::AwaitProoflessApplication {
                processing,
                application,
            } => {
                tracing::info!(
                    "Branch-exact application {:?} in pending={} contains durable deferred work but no checkpoint proof; awaiting the proofless terminal path",
                    application.archive_slot(),
                    processing.pending_id().get(),
                );
                return Ok(());
            }
            RealmProcessorApplicationProofWorkOutcome::Ready(work) => work,
        };
        self.execute_branch_exact_proof_and_narrow_write(iteration, work)
            .await
    }

    async fn execute_branch_exact_proof_and_narrow_write(
        &mut self,
        iteration: &mut psy_node_core::store::realm_processor_branch_exact_runtime::RealmBranchExactCommitIteration<'_, N::QHash>,
        work: RealmProcessorApplicationProofWork,
    ) -> anyhow::Result<()> {
        let processing = work.processing();
        let semantic = work.semantic();
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_generation(
                &self.db.state.realm_identifier,
                processing,
            )
            .await?;

        let mut jobs = Vec::<
            Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
        >::new();
        let mut witnesses = Vec::with_capacity(semantic.jobs().len());
        for stored in semantic.jobs() {
            let level = usize::from(stored.level());
            while jobs.len() <= level {
                jobs.push(Vec::new());
            }
            if usize::try_from(stored.ordinal())? != jobs[level].len() {
                anyhow::bail!("non-canonical branch-exact proof job ordinal");
            }
            let metadata = PsyProvingJobMetadataWithJobId::<
                N::QHash,
                N::JobId,
            >::psy_ser_from_slice(stored.metadata())?;
            if metadata.psy_ser_to_bytes_vec()? != stored.metadata() {
                anyhow::bail!("non-canonical branch-exact proof metadata");
            }
            witnesses.push((metadata.job_id, stored.witness().to_vec()));
            jobs[level].push(metadata);
        }
        self.db
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(
                &self.db.state.realm_identifier,
                &pending_context,
                witnesses,
            )
            .await?;
        for (level, level_jobs) in jobs.iter().enumerate() {
            for (ordinal, metadata) in level_jobs.iter().enumerate() {
                let stored = semantic
                    .jobs()
                    .iter()
                    .find(|job| {
                        usize::from(job.level()) == level
                            && usize::try_from(job.ordinal()).ok()
                                == Some(ordinal)
                    })
                    .ok_or_else(|| anyhow::anyhow!("missing semantic proof job"))?;
                let exact = self
                    .db
                    .temp_db
                    .get_tdb_proof_witness_bytes(
                        &self.db.state.realm_identifier,
                        &pending_context,
                        metadata.job_id,
                    )
                    .await?;
                if exact != stored.witness() {
                    anyhow::bail!("branch-exact proof witness readback mismatch");
                }
            }
        }

        let root_job_id = self
            .get_root_job_id(&jobs)?
            .ok_or_else(|| anyhow::anyhow!("proof-bearing application has no root job"))?;
        let guta_header = GlobalUserTreeAggregatorHeaderWithJobId::<
            N::F,
            N::QHash,
        >::psy_ser_from_slice(semantic.guta_header())?;
        if guta_header.psy_ser_to_bytes_vec()? != semantic.guta_header()
            || guta_header.job_id != root_job_id
        {
            anyhow::bail!("application GUTA header/root job mismatch");
        }
        let actual_jobs = jobs.iter().map(Vec::len).sum::<usize>();
        let proving_state = PsyNodeProvingState::new_standard_realm(
            self.db.state.realm_id_u64,
            u32::try_from(self.db.state.realm_sub_id_u64)?,
            semantic.processing_checkpoint_id(),
            semantic.processing_checkpoint_id(),
            semantic.total_users_updated(),
            semantic.total_proofs_generated(),
        );
        if u64::try_from(actual_jobs)? != proving_state.total_guta_jobs {
            anyhow::bail!(
                "application proof job count {} does not match semantic total {}",
                actual_jobs,
                proving_state.total_guta_jobs,
            );
        }
        let queue_key = RealmProvingWorkQueueKey {
            realm_id: self.db.state.realm_id_u64,
            realm_sub_id: self.db.state.realm_sub_id_u64,
            unique_id: processing.proc_checkpoint_id().as_u128(),
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let proof_address = self
            .db
            .proof_store
            .resolve_proof_address(&pending_context, &root_job_id)?;
        let recovered_root_proof = self
            .db
            .proof_store
            .get_proof_bytes_exact(&proof_address)
            .await?;
        let root_proof = if let Some(root_proof) = recovered_root_proof {
            tracing::info!(
                "Recovered exact branch-exact root proof for pending={} proc={}; proof workers are not republished",
                processing.pending_id().get(),
                processing.proc_checkpoint_id().as_u128(),
            );
            root_proof
        } else {
            self.publish_branch_exact_worker_jobs(
                proving_state,
                processing,
                &queue_key,
                &jobs,
            )
            .await?;
            self.db
                .proof_store
                .get_proof_bytes_exact(&proof_address)
                .await?
                .ok_or_else(|| anyhow::anyhow!("missing exact root GUTA proof"))?
        };
        let rewards_root = self
            .get_branch_exact_reward_tree_root(processing, root_job_id)
            .await?;
        let submission = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: guta_header.header,
                new_tag_tree_node_value: rewards_root,
            },
            job_type_u32: root_job_id.circuit_type as u32,
        };

        let prepared = work.prepared_update::<N::QHash>(
            u32::try_from(self.db.state.realm_id_u64)?,
            u16::try_from(self.db.state.realm_sub_id_u64)?,
        );
        let coordinator = submit_or_recover_exact_coordinator_inclusion(
            self.db.coordinator_client.as_ref(),
            self.db.state.realm_id_u64,
            prepared.old_realm_root,
            prepared.new_realm_root,
            submission,
            root_proof.clone(),
        )
        .await?;
        let authority = AuthorityScope::Realm {
            realm_id: u32::try_from(self.db.state.realm_id_u64)?,
            realm_sub_id: u16::try_from(self.db.state.realm_sub_id_u64)?,
        };
        let proof_verifier = self.proof_verifier.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "branch-exact proof verifier is absent from the authorized runtime"
            )
        })?;
        let proof_binding = SealedRealmProofBinding::verify_and_seal::<
            N::F,
            N::HasherBase,
            N::ZKProof,
            N::ZKVerifier,
        >(
            authority,
            &prepared,
            &submission,
            &root_proof,
            proof_verifier,
            &coordinator,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        )?;
        let evidence = RealmProcessorVerifiedNarrowWriterEvidence::try_from_verified(
            u32::try_from(self.db.state.realm_id_u64)?,
            u16::try_from(self.db.state.realm_sub_id_u64)?,
            &work,
            &proof_binding,
            &coordinator,
        )?;
        let observation = iteration
            .prepare_mapping_and_reward_proof(
                &evidence,
                Self::branch_exact_clock_sample()?,
            )
            .await?;
        tracing::info!(
            "Branch-exact narrow writer prepared application {:?}: pending={}, pipeline_revision={}, writer_revision={}, intent={:?}; full writer/head/terminal/rotation remain blocked",
            observation.application().archive_slot(),
            observation.processing().pending_id().get(),
            observation.pipeline_revision().get(),
            observation.writer_revision(),
            observation.intent_digest(),
        );
        if let Err(error) = self
            .db
            .proof_work_queue
            .delete_worker_queue_consumer(
                &queue_key,
                self.db.state.realm_id_u64,
                self.db.state.realm_sub_id_u64,
                processing.proc_checkpoint_id().as_u128(),
                0,
            )
            .await
        {
            tracing::warn!(
                "failed to delete branch-exact proof worker consumer after narrow writer commit: {}",
                error
            );
        }
        Ok(())
    }

    pub fn get_root_job_id(&self, guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>]) -> anyhow::Result<Option<N::JobId>> {
        let guta_root_job = guta_jobs.last().and_then(|jobs_at_level| jobs_at_level.first());
        if let Some(job) = guta_root_job {
            Ok(Some(job.job_id.clone()))
        } else {
            Ok(None)
        }
    }

    /// Project a finalized command-only builder into the complete canonical
    /// application payload that c4a2 will archive.  Every proof witness is
    /// read back from the exact processing pending namespace; a missing
    /// dependency fails before any pipeline handoff can exist.
    async fn build_branch_exact_semantic_output(
        &self,
        processing: PendingGenerationContext,
        receipt: &DurableTreeGathererFinalizeReceipt<
            RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>,
        >,
    ) -> anyhow::Result<RealmProcessorSemanticOutput> {
        project_branch_exact_semantic_output::<N, TempDatabase>(
            self.db.temp_db.as_ref(),
            &self.db.state,
            processing,
            receipt,
        )
        .await
    }

    async fn get_results_from_gatherers(
        &mut self,
        iteration: &mut RealmNormalCommitIteration<'_, N::QHash>,
    ) -> anyhow::Result<RealmGatheringOutcome<N::F, N::QHash, N::JobId>> {
        if let RealmNormalCommitIteration::BranchExact(iteration) = iteration {
            let continuation = iteration.observe_generation_continuation().await?;
            if continuation.phase()
                != RealmProcessorGenerationContinuationPhase::CaptureClosedSource
            {
                return Ok(RealmGatheringOutcome::BranchExactGenerationContinuation(
                    continuation,
                ));
            }
            let deferred_input = match iteration.prepare_deferred_actor_input().await? {
                RealmProcessorDeferredActorInputOutcome::AwaitExplicitCarryover {
                    continuation,
                } => {
                    return Ok(RealmGatheringOutcome::BranchExactAwaitingDeferredCarryover(
                        continuation,
                    ));
                }
                RealmProcessorDeferredActorInputOutcome::Ready(input) => input,
            };
            let processing = deferred_input.successor();
            let mut capture = iteration
                .open_durable_capture_for_deferred_input(deferred_input)
                .await?;
            if let Some(recovered) = capture.recover_application_handoff().await? {
                return Ok(RealmGatheringOutcome::BranchExactApplicationHandoff(
                    recovered,
                ));
            }

            let generation = match capture.replay_complete_generation().await? {
                Some(generation) => Some(generation),
                None => loop {
                    match capture.capture_next().await? {
                        Some(RealmProcessorDurableCaptureOutcome::Data(_)) => {}
                        Some(RealmProcessorDurableCaptureOutcome::Sealed { .. }) => {
                            break capture.replay_complete_generation().await?;
                        }
                        None => break None,
                    }
                },
            };
            let Some(generation) = generation else {
                return Ok(RealmGatheringOutcome::BranchExactAwaitingClosedSource);
            };
            let external_input = capture.qualify_external_actor_input(generation).await?;
            let deferred_input = capture.take_deferred_actor_input().await?;
            let actor_input = RealmProcessorActorInput::try_new(
                deferred_input,
                external_input,
            )?;
            let receipt = self
                .guta_queue_gatherer
                .apply_durable_generation(actor_input)
                .await?;
            let finalized = self
                .guta_queue_gatherer
                .finalize_durable_generation(receipt)
                .await?;
            let semantic = self
                .build_branch_exact_semantic_output(processing, &finalized)
                .await?;
            let handoff = capture
                .persist_application_and_handoff(semantic)
                .await?;
            return Ok(RealmGatheringOutcome::BranchExactApplicationHandoff(
                handoff,
            ));
        }

        // Sanity: outside of genesis, init must have already rotated the unique IDs once,
        // so gathering and processing IDs must differ. If they don't, state is corrupt —
        // bail rather than silently double-rotating.
        let ids_undifferentiated = self.db.state.gathering_proc_checkpoint_unique_id == self.db.state.processing_proc_checkpoint_unique_id
            || self.db.state.gathering_unique_pending_id == self.db.state.processing_unique_pending_id;
        if ids_undifferentiated && self.db.state.last_committed_checkpoint_id != 0 {
            anyhow::bail!(
                "Unique IDs not differentiated outside of genesis (last_committed_checkpoint_id={}). \
                 init.rs::init_with_setup_and_genesis must have run set_new_unique_ids before reaching here.",
                self.db.state.last_committed_checkpoint_id
            );
        }

        // Single rotation per block. `set_new_unique_ids` itself ensures the streams and
        // consumers (including the genesis processing-id consumer when applicable), so
        // no manual ensure_stream / ensure_consumer is needed here. Calling it twice — as
        // the previous genesis branch did — would advance unique_pending_id by two for
        // the first block and silently drop the genesis-time finalize output.
        self.db.set_new_unique_ids(None).await?;

        // Reset revert flag if it was set, as we are starting a fresh attempt
        if self.db.needs_revert {
            self.db.needs_revert = false;
        }

        let guta_result = self
            .guta_queue_gatherer
            // The gatherer actor owns the queue-key rotation. Mutating the
            // shared status manager before sending this command would let a
            // stale caller rotate a paused gatherer even though the command
            // itself is rejected.
            .finalize_gathering_and_update_queue_key(self.db.state.gathering_proc_checkpoint_unique_id)
            .await?;

        Ok(RealmGatheringOutcome::Legacy(guta_result))
    }

    pub async fn sync_and_verify(&mut self) -> anyhow::Result<()> {
        // let mut timer = TraceTimer::new("sync_and_verify");
        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block before
        // sync_with_coordinator").await?;

        // 1. Sync & Verify Consistency
        // We attempt to ensure we are consistent. If we are behind, we catch up.
        self.db.sync_with_coordinator().await?;
        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block after
        // sync_with_coordinator").await?;

        match self.db.ensure_db_matches_coordinator_head().await {
            Ok(_) => {
                // Consistent, proceed
            }
            Err(e) => {
                let err_str = e.to_string();
                if err_str.contains("Local database is stale") || err_str.contains("Realm Root mismatch") {
                    tracing::warn!("Coordinator is ahead of local DB ({}), attempting to fast-forward sync...", err_str);
                    // We are behind. The coordinator has processed updates we missed (perhaps while
                    // we were down). We must sync to the latest state before
                    // doing anything else.
                    self.db.sync_to_coordinator_set_checkpoint_id().await?;

                    // Re-verify after sync
                    self.db.ensure_db_matches_coordinator_head().await?;
                    // timer.lap("recovery_sync");
                    tracing::info!("Fast-forward sync complete. Resuming block processing.");
                } else {
                    return Err(e);
                }
            }
        }
        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block after
        // ensure_db_matches_coordinator_head").await?;

        // timer.lap("sync_and_verify_coordinator");
        Ok(())
    }

    pub(super) async fn process_block(
        &mut self,
        iteration: &mut RealmNormalCommitIteration<'_, N::QHash>,
    ) -> anyhow::Result<()> {
        self.db.run_sanity_check("process_block start").await?;
        let mut timer = TraceTimer::new("process_block");
        tracing::info!(
            "Starting to process new realm block. Last Committed Checkpoint: {}",
            self.db.state.last_committed_checkpoint_id
        );

        // 2. Gather Updates
        let guta_output = match self.get_results_from_gatherers(iteration).await? {
            RealmGatheringOutcome::Legacy(output) => output,
            RealmGatheringOutcome::BranchExactApplicationHandoff(handoff) => {
                tracing::info!(
                    "Branch-exact application archive is the first durable pipeline candidate: archive={:?}, archive_digest={:?}, semantic={:?}, pipeline_revision={}, has_work={}; proof/writer/head remain blocked",
                    handoff.archive_slot(),
                    handoff.archive_digest(),
                    handoff.semantic_digest(),
                    handoff.pipeline_revision(),
                    handoff.has_application_work(),
                );
                return Ok(());
            }
            RealmGatheringOutcome::BranchExactGenerationContinuation(continuation) => {
                if continuation.phase()
                    == RealmProcessorGenerationContinuationPhase::AwaitWriter
                {
                    let RealmNormalCommitIteration::BranchExact(iteration) = iteration
                    else {
                        anyhow::bail!(
                            "branch-exact continuation observed under legacy iteration"
                        );
                    };
                    return self
                        .resume_branch_exact_await_writer(iteration)
                        .await;
                }
                tracing::info!(
                    "Branch-exact generation is durably classified as {:?}: processing_pending={}, pipeline_revision={}; its next qualified owner is not integrated yet",
                    continuation.phase(),
                    continuation.processing().pending_id().get(),
                    continuation.pipeline_revision().get(),
                );
                return Ok(());
            }
            RealmGatheringOutcome::BranchExactAwaitingDeferredCarryover(continuation) => {
                tracing::debug!(
                    "Branch-exact processing generation has no explicit durable carryover: processing_pending={}, pipeline_revision={}; missing is not empty and capture/actor remain unopened",
                    continuation.processing().pending_id().get(),
                    continuation.pipeline_revision().get(),
                );
                return Ok(());
            }
            RealmGatheringOutcome::BranchExactAwaitingClosedSource => {
                tracing::debug!(
                    "Branch-exact processing source is not durably closed yet; no semantic or commit action taken"
                );
                return Ok(());
            }
        };
        let guta_jobs = guta_output.job_ids;
        let guta_update = guta_output.db_output;

        timer.lap("get_results_from_gatherers");
        let worker_queue_key_for_cleanup = self.db.get_proof_worker_queue_key();
        let worker_unique_id_for_cleanup = self.db.state.processing_proc_checkpoint_unique_id;

        // 3. Check for work BEFORE mutating processing_realm_end_root. The new root is
        // only meaningful when we are going to commit a block; if there are no jobs we
        // must leave processing state untouched so we don't rely on a downstream sync
        // overwriting it back to the coordinator value.
        let root_job_id = self.get_root_job_id(&guta_jobs)?;
        if root_job_id.is_none() {
            tracing::info!("No GUTA jobs to process in this block, skipping.");
            self.db.sync_to_coordinator_set_checkpoint_id().await?;
            if let Err(err) = self
                .db
                .proof_work_queue
                .delete_worker_queue_consumer(
                    &worker_queue_key_for_cleanup,
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    worker_unique_id_for_cleanup,
                    0,
                )
                .await
            {
                tracing::warn!(
                    "Failed to delete empty realm worker queue consumer after sync: {}",
                    err
                );
            }
            return Ok(());
        }
        let root_job_id = root_job_id.unwrap();
        timer.lap("get_root_job_ids");

        // Record the new realm root the upcoming commit will promote to last_committed
        // via commit_processing(). Must happen after the no-jobs early return so that
        // path leaves processing_realm_end_root untouched.
        self.db.state.processing_realm_end_root = guta_update.new_realm_root;

        let proving_state = PsyNodeProvingState::new_standard_realm(
            self.db.state.realm_id_u64,
            self.db.state.realm_identifier.realm_sub_id as u32,
            self.db.state.processing_checkpoint_id,
            self.db.state.last_committed_checkpoint_id,
            guta_update.total_users_updated,
            guta_update.total_proofs_generated,
        );
        // sanity check for dev
        let actual_guta_jobs_total = guta_jobs.iter().map(|level_jobs| level_jobs.len()).sum::<usize>();
        if actual_guta_jobs_total as u64 != proving_state.total_guta_jobs {
            tracing::error!(
                "GUTA jobs total ({}) does not match expected total from proving state ({}).",
                actual_guta_jobs_total,
                proving_state.total_guta_jobs
            );
            anyhow::bail!(
                "GUTA jobs total ({}) does not match expected total from proving state ({}).",
                actual_guta_jobs_total,
                proving_state.total_guta_jobs
            );
        }
        // 4. Proving Work
        self.publish_all_worker_jobs(proving_state, &worker_queue_key_for_cleanup, &guta_jobs).await?;
        timer.lap("publish_all_worker_jobs");
        tracing::info!("GUTA jobs completed!");

        // 5. Retrieve Proof
        let pending_context = self
            .db
            .temp_db
            .require_pending_context_for_pending_id(
                &self.db.state.realm_identifier,
                self.db.state.processing_unique_pending_id,
            )
            .await?;
        let root_proof_address = self
            .db
            .proof_store
            .resolve_proof_address(&pending_context, &root_job_id)?;
        let root_job_proof = self
            .db
            .proof_store
            .get_proof_bytes_exact(&root_proof_address)
            .await?;
        if root_job_proof.is_none() {
            anyhow::bail!("No proof found for root GUTA job id: {:?}", root_job_id);
        }
        let root_job_proof = root_job_proof.unwrap();
        timer.lap("get_root_job_proof");

        // 6. Get Rewards Root
        let rewards_root = self
            .db
            .get_reward_tree_root(
                self.db.state.processing_checkpoint_id,
                self.db.state.processing_unique_pending_id,
                root_job_id,
            )
            .await?;

        let submission_header = GlobalUserTreeAggregatorHeaderWithTagValueAndJobType {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: guta_update.guta_header.header,
                new_tag_tree_node_value: rewards_root,
            },
            job_type_u32: root_job_id.circuit_type as u32,
        };
        timer.lap("build_submission_header");

        // 7. Submit to Coordinator
        tracing::info!("Submitting GUTA proof to Coordinator...");
        self.db
            .coordinator_client
            .rc_submit_guta_proof(submission_header, root_job_proof.clone(), self.db.state.realm_id_u64)
            .await?;
        timer.lap("submit_guta_proof");

        // 8. Wait for Coordinator Commit
        tracing::info!("Waiting for Coordinator to include Realm Root: {:?}", guta_update.new_realm_root);
        let sync_info = self.db.wait_for_realm_update_sync_with_coordinator(guta_update.new_realm_root).await?;
        timer.lap("wait_for_realm_update_sync");

        // 9. Commit Local State
        let db_output = PsyPreparedRealmBlockStateUpdates {
            unique_pending_id: self.db.state.processing_unique_pending_id,
            proc_checkpoint_unique_id: self.db.state.processing_proc_checkpoint_unique_id,
            realm_id: self.db.state.realm_id_u64,
            realm_sub_id: self.db.state.realm_sub_id_u64,
            old_realm_root: guta_update.old_realm_root,
            new_realm_root: guta_update.new_realm_root,
            update_user_contract_tree_nodes_ffs: guta_update.update_user_contract_tree_nodes_ffs,
            update_contract_state_tree_nodes_ffs: guta_update.update_contract_state_tree_nodes_ffs,
            update_user_leaves_ffs: guta_update.update_user_leaves_ffs,
            update_global_user_tree_nodes_ffs: guta_update.update_global_user_tree_nodes_ffs,
            update_contract_state_imt_leaves_ffs: guta_update.update_contract_state_imt_leaves_ffs,
        };

        self.db.run_sanity_check("before commit").await?;

        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block before
        // commit_state").await?;

        let commit_input = RealmCommitInput::try_live_proof(
            &sync_info,
            &db_output,
            &submission_header,
            &root_job_proof,
        )?;
        self.commit_live(iteration, commit_input).await?;
        timer.lap("commit_state");
        self.db.run_sanity_check("after commit").await?;

        tracing::info!(
            "Committed new realm block with checkpoint_id = {}.",
            self.db.state.processing_checkpoint_id
        );
        self.db.print_coordinator_processor_state();

        // Final sync
        self.db.sync_to_coordinator_set_checkpoint_id().await?;
        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block after
        // sync_to_coordinator_set_checkpoint_id").await?;

        timer.lap("sync_to_coordinator_set_checkpoint_id");
        self.db.run_sanity_check("after sync_to_coordinator_set_checkpoint_id").await?;
        if let Err(err) = self
            .db
            .proof_work_queue
            .delete_worker_queue_consumer(
                &worker_queue_key_for_cleanup,
                self.db.state.realm_id_u64,
                self.db.state.realm_sub_id_u64,
                worker_unique_id_for_cleanup,
                0,
            )
            .await
        {
            tracing::warn!(
                "Failed to delete realm worker queue consumer after checkpoint commit: {}",
                err
            );
        }

        Ok(())
    }

    /// Unique live-proof persistence route. Keeping the match inside the
    /// Processor prevents a future caller from selecting the legacy DB path
    /// after branch-exact startup has been authorized.
    async fn commit_live(
        &mut self,
        iteration: &mut RealmNormalCommitIteration<'_, N::QHash>,
        commit_input: RealmCommitInput<'_, N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        match iteration {
            RealmNormalCommitIteration::Legacy { .. } => {
                self.db.commit_state(commit_input).await
            }
            RealmNormalCommitIteration::BranchExact(_) => {
                anyhow::bail!(
                    "REALM_BRANCH_EXACT_FULL_COMMIT_COVERAGE_NOT_INTEGRATED"
                )
            }
        }
    }

    /// Execute one whole real loop iteration under exactly one normal-commit
    /// owner.  The owner is temporarily absent from `self`, so cancellation or
    /// re-entry fails closed instead of exposing a legacy fallback.
    pub(super) async fn run_owned_iteration(
        &mut self,
        permit: RealmProcessorIterationPermit,
        should_process: bool,
    ) -> Result<(), RealmOwnedIterationError> {
        let mut owner = self
            .normal_commit_owner
            .take()
            .ok_or(RealmOwnedIterationError::MissingCommitOwner)?;
        let result = async {
            let mut iteration = owner
                .begin_iteration(permit)
                .map_err(RealmOwnedIterationError::Begin)?;
            self.sync_and_verify()
                .await
                .map_err(RealmOwnedIterationError::Sync)?;
            if should_process {
                self.process_block(&mut iteration)
                    .await
                    .map_err(RealmOwnedIterationError::Process)?;
            }
            Ok(())
        }
        .await;
        self.normal_commit_owner = Some(owner);
        result
    }
}

#[cfg(test)]
mod h23c4b_tests {
    #[test]
    fn live_commit_has_one_owner_route_and_no_direct_db_bypass() {
        let source = include_str!("process_block.rs");
        let live = source
            .split("pub(super) async fn process_block")
            .nth(1)
            .unwrap()
            .split("#[cfg(test)]")
            .next()
            .unwrap();
        assert_eq!(
            live.matches("self.commit_live(iteration, commit_input).await?")
                .count(),
            1
        );
        assert_eq!(live.matches("self.db.commit_state(commit_input)").count(), 1);
        let call = live
            .find("self.commit_live(iteration, commit_input).await?")
            .unwrap();
        let router = live.find("async fn commit_live(").unwrap();
        assert!(call < router);

        let router = live.split("async fn commit_live(").nth(1).unwrap();
        assert!(router.contains("RealmNormalCommitIteration::Legacy"));
        assert!(router.contains("RealmNormalCommitIteration::BranchExact"));
        assert!(router.contains("REALM_BRANCH_EXACT_FULL_COMMIT_COVERAGE_NOT_INTEGRATED"));
        assert!(!router.contains("prepare_and_verify"));
        assert!(!router.contains("finish_published"));
    }

    #[test]
    fn genesis_and_recovery_remain_distinct_from_live_owner_route() {
        let input = include_str!("../commit_input.rs");
        assert!(input.contains("RealmCommitOrigin::Genesis"));
        assert!(input.contains("RealmCommitOrigin::StartupRecovery"));
        assert!(input.contains("RealmCommitOrigin::LiveProof"));
        assert!(input.contains("LiveEvidenceUnavailable"));
    }
}

#[cfg(test)]
mod h23c4c3b_tests {
    #[test]
    fn real_processor_routes_branch_exact_capture_without_legacy_drain() {
        let source = include_str!("process_block.rs");
        let function = source
            .split("async fn get_results_from_gatherers(")
            .nth(1)
            .unwrap()
            .split("// Sanity: outside of genesis")
            .next()
            .unwrap();
        assert!(function.contains("observe_generation_continuation().await?"));
        assert!(function.contains("prepare_deferred_actor_input().await?"));
        assert!(function.contains("open_durable_capture_for_deferred_input(deferred_input)"));
        assert!(function.contains("take_deferred_actor_input()"));
        assert!(function.contains("recover_application_handoff()"));
        assert!(function.contains("replay_complete_generation()"));
        assert!(function.contains("capture.capture_next()"));
        assert!(function.contains("apply_durable_generation(actor_input)"));
        assert!(function.contains("finalize_durable_generation(receipt)"));
        assert!(function.contains("build_branch_exact_semantic_output(processing, &finalized)"));
        assert!(function.contains("persist_application_and_handoff(semantic)"));
        assert!(!function.contains("set_new_unique_ids"));
        assert!(!function.contains("finalize_gathering_and_update_queue_key"));
        assert!(!function.contains("dump_entire_ephemeral_queue_bytes"));
        assert!(!function.contains("delete_ephemeral_queue_consumer"));
    }

    #[test]
    fn legacy_rotation_is_preserved_but_branch_exact_stops_after_first_handoff() {
        let source = include_str!("process_block.rs");
        let legacy = source
            .split("// Sanity: outside of genesis")
            .nth(1)
            .unwrap()
            .split("pub async fn sync_and_verify")
            .next()
            .unwrap();
        assert_eq!(legacy.matches("self.db.set_new_unique_ids(None).await?").count(), 1);
        assert_eq!(
            legacy
                .matches(".finalize_gathering_and_update_queue_key(")
                .count(),
            1
        );

        let process = source
            .split("pub(super) async fn process_block")
            .nth(1)
            .unwrap();
        let finalized = process
            .find("RealmGatheringOutcome::BranchExactApplicationHandoff")
            .unwrap();
        let semantic_stop = process[finalized..].find("return Ok(())").unwrap() + finalized;
        let proving = process.find("// 4. Proving Work").unwrap();
        assert!(semantic_stop < proving);
        assert!(process.contains("proof/writer/head remain blocked"));
    }

    #[test]
    fn semantic_candidate_uses_exact_pending_witnesses_and_affine_storage_authority() {
        let source = include_str!("process_block.rs");
        let builder = source
            .split("async fn project_branch_exact_semantic_output<")
            .nth(1)
            .unwrap()
            .split("/// RF=3 qualification")
            .next()
            .unwrap();
        assert!(builder.contains("require_pending_context_for_generation"));
        assert!(builder.contains("processing)"));
        assert!(!builder.contains("self.db.state.processing_unique_pending_id"));
        assert!(!builder.contains("self.db.state.processing_proc_checkpoint_unique_id"));
        assert!(builder.contains("get_tdb_proof_witness_bytes"));
        assert!(builder.contains("job.job_id"));
        assert!(builder.contains("RealmProcessorSemanticOutput::try_from_candidate_parts"));
        assert!(!builder.contains("handoff_to_pipeline"));
        assert!(!builder.contains("persist"));

        let gather = source
            .split("async fn get_results_from_gatherers(")
            .nth(1)
            .unwrap()
            .split("// Sanity: outside of genesis")
            .next()
            .unwrap();
        let build = gather
            .find("build_branch_exact_semantic_output(processing, &finalized)")
            .unwrap();
        let persist = gather
            .find("persist_application_and_handoff(semantic)")
            .unwrap();
        assert!(build < persist);
        assert!(!gather.contains("commit_state"));
        assert!(!gather.contains("publish_all_worker_jobs"));
    }

    #[test]
    fn startup_selects_command_only_actor_and_keeps_default_off_guard() {
        let startup = include_str!("startup.rs");
        let branch = startup
            .split("if branch_exact {")
            .nth(1)
            .unwrap()
            .split("} else {")
            .next()
            .unwrap();
        assert!(branch.contains("new_durable_with_status"));
        assert!(!branch.contains("guta_update_queue.clone()"));
        let legacy = startup
            .split("} else {")
            .nth(1)
            .unwrap()
            .split("};")
            .next()
            .unwrap();
        assert!(legacy.contains("new_with_status"));
        assert!(legacy.contains("db.guta_update_queue.clone()"));

        let create = include_str!("../create.rs");
        assert!(create.contains("ServingCompositionNotIntegrated"));
        assert!(create.contains("reject_unintegrated_branch_exact_serving"));
    }

    #[test]
    fn command_only_runner_has_no_queue_backend_or_terminal_authority() {
        let gatherer = include_str!("../../../queue/gatherer.rs");
        let durable = gatherer
            .split("async fn durable_gatherer_runner_for_tree")
            .nth(1)
            .unwrap()
            .split("async fn gatherer_runner_for_tree")
            .next()
            .unwrap();
        assert!(!durable.contains("QStandardEphemeralQueueSubscriber"));
        assert!(!durable.contains("dump_entire_ephemeral_queue_bytes"));
        assert!(!durable.contains("AckBatchLast"));
        assert!(!durable.contains("delete_ephemeral_queue_consumer"));
        assert!(durable.contains("finalize_with_tree"));
        assert!(durable.contains("SemanticHandoffNotIntegrated"));
    }
}

#[cfg(test)]
mod h23c4c4b1_tests {
    #[test]
    fn branch_exact_generation_identity_comes_from_durable_pipeline() {
        let source = include_str!("process_block.rs");
        let gather = source
            .split("async fn get_results_from_gatherers(")
            .nth(1)
            .unwrap()
            .split("// Sanity: outside of genesis")
            .next()
            .unwrap();
        assert!(gather.contains("observe_generation_continuation().await?"));
        assert!(gather.contains("prepare_deferred_actor_input().await?"));
        assert!(gather.contains("let processing = deferred_input.successor()"));
        assert!(gather.contains("open_durable_capture_for_deferred_input(deferred_input)"));
        assert!(!gather.contains("self.db.state.processing_unique_pending_id"));
        assert!(!gather.contains("self.db.state.processing_proc_checkpoint_unique_id"));
    }

    #[test]
    fn await_writer_has_one_narrow_route_and_other_continuations_stop() {
        let source = include_str!("process_block.rs");
        let process = source
            .split("pub(super) async fn process_block")
            .nth(1)
            .unwrap();
        let branch = process
            .find("RealmGatheringOutcome::BranchExactGenerationContinuation")
            .unwrap();
        let continuation_arm = process[branch..]
            .split("RealmGatheringOutcome::BranchExactAwaitingDeferredCarryover")
            .next()
            .unwrap();
        assert!(continuation_arm.contains(
            "RealmProcessorGenerationContinuationPhase::AwaitWriter"
        ));
        assert!(continuation_arm.contains("resume_branch_exact_await_writer(iteration)"));
        let stop = branch + continuation_arm.rfind("return Ok(())").unwrap();
        let proof = process.find("// 4. Proving Work").unwrap();
        assert!(stop < proof);
        for forbidden in [
            "seal_begin_processing",
            "seal_retire_no_work",
            "seal_publish",
            "seal_rotation",
            "commit_state",
        ] {
            assert!(!continuation_arm.contains(forbidden));
        }
    }
}

#[cfg(test)]
mod h23c4d2_tests {
    #[test]
    fn await_writer_reconstructs_exact_proof_and_stops_at_narrow_writer() {
        let source = include_str!("process_block.rs");
        let route = source
            .split("async fn execute_branch_exact_proof_and_narrow_write(")
            .nth(1)
            .unwrap()
            .split("pub fn get_root_job_id")
            .next()
            .unwrap();
        for required in [
            "require_pending_context_for_generation",
            "set_tdb_proof_witnesses_tuple_owned_raw",
            "get_tdb_proof_witness_bytes",
            "publish_branch_exact_worker_jobs",
            "get_proof_bytes_exact",
            "submit_or_recover_exact_coordinator_inclusion",
            "SealedRealmProofBinding::verify_and_seal",
            "RealmProcessorVerifiedNarrowWriterEvidence::try_from_verified",
            "prepare_mapping_and_reward_proof",
        ] {
            assert!(route.contains(required), "missing {required}");
        }
        for forbidden in [
            "wait_for_realm_update_sync_with_coordinator(",
            "self.db.commit_state",
            "seal_publish",
            "seal_rotation",
            "authority_head",
        ] {
            assert!(!route.contains(forbidden), "found {forbidden}");
        }
        let proof_read = route.find("let recovered_root_proof").unwrap();
        let proof_publish = route
            .find("self.publish_branch_exact_worker_jobs")
            .unwrap();
        assert!(proof_read < proof_publish);
    }

    #[test]
    fn live_and_rf3_routes_share_exact_coordinator_response_loss_policy() {
        let source = include_str!("process_block.rs");
        let helper = source
            .split("async fn submit_or_recover_exact_coordinator_inclusion")
            .nth(1)
            .unwrap()
            .split("#[cfg(feature = \"rf3-test-support\")]")
            .next()
            .unwrap();
        let pre_observe = helper
            .find("observe_exact_coordinator_inclusion(")
            .unwrap();
        let submit = helper.find(".rc_submit_guta_proof(").unwrap();
        let post_observe = helper.rfind("observe_exact_coordinator_inclusion(").unwrap();
        assert!(pre_observe < submit);
        assert!(submit < post_observe);
        assert!(helper.contains("wait_for_exact_coordinator_inclusion("));

        let live_route = source
            .split("async fn execute_branch_exact_proof_and_narrow_write(")
            .nth(1)
            .unwrap()
            .split("pub fn get_root_job_id")
            .next()
            .unwrap();
        assert!(live_route.contains("submit_or_recover_exact_coordinator_inclusion("));

        let qualification_route = source
            .split("pub async fn qualification_submit_or_recover_exact_coordinator_inclusion")
            .nth(1)
            .unwrap()
            .split("async fn project_branch_exact_semantic_output")
            .next()
            .unwrap();
        assert!(qualification_route
            .contains("submit_or_recover_exact_coordinator_inclusion("));
    }

    #[test]
    fn proofless_application_is_typed_await_and_not_fake_proof_work() {
        let source = include_str!("process_block.rs");
        let route = source
            .split("async fn resume_branch_exact_await_writer(")
            .nth(1)
            .unwrap()
            .split("async fn execute_branch_exact_proof_and_narrow_write(")
            .next()
            .unwrap();
        assert!(route.contains(
            "RealmProcessorApplicationProofWorkOutcome::AwaitProoflessApplication"
        ));
        assert!(route.contains("return Ok(())"));
        assert!(!route.contains("publish_branch_exact_worker_jobs"));
        assert!(!route.contains("prepare_mapping_and_reward_proof"));
    }
}
