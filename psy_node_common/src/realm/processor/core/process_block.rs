use cf_utils::timer::TraceTimer;
use parth_core::{
    data::queue::queue_key::{QPBaseQueueType, PCoreSubjectQueueBase},
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::realm::{
    processor::{core::PsyRealmProcessor, gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput},
    queue_key::{RealmProvingWorkQueueKey, RealmUserUpdateQueueKey},
};

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
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

    pub fn get_root_job_id(&self, guta_jobs: &[Vec<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>]) -> anyhow::Result<Option<N::JobId>> {
        let guta_root_job = guta_jobs.last().and_then(|jobs_at_level| jobs_at_level.first());
        if let Some(job) = guta_root_job {
            Ok(Some(job.job_id.clone()))
        } else {
            Ok(None)
        }
    }

    pub async fn get_results_from_gatherers(&mut self) -> anyhow::Result<RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>> {
        // Ensure unique IDs are rotated correctly before gathering to prevent
        // overwriting pending state
        if self.db.state.gathering_proc_checkpoint_unique_id == self.db.state.processing_proc_checkpoint_unique_id
            || self.db.state.gathering_unique_pending_id == self.db.state.processing_unique_pending_id
        {
            tracing::info!("Rotating unique IDs before gathering results.");
            if self.db.state.last_committed_checkpoint_id == 0 {
                // Ensure streams exist first
                self.db.guta_update_queue.ensure_stream().await?;
                self.db.proof_work_queue.ensure_stream().await?;

                // Create consumers for both processing and gathering proc_checkpoint_unique_id in genesis
                let realm_id = self.db.state.realm_id_u64;
                let realm_sub_id = self.db.state.realm_sub_id_u64;
                let unique_id = self.db.state.processing_proc_checkpoint_unique_id;

                // GUTA ephemeral queues
                let guta_processing_key = RealmUserUpdateQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyRealmUserUpdateQueueItem<N::F, N::QHash>>,
                };

                self.db.guta_update_queue.ensure_consumer(&guta_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;

                // Proof Worker queues
                let proof_processing_key = RealmProvingWorkQueueKey {
                    realm_id, realm_sub_id, unique_id, task_group: 0,
                    queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
                };

                self.db.proof_work_queue.ensure_consumer(&proof_processing_key, realm_id, realm_sub_id, unique_id, 0).await?;

                // Special handling for genesis rotation
                self.db.set_new_unique_ids(None).await?;
                
                // Flush the gatherer to ensure it picks up the new IDs
                let _ = self
                    .guta_queue_gatherer
                    .finalize_gathering_and_update_queue_key(self.db.state.gathering_proc_checkpoint_unique_id)
                    .await?;
            } else {
                anyhow::bail!("Cannot gather results: unique IDs match processing IDs, but we are not at genesis.");
            }
        }

        // Standard rotation for a new block
        self.db.set_new_unique_ids(None).await?;

        // Reset revert flag if it was set, as we are starting a fresh attempt
        if self.db.needs_revert {
            self.db.needs_revert = false;
        }

        let guta_result = self
            .guta_queue_gatherer
            .finalize_gathering_and_update_queue_key(self.db.state.gathering_proc_checkpoint_unique_id)
            .await?;

        Ok(guta_result)
    }

    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        self.db.run_sanity_check("process_block start").await?;
        let mut timer = TraceTimer::new("process_block");
        tracing::info!(
            "Starting to process new realm block. Last Committed Checkpoint: {}",
            self.db.state.last_committed_checkpoint_id
        );

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
                    timer.lap("recovery_sync");
                    tracing::info!("Fast-forward sync complete. Resuming block processing.");
                } else {
                    return Err(e);
                }
            }
        }
        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block after
        // ensure_db_matches_coordinator_head").await?;

        timer.lap("sync_and_verify_coordinator");

        // 2. Gather Updates
        let guta_output = self.get_results_from_gatherers().await?;
        let guta_jobs = guta_output.job_ids;
        let guta_update = guta_output.db_output;


        timer.lap("get_results_from_gatherers");

        // CRITICAL FIX: Update the processing end root state with the new root from the
        // gatherer. This ensures that when `commit_state` calls
        // `state.commit_processing()`, it propagates the correct new realm root
        // to `last_committed`, rather than carrying over the old root.
        self.db.state.processing_realm_end_root = guta_update.new_realm_root;

        // 3. Check for work
        let root_job_id = self.get_root_job_id(&guta_jobs)?;
        if root_job_id.is_none() {
            tracing::info!("No GUTA jobs to process in this block, skipping.");
            self.db.sync_to_coordinator_set_checkpoint_id().await?;
            return Ok(());
        }
        let root_job_id = root_job_id.unwrap();
        timer.lap("get_root_job_ids");

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
        self.publish_all_worker_jobs(proving_state, &self.db.get_proof_worker_queue_key(), &guta_jobs).await?;
        timer.lap("publish_all_worker_jobs");
        tracing::info!("GUTA jobs completed!");

        // 5. Retrieve Proof
        let root_job_proof = self.db.proof_store.get_proof_bytes_by_job_id(root_job_id).await?;
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
        };

        self.db.run_sanity_check("before commit").await?;

        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block before
        // commit_state").await?;

        self.db
            .commit_state(&sync_info, &db_output, root_job_id.circuit_type, root_job_proof)
            .await?;
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

        Ok(())
    }
}
