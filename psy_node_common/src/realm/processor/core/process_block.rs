use cf_utils::timer::TraceTimer;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
    node::node_proving_state::PsyNodeProvingState,
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use std::time::Duration;
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
    queue_key::RealmProvingWorkQueueKey,
};
use crate::utils::persisted_artifact::wait_for_persisted_artifact;

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
        let root_job_id = self.get_root_job_id(jobs)?;

        let mut non_empty_levels = 0usize;
        for level in 0..jobs.len() {
            if jobs[level].is_empty() {
                continue;
            }

            proving_state.set_current_proving_level(non_empty_levels as u8);
            self.db.temp_db.set_psy_node_proving_state(&self.db.state.realm_identifier, &proving_state).await?;
            non_empty_levels+=1;

            tracing::info!(
                realm_id = self.db.state.realm_id_u64,
                realm_sub_id = self.db.state.realm_sub_id_u64,
                checkpoint_id = self.db.state.processing_checkpoint_id,
                unique_pending_id = self.db.state.processing_unique_pending_id,
                proc_checkpoint_unique_id = self.db.state.processing_proc_checkpoint_unique_id,
                task_group = 0,
                level,
                job_count = jobs[level].len(),
                root_job_id = ?root_job_id,
                "Publishing Realm worker jobs"
            );
            let barrier = self.db
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
            tracing::info!(
                realm_id = self.db.state.realm_id_u64,
                realm_sub_id = self.db.state.realm_sub_id_u64,
                checkpoint_id = self.db.state.processing_checkpoint_id,
                unique_pending_id = self.db.state.processing_unique_pending_id,
                proc_checkpoint_unique_id = self.db.state.processing_proc_checkpoint_unique_id,
                task_group = 0,
                level,
                job_count = jobs[level].len(),
                root_job_id = ?root_job_id,
                publish_barrier = ?barrier,
                "Realm worker publication acknowledged"
            );

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
                    &barrier,
                    self.proof_worker_queue_max_time_ms,
                )
                .await?;
            timer.lap("waited for jobs to complete");
            tracing::info!(
                realm_id = self.db.state.realm_id_u64,
                realm_sub_id = self.db.state.realm_sub_id_u64,
                checkpoint_id = self.db.state.processing_checkpoint_id,
                unique_pending_id = self.db.state.processing_unique_pending_id,
                proc_checkpoint_unique_id = self.db.state.processing_proc_checkpoint_unique_id,
                task_group = 0,
                level,
                job_count = jobs[level].len(),
                root_job_id = ?root_job_id,
                publish_barrier = ?barrier,
                "Realm worker transport barrier completed"
            );
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

        // Sync the gatherer's queue key to the new gathering proc ID so the
        // gatherer polls the same queue that end-cap submissions write to.
        // set_new_unique_ids above advances gathering_proc_checkpoint_unique_id,
        // but guta_queue_key_status_manager was initialized with the old ID
        // and must be updated to match.
        self.db
            .guta_queue_key_status_manager
            .set_unique_id(self.db.state.gathering_proc_checkpoint_unique_id)?;

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

    pub async fn process_block(&mut self) -> anyhow::Result<()> {
        self.db.run_sanity_check("process_block start").await?;
        let mut timer = TraceTimer::new("process_block");
        tracing::info!(
            "Starting to process new realm block. Last Committed Checkpoint: {}",
            self.db.state.last_committed_checkpoint_id
        );

        // 2. Gather Updates
        let guta_output = self.get_results_from_gatherers().await?;
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
        let unique_pending_id = self.db.state.processing_unique_pending_id;
        let proof_artifact_name = format!(
            "Realm root proof realm={:?} checkpoint={} proc_checkpoint_unique_id={} job_id={root_job_id:?} unique_pending_id={unique_pending_id}",
            self.db.state.realm_identifier,
            self.db.state.processing_checkpoint_id,
            self.db.state.processing_proc_checkpoint_unique_id,
        );
        let root_job_proof = wait_for_persisted_artifact(
            &proof_artifact_name,
            self.proof_worker_queue_max_time_ms,
            Duration::from_millis(50),
            || {
                self.db
                    .proof_store
                    .get_proof_bytes_by_job_id(root_job_id, unique_pending_id)
            },
        )
        .await?;
        timer.lap("get_root_job_proof");

        // 6. Get Rewards Root
        let reward_artifact_name = format!(
            "Realm root reward realm={:?} checkpoint={} proc_checkpoint_unique_id={} job_id={root_job_id:?} unique_pending_id={unique_pending_id}",
            self.db.state.realm_identifier,
            self.db.state.processing_checkpoint_id,
            self.db.state.processing_proc_checkpoint_unique_id,
        );
        let rewards_root = wait_for_persisted_artifact(
            &reward_artifact_name,
            self.proof_worker_queue_max_time_ms,
            Duration::from_millis(50),
            || {
                self.db.get_reward_tree_root_or_none(
                    self.db.state.processing_checkpoint_id,
                    unique_pending_id,
                    root_job_id,
                )
            },
        )
        .await?;
        tracing::info!(
            realm_id = self.db.state.realm_id_u64,
            realm_sub_id = self.db.state.realm_sub_id_u64,
            checkpoint_id = self.db.state.processing_checkpoint_id,
            unique_pending_id,
            proc_checkpoint_unique_id = self.db.state.processing_proc_checkpoint_unique_id,
            root_job_id = ?root_job_id,
            proof_store_ready = true,
            "Realm root proof and reward artifacts are ready"
        );

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

        self.db
            .commit_state(&sync_info, &db_output, root_job_id.circuit_type, root_job_proof, false)
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
}

#[cfg(test)]
mod process_block_tests {
    use parth_core::{
        crypto::hash::{merkle_proof::compute_root_merkle_proof_generic, traits::QFieldHashable},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QNetworkTreeConstants,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::worker::{
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    };
    use psy_node_core::psy_temp_db::QTempDBNodeProvingStateReader;

    use crate::realm::processor::{
        core::startup::startup_tests::RealmProcessorTestEnv,
        db::realm_db_test_env::{zh, N},
    };

    type TestJobs = Vec<Vec<PsyProvingJobMetadataWithJobId<parth_core::PHash, QProvingJobDataID>>>;

    fn job(
        circuit: ProvingJobCircuitType,
        salt: u64,
    ) -> PsyProvingJobMetadataWithJobId<parth_core::PHash, QProvingJobDataID> {
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

    #[tokio::test]
    async fn get_root_job_id_returns_last_level_first_job_or_none() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;

        // no levels at all, or only empty levels: no root job
        assert!(env.processor.get_root_job_id(&vec![])?.is_none());
        assert!(env.processor.get_root_job_id(&vec![vec![]])?.is_none());

        // a single level reports its first job
        let only = job(ProvingJobCircuitType::GUTATwoEndCap, 1);
        let root = env
            .processor
            .get_root_job_id(&vec![vec![only.clone()]])?
            .expect("a single job must be the root");
        assert_eq!(root, only.job_id);

        // multi-level job lists report the first job of the LAST level
        let lower = job(ProvingJobCircuitType::UserEndCap, 2);
        let upper_a = job(ProvingJobCircuitType::GUTATwoEndCap, 3);
        let upper_b = job(ProvingJobCircuitType::GUTATwoEndCap, 4);
        let root = env
            .processor
            .get_root_job_id(&vec![vec![lower], vec![upper_a.clone(), upper_b]])?
            .expect("the last level must provide the root");
        assert_eq!(root, upper_a.job_id);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_all_worker_jobs_persists_proving_state_per_level() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;
        let queue_key = env.processor.db.get_proof_worker_queue_key();

        let level_zero = job(ProvingJobCircuitType::UserEndCap, 11);
        let level_one = job(ProvingJobCircuitType::GUTATwoEndCap, 12);
        let jobs: TestJobs = vec![vec![level_zero], vec![level_one]];
        let proving_state = psy_data::node::node_proving_state::PsyNodeProvingState::new_standard_realm(
            1,
            2,
            0,
            0,
            0,
            2,
        );

        env.processor.publish_all_worker_jobs(proving_state, &queue_key, &jobs).await?;

        // both non-empty levels were published to the worker queue
        assert_eq!(*env.db_env.proof_queue.published_count.lock().unwrap(), 2);

        // the persisted proving state names the last published level and is
        // marked finished
        let persisted = env
            .db_env
            .temp_db
            .get_psy_node_proving_state(&env.processor.db.state.realm_identifier)
            .await?;
        assert_eq!(persisted.current_proving_level, 1);
        assert_eq!(persisted.has_remaining_proving_jobs, 0);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn publish_all_worker_jobs_counts_only_non_empty_levels() -> anyhow::Result<()> {
        let env = RealmProcessorTestEnv::create().await?;
        let queue_key = env.processor.db.get_proof_worker_queue_key();

        // an empty level does not advance the compacted level numbering: the
        // single job at raw level 1 becomes compacted level 0
        let only = job(ProvingJobCircuitType::GUTATwoEndCap, 21);
        let jobs: TestJobs = vec![vec![], vec![only]];
        let proving_state = psy_data::node::node_proving_state::PsyNodeProvingState::new_standard_realm(
            1,
            2,
            0,
            0,
            0,
            1,
        );

        env.processor.publish_all_worker_jobs(proving_state, &queue_key, &jobs).await?;

        assert_eq!(*env.db_env.proof_queue.published_count.lock().unwrap(), 1);
        let persisted = env
            .db_env
            .temp_db
            .get_psy_node_proving_state(&env.processor.db.state.realm_identifier)
            .await?;
        assert_eq!(persisted.current_proving_level, 0);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn get_results_from_gatherers_bails_when_ids_undifferentiated() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;
        // model a processor past genesis whose ids were never rotated
        env.processor.db.state.last_committed_checkpoint_id = 1;
        env.processor.db.state.processing_proc_checkpoint_unique_id =
            env.processor.db.state.gathering_proc_checkpoint_unique_id;
        env.processor.db.state.processing_unique_pending_id = env.processor.db.state.gathering_unique_pending_id;

        let error = match env.processor.get_results_from_gatherers().await {
            Err(e) => e.to_string(),
            Ok(_) => anyhow::bail!("undifferentiated ids past genesis must bail"),
        };
        assert!(
            error.contains("Unique IDs not differentiated outside of genesis"),
            "unexpected error: {error}"
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn get_results_from_gatherers_rotates_ids_once_and_returns_empty_output() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;
        let gathering_before = env.processor.db.state.gathering_unique_pending_id;
        let processing_before = env.processor.db.state.processing_unique_pending_id;

        let output = env.processor.get_results_from_gatherers().await?;

        // one rotation: the old gathering pair graduated to processing and
        // gathering advanced to the next pending id
        let state = &env.processor.db.state;
        assert_eq!(state.processing_unique_pending_id, gathering_before);
        assert_eq!(state.gathering_unique_pending_id, gathering_before + 1);
        assert_ne!(state.processing_unique_pending_id, processing_before);

        // with no queue items the gatherer finalizes to an empty no-op output
        assert!(output.job_ids.is_empty());
        assert!(output.db_output.is_noop());
        assert_eq!(output.db_output.total_users_updated, 0);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn sync_and_verify_fast_forwards_when_coordinator_is_ahead() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;
        assert_eq!(env.db_env.db.get_latest_checkpoint_id().await?, 0);

        // the coordinator advances one checkpoint past the local head; the
        // realm itself was not modified in that checkpoint, so the coordinator
        // still reports the exact realm-root node value the store holds
        let mut update = env.db_env.make_checkpoint_one_update();
        let realm_root_unchanged = env.db_env.local_realm_root().await?;
        update.merkle_proof_to_realm_root.value = realm_root_unchanged;
        update.merkle_proof_to_realm_root.root =
            update.merkle_proof_to_realm_root.compute_root_with_value::<PoseidonHasher>(realm_root_unchanged);
        update.checkpoint_sync_info.state_roots.user_tree_root = update.merkle_proof_to_realm_root.root;
        update.checkpoint_sync_info.checkpoint_leaf.global_chain_root =
            update.checkpoint_sync_info.state_roots.qfhash::<PoseidonHasher>();
        update.checkpoint_sync_info.checkpoint_leaf_hash =
            update.checkpoint_sync_info.checkpoint_leaf.qfhash::<PoseidonHasher>();
        let mut checkpoint_siblings = Vec::with_capacity(N::CHECKPOINT_TREE_HEIGHT_USIZE);
        checkpoint_siblings.push(env.db_env.genesis_leaf_hash());
        for level in 1..N::CHECKPOINT_TREE_HEIGHT_USIZE {
            checkpoint_siblings.push(zh(level));
        }
        update.checkpoint_sync_info.checkpoint_tree_root = compute_root_merkle_proof_generic::<_, PoseidonHasher>(
            update.checkpoint_sync_info.checkpoint_leaf_hash,
            1,
            &checkpoint_siblings,
        );
        env.db_env.seed_checkpoint_one(update, realm_root_unchanged);

        // the stale check must be recognized, fast-forwarded and re-verified
        env.processor.sync_and_verify().await?;

        assert_eq!(env.db_env.db.get_latest_checkpoint_id().await?, 1);
        assert_eq!(env.processor.db.state.last_committed_checkpoint_id, 1);
        assert_eq!(env.processor.db.state.processing_checkpoint_id, 1);
        assert_eq!(env.processor.db.state.last_committed_realm_end_root, realm_root_unchanged);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn sync_and_verify_fast_forwards_changed_realm_root() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;
        let old_realm_root = env.db_env.local_realm_root().await?;

        // This checkpoint comes from a separately built, internally consistent
        // genesis state, so its realm root and top-tree proof belong together.
        let update = env.db_env.make_checkpoint_one_update();
        let new_realm_root = update.merkle_proof_to_realm_root.value;
        assert_ne!(new_realm_root, old_realm_root);
        assert_eq!(
            update.merkle_proof_to_realm_root.root,
            update.checkpoint_sync_info.state_roots.user_tree_root
        );
        env.db_env.seed_checkpoint_one(update, new_realm_root);

        // Fast-forward must persist the changed realm node before the second
        // consistency check reads it back from the global-user-tree store.
        env.processor.sync_and_verify().await?;

        assert_eq!(env.db_env.db.get_latest_checkpoint_id().await?, 1);
        assert_eq!(env.processor.db.state.last_committed_realm_end_root, new_realm_root);
        assert_eq!(env.processor.db.get_realm_root_from_db().await?, new_realm_root);
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn sync_and_verify_propagates_unrecoverable_realm_root_mismatch() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;

        // the coordinator reports a realm root at the same checkpoint that
        // disagrees with the committed local root: the fast-forward path
        // cannot fix this, so the error must propagate
        env.db_env.coordinator.clear_realm_roots();
        env.db_env.coordinator.seed_realm_root(0, zh(99));

        let error = match env.processor.sync_and_verify().await {
            Err(e) => e.to_string(),
            Ok(_) => anyhow::bail!("a realm root mismatch at the same checkpoint must fail"),
        };
        assert!(
            error.contains("Realm Root mismatch"),
            "unexpected error: {error}"
        );
        env.abort_gatherers();
        Ok(())
    }

    #[tokio::test]
    async fn process_block_without_jobs_syncs_and_cleans_up_consumer() -> anyhow::Result<()> {
        let mut env = RealmProcessorTestEnv::create().await?;

        // an empty gatherer result takes the no-jobs early return
        env.processor.process_block().await?;

        // the ids still rotated once for the attempt, but no checkpoint was
        // committed
        assert_eq!(env.processor.db.state.processing_unique_pending_id, 1);
        assert_eq!(env.processor.db.state.last_committed_checkpoint_id, 0);
        assert_eq!(env.db_env.db.get_latest_checkpoint_id().await?, 0);

        // the worker-queue consumer for the finished attempt was cleaned up
        assert!(!env.db_env.proof_queue.deleted_consumers.lock().unwrap().is_empty());
        env.abort_gatherers();
        Ok(())
    }
}
