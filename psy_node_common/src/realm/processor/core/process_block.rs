use std::time::Duration;

use parth_core::{
    crypto::hash::traits::{HashTo4Felts, MerkleZeroHasher},
    felt::ToU64Value,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};



use psy_config::CHECKPOINTS_PER_EPOCH;
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::{
        header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
        realm_finalize::{
            finalize_output_from_witness, finalize_reward_root63, realm_finalize_guta_chain_domain,
            protocol_encode_finalize_output, RealmFinalizeBinding, RealmFinalizeGUTAInput,
        },
    },
    node::node_proving_state::PsyNodeProvingState,
    p2p::{
        encode_proposal_body, proposal_from_parts, replication_threshold, sha256, vote_message,
        Certificate, Proposal, ProtocolEncode,
    },
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use cf_utils::timer::TraceTimer;
use psy_node_core::{
    p2p::{traits::realm_coordinantor::RealmCoordinatorClient, validator_lookup::load_realm_validators_from_tree},
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    realm::{
        processor::{
            consensus::{form_certificate, require_nonzero_validator_tree_root, sign_vote, validate_certificate, votes_meet_wait},
            core::PsyRealmProcessor,
            gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput,
        },
        queue_key::RealmProvingWorkQueueKey,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
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
        self.db
            .set_new_unique_ids(Some(self.db.state.processing_realm_end_root))
            .await?;

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
        self.db.sync_with_coordinator().await?;
        if let Err(error) = self.db.ensure_db_matches_coordinator_head().await {
            let message = error.to_string();
            if !message.contains("Local database is stale") && !message.contains("Realm Root mismatch") {
                return Err(error);
            }
            tracing::warn!("Coordinator is ahead of local DB ({}), attempting recovery sync...", message);
            self.commit_included_proposal_ffs().await?;

            self.db.ensure_db_matches_coordinator_head().await?;
            tracing::info!("Coordinator recovery sync complete. Resuming block processing.");
        }
        Ok(())
    }
    async fn ensure_uncommitted_processing_ids(&mut self) -> anyhow::Result<()> {
        let pending_id = self.db.state.processing_unique_pending_id;
        if pending_id != 0 && self.db.db.get_checkpoint_id_for_unique_pending_id(pending_id).await?.is_none() {
            return Ok(());
        }
        let (pending_id, proc_checkpoint_unique_id) = self.db.db.inc_unique_pending_id(1).await?;
        self.db.state.processing_unique_pending_id = pending_id;
        self.db.state.processing_proc_checkpoint_unique_id = proc_checkpoint_unique_id;
        self.db
            .temp_db
            .set_unique_pending_ids(&self.db.state.realm_identifier, pending_id, proc_checkpoint_unique_id)
            .await?;
        Ok(())
    }


    async fn commit_included_proposal_ffs(&mut self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id = self.db.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let coordinator_realm_state = self
            .db
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.db.state.realm_id_u64)
            .await?;
        let included_checkpoint_id = coordinator_realm_state.checkpoint_id;
        let db_matches = coordinator_realm_state.value == self.db.state.last_committed_realm_end_root;

        if let Some(rx) = self.verified_state_updates.as_mut() {
            while let Ok(updates_bytes) = rx.try_recv() {
                self.held_state_updates = Some(updates_bytes);
            }
        }
        let Some(updates_bytes) = self.held_state_updates.clone() else {
            return self.db.sync_to_coordinator_set_checkpoint_id().await;
        };
        let updates = PsyPreparedRealmBlockStateUpdates::<N::QHash>::psy_ser_from_slice(&updates_bytes)?;
        if updates.new_realm_root != coordinator_realm_state.value {
            anyhow::ensure!(
                db_matches,
                "Checkpoint {}: in-band new_realm_root {:?} does not match included root {:?}",
                included_checkpoint_id,
                updates.new_realm_root,
                coordinator_realm_state.value
            );
            return self.db.sync_to_coordinator_set_checkpoint_id().await;
        }

        self.db.state.processing_realm_end_root = coordinator_realm_state.value;
        self.db
            .shared_state
            .update_from_core_state(&self.db.state)
            .await?;

        if !db_matches {
            anyhow::ensure!(
                updates.old_realm_root == self.db.state.last_committed_realm_end_root,
                "Checkpoint {}: in-band old_realm_root {:?} does not match last committed {:?}",
                included_checkpoint_id,
                updates.old_realm_root,
                self.db.state.last_committed_realm_end_root
            );
            self.ensure_uncommitted_processing_ids().await?;
            let coordinator_update = self
                .db
                .coordinator_client
                .rc_get_realm_sync_info(included_checkpoint_id, self.db.state.realm_id_u64)
                .await?;
            self.db.state.processing_checkpoint_id = included_checkpoint_id;
            self.db.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
            self.db.state.processing_realm_start_root = self.db.state.last_committed_realm_end_root;
            self.db
                .commit_state(
                    &coordinator_update,
                    &updates,
                    ProvingJobCircuitType::GUTANoChange,
                    vec![],
                    true,
                )
                .await?;
            tracing::info!(
                "Committed Realm proposal FFS end_root={:?} checkpoint_id={}",
                updates.new_realm_root,
                included_checkpoint_id
            );
        }

        self.db.state.gathering_realm_start_root = coordinator_realm_state.value;
        self.db
            .shared_state
            .update_from_core_state(&self.db.state)
            .await?;

        if updates.realm_sub_id != self.db.state.realm_sub_id_u64 {
            self.guta_queue_gatherer.fast_forward(updates_bytes).await?;
            tracing::info!(
                "Applied Realm proposal FFS end_root={:?} checkpoint_id={}",
                updates.new_realm_root,
                included_checkpoint_id
            );
        }
        self.held_state_updates = None;

        self.db.sync_to_coordinator_set_checkpoint_id().await
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

        if self.rotation.as_ref().is_some_and(|rotation| rotation.is_enabled()) {
            let base_checkpoint_id = self
                .db
                .db
                .get_checkpoint_id_for_checkpoint_root_hash(guta_update.guta_header.header.checkpoint_tree_root)
                .await?
                .ok_or_else(|| anyhow::anyhow!("GUTA checkpoint tree root has no canonical checkpoint ID"))?;
            if !self.is_scheduled_proposer_for_base(base_checkpoint_id).await? {
                tracing::warn!(
                    "realm P2P nonempty gather is not scheduled at T=base+1 realm={} sub={} base={} end_caps={}; skipping prove/submit/commit so the next gatherer cycle rebases",
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    base_checkpoint_id,
                    guta_update.total_users_updated
                );
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
                        "Failed to delete realm worker queue consumer after unscheduled nonempty gather: {}",
                        err
                    );
                }
                return Ok(());
            }
        }

        // Record the new realm root the upcoming commit will promote to last_committed
        // via commit_processing(). Must happen after the no-jobs early return so that
        // path leaves processing_realm_end_root untouched.
        self.db.state.processing_realm_end_root = guta_update.new_realm_root;
        self.db
            .shared_state
            .update_from_core_state(&self.db.state)
            .await?;
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
        let mut p2p_submission = None;
        if self.p2p.is_some() && self.rotation.as_ref().is_some_and(|rotation| rotation.is_enabled()) {
            p2p_submission = self
                .publish_realm_p2p_proposal(&root_job_id, &root_job_proof, rewards_root, &db_output)
                .await?;
        }

        if let Some((proposal, certificate, output_bytes, worker_tag)) = p2p_submission.as_ref() {
            let finalize_binding = RealmFinalizeBinding {
                output: *output_bytes,
                finalizer_worker_reward_tag: *worker_tag,
            };
            tracing::info!(
                "Submitting GUTA proof to Coordinator proposal={} realm={} sub_id={}",
                hex::encode(proposal.proposal_id),
                self.db.state.realm_id_u64,
                self.db.state.realm_sub_id_u64
            );
            self.db
                .coordinator_client
                .rc_submit_guta_proof(
                    submission_header,
                    root_job_proof.clone(),
                    self.db.state.realm_id_u64,
                    Some(proposal.protocol_encode_to_vec()),
                    Some(certificate.protocol_encode_to_vec()),
                    finalize_binding.protocol_encode_to_vec(),
                )
                .await?;
        } else {
            tracing::info!("Submitting GUTA proof to Coordinator...");
            self.db
                .coordinator_client
                .rc_submit_guta_proof(
                    submission_header,
                    root_job_proof.clone(),
                    self.db.state.realm_id_u64,
                    None,
                    None,
                    Vec::new(),
                )
                .await?;
        }

        timer.lap("submit_guta_proof");

        // 8. Wait for Coordinator Commit
        tracing::info!("Waiting for Coordinator to include Realm Root: {:?}", guta_update.new_realm_root);
        let sync_info = self.db.wait_for_realm_update_sync_with_coordinator(guta_update.new_realm_root).await?;
        timer.lap("wait_for_realm_update_sync");

        // 9. Commit Local State


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

    /// Publish the Realm P2P Proposal + own Vote, block on votes, and form a
    /// Certificate (without submitting it to the coordinator).
    ///
    /// This runs the full P2P proposer sequence: epoch-of-target
    /// scheduled-proposer check, in-band FFS encode, 410-byte actual
    /// finalizer-output encode, proposal publish, own-vote sign + publish,
    /// blocking `wait_votes` until `ceil(n/2)` replication, and
    /// `form_certificate`.
    async fn publish_realm_p2p_proposal(
        &mut self,
        root_job_id: &QProvingJobDataID,
        root_job_proof: &[u8],
        rewards_root: N::QHash,
        state_updates: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<Option<(Proposal, Certificate, [u8; 410], [u8; 32])>> {
        let cmds = self.p2p.as_ref().expect("p2p handle checked by caller");
        let bls_secret = self.bls_secret.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "realm P2P enabled for realm {} but no BLS secret key was wired via set_realm_p2p",
                self.db.state.realm_id_u64
            )
        })?;
        let (output_bytes, base_checkpoint_id, validator_tree_root, worker_tag, output_validator_user_id) = self
            .build_p2p_finalize_output(root_job_id, rewards_root)
            .await?;
        let target = base_checkpoint_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("GUTA Proposal proof-base checkpoint overflow"))?;

        let local_sub_id = self.db.state.realm_sub_id_u64 as u16;
        let (validator_sub_ids, leaf_bls_keys, validator_user_ids) =
            self.load_base_checkpoint_validators(base_checkpoint_id).await?;
        let proposer_user_id = validator_user_ids
            .iter()
            .find(|(sub_id, _)| *sub_id == local_sub_id)
            .map(|(_, user_id)| *user_id)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "missing tree-authenticated validator user id for scheduled proposer sub_id {local_sub_id}"
                )
            })?;
        anyhow::ensure!(
            output_validator_user_id == proposer_user_id,
            "finalize output validator_user_id {output_validator_user_id} does not match tree-authenticated proposer user {proposer_user_id} at base checkpoint {base_checkpoint_id}"
        );
        let epoch = parth_common::realm_rotation::epoch(target, CHECKPOINTS_PER_EPOCH);
        tracing::info!(
            "realm P2P scheduled proposer realm={} sub_id={} epoch={} target={} base={}",
            self.db.state.realm_id_u64,
            local_sub_id,
            epoch,
            target,
            base_checkpoint_id
        );

        let state_updates_bytes = state_updates.psy_ser_to_bytes_vec()?;
        let body = encode_proposal_body(&output_bytes, root_job_proof, &state_updates_bytes, &worker_tag)?;
        let body_hash = sha256(&body);
        let public_output_hash = sha256(&output_bytes);
        let finalizer_proof_hash = sha256(root_job_proof);
        let backup_hash = sha256(&state_updates_bytes);

        let proposal = proposal_from_parts(
            self.db.state.chain_id,
            self.db.state.realm_id_u64 as u32,
            base_checkpoint_id,
            local_sub_id,
            validator_tree_root,
            public_output_hash,
            finalizer_proof_hash,
            backup_hash,
            body_hash,
        );
        let message = vote_message(
            proposal.chain_id,
            proposal.realm_id,
            &proposal.validator_tree_root,
            &proposal.proposal_id,
        );
        let own_vote = sign_vote(bls_secret, local_sub_id, &proposal);
        let remote_bls_keys = leaf_bls_keys
            .iter()
            .copied()
            .filter(|(sub_id, _)| *sub_id != local_sub_id)
            .collect();
        cmds.publish_proposal(proposal.clone(), body, remote_bls_keys).await?;
        cmds.publish_vote(own_vote.clone()).await?;
        tracing::info!(
            "realm P2P proposal published proposal={} realm={} sub_id={} epoch={} target={} base={} validator_tree_root={}",
            hex::encode(proposal.proposal_id),
            self.db.state.realm_id_u64,
            local_sub_id,
            epoch,
            target,
            base_checkpoint_id,
            hex::encode(proposal.validator_tree_root)
        );
        let n = validator_sub_ids.len();
        let mut all_votes = vec![(own_vote.signer_sub_id, own_vote.signature)];
        let mut seen = std::collections::HashSet::from([local_sub_id]);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
        while !votes_meet_wait(
            n,
            local_sub_id,
            &all_votes.iter().map(|(sub_id, _)| *sub_id).collect::<Vec<_>>(),
        ) {
            let remaining_time = deadline.saturating_duration_since(tokio::time::Instant::now());
            anyhow::ensure!(!remaining_time.is_zero(), "timed out waiting for valid Realm votes");
            let remaining = replication_threshold(n).saturating_sub(seen.len()).max(1);
            let received = cmds
                .wait_votes(proposal.proposal_id, remaining, remaining_time)
                .await?;
            for vote in received {
                if seen.contains(&vote.signer_sub_id) {
                    continue;
                }
                let Some(public_key) = leaf_bls_keys
                    .iter()
                    .find(|(sub_id, _)| *sub_id == vote.signer_sub_id)
                    .map(|(_, key)| key)
                else {
                    tracing::warn!(
                        "dropped Realm vote from non-validator proposal={} signer_sub_id={}",
                        hex::encode(proposal.proposal_id),
                        vote.signer_sub_id
                    );
                    continue;
                };
                if let Err(error) = vote.signature.verify_vote(&message, public_key) {
                    tracing::warn!(
                        "dropped invalid Realm vote proposal={} signer_sub_id={} error={}",
                        hex::encode(proposal.proposal_id),
                        vote.signer_sub_id,
                        error
                    );
                    continue;
                }
                seen.insert(vote.signer_sub_id);
                all_votes.push((vote.signer_sub_id, vote.signature));
                tracing::info!(
                    "realm P2P vote accepted proposal={} signer_sub_id={} realm={} epoch={} target={}",
                    hex::encode(proposal.proposal_id),
                    vote.signer_sub_id,
                    self.db.state.realm_id_u64,
                    epoch,
                    target
                );
            }
        }
        let certificate = form_certificate(&proposal, &all_votes)?;
        validate_certificate(&proposal, &certificate, &validator_sub_ids, &leaf_bls_keys)?;
        let signer_ids = all_votes.iter().map(|(sub_id, _)| *sub_id).collect::<Vec<_>>();
        tracing::info!(
            "realm P2P certificate formed proposal={} realm={} target={} epoch={} signers={:?} verified_votes={}",
            hex::encode(proposal.proposal_id),
            self.db.state.realm_id_u64,
            target,
            epoch,
            signer_ids,
            all_votes.len()
        );
        Ok(Some((proposal, certificate, output_bytes, worker_tag)))
    }

    async fn load_base_checkpoint_validators(
        &self,
        checkpoint_id: u64,
    ) -> anyhow::Result<(
        Vec<u16>,
        Vec<(u16, psy_data::p2p::BlsPublicKey)>,
        Vec<(u16, u64)>,
    )>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
        let roots = self.db.db.get_checkpoint_global_state_roots(checkpoint_id).await?;
        load_realm_validators_from_tree::<N::HasherBase, N::QHash, _>(
            &*self.db.db,
            self.db.state.chain_id,
            checkpoint_id,
            self.db.state.realm_id_u64 as u32,
            &roots.validator_tree_root,
        )
        .await
    }

    async fn is_scheduled_proposer_for_base(&self, base_checkpoint_id: u64) -> anyhow::Result<bool> {
        let Some(rotation) = self.rotation.as_ref() else {
            return Ok(true);
        };
        if self.p2p.is_none() || !rotation.is_enabled() {
            return Ok(true);
        }
        let target = base_checkpoint_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("GUTA Proposal proof-base checkpoint overflow"))?;
        let (validator_sub_ids, _, _) = self.load_base_checkpoint_validators(base_checkpoint_id).await?;
        let tree_rotation = parth_common::realm_rotation::RealmRotationConfig {
            checkpoints_per_epoch: CHECKPOINTS_PER_EPOCH,
            validator_sub_ids,
        };
        let epoch = parth_common::realm_rotation::epoch(target, CHECKPOINTS_PER_EPOCH);
        let anchor_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, CHECKPOINTS_PER_EPOCH);
        let anchor_leaf = self.db.db.get_checkpoint_leaf_data(anchor_id).await?;
        let seed_felts = anchor_leaf.stats.random_seed.to_4_felts();
        let anchor_seed = [
            seed_felts[0].to_u64_value(),
            seed_felts[1].to_u64_value(),
            seed_felts[2].to_u64_value(),
            seed_felts[3].to_u64_value(),
        ];
        let scheduled_proposer = tree_rotation
            .proposer_sub_id(self.db.state.realm_id_u64 as u32, target, anchor_seed)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rotation enabled but proposer_sub_id returned None for realm {} target {}",
                    self.db.state.realm_id_u64,
                    target
                )
            })?;
        Ok(scheduled_proposer == self.db.state.realm_sub_id_u64 as u16)
    }

    /// Build the actual canonical 410-byte finalizer output plus the worker
    /// reward tag from the exact planner witness artifacts, and verify the
    /// reward-root binding R63 = H(A, H(root_reward, worker_tag)) against the
    /// persisted finalizer reward root before anything is signed or submitted.
    async fn build_p2p_finalize_output(
        &self,
        root_job_id: &QProvingJobDataID,
        rewards_root: N::QHash,
    ) -> anyhow::Result<([u8; 410], u64, [u8; 32], [u8; 32], u64)> {
        let unique_pending_id = self.db.state.processing_unique_pending_id;
        let metadata = self
            .db
            .temp_db
            .get_proving_job_metadata(&self.db.state.realm_identifier, unique_pending_id, root_job_id.get_output_id())
            .await?;
        anyhow::ensure!(
            metadata.dependencies.len() == 1,
            "RealmFinalizeGUTA must have exactly the root GUTA child dependency"
        );
        let root_guta_job_id = metadata.dependencies[0].clone();
        let witness = self
            .db
            .temp_db
            .get_tdb_proof_witness::<RealmFinalizeGUTAInput<N::F, N::QHash>>(
                &self.db.state.realm_identifier,
                unique_pending_id,
                root_job_id.get_input_witness_id(),
            )
            .await?;
        let root_guta_reward_tag = self
            .db
            .temp_db
            .get_proof_miner_rewards_tree_value(
                &self.db.state.realm_identifier,
                unique_pending_id,
                root_guta_job_id.get_output_id(),
            )
            .await?;
        let worker_tag = self
            .db
            .temp_db
            .get_proof_claim_tag(
                &self.db.state.realm_identifier,
                unique_pending_id,
                root_job_id.get_input_witness_id(),
            )
            .await?;
        let chain_domain =
            realm_finalize_guta_chain_domain::<N::F, N::QHash, N::HasherBase>(self.db.state.chain_id);
        let output = finalize_output_from_witness::<N::F, N::QHash, N::HasherBase>(
            &witness,
            chain_domain,
            root_guta_reward_tag,
        );
        let reward_root63 = finalize_reward_root63::<N::F, N::QHash, N::HasherBase>(&output, &worker_tag);
        anyhow::ensure!(
            reward_root63 == rewards_root,
            "Actual finalizer output does not bind the persisted reward root (A/R63 mismatch)"
        );
        let base_checkpoint_id = output.checkpoint_id.to_u64_value();
        let validator_tree_root = output.validator_tree_root.into_owned_32bytes();
        require_nonzero_validator_tree_root(&validator_tree_root)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        Ok((
            protocol_encode_finalize_output(&output)?,
            base_checkpoint_id,
            validator_tree_root,
            worker_tag.into_owned_32bytes(),
            output.validator_user_id.to_u64_value(),
        ))
    }
}
