use std::time::Duration;

use parth_core::{
    crypto::hash::traits::HashTo4Felts,
    felt::ToU64Value,
    protocol::core_types::QNetworkTypesConfig,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobType},
    node::node_proving_state::PsyNodeProvingState,
    p2p::{encode_proposal_body, proposal_from_parts, replication_threshold, sha256},
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use cf_utils::timer::TraceTimer;
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
    processor::{
        consensus::{form_certificate, sign_vote},
        core::PsyRealmProcessor,
        gatherers::realm_end_cap_gatherer::{
            get_new_realm_end_cap_gatherer_backup_file_path, RealmGUTAEndCapGathererOutput,
        },
    },
    queue_key::RealmProvingWorkQueueKey,
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
        let root_job_proof = self
            .db
            .proof_store
            .get_proof_bytes_by_job_id(root_job_id, self.db.state.processing_unique_pending_id)
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

        // Optional Realm P2P proposal publish + blocking vote wait (Slice C).
        // Engages only when a RealmNetworkCommands handle and a
        // RealmRotationConfig have been wired in via `set_realm_p2p` AND
        // rotation is enabled. This block publishes the Proposal and the
        // processor's own Vote, then blocks on `wait_votes` until the
        // replication threshold is met, and forms a Certificate it does NOT
        // submit to the coordinator over P2P. GUTA admission stays on the
        // HTTP `rc_submit_guta_proof` path below regardless of this block.
        // Every missing input fails closed with a named error; there is no
        // local fallback after a failed forward.
        if let (Some(cmds), Some(rotation)) = (&self.p2p, &self.rotation) {
            if rotation.is_enabled() {
                self.publish_realm_p2p_proposal(&submission_header, &root_job_proof)
                    .await?;
            }
        }

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

    /// Publish the Realm P2P Proposal + own Vote, block on votes, and form a
    /// Certificate (without submitting it to the coordinator).
    ///
    /// This runs the Slice C sequence: epoch-of-target scheduled-proposer
    /// check, RGE2 backup read, 410-byte finalizer-output encode, proposal
    /// publish, own-vote sign + publish, blocking `wait_votes` until
    /// `ceil(n/2)` replication, and `form_certificate`. The certificate is
    /// retained (`_certificate`) and never sent over P2P; GUTA admission stays
    /// on the HTTP path in `process_block`. Every missing input bails
    /// fail-closed with a named error.
    async fn publish_realm_p2p_proposal(
        &mut self,
        submission_header: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        root_job_proof: &[u8],
    ) -> anyhow::Result<()> {
        let (cmds, rotation) = (
            self.p2p.as_ref().expect("p2p handle checked by caller"),
            self.rotation.as_ref().expect("rotation checked by caller"),
        );

        // A BLS secret key is required to sign the processor's own Vote. If
        // P2P is enabled without one, fail closed rather than publishing an
        // unsigned / spoofed vote.
        let bls_secret = self.bls_secret.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "realm P2P enabled for realm {} but no BLS secret key was wired via set_realm_p2p",
                self.db.state.realm_id_u64
            )
        })?;

        // Epoch-of-target scheduled-proposer check. The target checkpoint T
        // is the one this GUTA is for (`processing_checkpoint_id`), never the
        // coordinator's current epoch. The anchor seed is the `random_seed` of
        // the epoch's anchor checkpoint leaf, as four Goldilocks u64 limbs.
        // This mirrors the edge EndCap forward path exactly.
        let target = self.db.state.processing_checkpoint_id;
        let epoch = parth_common::realm_rotation::epoch(target, rotation.checkpoints_per_epoch);
        let anchor_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, rotation.checkpoints_per_epoch);
        let anchor_leaf = self.db.db.get_checkpoint_leaf_data(anchor_id).await?;
        let seed_felts = anchor_leaf.stats.random_seed.to_4_felts();
        let anchor_seed = [
            seed_felts[0].to_u64_value(),
            seed_felts[1].to_u64_value(),
            seed_felts[2].to_u64_value(),
            seed_felts[3].to_u64_value(),
        ];
        let scheduled_proposer = rotation
            .proposer_sub_id(self.db.state.realm_id_u64 as u32, target, anchor_seed)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "rotation enabled but proposer_sub_id returned None for realm {} target {}",
                    self.db.state.realm_id_u64,
                    target
                )
            })?;
        let local_sub_id = self.db.state.realm_sub_id_u64 as u16;
        if scheduled_proposer != local_sub_id {
            anyhow::bail!(
                "local realm_sub_id {} is not the scheduled proposer {} for target checkpoint {} \
                 (realm {}); fail-closed, will not submit",
                local_sub_id,
                scheduled_proposer,
                target,
                self.db.state.realm_id_u64
            );
        }

        // Read the gatherer RGE2 backup file carried inside the Proposal body.
        // Fail-closed if the file is missing or unreadable; never invent bytes.
        let backup_path = get_new_realm_end_cap_gatherer_backup_file_path(
            &self.guta_gatherer_backup_directory,
            self.db.state.realm_id_u64,
            self.db.state.realm_sub_id_u64,
            self.db.state.processing_unique_pending_id,
        );
        let backup_path_str = backup_path.to_string_lossy().to_string();
        let backup_bytes = tokio::fs::read(&backup_path).await.map_err(|err| {
            anyhow::anyhow!(
                "realm P2P backup file missing or unreadable at {}: {}",
                backup_path_str,
                err
            )
        })?;

        // 410-byte RealmFinalizeGUTAPublicOutput + the checkpoint-bound
        // validator_tree_root carried by the Proposal. Both require spec
        // fields (`chain_domain`, `validator_tree_root`, `validator_user_id`,
        // `action_hash`) that are not yet plumbed into `PsyRealmProcessorStore`
        // / processor state. Fail-closed: do not zero-fill, do not invent.
        let (output_bytes, validator_tree_root) = self
            .build_p2p_finalize_output(submission_header, root_job_proof, anchor_id)
            .await?;

        let body = encode_proposal_body(&output_bytes, root_job_proof, &backup_bytes)?;
        let body_hash = sha256(&body);
        let public_output_hash = sha256(&output_bytes);
        let finalizer_proof_hash = sha256(root_job_proof);
        let backup_hash = sha256(&backup_bytes);

        let proposal = proposal_from_parts(
            self.db.state.chain_id,
            self.db.state.realm_id_u64 as u32,
            target,
            self.db.state.last_committed_checkpoint_id,
            local_sub_id,
            validator_tree_root,
            public_output_hash,
            finalizer_proof_hash,
            backup_hash,
            body_hash,
        );

        // Publish the Proposal, then sign + publish the processor's own Vote.
        cmds.publish_proposal(proposal.clone(), body).await?;
        let own_vote = sign_vote(bls_secret, local_sub_id, &proposal);
        cmds.publish_vote(own_vote.clone()).await?;

        // Blocking vote collect: `ceil(n/2)` replication threshold, minus the
        // processor's own already-published vote. `wait_votes` is fulfilled by
        // the drive loop; a timeout is fail-closed (NetworkError::Timeout).
        let n = rotation.validator_sub_ids.len();
        let need = replication_threshold(n);
        let remaining = need.saturating_sub(1);
        let mut all_votes = vec![(own_vote.signer_sub_id, own_vote.signature)];
        if remaining > 0 {
            let received = cmds
                .wait_votes(proposal.proposal_id, remaining, Duration::from_secs(120))
                .await?;
            for vote in received {
                all_votes.push((vote.signer_sub_id, vote.signature));
            }
        }

        // Aggregate the collected votes into a Certificate. The certificate is
        // kept locally and is NOT submitted to the coordinator over P2P; GUTA
        // admission stays on the HTTP `rc_submit_guta_proof` path.
        let _certificate = form_certificate(&proposal, &all_votes)?;
        tracing::info!(
            "realm P2P proposal published and certificate formed for realm {} target {} ({} votes)",
            self.db.state.realm_id_u64,
            target,
            all_votes.len()
        );
        Ok(())
    }

    /// Build the 410-byte `RealmFinalizeGUTAPublicOutput` and the
    /// checkpoint-bound `validator_tree_root` carried by the Proposal.
    ///
    /// Per the Slice C wiring contract, only fields provable from
    /// `submission_header` + `db.state` + the anchor checkpoint leaf are
    /// mapped. The spec fields `chain_domain`, `validator_tree_root`,
    /// `validator_user_id`, and `action_hash` are not yet plumbed into
    /// `PsyRealmProcessorStore` / processor state, so this fails closed with a
    /// named error rather than zero-filling or inventing values. When the
    /// validator-tree record API and chain-domain source land, this is the
    /// single point to extend; the publish/vote/wait/certificate wiring above
    /// is already in place.
    async fn build_p2p_finalize_output(
        &self,
        _submission_header: &GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        _root_job_proof: &[u8],
        _anchor_checkpoint_id: u64,
    ) -> anyhow::Result<([u8; 410], [u8; 32])> {
        anyhow::bail!(
            "realm P2P finalize output unavailable for realm {}: spec fields chain_domain, \
             validator_tree_root, validator_user_id, and action_hash are not plumbed into the \
             processor state; refusing to zero-fill or invent (fail-closed)",
            self.db.state.realm_id_u64
        );
    }
}
