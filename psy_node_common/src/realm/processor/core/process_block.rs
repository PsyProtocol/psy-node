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
            protocol_encode_finalize_output, RealmFinalizeGUTAInput,
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
    p2p::{
        traits::realm_coordinantor::RealmCoordinatorClient,
        validator_lookup::{load_realm_validators_from_tree, validator_nodes_from_leaves},
    },
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
            consensus::{
                form_certificate, require_nonzero_validator_tree_root, sign_vote, validate_certificate,
                votes_meet_wait,
            },
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
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
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

    pub async fn sync_and_verify(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
        let mut replay_requests = Vec::new();
        if let Some(replay_rx) = self.baseline_replay_rx.as_mut() {
            while let Ok(request) = replay_rx.try_recv() {
                replay_requests.push(request);
            }
        }
        for request in replay_requests {
            let result = self
                .db
                .verify_state_updates_from_baseline(request.previous_checkpoint_id, &request.updates)
                .await;
            let _ = request.reply.send(result);
        }
        self.db.sync_with_coordinator().await?;
        self.apply_proposal_ffs().await?;
        self.db.ensure_db_matches_coordinator_head().await
    }


    async fn apply_proposal_ffs(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
        let latest_checkpoint_id = self.db.coordinator_client.rc_get_latest_checkpoint_id().await?;
        self.db.set_last_committed_realm_root_from_db().await?;
        let mut coordinator_realm_state = self.db.coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(latest_checkpoint_id, self.db.state.realm_id_u64)
            .await?;
        let mut last_modifieds = Vec::new();
        while coordinator_realm_state.checkpoint_id > self.db.state.last_committed_checkpoint_id {
            last_modifieds.push((
                coordinator_realm_state.checkpoint_id,
                coordinator_realm_state.value.into_owned_32bytes(),
            ));
            let previous = self.db.coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(
                    coordinator_realm_state.checkpoint_id - 1, self.db.state.realm_id_u64,
                ).await?;
            if previous.checkpoint_id <= self.db.state.last_committed_checkpoint_id {
                break;
            }
            anyhow::ensure!(previous.checkpoint_id < coordinator_realm_state.checkpoint_id,
                "Coordinator realm last-modified checkpoint did not decrease during recovery");
            coordinator_realm_state = previous;
        }
        last_modifieds.reverse();
        let old_root = self.db.state.last_committed_realm_end_root.into_owned_32bytes();
        let (transition, included_checkpoint_id) = match crate::realm::processor::catchup::first_root_change(
            self.db.state.last_committed_checkpoint_id,
            old_root,
            &last_modifieds,
        ) {
            None => {
                if let Some(&(accounted_checkpoint, _)) = last_modifieds
                    .iter()
                    .rev()
                    .find(|(checkpoint_id, _)| *checkpoint_id > self.db.state.last_committed_checkpoint_id)
                {
                    self.db.state.last_committed_checkpoint_id = accounted_checkpoint;
                    self.db.shared_state.update_from_core_state(&self.db.state).await?;
                }
                return self.db.sync_to_coordinator_checkpoint_id(latest_checkpoint_id).await;
            }
            Some((transition, included_checkpoint)) => (transition, included_checkpoint),
        };
        coordinator_realm_state = self.db.coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(included_checkpoint_id, self.db.state.realm_id_u64)
            .await?;
        let coordinator_update = self.db.coordinator_client
            .rc_get_realm_sync_info(included_checkpoint_id, self.db.state.realm_id_u64)
            .await?;
        let included = crate::realm::processor::ffs::CheckpointIdentity {
            checkpoint_id: included_checkpoint_id,
            checkpoint_leaf_hash: coordinator_update
                .checkpoint_sync_info
                .checkpoint_leaf_hash
                .into_owned_32bytes(),
        };
        let gathering_start = self.db.state.gathering_realm_start_root;
        let mut selected = match self
            .db
            .verify_history_transition(&included, transition, None, &self.proposal_backup)
            .await
        {
            Ok(Some(verified)) if included.checkpoint_id > self.db.state.last_committed_checkpoint_id => {
                Some(
                    self.db
                        .apply_history_proposal(&included, verified)
                        .await?,
                )
            }
            Ok(Some(verified)) => Some((verified.updates, verified.state_updates)),
            Ok(None) => None,
            Err(error) if crate::realm::processor::ffs::invalid_candidate_id(&error).is_some() => None,
            Err(error) => return Err(error),
        };
        if selected.is_none() {
            if let Some(client) = self.p2p.as_ref() {
                let (_, _, _, leaves) = self
                    .load_base_checkpoint_validators(self.db.state.last_committed_checkpoint_id)
                    .await?;
                let validator_nodes = validator_nodes_from_leaves(&leaves);
                let peers = crate::realm::processor::catchup::CatchupPeers::select(
                    &validator_nodes,
                    self.db.state.realm_sub_id_u64 as u16,
                )?;
                let staged = crate::realm::processor::catchup::stage_transition_blocks(
                    client,
                    &self.proposal_backup,
                    &peers,
                    self.db.state.chain_id,
                    self.db.state.realm_id_u64 as u32,
                    &[transition],
                    &[],
                )
                .await
                .into_iter()
                .find_map(|outcome| match outcome {
                    crate::realm::processor::catchup::TransitionFetchOutcome::Staged(_, staged) => Some(staged),
                    crate::realm::processor::catchup::TransitionFetchOutcome::Absent(transition) => {
                        tracing::debug!(
                            "no peer offered transition=({},{})",
                            hex::encode(transition.old_root),
                            hex::encode(transition.new_root)
                        );
                        None
                    }
                    crate::realm::processor::catchup::TransitionFetchOutcome::Failed(transition, error) => {
                        tracing::warn!(
                            "peer fetch failed transition=({},{}) error={error:#}",
                            hex::encode(transition.old_root),
                            hex::encode(transition.new_root)
                        );
                        None
                    }
                });
                selected = match self
                    .db
                    .verify_history_transition(&included, transition, staged.as_ref(), &self.proposal_backup)
                    .await
                {
                    Ok(Some(verified)) => {
                        if let Some(staged) = staged {
                            self.proposal_backup.install(staged).await?;
                        }
                        if included.checkpoint_id > self.db.state.last_committed_checkpoint_id {
                            Some(
                                self.db
                                    .apply_history_proposal(&included, verified)
                                    .await?,
                            )
                        } else {
                            Some((verified.updates, verified.state_updates))
                        }
                    }
                    Ok(None) => None,
                    Err(error) => {
                        if crate::realm::processor::ffs::invalid_candidate_id(&error).is_none() {
                            return Err(error);
                        }
                        None
                    }
                };
            }
        }
        let Some((updates, updates_bytes)) = selected else {
            anyhow::ensure!(coordinator_realm_state.value == self.db.state.last_committed_realm_end_root
                && coordinator_realm_state.checkpoint_id <= self.db.state.last_committed_checkpoint_id,
                "Checkpoint {}: no stored proposal for included realm transition {:?} -> {:?}",
                coordinator_realm_state.checkpoint_id, self.db.state.last_committed_realm_end_root,
                coordinator_realm_state.value);
            return self.db.sync_to_coordinator_checkpoint_id(latest_checkpoint_id).await;
        };
        if included_checkpoint_id > self.db.state.last_committed_checkpoint_id {
            tracing::info!(
                "Applied proposal FFS checkpoint_id={}",
                included_checkpoint_id
            );
        }

        self.db.state.gathering_realm_start_root = updates.new_realm_root;
        self.db.shared_state.update_from_core_state(&self.db.state).await?;
        if gathering_start != updates.old_realm_root && gathering_start != updates.new_realm_root {
            self.recreate_guta_gatherer().await?;
        } else if updates.realm_sub_id != self.db.state.realm_sub_id_u64 {
            self.guta_queue_gatherer.fast_forward(updates_bytes).await?;
        }
        self.db
            .publish_validator_leaves(self.p2p.as_ref(), self.db.state.last_committed_checkpoint_id)
            .await?;
        self.db.sync_to_coordinator_checkpoint_id(self.db.state.last_committed_checkpoint_id).await
    }






    pub async fn process_block(&mut self) -> anyhow::Result<()>
    where
        N::HasherBase: MerkleZeroHasher<N::QHash>,
    {
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
            self.db.sync_to_coordinator_checkpoint_id(self.db.state.last_committed_checkpoint_id).await?;
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
                anyhow::bail!(
                    "realm P2P nonempty gather is not scheduled at T=base+1 realm={} sub={} base={} end_caps={}; refusing to sync after gatherer tree commit",
                    self.db.state.realm_id_u64,
                    self.db.state.realm_sub_id_u64,
                    base_checkpoint_id,
                    guta_update.total_users_updated
                );
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
        let mut p2p_submission = None;
        if self.p2p.is_some() && self.rotation.as_ref().is_some_and(|rotation| rotation.is_enabled()) {
            p2p_submission = self
                .publish_realm_p2p_proposal(&root_job_id, &root_job_proof, rewards_root, &db_output)
                .await?;
        }

        let (proposal_bytes, certificate_bytes) = match p2p_submission.as_ref() {
            Some((proposal, certificate, _output_bytes, _worker_tag)) => (
                Some(proposal.protocol_encode_to_vec()),
                Some(certificate.protocol_encode_to_vec()),
            ),
            None => (None, None),
        };

        // 7. Submit to Coordinator
        tracing::info!("Submitting GUTA proof to Coordinator...");
        self.db
            .coordinator_client
            .rc_submit_guta_proof(
                submission_header.clone(),
                root_job_proof.clone(),
                self.db.state.realm_id_u64,
                proposal_bytes.clone(),
                certificate_bytes.clone(),
            )
            .await?;
        timer.lap("submit_guta_proof");

        // 8. Wait for Coordinator Commit
        tracing::info!("Waiting for Coordinator to include Realm Root: {:?}", guta_update.new_realm_root);
        let sync_info = self
            .db
            .wait_for_realm_update_sync_with_coordinator(
                guta_update.new_realm_root,
                submission_header,
                &root_job_proof,
                self.guta_resend_after_checkpoints,
                proposal_bytes,
                certificate_bytes,
            )
            .await?;
        timer.lap("wait_for_realm_update_sync");


        // 9. Commit Local State


        self.db.run_sanity_check("before commit").await?;

        //self.db.print_last_10_checkpoint_roots_and_leaves("process_block before
        // commit_state").await?;

        self.db
            .commit_state(
                &sync_info,
                &db_output,
                root_job_id.circuit_type,
                root_job_proof,
            )
            .await?;
        timer.lap("commit_state");
        self.db.run_sanity_check("after commit").await?;
        self.db
            .publish_validator_leaves(self.p2p.as_ref(), self.db.state.last_committed_checkpoint_id)
            .await?;

        tracing::info!(
            "Committed new realm block with checkpoint_id = {}.",
            self.db.state.processing_checkpoint_id
        );
        self.db.print_coordinator_processor_state();

        // Final sync
        self.db.sync_to_coordinator_checkpoint_id(self.db.state.last_committed_checkpoint_id).await?;
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
        let (validator_sub_ids, leaf_bls_keys, validator_user_ids, _) =
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
        self.proposal_backup.save_proposal(&proposal, &body).await?;
        cmds.publish_proposal(proposal.clone(), body.clone(), remote_bls_keys).await?;
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
        self.proposal_backup.save_proposal(&proposal, &body).await?;
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
        Vec<(u16, psy_data::p2p::ValidatorLeaf)>,
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
        let (validator_sub_ids, _, _, _) = self.load_base_checkpoint_validators(base_checkpoint_id).await?;
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
