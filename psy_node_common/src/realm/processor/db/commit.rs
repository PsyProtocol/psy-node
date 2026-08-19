use anyhow::Ok;
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::
        merkle_proof::MerkleProofCore
    ,
    protocol::core_types::QNetworkTypesConfig,
    data::queue::queue_key::{PCoreSubjectQueueBase, QPBaseQueueType},
};
use psy_core::
    job::job_id::ProvingJobCircuitType
;
use psy_data::{
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyRealmCoordinatorUpdate},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::
        checkpoint_sync::PQEDCheckpointSyncInfoCompact
    ,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;

use crate::realm::{
    processor::db::PsyRealmDatabaseProcessor,
    queue_key::{RealmUserUpdateQueueKey, RealmProvingWorkQueueKey},
};

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync,
        ProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync,
{
    pub async fn set_new_unique_ids(&mut self, gathering_realm_end_root: Option<N::QHash>) -> anyhow::Result<()> {
        println!(
            "old_unique_pending_id: {}, old_proc_checkpoint_unique_id: {}",
            self.state.processing_unique_pending_id, self.state.processing_proc_checkpoint_unique_id
        );
        println!(
            "old_gathering_unique_pending_id: {}, old_gathering_proc_checkpoint_unique_id: {}",
            self.state.gathering_unique_pending_id, self.state.gathering_proc_checkpoint_unique_id
        );
        let (new_gathering_unique_pending_id, new_gathering_proc_checkpoint_unique_id) = self.db.inc_unique_pending_id(1).await?;

        // Ensure streams exist first
        self.guta_update_queue.ensure_stream().await?;
        self.proof_work_queue.ensure_stream().await?;

        // Create consumers for gathering proc_checkpoint_unique_id, and also for processing if it's 0 (genesis case)
        let realm_id = self.state.realm_id_u64;
        let realm_sub_id = self.state.realm_sub_id_u64;
        let unique_id = new_gathering_proc_checkpoint_unique_id;
        let gathering_proc_id = self.state.gathering_proc_checkpoint_unique_id;
        let should_create_genesis_consumers = gathering_proc_id == QCoreProcCheckpointUniqueId::from(0u128);

        let guta_key = RealmUserUpdateQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyRealmUserUpdateQueueItem<N::F, N::QHash>>,
        };
        let proof_key = RealmProvingWorkQueueKey {
            realm_id, realm_sub_id, unique_id, task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
        };

        // Create consumers for gathering proc_id
        self.guta_update_queue.ensure_consumer(&guta_key, realm_id, realm_sub_id, unique_id, 0).await?;
        self.proof_work_queue.ensure_consumer(&proof_key, realm_id, realm_sub_id, unique_id, 0).await?;

        // Also create consumers for processing proc_id if it's 0 (genesis case)
        if should_create_genesis_consumers {
            let processing_guta_key = RealmUserUpdateQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral, _phantom_queue_item: std::marker::PhantomData::<PsyRealmUserUpdateQueueItem<N::F, N::QHash>>,
            };
            let processing_proof_key = RealmProvingWorkQueueKey {
                realm_id, realm_sub_id, unique_id: gathering_proc_id, task_group: 0,
                queue_type: QPBaseQueueType::WorkerQueue, _phantom_queue_item: std::marker::PhantomData::<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>>,
            };

            self.guta_update_queue.ensure_consumer(&processing_guta_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
            self.proof_work_queue.ensure_consumer(&processing_proof_key, realm_id, realm_sub_id, gathering_proc_id, 0).await?;
        }

        self.state.finish_gathering(
            gathering_realm_end_root.unwrap_or(self.state.last_committed_realm_end_root),
            self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head(),
            self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head(),
            new_gathering_unique_pending_id,
            new_gathering_proc_checkpoint_unique_id,
        )?;
        self.shared_state.update_from_core_state(&self.state).await?;

        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.state.realm_identifier,
                self.state.gathering_unique_pending_id,
                self.state.gathering_proc_checkpoint_unique_id,
            )
            .await?;
        self.temp_db
            .set_unique_pending_ids(
                &self.state.realm_identifier,
                self.state.processing_unique_pending_id,
                self.state.processing_proc_checkpoint_unique_id,
            )
            .await?;

        println!(
            "new_unique_pending_id: {}, new_proc_checkpoint_unique_id: {}",
            self.state.processing_unique_pending_id, self.state.processing_proc_checkpoint_unique_id
        );
        println!(
            "new_gathering_unique_pending_id: {}, new_gathering_proc_checkpoint_unique_id: {}",
            self.state.gathering_unique_pending_id, self.state.gathering_proc_checkpoint_unique_id
        );

        Ok(())
    }

    pub async fn commit_checkpoint_state_no_guta_update(
        &mut self,
        checkpoint_sync_info: &PQEDCheckpointSyncInfoCompact<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let previous = self.write_checkpoint_state_records(checkpoint_sync_info).await?;

        let expected_new_checkpoint_root = previous.compute_root_with_value::<N::HasherBase>(checkpoint_sync_info.checkpoint_leaf_hash);
        if expected_new_checkpoint_root != checkpoint_sync_info.checkpoint_tree_root {
            anyhow::bail!("Inconsistent checkpoint tree root detected when committing checkpoint ID: {}. Expected root: {:?}, but got: {:?}. This indicates a serious inconsistency in the checkpoint tree state.",
                checkpoint_sync_info.checkpoint_id, expected_new_checkpoint_root, checkpoint_sync_info.checkpoint_tree_root);
        }

        self.checkpoint_tree_backup_manager
            .append_checkpoint_leaf_hash(checkpoint_sync_info.checkpoint_id, checkpoint_sync_info.checkpoint_leaf_hash)
            .await?;

        // THIS DOES NOT SET THE LATEST CHECKPOINT ID, THAT MUST BE DONE AT THE VERY END
        // OF COMMITTING THE FULL STATE

        Ok(())
    }

    async fn commit_checkpoint_state_after_checkpoint_tree_sync(
        &mut self,
        checkpoint_sync_info: &PQEDCheckpointSyncInfoCompact<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        self.write_checkpoint_state_records(checkpoint_sync_info).await?;

        // The checkpoint tree backup manager was already synced from coordinator,
        // so do not recompute a historical append root or append this leaf again.
        Ok(())
    }

    async fn write_checkpoint_state_records(
        &mut self,
        checkpoint_sync_info: &PQEDCheckpointSyncInfoCompact<N::F, N::QHash>,
    ) -> anyhow::Result<MerkleProofCore<N::QHash>> {
        let previous: MerkleProofCore<N::QHash> = self
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(checkpoint_sync_info.checkpoint_id);

        // ORDERING IS LOAD-BEARING: these writes are not transactional. Recovery
        // (`get_latest_available_l2_block_state` / `try_get_complete_l2_block_state`) treats a checkpoint as
        // complete based on its core metadata records, so the L2 block state MUST be written LAST — after the
        // state roots, checkpoint leaf, tree proof, and root mapping. Writing it earlier would let a crash mid-way
        // leave a checkpoint that looks complete (L2 present) but is missing its proof/root mapping, which recovery
        // would then never backfill. The `latest_l2_block_state` singleton is advanced by the caller
        // (`commit_state`) only after `set_latest_checkpoint_id`, so it can never lead the committed marker.
        self.db
            .set_checkpoint_global_state_roots(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.state_roots)
            .await?;
        self.db
            .set_checkpoint_leaf_data(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.checkpoint_leaf)
            .await?;

        println!("committing checkpoint proof: {:?}", &previous.to_append_proof::<N::HasherBase>());
        // --- START FIX ---
        // Instead of just setting the leaf hash, ingest the full proof from the correct in-memory tree.
        // This ensures the database's internal tree structure is updated correctly.
        self.db
            .checkpoint_tree_injest_merkle_proof(checkpoint_sync_info.checkpoint_id, &previous.to_append_proof::<N::HasherBase>())
            .await?;
        // --- END FIX ---

        self.db
            .set_checkpoint_root_hash_to_id_mapping(checkpoint_sync_info.checkpoint_tree_root, checkpoint_sync_info.checkpoint_id)
            .await?;

        // Sentinel write — must remain the final persisted metadata for this checkpoint (see note above).
        self.db
            .set_l2_block_state(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.block_state)
            .await?;

        Ok(previous)
    }

    /// Plan this Realm commit and make its manifest durable.
    ///
    /// The chain reference is the Coordinator's, not one this Realm invents: a
    /// Realm commits at a checkpoint it was told to commit, so both manifests
    /// name the same `(chain_epoch, checkpoint)` and a rollback can line them up
    /// rather than infer a correspondence (§6.3).
    async fn record_realm_commit_prepared(
        &self,
        coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    ) -> anyhow::Result<
        psy_node_core::store::realm_recording_flow::PreparedRealmCommit<N::QHash>,
    > {
        use psy_data::protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
        };
        use psy_node_core::store::authority_commit::{
            AuthorityClockSampleUs, AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        };
        use psy_node_core::store::commit_planner::RealmCommitPlanInputs;
        use psy_data::protocol::chain_context::{
            AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
        };
        use psy_node_core::store::manifest_intent::{AuthorityHeadPayload, AuthorityStateTransition};

        let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
        let unique_pending_id = self.state.processing_unique_pending_id;

        let inputs = RealmCommitPlanInputs {
            checkpoint_id,
            unique_pending_id,
            realm_id: self.state.realm_id_u64,
            update_user_leaves_ffs: &realm_update.update_user_leaves_ffs,
            update_user_contract_tree_nodes_ffs: &realm_update.update_user_contract_tree_nodes_ffs,
            update_contract_state_tree_nodes_ffs: &realm_update
                .update_contract_state_tree_nodes_ffs,
            update_contract_state_imt_leaves_ffs: &realm_update
                .update_contract_state_imt_leaves_ffs,
            update_global_user_tree_nodes_ffs: &realm_update.update_global_user_tree_nodes_ffs,
        };

        // The allocator and the manifest are partitioned by this exact scope, so
        // a Realm's records sit beside the Coordinator's at the same height.
        let key = AuthorityTimestampKey::new(
            self.network_id,
            AuthorityScope::Realm {
                realm_id: self.state.realm_identifier.realm_id,
                realm_sub_id: self.state.realm_identifier.realm_sub_id,
            },
        );
        // The Coordinator's coordinate, carried through untouched.
        // The epoch the Coordinator is in, not zero.  The manifest is
        // partitioned by it, so a hardcoded zero put the record of a discarded
        // branch and the record of its replacement in the same partition at the
        // same height -- and the second one could not be written.
        let chain_at = |height: u64, hash: N::QHash| {
            CanonicalChainRef::new(
                self.network_id,
                ChainEpoch::new(self.state.coordinator_chain_epoch),
                CheckpointRef::new(
                    CheckpointId::new(height),
                    CheckpointHash::from_last_chain_hash(hash),
                ),
            )
        };
        let candidate = chain_at(
            checkpoint_id,
            coordinator_update.checkpoint_sync_info.checkpoint_tree_root,
        );
        let expected = chain_at(
            checkpoint_id.saturating_sub(1),
            self.state.last_committed_checkpoint_root,
        );

        // Changed or Unchanged by what the roots actually say, not by assumption.
        //
        // A Realm commits at every checkpoint the Coordinator publishes, and most
        // of them change nothing of its own -- it is following, not transacting.
        // `Changed` asserts the two roots differ, so declaring it unconditionally
        // makes the manifest claim a state change it cannot show, and sealing
        // fails with ChangedStateHasSameRoot.  It failed exactly that way on the
        // testnet: the Realm processor parked in Error and stopped gathering, so
        // the faucet transaction never landed.
        //
        // The assertion is right; the caller was wrong to bypass the question.
        // The root this block started from, captured before the commit began.
        // `last_committed_realm_end_root` is not it: by the time this runs the
        // sync has already advanced it to the new root, so comparing against it
        // said "unchanged" for every commit the Realm ever made.
        let old_root = self.state.processing_realm_start_root;
        let new_root = realm_update.new_realm_root;
        let transition = if old_root == new_root {
            // `Unchanged` names the checkpoint the state is still *at*, so it has
            // to be at or below the expected head -- naming the height being
            // committed would say "nothing changed, and it did not change at a
            // height nobody has published yet".  The right value is the Realm's
            // last committed height, which is §6.3's sparse "last height that
            // actually changed" semantics: a Realm's state checkpoint does not
            // advance in step with the Coordinator's.
            AuthorityStateTransition::Unchanged {
                checkpoint: AuthorityStateCheckpointId::new(
                    self.state.last_committed_checkpoint_id.min(
                        checkpoint_id.saturating_sub(1),
                    ),
                ),
                root: AuthorityStateRoot::from_local_state_root(new_root),
            }
        } else {
            AuthorityStateTransition::Changed {
                previous_checkpoint: AuthorityStateCheckpointId::new(
                    checkpoint_id.saturating_sub(1),
                ),
                checkpoint: AuthorityStateCheckpointId::new(checkpoint_id),
                old_root: AuthorityStateRoot::from_local_state_root(old_root),
                new_root: AuthorityStateRoot::from_local_state_root(new_root),
            }
        };

        // Logged because the choice is invisible otherwise, and it was wrong for
        // the life of the project without anything showing: the comparison read
        // a root the sync had already advanced, so every commit recorded
        // Unchanged.  A line naming the transition and both roots makes the next
        // such mistake visible in the log rather than only in a manifest nobody
        // decodes.
        if old_root != new_root {
            // Only the state changes are logged.  Unchanged is every other
            // checkpoint and would drown the log; Changed is the case that was
            // silently impossible to record for the life of the project, and is
            // worth a line on its own account -- a Realm changing state is not a
            // routine event.
            tracing::warn!(
                "[REALM_COMMIT] checkpoint {} records Changed: {:?} -> {:?}",
                checkpoint_id,
                old_root,
                new_root
            );
        }

        // The realm root goes in through the state transition above, which already
        // binds it; the payload carries only what the transition does not -- the
        // height and the pending id this commit consumed.  Adding the root here
        // would need a serializer bound this impl does not declare, and would say
        // the same thing twice.
        let mut head_payload = Vec::with_capacity(16);
        head_payload.extend_from_slice(&checkpoint_id.to_le_bytes());
        head_payload.extend_from_slice(&unique_pending_id.to_le_bytes());

        let clock_sample = AuthorityClockSampleUs::try_from_i128(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_micros() as i128,
        )?;

        psy_node_core::store::realm_recording_flow::prepare_realm_commit(
            &self.recording,
            key,
            &inputs,
            expected,
            candidate,
            transition,
            AuthorityHeadPayload::try_new(head_payload)?,
            clock_sample,
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        )
        .await
    }

    /// Seal the Realm manifest against what was actually written.
    ///
    /// A Realm manifest ends at SEALED, and that is a statement about authority
    /// rather than an omission.
    ///
    /// COMMITTED is defined as "the head was published" -- `mark_committed`
    /// takes a `HeadPublishReceipt`, which only a head CAS produces.  §6 gives
    /// the chain one head authority and it is the Coordinator's, so a Realm has
    /// no CAS to produce one and manufacturing a receipt would assert exactly the
    /// authority §6 withholds.
    ///
    /// SEALED already carries what a Realm can honestly claim: `verify_and_seal`
    /// checks the observation against the record, so the row means "my state
    /// writes landed and they match what I recorded".  A Realm rollback planner
    /// therefore takes SEALED as its completeness marker where the Coordinator's
    /// takes COMMITTED.
    async fn complete_realm_commit_record(
        &self,
        prepared: psy_node_core::store::realm_recording_flow::PreparedRealmCommit<N::QHash>,
        observed_realm_root: N::QHash,
    ) -> anyhow::Result<()> {
        use psy_data::protocol::chain_context::{AuthorityStateCheckpointId, AuthorityStateRoot};
        use psy_node_core::store::manifest_lifecycle::{
            AuthorityHeadPayloadDigest, AuthorityHeadView, AuthorityPostWriteObservation,
            AuthorityProofObservation, SealedAuthorityManifest,
        };

        let record = prepared.record().clone();
        let key = record.intent().key();
        let candidate_chain = *record.identity().canonical_chain();
        let checkpoint_id = candidate_chain.checkpoint().checkpoint_id().get();

        // The observation has to restate what the intent committed to, not
        // rebuild it from the caller's own variables.  The state checkpoint is
        // the transition's, which for an unchanged Realm is its last committed
        // height rather than the height being written -- deriving it here from
        // `checkpoint_id` made the two disagree and sealing failed with
        // PostWriteHeadMismatch, leaving a PREPARED row with no SEALED sibling.
        //
        // The root still comes from what was actually observed after the writes:
        // that is the half the check exists to compare.
        let transition = record.intent().state_transition();
        let observed_head = AuthorityHeadView::try_from_observed(
            key,
            candidate_chain,
            transition.state_checkpoint(),
            AuthorityStateRoot::from_local_state_root(observed_realm_root),
        )?;
        let observation = AuthorityPostWriteObservation::new(
            observed_head,
            record.intent().artifacts().mutation_digest(),
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                record.intent().head_payload().as_bytes(),
            ),
            // A Realm proves no checkpoint public input: the checkpoint is the
            // Coordinator's, and claiming it here would assert an authority §6
            // does not give this side.
            AuthorityProofObservation::NotApplicableForRealm,
        );
        let sealed = SealedAuthorityManifest::verify_and_seal(record, observation)?;
        self.recording.manifest().append_sealed(&sealed).await?;

        // Release the lease so the next commit can reserve.
        let state = match self.recording.timestamp().read_timestamp_state(key).await? {
            psy_node_core::store::authority_commit::AuthorityTimestampReadState::Current(state) => {
                state
            }
            psy_node_core::store::authority_commit::AuthorityTimestampReadState::Uninitialized => {
                anyhow::bail!("this Realm's allocator row vanished mid-commit")
            }
        };
        let completion = state.seal_completion(key, prepared.lease())?;
        self.recording
            .timestamp()
            .complete_timestamp(&completion)
            .await?;
        Ok(())
    }

    pub async fn commit_state(
        &mut self,
        coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
        _state_transition_circuit_type: ProvingJobCircuitType,
        _zk_proof: Vec<u8>,
        skip_checkpoint_root_check: bool,
    ) -> anyhow::Result<()> {
        let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
        let unique_pending_id = self.state.processing_unique_pending_id;

        // Record what this commit will write before it writes any of it.  Same
        // rule as the Coordinator's (§3): a crash after the state writes but
        // before the manifest leaves physical rows that no manifest names, and a
        // rollback then has no way to find them.
        //
        // Genesis is exempt on this side too -- it precedes the rollback floor,
        // which is the Coordinator's, so nothing will ever roll back through it.
        let recorded = if checkpoint_id == 0 {
            None
        } else {
            Some(
                self.record_realm_commit_prepared(coordinator_update, realm_update)
                    .await?,
            )
        };

        let _commit_window = match &recorded {
            Some(prepared) => Some(
                self.recording
                    .open_commit_window(checkpoint_id, prepared.lease().timestamp())?,
            ),
            None => None,
        };

        if let (Some(prepared), Some(journal)) = (&recorded, self.recording.journal()) {
            journal
                .record_before(checkpoint_id, prepared.planned_rows())
                .await?;
        }
        // CRITICAL: set unique_pending_id to checkpoint_id mapping BEFORE ANY OTHER
        // STATE UPDATES so we can recover if something goes wrong.
        //
        // SOLE writer of the (unique_pending_id <-> checkpoint_id) mapping. Catch-up,
        // fast-forward, init, and no-jobs-skip paths MUST NOT write this mapping —
        // doing so either pollutes it with `processing_unique_pending_id` values that
        // were never actually committed, or overwrites a correct entry with a stale
        // key -> newer checkpoint pair if the coordinator advanced between commit and
        // a subsequent sync. Both break recovery (init.rs:423) and RPC consumers.
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        self.db
            .set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &self.state.processing_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Set unique pending ID to checkpoint ID mapping for checkpoint ID: {}", checkpoint_id);

        self.db
            .global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &coordinator_update.merkle_proof_to_realm_root)
            .await?;
        self.db
            .set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
                unique_pending_id,
                &coordinator_update.reward_tree_top_proof,
            )
            .await?;
        if skip_checkpoint_root_check {
            self.commit_checkpoint_state_after_checkpoint_tree_sync(&coordinator_update.checkpoint_sync_info)
                .await?;
        } else {
            self.commit_checkpoint_state_no_guta_update(&coordinator_update.checkpoint_sync_info)
                .await?;
        }

        // START STANDARD STATE UPDATES (technically these can be done in any order
        // after the above two are done) start contract updates
        if !realm_update.update_user_leaves_ffs.is_empty() {
            self.db.set_user_leaves_ffs(checkpoint_id, &realm_update.update_user_leaves_ffs).await?;
            tracing::info!("Committed user leaves ffs for checkpoint ID: {}", checkpoint_id);
            self.db
                .contract_state_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_contract_state_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed contract state tree updates for checkpoint ID: {}", checkpoint_id);
            // Write IMT (Indexed Merkle Tree) leaf preimages and key index entries
            if !realm_update.update_contract_state_imt_leaves_ffs.is_empty() {
                self.db
                    .contract_state_imt_set_leaves_ffs(checkpoint_id, &realm_update.update_contract_state_imt_leaves_ffs)
                    .await?;
                tracing::info!("Committed contract state IMT leaf updates for checkpoint ID: {}", checkpoint_id);
            }
            self.db
                .user_contract_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_user_contract_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed user contract tree updates for checkpoint ID: {}", checkpoint_id);
            self.db
                .global_user_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_global_user_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed global user tree updates for checkpoint ID: {}", checkpoint_id);
        }
        // END STANDARD STATE UPDATES (technically these can be done in any order after
        // the above two are done)

        // CRITICAL: we need to set the checkpoint id at the VERY END otherwise the
        // recovery doesn't work this enables us to avoid having to do atomic
        // commits, since if the node dies during this process, it will load the backups
        // from disk SO LONG AS THE checkpoint_id is not set!!!!
        let previous_checkpoint_id = self.state.last_committed_checkpoint_id;
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;
        // Advance the `latest_l2_block_state` singleton only AFTER the checkpoint marker is committed, so the RPC
        // `get_latest_l2_block_state` can never expose a block state that leads the committed `latest_checkpoint_id`.
        self.db
            .set_l2_latest_block_state(&coordinator_update.checkpoint_sync_info.block_state)
            .await?;
        if checkpoint_id > 0 && previous_checkpoint_id < checkpoint_id {
            if let Some((previous_pending_id, _)) = self
                .db
                .get_unique_pending_id_for_checkpoint_id(previous_checkpoint_id)
                .await?
            {
                if let Err(err) = self
                    .proof_store
                    .delete_all_proofs_for_pending_id(previous_pending_id)
                    .await
                {
                    tracing::warn!(
                        "Failed to delete realm proofs for previous checkpoint {} (pending_id={}): {}",
                        previous_checkpoint_id,
                        previous_pending_id,
                        err
                    );
                }
            }
        }
        // Observe the recorded keys now that the writes have landed, then seal
        // the manifest against what was actually written.
        if let (Some(prepared), Some(journal)) = (&recorded, self.recording.journal()) {
            journal
                .record_after(checkpoint_id, prepared.planned_rows())
                .await?;
        }
        if let Some(prepared) = recorded {
            self.complete_realm_commit_record(prepared, realm_update.new_realm_root)
                .await?;
        }

        tracing::info!("Committed coordinator processor state for checkpoint ID: {}", checkpoint_id);
        tracing::info!("Backed up checkpoint tree root for checkpoint ID: {}", checkpoint_id);
        self.state.commit_processing()?;
        self.shared_state.update_from_core_state(&self.state).await?;
        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);

        Ok(())
    }
}
