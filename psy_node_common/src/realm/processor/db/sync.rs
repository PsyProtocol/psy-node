use anyhow::Ok;
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::{prepared_block::realm::PsyRealmCoordinatorUpdate, v1::qdata::checkpoint::QEDL2BlockState};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::realm::processor::db::PsyRealmDatabaseProcessor;

impl<
        N: QNetworkTypesConfig,
        S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
        CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
    > PsyRealmDatabaseProcessor<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>
where
    N::HasherBase: 'static + Send + Sync,
{
    pub async fn sync_to_coordinator_set_checkpoint_id(&mut self) -> anyhow::Result<()> {
        // 1. Sync Headers
        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;

        let mut latest_db_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let latest_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let latest_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        // Defensive: if a previous run (e.g. old fast-forward code) set latest_checkpoint_id
        // without writing the corresponding L2 block state, roll back to the last checkpoint
        // that actually has metadata. This keeps the DB self-consistent.
        let requested_latest_db_checkpoint_id = latest_db_checkpoint_id;
        let (available_latest_db_checkpoint_id, latest_db_l2_info) = self
            .get_latest_available_l2_block_state(latest_db_checkpoint_id)
            .await?;
        latest_db_checkpoint_id = available_latest_db_checkpoint_id;
        if latest_db_checkpoint_id != self.db.get_latest_checkpoint_id().await? {
            tracing::warn!(
                "No L2 block state for latest_checkpoint_id marker {}. Rolling back marker to checkpoint {}.",
                requested_latest_db_checkpoint_id,
                latest_db_checkpoint_id
            );
            self.db.set_latest_checkpoint_id(latest_db_checkpoint_id).await?;
        }

        // Re-anchor the `latest_l2_block_state` singleton to the resolved marker on every sync start, even when
        // the marker itself looked complete. The singleton and the marker are written non-transactionally and in
        // separate steps (see steps 3/4 below and the wait path), so a crash after advancing the singleton but
        // before advancing the marker / committing leaves the singleton *ahead* of the marker. In that case the
        // rollback branch above does NOT fire (the marker's own checkpoint is complete), so the RPC
        // `get_latest_l2_block_state` would keep serving a block_state for a checkpoint that was never committed.
        // Pulling the singleton back to the marker's block state here heals that lead before we advance again.
        self.db.set_l2_latest_block_state(&latest_db_l2_info).await?;

        // Check if DB is already up to date
        let db_root = self.db.checkpoint_tree_get_root_hash(latest_db_checkpoint_id).await?;
        if latest_synced_checkpoint_id == latest_db_checkpoint_id && latest_synced_checkpoint_root == db_root {
            tracing::debug!(
                "Coordinator processor database is already synced to latest checkpoint ID: {} and root: {:?}",
                latest_synced_checkpoint_id,
                latest_synced_checkpoint_root
            );
            return Ok(());
        }

        // 2. Fetch and persist metadata for missing checkpoints
        let latest_sync_info = match self
            .persist_checkpoint_metadata_range(latest_db_checkpoint_id + 1, latest_synced_checkpoint_id, latest_db_checkpoint_id)
            .await?
        {
            Some(sync_info) => sync_info,
            None => self
                .coordinator_client
                .rc_get_realm_sync_info(latest_synced_checkpoint_id, self.state.realm_id_u64)
                .await?,
        };

        self.sync_contract_heights(
            latest_db_l2_info.next_contract_id,
            latest_sync_info.checkpoint_sync_info.block_state.next_contract_id,
            latest_synced_checkpoint_id,
        )
        .await?;

        self.db.set_latest_checkpoint_id(latest_synced_checkpoint_id).await?;

        // Advance the `latest_l2_block_state` singleton only AFTER the checkpoint marker (and all dependent
        // writes above) have succeeded, so the RPC `get_latest_l2_block_state` can never expose a block state
        // that leads the committed `latest_checkpoint_id`.
        self.db
            .set_l2_latest_block_state(&latest_sync_info.checkpoint_sync_info.block_state)
            .await?;

        // 5. CRITICAL: Update Internal Memory State to match the new HEAD
        let latest_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        
        self.state.coordinator_head_synced_checkpoint_id = latest_synced_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = latest_checkpoint_root;
        self.state.processing_checkpoint_root = latest_checkpoint_root;
        self.state.gathering_checkpoint_root = latest_checkpoint_root;
        self.state.processing_checkpoint_id = latest_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = latest_synced_checkpoint_id;

        // Update the last committed markers so wait logic knows where to start looking next
        let realm_root_state = self.coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(latest_synced_checkpoint_id, self.state.realm_id_u64)
            .await?;
        
        self.state.last_committed_checkpoint_id = latest_synced_checkpoint_id;
        self.state.last_committed_realm_end_root = realm_root_state.value;
        // The start root for the NEXT block is the end root of the current block
        self.state.last_committed_realm_start_root = realm_root_state.value;
        self.state.processing_realm_start_root = realm_root_state.value;
        self.state.processing_realm_end_root = realm_root_state.value;
        self.state.gathering_realm_start_root = realm_root_state.value;

        // Also update checkpoint root
        let checkpoint_proof = self.checkpoint_tree_backup_manager.checkpoint_tree.get_leaf(latest_synced_checkpoint_id);
        self.state.last_committed_checkpoint_root = checkpoint_proof.get_append_root::<N::HasherBase>();

        tracing::info!(
            "Synchronized coordinator processor database to checkpoint ID: {}. New Base Realm Root: {:?}.", 
            latest_synced_checkpoint_id, realm_root_state.value
        );
        Ok(())
    }

    /// Point this Realm back at `target` so its next sync re-fetches from there.
    ///
    /// A Realm holds two different kinds of state, and only one of them is its
    /// own.  Its transactions -- user leaves, contract state, the IMT -- are
    /// written by `commit_state`, recorded in its manifest, and rolled back by
    /// deleting what the manifest names.  Everything this module writes is a
    /// *copy* of checkpoints the Coordinator published: leaf data, state roots,
    /// the root mapping, the block state.  Copies do not need their old values
    /// restored, because the authoritative source still has them -- they need to
    /// be fetched again.
    ///
    /// Two things make that work, and neither is optional.
    ///
    /// The marker has to move first.  `persist_checkpoint_metadata_range` starts
    /// at `latest_checkpoint_id + 1`, so a Realm that still believes it is at 100
    /// while the Coordinator has rolled back to 95 computes `from = 101,
    /// to = 95`, returns immediately, and never syncs again.  It does not drift
    /// -- it stops.
    ///
    /// The local checkpoint tree has to be truncated too.  `sync` validates each
    /// fetched checkpoint against the root its own in-memory tree computes, and
    /// after a rollback that tree still holds the discarded branch's leaves, so
    /// the first re-fetched height fails the check.  That path does recover --
    /// it hard-resets and asks the caller to retry -- but recovering through a
    /// deliberate error is not the same as not needing one, and the reset it
    /// performs uses whatever marker it happened to read.  Truncating here makes
    /// the first attempt correct.
    ///
    /// Rows the Realm holds above `target` are left to be overwritten as the
    /// chain climbs back through those heights; each write in the loop is an
    /// unconditional `set_*`, so a re-synced height replaces what was there.
    /// Heights the new branch never reaches keep stale copies, which is a leak
    /// rather than a ghost: nothing reads a checkpoint above the current head.
    /// Run this Realm's share of a rollback the Coordinator has published, and
    /// report whether it did.
    ///
    /// Called when the Coordinator publishes FROZEN, which is the only moment a
    /// Realm can join: the archive barrier is what stops the Coordinator
    /// crossing the point of no return while a participant has copied nothing,
    /// and it can only wait for a receipt that a running Realm files.  A Realm
    /// that is down for this misses it and recovers afterwards instead --
    /// slower, and without the barrier's protection, but the only option left
    /// to it.
    ///
    /// `Ok(false)` means this Realm has no way to take part, which is the
    /// configuration before rollback participation is enabled.
    pub async fn take_part_in_rollback(&mut self, target: u64) -> anyhow::Result<bool> {
        let Some(driver) = self.recording.participation() else {
            return Ok(false);
        };
        let head = self.coordinator_chain_ref_last_synced();
        let report = driver
            .take_part_in_rollback(
                &self.recording,
                self.state.realm_identifier.realm_id,
                self.state.realm_identifier.realm_sub_id,
                &head,
                target,
            )
            .await?;
        tracing::warn!(
            "[REALM_ROLLBACK] took part in the rollback to {}: {} rows planned, {} archived, {} \
             deleted from this Realm's own share",
            report.target,
            report.planned_rows,
            report.archived_rows,
            report.deleted_rows
        );
        // The sync markers still describe the discarded range: the rows are
        // gone but this Realm still believes it is at the old height.
        self.reset_for_rollback_to(target).await?;
        Ok(true)
    }

    /// Confirm this Realm has reached `target` and file the verify receipt the
    /// Coordinator's publish barrier waits for.
    pub async fn confirm_rollback_target_reached(&mut self, target: u64) -> anyhow::Result<bool> {
        let Some(driver) = self.recording.participation() else {
            return Ok(false);
        };
        let search_head = self.coordinator_chain_ref_last_synced();
        driver
            .confirm_target_reached(
                &self.recording,
                self.state.realm_identifier.realm_id,
                self.state.realm_identifier.realm_sub_id,
                &search_head,
                target,
            )
            .await?;
        Ok(true)
    }

    /// Undo everything above `target`: what this Realm wrote itself, then what
    /// it copied from the Coordinator.
    ///
    /// Own state first.  The sync reset makes the Realm re-fetch the
    /// Coordinator's view of the range, and doing that while the Realm still
    /// holds its own discarded writes would have it compare a rebuilt copy
    /// against state that should no longer exist.
    ///
    /// A Realm with no transactions in the range does nothing here beyond one
    /// manifest read, which is the ordinary case.
    pub async fn undo_everything_above(&mut self, target: u64) -> anyhow::Result<()> {
        // No epoch override: a Realm following a rollback while running has not
        // adopted the new one yet, so the epoch it is carrying is still the
        // branch its own state was written on.
        self.undo_everything_above_bounded(target, None, None).await
    }

    /// As above, with an explicit bound on how far the Realm's own manifest is
    /// searched.
    ///
    /// The bound matters more than it looks.  Derived from this Realm's own
    /// caches it is only right while they are intact, and the recovery paths
    /// truncate exactly those -- so a reconciliation that truncated first and
    /// searched second found an empty range and concluded the Realm had nothing
    /// of its own above the target, for a Realm that had plenty.  The
    /// Coordinator's published head is not derived from anything this Realm can
    /// damage, and no Realm commits above it.
    ///
    /// `plan_epoch` names the branch the state being undone was committed
    /// under, and it is not the epoch this Realm is now on.  Startup adopts the
    /// Coordinator's epoch before anything else runs -- it has to, so nothing
    /// stamps a record with a stale one -- so by the time a reconciliation gets
    /// here, `coordinator_chain_epoch` is the *new* branch's.  Planning with it
    /// searches a manifest partition that by construction cannot hold the range,
    /// finds nothing, and reports that the Realm had nothing of its own to undo.
    ///
    /// realm_0 wedged that way for 954 retries: its own commits at 144 through
    /// 149 were written under epoch 3, the chain moved to epoch 4, and the
    /// restart planned against epoch 4. Nothing was undone, so the Realm sat at
    /// checkpoint 149 while the Coordinator said its root was at 141, and
    /// `Sync and verify failed: Realm Root mismatch` every second after that.
    ///
    /// The live path passes `None` and is right to: a Realm that follows a
    /// rollback while running has not adopted the new epoch yet.
    pub async fn undo_everything_above_bounded(
        &mut self,
        target: u64,
        search_head_height: Option<u64>,
        plan_epoch: Option<u64>,
    ) -> anyhow::Result<()> {
        if let Some(driver) = self.recording.self_rollback() {
            let mut search_head = self.coordinator_chain_ref_last_synced();
            if search_head_height.is_some() || plan_epoch.is_some() {
                use psy_data::protocol::canonical_chain::{
                    CanonicalChainRef, ChainEpoch, CheckpointId, CheckpointRef,
                };
                let height = search_head_height
                    .unwrap_or_else(|| search_head.checkpoint().checkpoint_id().get());
                let epoch = plan_epoch.unwrap_or_else(|| search_head.chain_epoch().get());
                search_head = CanonicalChainRef::new(
                    search_head.network_id(),
                    ChainEpoch::new(epoch),
                    CheckpointRef::new(
                        CheckpointId::new(height),
                        *search_head.checkpoint().checkpoint_hash(),
                    ),
                );
            }
            let report = driver
                .recover_own_state_to(
                    &self.recording,
                    self.state.realm_identifier.realm_id,
                    self.state.realm_identifier.realm_sub_id,
                    &search_head,
                    target,
                )
                .await?;
            if report.changed_anything() {
                tracing::warn!(
                    "[REALM_ROLLBACK] undid this Realm's own state from checkpoint {} down to \
                     {}: {} rows archived and deleted",
                    report.own_head,
                    report.target,
                    report.deleted_rows
                );
            } else if plan_epoch.is_some() {
                // Saying so out loud, because this is the shape the failure took
                // and it took a day to see. A reconciliation runs only when a
                // rollback was missed; finding nothing to undo is possible -- a
                // Realm with no transactions in the range -- but it is also what
                // searching the wrong epoch looks like, and the two are
                // indistinguishable from in here. Whichever it is, the epoch
                // gets recorded next and the Realm will never look again, so
                // this line is the only trace left if it was the second.
                tracing::warn!(
                    "[REALM_ROLLBACK] found nothing of this Realm's own above {} under epoch {}; \
                     recording the epoch regardless -- if this Realm did commit up there, it is \
                     about to keep state from a branch that no longer exists",
                    target,
                    plan_epoch.unwrap_or_default(),
                );
            }
        }
        self.reset_for_rollback_to(target).await
    }

    pub async fn reset_for_rollback_to(&mut self, target: u64) -> anyhow::Result<()> {
        let resync_from = target.saturating_sub(1);
        tracing::warn!(
            "[REALM_ROLLBACK] resetting Realm sync state to checkpoint {} so the next sync \
             re-fetches {} onward",
            resync_from,
            target
        );
        self.checkpoint_tree_backup_manager
            .hard_reset_and_truncate(resync_from)
            .await?;
        self.db.set_latest_checkpoint_id(resync_from).await?;
        Ok(())
    }

    /// Release an allocator lease left held by a commit that never finished.
    ///
    /// The same shape as the Coordinator's, and for the same reason: the
    /// allocator keeps a lease through a rollback deliberately, because
    /// clearing one would rob a commit still in flight of its exclusivity.  A
    /// process that has just started has no commit in flight, so here that
    /// caution only leaves the Realm unable to reserve -- `authority already has
    /// active intent` -- with nothing to ever clear it.
    pub async fn release_stale_commit_lease(&mut self) -> anyhow::Result<()> {
        use psy_node_core::store::authority_commit::{
            AuthorityIntentObservation, AuthorityTimestampKey, AuthorityTimestampPhase,
            AuthorityTimestampReadState, AuthorityTimestampWriteOutcome,
        };
        use psy_data::protocol::chain_context::AuthorityScope;

        let key = AuthorityTimestampKey::new(
            self.network_id,
            AuthorityScope::Realm {
                realm_id: self.state.realm_identifier.realm_id,
                realm_sub_id: self.state.realm_identifier.realm_sub_id,
            },
        );
        let AuthorityTimestampReadState::Current(state) =
            self.recording.timestamp().read_timestamp_state(key).await?
        else {
            return Ok(());
        };
        let AuthorityTimestampPhase::Active { intent } = state.phase() else {
            return Ok(());
        };
        let AuthorityIntentObservation::Active(lease) = state.observe_intent(key, intent) else {
            return Ok(());
        };
        tracing::warn!(
            "[REALM_INIT] the commit timestamp lease was still held at startup by a commit that \
             never finished; releasing it so the next commit can reserve"
        );
        let completion = state.seal_completion(key, lease)?;
        match self
            .recording
            .timestamp()
            .complete_timestamp(&completion)
            .await?
        {
            AuthorityTimestampWriteOutcome::Applied(_)
            | AuthorityTimestampWriteOutcome::Idempotent(_) => Ok(()),
            AuthorityTimestampWriteOutcome::Conflict(current) => anyhow::bail!(
                "another writer holds this Realm's commit timestamp allocator (observed \
                 revision {}); two processors are running for one Realm",
                current.revision().get()
            ),
        }
    }

    /// Truncate this Realm's cached view of the chain when the Coordinator has
    /// published a head below it.
    ///
    /// This is the check the Coordinator has had since the first rollback
    /// ([`db.rs`] `COORD_INIT`) and the Realm has not.  The Realm's own
    /// divergence detector compares its computed root against the Coordinator's
    /// **for each checkpoint it syncs**, which structurally cannot catch this
    /// case: after a rollback the Realm already holds those heights, so it never
    /// re-fetches them and the comparison never runs on the leaves that went
    /// stale.  The damage surfaces much later, as a witness the worker cannot
    /// prove -- `Wire ... was set twice with different values` -- because the
    /// witness mixes the discarded branch's leaves with the current database.
    ///
    /// Runs at startup, which is where a node that was down for the rollback
    /// gets its only chance to notice: it comes back to an Idle control row and
    /// no phase to observe, and only the published head still says where the
    /// chain is.
    pub async fn truncate_if_ahead_of_published_head(&mut self) -> anyhow::Result<()> {
        let seen = self.coordinator_chain_ref_last_synced();
        let Some(published) = self.recording.observe_published_head(&seen).await? else {
            return Ok(());
        };
        // Adopt the Coordinator's epoch before anything stamps a record with it.
        // This runs at startup and after every rollback this Realm follows, and
        // the epoch only moves at a rollback, so those are the only moments it
        // can be stale.
        self.state.coordinator_chain_epoch = published.chain_epoch().get();
        let published_height = published.checkpoint().checkpoint_id().get();
        let cached = self
            .checkpoint_tree_backup_manager
            .get_current_checkpoint_id_head();
        if cached <= published_height {
            return Ok(());
        }
        tracing::warn!(
            "[REALM_INIT] checkpoint cache is ahead of the published head ({} > {}); truncating \
             so the discarded branch is re-fetched rather than reused",
            cached,
            published_height
        );
        self.undo_everything_above(published_height).await
    }

    /// Reconcile this Realm against rollbacks it slept through.
    ///
    /// The height check next to this one only sees a rollback the Realm comes
    /// back to immediately: once the Coordinator has produced past the old head
    /// again the heights agree and only the contents differ, which no height
    /// comparison can detect.  The epoch can, because it advances if and only
    /// if a rollback published one and it is carried on the head the
    /// Coordinator publishes.
    ///
    /// The epoch says a rollback happened, not where the discarded branch
    /// began, so the targets come from the Coordinator's rollback history.  The
    /// lowest one across the rollbacks this Realm missed is the height above
    /// which everything it still holds belongs to a branch that no longer
    /// exists.
    ///
    /// A Realm with no recorded epoch is one that has never synced, not one at
    /// epoch zero: it has no stale cache, and truncating it would discard a
    /// chain that was never rolled back.
    pub async fn reconcile_missed_rollback_epochs(&mut self) -> anyhow::Result<()> {
        if self.recording.sync_epoch_store().is_none() {
            return Ok(());
        }
        let seen = self.coordinator_chain_ref_last_synced();
        let Some(published) = self.recording.observe_published_head(&seen).await? else {
            return Ok(());
        };
        let published_epoch = published.chain_epoch().get();
        let published_now = published.checkpoint().checkpoint_id().get();
        let recorded_epoch = {
            let store = self
                .recording
                .sync_epoch_store()
                .expect("checked above and the bundle is immutable");
            match store.read_synced_epoch().await? {
                Some(epoch) => epoch,
                None => {
                    store.write_synced_epoch(published_epoch).await?;
                    return Ok(());
                }
            }
        };
        if recorded_epoch >= published_epoch {
            return Ok(());
        }

        let targets = self
            .recording
            .rollback_targets_after(recorded_epoch)
            .await?;
        let lowest = targets.iter().map(|(_, target)| *target).min();
        tracing::warn!(
            "[REALM_INIT] this Realm last synced under epoch {} and the chain is now at {}; {} \
             rollback(s) happened while it was not watching",
            recorded_epoch,
            published_epoch,
            targets.len()
        );
        match lowest {
            // Bounded by the Coordinator's published head rather than by
            // anything of this Realm's, because the step that follows truncates
            // this Realm's caches and a bound taken from them would already be
            // wrong by the time it was used.
            Some(target) => {
                // `recorded_epoch` is the branch this Realm's own state was
                // committed under -- the one it last synced with, before the
                // rollbacks it missed. Its manifests live in that partition and
                // nowhere else.
                self.undo_everything_above_bounded(
                    target,
                    Some(published_now),
                    Some(recorded_epoch),
                )
                .await?
            }
            None => {
                // The epoch moved but no rollback recorded a target for it.
                // Refusing is the safe direction: the alternative is to carry on
                // with a cache whose provenance cannot be established, and the
                // damage from that surfaces as an unprovable witness long after
                // the cause.
                anyhow::bail!(
                    "the chain advanced from epoch {} to {} with no recorded rollback target; \
                     this Realm cannot establish which of its cached checkpoints are still real",
                    recorded_epoch,
                    published_epoch
                );
            }
        }
        // Written after the truncation, not before: a crash in between must
        // leave the Realm looking like it still has to reconcile, because it
        // does.
        self.recording
            .sync_epoch_store()
            .expect("checked above and the bundle is immutable")
            .write_synced_epoch(published_epoch)
            .await?;
        Ok(())
    }

    /// Record the epoch the chain is in now, after a rollback this Realm
    /// watched and has just undone its share of.
    pub async fn note_current_chain_epoch(&mut self) -> anyhow::Result<()> {
        let Some(store) = self.recording.sync_epoch_store() else {
            return Ok(());
        };
        let seen = self.coordinator_chain_ref_last_synced();
        let Some(published) = self.recording.observe_published_head(&seen).await? else {
            return Ok(());
        };
        store
            .write_synced_epoch(published.chain_epoch().get())
            .await
    }

    /// Bring this Realm's commit path into line with the rollback phase the
    /// Coordinator has published, and report that phase.
    ///
    /// Called at the top of the processor loop, before anything decides to sync
    /// or produce.  Freezing has to cover the sync as well as the commit: a
    /// Realm that only stopped producing would still copy the Coordinator
    /// checkpoints that are about to be discarded, and then hold a recorded
    /// coordinator height inside the range the rollback is deleting.
    ///
    /// `Ok(None)` means this Realm has no view of the control row, which is the
    /// configuration before rollback is enabled and leaves the loop as it was.
    /// Resolves when a rollback has been published, and never otherwise.
    ///
    /// Lives here, on the database handle, rather than on the processor: the
    /// waits it guards borrow other fields of the processor mutably, and a
    /// method taking `&self` on the whole processor cannot be raced against
    /// them. Both call sites want the same guard, and a guard that has to be
    /// written twice is one that drifts.
    ///
    /// Polled, because the phase lives on a durable row another process writes
    /// and there is nothing to subscribe to. Every few seconds, against waits
    /// that would otherwise run for minutes.
    ///
    /// The error is **typed**, and has to be. `is_refused_because_rollback`
    /// classifies by downcasting, not by reading the message, and the Realm's
    /// loop parks the processor in Error for anything it does not recognise. A
    /// plain `anyhow!` here would abandon the block and then stop the Realm for
    /// having abandoned it -- a correct guard killing the node, which this
    /// codebase has done five times.
    pub async fn rollback_published_while_waiting(&self) -> anyhow::Error {
        use psy_node_core::store::canonical_head::CanonicalHeadModelError;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let observed = self.follow_coordinator_rollback_phase().await;
            if let core::result::Result::Ok(core::option::Option::Some(phase)) = observed {
                if !phase.permits_commit() {
                    return anyhow::Error::new(
                        CanonicalHeadModelError::NormalAdvanceWhileRollbackActive,
                    )
                    .context(
                        "a rollback was published while this block was waiting; abandoning it so \
                         this Realm can reach the phase check and take part",
                    );
                }
            }
        }
    }

    pub async fn follow_coordinator_rollback_phase(
        &self,
    ) -> anyhow::Result<Option<psy_node_core::store::rollback_coordination::ObservedRollbackPhase>>
    {
        let seen = self.coordinator_chain_ref_last_synced();
        self.recording.follow_published_phase(&seen).await
    }

    /// The highest Coordinator checkpoint this Realm has seen.
    ///
    /// The higher of the in-memory sync marker and the checkpoint cache, because
    /// the two are current at different times: at startup the marker is still
    /// zero and only the cache, loaded from its backup file, knows where the
    /// Realm had got to.  Taking the marker alone made the reconciliation at
    /// init search an empty range and conclude there was nothing of its own to
    /// undo -- for a Realm holding real transactions, the opposite of the truth.
    ///
    /// Only the network is read from it by the control-row queries; the height
    /// bounds how far the Realm's own manifest is searched.  Built from what
    /// this Realm has seen rather than from something it assumed, so a wrong
    /// value here can never be mistaken for evidence.
    fn coordinator_chain_ref_last_synced(
        &self,
    ) -> psy_data::protocol::canonical_chain::CanonicalChainRef<N::QHash> {
        use psy_data::protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
        };
        let seen = self
            .state
            .coordinator_head_synced_checkpoint_id
            .max(self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head());
        CanonicalChainRef::new(
            self.network_id,
            ChainEpoch::new(self.state.coordinator_chain_epoch),
            CheckpointRef::new(
                CheckpointId::new(seen),
                CheckpointHash::from_last_chain_hash(
                    self.state.coordinator_head_synced_checkpoint_root,
                ),
            ),
        )
    }

    pub async fn sync_with_coordinator(&mut self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let last_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        
        if coordinator_latest_checkpoint_id < last_synced_checkpoint_id {
            anyhow::bail!("Local checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency.",
                last_synced_checkpoint_id, coordinator_latest_checkpoint_id);
        }
        
        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;
            
        self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.processing_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.gathering_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.processing_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;

        Ok(())
    }

    pub async fn wait_for_realm_update_sync_with_coordinator(
        &mut self,
        new_realm_root: N::QHash,
    ) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        let old_realm_root = self.state.last_committed_realm_end_root;
        let start_wait_checkpoint = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();

        tracing::info!(
            "Waiting for Coordinator to include New Realm Root: {:?}. (Current/Old Root: {:?}). Starting watch at Checkpoint {}.",
            new_realm_root, old_realm_root, start_wait_checkpoint
        );

        loop {
            // 1. Sync Checkpoint Tree to get latest proofs locally
            self.checkpoint_tree_backup_manager
                .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
                .await?;

            let latest_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();

            // 2. Query Coordinator for the Realm's state at the absolute Tip
            // We use `latest_synced_checkpoint_id` to get the latest state available to us.
            let realm_state = self.coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(latest_synced_checkpoint_id, self.state.realm_id_u64)
                .await?;
            tracing::info!("realm state {}", serde_json::to_string_pretty(&realm_state)?);

            // 3. Evaluate State
            if realm_state.value == new_realm_root {
                tracing::info!(
                    "Confirmed: Realm updated to {:?} at Checkpoint {}.",
                    new_realm_root, realm_state.checkpoint_id
                );

                let (previous_l2_checkpoint_id, previous_l2_info) = self
                    .get_latest_available_l2_block_state(self.state.last_committed_checkpoint_id)
                    .await?;
                if previous_l2_checkpoint_id != self.state.last_committed_checkpoint_id {
                    tracing::warn!(
                        "No L2 block state for last_committed_checkpoint_id {}. Backfilling metadata from checkpoint {}.",
                        self.state.last_committed_checkpoint_id,
                        previous_l2_checkpoint_id.saturating_add(1)
                    );
                }
                let metadata_from_checkpoint_id = previous_l2_checkpoint_id.saturating_add(1);
                let sync_info = match self
                    .persist_checkpoint_metadata_range(
                        metadata_from_checkpoint_id,
                        realm_state.checkpoint_id,
                        previous_l2_checkpoint_id,
                    )
                    .await?
                {
                    Some(sync_info) => sync_info,
                    None => self
                        .coordinator_client
                        .rc_get_realm_sync_info(realm_state.checkpoint_id, self.state.realm_id_u64)
                        .await?,
                };

                // Update mappings for the unique pending ID
                self.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
                    self.state.processing_unique_pending_id,
                    &sync_info.reward_tree_top_proof,
                ).await?;

                self.sync_contract_heights(
                    previous_l2_info.next_contract_id,
                    sync_info.checkpoint_sync_info.block_state.next_contract_id,
                    realm_state.checkpoint_id,
                )
                .await?;

                // NOTE: intentionally do NOT advance the `latest_l2_block_state` singleton here. The caller
                // (`process_block`) runs `commit_state` right after this returns, and the local tree/user/contract
                // state is only durably committed there. `commit_state` advances the singleton as its final step
                // (after `set_latest_checkpoint_id`). Advancing it here would expose, via the
                // `get_latest_l2_block_state` RPC, a latest checkpoint whose dependent state is not yet committed.

                // Update In-Memory State for the commit
                self.state.last_committed_checkpoint_id = realm_state.checkpoint_id;
                self.state.last_committed_realm_end_root = realm_state.value;
                self.state.last_committed_proc_checkpoint_unique_id = self.state.processing_proc_checkpoint_unique_id;
                self.state.last_committed_unique_pending_id = self.state.processing_unique_pending_id;

                return Ok(sync_info);

            } else if realm_state.value == old_realm_root {
                // Case: The coordinator is processing other things. Our update is pending.
                // Action: Wait patiently.
                tracing::debug!(
                    "Waiting... Latest Checkpoint: {}. Realm Root still old ({:?}).", 
                    latest_synced_checkpoint_id, old_realm_root
                );
                
                // Sleep via client wait
                self.coordinator_client.rc_wait_for_next_checkpoint().await?;
                
            } else {
                // Case: The root changed to something else entirely.
                // This implies a race condition (someone else updated the realm) or a reorg.
                // Our calculated proof is now invalid. We must abort.
                // A rollback is the expected cause, and it is not a fault: it
                // moves the Realm root back to the target's, which is neither
                // end of the transition this update is proving.  A genuine race
                // -- two writers for one Realm -- produces the same reading, so
                // this stays loud; what changed is that it no longer kills the
                // node, because the next iteration re-derives from whatever the
                // rollback left.
                tracing::error!(
                    "Realm state diverged: expected transition {:?} -> {:?}, found root {:?} at \
                     checkpoint {}; abandoning this block",
                    old_realm_root,
                    new_realm_root,
                    realm_state.value,
                    realm_state.checkpoint_id
                );
                return Err(anyhow::Error::new(
                    psy_node_core::store::rollback_coordination::RealmRootMovedUnderUs,
                ));
            }
        }
    }

    // --- Helper Functions ---

    /// Walk backwards from `checkpoint_id` to the most recent checkpoint whose metadata is *fully* persisted.
    /// Completeness is judged by `try_get_complete_l2_block_state`, which requires all per-checkpoint dependency
    /// records to be present (L2 block state, global state roots, checkpoint leaf, checkpoint root->id mapping, and
    /// global-user-tree top proof) — so this does not depend on any single record's write order and detects
    /// partially-written checkpoints left by either the old or new ordering. We only treat a `None` (genuinely
    /// incomplete checkpoint) as a reason to roll back; any real DB/IO/deserialization error is propagated so we
    /// never silently regress the checkpoint marker over transient or corruption failures.
    async fn get_latest_available_l2_block_state(&self, checkpoint_id: u64) -> anyhow::Result<(u64, QEDL2BlockState)> {
        let mut candidate_checkpoint_id = checkpoint_id;
        loop {
            match self.db.try_get_complete_l2_block_state(candidate_checkpoint_id).await? {
                Some(info) => return Ok((candidate_checkpoint_id, info)),
                None if candidate_checkpoint_id > 0 => {
                    candidate_checkpoint_id -= 1;
                }
                None => {
                    anyhow::bail!(
                        "No complete checkpoint metadata found at or below checkpoint {}; database has no usable checkpoint metadata.",
                        checkpoint_id
                    );
                }
            }
        }
    }

    async fn persist_checkpoint_metadata_range(
        &mut self,
        from_checkpoint_id: u64,
        to_checkpoint_id: u64,
        reset_checkpoint_id: u64,
    ) -> anyhow::Result<Option<PsyRealmCoordinatorUpdate<N::F, N::QHash>>> {
        if from_checkpoint_id > to_checkpoint_id {
            return Ok(None);
        }

        let mut latest_sync_info = None;
        for checkpoint_id in from_checkpoint_id..=to_checkpoint_id {
            let sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> = self
                .coordinator_client
                .rc_get_realm_sync_info(checkpoint_id, self.state.realm_id_u64)
                .await?;

            // CRITICAL VALIDATION: Ensure the local in-memory tree matches the Coordinator's canonical root for this checkpoint.
            // If we have diverged (e.g. bad leaves or fork), we must reset the Backup Manager.
            // We retrieve the proof for the leaf at `checkpoint_id`. The `get_append_root` from that proof
            // represents the root of the tree at the moment that leaf was the right-most element (i.e., at that checkpoint).
            let local_proof = self.checkpoint_tree_backup_manager.checkpoint_tree.get_leaf(checkpoint_id);
            let local_calculated_root = local_proof.get_append_root::<N::HasherBase>();

            if local_calculated_root != sync_info.checkpoint_sync_info.checkpoint_tree_root {
                tracing::error!(
                    "CRITICAL CHECKSUM MISMATCH: Local Checkpoint Tree Root {:?} != Coordinator Root {:?} at Checkpoint {}. Triggering Backup Manager Hard Reset.",
                    local_calculated_root,
                    sync_info.checkpoint_sync_info.checkpoint_tree_root,
                    checkpoint_id
                );

                // Reset the backup manager to the last known committed state in the DB to clear invalid in-memory state.
                self.checkpoint_tree_backup_manager
                    .hard_reset_and_truncate(reset_checkpoint_id)
                    .await?;

                anyhow::bail!("Checkpoint Tree Divergence detected at checkpoint {}. Local state reset. Please retry sync.", checkpoint_id);
            }

            tracing::info!(
                "sync checkpoint metadata: checkpoint_id={}, checkpoint_tree_root={:?}, block_state_checkpoint_id={}",
                checkpoint_id,
                sync_info.checkpoint_sync_info.checkpoint_tree_root,
                sync_info.checkpoint_sync_info.block_state.checkpoint_id
            );
            // ORDERING IS LOAD-BEARING: these writes are not transactional, so a crash between them can leave a
            // checkpoint half-written. Recovery (`try_get_complete_l2_block_state`) requires all dependency records,
            // and the L2 block state is written LAST so that its presence implies every other record was already
            // written. Writing it earlier would let a crash after the block state but before the roots/leaf/proofs
            // leave a checkpoint that recovery believes is complete and never re-syncs.
            tracing::debug!(
                "set checkpoint global state roots {} {:?}",
                checkpoint_id,
                sync_info.checkpoint_sync_info.state_roots
            );
            self.db
                .set_checkpoint_global_state_roots(checkpoint_id, &sync_info.checkpoint_sync_info.state_roots)
                .await?;
            self.db
                .set_checkpoint_leaf_data(checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf)
                .await?;
            tracing::debug!(
                "committing checkpoint proof: {:?}",
                &local_proof.to_append_proof::<N::HasherBase>()
            );

            self.db
                .checkpoint_tree_injest_merkle_proof(checkpoint_id, &local_proof.to_append_proof::<N::HasherBase>())
                .await?;
            self.db
                .set_checkpoint_root_hash_to_id_mapping(
                    sync_info.checkpoint_sync_info.checkpoint_tree_root,
                    sync_info.checkpoint_sync_info.checkpoint_id,
                )
                .await?;

            self.db
                .global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &sync_info.merkle_proof_to_realm_root)
                .await?;

            // Sentinel write — must remain the final persisted metadata for this checkpoint (see note above).
            self.db
                .set_l2_block_state(checkpoint_id, &sync_info.checkpoint_sync_info.block_state)
                .await?;

            latest_sync_info = Some(sync_info);
        }

        Ok(latest_sync_info)
    }

    async fn sync_contract_heights(&self, start_id: u32, end_id: u32, checkpoint_id: u64) -> anyhow::Result<()> {
        if start_id == end_id {
            return Ok(());
        }
        if start_id > end_id {
            // A regressing next_contract_id is never expected: contract ids are monotonic, so local > remote
            // means local state leads the coordinator (reorg, fork, or DB inconsistency). Silently returning here
            // would advance the checkpoint marker while keeping stale, too-high contract heights in the DB. Fail
            // loudly so the inconsistency surfaces and triggers recovery instead of being baked into committed state.
            anyhow::bail!(
                "next_contract_id regressed (local={}, remote={}, checkpoint={}); local contract state leads the coordinator. \
                 Refusing to advance with stale contract heights — manual/recovery intervention required.",
                start_id,
                end_id,
                checkpoint_id
            );
        }

        tracing::info!(
            "Syncing contract heights: local={}, remote={}, checkpoint={}",
            start_id,
            end_id,
            checkpoint_id
        );

        let batch_size = 1000u32;
        let diff = end_id - start_id;
        let full_batches = diff / batch_size;
        let remainder = diff % batch_size;

        for i in 0..full_batches {
            let s = start_id + i * batch_size;
            let e = s + batch_size;
            self.fetch_and_set_contract_heights(s, e, checkpoint_id).await?;
        }
        if remainder > 0 {
            let s = start_id + full_batches * batch_size;
            let e = s + remainder;
            self.fetch_and_set_contract_heights(s, e, checkpoint_id).await?;
        }
        Ok(())
    }

    async fn fetch_and_set_contract_heights(&self, start_id: u32, end_id: u32, checkpoint_id: u64) -> anyhow::Result<()> {
        let ids: Vec<u64> = (start_id..end_id).map(|x| x as u64).collect();
        let heights = self.coordinator_client.rc_get_contract_tree_state_heights(checkpoint_id, ids.clone()).await?;
        // `zip` would silently drop trailing contract ids if the coordinator returned fewer heights, leaving
        // those contracts unset. Fail loudly instead so a truncated/mismatched response cannot corrupt state.
        if heights.len() != ids.len() {
            anyhow::bail!(
                "Contract height count mismatch at checkpoint {}: requested {} ids ({}..{}), got {} heights",
                checkpoint_id,
                ids.len(),
                start_id,
                end_id,
                heights.len()
            );
        }
        let mapping: Vec<(u64, u8)> = ids.into_iter().zip(heights.into_iter()).collect();
        self.db.set_contract_tree_heights(checkpoint_id, &mapping).await?;
        Ok(())
    }
}
