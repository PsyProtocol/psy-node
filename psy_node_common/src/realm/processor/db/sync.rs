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
    pub async fn follow_coordinator_rollback_phase(
        &self,
    ) -> anyhow::Result<Option<psy_node_core::store::rollback_coordination::ObservedRollbackPhase>>
    {
        use psy_data::protocol::canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef,
        };
        // Only the network is read from this; the phase lives on the
        // Coordinator's control row, not in the coordinate we pass in.  Built
        // from the last head this Realm actually synced so that the value is one
        // it has seen rather than one it assumed.
        let seen = CanonicalChainRef::new(
            self.network_id,
            ChainEpoch::new(0),
            CheckpointRef::new(
                CheckpointId::new(self.state.coordinator_head_synced_checkpoint_id),
                CheckpointHash::from_last_chain_hash(
                    self.state.coordinator_head_synced_checkpoint_root,
                ),
            ),
        );
        self.recording.follow_published_phase(&seen).await
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
                anyhow::bail!(
                    "CRITICAL: Realm state diverged! Expected transition {:?} -> {:?}, but found root {:?} at Checkpoint {}. Aborting.",
                    old_realm_root, new_realm_root, realm_state.value, realm_state.checkpoint_id
                );
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
