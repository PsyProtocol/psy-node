use anyhow::{Context, Ok};
use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
use parth_core::{
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash},
    },
    protocol::core_types::QNetworkTypesConfig,
};
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType, prepared_block::realm::PsyRealmCoordinatorUpdate,
    v1::qdata::{checkpoint::QEDL2BlockState, checkpoint_sync::PQEDCheckpointSyncInfoCompact},
};
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

use crate::realm::processor::{db::PsyRealmDatabaseProcessor, guta_resend::REALM_GUTA_RESEND_MIN_CHECKPOINTS};

fn require_checkpoint_metadata<F, Hash, H>(
    checkpoint_id: u64,
    realm_id: u64,
    checkpoint_tree_height: usize,
    coordinator_global_user_tree_height: usize,
    checkpoint_sync: &PQEDCheckpointSyncInfoCompact<F, Hash>,
    membership: &MerkleProofCore<Hash>,
    local_proof: &MerkleProofCore<Hash>,
    previous_root: Hash,
    realm_proof: &MerkleProofCore<Hash>,
) -> anyhow::Result<()>
where
    F: parth_core::felt::QFelt64,
    Hash: parth_core::protocol::core_types::QFHashBase<F>,
    H: FieldQHasher<F, Hash> + MerkleZeroHasher<Hash>,
{
    anyhow::ensure!(
        checkpoint_sync.checkpoint_id == checkpoint_id
            && checkpoint_sync.block_state.checkpoint_id == checkpoint_id,
        "MissingHistoryProof at C={checkpoint_id}: coordinator metadata checkpoint IDs do not match C"
    );
    anyhow::ensure!(
        membership.index == checkpoint_id,
        "MissingHistoryProof at C={checkpoint_id}: membership index {} is not C",
        membership.index
    );
    anyhow::ensure!(
        membership.siblings.len() == checkpoint_tree_height && membership.siblings.len() <= 64,
        "MissingHistoryProof at C={checkpoint_id}: membership height {} is not {}",
        membership.siblings.len(),
        checkpoint_tree_height
    );
    anyhow::ensure!(
        membership.value == checkpoint_sync.checkpoint_leaf_hash && membership.value == local_proof.value,
        "MissingHistoryProof at C={checkpoint_id}: membership value does not match checkpoint leaf hash"
    );
    anyhow::ensure!(
        membership.root == checkpoint_sync.checkpoint_tree_root,
        "MissingHistoryProof at C={checkpoint_id}: membership root does not match synchronized C root"
    );
    checkpoint_sync.ensure_valid::<H>(&membership.siblings)?;
    anyhow::ensure!(
        membership.compute_root_with_value::<H>(Hash::get_zero_value()) == previous_root,
        "MissingHistoryProof at C={checkpoint_id}: empty-leaf root does not match synchronized C-1 root"
    );
    anyhow::ensure!(
        realm_proof.verify::<H>(),
        "MissingHistoryProof at C={checkpoint_id}: Realm top proof does not verify"
    );
    anyhow::ensure!(
        realm_proof.index == realm_id,
        "MissingHistoryProof at C={checkpoint_id}: Realm top proof index mismatch"
    );
    anyhow::ensure!(
        realm_proof.siblings.len() == coordinator_global_user_tree_height,
        "MissingHistoryProof at C={checkpoint_id}: Realm top proof height mismatch"
    );
    anyhow::ensure!(
        realm_proof.root == checkpoint_sync.state_roots.user_tree_root,
        "MissingHistoryProof at C={checkpoint_id}: Realm top proof is not bound to C user tree root"
    );
    Ok(())
}

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
        let checkpoint_id = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        self.sync_to_coordinator_checkpoint_id(checkpoint_id).await
    }

    pub async fn sync_to_coordinator_checkpoint_id(&mut self, checkpoint_id: u64) -> anyhow::Result<()> {
        anyhow::ensure!(checkpoint_id >= self.state.last_committed_checkpoint_id,
            "metadata sync checkpoint {} precedes local committed checkpoint {}", checkpoint_id, self.state.last_committed_checkpoint_id);
        let realm_root_state = self.coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, self.state.realm_id_u64)
            .await?;
        anyhow::ensure!(realm_root_state.value == self.state.last_committed_realm_end_root,
            "checkpoint {} requires Realm state updates before metadata sync", checkpoint_id);
        anyhow::ensure!(realm_root_state.checkpoint_id <= self.state.last_committed_checkpoint_id,
            "checkpoint {} contains an unapplied Realm transition at checkpoint {}", checkpoint_id, realm_root_state.checkpoint_id);
        // 1. Sync Headers
        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;

        let mut latest_db_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let latest_synced_checkpoint_id = checkpoint_id;
        anyhow::ensure!(checkpoint_id <= self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head(),
            "checkpoint {} is not available in the synchronized checkpoint tree", checkpoint_id);
        let latest_synced_checkpoint_root = self.checkpoint_tree_backup_manager.checkpoint_tree
            .get_leaf(checkpoint_id).get_append_root::<N::HasherBase>();

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
        let latest_checkpoint_root = latest_synced_checkpoint_root;
        
        self.state.coordinator_head_synced_checkpoint_id = latest_synced_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = latest_checkpoint_root;
        self.state.processing_checkpoint_root = latest_checkpoint_root;
        self.state.gathering_checkpoint_root = latest_checkpoint_root;
        self.state.processing_checkpoint_id = latest_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = latest_synced_checkpoint_id;

        // Update the last committed markers so wait logic knows where to start looking next
        
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

        let latest_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let latest_db_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let (latest_complete_checkpoint_id, _) = self.get_latest_available_l2_block_state(latest_db_checkpoint_id).await?;
        // Metadata must precede the gathering base; realm roots and committed markers remain owned by recovery/commit.
        if latest_complete_checkpoint_id < latest_synced_checkpoint_id {
            self.persist_checkpoint_metadata_range(
                latest_complete_checkpoint_id + 1,
                latest_synced_checkpoint_id,
                latest_complete_checkpoint_id,
            )
            .await?;
        }
            
        self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.processing_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.gathering_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.processing_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;

        Ok(())
    }

    /// Waits until the Coordinator reports `new_realm_root` for this realm.
    ///
    /// A submission the Coordinator accepted can still be lost before it reaches a batch. When
    /// `resend_after_checkpoints` Coordinator checkpoints have been committed since the last
    /// attempt and the realm root is still the old one, the same header and proof are submitted
    /// again. See `guta_resend::REALM_GUTA_RESEND_MIN_CHECKPOINTS` for why resending earlier is
    /// unsafe.
    pub async fn wait_for_realm_update_sync_with_coordinator(
        &mut self,
        new_realm_root: N::QHash,
        submission_header: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<N::F, N::QHash>,
        submission_proof: &[u8],
        resend_after_checkpoints: u64,
        proposal: Option<Vec<u8>>,
        certificate: Option<Vec<u8>>,
    ) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        anyhow::ensure!(
            resend_after_checkpoints >= REALM_GUTA_RESEND_MIN_CHECKPOINTS,
            "GUTA resend threshold {} is unsafe; it must be at least {} checkpoints",
            resend_after_checkpoints,
            REALM_GUTA_RESEND_MIN_CHECKPOINTS
        );
        let old_realm_root = self.state.last_committed_realm_end_root;
        let start_wait_checkpoint = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        // Checkpoint the latest submission attempt is measured from. Taking the larger of the
        // coordinator's answer and the local head can only delay a resend.
        let mut resend_baseline_checkpoint = self
            .coordinator_client
            .rc_get_latest_checkpoint_id()
            .await?
            .max(start_wait_checkpoint);
        let mut resend_attempts: u64 = 0;

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

                if latest_synced_checkpoint_id >= resend_baseline_checkpoint.saturating_add(resend_after_checkpoints) {
                    resend_attempts += 1;
                    tracing::warn!(
                        "Realm {} GUTA update not included {} checkpoints after the last attempt (baseline {}, synced {}); resending, attempt {}. Old Root: {:?}, New Root: {:?}",
                        self.state.realm_id_u64,
                        resend_after_checkpoints,
                        resend_baseline_checkpoint,
                        latest_synced_checkpoint_id,
                        resend_attempts,
                        old_realm_root,
                        new_realm_root
                    );
                    if let Err(err) = self
                        .coordinator_client
                        .rc_submit_guta_proof(
                            submission_header,
                            submission_proof.to_vec(),
                            self.state.realm_id_u64,
                            proposal.clone(),
                            certificate.clone(),
                        )
                        .await
                    {
                        tracing::error!(
                            "Realm {} GUTA resend attempt {} failed; retrying after {} more checkpoints: {:#}",
                            self.state.realm_id_u64,
                            resend_attempts,
                            resend_after_checkpoints,
                            err
                        );
                    }
                    resend_baseline_checkpoint = self
                        .coordinator_client
                        .rc_get_latest_checkpoint_id()
                        .await?
                        .max(latest_synced_checkpoint_id);
                }

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

    pub(super) async fn persist_checkpoint_metadata_range(
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
            let membership = self
                .coordinator_client
                .rc_get_checkpoint_tree_merkle_proof(checkpoint_id)
                .await
                .with_context(|| {
                    format!("MissingHistoryProof at C={checkpoint_id}: checkpoint tree membership unavailable")
                })?;
            let checkpoint_sync = &sync_info.checkpoint_sync_info;
            let local_proof = self.checkpoint_tree_backup_manager.checkpoint_tree.get_leaf(checkpoint_id);
            let local_root = local_proof.get_append_root::<N::HasherBase>();
            if local_root != checkpoint_sync.checkpoint_tree_root {
                self.checkpoint_tree_backup_manager
                    .hard_reset_and_truncate(reset_checkpoint_id)
                    .await?;
                anyhow::bail!(
                    "Checkpoint Tree Divergence detected at checkpoint {checkpoint_id}. Local state reset. Please retry sync."
                );
            }
            let previous_root = if checkpoint_id == 0 {
                N::HasherBase::get_zero_hash(N::CHECKPOINT_TREE_HEIGHT as usize)
            } else {
                self.checkpoint_tree_backup_manager
                    .checkpoint_tree
                    .get_leaf(checkpoint_id - 1)
                    .get_append_root::<N::HasherBase>()
            };
            let realm_proof = &sync_info.merkle_proof_to_realm_root;
            require_checkpoint_metadata::<N::F, N::QHash, N::HasherBase>(
                checkpoint_id,
                self.state.realm_id_u64,
                N::CHECKPOINT_TREE_HEIGHT as usize,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as usize,
                checkpoint_sync,
                &membership,
                &local_proof,
                previous_root,
                realm_proof,
            )?;

            tracing::info!(
                "sync checkpoint metadata: checkpoint_id={}, checkpoint_tree_root={:?}, block_state_checkpoint_id={}",
                checkpoint_id,
                checkpoint_sync.checkpoint_tree_root,
                checkpoint_sync.block_state.checkpoint_id
            );
            self.db
                .set_checkpoint_global_state_roots(checkpoint_id, &checkpoint_sync.state_roots)
                .await?;
            self.db
                .set_checkpoint_leaf_data(checkpoint_id, &checkpoint_sync.checkpoint_leaf)
                .await?;
            self.db
                .checkpoint_tree_injest_merkle_proof(checkpoint_id, &membership)
                .await?;
            self.db
                .set_checkpoint_root_hash_to_id_mapping(checkpoint_sync.checkpoint_tree_root, checkpoint_id)
                .await?;

            let realm_root_proof = &sync_info.merkle_proof_to_realm_root;
            anyhow::ensure!(
                realm_root_proof.index == self.state.realm_id_u64,
                "Realm-root proof index {} does not match realm id {} at checkpoint {}",
                realm_root_proof.index,
                self.state.realm_id_u64,
                checkpoint_id
            );
            anyhow::ensure!(
                realm_root_proof.siblings.len() == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as usize,
                "Realm-root proof height {} does not match coordinator global-user-tree height {} at checkpoint {}",
                realm_root_proof.siblings.len(),
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                checkpoint_id
            );
            anyhow::ensure!(
                realm_root_proof.root == sync_info.checkpoint_sync_info.state_roots.user_tree_root,
                "Realm-root proof root does not match checkpoint user-tree root at checkpoint {}",
                checkpoint_id
            );
            let realm_root_nodes = realm_root_proof.get_all_merkle_nodes_and_verify::<N::HasherBase>()?;
            self.db
                .global_user_tree_set_nodes(checkpoint_id, &realm_root_nodes)
                .await?;
            self.db
                .global_user_tree_set_top_tree_merkle_proof(checkpoint_id, realm_root_proof)
                .await?;
            self.db
                .set_l2_block_state(checkpoint_id, &checkpoint_sync.block_state)
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

#[cfg(test)]
mod tests {
    use super::require_checkpoint_metadata;
    use parth_common::memory_stores::dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore;
    use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
    use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
    use parth_core::crypto::hash::traits::{FieldQHasher, FromU64x4, MerkleZeroHasher, QFieldHashable, ZeroableHash};
    use parth_core::pgoldilocks::PoseidonHasher;
    use parth_core::{PF, PHash};
    use psy_data::v1::qdata::checkpoint::{
        PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState,
    };
    use psy_data::v1::qdata::checkpoint_sync::PQEDCheckpointSyncInfoCompact;

    const CHECKPOINT_HEIGHT: usize = 8;
    const REALM_HEIGHT: usize = 4;
    const REALM_ID: u64 = 0;

    struct Fixture {
        checkpoint_id: u64,
        previous_root: PHash,
        local_proof: MerkleProofCore<PHash>,
        checkpoint_sync: PQEDCheckpointSyncInfoCompact<PF, PHash>,
        membership: MerkleProofCore<PHash>,
        realm_proof: MerkleProofCore<PHash>,
    }

    fn zero_siblings(height: usize) -> Vec<PHash> {
        (0..height).map(|level| PoseidonHasher::get_zero_hash(level)).collect()
    }

    fn empty_roots(user_tree_root: PHash) -> PQEDCheckpointGlobalStateRoots<PHash> {
        PQEDCheckpointGlobalStateRoots {
            contract_tree_root: PHash::get_zero_value(),
            deposit_tree_root: PHash::get_zero_value(),
            user_tree_root,
            withdrawal_tree_root: PHash::get_zero_value(),
            user_registration_tree_root: PHash::get_zero_value(),
            validator_tree_root: PHash::get_zero_value(),
        }
    }

    fn genesis_fixture() -> Fixture {
        let realm_value = PHash::from_u64x4([7, 0, 0, 0]);
        let realm_proof = MerkleProofCore::new_from_params::<PoseidonHasher>(REALM_ID, realm_value, zero_siblings(REALM_HEIGHT));
        let state_roots = empty_roots(realm_proof.root);
        let leaf = PQEDCheckpointLeaf {
            global_chain_root: state_roots.qfhash::<PoseidonHasher>(),
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        };
        let leaf_hash = leaf.qfhash::<PoseidonHasher>();
        let tree = PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(CHECKPOINT_HEIGHT as u8);
        tree.append_leaf(0, leaf_hash).unwrap();
        let local_proof = tree.get_leaf(0);
        let membership = MerkleProofCore::new_from_params::<PoseidonHasher>(0, leaf_hash, zero_siblings(CHECKPOINT_HEIGHT));
        let checkpoint_sync = PQEDCheckpointSyncInfoCompact {
            checkpoint_id: 0,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 0,
            block_state: QEDL2BlockState::get_genesis_value(),
            state_roots,
            checkpoint_leaf: leaf,
            checkpoint_leaf_hash: leaf_hash,
            checkpoint_tree_root: local_proof.get_append_root::<PoseidonHasher>(),
        };
        Fixture {
            checkpoint_id: 0,
            previous_root: PoseidonHasher::get_zero_hash(CHECKPOINT_HEIGHT),
            local_proof,
            checkpoint_sync,
            membership,
            realm_proof,
        }
    }

    fn historical_fixture() -> Fixture {
        let realm_value = PHash::from_u64x4([11, 0, 0, 0]);
        let realm_proof = MerkleProofCore::new_from_params::<PoseidonHasher>(REALM_ID, realm_value, zero_siblings(REALM_HEIGHT));
        let first_roots = empty_roots(PHash::from_u64x4([1, 0, 0, 0]));
        let first_leaf = PQEDCheckpointLeaf {
            global_chain_root: first_roots.qfhash::<PoseidonHasher>(),
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        };
        let first_hash = first_leaf.qfhash::<PoseidonHasher>();
        let second_roots = empty_roots(realm_proof.root);
        let second_leaf = PQEDCheckpointLeaf {
            global_chain_root: second_roots.qfhash::<PoseidonHasher>(),
            stats: PQEDCheckpointLeafStats::get_empty_stats(),
        };
        let second_hash = second_leaf.qfhash::<PoseidonHasher>();
        let tree = PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(CHECKPOINT_HEIGHT as u8);
        tree.append_leaf(0, first_hash).unwrap();
        let previous_root = tree.get_leaf(0).get_append_root::<PoseidonHasher>();
        tree.append_leaf(1, second_hash).unwrap();
        let local_proof = tree.get_leaf(1);
        let membership = tree.get_historical_merkle_proof_at_historical_index(1, 1);
        let checkpoint_sync = PQEDCheckpointSyncInfoCompact {
            checkpoint_id: 1,
            coordinator_id: 0,
            coordinator_sub_id: 0,
            coordinator_unique_pending_id: 0,
            block_state: QEDL2BlockState {
                checkpoint_id: 1,
                ..QEDL2BlockState::get_genesis_value()
            },
            state_roots: second_roots,
            checkpoint_leaf: second_leaf,
            checkpoint_leaf_hash: second_hash,
            checkpoint_tree_root: local_proof.get_append_root::<PoseidonHasher>(),
        };
        Fixture {
            checkpoint_id: 1,
            previous_root,
            local_proof,
            checkpoint_sync,
            membership,
            realm_proof,
        }
    }

    fn require_fixture(fixture: &Fixture) -> anyhow::Result<()> {
        require_checkpoint_metadata::<PF, PHash, PoseidonHasher>(
            fixture.checkpoint_id,
            REALM_ID,
            CHECKPOINT_HEIGHT,
            REALM_HEIGHT,
            &fixture.checkpoint_sync,
            &fixture.membership,
            &fixture.local_proof,
            fixture.previous_root,
            &fixture.realm_proof,
        )
    }

    #[test]
    fn require_checkpoint_metadata_accepts_genesis_and_historical_proofs() {
        require_fixture(&genesis_fixture()).expect("genesis metadata must authenticate");
        require_fixture(&historical_fixture()).expect("historical metadata must authenticate");
    }

    #[test]
    fn require_checkpoint_metadata_rejects_altered_bindings() {
        let mut fixture = genesis_fixture();
        fixture.checkpoint_sync.state_roots.contract_tree_root = PHash::from_u64x4([9, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.checkpoint_sync.checkpoint_leaf_hash = PHash::from_u64x4([3, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.membership.index = 1;
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.membership.value = PHash::from_u64x4([4, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.membership.root = PHash::from_u64x4([5, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.membership.siblings.push(PHash::get_zero_value());
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.previous_root = PHash::from_u64x4([6, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.local_proof.value = PHash::from_u64x4([8, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.realm_proof.index = 1;
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.realm_proof.root = PHash::from_u64x4([12, 0, 0, 0]);
        assert!(require_fixture(&fixture).is_err());

        let mut fixture = genesis_fixture();
        fixture.realm_proof.siblings.truncate(REALM_HEIGHT - 1);
        assert!(require_fixture(&fixture).is_err());
    }
}

#[cfg(test)]
mod sync_tests {
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointTreeDatabaseReader,
        PsyNodeCoreDatabaseBasicContractInfoStoreReader,
    };

    use parth_core::{utils::QPGenRandom, PHash, PF};
    use psy_data::guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType;
    use psy_node_core::p2p::traits::realm_coordinantor::RealmCoordinatorClient;

    use crate::realm::processor::db::realm_db_test_env::*;

    const TEST_RESEND_AFTER_CHECKPOINTS: u64 = 3;

    fn test_submission() -> (GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>, Vec<u8>) {
        (GlobalUserTreeAggregatorHeaderWithTagValueAndJobType::<PF, PHash>::qp_rand_gen(), vec![7u8; 48])
    }

    /// Genesis committed, ids rotated, and the coordinator reporting the realm's old root at
    /// checkpoint 0: the state a realm is in right after it submitted a GUTA proof.
    async fn env_waiting_on_old_root() -> anyhow::Result<RealmDbTestEnv> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        let old_root = env.processor.state.last_committed_realm_end_root;
        env.coordinator.seed_realm_root(0, old_root);
        Ok(env)
    }

    async fn wait_error(
        env: &mut RealmDbTestEnv,
        new_root: PHash,
        header: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
        proof: &[u8],
        resend_after_checkpoints: u64,
    ) -> String {
        match env
            .processor
            .wait_for_realm_update_sync_with_coordinator(new_root, header, proof, resend_after_checkpoints)
            .await
        {
            Err(err) => err.to_string(),
            Ok(_) => panic!("the wait was expected to fail"),
        }
    }

    #[tokio::test]
    async fn sync_to_coordinator_bails_on_fresh_database_without_metadata() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;

        let err = match env.processor.sync_to_coordinator_set_checkpoint_id().await {
            Err(err) => err,
            Ok(_) => panic!("syncing a database without any checkpoint metadata must fail"),
        };
        assert!(err.to_string().contains("No complete checkpoint metadata"), "unexpected error: {err}");
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn sync_to_coordinator_at_genesis_head_keeps_state_consistent() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.seed_consistent_coordinator_head().await?;

        env.processor.sync_to_coordinator_set_checkpoint_id().await?;

        // the coordinator sits at the same checkpoint 0 as the db
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        let state = &env.processor.state;
        assert_eq!(state.coordinator_head_synced_checkpoint_id, 0);
        assert_eq!(state.last_committed_checkpoint_id, 0);
        assert_eq!(state.processing_checkpoint_id, 0);
        assert_eq!(state.gathering_checkpoint_id, 0);
        assert_eq!(state.last_committed_checkpoint_root, state.processing_checkpoint_root);
        // realm root pointers stay aligned regardless of the early-return path
        assert_eq!(state.last_committed_realm_end_root, state.processing_realm_end_root);
        assert_eq!(state.last_committed_realm_end_root, state.gathering_realm_start_root);
        Ok(())
    }

    #[tokio::test]
    async fn sync_to_coordinator_fetches_checkpoint_one_metadata() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        env.seed_consistent_coordinator_head().await?;

        let update = env.make_checkpoint_one_update();
        let root_at_one = zh(71);
        env.seed_checkpoint_one(update.clone(), root_at_one);
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);

        env.processor.sync_to_coordinator_set_checkpoint_id().await?;

        // db advanced to checkpoint 1 with all per-checkpoint metadata
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 1);
        assert_eq!(env.db.get_l2_block_state(1).await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_latest_l2_block_state().await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_checkpoint_global_state_roots(1).await?, update.checkpoint_sync_info.state_roots);
        assert_eq!(
            env.db.get_checkpoint_id_for_checkpoint_root_hash(update.checkpoint_sync_info.checkpoint_tree_root).await?,
            Some(1)
        );
        assert_eq!(
            env.db.checkpoint_tree_get_root_hash(1).await?,
            update.checkpoint_sync_info.checkpoint_tree_root
        );

        // the new contract introduced at checkpoint 1 got its tree height fetched
        assert_eq!(env.db.get_contract_tree_heights(1, &[1]).await?, vec![8u8]);

        // in-memory state moved to the new head
        let state = &env.processor.state;
        assert_eq!(state.coordinator_head_synced_checkpoint_id, 1);
        assert_eq!(state.last_committed_checkpoint_id, 1);
        assert_eq!(state.processing_checkpoint_id, 1);
        assert_eq!(state.gathering_checkpoint_id, 1);
        assert_eq!(state.last_committed_realm_end_root, root_at_one);
        assert_eq!(state.processing_realm_start_root, root_at_one);
        assert_eq!(state.gathering_realm_start_root, root_at_one);
        assert_eq!(state.processing_checkpoint_root, state.coordinator_head_synced_checkpoint_root);
        Ok(())
    }

    #[tokio::test]
    async fn sync_with_coordinator_updates_heads_and_bails_when_local_ahead() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        env.seed_consistent_coordinator_head().await?;

        // coordinator one checkpoint ahead: heads move to 1
        let update = env.make_checkpoint_one_update();
        env.seed_checkpoint_one(update, zh(72));
        env.processor.sync_with_coordinator().await?;
        let state = &env.processor.state;
        assert_eq!(state.coordinator_head_synced_checkpoint_id, 1);
        assert_eq!(state.processing_checkpoint_id, 1);
        assert_eq!(state.gathering_checkpoint_id, 1);
        assert_eq!(state.processing_checkpoint_root, state.coordinator_head_synced_checkpoint_root);
        assert_eq!(state.gathering_checkpoint_root, state.coordinator_head_synced_checkpoint_root);

        // coordinator falling behind the local backup head is an inconsistency
        env.coordinator.set_latest_checkpoint_id(0);
        let err = match env.processor.sync_with_coordinator().await {
            Err(err) => err,
            Ok(_) => panic!("coordinator behind the local head must fail"),
        };
        assert!(err.to_string().contains("ahead of coordinator"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_waits_then_confirms() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        let old_root = env.processor.state.last_committed_realm_end_root;
        env.coordinator.seed_realm_root(0, old_root);

        // the next coordinator checkpoint carries the new realm root; it only
        // becomes visible after the realm waits for it
        let new_root = zh(73);
        let update = env.make_checkpoint_one_update();
        env.coordinator.stage_checkpoint(update.checkpoint_sync_info.checkpoint_leaf_hash, update.clone());
        env.coordinator.seed_realm_root(1, new_root);
        // latest stays 0 so the first loop iteration sees the old root

        let (header, proof) = test_submission();
        let sync_info = env
            .processor
            .wait_for_realm_update_sync_with_coordinator(new_root, header, &proof, TEST_RESEND_AFTER_CHECKPOINTS)
            .await?;

        // exactly one wait was needed before the update showed up, and nothing was resent
        assert_eq!(env.coordinator.wait_call_count(), 1);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        assert_eq!(sync_info.checkpoint_sync_info.checkpoint_id, 1);
        assert_eq!(sync_info.checkpoint_sync_info.checkpoint_tree_root, update.checkpoint_sync_info.checkpoint_tree_root);

        // metadata for checkpoint 1 was persisted...
        assert_eq!(env.db.get_l2_block_state(1).await?, update.checkpoint_sync_info.block_state);
        // ...but the checkpoint marker stays: the caller commits after the wait
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);

        let state = &env.processor.state;
        assert_eq!(state.last_committed_checkpoint_id, 1);
        assert_eq!(state.last_committed_realm_end_root, new_root);
        assert_eq!(state.last_committed_unique_pending_id, state.processing_unique_pending_id);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_bails_on_divergent_root() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        let old_root = env.processor.state.last_committed_realm_end_root;
        env.coordinator.seed_realm_root(0, old_root);

        // the coordinator reports a root that is neither the old nor the
        // expected new one: someone else updated the realm
        env.coordinator.clear_realm_roots();
        env.coordinator.seed_realm_root(0, zh(88));

        let (header, proof) = test_submission();
        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;
        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.wait_call_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_confirms_immediately_when_already_included() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        let old_root = env.processor.state.last_committed_realm_end_root;
        env.coordinator.seed_realm_root(0, old_root);

        // checkpoint 1 (with the new root) is already published
        let new_root = zh(74);
        let update = env.make_checkpoint_one_update();
        env.seed_checkpoint_one(update.clone(), new_root);

        let (header, proof) = test_submission();
        let sync_info = env
            .processor
            .wait_for_realm_update_sync_with_coordinator(new_root, header, &proof, TEST_RESEND_AFTER_CHECKPOINTS)
            .await?;

        assert_eq!(env.coordinator.wait_call_count(), 0);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        assert_eq!(sync_info.checkpoint_sync_info.checkpoint_id, 1);
        assert_eq!(env.processor.state.last_committed_realm_end_root, new_root);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_does_not_resend_before_threshold() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(2);
        env.coordinator.seed_realm_root(2, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.wait_call_count(), 2);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_measures_the_threshold_from_the_coordinator_head() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(5);
        // the coordinator is already at checkpoint 2 when the realm starts waiting, while the
        // realm's own checkpoint tree is still at 0
        env.coordinator.rc_wait_for_next_checkpoint().await?;
        env.coordinator.rc_wait_for_next_checkpoint().await?;
        env.coordinator.seed_realm_root(5, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        // counted from the realm's stale head the resend would fire at checkpoint 3; counted
        // from the coordinator's head it is due at 5, where the divergent root ends the wait
        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_resends_once_at_threshold() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(4);
        env.coordinator.seed_realm_root(4, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 1);
        assert_eq!(*env.coordinator.submitted_gutas.lock().unwrap(), vec![(TEST_REALM_ID, proof.clone())]);
        assert_eq!(*env.coordinator.submitted_guta_headers.lock().unwrap(), vec![header]);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_resends_every_threshold_checkpoints() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(7);
        env.coordinator.seed_realm_root(7, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        // resent at checkpoints 3 and 6, not at 4, 5 or 7
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 2);
        assert_eq!(*env.coordinator.submitted_guta_headers.lock().unwrap(), vec![header, header]);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_measures_the_next_resend_from_the_coordinator_head() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(9);
        // the coordinator commits checkpoints 4 and 5 while it handles the resend sent at 3
        env.coordinator.set_checkpoints_committed_during_guta_submit(2);
        env.coordinator.seed_realm_root(7, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        // counted from the head the realm had synced when it resent (3), a second resend would
        // fire at checkpoint 6; counted from the coordinator's head after the resend (5) it is
        // due at 8, and the divergent root at 7 ends the wait first
        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_never_resends_with_the_largest_threshold() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(3);
        // a non-zero baseline, so that baseline + threshold would overflow
        env.coordinator.rc_wait_for_next_checkpoint().await?;
        env.coordinator.seed_realm_root(3, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, u64::MAX).await;

        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_keeps_waiting_when_resend_fails() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.coordinator.set_fail_guta_submissions(true);
        env.stage_checkpoint_chain(7);
        env.coordinator.seed_realm_root(7, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        // the wait ended on the divergent root, not on the injected submission failure
        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.wait_call_count(), 7);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 2);
        assert!(env.coordinator.submitted_gutas.lock().unwrap().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_does_not_resend_when_diverged_at_threshold() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        env.stage_checkpoint_chain(3);
        env.coordinator.seed_realm_root(3, zh(88));

        let err = wait_error(&mut env, zh(89), header, &proof, TEST_RESEND_AFTER_CHECKPOINTS).await;

        assert!(err.contains("Realm state diverged"), "unexpected error: {err}");
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_does_not_resend_when_included_at_threshold() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        let new_root = zh(75);
        env.stage_checkpoint_chain(3);
        env.coordinator.seed_realm_root(3, new_root);

        let sync_info = env
            .processor
            .wait_for_realm_update_sync_with_coordinator(new_root, header, &proof, TEST_RESEND_AFTER_CHECKPOINTS)
            .await?;

        assert_eq!(sync_info.checkpoint_sync_info.checkpoint_id, 3);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        assert_eq!(env.processor.state.last_committed_checkpoint_id, 3);
        assert_eq!(env.processor.state.last_committed_realm_end_root, new_root);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_confirms_inclusion_after_resend() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();
        let new_root = zh(76);
        let updates = env.stage_checkpoint_chain(5);
        env.coordinator.seed_realm_root(5, new_root);

        let sync_info = env
            .processor
            .wait_for_realm_update_sync_with_coordinator(new_root, header, &proof, TEST_RESEND_AFTER_CHECKPOINTS)
            .await?;

        // resent once at checkpoint 3, included at checkpoint 5
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 1);
        assert_eq!(*env.coordinator.submitted_gutas.lock().unwrap(), vec![(TEST_REALM_ID, proof.clone())]);
        assert_eq!(sync_info.checkpoint_sync_info.checkpoint_id, 5);
        assert_eq!(env.db.get_l2_block_state(5).await?, updates[4].checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        let state = &env.processor.state;
        assert_eq!(state.last_committed_checkpoint_id, 5);
        assert_eq!(state.last_committed_realm_end_root, new_root);
        assert_eq!(state.last_committed_unique_pending_id, state.processing_unique_pending_id);
        Ok(())
    }

    #[tokio::test]
    async fn wait_for_realm_update_refuses_a_threshold_below_the_minimum() -> anyhow::Result<()> {
        let mut env = env_waiting_on_old_root().await?;
        let (header, proof) = test_submission();

        let err = wait_error(&mut env, zh(89), header, &proof, 1).await;

        assert!(err.contains("at least 2"), "unexpected error: {err}");
        assert_eq!(env.coordinator.wait_call_count(), 0);
        assert_eq!(env.coordinator.guta_submit_attempt_count(), 0);
        Ok(())
    }
}
