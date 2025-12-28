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

        let latest_db_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        let latest_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let latest_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

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

        let latest_db_l2_info: QEDL2BlockState = self.db.get_l2_block_state(latest_db_checkpoint_id).await?;

        // 2. Fetch and persist metadata for missing checkpoints
        for checkpoint_id in (latest_db_checkpoint_id + 1)..=latest_synced_checkpoint_id {
            let sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> = self.coordinator_client.rc_get_realm_sync_info(checkpoint_id, self.state.realm_id_u64).await?;
            

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
                
                // Reset the backup manager to the last known committed state in the DB to clear invalid in-memory state
                self.checkpoint_tree_backup_manager.hard_reset_and_truncate(latest_db_checkpoint_id).await?;
                
                anyhow::bail!("Checkpoint Tree Divergence detected at checkpoint {}. Local state reset. Please retry sync.", checkpoint_id);
            }

            tracing::info!("sync checkpoint id {} {}", checkpoint_id, serde_json::to_string_pretty(&sync_info)?);
            self.db
                .set_l2_block_state(checkpoint_id, &sync_info.checkpoint_sync_info.block_state)
                .await?;
            tracing::info!("set checkpoint global state roots {} {}", checkpoint_id, serde_json::to_string_pretty(&sync_info.checkpoint_sync_info.state_roots)?);
            self.db
                .set_checkpoint_global_state_roots(checkpoint_id, &sync_info.checkpoint_sync_info.state_roots)
                .await?;
            tracing::info!("get checkpoint global state roots {} {}", checkpoint_id, serde_json::to_string_pretty(&self.db.get_checkpoint_global_state_roots(checkpoint_id).await?)?);
            self.db
                .set_checkpoint_leaf_data(checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf)
                .await?;
                    println!("committing checkpoint proof: {:?}", &local_proof.to_append_proof::<N::HasherBase>());

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
        }

        // 3. Update Latest Block State
        let latest_sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> =
            self.coordinator_client.rc_get_realm_sync_info(latest_synced_checkpoint_id, self.state.realm_id_u64).await?;
        
        self.db
            .set_l2_latest_block_state(&latest_sync_info.checkpoint_sync_info.block_state)
            .await?;

        // 4. Sync Contract Heights
        if latest_db_l2_info.next_contract_id != latest_sync_info.checkpoint_sync_info.block_state.next_contract_id {
            tracing::info!(
                "Syncing contract heights: local={}, remote={}", 
                latest_db_l2_info.next_contract_id, 
                latest_sync_info.checkpoint_sync_info.block_state.next_contract_id
            );
            self.sync_contract_heights(
                latest_db_l2_info.next_contract_id,
                latest_sync_info.checkpoint_sync_info.block_state.next_contract_id,
                latest_synced_checkpoint_id
            ).await?;
        }

        // 5. Update Mappings
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(self.state.processing_unique_pending_id, latest_synced_checkpoint_id)
            .await?;
        self.db
            .set_checkpoint_id_to_unique_pending_id_mapping(
                latest_synced_checkpoint_id,
                self.state.processing_unique_pending_id,
                &self.state.processing_proc_checkpoint_unique_id,
            )
            .await?;
        self.db.set_latest_checkpoint_id(latest_synced_checkpoint_id).await?;

        // 6. CRITICAL: Update Internal Memory State to match the new HEAD
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

                // Fetch the full block info for the *specific* checkpoint where the update happened
                let sync_info: PsyRealmCoordinatorUpdate<N::F, N::QHash> =
                    self.coordinator_client.rc_get_realm_sync_info(realm_state.checkpoint_id, self.state.realm_id_u64).await?;

                // Persist auxiliary proofs to DB
                self.db.set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(realm_state.checkpoint_id, &sync_info.reward_tree_top_proof).await?;
                tracing::info!("set global user tree top tree merkle proof at checkpoint id {} {}", realm_state.checkpoint_id, serde_json::to_string_pretty(&sync_info.merkle_proof_to_realm_root)?);
                self.db.global_user_tree_set_top_tree_merkle_proof(realm_state.checkpoint_id, &sync_info.merkle_proof_to_realm_root).await?;
                
                // Update mappings for the unique pending ID
                self.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
                    self.state.processing_unique_pending_id,
                    &sync_info.reward_tree_top_proof,
                ).await?;

                // Set Block/State Info
                self.db.set_l2_block_state(realm_state.checkpoint_id, &sync_info.checkpoint_sync_info.block_state).await?;
                self.db.set_l2_latest_block_state(&sync_info.checkpoint_sync_info.block_state).await?;
                self.db.set_checkpoint_global_state_roots(realm_state.checkpoint_id, &sync_info.checkpoint_sync_info.state_roots).await?;
                self.db.set_checkpoint_leaf_data(realm_state.checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf).await?;

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

    async fn sync_contract_heights(&self, start_id: u32, end_id: u32, checkpoint_id: u64) -> anyhow::Result<()> {
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
        let mapping: Vec<(u64, u8)> = ids.into_iter().zip(heights.into_iter()).collect();
        self.db.set_contract_tree_heights(checkpoint_id, &mapping).await?;
        Ok(())
    }
}
