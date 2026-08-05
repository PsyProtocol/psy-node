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
        // Publish the complete branch + authority + pending/proc identity last.
        // Edge must consume this one value instead of composing independently
        // mutable observation and legacy pending-ID reads.
        self.publish_current_pending_context().await?;

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

    pub async fn commit_state(
        &mut self,
        coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
        _state_transition_circuit_type: ProvingJobCircuitType,
        _zk_proof: Vec<u8>,
        skip_checkpoint_root_check: bool,
    ) -> anyhow::Result<()> {
        self.validate_realm_sync_context(coordinator_update)?;
        let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
        if coordinator_update.merkle_proof_to_realm_root.value != realm_update.new_realm_root {
            anyhow::bail!(
                "REALM_AUTHORITY_OBSERVATION_ROOT_MISMATCH:checkpoint={},coordinator={:?},local={:?}",
                checkpoint_id,
                coordinator_update.merkle_proof_to_realm_root.value,
                realm_update.new_realm_root
            );
        }
        let prior_observation = self.db.get_realm_authority_observation().await?;
        let state_checkpoint_id = if checkpoint_id == 0
            || realm_update.old_realm_root != realm_update.new_realm_root
        {
            checkpoint_id
        } else {
            prior_observation
                .as_ref()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "REALM_AUTHORITY_OBSERVATION_UNINITIALIZED_FOR_UNCHANGED_STATE"
                    )
                })?
                .state_checkpoint_id()
                .get()
        };
        let unique_pending_id = self.state.processing_unique_pending_id;
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
        // Final durable publication marker for consumers.  It is written only
        // after the local state, checkpoint marker, and latest block-state
        // singleton are complete; startup/sync can safely republish it after a
        // crash in this narrow final window.
        self.publish_realm_authority_observation(
            coordinator_update.canonical_chain_ref,
            state_checkpoint_id,
            realm_update.new_realm_root,
        )
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
        tracing::info!("Committed coordinator processor state for checkpoint ID: {}", checkpoint_id);
        tracing::info!("Backed up checkpoint tree root for checkpoint ID: {}", checkpoint_id);
        self.state.commit_processing()?;
        self.shared_state.update_from_core_state(&self.state).await?;
        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);

        Ok(())
    }
}
