use std::collections::HashSet;

use anyhow::{Context, Ok};
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash},
    },
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
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
        PsyRealmProcessorStore,
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

async fn write_checkpoint_state_records<N, S>(
    db: &S,
    checkpoint_sync_info: &PQEDCheckpointSyncInfoCompact<N::F, N::QHash>,
    membership: &MerkleProofCore<N::QHash>,
) -> anyhow::Result<()>
where
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
{
    // ORDERING IS LOAD-BEARING: these writes are not transactional. Recovery
    // (`get_latest_available_l2_block_state` / `try_get_complete_l2_block_state`) treats a checkpoint as
    // complete based on its core metadata records, so the L2 block state MUST be written LAST — after the
    // state roots, checkpoint leaf, tree proof, and root mapping. Writing it earlier would let a crash mid-way
    // leave a checkpoint that looks complete (L2 present) but is missing its proof/root mapping, which recovery
    // would then never backfill. The `latest_l2_block_state` singleton is advanced by the caller
    // (`apply_prepared_realm_checkpoint`) only after `set_latest_checkpoint_id`, so it can never lead the committed marker.
    db.set_checkpoint_global_state_roots(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.state_roots)
        .await?;
    db.set_checkpoint_leaf_data(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.checkpoint_leaf)
        .await?;
    db.checkpoint_tree_injest_merkle_proof(checkpoint_sync_info.checkpoint_id, membership)
        .await?;
    db.set_checkpoint_root_hash_to_id_mapping(checkpoint_sync_info.checkpoint_tree_root, checkpoint_sync_info.checkpoint_id)
        .await?;
    db.set_l2_block_state(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.block_state)
        .await?;
    Ok(())
}

async fn apply_realm_ffs_updates<N, S>(
    db: &S,
    checkpoint_id: u64,
    realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
) -> anyhow::Result<()>
where
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
{
    if realm_update.update_user_leaves_ffs.is_empty() {
        return Ok(());
    }
    db.set_user_leaves_ffs(checkpoint_id, &realm_update.update_user_leaves_ffs)
        .await?;
    db.contract_state_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_contract_state_tree_nodes_ffs)
        .await?;
    if !realm_update.update_contract_state_imt_leaves_ffs.is_empty() {
        db.contract_state_imt_set_leaves_ffs(checkpoint_id, &realm_update.update_contract_state_imt_leaves_ffs)
            .await?;
    }
    db.user_contract_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_user_contract_tree_nodes_ffs)
        .await?;
    db.global_user_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_global_user_tree_nodes_ffs)
        .await?;
    Ok(())
}

pub(crate) async fn apply_prepared_realm_checkpoint<N, S>(
    db: &S,
    coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
    unique_pending_id: u64,
    proc_id: &QCoreProcCheckpointUniqueId,
    membership: &MerkleProofCore<N::QHash>,
) -> anyhow::Result<()>
where
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
{
    let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
    db.set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
        .await?;
    db.set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, proc_id)
        .await?;
    db.global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &coordinator_update.merkle_proof_to_realm_root)
        .await?;
    db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(
        unique_pending_id,
        &coordinator_update.reward_tree_top_proof,
    )
    .await?;
    write_checkpoint_state_records::<N, S>(db, &coordinator_update.checkpoint_sync_info, membership).await?;
    let changed_leaves_on_imt_indexed_trees = if checkpoint_id == 0 {
        HashSet::new()
    } else {
        crate::realm::processor::db::load_changed_leaves_on_imt_indexed_trees::<S, N::F, N::QHash>(db, realm_update)
            .await?
    };
    crate::realm::processor::db::require_state_update_record_coverage(realm_update, checkpoint_id, &changed_leaves_on_imt_indexed_trees)?;
    apply_realm_ffs_updates::<N, S>(db, checkpoint_id, realm_update).await?;
    let durable_tip = db.get_latest_checkpoint_id().await?;
    if checkpoint_id >= durable_tip {
        db.set_latest_checkpoint_id(checkpoint_id).await?;
        db.set_l2_latest_block_state(&coordinator_update.checkpoint_sync_info.block_state)
            .await?;
    }
    Ok(())
}

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
    N::HasherBase: 'static + Send + Sync + MerkleZeroHasher<N::QHash> + FieldQHasher<N::F, N::QHash>,
{
    pub async fn set_new_unique_ids(&mut self, gathering_realm_end_root: Option<N::QHash>) -> anyhow::Result<()> {
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
            self.state.gathering_checkpoint_id,
            self.state.gathering_checkpoint_root,
            new_gathering_unique_pending_id,
            new_gathering_proc_checkpoint_unique_id,
        )?;
        self.shared_state.update_from_core_state(&self.state).await?;

        self.temp_db
            .set_gathering_generation(
                &self.state.realm_identifier,
                psy_node_core::psy_temp_db::GatheringGeneration {
                    checkpoint_id: self.state.gathering_checkpoint_id,
                    unique_pending_id: self.state.gathering_unique_pending_id,
                    proc_checkpoint_unique_id: self.state.gathering_proc_checkpoint_unique_id,
                },
            )
            .await?;
        self.temp_db
            .set_unique_pending_ids(
                &self.state.realm_identifier,
                self.state.processing_unique_pending_id,
                self.state.processing_proc_checkpoint_unique_id,
            )
            .await?;


        Ok(())
    }

    pub async fn commit_state(
        &mut self,
        coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
        _state_transition_circuit_type: ProvingJobCircuitType,
        _zk_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
        let leaf_hash = coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash;
        let tree_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        let membership = if checkpoint_id == 0 {
            let siblings = (0..N::CHECKPOINT_TREE_HEIGHT as usize)
                .map(|level| N::HasherBase::get_zero_hash(level))
                .collect();
            MerkleProofCore::new_from_params::<N::HasherBase>(0, leaf_hash, siblings)
        } else {
            self.coordinator_client
                .rc_get_checkpoint_tree_merkle_proof(checkpoint_id)
                .await
                .context(format!(
                    "MissingHistoryProof at C={checkpoint_id}: checkpoint tree membership unavailable"
                ))?
        };
        anyhow::ensure!(
            membership.verify::<N::HasherBase>(),
            "MissingHistoryProof at C={checkpoint_id}: checkpoint membership does not verify"
        );
        anyhow::ensure!(
            membership.index == checkpoint_id,
            "MissingHistoryProof at C={checkpoint_id}: membership index {} is not C",
            membership.index
        );
        anyhow::ensure!(
            membership.siblings.len() == N::CHECKPOINT_TREE_HEIGHT as usize,
            "MissingHistoryProof at C={checkpoint_id}: membership height {} is not {}",
            membership.siblings.len(),
            N::CHECKPOINT_TREE_HEIGHT
        );
        anyhow::ensure!(
            membership.value == leaf_hash,
            "MissingHistoryProof at C={checkpoint_id}: membership value does not match checkpoint leaf hash"
        );
        anyhow::ensure!(
            membership.root == tree_root,
            "MissingHistoryProof at C={checkpoint_id}: membership root does not match trusted C after-root"
        );
        let trusted_previous_root = if checkpoint_id == 0 {
            N::HasherBase::get_zero_hash(N::CHECKPOINT_TREE_HEIGHT as usize)
        } else {
            self.db
                .checkpoint_tree_get_root_hash(checkpoint_id - 1)
                .await
                .context(format!(
                    "MissingHistoryProof at C={checkpoint_id}: trusted C-1 checkpoint root read failed"
                ))?
        };
        anyhow::ensure!(
            membership.compute_root_with_value::<N::HasherBase>(N::QHash::get_zero_value())
                == trusted_previous_root,
            "MissingHistoryProof at C={checkpoint_id}: empty-leaf root does not match trusted C-1 root"
        );
        coordinator_update
            .checkpoint_sync_info
            .ensure_valid::<N::HasherBase>(&membership.siblings)?;

        let unique_pending_id = self.state.processing_unique_pending_id;
        apply_prepared_realm_checkpoint::<N, S>(
            self.db.as_ref(),
            coordinator_update,
            realm_update,
            unique_pending_id,
            &self.state.processing_proc_checkpoint_unique_id,
            &membership,
        )
        .await?;
        tracing::info!("Set unique pending ID to checkpoint ID mapping for checkpoint ID: {}", checkpoint_id);
        let previous_checkpoint_id = self.state.last_committed_checkpoint_id;
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
        self.state.processing_checkpoint_id = checkpoint_id;
        self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;
        self.state.processing_realm_start_root = realm_update.old_realm_root;
        self.state.processing_realm_end_root = realm_update.new_realm_root;
        self.state.commit_processing()?;
        self.shared_state.update_from_core_state(&self.state).await?;
        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore;
    use parth_common::memory_stores::traits::PsyMemoryMerkleStoreImm;
    use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
    use parth_core::crypto::hash::traits::{FromU64x4, MerkleZeroHasher, ZeroableHash};
    use parth_core::pgoldilocks::PoseidonHasher;
    use parth_core::PHash;

    #[test]
    fn tip_empty_append_proof_is_not_historical_membership() {
        let tree = PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(8);
        tree.set_leaf(0, PHash::from_u64x4([1, 0, 0, 0]));
        let tip_empty_append = tree.get_leaf(1).to_append_proof::<PoseidonHasher>();
        tree.set_leaf(1, PHash::from_u64x4([2, 0, 0, 0]));
        tree.set_leaf(2, PHash::from_u64x4([3, 0, 0, 0]));
        let historical = tree.get_historical_merkle_proof_at_historical_index(1, 1);
        assert_ne!(
            tip_empty_append.value, historical.value,
            "commit must not persist get_leaf(C).to_append_proof() taken before the leaf is set"
        );
        assert!(historical.verify::<PoseidonHasher>());
        assert_eq!(historical.index, 1);
        assert_eq!(
            historical.compute_root_with_value::<PoseidonHasher>(PHash::get_zero_value()),
            tree.get_historical_merkle_proof_at_historical_index(0, 0).root
        );
    }

    #[test]
    fn genesis_setup_membership_has_no_predecessor() {
        let height = 8usize;
        let leaf = PHash::from_u64x4([9, 0, 0, 0]);
        let siblings = (0..height)
            .map(|level| PoseidonHasher::get_zero_hash(level))
            .collect();
        let membership = MerkleProofCore::new_from_params::<PoseidonHasher>(0, leaf, siblings);
        assert!(membership.verify::<PoseidonHasher>());
        assert_eq!(membership.index, 0);
        assert_eq!(
            membership.compute_root_with_value::<PoseidonHasher>(PHash::get_zero_value()),
            PoseidonHasher::get_zero_hash(height)
        );
    }
}
