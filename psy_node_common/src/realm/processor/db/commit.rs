use std::collections::HashSet;

use anyhow::{Context, Ok};
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::{
        merkle_proof::MerkleProofCore,
        traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash},
    },
    protocol::core_types::QNetworkTypesConfig,
    data::queue::queue_key::QPBaseQueueType,
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

pub(crate) fn require_realm_top_proofs<N: QNetworkTypesConfig>(
    coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
    realm_id: u64,
    realm_root: N::QHash,
    reward_root: Option<N::QHash>,
) -> anyhow::Result<()> {
    let top = &coordinator_update.merkle_proof_to_realm_root;
    anyhow::ensure!(top.siblings.len() == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as usize
        && top.siblings.len() <= 64, "Realm top user proof height mismatch");
    anyhow::ensure!(top.index == realm_id && (top.siblings.len() == 64 || top.index >> top.siblings.len() == 0),
        "Realm top user proof index mismatch");
    anyhow::ensure!(top.value == realm_root, "Realm top user proof value mismatch");
    anyhow::ensure!(top.root == coordinator_update.checkpoint_sync_info.state_roots.user_tree_root
        && top.verify::<N::HasherBase>(), "Realm top user proof does not verify against checkpoint user root");
    let reward = &coordinator_update.reward_tree_top_proof;
    if reward.is_empty() {
        anyhow::ensure!(reward_root.is_none() || reward_root == Some(N::QHash::get_zero_value()),
            "Realm top reward proof missing for submitted reward root");
        return Ok(());
    }
    let mut value = reward_root.ok_or_else(|| anyhow::anyhow!("Realm top reward proof requires authenticated reward root"))?;
    anyhow::ensure!((reward.leaf.left == N::QHash::get_zero_value()
        && reward.leaf.right == N::QHash::get_zero_value() && reward.leaf.tag == N::QHash::get_zero_value())
        || reward.leaf.get_node_hash::<N::HasherBase>() == value, "Realm top reward proof leaf mismatch");
    anyhow::ensure!(reward.siblings.len() <= 64
        && (reward.siblings.len() == 64 || reward.index >> reward.siblings.len() == 0),
        "Realm top reward proof index or height mismatch");
    // The Coordinator may not retain the subtree preimage. Start at the authenticated
    // subtree commitment, rather than hashing the opaque leaf preimage.
    for (level, sibling) in reward.siblings.iter().enumerate() {
        value = if (reward.index >> level) & 1 == 0 {
            N::HasherBase::q_two_to_one(value, sibling.sibling)
        } else {
            N::HasherBase::q_two_to_one(sibling.sibling, value)
        };
        value = N::HasherBase::q_two_to_one(value, sibling.parent_tag);
    }
    anyhow::ensure!(value == reward.root
        && reward.root == coordinator_update.checkpoint_sync_info.checkpoint_leaf.stats.pm_rewards_commitment.gutas_root,
        "Realm top reward proof does not verify against checkpoint gutas root");
    Ok(())
}

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
    reward_root: Option<N::QHash>,
) -> anyhow::Result<()>
where
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
{
    let realm_root = if coordinator_update.checkpoint_sync_info.checkpoint_id == 0 {
        // The trusted Genesis bundle's prepared root uses the full global-tree root.
        coordinator_update.merkle_proof_to_realm_root.value
    } else { realm_update.new_realm_root };
    require_realm_top_proofs::<N>(coordinator_update, realm_update.realm_id, realm_root, reward_root)?;
    let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
    anyhow::ensure!(checkpoint_id == 0 || realm_update.old_realm_root == realm_update.new_realm_root
        || !coordinator_update.reward_tree_top_proof.is_empty(), "Realm transition reward proof missing");
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
        crate::realm::processor::db::load_changed_leaves_on_imt_indexed_trees::<S, N::F, N::QHash, N::HasherBase>(db, checkpoint_id - 1, realm_update)
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
        reward_root: Option<N::QHash>,
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
        anyhow::ensure!(realm_update.realm_id == self.state.realm_id_u64, "Realm commit identity mismatch");
        let reward_root = if reward_root.is_none() && !coordinator_update.reward_tree_top_proof.is_empty() {
            let root = self.tag_tree_rewards_store.rewards_tag_tree_get_root_at_unique_pending_id(unique_pending_id).await?;
            anyhow::ensure!(root != N::QHash::get_zero_value(), "Realm recovery reward root unavailable");
            Some(root)
        } else { reward_root };
        apply_prepared_realm_checkpoint::<N, S>(
            self.db.as_ref(),
            coordinator_update,
            realm_update,
            unique_pending_id,
            &self.state.processing_proc_checkpoint_unique_id,
            &membership,
            reward_root,
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

#[cfg(test)]
mod commit_tests {
    use parth_core::crypto::hash::merkle_proof::MerkleProofCore;
    use parth_core::pgoldilocks::PoseidonHasher;
    use parth_core::protocol::core_types::QNetworkTreeConstants;
    use parth_core::{PF, QCoreProcCheckpointUniqueId, PHash};
    use psy_core::job::job_id::ProvingJobCircuitType;
    use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;
    use psy_node_core::psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseReader;
    use psy_node_core::psy_temp_db::QTempDBPendingIdReader;

    use crate::realm::processor::db::realm_db_test_env::*;

    #[tokio::test]
    async fn top_proofs_reject_tampering_before_database_writes() -> anyhow::Result<()> {
        use parth_core::crypto::hash::{tag_tree::{TagTreeMerkleProof, TagTreeProofNode}, traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash}};
        use psy_data::{genesis::genesis_block_setup::GenesisValidator, p2p::{BlsSecretKey, NodeId}};
        let mut genesis_data = genesis_setup_data(1, 4);
        for position in 1..=TEST_REALM_SUB_ID {
            let seed = position as u8;
            let mut secret = [seed; 32];
            let node = NodeId::from_keypair(&libp2p_identity::Keypair::ed25519_from_bytes(&mut secret)?)?;
            genesis_data.validators.push(GenesisValidator {
                realm_id: TEST_REALM_ID as u32,
                validator_user_id: psy_core::user_id::get_user_id_from_user_registration_id(
                    position * 2 - 1, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                    N::REALM_GLOBAL_USER_TREE_HEIGHT, N::GROUP_REALM_HEIGHT),
                node_id: node.to_raw(),
                bls_public_key: BlsSecretKey::key_gen(&[seed; 32])?.public_key().to_bytes(),
            });
        }
        let env = RealmDbTestEnv::create_with_genesis_data(genesis_data).await?;
        let mut update = env.genesis.coordinator_update.clone();
        let realm_root = update.merkle_proof_to_realm_root.value;
        let reward_root = zh(91);
        let sibling = TagTreeProofNode { sibling: zh(92), parent_tag: zh(93) };
        let root = PoseidonHasher::q_two_to_one(
            PoseidonHasher::q_two_to_one(reward_root, sibling.sibling), sibling.parent_tag,
        );
        let mut reward = TagTreeMerkleProof::new_empty();
        reward.root = root;
        reward.siblings.push(sibling);
        update.reward_tree_top_proof = reward;
        update.checkpoint_sync_info.checkpoint_leaf.stats.pm_rewards_commitment.gutas_root = root;
        super::require_realm_top_proofs::<N>(&update, TEST_REALM_ID, realm_root, Some(reward_root))?;
        let membership = MerkleProofCore::new_from_params::<PoseidonHasher>(
            0, update.checkpoint_sync_info.checkpoint_leaf_hash,
            (0..N::CHECKPOINT_TREE_HEIGHT as usize).map(PoseidonHasher::get_zero_hash).collect(),
        );
        for mutation in 0..9 {
            let mut bad = update.clone();
            match mutation {
                0 => bad.merkle_proof_to_realm_root.index ^= 1,
                1 => bad.merkle_proof_to_realm_root.value = zh(99),
                2 => bad.merkle_proof_to_realm_root.siblings[0] = zh(99),
                3 => bad.merkle_proof_to_realm_root.siblings.pop().map(|_| ()).unwrap(),
                4 => bad.reward_tree_top_proof.siblings[0].sibling = zh(99),
                5 => bad.reward_tree_top_proof.siblings[0].parent_tag = zh(99),
                6 => bad.reward_tree_top_proof.root = zh(99),
                7 => bad.reward_tree_top_proof.index = 2,
                _ => bad.reward_tree_top_proof.leaf.tag = zh(99),
            }
            super::apply_prepared_realm_checkpoint::<N, _>(
                env.db.as_ref(), &bad, &env.genesis.prepared_updates, 99, &99, &membership, Some(reward_root),
            ).await.expect_err("tampered proof must fail before writes");
            assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(99).await?, None);
            assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        }
        let mut missing = update.clone();
        missing.reward_tree_top_proof = TagTreeMerkleProof::new_empty();
        assert!(super::require_realm_top_proofs::<N>(&missing, TEST_REALM_ID, realm_root, Some(reward_root)).is_err());
        assert!(super::require_realm_top_proofs::<N>(&update, TEST_REALM_ID, realm_root, None).is_err());
        assert!(super::require_realm_top_proofs::<N>(&update, TEST_REALM_ID, realm_root, Some(PHash::get_zero_value())).is_err());
        Ok(())
    }

    #[tokio::test]
    async fn set_new_unique_ids_rotates_state_and_ensures_queue_consumers() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        let rid = test_realm_identifier();

        // fresh state: everything parked at zero, so the first rotation also
        // creates the genesis (unique id 0) consumers
        assert_eq!(env.processor.state.gathering_unique_pending_id, 0);
        assert_eq!(env.processor.state.gathering_proc_checkpoint_unique_id, 0u128);

        let custom_end_root = zh(61);
        env.processor.set_new_unique_ids(Some(custom_end_root)).await?;

        // gathering moved to the freshly allocated ids, processing still at 0
        assert_eq!(env.processor.state.gathering_unique_pending_id, 1);
        assert_ne!(env.processor.state.gathering_proc_checkpoint_unique_id, 0u128);
        assert_eq!(env.processor.state.processing_unique_pending_id, 0);
        // the provided end root becomes the new gathering start root
        assert_eq!(env.processor.state.gathering_realm_start_root, custom_end_root);
        assert_eq!(env.processor.state.processing_realm_end_root, custom_end_root);

        // one consumer for the new gathering id + one for the genesis id 0
        assert_eq!(env.guta_queue.ensured_consumer_count(), 2);
        assert_eq!(env.proof_queue.ensured_consumers.lock().unwrap().len(), 2);

        // temp db mirrors the rotated ids
        let gathering = env.temp_db.get_gathering_generation(&rid).await?;
        assert_eq!(gathering.unique_pending_id, 1);
        assert_eq!(gathering.proc_checkpoint_unique_id, env.processor.state.gathering_proc_checkpoint_unique_id);
        let processing = env.temp_db.get_unique_pending_ids(&rid).await?;
        assert_eq!(processing, (0, 0u128));

        // second rotation: gathering graduates into processing, and only one
        // new consumer pair is ensured (the genesis branch no longer fires)
        env.processor.set_new_unique_ids(None).await?;
        assert_eq!(env.processor.state.gathering_unique_pending_id, 2);
        assert_ne!(env.processor.state.gathering_proc_checkpoint_unique_id, 0u128);
        assert_eq!(env.processor.state.processing_unique_pending_id, 1);
        assert_eq!(env.guta_queue.ensured_consumer_count(), 3);
        assert_eq!(env.proof_queue.ensured_consumers.lock().unwrap().len(), 3);

        // shared state wrapper stays in sync
        let shared = env.processor.shared_state.load_core_state().await?;
        assert_eq!(shared.gathering_unique_pending_id, 2);
        assert_eq!(shared.processing_unique_pending_id, 1);
        Ok(())
    }

    #[tokio::test]
    async fn commit_state_bails_on_inconsistent_checkpoint_tree_root() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;

        // tamper the checkpoint tree root so the append-root checksum fails
        let mut tampered = env.genesis.coordinator_update.clone();
        tampered.checkpoint_sync_info.checkpoint_tree_root = zh(99);

        let err = match env
            .processor
            .commit_state(&tampered, &env.genesis.prepared_updates, ProvingJobCircuitType::GUTANoChange, vec![], None)
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("tampered checkpoint tree root must fail the commit"),
        };
        assert!(err.to_string().contains("membership root does not match"), "unexpected error: {err}");

        // the checkpoint marker must NOT advance on a failed commit
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        // the pending-id mapping written up-front still points 0 -> 0
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));
        Ok(())
    }

    #[tokio::test]
    async fn commit_state_persists_records_and_advances_state() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        let update = &env.genesis.coordinator_update;

        // the l2 singleton advances together with the committed marker
        assert_eq!(env.db.get_latest_l2_block_state().await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_l2_block_state(0).await?, update.checkpoint_sync_info.block_state);

        // core state committed the processing snapshot. Note: neither the
        // state's committed root nor the per-checkpoint tree root stored in
        // the db equals the coordinator's canonical checkpoint_tree_root —
        // the canonical root is only recorded via the root -> checkpoint id
        // mapping, asserted below
        let state = &env.processor.state;
        assert_eq!(state.last_committed_checkpoint_id, 0);
        assert_ne!(state.last_committed_checkpoint_root, update.checkpoint_sync_info.checkpoint_tree_root);
        assert_eq!(
            env.db.get_checkpoint_id_for_checkpoint_root_hash(update.checkpoint_sync_info.checkpoint_tree_root).await?,
            Some(0)
        );
        assert_eq!(state.last_committed_realm_end_root, env.genesis.prepared_updates.new_realm_root);
        assert_eq!(state.last_committed_unique_pending_id, 0);
        Ok(())
    }

    /// Seeds the fake coordinator with the checkpoint-tree membership proof
    /// matching `update` (its leaf sits at index `checkpoint_id`).
    fn seed_membership(env: &RealmDbTestEnv, update: &psy_data::prepared_block::realm::PsyRealmCoordinatorUpdate<PF, PHash>) {
        let checkpoint_id = update.checkpoint_sync_info.checkpoint_id;
        let mut siblings = vec![env.genesis_leaf_hash()];
        for level in 1..N::CHECKPOINT_TREE_HEIGHT_USIZE {
            siblings.push(zh(level));
        }
        let proof = MerkleProofCore::new_from_params::<PoseidonHasher>(
            checkpoint_id,
            update.checkpoint_sync_info.checkpoint_leaf_hash,
            siblings,
        );
        env.coordinator.seed_checkpoint_tree_proof(checkpoint_id, proof);
    }

    #[tokio::test]
    async fn commit_state_accepts_coordinator_membership_at_checkpoint_one() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        let local_root = env.seed_consistent_coordinator_head().await?;

        // a checkpoint-1 update carrying the coordinator's canonical tree
        // root: commit must verify the membership proof served by the
        // coordinator client and persist the checkpoint
        let update = env.make_checkpoint_one_update();
        seed_membership(&env, &update);

        let proc_id: QCoreProcCheckpointUniqueId = 7;
        env.processor.state.processing_checkpoint_id = 1;
        env.processor.state.processing_checkpoint_root = update.checkpoint_sync_info.checkpoint_tree_root;
        env.processor.state.processing_realm_start_root = local_root;
        env.processor.state.processing_realm_end_root = local_root;
        env.processor.state.processing_unique_pending_id = 1;
        env.processor.state.processing_proc_checkpoint_unique_id = proc_id;

        let prepared = PsyPreparedRealmBlockStateUpdates::<PHash> {
            realm_id: TEST_REALM_ID,
            realm_sub_id: TEST_REALM_SUB_ID,
            unique_pending_id: 1,
            proc_checkpoint_unique_id: proc_id,
            old_realm_root: local_root,
            new_realm_root: local_root,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        };
        env.processor
            .commit_state(&update, &prepared, ProvingJobCircuitType::GUTANoChange, vec![], None)
            .await?;

        assert_eq!(env.db.get_latest_checkpoint_id().await?, 1);
        assert_eq!(env.db.get_latest_l2_block_state().await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(1).await?, Some(1));
        assert_eq!(env.db.get_unique_pending_id_for_checkpoint_id(1).await?, Some((1, proc_id)));
        assert_eq!(
            env.db.get_checkpoint_id_for_checkpoint_root_hash(update.checkpoint_sync_info.checkpoint_tree_root).await?,
            Some(1)
        );

        let state = &env.processor.state;
        assert_eq!(state.last_committed_checkpoint_id, 1);
        assert_eq!(state.last_committed_unique_pending_id, 1);
        assert_eq!(state.last_committed_proc_checkpoint_unique_id, proc_id);
        assert_eq!(state.last_committed_checkpoint_root, update.checkpoint_sync_info.checkpoint_tree_root);
        Ok(())
    }

    #[tokio::test]
    async fn commit_state_cleans_up_proofs_of_previous_pending_id() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        let local_root = env.seed_consistent_coordinator_head().await?;

        let update = env.make_checkpoint_one_update();
        seed_membership(&env, &update);
        env.processor.state.processing_checkpoint_id = 1;
        env.processor.state.processing_checkpoint_root = update.checkpoint_sync_info.checkpoint_tree_root;
        env.processor.state.processing_realm_start_root = local_root;
        env.processor.state.processing_realm_end_root = local_root;
        env.processor.state.processing_unique_pending_id = 1;
        env.processor.state.processing_proc_checkpoint_unique_id = 7;

        let prepared = PsyPreparedRealmBlockStateUpdates::<PHash> {
            realm_id: TEST_REALM_ID,
            realm_sub_id: TEST_REALM_SUB_ID,
            unique_pending_id: 1,
            proc_checkpoint_unique_id: 7,
            old_realm_root: local_root,
            new_realm_root: local_root,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            update_contract_state_imt_leaves_ffs: vec![],
        };
        env.processor
            .commit_state(&update, &prepared, ProvingJobCircuitType::GUTANoChange, vec![], None)
            .await?;
        // the previous checkpoint's proofs (pending id 0) were dropped; the
        // commit itself still reports checkpoint 1 fully persisted
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 1);
        Ok(())
    }

}
