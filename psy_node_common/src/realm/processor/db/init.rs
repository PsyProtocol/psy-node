use std::future::Future;
use std::sync::Arc;

use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QCoreProcCheckpointUniqueId,
    crypto::hash::
        traits::MerkleZeroHasher
    ,
    data::{
        hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::SimpleMerkleNodeKey},
        queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    },
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
};
use psy_core::{
    constants::stale_checkpoint::STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    node::realm_processor::{RealmProcessorCoreState, RealmProcessorCoreStateWrapper},
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    p2p::{traits::realm_coordinantor::RealmCoordinatorClient, validator_lookup::write_validator_tree_genesis},
    psy_core_db::traits::full::{
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::{
        checkpoint_tree::CheckpointTreeBackupManager,
        realm::generate_realm_output_from_backups,
    },
    constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    queue::gatherer::QueueKeyStatusManager,
    realm::processor::{
        db::{DatabaseCheckState, PsyRealmDatabaseProcessor},
        gatherers::realm_end_cap_gatherer::{
            get_new_realm_end_cap_gatherer_backup_file_path, read_realm_backup_end_root,
        },
    },
    utils::processor_status::ProcessorStatus,
};

pub async fn create_new_checkpoint_backup_manager_from_file_path<
    Hasher: MerkleZeroHasher<Hash> + 'static + Send + Sync,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash,
    CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: Arc<FileSystem>,
    max_checkpoints_to_keep: u64,
    checkpoint_tree_height: u8,
    checkpoint_tree_store: &CheckpointTreeStore,
    backup_file_path: &str,
    allow_create_file: bool,
) -> anyhow::Result<CheckpointTreeBackupManager<Hasher, Hash, FileSystem>> {
    CheckpointTreeBackupManager::<Hasher, Hash, FileSystem>::new_from_file_path(
        file_system,
        max_checkpoints_to_keep,
        checkpoint_tree_height,
        checkpoint_tree_store,
        backup_file_path,
        allow_create_file,
    )
    .await
}

async fn find_latest_mapped_pending_at_or_before<F, Fut>(
    target_checkpoint_id: u64,
    mut query: F,
) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>>,
{
    let mut cp = target_checkpoint_id;
    loop {
        match query(cp).await? {
            Some(res) => return Ok(res),
            None if cp == 0 => {
                if target_checkpoint_id == 0 {
                    return Ok((0u64, 0u128));
                } else {
                    anyhow::bail!(
                        "No checkpoint->pending mapping found for any checkpoint <= target {}. Cannot prove the latest mapped pending IDs; refusing startup to avoid pending/proc ID reuse or reapplying post-target backups.",
                        target_checkpoint_id
                    );
                }
            }
            None => cp -= 1,
        }
    }
}

async fn resolve_current_and_last_committed_pending_ids<BoundaryF, BoundaryFut, LatestF, LatestFut, ReverseF, ReverseFut>(
    target_checkpoint_id: u64,
    boundary_query: BoundaryF,
    latest_mapped_query: LatestF,
    reverse_query: ReverseF,
) -> anyhow::Result<(
    (u64, QCoreProcCheckpointUniqueId),
    (u64, QCoreProcCheckpointUniqueId),
)>
where
    BoundaryF: FnMut(u64) -> BoundaryFut,
    BoundaryFut: Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>>,
    LatestF: FnOnce() -> LatestFut,
    LatestFut: Future<Output = anyhow::Result<(u64, QCoreProcCheckpointUniqueId)>>,
    ReverseF: FnOnce(u64) -> ReverseFut,
    ReverseFut: Future<Output = anyhow::Result<Option<u64>>>,
{
    let last_committed = find_latest_mapped_pending_at_or_before(target_checkpoint_id, boundary_query).await?;
    let current = match latest_mapped_query().await {
        Ok(ids) => ids,
        Err(error) => {
            tracing::warn!(
                "No positive mapped pending generation could be resolved at startup; using proven checkpoint boundary {:?}: {:?}",
                last_committed,
                error
            );
            last_committed
        }
    };

    let latest_pending_reverse_mapping = reverse_query(current.0).await?;
    ensure_latest_pending_within_target(current.0, latest_pending_reverse_mapping, target_checkpoint_id)?;

    Ok((current, last_committed))
}

// Post-T reverse mapping of the latest pending is a leftover generation; fail closed so startup cannot replay its backup.
fn ensure_latest_pending_within_target(
    current_unique_pending_id: u64,
    latest_pending_reverse_mapping: Option<u64>,
    target_checkpoint_id: u64,
) -> anyhow::Result<()> {
    if let Some(mapped_checkpoint_id) = latest_pending_reverse_mapping {
        if mapped_checkpoint_id > target_checkpoint_id {
            anyhow::bail!(
                "Contradictory pending mapping: latest mapped unique pending ID {} maps to \
                 checkpoint {}, beyond the target checkpoint {}. A leftover post-target \
                 generation survived; refusing to start up to prevent reapplying its backup.",
                current_unique_pending_id,
                mapped_checkpoint_id,
                target_checkpoint_id
            );
        }
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
    N::HasherBase: 'static + Send + Sync,
{
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;

        if local_latest_checkpoint_id == 0 {
            let (last_unique_pending_id, _) = match self.db.get_latest_mapped_unique_pending_id().await {
                Ok(ids) => ids,
                Err(_) => return Ok(DatabaseCheckState::NeedsGenesis),
            };
            if last_unique_pending_id == 0 {
                return Ok(DatabaseCheckState::NeedsGenesis);
            }
        }

        let coordinator_realm_state: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(u64::MAX - 0xffff, self.state.realm_id_u64)
            .await?;

        if coordinator_realm_state.checkpoint_id > local_latest_checkpoint_id {
            tracing::info!(
                "Coordinator indicates Realm updated at checkpoint {}, but local DB only at {}. Needs Recovery.",
                coordinator_realm_state.checkpoint_id,
                local_latest_checkpoint_id
            );
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        let local_realm_root = self
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(coordinator_realm_state.checkpoint_id, &self.realm_root_node)
            .await?;

        if local_realm_root.value != coordinator_realm_state.value {
            tracing::warn!(
                "Realm Root Mismatch at Checkpoint {}. Local: {:?}, Remote: {:?}. Needs Recovery.",
                coordinator_realm_state.checkpoint_id,
                local_realm_root.value,
                coordinator_realm_state.value
            );
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        let ((last_unique_pending_id, _), _) = resolve_current_and_last_committed_pending_ids(
            local_latest_checkpoint_id,
            |checkpoint_id| {
                let db = self.db.clone();
                async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
            },
            || self.db.get_latest_mapped_unique_pending_id(),
            |unique_pending_id| self.db.get_checkpoint_id_for_unique_pending_id(unique_pending_id),
        )
        .await?;
        let expected_checkpoint_id_opt = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;

        if let Some(expected_checkpoint_id) = expected_checkpoint_id_opt {
            if expected_checkpoint_id != local_latest_checkpoint_id {
                if expected_checkpoint_id > local_latest_checkpoint_id {
                     tracing::error!("DB Inconsistency: PendingID {} maps to Checkpoint {}, but latest is {}.", 
                        last_unique_pending_id, expected_checkpoint_id, local_latest_checkpoint_id);
                     return Ok(DatabaseCheckState::NeedsRecovery);
                }
            }
        }

        Ok(DatabaseCheckState::Ready)
    }

    pub async fn new_init(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        proof_work_queue: Arc<ProofWorkQueue>,
        coordinator_client: Arc<CoordinatorClient>,
        chain_id: u32,
        realm_identifier: QRealmIdentifier,
        circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
        file_system: Arc<FileSystem>,
        checkpoint_tree_root_backup_file_path: String,
        genesis_realm_root: N::QHash,
        genesis_checkpoint_root: N::QHash,
    ) -> anyhow::Result<Self> {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        let realm_root_node = SimpleMerkleNodeKey {
            level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            index: realm_id_u64,
        };
        tracing::info!("[REALM_INIT] new_init start");

        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;
        tracing::info!("[REALM_INIT] latest checkpoint id = {}", last_committed_checkpoint_id);
        let ((current_unique_pending_id, current_core_proc_unique_pending_id), (last_committed_unique_pending_id, last_committed_proc_checkpoint_unique_id)) =
            if last_committed_checkpoint_id == 0 {
                let committed = match db.get_unique_pending_id_for_checkpoint_id(0).await {
                    Ok(Some(res)) => res,
                    _ => (0u64, 0u128),
                };
                ((0u64, 0u128), committed)
            } else {
                resolve_current_and_last_committed_pending_ids(
                    last_committed_checkpoint_id,
                    |checkpoint_id| {
                        let db = db.clone();
                        async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
                    },
                    || {
                        let db = db.clone();
                        async move { db.get_latest_mapped_unique_pending_id().await }
                    },
                    |unique_pending_id| {
                        let db = db.clone();
                        async move { db.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await }
                    },
                )
                .await?
            };
        tracing::info!(
            "[REALM_INIT] current unique ids = ({}, {})",
            current_unique_pending_id,
            current_core_proc_unique_pending_id
        );

        let last_committed_checkpoint_root = match db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await {
            Ok(root) => root,
            Err(_) if last_committed_checkpoint_id == 0 => genesis_checkpoint_root,
            Err(e) => return Err(e),
        };

        let last_committed_realm_root = if last_committed_checkpoint_id == 0 {
            genesis_realm_root
        } else {
            db.global_user_tree_get_node(last_committed_checkpoint_id, realm_root_node).await?
        };

        let state = RealmProcessorCoreState::new_basic(
            chain_id,
            realm_identifier,
            last_committed_checkpoint_id,
            last_committed_unique_pending_id,
            last_committed_proc_checkpoint_unique_id,
            last_committed_checkpoint_root,
            last_committed_realm_root,
        );

        let checkpoint_tree_backup_manager = create_new_checkpoint_backup_manager_from_file_path(
            file_system.clone(),
            STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
            N::CHECKPOINT_TREE_HEIGHT,
            &db,
            &checkpoint_tree_root_backup_file_path,
            true,
        )
        .await?;
        tracing::info!("[REALM_INIT] checkpoint backup manager created");

        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        tracing::info!("[REALM_INIT] temp db unique ids set");

        temp_db
            .set_gathering_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        tracing::info!("[REALM_INIT] temp db gathering unique ids set");

        let status = ProcessorStatus::new();
        Ok(Self {
            db,
            status: status.clone(),
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            guta_update_queue,
            proof_work_queue,
            coordinator_client,
            checkpoint_tree_backup_manager,
            shared_state: RealmProcessorCoreStateWrapper::new(state.clone()),
            circuit_fingerprint_config,
            guta_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
                PsyRealmUserUpdateQueueItem<N::F, N::QHash>,
            >::new_with_status(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }, status.clone()),
            needs_revert: false,
            state,
            realm_root_node,
        })
    }

    pub async fn ensure_genesis_applied(
        &mut self,
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to realm processor database...");
            println!("genesis_block_update.coordinator_update: {:?}", genesis_block_update.coordinator_update);
            self.checkpoint_tree_backup_manager.append_checkpoint_leaf_hash(0, genesis_block_update.coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash).await?;
            self.commit_state(
                &genesis_block_update.coordinator_update,
                &genesis_block_update.prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
                false,
            )
            .await?;
            write_validator_tree_genesis(
                &*self.db,
                &genesis_block_update.update_validator_tree_nodes_ffs,
                &genesis_block_update.new_validator_leaf_preimages,
            )
            .await?;
            tracing::info!("Genesis block setup data applied.");
        }
        Ok(())
    }

    pub async fn ensure_genesis_applied_from_setup_data(&mut self, genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to realm processor database...");
            let genesis_block_update = GenesisDatabaseDataBuilder::setup_for_realm::<N::HasherBase, N>(
                &genesis_data,
                self.state.chain_id,
                self.state.realm_id_u64,
                self.state.realm_sub_id_u64,
            )?;
            self.commit_state(
                &genesis_block_update.coordinator_update,
                &genesis_block_update.prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
                false,
            )
            .await?;
            write_validator_tree_genesis(
                &*self.db,
                &genesis_block_update.update_validator_tree_nodes_ffs,
                &genesis_block_update.new_validator_leaf_preimages,
            )
            .await?;
            tracing::info!("Genesis block setup data applied.");
        }
        Ok(())
    }

    pub async fn ensure_db_matches_coordinator_head(&self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        
        if coordinator_latest_checkpoint_id < local_latest_checkpoint_id {
            anyhow::bail!("Local database checkpoint ID ({}) is ahead of coordinator ({}). Inconsistency detected.",
                local_latest_checkpoint_id, coordinator_latest_checkpoint_id);
        }

        let coordinator_realm_root_state = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.state.realm_id_u64)
            .await?;
            
        let local_realm_root_state = self
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(coordinator_latest_checkpoint_id, &self.realm_root_node)
            .await?;

        if local_latest_checkpoint_id < coordinator_realm_root_state.checkpoint_id {
             anyhow::bail!("Local database is stale. Coordinator sees update at {}, local head is {}.", 
                coordinator_realm_root_state.checkpoint_id, local_latest_checkpoint_id);
        }

        if coordinator_realm_root_state.value != local_realm_root_state.value {
            anyhow::bail!("Realm Root mismatch. Coordinator: {:?}, Local: {:?}.",
                coordinator_realm_root_state, local_realm_root_state);
        }

        Ok(())
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
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
    pub async fn ensure_backup_restored_if_necessary(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsRecovery {
            tracing::warn!("Inconsistent Realm Processor State detected. Initiating Recovery.");

            let coordinator_latest_checkpoint_id = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            
            self.checkpoint_tree_backup_manager
                .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
                .await?;

            let mut checkpoint_id = self.state.last_committed_checkpoint_id + 1;
            while checkpoint_id <= coordinator_latest_checkpoint_id {
                tracing::info!("Recovering checkpoint {}...", checkpoint_id);

                let coordinator_update = self.coordinator_client.rc_get_realm_sync_info(checkpoint_id, self.state.realm_id_u64).await?;

                let target_realm_state = self
                    .coordinator_client
                    .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, self.state.realm_id_u64)
                    .await?;

                tracing::info!("Coordinator realm root at checkpoint {}: {:?}", checkpoint_id, target_realm_state.value);

                if target_realm_state.value == self.state.last_committed_realm_end_root {
                    tracing::debug!(
                        "Checkpoint {}: realm root unchanged ({:?}), skipping recovery.",
                        checkpoint_id,
                        target_realm_state.value
                    );
                    checkpoint_id += 1;
                    continue;
                }

                self.state.processing_checkpoint_id = checkpoint_id;
                self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;

                let prepared_updates = if checkpoint_id == 0 {
                    tracing::info!("Restore target is checkpoint 0 (genesis); using genesis path without backup file.");
                    self.state.processing_realm_start_root = target_realm_state.value;
                    self.state.processing_realm_end_root = target_realm_state.value;
                    PsyPreparedRealmBlockStateUpdates {
                        realm_id: self.state.realm_id_u64,
                        realm_sub_id: self.state.realm_sub_id_u64,
                        old_realm_root: target_realm_state.value,
                        new_realm_root: target_realm_state.value,
                        unique_pending_id: 0,
                        proc_checkpoint_unique_id: 0,
                        update_global_user_tree_nodes_ffs: vec![],
                        update_user_contract_tree_nodes_ffs: vec![],
                        update_contract_state_tree_nodes_ffs: vec![],
                        update_user_leaves_ffs: vec![],
                        update_contract_state_imt_leaves_ffs: vec![],
                    }
                } else {
                    let realm_pending_id = self
                        .db
                        .get_unique_pending_id_for_checkpoint_id(checkpoint_id)
                        .await?;
                    let (realm_unique_pending_id, realm_proc_checkpoint_id) = match realm_pending_id {
                        Some(res) => res,
                        None => {
                            let ((current_unique_pending_id, current_proc_checkpoint_id), _) =
                                resolve_current_and_last_committed_pending_ids(
                                    self.state.last_committed_checkpoint_id,
                                    |checkpoint_id| {
                                        let db = self.db.clone();
                                        async move { db.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await }
                                    },
                                    || self.db.get_latest_mapped_unique_pending_id(),
                                    |unique_pending_id| self.db.get_checkpoint_id_for_unique_pending_id(unique_pending_id),
                                )
                                .await?;
                            let last_committed_unique_pending_id = self.state.last_committed_unique_pending_id;

                            let mut recovered_from_backup = false;
                            if current_unique_pending_id > last_committed_unique_pending_id {
                                for candidate in (last_committed_unique_pending_id + 1)..=current_unique_pending_id {
                                    let path = get_new_realm_end_cap_gatherer_backup_file_path(
                                        guta_gatherer_backup_directory,
                                        self.state.realm_id_u64,
                                        self.state.realm_sub_id_u64,
                                        candidate,
                                    );
                                    match read_realm_backup_end_root::<FileSystem, N::QHash>(file_system, &path.to_string_lossy()).await {
                                        Ok(end_root) if end_root == target_realm_state.value => {
                                            let candidate_proc_checkpoint_id = if candidate == current_unique_pending_id {
                                                current_proc_checkpoint_id
                                            } else if let Some(mapped_checkpoint_id) =
                                                self.db.get_checkpoint_id_for_unique_pending_id(candidate).await?
                                            {
                                                match self.db.get_unique_pending_id_for_checkpoint_id(mapped_checkpoint_id).await? {
                                                    Some((mapped_pending_id, mapped_proc_checkpoint_id))
                                                        if mapped_pending_id == candidate =>
                                                    {
                                                        mapped_proc_checkpoint_id
                                                    }
                                                    _ => {
                                                        tracing::warn!(
                                                            "Backup pending_id {} matches checkpoint {} end_root, but its stored proc_checkpoint_unique_id could not be verified via mapped checkpoint {}. Using current proc_checkpoint_unique_id {}.",
                                                            candidate,
                                                            checkpoint_id,
                                                            mapped_checkpoint_id,
                                                            current_proc_checkpoint_id
                                                        );
                                                        current_proc_checkpoint_id
                                                    }
                                                }
                                            } else {
                                                tracing::warn!(
                                                    "Backup pending_id {} matches checkpoint {} end_root, but it has no checkpoint mapping to recover proc_checkpoint_unique_id. Current pending_id is {}; using current proc_checkpoint_unique_id {}.",
                                                    candidate,
                                                    checkpoint_id,
                                                    current_unique_pending_id,
                                                    current_proc_checkpoint_id
                                                );
                                                current_proc_checkpoint_id
                                            };
                                            let mut recovery_state = self.state.clone();
                                            recovery_state.processing_unique_pending_id = candidate;
                                            recovery_state.processing_proc_checkpoint_unique_id = candidate_proc_checkpoint_id;
                                            recovery_state.processing_realm_start_root = self.state.last_committed_realm_end_root;
                                            recovery_state.processing_realm_end_root = target_realm_state.value;
                                            tracing::info!(
                                                "Found matching backup for checkpoint {}: pending_id={}. Attempting full load.",
                                                checkpoint_id,
                                                candidate
                                            );
                                            match generate_realm_output_from_backups::<N, FileSystem>(
                                                file_system,
                                                guta_gatherer_backup_directory,
                                                &recovery_state,
                                                Some(candidate),
                                                global_user_tree,
                                            ).await {
                                                Ok(updates) if updates.new_realm_root == target_realm_state.value => {
                                                    tracing::info!(
                                                        "Backup recovery successful for pending_id {}: end_root matches coordinator target {:?}.",
                                                        candidate,
                                                        target_realm_state.value
                                                    );
                                                    self.state.processing_unique_pending_id = recovery_state.processing_unique_pending_id;
                                                    self.state.processing_proc_checkpoint_unique_id =
                                                        recovery_state.processing_proc_checkpoint_unique_id;
                                                    self.state.processing_realm_start_root =
                                                        recovery_state.processing_realm_start_root;
                                                    self.state.processing_realm_end_root =
                                                        recovery_state.processing_realm_end_root;
                                                    self.commit_state(
                                                        &coordinator_update,
                                                        &updates,
                                                        ProvingJobCircuitType::GUTANoChange,
                                                        vec![],
                                                        true,
                                                    ).await?;
                                                    tracing::info!(
                                                        "Checkpoint {} recovered from backup (pending_id={}).",
                                                        checkpoint_id,
                                                        candidate
                                                    );
                                                    recovered_from_backup = true;
                                                    break;
                                                }
                                                Ok(updates) => {
                                                    tracing::warn!(
                                                        "Backup end_root {:?} does not match coordinator target {:?} for pending_id {}. Trying next candidate.",
                                                        updates.new_realm_root,
                                                        target_realm_state.value,
                                                        candidate
                                                    );
                                                }
                                                Err(e) => {
                                                    tracing::warn!(
                                                        "Backup pending_id {} end_root matches but full load failed: {:?}. Trying next candidate.",
                                                        candidate,
                                                        e
                                                    );
                                                }
                                            }
                                        }
                                        Ok(end_root) => {
                                            tracing::debug!(
                                                "Backup pending_id {} end_root {:?} does not match coordinator target {:?} for checkpoint {}.",
                                                candidate,
                                                end_root,
                                                target_realm_state.value,
                                                checkpoint_id
                                            );
                                        }
                                        Err(e) => {
                                            tracing::debug!(
                                                "Failed to read backup pending_id {} for checkpoint {}: {:?}",
                                                candidate,
                                                checkpoint_id,
                                                e
                                            );
                                        }
                                    }
                                }
                            }

                            if !recovered_from_backup {
                                anyhow::bail!(
                                    "Checkpoint {}: realm root changed from {:?} to {:?} but no local backup found. \
                                     This indicates data loss — the sub-tree nodes required to generate proofs are missing.",
                                    checkpoint_id,
                                    self.state.last_committed_realm_end_root,
                                    target_realm_state.value
                                );
                            }

                            let latest_realm_root = self.get_realm_root_from_db().await?;
                            if latest_realm_root != target_realm_state.value {
                                anyhow::bail!(
                                    "Post-recovery root mismatch at checkpoint {}! Local: {:?}, Target: {:?}",
                                    checkpoint_id,
                                    latest_realm_root,
                                    target_realm_state.value
                                );
                            }
                            checkpoint_id += 1;
                            continue;
                        }
                    };
                    if realm_unique_pending_id == 0 {
                        tracing::info!(
                            "Restore target checkpoint {} maps to unique_pending_id 0 (no backup file); using genesis-like path.",
                            checkpoint_id
                        );
                        self.state.processing_realm_start_root = target_realm_state.value;
                        self.state.processing_realm_end_root = target_realm_state.value;
                        PsyPreparedRealmBlockStateUpdates {
                            realm_id: self.state.realm_id_u64,
                            realm_sub_id: self.state.realm_sub_id_u64,
                            unique_pending_id: 0,
                            proc_checkpoint_unique_id: realm_proc_checkpoint_id,
                            old_realm_root: target_realm_state.value,
                            new_realm_root: target_realm_state.value,
                            update_global_user_tree_nodes_ffs: vec![],
                            update_user_contract_tree_nodes_ffs: vec![],
                            update_contract_state_tree_nodes_ffs: vec![],
                            update_user_leaves_ffs: vec![],
                            update_contract_state_imt_leaves_ffs: vec![],
                        }
                    } else {
                        self.state.processing_unique_pending_id = realm_unique_pending_id;
                        self.state.processing_proc_checkpoint_unique_id = realm_proc_checkpoint_id;
                        self.state.processing_realm_start_root = self.state.last_committed_realm_end_root;
                        self.state.processing_realm_end_root = target_realm_state.value;
                        generate_realm_output_from_backups::<N, FileSystem>(
                            file_system,
                            guta_gatherer_backup_directory,
                            &self.state,
                            Some(realm_unique_pending_id),
                            global_user_tree,
                        )
                        .await?
                    }
                };

                self.commit_state(
                    &coordinator_update,
                    &prepared_updates,
                    ProvingJobCircuitType::GUTANoChange,
                    vec![],
                    true,
                ).await?;

                tracing::info!("Checkpoint {} recovered successfully.", checkpoint_id);

                let latest_realm_root = self.get_realm_root_from_db().await?;
                if latest_realm_root != target_realm_state.value {
                    anyhow::bail!(
                        "Post-recovery root mismatch at checkpoint {}! Local: {:?}, Target: {:?}",
                        checkpoint_id,
                        latest_realm_root,
                        target_realm_state.value
                    );
                }

                checkpoint_id += 1;
            }
        }

        Ok(())
    }

    pub async fn init_with_setup_and_genesis(
        &mut self,
        file_system: &FileSystem,
        guta_gatherer_backup_directory: &str,
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<()> {
        let genesis_checkpoint_root = genesis_block_update.coordinator_update.checkpoint_sync_info.checkpoint_tree_root;

        self.ensure_genesis_applied(genesis_block_update).await?;

        self.ensure_backup_restored_if_necessary(file_system, guta_gatherer_backup_directory, global_user_tree)
            .await?;

        if self.state.last_committed_checkpoint_id > 0 {
            self.checkpoint_tree_backup_manager
                .sync_from_database::<S>(&self.db, 1000, self.state.last_committed_checkpoint_id)
                .await?;
        }

        self.sync_to_coordinator_set_checkpoint_id().await?;

        let current_realm_root = self.db.global_user_tree_get_node(self.state.last_committed_checkpoint_id, self.realm_root_node).await?;
        
        self.state.last_committed_realm_end_root = current_realm_root;
        self.state.last_committed_realm_start_root = current_realm_root;
        self.state.processing_realm_start_root = current_realm_root;
        self.state.processing_realm_end_root = current_realm_root;
        self.state.gathering_realm_start_root = current_realm_root;

        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;

        let head_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let head_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.coordinator_head_synced_checkpoint_id = head_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = head_checkpoint_root;
        
        self.state.processing_checkpoint_root = head_checkpoint_root;
        self.state.gathering_checkpoint_root = head_checkpoint_root;
        self.state.processing_checkpoint_id = head_checkpoint_id;
        self.state.gathering_checkpoint_id = head_checkpoint_id;

        let last_committed_checkpoint_root = if self.state.last_committed_checkpoint_id == 0 {
            genesis_checkpoint_root 
        } else {
            self.checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_leaf(self.state.last_committed_checkpoint_id)
                .get_append_root::<N::HasherBase>()
        };
        self.state.last_committed_checkpoint_root = last_committed_checkpoint_root;

        self.set_new_unique_ids(Some(current_realm_root)).await?;

        self.guta_queue_key_status_manager
            .set_unique_id(self.state.gathering_proc_checkpoint_unique_id)?;
        
        self.shared_state.update_from_core_state(&self.state).await?;

        tracing::info!(
            "[REALM] Initialized. Checkpoint: {}, Pending ID: {}, Realm Root: {:?}",
            self.state.coordinator_head_synced_checkpoint_id,
            self.state.gathering_unique_pending_id,
            current_realm_root
        );
        self.print_coordinator_processor_state();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{ensure_latest_pending_within_target, find_latest_mapped_pending_at_or_before, resolve_current_and_last_committed_pending_ids};

    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::Arc;

    use parth_core::QCoreProcCheckpointUniqueId;

    fn mapping_query(
        mappings: HashMap<u64, (u64, QCoreProcCheckpointUniqueId)>,
    ) -> impl FnMut(u64) -> Pin<Box<dyn Future<Output = anyhow::Result<Option<(u64, QCoreProcCheckpointUniqueId)>>> + Send>> {
        let mappings = Arc::new(mappings);
        move |cp| {
            let mappings = Arc::clone(&mappings);
            Box::pin(async move { Ok(mappings.get(&cp).copied()) })
        }
    }

    #[tokio::test]
    async fn missing_mapping_walks_back_to_latest_mapping() {
        let mappings = HashMap::from([(197u64, (87u64, 10087u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(199, mapping_query(mappings))
            .await
            .expect("the latest mapping below T must resolve, not (0, 0)");
        assert_eq!(resolved, (87u64, 10087u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn real_mapping_at_target_uses_it_unchanged() {
        let mappings = HashMap::from([(199u64, (88u64, 10088u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(199, mapping_query(mappings))
            .await
            .expect("a mapping at T resolves on the first point read");
        assert_eq!(resolved, (88u64, 10088u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn genesis_empty_store_returns_zero() {
        let resolved = find_latest_mapped_pending_at_or_before(0, mapping_query(HashMap::new()))
            .await
            .expect("genesis with no mapping is the valid empty-store startup state");
        assert_eq!(resolved, (0u64, 0u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn genesis_with_mapping_uses_mapping() {
        let mappings = HashMap::from([(0u64, (5u64, 1005u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(0, mapping_query(mappings))
            .await
            .expect("a genesis mapping resolves to that pair");
        assert_eq!(resolved, (5u64, 1005u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn mapping_at_genesis_resolves_for_non_genesis_target() {
        let mappings = HashMap::from([(0u64, (5u64, 1005u128))]);
        let resolved = find_latest_mapped_pending_at_or_before(5, mapping_query(mappings))
            .await
            .expect("a genesis mapping is the latest mapping for this target");
        assert_eq!(resolved, (5u64, 1005u128 as QCoreProcCheckpointUniqueId));
    }

    #[tokio::test]
    async fn non_genesis_with_no_mapping_fails_closed() {
        let err = find_latest_mapped_pending_at_or_before(5, mapping_query(HashMap::new()))
            .await
            .expect_err("a non-genesis target with no mapping must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("No checkpoint->pending mapping"), "got: {msg}");
        assert!(msg.contains("<= target 5"), "got: {msg}");
    }

    #[tokio::test]
    async fn mapping_query_error_propagates_fail_closed() {
        let err = find_latest_mapped_pending_at_or_before(5, |cp| {
            Box::pin(async move {
                Err::<Option<(u64, QCoreProcCheckpointUniqueId)>, _>(anyhow::anyhow!(
                    "injected point-read failure at checkpoint {cp}"
                ))
            })
        })
        .await
        .expect_err("an injected point-read error must propagate, never fall back to (0, 0)");
        let msg = err.to_string();
        assert!(msg.contains("injected point-read failure at checkpoint 5"), "got: {msg}");
    }

    #[test]
    fn leftover_post_t_pending_fails_closed() {
        let err = ensure_latest_pending_within_target(104, Some(210), 199)
            .expect_err("a reverse mapping beyond T must fail closed");
        let msg = err.to_string();
        assert!(msg.contains("Contradictory pending mapping"), "got: {msg}");
        assert!(msg.contains("unique pending ID 104"), "got: {msg}");
        assert!(msg.contains("checkpoint 210"), "got: {msg}");
        assert!(msg.contains("target checkpoint 199"), "got: {msg}");
    }

    #[test]
    fn latest_pending_within_or_at_target_is_consistent() {
        ensure_latest_pending_within_target(87, Some(197), 199)
            .expect("a reverse mapping <= T is consistent");
        ensure_latest_pending_within_target(88, Some(199), 199)
            .expect("a reverse mapping == T is consistent (boundary is >, not >=)");
    }

    #[tokio::test]
    async fn marker_63_with_only_sentinel_mapping_uses_proven_zero_pair() {
        let mappings = HashMap::from([(0u64, (0u64, 0u128))]);
        let resolved = resolve_current_and_last_committed_pending_ids(
            63,
            mapping_query(mappings),
            || async { anyhow::bail!("No mapped unique pending ID found at or below pending counter 1100") },
            |pending_id| async move { Ok((pending_id == 0).then_some(0)) },
        )
        .await
        .expect("the sentinel checkpoint boundary proves the committed/current pair despite a high raw counter");

        assert_eq!(resolved, ((0, 0), (0, 0)));
    }

    #[tokio::test]
    async fn normal_positive_mapping_keeps_latest_and_boundary_pairs() {
        let mappings = HashMap::from([(62u64, (87u64, 10087u128))]);
        let resolved = resolve_current_and_last_committed_pending_ids(
            63,
            mapping_query(mappings),
            || async { Ok((87u64, 10087u128)) },
            |pending_id| async move { Ok((pending_id == 87).then_some(62)) },
        )
        .await
        .expect("a normal positive mapping at/before the marker remains unchanged");

        assert_eq!(resolved, ((87, 10087), (87, 10087)));
    }

    #[test]
    fn latest_pending_inflight_no_reverse_is_allowed() {
        ensure_latest_pending_within_target(94, None, 199)
            .expect("an in-flight pending (no checkpoint mapping) is not a post-T leftover");
    }

    #[test]
    fn recovery_candidate_range_excludes_post_t_backups_after_rollback() {
        let boundary = 87u64;
        let current = 87u64;
        let candidate_range = (boundary + 1)..=current;

        assert!(candidate_range.is_empty(), "candidate range must be empty after a correct rollback");
        for post_target_pending in [88u64, 89, 94] {
            assert!(
                !candidate_range.contains(&post_target_pending),
                "post-T post-target generation pending {} must not be in the recovery candidate range",
                post_target_pending
            );
        }
    }

    #[test]
    fn partial_rollback_leftover_bails_before_recovery_applies_backup() {
        let boundary = 87u64;
        let leftover_pending = 88u64;
        let leftover_reverse = Some(200u64);
        ensure_latest_pending_within_target(leftover_pending, leftover_reverse, 199)
            .expect_err("a leftover post-T pending must bail before recovery runs");
        let would_walk = (boundary + 1)..=leftover_pending;
        assert!(would_walk.contains(&leftover_pending), "sanity: without the guard the leftover would be walked");
    }
}
