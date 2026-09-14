use std::sync::Arc;

use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
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
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::{
        PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::{checkpoint_tree::CheckpointTreeBackupManager, realm::generate_realm_output_from_backups},
    constants::queue::PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    queue::gatherer::QueueKeyStatusManager,
    realm::processor::db::{DatabaseCheckState, PsyRealmDatabaseProcessor},
    realm::processor::gatherers::realm_end_cap_gatherer::{get_new_realm_end_cap_gatherer_backup_file_path, read_realm_backup_end_root},
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
        
        // 1. Check for Genesis requirement
        if local_latest_checkpoint_id == 0 {
            // Check if we actually have genesis applied (unique IDs > 0 usually implies initialization)
            let (last_unique_pending_id, _) = match self.db.get_latest_mapped_unique_pending_id().await {
                Ok(ids) => ids,
                Err(_) => return Ok(DatabaseCheckState::NeedsGenesis),
            };
            if last_unique_pending_id == 0 {
                // Completely empty
                return Ok(DatabaseCheckState::NeedsGenesis);
            }
        }

        // 2. Check Consistency against Coordinator
        // We get the coordinator's view of *our* realm root.
        // u64::MAX-0xffff is a convention for "latest checkpoint known to coordinator"
        let coordinator_realm_state: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(u64::MAX - 0xffff, self.state.realm_id_u64)
            .await?;

        // Get our local root at the checkpoint the coordinator claims we are at.
        // If we don't have this checkpoint locally, we are definitely behind/broken.
        if coordinator_realm_state.checkpoint_id > local_latest_checkpoint_id {
            tracing::info!(
                "Coordinator indicates Realm updated at checkpoint {}, but local DB only at {}. Needs Recovery.",
                coordinator_realm_state.checkpoint_id,
                local_latest_checkpoint_id
            );
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        // We have the checkpoint ID locally. Let's compare roots.
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

        // 3. Check internal DB consistency (Pending ID vs Checkpoint ID mapping)
        let (last_unique_pending_id, _) = self.db.get_latest_mapped_unique_pending_id().await?;
        let expected_checkpoint_id_opt = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;

        if let Some(expected_checkpoint_id) = expected_checkpoint_id_opt {
            if expected_checkpoint_id != local_latest_checkpoint_id {
                // If the mapping says we should be at X, but we are at Y.
                // Assuming mapping is set on commit.
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

        // 1. Recover basic state from DB
        let mut last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;
        tracing::info!("[REALM_INIT] latest checkpoint id = {}", last_committed_checkpoint_id);
        let (current_unique_pending_id, current_core_proc_unique_pending_id) = if last_committed_checkpoint_id == 0 {
            (0, 0u128)
        } else {
            db.get_latest_mapped_unique_pending_id().await?
        };
        tracing::info!(
            "[REALM_INIT] current unique ids = ({}, {})",
            current_unique_pending_id,
            current_core_proc_unique_pending_id
        );

        // 2. Validate consistency of unique pending IDs
        // Defensive: if a previous run fast-forwarded and set latest_checkpoint_id
        // without writing the unique_pending_id mapping, roll back to the last
        // checkpoint that actually has a mapping.
        let (last_committed_unique_pending_id, last_committed_proc_checkpoint_unique_id) = loop {
            match db.get_unique_pending_id_for_checkpoint_id(last_committed_checkpoint_id).await {
                Ok(Some(res)) => break res,
                Ok(None) if last_committed_checkpoint_id == 0 => break (0, 0u128),
                Ok(None) => {
                    tracing::warn!(
                        "No unique pending ID for checkpoint {}. Rolling back to previous checkpoint.",
                        last_committed_checkpoint_id
                    );
                    last_committed_checkpoint_id -= 1;
                }
                Err(e) => {
                    if last_committed_checkpoint_id == 0 {
                        break (0, 0u128);
                    } else {
                        return Err(e);
                    }
                }
            }
        };
        if last_committed_checkpoint_id != db.get_latest_checkpoint_id().await? {
            db.set_latest_checkpoint_id(last_committed_checkpoint_id).await?;
        }

        // 3. Get Checkpoint Root
        let last_committed_checkpoint_root = match db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await {
            Ok(root) => root,
            Err(_) if last_committed_checkpoint_id == 0 => genesis_checkpoint_root,
            Err(e) => return Err(e),
        };

        // 4. Get Realm Root
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

        // 5. Initialize Backup Manager
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

        // Initialize unique ID tracking in temp DB
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
            tracing::info!("Genesis block setup data applied.");
        }
        Ok(())
    }

    pub async fn ensure_genesis_applied_from_setup_data(&mut self, genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to realm processor database...");
            let genesis_block_update =
                GenesisDatabaseDataBuilder::setup_for_realm::<N::HasherBase, N>(&genesis_data, self.state.realm_id_u64, self.state.realm_sub_id_u64)?;
            self.commit_state(
                &genesis_block_update.coordinator_update,
                &genesis_block_update.prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
                false,
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

        // If local latest checkpoint is older than what coordinator thinks we modified last
        if local_latest_checkpoint_id < coordinator_realm_root_state.checkpoint_id {
             anyhow::bail!("Local database is stale. Coordinator sees update at {}, local head is {}.", 
                coordinator_realm_root_state.checkpoint_id, local_latest_checkpoint_id);
        }

        // Compare roots
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

            // 1. Fetch correct state from Coordinator
            let coordinator_latest_checkpoint_id = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            
            // Sync checkpoints first to ensure we have the proof data
            self.checkpoint_tree_backup_manager
                .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
                .await?;

            // 2. Recover each missing checkpoint in order
            let mut checkpoint_id = self.state.last_committed_checkpoint_id + 1;
            while checkpoint_id <= coordinator_latest_checkpoint_id {
                tracing::info!("Recovering checkpoint {}...", checkpoint_id);

                // 3. Fetch Full Coordinator Update Data for this checkpoint
                let coordinator_update = self.coordinator_client.rc_get_realm_sync_info(checkpoint_id, self.state.realm_id_u64).await?;

                // 4. Fetch coordinator realm state for this checkpoint
                let target_realm_state = self
                    .coordinator_client
                    .rc_get_realm_root_and_last_modified_checkpoint(checkpoint_id, self.state.realm_id_u64)
                    .await?;

                tracing::info!("Coordinator realm root at checkpoint {}: {:?}", checkpoint_id, target_realm_state.value);

                // Fast-path: if the realm root did not change at this checkpoint,
                // there is nothing to recover. Skip to the next one.
                if target_realm_state.value == self.state.last_committed_realm_end_root {
                    tracing::debug!(
                        "Checkpoint {}: realm root unchanged ({:?}), skipping recovery.",
                        checkpoint_id,
                        target_realm_state.value
                    );
                    checkpoint_id += 1;
                    continue;
                }

                // Seed processing_* fields before any commit_state call.
                // commit_processing() copies processing_* into last_committed_*,
                // so these must reflect the checkpoint we are about to commit.
                self.state.processing_checkpoint_id = checkpoint_id;
                self.state.processing_checkpoint_root = coordinator_update.checkpoint_sync_info.checkpoint_tree_root;

                // 5. Generate local updates
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
                            // Coordinator has advanced past what realm committed locally.
                            // Scan all candidate pending_ids to find a backup whose end_root matches.
                            let (current_unique_pending_id, current_proc_checkpoint_id) = self.db.get_latest_mapped_unique_pending_id().await?;
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
                                // Realm root changed but we have no local backup.
                                // Fast-forwarding is NOT safe here because we would be missing
                                // the sub-tree nodes needed to generate proofs. This is a
                                // data-loss scenario.
                                anyhow::bail!(
                                    "Checkpoint {}: realm root changed from {:?} to {:?} but no local backup found. \
                                     This indicates data loss — the sub-tree nodes required to generate proofs are missing.",
                                    checkpoint_id,
                                    self.state.last_committed_realm_end_root,
                                    target_realm_state.value
                                );
                            }

                            // After handling backup recovery, verify and continue to next checkpoint.
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
                    // unique_pending_id 0: no backup file exists (first file is pending_1.backup after first commit)
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

                // 6. Commit state to DB (for genesis, mapping, or backup recovery)
                self.commit_state(
                    &coordinator_update,
                    &prepared_updates,
                    ProvingJobCircuitType::GUTANoChange, // Dummy type for recovery
                    vec![],
                    true,
                ).await?;

                tracing::info!("Checkpoint {} recovered successfully.", checkpoint_id);

                // 7. Verify Post-Recovery
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

        // 1. Genesis Check
        self.ensure_genesis_applied(genesis_block_update).await?;

        // 2. Recovery Check
        self.ensure_backup_restored_if_necessary(file_system, guta_gatherer_backup_directory, global_user_tree)
            .await?;

        // 3. Hydrate Checkpoint Manager from Local DB (if we have data)
        if self.state.last_committed_checkpoint_id > 0 {
            self.checkpoint_tree_backup_manager
                .sync_from_database::<S>(&self.db, 1000, self.state.last_committed_checkpoint_id)
                .await?;
        }

        // 4. Fast Forward / Sync with Coordinator
        self.sync_to_coordinator_set_checkpoint_id().await?;

        // 5. Refresh Internal State
        let current_realm_root = self.db.global_user_tree_get_node(self.state.last_committed_checkpoint_id, self.realm_root_node).await?;
        
        self.state.last_committed_realm_end_root = current_realm_root;
        self.state.last_committed_realm_start_root = current_realm_root;
        self.state.processing_realm_start_root = current_realm_root;
        self.state.processing_realm_end_root = current_realm_root;
        self.state.gathering_realm_start_root = current_realm_root;

        // 6. Final Sync of Checkpoint Manager (Tip Verification)
        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;

        let head_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let head_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.coordinator_head_synced_checkpoint_id = head_checkpoint_id;
        self.state.coordinator_head_synced_checkpoint_root = head_checkpoint_root;
        
        // Update processing pointers
        self.state.processing_checkpoint_root = head_checkpoint_root;
        self.state.gathering_checkpoint_root = head_checkpoint_root;
        self.state.processing_checkpoint_id = head_checkpoint_id;
        self.state.gathering_checkpoint_id = head_checkpoint_id;

        // Get the root of the *last committed* checkpoint for historical consistency
        let last_committed_checkpoint_root = if self.state.last_committed_checkpoint_id == 0 {
            genesis_checkpoint_root 
        } else {
            self.checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_leaf(self.state.last_committed_checkpoint_id)
                .get_append_root::<N::HasherBase>()
        };
        self.state.last_committed_checkpoint_root = last_committed_checkpoint_root;

        // 7. Initialize Unique IDs for new work
        self.set_new_unique_ids(Some(current_realm_root)).await?;

        // Sync gatherer queue key to the new gathering proc ID so the
        // gatherer (created shortly after this, in startup.rs) polls the
        // queue that end-cap submissions will write to.
        self.guta_queue_key_status_manager
            .set_unique_id(self.state.gathering_proc_checkpoint_unique_id)?;
        
        // 8. Publish state to shared wrapper
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

/// Shared fixtures for the realm database processor tests: an in-memory
/// unified store, the real temp/proof store, fake queues and a controllable
/// coordinator client. Lives here (`db::init`) and is re-exported for the
/// sibling test modules via `db::mod`.
#[cfg(test)]
pub(crate) mod realm_db_test_env {
    use std::collections::{HashMap, VecDeque};
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use parth_core::{
        crypto::hash::{
            merkle_proof::{compute_root_merkle_proof_generic, MerkleProofCore},
            traits::MerkleZeroHasher,
        },
        data::hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::SimpleMerkleNodeKey},
        node::realm_identifier::QRealmIdentifier,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QNetworkTreeConstants,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_data::{
        config::network_config::PsyNodeCircuitFingerprintConfig,
        genesis::genesis_block_setup::PsyGenesisBlockSetupData,
        guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
        prepared_block::realm::{PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate, PsyRealmCoordinatorUpdate},
        user::complete_user_record::PsyCompactUserDefinition,
        v1::qdata::{
            checkpoint::PQEDCheckpointLeafStats,
            contract::{ContractCodeDefinition, PQBCDeployContract},
            public_key::PZKPublicKeyInfo,
        },
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
        p2p::traits::realm_coordinantor::RealmCoordinatorClient,
        psy_core_db::traits::full::PsyNodeGlobalUserTreeDatabaseReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    use crate::test_common::{
        create_test_unified_db, FakeEphemeralQueueSubscriber, FakeWorkerQueue, TestNetworkConfig,
        TestUnifiedDatabaseStore,
    };

    use super::{DatabaseCheckState, PsyRealmDatabaseProcessor};

    pub(crate) type N = TestNetworkConfig;

    pub(crate) type TestRealmProcessor = PsyRealmDatabaseProcessor<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueueSubscriber,
        FakeWorkerQueue,
        InMemoryTempStore,
        InMemoryTempStore,
        SimpleMockMemoryFileSystem,
        FakeRealmCoordinatorClient,
    >;

    pub(crate) const TEST_CHAIN_ID: u32 = 1;
    pub(crate) const TEST_REALM_ID: u64 = 1;
    pub(crate) const TEST_REALM_SUB_ID: u64 = 2;
    pub(crate) const TEST_BACKUP_PATH: &str = "realm_checkpoint_tree_backup.bin";
    pub(crate) const TEST_GUTA_BACKUP_DIR: &str = "realm_guta_backups";

    pub(crate) fn zh(level: usize) -> PHash {
        PoseidonHasher::get_zero_hash(level)
    }

    pub(crate) fn fingerprint_config() -> PsyNodeCircuitFingerprintConfig<PHash> {
        PsyNodeCircuitFingerprintConfig {
            guta_circuit_whitelist_root: zh(21),
            register_users_circuit_whitelist_root: zh(22),
            deploy_contracts_circuit_whitelist_root: zh(23),
            update_contracts_circuit_whitelist_root: zh(24),
            checkpoint_state_transition_circuit_fingerprint: zh(25),
            genesis_checkpoint_state_transition_fingerprint: zh(26),
        }
    }

    pub(crate) fn test_realm_identifier() -> QRealmIdentifier {
        QRealmIdentifier::new(TEST_REALM_ID as u32, TEST_REALM_SUB_ID as u16)
    }

    fn genesis_user(balance: u64) -> PsyCompactUserDefinition<PHash> {
        PsyCompactUserDefinition {
            public_key_info: PZKPublicKeyInfo::qp_rand_gen(),
            balance,
            nonce: 0,
            last_checkpoint_id: 0,
            event_index: 0,
            constract_state_tree_records: vec![],
        }
    }

    /// Genesis setup data with `contract_count` contracts and `user_count`
    /// users. With GROUP_REALM_HEIGHT = 1 and Strategy-5 user-id derivation,
    /// odd registration ids land in realm `TEST_REALM_ID`, so an even user
    /// count puts half of the users inside the realm under test.
    pub(crate) fn genesis_setup_data(contract_count: usize, user_count: usize) -> PsyGenesisBlockSetupData<PF, PHash> {
        let contracts = (0..contract_count)
            .map(|i| {
                PQBCDeployContract::new(
                    PHash::from_values(i as u64 + 1, 0, 0, 0),
                    ContractCodeDefinition { state_tree_height: 8, functions: vec![] },
                    vec![PHash::from_values(100 + i as u64, 0, 0, 0)],
                    PHash::from_values(200 + i as u64, 0, 0, 0),
                )
            })
            .collect();
        let users = (0..user_count).map(|i| genesis_user((i as u64 + 1) * 1_000)).collect();
        PsyGenesisBlockSetupData {
            contracts,
            users,
            checkpoint_stats: PQEDCheckpointLeafStats::qp_rand_gen(),
            deposit_tree_root: PHash::from_values(4, 0, 0, 0),
            withdrawal_tree_root: PHash::from_values(5, 0, 0, 0),
        }
    }

    pub(crate) fn build_realm_genesis(
        genesis_data: &PsyGenesisBlockSetupData<PF, PHash>,
    ) -> anyhow::Result<PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<PF, PHash>> {
        GenesisDatabaseDataBuilder::<PF, PHash>::setup_for_realm::<PoseidonHasher, N>(
            genesis_data,
            TEST_REALM_ID,
            TEST_REALM_SUB_ID,
        )
    }

    /// In-memory fake of the coordinator client the realm processor talks to.
    /// Default answers: latest checkpoint 0, realm root = default hash at
    /// checkpoint 0; tests seed leaves / sync infos / realm roots explicitly.
    #[derive(Default)]
    pub(crate) struct FakeRealmCoordinatorClient {
        pub latest_checkpoint_id: Mutex<u64>,
        /// checkpoint leaf hashes by checkpoint id (index == checkpoint id)
        pub checkpoint_leaves: Mutex<Vec<PHash>>,
        pub realm_sync_infos: Mutex<HashMap<u64, PsyRealmCoordinatorUpdate<PF, PHash>>>,
        /// realm-root states keyed by the checkpoint that last modified them;
        /// a query at id resolves to the largest key <= id
        pub realm_roots: Mutex<HashMap<u64, CheckpointedMerkleHash<PHash>>>,
        pub submitted_gutas: Mutex<Vec<(u64, Vec<u8>)>>,
        pub wait_calls: Mutex<u64>,
        /// leaves + sync infos published by the coordinator only once a waiter
        /// asks for the next checkpoint (drives the wait-loop deterministically)
        pub staged_leaves: Mutex<VecDeque<PHash>>,
        pub staged_sync_infos: Mutex<VecDeque<PsyRealmCoordinatorUpdate<PF, PHash>>>,
    }

    impl FakeRealmCoordinatorClient {
        pub(crate) fn new() -> Self {
            Self::default()
        }
        pub(crate) fn set_latest_checkpoint_id(&self, id: u64) {
            *self.latest_checkpoint_id.lock().unwrap() = id;
        }
        pub(crate) fn push_checkpoint_leaf(&self, leaf: PHash) {
            self.checkpoint_leaves.lock().unwrap().push(leaf);
        }
        pub(crate) fn seed_realm_sync_info(&self, update: PsyRealmCoordinatorUpdate<PF, PHash>) {
            let id = update.checkpoint_sync_info.checkpoint_id;
            self.realm_sync_infos.lock().unwrap().insert(id, update);
        }
        /// Stages a checkpoint to become visible on the next wait call.
        pub(crate) fn stage_checkpoint(
            &self,
            leaf: PHash,
            update: PsyRealmCoordinatorUpdate<PF, PHash>,
        ) {
            self.staged_leaves.lock().unwrap().push_back(leaf);
            self.staged_sync_infos.lock().unwrap().push_back(update);
        }
        pub(crate) fn seed_realm_root(&self, checkpoint_id: u64, value: PHash) {
            self.realm_roots
                .lock()
                .unwrap()
                .insert(checkpoint_id, CheckpointedMerkleHash { checkpoint_id, value });
        }
        pub(crate) fn clear_realm_roots(&self) {
            self.realm_roots.lock().unwrap().clear();
        }
        pub(crate) fn wait_call_count(&self) -> u64 {
            *self.wait_calls.lock().unwrap()
        }
        fn realm_root_at(&self, checkpoint_id: u64) -> CheckpointedMerkleHash<PHash> {
            let map = self.realm_roots.lock().unwrap();
            map.iter()
                .filter(|(id, _)| **id <= checkpoint_id)
                .max_by_key(|(id, _)| **id)
                .map(|(_, state)| *state)
                .unwrap_or(CheckpointedMerkleHash { checkpoint_id: 0, value: PHash::default() })
        }
    }

    #[async_trait]
    impl RealmCoordinatorClient<PF, PHash> for FakeRealmCoordinatorClient {
        async fn rc_get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
            Ok(*self.latest_checkpoint_id.lock().unwrap())
        }
        async fn rc_wait_for_next_checkpoint(&self) -> anyhow::Result<u64> {
            let mut latest = self.latest_checkpoint_id.lock().unwrap();
            *latest += 1;
            *self.wait_calls.lock().unwrap() += 1;
            // release one staged checkpoint (leaf + sync info), if any
            if let Some(leaf) = self.staged_leaves.lock().unwrap().pop_front() {
                self.checkpoint_leaves.lock().unwrap().push(leaf);
            }
            if let Some(update) = self.staged_sync_infos.lock().unwrap().pop_front() {
                self.seed_realm_sync_info(update);
            }
            Ok(*latest)
        }
        async fn rc_get_realm_sync_info(
            &self,
            checkpoint_id: u64,
            _realm_id: u64,
        ) -> anyhow::Result<PsyRealmCoordinatorUpdate<PF, PHash>> {
            self.realm_sync_infos
                .lock()
                .unwrap()
                .get(&checkpoint_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("realm sync info for checkpoint {} not seeded", checkpoint_id))
        }
        async fn rc_get_checkpoint_leaves_batch(&self, start_checkpoint_id: u64, count: u32) -> anyhow::Result<Vec<PHash>> {
            let leaves = self.checkpoint_leaves.lock().unwrap();
            let start = start_checkpoint_id as usize;
            if start >= leaves.len() {
                return Ok(vec![]);
            }
            let end = (start + count as usize).min(leaves.len());
            Ok(leaves[start..end].to_vec())
        }
        async fn rc_get_checkpoint_tree_merkle_proof(&self, _checkpoint_id: u64) -> anyhow::Result<MerkleProofCore<PHash>> {
            Ok(MerkleProofCore::default())
        }
        async fn rc_get_realm_root_and_last_modified_checkpoint(
            &self,
            checkpoint_id: u64,
            _realm_id: u64,
        ) -> anyhow::Result<CheckpointedMerkleHash<PHash>> {
            Ok(self.realm_root_at(checkpoint_id))
        }
        async fn rc_submit_guta_proof(
            &self,
            _input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType<PF, PHash>,
            proof: Vec<u8>,
            realm_id: u64,
        ) -> anyhow::Result<()> {
            self.submitted_gutas.lock().unwrap().push((realm_id, proof));
            Ok(())
        }
        async fn rc_get_contract_tree_state_heights(&self, _checkpoint_id: u64, contract_ids: Vec<u64>) -> anyhow::Result<Vec<u8>> {
            Ok(vec![8u8; contract_ids.len()])
        }
    }

    pub(crate) struct RealmDbTestEnv {
        pub processor: TestRealmProcessor,
        pub db: Arc<TestUnifiedDatabaseStore>,
        pub temp_db: Arc<InMemoryTempStore>,
        pub guta_queue: Arc<FakeEphemeralQueueSubscriber>,
        pub proof_queue: Arc<FakeWorkerQueue>,
        pub file_system: Arc<SimpleMockMemoryFileSystem>,
        pub coordinator: Arc<FakeRealmCoordinatorClient>,
        pub genesis_data: PsyGenesisBlockSetupData<PF, PHash>,
        pub genesis: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<PF, PHash>,
    }

    impl RealmDbTestEnv {
        pub(crate) async fn create() -> anyhow::Result<Self> {
            let db = Arc::new(create_test_unified_db().await?);
            let tag_tree_rewards_store = Arc::clone(&db);
            let temp_db = Arc::new(InMemoryTempStore::new("realm_proc_test".to_string(), 1, 2));
            let proof_store = Arc::clone(&temp_db);
            let guta_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
            let proof_queue = Arc::new(FakeWorkerQueue::new());
            let file_system = Arc::new(SimpleMockMemoryFileSystem::new());
            let genesis_data = genesis_setup_data(1, 4);
            let genesis = build_realm_genesis(&genesis_data)?;

            let coordinator = Arc::new(FakeRealmCoordinatorClient::new());
            // the coordinator is sitting at genesis (checkpoint 0)
            coordinator.push_checkpoint_leaf(genesis.coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash);
            coordinator.seed_realm_sync_info(genesis.coordinator_update.clone());

            let processor = TestRealmProcessor::new_init(
                Arc::clone(&db),
                tag_tree_rewards_store,
                Arc::clone(&temp_db),
                proof_store,
                Arc::clone(&guta_queue),
                Arc::clone(&proof_queue),
                Arc::clone(&coordinator),
                TEST_CHAIN_ID,
                test_realm_identifier(),
                fingerprint_config(),
                Arc::clone(&file_system),
                TEST_BACKUP_PATH.to_string(),
                genesis.prepared_updates.new_realm_root,
                genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root,
            )
            .await?;

            Ok(Self {
                processor,
                db,
                temp_db,
                guta_queue,
                proof_queue,
                file_system,
                coordinator,
                genesis_data,
                genesis,
            })
        }

        /// Drives the real genesis commit through `ensure_genesis_applied`.
        pub(crate) async fn commit_genesis(&mut self) -> anyhow::Result<()> {
            self.processor.ensure_genesis_applied(self.genesis.clone()).await
        }

        pub(crate) fn genesis_leaf_hash(&self) -> PHash {
            self.genesis.coordinator_update.checkpoint_sync_info.checkpoint_leaf_hash
        }

        /// The realm root the local database reports at checkpoint 0, i.e. the
        /// node at (COORDINATOR_GLOBAL_USER_TREE_HEIGHT, realm_id).
        pub(crate) async fn local_realm_root(&self) -> anyhow::Result<PHash> {
            Ok(self
                .db
                .global_user_tree_get_node(
                    0,
                    SimpleMerkleNodeKey { level: N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, index: TEST_REALM_ID },
                )
                .await?)
        }

        /// Seed the fake coordinator so the local post-genesis state at
        /// checkpoint 0 looks fully consistent (root matches the db).
        pub(crate) async fn seed_consistent_coordinator_head(&self) -> anyhow::Result<PHash> {
            let realm_root = self.local_realm_root().await?;
            self.coordinator.seed_realm_root(0, realm_root);
            Ok(realm_root)
        }

        /// A distinct coordinator update for checkpoint 1, as a coordinator
        /// that advanced one block past genesis would hand it out. The
        /// checkpoint-tree root is recomputed for the genesis leaf sitting at
        /// index 0, so the local checksum validation during sync accepts it.
        pub(crate) fn make_checkpoint_one_update(&self) -> PsyRealmCoordinatorUpdate<PF, PHash> {
            let second_data = genesis_setup_data(2, 4);
            let second = build_realm_genesis(&second_data).expect("second genesis builds");
            let mut update = second.coordinator_update;
            update.checkpoint_sync_info.checkpoint_id = 1;
            update.checkpoint_sync_info.block_state.checkpoint_id = 1;
            // realm genesis block states carry next_contract_id = 0 (realms do
            // not own contract registration), so set it explicitly to model a
            // coordinator that registered two contracts by checkpoint 1
            update.checkpoint_sync_info.block_state.next_contract_id = 2;
            let mut siblings = Vec::with_capacity(N::CHECKPOINT_TREE_HEIGHT_USIZE);
            siblings.push(self.genesis_leaf_hash());
            for level in 1..N::CHECKPOINT_TREE_HEIGHT_USIZE {
                siblings.push(zh(level));
            }
            update.checkpoint_sync_info.checkpoint_tree_root =
                compute_root_merkle_proof_generic::<PHash, PoseidonHasher>(
                    update.checkpoint_sync_info.checkpoint_leaf_hash,
                    1,
                    &siblings,
                );
            update
        }

        /// Seeds the fake coordinator to be one checkpoint ahead: leaf +
        /// sync info for checkpoint 1 exist, latest = 1. Returns the seeded
        /// update and the new realm root the coordinator reports at 1.
        pub(crate) fn seed_checkpoint_one(&self, update: PsyRealmCoordinatorUpdate<PF, PHash>, realm_root_at_one: PHash) {
            self.coordinator.push_checkpoint_leaf(update.checkpoint_sync_info.checkpoint_leaf_hash);
            self.coordinator.seed_realm_sync_info(update.clone());
            self.coordinator.seed_realm_root(1, realm_root_at_one);
            self.coordinator.set_latest_checkpoint_id(1);
        }

        /// Convenience state reader mirroring `get_database_check_state`.
        pub(crate) async fn check_state(&self) -> anyhow::Result<DatabaseCheckState> {
            self.processor.get_database_check_state().await
        }
    }

    /// Helper for tests that need a `SimpleMemoryMerkleRecorderStore` loaded
    /// from the db (recovery / init paths).
    pub(crate) async fn load_global_user_tree(env: &RealmDbTestEnv) -> anyhow::Result<
        parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>,
    > {
        let trees = crate::backup::realm::load_realm_memory_trees_from_db::<N, _>(
            &env.db,
            env.processor.state.gathering_checkpoint_id,
            TEST_REALM_ID,
        )
        .await?;
        Ok(trees.into_tuple().0)
    }
}

#[cfg(test)]
mod init_tests {
    use parth_core::{protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeCheckpointObjectDatabaseReader, PsyNodeCheckpointObjectDatabaseWriter,
        PsyNodeCheckpointTreeDatabaseReader,
    };

    use super::*;
    use super::realm_db_test_env::*;

    #[tokio::test]
    async fn new_init_on_fresh_database_reports_needs_genesis() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;
        let processor = &env.processor;

        // fresh database: nothing committed, no pending-id mapping
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(processor.get_database_check_state().await?, DatabaseCheckState::NeedsGenesis);

        // state recovered from the empty database defaults to genesis params
        assert_eq!(processor.state.last_committed_checkpoint_id, 0);
        assert_eq!(processor.state.last_committed_unique_pending_id, 0);
        assert_eq!(processor.state.last_committed_proc_checkpoint_unique_id, 0u128);
        // note: the db reports the zero-tree root for checkpoint 0 on a fresh
        // database (Ok, not Err), so new_init's genesis-root fallback never
        // fires and the state carries the db's zero root, not the update root
        let fresh_db_root = env.db.checkpoint_tree_get_root_hash(0).await?;
        assert_ne!(fresh_db_root, env.genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root);
        assert_eq!(processor.state.last_committed_checkpoint_root, fresh_db_root);
        // nothing is mapped yet
        assert_eq!(
            env.db
                .get_checkpoint_id_for_checkpoint_root_hash(env.genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root)
                .await?,
            None
        );
        assert_eq!(
            processor.state.last_committed_realm_end_root,
            env.genesis.prepared_updates.new_realm_root
        );
        assert_eq!(processor.state.chain_id, TEST_CHAIN_ID);
        assert_eq!(processor.state.realm_id_u64, TEST_REALM_ID);
        assert_eq!(processor.state.realm_sub_id_u64, TEST_REALM_SUB_ID);
        assert!(!processor.needs_revert);

        // realm root node points at (coordinator height, realm id)
        assert_eq!(processor.realm_root_node.level, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        assert_eq!(processor.realm_root_node.index, TEST_REALM_ID);

        // queue key manager starts parked on unique id 0
        assert_eq!(processor.guta_queue_key_status_manager.get_queue_key()?.unique_id, 0);

        // backup manager starts empty but initialized from the file
        assert_eq!(processor.checkpoint_tree_backup_manager.get_current_checkpoint_id_head(), 0);

        // the checkpoint tree backup file was created in the mock file system
        let _backup_file = env.file_system.file_like_fs_open(TEST_BACKUP_PATH).await?;
        Ok(())
    }

    #[tokio::test]
    async fn new_init_rolls_back_marker_without_pending_id_mapping() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;
        // simulate a database where latest_checkpoint_id was fast-forwarded
        // without writing the pending-id mapping for any checkpoint
        env.db.set_latest_checkpoint_id(3).await?;
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 3);

        // re-running new_init must roll the marker back to 0
        let processor = TestRealmProcessor::new_init(
            Arc::clone(&env.db),
            Arc::clone(&env.db),
            Arc::new(psy_node_store_memory::temp_store::InMemoryTempStore::new(
                "realm_rollback".to_string(),
                1,
                2,
            )),
            Arc::new(psy_node_store_memory::temp_store::InMemoryTempStore::new(
                "realm_rollback".to_string(),
                1,
                2,
            )),
            Arc::clone(&env.guta_queue),
            Arc::clone(&env.proof_queue),
            Arc::clone(&env.coordinator),
            TEST_CHAIN_ID,
            test_realm_identifier(),
            fingerprint_config(),
            Arc::clone(&env.file_system),
            format!("rollback_{}", std::process::id()),
            env.genesis.prepared_updates.new_realm_root,
            env.genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root,
        )
        .await?;

        assert_eq!(processor.state.last_committed_checkpoint_id, 0);
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn get_database_check_state_classifies_coordinator_divergence() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        // genesis commits checkpoint 0 but the pending-id counter is still 0,
        // so the state machine still classifies the db as needing genesis
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsGenesis);

        // rotating unique ids advances the pending-id counter past 0 so the
        // coordinator-consistency checks run
        env.processor.set_new_unique_ids(None).await?;

        // no realm root seeded at all: fake answers checkpoint 0 with the
        // default hash, which cannot match the local realm root
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);

        // coordinator thinks the realm changed at a checkpoint we do not have
        env.coordinator.clear_realm_roots();
        env.coordinator.seed_realm_root(3, zh(42));
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);

        // coordinator at our checkpoint but with a different realm root
        env.coordinator.clear_realm_roots();
        env.coordinator.seed_realm_root(0, zh(43));
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);

        // consistent coordinator view: Ready
        env.coordinator.clear_realm_roots();
        let seeded = env.seed_consistent_coordinator_head().await?;
        assert_ne!(seeded, PHash::default());
        assert_eq!(env.check_state().await?, DatabaseCheckState::Ready);

        // pending-id mapping pointing at a future checkpoint is an inconsistency
        env.db.set_unique_pending_id_checkpoint_id_mapping(1, 5).await?;
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_genesis_applied_persists_records_and_is_idempotent() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;

        let update = &env.genesis.coordinator_update;
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(env.db.get_l2_block_state(0).await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_checkpoint_leaf_data(0).await?, update.checkpoint_sync_info.checkpoint_leaf);
        assert_eq!(env.db.get_checkpoint_global_state_roots(0).await?, update.checkpoint_sync_info.state_roots);
        assert_eq!(
            env.db.checkpoint_tree_get_root_hash(0).await?,
            update.checkpoint_sync_info.checkpoint_tree_root
        );
        assert_eq!(
            env.db.get_checkpoint_id_for_checkpoint_root_hash(update.checkpoint_sync_info.checkpoint_tree_root).await?,
            Some(0)
        );
        // genesis is committed under unique pending id 0
        assert_eq!(env.db.get_checkpoint_id_for_unique_pending_id(0).await?, Some(0));
        assert_eq!(env.db.get_unique_pending_id_for_checkpoint_id(0).await?, Some((0, 0u128)));

        // once the pending-id counter advances, the state is no longer
        // NeedsGenesis and a second ensure call must not re-apply genesis
        env.processor.set_new_unique_ids(None).await?;
        env.seed_consistent_coordinator_head().await?;
        assert_eq!(env.check_state().await?, DatabaseCheckState::Ready);
        env.processor.ensure_genesis_applied(env.genesis.clone()).await?;
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        assert_eq!(env.check_state().await?, DatabaseCheckState::Ready);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_genesis_applied_from_setup_data_matches_prepared_update() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.processor.ensure_genesis_applied_from_setup_data(&env.genesis_data).await?;

        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        let update = &env.genesis.coordinator_update;
        assert_eq!(env.db.get_l2_block_state(0).await?, update.checkpoint_sync_info.block_state);
        assert_eq!(env.db.get_checkpoint_leaf_data(0).await?, update.checkpoint_sync_info.checkpoint_leaf);
        // the coordinator's root maps back to checkpoint 0 (the per-checkpoint
        // tree root stored by the db is the zero-slot append root, not the
        // coordinator's canonical root)
        assert_eq!(
            env.db.get_checkpoint_id_for_checkpoint_root_hash(update.checkpoint_sync_info.checkpoint_tree_root).await?,
            Some(0)
        );

        // the setup-data variant is also a no-op once genesis is applied
        env.processor.set_new_unique_ids(None).await?;
        env.seed_consistent_coordinator_head().await?;
        env.processor.ensure_genesis_applied_from_setup_data(&env.genesis_data).await?;
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_db_matches_coordinator_head_validates_all_inconsistencies() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        let local_root = env.seed_consistent_coordinator_head().await?;
        env.processor.ensure_db_matches_coordinator_head().await?;

        // local checkpoint marker ahead of the coordinator
        env.db.set_latest_checkpoint_id(2).await?;
        let err = match env.processor.ensure_db_matches_coordinator_head().await {
            Err(err) => err,
            Ok(_) => panic!("local ahead of coordinator must fail"),
        };
        assert!(err.to_string().contains("ahead of coordinator"), "unexpected error: {err}");

        // coordinator ahead of the local realm state
        env.db.set_latest_checkpoint_id(0).await?;
        env.coordinator.set_latest_checkpoint_id(2);
        env.coordinator.clear_realm_roots();
        env.coordinator.seed_realm_root(2, local_root);
        let err = match env.processor.ensure_db_matches_coordinator_head().await {
            Err(err) => err,
            Ok(_) => panic!("stale local database must fail"),
        };
        assert!(err.to_string().contains("Local database is stale"), "unexpected error: {err}");

        // realm root mismatch at the same checkpoint
        env.coordinator.set_latest_checkpoint_id(0);
        env.coordinator.clear_realm_roots();
        env.coordinator.seed_realm_root(0, zh(44));
        let err = match env.processor.ensure_db_matches_coordinator_head().await {
            Err(err) => err,
            Ok(_) => panic!("realm root mismatch must fail"),
        };
        assert!(err.to_string().contains("Realm Root mismatch"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn ensure_backup_restored_skips_checkpoints_with_unchanged_realm_root() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        env.processor.set_new_unique_ids(None).await?;
        let old_root = env.processor.state.last_committed_realm_end_root;

        // coordinator advanced to checkpoint 1 but our realm root is unchanged
        let update = env.make_checkpoint_one_update();
        env.seed_checkpoint_one(update, old_root);
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);

        let mut tree = load_global_user_tree(&env).await?;
        env.processor
            .ensure_backup_restored_if_necessary(&env.file_system, TEST_GUTA_BACKUP_DIR, &mut tree)
            .await?;

        // the unchanged checkpoint was skipped: nothing was committed locally
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        // but the checkpoint leaf for checkpoint 1 was synced into the backup manager
        assert_eq!(env.processor.checkpoint_tree_backup_manager.get_current_checkpoint_id_head(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn ensure_backup_restored_bails_on_changed_root_without_backup() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        // advance the pending-id counter so the candidate scan branch runs
        env.processor.set_new_unique_ids(None).await?;

        let changed_root = zh(55);
        let update = env.make_checkpoint_one_update();
        env.seed_checkpoint_one(update, changed_root);
        assert_eq!(env.check_state().await?, DatabaseCheckState::NeedsRecovery);

        let mut tree = load_global_user_tree(&env).await?;
        let err = match env
            .processor
            .ensure_backup_restored_if_necessary(&env.file_system, TEST_GUTA_BACKUP_DIR, &mut tree)
            .await
        {
            Err(err) => err,
            Ok(_) => panic!("recovery without a matching backup must fail"),
        };
        assert!(err.to_string().contains("no local backup found"), "unexpected error: {err}");

        // nothing was committed by the failed recovery
        assert_eq!(env.db.get_latest_checkpoint_id().await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn init_with_setup_and_genesis_rotates_ids_and_publishes_state() -> anyhow::Result<()> {
        let mut env = RealmDbTestEnv::create().await?;
        env.commit_genesis().await?;
        // the pending-id counter must advance past 0 before the state machine
        // leaves NeedsGenesis
        env.processor.set_new_unique_ids(None).await?;
        env.seed_consistent_coordinator_head().await?;
        assert_eq!(env.check_state().await?, DatabaseCheckState::Ready);

        let mut tree = load_global_user_tree(&env).await?;
        env.processor
            .init_with_setup_and_genesis(&env.file_system, TEST_GUTA_BACKUP_DIR, env.genesis.clone(), &mut tree)
            .await?;

        let state = &env.processor.state;
        assert_eq!(state.last_committed_checkpoint_id, 0);
        assert_eq!(state.coordinator_head_synced_checkpoint_id, 0);
        // init refreshes the committed root from the genesis param at
        // checkpoint 0 (unlike new_init, which falls back to the db's
        // zero-slot root)
        assert_eq!(
            state.last_committed_checkpoint_root,
            env.genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root
        );
        // unique ids rotated twice: once before the Ready check and once
        // inside init_with_setup_and_genesis, so gathering graduated to
        // processing on the second rotation
        assert_eq!(state.gathering_unique_pending_id, 2);
        assert_ne!(state.gathering_proc_checkpoint_unique_id, 0u128);
        assert_eq!(state.processing_unique_pending_id, 1);
        // all realm-root pointers converge on the committed root
        assert_eq!(state.last_committed_realm_end_root, state.processing_realm_end_root);
        assert_eq!(state.last_committed_realm_end_root, state.gathering_realm_start_root);

        // gatherer queue key was moved to the new gathering proc id
        let queue_key = env.processor.guta_queue_key_status_manager.get_queue_key()?;
        assert_eq!(queue_key.unique_id, state.gathering_proc_checkpoint_unique_id);
        assert_eq!(queue_key.realm_id, TEST_REALM_ID);
        assert_eq!(queue_key.realm_sub_id, TEST_REALM_SUB_ID);

        // consumers were ensured for the new gathering id and the genesis (0) id
        assert!(env.guta_queue.ensured_consumer_count() >= 2);
        assert!(env.proof_queue.ensured_consumers.lock().unwrap().len() >= 2);

        // shared state wrapper received the refreshed core state
        let shared = env.processor.shared_state.load_core_state().await?;
        assert_eq!(shared.gathering_unique_pending_id, 2);
        assert_eq!(shared.coordinator_head_synced_checkpoint_id, 0);
        Ok(())
    }
}
