use std::sync::{atomic::AtomicBool, Arc};

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
    prepared_block::realm::PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate,
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
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        
        // 1. Check for Genesis requirement
        if local_latest_checkpoint_id == 0 {
            // Check if we actually have genesis applied (unique IDs > 0 usually implies initialization)
            let (last_unique_pending_id, _) = self.db.get_current_unique_pending_id().await?;
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
        let (last_unique_pending_id, _) = self.db.get_current_unique_pending_id().await?;
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

        // 1. Recover basic state from DB
        let (current_unique_pending_id, current_core_proc_unique_pending_id) = db.get_current_unique_pending_id().await?;
        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;

        // 2. Validate consistency of unique pending IDs
        let get_unique_pending_ids_result = db.get_unique_pending_id_for_checkpoint_id(last_committed_checkpoint_id).await;
        
        let (last_committed_unique_pending_id, last_committed_proc_checkpoint_unique_id) = match get_unique_pending_ids_result {
            Ok(Some(res)) => res,
            Ok(None) if last_committed_checkpoint_id == 0 => (0, 0u128),
            Ok(None) => {
                tracing::error!("DB Inconsistency: No unique pending ID for last committed checkpoint {}", last_committed_checkpoint_id);
                anyhow::bail!("DB Inconsistency: No unique pending ID for last committed checkpoint");
            }
            Err(e) => {
                if last_committed_checkpoint_id == 0 {
                    (0, 0u128)
                } else {
                    return Err(e);
                }
            }
        };

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

        // Initialize unique ID tracking in temp DB
        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;

        temp_db
            .set_gathering_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;

        Ok(Self {
            db,
            is_active: Arc::new(AtomicBool::new(true)),
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
            >::new(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }),
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
        if coordinator_realm_root_state.value != local_realm_root_state.value || coordinator_realm_root_state.checkpoint_id > local_realm_root_state.checkpoint_id {
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

            // 2. Identify the target checkpoint for restoration
            let target_realm_state = self
                .coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.state.realm_id_u64)
                .await?;
            
            let restore_checkpoint_id = target_realm_state.checkpoint_id;
            tracing::info!("Restoring to Coordinator Realm Root at Checkpoint {}", restore_checkpoint_id);

            // 3. Fetch Full Coordinator Update Data for that checkpoint
            let coordinator_update = self.coordinator_client.rc_get_realm_sync_info(restore_checkpoint_id, self.state.realm_id_u64).await?;

            // 4. Generate local updates from backup files corresponding to that state
            let prepared_updates = generate_realm_output_from_backups::<N, FileSystem>(
                file_system,
                guta_gatherer_backup_directory,
                &self.state, // Note: verify if self.state has correct pending IDs for finding the file?
                global_user_tree,
            )
            .await?;

            // 5. Commit state to DB
            self.commit_state(
                &coordinator_update,
                &prepared_updates,
                ProvingJobCircuitType::GUTANoChange, // Dummy type for recovery
                vec![],
            ).await?;

            tracing::info!("Recovery Complete. Restored to Checkpoint {}.", restore_checkpoint_id);

            // 6. Verify Post-Recovery
            let latest_realm_root = self.get_realm_root_from_db().await?;
            if latest_realm_root != target_realm_state.value {
                anyhow::bail!("Post-recovery root mismatch! Local: {:?}, Target: {:?}", latest_realm_root, target_realm_state.value);
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
        // self.ensure_genesis_applied(genesis_block_update).await?;

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
