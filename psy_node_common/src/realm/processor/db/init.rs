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
        network: psy_core::constants::chain_id::PsyChainNetworkType,
        recording: psy_node_core::store::realm_commit_recording::RealmCommitRecording<N::QHash>,
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
            recording,
            network_id: psy_data::protocol::canonical_chain::NetworkId::from_network_type(network),
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
