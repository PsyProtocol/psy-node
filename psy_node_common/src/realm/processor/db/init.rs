use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Ok;
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
    QCoreProcCheckpointUniqueId,
};
use psy_core::{
    constants::stale_checkpoint::{STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF, STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF},
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    node::realm_processor::{RealmProcessorCoreState, RealmProcessorCoreStateWrapper},
    prepared_block::realm::{PsyPreparedRealmBlockStateUpdates, PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate, PsyRealmCoordinatorUpdate},
    protocol::{
        checkpoint_transition_hash::CheckpointStateHashTransition,
        verifiable_checkpoint_transition::{self, PsyVerifiableCheckpointTransition, PsyVerifiableCheckpointTransitionWithProof},
    },
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::{
        checkpoint::QEDL2BlockState, checkpoint_sync::PQEDCheckpointSyncInfoCompact, contract::PsyDeployContractQueueItem,
        public_key::PZKPublicKeyInfo,
    },
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
    backup::{checkpoint_tree::CheckpointTreeBackupManager, coordinator::generate_coordinator_output_from_backups, realm::generate_realm_output_from_backups},
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    },
    queue::gatherer::QueueKeyStatusManager,
    realm::{
        processor::{db::{DatabaseCheckState, PsyRealmDatabaseProcessor}, processor_shared_status::{PsyRealmProcessorSharedStatus, PsyRealmProcessorSharedStatusWrapper}},
        queue_key::RealmProvingWorkQueueKey,
    },
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
        let realm_root = self.get_realm_root_from_db().await?;
        let coordinator_realm_root: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(u64::MAX-0xffff, self.state.realm_id_u64)
            .await?;
        if coordinator_realm_root.value != realm_root {
            tracing::info!("Realm root in database ({:?}) does not match coordinator's realm root ({:?}) for realm ID: {}. Database needs recovery.",
                realm_root, coordinator_realm_root.value, self.state.realm_id_u64);
            return Ok(DatabaseCheckState::NeedsRecovery);
        }

        let actual_latest_applied_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        let (last_unique_pending_id, _last_unique_proc_checkpoint_id): (u64, QCoreProcCheckpointUniqueId) =
            self.db.get_current_unique_pending_id().await?;

        let expected_checkpoint_id: Option<u64> = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;
        let database_check_state = if expected_checkpoint_id.is_none() && actual_latest_applied_checkpoint_id == 0 {
            // needs genesis
            DatabaseCheckState::NeedsGenesis
        } else if expected_checkpoint_id.is_none() {
            // died before setting anything in the database, we don't need to recover
            DatabaseCheckState::Ready
        } else {
            let expected_checkpoint_id = expected_checkpoint_id.unwrap();
            if expected_checkpoint_id != actual_latest_applied_checkpoint_id {
                if expected_checkpoint_id < actual_latest_applied_checkpoint_id {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is less than actual latest applied checkpoint ID ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id);
                } else if expected_checkpoint_id > actual_latest_applied_checkpoint_id + 1 {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is greater than actual latest applied checkpoint ID + 1 ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id + 1);
                } else if expected_checkpoint_id == 0 {
                    // needs genesis
                    DatabaseCheckState::NeedsGenesis
                } else {
                    // needs recovery
                    DatabaseCheckState::NeedsRecovery
                }
            } else {
                DatabaseCheckState::Ready
            }
        };
        Ok(database_check_state)
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
            index: realm_id_u64 << N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
        };

        let (current_unique_pending_id, current_core_proc_unique_pending_id) = db.get_current_unique_pending_id().await?;
        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;

        let get_unique_pending_ids_result = db.get_unique_pending_id_for_checkpoint_id(last_committed_checkpoint_id).await;
        if last_committed_checkpoint_id > 0 && get_unique_pending_ids_result.is_err() {
            tracing::error!("Inconsistent database state detected: unable to retrieve unique pending IDs for last committed checkpoint ID ({}). This indicates a serious inconsistency in the database state.", last_committed_checkpoint_id);
            anyhow::bail!("Inconsistent database state detected: unable to retrieve unique pending IDs for last committed checkpoint ID ({}). This indicates a serious inconsistency in the database state.", last_committed_checkpoint_id);
        }

        let (last_committed_unique_pending_id, last_committed_proc_checkpoint_unique_id) =
            get_unique_pending_ids_result.unwrap_or(Some((0, 0u128))).unwrap();
        let last_committed_checkpoint_root = db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await;
        if last_committed_checkpoint_root.is_err() {
            if last_committed_checkpoint_id == 0 && current_unique_pending_id == 0 {
                // genesis case
            } else {
                tracing::error!("Inconsistent database state detected: unable to retrieve checkpoint tree root hash for last committed checkpoint ID ({}). This indicates a serious inconsistency in the database state.", last_committed_checkpoint_id);
                anyhow::bail!("Inconsistent database state detected: unable to retrieve checkpoint tree root hash for last committed checkpoint ID ({}). This indicates a serious inconsistency in the database state.", last_committed_checkpoint_id);
            }
        }
        let last_committed_checkpoint_root = last_committed_checkpoint_root.unwrap_or(genesis_checkpoint_root);
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

        let mut checkpoint_tree_backup_manager = create_new_checkpoint_backup_manager_from_file_path(
            file_system.clone(),
            STALE_CHECKPOINT_AGE_USER_END_CAP_TO_REALM_PROOF,
            N::CHECKPOINT_TREE_HEIGHT,
            &db,
            &checkpoint_tree_root_backup_file_path,
            true,
        )
        .await?;
        checkpoint_tree_backup_manager
            .sync_from_database::<S>(&db, 1000, last_committed_checkpoint_id)
            .await?;
        checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&coordinator_client, 10000)
            .await?;

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
        // Check if genesis has already been applied
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to coordinator processor database...");
            self.commit_state(
                &genesis_block_update.coordinator_update,
                &genesis_block_update.prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
            )
            .await?;
            tracing::info!("Genesis block setup data applied to coordinator processor database.");
        }
        Ok(())
    }

    pub async fn ensure_genesis_applied_from_setup_data(&mut self, genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>) -> anyhow::Result<()> {
        // Check if genesis has already been applied
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to coordinator processor database...");
            let genesis_block_update =
                GenesisDatabaseDataBuilder::setup_for_realm::<N::HasherBase, N>(&genesis_data, self.state.realm_id_u64, self.state.realm_sub_id_u64)?;
            self.commit_state(
                &genesis_block_update.coordinator_update,
                &genesis_block_update.prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
            )
            .await?;
            tracing::info!("Genesis block setup data applied to coordinator processor database.");
        }
        Ok(())
    }

    pub async fn ensure_db_matches_coordinator_head(&self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let local_latest_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        if coordinator_latest_checkpoint_id < local_latest_checkpoint_id {
            anyhow::bail!("Local database checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                local_latest_checkpoint_id, coordinator_latest_checkpoint_id);
        }

        let coordinator_last_realm_root: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.state.realm_id_u64)
            .await?;
        let local_last_realm_root = self
            .db
            .global_user_tree_get_node_and_checkpoint_id_max_checkpoint(coordinator_latest_checkpoint_id, &self.realm_root_node)
            .await?;
        if coordinator_last_realm_root != local_last_realm_root {
            anyhow::bail!("Local database realm root ({:?}) does not match coordinator's realm root ({:?}) at checkpoint ID: {}. This indicates an inconsistency between the local database and the coordinator.",
                local_last_realm_root, coordinator_last_realm_root, coordinator_latest_checkpoint_id);
        }
        if local_latest_checkpoint_id < coordinator_last_realm_root.checkpoint_id {
            anyhow::bail!("Local database checkpoint ID ({}) is behind the coordinator's realm root last modified checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                local_latest_checkpoint_id, coordinator_last_realm_root.checkpoint_id);
        }

        if coordinator_latest_checkpoint_id > local_latest_checkpoint_id {
            tracing::info!("realm root is correctly synced with coordinator, but we need to sync checkpooint data from coordinator. Local checkpoint ID: {}, Coordinator checkpoint ID: {}",
                local_latest_checkpoint_id, coordinator_latest_checkpoint_id);
            // we need to sync data from coordinator
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
            // wait for two checkpoints to ensure the coordinator has progressed
            self.coordinator_client.rc_wait_for_next_checkpoint().await?;
            self.coordinator_client.rc_wait_for_next_checkpoint().await?;
            let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            self.checkpoint_tree_backup_manager
                .sync_from_coordinator_client::<_, N::F>(&self.coordinator_client, 2000)
                .await?;

            let realm_root_with_id: CheckpointedMerkleHash<N::QHash> = self
                .coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(coordinator_latest_checkpoint_id, self.state.realm_id_u64)
                .await?;
            let (local_latest_unique_pending_id, _): (u64, _) = self.db.get_current_unique_pending_id().await?;

            let restore_checkpoint_id = realm_root_with_id.checkpoint_id;

            let coordinator_update: PsyRealmCoordinatorUpdate<N::F, N::QHash> = self.coordinator_client.rc_get_realm_sync_info(restore_checkpoint_id).await?;

            let prepared_updates = generate_realm_output_from_backups::<N, FileSystem>(
                file_system,
                guta_gatherer_backup_directory,
                &self.state,
                global_user_tree,
            )
            .await?;


            self.commit_state(
                &coordinator_update,
                &prepared_updates,
                ProvingJobCircuitType::GUTANoChange,
                vec![],
            ).await?;
            tracing::info!("Restored database state from backups up to checkpoint ID: {}",
                restore_checkpoint_id);

            let latest_realm_root = self.get_realm_root_from_db().await?;
            if latest_realm_root != realm_root_with_id.value {
                tracing::error!("Post-recovery realm root ({:?}) does not match expected realm root from coordinator ({:?}) at checkpoint ID: {}. This indicates an inconsistency after recovery.",
                    latest_realm_root, realm_root_with_id.value, restore_checkpoint_id);
                anyhow::bail!("Post-recovery realm root ({:?}) does not match expected realm root from coordinator ({:?}) at checkpoint ID: {}. This indicates an inconsistency after recovery.",
                    latest_realm_root, realm_root_with_id.value, restore_checkpoint_id);
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
        self.ensure_genesis_applied(genesis_block_update).await?;
        self.ensure_backup_restored_if_necessary(file_system, guta_gatherer_backup_directory, global_user_tree)
            .await?;
        self.sync_to_coordinator_set_checkpoint_id().await?;

        let global_user_tree_root = self.db.global_user_tree_get_root_hash(0xffffffffffffff00u64).await?;
        let last_commited_realm_root: CheckpointedMerkleHash<N::QHash> = self
            .coordinator_client
            .rc_get_realm_root_and_last_modified_checkpoint(0xffffffffffffff00u64, self.state.realm_id_u64)
            .await?;

        self.state.last_committed_checkpoint_id = last_commited_realm_root.checkpoint_id;
        self.state.last_committed_realm_end_root = last_commited_realm_root.value;

        self.state.last_committed_realm_end_root = global_user_tree_root;
        self.state.last_committed_realm_start_root = global_user_tree_root;
        self.state.processing_realm_start_root = global_user_tree_root;
        self.state.processing_realm_end_root = global_user_tree_root;
        self.state.gathering_realm_start_root = global_user_tree_root;

        self.checkpoint_tree_backup_manager
            .sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000)
            .await?;

        self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        let checkpoint_root = self.checkpoint_tree_backup_manager.checkpoint_tree.get_root();
        self.state.processing_checkpoint_root = checkpoint_root;
        self.state.gathering_checkpoint_root = checkpoint_root;
        self.state.processing_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        let last_committed_checkpoint_root = self
            .checkpoint_tree_backup_manager
            .checkpoint_tree
            .get_leaf(self.state.last_committed_checkpoint_id)
            .get_append_root::<N::HasherBase>();
        self.state.last_committed_checkpoint_root = last_committed_checkpoint_root;

        self.set_new_unique_ids(Some(global_user_tree_root)).await?;
        self.shared_state.update_from_core_state(&self.state).await?;

        tracing::info!(
            "[COORDINATOR] Started with checkpoint ID: {}, unique pending ID: {}",
            self.state.coordinator_head_synced_checkpoint_id,
            self.state.gathering_unique_pending_id,
        );
        self.print_coordinator_processor_state();
        Ok(())
    }
}
