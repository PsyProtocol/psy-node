use std::sync::{atomic::AtomicBool, Arc};

use anyhow::Ok;
use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        tag_tree::TagTreeMerkleProof,
        traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
    },
    data::{
        hash::{checkpointed_merkle_node::CheckpointedMerkleHash, merkle_node_key::SimpleMerkleNodeKey},
        queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    },
    generic_traits::psy_debug_printable::PsyDebugPrintable,
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
    backup::{checkpoint_tree::CheckpointTreeBackupManager, coordinator::generate_coordinator_output_from_backups},
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID, PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
    },
    queue::gatherer::QueueKeyStatusManager,
    realm::{
        processor::processor_shared_status::{PsyRealmProcessorSharedStatus, PsyRealmProcessorSharedStatusWrapper},
        queue_key::RealmProvingWorkQueueKey,
    },
};
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum DatabaseCheckState {
    NeedsGenesis = 0,
    NeedsRecovery = 1,
    Ready = 2,
}

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

pub struct PsyRealmDatabaseProcessor<
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    ProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
> {
    // stores
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    //queues
    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub proof_work_queue: Arc<ProofWorkQueue>,

    //checkpoint tree
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash, FileSystem>,

    // coordinator connection
    pub coordinator_client: Arc<CoordinatorClient>,
    // status
    pub is_active: Arc<AtomicBool>,
    pub guta_queue_key_status_manager: QueueKeyStatusManager<PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID, PsyRealmUserUpdateQueueItem<N::F, N::QHash>>,
    pub shared_state: RealmProcessorCoreStateWrapper<N::QHash>,
    pub needs_revert: bool,

    // state
    pub state: RealmProcessorCoreState<N::QHash>,

    pub realm_root_node: SimpleMerkleNodeKey,

    // config
    pub circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
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
    pub async fn get_next_checkpoint_id(&self) -> anyhow::Result<u64> {
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        Ok(latest_checkpoint_id + 1)
    }
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {
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
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db.get_latest_checkpoint_id().await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.db.get_current_unique_pending_id().await
    }
    pub async fn set_new_unique_ids(&mut self, gathering_realm_end_root: Option<N::QHash>) -> anyhow::Result<()> {
        println!(
            "old_unique_pending_id: {}, old_proc_checkpoint_unique_id: {}",
            self.state.processing_unique_pending_id, self.state.processing_proc_checkpoint_unique_id
        );
        println!(
            "old_gathering_unique_pending_id: {}, old_gathering_proc_checkpoint_unique_id: {}",
            self.state.processing_unique_pending_id, self.state.processing_proc_checkpoint_unique_id
        );
        let (new_gathering_unique_pending_id, new_gathering_proc_checkpoint_unique_id) = self.db.inc_unique_pending_id(1).await?;
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
    pub fn get_proof_worker_queue_key(&self) -> RealmProvingWorkQueueKey<N::QHash, N::JobId> {
        println!(
            "get_proof_worker_queue_key: self.state.processing_proc_checkpoint_unique_id: {:?}",
            self.state.processing_proc_checkpoint_unique_id
        );

        RealmProvingWorkQueueKey {
            realm_id: self.state.realm_id_u64,
            realm_sub_id: self.state.realm_sub_id_u64,
            unique_id: self.state.processing_proc_checkpoint_unique_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }
    pub async fn commit_checkpoint_state_no_guta_update(
        &mut self,
        checkpoint_sync_info: &PQEDCheckpointSyncInfoCompact<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let previous: MerkleProofCore<N::QHash> = self
            .db
            .checkpoint_tree_get_merkle_proof(checkpoint_sync_info.checkpoint_id, checkpoint_sync_info.checkpoint_id)
            .await?;
        let expected_new_checkpoint_root = previous.compute_root_with_value::<N::HasherBase>(checkpoint_sync_info.checkpoint_leaf_hash);
        if expected_new_checkpoint_root != checkpoint_sync_info.checkpoint_tree_root {
            anyhow::bail!("Inconsistent checkpoint tree root detected when committing checkpoint ID: {}. Expected root: {:?}, but got: {:?}. This indicates a serious inconsistency in the checkpoint tree state.",
                checkpoint_sync_info.checkpoint_id, expected_new_checkpoint_root, checkpoint_sync_info.checkpoint_tree_root);
        }

        self.db
            .set_l2_block_state(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.block_state)
            .await?;
        self.db
            .set_checkpoint_global_state_roots(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.state_roots)
            .await?;
        self.db
            .set_checkpoint_leaf_data(checkpoint_sync_info.checkpoint_id, &checkpoint_sync_info.checkpoint_leaf)
            .await?;
        self.db
            .checkpoint_tree_set_leaf_hash(checkpoint_sync_info.checkpoint_id, checkpoint_sync_info.checkpoint_leaf_hash)
            .await?;
        self.db
            .set_checkpoint_root_hash_to_id_mapping(checkpoint_sync_info.checkpoint_tree_root, checkpoint_sync_info.checkpoint_id)
            .await?;
        self.checkpoint_tree_backup_manager
            .append_checkpoint_leaf_hash(checkpoint_sync_info.checkpoint_id, checkpoint_sync_info.checkpoint_leaf_hash)
            .await?;

        // THIS DOES NOT SET THE LATEST CHECKPOINT ID, THAT MUST BE DONE AT THE VERY END
        // OF COMMITTING THE FULL STATE

        Ok(())
    }
    pub async fn commit_state(
        &mut self,
        coordinator_update: &PsyRealmCoordinatorUpdate<N::F, N::QHash>,
        realm_update: &PsyPreparedRealmBlockStateUpdates<N::QHash>,
        state_transition_circuit_type: ProvingJobCircuitType,
        zk_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let checkpoint_id = coordinator_update.checkpoint_sync_info.checkpoint_id;
        let unique_pending_id = self.state.processing_unique_pending_id;
        // CRITICAL: set unique_pending_id to checkpoint_id mapping BEFORE ANY OTHER
        // STATE UPDATES so we can recover if something goes wrong
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        self.db
            .set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &self.state.processing_proc_checkpoint_unique_id)
            .await?;
        tracing::info!("Set unique pending ID to checkpoint ID mapping for checkpoint ID: {}", checkpoint_id);

        self.db
            .set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(checkpoint_id, &coordinator_update.reward_tree_top_proof)
            .await?;
        self.db
            .global_user_tree_set_top_tree_merkle_proof(checkpoint_id, &coordinator_update.merkle_proof_to_realm_root)
            .await?;
        self.commit_checkpoint_state_no_guta_update(&coordinator_update.checkpoint_sync_info)
            .await?;
        tracing::info!(
            "Set rewards tag tree and global user tree top proofs for checkpoint ID: {}",
            checkpoint_id
        );

        // START STANDARD STATE UPDATES (technically these can be done in any order
        // after the above two are done) start contract updates
        if !realm_update.update_user_leaves_ffs.is_empty() {
            self.db.set_user_leaves_ffs(checkpoint_id, &realm_update.update_user_leaves_ffs).await?;
            tracing::info!("Committed user leaves ffs for checkpoint ID: {}", checkpoint_id);
            self.db
                .contract_state_tree_set_nodes_ffs(checkpoint_id, &realm_update.update_contract_state_tree_nodes_ffs)
                .await?;
            tracing::info!("Committed contract state tree updates for checkpoint ID: {}", checkpoint_id);
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
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;
        tracing::info!("Committed coordinator processor state for checkpoint ID: {}", checkpoint_id);
        tracing::info!("Backed up checkpoint tree root for checkpoint ID: {}", checkpoint_id);
        self.state.commit_processing()?;
        self.shared_state.update_from_core_state(&self.state).await?;
        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);

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
    pub async fn get_reward_tree_root(&self, checkpoint_id: u64, unique_pending_id: u64, job_id: N::JobId) -> anyhow::Result<N::QHash> {
        let temp_store_reward_tree_root: Option<N::QHash> = self
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.state.realm_identifier,
                unique_pending_id,
                job_id,
            )
            .await?;
        if temp_store_reward_tree_root.is_some() {
            let root = temp_store_reward_tree_root.unwrap();
            if root != N::QHash::get_zero_value() || unique_pending_id == 0 {
                return Ok(root);
            } else {
                tracing::warn!(
                    "Temporary store returned zero value for reward tree root at unique pending ID: {}. Falling back to permanent store.",
                    unique_pending_id
                );
            }
        }
        let reward_tree_root = self
            .tag_tree_rewards_store
            .rewards_tag_tree_get_root_at_unique_pending_id(unique_pending_id)
            .await?;
        if reward_tree_root == N::QHash::get_zero_value() && unique_pending_id != 0 {
            anyhow::bail!("Permanent store returned zero value for reward tree root at unique pending ID: {}. This indicates an inconsistency in the database state.", unique_pending_id);
        }
        Ok(reward_tree_root)
    }
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

            todo!("Implement restore from backup logic here");
        }
        Ok(())
    }

    pub async fn sync_with_coordinator(&mut self) -> anyhow::Result<()> {
        let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
        let last_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        if coordinator_latest_checkpoint_id < last_synced_checkpoint_id {
            anyhow::bail!("Local checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                last_synced_checkpoint_id, coordinator_latest_checkpoint_id);
        }
        self.checkpoint_tree_backup_manager.sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000).await?;
        self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
        self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

        self.state.processing_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.gathering_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();
        self.state.processing_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        self.state.gathering_checkpoint_id = self.state.coordinator_head_synced_checkpoint_id;
        
        Ok(())
    }

    pub async fn wait_for_realm_update_sync_with_coordinator(&mut self, new_realm_root: N::QHash) -> anyhow::Result<PsyRealmCoordinatorUpdate<N::F, N::QHash>> {
        loop {
            tracing::info!("Checking for realm root update to new value: {:?}...", new_realm_root);
            let coordinator_latest_checkpoint_id: u64 = self.coordinator_client.rc_get_latest_checkpoint_id().await?;
            let last_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
            if coordinator_latest_checkpoint_id < last_synced_checkpoint_id {
            anyhow::bail!("Local checkpoint ID ({}) is ahead of coordinator's latest checkpoint ID ({}). This indicates an inconsistency between the local database and the coordinator.",
                last_synced_checkpoint_id, coordinator_latest_checkpoint_id);
            }
            self.checkpoint_tree_backup_manager.sync_from_coordinator_client::<CoordinatorClient, N::F>(&self.coordinator_client, 2000).await?;
            self.state.coordinator_head_synced_checkpoint_id = self.checkpoint_tree_backup_manager.get_current_checkpoint_id_head();
            self.state.coordinator_head_synced_checkpoint_root = self.checkpoint_tree_backup_manager.get_current_checkpoint_tree_root_head();

            let latest_realm_root: CheckpointedMerkleHash<N::QHash> = self
                .coordinator_client
                .rc_get_realm_root_and_last_modified_checkpoint(self.state.coordinator_head_synced_checkpoint_id, self.state.realm_id_u64)
                .await?;
            if latest_realm_root.value == new_realm_root {
                tracing::info!("Realm root has been updated to the new value: {:?} at checkpoint ID: {}", new_realm_root, latest_realm_root.checkpoint_id);
                self.state.last_committed_checkpoint_id = latest_realm_root.checkpoint_id;
                self.state.last_committed_realm_end_root = latest_realm_root.value;
                self.state.last_committed_proc_checkpoint_unique_id = self.state.processing_proc_checkpoint_unique_id;
                self.state.last_committed_unique_pending_id = self.state.processing_unique_pending_id;
                let sync_info : PsyRealmCoordinatorUpdate<N::F, N::QHash> = self.coordinator_client.rc_get_realm_sync_info(latest_realm_root.checkpoint_id).await?;
                self.db.set_realm_rewards_tag_tree_top_proof_at_checkpoint_id(latest_realm_root.checkpoint_id, &sync_info.reward_tree_top_proof).await?;
                self.db.global_user_tree_set_top_tree_merkle_proof(latest_realm_root.checkpoint_id, &sync_info.merkle_proof_to_realm_root).await?;
                self.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(self.state.last_committed_unique_pending_id, &sync_info.reward_tree_top_proof).await?;
                self.db.set_l2_block_state(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.block_state).await?;
                self.db.set_checkpoint_global_state_roots(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.state_roots).await?;
                self.db.set_checkpoint_leaf_data(latest_realm_root.checkpoint_id, &sync_info.checkpoint_sync_info.checkpoint_leaf).await?;    
                return Ok(sync_info);
            }else{
                tracing::info!("Waiting for realm root to be updated to the new value: {:?}. Current realm root at checkpoint ID {} is {:?}. Retrying...", new_realm_root, latest_realm_root.checkpoint_id, latest_realm_root.value);
                self.coordinator_client.rc_wait_for_next_checkpoint().await?;
            }
        }
        
    }

    pub fn print_coordinator_processor_state(&self) {
        tracing::info!(
            r#"======== Realm Processor State ========
[STATE]
{:#?}
[/STATE]
============================================="#,
            self.state,
        );
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
