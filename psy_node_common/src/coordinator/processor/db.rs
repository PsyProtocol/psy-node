use std::sync::{Arc, atomic::AtomicBool};

use parth_common::memory_stores::{mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
    }, data::queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey}, generic_traits::psy_debug_printable::PsyDebugPrintable, node::realm_identifier::QRealmIdentifier, protocol::core_types::{Q256BitHash, QNetworkTypesConfig}
};
use psy_core::{
    constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
    job::job_id::{ProvingJobCircuitType, QProvingJobDataID},
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    node::coordinator_processor::{CoordinatorProcessorIdState, CoordinatorProcessorLastCommittedState},
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::{
        checkpoint_transition_hash::CheckpointStateHashTransition,
        verifiable_checkpoint_transition::{self, PsyVerifiableCheckpointTransition, PsyVerifiableCheckpointTransitionWithProof},
    },
    v1::qdata::{checkpoint::QEDL2BlockState, contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo},
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    psy_core_db::traits::full::{
        PsyCoordinatorProcessorStore, PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::{checkpoint_tree::{CheckpointTreeBackupManager}, coordinator::generate_coordinator_output_from_backups},
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    },
    coordinator::{
        processor::processor_shared_status::{PsyCoordinatorProcessorSharedStatus, PsyCoordinatorProcessorSharedStatusWrapper},
        queue_key::CoordinatorProvingWorkQueueKey,
    },
    queue::gatherer::QueueKeyStatusManager,
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

pub struct PsyCoordinatorDatabaseProcessor<
    N: QNetworkTypesConfig,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber,
    DeployContractQueue: QStandardEphemeralQueueSubscriber,
    ProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem,
> {
    // stores
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    //queues
    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub register_user_queue: Arc<RegisterUserQueue>,
    pub deploy_contract_queue: Arc<DeployContractQueue>,
    pub proof_work_queue: Arc<ProofWorkQueue>,

    //checkpoint tree
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash, FileSystem>,

    // status
    pub is_active: Arc<AtomicBool>,
    pub guta_queue_key_status_manager: QueueKeyStatusManager<
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<N::F, N::QHash>,
    >,
    pub register_user_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PZKPublicKeyInfo<N::QHash>>,
    pub deploy_contract_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PsyDeployContractQueueItem<N::F, N::QHash>>,
    pub shared_status: PsyCoordinatorProcessorSharedStatusWrapper<N::F, N::QHash>,
    pub needs_revert: bool,

    // state
    pub last_committed: CoordinatorProcessorLastCommittedState<N::F, N::QHash>,
    pub ids: CoordinatorProcessorIdState,

    // config
    pub circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    pub genesis_checkpoint_state_transition_hash: N::QHash,
    pub genesis_verifiable_state_transition: PsyVerifiableCheckpointTransition<N::F, N::QHash>,
}

impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber,
        DeployContractQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    > where N::HasherBase: 'static + Send + Sync
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
        } else if expected_checkpoint_id.is_none(){
            // died before setting anything in the database, we don't need to recover
            DatabaseCheckState::Ready 
        }else{
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
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        proof_work_queue: Arc<ProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
        genesis_verifiable_state_transition: PsyVerifiableCheckpointTransition<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        checkpoint_tree_root_backup_file_path: String,
    ) -> anyhow::Result<Self> {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;

        let (current_unique_pending_id, current_core_proc_unique_pending_id) = db.get_current_unique_pending_id().await?;
        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;

        let ids = CoordinatorProcessorIdState {
            realm_identifier: realm_identifier.clone(),
            realm_id_u64,
            realm_sub_id_u64,
            checkpoint_id: last_committed_checkpoint_id,
            next_checkpoint_id: last_committed_checkpoint_id + 1,
            unique_pending_id: current_unique_pending_id,
            proc_checkpoint_unique_id: current_core_proc_unique_pending_id,
            gathering_unique_pending_id: current_unique_pending_id,
            gathering_proc_checkpoint_unique_id: current_core_proc_unique_pending_id,
        };

        let mut checkpoint_tree_backup_manager = create_new_checkpoint_backup_manager_from_file_path(
            file_system.clone(),
            STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
            N::CHECKPOINT_TREE_HEIGHT,
            &db,
            &checkpoint_tree_root_backup_file_path,
            true,
        )
        .await?;
        checkpoint_tree_backup_manager
            .sync_from_database::<S>(&db, 1000, last_committed_checkpoint_id)
            .await?;

        let shared_status = if last_committed_checkpoint_id == 0 {
            PsyCoordinatorProcessorSharedStatus {
                last_committed_checkpoint_id,
                unique_pending_id: current_unique_pending_id,
                last_committed_checkpoint_leaf: genesis_verifiable_state_transition.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>(),
                last_committed_checkpoint_state_roots: genesis_verifiable_state_transition.checkpoint_leaf.global_state_roots.clone(),
                should_revert_last_changes: false,
                block_state: QEDL2BlockState {
                    checkpoint_id: 0,
                    next_add_withdrawal_id: 0,
                    next_process_withdrawal_id: 0,
                    next_deposit_id: 0,
                    total_deposits_claimed_epoch: 0,
                    next_user_id: 0,
                    end_balance: 0,
                    next_contract_id: 0,
                },
            }
        } else {
            PsyCoordinatorProcessorSharedStatus {
                last_committed_checkpoint_id,
                unique_pending_id: current_unique_pending_id,
                last_committed_checkpoint_leaf: db.get_checkpoint_leaf_data(last_committed_checkpoint_id).await?,
                last_committed_checkpoint_state_roots: db.get_checkpoint_global_state_roots(last_committed_checkpoint_id).await?,
                should_revert_last_changes: false,
                block_state: db.get_l2_block_state(last_committed_checkpoint_id).await?,
            }
        };

        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;
        let last_committed_l2_state = shared_status.block_state.clone();
        let last_committed_checkpoint_leaf = shared_status.last_committed_checkpoint_leaf.clone();
        let last_committed_checkpoint_root = db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await?;
        let last_committed_checkpoint_state_roots = shared_status.last_committed_checkpoint_state_roots.clone();
        let last_committed_checkpoint_leaf_stats = last_committed_checkpoint_leaf.stats.clone();
        let last_committed_checkpoint_state_transition = if last_committed_checkpoint_id == 0 {
            genesis_verifiable_state_transition.state_transition.checkpoint_transition.clone()
        } else {
            CheckpointStateHashTransition {
                old_checkpoint_tree_root: db.checkpoint_tree_get_root_hash(last_committed_checkpoint_id - 1).await?,
                new_checkpoint_tree_root: last_committed_checkpoint_root,
                old_checkpoint_leaf_hash: db
                    .checkpoint_tree_get_leaf_hash(last_committed_checkpoint_id, last_committed_checkpoint_id - 1)
                    .await?,
                new_checkpoint_leaf_hash: last_committed_checkpoint_leaf.qfhash::<N::HasherBase>(),
            }
        };
        let last_committed = CoordinatorProcessorLastCommittedState::<N::F, N::QHash> {
            l2_state: last_committed_l2_state,
            checkpoint_leaf_stats: last_committed_checkpoint_leaf_stats,
            checkpoint_leaf: last_committed_checkpoint_leaf,
            checkpoint_state_roots: last_committed_checkpoint_state_roots,
            checkpoint_state_transition: last_committed_checkpoint_state_transition,
            checkpoint_root: last_committed_checkpoint_root,
            checkpoint_leaf_hash: last_committed_checkpoint_leaf.qfhash::<N::HasherBase>(),
        };
        Ok(Self {
            db,
            is_active: Arc::new(AtomicBool::new(true)),
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            guta_update_queue,
            register_user_queue,
            deploy_contract_queue,
            proof_work_queue,
            checkpoint_tree_backup_manager,
            shared_status: PsyCoordinatorProcessorSharedStatusWrapper::new(shared_status),

            circuit_fingerprint_config,
            genesis_verifiable_state_transition,
            guta_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
                GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<N::F, N::QHash>,
            >::new(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }),
            register_user_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
                PZKPublicKeyInfo<N::QHash>,
            >::new(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }),
            deploy_contract_queue_key_status_manager: QueueKeyStatusManager::<
                PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID,
                PsyDeployContractQueueItem<N::F, N::QHash>,
            >::new(QPStandardUniqueIdQueueKey {
                realm_id: realm_id_u64,
                realm_sub_id: realm_sub_id_u64,
                unique_id: current_core_proc_unique_pending_id,
                task_group: 0,
                queue_type: QPBaseQueueType::StandardEphemeral,
                _phantom_queue_item: std::marker::PhantomData,
            }),
            needs_revert: false,
            genesis_checkpoint_state_transition_hash: genesis_verifiable_state_transition
                .state_transition
                .checkpoint_transition
                .qfhash::<N::HasherBase>(),
            last_committed,
            ids,
        })
    }

    pub async fn ensure_genesis_applied(
        &mut self,
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        // Check if genesis has already been applied
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsGenesis {
            tracing::info!("Applying genesis block setup data to coordinator processor database...");
            self.commit_state(genesis_block_update, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, vec![])
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
            let (_, genesis_block_update) = GenesisDatabaseDataBuilder::setup_for_coordinator::<N::HasherBase, N>(
                &genesis_data,
                self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
            )?;
            self.commit_state(genesis_block_update, ProvingJobCircuitType::GenesisBlockCheckpointStateTransition, vec![])
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
    pub async fn set_new_unique_ids(&mut self) -> anyhow::Result<()> {
        let (new_unique_pending_id, new_core_proc_unique_pending_id) = self.db.inc_unique_pending_id(1).await?;
        self.ids.unique_pending_id = self.ids.gathering_unique_pending_id;
        self.ids.proc_checkpoint_unique_id = self.ids.gathering_proc_checkpoint_unique_id;
        self.ids.gathering_unique_pending_id = new_unique_pending_id;
        self.ids.gathering_proc_checkpoint_unique_id = new_core_proc_unique_pending_id;
        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.ids.realm_identifier,
                self.ids.gathering_unique_pending_id,
                self.ids.gathering_proc_checkpoint_unique_id,
            )
            .await?;
        self.temp_db
            .set_unique_pending_ids(&self.ids.realm_identifier, self.ids.unique_pending_id, self.ids.proc_checkpoint_unique_id)
            .await?;

        Ok(())
    }
    pub fn get_proof_worker_queue_key(&self) -> CoordinatorProvingWorkQueueKey<N::QHash, N::JobId> { 
        println!("get_proof_worker_queue_key: self.db.ids.proc_checkpoint_unique_id: {:?}", self.ids.proc_checkpoint_unique_id);
       
        CoordinatorProvingWorkQueueKey {
            realm_id: self.ids.realm_id_u64,
            realm_sub_id: self.ids.realm_sub_id_u64,
            unique_id: self.ids.proc_checkpoint_unique_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }
    pub async fn commit_state(
        &mut self,
        coordinator_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        state_transition_circuit_type: ProvingJobCircuitType,
        zk_proof: Vec<u8>,
    ) -> anyhow::Result<()> {
        let checkpoint_id = coordinator_update.checkpoint_id;
        tracing::info!("vaidation -> Committing coordinator state update to database for checkpoint_id: {}", checkpoint_id);
        let checkpoint_leaf_hash = coordinator_update.new_base.checkpoint_leaf.qfhash::<N::HasherBase>();
        if checkpoint_leaf_hash != coordinator_update.new_base.checkpoint_leaf_hash {
            tracing::error!(
                "Computed checkpoint leaf hash: {:?}, expected checkpoint leaf hash: {:?}",
                checkpoint_leaf_hash,
                coordinator_update.new_base.checkpoint_leaf_hash
            );
            anyhow::bail!(
                "Checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                checkpoint_leaf_hash,
                coordinator_update.new_base.checkpoint_leaf_hash
            );
        }

        let old_checkpoint_leaf_hash = coordinator_update.old_base.checkpoint_leaf_hash;
        if old_checkpoint_leaf_hash != self.last_committed.checkpoint_leaf_hash {
            tracing::error!(
                "Computed old checkpoint leaf hash: {:?}, expected old checkpoint leaf hash: {:?}",
                self.last_committed.checkpoint_leaf_hash,
                old_checkpoint_leaf_hash
            );
            anyhow::bail!(
                "Old checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                self.last_committed.checkpoint_leaf_hash,
                old_checkpoint_leaf_hash
            );
        }

        let old_checkpoint_root = self.db.checkpoint_tree_get_root_hash(checkpoint_id).await?;
        if checkpoint_id != 0 && old_checkpoint_root != coordinator_update.old_base.checkpoint_tree_root {
            let actual_checkpoint_root = self.checkpoint_tree_backup_manager.checkpoint_tree.get_root();
            tracing::error!(
                "Computed old checkpoint tree root hash: {:?}, expected old checkpoint tree root hash: {:?}, actual root from backup manager: {:?}",
                old_checkpoint_root,
                coordinator_update.old_base.checkpoint_tree_root,
                actual_checkpoint_root
            );
            anyhow::bail!("Old checkpoint tree root hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}", old_checkpoint_root, coordinator_update.old_base.checkpoint_tree_root);
        }

        tracing::info!("start -> Committing coordinator state update to database for checkpoint_id: {}", checkpoint_id);

        let mut verifiable_checkpoint_transition = coordinator_update.get_public_inputs_verifiable_state_transition(
            self.genesis_checkpoint_state_transition_hash,
            self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        );
        if checkpoint_id == 0 {
            verifiable_checkpoint_transition.state_transition.checkpoint_transition.old_checkpoint_tree_root = verifiable_checkpoint_transition.state_transition.checkpoint_transition.new_checkpoint_tree_root;
            verifiable_checkpoint_transition.state_transition.checkpoint_transition.old_checkpoint_leaf_hash = verifiable_checkpoint_transition.state_transition.checkpoint_transition.new_checkpoint_leaf_hash;
        }

        let verifiable_checkpoint_transition_with_proof = PsyVerifiableCheckpointTransitionWithProof {
            info: verifiable_checkpoint_transition,
            circuit_type: state_transition_circuit_type as u32,
            zk_proof,
        };
        let unique_pending_id = coordinator_update.unique_pending_id;

        let contract_tree_heights = coordinator_update
            .new_contract_code_definitions
            .iter()
            .enumerate()
            .map(|(ind, c)| {
                (
                    (coordinator_update.old_base.block_state.next_contract_id as u64 + ind as u64),
                    c.code_definition.state_tree_height as u8,
                )
            })
            .collect::<Vec<(u64, u8)>>();

        // CRITICAL: save the ZKP we generated FIRST before any state updates
        self.db
            .set_verifiable_checkpoint_state_transition_and_zkp(checkpoint_id, &verifiable_checkpoint_transition_with_proof)
            .await?;
        tracing::info!("Saved verifiable checkpoint state transition and ZKP for checkpoint ID: {}", checkpoint_id);
        // CRITICAL: set unique_pending_id to checkpoint_id mapping BEFORE ANY OTHER
        // STATE UPDATES so we can recover if something goes wrong
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        self.db.set_checkpoint_id_to_unique_pending_id_mapping(checkpoint_id, unique_pending_id, &self.ids.proc_checkpoint_unique_id).await?;
        tracing::info!("Set unique pending ID to checkpoint ID mapping for checkpoint ID: {}", checkpoint_id);
        // START STANDARD STATE UPDATES (technically these can be done in any order
        // after the above two are done) start contract updates
        if !coordinator_update.new_contract_leaves_ffs.is_empty() {
            self.db
                .set_contract_leaves_ffs(checkpoint_id, &coordinator_update.new_contract_leaves_ffs)
                .await?;
            self.db
                .set_many_contract_code_definitions(checkpoint_id, &coordinator_update.new_contract_code_definitions)
                .await?;
            self.db.set_contract_tree_heights(checkpoint_id, &contract_tree_heights).await?;
            self.db
                .contract_function_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_contract_function_tree_nodes_ffs)
                .await?;
            self.db
                .global_contract_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_global_contract_tree_nodes_ffs)
                .await?;
        }
        tracing::info!("Committed contract state updates for checkpoint ID: {}", checkpoint_id);
        // start user registraion updates
        if !coordinator_update.new_user_public_keys_ffs.is_empty() {
            println!("committing new user public keys ffs (len: {}) for checkpoint ID: {}", coordinator_update.new_user_public_keys_ffs.len(), checkpoint_id);
            self.db
                .set_zk_public_keys_ffs(checkpoint_id, &coordinator_update.new_user_public_keys_ffs)
                .await?;
            println!("set_public_key_for_user_ids_ffs  (len: {}) for checkpoint ID: {}", coordinator_update.new_public_key_hash_to_user_id_rows_ffs.len(), checkpoint_id);
            self.db
                .set_public_key_for_user_ids_ffs(&coordinator_update.new_public_key_hash_to_user_id_rows_ffs)
                .await?;
                        println!("user_registration_tree_set_nodes_ffs  (len: {}) for checkpoint ID: {}", coordinator_update.update_user_registration_tree_nodes_ffs.len(), checkpoint_id);

            self.db
                .user_registration_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_user_registration_tree_nodes_ffs)
                .await?;
        }
        tracing::info!("Committed user registration state updates for checkpoint ID: {}", checkpoint_id);
        // start global user tree updates
        if !coordinator_update.update_global_user_tree_nodes_ffs.is_empty() {
            self.db
            .global_user_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_global_user_tree_nodes_ffs)
            .await?;
        }
        tracing::info!("Committed global user tree state updates for checkpoint ID: {}", checkpoint_id);
        // set l2 block state
        self.db
            .set_checkpoint_global_state_roots(checkpoint_id, &coordinator_update.new_base.checkpoint_leaf.global_state_roots)
            .await?;
        self.db
            .set_l2_block_state(checkpoint_id, &coordinator_update.new_base.block_state)
            .await?;
        let checkpoint_leaf_standard = coordinator_update.new_base.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>();
        self.db.set_checkpoint_leaf_data(checkpoint_id, &checkpoint_leaf_standard).await?;
        let checkpoint_delta_merkle_proof: DeltaMerkleProofCore<N::QHash> =
            self.db.checkpoint_tree_set_leaf_hash(checkpoint_id, checkpoint_leaf_hash).await?;
        self.db
            .set_checkpoint_root_hash_to_id_mapping(checkpoint_delta_merkle_proof.new_root, checkpoint_id)
            .await?;
        tracing::info!("Set checkpoint root hash to ID mapping for checkpoint ID: {}\n{:#?}", checkpoint_id, checkpoint_delta_merkle_proof);
        // END STANDARD STATE UPDATES (technically these can be done in any order after
        // the above two are done)

        // CRITICAL: we need to set the checkpoint id at the VERY END otherwise the
        // recovery doesn't work this enables us to avoid having to do atomic
        // commits, since if the node dies during this process, it will load the backups
        // from disk SO LONG AS THE checkpoint_id is not set!!!!
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;
        tracing::info!("Committed coordinator processor state for checkpoint ID: {}", checkpoint_id);
        self.checkpoint_tree_backup_manager
            .append_checkpoint_leaf_hash(checkpoint_id, checkpoint_leaf_hash)
            .await?;
        tracing::info!("Backed up checkpoint tree root for checkpoint ID: {}", checkpoint_id);

        if checkpoint_id != 0 {

            self.last_committed.checkpoint_state_transition = CheckpointStateHashTransition {
                old_checkpoint_tree_root: coordinator_update.old_base.checkpoint_tree_root,
                new_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: coordinator_update.old_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
            };
        }else{
            self.last_committed.checkpoint_state_transition = CheckpointStateHashTransition {
                old_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                new_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
                old_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
                new_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
            };
        }
        self.ids.checkpoint_id = checkpoint_id;
        self.ids.next_checkpoint_id = checkpoint_id + 1;
        self.last_committed.update_for_block::<N::HasherBase>(
            coordinator_update.new_base.block_state,
            verifiable_checkpoint_transition.checkpoint_leaf,
            verifiable_checkpoint_transition.state_transition.checkpoint_transition,
        )?;

        tracing::info!("Updated last committed state for checkpoint ID: {}", checkpoint_id);
        // This just updates the RwLock protected shared status, this is ok because we
        // only read when we dump/create the queue builder
        self.shared_status.update_status(
            self.ids.unique_pending_id,
            checkpoint_id,
            checkpoint_leaf_standard,
            coordinator_update.new_base.checkpoint_leaf.global_state_roots,
            coordinator_update.new_base.block_state,
            false,
        )?;
        tracing::info!("Updated shared status for checkpoint ID: {}", checkpoint_id);

        Ok(())
    }

    pub async fn ensure_db_matches_verifiable_transition(
        &self,
        verifiable_transition: &PsyVerifiableCheckpointTransition<N::F, N::QHash>,
    ) -> anyhow::Result<()> {
        let checkpoint_id = self.ids.checkpoint_id;
        let db_checkpoint_tree_proof: MerkleProofCore<N::QHash> = self.db.checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id).await?;
        let db_checkpoint_tree_root = db_checkpoint_tree_proof.root;
        let v_checkpoint_tree_root = verifiable_transition.state_transition.checkpoint_transition.new_checkpoint_tree_root;
        if db_checkpoint_tree_root != v_checkpoint_tree_root {
            anyhow::bail!("Checkpoint tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_checkpoint_tree_root, v_checkpoint_tree_root);
        }
        let p_state_transition_hash = self.last_committed.checkpoint_state_transition.qfhash::<N::HasherBase>();
        let v_state_transition_hash = verifiable_transition.state_transition.checkpoint_transition.qfhash::<N::HasherBase>();
        if p_state_transition_hash != v_state_transition_hash {
            anyhow::bail!("Checkpoint state transition hash mismatch between processor state and verifiable transition at checkpoint ID: {}. Database hash: {:?}, verifiable transition hash: {:?}", checkpoint_id, p_state_transition_hash, v_state_transition_hash);
        }
        let checkpoint_leaf = verifiable_transition.checkpoint_leaf.to_checkpoint_leaf::<N::HasherBase>();
        if checkpoint_leaf != self.last_committed.checkpoint_leaf {
            anyhow::bail!("Checkpoint leaf mismatch between processor state and verifiable transition at checkpoint ID: {}. Database leaf: {:?}, verifiable transition leaf: {:?}", checkpoint_id, self.last_committed.checkpoint_leaf, checkpoint_leaf);
        }

        let db_user_registration_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .user_registration_tree_get_merkle_proof(checkpoint_id, self.last_committed.l2_state.next_user_id.max(1) - 1)
            .await?;

        if !db_user_registration_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "User registration tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_user_registration_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.user_registration_tree_root != db_user_registration_tree_merkle_proof.root {
            anyhow::bail!("User registration tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_user_registration_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.user_registration_tree_root);
        }

        let db_deploy_contract_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .global_contract_tree_get_merkle_proof(checkpoint_id, (self.last_committed.l2_state.next_contract_id.max(1) - 1) as u64)
            .await?;
        if !db_deploy_contract_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "Global contract tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_deploy_contract_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.contract_tree_root != db_deploy_contract_tree_merkle_proof.root {
            anyhow::bail!("Global contract tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_deploy_contract_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.contract_tree_root);
        }

        let db_global_user_tree_merkle_proof: MerkleProofCore<N::QHash> = self
            .db
            .global_user_tree_get_merkle_proof(checkpoint_id, 1u64 << (N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT - 1))
            .await?;
        if !db_global_user_tree_merkle_proof.verify::<N::HasherBase>() {
            anyhow::bail!(
                "Global user tree merkle proof verification failed for database at checkpoint ID: {}.\n Invalid Proof: \n {:#?}",
                checkpoint_id,
                &db_global_user_tree_merkle_proof
            );
        }
        if verifiable_transition.checkpoint_leaf.global_state_roots.user_tree_root != db_global_user_tree_merkle_proof.root {
            anyhow::bail!("Global user tree root mismatch between database and verifiable transition at checkpoint ID: {}. Database root: {:?}, verifiable transition root: {:?}", checkpoint_id, db_global_user_tree_merkle_proof.root, verifiable_transition.checkpoint_leaf.global_state_roots.user_tree_root);
        }

        Ok(())
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber,
        DeployContractQueue: QStandardEphemeralQueueSubscriber,
        ProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
        FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    >
    PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    > where N::HasherBase: 'static + Send + Sync
{
    pub async fn get_reward_tree_root(&self, checkpoint_id: u64, unique_pending_id: u64) -> anyhow::Result<N::QHash> {
        let temp_store_reward_tree_root: Option<N::QHash> = self
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(
                &self.ids.realm_identifier,
                unique_pending_id,
                QProvingJobDataID::get_checkpoint_state_transition_job_id(checkpoint_id),
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
        deploy_contract_gatherer_backup_directory: &str,
        register_user_gatherer_backup_directory: &str,
        guta_gatherer_backup_directory: &str,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        global_contract_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        user_registration_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<()> {
        let database_check_state = self.get_database_check_state().await?;
        if database_check_state == DatabaseCheckState::NeedsRecovery {
            let restore_unique_pending_id = self.ids.unique_pending_id;
            let restore_checkpoint_id = self.ids.checkpoint_id;

            let next_checkpoint_id = self.ids.checkpoint_id + 1;
            tracing::warn!("Detected inconsistent coordinator processor database state. Initiating restoration from backups... last committed checkpoint ID: {}, unique pending ID: {}, target_checkpoint: {}", self.ids.checkpoint_id, self.ids.unique_pending_id, next_checkpoint_id);
            tracing::info!(
                "Restoring coordinator processor database to checkpoint ID: {} from backups...",
                next_checkpoint_id
            );

            let verifiable_transition_with_proof: PsyVerifiableCheckpointTransitionWithProof<N::F, N::QHash> = self
                .db
                .get_verifiable_checkpoint_state_transition_and_zkp(self.ids.checkpoint_id + 1)
                .await?;

            tracing::info!(
                "Found verifiable checkpoint transition and ZKP for checkpoint ID: {}. Proceeding with restoration...",
                next_checkpoint_id
            );
            tracing::info!("Restoring coordinator processor database from backups...");
            let append_checkpoint_update_siblings = self
                .checkpoint_tree_backup_manager
                .checkpoint_tree
                .get_leaf(self.ids.checkpoint_id + 1)
                .siblings;

            let reward_tree_root = self.get_reward_tree_root(restore_checkpoint_id, restore_unique_pending_id).await?;
            let expected_reward_tree_root = verifiable_transition_with_proof.info.checkpoint_leaf.get_rewards_tree_root();
            if reward_tree_root != expected_reward_tree_root {
                anyhow::bail!(
                    "Reward tree root mismatch during restoration from backups. Computed root: {:?}, expected root from verifiable transition: {:?}",
                    reward_tree_root,
                    expected_reward_tree_root
                );
            }

            let circuit_type = ProvingJobCircuitType::try_from_u32(verifiable_transition_with_proof.circuit_type)?;

            let coordinator_update = generate_coordinator_output_from_backups::<N, FileSystem>(
                file_system,
                deploy_contract_gatherer_backup_directory,
                register_user_gatherer_backup_directory,
                guta_gatherer_backup_directory,
                &self.ids,
                &self.last_committed,
                reward_tree_root,
                append_checkpoint_update_siblings,
                global_user_tree,
                global_contract_tree,
                user_registration_tree,
            )
            .await?;
            let (info, _, zk_proof) = verifiable_transition_with_proof.into_tuple();
            self.commit_state(coordinator_update, circuit_type, zk_proof).await?;
            self.ensure_db_matches_verifiable_transition(&info).await?;
            tracing::info!(
                "Coordinator processor database restored from backups.\n Restored checkpoint ID: {}, unique pending ID: {}",
                self.ids.checkpoint_id,
                self.ids.unique_pending_id
            );
        }
        Ok(())
    }

    pub fn print_coordinator_processor_state(&self) {
        tracing::info!(
            r#"======== Coordinator Processor State ========
[CORE_VITALS]
Last Committed Checkpoint ID: {}
Next Checkpoint ID: {}
Unique Pending ID: {}
Gatherer Unique Pending ID: {}
Checkpoint Root Hash: {}
[/CORE_VITALS]

[IDS]
{:#?}
[/IDS]

[LAST_COMMITTED]
{:#?}
[/LAST_COMMITTED]
============================================="#,
            self.ids.checkpoint_id,
            self.ids.next_checkpoint_id,
            self.ids.unique_pending_id,
            self.ids.gathering_unique_pending_id,
            self.last_committed.checkpoint_root.psy_debug_print(),
            self.ids,
            self.last_committed
        );
    }

    pub async fn init_with_setup_and_genesis(
        &mut self,
        file_system: &FileSystem,
        deploy_contract_gatherer_backup_directory: &str,
        register_user_gatherer_backup_directory: &str,
        guta_gatherer_backup_directory: &str,
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        global_user_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        global_contract_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        user_registration_tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    ) -> anyhow::Result<()> {
        self.ensure_genesis_applied(genesis_block_update).await?;
        self.ensure_backup_restored_if_necessary(
            file_system,
            deploy_contract_gatherer_backup_directory,
            register_user_gatherer_backup_directory,
            guta_gatherer_backup_directory,
            global_user_tree,
            global_contract_tree,
            user_registration_tree,
        )
        .await?;
        self.set_new_unique_ids().await?;

        self.shared_status.update_status(
            self.ids.gathering_unique_pending_id,
            self.ids.checkpoint_id,
            self.last_committed.checkpoint_leaf.clone(),
            self.last_committed.checkpoint_state_roots.clone(),
            self.last_committed.l2_state.clone(),
            false,
        )?;

        tracing::info!(
            "[COORDINATOR] Started with checkpoint ID: {}, unique pending ID: {}",
            self.ids.checkpoint_id,
            self.ids.unique_pending_id
        );
        self.print_coordinator_processor_state();
        Ok(())
    }
}
