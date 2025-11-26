use std::sync::{atomic::AtomicBool, Arc};

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::QFieldHashable},
    data::queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::QNetworkTypesConfig,
    QCoreProcCheckpointUniqueId,
};
use psy_core::{constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF, job::job_id::ProvingJobCircuitType};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    prepared_block::coordinator::PsyPreparedCoordinatorBlockStateUpdates,
    protocol::{checkpoint_transition_hash::CheckpointStateHashTransition, verifiable_checkpoint_transition::{PsyVerifiableCheckpointTransition, PsyVerifiableCheckpointTransitionWithProof}},
    v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, PQEDCheckpointLeafStats, QEDL2BlockState},
        contract::PsyDeployContractQueueItem,
        public_key::PZKPublicKeyInfo,
    },
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorProcessorStore, PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    backup::checkpoint_tree::CheckpointTreeBackupManager,
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
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,
    pub is_active: Arc<AtomicBool>,

    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub register_user_queue: Arc<RegisterUserQueue>,
    pub deploy_contract_queue: Arc<DeployContractQueue>,
    pub proof_work_queue: Arc<ProofWorkQueue>,
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash, FileSystem::File>,
    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub shared_status: PsyCoordinatorProcessorSharedStatusWrapper<N::F, N::QHash>,
    pub last_committed_checkpoint_id: u64,
    pub current_core_proc_unique_pending_id: QCoreProcCheckpointUniqueId,
    pub current_unique_pending_id: u64,
    pub pending_checkpoint_id: u64,
    pub last_committed_l2_state: QEDL2BlockState,
    pub last_committed_checkpoint_leaf_stats: PQEDCheckpointLeafStats<N::F, N::QHash>,
    pub last_committed_checkpoint_leaf: PQEDCheckpointLeaf<N::F, N::QHash>,
    pub last_committed_checkpoint_root: N::QHash,
    pub last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<N::QHash>,
    pub last_committed_checkpoint_state_transition: CheckpointStateHashTransition<N::QHash>,
    pub gathering_unique_pending_id: u64,


    pub gathering_core_proc_unique_pending_id: QCoreProcCheckpointUniqueId,
    pub guta_queue_key_status_manager: QueueKeyStatusManager<
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<N::F, N::QHash>,
    >,
    pub register_user_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PZKPublicKeyInfo<N::QHash>>,
    pub deploy_contract_queue_key_status_manager:
        QueueKeyStatusManager<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PsyDeployContractQueueItem<N::F, N::QHash>>,
    pub needs_revert: bool,
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
        FileSystem: TokioLikeFileSystem+ Send + Sync + 'static,
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
    >
{
    pub async fn get_next_checkpoint_id(&self) -> anyhow::Result<u64> {
        let latest_checkpoint_id = self.db.get_latest_checkpoint_id().await?;
        Ok(latest_checkpoint_id + 1)
    }
    pub async fn get_database_check_state(&self) -> anyhow::Result<DatabaseCheckState> {

        let actual_latest_applied_checkpoint_id: u64 = self.db.get_latest_checkpoint_id().await?;
        let (last_unique_pending_id, _last_unique_proc_checkpoint_id): (u64, QCoreProcCheckpointUniqueId) = self.db.get_current_unique_pending_id().await?;
        let expected_checkpoint_id: Option<u64> = self.db.get_checkpoint_id_for_unique_pending_id(last_unique_pending_id).await?;
        let database_check_state = if expected_checkpoint_id.is_none() {
            // needs genesis
            DatabaseCheckState::NeedsGenesis
        }else{
            let expected_checkpoint_id = expected_checkpoint_id.unwrap();
            if expected_checkpoint_id != actual_latest_applied_checkpoint_id {
                if expected_checkpoint_id < actual_latest_applied_checkpoint_id {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is less than actual latest applied checkpoint ID ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id);
                }else if expected_checkpoint_id > actual_latest_applied_checkpoint_id + 1 {
                    anyhow::bail!("Inconsistent database state detected: expected checkpoint ID ({}) for unique pending ID ({}) is greater than actual latest applied checkpoint ID + 1 ({}). This indicates a serious inconsistency in the database state.",
                        expected_checkpoint_id, last_unique_pending_id, actual_latest_applied_checkpoint_id + 1);
                }else if expected_checkpoint_id == 0 {
                    // needs genesis
                    DatabaseCheckState::NeedsGenesis
                }else{
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
        checkpoint_tree_root_backup_file_path: String,
    ) -> anyhow::Result<Self> {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;

        let (current_unique_pending_id, current_core_proc_unique_pending_id) = db.get_current_unique_pending_id().await?;
        let last_committed_checkpoint_id = db.get_latest_checkpoint_id().await?;

        let mut checkpoint_tree_backup_manager = CheckpointTreeBackupManager::new_from_file_path(
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

        let shared_status = PsyCoordinatorProcessorSharedStatus {
            last_committed_checkpoint_id,
            unique_pending_id: current_unique_pending_id,
            last_committed_checkpoint_leaf: db.get_checkpoint_leaf_data(last_committed_checkpoint_id).await?,
            last_committed_checkpoint_state_roots: db.get_checkpoint_global_state_roots(last_committed_checkpoint_id).await?,
            should_revert_last_changes: false,
            block_state: db.get_l2_block_state(last_committed_checkpoint_id).await?,
        };

        temp_db
            .set_unique_pending_ids(&realm_identifier, current_unique_pending_id, current_core_proc_unique_pending_id)
            .await?;

        let last_committed_l2_state = shared_status.block_state.clone();
        let pending_checkpoint_id = last_committed_checkpoint_id + 1;

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
            old_checkpoint_leaf_hash: db.checkpoint_tree_get_leaf_hash(last_committed_checkpoint_id, last_committed_checkpoint_id - 1).await?,
            new_checkpoint_leaf_hash: last_committed_checkpoint_leaf_stats.qfhash::<N::HasherBase>(),
        }
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
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            checkpoint_tree_backup_manager,
            shared_status: PsyCoordinatorProcessorSharedStatusWrapper::new(shared_status),
            last_committed_checkpoint_id,
            current_core_proc_unique_pending_id,
            current_unique_pending_id,
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
            pending_checkpoint_id,
            last_committed_l2_state,
            last_committed_checkpoint_leaf_stats,
            last_committed_checkpoint_leaf,
            last_committed_checkpoint_root,
            last_committed_checkpoint_state_roots,
            last_committed_checkpoint_state_transition,
            gathering_unique_pending_id: current_unique_pending_id,
            gathering_core_proc_unique_pending_id: current_core_proc_unique_pending_id,
            needs_revert: false,
            genesis_checkpoint_state_transition_hash: genesis_verifiable_state_transition.state_transition.checkpoint_transition.qfhash::<N::HasherBase>(),
        })
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db.get_latest_checkpoint_id().await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.db.get_current_unique_pending_id().await
    }
    pub async fn set_new_unique_ids(&mut self) -> anyhow::Result<()> {
        let (new_unique_pending_id, new_core_proc_unique_pending_id) = self.db.inc_unique_pending_id(1).await?;
        self.current_unique_pending_id = self.gathering_unique_pending_id;
        self.current_core_proc_unique_pending_id = self.gathering_core_proc_unique_pending_id;
        self.gathering_unique_pending_id = new_unique_pending_id;
        self.gathering_core_proc_unique_pending_id = new_core_proc_unique_pending_id;
        self.temp_db
            .set_gathering_unique_pending_ids(
                &self.realm_identifier,
                self.gathering_unique_pending_id,
                self.gathering_core_proc_unique_pending_id,
            )
            .await?;
        self.temp_db
            .set_unique_pending_ids(
                &self.realm_identifier,
                self.current_unique_pending_id,
                self.current_core_proc_unique_pending_id,
            )
            .await?;

        Ok(())
    }
    pub async fn commit_updated_to_db(
        &mut self,
        new_checkpoint_leaf: PQEDCheckpointLeaf<N::F, N::QHash>,
        new_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<N::QHash>,
        new_l2_block_state: QEDL2BlockState,
    ) -> anyhow::Result<()> {
        let old_unique_pending_id = self.current_unique_pending_id;
        let old_proc_unique_id = self.current_core_proc_unique_pending_id;

        self.db
            .set_checkpoint_id_to_unique_pending_id_mapping(self.pending_checkpoint_id, old_unique_pending_id, &old_proc_unique_id)
            .await?;
        self.db.set_latest_checkpoint_id(self.pending_checkpoint_id).await?;
        self.last_committed_checkpoint_id = self.pending_checkpoint_id;
        self.pending_checkpoint_id += 1;
        self.last_committed_checkpoint_leaf = new_checkpoint_leaf;
        self.last_committed_checkpoint_leaf_stats = new_checkpoint_leaf.stats.clone();
        self.last_committed_checkpoint_state_roots = new_checkpoint_state_roots;
        self.last_committed_l2_state = new_l2_block_state;

        Ok(())
    }
    pub fn get_proof_worker_queue_key(&self) -> CoordinatorProvingWorkQueueKey<N::QHash, N::JobId> {
        CoordinatorProvingWorkQueueKey {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: self.current_core_proc_unique_pending_id,
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
        let checkpoint_leaf_hash = coordinator_update.new_base.checkpoint_leaf.qfhash::<N::HasherBase>();
        if checkpoint_leaf_hash != coordinator_update.new_base.checkpoint_leaf_hash {
            anyhow::bail!(
                "Checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                checkpoint_leaf_hash,
                coordinator_update.new_base.checkpoint_leaf_hash
            );
        }

        let old_checkpoint_leaf_hash = coordinator_update.old_base.checkpoint_leaf_hash;
        if old_checkpoint_leaf_hash != self.last_committed_checkpoint_leaf.qfhash::<N::HasherBase>() {
            anyhow::bail!(
                "Old checkpoint leaf hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}",
                self.last_committed_checkpoint_leaf.qfhash::<N::HasherBase>(),
                old_checkpoint_leaf_hash
            );
        }

        let old_checkpoint_root = self.db.checkpoint_tree_get_root_hash(checkpoint_id).await?;
        if old_checkpoint_root != coordinator_update.old_base.checkpoint_tree_root {
            anyhow::bail!("Old checkpoint tree root hash mismatch when committing coordinator state update to database. Computed hash: {:?}, expected hash: {:?}", old_checkpoint_root, coordinator_update.old_base.checkpoint_tree_root);
        }

        let verifiable_checkpoint_transition = coordinator_update.get_public_inputs_verifiable_state_transition(
            self.genesis_checkpoint_state_transition_hash,
            self.circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        );

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
        // CRITICAL: set unique_pending_id to checkpoint_id mapping BEFORE ANY OTHER STATE UPDATES so we can recover if something goes wrong
        self.db
            .set_unique_pending_id_checkpoint_id_mapping(unique_pending_id, checkpoint_id)
            .await?;
        // START STANDARD STATE UPDATES (technically these can be done in any order after the above two are done)
        // start contract updates
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

        // start user registraion updates
        self.db
            .set_zk_public_keys_ffs(checkpoint_id, &coordinator_update.new_user_public_keys_ffs)
            .await?;
        self.db
            .set_public_key_for_user_ids_ffs(&coordinator_update.new_public_key_hash_to_user_id_rows_ffs)
            .await?;
        self.db
            .user_registration_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_user_registration_tree_nodes_ffs)
            .await?;

        // start global user tree updates
        self.db
            .global_user_tree_set_nodes_ffs(checkpoint_id, &coordinator_update.update_global_user_tree_nodes_ffs)
            .await?;

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
        // END STANDARD STATE UPDATES (technically these can be done in any order after the above two are done)

        // CRITICAL: we need to set the checkpoint id at the VERY END otherwise the
        // recovery doesn't work this enables us to avoid having to do atomic
        // commits, since if the node dies during this process, it will load the backups
        // from disk SO LONG AS THE checkpoint_id is not set!!!!
        self.db.set_latest_checkpoint_id(checkpoint_id).await?;

        self.last_committed_checkpoint_state_transition = CheckpointStateHashTransition {
            old_checkpoint_tree_root: coordinator_update.old_base.checkpoint_tree_root,
            new_checkpoint_tree_root: coordinator_update.new_base.checkpoint_tree_root,
            old_checkpoint_leaf_hash: coordinator_update.old_base.checkpoint_leaf_hash,
            new_checkpoint_leaf_hash: coordinator_update.new_base.checkpoint_leaf_hash,
        };
        self.last_committed_checkpoint_id = checkpoint_id;
        self.last_committed_checkpoint_leaf = checkpoint_leaf_standard;
        self.last_committed_checkpoint_leaf_stats = coordinator_update.new_base.checkpoint_leaf.stats.clone();
        self.last_committed_checkpoint_state_roots = coordinator_update.new_base.checkpoint_leaf.global_state_roots;
        self.last_committed_l2_state = coordinator_update.new_base.block_state;
        self.last_committed_checkpoint_root = checkpoint_delta_merkle_proof.new_root;

        // This just updates the RwLock protected shared status, this is ok because we only read when we dump/create the queue builder
        self.shared_status.update_status(
            self.gathering_unique_pending_id,
            checkpoint_id,
            checkpoint_leaf_standard,
            coordinator_update.new_base.checkpoint_leaf.global_state_roots,
            coordinator_update.new_base.block_state,
            false,
        )?;

        Ok(())
    }
}
