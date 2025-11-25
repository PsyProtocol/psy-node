use std::sync::Arc;

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        hash::merkle_node_key::SimpleMerkleNodeKey,
        queue::queue_key::{QPBaseQueueType, QPStandardUniqueIdQueueKey},
    },
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath,
};
use psy_core::constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{DashMapContractHeightCache, PsyDeployContractQueueItem},
            public_key::PZKPublicKeyInfo,
        },
    },
};
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorEdgeAPIStoreReader, PsyCoordinatorProcessorStore, PsyNodeCheckpointTreeDatabaseReader, PsyNodeCoreRewardsTagTreeStoreReader,
        PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::{StandardEdgeAPITempDBStoreBase, StandardProcessorTempDBStoreBase},
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};
use serde::de::value;

use crate::{
    checkpoint_tree_backup::CheckpointTreeBackupManager,
    constants::queue::{PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID, PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID},
    coordinator::processor::{
        gatherers::{
            coordinator_guta_update_gatherer::CoordinatorGUTAUpdateGathererOutput,
            deploy_contract_gatherer::DeployContractGathererOutput,
            register_user_gatherer::{self, RegisterUserGathererOutput},
        },
        processor_shared_status::{PsyCoordinatorProcessorSharedStatus, PsyCoordinatorProcessorSharedStatusWrapper},
    },
    queue::gatherer::{EphemeralQueueGatherer, QueueKeyStatusManager},
};

pub struct PsyCoordinatorDatabaseProcessor<
    N: QNetworkTypesConfig,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber,
    DeployContractQueue: QStandardEphemeralQueueSubscriber,
    GetProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
> {
    pub db: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    pub guta_update_queue: Arc<GUTAUpdateQueue>,
    pub register_user_queue: Arc<RegisterUserQueue>,
    pub deploy_contract_queue: Arc<DeployContractQueue>,
    pub get_proof_work_queue: Arc<GetProofWorkQueue>,
    pub checkpoint_tree_backup_manager: CheckpointTreeBackupManager<N::HasherBase, N::QHash>,
    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub shared_status: PsyCoordinatorProcessorSharedStatusWrapper<N::F, N::QHash>,
    pub last_committed_checkpoint_id: u64,
    pub current_core_proc_unique_pending_id: QCoreProcCheckpointUniqueId,
    pub current_unique_pending_id: u64,
    pub pending_checkpoint_id: u64,
    pub last_committed_l2_state: QEDL2BlockState,
    pub last_committed_checkpoint_leaf: PQEDCheckpointLeaf<N::F, N::QHash>,
    pub last_committed_checkpoint_root: N::QHash,
    pub last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<N::QHash>,
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
}

impl<
        N: QNetworkTypesConfig,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber,
        DeployContractQueue: QStandardEphemeralQueueSubscriber,
        GetProofWorkQueue: QStandardWorkerQueuePublisher,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    >
    PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    pub async fn new_init(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
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

        Ok(Self {
            db,
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            guta_update_queue,
            register_user_queue,
            deploy_contract_queue,
            get_proof_work_queue,
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            checkpoint_tree_backup_manager,
            shared_status: PsyCoordinatorProcessorSharedStatusWrapper::new(shared_status),
            last_committed_checkpoint_id,
            current_core_proc_unique_pending_id,
            current_unique_pending_id,
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
            last_committed_checkpoint_leaf,
            last_committed_checkpoint_root,
            last_committed_checkpoint_state_roots,
            gathering_unique_pending_id: current_unique_pending_id,
            gathering_core_proc_unique_pending_id: current_core_proc_unique_pending_id,
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
            .set_gathering_unique_pending_ids(&self.realm_identifier, self.gathering_unique_pending_id, self.gathering_core_proc_unique_pending_id)
            .await?;
        self.temp_db
            .set_unique_pending_ids(&self.realm_identifier, self.current_unique_pending_id, self.current_core_proc_unique_pending_id)
            .await?;

        Ok(())
    }
    pub async fn revert_block(&mut self) -> anyhow::Result<()> {
        self.set_new_unique_ids().await?;
        self.shared_status.revert_last_changes(self.current_unique_pending_id)?;
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
        self.set_new_unique_ids().await?;
        self.shared_status.update_status(
            self.gathering_unique_pending_id,
            self.last_committed_checkpoint_id,
            self.last_committed_checkpoint_leaf,
            self.last_committed_checkpoint_state_roots,
            self.last_committed_l2_state,
        )?;
        

        self.db.set_checkpoint_id_to_unique_pending_id_mapping(self.pending_checkpoint_id, old_unique_pending_id, &old_proc_unique_id).await?;
        self.db.set_latest_checkpoint_id(self.pending_checkpoint_id).await?;
        self.last_committed_checkpoint_id = self.pending_checkpoint_id;
        self.pending_checkpoint_id += 1;
        self.last_committed_checkpoint_leaf = new_checkpoint_leaf;
        self.last_committed_checkpoint_state_roots = new_checkpoint_state_roots;
        self.last_committed_l2_state = new_l2_block_state;
        
        Ok(())
    }
}
