use std::sync::Arc;

use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    data::hash::merkle_node_key::SimpleMerkleNodeKey, node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig,
    QCoreProcCheckpointUniqueId, QProvingJobDataIDWithRewardPath,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            contract::{DashMapContractHeightCache, PsyDeployContractQueueItem},
            public_key::PZKPublicKeyInfo,
        },
    },
};
use psy_node_core::{
    psy_core_db::traits::full::{
        PsyCoordinatorEdgeAPIStoreReader, PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter,
    },
    psy_temp_db::{StandardEdgeAPITempDBStoreBase, StandardProcessorTempDBStoreBase},
    queue::{
        ephemeral::{QStandardEphemeralQueuePublisher, QStandardEphemeralQueueSubscriber},
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::{
    constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    },
    coordinator::processor::{
        db::PsyCoordinatorDatabaseProcessor,
        gatherers::{
            coordinator_guta_update_gatherer::{
                CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig, CoordinatorGUTAUpdateGathererOutput,
            },
            deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig, DeployContractGathererOutput},
            register_user_gatherer::{self, RegisterUserGatherer, RegisterUserGathererConfig, RegisterUserGathererOutput},
        },
        processor_shared_status::PsyCoordinatorProcessorSharedStatusWrapper,
    },
    queue::gatherer::{EphemeralQueueGatherer, EphemeralQueueGathererWithTree},
};

pub struct PsyCoordinatorProcessor<
    N: QNetworkTypesConfig,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber,
    DeployContractQueue: QStandardEphemeralQueueSubscriber,
    GetProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
> where
    N: 'static,
{
    pub db: PsyCoordinatorDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >,
    pub guta_queue_gatherer: EphemeralQueueGathererWithTree<
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
        GlobalUserTreeAggregatorHeaderWithTagValueAndJobID<N::F, N::QHash>,
        CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>,
    >,
    pub register_user_queue_gatherer: EphemeralQueueGathererWithTree<
        PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PZKPublicKeyInfo<N::QHash>,
        RegisterUserGathererOutput<N::QHash, N::JobId>,
    >,
    pub deploy_contract_queue_gatherer: EphemeralQueueGathererWithTree<
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID,
        PsyDeployContractQueueItem<N::F, N::QHash>,
        DeployContractGathererOutput<N::QHash, N::JobId>,
    >,
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueueSubscriber +  Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueuePublisher + Send + Sync,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore,
    >
    PsyCoordinatorProcessor<
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
    pub async fn new(
        db: PsyCoordinatorDatabaseProcessor<
            N,
            S,
            STagTreeRewards,
            GUTAUpdateQueue,
            RegisterUserQueue,
            DeployContractQueue,
            GetProofWorkQueue,
            TempDatabase,
            ProofStore,
        >,
        coordinator_guta_updates_circuit_whitelist: N::QHash,
        register_users_circuit_whitelist: N::QHash,
        deploy_contract_circuit_whitelist: N::QHash,
        deploy_contract_gatherer_backup_directory: String,
        register_user_gatherer_backup_directory: String,
        guta_gatherer_backup_directory: String,
    ) -> anyhow::Result<Self> {
        let guta_create_builder_config = CoordinatorGUTAUpdateGathererConfig::<N, TempDatabase> {
            realm_id_u64: db.realm_id_u64,
            realm_sub_id_u64: db.realm_sub_id_u64,
            status: db.shared_status.inner.clone(),
            temp_db: db.temp_db.clone(),
            backup_file_directory: guta_gatherer_backup_directory,
            coordinator_guta_updates_circuit_whitelist,
            checkpoint_tree: db.checkpoint_tree_backup_manager.checkpoint_tree.clone(),
            _phantom_n: std::marker::PhantomData,
        };
        let p = guta_create_builder_config.clone();

        let mut guta_tree = SimpleMemoryMerkleRecorderStore::<N::HasherBase, N::QHash>::new(N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);

        let (guta_queue_gatherer, guta_join_handle) = EphemeralQueueGathererWithTree::new::<
            GUTAUpdateQueue,
            CoordinatorGUTAUpdateGathererConfig<N, TempDatabase>,
            N::QHash,
            N::HasherBase,
            CoordinatorGUTAUpdateGatherer<N, TempDatabase>,
        >(
            db.guta_update_queue.clone(),
            guta_create_builder_config,
            db.guta_queue_key_status_manager.get_queue_key()?,
            guta_tree,
        );

        let mut user_registration_tree = SimpleMemoryMerkleRecorderStore::<N::HasherBase, N::QHash>::new(N::GLOBAL_USER_TREE_HEIGHT);
        let (register_user_queue_gatherer, register_user_join_handle) = EphemeralQueueGathererWithTree::new::<
            RegisterUserQueue,
            RegisterUserGathererConfig<N, TempDatabase>,
            N::QHash,
            N::HasherBase,
            RegisterUserGatherer<N, TempDatabase>,
        >(
            db.register_user_queue.clone(),
            RegisterUserGathererConfig {
                realm_id_u64: db.realm_id_u64,
                realm_sub_id_u64: db.realm_sub_id_u64,
                temp_db: db.temp_db.clone(),
                backup_file_directory: register_user_gatherer_backup_directory,
                _phantom_n: std::marker::PhantomData,
                status: db.shared_status.inner.clone(),
                register_users_circuit_whitelist,
            },
            db.register_user_queue_key_status_manager.get_queue_key()?,
            user_registration_tree,
        );
        let mut deploy_contract_tree = SimpleMemoryMerkleRecorderStore::<N::HasherBase, N::QHash>::new(N::GLOBAL_CONTRACT_TREE_HEIGHT);
        let (deploy_contract_queue_gatherer, deploy_contract_join_handle) = EphemeralQueueGathererWithTree::<PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, _,_>::new::<
            DeployContractQueue,
            DeployContractGathererConfig<N, TempDatabase>,
            N::QHash,
            N::HasherBase,
            DeployContractGatherer<N, TempDatabase>,
        >(
            db.deploy_contract_queue.clone(),
            DeployContractGathererConfig {
                realm_id_u64: db.realm_id_u64,
                realm_sub_id_u64: db.realm_sub_id_u64,
                temp_db: db.temp_db.clone(),
                backup_file_directory: deploy_contract_gatherer_backup_directory,
                _phantom_n: std::marker::PhantomData,
                shared_status: db.shared_status.inner.clone(),
                deploy_contract_circuit_whitelist,
            },
            db.deploy_contract_queue_key_status_manager.get_queue_key()?,
            deploy_contract_tree,
        );

        Ok(Self {
            db,
            guta_queue_gatherer: guta_queue_gatherer,
            register_user_queue_gatherer : register_user_queue_gatherer,
            deploy_contract_queue_gatherer: deploy_contract_queue_gatherer,
        })
    }
    pub async fn get_latest_checkpoint_id_internal(&self) -> anyhow::Result<u64> {
        self.db.db.get_latest_checkpoint_id().await
    }
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.db.db.get_current_unique_pending_id().await
    }

    pub async fn write_all_updates_to_db(&self) -> anyhow::Result<()> {
        Ok(())
    }
}
