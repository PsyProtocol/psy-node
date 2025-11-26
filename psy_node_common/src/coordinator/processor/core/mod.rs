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
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
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
    backup::coordinator::{load_coordinator_memory_trees_from_db}, constants::queue::{
        PQ_COORDINATOR_DEPLOY_CONTRACT_QUEUE_TOPIC_ID, PQ_COORDINATOR_REGISTER_USER_PUBLIC_KEY_QUEUE_TOPIC_ID,
        PQ_COORDINATOR_SUBMIT_REALM_GUTA_UPDATE_QUEUE_TOPIC_ID,
    }, coordinator::processor::{
        db::PsyCoordinatorDatabaseProcessor,
        gatherers::{
            coordinator_guta_update_gatherer::{
                CoordinatorGUTAUpdateGatherer, CoordinatorGUTAUpdateGathererConfig, CoordinatorGUTAUpdateGathererOutput,
            },
            deploy_contract_gatherer::{DeployContractGatherer, DeployContractGathererConfig, DeployContractGathererOutput},
            register_user_gatherer::{RegisterUserGatherer, RegisterUserGathererConfig, RegisterUserGathererOutput},
        },
    }, queue::gatherer::EphemeralQueueGathererWithTree
};
mod init;
mod runner;
mod process_block;
mod startup;
mod genesis;
mod recover_from_backup;
pub struct PsyCoordinatorProcessor<
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
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
    >,
    coordinator_guta_updates_circuit_whitelist: N::QHash,
    register_users_circuit_whitelist: N::QHash,
    deploy_contract_circuit_whitelist: N::QHash,
    
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
    pub proof_worker_queue_max_time_ms: u64,
}