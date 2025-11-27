use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::{
    guta::header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID,
    v1::qdata::{contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo},
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher},
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
            coordinator_guta_update_gatherer::CoordinatorGUTAUpdateGathererOutput, deploy_contract_gatherer::DeployContractGathererOutput,
            register_user_gatherer::RegisterUserGathererOutput,
        },
    },
    queue::gatherer::EphemeralQueueGathererWithTree,
};
mod genesis;
mod init;
mod process_block;
mod recover_from_backup;
pub mod runner;
pub mod startup;

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
