use std::sync::Arc;

use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::v1::qdata::{contract::PsyDeployContractQueueItem, public_key::PZKPublicKeyInfo};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        coordinator_guta_durable_submission::CoordinatorGutaQueueItem,
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::QStandardWorkerQueuePublisher,
    },
    store::traits::proof_store::QParthProofStore,
    store::coordinator_processor_branch_exact_runtime::CoordinatorBranchExactProcessorOwner,
    store::coordinator_processor_full_commit::CoordinatorProcessorFullCommitStore,
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
    queue::gatherer::{EphemeralQueueGathererWithTree, GathererPauseReceipt},
};
mod genesis;
mod process_block;
mod recover_from_backup;
pub mod runner;
pub mod startup;

pub(super) struct CoordinatorRollbackGathererPauseSet {
    pub(super) guta: GathererPauseReceipt,
    pub(super) registration: GathererPauseReceipt,
    pub(super) deploy: GathererPauseReceipt,
}

pub(crate) enum CoordinatorNormalProcessingOwner {
    Legacy,
    BranchExact(CoordinatorBranchExactProcessorOwner),
}

impl CoordinatorNormalProcessingOwner {
    pub const fn legacy() -> Self {
        Self::Legacy
    }

    pub fn branch_exact(owner: CoordinatorBranchExactProcessorOwner) -> Self {
        Self::BranchExact(owner)
    }

    pub const fn is_branch_exact(&self) -> bool {
        matches!(self, Self::BranchExact(_))
    }
}

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
        CoordinatorGutaQueueItem<N::F, N::QHash>,
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
    normal_processing_owner: Option<CoordinatorNormalProcessingOwner>,
    branch_exact_full_commit:
        Option<Arc<dyn CoordinatorProcessorFullCommitStore<N::QHash>>>,
    initial_rollback_pauses: Option<CoordinatorRollbackGathererPauseSet>,
}
