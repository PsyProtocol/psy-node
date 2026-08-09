use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem
;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher}, store::{realm_processor_quiescence::RealmProcessorIterationGate, traits::proof_store::QParthProofStore}
};

use crate::{
    constants::queue::
        PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID
    ,
    queue::gatherer::EphemeralQueueGathererWithTree, realm::processor::{db::PsyRealmDatabaseProcessor, gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput},
};

mod process_block;
mod control;
pub mod runner;
pub mod startup;

pub use control::{
    RealmProcessorControlError, RealmProcessorControlHandle,
    RealmProcessorControlPhase, RealmProcessorControlRevision,
    RealmProcessorControlSnapshot, RealmProcessorDrainAcceptance,
};

pub struct PsyRealmProcessor<
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber,
    ProofWorkQueue: QStandardWorkerQueuePublisher,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
    FileSystem: TokioLikeFileSystem,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync,
> where
    N: 'static,
{
    pub db: PsyRealmDatabaseProcessor<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        ProofWorkQueue,
        TempDatabase,
        ProofStore,
        FileSystem,
        CoordinatorClient,
    >,

    pub guta_queue_gatherer: EphemeralQueueGathererWithTree<
        PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID,
        PsyRealmUserUpdateQueueItem<N::F, N::QHash>,
        RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>,
    >,
    pub proof_worker_queue_max_time_ms: u64,
    /// The real loop owns the only iteration permit. Ordinary construction
    /// installs `Disabled`; h23 does not open a production cutover flag.
    pub(super) iteration_quiescence: RealmProcessorIterationGate,
    /// The sole receiver/lease owner. Ordinary startup leaves it absent; a
    /// later composition root must opt in explicitly after durable preflight.
    control_owner: Option<control::RealmProcessorControlOwner>,
}
