use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_data::
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem
;
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueueSubscriber, worker_queue::QStandardWorkerQueuePublisher}, store::traits::proof_store::QParthProofStore
};

use crate::{
    constants::queue::
        PQ_REALM_SUBMIT_USER_UPDATE_QUEUE_TOPIC_ID
    ,
    queue::gatherer::EphemeralQueueGathererWithTree, realm::processor::{db::PsyRealmDatabaseProcessor, gatherers::realm_end_cap_gatherer::RealmGUTAEndCapGathererOutput},
};

mod process_block;
pub mod runner;
pub mod startup;

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

    // --- Optional Realm P2P wiring (Slice C) ---
    // Defaults are `None` / empty in `new`, so the unset path is byte-identical
    // to today's single-producer HTTP/NATS flow. A non-`None` handle plus an
    // enabled `RealmRotationConfig` engage the publish + blocking vote wait in
    // `process_block`; GUTA admission stays on the HTTP `rc_submit_guta_proof`
    // path regardless.
    /// Backup directory copy kept on `Self` so `process_block` can read the
    /// RGE2 gatherer backup file when publishing a Proposal body. The gatherer
    /// config owns the live `FileSystem` handle; the processor only needs the
    /// directory path to locate the per-pending backup file.
    pub guta_gatherer_backup_directory: String,
    /// Cloneable command sender into the Realm network drive loop. `None` until
    /// `set_realm_p2p` wires it.
    pub p2p: Option<crate::realm::network::RealmNetworkCommands>,
    /// Per-Realm rotation config gating the scheduled-proposer check.
    pub rotation: Option<parth_common::realm_rotation::RealmRotationConfig>,
    /// Local validator BLS secret key used to sign the processor's own Vote.
    /// Required when P2P is enabled; `set_realm_p2p` wires it.
    pub bls_secret: Option<psy_data::p2p::BlsSecretKey>,
    /// Local validator user id carried in the 410-byte finalize output.
    /// Wired by `set_realm_p2p`; `None` until then.
    pub p2p_validator_user_id: Option<u64>,
    /// Authenticated BLS keys used to verify individual votes before aggregation.
    pub p2p_bls_public_keys: Option<std::collections::HashMap<u16, psy_data::p2p::BlsPublicKey>>,
}
