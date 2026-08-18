use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig, genesis::genesis_block_setup::PsyGenesisBlockSetupData,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder, p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmProcessorStore}, psy_temp_db::StandardProcessorTempDBStoreBase, queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    }, store::traits::proof_store::QParthProofStore
};

use crate::realm::processor::{core::{PsyRealmProcessor, runner::run_realm_processor}, db::PsyRealmDatabaseProcessor};

pub async fn create_realm_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    chain_id: u32,
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    file_system: Arc<FileSystem>,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    network: psy_core::constants::chain_id::PsyChainNetworkType,
    recording: psy_node_core::store::realm_commit_recording::RealmCommitRecording<N::QHash>,
) -> anyhow::Result<(
    PsyRealmProcessor<
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
    tokio::task::JoinHandle<Result<(), anyhow::Error>>,
)>
where
    FileSystem::File: Send + Sync,
{
    tracing::info!("[REALM_CREATE] setup_for_realm start");
    let genesis =
        GenesisDatabaseDataBuilder::<N::F, N::QHash>::setup_for_realm::<N::HasherBase, N>(
            genesis_data,
            realm_identifier.realm_id as u64,
            realm_identifier.realm_sub_id as u64,
        )?;
    tracing::info!("[REALM_CREATE] setup_for_realm done");

        /*
        
        
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
        
         */
    let db = PsyRealmDatabaseProcessor::<N, _, _, _, _, _, _, FileSystem, CoordinatorClient>::new_init(
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        guta_update_queue,
        proof_work_queue,
        coordinator_client,
        chain_id,
        realm_identifier,
        circuit_fingerprint_config,
        network,
        recording,
        file_system.clone(),
        checkpoint_tree_root_backup_file_path,
        genesis.prepared_updates.new_realm_root,
        genesis.coordinator_update.checkpoint_sync_info.checkpoint_tree_root,
    )
    .await?;
    tracing::info!("[REALM_CREATE] db new_init done");
    /*
    pub async fn new(
        mut db: PsyCoordinatorDatabaseProcessor<
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
        genesis_block_update: PsyPreparedCoordinatorBlockStateUpdates<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        deploy_contract_gatherer_backup_directory: String,
        register_user_gatherer_backup_directory: String,
        guta_gatherer_backup_directory: String,
    ) -> anyhow::Result<(
        Self,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    )> {

        mut db: PsyRealmDatabaseProcessor<
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
        genesis_block_update: PsyPreparedRealmBlockStateUpdatesWithCoordinatorUpdate<N::F, N::QHash>,
        file_system: Arc<FileSystem>,
        guta_gatherer_backup_directory: String,
     */
    let processor_result: (
        PsyRealmProcessor<
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
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    ) = PsyRealmProcessor::new(
        db,
        genesis,
        file_system,
        guta_gatherer_backup_directory,
    )
    .await?;
    tracing::info!("[REALM_CREATE] processor new done");

    Ok(processor_result)
}



pub async fn create_realm_processor_and_run<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
    CoordinatorClient: RealmCoordinatorClient<N::F, N::QHash> + Send + Sync + 'static,
>(
    chain_id: u32,
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    file_system: Arc<FileSystem>,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    network: psy_core::constants::chain_id::PsyChainNetworkType,
    recording: psy_node_core::store::realm_commit_recording::RealmCommitRecording<N::QHash>,
) -> anyhow::Result<()>
where
    FileSystem::File: Send + Sync,
{
    tracing::info!("[REALM_CREATE] create_and_run start");
    let (processor, guta_gatherer_join_handle) = create_realm_processor::<N, S, STagTreeRewards, GUTAUpdateQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem, CoordinatorClient>(
        chain_id,
        genesis_data,
        file_system,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        guta_update_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
        coordinator_client,
        network,
        recording,
    )
    .await?;

    tracing::info!("Starting realm processor...");
    run_realm_processor(processor, guta_gatherer_join_handle).await?;

    Ok(())
}
