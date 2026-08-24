use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig, genesis::genesis_block_setup::PsyGenesisBlockSetupData,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::QParthProofStore,
};

use crate::coordinator::processor::{PsyCoordinatorProcessor, db::PsyCoordinatorDatabaseProcessor, runner::run_coordinator_processor};

pub async fn create_coordinator_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    update_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
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
) -> anyhow::Result<(
    PsyCoordinatorProcessor<
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
    tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    tokio::task::JoinHandle<Result<(), anyhow::Error>>,
)>
where
    FileSystem::File: Send + Sync,
{
    tracing::info!("[COORD_CREATE] setup_for_coordinator start");
    let (genesis_verifiable_checkpoint_transition, genesis_block_update) =
        GenesisDatabaseDataBuilder::<N::F, N::QHash>::setup_for_coordinator::<N::HasherBase, N>(
            genesis_data,
            circuit_fingerprint_config.checkpoint_state_transition_circuit_fingerprint,
        )?;
    tracing::info!("[COORD_CREATE] setup_for_coordinator done");

    //tracing::debug!("genesis verifiable_checkpoint_transition: {:#?}", genesis_verifiable_checkpoint_transition);

    /*


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

      */

    let db = PsyCoordinatorDatabaseProcessor::<N, _, _, _, _, _, _, _, _, FileSystem>::new_init(
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
        genesis_verifiable_checkpoint_transition,
        file_system.clone(),
        checkpoint_tree_root_backup_file_path,
    )
    .await?;
    tracing::info!("[COORD_CREATE] db new_init done");
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

     */
    let processor_result: (
        PsyCoordinatorProcessor<
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
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
        tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    ) = PsyCoordinatorProcessor::new(
        db,
        genesis_block_update,
        file_system,
        deploy_contract_gatherer_backup_directory,
        update_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
    )
    .await?;
    tracing::info!("[COORD_CREATE] processor new done");

    Ok(processor_result)
}



pub async fn create_coordinator_processor_and_run<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    update_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    guta_update_queue: Arc<GUTAUpdateQueue>,
    register_user_queue: Arc<RegisterUserQueue>,
    deploy_contract_queue: Arc<DeployContractQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
) -> anyhow::Result<()>
where
    FileSystem::File: Send + Sync,
{
    tracing::info!("[COORD_CREATE] create_and_run start");
    let (processor, guta_gatherer_join_handle, register_users_gatherer_join_handle, deploy_contracts_gatherer_join_handle) = create_coordinator_processor::<N, S, STagTreeRewards, GUTAUpdateQueue, RegisterUserQueue, DeployContractQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem>(
        genesis_data,
        file_system,
        deploy_contract_gatherer_backup_directory,
        update_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
    )
    .await?;

    tracing::info!("Starting coordinator processor...");
    run_coordinator_processor(processor, guta_gatherer_join_handle, register_users_gatherer_join_handle, deploy_contracts_gatherer_join_handle).await?;

    Ok(())
}
