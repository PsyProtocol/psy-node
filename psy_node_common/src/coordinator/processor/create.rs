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

#[cfg(test)]
mod create_and_run_tests {
    use std::{sync::Arc, time::{Duration, Instant}};

    use parth_core::node::realm_identifier::QRealmIdentifier;

    use crate::{
        coordinator::processor::{
            core::startup::startup_tests::{fingerprint_config, genesis_setup_data, N},
            create::create_coordinator_processor_and_run,
        },
        test_common::{create_test_unified_db, FakeEphemeralQueueSubscriber, FakeWorkerQueue},
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::PsyNodeCheckpointObjectDatabaseReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    #[tokio::test]
    async fn create_coordinator_processor_and_run_builds_processor_and_keeps_loop_alive() -> anyhow::Result<()> {
        let db = Arc::new(create_test_unified_db().await?);
        let tag_tree = Arc::clone(&db);
        let temp_db = Arc::new(InMemoryTempStore::new("coord_create_test".to_string(), 1, 2));
        let proof_store = Arc::clone(&temp_db);
        let guta_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
        let register_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
        let deploy_queue = Arc::new(FakeEphemeralQueueSubscriber::new());
        let proof_work_queue = Arc::new(FakeWorkerQueue::new());
        let file_system = Arc::new(SimpleMockMemoryFileSystem::new());

        let genesis_data = Arc::new(genesis_setup_data());
        let task_genesis_data = Arc::clone(&genesis_data);
        let observe_db = Arc::clone(&db);
        let observe_guta_queue = Arc::clone(&guta_queue);
        let task = tokio::spawn(async move {
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &task_genesis_data,
                fingerprint_config(),
                Arc::clone(&file_system),
                "coord_create_deploy_backups".to_string(),
                "coord_create_update_backups".to_string(),
                "coord_create_register_backups".to_string(),
                "coord_create_guta_backups".to_string(),
                "coord_create_checkpoint_tree_backup.bin".to_string(),
                Arc::clone(&db),
                tag_tree,
                Arc::clone(&temp_db),
                Arc::clone(&proof_store),
                Arc::clone(&guta_queue),
                Arc::clone(&register_queue),
                Arc::clone(&deploy_queue),
                Arc::clone(&proof_work_queue),
                QRealmIdentifier::new(1, 2),
            )
            .await
        });

        // construction ensures queue consumers; poll for that side effect
        // instead of assuming a fixed startup duration
        let deadline = Instant::now() + Duration::from_secs(10);
        while observe_guta_queue.ensured_consumers.lock().unwrap().is_empty() {
            assert!(Instant::now() < deadline, "and_run never built the processor");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(observe_db.get_latest_checkpoint_id().await?, 0);

        // the run loop is now driving the processor; the task must not have
        // exited (it only returns on shutdown or a fatal join error)
        assert!(!task.is_finished());
        task.abort();
        Ok(())
    }
}
