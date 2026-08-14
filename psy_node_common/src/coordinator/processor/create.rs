use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig};
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    job::job_id::QProvingJobDataID,
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig, genesis::genesis_block_setup::PsyGenesisBlockSetupData,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        coordinator_guta_durable_submission::CoordinatorGutaDurableSubmissionStore,
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
    store::canonical_head::{
        CanonicalHeadBootstrapProfile, CoordinatorCanonicalHeadStore,
    },
    store::rollback_admission::CoordinatorRollbackAdmissionStore,
    store::rollback_participant_maintenance::CoordinatorRollbackMaintenanceExecutor,
    store::rollback_runtime_rebuild::CoordinatorRollbackRuntimeRebuildStore,
    store::coordinator_processor_branch_exact_runtime::CoordinatorBranchExactProcessorOwner,
};

use crate::coordinator::processor::{PsyCoordinatorProcessor, db::PsyCoordinatorDatabaseProcessor, runner::run_coordinator_processor};

async fn create_coordinator_processor_with_processing_owner<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    durable_guta_submissions:
        Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,
    normal_processing_owner:
        crate::coordinator::processor::CoordinatorNormalProcessingOwner,
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
        canonical_head_store,
        rollback_admission_store,
        network,
        canonical_head_bootstrap_profile,
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
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        durable_guta_submissions,
        normal_processing_owner,
    )
    .await?;
    tracing::info!("[COORD_CREATE] processor new done");

    Ok(processor_result)
}

pub async fn create_coordinator_processor_with_durable_guta_submissions<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
        + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
        + Send
        + Sync
        + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher
        + QStandardWorkerQueueSubscriber
        + Send
        + Sync
        + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>
        + Send
        + Sync
        + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    durable_guta_submissions:
        Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,
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
    create_coordinator_processor_with_processing_owner(
        genesis_data,
        network,
        canonical_head_bootstrap_profile,
        canonical_head_store,
        rollback_admission_store,
        file_system,
        deploy_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        durable_guta_submissions,
        crate::coordinator::processor::CoordinatorNormalProcessingOwner::legacy(),
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
    )
    .await
}

/// Explicit default-off constructor for the branch-exact Coordinator capture
/// owner. It installs command-only gatherers and never falls back to legacy
/// whole-queue draining for this Processor instance.
pub async fn create_coordinator_processor_with_branch_exact_capture<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
        + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
        + Send
        + Sync
        + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher
        + QStandardWorkerQueueSubscriber
        + Send
        + Sync
        + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>
        + Send
        + Sync
        + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    durable_guta_submissions:
        Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,
    branch_exact_owner: CoordinatorBranchExactProcessorOwner,
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
    if branch_exact_owner.network() != network.into() {
        anyhow::bail!("branch-exact Coordinator owner network does not match Processor network");
    }
    create_coordinator_processor_with_processing_owner(
        genesis_data,
        network,
        canonical_head_bootstrap_profile,
        canonical_head_store,
        rollback_admission_store,
        file_system,
        deploy_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        durable_guta_submissions,
        crate::coordinator::processor::CoordinatorNormalProcessingOwner::branch_exact(
            branch_exact_owner,
        ),
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
    )
    .await
}

pub async fn create_coordinator_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
        + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
        + Send
        + Sync
        + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher
        + QStandardWorkerQueueSubscriber
        + Send
        + Sync
        + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>
        + Send
        + Sync
        + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
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
    create_coordinator_processor_with_durable_guta_submissions::<
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
    >(
        genesis_data,
        network,
        canonical_head_bootstrap_profile,
        canonical_head_store,
        rollback_admission_store,
        file_system,
        deploy_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        None,
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
    )
    .await
}



pub async fn create_coordinator_processor_and_run_with_durable_guta_submissions<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
    register_user_gatherer_backup_directory: String,
    guta_gatherer_backup_directory: String,
    checkpoint_tree_root_backup_file_path: String,
    db: Arc<S>,
    tag_tree_rewards_store: Arc<STagTreeRewards>,
    temp_db: Arc<TempDatabase>,
    proof_store: Arc<ProofStore>,
    durable_guta_submissions:
        Option<Arc<dyn CoordinatorGutaDurableSubmissionStore<N::QHash>>>,
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
    loop {
        let (processor, guta_gatherer_join_handle, register_users_gatherer_join_handle, deploy_contracts_gatherer_join_handle) = create_coordinator_processor_with_durable_guta_submissions::<N, S, STagTreeRewards, GUTAUpdateQueue, RegisterUserQueue, DeployContractQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem>(
            genesis_data,
            network,
            canonical_head_bootstrap_profile,
            canonical_head_store.clone(),
            rollback_admission_store.clone(),
            file_system.clone(),
            deploy_contract_gatherer_backup_directory.clone(),
            register_user_gatherer_backup_directory.clone(),
            guta_gatherer_backup_directory.clone(),
            checkpoint_tree_root_backup_file_path.clone(),
            db.clone(),
            tag_tree_rewards_store.clone(),
            temp_db.clone(),
            proof_store.clone(),
            durable_guta_submissions.clone(),
            guta_update_queue.clone(),
            register_user_queue.clone(),
            deploy_contract_queue.clone(),
            proof_work_queue.clone(),
            realm_identifier,
            circuit_fingerprint_config.clone(),
        )
        .await?;

        tracing::info!("Starting coordinator processor...");
        match run_coordinator_processor(
            processor,
            guta_gatherer_join_handle,
            register_users_gatherer_join_handle,
            deploy_contracts_gatherer_join_handle,
        )
        .await?
        {
            super::core::runner::CoordinatorProcessorRunExit::ShutdownRequested => {
                return Ok(())
            }
            super::core::runner::CoordinatorProcessorRunExit::RestartAfterRollback(
                published,
            ) => {
                tracing::warn!(
                    "Coordinator rollback target {} at epoch {} is published; recreating all three gatherer trees from restored storage",
                    published.canonical_ref().checkpoint().checkpoint_id().get(),
                    published.canonical_ref().chain_epoch().get(),
                );
            }
        }
    }
}

pub async fn create_coordinator_processor_and_run<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyCoordinatorProcessorStore<N::F, N::QHash>
        + CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync
        + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash>
        + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash>
        + Send
        + Sync
        + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    RegisterUserQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    DeployContractQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher
        + QStandardWorkerQueueSubscriber
        + Send
        + Sync
        + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>
        + Send
        + Sync
        + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    FileSystem: TokioLikeFileSystem + Send + Sync + 'static,
>(
    genesis_data: &PsyGenesisBlockSetupData<N::F, N::QHash>,
    network: PsyChainNetworkType,
    canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    canonical_head_store: Arc<dyn CoordinatorCanonicalHeadStore<N::QHash>>,
    rollback_admission_store: Arc<dyn CoordinatorRollbackAdmissionStore<N::QHash>>,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    file_system: Arc<FileSystem>,
    deploy_contract_gatherer_backup_directory: String,
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
    create_coordinator_processor_and_run_with_durable_guta_submissions::<
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
    >(
        genesis_data,
        network,
        canonical_head_bootstrap_profile,
        canonical_head_store,
        rollback_admission_store,
        circuit_fingerprint_config,
        file_system,
        deploy_contract_gatherer_backup_directory,
        register_user_gatherer_backup_directory,
        guta_gatherer_backup_directory,
        checkpoint_tree_root_backup_file_path,
        db,
        tag_tree_rewards_store,
        temp_db,
        proof_store,
        None,
        guta_update_queue,
        register_user_queue,
        deploy_contract_queue,
        proof_work_queue,
        realm_identifier,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn legacy_and_branch_exact_constructors_install_disjoint_processing_owners() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let legacy = production
            .split("pub async fn create_coordinator_processor_with_durable_guta_submissions")
            .nth(1)
            .unwrap()
            .split("pub async fn create_coordinator_processor_with_branch_exact_capture")
            .next()
            .unwrap();
        assert!(legacy.contains("CoordinatorNormalProcessingOwner::legacy()"));
        assert!(!legacy.contains("CoordinatorNormalProcessingOwner::branch_exact"));

        let branch_exact = production
            .split("pub async fn create_coordinator_processor_with_branch_exact_capture")
            .nth(1)
            .unwrap()
            .split("pub async fn create_coordinator_processor<")
            .next()
            .unwrap();
        assert!(branch_exact.contains("branch_exact_owner.network() != network.into()"));
        assert!(branch_exact.contains("CoordinatorNormalProcessingOwner::branch_exact"));
        assert!(!branch_exact.contains("CoordinatorNormalProcessingOwner::legacy()"));
    }

    #[test]
    fn coordinator_create_loop_rebuilds_all_actors_after_rollback() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let function = production
            .split("pub async fn create_coordinator_processor_and_run_with_durable_guta_submissions<")
            .nth(1)
            .expect("Coordinator create-and-run entry");
        let recreate_loop = function.find("loop {").expect("recreate loop");
        let create = function
            .find("create_coordinator_processor_with_durable_guta_submissions::<")
            .expect("processor construction");
        let run = function
            .find("match run_coordinator_processor(")
            .expect("processor runner");
        let restart = function
            .find("CoordinatorProcessorRunExit::RestartAfterRollback")
            .expect("rollback restart branch");
        let shutdown = function
            .find("CoordinatorProcessorRunExit::ShutdownRequested")
            .expect("shutdown branch");
        assert!(recreate_loop < create && create < run);
        assert!(run < shutdown && run < restart);
        assert!(!function[restart..].contains("return Ok(())"));
    }
}
