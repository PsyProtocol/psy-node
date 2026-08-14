use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfig};
use rand::RngCore;
use psy_core::{
    constants::chain_id::PsyChainNetworkType,
    job::job_id::QProvingJobDataID,
};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfig,
    genesis::genesis_block_setup::PsyGenesisBlockSetupData,
    protocol::canonical_chain::NetworkId,
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    psy_core_db::traits::full::{PsyCoordinatorProcessorStore, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::StandardProcessorTempDBStoreBase,
    queue::{
        coordinator_guta_durable_submission::CoordinatorGutaDurableSubmissionStore,
        coordinator_processor_durable_capture::CoordinatorProcessorDurableCaptureFactory,
        ephemeral::QStandardEphemeralQueueSubscriber,
        worker_queue::{QStandardWorkerQueuePublisher, QStandardWorkerQueueSubscriber},
    },
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
    store::canonical_head::{
        CanonicalHeadBootstrapProfile, CanonicalHeadReadState,
        CoordinatorCanonicalHeadStore,
    },
    store::rollback_control::RollbackControlState,
    store::realm_processor_quiescence::RealmProcessorDrainRequest,
    store::rollback_admission::CoordinatorRollbackAdmissionStore,
    store::rollback_participant_maintenance::{
        CoordinatorRollbackGlobalProgress, CoordinatorRollbackMaintenanceExecutor,
    },
    store::rollback_runtime_rebuild::{
        CoordinatorRollbackRuntimeRebuildStore, RollbackRuntimeRebuildDirective,
    },
    store::coordinator_processor_branch_exact_runtime::CoordinatorBranchExactProcessorOwner,
    store::coordinator_processor_full_commit::CoordinatorProcessorFullCommitStore,
};

use crate::coordinator::processor::{PsyCoordinatorProcessor, db::PsyCoordinatorDatabaseProcessor, runner::run_coordinator_processor};

/// Resume only the storage-owned post-PONR executor before constructing a
/// normal Coordinator runtime. During DELETING/RESTORING the hot singleton
/// and suffix rows may be intentionally absent, so normal startup must not
/// inspect them until the idempotent executor has reached VERIFYING.
async fn resume_coordinator_post_ponr_before_runtime<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: CoordinatorRollbackMaintenanceExecutor<N::F, N::QHash>
        + CoordinatorRollbackRuntimeRebuildStore<N::QHash>
        + Send
        + Sync,
>(
    network: PsyChainNetworkType,
    canonical_head_store: &dyn CoordinatorCanonicalHeadStore<N::QHash>,
    db: &S,
) -> anyhow::Result<Option<RollbackRuntimeRebuildDirective<N::QHash>>> {
    let network_id = NetworkId::from(network);
    loop {
        let head = match canonical_head_store.read_canonical_head(network_id).await? {
            CanonicalHeadReadState::Current(head) => head,
            CanonicalHeadReadState::Uninitialized => return Ok(None),
        };
        if !matches!(
            head.rollback_control(),
            RollbackControlState::Deleting(_) | RollbackControlState::Restoring(_)
        ) {
            if matches!(
                head.rollback_control(),
                RollbackControlState::Verifying(_) | RollbackControlState::AllRealmsReady(_)
            ) {
                if let Some(directive) = db
                    .read_selected_coordinator_runtime_rebuild(network_id)
                    .await?
                {
                    return Ok(Some(directive));
                }
                tracing::warn!(
                    "Coordinator startup recovery awaits its durable runtime rebuild directive"
                );
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
            return Ok(None);
        }
        match db
            .progress_coordinator_rollback(network_id, N::CHECKPOINT_TREE_HEIGHT)
            .await?
        {
            CoordinatorRollbackGlobalProgress::ReadyForRuntimeRebuild(_) => continue,
            CoordinatorRollbackGlobalProgress::AwaitingParticipants {
                completed,
                expected,
                ..
            } => tracing::warn!(
                "Coordinator startup recovery awaits post-PONR participants: {completed}/{expected}"
            ),
            CoordinatorRollbackGlobalProgress::Progressed(current) => tracing::warn!(
                "Coordinator startup recovery advanced durable rollback phase at epoch {}, checkpoint {}",
                current.canonical_ref().chain_epoch().get(),
                current.canonical_ref().checkpoint().checkpoint_id().get(),
            ),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

async fn read_coordinator_initial_rollback_drain<Hash>(
    network: PsyChainNetworkType,
    realm_identifier: QRealmIdentifier,
    canonical_head_store: &dyn CoordinatorCanonicalHeadStore<Hash>,
) -> anyhow::Result<Option<RealmProcessorDrainRequest>>
where
    Hash: parth_core::protocol::core_types::Q256BitHash,
{
    let network_id = NetworkId::from(network);
    let head = match canonical_head_store.read_canonical_head(network_id).await? {
        CanonicalHeadReadState::Current(head) => head,
        CanonicalHeadReadState::Uninitialized => return Ok(None),
    };
    let Some(request) = head.rollback_control().requested() else {
        return Ok(None);
    };
    Ok(Some(RealmProcessorDrainRequest::try_new(
        network_id,
        realm_identifier.realm_id,
        realm_identifier.realm_sub_id,
        head.canonical_ref().chain_epoch().get(),
        head.revision().get(),
        *request.plan_digest().as_bytes(),
        *request.plan_digest().as_bytes(),
    )?))
}

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
    branch_exact_full_commit:
        Option<Arc<dyn CoordinatorProcessorFullCommitStore<N::QHash>>>,
    rollback_restart_directive: Option<RollbackRuntimeRebuildDirective<N::QHash>>,
    initial_rollback_drain: Option<RealmProcessorDrainRequest>,
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
        branch_exact_full_commit,
        rollback_restart_directive,
        initial_rollback_drain,
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
        None,
        None,
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
    branch_exact_full_commit:
        Arc<dyn CoordinatorProcessorFullCommitStore<N::QHash>>,
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
        Some(branch_exact_full_commit),
        None,
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


fn fresh_coordinator_owner_attempt_digest() -> [u8; 32] {
    loop {
        let mut digest = [0; 32];
        rand::thread_rng().fill_bytes(&mut digest);
        if digest != [0; 32] {
            return digest;
        }
    }
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
    branch_exact_capture_factory:
        Option<Arc<dyn CoordinatorProcessorDurableCaptureFactory>>,
    branch_exact_full_commit:
        Option<Arc<dyn CoordinatorProcessorFullCommitStore<N::QHash>>>,
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
    let mut rollback_restart_directive = None;
    loop {
        if rollback_restart_directive.is_none() {
            rollback_restart_directive = resume_coordinator_post_ponr_before_runtime::<N, S>(
                network,
                canonical_head_store.as_ref(),
                db.as_ref(),
            )
            .await?;
        }
        let initial_rollback_drain = read_coordinator_initial_rollback_drain(
            network,
            realm_identifier,
            canonical_head_store.as_ref(),
        )
        .await?;
        let (normal_processing_owner, full_commit) = match (
            branch_exact_capture_factory.as_ref(),
            branch_exact_full_commit.as_ref(),
        ) {
            (None, None) => (
                crate::coordinator::processor::CoordinatorNormalProcessingOwner::legacy(),
                None,
            ),
            (Some(factory), Some(full_commit)) => {
                let owner = CoordinatorBranchExactProcessorOwner::install(
                    Arc::clone(factory),
                    NetworkId::from(network),
                    factory.writer_activation_digest(),
                    factory.queue_readiness_digest(),
                    fresh_coordinator_owner_attempt_digest(),
                )?;
                (
                    crate::coordinator::processor::CoordinatorNormalProcessingOwner::branch_exact(owner),
                    Some(Arc::clone(full_commit)),
                )
            }
            _ => anyhow::bail!(
                "Coordinator branch-exact capture and full-commit capabilities must be supplied together"
            ),
        };
        let (processor, guta_gatherer_join_handle, register_users_gatherer_join_handle, deploy_contracts_gatherer_join_handle) = create_coordinator_processor_with_processing_owner::<N, S, STagTreeRewards, GUTAUpdateQueue, RegisterUserQueue, DeployContractQueue, ProofWorkQueue, TempDatabase, ProofStore, FileSystem>(
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
            normal_processing_owner,
            full_commit,
            rollback_restart_directive.take(),
            initial_rollback_drain,
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
            super::core::runner::CoordinatorProcessorRunExit::RestartAfterRollback {
                published,
                directive,
            } => {
                rollback_restart_directive = Some(directive);
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
        None,
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
    fn active_rollback_is_selected_before_coordinator_actor_construction() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let function = production
            .split("pub async fn create_coordinator_processor_and_run_with_durable_guta_submissions<")
            .nth(1)
            .expect("Coordinator create-and-run entry");
        let read = function
            .find("read_coordinator_initial_rollback_drain(")
            .expect("active rollback selector");
        let create = function
            .find("create_coordinator_processor_with_processing_owner::<")
            .expect("actor construction");
        let consume = function
            .find("initial_rollback_drain,")
            .expect("sealed startup drain input");
        assert!(read < create && create < consume);

        let helper = production
            .split("async fn read_coordinator_initial_rollback_drain<")
            .nth(1)
            .unwrap()
            .split("async fn create_coordinator_processor_with_processing_owner<")
            .next()
            .unwrap();
        assert!(helper.contains("head.rollback_control().requested()"));
        assert!(helper.contains("RealmProcessorDrainRequest::try_new("));
        let startup = include_str!("core/startup.rs");
        assert_eq!(
            startup
                .matches("new_with_status_initially_paused::<")
                .count(),
            3
        );
        assert!(startup.contains("initial_rollback_pauses,"));
    }

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
        assert!(branch_exact.contains("Some(branch_exact_full_commit)"));
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
        let maintenance_resume = function
            .find("resume_coordinator_post_ponr_before_runtime::<")
            .expect("post-PONR maintenance resume");
        let create = function
            .find("create_coordinator_processor_with_processing_owner::<")
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
        let consume = function
            .find("rollback_restart_directive.take()")
            .expect("restart directive consumption");
        let retain = function
            .find("rollback_restart_directive = Some(directive)")
            .expect("restart directive retention");
        assert!(recreate_loop < maintenance_resume && maintenance_resume < create && create < run);
        assert!(create < consume && consume < run && restart < retain);
        assert!(run < shutdown && run < restart);
        assert!(!function[restart..].contains("return Ok(())"));
    }

    #[test]
    fn coordinator_run_loop_installs_branch_exact_capabilities_as_one_pair() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let function = production
            .split("pub async fn create_coordinator_processor_and_run_with_durable_guta_submissions<")
            .nth(1)
            .expect("Coordinator create-and-run entry");
        let recreate_loop = function.find("loop {").expect("recreate loop");
        let capability_match = function
            .find("branch_exact_capture_factory.as_ref()")
            .expect("paired branch-exact capability match");
        let owner_install = function
            .find("CoordinatorBranchExactProcessorOwner::install(")
            .expect("fresh owner installation");
        let processor_create = function
            .find("create_coordinator_processor_with_processing_owner::<")
            .expect("processor construction");
        assert!(recreate_loop < capability_match);
        assert!(capability_match < owner_install && owner_install < processor_create);
        assert!(function.contains("(None, None)"));
        assert!(function.contains("(Some(factory), Some(full_commit))"));
        assert!(function.contains("must be supplied together"));
        assert!(function.contains("fresh_coordinator_owner_attempt_digest()"));
    }

    #[test]
    fn post_ponr_executor_runs_before_coordinator_db_or_actor_construction() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let helper = production
            .split("async fn resume_coordinator_post_ponr_before_runtime")
            .nth(1)
            .expect("maintenance-only startup helper")
            .split("async fn create_coordinator_processor_with_processing_owner")
            .next()
            .unwrap();
        assert!(helper.contains("RollbackControlState::Deleting"));
        assert!(helper.contains("RollbackControlState::Restoring"));
        assert!(helper.contains("progress_coordinator_rollback"));
        assert!(helper.contains("read_selected_coordinator_runtime_rebuild"));
        assert!(!helper.contains("PsyCoordinatorDatabaseProcessor::<"));
        assert!(!helper.contains("PsyCoordinatorProcessor::new"));
    }
}
