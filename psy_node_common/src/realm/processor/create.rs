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
    }, store::{realm_processor_branch_exact_runtime::{RealmBranchExactCommitRuntimeInstaller, RealmBranchExactSingleCommitOwner}, realm_processor_startup::{authorize_realm_processor_startup, RealmProcessorStartupAuthorization, RealmProcessorStartupError, RealmProcessorStartupMode, RealmProcessorStartupPreflightProvider}, rollback_runtime_rebuild::RealmRollbackRuntimeControl, traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore}}
};

use crate::realm::processor::{core::{PsyRealmProcessor, RealmNormalCommitOwner, runner::run_realm_processor}, db::PsyRealmDatabaseProcessor};

pub async fn create_realm_processor<
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    GUTAUpdateQueue: QStandardEphemeralQueueSubscriber + Send + Sync + 'static,
    ProofWorkQueue: QStandardWorkerQueuePublisher + QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
    proof_verifier: Option<Arc<N::ZKVerifier>>,
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    startup_mode: RealmProcessorStartupMode,
    startup_preflight: Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
    commit_runtime_installer:
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
    rollback_runtime_control:
        Option<Arc<dyn RealmRollbackRuntimeControl<N::QHash>>>,
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
    if let RealmProcessorStartupMode::RequireBranchExact(expectation) = startup_mode {
        if expectation.network().chain_id() != chain_id
            || expectation.realm_id() != realm_identifier.realm_id
            || expectation.realm_sub_id() != realm_identifier.realm_sub_id
        {
            return Err(RealmProcessorStartupError::AuthorityMismatch.into());
        }
    }
    let startup_authorization =
        authorize_realm_processor_startup(startup_mode, startup_preflight.as_deref()).await?;
    let normal_commit_owner = match startup_authorization {
        RealmProcessorStartupAuthorization::Disabled => {
            if proof_verifier.is_some() {
                return Err(
                    RealmProcessorStartupError::UnexpectedProofVerifierWhileDisabled
                        .into(),
                );
            }
            if commit_runtime_installer.is_some() {
                return Err(
                    RealmProcessorStartupError::UnexpectedCommitRuntimeInstallerWhileDisabled
                        .into(),
                );
            }
            RealmNormalCommitOwner::legacy_disabled()
        }
        RealmProcessorStartupAuthorization::BranchExact(run_permit) => {
            if proof_verifier.is_none() {
                return Err(RealmProcessorStartupError::ProofVerifierMissing.into());
            }
            let installer = commit_runtime_installer
                .ok_or(RealmProcessorStartupError::CommitRuntimeInstallerMissing)?;
            let installed = installer.install(run_permit).await?;
            let commit_owner = RealmBranchExactSingleCommitOwner::from_installed(installed);
            RealmNormalCommitOwner::branch_exact(commit_owner)
        }
    };

    tracing::info!("[REALM_CREATE] setup_for_realm start");
    let genesis =
        GenesisDatabaseDataBuilder::<N::F, N::QHash>::setup_for_realm::<N::HasherBase, N>(
            genesis_data,
            realm_identifier.realm_id as u64,
            realm_identifier.realm_sub_id as u64,
            chain_id,
            circuit_fingerprint_config.genesis_checkpoint_state_transition_fingerprint,
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
        proof_verifier,
        normal_commit_owner,
        rollback_runtime_control,
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
    ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
    proof_verifier: Option<Arc<N::ZKVerifier>>,
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    startup_mode: RealmProcessorStartupMode,
    startup_preflight: Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
    commit_runtime_installer:
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
    rollback_runtime_control:
        Option<Arc<dyn RealmRollbackRuntimeControl<N::QHash>>>,
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
        proof_verifier,
        guta_update_queue,
        proof_work_queue,
        realm_identifier,
        circuit_fingerprint_config,
        coordinator_client,
        startup_mode,
        startup_preflight,
        commit_runtime_installer,
        rollback_runtime_control,
    )
    .await?;

    tracing::info!("Starting realm processor...");
    run_realm_processor(processor, guta_gatherer_join_handle).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn startup_preflight_precedes_every_realm_startup_side_effect() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let function = production
            .split("pub async fn create_realm_processor<")
            .nth(1)
            .expect("create_realm_processor must remain present");
        let preflight = function
            .find("authorize_realm_processor_startup(")
            .expect("startup must authorize at the real creation entrance");
        for side_effect in [
            "GenesisDatabaseDataBuilder::<",
            "PsyRealmDatabaseProcessor::<",
            "PsyRealmProcessor::new(",
        ] {
            assert!(
                preflight < function.find(side_effect).expect("startup step must remain present"),
                "preflight must precede {side_effect}"
            );
        }
    }

    #[test]
    fn enabled_permit_installs_the_single_branch_exact_serving_owner() {
        let source = include_str!("create.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        let function = production
            .split("pub async fn create_realm_processor<")
            .nth(1)
            .expect("create_realm_processor must remain present");
        assert!(function.contains(
            "RealmProcessorStartupError::UnexpectedCommitRuntimeInstallerWhileDisabled"
        ));
        assert!(function.contains(
            "RealmProcessorStartupError::UnexpectedProofVerifierWhileDisabled"
        ));
        assert!(function.contains(
            "RealmProcessorStartupError::ProofVerifierMissing"
        ));
        assert!(function.contains(
            ".ok_or(RealmProcessorStartupError::CommitRuntimeInstallerMissing)?"
        ));
        let install = function
            .find("installer.install(run_permit).await")
            .expect("enabled startup must install the exact runtime");
        let owner = function
            .find("RealmBranchExactSingleCommitOwner::from_installed(installed)")
            .expect("installed runtime must have one process-local owner");
        let routed_owner = function
            .find("RealmNormalCommitOwner::branch_exact(commit_owner)")
            .expect("enabled startup must route the installed owner");
        let first_side_effect = function
            .find("GenesisDatabaseDataBuilder::<")
            .expect("genesis builder must remain present");
        assert!(install < owner && owner < routed_owner && routed_owner < first_side_effect);
        assert!(!function.contains("reject_unintegrated_branch_exact_serving"));
        assert!(!function.contains("ServingCompositionNotIntegrated"));
    }

    #[test]
    fn proof_verifier_is_required_only_for_branch_exact_startup() {
        let source = include_str!("create.rs");
        let function = source
            .split("pub async fn create_realm_processor<")
            .nth(1)
            .expect("create_realm_processor must remain present");
        let disabled = function
            .split("RealmProcessorStartupAuthorization::Disabled =>")
            .nth(1)
            .unwrap()
            .split("RealmProcessorStartupAuthorization::BranchExact")
            .next()
            .unwrap();
        assert!(disabled.contains("if proof_verifier.is_some()"));
        assert!(disabled.contains("UnexpectedProofVerifierWhileDisabled"));

        let enabled = function
            .split("RealmProcessorStartupAuthorization::BranchExact")
            .nth(1)
            .unwrap()
            .split("tracing::info!(\"[REALM_CREATE] setup_for_realm start\")")
            .next()
            .unwrap();
        assert!(enabled.contains("if proof_verifier.is_none()"));
        assert!(enabled.contains("ProofVerifierMissing"));
    }
}
