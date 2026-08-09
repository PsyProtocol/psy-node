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
    }, store::{realm_processor_branch_exact_runtime::{InstalledRealmBranchExactCommitRuntime, RealmBranchExactCommitRuntimeInstaller}, realm_processor_startup::{authorize_realm_processor_startup, RealmProcessorStartupAuthorization, RealmProcessorStartupError, RealmProcessorStartupMode, RealmProcessorStartupPreflightProvider}, traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore}}
};

use crate::realm::processor::{core::{PsyRealmProcessor, runner::run_realm_processor}, db::PsyRealmDatabaseProcessor};

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
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    startup_mode: RealmProcessorStartupMode,
    startup_preflight: Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
    commit_runtime_installer:
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
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
    match startup_authorization {
        RealmProcessorStartupAuthorization::Disabled => {
            if commit_runtime_installer.is_some() {
                return Err(
                    RealmProcessorStartupError::UnexpectedCommitRuntimeInstallerWhileDisabled
                        .into(),
                );
            }
        }
        RealmProcessorStartupAuthorization::BranchExact(run_permit) => {
            let installer = commit_runtime_installer
                .ok_or(RealmProcessorStartupError::CommitRuntimeInstallerMissing)?;
            let installed = installer.install(run_permit).await?;
            return Err(reject_unintegrated_branch_exact_serving(installed).into());
        }
    }

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
    )
    .await?;
    tracing::info!("[REALM_CREATE] processor new done");

    Ok(processor_result)
}

/// The non-Clone fresh permit is consumed at the real serving boundary. Until
/// h23c4 replaces legacy startup/commit with the branch-aware composition,
/// consuming it can only produce a fail-closed error.
fn reject_unintegrated_branch_exact_serving<Hash>(
    _installed: InstalledRealmBranchExactCommitRuntime<Hash>,
) -> RealmProcessorStartupError {
    RealmProcessorStartupError::ServingCompositionNotIntegrated
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
    guta_update_queue: Arc<GUTAUpdateQueue>,
    proof_work_queue: Arc<ProofWorkQueue>,
    realm_identifier: QRealmIdentifier,
    circuit_fingerprint_config: PsyNodeCircuitFingerprintConfig<N::QHash>,
    coordinator_client: Arc<CoordinatorClient>,
    startup_mode: RealmProcessorStartupMode,
    startup_preflight: Option<Arc<dyn RealmProcessorStartupPreflightProvider>>,
    commit_runtime_installer:
        Option<Arc<dyn RealmBranchExactCommitRuntimeInstaller<N::QHash>>>,
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
        startup_mode,
        startup_preflight,
        commit_runtime_installer,
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
        let function = source
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
    fn enabled_permit_is_rejected_until_production_composition_is_integrated() {
        let source = include_str!("create.rs");
        let function = source
            .split("pub async fn create_realm_processor<")
            .nth(1)
            .expect("create_realm_processor must remain present");
        assert!(function.contains(
            "RealmProcessorStartupError::UnexpectedCommitRuntimeInstallerWhileDisabled"
        ));
        assert!(function.contains(
            ".ok_or(RealmProcessorStartupError::CommitRuntimeInstallerMissing)?"
        ));
        let install = function
            .find("installer.install(run_permit).await")
            .expect("enabled startup must install the exact runtime");
        let rejection = function
            .find("reject_unintegrated_branch_exact_serving(installed)")
            .expect("enabled startup must remain fail closed after installation");
        let first_side_effect = function
            .find("GenesisDatabaseDataBuilder::<")
            .expect("genesis builder must remain present");
        assert!(install < rejection && rejection < first_side_effect);
        let rejector = source
            .split("fn reject_unintegrated_branch_exact_serving<Hash>(")
            .nth(1)
            .unwrap()
            .split("pub async fn create_realm_processor_and_run")
            .next()
            .unwrap();
        assert!(rejector.contains("_installed: InstalledRealmBranchExactCommitRuntime<Hash>"));
        assert!(rejector.contains(
            "RealmProcessorStartupError::ServingCompositionNotIntegrated"
        ));
    }
}
