use std::sync::Arc;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::time::Duration;
use parth_core::{
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{QNetworkHashTypes, QNetworkTreeConstants, QNetworkTypesConfigHelper},
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfigProvider, genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider,
};
use psy_io::tokio::{TokioLikeFileSystem, TokioStdFileSystem};
use psy_node_common::{coordinator::processor::create::create_coordinator_processor_and_run_with_durable_guta_submissions, p2p::realm_coordinator::PsyRealmCoordinatorClientAPI, realm::processor::create::create_realm_processor_and_run};
use psy_node_core::{
    config::node_start_config::{CoordinatorProcessorStartConfig, RealmProcessorStartConfig},
    genesis::genesis_db_data_builder::GenesisDatabaseDataBuilder,
    store::rollback_runtime_rebuild::RealmRollbackRuntimeControl,
};
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::{
    setup_coordinator_psy_scylla_database_store_from_connection_string,
    setup_realm_processor_scylla_startup_composition,
};
use psy_node_scylla::rollback::PendingQueueSidecarSetupMode;
use psy_plonky2_circuits::{
    node::config::networks::resolver::PsyPlonky2NodeConfigResolver,
    protocol_types::ZKTypesPlonky2GoldilocksPoseidon,
    zk_verifier::PsyPlonky2ZKVerifier,
};
use psy_data::protocol::chain_context::AuthorityScope;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

pub async fn run_startup_plonky2_scylla_coordinator_processor_node(config: &CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyPlonky2NodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network, config.genesis_data_path.clone())?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace).await?;

    let file_system = TokioStdFileSystem {};

    let file_system = Arc::new(file_system);
    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);

    let deploy_contract_gatherer_backup_directory = config.get_deploy_contracts_backup_path();
    let register_user_gatherer_backup_directory = config.get_register_users_backup_path();
    let guta_gatherer_backup_directory = config.get_guta_updates_backup_path();
    let checkpoint_tree_root_backup_file_path = config.get_checkpoint_tree_backup_file_path();
    file_system
        .file_like_fs_create_dir_all(&deploy_contract_gatherer_backup_directory)
        .await?;
    file_system.file_like_fs_create_dir_all(&register_user_gatherer_backup_directory).await?;
    file_system.file_like_fs_create_dir_all(&guta_gatherer_backup_directory).await?;

    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let register_user_queue = nats_queue.clone();
    let deploy_contract_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_identifier = QRealmIdentifier {
        realm_id: config.coordinator_id as u32,
        realm_sub_id: config.coordinator_sub_id,
    };

    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_coordinator_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            if let Some(topology) = &config.rollback_topology {
                db.store
                    .install_coordinator_rollback_topology(
                        &topology.try_snapshot(config.network)?,
                    )
                    .await?;
            }
            let (
                durable_guta_submissions,
                branch_exact_capture_factory,
                branch_exact_full_commit,
            ) = if let Some(startup) = &config.branch_exact_startup {
                let (genesis_transition, _) = GenesisDatabaseDataBuilder::<
                    <N as QNetworkHashTypes>::F,
                    <N as QNetworkHashTypes>::QHash,
                >::setup_for_coordinator::<<N as QNetworkHashTypes>::HasherBase, N>(
                    &genesis_data,
                    circuit_fingerprint_config
                        .checkpoint_state_transition_circuit_fingerprint,
                )?;
                let (submissions, capture, full_commit) = db
                    .store
                    .prepare_coordinator_processor_branch_exact_runtime::<<N as QNetworkHashTypes>::F>(
                        config.network.into(),
                        nats_queue.clone(),
                        startup.try_writer_activation_digest()?,
                        genesis_transition
                            .state_transition
                            .genesis_checkpoint_state_transition_hash,
                        circuit_fingerprint_config
                            .checkpoint_state_transition_circuit_fingerprint,
                        N::CHECKPOINT_TREE_HEIGHT,
                    )
                    .await?;
                (Some(submissions), Some(capture), Some(full_commit))
            } else if config.durable_guta_submission_enabled {
                db.store.initialize_pending_queue_sidecar_setup(
                    AuthorityScope::Coordinator,
                    PendingQueueSidecarSetupMode::RequireVerified,
                ).await?;
                (
                    Some(db.store.prepare_coordinator_guta_durable_submission_store(config.network.into()).await?),
                    None,
                    None,
                )
            } else {
                (None, None, None)
            };
            let canonical_head_store = db.store.clone();
            let rollback_admission_store = db.store.clone();
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run_with_durable_guta_submissions::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
                config.network,
                config.canonical_head_bootstrap_profile,
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
                durable_guta_submissions,
                branch_exact_capture_factory,
                branch_exact_full_commit,
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for Plonky2 Scylla coordinator processor node", config.network );
        }
        /*
        psy_core::constants::chain_id::PsyChainNetworkType::PsyTeamDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalPreProduction => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicCanary => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyMainnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }*/
    }


    Ok(())
}

pub async fn run_startup_plonky2_scylla_realm_processor_node(config: &RealmProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyPlonky2NodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network, config.genesis_data_path.clone())?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.realm_id as u64,
        config.realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace).await?;

    let file_system = TokioStdFileSystem {};

    let file_system = Arc::new(file_system);
    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);

    let guta_gatherer_backup_directory = config.get_guta_updates_backup_path();
    let checkpoint_tree_root_backup_file_path = config.get_checkpoint_tree_backup_file_path();
    file_system.file_like_fs_create_dir_all(&guta_gatherer_backup_directory).await?;

    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_id = u32::try_from(config.realm_id)
        .map_err(|_| anyhow::anyhow!("Realm ID exceeds u32"))?;
    let realm_identifier = QRealmIdentifier {
        realm_id,
        realm_sub_id: config.realm_sub_id,
    };
    let branch_exact_lineage = config
        .branch_exact_startup
        .as_ref()
        .map(|activation| {
            activation.try_lineage(
                config.network,
                config.realm_id,
                config.realm_sub_id,
            )
        })
        .transpose()?;
    let proof_verifier = if branch_exact_lineage.is_some() {
        Some(Arc::new(PsyPlonky2ZKVerifier::<C, D>::for_network(
            config.network,
        )?))
    } else {
        None
    };
    let chain_id = config.network.get_chain_id();
    if config.coordinator_api_urls.is_empty() {
        anyhow::bail!("No coordinator API URLs provided for realm processor node");
    }
    
    let http_client: HttpClient = HttpClientBuilder::default().set_keep_alive(Some(Duration::from_secs(10))).build(&config.coordinator_api_urls[0])?;

    /*
    
    
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
    
     */
    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let composition = setup_realm_processor_scylla_startup_composition::<N>(
                &config.db_namespace,
                &config.scylla_db_url,
                true,
                realm_id,
                config.realm_sub_id,
                branch_exact_lineage,
                nats_queue.clone(),
            )
            .await?;
            let (
                db,
                startup_mode,
                startup_preflight,
                commit_runtime_installer,
            ) = composition.into_parts();
            let rollback_runtime_control = match config
                .coordinator_rollback_db_namespace
                .as_deref()
            {
                Some(keyspace) => Some(Arc::new(
                    db.store.prepare_realm_rollback_runtime_control(keyspace)
                    .await?,
                ) as Arc<dyn RealmRollbackRuntimeControl<<N as QNetworkHashTypes>::QHash>>),
                None => None,
            };
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            let coordinator_client = PsyRealmCoordinatorClientAPI::<N, _>::new(
                http_client,
            );
            create_realm_processor_and_run::<N, _, _, _, _, _, _, _, _>(
                chain_id,
                &genesis_data,
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
                Arc::new(coordinator_client),
                startup_mode,
                startup_preflight,
                commit_runtime_installer,
                rollback_runtime_control,

            )
            .await?;
        }
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for Plonky2 Scylla coordinator processor node", config.network );
        }
        /*
        psy_core::constants::chain_id::PsyChainNetworkType::PsyTeamDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::InternalPreProduction => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicCanary => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }
        psy_core::constants::chain_id::PsyChainNetworkType::PsyMainnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                &genesis_data,
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
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
            )
            .await?;
        }*/
    }


    Ok(())
}
