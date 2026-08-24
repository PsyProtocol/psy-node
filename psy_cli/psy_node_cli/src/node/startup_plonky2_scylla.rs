use std::sync::Arc;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::time::Duration;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfigProvider, genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider,
};
use psy_io::tokio::{TokioLikeFileSystem, TokioStdFileSystem};
use psy_node_common::{coordinator::processor::create::create_coordinator_processor_and_run, p2p::realm_coordinator::PsyRealmCoordinatorClientAPI, realm::processor::create::create_realm_processor_and_run};
use psy_node_core::config::node_start_config::{CoordinatorProcessorStartConfig, RealmProcessorStartConfig};
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_scylla::rollback::{coordinator_branch_namespace, realm_branch_namespace};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::{setup_coordinator_psy_scylla_store_from_connection_string, setup_psy_scylla_database_store_from_connection_string, setup_realm_psy_scylla_store_from_connection_string};
use psy_plonky2_circuits::{
    node::config::networks::resolver::PsyPlonky2NodeConfigResolver,
    protocol_types::ZKTypesPlonky2GoldilocksPoseidon,
};

pub async fn run_startup_plonky2_scylla_coordinator_processor_node(config: &CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyPlonky2NodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network, config.genesis_data_path.clone())?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    // Redis and NATS answer to the branch this node is on, not merely to the
    // deployment: a rollback leaves the discarded branch's queue messages and
    // Redis entries behind, and they are keyed by ids the new branch issues
    // again.  See `psy_node_scylla::rollback::branch_namespace`.  Read before
    // either store is built, because the name is what they are built with --
    // and the Scylla keyspaces keep their plain names, since they hold the
    // state that was repaired rather than abandoned.
    let (branch_ns, _branch_epoch) = coordinator_branch_namespace(
        &config.scylla_db_url,
        &config.db_namespace,
        config.network.get_chain_id() as i64,
    )
    .await?;
    let temp_store = StandardRedisStore::new(
        pool,
        branch_ns.clone(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &branch_ns).await?;

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
            let (db, rollback_control) = setup_coordinator_psy_scylla_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url).await?;
            let db = Arc::new(db);
            let recording = rollback_control.recording();
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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

    // Redis and NATS answer to the branch this node is on, not merely to the
    // deployment: a rollback leaves the discarded branch's queue messages and
    // Redis entries behind, and they are keyed by ids the new branch issues
    // again.  See `psy_node_scylla::rollback::branch_namespace`.  Read before
    // either store is built, because the name is what they are built with --
    // and the Scylla keyspaces keep their plain names, since they hold the
    // state that was repaired rather than abandoned.
    let (branch_ns, _branch_epoch) = realm_branch_namespace(
        &config.scylla_db_url,
        &config.db_namespace,
        config.network.get_chain_id() as i64,
    )
    .await?;
    let temp_store = StandardRedisStore::new(
        pool,
        branch_ns.clone(),
        config.realm_id as u64,
        config.realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &branch_ns).await?;

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

    let realm_identifier = QRealmIdentifier {
        realm_id: config.realm_id as u32,
        realm_sub_id: config.realm_sub_id,
    };
    let chain_id = config.network.get_chain_id();
    if config.coordinator_api_urls.is_empty() {
        anyhow::bail!("No coordinator API URLs provided for realm processor node");
    }
    
    let http_client: HttpClient = HttpClientBuilder::default().set_keep_alive(Some(Duration::from_secs(10))).build(&config.coordinator_api_urls[0])?;

    // A Realm cannot start without the Coordinator, so waiting for it is part of
    // starting rather than a failure to start.  The first thing startup does is
    // talk to the Coordinator Edge, and an Edge that is restarting refuses the
    // connection for a few seconds -- which used to end the process with a
    // non-75 code, so the supervisor treated a five-second outage as a crash and
    // the Realm stayed down.  That happened the moment Edges began restarting on
    // a rollback: realm-0 died at 02:06 and was still down when the chain had
    // moved thirty checkpoints on.
    //
    // Bounded, so a Coordinator that is genuinely gone still stops this node
    // rather than hiding behind a restart that never succeeds.
    {
        // Untyped, because the concrete proof and hash types are not chosen
        // until the backend match further down, and this only needs to know
        // whether anyone is listening.
        use jsonrpsee::core::client::ClientT;
        let waited_from = std::time::Instant::now();
        let limit = Duration::from_secs(120);
        loop {
            match http_client
                .request::<u64, _>("psy_get_latest_checkpoint_id", jsonrpsee::rpc_params![])
                .await
            {
                Ok(head) => {
                    tracing::info!(
                        "[REALM_STARTUP] the Coordinator Edge at {} is answering (head {head})",
                        config.coordinator_api_urls[0]
                    );
                    break;
                }
                // A refusal is not a failure to answer, it is an answer: the
                // Coordinator is mid-rollback and will not describe a branch it
                // is discarding.  That is definite and self-limiting, so it is
                // waited out rather than counted against the budget -- and it
                // has to be, since a Realm restarts *during* a rollback, right
                // after taking part in one, and rollbacks outlast two minutes.
                Err(e) if format!("{e}").contains("a rollback is running") => {
                    if waited_from.elapsed().as_secs() % 30 < 2 {
                        tracing::info!(
                            "[REALM_STARTUP] the Coordinator is rolling back and is not \
                             answering questions about the chain yet; waiting for it to finish"
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) if waited_from.elapsed() < limit => {
                    tracing::warn!(
                        "[REALM_STARTUP] the Coordinator Edge at {} is not answering yet ({e}); \
                         waiting, since it may be restarting for a rollback",
                        config.coordinator_api_urls[0]
                    );
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                Err(e) => anyhow::bail!(
                    "the Coordinator Edge at {} did not answer within {}s ({e}); this Realm \
                     cannot start without it",
                    config.coordinator_api_urls[0],
                    limit.as_secs()
                ),
            }
        }
    }

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
            // Store and control plane together: a Realm processor cannot be
            // handed a store it can write without the means to record what it
            // wrote (design-r1 §0.2 D3).
            let (db, rollback_control) = setup_realm_psy_scylla_store_from_connection_string::<N>(
                &config.db_namespace,
                &config.scylla_db_url,
                chain_id as i64,
            )
            .await?;
            let realm_recording = rollback_control.recording();
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
                guta_update_queue,

                proof_work_queue,
                realm_identifier,

                circuit_fingerprint_config,
                Arc::new(coordinator_client),
                config.network,
                realm_recording,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
                recording,
                config.network,
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
