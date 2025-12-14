use std::sync::Arc;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfigProvider, genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider,
};
use psy_io::tokio::{TokioLikeFileSystem, TokioStdFileSystem};
use psy_jtmb_testing_core::{config::poseidon_goldilocks::resolver::PsyJTMBPoseidonGoldilocksNodeConfigResolver, protocol_types::ZKTypesJTMBGoldilocksPoseidon};
use psy_node_common::{coordinator::processor::create::create_coordinator_processor_and_run, p2p::realm_coordinator::PsyRealmCoordinatorClientAPI, realm::processor::create::create_realm_processor_and_run};
use psy_node_core::config::node_start_config::{CoordinatorProcessorStartConfig, RealmProcessorStartConfig};
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string;

pub async fn run_startup_jtmb_poseidon_goldilocks_scylla_coordinator_processor_node(config: &CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyJTMBPoseidonGoldilocksNodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network)?;

    let pool = new_redis_async_pool(&config.redis_url, 10).await?;

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
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url).await?;
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
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for JTMB Poseidon Goldilocks Scylla coordinator processor node", config.network );
        }
    }


    Ok(())
}

pub async fn run_startup_jtmb_poseidon_goldilocks_scylla_realm_processor_node(config: &RealmProcessorStartConfig) -> anyhow::Result<()> {


    //let (verifier, _) = get_jtmb_circuit_library_and_prover_for_network::<JTMBPoseidonGoldilocksConfig>(config.network)?;

    

    let resolver = PsyJTMBPoseidonGoldilocksNodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network)?;

    let pool = new_redis_async_pool(&config.redis_url, 10).await?;

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

    let realm_identifier = QRealmIdentifier {
        realm_id: config.realm_id as u32,
        realm_sub_id: config.realm_sub_id,
    };
    let chain_id = config.network.get_chain_id();
    if config.coordinator_api_urls.is_empty() {
        anyhow::bail!("No coordinator API URLs provided for realm processor node");
    }
    
    let http_client: HttpClient = HttpClientBuilder::default().build(&config.coordinator_api_urls[0])?;

    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url).await?;
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

            )
            .await?;
        }
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for JTMB Poseidon Goldilocks Scylla coordinator processor node", config.network );
        }
    }


    Ok(())
}
