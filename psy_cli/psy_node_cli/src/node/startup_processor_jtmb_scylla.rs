use std::sync::Arc;

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use std::time::Duration;
use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfigProvider, genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider,
};
use psy_io::tokio::{TokioLikeFileSystem, TokioStdFileSystem};
use psy_jtmb_testing_core::{
    circuit_library::core::get_jtmb_circuit_library_and_prover_for_network,
    config::poseidon_goldilocks::resolver::PsyJTMBPoseidonGoldilocksNodeConfigResolver,
    protocol_types::{JTMBPoseidonGoldilocksConfig, ZKTypesJTMBGoldilocksPoseidon},
    zk_verifier::PsyJTMBZKVerifier,
};
use psy_node_common::{coordinator::processor::create::create_coordinator_processor_and_run, p2p::realm_coordinator::PsyRealmCoordinatorClientAPI, realm::network::load_bls_secret_key, realm::processor::create::create_realm_processor, realm::processor::core::runner::run_realm_processor};
use psy_node_core::config::node_start_config::{CoordinatorProcessorStartConfig, RealmProcessorStartConfig};
use psy_node_nats::psy_queue::{setup_nats_psy_queue_from_connection_str, NatsSetupMode};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string;

pub async fn run_startup_jtmb_poseidon_goldilocks_scylla_coordinator_processor_node(config: &CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyJTMBPoseidonGoldilocksNodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network, config.genesis_data_path.clone())?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace, NatsSetupMode::CreateIfMissing).await?;

    let file_system = TokioStdFileSystem {};

    let file_system = Arc::new(file_system);
    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);

    let deploy_contract_gatherer_backup_directory = config.get_deploy_contracts_backup_path();
    let update_contract_gatherer_backup_directory = config.get_update_contracts_backup_path();
    let register_user_gatherer_backup_directory = config.get_register_users_backup_path();
    let guta_gatherer_backup_directory = config.get_guta_updates_backup_path();
    let checkpoint_tree_root_backup_file_path = config.get_checkpoint_tree_backup_file_path();
    file_system
        .file_like_fs_create_dir_all(&deploy_contract_gatherer_backup_directory)
        .await?;
    file_system.file_like_fs_create_dir_all(&update_contract_gatherer_backup_directory).await?;
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
    let chain_id = config.network.get_chain_id();

    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            tracing::info!("[COORD_BOOT] scylla store ready");
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            tracing::info!("[COORD_BOOT] creating coordinator processor");
            create_coordinator_processor_and_run::<N, _, _, _, _, _, _, _, _, _>(
                chain_id,
                &genesis_data,
                circuit_fingerprint_config,
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
            )
            .await?;
            tracing::info!("[COORD_BOOT] coordinator processor exited");
        }
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for JTMB Poseidon Goldilocks Scylla coordinator processor node", config.network );
        }
    }


    Ok(())
}

pub async fn run_startup_jtmb_poseidon_goldilocks_scylla_realm_processor_node(config: &RealmProcessorStartConfig) -> anyhow::Result<()> {
    let (verifier, _) = get_jtmb_circuit_library_and_prover_for_network::<JTMBPoseidonGoldilocksConfig>(config.network)?;
    let resolver = PsyJTMBPoseidonGoldilocksNodeConfigResolver {};
    let circuit_fingerprint_config = resolver.get_circuit_fingerprint_config_for_network(config.network)?;
    let genesis_data = resolver.get_genesis_block_setup_data_for_network(config.network, config.genesis_data_path.clone())?;
    let (realm_sub_id, validator_user_id, bls_public_keys) =
        crate::node::realm_p2p::processor_validator_data(config, &genesis_data)?;
    let config = &config.clone().with_derived_realm_sub_id(realm_sub_id);
    let rotation = psy_data::config::network_config::load_realm_rotation_config(config.network)?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.realm_id as u64,
        realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace, NatsSetupMode::CreateIfMissing).await?;

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
        realm_sub_id,
    };
    let chain_id = config.network.get_chain_id();
    if config.coordinator_api_urls.is_empty() {
        anyhow::bail!("No coordinator API URLs provided for realm processor node");
    }
    
    let http_client: HttpClient = HttpClientBuilder::default().set_keep_alive(Some(Duration::from_secs(10))).build(&config.coordinator_api_urls[0])?;

    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesJTMBGoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, true).await?;
            tracing::info!("[REALM_BOOT] scylla store ready");
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            let coordinator_client = PsyRealmCoordinatorClientAPI::<N, _>::new(
                http_client,
            );
            tracing::info!("[REALM_BOOT] creating realm processor");
            let (mut processor, guta_gatherer_join_handle) = create_realm_processor::<N, _, _, _, _, _, _, _, _>(
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
                rotation.checkpoints_per_epoch,
            )
            .await?;
            let built = crate::node::realm_p2p::maybe_build_processor_network(config, chain_id)?;
            let bls_secret = load_bls_secret_key(config.p2p_bls_key_path.as_deref().ok_or_else(|| {
                anyhow::anyhow!("processor P2P requires --p2p-bls-key")
            })?)?;
            let commands = built.handle.commands();
            let rotation = built.rotation.clone();
            processor.set_realm_p2p(commands, rotation, bls_secret, validator_user_id, bls_public_keys);
                let (state_updates_tx, state_updates_rx) = tokio::sync::mpsc::channel(4);
                processor.verified_state_updates = Some(state_updates_rx);
                crate::node::realm_p2p::spawn_processor_realm_network::<N>(
                    built,
                    config,
                    realm_sub_id,
                    PsyJTMBZKVerifier::new(verifier),
                    state_updates_tx,
                );





            run_realm_processor(processor, guta_gatherer_join_handle).await?;
            tracing::info!("[REALM_BOOT] realm processor exited");
        }
        _ => {
            anyhow::bail!("Unsupported network type '{:?}' for JTMB Poseidon Goldilocks Scylla coordinator processor node", config.network );
        }
    }


    Ok(())
}
