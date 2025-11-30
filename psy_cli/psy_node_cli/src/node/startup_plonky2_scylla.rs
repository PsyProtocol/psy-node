use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::{
    config::network_config::PsyNodeCircuitFingerprintConfigProvider, gatherer_builders::deploy_contract,
    genesis::genesis_block_setup::PsyGenesisBlockSetupDataProvider,
};
use psy_io::tokio::{TokioLikeFileSystem, TokioStdFileSystem};
use psy_node_common::coordinator::processor::create::create_coordinator_processor_and_run;
use psy_node_core::config::node_start_config::CoordinatorProcessorStartConfig;
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string;
use psy_plonky2_circuits::{
    circuit_library::get_plonky2_circuit_library_and_prover_for_network, node::config::networks::resolver::PsyPlonky2NodeConfigResolver,
    protocol_types::ZKTypesPlonky2GoldilocksPoseidon,
};

type F = parth_core::PF;
type Hash = parth_core::pgoldilocks::QHashOut<F>;
type C = PoseidonGoldilocksConfig;

const D: usize = 2;

pub async fn run_startup_plonky2_scylla_processor_node(config: &CoordinatorProcessorStartConfig) -> anyhow::Result<()> {
    let resolver = PsyPlonky2NodeConfigResolver {};
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
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
            anyhow::bail!("Unsupported network type '{:?}' for Plonky2 Scylla coordinator processor node", config.network );
        }
        /*
        psy_core::constants::chain_id::PsyChainNetworkType::PsyTeamDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::InternalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::InternalTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::InternalPreProduction => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicCanary => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::PsyPublicTestnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        psy_core::constants::chain_id::PsyChainNetworkType::PsyMainnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
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
        }*/
    }


    Ok(())
}
