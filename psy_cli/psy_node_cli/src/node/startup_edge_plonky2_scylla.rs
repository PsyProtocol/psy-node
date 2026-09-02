use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::
    config::network_config::PsyNodeCircuitFingerprintConfigProvider
;
use psy_node_common::{coordinator::edge::{handler::CoordinatorEdgeHandler, server::start_coordinator_edge_rpc_server}, realm::edge::{handler::RealmEdgeHandler, server::start_realm_edge_rpc_server}, worker_whitelist::WhiteListCache};
use psy_node_core::config::node_start_config::{CoordinatorEdgeStartConfig, RealmEdgeStartConfig};
use psy_node_nats::psy_queue::{setup_nats_psy_queue_from_connection_str, NatsSetupMode};
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::setup_psy_scylla_database_store_from_connection_string;
use psy_plonky2_circuits::{
    node::config::networks::resolver::PsyPlonky2NodeConfigResolver,
    protocol_types::ZKTypesPlonky2GoldilocksPoseidon, zk_verifier::PsyPlonky2ZKVerifier,
};

type C = PoseidonGoldilocksConfig;

const D: usize = 2;

pub async fn run_startup_plonky2_scylla_edge_node(config: &CoordinatorEdgeStartConfig) -> anyhow::Result<()> {

    let fingerprint_config = PsyPlonky2NodeConfigResolver::new().get_circuit_fingerprint_config_for_network(config.network)?;
    let checkpoint_state_transition_circuit_fingerprint =fingerprint_config.checkpoint_state_transition_circuit_fingerprint;
    let worker_whitelist = WhiteListCache::new(&config.worker_whitelist_config, config.network)?;

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace, NatsSetupMode::CreateIfMissing).await?;

    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);
    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let register_user_queue = nats_queue.clone();
    let deploy_contract_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_identifier = QRealmIdentifier {
        realm_id: config.coordinator_id as u32,
        realm_sub_id: config.coordinator_sub_id,
    };
    // Edge only verifies proofs. Load the generated verifier/common-data cache
    // instead of rebuilding every coordinator and state-layout circuit at
    // startup (the latter includes all layout aggregation levels).
    let proof_verifier = Arc::new(PsyPlonky2ZKVerifier::<C, D>::from_cached());
/*

    pub fn new(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        proof_verifier: Arc<N::ZKVerifier>,
    ) -> Self {
      */
    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, false).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            let mut handler = CoordinatorEdgeHandler::<N, _, _, _, _, _, _, _, _>::new(
                db,
                tag_tree_rewards_store,
                temp_db,
                proof_store,
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
                worker_whitelist,
                config.network.get_chain_id(),
                proof_verifier,
                checkpoint_state_transition_circuit_fingerprint,
            );
            if let Some((validators_path, checkpoints_per_epoch)) = config.p2p_validator_config()? {
                handler.set_validators(
                    crate::node::realm_p2p::validator_registry_from_validators_path(validators_path)?,
                    checkpoints_per_epoch,
                )?;
            }
            start_coordinator_edge_rpc_server::<N, _, _, _, _, _, _, _, _>(
                handler,
                &config.listen,
                config.port,
            ).await?;
        }
        _ => {
            anyhow::bail!("Unsupported network type for plonky2 scylla edge node");
        }
    }


    Ok(())
}



pub async fn run_startup_plonky2_scylla_realm_edge_node(config: &RealmEdgeStartConfig) -> anyhow::Result<()> {


    let worker_whitelist = WhiteListCache::new(&config.worker_whitelist_config, config.network)?;
    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.realm_id,
        config.realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace, NatsSetupMode::CreateIfMissing).await?;

    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);
    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_identifier = QRealmIdentifier {
        realm_id: config.realm_id as u32,
        realm_sub_id: config.realm_sub_id,
    };
    // Edge only verifies proofs. Load the generated verifier/common-data cache
    // instead of rebuilding every coordinator and state-layout circuit at
    // startup (the latter includes all layout aggregation levels).
    let proof_verifier = Arc::new(PsyPlonky2ZKVerifier::<C, D>::from_cached());
    let chain_id = config.network.get_chain_id();
/*

    pub fn new(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        guta_update_queue: Arc<GUTAUpdateQueue>,
        register_user_queue: Arc<RegisterUserQueue>,
        deploy_contract_queue: Arc<DeployContractQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        proof_verifier: Arc<N::ZKVerifier>,
    ) -> Self {
      */
    match config.network {
        psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet => {
            type N = QNetworkTypesConfigHelper<QProvingJobDataID, ZKTypesPlonky2GoldilocksPoseidon, PsyNetworkLocalDevnetConstants>;
            let db = setup_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, false).await?;
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            
            let mut handler = RealmEdgeHandler::<N, _, _, _, _, _, _>::new(
                db,
                tag_tree_rewards_store,
                temp_db,
                proof_store,
                guta_update_queue,
                proof_work_queue,
                realm_identifier,
                worker_whitelist,
                chain_id,
                0,
                proof_verifier,
            );
            if let Some((built, proposer_node_ids, rotation)) =
                crate::node::realm_p2p::maybe_build_edge_network(config, chain_id)?
            {
                handler.set_realm_p2p(built.handle.commands(), rotation, proposer_node_ids);
                crate::node::realm_p2p::spawn_edge_realm_network(built, handler.clone());
            }
            start_realm_edge_rpc_server::<N, _, _, _, _, _, _>(
                handler,
                &config.listen,
                config.port,
            ).await?;
        }
        _ => {
            anyhow::bail!("Unsupported network type for plonky2 scylla edge node");
        }
    }


    Ok(())
}
