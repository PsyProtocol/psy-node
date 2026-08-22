use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::QNetworkTypesConfigHelper};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::
    config::network_config::PsyNodeCircuitFingerprintConfigProvider
;
use psy_node_common::{coordinator::edge::{handler::CoordinatorEdgeHandler, server::start_coordinator_edge_rpc_server}, realm::edge::{handler::RealmEdgeHandler, server::start_realm_edge_rpc_server}};
use psy_node_core::config::node_start_config::{CoordinatorEdgeStartConfig, RealmEdgeStartConfig};
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_scylla::rollback::{
    coordinator_branch_namespace, realm_branch_namespace, watch_branch_and_reload,
};
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

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    // Redis and NATS answer to the branch this node is on, not merely to the
    // deployment: a rollback leaves the discarded branch's queue messages and
    // Redis entries behind, and they are keyed by ids the new branch issues
    // again.  See `psy_node_scylla::rollback::branch_namespace`.  Read before
    // either store is built, because the name is what they are built with --
    // and the Scylla keyspaces keep their plain names, since they hold the
    // state that was repaired rather than abandoned.
    let (branch_ns, branch_epoch) = coordinator_branch_namespace(
        &config.scylla_db_url,
        &config.db_namespace,
        config.network.get_chain_id() as i64,
    )
    .await?;
    // An Edge holds the stores it opened at startup and has no moment of its own
    // to notice a rollback.  Without this it keeps serving the discarded
    // branch's queue while the processor beside it has moved to a name the Edge
    // has never heard of: workers find nothing, and the chain stalls with every
    // part of it apparently healthy.
    watch_branch_and_reload(
        config.scylla_db_url.clone(),
        config.db_namespace.clone(),
        config.network.get_chain_id() as i64,
        false,
        branch_epoch,
    );
    let temp_store = StandardRedisStore::new(
        pool,
        branch_ns.clone(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &branch_ns).await?;

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
    let proof_verifier = Arc::new(PsyPlonky2ZKVerifier::<C, D>::for_network(config.network)?);
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
            let handler = CoordinatorEdgeHandler::<N, _, _, _, _, _, _, _, _>::new(
                db,
                tag_tree_rewards_store,
                temp_db,
                proof_store,
                guta_update_queue,
                register_user_queue,
                deploy_contract_queue,
                proof_work_queue,
                realm_identifier,
                proof_verifier,
                checkpoint_state_transition_circuit_fingerprint,
            );
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


    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    // Redis and NATS answer to the branch this node is on, not merely to the
    // deployment: a rollback leaves the discarded branch's queue messages and
    // Redis entries behind, and they are keyed by ids the new branch issues
    // again.  See `psy_node_scylla::rollback::branch_namespace`.  Read before
    // either store is built, because the name is what they are built with --
    // and the Scylla keyspaces keep their plain names, since they hold the
    // state that was repaired rather than abandoned.
    let (branch_ns, branch_epoch) = realm_branch_namespace(
        &config.scylla_db_url,
        &config.db_namespace,
        config.network.get_chain_id() as i64,
    )
    .await?;
    // An Edge holds the stores it opened at startup and has no moment of its own
    // to notice a rollback.  Without this it keeps serving the discarded
    // branch's queue while the processor beside it has moved to a name the Edge
    // has never heard of: workers find nothing, and the chain stalls with every
    // part of it apparently healthy.
    watch_branch_and_reload(
        config.scylla_db_url.clone(),
        config.db_namespace.clone(),
        config.network.get_chain_id() as i64,
        true,
        branch_epoch,
    );
    let temp_store = StandardRedisStore::new(
        pool,
        branch_ns.clone(),
        config.realm_id,
        config.realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &branch_ns).await?;

    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);
    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_identifier = QRealmIdentifier {
        realm_id: config.realm_id as u32,
        realm_sub_id: config.realm_sub_id,
    };
    let proof_verifier = Arc::new(PsyPlonky2ZKVerifier::<C, D>::for_network(config.network)?);
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
            
            let handler = RealmEdgeHandler::<N, _, _, _, _, _, _>::new(
                db,
                tag_tree_rewards_store,
                temp_db,
                proof_store,
                guta_update_queue,
                proof_work_queue,
                realm_identifier,
                chain_id,
                0,
                proof_verifier,
            );
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
