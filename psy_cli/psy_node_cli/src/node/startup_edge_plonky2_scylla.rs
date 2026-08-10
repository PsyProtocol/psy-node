use std::sync::Arc;

use parth_core::{node::realm_identifier::QRealmIdentifier, protocol::core_types::{QNetworkHashTypes, QNetworkTypesConfigHelper}};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_core::{job::job_id::QProvingJobDataID, network_config::PsyNetworkLocalDevnetConstants};
use psy_data::
    config::network_config::PsyNodeCircuitFingerprintConfigProvider
;
use psy_node_common::{coordinator::edge::{handler::CoordinatorEdgeHandler, server::start_coordinator_edge_rpc_server}, realm::edge::{durable_user_update_artifact::DeterministicRealmUserUpdateArtifactFactory, handler::RealmEdgeHandler, server::start_realm_edge_rpc_server}};
use psy_node_core::{
    config::node_start_config::{CoordinatorEdgeStartConfig, RealmEdgeStartConfig},
    queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierRegistry,
    store::rollback_admin::{CoordinatorRollbackAdminInbox, RollbackAdminInboxAccess},
};
use psy_node_nats::psy_queue::setup_nats_psy_queue_from_connection_str;
use psy_node_redis::store::{new_redis_async_pool, StandardRedisStore};
use psy_node_scylla::psy_setup::{
    setup_realm_edge_scylla_startup_composition,
    setup_coordinator_psy_scylla_database_store_from_connection_string,
};
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

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.coordinator_id,
        config.coordinator_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace).await?;

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
            let db = setup_coordinator_psy_scylla_database_store_from_connection_string::<N>(&config.db_namespace, &config.scylla_db_url, false).await?;
            let canonical_head_reader = db.store.clone();
            let rollback_admin_inbox = Arc::new(CoordinatorRollbackAdminInbox::new(
                config.network.into(),
                if config.rollback_admin_rpc_enabled {
                    RollbackAdminInboxAccess::ManualPreflight
                } else {
                    RollbackAdminInboxAccess::Disabled
                },
                canonical_head_reader.clone(),
                db.store.clone(),
            ));
            let db = Arc::new(db);
            let tag_tree_rewards_store = db.clone();
            let handler = CoordinatorEdgeHandler::<N, _, _, _, _, _, _, _, _>::new(
                db,
                canonical_head_reader,
                rollback_admin_inbox,
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
                config.network.into(),
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
    let realm_id = u32::try_from(config.realm_id)
        .map_err(|_| anyhow::anyhow!("Realm Edge realm_id exceeds u32"))?;
    let branch_exact_lineage = config
        .branch_exact_startup
        .as_ref()
        .map(|startup| {
            startup.try_lineage(config.network, config.realm_id, config.realm_sub_id)
        })
        .transpose()?;
    let branch_exact_enabled = branch_exact_lineage.is_some();

    let pool = new_redis_async_pool(&config.redis_url, 2).await?;

    let temp_store = StandardRedisStore::new(
        pool,
        config.db_namespace.to_string(),
        config.realm_id,
        config.realm_sub_id as u64,
    );
    let nats_queue = setup_nats_psy_queue_from_connection_str(&config.nats_jetstream_url, &config.db_namespace).await?;

    let nats_queue = Arc::new(nats_queue);
    let temp_db = Arc::new(temp_store);
    let proof_store = temp_db.clone();
    let guta_update_queue = nats_queue.clone();
    let proof_work_queue = nats_queue.clone();

    let realm_identifier = QRealmIdentifier {
        realm_id,
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
            let composition = setup_realm_edge_scylla_startup_composition::<N>(
                &config.db_namespace,
                &config.scylla_db_url,
                false,
                realm_id,
                config.realm_sub_id,
                branch_exact_lineage,
            )
            .await?;
            let (db, durable_user_update_ingress) = if branch_exact_enabled {
                let profile = proof_verifier
                    .realm_user_update_verifier_profile(config.network)?;
                let verifier_profiles = Arc::new(
                    RealmUserUpdateVerifierRegistry::try_new([(
                        profile,
                        Arc::clone(&proof_verifier),
                    )])?,
                );
                let artifact_factory = Arc::new(
                    DeterministicRealmUserUpdateArtifactFactory::<
                        <N as QNetworkHashTypes>::F,
                        <N as QNetworkHashTypes>::QHash,
                        <N as QNetworkHashTypes>::HasherBase,
                    >::new(),
                );
                let (db, ingress) = composition
                    .into_branch_exact_ingress(
                        verifier_profiles,
                        artifact_factory,
                        Arc::clone(&nats_queue),
                    )
                    .await?;
                (db, Some(ingress))
            } else {
                (composition.into_legacy_db()?, None)
            };
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
            let handler = match durable_user_update_ingress {
                Some(installation) => {
                    handler.install_durable_user_update_ingress(installation)?
                }
                None => handler,
            };
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
