use cf_utils::log_indicator::print_cf_log_indicator;
use jsonrpsee::{RpcModule, server::ServerBuilder};
use jsonrpsee::server::{BatchRequestConfig, ServerConfig};
use tower::limit::ConcurrencyLimitLayer;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_api_core::{realm::standard_edge_rpc::RealmEdgeRpcServer, worker::standard_worker_rpc::NodeEdgeWorkerRpcServer};
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_core::{psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader}, psy_temp_db::StandardEdgeAPITempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber}, store::traits::proof_store::QParthProofStore};
use tower_http::cors::{Any, CorsLayer};
use tower_http::compression::CompressionLayer;

use crate::realm::edge::handler::RealmEdgeHandler;

pub async fn start_realm_edge_rpc_server<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + std::marker::Sync + std::marker::Send + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
>(
    handler: RealmEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >,
    listen: &str, // ip
    port: u16, // port
) -> anyhow::Result<()> {

    let realm_id = handler.realm_id_u64;
    let realm_sub_id = handler.realm_sub_id_u64;


    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_connections(100000)
                .max_request_body_size(512 * 1024 * 1024)// 512MB
                .max_response_body_size(512 * 1024 * 1024)// 512MB
                .build()
        )
        .set_http_middleware(
            tower::ServiceBuilder::new()
                .layer(cors)
                .layer(CompressionLayer::new().gzip(true))
        )
        .build(format!("{}:{}", listen, port))
        .await?;

    let addr = server.local_addr()?;
    let mut rpc_module = RpcModule::new(handler.clone());
    rpc_module.merge(NodeEdgeWorkerRpcServer::into_rpc(handler.clone()))?;
    rpc_module.merge(RealmEdgeRpcServer::into_rpc(handler.clone()))?;
    if let Some(admission) = psy_worker_admission::rpc::AdmissionEnv::from_env(1, realm_id.try_into()?, realm_sub_id.try_into()?)? {
        let store = admission.connect().await?;
        let gate: std::sync::Arc<dyn psy_worker_admission::service::KeyGate> = std::sync::Arc::new(crate::worker_whitelist::AdmissionGate(handler.worker_whitelist.clone()));
        rpc_module.merge(admission.admission_rpc(store.clone(), Some(gate.clone()))?)?;
        if admission.tasks_v2 {
            // V2 tasks share the legacy queue. Enable only where every worker
            // speaks V2: a legacy claim of the same job is outside the lease.
            let adapter = std::sync::Arc::new(crate::realm::edge::task_adapter::RealmTaskAdapter {
                handler: handler.clone(),
                staging: std::sync::Arc::new(store.clone()),
                lease_ms: 300_000,
                staging_ttl_ms: admission.policy.receipt_retention_ms,
            });
            let flow = psy_worker_admission::flow::TaskFlow::new(
                admission.lease_service(store, Some(gate))?, adapter.clone(), adapter, psy_worker_admission::flow::FlowConfig::default(),
            );
            rpc_module.merge(psy_worker_admission::rpc::WorkerTaskRpcServer::into_rpc(psy_worker_admission::rpc::TaskRpc::new(flow.clone())))?;
            tokio::spawn(psy_worker_admission::rpc::run_maintenance(flow, std::time::Duration::from_secs(5)));
            crate::worker_whitelist::disable_legacy_worker_api();
            tracing::warn!("worker V2 task protocol enabled; legacy worker claim and submit are refused on this edge");
        }
    }
    let handle = server.start(rpc_module);
    print_cf_log_indicator("PSY_REALM_EDGE_RPC_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    tracing::info!("Realm Edge RPC Server started on {}", addr);

    handle.stopped().await;
    print_cf_log_indicator("PSY_REALM_EDGE_RPC_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    tracing::info!("Realm Edge RPC Server stopped");
    Ok(())
}
