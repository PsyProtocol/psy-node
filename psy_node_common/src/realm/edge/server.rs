use cf_utils::log_indicator::print_cf_log_indicator;
use jsonrpsee::{RpcModule, server::ServerBuilder};
use jsonrpsee::server::{BatchRequestConfig, ServerConfig};
use tower::limit::ConcurrencyLimitLayer;
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_api_core::{realm::standard_edge_rpc::RealmEdgeRpcServer, worker::standard_worker_rpc::NodeEdgeWorkerRpcServer};
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_core::{psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader}, psy_temp_db::StandardEdgeAPITempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber}, store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore}};
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
    let handle = server.start(rpc_module);
    print_cf_log_indicator("PSY_REALM_EDGE_RPC_STARTED", &format!("R{}_{}", realm_id, realm_sub_id));

    tracing::info!("Realm Edge RPC Server started on {}", addr);

    handle.stopped().await;
    print_cf_log_indicator("PSY_REALM_EDGE_RPC_STOPPED", &format!("R{}_{}", realm_id, realm_sub_id));

    tracing::info!("Realm Edge RPC Server stopped");
    Ok(())
}
