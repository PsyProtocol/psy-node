use jsonrpsee::{RpcModule, server::ServerBuilder};
use parth_core::protocol::core_types::QNetworkTypesConfig;
use psy_api_core::{coordinator::standard_edge_rpc::CoordinatorEdgeRpcServer, worker::standard_worker_rpc::NodeEdgeWorkerRpcServer};
use psy_core::job::job_id::QProvingJobDataID;
use psy_node_core::{psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter}, psy_temp_db::StandardEdgeAPITempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber}, store::traits::proof_store::QParthProofStore};
use tower_http::cors::{Any, CorsLayer};

use crate::coordinator::edge::handler::CoordinatorEdgeHandler;

pub async fn start_coordinator_edge_rpc_server<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        RegisterUserQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        DeployContractQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + std::marker::Sync + std::marker::Send + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
>(
    handler: CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >,
    listen: &str, // ip
    port: u16, // port
) -> anyhow::Result<()> {


    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let server = ServerBuilder::default()
        .set_http_middleware(tower::ServiceBuilder::new().layer(cors))
        .build(format!("{}:{}", listen, port))
        .await?;

    let addr = server.local_addr()?;
    let mut rpc_module = RpcModule::new(handler.clone());
    rpc_module.merge(NodeEdgeWorkerRpcServer::into_rpc(handler.clone()))?;
    rpc_module.merge(CoordinatorEdgeRpcServer::into_rpc(handler.clone()))?;
    let handle = server.start(rpc_module);

    tracing::info!("Coordinator Edge RPC Server started on {}", addr);

    handle.stopped().await;

    tracing::info!("Coordinator Edge RPC Server stopped");
    Ok(())
}