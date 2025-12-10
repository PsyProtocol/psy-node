use cf_utils::timer::DebugTimer;
use jsonrpsee::{
    RpcModule, core::RpcResult, http_client::{HttpClient, HttpClientBuilder}, proc_macros::rpc, server::{ServerBuilder, ServerHandle}, ws_client::{WsClient, WsClientBuilder}
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};

#[rpc(server, client, namespace = "psy")]
pub trait ExampleRPCTrait1 {
    #[method(name = "get_sum")]
    async fn get_sum(&self, a: u64, b: u64) -> RpcResult<u64>;
}

#[rpc(server, client, namespace = "zpd")]
pub trait ExampleRPCTrait2 {
    #[method(name = "get_sub")]
    async fn get_sub(&self, a: u64, b: u64) -> RpcResult<u64>;
}

pub struct ExampleServer;

#[async_trait::async_trait]
impl ExampleRPCTrait1Server for ExampleServer {
    async fn get_sum(&self, a: u64, b: u64) -> RpcResult<u64> {
        Ok(a + b)
    }
}
#[async_trait::async_trait]
impl ExampleRPCTrait2Server for ExampleServer {
    async fn get_sub(&self, a: u64, b: u64) -> RpcResult<u64> {
        Ok(a - b)
    }
}

async fn run_server() -> anyhow::Result<SocketAddr> {
    let cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_origin(Any)
        .allow_headers(Any);

    let server = ServerBuilder::default()
        .set_http_middleware(tower::ServiceBuilder::new().layer(cors))
        .build("127.0.0.1:0")
        .await?;

    let addr = server.local_addr()?;
    let mut rpc_module = RpcModule::new(ExampleServer);
    rpc_module.merge(ExampleRPCTrait1Server::into_rpc(ExampleServer))?;
    rpc_module.merge(ExampleRPCTrait2Server::into_rpc(ExampleServer))?;
    let handle = server.start(rpc_module);

    tokio::spawn(handle.stopped());

    Ok(addr)
}

async fn test_client(addr: SocketAddr) -> anyhow::Result<()> {
    let a = rand::random::<u64>() & 0xffffffffu64;
    let b = rand::random::<u64>() & 0xffffffffu64;

    let expected_result = a + b;

    // Test WebSocket client
    let ws_url = format!("ws://{}", addr);
    let ws_client = WsClientBuilder::default().build(&ws_url).await?;
    let mut timer = DebugTimer::new("ws");
    for _ in 0..10000 {
        let ws_result: u64 = ws_client.get_sum(a, b).await?;
        assert_eq!(ws_result, expected_result);
    }

    timer.lap_batch("ws", "get_sum", 10000);

    println!("WebSocket client test passed.");

    let mut timer = DebugTimer::new("http");
    // Test HTTP client
    let http_url = format!("http://{}", addr);
    let http_client: HttpClient = HttpClientBuilder::default().build(&http_url)?;
    for _ in 0..10000 {
        let http_result: u64 = http_client.get_sum(a, b).await?;
        let result_2 = http_client.get_sub(expected_result, b).await?;
        assert_eq!(result_2, a);
        assert_eq!(http_result, expected_result);
    }
    timer.lap_batch("http", "get_sum", 10000);

    println!("HTTP client test passed.");


    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let server_addr = run_server().await?;
    println!("Server started on {}", server_addr);

    // Give the server a moment to start
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    test_client(server_addr).await?;

    Ok(())
}
