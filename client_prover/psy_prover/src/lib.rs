pub mod local;
pub mod session;
pub mod signature;
pub mod trace;
pub mod wallet;

#[cfg(all(not(target_arch = "wasm32"), feature = "gnark-wrap"))]
use psy_config::PSY_NETWORK_MAGIC;

#[cfg(not(target_arch = "wasm32"))]
use crate::local::native::faucet::PsyFaucetServerProvider;
#[cfg(all(not(target_arch = "wasm32"), feature = "gnark-wrap"))]
use crate::local::native::prove_proxy::ProveProxyServerProvider;

#[cfg(not(target_arch = "wasm32"))]
pub async fn run_server(args: psy_client_common::args::ProverArgs) -> anyhow::Result<()> {
    use std::{net::SocketAddr, sync::Arc};

    use hyper::Method;
    use jsonrpsee::server::{ServerBuilder, ServerConfig};
    use parking_lot::RwLock;
    use psy_client_common::{data::base_types::hash256::Hash256, health::HealthLayer};
    use tower_http::cors::{Any, CorsLayer};

    use crate::{
        local::{
            common::enc::SimpleZeroPadEncryptionHelper,
            native::{RpcServer, RpcServerImpl},
        },
        session::WalletSession,
    };

    let api_key = Hash256::from_hex_string(&args.api_key)?;
    let _encryption_helper = SimpleZeroPadEncryptionHelper::new(api_key);

    let cors_opts = CorsLayer::new()
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);
    let cors = tower::ServiceBuilder::new().layer(HealthLayer).layer(cors_opts);

    let server_addr: SocketAddr = args.listen_addr.parse()?;
    tracing::info!("Starting user prover server at {}", server_addr);

    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_request_body_size(512 * 1024 * 1024)
                .max_response_body_size(512 * 1024 * 1024)
                .build(),
        )
        .set_http_middleware(cors)
        .build(server_addr)
        .await?;

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?;

    // let store = Arc::new(Mutex::new(UserProverWorkerStore::new()));
    let wallet_session = Arc::new(RwLock::new(WalletSession::new(&rpc_config).await?));
    let rpc_server_impl = RpcServerImpl::new(wallet_session);
    let handle = server.start(rpc_server_impl.into_rpc());
    handle.stopped().await;
    Ok(())
}

#[cfg(all(not(target_arch = "wasm32"), feature = "gnark-wrap"))]
pub async fn run_prove_proxy_server(args: psy_client_common::args::ProveProxyArgs) -> anyhow::Result<()> {
    use std::net::SocketAddr;

    use hyper::Method;
    use jsonrpsee::server::{ServerBuilder, ServerConfig};
    use psy_client_common::health::HealthLayer;
    use tower_http::cors::{Any, CorsLayer};

    use crate::local::native::prove_proxy::ProveProxyRpcServer;

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?;
    let prove_proxy = ProveProxyServerProvider::new_with_config(rpc_config.clone(), PSY_NETWORK_MAGIC).await?;
    let cors_opts = CorsLayer::new()
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);
    let cors = tower::ServiceBuilder::new().layer(HealthLayer).layer(cors_opts);
    let server_addr: SocketAddr = args.listen_addr.parse()?;
    tracing::info!("Starting prove proxy server at {}", server_addr);
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_request_body_size(512 * 1024 * 1024)
                .max_response_body_size(512 * 1024 * 1024)
                .build(),
        )
        .set_http_middleware(cors)
        .build(server_addr)
        .await?;

    let handle = server.start(prove_proxy.into_rpc());
    println!("\n[CFLI:PSY_PROVE_PROXY_STARTED][{}]\n", server_addr);
    handle.stopped().await;
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
pub async fn run_psy_faucet_server(args: psy_client_common::args::PsyFaucetServerArgs) -> anyhow::Result<()> {
    use std::net::SocketAddr;

    use hyper::Method;
    use jsonrpsee::server::{ServerBuilder, ServerConfig};
    use psy_client_common::health::HealthLayer;
    use tower_http::cors::{Any, CorsLayer};

    use crate::local::native::faucet::PsyFaucetRpcServer;

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?;
    let faucet = PsyFaucetServerProvider::new_with_config(rpc_config.clone()).await?;
    let cors_opts = CorsLayer::new()
        .allow_methods([Method::POST, Method::OPTIONS])
        .allow_origin(Any)
        .allow_headers(Any);
    let cors = tower::ServiceBuilder::new().layer(HealthLayer).layer(cors_opts);
    let server_addr: SocketAddr = args.listen_addr.parse()?;
    tracing::info!("Starting psy faucet server at {}", server_addr);
    let server = ServerBuilder::default()
        .set_config(
            ServerConfig::builder()
                .max_request_body_size(512 * 1024 * 1024)
                .max_response_body_size(512 * 1024 * 1024)
                .build(),
        )
        .set_http_middleware(cors)
        .build(server_addr)
        .await?;

    let handle = server.start(faucet.into_rpc());
    println!("\n[CFLI:PSY_FAUCET_SERVER_STARTED][{}]\n", server_addr);
    handle.stopped().await;
    Ok(())
}
