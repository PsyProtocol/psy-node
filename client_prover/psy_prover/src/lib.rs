#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod local;
pub mod session;
pub mod signature;
pub mod trace;
pub mod wallet;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) mod test_support;

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

#[cfg(all(test, not(target_arch = "wasm32")))]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use psy_client_common::args::{ProverArgs, PsyFaucetServerArgs};

    use super::*;

    fn write_dead_network_config(tag: &str) -> String {
        let network = serde_json::to_value(crate::test_support::dead_network_config()).unwrap();
        let config = serde_json::json!({ "networks": { "local": network }, "defaultNetwork": "local" });
        let path = std::env::temp_dir().join(format!("psy-prover-test-config-{}-{tag}.json", std::process::id()));
        std::fs::write(&path, config.to_string()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn run_server_rejects_invalid_arguments_before_serving() {
        let config_path = write_dead_network_config("server-invalid");

        let mut args = ProverArgs {
            rpc_config: config_path.clone(),
            listen_addr: "127.0.0.1:0".to_string(),
            private_key: "17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a".to_string(),
            api_key: "not-hex".to_string(),
        };
        let error = run_server(args.clone()).await.err().unwrap();
        assert!(!error.to_string().is_empty());

        args.api_key = "9f5cb6b51fd293bbc95f94013d65c566d7adeebb7e1cc77c89b9ccd73571b5c0".to_string();
        args.listen_addr = "not a socket address".to_string();
        let error = run_server(args.clone()).await.err().unwrap();
        assert!(!error.to_string().is_empty());

        // the server socket itself binds fine; the missing config file fails
        // the run just before the wallet session would initialize
        args.listen_addr = "127.0.0.1:0".to_string();
        args.rpc_config = "/nonexistent/psy-prover-test-config.json".to_string();
        let error = run_server(args).await.err().unwrap();
        assert!(!error.to_string().is_empty());
    }

    #[tokio::test]
    async fn run_server_initializes_the_offline_session_and_serves_rpc() {
        let config_path = write_dead_network_config("server-live");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let args = ProverArgs {
            rpc_config: config_path,
            listen_addr: format!("127.0.0.1:{port}"),
            private_key: "17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a".to_string(),
            api_key: "9f5cb6b51fd293bbc95f94013d65c566d7adeebb7e1cc77c89b9ccd73571b5c0".to_string(),
        };
        let task = tokio::spawn(run_server(args));

        // the socket accepts TCP connections before the RPC service is
        // installed, so keep issuing JSON-RPC requests until one is answered;
        // that only happens once the offline wallet session initialized and
        // the server handle started
        let client = reqwest::Client::new();
        let mut served = false;
        for _ in 0..240 {
            if client
                .post(format!("http://127.0.0.1:{port}"))
                .header("content-type", "application/json")
                .body(r#"{"jsonrpc":"2.0","id":1,"method":"psy_get_random_keypair","params":[]}"#)
                .timeout(std::time::Duration::from_secs(2))
                .send()
                .await
                .is_ok()
            {
                served = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
        assert!(served, "run_server should install its RPC service");
        assert!(!task.is_finished());
        task.abort();
    }

    #[tokio::test]
    async fn run_psy_faucet_server_fails_without_operator_configuration() {
        let config_path = write_dead_network_config("faucet");

        let args = PsyFaucetServerArgs {
            listen_addr: "127.0.0.1:0".to_string(),
            rpc_config: config_path,
        };
        let error = run_psy_faucet_server(args).await.err().unwrap();
        let message = error.to_string();
        assert!(
            message.contains("PSY_FAUCET_OPERATORS_JSON") || message.contains("not registered for explicit user_id"),
            "unexpected faucet server failure: {message}"
        );
    }
}
