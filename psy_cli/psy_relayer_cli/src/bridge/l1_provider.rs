use std::sync::Arc;
use std::time::Duration;

use alloy_network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_rpc_client::RpcClient;
use alloy_transport::BoxTransport;
use alloy_transport_http::Http;
use anyhow::{Context, Result};
use psy_rpc_pool::{PoolConfig, ProviderPool, ProviderSpec};
use url::Url;

use super::pool_transport::PoolTransport;
use super::rpc_providers::RpcProviderConfig;

tokio::task_local! {
    // Scope provider construction to a chain without a global URL/state registry.
    // Providers constructed here carry the shared transport into background tasks.
    static L1_RPC_CONTEXT: (Url, RpcClient);
}

pub(super) async fn with_l1_rpc_client<T>(
    primary: Url,
    client: RpcClient,
    operation: impl std::future::Future<Output = T>,
) -> T {
    L1_RPC_CONTEXT.scope((primary, client), operation).await
}

pub(super) fn build_pool_client(label: &str, providers: &[RpcProviderConfig]) -> Result<RpcClient> {
    let http = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(POOL_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build L1 pool HTTP client")?;
    let mut is_local = true;
    let mut specs = Vec::with_capacity(providers.len());
    for provider in providers {
        // Never echo the URL: provider URLs can embed API keys.
        let url: Url = provider.url.trim().parse().map_err(|_| {
            anyhow::anyhow!("invalid L1 RPC URL for provider {} on {label}", provider.name)
        })?;
        let transport = Http::with_client(http.clone(), url);
        is_local &= transport.guess_local();
        specs.push(
            ProviderSpec::new(provider.name.clone(), BoxTransport::new(transport))
                .with_priority_weight(provider.priority_weight),
        );
    }
    let pool = ProviderPool::new(label, specs, PoolConfig::default())
        .with_context(|| format!("invalid L1 RPC provider pool for {label}"))?;
    Ok(ClientBuilder::default().transport(PoolTransport::new(Arc::new(pool)), is_local))
}

/// Above the pool's 15s attempt timeout, so the pool classifies hangs as Timeout.
const POOL_HTTP_TIMEOUT_SECS: u64 = 20;

const L1_HTTP_TIMEOUT_SECS: u64 = 15;

fn build_rpc_client(rpc_url: Url) -> Result<alloy_rpc_client::RpcClient> {
    if let Ok((primary, client)) = L1_RPC_CONTEXT.try_with(Clone::clone) {
        anyhow::ensure!(rpc_url == primary, "L1 provider URL does not match scoped chain");
        return Ok(client);
    }
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(L1_HTTP_TIMEOUT_SECS))
        .build()
        .context("failed to build reqwest client for L1 RPC")?;
    // Endpoint selection owns retries, and provider errors retain their typed payload.
    Ok(ClientBuilder::default().http_with_client(client, rpc_url))
}

pub fn connect_l1_readonly(rpc_url: Url) -> Result<impl Provider> {
    let client = build_rpc_client(rpc_url)?;
    Ok(ProviderBuilder::new().connect_client(client))
}

pub fn connect_l1_with_wallet(rpc_url: Url, wallet: EthereumWallet) -> Result<impl Provider> {
    let client = build_rpc_client(rpc_url)?;
    Ok(ProviderBuilder::new().wallet(wallet).connect_client(client))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct Endpoint {
        url: Url,
        calls: Arc<AtomicUsize>,
        task: tokio::task::JoinHandle<()>,
    }

    impl Drop for Endpoint {
        fn drop(&mut self) { self.task.abort(); }
    }

    fn providers(urls: &[&Url]) -> Vec<RpcProviderConfig> {
        urls.iter().enumerate().map(|(i, url)| RpcProviderConfig {
            name: format!("p{i}"), url: url.to_string(), priority_weight: 10,
        }).collect()
    }

    async fn endpoint(status: u16, error: Option<serde_json::Value>) -> Endpoint {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let task = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let (header_end, length) = loop {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                    if let Some(end) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&data[..end]).unwrap();
                        let len = headers.lines().filter_map(|line| line.split_once(':'))
                            .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                            .unwrap().1.trim().parse::<usize>().unwrap();
                        break (end + 4, len);
                    }
                };
                while data.len() < header_end + length {
                    let mut buf = [0; 4096];
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                }
                count.fetch_add(1, Ordering::SeqCst);
                let request: serde_json::Value = serde_json::from_slice(&data[header_end..]).unwrap();
                let body = match &error {
                    Some(error) => serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "error":error}),
                    None => serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":"0x2a"}),
                }.to_string();
                let response = format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        Endpoint { url, calls, task }
    }

    #[tokio::test]
    async fn http_failover_survives_scope_exit_and_preserves_local_polling() {
        let primary = endpoint(503, None).await;
        let backup = endpoint(200, None).await;
        let client = build_pool_client("test", &providers(&[&primary.url, &backup.url])).unwrap();
        assert!(client.is_local());
        assert_eq!(client.poll_interval(), Duration::from_millis(250));
        let provider = with_l1_rpc_client(primary.url.clone(), client, async {
            assert!(connect_l1_readonly(backup.url.clone()).is_err());
            connect_l1_readonly(primary.url.clone()).unwrap()
        }).await;
        let provider = tokio::spawn(async move {
            assert_eq!(provider.get_block_number().await.unwrap(), 42);
            assert_eq!(provider.get_block_number().await.unwrap(), 42);
            provider
        }).await.unwrap();
        drop(provider);
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(backup.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn http_200_quota_fails_over_but_revert_remains_typed() {
        let primary = endpoint(200, Some(serde_json::json!({"code":429, "message":"quota exceeded"}))).await;
        let backup = endpoint(200, Some(serde_json::json!({"code":3, "message":"execution reverted", "data":"0x1234"}))).await;
        let rpc = build_pool_client("test", &providers(&[&primary.url, &backup.url])).unwrap();
        let result = rpc.request::<_, serde_json::Value>("eth_call", serde_json::json!([])).await;
        let alloy_transport::TransportError::ErrorResp(error) = result.unwrap_err() else {
            panic!("must preserve JSON-RPC error type");
        };
        assert_eq!(error.code, 3);
        assert_eq!(error.data.unwrap().get(), "\"0x1234\"");
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(backup.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_http_backup_is_not_hidden_by_another_retry_layer() {
        let primary = endpoint(503, None).await;
        let backup = endpoint(503, None).await;
        let rpc = build_pool_client("test", &providers(&[&primary.url, &backup.url])).unwrap();
        let error = rpc.request::<_, serde_json::Value>("eth_blockNumber", ()).await.unwrap_err();
        assert!(matches!(error, alloy_transport::TransportError::Transport(
            alloy_transport::TransportErrorKind::HttpError(_)
        )));
        assert_eq!(primary.calls.load(Ordering::SeqCst), 1);
        assert_eq!(backup.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn invalid_url_error_names_provider_but_not_url() {
        let bad = vec![RpcProviderConfig {
            name: "alchemy".into(), url: "not a url/SECRETKEY".into(), priority_weight: 10,
        }];
        let error = format!("{:#}", build_pool_client("sepolia", &bad).unwrap_err());
        assert!(error.contains("alchemy"), "{error}");
        assert!(!error.contains("SECRETKEY"), "{error}");
    }

    #[test]
    fn duplicate_provider_names_fail_at_startup() {
        let dup = vec![
            RpcProviderConfig { name: "alchemy".into(), url: "http://127.0.0.1:1".into(), priority_weight: 10 },
            RpcProviderConfig { name: "alchemy".into(), url: "http://127.0.0.1:2".into(), priority_weight: 10 },
        ];
        let error = format!("{:#}", build_pool_client("sepolia", &dup).unwrap_err());
        assert!(error.contains("duplicate provider name alchemy"), "{error}");
    }
}
