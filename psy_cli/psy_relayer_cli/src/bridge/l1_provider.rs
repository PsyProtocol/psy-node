use std::sync::Arc;
use std::time::Duration;

use alloy_network::EthereumWallet;
use alloy_provider::{Provider, ProviderBuilder};
use alloy_rpc_client::ClientBuilder;
use alloy_rpc_client::RpcClient;
use alloy_transport::BoxTransport;
use alloy_transport_http::Http;
use anyhow::{Context, Result};
use psy_rpc_pool::{PoolConfig, ProviderPool, ProviderSnapshot, ProviderSpec};
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

/// Builds the scored pool behind `build_pool_client`, split out so tests can
/// inspect `ProviderPool::snapshot()` directly (operator/quota_group
/// resolution, the single-operator WARN) without reaching into the boxed
/// `RpcClient` transport.
fn build_pool(label: &str, providers: &[RpcProviderConfig]) -> Result<(Arc<ProviderPool<BoxTransport>>, bool)> {
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
        // operator: explicit value wins, otherwise inferred from the URL
        // host. quota_group is passed through as configured (blank when
        // unset): the pool's own default (the exact provider name) applies
        // via `.with_quota_group(..)`'s blank-keeps-default rule. See spec
        // §7.2.1.
        let operator = if provider.operator.trim().is_empty() {
            infer_operator(&provider.url)
        } else {
            provider.operator.clone()
        };
        specs.push(
            ProviderSpec::new(provider.name.clone(), BoxTransport::new(transport))
                .with_priority_weight(provider.priority_weight)
                .with_operator(operator)
                .with_quota_group(provider.quota_group.clone()),
        );
    }
    let pool = ProviderPool::new(label, specs, PoolConfig::default())
        .with_context(|| format!("invalid L1 RPC provider pool for {label}"))?;
    if let Some(operator) = shared_operator(&pool.snapshot()) {
        tracing::warn!(
            label,
            operator = %operator,
            "all L1 RPC providers share one operator; no infrastructure-level backup"
        );
    }
    Ok((Arc::new(pool), is_local))
}

pub(super) fn build_pool_client(label: &str, providers: &[RpcProviderConfig]) -> Result<RpcClient> {
    let (pool, is_local) = build_pool(label, providers)?;
    Ok(ClientBuilder::default().transport(PoolTransport::new(pool), is_local))
}

/// The operator shared by every provider in `snapshot`, or `None` when more
/// than one operator is present. A single-provider pool always returns
/// `Some`, so the caller's WARN fires for single-provider chains too (spec
/// §7.2.1).
fn shared_operator(snapshot: &[ProviderSnapshot]) -> Option<String> {
    let first = snapshot.first()?.operator.clone();
    snapshot.iter().all(|entry| entry.operator == first).then_some(first)
}

/// Infers the operator (shared infrastructure failure domain, spec §5.1)
/// from a provider URL's host when no explicit `operator` is configured.
///
/// - An unparseable URL, or one with no host, returns `"unknown"`.
/// - An IPv4 address, a bracketed IPv6 address, or a single-label host
///   (e.g. `localhost`) returns the whole host, lowercased.
/// - Otherwise returns the second-to-last dot-separated label, lowercased,
///   e.g. `eth-sepolia.g.alchemy.com` -> `alchemy`. This heuristic ignores
///   multi-part public suffixes such as `co.uk`: `foo.co.uk` -> `co`. Set
///   `operator` explicitly for such hosts.
///
/// Never panics: every branch handles its `None`/`Err` case explicitly.
pub(crate) fn infer_operator(url: &str) -> String {
    let Ok(parsed) = url.trim().parse::<Url>() else { return "unknown".to_string() };
    let Some(host) = parsed.host_str() else { return "unknown".to_string() };
    let host = host.to_ascii_lowercase();
    match parsed.host() {
        Some(url::Host::Domain(_)) => {
            let host = host.strip_suffix('.').unwrap_or(&host);
            let labels: Vec<&str> = host.split('.').filter(|label| !label.is_empty()).collect();
            match labels.len() {
                0 => "unknown".to_string(),
                1 => host.to_string(),
                n => labels[n - 2].to_string(),
            }
        }
        // IPv4 / bracketed IPv6: the whole host, as-is (host_str keeps the
        // brackets for IPv6).
        _ => host,
    }
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
    use super::super::rpc_providers::resolve_rpc_providers;
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
            operator: String::new(), quota_group: String::new(),
        }).collect()
    }

    fn provider(name: &str, url: &str, weight: i32, operator: &str, quota_group: &str) -> RpcProviderConfig {
        RpcProviderConfig {
            name: name.to_string(),
            url: url.to_string(),
            priority_weight: weight,
            operator: operator.to_string(),
            quota_group: quota_group.to_string(),
        }
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
        let bad = vec![provider("alchemy", "not a url/SECRETKEY", 10, "", "")];
        let error = format!("{:#}", build_pool_client("sepolia", &bad).unwrap_err());
        assert!(error.contains("alchemy"), "{error}");
        assert!(!error.contains("SECRETKEY"), "{error}");
    }

    #[test]
    fn duplicate_provider_names_fail_at_startup() {
        let dup = vec![
            provider("alchemy", "http://127.0.0.1:1", 10, "", ""),
            provider("alchemy", "http://127.0.0.1:2", 10, "", ""),
        ];
        let error = format!("{:#}", build_pool_client("sepolia", &dup).unwrap_err());
        assert!(error.contains("duplicate provider name alchemy"), "{error}");
    }

    // -- Operator inference (spec §5.1 / §7.2.1) -----------------------------

    #[test]
    fn infer_operator_examples() {
        let cases = [
            ("https://eth-sepolia.g.alchemy.com/v2/KEY", "alchemy"),
            ("https://sepolia.infura.io/v3/KEY", "infura"),
            ("https://bsc-testnet.nodereal.io/v1/KEY", "nodereal"),
            ("http://127.0.0.1:8545", "127.0.0.1"),
            ("http://localhost:8545", "localhost"),
            ("http://LOCALHOST:8545", "localhost"),
            ("https://ETH-SEPOLIA.G.ALCHEMY.COM/v2/KEY", "alchemy"),
            ("https://eth-sepolia.g.alchemy.com./v2/KEY", "alchemy"),
            // co.uk caveat: the heuristic ignores multi-part public
            // suffixes, so this is "co", not "foo". Set `operator`
            // explicitly for such hosts.
            ("https://foo.co.uk/", "co"),
            ("not a url/SECRETKEY", "unknown"),
            ("", "unknown"),
            ("http://", "unknown"),
        ];
        for (url, expected) in cases {
            assert_eq!(infer_operator(url), expected, "url={url}");
        }
    }

    #[test]
    fn infer_operator_handles_bracketed_ipv6_without_panicking() {
        let inferred = infer_operator("http://[::1]:8545");
        assert!(inferred.contains("::1"), "{inferred}");
    }

    #[test]
    fn infer_operator_never_panics_on_garbage() {
        for garbage in ["\0", "http://[", "http:///", "://x", "http://user:pass@", "   "] {
            let _ = infer_operator(garbage);
        }
    }

    // -- Operator and quota group resolution at pool-build time -------------

    #[test]
    fn shared_operator_detects_single_operator_pools_including_size_one() {
        let (one, _) = build_pool("t", &[provider("a", "http://127.0.0.1:1", 10, "alchemy", "")]).unwrap();
        assert_eq!(shared_operator(&one.snapshot()), Some("alchemy".to_string()));

        let (same, _) = build_pool("t", &[
            provider("a", "http://127.0.0.1:1", 10, "Alchemy", ""),
            provider("b", "http://127.0.0.1:2", 10, "alchemy", ""),
        ]).unwrap();
        assert_eq!(shared_operator(&same.snapshot()), Some("alchemy".to_string()));

        let (different, _) = build_pool("t", &[
            provider("a", "http://127.0.0.1:1", 10, "alchemy", ""),
            provider("b", "http://127.0.0.1:2", 10, "infura", ""),
        ]).unwrap();
        assert_eq!(shared_operator(&different.snapshot()), None);
    }

    #[test]
    fn explicit_operator_and_quota_group_are_trimmed_and_lowercased_in_the_pool() {
        let (pool, _) = build_pool("sepolia", &[
            provider("alchemy-jason", "http://127.0.0.1:1", 10, "  Alchemy  ", " QA-Jason "),
        ]).unwrap();
        let snapshot = pool.snapshot();
        assert_eq!(snapshot[0].operator, "alchemy");
        assert_eq!(snapshot[0].quota_group, "qa-jason");
    }

    #[test]
    fn operator_and_quota_group_defaults_are_applied_in_the_pool() {
        // operator unset -> inferred from the URL host; quota_group unset ->
        // the pool's own default, the exact (unnormalized) provider name.
        let (pool, _) = build_pool("sepolia", &[
            provider("Alchemy-Jason", "https://eth-sepolia.g.alchemy.com/v2/KEY", 10, "", ""),
        ]).unwrap();
        let snapshot = pool.snapshot();
        assert_eq!(snapshot[0].operator, "alchemy");
        assert_eq!(snapshot[0].quota_group, "Alchemy-Jason");
    }

    #[test]
    fn legacy_rpc_urls_providers_get_inferred_operators() {
        let resolved = resolve_rpc_providers(
            "sepolia", &[], &["https://sepolia.infura.io/v3/KEY".to_string()],
        ).unwrap();
        let (pool, _) = build_pool("sepolia", &resolved).unwrap();
        let snapshot = pool.snapshot();
        assert_eq!(snapshot[0].name, "sepolia-rpc-0");
        assert_eq!(snapshot[0].operator, "infura");
        assert_eq!(snapshot[0].quota_group, "sepolia-rpc-0");
    }
}
