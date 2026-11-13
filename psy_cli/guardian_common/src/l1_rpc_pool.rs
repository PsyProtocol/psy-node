use std::{collections::HashMap, sync::{Arc, LazyLock, Mutex, PoisonError}, time::Duration};

use psy_rpc_pool::{CallOutcome, PoolConfig, PoolError, ProviderPool, ProviderSpec, RetryPolicy};
use reqwest::StatusCode;
use serde_json::{json, Value};

use crate::protocol::{validate_rpc_providers, ChainEndpoint, GuardianRpcProvider, GuardianSignError};

type PoolKey = (u8, Vec<GuardianRpcProvider>);

/// One pool per chain and provider list for the process lifetime, so provider health outlives a verification.
/// Entries are never removed; provider lists come only from the startup deployment documents.
static L1_RPC_POOLS: LazyLock<Mutex<HashMap<PoolKey, Arc<ProviderPool<L1RpcRoute>>>>> = LazyLock::new(Default::default);

#[derive(Clone)]
struct L1RpcRoute { client: reqwest::Client, url: Arc<str> }

/// Attempt failures before a JSON body exists. Only `Transport`, 5xx and 429 move to the next provider.
#[derive(Debug)]
enum L1RpcAttemptError { Transport, HttpStatus(StatusCode), UndecodableBody }

/// Shared handle to the provider pool of one chain.
pub(crate) struct L1RpcPool(Arc<ProviderPool<L1RpcRoute>>);

impl L1RpcPool {
    pub(crate) fn for_chain(endpoint: &ChainEndpoint) -> Result<Self, GuardianSignError> {
        validate_rpc_providers(&endpoint.rpc_providers)?;
        let key = (endpoint.chain_index, endpoint.rpc_providers.clone());
        let mut pools = L1_RPC_POOLS.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(pool) = pools.get(&key) { return Ok(Self(pool.clone())); }
        let pool = Arc::new(build_pool(endpoint.chain_index, &endpoint.rpc_providers, custody_pool_config())?);
        pools.insert(key, pool.clone());
        Ok(Self(pool))
    }

    /// The JSON-RPC `result`. Any decoded answer, including an error object, a wrong id or a null result, is final.
    pub(crate) async fn call(&self, method: &str, params: Value) -> Result<Value, GuardianSignError> {
        let request = json!({"jsonrpc":"2.0","id":1,"method":method,"params":params});
        let response = self.0.call(RetryPolicy::SafeAcrossEndpoints, method, classify, |route| post(route, &request)).await.map_err(|error| match error {
            PoolError::Provider(L1RpcAttemptError::UndecodableBody) => GuardianSignError::L1ResponseMismatch,
            PoolError::Provider(L1RpcAttemptError::Transport | L1RpcAttemptError::HttpStatus(_)) | PoolError::Timeout | PoolError::Unavailable => GuardianSignError::L1RpcUnavailable,
        })?;
        json_rpc_result(&response).cloned().ok_or(GuardianSignError::L1ResponseMismatch)
    }
}

/// Each attempt keeps the former 30 s request limit; one read may spend two full attempts.
/// No cooldown or quarantine: a failed provider stays a fallback, and decayed health alone orders later reads.
fn custody_pool_config() -> PoolConfig {
    PoolConfig {
        attempt_timeout: Duration::from_secs(30),
        total_timeout: Duration::from_secs(60),
        failure_cooldown: Duration::ZERO,
        quarantine_after: u32::MAX,
        ..PoolConfig::default()
    }
}

fn build_pool(chain_index: u8, providers: &[GuardianRpcProvider], config: PoolConfig) -> Result<ProviderPool<L1RpcRoute>, GuardianSignError> {
    let mut specs = Vec::with_capacity(providers.len());
    for provider in providers {
        let client = reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).build().map_err(|_| GuardianSignError::L1RpcUnavailable)?;
        let spec = ProviderSpec::new(provider.name.clone(), L1RpcRoute { client, url: provider.url.as_str().into() });
        specs.push(match &provider.operator { Some(operator) => spec.with_operator(operator.clone()), None => spec });
    }
    ProviderPool::new(format!("guardian-l1-chain-{chain_index}"), specs, config).map_err(|_| GuardianSignError::AuthorizationMismatch)
}

async fn post(route: L1RpcRoute, request: &Value) -> Result<Value, L1RpcAttemptError> {
    let mut response = route.client.post(&*route.url).json(request).send().await.map_err(|_| L1RpcAttemptError::Transport)?;
    if !response.status().is_success() { return Err(L1RpcAttemptError::HttpStatus(response.status())); }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| L1RpcAttemptError::Transport)? {
        body.try_reserve(chunk.len()).map_err(|_| L1RpcAttemptError::Transport)?;
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| L1RpcAttemptError::UndecodableBody)
}

fn json_rpc_result(response: &Value) -> Option<&Value> {
    if response.get("error").is_some() || response.get("id") != Some(&json!(1)) { return None; }
    response.get("result").filter(|result| !result.is_null())
}

fn classify(attempt: &Result<Value, L1RpcAttemptError>) -> CallOutcome {
    match attempt {
        Ok(response) if json_rpc_result(response).is_some() => CallOutcome::Success,
        Ok(_) | Err(L1RpcAttemptError::UndecodableBody) => CallOutcome::Application,
        Err(L1RpcAttemptError::Transport) => CallOutcome::Transport,
        Err(L1RpcAttemptError::HttpStatus(StatusCode::TOO_MANY_REQUESTS)) => CallOutcome::RateLimited,
        Err(L1RpcAttemptError::HttpStatus(status)) if status.is_server_error() => CallOutcome::Server,
        Err(L1RpcAttemptError::HttpStatus(_)) => CallOutcome::Application,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;

    #[derive(Clone)]
    enum Reply { Http(u16, String), Hang }

    struct MockL1 { url: String, requests: Arc<AtomicUsize>, server: tokio::task::JoinHandle<()> }
    impl Drop for MockL1 {
        fn drop(&mut self) { self.server.abort(); }
    }
    impl MockL1 {
        fn requests(&self) -> usize { self.requests.load(Ordering::SeqCst) }
        fn provider(&self, name: &str) -> GuardianRpcProvider { GuardianRpcProvider { name: name.into(), url: self.url.clone(), operator: None } }
    }

    async fn serve(reply: Reply) -> MockL1 {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let counter = requests.clone();
        let server = tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let (counter, reply) = (counter.clone(), reply.clone());
                tokio::spawn(async move {
                    let mut socket = BufReader::new(socket);
                    let mut line = String::new();
                    let mut length = 0usize;
                    loop {
                        line.clear();
                        if socket.read_line(&mut line).await.unwrap() == 0 || line == "\r\n" { break; }
                        if let Some((name, value)) = line.split_once(':') {
                            if name.eq_ignore_ascii_case("content-length") { length = value.trim().parse().unwrap(); }
                        }
                    }
                    let mut body = vec![0; length];
                    socket.read_exact(&mut body).await.unwrap();
                    counter.fetch_add(1, Ordering::SeqCst);
                    let Reply::Http(status, payload) = reply else { return std::future::pending().await };
                    let response = format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}", payload.len());
                    socket.into_inner().write_all(response.as_bytes()).await.unwrap();
                });
            }
        });
        MockL1 { url, requests, server }
    }

    async fn serve_json(response: Value) -> MockL1 { serve(Reply::Http(200, response.to_string())).await }
    async fn serve_result() -> MockL1 { serve_json(json!({"jsonrpc":"2.0","id":1,"result":"0x2a"})).await }

    async fn refused_provider(name: &str) -> GuardianRpcProvider {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        GuardianRpcProvider { name: name.into(), url, operator: None }
    }

    fn pool(providers: Vec<GuardianRpcProvider>) -> L1RpcPool {
        let config = PoolConfig { attempt_timeout: Duration::from_millis(500), total_timeout: Duration::from_secs(5), ..custody_pool_config() };
        L1RpcPool(Arc::new(build_pool(0, &providers, config).unwrap()))
    }

    async fn assert_fails_over(primary: MockL1) {
        let backup = serve_result().await;
        let result = pool(vec![primary.provider("primary"), backup.provider("backup")]).call("eth_chainId", json!([])).await;
        assert_eq!(result, Ok(json!("0x2a")));
        assert_eq!((primary.requests(), backup.requests()), (1, 1));
    }

    #[tokio::test]
    async fn server_error_rate_limit_and_timeout_fail_over_to_the_next_provider() {
        assert_fails_over(serve(Reply::Http(503, String::new())).await).await;
        assert_fails_over(serve(Reply::Http(500, String::new())).await).await;
        assert_fails_over(serve(Reply::Http(429, String::new())).await).await;
        assert_fails_over(serve(Reply::Hang).await).await;
    }

    #[tokio::test]
    async fn transport_error_fails_over_to_the_next_provider() {
        let backup = serve_result().await;
        let result = pool(vec![refused_provider("primary").await, backup.provider("backup")]).call("eth_chainId", json!([])).await;
        assert_eq!(result, Ok(json!("0x2a")));
        assert_eq!(backup.requests(), 1);
    }

    async fn assert_final_without_failover(primary: MockL1, expected: GuardianSignError) {
        let backup = serve_result().await;
        let result = pool(vec![primary.provider("primary"), backup.provider("backup")]).call("eth_call", json!([])).await;
        assert_eq!(result, Err(expected));
        assert_eq!((primary.requests(), backup.requests()), (1, 0), "a decoded or client-rejected answer is never re-asked");
    }

    #[tokio::test]
    async fn decoded_answers_are_final_and_keep_their_error_code() {
        use GuardianSignError::{L1ResponseMismatch, L1RpcUnavailable};
        assert_final_without_failover(serve_json(json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"header not found"}})).await, L1ResponseMismatch).await;
        assert_final_without_failover(serve_json(json!({"jsonrpc":"2.0","id":1,"result":null})).await, L1ResponseMismatch).await;
        assert_final_without_failover(serve_json(json!({"jsonrpc":"2.0","id":2,"result":"0x1"})).await, L1ResponseMismatch).await;
        assert_final_without_failover(serve(Reply::Http(200, "not json".into())).await, L1ResponseMismatch).await;
        assert_final_without_failover(serve(Reply::Http(403, String::new())).await, L1RpcUnavailable).await;
        assert_final_without_failover(serve(Reply::Http(404, String::new())).await, L1RpcUnavailable).await;
    }

    #[tokio::test]
    async fn every_provider_failing_is_l1_rpc_unavailable() {
        let first = serve(Reply::Http(502, String::new())).await;
        let second = serve(Reply::Http(429, String::new())).await;
        let result = pool(vec![first.provider("first"), second.provider("second"), refused_provider("third").await]).call("eth_chainId", json!([])).await;
        assert_eq!(result, Err(GuardianSignError::L1RpcUnavailable));
        assert_eq!((first.requests(), second.requests()), (1, 1));
    }

    #[tokio::test]
    async fn pools_are_shared_per_chain_and_provider_list() {
        let primary = serve(Reply::Http(503, String::new())).await;
        let backup = serve_result().await;
        let endpoint = ChainEndpoint {
            chain_index: 9, chain_id: alloy_primitives::U256::from(9u8), bridge: crate::protocol::Hex([0x11; 20]), deployment_block: 0,
            rpc_providers: vec![primary.provider("primary"), backup.provider("backup")],
        };
        assert_eq!(L1RpcPool::for_chain(&endpoint).unwrap().call("eth_chainId", json!([])).await, Ok(json!("0x2a")));
        assert_eq!(L1RpcPool::for_chain(&endpoint).unwrap().call("eth_chainId", json!([])).await, Ok(json!("0x2a")));
        assert_eq!((primary.requests(), backup.requests()), (1, 2), "the penalized primary is not retried first by the next verification");
    }

    #[tokio::test]
    async fn invalid_provider_lists_are_rejected_before_any_request() {
        let provider = |name: &str, url: &str| GuardianRpcProvider { name: name.into(), url: url.into(), operator: None };
        let endpoint = |rpc_providers| ChainEndpoint { chain_index: 0, chain_id: alloy_primitives::U256::from(1u8), bridge: crate::protocol::Hex([0x11; 20]), deployment_block: 0, rpc_providers };
        for providers in [
            vec![],
            vec![provider("a", "https://a.example/rpc"), provider("a", "https://b.example/rpc")],
            vec![provider(" ", "https://a.example/rpc")],
            vec![provider("a", "https://a.example/rpc"), provider("b", "http://10.0.0.1:8545")],
        ] {
            assert!(matches!(L1RpcPool::for_chain(&endpoint(providers)), Err(GuardianSignError::AuthorizationMismatch)));
        }
    }
}
