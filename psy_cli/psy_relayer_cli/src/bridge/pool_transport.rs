use std::{sync::Arc, task::{Context, Poll}};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{BoxTransport, TransportError, TransportErrorKind, TransportFut};
use psy_rpc_pool::{CallOutcome, PoolError, ProviderPool, RetryPolicy};
use serde::de::Error as _;
use tower::Service;

/// alloy transport over a scored provider pool. Shared by all providers for
/// one chain, including receipt polling and signing fillers.
#[derive(Clone)]
pub(super) struct PoolTransport {
    pool: Arc<ProviderPool<BoxTransport>>,
}

impl PoolTransport {
    pub(super) fn new(pool: Arc<ProviderPool<BoxTransport>>) -> Self {
        Self { pool }
    }

    async fn request(self, request: RequestPacket) -> Result<ResponsePacket, TransportError> {
        let method = request.method_names().next().unwrap_or("empty").to_owned();
        let policy = if replay_safe(&request) {
            RetryPolicy::SafeAcrossEndpoints
        } else {
            RetryPolicy::NoRetry
        };
        self.pool
            .call(policy, &method, classify, |mut transport| {
                let request = request.clone();
                async move { send(&mut transport, request).await }
            })
            .await
            .map_err(|error| match error {
                PoolError::Provider(error) => error,
                PoolError::Timeout => TransportErrorKind::custom_str("L1 RPC attempt timed out"),
            })
    }
}

impl Service<RequestPacket> for PoolTransport {
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        Box::pin(self.clone().request(request))
    }
}

async fn send(transport: &mut BoxTransport, request: RequestPacket) -> Result<ResponsePacket, TransportError> {
    std::future::poll_fn(|cx| transport.poll_ready(cx)).await?;
    let response = transport.call(request.clone()).await?;
    if response.responses().len() != request.len()
        || request.requests().iter().any(|req| {
            response.response_ids().filter(|id| *id == req.id()).count() != 1
        })
    {
        return Err(TransportError::deser_err(
            serde_json::Error::custom("L1 RPC response IDs do not match request"),
            "",
        ));
    }
    // HTTP 200 can still carry provider-side rate limits or quota errors.
    for error in response.iter_errors() {
        let error = TransportError::ErrorResp(error.clone());
        if is_endpoint_failure(&error) {
            return Err(error);
        }
    }
    Ok(response)
}

/// `send` already turns in-body provider faults into errors, so any response
/// that reaches `Ok` came from a working provider.
fn classify(result: &Result<ResponsePacket, TransportError>) -> CallOutcome {
    match result {
        Ok(_) => CallOutcome::Success,
        Err(error) => outcome_of(error),
    }
}

fn outcome_of(error: &TransportError) -> CallOutcome {
    if !is_endpoint_failure(error) {
        return CallOutcome::Application;
    }
    match error {
        TransportError::Transport(TransportErrorKind::HttpError(http)) if http.status == 429 => {
            CallOutcome::RateLimited
        }
        TransportError::Transport(TransportErrorKind::HttpError(_)) => CallOutcome::Server,
        TransportError::Transport(_) => CallOutcome::Transport,
        TransportError::NullResp | TransportError::DeserError { .. } => CallOutcome::InvalidResponse,
        TransportError::ErrorResp(payload) => {
            let message = payload.message.to_ascii_lowercase();
            if payload.is_retry_err()
                || message.contains("rate limit")
                || message.contains("quota")
                || message.contains("free tier")
            {
                CallOutcome::RateLimited
            } else {
                CallOutcome::Server
            }
        }
        _ => CallOutcome::Server,
    }
}

fn is_endpoint_failure(error: &TransportError) -> bool {
    match error {
        TransportError::Transport(_)
        | TransportError::NullResp
        | TransportError::DeserError { .. }
        | TransportError::UnsupportedFeature(_) => true,
        TransportError::ErrorResp(payload) => {
            let message = payload.message.to_ascii_lowercase();
            if payload.code == 3 || message.contains("revert") {
                return false;
            }
            payload.is_retry_err()
                || matches!(payload.code, -32601 | -32603)
                || message.contains("quota")
                || message.contains("free tier")
                || message.contains("not enabled")
                || message.contains("block range")
        }
        _ => false,
    }
}

fn replay_safe(request: &RequestPacket) -> bool {
    request.method_names().all(|method| matches!(method,
        "eth_chainId" | "net_version" | "eth_blockNumber" | "eth_call"
        | "eth_estimateGas" | "eth_gasPrice" | "eth_maxPriorityFeePerGas" | "eth_feeHistory"
        | "eth_getBlockByNumber" | "eth_getBlockByHash" | "eth_getTransactionReceipt"
        | "eth_getTransactionByHash" | "eth_getTransactionCount" | "eth_getBalance"
        | "eth_getCode" | "eth_getStorageAt" | "eth_getLogs" | "eth_getProof"
        // Re-send the identical signed bytes. Never re-run a signer or nonce filler.
        | "eth_sendRawTransaction"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_json_rpc::{Id, Request};
    use psy_rpc_pool::{PoolConfig, ProviderSpec};
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::time::Instant;

    #[derive(Clone, Default)]
    struct Mock {
        calls: Arc<StdMutex<Vec<serde_json::Value>>>,
        fault: Arc<StdMutex<Option<i64>>>,
        wait: Arc<StdMutex<Option<Arc<tokio::sync::Notify>>>>,
        response: Arc<StdMutex<Option<serde_json::Value>>>,
    }

    impl Mock {
        fn fail(&self, code: i64) { *self.fault.lock().unwrap() = Some(code); }
        fn recover(&self) { *self.fault.lock().unwrap() = None; }
        fn count(&self) -> usize { self.calls.lock().unwrap().len() }
    }

    impl Service<RequestPacket> for Mock {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;
        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: RequestPacket) -> Self::Future {
            self.calls.lock().unwrap().push(serde_json::to_value(&req).unwrap());
            let fault = *self.fault.lock().unwrap();
            let wait = self.wait.lock().unwrap().clone();
            let response = self.response.lock().unwrap().clone();
            Box::pin(async move {
                if let Some(wait) = wait { wait.notified().await; }
                if let Some(response) = response {
                    return serde_json::from_value(response.clone())
                        .map_err(|err| TransportError::deser_err(err, response.to_string()));
                }
                if fault == Some(503) {
                    return Err(TransportErrorKind::http_error(503, "unavailable".into()));
                }
                let responses: Vec<_> = req.requests().iter().map(|r| {
                    if let Some(code) = fault {
                        serde_json::json!({"jsonrpc":"2.0", "id":r.id(),
                            "error":{"code":code, "message":match code {
                                3 => "execution reverted", -32602 => "invalid params", _ => "rate limit"
                            }}})
                    } else {
                        serde_json::json!({"jsonrpc":"2.0", "id":r.id(), "result":"0x1"})
                    }
                }).collect();
                let value = if req.as_single().is_some() { responses[0].clone() }
                    else { serde_json::Value::Array(responses) };
                Ok(serde_json::from_value(value).unwrap())
            })
        }
    }

    fn packet(method: &'static str) -> RequestPacket {
        Request::new(method, Id::Number(1), serde_json::json!([])).serialize().unwrap().into()
    }

    fn batch(methods: &[&'static str]) -> RequestPacket {
        RequestPacket::Batch(methods.iter().enumerate().map(|(index, method)| {
            Request::new(*method, Id::Number(index as u64 + 1), serde_json::json!([]))
                .serialize().unwrap()
        }).collect())
    }

    // `Mock` impl and `packet` / `batch` helpers: copy unchanged from the old
    // rpc_failover.rs test module (struct Mock, impl Mock, impl Service for Mock,
    // fn packet, fn batch).

    fn fixture_n(n: usize) -> (PoolTransport, Vec<Mock>) {
        let mocks: Vec<Mock> = (0..n).map(|_| Mock::default()).collect();
        let specs = mocks
            .iter()
            .enumerate()
            .map(|(i, mock)| ProviderSpec::new(format!("p{i}"), BoxTransport::new(mock.clone())))
            .collect();
        let pool = ProviderPool::new("test-chain", specs, PoolConfig::default()).unwrap();
        (PoolTransport::new(Arc::new(pool)), mocks)
    }

    fn fixture() -> (PoolTransport, Mock, Mock) {
        let (rpc, mocks) = fixture_n(2);
        (rpc, mocks[0].clone(), mocks[1].clone())
    }

    fn health(rpc: &PoolTransport, index: usize) -> f64 {
        rpc.pool.snapshot()[index].health
    }

    #[tokio::test(start_paused = true)]
    async fn primary_success_never_uses_backup() {
        let (mut rpc, p, b) = fixture();
        rpc.call(packet("eth_blockNumber")).await.unwrap();
        rpc.call(packet("eth_getTransactionReceipt")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn penalized_primary_returns_after_penalty_decays_within_tolerance() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        rpc.call(packet("eth_blockNumber")).await.unwrap();
        p.recover();
        // HTTP 503 is Server (15); it decays to 2 after about 174.4s.
        tokio::time::advance(Duration::from_secs(174)).await;
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (1, 2));
        tokio::time::advance(Duration::from_secs(1)).await;
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn all_providers_failing_returns_error_without_sleeping() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        b.fail(503);
        let start = Instant::now();
        assert!(rpc.call(packet("eth_call")).await.is_err());
        assert_eq!((p.count(), b.count()), (1, 1));
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test(start_paused = true)]
    async fn three_providers_fail_over_in_configured_order() {
        let (mut rpc, mocks) = fixture_n(3);
        mocks[0].fail(503);
        mocks[1].fail(429);
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!(mocks.iter().map(Mock::count).collect::<Vec<_>>(), vec![1, 1, 1]);
    }

    #[tokio::test(start_paused = true)]
    async fn chains_are_isolated_and_clones_share_state() {
        let (mut one, p, b) = fixture();
        let (mut two, p2, b2) = fixture();
        p.fail(503);
        one.call(packet("eth_call")).await.unwrap();
        one.clone().call(packet("eth_call")).await.unwrap();
        two.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count(), p2.count(), b2.count()), (1, 2, 1, 0));
    }

    #[tokio::test]
    async fn reverts_and_invalid_params_do_not_fail_over_or_penalize() {
        for code in [3, -32602] {
            let (mut rpc, p, b) = fixture();
            p.fail(code);
            let response = rpc.call(packet("eth_call")).await.unwrap();
            assert_eq!(response.first_error_code(), Some(code));
            assert_eq!((p.count(), b.count()), (1, 0));
            assert_eq!(health(&rpc, 0), 100.0);
        }
    }

    #[tokio::test]
    async fn signed_transaction_reuses_identical_packet_on_backup() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        let req = Request::new("eth_sendRawTransaction", Id::Number(123), ["0x1234"])
            .serialize().unwrap().into();
        rpc.call(req).await.unwrap();
        assert_eq!(*p.calls.lock().unwrap(), *b.calls.lock().unwrap());
    }

    #[tokio::test]
    async fn node_signed_transaction_is_never_replayed() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        assert!(rpc.call(packet("eth_sendTransaction")).await.is_err());
        assert_eq!((p.count(), b.count()), (1, 0));
        assert!(health(&rpc, 0) < 100.0);
    }

    #[tokio::test]
    async fn single_provider_attempts_once() {
        let (mut rpc, mocks) = fixture_n(1);
        mocks[0].fail(503);
        assert!(rpc.call(packet("eth_call")).await.is_err());
        assert_eq!(mocks[0].count(), 1);
    }

    #[tokio::test]
    async fn receipt_query_failover_does_not_resubmit_previous_transaction() {
        let (mut rpc, p, b) = fixture();
        rpc.call(packet("eth_sendRawTransaction")).await.unwrap();
        p.fail(503);
        rpc.call(packet("eth_getTransactionReceipt")).await.unwrap();
        let calls = b.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["method"], "eth_getTransactionReceipt");
    }

    #[test]
    fn errors_are_classified_by_provider_fault() {
        use CallOutcome::*;
        let resp = |code: i64, message: &str| {
            TransportError::ErrorResp(
                serde_json::from_value(serde_json::json!({"code": code, "message": message})).unwrap(),
            )
        };
        for (error, expected) in [
            (resp(-32600, "Under the Free tier plan, up to a 10 block range"), RateLimited),
            (resp(429, "rate limit"), RateLimited),
            (resp(-32000, "monthly quota exceeded"), RateLimited),
            (resp(-32603, "upstream unavailable"), Server),
            (resp(-32000, "execution reverted"), Application),
            (resp(3, "execution reverted"), Application),
            (resp(-32000, "nonce too low"), Application),
            (resp(-32000, "insufficient funds"), Application),
            (resp(-32602, "invalid params"), Application),
            (TransportErrorKind::http_error(429, "busy".into()), RateLimited),
            (TransportErrorKind::http_error(503, "down".into()), Server),
            (TransportErrorKind::custom_str("connection reset"), Transport),
            (TransportError::NullResp, InvalidResponse),
        ] {
            assert_eq!(outcome_of(&error), expected, "{error:?}");
        }
    }

    #[tokio::test]
    async fn mixed_success_and_revert_batch_is_preserved_without_failover() {
        let (mut rpc, p, b) = fixture();
        let body = serde_json::json!([
            {"jsonrpc":"2.0", "id":1, "result":"0x1"},
            {"jsonrpc":"2.0", "id":2,
                "error":{"code":3, "message":"execution reverted", "data":"0xdeadbeef"}}
        ]);
        *p.response.lock().unwrap() = Some(body.clone());
        let response = rpc.call(batch(&["eth_blockNumber", "eth_call"])).await.unwrap();
        assert_eq!(serde_json::to_value(response.as_batch().unwrap()).unwrap(), body);
        assert_eq!((p.count(), b.count()), (1, 0));
        assert_eq!(health(&rpc, 0), 100.0);
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_success_and_quota_batch_replays_identical_safe_packet_once() {
        let (mut rpc, p, b) = fixture();
        *p.response.lock().unwrap() = Some(serde_json::json!([
            {"jsonrpc":"2.0", "id":1, "result":"0x1"},
            {"jsonrpc":"2.0", "id":2, "error":{"code":429, "message":"quota exceeded"}}
        ]));
        let response = rpc.call(batch(&["eth_blockNumber", "eth_call"])).await.unwrap();
        assert!(response.is_success());
        assert_eq!((p.count(), b.count()), (1, 1));
        assert_eq!(*p.calls.lock().unwrap(), *b.calls.lock().unwrap());
        assert_eq!(health(&rpc, 0), 80.0);
    }

    #[tokio::test]
    async fn mixed_batch_with_node_signed_send_is_not_replayed_after_partial_success() {
        let (mut rpc, p, b) = fixture();
        *p.response.lock().unwrap() = Some(serde_json::json!([
            {"jsonrpc":"2.0", "id":1, "result":"0x1234"},
            {"jsonrpc":"2.0", "id":2, "error":{"code":429, "message":"quota exceeded"}}
        ]));
        let error = rpc.call(batch(&["eth_sendTransaction", "eth_call"])).await.unwrap_err();
        assert!(matches!(error, TransportError::ErrorResp(ref payload) if payload.code == 429));
        assert_eq!((p.count(), b.count()), (1, 0));
    }

    #[tokio::test]
    async fn reordered_batch_response_ids_are_accepted() {
        let (mut rpc, p, b) = fixture();
        let body = serde_json::json!([
            {"jsonrpc":"2.0", "id":2, "result":"0x2"},
            {"jsonrpc":"2.0", "id":1, "result":"0x1"}
        ]);
        *p.response.lock().unwrap() = Some(body.clone());
        let response = rpc.call(batch(&["eth_blockNumber", "eth_chainId"])).await.unwrap();
        assert_eq!(serde_json::to_value(response.as_batch().unwrap()).unwrap(), body);
        assert_eq!((p.count(), b.count()), (1, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_missing_duplicate_and_wrong_ids_are_invalid_responses() {
        let cases = [
            ("missing member", serde_json::json!([{"jsonrpc":"2.0", "id":1, "result":"0x1"}])),
            ("missing id", serde_json::json!([
                {"jsonrpc":"2.0", "result":"0x1"}, {"jsonrpc":"2.0", "id":2, "result":"0x1"}])),
            ("duplicate id", serde_json::json!([
                {"jsonrpc":"2.0", "id":1, "result":"0x1"}, {"jsonrpc":"2.0", "id":1, "result":"0x1"}])),
            ("wrong id", serde_json::json!([
                {"jsonrpc":"2.0", "id":1, "result":"0x1"}, {"jsonrpc":"2.0", "id":99, "result":"0x1"}])),
            ("malformed id", serde_json::json!([
                {"jsonrpc":"2.0", "id":true, "result":"0x1"}, {"jsonrpc":"2.0", "id":2, "result":"0x1"}])),
        ];
        for (name, body) in cases {
            for backup_invalid in [false, true] {
                let (mut rpc, p, b) = fixture();
                *p.response.lock().unwrap() = Some(body.clone());
                if backup_invalid { *b.response.lock().unwrap() = Some(body.clone()); }
                let result = rpc.call(batch(&["eth_blockNumber", "eth_call"])).await;
                assert_eq!(result.is_err(), backup_invalid, "{name}");
                if let Err(error) = result {
                    assert_eq!(outcome_of(&error), CallOutcome::InvalidResponse, "{name}");
                }
                assert_eq!((p.count(), b.count()), (1, 1), "{name}");
                assert_eq!(*p.calls.lock().unwrap(), *b.calls.lock().unwrap(), "{name}");
                assert_eq!(health(&rpc, 0), 70.0, "{name}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_request_records_nothing() {
        let (mut rpc, p, b) = fixture();
        *p.wait.lock().unwrap() = Some(Arc::new(tokio::sync::Notify::new()));
        let mut cancelled = rpc.call(packet("eth_call"));
        assert!(futures::poll!(cancelled.as_mut()).is_pending());
        drop(cancelled);
        *p.wait.lock().unwrap() = None;
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 0));
        assert_eq!(health(&rpc, 0), 100.0);
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_request_does_not_serialize_other_requests() {
        let (mut rpc, p, b) = fixture();
        let release = Arc::new(tokio::sync::Notify::new());
        *p.wait.lock().unwrap() = Some(release.clone());
        let mut slow = rpc.call(packet("eth_blockNumber"));
        assert!(futures::poll!(slow.as_mut()).is_pending());
        *p.wait.lock().unwrap() = None;
        tokio::time::timeout(Duration::from_secs(1), rpc.call(packet("eth_chainId")))
            .await.unwrap().unwrap();
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), slow).await.unwrap().unwrap();
        assert_eq!((p.count(), b.count()), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn lost_signed_send_response_then_already_known_does_not_resign_or_retry() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        let body = serde_json::json!({"jsonrpc":"2.0", "id":123,
            "error":{"code":-32000, "message":"already known", "data":null}});
        *b.response.lock().unwrap() = Some(body.clone());
        let request: RequestPacket = Request::new("eth_sendRawTransaction", Id::Number(123), ["0x1234"])
            .serialize().unwrap().into();
        let expected = serde_json::to_value(&request).unwrap();
        let start = Instant::now();
        let response = rpc.call(request).await.unwrap();
        assert_eq!(serde_json::to_value(response.as_single().unwrap()).unwrap(), body);
        assert_eq!((p.count(), b.count()), (1, 1));
        assert_eq!(*p.calls.lock().unwrap(), vec![expected.clone()]);
        assert_eq!(*b.calls.lock().unwrap(), vec![expected]);
        assert_eq!(Instant::now(), start);
        assert_eq!(health(&rpc, 1), 100.0);
    }
}
