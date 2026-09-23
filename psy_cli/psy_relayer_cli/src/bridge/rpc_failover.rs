use std::{sync::Arc, task::{Context, Poll}, time::Duration};

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{BoxTransport, TransportError, TransportErrorKind, TransportFut};
use tokio::{sync::Mutex, time::Instant};
use tower::Service;

const PRIMARY_COOLDOWN: Duration = Duration::from_secs(300);

/// Shared by all providers for one chain, including receipt polling and signing fillers.
#[derive(Clone)]
pub(super) struct RpcFailover {
    primary: BoxTransport,
    backup: Option<BoxTransport>,
    primary_retry_at: Arc<Mutex<Option<Instant>>>,
}

impl RpcFailover {
    pub(super) fn new(primary: BoxTransport, backup: Option<BoxTransport>) -> Self {
        Self { primary, backup, primary_retry_at: Arc::new(Mutex::new(None)) }
    }

    async fn request(mut self, request: RequestPacket) -> Result<ResponsePacket, TransportError> {
        // Serialize requests per chain so clones cannot race the recovery probe.
        // The lock covers one RPC, never a proof job or a receipt polling loop.
        let mut retry_at = self.primary_retry_at.lock().await;
        let method = request.method_names().next().unwrap_or("empty").to_owned();
        if retry_at.is_none_or(|deadline| Instant::now() >= deadline) {
            let response = send(&mut self.primary, request.clone()).await;
            match response {
                Err(error) if self.backup.is_some() && is_endpoint_failure(&error) => {
                    *retry_at = Some(Instant::now() + PRIMARY_COOLDOWN);
                    // Do not log URLs, request params or provider messages containing API keys.
                    tracing::warn!(%method, cooldown_secs = PRIMARY_COOLDOWN.as_secs(),
                        "L1 primary RPC failed; using backup during cooldown");
                    if !replay_safe(&request) {
                        return Err(error);
                    }
                }
                response => {
                    if response.as_ref().is_ok_and(ResponsePacket::is_success)
                        && retry_at.take().is_some()
                    {
                        tracing::info!(%method, "L1 primary RPC recovered");
                    }
                    return response;
                }
            }
        }
        let backup = self.backup.as_mut().expect("cooldown requires a backup");
        // Exactly one backup attempt, with no sleep or outer operation replay.
        send(backup, request).await
    }
}

impl Service<RequestPacket> for RpcFailover {
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
        return Err(TransportErrorKind::custom_str("L1 RPC response IDs do not match request"));
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
    use std::sync::Mutex as StdMutex;

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

    fn fixture() -> (RpcFailover, Mock, Mock) {
        let primary = Mock::default();
        let backup = Mock::default();
        (RpcFailover::new(BoxTransport::new(primary.clone()), Some(BoxTransport::new(backup.clone()))), primary, backup)
    }

    fn batch(methods: &[&'static str]) -> RequestPacket {
        RequestPacket::Batch(methods.iter().enumerate().map(|(index, method)| {
            Request::new(*method, Id::Number(index as u64 + 1), serde_json::json!([]))
                .serialize().unwrap()
        }).collect())
    }

    #[tokio::test(start_paused = true)]
    async fn primary_success_never_uses_backup() {
        let (mut rpc, p, b) = fixture();
        rpc.call(packet("eth_blockNumber")).await.unwrap();
        rpc.call(packet("eth_getTransactionReceipt")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn backup_is_sticky_until_exactly_five_minutes_then_primary_recovers() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        rpc.call(packet("eth_blockNumber")).await.unwrap();
        p.recover();
        tokio::time::advance(Duration::from_secs(299)).await;
        rpc.clone().call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (1, 2));
        tokio::time::advance(Duration::from_secs(1)).await;
        rpc.call(packet("eth_call")).await.unwrap();
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (3, 2));
    }

    #[tokio::test(start_paused = true)]
    async fn failed_primary_probe_renews_cooldown() {
        let (mut rpc, p, b) = fixture();
        p.fail(429);
        rpc.call(packet("eth_call")).await.unwrap();
        tokio::time::advance(PRIMARY_COOLDOWN).await;
        rpc.call(packet("eth_call")).await.unwrap();
        tokio::time::advance(Duration::from_secs(299)).await;
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 3));
    }

    #[tokio::test(start_paused = true)]
    async fn backup_failure_returns_without_retry_or_cooldown_extension() {
        let (mut rpc, p, b) = fixture();
        p.fail(503); b.fail(503);
        let start = Instant::now();
        assert!(rpc.call(packet("eth_call")).await.is_err());
        assert_eq!((p.count(), b.count()), (1, 1));
        assert_eq!(Instant::now(), start);
        tokio::time::advance(Duration::from_secs(299)).await;
        assert!(rpc.call(packet("eth_call")).await.is_err());
        assert_eq!((p.count(), b.count()), (1, 2));
        tokio::time::advance(Duration::from_secs(1)).await;
        p.recover();
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (2, 2));
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

    #[tokio::test(start_paused = true)]
    async fn concurrent_expiry_only_probes_failed_primary_once() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        rpc.call(packet("eth_call")).await.unwrap();
        tokio::time::advance(PRIMARY_COOLDOWN).await;
        let mut jobs = Vec::new();
        for _ in 0..8 {
            let mut client = rpc.clone();
            jobs.push(tokio::spawn(async move { client.call(packet("eth_call")).await.unwrap(); }));
        }
        for job in jobs { job.await.unwrap(); }
        assert_eq!((p.count(), b.count()), (2, 9));
    }

    #[tokio::test]
    async fn reverts_and_invalid_params_do_not_fail_over() {
        for code in [3, -32602] {
            let (mut rpc, p, b) = fixture();
            p.fail(code);
            let response = rpc.call(packet("eth_call")).await.unwrap();
            assert_eq!(response.first_error_code(), Some(code));
            assert_eq!((p.count(), b.count()), (1, 0));
            assert!(rpc.primary_retry_at.lock().await.is_none());
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
    }

    #[tokio::test]
    async fn no_backup_attempts_primary_once() {
        let p = Mock::default(); p.fail(503);
        let mut rpc = RpcFailover::new(BoxTransport::new(p.clone()), None);
        assert!(rpc.call(packet("eth_call")).await.is_err());
        assert_eq!(p.count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_releases_lock_and_preserves_recorded_cooldown() {
        let (mut rpc, p, b) = fixture();
        p.fail(503);
        *b.wait.lock().unwrap() = Some(Arc::new(tokio::sync::Notify::new()));
        let mut clone = rpc.clone();
        let job = tokio::spawn(async move { clone.call(packet("eth_call")).await });
        while b.count() == 0 { tokio::task::yield_now().await; }
        job.abort();
        assert!(job.await.unwrap_err().is_cancelled());
        *b.wait.lock().unwrap() = None;
        rpc.call(packet("eth_call")).await.unwrap();
        assert_eq!((p.count(), b.count()), (1, 2));
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
    fn quota_and_business_errors_are_distinguished() {
        for (code, message, expected) in [
            (-32600, "Under the Free tier plan, up to a 10 block range", true),
            (-32603, "upstream unavailable", true),
            (-32000, "execution reverted", false),
            (-32000, "nonce too low", false),
            (-32000, "insufficient funds", false),
            (-32602, "invalid params", false),
        ] {
            let payload = serde_json::from_value(serde_json::json!({"code":code,"message":message})).unwrap();
            assert_eq!(is_endpoint_failure(&TransportError::ErrorResp(payload)), expected, "{message}");
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
        assert!(rpc.primary_retry_at.lock().await.is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn mixed_success_and_quota_batch_replays_identical_safe_packet_once() {
        let (mut rpc, p, b) = fixture();
        *p.response.lock().unwrap() = Some(serde_json::json!([
            {"jsonrpc":"2.0", "id":1, "result":"0x1"},
            {"jsonrpc":"2.0", "id":2,
                "error":{"code":429, "message":"quota exceeded"}}
        ]));
        let response = rpc.call(batch(&["eth_blockNumber", "eth_call"])).await.unwrap();
        assert!(response.is_success());
        assert_eq!((p.count(), b.count()), (1, 1));
        assert_eq!(*p.calls.lock().unwrap(), *b.calls.lock().unwrap());
        assert_eq!(*rpc.primary_retry_at.lock().await, Some(Instant::now() + PRIMARY_COOLDOWN));
    }

    #[tokio::test]
    async fn mixed_batch_with_node_signed_send_is_not_replayed_after_partial_success() {
        let (mut rpc, p, b) = fixture();
        *p.response.lock().unwrap() = Some(serde_json::json!([
            {"jsonrpc":"2.0", "id":1, "result":"0x1234"},
            {"jsonrpc":"2.0", "id":2,
                "error":{"code":429, "message":"quota exceeded"}}
        ]));
        let error = rpc.call(batch(&["eth_sendTransaction", "eth_call"])).await.unwrap_err();
        assert!(matches!(error, TransportError::ErrorResp(ref payload) if payload.code == 429));
        assert_eq!((p.count(), b.count()), (1, 0));
        assert!(rpc.primary_retry_at.lock().await.is_some());
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
        assert!(rpc.primary_retry_at.lock().await.is_none());
    }

    #[tokio::test]
    async fn malformed_missing_duplicate_and_wrong_ids_fail_over_only_once() {
        let cases = [
            ("missing member", serde_json::json!([
                {"jsonrpc":"2.0", "id":1, "result":"0x1"}
            ])),
            ("missing id", serde_json::json!([
                {"jsonrpc":"2.0", "result":"0x1"},
                {"jsonrpc":"2.0", "id":2, "result":"0x1"}
            ])),
            ("duplicate id", serde_json::json!([
                {"jsonrpc":"2.0", "id":1, "result":"0x1"},
                {"jsonrpc":"2.0", "id":1, "result":"0x1"}
            ])),
            ("wrong id", serde_json::json!([
                {"jsonrpc":"2.0", "id":1, "result":"0x1"},
                {"jsonrpc":"2.0", "id":99, "result":"0x1"}
            ])),
            ("malformed id", serde_json::json!([
                {"jsonrpc":"2.0", "id":true, "result":"0x1"},
                {"jsonrpc":"2.0", "id":2, "result":"0x1"}
            ])),
        ];
        for (name, body) in cases {
            for backup_invalid in [false, true] {
                let (mut rpc, p, b) = fixture();
                *p.response.lock().unwrap() = Some(body.clone());
                if backup_invalid { *b.response.lock().unwrap() = Some(body.clone()); }
                let result = rpc.call(batch(&["eth_blockNumber", "eth_call"])).await;
                assert_eq!(result.is_err(), backup_invalid, "{name}");
                if let Err(error) = result { assert!(is_endpoint_failure(&error), "{name}"); }
                assert_eq!((p.count(), b.count()), (1, 1), "{name}");
                assert_eq!(*p.calls.lock().unwrap(), *b.calls.lock().unwrap(), "{name}");
                assert!(rpc.primary_retry_at.lock().await.is_some(), "{name}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_initial_primary_or_recovery_probe_releases_lock_without_new_cooldown() {
        for recovering in [false, true] {
            let (mut rpc, p, b) = fixture();
            if recovering {
                p.fail(503);
                rpc.call(packet("eth_call")).await.unwrap();
                tokio::time::advance(PRIMARY_COOLDOWN).await;
                p.recover();
            }
            let previous_deadline = *rpc.primary_retry_at.lock().await;
            *p.wait.lock().unwrap() = Some(Arc::new(tokio::sync::Notify::new()));
            let mut cancelled = rpc.call(packet("eth_call"));
            assert!(futures::poll!(cancelled.as_mut()).is_pending());
            assert_eq!((p.count(), b.count()), if recovering { (2, 1) } else { (1, 0) });
            drop(cancelled);
            assert_eq!(*rpc.primary_retry_at.try_lock().unwrap(), previous_deadline);
            *p.wait.lock().unwrap() = None;
            tokio::time::timeout(Duration::from_secs(1), rpc.call(packet("eth_call")))
                .await.unwrap().unwrap();
            assert_eq!((p.count(), b.count()), if recovering { (3, 1) } else { (2, 0) });
            assert!(rpc.primary_retry_at.lock().await.is_none());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancelling_mutex_waiter_sends_nothing_and_does_not_block_next_waiter() {
        let (mut rpc, p, b) = fixture();
        let release = Arc::new(tokio::sync::Notify::new());
        *p.wait.lock().unwrap() = Some(release.clone());
        let mut holder = rpc.call(packet("eth_blockNumber"));
        assert!(futures::poll!(holder.as_mut()).is_pending());
        let mut cancelled = rpc.call(packet("eth_getBalance"));
        assert!(futures::poll!(cancelled.as_mut()).is_pending());
        let mut next = rpc.call(packet("eth_chainId"));
        assert!(futures::poll!(next.as_mut()).is_pending());
        assert_eq!((p.count(), b.count()), (1, 0));
        drop(cancelled);
        assert!(rpc.primary_retry_at.try_lock().is_err());
        *p.wait.lock().unwrap() = None;
        release.notify_one();
        tokio::time::timeout(Duration::from_secs(1), holder).await.unwrap().unwrap();
        tokio::time::timeout(Duration::from_secs(1), next).await.unwrap().unwrap();
        let calls = p.calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["method"], "eth_blockNumber");
        assert_eq!(calls[1]["method"], "eth_chainId");
        assert_eq!(b.count(), 0);
        assert!(rpc.primary_retry_at.try_lock().unwrap().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn lost_signed_send_response_then_already_known_does_not_resign_or_retry() {
        let (mut rpc, p, b) = fixture();
        // Model a lost response after receipt of the packet, not on-chain execution.
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
        assert_eq!(*rpc.primary_retry_at.lock().await, Some(start + PRIMARY_COOLDOWN));
    }
}
