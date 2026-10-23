//! The Reader's internal HTTP/JSON server: bearer authentication, admission
//! lanes, request deadlines, error mapping, health and `/metrics`.
//!
//! Every `/v1` request authenticates, picks its lane (the route's default, or
//! an authenticated `x-psy-lane` header), takes a lane slot, and reads exactly
//! one `View` before its deadline. Every error is an `ErrorBody` whose HTTP
//! status is `ErrorCode::http_status`, and every 503 carries `Retry-After`.

use std::future::Future;
use std::sync::Arc;
use std::task::Poll;

use arc_swap::ArcSwap;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use psy_bridge_reader_api::{
    ClaimProofQuery, DepositByIndexQuery, DepositsByAddressQuery, DepositsByTxQuery, ErrorBody, ErrorCode, ExplorerQuery, Lane,
    PrefixQuery, TreeRootQuery, WithdrawalClaimsRequest, LANE_HEADER,
};
use serde::Serialize;
use tokio::time::Instant;

use crate::admission::Admission;
use crate::metrics::Metrics;
use crate::model::{ReadError, View};

/// Largest accepted request body.
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// A list read over this many rows runs on the blocking pool.
const INLINE_ROWS: usize = 100;

const LANES: [Lane; 4] = Lane::ALL;

#[derive(Clone)]
pub struct ServerState {
    pub view: Arc<ArcSwap<View>>,
    pub admission: Arc<Admission>,
    pub token: Arc<str>,
    pub metrics: Metrics,
}

pub fn router(state: ServerState) -> Router {
    // Every lane's gauges exist from the start, at zero.
    for lane in LANES {
        refresh_lane(&state.admission, &state.metrics, lane);
    }
    Router::new()
        .route("/v1/status", get(status))
        .route("/v1/deposits/by-address", get(deposits_by_address))
        .route("/v1/deposits/by-index", get(deposit_by_index))
        .route("/v1/deposits/by-tx", get(deposits_by_tx))
        .route("/v1/deposits/prefix", get(prefix))
        .route("/v1/withdrawal-claims", post(withdrawal_claims).layer(DefaultBodyLimit::max(MAX_BODY_BYTES)))
        .route("/v1/tree/root", get(tree_root))
        .route("/v1/tree/proof", get(claim_proof))
        .route("/v1/explorer", get(explorer))
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .fallback(no_route)
        .method_not_allowed_fallback(no_method)
        .layer(axum::middleware::map_response(no_store))
        .with_state(state)
}

/// An error answer: the status follows the code, and the `Retry-After`
/// header and field are set for every code a retry can cure.
struct ApiError {
    code: ErrorCode,
    message: String,
}

impl ApiError {
    fn new(code: ErrorCode, message: impl Into<String>) -> ApiError {
        ApiError { code, message: message.into() }
    }
}

fn retry_after(code: ErrorCode) -> Option<u32> {
    match code {
        ErrorCode::NotReady => Some(2),
        ErrorCode::CountNotIndexed
        | ErrorCode::Overloaded
        | ErrorCode::Timeout
        | ErrorCode::SchemaMismatch
        | ErrorCode::Unavailable => Some(1),
        ErrorCode::BadRequest | ErrorCode::Unauthorized | ErrorCode::Internal => None,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let retry = retry_after(self.code);
        let body = ErrorBody { code: self.code, message: self.message, retry_after_seconds: retry };
        let mut response = (status, Json(body)).into_response();
        if let Some(seconds) = retry {
            response.headers_mut().insert(RETRY_AFTER, HeaderValue::from(seconds));
        }
        response
    }
}

impl From<ReadError> for ApiError {
    fn from(e: ReadError) -> ApiError {
        let message = e.to_string();
        let code = match e {
            ReadError::BadRequest(_) => ErrorCode::BadRequest,
            ReadError::NotReady(_) => ErrorCode::NotReady,
            ReadError::CountNotIndexed { .. } => ErrorCode::CountNotIndexed,
            ReadError::Internal(_) => ErrorCode::Internal,
        };
        ApiError::new(code, message)
    }
}

async fn no_store(mut response: Response) -> Response {
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn no_route() -> Response {
    let mut response = ApiError::new(ErrorCode::BadRequest, "no such route").into_response();
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
}

async fn no_method() -> Response {
    let mut response = ApiError::new(ErrorCode::BadRequest, "method not allowed").into_response();
    *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
    response
}

/// Compares in time that depends only on the expected token's length.
fn token_matches(presented: &[u8], expected: &[u8]) -> bool {
    let mut diff = u8::from(presented.len() != expected.len());
    for (i, e) in expected.iter().enumerate() {
        diff |= presented.get(i).copied().unwrap_or(0) ^ e;
    }
    // An empty configured token admits nobody.
    diff == 0 && !expected.is_empty()
}

fn authenticate(token: &str, headers: &HeaderMap) -> Result<(), ApiError> {
    let presented = headers.get(AUTHORIZATION).and_then(|v| v.as_bytes().strip_prefix(b"Bearer "));
    match presented {
        Some(p) if token_matches(p, token.as_bytes()) => Ok(()),
        _ => Err(ApiError::new(ErrorCode::Unauthorized, "missing or wrong bearer token")),
    }
}

fn lane_header(headers: &HeaderMap) -> Result<Option<Lane>, ApiError> {
    let Some(value) = headers.get(LANE_HEADER) else { return Ok(None) };
    let parsed = value.to_str().ok().and_then(Lane::parse);
    match parsed {
        Some(lane) => Ok(Some(lane)),
        None => Err(ApiError::new(ErrorCode::BadRequest, format!("unknown {LANE_HEADER} value"))),
    }
}

fn refresh_lane(admission: &Admission, metrics: &Metrics, lane: Lane) {
    metrics.set_lane_queue(lane.clone(), admission.queue_len(lane.clone()) as i64);
    metrics.set_lane_in_flight(lane.clone(), admission.in_flight(lane) as i64);
}

/// Refreshes a lane's gauges when dropped, so a request that leaves for any
/// reason, including cancellation while queued, leaves them current.
struct LaneGauges<'a> {
    state: &'a ServerState,
    lane: Lane,
}

impl Drop for LaneGauges<'_> {
    fn drop(&mut self) {
        refresh_lane(&self.state.admission, &self.state.metrics, self.lane.clone());
    }
}

/// One `/v1` request: authenticate, pick the lane, admit, read one view
/// before the deadline, and record the request.
async fn run<Q, R>(
    state: &ServerState,
    headers: &HeaderMap,
    endpoint: &'static str,
    default_lane: Lane,
    input: Result<Q, String>,
    blocking: fn(&Q) -> bool,
    read: fn(&View, &Q) -> Result<R, ReadError>,
) -> Response
where
    Q: Send + 'static,
    R: Serialize + Send + 'static,
{
    let start = Instant::now();
    let mut lane = default_lane;
    let response = match admit_and_read(state, headers, &mut lane, input, blocking, read, start).await {
        Ok(body) => Json(body).into_response(),
        Err(e) => e.into_response(),
    };
    state.metrics.observe_request(endpoint, lane, response.status().as_u16(), start.elapsed().as_secs_f64());
    response
}

async fn admit_and_read<Q, R>(
    state: &ServerState,
    headers: &HeaderMap,
    lane: &mut Lane,
    input: Result<Q, String>,
    blocking: fn(&Q) -> bool,
    read: fn(&View, &Q) -> Result<R, ReadError>,
    start: Instant,
) -> Result<R, ApiError>
where
    Q: Send + 'static,
    R: Send + 'static,
{
    authenticate(&state.token, headers)?;
    if let Some(chosen) = lane_header(headers)? {
        *lane = chosen;
    }
    let q = input.map_err(|m| ApiError::new(ErrorCode::BadRequest, m))?;
    let lane = lane.clone();
    let _gauges = LaneGauges { state, lane: lane.clone() };
    let permit = {
        let mut enter = std::pin::pin!(state.admission.enter(lane.clone()));
        let first = std::future::poll_fn(|cx| Poll::Ready(enter.as_mut().poll(cx))).await;
        match first {
            Poll::Ready(r) => r,
            Poll::Pending => {
                // Queued: the queue gauge counts this request while it waits.
                refresh_lane(&state.admission, &state.metrics, lane.clone());
                enter.await
            }
        }
    };
    let permit = permit.map_err(|code| {
        state.metrics.inc_shed(lane.clone(), code.as_str());
        ApiError::new(code, format!("lane {} is full", lane.as_str()))
    })?;
    refresh_lane(&state.admission, &state.metrics, lane.clone());
    // The deadline counts from arrival, so it covers the queue wait too.
    let deadline = start + state.admission.budget(lane.clone()).deadline;
    let view = state.view.load_full();
    let work = async {
        if blocking(&q) {
            let admission = state.admission.clone();
            let metrics = state.metrics.clone();
            let lane = lane.clone();
            // The permit moves with the work: a read that outlives its
            // deadline still holds its slot until it finishes.
            let task = tokio::task::spawn_blocking(move || {
                let result = read(&view, &q);
                drop(permit);
                refresh_lane(&admission, &metrics, lane);
                result
            });
            task.await.map_err(|e| ApiError::new(ErrorCode::Internal, format!("read task failed: {e}")))?.map_err(ApiError::from)
        } else {
            let result = read(&view, &q);
            drop(permit);
            result.map_err(ApiError::from)
        }
    };
    match tokio::time::timeout_at(deadline, work).await {
        Ok(result) => result,
        Err(_) => Err(ApiError::new(ErrorCode::Timeout, format!("lane {} deadline passed", lane.as_str()))),
    }
}

fn query<T>(q: Result<Query<T>, QueryRejection>) -> Result<T, String> {
    q.map(|Query(q)| q).map_err(|e| e.body_text())
}

fn json<T>(b: Result<Json<T>, JsonRejection>) -> Result<T, String> {
    b.map(|Json(b)| b).map_err(|e| e.body_text())
}

async fn status(State(s): State<ServerState>, headers: HeaderMap) -> Response {
    run(&s, &headers, "status", Lane::Background, Ok(()), |_| false, |v, _: &()| Ok(v.status())).await
}

async fn deposits_by_address(
    State(s): State<ServerState>,
    headers: HeaderMap,
    q: Result<Query<DepositsByAddressQuery>, QueryRejection>,
) -> Response {
    let blocking = |q: &DepositsByAddressQuery| q.offset.saturating_add(u64::from(q.limit)) > INLINE_ROWS as u64;
    run(&s, &headers, "deposits_by_address", Lane::Interactive, query(q), blocking, View::deposits_by_address).await
}

async fn deposit_by_index(
    State(s): State<ServerState>,
    headers: HeaderMap,
    q: Result<Query<DepositByIndexQuery>, QueryRejection>,
) -> Response {
    run(&s, &headers, "deposit_by_index", Lane::BridgeProgress, query(q), |_| false, View::deposit_by_index).await
}

async fn deposits_by_tx(
    State(s): State<ServerState>,
    headers: HeaderMap,
    q: Result<Query<DepositsByTxQuery>, QueryRejection>,
) -> Response {
    run(&s, &headers, "deposits_by_tx", Lane::Interactive, query(q), |_| false, View::deposits_by_tx).await
}

async fn prefix(State(s): State<ServerState>, headers: HeaderMap, q: Result<Query<PrefixQuery>, QueryRejection>) -> Response {
    run(&s, &headers, "prefix", Lane::BridgeProgress, query(q), |_| false, View::prefix).await
}

async fn withdrawal_claims(
    State(s): State<ServerState>,
    headers: HeaderMap,
    b: Result<Json<WithdrawalClaimsRequest>, JsonRejection>,
) -> Response {
    let blocking = |b: &WithdrawalClaimsRequest| b.nullifiers.len() > INLINE_ROWS;
    run(&s, &headers, "withdrawal_claims", Lane::Interactive, json(b), blocking, View::withdrawal_claims).await
}

async fn tree_root(State(s): State<ServerState>, headers: HeaderMap, q: Result<Query<TreeRootQuery>, QueryRejection>) -> Response {
    run(&s, &headers, "tree_root", Lane::BridgeProgress, query(q), |_| true, View::tree_root).await
}

async fn claim_proof(
    State(s): State<ServerState>,
    headers: HeaderMap,
    q: Result<Query<ClaimProofQuery>, QueryRejection>,
) -> Response {
    run(&s, &headers, "claim_proof", Lane::ClaimProof, query(q), |_| true, View::claim_proof).await
}

async fn explorer(State(s): State<ServerState>, headers: HeaderMap, q: Result<Query<ExplorerQuery>, QueryRejection>) -> Response {
    // Up to FEED_LEN deposits plus FEED_LEN batches, merged across chain
    // indexes: always over INLINE_ROWS rows.
    run(&s, &headers, "explorer", Lane::Background, query(q), |_| true, View::explorer).await
}

#[derive(Serialize)]
struct Health {
    ok: bool,
}

async fn live() -> Response {
    Json(Health { ok: true }).into_response()
}

/// 200 iff the current view is ready on every chain.
async fn ready(State(s): State<ServerState>) -> Response {
    let status = s.view.load().status();
    if status.ready {
        return Json(Health { ok: true }).into_response();
    }
    let reason = status
        .chains
        .iter()
        .find_map(|c| c.not_ready_reason.clone())
        .unwrap_or_else(|| "not every chain is ready".to_owned());
    ApiError::new(ErrorCode::NotReady, reason).into_response()
}

async fn metrics(State(s): State<ServerState>) -> Response {
    for lane in LANES {
        refresh_lane(&s.admission, &s.metrics, lane);
    }
    let mut response = s.metrics.render().into_response();
    response.headers_mut().insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"));
    response
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use psy_bridge_reader_api::{Revision, TreeRootResponse};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;
    use crate::admission::{Budgets, LaneBudget};
    use crate::model::{ApplyOutcome, Model};
    use crate::test_support::TickBuilder;

    const TOKEN: &str = "secret-token";

    fn lane_budget(concurrency: usize, max_queue: usize) -> LaneBudget {
        LaneBudget { concurrency, max_queue, queue_wait: Duration::from_secs(5), deadline: Duration::from_secs(9) }
    }

    fn small_budgets() -> Budgets {
        Budgets {
            bridge_progress: lane_budget(2, 2),
            claim_proof: lane_budget(2, 2),
            interactive: lane_budget(2, 2),
            background: lane_budget(1, 1),
        }
    }

    /// Five deposits on chain index 0 of chain_id 1, and one claim.
    fn ready_model() -> (Model, TickBuilder) {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        for block in [10, 11, 95, 96, 97] {
            b.deposit(0, 1, block, "A");
        }
        b.claim(1, 10, "n1");
        let mut m = Model::new();
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Published { .. }));
        (m, b)
    }

    fn state_of(m: &Model, budgets: &Budgets) -> ServerState {
        ServerState {
            view: m.view_handle(),
            admission: Arc::new(Admission::new(budgets)),
            token: Arc::from(TOKEN),
            metrics: Metrics::new(1),
        }
    }

    fn get(path: &str) -> axum::http::request::Builder {
        Request::get(path).header(AUTHORIZATION, format!("Bearer {TOKEN}"))
    }

    fn req(path: &str) -> Request<Body> {
        get(path).body(Body::empty()).unwrap()
    }

    async fn send(state: &ServerState, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let response = router(state.clone()).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, headers, body)
    }

    fn metric(state: &ServerState, series: &str) -> Option<f64> {
        state.metrics.render().lines().find_map(|l| l.strip_prefix(series).and_then(|r| r.trim().parse().ok()))
    }

    fn assert_error(r: &(StatusCode, HeaderMap, Value), status: u16, code: &str, retry: Option<&str>) {
        assert_eq!(r.0.as_u16(), status, "{:?}", r.2);
        assert_eq!(r.2["code"], code);
        assert_eq!(r.1.get(CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(r.1.get(CACHE_CONTROL).unwrap(), "no-store");
        assert_eq!(r.1.get(RETRY_AFTER).map(|v| v.to_str().unwrap()), retry);
    }

    const ROOT: &str = "/v1/tree/root?chain_index=0&count=5";
    const BY_ADDRESS: &str = "/v1/deposits/by-address?shield_address=A&chain_id=1&limit=10&offset=0";

    /// Polls a future until `done` holds; panics if it finishes first.
    async fn poll_until<F: Future + Unpin>(f: &mut F, done: impl Fn() -> bool) {
        for _ in 0..1000 {
            if done() {
                return;
            }
            let pending = std::future::poll_fn(|cx| Poll::Ready(std::pin::Pin::new(&mut *f).poll(cx).is_pending())).await;
            assert!(pending, "finished before the condition held");
            tokio::task::yield_now().await;
        }
        panic!("condition never held");
    }

    async fn wait_queued(s: &ServerState, lane: Lane, n: usize) {
        let queued = async {
            while s.admission.queue_len(lane.clone()) < n {
                tokio::task::yield_now().await;
            }
        };
        tokio::time::timeout(Duration::from_secs(5), queued).await.unwrap();
    }

    #[tokio::test]
    async fn requests_without_the_token_are_401() {
        let (m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let none = Request::get(ROOT).body(Body::empty()).unwrap();
        assert_error(&send(&s, none).await, 401, "unauthorized", None);
        let wrong = Request::get(ROOT).header(AUTHORIZATION, "Bearer secret-tokem").body(Body::empty()).unwrap();
        assert_error(&send(&s, wrong).await, 401, "unauthorized", None);
        let longer = Request::get(ROOT).header(AUTHORIZATION, format!("Bearer {TOKEN}x")).body(Body::empty()).unwrap();
        assert_error(&send(&s, longer).await, 401, "unauthorized", None);
        let basic = Request::get(ROOT).header(AUTHORIZATION, format!("Basic {TOKEN}")).body(Body::empty()).unwrap();
        assert_error(&send(&s, basic).await, 401, "unauthorized", None);
        // A lane header is not looked at before authentication.
        let lane = Request::get(ROOT).header(LANE_HEADER, "bogus").body(Body::empty()).unwrap();
        assert_error(&send(&s, lane).await, 401, "unauthorized", None);
        let post = Request::post("/v1/withdrawal-claims").body(Body::from("{}")).unwrap();
        assert_error(&send(&s, post).await, 401, "unauthorized", None);
        let ok = send(&s, req(ROOT)).await;
        assert_eq!(ok.0, StatusCode::OK);
        assert_eq!(ok.1.get(CACHE_CONTROL).unwrap(), "no-store");
        let counted = "psy_bridge_reader_requests_total{endpoint=\"tree_root\",lane=\"bridge_progress\",status=\"4xx\"} ";
        assert_eq!(metric(&s, counted), Some(5.0));
        // An empty configured token admits nobody.
        let open = ServerState { token: Arc::from(""), ..s.clone() };
        let blank = Request::get(ROOT).header(AUTHORIZATION, "Bearer ").body(Body::empty()).unwrap();
        assert_error(&send(&open, blank).await, 401, "unauthorized", None);
    }

    #[tokio::test]
    async fn health_and_metrics_need_no_token() {
        let (m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let live = send(&s, Request::get("/health/live").body(Body::empty()).unwrap()).await;
        assert_eq!((live.0, live.2["ok"].clone()), (StatusCode::OK, Value::Bool(true)));
        let ready = send(&s, Request::get("/health/ready").body(Body::empty()).unwrap()).await;
        assert_eq!(ready.0, StatusCode::OK);
        assert_eq!(ready.1.get(CACHE_CONTROL).unwrap(), "no-store");
        let metrics = send(&s, Request::get("/metrics").body(Body::empty()).unwrap()).await;
        assert_eq!(metrics.0, StatusCode::OK);
        assert!(metrics.1.get(CONTENT_TYPE).unwrap().to_str().unwrap().starts_with("text/plain"));
        let text = metrics.2.as_str().unwrap();
        for lane in ["bridge_progress", "claim_proof", "interactive", "background"] {
            assert!(text.contains(&format!("psy_bridge_reader_lane_queue{{lane=\"{lane}\"}} 0")), "{lane}");
            assert!(text.contains(&format!("psy_bridge_reader_lane_in_flight{{lane=\"{lane}\"}} 0")), "{lane}");
        }
        assert_error(&send(&s, Request::get("/nowhere").body(Body::empty()).unwrap()).await, 404, "bad_request", None);
    }

    #[tokio::test]
    async fn not_ready_chain_is_503_with_retry_after() {
        // Before the first verified tick nothing is ready.
        let m = Model::new();
        let s = state_of(&m, &Budgets::default());
        assert_error(&send(&s, req(ROOT)).await, 503, "not_ready", Some("2"));
        let r = send(&s, Request::get("/health/ready").body(Body::empty()).unwrap()).await;
        assert_error(&r, 503, "not_ready", Some("2"));
        assert_eq!(r.2["retry_after_seconds"], 2);
        // The status endpoint reports readiness instead of failing.
        let status = send(&s, req("/v1/status")).await;
        assert_eq!((status.0, status.2["ready"].clone()), (StatusCode::OK, Value::Bool(false)));
        // One chain index reloading in an otherwise ready view.
        let (mut m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        assert_eq!(send(&s, Request::get("/health/ready").body(Body::empty()).unwrap()).await.0, StatusCode::OK);
        m.reset_chain(0);
        assert_error(&send(&s, req(ROOT)).await, 503, "not_ready", Some("2"));
        assert_error(&send(&s, Request::get("/health/ready").body(Body::empty()).unwrap()).await, 503, "not_ready", Some("2"));
    }

    #[tokio::test]
    async fn count_above_indexed_is_409() {
        let (m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let r = send(&s, req("/v1/tree/root?chain_index=0&count=6")).await;
        assert_error(&r, 409, "count_not_indexed", Some("1"));
        assert_eq!(r.2["retry_after_seconds"], 1);
        let proof = send(&s, req("/v1/tree/proof?chain_index=0&leaf=0&count=6")).await;
        assert_error(&proof, 409, "count_not_indexed", Some("1"));
        assert_eq!(send(&s, req("/v1/tree/proof?chain_index=0&leaf=0&count=5")).await.0, StatusCode::OK);
    }

    #[tokio::test]
    async fn page_over_1000_and_nullifiers_over_1000_are_400() {
        let (m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let page = send(&s, req("/v1/deposits/by-address?shield_address=A&chain_id=1&limit=1001&offset=0")).await;
        assert_error(&page, 400, "bad_request", None);
        let full = send(&s, req("/v1/deposits/by-address?shield_address=A&chain_id=1&limit=1000&offset=0")).await;
        assert_eq!((full.0, full.2["total"].clone()), (StatusCode::OK, Value::from(5)));
        let claims = |n: usize| {
            let nullifiers = (0..n).map(|i| format!("n{i}")).collect::<Vec<_>>();
            let body = serde_json::json!({ "chain_id": 1, "nullifiers": nullifiers }).to_string();
            Request::post("/v1/withdrawal-claims")
                .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(body))
                .unwrap()
        };
        assert_error(&send(&s, claims(1001)).await, 400, "bad_request", None);
        let found = send(&s, claims(1000)).await;
        assert_eq!(found.0, StatusCode::OK);
        assert_eq!(found.2["claims"][0]["nullifier"], "n1");
        // Malformed input is a JSON 400, never axum's plain-text rejection.
        assert_error(&send(&s, req("/v1/deposits/by-address?shield_address=A&chain_id=1")).await, 400, "bad_request", None);
        assert_error(&send(&s, req("/v1/tree/root?chain_index=x&count=1")).await, 400, "bad_request", None);
        let garbage = Request::post("/v1/withdrawal-claims")
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from("{"))
            .unwrap();
        assert_error(&send(&s, garbage).await, 400, "bad_request", None);
        let oversized = format!("{{\"chain_id\":1,\"nullifiers\":[\"{}\"]}}", "a".repeat(MAX_BODY_BYTES));
        let big = Request::post("/v1/withdrawal-claims")
            .header(AUTHORIZATION, format!("Bearer {TOKEN}"))
            .header(CONTENT_TYPE, "application/json")
            .body(Body::from(oversized))
            .unwrap();
        assert_error(&send(&s, big).await, 400, "bad_request", None);
    }

    #[tokio::test]
    async fn a_full_lane_sheds_with_503_overloaded_and_other_lanes_still_answer() {
        let (m, _) = ready_model();
        let s = state_of(&m, &small_budgets());
        // Concurrency 2: both slots held; queue 2: two requests waiting.
        let held = [s.admission.enter(Lane::Interactive).await.unwrap(), s.admission.enter(Lane::Interactive).await.unwrap()];
        let mut waiting = Vec::new();
        for _ in 0..2 {
            let s = s.clone();
            waiting.push(tokio::spawn(async move { send(&s, req(BY_ADDRESS)).await.0 }));
        }
        wait_queued(&s, Lane::Interactive, 2).await;
        assert_eq!(metric(&s, "psy_bridge_reader_lane_queue{lane=\"interactive\"} "), Some(2.0));
        let start = std::time::Instant::now();
        let shed = send(&s, req(BY_ADDRESS)).await;
        assert!(start.elapsed() < Duration::from_secs(1), "a full queue sheds at once");
        assert_error(&shed, 503, "overloaded", Some("1"));
        assert_eq!(metric(&s, "psy_bridge_reader_shed_total{code=\"overloaded\",lane=\"interactive\"} "), Some(1.0));
        // Another lane is untouched.
        let root = send(&s, req(ROOT)).await;
        assert_eq!(root.0, StatusCode::OK);
        // Releasing the held slots lets the queued requests through.
        drop(held);
        for w in waiting {
            assert_eq!(w.await.unwrap(), StatusCode::OK);
        }
        assert_eq!(s.admission.queue_len(Lane::Interactive), 0);
        assert_eq!(metric(&s, "psy_bridge_reader_lane_queue{lane=\"interactive\"} "), Some(0.0));
        assert_eq!(metric(&s, "psy_bridge_reader_lane_in_flight{lane=\"interactive\"} "), Some(0.0));
    }

    #[tokio::test]
    async fn abandoned_queued_request_releases_its_slot() {
        let (m, _) = ready_model();
        let s = state_of(&m, &small_budgets());
        let held = s.admission.enter(Lane::Background).await.unwrap();
        let queue = "psy_bridge_reader_lane_queue{lane=\"background\"} ";
        {
            let mut call = Box::pin(router(s.clone()).oneshot(req("/v1/status")));
            poll_until(&mut call, || s.admission.queue_len(Lane::Background) == 1).await;
            assert_eq!(metric(&s, queue), Some(1.0));
        }
        assert_eq!(s.admission.queue_len(Lane::Background), 0);
        assert_eq!(metric(&s, queue), Some(0.0));
        // The single queue slot is free again: the next request queues, not sheds.
        let next = tokio::spawn({
            let s = s.clone();
            async move { send(&s, req("/v1/status")).await.0 }
        });
        wait_queued(&s, Lane::Background, 1).await;
        drop(held);
        assert_eq!(next.await.unwrap(), StatusCode::OK);
    }

    #[tokio::test]
    async fn lane_header_overrides_the_default_lane() {
        let (m, _) = ready_model();
        let s = state_of(&m, &small_budgets());
        // Bridge progress is full, slots and queue: its default requests shed.
        let held = [s.admission.enter(Lane::BridgeProgress).await.unwrap(), s.admission.enter(Lane::BridgeProgress).await.unwrap()];
        let mut waiting = Vec::new();
        for _ in 0..2 {
            let s = s.clone();
            waiting.push(tokio::spawn(async move { send(&s, req(ROOT)).await.0 }));
        }
        wait_queued(&s, Lane::BridgeProgress, 2).await;
        assert_error(&send(&s, req(ROOT)).await, 503, "overloaded", Some("1"));
        // The same route on the interactive lane answers.
        let moved = send(&s, get(ROOT).header(LANE_HEADER, "interactive").body(Body::empty()).unwrap()).await;
        assert_eq!(moved.0, StatusCode::OK);
        let series = "psy_bridge_reader_requests_total{endpoint=\"tree_root\",lane=\"interactive\",status=\"2xx\"} ";
        assert_eq!(metric(&s, series), Some(1.0));
        // An unknown lane is a bad request.
        let bogus = send(&s, get(ROOT).header(LANE_HEADER, "bogus").body(Body::empty()).unwrap()).await;
        assert_error(&bogus, 400, "bad_request", None);
        drop(held);
        for w in waiting {
            assert_eq!(w.await.unwrap(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn unknown_query_parameter_is_400() {
        let (m, _) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let r = send(&s, req("/v1/tree/root?chain_index=0&count=5&chain_idx=1")).await;
        assert_error(&r, 400, "bad_request", None);
        assert_eq!(send(&s, req(ROOT)).await.0, StatusCode::OK);
    }

    #[test]
    fn a_timed_out_read_is_503_timeout_with_retry_after() {
        // One blocking thread, held by the test: the request's blocking read
        // cannot start, so it outlives its deadline whatever the machine speed.
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().max_blocking_threads(1).build().unwrap();
        rt.block_on(async {
            let (m, _) = ready_model();
            let mut budgets = small_budgets();
            budgets.interactive.queue_wait = Duration::from_millis(5);
            budgets.interactive.deadline = Duration::from_millis(50);
            let s = state_of(&m, &budgets);
            let (release, hold) = std::sync::mpsc::channel::<()>();
            let blocker = tokio::task::spawn_blocking(move || {
                let _ = hold.recv();
            });
            tokio::task::yield_now().await;
            let wide = "/v1/deposits/by-address?shield_address=A&chain_id=1&limit=101&offset=0";
            let r = send(&s, req(wide)).await;
            assert_error(&r, 503, "timeout", Some("1"));
            assert_eq!(r.2["retry_after_seconds"], 1);
            // The read still holds its slot until it runs; free the thread.
            release.send(()).unwrap();
            blocker.await.unwrap();
            tokio::time::timeout(Duration::from_secs(5), async {
                while s.admission.in_flight(Lane::Interactive) != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
        });
    }

    #[tokio::test]
    async fn responses_carry_the_view_revision() {
        let (mut m, mut b) = ready_model();
        let s = state_of(&m, &Budgets::default());
        let revision = |v: &Value| serde_json::from_value::<Revision>(v["revision"].clone()).unwrap();
        let first = send(&s, req(ROOT)).await;
        assert_eq!(&revision(&first.2), m.view().revision());
        let status = send(&s, req("/v1/status")).await;
        assert_eq!(&revision(&status.2), m.view().revision());
        let before = m.view().revision().clone();
        b.deposit(0, 1, 98, "A");
        assert!(matches!(b.apply_to(&mut m), ApplyOutcome::Published { .. }));
        let after = m.view().revision().clone();
        assert_ne!(after, before);
        let r: TreeRootResponse = serde_json::from_value(send(&s, req("/v1/tree/root?chain_index=0&count=6")).await.2).unwrap();
        assert_eq!(r.revision, after);
        assert_eq!(r.chain_local_count, 6);
        let list = send(&s, req(BY_ADDRESS)).await;
        assert_eq!(revision(&list.2), after);
        assert_eq!(list.2["total"], 6);
    }
}
