//! Open-loop load generator for the Reader's internal API (plan A4).
//!
//! Requests are emitted on an exact schedule per rate: request `i` of a step is
//! due at `start + i / rate`. A request is never delayed by an earlier
//! response. Generator lag (actual send time minus scheduled time) is
//! recorded; a step whose lag p99 exceeds 5 ms, or that hit the concurrency
//! cap, is marked `invalid`. Latency is measured from the scheduled time, so a
//! slow generator cannot hide queueing (no coordinated omission).
//!
//! ```text
//! cargo run --release --example reader_bench -- \
//!   --url http://127.0.0.1:8080 --token-file token --rates 2000,5000 \
//!   --step-secs 60 --addresses-from status --out bench.json
//! ```

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use clap::Parser;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use psy_bridge_reader_api::wire::{ErrorBody, ExplorerResponse, StatusResponse};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

const LAG_P99_LIMIT_US: u64 = 5_000;
/// Response-size bucket upper bounds in bytes; the last bucket is open.
const BYTE_BUCKETS: [u64; 6] = [256, 1024, 4096, 16384, 65536, u64::MAX];
/// `by-address` list lengths (`limit`) and their weights: the seeded distribution.
const LIMIT_DIST: [(u32, u32); 4] = [(1, 40), (10, 30), (50, 20), (100, 10)];
const NULLIFIERS_PER_CLAIM: usize = 10;

#[derive(Parser, Debug)]
#[command(about = "Open-loop load generator for the Bridge Reader API")]
struct Args {
    /// Reader base URL, `http://host:port`.
    #[arg(long)]
    url: String,
    /// File holding the bearer token.
    #[arg(long)]
    token_file: String,
    /// Comma-separated request rates (req/s), run in order.
    #[arg(long, default_value = "2000,5000,10000,15000")]
    rates: String,
    #[arg(long, default_value_t = 60)]
    step_secs: u64,
    /// `A4` (70/10/10/5/5) or `by_address=70,by_tx=10,claims=10,root=5,proof=5`.
    #[arg(long, default_value = "A4")]
    mix: String,
    /// `status` (derive from /v1/status and /v1/explorer) or a JSON file
    /// `{"chain_id":..,"chain_index":..,"count":..,"addresses":[..],"tx_hashes":[..],"nullifiers":[..]}`
    /// (`nullifiers` optional).
    #[arg(long, default_value = "status")]
    addresses_from: String,
    #[arg(long)]
    out: String,
    /// Maximum in-flight requests. A request due while at the cap is counted
    /// as `cap` error and the step is marked invalid.
    #[arg(long, default_value_t = 20000)]
    concurrency_cap: usize,
    #[arg(long, default_value_t = 1)]
    seed: u64,
    #[arg(long, default_value_t = 10_000)]
    timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Dataset {
    chain_id: u64,
    chain_index: u64,
    /// Chain-local deposit count used for `tree/root` and `tree/proof`.
    count: u64,
    addresses: Vec<String>,
    tx_hashes: Vec<String>,
    #[serde(default)]
    nullifiers: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Endpoint {
    ByAddress,
    ByTx,
    Claims,
    Root,
    Proof,
}

impl Endpoint {
    const ALL: [Endpoint; 5] = [Endpoint::ByAddress, Endpoint::ByTx, Endpoint::Claims, Endpoint::Root, Endpoint::Proof];
    fn name(self) -> &'static str {
        match self {
            Endpoint::ByAddress => "by_address",
            Endpoint::ByTx => "by_tx",
            Endpoint::Claims => "withdrawal_claims",
            Endpoint::Root => "tree_root",
            Endpoint::Proof => "tree_proof",
        }
    }
    fn index(self) -> usize {
        Endpoint::ALL.iter().position(|e| *e == self).unwrap()
    }
}

fn parse_mix(s: &str) -> Result<[u32; 5], String> {
    if s == "A4" {
        return Ok([70, 10, 10, 5, 5]);
    }
    let mut w = [0u32; 5];
    for part in s.split(',') {
        let (k, v) = part.split_once('=').ok_or_else(|| format!("bad mix entry {part:?}"))?;
        let e = match k {
            "by_address" => Endpoint::ByAddress,
            "by_tx" => Endpoint::ByTx,
            "claims" => Endpoint::Claims,
            "root" => Endpoint::Root,
            "proof" => Endpoint::Proof,
            _ => return Err(format!("unknown mix endpoint {k:?}")),
        };
        w[e.index()] = v.parse().map_err(|_| format!("bad weight {v:?}"))?;
    }
    if w.iter().sum::<u32>() == 0 {
        return Err("mix weights sum to zero".into());
    }
    Ok(w)
}

// ---------------------------------------------------------------- scheduler

/// Offset of request `i` from the step start at `rate` req/s, exact to the
/// nanosecond (no accumulated rounding).
fn due_offset(rate: u64, i: u64) -> Duration {
    Duration::from_nanos((i as u128 * 1_000_000_000u128 / rate as u128) as u64)
}

/// Emits `count` requests at their due times. `emit(i, lag)` is called at (or
/// after) the due time and must not block; if the loop is behind, it emits
/// immediately without sleeping and the lag shows it.
async fn run_schedule(start: Instant, rate: u64, count: u64, mut emit: impl FnMut(u64, Duration)) {
    for i in 0..count {
        let due = start + due_offset(rate, i);
        let now = Instant::now();
        if now < due {
            tokio::time::sleep_until(due).await;
        }
        emit(i, Instant::now().saturating_duration_since(due));
    }
}

// --------------------------------------------------------------- statistics

/// Nearest-rank percentile of an ascending sample; 0 for an empty sample.
fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// One second of a step, keyed by the second the request was due in.
#[derive(Default)]
struct SecStats {
    sent: u64,
    ok: u64,
    errors: BTreeMap<String, u64>,
    latency_us: Vec<u64>,
    send_lag_us: Vec<u64>,
}

#[derive(Default)]
struct StepStats {
    sent: u64,
    ok: u64,
    /// Successful responses that completed inside the send window.
    ok_in_window: u64,
    timeouts: u64,
    errors: BTreeMap<String, u64>,
    secs: Vec<SecStats>,
    send_lag_us: Vec<u64>,
    latency_us: [Vec<u64>; 5],
    bytes_hist: [u64; 6],
    bytes_sum: [u64; 5],
    bytes_max: [u64; 5],
    lag_us: Vec<u64>,
    limits: BTreeMap<u32, u64>,
}

#[derive(Serialize)]
struct Pct {
    count: u64,
    p50_us: u64,
    p95_us: u64,
    p99_us: u64,
    max_us: u64,
}

fn pct(mut v: Vec<u64>) -> Pct {
    v.sort_unstable();
    Pct { count: v.len() as u64, p50_us: percentile(&v, 50.0), p95_us: percentile(&v, 95.0), p99_us: percentile(&v, 99.0), max_us: v.last().copied().unwrap_or(0) }
}

#[derive(Serialize)]
struct EndpointReport {
    latency: Pct,
    mean_response_bytes: u64,
    max_response_bytes: u64,
}

#[derive(Serialize)]
struct SecReport {
    second: usize,
    sent: u64,
    ok: u64,
    errors: BTreeMap<String, u64>,
    latency_p50_us: u64,
    latency_p99_us: u64,
    send_lag_p99_us: u64,
}

#[derive(Serialize)]
struct StepReport {
    rate: u64,
    step_secs: u64,
    sent: u64,
    ok: u64,
    /// Requests that hit `--timeout-ms`; also counted under `errors["timeout"]`.
    timeouts: u64,
    errors: BTreeMap<String, u64>,
    /// Successful responses completed inside the send window / window length.
    throughput_ok_per_s: f64,
    peak_inflight: u64,
    per_second: Vec<SecReport>,
    endpoints: BTreeMap<&'static str, EndpointReport>,
    /// Count of responses per size bucket, keyed by upper bound in bytes.
    response_bytes_hist: BTreeMap<String, u64>,
    /// `by-address` requests sent per `limit` (list-length distribution).
    by_address_limit_counts: BTreeMap<u32, u64>,
    generator_cpu_seconds: f64,
    generator_cpu_cores: f64,
    /// Actual send (just before `client.request`) minus due time. Gates `valid`.
    send_lag: Pct,
    /// Scheduler emit time minus due time (before the request task starts).
    emit_lag: Pct,
    valid: bool,
    invalid_reasons: Vec<String>,
}

fn build_report(rate: u64, step_secs: u64, window: Duration, cpu_seconds: f64, peak_inflight: u64, mut st: StepStats) -> StepReport {
    let mut endpoints = BTreeMap::new();
    for e in Endpoint::ALL {
        let i = e.index();
        let n = st.latency_us[i].len() as u64;
        endpoints.insert(
            e.name(),
            EndpointReport {
                latency: pct(st.latency_us[i].clone()),
                mean_response_bytes: if n == 0 { 0 } else { st.bytes_sum[i] / n },
                max_response_bytes: st.bytes_max[i],
            },
        );
    }
    let mut hist = BTreeMap::new();
    for (i, c) in st.bytes_hist.iter().enumerate() {
        let key = if BYTE_BUCKETS[i] == u64::MAX { "inf".to_owned() } else { format!("le_{}", BYTE_BUCKETS[i]) };
        hist.insert(key, *c);
    }
    let emit_lag = pct(std::mem::take(&mut st.lag_us));
    let send_lag = pct(std::mem::take(&mut st.send_lag_us));
    let per_second = std::mem::take(&mut st.secs)
        .into_iter()
        .enumerate()
        .map(|(second, mut sec)| {
            sec.latency_us.sort_unstable();
            sec.send_lag_us.sort_unstable();
            SecReport {
                second,
                sent: sec.sent,
                ok: sec.ok,
                errors: sec.errors,
                latency_p50_us: percentile(&sec.latency_us, 50.0),
                latency_p99_us: percentile(&sec.latency_us, 99.0),
                send_lag_p99_us: percentile(&sec.send_lag_us, 99.0),
            }
        })
        .collect();
    let mut reasons = Vec::new();
    if send_lag.p99_us > LAG_P99_LIMIT_US {
        reasons.push(format!("send lag p99 {} us exceeds {} us", send_lag.p99_us, LAG_P99_LIMIT_US));
    }
    if emit_lag.p99_us > LAG_P99_LIMIT_US {
        reasons.push(format!("emit lag p99 {} us exceeds {} us", emit_lag.p99_us, LAG_P99_LIMIT_US));
    }
    if let Some(c) = st.errors.get("cap") {
        reasons.push(format!("{c} requests hit the concurrency cap"));
    }
    let secs = window.as_secs_f64().max(1e-9);
    StepReport {
        rate,
        step_secs,
        sent: st.sent,
        ok: st.ok,
        errors: st.errors,
        timeouts: st.timeouts,
        throughput_ok_per_s: st.ok_in_window as f64 / secs,
        peak_inflight,
        per_second,
        endpoints,
        response_bytes_hist: hist,
        by_address_limit_counts: st.limits,
        generator_cpu_seconds: cpu_seconds,
        generator_cpu_cores: cpu_seconds / secs,
        send_lag,
        emit_lag,
        valid: reasons.is_empty(),
        invalid_reasons: reasons,
    }
}

/// utime + stime of this process in seconds, from /proc/self/stat.
fn process_cpu_seconds() -> f64 {
    let Ok(s) = std::fs::read_to_string("/proc/self/stat") else { return 0.0 };
    // The command name may contain spaces; fields resume after the last ')'.
    let Some(rest) = s.rsplit_once(')').map(|(_, r)| r) else { return 0.0 };
    let f: Vec<&str> = rest.split_whitespace().collect();
    // After ')' the fields start at 3 (state): utime is 14, stime 15.
    let (Some(u), Some(t)) = (f.get(11), f.get(12)) else { return 0.0 };
    let ticks = (u.parse::<u64>().unwrap_or(0) + t.parse::<u64>().unwrap_or(0)) as f64;
    ticks / clock_ticks_per_sec()
}

fn clock_ticks_per_sec() -> f64 {
    // Linux USER_HZ is 100 on every supported platform.
    100.0
}

// ------------------------------------------------------------------ requests

struct Spec {
    endpoint: Endpoint,
    method: Method,
    uri: String,
    body: Option<String>,
}

fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

struct Picker {
    base: String,
    data: Dataset,
    weights: [u32; 5],
    total: u32,
    rng: StdRng,
}

impl Picker {
    fn new(base: &str, data: Dataset, weights: [u32; 5], seed: u64) -> Self {
        Picker { base: base.trim_end_matches('/').to_owned(), data, weights, total: weights.iter().sum(), rng: StdRng::seed_from_u64(seed) }
    }

    fn next(&mut self) -> (Spec, Option<u32>) {
        let mut x = self.rng.gen_range(0..self.total);
        let mut endpoint = Endpoint::ByAddress;
        for e in Endpoint::ALL {
            let w = self.weights[e.index()];
            if x < w {
                endpoint = e;
                break;
            }
            x -= w;
        }
        let d = self.data.clone_meta();
        let mut limit = None;
        let (method, path, body) = match endpoint {
            Endpoint::ByAddress => {
                let l = self.draw_limit();
                limit = Some(l);
                let a = self.data.addresses[self.rng.gen_range(0..self.data.addresses.len())].clone();
                (Method::GET, format!("/v1/deposits/by-address?shield_address={}&chain_id={}&limit={}&offset=0", encode(&a), d.0, l), None)
            }
            Endpoint::ByTx => {
                let t = self.data.tx_hashes[self.rng.gen_range(0..self.data.tx_hashes.len())].clone();
                (Method::GET, format!("/v1/deposits/by-tx?tx_hash={}&chain_index={}", encode(&t), d.1), None)
            }
            Endpoint::Claims => {
                let len = self.data.nullifiers.len();
                let ns: Vec<String> = (0..NULLIFIERS_PER_CLAIM).map(|_| self.data.nullifiers[self.rng.gen_range(0..len)].clone()).collect();
                let body = serde_json::json!({ "chain_id": d.0, "nullifiers": ns }).to_string();
                (Method::POST, "/v1/withdrawal-claims".to_owned(), Some(body))
            }
            Endpoint::Root => (Method::GET, format!("/v1/tree/root?chain_index={}&count={}", d.1, d.2), None),
            Endpoint::Proof => {
                let leaf = self.rng.gen_range(0..d.2.max(1));
                (Method::GET, format!("/v1/tree/proof?chain_index={}&leaf={}&count={}", d.1, leaf, d.2), None)
            }
        };
        (Spec { endpoint, method, uri: format!("{}{}", self.base, path), body }, limit)
    }

    fn draw_limit(&mut self) -> u32 {
        let total: u32 = LIMIT_DIST.iter().map(|(_, w)| w).sum();
        let mut x = self.rng.gen_range(0..total);
        for (l, w) in LIMIT_DIST {
            if x < w {
                return l;
            }
            x -= w;
        }
        LIMIT_DIST[0].0
    }
}

impl Dataset {
    fn clone_meta(&self) -> (u64, u64, u64) {
        (self.chain_id, self.chain_index, self.count)
    }
}

type HttpClient = Client<HttpConnector, Full<Bytes>>;

struct Shared {
    client: HttpClient,
    token: String,
    timeout: Duration,
    stats: Mutex<StepStats>,
    inflight: AtomicUsize,
    peak_inflight: AtomicU64,
    /// Set once the send window has closed (completions after it are drain).
    draining: std::sync::atomic::AtomicBool,
}

async fn do_request(sh: Arc<Shared>, spec: Spec, due: Instant, sec: usize) {
    let mut req = Request::builder().method(spec.method).uri(&spec.uri).header("authorization", format!("Bearer {}", sh.token));
    let body = match spec.body {
        Some(b) => {
            req = req.header("content-type", "application/json");
            Full::new(Bytes::from(b))
        }
        None => Full::new(Bytes::new()),
    };
    let mut send_at: Option<Instant> = None;
    let outcome: Result<(u16, Bytes), String> = match req.body(body) {
        Err(e) => Err(format!("transport:build:{e}")),
        Ok(req) => {
            let fut = async {
                send_at = Some(Instant::now());
                let resp = sh.client.request(req).await.map_err(|e| format!("transport:{}", short_err(&e)))?;
                let status = resp.status().as_u16();
                let bytes = resp.into_body().collect().await.map_err(|_| "transport:body".to_owned())?.to_bytes();
                Ok((status, bytes))
            };
            match tokio::time::timeout(sh.timeout, fut).await {
                Ok(r) => r,
                Err(_) => Err("timeout".to_owned()),
            }
        }
    };
    let done = Instant::now();
    let elapsed_us = done.saturating_duration_since(due).as_micros() as u64;
    let send_lag_us = send_at.map(|t| t.saturating_duration_since(due).as_micros() as u64);
    let in_window = !sh.draining.load(Ordering::Relaxed);
    {
        let mut st = sh.stats.lock().unwrap();
        if let Some(l) = send_lag_us {
            st.send_lag_us.push(l);
            st.secs[sec].send_lag_us.push(l);
        }
        match outcome {
            Ok((status, bytes)) if status == 200 => {
                st.ok += 1;
                st.ok_in_window += in_window as u64;
                st.secs[sec].ok += 1;
                st.secs[sec].latency_us.push(elapsed_us);
                record_bytes(&mut st, spec.endpoint, bytes.len() as u64);
                st.latency_us[spec.endpoint.index()].push(elapsed_us);
            }
            Ok((status, bytes)) => {
                let code = serde_json::from_slice::<ErrorBody>(&bytes).map(|b| b.code.as_str().to_owned()).unwrap_or_else(|_| "unparsed".to_owned());
                let key = format!("{status}:{code}");
                *st.secs[sec].errors.entry(key.clone()).or_default() += 1;
                *st.errors.entry(key).or_default() += 1;
            }
            Err(kind) => {
                if kind == "timeout" {
                    st.timeouts += 1;
                }
                *st.secs[sec].errors.entry(kind.clone()).or_default() += 1;
                *st.errors.entry(kind).or_default() += 1;
            }
        }
    }
    sh.inflight.fetch_sub(1, Ordering::Relaxed);
}

fn short_err(e: &hyper_util::client::legacy::Error) -> &'static str {
    if e.is_connect() {
        "connect"
    } else {
        "request"
    }
}

fn record_bytes(st: &mut StepStats, e: Endpoint, n: u64) {
    let b = BYTE_BUCKETS.iter().position(|ub| n <= *ub).unwrap();
    st.bytes_hist[b] += 1;
    st.bytes_sum[e.index()] += n;
    st.bytes_max[e.index()] = st.bytes_max[e.index()].max(n);
}

// --------------------------------------------------------------------- main

async fn get_json<T: serde::de::DeserializeOwned>(sh: &Shared, base: &str, path: &str) -> Result<T, String> {
    let req = Request::get(format!("{}{}", base.trim_end_matches('/'), path))
        .header("authorization", format!("Bearer {}", sh.token))
        .body(Full::new(Bytes::new()))
        .map_err(|e| e.to_string())?;
    let resp = sh.client.request(req).await.map_err(|e| format!("{path}: {e}"))?;
    let status = resp.status();
    let bytes = resp.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
    if !status.is_success() {
        return Err(format!("{path}: HTTP {status}"));
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))
}

async fn load_dataset(sh: &Shared, base: &str, from: &str) -> Result<Dataset, String> {
    let mut d: Dataset = if from == "status" {
        let status: StatusResponse = get_json(sh, base, "/v1/status").await?;
        let chain = status.chains.iter().find(|c| c.ready).or(status.chains.first()).ok_or("status lists no chains")?;
        let explorer: ExplorerResponse = get_json(sh, base, &format!("/v1/explorer?chain_id={}", chain.chain_id)).await?;
        let mut addresses: Vec<String> = explorer.deposits.iter().map(|r| r.shield_address.clone()).collect();
        let mut tx_hashes: Vec<String> = explorer.deposits.iter().map(|r| r.tx_hash.clone()).collect();
        addresses.sort();
        addresses.dedup();
        tx_hashes.sort();
        tx_hashes.dedup();
        Dataset { chain_id: chain.chain_id, chain_index: chain.chain_index, count: chain.committed_count, addresses, tx_hashes, nullifiers: vec![] }
    } else {
        let text = std::fs::read_to_string(from).map_err(|e| format!("{from}: {e}"))?;
        serde_json::from_str(&text).map_err(|e| format!("{from}: {e}"))?
    };
    if d.addresses.is_empty() || d.tx_hashes.is_empty() {
        return Err("dataset has no addresses or tx hashes (the Reader has no deposits yet?)".into());
    }
    if d.nullifiers.is_empty() {
        // Claims for unknown nullifiers are valid reads that return no rows.
        d.nullifiers = (0..1000).map(|i| format!("0x{:064x}", 0xb3_c000_0000u64 + i)).collect();
    }
    Ok(d)
}

async fn run_step(sh: &Arc<Shared>, picker: &mut Picker, rate: u64, step_secs: u64, cap: usize) -> StepReport {
    {
        let mut st = sh.stats.lock().unwrap();
        *st = StepStats::default();
        st.secs = (0..step_secs).map(|_| SecStats::default()).collect();
    }
    sh.draining.store(false, Ordering::Relaxed);
    sh.peak_inflight.store(0, Ordering::Relaxed);
    let count = rate * step_secs;
    let start = Instant::now() + Duration::from_millis(50);
    let cpu0 = process_cpu_seconds();
    let mut cpu_start = cpu0;
    let mut sent = 0u64;
    let mut limits: BTreeMap<u32, u64> = BTreeMap::new();
    let mut lags: Vec<u64> = Vec::with_capacity(count as usize);
    let mut capped = 0u64;
    let mut sec_sent = vec![0u64; step_secs as usize];
    let mut sec_capped = vec![0u64; step_secs as usize];
    run_schedule(start, rate, count, |i, lag| {
        if i == 0 {
            cpu_start = process_cpu_seconds();
        }
        lags.push(lag.as_micros() as u64);
        let (spec, limit) = picker.next();
        if let Some(l) = limit {
            *limits.entry(l).or_default() += 1;
        }
        sent += 1;
        let sec = ((i / rate) as usize).min(step_secs as usize - 1);
        sec_sent[sec] += 1;
        let due = start + due_offset(rate, i);
        if sh.inflight.load(Ordering::Relaxed) >= cap {
            capped += 1;
            sec_capped[sec] += 1;
            return;
        }
        let now = sh.inflight.fetch_add(1, Ordering::Relaxed) as u64 + 1;
        sh.peak_inflight.fetch_max(now, Ordering::Relaxed);
        tokio::spawn(do_request(sh.clone(), spec, due, sec));
    })
    .await;
    // Window closes here: CPU and throughput cover the same interval.
    sh.draining.store(true, Ordering::Relaxed);
    let window = Instant::now().saturating_duration_since(start);
    let cpu = process_cpu_seconds() - cpu_start;
    let peak = sh.peak_inflight.load(Ordering::Relaxed);
    // Drain in-flight requests (bounded by the request timeout).
    let drain_until = Instant::now() + sh.timeout + Duration::from_secs(1);
    while sh.inflight.load(Ordering::Relaxed) > 0 && Instant::now() < drain_until {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut st = std::mem::take(&mut *sh.stats.lock().unwrap());
    st.sent = sent;
    st.lag_us = lags;
    st.limits = limits;
    for (i, sec) in st.secs.iter_mut().enumerate() {
        sec.sent = sec_sent[i];
        if sec_capped[i] > 0 {
            sec.errors.insert("cap".to_owned(), sec_capped[i]);
        }
    }
    if capped > 0 {
        st.errors.insert("cap".to_owned(), capped);
    }
    build_report(rate, step_secs, window, cpu, peak, st)
}

/// Raises the soft open-files limit to the hard limit; returns the new soft limit.
fn raise_nofile() -> u64 {
    // SAFETY: plain getrlimit/setrlimit calls on a local struct.
    unsafe {
        let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 0;
        }
        if lim.rlim_cur < lim.rlim_max {
            let want = libc::rlimit { rlim_cur: lim.rlim_max, rlim_max: lim.rlim_max };
            if libc::setrlimit(libc::RLIMIT_NOFILE, &want) == 0 {
                lim.rlim_cur = lim.rlim_max;
            }
        }
        lim.rlim_cur as u64
    }
}

fn git_sha() -> Option<String> {
    let out = std::process::Command::new("git").args(["rev-parse", "--short=12", "HEAD"]).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args = Args::parse();
    if let Err(e) = real_main(args).await {
        eprintln!("reader_bench: {e}");
        std::process::exit(1);
    }
}

async fn real_main(args: Args) -> Result<(), String> {
    let weights = parse_mix(&args.mix)?;
    let rates: Vec<u64> = args.rates.split(',').map(|r| r.trim().parse::<u64>().map_err(|_| format!("bad rate {r:?}"))).collect::<Result<_, _>>()?;
    if rates.iter().any(|r| *r == 0) {
        return Err("rates must be positive".into());
    }
    let token = std::fs::read_to_string(&args.token_file).map_err(|e| format!("{}: {e}", args.token_file))?.trim().to_owned();
    let mut connector = HttpConnector::new();
    connector.set_nodelay(true);
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    let client: HttpClient = Client::builder(TokioExecutor::new()).pool_max_idle_per_host(args.concurrency_cap).build(connector);
    let sh = Arc::new(Shared {
        client,
        token,
        timeout: Duration::from_millis(args.timeout_ms),
        stats: Mutex::new(StepStats::default()),
        inflight: AtomicUsize::new(0),
        peak_inflight: AtomicU64::new(0),
        draining: std::sync::atomic::AtomicBool::new(false),
    });
    let nofile = raise_nofile();
    if nofile < 4 * args.concurrency_cap as u64 {
        eprintln!("warning: open-files limit {nofile} is below 4x --concurrency-cap {}; expect connect errors", args.concurrency_cap);
    }
    let started_unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let data = load_dataset(&sh, &args.url, &args.addresses_from).await?;
    eprintln!(
        "dataset: chain_id={} chain_index={} count={} addresses={} tx_hashes={} nullifiers={}",
        data.chain_id,
        data.chain_index,
        data.count,
        data.addresses.len(),
        data.tx_hashes.len(),
        data.nullifiers.len()
    );
    let mut picker = Picker::new(&args.url, data.clone(), weights, args.seed);
    let mut steps = Vec::new();
    for rate in rates {
        eprintln!("step: {rate} req/s for {} s", args.step_secs);
        let report = run_step(&sh, &mut picker, rate, args.step_secs, args.concurrency_cap).await;
        eprintln!(
            "  sent={} ok={} errors={:?} throughput={:.0}/s send_lag_p99={}us valid={}",
            report.sent, report.ok, report.errors, report.throughput_ok_per_s, report.send_lag.p99_us, report.valid
        );
        steps.push(report);
        let out = serde_json::json!({
            "config": {
                "url": args.url,
                "concurrency_cap": args.concurrency_cap,
                "timeout_ms": args.timeout_ms,
                "step_secs": args.step_secs,
                "rates": args.rates,
                "started_unix": started_unix,
                "git_sha": git_sha(),
                "nofile_soft_limit": nofile,
            },
            "mix": args.mix,
            "seed": args.seed,
            "dataset": { "chain_id": data.chain_id, "chain_index": data.chain_index, "count": data.count, "addresses": data.addresses.len(), "tx_hashes": data.tx_hashes.len() },
            "by_address_limit_weights": LIMIT_DIST.iter().map(|(l, w)| (l.to_string(), *w)).collect::<BTreeMap<_, _>>(),
            "steps": steps,
        });
        std::fs::write(&args.out, serde_json::to_vec_pretty(&out).unwrap()).map_err(|e| format!("{}: {e}", args.out))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn open_loop_schedule_is_exact() {
        let start = Instant::now() + Duration::from_millis(7);
        let rate = 3000; // 333_333.33 ns apart: rounding must not accumulate
        let n = 6000u64;
        let mut seen: Vec<(Instant, Duration)> = Vec::new();
        run_schedule(start, rate, n, |_, lag| seen.push((Instant::now(), lag))).await;
        assert_eq!(seen.len() as u64, n);
        for (i, (at, lag)) in seen.iter().enumerate() {
            let due = start + due_offset(rate, i as u64);
            // Never early; late only by the 1 ms timer granularity, and the
            // reported lag is exactly that difference (no drift).
            assert!(*at >= due, "request {i} sent early");
            assert_eq!(*lag, *at - due);
            assert!(*lag <= Duration::from_millis(1), "request {i} lag {lag:?}");
        }
        // Exactly `rate` requests per second.
        assert_eq!(due_offset(rate, rate), Duration::from_secs(1));
        assert!(due_offset(rate, n - 1) < Duration::from_secs(2));
        let last = seen.last().unwrap().0;
        assert!(last - start < Duration::from_millis(2001));
    }

    #[tokio::test(start_paused = true)]
    async fn a_generator_that_is_behind_catches_up_and_reports_lag() {
        // Started 1 s late at 100 req/s: the first 100 are already due.
        let t0 = Instant::now();
        let start = t0 - Duration::from_secs(1);
        let mut lags = Vec::new();
        run_schedule(start, 100, 101, |_, lag| lags.push(lag)).await;
        assert_eq!(Instant::now(), t0, "behind-schedule requests must not sleep");
        assert_eq!(lags[0], Duration::from_secs(1));
        assert_eq!(lags[99], Duration::from_millis(10));
        assert_eq!(lags[100], Duration::ZERO);
    }

    #[test]
    fn percentiles_match_a_known_sample() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 50.0), 50);
        assert_eq!(percentile(&v, 95.0), 95);
        assert_eq!(percentile(&v, 99.0), 99);
        assert_eq!(percentile(&v, 100.0), 100);
        assert_eq!(percentile(&[7], 99.0), 7);
        assert_eq!(percentile(&[], 50.0), 0);
        let p = pct((1..=100).rev().collect());
        assert_eq!((p.count, p.p50_us, p.p99_us, p.max_us), (100, 50, 99, 100));
    }

    #[test]
    fn send_lag_gates_validity_and_seconds_are_reported() {
        let mk = |send_lag: u64| {
            let mut st = StepStats::default();
            st.secs = (0..2).map(|_| SecStats::default()).collect();
            for i in 0..100u64 {
                let sec = (i / 50) as usize;
                st.sent += 1;
                st.ok += 1;
                st.ok_in_window += 1;
                st.secs[sec].sent += 1;
                st.secs[sec].ok += 1;
                st.secs[sec].latency_us.push(i + 1);
                st.secs[sec].send_lag_us.push(send_lag);
                st.send_lag_us.push(send_lag);
                st.lag_us.push(0);
            }
            build_report(50, 2, Duration::from_secs(2), 0.5, 7, st)
        };
        let good = mk(100);
        assert!(good.valid && good.per_second.len() == 2);
        assert_eq!((good.per_second[1].sent, good.per_second[1].latency_p99_us, good.peak_inflight), (50, 100, 7));
        assert!((good.throughput_ok_per_s - 50.0).abs() < 1e-9);
        let bad = mk(LAG_P99_LIMIT_US + 1);
        assert!(!bad.valid && bad.invalid_reasons[0].contains("send lag"));
    }

    #[test]
    fn mix_parses_and_picks_by_weight() {
        assert_eq!(parse_mix("A4").unwrap(), [70, 10, 10, 5, 5]);
        assert!(parse_mix("nope=1").is_err());
        let data = Dataset { chain_id: 1, chain_index: 0, count: 10, addresses: vec!["0xa".into()], tx_hashes: vec!["0xt".into()], nullifiers: vec!["0xn".into()] };
        let mut p = Picker::new("http://h:1/", data, [70, 10, 10, 5, 5], 7);
        let mut counts = [0u32; 5];
        for _ in 0..20_000 {
            counts[p.next().0.endpoint.index()] += 1;
        }
        for (c, w) in counts.iter().zip([70.0, 10.0, 10.0, 5.0, 5.0]) {
            assert!((*c as f64 / 200.0 - w).abs() < 1.5, "{counts:?}");
        }
        let (claims, _) = loop {
            let s = p.next();
            if s.0.endpoint == Endpoint::Claims {
                break s;
            }
        };
        assert_eq!(claims.method, Method::POST);
        let b: serde_json::Value = serde_json::from_str(&claims.body.unwrap()).unwrap();
        assert_eq!(b["nullifiers"].as_array().unwrap().len(), NULLIFIERS_PER_CLAIM);
    }
}
