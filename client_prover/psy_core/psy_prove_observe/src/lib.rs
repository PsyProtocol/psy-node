//! Opt-in native prover diagnostics. No payloads and no changes to admission or
//! execution. Request futures and blocking jobs have independent lifetimes.
//! Snapshots never wait on application locks; full diagnostics buffers drop
//! records instead of blocking proof work.

mod transport;
mod writer;
use std::{
    cell::RefCell,
    future::Future,
    path::PathBuf,
    sync::{
        atomic::{
            AtomicBool, AtomicU64,
            Ordering::{Relaxed, SeqCst},
        },
        mpsc::{sync_channel, SyncSender},
        Arc, Mutex, Weak,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::{json, Value};
use tracing::Instrument;
pub use transport::{HttpLayer, RpcObserver};

/// Only fixed stage names can be emitted; never use user data as metric labels.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[repr(usize)]
pub enum Stage {
    Http,
    Rpc,
    Upstream,
    Register,
    Resolve,
    CacheLookup,
    CacheWait,
    CircuitBuild,
    ExecutorQueue,
    Proof,
    Witness,
    WiresCommit,
    PartialProducts,
    ZsCommit,
    Quotient,
    QuotientCommit,
    Openings,
    Fri,
    LargeProofWait,
    LargeProofHeld,
    GpuBufferWait,
    GpuLaneWait,
    GpuLaneHeld,
    GpuDevice,
    GpuRebuild,
    GpuQuotientWait,
    GpuFriWait,
    ResponseReady,
}
const STAGES: usize = Stage::ResponseReady as usize + 1;
const BUCKETS_MS: [u64; 8] = [1, 10, 100, 1_000, 5_000, 30_000, 120_000, u64::MAX];

#[derive(Clone, Debug)]
pub struct Config {
    pub directory: PathBuf,
    pub capacity: usize,
    pub event_capacity: usize,
    pub file_bytes: u64,
    pub files: usize,
    pub slow_ms: u64,
}
impl Config {
    pub fn from_env() -> Result<Option<Self>, String> {
        let Some(directory) = std::env::var_os("PSY_PROVE_OBSERVE_DIR") else {
            return Ok(None);
        };
        if directory.is_empty() {
            return Err("PSY_PROVE_OBSERVE_DIR is empty".into());
        }
        Ok(Some(Self {
            directory: directory.into(),
            capacity: 1024,
            event_capacity: 4096,
            file_bytes: 16 * 1024 * 1024,
            files: 4,
            slow_ms: 1000,
        }))
    }
}

struct Inner {
    start: Instant,
    instance: String,
    next: AtomicU64,
    slots: Vec<Mutex<Weak<Entry>>>,
    cursor: AtomicU64,
    dropped: AtomicU64,
    overflow: AtomicU64,
    snapshot_skipped: AtomicU64,
    state_skipped: AtomicU64,
    writer_errors: Arc<AtomicU64>,
    heartbeat_ms: AtomicU64,
    heartbeat_lag_ms: AtomicU64,
    heartbeat_seen: AtomicBool,
    stop: AtomicBool,
    tx: SyncSender<Value>,
    slow_ms: u64,
    // Fixed stage dimensions, cumulative non-overlapping histogram buckets.
    hist: [[AtomicU64; 8]; STAGES],
}

#[derive(Clone)]
pub struct Observer(Option<Arc<Inner>>);

#[derive(Clone, Debug, Serialize)]
struct State {
    stage: Stage,
    since_ms: u64,
    cache_key: Option<u64>,
}

// Single logical activity writer. Atomic fields + versioning allow the watchdog
// to take a bounded consistent snapshot without ever delaying a stage update.
// Concurrent writers are an instrumentation misuse, counted rather than waited
// on.
struct AtomicState {
    version: AtomicU64,
    stage: AtomicU64,
    since_ms: AtomicU64,
    key: AtomicU64,
    has_key: AtomicBool,
}
const STAGE_NAMES: [Stage; STAGES] = [
    Stage::Http,
    Stage::Rpc,
    Stage::Upstream,
    Stage::Register,
    Stage::Resolve,
    Stage::CacheLookup,
    Stage::CacheWait,
    Stage::CircuitBuild,
    Stage::ExecutorQueue,
    Stage::Proof,
    Stage::Witness,
    Stage::WiresCommit,
    Stage::PartialProducts,
    Stage::ZsCommit,
    Stage::Quotient,
    Stage::QuotientCommit,
    Stage::Openings,
    Stage::Fri,
    Stage::LargeProofWait,
    Stage::LargeProofHeld,
    Stage::GpuBufferWait,
    Stage::GpuLaneWait,
    Stage::GpuLaneHeld,
    Stage::GpuDevice,
    Stage::GpuRebuild,
    Stage::GpuQuotientWait,
    Stage::GpuFriWait,
    Stage::ResponseReady,
];
impl AtomicState {
    fn new(s: State) -> Self {
        Self {
            version: AtomicU64::new(0),
            stage: AtomicU64::new(s.stage as u64),
            since_ms: AtomicU64::new(s.since_ms),
            key: AtomicU64::new(s.cache_key.unwrap_or(0)),
            has_key: AtomicBool::new(s.cache_key.is_some()),
        }
    }
    fn fields(&self) -> State {
        State {
            stage: STAGE_NAMES[self.stage.load(SeqCst) as usize],
            since_ms: self.since_ms.load(SeqCst),
            cache_key: self.has_key.load(SeqCst).then(|| self.key.load(SeqCst)),
        }
    }
    fn read(&self) -> Option<State> {
        for _ in 0..3 {
            let v = self.version.load(SeqCst);
            if v % 2 != 0 {
                continue;
            }
            let s = self.fields();
            if self.version.load(SeqCst) == v {
                return Some(s);
            }
        }
        None
    }
    fn replace(&self, s: State) -> Option<State> {
        let v = self.version.load(SeqCst);
        if v % 2 != 0 || self.version.compare_exchange(v, v.wrapping_add(1), SeqCst, SeqCst).is_err() {
            return None;
        }
        let previous = self.fields();
        self.stage.store(s.stage as u64, SeqCst);
        self.since_ms.store(s.since_ms, SeqCst);
        self.key.store(s.cache_key.unwrap_or(0), SeqCst);
        self.has_key.store(s.cache_key.is_some(), SeqCst);
        self.version.store(v.wrapping_add(2), SeqCst);
        Some(previous)
    }
}

struct Entry {
    observer: Arc<Inner>,
    id: u64,
    parent_id: Option<u64>,
    request_id: String,
    method: String,
    kind: &'static str,
    started_ms: u64,
    state: AtomicState,
    finished: AtomicBool,
    // Means the RPC waiter disappeared, NOT that the GPU/CPU job was aborted.
    rpc_waiter_gone: Arc<AtomicBool>,
}

#[derive(Clone)]
pub struct Context(Option<Arc<Entry>>);
pub struct Activity {
    context: Context,
    outcome: &'static str,
}

tokio::task_local! { static TASK: Context; }
thread_local! { static BLOCKING: RefCell<Option<Context>> = const { RefCell::new(None) }; }

impl Inner {
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn emit(&self, value: Value) {
        if self.tx.try_send(value).is_err() {
            self.dropped.fetch_add(1, Relaxed);
        }
    }
}

impl Observer {
    pub fn disabled() -> Self {
        Self(None)
    }
    pub fn start(config: Config, role: &str, build: &str) -> std::io::Result<Self> {
        if !(1..=16384).contains(&config.capacity)
            || !(1..=65536).contains(&config.event_capacity)
            || !(1024..=256 * 1024 * 1024).contains(&config.file_bytes)
            || !(1..=16).contains(&config.files)
        {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid diagnostic limits"));
        }
        let (tx, rx) = sync_channel(config.event_capacity);
        let writer_errors = Arc::new(AtomicU64::new(0));
        writer::start(&config, rx, writer_errors.clone())?;
        let epoch = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos();
        let inner = Arc::new(Inner {
            start: Instant::now(),
            instance: format!("{:x}-{epoch:x}", std::process::id()),
            next: AtomicU64::new(1),
            slots: (0..config.capacity).map(|_| Mutex::new(Weak::new())).collect(),
            cursor: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            overflow: AtomicU64::new(0),
            snapshot_skipped: AtomicU64::new(0),
            state_skipped: AtomicU64::new(0),
            writer_errors,
            heartbeat_ms: AtomicU64::new(0),
            heartbeat_lag_ms: AtomicU64::new(0),
            heartbeat_seen: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            tx,
            slow_ms: config.slow_ms,
            hist: std::array::from_fn(|_| std::array::from_fn(|_| AtomicU64::new(0))),
        });
        let observer = Self(Some(inner.clone()));
        inner.emit(json!({"event":"observer_start", "instance":inner.instance,
            "role": bounded_name(role), "build": bounded_name(build), "capacity":config.capacity,
            "max_log_bytes":config.file_bytes * config.files as u64,
            "epoch_ms":epoch / 1_000_000}));
        let weak = Arc::downgrade(&inner);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                let scheduled = tick.tick().await;
                let Some(inner) = weak.upgrade() else { break };
                if inner.stop.load(Relaxed) {
                    break;
                }
                inner.heartbeat_lag_ms.store(scheduled.elapsed().as_millis() as u64, Relaxed);
                inner.heartbeat_ms.store(inner.now_ms(), Relaxed);
                inner.heartbeat_seen.store(true, Relaxed);
            }
        });
        let weak = Arc::downgrade(&inner);
        std::thread::Builder::new().name("prove-watchdog".into()).spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let Some(inner) = weak.upgrade() else { break };
            if inner.stop.load(Relaxed) {
                break;
            }
            let observer = Observer(Some(inner.clone()));
            // Use our own bounded writer, never the application's tracing subscriber.
            let mut snapshot = observer.snapshot();
            let active = snapshot["active"].as_array_mut().expect("snapshot array");
            active.truncate(16);
            inner.emit(snapshot);
        })?;
        Ok(observer)
    }

    pub fn stop(&self) {
        if let Some(i) = &self.0 {
            i.stop.store(true, Relaxed);
        }
    }

    pub fn request_id(&self, supplied: Option<&str>) -> String {
        if let Some(s) = supplied.filter(|s| s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())) {
            return s.to_ascii_lowercase();
        }
        self.0
            .as_ref()
            .map_or_else(|| "disabled".into(), |i| format!("{}-{:x}", i.instance, i.next.fetch_add(1, Relaxed)))
    }

    pub fn activity(&self, kind: &'static str, request_id: &str, method: &str, stage: Stage) -> Activity {
        self.create(kind, request_id, method, stage, None, Arc::new(AtomicBool::new(false)))
    }
    fn create(
        &self,
        kind: &'static str,
        request_id: &str,
        method: &str,
        stage: Stage,
        parent_id: Option<u64>,
        rpc_waiter_gone: Arc<AtomicBool>,
    ) -> Activity {
        let Some(inner) = &self.0 else {
            return Activity {
                context: Context(None),
                outcome: "future_dropped",
            };
        };
        let now = inner.now_ms();
        let entry = Arc::new(Entry {
            observer: inner.clone(),
            id: inner.next.fetch_add(1, Relaxed),
            parent_id,
            request_id: bounded_name(request_id),
            method: bounded_name(method),
            kind,
            started_ms: now,
            state: AtomicState::new(State {
                stage,
                since_ms: now,
                cache_key: None,
            }),
            finished: AtomicBool::new(false),
            rpc_waiter_gone,
        });
        let start = inner.cursor.fetch_add(1, Relaxed) as usize;
        let mut registered = false;
        for offset in 0..inner.slots.len() {
            if let Ok(mut slot) = inner.slots[(start.wrapping_add(offset)) % inner.slots.len()].try_lock() {
                if slot.upgrade().is_none_or(|e| e.finished.load(Relaxed)) {
                    *slot = Arc::downgrade(&entry);
                    registered = true;
                    break;
                }
            }
        }
        if !registered {
            inner.overflow.fetch_add(1, Relaxed);
            // Observability must not reject or delay real requests. Bound tracker memory.
            return Activity {
                context: Context(None),
                outcome: "future_dropped",
            };
        }
        entry.event("begin", json!({"stage":stage}));
        Activity {
            context: Context(Some(entry)),
            outcome: "future_dropped",
        }
    }

    pub fn snapshot(&self) -> Value {
        let Some(inner) = &self.0 else {
            return json!({"event":"watchdog", "active":[]});
        };
        let now = inner.now_ms();
        let mut entries = Vec::new();
        for slot in &inner.slots {
            let Ok(slot) = slot.try_lock() else {
                inner.snapshot_skipped.fetch_add(1, Relaxed);
                continue;
            };
            let Some(entry) = slot.upgrade() else { continue };
            if entry.finished.load(Relaxed) {
                continue;
            }
            let Some(state) = entry.state.read() else {
                inner.snapshot_skipped.fetch_add(1, Relaxed);
                continue;
            };
            entries.push(json!({"id":entry.id, "parent_id":entry.parent_id, "request_id":entry.request_id,
                "kind":entry.kind, "method":entry.method, "stage":state.stage, "cache_key":state.cache_key,
                "stage_ms":now.saturating_sub(state.since_ms), "age_ms":now.saturating_sub(entry.started_ms),
                "rpc_waiter_gone":entry.rpc_waiter_gone.load(Relaxed)}));
        }
        entries.sort_by_key(|v| std::cmp::Reverse(v["age_ms"].as_u64().unwrap_or(0)));
        let hist: Vec<Vec<u64>> = inner.hist.iter().map(|h| h.iter().map(|a| a.load(Relaxed)).collect()).collect();
        json!({"event":"watchdog", "instance":inner.instance, "mono_ms":now,
            "heartbeat_seen":inner.heartbeat_seen.load(Relaxed),
            "heartbeat_age_ms":now.saturating_sub(inner.heartbeat_ms.load(Relaxed)),
            "heartbeat_lag_ms":inner.heartbeat_lag_ms.load(Relaxed),
            "inflight":entries.len(), "active":entries, "dropped_events":inner.dropped.load(Relaxed),
            "tracker_overflow":inner.overflow.load(Relaxed), "snapshot_skipped":inner.snapshot_skipped.load(Relaxed),
            "state_skipped":inner.state_skipped.load(Relaxed), "writer_errors":inner.writer_errors.load(Relaxed),
            "stage_histogram_buckets_ms":BUCKETS_MS, "stage_names":STAGE_NAMES, "stage_histograms":hist})
    }
}

impl Entry {
    fn event(&self, event: &'static str, detail: Value) {
        self.observer.emit(json!({"event":event, "instance":self.observer.instance,
            "mono_ms":self.observer.now_ms(), "id":self.id, "parent_id":self.parent_id,
            "request_id":self.request_id, "kind":self.kind, "method":self.method, "detail":detail}));
    }
}
impl Activity {
    pub fn context(&self) -> Context {
        self.context.clone()
    }
    pub fn finish(&mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
    pub fn event(&self, event: &'static str, detail: Value) {
        if let Some(e) = &self.context.0 {
            e.event(event, detail);
        }
    }
}
impl Drop for Activity {
    fn drop(&mut self) {
        if let Some(e) = &self.context.0 {
            if e.kind == "rpc" && self.outcome == "future_dropped" {
                e.rpc_waiter_gone.store(true, Relaxed);
            }
            e.finished.store(true, Relaxed);
            let outcome = if std::thread::panicking() { "panic" } else { self.outcome };
            e.event(
                "end",
                json!({"outcome":outcome, "elapsed_ms":e.observer.now_ms().saturating_sub(e.started_ms)}),
            );
        }
    }
}

impl Context {
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        let span = self.0.as_ref().map_or_else(tracing::Span::none, |e| {
            tracing::info_span!(
            target: "prove_proxy_observe", "prove_activity", activity_id = e.id,
            request_id = %e.request_id, kind = e.kind, rpc_method = %e.method)
        });
        TASK.scope(self.clone(), future).instrument(span).await
    }
    pub fn child(&self, kind: &'static str, stage: Stage) -> Activity {
        match &self.0 {
            Some(e) => Observer(Some(e.observer.clone())).create(kind, &e.request_id, &e.method, stage, Some(e.id), e.rpc_waiter_gone.clone()),
            None => Observer::disabled().activity(kind, "", "", stage),
        }
    }
    pub fn set_stage(&self, stage: Stage) {
        if let Some(e) = &self.0 {
            if e.state
                .replace(State {
                    stage,
                    since_ms: e.observer.now_ms(),
                    cache_key: None,
                })
                .is_none()
            {
                e.observer.state_skipped.fetch_add(1, Relaxed);
            }
        }
    }
}
pub fn current() -> Context {
    BLOCKING
        .with(|v| v.borrow().clone())
        .or_else(|| TASK.try_with(Clone::clone).ok())
        .unwrap_or(Context(None))
}

fn with_context<R>(context: Context, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Context>);
    impl Drop for Restore {
        fn drop(&mut self) {
            BLOCKING.with(|v| *v.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(BLOCKING.with(|v| v.replace(Some(context))));
    #[cfg(feature = "plonky2-hooks")]
    if current().0.is_some() {
        return plonky2::util::observation::with_hook(Arc::new(|phase| Box::new(stage(prover_phase(phase)))), f);
    }
    f()
}

#[cfg(feature = "plonky2-hooks")]
fn prover_phase(p: plonky2::util::observation::Phase) -> Stage {
    use plonky2::util::observation::Phase;
    match p {
        Phase::Witness => Stage::Witness,
        Phase::WiresCommit => Stage::WiresCommit,
        Phase::PartialProducts => Stage::PartialProducts,
        Phase::ZsCommit => Stage::ZsCommit,
        Phase::Quotient => Stage::Quotient,
        Phase::QuotientCommit => Stage::QuotientCommit,
        Phase::Openings => Stage::Openings,
        Phase::Fri => Stage::Fri,
        Phase::LargeProofWait => Stage::LargeProofWait,
        Phase::LargeProofHeld => Stage::LargeProofHeld,
        Phase::GpuBufferWait => Stage::GpuBufferWait,
        Phase::GpuLaneWait => Stage::GpuLaneWait,
        Phase::GpuLaneHeld => Stage::GpuLaneHeld,
        Phase::GpuDevice => Stage::GpuDevice,
        Phase::GpuRebuild => Stage::GpuRebuild,
        Phase::GpuQuotientWait => Stage::GpuQuotientWait,
        Phase::GpuFriWait => Stage::GpuFriWait,
    }
}

pub fn build<R>(key: u64, f: impl FnOnce() -> R) -> R {
    let mut activity = current().child("build", Stage::CircuitBuild);
    let context = activity.context();
    let result = with_context(context, || {
        let _stage = stage_key(Stage::CircuitBuild, Some(key));
        f()
    });
    activity.finish("completed");
    result
}

pub fn cache_event(event: &'static str, key: u64) {
    if let Some(e) = current().0 {
        e.event(event, json!({"cache_key":key}));
    }
}

/// Reuse cache statistics already collected by the caller; no added cache
/// locks.
pub fn cache_usage(bytes: u64, budget: u64, entries: usize) {
    if let Some(e) = current().0 {
        e.event("cache_usage", json!({"bytes":bytes, "budget_bytes":budget, "entries":entries}));
    }
}

pub struct StageGuard {
    entry: Option<Arc<Entry>>,
    previous: Option<State>,
    stage: Stage,
    start: Instant,
}
pub fn stage(stage: Stage) -> StageGuard {
    stage_key(stage, None)
}
pub fn stage_key(stage: Stage, key: Option<u64>) -> StageGuard {
    let context = current();
    let mut previous = None;
    if let Some(e) = &context.0 {
        previous = e.state.replace(State {
            stage,
            since_ms: e.observer.now_ms(),
            cache_key: key,
        });
        if previous.is_none() {
            e.observer.state_skipped.fetch_add(1, Relaxed);
        }
        e.event("stage_begin", json!({"stage":stage, "cache_key":key}));
    }
    StageGuard {
        entry: context.0,
        previous,
        stage,
        start: Instant::now(),
    }
}
impl Drop for StageGuard {
    fn drop(&mut self) {
        if let Some(e) = &self.entry {
            let ms = self.start.elapsed().as_millis().min(u64::MAX as u128) as u64;
            let bucket = BUCKETS_MS.iter().position(|&b| ms <= b).unwrap();
            e.observer.hist[self.stage as usize][bucket].fetch_add(1, Relaxed);
            if let Some(previous) = &self.previous {
                if e.state.replace(previous.clone()).is_none() {
                    e.observer.state_skipped.fetch_add(1, Relaxed);
                }
            }
            e.event(
                "stage_end",
                json!({"stage":self.stage, "elapsed_ms":ms,
                "slow":ms >= e.observer.slow_ms, "panicking":std::thread::panicking()}),
            );
        }
    }
}

/// Same execution policy as Tokio; only captures context and distinguishes
/// queue/run time.
pub fn spawn_blocking<F, R>(f: F) -> tokio::task::JoinHandle<R>
where
    F: FnOnce() -> R + Send + 'static,
    R: Send + 'static,
{
    let mut job = current().child("job", Stage::ExecutorQueue);
    let enqueued = Instant::now();
    let span = tracing::Span::current();
    tokio::task::spawn_blocking(move || {
        let context = job.context();
        context.set_stage(Stage::Proof);
        job.event("executor_started", json!({"queue_ms":enqueued.elapsed().as_millis()}));
        let result = span.in_scope(|| with_context(context, f));
        job.finish("completed");
        result
    })
}

/// Resource-key association only, never a metric label. Public contract/method
/// numbers.
pub fn cache_key(contract: u64, method: u32) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    (contract, method).hash(&mut h);
    h.finish()
}

fn bounded_name(value: &str) -> String {
    value
        .bytes()
        .take(96)
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"_-.:".contains(&b) {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests;
