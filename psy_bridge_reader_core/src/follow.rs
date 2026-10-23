//! The follow loop: start-up, catch-up and steady ticks from the model's cursors, reloads and reconnects.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::metrics::Metrics;
use crate::model::{ApplyOutcome, ChainProgress, Model, ReloadReason, TickData, View};
use crate::source::{EnvioSource, SourceError};

const MAX_TICK: Duration = Duration::from_millis(1000);
const MAX_FOLLOW_ROWS: usize = 50_000;
const FIRST_BACKOFF: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FollowConfig {
    pub tick: Duration,
    pub max_rows: usize,
    pub backoff_max: Duration,
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
}

impl Default for FollowConfig {
    fn default() -> Self {
        FollowConfig {
            tick: Duration::from_millis(500),
            max_rows: MAX_FOLLOW_ROWS,
            backoff_max: Duration::from_secs(10),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(10),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FollowConfigError {
    #[error("follow tick {0:?} is outside 1 ms..=1000 ms")]
    TickOutOfRange(Duration),
    #[error("follow max_rows {0} is outside 1..=50000")]
    MaxRowsOutOfRange(usize),
    #[error("follow connect_timeout is zero")]
    ConnectTimeoutZero,
    #[error("follow read_timeout is zero")]
    ReadTimeoutZero,
}

impl FollowConfig {
    pub fn validate(&self) -> Result<(), FollowConfigError> {
        if self.tick.is_zero() || self.tick > MAX_TICK {
            return Err(FollowConfigError::TickOutOfRange(self.tick));
        }
        if self.max_rows == 0 || self.max_rows > MAX_FOLLOW_ROWS {
            return Err(FollowConfigError::MaxRowsOutOfRange(self.max_rows));
        }
        if self.connect_timeout.is_zero() {
            return Err(FollowConfigError::ConnectTimeoutZero);
        }
        if self.read_timeout.is_zero() {
            return Err(FollowConfigError::ReadTimeoutZero);
        }
        Ok(())
    }
}

enum Step<S> {
    Stop,
    Connected(S),
    Ticked { next_read_at: Option<Instant> },
    Failed(SourceError),
}

/// Follows Envio until `shutdown` turns true or its sender is dropped.
pub async fn run_follow<S, F, Fut>(
    mut connect: F,
    model: Arc<Mutex<Model>>,
    cfg: FollowConfig,
    metrics: Metrics,
    mut shutdown: watch::Receiver<bool>,
) where
    S: EnvioSource,
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<S, SourceError>> + Send,
{
    if let Err(e) = cfg.validate() {
        tracing::error!(error = %e, "bridge reader follow config refused");
        return;
    }
    let mut follow = FollowState { model, metrics, started_at: Instant::now(), is_startup_recorded: false, is_schema_missing: false };
    let mut source: Option<S> = None;
    let mut backoff = FIRST_BACKOFF;
    loop {
        let step = match source.as_mut() {
            None => match until_shutdown(&mut shutdown, with_timeout(cfg.connect_timeout, "connect", connect())).await {
                None => Step::Stop,
                Some(Ok(connected)) => Step::Connected(connected),
                Some(Err(e)) => Step::Failed(e),
            },
            Some(src) => {
                let cursors = follow.model.lock().cursors();
                let tick_started_at = Instant::now();
                let read = with_timeout(cfg.read_timeout, "read", src.read_tick(&cursors, cfg.max_rows));
                match until_shutdown(&mut shutdown, read).await {
                    None => Step::Stop,
                    Some(Ok(tick)) => {
                        let is_catching_up = follow.apply(tick, tick_started_at) == ApplyOutcome::CatchingUp;
                        Step::Ticked { next_read_at: (!is_catching_up).then(|| tick_started_at + cfg.tick) }
                    }
                    Some(Err(e)) => Step::Failed(e),
                }
            }
        };
        let wake_at = match step {
            Step::Stop => return,
            Step::Connected(connected) => {
                source = Some(connected);
                continue;
            }
            Step::Ticked { next_read_at } => {
                backoff = FIRST_BACKOFF;
                match next_read_at {
                    Some(at) => at,
                    None => continue,
                }
            }
            Step::Failed(e) => {
                source = None;
                follow.handle_source_error(e, backoff);
                let at = Instant::now() + backoff;
                backoff = (backoff * 2).min(cfg.backoff_max).max(FIRST_BACKOFF);
                at
            }
        };
        if until_shutdown(&mut shutdown, tokio::time::sleep_until(wake_at)).await.is_none() {
            return;
        }
    }
}

async fn until_shutdown<T>(shutdown: &mut watch::Receiver<bool>, work: impl Future<Output = T>) -> Option<T> {
    tokio::select! {
        biased;
        () = stop_requested(shutdown) => None,
        out = work => Some(out),
    }
}

async fn with_timeout<T>(limit: Duration, call: &str, work: impl Future<Output = Result<T, SourceError>>) -> Result<T, SourceError> {
    tokio::time::timeout(limit, work)
        .await
        .unwrap_or_else(|_| Err(SourceError::Unavailable(format!("{call} timed out after {limit:?}"))))
}

async fn stop_requested(shutdown: &mut watch::Receiver<bool>) {
    loop {
        if *shutdown.borrow_and_update() || shutdown.changed().await.is_err() {
            return;
        }
    }
}

struct FollowState {
    model: Arc<Mutex<Model>>,
    metrics: Metrics,
    started_at: Instant,
    is_startup_recorded: bool,
    is_schema_missing: bool,
}

impl FollowState {
    fn apply(&mut self, tick: TickData, tick_started_at: Instant) -> ApplyOutcome {
        self.is_schema_missing = false;
        let progress = tick.progress.clone();
        let (outcome, view) = {
            let mut model = self.model.lock();
            let outcome = model.apply(tick);
            if let ApplyOutcome::Reload(reason) = &outcome {
                self.reset_for(&mut model, reason);
            }
            self.metrics.set_resident_bytes(model.resident_bytes_estimate());
            (outcome, model.view())
        };
        match &outcome {
            ApplyOutcome::Published { reorged } => reorged.iter().for_each(|_| self.metrics.inc_reorgs()),
            ApplyOutcome::Reload(reason) => {
                tracing::warn!(%reason, "bridge reader follow reload");
                self.metrics.inc_reload(reload_label(reason));
                if matches!(reason, ReloadReason::TreeMismatch { .. }) {
                    self.metrics.inc_tree_mismatch();
                }
            }
            ApplyOutcome::Unchanged | ApplyOutcome::CatchingUp => {}
        }
        self.metrics.observe_tick(tick_started_at.elapsed().as_secs_f64());
        self.set_view_metrics(&view, &progress);
        if !self.is_startup_recorded && view.status().ready {
            self.is_startup_recorded = true;
            self.metrics.set_startup_seconds(self.started_at.elapsed().as_secs_f64());
        }
        outcome
    }

    fn handle_source_error(&mut self, e: SourceError, backoff: Duration) {
        tracing::warn!(error = %e, backoff_ms = backoff.as_millis() as u64, "bridge reader Envio source failed");
        let is_new_schema_missing = matches!(e, SourceError::SchemaMissing(_)) && !self.is_schema_missing;
        let view = {
            let mut model = self.model.lock();
            if is_new_schema_missing {
                self.is_schema_missing = true;
                model.reset_all();
                self.metrics.clear_chain_gauges();
                self.metrics.inc_reload("schema_missing");
            }
            model.view()
        };
        self.set_view_metrics(&view, &[]);
    }

    fn reset_for(&self, model: &mut Model, reason: &ReloadReason) {
        match reason {
            ReloadReason::InvariantViolated { chain_index, .. } | ReloadReason::TreeMismatch { chain_index } => {
                model.reset_chain(*chain_index)
            }
            // reset_chain keeps the chain_id's committed safe block and claims, so only reset_all lowers them.
            ReloadReason::IdentityChanged | ReloadReason::ProgressBelowCommitted { .. } | ReloadReason::MetaMissing { .. } => {
                model.reset_all();
                self.metrics.clear_chain_gauges();
            }
            ReloadReason::WindowOverLimit => {}
        }
    }

    /// `follow_lag_blocks` is the tick's Envio progress block minus the
    /// progress block the published view serves (-1 when it serves none).
    fn set_view_metrics(&self, view: &View, progress: &[ChainProgress]) {
        let now_unix_ms = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
        self.metrics.set_view_age_seconds(now_unix_ms.saturating_sub(view.revision.as_of_unix_ms) as f64 / 1000.0);
        for (&chain_index, chain) in &view.chains {
            self.metrics.set_window_rows(chain_index, i64::try_from(chain.window.len()).unwrap_or(i64::MAX));
        }
        for p in progress {
            let served = view.envio_chains.get(&p.chain_id).map_or(-1, |e| i64::try_from(e.progress_block).unwrap_or(i64::MAX));
            self.metrics.set_follow_lag_blocks(p.chain_id, p.progress_block.saturating_sub(served).max(0));
        }
        self.metrics.refresh_process_rss();
    }
}

fn reload_label(reason: &ReloadReason) -> &'static str {
    match reason {
        ReloadReason::IdentityChanged => "identity_changed",
        ReloadReason::ProgressBelowCommitted { .. } => "progress_below_committed",
        ReloadReason::InvariantViolated { .. } => "invariant_violated",
        ReloadReason::TreeMismatch { .. } => "tree_mismatch",
        ReloadReason::MetaMissing { .. } => "meta_missing",
        ReloadReason::WindowOverLimit => "window_over_limit",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use arc_swap::ArcSwap;
    use psy_bridge_reader_api::{DepositsByAddressQuery, WithdrawalClaimsRequest};

    use super::*;
    use crate::model::{Cursors, DepositCursor, ReadError};
    use crate::test_support::TickBuilder;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Call {
        Connect,
        Read,
    }

    /// One call the loop made, with the cursors it passed and the view it had
    /// published by then.
    struct Event {
        call: Call,
        at_ms: u128,
        cursors: Option<Cursors>,
        view: Arc<View>,
    }

    struct Script {
        started_at: Instant,
        view: Arc<ArcSwap<View>>,
        connects: VecDeque<Result<(), SourceError>>,
        reads: VecDeque<Result<TickData, SourceError>>,
        read_latency: Duration,
        max_rows: usize,
        hangs: Hangs,
        events: Vec<Event>,
        stop: watch::Sender<bool>,
    }

    /// The 0-based connect or read call that never resolves.
    #[derive(Default)]
    struct Hangs {
        connect: Option<usize>,
        read: Option<usize>,
    }

    impl Script {
        /// Records the call; returns whether it hangs.
        fn record(&mut self, call: Call, cursors: Option<Cursors>) -> bool {
            let at_ms = self.started_at.elapsed().as_millis();
            let n = self.events.iter().filter(|e| e.call == call).count();
            self.events.push(Event { call, at_ms, cursors, view: self.view.load_full() });
            let hang = match call {
                Call::Connect => self.hangs.connect,
                Call::Read => self.hangs.read,
            };
            hang == Some(n)
        }
    }

    struct ScriptedSource {
        script: Arc<Mutex<Script>>,
    }

    impl EnvioSource for ScriptedSource {
        fn read_tick(&mut self, cursors: &Cursors, max_rows: usize) -> impl Future<Output = Result<TickData, SourceError>> + Send {
            let script = self.script.clone();
            let cursors = cursors.clone();
            async move {
                let step = {
                    let mut s = script.lock();
                    assert_eq!(max_rows, s.max_rows);
                    let hangs = s.record(Call::Read, Some(cursors));
                    (!hangs).then(|| (s.reads.pop_front(), s.read_latency))
                };
                let Some((next, latency)) = step else {
                    return std::future::pending().await;
                };
                let Some(next) = next else {
                    script.lock().stop.send_replace(true);
                    return std::future::pending().await;
                };
                tokio::time::sleep(latency).await;
                next
            }
        }
    }

    struct Run {
        events: Vec<Event>,
        metrics: String,
    }

    impl Run {
        fn calls(&self) -> Vec<(Call, u128)> {
            self.events.iter().map(|e| (e.call, e.at_ms)).collect()
        }

        fn reads(&self) -> Vec<&Event> {
            self.events.iter().filter(|e| e.call == Call::Read).collect()
        }

        fn metric(&self, series: &str) -> Option<f64> {
            self.metrics.lines().find_map(|l| l.strip_prefix(series).and_then(|r| r.trim().parse().ok()))
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    /// Runs the loop until the scripted reads are used up.
    async fn run(
        cfg: FollowConfig,
        connects: Vec<Result<(), SourceError>>,
        reads: Vec<Result<TickData, SourceError>>,
        read_latency: Duration,
    ) -> Run {
        run_with_hangs(cfg, connects, reads, read_latency, Hangs::default()).await
    }

    async fn run_with_hangs(
        cfg: FollowConfig,
        connects: Vec<Result<(), SourceError>>,
        reads: Vec<Result<TickData, SourceError>>,
        read_latency: Duration,
        hangs: Hangs,
    ) -> Run {
        let model = Arc::new(Mutex::new(Model::new()));
        let (stop, shutdown) = watch::channel(false);
        let script = Arc::new(Mutex::new(Script {
            started_at: Instant::now(),
            view: model.lock().view_handle(),
            connects: connects.into(),
            reads: reads.into(),
            read_latency,
            max_rows: cfg.max_rows,
            hangs,
            events: Vec::new(),
            stop,
        }));
        let connect_script = script.clone();
        let connect = move || {
            let script = connect_script.clone();
            async move {
                let result = {
                    let mut s = script.lock();
                    let hangs = s.record(Call::Connect, None);
                    (!hangs).then(|| s.connects.pop_front().unwrap_or(Ok(())))
                };
                let Some(result) = result else {
                    return std::future::pending().await;
                };
                result.map(|()| ScriptedSource { script })
            }
        };
        let metrics = Metrics::new(1 << 30);
        let follow = run_follow(connect, model, cfg, metrics.clone(), shutdown);
        assert_send(&follow);
        follow.await;
        let events = std::mem::take(&mut script.lock().events);
        Run { events, metrics: metrics.render() }
    }

    fn by_address(view: &View, chain_id: u64, chain_index: u64, shield_address: &str) -> Result<Vec<psy_bridge_reader_api::DepositRow>, ReadError> {
        let q = DepositsByAddressQuery { shield_address: shield_address.to_owned(), chain_id, chain_index: Some(chain_index), limit: 1000, offset: 0 };
        view.deposits_by_address(&q).map(|r| r.rows)
    }

    fn local_count(cursors: &Cursors, chain_index: u64) -> u64 {
        cursors.deposits.get(&chain_index).map_or(0, |c| c.local_count)
    }

    fn unavailable() -> SourceError {
        SourceError::Unavailable("connection reset".to_owned())
    }

    #[tokio::test(start_paused = true)]
    async fn startup_pages_until_caught_up() {
        let mut b = TickBuilder::new();
        b.progress(1, 1000, 8);
        for block in 0..40 {
            b.deposit(0, 1, 10 + block, "A");
        }
        let mut expected = Model::new();
        let mut cursors = Vec::new();
        let mut reads = Vec::new();
        for _ in 0..4 {
            let tick = b.tick_limited(&expected.cursors(), 10);
            cursors.push(expected.cursors());
            expected.apply(tick.clone());
            reads.push(Ok(tick));
        }
        cursors.push(expected.cursors());
        let truncated = reads.iter().map(|r| r.as_ref().unwrap().truncated).collect::<Vec<_>>();
        assert_eq!(truncated, [true, true, true, false]);

        let cfg = FollowConfig { max_rows: 10, ..FollowConfig::default() };
        let r = run(cfg, vec![], reads, Duration::from_millis(50)).await;
        let read_events = r.reads();
        assert_eq!(read_events.iter().map(|e| e.cursors.clone().unwrap()).collect::<Vec<_>>(), cursors);
        assert_eq!(read_events.iter().map(|e| local_count(e.cursors.as_ref().unwrap(), 0)).collect::<Vec<_>>(), [0, 10, 20, 30, 40]);
        assert_eq!(read_events.iter().map(|e| e.view.status().ready).collect::<Vec<_>>(), [false, false, false, false, true]);
        for e in &read_events[..4] {
            assert!(matches!(by_address(&e.view, 1, 0, "A"), Err(ReadError::NotReady(_))));
        }
        assert_eq!(by_address(&read_events[4].view, 1, 0, "A").unwrap(), b.rows(0));
        // Catch-up reads follow each other at once; the steady tick waits.
        assert_eq!(read_events.iter().map(|e| e.at_ms).collect::<Vec<_>>(), [0, 50, 100, 150, 650]);
        let startup = r.metric("psy_bridge_reader_startup_seconds ").unwrap();
        assert!((startup - 0.2).abs() < 1e-9, "{startup}");
        assert_eq!(r.metric("psy_bridge_reader_tick_seconds_count "), Some(4.0));
        let resident = r.metric("psy_bridge_reader_resident_bytes ").unwrap();
        assert!(resident > 0.0);
        assert_eq!(resident, expected.resident_bytes_estimate() as f64);
    }

    #[tokio::test(start_paused = true)]
    async fn envio_reset_makes_every_chain_not_ready_then_reloads() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8).progress(2, 100, 8);
        a.deposit(0, 1, 10, "A");
        a.deposit(0, 1, 95, "A");
        a.deposit(1, 2, 95, "A");
        let mut b = TickBuilder::new();
        b.identity.deposit_oid += 1;
        b.progress(1, 50, 8);
        b.deposit(0, 1, 45, "B");
        let reads = vec![
            Ok(a.tick(&Cursors::default())),
            Err(SourceError::SchemaMissing("table DepositLeaf".to_owned())),
            Ok(b.tick(&Cursors::default())),
        ];
        let r = run(FollowConfig::default(), vec![], reads, Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Connect, 600), (Read, 600), (Read, 1100)]);
        let before = &r.events[2].view;
        assert!(before.status().ready);
        assert_eq!(by_address(before, 1, 0, "A").unwrap(), a.rows(0));

        let reset = &r.events[3].view;
        assert!(!reset.status().ready);
        assert!(reset.status().chains.is_empty());
        assert!(reset.revision().epoch > before.revision().epoch);
        for (chain_id, chain_index) in [(1, 0), (2, 1)] {
            assert!(matches!(by_address(reset, chain_id, chain_index, "A"), Err(ReadError::NotReady(_))));
        }
        assert_eq!(r.events[4].cursors, Some(Cursors::default()));

        let after = &r.events[5].view;
        assert!(after.status().ready);
        assert_eq!(after.status().chains.iter().map(|c| c.chain_index).collect::<Vec<_>>(), [0]);
        assert_eq!(by_address(after, 1, 0, "B").unwrap(), b.rows(0));
        assert!(by_address(after, 1, 0, "A").unwrap().is_empty());
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"schema_missing\"} "), Some(1.0));
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"identity_changed\"} "), None);
        assert_eq!(r.metric("psy_bridge_reader_window_rows{chain_index=\"1\"} "), None);
        assert_eq!(r.metric("psy_bridge_reader_window_rows{chain_index=\"0\"} "), Some(1.0));
    }

    #[tokio::test(start_paused = true)]
    async fn schema_missing_resets_once_while_it_persists() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8);
        a.deposit(0, 1, 95, "A");
        let tick = a.tick(&Cursors::default());
        let missing = || SourceError::SchemaMissing("index on DepositLeaf".to_owned());
        let reads = vec![Ok(tick.clone()), Err(missing()), Ok(tick.clone()), Err(missing())];
        let connects = vec![Ok(()), Err(missing()), Err(unavailable()), Err(missing()), Ok(()), Ok(())];
        let r = run(FollowConfig::default(), connects, reads, Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(
            r.calls(),
            [
                (Connect, 0),
                (Read, 0),
                (Read, 500),
                (Connect, 600),
                (Connect, 800),
                (Connect, 1200),
                (Connect, 2000),
                (Read, 2000),
                (Read, 2500),
                (Connect, 2600),
                (Read, 2600),
            ]
        );
        let reset = &r.events[3].view;
        assert!(!reset.status().ready);
        for e in &r.events[3..=7] {
            assert!(Arc::ptr_eq(&e.view, reset), "a persisting SchemaMissing must not reset again");
        }
        assert!(r.events[8].view.status().ready);
        let reset_again = &r.events[9].view;
        assert!(!reset_again.status().ready);
        assert!(reset_again.revision().epoch > reset.revision().epoch);
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"schema_missing\"} "), Some(2.0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_read_times_out_and_reconnects_keeping_the_view() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8);
        a.deposit(0, 1, 95, "A");
        let first = a.tick(&Cursors::default());
        a.deposit(0, 1, 96, "A");
        let second = a.tick(&Cursors::default());
        let hangs = Hangs { read: Some(1), ..Hangs::default() };
        let r = run_with_hangs(FollowConfig::default(), vec![], vec![Ok(first), Ok(second)], Duration::ZERO, hangs).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Connect, 10_600), (Read, 10_600), (Read, 11_100)]);
        let kept = &r.events[2].view;
        assert!(kept.status().ready);
        for e in &r.events[2..=4] {
            assert!(Arc::ptr_eq(&e.view, kept));
        }
        assert_eq!(by_address(&r.events[5].view, 1, 0, "A").unwrap(), a.rows(0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_connect_times_out_and_retries() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8);
        a.deposit(0, 1, 95, "A");
        let cfg = FollowConfig { connect_timeout: Duration::from_secs(2), ..FollowConfig::default() };
        let hangs = Hangs { connect: Some(0), ..Hangs::default() };
        let r = run_with_hangs(cfg, vec![], vec![Ok(a.tick(&Cursors::default()))], Duration::ZERO, hangs).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Connect, 2100), (Read, 2100), (Read, 2600)]);
        assert!(!r.events[1].view.status().ready);
        assert_eq!(by_address(&r.events[3].view, 1, 0, "A").unwrap(), a.rows(0));
    }

    #[tokio::test(start_paused = true)]
    async fn window_over_limit_keeps_the_view_and_alarms() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        b.deposit(0, 1, 96, "A");
        let first = b.tick(&Cursors::default());
        b.deposit(0, 1, 97, "A");
        b.deposit(0, 1, 98, "A");
        let over = b.tick_limited(&Cursors::default(), 2);
        assert!(over.truncated);
        let full = b.tick(&Cursors::default());
        let r = run(FollowConfig::default(), vec![], vec![Ok(first), Ok(over), Ok(full)], Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Read, 1000), (Read, 1500)]);
        let kept = &r.events[2].view;
        assert!(kept.status().ready);
        assert!(Arc::ptr_eq(&r.events[3].view, kept));
        assert_eq!(r.events[3].cursors, r.events[2].cursors);
        assert_eq!(local_count(r.events[3].cursors.as_ref().unwrap(), 0), 0);
        assert_eq!(by_address(&r.events[3].view, 1, 0, "A").unwrap(), b.rows(0)[..2].to_vec());
        assert_eq!(by_address(&r.events[4].view, 1, 0, "A").unwrap(), b.rows(0));
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"window_over_limit\"} "), Some(1.0));
    }

    #[tokio::test(start_paused = true)]
    async fn source_loss_keeps_last_view_and_recovers() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8);
        a.deposit(0, 1, 95, "A");
        let first = a.tick(&Cursors::default());
        a.deposit(0, 1, 96, "A");
        let second = a.tick(&Cursors::default());
        let reads = vec![Ok(first), Err(unavailable()), Err(unavailable()), Ok(second), Err(SourceError::Decode("bad amount".to_owned()))];
        let connects = vec![Ok(()), Err(unavailable()), Ok(()), Ok(())];
        let cfg = FollowConfig { backoff_max: Duration::from_millis(300), ..FollowConfig::default() };
        let r = run(cfg, connects, reads, Duration::ZERO).await;
        use Call::{Connect, Read};
        // Backoff 100, 200, then capped at 300; reset to 100 after a good tick.
        assert_eq!(
            r.calls(),
            [
                (Connect, 0),
                (Read, 0),
                (Read, 500),
                (Connect, 600),
                (Connect, 800),
                (Read, 800),
                (Connect, 1100),
                (Read, 1100),
                (Read, 1600),
                (Connect, 1700),
                (Read, 1700),
            ]
        );
        let kept = &r.events[2].view;
        assert!(kept.status().ready);
        for e in &r.events[2..=7] {
            assert!(Arc::ptr_eq(&e.view, kept));
            assert_eq!(by_address(&e.view, 1, 0, "A").unwrap(), a.rows(0)[..1].to_vec());
        }
        let recovered = &r.events[8].view;
        assert!(recovered.revision().seq > kept.revision().seq);
        assert_eq!(by_address(recovered, 1, 0, "A").unwrap(), a.rows(0));
        for e in &r.events[9..] {
            assert!(Arc::ptr_eq(&e.view, recovered));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn tree_mismatch_reloads_only_that_chain() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8).progress(2, 100, 8);
        for block in [10, 11, 95, 96] {
            b.deposit(0, 1, block, "A");
            b.deposit(1, 2, block, "A");
        }
        let mut expected = Model::new();
        let first = b.tick(&expected.cursors());
        expected.apply(first.clone());
        let after_first = expected.cursors();
        b.meta_root.insert(0, crate::tree::hash::zero(5));
        let mismatch = b.tick(&after_first);
        b.meta_root.remove(&0);
        let mut after_reset = after_first.clone();
        after_reset.deposits.insert(0, DepositCursor::default());
        let repaired = b.tick(&after_reset);
        let r = run(FollowConfig::default(), vec![], vec![Ok(first), Ok(mismatch), Ok(repaired)], Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Read, 1000), (Read, 1500)]);

        let before = &r.events[2].view;
        assert!(before.status().ready);
        let reloading = &r.events[3];
        assert_eq!(local_count(&after_first, 1), 2);
        assert_eq!(reloading.cursors.as_ref(), Some(&after_reset));
        let status = reloading.view.status();
        assert!(!status.chains[0].ready && status.chains[1].ready);
        assert!(matches!(by_address(&reloading.view, 1, 0, "A"), Err(ReadError::NotReady(_))));
        assert_eq!(by_address(&reloading.view, 2, 1, "A").unwrap(), b.rows(1));
        assert!(Arc::ptr_eq(&before.chains[&1].window, &reloading.view.chains[&1].window));

        let after = &r.events[4].view;
        assert!(after.status().ready);
        assert_eq!(by_address(after, 1, 0, "A").unwrap(), b.rows(0));
        assert_eq!(by_address(after, 2, 1, "A").unwrap(), b.rows(1));
        assert_eq!(r.metric("psy_bridge_reader_tree_mismatch_total "), Some(1.0));
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"tree_mismatch\"} "), Some(1.0));
    }

    #[tokio::test(start_paused = true)]
    async fn invariant_violation_resets_only_that_chain() {
        let mut b = TickBuilder::new();
        b.progress(1, 100, 8).progress(2, 100, 8);
        for block in [10, 11, 95] {
            b.deposit(0, 1, block, "A");
            b.deposit(1, 2, block, "A");
        }
        let mut expected = Model::new();
        let first = b.tick(&expected.cursors());
        expected.apply(first.clone());
        let after_first = expected.cursors();
        b.deposit(0, 1, 96, "A");
        b.deposits.get_mut(&0).unwrap()[3].row.chain_local_deposit_index = 9;
        let violating = b.tick(&after_first);
        b.deposits.get_mut(&0).unwrap()[3].row.chain_local_deposit_index = 3;
        let mut after_reset = after_first.clone();
        after_reset.deposits.insert(0, DepositCursor::default());
        let repaired = b.tick(&after_reset);
        let r = run(FollowConfig::default(), vec![], vec![Ok(first), Ok(violating), Ok(repaired)], Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Read, 1000), (Read, 1500)]);

        let before = &r.events[2].view;
        assert!(before.status().ready);
        let reloading = &r.events[3];
        assert_eq!(local_count(&after_first, 1), 2);
        assert_eq!(reloading.cursors.as_ref(), Some(&after_reset));
        let status = reloading.view.status();
        assert!(!status.chains[0].ready && status.chains[1].ready);
        assert!(matches!(by_address(&reloading.view, 1, 0, "A"), Err(ReadError::NotReady(_))));
        assert!(Arc::ptr_eq(&before.chains[&1].window, &reloading.view.chains[&1].window));

        let after = &r.events[4].view;
        assert!(after.status().ready);
        assert_eq!(by_address(after, 1, 0, "A").unwrap(), b.rows(0));
        assert_eq!(by_address(after, 2, 1, "A").unwrap(), b.rows(1));
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"invariant_violated\"} "), Some(1.0));
        assert_eq!(r.metric("psy_bridge_reader_tree_mismatch_total "), Some(0.0));
    }

    #[tokio::test(start_paused = true)]
    async fn progress_below_committed_resets_everything() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8);
        a.deposit(0, 1, 10, "A");
        a.deposit(0, 1, 95, "A");
        a.claim(1, 20, "n1");
        let mut expected = Model::new();
        let first = a.tick(&expected.cursors());
        expected.apply(first.clone());
        a.progress(1, 50, 8);
        let below = a.tick(&expected.cursors());
        a.claims.clear();
        a.deposits.get_mut(&0).unwrap().truncate(1);
        let reloaded = a.tick(&Cursors::default());
        let r = run(FollowConfig::default(), vec![], vec![Ok(first), Ok(below), Ok(reloaded)], Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Read, 1000), (Read, 1500)]);
        let claims = |view: &View| {
            let q = WithdrawalClaimsRequest { chain_id: 1, nullifiers: vec!["n1".to_owned()] };
            view.withdrawal_claims(&q).unwrap().claims.len()
        };

        let before = &r.events[2];
        assert!(before.view.status().ready);
        assert_eq!(local_count(before.cursors.as_ref().unwrap(), 0), 1);
        assert_eq!(claims(&before.view), 1);
        let reset = &r.events[3];
        assert_eq!(reset.cursors, Some(Cursors::default()));
        assert!(!reset.view.status().ready && reset.view.status().chains.is_empty());
        assert!(matches!(by_address(&reset.view, 1, 0, "A"), Err(ReadError::NotReady(_))));
        let after = &r.events[4].view;
        assert!(after.status().ready);
        assert_eq!(after.status().envio_chains[0].committed_safe_block, 42);
        assert_eq!(by_address(after, 1, 0, "A").unwrap(), a.rows(0));
        assert_eq!(claims(after), 0);
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"progress_below_committed\"} "), Some(1.0));
    }

    #[tokio::test(start_paused = true)]
    async fn a_missing_meta_row_under_committed_deposits_resets_everything() {
        let mut a = TickBuilder::new();
        a.progress(1, 100, 8).progress(2, 100, 8);
        a.deposit(0, 1, 10, "A");
        a.deposit(1, 2, 10, "A");
        let mut expected = Model::new();
        let first = a.tick(&expected.cursors());
        expected.apply(first.clone());
        let rows = a.deposits.remove(&0).unwrap();
        let missing = a.tick(&expected.cursors());
        a.deposits.insert(0, rows);
        let reloaded = a.tick(&Cursors::default());
        let r = run(FollowConfig::default(), vec![], vec![Ok(first), Ok(missing), Ok(reloaded)], Duration::ZERO).await;
        use Call::{Connect, Read};
        assert_eq!(r.calls(), [(Connect, 0), (Read, 0), (Read, 500), (Read, 1000), (Read, 1500)]);
        assert!(r.events[2].view.status().ready);
        let reset = &r.events[3];
        assert_eq!(reset.cursors, Some(Cursors::default()));
        assert!(!reset.view.status().ready && reset.view.status().chains.is_empty());
        assert!(reset.view.revision().epoch > r.events[2].view.revision().epoch);
        let after = &r.events[4].view;
        assert!(after.status().ready);
        assert_eq!(by_address(after, 1, 0, "A").unwrap(), a.rows(0));
        assert_eq!(by_address(after, 2, 1, "A").unwrap(), a.rows(1));
        assert_eq!(r.metric("psy_bridge_reader_reloads_total{reason=\"meta_missing\"} "), Some(1.0));
    }

    #[tokio::test(start_paused = true)]
    async fn ticks_never_exceed_the_configured_interval() {
        let ms = Duration::from_millis;
        assert_eq!(FollowConfig::default().validate(), Ok(()));
        assert_eq!(FollowConfig { tick: ms(1000), max_rows: 50_000, ..FollowConfig::default() }.validate(), Ok(()));
        for tick in [Duration::ZERO, ms(1001)] {
            assert_eq!(FollowConfig { tick, ..FollowConfig::default() }.validate(), Err(FollowConfigError::TickOutOfRange(tick)));
        }
        for max_rows in [0, 50_001] {
            assert_eq!(FollowConfig { max_rows, ..FollowConfig::default() }.validate(), Err(FollowConfigError::MaxRowsOutOfRange(max_rows)));
        }
        let zero = Duration::ZERO;
        assert_eq!(FollowConfig { connect_timeout: zero, ..FollowConfig::default() }.validate(), Err(FollowConfigError::ConnectTimeoutZero));
        assert_eq!(FollowConfig { read_timeout: zero, ..FollowConfig::default() }.validate(), Err(FollowConfigError::ReadTimeoutZero));
        let refused = run(FollowConfig { tick: zero, ..FollowConfig::default() }, vec![], vec![], Duration::ZERO).await;
        assert!(refused.events.is_empty(), "a refused config must not connect");

        let mut b = TickBuilder::new();
        b.progress(1, 100, 8);
        b.deposit(0, 1, 95, "A");
        let tick = b.tick(&Cursors::default());
        for (latency, gap) in [(ms(120), 500), (ms(700), 700)] {
            let reads = vec![Ok(tick.clone()); 4];
            let r = run(FollowConfig::default(), vec![], reads, latency).await;
            let starts = r.reads().iter().map(|e| e.at_ms).collect::<Vec<_>>();
            assert_eq!(starts.len(), 5);
            assert!(starts.windows(2).all(|w| w[1] - w[0] == gap), "{latency:?}: {starts:?}");
            assert_eq!(r.metric("psy_bridge_reader_tick_seconds_count "), Some(4.0));
        }
    }
}
