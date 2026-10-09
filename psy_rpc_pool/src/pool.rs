use std::{
    future::Future,
    sync::{Mutex, MutexGuard, PoisonError},
    time::Duration,
};

use tokio::time::Instant;

use crate::{
    health::{CallOutcome, Health, HealthPolicy, Transition},
    select::{select_best, Candidate},
};

pub const DEFAULT_PRIORITY_WEIGHT: i32 = 10;

pub struct ProviderSpec<C> {
    /// Log label. Must not be a URL: provider URLs can embed API keys.
    pub name: String,
    /// Legacy metadata; selection uses health then declaration order.
    pub priority_weight: i32,
    /// Shared infrastructure failure domain, e.g. `alchemy`, `infura`.
    /// Defaults to `name` (unnormalized); an explicit value is trimmed and
    /// lowercased. Defaults and explicit values share one namespace, so an
    /// unlabeled provider can coincide with another provider's explicit
    /// label if their names collide after normalization. Diagnostic only.
    pub operator: String,
    /// Shared rate-limit/credit domain, e.g. an account or subscription.
    /// Same default and namespace rules as `operator`. Diagnostic only.
    pub quota_group: String,
    pub client: C,
}

impl<C> ProviderSpec<C> {
    pub fn new(name: impl Into<String>, client: C) -> Self {
        let name = name.into();
        Self {
            operator: name.clone(),
            quota_group: name.clone(),
            name,
            priority_weight: DEFAULT_PRIORITY_WEIGHT,
            client,
        }
    }

    pub fn with_priority_weight(mut self, priority_weight: i32) -> Self {
        self.priority_weight = priority_weight;
        self
    }

    /// Trimmed and lowercased; a blank value keeps the name-derived default.
    pub fn with_operator(mut self, operator: impl Into<String>) -> Self {
        let normalized = normalize_label(operator.into());
        if let Some(operator) = normalized {
            self.operator = operator;
        }
        self
    }

    /// Trimmed and lowercased; a blank value keeps the name-derived default.
    pub fn with_quota_group(mut self, quota_group: impl Into<String>) -> Self {
        let normalized = normalize_label(quota_group.into());
        if let Some(quota_group) = normalized {
            self.quota_group = quota_group;
        }
        self
    }
}

/// Trims and lowercases a label; returns `None` for a blank value so the
/// caller can keep its existing default.
fn normalize_label(value: String) -> Option<String> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_lowercase())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetryPolicy {
    /// The same request may be sent to another provider after a failure.
    SafeAcrossEndpoints,
    /// One attempt only. A timeout does not prove the request was not executed.
    NoRetry,
}

#[derive(Debug)]
pub enum PoolError<E> {
    /// Every eligible provider is cooling down or has a recovery probe in flight.
    Unavailable,
    /// The last attempted provider's error.
    Provider(E),
    /// The last attempt exceeded its time budget.
    Timeout,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PoolBuildError {
    Empty,
    DuplicateName(String),
}

impl std::fmt::Display for PoolBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "provider pool needs at least one provider"),
            Self::DuplicateName(name) => write!(f, "duplicate provider name {name}"),
        }
    }
}

impl std::error::Error for PoolBuildError {}

#[derive(Clone, Debug)]
pub struct PoolConfig {
    pub attempt_timeout: Duration,
    pub total_timeout: Duration,
    pub max_attempts: usize,
    /// Minimum wait after each provider failure before a recovery trial.
    pub failure_cooldown: Duration,
    /// Health gap within which declaration order decides.
    pub tolerance: f64,
    pub half_life: Duration,
    pub quarantine_after: u32,
    pub quarantine_for: Duration,
    pub latency_alpha: f64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_secs(15),
            total_timeout: Duration::from_secs(30),
            max_attempts: usize::MAX,
            failure_cooldown: Duration::from_secs(30),
            tolerance: 2.0,
            half_life: Duration::from_secs(60),
            quarantine_after: 5,
            quarantine_for: Duration::from_secs(30 * 60),
            latency_alpha: 0.2,
        }
    }
}

impl PoolConfig {
    fn health_policy(&self) -> HealthPolicy {
        HealthPolicy {
            failure_cooldown: self.failure_cooldown,
            half_life: self.half_life,
            quarantine_after: self.quarantine_after,
            quarantine_for: self.quarantine_for,
            latency_alpha: self.latency_alpha,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProviderSnapshot {
    pub name: String,
    pub priority_weight: i32,
    pub operator: String,
    pub quota_group: String,
    pub health: f64,
    pub quarantined: bool,
    pub consecutive_failures: u32,
    pub latency_ewma: Option<Duration>,
}

pub struct ProviderPool<C> {
    label: String,
    providers: Vec<ProviderSpec<C>>,
    health: Mutex<Vec<Health>>,
    config: PoolConfig,
}

/// Releases a probe slot if the attempt is cancelled before it is recorded.
struct AttemptGuard<'a, C> {
    pool: &'a ProviderPool<C>,
    index: usize,
    probe: bool,
    recorded: bool,
}

impl<C> Drop for AttemptGuard<'_, C> {
    fn drop(&mut self) {
        if !self.recorded {
            self.pool.lock()[self.index].abandon_attempt(self.probe);
        }
    }
}

impl<C> ProviderPool<C> {
    fn lock(&self) -> MutexGuard<'_, Vec<Health>> {
        self.health.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl<C: Clone> ProviderPool<C> {
    pub fn new(
        label: impl Into<String>,
        providers: Vec<ProviderSpec<C>>,
        config: PoolConfig,
    ) -> Result<Self, PoolBuildError> {
        if providers.is_empty() {
            return Err(PoolBuildError::Empty);
        }
        for (index, provider) in providers.iter().enumerate() {
            if providers[..index].iter().any(|other| other.name == provider.name) {
                return Err(PoolBuildError::DuplicateName(provider.name.clone()));
            }
        }
        let health = Mutex::new(vec![Health::default(); providers.len()]);
        Ok(Self { label: label.into(), providers, health, config })
    }

    pub fn label(&self) -> &str {
        &self.label
    }

    pub fn snapshot(&self) -> Vec<ProviderSnapshot> {
        let now = Instant::now();
        let health = self.lock();
        self.providers
            .iter()
            .zip(health.iter())
            .map(|(provider, h)| ProviderSnapshot {
                name: provider.name.clone(),
                priority_weight: provider.priority_weight,
                operator: provider.operator.clone(),
                quota_group: provider.quota_group.clone(),
                health: h.health(now, self.config.half_life),
                quarantined: h.quarantined(now),
                consecutive_failures: h.consecutive_failures(),
                latency_ewma: h.latency_ewma(),
            })
            .collect()
    }

    /// Run one logical request. `f` is invoked once per attempt with the chosen
    /// provider's client; `classify` decides whether that attempt was a
    /// provider fault. `method` is only used for logs.
    pub async fn call<T, E, F, Fut, K>(
        &self,
        policy: RetryPolicy,
        method: &str,
        classify: K,
        f: F,
    ) -> Result<T, PoolError<E>>
    where
        F: Fn(C) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        K: Fn(&Result<T, E>) -> CallOutcome,
    {
        self.call_inner(policy, method, Instant::now() + self.config.total_timeout,
            |_| true, |result| { let outcome = result.map(&classify).unwrap_or(CallOutcome::Timeout); (Some(outcome), outcome.is_failure()) },
            f, false).await
    }

    /// Query-aware adapter entry point. The caller's absolute deadline includes
    /// time already spent queuing and on other calls in the same operation.
    /// `eligible` can skip a known missing capability without changing health.
    /// Classification separates health from retry: `(Some(Application), true)` tries
    /// another endpoint without penalizing a healthy but unsuitable provider.
    /// `(None, true)` skips recording entirely when an adapter reused an
    /// already-recorded failure without making a new observation. In particular,
    /// this must not reset cooldown like a fresh Application response would.
    /// The classifier receives `None` on attempt timeout, allowing adapters to
    /// distinguish a timed-out wire call from local single-flight waiting.
    /// Expired recovery candidates receive one guarded trial in list order.
    /// Existing `call` behavior and defaults are deliberately unchanged.
    #[allow(clippy::too_many_arguments)]
    pub async fn call_filtered<T, E, F, Fut, K, A>(
        &self, policy: RetryPolicy, method: &str, deadline: Instant,
        eligible: A, classify: K, f: F,
    ) -> Result<T, PoolError<E>>
    where
        F: Fn(C) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        K: Fn(Option<&Result<T, E>>) -> (Option<CallOutcome>, bool),
        A: Fn(&C) -> bool,
    {
        self.call_inner(policy, method, deadline, eligible, classify, f, true).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn call_inner<T, E, F, Fut, K, A>(
        &self, policy: RetryPolicy, method: &str, deadline: Instant,
        eligible: A, classify: K, f: F, probe_recovered: bool,
    ) -> Result<T, PoolError<E>>
    where
        F: Fn(C) -> Fut,
        Fut: Future<Output = Result<T, E>>,
        K: Fn(Option<&Result<T, E>>) -> (Option<CallOutcome>, bool),
        A: Fn(&C) -> bool,
    {
        let deadline = deadline.min(Instant::now() + self.config.total_timeout);
        let max_attempts = self.config.max_attempts.clamp(1, self.providers.len());
        let mut tried = vec![false; self.providers.len()];
        let mut last = None;
        for attempt in 1..=max_attempts {
            if Instant::now() >= deadline {
                return last.unwrap_or(Err(PoolError::Timeout));
            }
            let Some(mut guard) = self.begin(&tried, &eligible, probe_recovered) else {
                return last.unwrap_or(Err(PoolError::Unavailable));
            };
            let index = guard.index;
            tried[index] = true;
            let started = Instant::now();
            let budget = self.config.attempt_timeout.min(deadline.saturating_duration_since(started));
            let result = tokio::time::timeout(budget, f(self.providers[index].client.clone())).await;
            let now = Instant::now();
            let (outcome, retry, result) = match result {
                Ok(result) => {
                    let (outcome, retry) = classify(Some(&result));
                    (outcome, retry, result.map_err(PoolError::Provider))
                }
                Err(_) => {
                    let (outcome, retry) = classify(None);
                    (outcome, retry, Err(PoolError::Timeout))
                },
            };
            if let Some(outcome) = outcome {
                let latency = (outcome != CallOutcome::Timeout).then(|| now - started);
                self.record(index, outcome, latency, now, guard.probe);
                guard.recorded = true;
            }
            let observed = outcome.is_some();
            let outcome = outcome.unwrap_or(CallOutcome::Application);
            if !retry {
                return result;
            }
            let provider = &self.providers[index];
            let stop = policy == RetryPolicy::NoRetry || attempt == max_attempts || now >= deadline;
            tracing::warn!(
                pool = %self.label,
                provider = %provider.name,
                operator = %provider.operator,
                quota_group = %provider.quota_group,
                ?outcome,
                observed,
                method,
                failover = !stop,
                "RPC provider attempt failed"
            );
            last = Some(result);
            if stop {
                break;
            }
        }
        last.expect("at least one attempt runs")
    }

    fn begin(
        &self,
        tried: &[bool],
        eligible: &impl Fn(&C) -> bool,
        probe_recovered: bool,
    ) -> Option<AttemptGuard<'_, C>> {
        let now = Instant::now();
        let mut health = self.lock();
        let candidates: Vec<Candidate> = health
            .iter()
            .enumerate()
            .filter(|(index, _)| !tried[*index] && eligible(&self.providers[*index].client))
            .map(|(index, h)| {
                Candidate {
                    index,
                    health: h.health(now, self.config.half_life),
                    available: h.available(now),
                }
            })
            .collect();
        let best = select_best(&candidates, self.config.tolerance)?;
        // After the current choice fails, trial an earlier failed provider
        // whose cooldown has elapsed before moving farther down the list.
        // Reservation under the same lock limits it to one concurrent trial.
        let index = if probe_recovered || tried.iter().any(|tried| *tried) {
            candidates.iter().filter(|c| c.available && c.index < best
                && health[c.index].on_probation(now)).map(|c| c.index).min().unwrap_or(best)
        } else {
            best
        };
        let probe = health[index].begin_attempt(now);
        Some(AttemptGuard { pool: self, index, probe, recorded: false })
    }

    fn record(
        &self,
        index: usize,
        outcome: CallOutcome,
        latency: Option<Duration>,
        now: Instant,
        probe: bool,
    ) {
        let transition = self.lock()[index].record(outcome, latency, now, &self.config.health_policy(), probe);
        let provider = &self.providers[index].name;
        match transition {
            Transition::Quarantined => tracing::info!(
                pool = %self.label,
                %provider,
                minutes = self.config.quarantine_for.as_secs() / 60,
                "RPC provider quarantined"
            ),
            Transition::Restored => tracing::info!(pool = %self.label, %provider, "RPC provider restored"),
            Transition::None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::Notify;

    #[derive(Clone)]
    enum Mode {
        Ok,
        Fail(CallOutcome),
        Hang,
        Delay(Duration),
        Gate(Arc<Notify>),
    }

    #[derive(Clone, Default)]
    struct World {
        modes: Arc<Mutex<HashMap<&'static str, Mode>>>,
        calls: Arc<Mutex<Vec<&'static str>>>,
    }

    impl World {
        fn set(&self, name: &'static str, mode: Mode) {
            self.modes.lock().unwrap().insert(name, mode);
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
        async fn run(&self, name: &'static str) -> Result<&'static str, CallOutcome> {
            self.calls.lock().unwrap().push(name);
            let mode = self.modes.lock().unwrap().get(name).cloned().unwrap_or(Mode::Ok);
            match mode {
                Mode::Ok => Ok(name),
                Mode::Fail(outcome) => Err(outcome),
                Mode::Hang => std::future::pending().await,
                Mode::Delay(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(name)
                }
                Mode::Gate(gate) => {
                    gate.notified().await;
                    Ok(name)
                }
            }
        }
    }

    fn classify(result: &Result<&'static str, CallOutcome>) -> CallOutcome {
        match result {
            Ok(_) => CallOutcome::Success,
            Err(outcome) => *outcome,
        }
    }

    fn pool_with(names: &[(&'static str, i32)], config: PoolConfig) -> Arc<ProviderPool<&'static str>> {
        let specs = names
            .iter()
            .map(|(name, weight)| ProviderSpec::new(*name, *name).with_priority_weight(*weight))
            .collect();
        Arc::new(ProviderPool::new("test", specs, config).unwrap())
    }

    fn pool(names: &[(&'static str, i32)]) -> Arc<ProviderPool<&'static str>> {
        pool_with(names, PoolConfig::default())
    }

    fn pool_labeled_with(
        specs: &[(&'static str, i32, &'static str, &'static str)],
        config: PoolConfig,
    ) -> Arc<ProviderPool<&'static str>> {
        let specs = specs
            .iter()
            .map(|(name, weight, operator, quota_group)| {
                ProviderSpec::new(*name, *name)
                    .with_priority_weight(*weight)
                    .with_operator(*operator)
                    .with_quota_group(*quota_group)
            })
            .collect();
        Arc::new(ProviderPool::new("test", specs, config).unwrap())
    }

    fn pool_labeled(specs: &[(&'static str, i32, &'static str, &'static str)]) -> Arc<ProviderPool<&'static str>> {
        pool_labeled_with(specs, PoolConfig::default())
    }

    /// Tolerance above 100 makes static priority always win among available
    /// providers, so one provider can be driven into quarantine.
    fn sticky() -> PoolConfig {
        PoolConfig { tolerance: 1000.0, failure_cooldown: Duration::ZERO, ..PoolConfig::default() }
    }

    async fn call(
        pool: &ProviderPool<&'static str>,
        world: &World,
        policy: RetryPolicy,
    ) -> Result<&'static str, PoolError<CallOutcome>> {
        let world = world.clone();
        pool.call(policy, "eth_test", classify, move |name| {
            let world = world.clone();
            async move { world.run(name).await }
        })
        .await
    }

    fn health_of(pool: &ProviderPool<&'static str>, name: &str) -> ProviderSnapshot {
        pool.snapshot().into_iter().find(|s| s.name == name).unwrap()
    }

    use RetryPolicy::{NoRetry, SafeAcrossEndpoints as Safe};

    #[test]
    fn empty_and_duplicate_pools_are_rejected() {
        let empty: Vec<ProviderSpec<()>> = Vec::new();
        assert_eq!(ProviderPool::new("t", empty, PoolConfig::default()).err(), Some(PoolBuildError::Empty));
        let dup = vec![ProviderSpec::new("a", ()), ProviderSpec::new("a", ())];
        assert_eq!(
            ProviderPool::new("t", dup, PoolConfig::default()).err(),
            Some(PoolBuildError::DuplicateName("a".into()))
        );
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_pool_uses_config_order_even_with_higher_later_weights() {
        let world = World::default();
        let pool = pool(&[("a", 10), ("b", 11), ("c", 11)]);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert_eq!(world.calls(), vec!["a"]);
    }

    #[tokio::test(start_paused = true)]
    async fn failure_fails_over_and_preferred_provider_returns_after_decay() {
        let world = World::default();
        let pool = pool(&[("a", 11), ("b", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "b");
        world.set("a", Mode::Ok);
        // Penalty 15 decays to 2 after 60s * log2(7.5), about 174.4s.
        tokio::time::advance(Duration::from_secs(174)).await;
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert_eq!(world.calls(), vec!["a", "b", "b", "a"]);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert_eq!(health_of(&pool, "a").health, 100.0);
    }

    #[tokio::test(start_paused = true)]
    async fn default_can_reach_fourth_provider_without_repeating_any() {
        let world = World::default();
        let pool = pool(&[("a", 1), ("b", 100), ("c", 100), ("d", 100)]);
        for name in ["a", "b", "c"] { world.set(name, Mode::Fail(CallOutcome::Server)); }
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "d");
        assert_eq!(world.calls(), vec!["a", "b", "c", "d"]);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "d");
    }

    #[tokio::test(start_paused = true)]
    async fn failed_current_trials_earlier_cooled_candidate_before_later_entries() {
        let world = World::default();
        let pool = pool(&[("a", 10), ("b", 10), ("c", 10), ("d", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(30)).await;
        world.set("b", Mode::Fail(CallOutcome::Server));
        world.set("c", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "d");
        assert_eq!(world.calls(), vec!["a", "b", "b", "a", "c", "d"]);
    }

    #[tokio::test(start_paused = true)]
    async fn recovered_earlier_candidate_can_rescue_a_failed_current() {
        let world = World::default();
        let pool = pool(&[("a", 10), ("b", 10), ("c", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(30)).await;
        world.set("a", Mode::Ok);
        world.set("b", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert_eq!(world.calls(), vec!["a", "b", "b", "a"]);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert_eq!(health_of(&pool, "a").health, 100.0);
    }

    #[tokio::test(start_paused = true)]
    async fn first_failure_cools_down_even_when_every_provider_failed() {
        let world = World::default();
        let pool = pool(&[("a", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        call(&pool, &world, Safe).await.unwrap_err();
        world.set("a", Mode::Ok);
        tokio::time::advance(Duration::from_secs(29)).await;
        assert!(matches!(call(&pool, &world, Safe).await, Err(PoolError::Unavailable)));
        assert_eq!(world.calls(), vec!["a"]);
        tokio::time::advance(Duration::from_secs(1)).await;
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn sole_provider_recovery_does_not_fan_out_and_cancel_releases_slot() {
        let world = World::default();
        let pool = pool(&[("a", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        call(&pool, &world, Safe).await.unwrap_err();
        tokio::time::advance(Duration::from_secs(30)).await;
        world.set("a", Mode::Hang);
        let (p, w) = (pool.clone(), world.clone());
        let probe = tokio::spawn(async move { call(&p, &w, Safe).await });
        while world.calls().len() < 2 { tokio::task::yield_now().await; }
        for _ in 0..3 {
            assert!(matches!(call(&pool, &world, Safe).await, Err(PoolError::Unavailable)));
        }
        assert_eq!(world.calls(), vec!["a", "a"]);
        probe.abort();
        assert!(probe.await.unwrap_err().is_cancelled());
        world.set("a", Mode::Ok);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn expired_request_budget_never_invokes_transport() {
        let world = World::default();
        let pool = pool_with(&[("a", 10)], PoolConfig { total_timeout: Duration::ZERO, ..PoolConfig::default() });
        assert!(matches!(call(&pool, &world, Safe).await, Err(PoolError::Timeout)));
        assert!(world.calls().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn separate_chain_pools_do_not_share_failure_state() {
        let world = World::default();
        let first = pool(&[("a", 10)]);
        let second = pool(&[("a", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Server));
        call(&first, &world, Safe).await.unwrap_err();
        world.set("a", Mode::Ok);
        assert_eq!(call(&second, &world, Safe).await.unwrap(), "a");
        assert!(matches!(call(&first, &world, Safe).await, Err(PoolError::Unavailable)));
    }

    #[tokio::test(start_paused = true)]
    async fn no_retry_makes_exactly_one_attempt() {
        let world = World::default();
        let pool = pool(&[("a", 11), ("b", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Transport));
        let error = call(&pool, &world, NoRetry).await.unwrap_err();
        assert!(matches!(error, PoolError::Provider(CallOutcome::Transport)));
        assert_eq!(world.calls(), vec!["a"]);
    }

    #[tokio::test(start_paused = true)]
    async fn application_error_returns_without_failover_or_penalty() {
        let world = World::default();
        let pool = pool(&[("a", 11), ("b", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Application));
        let error = call(&pool, &world, Safe).await.unwrap_err();
        assert!(matches!(error, PoolError::Provider(CallOutcome::Application)));
        assert_eq!(world.calls(), vec!["a"]);
        let a = health_of(&pool, "a");
        assert_eq!((a.health, a.consecutive_failures), (100.0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn explicit_attempt_cap_and_last_error_are_preserved() {
        let world = World::default();
        let pool = pool_with(&[("a", 15), ("b", 14), ("c", 13), ("d", 12), ("e", 11)],
            PoolConfig { max_attempts: 3, ..PoolConfig::default() });
        for name in ["a", "b", "c", "d", "e"] { world.set(name, Mode::Fail(CallOutcome::Server)); }
        world.set("c", Mode::Fail(CallOutcome::RateLimited));
        let error = call(&pool, &world, Safe).await.unwrap_err();
        assert!(matches!(error, PoolError::Provider(CallOutcome::RateLimited)));
        assert_eq!(world.calls(), vec!["a", "b", "c"]);
    }

    #[tokio::test(start_paused = true)]
    async fn hung_attempt_times_out_and_fails_over() {
        let world = World::default();
        let pool = pool(&[("a", 11), ("b", 10)]);
        world.set("a", Mode::Hang);
        let start = Instant::now();
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "b");
        assert_eq!(Instant::now() - start, Duration::from_secs(15));
        assert_eq!(health_of(&pool, "a").health, 70.0);
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_stops_further_attempts() {
        let world = World::default();
        let pool = pool(&[("a", 12), ("b", 11), ("c", 10)]);
        for name in ["a", "b", "c"] { world.set(name, Mode::Hang); }
        let start = Instant::now();
        assert!(matches!(call(&pool, &world, Safe).await.unwrap_err(), PoolError::Timeout));
        assert_eq!(Instant::now() - start, Duration::from_secs(30));
        assert_eq!(world.calls(), vec!["a", "b"]);
    }

    #[tokio::test(start_paused = true)]
    async fn quarantine_excludes_until_thirty_minutes_then_probes() {
        let world = World::default();
        let pool = pool_with(&[("a", 11), ("b", 10)], sticky());
        world.set("a", Mode::Fail(CallOutcome::Server));
        for _ in 0..4 { call(&pool, &world, NoRetry).await.unwrap_err(); }
        assert!(!health_of(&pool, "a").quarantined);
        call(&pool, &world, NoRetry).await.unwrap_err();
        assert!(health_of(&pool, "a").quarantined);
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(30 * 60 - 1)).await;
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(1)).await;
        // Probe fails: quarantined again, next request uses b.
        call(&pool, &world, NoRetry).await.unwrap_err();
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "b");
        world.set("a", Mode::Ok);
        tokio::time::advance(Duration::from_secs(30 * 60)).await;
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "a");
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "a");
        assert!(!health_of(&pool, "a").quarantined);
    }

    #[tokio::test(start_paused = true)]
    async fn all_quarantined_waits_for_recovery_instead_of_hammering() {
        let world = World::default();
        let pool = pool_with(&[("a", 10)], sticky());
        world.set("a", Mode::Fail(CallOutcome::Server));
        for _ in 0..5 { call(&pool, &world, NoRetry).await.unwrap_err(); }
        assert!(health_of(&pool, "a").quarantined);
        world.set("a", Mode::Ok);
        assert!(matches!(call(&pool, &world, NoRetry).await, Err(PoolError::Unavailable)));
        assert_eq!(world.calls().len(), 5);
        tokio::time::advance(Duration::from_secs(1800)).await;
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "a");
        assert!(!health_of(&pool, "a").quarantined);
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_requests_after_expiry_send_one_probe() {
        let world = World::default();
        let pool = pool_with(&[("a", 11), ("b", 10)], sticky());
        world.set("a", Mode::Fail(CallOutcome::Server));
        for _ in 0..5 { call(&pool, &world, NoRetry).await.unwrap_err(); }
        tokio::time::advance(Duration::from_secs(30 * 60)).await;
        let gate = Arc::new(Notify::new());
        world.set("a", Mode::Gate(gate.clone()));
        let (p, w) = (pool.clone(), world.clone());
        let probe = tokio::spawn(async move { call(&p, &w, NoRetry).await });
        // Five failed calls precede it; the sixth recorded call is the probe.
        while world.calls().len() < 6 { tokio::task::yield_now().await; }
        for _ in 0..3 { assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "b"); }
        gate.notify_one();
        assert_eq!(probe.await.unwrap().unwrap(), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn cancelled_attempt_records_nothing_and_releases_probe() {
        let world = World::default();
        let pool = pool_with(&[("a", 11), ("b", 10)], sticky());
        world.set("a", Mode::Fail(CallOutcome::Server));
        for _ in 0..5 { call(&pool, &world, NoRetry).await.unwrap_err(); }
        tokio::time::advance(Duration::from_secs(30 * 60)).await;
        world.set("a", Mode::Hang);
        let before = health_of(&pool, "a");
        let (p, w) = (pool.clone(), world.clone());
        let probe = tokio::spawn(async move { call(&p, &w, NoRetry).await });
        while world.calls().len() < 6 { tokio::task::yield_now().await; }
        probe.abort();
        assert!(probe.await.unwrap_err().is_cancelled());
        let after = health_of(&pool, "a");
        assert_eq!((after.health, after.consecutive_failures), (before.health, before.consecutive_failures));
        world.set("a", Mode::Ok);
        assert_eq!(call(&pool, &world, NoRetry).await.unwrap(), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn in_flight_request_does_not_block_other_requests() {
        let world = World::default();
        let pool = pool(&[("a", 10)]);
        let gate = Arc::new(Notify::new());
        world.set("a", Mode::Gate(gate.clone()));
        let (p, w) = (pool.clone(), world.clone());
        let slow = tokio::spawn(async move { call(&p, &w, Safe).await });
        while world.calls().is_empty() { tokio::task::yield_now().await; }
        world.set("a", Mode::Ok);
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a");
        assert!(!slow.is_finished());
        gate.notify_one();
        assert_eq!(slow.await.unwrap().unwrap(), "a");
    }

    #[tokio::test(start_paused = true)]
    async fn latency_is_observed_but_does_not_change_health() {
        let world = World::default();
        let pool = pool(&[("a", 10)]);
        world.set("a", Mode::Delay(Duration::from_millis(100)));
        call(&pool, &world, Safe).await.unwrap();
        world.set("a", Mode::Delay(Duration::from_millis(200)));
        call(&pool, &world, Safe).await.unwrap();
        let a = health_of(&pool, "a");
        assert_eq!(a.latency_ewma, Some(Duration::from_millis(120)));
        assert_eq!(a.health, 100.0);
    }

    // Operator/quota labels remain diagnostic metadata, not routing tiers.

    /// The trio used across the failure-domain tests below.
    fn trio() -> Arc<ProviderPool<&'static str>> {
        pool_labeled(&[
            ("a1", 12, "alchemy", "qa1"),
            ("a2", 11, "alchemy", "qa2"),
            ("i1", 10, "infura", "qi1"),
        ])
    }

    #[tokio::test(start_paused = true)]
    async fn infra_failure_preserves_order_instead_of_skipping_operators() {
        let world = World::default();
        let pool = trio();
        world.set("a1", Mode::Fail(CallOutcome::Transport));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a2");
        assert_eq!(world.calls(), vec!["a1", "a2"]);
    }

    #[tokio::test(start_paused = true)]
    async fn quota_failure_preserves_order_instead_of_skipping_operators() {
        let world = World::default();
        let pool = trio();
        world.set("a1", Mode::Fail(CallOutcome::RateLimited));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a2");
        assert_eq!(world.calls(), vec!["a1", "a2"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_quarantined_provider_is_skipped_for_an_available_sibling() {
        let world = World::default();
        // Drive the first entry into quarantine, then preserve the order of
        // the remaining candidates irrespective of their operator labels.
        let pool = pool_labeled_with(
            &[("i1", 12, "infura", "qi1"), ("a1", 11, "alchemy", "qa1"), ("a2", 10, "alchemy", "qa2")],
            sticky(),
        );
        world.set("i1", Mode::Fail(CallOutcome::Server));
        for _ in 0..5 { call(&pool, &world, NoRetry).await.unwrap_err(); }
        assert!(health_of(&pool, "i1").quarantined);
        world.set("i1", Mode::Ok);
        world.set("a1", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a2");
        assert_eq!(world.calls()[5..], ["a1", "a2"]);
    }

    #[tokio::test(start_paused = true)]
    async fn two_infra_failures_reach_the_third_entry_in_order() {
        let world = World::default();
        let pool = trio();
        // Server (not Timeout) per the brief: two 15s timeouts plus the 30s
        // total deadline would cut off the third attempt.
        world.set("a1", Mode::Fail(CallOutcome::Server));
        world.set("a2", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "i1");
        assert_eq!(world.calls(), vec!["a1", "a2", "i1"]);
    }

    #[tokio::test(start_paused = true)]
    async fn quota_failure_does_not_override_declared_sibling_order() {
        let world = World::default();
        let pool = pool_labeled(&[
            ("a1", 12, "alchemy", "qa1"),
            ("a1b", 11, "alchemy", "qa1"),
            ("a2", 10, "alchemy", "qa2"),
        ]);
        world.set("a1", Mode::Fail(CallOutcome::RateLimited));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a1b");
        assert_eq!(world.calls(), vec!["a1", "a1b"]);
    }

    #[tokio::test(start_paused = true)]
    async fn infra_failure_does_not_override_declared_sibling_order() {
        let world = World::default();
        let pool = pool_labeled(&[
            ("a1", 12, "alchemy", "qa1"),
            ("a1b", 11, "alchemy", "qa1"),
            ("a2", 10, "alchemy", "qa2"),
        ]);
        world.set("a1", Mode::Fail(CallOutcome::Server));
        assert_eq!(call(&pool, &world, Safe).await.unwrap(), "a1b");
        assert_eq!(world.calls(), vec!["a1", "a1b"]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_on_one_provider_leaves_a_same_operator_sibling_at_full_health() {
        let world = World::default();
        let pool = trio();
        world.set("a1", Mode::Fail(CallOutcome::Server));
        call(&pool, &world, NoRetry).await.unwrap_err();
        let a2 = health_of(&pool, "a2");
        assert_eq!((a2.health, a2.consecutive_failures), (100.0, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn snapshot_reports_operator_and_quota_group() {
        let pool = trio();
        let a1 = health_of(&pool, "a1");
        assert_eq!((a1.operator.as_str(), a1.quota_group.as_str()), ("alchemy", "qa1"));
    }

    #[test]
    fn operator_and_quota_group_default_to_the_exact_name() {
        let spec = ProviderSpec::new("Alchemy-Jason", ());
        assert_eq!(spec.operator, "Alchemy-Jason");
        assert_eq!(spec.quota_group, "Alchemy-Jason");
    }

    #[test]
    fn operator_and_quota_group_builders_trim_and_lowercase_and_keep_the_default_when_blank() {
        let spec =
            ProviderSpec::new("p", ()).with_operator("  Alchemy  ").with_quota_group(" QA-Jason ");
        assert_eq!(spec.operator, "alchemy");
        assert_eq!(spec.quota_group, "qa-jason");

        let blank = ProviderSpec::new("p", ()).with_operator("   ").with_quota_group("");
        assert_eq!(blank.operator, "p");
        assert_eq!(blank.quota_group, "p");
    }
    #[tokio::test(start_paused = true)]
    async fn capability_retry_is_neutral_and_filter_skips_without_attempts() {
        let p = pool(&[("a", 10), ("b", 10)]);
        let world = World::default();
        world.set("a", Mode::Fail(CallOutcome::Application));
        let run = |result: Option<&Result<&'static str, CallOutcome>>| {
            let outcome = result.map(classify).unwrap_or(CallOutcome::Timeout);
            (Some(outcome), result.is_none_or(Result::is_err))
        };
        let got = p.call_filtered(Safe, "history", Instant::now() + Duration::from_secs(6),
            |_| true, run, |name| world.run(name)).await.unwrap();
        assert_eq!(got, "b");
        assert_eq!(world.calls(), vec!["a", "b"]);
        assert_eq!(p.snapshot()[0].health, 100.0);
        assert_eq!(p.snapshot()[0].consecutive_failures, 0);
        world.set("a", Mode::Ok);
        assert_eq!(p.call_filtered(Safe, "history", Instant::now() + Duration::from_secs(6),
            |name| *name != "a", run, |name| world.run(name)).await.unwrap(), "b");
        assert_eq!(call(&p, &world, Safe).await.unwrap(), "a");
        assert!(matches!(p.call_filtered(Safe, "history", Instant::now(), |_| true,
            run, |name| world.run(name)).await, Err(PoolError::Timeout)));
        assert!(matches!(p.call_filtered(Safe, "history", Instant::now() + Duration::from_secs(6), |_| false,
            run, |name| world.run(name)).await, Err(PoolError::Unavailable)));
    }

    #[tokio::test(start_paused = true)]
    async fn filtered_recovery_probes_preferred_endpoint_once_and_cancellation_releases_it() {
        let p = pool(&[("a", 10), ("b", 10)]);
        let world = World::default();
        world.set("a", Mode::Fail(CallOutcome::Transport));
        assert_eq!(call(&p, &world, Safe).await.unwrap(), "b");
        tokio::time::advance(Duration::from_secs(31)).await;
        let gate = Arc::new(Notify::new());
        world.set("a", Mode::Gate(gate));
        let task = {
            let p = p.clone(); let world = world.clone();
            tokio::spawn(async move {
                p.call_filtered(Safe, "recover", Instant::now() + Duration::from_secs(6), |_| true,
                    |r| { let o = r.map(classify).unwrap_or(CallOutcome::Timeout); (Some(o), o.is_failure()) }, |name| world.run(name)).await
            })
        };
        tokio::task::yield_now().await;
        for _ in 0..10 {
            assert_eq!(p.call_filtered(Safe, "recover", Instant::now() + Duration::from_secs(6), |_| true,
                |r| { let o = r.map(classify).unwrap_or(CallOutcome::Timeout); (Some(o), o.is_failure()) }, |name| world.run(name)).await.unwrap(), "b");
        }
        assert_eq!(world.calls().iter().filter(|name| **name == "a").count(), 2);
        task.abort(); let _ = task.await;
        world.set("a", Mode::Ok);
        assert_eq!(p.call_filtered(Safe, "recover", Instant::now() + Duration::from_secs(6), |_| true,
            |r| { let o = r.map(classify).unwrap_or(CallOutcome::Timeout); (Some(o), o.is_failure()) }, |name| world.run(name)).await.unwrap(), "a");
        assert_eq!(p.snapshot()[0].health, 100.0);
    }

    #[tokio::test(start_paused = true)]
    async fn caller_deadline_bounds_filtered_retries_and_no_retry_remains_one_attempt() {
        let p = pool(&[("a", 10), ("b", 10)]);
        let world = World::default();
        world.set("a", Mode::Hang);
        let start = Instant::now();
        assert!(matches!(p.call_filtered(Safe, "deadline", start + Duration::from_millis(120), |_| true,
            |r| { let o = r.map(classify).unwrap_or(CallOutcome::Timeout); (Some(o), o.is_failure()) }, |name| world.run(name)).await, Err(PoolError::Timeout)));
        assert_eq!(Instant::now() - start, Duration::from_millis(120));
        assert_eq!(world.calls(), vec!["a"]);
        let p = pool(&[("a", 10), ("b", 10)]);
        world.set("a", Mode::Fail(CallOutcome::Application));
        let before = world.calls().len();
        assert!(p.call_filtered(NoRetry, "single", Instant::now() + Duration::from_secs(6), |_| true,
            |r| (Some(r.map(classify).unwrap_or(CallOutcome::Timeout)), true), |name| world.run(name)).await.is_err());
        assert_eq!(world.calls().len(), before + 1);
    }

    #[tokio::test(start_paused = true)]
    async fn local_wait_timeout_can_release_probe_without_recording_provider_failure() {
        let p = pool(&[("a", 10)]);
        let world = World::default();
        world.set("a", Mode::Hang);
        let result = p.call_filtered(Safe, "identity-wait", Instant::now() + Duration::from_secs(1),
            |_| true, |r| { assert!(r.is_none()); (None, true) }, |name| world.run(name)).await;
        assert!(matches!(result, Err(PoolError::Timeout)));
        assert_eq!(p.snapshot()[0].consecutive_failures, 0);
        assert_eq!(p.snapshot()[0].health, 100.0);
        world.set("a", Mode::Ok);
        assert_eq!(call(&p, &world, Safe).await.unwrap(), "a");
    }

}
