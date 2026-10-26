use std::time::Duration;

use tokio::time::Instant;

pub(crate) const MAX_HEALTH: f64 = 100.0;

/// Result class of one attempt, decided by the adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallOutcome {
    Success,
    /// The provider answered with a business error (revert, bad params).
    /// Returned to the caller; not a provider fault.
    Application,
    Timeout,
    Transport,
    Server,
    RateLimited,
    InvalidResponse,
}

impl CallOutcome {
    pub fn is_failure(self) -> bool {
        !matches!(self, Self::Success | Self::Application)
    }

    /// Rate-limit classification for diagnostics; routing remains list-ordered.
    pub fn is_quota_failure(self) -> bool {
        matches!(self, Self::RateLimited)
    }

    /// Infrastructure failure classification; sibling endpoints retain their
    /// own health and cooldown state.
    pub fn is_infra_failure(self) -> bool {
        matches!(self, Self::Timeout | Self::Transport | Self::Server | Self::InvalidResponse)
    }

    fn penalty(self) -> f64 {
        match self {
            Self::Success | Self::Application => 0.0,
            Self::Timeout | Self::InvalidResponse => 30.0,
            Self::Transport => 25.0,
            Self::RateLimited => 20.0,
            Self::Server => 15.0,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct HealthPolicy {
    pub failure_cooldown: Duration,
    pub half_life: Duration,
    pub quarantine_after: u32,
    pub quarantine_for: Duration,
    pub latency_alpha: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Transition {
    None,
    Quarantined,
    Restored,
}

/// Runtime facts for one provider. Penalties share one half-life, so the
/// decayed sum is a single value and its timestamp.
#[derive(Clone, Debug, Default)]
pub(crate) struct Health {
    penalty: f64,
    penalty_at: Option<Instant>,
    consecutive_failures: u32,
    quarantined_until: Option<Instant>,
    retry_after: Option<Instant>,
    probe_in_flight: bool,
    latency_ewma: Option<Duration>,
}

impl Health {
    fn penalty(&self, now: Instant, half_life: Duration) -> f64 {
        let Some(at) = self.penalty_at else { return 0.0 };
        let elapsed = now.saturating_duration_since(at).as_secs_f64();
        self.penalty * 0.5f64.powf(elapsed / half_life.as_secs_f64())
    }

    pub(crate) fn health(&self, now: Instant, half_life: Duration) -> f64 {
        (MAX_HEALTH - self.penalty(now, half_life)).clamp(0.0, MAX_HEALTH)
    }

    pub(crate) fn quarantined(&self, now: Instant) -> bool {
        self.quarantined_until.is_some_and(|until| now < until)
    }

    /// Past the failure cooldown (and quarantine, if any), awaiting validation.
    pub(crate) fn on_probation(&self, now: Instant) -> bool {
        self.retry_after.is_some_and(|until| now >= until) && !self.quarantined(now)
    }

    /// Whether normal selection may route here. A provider on probation
    /// accepts one probe at a time.
    pub(crate) fn available(&self, now: Instant) -> bool {
        !(self.quarantined(now) || self.retry_after.is_some_and(|until| now < until)
            || self.probe_in_flight)
    }

    /// Returns true when this attempt is the probe for a provider on probation.
    pub(crate) fn begin_attempt(&mut self, now: Instant) -> bool {
        let probe = self.on_probation(now) && !self.probe_in_flight;
        if probe {
            self.probe_in_flight = true;
        }
        probe
    }

    /// A cancelled attempt records nothing but must release its probe slot.
    pub(crate) fn abandon_attempt(&mut self, probe: bool) {
        if probe {
            self.probe_in_flight = false;
        }
    }

    pub(crate) fn record(
        &mut self,
        outcome: CallOutcome,
        latency: Option<Duration>,
        now: Instant,
        policy: &HealthPolicy,
        probe: bool,
    ) -> Transition {
        if probe {
            self.probe_in_flight = false;
        }
        if let Some(sample) = latency {
            self.latency_ewma = Some(match self.latency_ewma {
                None => sample,
                Some(previous) => previous.mul_f64(1.0 - policy.latency_alpha)
                    + sample.mul_f64(policy.latency_alpha),
            });
        }
        if !outcome.is_failure() {
            self.consecutive_failures = 0;
            self.retry_after = None;
            // A successful limited recovery trial is fresh evidence. Without
            // this, a recovered earlier entry would immediately lose to an
            // untried later entry's synthetic full-health score.
            if probe && outcome == CallOutcome::Success {
                self.penalty = 0.0;
                self.penalty_at = Some(now);
            }
            return if self.quarantined_until.take().is_some() {
                Transition::Restored
            } else {
                Transition::None
            };
        }
        self.penalty = self.penalty(now, policy.half_life) + outcome.penalty();
        self.penalty_at = Some(now);
        self.retry_after = Some(now + policy.failure_cooldown);
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        // Any failure while quarantined or on probation renews the quarantine.
        if self.quarantined_until.is_some()
            || self.consecutive_failures >= policy.quarantine_after
        {
            self.quarantined_until = Some(now + policy.quarantine_for);
            return Transition::Quarantined;
        }
        Transition::None
    }

    pub(crate) fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub(crate) fn latency_ewma(&self) -> Option<Duration> {
        self.latency_ewma
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_rate_limited_is_a_quota_failure() {
        assert!(CallOutcome::RateLimited.is_quota_failure());
        for other in [
            CallOutcome::Success,
            CallOutcome::Application,
            CallOutcome::Timeout,
            CallOutcome::Transport,
            CallOutcome::Server,
            CallOutcome::InvalidResponse,
        ] {
            assert!(!other.is_quota_failure(), "{other:?} must not be a quota failure");
        }
    }

    #[test]
    fn timeout_transport_server_and_invalid_response_are_infra_failures() {
        for infra in
            [CallOutcome::Timeout, CallOutcome::Transport, CallOutcome::Server, CallOutcome::InvalidResponse]
        {
            assert!(infra.is_infra_failure(), "{infra:?} must be an infra failure");
        }
        for other in [CallOutcome::Success, CallOutcome::Application, CallOutcome::RateLimited] {
            assert!(!other.is_infra_failure(), "{other:?} must not be an infra failure");
        }
    }

    fn policy() -> HealthPolicy {
        HealthPolicy {
            failure_cooldown: Duration::from_secs(30),
            half_life: Duration::from_secs(60),
            quarantine_after: 5,
            quarantine_for: Duration::from_secs(30 * 60),
            latency_alpha: 0.2,
        }
    }

    fn close(a: f64, b: f64) -> bool { (a - b).abs() < 1e-9 }

    fn fail(h: &mut Health, outcome: CallOutcome, now: Instant) -> Transition {
        let probe = h.begin_attempt(now);
        h.record(outcome, None, now, &policy(), probe)
    }

    #[test]
    fn penalty_halves_every_half_life() {
        let t0 = Instant::now();
        let mut h = Health::default();
        fail(&mut h, CallOutcome::Timeout, t0);
        let hl = policy().half_life;
        assert!(close(h.health(t0, hl), 70.0));
        assert!(close(h.health(t0 + Duration::from_secs(60), hl), 85.0));
        assert!(close(h.health(t0 + Duration::from_secs(120), hl), 92.5));
    }

    #[test]
    fn new_penalty_adds_to_decayed_value() {
        let t0 = Instant::now();
        let mut h = Health::default();
        fail(&mut h, CallOutcome::Timeout, t0);
        let t1 = t0 + Duration::from_secs(60);
        fail(&mut h, CallOutcome::Timeout, t1);
        assert!(close(h.health(t1, policy().half_life), 55.0));
    }

    #[test]
    fn health_is_clamped_at_zero() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..4 { fail(&mut h, CallOutcome::Timeout, t0); }
        assert!(close(h.health(t0, policy().half_life), 0.0));
    }

    #[test]
    fn success_and_application_carry_no_penalty_and_reset_the_counter() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..4 { fail(&mut h, CallOutcome::Server, t0); }
        assert_eq!(h.consecutive_failures(), 4);
        h.record(CallOutcome::Application, None, t0, &policy(), false);
        assert_eq!(h.consecutive_failures(), 0);
        for _ in 0..4 { fail(&mut h, CallOutcome::Server, t0); }
        assert!(!h.quarantined(t0));
        h.record(CallOutcome::Success, None, t0, &policy(), false);
        assert_eq!(h.consecutive_failures(), 0);
        // Eight Server penalties (120) clamp health to 0; Success adds nothing.
        assert!(close(h.health(t0, policy().half_life), 0.0));
    }

    #[test]
    fn fifth_consecutive_failure_quarantines_for_thirty_minutes() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..4 { assert_eq!(fail(&mut h, CallOutcome::Server, t0), Transition::None); }
        assert!(!h.quarantined(t0));
        assert_eq!(fail(&mut h, CallOutcome::Server, t0), Transition::Quarantined);
        assert!(h.quarantined(t0 + Duration::from_secs(30 * 60 - 1)));
        assert!(!h.available(t0 + Duration::from_secs(30 * 60 - 1)));
        assert!(!h.quarantined(t0 + Duration::from_secs(30 * 60)));
        assert!(h.available(t0 + Duration::from_secs(30 * 60)));
    }

    #[test]
    fn failed_probe_requarantines_and_successful_probe_restores() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..5 { fail(&mut h, CallOutcome::Server, t0); }
        let expiry = t0 + Duration::from_secs(30 * 60);
        assert_eq!(fail(&mut h, CallOutcome::Server, expiry), Transition::Quarantined);
        assert!(h.quarantined(expiry + Duration::from_secs(30 * 60 - 1)));
        let second = expiry + Duration::from_secs(30 * 60);
        let probe = h.begin_attempt(second);
        assert!(probe);
        assert_eq!(h.record(CallOutcome::Success, None, second, &policy(), probe), Transition::Restored);
        assert!(!h.quarantined(second));
        assert_eq!(h.consecutive_failures(), 0);
    }

    #[test]
    fn only_one_probe_is_in_flight_and_abandoning_it_frees_the_slot() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..5 { fail(&mut h, CallOutcome::Server, t0); }
        let expiry = t0 + Duration::from_secs(30 * 60);
        assert!(h.begin_attempt(expiry));
        assert!(!h.available(expiry));
        h.abandon_attempt(true);
        assert!(h.available(expiry));
    }

    #[test]
    fn abandoning_a_normal_attempt_keeps_the_probe_slot() {
        let t0 = Instant::now();
        let mut h = Health::default();
        for _ in 0..5 { fail(&mut h, CallOutcome::Server, t0); }
        let expiry = t0 + Duration::from_secs(30 * 60);
        assert!(h.begin_attempt(expiry));
        h.abandon_attempt(false);
        assert!(!h.available(expiry));
    }

    #[test]
    fn latency_ewma_weights_new_samples_by_alpha() {
        let t0 = Instant::now();
        let mut h = Health::default();
        h.record(CallOutcome::Success, Some(Duration::from_millis(100)), t0, &policy(), false);
        assert_eq!(h.latency_ewma(), Some(Duration::from_millis(100)));
        h.record(CallOutcome::Success, Some(Duration::from_millis(200)), t0, &policy(), false);
        assert_eq!(h.latency_ewma(), Some(Duration::from_millis(120)));
    }
}
