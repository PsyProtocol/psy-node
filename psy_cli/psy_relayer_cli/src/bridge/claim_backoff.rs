//! Retry pacing for withdrawal claims.
//!
//! Every claim failure used to mean "retry next round, forever". The pending
//! set is durable, so a withdrawal that could never be claimed was re-attempted
//! on every round and across restarts — and an attempt is not cheap: it fetches
//! a claim proof from psy-services and then asks prove-proxy for a Groth16
//! batch proof. A single unclaimable withdrawal therefore burned prover time
//! indefinitely, which is exactly what happened in production when a withdrawal
//! reached L1 with an all-zero recipient and a destination chain index that was
//! not ours.
//!
//! Two mechanisms, deliberately general rather than a list of known-bad values:
//!
//! * **Exponential backoff.** The interval between attempts doubles, so a claim
//!   that keeps failing costs less and less. The common case — a transient
//!   outage — still recovers, just with a delay proportional to how long the
//!   problem has lasted.
//! * **An attempt ceiling.** Past it the withdrawal is retired: no further
//!   proofs are requested for it. Retiring is not discarding. The funds are
//!   genuinely stuck and need a human, so the record and the last failure
//!   reason are kept, in a separate set, where they can be found and re-armed.
//!
//! Enumerating invalid values (zero recipient, unknown chain index, ...) is
//! worth doing too, but it can only ever cover the cases already thought of.
//! These two cover the next one.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// First retry delay. Roughly a daemon round, so the first retry is not
/// noticeably slower than the old behaviour.
pub const CLAIM_RETRY_BASE_DELAY_SECS: u64 = 60;

/// Ceiling on the interval. Past this the backoff stops growing, so a claim
/// blocked on a long outage still gets a look once an hour.
pub const CLAIM_RETRY_MAX_DELAY_SECS: u64 = 3_600;

/// Failed attempts before the withdrawal is retired. With the delays above this
/// is a little under a day of trying, which outlasts any outage we have had
/// while bounding what one bad withdrawal can cost.
pub const CLAIM_RETRY_MAX_ATTEMPTS: u32 = 24;

/// Per-withdrawal retry bookkeeping, keyed by leaf_hash in the daemon state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimRetryState {
    /// Consecutive failed attempts. Reset by a successful claim, which removes
    /// the entry outright.
    #[serde(default)]
    pub attempts: u32,
    /// Unix seconds before which the next attempt is not worth making.
    #[serde(default)]
    pub next_attempt_unix: u64,
    /// Why the last attempt failed. Carried into the retired set so a human has
    /// something to work from.
    #[serde(default)]
    pub last_reason: String,
}

/// A withdrawal that has exhausted its attempts. Kept so the funds are
/// traceable; nothing in the daemon retries it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredClaim<W> {
    pub withdrawal: W,
    pub attempts: u32,
    pub last_reason: String,
    pub retired_at_unix: u64,
}

/// Delay before attempt `attempts + 1`, doubling and then flat.
///
/// `attempts` is the number that have already failed, so the first retry after
/// one failure waits `CLAIM_RETRY_BASE_DELAY_SECS`.
pub fn retry_delay_secs(attempts: u32) -> u64 {
    if attempts == 0 {
        return 0;
    }
    // Shift rather than pow so a large attempt count cannot overflow; anything
    // past ~6 doublings is capped anyway.
    let doublings = attempts.saturating_sub(1).min(32);
    let scaled = CLAIM_RETRY_BASE_DELAY_SECS.saturating_mul(1u64 << doublings.min(20));
    scaled.min(CLAIM_RETRY_MAX_DELAY_SECS)
}

/// Has this withdrawal run out of attempts?
pub fn is_exhausted(state: &ClaimRetryState) -> bool {
    state.attempts >= CLAIM_RETRY_MAX_ATTEMPTS
}

/// Is this withdrawal due for another attempt?
///
/// Unknown withdrawals are due: a claim that has never failed must not be
/// delayed. Exhausted ones are not, though the caller is expected to have
/// retired them already.
pub fn is_due(retry: Option<&ClaimRetryState>, now_unix: u64) -> bool {
    match retry {
        None => true,
        Some(state) if is_exhausted(state) => false,
        Some(state) => now_unix >= state.next_attempt_unix,
    }
}

/// Record one failed attempt and schedule the next.
pub fn record_failure(
    retry: &mut HashMap<String, ClaimRetryState>,
    leaf_hash: &str,
    reason: &str,
    now_unix: u64,
) -> ClaimRetryState {
    let entry = retry.entry(leaf_hash.to_string()).or_default();
    entry.attempts = entry.attempts.saturating_add(1);
    entry.last_reason = reason.to_string();
    entry.next_attempt_unix = now_unix.saturating_add(retry_delay_secs(entry.attempts));
    entry.clone()
}

/// Forget a withdrawal's retry history, after it is claimed or retired.
pub fn clear(retry: &mut HashMap<String, ClaimRetryState>, leaf_hash: &str) {
    retry.remove(leaf_hash);
}

pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delay_doubles_then_flattens_at_the_cap() {
        assert_eq!(retry_delay_secs(0), 0);
        assert_eq!(retry_delay_secs(1), CLAIM_RETRY_BASE_DELAY_SECS);
        assert_eq!(retry_delay_secs(2), CLAIM_RETRY_BASE_DELAY_SECS * 2);
        assert_eq!(retry_delay_secs(3), CLAIM_RETRY_BASE_DELAY_SECS * 4);
        // Growth is what bounds the cost, so assert it actually grows rather
        // than only that the endpoints are right.
        for attempts in 1..6 {
            assert!(retry_delay_secs(attempts + 1) > retry_delay_secs(attempts));
        }
        assert_eq!(retry_delay_secs(20), CLAIM_RETRY_MAX_DELAY_SECS);
    }

    #[test]
    fn delay_never_overflows_at_absurd_attempt_counts() {
        assert_eq!(retry_delay_secs(u32::MAX), CLAIM_RETRY_MAX_DELAY_SECS);
    }

    #[test]
    fn a_withdrawal_that_has_never_failed_is_due_immediately() {
        assert!(is_due(None, 0));
    }

    #[test]
    fn a_failed_withdrawal_waits_its_delay_and_no_longer() {
        let mut retry = HashMap::new();
        let state = record_failure(&mut retry, "leaf", "rpc down", 1_000);
        assert_eq!(state.attempts, 1);
        assert_eq!(state.next_attempt_unix, 1_000 + CLAIM_RETRY_BASE_DELAY_SECS);
        assert!(!is_due(retry.get("leaf"), 1_000));
        assert!(!is_due(retry.get("leaf"), 1_000 + CLAIM_RETRY_BASE_DELAY_SECS - 1));
        assert!(is_due(retry.get("leaf"), 1_000 + CLAIM_RETRY_BASE_DELAY_SECS));
    }

    #[test]
    fn repeated_failures_push_the_next_attempt_further_out() {
        let mut retry = HashMap::new();
        record_failure(&mut retry, "leaf", "still down", 0);
        let first = retry["leaf"].next_attempt_unix;
        record_failure(&mut retry, "leaf", "still down", first);
        let second = retry["leaf"].next_attempt_unix;
        assert!(second - first > first, "second wait must exceed the first");
    }

    #[test]
    fn a_withdrawal_is_exhausted_only_at_the_ceiling() {
        let mut retry = HashMap::new();
        for attempt in 1..CLAIM_RETRY_MAX_ATTEMPTS {
            record_failure(&mut retry, "leaf", "nope", 0);
            assert!(!is_exhausted(&retry["leaf"]), "exhausted early at {attempt}");
        }
        record_failure(&mut retry, "leaf", "nope", 0);
        assert!(is_exhausted(&retry["leaf"]));
        // An exhausted withdrawal is never due again, however long we wait.
        assert!(!is_due(retry.get("leaf"), u64::MAX));
    }

    #[test]
    fn the_last_reason_is_kept_for_whoever_has_to_look() {
        let mut retry = HashMap::new();
        record_failure(&mut retry, "leaf", "first", 0);
        record_failure(&mut retry, "leaf", "second", 0);
        assert_eq!(retry["leaf"].last_reason, "second");
    }

    #[test]
    fn a_successful_claim_forgets_the_history() {
        let mut retry = HashMap::new();
        record_failure(&mut retry, "leaf", "transient", 0);
        clear(&mut retry, "leaf");
        assert!(is_due(retry.get("leaf"), 0));
    }

    /// The property that matters: a permanently broken withdrawal must cost a
    /// bounded number of proofs, not one per round forever.
    #[test]
    fn a_permanently_failing_withdrawal_stops_costing_proofs() {
        let mut retry = HashMap::new();
        let mut now = 0u64;
        let mut attempts_made = 0u32;
        // A year of a 30-second daemon round.
        for _ in 0..(365 * 24 * 60 * 2) {
            now += 30;
            let entry = retry.get("leaf");
            if entry.map(is_exhausted).unwrap_or(false) {
                continue;
            }
            if is_due(entry, now) {
                attempts_made += 1;
                record_failure(&mut retry, "leaf", "unclaimable", now);
            }
        }
        assert_eq!(attempts_made, CLAIM_RETRY_MAX_ATTEMPTS);
        assert!(is_exhausted(&retry["leaf"]));
    }
}
