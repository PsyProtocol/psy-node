//! How many times a withdrawal claim is retried before it is given up on.
//!
//! Every failure used to mean "retry next round, forever". The pending set is
//! durable, so a withdrawal that could never be claimed was re-attempted every
//! round and across restarts — and an attempt asks prove-proxy for a Groth16
//! batch proof. One bad withdrawal burned prover time indefinitely. That is
//! what happened in production, with a withdrawal whose recipient was all
//! zeroes and whose destination chain index was not ours; Bridge.sol reverts
//! both before it touches the token, so no number of retries could have helped.
//!
//! The rule is a count and nothing else: try, retry twice, give up.
//!
//! Giving up is not discarding. The funds are genuinely stuck and need a
//! person, so the withdrawal and its last failure reason move to a retired set
//! and are logged at error level.
//!
//! Two things make a plain count safe enough without any backoff:
//!
//! * A round already absorbs short outages on its own. `claim_withdrawals`
//!   polls psy-services for the claim proof 12 times at 5s intervals before it
//!   reports failure, so a minute of unavailability costs no attempts at all.
//! * Waiting for bridge liquidity is reported as a deferral rather than a
//!   failure, so a withdrawal parked behind an empty bridge does not spend its
//!   attempts while it waits.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Attempts before a claim is retired: the first try plus two retries.
pub const CLAIM_MAX_ATTEMPTS: u32 = 3;

/// Per-withdrawal attempt count, keyed by leaf_hash in the daemon state.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAttempts {
    #[serde(default)]
    pub attempts: u32,
    /// Why the last attempt failed, carried into the retired set so whoever
    /// picks it up has something to work from.
    #[serde(default)]
    pub last_reason: String,
}

/// A withdrawal that has used up its attempts. Nothing retries these.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetiredClaim<W> {
    pub withdrawal: W,
    pub attempts: u32,
    pub last_reason: String,
    pub retired_at_unix: u64,
}

pub fn is_exhausted(state: &ClaimAttempts) -> bool {
    state.attempts >= CLAIM_MAX_ATTEMPTS
}

/// Should this withdrawal be handed to the claim path again?
pub fn is_retriable(state: Option<&ClaimAttempts>) -> bool {
    !state.map(is_exhausted).unwrap_or(false)
}

pub fn record_failure(
    attempts: &mut HashMap<String, ClaimAttempts>,
    leaf_hash: &str,
    reason: &str,
) -> ClaimAttempts {
    let entry = attempts.entry(leaf_hash.to_string()).or_default();
    entry.attempts = entry.attempts.saturating_add(1);
    entry.last_reason = reason.to_string();
    entry.clone()
}

/// Forget a withdrawal's history, after it is claimed or retired.
pub fn clear(attempts: &mut HashMap<String, ClaimAttempts>, leaf_hash: &str) {
    attempts.remove(leaf_hash);
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
    fn a_withdrawal_that_has_never_failed_is_retriable() {
        assert!(is_retriable(None));
    }

    #[test]
    fn the_first_try_and_two_retries_are_allowed_and_no_more() {
        let mut attempts = HashMap::new();
        for n in 1..CLAIM_MAX_ATTEMPTS {
            record_failure(&mut attempts, "leaf", "nope");
            assert!(is_retriable(attempts.get("leaf")), "gave up after {n} attempt(s)");
        }
        record_failure(&mut attempts, "leaf", "nope");
        assert_eq!(attempts["leaf"].attempts, CLAIM_MAX_ATTEMPTS);
        assert!(!is_retriable(attempts.get("leaf")));
    }

    #[test]
    fn the_last_reason_is_kept_for_whoever_has_to_look() {
        let mut attempts = HashMap::new();
        record_failure(&mut attempts, "leaf", "first");
        record_failure(&mut attempts, "leaf", "second");
        assert_eq!(attempts["leaf"].last_reason, "second");
    }

    #[test]
    fn a_successful_claim_forgets_the_history() {
        let mut attempts = HashMap::new();
        record_failure(&mut attempts, "leaf", "transient");
        clear(&mut attempts, "leaf");
        assert!(is_retriable(attempts.get("leaf")));
    }
}
