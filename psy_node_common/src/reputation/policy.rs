//! Worker reputation rules as pure functions of a record, an event and the clock.
//! Storage, compare-and-set and logging live in `worker_reputation_ops`.

use psy_node_core::psy_temp_db::{JobClaimRecord, WorkerReputationRecord};

use crate::constants::worker_reputation::{
    MAX_WORKER_REPUTATION, REPUTATION_COOLDOWN_BASE_MS, REPUTATION_COOLDOWN_MAX_MS, REPUTATION_INVALID_PROOF_PENALTY,
    REPUTATION_LEASE_EXPIRY_PENALTY, REPUTATION_ON_TIME_REWARD, REPUTATION_STRIKE_RESET_STREAK,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationEvent {
    /// A verified proof submitted within the lease.
    OnTimeSuccess,
    /// A verified proof submitted after the lease while its claim was still current.
    LateSuccess,
    /// A claim outlived its lease without a submit and the job was claimed again.
    LeaseExpired,
    /// A submitted proof was malformed or failed verification.
    InvalidProof,
}

impl ReputationEvent {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::OnTimeSuccess => "on_time_success",
            Self::LateSuccess => "late_success",
            Self::LeaseExpired => "lease_expiry",
            Self::InvalidProof => "invalid_proof",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Eligibility {
    Eligible,
    /// The score is zero and the cooldown is over: one claim may be reserved.
    Probation,
    NotEligible { retry_at_ms: u64 },
}

/// Cooldown at zero after `strikes` strikes: 2, 4, 8, 16, 32 minutes, then 60.
pub fn cooldown_ms(strikes: u8) -> u64 {
    // Past 16 doublings the cap has long applied; bounding the shift keeps it from overflowing.
    let doublings = u32::from(strikes.max(1) - 1).min(16);
    (REPUTATION_COOLDOWN_BASE_MS << doublings).min(REPUTATION_COOLDOWN_MAX_MS)
}

/// When a zero score's cooldown ends, if it has not ended yet.
fn cooldown_until(record: &WorkerReputationRecord, now_ms: u64) -> Option<u64> {
    if record.score > 0 {
        return None;
    }
    let until = record.last_penalty_ms.saturating_add(cooldown_ms(record.strikes));
    (now_ms < until).then_some(until)
}

pub fn eligibility(record: &WorkerReputationRecord, now_ms: u64, lease_ms: u64) -> Eligibility {
    if record.score > 0 {
        return Eligibility::Eligible;
    }
    if let Some(retry_at_ms) = cooldown_until(record, now_ms) {
        return Eligibility::NotEligible { retry_at_ms };
    }
    if record.probation_claim_ms != 0 {
        let retry_at_ms = record.probation_claim_ms.saturating_add(lease_ms);
        if now_ms < retry_at_ms {
            return Eligibility::NotEligible { retry_at_ms };
        }
    }
    Eligibility::Probation
}

/// The record after `event`, or `None` when the event changes nothing.
///
/// A late success leaves a positive score alone, but lifts a zero score to 1: the worker delivered
/// a verified proof that nobody else had re-claimed, and a worker whose proofs outlast the lease
/// would otherwise never leave probation.
///
/// A penalty that lands while a zero score is cooling down is absorbed: it comes from a claim made
/// before the score reached zero, and charging it would stack strikes for one outage.
pub fn apply(record: &WorkerReputationRecord, event: ReputationEvent, now_ms: u64) -> Option<WorkerReputationRecord> {
    let penalty = match event {
        ReputationEvent::LateSuccess => {
            if record.score > 0 {
                return None;
            }
            return Some(WorkerReputationRecord {
                score: 1,
                probation_claim_ms: 0,
                ..*record
            });
        }
        ReputationEvent::OnTimeSuccess => {
            let mut next = *record;
            next.score = record.score.saturating_add(REPUTATION_ON_TIME_REWARD).min(MAX_WORKER_REPUTATION);
            next.probation_claim_ms = 0;
            next.streak = record.streak.saturating_add(1);
            if next.streak >= REPUTATION_STRIKE_RESET_STREAK {
                next.strikes = 0;
                next.streak = 0;
            }
            return (next != *record).then_some(next);
        }
        ReputationEvent::LeaseExpired => REPUTATION_LEASE_EXPIRY_PENALTY,
        ReputationEvent::InvalidProof => REPUTATION_INVALID_PROOF_PENALTY,
    };
    if cooldown_until(record, now_ms).is_some() {
        return None;
    }
    let mut next = *record;
    next.score = record.score.saturating_sub(penalty);
    next.streak = 0;
    next.last_penalty_ms = now_ms;
    if next.score == 0 {
        next.strikes = record.strikes.saturating_add(1);
    }
    Some(next)
}

/// Reserves the probation slot at `now_ms`. Zero means "no slot", so it is never stored.
pub fn reserve_probation(record: &WorkerReputationRecord, now_ms: u64) -> WorkerReputationRecord {
    WorkerReputationRecord {
        probation_claim_ms: now_ms.max(1),
        ..*record
    }
}

/// Frees a slot reserved at `reserved_at_ms`, unless it has since been used or replaced.
pub fn release_probation(record: &WorkerReputationRecord, reserved_at_ms: u64) -> Option<WorkerReputationRecord> {
    (record.probation_claim_ms == reserved_at_ms).then_some(WorkerReputationRecord {
        probation_claim_ms: 0,
        ..*record
    })
}

/// Whether the previous claim of a job being claimed again lapsed through its holder's fault.
/// A redelivery sooner than one full lease (consumer recreation, Edge restart) is not.
pub fn previous_claim_lapsed(previous: &JobClaimRecord, already_submitted: bool, now_ms: u64, lease_ms: u64) -> bool {
    !previous.settled && !already_submitted && now_ms.saturating_sub(previous.claim_time_ms) >= lease_ms
}

pub fn submit_event(claim_time_ms: u64, now_ms: u64, lease_ms: u64) -> ReputationEvent {
    if now_ms.saturating_sub(claim_time_ms) <= lease_ms {
        ReputationEvent::OnTimeSuccess
    } else {
        ReputationEvent::LateSuccess
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60_000;
    const LEASE: u64 = 30_000;

    fn rec(score: u64) -> WorkerReputationRecord {
        WorkerReputationRecord {
            score,
            ..WorkerReputationRecord::initial()
        }
    }

    #[test]
    fn on_time_success_adds_one_up_to_fifteen() {
        assert_eq!(apply(&rec(5), ReputationEvent::OnTimeSuccess, 0).unwrap().score, 6);
        assert_eq!(apply(&rec(14), ReputationEvent::OnTimeSuccess, 0).unwrap().score, 15);
        let at_cap = WorkerReputationRecord { streak: 1, ..rec(15) };
        assert_eq!(apply(&at_cap, ReputationEvent::OnTimeSuccess, 0).unwrap().score, 15);
    }

    #[test]
    fn late_success_leaves_a_positive_score_alone() {
        assert_eq!(apply(&rec(5), ReputationEvent::LateSuccess, 0), None);
    }

    #[test]
    fn late_success_ends_probation() {
        let reserved = reserve_probation(&WorkerReputationRecord { strikes: 3, ..rec(0) }, 50);
        let next = apply(&reserved, ReputationEvent::LateSuccess, 50 + 2 * LEASE).unwrap();
        assert_eq!((next.score, next.probation_claim_ms, next.strikes, next.streak), (1, 0, 3, 0));
    }

    #[test]
    fn penalties_floor_at_zero_and_record_the_time() {
        let next = apply(&rec(15), ReputationEvent::LeaseExpired, 7).unwrap();
        assert_eq!((next.score, next.last_penalty_ms, next.strikes), (14, 7, 0));
        let next = apply(&rec(15), ReputationEvent::InvalidProof, 7).unwrap();
        assert_eq!(next.score, 10);
        let next = apply(&rec(3), ReputationEvent::InvalidProof, 7).unwrap();
        assert_eq!((next.score, next.strikes), (0, 1));
    }

    #[test]
    fn reaching_zero_is_a_strike() {
        let next = apply(&rec(1), ReputationEvent::LeaseExpired, 100).unwrap();
        assert_eq!((next.score, next.strikes, next.last_penalty_ms), (0, 1, 100));
    }

    #[test]
    fn penalties_during_cooldown_are_absorbed() {
        let zero = apply(&rec(1), ReputationEvent::LeaseExpired, 0).unwrap();
        assert_eq!(apply(&zero, ReputationEvent::LeaseExpired, MIN), None);
        assert_eq!(apply(&zero, ReputationEvent::InvalidProof, 2 * MIN - 1), None);
        // After the cooldown, a failure (a probation claim) is the next strike.
        let next = apply(&zero, ReputationEvent::LeaseExpired, 2 * MIN).unwrap();
        assert_eq!((next.score, next.strikes, next.last_penalty_ms), (0, 2, 2 * MIN));
    }

    #[test]
    fn cooldown_doubles_to_an_hour() {
        let minutes: Vec<u64> = (0u8..=8).map(|s| cooldown_ms(s) / MIN).collect();
        assert_eq!(minutes, vec![2, 2, 4, 8, 16, 32, 60, 60, 60]);
        for strikes in 7..=u8::MAX {
            assert_eq!(cooldown_ms(strikes), REPUTATION_COOLDOWN_MAX_MS, "strikes {strikes}");
        }
    }

    #[test]
    fn strike_count_saturates() {
        let worn = WorkerReputationRecord { strikes: u8::MAX, ..rec(0) };
        let next = apply(&worn, ReputationEvent::LeaseExpired, u64::MAX / 2).unwrap();
        assert_eq!(next.strikes, u8::MAX);
    }

    #[test]
    fn five_on_time_successes_clear_the_strikes() {
        let mut r = WorkerReputationRecord { strikes: 4, ..rec(1) };
        for _ in 0..4 {
            r = apply(&r, ReputationEvent::OnTimeSuccess, 0).unwrap();
            assert_eq!(r.strikes, 4);
        }
        r = apply(&r, ReputationEvent::OnTimeSuccess, 0).unwrap();
        assert_eq!((r.score, r.strikes, r.streak), (6, 0, 0));
    }

    #[test]
    fn a_penalty_breaks_the_streak() {
        let r = WorkerReputationRecord { strikes: 2, streak: 4, ..rec(9) };
        let r = apply(&r, ReputationEvent::LeaseExpired, 0).unwrap();
        assert_eq!(r.streak, 0);
        let r = apply(&r, ReputationEvent::OnTimeSuccess, 0).unwrap();
        assert_eq!((r.strikes, r.streak), (2, 1));
    }

    #[test]
    fn positive_score_is_eligible() {
        assert_eq!(eligibility(&rec(1), 0, LEASE), Eligibility::Eligible);
    }

    #[test]
    fn zero_waits_out_its_cooldown_then_gets_probation() {
        let zero = WorkerReputationRecord { strikes: 2, last_penalty_ms: 1_000, ..rec(0) };
        assert_eq!(
            eligibility(&zero, 1_000 + 4 * MIN - 1, LEASE),
            Eligibility::NotEligible { retry_at_ms: 1_000 + 4 * MIN }
        );
        assert_eq!(eligibility(&zero, 1_000 + 4 * MIN, LEASE), Eligibility::Probation);
    }

    #[test]
    fn legacy_zero_record_gets_probation_at_once() {
        assert_eq!(eligibility(&rec(0), 1_760_000_000_000, LEASE), Eligibility::Probation);
    }

    #[test]
    fn one_probation_claim_per_lease() {
        let now = 1_760_000_000_000;
        let reserved = reserve_probation(&rec(0), now);
        assert_eq!(
            eligibility(&reserved, now + LEASE - 1, LEASE),
            Eligibility::NotEligible { retry_at_ms: now + LEASE }
        );
        assert_eq!(eligibility(&reserved, now + LEASE, LEASE), Eligibility::Probation);
    }

    #[test]
    fn probation_success_lifts_the_score_and_frees_the_slot() {
        let reserved = reserve_probation(&rec(0), 50);
        let next = apply(&reserved, ReputationEvent::OnTimeSuccess, 60).unwrap();
        assert_eq!((next.score, next.probation_claim_ms), (1, 0));
    }

    #[test]
    fn release_only_frees_the_same_reservation() {
        let reserved = reserve_probation(&rec(0), 50);
        assert_eq!(release_probation(&reserved, 50).unwrap().probation_claim_ms, 0);
        assert_eq!(release_probation(&reserved, 49), None);
        assert_eq!(reserve_probation(&rec(0), 0).probation_claim_ms, 1);
    }

    #[test]
    fn previous_claim_lapses_only_after_a_full_lease_unsubmitted_and_open() {
        let claim = JobClaimRecord::open([1u8; 33], 1_000);
        assert!(previous_claim_lapsed(&claim, false, 1_000 + LEASE, LEASE));
        assert!(!previous_claim_lapsed(&claim, false, 1_000 + LEASE - 1, LEASE));
        assert!(!previous_claim_lapsed(&claim, true, 1_000 + LEASE, LEASE));
        let settled = JobClaimRecord { settled: true, ..claim };
        assert!(!previous_claim_lapsed(&settled, false, 1_000 + LEASE, LEASE));
    }

    #[test]
    fn submit_is_on_time_within_the_lease() {
        assert_eq!(submit_event(1_000, 1_000 + LEASE, LEASE), ReputationEvent::OnTimeSuccess);
        assert_eq!(submit_event(1_000, 1_000 + LEASE + 1, LEASE), ReputationEvent::LateSuccess);
    }
}
