//! The owner's record of real payments must not be erasable by the agent.
//!
//! Both logs are 100-entry rings and EVERY authorization writes a row —
//! including amount-0 claim gates and attempts that were refunded, neither of
//! which moved money and neither of which needs funds or chain success. Under
//! plain FIFO, roughly a hundred deliberately-failed calls evicted every
//! genuine payment from the only history the owner has, and the dashboard's
//! Activity page reads exactly this log.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine, SELF_RECIPIENT};

const PSY: u64 = 1_000_000_000;

fn engine() -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent-1",
        Limits { per_transaction: 1_000 * PSY, per_day: 1_000_000 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    (e, pid, t)
}

#[test]
fn a_flood_of_claim_gates_cannot_erase_a_real_payment() {
    let (mut e, _pid, tok) = engine();
    e.authorize(&tok, "alice", 42 * PSY, "simple_transfer").unwrap();

    // Claims authorize with amount 0, need no funds and no chain success.
    for _ in 0..300 {
        e.authorize(&tok, SELF_RECIPIENT, 0, "simple_claim").unwrap();
    }

    let log = e.spend_log(200, None);
    assert!(
        log.iter().any(|r| r.recipient == "alice" && r.amount_nano == 42 * PSY),
        "the real payment must survive a flood of zero-amount gates",
    );
}

#[test]
fn a_flood_of_refunded_attempts_cannot_erase_a_real_payment() {
    let (mut e, _pid, tok) = engine();
    e.authorize(&tok, "alice", 42 * PSY, "simple_transfer").unwrap();

    // Every one of these is authorized then refunded — nothing moved.
    for _ in 0..300 {
        let auth = e.authorize(&tok, "bob", 1 * PSY, "simple_transfer").unwrap();
        e.refund(&auth, 1 * PSY);
    }

    let log = e.spend_log(200, None);
    assert!(
        log.iter().any(|r| r.recipient == "alice" && r.amount_nano == 42 * PSY),
        "the real payment must survive a flood of refunded attempts",
    );
}

#[test]
fn the_ring_is_still_bounded() {
    let (mut e, _pid, tok) = engine();
    for _ in 0..300 {
        e.authorize(&tok, SELF_RECIPIENT, 0, "simple_claim").unwrap();
    }
    assert!(e.spend_log_len() <= 100, "bounded memory is not negotiable either");
}

#[test]
fn real_payments_still_age_out_when_they_are_all_that_is_left() {
    // Protecting real payments must not mean keeping them forever — that would
    // be an unbounded ring by another name.
    let (mut e, _pid, tok) = engine();
    for i in 1..=150u64 {
        e.authorize(&tok, "alice", i * PSY, "simple_transfer").unwrap();
    }
    assert!(e.spend_log_len() <= 100);
    let log = e.spend_log(200, None);
    assert!(log.iter().any(|r| r.amount_nano == 150 * PSY), "newest survives");
    assert!(!log.iter().any(|r| r.amount_nano == 1 * PSY), "oldest real payment did age out");
}

#[test]
fn a_flood_evicts_the_earliest_refusal_and_SAYS_SO() {
    // This used to assert that a refusal naming a real amount survived a flood
    // of zero-amount ones, because eviction preferred to drop the zero-amount
    // rows. That protection was an illusion: `amount` is chosen by the CALLER,
    // so a flood naming amount=1 matched nothing and eviction fell through to
    // plain FIFO — evicting the "protected" row FIRST, since it was the oldest.
    // The test passed only because it fed the heuristic the one input it
    // handled.
    //
    // The ring is now honest FIFO and the loss is COUNTED, so what a reader
    // must be able to tell is not "the important row survived" (it cannot be
    // promised) but "rows were lost" (which can).
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent-1",
        Limits { per_transaction: 5 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
        None,
        vec!["simple_transfer".into()],
    );
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    let _ = e.authorize(&tok, "mallory", 99 * PSY, "simple_transfer");
    for _ in 0..300 {
        let _ = e.authorize(&tok, SELF_RECIPIENT, 0, "simple_claim");
    }
    let blocked = e.denied_log(200, None);
    assert!(
        !blocked.iter().any(|d| d.recipient == "mallory"),
        "300 later refusals push it out — pretending otherwise is the bug",
    );
    assert!(
        e.denied_log_dropped() >= 200,
        "and the owner is told the view is truncated: dropped={}",
        e.denied_log_dropped(),
    );
}

// ── the flood the old heuristic could not survive ──────────────────────
//
// The denied ring used to prefer evicting a zero-amount refusal so a row
// naming a real amount would survive. But `amount` is chosen by the CALLER, so
// a flood of amount=1 denials matched nothing, `position` returned None, and
// eviction fell through to `unwrap_or(0)` — exact FIFO, evicting the protected
// high-value row FIRST because it was the oldest. The heuristic degraded
// precisely when it was under attack, and the earlier test in this file only
// ever floods with amount=0: the one shape it handled.
//
// A denial costs nothing — no funds, no chain call, no budget, no rate limit —
// so ~101 refused calls is a complete wipe. It cannot be defended by ranking
// rows on a field the agent controls, so the ring is FIFO and the loss is
// COUNTED instead.

/// A policy tight enough that every authorize below is REFUSED — otherwise the
/// "denials" would be ordinary spends and the ring under test stays empty.
fn tight_engine() -> (PolicyEngine, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent-1",
        Limits { per_transaction: 1, per_day: 1, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    (e, t)
}

#[test]
fn a_flood_of_nonzero_denials_is_counted_not_silent() {
    let (mut e, tok) = tight_engine();

    // One real, high-value refusal we would want to remember.
    let _ = e.authorize(&tok, "mallory", 99_000_000_000, "simple_transfer");
    assert_eq!(e.denied_log_dropped(), 0, "nothing dropped yet");

    // The attacker's flood: every row carries a nonzero, attacker-chosen
    // amount, which the old heuristic could not match.
    for _ in 0..120 {
        let _ = e.authorize(&tok, "mallory", 2, "simple_transfer");
    }

    assert!(
        e.denied_log_dropped() >= 20,
        "the wipe must be visible, not silent: dropped={}",
        e.denied_log_dropped()
    );
    assert_eq!(e.denied_log_len(), 100, "the ring is still capped");
}

#[test]
fn an_untouched_ring_reports_nothing_dropped() {
    let (mut e, tok) = tight_engine();
    let _ = e.authorize(&tok, "bob", 99_000_000_000, "simple_transfer");
    assert_eq!(e.denied_log_dropped(), 0);
    assert_eq!(e.spend_log_dropped(), 0);
    assert_eq!(e.denied_log_len(), 1);
}
