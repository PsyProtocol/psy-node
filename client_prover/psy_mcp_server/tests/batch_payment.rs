//! Batch payment authorization — the all-or-nothing property.
//!
//! THREAT MODEL, as elsewhere in this suite: the agent is untrusted and
//! prompt-injectable. A batch is the sharpest version of the budget problem,
//! because the naive implementation (loop over `authorize()`) charges the
//! owner's daily, 30-day and lifetime budgets for the legs that passed before
//! refusing the one that did not — burning budget on payments that never
//! happened and that no one can account for afterwards.
//!
//! The invariant every test here defends: **if a batch is refused, the spend
//! counters must be byte-identical to what they were before the call.**

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine, MAX_BATCH_PAYMENTS};

const PSY: u64 = 1_000_000_000;

fn limits(per_tx: u64, per_day: u64) -> Limits {
    Limits { per_transaction: per_tx, per_day, per_month: None, total_budget: None }
}

fn engine_with(l: Limits, recipients: Option<Vec<String>>) -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent-1", l, recipients, vec![]);
    let (token, _) = e.issue_session(&pid, 60).unwrap();
    (e, pid, token)
}

fn spent(e: &mut PolicyEngine, pid: &str) -> (u64, u64, u64) {
    let d = e.describe(pid).unwrap();
    (d.spent_today_nano, d.spent_this_month_nano, d.spent_total_nano)
}

#[test]
fn a_clean_batch_is_authorized_and_charged_exactly_once() {
    let (mut e, pid, tok) = engine_with(limits(100 * PSY, 100 * PSY), None);
    let legs = [("alice", 10 * PSY), ("bob", 20 * PSY), ("carol", 5 * PSY)];
    e.authorize_batch(&tok, &legs, "simple_transfer").expect("clean batch is allowed");
    assert_eq!(spent(&mut e, &pid), (35 * PSY, 35 * PSY, 35 * PSY), "the sum of the legs, no more and no less");
}

#[test]
fn every_leg_lands_in_the_spend_history() {
    let (mut e, _pid, tok) = engine_with(limits(100 * PSY, 100 * PSY), None);
    let legs = [("alice", 1 * PSY), ("bob", 2 * PSY)];
    e.authorize_batch(&tok, &legs, "simple_transfer").unwrap();
    let log = e.spend_log(50, None);
    assert!(log.len() >= 2, "an owner reviewing history must see each payment, not one lump");
    assert!(log.iter().any(|r| r.recipient == "alice"));
    assert!(log.iter().any(|r| r.recipient == "bob"));
}

// ── The invariant: a refused batch spends nothing ────────────────────────────

#[test]
fn a_leg_over_the_per_payment_cap_rejects_the_whole_batch_and_spends_nothing() {
    let (mut e, pid, tok) = engine_with(limits(10 * PSY, 1_000 * PSY), None);
    let before = spent(&mut e, &pid);
    // leg 1 and 3 are fine; leg 2 is over the per-payment cap.
    let legs = [("alice", 5 * PSY), ("bob", 50 * PSY), ("carol", 5 * PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("nothing was sent"), "the caller must be told the batch did not partially apply: {err}");
    assert!(err.contains("payment 2"), "the refusal must say WHICH payment: {err}");
    assert_eq!(spent(&mut e, &pid), before, "a refused batch must not consume any budget");
}

#[test]
fn the_cumulative_total_is_checked_not_just_each_leg() {
    // Each leg is individually under both caps; together they exceed the day.
    let (mut e, pid, tok) = engine_with(limits(40 * PSY, 100 * PSY), None);
    let before = spent(&mut e, &pid);
    let legs = [("alice", 40 * PSY), ("bob", 40 * PSY), ("carol", 40 * PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("daily cap"), "the running total must be charged against the day: {err}");
    assert_eq!(spent(&mut e, &pid), before, "still nothing spent");
}

#[test]
fn a_non_allowlisted_recipient_anywhere_rejects_the_whole_batch() {
    let (mut e, pid, tok) = engine_with(
        limits(100 * PSY, 1_000 * PSY),
        Some(vec!["alice".into(), "bob".into()]),
    );
    let before = spent(&mut e, &pid);
    let legs = [("alice", 1 * PSY), ("mallory", 1 * PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("allowlist"), "{err}");
    assert_eq!(spent(&mut e, &pid), before, "the allowlisted leg must not slip through on its own");
}

#[test]
fn a_paused_policy_refuses_the_batch() {
    let (mut e, pid, tok) = engine_with(limits(100 * PSY, 1_000 * PSY), None);
    e.pause(&pid);
    let before = spent(&mut e, &pid);
    let legs = [("alice", 1 * PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("paused"), "{err}");
    assert_eq!(spent(&mut e, &pid), before);
}

#[test]
fn refusals_are_visible_to_the_owner_as_blocked_attempts() {
    let (mut e, _pid, tok) = engine_with(limits(10 * PSY, 1_000 * PSY), None);
    let legs = [("alice", 5 * PSY), ("bob", 50 * PSY)];
    let _ = e.authorize_batch(&tok, &legs, "simple_transfer");
    let blocked = e.denied_log(50, None);
    assert!(
        blocked.iter().any(|d| d.recipient == "bob"),
        "an owner reviewing blocked attempts must see the refused payment",
    );
}

#[test]
fn a_refused_leg_does_not_cascade_into_spurious_refusals() {
    // bob alone blows the day; alice and carol are affordable on their own. Only
    // bob should be reported — bob's amount must not be counted against the
    // budget when judging carol, or carol gets refused for a payment that was
    // never going to happen.
    let (mut e, _pid, tok) = engine_with(limits(100 * PSY, 30 * PSY), None);
    let legs = [("alice", 10 * PSY), ("bob", 90 * PSY), ("carol", 10 * PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("1 of 3 payments"), "only bob should be refused: {err}");
    assert!(err.contains("payment 2"), "{err}");
    assert!(!err.contains("payment 3"), "carol was affordable and must not be blamed: {err}");
}

// ── Shape guards ─────────────────────────────────────────────────────────────

#[test]
fn an_empty_batch_is_refused() {
    let (mut e, _pid, tok) = engine_with(limits(100 * PSY, 1_000 * PSY), None);
    assert!(e.authorize_batch(&tok, &[], "simple_transfer").is_err());
}

#[test]
fn an_oversized_batch_is_refused_before_any_evaluation() {
    let (mut e, pid, tok) = engine_with(limits(1_000 * PSY, 1_000_000 * PSY), None);
    let before = spent(&mut e, &pid);
    let legs: Vec<(&str, u64)> = (0..=MAX_BATCH_PAYMENTS).map(|_| ("alice", 1 * PSY)).collect();
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("nothing was sent"), "{err}");
    assert_eq!(spent(&mut e, &pid), before);
}

#[test]
fn a_batch_needs_a_valid_live_session() {
    let (mut e, _pid, tok) = engine_with(limits(100 * PSY, 1_000 * PSY), None);
    assert!(e.authorize_batch("not-a-token", &[("alice", 1 * PSY)], "simple_transfer").is_err());
    e.expire_session_for_test(&tok);
    assert!(e.authorize_batch(&tok, &[("alice", 1 * PSY)], "simple_transfer").is_err());
}

#[test]
fn a_disallowed_method_refuses_the_batch() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent-1", limits(100 * PSY, 1_000 * PSY), None, vec!["simple_claim".into()]);
    let (tok, _) = e.issue_session(&pid, 60).unwrap();
    let before = spent(&mut e, &pid);
    let err = e
        .authorize_batch(&tok, &[("alice", 1 * PSY)], "simple_transfer")
        .unwrap_err()
        .to_string();
    assert!(err.contains("not allowed"), "{err}");
    assert_eq!(spent(&mut e, &pid), before);
}

#[test]
fn a_repeated_recipient_is_allowed_and_charged_twice() {
    // Deliberately different from the Mode-A wallet, which rejects duplicates to
    // catch a human typing a payee twice. An agent paying one seller for two
    // items is ordinary; the caps still bound the total.
    let (mut e, pid, tok) = engine_with(limits(100 * PSY, 1_000 * PSY), None);
    e.authorize_batch(&tok, &[("alice", 3 * PSY), ("alice", 4 * PSY)], "simple_transfer").unwrap();
    assert_eq!(spent(&mut e, &pid).0, 7 * PSY);
}
