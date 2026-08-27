//! The spend log must not show money that never moved.
//!
//! Observed live against staging: a `transfer_batch` was authorized, the
//! submission failed ("insufficient balance"), the budget was correctly
//! refunded — and `get_spend_log` still reported 2 payments totalling 0.8 PSY.
//! The owner had two contradicting numbers on one screen: a history showing two
//! completed payments and a budget meter showing nothing spent.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

const PSY: u64 = 1_000_000_000;

fn engine() -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent-1",
        Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    (e, pid, t)
}

fn spent(e: &mut PolicyEngine, pid: &str) -> u64 {
    e.describe(pid).unwrap().spent_today_nano
}

#[test]
fn an_authorized_spend_is_not_marked_refunded() {
    let (mut e, _pid, tok) = engine();
    e.authorize(&tok, "alice", 5 * PSY, "simple_transfer").unwrap();
    let log = e.spend_log(10, None);
    assert_eq!(log.len(), 1);
    assert!(!log[0].refunded, "a spend that stands must not look refunded");
}

#[test]
fn a_refunded_single_payment_is_marked_in_the_log() {
    let (mut e, pid, tok) = engine();
    let auth = e.authorize(&tok, "alice", 5 * PSY, "simple_transfer").unwrap();
    e.refund(&auth, 5 * PSY);
    assert_eq!(spent(&mut e, &pid), 0, "budget restored");
    let log = e.spend_log(10, None);
    assert_eq!(log.len(), 1, "the attempt is KEPT — the owner should see it was tried");
    assert!(log[0].refunded, "but it must not read as a completed payment");
}

#[test]
fn every_leg_of_a_refunded_batch_is_marked() {
    // The live case: 2 legs authorized, submission failed, whole total refunded.
    let (mut e, pid, tok) = engine();
    let auth = e
        .authorize_batch(&tok, &[("alice", 5 * PSY), ("bob", 3 * PSY)], "simple_transfer")
        .unwrap();
    assert_eq!(spent(&mut e, &pid), 8 * PSY);
    e.refund(&auth, 8 * PSY);
    assert_eq!(spent(&mut e, &pid), 0, "budget restored in full");
    let log = e.spend_log(10, None);
    assert_eq!(log.len(), 2);
    assert!(log.iter().all(|r| r.refunded), "no leg may look like a payment that happened");
}

#[test]
fn a_refund_does_not_touch_an_unrelated_earlier_spend() {
    let (mut e, pid, tok) = engine();
    e.authorize(&tok, "alice", 5 * PSY, "simple_transfer").unwrap();
    let second = e.authorize(&tok, "bob", 2 * PSY, "simple_transfer").unwrap();
    e.refund(&second, 2 * PSY);
    assert_eq!(spent(&mut e, &pid), 5 * PSY, "only the failed one comes back");
    let log = e.spend_log(10, None);
    let alice = log.iter().find(|r| r.recipient == "alice").unwrap();
    let bob = log.iter().find(|r| r.recipient == "bob").unwrap();
    assert!(!alice.refunded);
    assert!(bob.refunded);
}

#[test]
fn refunding_twice_does_not_hand_the_budget_back_twice() {
    let (mut e, pid, tok) = engine();
    e.authorize(&tok, "carol", 10 * PSY, "simple_transfer").unwrap();
    let auth = e.authorize(&tok, "alice", 5 * PSY, "simple_transfer").unwrap();
    e.refund(&auth, 5 * PSY);
    e.refund(&auth, 5 * PSY);
    assert_eq!(spent(&mut e, &pid), 10 * PSY, "carol's spend must survive a double refund");
}

#[test]
fn spend_rows_carry_distinct_ids() {
    let (mut e, _pid, tok) = engine();
    e.authorize_batch(&tok, &[("alice", 1 * PSY), ("bob", 1 * PSY), ("carol", 1 * PSY)], "simple_transfer")
        .unwrap();
    let log = e.spend_log(10, None);
    let mut ids: Vec<u64> = log.iter().map(|r| r.id).collect();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 3, "ids must be unique or a refund marks the wrong row");
}
