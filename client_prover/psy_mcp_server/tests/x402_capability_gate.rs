//! A tool that does real work BEFORE it pays must check the session before that
//! work, or the owner's stop controls do not stop it.
//!
//! x402_fetch validated the session only at the payment step, far below the
//! network call. Everything above ran for a REVOKED or EXPIRED session and for
//! a PAUSED policy: the URL was fetched, a non-402 body was returned straight
//! into model context, and the whole dry_run branch answered normally. Pause and
//! Revoke left the agent using the wallet as a fetcher.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

const PSY: u64 = 1_000_000_000;

fn armed() -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent",
        Limits { per_transaction: 10 * PSY, per_day: 100 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    (e, pid, t)
}

#[test]
fn a_live_session_may_act() {
    let (mut e, _pid, t) = armed();
    assert!(e.check_can_act(&t, "x402_fetch").is_ok());
}

#[test]
fn a_PAUSED_policy_may_not_even_fetch() {
    let (mut e, pid, t) = armed();
    assert!(e.pause(&pid));
    let err = e.check_can_act(&t, "x402_fetch").unwrap_err().to_string();
    assert!(err.contains("paus"), "{err}");
}

#[test]
fn a_REVOKED_session_may_not_even_fetch() {
    let (mut e, _pid, t) = armed();
    assert!(e.revoke(&t));
    let err = e.check_can_act(&t, "x402_fetch").unwrap_err().to_string();
    assert!(err.contains("not valid") || err.contains("revoked"), "{err}");
}

#[test]
fn a_method_the_owner_did_not_allow_may_not_act() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent",
        Limits { per_transaction: PSY, per_day: PSY, per_month: None, total_budget: None },
        None,
        vec!["simple_transfer".into()], // x402_fetch deliberately absent
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    let err = e.check_can_act(&t, "x402_fetch").unwrap_err().to_string();
    assert!(err.contains("x402_fetch"), "the refusal names the method: {err}");
}

#[test]
fn the_check_records_NO_spend() {
    // Going through authorize(0) would log a zero-amount row for every fetch,
    // including a dry run that pays nothing — non-payments in the owner's
    // audit trail.
    let (mut e, _pid, t) = armed();
    assert!(e.check_can_act(&t, "x402_fetch").is_ok());
    assert_eq!(e.spend_log(10, None).len(), 0, "a capability check is not a spend");
}

#[test]
fn a_refusal_IS_recorded_as_a_blocked_attempt() {
    // The owner should see that a paused agent kept trying.
    let (mut e, pid, t) = armed();
    e.pause(&pid);
    let _ = e.check_can_act(&t, "x402_fetch");
    assert_eq!(e.denied_log(10, None).len(), 1, "the attempt is on the record");
}

#[test]
fn the_check_does_not_consume_budget() {
    // It must not make the later real payment fail for lack of headroom.
    let (mut e, pid, t) = armed();
    for _ in 0..5 {
        assert!(e.check_can_act(&t, "x402_fetch").is_ok());
    }
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, 0, "checking is free");
    assert!(e.authorize(&t, "1234", 10 * PSY, "x402_fetch").is_ok(), "full per-tx cap still available");
}

#[test]
fn the_allowlist_is_NOT_applied_at_check_time() {
    // The payee comes from the 402 challenge and is not known yet; applying the
    // allow-list here would refuse every fetch on an allow-listed policy.
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent",
        Limits { per_transaction: PSY, per_day: PSY, per_month: None, total_budget: None },
        Some(vec!["1234".into()]),
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.check_can_act(&t, "x402_fetch").is_ok(), "an allow-listed policy may still fetch");
}
