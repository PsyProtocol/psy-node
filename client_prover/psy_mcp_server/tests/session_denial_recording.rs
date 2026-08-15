//! An attempt the wallet refused is what the owner needs to see — whether the
//! refusal came from a spending cap or from a dead session token.
//!
//! Session-level refusals used to bail before record_denial ran, so the single
//! highest-signal scenario in the product — owner hits Revoke, agent keeps
//! hammering transfer — produced ZERO rows in get_blocked, while the tool said
//! "Nothing has been blocked — every attempt so far was within your rules."

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
    let (tok, _) = e.issue_session(&pid, 60).unwrap();
    (e, pid, tok)
}

#[test]
fn revoke_then_hammer_is_recorded_not_silent() {
    let (mut e, _pid, tok) = engine();
    assert!(e.authorize(&tok, "1234", PSY, "simple_transfer").is_ok(), "baseline spend works");

    assert!(e.revoke(&tok), "owner revokes the session");

    for _ in 0..5 {
        assert!(e.authorize(&tok, "1234", PSY, "simple_transfer").is_err());
    }

    let blocked = e.denied_log(50, None);
    assert_eq!(blocked.len(), 5, "every attempt after the revoke is on the record");
    assert!(
        blocked.iter().all(|d| d.reason.contains("revoked") || d.reason.contains("not valid")),
        "the reason says the token is dead: {:?}",
        blocked.first().map(|d| &d.reason)
    );
    assert!(
        blocked.iter().all(|d| d.recipient == "1234" && d.amount_nano == PSY),
        "and what it TRIED is preserved, not just that it failed",
    );
}

#[test]
fn an_expired_session_records_its_refusal_and_says_what_to_do() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "agent-1",
        Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    // ttl 0 sets expires_at == now, and the gate is `now > expires_at`, so it
    // is not yet lapsed. Wait past the second boundary rather than asserting on
    // an equality the gate deliberately does not treat as expired.
    let (tok, _) = e.issue_session(&pid, 0).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert!(e.authorize(&tok, "9999", 5 * PSY, "simple_transfer").is_err());

    let blocked = e.denied_log(10, None);
    assert_eq!(blocked.len(), 1);
    assert!(blocked[0].reason.contains("expired"), "{}", blocked[0].reason);
    assert!(blocked[0].reason.contains("issue_session"), "it names the remedy: {}", blocked[0].reason);
    assert_eq!(blocked[0].amount_nano, 5 * PSY);
}

#[test]
fn a_garbage_token_is_recorded_against_no_policy() {
    let (mut e, _pid, _tok) = engine();
    assert!(e.authorize("not-a-real-token", "1234", PSY, "simple_transfer").is_err());
    let blocked = e.denied_log(10, None);
    assert_eq!(blocked.len(), 1, "an unauthenticated attempt is still an attempt");
    assert_eq!(blocked[0].policy_id, "-", "it names no policy, and the reader surfaces it anyway");
}

#[test]
fn a_valid_session_still_records_nothing_extra() {
    // Regression guard: the resolver must not record on the happy path.
    let (mut e, _pid, tok) = engine();
    assert!(e.authorize(&tok, "1234", PSY, "simple_transfer").is_ok());
    assert_eq!(e.denied_log(10, None).len(), 0);
}

#[test]
fn an_oversized_batch_is_recorded_too() {
    let (mut e, _pid, tok) = engine();
    let legs: Vec<(&str, u64)> = (0..500).map(|_| ("1234", 1u64)).collect();
    assert!(e.authorize_batch(&tok, &legs, "simple_transfer").is_err());
    let blocked = e.denied_log(10, None);
    assert_eq!(blocked.len(), 1, "a refused batch shape is a refused attempt");
    assert!(blocked[0].reason.contains("batch"), "{}", blocked[0].reason);
}

#[test]
fn a_revoked_token_on_the_BATCH_path_is_recorded() {
    let (mut e, _pid, tok) = engine();
    e.revoke(&tok);
    let legs: Vec<(&str, u64)> = vec![("1234", PSY)];
    assert!(e.authorize_batch(&tok, &legs, "simple_transfer").is_err());
    let blocked = e.denied_log(10, None);
    assert_eq!(blocked.len(), 1);
    assert_eq!(blocked[0].amount_nano, PSY, "the batch total is what it tried to move");
}
