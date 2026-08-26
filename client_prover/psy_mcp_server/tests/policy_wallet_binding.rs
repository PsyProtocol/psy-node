//! A policy is a budget for ONE wallet.
//!
//! `create_wallet(mode="load")` replaces the process's wallet globally, and
//! nothing tied a policy to an identity — so an agent could point at another of
//! the owner's key backups (their names are structured and sit in the same
//! keystore dir) and operate a richer wallet under the caps sized for the
//! first. The spent counters cut both ways too: the second wallet inherits the
//! first's exhausted budget, or resets it.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

const PSY: u64 = 1_000_000_000;

fn limits() -> Limits {
    Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None }
}

#[test]
fn a_policy_created_for_one_wallet_refuses_another() {
    let mut e = PolicyEngine::new();
    e.set_current_user(111);
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_ok(), "its own wallet spends fine");

    // The process swaps identity underneath the policy.
    e.set_current_user(222);
    let err = e
        .authorize(&tok, "1", PSY, "simple_transfer")
        .expect_err("a policy must not govern a wallet it was not created for");
    let msg = err.to_string();
    assert!(msg.contains("Psy-00000111"), "it names the wallet the policy is for: {msg}");
    assert!(msg.contains("Psy-00000222"), "and the one actually loaded: {msg}");
    assert!(msg.contains("do not transfer"), "{msg}");
}

#[test]
fn the_refusal_is_recorded_as_a_blocked_attempt() {
    // This is the shape of an agent pointing at another of the owner's backups.
    // It must be visible in the audit trail, not just returned to the caller.
    let mut e = PolicyEngine::new();
    e.set_current_user(111);
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    e.set_current_user(222);
    let _ = e.authorize(&tok, "9", 7 * PSY, "simple_transfer");

    let blocked = e.denied_log(10, None);
    assert_eq!(blocked.len(), 1, "the attempt is on the record");
    assert_eq!(blocked[0].amount_nano, 7 * PSY, "and what it tried to move");
    assert!(blocked[0].reason.contains("one wallet"), "{}", blocked[0].reason);
}

#[test]
fn returning_to_the_right_wallet_works_again() {
    // The refusal is about identity, not a permanent lockout.
    let mut e = PolicyEngine::new();
    e.set_current_user(111);
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    e.set_current_user(222);
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_err());
    e.set_current_user(111);
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_ok(), "back on its own wallet");
}

#[test]
fn a_persisted_policy_names_the_wallet_mismatch_after_an_in_process_swap() {
    let dir = std::env::temp_dir().join(format!(
        "psy-policy-wallet-swap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut e = PolicyEngine::load_or_new(&dir);
    e.set_current_user(111);
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();

    e.set_current_user(222);
    let msg = e.authorize(&tok, "1", PSY, "simple_transfer")
        .expect_err("a persisted policy must remain visible to the binding gate")
        .to_string();
    assert!(msg.contains("Psy-00000111"), "{msg}");
    assert!(msg.contains("Psy-00000222"), "{msg}");
    assert!(!msg.contains("no longer exists"), "{msg}");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_policy_written_before_this_binds_on_first_use_rather_than_locking_out() {
    // Back-compat: policies persisted before the binding existed have no
    // bound_user_id. Refusing them would brick every existing deployment;
    // binding on first spend upgrades them safely.
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("legacy", limits(), None, vec![]); // no current user yet
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();

    e.set_current_user(555);
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_ok(), "first use binds, does not refuse");

    // ...and from then on it is checked like any other.
    e.set_current_user(666);
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_err(), "bound on first use, enforced after");
}

#[test]
fn with_no_wallet_loaded_the_gate_stays_out_of_the_way() {
    // The spend cannot execute anyway; refusing here would replace a clear
    // "no wallet loaded" error with a confusing identity mismatch.
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_ok());
}

#[test]
fn the_batch_path_is_gated_too() {
    let mut e = PolicyEngine::new();
    e.set_current_user(111);
    let pid = e.create_policy("agent", limits(), None, vec![]);
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    e.set_current_user(222);
    let legs: Vec<(&str, u64)> = vec![("1", PSY), ("2", PSY)];
    let err = e.authorize_batch(&tok, &legs, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("one wallet"), "{err}");
    assert_eq!(e.denied_log(10, None).len(), 1, "recorded on the batch path too");
}

#[test]
fn spent_counters_do_not_leak_between_wallets() {
    // The counters are the other half: without binding, wallet B would inherit
    // A's exhausted budget (or reset it).
    let mut e = PolicyEngine::new();
    e.set_current_user(111);
    let pid = e.create_policy(
        "agent",
        Limits { per_transaction: 10 * PSY, per_day: 10 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (tok, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&tok, "1", 9 * PSY, "simple_transfer").is_ok());

    // Wallet B must not be able to spend against A's remaining 1 PSY, nor be
    // charged for A's 9.
    e.set_current_user(222);
    assert!(e.authorize(&tok, "1", PSY, "simple_transfer").is_err(), "B cannot draw on A's policy at all");
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, 9 * PSY, "A's counter is untouched by B's attempt");
}
