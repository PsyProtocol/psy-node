//! An owner edit must change ONLY what the owner touched.
//!
//! update_policy used to take a whole Limits and assign it wholesale, so every
//! edit was a full replacement of fields the caller may not have been thinking
//! about. The dashboard's Permissions page has no lifetime-budget field and
//! never sent one — so tightening a DAILY limit silently deleted the lifetime
//! cap. Requiring both caps on every call also forced an owner editing only the
//! allow-list to resend numbers they were not changing, where any stale value
//! silently became the new budget.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

const PSY: u64 = 1_000_000_000;

fn engine() -> (PolicyEngine, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(
        "shopper",
        Limits {
            per_transaction: 5 * PSY,
            per_day: 50 * PSY,
            per_month: Some(500 * PSY),
            total_budget: Some(1_000 * PSY),
        },
        Some(vec!["1908736".into()]),
        vec![],
    );
    (e, pid)
}

#[test]
fn a_daily_limit_edit_does_not_delete_the_lifetime_cap() {
    // The exact dashboard bug: the Permissions page sends no totalPsy.
    let (mut e, pid) = engine();
    e.update_policy(&pid, None, Some(10 * PSY), None, None, None, vec![]).unwrap();
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.per_day_nano, 10 * PSY, "the edit applied");
    assert_eq!(d.total_budget_nano, Some(1_000 * PSY), "the lifetime cap SURVIVED");
    assert_eq!(d.per_month_nano, Some(500 * PSY), "so did the 30-day cap");
    assert_eq!(d.per_transaction_nano, 5 * PSY, "and the untouched per-payment cap");
}

#[test]
fn an_allowlist_edit_does_not_disturb_any_cap() {
    let (mut e, pid) = engine();
    e.update_policy(&pid, None, None, None, None, Some(Some(vec!["630784".into()])), vec![])
        .unwrap();
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.allowed_recipient_count, Some(1));
    assert_eq!(d.per_transaction_nano, 5 * PSY);
    assert_eq!(d.per_day_nano, 50 * PSY);
    assert_eq!(d.per_month_nano, Some(500 * PSY));
    assert_eq!(d.total_budget_nano, Some(1_000 * PSY));
}

#[test]
fn a_cap_edit_does_not_widen_the_allowlist() {
    let (mut e, pid) = engine();
    e.update_policy(&pid, Some(1 * PSY), None, None, None, None, vec![]).unwrap();
    assert_eq!(
        e.describe(&pid).unwrap().allowed_recipient_count,
        Some(1),
        "omitting recipients must never mean 'pay anyone'",
    );
}

#[test]
fn an_explicit_null_removes_a_cap() {
    // "Omit = unchanged" still has to leave a way to REMOVE a limit.
    let (mut e, pid) = engine();
    e.update_policy(&pid, None, None, Some(None), Some(None), None, vec![]).unwrap();
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.per_month_nano, None, "an explicit null clears the 30-day cap");
    assert_eq!(d.total_budget_nano, None, "and the lifetime cap");
}

#[test]
fn a_cap_can_still_be_set_to_a_new_value() {
    let (mut e, pid) = engine();
    e.update_policy(&pid, None, None, Some(Some(200 * PSY)), Some(Some(400 * PSY)), None, vec![])
        .unwrap();
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.per_month_nano, Some(200 * PSY));
    assert_eq!(d.total_budget_nano, Some(400 * PSY));
}

#[test]
fn an_empty_edit_changes_nothing_at_all() {
    let (mut e, pid) = engine();
    let before = e.describe(&pid).unwrap();
    e.update_policy(&pid, None, None, None, None, None, vec![]).unwrap();
    let after = e.describe(&pid).unwrap();
    assert_eq!(after.per_transaction_nano, before.per_transaction_nano);
    assert_eq!(after.per_day_nano, before.per_day_nano);
    assert_eq!(after.per_month_nano, before.per_month_nano);
    assert_eq!(after.total_budget_nano, before.total_budget_nano);
    assert_eq!(after.allowed_recipient_count, before.allowed_recipient_count);
    assert_eq!(after.allowed_methods, before.allowed_methods);
}

#[test]
fn a_tightened_cap_still_binds_the_live_session_immediately() {
    let (mut e, pid) = engine();
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    e.authorize(&t, "1908736", 3 * PSY, "simple_transfer").unwrap();
    e.update_policy(&pid, Some(1 * PSY), None, None, None, None, vec![]).unwrap();
    let err = e.authorize(&t, "1908736", 2 * PSY, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("per-transaction cap"), "{err}");
    assert_eq!(e.describe(&pid).unwrap().spent_today_nano, 3 * PSY, "spent counters survive the edit");
}
