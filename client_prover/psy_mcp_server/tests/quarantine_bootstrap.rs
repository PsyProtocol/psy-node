//! A corrupt policy file must not become a way to mint an unlimited policy.
//!
//! `creation_widens` exempts the first-ever creation, because a fresh server
//! has nothing to compare against and refusing would make it unusable. That
//! exemption keys off the policy set being EMPTY — and an unreadable or
//! unparseable policy file also produces an empty set. Without the distinction,
//! the widening gate is defeated by emptying the set it compares against
//! rather than by beating it.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("psy-quarantine-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const NANO: u64 = 1_000_000_000;

fn wide() -> Limits {
    Limits { per_transaction: u64::MAX, per_day: u64::MAX, per_month: None, total_budget: None }
}

fn narrow() -> Limits {
    Limits {
        per_transaction: NANO,
        per_day: 2 * NANO,
        per_month: Some(10 * NANO),
        total_budget: Some(20 * NANO),
    }
}

#[test]
fn a_genuinely_fresh_server_still_bootstraps() {
    let dir = tmpdir("fresh");
    let e = PolicyEngine::load_or_new(&dir);
    assert!(!e.lost_policies(), "no file ever existed");
    assert!(
        e.creation_widens(&wide(), &None, &[]).is_none(),
        "the owner's setup call must not be refused on an empty server"
    );
}

#[test]
fn a_corrupt_policy_file_does_not_grant_a_bootstrap() {
    let dir = tmpdir("corrupt");
    std::fs::write(&dir.join("policies.json"), b"{ this is not json").unwrap();

    let e = PolicyEngine::load_or_new(&dir);
    assert!(e.lost_policies(), "the file existed and could not be parsed");
    let reason = e
        .creation_widens(&wide(), &None, &[])
        .expect("an emptied set must not be mistaken for a fresh server");
    assert!(reason.contains("quarantined"), "the owner is told why: {reason}");
}

#[test]
fn a_non_utf8_policy_file_is_treated_the_same_way() {
    // A torn write / bit rot produces bytes that are not valid UTF-8 — the
    // corruption the byte-level read exists to catch.
    let dir = tmpdir("nonutf8");
    std::fs::write(&dir.join("policies.json"), [0xff, 0xfe, 0x00, 0x01]).unwrap();
    let e = PolicyEngine::load_or_new(&dir);
    assert!(e.lost_policies());
    assert!(e.creation_widens(&narrow(), &None, &[]).is_some());
}

#[test]
fn even_a_narrow_policy_is_gated_after_a_quarantine() {
    // We cannot know it is narrow RELATIVE TO WHAT — the previous limits are
    // exactly what was lost.
    let dir = tmpdir("narrow");
    std::fs::write(&dir.join("policies.json"), b"garbage").unwrap();
    let e = PolicyEngine::load_or_new(&dir);
    assert!(e.creation_widens(&narrow(), &Some(vec!["1234".into()]), &["simple_transfer".into()]).is_some());
}

#[test]
fn a_readable_file_restores_the_normal_comparison() {
    let dir = tmpdir("readable");
    {
        let mut e = PolicyEngine::load_or_new(&dir);
        e.create_policy("a", narrow(), Some(vec!["1234".into()]), vec!["simple_transfer".into()]);
    }
    let e = PolicyEngine::load_or_new(&dir);
    assert!(!e.lost_policies(), "a good file is not a loss");
    // Equivalent is fine, wider is not — the ordinary rule.
    assert!(e
        .creation_widens(&narrow(), &Some(vec!["1234".into()]), &["simple_transfer".into()])
        .is_none());
    assert!(e.creation_widens(&wide(), &None, &[]).is_some());
}
