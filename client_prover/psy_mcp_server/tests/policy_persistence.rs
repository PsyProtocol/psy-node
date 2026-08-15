//! The owner's spend counters are the budget. Losing them silently grants the
//! agent a fresh budget; losing the FILE too means nobody can prove what they
//! were.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine};

const PSY: u64 = 1_000_000_000;

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("psy-policy-test-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn spent_counters_survive_a_restart() {
    let dir = tmpdir("restart");
    let pid = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy(
            "agent",
            Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: Some(500 * PSY) },
            None,
            vec![],
        );
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        e.authorize(&t, "alice", 7 * PSY, "simple_transfer").unwrap();
        pid
    };
    let mut reloaded = PolicyEngine::load_or_new(&dir);
    assert_eq!(
        reloaded.describe(&pid).unwrap().spent_total_nano,
        7 * PSY,
        "a restart must not re-grant the lifetime budget",
    );
}

#[test]
fn a_corrupt_policy_file_is_quarantined_not_destroyed() {
    let dir = tmpdir("corrupt");
    {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy(
            "agent",
            Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
            None,
            vec![],
        );
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        e.authorize(&t, "alice", 9 * PSY, "simple_transfer").unwrap();
    }
    let path = dir.join("policies.json");
    let original = std::fs::read_to_string(&path).unwrap();
    assert!(original.contains("9000000000"), "precondition: the spend is on disk");

    // Truncated write / disk corruption.
    std::fs::write(&path, "{ \"broken\": ").unwrap();

    let mut e = PolicyEngine::load_or_new(&dir);
    // Starting empty is survivable; DESTROYING the evidence is not. Force a
    // save, which is what used to overwrite the corrupt file.
    let pid2 = e.create_policy(
        "agent2",
        Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    assert!(e.describe(&pid2).is_ok());

    let quarantined: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|x| x.ok())
        .map(|x| x.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("policies.corrupt-"))
        .collect();
    assert_eq!(quarantined.len(), 1, "the unreadable file must be preserved, not overwritten");
    let saved = std::fs::read_to_string(dir.join(&quarantined[0])).unwrap();
    assert!(saved.contains("broken"), "the quarantined copy is the bytes we could not parse");
}

fn seed_with_a_spend(dir: &std::path::Path) {
    let mut e = PolicyEngine::load_or_new(dir);
    let pid = e.create_policy(
        "agent",
        Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    e.authorize(&t, "alice", 9 * PSY, "simple_transfer").unwrap();
}

fn quarantined(dir: &std::path::Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|x| x.ok())
        .map(|x| x.file_name().to_string_lossy().to_string())
        .filter(|n| n.starts_with("policies.corrupt-"))
        .collect()
}

#[test]
fn a_torn_non_utf8_file_is_quarantined_too() {
    // read_to_string fails BEFORE any parse for invalid UTF-8 — which is what a
    // torn write or bit rot actually produces — and that used to be treated as
    // "first run": no quarantine, no log, overwritten on the next save. The
    // earlier test only covered valid-UTF-8 garbage, i.e. the half that worked.
    let dir = tmpdir("torn");
    seed_with_a_spend(&dir);
    let path = dir.join("policies.json");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes[0] = 0xFF;
    bytes[1] = 0xFE;
    std::fs::write(&path, &bytes).unwrap();

    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy(
        "agent2",
        Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    assert_eq!(quarantined(&dir).len(), 1, "a damaged file must be preserved, not silently replaced");
}

#[test]
fn an_unreadable_file_is_quarantined_rather_than_replaced() {
    // Wrong owner after a root-run, an ACL, EIO. We cannot tell whether it
    // holds live counters, so it must not be replaced.
    let dir = tmpdir("unreadable");
    seed_with_a_spend(&dir);
    let path = dir.join("policies.json");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy(
        "agent2",
        Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    #[cfg(unix)]
    assert_eq!(quarantined(&dir).len(), 1, "an unreadable file must be preserved");
}

#[test]
fn two_quarantines_do_not_overwrite_each_other() {
    let dir = tmpdir("twice");
    for _ in 0..2 {
        seed_with_a_spend(&dir);
        std::fs::write(dir.join("policies.json"), [0xFFu8, 0xFE, 0x00]).unwrap();
        let mut e = PolicyEngine::load_or_new(&dir);
        e.create_policy(
            "a",
            Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
            None,
            vec![],
        );
    }
    assert_eq!(quarantined(&dir).len(), 2, "the earlier evidence must survive the later quarantine");
}

#[test]
fn a_healthy_file_is_never_quarantined() {
    let dir = tmpdir("healthy");
    seed_with_a_spend(&dir);
    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy(
        "a",
        Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    assert!(quarantined(&dir).is_empty(), "a good file must be left alone");
    // and an empty object is healthy, not damaged
    let d2 = tmpdir("healthy-empty");
    std::fs::write(d2.join("policies.json"), "{}\n").unwrap();
    let _ = PolicyEngine::load_or_new(&d2);
    assert!(quarantined(&d2).is_empty());
}

#[test]
fn no_stray_tmp_file_survives_a_successful_save() {
    let dir = tmpdir("tmp");
    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy(
        "agent",
        Limits { per_transaction: 1 * PSY, per_day: 1 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let strays: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|x| x.ok())
        .map(|x| x.file_name().to_string_lossy().to_string())
        .filter(|n| n.contains(".tmp"))
        .collect();
    assert!(strays.is_empty(), "left behind: {strays:?}");
    assert!(dir.join("policies.json").exists());
}

// ── cross-process safety ──────────────────────────────────────────────
//
// Two servers legitimately share one keystore directory: the owner dashboard
// spawns its own MCP child, and the agent host spawns another. Each used to
// load policies.json ONCE at startup and write the whole map back on every
// change, so their read-modify-write cycles lost each other's updates.
//
// These model that with two PolicyEngine instances over one directory — which
// is exactly what two processes are, minus the process boundary.

#[test]
fn a_pause_is_not_rewritten_by_the_other_process() {
    let dir = tmpdir("xproc-pause");
    // The dashboard's process creates the policy and issues the agent a session.
    let mut dash = PolicyEngine::load_or_new(&dir);
    let pid = dash.create_policy(
        "agent",
        Limits { per_transaction: 100 * PSY, per_day: 1_000 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    // The agent's process — a SEPARATE engine that loaded at its own startup.
    let mut agent = PolicyEngine::load_or_new(&dir);
    let (tok, _) = agent.issue_session(&pid, 60).unwrap();
    assert!(agent.authorize(&tok, "1", PSY, "simple_transfer").is_ok(), "baseline spend works");

    // The owner hits Pause in the dashboard.
    assert!(dash.pause(&pid), "pause applies in the dashboard's process");

    // The agent's process still holds active:true in memory. Its next spend
    // must SEE the pause, and must not write active:true back over it.
    let err = agent
        .authorize(&tok, "1", PSY, "simple_transfer")
        .expect_err("a paused policy must refuse the agent's next spend");
    assert!(err.to_string().contains("paus"), "{err}");

    // And the pause must survive on disk — this is what used to be undone.
    let mut reread = PolicyEngine::load_or_new(&dir);
    assert!(!reread.describe(&pid).unwrap().active, "the pause must still be in effect on disk");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn spend_counters_do_not_double_across_two_processes() {
    let dir = tmpdir("xproc-budget");
    let mut a = PolicyEngine::load_or_new(&dir);
    // 10 PSY/day. Two processes must share ONE budget, not one each.
    let pid = a.create_policy(
        "agent",
        Limits { per_transaction: 10 * PSY, per_day: 10 * PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let mut b = PolicyEngine::load_or_new(&dir);
    let (ta, _) = a.issue_session(&pid, 60).unwrap();
    let (tb, _) = b.issue_session(&pid, 60).unwrap();

    // Alternate spends between the two processes, 6 PSY each.
    assert!(a.authorize(&ta, "1", 6 * PSY, "simple_transfer").is_ok(), "first 6 PSY fits");
    let err = b
        .authorize(&tb, "1", 6 * PSY, "simple_transfer")
        .expect_err("the second 6 PSY exceeds the SHARED 10 PSY daily cap");
    assert!(err.to_string().contains("daily") || err.to_string().contains("day"), "{err}");

    // On disk, exactly one 6 PSY spend is recorded — not two, not zero.
    let mut reread = PolicyEngine::load_or_new(&dir);
    assert_eq!(reread.describe(&pid).unwrap().spent_today_nano, 6 * PSY);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_policy_created_by_one_process_is_visible_to_the_other() {
    let dir = tmpdir("xproc-visible");
    let mut a = PolicyEngine::load_or_new(&dir);
    let mut b = PolicyEngine::load_or_new(&dir);
    // b started before this policy existed.
    let pid = a.create_policy(
        "late",
        Limits { per_transaction: PSY, per_day: PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    // b must not clobber it on ITS next write.
    let _ = b.pause("nonexistent-policy");
    let reread = PolicyEngine::load_or_new(&dir);
    assert!(reread.policy_ids().contains(&pid), "the other process's policy must survive our write");
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn a_paused_policy_cannot_be_handed_a_fresh_session_by_the_other_process() {
    // Minting a session is a read of `active`, so it needs the same freshness
    // as a spend. A token that cannot be used is its own kind of confusion.
    let dir = tmpdir("xproc-issue");
    let mut dash = PolicyEngine::load_or_new(&dir);
    let pid = dash.create_policy(
        "agent",
        Limits { per_transaction: PSY, per_day: PSY, per_month: None, total_budget: None },
        None,
        vec![],
    );
    let mut agent = PolicyEngine::load_or_new(&dir);
    assert!(agent.issue_session(&pid, 30).is_ok(), "baseline: an active policy issues");

    dash.pause(&pid);

    let err = agent
        .issue_session(&pid, 30)
        .expect_err("the other process must see the pause before minting a token");
    assert!(err.to_string().contains("paus"), "{err}");
    std::fs::remove_dir_all(&dir).ok();
}
