//! Production Test Matrix — **Agent / policy** row.
//!
//! Covers: normal payment, over-budget (per-tx / daily / monthly / lifetime),
//! unauthorized recipient, revoked session, expired session, restart recovery.
//!
//! These are black-box tests: this file is the crate root of its own test
//! binary, so it sees only what `policy.rs` makes `pub`. That is deliberate —
//! the inline `#[cfg(test)] mod tests` inside `policy.rs` already reaches into
//! private fields to simulate a clock change; the cases here instead exercise
//! the surface an MCP tool handler actually calls, plus the on-disk persistence
//! contract that survives a restart. Anything asserted here is a promise made
//! to `main.rs`, not to the module's internals.
//!
//! The crate has no `[lib]` target (only `[[bin]]`), so the module is pulled in
//! by path. `policy.rs` depends on nothing else in the crate, so this compiles
//! standalone.

#[path = "../src/policy.rs"]
mod policy;

use policy::{Limits, PolicyEngine, SELF_RECIPIENT};

/// Caps wide enough that a test which is not about caps never trips one.
fn wide() -> Limits {
    Limits {
        per_transaction: 1_000_000_000_000,
        per_day: 1_000_000_000_000,
        per_month: None,
        total_budget: None,
    }
}

/// One policy, one live session — the state an agent is handed after the owner
/// runs `create_wallet` + `issue_session`.
fn armed(limits: Limits, recipients: Option<Vec<String>>) -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("matrix-agent", limits, recipients, vec![]);
    let (token, _) = e.issue_session(&pid, 60, None).unwrap();
    (e, pid, token)
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!("psy-mcp-prod-matrix-{tag}-{nanos}-{:?}", std::thread::current().id()))
}

// ─────────────────────────── AGENT-01 · normal payment ───────────────────────

#[test]
fn agent_01_a_payment_within_every_cap_is_authorized_and_logged() {
    let limits = Limits {
        per_transaction: 1_000_000_000,
        per_day: 5_000_000_000,
        per_month: Some(50_000_000_000),
        total_budget: Some(100_000_000_000),
    };
    let (mut e, pid, t) = armed(limits, Some(vec!["Psy-00204800".into()]));

    let auth = e
        .authorize(&t, "204800", 250_000_000, "simple_transfer")
        .expect("a payment inside every cap, to an allowlisted payee, must go through");
    assert_eq!(auth.policy_id, pid);
    assert_eq!(auth.agent_id, "matrix-agent");

    // The decision is visible to the owner without consulting the chain.
    let log = e.spend_log(10, None);
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].amount_nano, 250_000_000);
    assert_eq!(log[0].method, "simple_transfer");

    // ...and every counter moved by exactly the amount, no more.
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, 250_000_000);
    assert_eq!(d.spent_this_month_nano, 250_000_000);
    assert_eq!(d.spent_total_nano, 250_000_000);
    assert_eq!(d.remaining_day_nano, 4_750_000_000);
}

#[test]
fn agent_01b_a_claim_needs_no_allowlist_entry_and_costs_no_budget() {
    // Claims fold in money already addressed to this wallet. They are gated by
    // the method list, never by the payee allowlist, and they spend nothing.
    let (mut e, pid, t) = armed(Limits { per_day: 100, ..wide() }, Some(vec![]));
    for method in ["simple_claim", "private_claim", "claim_deposit"] {
        e.authorize(&t, SELF_RECIPIENT, 0, method)
            .unwrap_or_else(|e| panic!("{method} must not be blocked by an empty allowlist: {e}"));
    }
    assert_eq!(e.describe(&pid).unwrap().spent_today_nano, 0, "claims must not consume the daily budget");
}

// ─────────────────────────── AGENT-02..05 · over budget ──────────────────────

#[test]
fn agent_02_over_the_per_transaction_cap_is_denied() {
    // Whole-PSY amounts: the denial speaks PSY, and the human-facing figures
    // are asserted directly.
    const PSY: u64 = 1_000_000_000;
    let (mut e, pid, t) = armed(Limits { per_transaction: 5 * PSY, ..wide() }, None);
    assert!(e.authorize(&t, "1", 5 * PSY, "simple_transfer").is_ok(), "exactly at the cap is allowed");
    let err = e.authorize(&t, "1", 6 * PSY, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("per-transaction cap"), "the denial must name the cap that bound: {err}");
    assert!(err.contains("6 PSY") && err.contains("5 PSY"), "it must state attempt and limit in PSY: {err}");
    assert_eq!(
        e.describe(&pid).unwrap().spent_today_nano,
        5 * PSY,
        "a denied attempt must not move the counters"
    );
}

#[test]
fn agent_03_over_the_daily_cap_is_denied_and_says_what_is_left() {
    const PSY: u64 = 1_000_000_000;
    let (mut e, pid, t) = armed(Limits { per_transaction: 1_000 * PSY, per_day: 15 * PSY, ..wide() }, None);
    e.authorize(&t, "1", 10 * PSY, "simple_transfer").unwrap();
    let err = e.authorize(&t, "1", 10 * PSY, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("daily cap"), "{err}");
    assert!(err.contains("5 PSY left today"), "the agent must be told the headroom in PSY, not just refused: {err}");
    // The remaining 5 PSY is still spendable — a denial must not wedge the policy.
    assert!(e.authorize(&t, "1", 5 * PSY, "simple_transfer").is_ok());
    assert_eq!(e.describe(&pid).unwrap().remaining_day_nano, 0);
}

#[test]
fn agent_04_over_the_thirty_day_cap_is_denied_even_with_daily_headroom() {
    let limits = Limits { per_transaction: 1_000, per_day: 100_000, per_month: Some(1_500), total_budget: None };
    let (mut e, _pid, t) = armed(limits, None);
    e.authorize(&t, "1", 1_000, "simple_transfer").unwrap();
    let err = e.authorize(&t, "1", 1_000, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("30-day cap"), "the monthly cap must bind independently of the daily one: {err}");
    assert!(e.authorize(&t, "1", 500, "simple_transfer").is_ok(), "exactly at the period cap is allowed");
}

#[test]
fn agent_05_over_the_lifetime_budget_is_denied_and_never_resets() {
    let limits = Limits { per_transaction: 1_000, per_day: 100_000, per_month: None, total_budget: Some(1_500) };
    let (mut e, pid, t) = armed(limits, None);
    e.authorize(&t, "1", 1_000, "simple_transfer").unwrap();
    e.authorize(&t, "1", 500, "simple_transfer").unwrap();
    let err = e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("total budget"), "{err}");
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.remaining_total_nano, Some(0));
    // A new session does not refresh a lifetime budget — that is the point of it.
    let (t2, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&t2, "1", 1, "simple_transfer").is_err(), "re-issuing a session must not top up the lifetime budget");
}

// ────────────────────── AGENT-06 · unauthorized recipient ────────────────────

#[test]
fn agent_06_an_unlisted_recipient_is_denied_without_leaking_the_allowlist() {
    let (mut e, _pid, t) = armed(wide(), Some(vec!["204800".into(), "999001".into()]));
    assert!(e.authorize(&t, "Psy-00204800", 1, "simple_transfer").is_ok(), "spelling must not decide the outcome");
    let err = e.authorize(&t, "31337", 1, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("31337"), "name the attempted payee so the agent can report it: {err}");
    assert!(err.contains("2 approved"), "state the allowlist SIZE: {err}");
    assert!(!err.contains("999001"), "never hand the agent a directory of payees to try: {err}");
}

#[test]
fn agent_06b_a_lookalike_x402_host_cannot_satisfy_an_allowlisted_one() {
    // x402_fetch offers the gate two names for one seller: the payee id from the
    // 402 challenge and the URL that served it. Both come from the same hostile
    // response, so neither may be spoofable into matching an approved seller.
    let (mut e, _pid, t) = armed(wide(), Some(vec!["https://api.example.com/paid".into()]));
    let approved = "https://api.example.com/paid/report";
    assert!(
        e.authorize_aliases(&t, &["777", approved], 1, "x402_fetch").is_ok(),
        "the approved seller, reached at another path, is still the approved seller"
    );
    for hostile in [
        "https://api.example.com.evil.test/paid", // suffix-appended lookalike
        "https://evil.test/?next=api.example.com", // query-string smuggling
        "https://api.example.com@evil.test/paid",  // userinfo smuggling
        "https://apiexample.com/paid",             // dot removed
        "https://sub.api.example.com/paid",        // subdomain of the approved host
    ] {
        assert!(
            e.authorize_aliases(&t, &["777", hostile], 1, "x402_fetch").is_err(),
            "`{hostile}` must not satisfy an allowlist entry for api.example.com"
        );
    }
}

#[test]
fn agent_06c_the_self_sentinel_cannot_be_forged_by_a_payee_named_self() {
    // `self` is the inbound sentinel. A hostile 402 challenge naming the literal
    // string as its payee would, if the exemption were name-based only, buy a
    // free pass around the allowlist. It cannot: the exemption applies only when
    // EVERY alias is the sentinel, and an outbound transfer always carries a
    // real destination alongside it.
    let (mut e, _pid, t) = armed(wide(), Some(vec!["204800".into()]));
    assert!(
        e.authorize_aliases(&t, &["31337", SELF_RECIPIENT], 1, "simple_transfer").is_err(),
        "mixing the inbound sentinel into an outbound payment must not bypass the allowlist"
    );
}

// ───────────────────────── AGENT-07 · revoked session ────────────────────────

#[test]
fn agent_07_a_revoked_session_stops_spending_immediately() {
    let (mut e, pid, t) = armed(wide(), None);
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok());
    assert!(e.revoke(&t), "revoking a live token reports that it existed");
    let err = e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string();
    // The refusal is now a sentence the OWNER reads (it is also recorded as a
    // blocked attempt), not the internal "invalid session token" string.
    assert!(err.contains("not valid"), "{err}");
    assert!(err.contains("revoked"), "it says WHY the token is dead: {err}");
    assert_eq!(
        e.denied_log(10, None).len(),
        1,
        "and revoke-then-spend is on the record — it used to vanish entirely",
    );
    assert!(!e.revoke(&t), "revoking twice is a no-op, not a second success");
    assert_eq!(e.describe(&pid).unwrap().active_sessions, 0);
    assert!(e.policy_id_for_session(&t).is_none(), "a revoked token must not still resolve to its policy");

    // Revocation kills one token, not the policy: the owner can re-arm.
    let (t2, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&t2, "1", 1, "simple_transfer").is_ok());
}

#[test]
fn agent_07b_a_paused_policy_cannot_issue_a_fresh_session() {
    // The emergency stop would be theater if pausing left session-minting open.
    let (mut e, pid, t) = armed(wide(), None);
    assert!(e.pause(&pid));
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "existing sessions stop spending");
    assert!(e.issue_session(&pid, 60, None).is_err(), "and no new session may be minted while paused");
    assert!(e.resume(&pid));
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok(), "resume restores the existing session");
}

// ───────────────────────── AGENT-08 · expired session ────────────────────────

#[test]
fn agent_08_an_expired_session_is_denied_and_the_token_is_dropped() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("matrix-agent", wide(), None, vec![]);
    // ttl 0 => expires at the current second; one second later it is stale.
    let (t, expires_at) = e.issue_session(&pid, 0, None).unwrap();
    assert!(e.policy_id_for_session(&t).is_some(), "the token exists before it lapses");
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    assert!(
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() > expires_at,
        "the test's own clock must actually have passed the expiry"
    );

    let err = e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("expired"), "{err}");
    assert!(e.policy_id_for_session(&t).is_none(), "an expired token is dropped, not left to accumulate");
    assert_eq!(e.describe(&pid).unwrap().active_sessions, 0);
    assert!(e.budget(&t).is_none(), "check_budget must not report headroom for a lapsed session");
}

#[test]
fn agent_08b_session_ttl_is_clamped_to_a_day() {
    // An unclamped TTL both defeats revocation in practice and overflows the
    // expiry arithmetic on absurd input.
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("matrix-agent", wide(), None, vec![]);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let (_t, expires_at) = e.issue_session(&pid, u64::MAX, None).unwrap();
    assert!(
        expires_at <= now + 24 * 60 * 60 + 2,
        "a u64::MAX TTL must clamp to 24h, got {} seconds out",
        expires_at.saturating_sub(now)
    );
    assert!(expires_at > now, "and it must not have wrapped to the past");
}

// ──────────────────────── AGENT-09 · restart recovery ────────────────────────

#[test]
fn agent_09_spent_counters_survive_a_restart_but_sessions_do_not() {
    let dir = temp_dir("restart");
    let (pid, token) = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy(
            "matrix-agent",
            Limits { per_transaction: 1_000, per_day: 10_000, per_month: Some(10_000), total_budget: Some(1_500) },
            Some(vec!["204800".into()]),
            vec!["simple_transfer".into()],
        );
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        e.authorize(&t, "204800", 1_000, "simple_transfer").unwrap();
        (pid, t)
    };

    // "Restart": a new process over the same keystore directory.
    let mut e2 = PolicyEngine::load_or_new(&dir);
    assert_eq!(e2.policy_ids(), vec![pid.clone()], "the policy itself is restored");
    assert!(
        e2.policy_id_for_session(&token).is_none(),
        "sessions must NOT survive — a restart fails toward re-authorization, never toward extra spend"
    );

    let d = e2.describe(&pid).unwrap();
    assert_eq!(d.spent_total_nano, 1_000, "the lifetime counter came back with the policy");
    assert_eq!(d.remaining_total_nano, Some(500));
    assert_eq!(d.allowed_recipient_count, Some(1), "the allowlist survived");
    assert_eq!(d.allowed_methods, vec!["simple_transfer".to_string()], "the method list survived");

    let (t2, _) = e2.issue_session(&pid, 60, None).unwrap();
    assert!(
        e2.authorize(&t2, "204800", 1_000, "simple_transfer").is_err(),
        "a crash-loop must not re-grant the lifetime budget"
    );
    assert!(e2.authorize(&t2, "204800", 500, "simple_transfer").is_ok());
    assert!(
        e2.authorize(&t2, "31337", 1, "simple_transfer").is_err(),
        "the restored allowlist still binds"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn agent_09b_a_corrupt_policy_file_starts_empty_rather_than_unbounded() {
    // The failure mode to avoid is a torn/garbage file being read as "no caps".
    // Starting with NO policies is the safe reading: nothing can be spent until
    // the owner creates one.
    for corruption in [
        "",                       // truncated to nothing
        "{",                      // torn mid-write
        "not json at all",        // clobbered by something else
        "[]",                     // right JSON, wrong shape
        r#"{"abc":{"agent_id":"x"}}"#, // a policy missing its limits
    ] {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policies.json"), corruption).unwrap();
        let mut e = PolicyEngine::load_or_new(&dir);
        assert!(
            e.policy_ids().is_empty(),
            "corrupt policies.json ({corruption:?}) must yield no policies, not an unbounded one"
        );
        assert!(e.sole_policy_id().is_none());
        assert!(e.describe("abc").is_err(), "and nothing may be describable/spendable from it");
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn agent_09c_the_on_disk_format_is_the_contract_a_restart_depends_on() {
    // Pins the persisted field names. Renaming one silently resets every spent
    // counter on the next restart, which is the same failure as not persisting
    // at all — and it would pass a round-trip-only test.
    let dir = temp_dir("format");
    {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("matrix-agent", Limits { per_transaction: 7, per_day: 8, per_month: Some(9), total_budget: Some(10) }, Some(vec!["Psy-00000042".into()]), vec!["simple_transfer".into()]);
        let (t, _) = e.issue_session(&pid, 60, None).unwrap();
        e.authorize(&t, "42", 5, "simple_transfer").unwrap();
    }
    let raw = std::fs::read_to_string(dir.join("policies.json")).expect("policies.json is written");
    let parsed: serde_json::Value = serde_json::from_str(&raw).expect("and it is valid JSON");
    let policy = parsed.as_object().unwrap().values().next().unwrap();
    for field in [
        "agent_id", "limits", "allowed_recipients", "allowed_methods", "active",
        "spent_today", "spent_this_month", "spent_total", "last_day", "last_month",
    ] {
        assert!(policy.get(field).is_some(), "persisted policy lost the `{field}` field:\n{raw}");
    }
    assert_eq!(policy["spent_total"], 5, "the spent counter is what a restart must not lose");
    assert_eq!(policy["limits"]["per_transaction"], 7);
    assert_eq!(
        policy["allowed_recipients"],
        serde_json::json!(["42"]),
        "recipients are stored already normalized, so an owner's spelling cannot drift"
    );
    // The session token must never be on disk — persisting it would make a
    // restart carry the agent's authority across, defeating the design.
    assert!(!raw.contains("session"), "sessions must not be persisted:\n{raw}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("policies.json")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the policy file records spend history — owner-only");
    }
    std::fs::remove_dir_all(&dir).ok();
}

// ───────────────────────────── method allowlist ──────────────────────────────

#[test]
fn agent_10_a_method_outside_the_list_is_denied_however_small_the_amount() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("matrix-agent", wide(), None, vec!["simple_transfer".into()]);
    let (t, _) = e.issue_session(&pid, 60, None).unwrap();
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok());
    for denied in ["withdraw", "private_transfer", "x402_fetch", "deposit", "SIMPLE_TRANSFER", "simple_transfer "] {
        assert!(
            e.authorize(&t, "1", 0, denied).is_err(),
            "`{denied}` is not on the list and a zero amount must not smuggle it through"
        );
    }
}

// ───────────────────────────────── refunds ───────────────────────────────────

#[test]
fn agent_13_a_refund_returns_headroom_without_ever_creating_new_budget() {
    // Refund exists so a failed settle does not eat the day's budget. It must
    // never become a way to mint headroom: refunding more than was spent, or
    // refunding twice, must not raise the ceiling.
    let limits = Limits { per_transaction: 100, per_day: 100, per_month: Some(100), total_budget: Some(100) };
    let (mut e, pid, t) = armed(limits, None);
    let auth = e.authorize(&t, "1", 100, "simple_transfer").unwrap();
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "budget is exhausted");

    e.refund(&auth, 100);
    e.refund(&auth, 100); // a double-refund (retry bug in a caller)
    e.refund(&auth, u64::MAX); // and an absurd one
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, 0, "counters floor at zero, they do not go negative or wrap");
    assert_eq!(d.spent_total_nano, 0);
    assert_eq!(d.remaining_total_nano, Some(100), "the cap is still the cap — no extra budget was minted");
    assert!(e.authorize(&t, "1", 100, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "and it is exhausted again at exactly the cap");
}

// ──────────────────────── arithmetic edge (see 05-testing.md) ────────────────

#[test]
fn agent_14_a_near_max_cap_must_not_silently_authorize_a_max_spend() {
    // An owner writing "no limit" as u64::MAX makes `spent_today + amount`
    // overflow. Debug builds abort the thread; release builds WRAP, and the
    // wrapped sum compares under the cap — which authorizes the spend and
    // resets the counter. Either way the one thing that must never happen is a
    // silent Ok. This test asserts that, and the panic path is itself a defect
    // (a poisoned std::sync::Mutex bricks every later policy call in main.rs).
    let (mut e, _pid, t) = armed(Limits { per_transaction: u64::MAX, per_day: u64::MAX, per_month: None, total_budget: None }, None);
    e.authorize(&t, "1", 1, "simple_transfer").unwrap();

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        e.authorize(&t, "1", u64::MAX, "simple_transfer").is_ok()
    }));
    match outcome {
        Ok(true) => panic!(
            "u64::MAX was authorized on top of an existing spend — the daily accumulator wrapped \
             and the cap was defeated (release-build behaviour; add a checked_add in authorize)"
        ),
        Ok(false) => {} // denied cleanly — the desired behaviour
        Err(_) => {}    // debug-build overflow panic — denied, but see the doc's finding F-1
    }
}

#[test]
fn check_budget_reports_a_paused_policy_as_having_no_headroom() {
    // budget() ignored `active` entirely, so a paused policy answered with its
    // full caps. No money moved — the gate still refused the spend — but the
    // agent planned against a number that was a lie about what was possible,
    // and the owner reading check_budget saw a live budget on a policy they had
    // just stopped.
    let (mut e, pid, t) = armed(wide(), None);
    let before = e.budget(&t).expect("a live session has a budget");
    assert!(before.remaining_day > 0, "baseline has headroom");
    assert!(!before.paused);

    assert!(e.pause(&pid));

    let after = e.budget(&t).expect("the session still resolves while paused");
    assert!(after.paused, "the pause must be visible, not inferred from zeros");
    assert_eq!(after.remaining_day, 0, "a paused policy has no daily headroom");
    assert_eq!(
        after.per_transaction, before.per_transaction,
        "the CAP is unchanged — only the available headroom is zero",
    );

    // ...and resuming restores it, so this is not a one-way door.
    assert!(e.resume(&pid));
    let resumed = e.budget(&t).expect("budget after resume");
    assert!(!resumed.paused);
    assert_eq!(resumed.remaining_day, before.remaining_day);
}

#[test]
fn a_paused_policy_reports_zero_for_every_optional_ceiling_it_has() {
    let (mut e, pid, t) = armed(
        Limits { per_transaction: 5, per_day: 10, per_month: Some(20), total_budget: Some(30) },
        None,
    );
    e.pause(&pid);
    let b = e.budget(&t).unwrap();
    assert_eq!(b.remaining_month, Some(0), "a configured 30-day ceiling reports 0, not its cap");
    assert_eq!(b.remaining_total, Some(0));
    // An absent ceiling stays absent rather than becoming a misleading 0.
    let (mut e2, pid2, t2) = armed(wide(), None);
    e2.pause(&pid2);
    let b2 = e2.budget(&t2).unwrap();
    assert_eq!(b2.remaining_month, None, "an unset ceiling must not appear as a limit of 0");
}
