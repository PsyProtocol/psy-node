//! Adversarial tests for the spending-policy gate.
//!
//! THREAT MODEL: the LLM agent is untrusted and prompt-injectable. It holds a
//! session token and calls tools; the owner sets policy out-of-band. Every test
//! here plays the agent and tries to move money the owner did not sanction.
//!
//! A PASSING test named `attack_*` or `*_is_denied` means the attack is BLOCKED.
//! A test named `FINDING_*` documents an attack that SUCCEEDS today: it asserts
//! the SECURE behaviour, is `#[ignore]`d so the suite stays green, and fails
//! when run with `cargo test -- --ignored`. Each has a sibling `documents_*`
//! test that pins the current (vulnerable) behaviour so a fix visibly flips it.
//!
//! The crate has no `[lib]` target, so the module under test is included by
//! path. That is deliberate: these tests exercise the REAL `policy.rs`, not a
//! copy of it.

#[allow(dead_code, unused_imports)]
#[path = "../src/policy.rs"]
mod policy;

use policy::{normalize_recipient, Limits, PolicyEngine, SELF_RECIPIENT};

const DAY: u64 = 86_400;

fn open_limits() -> Limits {
    Limits {
        per_transaction: 1_000_000_000_000,
        per_day: 1_000_000_000_000,
        per_month: None,
        total_budget: None,
    }
}

/// One policy, one live session. Returns (engine, policy_id, session_token).
fn engine_with(limits: Limits, recipients: Option<Vec<String>>) -> (PolicyEngine, String, String) {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent-1", limits, recipients, vec![]);
    let (token, _) = e.issue_session(&pid, 60).unwrap();
    (e, pid, token)
}

fn spent_today(e: &mut PolicyEngine, pid: &str) -> u64 {
    e.describe(pid).unwrap().spent_today_nano
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 1 — Budget evasion: split, refund-farm, and race the rollover.
// ─────────────────────────────────────────────────────────────────────────────

/// The classic: one 300-Nano payment is over the per-tx cap, so send three 100s.
/// The daily counter must SUM, not reset per call.
#[test]
fn attack_splitting_an_over_cap_payment_still_hits_the_daily_cap() {
    let limits = Limits { per_transaction: 100, per_day: 250, ..open_limits() };
    let (mut e, pid, t) = engine_with(limits, None);

    assert!(e.authorize(&t, "9999", 300, "simple_transfer").is_err(), "the whole amount is over the per-tx cap");
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    let err = e.authorize(&t, "9999", 100, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("daily cap"), "the third slice must be refused by the daily cap: {err}");
    assert_eq!(spent_today(&mut e, &pid), 200, "exactly what was authorized, nothing lost or double-counted");

    // ...and the leftover headroom is honoured exactly, not rounded up.
    assert!(e.authorize(&t, "9999", 51, "simple_transfer").is_err(), "51 > the 50 left");
    assert!(e.authorize(&t, "9999", 50, "simple_transfer").is_ok(), "exactly the remainder is allowed");
    assert!(e.authorize(&t, "9999", 1, "simple_transfer").is_err(), "and then nothing at all");
}

/// Splitting under a wide-open daily cap must still be caught by the 30-day one.
#[test]
fn attack_splitting_under_a_wide_daily_cap_still_hits_the_monthly_cap() {
    let limits = Limits { per_transaction: 100, per_day: 1_000_000, per_month: Some(250), total_budget: None };
    let (mut e, pid, t) = engine_with(limits, None);
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    let err = e.authorize(&t, "9999", 100, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("30-day cap"), "the daily cap is wide open; the monthly one must bind: {err}");
    assert_eq!(e.describe(&pid).unwrap().spent_this_month_nano, 200);
    assert!(e.authorize(&t, "9999", 50, "simple_transfer").is_ok(), "exactly the remainder");
}

/// The LIFETIME cap is the one that must survive a period rollover — otherwise
/// "500 PSY total, ever" becomes "500 PSY every 30 days".
#[test]
fn attack_a_period_rollover_does_not_refresh_the_lifetime_budget() {
    let limits = Limits { per_transaction: 100, per_day: 1_000_000, per_month: Some(1_000_000), total_budget: Some(300) };
    let (mut e, pid, t) = engine_with(limits, None);
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());

    e.force_period_rollover_for_test(); // a new 30-day bucket, and a new day
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok(), "the periodic budgets did refresh");
    let err = e.authorize(&t, "9999", 100, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("total budget"), "300 lifetime is spent; a new period changes nothing: {err}");

    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_this_month_nano, 100, "the new period counts only its own spend");
    assert_eq!(d.spent_total_nano, 300, "the lifetime total never rolls over");
    assert_eq!(d.remaining_total_nano, Some(0));
}

/// Refund-farming: over-refund, refund twice, refund an amount that was never
/// authorized. None of it may create headroom beyond the owner's cap.
#[test]
fn attack_over_refunding_cannot_manufacture_headroom() {
    let limits = Limits { per_transaction: 100, per_day: 100, per_month: Some(100), total_budget: Some(100) };
    let (mut e, pid, t) = engine_with(limits, None);

    let auth = e.authorize(&t, "9999", 100, "simple_transfer").unwrap();
    // Refund far more than was ever spent, several times over.
    for _ in 0..5 {
        e.refund(&auth, u64::MAX);
    }
    let d = e.describe(&pid).unwrap();
    assert_eq!(d.spent_today_nano, 0, "saturating: spend never goes negative");
    assert_eq!(d.spent_this_month_nano, 0);
    assert_eq!(d.spent_total_nano, 0);
    assert_eq!(d.remaining_day_nano, 100, "headroom is capped by the LIMIT, not by the refund");
    assert_eq!(d.remaining_total_nano, Some(100));

    // The budget is exactly one payment wide, still.
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "9999", 1, "simple_transfer").is_err(), "no free lifetime budget was minted");
}

/// A spend that fails and is retried must cost the budget ONCE — not twice
/// (which would let a flaky chain burn the budget) and not zero (which would
/// make failure a free retry loop past the cap).
#[test]
fn attack_a_failed_then_retried_spend_nets_exactly_one_charge() {
    let limits = Limits { per_transaction: 100, per_day: 150, ..open_limits() };
    let (mut e, pid, t) = engine_with(limits, None);

    let auth = e.authorize(&t, "9999", 100, "simple_transfer").unwrap();
    e.refund(&auth, 100); // the tool's failure path
    assert_eq!(spent_today(&mut e, &pid), 0);
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok(), "the retry is affordable again");
    assert_eq!(spent_today(&mut e, &pid), 100, "one net charge for one settled payment");
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_err(), "and the cap still binds after the round trip");
}

/// A refund is never a spend: the daily counter after N failed-and-refunded
/// attempts is identical to never having tried.
#[test]
fn attack_a_thousand_refunded_attempts_do_not_drift_the_counter() {
    let (mut e, pid, t) = engine_with(Limits { per_transaction: 7, per_day: 1_000, ..open_limits() }, None);
    for _ in 0..1_000 {
        let auth = e.authorize(&t, "9999", 7, "simple_transfer").unwrap();
        e.refund(&auth, 7);
    }
    assert_eq!(spent_today(&mut e, &pid), 0, "no accumulated drift from refund arithmetic");
    assert_eq!(e.describe(&pid).unwrap().spent_total_nano, 0);
}

/// FINDING (LOW) — a refund issued after the daily window rolled over subtracts
/// from the NEW day's counter, handing back budget that was never spent today.
/// Reachable when a tool call straddles the UTC-midnight boundary: proving and
/// settlement take minutes, and the failure path refunds long after the gate ran.
#[test]
#[ignore = "FINDING: refund after rollover credits the new day's counter"]
fn finding_a_refund_across_the_day_boundary_must_not_credit_the_new_day() {
    let limits = Limits { per_transaction: 100, per_day: 100, ..open_limits() };
    let (mut e, pid, t) = engine_with(limits, None);

    let yesterday = e.authorize(&t, "9999", 100, "simple_transfer").unwrap(); // day D
    e.force_day_rollover_for_test(); // wall clock crosses midnight
    e.authorize(&t, "9999", 100, "simple_transfer").unwrap(); // day D+1, budget now spent
    e.refund(&yesterday, 100); // day D's call finally fails

    assert_eq!(
        spent_today(&mut e, &pid),
        100,
        "yesterday's refund must not restore today's budget"
    );
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_err(), "today's cap is already spent");
}

#[test]
fn documents_the_cross_day_refund_credit() {
    let limits = Limits { per_transaction: 100, per_day: 100, ..open_limits() };
    let (mut e, pid, t) = engine_with(limits, None);
    let yesterday = e.authorize(&t, "9999", 100, "simple_transfer").unwrap();
    e.force_day_rollover_for_test();
    e.authorize(&t, "9999", 100, "simple_transfer").unwrap();
    e.refund(&yesterday, 100);
    // CURRENT behaviour: today's 100 was silently un-spent, so a second 100
    // goes through — 200 Nano moved on a 100/day policy.
    assert_eq!(spent_today(&mut e, &pid), 0, "current (vulnerable) behaviour");
    assert!(e.authorize(&t, "9999", 100, "simple_transfer").is_ok(), "second 100 on a 100/day cap");
}

/// FIXED: the cap comparisons use checked arithmetic, so an amount that
/// would overflow u64 is denied — no panic, no wrap-around approval.
#[test]
fn attack_an_overflowing_amount_is_denied_by_the_authorize_gate() {
    let limits = Limits { per_transaction: u64::MAX, per_day: 1_000, per_month: None, total_budget: None };
    let (mut e, _pid, t) = engine_with(limits, None);
    // Land a small legitimate spend so spent_today > 0.
    e.authorize(&t, "9999", 500, "simple_transfer").unwrap();
    // amount <= per_transaction, so the per-tx gate passes; the daily gate then
    // computes 500 + u64::MAX, which saturates and is denied.
    assert!(
        e.authorize(&t, "9999", u64::MAX, "simple_transfer").is_err(),
        "u64::MAX on a 1000/day policy must be refused"
    );
}

/// The same overflow reached through the monthly cap.
#[test]
fn attack_the_monthly_cap_overflow_is_denied() {
    let limits = Limits { per_transaction: u64::MAX, per_day: u64::MAX, per_month: Some(1_000), total_budget: None };
    let (mut e, _pid, t) = engine_with(limits, None);
    e.authorize(&t, "9999", 500, "simple_transfer").unwrap();
    assert!(
        e.authorize(&t, "9999", u64::MAX, "simple_transfer").is_err(),
        "u64::MAX on a 1000/month policy must be refused"
    );
}

/// Sanity: with sane owner limits there is no overflow to reach, so the fix is
/// about robustness, not about a policy an owner would plausibly write.
#[test]
fn attack_huge_amounts_under_sane_limits_are_simply_denied() {
    let limits = Limits { per_transaction: 5_000_000_000, per_day: 50_000_000_000, ..open_limits() };
    let (mut e, _pid, t) = engine_with(limits, None);
    for amount in [u64::MAX, u64::MAX - 1, u64::MAX / 2, 5_000_000_001] {
        assert!(e.authorize(&t, "9999", amount, "simple_transfer").is_err(), "amount {amount} must be denied");
    }
    assert!(e.authorize(&t, "9999", 0, "simple_transfer").is_ok(), "a zero-value call is not a cap violation");
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 2 — Allowlist evasion: spelling, collision, alias.
// ─────────────────────────────────────────────────────────────────────────────

/// Every spelling of an UNAPPROVED payee must be refused. This is the single
/// most important property in the file: it is what "the owner approved this
/// payee" means.
#[test]
fn attack_an_unlisted_recipient_is_denied_in_every_spelling() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    let disguises = [
        "9999",
        "09999",
        "0000000009999",
        "Psy-00009999",
        "psy-9999",
        "PSY-9999",
        " 9999 ",
        "\t9999\n",
        "0x270f",           // 9999 in hex — a different identifier space
        "0X270F",
        "9999.",
        "9999 ",
        "https://evil.example.com/pay",
        "http://evil.example.com",
        "evil.example.com",
        "0xdeadbeef",
        "99990",
        "999",
        "١٢٣٤",              // Arabic-Indic digits: must not parse as 1234
        "१२३४",              // Devanagari digits
        "1234\u{200b}",     // zero-width space
        "1234 ",            // trailing space is trimmed → 1234, and IS allowed; see below
    ];
    for d in disguises.iter().take(disguises.len() - 1) {
        assert!(
            e.authorize(&t, d, 1, "simple_transfer").is_err(),
            "`{d}` must not reach an unapproved party (normalized to `{}`)",
            normalize_recipient(d)
        );
    }
    // Whitespace around the APPROVED id is genuinely the approved id.
    assert!(e.authorize(&t, "1234 ", 1, "simple_transfer").is_ok());
}

/// Non-ASCII digit forms must not be silently folded into an approved decimal id.
#[test]
fn attack_unicode_digits_do_not_normalize_into_an_approved_id() {
    assert_ne!(normalize_recipient("١٢٣٤"), "1234", "Arabic-Indic digits must stay distinct");
    assert_ne!(normalize_recipient("１２３４"), "1234", "fullwidth digits must stay distinct");
    assert_ne!(normalize_recipient("1234\u{200b}"), "1234", "a zero-width space must not be trimmed away");
    // `trim()` strips unicode whitespace, and that IS the same principal.
    assert_eq!(normalize_recipient("\u{00a0}1234\u{00a0}"), "1234", "nbsp is whitespace, not an identifier");
}

/// The URL branch: userinfo, trailing dots, case and ports. The property that
/// matters is that a URL naming an UNAPPROVED host is refused however it is
/// dressed up.
#[test]
fn attack_url_dressing_cannot_impersonate_an_approved_host() {
    let (mut e, _pid, t) =
        engine_with(open_limits(), Some(vec!["https://good.example.com/paid".into()]));

    // These really are the approved host — reqwest would connect there too.
    for ok in [
        "https://good.example.com/paid",
        "https://GOOD.example.COM/other",
        "https://good.example.com./paid",     // trailing dot is the same host
        "http://good.example.com/paid?x=1#y",
        "https://user:pass\u{40}good.example.com/paid",
        "https://evil.example.com%40user\u{40}good.example.com/paid", // userinfo, host is good
    ] {
        assert!(e.authorize(&t, ok, 1, "x402_fetch").is_ok(), "`{ok}` IS the approved host");
    }

    // These are NOT, and must be refused.
    for bad in [
        "https://good.example.com\u{40}evil.com/paid",   // last @ wins: host is evil
        "https://good.example.com.evil.com/paid",
        "https://evil.com/good.example.com",
        "https://evil.com/@good.example.com",
        "https://evil.com?x=@good.example.com",
        "https://evil.com#@good.example.com",
        "https://good.example.com:8443/paid",   // a different port is a different seller
        "https://goodxexample.com/paid",
        "https://xn--good-example.com/paid",
        "goodexample.com",
    ] {
        assert!(
            e.authorize(&t, bad, 1, "x402_fetch").is_err(),
            "`{bad}` must be refused (normalized to `{}`)",
            normalize_recipient(bad)
        );
    }
}

/// The x402 alias pair (payee user id, seller URL). Approving EITHER name is
/// approving that seller; approving neither must deny.
#[test]
fn attack_x402_aliases_cannot_smuggle_an_unapproved_seller() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["https://good.example.com".into()]));

    assert!(
        e.authorize_aliases(&t, &["777", "https://good.example.com/a"], 1, "x402_fetch").is_ok(),
        "an approved host authorizes the payee id its own challenge names"
    );
    assert!(
        e.authorize_aliases(&t, &["777", "https://evil.example.com/a"], 1, "x402_fetch").is_err(),
        "an unapproved host with an unapproved payee id is denied"
    );
    // Padding the alias list with junk must not help.
    assert!(
        e.authorize_aliases(&t, &["777", "https://evil.example.com/a", "", "self", "0"], 1, "x402_fetch").is_err(),
        "extra aliases are not a wildcard"
    );
}

/// FINDING (LOW, latent) — `recipients.iter().all(..)` is vacuously TRUE for an
/// empty slice, so `authorize_aliases(token, &[], ..)` skips the recipient
/// allowlist entirely. No caller passes an empty slice today; this is a trap
/// for the next one.
#[test]
#[ignore = "FINDING: an empty alias list is treated as an inbound (self) operation"]
fn finding_an_empty_alias_list_must_not_bypass_the_allowlist() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    assert!(
        e.authorize_aliases(&t, &[], 1_000, "simple_transfer").is_err(),
        "a spend with no named recipient must be refused, not treated as self"
    );
}

#[test]
fn documents_the_empty_alias_list_bypass() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    assert!(
        e.authorize_aliases(&t, &[], 1_000, "simple_transfer").is_ok(),
        "current (vulnerable) behaviour: vacuous all() ⇒ inbound ⇒ allowlist skipped"
    );
}

/// FINDING (LOW) — `0x`-prefixed hex and bare decimal share one namespace after
/// normalization, so approving public user id `1234` also approves the shielded
/// address `0x1234` and the L1 address `0x1234`. Practical impact is capped by
/// the fact that a short address like that is not an address anyone owns, so
/// this is fund-destruction/griefing rather than theft.
#[test]
#[ignore = "FINDING: hex and decimal identifiers collide after normalization"]
fn finding_a_hex_address_must_not_collide_with_a_decimal_user_id() {
    assert_ne!(
        normalize_recipient("0x1234"),
        normalize_recipient("1234"),
        "a shielded/L1 address and a public user id are different principals"
    );
}

#[test]
fn documents_the_hex_decimal_collision() {
    assert_eq!(normalize_recipient("0x1234"), "1234", "current behaviour");
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    // Owner approved public user id 1234; the agent gets a PRIVATE transfer to
    // shielded address 0x1234 past the gate on the strength of that.
    assert!(e.authorize(&t, "0x1234", 1_000, "private_transfer").is_ok());
    assert!(e.authorize(&t, "0x1234", 1_000, "withdraw").is_ok(), "and an L1 withdrawal too");
    // Addresses that are not all decimal digits do NOT collide, which is why
    // this is narrow.
    assert!(e.authorize(&t, "0x12ab", 1_000, "private_transfer").is_err());
}

/// An empty string in the allowlist must not act as a wildcard for degenerate
/// recipients. (It does match other degenerate inputs — recorded here so the
/// blast radius is known.)
#[test]
fn attack_a_blank_allowlist_entry_is_not_a_wildcard_for_real_payees() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["".into()]));
    for real in ["1234", "0xdeadbeef", "https://evil.com/x", "evil.com"] {
        assert!(e.authorize(&t, real, 1, "simple_transfer").is_err(), "`{real}` must not match a blank entry");
    }
    // Degenerate inputs DO match it — they normalize to "" as well. They are
    // not payable identifiers, so nothing can be sent to them, but a blank
    // entry is still a configuration smell worth rejecting at create time.
    assert!(e.authorize(&t, "", 1, "simple_transfer").is_ok(), "documented: blank matches blank");
    assert!(e.authorize(&t, "   ", 1, "simple_transfer").is_ok());
}

#[test]
fn attack_an_empty_allowlist_blocks_outbound_but_not_inbound() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec![])); // "pay nobody"
    for r in ["1234", "0xdeadbeef", "https://good.example.com", ""] {
        assert!(e.authorize(&t, r, 1, "simple_transfer").is_err(), "`{r}` must be refused");
    }
    assert!(e.authorize(&t, SELF_RECIPIENT, 0, "simple_claim").is_ok(), "claims still fold funds in");
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 6 — Method gate and the SELF_RECIPIENT exemption.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attack_a_method_off_the_allowlist_is_denied_even_to_an_approved_recipient() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent-1", open_limits(), Some(vec!["1234".into()]), vec!["simple_claim".into()]);
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    for m in ["simple_transfer", "private_transfer", "withdraw", "deposit", "x402_fetch", "claim_deposit", "private_claim"] {
        let err = e.authorize(&t, "1234", 1, m).unwrap_err().to_string();
        assert!(err.contains("not allowed"), "`{m}` must be off-limits: {err}");
    }
    assert!(e.authorize(&t, SELF_RECIPIENT, 0, "simple_claim").is_ok(), "only the one granted method works");
}

/// Method names are matched exactly — no case folding, no prefix matching, no
/// separator tricks that would let a near-miss through.
#[test]
fn attack_method_names_are_matched_exactly() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("agent-1", open_limits(), None, vec!["simple_claim".into()]);
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    for near_miss in [
        "SIMPLE_CLAIM", "Simple_Claim", "simple_claim ", " simple_claim",
        "simple_claim\0", "simple_claims", "simple", "simple_transfer",
        "simple_claim;simple_transfer", "simple_claim\nsimple_transfer",
    ] {
        assert!(e.authorize(&t, "1", 1, near_miss).is_err(), "`{near_miss}` must not pass as simple_claim");
    }
    assert!(e.authorize(&t, "1", 1, "simple_claim").is_ok());
}

/// x402 payments and direct transfers are separately gated in BOTH directions,
/// so an owner can allow one without the other.
#[test]
fn attack_x402_and_simple_transfer_are_not_interchangeable() {
    let mut e = PolicyEngine::new();
    let transfers_only = e.create_policy("a", open_limits(), None, vec!["simple_transfer".into()]);
    let x402_only = e.create_policy("b", open_limits(), None, vec!["x402_fetch".into()]);
    let (t1, _) = e.issue_session(&transfers_only, 60).unwrap();
    let (t2, _) = e.issue_session(&x402_only, 60).unwrap();

    assert!(e.authorize(&t1, "1", 1, "simple_transfer").is_ok());
    assert!(e.authorize(&t1, "1", 1, "x402_fetch").is_err(), "paid fetches are separately approved");
    assert!(e.authorize(&t2, "1", 1, "x402_fetch").is_ok());
    assert!(e.authorize(&t2, "1", 1, "simple_transfer").is_err(), "and so are direct transfers");
}

/// FINDING (MEDIUM, defence-in-depth) — the inbound exemption tests the RAW
/// recipient string against the literal "self". Two tools pass an
/// agent-controlled string into that position (`withdraw.l1_recipient` and
/// `private_transfer.to_shielded_address`), so the agent can name any spend
/// "self" and skip the recipient allowlist entirely. Today the downstream
/// address parsers reject "self", so no funds move — the gate is what fails,
/// not the wallet, and a future lenient parser turns this into theft.
#[test]
#[ignore = "FINDING: the literal \"self\" bypasses the recipient allowlist on spend methods"]
fn finding_the_self_sentinel_must_not_exempt_a_spend_method() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    for method in ["withdraw", "private_transfer", "simple_transfer", "x402_fetch"] {
        assert!(
            e.authorize(&t, SELF_RECIPIENT, 1_000_000, method).is_err(),
            "`{method}` moves money OUT; \"self\" is not a payee it may name"
        );
    }
}

#[test]
fn documents_the_self_sentinel_bypass() {
    let (mut e, _pid, t) = engine_with(open_limits(), Some(vec!["1234".into()]));
    // Current behaviour: the allowlist is skipped for ANY method when the
    // recipient string is exactly "self".
    assert!(e.authorize(&t, SELF_RECIPIENT, 1_000_000, "withdraw").is_ok());
    assert!(e.authorize(&t, SELF_RECIPIENT, 1_000_000, "private_transfer").is_ok());
    // The hole is exact-match only — case and whitespace variants are denied.
    for variant in ["SELF", "Self", " self", "self ", "self\0", "sel f", "0xself"] {
        assert!(e.authorize(&t, variant, 1, "withdraw").is_err(), "`{variant}` must not be the sentinel");
    }
    // And a mixed alias list is not vacuous, so it is still checked.
    assert!(
        e.authorize_aliases(&t, &[SELF_RECIPIENT, "evil.com"], 1, "x402_fetch").is_err(),
        "one real recipient among the aliases restores the allowlist check"
    );
}

/// Whatever the exemption does to the ALLOWLIST, it must never touch the CAPS.
/// This is the property that keeps a claim from becoming an unlimited spend.
#[test]
fn attack_the_self_exemption_does_not_lift_the_amount_caps() {
    let limits = Limits { per_transaction: 100, per_day: 100, per_month: Some(100), total_budget: Some(100) };
    let (mut e, _pid, t) = engine_with(limits, Some(vec![]));
    assert!(e.authorize(&t, SELF_RECIPIENT, 101, "deposit").is_err(), "per-tx cap still applies to self");
    assert!(e.authorize(&t, SELF_RECIPIENT, 100, "deposit").is_ok());
    assert!(e.authorize(&t, SELF_RECIPIENT, 1, "deposit").is_err(), "daily cap still applies to self");
    // A paused policy freezes inbound operations too — that is the kill switch.
    assert!(e.authorize(&t, SELF_RECIPIENT, 0, "simple_claim").is_ok());
}

#[test]
fn attack_a_paused_policy_freezes_claims_too_so_pause_is_a_real_kill_switch() {
    let (mut e, pid, t) = engine_with(open_limits(), None);
    e.pause(&pid);
    for (r, m, amt) in [
        (SELF_RECIPIENT, "simple_claim", 0u64),
        (SELF_RECIPIENT, "private_claim", 0),
        (SELF_RECIPIENT, "claim_deposit", 0),
        ("1234", "simple_transfer", 1),
        ("1234", "x402_fetch", 1),
    ] {
        let err = e.authorize(&t, r, amt, m).unwrap_err().to_string();
        assert!(err.contains("paused"), "{m} must be frozen while paused: {err}");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 4 — Session abuse.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn attack_a_revoked_token_stays_dead() {
    let (mut e, pid, t) = engine_with(open_limits(), None);
    assert!(e.revoke(&t));
    assert!(!e.revoke(&t), "revoking twice reports honestly");
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err());
    assert!(e.budget(&t).is_none(), "and it can no longer even read the budget");
    assert!(e.policy_id_for_session(&t).is_none());
    // Pausing/resuming the policy must not resurrect it.
    e.pause(&pid);
    e.resume(&pid);
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "a revoked token is gone for good");
}

#[test]
fn attack_an_expired_token_is_dead_and_is_reaped() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("a", open_limits(), None, vec![]);
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    e.expire_session_for_test(&t);
    assert!(e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string().contains("expired"));
    assert!(e.policy_id_for_session(&t).is_none(), "expired tokens are dropped, not left to leak");
    assert_eq!(e.describe(&pid).unwrap().active_sessions, 0);
}

/// A year-long session defeats revocation, so the TTL is clamped. Absurd inputs
/// must clamp rather than overflow into a distant (or past) expiry.
#[test]
fn attack_an_absurd_ttl_is_clamped_to_twenty_four_hours() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("a", open_limits(), None, vec![]);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    for ttl in [u64::MAX, u64::MAX / 60, u64::MAX / 2, 525_600, 1_441, 100_000_000] {
        let (_t, exp) = e.issue_session(&pid, ttl).unwrap();
        assert!(exp >= now, "ttl {ttl} must not wrap into the past");
        assert!(exp - now <= DAY + 2, "ttl {ttl} must clamp to 24h, got {} seconds", exp - now);
    }
    let (_t, exp) = e.issue_session(&pid, 0).unwrap();
    assert!(exp - now <= 2, "a zero TTL is an immediately-dead session");
}

/// Tokens must be unguessable and never repeat.
#[test]
fn attack_session_tokens_are_unguessable_and_unique() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("a", open_limits(), None, vec![]);
    let mut seen = std::collections::HashSet::new();
    for _ in 0..2_000 {
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        assert_eq!(t.len(), 64, "32 bytes of entropy, hex-encoded");
        assert!(t.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(seen.insert(t), "a repeated session token would be a catastrophic PRNG failure");
    }
    // Nothing structural leaks the policy id into the token.
    assert!(seen.iter().all(|t| !t.contains(&pid)));
}

/// Guessed / forged / structurally-plausible tokens are all rejected.
#[test]
fn attack_forged_tokens_are_rejected() {
    let (mut e, pid, t) = engine_with(open_limits(), None);
    let forgeries = [
        String::new(),
        "0".repeat(64),
        "f".repeat(64),
        t.to_uppercase(),
        format!("{t} "),
        format!(" {t}"),
        t[..63].to_string(),
        format!("{t}0"),
        t.replacen('0', "1", 1),
        pid.clone(),
        format!("{pid}{pid}{pid}{pid}"),
        "../../etc/passwd".into(),
        "\0".repeat(64),
    ];
    for f in &forgeries {
        if f == &t { continue }
        assert!(e.authorize(f, "1", 1, "simple_transfer").is_err(), "forged token `{f}` must be rejected");
    }
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok(), "the real one still works");
}

#[test]
fn attack_a_session_cannot_be_minted_from_a_paused_policy() {
    let mut e = PolicyEngine::new();
    let pid = e.create_policy("a", open_limits(), None, vec![]);
    e.pause(&pid);
    let err = e.issue_session(&pid, 60).unwrap_err().to_string();
    assert!(err.contains("paused"), "{err}");
    assert!(e.issue_session("no-such-policy", 60).is_err(), "and not from a policy that does not exist");
}

/// A session is bound to ONE policy; it cannot be pointed at a wealthier one.
#[test]
fn attack_a_session_cannot_be_spent_against_another_policy() {
    let mut e = PolicyEngine::new();
    let poor = e.create_policy("a", Limits { per_transaction: 1, per_day: 1, ..open_limits() }, None, vec![]);
    let rich = e.create_policy("b", open_limits(), None, vec![]);
    let (t, _) = e.issue_session(&poor, 60).unwrap();
    assert_eq!(e.policy_id_for_session(&t).as_deref(), Some(poor.as_str()));
    assert!(e.authorize(&t, "1", 1_000, "simple_transfer").is_err(), "the poor policy's cap binds");
    assert_eq!(e.describe(&rich).unwrap().spent_total_nano, 0, "the rich policy was never touched");
}

/// INFORMATIONAL — resume() re-arms every token issued before the pause. That
/// is arguably the owner's intent, but it means `pause_policy` alone is not a
/// credential rotation: `revoke_session` is also required.
#[test]
fn documents_that_resume_rearms_pre_pause_sessions() {
    let (mut e, pid, t) = engine_with(open_limits(), None);
    e.pause(&pid);
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err());
    e.resume(&pid);
    assert!(e.authorize(&t, "1", 1, "simple_transfer").is_ok(), "the pre-pause token works again");
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 7 — Persistence: restart-to-reset, and a corrupt store.
// ─────────────────────────────────────────────────────────────────────────────

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let n: u64 = rand::random();
    std::env::temp_dir().join(format!("psy-mcp-adv-{tag}-{n:016x}"))
}

/// The lifetime budget is the one counter a restart could re-grant. It must not.
#[test]
fn attack_a_restart_does_not_re_grant_the_lifetime_budget() {
    let dir = temp_dir("restart");
    let limits = Limits { per_transaction: 100, per_day: 10_000, per_month: Some(10_000), total_budget: Some(300) };
    let pid = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("a", limits, None, vec![]);
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        for _ in 0..3 {
            e.authorize(&t, "1", 100, "simple_transfer").unwrap();
        }
        assert!(e.authorize(&t, "1", 1, "simple_transfer").is_err(), "lifetime budget spent");
        pid
    };
    // Crash-loop the server ten times; each restart must find the budget spent.
    for i in 0..10 {
        let mut e = PolicyEngine::load_or_new(&dir);
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        let err = e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string();
        assert!(err.contains("total budget"), "restart {i} re-granted the budget: {err}");
        assert_eq!(e.describe(&pid).unwrap().spent_total_nano, 300);
    }
    std::fs::remove_dir_all(&dir).ok();
}

/// The daily counter must survive a restart too, or a crash loop is a fresh day.
#[test]
fn attack_a_restart_does_not_reset_the_daily_counter() {
    let dir = temp_dir("daily");
    let limits = Limits { per_transaction: 100, per_day: 100, ..open_limits() };
    let pid = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("a", limits, None, vec![]);
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        e.authorize(&t, "1", 100, "simple_transfer").unwrap();
        pid
    };
    let mut e = PolicyEngine::load_or_new(&dir);
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    let err = e.authorize(&t, "1", 1, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("daily cap"), "the daily window survived the restart: {err}");
    std::fs::remove_dir_all(&dir).ok();
}

/// A paused policy must STAY paused across a restart — otherwise the kill
/// switch is undone by a crash.
#[test]
fn attack_a_restart_does_not_unpause_a_policy() {
    let dir = temp_dir("paused");
    let pid = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("a", open_limits(), None, vec![]);
        e.pause(&pid);
        pid
    };
    let mut e = PolicyEngine::load_or_new(&dir);
    assert!(!e.describe(&pid).unwrap().active, "the pause survived the restart");
    assert!(e.issue_session(&pid, 60).is_err(), "and no session can be minted");
    std::fs::remove_dir_all(&dir).ok();
}

/// Sessions must NOT survive a restart: forgetting them fails toward
/// re-authorization, never toward extra spend.
#[test]
fn attack_sessions_do_not_survive_a_restart() {
    let dir = temp_dir("sessions");
    let (pid, token) = {
        let mut e = PolicyEngine::load_or_new(&dir);
        let pid = e.create_policy("a", open_limits(), None, vec![]);
        let (t, _) = e.issue_session(&pid, 60).unwrap();
        (pid, t)
    };
    let mut e = PolicyEngine::load_or_new(&dir);
    assert!(e.authorize(&token, "1", 1, "simple_transfer").is_err(), "a stale token is not honoured");
    assert!(e.policy_id_for_session(&token).is_none());
    assert_eq!(e.describe(&pid).unwrap().active_sessions, 0);
    std::fs::remove_dir_all(&dir).ok();
}

/// The allowlist itself must survive a restart, or restarting widens the policy
/// to "pay anyone".
#[test]
fn attack_a_restart_does_not_widen_the_recipient_allowlist() {
    let dir = temp_dir("allowlist");
    let pid = {
        let mut e = PolicyEngine::load_or_new(&dir);
        e.create_policy("a", open_limits(), Some(vec!["1234".into()]), vec!["simple_transfer".into()])
    };
    let mut e = PolicyEngine::load_or_new(&dir);
    let (t, _) = e.issue_session(&pid, 60).unwrap();
    assert_eq!(e.describe(&pid).unwrap().allowed_recipient_count, Some(1));
    assert!(e.authorize(&t, "9999", 1, "simple_transfer").is_err(), "still restricted after a restart");
    assert!(e.authorize(&t, "1234", 1, "simple_transfer").is_ok());
    assert!(e.authorize(&t, "1234", 1, "withdraw").is_err(), "and the method list survived too");
    std::fs::remove_dir_all(&dir).ok();
}

/// A corrupt store must not fail OPEN. It does fail closed for spending (no
/// policies ⇒ no sessions ⇒ no spend) — but see the FINDING below for what it
/// destroys on the way.
#[test]
fn attack_a_corrupt_store_fails_closed_for_spending() {
    for garbage in [
        "",
        "{",
        "not json at all",
        "[]",
        "null",
        r#"{"abc": {"agent_id": "x"}}"#,               // right shape, missing fields
        r#"{"abc": {"agent_id":"x","limits":{"per_transaction":0,"per_day":0,"per_month":null,"total_budget":null},"allowed_recipients":null,"allowed_methods":[],"active":true,"spent_today":0,"spent_this_month":0,"spent_total":0,"last_day":0}}"#, // missing last_month
        "\u{0}\u{1}\u{2}",
    ] {
        let dir = temp_dir("corrupt");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("policies.json"), garbage).unwrap();
        let mut e = PolicyEngine::load_or_new(&dir);
        assert!(e.policy_ids().is_empty(), "a corrupt store must not yield a usable policy: {garbage:?}");
        assert!(e.issue_session("anything", 60).is_err());
        assert!(e.authorize("anything", "1", 1, "simple_transfer").is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}

/// FINDING (LOW) — a corrupt store is indistinguishable from a first run: the
/// engine logs a warning, starts empty, and the next `save()` OVERWRITES the
/// damaged file. Every spent counter (including the lifetime one) and every
/// pause is lost silently. If the operator can then re-create a policy — which
/// they can, and in owner-token-less dev mode so can the AGENT — a corrupted
/// file is a budget reset.
#[test]
#[ignore = "FINDING: a corrupt policies.json is silently discarded and then overwritten"]
fn finding_a_corrupt_store_must_be_quarantined_not_overwritten() {
    let dir = temp_dir("clobber");
    std::fs::create_dir_all(&dir).unwrap();
    let damaged = r#"{"deadbeef": {"agent_id":"a","limits":{"per_transaction":1"#; // truncated write
    std::fs::write(dir.join("policies.json"), damaged).unwrap();

    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy("fresh", open_limits(), None, vec![]);

    let on_disk = std::fs::read_to_string(dir.join("policies.json")).unwrap();
    assert!(
        on_disk.contains("deadbeef") || dir.join("policies.json.corrupt").exists(),
        "the unreadable prior state must be preserved or moved aside, not clobbered"
    );
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn documents_the_corrupt_store_clobber() {
    let dir = temp_dir("clobber-doc");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("policies.json"), r#"{"deadbeef": {"agent_id":"a","limi"#).unwrap();
    let mut e = PolicyEngine::load_or_new(&dir);
    e.create_policy("fresh", open_limits(), None, vec![]);
    let on_disk = std::fs::read_to_string(dir.join("policies.json")).unwrap();
    assert!(!on_disk.contains("deadbeef"), "current behaviour: prior state is gone");
    assert!(!dir.join("policies.json.corrupt").exists(), "and nothing was quarantined");
    std::fs::remove_dir_all(&dir).ok();
}

/// A leftover `.tmp` from an interrupted write must never be loaded as state.
#[test]
fn attack_a_stray_tmp_file_is_not_loaded_as_policy() {
    let dir = temp_dir("tmp");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("policies.json.tmp"),
        r#"{"attacker": {"agent_id":"evil","limits":{"per_transaction":18446744073709551615,"per_day":18446744073709551615,"per_month":null,"total_budget":null},"allowed_recipients":null,"allowed_methods":["simple_transfer"],"active":true,"spent_today":0,"spent_this_month":0,"spent_total":0,"last_day":0,"last_month":0}}"#,
    ).unwrap();
    let e = PolicyEngine::load_or_new(&dir);
    assert!(e.policy_ids().is_empty(), "only policies.json is authoritative");
    std::fs::remove_dir_all(&dir).ok();
}

// ─────────────────────────────────────────────────────────────────────────────
// ATTACK 8 — Panic-as-DoS on the policy surface.
// ─────────────────────────────────────────────────────────────────────────────

/// `normalize_recipient` sees raw, agent-chosen strings on every spend. A panic
/// here would poison the policy mutex (every call site is `lock().unwrap()`)
/// and permanently brick the wallet, `pause_policy` included.
#[test]
fn attack_normalize_recipient_never_panics_on_hostile_input() {
    let big_digits = "9".repeat(100_000);
    let big_hex = format!("0x{}", "f".repeat(100_000));
    let deep_scheme = "a://".repeat(10_000);
    let many_at = format!("https://{}", "@".repeat(10_000));
    let hostile: Vec<&str> = vec![
        "", " ", "\t\n\r", "\0", "\0\0\0",
        "://", ":///", "a://", "://@", "://.", "://...",
        "http://", "https://", "https://.", "https://...",
        "psy-", "psy--", "psy-0", "psy-x", "PSY-", "Psy-",
        "0x", "0X", "0x0", "0xg", "0x0x", "0x0x0x",
        "-1", "+1", "1e9", "0b1010", "0o777", "١٢٣٤", "１２３４",
        "\u{202e}1234", "1234\u{200b}", "🙂", "🙂://🙂@🙂",
        "//evil.com", "\\\\evil.com", "file:///etc/passwd",
        "http://[::1]:80/", "http://[fe80::1%25eth0]/",
        "http://user:pass@@@host/", "http://@/", "http://a@b@c@d/",
        &big_digits, &big_hex, &deep_scheme, &many_at,
        "340282366920938463463374607431768211456",   // u128::MAX + 1
        "115792089237316195423570985008687907853269984665640564039457584007913129639935",
    ];
    for h in hostile {
        let out = normalize_recipient(h);
        // The only contract: it returns, and the result is idempotent for the
        // shapes the allowlist stores (it is normalized at write time and
        // compared at read time, so a non-idempotent transform is a silent
        // allowlist mismatch).
        let twice = normalize_recipient(&out);
        assert_eq!(
            out, twice,
            "normalization must be idempotent or an allowlist entry drifts from the value it is compared against: {h:?}"
        );
    }
}

/// Every entry point takes hostile arguments without panicking.
#[test]
fn attack_the_engine_surface_never_panics_on_hostile_arguments() {
    let limits = Limits { per_transaction: u64::MAX, per_day: u64::MAX, per_month: Some(u64::MAX), total_budget: Some(u64::MAX) };
    let mut e = PolicyEngine::new();
    let pid = e.create_policy(&"A".repeat(100_000), limits, Some(vec!["".into(), "\0".into(), "🙂".into()]), vec!["".into(), "\0".into()]);
    let (t, _) = e.issue_session(&pid, 60).unwrap();

    assert!(e.authorize(&t, &"z".repeat(100_000), 0, &"m".repeat(100_000)).is_err());
    assert!(e.authorize("", "", 0, "").is_err());
    assert!(e.authorize(&t, "\0", u64::MAX, "not_a_method").is_err(), "an unlisted method is refused");
    // A NUL-named method genuinely IS on this policy's list, and u64::MAX is
    // genuinely under a u64::MAX cap — the gate approves it without panicking,
    // which is the property under test here.
    assert!(e.authorize(&t, "\0", u64::MAX, "\0").is_ok(), "absurd-but-consistent limits are honoured, not crashed");
    assert!(e.budget(&"\0".repeat(1000)).is_none());
    assert!(e.policy_id_for_session("").is_none());
    assert!(e.describe(&"?".repeat(100_000)).is_err());
    assert!(e.describe("").is_err());
    assert_eq!(e.spend_log(0, None).len(), 0);
    assert_eq!(e.spend_log(usize::MAX, Some("nope")).len(), 0);
    assert!(!e.pause(""));
    assert!(!e.resume(&"\0".repeat(64)));
    assert!(!e.revoke(""));

    // describe() formats every limit; u64::MAX must not overflow the formatter.
    let d = e.describe(&pid).unwrap();
    assert!(d.summary.contains("PSY"), "{}", d.summary);
    assert_eq!(d.per_transaction_nano, u64::MAX);
    assert_eq!(d.spent_total_nano, u64::MAX, "the one approved spend was recorded");
    assert_eq!(d.remaining_total_nano, Some(0), "and it exhausted the budget rather than wrapping");
}

/// The audit ring is bounded, so an agent cannot exhaust memory by spending in
/// a tight loop, and the newest decisions are the ones retained.
#[test]
fn attack_the_spend_log_cannot_be_grown_without_bound() {
    let (mut e, _pid, t) = engine_with(open_limits(), None);
    for i in 0..5_000u64 {
        e.authorize(&t, "1", i % 10, "simple_transfer").unwrap();
    }
    assert!(e.spend_log_len() <= 100, "the ring is capped, got {}", e.spend_log_len());
    assert_eq!(e.spend_log(usize::MAX, None).len(), e.spend_log_len());
}

/// A denial must never be recorded as a spend — the audit trail is what the
/// owner reads to answer "what did my agent do".
#[test]
fn attack_denied_attempts_never_enter_the_audit_trail() {
    let (mut e, pid, t) = engine_with(Limits { per_transaction: 5, ..open_limits() }, Some(vec!["1234".into()]));
    let _ = e.authorize(&t, "9999", 1, "simple_transfer");   // allowlist
    let _ = e.authorize(&t, "1234", 500, "simple_transfer"); // per-tx cap
    let _ = e.authorize(&t, "1234", 1, "sudo_drain");        // method
    let _ = e.authorize("bogus", "1234", 1, "simple_transfer"); // session
    e.pause(&pid);
    let _ = e.authorize(&t, "1234", 1, "simple_transfer");   // paused
    assert_eq!(e.spend_log(100, None).len(), 0, "only approvals are spends");
    assert_eq!(e.describe(&pid).unwrap().spent_total_nano, 0);
}

/// `describe()` must not hand the agent a directory of payees to try.
#[test]
fn attack_describe_does_not_leak_the_allowlist_contents() {
    let secrets = vec!["4815162342".to_string(), "0xfeedface".to_string(), "https://private.seller.example".to_string()];
    let (mut e, pid, _t) = engine_with(open_limits(), Some(secrets.clone()));
    let d = e.describe(&pid).unwrap();
    let rendered = format!("{} {}", d.summary, serde_json::to_string(&d).unwrap());
    for s in &secrets {
        assert!(!rendered.contains(s.trim_start_matches("https://")), "leaked `{s}` in: {rendered}");
    }
    assert_eq!(d.allowed_recipient_count, Some(3), "the agent learns it is constrained, and how tightly");

    // A denial names the attempted recipient and the list SIZE only.
    let err = e.authorize(&_t, "9999", 1, "simple_transfer").unwrap_err().to_string();
    assert!(err.contains("9999"));
    for s in &secrets {
        assert!(!err.contains(s.trim_start_matches("https://")), "denial leaked `{s}`: {err}");
    }
}
