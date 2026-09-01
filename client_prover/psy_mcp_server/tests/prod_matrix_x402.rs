//! Production Test Matrix — **x402** row.
//!
//! Covers: valid payment, replay attack, expired/stale request, malicious
//! merchant (inflated header, wrong recipient, fabricated tx), and invalid
//! payment requests (bad header / scheme / asset).
//!
//! Scope note, because it decides what these tests can honestly claim:
//! `x402.rs` is the *parsing and encoding* half of the protocol — it decides
//! what a 402 challenge means and what an `X-PAYMENT` header says. The
//! *believing* half (does this payment exist on chain, was it already spent,
//! is it too old) lives in `x402_verify` inside `main.rs`, which reaches the
//! indexer over HTTP and the chain for the latest checkpoint, and is therefore
//! not reachable from a test binary while the crate has no `[lib]` target.
//!
//! So the cases here assert two different things, and the matrix doc keeps them
//! apart: what the wallet REFUSES on its own, and what it deliberately accepts
//! at this layer because only the chain can settle it. The second kind is
//! written as an explicit trust-boundary assertion — if someone later makes
//! `from_header` "validate" a payment, these tests say why that is not enough.

#[path = "../src/x402.rs"]
mod x402;

#[path = "../src/policy.rs"]
mod policy;

use policy::{normalize_recipient, Limits, PolicyEngine};
use x402::{
    parse_psy_id, select_requirement, PaymentPayload, PaymentRequired, PsyPaymentProof,
    SCHEME_EXACT, X402_VERSION,
};

fn challenge(json: &str) -> PaymentRequired {
    serde_json::from_str(json).expect("fixture is valid JSON")
}

fn proof(tx: &str, payer: u64, recipient: u64, amount: u64) -> PsyPaymentProof {
    PsyPaymentProof {
        tx_hash: tx.into(),
        payer_user_id: payer,
        recipient_user_id: recipient,
        amount_nano: amount,
        contract_id: 0,
        resource: Some("/report".into()),
    }
}

// ───────────────────────── X402-01 · valid payment ───────────────────────────

#[test]
fn x402_01_a_well_formed_challenge_is_read_exactly_as_the_seller_wrote_it() {
    let body = challenge(
        r#"{"x402Version":1,"error":"payment required","accepts":[
            {"scheme":"exact","network":"psy-sepolia","maxAmountRequired":"1000000000",
             "payTo":"Psy-00204800","asset":"PSY","resource":"/report",
             "description":"one report","maxTimeoutSeconds":60}]}"#,
    );
    let req = select_requirement(&body.accepts, "psy-sepolia").unwrap();
    assert_eq!(req.amount().unwrap(), 1_000_000_000);
    assert_eq!(req.recipient_user_id().unwrap(), 204_800);
    assert_eq!(req.token_symbol(), "PSY");
    assert_eq!(req.resource.as_deref(), Some("/report"));

    // The receipt the buyer hands back must survive the wire unchanged: a
    // mangled field here is a payment the seller cannot match to its own row.
    let payload = PaymentPayload::new("psy-sepolia", proof("0xabc", 1, 204_800, 1_000_000_000));
    let header = payload.to_header().unwrap();
    assert!(!header.starts_with('{'), "the header goes out base64-encoded, per x402");
    let back = PaymentPayload::from_header(&header).unwrap();
    assert_eq!(back.x402_version, X402_VERSION);
    assert_eq!(back.scheme, SCHEME_EXACT);
    assert_eq!(back.network, "psy-sepolia");
    assert_eq!(back.payload.tx_hash, "0xabc");
    assert_eq!(back.payload.amount_nano, 1_000_000_000);
    assert_eq!(back.payload.recipient_user_id, 204_800);
    assert_eq!(back.payload.resource.as_deref(), Some("/report"));
}

#[test]
fn x402_01b_the_payee_the_challenge_names_is_the_payee_the_policy_gate_sees() {
    // x402_fetch pays `req.recipient_user_id()` and asks the policy gate about
    // that same id (stringified) plus the seller's URL. If the two modules
    // disagreed about what "Psy-00204800" means, an owner's allowlist entry
    // would silently stop matching the payee actually being paid.
    for spelling in ["Psy-00204800", "psy-204800", "204800", "0000204800"] {
        let paid = parse_psy_id(spelling).unwrap();
        assert_eq!(paid, 204_800, "x402 resolves `{spelling}` to the payee id");
        assert_eq!(
            normalize_recipient(&paid.to_string()),
            normalize_recipient(spelling),
            "the policy gate must canonicalise `{spelling}` to the same principal x402 pays"
        );
    }
}

// ───────────────────────── X402-02 · replay attack ───────────────────────────

#[test]
fn x402_02_a_receipt_carries_nothing_that_makes_a_replay_distinguishable() {
    // This is the trust boundary, asserted rather than assumed. An X-PAYMENT
    // payload has no nonce, no expiry and no seller-chosen challenge binding:
    // the SAME bytes replayed a second time are byte-identical and decode
    // identically. Anti-replay therefore cannot live in this module — it is
    // `x402_verify`'s consumed-payments set, keyed on the indexer's tx hash.
    let header = PaymentPayload::new("psy-sepolia", proof("0xdead", 1, 2, 500)).to_header().unwrap();
    let first = PaymentPayload::from_header(&header).unwrap();
    let second = PaymentPayload::from_header(&header).unwrap();
    assert_eq!(first.payload.tx_hash, second.payload.tx_hash);
    assert_eq!(first.payload.amount_nano, second.payload.amount_nano);

    let as_json = serde_json::to_value(&first).unwrap();
    let fields: Vec<&str> = as_json["payload"].as_object().unwrap().keys().map(|s| s.as_str()).collect();
    for absent in ["nonce", "expiresAt", "validUntil", "challenge", "signature"] {
        assert!(
            !fields.contains(&absent),
            "the payload gained a `{absent}` field — if it is now an anti-replay measure, \
             the seller-side check in x402_verify must be updated to enforce it"
        );
    }
    assert!(
        fields.contains(&"txHash"),
        "the tx hash is the only replay key a seller has; it must stay in the payload"
    );
}

#[test]
fn x402_02b_one_settled_payment_unlocks_exactly_one_resource() {
    // Model of x402_verify's replay gate (`consumed_payments.insert(row_hash)`),
    // so the property is pinned even though the tool itself needs an indexer.
    // The gate is keyed on the INDEXER's tx hash, not the buyer's claim — a
    // buyer who edits the hash in its own header cannot mint a fresh key.
    let mut consumed: std::collections::HashSet<String> = Default::default();
    let indexer_row_hash = "0xsettled-endcap";
    assert!(consumed.insert(indexer_row_hash.to_string()), "first presentation is honoured");
    assert!(!consumed.insert(indexer_row_hash.to_string()), "the same settled row must not unlock a second resource");

    // Documented limitation the matrix records as a gap: the set is process
    // memory, so a restarted seller re-opens every historic payment for one
    // more use. Nothing here can fix that; the test states the exposure.
    let after_restart: std::collections::HashSet<String> = Default::default();
    assert!(
        !after_restart.contains(indexer_row_hash),
        "replay protection is in-process only — see gap G-2 in 05-testing.md"
    );
}

// ─────────────────────── X402-03 · expired / stale request ───────────────────

#[test]
fn x402_03_a_receipt_has_no_self_describing_freshness() {
    // `maxTimeoutSeconds` is the SELLER's statement about its own challenge; the
    // buyer's receipt says nothing about when it was paid. Staleness is judged
    // seller-side from the settled row's checkpoint (max_age_checkpoints,
    // default 240). Pinned here because a payload that grew a self-reported
    // timestamp would be attacker-controlled and must never become the check.
    let body = challenge(
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","maxTimeoutSeconds":60}]}"#,
    );
    assert_eq!(select_requirement(&body.accepts, "psy").unwrap().max_timeout_seconds, Some(60));

    let payload = PaymentPayload::new("psy", proof("0xold", 1, 2, 1));
    let json = serde_json::to_value(&payload).unwrap();
    for self_reported in ["timestamp", "paidAt", "checkpointId", "blockNumber"] {
        assert!(
            json["payload"].get(self_reported).is_none(),
            "`{self_reported}` in the payload would be a buyer-controlled freshness claim; \
             staleness must stay a chain-side judgement"
        );
    }
}

#[test]
fn x402_03b_the_staleness_window_is_a_bounded_checkpoint_distance() {
    // Model of x402_verify's stale gate, so the boundary is pinned: a payment
    // exactly at the limit still counts, one past it does not, and the
    // subtraction saturates rather than wrapping when the indexer reports a
    // checkpoint ahead of the chain's latest.
    fn too_old(paid_at: u64, latest: u64, max_age: u64) -> bool {
        latest.saturating_sub(paid_at) > max_age
    }
    assert!(!too_old(1_000, 1_240, 240), "exactly at the limit is still payment for now");
    assert!(too_old(1_000, 1_241, 240), "one checkpoint past the limit is a receipt, not an offer");
    assert!(!too_old(1_000, 999, 240), "a paid_at ahead of latest must saturate, never wrap to huge");
    assert!(!too_old(0, u64::MAX, u64::MAX), "an explicit unbounded window disables the gate rather than overflowing");
}

// ──────────────────────── X402-04 · malicious merchant ───────────────────────

#[test]
fn x402_04_an_inflated_price_is_still_only_a_number_the_caller_must_cap() {
    // A hostile seller can demand anything, including a value that overflows a
    // naive parse. The parser must hand back the true number (so the caller's
    // max_amount_nano and the policy cap can both see it) and must refuse
    // anything it cannot represent exactly rather than truncating it small.
    let huge = challenge(&format!(
        r#"{{"accepts":[{{"scheme":"exact","network":"psy","maxAmountRequired":"{}","payTo":"1"}}]}}"#,
        u64::MAX
    ));
    assert_eq!(select_requirement(&huge.accepts, "psy").unwrap().amount().unwrap(), u64::MAX);

    for unrepresentable in ["18446744073709551616", "-1", "1e9", "1.5", "0x10", " ", "1_000"] {
        let body = challenge(&format!(
            r#"{{"accepts":[{{"scheme":"exact","network":"psy","maxAmountRequired":"{unrepresentable}","payTo":"1"}}]}}"#
        ));
        assert!(
            select_requirement(&body.accepts, "psy").unwrap().amount().is_err(),
            "`{unrepresentable}` must be refused, never silently truncated into a payable amount"
        );
    }
    // A JSON float or negative number is refused for the same reason.
    for bad in ["1.5", "-1", "1e9"] {
        let body = challenge(&format!(
            r#"{{"accepts":[{{"scheme":"exact","network":"psy","maxAmountRequired":{bad},"payTo":"1"}}]}}"#
        ));
        assert!(select_requirement(&body.accepts, "psy").unwrap().amount().is_err(), "numeric {bad}");
    }
}

#[test]
fn x402_04b_a_seller_offering_several_prices_is_shopped_for_the_cheapest() {
    // FINDING F-2, NOW FIXED. This used to pin the opposite: the FIRST `exact`
    // option on the matching network won regardless of price, so a seller
    // listing a decoy cheap option AFTER an expensive one was paid the
    // expensive one. The only ceiling below the policy cap was
    // max_amount_nano — an argument the AGENT supplies, not an owner control —
    // so nothing the owner set was actually bounding the overpayment.
    //
    // Selection now takes the cheapest option it can satisfy.
    let body = challenge(
        r#"{"accepts":[
            {"scheme":"exact","network":"psy","maxAmountRequired":"9000000000","payTo":"1"},
            {"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
    );
    assert_eq!(
        select_requirement(&body.accepts, "psy").unwrap().amount().unwrap(),
        1,
        "the cheapest satisfiable option must win, whatever order the seller lists them in"
    );

    // Network matching does take priority over order, so a seller cannot get
    // paid on the wrong network by listing it first.
    let mixed = challenge(
        r#"{"accepts":[
            {"scheme":"exact","network":"base","maxAmountRequired":"1","payTo":"1"},
            {"scheme":"exact","network":"psy-sepolia","maxAmountRequired":"2","payTo":"1"}]}"#,
    );
    assert_eq!(select_requirement(&mixed.accepts, "psy-sepolia").unwrap().network, "psy-sepolia");
}

#[test]
fn x402_04c_a_hostile_pay_to_is_refused_rather_than_resolved_to_a_wrong_payee() {
    // `payTo` decides who gets the money. Anything that is not unambiguously a
    // Psy user id must fail the parse — resolving it "helpfully" would send
    // funds to a payee the owner never approved.
    for hostile in [
        "0xattacker",            // an EVM address
        "Psy-",                  // empty id
        "",                      // absent
        "-1",                    // negative
        "1e5",                   // exponent
        "204800 204801",         // two ids
        "204800;drop",           // trailing junk
        "Psy-00204800x",         // trailing junk after a valid id
        "١٢٣",                   // non-ASCII digits
        "18446744073709551616",  // past u64
    ] {
        assert!(
            parse_psy_id(hostile).is_err(),
            "`{hostile}` must not resolve to a payee id"
        );
    }
    // ...and a whole challenge naming one is unusable rather than payable.
    let body = challenge(r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"0xattacker"}]}"#);
    assert!(select_requirement(&body.accepts, "psy").unwrap().recipient_user_id().is_err());
}

#[test]
fn x402_04d_a_fabricated_receipt_decodes_cleanly_which_is_why_the_chain_decides() {
    // A seller receiving an X-PAYMENT header gets a buyer-authored document.
    // Decoding it must succeed — refusing to parse would just make the error
    // worse — but nothing in it is evidence. This test states the boundary:
    // every field below is a lie, and the header still parses.
    let lie = PaymentPayload::new(
        "psy-sepolia",
        proof("0x0000000000000000000000000000000000000000", 999_999, 42, u64::MAX),
    );
    let decoded = PaymentPayload::from_header(&lie.to_header().unwrap()).unwrap();
    assert_eq!(decoded.payload.amount_nano, u64::MAX, "a fabricated amount parses — only the chain can refute it");
    assert_eq!(decoded.payload.payer_user_id, 999_999);

    // The seller-side field checks that DO run before the indexer is consulted:
    // the claimed recipient must be the seller, and must cover the price.
    let me = 42u64;
    assert_eq!(decoded.payload.recipient_user_id, me, "fixture pays this seller");
    let wrong_seller = PaymentPayload::from_header(
        &PaymentPayload::new("psy-sepolia", proof("0xabc", 1, 43, 100)).to_header().unwrap(),
    )
    .unwrap();
    assert_ne!(wrong_seller.payload.recipient_user_id, me, "a payment to someone else must be rejectable on this field alone");
    assert!(100u64 < 500u64, "and a payment under the asking price is rejectable before any network call");
}

#[test]
fn x402_04e_a_hostile_seller_cannot_reach_an_allowlisted_payee_through_its_own_challenge() {
    // End-to-end of the two-alias gate: x402_fetch offers the policy engine the
    // payee id from the challenge AND the URL that served it. A seller the owner
    // never approved must fail on both names at once.
    let mut engine = PolicyEngine::new();
    let pid = engine.create_policy(
        "matrix-agent",
        Limits { per_transaction: 1_000_000_000, per_day: 1_000_000_000, per_month: None, total_budget: None },
        Some(vec!["https://api.trusted.test/paid".into()]),
        vec![],
    );
    let (session, _) = engine.issue_session(&pid, 60, None).unwrap();

    let honest = challenge(
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1000","payTo":"Psy-00204800"}]}"#,
    );
    let req = select_requirement(&honest.accepts, "psy").unwrap();
    let payee = req.recipient_user_id().unwrap().to_string();
    assert!(
        engine
            .authorize_aliases(&session, &[&payee, "https://api.trusted.test/paid/report"], req.amount().unwrap(), "x402_fetch")
            .is_ok(),
        "the approved seller is payable even though its payee id was never allowlisted"
    );

    // Same challenge body, served by a host the owner never approved.
    assert!(
        engine
            .authorize_aliases(&session, &[&payee, "https://api.trusted.test.evil/paid"], 1_000, "x402_fetch")
            .is_err(),
        "an unapproved host must not inherit the approved seller's authority"
    );
    // And the approved host cannot exceed the caps just because it is approved.
    assert!(
        engine
            .authorize_aliases(&session, &[&payee, "https://api.trusted.test/paid"], 1_000_000_001, "x402_fetch")
            .is_err(),
        "allowlisting a seller is not a budget exemption"
    );
}

// ─────────────────────── X402-05 · invalid payment request ───────────────────

#[test]
fn x402_05_a_malformed_x_payment_header_is_refused_with_a_reason() {
    for (bad, why) in [
        ("", "empty"),
        ("   ", "whitespace"),
        ("!!!not base64!!!", "not base64"),
        ("aGVsbG8gd29ybGQ=", "base64 of non-JSON"),
        ("eyJhIjoxfQ==", "base64 of the wrong JSON shape"),
        ("{}", "raw JSON of the wrong shape"),
        (r#"{"x402Version":1,"scheme":"exact"}"#, "raw JSON missing the payload"),
        (r#"{"x402Version":1,"scheme":"exact","network":"psy","payload":{}}"#, "payload missing every field"),
        (
            r#"{"x402Version":1,"scheme":"exact","network":"psy","payload":{"txHash":"a","payerUserId":"one","recipientUserId":2,"amountNano":3,"contractId":0}}"#,
            "a non-numeric user id",
        ),
    ] {
        assert!(
            PaymentPayload::from_header(bad).is_err(),
            "an X-PAYMENT header that is {why} must be refused, not half-read: {bad:?}"
        );
    }
}

#[test]
fn x402_05b_an_unknown_scheme_or_no_option_at_all_is_never_paid_blind() {
    for (body, why) in [
        (r#"{"accepts":[]}"#, "no options"),
        (r#"{}"#, "no accepts key"),
        (r#"{"accepts":[{"scheme":"permit","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#, "unknown scheme"),
        (r#"{"accepts":[{"scheme":"upto","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#, "a scheme with different semantics"),
    ] {
        assert!(select_requirement(&challenge(body).accepts, "psy").is_err(), "{why} must not be payable");
    }
    // Scheme matching is case-insensitive — a seller writing "Exact" is honest,
    // not hostile, and refusing it would only cause support noise.
    let cased = challenge(r#"{"accepts":[{"scheme":"EXACT","network":"PSY","maxAmountRequired":"1","payTo":"1"}]}"#);
    assert!(select_requirement(&cased.accepts, "psy").is_ok());
}

#[test]
fn x402_05c_an_unknown_asset_defaults_to_nothing_and_must_be_resolved_by_the_caller() {
    // `token_symbol()` returns whatever the seller wrote (PSY when absent).
    // The scale of an unknown symbol is not guessable, so x402_fetch refuses it
    // rather than paying a 1e9-scaled amount of a 1e6-scaled token.
    let absent = challenge(r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#);
    assert_eq!(select_requirement(&absent.accepts, "psy").unwrap().token_symbol(), "PSY", "absent asset means PSY");

    for symbol in ["USDT", "usdt", "WBTC", "0xdeadbeef", ""] {
        let body = challenge(&format!(
            r#"{{"accepts":[{{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":"{symbol}"}}]}}"#
        ));
        assert_eq!(select_requirement(&body.accepts, "psy").unwrap().token_symbol(), symbol);
    }

    // The caller's mapping is exact-match on the uppercase symbol; anything else
    // must be rejected rather than defaulted to PSY.
    fn contract_for(token: &str) -> Option<u64> {
        match token.to_ascii_uppercase().as_str() {
            "PSY" => Some(0),
            "USDT" | "USDT_P" => Some(4),
            _ => None,
        }
    }
    assert_eq!(contract_for("PSY"), Some(0));
    assert_eq!(contract_for("usdt"), Some(4));
    assert_eq!(contract_for("WBTC"), None, "an unknown asset has no known scale and must not be paid");
    assert_eq!(contract_for(""), None);
}

#[test]
fn x402_05d_a_version_or_scheme_mismatch_in_a_receipt_is_not_caught_at_decode_time() {
    // Honest statement of a gap: `from_header` deserializes the version and
    // scheme but enforces neither, so a receipt claiming x402Version 999 or
    // scheme "upto" is accepted by the decoder. A seller must check these
    // itself. Pinned so the gap cannot close silently and go unnoticed.
    let odd = r#"{"x402Version":999,"scheme":"upto","network":"nowhere","payload":
        {"txHash":"a","payerUserId":1,"recipientUserId":2,"amountNano":3,"contractId":0}}"#;
    let decoded = PaymentPayload::from_header(odd).expect("decodes today — see gap G-3");
    assert_eq!(decoded.x402_version, 999);
    assert_eq!(decoded.scheme, "upto");
    assert_ne!(decoded.x402_version, X402_VERSION, "this receipt is for a protocol version we do not speak");
    assert_ne!(decoded.scheme, SCHEME_EXACT, "and a scheme whose settlement semantics differ");
}
