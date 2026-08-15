//! Adversarial tests for the x402 payment surface.
//!
//! Two hostile parties here, and both are modelled:
//!   * a hostile SELLER, whose 402 challenge is attacker-controlled JSON that
//!     the agent is about to pay against (`select_requirement`, `amount`,
//!     `recipient_user_id`, `token_symbol`);
//!   * a hostile BUYER, whose `X-PAYMENT` header is attacker-controlled and is
//!     the only thing `x402_verify` has before it consults the chain
//!     (`PaymentPayload::from_header`).
//!
//! Naming follows adversarial_policy.rs: `attack_*` passing = attack blocked,
//! `finding_*` = `#[ignore]`d, asserts the secure behaviour, fails today.

#[allow(dead_code, unused_imports)]
#[path = "../src/x402.rs"]
mod x402;

use x402::{parse_psy_id, select_requirement, PaymentPayload, PaymentRequired, PsyPaymentProof};

fn challenge(json: &str) -> PaymentRequired {
    serde_json::from_str(json).unwrap()
}

fn proof() -> PsyPaymentProof {
    PsyPaymentProof {
        tx_hash: "abc123".into(),
        payer_user_id: 7,
        recipient_user_id: 9,
        amount_nano: 1_000,
        contract_id: 0,
        resource: Some("/report".into()),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hostile SELLER — the 402 challenge is attacker-controlled.
// ─────────────────────────────────────────────────────────────────────────────

/// A challenge that does not state a price must be an error, never a zero or a
/// default payment. This is what stops "pay whatever you think is right".
#[test]
fn attack_an_unstated_or_unparseable_price_is_refused_not_guessed() {
    for body in [
        r#"{"accepts":[{"scheme":"exact","network":"psy","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":null,"payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"abc","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1_000","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"0x3e8","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1e9","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"+1000","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"-1000","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":-1,"payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":1.5,"payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":true,"payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":[1000],"payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"18446744073709551616","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":" 1000 000","payTo":"1"}]}"#,
    ] {
        let c = challenge(body);
        let r = select_requirement(&c.accepts, "psy").unwrap();
        assert!(r.amount().is_err(), "must refuse to price this challenge: {body}");
    }
    // Whitespace around an otherwise honest integer is tolerated.
    let c = challenge(r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"  1000\n","payTo":"1"}]}"#);
    assert_eq!(select_requirement(&c.accepts, "psy").unwrap().amount().unwrap(), 1_000);
}

/// An unknown scheme means we do not understand what is being asked for.
/// Paying anyway is paying blind, so selection must fail.
#[test]
fn attack_an_unknown_scheme_is_never_paid_blind() {
    for body in [
        r#"{"accepts":[{"scheme":"permit","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"upto","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact ","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
        r#"{"accepts":[{"scheme":"exact\u0000","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#,
        r#"{"accepts":[]}"#,
        r#"{}"#,
        r#"{"accepts":[],"error":"pay me"}"#,
    ] {
        assert!(select_requirement(&challenge(body).accepts, "psy").is_err(), "must not select: {body}");
    }
    // Case-insensitivity is deliberate and IS accepted.
    for ok in ["exact", "EXACT", "Exact", "eXaCt"] {
        let body = format!(r#"{{"accepts":[{{"scheme":"{ok}","network":"PSY","maxAmountRequired":"1","payTo":"1"}}]}}"#);
        assert!(select_requirement(&challenge(&body).accepts, "psy").is_ok(), "`{ok}` is the exact scheme");
    }
}

/// A seller who offers a cheap option on our network and an expensive one on
/// another must not get us to take the expensive one. Network-matching wins.
#[test]
fn attack_a_seller_cannot_steer_us_off_our_own_network() {
    let c = challenge(
        r#"{"accepts":[
            {"scheme":"exact","network":"base","maxAmountRequired":"999999999","payTo":"1"},
            {"scheme":"exact","network":"psy-sepolia","maxAmountRequired":"1000","payTo":"2"}
        ]}"#,
    );
    let r = select_requirement(&c.accepts, "psy-sepolia").unwrap();
    assert_eq!(r.amount().unwrap(), 1_000, "the option on OUR network is the one taken");
    assert_eq!(r.recipient_user_id().unwrap(), 2);
}

/// An unknown asset must not be settled at PSY scale — 1000 "USDC" base units
/// paid as 1000 Nano (or worse, at USDC's 6 decimals against 9) is a silent
/// 1000x. `contract_for` in main.rs is what refuses; this pins the symbol the
/// challenge hands it, including the shapes designed to slip past a match.
#[test]
fn attack_the_asset_symbol_is_reported_verbatim_for_the_caller_to_refuse() {
    let cases = [
        (r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":"USDC"}]}"#, "USDC"),
        (r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":"psy "}]}"#, "psy "),
        (r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":""}]}"#, ""),
        (r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":"PSY\u0000"}]}"#, "PSY\0"),
        (r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","asset":"ΡSY"}]}"#, "ΡSY"), // Greek Rho
    ];
    for (body, expected) in cases {
        let c = challenge(body);
        assert_eq!(select_requirement(&c.accepts, "psy").unwrap().token_symbol(), expected);
    }
    // Absent asset means PSY — the wallet's native unit, not a guess.
    let c = challenge(r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1"}]}"#);
    assert_eq!(select_requirement(&c.accepts, "psy").unwrap().token_symbol(), "PSY");
}

/// A challenge naming an unpayable payee must error rather than resolve to
/// user 0 (the coordinator) or to some default.
#[test]
fn attack_an_unpayable_payee_is_an_error_not_user_zero() {
    for pay_to in [
        "", " ", "0xabc", "0xdeadbeef", "Psy-", "psy-", "PSY-", "Psy-abc", "pSy-1234",
        "1234abc", "-1", "+1", "1.0", "1e3", "١٢٣٤", "18446744073709551616",
        "Psy-18446744073709551616", "self", "\0", "1234\0", "psy-1234 5",
    ] {
        assert!(parse_psy_id(pay_to).is_err(), "`{pay_to}` must not resolve to a payable user id");
    }
    // The forms a Psy ID is actually displayed in all resolve, including zero.
    for (raw, id) in [
        ("Psy-00204800", 204_800u64), ("psy-204800", 204_800), ("PSY-204800", 204_800),
        ("204800", 204_800), ("0000204800", 204_800), (" 204800 ", 204_800),
        ("Psy-00000000", 0), ("0", 0), ("000", 0),
        ("18446744073709551615", u64::MAX),
    ] {
        assert_eq!(parse_psy_id(raw).unwrap(), id, "`{raw}`");
    }
}

/// A pathological challenge body must be rejected by the parser, not blow the
/// stack or hang. The body is attacker-controlled and arrives over the network.
#[test]
fn attack_a_pathological_challenge_body_does_not_panic_the_parser() {
    let deep = format!("{}{}", "[".repeat(50_000), "]".repeat(50_000));
    let bodies = vec![
        String::new(),
        "null".into(),
        "[]".into(),
        "\"a string\"".into(),
        "{".into(),
        format!(r#"{{"accepts":{deep}}}"#),
        format!(r#"{{"accepts":[{{"scheme":"exact","network":"psy","maxAmountRequired":"1","payTo":"1","description":"{}"}}]}}"#, "A".repeat(1_000_000)),
        // 5k options, each with a different price — selection must terminate.
        format!(
            r#"{{"accepts":[{}]}}"#,
            (0..5_000)
                .map(|i| format!(r#"{{"scheme":"nope","network":"x","maxAmountRequired":"{i}","payTo":"{i}"}}"#))
                .collect::<Vec<_>>()
                .join(",")
        ),
    ];
    for body in bodies {
        match serde_json::from_str::<PaymentRequired>(&body) {
            Ok(c) => {
                // Whatever parsed, downstream must not panic either.
                if let Ok(r) = select_requirement(&c.accepts, "psy") {
                    let _ = r.amount();
                    let _ = r.recipient_user_id();
                    let _ = r.token_symbol();
                }
            }
            Err(_) => {} // refusing to parse is the correct outcome
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hostile BUYER — the X-PAYMENT header is attacker-controlled.
// ─────────────────────────────────────────────────────────────────────────────

/// Decoding a header is NOT verifying it. This test exists to pin that
/// distinction: any buyer can mint a syntactically perfect proof for any tx
/// hash, payer, recipient and amount. Everything that makes it true is the
/// chain lookup in `x402_verify` — see the report's x402 section.
#[test]
fn attack_a_fully_fabricated_payment_header_decodes_and_carries_no_authority() {
    let forged = PaymentPayload::new(
        "psy-sepolia",
        PsyPaymentProof {
            tx_hash: "0".repeat(64),
            payer_user_id: u64::MAX,
            recipient_user_id: 1,
            amount_nano: u64::MAX,
            contract_id: 0,
            resource: Some("/premium".into()),
        },
    );
    let header = forged.to_header().unwrap();
    let back = PaymentPayload::from_header(&header).unwrap();
    assert_eq!(back.payload.amount_nano, u64::MAX, "the header is a CLAIM, nothing more");
    assert_eq!(back.payload.payer_user_id, u64::MAX);
    assert!(!header.starts_with('{'), "header is base64, per x402");
}

/// A malformed / hostile header must produce an error, never a panic: the
/// verify tool is reachable by anyone who can hand this agent a header.
#[test]
fn attack_a_hostile_payment_header_errors_rather_than_panicking() {
    let long_b64 = base64_of(&"A".repeat(2_000_000));
    let deep_json = format!(r#"{{"payload":{}}}"#, "[".repeat(20_000));
    let headers: Vec<String> = vec![
        String::new(),
        " ".into(),
        "\0".into(),
        "!!!!".into(),
        "{".into(),
        "{}".into(),
        "[]".into(),
        "null".into(),
        "not base64 and not json".into(),
        "=====".into(),
        "QUJD".into(),                       // valid base64 of "ABC", not JSON
        base64_of("{}"),
        base64_of("null"),
        base64_of(r#"{"x402Version":1}"#),   // missing scheme/network/payload
        base64_of(r#"{"x402Version":"one","scheme":"exact","network":"psy","payload":{}}"#),
        base64_of(r#"{"x402Version":1,"scheme":"exact","network":"psy","payload":{"txHash":1,"payerUserId":"x"}}"#),
        base64_of(r#"{"x402Version":1,"scheme":"exact","network":"psy","payload":{"txHash":"a","payerUserId":-1,"recipientUserId":1,"amountNano":1,"contractId":0}}"#),
        base64_of(r#"{"x402Version":1,"scheme":"exact","network":"psy","payload":{"txHash":"a","payerUserId":1,"recipientUserId":1,"amountNano":18446744073709551616,"contractId":0}}"#),
        deep_json,
        long_b64,
        "🙂".repeat(1000),
        format!("{}\n{}", base64_of(r#"{"a":1}"#), base64_of(r#"{"b":2}"#)),
    ];
    for h in headers {
        // The contract is only that it returns. Anything that parses is then a
        // claim to be checked against the chain, which this layer does not do.
        let _ = PaymentPayload::from_header(&h);
    }
}

/// A header claiming MORE than was paid is only a claim — the encoded value
/// round-trips unchanged, so `x402_verify`'s chain comparison is the sole
/// defence and must not be short-circuited by trusting the payload.
#[test]
fn attack_an_inflated_amount_survives_the_round_trip_unchanged() {
    let mut p = proof();
    p.amount_nano = 1; // actually paid 1
    let honest = PaymentPayload::new("psy", p.clone()).to_header().unwrap();
    p.amount_nano = 1_000_000_000; // claims 1 PSY
    let inflated = PaymentPayload::new("psy", p).to_header().unwrap();
    assert_ne!(honest, inflated);
    assert_eq!(PaymentPayload::from_header(&inflated).unwrap().payload.amount_nano, 1_000_000_000);
    assert_eq!(PaymentPayload::from_header(&honest).unwrap().payload.amount_nano, 1);
}

/// Raw-JSON headers are tolerated for client compatibility. Verify that the
/// tolerance does not extend to accepting a DIFFERENT shape.
#[test]
fn attack_raw_json_tolerance_does_not_widen_the_accepted_shape() {
    let payload = PaymentPayload::new("psy", proof());
    let raw = serde_json::to_string(&payload).unwrap();
    assert_eq!(PaymentPayload::from_header(&raw).unwrap().payload.payer_user_id, 7);
    assert_eq!(PaymentPayload::from_header(&format!("   {raw}   ")).unwrap().payload.payer_user_id, 7);
    // A JSON object that is not a payment payload is still refused.
    assert!(PaymentPayload::from_header(r#"{"hello":"world"}"#).is_err());
    assert!(PaymentPayload::from_header(r#"{"payload":{}}"#).is_err());
}

/// The network label in the payload is attacker-chosen and is NOT a security
/// boundary — pinned here so nobody later treats it as one.
#[test]
fn documents_that_the_payload_network_label_is_attacker_chosen() {
    for network in ["psy-sepolia", "base", "", "psy-mainnet\0", "🙂"] {
        let h = PaymentPayload::new(network, proof()).to_header().unwrap();
        assert_eq!(PaymentPayload::from_header(&h).unwrap().network, network);
    }
}

fn base64_of(s: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
}
