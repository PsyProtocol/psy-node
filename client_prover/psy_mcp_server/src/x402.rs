//! x402 — pay-per-request over HTTP 402, settled on Psy.
//!
//! The flow an agent follows:
//!   1. request a resource; the server answers `402 Payment Required` with a
//!      body listing what it accepts,
//!   2. pick an acceptable requirement, settle it on Psy (policy-gated),
//!   3. retry the request with `X-PAYMENT: base64(payload)` proving payment.
//!
//! Design choices, made explicit because x402 leaves them to the network:
//!
//! * **Proof of payment is the settled transaction**, not a signed intent. The
//!   payload carries the tx hash, payer, amount and recipient; a resource server
//!   verifies it by asking psy-services what that user actually paid. No prover
//!   and no facilitator are required to verify, which is what makes this usable
//!   by an ordinary web backend.
//! * **No facilitator.** `verify` talks to psy-services directly. It is kept as
//!   a separate seam so a facilitator can be slotted in later without changing
//!   the tool surface.
//!
//! The agent is NOT trusted to decide what to pay: every payment here goes
//! through the same policy gate as a direct transfer, so a malicious or confused
//! 402 challenge cannot spend more than the owner allowed.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};

/// The x402 version this implementation speaks.
pub const X402_VERSION: u64 = 1;
/// Scheme name for "pay this exact amount".
pub const SCHEME_EXACT: &str = "exact";

/// One payment option offered by a resource server (the `accepts` entries of a
/// 402 body). Unknown fields are ignored so a server can carry extras.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequirements {
    pub scheme: String,
    pub network: String,
    /// Maximum the server will accept for this resource, in the asset's base
    /// units (Nano for PSY). Accepts a string or a number.
    #[serde(rename = "maxAmountRequired", default)]
    pub max_amount_required: Option<serde_json::Value>,
    #[serde(default)]
    pub resource: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Who to pay: a Psy ID ("Psy-00204800") or a bare user id.
    #[serde(rename = "payTo")]
    pub pay_to: String,
    /// Token: "PSY"/"USDT", or a contract id. Absent means PSY.
    #[serde(default)]
    pub asset: Option<String>,
    #[serde(rename = "maxTimeoutSeconds", default)]
    #[allow(dead_code)]
    pub max_timeout_seconds: Option<u64>,
}

impl PaymentRequirements {
    /// Amount to pay, in base units.
    pub fn amount(&self) -> Result<u64> {
        match &self.max_amount_required {
            Some(serde_json::Value::String(s)) => {
                // Require a canonical unsigned integer: digits only, after
                // trimming surrounding whitespace. u64::from_str would otherwise
                // accept a leading '+' ("+1000" → 1000), and a hostile seller
                // must never have a non-obvious price honoured.
                let t = s.trim();
                if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(anyhow!(
                        "maxAmountRequired `{s}` is not a whole number of base units"
                    ));
                }
                t.parse::<u64>()
                    .with_context(|| format!("maxAmountRequired `{s}` is not a whole number of base units"))
            }
            Some(serde_json::Value::Number(n)) => n
                .as_u64()
                .ok_or_else(|| anyhow!("maxAmountRequired must be a non-negative integer")),
            _ => Err(anyhow!("the 402 challenge did not state maxAmountRequired")),
        }
    }

    /// Recipient user id, from either "Psy-00204800" or "204800".
    pub fn recipient_user_id(&self) -> Result<u64> {
        parse_psy_id(&self.pay_to)
    }

    pub fn token_symbol(&self) -> String {
        self.asset.clone().unwrap_or_else(|| "PSY".to_string())
    }
}

/// Accepts "Psy-00204800", "psy-204800" or "204800".
pub fn parse_psy_id(value: &str) -> Result<u64> {
    let raw = value.trim();
    let digits = raw
        .strip_prefix("Psy-")
        .or_else(|| raw.strip_prefix("psy-"))
        .or_else(|| raw.strip_prefix("PSY-"))
        .unwrap_or(raw);
    // Digits only — reject a leading sign, decimal point, exponent, unicode
    // digits, embedded whitespace or NUL. u64::from_str would accept "+1" as 1;
    // a payee id must be exact. Leading zeros in the display form are fine
    // (parse handles them), so "Psy-00204800" and "0" both resolve.
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(anyhow!("`{value}` is not a Psy ID or user id"));
    }
    digits
        .parse::<u64>()
        .map_err(|_| anyhow!("`{value}` is not a Psy ID or user id"))
}

/// The body a server returns with 402.
#[derive(Debug, Clone, Deserialize)]
pub struct PaymentRequired {
    #[serde(default)]
    pub accepts: Vec<PaymentRequirements>,
    #[serde(default)]
    #[allow(dead_code)]
    pub error: Option<String>,
}

/// What we settled, carried back to the server in `X-PAYMENT`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PsyPaymentProof {
    #[serde(rename = "txHash")]
    pub tx_hash: String,
    #[serde(rename = "payerUserId")]
    pub payer_user_id: u64,
    #[serde(rename = "recipientUserId")]
    pub recipient_user_id: u64,
    // Wire name is `amount` (the unit — nano — is documented, not in the
    // field name). `alias` keeps us able to VERIFY headers other x402
    // implementations sent with the reference field name `amountNano`, so
    // accepting and emitting stay independent.
    #[serde(rename = "amount", alias = "amountNano")]
    pub amount_nano: u64,
    #[serde(rename = "contractId")]
    pub contract_id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}

/// The `X-PAYMENT` header value, before base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentPayload {
    #[serde(rename = "x402Version")]
    pub x402_version: u64,
    pub scheme: String,
    pub network: String,
    pub payload: PsyPaymentProof,
}

impl PaymentPayload {
    pub fn new(network: &str, proof: PsyPaymentProof) -> Self {
        Self {
            x402_version: X402_VERSION,
            scheme: SCHEME_EXACT.to_string(),
            network: network.to_string(),
            payload: proof,
        }
    }

    /// Encode for the `X-PAYMENT` header (base64 of the JSON, per x402).
    pub fn to_header(&self) -> Result<String> {
        Ok(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(self)?))
    }

    /// Decode an `X-PAYMENT` header. Tolerates raw (un-base64'd) JSON, which
    /// clients send often enough that rejecting it only causes support noise.
    pub fn from_header(header: &str) -> Result<Self> {
        let trimmed = header.trim();
        if trimmed.starts_with('{') {
            return serde_json::from_str(trimmed).context("X-PAYMENT is not a valid payload");
        }
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(trimmed.as_bytes())
            .context("X-PAYMENT is neither base64 nor JSON")?;
        serde_json::from_slice(&bytes).context("X-PAYMENT did not decode to a valid payload")
    }
}

/// Pick a requirement this wallet can actually satisfy.
///
/// Selection is deliberately strict: an unknown scheme means we do not
/// understand what the server wants, and paying anyway would be paying blind.
///
/// The NETWORK is held to the same standard, which it previously was not. The
/// strict match used to fall back to `find(scheme == exact)` with no network
/// check at all, so a challenge declaring `network: "base"` was selected and
/// then settled ON PSY — the payment leaves, and the seller never sees it
/// because it landed on a chain they were not asking about. The receipt is even
/// stamped with OUR network rather than the one demanded, so nothing downstream
/// notices the mismatch.
///
/// Among the options we CAN satisfy, the cheapest wins. It used to be the
/// first, so a hostile body ordering `[expensive, cheap]` was paid the
/// expensive one — and the only ceiling below the policy cap is
/// `max_amount_nano`, which is supplied by the agent, not the owner.
pub fn select_requirement<'a>(
    accepts: &'a [PaymentRequirements],
    network: &str,
) -> Result<&'a PaymentRequirements> {
    if accepts.is_empty() {
        return Err(anyhow!("the 402 challenge listed no payment options"));
    }
    let satisfiable: Vec<&PaymentRequirements> = accepts
        .iter()
        .filter(|r| {
            r.scheme.eq_ignore_ascii_case(SCHEME_EXACT) && r.network.eq_ignore_ascii_case(network)
        })
        .collect();
    if satisfiable.is_empty() {
        return Err(anyhow!(
            "no payment option this wallet can satisfy on `{network}` (offered: {}). \
             Paying a requirement for another network would settle on Psy and the seller would never see it.",
            accepts
                .iter()
                .map(|r| format!("{}/{}", r.scheme, r.network))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    // Cheapest satisfiable option. An option whose price does not parse is not
    // preferred over one that does, but it is still selectable when it is all
    // there is — the existing amount() error then reports it precisely rather
    // than this function inventing a different one.
    Ok(satisfiable
        .iter()
        .filter(|r| r.amount().is_ok())
        .min_by_key(|r| r.amount().unwrap_or(u64::MAX))
        .copied()
        .unwrap_or(satisfiable[0]))
}

#[cfg(test)]
mod tests {
    #[test]
    fn old_amountNano_headers_still_decode() {
        // We emit `amount` now, but other x402 implementations (and anything
        // built before the rename) send `amountNano` in X-PAYMENT. Verifying
        // their proof must keep working.
        let old_header = r#"{"x402Version":1,"scheme":"exact","network":"psy-sepolia","payload":{"txHash":"0xabc","payerUserId":1,"recipientUserId":2,"amountNano":500000000,"contractId":0}}"#;
        let decoded = PaymentPayload::from_header(old_header)
            .expect("old-format header must decode");
        assert_eq!(decoded.payload.amount_nano, 500_000_000);
        // And our own round-trip emits `amount`.
        let p = PaymentPayload::new("psy-sepolia", PsyPaymentProof {
            tx_hash: "0xabc".into(), payer_user_id: 1, recipient_user_id: 2,
            amount_nano: 500_000_000, contract_id: 0, resource: None,
        });
        let hdr = p.to_header().unwrap();
        let raw = String::from_utf8_lossy(&base64::engine::general_purpose::STANDARD.decode(&hdr).unwrap()).to_string();
        assert!(raw.contains("\"amount\":500000000"), "emits amount: {raw}");
        assert!(!raw.contains("amountNano"), "no amountNano in emitted header: {raw}");
    }

    use super::*;

    fn reqs(json: &str) -> PaymentRequired {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn parses_a_402_challenge() {
        let body = reqs(r#"{"x402Version":1,"error":"payment required","accepts":[
            {"scheme":"exact","network":"psy-sepolia","maxAmountRequired":"1000000000",
             "payTo":"Psy-00204800","asset":"PSY","resource":"/report","maxTimeoutSeconds":60}]}"#);
        let r = select_requirement(&body.accepts, "psy-sepolia").unwrap();
        assert_eq!(r.amount().unwrap(), 1_000_000_000);
        assert_eq!(r.recipient_user_id().unwrap(), 204800);
        assert_eq!(r.token_symbol(), "PSY");
    }

    #[test]
    fn accepts_a_numeric_amount_and_a_bare_user_id() {
        let body = reqs(r#"{"accepts":[{"scheme":"exact","network":"psy","maxAmountRequired":250,"payTo":"204800"}]}"#);
        let r = select_requirement(&body.accepts, "psy").unwrap();
        assert_eq!(r.amount().unwrap(), 250);
        assert_eq!(r.recipient_user_id().unwrap(), 204800);
    }

    #[test]
    fn an_unknown_scheme_is_refused_rather_than_paid_blind() {
        let body = reqs(r#"{"accepts":[{"scheme":"permit","network":"base","maxAmountRequired":"1","payTo":"0xabc"}]}"#);
        assert!(select_requirement(&body.accepts, "psy-sepolia").is_err());
    }

    #[test]
    fn an_empty_accepts_list_is_an_error_not_a_free_pass() {
        let body = reqs(r#"{"accepts":[]}"#);
        assert!(select_requirement(&body.accepts, "psy").is_err());
    }

    #[test]
    fn a_missing_amount_is_an_error_not_a_zero_payment() {
        let body = reqs(r#"{"accepts":[{"scheme":"exact","network":"psy","payTo":"Psy-00000001"}]}"#);
        assert!(select_requirement(&body.accepts, "psy").unwrap().amount().is_err());
    }

    #[test]
    fn header_round_trips_through_base64() {
        let payload = PaymentPayload::new("psy-sepolia", PsyPaymentProof {
            tx_hash: "deadbeef".into(), payer_user_id: 1, recipient_user_id: 2,
            amount_nano: 42, contract_id: 0, resource: Some("/report".into()),
        });
        let header = payload.to_header().unwrap();
        assert!(!header.starts_with('{'), "header must be base64, not raw JSON");
        let back = PaymentPayload::from_header(&header).unwrap();
        assert_eq!(back.payload.tx_hash, "deadbeef");
        assert_eq!(back.payload.amount_nano, 42);
        assert_eq!(back.x402_version, X402_VERSION);
    }

    #[test]
    fn raw_json_headers_are_tolerated() {
        let payload = PaymentPayload::new("psy", PsyPaymentProof {
            tx_hash: "abc".into(), payer_user_id: 7, recipient_user_id: 8,
            amount_nano: 9, contract_id: 4, resource: None,
        });
        let raw = serde_json::to_string(&payload).unwrap();
        assert_eq!(PaymentPayload::from_header(&raw).unwrap().payload.payer_user_id, 7);
    }

    #[test]
    fn psy_ids_parse_in_every_form_they_are_displayed_in() {
        assert_eq!(parse_psy_id("Psy-00204800").unwrap(), 204800);
        assert_eq!(parse_psy_id("psy-204800").unwrap(), 204800);
        assert_eq!(parse_psy_id("204800").unwrap(), 204800);
        assert!(parse_psy_id("0xabc").is_err());
    }
}

#[cfg(test)]
mod network_selection_tests {
    use super::*;

    fn req(scheme: &str, network: &str, amount: &str) -> PaymentRequirements {
        serde_json::from_str(&format!(
            r#"{{"scheme":"{scheme}","network":"{network}","maxAmountRequired":"{amount}","payTo":"1","asset":"PSY"}}"#
        ))
        .unwrap()
    }

    #[test]
    fn a_requirement_for_ANOTHER_network_is_refused_not_settled_on_psy() {
        // This is the defect: the strict match fell back to scheme-only, so a
        // "base" requirement was selected and then settled on Psy. The payment
        // leaves and the seller never sees it.
        let accepts = vec![req("exact", "base", "1000")];
        let err = select_requirement(&accepts, "psy").unwrap_err().to_string();
        assert!(err.contains("psy"), "names the network we can satisfy: {err}");
        assert!(err.contains("base"), "and what was offered: {err}");
    }

    #[test]
    fn our_network_is_selected_when_offered_alongside_others() {
        let accepts = vec![
            req("exact", "base", "1"),
            req("exact", "psy", "500"),
            req("exact", "solana", "2"),
        ];
        let got = select_requirement(&accepts, "psy").unwrap();
        assert_eq!(got.network, "psy", "never pick a cheaper option on a chain we cannot settle");
    }

    #[test]
    fn the_CHEAPEST_satisfiable_option_wins_not_the_first() {
        // A hostile body ordering [expensive, cheap] used to be paid the
        // expensive one, and the only ceiling below the policy cap is
        // max_amount_nano — an agent-supplied argument, not an owner control.
        let accepts = vec![
            req("exact", "psy", "9000"),
            req("exact", "psy", "10"),
            req("exact", "psy", "3000"),
        ];
        let got = select_requirement(&accepts, "psy").unwrap();
        assert_eq!(got.amount().unwrap(), 10);
    }

    #[test]
    fn network_matching_is_case_insensitive() {
        let accepts = vec![req("EXACT", "PSY", "5")];
        assert!(select_requirement(&accepts, "psy").is_ok());
    }

    #[test]
    fn an_unknown_scheme_on_our_network_is_still_refused() {
        // The pre-existing doctrine, unchanged.
        let accepts = vec![req("upto", "psy", "5")];
        assert!(select_requirement(&accepts, "psy").is_err());
    }

    #[test]
    fn an_empty_accepts_list_is_refused() {
        assert!(select_requirement(&[], "psy").is_err());
    }

    #[test]
    fn an_unparseable_price_does_not_shadow_a_valid_cheaper_one() {
        let accepts = vec![req("exact", "psy", "not-a-number"), req("exact", "psy", "7")];
        let got = select_requirement(&accepts, "psy").unwrap();
        assert_eq!(got.amount().unwrap(), 7);
    }

    #[test]
    fn a_sole_unparseable_option_still_surfaces_its_own_error() {
        // Selection must not invent a different failure than the real one.
        let accepts = vec![req("exact", "psy", "not-a-number")];
        let got = select_requirement(&accepts, "psy").expect("selectable");
        assert!(got.amount().is_err(), "the precise price error is reported downstream");
    }
}
