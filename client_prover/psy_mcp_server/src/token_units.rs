//! How much is this, in the unit the owner's limits are written in?
//!
//! Extracted from main.rs so the tests exercise the REAL function. The test
//! suite reaches main.rs helpers by copying them (see prod_matrix_x402.rs's
//! local `contract_for`), which cannot catch a change on the shipped side —
//! and this is a rule where a silent drift is a thousand-fold overspend.

/// A token amount expressed in the unit the POLICY is written in.
///
/// Every cap the owner sets is Nano (9 decimals). On-chain amounts are in the
/// token's own base units, and USDT_P is 6-decimal — so charging base units
/// against a Nano cap authorized ~1000x what the owner set. `deposit` already
/// normalized and said so in a comment; no sibling did, which meant a 5 PSY
/// per-payment cap permitted 5,000 USDT, and the daily / 30-day / lifetime
/// meters were debited a thousandth of what actually left.
///
/// The x402 leg is the sharp end: the asset there is named by the REMOTE
/// SERVER's 402 body, so without this the counterparty chooses the unit the
/// owner's limit is enforced in.
///
/// Returns None for a token whose scale we do not know. Refusing is the same
/// call `contract_for` already makes — guessing a scale is how a figure gets
/// paid at 1000x its intended size.
pub fn nano_equivalent(token: &str, base_units: u64) -> Option<u64> {
    match token.to_ascii_uppercase().as_str() {
        // 6 decimals on Psy -> 9 decimals of Nano.
        "USDT" | "USDT_P" => Some(base_units.saturating_mul(1_000)),
        "PSY" => Some(base_units),
        _ => None,
    }
}

