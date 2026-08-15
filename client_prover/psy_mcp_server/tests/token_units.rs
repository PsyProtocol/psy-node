//! Every cap the owner writes is in Nano. Every on-chain amount is in the
//! token's own base units, and USDT_P is 6-decimal. Charging one against the
//! other authorized ~1000x what the owner set — and on the x402 path the asset
//! is named by the REMOTE SERVER, so without this the counterparty chose the
//! unit the owner's limit was enforced in.
//!
//! This includes the REAL module rather than copying it, because the older
//! tests reach main.rs helpers by copying them (prod_matrix_x402.rs has its own
//! `contract_for`) and a copy cannot catch a drift on the shipped side.

#[path = "../src/token_units.rs"]
mod token_units;

use token_units::nano_equivalent;

const NANO: u64 = 1_000_000_000;

#[test]
fn psy_is_already_nano() {
    assert_eq!(nano_equivalent("PSY", 5 * NANO), Some(5 * NANO));
    assert_eq!(nano_equivalent("psy", 1), Some(1));
}

#[test]
fn usdt_base_units_scale_up_by_a_thousand() {
    // USDT_P is 6-decimal: 1 USDT = 1_000_000 base units = 1e9 Nano.
    assert_eq!(nano_equivalent("USDT", 1_000_000), Some(NANO));
    assert_eq!(nano_equivalent("USDT_P", 1_000_000), Some(NANO));
    assert_eq!(nano_equivalent("usdt", 1_000_000), Some(NANO));
}

#[test]
fn the_thousandfold_overspend_is_what_this_prevents() {
    // The exact number from the finding: with a 5 PSY per-payment cap, an
    // un-normalized USDT amount of 5e9 base units reads as "5 PSY" to the gate
    // while actually being 5,000 USDT.
    let raw = 5 * NANO; // what the tool receives as `amount_nano`
    let cap = 5 * NANO; // the owner's per-payment cap, in Nano
    assert!(raw <= cap, "un-normalized, this slips under the cap");
    let charged = nano_equivalent("USDT", raw).unwrap();
    assert_eq!(charged, 5_000 * NANO);
    assert!(charged > cap, "normalized, the gate sees its real size and refuses");
}

#[test]
fn an_unknown_asset_is_refused_rather_than_guessed() {
    // The 402 body names the asset. Guessing a scale is how a figure gets paid
    // at a thousand times its intended size.
    assert_eq!(nano_equivalent("USDC", 1_000_000), None);
    assert_eq!(nano_equivalent("", 1), None);
    assert_eq!(nano_equivalent("ETH", 1), None);
}

#[test]
fn conversion_saturates_instead_of_wrapping() {
    // u64::MAX * 1000 must not wrap to a small number that sails under a cap.
    let v = nano_equivalent("USDT", u64::MAX).unwrap();
    assert_eq!(v, u64::MAX);
    assert!(v > 0);
}

#[test]
fn zero_stays_zero_for_every_known_token() {
    // The claim paths authorize at amount 0; normalization must not invent a
    // charge for them.
    assert_eq!(nano_equivalent("PSY", 0), Some(0));
    assert_eq!(nano_equivalent("USDT", 0), Some(0));
}
