//! Derive a receiver shield address for private transfers.
//!
//! Usage: derive_shield <user_id> <random0> <random1>
//! Prints the shield address in the canonical form accepted by
//! `psy_user_cli private-transfer --receiver` (QHashOut serde string round-trip).

use plonky2::field::types::Field;
use psy_crypto::shield_address::derive_shield_address;
use serde_json::to_string;

fn parse_arg<T: std::str::FromStr>(value: &str, name: &str) -> anyhow::Result<T> {
    value.parse::<T>().map_err(|_| anyhow::anyhow!("invalid {name}: {value}"))
}

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let user_id: u64 = parse_arg(&args.next().ok_or_else(|| anyhow::anyhow!("missing user_id"))?, "user_id")?;
    let random0: u64 = parse_arg(&args.next().ok_or_else(|| anyhow::anyhow!("missing random0"))?, "random0")?;
    let random1: u64 = parse_arg(&args.next().ok_or_else(|| anyhow::anyhow!("missing random1"))?, "random1")?;
    let shield = derive_shield_address(user_id, random0, random1);
    // serde round-trip: from_str parses exactly this string back.
    println!("{}", to_string(&shield)?.replace('"', ""));
    let _ = plonky2::field::goldilocks_field::GoldilocksField::ZERO;
    Ok(())
}
