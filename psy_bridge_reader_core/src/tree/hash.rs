//! Poseidon hashing and the display hex encoding of deposit tree nodes.
//!
//! Envio's `DepositRecorded` handler (`psy_cli/psy_relayer_cli/indexer/envio/handlers.ts`)
//! stores every tree node and root as display hex: `0x` and the four
//! Goldilocks limbs written e3, e2, e1, e0, each as 16 big-endian hex digits.
//! A parent is Poseidon two-to-one of its left (even index) and right children,
//! and an empty subtree at level `k` is `zero(k)`.

use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, ToU64x4},
    pgoldilocks::{GoldilocksHashOut, PoseidonHasher},
};

pub type Hash = GoldilocksHashOut;

const DISPLAY_HEX_DIGITS: usize = 64;

#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum HashParseError {
    #[error("display hash {value:?} does not start with 0x")]
    MissingPrefix { value: String },
    #[error("display hash {value:?} has {digits} hex digits after 0x, expected 64")]
    Length { value: String, digits: usize },
    #[error("display hash {value:?} has an uppercase hex digit")]
    Uppercase { value: String },
    #[error("display hash {value:?} is not hex")]
    NotHex {
        value: String,
        #[source]
        source: hex::FromHexError,
    },
    #[error("display hash {value:?} limb e{limb_index} {limb:#018x} is not a canonical Goldilocks element")]
    NonCanonicalLimb { value: String, limb_index: usize, limb: u64 },
}

/// Parses Envio's display hex. The limbs are written e3, e2, e1, e0, as in
/// psy-services `parse_display_qhash`. Only strings `to_display_hex` can print
/// are accepted, so an accepted string always prints back unchanged: unlike
/// psy-services, an uppercase digit and a limb at or above the Goldilocks order
/// are rejected. Envio writes neither.
pub fn parse_display_hex(s: &str) -> Result<Hash, HashParseError> {
    let digits = s.strip_prefix("0x").ok_or_else(|| HashParseError::MissingPrefix { value: s.to_owned() })?;
    if digits.len() != DISPLAY_HEX_DIGITS {
        return Err(HashParseError::Length { value: s.to_owned(), digits: digits.len() });
    }
    if digits.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(HashParseError::Uppercase { value: s.to_owned() });
    }
    let mut bytes = [0u8; DISPLAY_HEX_DIGITS / 2];
    hex::decode_to_slice(digits, &mut bytes).map_err(|source| HashParseError::NotHex { value: s.to_owned(), source })?;
    let mut written = [0u64; 4];
    for (limb, chunk) in written.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut be = [0u8; 8];
        be.copy_from_slice(chunk);
        *limb = u64::from_be_bytes(be);
    }
    let [e3, e2, e1, e0] = written;
    let hash = Hash::from_values(e0, e1, e2, e3);
    for (limb_index, (canonical, limb)) in hash.to_u64x4().into_iter().zip([e0, e1, e2, e3]).enumerate() {
        if canonical != limb {
            return Err(HashParseError::NonCanonicalLimb { value: s.to_owned(), limb_index, limb });
        }
    }
    Ok(hash)
}

/// Lowercase display hex of the canonical limbs, the encoding Envio writes.
pub fn to_display_hex(h: &Hash) -> String {
    let [e0, e1, e2, e3] = h.to_u64x4();
    format!("0x{e3:016x}{e2:016x}{e1:016x}{e0:016x}")
}

/// Parent of a left (even index) and a right (odd index) child.
pub fn two_to_one(l: Hash, r: Hash) -> Hash {
    PoseidonHasher::q_two_to_one(l, r)
}

/// Root of an empty subtree whose leaves are `level` levels below it. Level 0
/// is all zeros.
pub fn zero(level: u8) -> Hash {
    PoseidonHasher::get_zero_hash(usize::from(level))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{fixture, naive_root, naive_siblings};

    #[test]
    fn display_hex_round_trips_envio_values() {
        let s = "0x1227beae8ca7cb5e5f1b72673239885cff16a7d0b45d33bb47700082df261019";
        assert_eq!(to_display_hex(&parse_display_hex(s).unwrap()), s);
    }

    #[test]
    fn display_hex_rejects_bad_input() {
        for bad in ["", "0x", "1227beae", &format!("0x{}", "g".repeat(64)), &format!("0x{}", "0".repeat(63))] {
            assert!(parse_display_hex(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn display_hex_limb_order_is_e3_first() {
        let s = format!("0x{:016x}{:016x}{:016x}{:016x}", 4u64, 3u64, 2u64, 1u64);
        assert_eq!(parse_display_hex(&s).unwrap(), Hash::from_values(1, 2, 3, 4));
        assert_eq!(to_display_hex(&Hash::from_values(1, 2, 3, 4)), s);
    }

    #[test]
    fn display_hex_accepts_only_what_to_display_hex_prints() {
        let digits = "1227beae8ca7cb5e5f1b72673239885cff16a7d0b45d33bb47700082df261019";
        assert!(matches!(parse_display_hex(digits), Err(HashParseError::MissingPrefix { .. })));
        assert!(matches!(parse_display_hex(&format!("0X{digits}")), Err(HashParseError::MissingPrefix { .. })));
        assert!(matches!(parse_display_hex(&format!("0x{digits}0")), Err(HashParseError::Length { digits: 65, .. })));
        assert!(matches!(parse_display_hex(&format!("0x{}", digits.to_uppercase())), Err(HashParseError::Uppercase { .. })));
        assert!(matches!(parse_display_hex(&format!("0x{}", "g".repeat(64))), Err(HashParseError::NotHex { .. })));
        // The Goldilocks order itself, written as limb e1.
        let order = format!("0x{:016x}{:016x}{:016x}{:016x}", 0u64, 0u64, 0xffff_ffff_0000_0001u64, 0u64);
        assert!(matches!(
            parse_display_hex(&order),
            Err(HashParseError::NonCanonicalLimb { limb_index: 1, limb: 0xffff_ffff_0000_0001, .. })
        ));
        let largest = format!("0x{:016x}{:016x}{:016x}{:016x}", 0u64, 0u64, 0xffff_ffff_0000_0000u64, 0u64);
        assert_eq!(to_display_hex(&parse_display_hex(&largest).unwrap()), largest);
    }

    #[test]
    fn zero_hashes_chain() {
        assert_eq!(to_display_hex(&zero(0)), format!("0x{}", "0".repeat(64)));
        for l in 0..32u8 { assert_eq!(zero(l + 1), two_to_one(zero(l), zero(l))); }
    }

    #[test]
    fn two_to_one_is_ordered() {
        let f = fixture();
        let (a, b) = (f.leaves[0], f.leaves[1]);
        assert_ne!(two_to_one(a, b), two_to_one(b, a));
    }

    #[test]
    fn fixture_leaves_round_trip_display_hex() {
        let f = fixture();
        assert_eq!(f.leaves.len(), 2100);
        assert_eq!(f.roots_after.len(), 2100);
        for (i, leaf) in f.leaves.iter().enumerate() {
            assert_eq!(parse_display_hex(&to_display_hex(leaf)).unwrap(), *leaf, "leaf {i}");
        }
        for root in &f.roots_after {
            assert_eq!(to_display_hex(&parse_display_hex(root).unwrap()), *root);
        }
    }

    #[test]
    fn naive_root_matches_envio_after_every_deposit() {
        let f = fixture();
        for (k, root) in f.roots_after.iter().enumerate() {
            assert_eq!(to_display_hex(&naive_root(&f.leaves, k as u64 + 1)), *root, "count {}", k + 1);
        }
        assert_eq!(naive_root(&f.leaves, 0), zero(32));
    }

    #[test]
    fn naive_siblings_fold_to_the_envio_root() {
        let f = fixture();
        for n in [1u64, 2, 5, 1023, 1024, 1025, 2047, 2048, 2049, 2100] {
            for i in [0, n / 2, n - 1] {
                let siblings = naive_siblings(&f.leaves, i, n);
                assert_eq!(siblings.len(), 32);
                let mut node = f.leaves[i as usize];
                for (level, sibling) in siblings.iter().enumerate() {
                    node = if (i >> level) & 1 == 0 { two_to_one(node, *sibling) } else { two_to_one(*sibling, node) };
                }
                assert_eq!(to_display_hex(&node), f.roots_after[n as usize - 1], "leaf {i} of {n}");
            }
        }
    }
}
