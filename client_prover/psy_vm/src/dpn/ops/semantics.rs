//! Authoritative DPN opcode semantics — the single native reference shared by
//! `core_eval` (pre-compilation evaluator), `SimpleDPNExecutor` (VM witness)
//! and `VmExecutor` (indexed-IR evaluator). The circuit (`SimpleDPNBuilder`)
//! constrains exactly the behavior documented here; an implementation that
//! silently accepts what the circuit rejects (or vice versa) is a bug.
//!
//! # Semantics table
//!
//! | Opcode family | Accepted operands | Result / failure policy |
//! |---|---|---|
//! | felt `Add`/`Sub`/`Mul`/`UnaryNegative` | any canonical Goldilocks value | unchecked field arithmetic mod p |
//! | felt `Div` | divisor != 0 | `a * b^-1 mod p`; zero divisor is an error (never a field panic) |
//! | felt `Mod`, `ModConstant*` | divisor != 0 | integer remainder of canonical values; zero divisor is an error |
//! | `UnaryInverse` | operand != 0 | field inverse; zero operand is an error |
//! | felt `Exp`, `ExpConstant*` | any canonical value | field exponentiation mod p |
//! | `Eq`/`Lt`/`Lte`/`Gt`/`Gte` | any canonical value | full canonical-u64 comparison (the circuit gadget covers all 64 bits) |
//! | `BoolNot`/`BoolAnd`/`BoolOr`/`Xor`/`Nor` | operands in {0, 1} | boolean algebra; non-boolean operand is an error |
//! | `CastBool` | value in {0, 1} | strict: nonzero-and-non-one is an error (no nonzero-means-true) |
//! | `CastU32` | value <= 0xffff_ffff | strict checked conversion (no truncation); 0xffff_ffff is legal |
//! | `SplitBits` | num_bits <= 64 and value < 2^num_bits | little-endian bit array |
//! | `SumBits` | <= 64 inputs, each in {0, 1} | weighted binary reconstruction `sum(bit[i] * 2^i)`, reduced mod p |
//! | u32 `Add`/`Sub`/`Mul` | operands <= 0xffff_ffff | checked: overflow/underflow is an error; `Sub` allows equality (`x - x = 0`) |
//! | u32 `Div`/`Mod` | operands <= 0xffff_ffff, divisor != 0 | checked; zero divisor is an error |
//! | u32 `Exp` | operands <= 0xffff_ffff | field pow `base^exp mod p`, then result must fit u32 |
//! | u32 shifts (all six opcodes) | u32 operands | distance >= 32 => 0; distance < 32 => plain u32 shift (bits shifted out are dropped) |
//! | `Keccak256` words | each word <= 0xffff_ffff | big-endian bytes per word; out-of-range word is an error (no truncation) |
//!
//! Error [`Display`] strings keep the substrings ("value too large", "value
//! too low", "by zero", "invert zero", "invalid bool value", "invalid u32
//! value") that the random differential harness classifies rejections by.

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, PrimeField64},
};
use tiny_keccak::{Hasher as _, Keccak};

/// Inclusive maximum of the u32 lane.
pub const U32_MAX: u64 = 0xffff_ffff;

/// A violation of the authoritative opcode semantics documented above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticsError {
    DivisionByZero { op: &'static str },
    InverseOfZero { op: &'static str },
    U32OperandTooLarge { op: &'static str, value: u64 },
    U32Overflow { op: &'static str, lhs: u64, rhs: u64 },
    U32Underflow { op: &'static str, lhs: u64, rhs: u64 },
    BoolOperandInvalid { op: &'static str, value: u64 },
    KeccakWordTooLarge { word: u64 },
    SplitBitsNumBitsTooLarge { num_bits: u64 },
    SplitBitsValueTooLarge { value: u64, num_bits: u64 },
    SumBitsTooManyInputs { len: usize },
}

impl std::fmt::Display for SemanticsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SemanticsError::DivisionByZero { op } => write!(f, "{op} by zero"),
            SemanticsError::InverseOfZero { op } => write!(f, "{op}: cannot invert zero"),
            SemanticsError::U32OperandTooLarge { op, value } => {
                write!(f, "{op}: invalid u32 value {value:#x}")
            }
            SemanticsError::U32Overflow { op, lhs, rhs } => {
                write!(f, "{op} value too large: {lhs:#x}, {rhs:#x}")
            }
            SemanticsError::U32Underflow { op, lhs, rhs } => {
                write!(f, "{op} value too low: {lhs:#x}, {rhs:#x}")
            }
            SemanticsError::BoolOperandInvalid { op, value } => {
                write!(f, "{op}: invalid bool value {value}")
            }
            SemanticsError::KeccakWordTooLarge { word } => {
                write!(f, "keccak input word does not fit u32: {word:#x}")
            }
            SemanticsError::SplitBitsNumBitsTooLarge { num_bits } => {
                write!(f, "SplitBits: num_bits must be at most 64, got {num_bits}")
            }
            SemanticsError::SplitBitsValueTooLarge { value, num_bits } => {
                write!(f, "SplitBits: value {value:#x} does not fit in {num_bits} bits")
            }
            SemanticsError::SumBitsTooManyInputs { len } => {
                write!(f, "SumBits: can only sum at most 64 bits, got {len}")
            }
        }
    }
}

impl std::error::Error for SemanticsError {}

pub type SemanticsResult<T> = Result<T, SemanticsError>;

// ---------- felt lane ----------

/// Field addition mod p.
pub fn felt_add(a: u64, b: u64) -> u64 {
    (GoldilocksField::from_noncanonical_u64(a) + GoldilocksField::from_noncanonical_u64(b)).to_canonical_u64()
}

/// Field subtraction mod p.
pub fn felt_sub(a: u64, b: u64) -> u64 {
    (GoldilocksField::from_noncanonical_u64(a) - GoldilocksField::from_noncanonical_u64(b)).to_canonical_u64()
}

/// Field multiplication mod p.
pub fn felt_mul(a: u64, b: u64) -> u64 {
    (GoldilocksField::from_noncanonical_u64(a) * GoldilocksField::from_noncanonical_u64(b)).to_canonical_u64()
}

/// Field negation mod p (neg(0) = 0, always canonical).
pub fn felt_neg(a: u64) -> u64 {
    (-GoldilocksField::from_noncanonical_u64(a)).to_canonical_u64()
}

/// Field exponentiation `base^exp mod p`.
pub fn felt_pow(base: u64, exp: u64) -> u64 {
    GoldilocksField::from_noncanonical_u64(base)
        .exp_u64(exp)
        .to_canonical_u64()
}

/// `[quotient, remainder]` of division by 4 (the DivRem4 opcode).
pub fn div_rem4(value: u64) -> [u64; 2] {
    [value >> 2, value & 3]
}

/// Field division `a * b^-1 mod p` over canonical values.
pub fn felt_div(a: u64, b: u64) -> SemanticsResult<u64> {
    Ok(felt_mul(a, felt_inverse("felt div", b)?))
}

/// Field inverse over a canonical value; zero has no inverse.
pub fn felt_inverse(op: &'static str, a: u64) -> SemanticsResult<u64> {
    if a == 0 {
        Err(SemanticsError::InverseOfZero { op })
    } else {
        Ok(GoldilocksField::from_canonical_u64(a).inverse().to_canonical_u64())
    }
}

/// Integer remainder of canonical values (`a mod b`, not field reduction).
pub fn felt_mod(op: &'static str, a: u64, b: u64) -> SemanticsResult<u64> {
    if b == 0 {
        Err(SemanticsError::DivisionByZero { op })
    } else {
        Ok(a % b)
    }
}

// ---------- boolean lane ----------

/// Strict boolean interpretation: only 0 and 1 are boolean values.
pub fn resolve_bool_value(op: &'static str, value: u64) -> SemanticsResult<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        v => Err(SemanticsError::BoolOperandInvalid { op, value: v }),
    }
}

/// Boolean `Not` over a strict boolean operand.
pub fn bool_not(op: &'static str, a: u64) -> SemanticsResult<u64> {
    Ok((!resolve_bool_value(op, a)?) as u64)
}

/// Boolean `And` over strict boolean operands.
pub fn bool_and(op: &'static str, a: u64, b: u64) -> SemanticsResult<u64> {
    let (a, b) = (resolve_bool_value(op, a)?, resolve_bool_value(op, b)?);
    Ok((a && b) as u64)
}

/// Boolean `Or` over strict boolean operands.
pub fn bool_or(op: &'static str, a: u64, b: u64) -> SemanticsResult<u64> {
    let (a, b) = (resolve_bool_value(op, a)?, resolve_bool_value(op, b)?);
    Ok((a || b) as u64)
}

/// Boolean `Xor` over strict boolean operands.
pub fn bool_xor(op: &'static str, a: u64, b: u64) -> SemanticsResult<u64> {
    Ok((resolve_bool_value(op, a)? ^ resolve_bool_value(op, b)?) as u64)
}

/// Boolean `Nor` over strict boolean operands.
pub fn bool_nor(op: &'static str, a: u64, b: u64) -> SemanticsResult<u64> {
    // Bind both operands BEFORE the boolean ops: an inline `||` short-circuits
    // when a is true and never validates b (caught by the VmExecutor random
    // differential: Nor(true, 2) silently returned 0).
    let (a, b) = (resolve_bool_value(op, a)?, resolve_bool_value(op, b)?);
    Ok((!(a || b)) as u64)
}

/// Truthiness for Select / event / state-command conditions. This is a
/// DOCUMENTED domain decision: conditions use truthy semantics (nonzero
/// = true) everywhere - witness, circuit, core_eval and VmExecutor - unlike
/// the strict boolean-lane ops above. Kept here so the single point of
/// truth is named.
pub fn is_truthy(condition: u64) -> bool {
    condition != 0
}

// ---------- bit decomposition ----------

/// Little-endian bit decomposition with the circuit's `split_le` domain:
/// at most 64 bits and the value must fit in `num_bits`.
pub fn split_bits(value: u64, num_bits: u64) -> SemanticsResult<Vec<bool>> {
    if num_bits > 64 {
        return Err(SemanticsError::SplitBitsNumBitsTooLarge { num_bits });
    }
    if num_bits < 64 && value >= 1u64 << num_bits {
        return Err(SemanticsError::SplitBitsValueTooLarge { value, num_bits });
    }
    Ok((0..num_bits).map(|i| (value >> i) & 1 == 1).collect())
}

/// Weighted binary reconstruction `sum(bit[i] * 2^i)` over at most 64 strict
/// boolean inputs. The exact sum fits u64 (max 2^64 - 1); callers reduce mod
/// p when storing into the felt lane (`from_noncanonical_u64`), matching the
/// circuit's field `mul_add` accumulation.
pub fn sum_bits_weighted(bits: &[bool]) -> SemanticsResult<u64> {
    if bits.len() > 64 {
        return Err(SemanticsError::SumBitsTooManyInputs { len: bits.len() });
    }
    let mut sum: u64 = 0;
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            sum += 1 << i;
        }
    }
    Ok(sum)
}

// ---------- u32 lane ----------

/// Validate a canonical value as a u32-lane operand.
pub fn u32_operand(op: &'static str, value: u64) -> SemanticsResult<u32> {
    if value > U32_MAX {
        Err(SemanticsError::U32OperandTooLarge { op, value })
    } else {
        Ok(value as u32)
    }
}

/// Checked u32 addition; the carry out must be zero, like the circuit.
pub fn u32_add(op: &'static str, lhs: u64, rhs: u64) -> SemanticsResult<u32> {
    let (lhs, rhs) = (u32_operand(op, lhs)?, u32_operand(op, rhs)?);
    let sum = lhs as u64 + rhs as u64;
    if sum > U32_MAX {
        Err(SemanticsError::U32Overflow {
            op,
            lhs: lhs as u64,
            rhs: rhs as u64,
        })
    } else {
        Ok(sum as u32)
    }
}

/// Checked u32 subtraction; equality is allowed (`x - x = 0`), only the
/// borrow is rejected.
pub fn u32_sub(op: &'static str, lhs: u64, rhs: u64) -> SemanticsResult<u32> {
    let (lhs, rhs) = (u32_operand(op, lhs)?, u32_operand(op, rhs)?);
    if lhs < rhs {
        Err(SemanticsError::U32Underflow {
            op,
            lhs: lhs as u64,
            rhs: rhs as u64,
        })
    } else {
        Ok(lhs - rhs)
    }
}

/// Checked u32 multiplication; the high limb must be zero, like the circuit.
pub fn u32_mul(op: &'static str, lhs: u64, rhs: u64) -> SemanticsResult<u32> {
    let (lhs, rhs) = (u32_operand(op, lhs)?, u32_operand(op, rhs)?);
    let product = lhs as u64 * rhs as u64;
    if product > U32_MAX {
        Err(SemanticsError::U32Overflow {
            op,
            lhs: lhs as u64,
            rhs: rhs as u64,
        })
    } else {
        Ok(product as u32)
    }
}

/// Checked u32 division; a zero divisor is an error.
pub fn u32_div(op: &'static str, lhs: u64, rhs: u64) -> SemanticsResult<u32> {
    let (lhs, rhs) = (u32_operand(op, lhs)?, u32_operand(op, rhs)?);
    if rhs == 0 {
        Err(SemanticsError::DivisionByZero { op })
    } else {
        Ok(lhs / rhs)
    }
}

/// Checked u32 remainder; a zero divisor is an error.
pub fn u32_mod(op: &'static str, lhs: u64, rhs: u64) -> SemanticsResult<u32> {
    let (lhs, rhs) = (u32_operand(op, lhs)?, u32_operand(op, rhs)?);
    if rhs == 0 {
        Err(SemanticsError::DivisionByZero { op })
    } else {
        Ok(lhs % rhs)
    }
}

/// Field exponentiation `base^exp mod p` whose canonical result must fit u32
/// (mirrors the circuit's `exp` + high-limb assert).
pub fn u32_exp(op: &'static str, base: u64, exponent: u64) -> SemanticsResult<u32> {
    let (base, exponent) = (u32_operand(op, base)?, u32_operand(op, exponent)?);
    let res = GoldilocksField::from_canonical_u64(base as u64)
        .exp_u64(exponent as u64)
        .to_canonical_u64();
    if res > U32_MAX {
        Err(SemanticsError::U32Overflow {
            op,
            lhs: base as u64,
            rhs: exponent as u64,
        })
    } else {
        Ok(res as u32)
    }
}

/// u32 shift left: distance >= 32 folds to 0, otherwise plain `u32 <<`
/// (bits shifted out are dropped, like the circuit's low-limb product).
pub fn u32_shl(a: u32, distance: u32) -> u32 {
    if distance >= 32 {
        0
    } else {
        a << distance
    }
}

/// u32 shift right: distance >= 32 folds to 0, otherwise plain `u32 >>`.
pub fn u32_shr(a: u32, distance: u32) -> u32 {
    if distance >= 32 {
        0
    } else {
        a >> distance
    }
}

/// Strict checked conversion to the u32 lane; 0xffff_ffff is legal.
pub fn cast_u32(value: u64) -> SemanticsResult<u32> {
    if value > U32_MAX {
        Err(SemanticsError::U32OperandTooLarge { op: "CastU32", value })
    } else {
        Ok(value as u32)
    }
}

// ---------- keccak ----------

/// keccak256 over u32 words serialized as big-endian bytes
/// (`abi.encodePacked(uint32, ...)` semantics); the result is the eight
/// big-endian u32 words of the 32-byte digest. Every input word must fit
/// u32 — the circuit range-checks them, so native paths must not truncate.
pub fn keccak_u32_words_be(words: &[u64]) -> SemanticsResult<Vec<u32>> {
    let mut bytes = Vec::with_capacity(words.len() * 4);
    for &word in words {
        let word = u32_operand("Keccak256", word)?;
        bytes.extend_from_slice(&word.to_be_bytes());
    }
    let mut digest = [0u8; 32];
    let mut keccak = Keccak::v256();
    keccak.update(&bytes);
    keccak.finalize(&mut digest);

    Ok(digest
        .chunks_exact(4)
        .take(8)
        .map(|chunk| {
            let mut word = [0u8; 4];
            word.copy_from_slice(chunk);
            u32::from_be_bytes(word)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_str(r: SemanticsResult<u64>) -> &'static str {
        match r {
            Ok(_) => panic!("expected an error"),
            Err(e) => Box::leak(e.to_string().into_boxed_str()),
        }
    }

    #[test]
    fn u32_arithmetic_is_checked_and_boundary_inclusive() {
        assert_eq!(u32_add("u32 add", U32_MAX, 0).unwrap(), u32::MAX);
        assert_eq!(u32_add("u32 add", 0xffff_fffe, 1).unwrap(), u32::MAX);
        assert!(u32_add("u32 add", U32_MAX, 1).is_err());

        // Subtraction allows equality; only a borrow is rejected.
        assert_eq!(u32_sub("u32 sub", 7, 7).unwrap(), 0);
        assert_eq!(u32_sub("u32 sub", 0, 0).unwrap(), 0);
        assert_eq!(u32_sub("u32 sub", U32_MAX, U32_MAX).unwrap(), 0);
        assert!(u32_sub("u32 sub", 6, 7).is_err());

        assert_eq!(u32_mul("u32 mul", 0xffff, 0x1_0001).unwrap(), 0xffff_ffff);
        assert!(u32_mul("u32 mul", 0x1_0000, 0x1_0000).is_err());

        assert_eq!(u32_div("u32 div", 7, 2).unwrap(), 3);
        assert_eq!(u32_mod("u32 mod", 7, 2).unwrap(), 1);
        assert!(u32_div("u32 div", 7, 0).is_err());
        assert!(u32_mod("u32 mod", 7, 0).is_err());

        // Operands above the u32 lane are rejected before any arithmetic.
        assert!(u32_add("u32 add", 0x1_0000_0000, 0).is_err());
    }

    #[test]
    fn u32_exp_is_field_pow_then_fits_check() {
        assert_eq!(u32_exp("u32 exp", 3, 10).unwrap(), 59_049);
        assert_eq!(u32_exp("u32 exp", 2, 0).unwrap(), 1);
        assert_eq!(u32_exp("u32 exp", 0, 0).unwrap(), 1);
        // 2^32 wraps mod p (p = 2^64 - 2^32 + 1): 2^32 = p - 2^32 + ... is
        // still > U32_MAX as a canonical value, so this must reject.
        assert!(u32_exp("u32 exp", 2, 32).is_err());
        // ...but a wrap that lands back inside u32 is accepted: the field
        // residue is the authoritative result.
        let v = GoldilocksField::from_canonical_u64(2).exp_u64(64).to_canonical_u64();
        assert_eq!(u32_exp("u32 exp", 2, 64).unwrap() as u64, v);
    }

    #[test]
    fn shifts_clamp_distance_and_truncate_value() {
        assert_eq!(u32_shl(1, 0), 1);
        assert_eq!(u32_shl(1, 4), 16);
        assert_eq!(u32_shl(0xffff_ffff, 4), 0xffff_fff0); // truncates
        assert_eq!(u32_shl(1, 31), 0x8000_0000);
        assert_eq!(u32_shl(1, 32), 0);
        assert_eq!(u32_shl(1, 64), 0);
        assert_eq!(u32_shl(1, 100), 0);
        assert_eq!(u32_shr(0x8000_0000, 31), 1);
        assert_eq!(u32_shr(0x8000_0000, 32), 0);
        assert_eq!(u32_shr(0xffff_ffff, 64), 0);
    }

    #[test]
    fn casts_are_strict() {
        assert_eq!(cast_u32(U32_MAX).unwrap(), u32::MAX); // 0xffffffff is legal
        assert!(cast_u32(0x1_0000_0000).is_err());
        assert!(!resolve_bool_value("CastBool", 0).unwrap());
        assert!(resolve_bool_value("CastBool", 1).unwrap());
        assert!(resolve_bool_value("CastBool", 2).is_err());
    }

    #[test]
    fn bool_algebra_validates_operands() {
        assert_eq!(bool_not("BoolNot", 0).unwrap(), 1);
        assert_eq!(bool_not("BoolNot", 1).unwrap(), 0);
        assert_eq!(bool_and("BoolAnd", 1, 1).unwrap(), 1);
        assert_eq!(bool_and("BoolAnd", 1, 0).unwrap(), 0);
        assert_eq!(bool_or("BoolOr", 0, 1).unwrap(), 1);
        assert_eq!(bool_or("BoolOr", 0, 0).unwrap(), 0);
        assert_eq!(bool_xor("Xor", 1, 0).unwrap(), 1);
        assert_eq!(bool_xor("Xor", 1, 1).unwrap(), 0);
        assert_eq!(bool_nor("Nor", 0, 0).unwrap(), 1);
        assert_eq!(bool_nor("Nor", 0, 1).unwrap(), 0);
        // Non-boolean operands are rejected, not interpreted as truthy -
        // on BOTH sides (the short-circuit trap).
        assert!(bool_not("BoolNot", 2).is_err());
        assert!(bool_and("BoolAnd", 2, 1).is_err());
        assert!(bool_and("BoolAnd", 1, 2).is_err());
        assert!(bool_or("BoolOr", 2, 0).is_err());
        assert!(bool_or("BoolOr", 0, 2).is_err());
        assert!(bool_xor("Xor", 2, 1).is_err());
        assert!(bool_xor("Xor", 1, 2).is_err());
        assert!(bool_nor("Nor", 0, 2).is_err());
        assert!(bool_nor("Nor", 1, 2).is_err());
    }

    #[test]
    fn felt_arithmetic_helpers_reduce_canonically() {
        const P_MINUS_1: u64 = 0xffff_ffff_0000_0000; // p = 2^64 - 2^32 + 1
        assert_eq!(felt_add(P_MINUS_1, 2), 1); // (p-1) + 2 = p + 1 -> 1
        assert_eq!(felt_sub(0, 1), P_MINUS_1); // -1 mod p
        assert_eq!(felt_mul(P_MINUS_1, P_MINUS_1), 1); // (-1)^2 = 1
        assert_eq!(felt_neg(0), 0);
        assert_eq!(felt_neg(1), P_MINUS_1);
    }

    #[test]
    fn split_bits_bounds_the_domain() {
        assert_eq!(split_bits(0b101, 3).unwrap(), vec![true, false, true]);
        assert_eq!(split_bits(0, 0).unwrap(), Vec::<bool>::new());
        assert_eq!(split_bits(u64::MAX, 64).unwrap().len(), 64);
        // num_bits == 64 accepts any u64 value; 65 is out of domain.
        assert_eq!(split_bits(U32_MAX, 64).unwrap().len(), 64);
        assert!(split_bits(1, 65).is_err());
        // Value must fit within num_bits.
        assert!(split_bits(8, 3).is_err());
        assert!(split_bits(0x1_0000_0000, 32).is_err());
        assert!(split_bits(0xffff_ffff, 32).is_ok());
    }

    #[test]
    fn sum_bits_is_weighted_binary_reconstruction() {
        // [1, 0, 1] reconstructs 5, not the popcount 2.
        assert_eq!(sum_bits_weighted(&[true, false, true]).unwrap(), 5);
        assert_eq!(sum_bits_weighted(&[]).unwrap(), 0);
        assert_eq!(sum_bits_weighted(&[true]).unwrap(), 1);
        // All 64 bits set: exact sum 2^64 - 1 fits u64 but exceeds the field
        // order — the caller must reduce via from_noncanonical_u64.
        let all_ones = vec![true; 64];
        assert_eq!(sum_bits_weighted(&all_ones).unwrap(), u64::MAX);
        assert!(sum_bits_weighted(&vec![true; 65]).is_err());
    }

    #[test]
    fn felt_zero_divisor_and_inverse_are_typed_errors() {
        assert_eq!(felt_div(6, 2).unwrap(), 3);
        // 2^-1 mod p = (p + 1) / 2 with p = 2^64 - 2^32 + 1.
        assert_eq!(felt_div(1, 2).unwrap(), 0x7fff_ffff_8000_0001);
        assert!(felt_div(1, 0).is_err());
        assert!(felt_mod("Mod", 7, 0).is_err());
        assert_eq!(felt_mod("Mod", 7, 3).unwrap(), 1);
        assert_eq!(felt_inverse("UnaryInverse", 1).unwrap(), 1);
        assert!(felt_inverse("UnaryInverse", 0).is_err());
        let msg = err_str(Err::<u64, _>(SemanticsError::InverseOfZero { op: "UnaryInverse" }));
        assert!(msg.contains("invert zero"), "{msg}");
    }

    #[test]
    fn keccak_words_must_fit_u32_and_match_known_digest() {
        // keccak256(abi.encodePacked(uint32(0), uint32(0))) — first 4 bytes
        // of the digest of eight zero bytes; the full expected vector is
        // asserted against tiny_keccak directly below, this pins the range
        // check.
        assert!(keccak_u32_words_be(&[0, 0]).is_ok());
        assert!(keccak_u32_words_be(&[U32_MAX]).is_ok());
        assert!(keccak_u32_words_be(&[0x1_0000_0000]).is_err());

        // Cross-check the packing against a direct tiny_keccak invocation.
        let words = [0x0123_4567u64, 0x89ab_cdef];
        let mut digest = [0u8; 32];
        let mut k = Keccak::v256();
        k.update(&0x0123_4567u32.to_be_bytes());
        k.update(&0x89ab_cdefu32.to_be_bytes());
        k.finalize(&mut digest);
        let expected: Vec<u32> = digest
            .chunks_exact(4)
            .take(8)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect();
        assert_eq!(keccak_u32_words_be(&words).unwrap(), expected);
    }

    #[test]
    fn error_display_keeps_classification_substrings() {
        let cases = [
            (
                SemanticsError::U32Overflow {
                    op: "u32 add",
                    lhs: 1,
                    rhs: 2,
                },
                "value too large",
            ),
            (
                SemanticsError::U32Underflow {
                    op: "u32 sub",
                    lhs: 1,
                    rhs: 2,
                },
                "value too low",
            ),
            (SemanticsError::DivisionByZero { op: "u32 div" }, "by zero"),
            (SemanticsError::InverseOfZero { op: "UnaryInverse" }, "invert zero"),
            (SemanticsError::BoolOperandInvalid { op: "CastBool", value: 2 }, "invalid bool value"),
            (SemanticsError::U32OperandTooLarge { op: "CastU32", value: 2 }, "invalid u32 value"),
        ];
        for (err, needle) in cases {
            let msg = err.to_string().to_lowercase();
            assert!(msg.contains(needle), "{msg} lost the {needle:?} substring");
        }
    }
}
