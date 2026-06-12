use core::{
    fmt::{self, Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num::{bigint::BigUint, One};
use plonky2::field::types::{Field, PrimeField, Sample};
use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Bn128Scalar(pub [u64; 4]);

fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}

impl Default for Bn128Scalar {
    fn default() -> Self {
        Self::ZERO
    }
}

impl PartialEq for Bn128Scalar {
    fn eq(&self, other: &Self) -> bool {
        self.to_canonical_biguint() == other.to_canonical_biguint()
    }
}

impl Eq for Bn128Scalar {}

impl Hash for Bn128Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.to_canonical_biguint().hash(state)
    }
}

impl Display for Bn128Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.to_canonical_biguint(), f)
    }
}

impl Debug for Bn128Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.to_canonical_biguint(), f)
    }
}

impl Bn128Scalar {
    pub const ZERO: Self = Self([0; 4]);
    pub const ONE: Self = Self([1, 0, 0, 0]);
    pub const TWO: Self = Self([2, 0, 0, 0]);
    pub const NEG_ONE: Self = Self([0x43e1f593f0000000, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029]);

    pub const NONRESIDUE: Self = todo!();

    pub fn mul_by_nonresidue(&self) -> Self {
        todo!()
    }

    pub const ORDER: [u64; 4] = [0x43e1f593f0000001, 0x2833e84879b97091, 0xb85045b68181585d, 0x30644e72e131a029];

    pub const MONTGOMERY_INV: [u64; 4] = [1, 0, 0, 0];

    pub const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self([5, 0, 0, 0]);

    pub const POWER_OF_TWO_GENERATOR: Self = Self::NEG_ONE;

    pub const TWO_ADICITY: usize = 1;

    pub fn from_canonical_u64(n: u64) -> Self {
        Self([n, 0, 0, 0])
    }

    pub fn from_canonical_u128(n: u128) -> Self {
        Self([n as u64, (n >> 64) as u64, 0, 0])
    }

    pub fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    pub fn from_noncanonical_u96(n: (u64, u32)) -> Self {
        Self([n.0, n.1 as u64, 0, 0])
    }

    pub fn from_noncanonical_u128(n: u128) -> Self {
        Self::from_canonical_u128(n)
    }

    pub fn from_noncanonical_biguint(val: BigUint) -> Self {
        let digits = val.to_u64_digits();
        let mut result = [0u64; 4];
        for (i, &digit) in digits.iter().enumerate() {
            if i >= 4 {
                break;
            }
            result[i] = digit;
        }
        Self(result).reduce()
    }

    pub fn to_canonical_biguint(&self) -> BigUint {
        let mut result = biguint_from_array(self.0);
        let order = Self::order();
        if result >= order {
            result -= order;
        }
        result
    }

    fn reduce(self) -> Self {
        let order = Self::order();
        let value = biguint_from_array(self.0);
        if value >= order {
            Self::from_noncanonical_biguint(value % order)
        } else {
            self
        }
    }

    pub fn order() -> BigUint {
        BigUint::from_slice(&[
            0xf0000001, 0x43e1f593, 0x79b97091, 0x2833e848, 0x8181585d, 0xb85045b6, 0xe131a029, 0x30644e72,
        ])
    }

    pub fn characteristic() -> BigUint {
        Self::order()
    }

    pub const fn bits() -> usize {
        256
    }

    pub fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        Some(self.exp_biguint(&(Self::order() - BigUint::one() - BigUint::one())))
    }

    pub fn exp_biguint(&self, exp: &BigUint) -> Self {
        use num::traits::Zero;

        if exp.is_zero() {
            return Self::ONE;
        }

        let mut result = Self::ONE;
        let mut base = *self;
        let mut e = exp.clone();

        while !e.is_zero() {
            if &e & BigUint::one() == BigUint::one() {
                result = result * base;
            }
            base = base * base;
            e >>= 1;
        }

        result
    }

    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }

    pub fn rand_from_rng<R: rand::Rng + ?Sized>(rng: &mut R) -> Self {
        use num::bigint::RandBigInt;
        Self::from_noncanonical_biguint(rng.gen_biguint_below(&Self::order()))
    }

    pub fn rand() -> Self {
        let mut rng = rand::thread_rng();
        Self::rand_from_rng(&mut rng)
    }

    pub fn is_quadratic_residue(&self) -> bool {
        if self.is_zero() {
            return true;
        }

        let exp = (Self::order() - BigUint::one()) / 2u32;
        self.exp_biguint(&exp) == Self::ONE
    }

    pub fn multiplicative_group_factors() -> Vec<(BigUint, usize)> {
        vec![(BigUint::from(2u32), Self::TWO_ADICITY)]
    }
}

impl Sample for Bn128Scalar {
    fn sample<R>(rng: &mut R) -> Self
    where
        R: rand::RngCore + ?Sized,
    {
        Self::rand_from_rng(rng)
    }
}

impl Field for Bn128Scalar {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;
    const TWO_ADICITY: usize = Self::TWO_ADICITY;
    const CHARACTERISTIC_TWO_ADICITY: usize = 0;
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self::MULTIPLICATIVE_GROUP_GENERATOR;
    const POWER_OF_TWO_GENERATOR: Self = Self::POWER_OF_TWO_GENERATOR;

    const BITS: usize = 256;

    fn try_inverse(&self) -> Option<Self> {
        self.try_inverse()
    }

    fn from_noncanonical_biguint(n: BigUint) -> Self {
        Self::from_noncanonical_biguint(n)
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    fn from_noncanonical_i64(n: i64) -> Self {
        if n >= 0 {
            Self::from_canonical_u64(n as u64)
        } else {
            Self::ZERO - Self::from_canonical_u64((-n) as u64)
        }
    }

    fn from_noncanonical_u96(n: (u64, u32)) -> Self {
        Self::from_noncanonical_u96(n)
    }

    fn from_noncanonical_u128(n: u128) -> Self {
        Self::from_noncanonical_u128(n)
    }

    fn order() -> BigUint {
        Self::order()
    }

    fn characteristic() -> BigUint {
        Self::characteristic()
    }
}

impl PrimeField for Bn128Scalar {
    fn to_canonical_biguint(&self) -> BigUint {
        self.to_canonical_biguint()
    }
}

impl Add for Bn128Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        let mut result = self.to_canonical_biguint() + rhs.to_canonical_biguint();
        let order = Self::order();
        if result >= order {
            result -= order;
        }
        Self::from_noncanonical_biguint(result)
    }
}

impl AddAssign for Bn128Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub for Bn128Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self + (-rhs)
    }
}

impl SubAssign for Bn128Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for Bn128Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let result = self.to_canonical_biguint() * rhs.to_canonical_biguint();
        Self::from_noncanonical_biguint(result % Self::order())
    }
}

impl MulAssign for Bn128Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Div for Bn128Scalar {
    type Output = Self;

    fn div(self, rhs: Self) -> Self {
        self * rhs.try_inverse().expect("division by zero")
    }
}

impl DivAssign for Bn128Scalar {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl Neg for Bn128Scalar {
    type Output = Self;

    fn neg(self) -> Self {
        if self.is_zero() {
            Self::ZERO
        } else {
            Self::from_noncanonical_biguint(Self::order() - self.to_canonical_biguint())
        }
    }
}

impl Sum for Bn128Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl Product for Bn128Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl From<u32> for Bn128Scalar {
    fn from(n: u32) -> Self {
        Self::from_canonical_u64(n as u64)
    }
}

impl From<u64> for Bn128Scalar {
    fn from(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }
}

impl From<u128> for Bn128Scalar {
    fn from(n: u128) -> Self {
        Self::from_canonical_u128(n)
    }
}

impl From<bool> for Bn128Scalar {
    fn from(b: bool) -> Self {
        if b {
            Self::ONE
        } else {
            Self::ZERO
        }
    }
}

#[cfg(test)]
mod tests {
    use num::BigUint;
    use plonky2::field::{ops::Square, types::Field};

    use super::*;
    use crate::test_field_arithmetic;

    test_field_arithmetic!(crate::crypto::bn254::field::bn128_scalar::Bn128Scalar);

    #[test]
    fn test_constants() {
        assert_eq!(Bn128Scalar::ZERO.0, [0, 0, 0, 0]);

        assert_eq!(Bn128Scalar::ONE.0, [1, 0, 0, 0]);

        assert_eq!(Bn128Scalar::TWO.0, [2, 0, 0, 0]);

        let p = Bn128Scalar::characteristic();
        let expected_p = BigUint::parse_bytes(b"21888242871839275222246405745257275088548364400416034343698204186575808495617", 10).unwrap();
        assert_eq!(p, expected_p);
    }

    #[test]
    fn test_scalar_vs_base_field() {
        let scalar_order = Bn128Scalar::characteristic();
        let base_order = BigUint::parse_bytes(b"21888242871839275222246405745257275088696311157297823662689037894645226208583", 10).unwrap();
        assert_ne!(scalar_order, base_order);
    }

    #[test]
    fn test_arithmetic_operations() {
        let a = Bn128Scalar::from(42u64);
        let b = Bn128Scalar::from(13u64);

        assert_eq!(a + b, Bn128Scalar::from(55u64));

        assert_eq!(a - b, Bn128Scalar::from(29u64));

        assert_eq!(a * b, Bn128Scalar::from(546u64));

        let c = a / b;
        assert_eq!(c * b, a);
    }

    #[test]
    fn test_field_axioms() {
        let x = Bn128Scalar::rand();
        let y = Bn128Scalar::rand();
        let z = Bn128Scalar::rand();

        assert_eq!(x + Bn128Scalar::ZERO, x);

        assert_eq!(x * Bn128Scalar::ONE, x);

        assert_eq!(x + (-x), Bn128Scalar::ZERO);

        if !x.is_zero() {
            assert_eq!(x * x.inverse(), Bn128Scalar::ONE);
        }

        assert_eq!((x + y) + z, x + (y + z));
        assert_eq!((x * y) * z, x * (y * z));

        assert_eq!(x + y, y + x);
        assert_eq!(x * y, y * x);

        assert_eq!(x * (y + z), x * y + x * z);
    }

    #[test]
    fn test_powers() {
        let base = Bn128Scalar::from(3u64);

        assert_eq!(base.square(), Bn128Scalar::from(9u64));

        let base_cubed = base * base * base;
        assert_eq!(base_cubed, Bn128Scalar::from(27u64));

        let base4 = base.square().square();
        assert_eq!(base4, Bn128Scalar::from(81u64));
    }

    #[test]
    fn test_conversion_roundtrip() {
        let x = Bn128Scalar::rand();
        let big = x.to_canonical_biguint();
        let y = Bn128Scalar::from_noncanonical_biguint(big.clone());
        assert_eq!(x, y);
        assert_eq!(y.to_canonical_biguint(), big);

        let large = Bn128Scalar::characteristic() + BigUint::from(12345u64);
        let reduced = Bn128Scalar::from_noncanonical_biguint(large);
        assert_eq!(reduced, Bn128Scalar::from(12345u64));
    }

    #[test]
    fn test_sample_distribution() {
        let mut samples = Vec::new();
        for _ in 0..100 {
            let s = Bn128Scalar::rand();
            let big = s.to_canonical_biguint();
            assert!(big < Bn128Scalar::characteristic());
            samples.push(s);
        }

        let unique_samples: std::collections::HashSet<_> = samples.iter().collect();
        assert!(unique_samples.len() > 90); // Allow for some collisions
    }
}
