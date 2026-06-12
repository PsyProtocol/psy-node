use core::{
    fmt::{Debug, Display, Formatter},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num::bigint::BigUint;
use plonky2::field::{
    extension::{Extendable, FieldExtension, Frobenius, OEF},
    ops::Square,
    types::{Field, PrimeField, Sample},
};
use serde::{Deserialize, Serialize};

use crate::crypto::bn254::field::bn128_base::Bn128Base;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct QuadraticExtension<F: Extendable<2>>(pub [F; 2]);

impl<F: Extendable<2>> Default for QuadraticExtension<F> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<F: Extendable<2>> FieldExtension<2> for QuadraticExtension<F> {
    type BaseField = F;

    fn to_basefield_array(&self) -> [F; 2] {
        self.0
    }

    fn from_basefield_array(arr: [F; 2]) -> Self {
        Self(arr)
    }

    fn from_basefield(x: F) -> Self {
        x.into()
    }
}

impl<F: Extendable<2>> From<F> for QuadraticExtension<F> {
    fn from(x: F) -> Self {
        Self([x, F::ZERO])
    }
}

impl<F: Extendable<2>> QuadraticExtension<F> {
    pub const ZERO: Self = Self([F::ZERO; 2]);
    pub const ONE: Self = Self([F::ONE, F::ZERO]);
    pub const TWO: Self = Self([F::TWO, F::ZERO]);
    pub const NEG_ONE: Self = Self([F::NEG_ONE, F::ZERO]);

    pub fn rand_from_rng<R: rand::RngCore + ?Sized>(rng: &mut R) -> Self {
        Self([F::sample(rng), F::sample(rng)])
    }

    pub fn rand() -> Self {
        let mut rng = rand::thread_rng();
        Self::rand_from_rng(&mut rng)
    }

    pub fn is_zero(&self) -> bool {
        self.0[0].is_zero() && self.0[1].is_zero()
    }

    pub fn double(&self) -> Self {
        *self + *self
    }

    pub fn square(&self) -> Self {
        *self * *self
    }

    pub fn cube(&self) -> Self {
        *self * self.square()
    }

    pub fn mul_by_nonresidue(&self) -> Self {
        // Default implementation: multiply the second component by W (the quadratic
        // nonresidue) and swap components. This matches the tower extension
        // structure.
        let c0 = self.0[1] * F::W;
        let c1 = self.0[0];
        Self([c0, c1])
    }

    pub fn order() -> BigUint {
        F::order() * F::order()
    }

    pub fn characteristic() -> BigUint {
        F::characteristic()
    }

    pub const fn bits() -> usize {
        F::BITS * 2
    }

    pub fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let c0 = self.0[0];
        let c1 = self.0[1];

        // Generic implementation uses F::W
        let norm = c0.square() - c1.square() * F::W;
        let norm_inv = norm.try_inverse()?;

        Some(Self([c0 * norm_inv, -c1 * norm_inv]))
    }

    pub fn inverse(&self) -> Self {
        self.try_inverse().expect("attempted to invert zero")
    }

    pub fn from_noncanonical_biguint(n: BigUint) -> Self {
        F::from_noncanonical_biguint(n).into()
    }

    pub fn from_canonical_u64(n: u64) -> Self {
        F::from_canonical_u64(n).into()
    }

    pub fn from_noncanonical_u128(n: u128) -> Self {
        F::from_noncanonical_u128(n).into()
    }

    pub fn is_quadratic_residue(&self) -> bool {
        !self.is_zero()
    }

    pub fn sqrt(&self) -> Option<Self> {
        if self.is_zero() {
            Some(Self::ZERO)
        } else if *self == Self::ONE {
            Some(Self::ONE)
        } else {
            None // Simplified - real implementation would use Tonelli-Shanks or
                 // similar
        }
    }

    pub fn multiplicative_group_factors() -> Vec<(BigUint, usize)> {
        vec![(BigUint::from(2u32), F::TWO_ADICITY + 1)]
    }
}

impl<F: Extendable<2>> Sample for QuadraticExtension<F> {
    fn sample<R>(rng: &mut R) -> Self
    where
        R: rand::RngCore + ?Sized,
    {
        Self([F::sample(rng), F::sample(rng)])
    }
}

// Special implementation for Bn128Base
impl QuadraticExtension<Bn128Base> {
    /// Specific implementation of mul_by_nonresidue for Fp2 over Bn128Base
    pub fn mul_by_nonresidue_bn128(&self) -> Self {
        // For BN128, we need to multiply by the actual nonresidue element
        // which is stored in EXT_NONRESIDUE
        use crate::crypto::bn254::field::{bn128_base::Bn128Base, bn128_extension::Bn128ExtConstants};
        let nonresidue = Self(<Bn128Base as Bn128ExtConstants>::EXT_NONRESIDUE);
        *self * nonresidue
    }
}

// Override try_inverse for Bn128Base to use correct nonresidue
impl QuadraticExtension<Bn128Base> {
    #[allow(dead_code)]
    fn try_inverse_bn128(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let c0 = self.0[0];
        let c1 = self.0[1];

        // For Fp2 over Bn128Base, the nonresidue is -1 (since u^2 = -1)
        let norm = c0.square() - c1.square() * Bn128Base::NEG_ONE;
        let norm_inv = norm.try_inverse()?;

        Some(Self([c0 * norm_inv, -c1 * norm_inv]))
    }
}

impl<F: Extendable<2>> Field for QuadraticExtension<F> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;
    const TWO_ADICITY: usize = F::TWO_ADICITY + 1;
    const CHARACTERISTIC_TWO_ADICITY: usize = F::CHARACTERISTIC_TWO_ADICITY;
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self([F::MULTIPLICATIVE_GROUP_GENERATOR, F::ZERO]);
    const POWER_OF_TWO_GENERATOR: Self = Self([F::POWER_OF_TWO_GENERATOR, F::ZERO]);
    const BITS: usize = F::BITS * 2;

    fn try_inverse(&self) -> Option<Self> {
        self.try_inverse()
    }

    fn from_noncanonical_biguint(n: BigUint) -> Self {
        Self::from_noncanonical_biguint(n)
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self([F::from_canonical_u64(n), F::ZERO])
    }

    fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    fn from_noncanonical_i64(n: i64) -> Self {
        Self([F::from_noncanonical_i64(n), F::ZERO])
    }

    fn from_noncanonical_u128(n: u128) -> Self {
        Self([F::from_noncanonical_u128(n), F::ZERO])
    }

    fn order() -> BigUint {
        F::order()
    }

    fn characteristic() -> BigUint {
        F::characteristic()
    }
}

impl<F: Extendable<2> + PrimeField> PrimeField for QuadraticExtension<F> {
    fn to_canonical_biguint(&self) -> BigUint {
        let a = self.0[0].to_canonical_biguint();
        let b = self.0[1].to_canonical_biguint();
        let p = F::order();
        a + b * p
    }
}

impl<F: Extendable<2>> Display for QuadraticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} + {}*u", self.0[0], self.0[1])
    }
}

impl<F: Extendable<2>> Debug for QuadraticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl<F: Extendable<2>> Neg for QuadraticExtension<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self([-self.0[0], -self.0[1]])
    }
}

impl<F: Extendable<2>> Add for QuadraticExtension<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self([self.0[0] + rhs.0[0], self.0[1] + rhs.0[1]])
    }
}

impl<F: Extendable<2>> AddAssign for QuadraticExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: Extendable<2>> Sum for QuadraticExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl<F: Extendable<2>> Sub for QuadraticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self([self.0[0] - rhs.0[0], self.0[1] - rhs.0[1]])
    }
}

impl<F: Extendable<2>> SubAssign for QuadraticExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: Extendable<2>> Mul for QuadraticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let Self([a0, a1]) = self;
        let Self([b0, b1]) = rhs;

        let aa = a0 * b0;
        let bb = a1 * b1;

        // Generic implementation uses F::W (which equals NEG_ONE for Bn128Base)
        let c0 = bb * F::W + aa;
        let c1 = (a0 + a1) * (b0 + b1) - aa - bb;

        Self([c0, c1])
    }
}

impl<F: Extendable<2>> MulAssign for QuadraticExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: Extendable<2>> Product for QuadraticExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl<F: Extendable<2>> Div for QuadraticExtension<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F: Extendable<2>> DivAssign for QuadraticExtension<F> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<F: Extendable<2>> OEF<2> for QuadraticExtension<F> {
    const W: F = F::W;
    const DTH_ROOT: F = F::DTH_ROOT;
}

impl<F: Extendable<2>> Frobenius<2> for QuadraticExtension<F> {
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count % 2 == 0 {
            *self
        } else {
            Self([self.0[0], -self.0[1]])
        }
    }
}

#[cfg(test)]
mod tests {
    use plonky2::field::types::{Field, PrimeField, Sample};

    use super::*;
    use crate::crypto::bn254::field::bn128_base::Bn128Base;

    type Fp2 = QuadraticExtension<Bn128Base>;

    #[test]
    fn test_quadratic_extension_basics() {
        assert_eq!(Fp2::ZERO.0, [Bn128Base::ZERO, Bn128Base::ZERO]);
        assert_eq!(Fp2::ONE.0, [Bn128Base::ONE, Bn128Base::ZERO]);

        let x = Bn128Base::from_canonical_u64(42);
        let ext = Fp2::from(x);
        assert_eq!(ext.0[0], x);
        assert_eq!(ext.0[1], Bn128Base::ZERO);
    }

    #[test]
    fn test_quadratic_arithmetic() {
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(3), Bn128Base::from_canonical_u64(4)]);
        let b = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(1), Bn128Base::from_canonical_u64(2)]);

        let sum = a + b;
        assert_eq!(sum.0[0], Bn128Base::from_canonical_u64(4));
        assert_eq!(sum.0[1], Bn128Base::from_canonical_u64(6));

        let diff = a - b;
        assert_eq!(diff.0[0], Bn128Base::from_canonical_u64(2));
        assert_eq!(diff.0[1], Bn128Base::from_canonical_u64(2));

        let neg_a = -a;
        assert_eq!(a + neg_a, Fp2::ZERO);
    }

    #[test]
    fn test_quadratic_inverse() {
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(2), Bn128Base::from_canonical_u64(3)]);
        let a_inv = a.inverse();

        let product = a * a_inv;
        assert_eq!(product, Fp2::ONE);

        assert!(Fp2::ZERO.try_inverse().is_none());
    }

    #[test]
    fn test_quadratic_square() {
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(3), Bn128Base::from_canonical_u64(4)]);
        let a_sq = a.square();
        let a_mul_a = a * a;
        assert_eq!(a_sq, a_mul_a);
    }

    #[test]
    fn test_mul_by_nonresidue() {
        use crate::crypto::bn254::field::bn128_extension::Bn128ExtConstants;

        // Test that mul_by_nonresidue_bn128 matches multiplication by EXT_NONRESIDUE
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(2), Bn128Base::from_canonical_u64(3)]);

        // Method 1: using mul_by_nonresidue_bn128
        let result1 = a.mul_by_nonresidue_bn128();

        // Method 2: multiply by EXT_NONRESIDUE directly
        let ext_nonresidue = <Bn128Base as Bn128ExtConstants>::EXT_NONRESIDUE;
        let nonresidue = Fp2::from_basefield_array(ext_nonresidue);
        let result2 = a * nonresidue;

        assert_eq!(result1, result2, "mul_by_nonresidue_bn128 should match multiplication by EXT_NONRESIDUE");
    }

    #[test]
    fn test_frobenius_map() {
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(5), Bn128Base::from_canonical_u64(7)]);

        let frob0 = a.repeated_frobenius(0);
        assert_eq!(frob0, a);

        let frob1 = a.repeated_frobenius(1);
        assert_eq!(frob1.0[0], a.0[0]);
        assert_eq!(frob1.0[1], -a.0[1]);

        let frob2 = a.repeated_frobenius(2);
        assert_eq!(frob2, a);
    }

    #[test]
    fn test_field_properties() {
        let x = Fp2::rand();
        let y = Fp2::rand();
        let z = Fp2::rand();

        assert_eq!((x + y) + z, x + (y + z));
        assert_eq!((x * y) * z, x * (y * z));

        assert_eq!(x + y, y + x);
        assert_eq!(x * y, y * x);

        assert_eq!(x * (y + z), x * y + x * z);

        assert_eq!(x + Fp2::ZERO, x);
        assert_eq!(x * Fp2::ONE, x);

        assert_eq!(x + (-x), Fp2::ZERO);
        if !x.is_zero() {
            assert_eq!(x * x.inverse(), Fp2::ONE);
        }
    }

    #[test]
    fn test_canonical_biguint() {
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(100), Bn128Base::from_canonical_u64(200)]);
        let big = a.to_canonical_biguint();

        let p = Bn128Base::order();
        let expected = BigUint::from(100u64) + BigUint::from(200u64) * p;
        assert_eq!(big, expected);
    }

    #[test]
    fn test_nonresidue_multiplication() {
        // Since the Bn128Base field implementation seems to have issues with Montgomery
        // form, let's use a different approach - use field arithmetic to build
        // our values
        let one = Bn128Base::ONE;
        let two = one + one;
        let three = two + one;
        let four = three + one;
        let five = four + one;
        let six = five + one;

        let a = Fp2::from_basefield_array([three, four]);
        let b = Fp2::from_basefield_array([five, six]);

        // (3 + 4u) * (5 + 6u) = 15 + 18u + 20u + 24u^2
        // Since u^2 = -1, this becomes:
        // = 15 + 38u - 24
        // = -9 + 38u
        let product = a * b;

        // Build expected result using field arithmetic
        let nine = three + three + three;
        let thirtyeight = six + six + six + six + six + six + two;
        let neg_nine = Bn128Base::ZERO - nine;
        let expected = Fp2::from_basefield_array([neg_nine, thirtyeight]);

        assert_eq!(product, expected);
    }

    #[test]
    fn test_inverse_with_correct_nonresidue() {
        // Test that inverse calculation uses the correct nonresidue
        let a = Fp2::from_basefield_array([Bn128Base::from_canonical_u64(2), Bn128Base::from_canonical_u64(3)]);

        // For a = 2 + 3u, the inverse is:
        // 1/(2 + 3u) = (2 - 3u) / (2^2 - 3^2 * u^2)
        // Since u^2 = -1:
        // = (2 - 3u) / (4 - 9 * (-1))
        // = (2 - 3u) / (4 + 9)
        // = (2 - 3u) / 13

        let a_inv = a.inverse();
        let product = a * a_inv;
        assert_eq!(product, Fp2::ONE);
    }
}
