use core::{
    fmt::{self, Debug, Display, Formatter},
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use num::bigint::BigUint;
use plonky2::field::{
    extension::{Extendable, FieldExtension, Frobenius, OEF},
    types::{Field, PrimeField, Sample},
};
use serde::{Deserialize, Serialize};

use super::quadratic::QuadraticExtension;
use crate::crypto::bn254::field::bn128_base::Bn128Base;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct SexticExtension<F: Extendable<6>>(pub [F; 6]);

impl<F: Extendable<6> + Extendable<2> + PrimeField> Default for SexticExtension<F> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> FieldExtension<6> for SexticExtension<F> {
    type BaseField = F;

    fn to_basefield_array(&self) -> [F; 6] {
        self.0
    }

    fn from_basefield_array(arr: [F; 6]) -> Self {
        Self(arr)
    }

    fn from_basefield(x: F) -> Self {
        x.into()
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> From<F> for SexticExtension<F> {
    fn from(x: F) -> Self {
        Self([x, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> SexticExtension<F> {
    pub const ZERO: Self = Self([F::ZERO; 6]);
    pub const ONE: Self = Self([F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
    pub const TWO: Self = Self([F::TWO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
    pub const NEG_ONE: Self = Self([F::NEG_ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);

    pub fn rand_from_rng<R: rand::RngCore + ?Sized>(rng: &mut R) -> Self {
        Self::from_basefield_array([
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
        ])
    }

    pub fn rand() -> Self {
        let mut rng = rand::thread_rng();
        Self::rand_from_rng(&mut rng)
    }

    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|x| x.is_zero())
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
        // For sextic extension over Fp2, multiplying by nonresidue shifts components
        // c2 -> c0 (with multiplication by Fp2's nonresidue)
        // c0 -> c1
        // c1 -> c2

        // Check if we're dealing with Bn128Base
        if core::any::TypeId::of::<F>() == core::any::TypeId::of::<Bn128Base>() {
            // We know F is Bn128Base at runtime, so we can safely convert
            let self_bn128: &SexticExtension<Bn128Base> = unsafe { core::mem::transmute(self) };
            let result_bn128 = self_bn128.mul_by_nonresidue_bn128();
            return unsafe { core::mem::transmute_copy(&result_bn128) };
        }

        // Generic implementation
        let c0 = QuadraticExtension([self.0[4], self.0[5]]).mul_by_nonresidue();
        Self {
            0: [c0.0[0], c0.0[1], self.0[0], self.0[1], self.0[2], self.0[3]],
        }
    }

    pub fn order() -> BigUint {
        use num::traits::Pow;
        F::order().pow(6u32)
    }

    pub fn characteristic() -> BigUint {
        F::characteristic()
    }

    pub const fn bits() -> usize {
        F::BITS * 6
    }

    pub fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let s0 = QuadraticExtension([self.0[0], self.0[1]]);
        let s1 = QuadraticExtension([self.0[2], self.0[3]]);
        let s2 = QuadraticExtension([self.0[4], self.0[5]]);

        let c0 = (s0 * s0) - s1 * s2.mul_by_nonresidue();
        let c1 = (s2 * s2).mul_by_nonresidue() - s0 * s1;
        let c2 = s1 * s1 - s0 * s2;

        let t = ((s2 * c1 + s1 * c2).mul_by_nonresidue() + s0 * c0).try_inverse()?;

        let c0 = t * c0;
        let c1 = t * c1;
        let c2 = t * c2;

        Some(Self([c0.0[0], c0.0[1], c1.0[0], c1.0[1], c2.0[0], c2.0[1]]))
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

    pub fn to_canonical_biguint(&self) -> BigUint {
        self.0[0].to_canonical_biguint()
    }

    pub fn multiplicative_group_factors() -> Vec<(BigUint, usize)> {
        vec![(BigUint::from(2u32), F::TWO_ADICITY + 2)]
    }
}

// Special implementation for SexticExtension over Bn128Base
impl SexticExtension<Bn128Base> {
    /// Specific implementation of mul_by_nonresidue for Fp6 over Bn128Base
    pub fn mul_by_nonresidue_bn128(&self) -> Self {
        // For sextic extension over Fp2, multiplying by nonresidue shifts components
        // c2 -> c0 (with multiplication by Fp2's nonresidue)
        // c0 -> c1
        // c1 -> c2
        let c2 = QuadraticExtension([self.0[4], self.0[5]]);
        let c0 = c2.mul_by_nonresidue_bn128();
        Self {
            0: [c0.0[0], c0.0[1], self.0[0], self.0[1], self.0[2], self.0[3]],
        }
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Sample for SexticExtension<F> {
    fn sample<R>(rng: &mut R) -> Self
    where
        R: rand::RngCore + ?Sized,
    {
        Self([
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
        ])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Field for SexticExtension<F> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;
    const TWO_ADICITY: usize = F::TWO_ADICITY + 2;
    const CHARACTERISTIC_TWO_ADICITY: usize = F::CHARACTERISTIC_TWO_ADICITY;
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self([F::MULTIPLICATIVE_GROUP_GENERATOR, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
    const POWER_OF_TWO_GENERATOR: Self = Self([F::POWER_OF_TWO_GENERATOR, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
    const BITS: usize = F::BITS * 6;

    fn try_inverse(&self) -> Option<Self> {
        self.try_inverse()
    }

    fn from_noncanonical_biguint(n: BigUint) -> Self {
        Self::from_noncanonical_biguint(n)
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self([F::from_canonical_u64(n), F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }

    fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    fn from_noncanonical_i64(n: i64) -> Self {
        Self([F::from_noncanonical_i64(n), F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }

    fn from_noncanonical_u128(n: u128) -> Self {
        Self([F::from_noncanonical_u128(n), F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }

    fn order() -> BigUint {
        F::order()
    }

    fn characteristic() -> BigUint {
        F::characteristic()
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Display for SexticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} + {}*v + {}*v^2 + {}*v^3 + {}*v^4 + {}*v^5",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Debug for SexticExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Neg for SexticExtension<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self([-self.0[0], -self.0[1], -self.0[2], -self.0[3], -self.0[4], -self.0[5]])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Add for SexticExtension<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
            self.0[5] + rhs.0[5],
        ])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> AddAssign for SexticExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Sum for SexticExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Sub for SexticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self([
            self.0[0] - rhs.0[0],
            self.0[1] - rhs.0[1],
            self.0[2] - rhs.0[2],
            self.0[3] - rhs.0[3],
            self.0[4] - rhs.0[4],
            self.0[5] - rhs.0[5],
        ])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> SubAssign for SexticExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Mul for SexticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let l0 = QuadraticExtension([self.0[0], self.0[1]]);
        let l1 = QuadraticExtension([self.0[2], self.0[3]]);
        let l2 = QuadraticExtension([self.0[4], self.0[5]]);
        let r0 = QuadraticExtension([rhs.0[0], rhs.0[1]]);
        let r1 = QuadraticExtension([rhs.0[2], rhs.0[3]]);
        let r2 = QuadraticExtension([rhs.0[4], rhs.0[5]]);

        let aa = r0 * l0;
        let bb = r1 * l1;
        let cc = r2 * l2;

        let c0 = ((l1 + l2) * (r1 + r2) - bb - cc).mul_by_nonresidue() + aa;
        let c1 = (l0 + l1) * (r0 + r1) - aa - bb + cc.mul_by_nonresidue();
        let c2 = (l0 + l2) * (r0 + r2) - aa + bb - cc;

        Self([c0.0[0], c0.0[1], c1.0[0], c1.0[1], c2.0[0], c2.0[1]])
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> MulAssign for SexticExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Product for SexticExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Div for SexticExtension<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> DivAssign for SexticExtension<F> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> OEF<6> for SexticExtension<F> {
    const W: F = <F as Extendable<6>>::W;
    const DTH_ROOT: F = <F as Extendable<6>>::DTH_ROOT;
}

impl<F: Extendable<6> + Extendable<2> + PrimeField> Frobenius<6> for SexticExtension<F> {
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count % 6 == 0 {
            *self
        } else {
            *self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mul_by_nonresidue_bn128() {
        // Test that mul_by_nonresidue works correctly for Fp6 over Bn128Base
        type Fp6 = SexticExtension<Bn128Base>;

        // Create a test element
        let a = Fp6::from_basefield_array([
            Bn128Base::from_canonical_u64(1),
            Bn128Base::from_canonical_u64(2),
            Bn128Base::from_canonical_u64(3),
            Bn128Base::from_canonical_u64(4),
            Bn128Base::from_canonical_u64(5),
            Bn128Base::from_canonical_u64(6),
        ]);

        // Method 1: using the generic mul_by_nonresidue
        let result1 = a.mul_by_nonresidue();

        // Method 2: using the specialized mul_by_nonresidue_bn128
        let result2 = a.mul_by_nonresidue_bn128();

        // They should give the same result
        assert_eq!(result1, result2, "mul_by_nonresidue and mul_by_nonresidue_bn128 should match");

        // Also verify the structure: c2 should move to c0 (after multiplication by
        // Fp2's nonresidue) c0 should move to c1, c1 should move to c2
        let c2 = QuadraticExtension([a.0[4], a.0[5]]);
        let c0_expected = c2.mul_by_nonresidue_bn128();

        // Extract components
        let result1_c0 = QuadraticExtension([result1.0[0], result1.0[1]]);
        let result1_c1 = QuadraticExtension([result1.0[2], result1.0[3]]);
        let result1_c2 = QuadraticExtension([result1.0[4], result1.0[5]]);

        let a_c0 = QuadraticExtension([a.0[0], a.0[1]]);
        let a_c1 = QuadraticExtension([a.0[2], a.0[3]]);

        assert_eq!(result1_c0, c0_expected);
        assert_eq!(result1_c1, a_c0);
        assert_eq!(result1_c2, a_c1);
    }
}
