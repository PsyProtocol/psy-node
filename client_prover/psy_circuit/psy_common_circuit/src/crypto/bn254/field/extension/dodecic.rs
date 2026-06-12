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

use super::sextic::SexticExtension;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(bound = "")]
pub struct DodecicExtension<F: Extendable<12> + Extendable<6> + Extendable<2>>(pub [F; 12]);

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Default for DodecicExtension<F> {
    fn default() -> Self {
        Self::ZERO
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> FieldExtension<12> for DodecicExtension<F> {
    type BaseField = F;

    fn to_basefield_array(&self) -> [F; 12] {
        self.0
    }

    fn from_basefield_array(arr: [F; 12]) -> Self {
        Self(arr)
    }

    fn from_basefield(x: F) -> Self {
        x.into()
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> From<F> for DodecicExtension<F> {
    fn from(x: F) -> Self {
        Self([
            x,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> DodecicExtension<F> {
    pub const ZERO: Self = Self([F::ZERO; 12]);
    pub const ONE: Self = Self([
        F::ONE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);
    pub const TWO: Self = Self([
        F::TWO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);
    pub const NEG_ONE: Self = Self([
        F::NEG_ONE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);

    pub fn rand_from_rng<R: rand::RngCore + ?Sized>(rng: &mut R) -> Self {
        Self::from_basefield_array([
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
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

    pub fn order() -> BigUint {
        use num::traits::Pow;
        F::order().pow(12u32)
    }

    pub fn characteristic() -> BigUint {
        F::characteristic()
    }

    pub const fn bits() -> usize {
        F::BITS * 12
    }

    pub fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }

        let c0 = SexticExtension([self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]]);
        let c1 = SexticExtension([self.0[6], self.0[7], self.0[8], self.0[9], self.0[10], self.0[11]]);

        let c0_squared = c0 * c0;
        let c1_squared_mul_by_nonresidue = (c1 * c1).mul_by_nonresidue();
        let t = (c0_squared - c1_squared_mul_by_nonresidue).try_inverse()?;

        let r0 = c0 * t;
        let r1 = -(c1 * t);

        Some(DodecicExtension([
            r0.0[0], r0.0[1], r0.0[2], r0.0[3], r0.0[4], r0.0[5], r1.0[0], r1.0[1], r1.0[2], r1.0[3], r1.0[4], r1.0[5],
        ]))
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
        vec![(BigUint::from(2u32), F::TWO_ADICITY)]
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Sample for DodecicExtension<F> {
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
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
            F::sample(rng),
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Field for DodecicExtension<F> {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;
    const TWO: Self = Self::TWO;
    const NEG_ONE: Self = Self::NEG_ONE;
    const TWO_ADICITY: usize = F::TWO_ADICITY;
    const CHARACTERISTIC_TWO_ADICITY: usize = F::CHARACTERISTIC_TWO_ADICITY;
    const MULTIPLICATIVE_GROUP_GENERATOR: Self = Self([
        F::MULTIPLICATIVE_GROUP_GENERATOR,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);
    const POWER_OF_TWO_GENERATOR: Self = Self([
        F::POWER_OF_TWO_GENERATOR,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);
    const BITS: usize = F::BITS * 12;

    fn try_inverse(&self) -> Option<Self> {
        self.try_inverse()
    }

    fn from_noncanonical_biguint(n: BigUint) -> Self {
        Self::from_noncanonical_biguint(n)
    }

    fn from_canonical_u64(n: u64) -> Self {
        Self([
            F::from_canonical_u64(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_noncanonical_u64(n: u64) -> Self {
        Self::from_canonical_u64(n)
    }

    fn from_noncanonical_i64(n: i64) -> Self {
        Self([
            F::from_noncanonical_i64(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_noncanonical_u128(n: u128) -> Self {
        Self([
            F::from_noncanonical_u128(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn order() -> BigUint {
        F::order()
    }

    fn characteristic() -> BigUint {
        F::characteristic()
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Display for DodecicExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} + {}*w + {}*w^2 + {}*w^3 + {}*w^4 + {}*w^5 + {}*w^6 + {}*w^7 + {}*w^8 + {}*w^9 + {}*w^10 + {}*w^11",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5], self.0[6], self.0[7], self.0[8], self.0[9], self.0[10], self.0[11]
        )
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Debug for DodecicExtension<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Neg for DodecicExtension<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self([
            -self.0[0],
            -self.0[1],
            -self.0[2],
            -self.0[3],
            -self.0[4],
            -self.0[5],
            -self.0[6],
            -self.0[7],
            -self.0[8],
            -self.0[9],
            -self.0[10],
            -self.0[11],
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Add for DodecicExtension<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self([
            self.0[0] + rhs.0[0],
            self.0[1] + rhs.0[1],
            self.0[2] + rhs.0[2],
            self.0[3] + rhs.0[3],
            self.0[4] + rhs.0[4],
            self.0[5] + rhs.0[5],
            self.0[6] + rhs.0[6],
            self.0[7] + rhs.0[7],
            self.0[8] + rhs.0[8],
            self.0[9] + rhs.0[9],
            self.0[10] + rhs.0[10],
            self.0[11] + rhs.0[11],
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> AddAssign for DodecicExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Sum for DodecicExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |acc, x| acc + x)
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Sub for DodecicExtension<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self([
            self.0[0] - rhs.0[0],
            self.0[1] - rhs.0[1],
            self.0[2] - rhs.0[2],
            self.0[3] - rhs.0[3],
            self.0[4] - rhs.0[4],
            self.0[5] - rhs.0[5],
            self.0[6] - rhs.0[6],
            self.0[7] - rhs.0[7],
            self.0[8] - rhs.0[8],
            self.0[9] - rhs.0[9],
            self.0[10] - rhs.0[10],
            self.0[11] - rhs.0[11],
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> SubAssign for DodecicExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Mul for DodecicExtension<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let l0 = SexticExtension([self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]]);
        let l1 = SexticExtension([self.0[6], self.0[7], self.0[8], self.0[9], self.0[10], self.0[11]]);
        let r0 = SexticExtension([rhs.0[0], rhs.0[1], rhs.0[2], rhs.0[3], rhs.0[4], rhs.0[5]]);
        let r1 = SexticExtension([rhs.0[6], rhs.0[7], rhs.0[8], rhs.0[9], rhs.0[10], rhs.0[11]]);

        let aa = l0 * r0;
        let bb = l1 * r1;

        let c0 = bb.mul_by_nonresidue() + aa;
        let c1 = (l0 + l1) * (r0 + r1) - aa - bb;

        Self([
            c0.0[0], c0.0[1], c0.0[2], c0.0[3], c0.0[4], c0.0[5], c1.0[0], c1.0[1], c1.0[2], c1.0[3], c1.0[4], c1.0[5],
        ])
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> MulAssign for DodecicExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Product for DodecicExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |acc, x| acc * x)
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Div for DodecicExtension<F> {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> DivAssign for DodecicExtension<F> {
    fn div_assign(&mut self, rhs: Self) {
        *self = *self / rhs;
    }
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> OEF<12> for DodecicExtension<F> {
    const W: F = <F as Extendable<12>>::W;
    const DTH_ROOT: F = <F as Extendable<12>>::DTH_ROOT;
}

impl<F: Extendable<12> + Extendable<6> + Extendable<2> + PrimeField> Frobenius<12> for DodecicExtension<F> {
    fn repeated_frobenius(&self, count: usize) -> Self {
        if count % 12 == 0 {
            *self
        } else {
            *self
        }
    }
}
