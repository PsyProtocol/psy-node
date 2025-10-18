use std::{
    fmt::{Debug, Display},
    hash::Hash,
    iter::Sum,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign},
};

use serde::{de::DeserializeOwned, Serialize};
use ts_rs::TS;

use crate::{
    data::maybe_serialization::{MaybeBytemuck, MaybeSpeedy}, generic_traits::QNamedType, utils::QPGenRandom
};

pub trait ToU64Value {
    fn to_u64_value(&self) -> u64;
    fn tuv_to_canonical_u64(&self) -> u64;
    fn into_u64_value_serialize_non_canonical(self) -> u64;
    fn from_owned_u64(value: u64) -> Self;
}

pub trait FromPrimitiveValuesFelt {
    fn from_u8_value(value: u8) -> Self;
    fn from_u16_value(value: u16) -> Self;
    fn from_u32_value(value: u32) -> Self;
    fn from_u64_value(value: u64) -> Self;
}
impl FromPrimitiveValuesFelt for u64 {
    fn from_u8_value(value: u8) -> Self {
        value as u64
    }
    fn from_u16_value(value: u16) -> Self {
        value as u64
    }
    fn from_u32_value(value: u32) -> Self {
        value as u64
    }
    fn from_u64_value(value: u64) -> Self {
        value
    }
}

pub trait SimpleRandFelt {
    fn get_simple_rand() -> Self;
}
pub trait ZeroableFelt {
    const ZERO_VALUE: Self;
}
impl ZeroableFelt for u64 {
    const ZERO_VALUE: Self = 0;
}
pub trait QFelt:
    'static
    + Copy
    + Eq
    + Hash
    + Add<Self, Output = Self>
    + AddAssign<Self>
    + Sum
    + Sub<Self, Output = Self>
    + SubAssign<Self>
    + Mul<Self, Output = Self>
    + MulAssign<Self>
    + Div<Self, Output = Self>
    + DivAssign<Self>
    + Debug
    + Default
    + Display
    + Send
    + Sync
    + Serialize
    + DeserializeOwned
    + ZeroableFelt
    + TS
    + FromPrimitiveValuesFelt
    + SimpleRandFelt
    + QPGenRandom
    + QNamedType
{
}
impl<
        T: 'static
            + Copy
            + Eq
            + Hash
            + Add<Self, Output = Self>
            + AddAssign<Self>
            + Sum
            + Sub<Self, Output = Self>
            + SubAssign<Self>
            + Mul<Self, Output = Self>
            + MulAssign<Self>
            + Div<Self, Output = Self>
            + DivAssign<Self>
            + Debug
            + Default
            + Display
            + Send
            + Sync
            + Serialize
            + DeserializeOwned
            + ZeroableFelt
            + TS
            + FromPrimitiveValuesFelt
            + SimpleRandFelt
            + QPGenRandom
            + QNamedType
            + MaybeSpeedy
            + MaybeBytemuck 
    > QFelt for T
{
}

pub trait QFelt64: QFelt + ToU64Value + MaybeBytemuck + MaybeSpeedy {}
impl<T: QFelt + ToU64Value + MaybeBytemuck + MaybeSpeedy> QFelt64 for T {}
pub trait QFeltSized {
    fn q_felt_size() -> usize;
    fn self_qsize(&self) -> usize {
        Self::q_felt_size()
    }
}
pub trait ToQFelts<F> {
    fn to_qfelts(&self) -> Vec<F>;
    fn from_qfelts(felts: &[F]) -> Self;
}

impl<F: Copy> ToQFelts<F> for F {
    fn to_qfelts(&self) -> Vec<F> {
        vec![*self]
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != 1 {
            panic!("Invalid number of elements for Felt");
        }
        felts[0]
    }
}
impl<const N: usize, F: Copy> ToQFelts<F> for [F; N] {
    fn to_qfelts(&self) -> Vec<F> {
        self.to_vec()
    }
    fn from_qfelts(felts: &[F]) -> Self {
        if felts.len() != N {
            panic!("Invalid number of elements for [F; {}]", N);
        }
        let mut arr = [felts[0]; N];
        arr.copy_from_slice(&felts[0..N]);
        arr
    }
}

impl ToU64Value for u64 {
    #[inline(always)]
    fn to_u64_value(&self) -> u64 {
        *self
    }
    
    #[inline(always)]
    fn into_u64_value_serialize_non_canonical(self) -> u64 {
        self
    }
    
    #[inline(always)]
    fn from_owned_u64(value: u64) -> Self {
        value
    }

    #[inline(always)]
    fn tuv_to_canonical_u64(&self) -> u64 {
        *self
    }
}

impl SimpleRandFelt for u64 {
    fn get_simple_rand() -> Self {
        rand::random::<u64>()
    }
}

impl QPGenRandom for u64 {
    fn qp_rand_gen() -> Self
    where
        Self: Sized,
    {
        rand::random::<u64>()
    }
}
