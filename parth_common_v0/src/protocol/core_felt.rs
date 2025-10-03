use std::{iter::Sum, ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign, Div, DivAssign}};
use std::fmt::{Debug, Display};
use std::hash::Hash;

use serde::{de::DeserializeOwned, Serialize};
pub trait ToU64Value {
    fn to_u64_value(&self) -> u64;
}
pub trait QFelt: 
    'static
    + Copy
    + Eq
    + Hash
    + Neg<Output = Self>
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
    + DeserializeOwned {}
impl<T: 
    'static
    + Copy
    + Eq
    + Hash
    + Neg<Output = Self>
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
> QFelt for T {}

pub trait QFelt64: QFelt + ToU64Value {}
impl<T: QFelt + ToU64Value> QFelt64 for T {}