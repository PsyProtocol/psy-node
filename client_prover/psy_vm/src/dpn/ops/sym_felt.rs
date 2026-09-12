use std::{
    fmt::{Debug, Display},
    hash::Hasher,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Div, DivAssign, Mul, MulAssign, Neg, Not, Rem, RemAssign,
        Shl, ShlAssign, Shr, ShrAssign, Sub, SubAssign,
    },
};

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, Field64, PrimeField64},
};
use serde::{Deserialize, Serialize};
use twox_hash::xxh3::HasherExt;

use super::{
    context_trait::{ContextFelt, DPNContext, FeltSized},
    op_types::{DPNBuiltInDataType, DPNOpType},
};

pub const SYM_FELT_REF_STORE_TYPE_MASK: u128 = 0xffff0000000000000000000000000000u128;
pub const SYM_FELT_REF_STORE_VALUE_MASK: u128 = 0x0000ffffffffffffffffffffffffffffu128;

pub const CONSTANT_TRUE_OP: u128 = (DPNOpType::ConstantTrue as u128) << 112;
pub const CONSTANT_FALSE_OP: u128 = (DPNOpType::ConstantFalse as u128) << 112;

#[derive(Clone, Serialize, Deserialize, PartialEq, Hash, PartialOrd, Ord, Eq, Copy)]
pub struct SymFeltRef(pub u128);
impl SymFeltRef {
    pub fn new_input(index: u64, input_type: DPNBuiltInDataType) -> SymFeltRef {
        match input_type {
            DPNBuiltInDataType::Target => SymFeltRef((DPNOpType::InputTarget as u128) << 112 | index as u128),
            DPNBuiltInDataType::U32Target => SymFeltRef((DPNOpType::U32InputTarget as u128) << 112 | index as u128),
            DPNBuiltInDataType::Bool => SymFeltRef((DPNOpType::BoolInputTarget as u128) << 112 | index as u128),
            _ => unreachable!(),
        }
    }
    pub const fn new_constant(value: u64) -> SymFeltRef {
        //assert!(value < GoldilocksField::ORDER, "Constant value {} is too large",
        // value);
        SymFeltRef((DPNOpType::Constant as u128) << 112 | (value % GoldilocksField::ORDER) as u128)
    }
    pub const fn new_constant_u32(value: u32) -> SymFeltRef {
        //assert!(value < GoldilocksField::ORDER, "Constant value {} is too large",
        // value);
        SymFeltRef((DPNOpType::ConstantU32 as u128) << 112 | value as u128)
    }
    pub fn cns<T: Into<SymFeltRef>>(val: T) -> SymFeltRef {
        val.into()
    }
    pub fn new_constant_reduce(value: u128) -> SymFeltRef {
        SymFeltRef((DPNOpType::Constant as u128) << 112 | (value % (GoldilocksField::ORDER as u128)) as u128)
    }
    pub fn is_constant_type(&self) -> bool {
        let op_type = self.get_op_type();
        op_type == DPNOpType::Constant || op_type == DPNOpType::ConstantTrue || op_type == DPNOpType::ConstantFalse
    }
    pub fn get_constant_value_multi(&self) -> u64 {
        let op_type = self.get_op_type();
        match op_type {
            DPNOpType::Constant => (self.0 & 0xffffffffffffffffu128) as u64,
            DPNOpType::ConstantTrue => 1,
            DPNOpType::ConstantFalse => 0,
            _ => panic!("Not a constant type"),
        }
    }
    pub fn get_constant_value_multi_u128(&self) -> u128 {
        self.get_constant_value_multi() as u128
    }

    pub fn get_constant_bool_value_multi(&self) -> bool {
        self.get_constant_value_multi() != 0
    }
    pub fn get_constant_value(&self) -> u64 {
        if self.0 == CONSTANT_TRUE_OP {
            1
        } else if self.0 == CONSTANT_FALSE_OP {
            0
        } else {
            (self.0 & 0xffffffffffffffffu128) as u64
        }
    }
    pub fn get_input_index(&self) -> u64 {
        (self.0 & 0xffffffffffffffffu128) as u64
    }
    pub fn get_target_hash_value(&self) -> u128 {
        self.0 & SYM_FELT_REF_STORE_VALUE_MASK
    }
    pub fn new_valueless(op_type: DPNOpType) -> SymFeltRef {
        SymFeltRef((op_type as u128) << 112)
    }

    pub fn get_op_type(&self) -> DPNOpType {
        ((self.0 >> 112) as u16).into()
    }
    pub fn needs_store(&self) -> bool {
        let type_id = (self.0 >> 112) as u16;
        /*
            Op Types which do NOT need to be stored:
                InputTarget = 0,
                Constant = 1,
                ConstantTrue = 2,
                ConstantFalse = 3,

                GetUserId = 46,
                GetContractId = 47,
                GetCheckpointId = 48,
                GetNonce = 49,
                GetUserPublicKeyHash = 50,
                GetCallerContractId = 79,

                U32InputTarget = 66,
                ConstantU32 = 67,

                BoolInputTarget = 74,
        */
        type_id > 3
            && type_id != DPNOpType::GetUserId as u16
            && type_id != DPNOpType::GetContractId as u16
            && type_id != DPNOpType::GetCallerContractId as u16
            && type_id != DPNOpType::GetCheckpointId as u16
            && type_id != DPNOpType::GetNonce as u16
            && type_id != DPNOpType::GetUserPublicKeyHash as u16
            && type_id != DPNOpType::GetSessionProofTreeRoot as u16
            && type_id != DPNOpType::U32InputTarget as u16
            && type_id != DPNOpType::ConstantU32 as u16
            && type_id != DPNOpType::BoolInputTarget as u16
    }
    pub fn constant_true() -> SymFeltRef {
        SymFeltRef((DPNOpType::ConstantTrue as u128) << 112)
    }
    pub fn constant_false() -> SymFeltRef {
        SymFeltRef((DPNOpType::ConstantFalse as u128) << 112)
    }
    pub fn constant_bool(val: bool) -> SymFeltRef {
        if val {
            SymFeltRef::constant_true()
        } else {
            SymFeltRef::constant_false()
        }
    }
    pub fn get_inline_def(&self) -> SymFeltDef {
        assert!(self.needs_store() == false, "Cannot get inline ref for non-store ref");
        SymFeltDef {
            op_type: self.get_op_type(),
            const_param: self.get_constant_value(),
            inputs: vec![],
        }
    }
}

impl Debug for SymFeltRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.get_op_type() {
            DPNOpType::InputTarget => {
                write!(f, "Input({})", self.get_input_index())
            }
            DPNOpType::Constant => {
                write!(f, "{}", self.get_constant_value())
            }
            DPNOpType::BoolInputTarget => {
                write!(f, "BoolInput({})", self.get_input_index())
            }
            DPNOpType::ConstantTrue => {
                write!(f, "true")
            }
            DPNOpType::ConstantFalse => {
                write!(f, "false")
            }
            DPNOpType::U32InputTarget => {
                write!(f, "{}", self.get_input_index())
            }
            DPNOpType::ConstantU32 => {
                write!(f, "{}u32", self.get_constant_value())
            }
            _ => {
                write!(f, "{:?}({:?})", self.get_op_type(), self.0 & SYM_FELT_REF_STORE_VALUE_MASK)
            }
        }
    }
}

impl Display for SymFeltRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Add for SymFeltRef {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() + other.get_u64()) % GoldilocksField::ORDER)
    }
}
impl Sub for SymFeltRef {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) - GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Mul for SymFeltRef {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) * GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Div for SymFeltRef {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) / GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Rem for SymFeltRef {
    type Output = Self;
    fn rem(self, other: Self) -> Self {
        SymFeltRef::new_constant(self.get_u64() % other.get_u64())
    }
}
impl BitAnd for SymFeltRef {
    type Output = Self;
    fn bitand(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() & other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitOr for SymFeltRef {
    type Output = Self;
    fn bitor(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() | other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitXor for SymFeltRef {
    type Output = Self;
    fn bitxor(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() ^ other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl Shl for SymFeltRef {
    type Output = Self;
    fn shl(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() << other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl Shr for SymFeltRef {
    type Output = Self;
    fn shr(self, other: Self) -> Self {
        SymFeltRef::new_constant((self.get_u64() >> other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl Not for SymFeltRef {
    type Output = Self;
    fn not(self) -> Self {
        SymFeltRef::new_constant((self.get_u64() == 0) as u64)
    }
}
impl Neg for SymFeltRef {
    type Output = Self;
    fn neg(self) -> Self {
        SymFeltRef::new_constant(GoldilocksField::from_noncanonical_u64(self.get_u64()).neg().to_canonical_u64())
    }
}
impl AddAssign for SymFeltRef {
    fn add_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() + other.get_u64()) % GoldilocksField::ORDER)
    }
}
impl SubAssign for SymFeltRef {
    fn sub_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) - GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl MulAssign for SymFeltRef {
    fn mul_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) * GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl DivAssign for SymFeltRef {
    fn div_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) / GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl RemAssign for SymFeltRef {
    fn rem_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant(self.get_u64() % other.get_u64())
    }
}
impl BitAndAssign for SymFeltRef {
    fn bitand_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() & other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitOrAssign for SymFeltRef {
    fn bitor_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() | other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitXorAssign for SymFeltRef {
    fn bitxor_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() ^ other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl ShlAssign for SymFeltRef {
    fn shl_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() << other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl ShrAssign for SymFeltRef {
    fn shr_assign(&mut self, other: Self) {
        *self = SymFeltRef::new_constant((self.get_u64() >> other.get_u64()) & 0xFFFFFFFFu64)
    }
}

impl Add<u64> for SymFeltRef {
    type Output = Self;
    fn add(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() + other) % GoldilocksField::ORDER)
    }
}
impl Sub<u64> for SymFeltRef {
    type Output = Self;
    fn sub(self, other: u64) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) - GoldilocksField::from_noncanonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl Mul<u64> for SymFeltRef {
    type Output = Self;
    fn mul(self, other: u64) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) * GoldilocksField::from_noncanonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl Div<u64> for SymFeltRef {
    type Output = Self;
    fn div(self, other: u64) -> Self {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self.get_u64()) / GoldilocksField::from_noncanonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl Rem<u64> for SymFeltRef {
    type Output = Self;
    fn rem(self, other: u64) -> Self {
        SymFeltRef::new_constant(self.get_u64() % other)
    }
}
impl BitAnd<u64> for SymFeltRef {
    type Output = Self;
    fn bitand(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() & other) & 0xFFFFFFFFu64)
    }
}
impl BitOr<u64> for SymFeltRef {
    type Output = Self;
    fn bitor(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() | other) & 0xFFFFFFFFu64)
    }
}
impl BitXor<u64> for SymFeltRef {
    type Output = Self;
    fn bitxor(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() ^ other) & 0xFFFFFFFFu64)
    }
}
impl Shl<u64> for SymFeltRef {
    type Output = Self;
    fn shl(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() << other) & 0xFFFFFFFFu64)
    }
}
impl Shr<u64> for SymFeltRef {
    type Output = Self;
    fn shr(self, other: u64) -> Self {
        SymFeltRef::new_constant((self.get_u64() >> other) & 0xFFFFFFFFu64)
    }
}

impl Add<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn add(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self + other.get_u64()) % GoldilocksField::ORDER)
    }
}
impl Sub<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn sub(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self) - GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Mul<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn mul(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self) * GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Div<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn div(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant(
            (GoldilocksField::from_noncanonical_u64(self) / GoldilocksField::from_noncanonical_u64(other.get_u64())).to_canonical_u64(),
        )
    }
}
impl Rem<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn rem(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant(self % other.get_u64())
    }
}
impl BitAnd<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn bitand(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self & other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitOr<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn bitor(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self | other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl BitXor<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn bitxor(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self ^ other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl Shl<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn shl(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self << other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl Shr<SymFeltRef> for u64 {
    type Output = SymFeltRef;
    fn shr(self, other: SymFeltRef) -> SymFeltRef {
        SymFeltRef::new_constant((self >> other.get_u64()) & 0xFFFFFFFFu64)
    }
}
impl AddAssign<SymFeltRef> for u64 {
    fn add_assign(&mut self, other: SymFeltRef) {
        *self = *self + other.get_u64() % GoldilocksField::ORDER
    }
}
impl SubAssign<SymFeltRef> for u64 {
    fn sub_assign(&mut self, other: SymFeltRef) {
        *self = (GoldilocksField::from_canonical_u64(*self) - GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64()
    }
}
impl MulAssign<SymFeltRef> for u64 {
    fn mul_assign(&mut self, other: SymFeltRef) {
        *self = (GoldilocksField::from_canonical_u64(*self) * GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64()
    }
}
impl DivAssign<SymFeltRef> for u64 {
    fn div_assign(&mut self, other: SymFeltRef) {
        *self = (GoldilocksField::from_canonical_u64(*self) / GoldilocksField::from_canonical_u64(other.get_u64())).to_canonical_u64()
    }
}
impl RemAssign<SymFeltRef> for u64 {
    fn rem_assign(&mut self, other: SymFeltRef) {
        *self = *self % other.get_u64()
    }
}
impl BitAndAssign<SymFeltRef> for u64 {
    fn bitand_assign(&mut self, other: SymFeltRef) {
        *self = (*self & other.get_u64()) & 0xFFFFFFFFu64
    }
}
impl BitOrAssign<SymFeltRef> for u64 {
    fn bitor_assign(&mut self, other: SymFeltRef) {
        *self = (*self | other.get_u64()) & 0xFFFFFFFFu64
    }
}
impl BitXorAssign<SymFeltRef> for u64 {
    fn bitxor_assign(&mut self, other: SymFeltRef) {
        *self = (*self ^ other.get_u64()) & 0xFFFFFFFFu64
    }
}
impl ShlAssign<SymFeltRef> for u64 {
    fn shl_assign(&mut self, other: SymFeltRef) {
        *self = (*self << other.get_u64()) & 0xFFFFFFFFu64
    }
}
impl ShrAssign<SymFeltRef> for u64 {
    fn shr_assign(&mut self, other: SymFeltRef) {
        *self = (*self >> other.get_u64()) & 0xFFFFFFFFu64
    }
}
impl AddAssign<u64> for SymFeltRef {
    fn add_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() + other) % GoldilocksField::ORDER)
    }
}
impl SubAssign<u64> for SymFeltRef {
    fn sub_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) - GoldilocksField::from_canonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl MulAssign<u64> for SymFeltRef {
    fn mul_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) * GoldilocksField::from_canonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl DivAssign<u64> for SymFeltRef {
    fn div_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant(
            (GoldilocksField::from_canonical_u64(self.get_u64()) / GoldilocksField::from_canonical_u64(other)).to_canonical_u64(),
        )
    }
}
impl RemAssign<u64> for SymFeltRef {
    fn rem_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant(self.get_u64() % other)
    }
}
impl BitAndAssign<u64> for SymFeltRef {
    fn bitand_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() & other) & 0xFFFFFFFFu64)
    }
}
impl BitOrAssign<u64> for SymFeltRef {
    fn bitor_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() | other) & 0xFFFFFFFFu64)
    }
}
impl BitXorAssign<u64> for SymFeltRef {
    fn bitxor_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() ^ other) & 0xFFFFFFFFu64)
    }
}
impl ShlAssign<u64> for SymFeltRef {
    fn shl_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() << other) & 0xFFFFFFFFu64)
    }
}
impl ShrAssign<u64> for SymFeltRef {
    fn shr_assign(&mut self, other: u64) {
        *self = SymFeltRef::new_constant((self.get_u64() >> other) & 0xFFFFFFFFu64)
    }
}
impl PartialEq<u64> for SymFeltRef {
    fn eq(&self, other: &u64) -> bool {
        self.get_u64() == *other
    }
}
impl PartialOrd<u64> for SymFeltRef {
    fn partial_cmp(&self, other: &u64) -> Option<std::cmp::Ordering> {
        self.get_u64().partial_cmp(other)
    }
}
impl From<u8> for SymFeltRef {
    fn from(val: u8) -> SymFeltRef {
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}
impl From<u16> for SymFeltRef {
    fn from(val: u16) -> SymFeltRef {
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}
impl From<u32> for SymFeltRef {
    fn from(val: u32) -> SymFeltRef {
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}

impl From<u64> for SymFeltRef {
    fn from(val: u64) -> SymFeltRef {
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}

impl From<i32> for SymFeltRef {
    fn from(val: i32) -> SymFeltRef {
        assert!(val >= 0, "Negative values are not supported");
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}
impl From<i64> for SymFeltRef {
    fn from(val: i64) -> SymFeltRef {
        assert!(val >= 0, "Negative values are not supported");
        SymFeltRef((val as u128) | ((DPNOpType::Constant as u128) << 112))
    }
}
impl From<bool> for SymFeltRef {
    fn from(val: bool) -> SymFeltRef {
        SymFeltRef::constant_bool(val)
    }
}

impl ContextFelt for SymFeltRef {
    fn cns(value: u64) -> Self {
        SymFeltRef::new_constant(value)
    }
    fn cns_inverse(value: u64) -> Self {
        SymFeltRef::new_constant(GoldilocksField::from_noncanonical_u64(value).inverse().to_canonical_u64())
    }

    fn get_u64(&self) -> u64 {
        self.get_constant_value()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Hash, PartialOrd, Ord, Eq)]
pub struct SymFeltRefValue {
    pub op_type: DPNOpType,
    pub const_param: u64,
    pub inputs: Vec<SymFeltRef>,
}

impl SymFeltRefValue {
    pub fn get_ref_key(&self) -> SymFeltRef {
        if self.op_type == DPNOpType::Constant || self.op_type == DPNOpType::InputTarget {
            return SymFeltRef(((self.op_type as u128) << 112) | self.const_param as u128);
        } else {
            let mut hasher = twox_hash::Xxh3Hash128::default();
            hasher.write(&bincode::serialize(&self).unwrap());
            SymFeltRef((hasher.finish_ext() & SYM_FELT_REF_STORE_VALUE_MASK) | ((self.op_type as u128) << 112))
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Hash, PartialOrd, Ord, Eq)]
pub struct SymFeltDef {
    pub op_type: DPNOpType,
    pub const_param: u64,
    pub inputs: Vec<SymFeltDef>,
}

impl SymFeltDef {
    pub fn to_code_string(&self) -> String {
        if self.op_type == DPNOpType::Constant {
            return format!("{}", self.const_param);
        } else if self.op_type == DPNOpType::InputTarget {
            return format!("input{}", self.const_param);
        } else if self.op_type == DPNOpType::ConstantTrue {
            return format!("true");
        } else if self.op_type == DPNOpType::ConstantFalse {
            return format!("false");
        }
        let op_type_string = self.op_type.to_string();
        let args = self.inputs.iter().map(|x| x.to_code_string()).collect::<Vec<String>>().join(", ");
        format!("{}({})", op_type_string, args)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymRefAssertion {
    pub left: SymFeltRef,
    pub right: SymFeltRef,
    pub message: &'static str,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetSymFeltRef {
    pub before_external_function_call: u16,
    pub index: SymFeltRef,
    pub value: SymFeltRef,
}

impl SymFeltRef {
    pub fn set_state<CTXT: DPNContext<SymFeltRef>>(&self, context: &mut CTXT, value: SymFeltRef) -> SymFeltRef {
        context.cset_state(*self, value)
    }
}
impl SetSymFeltRef {
    pub fn new(before_external_function_call: u16, index: SymFeltRef, value: SymFeltRef) -> SetSymFeltRef {
        SetSymFeltRef {
            before_external_function_call,
            index: index,
            value: value,
        }
    }
}

impl FeltSized for SymFeltRef {
    fn size() -> u64 {
        1
    }
}

pub trait QStateInitializable: FeltSized {
    fn create_stateful_at<CTXT: DPNContext<SymFeltRef>>(
        context: &mut CTXT,
        state_pointer: SymFeltRef,
        contract_state_tree_height: u16,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
    ) -> Self;
}

impl QStateInitializable for SymFeltRef {
    fn create_stateful_at<CTXT: DPNContext<SymFeltRef>>(
        context: &mut CTXT,
        state_pointer: SymFeltRef,
        contract_state_tree_height: u16,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
    ) -> Self {
        context.op_get_state_felt(
            SymFeltRef::new_constant(contract_state_tree_height as u64),
            contract_id,
            user_id,
            state_pointer,
        )
    }
}

impl<T: QStateInitializable, const N: usize> QStateInitializable for [T; N] {
    fn create_stateful_at<CTXT: DPNContext<SymFeltRef>>(
        context: &mut CTXT,
        state_pointer: SymFeltRef,
        contract_state_tree_height: u16,
        contract_id: SymFeltRef,
        user_id: SymFeltRef,
    ) -> Self {
        core::array::from_fn(|i| {
            let offset = if i == 0 {
                state_pointer
            } else {
                let constant_i = SymFeltRef::new_constant((i as u64) * T::size());
                context.op_add(state_pointer, constant_i)
            };
            T::create_stateful_at(context, offset, contract_state_tree_height, contract_id, user_id)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(reference: SymFeltRef) -> u64 {
        reference.get_constant_value()
    }

    #[test]
    fn constant_and_input_references_keep_their_kind_and_payload() {
        let input = SymFeltRef::new_input(12, DPNBuiltInDataType::Target);
        let boolean = SymFeltRef::new_input(3, DPNBuiltInDataType::Bool);
        let constant = SymFeltRef::new_constant(99);

        assert_eq!(input.get_op_type(), DPNOpType::InputTarget);
        assert_eq!(input.get_input_index(), 12);
        assert_eq!(boolean.get_op_type(), DPNOpType::BoolInputTarget);
        assert_eq!(constant.get_constant_value_multi(), 99);
        assert!(constant.is_constant_type());
        assert_eq!(format!("{input}"), "Input(12)");
        assert_eq!(format!("{}", SymFeltRef::constant_true()), "true");
        assert_eq!(format!("{}", SymFeltRef::constant_false()), "false");
        assert!(!input.needs_store());
        assert!(!constant.needs_store());
    }

    #[test]
    fn arithmetic_bitwise_and_assignment_operators_preserve_constant_semantics() {
        let a = SymFeltRef::new_constant(12);
        let b = SymFeltRef::new_constant(3);

        assert_eq!(value(a + b), 15);
        assert_eq!(value(a - b), 9);
        assert_eq!(value(a * b), 36);
        assert_eq!(value(a / b), 4);
        assert_eq!(value(a % b), 0);
        assert_eq!(value(a & b), 0);
        assert_eq!(value(a | b), 15);
        assert_eq!(value(a ^ b), 15);
        assert_eq!(value(a << b), 96);
        assert_eq!(value(a >> b), 1);
        assert_eq!(value(!SymFeltRef::new_constant(0)), 1);
        assert_eq!(value(!SymFeltRef::new_constant(1)), 0);

        let mut assigned = a;
        assigned += b;
        assigned -= 2;
        assigned *= 2;
        assigned /= 13;
        assigned %= 2;
        assigned |= 8;
        assigned ^= 1;
        assigned &= 15;
        assigned <<= 1;
        assigned >>= 1;
        assert_eq!(value(assigned), 9);
    }

    #[test]
    fn primitive_interoperability_and_definition_rendering_are_stable() {
        let reference = SymFeltRef::from(4u64);
        assert_eq!(value(reference + 5), 9);
        assert_eq!(value(20u64 - reference), 16);
        assert_eq!(value(3u64 * reference), 12);
        assert_eq!(value(20u64 / reference), 5);
        assert_eq!(value(21u64 % reference), 1);
        assert_eq!(value(8u64 | reference), 12);

        let mut number = 20u64;
        number -= reference;
        number *= reference;
        number /= reference;
        number %= reference;
        number |= reference;
        number ^= reference;
        number &= reference;
        number <<= reference;
        number >>= reference;
        assert_eq!(number, 0);

        let def = SymFeltDef {
            op_type: DPNOpType::Add,
            const_param: 0,
            inputs: vec![
                SymFeltDef { op_type: DPNOpType::InputTarget, const_param: 1, inputs: vec![] },
                SymFeltDef { op_type: DPNOpType::Constant, const_param: 2, inputs: vec![] },
            ],
        };
        assert_eq!(def.to_code_string(), "DPNOpType::Add(input1, 2)");
        assert_eq!(SymFeltRefValue { op_type: DPNOpType::Constant, const_param: 7, inputs: vec![] }.get_ref_key(), SymFeltRef::new_constant(7));
    }

    #[test]
    fn constant_helpers_cover_boolean_and_u128_reduction_boundaries() {
        assert_eq!(SymFeltRef::constant_bool(true), SymFeltRef::constant_true());
        assert_eq!(SymFeltRef::constant_bool(false), SymFeltRef::constant_false());
        assert_eq!(SymFeltRef::new_constant_u32(u32::MAX).get_constant_value(), u32::MAX as u64);
        assert_eq!(SymFeltRef::new_constant_reduce(u128::MAX).get_constant_value(), (u128::MAX % GoldilocksField::ORDER as u128) as u64);
        assert_eq!(SymFeltRef::constant_true().get_constant_bool_value_multi(), true);
        assert_eq!(SymFeltRef::constant_false().get_constant_bool_value_multi(), false);
    }

    #[test]
    #[should_panic(expected = "Cannot get inline ref")]
    fn inline_definition_rejects_stored_operation_references() {
        let stored = SymFeltRef((DPNOpType::Add as u128) << 112);
        let _ = stored.get_inline_def();
    }

    #[test]
    #[should_panic]
    fn new_input_rejects_array_data_types() {
        let _ = SymFeltRef::new_input(0, DPNBuiltInDataType::TargetArray);
    }

    #[test]
    fn reference_rhs_assignments_and_reverse_integer_operators_are_exercised() {
        let a = SymFeltRef::new_constant(20);
        let b = SymFeltRef::new_constant(4);
        let _ = -a;
        let mut assigned = a;
        assigned += b;
        assigned -= b;
        assigned *= b;
        assigned /= b;
        assigned %= b;
        assigned &= b;
        assigned |= b;
        assigned ^= b;
        assigned <<= b;
        assigned >>= b;
        assert_eq!(assigned.get_constant_value(), 0);

        assert_eq!(value(20u64 + b), 24);
        assert_eq!(value(20u64 - b), 16);
        assert_eq!(value(20u64 * b), 80);
        assert_eq!(value(20u64 / b), 5);
        assert_eq!(value(20u64 % b), 0);
        assert_eq!(value(20u64 & b), 4);
        assert_eq!(value(20u64 | b), 20);
        assert_eq!(value(20u64 ^ b), 16);
        assert_eq!(value(20u64 << b), 320);
        assert_eq!(value(20u64 >> b), 1);
    }

    #[test]
    fn primitive_operator_conversion_and_rendering_boundaries_are_exercised() {
        let base = SymFeltRef::new_constant(20);
        assert_eq!(value(base + 4u64), 24);
        assert_eq!(value(base - 4u64), 16);
        assert_eq!(value(base * 4u64), 80);
        assert_eq!(value(base / 4u64), 5);
        assert_eq!(value(base % 6u64), 2);
        assert_eq!(value(base & 6u64), 4);
        assert_eq!(value(base | 3u64), 23);
        assert_eq!(value(base ^ 4u64), 16);
        assert_eq!(value(base << 2u64), 80);
        assert_eq!(value(base >> 2u64), 5);

        let mut assigned = base;
        assigned += 4u64;
        assert_eq!(assigned, 24u64);
        assigned -= 4u64;
        assigned *= 2u64;
        assigned /= 4u64;
        assigned %= 7u64;
        assigned &= 6u64;
        assigned |= 8u64;
        assigned ^= 2u64;
        assigned <<= 1u64;
        assigned >>= 2u64;
        assert_eq!(assigned.get_constant_value(), 4);
        assert!(assigned < 5u64);

        assert_eq!(SymFeltRef::from(u8::MAX).get_constant_value(), u8::MAX as u64);
        assert_eq!(SymFeltRef::from(u16::MAX).get_constant_value(), u16::MAX as u64);
        assert_eq!(SymFeltRef::from(u32::MAX).get_constant_value(), u32::MAX as u64);
        assert_eq!(SymFeltRef::from(7i32).get_constant_value(), 7);
        assert_eq!(SymFeltRef::from(8i64).get_constant_value(), 8);
        assert_eq!(SymFeltRef::from(true), SymFeltRef::constant_true());
        assert_eq!(SymFeltRef::from(false), SymFeltRef::constant_false());
        assert!(std::panic::catch_unwind(|| SymFeltRef::from(-1i32)).is_err());
        assert!(std::panic::catch_unwind(|| SymFeltRef::from(-1i64)).is_err());

        assert_eq!(SymFeltRef::new_constant(17).get_constant_value_multi_u128(), 17u128);
        assert_eq!(SymFeltRef::new_valueless(DPNOpType::Add).get_target_hash_value(), 0);
        assert_eq!(format!("{:?}", SymFeltRef::new_input(2, DPNBuiltInDataType::Bool)), "BoolInput(2)");
        assert_eq!(format!("{:?}", SymFeltRef::new_input(3, DPNBuiltInDataType::U32Target)), "3");
        assert_eq!(format!("{:?}", SymFeltRef::new_constant_u32(4)), "4u32");
        assert!(format!("{:?}", SymFeltRef::new_valueless(DPNOpType::Add)).contains("Add"));
        assert_eq!(<SymFeltRef as ContextFelt>::cns(9).get_constant_value(), 9);
        assert_eq!(
            <SymFeltRef as ContextFelt>::cns_inverse(2).get_constant_value(),
            GoldilocksField::from_canonical_u64(2).inverse().to_canonical_u64()
        );

        let set = SetSymFeltRef::new(5, SymFeltRef::new_constant(6), SymFeltRef::new_constant(7));
        assert_eq!(set.before_external_function_call, 5);
        assert_eq!(set.index.get_constant_value(), 6);
        assert_eq!(set.value.get_constant_value(), 7);
        assert_eq!(SymFeltRef::size(), 1);
    }

    #[test]
    #[should_panic(expected = "Not a constant type")]
    fn multi_constant_accessor_rejects_input_references() {
        let _ = SymFeltRef::new_input(0, DPNBuiltInDataType::Target).get_constant_value_multi();
    }
}
