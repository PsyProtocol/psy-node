use core::panic;
use std::ops::Neg;

use plonky2::field::{
    goldilocks_field::GoldilocksField,
    types::{Field, Field64, PrimeField64},
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use ts_rs::TS;
const INDEX_BITS: u64 = 32;
const INDEX_MASK: u64 = (1u64 << INDEX_BITS) - 1u64;

pub fn decode_indexed_op_id(id: u64) -> (DPNBuiltInDataType, usize) {
    (DPNBuiltInDataType::from(id >> INDEX_BITS), (id & INDEX_MASK) as usize)
}
pub fn encode_indexed_op_id(data_type: DPNBuiltInDataType, index: usize) -> u64 {
    ((data_type as u64) << INDEX_BITS) | (index as u64)
}

#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, TS)]
#[repr(u16)]
pub enum DPNOpType {
    InputTarget = 0,
    Constant = 1,
    ConstantTrue = 2,
    ConstantFalse = 3,
    Add = 4,
    Sub = 5,
    Mul = 6,
    Div = 7,
    BoolNot = 8,
    BoolAnd = 9,
    BoolOr = 10,
    Xor = 11,
    Nor = 12,
    Eq = 13,
    Lte = 14,
    Gte = 15,
    Gt = 16,
    Lt = 17,
    SplitBits = 18,
    SumBits = 19,
    TargetAt = 20,
    HashNoPad = 21,
    HashPad = 22,
    Select = 23,

    Exp = 24,
    ExpConstantPower = 25,
    ExpConstantBase = 26,

    Mod = 27,
    ModConstantDividend = 28,
    ModConstantDivisor = 29,
    DivRem4 = 30,

    CastU32 = 31,

    U32And = 32,
    U32AndConstant = 33,

    U32Or = 34,
    U32OrConstant = 35,

    U32Xor = 36,
    U32XorConstant = 37,

    U32ShiftLeft = 38,
    U32ShiftLeftConstantBitDistance = 40,
    U32ShiftLeftConstantValue = 41,

    U32ShiftRight = 42,
    U32ShiftRightConstantBitDistance = 43,
    U32ShiftRightConstantValue = 44,

    CalculateMerkleRoot = 45,

    GetUserId = 46,
    GetContractId = 47,
    GetCheckpointId = 48,
    GetNonce = 49,
    GetUserPublicKeyHash = 50,
    GetStateQueryResult = 51,
    GetStateQueryResultSingle = 52,

    GetStateCommandResultHash = 53,
    GetStateCommandResultSingle = 54,
    GetStateCommandResultArray = 55,

    UnaryInverse = 64,
    UnaryNegative = 65,
    U32InputTarget = 66,
    ConstantU32 = 67,
    U32Add = 68,
    U32Sub = 69,
    U32Mul = 70,
    U32Div = 71,
    CastFelt = 72,
    CastBool = 73,
    BoolInputTarget = 74,
    U32Mod = 75,
    U32Exp = 76,

    Secp256k1Verify = 77,
    HashTwoToOne = 78,
    GetCallerContractId = 79,
    GetSessionProofTreeRoot = 80,
    Keccak256 = 81,
}

impl From<u16> for DPNOpType {
    fn from(value: u16) -> Self {
        match value {
            0 => DPNOpType::InputTarget,
            1 => DPNOpType::Constant,
            2 => DPNOpType::ConstantTrue,
            3 => DPNOpType::ConstantFalse,
            4 => DPNOpType::Add,
            5 => DPNOpType::Sub,
            6 => DPNOpType::Mul,
            7 => DPNOpType::Div,
            8 => DPNOpType::BoolNot,
            9 => DPNOpType::BoolAnd,
            10 => DPNOpType::BoolOr,
            11 => DPNOpType::Xor,
            12 => DPNOpType::Nor,
            13 => DPNOpType::Eq,
            14 => DPNOpType::Lte,
            15 => DPNOpType::Gte,
            16 => DPNOpType::Gt,
            17 => DPNOpType::Lt,
            18 => DPNOpType::SplitBits,
            19 => DPNOpType::SumBits,
            20 => DPNOpType::TargetAt,
            21 => DPNOpType::HashNoPad,
            22 => DPNOpType::HashPad,
            23 => DPNOpType::Select,
            24 => DPNOpType::Exp,
            25 => DPNOpType::ExpConstantPower,
            26 => DPNOpType::ExpConstantBase,
            27 => DPNOpType::Mod,
            28 => DPNOpType::ModConstantDividend,
            29 => DPNOpType::ModConstantDivisor,
            30 => DPNOpType::DivRem4,
            31 => DPNOpType::CastU32,
            32 => DPNOpType::U32And,
            33 => DPNOpType::U32AndConstant,
            34 => DPNOpType::U32Or,
            35 => DPNOpType::U32OrConstant,
            36 => DPNOpType::U32Xor,
            37 => DPNOpType::U32XorConstant,
            38 => DPNOpType::U32ShiftLeft,
            40 => DPNOpType::U32ShiftLeftConstantBitDistance,
            41 => DPNOpType::U32ShiftLeftConstantValue,
            42 => DPNOpType::U32ShiftRight,
            43 => DPNOpType::U32ShiftRightConstantBitDistance,
            44 => DPNOpType::U32ShiftRightConstantValue,
            45 => DPNOpType::CalculateMerkleRoot,
            46 => DPNOpType::GetUserId,
            47 => DPNOpType::GetContractId,
            48 => DPNOpType::GetCheckpointId,
            49 => DPNOpType::GetNonce,
            50 => DPNOpType::GetUserPublicKeyHash,
            51 => DPNOpType::GetStateQueryResult,
            52 => DPNOpType::GetStateQueryResultSingle,
            53 => DPNOpType::GetStateCommandResultHash,
            54 => DPNOpType::GetStateCommandResultSingle,
            55 => DPNOpType::GetStateCommandResultArray,
            64 => DPNOpType::UnaryInverse,
            65 => DPNOpType::UnaryNegative,
            66 => DPNOpType::U32InputTarget,
            67 => DPNOpType::ConstantU32,
            68 => DPNOpType::U32Add,
            69 => DPNOpType::U32Sub,
            70 => DPNOpType::U32Mul,
            71 => DPNOpType::U32Div,
            72 => DPNOpType::CastFelt,
            73 => DPNOpType::CastBool,
            74 => DPNOpType::BoolInputTarget,
            75 => DPNOpType::U32Mod,
            76 => DPNOpType::U32Exp,
            77 => DPNOpType::Secp256k1Verify,
            78 => DPNOpType::HashTwoToOne,
            79 => DPNOpType::GetCallerContractId,
            80 => DPNOpType::GetSessionProofTreeRoot,
            81 => DPNOpType::Keccak256,
            _ => panic!("Unknown DPNOpType: {}", value),
        }
    }
}

impl DPNOpType {
    pub fn get_enc_value(&self) -> u16 {
        *self as u16
    }
    pub fn eval_binary_constant(&self, a: u64, b: u64) -> u64 {
        assert!(a < GoldilocksField::ORDER, "value {} is not a valid Felt", a);
        assert!(b < GoldilocksField::ORDER, "value {} is not a valid Felt", b);
        match self {
            DPNOpType::Add => (GoldilocksField::from_canonical_u64(a) + GoldilocksField::from_canonical_u64(b)).to_canonical_u64(),
            DPNOpType::Sub => (GoldilocksField::from_canonical_u64(a) - GoldilocksField::from_canonical_u64(b)).to_canonical_u64(),
            DPNOpType::Mul => (GoldilocksField::from_canonical_u64(a) * GoldilocksField::from_canonical_u64(b)).to_canonical_u64(),
            DPNOpType::Div => (GoldilocksField::from_canonical_u64(a) / GoldilocksField::from_canonical_u64(b)).to_canonical_u64(),
            DPNOpType::Xor => GoldilocksField::from_noncanonical_u64(a ^ b).0,
            DPNOpType::Eq => {
                if a == b {
                    1
                } else {
                    0
                }
            }
            DPNOpType::Lte => {
                if a <= b {
                    1
                } else {
                    0
                }
            }
            DPNOpType::Gte => {
                if a >= b {
                    1
                } else {
                    0
                }
            }
            DPNOpType::Gt => {
                if a > b {
                    1
                } else {
                    0
                }
            }
            DPNOpType::Lt => {
                if a < b {
                    1
                } else {
                    0
                }
            }
            DPNOpType::Exp | DPNOpType::ExpConstantPower | DPNOpType::ExpConstantBase => {
                (GoldilocksField::from_canonical_u64(a).exp_u64(b)).to_canonical_u64()
            }
            DPNOpType::Mod => a % b,
            DPNOpType::U32And => (a & b) & 0xffffffffu64,
            DPNOpType::U32Or => (a | b) & 0xffffffffu64,
            DPNOpType::U32Xor => (a ^ b) & 0xffffffffu64,
            // DPNOpType::U32ShiftLeft => (a << b) & 0xffffffffu64,
            // DPNOpType::U32ShiftRight => (a >> b) & 0xffffffffu64,
            DPNOpType::BoolAnd => (a & b) & 1,
            DPNOpType::BoolOr => (a | b) & 1,
            DPNOpType::U32Add => a + b,
            DPNOpType::U32Sub => a - b,
            DPNOpType::U32Mul => a * b,
            DPNOpType::U32Div => a / b,
            DPNOpType::U32Mod => a % b,
            DPNOpType::U32Exp => (GoldilocksField::from_canonical_u64(a).exp_u64(b)).to_canonical_u64(),
            DPNOpType::U32ShiftLeft | DPNOpType::U32ShiftLeftConstantBitDistance | DPNOpType::U32ShiftLeftConstantValue => (a << b) & 0xffffffffu64,
            DPNOpType::U32ShiftRight | DPNOpType::U32ShiftRightConstantBitDistance | DPNOpType::U32ShiftRightConstantValue => {
                (a >> b) & 0xffffffffu64
            }
            _ => panic!("DPNOpType::eval_binary_constant not implemented for {:?}", self),
        }
    }
    pub fn eval_unary_constant(&self, a: u64) -> u64 {
        assert!(a < GoldilocksField::ORDER, "value {} is not a valid Felt", a);
        match self {
            DPNOpType::BoolNot => {
                if a == 0 {
                    1
                } else {
                    0
                }
            }
            DPNOpType::UnaryInverse => GoldilocksField::from_noncanonical_u64(a).inverse().to_canonical_u64(),
            DPNOpType::UnaryNegative => GoldilocksField::from_noncanonical_u64(a).neg().to_canonical_u64(),
            _ => panic!("DPNOpType::eval_unary_constant not implemented for {:?}", self),
        }
    }
    pub fn get_data_type(&self) -> DPNBuiltInDataType {
        match self {
            DPNOpType::InputTarget => DPNBuiltInDataType::Target,
            DPNOpType::Constant => DPNBuiltInDataType::Target,
            DPNOpType::ConstantTrue => DPNBuiltInDataType::Bool,
            DPNOpType::ConstantFalse => DPNBuiltInDataType::Bool,
            DPNOpType::Add => DPNBuiltInDataType::Target,
            DPNOpType::Sub => DPNBuiltInDataType::Target,
            DPNOpType::Mul => DPNBuiltInDataType::Target,
            DPNOpType::Div => DPNBuiltInDataType::Target,
            DPNOpType::BoolNot => DPNBuiltInDataType::Bool,
            DPNOpType::BoolAnd => DPNBuiltInDataType::Bool,
            DPNOpType::BoolOr => DPNBuiltInDataType::Bool,
            DPNOpType::Xor => DPNBuiltInDataType::Bool,
            DPNOpType::Nor => DPNBuiltInDataType::Bool,
            DPNOpType::Eq => DPNBuiltInDataType::Bool,
            DPNOpType::Lte => DPNBuiltInDataType::Bool,
            DPNOpType::Gte => DPNBuiltInDataType::Bool,
            DPNOpType::Gt => DPNBuiltInDataType::Bool,
            DPNOpType::Lt => DPNBuiltInDataType::Bool,
            DPNOpType::SplitBits => DPNBuiltInDataType::BoolArray,
            DPNOpType::SumBits => DPNBuiltInDataType::Target,
            DPNOpType::TargetAt => DPNBuiltInDataType::Target,
            DPNOpType::HashNoPad => DPNBuiltInDataType::HashOut,
            DPNOpType::HashPad => DPNBuiltInDataType::HashOut,
            DPNOpType::Select => DPNBuiltInDataType::Target,
            DPNOpType::Exp => DPNBuiltInDataType::Target,
            DPNOpType::ExpConstantPower => DPNBuiltInDataType::Target,
            DPNOpType::ExpConstantBase => DPNBuiltInDataType::Target,
            DPNOpType::Mod => DPNBuiltInDataType::Target,
            DPNOpType::ModConstantDividend => DPNBuiltInDataType::Target,
            DPNOpType::ModConstantDivisor => DPNBuiltInDataType::Target,
            DPNOpType::DivRem4 => DPNBuiltInDataType::Target,
            DPNOpType::CastU32 => DPNBuiltInDataType::U32Target,
            DPNOpType::U32And => DPNBuiltInDataType::U32Target,
            DPNOpType::U32AndConstant => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Or => DPNBuiltInDataType::U32Target,
            DPNOpType::U32OrConstant => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Xor => DPNBuiltInDataType::U32Target,
            DPNOpType::U32XorConstant => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftLeft => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftLeftConstantBitDistance => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftLeftConstantValue => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftRight => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftRightConstantBitDistance => DPNBuiltInDataType::U32Target,
            DPNOpType::U32ShiftRightConstantValue => DPNBuiltInDataType::U32Target,
            DPNOpType::CalculateMerkleRoot => DPNBuiltInDataType::HashOut,
            DPNOpType::GetUserId => DPNBuiltInDataType::Target,
            DPNOpType::GetContractId => DPNBuiltInDataType::Target,
            DPNOpType::GetCallerContractId => DPNBuiltInDataType::Target,
            DPNOpType::GetCheckpointId => DPNBuiltInDataType::Target,
            DPNOpType::GetNonce => DPNBuiltInDataType::Target,
            DPNOpType::GetUserPublicKeyHash => DPNBuiltInDataType::HashOut,
            DPNOpType::GetSessionProofTreeRoot => DPNBuiltInDataType::HashOut,
            DPNOpType::GetStateQueryResult => DPNBuiltInDataType::HashOut,
            DPNOpType::GetStateQueryResultSingle => DPNBuiltInDataType::Target,
            DPNOpType::GetStateCommandResultHash => DPNBuiltInDataType::HashOut,
            DPNOpType::GetStateCommandResultSingle => DPNBuiltInDataType::Target,
            DPNOpType::GetStateCommandResultArray => DPNBuiltInDataType::TargetArray,
            DPNOpType::UnaryInverse => DPNBuiltInDataType::Target,
            DPNOpType::UnaryNegative => DPNBuiltInDataType::Target,
            DPNOpType::U32InputTarget => DPNBuiltInDataType::U32Target,
            DPNOpType::ConstantU32 => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Add => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Sub => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Mul => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Div => DPNBuiltInDataType::U32Target,
            DPNOpType::CastFelt => DPNBuiltInDataType::Target,
            DPNOpType::CastBool => DPNBuiltInDataType::Bool,
            DPNOpType::BoolInputTarget => DPNBuiltInDataType::Bool,
            DPNOpType::U32Mod => DPNBuiltInDataType::U32Target,
            DPNOpType::U32Exp => DPNBuiltInDataType::U32Target,
            DPNOpType::Secp256k1Verify => DPNBuiltInDataType::Bool,
            DPNOpType::HashTwoToOne => DPNBuiltInDataType::HashOut,
            DPNOpType::Keccak256 => DPNBuiltInDataType::U32TargetArray,
        }
    }
    pub fn is_inputless(&self) -> bool {
        match self {
            DPNOpType::ConstantTrue => true,
            DPNOpType::ConstantFalse => true,
            DPNOpType::GetUserId => true,
            DPNOpType::GetContractId => true,
            DPNOpType::GetCallerContractId => true,
            DPNOpType::GetCheckpointId => true,
            DPNOpType::GetNonce => true,
            DPNOpType::GetUserPublicKeyHash => true,
            DPNOpType::GetSessionProofTreeRoot => true,
            _ => false,
        }
    }
    pub fn needs_store(&self) -> bool {
        match self {
            DPNOpType::InputTarget => false,
            DPNOpType::Constant => false,
            DPNOpType::ConstantTrue => false,
            DPNOpType::ConstantFalse => false,
            DPNOpType::GetUserId => false,
            DPNOpType::GetContractId => false,
            DPNOpType::GetCallerContractId => false,
            DPNOpType::GetCheckpointId => false,
            DPNOpType::GetNonce => false,
            DPNOpType::GetUserPublicKeyHash => false,
            DPNOpType::GetSessionProofTreeRoot => false,
            _ => true,
        }
    }
    pub fn has_constant_param(&self) -> bool {
        match self {
            DPNOpType::Constant => true,
            DPNOpType::ConstantTrue => true,
            DPNOpType::ConstantFalse => true,
            DPNOpType::ExpConstantPower => true,
            DPNOpType::ExpConstantBase => true,
            DPNOpType::ModConstantDividend => true,
            DPNOpType::ModConstantDivisor => true,
            DPNOpType::U32AndConstant => true,
            DPNOpType::U32OrConstant => true,
            DPNOpType::U32XorConstant => true,
            // DPNOpType::U32ShiftLeftConstantBitDistance => true,
            // DPNOpType::U32ShiftLeftConstantValue => true,
            // DPNOpType::U32ShiftRightConstantBitDistance => true,
            // DPNOpType::U32ShiftRightConstantValue => true,
            DPNOpType::SplitBits => true,
            DPNOpType::GetStateCommandResultSingle => true,
            DPNOpType::GetStateCommandResultArray => true,
            DPNOpType::GetStateCommandResultHash => true,

            _ => false,
        }
    }
}

impl std::fmt::Display for DPNOpType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match &self {
            DPNOpType::InputTarget => "InputTarget",
            DPNOpType::Constant => "Constant",
            DPNOpType::ConstantTrue => "ConstantTrue",
            DPNOpType::ConstantFalse => "ConstantFalse",
            DPNOpType::Add => "Add",
            DPNOpType::Sub => "Sub",
            DPNOpType::Mul => "Mul",
            DPNOpType::Div => "Div",
            DPNOpType::BoolNot => "BoolNot",
            DPNOpType::BoolAnd => "BoolAnd",
            DPNOpType::BoolOr => "BoolOr",
            DPNOpType::Xor => "Xor",
            DPNOpType::Nor => "Nor",
            DPNOpType::Eq => "Eq",
            DPNOpType::Lte => "Lte",
            DPNOpType::Gte => "Gte",
            DPNOpType::Gt => "Gt",
            DPNOpType::Lt => "Lt",
            DPNOpType::SplitBits => "SplitBits",
            DPNOpType::SumBits => "SumBits",
            DPNOpType::TargetAt => "TargetAt",
            DPNOpType::HashNoPad => "HashNoPad",
            DPNOpType::HashPad => "HashPad",
            DPNOpType::Select => "Select",
            DPNOpType::Exp => "Exp",
            DPNOpType::ExpConstantPower => "ExpConstantPower",
            DPNOpType::ExpConstantBase => "ExpConstantBase",
            DPNOpType::Mod => "Mod",
            DPNOpType::ModConstantDividend => "ModConstantDividend",
            DPNOpType::ModConstantDivisor => "ModConstantDivisor",
            DPNOpType::DivRem4 => "DivRem4",
            DPNOpType::CastU32 => "CastU32",
            DPNOpType::U32And => "U32And",
            DPNOpType::U32AndConstant => "U32AndConstant",
            DPNOpType::U32Or => "U32Or",
            DPNOpType::U32OrConstant => "U32OrConstant",
            DPNOpType::U32Xor => "U32Xor",
            DPNOpType::U32XorConstant => "U32XorConstant",
            DPNOpType::U32ShiftLeft => "U32ShiftLeft",
            DPNOpType::U32ShiftLeftConstantBitDistance => "U32ShiftLeftConstantBitDistance",
            DPNOpType::U32ShiftLeftConstantValue => "U32ShiftLeftConstantValue",
            DPNOpType::U32ShiftRight => "U32ShiftRight",
            DPNOpType::U32ShiftRightConstantBitDistance => "U32ShiftRightConstantBitDistance",
            DPNOpType::U32ShiftRightConstantValue => "U32ShiftRightConstantValue",
            DPNOpType::CalculateMerkleRoot => "CalculateMerkleRoot",
            DPNOpType::GetUserId => "GetUserId",
            DPNOpType::GetContractId => "GetContractId",
            DPNOpType::GetCallerContractId => "GetCallerContractId",
            DPNOpType::GetCheckpointId => "GetCheckpointId",
            DPNOpType::GetNonce => "GetNonce",
            DPNOpType::GetUserPublicKeyHash => "GetUserPublicKeyHash",
            DPNOpType::GetSessionProofTreeRoot => "GetSessionProofTreeRoot",
            DPNOpType::GetStateQueryResult => "GetStateQueryResult",
            DPNOpType::GetStateQueryResultSingle => "GetStateQueryResultSingle",
            DPNOpType::GetStateCommandResultHash => "GetStateCommandResultHash",
            DPNOpType::GetStateCommandResultSingle => "GetStateCommandResultSingle",
            DPNOpType::GetStateCommandResultArray => "GetStateCommandResultArray",
            DPNOpType::UnaryInverse => "UnaryInverse",
            DPNOpType::UnaryNegative => "UnaryNegative",
            DPNOpType::U32InputTarget => "U32InputTarget",
            DPNOpType::ConstantU32 => "ConstantU32",
            DPNOpType::U32Add => "U32Add",
            DPNOpType::U32Sub => "U32Sub",
            DPNOpType::U32Mul => "U32Mul",
            DPNOpType::U32Div => "U32Div",
            DPNOpType::CastFelt => "CastFelt",
            DPNOpType::CastBool => "CastBool",
            DPNOpType::BoolInputTarget => "BoolInputTarget",
            DPNOpType::U32Mod => "U32Mod",
            DPNOpType::U32Exp => "U32Exp",
            DPNOpType::Secp256k1Verify => "Secp256k1Verify",
            DPNOpType::HashTwoToOne => "HashTwoToOne",
            DPNOpType::Keccak256 => "Keccak256",
        };
        write!(f, "DPNOpType::{}", r)
    }
}

#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, TS)]
#[repr(u8)]
pub enum DPNBuiltInDataType {
    Target = 0,
    Bool = 1,
    U32Target = 2,
    HashOut = 3,
    HashOut160 = 4,
    TargetArray = 5,
    BoolArray = 6,
    U32TargetArray = 7,
    Unknown = 63,
}

impl std::fmt::Display for DPNBuiltInDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match &self {
            DPNBuiltInDataType::Target => "Target",
            DPNBuiltInDataType::Bool => "Bool",
            DPNBuiltInDataType::HashOut => "HashOut",
            DPNBuiltInDataType::HashOut160 => "HashOut160",
            DPNBuiltInDataType::TargetArray => "TargetArray",
            DPNBuiltInDataType::BoolArray => "BoolArray",
            DPNBuiltInDataType::Unknown => "Unknown",
            DPNBuiltInDataType::U32Target => "U32Target",
            DPNBuiltInDataType::U32TargetArray => "U32TargetArray",
        };
        write!(f, "DPNBuiltInDataType::{}", r)
    }
}

impl From<u64> for DPNBuiltInDataType {
    fn from(x: u64) -> Self {
        match x {
            0 => Self::Target,
            1 => Self::Bool,
            2 => Self::U32Target,
            3 => Self::HashOut,
            4 => Self::HashOut160,
            5 => Self::TargetArray,
            6 => Self::BoolArray,
            7 => Self::U32TargetArray,
            _ => Self::Unknown,
        }
    }
}
impl From<u32> for DPNBuiltInDataType {
    fn from(x: u32) -> Self {
        DPNBuiltInDataType::from(x as u64)
    }
}
impl From<u16> for DPNBuiltInDataType {
    fn from(x: u16) -> Self {
        DPNBuiltInDataType::from(x as u64)
    }
}
impl From<u8> for DPNBuiltInDataType {
    fn from(x: u8) -> Self {
        DPNBuiltInDataType::from(x as u64)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, TS)]
pub struct DPNIndexedVarDef {
    pub data_type: DPNBuiltInDataType,
    pub index: usize,
    pub op_type: DPNOpType,
    pub inputs: Vec<u64>,
}
impl DPNIndexedVarDef {
    pub fn get_combined_data_type_index(&self) -> u64 {
        encode_indexed_op_id(self.data_type, self.index)
    }
}

use crate::dpn::ops::context_trait::{ContextFelt, ToFelts};

impl<F: ContextFelt> ToFelts<F> for DPNIndexedVarDef {
    fn to_felts(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(4 + self.inputs.len());
        out.push(F::cns(self.data_type as u8 as u64));
        out.push(F::cns(self.index as u64));
        out.push(F::cns(self.op_type.get_enc_value() as u64));
        out.push(F::cns(self.inputs.len() as u64));
        for value in &self.inputs {
            out.push(F::cns(*value));
        }
        out
    }

    fn from_felts(felts: &[F]) -> Self {
        if felts.len() < 4 {
            panic!("DPNIndexedVarDef expects at least 4 felts, got {}", felts.len());
        }
        let mut idx = 0usize;
        let take = |felts: &[F], idx: &mut usize| {
            if *idx >= felts.len() {
                panic!("DPNIndexedVarDef decoding overflow");
            }
            let v = felts[*idx].get_u64();
            *idx += 1;
            v
        };
        let data_type = DPNBuiltInDataType::from(take(felts, &mut idx) as u8);
        let index = take(felts, &mut idx) as usize;
        let op_type = DPNOpType::from(take(felts, &mut idx) as u16);
        let inputs_len = take(felts, &mut idx) as usize;
        if felts.len() < idx + inputs_len {
            panic!(
                "DPNIndexedVarDef inputs length mismatch: expected {}, remaining {}",
                inputs_len,
                felts.len().saturating_sub(idx)
            );
        }
        let mut inputs = Vec::with_capacity(inputs_len);
        for _ in 0..inputs_len {
            inputs.push(take(felts, &mut idx));
        }
        DPNIndexedVarDef {
            data_type,
            index,
            op_type,
            inputs,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, TS)]
pub struct DPNAssertEqInfoIndexed {
    pub left: u64,
    pub right: u64,
    pub message: String,
}

impl<F: ContextFelt> ToFelts<F> for DPNAssertEqInfoIndexed {
    fn to_felts(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(3 + self.message.len());
        out.push(F::cns(self.left));
        out.push(F::cns(self.right));
        out.push(F::cns(self.message.as_bytes().len() as u64));
        for b in self.message.as_bytes() {
            out.push(F::cns(*b as u64));
        }
        out
    }

    fn from_felts(felts: &[F]) -> Self {
        if felts.len() < 3 {
            panic!("DPNAssertEqInfoIndexed expects at least 3 felts");
        }
        let left = felts[0].get_u64();
        let right = felts[1].get_u64();
        let msg_len = felts[2].get_u64() as usize;
        if felts.len() != 3 + msg_len {
            panic!(
                "DPNAssertEqInfoIndexed message length mismatch: expected {}, got {}",
                msg_len,
                felts.len().saturating_sub(3)
            );
        }
        let mut bytes = Vec::with_capacity(msg_len);
        for felt in &felts[3..] {
            bytes.push(felt.get_u64() as u8);
        }
        let message = String::from_utf8(bytes).expect("invalid utf8 in DPNAssertEqInfoIndexed");
        DPNAssertEqInfoIndexed { left, right, message }
    }
}

fn default_event_condition_true() -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Bool, 0)
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, TS)]
pub struct DPNEventRecord {
    // event_name: String,
    #[serde(default = "default_event_condition_true")]
    pub condition: u64,
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub data: Vec<u64>,
}

#[cfg(test)]
mod event_record_tests {
    use super::*;

    #[test]
    fn legacy_event_record_defaults_condition_to_true() {
        let event: DPNEventRecord = serde_json::from_str(r#"{"checkpoint_id":10,"user_id":11,"contract_id":12,"data":[1,2]}"#).unwrap();

        assert_eq!(event.condition, encode_indexed_op_id(DPNBuiltInDataType::Bool, 0));
    }
}

impl<F: ContextFelt> ToFelts<F> for DPNEventRecord {
    fn to_felts(&self) -> Vec<F> {
        let mut out = Vec::with_capacity(5 + self.data.len());
        out.push(F::cns(self.condition));
        out.push(F::cns(self.checkpoint_id));
        out.push(F::cns(self.user_id));
        out.push(F::cns(self.contract_id));
        for b in &self.data {
            out.push(F::cns(*b));
        }
        out
    }

    fn from_felts(felts: &[F]) -> Self {
        if felts.len() < 4 {
            panic!("DPNEventRecord expects at least 4 felts");
        }
        let condition = felts[0].get_u64();
        let checkpoint_id = felts[1].get_u64();
        let user_id = felts[2].get_u64();
        let contract_id = felts[3].get_u64();
        let data_len = felts.len().saturating_sub(4);
        if felts.len() != 4 + data_len {
            panic!(
                "DPNEventRecord data length mismatch: expected {}, got {}",
                data_len,
                felts.len().saturating_sub(4)
            );
        }
        let mut data = Vec::with_capacity(data_len);
        for felt in &felts[4..] {
            data.push(felt.get_u64());
        }
        DPNEventRecord {
            condition,
            checkpoint_id,
            user_id,
            contract_id,
            data,
        }
    }
}
