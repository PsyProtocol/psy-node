use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum UPSCommonDataTypes {
    Unknown = 0,
    TypeA = 1,
    TypeB = 2,
}
impl UPSCommonDataTypes {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
}
impl TryFrom<u8> for UPSCommonDataTypes {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UPSCommonDataTypes::Unknown),
            1 => Ok(UPSCommonDataTypes::TypeA),
            2 => Ok(UPSCommonDataTypes::TypeB),
            _ => Err(anyhow::format_err!("Invalid UPSCircuitType value: {}", value)),
        }
    }
}
impl From<UPSCommonDataTypes> for u8 {
    fn from(value: UPSCommonDataTypes) -> u8 {
        value as u8
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum UPSCircuitType {
    Start = 0,
    CFCStandard = 1,
    CFCDeferred = 2,
    StartRegisterUser = 3,
}
impl UPSCircuitType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn get_lct(&self) -> LocalCircuitType {
        match self {
            UPSCircuitType::Start => LocalCircuitType::UPSStart,
            UPSCircuitType::CFCStandard => LocalCircuitType::UPSCFCStandard,
            UPSCircuitType::CFCDeferred => LocalCircuitType::UPSCFCDeferred,
            UPSCircuitType::StartRegisterUser => LocalCircuitType::UPSStartRegisterUser,
        }
    }
}
impl TryFrom<u8> for UPSCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(UPSCircuitType::Start),
            1 => Ok(UPSCircuitType::CFCStandard),
            2 => Ok(UPSCircuitType::CFCDeferred),
            3 => Ok(UPSCircuitType::StartRegisterUser),
            _ => Err(anyhow::format_err!("Invalid UPSCircuitType value: {}", value)),
        }
    }
}
impl From<UPSCircuitType> for u8 {
    fn from(value: UPSCircuitType) -> u8 {
        value as u8
    }
}

#[derive(Serialize_repr, Deserialize_repr, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum LocalCircuitType {
    // UPS Step Circuits (0-31 reserved)
    UPSStart = 0,
    UPSCFCStandard = 1,
    UPSCFCDeferred = 2,
    UPSStartRegisterUser = 3,
    // ...
    UPSEndCap = 31,

    // Proof Tree Agg Helpers (32-47 reserved)
    PTAggSingle = 33,
    PTAggTwoLeaf = 34,
    PTAggTwoAgg = 35,
    PTAggLeftAggRightLeaf = 36,
    PTAggLeftLeafRightAgg = 37,

    // Common Signature Circuits (48-63 reserved)
    SimpleZKSignature = 48,
    SimpleSecp256K1 = 49,

    // GUTA Circuits
    GUTATwoEndCap = 65,
    GUTATwoGUTA = 66,
    GUTALeftEndCapRightGUTA = 67,
    GUTALeftGUTARightEndCap = 68,
    GUTASingleEndCap = 69,

    // Circuit Templates with Custom Variants (192-254)
    ContractFunctionCircuit = 192,

    // Unknown = 0xff
    Unknown = 255,
}
impl Default for LocalCircuitType {
    fn default() -> Self {
        Self::Unknown
    }
}
impl LocalCircuitType {
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }
    pub fn is_ups_step(&self) -> bool {
        self.to_u8() <= 31
    }
    pub fn is_proof_tree_aggregator(&self) -> bool {
        let v = self.to_u8();
        v >= 32 && v <= 47
    }
    pub fn is_contract_function_circuit(&self) -> bool {
        *self == LocalCircuitType::ContractFunctionCircuit
    }
    pub fn has_custom_variant(&self) -> bool {
        (*self as u8) >= 192
    }
}
impl From<LocalCircuitType> for u8 {
    fn from(value: LocalCircuitType) -> u8 {
        value as u8
    }
}
impl TryFrom<u8> for LocalCircuitType {
    type Error = anyhow::Error;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LocalCircuitType::UPSStart),
            1 => Ok(LocalCircuitType::UPSCFCStandard),
            2 => Ok(LocalCircuitType::UPSCFCDeferred),
            3 => Ok(LocalCircuitType::UPSStartRegisterUser),
            31 => Ok(LocalCircuitType::UPSEndCap),
            33 => Ok(LocalCircuitType::PTAggSingle),
            34 => Ok(LocalCircuitType::PTAggTwoLeaf),
            35 => Ok(LocalCircuitType::PTAggTwoAgg),
            36 => Ok(LocalCircuitType::PTAggLeftAggRightLeaf),
            37 => Ok(LocalCircuitType::PTAggLeftLeafRightAgg),
            48 => Ok(LocalCircuitType::SimpleZKSignature),
            49 => Ok(LocalCircuitType::SimpleSecp256K1),

            65 => Ok(LocalCircuitType::GUTATwoEndCap),
            66 => Ok(LocalCircuitType::GUTATwoGUTA),
            67 => Ok(LocalCircuitType::GUTALeftEndCapRightGUTA),
            68 => Ok(LocalCircuitType::GUTALeftGUTARightEndCap),
            69 => Ok(LocalCircuitType::GUTASingleEndCap),

            192 => Ok(LocalCircuitType::ContractFunctionCircuit),
            _ => Err(anyhow::format_err!("Invalid LocalCircuitType value: {}", value)),
        }
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord, Default)]
pub struct LocalCircuitId {
    pub circuit_type: LocalCircuitType,
    pub variant: u64,
}

impl LocalCircuitId {
    pub fn new(circuit_type: LocalCircuitType) -> Self {
        Self {
            circuit_type: circuit_type,
            variant: 0,
        }
    }
    pub fn new_with_variant(circuit_type: LocalCircuitType, variant: u64) -> Self {
        Self {
            circuit_type: circuit_type,
            variant: variant,
        }
    }
    pub fn is_type(&self, circuit_type: LocalCircuitType) -> bool {
        self.circuit_type == circuit_type
    }
    pub fn new_cfc(contract_id: u32, method_id: u32) -> Self {
        ContractFunctionCircuitId::new(contract_id, method_id).get_circuit_id()
    }
}

impl From<LocalCircuitId> for LocalCircuitType {
    fn from(value: LocalCircuitId) -> Self {
        value.circuit_type
    }
}
impl From<&LocalCircuitId> for LocalCircuitType {
    fn from(value: &LocalCircuitId) -> Self {
        value.circuit_type
    }
}

impl From<LocalCircuitType> for LocalCircuitId {
    fn from(value: LocalCircuitType) -> Self {
        Self {
            circuit_type: value,
            variant: 0,
        }
    }
}
impl From<&LocalCircuitType> for LocalCircuitId {
    fn from(value: &LocalCircuitType) -> Self {
        Self {
            circuit_type: *value,
            variant: 0,
        }
    }
}
/*
impl PartialEq<LocalCircuitType> for LocalCircuitId {
    fn eq(&self, other: &LocalCircuitType) -> bool {
        self.circuit_type.eq(other) && !self.circuit_type.has_custom_variant()
    }
}*/

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Copy, Eq, Hash, PartialOrd, Ord)]
pub struct ContractFunctionCircuitId {
    pub contract_id: u32,
    pub method_id: u32,
}

impl ContractFunctionCircuitId {
    pub fn new(contract_id: u32, method_id: u32) -> Self {
        Self { contract_id, method_id }
    }
    pub fn get_circuit_id(&self) -> LocalCircuitId {
        LocalCircuitId {
            circuit_type: LocalCircuitType::ContractFunctionCircuit,
            variant: ((self.contract_id as u64) << 32u64) | (self.method_id as u64),
        }
    }
}
