use serde_repr::{Deserialize_repr, Serialize_repr};

use crate::dpn::ops::op_types::DPNBuiltInDataType;

#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
#[repr(u8)]
pub enum DPNStateCommandType {
    // set state commands (0-7)
    SetContractStateSlotHash = 0,
    SetContractStateSlotSingle = 1,
    SetContractStateSlotRange = 2,
    ClearEntireTree = 3,

    // external contract call commands (8-15)
    InvokeExternalContractFunctionSync = 8,
    InvokeExternalContractFunctionDeferred = 9,

    // the get state commands below are sensitive to order relative to set state commands and external calls (16-23)
    GetSelfUserCurrentContractStateSlotHash = 16,
    GetSelfUserCurrentContractStateSlotSingle = 17,
    GetSelfUserCurrentContractStateSlotRange = 18,

    // the state commands below are sensitive to order relative to external calls only (24-31)
    GetSelfUserExternalContractStateSlotHash = 24,
    GetSelfUserExternalContractStateSlotSingle = 25,
    GetSelfUserExternalContractStateSlotRange = 26,

    // other get state commands are not order sensitive (32-39)
    GetOtherUserContractStateSlotHash = 32,
    GetOtherUserContractStateSlotSingle = 33,
    GetOtherUserContractStateSlotRange = 34,

    // checkpoint state commands (not order sensitive) (40-47)
    GetCheckpointLeafStats = 40,
    GetContractLeaf = 41,
    GetGlobalStateRoots = 42,

    // IMT key-based state commands (48-63)
    // set IMT state by 256-bit key
    SetIMTContractStateValue = 48,

    // get IMT state by 256-bit key (self user, current contract)
    GetSelfUserCurrentIMTContractStateValue = 56,
    // get IMT state by 256-bit key (self user, external contract)
    GetSelfUserExternalIMTContractStateValue = 57,
    // get IMT state by 256-bit key (other user)
    GetOtherUserIMTContractStateValue = 58,
    // contains IMT key by 256-bit key (self user, current contract)
    ContainsSelfUserCurrentIMTContractStateValue = 59,
    // contains IMT key by 256-bit key (other user, external contract)
    ContainsOtherUserIMTContractStateValue = 60,
}

impl From<u8> for DPNStateCommandType {
    fn from(value: u8) -> Self {
        match value {
            0 => DPNStateCommandType::SetContractStateSlotHash,
            1 => DPNStateCommandType::SetContractStateSlotSingle,
            2 => DPNStateCommandType::SetContractStateSlotRange,
            3 => DPNStateCommandType::ClearEntireTree,

            8 => DPNStateCommandType::InvokeExternalContractFunctionSync,
            9 => DPNStateCommandType::InvokeExternalContractFunctionDeferred,

            16 => DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash,
            17 => DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle,
            18 => DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange,

            24 => DPNStateCommandType::GetSelfUserExternalContractStateSlotHash,
            25 => DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle,
            26 => DPNStateCommandType::GetSelfUserExternalContractStateSlotRange,

            32 => DPNStateCommandType::GetOtherUserContractStateSlotHash,
            33 => DPNStateCommandType::GetOtherUserContractStateSlotSingle,
            34 => DPNStateCommandType::GetOtherUserContractStateSlotRange,

            40 => DPNStateCommandType::GetCheckpointLeafStats,
            41 => DPNStateCommandType::GetContractLeaf,
            42 => DPNStateCommandType::GetGlobalStateRoots,

            48 => DPNStateCommandType::SetIMTContractStateValue,
            56 => DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue,
            57 => DPNStateCommandType::GetSelfUserExternalIMTContractStateValue,
            58 => DPNStateCommandType::GetOtherUserIMTContractStateValue,
            59 => DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue,
            60 => DPNStateCommandType::ContainsOtherUserIMTContractStateValue,
            _ => panic!("Unknown DPNStateCommandType: {}", value),
        }
    }
}

impl DPNStateCommandType {
    pub fn get_enc_value(&self) -> u8 {
        *self as u8
    }
    pub fn get_data_type(&self) -> DPNBuiltInDataType {
        match self {
            DPNStateCommandType::SetContractStateSlotHash => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::SetContractStateSlotSingle => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::SetContractStateSlotRange => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::ClearEntireTree => DPNBuiltInDataType::TargetArray,

            DPNStateCommandType::InvokeExternalContractFunctionSync => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::InvokeExternalContractFunctionDeferred => DPNBuiltInDataType::TargetArray,

            DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle => DPNBuiltInDataType::Target,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange => DPNBuiltInDataType::TargetArray,

            DPNStateCommandType::GetSelfUserExternalContractStateSlotHash => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle => DPNBuiltInDataType::Target,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotRange => DPNBuiltInDataType::TargetArray,

            DPNStateCommandType::GetOtherUserContractStateSlotHash => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::GetOtherUserContractStateSlotSingle => DPNBuiltInDataType::Target,
            DPNStateCommandType::GetOtherUserContractStateSlotRange => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::GetCheckpointLeafStats => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::GetContractLeaf => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::GetGlobalStateRoots => DPNBuiltInDataType::TargetArray,

            DPNStateCommandType::SetIMTContractStateValue => DPNBuiltInDataType::TargetArray,
            DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::GetSelfUserExternalIMTContractStateValue => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::GetOtherUserIMTContractStateValue => DPNBuiltInDataType::HashOut,
            DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue => DPNBuiltInDataType::Target,
            DPNStateCommandType::ContainsOtherUserIMTContractStateValue => DPNBuiltInDataType::Target,
        }
    }
    pub fn is_read_only(&self) -> bool {
        match self {
            DPNStateCommandType::SetContractStateSlotHash => false,
            DPNStateCommandType::SetContractStateSlotSingle => false,
            DPNStateCommandType::SetContractStateSlotRange => false,
            DPNStateCommandType::ClearEntireTree => false,
            DPNStateCommandType::InvokeExternalContractFunctionSync => false,
            DPNStateCommandType::InvokeExternalContractFunctionDeferred => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotHash => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotRange => true,
            DPNStateCommandType::GetOtherUserContractStateSlotHash => true,
            DPNStateCommandType::GetOtherUserContractStateSlotSingle => true,
            DPNStateCommandType::GetOtherUserContractStateSlotRange => true,
            DPNStateCommandType::GetCheckpointLeafStats => true,
            DPNStateCommandType::GetContractLeaf => true,
            DPNStateCommandType::GetGlobalStateRoots => true,

            DPNStateCommandType::SetIMTContractStateValue => false,
            DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::GetSelfUserExternalIMTContractStateValue => true,
            DPNStateCommandType::GetOtherUserIMTContractStateValue => true,
            DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::ContainsOtherUserIMTContractStateValue => true,
        }
    }
    pub fn updates_state(&self) -> bool {
        !self.is_read_only()
    }
    pub fn is_external_call_order_sensitive(&self) -> bool {
        match self {
            DPNStateCommandType::SetContractStateSlotHash => true,
            DPNStateCommandType::SetContractStateSlotSingle => true,
            DPNStateCommandType::SetContractStateSlotRange => true,
            DPNStateCommandType::ClearEntireTree => true,
            DPNStateCommandType::InvokeExternalContractFunctionSync => true,
            DPNStateCommandType::InvokeExternalContractFunctionDeferred => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotHash => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle => true,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotRange => true,

            DPNStateCommandType::GetOtherUserContractStateSlotHash => false,
            DPNStateCommandType::GetOtherUserContractStateSlotSingle => false,
            DPNStateCommandType::GetOtherUserContractStateSlotRange => false,
            DPNStateCommandType::GetCheckpointLeafStats => false,
            DPNStateCommandType::GetContractLeaf => false,
            DPNStateCommandType::GetGlobalStateRoots => false,

            DPNStateCommandType::SetIMTContractStateValue => true,
            DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::GetSelfUserExternalIMTContractStateValue => true,
            DPNStateCommandType::GetOtherUserIMTContractStateValue => false,
            DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::ContainsOtherUserIMTContractStateValue => false,
        }
    }
    pub fn is_set_state_order_sensitive(&self) -> bool {
        match self {
            DPNStateCommandType::SetContractStateSlotHash => true,
            DPNStateCommandType::SetContractStateSlotSingle => true,
            DPNStateCommandType::SetContractStateSlotRange => true,
            DPNStateCommandType::ClearEntireTree => true,
            DPNStateCommandType::InvokeExternalContractFunctionSync => true,
            DPNStateCommandType::InvokeExternalContractFunctionDeferred => false,

            DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle => true,
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange => true,

            DPNStateCommandType::GetSelfUserExternalContractStateSlotHash => false,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle => false,
            DPNStateCommandType::GetSelfUserExternalContractStateSlotRange => false,
            DPNStateCommandType::GetOtherUserContractStateSlotHash => false,
            DPNStateCommandType::GetOtherUserContractStateSlotSingle => false,
            DPNStateCommandType::GetOtherUserContractStateSlotRange => false,
            DPNStateCommandType::GetCheckpointLeafStats => false,
            DPNStateCommandType::GetContractLeaf => false,
            DPNStateCommandType::GetGlobalStateRoots => false,

            DPNStateCommandType::SetIMTContractStateValue => true,
            DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::GetSelfUserExternalIMTContractStateValue => false,
            DPNStateCommandType::GetOtherUserIMTContractStateValue => false,
            DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue => true,
            DPNStateCommandType::ContainsOtherUserIMTContractStateValue => false,
        }
    }
    pub fn is_inline_external_call_cmd(&self) -> bool {
        match self {
            DPNStateCommandType::InvokeExternalContractFunctionSync => true,
            _ => false,
        }
    }
    pub fn is_set_state_cmd(&self) -> bool {
        match self {
            DPNStateCommandType::SetContractStateSlotHash => true,
            DPNStateCommandType::SetContractStateSlotSingle => true,
            DPNStateCommandType::SetContractStateSlotRange => true,
            DPNStateCommandType::ClearEntireTree => true,
            DPNStateCommandType::SetIMTContractStateValue => true,
            _ => false,
        }
    }
    pub fn is_imt_set_state_cmd(&self) -> bool {
        matches!(self, DPNStateCommandType::SetIMTContractStateValue)
    }
}

impl std::fmt::Display for DPNStateCommandType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let r = match &self {
            DPNStateCommandType::SetContractStateSlotHash => "SetContractStateSlotHash",
            DPNStateCommandType::SetContractStateSlotSingle => "SetContractStateSlotSingle",
            DPNStateCommandType::SetContractStateSlotRange => "SetContractStateSlotRange",
            DPNStateCommandType::ClearEntireTree => "ClearEntireTree",
            DPNStateCommandType::InvokeExternalContractFunctionSync => "InvokeExternalContractFunctionSync",
            DPNStateCommandType::InvokeExternalContractFunctionDeferred => "InvokeExternalContractFunctionDeferred",

            DPNStateCommandType::GetSelfUserCurrentContractStateSlotHash => "GetSelfUserCurrentContractStateSlotHash",
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotSingle => "GetSelfUserCurrentContractStateSlotSingle",
            DPNStateCommandType::GetSelfUserCurrentContractStateSlotRange => "GetSelfUserCurrentContractStateSlotRange",
            DPNStateCommandType::GetSelfUserExternalContractStateSlotHash => "GetSelfUserExternalContractStateSlotHash",
            DPNStateCommandType::GetSelfUserExternalContractStateSlotSingle => "GetSelfUserExternalContractStateSlotSingle",
            DPNStateCommandType::GetSelfUserExternalContractStateSlotRange => "GetSelfUserExternalContractStateSlotRange",
            DPNStateCommandType::GetOtherUserContractStateSlotHash => "GetOtherUserContractStateSlotHash",
            DPNStateCommandType::GetOtherUserContractStateSlotSingle => "GetOtherUserContractStateSlotSingle",
            DPNStateCommandType::GetOtherUserContractStateSlotRange => "GetOtherUserContractStateSlotRange",
            DPNStateCommandType::GetCheckpointLeafStats => "GetCheckpointLeafStats",
            DPNStateCommandType::GetContractLeaf => "GetContractLeaf",
            DPNStateCommandType::GetGlobalStateRoots => "GetGlobalStateRoots",

            DPNStateCommandType::SetIMTContractStateValue => "SetIMTContractStateValue",
            DPNStateCommandType::GetSelfUserCurrentIMTContractStateValue => "GetSelfUserCurrentIMTContractStateValue",
            DPNStateCommandType::GetSelfUserExternalIMTContractStateValue => "GetSelfUserExternalIMTContractStateValue",
            DPNStateCommandType::GetOtherUserIMTContractStateValue => "GetOtherUserIMTContractStateValue",
            DPNStateCommandType::ContainsSelfUserCurrentIMTContractStateValue => "ContainsSelfUserCurrentIMTContractStateValue",
            DPNStateCommandType::ContainsOtherUserIMTContractStateValue => "ContainsOtherUserIMTContractStateValue",
        };
        write!(f, "DPNStateCommandType::{}", r)
    }
}

pub trait DPNStateCmdCore<T>: Eq + PartialEq + Clone + std::hash::Hash + Ord + PartialOrd {
    fn get_inputs(&self) -> Vec<T>;
    fn get_state_command_type(&self) -> DPNStateCommandType;
    fn is_read_only(&self) -> bool {
        self.get_state_command_type().is_read_only()
    }
    fn is_external_call_order_sensitive(&self) -> bool {
        self.get_state_command_type().is_external_call_order_sensitive()
    }
    fn is_set_state_order_sensitive(&self) -> bool {
        self.get_state_command_type().is_set_state_order_sensitive()
    }
    fn is_set_state_cmd(&self) -> bool {
        self.get_state_command_type().is_set_state_cmd()
    }
    fn is_inline_external_call_cmd(&self) -> bool {
        self.get_state_command_type().is_inline_external_call_cmd()
    }
    fn get_hint_result_type(&self) -> DPNBuiltInDataType {
        self.get_state_command_type().get_data_type()
    }
    fn get_output_felt_size(&self) -> usize;
}
