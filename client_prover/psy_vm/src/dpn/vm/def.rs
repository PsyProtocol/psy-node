use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::dpn::ops::{
    op_types::{DPNAssertEqInfoIndexed, DPNEventRecord, DPNIndexedVarDef},
    state_cmd::data::DPNStateCmd,
};

/*
const INDEX_BITS: u64 = 32;
const INDEX_MASK: u64 = (1u64<<INDEX_BITS)-1u64;

pub fn decode_indexed_op_id(id: u64)->(DPNBuiltInDataType, usize){
  (DPNBuiltInDataType::from(id>>INDEX_BITS), (id&INDEX_MASK) as usize)
}
pub fn encode_indexed_op_id(data_type: DPNBuiltInDataType, index: usize)->u64{
  ((data_type as u64)<<INDEX_BITS)|(index as u64)
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DPNIndexedVarDef {
  pub data_type: DPNBuiltInDataType,
  pub index: usize,
  pub op_type: DPNOpType,
  pub inputs: Vec<u64>,
}
impl DPNIndexedVarDef {
  pub fn get_combined_data_type_index(&self)->u64{
    encode_indexed_op_id(self.data_type, self.index)
  }
}

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct DPNAssertEqInfoIndexed {
  pub left: u64,
  pub right: u64,
  pub message: String,
}
*/

#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq, TS)]
pub struct DPNFunctionCircuitDefinition {
    pub name: String,
    pub method_id: u32,
    pub circuit_inputs: Vec<u64>,
    pub circuit_outputs: Vec<u64>,
    pub state_commands: Vec<DPNStateCmd<u64>>,
    pub state_command_resolution_indices: Vec<usize>,
    pub assertions: Vec<DPNAssertEqInfoIndexed>,
    pub definitions: Vec<DPNIndexedVarDef>,
    #[serde(default)]
    pub events: Vec<DPNEventRecord>,
}

impl DPNFunctionCircuitDefinition {
    pub fn is_view_function(&self) -> bool {
        !self.state_commands.iter().any(|cmd| {
            matches!(
                cmd,
                DPNStateCmd::SetContractStateSlotHash(_)
                    | DPNStateCmd::SetContractStateSlotSingle(_)
                    | DPNStateCmd::SetContractStateSlotRange(_)
                    | DPNStateCmd::ClearEntireTree(_)
                    | DPNStateCmd::InvokeExternalContractFunctionSync(_)
                    | DPNStateCmd::InvokeExternalContractFunctionDeferred(_)
            )
        })
    }
}
