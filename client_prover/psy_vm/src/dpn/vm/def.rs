use serde::{Deserialize, Serialize};
use ts_rs::TS;

use crate::dpn::ops::{
    op_types::{DPNAssertEqInfoIndexed, DPNEventRecord, DPNIndexedVarDef},
    state_cmd::{data::DPNStateCmd, types::DPNStateCmdCore},
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
        self.events.is_empty() && self.state_commands.iter().all(|cmd| cmd.is_read_only())
    }
}

/// Derive the contract state tree height from the compiled function
/// definitions.
///
/// The compiler already packs contract state into 4-felt leaves, so
/// `sub_slot_index` values are leaf indices. The height is the smallest power
/// of two that can cover the maximum leaf index used by any state command.
/// A minimum of 4 is enforced to match the current compiler/VM conventions.
pub fn derive_state_tree_height(defs: &[DPNFunctionCircuitDefinition]) -> u8 {
    let mut max_slot = None::<u64>;

    for def in defs {
        for cmd in &def.state_commands {
            let slot = match cmd {
                DPNStateCmd::SetContractStateSlotHash(c) => Some(c.slot_index),
                DPNStateCmd::SetContractStateSlotSingle(c) => Some(c.sub_slot_index),
                DPNStateCmd::SetContractStateSlotRange(c) => Some(c.sub_slot_index.saturating_add(c.value.len().saturating_sub(1) as u64)),
                DPNStateCmd::SetIMTContractStateValue(c) => {
                    let span = c.capacity.saturating_mul(4);
                    Some(c.base_offset.saturating_add(span.saturating_sub(1)))
                }
                _ => None,
            };
            if let Some(slot) = slot {
                max_slot = Some(max_slot.map_or(slot, |current| current.max(slot)));
            }
        }
    }

    let computed = match max_slot {
        Some(max_slot) => ceil_log2(max_slot.saturating_add(1)),
        None => 0,
    };

    computed.max(4)
}

fn ceil_log2(value: u64) -> u8 {
    if value <= 1 {
        return 0;
    }
    (u64::BITS - (value - 1).leading_zeros()) as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    fn definition(state_commands: Vec<DPNStateCmd<u64>>) -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "test".to_string(),
            method_id: 1,
            circuit_inputs: Vec::new(),
            circuit_outputs: Vec::new(),
            state_commands,
            state_command_resolution_indices: Vec::new(),
            assertions: Vec::new(),
            definitions: Vec::new(),
            events: Vec::new(),
        }
    }

    #[test]
    fn view_detection_accepts_reads_and_rejects_all_write_command_kinds() {
        use crate::dpn::ops::state_cmd::data::DPNStateCmdClearEntireTree;

        assert!(definition(vec![DPNStateCmd::get_self_user_current_contract_state_slot_single(0)]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::set_contract_state_slot_hash(1, 0, [1; 4])]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::set_contract_state_slot_single(1, 0, 1)]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::set_contract_state_slot_range(1, 0, vec![1])]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::ClearEntireTree(DPNStateCmdClearEntireTree { condition: 1 })]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::set_imt_contract_state_value(1, 0, 4, [0; 4], [1; 4])]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::invoke_external_contract_function(1, 2, 3, Vec::new(), 0)]).is_view_function());
        assert!(!definition(vec![DPNStateCmd::invoke_external_contract_function_deferred(1, 2, 3, Vec::new())]).is_view_function());
    }

    #[test]
    fn view_detection_rejects_event_only_definitions() {
        let mut event_only = definition(Vec::new());
        event_only.events.push(DPNEventRecord {
            condition: 0,
            checkpoint_id: 0,
            user_id: 0,
            contract_id: 0,
            data: Vec::new(),
        });
        assert!(!event_only.is_view_function());
    }
}
