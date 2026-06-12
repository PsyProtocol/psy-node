use plonky2::{field::types::PrimeField64, hash::hash_types::RichField};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::qdata::contract::ContractFunctionCodeDefinition;
use psy_config::network_constants::VM_TYPE_STANRDARD_DAPEN_V1;
use psy_crypto::hash::{traits::hasher::PoseidonHasher, utils::safe_hash_fixed_length};
use serde_cbor::Value;

use crate::dpn::{
    ops::{
        op_types::{DPNAssertEqInfoIndexed, DPNEventRecord, DPNIndexedVarDef},
        state_cmd::{data::DPNStateCmd, types::DPNStateCmdCore},
    },
    vm::def::DPNFunctionCircuitDefinition,
};

pub fn dapen_fc_to_cfc_code_definition(dpn_fc_def: &DPNFunctionCircuitDefinition) -> ContractFunctionCodeDefinition {
    ContractFunctionCodeDefinition {
        method_id: dpn_fc_def.method_id,
        num_inputs: dpn_fc_def.circuit_inputs.len() as u32,
        num_outputs: dpn_fc_def.circuit_outputs.len() as u32,
        vm_type: VM_TYPE_STANRDARD_DAPEN_V1,
        code: serde_cbor::to_vec(dpn_fc_def).unwrap(),
    }
}

fn encode_vec(buffer: &mut Vec<u64>, values: &[u64]) {
    buffer.push(values.len() as u64);
    buffer.extend(values.iter());
}

fn encode_state_cmd(buffer: &mut Vec<u64>, cmd: &DPNStateCmd<u64>) {
    use crate::dpn::ops::state_cmd::data::*;
    buffer.push(cmd.get_state_command_type().get_enc_value() as u64);
    match cmd {
        DPNStateCmd::SetContractStateSlotHash(c) => {
            buffer.push(c.condition);
            buffer.push(c.slot_index);
            buffer.extend(c.value.iter());
        }
        DPNStateCmd::SetContractStateSlotSingle(c) => {
            buffer.push(c.condition);
            buffer.push(c.sub_slot_index);
            buffer.push(c.value);
        }
        DPNStateCmd::SetContractStateSlotRange(c) => {
            buffer.push(c.condition);
            buffer.push(c.sub_slot_index);
            buffer.push(c.value.len() as u64);
            buffer.extend(c.value.iter());
        }
        DPNStateCmd::ClearEntireTree(c) => {
            buffer.push(c.condition);
        }
        DPNStateCmd::InvokeExternalContractFunctionSync(c) => {
            buffer.push(c.condition);
            buffer.push(c.contract_id);
            buffer.push(c.method_id);
            buffer.push(c.input_args.len() as u64);
            buffer.extend(c.input_args.iter());
            buffer.push(c.num_outputs as u64);
        }
        DPNStateCmd::InvokeExternalContractFunctionDeferred(c) => {
            buffer.push(c.condition);
            buffer.push(c.contract_id);
            buffer.push(c.method_id);
            buffer.push(c.input_args.len() as u64);
            buffer.extend(c.input_args.iter());
        }
        DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
            buffer.push(c.slot_index);
        }
        DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
            buffer.push(c.sub_slot_index);
        }
        DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
            buffer.push(c.sub_slot_index);
            buffer.push(c.length as u64);
        }
        DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
            buffer.push(c.contract_id);
            buffer.push(c.slot_index);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
            buffer.push(c.contract_id);
            buffer.push(c.sub_slot_index);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => {
            buffer.push(c.contract_id);
            buffer.push(c.sub_slot_index);
            buffer.push(c.length as u64);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetOtherUserContractStateSlotHash(c) => {
            buffer.push(c.user_id);
            buffer.push(c.contract_id);
            buffer.push(c.slot_index);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
            buffer.push(c.user_id);
            buffer.push(c.contract_id);
            buffer.push(c.sub_slot_index);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetOtherUserContractStateSlotRange(c) => {
            buffer.push(c.user_id);
            buffer.push(c.contract_id);
            buffer.push(c.sub_slot_index);
            buffer.push(c.length as u64);
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetCheckpointLeafStats(c) => {
            buffer.push(c.checkpoint_id);
        }
        DPNStateCmd::GetContractLeaf(c) => {
            buffer.push(c.contract_id);
        }
        DPNStateCmd::GetGlobalStateRoots(c) => {
            buffer.push(c.checkpoint_id);
        }
        DPNStateCmd::SetIMTContractStateValue(c) => {
            buffer.push(c.condition);
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
            buffer.extend(c.value.iter());
        }
        DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
        }
        DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
            buffer.push(c.contract_id);
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
            buffer.push(c.user_id);
            buffer.push(c.contract_id);
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
            buffer.push(c.contract_state_tree_height as u64);
        }
        DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
        }
        DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
            buffer.push(c.user_id);
            buffer.push(c.contract_id);
            buffer.push(c.base_offset);
            buffer.push(c.capacity);
            buffer.extend(c.key.iter());
            buffer.push(c.contract_state_tree_height as u64);
        }
    }
}

fn encode_state_cmds(buffer: &mut Vec<u64>, cmds: &[DPNStateCmd<u64>]) {
    buffer.push(cmds.len() as u64);
    for cmd in cmds {
        let mut local = Vec::new();
        encode_state_cmd(&mut local, cmd);
        buffer.push(local.len() as u64);
        buffer.extend(local.into_iter());
    }
}

fn encode_assertions(buffer: &mut Vec<u64>, assertions: &[DPNAssertEqInfoIndexed]) {
    buffer.push(assertions.len() as u64);
    for assertion in assertions {
        buffer.push(assertion.left);
        buffer.push(assertion.right);
    }
}

fn encode_indexed_var_defs(buffer: &mut Vec<u64>, defs: &[DPNIndexedVarDef]) {
    buffer.push(defs.len() as u64);
    for def in defs {
        buffer.push(def.data_type as u8 as u64);
        buffer.push(def.index as u64);
        buffer.push(def.op_type.get_enc_value() as u64);
        buffer.push(def.inputs.len() as u64);
        buffer.extend(def.inputs.iter());
    }
}

fn encode_events(buffer: &mut Vec<u64>, events: &[DPNEventRecord]) {
    buffer.push(events.len() as u64);
    for event in events {
        buffer.push(event.condition as u64);
        buffer.push(event.checkpoint_id as u64);
        buffer.push(event.user_id as u64);
        buffer.push(event.contract_id as u64);
        buffer.push(event.data.len() as u64);
        buffer.extend(event.data.iter());
    }
}

fn dpn_function_words(def: &DPNFunctionCircuitDefinition) -> Vec<u64> {
    let mut out = Vec::new();
    out.push(def.method_id as u64);
    encode_vec(&mut out, &def.circuit_inputs);
    encode_vec(&mut out, &def.circuit_outputs);
    encode_state_cmds(&mut out, &def.state_commands);
    let resolutions: Vec<u64> = def.state_command_resolution_indices.iter().map(|x| *x as u64).collect();
    encode_vec(&mut out, &resolutions);
    encode_assertions(&mut out, &def.assertions);
    encode_indexed_var_defs(&mut out, &def.definitions);
    encode_events(&mut out, &def.events);
    out
}

pub fn hash_dpn_function<F: RichField + PrimeField64>(def: &DPNFunctionCircuitDefinition) -> QHashOut<F> {
    let felts = dpn_function_words(def).into_iter().map(F::from_canonical_u64).collect::<Vec<_>>();
    safe_hash_fixed_length::<PoseidonHasher, F>(&felts)
}

pub fn cfc_code_definition_to_dapen_fc(cfc_def: &ContractFunctionCodeDefinition) -> anyhow::Result<DPNFunctionCircuitDefinition> {
    let res = serde_cbor::from_slice::<DPNFunctionCircuitDefinition>(&cfc_def.code);

    match res {
        Ok(r) => Ok(r),
        Err(e) => anyhow::bail!("error deserializing dapen function definition {:?}", e),
    }
}
