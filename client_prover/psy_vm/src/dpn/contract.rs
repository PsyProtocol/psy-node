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

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;

    fn definition(method_id: u32) -> DPNFunctionCircuitDefinition {
        DPNFunctionCircuitDefinition {
            name: "transfer".into(),
            method_id,
            circuit_inputs: vec![1, 2],
            circuit_outputs: vec![3],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            definitions: vec![],
            events: vec![],
        }
    }

    #[test]
    fn function_code_conversion_round_trips_and_keeps_wire_metadata() {
        let definition = definition(17);
        let code = dapen_fc_to_cfc_code_definition(&definition);

        assert_eq!(code.method_id, 17);
        assert_eq!(code.num_inputs, 2);
        assert_eq!(code.num_outputs, 1);
        assert_eq!(code.vm_type, VM_TYPE_STANRDARD_DAPEN_V1);
        assert_eq!(cfc_code_definition_to_dapen_fc(&code).unwrap(), definition);
    }

    #[test]
    fn invalid_function_code_is_rejected_and_hash_tracks_definition_contents() {
        let invalid = ContractFunctionCodeDefinition {
            method_id: 0,
            num_inputs: 0,
            num_outputs: 0,
            vm_type: VM_TYPE_STANRDARD_DAPEN_V1,
            code: vec![0xff],
        };
        assert!(cfc_code_definition_to_dapen_fc(&invalid).is_err());

        let first = definition(1);
        let second = definition(2);
        assert_ne!(hash_dpn_function::<GoldilocksField>(&first), hash_dpn_function::<GoldilocksField>(&second));
        assert_eq!(hash_dpn_function::<GoldilocksField>(&first), hash_dpn_function::<GoldilocksField>(&first));
    }

    #[test]
    fn function_hash_encodes_every_state_command_variant() {
        use crate::dpn::ops::state_cmd::data::DPNStateCmdClearEntireTree;

        let commands = vec![
            DPNStateCmd::set_contract_state_slot_hash(1, 2, [3, 4, 5, 6]),
            DPNStateCmd::set_contract_state_slot_single(1, 2, 3),
            DPNStateCmd::set_contract_state_slot_range(1, 2, vec![3, 4]),
            DPNStateCmd::ClearEntireTree(DPNStateCmdClearEntireTree { condition: 1 }),
            DPNStateCmd::invoke_external_contract_function(1, 2, 3, vec![4, 5], 2),
            DPNStateCmd::invoke_external_contract_function_deferred(1, 2, 3, vec![4, 5]),
            DPNStateCmd::get_self_user_current_contract_state_slot_hash(2),
            DPNStateCmd::get_self_user_current_contract_state_slot_single(2),
            DPNStateCmd::get_self_user_current_contract_state_slot_range(2, 2),
            DPNStateCmd::get_self_user_external_contract_state_slot_hash(2, 4, 3),
            DPNStateCmd::get_self_user_external_contract_state_slot_single(2, 4, 3),
            DPNStateCmd::get_self_user_external_contract_state_slot_range(2, 4, 3, 2),
            DPNStateCmd::get_other_user_contract_state_slot_hash(1, 2, 4, 3),
            DPNStateCmd::get_other_user_contract_state_slot_single(1, 2, 4, 3),
            DPNStateCmd::get_other_user_contract_state_slot_range(1, 2, 4, 3, 2),
            DPNStateCmd::get_checkpoint_leaf_stats(1),
            DPNStateCmd::get_contract_leaf(2),
            DPNStateCmd::get_global_state_roots(1),
            DPNStateCmd::set_imt_contract_state_value(1, 2, 4, [5, 6, 7, 8], [9, 10, 11, 12]),
            DPNStateCmd::get_self_user_current_imt_contract_state_value(2, 4, [5, 6, 7, 8]),
            DPNStateCmd::get_self_user_external_imt_contract_state_value(2, 4, 2, 4, [5, 6, 7, 8]),
            DPNStateCmd::get_other_user_imt_contract_state_value(1, 2, 4, 2, 4, [5, 6, 7, 8]),
            DPNStateCmd::contains_self_user_current_imt_contract_state_value(2, 4, [5, 6, 7, 8]),
            DPNStateCmd::contains_other_user_imt_contract_state_value(1, 2, 4, 2, 4, [5, 6, 7, 8]),
        ];
        let mut rich_definition = definition(1);
        rich_definition.state_commands = commands;
        rich_definition.state_command_resolution_indices = (0..rich_definition.state_commands.len()).collect();
        rich_definition.assertions.push(DPNAssertEqInfoIndexed {
            left: 9,
            right: 10,
            message: "ignored in hash".to_string(),
        });
        rich_definition.events.push(DPNEventRecord {
            condition: 1,
            checkpoint_id: 2,
            user_id: 3,
            contract_id: 4,
            data: vec![5, 6],
        });

        assert_eq!(rich_definition.state_commands.len(), 24);
        assert_ne!(hash_dpn_function::<GoldilocksField>(&rich_definition), hash_dpn_function::<GoldilocksField>(&definition(1)));
    }
}
