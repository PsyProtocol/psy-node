use psy_vm::dpn::{
    eval::executor::{ExecutionContext, InMemoryStateBackend, VmExecutor},
    ops::{
        op_types::{encode_indexed_op_id, DPNBuiltInDataType, DPNEventRecord, DPNIndexedVarDef, DPNOpType},
        state_cmd::data::DPNStateCmd,
    },
    vm::def::DPNFunctionCircuitDefinition,
};

fn target(index: usize) -> u64 {
    encode_indexed_op_id(DPNBuiltInDataType::Target, index)
}

fn definition(op_type: DPNOpType, index: usize, inputs: Vec<u64>) -> DPNIndexedVarDef {
    DPNIndexedVarDef {
        data_type: DPNBuiltInDataType::Target,
        index,
        op_type,
        inputs,
    }
}

fn contract() -> DPNFunctionCircuitDefinition {
    DPNFunctionCircuitDefinition {
        name: "read_write_read".into(),
        method_id: 1,
        circuit_inputs: (0..3).map(target).collect(),
        circuit_outputs: vec![target(3), target(4)],
        state_commands: vec![
            DPNStateCmd::get_self_user_current_contract_state_slot_single(target(1)),
            DPNStateCmd::set_contract_state_slot_single(target(0), target(1), target(2)),
            DPNStateCmd::get_self_user_current_contract_state_slot_single(target(1)),
        ],
        state_command_resolution_indices: vec![3, 4, 4],
        definitions: vec![
            definition(DPNOpType::InputTarget, 0, vec![0]),
            definition(DPNOpType::InputTarget, 1, vec![1]),
            definition(DPNOpType::InputTarget, 2, vec![2]),
            definition(DPNOpType::GetStateCommandResultSingle, 3, vec![0]),
            definition(DPNOpType::GetStateCommandResultSingle, 4, vec![2]),
        ],
        assertions: vec![],
        events: vec![DPNEventRecord {
            condition: target(0),
            checkpoint_id: target(0),
            user_id: target(0),
            contract_id: target(0),
            data: vec![target(3), target(4)],
        }],
    }
}

fn context() -> ExecutionContext {
    ExecutionContext {
        user_id: 7,
        contract_id: 8,
        caller_contract_id: 9,
        checkpoint_id: 10,
        nonce: 11,
        user_public_key_hash: [0; 4],
        session_proof_tree_root: [0; 4],
    }
}

#[test]
fn read_write_read_uses_pending_write_and_emits_result() {
    let mut backend = InMemoryStateBackend::new();
    backend.set_hash(7, 8, 1, [40, 41, 42, 43]);
    let mut vm = VmExecutor::new(backend);

    let result = vm.execute(&contract(), &context(), &[1, 5, 99]).unwrap();

    assert!(result.success);
    assert_eq!(result.outputs, vec![41, 99]);
    assert_eq!(
        result.state_reads.iter().map(|read| read.value.as_slice()).collect::<Vec<_>>(),
        vec![&[41][..], &[99][..]]
    );
    assert_eq!(result.state_writes.len(), 1);
    assert_eq!(result.state_writes[0].old_value, vec![41]);
    assert_eq!(result.state_writes[0].new_value, vec![99]);
    assert_eq!(result.state_delta.len(), 1);
    assert_eq!(result.state_delta[0].new_value, vec![99]);
    assert_eq!(vm.write_overlay().get(&(7, 8, 5)), Some(&99));
    assert_eq!(result.events.len(), 1);
    assert_eq!(result.events[0].data, vec![41, 99]);
    assert_eq!(
        (result.events[0].checkpoint_id, result.events[0].user_id, result.events[0].contract_id),
        (10, 7, 8)
    );
}

#[test]
fn false_write_condition_keeps_original_slot_and_suppresses_event() {
    let mut backend = InMemoryStateBackend::new();
    backend.set_slot(7, 8, 5, 41);
    let mut vm = VmExecutor::new(backend);

    let result = vm.execute(&contract(), &context(), &[0, 5, 99]).unwrap();

    assert!(result.success);
    assert_eq!(result.outputs, vec![41, 41]);
    assert!(result.state_delta.is_empty());
    assert!(vm.write_overlay().is_empty());
    assert!(result.events.is_empty());
}

#[test]
fn malformed_command_schedule_is_rejected_before_state_changes() {
    let mut vm = VmExecutor::new(InMemoryStateBackend::new());
    let mut invalid = contract();
    invalid.state_command_resolution_indices.pop();

    let error = vm.execute(&invalid, &context(), &[1, 5, 99]).unwrap_err();

    assert!(error.to_string().contains("state_command_resolution_indices"));
    assert!(vm.write_overlay().is_empty());
}
