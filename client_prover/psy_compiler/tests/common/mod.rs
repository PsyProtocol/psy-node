use psy_compiler::compile;
use psy_vm::dpn::{
    eval::executor::{ExecutionContext, ExecutionResult, InMemoryStateBackend, StateWrite, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};

pub fn default_context() -> ExecutionContext {
    ExecutionContext {
        user_id: 1,
        contract_id: 1,
        caller_contract_id: 0,
        checkpoint_id: 42,
        nonce: 0,
        user_public_key_hash: [0; 4],
    }
}

pub fn compile_method(source: &str, method_name: &str) -> DPNFunctionCircuitDefinition {
    let output = compile(source).expect("compilation should succeed");
    let method = output
        .abi
        .contract
        .methods
        .iter()
        .find(|m| m.name == method_name)
        .unwrap_or_else(|| panic!("method '{}' not found in ABI", method_name));
    output
        .circuit_definitions
        .iter()
        .find(|d| d.method_id == method.method_id)
        .unwrap_or_else(|| panic!("circuit for method '{}' not found", method_name))
        .clone()
}

pub fn execute(source: &str, method_name: &str, ctx: &ExecutionContext, inputs: &[u64]) -> ExecutionResult {
    let circuit = compile_method(source, method_name);
    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    executor.execute(&circuit, ctx, inputs).expect("vm execution should complete")
}

pub fn has_write(result: &ExecutionResult, user_id: u64, contract_id: u64, slot_index: u64, new_value: &[u64]) -> bool {
    result
        .state_writes
        .iter()
        .any(|w| w.condition && w.user_id == user_id && w.contract_id == contract_id && w.slot_index == slot_index && w.new_value == new_value)
}

pub fn assert_write(result: &ExecutionResult, user_id: u64, contract_id: u64, slot_index: u64, new_value: &[u64]) {
    assert!(
        has_write(result, user_id, contract_id, slot_index, new_value),
        "expected write not found: user_id={}, contract_id={}, slot_index={}, new_value={:?}, writes={:?}",
        user_id,
        contract_id,
        slot_index,
        new_value,
        result.state_writes
    );
}

pub fn assert_all_effective_writes_match_ctx(result: &ExecutionResult, ctx: &ExecutionContext) {
    let effective: Vec<&StateWrite> = result.state_writes.iter().filter(|w| w.condition).collect();
    assert!(
        !effective.is_empty(),
        "expected at least one effective write, got writes={:?}",
        result.state_writes
    );
    assert!(
        effective.iter().all(|w| w.user_id == ctx.user_id && w.contract_id == ctx.contract_id),
        "found effective write with mismatched user/contract: ctx=({}, {}), writes={:?}",
        ctx.user_id,
        ctx.contract_id,
        effective
    );
}
