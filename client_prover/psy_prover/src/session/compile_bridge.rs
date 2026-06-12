//! Bridge between psy_compiler output and the UPS proving pipeline.
//!
//! Provides functions to:
//! 1. Compile a contract and produce deploy-ready artifacts
//! 2. Simulate execution before proof generation (pre-flight check)
//! 3. Compile + deploy in one step

use std::path::Path;

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{config::store_config::F, qblock::cmds::deploy_contract::QBCDeployContract};
use psy_compiler::output::serialize::ContractOutput;
use psy_dpn_circuit::circuits::cfc::DapenContractFunctionCircuit;
use psy_vm::dpn::{
    eval::executor::{ExecutionContext, ExecutionResult, InMemoryStateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};
use serde::{Deserialize, Serialize};

use super::gen_contract_deploy_and_circuits_for_functions;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Result of compiling and optionally deploying a contract.
#[derive(Debug)]
pub struct CompileResult {
    /// Compiler output (code definition, circuit defs, ABI)
    pub contract_output: ContractOutput,
    /// Generated plonky2 circuits (one per method)
    pub circuits: Vec<DapenContractFunctionCircuit<C, D>>,
    /// Deploy command ready for submission
    pub deploy_cmd: QBCDeployContract<F>,
}

/// Result of a pre-flight simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// The execution result from the VM
    pub execution: ExecutionResult,
    /// Method name that was simulated
    pub method_name: String,
    /// Whether the simulation passed (all assertions OK)
    pub passed: bool,
}

// ---------------------------------------------------------------------------
// Compile functions
// ---------------------------------------------------------------------------

/// Compile a single-file contract source and generate deployment artifacts.
pub fn compile_contract(source: &str, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let contract_output = psy_compiler::compile(source)?;
    build_deploy_artifacts(contract_output, deployer)
}

/// Compile a multi-file contract crate and generate deployment artifacts.
pub fn compile_crate_contract(root_file: &Path, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let contract_output = psy_compiler::compile_crate(root_file)?;
    build_deploy_artifacts(contract_output, deployer)
}

/// Build deploy artifacts from a ContractOutput.
fn build_deploy_artifacts(contract_output: ContractOutput, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let state_tree_height = contract_output.state_tree_height() as u8;

    let (circuits, deploy_cmd) =
        gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, state_tree_height, &contract_output.circuit_definitions)?;

    Ok(CompileResult {
        contract_output,
        circuits,
        deploy_cmd,
    })
}

// ---------------------------------------------------------------------------
// Simulation (pre-flight check)
// ---------------------------------------------------------------------------

/// Simulate a contract method execution without generating proofs.
///
/// This is useful as a pre-flight check before expensive proof generation.
/// If the simulation fails (assertion violation), we can skip proof gen and
/// return an error immediately.
pub fn simulate_method(
    contract_output: &ContractOutput,
    method_name: &str,
    inputs: &[u64],
    context: &ExecutionContext,
) -> anyhow::Result<SimulationResult> {
    // Find the method by name in the ABI
    let abi_method = contract_output.abi.methods.iter().find(|m| m.name == method_name).ok_or_else(|| {
        let available: Vec<&str> = contract_output.abi.methods.iter().map(|m| m.name.as_str()).collect();
        anyhow::anyhow!("Method '{}' not found. Available: {:?}", method_name, available)
    })?;

    // Find the matching circuit definition
    let circuit_def = contract_output
        .circuit_definitions
        .iter()
        .find(|d| d.method_id == abi_method.method_id)
        .ok_or_else(|| anyhow::anyhow!("No circuit definition for method '{}' (method_id={})", method_name, abi_method.method_id))?;

    // Execute in-memory
    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let execution = executor.execute(circuit_def, context, inputs)?;

    let passed = execution.success;

    Ok(SimulationResult {
        execution,
        method_name: method_name.to_string(),
        passed,
    })
}

/// Simulate with a pre-populated in-memory state backend.
pub fn simulate_method_with_state(
    circuit_def: &DPNFunctionCircuitDefinition,
    inputs: &[u64],
    context: &ExecutionContext,
    state: InMemoryStateBackend,
) -> anyhow::Result<ExecutionResult> {
    let mut executor = VmExecutor::new(state);
    executor.execute(circuit_def, context, inputs)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simulate_basic_contract() {
        // A simple contract that just sets a state slot
        let source = r#"
            const PSY_TOTAL_USERS: usize = 4;
            const PSY_TOTAL_CONTRACTS: usize = 4;

            #[contract]
            pub struct TestContract {
                pub value: Felt,
            }

            #[contract_implementation]
            impl TestContract {
                #[contract_method]
                pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                    self.value = new_value;
                }
            }
        "#;

        let contract_output = psy_compiler::compile(source).expect("compilation should succeed");
        assert_eq!(contract_output.method_count(), 1);

        let context = ExecutionContext {
            user_id: 1,
            contract_id: 1,
            caller_contract_id: 0,
            checkpoint_id: 100,
            nonce: 0,
            user_public_key_hash: [0; 4],
        };

        let result = simulate_method(&contract_output, "set_value", &[42], &context);
        assert!(result.is_ok(), "simulation should succeed: {:?}", result.err());

        let sim = result.unwrap();
        assert!(sim.passed, "simulation should pass");
        assert_eq!(sim.method_name, "set_value");
    }
}
