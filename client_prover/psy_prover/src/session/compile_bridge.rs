//! Bridge between psy_compiler output and the UPS proving pipeline.
//!
//! Provides functions to:
//! 1. Compile a contract and produce deploy-ready artifacts
//! 2. Simulate execution before proof generation (pre-flight check)
//! 3. Compile + deploy in one step

use std::{
    collections::HashMap,
    path::Path,
    sync::{Mutex, OnceLock},
};

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{
    config::store_config::F,
    qblock::cmds::deploy_contract::{QBCDeployContract, QBCDeployContractV2, QBCUpdateContract},
};
use psy_compiler::output::serialize::ContractOutput;
use psy_dpn_circuit::circuits::cfc::DapenContractFunctionCircuit;
use psy_vm::dpn::{
    eval::executor::{ExecutionContext, ExecutionResult, InMemoryStateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};
use serde::{Deserialize, Serialize};

#[cfg(not(target_arch = "wasm32"))]
use super::gen_contract_deploy_and_circuits_for_functions;

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn local_state_layout_manager() -> &'static psy_plonky2_circuits::coordinator::state_layout_helper::StateLayoutCircuitManager<C, D> {
    static MANAGER: OnceLock<psy_plonky2_circuits::coordinator::state_layout_helper::StateLayoutCircuitManager<C, D>> = OnceLock::new();
    MANAGER.get_or_init(|| {
        use psy_core::constants::protocol::{STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT, STATE_LAYOUT_MAX_AGGREGATION_DEPTH, STATE_LAYOUT_TREE_HEIGHT};
        psy_plonky2_circuits::coordinator::state_layout_helper::StateLayoutCircuitManager::<C, D>::new_layout_only(
            STATE_LAYOUT_TREE_HEIGHT - STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
            STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
            STATE_LAYOUT_MAX_AGGREGATION_DEPTH,
        )
    })
}

fn local_layout_proof_cache() -> &'static Mutex<HashMap<String, psy_plonky2_circuits::coordinator::state_layout_helper::LocalInitialLayoutProof<F>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, psy_plonky2_circuits::coordinator::state_layout_helper::LocalInitialLayoutProof<F>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

const LOCAL_LAYOUT_PROOF_CACHE_MAX_ENTRIES: usize = 64;

fn layout_proof_cache_key<T: Serialize>(kind: &str, contract_id: Option<u64>, value: &T) -> anyhow::Result<String> {
    use psy_core::constants::protocol::{STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT, STATE_LAYOUT_MAX_AGGREGATION_DEPTH, STATE_LAYOUT_TREE_HEIGHT};
    let manager = local_state_layout_manager();
    Ok(serde_json::to_string(&(
        psy_data::v1::qdata::contract::STATE_LAYOUT_VERSION,
        STATE_LAYOUT_TREE_HEIGHT,
        psy_data::v1::qdata::contract::CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT,
        STATE_LAYOUT_APPEND_SUB_TREE_HEIGHT,
        STATE_LAYOUT_MAX_AGGREGATION_DEPTH,
        manager.canonical_layout_append.fingerprint,
        kind,
        contract_id,
        value,
    ))?)
}

fn cache_layout_proof(key: String, proof: psy_plonky2_circuits::coordinator::state_layout_helper::LocalInitialLayoutProof<F>) -> anyhow::Result<()> {
    let mut cache = local_layout_proof_cache()
        .lock()
        .map_err(|_| anyhow::anyhow!("layout proof cache lock poisoned"))?;
    if cache.len() >= LOCAL_LAYOUT_PROOF_CACHE_MAX_ENTRIES && !cache.contains_key(&key) {
        if let Some(oldest_key) = cache.keys().next().cloned() {
            cache.remove(&oldest_key);
        }
    }
    cache.insert(key, proof);
    Ok(())
}

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
    pub deploy_cmd: QBCDeployContractV2<F>,
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
#[cfg(not(target_arch = "wasm32"))]
pub fn compile_contract(source: &str, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let contract_output = psy_compiler::compile(source)?;
    build_deploy_artifacts(contract_output, deployer)
}

/// Native deployment artifact generation is unavailable in a browser build.
#[cfg(target_arch = "wasm32")]
pub fn compile_contract(_source: &str, _deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    anyhow::bail!("native contract compilation with layout proofs is unavailable on wasm32")
}

/// Compile a multi-file contract crate and generate deployment artifacts.
#[cfg(not(target_arch = "wasm32"))]
pub fn compile_crate_contract(root_file: &Path, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let contract_output = psy_compiler::compile_crate(root_file)?;
    build_deploy_artifacts(contract_output, deployer)
}

/// Native deployment artifact generation is unavailable in a browser build.
#[cfg(target_arch = "wasm32")]
pub fn compile_crate_contract(_root_file: &Path, _deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    anyhow::bail!("native contract compilation with layout proofs is unavailable on wasm32")
}

/// Compile a single-file contract source and return the raw compiler output.
pub fn compile_contract_output(source: &str) -> anyhow::Result<ContractOutput> {
    psy_compiler::compile(source)
}

/// Compile a multi-file contract crate and return the raw compiler output.
pub fn compile_crate_output(root_file: &Path) -> anyhow::Result<ContractOutput> {
    psy_compiler::compile_crate(root_file)
}

/// Build deploy artifacts from a ContractOutput.
#[cfg(not(target_arch = "wasm32"))]
fn build_deploy_artifacts(contract_output: ContractOutput, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    let state_tree_height = contract_output.state_tree_height() as u8;

    let (circuits, base_deploy_cmd) =
        gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, state_tree_height, &contract_output.circuit_definitions)?;
    let deploy_cmd = build_layout_aware_deploy_command(&contract_output, base_deploy_cmd)?;

    Ok(CompileResult {
        contract_output,
        circuits,
        deploy_cmd,
    })
}

/// Generates the canonical layout proof and attaches it to an existing
/// compiler deploy artifact.
pub fn build_layout_aware_deploy_command(
    contract_output: &ContractOutput,
    deploy_contract: QBCDeployContract<F>,
) -> anyhow::Result<QBCDeployContractV2<F>> {
    use psy_core::constants::protocol::STATE_LAYOUT_TREE_HEIGHT;

    const STRUCT_MEMBERS_TREE_HEIGHT: usize = psy_data::v1::qdata::contract::CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT;
    let manager = local_state_layout_manager();
    let abi_json = contract_output.abi_to_json()?;
    let manifest = psy_data::v1::qdata::contract::canonical_layout_manifest_from_compiler_abi_json::<
        parth_core::pgoldilocks::PoseidonHasher,
        F,
        parth_core::pgoldilocks::QHashOut<F>,
    >(&abi_json, STATE_LAYOUT_TREE_HEIGHT, STRUCT_MEMBERS_TREE_HEIGHT)?;
    let cache_key = layout_proof_cache_key("deploy", None, &manifest)?;
    let cached_proof = {
        let cache = local_layout_proof_cache()
            .lock()
            .map_err(|_| anyhow::anyhow!("layout proof cache lock poisoned"))?;
        cache.get(&cache_key).cloned()
    };
    let proof = if let Some(proof) = cached_proof {
        tracing::debug!("layout deploy proof cache hit");
        proof
    } else {
        let proof = manager.prove_initial_layout(&manifest)?;
        cache_layout_proof(cache_key, proof.clone())?;
        proof
    };
    let layout = &proof.layout.contract_layout;
    let command = QBCDeployContractV2 {
        deploy_contract,
        layout_protocol_version: psy_data::v1::qdata::contract::STATE_LAYOUT_VERSION,
        state_layout_root: QHashOut(proof.layout.contract_layout.state_layout_root.0),
        state_layout_field_count: layout.state_layout_field_count,
        state_layout_slot_count: layout.state_layout_slot_count,
        canonical_layout_verifier_fingerprint: QHashOut(proof.canonical_verifier_fingerprint.0),
        canonical_layout_proof: proof.canonical_proof,
    };
    command.validate_shape()?;
    Ok(command)
}

pub fn build_layout_aware_update_command(
    old_contract_output: &ContractOutput,
    new_contract_output: &ContractOutput,
    mut update: QBCUpdateContract<F>,
) -> anyhow::Result<QBCUpdateContract<F>> {
    use psy_core::constants::protocol::STATE_LAYOUT_TREE_HEIGHT;

    const STRUCT_MEMBERS_TREE_HEIGHT: usize = psy_data::v1::qdata::contract::CANONICAL_TYPE_LAYOUT_STRUCT_TREE_HEIGHT;
    let layout_unchanged = old_contract_output.abi.contract.state_layout
        == new_contract_output.abi.contract.state_layout;
    if !layout_unchanged {
        new_contract_output
            .abi
            .validate_layout_update_from(&old_contract_output.abi)?;
    }
    let old_json = old_contract_output.abi_to_json()?;
    let new_json = new_contract_output.abi_to_json()?;
    let old_manifest = psy_data::v1::qdata::contract::canonical_layout_manifest_from_compiler_abi_json::<
        parth_core::pgoldilocks::PoseidonHasher,
        F,
        parth_core::pgoldilocks::QHashOut<F>,
    >(&old_json, STATE_LAYOUT_TREE_HEIGHT, STRUCT_MEMBERS_TREE_HEIGHT)?;
    let new_manifest = psy_data::v1::qdata::contract::canonical_layout_manifest_from_compiler_abi_json::<
        parth_core::pgoldilocks::PoseidonHasher,
        F,
        parth_core::pgoldilocks::QHashOut<F>,
    >(&new_json, STATE_LAYOUT_TREE_HEIGHT, STRUCT_MEMBERS_TREE_HEIGHT)?;
    let manager = local_state_layout_manager();
    let cache_namespace = if layout_unchanged {
        "update-no-layout-change"
    } else {
        "update"
    };
    let cache_key = layout_proof_cache_key(cache_namespace, Some(update.contract_id), &(old_manifest.clone(), new_manifest.clone()))?;
    let cached_proof = {
        let cache = local_layout_proof_cache()
            .lock()
            .map_err(|_| anyhow::anyhow!("layout proof cache lock poisoned"))?;
        cache.get(&cache_key).cloned()
    };
    let proof = if let Some(proof) = cached_proof {
        tracing::debug!("layout update proof cache hit");
        proof
    } else {
        // A code-only update still carries one canonical layout proof. For an
        // unchanged layout it proves an identity root transition; append-only
        // changes use the regular old-layout -> new-layout transition.
        let proof = if layout_unchanged {
            manager.prove_layout_no_change(
                update.contract_id,
                &old_manifest,
            )?
        } else {
            manager.prove_layout_update(
                update.contract_id,
                &old_manifest,
                &new_manifest,
            )?
        };
        cache_layout_proof(cache_key, proof.clone())?;
        proof
    };
    update.layout_protocol_version = psy_data::v1::qdata::contract::STATE_LAYOUT_VERSION;
    update.state_layout_root = QHashOut(proof.layout.contract_layout.state_layout_root.0);
    update.state_layout_field_count = proof.layout.contract_layout.state_layout_field_count;
    update.state_layout_slot_count = proof.layout.contract_layout.state_layout_slot_count;
    update.canonical_layout_verifier_fingerprint = QHashOut(proof.canonical_verifier_fingerprint.0);
    update.canonical_layout_proof = proof.canonical_proof;
    update.validate_shape()?;
    Ok(update)
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
    let abi_method = contract_output
        .abi
        .contract
        .methods
        .iter()
        .find(|m| m.name == method_name)
        .ok_or_else(|| {
            let available: Vec<&str> = contract_output.abi.contract.methods.iter().map(|m| m.name.as_str()).collect();
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

    #[test]
    #[ignore = "builds state-layout circuits and generates a recursive deploy proof"]
    fn proves_layout_aware_contract_deploy() -> anyhow::Result<()> {
        let source = r#"
            #[contract]
            pub struct LayoutAwareDeployContract {
                pub balance: Felt,
                pub nonce: U32,
            }

            #[contract_implementation]
            impl LayoutAwareDeployContract {
                #[contract_method]
                pub fn add_balance(&mut self, ctx: &mut ChainContext, amount: Felt) {
                    self.balance += amount;
                }
            }
        "#;
        let contract_output = psy_compiler::compile(source)?;
        let deployer = QHashOut::<F>::default();
        let (_, base_deploy) = super::super::gen_contract_deploy_and_circuits_for_functions::<C, D>(
            deployer,
            u8::try_from(contract_output.abi.contract.state_tree_height)?,
            &contract_output.circuit_definitions,
        )?;
        let deploy = build_layout_aware_deploy_command(&contract_output, base_deploy)?;

        assert_eq!(deploy.deploy_contract.deployer, deployer);
        assert_eq!(deploy.state_layout_field_count, 2);
        assert_eq!(deploy.state_layout_slot_count, 2);
        assert!(!deploy.canonical_layout_proof.is_empty());
        deploy.validate_shape()?;
        Ok(())
    }

    #[test]
    #[ignore = "builds state-layout circuits and generates a recursive update proof"]
    fn proves_complex_append_only_contract_update() -> anyhow::Result<()> {
        let old_source = r#"
            #[derive(FeltSized)]
            pub struct Account {
                pub balance: Felt,
                pub nonce: U32,
            }

            #[contract]
            pub struct ComplexUpdateContract {
                pub account: Account,
                pub reserved_history: [Felt; 32],
            }

            #[contract_implementation]
            impl ComplexUpdateContract {
                #[contract_method]
                pub fn add_balance(&mut self, ctx: &mut ChainContext, amount: Felt) {
                    self.account.balance += amount;
                }
            }
        "#;
        let new_source = r#"
            #[derive(FeltSized)]
            pub struct Account {
                pub balance: Felt,
                pub nonce: U32,
            }

            #[derive(FeltSized)]
            pub struct AuditRecord {
                pub actor: Hash,
                pub counters: [U32; 4],
                pub enabled: Bool,
            }

            #[contract]
            pub struct ComplexUpdateContract {
                pub account: Account,
                pub reserved_history: [Felt; 32],
                pub latest_audit: AuditRecord,
                pub checkpoint_roots: [Hash; 2],
                pub feature_flags: [Bool; 4],
            }

            #[contract_implementation]
            impl ComplexUpdateContract {
                #[contract_method]
                pub fn add_balance(&mut self, ctx: &mut ChainContext, amount: Felt) {
                    self.account.balance += amount;
                }
            }
        "#;

        let old_output = psy_compiler::compile(old_source)?;
        let new_output = psy_compiler::compile(new_source)?;
        assert_eq!(old_output.abi.contract.state_tree_height, 6);
        assert_eq!(new_output.abi.contract.state_tree_height, 6);
        assert_eq!(old_output.abi.contract.state_layout.field_count, 2);
        assert_eq!(old_output.abi.contract.state_layout.slot_count, 34);
        assert_eq!(new_output.abi.contract.state_layout.field_count, 5);
        assert_eq!(new_output.abi.contract.state_layout.slot_count, 55);
        new_output.abi.validate_layout_update_from(&old_output.abi)?;

        let deployer = QHashOut::<F>::default();
        let contract_id = 42;
        let (_, base_update) = super::super::gen_contract_update_and_circuits_for_functions::<C, D>(
            contract_id,
            deployer,
            u8::try_from(old_output.abi.contract.state_tree_height)?,
            &new_output.circuit_definitions,
        )?;
        let update = build_layout_aware_update_command(&old_output, &new_output, base_update)?;

        assert_eq!(update.contract_id, contract_id);
        assert_eq!(update.state_layout_field_count, 5);
        assert_eq!(update.state_layout_slot_count, 55);
        assert!(!update.canonical_layout_proof.is_empty());
        update.validate_shape()?;
        Ok(())
    }
}
