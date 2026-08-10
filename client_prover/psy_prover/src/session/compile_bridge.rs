//! Native bridge from the SDK local-web-compiler to the UPS proving pipeline.
//!
//! Native compilation is delegated to the sibling `psy-sdk` distribution so
//! this crate never links a parser or compiler implementation.

use std::path::Path;

use plonky2::plonk::config::PoseidonGoldilocksConfig;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::{config::store_config::F, qblock::cmds::deploy_contract::QBCDeployContract};
use psy_dpn_circuit::circuits::cfc::DapenContractFunctionCircuit;
use psy_vm::dpn::{
    compile_output::ContractOutput,
    eval::executor::{ExecutionContext, ExecutionResult, InMemoryStateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};
use serde::{Deserialize, Serialize};

use super::gen_contract_deploy_and_circuits_for_functions;

#[cfg(not(target_arch = "wasm32"))]
use {
    anyhow::Context,
    base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _},
    psy_client_data::{abi::Abi, qdata::contract::ContractCodeDefinition},
    psy_config::network_constants::{MAX_CONTRACT_STATE_TREE_HEIGHT, VM_TYPE_STANRDARD_DAPEN_V1},
    psy_vm::dpn::{
        contract::dapen_fc_to_cfc_code_definition,
        ops::{
            op_types::{decode_indexed_op_id, DPNBuiltInDataType, DPNOpType},
            state_cmd::types::DPNStateCmdCore,
        },
    },
    std::{
        collections::{HashMap, HashSet},
        env, fs,
        io::Write,
        path::PathBuf,
        process::{Command, Stdio},
    },
};

#[cfg(not(target_arch = "wasm32"))]
const NODE_COMPILE_DRIVER: &str = include_str!("node_compile_driver.mjs");

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Serialize)]
#[serde(tag = "mode", rename_all = "lowercase")]
enum CompilerRequest<'a> {
    Source { source: &'a str },
    Project { project: ProjectInput },
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Serialize)]
struct ProjectInput {
    entry: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method_names: Option<Vec<String>>,
    files: Vec<(Vec<String>, String)>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct CompilerResponse {
    success: bool,
    error: Option<String>,
    error_offset: Option<usize>,
    entry_path: Option<String>,
    compile_results: Option<Vec<DPNFunctionCircuitDefinition>>,
    contract_code: Option<CompilerContractCode>,
    abi: Option<Abi>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct CompilerContractCode {
    state_tree_height: u16,
    functions: Vec<CompilerContractFunction>,
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
struct CompilerContractFunction {
    method_id: u32,
    num_inputs: usize,
    num_outputs: usize,
    vm_type: u32,
    code_base64: String,
}

type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Result of compiling and generating deploy-ready artifacts.
#[derive(Debug)]
pub struct CompileResult {
    pub contract_output: ContractOutput,
    pub circuits: Vec<DapenContractFunctionCircuit<C, D>>,
    pub deploy_cmd: QBCDeployContract<F>,
}

/// Result of a pre-flight simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub execution: ExecutionResult,
    pub method_name: String,
    pub passed: bool,
}

/// Compile a single source string through the SDK local-web-compiler.
#[cfg(not(target_arch = "wasm32"))]
pub fn compile_contract_output(source: &str) -> anyhow::Result<ContractOutput> {
    invoke_compiler(&CompilerRequest::Source { source })
}

/// Native compilation is intentionally unavailable in a browser build.
#[cfg(target_arch = "wasm32")]
pub fn compile_contract_output(_source: &str) -> anyhow::Result<ContractOutput> {
    anyhow::bail!("native contract compilation is unavailable on wasm32; use @psy-protocol/psy-sdk/local-web-compiler")
}

/// Compile a crate root plus all sibling `.psy` and `.psy.rs` module sources.
#[cfg(not(target_arch = "wasm32"))]
pub fn compile_crate_output(root_file: &Path) -> anyhow::Result<ContractOutput> {
    invoke_compiler(&CompilerRequest::Project {
        project: collect_project_input(root_file)?,
    })
}

/// Native compilation is intentionally unavailable in a browser build.
#[cfg(target_arch = "wasm32")]
pub fn compile_crate_output(_root_file: &Path) -> anyhow::Result<ContractOutput> {
    anyhow::bail!("native contract compilation is unavailable on wasm32; use @psy-protocol/psy-sdk/local-web-compiler")
}

/// Compile a single-file contract and generate deployment artifacts.
pub fn compile_contract(source: &str, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    build_deploy_artifacts(compile_contract_output(source)?, deployer)
}

/// Compile a multi-file contract crate and generate deployment artifacts.
pub fn compile_crate_contract(root_file: &Path, deployer: QHashOut<F>) -> anyhow::Result<CompileResult> {
    build_deploy_artifacts(compile_crate_output(root_file)?, deployer)
}

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

#[cfg(not(target_arch = "wasm32"))]
fn invoke_compiler(request: &CompilerRequest<'_>) -> anyhow::Result<ContractOutput> {
    let compiler_dir = resolve_sdk_compiler_dir()?;
    let node_binary = env::var_os("PSY_NODE_BINARY").unwrap_or_else(|| "node".into());
    let request_json = serde_json::to_vec(request).context("failed to serialize local-web-compiler request")?;

    let mut child = Command::new(&node_binary)
        .args(["--input-type=module", "--eval", NODE_COMPILE_DRIVER])
        .env("PSY_COMPILER_MODULE_DIR", &compiler_dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to launch Node.js local-web-compiler adapter; install Node.js or set PSY_NODE_BINARY")?;

    child
        .stdin
        .take()
        .context("Node.js local-web-compiler adapter did not expose stdin")?
        .write_all(&request_json)
        .context("failed to send the compiler request to Node.js")?;

    let output = child.wait_with_output().context("failed while waiting for the Node.js local-web-compiler adapter")?;
    if !output.status.success() {
        let diagnostics = String::from_utf8_lossy(&output.stderr);
        let diagnostics = diagnostics.trim();
        if diagnostics.is_empty() {
            anyhow::bail!("Node.js local-web-compiler adapter exited with {}", output.status);
        }
        anyhow::bail!("Node.js local-web-compiler adapter failed: {diagnostics}");
    }

    let stdout = output.stdout.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&output.stdout);
    let response: CompilerResponse = serde_json::from_slice(stdout)
        .context("local-web-compiler stdout was not a valid raw compile-result JSON object")?;
    contract_output_from_response(response)
}

#[cfg(not(target_arch = "wasm32"))]
fn contract_output_from_response(response: CompilerResponse) -> anyhow::Result<ContractOutput> {
    if !response.success {
        let mut location = String::new();
        if let Some(entry_path) = response.entry_path.as_deref() {
            location.push_str(" in ");
            location.push_str(entry_path);
        }
        if let Some(offset) = response.error_offset {
            location.push_str(&format!(" at byte offset {offset}"));
        }
        anyhow::bail!(
            "PSY compilation failed{location}: {}",
            response.error.as_deref().unwrap_or("compiler returned no diagnostic")
        );
    }

    let circuit_definitions = response
        .compile_results
        .context("local-web-compiler reported success without compile_results")?;
    let emitted_contract_code = response
        .contract_code
        .context("local-web-compiler reported success without contract_code")?;
    let abi = response.abi.context("local-web-compiler reported success without an ABI artifact")?;

    anyhow::ensure!(
        emitted_contract_code.state_tree_height == abi.contract.state_tree_height,
        "compiler contract_code state_tree_height {} does not match ABI state_tree_height {}",
        emitted_contract_code.state_tree_height,
        abi.contract.state_tree_height
    );
    anyhow::ensure!(
        emitted_contract_code.state_tree_height <= MAX_CONTRACT_STATE_TREE_HEIGHT as u16,
        "compiler state_tree_height {} exceeds network maximum {}",
        emitted_contract_code.state_tree_height,
        MAX_CONTRACT_STATE_TREE_HEIGHT
    );

    let mut definitions_by_id = HashMap::with_capacity(circuit_definitions.len());
    for definition in &circuit_definitions {
        anyhow::ensure!(
            definitions_by_id.insert(definition.method_id, definition).is_none(),
            "local-web-compiler returned duplicate circuit method_id {}",
            definition.method_id
        );
        validate_circuit_definition(definition)
            .with_context(|| format!("invalid DPN circuit '{}' (method_id={})", definition.name, definition.method_id))?;
    }

    let mut abi_ids = HashSet::with_capacity(abi.contract.methods.len());
    for method in &abi.contract.methods {
        anyhow::ensure!(
            abi_ids.insert(method.method_id),
            "local-web-compiler returned duplicate ABI method_id {}",
            method.method_id
        );
        let definition = definitions_by_id.get(&method.method_id).with_context(|| {
            format!(
                "ABI method '{}' has no compiled circuit definition (method_id={})",
                method.name, method.method_id
            )
        })?;
        anyhow::ensure!(
            method.input_felt_count == definition.circuit_inputs.len(),
            "ABI input size for method '{}' does not match its compiled circuit definition",
            method.name
        );
        anyhow::ensure!(
            method.output_felt_count == definition.circuit_outputs.len(),
            "ABI output size for method '{}' does not match its compiled circuit definition",
            method.name
        );
    }
    anyhow::ensure!(
        definitions_by_id.len() == abi_ids.len() && definitions_by_id.keys().all(|id| abi_ids.contains(id)),
        "compiled circuit definitions and ABI methods do not describe the same method IDs"
    );

    anyhow::ensure!(
        emitted_contract_code.functions.len() == circuit_definitions.len(),
        "compiler contract_code function count {} does not match compile_results count {}",
        emitted_contract_code.functions.len(),
        circuit_definitions.len()
    );
    let mut emitted_function_ids = HashSet::with_capacity(emitted_contract_code.functions.len());
    for function in &emitted_contract_code.functions {
        anyhow::ensure!(
            emitted_function_ids.insert(function.method_id),
            "compiler contract_code contains duplicate method_id {}",
            function.method_id
        );
        let definition = definitions_by_id.get(&function.method_id).with_context(|| {
            format!("compiler contract_code method_id {} has no matching DPN definition", function.method_id)
        })?;
        anyhow::ensure!(
            function.num_inputs == definition.circuit_inputs.len() && function.num_outputs == definition.circuit_outputs.len(),
            "compiler contract_code metadata does not match DPN definition for method_id {}",
            function.method_id
        );
        validate_contract_function_vm_type(function.method_id, function.vm_type)
            .with_context(|| format!("compiler contract_code method_id {} has unsupported vm_type {}", function.method_id, function.vm_type))?;
        let emitted_bytes = BASE64_STANDARD
            .decode(&function.code_base64)
            .with_context(|| format!("compiler contract_code method_id {} has invalid base64 code", function.method_id))?;
        let emitted_definition: DPNFunctionCircuitDefinition = serde_cbor::from_slice(&emitted_bytes)
            .with_context(|| format!("compiler contract_code method_id {} code is not a CBOR DPN definition", function.method_id))?;
        anyhow::ensure!(
            serde_cbor::to_vec(&emitted_definition).context("failed to re-encode compiler-emitted DPN definition")? == emitted_bytes,
            "compiler contract_code method_id {} code has trailing or non-canonical CBOR data",
            function.method_id
        );
        anyhow::ensure!(
            emitted_definition == **definition,
            "compiler contract_code method_id {} code does not match compile_results",
            function.method_id
        );
    }

    let contract_code = ContractCodeDefinition {
        state_tree_height: emitted_contract_code.state_tree_height,
        functions: circuit_definitions.iter().map(dapen_fc_to_cfc_code_definition).collect(),
    };

    Ok(ContractOutput {
        contract_code,
        circuit_definitions,
        abi,
    })
}
#[cfg(not(target_arch = "wasm32"))]
fn validate_contract_function_vm_type(method_id: u32, vm_type: u32) -> anyhow::Result<()> {
    anyhow::ensure!(
        vm_type == VM_TYPE_STANRDARD_DAPEN_V1,
        "compiler contract_code method_id {} has non-canonical vm_type {} (expected {})",
        method_id,
        vm_type,
        VM_TYPE_STANRDARD_DAPEN_V1
    );
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_circuit_definition(definition: &DPNFunctionCircuitDefinition) -> anyhow::Result<()> {
    anyhow::ensure!(
        definition.state_commands.len() == definition.state_command_resolution_indices.len(),
        "state_commands length {} does not match state_command_resolution_indices length {}",
        definition.state_commands.len(),
        definition.state_command_resolution_indices.len()
    );
    let mut previous_resolution = 0usize;
    for (command_index, &resolution_index) in definition.state_command_resolution_indices.iter().enumerate() {
        anyhow::ensure!(
            resolution_index <= definition.definitions.len(),
            "state command {command_index} resolution index {resolution_index} exceeds definition count {}",
            definition.definitions.len()
        );
        anyhow::ensure!(
            command_index == 0 || resolution_index >= previous_resolution,
            "state command resolution indices are not nondecreasing at command {command_index}"
        );
        previous_resolution = resolution_index;
    }

    let mut available = HashSet::<(DPNBuiltInDataType, usize)>::new();
    let mut constant_targets = HashMap::<usize, u64>::new();
    let mut indexed_lengths = HashMap::<(DPNBuiltInDataType, usize), usize>::new();
    for (definition_index, operation) in definition.definitions.iter().enumerate() {
        let operation_context = || format!("definition {definition_index} ({})", operation.op_type);
        validate_operation_shape(operation, definition.circuit_inputs.len()).with_context(operation_context)?;
        let expected_type = operation.op_type.get_data_type();
        let compatible_output_type = operation.data_type == expected_type
            || (operation.op_type == DPNOpType::InputTarget && operation.data_type == DPNBuiltInDataType::U32TargetArray)
            || (operation.op_type == DPNOpType::DivRem4 && operation.data_type == DPNBuiltInDataType::TargetArray);
        anyhow::ensure!(
            compatible_output_type,
            "{} declares output type {} but downstream constructs {}",
            operation_context(),
            operation.data_type,
            expected_type
        );

        match operation.op_type {
            DPNOpType::InputTarget | DPNOpType::Constant | DPNOpType::ConstantU32 => {}
            DPNOpType::ConstantTrue
            | DPNOpType::ConstantFalse
            | DPNOpType::GetUserId
            | DPNOpType::GetContractId
            | DPNOpType::GetCallerContractId
            | DPNOpType::GetCheckpointId
            | DPNOpType::GetNonce
            | DPNOpType::GetUserPublicKeyHash
            | DPNOpType::GetSessionProofTreeRoot => {}
            DPNOpType::SplitBits => validate_reference(operation.inputs[1], &available, ReferenceKind::Target).with_context(operation_context)?,
            DPNOpType::TargetAt => {
                validate_reference(operation.inputs[0], &available, ReferenceKind::Indexable).with_context(operation_context)?;
                let (array_type, array_index) = decode_indexed_op_id(operation.inputs[0]);
                let (index_type, index) = decode_indexed_op_id(operation.inputs[1]);
                let index_value = constant_targets.get(&index).copied();
                anyhow::ensure!(
                    index_type == DPNBuiltInDataType::Target && available.contains(&(index_type, index)) && index_value.is_some(),
                    "{} TargetAt index operand must reference a preceding Constant target",
                    operation_context()
                );
                let indexed_length = indexed_lengths.get(&(array_type, array_index)).copied().with_context(|| {
                    format!("{} TargetAt source has no known downstream index bound", operation_context())
                })?;
                anyhow::ensure!(
                    (index_value.unwrap() as usize) < indexed_length,
                    "{} TargetAt index {} exceeds source length {}",
                    operation_context(),
                    index_value.unwrap(),
                    indexed_length
                );
            }
            DPNOpType::GetStateCommandResultSingle | DPNOpType::GetStateCommandResultArray | DPNOpType::GetStateCommandResultHash => {
                let command_index = operation.inputs[0] as usize;
                let command = definition.state_commands.get(command_index).with_context(|| {
                    format!("{} references missing state command {command_index}", operation_context())
                })?;
                let resolution_index = definition.state_command_resolution_indices[command_index];
                anyhow::ensure!(
                    (resolution_index > 0 && resolution_index <= definition_index) || (resolution_index == 0 && definition_index > 0),
                    "{} reads state command {command_index} before it is resolved",
                    operation_context()
                );
                let output_size = command.get_output_felt_size();
                match operation.op_type {
                    DPNOpType::GetStateCommandResultSingle => anyhow::ensure!(output_size >= 1, "{} reads an empty state command result", operation_context()),
                    DPNOpType::GetStateCommandResultHash => anyhow::ensure!(output_size >= 4, "{} reads a state command result shorter than four felts", operation_context()),
                    DPNOpType::GetStateCommandResultArray => {}
                    _ => unreachable!(),
                }
            }
            DPNOpType::HashNoPad | DPNOpType::Keccak256 => {
                for &operand in &operation.inputs {
                    validate_reference(operand, &available, ReferenceKind::Target).with_context(operation_context)?;
                }
            }
            DPNOpType::SumBits => {
                for &operand in &operation.inputs {
                    validate_reference(operand, &available, ReferenceKind::Bool).with_context(operation_context)?;
                }
            }
            DPNOpType::Secp256k1Verify => {
                for &operand in &operation.inputs[..32] {
                    validate_reference(operand, &available, ReferenceKind::U32).with_context(operation_context)?;
                }
                for &operand in &operation.inputs[32..] {
                    validate_reference(operand, &available, ReferenceKind::Target).with_context(operation_context)?;
                }
            }
            DPNOpType::BoolNot => validate_reference(operation.inputs[0], &available, ReferenceKind::Bool).with_context(operation_context)?,
            DPNOpType::BoolAnd | DPNOpType::BoolOr | DPNOpType::Xor | DPNOpType::Nor => {
                validate_reference(operation.inputs[0], &available, ReferenceKind::Bool).with_context(operation_context)?;
                validate_reference(operation.inputs[1], &available, ReferenceKind::Bool).with_context(operation_context)?;
            }
            DPNOpType::U32AndConstant | DPNOpType::U32OrConstant | DPNOpType::U32XorConstant => {
                validate_reference(operation.inputs[0], &available, ReferenceKind::U32).with_context(operation_context)?;
            }
            DPNOpType::U32And
            | DPNOpType::U32Or
            | DPNOpType::U32Xor
            | DPNOpType::U32ShiftLeft
            | DPNOpType::U32ShiftLeftConstantBitDistance
            | DPNOpType::U32ShiftLeftConstantValue
            | DPNOpType::U32ShiftRight
            | DPNOpType::U32ShiftRightConstantBitDistance
            | DPNOpType::U32ShiftRightConstantValue
            | DPNOpType::U32Add
            | DPNOpType::U32Sub
            | DPNOpType::U32Mul
            | DPNOpType::U32Div
            | DPNOpType::U32Mod
            | DPNOpType::U32Exp => {
                validate_reference(operation.inputs[0], &available, ReferenceKind::U32).with_context(operation_context)?;
                validate_reference(operation.inputs[1], &available, ReferenceKind::U32).with_context(operation_context)?;
            }
            DPNOpType::CastBool
            | DPNOpType::CastFelt
            | DPNOpType::CastU32
            | DPNOpType::UnaryInverse
            | DPNOpType::UnaryNegative
            | DPNOpType::DivRem4 => validate_reference(operation.inputs[0], &available, ReferenceKind::Target).with_context(operation_context)?,
            DPNOpType::HashTwoToOne
            | DPNOpType::Add
            | DPNOpType::Sub
            | DPNOpType::Mul
            | DPNOpType::Div
            | DPNOpType::Eq
            | DPNOpType::Lte
            | DPNOpType::Gte
            | DPNOpType::Gt
            | DPNOpType::Lt
            | DPNOpType::Exp
            | DPNOpType::ExpConstantPower
            | DPNOpType::ExpConstantBase
            | DPNOpType::Mod
            | DPNOpType::ModConstantDividend
            | DPNOpType::ModConstantDivisor => {
                for &operand in &operation.inputs {
                    validate_reference(operand, &available, ReferenceKind::Target).with_context(operation_context)?;
                }
            }
            DPNOpType::Select => {
                for &operand in &operation.inputs {
                    validate_reference(operand, &available, ReferenceKind::Target).with_context(operation_context)?;
                }
            }
            DPNOpType::U32InputTarget | DPNOpType::BoolInputTarget => {}
            DPNOpType::HashPad | DPNOpType::CalculateMerkleRoot | DPNOpType::GetStateQueryResult | DPNOpType::GetStateQueryResultSingle => {
                anyhow::bail!("{} uses an operation unsupported by downstream circuit construction", operation_context())
            }
        }

        let output_key = (operation.data_type, operation.index);
        anyhow::ensure!(available.insert(output_key), "{} assigns an already-defined output index", operation_context());
        match operation.op_type {
            DPNOpType::Constant if operation.data_type == DPNBuiltInDataType::Target => {
                constant_targets.insert(operation.index, operation.inputs[0]);
            }
            DPNOpType::SplitBits => {
                indexed_lengths.insert(output_key, operation.inputs[0] as usize);
            }
            DPNOpType::DivRem4 => {
                indexed_lengths.insert(output_key, 2);
            }
            DPNOpType::HashNoPad | DPNOpType::HashTwoToOne | DPNOpType::GetUserPublicKeyHash | DPNOpType::GetSessionProofTreeRoot => {
                indexed_lengths.insert(output_key, 4);
            }
            DPNOpType::Keccak256 => {
                indexed_lengths.insert(output_key, 8);
            }
            DPNOpType::InputTarget if operation.data_type == DPNBuiltInDataType::U32TargetArray => {
                indexed_lengths.insert(output_key, operation.inputs.len());
            }
            DPNOpType::GetStateCommandResultArray => {
                let command_index = operation.inputs[0] as usize;
                indexed_lengths.insert(output_key, definition.state_commands[command_index].get_output_felt_size());
            }
            DPNOpType::GetStateCommandResultHash => {
                indexed_lengths.insert(output_key, 4);
            }
            _ if matches!(operation.data_type, DPNBuiltInDataType::Target | DPNBuiltInDataType::Bool | DPNBuiltInDataType::U32Target) => {
                indexed_lengths.insert(output_key, 1);
            }
            _ => {}
        }
    }

    for (command_index, command) in definition.state_commands.iter().enumerate() {
        let resolution = definition.state_command_resolution_indices[command_index];
        let produced = definition.definitions[..resolution]
            .iter()
            .map(|operation| (operation.data_type, operation.index))
            .collect::<HashSet<_>>();
        for operand in command.get_inputs() {
            validate_reference(operand, &produced, ReferenceKind::AnyScalar)
                .with_context(|| format!("state command {command_index} has an invalid operand"))?;
        }
    }
    for &output in &definition.circuit_outputs {
        validate_reference(output, &available, ReferenceKind::Target).context("circuit output has an invalid operand")?;
    }
    for assertion in &definition.assertions {
        validate_reference(assertion.left, &available, ReferenceKind::Target).context("assertion left operand is invalid")?;
        validate_reference(assertion.right, &available, ReferenceKind::Target).context("assertion right operand is invalid")?;
    }
    for event in &definition.events {
        for operand in [event.condition, event.checkpoint_id, event.user_id, event.contract_id]
            .into_iter()
            .chain(event.data.iter().copied())
        {
            validate_reference(operand, &available, ReferenceKind::Target).context("event has an invalid operand")?;
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_operation_shape(operation: &psy_vm::dpn::ops::op_types::DPNIndexedVarDef, circuit_input_count: usize) -> anyhow::Result<()> {
    let exact = |expected: usize| -> anyhow::Result<()> {
        anyhow::ensure!(operation.inputs.len() == expected, "expected {expected} operands, got {}", operation.inputs.len());
        Ok(())
    };
    match operation.op_type {
        DPNOpType::InputTarget => {
            anyhow::ensure!(!operation.inputs.is_empty(), "InputTarget requires at least one input index");
            for &index in &operation.inputs {
                anyhow::ensure!((index as usize) < circuit_input_count, "input index {index} exceeds circuit input count {circuit_input_count}");
            }
            if operation.data_type != DPNBuiltInDataType::U32TargetArray {
                exact(1)?;
            }
        }
        DPNOpType::U32InputTarget | DPNOpType::BoolInputTarget => {
            exact(1)?;
            anyhow::ensure!((operation.inputs[0] as usize) < circuit_input_count, "input index {} exceeds circuit input count {circuit_input_count}", operation.inputs[0]);
        }
        DPNOpType::Constant | DPNOpType::ConstantU32 => exact(1)?,
        // The SDK compiler serializes boolean constants inline as
        // `inputs: vec![const_param]` (1 for ConstantTrue, 0 for
        // ConstantFalse), mirroring how `Constant`/`ConstantU32` carry
        // their value as the single operand. The VM (psy_vm exec.rs)
        // ignores this operand for ConstantTrue/ConstantFalse and
        // hardcodes the boolean, but it accepts the 1-operand shape the
        // compiler emits, so the structural check must require exactly
        // one operand (and the matching boolean value) rather than zero.
        DPNOpType::ConstantTrue | DPNOpType::ConstantFalse => {
            exact(1)?;
            let expected = if operation.op_type == DPNOpType::ConstantTrue { 1 } else { 0 };
            anyhow::ensure!(
                operation.inputs[0] == expected,
                "{} operand must be {}, got {}",
                operation.op_type,
                expected,
                operation.inputs[0]
            );
        }
        DPNOpType::GetUserId
        | DPNOpType::GetContractId
        | DPNOpType::GetCallerContractId
        | DPNOpType::GetCheckpointId
        | DPNOpType::GetNonce
        | DPNOpType::GetUserPublicKeyHash
        | DPNOpType::GetSessionProofTreeRoot => exact(0)?,
        DPNOpType::BoolNot
        | DPNOpType::DivRem4
        | DPNOpType::CastU32
        | DPNOpType::CastFelt
        | DPNOpType::CastBool
        | DPNOpType::UnaryInverse
        | DPNOpType::UnaryNegative
        | DPNOpType::GetStateCommandResultSingle
        | DPNOpType::GetStateCommandResultArray
        | DPNOpType::GetStateCommandResultHash => exact(1)?,
        DPNOpType::Add
        | DPNOpType::Sub
        | DPNOpType::Mul
        | DPNOpType::Div
        | DPNOpType::BoolAnd
        | DPNOpType::BoolOr
        | DPNOpType::Xor
        | DPNOpType::Nor
        | DPNOpType::Eq
        | DPNOpType::Lte
        | DPNOpType::Gte
        | DPNOpType::Gt
        | DPNOpType::Lt
        | DPNOpType::SplitBits
        | DPNOpType::TargetAt
        | DPNOpType::Exp
        | DPNOpType::ExpConstantPower
        | DPNOpType::ExpConstantBase
        | DPNOpType::Mod
        | DPNOpType::ModConstantDividend
        | DPNOpType::ModConstantDivisor
        | DPNOpType::U32And
        | DPNOpType::U32AndConstant
        | DPNOpType::U32Or
        | DPNOpType::U32OrConstant
        | DPNOpType::U32Xor
        | DPNOpType::U32XorConstant
        | DPNOpType::U32ShiftLeft
        | DPNOpType::U32ShiftLeftConstantBitDistance
        | DPNOpType::U32ShiftLeftConstantValue
        | DPNOpType::U32ShiftRight
        | DPNOpType::U32ShiftRightConstantBitDistance
        | DPNOpType::U32ShiftRightConstantValue
        | DPNOpType::U32Add
        | DPNOpType::U32Sub
        | DPNOpType::U32Mul
        | DPNOpType::U32Div
        | DPNOpType::U32Mod
        | DPNOpType::U32Exp => exact(2)?,
        DPNOpType::Select => exact(3)?,
        DPNOpType::HashTwoToOne => exact(8)?,
        DPNOpType::Secp256k1Verify => exact(36)?,
        DPNOpType::SumBits => {
            anyhow::ensure!(operation.inputs.len() <= 64, "SumBits supports at most 64 operands");
        }
        DPNOpType::HashNoPad | DPNOpType::HashPad | DPNOpType::Keccak256 | DPNOpType::CalculateMerkleRoot => {}
        DPNOpType::GetStateQueryResult | DPNOpType::GetStateQueryResultSingle => exact(1)?,
    }
    if operation.op_type == DPNOpType::ConstantU32 {
        anyhow::ensure!(operation.inputs[0] <= u32::MAX as u64, "ConstantU32 value exceeds u32 range");
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy)]
enum ReferenceKind {
    Target,
    Bool,
    U32,
    Indexable,
    AnyScalar,
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_reference(id: u64, available: &HashSet<(DPNBuiltInDataType, usize)>, kind: ReferenceKind) -> anyhow::Result<()> {
    let (data_type, index) = decode_indexed_op_id(id);
    let allowed = match kind {
        ReferenceKind::Target | ReferenceKind::AnyScalar => matches!(
            data_type,
            DPNBuiltInDataType::Target | DPNBuiltInDataType::Bool | DPNBuiltInDataType::U32Target
        ),
        ReferenceKind::Bool => matches!(data_type, DPNBuiltInDataType::Target | DPNBuiltInDataType::Bool | DPNBuiltInDataType::U32Target),
        ReferenceKind::U32 => matches!(data_type, DPNBuiltInDataType::Target | DPNBuiltInDataType::Bool | DPNBuiltInDataType::U32Target),
        ReferenceKind::Indexable => matches!(
            data_type,
            DPNBuiltInDataType::Target
                | DPNBuiltInDataType::Bool
                | DPNBuiltInDataType::U32Target
                | DPNBuiltInDataType::HashOut
                | DPNBuiltInDataType::HashOut160
                | DPNBuiltInDataType::TargetArray
                | DPNBuiltInDataType::BoolArray
                | DPNBuiltInDataType::U32TargetArray
        ),
    };
    anyhow::ensure!(allowed, "operand {id} has incompatible data type {data_type}");
    anyhow::ensure!(available.contains(&(data_type, index)), "operand {id} references unavailable {data_type} index {index}");
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_sdk_compiler_dir() -> anyhow::Result<PathBuf> {
    if let Some(override_dir) = env::var_os("PSY_SDK_DIR") {
        let canonical_override = fs::canonicalize(&override_dir).with_context(|| {
            format!("failed to canonicalize PSY_SDK_DIR {}", Path::new(&override_dir).display())
        })?;
        return resolve_explicit_sdk_compiler_dir(&canonical_override);
    }

    let executable = env::current_exe().context("failed to resolve the current executable path")?;
    let executable = fs::canonicalize(&executable)
        .with_context(|| format!("failed to canonicalize current executable {}", executable.display()))?;
    let sidecar = executable
        .parent()
        .context("current executable has no parent directory")?
        .join("psy-sdk-compiler");
    resolve_sidecar_compiler_dir(&sidecar).with_context(|| {
        format!(
            "trusted compiler sidecar {} is missing psy_compiler.mjs, wasm-binary.mjs, or a valid .compiler-artifact.json; set PSY_SDK_DIR to an explicit SDK directory",
            sidecar.display()
        )
    })
}

/// Resolve the compiler module directory for an explicit `PSY_SDK_DIR`.
///
/// In a real SDK package root the provenance `.compiler-artifact.json` lives
/// at the root while `psy_compiler.mjs`/`wasm-binary.mjs` live either at the
/// root or under `dist/local-web-compiler`. Provenance is therefore always
/// validated against the explicit root's artifact — never the module
/// directory — and the returned path is the directory that actually holds the
/// module files. No cwd/ancestor search is performed.
#[cfg(not(target_arch = "wasm32"))]
fn resolve_explicit_sdk_compiler_dir(base: &Path) -> anyhow::Result<PathBuf> {
    let artifact_path = base.join(".compiler-artifact.json");
    validate_compiler_artifact(&artifact_path)
        .with_context(|| format!("invalid compiler provenance for {}", base.display()))?;

    if has_compiler_module(base) {
        return fs::canonicalize(base)
            .with_context(|| format!("failed to canonicalize compiler directory {}", base.display()));
    }
    let dist_candidate = base.join("dist/local-web-compiler");
    if has_compiler_module(&dist_candidate) {
        return fs::canonicalize(&dist_candidate).with_context(|| {
            format!("failed to canonicalize compiler directory {}", dist_candidate.display())
        });
    }
    anyhow::bail!(
        "PSY_SDK_DIR {} does not contain psy_compiler.mjs and wasm-binary.mjs at its root or dist/local-web-compiler",
        base.display()
    )
}

/// Resolve the executable-relative trusted sidecar, where all three files
/// (`psy_compiler.mjs`, `wasm-binary.mjs`, `.compiler-artifact.json`) live in
/// a single directory.
#[cfg(not(target_arch = "wasm32"))]
fn resolve_sidecar_compiler_dir(sidecar: &Path) -> anyhow::Result<PathBuf> {
    for required in ["psy_compiler.mjs", "wasm-binary.mjs"] {
        let required_path = sidecar.join(required);
        if !required_path.is_file() {
            anyhow::bail!("missing required compiler sidecar file {}", required_path.display());
        }
    }
    let artifact_path = sidecar.join(".compiler-artifact.json");
    validate_compiler_artifact(&artifact_path)
        .with_context(|| format!("invalid compiler provenance for {}", sidecar.display()))?;
    fs::canonicalize(sidecar)
        .with_context(|| format!("failed to canonicalize compiler directory {}", sidecar.display()))
}

#[cfg(not(target_arch = "wasm32"))]
fn has_compiler_module(dir: &Path) -> bool {
    dir.join("psy_compiler.mjs").is_file() && dir.join("wasm-binary.mjs").is_file()
}

/// Provenance recorded next to the SDK compiler sidecar by the SDK build.
///
/// Both fields are emitted by `psy-sdk`'s `build-wasm-binary.ts`:
/// `compilerRevision` is a git object id (40 hex digits for SHA-1 repos,
/// 64 for SHA-256 repos) and `compilerSourcesHash` is a SHA-256 digest
/// (64 hex digits). Both must be non-empty lowercase hexadecimal of the
/// expected length so a malformed or tampered sidecar is rejected before
/// the compiler is invoked.
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompilerArtifact {
    compiler_revision: String,
    compiler_sources_hash: String,
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_compiler_artifact(artifact_path: &Path) -> anyhow::Result<()> {
    let contents = fs::read_to_string(artifact_path)
        .with_context(|| format!("failed to read compiler artifact {}", artifact_path.display()))?;
    let artifact: CompilerArtifact = serde_json::from_str(&contents)
        .with_context(|| format!("compiler artifact {} is not valid JSON", artifact_path.display()))?;

    if !is_lowercase_hex(&artifact.compiler_revision, &[40, 64]) {
        anyhow::bail!(
            "compiler artifact {} has invalid compilerRevision {:?}; expected 40 or 64 lowercase hex digits",
            artifact_path.display(),
            artifact.compiler_revision,
        );
    }
    if !is_lowercase_hex(&artifact.compiler_sources_hash, &[64]) {
        anyhow::bail!(
            "compiler artifact {} has invalid compilerSourcesHash {:?}; expected 64 lowercase hex digits",
            artifact_path.display(),
            artifact.compiler_sources_hash,
        );
    }
    Ok(())
}

/// `true` iff `value` is non-empty and consists only of lowercase hex digits
/// with one of the `allowed_lengths` (in hex digits). Rejects uppercase,
/// non-hex characters, and any other length so a malformed or tampered
/// provenance field cannot slip through.
#[cfg(not(target_arch = "wasm32"))]
fn is_lowercase_hex(value: &str, allowed_lengths: &[usize]) -> bool {
    let len = value.len();
    if len == 0 || !allowed_lengths.contains(&len) {
        return false;
    }
    value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(not(target_arch = "wasm32"))]
fn collect_project_input(root_input: &Path) -> anyhow::Result<ProjectInput> {
    let root_file = resolve_crate_root(root_input)?;
    let root_dir = root_file.parent().unwrap_or_else(|| Path::new("."));
    let root_source = fs::read_to_string(&root_file)
        .with_context(|| format!("failed to read crate root {}", root_input.display()))?;

    let mut source_paths = Vec::new();
    collect_source_paths(root_dir, &mut source_paths)?;
    source_paths.sort();
    anyhow::ensure!(
        source_paths.iter().any(|path| path == &root_file),
        "crate root was not found while collecting project sources"
    );

    let entry = vec!["main".to_string()];
    let mut files = Vec::with_capacity(source_paths.len().max(1));
    files.push((entry.clone(), root_source));

    let mut logical_paths = HashSet::new();
    logical_paths.insert(entry.clone());
    for source_path in source_paths {
        if source_path == root_file {
            continue;
        }
        let module_path = module_path_for_source(root_dir, &source_path)
            .with_context(|| format!("failed to map crate module {}", source_path.display()))?;
        anyhow::ensure!(
            logical_paths.insert(module_path.clone()),
            "multiple crate sources map to the same compiler module path {:?}",
            module_path
        );
        let source = fs::read_to_string(&source_path)
            .with_context(|| format!("failed to read crate module {}", source_path.display()))?;
        files.push((module_path, source));
    }

    Ok(ProjectInput {
        entry,
        method_names: None,
        files,
    })
}

#[cfg(not(target_arch = "wasm32"))]
fn resolve_crate_root(root_input: &Path) -> anyhow::Result<PathBuf> {
    if root_input.is_file() {
        anyhow::ensure!(is_psy_source(root_input), "crate root must have a .psy or .psy.rs extension");
        return Ok(root_input.to_path_buf());
    }
    anyhow::ensure!(root_input.is_dir(), "crate source path does not exist or is not readable");

    let relative_candidates = [
        "src/main.psy",
        "src/lib.psy",
        "src/main.psy.rs",
        "src/lib.psy.rs",
        "main.psy",
        "lib.psy",
        "main.psy.rs",
        "lib.psy.rs",
    ];
    let candidates = relative_candidates
        .into_iter()
        .map(|relative| root_input.join(relative))
        .filter(|candidate| candidate.is_file())
        .collect::<Vec<_>>();

    match candidates.as_slice() {
        [root] => Ok(root.clone()),
        [] => anyhow::bail!("crate directory contains no main/lib .psy or .psy.rs root; pass the root file explicitly"),
        _ => anyhow::bail!("crate directory contains multiple possible roots; pass the intended root file explicitly"),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn collect_source_paths(directory: &Path, output: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    let mut entries = fs::read_dir(directory)
        .with_context(|| format!("failed to read crate source directory {}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("failed to enumerate crate source directory {}", directory.display()))?;
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let file_type = entry
            .file_type()
            .with_context(|| format!("failed to inspect crate source entry {}", entry.path().display()))?;
        anyhow::ensure!(
            !file_type.is_symlink(),
            "crate source tree contains unsupported symbolic link {}",
            entry.path().display()
        );
        if file_type.is_dir() {
            collect_source_paths(&entry.path(), output)?;
        } else if file_type.is_file() && is_psy_source(&entry.path()) {
            output.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(not(target_arch = "wasm32"))]
fn is_psy_source(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(".psy") || name.ends_with(".psy.rs"))
}

#[cfg(not(target_arch = "wasm32"))]
fn module_path_for_source(root_dir: &Path, source_path: &Path) -> anyhow::Result<Vec<String>> {
    let relative = source_path
        .strip_prefix(root_dir)
        .context("crate module is outside the crate root directory")?;
    let file_name = relative
        .file_name()
        .and_then(|name| name.to_str())
        .context("crate module file name is not valid UTF-8")?;
    let stem = file_name
        .strip_suffix(".psy.rs")
        .or_else(|| file_name.strip_suffix(".psy"))
        .context("crate module must have a .psy or .psy.rs extension")?;

    let mut module_path = relative
        .parent()
        .map(|parent| {
            parent
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_str()
                        .map(str::to_owned)
                        .context("crate module path component is not valid UTF-8")
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    if stem != "mod" {
        module_path.push(stem.to_string());
    }

    anyhow::ensure!(!module_path.is_empty(), "crate module has an empty compiler path");
    anyhow::ensure!(module_path.iter().all(|component| !component.is_empty()), "crate module has an empty compiler path component");
    Ok(module_path)
}

/// Simulate a contract method without generating proofs.
pub fn simulate_method(
    contract_output: &ContractOutput,
    method_name: &str,
    inputs: &[u64],
    context: &ExecutionContext,
) -> anyhow::Result<SimulationResult> {
    let abi_method = contract_output
        .abi
        .contract
        .methods
        .iter()
        .find(|method| method.name == method_name)
        .ok_or_else(|| {
            let available = contract_output
                .abi
                .contract
                .methods
                .iter()
                .map(|method| method.name.as_str())
                .collect::<Vec<_>>();
            anyhow::anyhow!("Method '{}' not found. Available: {:?}", method_name, available)
        })?;

    let circuit_def = contract_output
        .circuit_definitions
        .iter()
        .find(|definition| definition.method_id == abi_method.method_id)
        .ok_or_else(|| anyhow::anyhow!("No circuit definition for method '{}' (method_id={})", method_name, abi_method.method_id))?;

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

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

    #[test]
    fn nested_module_paths_remain_distinct() {
        let root = Path::new("src");
        assert_eq!(
            module_path_for_source(root, Path::new("src/foo/types.psy")).unwrap(),
            vec!["foo".to_string(), "types".to_string()]
        );
        assert_eq!(
            module_path_for_source(root, Path::new("src/bar/types.psy.rs")).unwrap(),
            vec!["bar".to_string(), "types".to_string()]
        );
        assert_eq!(
            module_path_for_source(root, Path::new("src/name/mod.psy")).unwrap(),
            vec!["name".to_string()]
        );
        assert_eq!(
            module_path_for_source(root, Path::new("src/name/mod.psy.rs")).unwrap(),
            vec!["name".to_string()]
        );
    }

    #[test]
    fn malformed_definition_returns_error_before_downstream_indexing() {
        let malformed = DPNFunctionCircuitDefinition {
            name: "malformed".to_string(),
            method_id: 1,
            circuit_inputs: Vec::new(),
            circuit_outputs: Vec::new(),
            state_commands: Vec::new(),
            state_command_resolution_indices: Vec::new(),
            assertions: Vec::new(),
            definitions: vec![psy_vm::dpn::ops::op_types::DPNIndexedVarDef {
                data_type: DPNBuiltInDataType::Target,
                index: 0,
                op_type: DPNOpType::Add,
                inputs: vec![0],
            }],
            events: Vec::new(),
        };

        let error = validate_circuit_definition(&malformed).unwrap_err();
        let error_chain = format!("{error:#}");
        assert!(
            error_chain.contains("expected 2 operands"),
            "unexpected error: {error_chain}"
        );
    }

    fn mk_var_def(op_type: DPNOpType, data_type: DPNBuiltInDataType, inputs: Vec<u64>) -> psy_vm::dpn::ops::op_types::DPNIndexedVarDef {
        psy_vm::dpn::ops::op_types::DPNIndexedVarDef {
            data_type,
            index: 0,
            op_type,
            inputs,
        }
    }

    #[test]
    fn validate_operation_shape_accepts_compiler_constant_true() {
        // The SDK compiler serializes ConstantTrue inline as inputs: vec![1]
        // (const_param = 1). The VM (psy_vm exec.rs) ignores this operand and
        // hardcodes the boolean, accepting the 1-operand shape the compiler emits.
        let op = mk_var_def(DPNOpType::ConstantTrue, DPNBuiltInDataType::Bool, vec![1]);
        validate_operation_shape(&op, 0)
            .expect("compiler-emitted ConstantTrue (1 operand, value 1) must pass the shape check");
    }

    #[test]
    fn validate_operation_shape_accepts_compiler_constant_false() {
        let op = mk_var_def(DPNOpType::ConstantFalse, DPNBuiltInDataType::Bool, vec![0]);
        validate_operation_shape(&op, 0)
            .expect("compiler-emitted ConstantFalse (1 operand, value 0) must pass the shape check");
    }

    #[test]
    fn validate_operation_shape_rejects_constant_true_with_zero_operands() {
        let op = mk_var_def(DPNOpType::ConstantTrue, DPNBuiltInDataType::Bool, vec![]);
        let err = validate_operation_shape(&op, 0).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("expected 1 operands") && chain.contains("got 0"),
            "zero operands must be rejected with a precise count error; got: {chain}"
        );
    }

    #[test]
    fn validate_operation_shape_rejects_constant_true_with_extra_operands() {
        let op = mk_var_def(DPNOpType::ConstantTrue, DPNBuiltInDataType::Bool, vec![1, 0]);
        let err = validate_operation_shape(&op, 0).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("expected 1 operands") && chain.contains("got 2"),
            "extra operands must be rejected with a precise count error; got: {chain}"
        );
    }

    #[test]
    fn validate_operation_shape_rejects_constant_true_with_wrong_value() {
        // ConstantTrue must carry value 1; value 0 is really a ConstantFalse.
        let op = mk_var_def(DPNOpType::ConstantTrue, DPNBuiltInDataType::Bool, vec![0]);
        let err = validate_operation_shape(&op, 0).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("ConstantTrue operand must be 1"),
            "a ConstantTrue carrying 0 must be rejected with a precise value error; got: {chain}"
        );
    }

    #[test]
    fn validate_operation_shape_rejects_constant_false_with_wrong_value() {
        let op = mk_var_def(DPNOpType::ConstantFalse, DPNBuiltInDataType::Bool, vec![1]);
        let err = validate_operation_shape(&op, 0).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("ConstantFalse operand must be 0"),
            "a ConstantFalse carrying 1 must be rejected with a precise value error; got: {chain}"
        );
    }

    #[test]
    fn validate_circuit_definition_accepts_compiler_constant_true() {
        // Mirrors the structural path `test_simulate_basic_contract` exercises:
        // the compiler emits a ConstantTrue definition (Bool, inputs=[1]) that an
        // assertion references. The full circuit definition must validate.
        use psy_vm::dpn::ops::op_types::{encode_indexed_op_id, DPNAssertEqInfoIndexed};
        let constant_true = psy_vm::dpn::ops::op_types::DPNIndexedVarDef {
            data_type: DPNBuiltInDataType::Bool,
            index: 0,
            op_type: DPNOpType::ConstantTrue,
            inputs: vec![1],
        };
        let definition = DPNFunctionCircuitDefinition {
            name: "assert_true".to_string(),
            method_id: 1,
            circuit_inputs: Vec::new(),
            circuit_outputs: Vec::new(),
            state_commands: Vec::new(),
            state_command_resolution_indices: Vec::new(),
            assertions: vec![DPNAssertEqInfoIndexed {
                left: encode_indexed_op_id(DPNBuiltInDataType::Bool, 0),
                right: encode_indexed_op_id(DPNBuiltInDataType::Bool, 0),
                message: "must be true".to_string(),
            }],
            definitions: vec![constant_true],
            events: Vec::new(),
        };
        validate_circuit_definition(&definition)
            .expect("a circuit definition using the compiler-emitted ConstantTrue shape must validate");
    }

    #[test]
    fn validate_contract_function_vm_type_accepts_canonical_constant() {
        // Compiler output must use the shared canonical type.
        validate_contract_function_vm_type(1, VM_TYPE_STANRDARD_DAPEN_V1)
            .expect("the canonical DAPEN VM type constant must pass the compile bridge gate");
    }

    #[test]
    fn validate_contract_function_vm_type_rejects_legacy_zero() {
        // Legacy compiler output must fail before proving.
        let err = validate_contract_function_vm_type(7, 0).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("method_id 7"),
            "the rejection must name the offending method_id; got: {chain}"
        );
        assert!(
            chain.contains("non-canonical vm_type 0"),
            "the rejection must report the non-canonical vm_type value; got: {chain}"
        );
        assert!(
            chain.contains(&format!("expected {}", VM_TYPE_STANRDARD_DAPEN_V1)),
            "the rejection must name the expected canonical constant; got: {chain}"
        );
    }

    #[test]
    fn validate_contract_function_vm_type_rejects_unknown_vm_type() {
        // New VM variants require an explicit bridge upgrade.
        let err = validate_contract_function_vm_type(3, VM_TYPE_STANRDARD_DAPEN_V1 + 1).unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            chain.contains("non-canonical vm_type"),
            "a non-canonical vm_type must be rejected; got: {chain}"
        );
        assert!(
            chain.contains("method_id 3"),
            "the rejection must name the offending method_id; got: {chain}"
        );
    }

    #[test]
    fn test_simulate_basic_contract() {
        let source = r#"
            use std::prelude::*;

            #[contract]
            #[derive(Storage)]
            pub struct TestContract {
                pub value: Felt,
            }

            impl TestContractRef {
                #[contract::write_method]
                pub fn set_value(new_value: Felt) {
                    let c = TestContractRef::new(ContractMetadata::current());
                    c.value = new_value;
                }
            }
        "#;

        let contract_output = compile_contract_output(source).expect("compilation should succeed");
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

    // --- SDK compiler sidecar provenance gate ---

    const VALID_REVISION_40: &str = "d467279ddab4e57dd897670f09f4a8371a1123e2";
    const VALID_REVISION_64: &str = "268231b5d78ba6b35f08604f3b6bcef815386750fd416e59d7db1ba396c8a365";
    const VALID_SOURCES_HASH: &str = "268231b5d78ba6b35f08604f3b6bcef815386750fd416e59d7db1ba396c8a365";

    fn write_artifact(dir: &Path, revision: &str, sources_hash: &str) {
        let payload = serde_json::json!({
            "compilerRevision": revision,
            "compilerSourcesHash": sources_hash,
        });
        std::fs::write(dir.join(".compiler-artifact.json"), payload.to_string()).unwrap();
    }

    fn touch_sidecar_files(dir: &Path) {
        std::fs::write(dir.join("psy_compiler.mjs"), b"/* compiler */").unwrap();
        std::fs::write(dir.join("wasm-binary.mjs"), b"/* wasm */").unwrap();
    }

    #[test]
    fn valid_artifact_passes_provenance_gate() {
        let dir = tempfile::TempDir::new().unwrap();
        write_artifact(dir.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        let artifact_path = dir.path().join(".compiler-artifact.json");
        validate_compiler_artifact(&artifact_path)
            .expect("a real SHA-1 compilerRevision plus a 64-hex compilerSourcesHash must be accepted");
    }

    #[test]
    fn valid_sha256_revision_passes_provenance_gate() {
        let dir = tempfile::TempDir::new().unwrap();
        write_artifact(dir.path(), VALID_REVISION_64, VALID_SOURCES_HASH);
        let artifact_path = dir.path().join(".compiler-artifact.json");
        validate_compiler_artifact(&artifact_path)
            .expect("a 64-hex (SHA-256) compilerRevision plus a 64-hex compilerSourcesHash must be accepted");
    }

    #[test]
    fn missing_artifact_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("failed to read compiler artifact"),
            "missing artifact should surface a read error with the path; got: {chain}"
        );
        assert!(
            chain.contains(artifact_path.to_str().unwrap()),
            "error must carry the candidate artifact path; got: {chain}"
        );
    }

    #[test]
    fn malformed_artifact_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        std::fs::write(dir.path().join(".compiler-artifact.json"), b"{ not valid json ").unwrap();
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("not valid JSON"),
            "malformed artifact should surface a parse error; got: {chain}"
        );
        assert!(
            chain.contains(artifact_path.to_str().unwrap()),
            "error must carry the candidate artifact path; got: {chain}"
        );
    }

    #[test]
    fn illegal_revision_hash_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // Wrong length: 8 hex digits, not 40 or 64.
        write_artifact(dir.path(), "d467279d", VALID_SOURCES_HASH);
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compilerRevision"),
            "a too-short revision must be rejected; got: {chain}"
        );
    }

    #[test]
    fn uppercase_revision_hash_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // Valid length but uppercase hex must be rejected (strict lowercase).
        write_artifact(dir.path(), &VALID_REVISION_40.to_uppercase(), VALID_SOURCES_HASH);
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compilerRevision"),
            "uppercase hex must be rejected; got: {chain}"
        );
    }

    #[test]
    fn illegal_sources_hash_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        // 64 chars but not all lowercase hex (contains 'g').
        let bad_hash = "g68231b5d78ba6b35f08604f3b6bcef815386750fd416e59d7db1ba396c8a365";
        write_artifact(dir.path(), VALID_REVISION_40, bad_hash);
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compilerSourcesHash"),
            "a non-hex sources hash must be rejected; got: {chain}"
        );
    }

    #[test]
    fn uppercase_sources_hash_is_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        write_artifact(dir.path(), VALID_REVISION_40, &VALID_SOURCES_HASH.to_uppercase());
        let artifact_path = dir.path().join(".compiler-artifact.json");
        let error = validate_compiler_artifact(&artifact_path).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compilerSourcesHash"),
            "uppercase hex sources hash must be rejected; got: {chain}"
        );
    }

    #[test]
    fn resolve_compiler_dir_accepts_valid_sidecar() {
        let dir = tempfile::TempDir::new().unwrap();
        touch_sidecar_files(dir.path());
        write_artifact(dir.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        let resolved = resolve_sidecar_compiler_dir(dir.path())
            .expect("a sidecar with both .mjs files and a valid artifact must resolve");
        assert_eq!(resolved, std::fs::canonicalize(dir.path()).unwrap());
    }

    #[test]
    fn resolve_compiler_dir_rejects_missing_sidecar_files() {
        let dir = tempfile::TempDir::new().unwrap();
        // Valid artifact but no psy_compiler.mjs / wasm-binary.mjs.
        write_artifact(dir.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        let error = resolve_sidecar_compiler_dir(dir.path()).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("missing required compiler sidecar file"),
            "missing .mjs files must be rejected before provenance is checked; got: {chain}"
        );
    }

    #[test]
    fn resolve_compiler_dir_rejects_invalid_provenance() {
        let dir = tempfile::TempDir::new().unwrap();
        touch_sidecar_files(dir.path());
        // Both .mjs present, but the artifact is malformed JSON.
        std::fs::write(dir.path().join(".compiler-artifact.json"), b"{}").unwrap();
        let error = resolve_sidecar_compiler_dir(dir.path()).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compiler provenance for"),
            "a sidecar with present .mjs but bad provenance must be rejected with context; got: {chain}"
        );
    }

    #[test]
    fn resolve_explicit_root_layout_accepts_split_artifact() {
        // Real SDK package layout: .compiler-artifact.json at the root,
        // module files under dist/local-web-compiler.
        let root = tempfile::TempDir::new().unwrap();
        write_artifact(root.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        let dist = root.path().join("dist/local-web-compiler");
        std::fs::create_dir_all(&dist).unwrap();
        touch_sidecar_files(&dist);
        let resolved = resolve_explicit_sdk_compiler_dir(root.path())
            .expect("explicit SDK root with artifact at root and module under dist/local-web-compiler must resolve");
        assert_eq!(resolved, std::fs::canonicalize(&dist).unwrap());
    }

    #[test]
    fn resolve_explicit_root_layout_accepts_colocated_module() {
        // Explicit root where the artifact and the module files are colocated.
        let root = tempfile::TempDir::new().unwrap();
        write_artifact(root.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        touch_sidecar_files(root.path());
        let resolved = resolve_explicit_sdk_compiler_dir(root.path())
            .expect("explicit SDK root with artifact and module colocated must resolve");
        assert_eq!(resolved, std::fs::canonicalize(root.path()).unwrap());
    }

    #[test]
    fn resolve_explicit_root_layout_rejects_missing_root_artifact() {
        // Module present under dist/local-web-compiler but no root artifact:
        // provenance is validated against the explicit root, not the module
        // directory, so this must fail.
        let root = tempfile::TempDir::new().unwrap();
        let dist = root.path().join("dist/local-web-compiler");
        std::fs::create_dir_all(&dist).unwrap();
        touch_sidecar_files(&dist);
        let error = resolve_explicit_sdk_compiler_dir(root.path()).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compiler provenance for"),
            "missing root artifact must fail the provenance gate with context; got: {chain}"
        );
    }

    #[test]
    fn resolve_explicit_root_layout_rejects_bad_root_artifact() {
        // Module present under dist/local-web-compiler, but the root artifact
        // is malformed: the provenance gate fires against the root artifact.
        let root = tempfile::TempDir::new().unwrap();
        std::fs::write(root.path().join(".compiler-artifact.json"), b"{}").unwrap();
        let dist = root.path().join("dist/local-web-compiler");
        std::fs::create_dir_all(&dist).unwrap();
        touch_sidecar_files(&dist);
        let error = resolve_explicit_sdk_compiler_dir(root.path()).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("invalid compiler provenance for"),
            "a bad root artifact must be rejected even when the module is present under dist; got: {chain}"
        );
    }

    #[test]
    fn resolve_explicit_root_layout_rejects_missing_module() {
        // Valid root artifact but no module files anywhere: must report the
        // missing module rather than silently passing.
        let root = tempfile::TempDir::new().unwrap();
        write_artifact(root.path(), VALID_REVISION_40, VALID_SOURCES_HASH);
        let error = resolve_explicit_sdk_compiler_dir(root.path()).unwrap_err();
        let chain = format!("{error:#}");
        assert!(
            chain.contains("does not contain psy_compiler.mjs and wasm-binary.mjs"),
            "missing module files must be reported; got: {chain}"
        );
    }

}
