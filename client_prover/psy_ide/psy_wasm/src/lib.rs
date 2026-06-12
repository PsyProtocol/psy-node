use std::sync::Mutex;

use psy_compiler::{abi::ContractABI, output::serialize::ContractOutput, sdk_key::context::SDKKeyCompileOutput};
use psy_vm::dpn::{
    contract::dapen_fc_to_cfc_code_definition,
    eval::executor::{ExecutionContext, InMemoryStateBackend, StateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

// ---------------------------------------------------------------------------
// Global chain state (one per WASM instance)
// ---------------------------------------------------------------------------

static CHAIN: Mutex<Option<InMemoryChain>> = Mutex::new(None);

fn with_chain<F, R>(f: F) -> Result<R, JsValue>
where
    F: FnOnce(&mut InMemoryChain) -> Result<R, String>,
{
    let mut guard = CHAIN.lock().map_err(|e| JsValue::from_str(&e.to_string()))?;
    let chain = guard
        .as_mut()
        .ok_or_else(|| JsValue::from_str("Chain not initialized. Call init_chain() first."))?;
    f(chain).map_err(|e| JsValue::from_str(&e))
}

// ---------------------------------------------------------------------------
// Chain state types
// ---------------------------------------------------------------------------

struct InMemoryChain {
    accounts: Vec<Account>,
    contracts: Vec<DeployedContract>,
    state: InMemoryStateBackend,
    transaction_log: Vec<TransactionRecord>,
    next_user_id: u64,
    next_contract_id: u64,
    checkpoint_id: u64,
}

struct Account {
    user_id: u64,
    name: String,
}

struct DeployedContract {
    contract_id: u64,
    name: String,
    deployer_id: u64,
    abi: ContractABI,
    circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
    state_tree_height: u16,
}

#[derive(Serialize, Clone)]
struct TransactionRecord {
    tx_id: u64,
    caller_id: u64,
    caller_name: String,
    contract_id: u64,
    contract_name: String,
    method_name: String,
    args: Vec<u64>,
    success: bool,
    failure_message: Option<String>,
    state_reads: usize,
    state_writes: usize,
    total_ops: usize,
    outputs: Vec<u64>,
}

impl InMemoryChain {
    fn new() -> Self {
        Self {
            accounts: Vec::new(),
            contracts: Vec::new(),
            state: InMemoryStateBackend::new(),
            transaction_log: Vec::new(),
            next_user_id: 1,
            next_contract_id: 1,
            checkpoint_id: 100,
        }
    }

    fn create_account(&mut self, name: &str) -> Account {
        let account = Account {
            user_id: self.next_user_id,
            name: name.to_string(),
        };
        self.next_user_id += 1;
        self.accounts.push(account.clone());
        account
    }

    fn find_account(&self, user_id: u64) -> Option<&Account> {
        self.accounts.iter().find(|a| a.user_id == user_id)
    }

    fn find_contract(&self, contract_id: u64) -> Option<&DeployedContract> {
        self.contracts.iter().find(|c| c.contract_id == contract_id)
    }
}

impl Clone for Account {
    fn clone(&self) -> Self {
        Account {
            user_id: self.user_id,
            name: self.name.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Serializable types for JS
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JsCompileResult {
    success: bool,
    error: Option<String>,
    /// Byte offset in the source where the error occurred (extracted from error
    /// messages).
    error_offset: Option<usize>,
    /// Module path where the error occurred (if determinable).
    error_module: Option<Vec<String>>,
    abi: Option<JsContractABI>,
    spec_abi: Option<serde_json::Value>,
    state_tree_height: Option<u16>,
    method_count: Option<usize>,
    circuit_definitions: Option<Vec<DPNFunctionCircuitDefinition>>,
}

#[derive(Serialize)]
struct JsInterpretResult {
    success: bool,
    error: Option<String>,
    error_offset: Option<usize>,
    error_module: Option<Vec<String>>,
    execution_result: Option<serde_json::Value>,
    abi: Option<JsContractABI>,
    spec_abi: Option<serde_json::Value>,
    state_tree_height: Option<u16>,
    method_count: Option<usize>,
    circuit_definitions: Option<Vec<DPNFunctionCircuitDefinition>>,
}

#[derive(Deserialize)]
struct InterpretRequest {
    #[serde(default)]
    method_name: Option<String>,
    #[serde(default)]
    inputs: Vec<u64>,
    #[serde(default)]
    execution_context: Option<ExecutionContextInput>,
    #[serde(default)]
    initial_state: Option<InitialStateInput>,
}

#[derive(Deserialize)]
struct ExecutionContextInput {
    #[serde(default)]
    user_id: Option<u64>,
    #[serde(default)]
    contract_id: Option<u64>,
    #[serde(default)]
    caller_contract_id: Option<u64>,
    #[serde(default)]
    checkpoint_id: Option<u64>,
    #[serde(default)]
    nonce: Option<u64>,
    #[serde(default)]
    user_public_key_hash: Option<[u64; 4]>,
}

#[derive(Deserialize, Default)]
struct InitialStateInput {
    #[serde(default)]
    slots: Vec<SlotValueInput>,
    #[serde(default)]
    hashes: Vec<HashValueInput>,
    #[serde(default)]
    deployers: Vec<DeployerInput>,
    #[serde(default)]
    checkpoint_stats: Vec<CheckpointVecInput>,
    #[serde(default)]
    contract_leaves: Vec<ContractLeafInput>,
    #[serde(default)]
    checkpoint_global_state_roots: Vec<CheckpointVecInput>,
    #[serde(default)]
    imt: Vec<ImtValueInput>,
}

#[derive(Deserialize)]
struct SlotValueInput {
    user_id: u64,
    contract_id: u64,
    slot_index: u64,
    value: u64,
}

#[derive(Deserialize)]
struct HashValueInput {
    user_id: u64,
    contract_id: u64,
    slot_index: u64,
    value: [u64; 4],
}

#[derive(Deserialize)]
struct DeployerInput {
    contract_id: u64,
    deployer: [u64; 4],
}

#[derive(Deserialize)]
struct CheckpointVecInput {
    checkpoint_id: u64,
    values: Vec<u64>,
}

#[derive(Deserialize)]
struct ContractLeafInput {
    contract_id: u64,
    values: Vec<u64>,
}

#[derive(Deserialize)]
struct ImtValueInput {
    user_id: u64,
    contract_id: u64,
    key: [u64; 4],
    value: [u64; 4],
}

/// Try to extract a byte offset from an error message like "... at offset 123"
fn extract_error_offset(error_msg: &str) -> Option<usize> {
    // Match "at offset N" or "offset N"
    let re_patterns = ["at offset ", "offset "];
    for pattern in &re_patterns {
        if let Some(pos) = error_msg.rfind(pattern) {
            let after = &error_msg[pos + pattern.len()..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num_str.parse::<usize>() {
                return Some(n);
            }
        }
    }
    None
}

#[derive(Serialize, Clone)]
struct JsContractABI {
    contract_name: String,
    state_tree_height: u16,
    state_layout: Vec<JsABIStateField>,
    methods: Vec<JsABIMethod>,
}

#[derive(Serialize, Clone)]
struct JsABIStateField {
    name: String,
    field_type: String,
    offset: usize,
    felt_size: usize,
    is_array: bool,
    array_count: Option<usize>,
    element_type: Option<String>,
    element_felt_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub_fields: Option<Vec<JsABISubField>>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    is_imt_map: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    imt_key_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    imt_value_type: Option<String>,
}

#[derive(Serialize, Clone)]
struct JsABISubField {
    name: String,
    offset: usize,
    felt_size: usize,
}

#[derive(Serialize, Clone)]
struct JsABIMethod {
    name: String,
    method_id: u32,
    params: Vec<JsABIParam>,
    is_view: bool,
}

#[derive(Serialize, Clone)]
struct JsABIParam {
    name: String,
    param_type: String,
    felt_size: usize,
}

#[derive(Serialize)]
struct JsAccount {
    user_id: u64,
    name: String,
}

#[derive(Serialize)]
struct JsDeployedContract {
    contract_id: u64,
    name: String,
    deployer_id: u64,
    abi: JsContractABI,
}

#[derive(Serialize)]
struct JsDeployResult {
    success: bool,
    error: Option<String>,
    contract_id: Option<u64>,
}

#[derive(Serialize)]
struct JsCallResult {
    success: bool,
    error: Option<String>,
    failure_message: Option<String>,
    state_reads: Vec<JsStateRead>,
    state_writes: Vec<JsStateWrite>,
    outputs: Vec<u64>,
    total_ops: usize,
}

#[derive(Serialize)]
struct JsStateRead {
    command_index: usize,
    command_type: String,
    user_id: u64,
    contract_id: u64,
    slot_index: u64,
    value: Vec<u64>,
}

#[derive(Serialize)]
struct JsStateWrite {
    command_index: usize,
    command_type: String,
    user_id: u64,
    contract_id: u64,
    slot_index: u64,
    old_value: Vec<u64>,
    new_value: Vec<u64>,
    condition: bool,
}

#[derive(Serialize)]
struct JsStateEntry {
    slot_index: u64,
    value: u64,
}

#[derive(Serialize)]
struct JsIMTEntry {
    key: [u64; 4],
    value: [u64; 4],
}

fn abi_to_js(abi: &ContractABI) -> JsContractABI {
    JsContractABI {
        contract_name: abi.contract_name.clone(),
        state_tree_height: abi.state_tree_height,
        state_layout: abi
            .state_layout
            .iter()
            .map(|f| JsABIStateField {
                name: f.name.clone(),
                field_type: f.field_type.clone(),
                offset: f.offset,
                felt_size: f.felt_size,
                is_array: f.is_array,
                array_count: f.array_count,
                element_type: f.element_type.clone(),
                element_felt_size: f.element_felt_size,
                sub_fields: f.sub_fields.as_ref().map(|sfs| {
                    sfs.iter()
                        .map(|sf| JsABISubField {
                            name: sf.name.clone(),
                            offset: sf.offset,
                            felt_size: sf.felt_size,
                        })
                        .collect()
                }),
                is_imt_map: f.is_imt_map,
                imt_key_type: f.imt_key_type.clone(),
                imt_value_type: f.imt_value_type.clone(),
            })
            .collect(),
        methods: abi
            .methods
            .iter()
            .map(|m| JsABIMethod {
                name: m.name.clone(),
                method_id: m.method_id,
                params: m
                    .params
                    .iter()
                    .map(|p| JsABIParam {
                        name: p.name.clone(),
                        param_type: p.param_type.clone(),
                        felt_size: p.felt_size,
                    })
                    .collect(),
                is_view: m.is_view,
            })
            .collect(),
    }
}

fn interpret_compile_output(output: ContractOutput, request: InterpretRequest) -> String {
    let method_name = request.method_name.clone().unwrap_or_else(|| "main".to_string());
    let method = match output.abi.methods.iter().find(|m| m.name == method_name) {
        Some(method) => method,
        None => return interpret_error_result(format!("Method '{}' not found", method_name), None),
    };
    let circuit = match output
        .circuit_definitions
        .iter()
        .find(|definition| definition.method_id == method.method_id)
    {
        Some(circuit) => circuit,
        None => return interpret_error_result(format!("Circuit for method '{}' not found", method_name), None),
    };

    let execution_result = match execute_circuit(circuit, request) {
        Ok(result) => match serde_json::to_value(result) {
            Ok(value) => value,
            Err(e) => return interpret_error_result(format!("Failed to serialize execution result: {}", e), None),
        },
        Err(e) => return interpret_error_result(format!("Execution error: {}", e), None),
    };

    let result = JsInterpretResult {
        success: true,
        error: None,
        error_offset: None,
        error_module: None,
        execution_result: Some(execution_result),
        abi: Some(abi_to_js(&output.abi)),
        spec_abi: serde_json::to_value(&output.spec_abi).ok(),
        state_tree_height: Some(output.state_tree_height()),
        method_count: Some(output.method_count()),
        circuit_definitions: Some(output.circuit_definitions),
    };
    serde_json::to_string(&result).unwrap_or_else(|e| {
        format!(
            "{{\"success\":false,\"error\":\"Serialization error: {}\"}}",
            e
        )
    })
}

fn interpret_error_result(error_msg: String, error_offset: Option<usize>) -> String {
    let result = JsInterpretResult {
        success: false,
        error: Some(error_msg),
        error_offset,
        error_module: None,
        execution_result: None,
        abi: None,
        spec_abi: None,
        state_tree_height: None,
        method_count: None,
        circuit_definitions: None,
    };
    serde_json::to_string(&result)
        .unwrap_or_else(|e| format!("{{\"success\":false,\"error\":\"Serialization error: {}\"}}", e))
}

fn execute_circuit(
    circuit: &DPNFunctionCircuitDefinition,
    request: InterpretRequest,
) -> Result<psy_vm::dpn::eval::executor::ExecutionResult, String> {
    let mut state = InMemoryStateBackend::new();
    if let Some(initial_state) = request.initial_state {
        hydrate_initial_state(&mut state, initial_state);
    }

    let context = request
        .execution_context
        .map(ExecutionContext::from)
        .unwrap_or_else(default_execution_context);

    let mut executor = VmExecutor::new(state);
    executor
        .execute(circuit, &context, &request.inputs)
        .map_err(|e| format!("{:#}", e))
}

fn hydrate_initial_state(state: &mut InMemoryStateBackend, initial_state: InitialStateInput) {
    for slot in initial_state.slots {
        state.set_slot(slot.user_id, slot.contract_id, slot.slot_index, slot.value);
    }
    for hash in initial_state.hashes {
        state.set_hash(hash.user_id, hash.contract_id, hash.slot_index, hash.value);
    }
    for deployer in initial_state.deployers {
        state.set_deployer(deployer.contract_id, deployer.deployer);
    }
    for checkpoint_stats in initial_state.checkpoint_stats {
        state.set_checkpoint_stats(checkpoint_stats.checkpoint_id, checkpoint_stats.values);
    }
    for contract_leaf in initial_state.contract_leaves {
        state.set_contract_leaf(contract_leaf.contract_id, contract_leaf.values);
    }
    for roots in initial_state.checkpoint_global_state_roots {
        state.set_checkpoint_global_state_roots(roots.checkpoint_id, roots.values);
    }
    for imt in initial_state.imt {
        state.set_imt(imt.user_id, imt.contract_id, imt.key, imt.value);
    }
}

fn default_execution_context() -> ExecutionContext {
    ExecutionContext {
        user_id: 0,
        contract_id: 0,
        caller_contract_id: 0,
        checkpoint_id: 0,
        nonce: 0,
        user_public_key_hash: [0; 4],
    }
}

impl From<ExecutionContextInput> for ExecutionContext {
    fn from(value: ExecutionContextInput) -> Self {
        ExecutionContext {
            user_id: value.user_id.unwrap_or(0),
            contract_id: value.contract_id.unwrap_or(0),
            caller_contract_id: value.caller_contract_id.unwrap_or(0),
            checkpoint_id: value.checkpoint_id.unwrap_or(0),
            nonce: value.nonce.unwrap_or(0),
            user_public_key_hash: value.user_public_key_hash.unwrap_or([0; 4]),
        }
    }
}

// ---------------------------------------------------------------------------
// Compilation cache (stores last compilation result for deployment)
// ---------------------------------------------------------------------------

static LAST_COMPILE: Mutex<Option<ContractOutput>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// WASM exports
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn init_psy_ide() {
    console_error_panic_hook::set_once();
}

/// Initialize the in-memory chain.
#[wasm_bindgen]
pub fn init_chain() {
    let mut guard = CHAIN.lock().unwrap();
    *guard = Some(InMemoryChain::new());
}

/// Compile a single-file PSY source. Returns JSON string.
#[wasm_bindgen]
pub fn compile_source(source: &str) -> String {
    match psy_compiler::compile(source) {
        Ok(output) => {
            let result = JsCompileResult {
                success: true,
                error: None,
                error_offset: None,
                error_module: None,
                abi: Some(abi_to_js(&output.abi)),
                spec_abi: serde_json::to_value(&output.spec_abi).ok(),
                state_tree_height: Some(output.state_tree_height()),
                method_count: Some(output.method_count()),
                circuit_definitions: Some(output.circuit_definitions.clone()),
            };
            // Cache for deployment
            if let Ok(mut cache) = LAST_COMPILE.lock() {
                *cache = Some(output);
            }
            serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"success\":false,\"error\":\"Serialization error: {}\"}}", e))
        }
        Err(e) => {
            let error_msg = format!("{:#}", e);
            let error_offset = extract_error_offset(&error_msg);
            let result = JsCompileResult {
                success: false,
                error: Some(error_msg),
                error_offset,
                error_module: None,
                abi: None,
                spec_abi: None,
                state_tree_height: None,
                method_count: None,
                circuit_definitions: None,
            };
            serde_json::to_string(&result).unwrap_or_else(|_| format!("{{\"success\":false,\"error\":\"{}\"}}", e))
        }
    }
}

/// Compile a multi-file PSY project. `files_json` is a JSON array of
/// `[module_path_parts[], source_text]` pairs.
#[wasm_bindgen]
pub fn compile_project(files_json: &str) -> String {
    let files: Result<Vec<(Vec<String>, String)>, _> = serde_json::from_str(files_json);
    match files {
        Ok(file_list) => {
            let sources: Vec<(Vec<String>, String)> = file_list;
            match psy_compiler::compile_crate_from_sources(&sources) {
                Ok(output) => {
                    let result = JsCompileResult {
                        success: true,
                        error: None,
                        error_offset: None,
                        error_module: None,
                        abi: Some(abi_to_js(&output.abi)),
                        spec_abi: serde_json::to_value(&output.spec_abi).ok(),
                        state_tree_height: Some(output.state_tree_height()),
                        method_count: Some(output.method_count()),
                        circuit_definitions: Some(output.circuit_definitions.clone()),
                    };
                    if let Ok(mut cache) = LAST_COMPILE.lock() {
                        *cache = Some(output);
                    }
                    serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"success\":false,\"error\":\"Serialization error: {}\"}}", e))
                }
                Err(e) => {
                    let error_msg = format!("{:#}", e);
                    let error_offset = extract_error_offset(&error_msg);
                    let result = JsCompileResult {
                        success: false,
                        error: Some(error_msg),
                        error_offset,
                        error_module: None,
                        abi: None,
                        spec_abi: None,
                        state_tree_height: None,
                        method_count: None,
                        circuit_definitions: None,
                    };
                    serde_json::to_string(&result).unwrap_or_else(|_| format!("{{\"success\":false,\"error\":\"{}\"}}", e))
                }
            }
        }
        Err(e) => {
            format!("{{\"success\":false,\"error\":\"Invalid files JSON: {}\"}}", e)
        }
    }
}

/// Compile and execute a single-file PSY source. Returns JSON string.
#[wasm_bindgen]
pub fn interpret_source(source: &str, request_json: &str) -> String {
    let request = match serde_json::from_str::<InterpretRequest>(request_json) {
        Ok(request) => request,
        Err(e) => return interpret_error_result(format!("Invalid interpret request JSON: {}", e), None),
    };

    match psy_compiler::compile(source) {
        Ok(output) => interpret_compile_output(output, request),
        Err(e) => {
            let error_msg = format!("{:#}", e);
            interpret_error_result(error_msg.clone(), extract_error_offset(&error_msg))
        }
    }
}

/// Compile and execute a multi-file PSY project. `files_json` is a JSON array
/// of `[module_path_parts[], source_text]` pairs.
#[wasm_bindgen]
pub fn interpret_project(files_json: &str, request_json: &str) -> String {
    let request = match serde_json::from_str::<InterpretRequest>(request_json) {
        Ok(request) => request,
        Err(e) => return interpret_error_result(format!("Invalid interpret request JSON: {}", e), None),
    };
    let files = match serde_json::from_str::<Vec<(Vec<String>, String)>>(files_json) {
        Ok(files) => files,
        Err(e) => return interpret_error_result(format!("Invalid files JSON: {}", e), None),
    };

    match psy_compiler::compile_crate_from_sources(&files) {
        Ok(output) => interpret_compile_output(output, request),
        Err(e) => {
            let error_msg = format!("{:#}", e);
            interpret_error_result(error_msg.clone(), extract_error_offset(&error_msg))
        }
    }
}

/// Create a user account. Returns JSON.
#[wasm_bindgen]
pub fn create_account(name: &str) -> String {
    match with_chain(|chain| {
        let acct = chain.create_account(name);
        Ok(JsAccount {
            user_id: acct.user_id,
            name: acct.name,
        })
    }) {
        Ok(acct) => serde_json::to_string(&acct).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Get all accounts. Returns JSON array.
#[wasm_bindgen]
pub fn get_accounts() -> String {
    match with_chain(|chain| {
        let accounts: Vec<JsAccount> = chain
            .accounts
            .iter()
            .map(|a| JsAccount {
                user_id: a.user_id,
                name: a.name.clone(),
            })
            .collect();
        Ok(accounts)
    }) {
        Ok(accounts) => serde_json::to_string(&accounts).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Deploy the last compiled contract. Returns JSON.
#[wasm_bindgen]
pub fn deploy_contract(deployer_id: u64) -> String {
    let compile_output = match LAST_COMPILE.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(output) => output.clone(),
            None => {
                return "{\"success\":false,\"error\":\"No compiled contract. Compile first.\"}".to_string();
            }
        },
        Err(e) => {
            return format!("{{\"success\":false,\"error\":\"Lock error: {}\"}}", e);
        }
    };

    match with_chain(|chain| {
        if chain.find_account(deployer_id).is_none() {
            return Err(format!("Account with ID {} not found", deployer_id));
        }

        let contract_id = chain.next_contract_id;
        chain.next_contract_id += 1;

        let deployed = DeployedContract {
            contract_id,
            name: compile_output.abi.contract_name.clone(),
            deployer_id,
            abi: compile_output.abi.clone(),
            circuit_definitions: compile_output.circuit_definitions.clone(),
            state_tree_height: compile_output.state_tree_height(),
        };

        chain.contracts.push(deployed);

        Ok(JsDeployResult {
            success: true,
            error: None,
            contract_id: Some(contract_id),
        })
    }) {
        Ok(result) => serde_json::to_string(&result).unwrap(),
        Err(e) => {
            let err_msg = e.as_string().unwrap_or_else(|| format!("{:?}", e));
            let err_result = JsDeployResult {
                success: false,
                error: Some(err_msg),
                contract_id: None,
            };
            serde_json::to_string(&err_result).unwrap()
        }
    }
}

/// Get all deployed contracts. Returns JSON array.
#[wasm_bindgen]
pub fn get_contracts() -> String {
    match with_chain(|chain| {
        let contracts: Vec<JsDeployedContract> = chain
            .contracts
            .iter()
            .map(|c| JsDeployedContract {
                contract_id: c.contract_id,
                name: c.name.clone(),
                deployer_id: c.deployer_id,
                abi: abi_to_js(&c.abi),
            })
            .collect();
        Ok(contracts)
    }) {
        Ok(contracts) => serde_json::to_string(&contracts).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Call a contract method. Returns JSON with execution result.
#[wasm_bindgen]
pub fn call_contract(caller_id: u64, contract_id: u64, method_name: &str, args_json: &str) -> String {
    let args: Vec<u64> = match serde_json::from_str(args_json) {
        Ok(a) => a,
        Err(e) => {
            return format!("{{\"success\":false,\"error\":\"Invalid args: {}\"}}", e);
        }
    };

    match with_chain(|chain| {
        let contract = chain
            .find_contract(contract_id)
            .ok_or_else(|| format!("Contract {} not found", contract_id))?;

        let method = contract
            .abi
            .methods
            .iter()
            .find(|m| m.name == method_name)
            .ok_or_else(|| format!("Method '{}' not found", method_name))?;

        let circuit = contract
            .circuit_definitions
            .iter()
            .find(|d| d.method_id == method.method_id)
            .ok_or_else(|| format!("Circuit for method '{}' not found", method_name))?;

        let caller_name = chain
            .find_account(caller_id)
            .map(|a| a.name.clone())
            .unwrap_or_else(|| format!("User {}", caller_id));
        let contract_name = contract.name.clone();

        let ctx = ExecutionContext {
            user_id: caller_id,
            contract_id,
            caller_contract_id: 0,
            checkpoint_id: chain.checkpoint_id,
            nonce: chain.transaction_log.len() as u64,
            user_public_key_hash: [0; 4],
        };

        // Clone the state to create the executor
        let mut executor = VmExecutor::new(chain.state.clone());
        let result = executor.execute(circuit, &ctx, &args).map_err(|e| format!("Execution error: {:#}", e))?;

        // If successful, apply state changes (write overlay) back
        if result.success {
            chain.state.apply_overlay(executor.write_overlay());
            chain.state.apply_imt_overlay(executor.imt_write_overlay());
        }

        let tx_id = chain.transaction_log.len() as u64 + 1;
        let tx_record = TransactionRecord {
            tx_id,
            caller_id,
            caller_name: caller_name.clone(),
            contract_id,
            contract_name: contract_name.clone(),
            method_name: method_name.to_string(),
            args: args.clone(),
            success: result.success,
            failure_message: result.failure.as_ref().map(|f| f.message.clone()),
            state_reads: result.state_reads.len(),
            state_writes: result.state_writes.len(),
            total_ops: result.op_counts.total_operations,
            outputs: result.outputs.clone(),
        };
        chain.transaction_log.push(tx_record);

        let js_result = JsCallResult {
            success: result.success,
            error: None,
            failure_message: result.failure.as_ref().map(|f| f.message.clone()),
            state_reads: result
                .state_reads
                .iter()
                .map(|r| JsStateRead {
                    command_index: r.command_index,
                    command_type: r.command_type.clone(),
                    user_id: r.user_id,
                    contract_id: r.contract_id,
                    slot_index: r.slot_index,
                    value: r.value.clone(),
                })
                .collect(),
            state_writes: result
                .state_writes
                .iter()
                .map(|w| JsStateWrite {
                    command_index: w.command_index,
                    command_type: w.command_type.clone(),
                    user_id: w.user_id,
                    contract_id: w.contract_id,
                    slot_index: w.slot_index,
                    old_value: w.old_value.clone(),
                    new_value: w.new_value.clone(),
                    condition: w.condition,
                })
                .collect(),
            outputs: result.outputs,
            total_ops: result.op_counts.total_operations,
        };

        Ok(serde_json::to_string(&js_result).unwrap())
    }) {
        Ok(json) => json,
        Err(e) => {
            let err_msg = e.as_string().unwrap_or_else(|| format!("{:?}", e));
            let err_result = JsCallResult {
                success: false,
                error: Some(err_msg),
                failure_message: None,
                state_reads: vec![],
                state_writes: vec![],
                outputs: vec![],
                total_ops: 0,
            };
            serde_json::to_string(&err_result).unwrap()
        }
    }
}

/// Read contract state for a specific user. Returns JSON array of slot values.
#[wasm_bindgen]
pub fn read_contract_state(contract_id: u64, user_id: u64) -> String {
    match with_chain(|chain| {
        let contract = chain
            .find_contract(contract_id)
            .ok_or_else(|| format!("Contract {} not found", contract_id))?;

        let mut entries: Vec<JsStateEntry> = Vec::new();
        let total_slots = 1u64 << contract.state_tree_height;
        for slot in 0..total_slots.min(256) {
            // Limit to avoid huge reads
            let value = chain.state.get_contract_slot(user_id, contract_id, slot).unwrap_or(0);
            if value != 0 {
                entries.push(JsStateEntry { slot_index: slot, value });
            }
        }

        Ok(entries)
    }) {
        Ok(entries) => serde_json::to_string(&entries).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Read IMT (Indexed Merkle Tree) key-value entries for a specific
/// user/contract. Returns JSON array of `{key: [u64;4], value: [u64;4]}`
/// objects.
#[wasm_bindgen]
pub fn read_imt_state(contract_id: u32, user_id: u32) -> String {
    let contract_id = contract_id as u64;
    let user_id = user_id as u64;

    match with_chain(|chain| {
        // Verify the contract exists
        chain
            .find_contract(contract_id)
            .ok_or_else(|| format!("Contract {} not found", contract_id))?;

        let entries: Vec<JsIMTEntry> = chain
            .state
            .imt_entries_for(user_id, contract_id)
            .map(|(key, value)| JsIMTEntry { key: *key, value: *value })
            .collect();

        Ok(entries)
    }) {
        Ok(entries) => serde_json::to_string(&entries).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Get the full transaction log. Returns JSON array.
#[wasm_bindgen]
pub fn get_transaction_log() -> String {
    match with_chain(|chain| Ok(chain.transaction_log.clone())) {
        Ok(log) => serde_json::to_string(&log).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

/// Reset the chain (clear all state).
#[wasm_bindgen]
pub fn reset_chain() {
    let mut guard = CHAIN.lock().unwrap();
    *guard = Some(InMemoryChain::new());
}

/// Get the ABI for a deployed contract. Returns JSON.
#[wasm_bindgen]
pub fn get_contract_abi(contract_id: u64) -> String {
    match with_chain(|chain| {
        let contract = chain
            .find_contract(contract_id)
            .ok_or_else(|| format!("Contract {} not found", contract_id))?;
        Ok(abi_to_js(&contract.abi))
    }) {
        Ok(abi) => serde_json::to_string(&abi).unwrap(),
        Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
    }
}

// ---------------------------------------------------------------------------
// SDK Key compilation
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct JsSDKKeyCompileResult {
    success: bool,
    error: Option<String>,
    name: Option<String>,
    config: Option<JsSDKKeyConfig>,
    /// DPN bytecode (JSON-serialized DPNFunctionCircuitDefinition).
    dpn_bytecode: Option<String>,
    /// Dapen bytecode (hex-encoded CBOR of ContractFunctionCodeDefinition).
    dapen_bytecode: Option<String>,
    /// Number of DPN definitions in the circuit.
    num_definitions: Option<usize>,
    /// Number of circuit inputs.
    num_inputs: Option<usize>,
    /// Number of circuit outputs.
    num_outputs: Option<usize>,
    /// Number of state commands.
    num_state_commands: Option<usize>,
    /// Number of assertions.
    num_assertions: Option<usize>,
}

#[derive(Serialize)]
struct JsSDKKeyConfig {
    num_introspectable_transactions: u32,
    can_read_state: bool,
    contract_state_tree_height: u8,
    requires_secp256k1: bool,
    num_secp256k1_slots: u32,
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sdk_key_output_to_js(output: &SDKKeyCompileOutput, include_dapen: bool) -> JsSDKKeyCompileResult {
    let dpn_bytecode = serde_json::to_string(&output.circuit_def).ok();
    let dapen_bytecode = if include_dapen {
        let cfc = dapen_fc_to_cfc_code_definition(&output.circuit_def);
        Some(bytes_to_hex(&cfc.code))
    } else {
        None
    };

    JsSDKKeyCompileResult {
        success: true,
        error: None,
        name: Some(output.name.clone()),
        config: Some(JsSDKKeyConfig {
            num_introspectable_transactions: output.config.num_introspectable_transactions,
            can_read_state: output.config.can_read_state,
            contract_state_tree_height: output.config.contract_state_tree_height,
            requires_secp256k1: output.config.requires_secp256k1,
            num_secp256k1_slots: output.config.num_secp256k1_slots,
        }),
        dpn_bytecode,
        dapen_bytecode,
        num_definitions: Some(output.circuit_def.definitions.len()),
        num_inputs: Some(output.circuit_def.circuit_inputs.len()),
        num_outputs: Some(output.circuit_def.circuit_outputs.len()),
        num_state_commands: Some(output.circuit_def.state_commands.len()),
        num_assertions: Some(output.circuit_def.assertions.len()),
    }
}

fn sdk_key_error_result(error_msg: String) -> String {
    let result = JsSDKKeyCompileResult {
        success: false,
        error: Some(error_msg),
        name: None,
        config: None,
        dpn_bytecode: None,
        dapen_bytecode: None,
        num_definitions: None,
        num_inputs: None,
        num_outputs: None,
        num_state_commands: None,
        num_assertions: None,
    };
    serde_json::to_string(&result).unwrap_or_else(|e| format!("{{\"success\":false,\"error\":\"Serialization error: {}\"}}", e))
}

/// Compile a single-file PSY source as an SDK key. Returns JSON.
///
/// The result includes both DPN bytecode (JSON) and Dapen bytecode (hex CBOR).
#[wasm_bindgen]
pub fn compile_sdk_key_source(source: &str) -> String {
    match psy_compiler::compile_sdk_key(source) {
        Ok(output) => {
            let result = sdk_key_output_to_js(&output, true);
            serde_json::to_string(&result).unwrap_or_else(|e| sdk_key_error_result(format!("Serialization error: {}", e)))
        }
        Err(e) => sdk_key_error_result(format!("{:#}", e)),
    }
}

/// Compile a multi-file PSY project as an SDK key. Returns JSON.
///
/// `files_json` is a JSON array of `[module_path_parts[], source_text]` pairs.
/// The result includes both DPN bytecode (JSON) and Dapen bytecode (hex CBOR).
#[wasm_bindgen]
pub fn compile_sdk_key_project(files_json: &str) -> String {
    let files: Result<Vec<(Vec<String>, String)>, _> = serde_json::from_str(files_json);
    match files {
        Ok(file_list) => match psy_compiler::compile_sdk_key_from_sources(&file_list) {
            Ok(output) => {
                let result = sdk_key_output_to_js(&output, true);
                serde_json::to_string(&result).unwrap_or_else(|e| sdk_key_error_result(format!("Serialization error: {}", e)))
            }
            Err(e) => sdk_key_error_result(format!("{:#}", e)),
        },
        Err(e) => sdk_key_error_result(format!("Invalid files JSON: {}", e)),
    }
}
