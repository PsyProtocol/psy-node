//! VM Executor: Non-circuit execution of DPNFunctionCircuitDefinition
//!
//! Interprets compiled DPN circuits against concrete state, producing
//! execution results with state deltas, events, and assertion outcomes.

use std::collections::HashMap;

use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
    plonk::config::{GenericHashOut, Hasher},
};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher as _, Keccak};

use crate::dpn::{
    ops::{
        op_types::{decode_indexed_op_id, DPNBuiltInDataType, DPNOpType},
        semantics,
        state_cmd::data::DPNStateCmd,
    },
    vm::def::DPNFunctionCircuitDefinition,
};

// ---------------------------------------------------------------------------
// Core result types
// ---------------------------------------------------------------------------

/// Result of executing a contract function via the VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Whether all assertions passed
    pub success: bool,
    /// If failed, details about the first failure
    pub failure: Option<ExecutionFailure>,
    /// All state reads performed
    pub state_reads: Vec<StateRead>,
    /// All state writes performed
    pub state_writes: Vec<StateWrite>,
    /// Net state delta (merged reads + writes per slot)
    pub state_delta: Vec<StateDelta>,
    /// Events emitted
    pub events: Vec<ExecutionEvent>,
    /// Operation counts by category
    pub op_counts: OpCounts,
    /// Concrete output values
    pub outputs: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionFailure {
    pub assertion_index: usize,
    pub message: String,
    pub left_value: u64,
    pub right_value: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRead {
    pub command_index: usize,
    pub command_type: String,
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub value: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateWrite {
    pub command_index: usize,
    pub command_type: String,
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub old_value: Vec<u64>,
    pub new_value: Vec<u64>,
    pub condition: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub old_value: Vec<u64>,
    pub new_value: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEvent {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub data: Vec<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OpCounts {
    pub total_operations: usize,
    pub arithmetic_ops: usize,
    pub boolean_ops: usize,
    pub comparison_ops: usize,
    pub hash_ops: usize,
    pub state_read_ops: usize,
    pub state_write_ops: usize,
    pub external_call_ops: usize,
}

// ---------------------------------------------------------------------------
// Execution context
// ---------------------------------------------------------------------------

/// Goldilocks field order; felt-lane inputs are canonical (reduced mod p)
/// exactly like DSL constants and the witness/prove path.
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// Context for a contract function execution
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub user_id: u64,
    pub contract_id: u64,
    pub caller_contract_id: u64,
    pub checkpoint_id: u64,
    pub nonce: u64,
    pub user_public_key_hash: [u64; 4],
    /// Full 4-element session proof tree root, mirroring the witness
    /// executor's `session_proof_tree_root` (GetSessionProofTreeRoot).
    pub session_proof_tree_root: [u64; 4],
}

// ---------------------------------------------------------------------------
// State backend trait
// ---------------------------------------------------------------------------

/// Trait for providing contract state to the VM executor
pub trait StateBackend {
    /// Read a single felt from a user's contract state
    fn get_contract_slot(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<u64>;

    /// Read a hash (4 felts) from a user's contract state
    fn get_contract_hash(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<[u64; 4]>;

    /// Read a range of felts from a user's contract state
    fn get_contract_range(&self, user_id: u64, contract_id: u64, slot_index: u64, length: usize) -> anyhow::Result<Vec<u64>>;

    /// Get contract deployer user id
    fn get_contract_deployer(&self, contract_id: u64) -> anyhow::Result<u64>;

    /// Get checkpoint stats (returns array of stats felts)
    fn get_checkpoint_stats(&self, checkpoint_id: u64) -> anyhow::Result<Vec<u64>>;

    /// Get contract leaf data (returns [deployer(1), function_tree_root(4),
    /// code_root(4), state_tree_height(1), state_layout_root(4),
    /// state_layout_field_count(1), state_layout_slot_count(1)])
    fn get_contract_leaf(&self, contract_id: u64) -> anyhow::Result<Vec<u64>>;

    /// Get checkpoint global state roots (20 felts).
    fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<Vec<u64>>;

    /// Read a 256-bit value from the IMT (Indexed Merkle Tree) state by key
    fn get_imt_value(&self, user_id: u64, contract_id: u64, key: &[u64; 4]) -> [u64; 4];

    /// Write a 256-bit value to the IMT state by key (upsert semantics)
    fn set_imt_value(&mut self, user_id: u64, contract_id: u64, key: &[u64; 4], value: &[u64; 4]);
}

// ---------------------------------------------------------------------------
// InMemoryStateBackend
// ---------------------------------------------------------------------------

/// In-memory state backend for testing and local simulation
#[derive(Debug, Clone, Default)]
pub struct InMemoryStateBackend {
    /// State slots keyed by (user_id, contract_id, slot_index)
    slots: HashMap<(u64, u64, u64), u64>,
    /// Contract deployers keyed by contract_id
    deployers: HashMap<u64, u64>,
    /// Checkpoint stats keyed by checkpoint_id
    checkpoint_stats: HashMap<u64, Vec<u64>>,
    /// Contract leaf data keyed by contract_id
    contract_leaves: HashMap<u64, Vec<u64>>,
    /// Global state roots keyed by checkpoint_id
    checkpoint_global_state_roots: HashMap<u64, Vec<u64>>,
    /// IMT (Indexed Merkle Tree) state keyed by (user_id, contract_id, key[4])
    /// -> value[4]
    imt_store: HashMap<(u64, u64, [u64; 4]), [u64; 4]>,
}

impl InMemoryStateBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a single slot value
    pub fn set_slot(&mut self, user_id: u64, contract_id: u64, slot_index: u64, value: u64) {
        self.slots.insert((user_id, contract_id, slot_index), value);
    }

    /// Set a hash (4 felts) starting at slot_index * 4
    pub fn set_hash(&mut self, user_id: u64, contract_id: u64, slot_index: u64, value: [u64; 4]) {
        let base = slot_index * 4;
        for (i, v) in value.iter().enumerate() {
            self.slots.insert((user_id, contract_id, base + i as u64), *v);
        }
    }

    /// Set contract deployer
    pub fn set_deployer(&mut self, contract_id: u64, deployer: u64) {
        self.deployers.insert(contract_id, deployer);
    }

    /// Set checkpoint stats
    pub fn set_checkpoint_stats(&mut self, checkpoint_id: u64, stats: Vec<u64>) {
        self.checkpoint_stats.insert(checkpoint_id, stats);
    }

    /// Set contract leaf
    pub fn set_contract_leaf(&mut self, contract_id: u64, leaf: Vec<u64>) {
        self.contract_leaves.insert(contract_id, leaf);
    }

    /// Set checkpoint global state roots
    pub fn set_checkpoint_global_state_roots(&mut self, checkpoint_id: u64, roots: Vec<u64>) {
        self.checkpoint_global_state_roots.insert(checkpoint_id, roots);
    }

    /// Set an IMT value directly (for test setup)
    pub fn set_imt(&mut self, user_id: u64, contract_id: u64, key: [u64; 4], value: [u64; 4]) {
        self.imt_store.insert((user_id, contract_id, key), value);
    }

    /// Merge a write overlay into this backend's slot data.
    pub fn apply_overlay(&mut self, overlay: &HashMap<(u64, u64, u64), u64>) {
        for (&key, &value) in overlay {
            self.slots.insert(key, value);
        }
    }

    /// Merge an IMT write overlay into this backend's IMT store.
    pub fn apply_imt_overlay(&mut self, overlay: &HashMap<(u64, u64, [u64; 4]), [u64; 4]>) {
        for (&key, &value) in overlay {
            self.imt_store.insert(key, value);
        }
    }

    /// Iterate over all IMT entries matching a given (user_id, contract_id).
    /// Returns an iterator of (key, value) pairs.
    pub fn imt_entries_for(&self, user_id: u64, contract_id: u64) -> impl Iterator<Item = (&[u64; 4], &[u64; 4])> {
        self.imt_store
            .iter()
            .filter(move |&(&(uid, cid, _), _)| uid == user_id && cid == contract_id)
            .map(|((_, _, key), value)| (key, value))
    }
}

impl StateBackend for InMemoryStateBackend {
    fn get_contract_slot(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<u64> {
        Ok(*self.slots.get(&(user_id, contract_id, slot_index)).unwrap_or(&0))
    }

    fn get_contract_hash(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<[u64; 4]> {
        let base = slot_index * 4;
        Ok([
            *self.slots.get(&(user_id, contract_id, base)).unwrap_or(&0),
            *self.slots.get(&(user_id, contract_id, base + 1)).unwrap_or(&0),
            *self.slots.get(&(user_id, contract_id, base + 2)).unwrap_or(&0),
            *self.slots.get(&(user_id, contract_id, base + 3)).unwrap_or(&0),
        ])
    }

    fn get_contract_range(&self, user_id: u64, contract_id: u64, slot_index: u64, length: usize) -> anyhow::Result<Vec<u64>> {
        let mut result = Vec::with_capacity(length);
        for i in 0..length {
            result.push(*self.slots.get(&(user_id, contract_id, slot_index + i as u64)).unwrap_or(&0));
        }
        Ok(result)
    }

    fn get_contract_deployer(&self, contract_id: u64) -> anyhow::Result<u64> {
        Ok(*self.deployers.get(&contract_id).unwrap_or(&0))
    }

    fn get_checkpoint_stats(&self, checkpoint_id: u64) -> anyhow::Result<Vec<u64>> {
        Ok(self.checkpoint_stats.get(&checkpoint_id).cloned().unwrap_or_default())
    }

    fn get_contract_leaf(&self, contract_id: u64) -> anyhow::Result<Vec<u64>> {
        Ok(self.contract_leaves.get(&contract_id).cloned().unwrap_or_else(|| vec![0; 16]))
    }

    fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> anyhow::Result<Vec<u64>> {
        Ok(self
            .checkpoint_global_state_roots
            .get(&checkpoint_id)
            .cloned()
            .unwrap_or_else(|| vec![0; 20]))
    }

    fn get_imt_value(&self, user_id: u64, contract_id: u64, key: &[u64; 4]) -> [u64; 4] {
        *self.imt_store.get(&(user_id, contract_id, *key)).unwrap_or(&[0u64; 4])
    }

    fn set_imt_value(&mut self, user_id: u64, contract_id: u64, key: &[u64; 4], value: &[u64; 4]) {
        self.imt_store.insert((user_id, contract_id, *key), *value);
    }
}

// ---------------------------------------------------------------------------
// VM Executor
// ---------------------------------------------------------------------------

/// Non-circuit VM executor for DPN function circuits
pub struct VmExecutor<S: StateBackend> {
    state: S,
    /// Write overlay: subsequent reads see previously written values
    write_overlay: HashMap<(u64, u64, u64), u64>,
    /// IMT write overlay: subsequent IMT reads see previously written values
    imt_write_overlay: HashMap<(u64, u64, [u64; 4]), [u64; 4]>,
}

impl<S: StateBackend> VmExecutor<S> {
    pub fn new(state: S) -> Self {
        VmExecutor {
            state,
            write_overlay: HashMap::new(),
            imt_write_overlay: HashMap::new(),
        }
    }

    /// Consume the executor and return the underlying state backend.
    /// The write overlay is NOT merged — call `apply_writes_to_state` first
    /// if you need the overlay applied (only works for InMemoryStateBackend).
    pub fn into_inner(self) -> S {
        self.state
    }

    /// Get a reference to the write overlay for inspection.
    pub fn write_overlay(&self) -> &HashMap<(u64, u64, u64), u64> {
        &self.write_overlay
    }

    /// Get a reference to the IMT write overlay for inspection.
    pub fn imt_write_overlay(&self) -> &HashMap<(u64, u64, [u64; 4]), [u64; 4]> {
        &self.imt_write_overlay
    }

    /// Read a slot, checking the write overlay first
    fn read_slot(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<u64> {
        if let Some(v) = self.write_overlay.get(&(user_id, contract_id, slot_index)) {
            Ok(*v)
        } else {
            self.state.get_contract_slot(user_id, contract_id, slot_index)
        }
    }

    /// Read a range, checking the write overlay first
    fn read_range(&self, user_id: u64, contract_id: u64, slot_index: u64, length: usize) -> anyhow::Result<Vec<u64>> {
        let mut result = Vec::with_capacity(length);
        for i in 0..length {
            result.push(self.read_slot(user_id, contract_id, slot_index + i as u64)?);
        }
        Ok(result)
    }

    /// Read a hash (4 felts), checking the write overlay first
    fn read_hash(&self, user_id: u64, contract_id: u64, slot_index: u64) -> anyhow::Result<[u64; 4]> {
        let base = slot_index * 4;
        Ok([
            self.read_slot(user_id, contract_id, base)?,
            self.read_slot(user_id, contract_id, base + 1)?,
            self.read_slot(user_id, contract_id, base + 2)?,
            self.read_slot(user_id, contract_id, base + 3)?,
        ])
    }

    /// Read an IMT value, checking the IMT write overlay first
    fn read_imt_value(&self, user_id: u64, contract_id: u64, key: &[u64; 4]) -> [u64; 4] {
        if let Some(v) = self.imt_write_overlay.get(&(user_id, contract_id, *key)) {
            *v
        } else {
            self.state.get_imt_value(user_id, contract_id, key)
        }
    }

    /// Execute a contract function with the given context and inputs
    pub fn execute(&mut self, circuit: &DPNFunctionCircuitDefinition, context: &ExecutionContext, inputs: &[u64]) -> anyhow::Result<ExecutionResult> {
        // Untrusted-definition gate: reject malformed programs before the
        // evaluation arms can panic on them.
        crate::dpn::vm::validate::validate_function_definition(circuit)
            .map_err(|e| anyhow::anyhow!("dapen function definition failed validation: {e}"))?;

        // Clear write overlays for fresh execution
        self.write_overlay.clear();
        self.imt_write_overlay.clear();

        let mut registers = Registers::new();
        let mut state_reads = Vec::new();
        let mut state_writes = Vec::new();
        let mut op_counts = OpCounts::default();

        // Bind inputs. The felt lane canonicalizes with the same
        // reduce-mod-p semantics as DSL constants (`SymFeltRef::new_constant`)
        // and the witness/prove path (field elements are canonical by
        // construction); a raw host u64 >= p otherwise silently diverges the
        // preview from what the circuit proves (Lt(p+1, 2) would preview
        // false while the circuit proves F(1) < 2 = true). The u32 and bool
        // lanes carry the same range guards the witness executor asserts.
        for (i, &input_id) in circuit.circuit_inputs.iter().enumerate() {
            let (data_type, index) = decode_indexed_op_id(input_id);
            let raw = if i < inputs.len() { inputs[i] } else { 0 };
            let value = match data_type {
                DPNBuiltInDataType::U32Target => {
                    if raw > 0xffff_ffff {
                        anyhow::bail!("input[{i}] = {raw:#x} does not fit the u32 lane");
                    }
                    raw
                }
                DPNBuiltInDataType::Bool => {
                    if raw > 1 {
                        anyhow::bail!("input[{i}] = {raw} is not a boolean (0/1)");
                    }
                    raw
                }
                _ => raw % GOLDILOCKS_ORDER,
            };
            registers.set(data_type, index, value);
        }

        // State command results keyed by state command index.
        // The resolution indices mark WHEN each state command should be executed
        // (i.e., after all definitions before that index have been processed).
        // The results are stored here and later picked up by
        // GetStateCommandResultSingle/Hash/Array definitions.
        let mut state_cmd_results: HashMap<usize, Vec<u64>> = HashMap::new();

        // Build a map of definition_index -> list of state_command_indices for
        // interleaving. Multiple state commands may resolve at the same step,
        // so we use a Vec.
        let mut resolution_map: HashMap<usize, Vec<usize>> = HashMap::new();
        for (sci, &res_idx) in circuit.state_command_resolution_indices.iter().enumerate() {
            resolution_map.entry(res_idx).or_default().push(sci);
        }

        // Helper closure to process all state commands at a given step
        let process_state_cmds_at_step = |step: usize,
                                          executor: &mut Self,
                                          registers: &Registers,
                                          state_reads: &mut Vec<StateRead>,
                                          state_writes: &mut Vec<StateWrite>,
                                          op_counts: &mut OpCounts,
                                          state_cmd_results: &mut HashMap<usize, Vec<u64>>|
         -> anyhow::Result<()> {
            if let Some(sci_list) = resolution_map.get(&step) {
                for &sci in sci_list {
                    if sci < circuit.state_commands.len() {
                        let result = executor.process_state_command(
                            &circuit.state_commands[sci],
                            sci,
                            context,
                            registers,
                            state_reads,
                            state_writes,
                            op_counts,
                        )?;
                        if let Some(r) = result {
                            state_cmd_results.insert(sci, r);
                        }
                        op_counts.total_operations += 1;
                    }
                }
            }
            Ok(())
        };

        let total_steps = circuit.definitions.len();
        for step in 0..total_steps {
            // Check if any state commands resolve at this step
            process_state_cmds_at_step(
                step,
                self,
                &registers,
                &mut state_reads,
                &mut state_writes,
                &mut op_counts,
                &mut state_cmd_results,
            )?;

            // Always evaluate the definition at this step
            let def = &circuit.definitions[step];
            let value = self.eval_definition_with_state(def, context, &registers, &mut op_counts, &state_cmd_results)?;
            registers.set(def.data_type, def.index, value);
            if let Some(array) = self.get_state_cmd_array_result(def, &state_cmd_results) {
                registers.set_array(def.data_type, def.index, array);
            }
            // Store full hash/array result for TargetAt access
            if matches!(def.op_type, DPNOpType::HashNoPad | DPNOpType::HashTwoToOne) {
                let args: Vec<GoldilocksField> = def
                    .inputs
                    .iter()
                    .map(|&id| GoldilocksField::from_noncanonical_u64(registers.get_by_encoded_id(id)))
                    .collect();
                let hash_elements: Vec<GoldilocksField> = if def.op_type == DPNOpType::HashNoPad {
                    PoseidonHash::hash_no_pad(&args).to_vec()
                } else {
                    let left = plonky2::hash::hash_types::HashOut {
                        elements: [args[0], args[1], args[2], args[3]],
                    };
                    let right = plonky2::hash::hash_types::HashOut {
                        elements: [args[4], args[5], args[6], args[7]],
                    };
                    PoseidonHash::two_to_one(left, right).elements.to_vec()
                };
                let full_hash: Vec<u64> = hash_elements.iter().map(|f| f.to_canonical_u64()).collect();
                registers.hash_out_arrays.insert(def.index, full_hash);
            } else if matches!(def.op_type, DPNOpType::GetUserPublicKeyHash) {
                // Context hashes resolve like computed hashes: the scalar
                // arm above returns element 0, the full 4-element hash is
                // registered for TargetAt — same as the witness executor.
                registers
                    .hash_out_arrays
                    .insert(def.index, context.user_public_key_hash.to_vec());
            } else if matches!(def.op_type, DPNOpType::GetSessionProofTreeRoot) {
                registers
                    .hash_out_arrays
                    .insert(def.index, context.session_proof_tree_root.to_vec());
            } else if def.op_type == DPNOpType::Keccak256 {
                let words: Vec<u64> = def.inputs.iter().map(|&id| registers.get_by_encoded_id(id)).collect();
                let full_words: Vec<u64> = semantics::keccak_u32_words_be(&words)?.into_iter().map(|x| x as u64).collect();
                registers.set_array(DPNBuiltInDataType::U32TargetArray, def.index, full_words);
            } else if def.op_type == DPNOpType::SplitBits {
                let value = registers.get_by_encoded_id(def.inputs[1]);
                let num_bits = def.inputs[0];
                let bits: Vec<u64> = semantics::split_bits(value, num_bits)?.into_iter().map(|b| b as u64).collect();
                registers.set_array(DPNBuiltInDataType::BoolArray, def.index, bits);
            } else if def.op_type == DPNOpType::DivRem4 {
                let value = registers.get_by_encoded_id(def.inputs[0]);
                registers.set_array(DPNBuiltInDataType::TargetArray, def.index, semantics::div_rem4(value).to_vec());
            }
            op_counts.total_operations += 1;
        }

        // Process any state commands that resolve after all definitions
        // (resolution index == total_steps)
        process_state_cmds_at_step(
            total_steps,
            self,
            &registers,
            &mut state_reads,
            &mut state_writes,
            &mut op_counts,
            &mut state_cmd_results,
        )?;

        // Check assertions
        let mut failure = None;
        for (i, assertion) in circuit.assertions.iter().enumerate() {
            let left = registers.get_by_encoded_id(assertion.left);
            let right = registers.get_by_encoded_id(assertion.right);
            if left != right {
                failure = Some(ExecutionFailure {
                    assertion_index: i,
                    message: assertion.message.clone(),
                    left_value: left,
                    right_value: right,
                });
                break;
            }
        }

        // Collect outputs
        let outputs: Vec<u64> = circuit.circuit_outputs.iter().map(|&id| registers.get_by_encoded_id(id)).collect();

        // Build state delta
        let state_delta = Self::compute_state_delta(&state_reads, &state_writes);

        // Collect events — filter by condition (matching vm/exec.rs runtime).
        let events = circuit
            .events
            .iter()
            .filter(|ev| registers.get_by_encoded_id(ev.condition) != 0)
            .map(|ev| ExecutionEvent {
                checkpoint_id: context.checkpoint_id,
                user_id: context.user_id,
                contract_id: context.contract_id,
                data: ev.data.iter().map(|&id| registers.get_by_encoded_id(id)).collect(),
            })
            .collect();

        Ok(ExecutionResult {
            success: failure.is_none(),
            failure,
            state_reads,
            state_writes,
            state_delta,
            events,
            op_counts,
            outputs,
        })
    }

    /// Evaluate a single DPN indexed variable definition
    /// For GetStateCommandResult* definitions that return arrays, check if we
    /// need to store an array result from the state command results map.
    fn get_state_cmd_array_result(
        &self,
        def: &crate::dpn::ops::op_types::DPNIndexedVarDef,
        state_cmd_results: &HashMap<usize, Vec<u64>>,
    ) -> Option<Vec<u64>> {
        match def.op_type {
            DPNOpType::GetStateCommandResultHash | DPNOpType::GetStateCommandResultArray => {
                if !def.inputs.is_empty() {
                    let cmd_idx = def.inputs[0] as usize;
                    if let Some(result) = state_cmd_results.get(&cmd_idx) {
                        if result.len() > 1 {
                            return Some(result.clone());
                        }
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn eval_definition_with_state(
        &self,
        def: &crate::dpn::ops::op_types::DPNIndexedVarDef,
        context: &ExecutionContext,
        registers: &Registers,
        op_counts: &mut OpCounts,
        state_cmd_results: &HashMap<usize, Vec<u64>>,
    ) -> anyhow::Result<u64> {
        let resolve = |id: u64| -> u64 { registers.get_by_encoded_id(id) };
        let resolve_gl = |id: u64| -> GoldilocksField { GoldilocksField::from_noncanonical_u64(registers.get_by_encoded_id(id)) };

        match def.op_type {
            // Input types
            DPNOpType::InputTarget | DPNOpType::U32InputTarget | DPNOpType::BoolInputTarget => {
                // Already bound during input phase; if not, return 0
                Ok(registers.get(def.data_type, def.index))
            }

            // Constants
            DPNOpType::Constant | DPNOpType::ConstantU32 => {
                // The constant value is encoded in inputs[0]
                Ok(if !def.inputs.is_empty() { def.inputs[0] } else { 0 })
            }
            DPNOpType::ConstantTrue => Ok(1),
            DPNOpType::ConstantFalse => Ok(0),

            // Arithmetic (Goldilocks field)
            DPNOpType::Add => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::felt_add(a, b))
            }
            DPNOpType::Sub => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::felt_sub(a, b))
            }
            DPNOpType::Mul => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::felt_mul(a, b))
            }
            DPNOpType::Div => {
                op_counts.arithmetic_ops += 1;
                let a = resolve_gl(def.inputs[0]).to_canonical_u64();
                let b = resolve_gl(def.inputs[1]).to_canonical_u64();
                Ok(semantics::felt_div(a, b)?)
            }
            DPNOpType::Mod | DPNOpType::ModConstantDividend | DPNOpType::ModConstantDivisor => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::felt_mod("Mod", a, b)?)
            }
            DPNOpType::Exp | DPNOpType::ExpConstantPower | DPNOpType::ExpConstantBase => {
                op_counts.arithmetic_ops += 1;
                Ok(semantics::felt_pow(resolve(def.inputs[0]), resolve(def.inputs[1])))
            }

            // Unary
            DPNOpType::UnaryInverse => {
                op_counts.arithmetic_ops += 1;
                let a = resolve_gl(def.inputs[0]).to_canonical_u64();
                Ok(semantics::felt_inverse("UnaryInverse", a)?)
            }
            DPNOpType::UnaryNegative => {
                op_counts.arithmetic_ops += 1;
                Ok(semantics::felt_neg(resolve(def.inputs[0])))
            }

            // Boolean operations
            DPNOpType::BoolNot => {
                op_counts.boolean_ops += 1;
                let v = semantics::resolve_bool_value("BoolNot", resolve(def.inputs[0]))?;
                Ok((!v) as u64)
            }
            DPNOpType::BoolAnd => {
                op_counts.boolean_ops += 1;
                let a = semantics::resolve_bool_value("BoolAnd", resolve(def.inputs[0]))?;
                let b = semantics::resolve_bool_value("BoolAnd", resolve(def.inputs[1]))?;
                Ok((a && b) as u64)
            }
            DPNOpType::BoolOr => {
                op_counts.boolean_ops += 1;
                let a = semantics::resolve_bool_value("BoolOr", resolve(def.inputs[0]))?;
                let b = semantics::resolve_bool_value("BoolOr", resolve(def.inputs[1]))?;
                Ok((a || b) as u64)
            }
            DPNOpType::Xor => {
                op_counts.boolean_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::bool_xor("Xor", a, b)?)
            }
            DPNOpType::Nor => {
                op_counts.boolean_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::bool_nor("Nor", a, b)?)
            }

            // Comparison
            DPNOpType::Eq => {
                op_counts.comparison_ops += 1;
                Ok((resolve(def.inputs[0]) == resolve(def.inputs[1])) as u64)
            }
            DPNOpType::Lt => {
                op_counts.comparison_ops += 1;
                Ok((resolve(def.inputs[0]) < resolve(def.inputs[1])) as u64)
            }
            DPNOpType::Lte => {
                op_counts.comparison_ops += 1;
                Ok((resolve(def.inputs[0]) <= resolve(def.inputs[1])) as u64)
            }
            DPNOpType::Gt => {
                op_counts.comparison_ops += 1;
                Ok((resolve(def.inputs[0]) > resolve(def.inputs[1])) as u64)
            }
            DPNOpType::Gte => {
                op_counts.comparison_ops += 1;
                Ok((resolve(def.inputs[0]) >= resolve(def.inputs[1])) as u64)
            }

            // Select (conditional)
            DPNOpType::Select => {
                let cond = resolve(def.inputs[0]);
                let true_val = resolve(def.inputs[1]);
                let false_val = resolve(def.inputs[2]);
                Ok(if cond != 0 { true_val } else { false_val })
            }

            // U32 operations
            DPNOpType::U32Add => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::u32_add("u32 add", a, b)? as u64)
            }
            DPNOpType::U32Sub => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::u32_sub("u32 sub", a, b)? as u64)
            }
            DPNOpType::U32Mul => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::u32_mul("u32 mul", a, b)? as u64)
            }
            DPNOpType::U32Div => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::u32_div("u32 div", a, b)? as u64)
            }
            DPNOpType::U32Mod => {
                op_counts.arithmetic_ops += 1;
                let a = resolve(def.inputs[0]);
                let b = resolve(def.inputs[1]);
                Ok(semantics::u32_mod("u32 mod", a, b)? as u64)
            }
            DPNOpType::U32Exp => {
                op_counts.arithmetic_ops += 1;
                let base = resolve(def.inputs[0]);
                let exp = resolve(def.inputs[1]);
                Ok(semantics::u32_exp("u32 exp", base, exp)? as u64)
            }

            // U32 bitwise
            DPNOpType::U32And | DPNOpType::U32AndConstant => {
                op_counts.boolean_ops += 1;
                Ok((resolve(def.inputs[0]) & resolve(def.inputs[1])) & 0xFFFFFFFF)
            }
            DPNOpType::U32Or | DPNOpType::U32OrConstant => {
                op_counts.boolean_ops += 1;
                Ok((resolve(def.inputs[0]) | resolve(def.inputs[1])) & 0xFFFFFFFF)
            }
            DPNOpType::U32Xor | DPNOpType::U32XorConstant => {
                op_counts.boolean_ops += 1;
                Ok((resolve(def.inputs[0]) ^ resolve(def.inputs[1])) & 0xFFFFFFFF)
            }
            // u32 shifts: every bit leaves the 32-bit window once the
            // distance reaches 32, so distances >= 32 evaluate to 0. The
            // unguarded `a << b` on u64 panicked in debug and silently
            // wrapped in release for distances >= 64.
            // The Constant* variants carry their constant as a resolvable
            // input node, so the same logic covers all of them; they
            // previously fell through to the catch-all below and returned 0.
            DPNOpType::U32ShiftLeft | DPNOpType::U32ShiftLeftConstantBitDistance | DPNOpType::U32ShiftLeftConstantValue => {
                op_counts.boolean_ops += 1;
                let a = semantics::u32_operand("u32 shift", resolve(def.inputs[0]))?;
                let b = semantics::u32_operand("u32 shift", resolve(def.inputs[1]))?;
                Ok(semantics::u32_shl(a, b) as u64)
            }
            DPNOpType::U32ShiftRight | DPNOpType::U32ShiftRightConstantBitDistance | DPNOpType::U32ShiftRightConstantValue => {
                op_counts.boolean_ops += 1;
                let a = semantics::u32_operand("u32 shift", resolve(def.inputs[0]))?;
                let b = semantics::u32_operand("u32 shift", resolve(def.inputs[1]))?;
                Ok(semantics::u32_shr(a, b) as u64)
            }

            // Type casts
            DPNOpType::CastU32 => Ok(semantics::cast_u32(resolve(def.inputs[0]))? as u64),
            DPNOpType::CastFelt => Ok(resolve(def.inputs[0])),
            DPNOpType::CastBool => Ok(semantics::resolve_bool_value("CastBool", resolve(def.inputs[0]))? as u64),

            // Context
            DPNOpType::GetUserId => Ok(context.user_id),
            DPNOpType::GetContractId => Ok(context.contract_id),
            DPNOpType::GetCallerContractId => Ok(context.caller_contract_id),
            DPNOpType::GetCheckpointId => Ok(context.checkpoint_id),
            DPNOpType::GetNonce => Ok(context.nonce),
            DPNOpType::GetUserPublicKeyHash => {
                // Returns first element of hash; array result handled separately
                Ok(context.user_public_key_hash[0])
            }
            DPNOpType::GetSessionProofTreeRoot => {
                // Scalar view of the tree root; the full hash is registered
                // for TargetAt in the post-step below, matching the witness.
                Ok(context.session_proof_tree_root[0])
            }

            // Hashing
            DPNOpType::HashNoPad => {
                op_counts.hash_ops += 1;
                let args: Vec<GoldilocksField> = def.inputs.iter().map(|&id| GoldilocksField::from_noncanonical_u64(resolve(id))).collect();
                let result = PoseidonHash::hash_no_pad(&args);
                // Return first element; full hash stored as array
                Ok(result.to_vec()[0].to_canonical_u64())
            }
            DPNOpType::HashTwoToOne => {
                op_counts.hash_ops += 1;
                let args: Vec<GoldilocksField> = def.inputs.iter().map(|&id| GoldilocksField::from_noncanonical_u64(resolve(id))).collect();
                if args.len() == 8 {
                    let left = plonky2::hash::hash_types::HashOut {
                        elements: [args[0], args[1], args[2], args[3]],
                    };
                    let right = plonky2::hash::hash_types::HashOut {
                        elements: [args[4], args[5], args[6], args[7]],
                    };
                    let result = PoseidonHash::two_to_one(left, right);
                    Ok(result.elements[0].to_canonical_u64())
                } else {
                    anyhow::bail!("HashTwoToOne requires exactly 8 inputs, got {}", args.len());
                }
            }
            DPNOpType::Keccak256 => {
                op_counts.hash_ops += 1;
                let args: Vec<u64> = def.inputs.iter().map(|&id| resolve(id)).collect();
                let result = semantics::keccak_u32_words_be(&args)?;
                Ok(result[0] as u64)
            }

            // State command results: look up from pre-computed results map
            DPNOpType::GetStateCommandResultHash
            | DPNOpType::GetStateCommandResultSingle
            | DPNOpType::GetStateCommandResultArray
            | DPNOpType::GetStateQueryResult
            | DPNOpType::GetStateQueryResultSingle => {
                if !def.inputs.is_empty() {
                    let cmd_idx = def.inputs[0] as usize;
                    if let Some(result) = state_cmd_results.get(&cmd_idx) {
                        Ok(if !result.is_empty() { result[0] } else { 0 })
                    } else {
                        Ok(0)
                    }
                } else {
                    Ok(0)
                }
            }

            // Array access
            DPNOpType::TargetAt => {
                let array = registers.get_array_by_encoded_id(def.inputs[0]);
                let index = resolve(def.inputs[1]) as usize;
                if index < array.len() {
                    Ok(array[index])
                } else {
                    anyhow::bail!("Array index out of bounds: {} >= {}", index, array.len());
                }
            }

            // Bit operations.
            DPNOpType::SumBits => {
                // Weighted binary reconstruction sum(bit[i] * 2^i) over
                // strict boolean inputs, reduced mod p — matches the
                // witness and the circuit (the old fold was an unweighted
                // field sum, a third SumBits dialect).
                let bits: Vec<bool> = def
                    .inputs
                    .iter()
                    .map(|id| semantics::resolve_bool_value("SumBits", resolve(*id)))
                    .collect::<Result<_, _>>()?;
                let sum = semantics::sum_bits_weighted(&bits)?;
                Ok(GoldilocksField::from_noncanonical_u64(sum).to_canonical_u64())
            }

            // ECDSA verification: 36 inputs = pk[16] ++ sig[16] ++ msg[4],
            // packed exactly like the core_eval arm (u32 words in reversed
            // word order with big-endian bytes; msg words are full felts).
            // Invalid public keys / signatures fail verification (return 0)
            // instead of aborting. This arm previously fell through to the
            // catch-all below and silently returned 0 even for valid
            // signatures.
            DPNOpType::Secp256k1Verify => {
                use k256::ecdsa::signature::hazmat::PrehashVerifier;
                if def.inputs.len() != 36 {
                    anyhow::bail!("Secp256k1Verify requires exactly 36 inputs, got {}", def.inputs.len());
                }
                let words: Vec<u64> = def.inputs.iter().map(|&id| resolve(id)).collect();
                let be_u32_words = |ws: &[u64]| -> Vec<u8> {
                    ws.iter()
                        .map(|w| {
                            // Same range check as the vm / core_eval arms:
                            // pk and sig words must fit a u32 (0xffffffff is
                            // a legal word — a `< 0xffffffff` check rejects
                            // it, and silent `as u32` truncation hides it).
                            assert!(*w <= 0xffffffff, "secp pk/sig words must fit u32");
                            *w as u32
                        })
                        .flat_map(|w| w.to_le_bytes())
                        .rev()
                        .collect()
                };
                let mut sec1 = vec![0x04];
                sec1.extend(be_u32_words(&words[0..8]));
                sec1.extend(be_u32_words(&words[8..16]));
                let Ok(vk) = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
                    return Ok(0);
                };
                let mut sig_bytes = be_u32_words(&words[16..24]);
                sig_bytes.extend(be_u32_words(&words[24..32]));
                let Ok(sig) = k256::ecdsa::Signature::from_slice(&sig_bytes) else {
                    return Ok(0);
                };
                let msg_bytes: Vec<u8> = words[32..36].iter().flat_map(|w| w.to_le_bytes()).rev().collect();
                Ok(matches!(vk.verify_prehash(&msg_bytes, &sig), Ok(_)) as u64)
            }

            // SplitBits' real result is the bool array materialized in the
            // post-step below; array defs have no meaningful scalar view, so
            // the scalar resolution is an explicit placeholder.
            DPNOpType::SplitBits => Ok(0),
            // Same pattern for DivRem4's [quotient, remainder] array.
            DPNOpType::DivRem4 => Ok(0),

            _ => {
                // Every opcode must have an explicit arm: silently returning
                // 0 would hide a missing implementation as a wrong result.
                // (The structural validator already rejects the known
                // no-implementation opcodes before execution.)
                anyhow::bail!("VmExecutor has no arm for opcode {:?}", def.op_type)
            }
        }
    }

    /// Process a state command, recording reads and writes
    fn process_state_command(
        &mut self,
        cmd: &DPNStateCmd<u64>,
        cmd_index: usize,
        context: &ExecutionContext,
        registers: &Registers,
        state_reads: &mut Vec<StateRead>,
        state_writes: &mut Vec<StateWrite>,
        op_counts: &mut OpCounts,
    ) -> anyhow::Result<Option<Vec<u64>>> {
        let resolve = |id: u64| -> u64 { registers.get_by_encoded_id(id) };

        match cmd {
            // Write commands
            DPNStateCmd::SetContractStateSlotSingle(c) => {
                op_counts.state_write_ops += 1;
                let condition = resolve(c.condition) != 0;
                let slot = resolve(c.sub_slot_index);
                let new_val = resolve(c.value);
                let old_val = self.read_slot(context.user_id, context.contract_id, slot)?;

                if condition {
                    self.write_overlay.insert((context.user_id, context.contract_id, slot), new_val);
                }

                state_writes.push(StateWrite {
                    command_index: cmd_index,
                    command_type: "SetContractStateSlotSingle".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    old_value: vec![old_val],
                    new_value: vec![new_val],
                    condition,
                });
                return Ok(Some(vec![old_val, new_val]));
            }

            DPNStateCmd::SetContractStateSlotHash(c) => {
                op_counts.state_write_ops += 1;
                let condition = resolve(c.condition) != 0;
                let slot = resolve(c.slot_index);
                let new_val: [u64; 4] = [resolve(c.value[0]), resolve(c.value[1]), resolve(c.value[2]), resolve(c.value[3])];
                let old_val = self.read_hash(context.user_id, context.contract_id, slot)?;

                if condition {
                    let base = slot * 4;
                    for (i, &v) in new_val.iter().enumerate() {
                        self.write_overlay.insert((context.user_id, context.contract_id, base + i as u64), v);
                    }
                }

                state_writes.push(StateWrite {
                    command_index: cmd_index,
                    command_type: "SetContractStateSlotHash".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    old_value: old_val.to_vec(),
                    new_value: new_val.to_vec(),
                    condition,
                });
                let mut result = old_val.to_vec();
                result.extend_from_slice(&new_val);
                return Ok(Some(result));
            }

            DPNStateCmd::SetContractStateSlotRange(c) => {
                op_counts.state_write_ops += 1;
                let condition = resolve(c.condition) != 0;
                let slot = resolve(c.sub_slot_index);
                let new_vals: Vec<u64> = c.value.iter().map(|&id| resolve(id)).collect();
                let old_vals = self.read_range(context.user_id, context.contract_id, slot, new_vals.len())?;

                if condition {
                    for (i, &v) in new_vals.iter().enumerate() {
                        self.write_overlay.insert((context.user_id, context.contract_id, slot + i as u64), v);
                    }
                }

                state_writes.push(StateWrite {
                    command_index: cmd_index,
                    command_type: "SetContractStateSlotRange".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    old_value: old_vals.clone(),
                    new_value: new_vals.clone(),
                    condition,
                });
                let mut result = old_vals;
                result.extend(new_vals);
                return Ok(Some(result));
            }

            DPNStateCmd::ClearEntireTree(c) => {
                op_counts.state_write_ops += 1;
                let condition = resolve(c.condition) != 0;
                if condition {
                    // Clear all slots for this contract
                    self.write_overlay
                        .retain(|&(uid, cid, _), _| !(uid == context.user_id && cid == context.contract_id));
                }
                state_writes.push(StateWrite {
                    command_index: cmd_index,
                    command_type: "ClearEntireTree".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: 0,
                    old_value: vec![],
                    new_value: vec![],
                    condition,
                });
                return Ok(Some(vec![0; 4]));
            }

            // Read commands - self user current contract
            DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
                op_counts.state_read_ops += 1;
                let slot = resolve(c.sub_slot_index);
                let value = self.read_slot(context.user_id, context.contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserCurrentContractStateSlotSingle".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    value: vec![value],
                });
            }

            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
                op_counts.state_read_ops += 1;
                let slot = resolve(c.slot_index);
                let value = self.read_hash(context.user_id, context.contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserCurrentContractStateSlotHash".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    value: value.to_vec(),
                });
            }

            DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
                op_counts.state_read_ops += 1;
                let slot = resolve(c.sub_slot_index);
                let len = c.length as usize;
                let value = self.read_range(context.user_id, context.contract_id, slot, len)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserCurrentContractStateSlotRange".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: slot,
                    value,
                });
            }

            // Read commands - self user external contract
            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
                op_counts.state_read_ops += 1;
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                let value = self.read_slot(context.user_id, contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserExternalContractStateSlotSingle".to_string(),
                    user_id: context.user_id,
                    contract_id,
                    slot_index: slot,
                    value: vec![value],
                });
            }

            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
                op_counts.state_read_ops += 1;
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.slot_index);
                let value = self.read_hash(context.user_id, contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserExternalContractStateSlotHash".to_string(),
                    user_id: context.user_id,
                    contract_id,
                    slot_index: slot,
                    value: value.to_vec(),
                });
            }

            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => {
                op_counts.state_read_ops += 1;
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                let len = c.length as usize;
                let value = self.read_range(context.user_id, contract_id, slot, len)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserExternalContractStateSlotRange".to_string(),
                    user_id: context.user_id,
                    contract_id,
                    slot_index: slot,
                    value,
                });
            }

            // Read commands - other user
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
                op_counts.state_read_ops += 1;
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                let value = self.read_slot(user_id, contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetOtherUserContractStateSlotSingle".to_string(),
                    user_id,
                    contract_id,
                    slot_index: slot,
                    value: vec![value],
                });
            }

            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => {
                op_counts.state_read_ops += 1;
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.slot_index);
                let value = self.read_hash(user_id, contract_id, slot)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetOtherUserContractStateSlotHash".to_string(),
                    user_id,
                    contract_id,
                    slot_index: slot,
                    value: value.to_vec(),
                });
            }

            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => {
                op_counts.state_read_ops += 1;
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                let len = c.length as usize;
                let value = self.read_range(user_id, contract_id, slot, len)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetOtherUserContractStateSlotRange".to_string(),
                    user_id,
                    contract_id,
                    slot_index: slot,
                    value,
                });
            }

            // External calls
            DPNStateCmd::InvokeExternalContractFunctionSync(_c) => {
                op_counts.external_call_ops += 1;
                // Sync external call handling would require loading the target
                // contract For now, record the call without
                // executing
            }

            DPNStateCmd::InvokeExternalContractFunctionDeferred(_c) => {
                op_counts.external_call_ops += 1;
                // Deferred calls are just recorded, not executed
            }

            // Checkpoint/Contract queries
            DPNStateCmd::GetCheckpointLeafStats(c) => {
                op_counts.state_read_ops += 1;
                let cp_id = resolve(c.checkpoint_id);
                let stats = self.state.get_checkpoint_stats(cp_id)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetCheckpointLeafStats".to_string(),
                    user_id: 0,
                    contract_id: 0,
                    slot_index: cp_id,
                    value: stats,
                });
            }
            DPNStateCmd::GetGlobalStateRoots(c) => {
                op_counts.state_read_ops += 1;
                let cp_id = resolve(c.checkpoint_id);
                let roots = self.state.get_checkpoint_global_state_roots(cp_id)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetGlobalStateRoots".to_string(),
                    user_id: 0,
                    contract_id: 0,
                    slot_index: cp_id,
                    value: roots,
                });
            }

            DPNStateCmd::GetContractLeaf(c) => {
                op_counts.state_read_ops += 1;
                let cid = resolve(c.contract_id);
                let leaf = self.state.get_contract_leaf(cid)?;
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetContractLeaf".to_string(),
                    user_id: 0,
                    contract_id: cid,
                    slot_index: 0,
                    value: leaf,
                });
            }

            // IMT write command
            DPNStateCmd::SetIMTContractStateValue(c) => {
                op_counts.state_write_ops += 1;
                let condition = resolve(c.condition) != 0;
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let new_val = [resolve(c.value[0]), resolve(c.value[1]), resolve(c.value[2]), resolve(c.value[3])];
                let old_val = self.read_imt_value(context.user_id, context.contract_id, &key);

                if condition {
                    self.imt_write_overlay.insert((context.user_id, context.contract_id, key), new_val);
                }

                state_writes.push(StateWrite {
                    command_index: cmd_index,
                    command_type: "SetIMTContractStateValue".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: 0, // IMT uses key-based addressing, not slot index
                    old_value: old_val.to_vec(),
                    new_value: new_val.to_vec(),
                    condition,
                });
                let mut result = old_val.to_vec();
                result.extend_from_slice(&new_val);
                return Ok(Some(result));
            }

            // IMT read commands
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                op_counts.state_read_ops += 1;
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, context.contract_id, &key);
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserCurrentIMTContractStateValue".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: 0,
                    value: value.to_vec(),
                });
            }

            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
                op_counts.state_read_ops += 1;
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, contract_id, &key);
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetSelfUserExternalIMTContractStateValue".to_string(),
                    user_id: context.user_id,
                    contract_id,
                    slot_index: 0,
                    value: value.to_vec(),
                });
            }

            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                op_counts.state_read_ops += 1;
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(user_id, contract_id, &key);
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "GetOtherUserIMTContractStateValue".to_string(),
                    user_id,
                    contract_id,
                    slot_index: 0,
                    value: value.to_vec(),
                });
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                op_counts.state_read_ops += 1;
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, context.contract_id, &key);
                let exists = if value == [0u64; 4] { 0 } else { 1 };
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "ContainsSelfUserCurrentIMTContractStateValue".to_string(),
                    user_id: context.user_id,
                    contract_id: context.contract_id,
                    slot_index: 0,
                    value: vec![exists],
                });
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                op_counts.state_read_ops += 1;
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(user_id, contract_id, &key);
                let exists = if value == [0u64; 4] { 0 } else { 1 };
                state_reads.push(StateRead {
                    command_index: cmd_index,
                    command_type: "ContainsOtherUserIMTContractStateValue".to_string(),
                    user_id,
                    contract_id,
                    slot_index: 0,
                    value: vec![exists],
                });
            }
        }
        Ok(Some(self.get_state_cmd_result(cmd, context, registers)?))
    }

    /// Get the result values of a state command (for storing in registers)
    fn get_state_cmd_result(&self, cmd: &DPNStateCmd<u64>, context: &ExecutionContext, registers: &Registers) -> anyhow::Result<Vec<u64>> {
        let resolve = |id: u64| -> u64 { registers.get_by_encoded_id(id) };

        match cmd {
            // Read results
            DPNStateCmd::GetSelfUserCurrentContractStateSlotSingle(c) => {
                let slot = resolve(c.sub_slot_index);
                Ok(vec![self.read_slot(context.user_id, context.contract_id, slot)?])
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotHash(c) => {
                let slot = resolve(c.slot_index);
                let h = self.read_hash(context.user_id, context.contract_id, slot)?;
                Ok(h.to_vec())
            }
            DPNStateCmd::GetSelfUserCurrentContractStateSlotRange(c) => {
                let slot = resolve(c.sub_slot_index);
                self.read_range(context.user_id, context.contract_id, slot, c.length as usize)
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotSingle(c) => {
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                Ok(vec![self.read_slot(context.user_id, contract_id, slot)?])
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotHash(c) => {
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.slot_index);
                let h = self.read_hash(context.user_id, contract_id, slot)?;
                Ok(h.to_vec())
            }
            DPNStateCmd::GetSelfUserExternalContractStateSlotRange(c) => {
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                self.read_range(context.user_id, contract_id, slot, c.length as usize)
            }
            DPNStateCmd::GetOtherUserContractStateSlotSingle(c) => {
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                Ok(vec![self.read_slot(user_id, contract_id, slot)?])
            }
            DPNStateCmd::GetOtherUserContractStateSlotHash(c) => {
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.slot_index);
                let h = self.read_hash(user_id, contract_id, slot)?;
                Ok(h.to_vec())
            }
            DPNStateCmd::GetOtherUserContractStateSlotRange(c) => {
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let slot = resolve(c.sub_slot_index);
                self.read_range(user_id, contract_id, slot, c.length as usize)
            }

            // Write results return old + new values
            DPNStateCmd::SetContractStateSlotSingle(c) => {
                let slot = resolve(c.sub_slot_index);
                let old = self.read_slot(context.user_id, context.contract_id, slot)?;
                let new_val = resolve(c.value);
                Ok(vec![old, new_val])
            }
            DPNStateCmd::SetContractStateSlotHash(c) => {
                let slot = resolve(c.slot_index);
                let old = self.read_hash(context.user_id, context.contract_id, slot)?;
                let mut result = old.to_vec();
                for &v in &c.value {
                    result.push(resolve(v));
                }
                Ok(result)
            }
            DPNStateCmd::SetContractStateSlotRange(c) => {
                let slot = resolve(c.sub_slot_index);
                let len = c.value.len();
                let old = self.read_range(context.user_id, context.contract_id, slot, len)?;
                let mut result = old;
                for &v in &c.value {
                    result.push(resolve(v));
                }
                Ok(result)
            }
            DPNStateCmd::ClearEntireTree(_) => {
                Ok(vec![0; 4]) // Returns empty root hash
            }

            // Checkpoint/Contract
            DPNStateCmd::GetCheckpointLeafStats(c) => {
                let cp_id = resolve(c.checkpoint_id);
                self.state.get_checkpoint_stats(cp_id)
            }
            DPNStateCmd::GetGlobalStateRoots(c) => {
                let cp_id = resolve(c.checkpoint_id);
                self.state.get_checkpoint_global_state_roots(cp_id)
            }
            DPNStateCmd::GetContractLeaf(c) => {
                let cid = resolve(c.contract_id);
                self.state.get_contract_leaf(cid)
            }

            // External calls return their outputs
            DPNStateCmd::InvokeExternalContractFunctionSync(c) => {
                Ok(vec![0; c.num_outputs as usize]) // Placeholder
            }
            DPNStateCmd::InvokeExternalContractFunctionDeferred(_) => {
                Ok(vec![0; 4]) // Deferred call returns call-hash[4]
            }

            // IMT write result: old_value[4] + new_value[4] = 8 felts
            DPNStateCmd::SetIMTContractStateValue(c) => {
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let old_val = self.read_imt_value(context.user_id, context.contract_id, &key);
                let new_val = [resolve(c.value[0]), resolve(c.value[1]), resolve(c.value[2]), resolve(c.value[3])];
                let mut result = old_val.to_vec();
                result.extend_from_slice(&new_val);
                Ok(result)
            }

            // IMT read results: value[4] = 4 felts
            DPNStateCmd::GetSelfUserCurrentIMTContractStateValue(c) => {
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, context.contract_id, &key);
                Ok(value.to_vec())
            }
            DPNStateCmd::GetSelfUserExternalIMTContractStateValue(c) => {
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, contract_id, &key);
                Ok(value.to_vec())
            }
            DPNStateCmd::GetOtherUserIMTContractStateValue(c) => {
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(user_id, contract_id, &key);
                Ok(value.to_vec())
            }
            DPNStateCmd::ContainsSelfUserCurrentIMTContractStateValue(c) => {
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(context.user_id, context.contract_id, &key);
                Ok(vec![if value == [0u64; 4] { 0 } else { 1 }])
            }
            DPNStateCmd::ContainsOtherUserIMTContractStateValue(c) => {
                let user_id = resolve(c.user_id);
                let contract_id = resolve(c.contract_id);
                let key = [resolve(c.key[0]), resolve(c.key[1]), resolve(c.key[2]), resolve(c.key[3])];
                let value = self.read_imt_value(user_id, contract_id, &key);
                Ok(vec![if value == [0u64; 4] { 0 } else { 1 }])
            }
        }
    }

    /// Compute net state delta from reads and writes
    fn compute_state_delta(reads: &[StateRead], writes: &[StateWrite]) -> Vec<StateDelta> {
        let mut deltas: HashMap<(u64, u64, u64), (Vec<u64>, Vec<u64>)> = HashMap::new();

        // Collect initial read values
        for read in reads {
            let key = (read.user_id, read.contract_id, read.slot_index);
            deltas.entry(key).or_insert_with(|| (read.value.clone(), read.value.clone()));
        }

        // Apply writes
        for write in writes {
            if write.condition {
                let key = (write.user_id, write.contract_id, write.slot_index);
                let entry = deltas.entry(key).or_insert_with(|| (write.old_value.clone(), write.old_value.clone()));
                entry.1 = write.new_value.clone();
            }
        }

        // Filter to only changed values
        deltas
            .into_iter()
            .filter(|(_, (old, new))| old != new)
            .map(|((user_id, contract_id, slot_index), (old_value, new_value))| StateDelta {
                user_id,
                contract_id,
                slot_index,
                old_value,
                new_value,
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Register file for VM execution
// ---------------------------------------------------------------------------

/// Register file holding concrete values during execution
struct Registers {
    targets: Vec<u64>,
    bools: Vec<u64>,
    u32s: Vec<u64>,
    hashes: Vec<u64>,
    hash160s: Vec<u64>,
    target_arrays: Vec<Vec<u64>>,
    bool_arrays: Vec<Vec<u64>>,
    u32_arrays: Vec<Vec<u64>>,
    /// Full 4-element hash results for TargetAt access on HashOut values.
    hash_out_arrays: HashMap<usize, Vec<u64>>,
}

impl Registers {
    fn new() -> Self {
        // Pre-allocate reasonable sizes
        Registers {
            targets: vec![0; 4096],
            bools: vec![0; 1024],
            u32s: vec![0; 1024],
            hashes: vec![0; 1024],
            hash160s: vec![0; 256],
            target_arrays: vec![vec![]; 256],
            bool_arrays: vec![vec![]; 64],
            u32_arrays: vec![vec![]; 64],
            hash_out_arrays: HashMap::new(),
        }
    }

    fn ensure_capacity(&mut self, data_type: DPNBuiltInDataType, index: usize) {
        let vec = match data_type {
            DPNBuiltInDataType::Target => &mut self.targets,
            DPNBuiltInDataType::Bool => &mut self.bools,
            DPNBuiltInDataType::U32Target => &mut self.u32s,
            DPNBuiltInDataType::HashOut => &mut self.hashes,
            DPNBuiltInDataType::HashOut160 => &mut self.hash160s,
            DPNBuiltInDataType::TargetArray | DPNBuiltInDataType::BoolArray | DPNBuiltInDataType::U32TargetArray | DPNBuiltInDataType::Unknown => {
                return
            }
        };
        if index >= vec.len() {
            vec.resize(index + 1, 0);
        }
    }

    fn set(&mut self, data_type: DPNBuiltInDataType, index: usize, value: u64) {
        self.ensure_capacity(data_type, index);
        match data_type {
            DPNBuiltInDataType::Target => self.targets[index] = value,
            DPNBuiltInDataType::Bool => self.bools[index] = value,
            DPNBuiltInDataType::U32Target => self.u32s[index] = value,
            DPNBuiltInDataType::HashOut => self.hashes[index] = value,
            DPNBuiltInDataType::HashOut160 => self.hash160s[index] = value,
            DPNBuiltInDataType::Unknown => {}
            DPNBuiltInDataType::TargetArray => {
                if index >= self.target_arrays.len() {
                    self.target_arrays.resize(index + 1, vec![]);
                }
                self.target_arrays[index] = vec![value];
            }
            DPNBuiltInDataType::BoolArray => {
                if index >= self.bool_arrays.len() {
                    self.bool_arrays.resize(index + 1, vec![]);
                }
                self.bool_arrays[index] = vec![value];
            }
            DPNBuiltInDataType::U32TargetArray => {
                if index >= self.u32_arrays.len() {
                    self.u32_arrays.resize(index + 1, vec![]);
                }
                self.u32_arrays[index] = vec![value];
            }
        }
    }

    fn set_array(&mut self, data_type: DPNBuiltInDataType, index: usize, values: Vec<u64>) {
        match data_type {
            DPNBuiltInDataType::HashOut => {
                if !values.is_empty() {
                    self.set(data_type, index, values[0]);
                    self.hash_out_arrays.insert(index, values);
                }
            }
            DPNBuiltInDataType::TargetArray => {
                if index >= self.target_arrays.len() {
                    self.target_arrays.resize(index + 1, vec![]);
                }
                self.target_arrays[index] = values;
            }
            DPNBuiltInDataType::BoolArray => {
                if index >= self.bool_arrays.len() {
                    self.bool_arrays.resize(index + 1, vec![]);
                }
                self.bool_arrays[index] = values;
            }
            DPNBuiltInDataType::U32TargetArray => {
                if index >= self.u32_arrays.len() {
                    self.u32_arrays.resize(index + 1, vec![]);
                }
                self.u32_arrays[index] = values;
            }
            _ => {
                // For scalar types, just set the first value
                if !values.is_empty() {
                    self.set(data_type, index, values[0]);
                }
            }
        }
    }

    fn get(&self, data_type: DPNBuiltInDataType, index: usize) -> u64 {
        match data_type {
            DPNBuiltInDataType::Target => self.targets.get(index).copied().unwrap_or(0),
            DPNBuiltInDataType::Bool => self.bools.get(index).copied().unwrap_or(0),
            DPNBuiltInDataType::U32Target => self.u32s.get(index).copied().unwrap_or(0),
            DPNBuiltInDataType::HashOut => self.hashes.get(index).copied().unwrap_or(0),
            DPNBuiltInDataType::HashOut160 => self.hash160s.get(index).copied().unwrap_or(0),
            DPNBuiltInDataType::Unknown => 0,
            DPNBuiltInDataType::TargetArray => self.target_arrays.get(index).and_then(|v| v.first()).copied().unwrap_or(0),
            DPNBuiltInDataType::BoolArray => self.bool_arrays.get(index).and_then(|v| v.first()).copied().unwrap_or(0),
            DPNBuiltInDataType::U32TargetArray => self.u32_arrays.get(index).and_then(|v| v.first()).copied().unwrap_or(0),
        }
    }

    fn get_by_encoded_id(&self, encoded_id: u64) -> u64 {
        let (data_type, index) = decode_indexed_op_id(encoded_id);
        self.get(data_type, index)
    }

    fn get_array_by_encoded_id(&self, encoded_id: u64) -> Vec<u64> {
        let (data_type, index) = decode_indexed_op_id(encoded_id);
        match data_type {
            DPNBuiltInDataType::TargetArray => self.target_arrays.get(index).cloned().unwrap_or_default(),
            DPNBuiltInDataType::BoolArray => self.bool_arrays.get(index).cloned().unwrap_or_default(),
            DPNBuiltInDataType::U32TargetArray => self.u32_arrays.get(index).cloned().unwrap_or_default(),
            DPNBuiltInDataType::HashOut => {
                // Return full 4-element hash if stored, otherwise single scalar
                if let Some(arr) = self.hash_out_arrays.get(&index) {
                    arr.clone()
                } else {
                    vec![self.get(data_type, index)]
                }
            }
            _ => vec![self.get(data_type, index)],
        }
    }
}

#[cfg(test)]
mod input_binding_tests {
    use super::*;
    use crate::dpn::ops::op_types::{encode_indexed_op_id, DPNIndexedVarDef, DPNOpType};

    fn three_lane_program() -> DPNFunctionCircuitDefinition {
        let target = |i: usize| encode_indexed_op_id(DPNBuiltInDataType::Target, i);
        DPNFunctionCircuitDefinition {
            name: "binding".to_string(),
            method_id: 0,
            circuit_inputs: vec![
                encode_indexed_op_id(DPNBuiltInDataType::Target, 0),
                encode_indexed_op_id(DPNBuiltInDataType::U32Target, 0),
                encode_indexed_op_id(DPNBuiltInDataType::Bool, 0),
            ],
            circuit_outputs: vec![target(0)],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            events: vec![],
            definitions: vec![
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Target,
                    index: 0,
                    op_type: DPNOpType::InputTarget,
                    inputs: vec![0],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::U32Target,
                    index: 0,
                    op_type: DPNOpType::U32InputTarget,
                    inputs: vec![1],
                },
                DPNIndexedVarDef {
                    data_type: DPNBuiltInDataType::Bool,
                    index: 0,
                    op_type: DPNOpType::BoolInputTarget,
                    inputs: vec![2],
                },
            ],
        }
    }

    fn context() -> ExecutionContext {
        ExecutionContext {
            user_id: 0,
            contract_id: 0,
            caller_contract_id: 0,
            checkpoint_id: 0,
            nonce: 0,
            user_public_key_hash: [0; 4],
            session_proof_tree_root: [0; 4],
        }
    }

    // A host u64 at or above the field order must bind as the SAME value the
    // witness/circuit prove (F::from_noncanonical_u64 reduction): the preview
    // can never silently disagree with the proof.
    #[test]
    fn felt_inputs_bind_canonically_like_the_prove_path() {
        let defn = three_lane_program();
        let mut executor = VmExecutor::new(InMemoryStateBackend::new());
        let result = executor.execute(&defn, &context(), &[GOLDILOCKS_ORDER + 1, 0, 0]).unwrap();
        assert_eq!(result.outputs[0], 1, "p+1 must bind as F(1)");
    }

    #[test]
    fn u32_and_bool_inputs_reject_out_of_range_values() {
        let defn = three_lane_program();
        let mut executor = VmExecutor::new(InMemoryStateBackend::new());
        let err = executor.execute(&defn, &context(), &[0, 0x1_0000_0000, 0]).unwrap_err();
        assert!(err.to_string().contains("u32 lane"), "{err}");

        let mut executor = VmExecutor::new(InMemoryStateBackend::new());
        let err = executor.execute(&defn, &context(), &[0, 0, 2]).unwrap_err();
        assert!(err.to_string().contains("boolean"), "{err}");
    }
}

#[cfg(test)]
mod nor_lane_tests {
    use super::*;
    use crate::dpn::ops::op_types::DPNIndexedVarDef;

    fn d(lane: DPNBuiltInDataType, idx: usize, op: DPNOpType, inputs: Vec<u64>) -> DPNIndexedVarDef {
        DPNIndexedVarDef { data_type: lane, index: idx, op_type: op, inputs }
    }
    fn u32(i: usize) -> u64 { crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::U32Target, i) }
    fn tgt(i: usize) -> u64 { crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::Target, i) }

    #[test]
    fn nor_rejects_non_boolean_scalar_operand() {
        let target = |i: usize| crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::Target, i);
        let bool_id = |i: usize| crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::Bool, i);
        let defn = DPNFunctionCircuitDefinition {
            name: "nor".to_string(),
            method_id: 0,
            circuit_inputs: vec![tgt(0), bool_id(0)],
            circuit_outputs: vec![bool_id(2), crate::dpn::ops::op_types::encode_indexed_op_id(DPNBuiltInDataType::U32Target, 3)],
            state_commands: vec![],
            state_command_resolution_indices: vec![],
            assertions: vec![],
            events: vec![],
            definitions: vec![
                d(DPNBuiltInDataType::Target, 0, DPNOpType::InputTarget, vec![0]),
                d(DPNBuiltInDataType::Bool, 0, DPNOpType::BoolInputTarget, vec![1]),
                d(DPNBuiltInDataType::U32Target, 0, DPNOpType::ConstantU32, vec![1463407909]),
                d(DPNBuiltInDataType::U32Target, 1, DPNOpType::ConstantU32, vec![2]),
                d(DPNBuiltInDataType::Target, 1, DPNOpType::Constant, vec![8]),
                d(DPNBuiltInDataType::U32Target, 2, DPNOpType::ConstantU32, vec![1]),
                d(DPNBuiltInDataType::Bool, 1, DPNOpType::ConstantTrue, vec![]),
                d(DPNBuiltInDataType::Target, 2, DPNOpType::Constant, vec![2]),
                d(DPNBuiltInDataType::U32Target, 3, DPNOpType::CastU32, vec![tgt(2)]),
                d(DPNBuiltInDataType::Bool, 2, DPNOpType::Nor, vec![bool_id(1), tgt(2)]),
            ],
        };
        let ctx = ExecutionContext {
            user_id: 0,
            contract_id: 0,
            caller_contract_id: 0,
            checkpoint_id: 0,
            nonce: 0,
            user_public_key_hash: [0; 4],
            session_proof_tree_root: [0; 4],
        };
        let mut executor = VmExecutor::new(InMemoryStateBackend::new());
        let err = executor.execute(&defn, &ctx, &[4, 0]).unwrap_err();
        assert!(err.to_string().contains("invalid bool value"), "{err}");
    }
}
