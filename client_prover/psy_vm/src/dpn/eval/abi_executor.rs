//! ABI-Aware Executor: Higher-level interface for contract execution
//! using ABI metadata for named parameter binding and field resolution.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use psy_client_data::abi::{Abi, AbiMethod, TypeRef};

use super::executor::{ExecutionContext, ExecutionResult, StateBackend, VmExecutor};
use crate::dpn::vm::def::DPNFunctionCircuitDefinition;

// ---------------------------------------------------------------------------
// Param value types
// ---------------------------------------------------------------------------

/// A typed parameter value for ABI-aware method calls.
#[derive(Debug, Clone)]
pub enum ParamValue {
    Felt(u64),
    Bool(bool),
    U32(u32),
    Hash([u64; 4]),
    Array(Vec<ParamValue>),
    Struct(Vec<(String, ParamValue)>),
}

impl ParamValue {
    /// Flatten a ParamValue into a vector of felt values.
    pub fn to_felts(&self) -> Vec<u64> {
        match self {
            ParamValue::Felt(v) => vec![*v],
            ParamValue::Bool(b) => vec![if *b { 1 } else { 0 }],
            ParamValue::U32(v) => vec![*v as u64],
            ParamValue::Hash(h) => h.to_vec(),
            ParamValue::Array(elems) => elems.iter().flat_map(|e| e.to_felts()).collect(),
            ParamValue::Struct(fields) => fields.iter().flat_map(|(_, v)| v.to_felts()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Formatted state delta
// ---------------------------------------------------------------------------

/// Human-readable formatted state change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormattedFieldChange {
    /// Resolved field path, e.g., "token_state.balance" or
    /// "users[42].total_sent"
    pub field_path: String,
    /// Old value as string
    pub old_value: String,
    /// New value as string
    pub new_value: String,
}

/// Complete formatted state delta with contract name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FormattedStateDelta {
    pub contract_name: String,
    pub field_changes: Vec<FormattedFieldChange>,
}

// ---------------------------------------------------------------------------
// ABI Executor
// ---------------------------------------------------------------------------

/// ABI-aware executor wrapping VmExecutor with contract metadata.
pub struct AbiExecutor<S: StateBackend> {
    executor: VmExecutor<S>,
    abi: Abi,
    circuit_defs: Vec<DPNFunctionCircuitDefinition>,
    /// Method name → index into circuit_defs
    method_index: HashMap<String, usize>,
}

impl<S: StateBackend> AbiExecutor<S> {
    /// Create a new ABI executor.
    pub fn new(state: S, abi: Abi, circuit_defs: Vec<DPNFunctionCircuitDefinition>) -> Self {
        let method_index: HashMap<String, usize> = circuit_defs
            .iter()
            .enumerate()
            .filter_map(|(i, d)| abi.contract.methods.iter().find(|m| m.method_id == d.method_id).map(|m| (m.name.clone(), i)))
            .collect();

        AbiExecutor {
            executor: VmExecutor::new(state),
            abi,
            circuit_defs,
            method_index,
        }
    }

    /// Get the ABI
    pub fn abi(&self) -> &Abi {
        &self.abi
    }

    /// List available method names.
    pub fn method_names(&self) -> Vec<&str> {
        self.abi.contract.methods.iter().map(|m| m.name.as_str()).collect()
    }

    /// Call a contract method by name with named parameters.
    pub fn call(&mut self, method_name: &str, params: &[(&str, ParamValue)], context: &ExecutionContext) -> anyhow::Result<ExecutionResult> {
        // Find method in ABI
        let abi_method = self.abi.contract.methods.iter().find(|m| m.name == method_name).ok_or_else(|| {
            let available: Vec<&str> = self.method_names();
            anyhow::anyhow!("Method '{}' not found. Available: {:?}", method_name, available)
        })?;

        // Find circuit definition
        let circuit_idx = self.method_index.get(method_name).ok_or_else(|| {
            anyhow::anyhow!(
                "No circuit definition found for method '{}' (method_id={})",
                method_name,
                abi_method.method_id
            )
        })?;

        // Validate and flatten parameters
        let inputs = self.flatten_params(abi_method, params)?;

        // Execute
        let circuit = &self.circuit_defs[*circuit_idx];
        self.executor.execute(circuit, context, &inputs)
    }

    /// Call a method with raw felt inputs (bypasses ABI parameter validation).
    pub fn call_raw(&mut self, method_name: &str, inputs: &[u64], context: &ExecutionContext) -> anyhow::Result<ExecutionResult> {
        let circuit_idx = self.method_index.get(method_name).ok_or_else(|| {
            let available: Vec<&str> = self.method_names();
            anyhow::anyhow!("Method '{}' not found. Available: {:?}", method_name, available)
        })?;

        let circuit = &self.circuit_defs[*circuit_idx];
        self.executor.execute(circuit, context, inputs)
    }

    /// Format an execution result's state delta using ABI field names.
    pub fn format_state_delta(&self, result: &ExecutionResult) -> FormattedStateDelta {
        let field_changes: Vec<FormattedFieldChange> = result
            .state_delta
            .iter()
            .map(|delta| {
                let field_path = self.resolve_slot_to_field(delta.slot_index);
                FormattedFieldChange {
                    field_path,
                    old_value: format_felt_vec(&delta.old_value),
                    new_value: format_felt_vec(&delta.new_value),
                }
            })
            .collect();

        FormattedStateDelta {
            contract_name: self.abi.contract.name.clone(),
            field_changes,
        }
    }

    /// Resolve a slot index to a human-readable field path.
    fn resolve_slot_to_field(&self, slot_index: u64) -> String {
        for field in &self.abi.contract.state {
            let offset = field.offset as u64;
            let size = field.felt_size as u64;

            if slot_index >= offset && slot_index < offset + size {
                if let TypeRef::Array { item_felt_size, .. } = &field.ty {
                    let item_felt_size = *item_felt_size as u64;
                    let relative = slot_index - offset;
                    let array_index = relative / item_felt_size;
                    let field_offset = relative % item_felt_size;
                    if field_offset == 0 {
                        return format!("{}[{}]", field.name, array_index);
                    }
                    return format!("{}[{}]+{}", field.name, array_index, field_offset);
                }
                let relative = slot_index - offset;
                if relative == 0 {
                    return field.name.clone();
                } else {
                    return format!("{}+{}", field.name, relative);
                }
            }
        }
        format!("slot_{}", slot_index)
    }

    /// Flatten named parameters according to ABI method definition.
    fn flatten_params(&self, method: &AbiMethod, params: &[(&str, ParamValue)]) -> anyhow::Result<Vec<u64>> {
        let mut inputs = Vec::new();

        // Match params by name against ABI method inputs.
        for abi_param in &method.inputs {
            let value = params
                .iter()
                .find(|(name, _)| *name == abi_param.name)
                .ok_or_else(|| anyhow::anyhow!("Missing parameter '{}' for method '{}'", abi_param.name, method.name))?;

            let felts = value.1.to_felts();
            if felts.len() != abi_param.felt_size {
                anyhow::bail!(
                    "Parameter '{}' expects {} felts, got {}",
                    abi_param.name,
                    abi_param.felt_size,
                    felts.len()
                );
            }
            inputs.extend(felts);
        }

        Ok(inputs)
    }
}

/// Format a vec of felts as a readable string.
fn format_felt_vec(values: &[u64]) -> String {
    if values.len() == 1 {
        format!("{}", values[0])
    } else {
        format!("{:?}", values)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_value_to_felts() {
        assert_eq!(ParamValue::Felt(42).to_felts(), vec![42]);
        assert_eq!(ParamValue::Bool(true).to_felts(), vec![1]);
        assert_eq!(ParamValue::Bool(false).to_felts(), vec![0]);
        assert_eq!(ParamValue::U32(100).to_felts(), vec![100]);
        assert_eq!(ParamValue::Hash([1, 2, 3, 4]).to_felts(), vec![1, 2, 3, 4]);
        assert_eq!(
            ParamValue::Array(vec![ParamValue::Felt(10), ParamValue::Felt(20)]).to_felts(),
            vec![10, 20]
        );
        assert_eq!(
            ParamValue::Struct(vec![
                ("a".to_string(), ParamValue::Felt(1)),
                ("b".to_string(), ParamValue::Hash([5, 6, 7, 8])),
            ])
            .to_felts(),
            vec![1, 5, 6, 7, 8]
        );
    }

    #[test]
    fn test_format_felt_vec() {
        assert_eq!(format_felt_vec(&[42]), "42");
        assert_eq!(format_felt_vec(&[1, 2, 3]), "[1, 2, 3]");
        assert_eq!(format_felt_vec(&[]), "[]");
    }
}
