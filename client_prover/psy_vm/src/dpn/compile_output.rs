use psy_client_data::{abi::Abi, qdata::contract::ContractCodeDefinition};

use crate::dpn::vm::def::DPNFunctionCircuitDefinition;

/// The complete output of a PSY contract compilation.
///
/// Composes the deployable contract code, the per-method circuit
/// definitions, and the canonical ABI. This is the compiler-independent
/// canonical home of `ContractOutput`; the native compile adapter
/// constructs it from the standalone compiler's JSON output.
#[derive(Debug, Clone)]
pub struct ContractOutput {
    /// The compiled contract code definition (ready for deployment).
    pub contract_code: ContractCodeDefinition,
    /// The individual circuit definitions per method (for
    /// debugging/inspection).
    pub circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
    /// The ABI — the single shape.
    pub abi: Abi,
}

impl ContractOutput {
    /// Serialize the contract code to bytes (bincode).
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(&self.contract_code).map_err(|e| anyhow::anyhow!(e))
    }

    /// Serialize the ABI to JSON (primary output).
    pub fn abi_to_json(&self) -> anyhow::Result<String> {
        self.abi.to_json()
    }

    /// Get method count.
    pub fn method_count(&self) -> usize {
        self.contract_code.functions.len()
    }

    /// Get state tree height.
    pub fn state_tree_height(&self) -> u16 {
        self.contract_code.state_tree_height
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_client_data::{
        abi::{AbiContract, AbiMethod, StateMutability},
        qdata::contract::ContractFunctionCodeDefinition,
    };

    #[test]
    fn serializes_contract_code_and_reports_abi_metadata() {
        let output = ContractOutput {
            contract_code: ContractCodeDefinition {
                state_tree_height: 12,
                functions: vec![ContractFunctionCodeDefinition {
                    method_id: 7,
                    num_inputs: 1,
                    num_outputs: 1,
                    vm_type: 0,
                    code: vec![1, 2],
                }],
            },
            circuit_definitions: vec![],
            abi: Abi {
                schema_version: "1".into(),
                contract: AbiContract {
                    name: "Example".into(),
                    state_tree_height: 12,
                    state: vec![],
                    methods: vec![AbiMethod {
                        name: "run".into(),
                        method_id: 7,
                        state_mutability: StateMutability::External,
                        inputs: vec![],
                        outputs: vec![],
                        input_felt_count: 0,
                        output_felt_count: 0,
                        vm_type: None,
                    }],
                },
                types: vec![],
            },
        };
        let bytes = output.to_bytes().unwrap();
        let decoded: ContractCodeDefinition = bincode::deserialize(&bytes).unwrap();
        assert_eq!(decoded, output.contract_code);
        assert_eq!(output.method_count(), 1);
        assert_eq!(output.state_tree_height(), 12);
        assert!(output.abi_to_json().unwrap().contains("Example"));
    }
}
