use psy_client_data::qdata::contract::ContractCodeDefinition;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use crate::abi::{ContractABI, SpecCompliantAbi};

/// The complete output of the PSY compiler.
#[derive(Debug, Clone)]
pub struct ContractOutput {
    /// The compiled contract code definition (ready for deployment).
    pub contract_code: ContractCodeDefinition,
    /// The individual circuit definitions per method (for
    /// debugging/inspection).
    pub circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
    /// The contract ABI.
    pub abi: ContractABI,
    /// Spec-compliant ABI used by newer compiler consumers.
    pub spec_abi: SpecCompliantAbi,
}

impl ContractOutput {
    /// Serialize the contract code to bytes (bincode).
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(&self.contract_code).map_err(|e| anyhow::anyhow!(e))
    }

    /// Serialize the ABI to JSON.
    pub fn abi_to_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(&self.abi).map_err(|e| anyhow::anyhow!(e))
    }

    /// Serialize the spec-compliant ABI to JSON.
    pub fn spec_abi_to_json(&self) -> anyhow::Result<String> {
        self.spec_abi.to_json()
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
