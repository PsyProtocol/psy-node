use serde::{Deserialize, Serialize};

use psy_client_data::qdata::contract::ContractCodeDefinition;
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use crate::abi::Abi;

/// The complete output of the PSY compiler.
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

/// The complete compiler output consumed by deployment and update tooling.
///
/// This unifies `state_tree_height`, the per-method circuit definitions, and
/// the full ABI (including `state_layout`) in a single JSON artifact so that
/// callers do not need to pass a separate ABI file to deploy a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationArtifact {
    pub state_tree_height: u16,
    pub circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
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

    /// Build the unified compilation artifact used by deploy/update commands.
    pub fn to_compilation_artifact(&self) -> CompilationArtifact {
        CompilationArtifact {
            state_tree_height: self.contract_code.state_tree_height,
            circuit_definitions: self.circuit_definitions.clone(),
            abi: self.abi.clone(),
        }
    }

    /// Serialize the unified compilation artifact to JSON.
    pub fn to_compilation_artifact_json(&self) -> anyhow::Result<String> {
        serde_json::to_string(&self.to_compilation_artifact()).map_err(|e| anyhow::anyhow!(e))
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
