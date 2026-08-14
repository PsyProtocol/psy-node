use std::{fs, path::Path, str::FromStr};

use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyHasher, C, D, F};
use psy_compiler::{abi::Abi, output::serialize::{CompilationArtifact, ContractOutput}};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_prover::{
    session::{compile_bridge::build_layout_aware_update_command, gen_contract_update_and_circuits_for_functions},
    wallet::memory_wallet::{get_public_key_info, get_zk_fingerprint},
};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QUpdateContractRPCRequest,
};
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use super::args::UpdateContractArgs;
use crate::result::{CommandResult, UpdateResult, UpdateStatus};

// #[cfg(feature = "is_sync")]
pub async fn run(args: UpdateContractArgs) -> anyhow::Result<CommandResult> {
    tracing::info!("updating contract {}", args.contract_id);

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let rpc_provider = RpcProvider::new_with_config(&rpc_config)?;

    let private_key = QHashOut::<F>::from_str(&args.private_key)?;
    let fingerprint = args
        .fingerprint
        .as_ref()
        .map(|f| -> anyhow::Result<_> { QHashOut::<F>::from_str(f).map_err(|e| anyhow::anyhow!("parse fingerprint error: {}", e)) })
        .transpose()?;

    let fingerprint = fingerprint.unwrap_or_else(|| get_zk_fingerprint());
    let deployer = get_public_key_info::<F>(private_key, fingerprint)?.qfhash::<PsyHasher>();

    let contract_source = fs::read_to_string(&args.contract_path)?;
    // Prefer the unified compilation artifact (state_tree_height + defs + ABI).
    // Fall back to the legacy raw array of circuit definitions.
    let (defs_array, artifact_abi) =
        if let Ok(artifact) = serde_json::from_str::<CompilationArtifact>(&contract_source) {
            (artifact.circuit_definitions, Some(artifact.abi))
        } else {
            let defs: Vec<DPNFunctionCircuitDefinition> = serde_json::from_str(&contract_source)
                .map_err(|error| anyhow::anyhow!("failed to parse circuit definitions {}: {}", args.contract_path, error))?;
            (defs, None)
        };

    let old_abi: Abi = match &args.old_abi_path {
        Some(path) => read_abi_from_path(path)?,
        None => artifact_abi
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--old-abi-path is required when --contract-path is a legacy circuit-definition array"))?,
    };
    let new_abi: Abi = match &args.new_abi_path {
        Some(path) => read_abi_from_path(path)?,
        None => artifact_abi
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--new-abi-path is required when --contract-path is a legacy circuit-definition array"))?,
    };
    anyhow::ensure!(
        old_abi.contract.state_tree_height == new_abi.contract.state_tree_height,
        "contract state tree height is immutable: old ABI height {}, new ABI height {}",
        old_abi.contract.state_tree_height,
        new_abi.contract.state_tree_height,
    );
    let contract_state_tree_height =
        u8::try_from(old_abi.contract.state_tree_height).map_err(|_| anyhow::anyhow!("contract state tree height does not fit in u8"))?;

    tracing::info!(
        "generating circuits with immutable contract state tree height {}",
        contract_state_tree_height
    );
    let (_result_circuits, update_cmd) =
        gen_contract_update_and_circuits_for_functions::<C, D>(args.contract_id, deployer, contract_state_tree_height, &defs_array)?;
    let old_output = ContractOutput {
        contract_code: psy_client_data::qdata::contract::ContractCodeDefinition {
            state_tree_height: old_abi.contract.state_tree_height,
            functions: vec![],
        },
        circuit_definitions: vec![],
        abi: old_abi,
    };
    let new_output = ContractOutput {
        contract_code: update_cmd.code_definition.clone(),
        circuit_definitions: defs_array,
        abi: new_abi,
    };
    let update_cmd = build_layout_aware_update_command(&old_output, &new_output, update_cmd)?;
    update_cmd.validate_shape()?;

    match args.output_path {
        Some(output_path) => {
            tracing::debug!("update cmd save to {}", output_path);
            let update_cmd_path = Path::new(&output_path);
            fs::write(update_cmd_path, serde_json::to_string(&update_cmd)?)?;
        }
        None => {
            tracing::debug!("update cmd: {}", serde_json::to_string(&update_cmd)?);
        }
    }

    if args.is_update {
        tracing::info!("user cli updating contract {}", args.contract_id);
        let update_content_hash = rpc_provider
            .update_contract(QUpdateContractRPCRequest { update_contract: update_cmd })
            .await?;
        tracing::info!("contract updated: {}", update_content_hash);
        return Ok(CommandResult::Update(UpdateResult {
            contract_id: args.contract_id,
            update_content_hash,
            network: psy_config.current_network_name().to_string(),
            status: UpdateStatus::Submitted,
        }));
    }

    Ok(CommandResult::generic("update-contract"))
}

/// Read an ABI from a path that may contain either a unified compilation
/// artifact or a standalone ABI JSON file.
fn read_abi_from_path(path: &str) -> anyhow::Result<Abi> {
    let source = fs::read_to_string(path)?;
    if let Ok(artifact) = serde_json::from_str::<CompilationArtifact>(&source) {
        return Ok(artifact.abi);
    }
    Ok(serde_json::from_str(&source)
        .map_err(|error| anyhow::anyhow!("failed to parse ABI {}: {}", path, error))?)
}
