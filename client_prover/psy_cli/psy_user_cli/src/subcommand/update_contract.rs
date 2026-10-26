use std::{fs, path::Path, str::FromStr};

use plonky2::{field::types::PrimeField64, plonk::proof::ProofWithPublicInputs};
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyHasher, C, D, F};
use psy_client_data::{qdata::contract::PsyContractLeaf, traits::qdatastore::qmetadata::QMetaDataStoreReaderSync};
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

use super::{args::UpdateContractArgs, contract_abi_upload, resolve_deployer_user_id};
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
    let public_key_hash = get_public_key_info::<F>(private_key, fingerprint)?.qfhash::<PsyHasher>();
    let deployer = resolve_deployer_user_id(&rpc_provider, public_key_hash, args.user_id).await?;

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

    let old_abi_path = args.old_abi_path.as_deref().ok_or_else(||
        anyhow::anyhow!("--old-abi-path is required: supply the ABI of the currently deployed contract")
    )?;
    let old_abi: Abi = read_abi_from_path(old_abi_path)?;
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
    let new_abi_json = serde_json::to_string(&new_abi)?;

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

    if args.is_update {
        let on_chain_leaf: PsyContractLeaf<F> = rpc_provider.get_contract_leaf_data(args.contract_id).await?;
        validate_proof_old_layout_matches_chain(
            &update_cmd.canonical_layout_proof,
            args.contract_id,
            &on_chain_leaf,
        )?;
    }

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
        let uploaded_content_hash = contract_abi_upload::upload_update_contract_abi(
            &rpc_config,
            &update_cmd,
            &new_abi_json,
        )
        .await?;
        tracing::info!(
            "uploaded updated contract ABI to psy-services for content_hash={}",
            uploaded_content_hash
        );
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

fn validate_proof_old_layout_matches_chain(
    proof_bytes: &[u8],
    contract_id: u64,
    on_chain_leaf: &PsyContractLeaf<F>,
) -> anyhow::Result<()> {
    let proof: ProofWithPublicInputs<F, C, D> = bincode::deserialize(proof_bytes)?;
    let pi = &proof.public_inputs;
    anyhow::ensure!(pi.len() == 19, "canonical layout proof has an unexpected public input count");
    let old_root = on_chain_leaf.state_layout_root.0.elements.map(|value| value.to_canonical_u64());
    let proof_old_root = pi[2..6].iter().map(|value| value.to_canonical_u64()).collect::<Vec<_>>();
    anyhow::ensure!(
        pi[0].to_canonical_u64() == contract_id
            && proof_old_root.as_slice() == old_root
            && pi[6].to_canonical_u64() == on_chain_leaf.state_layout_field_count.to_canonical_u64()
            && pi[7].to_canonical_u64() == on_chain_leaf.state_layout_slot_count.to_canonical_u64(),
        "layout proof old endpoint does not match on-chain contract {}: proof root {:?}, fields {}, slots {}; chain root {:?}, fields {}, slots {}. Check --old-abi-path",
        contract_id,
        proof_old_root,
        pi[6].to_canonical_u64(),
        pi[7].to_canonical_u64(),
        old_root,
        on_chain_leaf.state_layout_field_count.to_canonical_u64(),
        on_chain_leaf.state_layout_slot_count.to_canonical_u64(),
    );
    Ok(())
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
