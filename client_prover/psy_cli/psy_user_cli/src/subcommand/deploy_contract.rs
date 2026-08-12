use std::{fs, path::Path};

use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_data::config::store_config::{C, D};
use psy_prover::session::gen_contract_deploy_and_circuits_for_functions;
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QDeployContractRPCRequest,
};
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;
use serde::Deserialize;

use super::{args::DeployContractArgs, contract_abi_upload};
use crate::result::{CommandResult, DeployResult, DeployStatus};

#[derive(Deserialize)]
struct CompilationArtifact {
    state_tree_height: u16,
    circuit_definitions: Vec<DPNFunctionCircuitDefinition>,
}

// #[cfg(feature = "is_sync")]
pub async fn run(args: DeployContractArgs) -> anyhow::Result<CommandResult> {
    tracing::info!("deploying contract");

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let rpc_provider = RpcProvider::new_with_config(&rpc_config)?;

    // `WalletSourceArgs` intentionally makes --sign-type live. A legacy
    // FINGERPRINT environment value is rejected in main before parsing so it
    // cannot silently select a different deployer identity.
    let info = load_wallet_key_info(&args.wallet, false)?;
    let deployer = info.public_key_hash;

    let artifact: CompilationArtifact = serde_json::from_str(&fs::read_to_string(args.contract_path)?)?;
    let defs_array = artifact.circuit_definitions;
    let contract_state_tree_height = usize::from(artifact.state_tree_height);

    tracing::info!("generating circuits");
    let (_result_circuits, deploy_cmd) =
        gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, contract_state_tree_height as u8, &defs_array)?;

    match args.output_path {
        Some(output_path) => {
            tracing::debug!("deploy cmd save to {}", output_path);
            fs::write(Path::new(&output_path), serde_json::to_string(&deploy_cmd)?)?;
        }
        None => tracing::debug!("deploy cmd: {}", serde_json::to_string(&deploy_cmd)?),
    }

    if args.is_deploy {
        tracing::info!("user cli deploying contract");
        if let Some(abi_path) = args.abi_path {
            let abi_json = fs::read_to_string(abi_path)?;
            let content_hash = contract_abi_upload::upload_contract_abi(&rpc_config, &deploy_cmd, &abi_json).await?;
            tracing::info!("uploaded contract ABI to psy-services for content_hash={}", content_hash);
        }

        let contract_uuid = rpc_provider
            .deploy_contract(QDeployContractRPCRequest { deploy_contract: deploy_cmd })
            .await?;
        tracing::info!("contract deployed: {}", contract_uuid);
        return Ok(CommandResult::Deploy(DeployResult {
            contract_id: None,
            tx_hash: contract_uuid.to_string(),
            network: psy_config.current_network_name().to_string(),
            status: DeployStatus::Submitted,
        }));
    }

    Ok(CommandResult::generic("deploy-contract"))
}
