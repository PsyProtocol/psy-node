use std::{fs, path::Path};

use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_data::config::store_config::{C, D};
use psy_compiler::output::serialize::{CompilationArtifact, ContractOutput};
use psy_prover::{
    session::{
        compile_bridge::build_layout_aware_deploy_command,
        gen_contract_deploy_and_circuits_for_functions,
    },
};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QDeployContractRPCRequest,
};

use super::{args::DeployContractArgs, contract_abi_upload};
use crate::result::{CommandResult, DeployResult, DeployStatus};

// #[cfg(feature = "is_sync")]
pub async fn run(args: DeployContractArgs) -> anyhow::Result<CommandResult> {
    tracing::info!("deploying contract");

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let rpc_provider = RpcProvider::new_with_config(&rpc_config)?;

    // Load the deployer key the same way the other wallet commands do: from a
    // keystore (`--keystore-path` + `--wallet-password`) or an explicit
    // `--private-key`. `public_key_hash` is the deployer identity.
    let info = load_wallet_key_info(&args.wallet, false)?;
    let deployer = info.public_key_hash;

    let artifact: CompilationArtifact = serde_json::from_str(&fs::read_to_string(&args.contract_path)?)?;

    let abi = artifact.abi.clone();
    let abi_json = serde_json::to_string(&abi)?;

    tracing::info!("getting contract state tree height");
    let contract_state_tree_height = usize::from(artifact.state_tree_height);
    let defs_array = artifact.circuit_definitions;

    tracing::info!("generating circuits");
    let (_result_circuits, deploy_cmd) = gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, contract_state_tree_height as u8, &defs_array)?;
    let contract_output = ContractOutput {
        contract_code: deploy_cmd.code_definition.clone(),
        circuit_definitions: defs_array,
        abi,
    };
    let deploy_cmd = build_layout_aware_deploy_command(&contract_output, deploy_cmd)?;

    match args.output_path {
        Some(output_path) => {
            tracing::debug!("deploy cmd save to {}", output_path);
            let deploy_cmd_path = Path::new(&output_path);
            fs::write(deploy_cmd_path, serde_json::to_string(&deploy_cmd)?)?;
        }
        None => {
            tracing::debug!("deploy cmd: {}", serde_json::to_string(&deploy_cmd)?);
        }
    }

    if args.is_deploy {
        tracing::info!("user cli deploying contract");
        {
            let content_hash = contract_abi_upload::upload_contract_abi(&rpc_config, &deploy_cmd, &abi_json).await?;
            tracing::info!("uploaded contract ABI to psy-services for content_hash={}", content_hash);
        }

        let contract_uuid = rpc_provider
            .deploy_contract(QDeployContractRPCRequest { deploy_contract: deploy_cmd })
            .await?;
        tracing::info!("contract deployed: {}", contract_uuid);

        // The deploy RPC only submits the contract; it does not wait for
        // inclusion, and contract_id resolution is not part of this flow
        // (the caller resolves it separately). Hence `submitted` + null ids.
        let res = DeployResult {
            contract_id: None,
            tx_hash: contract_uuid.to_string(),
            network: psy_config.current_network_name().to_string(),
            status: DeployStatus::Submitted,
        };
        return Ok(CommandResult::Deploy(res));
    }

    // `--is-deploy` not set: circuits were generated (and optionally written to
    // --output-path) but nothing was deployed. No deploy-specific fields exist,
    // so this is a generic acknowledgment rather than a deploy result.
    Ok(CommandResult::generic("deploy-contract"))
}
