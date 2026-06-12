use std::{fs, path::Path, str::FromStr};

use anyhow::Ok;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyHasher, C, D, F};
use psy_config::network_constants::MAX_CONTRACT_STATE_TREE_HEIGHT;
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_prover::{
    session::gen_contract_deploy_and_circuits_for_functions,
    wallet::memory_wallet::{get_public_key_info, get_zk_fingerprint},
};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QDeployContractRPCRequest,
};
use psy_vm::dpn::vm::def::DPNFunctionCircuitDefinition;

use super::{args::DeployContractArgs, contract_abi_upload};

// #[cfg(feature = "is_sync")]
pub async fn run(args: DeployContractArgs) -> anyhow::Result<()> {
    tracing::info!("deploying contract");

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

    let defs_array: Vec<DPNFunctionCircuitDefinition> = serde_json::from_str(&fs::read_to_string(args.contract_path)?)?;

    tracing::info!("getting contract state tree height");
    let contract_state_tree_height = MAX_CONTRACT_STATE_TREE_HEIGHT as usize;

    tracing::info!("generating circuits");
    let (_result_circuits, deploy_cmd) =
        gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, contract_state_tree_height as u8, &defs_array)?;

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
        if let Some(abi_path) = args.abi_path {
            let abi_json = fs::read_to_string(abi_path)?;
            let content_hash = contract_abi_upload::upload_contract_abi(&rpc_config, &deploy_cmd, &abi_json).await?;
            tracing::info!("uploaded contract ABI to psy-services for content_hash={}", content_hash);
        }

        let contract_uuid = rpc_provider
            .deploy_contract(QDeployContractRPCRequest { deploy_contract: deploy_cmd })
            .await?;
        tracing::info!("contract deployed: {}", contract_uuid);
        // tracing::info!("contract deployed: {:?}",
        // ContractUUID::from_str(&contract_uuid)?);
    }

    Ok(())
}
