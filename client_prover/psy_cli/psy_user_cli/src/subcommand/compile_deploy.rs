use std::{fs, path::Path, str::FromStr};

use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::config::store_config::{PsyHasher, C, D, F};
use psy_crypto::hash::traits::qhashable::QFieldHashable;
use psy_prover::{
    session::gen_contract_deploy_and_circuits_for_functions,
    wallet::memory_wallet::{get_public_key_info, get_zk_fingerprint},
};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QDeployContractRPCRequest,
};

use super::{args::CompileAndDeployArgs, contract_abi_upload};

pub async fn run(args: CompileAndDeployArgs) -> anyhow::Result<()> {
    tracing::info!("compile-and-deploy from: {}", args.source);

    let source_path = Path::new(&args.source);
    if !source_path.exists() {
        anyhow::bail!("Source file not found: {}", args.source);
    }

    // Phase 1: Compile
    tracing::info!("compiling contract...");
    let output = if args.is_crate {
        psy_compiler::compile_crate(source_path)?
    } else {
        let source = fs::read_to_string(source_path)?;
        psy_compiler::compile(&source)?
    };

    tracing::info!(
        "compilation successful: {} methods, state_tree_height={}",
        output.method_count(),
        output.state_tree_height()
    );

    // Save artifacts if output_dir specified
    if let Some(ref out_dir) = args.output_dir {
        fs::create_dir_all(out_dir)?;

        let abi_json = output.abi_to_json()?;
        fs::write(format!("{}/abi.json", out_dir), &abi_json)?;

        let code_bytes = output.to_bytes()?;
        fs::write(format!("{}/contract_code.bin", out_dir), &code_bytes)?;

        let defs_json = serde_json::to_string(&output.circuit_definitions)?;
        fs::write(format!("{}/circuit_defs.json", out_dir), &defs_json)?;
    }

    // Phase 2: Generate circuits and deploy command
    tracing::info!("generating circuits...");

    let private_key = QHashOut::<F>::from_str(&args.private_key)?;
    let fingerprint = args
        .fingerprint
        .as_ref()
        .map(|f| QHashOut::<F>::from_str(f).map_err(|e| anyhow::anyhow!("parse fingerprint error: {}", e)))
        .transpose()?;
    let fingerprint = fingerprint.unwrap_or_else(|| get_zk_fingerprint());
    let deployer = get_public_key_info::<F>(private_key, fingerprint)?.qfhash::<PsyHasher>();

    // Use the compiler-computed state tree height (not MAX)
    let state_tree_height = output.state_tree_height() as u8;

    let (_result_circuits, deploy_cmd) =
        gen_contract_deploy_and_circuits_for_functions::<C, D>(deployer, state_tree_height, &output.circuit_definitions)?;

    tracing::info!("circuits generated successfully");

    // Save deploy command
    if let Some(ref out_dir) = args.output_dir {
        let deploy_cmd_json = serde_json::to_string(&deploy_cmd)?;
        fs::write(format!("{}/deploy_cmd.json", out_dir), &deploy_cmd_json)?;
        tracing::info!("deploy command saved to {}/deploy_cmd.json", out_dir);
    }

    // Phase 3: Deploy (unless dry-run)
    if args.dry_run {
        println!("Dry run: compilation and circuit generation successful");
        println!("  Methods: {}", output.method_count());
        println!("  State tree height: {}", state_tree_height);
        println!("  Deploy command generated (not submitted)");
        return Ok(());
    }

    tracing::info!("deploying contract to coordinator...");

    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let rpc_provider = RpcProvider::new_with_config(&rpc_config)?;

    let abi_json = output.abi_to_json()?;
    let content_hash = contract_abi_upload::upload_contract_abi(&rpc_config, &deploy_cmd, &abi_json).await?;
    tracing::info!("uploaded contract ABI to psy-services for content_hash={}", content_hash);

    let contract_uuid = rpc_provider
        .deploy_contract(QDeployContractRPCRequest { deploy_contract: deploy_cmd })
        .await?;

    tracing::info!("contract deployed: {}", contract_uuid);

    // Save contract ID
    if let Some(ref out_dir) = args.output_dir {
        fs::write(format!("{}/contract_id.txt", out_dir), contract_uuid.to_string())?;
    }

    println!("Contract deployed successfully:");
    println!("  Contract ID: {}", contract_uuid);
    println!("  Methods: {}", output.method_count());
    println!("  State tree height: {}", state_tree_height);

    Ok(())
}
