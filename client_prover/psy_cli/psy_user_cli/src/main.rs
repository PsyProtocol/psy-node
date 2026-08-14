// #![cfg(feature = "is_sync")]
mod error;
mod result;
mod subcommand;

#[cfg(not(target_arch = "wasm32"))]
use shadow_rs::shadow;

#[cfg(not(target_arch = "wasm32"))]
shadow!(build);

use clap::Parser;

use crate::{
    result::{
        BlockStateResult, CodeDefinitionResult, CommandResult, EventResult, LeafData, LeafDataResult, LeafHashResult, LeafPreimageResult,
        MerkleProofResult, ResultFileGuard, TreeRootResult, UserLeafResult,
    },
    subcommand::{
        args::TxCommands, batch_claim, claim_amount, claim_deposit, claim_rewards, claim_withdrawal, compile, compile_deploy, deploy_contract, deposit,
        export_private_key, generate_batch_proof_miner_reward_proofs, generate_tx_trace, get_checkpoint_id_for_unique_pending_id, get_user_id,
        prove_tx_trace, register_user, simulate, submit_end_cap_proof, tx, update_contract, wallet, withdraw, Cli, Commands,
    },
};

fn normalized_args() -> Vec<String> {
    let mut args = std::env::args().collect::<Vec<_>>();
    let is_deploy = args.iter().any(|arg| arg == "deploy-contract");
    if is_deploy {
        for arg in &mut args {
            if arg == "-s" {
                *arg = "--sign-type".to_string();
            }
        }
    }
    args
}

fn preparse_result_file(args: &[String]) -> Option<std::path::PathBuf> {
    args.iter().enumerate().find_map(|(index, arg)| {
        if let Some(path) = arg.strip_prefix("--result-file=") {
            return (!path.is_empty()).then(|| std::path::PathBuf::from(path));
        }
        if arg == "--result-file" {
            return args
                .get(index + 1)
                .filter(|path| !path.is_empty() && !path.starts_with('-'))
                .map(std::path::PathBuf::from);
        }
        None
    })
}

fn parse_cli(args: Vec<String>) -> anyhow::Result<Option<Cli>> {
    match Cli::try_parse_from(args) {
        Ok(cli) => Ok(Some(cli)),
        Err(error) if matches!(error.kind(), clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion) => {
            error.print()?;
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}


fn normalized_path(path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = std::path::PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

fn comparable_path(path: &std::path::Path) -> anyhow::Result<std::path::PathBuf> {
    #[derive(Clone)]
    enum OwnedComponent {
        Prefix(std::ffi::OsString),
        Root,
        Parent,
        Normal(std::ffi::OsString),
    }

    fn prepend_components(path: &std::path::Path, pending: &mut std::collections::VecDeque<OwnedComponent>) {
        let components = path
            .components()
            .filter_map(|component| match component {
                std::path::Component::Prefix(prefix) => Some(OwnedComponent::Prefix(prefix.as_os_str().to_os_string())),
                std::path::Component::RootDir => Some(OwnedComponent::Root),
                std::path::Component::CurDir => None,
                std::path::Component::ParentDir => Some(OwnedComponent::Parent),
                std::path::Component::Normal(name) => Some(OwnedComponent::Normal(name.to_os_string())),
            })
            .collect::<Vec<_>>();
        for component in components.into_iter().rev() {
            pending.push_front(component);
        }
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut pending = std::collections::VecDeque::new();
    prepend_components(&absolute, &mut pending);
    let mut resolved = std::path::PathBuf::new();
    let mut symlink_expansions = 0usize;

    while let Some(component) = pending.pop_front() {
        match component {
            OwnedComponent::Prefix(prefix) => resolved = std::path::PathBuf::from(prefix),
            OwnedComponent::Root => resolved.push(std::path::MAIN_SEPARATOR_STR),
            OwnedComponent::Parent => {
                resolved.pop();
            }
            OwnedComponent::Normal(name) => {
                let candidate = resolved.join(&name);
                match std::fs::symlink_metadata(&candidate) {
                    Ok(metadata) if metadata.file_type().is_symlink() => {
                        symlink_expansions += 1;
                        anyhow::ensure!(symlink_expansions <= 64, "too many symlink expansions while resolving {}", path.display());
                        let target = std::fs::read_link(&candidate)?;
                        if target.is_absolute() {
                            resolved.clear();
                        }
                        prepend_components(&target, &mut pending);
                    }
                    Ok(_) => resolved = candidate,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => resolved = candidate,
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(resolved)
}

fn push_wallet_paths<'a>(paths: &mut Vec<&'a str>, wallet: &'a psy_client_common::args::WalletSourceArgs) {
    paths.extend(wallet.keystore_path.as_deref());
}

fn push_session_paths<'a>(paths: &mut Vec<&'a str>, session: &'a psy_client_common::args::WalletSessionArgs) {
    push_wallet_paths(paths, &session.wallet);
    paths.extend(session.contract_calls_file.as_deref());
    paths.extend(session.external_proof_file.iter().map(String::as_str));
}

fn command_paths(cli: &Cli) -> Vec<&str> {
    use crate::subcommand::args::WalletCommands;
    let mut paths = Vec::new();
    match &cli.command {
        Commands::Wallet(args) => match &args.command {
            WalletCommands::Create { output, wallet, .. } => { push_wallet_paths(&mut paths, wallet); paths.extend(output.as_deref()); }
            WalletCommands::Load { wallet } | WalletCommands::Info { wallet } => push_wallet_paths(&mut paths, wallet),
            WalletCommands::List { keystore_dir } => paths.extend(keystore_dir.as_deref()),
            WalletCommands::Random { .. } | WalletCommands::SdKeyFingerprint { .. } => {}
        },
        Commands::RegisterUser(args) => push_wallet_paths(&mut paths, &args.wallet),
        Commands::DeployContract(args) => {
            push_wallet_paths(&mut paths, &args.wallet);
            paths.extend([args.rpc_config.as_str(), args.contract_path.as_str()]);
            paths.extend(args.output_path.as_deref());
        }
        Commands::UpdateContract(args) => { paths.extend([args.rpc_config.as_str(), args.contract_path.as_str()]); paths.extend(args.old_abi_path.as_deref()); paths.extend(args.new_abi_path.as_deref()); paths.extend(args.output_path.as_deref()); }
        Commands::Call(args) => push_session_paths(&mut paths, args),
        Commands::GetUserId(args) => paths.push(&args.rpc_config),
        Commands::GetUserEventData(args) => paths.push(&args.rpc_config),
        Commands::GetUserLeaf(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractStateTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractStateTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractStateIMTLeafPreimage(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractStateTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetUserContractTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetUserRegistrationTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetUserRegistrationTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetUserRegistrationTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetUserTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetUserTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetUserTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetUserSubTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetContractFunctionTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetContractFunctionTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetContractFunctionTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetContractTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetContractTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetContractTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetWithdrawalTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetLatestCheckpointTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetCheckpointTreeRoot(args) => paths.push(&args.rpc_config),
        Commands::GetCheckpointTreeLeafHash(args) => paths.push(&args.rpc_config),
        Commands::GetCheckpointTreeMerkleProof(args) => paths.push(&args.rpc_config),
        Commands::GetContractLeafData(args) => paths.push(&args.rpc_config),
        Commands::GetCheckpointLeafData(args) => paths.push(&args.rpc_config),
        Commands::GetContractCodeDefinition(args) => paths.push(&args.rpc_config),
        Commands::GetLatestBlockState(args) => paths.push(&args.rpc_config),
        Commands::GetBlockState(args) => paths.push(&args.rpc_config),
        Commands::LocalProver(args) => paths.push(&args.rpc_config),
        #[cfg(feature = "gnark-wrap")]
        Commands::ProveProxy(args) => paths.push(&args.rpc_config),
        Commands::FaucetServer(args) => paths.push(&args.rpc_config),
        Commands::GetClaimAmount(args) => paths.push(&args.rpc_config),
        Commands::BatchClaim(args) => { push_wallet_paths(&mut paths, &args.wallet); paths.extend([args.rpc_config.as_str(), args.input.as_str()]); paths.extend(args.trace_out.as_deref()); }
        Commands::Tx(args) => match &args.command { TxCommands::GetStatus(args) => paths.push(&args.rpc_config) },
        Commands::GetCheckpointIdForUniquePendingId(args) => paths.push(&args.rpc_config),
        Commands::GenerateBatchProofMinerRewardProofs(args) => paths.extend([args.rpc_config.as_str(), args.jobs_file.as_str(), args.output_file.as_str()]),
        Commands::ClaimRewards(args) => { push_wallet_paths(&mut paths, &args.wallet); paths.extend([args.rpc_config.as_str(), args.jobs_file.as_str()]); }
        Commands::GetPsySdcFingerprint(args) => paths.push(&args.sdc_path),
        Commands::GetUserEndCapCommonData => {}
        Commands::Compile(args) => { paths.push(&args.source); paths.extend(args.output_dir.as_deref()); }
        Commands::CompileAndDeploy(args) => { paths.extend([args.source.as_str(), args.rpc_config.as_str()]); paths.extend(args.output_dir.as_deref()); }
        Commands::Simulate(args) => { paths.extend(args.source.as_deref()); paths.extend(args.circuit_defs_path.as_deref()); paths.extend(args.abi_path.as_deref()); }
        Commands::GenerateTxTrace(args) => { push_session_paths(&mut paths, &args.session); paths.extend([args.session.rpc_config.as_str(), args.output.as_str()]); }
        Commands::ProveTxTrace(args) => { push_session_paths(&mut paths, &args.session); paths.extend([args.session.rpc_config.as_str(), args.input.as_str()]); paths.extend(args.output.as_deref()); }
        Commands::PrivateTransfer(args) => paths.extend([args.rpc_config.as_str(), args.output.as_str()]),
        Commands::PrivateClaim(args) => { paths.push(&args.rpc_config); paths.extend(args.note_proof.as_deref()); }
        Commands::DeriveNoteOwner(args) => paths.push(&args.rpc_config),
        Commands::ClaimDeposit(args) => { push_wallet_paths(&mut paths, &args.wallet); paths.extend([args.rpc_config.as_str(), args.deposit_proof.as_str()]); }
        Commands::Withdraw(args) => { push_wallet_paths(&mut paths, &args.wallet); paths.push(&args.rpc_config); }
        Commands::Deposit(args) => { paths.push(&args.rpc_config); paths.extend(args.deposit_proof_output.as_deref()); }
        Commands::ClaimWithdrawal(args) => paths.push(&args.rpc_config),
        Commands::ExportPrivateKey(args) => paths.push(&args.keystore_path),
    }
    paths
}

fn reject_command_path_conflicts(cli: &Cli) -> anyhow::Result<()> {
    let ensure_distinct = |left: &str, right: &str, description: &str| -> anyhow::Result<()> {
        anyhow::ensure!(
            comparable_path(std::path::Path::new(left))? != comparable_path(std::path::Path::new(right))?,
            "{} must be different paths",
            description,
        );
        Ok(())
    };
    match &cli.command {
        Commands::BatchClaim(args) => {
            if let Some(output) = args.trace_out.as_deref() {
                ensure_distinct(&args.input, output, "batch-claim --input and --trace-out")?;
            }
        }
        Commands::ProveTxTrace(args) => {
            if let Some(output) = args.output.as_deref() {
                ensure_distinct(&args.input, output, "prove-tx-trace --input and --output")?;
            }
        }
        Commands::GenerateBatchProofMinerRewardProofs(args) => {
            ensure_distinct(&args.jobs_file, &args.output_file, "reward --jobs-file and --output-file")?;
        }
        _ => {}
    }
    Ok(())
}

fn reject_result_path_conflict(cli: &Cli) -> anyhow::Result<()> {
    let Some(result_file) = cli.result_file.as_deref() else { return Ok(()); };
    let comparable_result = comparable_path(result_file)?;
    for path in command_paths(cli) {
        anyhow::ensure!(
            comparable_result != comparable_path(std::path::Path::new(path))?,
            "--result-file must be different from every command input/output path: {}",
            path,
        );
    }
    Ok(())
}

fn reject_legacy_deploy_fingerprint_env(args: &[String]) -> anyhow::Result<()> {
    let is_deploy = args.iter().any(|arg| arg == "deploy-contract");
    let has_explicit_fingerprint = args.iter().any(|arg| arg == "--fingerprint" || arg.starts_with("--fingerprint="));
    if is_deploy && !has_explicit_fingerprint && std::env::var_os("FINGERPRINT").is_some() {
        anyhow::bail!(
            "deploy-contract no longer reads FINGERPRINT implicitly; pass --fingerprint explicitly with the intended --sign-type"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    let args = normalized_args();
    let preparsed_result_file = preparse_result_file(&args);
    let cli = match parse_cli(args.clone()) {
        Ok(Some(cli)) => cli,
        Ok(None) => return Ok(()),
        Err(error) => return Err(error),
    };
    anyhow::ensure!(preparsed_result_file == cli.result_file, "--result-file parsing mismatch");
    if let Err(error) = reject_result_path_conflict(&cli) {
        return Err(error);
    }
    if let Err(error) = reject_legacy_deploy_fingerprint_env(&args).and_then(|_| reject_command_path_conflicts(&cli)) {
        drop(ResultFileGuard::prepare(preparsed_result_file)?);
        return Err(error);
    }
    let result_guard = ResultFileGuard::prepare(preparsed_result_file)?;
    psy_client_common::setup_logging()?;
    tracing::info!("psy user cli");
    let result: CommandResult = match cli.command {
        Commands::Wallet(args) => wallet::run(args)?,
        Commands::RegisterUser(args) => register_user::run(args).await?,
        Commands::DeployContract(args) => deploy_contract::run(args).await?,
        Commands::UpdateContract(args) => update_contract::run(args).await?,
        Commands::Call(args) => submit_end_cap_proof::run(args).await?,
        Commands::GenerateTxTrace(args) => generate_tx_trace::run(args).await?,
        Commands::ProveTxTrace(args) => prove_tx_trace::run(args).await?,
        Commands::GetClaimAmount(args) => claim_amount::run(args).await?,
        Commands::BatchClaim(args) => batch_claim::run(args).await?,
        Commands::Tx(args) => match args.command {
            TxCommands::GetStatus(args) => tx::get_status(args).await?,
        },

        // batch proof miner rewards
        Commands::GetCheckpointIdForUniquePendingId(args) => get_checkpoint_id_for_unique_pending_id::run(args).await?,
        Commands::GenerateBatchProofMinerRewardProofs(args) => generate_batch_proof_miner_reward_proofs::run(args).await?,
        Commands::ClaimRewards(args) => claim_rewards::run(args).await?,

        // get block data
        Commands::GetUserId(user_id_args) => get_user_id::run(user_id_args).await?,
        Commands::GetUserEventData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;

            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let event = provider.get_user_event_data(args.user_id, args.checkpoint_id, args.event_index).await?;
            println!("{}", serde_json::to_string_pretty(&event)?);
            CommandResult::Event(EventResult { event })
        }
        Commands::GetUserLeaf(user_leaf_args) => {
            use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::qmetadata::QMetaDataStoreReaderSync};
            use psy_crypto::hash::traits::qhashable::QFieldHashable;
            use psy_provider::provider::RpcProvider;

            let provider = RpcProvider::new_with_config_path(&user_leaf_args.rpc_config)?;

            let (user_id, query_method) = match (&user_leaf_args.pub_key, &user_leaf_args.user_id) {
                (Some(pub_key), None) => {
                    // Query by public key - get user_id from coordinator first
                    let user_id = provider
                        .get_user_ids_for_public_key(*pub_key)
                        .await?
                        .first()
                        .copied()
                        .ok_or_else(|| anyhow::format_err!("No user id found for public key"))?;
                    (user_id, "public_key")
                }
                (None, Some(user_id)) => {
                    // Query by user_id directly - use provided user_id
                    (*user_id, "user_id")
                }
                (Some(_), Some(_)) => {
                    return Err(anyhow::format_err!("Cannot specify both --pub-key and --user-id"));
                }
                (None, None) => {
                    return Err(anyhow::format_err!("Must specify either --pub-key or --user-id"));
                }
            };

            let user_leaf_data = provider.get_user_leaf_data(user_leaf_args.checkpoint_id, user_id).await?;

            let leaf_hash = user_leaf_data.qfhash::<PsyHasher>();
            println!("Query method: {}", query_method);
            println!("Resolved user_id: {}", user_id);
            println!("user_leaf_data: {}", serde_json::to_string_pretty(&user_leaf_data)?);
            println!("user_leaf_hash: {}", leaf_hash);
            CommandResult::UserLeaf(UserLeafResult {
                user_id,
                query_method: query_method.to_string(),
                leaf_data: user_leaf_data,
                leaf_hash,
            })
        }

        // Tree commands
        Commands::GetUserContractStateTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider
                .get_user_contract_state_tree_root(args.checkpoint_id, args.user_id, args.contract_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetUserContractStateTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_contract_state_tree_leaf_hash(args.checkpoint_id, args.user_id, args.contract_id, 0, args.leaf_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetUserContractStateIMTLeafPreimage(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let leaf = provider
                .contract_state_imt_get_leaf_preimage(args.checkpoint_id, args.user_id, args.contract_id, args.leaf_index)
                .await?;
            println!("{}", serde_json::to_string_pretty(&leaf)?);
            CommandResult::LeafPreimage(LeafPreimageResult { leaf_preimage: leaf })
        }
        Commands::GetUserContractStateTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                // The Realm resolves the deployed contract's state-tree height.
                // The legacy local trait parameter is intentionally ignored by
                // RpcProvider and can be removed in a follow-up API cleanup.
                .get_user_contract_state_tree_merkle_proof(args.checkpoint_id, args.user_id, args.contract_id, 0, args.leaf_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetUserContractTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_contract_tree_root(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetUserContractTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_contract_tree_leaf_hash(args.checkpoint_id, args.user_id, args.contract_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetUserContractTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_contract_tree_merkle_proof(args.checkpoint_id, args.user_id, args.contract_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetUserRegistrationTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_registration_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetUserRegistrationTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_registration_tree_leaf_hash(args.checkpoint_id, args.registration_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetUserRegistrationTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_registration_tree_merkle_proof(args.checkpoint_id, args.registration_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetUserTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetUserTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider.get_user_tree_leaf_hash(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetUserTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider.get_user_tree_merkle_proof(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetUserSubTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_sub_tree_merkle_proof(args.checkpoint_id, args.root_level, args.leaf_level, args.leaf_index)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetContractFunctionTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_contract_function_tree_root(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetContractFunctionTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_contract_function_tree_leaf_hash(args.checkpoint_id, args.contract_id, args.function_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetContractFunctionTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_contract_function_tree_merkle_proof(args.checkpoint_id, args.contract_id, args.function_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetContractTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_contract_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetContractTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider.get_contract_tree_leaf_hash(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetContractTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider.get_contract_tree_merkle_proof(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }
        Commands::GetWithdrawalTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_withdrawal_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetLatestCheckpointTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_latest_checkpoint_tree_root().await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetCheckpointTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_checkpoint_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
            CommandResult::TreeRoot(TreeRootResult { root })
        }
        Commands::GetCheckpointTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_checkpoint_tree_leaf_hash(args.checkpoint_id, args.leaf_checkpoint_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
            CommandResult::LeafHash(LeafHashResult { leaf_hash: hash })
        }
        Commands::GetCheckpointTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_checkpoint_tree_merkle_proof(args.checkpoint_id, args.leaf_checkpoint_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
            CommandResult::MerkleProof(MerkleProofResult { merkle_proof: proof })
        }

        // Metadata commands
        Commands::GetContractLeafData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let data = provider.get_contract_leaf_data(args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
            CommandResult::LeafData(LeafDataResult {
                data: LeafData::Contract(data),
            })
        }
        Commands::GetCheckpointLeafData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let data = provider.get_checkpoint_leaf_data(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
            CommandResult::LeafData(LeafDataResult {
                data: LeafData::Checkpoint(data),
            })
        }
        Commands::GetContractCodeDefinition(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let definition = provider.get_contract_code_definition(args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&definition)?);
            CommandResult::CodeDefinition(CodeDefinitionResult { code_definition: definition })
        }
        Commands::GetLatestBlockState(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let state = provider.get_latest_block_state().await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            CommandResult::BlockState(BlockStateResult { block_state: state })
        }
        Commands::GetBlockState(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let state = provider.get_block_state(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
            CommandResult::BlockState(BlockStateResult { block_state: state })
        }

        // wallet session
        Commands::LocalProver(prover_args) => {
            psy_prover::run_server(prover_args).await?;
            CommandResult::generic("local-prover")
        }
        #[cfg(feature = "gnark-wrap")]
        Commands::ProveProxy(prove_proxy_args) => {
            crate::subcommand::prove_proxy::run(prove_proxy_args).await?;
            CommandResult::generic("prove-proxy")
        }
        Commands::FaucetServer(faucet_server_args) => {
            crate::subcommand::faucet_server::run(faucet_server_args).await?;
            CommandResult::generic("faucet-server")
        }

        Commands::GetPsySdcFingerprint(get_psy_sdc_fingerprint) => crate::subcommand::get_psy_sdc_fingerprint::run(get_psy_sdc_fingerprint).await?,

        Commands::GetUserEndCapCommonData => {
            crate::subcommand::get_user_endcap_common_data::run().await?;
            CommandResult::generic("get-user-endcap-common-data")
        }

        // PSY compiler commands
        Commands::Compile(args) => {
            compile::run(args).await?;
            CommandResult::generic("compile")
        }
        Commands::CompileAndDeploy(args) => {
            compile_deploy::run(args).await?;
            CommandResult::generic("compile-and-deploy")
        }
        Commands::Simulate(args) => {
            simulate::run(args).await?;
            CommandResult::generic("simulate")
        }
        Commands::PrivateTransfer(args) => crate::subcommand::private_transfer::run(args).await?,
        Commands::PrivateClaim(args) => crate::subcommand::private_claim::run(args).await?,
        Commands::DeriveNoteOwner(args) => crate::subcommand::shield_address::run(args).await?,
        Commands::ClaimDeposit(args) => claim_deposit::run(args).await?,
        Commands::Deposit(args) => deposit::run(args).await?,
        Commands::Withdraw(args) => withdraw::run(args).await?,
        Commands::ClaimWithdrawal(args) => claim_withdrawal::run(args).await?,
        Commands::ExportPrivateKey(args) => {
            export_private_key::run(args)?;
            CommandResult::generic("export-private-key")
        }
    };
    result_guard.commit(&result)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_paths_collapse_relative_components() {
        let left = normalized_path(std::path::Path::new("tmp/../trace.json")).unwrap();
        let right = normalized_path(std::path::Path::new("./trace.json")).unwrap();
        assert_eq!(left, right);
    }

    #[test]
    fn strict_result_file_preparse_rejects_options_as_paths() {
        let malformed = vec!["psy_user_cli".to_string(), "--result-file".to_string(), "--other".to_string()];
        assert_eq!(preparse_result_file(&malformed), None);
        let separate = vec!["psy_user_cli".to_string(), "--result-file".to_string(), "result.json".to_string()];
        assert_eq!(preparse_result_file(&separate), Some(std::path::PathBuf::from("result.json")));
        let equals = vec!["psy_user_cli".to_string(), "--result-file=result.json".to_string()];
        assert_eq!(preparse_result_file(&equals), Some(std::path::PathBuf::from("result.json")));
        let empty = vec!["psy_user_cli".to_string(), "--result-file=".to_string()];
        assert_eq!(preparse_result_file(&empty), None);
    }

    #[test]
    fn clap_help_and_version_are_successful_display_requests() {
        assert!(parse_cli(vec!["psy_user_cli".into(), "--help".into()]).unwrap().is_none());
        assert!(parse_cli(vec!["psy_user_cli".into(), "--version".into()]).unwrap().is_none());
    }

    #[test]
    fn clap_parse_errors_still_fail() {
        let error = match parse_cli(vec!["psy_user_cli".into(), "not-a-command".into()]) {
            Ok(_) => panic!("invalid subcommand unexpectedly parsed"),
            Err(error) => error,
        };
        let clap_error = error.downcast_ref::<clap::Error>().expect("expected clap parse error");
        assert_eq!(clap_error.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn result_path_conflicts_cover_wallet_and_trace_files() {
        let wallet = parse_cli(vec![
            "psy_user_cli".into(),
            "--result-file".into(),
            "wallet.json".into(),
            "wallet".into(),
            "create".into(),
            "--output".into(),
            "./wallet.json".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&wallet).unwrap_err().to_string().contains("wallet.json"));

        let trace = parse_cli(vec![
            "psy_user_cli".into(),
            "prove-tx-trace".into(),
            "--result-file=trace.json".into(),
            "--input".into(),
            "tmp/../trace.json".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&trace).unwrap_err().to_string().contains("trace.json"));
    }

    #[test]
    fn command_inputs_cannot_alias_outputs() {
        let batch = parse_cli(vec![
            "psy_user_cli".into(),
            "batch-claim".into(),
            "--input".into(),
            "batch.json".into(),
            "--trace-out".into(),
            "./batch.json".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_command_path_conflicts(&batch).is_err());

        let rewards = parse_cli(vec![
            "psy_user_cli".into(),
            "generate-batch-proof-miner-reward-proofs".into(),
            "--unique-pending-id".into(),
            "1".into(),
            "--jobs-file".into(),
            "jobs.json".into(),
            "--output-file".into(),
            "tmp/../jobs.json".into(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_command_path_conflicts(&rewards).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn result_path_rejects_symlink_aliases() {
        let dir = std::env::temp_dir().join(format!("psy-cli-path-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = dir.join("result.json");
        let alias = dir.join("alias.json");
        std::fs::write(&result, b"old result").unwrap();
        std::os::unix::fs::symlink(&result, &alias).unwrap();
        let cli = parse_cli(vec![
            "psy_user_cli".into(),
            "--result-file".into(),
            result.to_string_lossy().into_owned(),
            "wallet".into(),
            "create".into(),
            "--output".into(),
            alias.to_string_lossy().into_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&cli).is_err());
        assert_eq!(std::fs::read(&result).unwrap(), b"old result");
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_file(result).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn result_path_rejects_dangling_symlink_alias() {
        let dir = std::env::temp_dir().join(format!("psy-cli-dangling-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let result = dir.join("result.json");
        let alias = dir.join("wallet-link.json");
        std::os::unix::fs::symlink("result.json", &alias).unwrap();
        let cli = parse_cli(vec![
            "psy_user_cli".into(),
            "--result-file".into(),
            result.to_string_lossy().into_owned(),
            "wallet".into(),
            "create".into(),
            "--output".into(),
            alias.to_string_lossy().into_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&cli).is_err());
        assert!(!result.exists());
        std::fs::remove_file(alias).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn result_path_rejects_symlinked_ancestor_with_missing_child() {
        let dir = std::env::temp_dir().join(format!("psy-cli-ancestor-alias-{}", std::process::id()));
        let real_dir = dir.join("real");
        let link_dir = dir.join("linkdir");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::os::unix::fs::symlink(&real_dir, &link_dir).unwrap();
        let result = real_dir.join("newdir/wallet.json");
        let alias = link_dir.join("newdir/wallet.json");
        let cli = parse_cli(vec![
            "psy_user_cli".into(),
            "--result-file".into(),
            result.to_string_lossy().into_owned(),
            "wallet".into(),
            "create".into(),
            "--output".into(),
            alias.to_string_lossy().into_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&cli).is_err());
        assert!(!result.exists());
        assert!(!real_dir.join("newdir").exists());
        std::fs::remove_file(link_dir).unwrap();
        std::fs::remove_dir(real_dir).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn result_path_preserves_dotdot_after_symlink_resolution() {
        let dir = std::env::temp_dir().join(format!("psy-cli-dotdot-alias-{}", std::process::id()));
        let real_dir = dir.join("real");
        let subdir = real_dir.join("subdir");
        let link = dir.join("link");
        std::fs::create_dir_all(&subdir).unwrap();
        std::os::unix::fs::symlink(&subdir, &link).unwrap();
        let result = real_dir.join("wallet.json");
        let alias = link.join("../wallet.json");
        let cli = parse_cli(vec![
            "psy_user_cli".into(),
            "--result-file".into(),
            result.to_string_lossy().into_owned(),
            "wallet".into(),
            "create".into(),
            "--output".into(),
            alias.to_string_lossy().into_owned(),
        ])
        .unwrap()
        .unwrap();
        assert!(reject_result_path_conflict(&cli).is_err());
        assert!(!result.exists());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_dir(subdir).unwrap();
        std::fs::remove_dir(real_dir).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn comparable_path_rejects_symlink_cycles() {
        let dir = std::env::temp_dir().join(format!("psy-cli-cycle-alias-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = dir.join("first");
        let second = dir.join("second");
        std::os::unix::fs::symlink("second", &first).unwrap();
        std::os::unix::fs::symlink("first", &second).unwrap();
        assert!(comparable_path(&first).unwrap_err().to_string().contains("too many symlink expansions"));
        std::fs::remove_file(first).unwrap();
        std::fs::remove_file(second).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
