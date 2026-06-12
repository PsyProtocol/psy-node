// #![cfg(feature = "is_sync")]
mod error;
mod subcommand;

#[cfg(not(target_arch = "wasm32"))]
use shadow_rs::shadow;

#[cfg(not(target_arch = "wasm32"))]
shadow!(build);

use clap::Parser;

use crate::subcommand::{
    args::TxCommands, claim_amount, claim_deposit, claim_rewards, claim_withdrawal, compile, compile_deploy, deploy_contract, deposit,
    export_private_key, generate_batch_proof_miner_reward_proofs, get_checkpoint_id_for_unique_pending_id, register_user, simulate,
    submit_end_cap_proof, tx, wallet, withdraw, Cli, Commands,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();

    let cli = Cli::parse();
    psy_client_common::setup_logging()?;
    tracing::info!("psy user cli");
    match cli.command {
        Commands::Wallet(args) => wallet::run(args)?,
        Commands::RegisterUser(args) => register_user::run(args).await?,
        Commands::DeployContract(args) => deploy_contract::run(args).await?,
        Commands::Call(args) => submit_end_cap_proof::run(args).await?,
        Commands::GetClaimAmount(args) => claim_amount::run(args).await?,
        Commands::Tx(args) => match args.command {
            TxCommands::GetStatus(args) => tx::get_status(args).await?,
        },

        // batch proof miner rewards
        Commands::GetCheckpointIdForUniquePendingId(args) => get_checkpoint_id_for_unique_pending_id::run(args).await?,
        Commands::GenerateBatchProofMinerRewardProofs(args) => generate_batch_proof_miner_reward_proofs::run(args).await?,
        Commands::ClaimRewards(args) => claim_rewards::run(args).await?,

        // get block data
        Commands::GetUserId(user_id_args) => {
            use psy_provider::provider::RpcProvider;

            let provider = RpcProvider::new_with_config_path(&user_id_args.rpc_config)?;
            let user_id = provider.get_user_ids_for_public_key(user_id_args.pub_key).await?[0];
            println!("user_id: {}", user_id);
        }
        Commands::GetUserEventData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;

            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let event = provider.get_user_event_data(args.user_id, args.checkpoint_id, args.event_index).await?;
            println!("{}", serde_json::to_string_pretty(&event)?);
        }
        Commands::GetUserLeaf(user_leaf_args) => {
            use psy_client_data::{config::store_config::PsyHasher, traits::qdatastore::qmetadata::QMetaDataStoreReaderSync};
            use psy_crypto::hash::traits::qhashable::QFieldHashable;
            use psy_provider::provider::RpcProvider;

            let provider = RpcProvider::new_with_config_path(&user_leaf_args.rpc_config)?;

            let (user_id, query_method) = match (&user_leaf_args.pub_key, &user_leaf_args.user_id) {
                (Some(pub_key), None) => {
                    // Query by public key - get user_id from coordinator first
                    let user_id = provider.get_user_ids_for_public_key(*pub_key).await?[0];
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
            println!("Query method: {}", query_method);
            println!("Resolved user_id: {}", user_id);
            println!("user_leaf_data: {}", serde_json::to_string_pretty(&user_leaf_data)?);
            println!("user_leaf_hash: {}", user_leaf_data.qfhash::<PsyHasher>().to_string());
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
        }
        Commands::GetUserContractStateTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_contract_state_tree_leaf_hash(args.checkpoint_id, args.user_id, args.contract_id, args.height, args.leaf_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetUserContractStateIMTLeafPreimage(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let leaf = provider
                .contract_state_imt_get_leaf_preimage(args.checkpoint_id, args.user_id, args.contract_id, args.leaf_index)
                .await?;
            println!("{}", serde_json::to_string_pretty(&leaf)?);
        }
        Commands::GetUserContractStateTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_contract_state_tree_merkle_proof(args.checkpoint_id, args.user_id, args.contract_id, args.height, args.leaf_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetUserContractTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_contract_tree_root(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetUserContractTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_contract_tree_leaf_hash(args.checkpoint_id, args.user_id, args.contract_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetUserContractTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_contract_tree_merkle_proof(args.checkpoint_id, args.user_id, args.contract_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetUserRegistrationTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_registration_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetUserRegistrationTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_user_registration_tree_leaf_hash(args.checkpoint_id, args.registration_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetUserRegistrationTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_registration_tree_merkle_proof(args.checkpoint_id, args.registration_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetUserTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_user_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetUserTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider.get_user_tree_leaf_hash(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetUserTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider.get_user_tree_merkle_proof(args.checkpoint_id, args.user_id).await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetUserSubTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_user_sub_tree_merkle_proof(args.checkpoint_id, args.root_level, args.leaf_level, args.leaf_index)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetContractFunctionTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_contract_function_tree_root(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetContractFunctionTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_contract_function_tree_leaf_hash(args.checkpoint_id, args.contract_id, args.function_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetContractFunctionTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_contract_function_tree_merkle_proof(args.checkpoint_id, args.contract_id, args.function_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetContractTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_contract_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetContractTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider.get_contract_tree_leaf_hash(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetContractTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider.get_contract_tree_merkle_proof(args.checkpoint_id, args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }
        Commands::GetWithdrawalTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_withdrawal_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetLatestCheckpointTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_latest_checkpoint_tree_root().await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetCheckpointTreeRoot(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let root = provider.get_checkpoint_tree_root(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&root)?);
        }
        Commands::GetCheckpointTreeLeafHash(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let hash = provider
                .get_checkpoint_tree_leaf_hash(args.checkpoint_id, args.leaf_checkpoint_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&hash)?);
        }
        Commands::GetCheckpointTreeMerkleProof(args) => {
            use psy_client_data::traits::qdatastore::qtreedata::QTreeDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let proof = provider
                .get_checkpoint_tree_merkle_proof(args.checkpoint_id, args.leaf_checkpoint_id)
                .await?;
            println!("{}", serde_json::to_string_pretty(&proof)?);
        }

        // Metadata commands
        Commands::GetContractLeafData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let data = provider.get_contract_leaf_data(args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Commands::GetCheckpointLeafData(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let data = provider.get_checkpoint_leaf_data(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&data)?);
        }
        Commands::GetContractCodeDefinition(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let definition = provider.get_contract_code_definition(args.contract_id).await?;
            println!("{}", serde_json::to_string_pretty(&definition)?);
        }
        Commands::GetLatestBlockState(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let state = provider.get_latest_block_state().await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }
        Commands::GetBlockState(args) => {
            use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
            use psy_provider::provider::RpcProvider;
            let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
            let state = provider.get_block_state(args.checkpoint_id).await?;
            println!("{}", serde_json::to_string_pretty(&state)?);
        }

        // wallet session
        Commands::LocalProver(prover_args) => psy_prover::run_server(prover_args).await?,
        Commands::ProveProxy(prove_proxy_args) => crate::subcommand::prove_proxy::run(prove_proxy_args).await?,

        Commands::GetPsySdcFingerprint(get_psy_sdc_fingerprint) => crate::subcommand::get_psy_sdc_fingerprint::run(get_psy_sdc_fingerprint).await?,

        Commands::GetUserEndCapCommonData => crate::subcommand::get_user_endcap_common_data::run().await?,

        // PSY compiler commands
        Commands::Compile(args) => compile::run(args).await?,
        Commands::CompileAndDeploy(args) => compile_deploy::run(args).await?,
        Commands::Simulate(args) => simulate::run(args).await?,
        Commands::PrivateTransfer(args) => crate::subcommand::private_transfer::run(args).await?,
        Commands::PrivateClaim(args) => crate::subcommand::private_claim::run(args).await?,
        Commands::DeriveNoteOwner(args) => crate::subcommand::shield_address::run(args).await?,
        Commands::ClaimDeposit(args) => claim_deposit::run(args).await?,
        Commands::Deposit(args) => deposit::run(args).await?,
        Commands::Withdraw(args) => withdraw::run(args).await?,
        Commands::ClaimWithdrawal(args) => claim_withdrawal::run(args).await?,

        Commands::ExportPrivateKey(args) => export_private_key::run(args)?,
    }
    Ok(())
}
