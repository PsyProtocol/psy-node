use anyhow::Result;
use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::data::qhashout::QHashOut;
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_provider::provider::RpcProvider;

use crate::{
    result::{CommandResult, StatusResult, TransactionStatus},
    subcommand::args::TxGetStatusArgs,
};

type F = GoldilocksField;
pub async fn get_status(args: TxGetStatusArgs) -> Result<CommandResult> {
    tracing::info!("get endcap status: {}", serde_json::to_string_pretty(&args)?);
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;

    let checkpoint_before = args.start_checkpoint_id;
    let end_user_leaf_hash = parse_end_user_leaf_hash(&args.end_user_leaf_hash)?;
    let included_checkpoint = provider
        .wait_for_endcap_inclusion(args.user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
        .await?;
    let latest_checkpoint = provider.get_coordinator_latest_block_state().await?.checkpoint_id;

    let output = StatusResult {
        status: TransactionStatus::Confirmed,
        user_id: args.user_id,
        end_user_leaf_hash,
        checkpoint_id: included_checkpoint,
        from_checkpoint: checkpoint_before,
        latest_checkpoint,
    };
    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(CommandResult::TxStatus(output))
}

fn parse_end_user_leaf_hash(value: &str) -> Result<QHashOut<F>> {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
        .parse()
        .map_err(Into::into)
}
