use anyhow::Result;
use psy_client_data::traits::qdatastore::qmetadata::QMetaDataStoreReaderSync;
use psy_provider::provider::RpcProvider;

use crate::{result::{ClaimAmountResult, CommandResult}, subcommand::args::ClaimAmountArgs};

pub async fn run(args: ClaimAmountArgs) -> Result<CommandResult> {
    tracing::info!("claim amount: {}", serde_json::to_string_pretty(&args)?);
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;

    let checkpoint_id = match args.checkpoint_id {
        Some(id) => id,
        None => provider.with_user_id_owned(args.user_id).get_realm_latest_checkpoint_id().await?
            .min(provider.with_user_id_owned(args.claim_user_id).get_realm_latest_checkpoint_id().await?),
    };

    let claim_amount = provider.get_claim_amount(checkpoint_id, args.user_id, args.claim_user_id).await?;
    tracing::info!(
        "user {} can claim {} from user {} at checkpoint_id: {}",
        args.user_id,
        claim_amount,
        args.claim_user_id,
        checkpoint_id
    );

    Ok(CommandResult::ClaimAmount(ClaimAmountResult { claim_amount }))
}
