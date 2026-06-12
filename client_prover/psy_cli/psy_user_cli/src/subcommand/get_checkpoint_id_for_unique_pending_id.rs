use anyhow::Result;
use psy_provider::provider::RpcProvider;

use super::args::{GetCheckpointIdForUniquePendingIdArgs, RpcProviderType};

pub async fn run(args: GetCheckpointIdForUniquePendingIdArgs) -> Result<()> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    let checkpoint_id = match args.provider_type {
        RpcProviderType::Coordinator => {
            provider
                .get_coordinator_checkpoint_id_for_unique_pending_id(args.unique_pending_id)
                .await?
        }
        RpcProviderType::Realm => provider.get_realm_checkpoint_id_for_unique_pending_id(args.unique_pending_id).await?,
    };
    println!("unique_pending_id: {}, checkpoint_id: {:?}", args.unique_pending_id, checkpoint_id);
    Ok(())
}
