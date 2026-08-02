use anyhow::Result;
use psy_provider::provider::RpcProvider;

use crate::{
    result::{CommandResult, GetUserIdResult, UserRegistrationStatus},
    subcommand::args::UserIdArgs,
};

/// An empty successful RPC response is the public `not_registered` business
/// state. Transport and RPC failures continue to return an error.
pub async fn run(args: UserIdArgs) -> Result<CommandResult> {
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
    let public_key_hash = args.pub_key;
    let ids = provider.get_user_ids_for_public_key(public_key_hash).await?;
    let (status, user_id) = match ids.first().copied() {
        Some(user_id) => {
            println!("user_id: {}", user_id);
            (UserRegistrationStatus::Registered, Some(user_id))
        }
        None => {
            println!("no user ids found");
            (UserRegistrationStatus::NotRegistered, None)
        }
    };

    Ok(CommandResult::GetUserId(GetUserIdResult {
        public_key_hash,
        user_id,
        status,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_user_ids_are_a_not_registered_result() {
        let ids: Vec<u64> = Vec::new();
        let (status, user_id) = match ids.first().copied() {
            Some(user_id) => (UserRegistrationStatus::Registered, Some(user_id)),
            None => (UserRegistrationStatus::NotRegistered, None),
        };
        assert!(matches!(status, UserRegistrationStatus::NotRegistered));
        assert_eq!(user_id, None);
    }
}
