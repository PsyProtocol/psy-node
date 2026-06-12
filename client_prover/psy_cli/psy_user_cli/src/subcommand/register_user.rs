use anyhow::Result;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_data::config::store_config::PsyHasher;
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QRegisterUserRPCRequest,
};

use crate::subcommand::args::RegisterUserArgs;

pub async fn run(args: RegisterUserArgs) -> Result<()> {
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;

    let info = load_wallet_key_info(&args.wallet, false)?;
    let fingerprint = info.fingerprint.clone();
    let private_key_base = info.private_key;
    let generated_private_key = info.generated;

    let public_key_info = ZKPublicKeyInfo {
        fingerprint,
        public_key_param: info.public_key_param,
    };
    let register_user_uuid = provider.register_user(QRegisterUserRPCRequest { public_key: public_key_info }).await?;
    println!("registered user uuid: {}", register_user_uuid);

    let public_key_hash = public_key_info.qfhash::<PsyHasher>();
    println!("{{");
    if generated_private_key {
        println!("  \"private_key\": \"{}\",", private_key_base);
    }
    println!("  \"public_key_hash\": \"{}\",", public_key_hash);
    println!("  \"fingerprint\": \"{}\",", public_key_info.fingerprint);
    println!("  \"public_key_param\": \"{}\"", public_key_info.public_key_param);
    println!("}}");

    Ok(())
}
