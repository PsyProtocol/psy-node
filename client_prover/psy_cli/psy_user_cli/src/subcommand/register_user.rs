use anyhow::Result;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_data::config::store_config::PsyHasher;
use psy_crypto::{hash::traits::qhashable::QFieldHashable, signature::zk::data::ZKPublicKeyInfo};
use psy_provider::{
    provider::{QUserRpcProvider, RpcProvider},
    request::QRegisterUserRPCRequest,
};

use crate::{
    result::{CommandResult, RegisterUserResult, UserRegistrationStatus},
    subcommand::args::RegisterUserArgs,
};

pub async fn run(args: RegisterUserArgs) -> Result<CommandResult> {
    let provider = RpcProvider::new_with_config_path(&args.rpc_config)?;
    let info = load_wallet_key_info(&args.wallet, false)?;
    let generated_private_key = info.generated;
    let private_key = info.private_key;
    let public_key_info = ZKPublicKeyInfo {
        fingerprint: info.fingerprint,
        public_key_param: info.public_key_param,
    };
    let public_key_hash = public_key_info.qfhash::<PsyHasher>();
    let existing_ids = provider.get_user_ids_for_public_key(public_key_hash).await?;
    if let Some(user_id) = existing_ids.first().copied() {
        println!("public key already registered with user_ids: {:?}", existing_ids);
        println!("skip registration. use the first user_id ({}) for deposit/claim.", user_id);
        print_key_info(generated_private_key, private_key, public_key_hash, &public_key_info);
        return Ok(CommandResult::RegisterUser(RegisterUserResult {
            public_key_hash,
            user_id: Some(user_id),
            transaction_hash: None,
            status: UserRegistrationStatus::Registered,
        }));
    }

    let register_user_uuid = provider.register_user(QRegisterUserRPCRequest { public_key: public_key_info.clone() }).await?;
    println!("registered user uuid: {}", register_user_uuid);
    print_key_info(generated_private_key, private_key, public_key_hash, &public_key_info);
    Ok(CommandResult::RegisterUser(RegisterUserResult {
        public_key_hash,
        user_id: None,
        transaction_hash: Some(register_user_uuid.to_string()),
        status: UserRegistrationStatus::Pending,
    }))
}

fn print_key_info(
    generated_private_key: bool,
    private_key: psy_client_common::data::qhashout::QHashOut<plonky2::field::goldilocks_field::GoldilocksField>,
    public_key_hash: psy_client_common::data::qhashout::QHashOut<plonky2::field::goldilocks_field::GoldilocksField>,
    public_key_info: &ZKPublicKeyInfo<plonky2::field::goldilocks_field::GoldilocksField>,
) {
    println!("{{");
    if generated_private_key {
        println!("  \"private_key\": \"{}\",", private_key);
    }
    println!("  \"public_key_hash\": \"{}\",", public_key_hash);
    println!("  \"fingerprint\": \"{}\",", public_key_info.fingerprint);
    println!("  \"public_key_param\": \"{}\"", public_key_info.public_key_param);
    println!("}}");
}
