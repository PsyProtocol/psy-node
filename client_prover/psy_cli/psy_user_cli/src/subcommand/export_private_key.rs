use std::path::Path;

use plonky2::field::goldilocks_field::GoldilocksField;
use psy_client_common::{
    args::ExportKeyStoreArgs,
    data::{base_types::hash256::Hash256, qhashout::QHashOut},
};
use psy_provider::wallet::secp_wallet::Wallet;

pub fn run(args: ExportKeyStoreArgs) -> anyhow::Result<()> {
    let private_key = match Wallet::load(None, Some(Path::new(&args.keystore_path)), Some(&args.wallet_password)) {
        Ok(wallet) => {
            let private_key_hex = wallet.private_key_hex();
            let normalized = private_key_hex.trim().trim_start_matches("0x");
            let hash = Hash256::from_hex_string(normalized).map_err(|e| anyhow::format_err!("failed to parse private key: {}", e))?;
            QHashOut::<GoldilocksField>::from(hash)
        }
        Err(e) => return Err(e),
    };

    println!("{}", serde_json::to_string_pretty(&private_key)?);

    Ok(())
}
