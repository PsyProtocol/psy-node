use std::{
    io::{self, Write},
    path::Path,
};

use anyhow::Result;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_prover::wallet::memory_wallet::get_allow_method_sdk_key_fingerprint;
use psy_provider::wallet::secp_wallet::Wallet;
use rpassword::read_password;

use super::args::{WalletArgs, WalletCommands};

pub fn run(args: WalletArgs) -> Result<()> {
    match args.command {
        WalletCommands::Create { output, password, .. } => {
            let wallet = Wallet::new()?;

            if let Some(path) = output {
                let password = match password {
                    Some(p) => p,
                    None => {
                        print!("Enter password for wallet: ");
                        io::stdout().flush()?;
                        read_password()?
                    }
                };

                wallet.save(Path::new(&path), Some(&password))?;
                println!("✅ Wallet created and saved to: {}", path);
            } else {
                println!("✅ Wallet created:");
            }

            println!("ETH Address: {}", wallet.address());
            println!("Public Key: {}", wallet.public_key_hash());
            // println!("Private Key: {}", wallet.private_key_hex());

            Ok(())
        }
        WalletCommands::Load { wallet, .. } => {
            let wallet = Wallet::load(
                wallet.private_key.as_deref(),
                wallet.keystore_path.as_ref().map(|p| Path::new(p)),
                wallet.wallet_password.as_deref(),
            )?;

            println!("✅ Wallet loaded:");
            println!("ETH Address: {}", wallet.address());
            println!("Public Key: {}", wallet.public_key_hash());

            Ok(())
        }
        WalletCommands::List { keystore_dir } => {
            let dir = keystore_dir.as_ref().map(|p| Path::new(p));
            let accounts = Wallet::list_accounts(dir)?;

            if accounts.is_empty() {
                println!("No wallets found");
            } else {
                println!("Found {} wallet(s):", accounts.len());
                for account in accounts {
                    println!("  {}", account);
                }
            }

            Ok(())
        }
        WalletCommands::Random { sign_type } => {
            use psy_client_common::args::WalletSourceArgs;
            let wallet_args = WalletSourceArgs {
                private_key: None,
                keystore_path: None,
                wallet_password: None,
                sign_type,
                fingerprint: None,
                sdk_key_allowed_contract_id: vec![],
                sdk_key_allowed_method_id: vec![],
                sdk_key_expected_tx_count: 2,
            };
            let info = load_wallet_key_info(&wallet_args, true)?;
            println!("Generated wallet:");
            println!("{}", serde_json::to_string_pretty(&info)?);
            Ok(())
        }
        WalletCommands::Info { wallet } => {
            let info = load_wallet_key_info(&wallet, false)?;
            println!("sign_type: {:?}", info.sign_type);
            println!("fingerprint: {}", info.fingerprint);
            println!("public_key_param: {}", info.public_key_param);
            println!("public_key: {}", info.public_key_hash);
            println!("private_key: {}", info.private_key);
            Ok(())
        }
        WalletCommands::SdkKeyFingerprint {
            allowed_contract_id,
            allowed_method_id,
            expected_tx_count,
        } => {
            let fingerprint = get_allow_method_sdk_key_fingerprint(&allowed_contract_id, &allowed_method_id, expected_tx_count)?;
            println!("{}", fingerprint);
            Ok(())
        }
    }
}
