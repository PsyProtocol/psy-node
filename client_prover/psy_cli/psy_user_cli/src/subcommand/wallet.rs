use std::{
    io::{self, Write},
    path::Path,
};

use anyhow::Result;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_prover::wallet::memory_wallet::get_allow_method_sd_key_fingerprint;
use psy_provider::wallet::secp_wallet::Wallet;
use rpassword::read_password;

use super::args::{WalletArgs, WalletCommands};
use crate::result::{CommandResult, WalletCreateResult, WalletInfoResult};

pub fn run(args: WalletArgs) -> Result<CommandResult> {
    match args.command {
        WalletCommands::Create { output, password, .. } => {
            let wallet = Wallet::new()?;
            let keystore_path = output.clone();
            if let Some(path) = output {
                let password = match password {
                    Some(password) => password,
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
            Ok(CommandResult::WalletCreate(WalletCreateResult {
                keystore_path,
                public_key_hash: wallet.public_key_hash(),
                created: true,
            }))
        }
        WalletCommands::Load { wallet, .. } => {
            let wallet = Wallet::load(
                wallet.private_key.as_deref(),
                wallet.keystore_path.as_ref().map(Path::new),
                wallet.wallet_password.as_deref(),
            )?;
            println!("✅ Wallet loaded:");
            println!("ETH Address: {}", wallet.address());
            println!("Public Key: {}", wallet.public_key_hash());
            Ok(CommandResult::generic("wallet-load"))
        }
        WalletCommands::List { keystore_dir } => {
            let accounts = Wallet::list_accounts(keystore_dir.as_ref().map(Path::new))?;
            if accounts.is_empty() {
                println!("No wallets found");
            } else {
                println!("Found {} wallet(s):", accounts.len());
                for account in accounts {
                    println!("  {}", account);
                }
            }
            Ok(CommandResult::generic("wallet-list"))
        }
        WalletCommands::Random { sign_type } => {
            use psy_client_common::args::WalletSourceArgs;
            let info = load_wallet_key_info(
                &WalletSourceArgs {
                    private_key: None,
                    keystore_path: None,
                    wallet_password: None,
                    sign_type,
                    fingerprint: None,
                    sd_key_allowed_contract_id: vec![],
                    sd_key_allowed_method_id: vec![],
                    sd_key_expected_tx_count: 2,
                    sd_key_definition: None,
                },
                true,
            )?;
            println!("Generated wallet:");
            println!("{}", serde_json::to_string_pretty(&info)?);
            Ok(CommandResult::generic("wallet-random"))
        }
        WalletCommands::Info { wallet } => {
            let info = load_wallet_key_info(&wallet, false)?;
            println!("sign_type: {:?}", info.sign_type);
            println!("fingerprint: {}", info.fingerprint);
            println!("public_key_param: {}", info.public_key_param);
            println!("public_key: {}", info.public_key_hash);
            println!("private_key: {}", info.private_key);
            Ok(CommandResult::WalletInfo(WalletInfoResult {
                public_key_hash: info.public_key_hash,
                keystore_path: wallet.keystore_path,
            }))
        }
        WalletCommands::SdKeyFingerprint {
            allowed_contract_id,
            allowed_method_id,
            expected_tx_count,
        } => {
            println!(
                "{}",
                get_allow_method_sd_key_fingerprint(&allowed_contract_id, &allowed_method_id, expected_tx_count)?
            );
            Ok(CommandResult::generic("wallet-sd-key-fingerprint"))
        }
    }
}
