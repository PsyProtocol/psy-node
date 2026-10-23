use std::{
    io::{self, Write},
    path::Path,
};

use anyhow::{Context, Result};
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_prover::wallet::memory_wallet::get_allow_method_sd_key_fingerprint_range;
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
                    sd_key_min_tx_count: None,
                    sd_key_max_tx_count: None,
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
            min_tx_count,
            max_tx_count,
        } => {
            let (min_tx_count, max_tx_count) = match (min_tx_count, max_tx_count) {
                (Some(min), Some(max)) => (min, max),
                (Some(min), None) => (min, min),
                (None, Some(max)) => (1, max),
                (None, None) => (2, 2),
            };
            println!(
                "{}",
                get_allow_method_sd_key_fingerprint_range(&allowed_contract_id, &allowed_method_id, min_tx_count, max_tx_count)?
            );
            Ok(CommandResult::generic("wallet-sd-key-fingerprint"))
        }
        WalletCommands::SdKeyPolicyFingerprint { definition } => {
            let fingerprint = psy_cli_common::key_utils::sd_key_dpn_fingerprint_from_file(&definition)?;
            println!("{}", fingerprint);
            Ok(CommandResult::generic("wallet-sd-key-policy-fingerprint"))
        }
        WalletCommands::SdKeyPolicyTemplate { kind, contract, methods, word, max_per_tx, max_total, min_tx_count, max_tx_count, output, rpc_config } => {
            let kind = match kind {
                super::args::SdKeyPolicyTemplateKindArg::AllowMethod => psy_cli_common::key_utils::SdKeyPolicyTemplateKind::AllowMethod,
                super::args::SdKeyPolicyTemplateKindArg::SpendingLimit => psy_cli_common::key_utils::SdKeyPolicyTemplateKind::SpendingLimit,
                super::args::SdKeyPolicyTemplateKindArg::Sequence => psy_cli_common::key_utils::SdKeyPolicyTemplateKind::Sequence,
            };
            let (word, max_per_tx, max_total) = if matches!(kind, psy_cli_common::key_utils::SdKeyPolicyTemplateKind::SpendingLimit) {
                match (word, max_per_tx, max_total) {
                    (Some(word), Some(max_per_tx), Some(max_total)) => (word, max_per_tx, max_total),
                    _ => anyhow::bail!("--word, --max-per-tx, and --max-total are required for --kind spending-limit"),
                }
            } else {
                (0, 0, 0)
            };
            let specs: Vec<_> = methods.iter().map(|method| psy_cli_common::key_utils::MethodSpec::parse(method)).collect();
            let methods = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(psy_cli_common::key_utils::resolve_policy_methods(rpc_config.as_deref(), contract, &specs))
            })?;
            let json = psy_cli_common::key_utils::build_sd_key_policy_template(
                kind,
                contract,
                &methods,
                word,
                max_per_tx,
                max_total,
                min_tx_count,
                max_tx_count,
            )?;
            match output {
                Some(path) => std::fs::write(&path, format!("{json}\n")).with_context(|| format!("write policy template {path}"))?,
                None => println!("{json}"),
            }
            Ok(CommandResult::generic("wallet-sd-key-policy-template"))
        }
        WalletCommands::SdKeyPolicyCheck { definition, call, rpc_config } => {
            let specs: Vec<_> = call
                .iter()
                .map(|spec| psy_cli_common::key_utils::parse_policy_call_spec(spec))
                .collect::<Result<_>>()?;
            let calls = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(psy_cli_common::key_utils::resolve_policy_sim_calls(rpc_config.as_deref(), specs))
            })?;
            for line in psy_cli_common::key_utils::check_sd_key_policy(&definition, &calls)? {
                println!("{line}");
            }
            Ok(CommandResult::generic("wallet-sd-key-policy-check"))
        }
        WalletCommands::SdKeyPolicyDescribe { definition, contract, rpc_config } => {
            let names = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(psy_cli_common::key_utils::method_name_map(rpc_config.as_deref(), &contract))
            })?;
            print!("{}", psy_cli_common::key_utils::describe_sd_key_policy(&definition, if contract.is_empty() { None } else { Some(&names) })?);
            Ok(CommandResult::generic("wallet-sd-key-policy-describe"))
        }
        WalletCommands::SdKeyPolicyResolve { definition, contract, rpc_config, output } => {
            let contents = std::fs::read_to_string(&definition).with_context(|| format!("read SD key policy file {definition}"))?;
            let (json, log) = tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(psy_cli_common::key_utils::resolve_sd_key_policy_names(
                    &contents,
                    rpc_config.as_deref(),
                    contract,
                ))
            })?;
            for line in &log {
                println!("{line}");
            }
            if log.is_empty() {
                println!("no method names to resolve");
            }
            match output {
                Some(path) => std::fs::write(&path, format!("{json}\n")).with_context(|| format!("write resolved policy {path}"))?,
                None => println!("{json}"),
            }
            Ok(CommandResult::generic("wallet-sd-key-policy-resolve"))
        }
    }
}
