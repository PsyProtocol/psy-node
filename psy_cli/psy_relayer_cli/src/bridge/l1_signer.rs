use std::{
    io::{self, Write},
    path::Path,
    str::FromStr,
};

use alloy_network::EthereumWallet;
use alloy_signer_local::PrivateKeySigner;
use anyhow::{Context, Result};
pub fn load_l1_wallet(
    private_key: Option<&str>,
    keystore_path: Option<&Path>,
    password_env: Option<&str>,
    fallback_private_key: Option<&str>,
    key_label: &str,
) -> Result<EthereumWallet> {
    if let Some(path) = keystore_path {
        let env_name = password_env.unwrap_or("WALLET_PASSWORD");
        let password = match std::env::var(env_name) {
            Ok(password) => password,
            Err(_) => {
                print!("Enter password for {} keystore {}: ", key_label, path.display());
                io::stdout().flush()?;
                let mut password = String::new();
                io::stdin().read_line(&mut password)?;
                password.trim_end_matches(['\r', '\n']).to_string()
            }
        };
        let signer = PrivateKeySigner::decrypt_keystore(path, password.as_str())
            .with_context(|| format!("failed to decrypt {} keystore {}", key_label, path.display()))?;
        return Ok(EthereumWallet::from(signer));
    }

    let raw_key = private_key
        .or(fallback_private_key)
        .ok_or_else(|| anyhow::anyhow!("{} requires either private key or keystore path", key_label))?;
    let signer = PrivateKeySigner::from_str(raw_key.trim_start_matches("0x"))
        .or_else(|_| PrivateKeySigner::from_str(raw_key))
        .with_context(|| format!("invalid {}", key_label))?;
    Ok(EthereumWallet::from(signer))
}
