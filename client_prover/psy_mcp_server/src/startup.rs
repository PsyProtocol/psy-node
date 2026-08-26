use std::collections::{HashMap, HashSet};

use anyhow::Result;

use crate::{keystore, wallet::WalletManager};

pub async fn restore_wallets(wallet: &WalletManager) -> Result<()> {
    let explicit_key = std::env::var(keystore::KEY_FILE_ENV).ok().filter(|p| !p.trim().is_empty());
    let mut key_files = keystore::discover_key_files()?;
    if let Some(path) = explicit_key.as_ref() {
        let path = std::path::PathBuf::from(path);
        if !key_files.contains(&path) {
            key_files.insert(0, path);
        }
    }

    let mut restored = HashSet::new();
    let mut restored_networks = HashSet::new();
    let mut explicit_selection: Option<(String, String)> = None;
    for path in key_files {
        let path_text = path.to_string_lossy().to_string();
        let backup = match keystore::load_key_file(&path_text) {
            Ok(backup) => backup,
            Err(e) if explicit_key.as_deref() == Some(path_text.as_str()) => return Err(e),
            Err(e) => {
                tracing::warn!("skipping invalid discovered key backup {}: {e:#}", path.display());
                continue;
            }
        };
        let backup_network = backup.network.clone().unwrap_or_else(|| wallet.default_network().to_string());
        if !restored.insert((backup_network.clone(), backup.private_key.clone())) {
            tracing::info!("skipping duplicate wallet backup {}", path.display());
            continue;
        }
        let network = match wallet.resolve_network(Some(&backup_network)) {
            Ok(network) => network,
            Err(e) => {
                tracing::error!("could not resolve network `{backup_network}` for {}: {e:#}", path.display());
                continue;
            }
        };
        if let Err(e) = wallet.ensure_network(&network).await {
            tracing::error!("could not initialize network `{backup_network}` for {}: {e:#}", path.display());
            continue;
        }
        match wallet.load_from_backup(&network, &backup).await {
            Ok(loaded) => {
                restored_networks.insert(network.clone());
                if explicit_key.as_deref() == Some(path_text.as_str()) {
                    explicit_selection = Some((backup_network.clone(), loaded.pk_hash.to_string()));
                }
                tracing::info!(
                    "wallet restored from {} on {} — user id {} (Psy-{:08})",
                    path.display(),
                    backup_network,
                    loaded.user_id,
                    loaded.user_id
                )
            }
            Err(e) => tracing::error!("could not restore wallet from {} on {}: {e:#}", path.display(), backup_network),
        }
    }

    // Loading a key necessarily activates it in WalletSession. Remove those
    // incidental choices before applying durable owner intent below.
    for network in &restored_networks {
        wallet.clear_active_user(network).await?;
    }

    let saved = match keystore::load_active_wallets() {
        Ok(saved) => saved,
        Err(e) => {
            tracing::warn!("could not read active-wallet state; using restored backup order: {e:#}");
            HashMap::new()
        }
    };
    for (saved_network, pk_hash) in saved {
        let network = match wallet.resolve_network(Some(&saved_network)) {
            Ok(network) => network,
            Err(e) => {
                tracing::warn!("cannot resolve saved network `{saved_network}`: {e:#}");
                continue;
            }
        };
        if let Err(e) = wallet.ensure_network(&network).await {
            tracing::warn!("cannot restore active wallet for network `{saved_network}`: {e:#}");
            continue;
        }
        if let Err(e) = wallet.select_user(&network, &pk_hash).await {
            tracing::warn!("saved active wallet {pk_hash} is not loaded on network `{saved_network}`: {e:#}");
        }
    }
    // An explicitly supplied key is an owner choice for this boot and wins for
    // its network over both discovery order and an older persisted selection.
    if let Some((explicit_network, pk_hash)) = explicit_selection {
        let network = wallet.resolve_network(Some(&explicit_network))?;
        wallet.select_user(&network, &pk_hash).await?;
    }
    Ok(())
}
