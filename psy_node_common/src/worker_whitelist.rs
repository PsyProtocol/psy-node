//! Reloadable worker whitelist policy sourced from `psy-genesis/config.json`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use psy_core::constants::chain_id::PsyChainNetworkType;
use serde::Deserialize;

pub const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Debug, Clone, Default)]
pub struct WhiteList {
    enabled: bool,
    keys: BTreeSet<[u8; 33]>,
}

impl WhiteList {
    pub fn is_allowed(&self, public_key: &[u8; 33]) -> bool {
        !self.enabled || self.keys.contains(public_key)
    }

    fn load_from_config(config_path: &Path, network: PsyChainNetworkType) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(config_path).map_err(|error| {
            anyhow::anyhow!(
                "failed to read worker whitelist config at {}: {error}",
                config_path.display()
            )
        })?;
        Self::from_json(&raw, network)
    }

    fn from_json(json: &str, network: PsyChainNetworkType) -> anyhow::Result<Self> {
        let config: ConfigFile = serde_json::from_str(json)
            .map_err(|error| anyhow::anyhow!("failed to parse worker whitelist config JSON: {error}"))?;
        let config_key = config_key_for_network(network)?;
        let network_entry = config.networks.get(config_key).ok_or_else(|| {
            anyhow::anyhow!(
                "worker whitelist config has no network entry for {network:?} (config key \"{config_key}\")"
            )
        })?;
        let Some(whitelist) = network_entry.whitelist.as_ref() else {
            return Ok(Self::default());
        };
        if !whitelist.enabled {
            return Ok(Self::default());
        }

        let mut keys = BTreeSet::new();
        for value in &whitelist.secp256k1 {
            keys.insert(parse_compressed_key(value)?);
        }
        Ok(Self {
            enabled: true,
            keys,
        })
    }
}

struct Inner {
    snapshot: RwLock<WhiteList>,
    config_path: PathBuf,
    network: PsyChainNetworkType,
    reload_handle: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Clone)]
pub struct WhiteListCache {
    inner: Arc<Inner>,
}

impl WhiteListCache {
    pub fn new(config_path: impl AsRef<Path>, network: PsyChainNetworkType) -> anyhow::Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let snapshot = WhiteList::load_from_config(&config_path, network)?;
        let inner = Arc::new(Inner {
            snapshot: RwLock::new(snapshot),
            config_path,
            network,
            reload_handle: parking_lot::Mutex::new(None),
        });

        let weak_inner = Arc::downgrade(&inner);
        let reload_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(RELOAD_INTERVAL);
            interval.tick().await;
            loop {
                interval.tick().await;
                let Some(inner) = weak_inner.upgrade() else {
                    return;
                };
                let _ = reload_once(&inner);
            }
        });
        *inner.reload_handle.lock() = Some(reload_handle);

        Ok(Self { inner })
    }

    pub fn is_allowed(&self, public_key: &[u8; 33]) -> bool {
        self.inner.snapshot.read().is_allowed(public_key)
    }

    pub fn ensure_allowed(&self, public_key: &[u8; 33]) -> anyhow::Result<()> {
        if !self.is_allowed(public_key) {
            anyhow::bail!("worker public key is not whitelisted");
        }
        Ok(())
    }

    pub fn reload_once(&self) -> anyhow::Result<()> {
        reload_once(&self.inner)
    }
}

fn reload_once(inner: &Inner) -> anyhow::Result<()> {
    match WhiteList::load_from_config(&inner.config_path, inner.network) {
        Ok(snapshot) => {
            *inner.snapshot.write() = snapshot;
            Ok(())
        }
        Err(error) => {
            tracing::error!(
                ?error,
                network = ?inner.network,
                "worker whitelist reload failed; retaining last good snapshot"
            );
            Err(error)
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(handle) = self.reload_handle.get_mut().take() {
            handle.abort();
        }
    }
}

fn config_key_for_network(network: PsyChainNetworkType) -> anyhow::Result<&'static str> {
    match network {
        PsyChainNetworkType::LocalDevnet => Ok("localhost"),
        PsyChainNetworkType::PsyPublicTestnet => Ok("sepolia"),
        PsyChainNetworkType::PsyMainnet => Ok("ethereum"),
        PsyChainNetworkType::PsyTeamDevnet
        | PsyChainNetworkType::InternalDevnet
        | PsyChainNetworkType::InternalTestnet
        | PsyChainNetworkType::InternalPreProduction
        | PsyChainNetworkType::PsyPublicCanary => {
            anyhow::bail!("worker whitelist config has no explicit mapping for network {network:?}")
        }
    }
}

fn parse_compressed_key(value: &str) -> anyhow::Result<[u8; 33]> {
    let trimmed = value.trim();
    let hex_value = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_value)
        .map_err(|error| anyhow::anyhow!("invalid hex secp256k1 public key: {error}"))?;
    if bytes.len() != 33 {
        anyhow::bail!(
            "secp256k1 public key must be 33 bytes (66 hex chars), got {}",
            bytes.len()
        );
    }
    let verifying_key = k256::ecdsa::VerifyingKey::from_sec1_bytes(&bytes)
        .map_err(|error| anyhow::anyhow!("secp256k1 public key is not on curve: {error}"))?;
    verifying_key
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| anyhow::anyhow!("canonical compressed secp256k1 key is not 33 bytes"))
}

#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    networks: BTreeMap<String, NetworkEntry>,
}

#[derive(Debug, Deserialize)]
struct NetworkEntry {
    #[serde(default)]
    whitelist: Option<WhiteListConfig>,
}

#[derive(Debug, Deserialize)]
struct WhiteListConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    secp256k1: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn key_from_seed(seed: u8) -> [u8; 33] {
        let signing_key = SigningKey::from_slice(&[seed; 32]).unwrap();
        signing_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn write_config(dir: &tempfile::TempDir, json: serde_json::Value) -> PathBuf {
        let path = dir.path().join("config.json");
        fs::write(&path, json.to_string()).unwrap();
        path
    }

    fn config_with_policy(config_key: &str, enabled: bool, keys: &[[u8; 33]]) -> serde_json::Value {
        serde_json::json!({
            "networks": {
                config_key: {
                    "whitelist": {
                        "enabled": enabled,
                        "secp256k1": keys.iter().map(hex::encode).collect::<Vec<_>>()
                    }
                }
            }
        })
    }

    #[test]
    fn maps_only_explicitly_supported_networks() {
        let expectations = [
            (PsyChainNetworkType::LocalDevnet, Some("localhost")),
            (PsyChainNetworkType::PsyTeamDevnet, None),
            (PsyChainNetworkType::InternalDevnet, None),
            (PsyChainNetworkType::InternalTestnet, None),
            (PsyChainNetworkType::InternalPreProduction, None),
            (PsyChainNetworkType::PsyPublicCanary, None),
            (PsyChainNetworkType::PsyPublicTestnet, Some("sepolia")),
            (PsyChainNetworkType::PsyMainnet, Some("ethereum")),
        ];

        for (network, expected) in expectations {
            match expected {
                Some(config_key) => assert_eq!(config_key_for_network(network).unwrap(), config_key),
                None => assert!(config_key_for_network(network).is_err(), "{network:?} must fail closed"),
            }
        }
    }

    #[tokio::test]
    async fn disabled_policy_allows_workers() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(&dir, config_with_policy("localhost", false, &[]));
        let cache = WhiteListCache::new(path, PsyChainNetworkType::LocalDevnet).unwrap();
        cache.ensure_allowed(&key_from_seed(1)).unwrap();
    }

    #[tokio::test]
    async fn enabled_policy_enforces_membership() {
        let dir = tempfile::tempdir().unwrap();
        let member = key_from_seed(1);
        let non_member = key_from_seed(2);
        let path = write_config(&dir, config_with_policy("localhost", true, &[member]));
        let cache = WhiteListCache::new(path, PsyChainNetworkType::LocalDevnet).unwrap();

        cache.ensure_allowed(&member).unwrap();
        assert!(cache.ensure_allowed(&non_member).is_err());
    }

    #[tokio::test]
    async fn unsupported_network_fails_before_policy_selection() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(&dir, config_with_policy("localhost", false, &[]));
        let error = WhiteListCache::new(path, PsyChainNetworkType::PsyTeamDevnet)
            .err()
            .expect("unsupported network must fail closed");
        assert!(error.to_string().contains("no explicit mapping"));
    }

    #[tokio::test]
    async fn invalid_reload_retains_last_good_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let member = key_from_seed(1);
        let path = write_config(&dir, config_with_policy("localhost", true, &[member]));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        fs::write(&path, "not-json").unwrap();

        assert!(cache.reload_once().is_err());
        cache.ensure_allowed(&member).unwrap();
        assert!(cache.ensure_allowed(&key_from_seed(2)).is_err());
    }

    #[tokio::test]
    async fn valid_reload_replaces_snapshot_for_all_clones() {
        let dir = tempfile::tempdir().unwrap();
        let first = key_from_seed(1);
        let second = key_from_seed(2);
        let path = write_config(&dir, config_with_policy("localhost", true, &[first]));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        let clone = cache.clone();
        fs::write(&path, config_with_policy("localhost", true, &[second]).to_string()).unwrap();

        clone.reload_once().unwrap();
        assert!(cache.ensure_allowed(&first).is_err());
        cache.ensure_allowed(&second).unwrap();
    }

    #[tokio::test]
    async fn malformed_public_key_fails_initial_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(
            &dir,
            serde_json::json!({
                "networks": {
                    "localhost": {
                        "whitelist": { "enabled": true, "secp256k1": ["not-a-key"] }
                    }
                }
            }),
        );
        assert!(WhiteListCache::new(path, PsyChainNetworkType::LocalDevnet).is_err());
    }
}
