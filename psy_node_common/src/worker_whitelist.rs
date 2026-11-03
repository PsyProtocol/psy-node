//! Reloadable worker whitelist policy sourced from `psy-genesis/config.json`.
//!
//! The policy may carry an optional `labels` map from whitelisted public key to an operator name.
//! Labels never affect admission; they only name workers in Edge logs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use parking_lot::RwLock;
use psy_core::constants::chain_id::PsyChainNetworkType;
use serde::Deserialize;

pub const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
pub const MAX_LABEL_LEN: usize = 64;

type Labels = BTreeMap<[u8; 33], String>;

/// Labels of every loaded whitelist, keyed by config path, so code without a handle on the cache
/// (the reputation store) can still name a worker in its logs.
static LABEL_REGISTRY: LazyLock<RwLock<BTreeMap<PathBuf, Arc<Labels>>>> = LazyLock::new(Default::default);

/// Returns the operator label of `public_key` from any loaded whitelist.
pub fn worker_label(public_key: &[u8; 33]) -> Option<String> {
    LABEL_REGISTRY
        .read()
        .values()
        .find_map(|labels| labels.get(public_key).cloned())
}

/// Log field value for a worker: its label, or `-` when it has none.
pub fn worker_label_or_dash(public_key: &[u8; 33]) -> String {
    worker_label(public_key).unwrap_or_else(|| "-".to_string())
}

fn publish_labels(config_path: &Path, labels: &Labels) {
    LABEL_REGISTRY
        .write()
        .insert(config_path.to_path_buf(), Arc::new(labels.clone()));
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WhiteList {
    enabled: bool,
    keys: BTreeSet<[u8; 33]>,
    labels: Labels,
}

impl WhiteList {
    pub fn is_allowed(&self, public_key: &[u8; 33]) -> bool {
        !self.enabled || self.keys.contains(public_key)
    }

    pub fn label(&self, public_key: &[u8; 33]) -> Option<&str> {
        self.labels.get(public_key).map(String::as_str)
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
        let config_key = network.config_key()?;
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
        let labels = parse_labels(&whitelist.labels, &keys)?;
        Ok(Self {
            enabled: true,
            keys,
            labels,
        })
    }
}

fn parse_labels(raw: &BTreeMap<String, String>, keys: &BTreeSet<[u8; 33]>) -> anyhow::Result<Labels> {
    let mut labels = Labels::new();
    let mut names = BTreeSet::new();
    for (key, label) in raw {
        let public_key = parse_compressed_key(key)?;
        if !keys.contains(&public_key) {
            anyhow::bail!("worker label {label:?} names a key that is not whitelisted");
        }
        let valid = !label.is_empty()
            && label.len() <= MAX_LABEL_LEN
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
        if !valid {
            anyhow::bail!("worker label {label:?} must be 1-{MAX_LABEL_LEN} characters of [A-Za-z0-9._-]");
        }
        if !names.insert(label.as_str()) {
            anyhow::bail!("duplicate worker label {label:?}");
        }
        if labels.insert(public_key, label.clone()).is_some() {
            anyhow::bail!("worker key labelled twice");
        }
    }
    Ok(labels)
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
        publish_labels(&config_path, &snapshot.labels);
        tracing::info!(
            enabled = snapshot.enabled,
            keys = snapshot.keys.len(),
            labels = snapshot.labels.len(),
            "worker whitelist loaded"
        );
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

    pub fn label(&self, public_key: &[u8; 33]) -> Option<String> {
        self.inner.snapshot.read().label(public_key).map(str::to_string)
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
            publish_labels(&inner.config_path, &snapshot.labels);
            let mut current = inner.snapshot.write();
            if *current != snapshot {
                tracing::info!(
                    enabled = snapshot.enabled,
                    keys = snapshot.keys.len(),
                    labels = snapshot.labels.len(),
                    "worker whitelist reloaded with changes"
                );
                *current = snapshot;
            }
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
    #[serde(default)]
    labels: BTreeMap<String, String>,
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
    fn maps_only_supported_network_config_keys() {
        let expectations = [
            (PsyChainNetworkType::LocalDevnet, Some("localhost")),
            (PsyChainNetworkType::PsyTeamDevnet, None),
            (PsyChainNetworkType::InternalDevnet, None),
            (PsyChainNetworkType::InternalTestnet, None),
            (PsyChainNetworkType::InternalPreProduction, None),
            (PsyChainNetworkType::PsyPublicCanary, None),
            (PsyChainNetworkType::PsyPublicTestnet, Some("testnet")),
            (PsyChainNetworkType::PsyMainnet, Some("mainnet")),
        ];

        for (network, expected) in expectations {
            match expected {
                Some(config_key) => assert_eq!(network.config_key().unwrap(), config_key),
                None => assert!(network.config_key().is_err(), "{network:?} must fail closed"),
            }
        }
    }

    #[tokio::test]
    async fn testnet_policy_enforces_membership_without_legacy_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let member = key_from_seed(1);
        let non_member = key_from_seed(2);
        let mut config = config_with_policy("testnet", true, &[member]);
        config["networks"]["localhost"] = config_with_policy("localhost", false, &[])["networks"]["localhost"].clone();
        config["networks"]["sepolia"] = config_with_policy("sepolia", false, &[])["networks"]["sepolia"].clone();
        let path = write_config(&dir, config);
        let cache = WhiteListCache::new(path, PsyChainNetworkType::PsyPublicTestnet).unwrap();
        cache.ensure_allowed(&member).unwrap();
        assert!(cache.ensure_allowed(&non_member).is_err());
    }

    #[test]
    fn missing_testnet_policy_section_fails_closed() {
        for config_key in ["localhost", "sepolia"] {
            let config = config_with_policy(config_key, false, &[]);
            assert!(WhiteList::from_json(&config.to_string(), PsyChainNetworkType::PsyPublicTestnet).is_err());
        }
    }

    #[tokio::test]
    async fn testnet_reload_missing_section_retains_enforced_policy() {
        let dir = tempfile::tempdir().unwrap();
        let member = key_from_seed(1);
        let path = write_config(&dir, config_with_policy("testnet", true, &[member]));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::PsyPublicTestnet).unwrap();
        fs::write(&path, config_with_policy("sepolia", false, &[]).to_string()).unwrap();
        assert!(cache.reload_once().is_err());
        cache.ensure_allowed(&member).unwrap();
        assert!(cache.ensure_allowed(&key_from_seed(2)).is_err());
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
        assert!(error.to_string().contains("No configuration key"));
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

    fn config_with_labels(keys: &[[u8; 33]], labels: serde_json::Value) -> serde_json::Value {
        let mut config = config_with_policy("localhost", true, keys);
        config["networks"]["localhost"]["whitelist"]["labels"] = labels;
        config
    }

    #[tokio::test]
    async fn labels_name_workers_without_changing_admission() {
        let dir = tempfile::tempdir().unwrap();
        let (named, unnamed) = (key_from_seed(11), key_from_seed(12));
        let labels = serde_json::json!({ format!("0x{}", hex::encode(named)): "c4d-coordinator" });
        let path = write_config(&dir, config_with_labels(&[named, unnamed], labels));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();

        cache.ensure_allowed(&named).unwrap();
        cache.ensure_allowed(&unnamed).unwrap();
        assert_eq!(cache.label(&named).as_deref(), Some("c4d-coordinator"));
        assert_eq!(cache.label(&unnamed), None);
        assert_eq!(worker_label(&named).as_deref(), Some("c4d-coordinator"));
        assert_eq!(worker_label_or_dash(&unnamed), "-");
    }

    #[tokio::test]
    async fn reload_replaces_published_labels() {
        let dir = tempfile::tempdir().unwrap();
        let key = key_from_seed(13);
        let path = write_config(&dir, config_with_labels(&[key], serde_json::json!({ hex::encode(key): "old-name" })));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        fs::write(&path, config_with_labels(&[key], serde_json::json!({ hex::encode(key): "new-name" })).to_string()).unwrap();

        cache.reload_once().unwrap();
        assert_eq!(cache.label(&key).as_deref(), Some("new-name"));
        assert_eq!(worker_label(&key).as_deref(), Some("new-name"));

        fs::write(&path, config_with_policy("localhost", true, &[key]).to_string()).unwrap();
        cache.reload_once().unwrap();
        assert_eq!(worker_label(&key), None);
    }

    #[test]
    fn invalid_labels_fail_closed() {
        let (member, outsider) = (key_from_seed(14), key_from_seed(15));
        let other = key_from_seed(16);
        let cases = [
            serde_json::json!({ hex::encode(outsider): "outsider" }),
            serde_json::json!({ hex::encode(member): "" }),
            serde_json::json!({ hex::encode(member): "has space" }),
            serde_json::json!({ hex::encode(member): "x".repeat(MAX_LABEL_LEN + 1) }),
            serde_json::json!({ hex::encode(member): "same", hex::encode(other): "same" }),
            serde_json::json!({ hex::encode(member): "a", format!("0x{}", hex::encode(member)): "b" }),
            serde_json::json!({ "not-a-key": "name" }),
        ];
        for labels in cases {
            let config = config_with_labels(&[member, other], labels.clone());
            assert!(
                WhiteList::from_json(&config.to_string(), PsyChainNetworkType::LocalDevnet).is_err(),
                "labels must be rejected: {labels}"
            );
        }
        let longest = config_with_labels(&[member], serde_json::json!({ hex::encode(member): "x".repeat(MAX_LABEL_LEN) }));
        assert!(WhiteList::from_json(&longest.to_string(), PsyChainNetworkType::LocalDevnet).is_ok());
    }

    #[tokio::test]
    async fn invalid_label_reload_retains_last_good_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key = key_from_seed(17);
        let path = write_config(&dir, config_with_labels(&[key], serde_json::json!({ hex::encode(key): "kept" })));
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        fs::write(&path, config_with_labels(&[key], serde_json::json!({ hex::encode(key): "bad name" })).to_string()).unwrap();

        assert!(cache.reload_once().is_err());
        cache.ensure_allowed(&key).unwrap();
        assert_eq!(worker_label(&key).as_deref(), Some("kept"));
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
