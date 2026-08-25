//! Worker whitelist policy sourced from `psy-genesis/config.json`.
//!
//! One immutable [`WhiteList`] snapshot per check; [`WhiteListCache::reload_once`]
//! atomically swaps it on a valid reload and retains the last good snapshot on
//! error. Runtime identity is the canonical compressed SEC1 public key
//! (`signature.public_key`, `[u8; 33]`).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use parking_lot::RwLock;
use psy_core::constants::chain_id::PsyChainNetworkType;
use serde::Deserialize;

/// Gap between automatic background reloads of the policy file.
pub const RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Immutable snapshot of the worker whitelist policy for one network.
///
/// Disabled (or missing) allows all membership checks; enabled with no keys
/// denies all.
#[derive(Debug, Clone, Default)]
pub struct WhiteList {
    enabled: bool,
    keys: BTreeSet<[u8; 33]>,
}

impl WhiteList {
    /// Membership decision: disabled => allow, enabled empty => deny,
    /// enabled with keys => allow iff `public_key` is a member.
    pub fn is_allowed(&self, public_key: &[u8; 33]) -> bool {
        if !self.enabled {
            return true;
        }
        self.keys.contains(public_key)
    }

    /// Parse the config file and select the policy snapshot for `network`.
    ///
    /// File-read, JSON-parse and key-validation errors propagate. A missing
    /// selected network entry also propagates (it indicates a mapping error or
    /// truncated config and must not silently disable admission). A present
    /// network entry whose `whitelist` object (or `enabled`) is absent is
    /// treated as a disabled (allow-all) policy rather than an error.
    pub fn load_from_config(
        config_path: &Path,
        network: PsyChainNetworkType,
    ) -> anyhow::Result<Self> {
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

        let key = config_key_for_network(network);
        let network_entry = config.networks.get(key).ok_or_else(|| {
            anyhow::anyhow!(
                "worker whitelist config has no network entry for {network:?} (family key \"{key}\")"
            )
        })?;
        let Some(whitelist) = network_entry.whitelist.as_ref() else {
            return Ok(Self::disabled());
        };

        if !whitelist.enabled {
            return Ok(Self::disabled());
        }

        let mut keys: BTreeSet<[u8; 33]> = BTreeSet::new();
        for entry in &whitelist.secp256k1 {
            keys.insert(parse_compressed_key(entry)?);
        }
        Ok(Self {
            enabled: true,
            keys,
        })
    }

    const fn disabled() -> Self {
        Self {
            enabled: false,
            keys: BTreeSet::new(),
        }
    }
}

/// Shared reload state, referenced by the cache and its background reload task.
struct Inner {
    snapshot: RwLock<WhiteList>,
    config_path: PathBuf,
    network: PsyChainNetworkType,
    reload_handle: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Reloadable, clonable cache sharing one live policy snapshot.
///
/// Construction spawns a background task that reloads the policy every
/// [`RELOAD_INTERVAL`]. Clones share the same snapshot and reload task. The
/// final cache drop aborts the task.
#[derive(Clone)]
pub struct WhiteListCache {
    inner: Arc<Inner>,
}

impl WhiteListCache {
    /// Load the initial policy snapshot for `network` from `config_path` and
    /// spawn the background reload task. Initial file-read, JSON-parse and
    /// key-validation errors (including a missing selected network entry)
    /// propagate. Must be called within a Tokio runtime.
    pub fn new(
        config_path: impl AsRef<Path>,
        network: PsyChainNetworkType,
    ) -> anyhow::Result<Self> {
        let path = config_path.as_ref().to_path_buf();
        let snapshot = WhiteList::load_from_config(&path, network)?;
        let inner = Arc::new(Inner {
            snapshot: RwLock::new(snapshot),
            config_path: path,
            network,
            reload_handle: parking_lot::Mutex::new(None),
        });

        let task_inner = Arc::downgrade(&inner);
        let reload_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(RELOAD_INTERVAL);
            interval.tick().await; // consume the immediate first tick
            loop {
                interval.tick().await;
                let Some(inner) = task_inner.upgrade() else {
                    return;
                };
                let _ = reload_once(&inner);
            }
        });

        *inner.reload_handle.lock() = Some(reload_handle);
        Ok(Self { inner })
    }

    /// Membership check against the current snapshot.
    pub fn is_allowed(&self, public_key: &[u8; 33]) -> anyhow::Result<bool> {
        Ok(self.inner.snapshot.read().is_allowed(public_key))
    }

    /// Re-read the policy file and atomically swap the snapshot on success.
    /// On error the last good snapshot is retained (the failure is logged) and
    /// the error is returned. Also the sleep-free reload primitive exercised by
    /// the background task.
    pub fn reload_once(&self) -> anyhow::Result<()> {
        reload_once(&self.inner)
    }
}

/// Re-read and swap (or retain) the policy for `inner`.
fn reload_once(inner: &Inner) -> anyhow::Result<()> {
    match WhiteList::load_from_config(&inner.config_path, inner.network) {
        Ok(new_snapshot) => {
            *inner.snapshot.write() = new_snapshot;
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

/// Maps a runtime [`PsyChainNetworkType`] to its `psy-genesis/config.json`
/// network family key. The config defines three families: `localhost` (local
/// devnet), `sepolia` (testnet/pre-production staging on Ethereum Sepolia L1),
/// and `ethereum` (mainnet). Runtime variants route to the family matching
/// their deployment stage:
/// - devnets (`LocalDevnet`, `PsyTeamDevnet`, `InternalDevnet`) -> `localhost`
/// - testnet/pre-production (`InternalTestnet`, `InternalPreProduction`,
///   `PsyPublicCanary`, `PsyPublicTestnet`) -> `sepolia`
/// - mainnet (`PsyMainnet`) -> `ethereum`
fn config_key_for_network(network: PsyChainNetworkType) -> &'static str {
    match network {
        PsyChainNetworkType::LocalDevnet
        | PsyChainNetworkType::PsyTeamDevnet
        | PsyChainNetworkType::InternalDevnet => "localhost",
        PsyChainNetworkType::InternalTestnet
        | PsyChainNetworkType::InternalPreProduction
        | PsyChainNetworkType::PsyPublicCanary
        | PsyChainNetworkType::PsyPublicTestnet => "sepolia",
        PsyChainNetworkType::PsyMainnet => "ethereum",
    }
}

/// Parse a 33-byte compressed SEC1 public key from a hex string (optional
/// `0x`/`0X` prefix), validated on-curve via `k256` and re-encoded in canonical
/// compressed form so de-duplication is deterministic.
fn parse_compressed_key(value: &str) -> anyhow::Result<[u8; 33]> {
    let trimmed = value.trim();
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let bytes = hex::decode(hex_part)
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

// Minimal JSON shape read from `psy-genesis/config.json`; unknown fields ignored.
#[derive(Debug, Deserialize)]
struct ConfigFile {
    #[serde(default)]
    networks: std::collections::BTreeMap<String, NetworkEntry>,
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
        let encoded = signing_key.verifying_key().to_encoded_point(true);
        let mut out = [0u8; 33];
        out.copy_from_slice(encoded.as_bytes());
        out
    }

    fn write_config(dir: &tempfile::TempDir, json: &str) -> PathBuf {
        let path = dir.path().join("config.json");
        std::fs::write(&path, json).unwrap();
        path
    }

    fn hex_key(key: &[u8; 33]) -> String {
        hex::encode(key)
    }

    #[tokio::test]
    async fn disabled_allows_any_member() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": {
                "localhost": { "whitelist": { "enabled": false, "secp256k1": [] } }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(!cache.inner.snapshot.read().enabled);
        assert!(cache.is_allowed(&key_from_seed(1)).unwrap());
    }

    #[tokio::test]
    async fn missing_whitelist_allows_any_member() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": { "localhost": { "magic": "0x1" } }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.is_allowed(&key_from_seed(1)).unwrap());
    }

    #[tokio::test]
    async fn enabled_empty_denies_all() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": {
                "localhost": { "whitelist": { "enabled": true, "secp256k1": [] } }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.inner.snapshot.read().enabled);
        assert!(!cache.is_allowed(&key_from_seed(1)).unwrap());
    }

    #[tokio::test]
    async fn member_accepted_non_member_denied() {
        let dir = tempfile::tempdir().unwrap();
        let member = key_from_seed(1);
        let outsider = key_from_seed(2);
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&member)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.is_allowed(&member).unwrap());
        assert!(!cache.is_allowed(&outsider).unwrap());
    }

    #[tokio::test]
    async fn malformed_length_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": ["02".to_string() + &"a".repeat(62)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let err = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet)
            .err()
            .expect("bad length key must fail construction");
        assert!(err.to_string().contains("33 bytes"));
    }

    #[tokio::test]
    async fn malformed_hex_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": ["0x02zz".to_string() + &"a".repeat(58)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let err = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet)
            .err()
            .expect("bad hex key must fail construction");
        assert!(err.to_string().contains("invalid hex"));
    }

    #[tokio::test]
    async fn off_curve_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let mut off_curve = [0u8; 33];
        for x in 1u64.. {
            let mut key = [0x02u8; 33];
            let mut x_bytes = [0u8; 32];
            x_bytes[24..].copy_from_slice(&x.to_be_bytes());
            key[1..].copy_from_slice(&x_bytes);
            if k256::ecdsa::VerifyingKey::from_sec1_bytes(&key).is_err() {
                off_curve = key;
                break;
            }
        }
        assert_ne!(off_curve, [0u8; 33], "found an off-curve x");
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&off_curve)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let err = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet)
            .err()
            .expect("off-curve key must fail construction");
        assert!(err.to_string().contains("on curve"));
    }

    #[tokio::test]
    async fn duplicates_deduplicated_deterministically() {
        let dir = tempfile::tempdir().unwrap();
        let key = key_from_seed(1);
        let hex_plain = hex_key(&key);
        let hex_prefixed = format!("0x{}", hex_plain);
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": {
                        "enabled": true,
                        "secp256k1": [hex_plain, hex_prefixed, hex_plain]
                    }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert_eq!(cache.inner.snapshot.read().keys.len(), 1);
        assert!(cache.is_allowed(&key).unwrap());
    }

    #[tokio::test]
    async fn network_selection_uses_correct_family() {
        let dir = tempfile::tempdir().unwrap();
        let localhost_key = key_from_seed(1);
        let sepolia_key = key_from_seed(2);
        let mainnet_key = key_from_seed(3);
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&localhost_key)] }
                },
                "sepolia": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&sepolia_key)] }
                },
                "ethereum": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&mainnet_key)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);

        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.is_allowed(&localhost_key).unwrap());
        assert!(!cache.is_allowed(&sepolia_key).unwrap());

        let cache = WhiteListCache::new(&path, PsyChainNetworkType::PsyPublicTestnet).unwrap();
        assert!(cache.is_allowed(&sepolia_key).unwrap());
        assert!(!cache.is_allowed(&localhost_key).unwrap());

        let cache = WhiteListCache::new(&path, PsyChainNetworkType::PsyMainnet).unwrap();
        assert!(cache.is_allowed(&mainnet_key).unwrap());
        assert!(!cache.is_allowed(&sepolia_key).unwrap());

        let cache = WhiteListCache::new(&path, PsyChainNetworkType::PsyTeamDevnet).unwrap();
        assert!(cache.is_allowed(&localhost_key).unwrap());
        assert!(!cache.is_allowed(&sepolia_key).unwrap());
    }

    #[tokio::test]
    async fn absent_network_family_fails_construction() {
        let dir = tempfile::tempdir().unwrap();
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_from_seed(1))] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let err = WhiteListCache::new(&path, PsyChainNetworkType::PsyMainnet)
            .err()
            .expect("missing selected network entry must fail construction");
        assert!(err.to_string().contains("no network entry"));
    }

    #[tokio::test]
    async fn absent_network_on_reload_retains_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = key_from_seed(1);
        let initial = serde_json::json!({
            "networks": {
                "ethereum": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_a)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &initial);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::PsyMainnet).unwrap();
        assert!(cache.is_allowed(&key_a).unwrap());

        std::fs::write(&path, serde_json::json!({ "networks": {} }).to_string()).unwrap();
        assert!(cache.reload_once().is_err());

        assert!(cache.is_allowed(&key_a).unwrap());
    }

    #[tokio::test]
    async fn valid_reload_replaces_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = key_from_seed(1);
        let key_b = key_from_seed(2);
        let initial = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_a)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &initial);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.is_allowed(&key_a).unwrap());
        assert!(!cache.is_allowed(&key_b).unwrap());

        let replaced = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_b)] }
                }
            }
        })
        .to_string();
        std::fs::write(&path, &replaced).unwrap();
        cache.reload_once().unwrap();

        assert!(!cache.is_allowed(&key_a).unwrap());
        assert!(cache.is_allowed(&key_b).unwrap());
    }

    #[tokio::test]
    async fn invalid_reload_retains_prior_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = key_from_seed(1);
        let initial = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_a)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &initial);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        assert!(cache.is_allowed(&key_a).unwrap());

        let bad = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": ["not-a-key"] }
                }
            }
        })
        .to_string();
        std::fs::write(&path, &bad).unwrap();
        assert!(cache.reload_once().is_err());

        assert!(cache.is_allowed(&key_a).unwrap());

        let good = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": false, "secp256k1": [] }
                }
            }
        })
        .to_string();
        std::fs::write(&path, &good).unwrap();
        cache.reload_once().unwrap();
        assert!(cache.is_allowed(&key_from_seed(2)).unwrap());
    }

    #[tokio::test]
    async fn clones_share_snapshot_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let key_a = key_from_seed(1);
        let key_b = key_from_seed(2);
        let json = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_a)] }
                }
            }
        })
        .to_string();
        let path = write_config(&dir, &json);
        let cache = WhiteListCache::new(&path, PsyChainNetworkType::LocalDevnet).unwrap();
        let clone = cache.clone();

        assert!(clone.is_allowed(&key_a).unwrap());
        assert!(!clone.is_allowed(&key_b).unwrap());

        let replaced = serde_json::json!({
            "networks": {
                "localhost": {
                    "whitelist": { "enabled": true, "secp256k1": [hex_key(&key_b)] }
                }
            }
        })
        .to_string();
        std::fs::write(&path, &replaced).unwrap();
        clone.reload_once().unwrap();
        assert!(!cache.is_allowed(&key_a).unwrap());
        assert!(cache.is_allowed(&key_b).unwrap());
    }
}