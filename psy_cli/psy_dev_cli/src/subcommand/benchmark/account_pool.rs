use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use psy_client_common::args::{SignType, WalletSourceArgs};
use psy_config::NetworkConfigGoldilocks;
use psy_provider::wallet::secp_wallet::Wallet;
use serde::{Deserialize, Serialize};

use psy_cli_common::key_utils::load_wallet_key_info;

const POOL_INDEX_FILE: &str = "pool.json";
const POOL_LOCK_FILE: &str = "pool.lock";
const KEYSTORE_DIR: &str = "keystore";
const POOL_VERSION: u32 = 1;

/// Registration lifecycle of one pooled account. `Pending` means the register
/// RPC was accepted and confirmation is still in flight; `Unknown` means the
/// submission never confirmed within its timeout and must be queried, never
/// blindly resubmitted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum RegistrationState {
    Unregistered,
    Pending { tx_uuid: Option<String> },
    Unknown { tx_uuid: Option<String> },
    Registered,
    Failed { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolAccount {
    pub index: u32,
    pub keystore_file: String,
    pub sign_type: SignType,
    /// Hex string of the ZK public key hash; the pool never stores secrets.
    pub public_key_hash: String,
    /// Hex strings rebuilding `ZKPublicKeyInfo` for registration submission.
    pub fingerprint: String,
    pub public_key_param: String,
    pub user_id: Option<u64>,
    pub registration: RegistrationState,
    /// True while a benchmark scenario holds this account for an in-flight op.
    pub in_flight: bool,
    /// Faucet operator that last funded this account; the account claims
    /// incoming funds from this operator user id.
    pub last_faucet_operator: Option<u64>,
}

/// One durable record of a benchmark operation, kept so an interrupted run can
/// be resumed by querying instead of resubmitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolOpRecord {
    pub op_id: String,
    pub scenario: String,
    pub account_index: u32,
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub status: OpStatus,
    #[serde(default)]
    pub error: Option<String>,
    /// EndCap-only fields retained so a submitted or unknown EndCap can be
    /// re-queried for checkpoint inclusion after an interrupted run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_user_leaf_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_before: Option<u64>,
    /// Numeric on-chain contract id, resolved after checkpoint inclusion for
    /// deploy ops (`tx_hash` holds the RPC acceptance uuid instead).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_id: Option<u64>,
    pub started_unix_ms: i64,
    pub finished_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OpStatus {
    #[default]
    Submitted,
    Included,
    Failed,
    Unknown,
    /// Trace generated and durably recorded, but the submission phase was
    /// never entered: nothing reached the node, so recovery frees the account.
    Traced,
}

/// The account pool index. Bound to one network identity so accounts are never
/// reused across networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountPool {
    pub version: u32,
    pub network_name: String,
    pub network_magic: String,
    pub accounts: Vec<PoolAccount>,
    #[serde(default)]
    pub ops: Vec<PoolOpRecord>,
}

/// Exclusive cross-process guard held for the whole scenario run.
pub struct PoolGuard {
    #[allow(dead_code)]
    lock_file: std::fs::File,
    pool_dir: PathBuf,
    pool: AccountPool,
}

impl PoolGuard {
    pub fn pool(&self) -> &AccountPool {
        &self.pool
    }

    pub fn pool_mut(&mut self) -> &mut AccountPool {
        &mut self.pool
    }

    pub fn pool_dir(&self) -> &Path {
        &self.pool_dir
    }

    pub fn save(&self) -> Result<()> {
        let path = self.pool_dir.join(POOL_INDEX_FILE);
        let tmp = self.pool_dir.join(format!("{}.tmp", POOL_INDEX_FILE));
        let rendered = serde_json::to_string_pretty(&self.pool)?;
        fs::write(&tmp, rendered).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("rename {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }
}

pub fn open_pool(pool_dir: &Path, network: &NetworkConfigGoldilocks, network_name: &str) -> Result<PoolGuard> {
    fs::create_dir_all(pool_dir)?;
    let lock_path = pool_dir.join(POOL_LOCK_FILE);
    let lock_file = fs::OpenOptions::new().create(true).write(true).open(&lock_path)?;
    fs2::FileExt::lock_exclusive(&lock_file).context("acquire account pool lock; another benchmark may be running")?;

    let index_path = pool_dir.join(POOL_INDEX_FILE);
    let mut migrated = false;
    let pool = match fs::read_to_string(&index_path) {
        Ok(raw) => {
            let mut pool: AccountPool = serde_json::from_str(&raw)
                .with_context(|| format!("parse account pool index {}", index_path.display()))?;
            if pool.version == 1 {
                // v1 wrote every submit error — including ambiguous network
                // failures whose request may be queued — as Failed. v2 keeps
                // those isolated as Unknown so reconcile decides by chain
                // query instead of a blind resubmit.
                for account in pool.accounts.iter_mut() {
                    if matches!(account.registration, RegistrationState::Failed { .. }) {
                        account.registration = RegistrationState::Unknown { tx_uuid: None };
                    }
                }
                pool.version = POOL_VERSION;
                migrated = true;
            }
            anyhow::ensure!(
                pool.version == POOL_VERSION,
                "unsupported account pool version {}; expected {}",
                pool.version,
                POOL_VERSION
            );
            pool
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AccountPool {
            version: POOL_VERSION,
            network_name: network_name.to_string(),
            network_magic: network.magic.clone(),
            accounts: Vec::new(),
            ops: Vec::new(),
        },
        Err(error) => return Err(error).with_context(|| format!("read {}", index_path.display())),
    };

    anyhow::ensure!(
        pool.network_name == network_name && pool.network_magic == network.magic,
        "account pool is bound to network {} (magic {}), refusing to run against {} (magic {})",
        pool.network_name,
        pool.network_magic,
        network_name,
        network.magic
    );

    let mut guard = PoolGuard { lock_file, pool_dir: pool_dir.to_path_buf(), pool };
    if migrated {
        guard.save()?;
    }
    Ok(guard)
}

/// Create keystores and pool entries for account indices that do not exist yet.
pub fn create_missing_accounts(
    guard: &mut PoolGuard,
    count: u32,
    wallet_password: Option<&str>,
) -> Result<()> {
    let keystore_dir = guard.pool_dir().join(KEYSTORE_DIR);
    fs::create_dir_all(&keystore_dir)?;
    for index in 0..count {
        if guard.pool().accounts.iter().any(|account| account.index == index) {
            continue;
        }
        let keystore_file = format!("{}/account-{}.json", KEYSTORE_DIR, index);
        let keystore_path = guard.pool_dir().join(&keystore_file);
        if !keystore_path.exists() {
            let wallet = Wallet::new().context("generate benchmark account key")?;
            wallet.save(&keystore_path, wallet_password)?;
        }
        let wallet_args = wallet_source_args(keystore_path.to_str().context("keystore path is not UTF-8")?, wallet_password);
        let info = load_wallet_key_info(&wallet_args, false)?;
        guard.pool_mut().accounts.push(PoolAccount {
            index,
            keystore_file,
            sign_type: SignType::ZKSign,
            public_key_hash: info.public_key_hash.to_string(),
            fingerprint: info.fingerprint.to_string(),
            public_key_param: info.public_key_param.to_string(),
            user_id: None,
            registration: RegistrationState::Unregistered,
            in_flight: false,
            last_faucet_operator: None,
        });
    }
    guard.pool_mut().accounts.sort_by_key(|account| account.index);
    guard.save()
}

pub fn wallet_source_args(keystore_file: &str, wallet_password: Option<&str>) -> WalletSourceArgs {
    // A passwordless pool uses an empty-string keystore password; passing None
    // would trigger Wallet::load's interactive prompt.
    WalletSourceArgs {
        sign_type: SignType::ZKSign,
        private_key: None,
        keystore_path: Some(keystore_file.to_string()),
        wallet_password: Some(wallet_password.unwrap_or("").to_string()),
        fingerprint: None,
        sd_key_allowed_contract_id: Vec::new(),
        sd_key_allowed_method_id: Vec::new(),
        sd_key_min_tx_count: None,
        sd_key_max_tx_count: None,
        sd_key_definition: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_network() -> (NetworkConfigGoldilocks, String) {
        let raw = serde_json::json!({
            "magic": "0xbenchmark",
            "users_per_realm": 64,
            "global_user_tree_height": 20,
            "realm_user_tree_height": 6,
            "group_realm_height": 2,
            "realm_configs": [],
            "p2p": { "checkpoints_per_epoch": 32 },
            "coordinator_configs": [],
            "prove_proxy_url": [],
            "faucet_rpc_url": [],
            "nostr_relay_url": "ws://localhost:7777",
            "native_currency": "ETH",
            "native_currency_decimal": 18,
            "native_currency_name": "Ether",
            "fees": {
                "register_user_fee": 0,
                "deploy_contract_fee": 0,
                "guta_fee": 0,
                "da_fee": 0,
            },
        });
        let network: NetworkConfigGoldilocks = serde_json::from_value(raw).expect("build test network config");
        (network, "localhost".to_string())
    }

    #[test]
    fn open_creates_pool_bound_to_network() {
        let dir = std::env::temp_dir().join(format!("psy-bench-pool-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        let (network, name) = test_network();
        let guard = open_pool(&dir, &network, &name).unwrap();
        assert_eq!(guard.pool().network_name, "localhost");
        assert_eq!(guard.pool().network_magic, "0xbenchmark");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_migrates_v1_failed_registrations_to_unknown() {
        let dir = std::env::temp_dir().join(format!("psy-bench-pool-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        let (network, name) = test_network();
        {
            let mut guard = open_pool(&dir, &network, &name).unwrap();
            guard.pool_mut().accounts.push(PoolAccount {
                index: 0,
                keystore_file: "keystore/account-0.json".to_string(),
                sign_type: SignType::ZKSign,
                public_key_hash: "00".to_string(),
                fingerprint: "00".to_string(),
                public_key_param: "00".to_string(),
                user_id: None,
                // v1 semantics: a connection failure during submit.
                registration: RegistrationState::Failed { error: "Connection error".to_string() },
                in_flight: false,
                last_faucet_operator: None,
            });
            guard.pool_mut().version = 1;
            guard.save().unwrap();
        }
        let guard = open_pool(&dir, &network, &name).unwrap();
        assert_eq!(guard.pool().version, POOL_VERSION);
        assert!(matches!(guard.pool().accounts[0].registration, RegistrationState::Unknown { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn open_refuses_wrong_network_identity() {
        let dir = std::env::temp_dir().join(format!("psy-bench-pool-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        let (network, name) = test_network();
        let guard = open_pool(&dir, &network, &name).unwrap();
        guard.save().unwrap();
        drop(guard);
        let other_raw = serde_json::json!({
            "magic": "0xother",
            "users_per_realm": 64,
            "global_user_tree_height": 20,
            "realm_user_tree_height": 6,
            "group_realm_height": 2,
            "realm_configs": [],
            "p2p": { "checkpoints_per_epoch": 32 },
            "coordinator_configs": [],
            "prove_proxy_url": [],
            "faucet_rpc_url": [],
            "nostr_relay_url": "ws://localhost:7777",
            "native_currency": "ETH",
            "native_currency_decimal": 18,
            "native_currency_name": "Ether",
            "fees": {
                "register_user_fee": 0,
                "deploy_contract_fee": 0,
                "guta_fee": 0,
                "da_fee": 0,
            },
        });
        let other: NetworkConfigGoldilocks = serde_json::from_value(other_raw).unwrap();
        let error = open_pool(&dir, &other, &name).err().expect("wrong network must be rejected");
        assert!(error.to_string().contains("bound to network"), "{error:#}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_accounts_is_idempotent_and_sorted() {
        let dir = std::env::temp_dir().join(format!("psy-bench-pool-{}-{}", std::process::id(), line!()));
        let _ = fs::remove_dir_all(&dir);
        let (network, name) = test_network();
        let mut guard = open_pool(&dir, &network, &name).unwrap();
        create_missing_accounts(&mut guard, 3, None).unwrap();
        create_missing_accounts(&mut guard, 3, None).unwrap();
        assert_eq!(guard.pool().accounts.len(), 3);
        let indices: Vec<u32> = guard.pool().accounts.iter().map(|account| account.index).collect();
        assert_eq!(indices, vec![0, 1, 2]);
        for account in &guard.pool().accounts {
            assert!(matches!(account.registration, RegistrationState::Unregistered));
            assert!(dir.join(&account.keystore_file).exists());
            assert_eq!(account.sign_type, SignType::ZKSign);
        }
        let _ = fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod registration_state_tests {
    use super::*;

    #[test]
    fn registration_state_roundtrips_tagged_json() {
        for state in [
            RegistrationState::Unregistered,
            RegistrationState::Pending { tx_uuid: Some("uuid-1".to_string()) },
            RegistrationState::Unknown { tx_uuid: None },
            RegistrationState::Registered,
            RegistrationState::Failed { error: "rpc down".to_string() },
        ] {
            let rendered = serde_json::to_string(&state).unwrap();
            let decoded: RegistrationState = serde_json::from_str(&rendered).unwrap();
            assert_eq!(decoded, state);
        }
    }

    #[test]
    fn op_record_roundtrips_with_optional_endcap_fields() {
        let record = PoolOpRecord {
            op_id: "endcap-1".to_string(),
            scenario: "endcap".to_string(),
            account_index: 3,
            tx_hash: Some("0xabc".to_string()),
            status: OpStatus::Submitted,
            error: None,
            user_id: Some(42),
            end_user_leaf_hash: Some("0xdef".to_string()),
            checkpoint_before: Some(7),
            contract_id: None,
            started_unix_ms: 1,
            finished_unix_ms: None,
        };
        let rendered = serde_json::to_string(&record).unwrap();
        let decoded: PoolOpRecord = serde_json::from_str(&rendered).unwrap();
        assert_eq!(decoded.user_id, Some(42));
        assert_eq!(decoded.end_user_leaf_hash.as_deref(), Some("0xdef"));
        assert_eq!(decoded.contract_id, None);
        assert!(matches!(decoded.status, OpStatus::Submitted));
        let mut traced = record.clone();
        traced.status = OpStatus::Traced;
        let rendered_traced = serde_json::to_string(&traced).unwrap();
        assert!(rendered_traced.contains("\"traced\""));
        let decoded_traced: PoolOpRecord = serde_json::from_str(&rendered_traced).unwrap();
        assert!(matches!(decoded_traced.status, OpStatus::Traced));
    }
}
