//! Durable key backup for generated wallets — the anti-fund-loss layer.
//!
//! `create_wallet(mode="generate")` creates a fresh private key. Before this
//! module existed the key lived ONLY in process memory: the owner never saw it
//! and nothing persisted it, so killing the process made every coin in the
//! wallet unrecoverable. The rule enforced here:
//!
//!   A generated key MUST be durably written to owner-readable disk BEFORE the
//!   chain learns about it (write → fsync → rename → only then register).
//!
//! A crash between "key written" and "user registered" leaves a stray key file,
//! which is harmless. The opposite order can leave an on-chain identity whose
//! key nobody has, which is catastrophic. Never reverse it.
//!
//! Secrecy: the private key is written to the key file and NOWHERE else — not
//! in tool results, not in logs. Tool results carry only the backup *path* and
//! the key fingerprint. On unix the file is created with mode 0600.
//!
//! Restart flow: the owner points `PSY_MCP_KEY_FILE` at a backup file and the
//! server loads it during startup — the key never has to pass through the
//! model's context to bring a wallet back after a restart.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

/// Env var: directory generated-key backups are written into.
pub const KEYSTORE_DIR_ENV: &str = "PSY_MCP_KEYSTORE_DIR";
/// Env var: a single key-backup file to auto-load at startup.
pub const KEY_FILE_ENV: &str = "PSY_MCP_KEY_FILE";

const DEFAULT_DIR_NAME: &str = ".psy-mcp-keys";

/// On-disk format of one key backup. `private_key` is the QHashOut hex string
/// `WalletSession` parses; keep field names stable — files written by older
/// builds must stay loadable forever (they may guard real funds).
#[derive(Serialize, Deserialize)]
pub struct KeyBackup {
    /// Format marker for forward compatibility.
    pub kind: String,
    /// The wallet private key (QHashOut hex). SECRET.
    pub private_key: String,
    /// Public fingerprint of the key (safe to display).
    pub fingerprint: String,
    /// Unix seconds when the backup was written.
    pub created_at: u64,
    /// The mandate this key was minted under, when it is an agent account.
    ///
    /// Without it a minted account can never be reloaded: its identity comes
    /// from the software-defined CIRCUIT, and rebuilding that circuit needs the
    /// contract ids, method ids and calls-per-transaction — the fingerprint
    /// alone is not enough to re-register it. Optional and skipped when absent
    /// so every existing backup keeps loading unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate: Option<crate::agent_account::Mandate>,
}

impl KeyBackup {
    pub const KIND: &'static str = "psy-wallet-key-v1";
}

/// Resolve the keystore directory: `$PSY_MCP_KEYSTORE_DIR`, else
/// `$HOME/.psy-mcp-keys`, else `./.psy-mcp-keys`. Creation is deferred to the
/// first write so a read-only deployment that never generates keys never
/// touches the filesystem.
pub fn keystore_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(KEYSTORE_DIR_ENV) {
        if !dir.trim().is_empty() {
            return PathBuf::from(dir);
        }
    }
    match std::env::var("HOME") {
        Ok(home) if !home.trim().is_empty() => Path::new(&home).join(DEFAULT_DIR_NAME),
        _ => PathBuf::from(DEFAULT_DIR_NAME),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Restrict a path to its owner. Files get 0600; directories need the execute
/// bit to stay traversable, so they get 0700. Best-effort no-op off unix.
fn restrict_permissions(path: &Path, mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to set {mode:o} on {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode); // Windows ACLs default to the owning user for new files.
    }
    Ok(())
}

/// Durably write a key backup and return its path.
///
/// Write strategy: temp file in the SAME directory (rename must not cross a
/// filesystem) → restrict perms → write → fsync → rename to the final name →
/// fsync the directory so the rename itself is durable. The final file never
/// exists in a partially-written state.
pub fn persist_generated_key(private_key_hex: &str, fingerprint_hex: &str) -> Result<PathBuf> {
    persist_generated_key_with_mandate(private_key_hex, fingerprint_hex, None)
}

/// As `persist_generated_key`, but also records the mandate for an agent
/// account so the wallet can be restored after a restart.
pub fn persist_generated_key_with_mandate(
    private_key_hex: &str,
    fingerprint_hex: &str,
    mandate: Option<&crate::agent_account::Mandate>,
) -> Result<PathBuf> {
    let dir = keystore_dir();
    fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create keystore dir {}", dir.display()))?;
    restrict_permissions(&dir, 0o700).ok(); // dir perms are best-effort; file perms are enforced

    // Short fingerprint prefix + timestamp keeps names unique, meaningful, and
    // free of any secret material.
    let fp_short: String = fingerprint_hex.chars().filter(char::is_ascii_alphanumeric).take(12).collect();
    let final_path = dir.join(format!("wallet-{}-{}.json", fp_short, now_secs()));
    if final_path.exists() {
        // Same fingerprint + same second — astronomically unlikely, but never
        // overwrite something that could be guarding funds.
        return Err(anyhow!("key backup {} already exists; refusing to overwrite", final_path.display()));
    }
    let tmp_path = dir.join(format!(".tmp-{}", rand_suffix()));

    let backup = KeyBackup {
        kind: KeyBackup::KIND.to_string(),
        private_key: private_key_hex.to_string(),
        fingerprint: fingerprint_hex.to_string(),
        created_at: now_secs(),
        mandate: mandate.cloned(),
    };
    let json = serde_json::to_string_pretty(&backup).context("failed to serialize key backup")?;

    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("failed to create {}", tmp_path.display()))?;
    // Perms BEFORE the secret hits the file.
    restrict_permissions(&tmp_path, 0o600)?;
    let write_result = (|| -> Result<()> {
        file.write_all(json.as_bytes()).context("failed to write key backup")?;
        file.sync_all().context("failed to fsync key backup")?;
        Ok(())
    })();
    if let Err(e) = write_result {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(file);

    if let Err(e) = fs::rename(&tmp_path, &final_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(anyhow!(e)).with_context(|| format!("failed to finalize key backup {}", final_path.display()));
    }
    // Make the rename durable.
    if let Ok(dir_handle) = fs::File::open(&dir) {
        let _ = dir_handle.sync_all();
    }
    Ok(final_path)
}

fn rand_suffix() -> String {
    use rand::RngCore;
    let mut b = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// Load a key backup file (the `PSY_MCP_KEY_FILE` startup path).
pub fn load_key_file(path: &str) -> Result<KeyBackup> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read key file {path}"))?;
    let backup: KeyBackup =
        serde_json::from_str(&raw).with_context(|| format!("key file {path} is not a valid backup"))?;
    if backup.kind != KeyBackup::KIND {
        return Err(anyhow!("key file {path} has kind `{}` (expected `{}`)", backup.kind, KeyBackup::KIND));
    }
    if backup.private_key.trim().is_empty() {
        return Err(anyhow!("key file {path} has an empty private_key"));
    }
    Ok(backup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_temp_keystore<T>(f: impl FnOnce() -> T) -> T {
        // Serialize env mutation across tests in this module.
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        // A panicking sibling test must not cascade poison-failures here.
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("psy-mcp-keystore-test-{}", rand_suffix()));
        std::env::set_var(KEYSTORE_DIR_ENV, &dir);
        let out = f();
        std::env::remove_var(KEYSTORE_DIR_ENV);
        let _ = fs::remove_dir_all(&dir);
        out
    }

    #[test]
    fn persist_then_load_round_trips_the_key() {
        with_temp_keystore(|| {
            let path = persist_generated_key("0xdeadbeef:1:2:3", "fp0123456789abcdef").unwrap();
            assert!(path.exists());
            let loaded = load_key_file(path.to_str().unwrap()).unwrap();
            assert_eq!(loaded.private_key, "0xdeadbeef:1:2:3");
            assert_eq!(loaded.fingerprint, "fp0123456789abcdef");
            assert_eq!(loaded.kind, KeyBackup::KIND);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "key file must be owner-only");
            }
        })
    }

    #[test]
    fn load_rejects_wrong_kind() {
        with_temp_keystore(|| {
            let dir = keystore_dir();
            fs::create_dir_all(&dir).unwrap();
            let path = dir.join("bad.json");
            fs::write(&path, r#"{"kind":"other","private_key":"x","fingerprint":"y","created_at":0}"#).unwrap();
            assert!(load_key_file(path.to_str().unwrap()).is_err());
        })
    }

    #[test]
    fn no_secret_material_in_filename() {
        with_temp_keystore(|| {
            let secret = "aaaabbbbccccdddd:1:2:3";
            let path = persist_generated_key(secret, "fpfingerprint").unwrap();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            assert!(!name.contains("aaaabbbb"), "filename must not embed key material");
        })
    }
}
