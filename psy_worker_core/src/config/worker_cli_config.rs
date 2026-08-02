use std::path::Path;

use cf_utils::option::resolve_one_of_two_hex_32_byte_options_or_error;
use psy_core::constants::{chain_id::PsyNetworkTypeInput, url_rotation::PsyAPIURLRotationStrategyInput};
use psy_provider::wallet::secp_wallet::Wallet;
use serde::{Deserialize, Serialize};

use crate::config::worker_config::WorkerStartupConfig;


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerCliConfig {
    pub user: Option<u64>,
    pub completed_jobs_log_file: Option<String>,
    pub network: Option<PsyNetworkTypeInput>,
    pub private_key: Option<String>,
    pub coordinator_api_urls: Vec<String>,
    pub realm_api_urls: Vec<String>,
    pub url_rotation_strategy: Option<PsyAPIURLRotationStrategyInput>,
}
fn resolve_one_of_options_or_error<T: Clone>(
    cli_option: Option<T>,
    config_option: Option<T>,
    error_message: &str,
) -> anyhow::Result<T> {
    if let Some(value) = cli_option {
        Ok(value.clone())
    } else if let Some(value) = config_option {
        Ok(value.clone())
    } else {
        anyhow::bail!("{}", error_message);
    }
}

/// Resolve the worker private key from either an encrypted keystore file or a
/// raw hex private key. Keystore takes precedence over `--private-key` when both
/// are provided, mirroring the user CLI behavior in
/// `psy_cli_common::key_utils::load_or_create_key`.
///
/// Returns the private key as a hex string (no `0x` prefix).
fn resolve_private_key(
    keystore_path: Option<&str>,
    wallet_password: Option<&str>,
    private_key_cli: Option<&str>,
    private_key_config: Option<&str>,
) -> anyhow::Result<String> {
    if let Some(path) = keystore_path {
        let wallet = Wallet::load(None, Some(Path::new(path)), wallet_password)
            .map_err(|e| anyhow::anyhow!("failed to load keystore at {}: {}", path, e))?;
        return Ok(wallet.private_key_hex());
    }
    if let Some(pk) = private_key_cli {
        return Ok(pk.to_string());
    }
    if let Some(pk) = private_key_config {
        return Ok(pk.to_string());
    }
    anyhow::bail!(
        "--private-key or --keystore-path is required.\n  \
         --private-key: raw hex private key (insecure, visible in process list)\n  \
         --keystore-path: path to encrypted keystore file (use with --wallet-password)"
    );
}

impl WorkerCliConfig {
    pub fn get_default_empty() -> Self {
        WorkerCliConfig {
            user: None,
            private_key: None,
            completed_jobs_log_file: None,
            network: None,
            coordinator_api_urls: Vec::new(),
            realm_api_urls: Vec::new(),
            url_rotation_strategy: None,
        }
    }
    pub fn into_start_config_with_cli_args(
        self,
        private_key: Option<String>,
        keystore_path: Option<String>,
        wallet_password: Option<String>,
        user: Option<u64>,
        network: Option<PsyNetworkTypeInput>,
        completed_jobs_log_file: Option<String>,
        coordinator_api_urls: Vec<String>,
        realm_api_urls: Vec<String>,
        url_rotation_strategy: PsyAPIURLRotationStrategyInput,
    ) -> anyhow::Result<WorkerStartupConfig> {
        let resolved_private_key = resolve_private_key(
            keystore_path.as_deref(),
            wallet_password.as_deref(),
            private_key.as_deref(),
            self.private_key.as_deref(),
        )?;
        Ok(WorkerStartupConfig {
            private_key: resolve_one_of_two_hex_32_byte_options_or_error(
                Some(resolved_private_key),
                None,
                "API Private key for miner is required",
            )?,
            miner_user_id: resolve_one_of_options_or_error::<u64>(user, self.user, "User ID of miner is required")?,
            network: resolve_one_of_options_or_error::<PsyNetworkTypeInput>(network, self.network, "Network configuration is required")?.into(),
            worker_completed_jobs_log_file_path: completed_jobs_log_file.or(self.completed_jobs_log_file),
            coordinator_api_urls: [coordinator_api_urls, self.coordinator_api_urls].concat(),
            realm_api_urls: [realm_api_urls, self.realm_api_urls].concat(),
            url_rotation_strategy: url_rotation_strategy.into(),
        })
    }
    pub async fn get_start_config(
        config: Option<String>,
        private_key: Option<String>,
        keystore_path: Option<String>,
        wallet_password: Option<String>,
        user: Option<u64>,
        network: Option<PsyNetworkTypeInput>,
        completed_jobs_log_file: Option<String>,
        coordinator_api_urls: Vec<String>,
        realm_api_urls: Vec<String>,
        url_rotation_strategy: PsyAPIURLRotationStrategyInput,
    ) -> anyhow::Result<WorkerStartupConfig> {
        let cli_config = if let Some(config_path) = config {
            Self::load_from_file(&config_path).await?
        } else {
            Self::get_default_empty()
        };
        cli_config.into_start_config_with_cli_args(
            private_key,
            keystore_path,
            wallet_password,
            user,
            network,
            completed_jobs_log_file,
            coordinator_api_urls,
            realm_api_urls,
            url_rotation_strategy,
        )
    }
    pub fn ensure_unique_api_urls(&mut self) {
        let mut unique_coordinator_urls = Vec::new();
        for url in &self.coordinator_api_urls {
            if !unique_coordinator_urls.contains(url) {
                unique_coordinator_urls.push(url.clone());
            }
        }
        self.coordinator_api_urls = unique_coordinator_urls;

        let mut unique_realm_urls = Vec::new();
        for url in &self.realm_api_urls {
            if !unique_realm_urls.contains(url) {
                unique_realm_urls.push(url.clone());
            }
        }
        self.realm_api_urls = unique_realm_urls;
    }
    pub async fn load_from_file(path: &str) -> anyhow::Result<Self> {
        let is_yaml = path.ends_with(".yaml") || path.ends_with(".yml");
        let is_json = path.ends_with(".json");
        if !is_yaml && !is_json {
            anyhow::bail!("config file must be .yaml, .yml, or .json");
        }
        let file_content = tokio::fs::read_to_string(path).await?;
        let mut config: WorkerCliConfig = if is_yaml {
            serde_yaml::from_str(&file_content)?
        } else {
            serde_json::from_str(&file_content)?
        };
        config.ensure_unique_api_urls();
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_worker_cli_config_serialization() {
        let config = WorkerCliConfig {
            user: Some(42),
            private_key: None,
            completed_jobs_log_file: None,
            network: Some(PsyNetworkTypeInput::LocalDevnet),
            coordinator_api_urls: vec!["http://localhost:8000".to_string()],
            realm_api_urls: vec!["http://localhost:9000".to_string()],
            url_rotation_strategy: None,
        };
        let yaml_str = serde_yaml::to_string(&config).unwrap();
        let deserialized_config: WorkerCliConfig = serde_yaml::from_str(&yaml_str).unwrap();
        assert_eq!(config.user, deserialized_config.user);
        assert_eq!(config.network, deserialized_config.network);
        assert_eq!(config.coordinator_api_urls, deserialized_config.coordinator_api_urls);
        assert_eq!(config.realm_api_urls, deserialized_config.realm_api_urls);

        let allowed_ok = r#"
network: psy-mainnet
coordinator_api_urls:
- http://localhost:8000

realm_api_urls:
- http://localhost:9000
        "#;
        let _deserialized_config: WorkerCliConfig = serde_yaml::from_str(&allowed_ok).unwrap();
    }

    #[test]
    fn test_resolve_private_key_requires_one_source() {
        let err = resolve_private_key(None, None, None, None).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("--private-key"), "msg={msg}");
        assert!(msg.contains("--keystore-path"), "msg={msg}");
    }

    #[test]
    fn test_resolve_private_key_accepts_raw_hex() {
        // 32-byte hex of a well-known anvil account 0 private key
        let pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let got = resolve_private_key(None, None, Some(pk), None).unwrap();
        assert_eq!(got, pk);
    }

    #[test]
    fn test_resolve_private_key_accepts_config_fallback() {
        let pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let got = resolve_private_key(None, None, None, Some(pk)).unwrap();
        assert_eq!(got, pk);
    }

    #[test]
    fn test_resolve_private_key_keystore_takes_precedence_over_cli() {
        // If both are set, keystore wins. We can't easily exercise a real
        // keystore here without a fixture, but we can at least assert that a
        // bogus keystore path produces a keystore-load error (not a silent
        // fallback to the raw key).
        let pk = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let err = resolve_private_key(
            Some("/nonexistent/keystore.json"),
            Some("wrongpass"),
            Some(pk),
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to load keystore"), "msg={msg}");
    }

    #[test]
    fn test_resolve_private_key_loads_real_keystore() {
        // End-to-end: create an encrypted keystore with a known password,
        // then resolve the private key back from it. This proves the worker
        // CLI can authenticate from a keystore file the same way psy_user_cli
        // does, instead of requiring a raw --private-key on the command line.
        use psy_provider::wallet::secp_wallet::Wallet as Wallet2;
        use tempfile::tempdir;

        let dir = tempdir().unwrap();
        let keystore_path = dir.path().join("worker-wallet.json");
        let password = "worker-test-password";

        let wallet = Wallet2::new().unwrap();
        wallet.save(&keystore_path, Some(password)).unwrap();
        let expected_pk = wallet.private_key_hex();

        // Keystore path + correct password resolves to the same private key.
        let got = resolve_private_key(
            Some(keystore_path.to_str().expect("tempdir path is valid utf-8")),
            Some(password),
            None,
            None,
        )
        .unwrap();
        assert_eq!(got, expected_pk);

        // Wrong password yields a keystore-load error, not a silent fallback.
        let err = resolve_private_key(
            Some(keystore_path.to_str().expect("tempdir path is valid utf-8")),
            Some("wrong-password"),
            None,
            None,
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("failed to load keystore"), "msg={msg}");
    }
}
