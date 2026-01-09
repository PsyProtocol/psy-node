use cf_utils::option::resolve_one_of_two_hex_32_byte_options_or_error;
use psy_core::constants::{chain_id::PsyNetworkTypeInput, url_rotation::PsyAPIURLRotationStrategyInput};
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
        user: Option<u64>,
        network: Option<PsyNetworkTypeInput>,
        completed_jobs_log_file: Option<String>,
        coordinator_api_urls: Vec<String>,
        realm_api_urls: Vec<String>,
        url_rotation_strategy: PsyAPIURLRotationStrategyInput,
    ) -> anyhow::Result<WorkerStartupConfig> {
        Ok(WorkerStartupConfig {
            private_key: resolve_one_of_two_hex_32_byte_options_or_error(
                private_key,
                self.private_key,
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
        _keystore_path: Option<String>,
        _wallet_password: Option<String>,
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
}
