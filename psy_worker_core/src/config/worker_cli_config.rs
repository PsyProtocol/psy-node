use psy_core::constants::chain_id::PsyNetworkTypeInput;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkerCliConfig {
    pub user: Option<u64>,
    pub completed_jobs_log_file: Option<String>,
    pub network: Option<PsyNetworkTypeInput>,
    pub private_key: Option<String>,
    pub coordinator_api_urls: Vec<String>,
    pub realm_api_urls: Vec<String>,
}

impl WorkerCliConfig {
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
