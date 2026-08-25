use psy_core::constants::chain_id::PsyNetworkTypeInput;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::config::node_start_config::{CoordinatorEdgeStartConfig, CoordinatorProcessorStartConfig, RealmEdgeStartConfig, RealmProcessorStartConfig};


pub async fn load_cli_config_from_file<T: DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let is_yaml = path.ends_with(".yaml") || path.ends_with(".yml");
    let is_json = path.ends_with(".json");
    if !is_yaml && !is_json {
        anyhow::bail!("config file must be .yaml, .yml, or .json");
    }
    let file_content = tokio::fs::read_to_string(path).await?;
    if is_yaml {
        serde_yaml::from_str(&file_content).map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))
    } else {
        serde_json::from_str(&file_content).map_err(|e| anyhow::anyhow!("Failed to parse config file: {}", e))
    }
}

pub async fn save_cli_config_to_file<T: Serialize>(path: &str, config: &T) -> anyhow::Result<()> {
    let is_yaml = path.ends_with(".yaml") || path.ends_with(".yml");
    let is_json = path.ends_with(".json");
    if !is_yaml && !is_json {
        anyhow::bail!("config file must be .yaml, .yml, or .json");
    }
    let content = if is_yaml {
        serde_yaml::to_string(config)?
    } else {
        serde_json::to_string_pretty(config)?
    };
    tokio::fs::write(path, content).await?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmProcessorCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub realm_id: Option<u64>,
    pub realm_sub_id: Option<u16>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub checkpoint_backup_path: Option<String>,
    pub coordinator_api_urls: Vec<String>,
    pub genesis_data_path: Option<String>,
}
impl RealmProcessorCliConfig {
    pub fn get_default_empty() -> Self {
        RealmProcessorCliConfig {
            scylla_db_url: None,
            nats_jetstream_url: None,
            redis_url: None,
            db_namespace: None,
            realm_id: None,
            realm_sub_id: None,
            network: None,
            verbose: None,
            checkpoint_backup_path: None,
            coordinator_api_urls: Vec::new(),
            genesis_data_path: None,
        }
    }
    pub fn into_start_config_with_cli_args(
        self,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        realm_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        checkpoint_backup_path: Option<String>,
        coordinator_api_urls: Vec<String>,
        genesis_data_path: Option<String>,
    ) -> anyhow::Result<RealmProcessorStartConfig> {
        Ok(RealmProcessorStartConfig {
            scylla_db_url: scylla_db_url.or(self.scylla_db_url).ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url.or(self.nats_jetstream_url).ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url.or(self.redis_url).ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace.or(self.db_namespace).ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            realm_id: realm_id.or(self.realm_id).ok_or_else(|| anyhow::anyhow!("realm_id is required"))?,
            realm_sub_id: realm_sub_id.or(self.realm_sub_id).ok_or_else(|| anyhow::anyhow!("realm_sub_id is required"))?,
            network: network.or(self.network).ok_or_else(|| anyhow::anyhow!("network is required"))?.into(),
            verbose: verbose || self.verbose.unwrap_or(false),
            checkpoint_backup_path: checkpoint_backup_path.or(self.checkpoint_backup_path).ok_or_else(|| anyhow::anyhow!("checkpoint_backup_path is required"))?,
            coordinator_api_urls: if !coordinator_api_urls.is_empty() { coordinator_api_urls } else { self.coordinator_api_urls },
            genesis_data_path: genesis_data_path.or(self.genesis_data_path),
        })
    }
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        realm_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        checkpoint_backup_path: Option<String>,
        coordinator_api_urls: Vec<String>,
        genesis_data_path: Option<String>,
    ) -> anyhow::Result<RealmProcessorStartConfig> {
        let cli_config = if let Some(config_path) = config {
            load_cli_config_from_file::<Self>(&config_path).await?
        } else {
            Self::get_default_empty()
        };
        cli_config.into_start_config_with_cli_args(
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            realm_id,
            realm_sub_id,
            network,
            verbose,
            checkpoint_backup_path,
            coordinator_api_urls,
            genesis_data_path,
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmEdgeCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub realm_id: Option<u64>,
    pub realm_sub_id: Option<u16>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub port: Option<u16>,
    pub listen: Option<String>,
    pub worker_whitelist_config: Option<String>,
}

impl RealmEdgeCliConfig {
    pub fn get_default_empty() -> Self {
        RealmEdgeCliConfig {
            scylla_db_url: None,
            nats_jetstream_url: None,
            redis_url: None,
            db_namespace: None,
            realm_id: None,
            realm_sub_id: None,
            network: None,
            verbose: None,
            port: None,
            listen: None,
            worker_whitelist_config: None,
        }
    }
    pub fn into_start_config_with_cli_args(
        self,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        realm_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        port: Option<u16>,
        listen: Option<String>,
        worker_whitelist_config: Option<String>,
    ) -> anyhow::Result<RealmEdgeStartConfig> {
        Ok(RealmEdgeStartConfig {
            scylla_db_url: scylla_db_url.or(self.scylla_db_url).ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url.or(self.nats_jetstream_url).ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url.or(self.redis_url).ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace.or(self.db_namespace).ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            realm_id: realm_id.or(self.realm_id).ok_or_else(|| anyhow::anyhow!("realm_id is required"))?,
            realm_sub_id: realm_sub_id.or(self.realm_sub_id).ok_or_else(|| anyhow::anyhow!("realm_sub_id is required"))?,
            network: network.or(self.network).ok_or_else(|| anyhow::anyhow!("network is required"))?.into(),
            verbose: verbose || self.verbose.unwrap_or(false),
            port: port.or(self.port).unwrap_or(8080),
            listen: listen.or(self.listen).unwrap_or_else(|| "0.0.0.0".to_string()),
            worker_whitelist_config: worker_whitelist_config.or(self.worker_whitelist_config).unwrap_or_else(|| "psy-genesis/config.json".to_string()),
        })
    }
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        realm_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        port: Option<u16>,
        listen: Option<String>,
        worker_whitelist_config: Option<String>,
    ) -> anyhow::Result<RealmEdgeStartConfig> {
        let cli_config = if let Some(config_path) = config {
            load_cli_config_from_file::<Self>(&config_path).await?
        } else {
            Self::get_default_empty()
        };
        cli_config.into_start_config_with_cli_args(
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            realm_id,
            realm_sub_id,
            network,
            verbose,
            port,
            listen,
            worker_whitelist_config,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorProcessorCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub coordinator_id: Option<u64>,
    pub coordinator_sub_id: Option<u16>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub checkpoint_backup_path: Option<String>,
    pub genesis_data_path: Option<String>,
}
impl CoordinatorProcessorCliConfig {
    pub fn get_default_empty() -> Self {
        CoordinatorProcessorCliConfig {
            scylla_db_url: None,
            nats_jetstream_url: None,
            redis_url: None,
            db_namespace: None,
            coordinator_id: None,
            coordinator_sub_id: None,
            network: None,
            verbose: None,
            checkpoint_backup_path: None,
            genesis_data_path: None,
        }
    }
    pub fn into_start_config_with_cli_args(
        self,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        coordinator_id: Option<u64>,
        coordinator_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        checkpoint_backup_path: Option<String>,
        genesis_data_path: Option<String>,
    ) -> anyhow::Result<CoordinatorProcessorStartConfig> {
        Ok(CoordinatorProcessorStartConfig {
            scylla_db_url: scylla_db_url.or(self.scylla_db_url).ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url.or(self.nats_jetstream_url).ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url.or(self.redis_url).ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace.or(self.db_namespace).ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            coordinator_id: coordinator_id.or(self.coordinator_id).ok_or_else(|| anyhow::anyhow!("coordinator_id is required"))?,
            coordinator_sub_id: coordinator_sub_id.or(self.coordinator_sub_id).ok_or_else(|| anyhow::anyhow!("coordinator_sub_id is required"))?,
            network: network.or(self.network).ok_or_else(|| anyhow::anyhow!("network is required"))?.into(),
            verbose: verbose || self.verbose.unwrap_or(false),
            checkpoint_backup_path: checkpoint_backup_path.or(self.checkpoint_backup_path).ok_or_else(|| anyhow::anyhow!("checkpoint_backup_path is required"))?,
            genesis_data_path: genesis_data_path.or(self.genesis_data_path),
        })
    }
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        coordinator_id: Option<u64>,
        coordinator_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        checkpoint_backup_path: Option<String>,
        genesis_data_path: Option<String>,
    ) -> anyhow::Result<CoordinatorProcessorStartConfig> {
        let cli_config = if let Some(config_path) = config {
            load_cli_config_from_file::<Self>(&config_path).await?
        } else {
            Self::get_default_empty()
        };
        cli_config.into_start_config_with_cli_args(
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            coordinator_id,
            coordinator_sub_id,
            network,
            verbose,
            checkpoint_backup_path,
            genesis_data_path,
        )
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorEdgeCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub coordinator_id: Option<u64>,
    pub coordinator_sub_id: Option<u16>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub port: Option<u16>,
    pub listen: Option<String>,
    pub worker_whitelist_config: Option<String>,
}

impl CoordinatorEdgeCliConfig {
    pub fn get_default_empty() -> Self {
        CoordinatorEdgeCliConfig {
            scylla_db_url: None,
            nats_jetstream_url: None,
            redis_url: None,
            db_namespace: None,
            coordinator_id: None,
            coordinator_sub_id: None,
            network: None,
            verbose: None,
            port: None,
            listen: None,
            worker_whitelist_config: None,
        }
    }
    pub fn into_start_config_with_cli_args(
        self,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        coordinator_id: Option<u64>,
        coordinator_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        port: Option<u16>,
        listen: Option<String>,
        worker_whitelist_config: Option<String>,
    ) -> anyhow::Result<CoordinatorEdgeStartConfig> {
        Ok(CoordinatorEdgeStartConfig {
            scylla_db_url: scylla_db_url.or(self.scylla_db_url).ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url.or(self.nats_jetstream_url).ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url.or(self.redis_url).ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace.or(self.db_namespace).ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            coordinator_id: coordinator_id.or(self.coordinator_id).ok_or_else(|| anyhow::anyhow!("coordinator_id is required"))?,
            coordinator_sub_id: coordinator_sub_id.or(self.coordinator_sub_id).ok_or_else(|| anyhow::anyhow!("coordinator_sub_id is required"))?,
            network: network.or(self.network).ok_or_else(|| anyhow::anyhow!("network is required"))?.into(),
            verbose: verbose || self.verbose.unwrap_or(false),
            port: port.or(self.port).unwrap_or(8080),
            listen: listen.or(self.listen).unwrap_or_else(|| "0.0.0.0".to_string()),
            worker_whitelist_config: worker_whitelist_config.or(self.worker_whitelist_config).unwrap_or_else(|| "psy-genesis/config.json".to_string()),
        })
    }
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        coordinator_id: Option<u64>,
        coordinator_sub_id: Option<u16>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        port: Option<u16>,
        listen: Option<String>,
        worker_whitelist_config: Option<String>,
    ) -> anyhow::Result<CoordinatorEdgeStartConfig> {
        let cli_config = if let Some(config_path) = config {
            load_cli_config_from_file::<Self>(&config_path).await?
        } else {
            Self::get_default_empty()
        };
        cli_config.into_start_config_with_cli_args(
            scylla_db_url,
            nats_jetstream_url,
            redis_url,
            db_namespace,
            coordinator_id,
            coordinator_sub_id,
            network,
            verbose,
            port,
            listen,
            worker_whitelist_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_core::constants::chain_id::PsyNetworkTypeInput;

    const DEFAULT_WHITELIST_PATH: &str = "psy-genesis/config.json";

    fn realm_edge_config(whitelist: Option<String>) -> RealmEdgeCliConfig {
        RealmEdgeCliConfig {
            worker_whitelist_config: whitelist,
            ..RealmEdgeCliConfig::get_default_empty()
        }
    }

    fn coordinator_edge_config(whitelist: Option<String>) -> CoordinatorEdgeCliConfig {
        CoordinatorEdgeCliConfig {
            worker_whitelist_config: whitelist,
            ..CoordinatorEdgeCliConfig::get_default_empty()
        }
    }

    fn realm_edge_start(file: Option<String>, cli: Option<String>) -> RealmEdgeStartConfig {
        realm_edge_config(file)
            .into_start_config_with_cli_args(
                Some("127.0.0.1:9042".to_string()),
                Some("nats://127.0.0.1:4222".to_string()),
                Some("redis://127.0.0.1:6379".to_string()),
                Some("realm0".to_string()),
                Some(0),
                Some(1),
                Some(PsyNetworkTypeInput::LocalDevnet),
                false,
                None,
                None,
                cli,
            )
            .unwrap()
    }

    fn coordinator_edge_start(file: Option<String>, cli: Option<String>) -> CoordinatorEdgeStartConfig {
        coordinator_edge_config(file)
            .into_start_config_with_cli_args(
                Some("127.0.0.1:9042".to_string()),
                Some("nats://127.0.0.1:4222".to_string()),
                Some("redis://127.0.0.1:6379".to_string()),
                Some("coordinator".to_string()),
                Some(0),
                Some(0),
                Some(PsyNetworkTypeInput::LocalDevnet),
                false,
                None,
                None,
                cli,
            )
            .unwrap()
    }

    #[test]
    fn realm_edge_defaults_to_genesis_whitelist_path() {
        let start = realm_edge_start(None, None);
        assert_eq!(start.worker_whitelist_config, DEFAULT_WHITELIST_PATH);
    }

    #[test]
    fn coordinator_edge_defaults_to_genesis_whitelist_path() {
        let start = coordinator_edge_start(None, None);
        assert_eq!(start.worker_whitelist_config, DEFAULT_WHITELIST_PATH);
    }

    #[test]
    fn realm_edge_yaml_override_used_when_cli_absent() {
        let start = realm_edge_start(Some("custom-whitelist.json".to_string()), None);
        assert_eq!(start.worker_whitelist_config, "custom-whitelist.json");
    }

    #[test]
    fn coordinator_edge_yaml_override_used_when_cli_absent() {
        let start = coordinator_edge_start(Some("custom-whitelist.json".to_string()), None);
        assert_eq!(start.worker_whitelist_config, "custom-whitelist.json");
    }

    #[test]
    fn realm_edge_cli_arg_overrides_yaml() {
        let start = realm_edge_start(
            Some("file-whitelist.json".to_string()),
            Some("cli-whitelist.json".to_string()),
        );
        assert_eq!(start.worker_whitelist_config, "cli-whitelist.json");
    }

    #[test]
    fn coordinator_edge_cli_arg_overrides_yaml() {
        let start = coordinator_edge_start(
            Some("file-whitelist.json".to_string()),
            Some("cli-whitelist.json".to_string()),
        );
        assert_eq!(start.worker_whitelist_config, "cli-whitelist.json");
    }

    #[test]
    fn realm_edge_yaml_without_whitelist_field_stays_valid() {
        let yaml = "\
realm_id: 0
realm_sub_id: 1
network: local-devnet
verbose: true
db_namespace: realm0
scylla_db_url: 127.0.0.1:9042
nats_jetstream_url: nats://127.0.0.1:4222
redis_url: redis://127.0.0.1:6379
port: 1338
listen: 0.0.0.0
";
        let config: RealmEdgeCliConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.worker_whitelist_config, None);
    }

    #[test]
    fn coordinator_edge_yaml_without_whitelist_field_stays_valid() {
        let yaml = "\
coordinator_id: 0
coordinator_sub_id: 0
network: local-devnet
verbose: true
db_namespace: coordinator
scylla_db_url: 127.0.0.1:9042
nats_jetstream_url: nats://127.0.0.1:4222
redis_url: redis://127.0.0.1:6379
port: 1337
listen: 0.0.0.0
";
        let config: CoordinatorEdgeCliConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.worker_whitelist_config, None);
    }

    #[test]
    fn edge_configs_share_identical_default_whitelist_semantics() {
        // coordinator/realm parity: identical (file, cli) inputs yield identical whitelist paths
        assert_eq!(
            realm_edge_start(None, None).worker_whitelist_config,
            coordinator_edge_start(None, None).worker_whitelist_config
        );
        assert_eq!(
            realm_edge_start(Some("shared.json".to_string()), None).worker_whitelist_config,
            coordinator_edge_start(Some("shared.json".to_string()), None).worker_whitelist_config
        );
        assert_eq!(
            realm_edge_start(Some("file.json".to_string()), Some("cli.json".to_string())).worker_whitelist_config,
            coordinator_edge_start(Some("file.json".to_string()), Some("cli.json".to_string())).worker_whitelist_config
        );
    }
}