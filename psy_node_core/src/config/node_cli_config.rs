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
    #[serde(default)]
    pub p2p_identity_key_path: Option<String>,
    #[serde(default)]
    pub p2p_bls_key_path: Option<String>,
    #[serde(default)]
    pub p2p_listen: Option<String>,
    #[serde(default)]
    pub p2p_bootnodes: Vec<String>,
    #[serde(default)]
    pub p2p_coordinator: Option<String>,
    #[serde(default)]
    pub p2p_validator_sub_ids: Vec<u16>,
    #[serde(default)]
    pub p2p_checkpoints_per_epoch: Option<u64>,
    #[serde(default)]
    pub p2p_proposer_node_ids: Vec<String>,
    #[serde(default)]
    pub p2p_validator_user_id: Option<u64>,
    #[serde(default)]
    pub p2p_roster_path: Option<String>,
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
            p2p_identity_key_path: None,
            p2p_bls_key_path: None,
            p2p_listen: None,
            p2p_bootnodes: Vec::new(),
            p2p_coordinator: None,
            p2p_validator_sub_ids: Vec::new(),
            p2p_checkpoints_per_epoch: None,
            p2p_proposer_node_ids: Vec::new(),
            p2p_validator_user_id: None,
            p2p_roster_path: None,
        }
    }
    #[allow(clippy::too_many_arguments)]
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
        p2p_identity_key_path: Option<String>,
        p2p_bls_key_path: Option<String>,
        p2p_listen: Option<String>,
        p2p_bootnodes: Vec<String>,
        p2p_coordinator: Option<String>,
        p2p_validator_sub_ids: Vec<u16>,
        p2p_checkpoints_per_epoch: Option<u64>,
        p2p_proposer_node_ids: Vec<String>,
        p2p_validator_user_id: Option<u64>,
        p2p_roster_path: Option<String>,
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
            p2p_identity_key_path: p2p_identity_key_path.or(self.p2p_identity_key_path),
            p2p_bls_key_path: p2p_bls_key_path.or(self.p2p_bls_key_path),
            p2p_listen: p2p_listen.or(self.p2p_listen),
            p2p_bootnodes: if !p2p_bootnodes.is_empty() { p2p_bootnodes } else { self.p2p_bootnodes },
            p2p_coordinator: p2p_coordinator.or(self.p2p_coordinator),
            p2p_validator_sub_ids: if !p2p_validator_sub_ids.is_empty() { p2p_validator_sub_ids } else { self.p2p_validator_sub_ids },
            p2p_checkpoints_per_epoch: p2p_checkpoints_per_epoch.or(self.p2p_checkpoints_per_epoch),
            p2p_proposer_node_ids: if !p2p_proposer_node_ids.is_empty() { p2p_proposer_node_ids } else { self.p2p_proposer_node_ids },
            p2p_validator_user_id: p2p_validator_user_id.or(self.p2p_validator_user_id),
            p2p_roster_path: p2p_roster_path.or(self.p2p_roster_path),
        })
    }
    #[allow(clippy::too_many_arguments)]
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
        p2p_identity_key_path: Option<String>,
        p2p_bls_key_path: Option<String>,
        p2p_listen: Option<String>,
        p2p_bootnodes: Vec<String>,
        p2p_coordinator: Option<String>,
        p2p_validator_sub_ids: Vec<u16>,
        p2p_checkpoints_per_epoch: Option<u64>,
        p2p_proposer_node_ids: Vec<String>,
        p2p_validator_user_id: Option<u64>,
        p2p_roster_path: Option<String>,
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
            p2p_identity_key_path,
            p2p_bls_key_path,
            p2p_listen,
            p2p_bootnodes,
            p2p_coordinator,
            p2p_validator_sub_ids,
            p2p_checkpoints_per_epoch,
            p2p_proposer_node_ids,
            p2p_validator_user_id,
            p2p_roster_path,
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
    #[serde(default)]
    pub p2p_identity_key_path: Option<String>,
    #[serde(default)]
    pub p2p_bls_key_path: Option<String>,
    #[serde(default)]
    pub p2p_listen: Option<String>,
    #[serde(default)]
    pub p2p_bootnodes: Vec<String>,
    #[serde(default)]
    pub p2p_coordinator: Option<String>,
    #[serde(default)]
    pub p2p_validator_sub_ids: Vec<u16>,
    #[serde(default)]
    pub p2p_checkpoints_per_epoch: Option<u64>,
    #[serde(default)]
    pub p2p_proposer_node_ids: Vec<String>,
    #[serde(default)]
    pub p2p_validator_user_id: Option<u64>,
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
            p2p_identity_key_path: None,
            p2p_bls_key_path: None,
            p2p_listen: None,
            p2p_bootnodes: Vec::new(),
            p2p_coordinator: None,
            p2p_validator_sub_ids: Vec::new(),
            p2p_checkpoints_per_epoch: None,
            p2p_proposer_node_ids: Vec::new(),
            p2p_validator_user_id: None,
        }
    }
    #[allow(clippy::too_many_arguments)]
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
        p2p_identity_key_path: Option<String>,
        p2p_bls_key_path: Option<String>,
        p2p_listen: Option<String>,
        p2p_bootnodes: Vec<String>,
        p2p_coordinator: Option<String>,
        p2p_validator_sub_ids: Vec<u16>,
        p2p_checkpoints_per_epoch: Option<u64>,
        p2p_proposer_node_ids: Vec<String>,
        p2p_validator_user_id: Option<u64>,
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
            p2p_identity_key_path: p2p_identity_key_path.or(self.p2p_identity_key_path),
            p2p_bls_key_path: p2p_bls_key_path.or(self.p2p_bls_key_path),
            p2p_listen: p2p_listen.or(self.p2p_listen),
            p2p_bootnodes: if !p2p_bootnodes.is_empty() { p2p_bootnodes } else { self.p2p_bootnodes },
            p2p_coordinator: p2p_coordinator.or(self.p2p_coordinator),
            p2p_validator_sub_ids: if !p2p_validator_sub_ids.is_empty() { p2p_validator_sub_ids } else { self.p2p_validator_sub_ids },
            p2p_checkpoints_per_epoch: p2p_checkpoints_per_epoch.or(self.p2p_checkpoints_per_epoch),
            p2p_proposer_node_ids: if !p2p_proposer_node_ids.is_empty() { p2p_proposer_node_ids } else { self.p2p_proposer_node_ids },
            p2p_validator_user_id: p2p_validator_user_id.or(self.p2p_validator_user_id),
        })
    }
    #[allow(clippy::too_many_arguments)]
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
        p2p_identity_key_path: Option<String>,
        p2p_bls_key_path: Option<String>,
        p2p_listen: Option<String>,
        p2p_bootnodes: Vec<String>,
        p2p_coordinator: Option<String>,
        p2p_validator_sub_ids: Vec<u16>,
        p2p_checkpoints_per_epoch: Option<u64>,
        p2p_proposer_node_ids: Vec<String>,
        p2p_validator_user_id: Option<u64>,
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
            p2p_identity_key_path,
            p2p_bls_key_path,
            p2p_listen,
            p2p_bootnodes,
            p2p_coordinator,
            p2p_validator_sub_ids,
            p2p_checkpoints_per_epoch,
            p2p_proposer_node_ids,
            p2p_validator_user_id,
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
    #[serde(default)]
    pub p2p_roster_path: Option<String>,
    #[serde(default)]
    pub p2p_checkpoints_per_epoch: Option<u64>,
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
            p2p_roster_path: None,
            p2p_checkpoints_per_epoch: None,
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
        p2p_roster_path: Option<String>,
        p2p_checkpoints_per_epoch: Option<u64>,
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
            p2p_roster_path: p2p_roster_path.or(self.p2p_roster_path),
            p2p_checkpoints_per_epoch: p2p_checkpoints_per_epoch.or(self.p2p_checkpoints_per_epoch),
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
        p2p_roster_path: Option<String>,
        p2p_checkpoints_per_epoch: Option<u64>,
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
            p2p_roster_path,
            p2p_checkpoints_per_epoch,
        )
    }
}