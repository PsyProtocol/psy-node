use crate::config::node_start_config::{
    CoordinatorEdgeStartConfig, CoordinatorProcessorStartConfig, RealmEdgeStartConfig,
    RealmProcessorStartConfig,
};
use psy_core::constants::chain_id::PsyNetworkTypeInput;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub async fn load_cli_config_from_file<T: DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let text = tokio::fs::read_to_string(path).await?;
    if path.ends_with(".yaml") || path.ends_with(".yml") {
        Ok(serde_yaml::from_str(&text)?)
    } else if path.ends_with(".json") {
        Ok(serde_json::from_str(&text)?)
    } else {
        anyhow::bail!("config file must be .yaml, .yml, or .json")
    }
}

pub async fn save_cli_config_to_file<T: Serialize>(
    path: &str,
    config: &T,
) -> anyhow::Result<()> {
    let content = if path.ends_with(".yaml") || path.ends_with(".yml") {
        serde_yaml::to_string(config)?
    } else if path.ends_with(".json") {
        serde_json::to_string_pretty(config)?
    } else {
        anyhow::bail!("config file must be .yaml, .yml, or .json")
    };
    tokio::fs::write(path, content).await?;
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RealmProcessorCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub realm_id: Option<u64>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub checkpoint_backup_path: Option<String>,
    #[serde(default)]
    pub coordinator_api_urls: Vec<String>,
    pub genesis_data_path: Option<String>,
    pub p2p_identity_key_path: Option<String>,
    pub p2p_bls_key_path: Option<String>,
    pub p2p_listen: Option<String>,
}

impl RealmProcessorCliConfig {
    #[allow(clippy::too_many_arguments)]
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        checkpoint_backup_path: Option<String>,
        coordinator_api_urls: Vec<String>,
        genesis_data_path: Option<String>,
        p2p_identity_key_path: Option<String>,
        p2p_bls_key_path: Option<String>,
        p2p_listen: Option<String>,
    ) -> anyhow::Result<RealmProcessorStartConfig> {
        let base = if let Some(path) = config {
            load_cli_config_from_file(&path).await?
        } else {
            Self::default()
        };

        Ok(RealmProcessorStartConfig {
            scylla_db_url: scylla_db_url
                .or(base.scylla_db_url)
                .ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url
                .or(base.nats_jetstream_url)
                .ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url
                .or(base.redis_url)
                .ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace
                .or(base.db_namespace)
                .ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            realm_id: realm_id
                .or(base.realm_id)
                .ok_or_else(|| anyhow::anyhow!("realm_id is required"))?,
            realm_sub_id: 0,
            network: network
                .or(base.network)
                .ok_or_else(|| anyhow::anyhow!("network is required"))?
                .into(),
            verbose: verbose || base.verbose.unwrap_or(false),
            checkpoint_backup_path: checkpoint_backup_path
                .or(base.checkpoint_backup_path)
                .ok_or_else(|| anyhow::anyhow!("checkpoint_backup_path is required"))?,
            coordinator_api_urls: if coordinator_api_urls.is_empty() {
                base.coordinator_api_urls
            } else {
                coordinator_api_urls
            },
            genesis_data_path: genesis_data_path.or(base.genesis_data_path),
            p2p_identity_key_path: p2p_identity_key_path.or(base.p2p_identity_key_path),
            p2p_bls_key_path: p2p_bls_key_path.or(base.p2p_bls_key_path),
            p2p_listen: p2p_listen.or(base.p2p_listen),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RealmEdgeCliConfig {
    pub scylla_db_url: Option<String>,
    pub nats_jetstream_url: Option<String>,
    pub redis_url: Option<String>,
    pub db_namespace: Option<String>,
    pub realm_id: Option<u64>,
    pub network: Option<PsyNetworkTypeInput>,
    pub verbose: Option<bool>,
    pub port: Option<u16>,
    pub listen: Option<String>,
    pub worker_whitelist_config: Option<String>,
    pub p2p_identity_key_path: Option<String>,
    pub p2p_listen: Option<String>,
}

impl RealmEdgeCliConfig {
    #[allow(clippy::too_many_arguments)]
    pub async fn get_start_config(
        config: Option<String>,
        scylla_db_url: Option<String>,
        nats_jetstream_url: Option<String>,
        redis_url: Option<String>,
        db_namespace: Option<String>,
        realm_id: Option<u64>,
        network: Option<PsyNetworkTypeInput>,
        verbose: bool,
        port: Option<u16>,
        listen: Option<String>,
        worker_whitelist_config: Option<String>,
        p2p_identity_key_path: Option<String>,
        p2p_listen: Option<String>,
    ) -> anyhow::Result<RealmEdgeStartConfig> {
        let base = if let Some(path) = config {
            load_cli_config_from_file(&path).await?
        } else {
            Self::default()
        };

        Ok(RealmEdgeStartConfig {
            scylla_db_url: scylla_db_url
                .or(base.scylla_db_url)
                .ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url
                .or(base.nats_jetstream_url)
                .ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url
                .or(base.redis_url)
                .ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace
                .or(base.db_namespace)
                .ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            realm_id: realm_id
                .or(base.realm_id)
                .ok_or_else(|| anyhow::anyhow!("realm_id is required"))?,
            realm_sub_id: 0,
            network: network
                .or(base.network)
                .ok_or_else(|| anyhow::anyhow!("network is required"))?
                .into(),
            verbose: verbose || base.verbose.unwrap_or(false),
            port: port.or(base.port).unwrap_or(8080),
            listen: listen.or(base.listen).unwrap_or_else(|| "0.0.0.0".into()),
            worker_whitelist_config: worker_whitelist_config
                .or(base.worker_whitelist_config)
                .unwrap_or_else(|| "psy-genesis/config.json".into()),
            p2p_identity_key_path: p2p_identity_key_path.or(base.p2p_identity_key_path),
            p2p_listen: p2p_listen.or(base.p2p_listen),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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
    #[allow(clippy::too_many_arguments)]
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
        let base = if let Some(path) = config {
            load_cli_config_from_file(&path).await?
        } else {
            Self::default()
        };

        Ok(CoordinatorProcessorStartConfig {
            scylla_db_url: scylla_db_url
                .or(base.scylla_db_url)
                .ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url
                .or(base.nats_jetstream_url)
                .ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url
                .or(base.redis_url)
                .ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace
                .or(base.db_namespace)
                .ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            coordinator_id: coordinator_id
                .or(base.coordinator_id)
                .ok_or_else(|| anyhow::anyhow!("coordinator_id is required"))?,
            coordinator_sub_id: coordinator_sub_id
                .or(base.coordinator_sub_id)
                .ok_or_else(|| anyhow::anyhow!("coordinator_sub_id is required"))?,
            network: network
                .or(base.network)
                .ok_or_else(|| anyhow::anyhow!("network is required"))?
                .into(),
            verbose: verbose || base.verbose.unwrap_or(false),
            checkpoint_backup_path: checkpoint_backup_path
                .or(base.checkpoint_backup_path)
                .ok_or_else(|| anyhow::anyhow!("checkpoint_backup_path is required"))?,
            genesis_data_path: genesis_data_path.or(base.genesis_data_path),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
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
    #[allow(clippy::too_many_arguments)]
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
        let base = if let Some(path) = config {
            load_cli_config_from_file(&path).await?
        } else {
            Self::default()
        };

        Ok(CoordinatorEdgeStartConfig {
            scylla_db_url: scylla_db_url
                .or(base.scylla_db_url)
                .ok_or_else(|| anyhow::anyhow!("scylla_db_url is required"))?,
            nats_jetstream_url: nats_jetstream_url
                .or(base.nats_jetstream_url)
                .ok_or_else(|| anyhow::anyhow!("nats_jetstream_url is required"))?,
            redis_url: redis_url
                .or(base.redis_url)
                .ok_or_else(|| anyhow::anyhow!("redis_url is required"))?,
            db_namespace: db_namespace
                .or(base.db_namespace)
                .ok_or_else(|| anyhow::anyhow!("db_namespace is required"))?,
            coordinator_id: coordinator_id
                .or(base.coordinator_id)
                .ok_or_else(|| anyhow::anyhow!("coordinator_id is required"))?,
            coordinator_sub_id: coordinator_sub_id
                .or(base.coordinator_sub_id)
                .ok_or_else(|| anyhow::anyhow!("coordinator_sub_id is required"))?,
            network: network
                .or(base.network)
                .ok_or_else(|| anyhow::anyhow!("network is required"))?
                .into(),
            verbose: verbose || base.verbose.unwrap_or(false),
            port: port.or(base.port).unwrap_or(8080),
            listen: listen.or(base.listen).unwrap_or_else(|| "0.0.0.0".into()),
            worker_whitelist_config: worker_whitelist_config
                .or(base.worker_whitelist_config)
                .unwrap_or_else(|| "psy-genesis/config.json".into()),
        })
    }
}
