use psy_core::constants::chain_id::PsyChainNetworkType;
use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmProcessorStartConfig {
    pub scylla_db_url: String,
    pub nats_jetstream_url: String,
    pub redis_url: String,
    pub db_namespace: String,
    pub realm_id: u64,
    pub realm_sub_id: u16,
    pub network: PsyChainNetworkType,
    pub verbose: bool,
    pub checkpoint_backup_path: String,
    pub coordinator_api_urls: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RealmEdgeStartConfig {
    pub scylla_db_url: String,
    pub nats_jetstream_url: String,
    pub redis_url: String,
    pub db_namespace: String,
    pub realm_id: u64,
    pub realm_sub_id: u16,
    pub network: PsyChainNetworkType,
    pub verbose: bool,
    pub port: u16,
    pub listen: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorProcessorStartConfig {
    pub scylla_db_url: String,
    pub nats_jetstream_url: String,
    pub redis_url: String,
    pub db_namespace: String,
    pub coordinator_id: u64,
    pub coordinator_sub_id: u16,
    pub network: PsyChainNetworkType,
    pub verbose: bool,
    pub checkpoint_backup_path: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoordinatorEdgeStartConfig {
    pub scylla_db_url: String,
    pub nats_jetstream_url: String,
    pub redis_url: String,
    pub db_namespace: String,
    pub coordinator_id: u64,
    pub coordinator_sub_id: u16,
    pub network: PsyChainNetworkType,
    pub verbose: bool,
    pub port: u16,
    pub listen: String,
}