use psy_core::constants::chain_id::PsyChainNetworkType;
use crate::store::canonical_head::CanonicalHeadBootstrapProfile;
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
    pub genesis_data_path: Option<String>,
}
impl RealmProcessorStartConfig {
    pub fn get_checkpoint_tree_backup_file_path(&self) -> String {
        format!(
            "{}/realm_{}_{}/checkpoint_tree.bin",
            self.checkpoint_backup_path, self.realm_id, self.realm_sub_id
        )
    }
    pub fn get_guta_updates_backup_path(&self) -> String {
        format!(
            "{}/realm_{}_{}/guta_updates_backup",
            self.checkpoint_backup_path, self.realm_id, self.realm_sub_id
        )
    }
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
    /// Required only while the durable canonical-head row is absent. Once the
    /// row exists this value cannot overwrite or reinterpret it.
    #[serde(default)]
    pub canonical_head_bootstrap_profile: Option<CanonicalHeadBootstrapProfile>,
    pub verbose: bool,
    pub checkpoint_backup_path: String,
    pub genesis_data_path: Option<String>,
}
impl CoordinatorProcessorStartConfig {
    pub fn get_checkpoint_tree_backup_file_path(&self) -> String {
        format!(
            "{}/coordinator_{}_{}/checkpoint_tree.bin",
            self.checkpoint_backup_path, self.coordinator_id, self.coordinator_sub_id
        )
    }
    pub fn get_register_users_backup_path(&self) -> String {
        format!(
            "{}/coordinator_{}_{}/register_users_backup",
            self.checkpoint_backup_path, self.coordinator_id, self.coordinator_sub_id
        )
    }
    pub fn get_deploy_contracts_backup_path(&self) -> String {
        format!(
            "{}/coordinator_{}_{}/deploy_contracts_backup",
            self.checkpoint_backup_path, self.coordinator_id, self.coordinator_sub_id
        )
    }
    pub fn get_guta_updates_backup_path(&self) -> String {
        format!(
            "{}/coordinator_{}_{}/guta_updates_backup",
            self.checkpoint_backup_path, self.coordinator_id, self.coordinator_sub_id
        )
    }
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
