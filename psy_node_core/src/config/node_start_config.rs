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
impl RealmProcessorStartConfig {
    /// True when the optional Realm P2P transport is wired. Empty fields
    /// (the default) leave the node on today's HTTP/NATS path.
    pub fn realm_p2p_enabled(&self) -> bool {
        self.p2p_identity_key_path.is_some() && self.p2p_listen.is_some()
    }
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
impl RealmEdgeStartConfig {
    /// True when the optional Realm P2P transport is wired. Empty fields
    /// (the default) leave the node on today's HTTP/NATS path.
    pub fn realm_p2p_enabled(&self) -> bool {
        self.p2p_identity_key_path.is_some() && self.p2p_listen.is_some()
    }
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
    pub fn get_update_contracts_backup_path(&self) -> String {
        format!(
            "{}/coordinator_{}_{}/update_contracts_backup",
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
    #[serde(default)]
    pub p2p_roster_path: Option<String>,
    #[serde(default)]
    pub p2p_checkpoints_per_epoch: Option<u64>,
}

impl CoordinatorEdgeStartConfig {
    pub fn p2p_validator_roster_config(&self) -> anyhow::Result<Option<(&str, u64)>> {
        match (self.p2p_roster_path.as_deref(), self.p2p_checkpoints_per_epoch) {
            (None, None) => Ok(None),
            (Some(roster_path), Some(checkpoints_per_epoch)) => {
                anyhow::ensure!(checkpoints_per_epoch > 0, "P2P checkpoints_per_epoch must be greater than zero");
                Ok(Some((roster_path, checkpoints_per_epoch)))
            }
            (Some(_), None) => anyhow::bail!("--p2p-checkpoints-per-epoch is required with --p2p-roster-path"),
            (None, Some(_)) => anyhow::bail!("--p2p-roster-path is required with --p2p-checkpoints-per-epoch"),
        }
    }
}