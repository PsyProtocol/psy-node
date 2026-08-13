use crate::store::canonical_head::CanonicalHeadBootstrapProfile;
use crate::store::realm_processor_startup::RealmProcessorStartupLineage;
use crate::store::rollback_participant_plan::RollbackRealmParticipant;
use crate::store::rollback_topology::RollbackTopologySnapshot;
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_data::protocol::canonical_chain::NetworkId;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorRollbackTopologyRealmConfig {
    pub realm_id: u32,
    pub realm_sub_id: u16,
}

#[cfg(test)]
mod coordinator_rollback_topology_config_tests {
    use super::*;

    #[test]
    fn explicit_topology_is_canonicalized_without_inference() {
        let snapshot = CoordinatorRollbackTopologyConfig {
            revision: 4,
            realms: vec![
                CoordinatorRollbackTopologyRealmConfig {
                    realm_id: 9,
                    realm_sub_id: 2,
                },
                CoordinatorRollbackTopologyRealmConfig {
                    realm_id: 3,
                    realm_sub_id: 1,
                },
            ],
        }
        .try_snapshot(PsyChainNetworkType::LocalDevnet)
        .unwrap();

        assert_eq!(snapshot.revision(), 4);
        assert_eq!(snapshot.realms()[0], RollbackRealmParticipant::new(3, 1));
        assert_eq!(snapshot.realms()[1], RollbackRealmParticipant::new(9, 2));
    }

    #[test]
    fn empty_or_duplicate_topology_is_rejected() {
        assert!(CoordinatorRollbackTopologyConfig {
            revision: 0,
            realms: Vec::new(),
        }
        .try_snapshot(PsyChainNetworkType::LocalDevnet)
        .is_err());
        assert!(CoordinatorRollbackTopologyConfig {
            revision: 0,
            realms: vec![
                CoordinatorRollbackTopologyRealmConfig {
                    realm_id: 3,
                    realm_sub_id: 1,
                },
                CoordinatorRollbackTopologyRealmConfig {
                    realm_id: 3,
                    realm_sub_id: 1,
                },
            ],
        }
        .try_snapshot(PsyChainNetworkType::LocalDevnet)
        .is_err());
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoordinatorRollbackTopologyConfig {
    pub revision: u64,
    pub realms: Vec<CoordinatorRollbackTopologyRealmConfig>,
}

impl CoordinatorRollbackTopologyConfig {
    pub fn try_snapshot(
        &self,
        network: PsyChainNetworkType,
    ) -> anyhow::Result<RollbackTopologySnapshot> {
        RollbackTopologySnapshot::try_new(
            NetworkId::from_network_type(network),
            self.revision,
            self.realms
                .iter()
                .map(|realm| {
                    RollbackRealmParticipant::new(realm.realm_id, realm.realm_sub_id)
                })
                .collect(),
        )
        .map_err(Into::into)
    }
}


#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealmBranchExactStartupConfig {
    pub generation: u64,
    pub binding_digest_hex: String,
    pub writer_activation_digest_hex: String,
}

impl RealmBranchExactStartupConfig {
    pub fn try_lineage(
        &self,
        network: PsyChainNetworkType,
        realm_id: u64,
        realm_sub_id: u16,
    ) -> anyhow::Result<RealmProcessorStartupLineage> {
        let realm_id = u32::try_from(realm_id)
            .map_err(|_| anyhow::anyhow!("branch-exact Realm ID exceeds u32"))?;
        RealmProcessorStartupLineage::try_new(
            NetworkId::from_network_type(network),
            realm_id,
            realm_sub_id,
            self.generation,
            decode_canonical_digest(&self.binding_digest_hex)?,
            decode_canonical_digest(&self.writer_activation_digest_hex)?,
        )
        .map_err(Into::into)
    }
}

fn decode_canonical_digest(value: &str) -> anyhow::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        anyhow::bail!("branch-exact digest must be 64 lowercase hex characters");
    }
    let mut digest = [0; 32];
    hex::decode_to_slice(value, &mut digest)
        .map_err(|_| anyhow::anyhow!("invalid branch-exact digest"))?;
    Ok(digest)
}


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
    pub branch_exact_startup: Option<RealmBranchExactStartupConfig>,
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
    /// Disabled by default. An enabled Edge must pass the same durable
    /// branch-exact lineage preflight as its Realm Processor before any
    /// production handler may be constructed.
    #[serde(default)]
    pub branch_exact_startup: Option<RealmBranchExactStartupConfig>,
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
    /// Default-off until an operator has deployed and VERIFIED sidecar v18.
    #[serde(default)]
    pub durable_guta_submission_enabled: bool,
    /// Explicit deployment topology for global rollback. `None` never infers
    /// Realm membership from protocol capacity or observed traffic.
    #[serde(default)]
    pub rollback_topology: Option<CoordinatorRollbackTopologyConfig>,
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

#[cfg(test)]
mod realm_branch_exact_startup_tests {
    use super::*;

    fn config() -> RealmBranchExactStartupConfig {
        RealmBranchExactStartupConfig {
            generation: 9,
            binding_digest_hex: hex::encode([1; 32]),
            writer_activation_digest_hex: hex::encode([2; 32]),
        }
    }

    #[test]
    fn lineage_is_strict_canonical_and_has_no_configured_nonce() {
        let lineage = config()
            .try_lineage(PsyChainNetworkType::LocalDevnet, 7, 3)
            .unwrap();
        assert_eq!(lineage.realm_id(), 7);
        assert_eq!(lineage.realm_sub_id(), 3);
        assert_eq!(lineage.expected_generation(), 9);

        for digest in [
            "01".to_owned(),
            format!("0x{}", hex::encode([1; 32])),
            hex::encode_upper([0xab; 32]),
            hex::encode([0; 32]),
        ] {
            let mut malformed = config();
            malformed.binding_digest_hex = digest;
            assert!(malformed
                .try_lineage(PsyChainNetworkType::LocalDevnet, 7, 3)
                .is_err());
        }
        assert!(config()
            .try_lineage(
                PsyChainNetworkType::LocalDevnet,
                u64::from(u32::MAX) + 1,
                3,
            )
            .is_err());

        let encoded = serde_json::to_string(&config()).unwrap();
        assert!(!encoded.contains("nonce"));
        assert!(serde_json::from_str::<RealmBranchExactStartupConfig>(
            r#"{"generation":9,"binding_digest_hex":"01","writer_activation_digest_hex":"02","nonce":"forbidden"}"#,
        )
        .is_err());
    }

    #[test]
    fn existing_realm_config_defaults_branch_exact_to_disabled() {
        let config = RealmProcessorStartConfig {
            scylla_db_url: "scylla".to_owned(),
            nats_jetstream_url: "nats".to_owned(),
            redis_url: "redis".to_owned(),
            db_namespace: "psy".to_owned(),
            realm_id: 7,
            realm_sub_id: 3,
            network: PsyChainNetworkType::LocalDevnet,
            verbose: false,
            checkpoint_backup_path: "/tmp/psy".to_owned(),
            coordinator_api_urls: vec!["http://coordinator".to_owned()],
            genesis_data_path: None,
            branch_exact_startup: None,
        };
        let mut encoded = serde_json::to_value(config).unwrap();
        encoded
            .as_object_mut()
            .unwrap()
            .remove("branch_exact_startup");
        let parsed: RealmProcessorStartConfig =
            serde_json::from_value(encoded).unwrap();
        assert!(parsed.branch_exact_startup.is_none());
    }

    #[test]
    fn existing_realm_edge_config_defaults_branch_exact_to_disabled() {
        let json = serde_json::json!({
            "scylla_db_url": "scylla",
            "nats_jetstream_url": "nats",
            "redis_url": "redis",
            "db_namespace": "psy",
            "realm_id": 7,
            "realm_sub_id": 3,
            "network": PsyChainNetworkType::LocalDevnet,
            "verbose": false,
            "port": 8080,
            "listen": "127.0.0.1"
        });
        let parsed: RealmEdgeStartConfig = serde_json::from_value(json).unwrap();
        assert!(parsed.branch_exact_startup.is_none());
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
    /// Disabled by default. When enabled, the Edge may only enqueue a typed
    /// request; it still cannot publish canonical rollback control.
    #[serde(default)]
    pub rollback_admin_rpc_enabled: bool,
    /// Optional exact topology install/revalidation. Rollback start remains
    /// unavailable while no durable topology exists.
    #[serde(default)]
    pub rollback_topology: Option<CoordinatorRollbackTopologyConfig>,
    /// Default-off until an operator has deployed and VERIFIED sidecar v18.
    #[serde(default)]
    pub durable_guta_submission_enabled: bool,
}
