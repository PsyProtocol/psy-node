use parth_core::protocol::core_types::{QNetworkTreeCircuitSpecificConstantsData, QNetworkTreeConstantsData};
use psy_core::constants::chain_id::PsyChainNetworkType;

#[pderive::serialize_copy_ts_export]
pub struct PsyNetworkChainConfig {
    pub network_type: PsyChainNetworkType,
    pub tree_constants: QNetworkTreeConstantsData,
    pub circuit_constants: QNetworkTreeCircuitSpecificConstantsData,
}



#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyNodeCircuitFingerprintConfig<Hash>{
    pub guta_circuit_whitelist_root: Hash,
    pub register_users_circuit_whitelist_root: Hash,
    pub deploy_contracts_circuit_whitelist_root: Hash,
    pub update_contracts_circuit_whitelist_root: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
    pub genesis_checkpoint_state_transition_fingerprint: Hash,
}

pub trait PsyNodeCircuitFingerprintConfigProvider<Hash> {
    fn get_circuit_fingerprint_config_for_network(&self, network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>>;
}

pub fn load_realm_rotation_config(network: PsyChainNetworkType) -> anyhow::Result<parth_common::realm_rotation::RealmRotationConfig> {
    let name = match network {
        PsyChainNetworkType::LocalDevnet => "localhost",
        PsyChainNetworkType::PsyPublicTestnet => "sepolia",
        PsyChainNetworkType::PsyMainnet => "ethereum",
        _ => anyhow::bail!("No realm rotation configuration for network {network:?}"),
    };
    if let Ok(selected) = std::env::var("PSY_NETWORK") {
        anyhow::ensure!(selected == name, "PSY_NETWORK {selected} does not match {name}");
    }
    let configured_path = std::env::var("PSY_CONFIG_PATH").ok();
    let paths = match configured_path.as_deref() {
        Some(path) => vec![path],
        None => vec!["local_checkpoints/realm_p2p/config.json", "psy-genesis/config.json"],
    };
    for path in paths {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => anyhow::bail!("Cannot read network config {path}: {error}"),
        };
        let config: serde_json::Value = serde_json::from_str(&text)?;
        let network = &config["networks"][name];
        let has_validators = network["realm_configs"].as_array().is_some_and(|realms|
            realms.iter().any(|realm| realm["validators"].as_array().is_some_and(|validators| !validators.is_empty())));
        if has_validators {
            return realm_rotation_config_from_network(network);
        }
    }
    anyhow::bail!("No injected validator set found for network {name}")
}

fn realm_rotation_config_from_network(network: &serde_json::Value) -> anyhow::Result<parth_common::realm_rotation::RealmRotationConfig> {
    let realms = network["realm_configs"].as_array()
        .filter(|realms| !realms.is_empty())
        .ok_or_else(|| anyhow::anyhow!("Network requires active realms"))?;
    let mut validator_count = None;
    for realm in realms {
        let count = realm["validators"].as_array().map(Vec::len)
            .ok_or_else(|| anyhow::anyhow!("Realm {} requires validators", realm["id"]))?;
        if count == 0 {
            continue;
        }
        anyhow::ensure!((crate::p2p::MIN_VALIDATORS_PER_REALM..=crate::p2p::MAX_VALIDATORS_PER_REALM).contains(&count),
            "Realm {} has invalid validator count {count}", realm["id"]);
        anyhow::ensure!(validator_count.is_none_or(|expected| expected == count),
            "Active realms must have identical validator counts");
        validator_count = Some(count);
    }
    Ok(parth_common::realm_rotation::RealmRotationConfig {
        checkpoints_per_epoch: psy_config::CHECKPOINTS_PER_EPOCH,
        validator_sub_ids: (1..=validator_count.ok_or_else(|| anyhow::anyhow!("Network requires validators"))? as u16).collect(),
    })
}

#[cfg(test)]
mod tests {

    use psy_core::constants::chain_id::PsyChainNetworkType;

    use super::*;

    type Hash = parth_core::PHash;

    fn hash(value: u64) -> Hash {
        Hash::from_values(value, 0, 0, 0)
    }

    fn tree_constants() -> QNetworkTreeConstantsData {
        QNetworkTreeConstantsData {
            checkpoint_tree_height: 27,
            global_user_tree_height: 40,
            global_contract_tree_height: 24,
            contract_function_tree_height: 16,
            coordinator_global_user_tree_height: 13,
            realm_global_user_tree_height: 27,
            max_contract_state_tree_height: 32,
            group_realm_height: 1,
            max_users: 1 << 40,
            max_realms: 1 << 13,
            max_users_per_realm: 1 << 27,
        }
    }

    fn circuit_constants() -> QNetworkTreeCircuitSpecificConstantsData {
        QNetworkTreeCircuitSpecificConstantsData {
            global_user_tree_realm_height: 27,
            global_user_tree_height: 40,
            guta_circuit_whitelist_tree_height: 16,
            checkpoint_tree_height: 27,
            group_realm_height: 1,
            max_users_to_register_per_proof: 16,
            only_register_max_users_per_proof: 8,
            batch_user_registration_sub_tree_height: 4,
            batch_user_registration_max_sub_trees: 4,
            global_contract_tree_height: 24,
            batch_deploy_contract_sub_tree_height: 4,
            max_contract_state_tree_height: 32,
            default_user_state_tree_root_hash_u64_x4: [1, 2, 3, 4],
        }
    }

    #[test]
    fn chain_config_stores_network_and_tree_constants() {
        let config = PsyNetworkChainConfig {
            network_type: PsyChainNetworkType::PsyPublicTestnet,
            tree_constants: tree_constants(),
            circuit_constants: circuit_constants(),
        };
        assert_eq!(config.network_type, PsyChainNetworkType::PsyPublicTestnet);
        assert_eq!(config.network_type.to_u8(), 6);
        assert_eq!(config.tree_constants.max_users, 1 << 40);
        assert_eq!(config.tree_constants.max_realms, 1 << 13);
        assert_eq!(config.circuit_constants.checkpoint_tree_height, 27);
        assert_eq!(config.circuit_constants.default_user_state_tree_root_hash_u64_x4, [1, 2, 3, 4]);

        // Copy semantics plus derived equality and hashing.
        let copy = config;
        assert_eq!(copy.network_type, config.network_type);
        assert_eq!(copy.tree_constants.max_users_per_realm, config.tree_constants.max_users_per_realm);
        let mut set = std::collections::HashSet::new();
        assert!(set.insert(config));
        assert!(!set.insert(copy));
        assert_eq!(set.len(), 1);

        // serde round trip keeps the network and its constants.
        let json = serde_json::to_string(&copy).unwrap();
        let restored: PsyNetworkChainConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.network_type, PsyChainNetworkType::PsyPublicTestnet);
        assert_eq!(restored.tree_constants, copy.tree_constants);
        assert_eq!(restored.circuit_constants, copy.circuit_constants);
    }

    #[test]
    fn fingerprint_config_provider_serves_configs_per_network() {
        let config = PsyNodeCircuitFingerprintConfig::<Hash> {
            guta_circuit_whitelist_root: hash(1),
            register_users_circuit_whitelist_root: hash(2),
            deploy_contracts_circuit_whitelist_root: hash(3),
            update_contracts_circuit_whitelist_root: hash(4),
            checkpoint_state_transition_circuit_fingerprint: hash(5),
            genesis_checkpoint_state_transition_fingerprint: hash(6),
        };

        struct FixedProvider {
            config: PsyNodeCircuitFingerprintConfig<Hash>,
        }
        impl PsyNodeCircuitFingerprintConfigProvider<Hash> for FixedProvider {
            fn get_circuit_fingerprint_config_for_network(&self, _network: PsyChainNetworkType) -> anyhow::Result<PsyNodeCircuitFingerprintConfig<Hash>> {
                Ok(self.config.clone())
            }
        }

        let provider = FixedProvider { config: config.clone() };
        for network in [
            PsyChainNetworkType::LocalDevnet,
            PsyChainNetworkType::InternalTestnet,
            PsyChainNetworkType::PsyMainnet,
        ] {
            let fetched = provider.get_circuit_fingerprint_config_for_network(network).unwrap();
            assert_eq!(fetched, config);
            assert_eq!(fetched.guta_circuit_whitelist_root, hash(1));
            assert_eq!(fetched.genesis_checkpoint_state_transition_fingerprint, hash(6));
        }

        // Distinct configs compare and hash differently.
        let mut other = config.clone();
        other.checkpoint_state_transition_circuit_fingerprint = hash(7);
        assert_ne!(other, config);
        let mut set = std::collections::HashSet::new();
        assert!(set.insert(config));
        assert!(set.insert(other));
        assert_eq!(set.len(), 2);
    }

    use super::realm_rotation_config_from_network;
    use serde_json::json;

    #[test]
    fn realm_rotation_config_requires_uniform_validator_counts() -> anyhow::Result<()> {
        let mut network = json!({
            "p2p": {"checkpoints_per_epoch": 37},
            "realm_configs": [
                {"id": 0, "validators": [{}, {}]},
                {"id": 1, "validators": [{}, {}]}
            ]
        });
        let rotation = realm_rotation_config_from_network(&network)?;
        assert_eq!(rotation.checkpoints_per_epoch, psy_config::CHECKPOINTS_PER_EPOCH);
        assert_eq!(rotation.validator_sub_ids, vec![1, 2]);
        network["realm_configs"][1]["validators"].as_array_mut().unwrap().push(json!({}));
        assert!(realm_rotation_config_from_network(&network).unwrap_err().to_string().contains("identical"));
        Ok(())
    }

    #[test]
    fn realm_rotation_config_rejects_missing_validators() {
        for network in [
            json!({}),
            json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": []}),
            json!({"p2p": {"checkpoints_per_epoch": 10}, "realm_configs": [{"validators": []}]}),
        ] {
            assert!(realm_rotation_config_from_network(&network).is_err());
        }
    }

    #[test]
    fn realm_rotation_ignores_runtime_checkpoint_period() {
        let mut network = json!({"realm_configs": [{"id": 0, "validators": [{}, {}]}]});
        for p2p in [json!(null), json!({"checkpoints_per_epoch": 0}), json!({"checkpoints_per_epoch": psy_config::CHECKPOINTS_PER_EPOCH + 1})] {
            network["p2p"] = p2p;
            let rotation = realm_rotation_config_from_network(&network).unwrap();
            assert_eq!(rotation.checkpoints_per_epoch, psy_config::CHECKPOINTS_PER_EPOCH);
            assert_eq!(rotation.validator_sub_ids, vec![1, 2]);
        }
    }
}
