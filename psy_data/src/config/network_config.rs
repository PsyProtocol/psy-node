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