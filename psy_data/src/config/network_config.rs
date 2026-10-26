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
}