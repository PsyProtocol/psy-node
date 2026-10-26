#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyNodeChainConfig<Hash>{
    pub guta_circuit_whitelist_root: Hash,
    pub register_users_circuit_whitelist_root: Hash,
    pub deploy_contracts_circuit_whitelist_root: Hash,
    pub update_contracts_circuit_whitelist_root: Hash,
    pub genesis_checkpoint_state_transition_hash: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    type Hash = parth_core::PHash;

    fn hash(value: u64) -> Hash {
        Hash::from_values(value, 0, 0, 0)
    }

    fn sample_config() -> PsyNodeChainConfig<Hash> {
        PsyNodeChainConfig {
            guta_circuit_whitelist_root: hash(1),
            register_users_circuit_whitelist_root: hash(2),
            deploy_contracts_circuit_whitelist_root: hash(3),
            update_contracts_circuit_whitelist_root: hash(4),
            genesis_checkpoint_state_transition_hash: hash(5),
            checkpoint_state_transition_circuit_fingerprint: hash(6),
        }
    }

    #[test]
    fn chain_config_preserves_all_whitelist_roots() {
        let config = sample_config();
        assert_eq!(config.guta_circuit_whitelist_root, hash(1));
        assert_eq!(config.register_users_circuit_whitelist_root, hash(2));
        assert_eq!(config.deploy_contracts_circuit_whitelist_root, hash(3));
        assert_eq!(config.update_contracts_circuit_whitelist_root, hash(4));
        assert_eq!(config.genesis_checkpoint_state_transition_hash, hash(5));
        assert_eq!(config.checkpoint_state_transition_circuit_fingerprint, hash(6));
    }

    #[test]
    fn chain_config_clones_hashes_and_serde_roundtrips() {
        let config = sample_config();
        let clone = config.clone();
        assert_eq!(clone, config);

        let mut set = std::collections::HashSet::new();
        assert!(set.insert(config));
        assert!(!set.insert(clone.clone()));
        assert_eq!(set.len(), 1);

        let json = serde_json::to_string(&clone).unwrap();
        let restored: PsyNodeChainConfig<Hash> = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, clone);

        // Changing any root yields a distinct config.
        let mut other = clone.clone();
        other.guta_circuit_whitelist_root = hash(9);
        assert_ne!(other, clone);
    }
}