#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyNodeChainConfig<Hash>{
    pub guta_circuit_whitelist_root: Hash,
    pub register_users_circuit_whitelist_root: Hash,
    pub deploy_contracts_circuit_whitelist_root: Hash,
    pub genesis_checkpoint_state_transition_hash: Hash,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
}