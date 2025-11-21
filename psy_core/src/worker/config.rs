#[pderive::serialize_copy_ts_export]
pub struct WorkerCircuitsNetworkCoreConfig {
    pub global_user_tree_realm_height: usize,
    pub global_user_tree_height: usize,
    pub guta_circuit_whitelist_tree_height: u8,
    pub checkpoint_tree_height: usize,
    pub group_realm_height: usize,
    pub max_users_to_register_per_proof: usize,
    pub only_register_max_users_per_proof: usize,
    pub batch_user_registration_sub_tree_height: usize,
    pub batch_user_registration_max_sub_trees: usize,
    pub global_contract_tree_height: usize,
    pub batch_deploy_contract_sub_tree_height: usize,
    pub max_contract_state_tree_height: usize,
    pub default_user_state_tree_root_hash_u64_x4: [u64; 4],
}