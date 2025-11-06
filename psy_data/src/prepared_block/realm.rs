use parth_core::QCoreProcCheckpointUniqueId;






#[pderive::serialize_clone_hash_ts]
#[ts(export, concrete(Hash = parth_core::PHash))]
pub struct PsyPreparedRealmBlockStateUpdates<Hash> {
    pub realm_id: u64,
    pub realm_sub_id: u64,
    pub unique_pending_id: u64,
    pub proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub old_realm_root: Hash,
    pub new_realm_root: Hash,
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub update_user_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_state_tree_nodes_ffs: Vec<u8>,
    pub update_user_leaves_ffs: Vec<u8>,
}




