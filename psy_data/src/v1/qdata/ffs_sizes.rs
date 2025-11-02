// PQEDUserLeaf size in bytes
// public_key(32 bytes) + user_state_tree_root(32 bytes) + balance(8 bytes) + nonce(8 bytes) + last_checkpoint_id(8 bytes) + event_index(8 bytes) + user_id(8 bytes) = 104 bytes
pub const PSY_OBJECT_FFS_SIZE_USER_LEAF: usize = 104;// PQEDUserLeaf size in bytes

// fingerprint(32 bytes) + public_key_param(32 bytes) = 64 bytes
pub const PSY_OBJECT_FFS_SIZE_ZK_PUBLIC_KEY: usize = 64;



// PQEDContractLeaf size in bytes
// deployer(32 bytes) + function_tree_root(32 bytes) + state_tree_height(8 bytes) = 72 bytes
pub const PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF: usize = 72;

// PUPSEndCapResultCompact size in bytes
// start_user_leaf_hash(32 bytes) + end_user_leaf_hash(32 bytes) + checkpoint_tree_root_hash(32 bytes) + user_id(8 bytes) = 104 bytes
pub const PSY_OBJECT_FFS_SIZE_END_CAP_RESULT_COMPACT: usize = 104;


// PsyNodeUserUpdateMetaData size in bytes
// job_id(24) + user_id(8 bytes) + start_user_leaf_hash(32 bytes) + end_user_leaf_hash(32 bytes) + checkpoint_tree_root_hash(32 bytes) + checkpoint_tree_root_checkpoint_id(8 bytes) = 136 bytes
pub const PSY_OBJECT_FFS_SIZE_USER_UPDATE_METADATA: usize = 136;

// QEDL2BlockState size in bytes
// checkpoint_id(8 bytes) + next_add_withdrawal_id(8 bytes) + next_process_withdrawal_id(8 bytes) + next_deposit_id(8 bytes) + total_deposits_claimed_epoch(8 bytes) + next_user_id(8 bytes) + end_balance(8 bytes) + next_contract_id(8 bytes) + timestamp_current(8 bytes) = 64 bytes
pub const PSY_OBJECT_FFS_SIZE_L2_BLOCK_STATE: usize = 64;

// PQEDCheckpointGlobalStateRoots size in bytes
// contract_tree_root(32 bytes) + user_tree_root(32 bytes) + l2_block_state_hash(32 bytes) + pm_jobs_completed_stats_hash(32 bytes) + pm_rewards_commitment_hash(32 bytes) = 160 bytes
pub const PSY_OBJECT_FFS_SIZE_GLOBAL_STATE_ROOTS: usize = 160;




// PsyGUTANodeUpdate size in bytes
// contract_tree_root(32 bytes) + user_tree_root(32 bytes) + l2_block_state_hash(32 bytes) + pm_jobs_completed_stats_hash(32 bytes) + pm_rewards_commitment_hash(32 bytes) = 160 bytes
//pub const PSY_OBJECT_FFS_SIZE_GUTA_NODE_UPDATE: usize = 160;

