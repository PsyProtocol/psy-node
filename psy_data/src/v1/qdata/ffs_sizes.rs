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