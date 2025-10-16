// PQEDUserLeaf size in bytes
// public_key(32 bytes) + user_state_tree_root(32 bytes) + balance(8 bytes) + nonce(8 bytes) + last_checkpoint_id(8 bytes) + event_index(8 bytes) + user_id(8 bytes) = 104 bytes
pub const PSY_OBJECT_FFS_SIZE_USER_LEAF: usize = 104;



// PQEDContractLeaf size in bytes
// deployer(32 bytes) + function_tree_root(32 bytes) + state_tree_height(8 bytes) = 72 bytes
pub const PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF: usize = 72;