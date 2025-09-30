// total height of the global user merkle tree, both coordinator and realm trees combined into one big tree, where each leaf of the portion of the tree stored by the coordinator is the root of a realm merkle tree
pub const QP_GLOBAL_USER_TREE_HEIGHT: u8 = 32;

// height of the top portion of the global user tree stored by the coordinator, 
pub const QP_COORDINATOR_GUSER_TREE_HEIGHT: u8 = 12;

// height of the bottom sub-trees stored by each realm
pub const QP_REALM_GUSER_TREE_HEIGHT: u8 = 20;

// note that QP_COORDINATOR_GUSER_TREE_HEIGHT + QP_REALM_GUSER_TREE_HEIGHT == QP_GLOBAL_USER_TREE_HEIGHT


// max number of users in the entire network
pub const QP_MAX_TOTAL_USERS: u64 = 1 << QP_GLOBAL_USER_TREE_HEIGHT;

// max number of user leafs stored by each realm, which is also the total number of leaves in each realm's portion of the global user merkle tree
pub const QP_MAX_USERS_PER_REALM: u64 = 1 << QP_REALM_GUSER_TREE_HEIGHT;

// max number of realms in the entire network, which is also the total number of leaves in the coordinator's portion of global user merkle tree
pub const QP_MAX_REALMS: u64 = 1 << QP_COORDINATOR_GUSER_TREE_HEIGHT;



pub const QP_COORDINATOR_BLOCK_TIME_MS: u64 = 30_000; // 30 seconds per block