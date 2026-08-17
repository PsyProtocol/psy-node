pub const U64_SINGLETON_TABLE_OBJ_ID_CHECKPOINT_ID: u64 = 1;
pub const U64_SINGLETON_TABLE_OBJ_ID_PENDING_ID: u64 = 2;

pub const LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE: u64 = 1;
pub const LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT: u64 = 2;
/// Reserved for the Realm-local canonical authority observation that rollback
/// republishes before a restored Realm serves again (design-r1 §6.3).  The slot
/// number is declared here so the typed key space and the production KIV keys
/// cannot drift; no reader or writer exists yet.
pub const LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION: u64 = 3;

pub const CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_USER_TREE_ROOT_MERKLE_PROOF: u64 = 1;
pub const CHECKPOINTED_OBJECT_TABLE_OBJ_ID_REALM_ROOT_TO_GLOBAL_REWARDS_TAG_TREE_ROOT_PROOF: u64 = 2;
pub const CHECKPOINTED_OBJECT_TABLE_OBJ_ID_BRIDGE_DEPOSIT_LEAF_BASE: u64 = 1u64 << 63;
pub const U64_SINGLETON_TABLE_OBJ_ID_BRIDGE_DEPOSIT_NEXT_INDEX_BASE: u64 = 1u64 << 62;
