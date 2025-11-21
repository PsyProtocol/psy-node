use crate::crypto::hash::traits::FromU64x4;

#[pderive::serialize_copy_ts_export]
pub struct QNetworkTreeCircuitSpecificConstantsData {
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

impl QNetworkTreeCircuitSpecificConstantsData {
    pub const fn new_from_trait<T: QNetworkCircuitConstants>() -> Self {
        Self {
            global_user_tree_realm_height: T::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE,
            global_user_tree_height: T::GLOBAL_USER_TREE_HEIGHT_USIZE,
            guta_circuit_whitelist_tree_height: T::GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT,
            checkpoint_tree_height: T::CHECKPOINT_TREE_HEIGHT_USIZE,
            group_realm_height: T::GROUP_REALM_HEIGHT as usize,
            max_users_to_register_per_proof: T::MAX_USERS_TO_REGISTER_PER_PROOF,
            only_register_max_users_per_proof: T::ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF,
            batch_user_registration_sub_tree_height: T::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT,
            batch_user_registration_max_sub_trees: T::BATCH_USER_REGISTRATION_MAX_SUB_TREES,
            global_contract_tree_height: T::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
            batch_deploy_contract_sub_tree_height: T::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT,
            max_contract_state_tree_height: T::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE,
            default_user_state_tree_root_hash_u64_x4: T::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4,
        }
    }
}
pub trait QNetworkTreeCircuitSpecificConstants: Sized + Send + Sync + Copy + Clone {
    const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8;
    const MAX_USERS_TO_REGISTER_PER_PROOF: usize;
    const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize;
    const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize;
    const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize;
    const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize;
    const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4];
    const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4];


    fn get_end_cap_circuit_fingerprint_hash<Hash: FromU64x4>() -> Hash {
        Hash::from_u64s(
            Self::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4[0],
            Self::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4[1],
            Self::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4[2],
            Self::END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4[3],
        )
    }
    fn get_default_user_state_tree_root<Hash: FromU64x4>() -> Hash {
        Hash::from_u64s(
            Self::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[0],
            Self::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[1],
            Self::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[2],
            Self::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4[3],
        )
    }
    
}
#[pderive::serialize_copy_ts_export]
pub struct QNetworkTreeConstantsData {
    pub checkpoint_tree_height: u8,
    pub global_user_tree_height: u8,
    pub global_contract_tree_height: u8,
    pub contract_function_tree_height: u8,
    pub coordinator_global_user_tree_height: u8,
    pub realm_global_user_tree_height: u8,
    pub max_contract_state_tree_height: u8,
    pub group_realm_height: u8,
    pub max_users: u64,
    pub max_realms: u32,
    pub max_users_per_realm: u32,
}
impl QNetworkTreeConstantsData {
    pub fn new_from_trait<T: QNetworkTreeConstants>() -> Self {
        Self {
            checkpoint_tree_height: T::CHECKPOINT_TREE_HEIGHT,
            global_user_tree_height: T::GLOBAL_USER_TREE_HEIGHT,
            global_contract_tree_height: T::GLOBAL_CONTRACT_TREE_HEIGHT,
            contract_function_tree_height: T::CONTRACT_FUNCTION_TREE_HEIGHT,
            coordinator_global_user_tree_height: T::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            realm_global_user_tree_height: T::REALM_GLOBAL_USER_TREE_HEIGHT,
            max_contract_state_tree_height: T::MAX_CONTRACT_STATE_TREE_HEIGHT,
            group_realm_height: T::GROUP_REALM_HEIGHT,
            max_users: T::MAX_USERS,
            max_realms: T::MAX_REALMS,
            max_users_per_realm: T::MAX_USERS_PER_REALM,
        }
    }
}

pub trait QNetworkTreeConstants: Sized + Send + Sync + Copy + Clone {
    
    const CHECKPOINT_TREE_HEIGHT_USIZE: usize;
    const CHECKPOINT_TREE_HEIGHT: u8;

    const GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_USER_TREE_HEIGHT: u8;

    const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize;
    const GLOBAL_CONTRACT_TREE_HEIGHT: u8;
    
    const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize;
    const CONTRACT_FUNCTION_TREE_HEIGHT: u8;

    // the height of the global user tree stored in the coordinator (ie. the upper half of the merkle tree)
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8;
    
     // the height of the global user tree stored in each realm (ie. the height of the sub-trees stored in each realm == GLOBAL_USER_TREE_HEIGHT - COORDINATOR_GLOBAL_USER_TREE_HEIGHT)
    const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8;


    const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize;
    const MAX_CONTRACT_STATE_TREE_HEIGHT: u8;


    const GROUP_REALM_HEIGHT: u8;// 1, for user ids
    const MAX_USERS: u64; // = 2**GLOBAL_USER_TREE_HEIGHT
    const MAX_REALMS: u32; // = 2**COORDINATOR_GLOBAL_USER_TREE_HEIGHT
    const MAX_USERS_PER_REALM: u32; // = 2**REALM_GLOBAL_USER_TREE_HEIGHT
}


pub trait QNetworkHashConstants: Sized + Send + Sync + Copy + Clone {
    const DEFUALT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4];
}
#[pderive::serialize_copy_ts_export]
pub struct QNetworkCircuitConstantsData {
    pub tree_constants: QNetworkTreeConstantsData,
    pub circuit_constants: QNetworkTreeCircuitSpecificConstantsData,
}

impl QNetworkCircuitConstantsData {
    pub fn new_from_trait<T: QNetworkCircuitConstants>() -> Self {
        Self {
            tree_constants: QNetworkTreeConstantsData::new_from_trait::<T>(),
            circuit_constants: QNetworkTreeCircuitSpecificConstantsData::new_from_trait::<T>(),
        }
    }
}

pub trait QNetworkCircuitConstants: QNetworkTreeCircuitSpecificConstants + QNetworkTreeConstants {
}
impl<T: QNetworkTreeCircuitSpecificConstants + QNetworkTreeConstants> QNetworkCircuitConstants for T {}


pub trait QNetworkConstants: QNetworkCircuitConstants + QNetworkHashConstants {
}
impl<T: QNetworkCircuitConstants + QNetworkHashConstants> QNetworkConstants for T {}