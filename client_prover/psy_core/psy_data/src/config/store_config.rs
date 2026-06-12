use kvq::adapters::standard::KVQStandardAdapter;
use plonky2::{
    field::goldilocks_field::GoldilocksField,
    hash::poseidon::PoseidonHash,
    plonk::{circuit_data::VerifierOnlyCircuitData, config::PoseidonGoldilocksConfig, proof::ProofWithPublicInputs},
};
use psy_client_common::data::qhashout::QHashOut;
use psy_config::network_constants::{
    CHECKPOINT_TREE_HEIGHT, CONTRACT_FUNCTION_TREE_HEIGHT, GLOBAL_CONTRACT_TREE_HEIGHT, GLOBAL_DEPOSIT_TREE_HEIGHT, GLOBAL_USER_EVENT_TREE_HEIGHT,
    GLOBAL_USER_TREE_HEIGHT, GLOBAL_WITHDRAWAL_TREE_HEIGHT,
};
use psy_crypto::hash::merkle::core::{DeltaMerkleProofCore, MerkleProofCore};

use crate::{
    dpn::event::PsyUserEventRecord,
    models::{
        checkpoint::{
            block_state::BlockStatesModel, checkpoint_hash::PsyCheckpointHashHelperModel, checkpoint_leaf::PsyCheckpointLeafModel,
            sync_info::PsyCheckpointSyncInfoModel, user_public_keys::PsyUserPublicKeyHelperModel,
        },
        contract::{contract_code::ContractCodeModel, contract_leaf::ContractLeafModel},
        contract_metadata::ContractMetaDataModel,
        kvq_merkle::{
            key::KVQMerkleNodeKey,
            model::{KVQFixedConfigMerkleTreeModel, KVQMerkleTreeModel, KVQSemiFixedConfigMerkleTreeModel},
        },
        realm_status::RealmStatusModel,
        register_user_metadata::RegisterUserMetaDataModel,
        staging::{staging_checkpoint_info::StagingCheckpointInfoModel, staging_delta_record::StagingDeltaRecordModelCore},
        user::{user_event::UserEventModel, user_leaf::UserLeafModel},
        user_endcap_metadata::UserEndcapMetaDataModel,
    },
    qdata::{
        checkpoint::{PsyBlockState, PsyCheckpointLeaf},
        checkpoint_id_key::CheckpointTableIdKey,
        contract::{ContractCodeDefinition, PsyContractLeaf},
        contract_metadata::ContractMetaData,
        event_key::EventTableIdKey,
        hash_cache_result::PsyHashHelperResult,
        hash_key::Hash4x64Key,
        hash_key_with_id::Hash4x64KeyWithId,
        realm_id_key::RealmTableIdKey,
        realm_status::BasicRealmStatus,
        register_user_metadata::RegisterUserMetaData,
        staging_checkpoint_info::StagingCheckpointInfo,
        staging_checkpoint_key::StagingCheckpointKey,
        staging_delta_record_key::StagingDeltaRecordKey,
        u64_key::U64TableKey,
        user::PsyUserLeaf,
        user_endcap_metadata::UserEndCapMetaData,
        user_public_key::PsyUserPublicKeyRecord,
    },
    qsync::coordinator::PsyCheckpointSyncInfoCompact,
};
pub const MAX_CHECKPOINT: u64 = 0xfffffffffffffff1u64;
pub const CHECKPOINT_TREE_ID: u8 = 1u8;
pub const USER_TREE_ID: u8 = 2u8;
pub const CONTRACT_TREE_ID: u8 = 3u8;
pub const CONTRACT_FUNCTION_TREE_ID: u8 = 4u8;
pub const DEPOSIT_TREE_ID: u8 = 5u8;
pub const WITHDRAWAL_TREE_ID: u8 = 6u8;
pub const USER_CONTRACT_TREE_ID: u8 = 7u8;
pub const CONTRACT_STATE_TREE_ID: u8 = 8u8;
pub const USER_REGISTRATION_TREE_ID: u8 = 9u8;
pub const USER_EVENT_TREE_ID: u8 = 10u8;

pub const CHECKPOINT_TREE_TABLE_TYPE: u16 = 1;
pub const USER_TREE_TABLE_TYPE: u16 = 2;
pub const CONTRACT_TREE_TABLE_TYPE: u16 = 3;
pub const CONTRACT_FUNCTION_TREE_TABLE_TYPE: u16 = 4;
pub const DEPOSIT_TREE_TABLE_TYPE: u16 = 5;
pub const WITHDRAWAL_TREE_TABLE_TYPE: u16 = 6;
pub const USER_REGISTRATION_TREE_TABLE_TYPE: u16 = 7;

pub const USER_CONTRACT_TREE_TABLE_TYPE: u16 = 8;
pub const USER_CONTRACT_STATE_TREE_TABLE_TYPE: u16 = 9;

// Leaf table types
pub const USER_LEAF_TABLE_TYPE: u16 = 10;
pub const CHECKPOINT_LEAF_TABLE_TYPE: u16 = 11;
pub const CHECKPOINT_BLOCK_STATE_TABLE_TYPE: u16 = 12;
pub const CONTRACT_LEAF_TABLE_TYPE: u16 = 13;
pub const CONTRACT_CODE_TABLE_TYPE: u16 = 14;

// Helper table types
pub const CHECKPOINT_SYNC_INFO_TABLE_TYPE: u16 = 15;
pub const CHECKPOINT_HASH_HELPER_TABLE_TYPE: u16 = 16;
pub const USER_PUBLIC_KEY_HELPER_TABLE_TYPE: u16 = 17;

// Staging table types for dirty data
pub const STAGING_CHECKPOINT_INFO_TABLE_TYPE: u16 = 18;
pub const STAGING_DELTA_RECORD_TABLE_TYPE: u16 = 19;

// Realm status table type
pub const REALM_STATUS_TABLE_TYPE: u16 = 20;

// Contract id table type
pub const CONTRACT_METADATA_TABLE_TYPE: u16 = 21;

pub const REALM_SNAPSHOT_TABLE_TYPE: u16 = 22;
pub const REALM_ROOT_VERSION_TABLE_TYPE: u16 = 23;

pub const USER_EVENT_TABLE_TYPE: u16 = 24;
pub const USER_EVENT_TREE_TABLE_TYPE: u16 = 25;

// User registration id table type
pub const USER_REGISTRATION_METADATA_TABLE_TYPE: u16 = 26;

// User endcap id table type
pub const USER_ENDCAP_METADATA_TABLE_TYPE: u16 = 27;

// Legacy - kept for backward compatibility, should not be used for new trees
pub const PROTOCOL_TREE_TABLE_TYPE: u16 = 100;

pub type PsyFelt = GoldilocksField;
pub type PsyHash = QHashOut<PsyFelt>;
pub type PsyHasher = PoseidonHash;
pub type PsyMerkleProof = MerkleProofCore<PsyHash>;
pub type PsyDeltaMerkleProof = DeltaMerkleProofCore<PsyHash>;
pub type QCheckpointLeaf = PsyCheckpointLeaf<PsyFelt>;
pub type QCheckpointSyncInfoCompact = PsyCheckpointSyncInfoCompact<PsyFelt>;
pub type QUserPublicKeyRecord = PsyUserPublicKeyRecord<PsyFelt>;
pub type PsyPlonky2Config = PoseidonGoldilocksConfig;
pub type PsyProof = ProofWithPublicInputs<PsyFelt, PsyPlonky2Config, 2>;
pub type PsyVerifierData = VerifierOnlyCircuitData<PsyPlonky2Config, 2>;

pub type UserLeafTableStore<S, F = PsyFelt, IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<USER_LEAF_TABLE_TYPE>, PsyUserLeaf<F>>> =
    UserLeafModel<USER_LEAF_TABLE_TYPE, S, F, IDKVA>;
pub type ContractLeafTableStore<S, F = PsyFelt, IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<CONTRACT_LEAF_TABLE_TYPE>, PsyContractLeaf<F>>> =
    ContractLeafModel<CONTRACT_LEAF_TABLE_TYPE, S, F, IDKVA>;
pub type ContractCodeTableStore<S, IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<CONTRACT_CODE_TABLE_TYPE>, ContractCodeDefinition>> =
    ContractCodeModel<CONTRACT_CODE_TABLE_TYPE, S, IDKVA>;

pub type CheckpointLeafTableStore<S, IDKVA = KVQStandardAdapter<S, U64TableKey<CHECKPOINT_LEAF_TABLE_TYPE>, QCheckpointLeaf>> =
    PsyCheckpointLeafModel<CHECKPOINT_LEAF_TABLE_TYPE, S, IDKVA>;

pub type BlockStateTableStore<S, IDKVA = KVQStandardAdapter<S, U64TableKey<CHECKPOINT_BLOCK_STATE_TABLE_TYPE>, PsyBlockState>> =
    BlockStatesModel<CHECKPOINT_BLOCK_STATE_TABLE_TYPE, S, IDKVA>;

pub type CheckpointSyncInfoTableStore<S, IDKVA = KVQStandardAdapter<S, U64TableKey<CHECKPOINT_SYNC_INFO_TABLE_TYPE>, QCheckpointSyncInfoCompact>> =
    PsyCheckpointSyncInfoModel<CHECKPOINT_SYNC_INFO_TABLE_TYPE, S, IDKVA>;

pub type CheckpointHashHelperTableStore<S, IDKVA = KVQStandardAdapter<S, Hash4x64Key<CHECKPOINT_HASH_HELPER_TABLE_TYPE>, PsyHashHelperResult>> =
    PsyCheckpointHashHelperModel<CHECKPOINT_HASH_HELPER_TABLE_TYPE, S, IDKVA>;

pub type UserPublicKeyTableStore<S, IDKVA = KVQStandardAdapter<S, Hash4x64KeyWithId<USER_PUBLIC_KEY_HELPER_TABLE_TYPE>, QUserPublicKeyRecord>> =
    PsyUserPublicKeyHelperModel<USER_PUBLIC_KEY_HELPER_TABLE_TYPE, S, IDKVA>;

// Staging stores for dirty data
pub type StagingCheckpointInfoStore<
    S,
    IDKVA = KVQStandardAdapter<S, StagingCheckpointKey<STAGING_CHECKPOINT_INFO_TABLE_TYPE>, StagingCheckpointInfo>,
> = StagingCheckpointInfoModel<STAGING_CHECKPOINT_INFO_TABLE_TYPE, S, IDKVA>;

pub type StagingDeltaRecordStore<S, IDKVA = KVQStandardAdapter<S, StagingDeltaRecordKey<PsyFelt, STAGING_DELTA_RECORD_TABLE_TYPE>, Vec<u8>>> =
    StagingDeltaRecordModelCore<STAGING_DELTA_RECORD_TABLE_TYPE, S, IDKVA>;

pub type RealmStatusTableStore<S, F = PsyFelt, IDKVA = KVQStandardAdapter<S, RealmTableIdKey<REALM_STATUS_TABLE_TYPE>, BasicRealmStatus<F>>> =
    RealmStatusModel<REALM_STATUS_TABLE_TYPE, S, F, IDKVA>;

pub type ContractMetaDataTableStore<
    S,
    F = PsyFelt,
    IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<CONTRACT_METADATA_TABLE_TYPE>, ContractMetaData<F>>,
> = ContractMetaDataModel<CONTRACT_METADATA_TABLE_TYPE, S, F, IDKVA>;

pub type RegisterUserMetaDataTableStore<
    S,
    F = PsyFelt,
    IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<USER_REGISTRATION_METADATA_TABLE_TYPE>, RegisterUserMetaData<F>>,
> = RegisterUserMetaDataModel<USER_REGISTRATION_METADATA_TABLE_TYPE, S, F, IDKVA>;

pub type UserEndcapMetaDataTableStore<
    S,
    F = PsyFelt,
    IDKVA = KVQStandardAdapter<S, CheckpointTableIdKey<USER_ENDCAP_METADATA_TABLE_TYPE>, UserEndCapMetaData<F>>,
> = UserEndcapMetaDataModel<USER_ENDCAP_METADATA_TABLE_TYPE, S, F, IDKVA>;

// Generic protocol tree template - no longer used directly
pub type ProtocolTreeStore<
    const TREE_ID: u8,
    const HEIGHT: u8,
    const TABLE_TYPE: u16,
    S,
    F,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<TABLE_TYPE>, QHashOut<F>>,
> = KVQFixedConfigMerkleTreeModel<TREE_ID, HEIGHT, 0, 0, TABLE_TYPE, false, S, IDKVA, QHashOut<F>, H>;

pub type UserContractTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_TREE_TABLE_TYPE>, QHashOut<F>>,
> = KVQSemiFixedConfigMerkleTreeModel<
    USER_CONTRACT_TREE_ID,
    GLOBAL_CONTRACT_TREE_HEIGHT,
    0,
    USER_CONTRACT_TREE_TABLE_TYPE,
    false,
    S,
    IDKVA,
    QHashOut<F>,
    H,
>;

pub type UserEventTableStore<S, F = PsyFelt, IDKVA = KVQStandardAdapter<S, EventTableIdKey<USER_EVENT_TABLE_TYPE>, PsyUserEventRecord<F>>> =
    UserEventModel<USER_EVENT_TABLE_TYPE, S, F, IDKVA>;

pub type UserEventTreeStore<S, F = PsyFelt, H = PsyHasher, IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_EVENT_TREE_TABLE_TYPE>, QHashOut<F>>> =
    KVQSemiFixedConfigMerkleTreeModel<
        USER_EVENT_TREE_ID,
        GLOBAL_USER_EVENT_TREE_HEIGHT,
        0,
        USER_EVENT_TREE_TABLE_TYPE,
        false,
        S,
        IDKVA,
        QHashOut<F>,
        H,
    >;

pub type BaseContractStateTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
> = KVQMerkleTreeModel<USER_CONTRACT_STATE_TREE_TABLE_TYPE, false, S, IDKVA, QHashOut<F>, H>;

// Protocol tree stores with their own table types
pub type UserRegistrationTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_REGISTRATION_TREE_TABLE_TYPE>, QHashOut<F>>,
> = ProtocolTreeStore<USER_REGISTRATION_TREE_ID, GLOBAL_USER_TREE_HEIGHT, USER_REGISTRATION_TREE_TABLE_TYPE, S, F, H, IDKVA>;
pub type CheckpointTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<CHECKPOINT_TREE_TABLE_TYPE>, QHashOut<F>>,
> = ProtocolTreeStore<CHECKPOINT_TREE_ID, CHECKPOINT_TREE_HEIGHT, CHECKPOINT_TREE_TABLE_TYPE, S, F, H, IDKVA>;
pub type UserTreeStore<S, F = PsyFelt, H = PsyHasher, IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_TREE_TABLE_TYPE>, QHashOut<F>>> =
    ProtocolTreeStore<USER_TREE_ID, GLOBAL_USER_TREE_HEIGHT, USER_TREE_TABLE_TYPE, S, F, H, IDKVA>;
pub type ContractTreeStore<S, F = PsyFelt, H = PsyHasher, IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<CONTRACT_TREE_TABLE_TYPE>, QHashOut<F>>> =
    ProtocolTreeStore<CONTRACT_TREE_ID, GLOBAL_CONTRACT_TREE_HEIGHT, CONTRACT_TREE_TABLE_TYPE, S, F, H, IDKVA>;

pub type ContractFunctionTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<CONTRACT_FUNCTION_TREE_TABLE_TYPE>, QHashOut<F>>,
> = KVQSemiFixedConfigMerkleTreeModel<
    CONTRACT_FUNCTION_TREE_ID,
    CONTRACT_FUNCTION_TREE_HEIGHT,
    0,
    CONTRACT_FUNCTION_TREE_TABLE_TYPE,
    false,
    S,
    IDKVA,
    QHashOut<F>,
    H,
>;

pub type DepositTreeStore<S, F = PsyFelt, H = PsyHasher, IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<DEPOSIT_TREE_TABLE_TYPE>, QHashOut<F>>> =
    ProtocolTreeStore<DEPOSIT_TREE_ID, GLOBAL_DEPOSIT_TREE_HEIGHT, DEPOSIT_TREE_TABLE_TYPE, S, F, H, IDKVA>;
pub type WithdrawalTreeStore<
    S,
    F = PsyFelt,
    H = PsyHasher,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<WITHDRAWAL_TREE_TABLE_TYPE>, QHashOut<F>>,
> = ProtocolTreeStore<WITHDRAWAL_TREE_ID, GLOBAL_WITHDRAWAL_TREE_HEIGHT, WITHDRAWAL_TREE_TABLE_TYPE, S, F, H, IDKVA>;

pub type C = plonky2::plonk::config::PoseidonGoldilocksConfig;
pub const D: usize = 2;
pub type F = crate::config::store_config::PsyFelt;

// GLOBAL_CONTRACT_TREE_HEIGHT-th zero hash
#[cfg(test)]
mod tests {
    use psy_config::{get_default_user_state_tree_root, network_constants::GLOBAL_CONTRACT_TREE_HEIGHT};
    use psy_crypto::hash::traits::hasher::{MerkleZeroHasher, PoseidonHasher};

    #[test]
    fn check_default_user_state_tree_root() {
        let expected_empty_user_state_tree_root = PoseidonHasher::get_zero_hash(GLOBAL_CONTRACT_TREE_HEIGHT as usize);
        assert_eq!(
            get_default_user_state_tree_root(),
            expected_empty_user_state_tree_root,
            "DEFAULT_USER_STATE_TREE_ROOT does not match the expected value"
        );
        // TODO: make sure the default user tree root is correct
    }
}
