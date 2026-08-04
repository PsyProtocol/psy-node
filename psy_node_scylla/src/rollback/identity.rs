use strum_macros::EnumIter;

/// Stable physical table identity used by locators and future manifests.
#[derive(Clone, Copy, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ScyllaPhysicalTableId {
    CheckpointLeaf = 1,
    CheckpointRootToCheckpointIdK1 = 2,
    CheckpointRootToCheckpointIdK2 = 3,
    CheckpointLeafToCheckpointIdK1 = 4,
    CheckpointLeafToCheckpointIdK2 = 5,
    L2BlockState = 6,
    CheckpointIdToRealmRoot = 7,
    LatestInfo = 8,
    CheckpointedObject = 9,
    CheckpointStateRoots = 10,
    UserLeaf = 11,
    UserPublicKey = 12,
    U64Singleton = 13,
    U64CounterSingleton = 14,
    ContractStateTreeHeight = 15,
    CheckpointIdToPendingId = 16,
    PendingIdToCheckpointId = 17,
    PendingIdToPendingProcIdU64ToU128 = 18,
    PendingIdToPendingProcIdU128ToU64 = 19,
    RealmRewardsTreeNodeKey = 20,
    PublicKeyHashToUserIds = 21,
    GlobalUserTree = 22,
    UserContractTree = 23,
    ContractStateTree = 24,
    GlobalCheckpointTree = 25,
    GutaRewardTagTree = 26,
    UserRegistrationTree = 27,
    GlobalContractTree = 28,
    ContractFunctionTree = 29,
    ContractLeaf = 30,
    ContractCodeDefinition = 31,
    CheckpointZkProofAndTransition = 32,
    ImtLeaf = 33,
    ImtKeyIndex = 34,
    ImtNextAppendIndex = 35,
}

impl ScyllaPhysicalTableId {
    pub const fn stable_id(self) -> u16 {
        self as u16
    }
}

/// Stable semantic key domain.  Domains remain distinct even when the
/// current CQL schema flattens them to identical integer columns.
#[derive(Clone, Copy, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum ScyllaKeyDomain {
    CheckpointLeaf = 1,
    CheckpointRootByHash = 2,
    CheckpointRootByCheckpoint = 3,
    CheckpointLeafByHash = 4,
    CheckpointLeafByCheckpoint = 5,
    L2BlockState = 6,
    UnusedCheckpointRealmRoot = 7,
    LatestInfo = 8,
    CheckpointedGlobalUserProof = 9,
    CheckpointedRewardsProofAtCheckpoint = 10,
    CheckpointedRewardsProofAtPending = 11,
    CheckpointedContractStateProof = 12,
    CheckpointStateRoots = 13,
    UserLeaf = 14,
    UserPublicKey = 15,
    U64Singleton = 16,
    U64Counter = 17,
    ContractStateTreeHeight = 18,
    CheckpointToPending = 19,
    PendingToCheckpoint = 20,
    PendingToProc = 21,
    ProcToPending = 22,
    RealmRewardNode = 23,
    PublicKeyToUser = 24,
    GlobalUserMerkle = 25,
    UserContractMerkle = 26,
    ContractStateMerkle = 27,
    GlobalCheckpointMerkle = 28,
    RewardTagMerkle = 29,
    UserRegistrationMerkle = 30,
    GlobalContractMerkle = 31,
    ContractFunctionMerkle = 32,
    ContractLeaf = 33,
    ContractCodeDefinition = 34,
    CheckpointZkProof = 35,
    ImtLeaf = 36,
    ImtKeyIndex = 37,
    ImtCursor = 38,
}

impl ScyllaKeyDomain {
    pub const fn stable_id(self) -> u16 {
        self as u16
    }
}
