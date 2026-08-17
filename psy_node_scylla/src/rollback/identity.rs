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
    /// Realm serving-head marker stored in latest_info slot 3.  It is kept a
    /// distinct semantic domain from the derived legacy latest-info slots.
    RealmAuthorityObservation = 39,
}

impl ScyllaKeyDomain {
    pub const fn stable_id(self) -> u16 {
        self as u16
    }
}

/// A physical table id that is not in the registry.  Decoding a locator record
/// written by a newer schema must fail rather than land on a neighbouring table.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnknownScyllaPhysicalTableId(pub u16);

impl std::fmt::Display for UnknownScyllaPhysicalTableId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown physical table id {}", self.0)
    }
}

impl std::error::Error for UnknownScyllaPhysicalTableId {}

impl TryFrom<u16> for ScyllaPhysicalTableId {
    type Error = UnknownScyllaPhysicalTableId;

    /// Derived from the enum rather than a hand-written match, so a new physical
    /// table is decodable the moment it is registered.
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        use strum::IntoEnumIterator;
        Self::iter()
            .find(|id| *id as u16 == value)
            .ok_or(UnknownScyllaPhysicalTableId(value))
    }
}
