//! Driver-independent typed storage identities and mutation primitives.
//!
//! These types deliberately do not know about Scylla sessions or CQL.  The
//! Scylla registry resolves [`TypedTableKey`] values to physical tables and
//! produces the stable locator encoding.

use std::{error::Error, fmt};

use strum_macros::EnumIter;

/// The first version of the rollback storage-key codec.
pub const STORAGE_KEY_CODEC_VERSION: u16 = 1;

/// The 32 stable logical tables used by the Psy authority store.
///
/// The discriminant is also the existing database routing key.  Do not reuse
/// or reorder a discriminant: locators and manifests persist this identity.
#[derive(Clone, Copy, Debug, EnumIter, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum PsyLogicalTableId {
    CheckpointLeaf = 1,
    CheckpointRootToCheckpointId = 2,
    CheckpointLeafToCheckpointId = 3,
    L2BlockState = 4,
    CheckpointIdToRealmRoot = 5,
    LatestInfo = 6,
    CheckpointedObject = 7,
    CheckpointStateRoots = 8,
    UserLeaf = 9,
    UserPublicKey = 10,
    U64Singleton = 11,
    U64CounterSingleton = 12,
    ContractStateTreeHeight = 13,
    CheckpointIdToPendingId = 14,
    PendingIdToCheckpointId = 15,
    PendingIdToPendingProcId = 16,
    RealmRewardsTreeNodeKey = 17,
    PublicKeyHashToUserIds = 18,
    GlobalUserTree = 19,
    UserContractTree = 20,
    ContractStateTree = 21,
    GlobalCheckpointTree = 22,
    GutaRewardTagTree = 23,
    UserRegistrationTree = 24,
    GlobalContractTree = 25,
    ContractFunctionTree = 26,
    ContractLeaf = 27,
    ContractCodeDefinition = 28,
    CheckpointZkProofAndTransition = 29,
    ImtLeaf = 30,
    ImtKeyIndex = 31,
    ImtNextAppendIndex = 32,
}

impl PsyLogicalTableId {
    pub const fn routing_key(self) -> u64 {
        self as u16 as u64
    }

    pub const fn table_name(self) -> &'static str {
        match self {
            Self::CheckpointLeaf => "checkpoint_leaf_table",
            Self::CheckpointRootToCheckpointId => "checkpoint_root_to_checkpoint_id_table",
            Self::CheckpointLeafToCheckpointId => "checkpoint_leaf_to_checkpoint_id_table",
            Self::L2BlockState => "l2_block_state_table",
            Self::CheckpointIdToRealmRoot => "checkpoint_id_to_realm_root_table",
            Self::LatestInfo => "latest_info_table",
            Self::CheckpointedObject => "checkpointed_object_table",
            Self::CheckpointStateRoots => "checkpoint_state_roots_table",
            Self::UserLeaf => "user_leaf_table",
            Self::UserPublicKey => "user_public_key_table",
            Self::U64Singleton => "u64_singleton_table",
            Self::U64CounterSingleton => "u64_counter_singleton_table",
            Self::ContractStateTreeHeight => "contract_state_tree_height_table",
            Self::CheckpointIdToPendingId => "checkpoint_id_to_pending_id_table",
            Self::PendingIdToCheckpointId => "pending_id_to_checkpoint_id_table",
            Self::PendingIdToPendingProcId => "pending_id_to_pending_proc_id_table",
            Self::RealmRewardsTreeNodeKey => "realm_rewards_tree_node_key_table",
            Self::PublicKeyHashToUserIds => "public_key_hash_to_user_ids_table",
            Self::GlobalUserTree => "global_user_tree_table",
            Self::UserContractTree => "user_contract_tree_table",
            Self::ContractStateTree => "contract_state_tree_table",
            Self::GlobalCheckpointTree => "global_checkpoint_tree_table",
            Self::GutaRewardTagTree => "guta_reward_tag_tree_table",
            Self::UserRegistrationTree => "user_registration_tree_table",
            Self::GlobalContractTree => "global_contract_tree_table",
            Self::ContractFunctionTree => "contract_function_tree_table",
            Self::ContractLeaf => "contract_leaf_table",
            Self::ContractCodeDefinition => "contract_code_definition_table",
            Self::CheckpointZkProofAndTransition => "checkpoint_zk_proof_and_transition_table",
            Self::ImtLeaf => "imt_leaf_table",
            Self::ImtKeyIndex => "imt_key_index_table",
            Self::ImtNextAppendIndex => "imt_next_append_index_table",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointIdOutOfRange(pub u64);

impl fmt::Display for CheckpointIdOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checkpoint id {} exceeds the unambiguous Scylla BIGINT range 0..={}",
            self.0,
            i64::MAX
        )
    }
}

impl Error for CheckpointIdOutOfRange {}

/// A checkpoint that can be represented without aliasing in current CQL.
///
/// ```
/// use psy_node_core::store::typed::{CheckpointId, UniquePendingId};
/// let checkpoint = CheckpointId::try_new(7).unwrap();
/// let pending = UniquePendingId::try_new(7).unwrap();
/// assert_eq!(checkpoint.get(), pending.get());
/// ```
///
/// ```compile_fail
/// use psy_node_core::store::typed::{CheckpointId, UniquePendingId};
/// let checkpoint = CheckpointId::try_new(7).unwrap();
/// let _pending: UniquePendingId = checkpoint;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CheckpointId(u64);

impl CheckpointId {
    pub const fn try_new(value: u64) -> Result<Self, CheckpointIdOutOfRange> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(CheckpointIdOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

macro_rules! semantic_u64 {
    ($($(#[$meta:meta])* $name:ident),+ $(,)?) => {
        $(
            $(#[$meta])*
            #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
            pub struct $name(u64);

            impl $name {
                pub const fn new(value: u64) -> Self {
                    Self(value)
                }

                pub const fn get(self) -> u64 {
                    self.0
                }
            }
        )+
    };
}

semantic_u64!(
    UserId,
    ContractId,
    RealmId,
    TreeId,
    TreeSubId,
    LeafIndex,
    NodeIndex,
);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UniquePendingIdOutOfRange(pub u64);

impl fmt::Display for UniquePendingIdOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unique pending id {} exceeds the unambiguous Scylla BIGINT range 0..={}",
            self.0,
            i64::MAX
        )
    }
}

impl Error for UniquePendingIdOutOfRange {}

/// A unique-pending namespace that cannot alias in current CQL BIGINT keys.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct UniquePendingId(u64);

impl UniquePendingId {
    pub const fn try_new(value: u64) -> Result<Self, UniquePendingIdOutOfRange> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(UniquePendingIdOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProcCheckpointUniqueId([u8; 16]);

impl ProcCheckpointUniqueId {
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub const fn from_u128(value: u128) -> Self {
        Self(value.to_be_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub const fn as_u128(self) -> u128 {
        u128::from_be_bytes(self.0)
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CheckpointRootKey(Vec<u8>);

impl CheckpointRootKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CheckpointLeafKey(Vec<u8>);

impl CheckpointLeafKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicKeyHash(Vec<u8>);

impl PublicKeyHash {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MerkleNode {
    level: u8,
    index: NodeIndex,
}

impl MerkleNode {
    pub const fn new(level: u8, index: NodeIndex) -> Self {
        Self { level, index }
    }

    pub const fn level(self) -> u8 {
        self.level
    }

    pub const fn index(self) -> NodeIndex {
        self.index
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum LatestInfoSlot {
    LatestL2BlockState = 1,
    /// Legacy/read-only checkpoint-tree root slot. It remains part of the
    /// physical key domain even though the current v3 writer does not update it.
    LatestCheckpointTreeRoot = 2,
    /// Realm-local exact branch/root publication marker.
    RealmAuthorityObservation = 3,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum U64SingletonSlot {
    LatestCheckpoint = 1,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum U64CounterSlot {
    UniquePending = 2,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImtEncodedKey([u8; 32]);

impl ImtEncodedKey {
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn bucket(&self) -> u16 {
        u16::from_be_bytes([self.0[0], self.0[1]])
    }

    /// Converts the semantic unsigned bucket to the order-preserving signed
    /// representation currently bound to CQL SMALLINT.
    pub const fn cql_bucket(&self) -> i16 {
        (self.bucket() ^ 0x8000) as i16
    }
}

/// Logical sub-tables sharing `checkpointed_object_table`.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum CheckpointedObjectKey {
    GlobalUserProofAtCheckpoint(CheckpointId),
    RewardsProofAtCheckpoint(CheckpointId),
    RewardsProofAtPending(UniquePendingId),
    ContractStateProofAtCheckpoint(CheckpointId),
}

/// A table/domain-specific primary key.  No variant exposes a generic
/// `(u64, u64)` key, so checkpoint and pending namespaces cannot be silently
/// interchanged before the Scylla resolver validates them.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TypedTableKey {
    CheckpointLeaf(CheckpointId),
    CheckpointRootByHash(CheckpointRootKey),
    CheckpointRootByCheckpoint(CheckpointId),
    CheckpointLeafByHash(CheckpointLeafKey),
    CheckpointLeafByCheckpoint(CheckpointId),
    L2BlockState(CheckpointId),
    UnusedCheckpointRealmRoot(CheckpointId),
    LatestInfo(LatestInfoSlot),
    CheckpointedObject(CheckpointedObjectKey),
    CheckpointStateRoots(CheckpointId),
    UserLeaf { user: UserId, checkpoint: CheckpointId },
    UserPublicKey { user: UserId, checkpoint: CheckpointId },
    U64Singleton(U64SingletonSlot),
    U64Counter(U64CounterSlot),
    ContractStateTreeHeight { contract: ContractId, checkpoint: CheckpointId },
    CheckpointToPending(CheckpointId),
    PendingToCheckpoint(UniquePendingId),
    PendingToProc(UniquePendingId),
    ProcToPending(ProcCheckpointUniqueId),
    RealmRewardNode { realm: RealmId, pending: UniquePendingId },
    PublicKeyToUser { public_key_hash: PublicKeyHash, user: UserId },
    GlobalUserMerkle { node: MerkleNode, checkpoint: CheckpointId },
    UserContractMerkle { user: UserId, node: MerkleNode, checkpoint: CheckpointId },
    ContractStateMerkle {
        user: UserId,
        contract: ContractId,
        node: MerkleNode,
        checkpoint: CheckpointId,
    },
    GlobalCheckpointMerkle { node: MerkleNode, checkpoint: CheckpointId },
    RewardTagMerkle { pending: UniquePendingId, node: MerkleNode },
    UserRegistrationMerkle { node: MerkleNode, checkpoint: CheckpointId },
    GlobalContractMerkle { node: MerkleNode, checkpoint: CheckpointId },
    ContractFunctionMerkle { contract: ContractId, node: MerkleNode, checkpoint: CheckpointId },
    ContractLeaf { contract: ContractId, checkpoint: CheckpointId },
    ContractCodeDefinition { contract: ContractId, checkpoint: CheckpointId },
    CheckpointZkProof(CheckpointId),
    ImtLeaf {
        tree: TreeId,
        tree_sub: TreeSubId,
        leaf: LeafIndex,
        checkpoint: CheckpointId,
    },
    ImtKeyIndex { tree: TreeId, tree_sub: TreeSubId, encoded_key: ImtEncodedKey },
    ImtCursor { tree: TreeId, tree_sub: TreeSubId },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ValueDigestAlgorithm {
    Sha256 = 1,
}

/// Structured multi-column payloads whose wire format is owned by a table
/// adapter rather than by one scalar CQL value column.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StructuredValueSchema {
    TagTreeNodeV1 = 1,
    ImtLeafRowV1 = 2,
    ImtKeyIndexRowV1 = 3,
}

/// The stable wire contract between a key domain and its mutation value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationValueKind {
    PsyCanonicalBytes,
    CqlU64,
    CqlU128,
    KeyOnly,
    Structured(StructuredValueSchema),
    Digest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationValue {
    /// Bytes emitted by the existing Psy canonical serializer.  Primitive
    /// integers in this representation are little-endian.
    PsyCanonicalBytes(Vec<u8>),
    /// A value bound to an existing CQL BIGINT value column.
    CqlU64(u64),
    /// A value bound through the existing u128/UUID table adapter.
    CqlU128(u128),
    /// The row has no non-key value columns (for example hash-to-many).
    KeyOnly,
    /// Canonical bytes for a known multi-column row shape.  The schema tag is
    /// part of the mutation encoding, so unrelated structured rows cannot be
    /// silently interchanged.
    Structured { schema: StructuredValueSchema, canonical_bytes: Vec<u8> },
    /// A content commitment when a caller intentionally records only a value
    /// digest.  It is not an executable CQL payload.
    Digest { algorithm: ValueDigestAlgorithm, digest: [u8; 32] },
}

impl MutationValue {
    pub const fn kind(&self) -> MutationValueKind {
        match self {
            Self::PsyCanonicalBytes(_) => MutationValueKind::PsyCanonicalBytes,
            Self::CqlU64(_) => MutationValueKind::CqlU64,
            Self::CqlU128(_) => MutationValueKind::CqlU128,
            Self::KeyOnly => MutationValueKind::KeyOnly,
            Self::Structured { schema, .. } => MutationValueKind::Structured(*schema),
            Self::Digest { .. } => MutationValueKind::Digest,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationOperation {
    Put(MutationValue),
    Delete,
}

/// An intent before Scylla physical expansion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LogicalMutation {
    Put { key: TypedTableKey, value: MutationValue },
    Delete { key: TypedTableKey },
    CheckpointRootMapping { root: CheckpointRootKey, checkpoint: CheckpointId },
    CheckpointLeafMapping { leaf: CheckpointLeafKey, checkpoint: CheckpointId },
    PendingProcMapping { pending: UniquePendingId, proc_id: ProcCheckpointUniqueId },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::psy_core_db::core_implementation::constants::{
        LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT,
        LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE,
        LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION,
    };

    #[test]
    fn checkpoint_id_rejects_current_cql_alias_range() {
        assert_eq!(CheckpointId::try_new(i64::MAX as u64).unwrap().get(), i64::MAX as u64);
        assert_eq!(CheckpointId::try_new(i64::MAX as u64 + 1), Err(CheckpointIdOutOfRange(i64::MAX as u64 + 1)));
    }

    #[test]
    fn unique_pending_id_rejects_current_cql_alias_range() {
        assert_eq!(UniquePendingId::try_new(i64::MAX as u64).unwrap().get(), i64::MAX as u64);
        assert_eq!(
            UniquePendingId::try_new(i64::MAX as u64 + 1),
            Err(UniquePendingIdOutOfRange(i64::MAX as u64 + 1))
        );
    }

    #[test]
    fn imt_bucket_conversion_preserves_unsigned_order() {
        for (bucket, expected) in [(0_u16, i16::MIN), (32767, -1), (32768, 0), (65535, i16::MAX)] {
            let mut bytes = [0_u8; 32];
            bytes[..2].copy_from_slice(&bucket.to_be_bytes());
            assert_eq!(ImtEncodedKey::new(bytes).cql_bucket(), expected);
        }
    }

    #[test]
    fn latest_info_typed_slots_match_the_production_kiv_keys() {
        assert_eq!(
            LatestInfoSlot::LatestL2BlockState as u64,
            LATEST_INFO_TABLE_OBJ_ID_LATEST_L2_BLOCK_STATE
        );
        assert_eq!(
            LatestInfoSlot::LatestCheckpointTreeRoot as u64,
            LATEST_INFO_TABLE_OBJ_ID_LATEST_CHECKPOINT_TREE_ROOT
        );
        assert_eq!(
            LatestInfoSlot::RealmAuthorityObservation as u64,
            LATEST_INFO_TABLE_OBJ_ID_REALM_AUTHORITY_OBSERVATION
        );
    }
}
