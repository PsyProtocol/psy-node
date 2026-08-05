use psy_node_core::store::typed::{MutationValueKind, PsyLogicalTableId, StructuredValueSchema};
use strum::IntoEnumIterator;

use super::{ScyllaKeyDomain, ScyllaPhysicalTableId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScyllaKeyspaceKind {
    Standard,
    NoTablet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScyllaSchemaFamily {
    Kiv,
    Blob,
    ObjectSingle,
    U64,
    Counter,
    U64ToU128,
    U128ToU64,
    HashToMany,
    MerkleZero,
    MerkleSingle,
    MerkleDouble,
    TagTree,
    ImtLeaf,
    ImtKeyIndex,
    ImtCursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CqlPrimaryKeyShape {
    pub cql: &'static str,
    pub partition: &'static [&'static str],
    pub clustering: &'static [&'static str],
}

impl ScyllaSchemaFamily {
    pub const fn implementation(self) -> &'static str {
        match self {
            Self::Kiv => "ScyllaGenericKeyIdValueTablePreparedStatements",
            Self::Blob => "ScyllaBlobToBlobTablePreparedStatements",
            Self::ObjectSingle => "ScyllaGenericObjectSingleIdTablePreparedStatements",
            Self::U64 => "ScyllaU64ToU64TablePreparedStatements",
            Self::Counter => "ScyllaU64ToU64CounterTablePreparedStatements",
            Self::U64ToU128 => "ScyllaU64ToU128TablePreparedStatements",
            Self::U128ToU64 => "ScyllaU128ToU64TablePreparedStatements",
            Self::HashToMany => "ScyllaHashToManyIdsTablePreparedStatements",
            Self::MerkleZero => "ScyllaMerkleNodesZeroPreparedStatements",
            Self::MerkleSingle => "ScyllaMerkleNodesPreparedStatements",
            Self::MerkleDouble => "ScyllaDoubleMerkleNodesPreparedStatements",
            Self::TagTree => "ScyllaTagTreeNodesPreparedStatements",
            Self::ImtLeaf => "ScyllaIMTLeafPreparedStatements",
            Self::ImtKeyIndex => "ScyllaIMTKeyIndexPreparedStatements",
            Self::ImtCursor => "ScyllaIMTNextAppendIndexPreparedStatements",
        }
    }

    pub const fn primary_key(self) -> CqlPrimaryKeyShape {
        match self {
            Self::Kiv | Self::U64 | Self::Counter | Self::U64ToU128 => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((obj_id))",
                partition: &["obj_id BIGINT"],
                clustering: &[],
            },
            Self::Blob => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((obj_id))",
                partition: &["obj_id BLOB"],
                clustering: &[],
            },
            Self::ObjectSingle => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((obj_id), checkpoint_id)",
                partition: &["obj_id BIGINT"],
                clustering: &["checkpoint_id BIGINT DESC"],
            },
            Self::U128ToU64 => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((obj_id))",
                partition: &["obj_id UUID"],
                clustering: &[],
            },
            Self::HashToMany => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY (hash_id, value_u64)",
                partition: &["hash_id BLOB"],
                clustering: &["value_u64 BIGINT ASC"],
            },
            Self::MerkleZero => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((level), node_index, checkpoint_id)",
                partition: &["level TINYINT"],
                clustering: &["node_index BIGINT ASC", "checkpoint_id BIGINT DESC"],
            },
            Self::MerkleSingle => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((tree_id), level, node_index, checkpoint_id)",
                partition: &["tree_id BIGINT"],
                clustering: &["level TINYINT ASC", "node_index BIGINT ASC", "checkpoint_id BIGINT DESC"],
            },
            Self::MerkleDouble => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((tree_id, tree_sub_id), level, node_index, checkpoint_id)",
                partition: &["tree_id BIGINT", "tree_sub_id BIGINT"],
                clustering: &["level TINYINT ASC", "node_index BIGINT ASC", "checkpoint_id BIGINT DESC"],
            },
            Self::TagTree => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((unique_pending_id), level, node_index)",
                partition: &["unique_pending_id BIGINT"],
                clustering: &["level TINYINT ASC", "node_index BIGINT ASC"],
            },
            Self::ImtLeaf => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((tree_id, tree_sub_id, leaf_index), checkpoint_id)",
                partition: &["tree_id BIGINT", "tree_sub_id BIGINT", "leaf_index BIGINT"],
                clustering: &["checkpoint_id BIGINT DESC"],
            },
            Self::ImtKeyIndex => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((tree_id, tree_sub_id, key_bucket), encoded_key)",
                partition: &["tree_id BIGINT", "tree_sub_id BIGINT", "key_bucket SMALLINT"],
                clustering: &["encoded_key BLOB ASC"],
            },
            Self::ImtCursor => CqlPrimaryKeyShape {
                cql: "PRIMARY KEY ((tree_id, tree_sub_id))",
                partition: &["tree_id BIGINT", "tree_sub_id BIGINT"],
                clustering: &[],
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityScope {
    Coordinator,
    Realm,
    Shared,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageClassification {
    Authoritative,
    Derived,
    Operational,
    Unused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPattern {
    ReaderWriter,
    WriterOnly,
    Unused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedUpdateCoverage {
    Direct,
    Indirect,
    None,
}

/// Domain-level classification refines a physical descriptor where one table
/// contains both canonical-derived and operational key spaces.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDomainClassification {
    Authoritative,
    Derived,
    Operational,
    DerivedOperational,
    Unused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DomainPreparedUpdateCoverage {
    NotApplicable,
    Direct,
    Indirect,
    None,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PreparedCoverageByAuthority {
    pub coordinator: DomainPreparedUpdateCoverage,
    pub realm: DomainPreparedUpdateCoverage,
    pub realm_sync: DomainPreparedUpdateCoverage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VersionAxis {
    CheckpointPartition,
    CheckpointClustering,
    RootBirthPartition,
    Singleton,
    MonotonicCounter,
    ReusedCheckpointPartition,
    UniquePendingPartition,
    ProcUuidPartition,
    UniquePendingClustering,
    ContentBirth,
    MixedCheckpointPendingClustering,
    ImtBirthOrdinaryColumn,
    MutableCursor,
    NoActiveAxis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RollbackPolicy {
    ArchiveVersioned,
    DerivedBirth,
    RestoreSingleton,
    PreserveOperational,
    ByKeyDomain,
    RetireUnused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeleteStrategy {
    Point,
    VersionPartition,
    BoundedRange,
    SnapshotOnly,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    ArchiveAndSnapshot,
    ArchiveAndRebuild,
    RestoreFromTargetManifest,
    PreserveOperational,
    RotateNamespace,
    RebuildFromAuthoritative,
    Retire,
    BlockedUntilMigration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManifestRequirement {
    ExactMutation,
    PairPhysicalDirection,
    SingletonBeforeAfter,
    DerivedSupplement,
    CursorBeforeAfter,
    NoneOperational,
    NoMutationRetired,
    BlockedUntilMigration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationKind {
    CheckpointCommitment,
    BidirectionalMapping,
    NoProductionAccess,
    L2BlockState,
    TargetHeadPayload,
    MerkleRoot,
    MonotonicValue,
    OperationalMapping,
    RealmRewardMaterialization,
    PublicKeyProjection,
    ZkProofCommitment,
    ImtRoot,
    ImtIndexRebuild,
    ImtCursor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryBlocker {
    MixedCheckpointPendingAxis,
    ReusableCheckpointHeightKey,
    PendingSuffixReadThrough,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryReadiness {
    Ready,
    Blocked(RegistryBlocker),
    RetireCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryReadinessError {
    Blocked(RegistryBlocker),
    RetireCandidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PhysicalTableDescriptor {
    pub id: ScyllaPhysicalTableId,
    pub logical_owner: PsyLogicalTableId,
    pub physical_name: &'static str,
    pub suffix: &'static str,
    pub routing_key: u64,
    pub keyspace: ScyllaKeyspaceKind,
    pub schema_family: ScyllaSchemaFamily,
    pub authority: AuthorityScope,
    pub classification: StorageClassification,
    pub access: AccessPattern,
    pub prepared_coverage: PreparedUpdateCoverage,
    pub version_axis: VersionAxis,
    pub rollback_policy: RollbackPolicy,
    pub delete_candidates: &'static [DeleteStrategy],
    pub recovery_action: RecoveryAction,
    pub manifest_requirement: ManifestRequirement,
    pub verification: VerificationKind,
    pub readiness: RegistryReadiness,
    pub reader_symbols: &'static [&'static str],
    pub writer_symbols: &'static [&'static str],
}

impl PhysicalTableDescriptor {
    pub const fn cql_primary_key(self) -> CqlPrimaryKeyShape {
        self.schema_family.primary_key()
    }

    pub const fn rust_implementation(self) -> &'static str {
        self.schema_family.implementation()
    }

    pub const fn require_rollback_ready(self) -> Result<(), RegistryReadinessError> {
        match self.readiness {
            RegistryReadiness::Ready => Ok(()),
            RegistryReadiness::Blocked(blocker) => Err(RegistryReadinessError::Blocked(blocker)),
            RegistryReadiness::RetireCandidate => Err(RegistryReadinessError::RetireCandidate),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyDomainDescriptor {
    pub id: ScyllaKeyDomain,
    pub physical_table: ScyllaPhysicalTableId,
    pub logical_owner: PsyLogicalTableId,
    pub logical_subtable: &'static str,
    pub authority: AuthorityScope,
    pub classification: KeyDomainClassification,
    pub prepared_coverage: PreparedCoverageByAuthority,
    pub version_axis: VersionAxis,
    pub rollback_policy: RollbackPolicy,
    pub recovery_action: RecoveryAction,
    pub manifest_requirement: ManifestRequirement,
    pub allowed_put_values: &'static [MutationValueKind],
    pub readiness: RegistryReadiness,
}

impl KeyDomainDescriptor {
    pub const fn require_rollback_ready(self) -> Result<(), RegistryReadinessError> {
        match self.readiness {
            RegistryReadiness::Ready => Ok(()),
            RegistryReadiness::Blocked(blocker) => Err(RegistryReadinessError::Blocked(blocker)),
            RegistryReadiness::RetireCandidate => Err(RegistryReadinessError::RetireCandidate),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SetupInitializer {
    Standard(ScyllaSchemaFamily),
    NoTabletCounter,
    BlobBidirectional,
    U64U128Bidirectional,
    ZeroMerkle,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LogicalSetupSpec {
    pub logical_id: PsyLogicalTableId,
    pub table_name: &'static str,
    pub routing_key: u64,
    pub keyspace: ScyllaKeyspaceKind,
    pub initializer: SetupInitializer,
}

/// Capabilities of the production table adapters at the D-02a baseline.
/// D-02T must flip these only after every affected INSERT/batch and delete
/// path is migrated and tested.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProductionCqlCapabilities {
    pub explicit_write_timestamp: bool,
    pub delete_adapter: bool,
}

pub const PRODUCTION_CQL_CAPABILITIES: ProductionCqlCapabilities = ProductionCqlCapabilities {
    explicit_write_timestamp: false,
    delete_adapter: false,
};

pub const fn logical_setup_spec(id: PsyLogicalTableId) -> LogicalSetupSpec {
    let (keyspace, initializer) = match id {
        PsyLogicalTableId::CheckpointLeaf => (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::Kiv)),
        PsyLogicalTableId::CheckpointRootToCheckpointId | PsyLogicalTableId::CheckpointLeafToCheckpointId => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::BlobBidirectional)
        }
        PsyLogicalTableId::L2BlockState
        | PsyLogicalTableId::CheckpointIdToRealmRoot
        | PsyLogicalTableId::LatestInfo
        | PsyLogicalTableId::CheckpointStateRoots
        | PsyLogicalTableId::CheckpointZkProofAndTransition => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::Kiv))
        }
        PsyLogicalTableId::CheckpointedObject
        | PsyLogicalTableId::UserLeaf
        | PsyLogicalTableId::UserPublicKey
        | PsyLogicalTableId::ContractStateTreeHeight
        | PsyLogicalTableId::RealmRewardsTreeNodeKey
        | PsyLogicalTableId::ContractLeaf
        | PsyLogicalTableId::ContractCodeDefinition => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::ObjectSingle))
        }
        PsyLogicalTableId::U64Singleton
        | PsyLogicalTableId::CheckpointIdToPendingId
        | PsyLogicalTableId::PendingIdToCheckpointId => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::U64))
        }
        PsyLogicalTableId::U64CounterSingleton => (ScyllaKeyspaceKind::NoTablet, SetupInitializer::NoTabletCounter),
        PsyLogicalTableId::PendingIdToPendingProcId => (ScyllaKeyspaceKind::Standard, SetupInitializer::U64U128Bidirectional),
        PsyLogicalTableId::PublicKeyHashToUserIds => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::HashToMany))
        }
        PsyLogicalTableId::GlobalUserTree
        | PsyLogicalTableId::GlobalCheckpointTree
        | PsyLogicalTableId::UserRegistrationTree
        | PsyLogicalTableId::GlobalContractTree => (ScyllaKeyspaceKind::Standard, SetupInitializer::ZeroMerkle),
        PsyLogicalTableId::UserContractTree | PsyLogicalTableId::ContractFunctionTree => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::MerkleSingle))
        }
        PsyLogicalTableId::ContractStateTree => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::MerkleDouble))
        }
        PsyLogicalTableId::GutaRewardTagTree => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::TagTree))
        }
        PsyLogicalTableId::ImtLeaf => (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::ImtLeaf)),
        PsyLogicalTableId::ImtKeyIndex => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::ImtKeyIndex))
        }
        PsyLogicalTableId::ImtNextAppendIndex => {
            (ScyllaKeyspaceKind::Standard, SetupInitializer::Standard(ScyllaSchemaFamily::ImtCursor))
        }
    };
    LogicalSetupSpec { logical_id: id, table_name: id.table_name(), routing_key: id.routing_key(), keyspace, initializer }
}

pub fn setup_catalog() -> Vec<LogicalSetupSpec> {
    PsyLogicalTableId::iter().map(logical_setup_spec).collect()
}

pub const fn physical_tables(id: PsyLogicalTableId) -> &'static [ScyllaPhysicalTableId] {
    use ScyllaPhysicalTableId as P;
    match id {
        PsyLogicalTableId::CheckpointLeaf => &[P::CheckpointLeaf],
        PsyLogicalTableId::CheckpointRootToCheckpointId => &[P::CheckpointRootToCheckpointIdK1, P::CheckpointRootToCheckpointIdK2],
        PsyLogicalTableId::CheckpointLeafToCheckpointId => &[P::CheckpointLeafToCheckpointIdK1, P::CheckpointLeafToCheckpointIdK2],
        PsyLogicalTableId::L2BlockState => &[P::L2BlockState],
        PsyLogicalTableId::CheckpointIdToRealmRoot => &[P::CheckpointIdToRealmRoot],
        PsyLogicalTableId::LatestInfo => &[P::LatestInfo],
        PsyLogicalTableId::CheckpointedObject => &[P::CheckpointedObject],
        PsyLogicalTableId::CheckpointStateRoots => &[P::CheckpointStateRoots],
        PsyLogicalTableId::UserLeaf => &[P::UserLeaf],
        PsyLogicalTableId::UserPublicKey => &[P::UserPublicKey],
        PsyLogicalTableId::U64Singleton => &[P::U64Singleton],
        PsyLogicalTableId::U64CounterSingleton => &[P::U64CounterSingleton],
        PsyLogicalTableId::ContractStateTreeHeight => &[P::ContractStateTreeHeight],
        PsyLogicalTableId::CheckpointIdToPendingId => &[P::CheckpointIdToPendingId],
        PsyLogicalTableId::PendingIdToCheckpointId => &[P::PendingIdToCheckpointId],
        PsyLogicalTableId::PendingIdToPendingProcId => {
            &[P::PendingIdToPendingProcIdU64ToU128, P::PendingIdToPendingProcIdU128ToU64]
        }
        PsyLogicalTableId::RealmRewardsTreeNodeKey => &[P::RealmRewardsTreeNodeKey],
        PsyLogicalTableId::PublicKeyHashToUserIds => &[P::PublicKeyHashToUserIds],
        PsyLogicalTableId::GlobalUserTree => &[P::GlobalUserTree],
        PsyLogicalTableId::UserContractTree => &[P::UserContractTree],
        PsyLogicalTableId::ContractStateTree => &[P::ContractStateTree],
        PsyLogicalTableId::GlobalCheckpointTree => &[P::GlobalCheckpointTree],
        PsyLogicalTableId::GutaRewardTagTree => &[P::GutaRewardTagTree],
        PsyLogicalTableId::UserRegistrationTree => &[P::UserRegistrationTree],
        PsyLogicalTableId::GlobalContractTree => &[P::GlobalContractTree],
        PsyLogicalTableId::ContractFunctionTree => &[P::ContractFunctionTree],
        PsyLogicalTableId::ContractLeaf => &[P::ContractLeaf],
        PsyLogicalTableId::ContractCodeDefinition => &[P::ContractCodeDefinition],
        PsyLogicalTableId::CheckpointZkProofAndTransition => &[P::CheckpointZkProofAndTransition],
        PsyLogicalTableId::ImtLeaf => &[P::ImtLeaf],
        PsyLogicalTableId::ImtKeyIndex => &[P::ImtKeyIndex],
        PsyLogicalTableId::ImtNextAppendIndex => &[P::ImtNextAppendIndex],
    }
}

const POINT: &[DeleteStrategy] = &[DeleteStrategy::Point, DeleteStrategy::SnapshotOnly];
const VERSION_PARTITION: &[DeleteStrategy] = &[DeleteStrategy::VersionPartition, DeleteStrategy::SnapshotOnly];
const VERSION_CLUSTERING: &[DeleteStrategy] = &[DeleteStrategy::Point, DeleteStrategy::BoundedRange, DeleteStrategy::SnapshotOnly];
const NO_DELETE: &[DeleteStrategy] = &[];

#[allow(clippy::too_many_arguments)]
const fn desc(
    id: ScyllaPhysicalTableId,
    logical_owner: PsyLogicalTableId,
    physical_name: &'static str,
    suffix: &'static str,
    keyspace: ScyllaKeyspaceKind,
    schema_family: ScyllaSchemaFamily,
    authority: AuthorityScope,
    classification: StorageClassification,
    access: AccessPattern,
    prepared_coverage: PreparedUpdateCoverage,
    version_axis: VersionAxis,
    rollback_policy: RollbackPolicy,
    delete_candidates: &'static [DeleteStrategy],
    recovery_action: RecoveryAction,
    manifest_requirement: ManifestRequirement,
    verification: VerificationKind,
    readiness: RegistryReadiness,
    reader_symbols: &'static [&'static str],
    writer_symbols: &'static [&'static str],
) -> PhysicalTableDescriptor {
    PhysicalTableDescriptor {
        id,
        logical_owner,
        physical_name,
        suffix,
        routing_key: logical_owner.routing_key(),
        keyspace,
        schema_family,
        authority,
        classification,
        access,
        prepared_coverage,
        version_axis,
        rollback_policy,
        delete_candidates,
        recovery_action,
        manifest_requirement,
        verification,
        readiness,
        reader_symbols,
        writer_symbols,
    }
}

/// Returns the exhaustive descriptor for one of the 35 registered physical
/// tables.  The match intentionally has no wildcard arm.
pub const fn physical_descriptor(id: ScyllaPhysicalTableId) -> PhysicalTableDescriptor {
    use AccessPattern::{ReaderWriter as RW, Unused as AU, WriterOnly as WO};
    use AuthorityScope::{Coordinator as C, Realm as R, Shared as S};
    use ManifestRequirement::{BlockedUntilMigration as MB, CursorBeforeAfter as MC, DerivedSupplement as MD, ExactMutation as ME, NoMutationRetired as MR, NoneOperational as MO, PairPhysicalDirection as MP, SingletonBeforeAfter as MS};
    use PreparedUpdateCoverage::{Direct as PD, Indirect as PI, None as PN};
    use RecoveryAction::{ArchiveAndRebuild as RR, ArchiveAndSnapshot as RA, BlockedUntilMigration as RB, PreserveOperational as RP, RebuildFromAuthoritative as RD, RestoreFromTargetManifest as RT, Retire as RE, RotateNamespace as RN};
    use RegistryBlocker::{MixedCheckpointPendingAxis as BM, PendingSuffixReadThrough as BR, ReusableCheckpointHeightKey as BH};
    use RegistryReadiness::{Blocked as BlockedR, Ready, RetireCandidate};
    use RollbackPolicy::{ArchiveVersioned as AV, ByKeyDomain as BK, DerivedBirth as DB, PreserveOperational as PO, RestoreSingleton as RS, RetireUnused as RU};
    use ScyllaPhysicalTableId as P;
    use ScyllaSchemaFamily::{Blob, Counter, HashToMany, ImtCursor, ImtKeyIndex, ImtLeaf, Kiv, MerkleDouble, MerkleSingle, MerkleZero, ObjectSingle, TagTree, U128ToU64, U64, U64ToU128};
    use StorageClassification::{Authoritative as A, Derived as D, Operational as O, Unused as U};
    use VerificationKind::{BidirectionalMapping as VB, CheckpointCommitment as VC, ImtCursor as VIc, ImtIndexRebuild as VIi, ImtRoot as VIr, L2BlockState as VL, MerkleRoot as VM, MonotonicValue as VV, NoProductionAccess as VN, OperationalMapping as VO, PublicKeyProjection as VP, RealmRewardMaterialization as VR, TargetHeadPayload as VH, ZkProofCommitment as VZ};
    use VersionAxis::{CheckpointClustering as XC, CheckpointPartition as XP, ContentBirth as XB, ImtBirthOrdinaryColumn as XI, MixedCheckpointPendingClustering as XM, MonotonicCounter as XN, MutableCursor as XU, NoActiveAxis as XX, ProcUuidPartition as XQ, ReusedCheckpointPartition as XR, RootBirthPartition as XH, Singleton as XS, UniquePendingClustering as XL, UniquePendingPartition as XT};

    match id {
        P::CheckpointLeaf => desc(id, PsyLogicalTableId::CheckpointLeaf, "checkpoint_leaf_table", "", ScyllaKeyspaceKind::Standard, Kiv, S, A, RW, PI, XP, AV, VERSION_PARTITION, RA, ME, VC, Ready, &["get_checkpoint_leaf_data", "try_get_complete_l2_block_state"], &["set_checkpoint_leaf_data"]),
        P::CheckpointRootToCheckpointIdK1 => desc(id, PsyLogicalTableId::CheckpointRootToCheckpointId, "checkpoint_root_to_checkpoint_id_table_k1", "_k1", ScyllaKeyspaceKind::Standard, Blob, S, D, RW, PI, XH, DB, POINT, RR, MP, VB, Ready, &["get_checkpoint_id_for_checkpoint_root_hash"], &["set_checkpoint_root_hash_to_id_mapping -> db_insert_pair_ref"]),
        P::CheckpointRootToCheckpointIdK2 => desc(id, PsyLogicalTableId::CheckpointRootToCheckpointId, "checkpoint_root_to_checkpoint_id_table_k2", "_k2", ScyllaKeyspaceKind::Standard, Blob, S, D, RW, PI, XP, DB, VERSION_PARTITION, RR, MP, VB, Ready, &["try_get_complete_l2_block_state -> db_select_one_by_k2"], &["set_checkpoint_root_hash_to_id_mapping -> db_insert_pair_ref"]),
        P::CheckpointLeafToCheckpointIdK1 => desc(id, PsyLogicalTableId::CheckpointLeafToCheckpointId, "checkpoint_leaf_to_checkpoint_id_table_k1", "_k1", ScyllaKeyspaceKind::Standard, Blob, S, U, AU, PN, XX, RU, NO_DELETE, RE, MR, VN, RetireCandidate, &[], &[]),
        P::CheckpointLeafToCheckpointIdK2 => desc(id, PsyLogicalTableId::CheckpointLeafToCheckpointId, "checkpoint_leaf_to_checkpoint_id_table_k2", "_k2", ScyllaKeyspaceKind::Standard, Blob, S, U, AU, PN, XX, RU, NO_DELETE, RE, MR, VN, RetireCandidate, &[], &[]),
        P::L2BlockState => desc(id, PsyLogicalTableId::L2BlockState, "l2_block_state_table", "", ScyllaKeyspaceKind::Standard, Kiv, S, A, RW, PI, XP, AV, VERSION_PARTITION, RA, ME, VL, Ready, &["get_l2_block_state", "try_get_complete_l2_block_state"], &["set_l2_block_state"]),
        P::CheckpointIdToRealmRoot => desc(id, PsyLogicalTableId::CheckpointIdToRealmRoot, "checkpoint_id_to_realm_root_table", "", ScyllaKeyspaceKind::Standard, Kiv, S, U, AU, PN, XX, RU, NO_DELETE, RE, MR, VN, RetireCandidate, &[], &[]),
        P::LatestInfo => desc(id, PsyLogicalTableId::LatestInfo, "latest_info_table", "", ScyllaKeyspaceKind::Standard, Kiv, S, D, RW, PI, XS, RS, NO_DELETE, RT, MS, VH, Ready, &["get_latest_l2_block_state", "get_latest_checkpoint_tree_root (reader-only slot=2)", "get_realm_authority_observation (slot=3)"], &["set_l2_latest_block_state", "set_realm_authority_observation (slot=3)"]),
        P::CheckpointedObject => desc(id, PsyLogicalTableId::CheckpointedObject, "checkpointed_object_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, R, D, RW, PI, XM, BK, NO_DELETE, RB, MB, VM, BlockedR(BM), &["try_get_complete_l2_block_state", "get_top_global_user_*_proof_*"], &["global_user_tree_set_top_tree_merkle_proof", "set_realm_rewards_tag_tree_top_proof_at_*", "contract_state_tree_set_top_tree_merkle_proof"]),
        P::CheckpointStateRoots => desc(id, PsyLogicalTableId::CheckpointStateRoots, "checkpoint_state_roots_table", "", ScyllaKeyspaceKind::Standard, Kiv, S, A, RW, PI, XP, AV, VERSION_PARTITION, RA, ME, VC, Ready, &["get_checkpoint_global_state_roots", "try_get_complete_l2_block_state"], &["set_checkpoint_global_state_roots"]),
        P::UserLeaf => desc(id, PsyLogicalTableId::UserLeaf, "user_leaf_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, R, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["get_user_leaf", "get_user_leaves_batch"], &["set_user_leaf", "set_user_leaves_ffs"]),
        P::UserPublicKey => desc(id, PsyLogicalTableId::UserPublicKey, "user_public_key_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VP, Ready, &["get_zk_public_key"], &["set_zk_public_key", "set_zk_public_keys_ffs"]),
        P::U64Singleton => desc(id, PsyLogicalTableId::U64Singleton, "u64_singleton_table", "", ScyllaKeyspaceKind::Standard, U64, S, D, RW, PI, XS, RS, NO_DELETE, RT, MS, VH, Ready, &["get_latest_checkpoint_id"], &["set_latest_checkpoint_id"]),
        P::U64CounterSingleton => desc(id, PsyLogicalTableId::U64CounterSingleton, "u64_counter_singleton_table", "", ScyllaKeyspaceKind::NoTablet, Counter, S, O, RW, PN, XN, PO, NO_DELETE, RP, MO, VV, Ready, &["get_latest_pending_id", "get_current_unique_pending_id"], &["inc_unique_pending_id"]),
        P::ContractStateTreeHeight => desc(id, PsyLogicalTableId::ContractStateTreeHeight, "contract_state_tree_height_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, S, D, RW, PI, XC, DB, VERSION_CLUSTERING, RD, MD, VM, Ready, &["get_contract_tree_heights"], &["set_contract_tree_heights"]),
        P::CheckpointIdToPendingId => desc(id, PsyLogicalTableId::CheckpointIdToPendingId, "checkpoint_id_to_pending_id_table", "", ScyllaKeyspaceKind::Standard, U64, S, O, RW, PI, XR, PO, NO_DELETE, RB, MB, VO, BlockedR(BH), &["get_unique_pending_id_for_checkpoint_id"], &["set_checkpoint_id_to_unique_pending_id_mapping"]),
        P::PendingIdToCheckpointId => desc(id, PsyLogicalTableId::PendingIdToCheckpointId, "pending_id_to_checkpoint_id_table", "", ScyllaKeyspaceKind::Standard, U64, S, O, RW, PI, XT, PO, NO_DELETE, RP, MO, VO, Ready, &["get_checkpoint_id_for_unique_pending_id"], &["set_unique_pending_id_checkpoint_id_mapping"]),
        P::PendingIdToPendingProcIdU64ToU128 => desc(id, PsyLogicalTableId::PendingIdToPendingProcId, "pending_id_to_pending_proc_id_table_u64_to_u128", "_u64_to_u128", ScyllaKeyspaceKind::Standard, U64ToU128, S, O, RW, PI, XT, PO, NO_DELETE, RP, MP, VO, Ready, &["get_unique_pending_id_for_checkpoint_id", "get_current_unique_pending_id", "get_latest_mapped_unique_pending_id"], &["inc_unique_pending_id", "set_checkpoint_id_to_unique_pending_id_mapping -> pair helper"]),
        P::PendingIdToPendingProcIdU128ToU64 => desc(id, PsyLogicalTableId::PendingIdToPendingProcId, "pending_id_to_pending_proc_id_table_u128_to_u64", "_u128_to_u64", ScyllaKeyspaceKind::Standard, U128ToU64, S, O, WO, PI, XQ, PO, NO_DELETE, RP, MP, VO, Ready, &[], &["inc_unique_pending_id", "set_checkpoint_id_to_unique_pending_id_mapping -> pair helper"]),
        P::RealmRewardsTreeNodeKey => desc(id, PsyLogicalTableId::RealmRewardsTreeNodeKey, "realm_rewards_tree_node_key_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, C, D, RW, PD, XL, BK, POINT, RB, MB, VR, BlockedR(BR), &["get_realm_guta_reward_tree_node_key (<= pending)"], &["set_realm_guta_reward_tree_node_key", "set_realm_guta_reward_tree_node_keys_ffs"]),
        P::PublicKeyHashToUserIds => desc(id, PsyLogicalTableId::PublicKeyHashToUserIds, "public_key_hash_to_user_ids_table", "", ScyllaKeyspaceKind::Standard, HashToMany, C, D, RW, PD, XB, DB, POINT, RD, MD, VP, Ready, &["get_user_ids_for_public_key"], &["set_public_key_for_user_id", "set_public_key_for_user_ids_ffs"]),
        P::GlobalUserTree => desc(id, PsyLogicalTableId::GlobalUserTree, "global_user_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleZero, S, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["global_user_tree_get_*"], &["global_user_tree_set_*"]),
        P::UserContractTree => desc(id, PsyLogicalTableId::UserContractTree, "user_contract_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleSingle, R, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["user_contract_tree_get_*"], &["user_contract_tree_set_*"] ),
        P::ContractStateTree => desc(id, PsyLogicalTableId::ContractStateTree, "contract_state_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleDouble, R, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["contract_state_tree_get_*"], &["contract_state_tree_set_*"] ),
        P::GlobalCheckpointTree => desc(id, PsyLogicalTableId::GlobalCheckpointTree, "global_checkpoint_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleZero, S, A, RW, PI, XC, AV, VERSION_CLUSTERING, RA, ME, VC, Ready, &["checkpoint_tree_get_*"], &["checkpoint_tree_set_*", "checkpoint_tree_injest_merkle_proof"]),
        P::GutaRewardTagTree => desc(id, PsyLogicalTableId::GutaRewardTagTree, "guta_reward_tag_tree_table", "", ScyllaKeyspaceKind::Standard, TagTree, S, O, RW, PN, XT, PO, NO_DELETE, RN, MO, VR, Ready, &["rewards_tag_tree_get_*_at_unique_pending_id"], &["rewards_tag_tree_set_node_*"] ),
        P::UserRegistrationTree => desc(id, PsyLogicalTableId::UserRegistrationTree, "user_registration_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleZero, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["user_registration_tree_get_*"], &["user_registration_tree_set_*"] ),
        P::GlobalContractTree => desc(id, PsyLogicalTableId::GlobalContractTree, "global_contract_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleZero, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["global_contract_tree_get_*"], &["global_contract_tree_set_*"] ),
        P::ContractFunctionTree => desc(id, PsyLogicalTableId::ContractFunctionTree, "contract_function_tree_table", "", ScyllaKeyspaceKind::Standard, MerkleSingle, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["contract_function_tree_get_*"], &["contract_function_tree_set_*"] ),
        P::ContractLeaf => desc(id, PsyLogicalTableId::ContractLeaf, "contract_leaf_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["get_contract_leaf"], &["set_contract_leaf", "set_contract_leaves_ffs"]),
        P::ContractCodeDefinition => desc(id, PsyLogicalTableId::ContractCodeDefinition, "contract_code_definition_table", "", ScyllaKeyspaceKind::Standard, ObjectSingle, C, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VM, Ready, &["get_contract_code_definition"], &["set_contract_code_definition", "set_many_contract_code_definitions"]),
        P::CheckpointZkProofAndTransition => desc(id, PsyLogicalTableId::CheckpointZkProofAndTransition, "checkpoint_zk_proof_and_transition_table", "", ScyllaKeyspaceKind::Standard, Kiv, C, A, RW, PI, XP, AV, VERSION_PARTITION, RA, ME, VZ, Ready, &["get_verifiable_checkpoint_state_transition_and_zkp"], &["set_verifiable_checkpoint_state_transition_and_zkp"]),
        P::ImtLeaf => desc(id, PsyLogicalTableId::ImtLeaf, "imt_leaf_table", "", ScyllaKeyspaceKind::Standard, ImtLeaf, R, A, RW, PD, XC, AV, VERSION_CLUSTERING, RA, ME, VIr, Ready, &["contract_state_imt_get_leaf_preimage", "contract_state_imt_find_predecessor -> leaf reads"], &["contract_state_imt_set_leaves_ffs"]),
        P::ImtKeyIndex => desc(id, PsyLogicalTableId::ImtKeyIndex, "imt_key_index_table", "", ScyllaKeyspaceKind::Standard, ImtKeyIndex, R, D, RW, PI, XI, DB, POINT, RD, MD, VIi, Ready, &["contract_state_imt_get_leaf_index_for_key", "contract_state_imt_find_predecessor"], &["contract_state_imt_set_leaves_ffs -> indirect index write"]),
        P::ImtNextAppendIndex => desc(id, PsyLogicalTableId::ImtNextAppendIndex, "imt_next_append_index_table", "", ScyllaKeyspaceKind::Standard, ImtCursor, R, D, RW, PI, XU, RS, NO_DELETE, RT, MC, VIc, Ready, &["contract_state_imt_get_next_append_index", "contract_state_imt_set_leaves_ffs -> read-before-write"], &["contract_state_imt_set_leaves_ffs -> indirect cursor write"]),
    }
}

const NA: DomainPreparedUpdateCoverage = DomainPreparedUpdateCoverage::NotApplicable;
const DD: DomainPreparedUpdateCoverage = DomainPreparedUpdateCoverage::Direct;
const DI: DomainPreparedUpdateCoverage = DomainPreparedUpdateCoverage::Indirect;
const DN: DomainPreparedUpdateCoverage = DomainPreparedUpdateCoverage::None;

const fn coverage(
    coordinator: DomainPreparedUpdateCoverage,
    realm: DomainPreparedUpdateCoverage,
    realm_sync: DomainPreparedUpdateCoverage,
) -> PreparedCoverageByAuthority {
    PreparedCoverageByAuthority { coordinator, realm, realm_sync }
}

const C_DIRECT: PreparedCoverageByAuthority = coverage(DD, NA, NA);
const C_INDIRECT: PreparedCoverageByAuthority = coverage(DI, NA, NA);
const R_DIRECT: PreparedCoverageByAuthority = coverage(NA, DD, NA);
const R_INDIRECT: PreparedCoverageByAuthority = coverage(NA, DI, NA);
const R_NONE: PreparedCoverageByAuthority = coverage(NA, DN, NA);
const R_NONE_RS_INDIRECT: PreparedCoverageByAuthority = coverage(NA, DN, DI);
const SHARED_DIRECT: PreparedCoverageByAuthority = coverage(DD, DD, NA);
const C_INDIRECT_RS_INDIRECT: PreparedCoverageByAuthority = coverage(DI, NA, DI);
const C_INDIRECT_R_INDIRECT: PreparedCoverageByAuthority = coverage(DI, DI, NA);
const SHARED_NONE: PreparedCoverageByAuthority = coverage(DN, DN, NA);
const UNUSED_COVERAGE: PreparedCoverageByAuthority = coverage(NA, NA, NA);

const PSY_VALUES: &[MutationValueKind] = &[MutationValueKind::PsyCanonicalBytes, MutationValueKind::Digest];
const U64_VALUES: &[MutationValueKind] = &[MutationValueKind::CqlU64, MutationValueKind::Digest];
const U128_VALUES: &[MutationValueKind] = &[MutationValueKind::CqlU128, MutationValueKind::Digest];
const KEY_ONLY_VALUES: &[MutationValueKind] = &[MutationValueKind::KeyOnly, MutationValueKind::Digest];
const TAG_VALUES: &[MutationValueKind] = &[
    MutationValueKind::Structured(StructuredValueSchema::TagTreeNodeV1),
    MutationValueKind::Digest,
];
const IMT_LEAF_VALUES: &[MutationValueKind] = &[
    MutationValueKind::Structured(StructuredValueSchema::ImtLeafRowV1),
    MutationValueKind::Digest,
];
const IMT_INDEX_VALUES: &[MutationValueKind] = &[
    MutationValueKind::Structured(StructuredValueSchema::ImtKeyIndexRowV1),
    MutationValueKind::Digest,
];

const fn allowed_values_for_family(family: ScyllaSchemaFamily) -> &'static [MutationValueKind] {
    match family {
        ScyllaSchemaFamily::Kiv
        | ScyllaSchemaFamily::Blob
        | ScyllaSchemaFamily::ObjectSingle
        | ScyllaSchemaFamily::MerkleZero
        | ScyllaSchemaFamily::MerkleSingle
        | ScyllaSchemaFamily::MerkleDouble => PSY_VALUES,
        ScyllaSchemaFamily::U64
        | ScyllaSchemaFamily::Counter
        | ScyllaSchemaFamily::U128ToU64
        | ScyllaSchemaFamily::ImtCursor => U64_VALUES,
        ScyllaSchemaFamily::U64ToU128 => U128_VALUES,
        ScyllaSchemaFamily::HashToMany => KEY_ONLY_VALUES,
        ScyllaSchemaFamily::TagTree => TAG_VALUES,
        ScyllaSchemaFamily::ImtLeaf => IMT_LEAF_VALUES,
        ScyllaSchemaFamily::ImtKeyIndex => IMT_INDEX_VALUES,
    }
}

#[allow(clippy::too_many_arguments)]
const fn domain_desc(
    id: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
    logical_subtable: &'static str,
    classification: KeyDomainClassification,
    prepared_coverage: PreparedCoverageByAuthority,
    version_axis: VersionAxis,
    rollback_policy: RollbackPolicy,
    recovery_action: RecoveryAction,
    manifest_requirement: ManifestRequirement,
    allowed_put_values: &'static [MutationValueKind],
    readiness: RegistryReadiness,
) -> KeyDomainDescriptor {
    let physical = physical_descriptor(physical_table);
    KeyDomainDescriptor {
        id,
        physical_table,
        logical_owner: physical.logical_owner,
        logical_subtable,
        authority: physical.authority,
        classification,
        prepared_coverage,
        version_axis,
        rollback_policy,
        recovery_action,
        manifest_requirement,
        allowed_put_values,
        readiness,
    }
}

const fn domain_from_physical(
    id: ScyllaKeyDomain,
    physical_table: ScyllaPhysicalTableId,
    logical_subtable: &'static str,
    classification: KeyDomainClassification,
    prepared_coverage: PreparedCoverageByAuthority,
) -> KeyDomainDescriptor {
    let physical = physical_descriptor(physical_table);
    domain_desc(
        id,
        physical_table,
        logical_subtable,
        classification,
        prepared_coverage,
        physical.version_axis,
        physical.rollback_policy,
        physical.recovery_action,
        physical.manifest_requirement,
        allowed_values_for_family(physical.schema_family),
        physical.readiness,
    )
}

/// Returns the exhaustive logical-subtable/key-domain contract.  This layer
/// deliberately refines physical metadata for mixed derived/operational and
/// authority-specific PreparedUpdate paths.
pub const fn key_domain_descriptor(id: ScyllaKeyDomain) -> KeyDomainDescriptor {
    use KeyDomainClassification::{Authoritative as A, Derived as D, DerivedOperational as DO, Operational as O, Unused as U};
    use ManifestRequirement::{BlockedUntilMigration as MB, NoneOperational as MO};
    use RecoveryAction::{BlockedUntilMigration as RB, RotateNamespace as RN};
    use RegistryBlocker::MixedCheckpointPendingAxis as BM;
    use RegistryReadiness::Blocked;
    use RollbackPolicy::{ArchiveVersioned as AV, PreserveOperational as PO};
    use ScyllaKeyDomain as K;
    use ScyllaPhysicalTableId as P;
    use VersionAxis::{CheckpointClustering as XC, UniquePendingClustering as XL};

    match id {
        K::CheckpointLeaf => domain_from_physical(id, P::CheckpointLeaf, "checkpoint leaf", A, C_INDIRECT_RS_INDIRECT),
        K::CheckpointRootByHash => domain_from_physical(id, P::CheckpointRootToCheckpointIdK1, "root -> checkpoint", D, C_INDIRECT_RS_INDIRECT),
        K::CheckpointRootByCheckpoint => domain_from_physical(id, P::CheckpointRootToCheckpointIdK2, "checkpoint -> root", D, C_INDIRECT_RS_INDIRECT),
        K::CheckpointLeafByHash => domain_from_physical(id, P::CheckpointLeafToCheckpointIdK1, "unused leaf -> checkpoint", U, UNUSED_COVERAGE),
        K::CheckpointLeafByCheckpoint => domain_from_physical(id, P::CheckpointLeafToCheckpointIdK2, "unused checkpoint -> leaf", U, UNUSED_COVERAGE),
        K::L2BlockState => domain_from_physical(id, P::L2BlockState, "L2 block state", A, C_INDIRECT_RS_INDIRECT),
        K::UnusedCheckpointRealmRoot => domain_from_physical(id, P::CheckpointIdToRealmRoot, "unused checkpoint realm root", U, UNUSED_COVERAGE),
        K::LatestInfo => domain_from_physical(id, P::LatestInfo, "mutable latest-info slots", DO, C_INDIRECT_RS_INDIRECT),
        K::RealmAuthorityObservation => {
            domain_from_physical(id, P::LatestInfo, "Realm canonical/local-state observation slot=3", A, R_INDIRECT)
        }
        K::CheckpointedGlobalUserProof => domain_desc(id, P::CheckpointedObject, "obj_id=1 checkpoint proof", D, R_NONE_RS_INDIRECT, XC, AV, RB, MB, PSY_VALUES, Blocked(BM)),
        K::CheckpointedRewardsProofAtCheckpoint => {
            domain_desc(id, P::CheckpointedObject, "obj_id=2 checkpoint reward proof", D, R_NONE, XC, AV, RB, MB, PSY_VALUES, Blocked(BM))
        }
        K::CheckpointedRewardsProofAtPending => domain_desc(id, P::CheckpointedObject, "obj_id=2 pending reward proof", O, R_NONE, XL, PO, RN, MO, PSY_VALUES, Blocked(BM)),
        K::CheckpointedContractStateProof => domain_desc(id, P::CheckpointedObject, "obj_id=3 checkpoint contract-state proof", D, R_NONE, XC, AV, RB, MB, PSY_VALUES, Blocked(BM)),
        K::CheckpointStateRoots => domain_from_physical(id, P::CheckpointStateRoots, "checkpoint state roots", A, C_INDIRECT_RS_INDIRECT),
        K::UserLeaf => domain_from_physical(id, P::UserLeaf, "realm user leaf", A, R_DIRECT),
        K::UserPublicKey => domain_from_physical(id, P::UserPublicKey, "coordinator user public key", A, C_DIRECT),
        K::U64Singleton => domain_from_physical(id, P::U64Singleton, "mutable latest-checkpoint singleton", DO, C_INDIRECT_R_INDIRECT),
        K::U64Counter => domain_from_physical(id, P::U64CounterSingleton, "monotonic pending counter", O, SHARED_NONE),
        K::ContractStateTreeHeight => {
            domain_from_physical(id, P::ContractStateTreeHeight, "contract tree height", D, C_INDIRECT_R_INDIRECT)
        }
        K::CheckpointToPending => domain_from_physical(id, P::CheckpointIdToPendingId, "reusable checkpoint -> pending", O, C_INDIRECT_R_INDIRECT),
        K::PendingToCheckpoint => domain_from_physical(id, P::PendingIdToCheckpointId, "pending -> checkpoint", O, C_INDIRECT_R_INDIRECT),
        K::PendingToProc => domain_from_physical(id, P::PendingIdToPendingProcIdU64ToU128, "pending -> proc UUID", O, C_INDIRECT_R_INDIRECT),
        K::ProcToPending => domain_from_physical(id, P::PendingIdToPendingProcIdU128ToU64, "proc UUID -> pending", O, C_INDIRECT_R_INDIRECT),
        K::RealmRewardNode => domain_from_physical(id, P::RealmRewardsTreeNodeKey, "realm reward materialization by pending", DO, C_DIRECT),
        K::PublicKeyToUser => domain_from_physical(id, P::PublicKeyHashToUserIds, "public-key hash projection", D, C_DIRECT),
        K::GlobalUserMerkle => domain_from_physical(id, P::GlobalUserTree, "global user Merkle", A, SHARED_DIRECT),
        K::UserContractMerkle => domain_from_physical(id, P::UserContractTree, "user contract Merkle", A, R_DIRECT),
        K::ContractStateMerkle => domain_from_physical(id, P::ContractStateTree, "contract state Merkle", A, R_DIRECT),
        K::GlobalCheckpointMerkle => domain_from_physical(id, P::GlobalCheckpointTree, "checkpoint Merkle", A, C_INDIRECT_RS_INDIRECT),
        K::RewardTagMerkle => domain_from_physical(id, P::GutaRewardTagTree, "pending reward tag Merkle", O, SHARED_NONE),
        K::UserRegistrationMerkle => domain_from_physical(id, P::UserRegistrationTree, "user registration Merkle", A, C_DIRECT),
        K::GlobalContractMerkle => domain_from_physical(id, P::GlobalContractTree, "global contract Merkle", A, C_DIRECT),
        K::ContractFunctionMerkle => domain_from_physical(id, P::ContractFunctionTree, "contract function Merkle", A, C_DIRECT),
        K::ContractLeaf => domain_from_physical(id, P::ContractLeaf, "contract leaf", A, C_DIRECT),
        K::ContractCodeDefinition => domain_from_physical(id, P::ContractCodeDefinition, "contract code definition", A, C_DIRECT),
        K::CheckpointZkProof => domain_from_physical(id, P::CheckpointZkProofAndTransition, "checkpoint proof and transition", A, C_INDIRECT),
        K::ImtLeaf => domain_from_physical(id, P::ImtLeaf, "IMT leaf", A, R_DIRECT),
        K::ImtKeyIndex => domain_from_physical(id, P::ImtKeyIndex, "IMT key index", D, coverage(NA, DI, NA)),
        K::ImtCursor => domain_from_physical(id, P::ImtNextAppendIndex, "IMT append cursor", D, coverage(NA, DI, NA)),
    }
}

pub fn key_domain_registry() -> Vec<KeyDomainDescriptor> {
    ScyllaKeyDomain::iter().map(key_domain_descriptor).collect()
}

pub fn physical_registry() -> Vec<PhysicalTableDescriptor> {
    ScyllaPhysicalTableId::iter().map(physical_descriptor).collect()
}

/// Human-reviewable stable inventory used by the D-02a golden test.
pub fn registry_snapshot_v1() -> String {
    let mut result = String::new();
    let mut full_metadata_hash = 0xcbf29ce484222325_u64;
    for descriptor in physical_registry() {
        let shape = descriptor.cql_primary_key();
        for byte in format!("{descriptor:?}|{shape:?}|{}", descriptor.rust_implementation()).bytes() {
            full_metadata_hash ^= u64::from(byte);
            full_metadata_hash = full_metadata_hash.wrapping_mul(0x100000001b3);
        }
        result.push_str(&format!(
            "{}|{:?}|{}|{}|{}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}\n",
            descriptor.id.stable_id(),
            descriptor.logical_owner,
            descriptor.routing_key,
            descriptor.physical_name,
            descriptor.suffix,
            descriptor.keyspace,
            descriptor.schema_family,
            descriptor.authority,
            descriptor.classification,
            descriptor.access,
            descriptor.prepared_coverage,
            descriptor.version_axis,
            descriptor.rollback_policy,
            descriptor.delete_candidates,
            descriptor.recovery_action,
            descriptor.manifest_requirement,
            descriptor.verification,
            shape.cql,
            match descriptor.readiness {
                RegistryReadiness::Ready => "Ready".to_string(),
                RegistryReadiness::Blocked(blocker) => format!("Blocked({blocker:?})"),
                RegistryReadiness::RetireCandidate => "RetireCandidate".to_string(),
            },
        ));
    }
    result.push_str(&format!("FULL_METADATA_FNV1A64={full_metadata_hash:016x}\n"));
    result
}

pub fn key_domain_snapshot_v1() -> String {
    let mut result = String::new();
    let mut full_metadata_hash = 0xcbf29ce484222325_u64;
    for descriptor in key_domain_registry() {
        for byte in format!("{descriptor:?}").bytes() {
            full_metadata_hash ^= u64::from(byte);
            full_metadata_hash = full_metadata_hash.wrapping_mul(0x100000001b3);
        }
        result.push_str(&format!(
            "{}|{:?}|{:?}|{}|{:?}|{:?}|{}\n",
            descriptor.id.stable_id(),
            descriptor.id,
            descriptor.physical_table,
            descriptor.logical_subtable,
            descriptor.classification,
            descriptor.version_axis,
            match descriptor.readiness {
                RegistryReadiness::Ready => "Ready".to_string(),
                RegistryReadiness::Blocked(blocker) => format!("Blocked({blocker:?})"),
                RegistryReadiness::RetireCandidate => "RetireCandidate".to_string(),
            },
        ));
    }
    result.push_str(&format!("FULL_METADATA_FNV1A64={full_metadata_hash:016x}\n"));
    result
}
