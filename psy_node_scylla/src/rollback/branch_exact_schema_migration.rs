//! Isolated schema-migration prototype for the two Realm commit blockers.
//!
//! Its read/write adapter is intentionally absent from `psy_setup.rs` and
//! every current writer. The h20 setup gate can only inspect the target and
//! retain opaque prepared reads after durable verification. This module
//! proves the target shape for replacing the reusable-height
//! pending mapping and for removing pending-keyed reward proofs from the
//! mixed-axis `checkpointed_object_table`.

use std::{error::Error, fmt};

use futures::TryStreamExt;
use parth_core::{
    crypto::hash::tag_tree::TagTreeMerkleProof,
    protocol::core_types::Q256BitHash,
};
use psy_node_core::store::{
    branch_exact_schema::{
        BranchExactLogicalTableId, BranchExactMaterializationPlanDigest,
        BranchExactSchemaMaterializationPlan, AuthorityScope,
        BRANCH_EXACT_SCHEMA_VERSION,
        BRANCH_EXACT_TARGET_LOGICAL_TABLE_COUNT,
    },
    branch_pending_mapping::{
        BranchPendingMapping, BranchPendingMappingDigest,
    },
    canonical_head::CanonicalHeadBootstrapProfile,
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use sha2::{Digest, Sha256};
use scylla::{
    client::session::Session,
    statement::{
        batch::{Batch, BatchType},
        prepared::PreparedStatement,
        Consistency,
    },
};

use super::{CqlKeyspaceName, PrototypeBindValue};

pub const ACTIVE_PHYSICAL_TABLE_COUNT: usize = 35;
pub const BRANCH_EXACT_PHYSICAL_EXTENSION_COUNT: usize = 3;
pub const BRANCH_EXACT_TARGET_PHYSICAL_TABLE_COUNT: usize =
    ACTIVE_PHYSICAL_TABLE_COUNT + BRANCH_EXACT_PHYSICAL_EXTENSION_COUNT;
pub const ACTIVE_KEY_DOMAIN_COUNT: usize = 39;
pub const BRANCH_EXACT_KEY_DOMAIN_EXTENSION_COUNT: usize = 3;
pub const BRANCH_EXACT_TARGET_KEY_DOMAIN_COUNT: usize =
    ACTIVE_KEY_DOMAIN_COUNT + BRANCH_EXACT_KEY_DOMAIN_EXTENSION_COUNT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaInventoryCounts {
    pub active_logical: usize,
    pub active_physical: usize,
    pub active_key_domains: usize,
    pub target_logical: usize,
    pub target_physical: usize,
    pub target_key_domains: usize,
}

pub const BRANCH_EXACT_SCHEMA_INVENTORY_COUNTS: BranchExactSchemaInventoryCounts =
    BranchExactSchemaInventoryCounts {
        active_logical: 32,
        active_physical: ACTIVE_PHYSICAL_TABLE_COUNT,
        active_key_domains: ACTIVE_KEY_DOMAIN_COUNT,
        target_logical: BRANCH_EXACT_TARGET_LOGICAL_TABLE_COUNT,
        target_physical: BRANCH_EXACT_TARGET_PHYSICAL_TABLE_COUNT,
        target_key_domains: BRANCH_EXACT_TARGET_KEY_DOMAIN_COUNT,
    };

/// Stable physical identities reserved after the active `1..=35` registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum BranchExactPhysicalTableId {
    CanonicalChainRefToPendingId = 36,
    PendingIdToCanonicalChainRef = 37,
    PendingRewardTopProof = 38,
}

impl BranchExactPhysicalTableId {
    pub const ALL: [Self; 3] = [
        Self::CanonicalChainRefToPendingId,
        Self::PendingIdToCanonicalChainRef,
        Self::PendingRewardTopProof,
    ];

    pub const fn stable_id(self) -> u16 {
        self as u16
    }
}

/// Stable semantic domains reserved after the active `1..=39` registry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum BranchExactKeyDomain {
    CanonicalChainRefToPendingId = 40,
    PendingIdToCanonicalChainRef = 41,
    PendingRewardTopProof = 42,
}

impl BranchExactKeyDomain {
    pub const ALL: [Self; 3] = [
        Self::CanonicalChainRefToPendingId,
        Self::PendingIdToCanonicalChainRef,
        Self::PendingRewardTopProof,
    ];

    pub const fn stable_id(self) -> u16 {
        self as u16
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetAuthority {
    Shared,
    Realm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetClassification {
    Operational,
    Derived,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetAxis {
    CanonicalChainRefPartition,
    UniquePendingPartition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetAction {
    PreserveAppendOnly,
    RotatePendingNamespace,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetManifest {
    PairPhysicalDirection,
    ExactMutation,
}

/// Static migration-target readiness. Runtime setup readiness is represented
/// by the h20 durable setup token and never changes this catalog into a
/// serving authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactTargetReadiness {
    MigrationTargetNotActive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaTargetDescriptor {
    pub logical: BranchExactLogicalTableId,
    pub physical: BranchExactPhysicalTableId,
    pub key_domain: BranchExactKeyDomain,
    pub physical_name: &'static str,
    pub routing_key: u64,
    pub cql_primary_key: &'static str,
    pub authority: BranchExactTargetAuthority,
    pub classification: BranchExactTargetClassification,
    pub axis: BranchExactTargetAxis,
    pub action: BranchExactTargetAction,
    pub manifest: BranchExactTargetManifest,
    pub readiness: BranchExactTargetReadiness,
}

pub const BRANCH_EXACT_SCHEMA_TARGETS: [BranchExactSchemaTargetDescriptor; 3] = [
    BranchExactSchemaTargetDescriptor {
        logical: BranchExactLogicalTableId::CanonicalChainRefToPendingId,
        physical: BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
        key_domain: BranchExactKeyDomain::CanonicalChainRefToPendingId,
        physical_name: BranchExactLogicalTableId::CanonicalChainRefToPendingId
            .table_name(),
        routing_key: BranchExactLogicalTableId::CanonicalChainRefToPendingId
            .routing_key(),
        cql_primary_key: "PRIMARY KEY ((canonical_ref), pending_id)",
        authority: BranchExactTargetAuthority::Shared,
        classification: BranchExactTargetClassification::Operational,
        axis: BranchExactTargetAxis::CanonicalChainRefPartition,
        action: BranchExactTargetAction::PreserveAppendOnly,
        manifest: BranchExactTargetManifest::PairPhysicalDirection,
        readiness: BranchExactTargetReadiness::MigrationTargetNotActive,
    },
    BranchExactSchemaTargetDescriptor {
        logical: BranchExactLogicalTableId::PendingIdToCanonicalChainRef,
        physical: BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
        key_domain: BranchExactKeyDomain::PendingIdToCanonicalChainRef,
        physical_name: BranchExactLogicalTableId::PendingIdToCanonicalChainRef
            .table_name(),
        routing_key: BranchExactLogicalTableId::PendingIdToCanonicalChainRef
            .routing_key(),
        cql_primary_key: "PRIMARY KEY ((pending_id), canonical_ref)",
        authority: BranchExactTargetAuthority::Shared,
        classification: BranchExactTargetClassification::Operational,
        axis: BranchExactTargetAxis::UniquePendingPartition,
        action: BranchExactTargetAction::PreserveAppendOnly,
        manifest: BranchExactTargetManifest::PairPhysicalDirection,
        readiness: BranchExactTargetReadiness::MigrationTargetNotActive,
    },
    BranchExactSchemaTargetDescriptor {
        logical: BranchExactLogicalTableId::PendingRewardTopProof,
        physical: BranchExactPhysicalTableId::PendingRewardTopProof,
        key_domain: BranchExactKeyDomain::PendingRewardTopProof,
        physical_name: BranchExactLogicalTableId::PendingRewardTopProof.table_name(),
        routing_key: BranchExactLogicalTableId::PendingRewardTopProof.routing_key(),
        cql_primary_key: "PRIMARY KEY ((pending_id))",
        authority: BranchExactTargetAuthority::Realm,
        classification: BranchExactTargetClassification::Derived,
        axis: BranchExactTargetAxis::UniquePendingPartition,
        action: BranchExactTargetAction::RotatePendingNamespace,
        manifest: BranchExactTargetManifest::ExactMutation,
        readiness: BranchExactTargetReadiness::MigrationTargetNotActive,
    },
];

pub const BRANCH_TO_PENDING_TABLE: &str =
    BranchExactLogicalTableId::CanonicalChainRefToPendingId.table_name();
pub const PENDING_TO_BRANCH_TABLE: &str =
    BranchExactLogicalTableId::PendingIdToCanonicalChainRef.table_name();
pub const PENDING_REWARD_PROOF_TABLE: &str =
    BranchExactLogicalTableId::PendingRewardTopProof.table_name();

pub const fn branch_exact_schema_target(
    logical: BranchExactLogicalTableId,
) -> BranchExactSchemaTargetDescriptor {
    match logical {
        BranchExactLogicalTableId::CanonicalChainRefToPendingId => {
            BRANCH_EXACT_SCHEMA_TARGETS[0]
        }
        BranchExactLogicalTableId::PendingIdToCanonicalChainRef => {
            BRANCH_EXACT_SCHEMA_TARGETS[1]
        }
        BranchExactLogicalTableId::PendingRewardTopProof => {
            BRANCH_EXACT_SCHEMA_TARGETS[2]
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum BranchExactQueryId {
    CreateBranchToPending = 1,
    CreatePendingToBranch = 2,
    CreatePendingRewardProof = 3,
    PutBranchToPending = 4,
    PutPendingToBranch = 5,
    PutPendingRewardProof = 6,
    ReadBranchToPending = 7,
    ReadPendingToBranch = 8,
    ReadPendingRewardProof = 9,
    InspectTableColumns = 10,
    ScanBranchToPending = 11,
    ScanPendingToBranch = 12,
    ScanPendingRewardProof = 13,
}

const COORDINATOR_BRANCH_EXACT_CREATE_QUERIES: &[BranchExactQueryId] = &[
    BranchExactQueryId::CreateBranchToPending,
    BranchExactQueryId::CreatePendingToBranch,
];
const REALM_BRANCH_EXACT_CREATE_QUERIES: &[BranchExactQueryId] = &[
    BranchExactQueryId::CreateBranchToPending,
    BranchExactQueryId::CreatePendingToBranch,
    BranchExactQueryId::CreatePendingRewardProof,
];

pub const fn branch_exact_create_queries(
    authority: AuthorityScope,
) -> &'static [BranchExactQueryId] {
    match authority {
        AuthorityScope::Coordinator => COORDINATOR_BRANCH_EXACT_CREATE_QUERIES,
        AuthorityScope::Realm { .. } => REALM_BRANCH_EXACT_CREATE_QUERIES,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactQuery {
    id: BranchExactQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl BranchExactQuery {
    pub const fn id(&self) -> BranchExactQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

/// Single source of CQL for the prototype adapter and query-golden tests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactQueries {
    queries: [BranchExactQuery; 13],
}

impl BranchExactQueries {
    pub fn new(keyspace: &CqlKeyspaceName) -> Self {
        let forward = format!(
            "{}.{}",
            keyspace.as_str(),
            BRANCH_TO_PENDING_TABLE
        );
        let reverse = format!(
            "{}.{}",
            keyspace.as_str(),
            PENDING_TO_BRANCH_TABLE
        );
        let proof = format!(
            "{}.{}",
            keyspace.as_str(),
            PENDING_REWARD_PROOF_TABLE
        );
        Self {
            queries: [
                query(
                    BranchExactQueryId::CreateBranchToPending,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {forward} (canonical_ref blob, pending_id bigint, mapping_digest blob, PRIMARY KEY ((canonical_ref), pending_id))"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::CreatePendingToBranch,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {reverse} (pending_id bigint, canonical_ref blob, mapping_digest blob, PRIMARY KEY ((pending_id), canonical_ref))"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::CreatePendingRewardProof,
                    format!(
                        "CREATE TABLE IF NOT EXISTS {proof} (pending_id bigint, value blob, PRIMARY KEY ((pending_id)))"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::PutBranchToPending,
                    format!(
                        "INSERT INTO {forward} (canonical_ref, pending_id, mapping_digest) VALUES (?, ?, ?) USING TIMESTAMP ?"
                    ),
                    &["BLOB", "BIGINT", "BLOB", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::PutPendingToBranch,
                    format!(
                        "INSERT INTO {reverse} (pending_id, canonical_ref, mapping_digest) VALUES (?, ?, ?) USING TIMESTAMP ?"
                    ),
                    &["BIGINT", "BLOB", "BLOB", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::PutPendingRewardProof,
                    format!(
                        "INSERT INTO {proof} (pending_id, value) VALUES (?, ?) USING TIMESTAMP ?"
                    ),
                    &["BIGINT", "BLOB", "BIGINT"],
                ),
                query(
                    BranchExactQueryId::ReadBranchToPending,
                    format!(
                        "SELECT pending_id, mapping_digest, writetime(mapping_digest) FROM {forward} WHERE canonical_ref = ?"
                    ),
                    &["BLOB"],
                ),
                query(
                    BranchExactQueryId::ReadPendingToBranch,
                    format!(
                        "SELECT canonical_ref, mapping_digest, writetime(mapping_digest) FROM {reverse} WHERE pending_id = ?"
                    ),
                    &["BIGINT"],
                ),
                query(
                    BranchExactQueryId::ReadPendingRewardProof,
                    format!(
                        "SELECT value FROM {proof} WHERE pending_id = ?"
                    ),
                    &["BIGINT"],
                ),
                query(
                    BranchExactQueryId::InspectTableColumns,
                    "SELECT column_name, type, kind, position, clustering_order FROM system_schema.columns WHERE keyspace_name = ? AND table_name = ?".to_owned(),
                    &["TEXT", "TEXT"],
                ),
                query(
                    BranchExactQueryId::ScanBranchToPending,
                    format!(
                        "SELECT canonical_ref, pending_id, mapping_digest FROM {forward}"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::ScanPendingToBranch,
                    format!(
                        "SELECT pending_id, canonical_ref, mapping_digest FROM {reverse}"
                    ),
                    &[],
                ),
                query(
                    BranchExactQueryId::ScanPendingRewardProof,
                    format!("SELECT pending_id, value FROM {proof}"),
                    &[],
                ),
            ],
        }
    }

    pub fn get(&self, id: BranchExactQueryId) -> &BranchExactQuery {
        &self.queries[id as usize - 1]
    }

    pub fn all(&self) -> impl Iterator<Item = &BranchExactQuery> {
        self.queries.iter()
    }

    pub fn golden(&self) -> String {
        let mut output = String::new();
        for query in self.all() {
            output.push_str(&format!(
                "{:?}\n{}\n{}\n",
                query.id(),
                query.cql(),
                query.bind_shape().join(",")
            ));
        }
        output
    }
}

const BRANCH_EXACT_SCHEMA_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-schema-fingerprint/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BranchExactColumnKind {
    PartitionKey,
    Clustering,
    Regular,
}

impl BranchExactColumnKind {
    const fn as_system_schema_str(self) -> &'static str {
        match self {
            Self::PartitionKey => "partition_key",
            Self::Clustering => "clustering",
            Self::Regular => "regular",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BranchExactClusteringOrder {
    Asc,
    None,
}

impl BranchExactClusteringOrder {
    const fn as_system_schema_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactColumnSpec {
    pub physical: BranchExactPhysicalTableId,
    pub column_name: &'static str,
    pub cql_type: &'static str,
    pub kind: BranchExactColumnKind,
    pub position: i32,
    pub clustering_order: BranchExactClusteringOrder,
}

pub const BRANCH_EXACT_EXPECTED_COLUMNS: [BranchExactColumnSpec; 8] = [
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
        column_name: "canonical_ref",
        cql_type: "blob",
        kind: BranchExactColumnKind::PartitionKey,
        position: 0,
        clustering_order: BranchExactClusteringOrder::None,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
        column_name: "pending_id",
        cql_type: "bigint",
        kind: BranchExactColumnKind::Clustering,
        position: 0,
        clustering_order: BranchExactClusteringOrder::Asc,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
        column_name: "mapping_digest",
        cql_type: "blob",
        kind: BranchExactColumnKind::Regular,
        position: -1,
        clustering_order: BranchExactClusteringOrder::None,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
        column_name: "pending_id",
        cql_type: "bigint",
        kind: BranchExactColumnKind::PartitionKey,
        position: 0,
        clustering_order: BranchExactClusteringOrder::None,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
        column_name: "canonical_ref",
        cql_type: "blob",
        kind: BranchExactColumnKind::Clustering,
        position: 0,
        clustering_order: BranchExactClusteringOrder::Asc,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
        column_name: "mapping_digest",
        cql_type: "blob",
        kind: BranchExactColumnKind::Regular,
        position: -1,
        clustering_order: BranchExactClusteringOrder::None,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::PendingRewardTopProof,
        column_name: "pending_id",
        cql_type: "bigint",
        kind: BranchExactColumnKind::PartitionKey,
        position: 0,
        clustering_order: BranchExactClusteringOrder::None,
    },
    BranchExactColumnSpec {
        physical: BranchExactPhysicalTableId::PendingRewardTopProof,
        column_name: "value",
        cql_type: "blob",
        kind: BranchExactColumnKind::Regular,
        position: -1,
        clustering_order: BranchExactClusteringOrder::None,
    },
];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservedBranchExactColumn {
    pub physical: BranchExactPhysicalTableId,
    pub column_name: String,
    pub cql_type: String,
    pub kind: String,
    pub position: i32,
    pub clustering_order: String,
}

impl From<BranchExactColumnSpec> for ObservedBranchExactColumn {
    fn from(spec: BranchExactColumnSpec) -> Self {
        Self {
            physical: spec.physical,
            column_name: spec.column_name.to_owned(),
            cql_type: spec.cql_type.to_owned(),
            kind: spec.kind.as_system_schema_str().to_owned(),
            position: spec.position,
            clustering_order: spec
                .clustering_order
                .as_system_schema_str()
                .to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactSchemaFingerprint([u8; 32]);

impl BranchExactSchemaFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactSchemaInspection {
    Absent,
    Partial {
        present: Vec<BranchExactPhysicalTableId>,
        missing: Vec<BranchExactPhysicalTableId>,
    },
    Exact {
        fingerprint: BranchExactSchemaFingerprint,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactSchemaInspectionError {
    IncompatibleTable {
        physical: BranchExactPhysicalTableId,
        expected: Vec<ObservedBranchExactColumn>,
        observed: Vec<ObservedBranchExactColumn>,
    },
    UnexpectedTableForAuthority {
        authority: AuthorityScope,
        physical: BranchExactPhysicalTableId,
    },
}

impl fmt::Display for BranchExactSchemaInspectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactSchemaInspectionError {}

pub fn inspect_branch_exact_columns(
    authority: AuthorityScope,
    observed: Vec<ObservedBranchExactColumn>,
) -> Result<BranchExactSchemaInspection, BranchExactSchemaInspectionError> {
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for physical in BranchExactPhysicalTableId::ALL {
        let required = branch_exact_physical_applies_to_authority(physical, authority);
        let mut expected = BRANCH_EXACT_EXPECTED_COLUMNS
            .iter()
            .copied()
            .filter(|column| column.physical == physical)
            .map(ObservedBranchExactColumn::from)
            .collect::<Vec<_>>();
        let mut actual = observed
            .iter()
            .filter(|column| column.physical == physical)
            .cloned()
            .collect::<Vec<_>>();
        expected.sort();
        actual.sort();
        if !required {
            if !actual.is_empty() {
                return Err(
                    BranchExactSchemaInspectionError::UnexpectedTableForAuthority {
                        authority,
                        physical,
                    },
                );
            }
            continue;
        }
        if actual.is_empty() {
            missing.push(physical);
        } else if actual == expected {
            present.push(physical);
        } else {
            return Err(BranchExactSchemaInspectionError::IncompatibleTable {
                physical,
                expected,
                observed: actual,
            });
        }
    }
    if present.is_empty() {
        Ok(BranchExactSchemaInspection::Absent)
    } else if missing.is_empty() {
        Ok(BranchExactSchemaInspection::Exact {
            fingerprint: branch_exact_schema_fingerprint(authority),
        })
    } else {
        Ok(BranchExactSchemaInspection::Partial { present, missing })
    }
}

pub fn branch_exact_schema_fingerprint(
    authority: AuthorityScope,
) -> BranchExactSchemaFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(BRANCH_EXACT_SCHEMA_FINGERPRINT_DOMAIN);
    hasher.update(BRANCH_EXACT_SCHEMA_VERSION.to_be_bytes());
    update_authority_fingerprint(&mut hasher, authority);
    for spec in BRANCH_EXACT_EXPECTED_COLUMNS
        .into_iter()
        .filter(|spec| branch_exact_physical_applies_to_authority(spec.physical, authority))
    {
        hasher.update(spec.physical.stable_id().to_be_bytes());
        update_len_prefixed(&mut hasher, spec.column_name.as_bytes());
        update_len_prefixed(&mut hasher, spec.cql_type.as_bytes());
        update_len_prefixed(&mut hasher, spec.kind.as_system_schema_str().as_bytes());
        hasher.update(spec.position.to_be_bytes());
        update_len_prefixed(
            &mut hasher,
            spec.clustering_order.as_system_schema_str().as_bytes(),
        );
    }
    BranchExactSchemaFingerprint(hasher.finalize().into())
}

const fn branch_exact_physical_applies_to_authority(
    physical: BranchExactPhysicalTableId,
    authority: AuthorityScope,
) -> bool {
    match physical {
        BranchExactPhysicalTableId::CanonicalChainRefToPendingId
        | BranchExactPhysicalTableId::PendingIdToCanonicalChainRef => true,
        BranchExactPhysicalTableId::PendingRewardTopProof => {
            matches!(authority, AuthorityScope::Realm { .. })
        }
    }
}

fn update_authority_fingerprint(hasher: &mut Sha256, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

/// Schema-only receipt. It intentionally has no conversion into a production
/// read/write or cutover capability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaOnlyReceipt {
    keyspace: CqlKeyspaceName,
    authority: AuthorityScope,
    profile: CanonicalHeadBootstrapProfile,
    schema_version: u16,
    plan_digest: BranchExactMaterializationPlanDigest,
    schema_fingerprint: BranchExactSchemaFingerprint,
}

impl BranchExactSchemaOnlyReceipt {
    pub const fn keyspace(&self) -> &CqlKeyspaceName {
        &self.keyspace
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn profile(&self) -> CanonicalHeadBootstrapProfile {
        self.profile
    }

    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    pub const fn plan_digest(&self) -> BranchExactMaterializationPlanDigest {
        self.plan_digest
    }

    pub const fn schema_fingerprint(&self) -> BranchExactSchemaFingerprint {
        self.schema_fingerprint
    }

    #[cfg(test)]
    pub(crate) fn from_verified_parts_for_deployment(
        request: &BranchExactSchemaMaterializationRequest,
        schema_fingerprint: BranchExactSchemaFingerprint,
    ) -> Self {
        Self {
            keyspace: request.keyspace().clone(),
            authority: request.plan().authority(),
            profile: request.plan().profile(),
            schema_version: request.plan().schema_version(),
            plan_digest: request.plan().digest(),
            schema_fingerprint,
        }
    }
}

/// Binds a sealed authority/profile plan to one exact Scylla keyspace. The
/// materializer has no overload accepting a bare keyspace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactSchemaMaterializationRequest {
    keyspace: CqlKeyspaceName,
    plan: BranchExactSchemaMaterializationPlan,
}

impl BranchExactSchemaMaterializationRequest {
    pub fn try_new(
        keyspace: CqlKeyspaceName,
        plan: BranchExactSchemaMaterializationPlan,
    ) -> Result<Self, BranchExactMaterializationRequestError> {
        if keyspace.as_str().ends_with("_no_tablet") {
            return Err(BranchExactMaterializationRequestError::NoTabletKeyspace);
        }
        Ok(Self { keyspace, plan })
    }

    pub const fn keyspace(&self) -> &CqlKeyspaceName {
        &self.keyspace
    }

    pub const fn plan(&self) -> &BranchExactSchemaMaterializationPlan {
        &self.plan
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactMaterializationRequestError {
    NoTabletKeyspace,
}

impl fmt::Display for BranchExactMaterializationRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactMaterializationRequestError {}

fn query(
    id: BranchExactQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
) -> BranchExactQuery {
    BranchExactQuery {
        id,
        cql,
        bind_shape,
    }
}

/// Immutable retry unit for the two physical mapping rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchPendingPairPutPlan<Hash> {
    mapping: BranchPendingMapping<Hash>,
    canonical_ref: Vec<u8>,
    pending_id: i64,
    write_timestamp_us: i64,
    digest: BranchPendingMappingDigest,
    mapping_digest: Vec<u8>,
}

impl<Hash: Q256BitHash> BranchPendingPairPutPlan<Hash> {
    pub fn new(
        mapping: BranchPendingMapping<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> Self {
        let digest = mapping.digest();
        Self {
            canonical_ref: mapping.canonical_chain_bytes().to_vec(),
            pending_id: mapping.pending_id().get() as i64,
            write_timestamp_us: timestamp.as_i64(),
            mapping_digest: digest.as_bytes().to_vec(),
            digest,
            mapping,
        }
    }

    pub const fn mapping(&self) -> &BranchPendingMapping<Hash> {
        &self.mapping
    }

    pub const fn digest(&self) -> BranchPendingMappingDigest {
        self.digest
    }

    pub const fn write_timestamp_us(&self) -> i64 {
        self.write_timestamp_us
    }

    pub fn forward_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::Blob(self.canonical_ref.clone()),
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::Blob(self.mapping_digest.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn reverse_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::Blob(self.canonical_ref.clone()),
            PrototypeBindValue::Blob(self.mapping_digest.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn forward_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::Blob(self.canonical_ref.clone())]
    }

    pub fn reverse_read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.pending_id)]
    }

    fn canonical_ref_bytes(&self) -> &[u8] {
        &self.canonical_ref
    }

    pub(crate) fn mapping_digest_bytes(&self) -> &[u8] {
        &self.mapping_digest
    }
}

/// Exact proof payload moved out of `checkpointed_object_table`'s mixed axis.
/// It can only be constructed from the actual protocol proof type, never from
/// a digest-only mutation payload.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingRewardProofPutPlan {
    pending_id: i64,
    stored_value: Vec<u8>,
    canonical_value: Vec<u8>,
    write_timestamp_us: i64,
}

impl PendingRewardProofPutPlan {
    pub fn try_new<Hash: Q256BitHash>(
        pending_id: UniquePendingId,
        proof: &TagTreeMerkleProof<Hash>,
        timestamp: CommitWriteTimestampUs,
    ) -> anyhow::Result<Self> {
        let canonical_value = proof.psy_ser_to_bytes_vec()?;
        let stored_value = crate::compression::compress(&canonical_value)?;
        Ok(Self {
            pending_id: pending_id.get() as i64,
            stored_value,
            canonical_value,
            write_timestamp_us: timestamp.as_i64(),
        })
    }

    pub fn bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![
            PrototypeBindValue::BigInt(self.pending_id),
            PrototypeBindValue::Blob(self.stored_value.clone()),
            PrototypeBindValue::BigInt(self.write_timestamp_us),
        ]
    }

    pub fn read_bind_values(&self) -> Vec<PrototypeBindValue> {
        vec![PrototypeBindValue::BigInt(self.pending_id)]
    }

    pub fn canonical_value(&self) -> &[u8] {
        &self.canonical_value
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactReadError {
    MissingForward,
    MissingReverse,
    ForwardConflict { rows: Vec<i64> },
    ReverseConflict { rows: usize },
    MalformedCanonicalRef(String),
}

impl fmt::Display for BranchExactReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactReadError {}

/// Require exactly one matching clustering row. Multiple mappings are a hard
/// conflict, not last-write-wins repair.
pub fn verify_forward_rows<Hash: Q256BitHash>(
    plan: &BranchPendingPairPutPlan<Hash>,
    rows: Vec<(i64, Vec<u8>, i64)>,
) -> Result<(), BranchExactReadError> {
    match rows.as_slice() {
        [] => Err(BranchExactReadError::MissingForward),
        [(pending, digest, timestamp)]
            if *pending == plan.pending_id
                && digest.as_slice() == plan.mapping_digest_bytes()
                && *timestamp == plan.write_timestamp_us => Ok(()),
        _ => Err(BranchExactReadError::ForwardConflict {
            rows: rows.into_iter().map(|row| row.0).collect(),
        }),
    }
}

pub fn verify_reverse_rows<Hash: Q256BitHash>(
    plan: &BranchPendingPairPutPlan<Hash>,
    rows: Vec<(Vec<u8>, Vec<u8>, i64)>,
) -> Result<(), BranchExactReadError> {
    for row in &rows {
        BranchPendingMapping::<Hash>::validate_canonical_chain_bytes(&row.0)
            .map_err(|error| BranchExactReadError::MalformedCanonicalRef(error.to_string()))?;
    }
    match rows.as_slice() {
        [] => Err(BranchExactReadError::MissingReverse),
        [(canonical, digest, timestamp)]
            if canonical.as_slice() == plan.canonical_ref_bytes()
                && digest.as_slice() == plan.mapping_digest_bytes()
                && *timestamp == plan.write_timestamp_us => Ok(()),
        _ => Err(BranchExactReadError::ReverseConflict { rows: rows.len() }),
    }
}

struct PreparedBranchExact {
    forward_put: PreparedStatement,
    reverse_put: PreparedStatement,
    proof_put: Option<PreparedStatement>,
    forward_read: PreparedStatement,
    reverse_read: PreparedStatement,
    proof_read: Option<PreparedStatement>,
    forward_scan: PreparedStatement,
    reverse_scan: PreparedStatement,
    proof_scan: Option<PreparedStatement>,
}

/// Isolated schema materializer used by deployment tooling and RF=3 tests.
/// Production setup may call `inspect_schema` through the h20 default-off
/// gate, but never calls `materialize_schema`.
pub struct BranchExactSchemaMaterializer;

impl BranchExactSchemaMaterializer {
    pub async fn inspect_schema(
        session: &Session,
        keyspace: &CqlKeyspaceName,
        authority: AuthorityScope,
    ) -> anyhow::Result<BranchExactSchemaInspection> {
        let queries = BranchExactQueries::new(keyspace);
        let inspect = queries.get(BranchExactQueryId::InspectTableColumns);
        let mut observed = Vec::new();
        for target in BRANCH_EXACT_SCHEMA_TARGETS {
            let rows = session
                .query_unpaged(
                    inspect.cql(),
                    (keyspace.as_str(), target.physical_name),
                )
                .await?
                .into_rows_result()?;
            for row in rows.rows::<(String, String, String, i32, String)>()? {
                let (column_name, cql_type, kind, position, clustering_order) =
                    row?;
                observed.push(ObservedBranchExactColumn {
                    physical: target.physical,
                    column_name,
                    cql_type,
                    kind,
                    position,
                    clustering_order: normalize_system_clustering_order(
                        clustering_order,
                    ),
                });
            }
        }
        Ok(inspect_branch_exact_columns(authority, observed)?)
    }

    pub async fn materialize_schema(
        session: &Session,
        request: &BranchExactSchemaMaterializationRequest,
    ) -> anyhow::Result<BranchExactSchemaOnlyReceipt> {
        let keyspace = request.keyspace();
        let plan = request.plan();
        if plan.schema_version() != BRANCH_EXACT_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported branch-exact schema version {}",
                plan.schema_version()
            );
        }
        let authority = plan.authority();
        let before = Self::inspect_schema(session, keyspace, authority).await?;
        if !matches!(before, BranchExactSchemaInspection::Exact { .. }) {
            let queries = BranchExactQueries::new(keyspace);
            for id in branch_exact_create_queries(authority) {
                session
                    .query_unpaged(queries.get(*id).cql(), &[])
                    .await?;
            }
            session.await_schema_agreement().await?;
        }

        let BranchExactSchemaInspection::Exact { fingerprint } =
            Self::inspect_schema(session, keyspace, authority).await?
        else {
            anyhow::bail!(
                "branch-exact schema did not converge to the exact target"
            );
        };
        Ok(BranchExactSchemaOnlyReceipt {
            keyspace: keyspace.clone(),
            authority,
            profile: plan.profile(),
            schema_version: plan.schema_version(),
            plan_digest: plan.digest(),
            schema_fingerprint: fingerprint,
        })
    }
}

// Scylla exposes this system-schema enum as `ASC`/`DESC`/`NONE`, while the
// CQL schema model and older fixtures use lowercase. Normalize only this
// case-insensitive enum; names, types, key kinds, positions, and the resulting
// complete column set remain exact-match inputs.
fn normalize_system_clustering_order(mut value: String) -> String {
    value.make_ascii_lowercase();
    value
}

#[allow(dead_code)]
pub(crate) struct BranchExactSchemaMigrationAdapter {
    queries: BranchExactQueries,
    consistency: Consistency,
    prepared: PreparedBranchExact,
}

#[allow(dead_code)]
impl BranchExactSchemaMigrationAdapter {
    pub(crate) async fn prepare_with_consistency(
        session: &Session,
        keyspace: CqlKeyspaceName,
        authority: AuthorityScope,
        consistency: Consistency,
    ) -> anyhow::Result<Self> {
        let queries = BranchExactQueries::new(&keyspace);
        let realm_proof = matches!(authority, AuthorityScope::Realm { .. });
        let prepared = PreparedBranchExact {
            forward_put: prepare(
                session,
                queries.get(BranchExactQueryId::PutBranchToPending),
                consistency,
            )
            .await?,
            reverse_put: prepare(
                session,
                queries.get(BranchExactQueryId::PutPendingToBranch),
                consistency,
            )
            .await?,
            proof_put: if realm_proof {
                Some(
                    prepare(
                        session,
                        queries.get(BranchExactQueryId::PutPendingRewardProof),
                        consistency,
                    )
                    .await?,
                )
            } else {
                None
            },
            forward_read: prepare(
                session,
                queries.get(BranchExactQueryId::ReadBranchToPending),
                consistency,
            )
            .await?,
            reverse_read: prepare(
                session,
                queries.get(BranchExactQueryId::ReadPendingToBranch),
                consistency,
            )
            .await?,
            proof_read: if realm_proof {
                Some(
                    prepare(
                        session,
                        queries.get(BranchExactQueryId::ReadPendingRewardProof),
                        consistency,
                    )
                    .await?,
                )
            } else {
                None
            },
            forward_scan: prepare(
                session,
                queries.get(BranchExactQueryId::ScanBranchToPending),
                consistency,
            )
            .await?,
            reverse_scan: prepare(
                session,
                queries.get(BranchExactQueryId::ScanPendingToBranch),
                consistency,
            )
            .await?,
            proof_scan: if realm_proof {
                Some(
                    prepare(
                        session,
                        queries.get(BranchExactQueryId::ScanPendingRewardProof),
                        consistency,
                    )
                    .await?,
                )
            } else {
                None
            },
        };
        Ok(Self {
            queries,
            consistency,
            prepared,
        })
    }

    pub(crate) async fn put_pair<Hash: Q256BitHash>(
        &self,
        session: &Session,
        plan: &BranchPendingPairPutPlan<Hash>,
    ) -> anyhow::Result<()> {
        let mut batch = Batch::new(BatchType::Logged);
        batch.set_consistency(self.consistency);
        batch.set_is_idempotent(true);
        batch.append_statement(self.prepared.forward_put.clone());
        batch.append_statement(self.prepared.reverse_put.clone());
        session
            .batch(
                &batch,
                (
                    (
                        plan.canonical_ref.clone(),
                        plan.pending_id,
                        plan.mapping_digest.as_slice(),
                        plan.write_timestamp_us,
                    ),
                    (
                        plan.pending_id,
                        plan.canonical_ref.clone(),
                        plan.mapping_digest.as_slice(),
                        plan.write_timestamp_us,
                    ),
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn verify_pair<Hash: Q256BitHash>(
        &self,
        session: &Session,
        plan: &BranchPendingPairPutPlan<Hash>,
    ) -> anyhow::Result<()> {
        let rows = session
            .execute_unpaged(
                &self.prepared.forward_read,
                (plan.canonical_ref_bytes(),),
            )
            .await?
            .into_rows_result()?;
        let mut forward = Vec::new();
        for row in rows.rows::<(i64, Vec<u8>, i64)>()? {
            forward.push(row?);
        }
        verify_forward_rows(plan, forward)?;

        let rows = session
            .execute_unpaged(&self.prepared.reverse_read, (plan.pending_id,))
            .await?
            .into_rows_result()?;
        let mut reverse = Vec::new();
        for row in rows.rows::<(Vec<u8>, Vec<u8>, i64)>()? {
            reverse.push(row?);
        }
        verify_reverse_rows(plan, reverse)?;
        Ok(())
    }

    pub(crate) async fn put_pending_reward_proof(
        &self,
        session: &Session,
        plan: &PendingRewardProofPutPlan,
    ) -> anyhow::Result<()> {
        let proof_put = self
            .prepared
            .proof_put
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pending reward proof table is not available for Coordinator authority"))?;
        session
            .execute_unpaged(
                proof_put,
                (
                    plan.pending_id,
                    plan.stored_value.as_slice(),
                    plan.write_timestamp_us,
                ),
            )
            .await?;
        Ok(())
    }

    pub(crate) async fn read_pending_reward_proof<Hash: Q256BitHash>(
        &self,
        session: &Session,
        pending_id: UniquePendingId,
    ) -> anyhow::Result<Option<TagTreeMerkleProof<Hash>>> {
        let proof_read = self
            .prepared
            .proof_read
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("pending reward proof table is not available for Coordinator authority"))?;
        let row = session
            .execute_unpaged(proof_read, (pending_id.get() as i64,))
            .await?
            .into_rows_result()?
            .maybe_first_row::<(Vec<u8>,)>()?;
        row.map(|row| {
            TagTreeMerkleProof::<Hash>::psy_ser_from_owned_bytes_vec(
                crate::compression::decompress(&row.0)?,
            )
        })
        .transpose()
    }

    pub(crate) async fn scan_branch_to_pending(
        &self,
        session: &Session,
    ) -> anyhow::Result<Vec<(Vec<u8>, i64, Vec<u8>)>> {
        Ok(session
            .execute_iter(self.prepared.forward_scan.clone(), ())
            .await?
            .rows_stream::<(Vec<u8>, i64, Vec<u8>)>()?
            .try_collect()
            .await?)
    }

    pub(crate) async fn scan_pending_to_branch(
        &self,
        session: &Session,
    ) -> anyhow::Result<Vec<(i64, Vec<u8>, Vec<u8>)>> {
        Ok(session
            .execute_iter(self.prepared.reverse_scan.clone(), ())
            .await?
            .rows_stream::<(i64, Vec<u8>, Vec<u8>)>()?
            .try_collect()
            .await?)
    }

    pub(crate) async fn scan_pending_reward_proofs(
        &self,
        session: &Session,
    ) -> anyhow::Result<Vec<(i64, Vec<u8>)>> {
        let proof_scan = self.prepared.proof_scan.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "pending reward proof table is not available for Coordinator authority"
            )
        })?;
        Ok(session
            .execute_iter(proof_scan.clone(), ())
            .await?
            .rows_stream::<(i64, Vec<u8>)>()?
            .try_collect()
            .await?)
    }

    pub(crate) const fn queries(&self) -> &BranchExactQueries {
        &self.queries
    }
}

async fn prepare(
    session: &Session,
    query: &BranchExactQuery,
    consistency: Consistency,
) -> anyhow::Result<PreparedStatement> {
    let mut statement = session.prepare(query.cql()).await?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use parth_core::{
        PHash,
        crypto::hash::tag_tree::TagTreeMerkleProof,
        protocol::core_types::Q256BitHash,
    };
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::canonical_head::CanonicalHeadBootstrap;
    use strum::IntoEnumIterator;

    use super::*;
    use crate::rollback::{
        physical_descriptor, setup_catalog, ScyllaKeyDomain,
        ScyllaPhysicalTableId,
        PRODUCTION_CQL_CAPABILITIES,
    };

    fn chain(epoch: u64, height: u64, byte: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(0x6979_7350).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                    byte; 32
                ])),
            ),
        )
    }

    fn plan(epoch: u64, pending: u64) -> BranchPendingPairPutPlan<PHash> {
        BranchPendingPairPutPlan::new(
            BranchPendingMapping::new(
                chain(epoch, 100, 7),
                UniquePendingId::try_new(pending).unwrap(),
            ),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
        )
    }

    fn realm_authority() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn exact_observed_columns(
        authority: AuthorityScope,
    ) -> Vec<ObservedBranchExactColumn> {
        BRANCH_EXACT_EXPECTED_COLUMNS
            .into_iter()
            .filter(|column| {
                branch_exact_physical_applies_to_authority(
                    column.physical,
                    authority,
                )
            })
            .map(ObservedBranchExactColumn::from)
            .collect()
    }

    #[test]
    fn schema_is_append_only_and_never_height_keyed() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        let forward = queries.get(BranchExactQueryId::CreateBranchToPending).cql();
        let reverse = queries.get(BranchExactQueryId::CreatePendingToBranch).cql();
        assert!(forward.contains("PRIMARY KEY ((canonical_ref), pending_id)"));
        assert!(reverse.contains("PRIMARY KEY ((pending_id), canonical_ref)"));
        assert!(!forward.contains("checkpoint_id"));
        assert!(!reverse.contains("checkpoint_id"));
    }

    #[test]
    fn stable_extension_ids_are_contiguous_and_do_not_renumber_active_ids() {
        assert_eq!(
            ScyllaPhysicalTableId::iter()
                .map(ScyllaPhysicalTableId::stable_id)
                .collect::<Vec<_>>(),
            (1_u16..=35).collect::<Vec<_>>()
        );
        assert_eq!(
            ScyllaKeyDomain::iter()
                .map(ScyllaKeyDomain::stable_id)
                .collect::<Vec<_>>(),
            (1_u16..=39).collect::<Vec<_>>()
        );
        assert_eq!(
            BranchExactPhysicalTableId::ALL
                .map(BranchExactPhysicalTableId::stable_id),
            [36, 37, 38]
        );
        assert_eq!(
            BranchExactKeyDomain::ALL.map(BranchExactKeyDomain::stable_id),
            [40, 41, 42]
        );
        assert_eq!(
            BRANCH_EXACT_SCHEMA_INVENTORY_COUNTS,
            BranchExactSchemaInventoryCounts {
                active_logical: 32,
                active_physical: 35,
                active_key_domains: 39,
                target_logical: 35,
                target_physical: 38,
                target_key_domains: 42,
            }
        );
    }

    #[test]
    fn target_descriptors_are_exhaustive_unique_and_not_materialized() {
        let names = BRANCH_EXACT_SCHEMA_TARGETS
            .iter()
            .map(|descriptor| descriptor.physical_name)
            .collect::<BTreeSet<_>>();
        let active_names = ScyllaPhysicalTableId::iter()
            .map(|physical| physical_descriptor(physical).physical_name)
            .collect::<BTreeSet<_>>();
        let routing_keys = BRANCH_EXACT_SCHEMA_TARGETS
            .iter()
            .map(|descriptor| descriptor.routing_key)
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 3);
        assert!(names.is_disjoint(&active_names));
        assert_eq!(routing_keys, vec![33, 34, 35]);
        assert_eq!(setup_catalog().len(), 32);
        for logical in BranchExactLogicalTableId::ALL {
            let descriptor = branch_exact_schema_target(logical);
            assert_eq!(descriptor.logical, logical);
            assert_eq!(
                descriptor.readiness,
                BranchExactTargetReadiness::MigrationTargetNotActive
            );
            assert_eq!(descriptor.physical_name, logical.table_name());
            assert!(!descriptor.physical_name.starts_with("d04"));
        }
    }

    #[test]
    fn query_factory_uses_the_reserved_names_and_primary_keys() {
        let queries =
            BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        for (query_id, logical) in [
            (
                BranchExactQueryId::CreateBranchToPending,
                BranchExactLogicalTableId::CanonicalChainRefToPendingId,
            ),
            (
                BranchExactQueryId::CreatePendingToBranch,
                BranchExactLogicalTableId::PendingIdToCanonicalChainRef,
            ),
            (
                BranchExactQueryId::CreatePendingRewardProof,
                BranchExactLogicalTableId::PendingRewardTopProof,
            ),
        ] {
            let descriptor = branch_exact_schema_target(logical);
            let cql = queries.get(query_id).cql();
            assert!(cql.contains(descriptor.physical_name));
            assert!(cql.contains(descriptor.cql_primary_key));
        }
    }

    #[test]
    fn schema_inspection_distinguishes_absent_partial_and_exact() {
        assert_eq!(
            inspect_branch_exact_columns(realm_authority(), Vec::new()).unwrap(),
            BranchExactSchemaInspection::Absent
        );

        let partial = exact_observed_columns(realm_authority())
            .into_iter()
            .filter(|column| {
                column.physical
                    != BranchExactPhysicalTableId::PendingRewardTopProof
            })
            .collect();
        assert_eq!(
            inspect_branch_exact_columns(realm_authority(), partial).unwrap(),
            BranchExactSchemaInspection::Partial {
                present: vec![
                    BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
                    BranchExactPhysicalTableId::PendingIdToCanonicalChainRef,
                ],
                missing: vec![BranchExactPhysicalTableId::PendingRewardTopProof],
            }
        );

        assert_eq!(
            inspect_branch_exact_columns(
                realm_authority(),
                exact_observed_columns(realm_authority()),
            )
            .unwrap(),
            BranchExactSchemaInspection::Exact {
                fingerprint: branch_exact_schema_fingerprint(realm_authority()),
            }
        );
    }

    #[test]
    fn system_schema_clustering_order_is_canonicalized() {
        assert_eq!(normalize_system_clustering_order("ASC".to_owned()), "asc");
        assert_eq!(
            normalize_system_clustering_order("NONE".to_owned()),
            "none"
        );
    }

    #[test]
    fn coordinator_requires_shared_tables_and_rejects_realm_only_proof() {
        assert_eq!(
            branch_exact_create_queries(AuthorityScope::Coordinator),
            COORDINATOR_BRANCH_EXACT_CREATE_QUERIES
        );
        assert_eq!(
            branch_exact_create_queries(realm_authority()),
            REALM_BRANCH_EXACT_CREATE_QUERIES
        );
        let coordinator_columns =
            exact_observed_columns(AuthorityScope::Coordinator);
        assert_eq!(coordinator_columns.len(), 6);
        assert_eq!(
            inspect_branch_exact_columns(
                AuthorityScope::Coordinator,
                coordinator_columns.clone(),
            )
            .unwrap(),
            BranchExactSchemaInspection::Exact {
                fingerprint: branch_exact_schema_fingerprint(
                    AuthorityScope::Coordinator,
                ),
            }
        );

        let mut polluted = coordinator_columns;
        polluted.extend(
            exact_observed_columns(realm_authority())
                .into_iter()
                .filter(|column| {
                    column.physical
                        == BranchExactPhysicalTableId::PendingRewardTopProof
                }),
        );
        assert_eq!(
            inspect_branch_exact_columns(AuthorityScope::Coordinator, polluted),
            Err(
                BranchExactSchemaInspectionError::UnexpectedTableForAuthority {
                    authority: AuthorityScope::Coordinator,
                    physical: BranchExactPhysicalTableId::PendingRewardTopProof,
                }
            )
        );
    }

    #[test]
    fn partial_or_incompatible_table_shape_fails_closed() {
        let mut missing_column = exact_observed_columns(realm_authority());
        missing_column.retain(|column| {
            !(column.physical
                == BranchExactPhysicalTableId::CanonicalChainRefToPendingId
                && column.column_name == "pending_id")
        });
        assert!(matches!(
            inspect_branch_exact_columns(realm_authority(), missing_column),
            Err(BranchExactSchemaInspectionError::IncompatibleTable {
                physical:
                    BranchExactPhysicalTableId::CanonicalChainRefToPendingId,
                ..
            })
        ));

        let mut wrong_type = exact_observed_columns(realm_authority());
        wrong_type
            .iter_mut()
            .find(|column| column.column_name == "canonical_ref")
            .unwrap()
            .cql_type = "text".to_owned();
        assert!(matches!(
            inspect_branch_exact_columns(realm_authority(), wrong_type),
            Err(BranchExactSchemaInspectionError::IncompatibleTable { .. })
        ));

        let mut duplicate = exact_observed_columns(realm_authority());
        duplicate.push(duplicate[0].clone());
        assert!(matches!(
            inspect_branch_exact_columns(realm_authority(), duplicate),
            Err(BranchExactSchemaInspectionError::IncompatibleTable { .. })
        ));
    }

    #[test]
    fn schema_fingerprint_and_inspection_query_are_stable() {
        assert_eq!(
            branch_exact_schema_fingerprint(realm_authority()),
            branch_exact_schema_fingerprint(realm_authority())
        );
        assert_ne!(
            branch_exact_schema_fingerprint(AuthorityScope::Coordinator),
            branch_exact_schema_fingerprint(realm_authority())
        );
        let queries =
            BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        let inspect = queries.get(BranchExactQueryId::InspectTableColumns);
        assert_eq!(inspect.bind_shape(), &["TEXT", "TEXT"]);
        assert_eq!(
            inspect.cql(),
            "SELECT column_name, type, kind, position, clustering_order FROM system_schema.columns WHERE keyspace_name = ? AND table_name = ?"
        );
    }

    #[test]
    fn materialization_request_binds_one_exact_keyspace() {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            chain(0, 0, 7),
        )
        .unwrap();
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            AuthorityScope::Coordinator,
            None,
        )
        .unwrap();
        let first = BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new("coordinator_state").unwrap(),
            plan,
        )
        .unwrap();
        let other = BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new("realm_7_state").unwrap(),
            plan,
        )
        .unwrap();
        assert_ne!(first, other);
        assert_eq!(first.plan().authority(), AuthorityScope::Coordinator);
        assert_eq!(first.keyspace().as_str(), "coordinator_state");
        assert_eq!(
            BranchExactSchemaMaterializationRequest::try_new(
                CqlKeyspaceName::try_new("coordinator_state_no_tablet").unwrap(),
                plan,
            ),
            Err(BranchExactMaterializationRequestError::NoTabletKeyspace)
        );
    }

    #[test]
    fn every_put_requires_an_explicit_timestamp() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        for id in [
            BranchExactQueryId::PutBranchToPending,
            BranchExactQueryId::PutPendingToBranch,
            BranchExactQueryId::PutPendingRewardProof,
        ] {
            assert!(queries.get(id).cql().contains("USING TIMESTAMP ?"));
        }
    }

    #[test]
    fn same_height_and_hash_in_new_epoch_has_a_different_partition() {
        let old = plan(4, 901);
        let reopened = plan(5, 902);
        assert_ne!(
            old.forward_read_bind_values(),
            reopened.forward_read_bind_values()
        );
        assert_ne!(old.digest(), reopened.digest());
    }

    #[test]
    fn mapping_bind_order_and_retry_are_stable() {
        let first = plan(4, 901);
        let retry = first.clone();
        assert_eq!(first.forward_bind_values(), retry.forward_bind_values());
        assert_eq!(first.reverse_bind_values(), retry.reverse_bind_values());
        assert_eq!(first.digest(), retry.digest());
        assert_eq!(
            first.forward_bind_values(),
            vec![
                PrototypeBindValue::Blob(first.mapping().canonical_chain_bytes().to_vec()),
                PrototypeBindValue::BigInt(901),
                PrototypeBindValue::Blob(first.mapping().digest().as_bytes().to_vec()),
                PrototypeBindValue::BigInt(1_000),
            ]
        );
    }

    #[test]
    fn conflicting_rows_fail_closed_in_both_directions() {
        let expected = plan(4, 901);
        let digest = expected.mapping().digest().as_bytes().to_vec();
        let timestamp = expected.write_timestamp_us();
        assert_eq!(
            verify_forward_rows(&expected, vec![(901, digest.clone(), timestamp)]),
            Ok(())
        );
        assert!(matches!(
            verify_forward_rows(
                &expected,
                vec![
                    (901, digest.clone(), timestamp),
                    (902, digest.clone(), timestamp),
                ]
            ),
            Err(BranchExactReadError::ForwardConflict { .. })
        ));
        assert_eq!(
            verify_reverse_rows(
                &expected,
                vec![(
                    expected.mapping().canonical_chain_bytes().to_vec(),
                    digest.clone(),
                    timestamp,
                )]
            ),
            Ok(())
        );
        assert!(matches!(
            verify_reverse_rows(
                &expected,
                vec![
                    (
                        expected.mapping().canonical_chain_bytes().to_vec(),
                        digest.clone(),
                        timestamp,
                    ),
                    (
                        chain(5, 100, 7).to_canonical_bytes().to_vec(),
                        digest,
                        timestamp,
                    ),
                ]
            ),
            Err(BranchExactReadError::ReverseConflict { .. })
        ));
    }

    #[test]
    fn malformed_reverse_identity_is_not_treated_as_absence() {
        let expected = plan(4, 901);
        let digest = expected.mapping().digest().as_bytes().to_vec();
        let timestamp = expected.write_timestamp_us();
        assert!(matches!(
            verify_reverse_rows(&expected, vec![(vec![0; 65], digest.clone(), timestamp)]),
            Err(BranchExactReadError::MalformedCanonicalRef(_))
        ));
        let mut unknown = expected.mapping().canonical_chain_bytes().to_vec();
        unknown[8..10].copy_from_slice(&2_u16.to_le_bytes());
        assert!(matches!(
            verify_reverse_rows(&expected, vec![(unknown, digest, timestamp)]),
            Err(BranchExactReadError::MalformedCanonicalRef(_))
        ));
    }

    #[test]
    fn pending_reward_proof_has_a_dedicated_pending_partition() {
        let pending = UniquePendingId::try_new(901).unwrap();
        let proof = TagTreeMerkleProof::<PHash>::new_empty();
        let plan = PendingRewardProofPutPlan::try_new(
            pending,
            &proof,
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
        )
        .unwrap();
        assert!(!plan.canonical_value().is_empty());
        assert_eq!(
            plan.read_bind_values(),
            vec![PrototypeBindValue::BigInt(901)]
        );
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        assert!(queries
            .get(BranchExactQueryId::CreatePendingRewardProof)
            .cql()
            .contains("PRIMARY KEY ((pending_id))"));
        assert!(!queries
            .get(BranchExactQueryId::CreatePendingRewardProof)
            .cql()
            .contains("obj_id"));
    }

    #[test]
    fn production_capabilities_remain_false() {
        assert!(!PRODUCTION_CQL_CAPABILITIES.explicit_write_timestamp);
        assert!(!PRODUCTION_CQL_CAPABILITIES.delete_adapter);
    }

    #[test]
    fn prototype_is_not_registered_in_production_setup() {
        const SETUP: &str = include_str!("../psy_setup.rs");
        assert!(!SETUP.contains(BRANCH_TO_PENDING_TABLE));
        assert!(!SETUP.contains(PENDING_TO_BRANCH_TABLE));
        assert!(!SETUP.contains(PENDING_REWARD_PROOF_TABLE));
    }

    #[test]
    fn query_golden_is_deterministic_and_complete() {
        let queries = BranchExactQueries::new(&CqlKeyspaceName::try_new("ks").unwrap());
        assert_eq!(queries.all().count(), 13);
        assert_eq!(queries.golden(), queries.golden());
        assert!(queries.golden().contains("PutBranchToPending"));
        assert_eq!(
            queries
                .get(BranchExactQueryId::ScanBranchToPending)
                .cql(),
            "SELECT canonical_ref, pending_id, mapping_digest FROM ks.canonical_chain_ref_to_pending_id_table"
        );
        assert_eq!(
            queries
                .get(BranchExactQueryId::ScanPendingToBranch)
                .cql(),
            "SELECT pending_id, canonical_ref, mapping_digest FROM ks.pending_id_to_canonical_chain_ref_table"
        );
        assert_eq!(
            queries
                .get(BranchExactQueryId::ScanPendingRewardProof)
                .cql(),
            "SELECT pending_id, value FROM ks.pending_reward_top_proof_table"
        );
    }
}
