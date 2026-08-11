//! Exact, default-off schema boundary for the recoverable Realm queue.
//!
//! The twenty target tables have production-shaped, default-off adapters. This module
//! gives deployment tooling one deterministic manifest/materializer and gives
//! node startup an inspect-only capability.  Ordinary setup performs no queue
//! CQL.  Partial materialization is retained and completed idempotently; this
//! module deliberately contains no DROP path.

use std::{error::Error, fmt};

use scylla::client::session::Session;
use sha2::{Digest, Sha256};

use super::{
    pending_generation_pipeline_store::{
        PIPELINE_TABLE, RETIRED_V1_PIPELINE_TABLE,
    },
    pending_queue_consumer_gate::{
        ScyllaPendingQueueConsumerGateStore,
        PENDING_QUEUE_CONSUMER_GATE_TABLE,
    },
    pending_queue_generation_terminal::{
        ScyllaPendingQueueGenerationTerminalStore,
        PENDING_QUEUE_GENERATION_TERMINAL_TABLE,
    },
    pending_queue_segment_ledger::SEGMENT_LEDGER_TABLE,
    pending_queue_segment_lifecycle::{
        ScyllaPendingQueueSegmentLifecycleStore,
        PENDING_QUEUE_SEGMENT_LIFECYCLE_TABLE,
    },
    pending_queue_stream_provision::{
        ScyllaPendingQueueStreamProvisionStore,
        PENDING_QUEUE_STREAM_PROVISION_TABLE,
    },
    pending_queue_semantic_aggregate::{
        ScyllaPendingQueueSemanticAggregateStore,
        PENDING_QUEUE_SEMANTIC_GENERATION_TABLE,
    },
    realm_processor_application_archive::{
        ScyllaRealmProcessorApplicationArchiveStore,
        REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
        REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
    },
    realm_processor_deferred_carryover::{
        ScyllaRealmProcessorDeferredCarryoverStore,
        REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
    },
    realm_processor_generation_terminal::{
        ScyllaRealmProcessorGenerationTerminalStore,
        REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
    },
    BranchExactDeploymentNoTabletKeyspace, CqlKeyspaceName,
    PendingQueueArtifactControlKeyspace, PendingQueueArtifactDataKeyspace,
    PendingQueueArtifactKeyspaces, PendingQueuePublishDataKeyspace,
    PendingQueuePublishKeyspaces, ScyllaPendingPipelineStore,
    ScyllaPendingQueueArtifactStore, ScyllaPendingQueuePublishStore,
    ScyllaPendingQueueSegmentLedgerStore, ScyllaRealmUserUpdateClaimStore,
    ScyllaRealmUserUpdateAdmissionStore, ScyllaRealmUserUpdateDependencyStore,
    PENDING_QUEUE_ARTIFACT_FRAGMENT_TABLE,
    PENDING_QUEUE_ARTIFACT_HEADER_TABLE, PENDING_QUEUE_PUBLISH_FRAGMENT_TABLE,
    PENDING_QUEUE_PUBLISH_INTENT_TABLE, PENDING_QUEUE_PUBLISH_PREPARED_TABLE,
    PENDING_QUEUE_PUBLISH_SOURCE_TABLE, REALM_USER_UPDATE_ADMISSION_TABLE,
    REALM_USER_UPDATE_CLAIM_TABLE,
    REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE,
};

#[cfg(test)]
use super::RETIRED_REALM_USER_UPDATE_CLAIM_V1_TABLE;

// v12 adds the Realm predecessor terminal/rotation intent and successor
// deferred-carryover locator. A v11 VERIFIED receipt intentionally has a
// different deployment slot and cannot authorize this stronger contract.
pub const PENDING_QUEUE_SIDECAR_SCHEMA_VERSION: u16 = 12;
pub const PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT: usize = 20;
const FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-sidecar-schema/v12";
const INSPECT_COLUMNS_CQL: &str = "SELECT column_name, type, kind, position, clustering_order FROM system_schema.columns WHERE keyspace_name = ? AND table_name = ?";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum PendingQueueSidecarPhysicalTable {
    Pipeline = 1,
    SegmentLedger = 2,
    PublishSource = 3,
    PublishIntent = 4,
    PublishPrepared = 5,
    PublishFragment = 6,
    ArtifactHeader = 7,
    ArtifactFragment = 8,
    ConsumerGate = 9,
    SemanticGeneration = 10,
    GenerationTerminal = 11,
    SegmentLifecycle = 12,
    UserUpdateClaim = 13,
    UserUpdateDependencyFragment = 14,
    UserUpdateAdmission = 15,
    StreamProvisionBinding = 16,
    RealmApplicationArchiveHeader = 17,
    RealmApplicationArchiveFragment = 18,
    RealmGenerationTerminalIntent = 19,
    RealmDeferredCarryover = 20,
}

impl PendingQueueSidecarPhysicalTable {
    pub const ALL: [Self; PENDING_QUEUE_SIDECAR_TARGET_TABLE_COUNT] = [
        Self::Pipeline,
        Self::SegmentLedger,
        Self::PublishSource,
        Self::PublishIntent,
        Self::PublishPrepared,
        Self::PublishFragment,
        Self::ArtifactHeader,
        Self::ArtifactFragment,
        Self::ConsumerGate,
        Self::SemanticGeneration,
        Self::GenerationTerminal,
        Self::SegmentLifecycle,
        Self::UserUpdateClaim,
        Self::UserUpdateDependencyFragment,
        Self::UserUpdateAdmission,
        Self::StreamProvisionBinding,
        Self::RealmApplicationArchiveHeader,
        Self::RealmApplicationArchiveFragment,
        Self::RealmGenerationTerminalIntent,
        Self::RealmDeferredCarryover,
    ];

    pub const fn table_name(self) -> &'static str {
        match self {
            Self::Pipeline => PIPELINE_TABLE,
            Self::SegmentLedger => SEGMENT_LEDGER_TABLE,
            Self::PublishSource => PENDING_QUEUE_PUBLISH_SOURCE_TABLE,
            Self::PublishIntent => PENDING_QUEUE_PUBLISH_INTENT_TABLE,
            Self::PublishPrepared => PENDING_QUEUE_PUBLISH_PREPARED_TABLE,
            Self::PublishFragment => PENDING_QUEUE_PUBLISH_FRAGMENT_TABLE,
            Self::ArtifactHeader => PENDING_QUEUE_ARTIFACT_HEADER_TABLE,
            Self::ArtifactFragment => PENDING_QUEUE_ARTIFACT_FRAGMENT_TABLE,
            Self::ConsumerGate => PENDING_QUEUE_CONSUMER_GATE_TABLE,
            Self::SemanticGeneration => PENDING_QUEUE_SEMANTIC_GENERATION_TABLE,
            Self::GenerationTerminal => PENDING_QUEUE_GENERATION_TERMINAL_TABLE,
            Self::SegmentLifecycle => PENDING_QUEUE_SEGMENT_LIFECYCLE_TABLE,
            Self::UserUpdateClaim => REALM_USER_UPDATE_CLAIM_TABLE,
            Self::UserUpdateDependencyFragment => REALM_USER_UPDATE_DEPENDENCY_FRAGMENT_TABLE,
            Self::UserUpdateAdmission => REALM_USER_UPDATE_ADMISSION_TABLE,
            Self::StreamProvisionBinding => PENDING_QUEUE_STREAM_PROVISION_TABLE,
            Self::RealmApplicationArchiveHeader => REALM_PROCESSOR_APPLICATION_ARCHIVE_HEADER_TABLE,
            Self::RealmApplicationArchiveFragment => REALM_PROCESSOR_APPLICATION_ARCHIVE_FRAGMENT_TABLE,
            Self::RealmGenerationTerminalIntent => REALM_PROCESSOR_GENERATION_TERMINAL_TABLE,
            Self::RealmDeferredCarryover => REALM_PROCESSOR_DEFERRED_CARRYOVER_TABLE,
        }
    }

    pub const fn keyspace_kind(self) -> PendingQueueSidecarKeyspaceKind {
        match self {
            Self::PublishFragment
            | Self::ArtifactFragment
            | Self::UserUpdateDependencyFragment
            | Self::RealmApplicationArchiveFragment => {
                PendingQueueSidecarKeyspaceKind::StandardData
            }
            _ => PendingQueueSidecarKeyspaceKind::NoTabletControl,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PendingQueueSidecarKeyspaceKind {
    StandardData,
    NoTabletControl,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSidecarKeyspaces {
    data: CqlKeyspaceName,
    control: BranchExactDeploymentNoTabletKeyspace,
}

impl PendingQueueSidecarKeyspaces {
    pub fn try_new(
        data: impl Into<String>,
        control: impl Into<String>,
    ) -> Result<Self, PendingQueueSidecarSchemaError> {
        let data = data.into();
        let control = control.into();
        let data = PendingQueueArtifactDataKeyspace::try_new(data)
            .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?;
        let control = BranchExactDeploymentNoTabletKeyspace::try_new(control)
            .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?;
        Ok(Self {
            data: CqlKeyspaceName::try_new(data.as_str().to_owned())
                .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?,
            control,
        })
    }

    pub const fn data(&self) -> &CqlKeyspaceName {
        &self.data
    }

    pub const fn control(&self) -> &BranchExactDeploymentNoTabletKeyspace {
        &self.control
    }

    fn name_for(&self, table: PendingQueueSidecarPhysicalTable) -> &str {
        match table.keyspace_kind() {
            PendingQueueSidecarKeyspaceKind::StandardData => self.data.as_str(),
            PendingQueueSidecarKeyspaceKind::NoTabletControl => {
                self.control.as_str()
            }
        }
    }

    pub(crate) fn artifact_keyspaces(
        &self,
    ) -> Result<PendingQueueArtifactKeyspaces, PendingQueueSidecarSchemaError> {
        Ok(PendingQueueArtifactKeyspaces::new(
            PendingQueueArtifactControlKeyspace::try_new(
                self.control.as_str().to_owned(),
            )
            .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?,
            PendingQueueArtifactDataKeyspace::try_new(self.data.as_str().to_owned())
                .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?,
        ))
    }

    pub(crate) fn publish_keyspaces(
        &self,
    ) -> Result<PendingQueuePublishKeyspaces, PendingQueueSidecarSchemaError> {
        Ok(PendingQueuePublishKeyspaces::new(
            self.control.clone(),
            PendingQueuePublishDataKeyspace::try_new(self.data.as_str().to_owned())
                .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))?,
        ))
    }

    pub(crate) fn application_data_keyspace(
        &self,
    ) -> Result<PendingQueueArtifactDataKeyspace, PendingQueueSidecarSchemaError> {
        PendingQueueArtifactDataKeyspace::try_new(self.data.as_str().to_owned())
            .map_err(|error| PendingQueueSidecarSchemaError::InvalidKeyspace(error.to_string()))
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PendingQueueSidecarColumnKind {
    PartitionKey,
    Clustering,
    Regular,
}

impl PendingQueueSidecarColumnKind {
    const fn system_name(self) -> &'static str {
        match self {
            Self::PartitionKey => "partition_key",
            Self::Clustering => "clustering",
            Self::Regular => "regular",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PendingQueueSidecarClusteringOrder {
    Asc,
    None,
}

impl PendingQueueSidecarClusteringOrder {
    const fn system_name(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingQueueSidecarColumnSpec {
    pub table: PendingQueueSidecarPhysicalTable,
    pub name: &'static str,
    pub cql_type: &'static str,
    pub kind: PendingQueueSidecarColumnKind,
    pub position: i32,
    pub clustering_order: PendingQueueSidecarClusteringOrder,
}

const fn pk(
    table: PendingQueueSidecarPhysicalTable,
    name: &'static str,
    cql_type: &'static str,
    position: i32,
) -> PendingQueueSidecarColumnSpec {
    PendingQueueSidecarColumnSpec { table, name, cql_type, kind: PendingQueueSidecarColumnKind::PartitionKey, position, clustering_order: PendingQueueSidecarClusteringOrder::None }
}

const fn ck(
    table: PendingQueueSidecarPhysicalTable,
    name: &'static str,
    cql_type: &'static str,
    position: i32,
) -> PendingQueueSidecarColumnSpec {
    PendingQueueSidecarColumnSpec { table, name, cql_type, kind: PendingQueueSidecarColumnKind::Clustering, position, clustering_order: PendingQueueSidecarClusteringOrder::Asc }
}

const fn regular(
    table: PendingQueueSidecarPhysicalTable,
    name: &'static str,
    cql_type: &'static str,
) -> PendingQueueSidecarColumnSpec {
    PendingQueueSidecarColumnSpec { table, name, cql_type, kind: PendingQueueSidecarColumnKind::Regular, position: -1, clustering_order: PendingQueueSidecarClusteringOrder::None }
}

pub const PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS: [PendingQueueSidecarColumnSpec; 102] = [
    pk(PendingQueueSidecarPhysicalTable::Pipeline, "network_chain_id", "bigint", 0),
    pk(PendingQueueSidecarPhysicalTable::Pipeline, "authority_kind", "tinyint", 1),
    pk(PendingQueueSidecarPhysicalTable::Pipeline, "realm_id", "bigint", 2),
    pk(PendingQueueSidecarPhysicalTable::Pipeline, "realm_sub_id", "int", 3),
    regular(PendingQueueSidecarPhysicalTable::Pipeline, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::Pipeline, "pipeline", "blob"),
    pk(PendingQueueSidecarPhysicalTable::SegmentLedger, "ledger_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::SegmentLedger, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::SegmentLedger, "ledger_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::PublishSource, "source_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::PublishSource, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::PublishSource, "source_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::PublishIntent, "intent_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::PublishIntent, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::PublishIntent, "intent_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::PublishPrepared, "source_slot", "blob", 0),
    ck(PendingQueueSidecarPhysicalTable::PublishPrepared, "intent_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::PublishPrepared, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::PublishPrepared, "prepared_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::PublishFragment, "intent_slot", "blob", 0),
    pk(PendingQueueSidecarPhysicalTable::PublishFragment, "payload_digest", "blob", 1),
    pk(PendingQueueSidecarPhysicalTable::PublishFragment, "fragment_bucket", "bigint", 2),
    ck(PendingQueueSidecarPhysicalTable::PublishFragment, "fragment_index", "smallint", 0),
    regular(PendingQueueSidecarPhysicalTable::PublishFragment, "fragment_count", "smallint"),
    regular(PendingQueueSidecarPhysicalTable::PublishFragment, "payload_bytes", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::PublishFragment, "payload", "blob"),
    regular(PendingQueueSidecarPhysicalTable::PublishFragment, "fragment_digest", "blob"),
    pk(PendingQueueSidecarPhysicalTable::ArtifactHeader, "artifact_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::ArtifactHeader, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactHeader, "artifact_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::ArtifactFragment, "artifact_slot", "blob", 0),
    pk(PendingQueueSidecarPhysicalTable::ArtifactFragment, "fragment_bucket", "bigint", 1),
    ck(PendingQueueSidecarPhysicalTable::ArtifactFragment, "global_fragment_index", "bigint", 0),
    ck(PendingQueueSidecarPhysicalTable::ArtifactFragment, "candidate_digest", "blob", 1),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "batch_index", "int"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "batch_fragment_index", "smallint"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "batch_fragment_count", "smallint"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "candidate_bytes", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "payload", "blob"),
    regular(PendingQueueSidecarPhysicalTable::ArtifactFragment, "payload_digest", "blob"),
    pk(PendingQueueSidecarPhysicalTable::ConsumerGate, "gate_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::ConsumerGate, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::ConsumerGate, "gate_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::SemanticGeneration, "generation_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::SemanticGeneration, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::SemanticGeneration, "aggregate_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::GenerationTerminal, "archive_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::GenerationTerminal, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::GenerationTerminal, "terminal_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::SegmentLifecycle, "lifecycle_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::SegmentLifecycle, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::SegmentLifecycle, "lifecycle_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "network_chain_id", "bigint", 0),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "authority_kind", "tinyint", 1),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "realm_id", "bigint", 2),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "realm_sub_id", "int", 3),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "activation_digest", "blob", 4),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "unique_pending_id", "bigint", 5),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "proc_checkpoint_id", "blob", 6),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "claim_bucket", "smallint", 7),
    ck(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "user_id", "bigint", 0),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateClaim, "claim_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "dependency_slot", "blob", 0),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "dependency_digest", "blob", 1),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "component_kind", "smallint", 2),
    ck(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "fragment_index", "int", 0),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "fragment_count", "int"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "component_bytes", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "component_digest", "blob"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "payload", "blob"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment, "payload_digest", "blob"),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "network_chain_id", "bigint", 0),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "authority_kind", "tinyint", 1),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "realm_id", "bigint", 2),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "realm_sub_id", "int", 3),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "activation_digest", "blob", 4),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "unique_pending_id", "bigint", 5),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "proc_checkpoint_id", "blob", 6),
    pk(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "admission_shard", "smallint", 7),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::UserUpdateAdmission, "admission_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::StreamProvisionBinding, "provision_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::StreamProvisionBinding, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::StreamProvisionBinding, "provision_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader, "archive_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader, "archive_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "archive_slot", "blob", 0),
    pk(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "application_digest", "blob", 1),
    pk(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "fragment_bucket", "bigint", 2),
    ck(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "fragment_index", "int", 0),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "fragment_count", "int"),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "application_bytes", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "payload", "blob"),
    regular(PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment, "payload_digest", "blob"),
    pk(PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent, "terminal_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent, "terminal_payload", "blob"),
    pk(PendingQueueSidecarPhysicalTable::RealmDeferredCarryover, "successor_slot", "blob", 0),
    regular(PendingQueueSidecarPhysicalTable::RealmDeferredCarryover, "revision", "bigint"),
    regular(PendingQueueSidecarPhysicalTable::RealmDeferredCarryover, "carryover_payload", "blob"),
];

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObservedPendingQueueSidecarColumn {
    pub table: PendingQueueSidecarPhysicalTable,
    pub name: String,
    pub cql_type: String,
    pub kind: String,
    pub position: i32,
    pub clustering_order: String,
}

impl From<PendingQueueSidecarColumnSpec> for ObservedPendingQueueSidecarColumn {
    fn from(spec: PendingQueueSidecarColumnSpec) -> Self {
        Self {
            table: spec.table,
            name: spec.name.to_owned(),
            cql_type: spec.cql_type.to_owned(),
            kind: spec.kind.system_name().to_owned(),
            position: spec.position,
            clustering_order: spec.clustering_order.system_name().to_owned(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSidecarSchemaFingerprint([u8; 32]);

impl PendingQueueSidecarSchemaFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 }

    pub(super) const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarSchemaInspection {
    Absent,
    Partial { present: Vec<PendingQueueSidecarPhysicalTable>, missing: Vec<PendingQueueSidecarPhysicalTable> },
    Exact { fingerprint: PendingQueueSidecarSchemaFingerprint },
}

pub fn pending_queue_sidecar_schema_fingerprint() -> PendingQueueSidecarSchemaFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_DOMAIN);
    hasher.update(PENDING_QUEUE_SIDECAR_SCHEMA_VERSION.to_be_bytes());
    for table in PendingQueueSidecarPhysicalTable::ALL {
        hasher.update([table as u8]);
        update_len(&mut hasher, table.table_name().as_bytes());
        hasher.update([match table.keyspace_kind() { PendingQueueSidecarKeyspaceKind::StandardData => 1, PendingQueueSidecarKeyspaceKind::NoTabletControl => 2 }]);
        for column in PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.iter().filter(|column| column.table == table) {
            update_len(&mut hasher, column.name.as_bytes());
            update_len(&mut hasher, column.cql_type.as_bytes());
            update_len(&mut hasher, column.kind.system_name().as_bytes());
            hasher.update(column.position.to_be_bytes());
            update_len(&mut hasher, column.clustering_order.system_name().as_bytes());
        }
    }
    PendingQueueSidecarSchemaFingerprint(hasher.finalize().into())
}

pub fn inspect_pending_queue_sidecar_columns(
    observed: Vec<ObservedPendingQueueSidecarColumn>,
    retired_v1_present: bool,
) -> Result<PendingQueueSidecarSchemaInspection, PendingQueueSidecarSchemaError> {
    if retired_v1_present {
        return Err(PendingQueueSidecarSchemaError::RetiredPipelineV1Present);
    }
    let mut present = Vec::new();
    let mut missing = Vec::new();
    for table in PendingQueueSidecarPhysicalTable::ALL {
        let mut expected = PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.iter().copied().filter(|column| column.table == table).map(ObservedPendingQueueSidecarColumn::from).collect::<Vec<_>>();
        let mut actual = observed.iter().filter(|column| column.table == table).cloned().collect::<Vec<_>>();
        expected.sort();
        actual.sort();
        if actual.is_empty() {
            missing.push(table);
        } else if actual == expected {
            present.push(table);
        } else {
            return Err(PendingQueueSidecarSchemaError::IncompatibleTable { table, expected, observed: actual });
        }
    }
    if present.is_empty() {
        Ok(PendingQueueSidecarSchemaInspection::Absent)
    } else if missing.is_empty() {
        Ok(PendingQueueSidecarSchemaInspection::Exact { fingerprint: pending_queue_sidecar_schema_fingerprint() })
    } else {
        Ok(PendingQueueSidecarSchemaInspection::Partial { present, missing })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSidecarSchemaOnlyReceipt {
    keyspaces: PendingQueueSidecarKeyspaces,
    fingerprint: PendingQueueSidecarSchemaFingerprint,
}

impl PendingQueueSidecarSchemaOnlyReceipt {
    pub const fn keyspaces(&self) -> &PendingQueueSidecarKeyspaces { &self.keyspaces }
    pub const fn fingerprint(&self) -> PendingQueueSidecarSchemaFingerprint { self.fingerprint }
}

pub struct PendingQueueSidecarSchemaMaterializer;

impl PendingQueueSidecarSchemaMaterializer {
    pub async fn inspect_schema(
        session: &Session,
        keyspaces: &PendingQueueSidecarKeyspaces,
    ) -> Result<PendingQueueSidecarSchemaInspection, PendingQueueSidecarSchemaError> {
        let mut observed = Vec::new();
        for table in PendingQueueSidecarPhysicalTable::ALL {
            let rows = session.query_unpaged(INSPECT_COLUMNS_CQL, (keyspaces.name_for(table), table.table_name())).await.map_err(cql)?.into_rows_result().map_err(cql)?;
            for row in rows.rows::<(String, String, String, i32, String)>().map_err(cql)? {
                let (name, cql_type, kind, position, order) = row.map_err(cql)?;
                observed.push(ObservedPendingQueueSidecarColumn { table, name, cql_type, kind, position, clustering_order: order.to_ascii_lowercase() });
            }
        }
        let retired_v1_present = session.query_unpaged(INSPECT_COLUMNS_CQL, (keyspaces.control.as_str(), RETIRED_V1_PIPELINE_TABLE)).await.map_err(cql)?.into_rows_result().map_err(cql)?.rows_num() > 0;
        inspect_pending_queue_sidecar_columns(observed, retired_v1_present)
    }

    /// Explicit deployment operation. Production startup never calls it.
    pub async fn materialize_schema(
        session: &Session,
        keyspaces: &PendingQueueSidecarKeyspaces,
    ) -> Result<PendingQueueSidecarSchemaOnlyReceipt, PendingQueueSidecarSchemaError> {
        match Self::inspect_schema(session, keyspaces).await? {
            PendingQueueSidecarSchemaInspection::Exact { fingerprint } => {
                return Ok(PendingQueueSidecarSchemaOnlyReceipt { keyspaces: keyspaces.clone(), fingerprint });
            }
            PendingQueueSidecarSchemaInspection::Absent | PendingQueueSidecarSchemaInspection::Partial { .. } => {}
        }
        materialize_pre_v12_tables(session, keyspaces).await?;
        ScyllaRealmProcessorGenerationTerminalStore::create_schema(
            session,
            &keyspaces.control,
        )
        .await
        .map_err(sidecar)?;
        ScyllaRealmProcessorDeferredCarryoverStore::create_schema(
            session,
            &keyspaces.control,
        )
        .await
        .map_err(sidecar)?;
        let PendingQueueSidecarSchemaInspection::Exact { fingerprint } = Self::inspect_schema(session, keyspaces).await? else {
            return Err(PendingQueueSidecarSchemaError::DidNotConverge);
        };
        Ok(PendingQueueSidecarSchemaOnlyReceipt { keyspaces: keyspaces.clone(), fingerprint })
    }
}

async fn materialize_pre_v12_tables(
    session: &Session,
    keyspaces: &PendingQueueSidecarKeyspaces,
) -> Result<(), PendingQueueSidecarSchemaError> {
    ScyllaPendingPipelineStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueSegmentLedgerStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueConsumerGateStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueSemanticAggregateStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueGenerationTerminalStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueSegmentLifecycleStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueStreamProvisionStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaPendingQueueArtifactStore::create_schema(session, &keyspaces.artifact_keyspaces()?).await.map_err(sidecar)?;
    ScyllaPendingQueuePublishStore::create_schema(session, &keyspaces.publish_keyspaces()?).await.map_err(sidecar)?;
    ScyllaRealmUserUpdateClaimStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaRealmUserUpdateAdmissionStore::create_schema(session, &keyspaces.control).await.map_err(sidecar)?;
    ScyllaRealmUserUpdateDependencyStore::create_schema(
        session,
        &PendingQueueArtifactDataKeyspace::try_new(keyspaces.data.as_str().to_owned())
            .map_err(sidecar)?,
    )
    .await
    .map_err(sidecar)?;
    ScyllaRealmProcessorApplicationArchiveStore::create_schema(
        session,
        &keyspaces.control,
        &keyspaces.application_data_keyspace()?,
    )
    .await
    .map_err(sidecar)?;
    Ok(())
}

#[cfg(test)]
impl PendingQueueSidecarSchemaMaterializer {
    pub(super) async fn qualification_materialize_historical_v11(
        session: &Session,
        keyspaces: &PendingQueueSidecarKeyspaces,
    ) -> Result<(), PendingQueueSidecarSchemaError> {
        materialize_pre_v12_tables(session, keyspaces).await
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSidecarSchemaError {
    InvalidKeyspace(String),
    IncompatibleTable { table: PendingQueueSidecarPhysicalTable, expected: Vec<ObservedPendingQueueSidecarColumn>, observed: Vec<ObservedPendingQueueSidecarColumn> },
    RetiredPipelineV1Present,
    DidNotConverge,
    Cql(String),
    Sidecar(String),
}

impl fmt::Display for PendingQueueSidecarSchemaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}
impl Error for PendingQueueSidecarSchemaError {}

fn update_len(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}
fn cql(error: impl fmt::Display) -> PendingQueueSidecarSchemaError { PendingQueueSidecarSchemaError::Cql(error.to_string()) }
fn sidecar(error: impl fmt::Display) -> PendingQueueSidecarSchemaError { PendingQueueSidecarSchemaError::Sidecar(error.to_string()) }

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_columns() -> Vec<ObservedPendingQueueSidecarColumn> {
        PENDING_QUEUE_SIDECAR_EXPECTED_COLUMNS.iter().copied().map(Into::into).collect()
    }

    #[test]
    fn exact_manifest_is_twenty_unique_tables_with_stable_placement() {
        assert_eq!(PENDING_QUEUE_SIDECAR_SCHEMA_VERSION, 12);
        assert_eq!(PendingQueueSidecarPhysicalTable::ALL.len(), 20);
        let names = PendingQueueSidecarPhysicalTable::ALL.iter().map(|table| table.table_name()).collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), 20);
        assert_eq!(PendingQueueSidecarPhysicalTable::ALL.iter().filter(|table| table.keyspace_kind() == PendingQueueSidecarKeyspaceKind::StandardData).count(), 4);
        assert_eq!(PendingQueueSidecarPhysicalTable::ALL.iter().filter(|table| table.keyspace_kind() == PendingQueueSidecarKeyspaceKind::NoTabletControl).count(), 16);
        assert!(!names.contains(RETIRED_V1_PIPELINE_TABLE));
        assert!(!names.contains(RETIRED_REALM_USER_UPDATE_CLAIM_V1_TABLE));
        assert_ne!(pending_queue_sidecar_schema_fingerprint().as_bytes(), &[0; 32]);
    }

    #[test]
    fn exact_missing_extra_and_retired_schema_fail_closed() {
        assert!(matches!(inspect_pending_queue_sidecar_columns(exact_columns(), false).unwrap(), PendingQueueSidecarSchemaInspection::Exact { .. }));
        let mut missing = exact_columns();
        missing.retain(|column| column.table != PendingQueueSidecarPhysicalTable::ConsumerGate);
        assert!(matches!(inspect_pending_queue_sidecar_columns(missing, false).unwrap(), PendingQueueSidecarSchemaInspection::Partial { .. }));
        let mut old_v11 = exact_columns();
        old_v11.retain(|column| !matches!(
            column.table,
            PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent
                | PendingQueueSidecarPhysicalTable::RealmDeferredCarryover
        ));
        assert!(matches!(
            inspect_pending_queue_sidecar_columns(old_v11, false).unwrap(),
            PendingQueueSidecarSchemaInspection::Partial { missing, .. }
                if missing == vec![
                    PendingQueueSidecarPhysicalTable::RealmGenerationTerminalIntent,
                    PendingQueueSidecarPhysicalTable::RealmDeferredCarryover,
                ]
        ));
        let mut old_v10 = exact_columns();
        old_v10.retain(|column| !matches!(
            column.table,
            PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader
                | PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment
        ));
        assert!(matches!(
            inspect_pending_queue_sidecar_columns(old_v10, false).unwrap(),
            PendingQueueSidecarSchemaInspection::Partial { missing, .. }
                if missing == vec![
                    PendingQueueSidecarPhysicalTable::RealmApplicationArchiveHeader,
                    PendingQueueSidecarPhysicalTable::RealmApplicationArchiveFragment,
                ]
        ));
        let mut old_v8 = exact_columns();
        old_v8.retain(|column| column.table != PendingQueueSidecarPhysicalTable::StreamProvisionBinding);
        assert!(matches!(inspect_pending_queue_sidecar_columns(old_v8, false).unwrap(), PendingQueueSidecarSchemaInspection::Partial { missing, .. } if missing == vec![PendingQueueSidecarPhysicalTable::StreamProvisionBinding]));
        // A complete v5 deployment is not silently authorized as v7: the
        // admission fence is a required physical target, not an optional
        // capability inferred from the lifecycle row.
        let mut old_v5 = exact_columns();
        old_v5.retain(|column| column.table != PendingQueueSidecarPhysicalTable::UserUpdateAdmission);
        assert!(matches!(inspect_pending_queue_sidecar_columns(old_v5, false).unwrap(), PendingQueueSidecarSchemaInspection::Partial { missing, .. } if missing == vec![PendingQueueSidecarPhysicalTable::UserUpdateAdmission]));
        let mut old_thirteen = exact_columns();
        old_thirteen.retain(|column| column.table != PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment);
        assert!(matches!(inspect_pending_queue_sidecar_columns(old_thirteen, false).unwrap(), PendingQueueSidecarSchemaInspection::Partial { missing, .. } if missing == vec![PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment]));
        let mut old_twelve = exact_columns();
        old_twelve.retain(|column| !matches!(column.table, PendingQueueSidecarPhysicalTable::UserUpdateClaim | PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment));
        assert!(matches!(inspect_pending_queue_sidecar_columns(old_twelve, false).unwrap(), PendingQueueSidecarSchemaInspection::Partial { missing, .. } if missing == vec![PendingQueueSidecarPhysicalTable::UserUpdateClaim, PendingQueueSidecarPhysicalTable::UserUpdateDependencyFragment]));
        let mut incompatible = exact_columns();
        incompatible.push(ObservedPendingQueueSidecarColumn { table: PendingQueueSidecarPhysicalTable::Pipeline, name: "unexpected".to_owned(), cql_type: "blob".to_owned(), kind: "regular".to_owned(), position: -1, clustering_order: "none".to_owned() });
        assert!(matches!(inspect_pending_queue_sidecar_columns(incompatible, false), Err(PendingQueueSidecarSchemaError::IncompatibleTable { .. })));
        assert_eq!(inspect_pending_queue_sidecar_columns(exact_columns(), true), Err(PendingQueueSidecarSchemaError::RetiredPipelineV1Present));
    }

    #[test]
    fn materializer_is_explicit_and_has_no_drop_or_production_setup_registration() {
        let source = include_str!("pending_queue_sidecar_schema.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("DROP TABLE"));
        assert!(!production.contains("DROP KEYSPACE"));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains("PendingQueueSidecarSchemaMaterializer::materialize_schema"));
    }
}
