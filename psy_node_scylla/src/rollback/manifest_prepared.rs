//! Isolated D-03b durable chunk + PREPARED manifest adapter.
//!
//! Immutable chunks are written with the exact D-04a timestamp and verified
//! by QUORUM read-back before the PREPARED row is created with LWT. The module
//! is deliberately absent from production setup. D-03d2 adds exact lifecycle
//! CAS for SEALED and COMMITTED records, but no state-writer operation.

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::AuthorityScope,
    manifest_intent::PreparedAuthorityManifestIntent,
    manifest_record::{
        AuthorityManifestIdentity, ManifestRecordError,
        PreparedAuthorityManifestRecord, PreparedManifestWriteOutcome,
    },
    manifest_lifecycle::{
        CommittedAuthorityManifest, ManifestLifecycleError,
        PersistedAuthorityManifest, SealedAuthorityManifest,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};

use super::{
    decode_manifest_artifact_plan, verify_artifact_chunks,
    CanonicalManifestArtifact, CanonicalManifestArtifacts,
    CanonicalPhysicalMutationBatch, CqlKeyspaceName,
    DecodedManifestArtifactPlan, InvalidCqlKeyspaceName,
    ManifestArtifactChunk, ManifestArtifactDescriptor, ManifestArtifactError,
    ManifestArtifactKind, PreparedReferencePlusSupplementRecord,
    ReplayPrototypeError, ReplayRecordKind,
    MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET,
};

pub const D03B_AUTHORITY_MANIFEST_TABLE: &str =
    "d03b_authority_checkpoint_manifest";
pub const D03B_LOCATOR_CHUNK_TABLE: &str =
    "d03b_authority_checkpoint_locator_chunk";
pub const D03B_REPLAY_CHUNK_TABLE: &str =
    "d03b_authority_checkpoint_replay_chunk";
pub const D03B_PREPARED_PAYLOAD_CHUNK_TABLE: &str =
    "d03b_authority_prepared_payload_chunk";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidManifestControlNoTabletKeyspace(pub String);

impl fmt::Display for InvalidManifestControlNoTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "manifest control LWT keyspace {:?} must end in _no_tablet or _nt",
            self.0
        )
    }
}

impl Error for InvalidManifestControlNoTabletKeyspace {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidManifestArtifactTabletKeyspace(pub String);

impl fmt::Display for InvalidManifestArtifactTabletKeyspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "manifest artifact keyspace {:?} must not use the no-tablet suffix",
            self.0
        )
    }
}

impl Error for InvalidManifestArtifactTabletKeyspace {}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestControlNoTabletKeyspace(CqlKeyspaceName);

impl ManifestControlNoTabletKeyspace {
    pub fn try_new(
        name: impl Into<String>,
    ) -> Result<Self, ManifestPreparedError> {
        let name = name.into();
        let keyspace = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(ManifestPreparedError::InvalidControlKeyspace(
                InvalidManifestControlNoTabletKeyspace(name),
            ));
        }
        Ok(Self(keyspace))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ManifestArtifactKeyspace(CqlKeyspaceName);

impl ManifestArtifactKeyspace {
    pub fn try_new(
        name: impl Into<String>,
    ) -> Result<Self, ManifestPreparedError> {
        let name = name.into();
        if name.ends_with("_no_tablet") || name.ends_with("_nt") {
            return Err(ManifestPreparedError::InvalidArtifactKeyspace(
                InvalidManifestArtifactTabletKeyspace(name),
            ));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPreparedKeyspaces {
    control: ManifestControlNoTabletKeyspace,
    artifacts: ManifestArtifactKeyspace,
}

impl ManifestPreparedKeyspaces {
    pub const fn new(
        control: ManifestControlNoTabletKeyspace,
        artifacts: ManifestArtifactKeyspace,
    ) -> Self {
        Self { control, artifacts }
    }

    pub const fn control(&self) -> &ManifestControlNoTabletKeyspace {
        &self.control
    }

    pub const fn artifacts(&self) -> &ManifestArtifactKeyspace {
        &self.artifacts
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum ManifestPreparedQueryId {
    CreateManifest = 1,
    CreateLocatorChunk = 2,
    CreateReplayChunk = 3,
    CreatePreparedPayloadChunk = 4,
    ReadManifest = 5,
    InsertPreparedManifest = 6,
    PutLocatorChunk = 7,
    PutReplayChunk = 8,
    PutPreparedPayloadChunk = 9,
    ReadLocatorBucket = 10,
    ReadReplayBucket = 11,
    ReadPreparedPayloadBucket = 12,
    AdvanceLifecycle = 13,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPreparedQuery {
    id: ManifestPreparedQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl ManifestPreparedQuery {
    pub const fn id(&self) -> ManifestPreparedQueryId {
        self.id
    }

    pub fn cql(&self) -> &str {
        &self.cql
    }

    pub const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestPreparedQueries {
    create_manifest: ManifestPreparedQuery,
    create_chunks: [ManifestPreparedQuery; 3],
    read_manifest: ManifestPreparedQuery,
    insert_prepared_manifest: ManifestPreparedQuery,
    advance_lifecycle: ManifestPreparedQuery,
    put_chunks: [ManifestPreparedQuery; 3],
    read_buckets: [ManifestPreparedQuery; 3],
}

impl ManifestPreparedQueries {
    pub fn new(keyspaces: &ManifestPreparedKeyspaces) -> Self {
        let manifest = format!(
            "{}.{D03B_AUTHORITY_MANIFEST_TABLE}",
            keyspaces.control().as_str()
        );
        let locator = format!(
            "{}.{D03B_LOCATOR_CHUNK_TABLE}",
            keyspaces.artifacts().as_str()
        );
        let replay = format!(
            "{}.{D03B_REPLAY_CHUNK_TABLE}",
            keyspaces.artifacts().as_str()
        );
        let prepared_payload = format!(
            "{}.{D03B_PREPARED_PAYLOAD_CHUNK_TABLE}",
            keyspaces.artifacts().as_str()
        );
        let create_chunk = |id, table: &str| ManifestPreparedQuery {
            id,
            cql: format!(
                "CREATE TABLE IF NOT EXISTS {table} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id bigint, chain_epoch bigint, checkpoint_id bigint, checkpoint_hash blob, manifest_digest blob, chunk_bucket int, chunk_index int, encoding_version smallint, total_chunks int, payload blob, payload_hash blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, chain_epoch, checkpoint_id, checkpoint_hash, manifest_digest, chunk_bucket), chunk_index))"
            ),
            bind_shape: &[],
        };
        let put_chunk = |id, table: &str| ManifestPreparedQuery {
            id,
            cql: format!(
                "INSERT INTO {table} (network_chain_id, authority_kind, realm_id, realm_sub_id, chain_epoch, checkpoint_id, checkpoint_hash, manifest_digest, chunk_bucket, chunk_index, encoding_version, total_chunks, payload, payload_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) USING TIMESTAMP ?"
            ),
            bind_shape: CHUNK_PUT_BIND_SHAPE,
        };
        let read_bucket = |id, table: &str| ManifestPreparedQuery {
            id,
            cql: format!(
                "SELECT chunk_bucket, chunk_index, encoding_version, total_chunks, payload, payload_hash FROM {table} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND chain_epoch = ? AND checkpoint_id = ? AND checkpoint_hash = ? AND manifest_digest = ? AND chunk_bucket = ?"
            ),
            bind_shape: CHUNK_BUCKET_BIND_SHAPE,
        };
        Self {
            create_manifest: ManifestPreparedQuery {
                id: ManifestPreparedQueryId::CreateManifest,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {manifest} (network_chain_id bigint, authority_kind tinyint, realm_id bigint, realm_sub_id bigint, checkpoint_bucket bigint, chain_epoch bigint, checkpoint_id bigint, checkpoint_hash blob, revision bigint, status tinyint, manifest_digest blob, lifecycle_digest blob, manifest_payload blob, PRIMARY KEY ((network_chain_id, authority_kind, realm_id, realm_sub_id, checkpoint_bucket), chain_epoch, checkpoint_id, checkpoint_hash))"
                ),
                bind_shape: &[],
            },
            create_chunks: [
                create_chunk(
                    ManifestPreparedQueryId::CreateLocatorChunk,
                    &locator,
                ),
                create_chunk(
                    ManifestPreparedQueryId::CreateReplayChunk,
                    &replay,
                ),
                create_chunk(
                    ManifestPreparedQueryId::CreatePreparedPayloadChunk,
                    &prepared_payload,
                ),
            ],
            read_manifest: ManifestPreparedQuery {
                id: ManifestPreparedQueryId::ReadManifest,
                cql: format!(
                    "SELECT revision, status, manifest_digest, lifecycle_digest, manifest_payload FROM {manifest} WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND checkpoint_bucket = ? AND chain_epoch = ? AND checkpoint_id = ? AND checkpoint_hash = ?"
                ),
                bind_shape: MANIFEST_IDENTITY_BIND_SHAPE,
            },
            insert_prepared_manifest: ManifestPreparedQuery {
                id: ManifestPreparedQueryId::InsertPreparedManifest,
                cql: format!(
                    "INSERT INTO {manifest} (network_chain_id, authority_kind, realm_id, realm_sub_id, checkpoint_bucket, chain_epoch, checkpoint_id, checkpoint_hash, revision, status, manifest_digest, lifecycle_digest, manifest_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: MANIFEST_INSERT_BIND_SHAPE,
            },
            advance_lifecycle: ManifestPreparedQuery {
                id: ManifestPreparedQueryId::AdvanceLifecycle,
                cql: format!(
                    "UPDATE {manifest} SET revision = ?, status = ?, lifecycle_digest = ?, manifest_payload = ? WHERE network_chain_id = ? AND authority_kind = ? AND realm_id = ? AND realm_sub_id = ? AND checkpoint_bucket = ? AND chain_epoch = ? AND checkpoint_id = ? AND checkpoint_hash = ? IF revision = ? AND status = ? AND manifest_digest = ? AND lifecycle_digest = ? AND manifest_payload = ?"
                ),
                bind_shape: MANIFEST_LIFECYCLE_CAS_BIND_SHAPE,
            },
            put_chunks: [
                put_chunk(ManifestPreparedQueryId::PutLocatorChunk, &locator),
                put_chunk(ManifestPreparedQueryId::PutReplayChunk, &replay),
                put_chunk(
                    ManifestPreparedQueryId::PutPreparedPayloadChunk,
                    &prepared_payload,
                ),
            ],
            read_buckets: [
                read_bucket(
                    ManifestPreparedQueryId::ReadLocatorBucket,
                    &locator,
                ),
                read_bucket(
                    ManifestPreparedQueryId::ReadReplayBucket,
                    &replay,
                ),
                read_bucket(
                    ManifestPreparedQueryId::ReadPreparedPayloadBucket,
                    &prepared_payload,
                ),
            ],
        }
    }

    pub const fn create_manifest(&self) -> &ManifestPreparedQuery {
        &self.create_manifest
    }

    pub const fn create_chunks(&self) -> &[ManifestPreparedQuery; 3] {
        &self.create_chunks
    }

    pub const fn read_manifest(&self) -> &ManifestPreparedQuery {
        &self.read_manifest
    }

    pub const fn insert_prepared_manifest(&self) -> &ManifestPreparedQuery {
        &self.insert_prepared_manifest
    }

    pub const fn advance_lifecycle(&self) -> &ManifestPreparedQuery {
        &self.advance_lifecycle
    }

    pub const fn put_chunk(
        &self,
        kind: ManifestArtifactKind,
    ) -> &ManifestPreparedQuery {
        &self.put_chunks[kind_index(kind)]
    }

    pub const fn read_bucket(
        &self,
        kind: ManifestArtifactKind,
    ) -> &ManifestPreparedQuery {
        &self.read_buckets[kind_index(kind)]
    }

    pub fn render_golden(&self) -> String {
        let mut output = String::new();
        for query in std::iter::once(&self.create_manifest)
            .chain(self.create_chunks.iter())
            .chain(std::iter::once(&self.read_manifest))
            .chain(std::iter::once(&self.insert_prepared_manifest))
            .chain(std::iter::once(&self.advance_lifecycle))
            .chain(self.put_chunks.iter())
            .chain(self.read_buckets.iter())
        {
            output.push_str(&format!(
                "{:?}|{}\n{}\n",
                query.id,
                query.bind_shape.join(","),
                query.cql
            ));
        }
        output
    }
}

const MANIFEST_IDENTITY_BIND_SHAPE: &[&str] = &[
    "network_chain_id:BIGINT",
    "authority_kind:TINYINT",
    "realm_id:BIGINT",
    "realm_sub_id:BIGINT",
    "checkpoint_bucket:BIGINT",
    "chain_epoch:BIGINT",
    "checkpoint_id:BIGINT",
    "checkpoint_hash:BLOB",
];

const MANIFEST_INSERT_BIND_SHAPE: &[&str] = &[
    "network_chain_id:BIGINT",
    "authority_kind:TINYINT",
    "realm_id:BIGINT",
    "realm_sub_id:BIGINT",
    "checkpoint_bucket:BIGINT",
    "chain_epoch:BIGINT",
    "checkpoint_id:BIGINT",
    "checkpoint_hash:BLOB",
    "revision:BIGINT",
    "status:TINYINT",
    "manifest_digest:BLOB",
    "lifecycle_digest:BLOB",
    "manifest_payload:BLOB",
];

const MANIFEST_LIFECYCLE_CAS_BIND_SHAPE: &[&str] = &[
    "candidate_revision:BIGINT",
    "candidate_status:TINYINT",
    "candidate_lifecycle_digest:BLOB",
    "candidate_manifest_payload:BLOB",
    "network_chain_id:BIGINT",
    "authority_kind:TINYINT",
    "realm_id:BIGINT",
    "realm_sub_id:BIGINT",
    "checkpoint_bucket:BIGINT",
    "chain_epoch:BIGINT",
    "checkpoint_id:BIGINT",
    "checkpoint_hash:BLOB",
    "expected_revision:BIGINT",
    "expected_status:TINYINT",
    "expected_manifest_digest:BLOB",
    "expected_lifecycle_digest:BLOB",
    "expected_manifest_payload:BLOB",
];

const CHUNK_PUT_BIND_SHAPE: &[&str] = &[
    "network_chain_id:BIGINT",
    "authority_kind:TINYINT",
    "realm_id:BIGINT",
    "realm_sub_id:BIGINT",
    "chain_epoch:BIGINT",
    "checkpoint_id:BIGINT",
    "checkpoint_hash:BLOB",
    "manifest_digest:BLOB",
    "chunk_bucket:INT",
    "chunk_index:INT",
    "encoding_version:SMALLINT",
    "total_chunks:INT",
    "payload:BLOB",
    "payload_hash:BLOB",
    "commit_write_timestamp_us:BIGINT",
];

const CHUNK_BUCKET_BIND_SHAPE: &[&str] = &[
    "network_chain_id:BIGINT",
    "authority_kind:TINYINT",
    "realm_id:BIGINT",
    "realm_sub_id:BIGINT",
    "chain_epoch:BIGINT",
    "checkpoint_id:BIGINT",
    "checkpoint_hash:BLOB",
    "manifest_digest:BLOB",
    "chunk_bucket:INT",
];

const fn kind_index(kind: ManifestArtifactKind) -> usize {
    match kind {
        ManifestArtifactKind::Locator => 0,
        ManifestArtifactKind::ReplayRecord => 1,
        ManifestArtifactKind::DurablePreparedPayload => 2,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestPreparedBindValue {
    TinyInt(i8),
    SmallInt(i16),
    Int(i32),
    BigInt(i64),
    Blob(Vec<u8>),
}

impl ManifestPreparedBindValue {
    fn render(&self) -> String {
        match self {
            Self::TinyInt(value) => format!("TINYINT:{value}"),
            Self::SmallInt(value) => format!("SMALLINT:{value}"),
            Self::Int(value) => format!("INT:{value}"),
            Self::BigInt(value) => format!("BIGINT:{value}"),
            Self::Blob(value) => format!("BLOB:{}", hex::encode(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ManifestPartition {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
}

impl ManifestPartition {
    fn try_from_identity<Hash: Q256BitHash>(
        identity: &AuthorityManifestIdentity<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        let (authority_kind, realm_id, realm_sub_id) =
            match identity.authority() {
                AuthorityScope::Coordinator => (1, 0, 0),
                AuthorityScope::Realm {
                    realm_id,
                    realm_sub_id,
                } => (2, i64::from(realm_id), i64::from(realm_sub_id)),
            };
        Ok(Self {
            network_chain_id: i64::from(identity.network().chain_id()),
            authority_kind,
            realm_id,
            realm_sub_id,
            chain_epoch: i64::try_from(identity.chain_epoch().get())
                .map_err(|_| ManifestPreparedError::ChainEpochOutOfRange)?,
            checkpoint_id: i64::try_from(
                identity.checkpoint().checkpoint_id().get(),
            )
            .map_err(|_| ManifestPreparedError::CheckpointIdOutOfRange)?,
            checkpoint_hash: identity
                .checkpoint()
                .checkpoint_hash()
                .as_inner()
                .into_owned_32bytes()
                .to_vec(),
        })
    }

}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct ManifestReadBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    checkpoint_bucket: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
}

impl ManifestReadBinding {
    pub fn try_from_identity<Hash: Q256BitHash>(
        identity: &AuthorityManifestIdentity<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        let partition = ManifestPartition::try_from_identity(identity)?;
        Ok(Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            checkpoint_bucket: i64::try_from(identity.checkpoint_bucket())
                .map_err(|_| ManifestPreparedError::CheckpointBucketOutOfRange)?,
            chain_epoch: partition.chain_epoch,
            checkpoint_id: partition.checkpoint_id,
            checkpoint_hash: partition.checkpoint_hash,
        })
    }

    pub fn values(&self) -> Vec<ManifestPreparedBindValue> {
        vec![
            ManifestPreparedBindValue::BigInt(self.network_chain_id),
            ManifestPreparedBindValue::TinyInt(self.authority_kind),
            ManifestPreparedBindValue::BigInt(self.realm_id),
            ManifestPreparedBindValue::BigInt(self.realm_sub_id),
            ManifestPreparedBindValue::BigInt(self.checkpoint_bucket),
            ManifestPreparedBindValue::BigInt(self.chain_epoch),
            ManifestPreparedBindValue::BigInt(self.checkpoint_id),
            ManifestPreparedBindValue::Blob(self.checkpoint_hash.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct PreparedManifestInsertBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    checkpoint_bucket: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
    revision: i64,
    status: i8,
    manifest_digest: Vec<u8>,
    lifecycle_digest: Vec<u8>,
    manifest_payload: Vec<u8>,
}

impl PreparedManifestInsertBinding {
    pub fn try_from_record<Hash: Q256BitHash>(
        record: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        let identity = ManifestReadBinding::try_from_identity(record.identity())?;
        Ok(Self {
            network_chain_id: identity.network_chain_id,
            authority_kind: identity.authority_kind,
            realm_id: identity.realm_id,
            realm_sub_id: identity.realm_sub_id,
            checkpoint_bucket: identity.checkpoint_bucket,
            chain_epoch: identity.chain_epoch,
            checkpoint_id: identity.checkpoint_id,
            checkpoint_hash: identity.checkpoint_hash,
            revision: record.revision().as_i64(),
            status: record.status() as i8,
            manifest_digest: record.digest().as_bytes().to_vec(),
            lifecycle_digest: record.digest().as_bytes().to_vec(),
            manifest_payload: record.encode_canonical().to_vec(),
        })
    }

    pub fn values(&self) -> Vec<ManifestPreparedBindValue> {
        let mut values = ManifestReadBinding {
            network_chain_id: self.network_chain_id,
            authority_kind: self.authority_kind,
            realm_id: self.realm_id,
            realm_sub_id: self.realm_sub_id,
            checkpoint_bucket: self.checkpoint_bucket,
            chain_epoch: self.chain_epoch,
            checkpoint_id: self.checkpoint_id,
            checkpoint_hash: self.checkpoint_hash.clone(),
        }
        .values();
        values.extend([
            ManifestPreparedBindValue::BigInt(self.revision),
            ManifestPreparedBindValue::TinyInt(self.status),
            ManifestPreparedBindValue::Blob(self.manifest_digest.clone()),
            ManifestPreparedBindValue::Blob(self.lifecycle_digest.clone()),
            ManifestPreparedBindValue::Blob(self.manifest_payload.clone()),
        ]);
        values
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

/// Exact compare-and-set binding for one allowed lifecycle edge. The
/// immutable PREPARED digest is compared but never updated; only revision,
/// status, lifecycle digest and canonical lifecycle payload change.
#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct ManifestLifecycleCasBinding {
    candidate_revision: i64,
    candidate_status: i8,
    candidate_lifecycle_digest: Vec<u8>,
    candidate_manifest_payload: Vec<u8>,
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    checkpoint_bucket: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
    expected_revision: i64,
    expected_status: i8,
    expected_manifest_digest: Vec<u8>,
    expected_lifecycle_digest: Vec<u8>,
    expected_manifest_payload: Vec<u8>,
}

impl ManifestLifecycleCasBinding {
    pub fn try_from_sealed<Hash: Q256BitHash>(
        candidate: &SealedAuthorityManifest<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        let expected = PersistedAuthorityManifest::Prepared(
            candidate.prepared().clone(),
        );
        let candidate = PersistedAuthorityManifest::Sealed(candidate.clone());
        Self::try_new(&expected, &candidate)
    }

    pub fn try_from_committed<Hash: Q256BitHash>(
        candidate: &CommittedAuthorityManifest<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        let expected =
            PersistedAuthorityManifest::Sealed(candidate.sealed().clone());
        let candidate =
            PersistedAuthorityManifest::Committed(candidate.clone());
        Self::try_new(&expected, &candidate)
    }

    fn try_new<Hash: Q256BitHash>(
        expected: &PersistedAuthorityManifest<Hash>,
        candidate: &PersistedAuthorityManifest<Hash>,
    ) -> Result<Self, ManifestPreparedError> {
        if expected.identity() != candidate.identity()
            || candidate.revision().get()
                != expected.revision().get().checked_add(1).ok_or(
                    ManifestPreparedError::LifecycleRevisionOverflow,
                )?
        {
            return Err(ManifestPreparedError::InvalidLifecycleTransition);
        }
        let identity = ManifestReadBinding::try_from_identity(expected.identity())?;
        Ok(Self {
            candidate_revision: candidate.revision().as_i64(),
            candidate_status: candidate.status() as i8,
            candidate_lifecycle_digest: candidate
                .lifecycle_digest()
                .as_bytes()
                .to_vec(),
            candidate_manifest_payload: candidate.encode_canonical().to_vec(),
            network_chain_id: identity.network_chain_id,
            authority_kind: identity.authority_kind,
            realm_id: identity.realm_id,
            realm_sub_id: identity.realm_sub_id,
            checkpoint_bucket: identity.checkpoint_bucket,
            chain_epoch: identity.chain_epoch,
            checkpoint_id: identity.checkpoint_id,
            checkpoint_hash: identity.checkpoint_hash,
            expected_revision: expected.revision().as_i64(),
            expected_status: expected.status() as i8,
            expected_manifest_digest: expected
                .prepared()
                .digest()
                .as_bytes()
                .to_vec(),
            expected_lifecycle_digest: expected
                .lifecycle_digest()
                .as_bytes()
                .to_vec(),
            expected_manifest_payload: expected.encode_canonical().to_vec(),
        })
    }

    pub fn values(&self) -> Vec<ManifestPreparedBindValue> {
        vec![
            ManifestPreparedBindValue::BigInt(self.candidate_revision),
            ManifestPreparedBindValue::TinyInt(self.candidate_status),
            ManifestPreparedBindValue::Blob(
                self.candidate_lifecycle_digest.clone(),
            ),
            ManifestPreparedBindValue::Blob(
                self.candidate_manifest_payload.clone(),
            ),
            ManifestPreparedBindValue::BigInt(self.network_chain_id),
            ManifestPreparedBindValue::TinyInt(self.authority_kind),
            ManifestPreparedBindValue::BigInt(self.realm_id),
            ManifestPreparedBindValue::BigInt(self.realm_sub_id),
            ManifestPreparedBindValue::BigInt(self.checkpoint_bucket),
            ManifestPreparedBindValue::BigInt(self.chain_epoch),
            ManifestPreparedBindValue::BigInt(self.checkpoint_id),
            ManifestPreparedBindValue::Blob(self.checkpoint_hash.clone()),
            ManifestPreparedBindValue::BigInt(self.expected_revision),
            ManifestPreparedBindValue::TinyInt(self.expected_status),
            ManifestPreparedBindValue::Blob(
                self.expected_manifest_digest.clone(),
            ),
            ManifestPreparedBindValue::Blob(
                self.expected_lifecycle_digest.clone(),
            ),
            ManifestPreparedBindValue::Blob(
                self.expected_manifest_payload.clone(),
            ),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct ManifestChunkPutBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
    manifest_digest: Vec<u8>,
    chunk_bucket: i32,
    chunk_index: i32,
    encoding_version: i16,
    total_chunks: i32,
    payload: Vec<u8>,
    payload_hash: Vec<u8>,
    commit_write_timestamp_us: i64,
}

impl ManifestChunkPutBinding {
    pub fn try_new<Hash: Q256BitHash>(
        record: &PreparedAuthorityManifestRecord<Hash>,
        chunk: &ManifestArtifactChunk,
    ) -> Result<Self, ManifestPreparedError> {
        let partition = ManifestPartition::try_from_identity(record.identity())?;
        Ok(Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            chain_epoch: partition.chain_epoch,
            checkpoint_id: partition.checkpoint_id,
            checkpoint_hash: partition.checkpoint_hash,
            manifest_digest: record.digest().as_bytes().to_vec(),
            chunk_bucket: i32::try_from(chunk.chunk_bucket())
                .map_err(|_| ManifestPreparedError::ChunkCoordinateOutOfRange)?,
            chunk_index: i32::try_from(chunk.chunk_index())
                .map_err(|_| ManifestPreparedError::ChunkCoordinateOutOfRange)?,
            encoding_version: i16::try_from(chunk.encoding_version())
                .map_err(|_| ManifestPreparedError::ChunkCoordinateOutOfRange)?,
            total_chunks: i32::try_from(chunk.total_chunks())
                .map_err(|_| ManifestPreparedError::ChunkCoordinateOutOfRange)?,
            payload: chunk.payload().to_vec(),
            payload_hash: chunk.payload_hash().as_bytes().to_vec(),
            commit_write_timestamp_us: record.commit_write_timestamp().as_i64(),
        })
    }

    pub fn values(&self) -> Vec<ManifestPreparedBindValue> {
        vec![
            ManifestPreparedBindValue::BigInt(self.network_chain_id),
            ManifestPreparedBindValue::TinyInt(self.authority_kind),
            ManifestPreparedBindValue::BigInt(self.realm_id),
            ManifestPreparedBindValue::BigInt(self.realm_sub_id),
            ManifestPreparedBindValue::BigInt(self.chain_epoch),
            ManifestPreparedBindValue::BigInt(self.checkpoint_id),
            ManifestPreparedBindValue::Blob(self.checkpoint_hash.clone()),
            ManifestPreparedBindValue::Blob(self.manifest_digest.clone()),
            ManifestPreparedBindValue::Int(self.chunk_bucket),
            ManifestPreparedBindValue::Int(self.chunk_index),
            ManifestPreparedBindValue::SmallInt(self.encoding_version),
            ManifestPreparedBindValue::Int(self.total_chunks),
            ManifestPreparedBindValue::Blob(self.payload.clone()),
            ManifestPreparedBindValue::Blob(self.payload_hash.clone()),
            ManifestPreparedBindValue::BigInt(self.commit_write_timestamp_us),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct ManifestChunkBucketReadBinding {
    network_chain_id: i64,
    authority_kind: i8,
    realm_id: i64,
    realm_sub_id: i64,
    chain_epoch: i64,
    checkpoint_id: i64,
    checkpoint_hash: Vec<u8>,
    manifest_digest: Vec<u8>,
    chunk_bucket: i32,
}

impl ManifestChunkBucketReadBinding {
    pub fn try_new<Hash: Q256BitHash>(
        record: &PreparedAuthorityManifestRecord<Hash>,
        chunk_bucket: u32,
    ) -> Result<Self, ManifestPreparedError> {
        let partition = ManifestPartition::try_from_identity(record.identity())?;
        Ok(Self {
            network_chain_id: partition.network_chain_id,
            authority_kind: partition.authority_kind,
            realm_id: partition.realm_id,
            realm_sub_id: partition.realm_sub_id,
            chain_epoch: partition.chain_epoch,
            checkpoint_id: partition.checkpoint_id,
            checkpoint_hash: partition.checkpoint_hash,
            manifest_digest: record.digest().as_bytes().to_vec(),
            chunk_bucket: i32::try_from(chunk_bucket)
                .map_err(|_| ManifestPreparedError::ChunkCoordinateOutOfRange)?,
        })
    }

    pub fn values(&self) -> Vec<ManifestPreparedBindValue> {
        vec![
            ManifestPreparedBindValue::BigInt(self.network_chain_id),
            ManifestPreparedBindValue::TinyInt(self.authority_kind),
            ManifestPreparedBindValue::BigInt(self.realm_id),
            ManifestPreparedBindValue::BigInt(self.realm_sub_id),
            ManifestPreparedBindValue::BigInt(self.chain_epoch),
            ManifestPreparedBindValue::BigInt(self.checkpoint_id),
            ManifestPreparedBindValue::Blob(self.checkpoint_hash.clone()),
            ManifestPreparedBindValue::Blob(self.manifest_digest.clone()),
            ManifestPreparedBindValue::Int(self.chunk_bucket),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_bind_values(&self.values())
    }
}

fn render_bind_values(values: &[ManifestPreparedBindValue]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}:{}", value.render()))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One inseparable package accepted by the durable adapter. Construction
/// verifies that the artifact summary is exactly the one committed by the
/// prepared authority intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPreparedManifestPackage<Hash> {
    record: PreparedAuthorityManifestRecord<Hash>,
    artifacts: CanonicalManifestArtifacts,
}

/// Capability issued only after every chunk for one exact manifest digest
/// has been read back and verified. A conflicting intent at the same chain
/// identity cannot reuse this receipt because its manifest digest differs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPreparedChunkReceipt<Hash> {
    identity: AuthorityManifestIdentity<Hash>,
    manifest_digest: [u8; 32],
}

impl<Hash: Q256BitHash> VerifiedPreparedChunkReceipt<Hash> {
    fn from_verified_record(
        record: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Self {
        Self {
            identity: *record.identity(),
            manifest_digest: *record.digest().as_bytes(),
        }
    }

    pub const fn identity(&self) -> &AuthorityManifestIdentity<Hash> {
        &self.identity
    }

    pub const fn manifest_digest(&self) -> &[u8; 32] {
        &self.manifest_digest
    }

    pub fn verify_for(
        &self,
        record: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<(), ManifestPreparedError> {
        if self.identity == *record.identity()
            && self.manifest_digest == *record.digest().as_bytes()
        {
            Ok(())
        } else {
            Err(ManifestPreparedError::VerifiedChunkReceiptMismatch)
        }
    }
}

impl<Hash: Q256BitHash> VerifiedPreparedManifestPackage<Hash> {
    pub fn try_new(
        prepared: &PreparedAuthorityManifestIntent<Hash>,
        artifacts: CanonicalManifestArtifacts,
    ) -> Result<Self, ManifestPreparedError> {
        artifacts.verify_integrity()?;
        if prepared.intent().artifacts() != artifacts.commitment() {
            return Err(ManifestPreparedError::IntentArtifactMismatch);
        }
        let record = PreparedAuthorityManifestRecord::seal(
            prepared,
            artifacts.canonical_summary().to_vec(),
        )?;
        Ok(Self { record, artifacts })
    }

    pub const fn record(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.record
    }

    pub const fn artifacts(&self) -> &CanonicalManifestArtifacts {
        &self.artifacts
    }
}

/// Durable chunks reloaded and verified solely from a PREPARED manifest row.
/// A zero-mutation checkpoint carries its compact replay receipt inline and
/// therefore has no locator or payload chunks.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPersistedManifestArtifacts {
    plan: DecodedManifestArtifactPlan,
    locator: Option<Vec<u8>>,
    replay_record: Vec<u8>,
    durable_prepared_payload: Option<Vec<u8>>,
}

impl VerifiedPersistedManifestArtifacts {
    pub const fn plan(&self) -> &DecodedManifestArtifactPlan {
        &self.plan
    }

    pub fn locator(&self) -> Option<&[u8]> {
        self.locator.as_deref()
    }

    pub fn replay_record(&self) -> &[u8] {
        &self.replay_record
    }

    pub fn durable_prepared_payload(&self) -> Option<&[u8]> {
        self.durable_prepared_payload.as_deref()
    }

    /// Rebuilds the executable compact batch solely from durable bytes loaded
    /// after restart. Both the compact record's internal commitment and the
    /// PREPARED manifest's mutation digest must match.
    pub fn decode_and_expand_compact_replay(
        &self,
    ) -> Result<CanonicalPhysicalMutationBatch, ReplayPrototypeError> {
        if self.plan.replay_record_kind()
            != Some(ReplayRecordKind::PreparedReferencePlusSupplement)
        {
            return Err(ReplayPrototypeError::CompactReplayArtifactsRequired);
        }
        let payload = self
            .durable_prepared_payload()
            .ok_or(ReplayPrototypeError::DurablePreparedPayloadMissing)?;
        let record = PreparedReferencePlusSupplementRecord::decode_canonical(
            self.replay_record(),
        )?;
        let expanded = record.expand(payload)?;
        if expanded.digest().as_bytes() != self.plan.mutation_digest() {
            return Err(ReplayPrototypeError::ManifestMutationDigestMismatch);
        }
        Ok(expanded)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestPreparedConsistencyContract {
    chunk_write: Consistency,
    read: Consistency,
    lwt_regular: Consistency,
    lwt_serial: SerialConsistency,
}

impl ManifestPreparedConsistencyContract {
    pub const fn rf3_default() -> Self {
        Self {
            chunk_write: Consistency::Quorum,
            read: Consistency::Quorum,
            lwt_regular: Consistency::Quorum,
            lwt_serial: SerialConsistency::LocalSerial,
        }
    }

    pub const fn chunk_write(self) -> Consistency {
        self.chunk_write
    }

    pub const fn read(self) -> Consistency {
        self.read
    }

    pub const fn lwt_regular(self) -> Consistency {
        self.lwt_regular
    }

    pub const fn lwt_serial(self) -> SerialConsistency {
        self.lwt_serial
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ManifestDbRow {
    revision: i64,
    status: i8,
    manifest_digest: Vec<u8>,
    lifecycle_digest: Vec<u8>,
    manifest_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestLifecycleWriteOutcome<Hash> {
    Applied(PersistedAuthorityManifest<Hash>),
    Idempotent(PersistedAuthorityManifest<Hash>),
    Conflict {
        current: PersistedAuthorityManifest<Hash>,
    },
}

pub fn classify_lifecycle_cas_observation<Hash: Q256BitHash>(
    applied: bool,
    candidate: PersistedAuthorityManifest<Hash>,
    current: PersistedAuthorityManifest<Hash>,
) -> Result<ManifestLifecycleWriteOutcome<Hash>, ManifestPreparedError> {
    if current == candidate {
        if applied {
            Ok(ManifestLifecycleWriteOutcome::Applied(current))
        } else {
            Ok(ManifestLifecycleWriteOutcome::Idempotent(current))
        }
    } else if applied {
        Err(ManifestPreparedError::AppliedLifecycleCasMismatch)
    } else {
        Ok(ManifestLifecycleWriteOutcome::Conflict { current })
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct ManifestChunkDbRow {
    chunk_bucket: i32,
    chunk_index: i32,
    encoding_version: i16,
    total_chunks: i32,
    payload: Vec<u8>,
    payload_hash: Vec<u8>,
}

/// Real prepare/execute adapter kept outside production setup.
pub struct ScyllaPreparedManifestStore {
    session: Arc<Session>,
    queries: ManifestPreparedQueries,
    contract: ManifestPreparedConsistencyContract,
    read_manifest: PreparedStatement,
    insert_manifest: PreparedStatement,
    advance_lifecycle: PreparedStatement,
    put_chunks: [PreparedStatement; 3],
    read_buckets: [PreparedStatement; 3],
}

impl ScyllaPreparedManifestStore {
    pub async fn create_schema(
        session: &Session,
        keyspaces: &ManifestPreparedKeyspaces,
    ) -> Result<(), ManifestPreparedError> {
        let queries = ManifestPreparedQueries::new(keyspaces);
        session
            .query_unpaged(queries.create_manifest().cql(), &[])
            .await
            .map_err(cql_error)?;
        for query in queries.create_chunks() {
            session
                .query_unpaged(query.cql(), &[])
                .await
                .map_err(cql_error)?;
        }
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspaces: ManifestPreparedKeyspaces,
    ) -> Result<Self, ManifestPreparedError> {
        let queries = ManifestPreparedQueries::new(&keyspaces);
        let contract = ManifestPreparedConsistencyContract::rf3_default();
        let read_manifest =
            prepare_regular(&session, queries.read_manifest().cql(), contract.read())
                .await?;
        let insert_manifest = prepare_lwt(
            &session,
            queries.insert_prepared_manifest().cql(),
            contract,
        )
        .await?;
        let advance_lifecycle = prepare_lwt(
            &session,
            queries.advance_lifecycle().cql(),
            contract,
        )
        .await?;
        let put_chunks = [
            prepare_regular(
                &session,
                queries.put_chunk(ManifestArtifactKind::Locator).cql(),
                contract.chunk_write(),
            )
            .await?,
            prepare_regular(
                &session,
                queries.put_chunk(ManifestArtifactKind::ReplayRecord).cql(),
                contract.chunk_write(),
            )
            .await?,
            prepare_regular(
                &session,
                queries
                    .put_chunk(ManifestArtifactKind::DurablePreparedPayload)
                    .cql(),
                contract.chunk_write(),
            )
            .await?,
        ];
        let read_buckets = [
            prepare_regular(
                &session,
                queries
                    .read_bucket(ManifestArtifactKind::Locator)
                    .cql(),
                contract.read(),
            )
            .await?,
            prepare_regular(
                &session,
                queries
                    .read_bucket(ManifestArtifactKind::ReplayRecord)
                    .cql(),
                contract.read(),
            )
            .await?,
            prepare_regular(
                &session,
                queries
                    .read_bucket(ManifestArtifactKind::DurablePreparedPayload)
                    .cql(),
                contract.read(),
            )
            .await?,
        ];
        Ok(Self {
            session,
            queries,
            contract,
            read_manifest,
            insert_manifest,
            advance_lifecycle,
            put_chunks,
            read_buckets,
        })
    }

    pub const fn queries(&self) -> &ManifestPreparedQueries {
        &self.queries
    }

    pub const fn consistency_contract(
        &self,
    ) -> ManifestPreparedConsistencyContract {
        self.contract
    }

    pub async fn persist_prepared<Hash: Q256BitHash>(
        &self,
        package: &VerifiedPreparedManifestPackage<Hash>,
    ) -> Result<PreparedManifestWriteOutcome<Hash>, ManifestPreparedError> {
        let receipt = self.persist_artifacts(package).await?;
        self.insert_prepared(package.record(), &receipt).await
    }

    pub async fn persist_artifacts<Hash: Q256BitHash>(
        &self,
        package: &VerifiedPreparedManifestPackage<Hash>,
    ) -> Result<VerifiedPreparedChunkReceipt<Hash>, ManifestPreparedError> {
        self.persist_and_verify_chunks(package).await?;
        Ok(VerifiedPreparedChunkReceipt::from_verified_record(
            package.record(),
        ))
    }

    pub async fn verify_existing_artifacts<Hash: Q256BitHash>(
        &self,
        package: &VerifiedPreparedManifestPackage<Hash>,
    ) -> Result<VerifiedPreparedChunkReceipt<Hash>, ManifestPreparedError> {
        package.artifacts().verify_integrity()?;
        if let Some(set) = package.artifacts().chunked() {
            for descriptor in [
                Some(set.locator().descriptor()),
                Some(set.replay_record().descriptor()),
                set.durable_prepared_payload()
                    .map(CanonicalManifestArtifact::descriptor),
            ]
            .into_iter()
            .flatten()
            {
                self.read_verified_artifact(package.record(), descriptor)
                    .await?;
            }
        }
        Ok(VerifiedPreparedChunkReceipt::from_verified_record(
            package.record(),
        ))
    }

    pub async fn insert_prepared<Hash: Q256BitHash>(
        &self,
        record: &PreparedAuthorityManifestRecord<Hash>,
        receipt: &VerifiedPreparedChunkReceipt<Hash>,
    ) -> Result<PreparedManifestWriteOutcome<Hash>, ManifestPreparedError> {
        receipt.verify_for(record)?;
        let binding =
            PreparedManifestInsertBinding::try_from_record(record)?;
        let execution = self
            .session
            .execute_unpaged(&self.insert_manifest, binding)
            .await;
        self.finish_manifest_insert(execution, record).await
    }

    pub async fn read_manifest<Hash: Q256BitHash>(
        &self,
        identity: AuthorityManifestIdentity<Hash>,
    ) -> Result<Option<PreparedAuthorityManifestRecord<Hash>>, ManifestPreparedError> {
        match self.read_lifecycle(identity).await? {
            Some(PersistedAuthorityManifest::Prepared(record)) => Ok(Some(record)),
            Some(current) => Err(ManifestPreparedError::UnexpectedLifecyclePhase {
                expected: "PREPARED",
                actual: current.status() as i8,
            }),
            None => Ok(None),
        }
    }

    pub async fn read_lifecycle<Hash: Q256BitHash>(
        &self,
        identity: AuthorityManifestIdentity<Hash>,
    ) -> Result<Option<PersistedAuthorityManifest<Hash>>, ManifestPreparedError> {
        let binding = ManifestReadBinding::try_from_identity(&identity)?;
        let result = self
            .session
            .execute_unpaged(&self.read_manifest, binding)
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<ManifestDbRow>()
            .map_err(cql_error)?;
        row.map(|row| {
            PersistedAuthorityManifest::decode_persisted(
                identity,
                row.revision,
                row.status,
                &row.manifest_digest,
                &row.lifecycle_digest,
                &row.manifest_payload,
            )
            .map_err(Into::into)
        })
        .transpose()
    }

    pub async fn advance_to_sealed<Hash: Q256BitHash>(
        &self,
        candidate: &SealedAuthorityManifest<Hash>,
    ) -> Result<ManifestLifecycleWriteOutcome<Hash>, ManifestPreparedError> {
        let binding = ManifestLifecycleCasBinding::try_from_sealed(candidate)?;
        let execution = self
            .session
            .execute_unpaged(&self.advance_lifecycle, binding)
            .await;
        self.finish_lifecycle_cas(
            execution,
            PersistedAuthorityManifest::Sealed(candidate.clone()),
        )
        .await
    }

    pub async fn advance_to_committed<Hash: Q256BitHash>(
        &self,
        candidate: &CommittedAuthorityManifest<Hash>,
    ) -> Result<ManifestLifecycleWriteOutcome<Hash>, ManifestPreparedError> {
        let binding =
            ManifestLifecycleCasBinding::try_from_committed(candidate)?;
        let execution = self
            .session
            .execute_unpaged(&self.advance_lifecycle, binding)
            .await;
        self.finish_lifecycle_cas(
            execution,
            PersistedAuthorityManifest::Committed(candidate.clone()),
        )
        .await
    }

    pub async fn load_verified_artifacts<Hash: Q256BitHash>(
        &self,
        record: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<VerifiedPersistedManifestArtifacts, ManifestPreparedError> {
        let plan = decode_manifest_artifact_plan(
            record.artifact_summary(),
            record.intent().artifacts(),
        )?;
        match &plan {
            DecodedManifestArtifactPlan::Chunked {
                locator,
                replay_record,
                durable_prepared_payload,
                ..
            } => {
                let locator = self
                    .read_verified_artifact(record, *locator)
                    .await?;
                let replay_record = self
                    .read_verified_artifact(record, *replay_record)
                    .await?;
                let durable_prepared_payload = match durable_prepared_payload {
                    Some(descriptor) => Some(
                        self.read_verified_artifact(record, *descriptor)
                            .await?,
                    ),
                    None => None,
                };
                Ok(VerifiedPersistedManifestArtifacts {
                    plan,
                    locator: Some(locator),
                    replay_record,
                    durable_prepared_payload,
                })
            }
            DecodedManifestArtifactPlan::ZeroMutation { replay_record, .. } => {
                Ok(VerifiedPersistedManifestArtifacts {
                    plan: plan.clone(),
                    locator: None,
                    replay_record: replay_record.clone(),
                    durable_prepared_payload: None,
                })
            }
        }
    }

    async fn persist_and_verify_chunks<Hash: Q256BitHash>(
        &self,
        package: &VerifiedPreparedManifestPackage<Hash>,
    ) -> Result<(), ManifestPreparedError> {
        let Some(set) = package.artifacts().chunked() else {
            return Ok(());
        };
        for artifact in [
            set.locator(),
            set.replay_record(),
        ]
        .into_iter()
        .chain(set.durable_prepared_payload())
        {
            self.persist_artifact(package.record(), artifact).await?;
            self.read_verified_artifact(
                package.record(),
                artifact.descriptor(),
            )
                .await?;
        }
        Ok(())
    }

    async fn persist_artifact<Hash: Q256BitHash>(
        &self,
        record: &PreparedAuthorityManifestRecord<Hash>,
        artifact: &CanonicalManifestArtifact,
    ) -> Result<(), ManifestPreparedError> {
        let statement = &self.put_chunks[kind_index(artifact.descriptor().kind())];
        for chunk in artifact.chunks() {
            let binding = ManifestChunkPutBinding::try_new(record, chunk)?;
            self.session
                .execute_unpaged(statement, binding)
                .await
                .map_err(|error| ManifestPreparedError::IndeterminateChunkWrite {
                    kind: chunk.kind(),
                    chunk_index: chunk.chunk_index(),
                    execute_error: error.to_string(),
                })?;
        }
        Ok(())
    }

    async fn read_verified_artifact<Hash: Q256BitHash>(
        &self,
        record: &PreparedAuthorityManifestRecord<Hash>,
        descriptor: ManifestArtifactDescriptor,
    ) -> Result<Vec<u8>, ManifestPreparedError> {
        let kind = descriptor.kind();
        if descriptor.chunk_count() == 0 {
            return Err(ManifestPreparedError::ExpectedArtifactHasNoChunks);
        }
        let max_bucket =
            (descriptor.chunk_count() - 1) / MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET;
        let mut persisted = Vec::with_capacity(descriptor.chunk_count() as usize);
        for bucket in 0..=max_bucket {
            let binding = ManifestChunkBucketReadBinding::try_new(record, bucket)?;
            let result = self
                .session
                .execute_unpaged(&self.read_buckets[kind_index(kind)], binding)
                .await
                .map_err(cql_error)?;
            let rows = result.into_rows_result().map_err(cql_error)?;
            for row in rows.rows::<ManifestChunkDbRow>().map_err(cql_error)? {
                let row = row.map_err(cql_error)?;
                persisted.push(decode_chunk_row(kind, row)?);
            }
        }
        persisted.sort_by_key(ManifestArtifactChunk::chunk_index);
        verify_artifact_chunks(descriptor, &persisted).map_err(Into::into)
    }

    async fn finish_manifest_insert<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<PreparedManifestWriteOutcome<Hash>, ManifestPreparedError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = self
                    .read_lifecycle(*candidate.identity())
                    .await?
                    .ok_or(ManifestPreparedError::ManifestMissingAfterLwt {
                        applied,
                    })?;
                candidate
                    .classify_insert_observation(
                        applied,
                        current.prepared().clone(),
                    )
                    .map_err(Into::into)
            }
            Err(error) => match self.read_lifecycle(*candidate.identity()).await {
                Ok(Some(current)) if current.prepared() == candidate => Ok(
                    PreparedManifestWriteOutcome::Idempotent(
                        current.prepared().clone(),
                    ),
                ),
                Ok(_) => Err(ManifestPreparedError::IndeterminateManifestWrite {
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(
                    ManifestPreparedError::IndeterminateManifestReadFailed {
                        execute_error: error.to_string(),
                        read_error: read_error.to_string(),
                    },
                ),
            },
        }
    }

    async fn finish_lifecycle_cas<Hash: Q256BitHash>(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: PersistedAuthorityManifest<Hash>,
    ) -> Result<ManifestLifecycleWriteOutcome<Hash>, ManifestPreparedError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = self
                    .read_lifecycle(*candidate.identity())
                    .await?
                    .ok_or(ManifestPreparedError::ManifestMissingAfterLwt {
                        applied,
                    })?;
                classify_lifecycle_cas_observation(applied, candidate, current)
            }
            Err(error) => match self.read_lifecycle(*candidate.identity()).await {
                Ok(Some(current)) if current == candidate => {
                    Ok(ManifestLifecycleWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(ManifestPreparedError::IndeterminateLifecycleWrite {
                    execute_error: error.to_string(),
                }),
                Err(read_error) => Err(
                    ManifestPreparedError::IndeterminateManifestReadFailed {
                        execute_error: error.to_string(),
                        read_error: read_error.to_string(),
                    },
                ),
            },
        }
    }
}

async fn prepare_regular(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> Result<PreparedStatement, ManifestPreparedError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: ManifestPreparedConsistencyContract,
) -> Result<PreparedStatement, ManifestPreparedError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(contract.lwt_regular());
    statement.set_serial_consistency(Some(contract.lwt_serial()));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_chunk_row(
    kind: ManifestArtifactKind,
    row: ManifestChunkDbRow,
) -> Result<ManifestArtifactChunk, ManifestPreparedError> {
    let payload_hash: [u8; 32] = row
        .payload_hash
        .try_into()
        .map_err(|bytes: Vec<u8>| ManifestPreparedError::InvalidChunkHashLength(
            bytes.len(),
        ))?;
    ManifestArtifactChunk::try_from_persisted(
        kind as u8,
        u16::try_from(row.encoding_version)
            .map_err(|_| ManifestPreparedError::NegativeChunkCoordinate)?,
        u32::try_from(row.chunk_index)
            .map_err(|_| ManifestPreparedError::NegativeChunkCoordinate)?,
        u32::try_from(row.total_chunks)
            .map_err(|_| ManifestPreparedError::NegativeChunkCoordinate)?,
        u32::try_from(row.chunk_bucket)
            .map_err(|_| ManifestPreparedError::NegativeChunkCoordinate)?,
        row.payload,
        payload_hash,
    )
    .map_err(Into::into)
}

fn decode_lwt_applied(result: QueryResult) -> Result<bool, ManifestPreparedError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(ManifestPreparedError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(ManifestPreparedError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> ManifestPreparedError {
    ManifestPreparedError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestPreparedError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    InvalidControlKeyspace(InvalidManifestControlNoTabletKeyspace),
    InvalidArtifactKeyspace(InvalidManifestArtifactTabletKeyspace),
    ManifestRecord(ManifestRecordError),
    ManifestLifecycle(ManifestLifecycleError),
    Artifact(ManifestArtifactError),
    IntentArtifactMismatch,
    VerifiedChunkReceiptMismatch,
    CheckpointBucketOutOfRange,
    ChainEpochOutOfRange,
    CheckpointIdOutOfRange,
    ChunkCoordinateOutOfRange,
    NegativeChunkCoordinate,
    InvalidChunkHashLength(usize),
    ExpectedArtifactHasNoChunks,
    LifecycleRevisionOverflow,
    InvalidLifecycleTransition,
    UnexpectedLifecyclePhase {
        expected: &'static str,
        actual: i8,
    },
    IndeterminateChunkWrite {
        kind: ManifestArtifactKind,
        chunk_index: u32,
        execute_error: String,
    },
    MissingAppliedColumn,
    InvalidAppliedColumn,
    ManifestMissingAfterLwt {
        applied: bool,
    },
    IndeterminateManifestWrite {
        execute_error: String,
    },
    AppliedLifecycleCasMismatch,
    IndeterminateLifecycleWrite {
        execute_error: String,
    },
    IndeterminateManifestReadFailed {
        execute_error: String,
        read_error: String,
    },
    Cql(String),
}

impl From<InvalidCqlKeyspaceName> for ManifestPreparedError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<ManifestRecordError> for ManifestPreparedError {
    fn from(value: ManifestRecordError) -> Self {
        Self::ManifestRecord(value)
    }
}

impl From<ManifestLifecycleError> for ManifestPreparedError {
    fn from(value: ManifestLifecycleError) -> Self {
        Self::ManifestLifecycle(value)
    }
}

impl From<ManifestArtifactError> for ManifestPreparedError {
    fn from(value: ManifestArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl fmt::Display for ManifestPreparedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ManifestPreparedError {}
