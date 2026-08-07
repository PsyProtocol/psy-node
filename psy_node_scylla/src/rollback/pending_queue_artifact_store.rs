//! Isolated h22d3b1c1b Scylla adapter for recoverable queue artifacts.
//!
//! The small revisioned header lives in a no-tablet keyspace and advances by
//! full-payload LWT. Immutable 4 MiB fragments live in a standard/tablet
//! keyspace, are written at QUORUM, and are read back exactly before this
//! adapter returns an opaque selection receipt. The adapter is not registered
//! by production setup and intentionally exposes no generic header CAS.

use std::{error::Error, fmt, sync::Arc};

use psy_node_core::queue::{
    recoverable_artifact::{
        slot_for, PendingQueueArtifactAppendPlan,
        PendingQueueArtifactBootstrap, PendingQueueArtifactError,
        PendingQueueArtifactFragment, PendingQueueArtifactFragmentIndex,
        PendingQueueArtifactPhase, PendingQueueArtifactScanDigest,
        PendingQueueArtifactScanObservation, PendingQueueArtifactSlot,
        SealedPendingQueueArtifactTransition, StoredPendingQueueArtifact,
        MAX_PENDING_QUEUE_ARTIFACT_BUCKETS,
        MAX_PENDING_QUEUE_ARTIFACT_TOTAL_FRAGMENTS,
        PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET,
    },
    recoverable_ephemeral::{
        PendingQueueArtifactIdentity, PendingQueueCaptureCandidate,
        PendingQueueGenerationBoundary,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{CqlKeyspaceName, InvalidCqlKeyspaceName};

pub const PENDING_QUEUE_ARTIFACT_HEADER_TABLE: &str =
    "branch_exact_pending_queue_artifact_header";
pub const PENDING_QUEUE_ARTIFACT_FRAGMENT_TABLE: &str =
    "branch_exact_pending_queue_artifact_fragment";

const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-artifact-store/v1";
const RECEIPT_CANDIDATE_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-selection-receipt/v1";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueArtifactControlKeyspace(CqlKeyspaceName);

impl PendingQueueArtifactControlKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, PendingQueueArtifactStoreError> {
        let name = name.into();
        let parsed = CqlKeyspaceName::try_new(name.clone())?;
        if !name.ends_with("_no_tablet") && !name.ends_with("_nt") {
            return Err(PendingQueueArtifactStoreError::ControlKeyspaceMustBeNoTablet(
                name,
            ));
        }
        Ok(Self(parsed))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueArtifactDataKeyspace(CqlKeyspaceName);

impl PendingQueueArtifactDataKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, PendingQueueArtifactStoreError> {
        let name = name.into();
        if name.ends_with("_no_tablet") || name.ends_with("_nt") {
            return Err(PendingQueueArtifactStoreError::DataKeyspaceMustUseTablets(
                name,
            ));
        }
        Ok(Self(CqlKeyspaceName::try_new(name)?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactKeyspaces {
    control: PendingQueueArtifactControlKeyspace,
    data: PendingQueueArtifactDataKeyspace,
}

impl PendingQueueArtifactKeyspaces {
    pub const fn new(
        control: PendingQueueArtifactControlKeyspace,
        data: PendingQueueArtifactDataKeyspace,
    ) -> Self {
        Self { control, data }
    }

    pub const fn control(&self) -> &PendingQueueArtifactControlKeyspace {
        &self.control
    }

    pub const fn data(&self) -> &PendingQueueArtifactDataKeyspace {
        &self.data
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingQueueArtifactQueryId {
    CreateHeader = 1,
    CreateFragment = 2,
    ReadHeader = 3,
    BootstrapHeader = 4,
    AdvanceHeader = 5,
    PutFragment = 6,
    ReadFragment = 7,
    ReadFragmentBucketMetadata = 8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactQuery {
    id: PendingQueueArtifactQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingQueueArtifactQuery {
    pub const fn id(&self) -> PendingQueueArtifactQueryId {
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
pub struct PendingQueueArtifactQueries {
    create_header: PendingQueueArtifactQuery,
    create_fragment: PendingQueueArtifactQuery,
    read_header: PendingQueueArtifactQuery,
    bootstrap_header: PendingQueueArtifactQuery,
    advance_header: PendingQueueArtifactQuery,
    put_fragment: PendingQueueArtifactQuery,
    read_fragment: PendingQueueArtifactQuery,
    read_fragment_bucket_metadata: PendingQueueArtifactQuery,
}

impl PendingQueueArtifactQueries {
    pub fn new(keyspaces: &PendingQueueArtifactKeyspaces) -> Self {
        let header = format!(
            "{}.{}",
            keyspaces.control().as_str(),
            PENDING_QUEUE_ARTIFACT_HEADER_TABLE,
        );
        let fragment = format!(
            "{}.{}",
            keyspaces.data().as_str(),
            PENDING_QUEUE_ARTIFACT_FRAGMENT_TABLE,
        );
        Self {
            create_header: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::CreateHeader,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {header} (artifact_slot blob PRIMARY KEY, revision bigint, artifact_payload blob)"
                ),
                bind_shape: &[],
            },
            create_fragment: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::CreateFragment,
                cql: format!(
                    "CREATE TABLE IF NOT EXISTS {fragment} (artifact_slot blob, fragment_bucket bigint, global_fragment_index bigint, candidate_digest blob, batch_index int, batch_fragment_index smallint, batch_fragment_count smallint, candidate_bytes bigint, payload blob, payload_digest blob, PRIMARY KEY ((artifact_slot, fragment_bucket), global_fragment_index, candidate_digest)) WITH CLUSTERING ORDER BY (global_fragment_index ASC, candidate_digest ASC)"
                ),
                bind_shape: &[],
            },
            read_header: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::ReadHeader,
                cql: format!(
                    "SELECT revision, artifact_payload FROM {header} WHERE artifact_slot = ?"
                ),
                bind_shape: HEADER_READ_BIND_SHAPE,
            },
            bootstrap_header: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::BootstrapHeader,
                cql: format!(
                    "INSERT INTO {header} (artifact_slot, revision, artifact_payload) VALUES (?, ?, ?) IF NOT EXISTS"
                ),
                bind_shape: HEADER_BOOTSTRAP_BIND_SHAPE,
            },
            advance_header: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::AdvanceHeader,
                cql: format!(
                    "UPDATE {header} SET revision = ?, artifact_payload = ? WHERE artifact_slot = ? IF revision = ? AND artifact_payload = ?"
                ),
                bind_shape: HEADER_CAS_BIND_SHAPE,
            },
            put_fragment: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::PutFragment,
                cql: format!(
                    "INSERT INTO {fragment} (artifact_slot, fragment_bucket, global_fragment_index, candidate_digest, batch_index, batch_fragment_index, batch_fragment_count, candidate_bytes, payload, payload_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
                ),
                bind_shape: FRAGMENT_PUT_BIND_SHAPE,
            },
            read_fragment: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::ReadFragment,
                cql: format!(
                    "SELECT fragment_bucket, global_fragment_index, candidate_digest, batch_index, batch_fragment_index, batch_fragment_count, candidate_bytes, payload, payload_digest FROM {fragment} WHERE artifact_slot = ? AND fragment_bucket = ? AND global_fragment_index = ? AND candidate_digest = ?"
                ),
                bind_shape: FRAGMENT_READ_BIND_SHAPE,
            },
            read_fragment_bucket_metadata: PendingQueueArtifactQuery {
                id: PendingQueueArtifactQueryId::ReadFragmentBucketMetadata,
                cql: format!(
                    "SELECT fragment_bucket, global_fragment_index, candidate_digest FROM {fragment} WHERE artifact_slot = ? AND fragment_bucket = ?"
                ),
                bind_shape: FRAGMENT_BUCKET_BIND_SHAPE,
            },
        }
    }

    pub const fn create_header(&self) -> &PendingQueueArtifactQuery {
        &self.create_header
    }

    pub const fn create_fragment(&self) -> &PendingQueueArtifactQuery {
        &self.create_fragment
    }

    pub const fn read_header(&self) -> &PendingQueueArtifactQuery {
        &self.read_header
    }

    pub const fn bootstrap_header(&self) -> &PendingQueueArtifactQuery {
        &self.bootstrap_header
    }

    pub const fn advance_header(&self) -> &PendingQueueArtifactQuery {
        &self.advance_header
    }

    pub const fn put_fragment(&self) -> &PendingQueueArtifactQuery {
        &self.put_fragment
    }

    pub const fn read_fragment(&self) -> &PendingQueueArtifactQuery {
        &self.read_fragment
    }

    pub const fn read_fragment_bucket_metadata(&self) -> &PendingQueueArtifactQuery {
        &self.read_fragment_bucket_metadata
    }

    pub fn render_golden(&self) -> String {
        let mut rendered = String::new();
        for query in [
            &self.create_header,
            &self.create_fragment,
            &self.read_header,
            &self.bootstrap_header,
            &self.advance_header,
            &self.put_fragment,
            &self.read_fragment,
            &self.read_fragment_bucket_metadata,
        ] {
            rendered.push_str(&format!(
                "{:?}|{}\n{}\n",
                query.id,
                query.bind_shape.join(","),
                query.cql,
            ));
        }
        rendered
    }
}

const HEADER_READ_BIND_SHAPE: &[&str] = &["artifact_slot:BLOB"];
const HEADER_BOOTSTRAP_BIND_SHAPE: &[&str] = &[
    "artifact_slot:BLOB",
    "revision:BIGINT",
    "artifact_payload:BLOB",
];
const HEADER_CAS_BIND_SHAPE: &[&str] = &[
    "candidate_revision:BIGINT",
    "candidate_payload:BLOB",
    "artifact_slot:BLOB",
    "expected_revision:BIGINT",
    "expected_payload:BLOB",
];
const FRAGMENT_PUT_BIND_SHAPE: &[&str] = &[
    "artifact_slot:BLOB",
    "fragment_bucket:BIGINT",
    "global_fragment_index:BIGINT",
    "candidate_digest:BLOB",
    "batch_index:INT",
    "batch_fragment_index:SMALLINT",
    "batch_fragment_count:SMALLINT",
    "candidate_bytes:BIGINT",
    "payload:BLOB",
    "payload_digest:BLOB",
];
const FRAGMENT_READ_BIND_SHAPE: &[&str] = &[
    "artifact_slot:BLOB",
    "fragment_bucket:BIGINT",
    "global_fragment_index:BIGINT",
    "candidate_digest:BLOB",
];
const FRAGMENT_BUCKET_BIND_SHAPE: &[&str] =
    &["artifact_slot:BLOB", "fragment_bucket:BIGINT"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueArtifactBindValue {
    SmallInt(i16),
    Int(i32),
    BigInt(i64),
    Blob(Vec<u8>),
}

impl PendingQueueArtifactBindValue {
    fn render(&self) -> String {
        match self {
            Self::SmallInt(value) => format!("SMALLINT:{value}"),
            Self::Int(value) => format!("INT:{value}"),
            Self::BigInt(value) => format!("BIGINT:{value}"),
            Self::Blob(value) => format!("BLOB:{}", hex::encode(value)),
        }
    }
}

fn render_values(values: &[PendingQueueArtifactBindValue]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{index}:{}", value.render()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct PendingQueueArtifactHeaderReadBinding {
    artifact_slot: Vec<u8>,
}

impl PendingQueueArtifactHeaderReadBinding {
    pub fn new(slot: PendingQueueArtifactSlot) -> Self {
        Self {
            artifact_slot: slot.as_bytes().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<PendingQueueArtifactBindValue> {
        vec![PendingQueueArtifactBindValue::Blob(
            self.artifact_slot.clone(),
        )]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct PendingQueueArtifactHeaderBootstrapBinding {
    artifact_slot: Vec<u8>,
    revision: i64,
    artifact_payload: Vec<u8>,
}

impl PendingQueueArtifactHeaderBootstrapBinding {
    pub fn new(bootstrap: &PendingQueueArtifactBootstrap) -> Self {
        Self {
            artifact_slot: bootstrap.candidate().slot().as_bytes().to_vec(),
            revision: bootstrap.candidate().revision().as_i64(),
            artifact_payload: bootstrap.payload().to_vec(),
        }
    }

    pub fn values(&self) -> Vec<PendingQueueArtifactBindValue> {
        vec![
            PendingQueueArtifactBindValue::Blob(self.artifact_slot.clone()),
            PendingQueueArtifactBindValue::BigInt(self.revision),
            PendingQueueArtifactBindValue::Blob(self.artifact_payload.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactHeaderCasBinding {
    candidate_revision: i64,
    candidate_payload: Vec<u8>,
    artifact_slot: Vec<u8>,
    expected_revision: i64,
    expected_payload: Vec<u8>,
}

impl PendingQueueArtifactHeaderCasBinding {
    fn try_new(
        expected: &StoredPendingQueueArtifact,
        candidate: &StoredPendingQueueArtifact,
    ) -> Result<Self, PendingQueueArtifactStoreError> {
        if expected.slot() != candidate.slot()
            || expected.identity() != candidate.identity()
            || candidate.revision().get()
                != expected
                    .revision()
                    .get()
                    .checked_add(1)
                    .ok_or(PendingQueueArtifactStoreError::HeaderRevisionOverflow)?
        {
            return Err(PendingQueueArtifactStoreError::InvalidHeaderTransition);
        }
        Ok(Self {
            candidate_revision: candidate.revision().as_i64(),
            candidate_payload: candidate.to_persisted_bytes(),
            artifact_slot: expected.slot().as_bytes().to_vec(),
            expected_revision: expected.revision().as_i64(),
            expected_payload: expected.to_persisted_bytes(),
        })
    }

    #[cfg(test)]
    fn values(&self) -> Vec<PendingQueueArtifactBindValue> {
        vec![
            PendingQueueArtifactBindValue::BigInt(self.candidate_revision),
            PendingQueueArtifactBindValue::Blob(self.candidate_payload.clone()),
            PendingQueueArtifactBindValue::Blob(self.artifact_slot.clone()),
            PendingQueueArtifactBindValue::BigInt(self.expected_revision),
            PendingQueueArtifactBindValue::Blob(self.expected_payload.clone()),
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
pub struct PendingQueueArtifactFragmentPutBinding {
    artifact_slot: Vec<u8>,
    fragment_bucket: i64,
    global_fragment_index: i64,
    candidate_digest: Vec<u8>,
    batch_index: i32,
    batch_fragment_index: i16,
    batch_fragment_count: i16,
    candidate_bytes: i64,
    payload: Vec<u8>,
    payload_digest: Vec<u8>,
}

impl PendingQueueArtifactFragmentPutBinding {
    pub fn try_new(
        slot: PendingQueueArtifactSlot,
        fragment: &PendingQueueArtifactFragment,
    ) -> Result<Self, PendingQueueArtifactStoreError> {
        Ok(Self {
            artifact_slot: slot.as_bytes().to_vec(),
            fragment_bucket: i64::try_from(fragment.global_index().bucket())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            global_fragment_index: i64::try_from(fragment.global_index().get())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            candidate_digest: fragment.candidate_digest().as_bytes().to_vec(),
            batch_index: i32::try_from(fragment.batch_index().get())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            batch_fragment_index: i16::try_from(fragment.batch_fragment_index())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            batch_fragment_count: i16::try_from(fragment.batch_fragment_count())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            candidate_bytes: i64::try_from(fragment.candidate_bytes())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            payload: fragment.payload().to_vec(),
            payload_digest: fragment.payload_digest().as_bytes().to_vec(),
        })
    }

    pub fn values(&self) -> Vec<PendingQueueArtifactBindValue> {
        vec![
            PendingQueueArtifactBindValue::Blob(self.artifact_slot.clone()),
            PendingQueueArtifactBindValue::BigInt(self.fragment_bucket),
            PendingQueueArtifactBindValue::BigInt(self.global_fragment_index),
            PendingQueueArtifactBindValue::Blob(self.candidate_digest.clone()),
            PendingQueueArtifactBindValue::Int(self.batch_index),
            PendingQueueArtifactBindValue::SmallInt(self.batch_fragment_index),
            PendingQueueArtifactBindValue::SmallInt(self.batch_fragment_count),
            PendingQueueArtifactBindValue::BigInt(self.candidate_bytes),
            PendingQueueArtifactBindValue::Blob(self.payload.clone()),
            PendingQueueArtifactBindValue::Blob(self.payload_digest.clone()),
        ]
    }

    pub fn render_golden(&self) -> String {
        render_values(&self.values())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactFragmentReadBinding {
    artifact_slot: Vec<u8>,
    fragment_bucket: i64,
    global_fragment_index: i64,
    candidate_digest: Vec<u8>,
}

impl PendingQueueArtifactFragmentReadBinding {
    fn try_new(
        slot: PendingQueueArtifactSlot,
        index: PendingQueueArtifactFragmentIndex,
        candidate_digest: [u8; 32],
    ) -> Result<Self, PendingQueueArtifactStoreError> {
        Ok(Self {
            artifact_slot: slot.as_bytes().to_vec(),
            fragment_bucket: i64::try_from(index.bucket())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            global_fragment_index: i64::try_from(index.get())
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
            candidate_digest: candidate_digest.to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactBucketReadBinding {
    artifact_slot: Vec<u8>,
    fragment_bucket: i64,
}

impl PendingQueueArtifactBucketReadBinding {
    fn try_new(
        slot: PendingQueueArtifactSlot,
        bucket: u64,
    ) -> Result<Self, PendingQueueArtifactStoreError> {
        if bucket >= MAX_PENDING_QUEUE_ARTIFACT_BUCKETS {
            return Err(PendingQueueArtifactStoreError::IllegalBucket(bucket));
        }
        Ok(Self {
            artifact_slot: slot.as_bytes().to_vec(),
            fragment_bucket: i64::try_from(bucket)
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactConsistencyContract {
    fragment_write: Consistency,
    read: Consistency,
    lwt_regular: Consistency,
    lwt_serial: SerialConsistency,
}

impl PendingQueueArtifactConsistencyContract {
    pub const fn rf3_default() -> Self {
        Self {
            fragment_write: Consistency::Quorum,
            read: Consistency::Quorum,
            lwt_regular: Consistency::Quorum,
            lwt_serial: SerialConsistency::LocalSerial,
        }
    }

    pub const fn fragment_write(self) -> Consistency {
        self.fragment_write
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueArtifactStoreFingerprint([u8; 32]);

impl PendingQueueArtifactStoreFingerprint {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn store_fingerprint(
    keyspaces: &PendingQueueArtifactKeyspaces,
    queries: &PendingQueueArtifactQueries,
) -> PendingQueueArtifactStoreFingerprint {
    let mut hasher = Sha256::new();
    for part in [
        STORE_FINGERPRINT_DOMAIN,
        keyspaces.control().as_str().as_bytes(),
        keyspaces.data().as_str().as_bytes(),
        queries.render_golden().as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    PendingQueueArtifactStoreFingerprint(hasher.finalize().into())
}

/// Opaque proof that the concrete store selected one exact batch header and
/// read every immutable fragment back from Scylla. It is intentionally not
/// `Clone` and has no public constructor. It does not itself perform ACK.
///
/// ```compile_fail
/// use psy_node_scylla::rollback::DurablySelectedPendingQueueBatchReceipt;
/// let _ = DurablySelectedPendingQueueBatchReceipt {};
/// ```
#[derive(Debug)]
pub struct DurablySelectedPendingQueueBatchReceipt {
    store_fingerprint: PendingQueueArtifactStoreFingerprint,
    slot: PendingQueueArtifactSlot,
    selected_revision: u64,
    candidate_digest: [u8; 32],
    canonical_receipt_digest: [u8; 32],
}

impl DurablySelectedPendingQueueBatchReceipt {
    fn from_exact_readback(
        store_fingerprint: PendingQueueArtifactStoreFingerprint,
        selected: &StoredPendingQueueArtifact,
        plan: &PendingQueueArtifactAppendPlan,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Self {
        let canonical = candidate.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_CANDIDATE_DOMAIN);
        hasher.update(store_fingerprint.as_bytes());
        hasher.update(selected.slot().as_bytes());
        hasher.update(selected.revision().get().to_be_bytes());
        hasher.update(plan.descriptor().candidate_digest().as_bytes());
        hasher.update((canonical.len() as u64).to_be_bytes());
        hasher.update(&canonical);
        Self {
            store_fingerprint,
            slot: selected.slot(),
            selected_revision: selected.revision().get(),
            candidate_digest: *plan.descriptor().candidate_digest().as_bytes(),
            canonical_receipt_digest: hasher.finalize().into(),
        }
    }

    pub const fn store_fingerprint(&self) -> PendingQueueArtifactStoreFingerprint {
        self.store_fingerprint
    }

    pub const fn slot(&self) -> PendingQueueArtifactSlot {
        self.slot
    }

    pub const fn selected_revision(&self) -> u64 {
        self.selected_revision
    }

    pub const fn candidate_digest(&self) -> &[u8; 32] {
        &self.candidate_digest
    }

    pub const fn canonical_receipt_digest(&self) -> &[u8; 32] {
        &self.canonical_receipt_digest
    }

    pub fn verify_candidate(
        &self,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<(), PendingQueueArtifactStoreError> {
        if slot_for(candidate.artifact_identity()) != self.slot {
            return Err(PendingQueueArtifactStoreError::ReceiptCandidateMismatch);
        }
        let canonical = candidate.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(RECEIPT_CANDIDATE_DOMAIN);
        hasher.update(self.store_fingerprint.as_bytes());
        hasher.update(self.slot.as_bytes());
        hasher.update(self.selected_revision.to_be_bytes());
        hasher.update(self.candidate_digest);
        hasher.update((canonical.len() as u64).to_be_bytes());
        hasher.update(canonical);
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != self.canonical_receipt_digest {
            return Err(PendingQueueArtifactStoreError::ReceiptCandidateMismatch);
        }
        Ok(())
    }
}

/// Opaque per-source structural scan receipt. It is not a generation terminal
/// seal and cannot authorize `WorkCaptured` or `EmptyQueueSealed`.
#[derive(Debug)]
pub struct PersistedPendingQueueSourceScanReceipt {
    store_fingerprint: PendingQueueArtifactStoreFingerprint,
    slot: PendingQueueArtifactSlot,
    source_scan_revision: u64,
    scan_digest: PendingQueueArtifactScanDigest,
}

impl PersistedPendingQueueSourceScanReceipt {
    pub const fn store_fingerprint(&self) -> PendingQueueArtifactStoreFingerprint {
        self.store_fingerprint
    }

    pub const fn slot(&self) -> PendingQueueArtifactSlot {
        self.slot
    }

    pub const fn source_scan_revision(&self) -> u64 {
        self.source_scan_revision
    }

    pub const fn scan_digest(&self) -> PendingQueueArtifactScanDigest {
        self.scan_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueArtifactHeaderWriteOutcome {
    Applied(StoredPendingQueueArtifact),
    Idempotent(StoredPendingQueueArtifact),
    Conflict {
        current: StoredPendingQueueArtifact,
    },
}

impl PendingQueueArtifactHeaderWriteOutcome {
    pub const fn current(&self) -> &StoredPendingQueueArtifact {
        match self {
            Self::Applied(current)
            | Self::Idempotent(current)
            | Self::Conflict { current } => current,
        }
    }
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactHeaderDbRow {
    revision: i64,
    artifact_payload: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactFragmentMetadataDbRow {
    fragment_bucket: i64,
    global_fragment_index: i64,
    candidate_digest: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PendingQueueArtifactFragmentDbRow {
    fragment_bucket: i64,
    global_fragment_index: i64,
    candidate_digest: Vec<u8>,
    batch_index: i32,
    batch_fragment_index: i16,
    batch_fragment_count: i16,
    candidate_bytes: i64,
    payload: Vec<u8>,
    payload_digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PendingQueueArtifactFragmentMetadata {
    bucket: u64,
    index: PendingQueueArtifactFragmentIndex,
    candidate_digest: [u8; 32],
}

/// Real prepare/execute adapter. It is exported for controlled tests and the
/// later private backend composition, but no production setup constructs it.
pub struct ScyllaPendingQueueArtifactStore {
    session: Arc<Session>,
    queries: PendingQueueArtifactQueries,
    contract: PendingQueueArtifactConsistencyContract,
    fingerprint: PendingQueueArtifactStoreFingerprint,
    read_header: PreparedStatement,
    bootstrap_header: PreparedStatement,
    advance_header: PreparedStatement,
    put_fragment: PreparedStatement,
    read_fragment: PreparedStatement,
    read_fragment_bucket_metadata: PreparedStatement,
}

impl ScyllaPendingQueueArtifactStore {
    pub async fn create_schema(
        session: &Session,
        keyspaces: &PendingQueueArtifactKeyspaces,
    ) -> Result<(), PendingQueueArtifactStoreError> {
        let queries = PendingQueueArtifactQueries::new(keyspaces);
        session
            .query_unpaged(queries.create_header().cql(), &[])
            .await
            .map_err(cql_error)?;
        session
            .query_unpaged(queries.create_fragment().cql(), &[])
            .await
            .map_err(cql_error)?;
        session.await_schema_agreement().await.map_err(cql_error)?;
        Ok(())
    }

    pub async fn prepare(
        session: Arc<Session>,
        keyspaces: PendingQueueArtifactKeyspaces,
    ) -> Result<Self, PendingQueueArtifactStoreError> {
        let queries = PendingQueueArtifactQueries::new(&keyspaces);
        let contract = PendingQueueArtifactConsistencyContract::rf3_default();
        let fingerprint = store_fingerprint(&keyspaces, &queries);
        let read_header =
            prepare_regular(&session, queries.read_header().cql(), contract.read()).await?;
        let bootstrap_header =
            prepare_lwt(&session, queries.bootstrap_header().cql(), contract).await?;
        let advance_header =
            prepare_lwt(&session, queries.advance_header().cql(), contract).await?;
        let put_fragment = prepare_regular(
            &session,
            queries.put_fragment().cql(),
            contract.fragment_write(),
        )
        .await?;
        let read_fragment = prepare_regular(
            &session,
            queries.read_fragment().cql(),
            contract.read(),
        )
        .await?;
        let read_fragment_bucket_metadata = prepare_regular(
            &session,
            queries.read_fragment_bucket_metadata().cql(),
            contract.read(),
        )
        .await?;
        Ok(Self {
            session,
            queries,
            contract,
            fingerprint,
            read_header,
            bootstrap_header,
            advance_header,
            put_fragment,
            read_fragment,
            read_fragment_bucket_metadata,
        })
    }

    pub const fn queries(&self) -> &PendingQueueArtifactQueries {
        &self.queries
    }

    pub const fn consistency_contract(&self) -> PendingQueueArtifactConsistencyContract {
        self.contract
    }

    pub const fn fingerprint(&self) -> PendingQueueArtifactStoreFingerprint {
        self.fingerprint
    }

    pub async fn read_header(
        &self,
        identity: &PendingQueueArtifactIdentity,
    ) -> Result<Option<StoredPendingQueueArtifact>, PendingQueueArtifactStoreError> {
        self.read_header_by_slot(slot_for(identity)).await
    }

    pub async fn bootstrap(
        &self,
        bootstrap: &PendingQueueArtifactBootstrap,
    ) -> Result<PendingQueueArtifactHeaderWriteOutcome, PendingQueueArtifactStoreError> {
        let binding = PendingQueueArtifactHeaderBootstrapBinding::new(bootstrap);
        let execution = self
            .session
            .execute_unpaged(&self.bootstrap_header, binding)
            .await;
        self.finish_header_write(execution, bootstrap.candidate())
            .await
    }

    /// Persists one exact candidate, reads every fragment back, selects it in
    /// the header, and only then returns an opaque receipt. It does not ACK the
    /// backend and exposes no method to advance `SelectedAwaitingAck -> Open`.
    pub async fn persist_selected_batch(
        &self,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<DurablySelectedPendingQueueBatchReceipt, PendingQueueArtifactStoreError> {
        let identity = candidate.artifact_identity();
        let current = self
            .read_header(identity)
            .await?
            .ok_or(PendingQueueArtifactStoreError::Uninitialized)?;
        let (plan, already_selected) = match current.phase() {
            PendingQueueArtifactPhase::Open(_) => {
                let plan = PendingQueueArtifactAppendPlan::try_new(&current, candidate)?;
                let outcome = self
                    .cas_header(plan.expected_open(), plan.prepared())
                    .await?;
                require_exact_header(outcome, plan.prepared())?;
                (plan, false)
            }
            PendingQueueArtifactPhase::AppendPrepared { .. } => (
                PendingQueueArtifactAppendPlan::try_resume(&current, candidate)?,
                false,
            ),
            PendingQueueArtifactPhase::SelectedAwaitingAck { .. } => (
                PendingQueueArtifactAppendPlan::try_resume_selected(&current, candidate)?,
                true,
            ),
            _ => return Err(PendingQueueArtifactStoreError::HeaderNotAppendable),
        };

        for fragment in plan.fragments() {
            self.persist_and_readback_fragment(plan.selected().slot(), fragment)
                .await?;
        }

        let selected = if already_selected {
            current
        } else {
            let outcome = self.cas_header(plan.prepared(), plan.selected()).await?;
            require_exact_header(outcome, plan.selected())?
        };
        Ok(DurablySelectedPendingQueueBatchReceipt::from_exact_readback(
            self.fingerprint,
            &selected,
            &plan,
            candidate,
        ))
    }

    /// Persists a structural close observation, enumerates every legal bucket,
    /// reloads the exact selected fragments, and records `SourceScanned`.
    /// The returned receipt is still per-source and non-terminal.
    pub async fn scan_closed_source(
        &self,
        identity: &PendingQueueArtifactIdentity,
        boundary: PendingQueueGenerationBoundary,
    ) -> Result<PersistedPendingQueueSourceScanReceipt, PendingQueueArtifactStoreError> {
        let current = self
            .read_header(identity)
            .await?
            .ok_or(PendingQueueArtifactStoreError::Uninitialized)?;
        let close_or_scanned = match current.phase() {
            PendingQueueArtifactPhase::Open(_) => {
                let transition = SealedPendingQueueArtifactTransition::observe_close(
                    &current,
                    boundary.clone(),
                )?;
                let outcome = self
                    .cas_header(transition.expected(), transition.candidate())
                    .await?;
                require_exact_header(outcome, transition.candidate())?
            }
            PendingQueueArtifactPhase::CloseObserved {
                boundary: persisted,
                ..
            }
            | PendingQueueArtifactPhase::SourceScanned {
                boundary: persisted,
                ..
            } if persisted == &boundary => current,
            _ => return Err(PendingQueueArtifactStoreError::CloseBoundaryConflict),
        };

        let fragments = self
            .load_exhaustive_fragment_set(&close_or_scanned)
            .await?;
        let observation = PendingQueueArtifactScanObservation::verify(
            &close_or_scanned,
            fragments,
        )?;
        let scanned = match close_or_scanned.phase() {
            PendingQueueArtifactPhase::CloseObserved { .. } => {
                let transition = SealedPendingQueueArtifactTransition::record_source_scan(
                    &close_or_scanned,
                    &observation,
                )?;
                let outcome = self
                    .cas_header(transition.expected(), transition.candidate())
                    .await?;
                require_exact_header(outcome, transition.candidate())?
            }
            PendingQueueArtifactPhase::SourceScanned { scan_digest, .. }
                if *scan_digest == observation.scan_digest() =>
            {
                close_or_scanned
            }
            _ => return Err(PendingQueueArtifactStoreError::SourceScanConflict),
        };
        Ok(PersistedPendingQueueSourceScanReceipt {
            store_fingerprint: self.fingerprint,
            slot: scanned.slot(),
            source_scan_revision: scanned.revision().get(),
            scan_digest: observation.scan_digest(),
        })
    }

    async fn cas_header(
        &self,
        expected: &StoredPendingQueueArtifact,
        candidate: &StoredPendingQueueArtifact,
    ) -> Result<PendingQueueArtifactHeaderWriteOutcome, PendingQueueArtifactStoreError> {
        let binding = PendingQueueArtifactHeaderCasBinding::try_new(expected, candidate)?;
        let execution = self
            .session
            .execute_unpaged(&self.advance_header, binding)
            .await;
        self.finish_header_write(execution, candidate).await
    }

    async fn finish_header_write(
        &self,
        execution: Result<QueryResult, scylla::errors::ExecutionError>,
        candidate: &StoredPendingQueueArtifact,
    ) -> Result<PendingQueueArtifactHeaderWriteOutcome, PendingQueueArtifactStoreError> {
        match execution {
            Ok(result) => {
                let applied = decode_lwt_applied(result)?;
                let current = self
                    .read_header_by_slot(candidate.slot())
                    .await?
                    .ok_or(PendingQueueArtifactStoreError::HeaderMissingAfterLwt {
                        applied,
                    })?;
                classify_header_observation(applied, candidate, current)
            }
            Err(execute_error) => match self.read_header_by_slot(candidate.slot()).await {
                Ok(Some(current)) if current == *candidate => {
                    Ok(PendingQueueArtifactHeaderWriteOutcome::Idempotent(current))
                }
                Ok(_) => Err(PendingQueueArtifactStoreError::IndeterminateHeaderWrite {
                    execute_error: execute_error.to_string(),
                }),
                Err(read_error) => Err(
                    PendingQueueArtifactStoreError::IndeterminateHeaderReadFailed {
                        execute_error: execute_error.to_string(),
                        read_error: read_error.to_string(),
                    },
                ),
            },
        }
    }

    async fn read_header_by_slot(
        &self,
        slot: PendingQueueArtifactSlot,
    ) -> Result<Option<StoredPendingQueueArtifact>, PendingQueueArtifactStoreError> {
        let result = self
            .session
            .execute_unpaged(
                &self.read_header,
                PendingQueueArtifactHeaderReadBinding::new(slot),
            )
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<PendingQueueArtifactHeaderDbRow>()
            .map_err(cql_error)?;
        row.map(|row| {
            StoredPendingQueueArtifact::decode_persisted(
                slot,
                row.revision,
                &row.artifact_payload,
            )
            .map_err(Into::into)
        })
        .transpose()
    }

    async fn persist_and_readback_fragment(
        &self,
        slot: PendingQueueArtifactSlot,
        fragment: &PendingQueueArtifactFragment,
    ) -> Result<(), PendingQueueArtifactStoreError> {
        let binding = PendingQueueArtifactFragmentPutBinding::try_new(slot, fragment)?;
        let execution = self
            .session
            .execute_unpaged(&self.put_fragment, binding)
            .await;
        match execution {
            Ok(_) => {}
            Err(execute_error) => {
                match self.read_exact_fragment(slot, fragment).await {
                    Ok(Some(current)) if current == *fragment => return Ok(()),
                    Ok(_) => {
                        return Err(
                            PendingQueueArtifactStoreError::IndeterminateFragmentWrite {
                                index: fragment.global_index().get(),
                                execute_error: execute_error.to_string(),
                            },
                        )
                    }
                    Err(read_error) => {
                        return Err(
                            PendingQueueArtifactStoreError::IndeterminateFragmentReadFailed {
                                index: fragment.global_index().get(),
                                execute_error: execute_error.to_string(),
                                read_error: read_error.to_string(),
                            },
                        )
                    }
                }
            }
        }
        match self.read_exact_fragment(slot, fragment).await? {
            Some(current) if current == *fragment => Ok(()),
            Some(_) => Err(PendingQueueArtifactStoreError::FragmentReadbackMismatch {
                index: fragment.global_index().get(),
            }),
            None => Err(PendingQueueArtifactStoreError::FragmentMissingAfterWrite {
                index: fragment.global_index().get(),
            }),
        }
    }

    async fn read_exact_fragment(
        &self,
        slot: PendingQueueArtifactSlot,
        expected: &PendingQueueArtifactFragment,
    ) -> Result<Option<PendingQueueArtifactFragment>, PendingQueueArtifactStoreError> {
        let binding = PendingQueueArtifactFragmentReadBinding::try_new(
            slot,
            expected.global_index(),
            *expected.candidate_digest().as_bytes(),
        )?;
        self.read_fragment_with_binding(binding).await
    }

    async fn read_fragment_with_metadata(
        &self,
        slot: PendingQueueArtifactSlot,
        metadata: &PendingQueueArtifactFragmentMetadata,
    ) -> Result<PendingQueueArtifactFragment, PendingQueueArtifactStoreError> {
        let binding = PendingQueueArtifactFragmentReadBinding::try_new(
            slot,
            metadata.index,
            metadata.candidate_digest,
        )?;
        self.read_fragment_with_binding(binding)
            .await?
            .ok_or(PendingQueueArtifactStoreError::FragmentDisappearedDuringScan {
                index: metadata.index.get(),
            })
    }

    async fn read_fragment_with_binding(
        &self,
        binding: PendingQueueArtifactFragmentReadBinding,
    ) -> Result<Option<PendingQueueArtifactFragment>, PendingQueueArtifactStoreError> {
        let expected_bucket = u64::try_from(binding.fragment_bucket)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
        let expected_index = u64::try_from(binding.global_fragment_index)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
        let expected_candidate: [u8; 32] = binding
            .candidate_digest
            .clone()
            .try_into()
            .map_err(|bytes: Vec<u8>| {
                PendingQueueArtifactStoreError::InvalidDigestLength(bytes.len())
            })?;
        let result = self
            .session
            .execute_unpaged(&self.read_fragment, binding)
            .await
            .map_err(cql_error)?;
        let row = result
            .into_rows_result()
            .map_err(cql_error)?
            .maybe_first_row::<PendingQueueArtifactFragmentDbRow>()
            .map_err(cql_error)?;
        row.map(|row| {
            decode_fragment_row(
                row,
                expected_bucket,
                expected_index,
                expected_candidate,
            )
        })
        .transpose()
    }

    async fn load_exhaustive_fragment_set(
        &self,
        header: &StoredPendingQueueArtifact,
    ) -> Result<Vec<PendingQueueArtifactFragment>, PendingQueueArtifactStoreError> {
        let expected_count = selected_fragment_count(header)?;
        let mut metadata = Vec::with_capacity(
            usize::try_from(expected_count)
                .map_err(|_| PendingQueueArtifactStoreError::CoordinateOutOfRange)?,
        );
        for bucket in 0..MAX_PENDING_QUEUE_ARTIFACT_BUCKETS {
            let binding = PendingQueueArtifactBucketReadBinding::try_new(
                header.slot(),
                bucket,
            )?;
            let result = self
                .session
                .execute_unpaged(&self.read_fragment_bucket_metadata, binding)
                .await
                .map_err(cql_error)?;
            let rows = result.into_rows_result().map_err(cql_error)?;
            for row in rows
                .rows::<PendingQueueArtifactFragmentMetadataDbRow>()
                .map_err(cql_error)?
            {
                metadata.push(decode_fragment_metadata(row.map_err(cql_error)?)?);
                if metadata.len() as u64 > expected_count
                    || metadata.len() as u64 > MAX_PENDING_QUEUE_ARTIFACT_TOTAL_FRAGMENTS
                {
                    return Err(PendingQueueArtifactStoreError::ExtraFragmentRows {
                        expected: expected_count,
                        observed_at_least: metadata.len() as u64,
                    });
                }
            }
        }
        validate_fragment_metadata_set(expected_count, &mut metadata)?;
        let mut fragments = Vec::with_capacity(metadata.len());
        for row in &metadata {
            fragments.push(
                self.read_fragment_with_metadata(header.slot(), row)
                    .await?,
            );
        }
        Ok(fragments)
    }
}

fn validate_fragment_metadata_set(
    expected_count: u64,
    metadata: &mut [PendingQueueArtifactFragmentMetadata],
) -> Result<(), PendingQueueArtifactStoreError> {
    metadata.sort_by_key(|row| (row.index.get(), row.candidate_digest));
    if metadata.len() as u64 != expected_count {
        return Err(PendingQueueArtifactStoreError::FragmentMetadataCardinality {
            expected: expected_count,
            actual: metadata.len() as u64,
        });
    }
    for (expected_index, row) in metadata.iter().enumerate() {
        let expected_index = expected_index as u64;
        if row.index.get() != expected_index
            || row.bucket
                != expected_index / PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET
        {
            return Err(PendingQueueArtifactStoreError::NonContiguousFragmentMetadata);
        }
    }
    Ok(())
}

fn selected_fragment_count(
    header: &StoredPendingQueueArtifact,
) -> Result<u64, PendingQueueArtifactStoreError> {
    match header.phase() {
        PendingQueueArtifactPhase::CloseObserved { progress, .. }
        | PendingQueueArtifactPhase::SourceScanned { progress, .. } => {
            Ok(progress.next_fragment_index())
        }
        _ => Err(PendingQueueArtifactStoreError::HeaderNotClosed),
    }
}

fn decode_fragment_metadata(
    row: PendingQueueArtifactFragmentMetadataDbRow,
) -> Result<PendingQueueArtifactFragmentMetadata, PendingQueueArtifactStoreError> {
    let bucket = u64::try_from(row.fragment_bucket)
        .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
    if bucket >= MAX_PENDING_QUEUE_ARTIFACT_BUCKETS {
        return Err(PendingQueueArtifactStoreError::IllegalBucket(bucket));
    }
    let index_value = u64::try_from(row.global_fragment_index)
        .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
    let index = PendingQueueArtifactFragmentIndex::try_new(index_value)?;
    if index.bucket() != bucket {
        return Err(PendingQueueArtifactStoreError::FragmentBucketMismatch);
    }
    let candidate_digest: [u8; 32] = row
        .candidate_digest
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            PendingQueueArtifactStoreError::InvalidDigestLength(bytes.len())
        })?;
    if candidate_digest == [0; 32] {
        return Err(PendingQueueArtifactStoreError::ZeroDigest);
    }
    Ok(PendingQueueArtifactFragmentMetadata {
        bucket,
        index,
        candidate_digest,
    })
}

fn decode_fragment_row(
    row: PendingQueueArtifactFragmentDbRow,
    expected_bucket: u64,
    expected_index: u64,
    expected_candidate: [u8; 32],
) -> Result<PendingQueueArtifactFragment, PendingQueueArtifactStoreError> {
    let bucket = u64::try_from(row.fragment_bucket)
        .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
    let index = u64::try_from(row.global_fragment_index)
        .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?;
    let candidate_digest: [u8; 32] = row
        .candidate_digest
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            PendingQueueArtifactStoreError::InvalidDigestLength(bytes.len())
        })?;
    if bucket != expected_bucket
        || index != expected_index
        || candidate_digest != expected_candidate
        || index / PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET != bucket
    {
        return Err(PendingQueueArtifactStoreError::FragmentPrimaryKeyMismatch);
    }
    let payload_digest: [u8; 32] = row
        .payload_digest
        .try_into()
        .map_err(|bytes: Vec<u8>| {
            PendingQueueArtifactStoreError::InvalidDigestLength(bytes.len())
        })?;
    PendingQueueArtifactFragment::try_from_parts(
        index,
        u32::try_from(row.batch_index)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?,
        u16::try_from(row.batch_fragment_index)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?,
        u16::try_from(row.batch_fragment_count)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?,
        psy_node_core::queue::recoverable_artifact::PendingQueueCandidateDigest::try_new(
            candidate_digest,
        )?,
        u64::try_from(row.candidate_bytes)
            .map_err(|_| PendingQueueArtifactStoreError::NegativeCoordinate)?,
        row.payload,
        psy_node_core::queue::recoverable_artifact::PendingQueueFragmentDigest::try_new(
            payload_digest,
        )?,
    )
    .map_err(Into::into)
}

pub fn classify_header_observation(
    applied: bool,
    candidate: &StoredPendingQueueArtifact,
    current: StoredPendingQueueArtifact,
) -> Result<PendingQueueArtifactHeaderWriteOutcome, PendingQueueArtifactStoreError> {
    if current == *candidate {
        if applied {
            Ok(PendingQueueArtifactHeaderWriteOutcome::Applied(current))
        } else {
            Ok(PendingQueueArtifactHeaderWriteOutcome::Idempotent(current))
        }
    } else if applied {
        Err(PendingQueueArtifactStoreError::AppliedHeaderMismatch)
    } else {
        Ok(PendingQueueArtifactHeaderWriteOutcome::Conflict { current })
    }
}

fn require_exact_header(
    outcome: PendingQueueArtifactHeaderWriteOutcome,
    candidate: &StoredPendingQueueArtifact,
) -> Result<StoredPendingQueueArtifact, PendingQueueArtifactStoreError> {
    match outcome {
        PendingQueueArtifactHeaderWriteOutcome::Applied(current)
        | PendingQueueArtifactHeaderWriteOutcome::Idempotent(current)
            if current == *candidate =>
        {
            Ok(current)
        }
        PendingQueueArtifactHeaderWriteOutcome::Conflict { current } => {
            Err(PendingQueueArtifactStoreError::HeaderConflict {
                current_revision: current.revision().get(),
            })
        }
        _ => Err(PendingQueueArtifactStoreError::AppliedHeaderMismatch),
    }
}

async fn prepare_regular(
    session: &Session,
    cql: &str,
    consistency: Consistency,
) -> Result<PreparedStatement, PendingQueueArtifactStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(consistency);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql: &str,
    contract: PendingQueueArtifactConsistencyContract,
) -> Result<PreparedStatement, PendingQueueArtifactStoreError> {
    let mut statement = session.prepare(cql).await.map_err(cql_error)?;
    statement.set_consistency(contract.lwt_regular());
    statement.set_serial_consistency(Some(contract.lwt_serial()));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_lwt_applied(result: QueryResult) -> Result<bool, PendingQueueArtifactStoreError> {
    let rows = result.into_rows_result().map_err(cql_error)?;
    let applied_column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingQueueArtifactStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql_error)?;
    match row.columns.get(applied_column.0) {
        Some(Some(CqlValue::Boolean(applied))) => Ok(*applied),
        _ => Err(PendingQueueArtifactStoreError::InvalidAppliedColumn),
    }
}

fn cql_error(error: impl fmt::Display) -> PendingQueueArtifactStoreError {
    PendingQueueArtifactStoreError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueArtifactStoreError {
    InvalidKeyspace(InvalidCqlKeyspaceName),
    ControlKeyspaceMustBeNoTablet(String),
    DataKeyspaceMustUseTablets(String),
    Artifact(PendingQueueArtifactError),
    CoordinateOutOfRange,
    NegativeCoordinate,
    InvalidDigestLength(usize),
    ZeroDigest,
    HeaderRevisionOverflow,
    InvalidHeaderTransition,
    Uninitialized,
    HeaderNotAppendable,
    HeaderNotClosed,
    CloseBoundaryConflict,
    SourceScanConflict,
    ReceiptCandidateMismatch,
    IllegalBucket(u64),
    FragmentBucketMismatch,
    FragmentPrimaryKeyMismatch,
    FragmentMetadataCardinality { expected: u64, actual: u64 },
    ExtraFragmentRows {
        expected: u64,
        observed_at_least: u64,
    },
    NonContiguousFragmentMetadata,
    FragmentMissingAfterWrite { index: u64 },
    FragmentReadbackMismatch { index: u64 },
    FragmentDisappearedDuringScan { index: u64 },
    IndeterminateFragmentWrite { index: u64, execute_error: String },
    IndeterminateFragmentReadFailed {
        index: u64,
        execute_error: String,
        read_error: String,
    },
    MissingAppliedColumn,
    InvalidAppliedColumn,
    HeaderMissingAfterLwt { applied: bool },
    AppliedHeaderMismatch,
    HeaderConflict { current_revision: u64 },
    IndeterminateHeaderWrite { execute_error: String },
    IndeterminateHeaderReadFailed {
        execute_error: String,
        read_error: String,
    },
    Cql(String),
}

impl From<InvalidCqlKeyspaceName> for PendingQueueArtifactStoreError {
    fn from(value: InvalidCqlKeyspaceName) -> Self {
        Self::InvalidKeyspace(value)
    }
}

impl From<PendingQueueArtifactError> for PendingQueueArtifactStoreError {
    fn from(value: PendingQueueArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl fmt::Display for PendingQueueArtifactStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueArtifactStoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::recoverable_ephemeral::{
            PendingQueueCaptureContext, PendingQueueSourceCursor,
            PendingQueueSourceIdentity,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
        },
    };

    fn keyspaces() -> PendingQueueArtifactKeyspaces {
        PendingQueueArtifactKeyspaces::new(
            PendingQueueArtifactControlKeyspace::try_new("psy_control_no_tablet")
                .unwrap(),
            PendingQueueArtifactDataKeyspace::try_new("psy_artifacts").unwrap(),
        )
    }

    fn context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 2,
                },
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(101, 9001).unwrap(),
        )
        .unwrap()
    }

    fn candidate() -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            context(),
            PendingQueueSourceIdentity::nats_jetstream(
                "psy",
                "psy_stream",
                "psy.pq.r7.rs2.u65.qt9.g0",
            )
            .unwrap(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], &[10, 11])
                .unwrap(),
            vec![b"first".to_vec(), b"second".to_vec()],
        )
        .unwrap()
    }

    fn append_plan() -> PendingQueueArtifactAppendPlan {
        let candidate = candidate();
        let bootstrap = PendingQueueArtifactBootstrap::try_new(
            candidate.artifact_identity().clone(),
        )
        .unwrap();
        PendingQueueArtifactAppendPlan::try_new(bootstrap.candidate(), &candidate)
            .unwrap()
    }

    #[test]
    fn query_contract_is_exact_and_separates_control_from_large_data() {
        let queries = PendingQueueArtifactQueries::new(&keyspaces());
        assert!(queries.create_header().cql().contains("psy_control_no_tablet"));
        assert!(queries.create_fragment().cql().contains("psy_artifacts"));
        assert!(queries.bootstrap_header().cql().contains("IF NOT EXISTS"));
        assert!(queries
            .advance_header()
            .cql()
            .contains("IF revision = ? AND artifact_payload = ?"));
        assert!(queries.create_fragment().cql().contains(
            "PRIMARY KEY ((artifact_slot, fragment_bucket), global_fragment_index, candidate_digest)"
        ));
        assert!(!queries.put_fragment().cql().contains("USING TIMESTAMP"));
        assert_eq!(
            queries.read_fragment_bucket_metadata().bind_shape(),
            FRAGMENT_BUCKET_BIND_SHAPE,
        );
        assert_eq!(MAX_PENDING_QUEUE_ARTIFACT_TOTAL_FRAGMENTS, 1_279);
        assert_eq!(MAX_PENDING_QUEUE_ARTIFACT_BUCKETS, 80);
        assert!(PendingQueueArtifactControlKeyspace::try_new("psy_control").is_err());
        assert!(PendingQueueArtifactDataKeyspace::try_new("psy_data_nt").is_err());
    }

    #[test]
    fn query_and_binding_golden_are_deterministic() {
        let queries = PendingQueueArtifactQueries::new(&keyspaces());
        let first = queries.render_golden();
        assert_eq!(first, PendingQueueArtifactQueries::new(&keyspaces()).render_golden());
        let golden_digest: [u8; 32] = Sha256::digest(first.as_bytes()).into();
        assert_eq!(
            golden_digest,
            [
                60, 23, 76, 172, 252, 82, 106, 15, 184, 73, 40, 107, 159, 81,
                124, 164, 49, 176, 176, 44, 170, 87, 89, 82, 25, 192, 134, 6,
                187, 121, 195, 2,
            ],
        );

        let plan = append_plan();
        let binding = PendingQueueArtifactFragmentPutBinding::try_new(
            plan.selected().slot(),
            &plan.fragments()[0],
        )
        .unwrap();
        let rendered = binding.render_golden();
        assert!(rendered.contains("1:BIGINT:0"));
        assert!(rendered.contains("2:BIGINT:0"));
        assert_eq!(binding.values().len(), FRAGMENT_PUT_BIND_SHAPE.len());
        let cas = PendingQueueArtifactHeaderCasBinding::try_new(
            plan.expected_open(),
            plan.prepared(),
        )
        .unwrap();
        assert_eq!(cas.values().len(), HEADER_CAS_BIND_SHAPE.len());
    }

    #[test]
    fn fingerprint_binds_both_keyspaces_and_all_queries() {
        let queries = PendingQueueArtifactQueries::new(&keyspaces());
        let first = store_fingerprint(&keyspaces(), &queries);
        let changed = PendingQueueArtifactKeyspaces::new(
            PendingQueueArtifactControlKeyspace::try_new("psy_other_nt").unwrap(),
            PendingQueueArtifactDataKeyspace::try_new("psy_artifacts").unwrap(),
        );
        assert_ne!(
            first,
            store_fingerprint(&changed, &PendingQueueArtifactQueries::new(&changed)),
        );
        assert_ne!(first.as_bytes(), &[0; 32]);
    }

    #[test]
    fn header_observation_is_idempotent_and_aba_safe() {
        let plan = append_plan();
        assert!(matches!(
            classify_header_observation(true, plan.prepared(), plan.prepared().clone())
                .unwrap(),
            PendingQueueArtifactHeaderWriteOutcome::Applied(_)
        ));
        assert!(matches!(
            classify_header_observation(false, plan.prepared(), plan.prepared().clone())
                .unwrap(),
            PendingQueueArtifactHeaderWriteOutcome::Idempotent(_)
        ));
        assert!(matches!(
            classify_header_observation(
                false,
                plan.prepared(),
                plan.expected_open().clone(),
            )
            .unwrap(),
            PendingQueueArtifactHeaderWriteOutcome::Conflict { .. }
        ));
        assert_eq!(
            classify_header_observation(
                true,
                plan.prepared(),
                plan.expected_open().clone(),
            ),
            Err(PendingQueueArtifactStoreError::AppliedHeaderMismatch),
        );
    }

    #[test]
    fn opaque_receipt_binds_store_slot_revision_and_candidate() {
        let plan = append_plan();
        let candidate = candidate();
        let queries = PendingQueueArtifactQueries::new(&keyspaces());
        let fingerprint = store_fingerprint(&keyspaces(), &queries);
        let receipt = DurablySelectedPendingQueueBatchReceipt::from_exact_readback(
            fingerprint,
            plan.selected(),
            &plan,
            &candidate,
        );
        receipt.verify_candidate(&candidate).unwrap();
        let changed = PendingQueueCaptureCandidate::try_new(
            context(),
            candidate.source_identity().clone(),
            candidate.source().clone(),
            vec![b"first".to_vec(), b"changed".to_vec()],
        )
        .unwrap();
        assert_eq!(
            receipt.verify_candidate(&changed),
            Err(PendingQueueArtifactStoreError::ReceiptCandidateMismatch),
        );
        assert_eq!(receipt.slot(), plan.selected().slot());
        assert_eq!(receipt.selected_revision(), plan.selected().revision().get());
    }

    #[test]
    fn fragment_metadata_rejects_extra_direction_and_invalid_keys() {
        let good = decode_fragment_metadata(PendingQueueArtifactFragmentMetadataDbRow {
            fragment_bucket: 79,
            global_fragment_index: 1_278,
            candidate_digest: vec![7; 32],
        })
        .unwrap();
        assert_eq!(good.index.get(), 1_278);
        assert_eq!(good.bucket, 79);
        assert_eq!(
            decode_fragment_metadata(PendingQueueArtifactFragmentMetadataDbRow {
                fragment_bucket: 0,
                global_fragment_index: 17,
                candidate_digest: vec![7; 32],
            }),
            Err(PendingQueueArtifactStoreError::FragmentBucketMismatch),
        );
        assert!(decode_fragment_metadata(PendingQueueArtifactFragmentMetadataDbRow {
            fragment_bucket: 80,
            global_fragment_index: 1_279,
            candidate_digest: vec![7; 32],
        })
        .is_err());
    }

    #[test]
    fn exhaustive_metadata_validation_rejects_missing_extra_and_duplicate_rows() {
        let metadata = |index: u64, digest: u8| PendingQueueArtifactFragmentMetadata {
            bucket: index / PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET,
            index: PendingQueueArtifactFragmentIndex::try_new(index).unwrap(),
            candidate_digest: [digest; 32],
        };

        let mut exact = vec![metadata(1, 2), metadata(0, 1)];
        validate_fragment_metadata_set(2, &mut exact).unwrap();
        assert_eq!(exact[0].index.get(), 0);

        let mut missing = vec![metadata(0, 1)];
        assert_eq!(
            validate_fragment_metadata_set(2, &mut missing),
            Err(PendingQueueArtifactStoreError::FragmentMetadataCardinality {
                expected: 2,
                actual: 1,
            }),
        );

        let mut extra = vec![metadata(0, 1), metadata(1, 2)];
        assert_eq!(
            validate_fragment_metadata_set(1, &mut extra),
            Err(PendingQueueArtifactStoreError::FragmentMetadataCardinality {
                expected: 1,
                actual: 2,
            }),
        );

        let mut duplicate = vec![metadata(0, 1), metadata(0, 2)];
        assert_eq!(
            validate_fragment_metadata_set(2, &mut duplicate),
            Err(PendingQueueArtifactStoreError::NonContiguousFragmentMetadata),
        );
    }

    #[test]
    fn prototype_is_absent_from_setup_and_capabilities_remain_closed() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_ARTIFACT_HEADER_TABLE));
        assert!(!setup.contains(PENDING_QUEUE_ARTIFACT_FRAGMENT_TABLE));
        assert!(!crate::rollback::PRODUCTION_CQL_CAPABILITIES
            .explicit_write_timestamp);
        assert!(!crate::rollback::PRODUCTION_CQL_CAPABILITIES.delete_adapter);
    }
}
