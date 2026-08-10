//! Default-off durable producer outbox for branch-exact pending queues.
//!
//! Source and intent headers are small full-payload LWT rows in a no-tablet
//! keyspace. Raw business payload is first materialized as immutable 4 MiB
//! fragments in a tablet keyspace. Only after exact readback may a source LWT
//! assign the final ordinal/predecessor and mint an opaque publish permit.
//! The transport uses JetStream expected-stream + expected-last-subject-seq,
//! awaits PubAck, and reconciles every uncertain outcome with a leader read.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_nats::{
    recoverable_assignment::PendingQueueGenerationSegmentAssignment,
    recoverable_outbox::{
        reconstruct_payload, PendingQueueIntentTransitionPlan,
        PendingQueueOutboxError,
        PendingQueuePayloadFragment, PendingQueuePublishIntentPhase,
        PendingQueuePublishIntentSlot, PendingQueuePublishRequestKind,
        StoredPendingQueuePublishIntent,
        RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS_PER_BUCKET,
    },
    recoverable_publish::{
        PendingQueueEnvelopeError,
        PendingQueueMemberOrdinal, PendingQueuePublishEnvelope,
        PendingQueuePublishIntentId, PendingQueuePublishSourcePhase,
        PendingQueuePublishSourceSlot, PendingQueuePublishSourceState,
        PendingQueuePublisherKind, RecoverableNatsSourceRoute,
    },
    recoverable_segment::RecoverableNatsStreamSegment,
    recoverable_transport::{
        RecoverableNatsPublishDisposition, RecoverableNatsTransportError,
        RecoverablePendingQueueNatsPublisher,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactDeploymentNoTabletKeyspace, CqlKeyspaceName,
    PendingQueueSegmentAssignmentReceipt, PersistedPendingQueueCloseReceipt,
    ScyllaPendingPipelineStore,
};

pub const PENDING_QUEUE_PUBLISH_SOURCE_TABLE: &str =
    "branch_exact_pending_queue_publish_source_v1";
pub const PENDING_QUEUE_PUBLISH_INTENT_TABLE: &str =
    "branch_exact_pending_queue_publish_intent_v1";
pub const PENDING_QUEUE_PUBLISH_PREPARED_TABLE: &str =
    "branch_exact_pending_queue_publish_prepared_v1";
pub const PENDING_QUEUE_PUBLISH_FRAGMENT_TABLE: &str =
    "branch_exact_pending_queue_publish_payload_fragment_v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-publish-store/v1";

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishDataKeyspace(CqlKeyspaceName);

impl PendingQueuePublishDataKeyspace {
    pub fn try_new(name: impl Into<String>) -> Result<Self, PendingQueuePublishStoreError> {
        let name = name.into();
        if name.ends_with("_no_tablet") || name.ends_with("_nt") {
            return Err(PendingQueuePublishStoreError::DataKeyspaceMustUseTablets(name));
        }
        Ok(Self(CqlKeyspaceName::try_new(name).map_err(|error| {
            PendingQueuePublishStoreError::InvalidKeyspace(error.to_string())
        })?))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishKeyspaces {
    control: BranchExactDeploymentNoTabletKeyspace,
    data: PendingQueuePublishDataKeyspace,
}

impl PendingQueuePublishKeyspaces {
    pub const fn new(
        control: BranchExactDeploymentNoTabletKeyspace,
        data: PendingQueuePublishDataKeyspace,
    ) -> Self {
        Self { control, data }
    }

    pub const fn control(&self) -> &BranchExactDeploymentNoTabletKeyspace {
        &self.control
    }

    pub const fn data(&self) -> &PendingQueuePublishDataKeyspace {
        &self.data
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingQueuePublishQueryId {
    CreateSource = 1,
    CreateIntent = 2,
    CreateFragment = 3,
    ReadSource = 4,
    BootstrapSource = 5,
    CasSource = 6,
    ReadIntent = 7,
    BootstrapIntent = 8,
    CasIntent = 9,
    PutFragment = 10,
    ReadFragment = 11,
    ReadFragmentBucket = 12,
    CreatePrepared = 13,
    ReadPrepared = 14,
    BootstrapPrepared = 15,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishQuery {
    id: PendingQueuePublishQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingQueuePublishQuery {
    pub const fn id(&self) -> PendingQueuePublishQueryId { self.id }
    pub fn cql(&self) -> &str { &self.cql }
    pub const fn bind_shape(&self) -> &'static [&'static str] { self.bind_shape }
}

const HEADER_READ: &[&str] = &["slot:BLOB"];
const HEADER_BOOTSTRAP: &[&str] = &["slot:BLOB", "revision:BIGINT", "payload:BLOB"];
const HEADER_CAS: &[&str] = &[
    "candidate_revision:BIGINT",
    "candidate_payload:BLOB",
    "slot:BLOB",
    "expected_revision:BIGINT",
    "expected_payload:BLOB",
];
const PREPARED_READ: &[&str] = &["source_slot:BLOB", "intent_slot:BLOB"];
const PREPARED_BOOTSTRAP: &[&str] = &[
    "source_slot:BLOB",
    "intent_slot:BLOB",
    "revision:BIGINT",
    "payload:BLOB",
];
const FRAGMENT_PUT: &[&str] = &[
    "intent_slot:BLOB",
    "payload_digest:BLOB",
    "fragment_bucket:BIGINT",
    "fragment_index:SMALLINT",
    "fragment_count:SMALLINT",
    "payload_bytes:BIGINT",
    "payload:BLOB",
    "fragment_digest:BLOB",
];
const FRAGMENT_READ: &[&str] = &[
    "intent_slot:BLOB",
    "payload_digest:BLOB",
    "fragment_bucket:BIGINT",
    "fragment_index:SMALLINT",
];
const FRAGMENT_BUCKET_READ: &[&str] = &[
    "intent_slot:BLOB",
    "payload_digest:BLOB",
    "fragment_bucket:BIGINT",
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishQueries {
    queries: [PendingQueuePublishQuery; 15],
}

impl PendingQueuePublishQueries {
    pub fn new(keyspaces: &PendingQueuePublishKeyspaces) -> Self {
        let source = format!("{}.{}", keyspaces.control().as_str(), PENDING_QUEUE_PUBLISH_SOURCE_TABLE);
        let intent = format!("{}.{}", keyspaces.control().as_str(), PENDING_QUEUE_PUBLISH_INTENT_TABLE);
        let prepared = format!("{}.{}", keyspaces.control().as_str(), PENDING_QUEUE_PUBLISH_PREPARED_TABLE);
        let fragment = format!("{}.{}", keyspaces.data().as_str(), PENDING_QUEUE_PUBLISH_FRAGMENT_TABLE);
        Self { queries: [
            query(PendingQueuePublishQueryId::CreateSource, format!("CREATE TABLE IF NOT EXISTS {source} (source_slot blob PRIMARY KEY, revision bigint, source_payload blob)"), &[]),
            query(PendingQueuePublishQueryId::CreateIntent, format!("CREATE TABLE IF NOT EXISTS {intent} (intent_slot blob PRIMARY KEY, revision bigint, intent_payload blob)"), &[]),
            query(PendingQueuePublishQueryId::CreateFragment, format!("CREATE TABLE IF NOT EXISTS {fragment} (intent_slot blob, payload_digest blob, fragment_bucket bigint, fragment_index smallint, fragment_count smallint, payload_bytes bigint, payload blob, fragment_digest blob, PRIMARY KEY ((intent_slot, payload_digest, fragment_bucket), fragment_index)) WITH CLUSTERING ORDER BY (fragment_index ASC)"), &[]),
            query(PendingQueuePublishQueryId::ReadSource, format!("SELECT revision, source_payload FROM {source} WHERE source_slot = ?"), HEADER_READ),
            query(PendingQueuePublishQueryId::BootstrapSource, format!("INSERT INTO {source} (source_slot, revision, source_payload) VALUES (?, ?, ?) IF NOT EXISTS"), HEADER_BOOTSTRAP),
            query(PendingQueuePublishQueryId::CasSource, format!("UPDATE {source} SET revision = ?, source_payload = ? WHERE source_slot = ? IF revision = ? AND source_payload = ?"), HEADER_CAS),
            query(PendingQueuePublishQueryId::ReadIntent, format!("SELECT revision, intent_payload FROM {intent} WHERE intent_slot = ?"), HEADER_READ),
            query(PendingQueuePublishQueryId::BootstrapIntent, format!("INSERT INTO {intent} (intent_slot, revision, intent_payload) VALUES (?, ?, ?) IF NOT EXISTS"), HEADER_BOOTSTRAP),
            query(PendingQueuePublishQueryId::CasIntent, format!("UPDATE {intent} SET revision = ?, intent_payload = ? WHERE intent_slot = ? IF revision = ? AND intent_payload = ?"), HEADER_CAS),
            query(PendingQueuePublishQueryId::PutFragment, format!("INSERT INTO {fragment} (intent_slot, payload_digest, fragment_bucket, fragment_index, fragment_count, payload_bytes, payload, fragment_digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"), FRAGMENT_PUT),
            query(PendingQueuePublishQueryId::ReadFragment, format!("SELECT payload_digest, fragment_bucket, fragment_index, fragment_count, payload_bytes, payload, fragment_digest FROM {fragment} WHERE intent_slot = ? AND payload_digest = ? AND fragment_bucket = ? AND fragment_index = ?"), FRAGMENT_READ),
            query(PendingQueuePublishQueryId::ReadFragmentBucket, format!("SELECT fragment_index, fragment_digest FROM {fragment} WHERE intent_slot = ? AND payload_digest = ? AND fragment_bucket = ?"), FRAGMENT_BUCKET_READ),
            query(PendingQueuePublishQueryId::CreatePrepared, format!("CREATE TABLE IF NOT EXISTS {prepared} (source_slot blob, intent_slot blob, revision bigint, prepared_payload blob, PRIMARY KEY ((source_slot), intent_slot)) WITH CLUSTERING ORDER BY (intent_slot ASC)"), &[]),
            query(PendingQueuePublishQueryId::ReadPrepared, format!("SELECT revision, prepared_payload FROM {prepared} WHERE source_slot = ? AND intent_slot = ?"), PREPARED_READ),
            query(PendingQueuePublishQueryId::BootstrapPrepared, format!("INSERT INTO {prepared} (source_slot, intent_slot, revision, prepared_payload) VALUES (?, ?, ?, ?) IF NOT EXISTS"), PREPARED_BOOTSTRAP),
        ] }
    }

    pub fn get(&self, id: PendingQueuePublishQueryId) -> &PendingQueuePublishQuery {
        &self.queries[id as usize - 1]
    }

    pub fn all(&self) -> &[PendingQueuePublishQuery; 15] { &self.queries }

    pub fn render_golden(&self) -> String {
        self.queries.iter().map(|q| format!("{:?}|{}\n{}\n", q.id, q.bind_shape.join(","), q.cql)).collect()
    }
}

fn query(id: PendingQueuePublishQueryId, cql: String, bind_shape: &'static [&'static str]) -> PendingQueuePublishQuery {
    PendingQueuePublishQuery { id, cql, bind_shape }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct HeaderReadBinding { slot: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct HeaderBootstrapBinding { slot: Vec<u8>, revision: i64, payload: Vec<u8> }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct HeaderCasBinding {
    candidate_revision: i64,
    candidate_payload: Vec<u8>,
    slot: Vec<u8>,
    expected_revision: i64,
    expected_payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PreparedReadBinding {
    source_slot: Vec<u8>,
    intent_slot: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PreparedBootstrapBinding {
    source_slot: Vec<u8>,
    intent_slot: Vec<u8>,
    revision: i64,
    payload: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentPutBinding {
    intent_slot: Vec<u8>, payload_digest: Vec<u8>, fragment_bucket: i64,
    fragment_index: i16, fragment_count: i16, payload_bytes: i64,
    payload: Vec<u8>, fragment_digest: Vec<u8>,
}

impl FragmentPutBinding {
    fn try_new(slot: PendingQueuePublishIntentSlot, fragment: &PendingQueuePayloadFragment) -> Result<Self, PendingQueuePublishStoreError> {
        Ok(Self {
            intent_slot: slot.as_bytes().to_vec(),
            payload_digest: fragment.payload_digest().as_bytes().to_vec(),
            fragment_bucket: i64::from(fragment.fragment_bucket()),
            fragment_index: i16::try_from(fragment.fragment_index()).map_err(|_| PendingQueuePublishStoreError::CoordinateOutOfRange)?,
            fragment_count: i16::try_from(fragment.fragment_count()).map_err(|_| PendingQueuePublishStoreError::CoordinateOutOfRange)?,
            payload_bytes: i64::try_from(fragment.payload_bytes()).map_err(|_| PendingQueuePublishStoreError::CoordinateOutOfRange)?,
            payload: fragment.bytes().to_vec(),
            fragment_digest: fragment.digest().as_bytes().to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentReadBinding { intent_slot: Vec<u8>, payload_digest: Vec<u8>, fragment_bucket: i64, fragment_index: i16 }

#[derive(Clone, Debug, Eq, PartialEq, scylla::SerializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentBucketReadBinding { intent_slot: Vec<u8>, payload_digest: Vec<u8>, fragment_bucket: i64 }

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct HeaderDbRow { revision: i64, source_payload: Vec<u8> }

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct IntentHeaderDbRow { revision: i64, intent_payload: Vec<u8> }

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct PreparedDbRow { revision: i64, prepared_payload: Vec<u8> }

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentDbRow {
    payload_digest: Vec<u8>, fragment_bucket: i64, fragment_index: i16,
    fragment_count: i16, payload_bytes: i64, payload: Vec<u8>, fragment_digest: Vec<u8>,
}

#[derive(scylla::DeserializeRow)]
#[scylla(flavor = "enforce_order", skip_name_checks)]
struct FragmentMetadataDbRow { fragment_index: i16, fragment_digest: Vec<u8> }

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishStoreFingerprint([u8; 32]);

impl PendingQueuePublishStoreFingerprint { pub const fn as_bytes(&self) -> &[u8; 32] { &self.0 } }

#[derive(Debug)]
pub struct DurablyBoundPendingQueuePublish {
    store_fingerprint: PendingQueuePublishStoreFingerprint,
    intent_slot: PendingQueuePublishIntentSlot,
    source_slot: PendingQueuePublishSourceSlot,
    intent_revision: u64,
    source_revision: u64,
    envelope: PendingQueuePublishEnvelope,
}

impl DurablyBoundPendingQueuePublish {
    pub const fn intent_slot(&self) -> PendingQueuePublishIntentSlot { self.intent_slot }
    pub const fn source_slot(&self) -> PendingQueuePublishSourceSlot { self.source_slot }
    pub const fn envelope(&self) -> &PendingQueuePublishEnvelope { &self.envelope }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingQueueNatsPublishDisposition {
    PubAck,
    LeaderReadback,
    DurableResume,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishCommitReceipt {
    intent_slot: PendingQueuePublishIntentSlot,
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    disposition: PendingQueueNatsPublishDisposition,
}

/// Private continuation captured after NATS acceptance and after the source
/// cursor has reached CommitPending. The intent may still be NatsAccepted at
/// this earliest durable crash boundary, or already SourceCommitted during an
/// idempotent retry. Production immediately consumes it to finish both CASes.
struct PendingQueueSourceCommitProgress {
    source: PendingQueuePublishSourceState,
    intent: StoredPendingQueuePublishIntent,
    intent_slot: PendingQueuePublishIntentSlot,
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    disposition: PendingQueueNatsPublishDisposition,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PersistedCommitPendingFixture {
    source_slot: PendingQueuePublishSourceSlot,
    intent_slot: PendingQueuePublishIntentSlot,
    source_revision: u64,
    intent_revision: u64,
    subject_sequence: u64,
    envelope_digest: [u8; 32],
}

#[cfg(test)]
impl PersistedCommitPendingFixture {
    pub(crate) const fn source_slot(&self) -> PendingQueuePublishSourceSlot {
        self.source_slot
    }

    pub(crate) const fn intent_slot(&self) -> PendingQueuePublishIntentSlot {
        self.intent_slot
    }

    pub(crate) const fn source_revision(&self) -> u64 {
        self.source_revision
    }

    pub(crate) const fn intent_revision(&self) -> u64 {
        self.intent_revision
    }

    pub(crate) const fn subject_sequence(&self) -> u64 {
        self.subject_sequence
    }

    pub(crate) const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }
}

/// Opaque exact readback of one durable publisher source after Seal.  It is
/// deliberately non-Clone and can only be minted by this store after the
/// assignment, publisher role, and close intent all match the current row.
#[derive(Debug)]
pub struct PersistedPendingQueueSealedSourceReceipt {
    store_fingerprint: PendingQueuePublishStoreFingerprint,
    source_state: PendingQueuePublishSourceState,
}

impl PersistedPendingQueueSealedSourceReceipt {
    pub const fn store_fingerprint(&self) -> PendingQueuePublishStoreFingerprint {
        self.store_fingerprint
    }

    pub const fn source_state(&self) -> &PendingQueuePublishSourceState {
        &self.source_state
    }
}

impl PendingQueuePublishCommitReceipt {
    pub const fn intent_slot(&self) -> PendingQueuePublishIntentSlot {
        self.intent_slot
    }

    pub const fn subject_sequence(&self) -> u64 {
        self.subject_sequence
    }

    pub const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    pub const fn disposition(&self) -> PendingQueueNatsPublishDisposition {
        self.disposition
    }
}

pub struct ScyllaPendingQueuePublishStore {
    session: Arc<Session>,
    nats: Arc<RecoverablePendingQueueNatsPublisher>,
    segment: RecoverableNatsStreamSegment,
    queries: PendingQueuePublishQueries,
    fingerprint: PendingQueuePublishStoreFingerprint,
    read_source: PreparedStatement, bootstrap_source: PreparedStatement, cas_source: PreparedStatement,
    read_intent: PreparedStatement, bootstrap_intent: PreparedStatement, cas_intent: PreparedStatement,
    read_prepared: PreparedStatement, bootstrap_prepared: PreparedStatement,
    put_fragment: PreparedStatement, read_fragment: PreparedStatement, read_fragment_bucket: PreparedStatement,
}

impl ScyllaPendingQueuePublishStore {
    pub(crate) async fn create_schema(
        session: &Session,
        keyspaces: &PendingQueuePublishKeyspaces,
    ) -> Result<(), PendingQueuePublishStoreError> {
        let queries = PendingQueuePublishQueries::new(keyspaces);
        for id in [
            PendingQueuePublishQueryId::CreateSource,
            PendingQueuePublishQueryId::CreateIntent,
            PendingQueuePublishQueryId::CreateFragment,
            PendingQueuePublishQueryId::CreatePrepared,
        ] {
            session.query_unpaged(queries.get(id).cql(), &[]).await.map_err(cql)?;
        }
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(crate) async fn prepare(
        session: Arc<Session>,
        nats: Arc<RecoverablePendingQueueNatsPublisher>,
        segment: RecoverableNatsStreamSegment,
        keyspaces: PendingQueuePublishKeyspaces,
    ) -> Result<Self, PendingQueuePublishStoreError> {
        let queries = PendingQueuePublishQueries::new(&keyspaces);
        let fingerprint = store_fingerprint(&keyspaces, &segment, &queries);
        Ok(Self {
            read_source: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadSource).cql()).await?,
            bootstrap_source: prepare_lwt(&session, queries.get(PendingQueuePublishQueryId::BootstrapSource).cql()).await?,
            cas_source: prepare_lwt(&session, queries.get(PendingQueuePublishQueryId::CasSource).cql()).await?,
            read_intent: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadIntent).cql()).await?,
            bootstrap_intent: prepare_lwt(&session, queries.get(PendingQueuePublishQueryId::BootstrapIntent).cql()).await?,
            cas_intent: prepare_lwt(&session, queries.get(PendingQueuePublishQueryId::CasIntent).cql()).await?,
            read_prepared: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadPrepared).cql()).await?,
            bootstrap_prepared: prepare_lwt(&session, queries.get(PendingQueuePublishQueryId::BootstrapPrepared).cql()).await?,
            put_fragment: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::PutFragment).cql()).await?,
            read_fragment: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadFragment).cql()).await?,
            read_fragment_bucket: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadFragmentBucket).cql()).await?,
            session, nats, segment, queries, fingerprint,
        })
    }

    pub const fn queries(&self) -> &PendingQueuePublishQueries { &self.queries }
    pub const fn fingerprint(&self) -> PendingQueuePublishStoreFingerprint { self.fingerprint }
    pub(super) const fn segment(&self) -> &RecoverableNatsStreamSegment { &self.segment }

    pub(super) async fn read_sealed_source_exact(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        close_receipt: &PersistedPendingQueueCloseReceipt,
    ) -> Result<PersistedPendingQueueSealedSourceReceipt, PendingQueuePublishStoreError> {
        if !close_receipt.matches_context(assignment_receipt.assignment().context()) {
            return Err(PendingQueuePublishStoreError::CloseContextMismatch);
        }
        let source = self
            .require_source(assignment_receipt, publisher_kind)
            .await?;
        match source.phase() {
            PendingQueuePublishSourcePhase::Sealed { close_intent, .. }
                if *close_intent == close_receipt.close_intent() => {}
            PendingQueuePublishSourcePhase::Sealed { .. } => {
                return Err(PendingQueuePublishStoreError::CloseIntentMismatch)
            }
            _ => return Err(PendingQueuePublishStoreError::SourceNotSealed),
        }
        Ok(PersistedPendingQueueSealedSourceReceipt {
            store_fingerprint: self.fingerprint,
            source_state: source,
        })
    }

    pub async fn bootstrap_source(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
    ) -> Result<PendingQueuePublishSourceState, PendingQueuePublishStoreError> {
        match self
            .require_source(assignment_receipt, publisher_kind)
            .await
        {
            Ok(current) => return Ok(current),
            Err(PendingQueuePublishStoreError::SourceUninitialized) => {}
            Err(error) => return Err(error),
        }
        let assignment = assignment_receipt.assignment();
        self.validate_assignment(assignment)?;
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), publisher_kind, &self.segment,
        ).map_err(model_envelope)?;
        let candidate = PendingQueuePublishSourceState::bootstrap(&route, assignment)
            .map_err(model_envelope)?;
        let binding = HeaderBootstrapBinding {
            slot: candidate.slot().map_err(model_envelope)?.as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            payload: candidate.to_persisted_bytes(),
        };
        let execution = self.session.execute_unpaged(&self.bootstrap_source, binding).await;
        match self.finish_source_write(execution, &candidate).await {
            Ok(current) => Ok(current),
            // Another exact publisher may have bootstrapped and already
            // advanced this source between the pre-read and IF NOT EXISTS.
            // Re-read through require_source so only the same assignment and
            // artifact identity are accepted; a foreign source remains a
            // hard conflict.
            Err(PendingQueuePublishStoreError::CasConflict) => {
                self.require_source(assignment_receipt, publisher_kind).await
            }
            Err(error) => Err(error),
        }
    }

    pub async fn materialize_data(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        intent_id: PendingQueuePublishIntentId,
        payload: &[u8],
    ) -> Result<PendingQueuePublishIntentSlot, PendingQueuePublishStoreError> {
        let source = self.require_source(assignment_receipt, publisher_kind).await?;
        let (candidate, fragments) = StoredPendingQueuePublishIntent::materialize_data(
            &source, intent_id, payload,
        ).map_err(model_outbox)?;
        for fragment in &fragments {
            self.persist_and_readback_fragment(candidate.slot(), fragment).await?;
        }
        self.require_exact_fragment_set(&candidate).await?;
        self.persist_and_readback_prepared(&candidate).await?;
        Ok(candidate.slot())
    }

    pub(crate) async fn materialize_seal<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        intent_id: PendingQueuePublishIntentId,
        close_receipt: &PersistedPendingQueueCloseReceipt,
    ) -> Result<PendingQueuePublishIntentSlot, PendingQueuePublishStoreError> {
        if !close_receipt.matches_context(assignment_receipt.assignment().context()) {
            return Err(PendingQueuePublishStoreError::CloseContextMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(
                assignment_receipt.assignment().context(),
                close_receipt,
            )
            .await
            .map_err(|error| PendingQueuePublishStoreError::Pipeline(error.to_string()))?;
        let source = self.require_source(assignment_receipt, publisher_kind).await?;
        let candidate = StoredPendingQueuePublishIntent::materialize_seal(
            &source,
            intent_id,
            close_receipt.close_intent(),
        )
        .map_err(model_outbox)?;
        self.persist_and_readback_prepared(&candidate).await?;
        Ok(candidate.slot())
    }

    pub async fn bind_materialized(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        intent_slot: PendingQueuePublishIntentSlot,
    ) -> Result<DurablyBoundPendingQueuePublish, PendingQueuePublishStoreError> {
        let assignment = assignment_receipt.assignment();
        self.validate_assignment(assignment)?;
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), publisher_kind, &self.segment,
        ).map_err(model_envelope)?;
        let expected_source = PendingQueuePublishSourceState::bootstrap(&route, assignment)
            .map_err(model_envelope)?;
        let source_slot = expected_source.slot().map_err(model_envelope)?;
        let mut source = self.read_source(source_slot).await?
            .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?;
        let prepared = self.read_prepared(source_slot, intent_slot).await?
            .ok_or(PendingQueuePublishStoreError::IntentUninitialized)?;
        if prepared.publisher_kind() != publisher_kind
            || prepared.assignment_digest() != assignment.digest()
            || prepared.source_slot() != source_slot
        {
            return Err(PendingQueuePublishStoreError::AssignmentMismatch);
        }
        let payload = self.load_payload(&prepared).await?;
        let envelope = self.build_envelope(&route, assignment, &source, &prepared, payload.clone())?;
        let persisted_intent = self.read_intent(intent_slot).await?;
        if let Some(current) = persisted_intent.as_ref() {
            if current.source_slot() != source_slot
                || current.assignment_digest() != assignment.digest()
            {
                if source.inflight_matches(&envelope) {
                    self.cancel_unpublished_source_selection(&source, &envelope).await?;
                }
                return Err(PendingQueuePublishStoreError::IntentBoundElsewhere);
            }
        }
        let mut intent = persisted_intent.unwrap_or(prepared);
        if matches!(intent.phase(), PendingQueuePublishIntentPhase::Materialized) {
            let source_plan = source.select(&envelope).map_err(model_envelope)?;
            if let Some((expected, candidate)) = source_plan.transition() {
                source = self.cas_source_state(expected, candidate).await?;
            }
        }
        if !source.inflight_matches(&envelope)
            && !(source.last_subject_sequence() > envelope.previous_subject_sequence()
                && source.last_envelope_digest() == *envelope.digest().as_bytes())
        {
            return Err(PendingQueuePublishStoreError::SourceSelectionMismatch);
        }
        if matches!(intent.phase(), PendingQueuePublishIntentPhase::Materialized) {
            let intent_plan = intent.bind(&source, &envelope, &payload).map_err(model_outbox)?;
            let (_, candidate) = intent_plan.transition()
                .ok_or(PendingQueuePublishStoreError::IntentPhaseMismatch)?;
            intent = match self.bootstrap_bound_intent(candidate).await {
                Ok(intent) => intent,
                Err(PendingQueuePublishStoreError::CasConflict) => {
                    let current = self.read_intent(intent_slot).await?
                        .ok_or(PendingQueuePublishStoreError::IntentUninitialized)?;
                    if current.source_slot() == source_slot
                        && current.assignment_digest() == assignment.digest()
                        && self.intent_matches_envelope(&current, &envelope)
                    {
                        current
                    } else {
                        self.cancel_unpublished_source_selection(&source, &envelope).await?;
                        return Err(PendingQueuePublishStoreError::IntentBoundElsewhere);
                    }
                }
                Err(error) => return Err(error),
            };
        }
        if intent.bound_envelope().is_none() || !self.intent_matches_envelope(&intent, &envelope) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        Ok(DurablyBoundPendingQueuePublish {
            store_fingerprint: self.fingerprint,
            intent_slot,
            source_slot: source.slot().map_err(model_envelope)?,
            intent_revision: intent.revision().get(),
            source_revision: source.revision().get(),
            envelope,
        })
    }

    pub async fn publish_and_commit(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        permit: DurablyBoundPendingQueuePublish,
    ) -> Result<PendingQueuePublishCommitReceipt, PendingQueuePublishStoreError> {
        let progress = self
            .persist_through_source_commit_pending(assignment_receipt, permit)
            .await?;
        self.finalize_source_commit(progress).await
    }

    async fn persist_through_source_commit_pending(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        permit: DurablyBoundPendingQueuePublish,
    ) -> Result<PendingQueueSourceCommitProgress, PendingQueuePublishStoreError> {
        if permit.store_fingerprint != self.fingerprint {
            return Err(PendingQueuePublishStoreError::PermitStoreMismatch);
        }
        let assignment = assignment_receipt.assignment();
        self.validate_assignment(assignment)?;
        if permit.envelope.assignment_digest() != assignment.digest() {
            return Err(PendingQueuePublishStoreError::AssignmentMismatch);
        }
        let mut intent = self.read_intent(permit.intent_slot).await?
            .ok_or(PendingQueuePublishStoreError::IntentUninitialized)?;
        let mut source = self.read_source(permit.source_slot).await?
            .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?;
        let payload = self.load_payload(&intent).await?;
        if intent.revision().get() < permit.intent_revision
            || source.revision().get() < permit.source_revision
            || !self.intent_matches_envelope(&intent, &permit.envelope)
        {
            return Err(PendingQueuePublishStoreError::PermitStateMismatch);
        }

        let (subject_sequence, disposition) = match intent.accepted_subject_sequence() {
            Some(sequence) => (sequence, PendingQueueNatsPublishDisposition::DurableResume),
            None => {
                if !matches!(intent.phase(), PendingQueuePublishIntentPhase::Bound(_))
                    || !source.selected_matches(&permit.envelope)
                {
                    return Err(PendingQueuePublishStoreError::PermitStateMismatch);
                }
                let result = self.publish_exact(&permit.envelope).await?;
                let plan = intent.record_nats_accepted(result.0).map_err(model_outbox)?;
                intent = self.apply_intent_plan(plan).await?;
                result
            }
        };

        if matches!(source.phase(), PendingQueuePublishSourcePhase::Publishing(_)) {
            let plan = source.record_published(subject_sequence).map_err(model_envelope)?;
            source = self.cas_source_state(plan.expected(), plan.candidate()).await?;
        }
        if !matches!(source.phase(), PendingQueuePublishSourcePhase::CommitPending { .. })
            && !(source.last_subject_sequence() == subject_sequence
                && source.last_envelope_digest() == *permit.envelope.digest().as_bytes())
        {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        if !matches!(
            intent.phase(),
            PendingQueuePublishIntentPhase::NatsAccepted { .. }
                | PendingQueuePublishIntentPhase::SourceCommitted { .. }
        ) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        if intent.accepted_subject_sequence() != Some(subject_sequence) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        let _ = payload;
        Ok(PendingQueueSourceCommitProgress {
            source,
            intent,
            intent_slot: permit.intent_slot,
            subject_sequence,
            envelope_digest: *permit.envelope.digest().as_bytes(),
            disposition,
        })
    }

    async fn finalize_source_commit(
        &self,
        mut progress: PendingQueueSourceCommitProgress,
    ) -> Result<PendingQueuePublishCommitReceipt, PendingQueuePublishStoreError> {
        if matches!(
            progress.intent.phase(),
            PendingQueuePublishIntentPhase::NatsAccepted { .. }
        ) {
            let plan = progress
                .intent
                .record_source_committed()
                .map_err(model_outbox)?;
            progress.intent = self.apply_intent_plan(plan).await?;
        }
        if !matches!(
            progress.intent.phase(),
            PendingQueuePublishIntentPhase::SourceCommitted { .. }
        ) || progress.intent.accepted_subject_sequence()
            != Some(progress.subject_sequence)
        {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        if matches!(
            progress.source.phase(),
            PendingQueuePublishSourcePhase::CommitPending { .. }
        ) {
            let plan = progress
                .source
                .finalize_published()
                .map_err(model_envelope)?;
            progress.source = self
                .cas_source_state(plan.expected(), plan.candidate())
                .await?;
        }
        if progress.source.last_subject_sequence() != progress.subject_sequence
            || progress.source.last_envelope_digest() != progress.envelope_digest
        {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        Ok(PendingQueuePublishCommitReceipt {
            intent_slot: progress.intent_slot,
            subject_sequence: progress.subject_sequence,
            envelope_digest: progress.envelope_digest,
            disposition: progress.disposition,
        })
    }

    /// Test-only deterministic crash stop at the sole durable boundary used
    /// by production. It cannot mutate an arbitrary phase or finalize/resume
    /// the source and exposes only a read-only witness.
    #[cfg(test)]
    pub(crate) async fn publish_through_commit_pending_fixture(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        permit: DurablyBoundPendingQueuePublish,
    ) -> Result<PersistedCommitPendingFixture, PendingQueuePublishStoreError> {
        let progress = self
            .persist_through_source_commit_pending(assignment_receipt, permit)
            .await?;
        if !matches!(
            progress.source.phase(),
            PendingQueuePublishSourcePhase::CommitPending { .. }
        ) || !matches!(
            progress.intent.phase(),
            PendingQueuePublishIntentPhase::NatsAccepted { .. }
        ) {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        Ok(PersistedCommitPendingFixture {
            source_slot: progress.source.slot().map_err(model_envelope)?,
            intent_slot: progress.intent.slot(),
            source_revision: progress.source.revision().get(),
            intent_revision: progress.intent.revision().get(),
            subject_sequence: progress.subject_sequence,
            envelope_digest: progress.envelope_digest,
        })
    }

    /// Reconstruct exact committed evidence for an existing data intent. This
    /// path remains valid after the source generation has rotated. It never
    /// selects a new source member or publishes to NATS; it may only finish
    /// the exact CommitPending cursor CAS left after an earlier NATS commit.
    pub(crate) async fn observe_committed_data(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        intent_id: PendingQueuePublishIntentId,
        payload: &[u8],
    ) -> Result<Option<PendingQueuePublishCommitReceipt>, PendingQueuePublishStoreError> {
        let assignment = assignment_receipt.assignment();
        self.validate_assignment(assignment)?;
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(),
            publisher_kind,
            &self.segment,
        )
        .map_err(model_envelope)?;
        let mut source = match self
            .require_source(assignment_receipt, publisher_kind)
            .await
        {
            Ok(source) => source,
            Err(PendingQueuePublishStoreError::SourceUninitialized) => {
                // Before the first live publish neither the source cursor nor
                // this exact intent exists.  That is a clean "not observed"
                // result, not recovery evidence.  Conversely, an intent with
                // a missing source cursor is inconsistent durable state and
                // must remain fail closed: allowing the caller to bootstrap a
                // new cursor could duplicate an already accepted envelope.
                let candidate = PendingQueuePublishSourceState::bootstrap(
                    &route,
                    assignment,
                )
                .map_err(model_envelope)?;
                let (expected, _) = StoredPendingQueuePublishIntent::materialize_data(
                    &candidate,
                    intent_id,
                    payload,
                )
                .map_err(model_outbox)?;
                if self.read_intent(expected.slot()).await?.is_none() {
                    return Ok(None);
                }
                return Err(PendingQueuePublishStoreError::SourceUninitialized);
            }
            Err(error) => return Err(error),
        };
        let (expected, _) = StoredPendingQueuePublishIntent::materialize_data(
            &source,
            intent_id,
            payload,
        )
        .map_err(model_outbox)?;
        let Some(current) = self.read_intent(expected.slot()).await? else {
            return Ok(None);
        };
        if current.artifact_identity() != expected.artifact_identity()
            || current.source_slot() != expected.source_slot()
            || current.publisher_kind() != expected.publisher_kind()
            || current.assignment_digest() != expected.assignment_digest()
            || current.intent_id() != expected.intent_id()
            || current.request_kind() != expected.request_kind()
            || current.payload_digest() != expected.payload_digest()
            || current.payload_bytes() != expected.payload_bytes()
            || current.fragment_count() != expected.fragment_count()
        {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        let loaded = self.load_payload(&current).await?;
        if loaded != payload {
            return Err(PendingQueuePublishStoreError::PayloadMismatch);
        }
        if !matches!(
            current.phase(),
            PendingQueuePublishIntentPhase::SourceCommitted { .. }
        ) {
            return Ok(None);
        }
        let envelope = self.build_envelope(
            &route,
            assignment,
            &source,
            &current,
            loaded,
        )?;
        if !self.intent_matches_envelope(&current, &envelope) {
            return Err(PendingQueuePublishStoreError::PermitStateMismatch);
        }
        let subject_sequence = current
            .accepted_subject_sequence()
            .ok_or(PendingQueuePublishStoreError::IntentPhaseMismatch)?;
        if let Some((_, pending_sequence)) = source.commit_pending() {
            if pending_sequence != subject_sequence
                || !source.inflight_matches(&envelope)
            {
                return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
            }
            let plan = source.finalize_published().map_err(model_envelope)?;
            source = match self
                .cas_source_state(plan.expected(), plan.candidate())
                .await
            {
                Ok(current) => current,
                Err(PendingQueuePublishStoreError::CasConflict) => self
                    .read_source(source.slot().map_err(model_envelope)?)
                    .await?
                    .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?,
                Err(error) => return Err(error),
            };
        }
        if source.commit_pending().is_some() {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        if source.data_member_count() < envelope.member_ordinal().get()
            || source.last_subject_sequence() < subject_sequence
            || (source.last_subject_sequence() == subject_sequence
                && source.last_envelope_digest()
                    != *envelope.digest().as_bytes())
        {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        Ok(Some(PendingQueuePublishCommitReceipt {
            intent_slot: current.slot(),
            subject_sequence,
            envelope_digest: *envelope.digest().as_bytes(),
            disposition: PendingQueueNatsPublishDisposition::DurableResume,
        }))
    }

    fn validate_assignment(&self, assignment: &PendingQueueGenerationSegmentAssignment) -> Result<(), PendingQueuePublishStoreError> {
        if assignment.segment_id() != self.segment.segment_id()
            || assignment.contract_digest() != self.segment.digest()
        {
            return Err(PendingQueuePublishStoreError::AssignmentMismatch);
        }
        Ok(())
    }

    async fn require_source(
        &self,
        receipt: &PendingQueueSegmentAssignmentReceipt,
        kind: PendingQueuePublisherKind,
    ) -> Result<PendingQueuePublishSourceState, PendingQueuePublishStoreError> {
        let assignment = receipt.assignment();
        self.validate_assignment(assignment)?;
        let route = RecoverableNatsSourceRoute::try_new(assignment.context(), kind, &self.segment).map_err(model_envelope)?;
        let expected = PendingQueuePublishSourceState::bootstrap(&route, assignment).map_err(model_envelope)?;
        let current = self.read_source(expected.slot().map_err(model_envelope)?).await?
            .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?;
        if current.artifact_identity() != expected.artifact_identity()
            || current.assignment_digest() != expected.assignment_digest()
            || current.publisher_kind() != expected.publisher_kind()
        {
            return Err(PendingQueuePublishStoreError::AssignmentMismatch);
        }
        Ok(current)
    }

    fn build_envelope(
        &self,
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        source: &PendingQueuePublishSourceState,
        intent: &StoredPendingQueuePublishIntent,
        payload: Vec<u8>,
    ) -> Result<PendingQueuePublishEnvelope, PendingQueuePublishStoreError> {
        let (ordinal, previous_subject_sequence, previous_envelope_digest) =
            if let Some(bound) = intent.bound_envelope() {
                (
                    bound.member_ordinal(),
                    bound.previous_subject_sequence(),
                    bound.previous_envelope_digest(),
                )
            } else {
                (
                    PendingQueueMemberOrdinal::try_new(source.data_member_count().checked_add(1).ok_or(PendingQueuePublishStoreError::CoordinateOutOfRange)?)
                        .map_err(model_envelope)?,
                    source.last_subject_sequence(),
                    source.last_envelope_digest(),
                )
            };
        match intent.request_kind() {
            PendingQueuePublishRequestKind::Data => PendingQueuePublishEnvelope::data(
                route, assignment, intent.intent_id(), ordinal,
                previous_subject_sequence, previous_envelope_digest, payload,
            ).map_err(model_envelope),
            PendingQueuePublishRequestKind::Seal => PendingQueuePublishEnvelope::seal(
                route, assignment, intent.intent_id(), ordinal,
                previous_subject_sequence, previous_envelope_digest,
                source.seal_summary(
                    intent.close_intent().ok_or(PendingQueuePublishStoreError::IntentPhaseMismatch)?
                ).map_err(model_envelope)?,
            ).map_err(model_envelope),
        }
    }

    fn intent_matches_envelope(&self, intent: &StoredPendingQueuePublishIntent, envelope: &PendingQueuePublishEnvelope) -> bool {
        intent.bound_envelope().is_some_and(|bound| {
            bound.envelope_digest() == envelope.digest()
                && bound.member_ordinal() == envelope.member_ordinal()
                && bound.previous_subject_sequence() == envelope.previous_subject_sequence()
                && bound.previous_envelope_digest() == envelope.previous_envelope_digest()
                && bound.encoded_bytes() == envelope.to_canonical_bytes().len() as u64
        })
    }

    async fn publish_exact(
        &self,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<(u64, PendingQueueNatsPublishDisposition), PendingQueuePublishStoreError> {
        let outcome = self.nats.publish(envelope).await.map_err(nats_transport)?;
        let disposition = match outcome.disposition() {
            RecoverableNatsPublishDisposition::PubAck => {
                PendingQueueNatsPublishDisposition::PubAck
            }
            RecoverableNatsPublishDisposition::LeaderReadback => {
                PendingQueueNatsPublishDisposition::LeaderReadback
            }
        };
        Ok((outcome.subject_sequence(), disposition))
    }

    async fn read_source(&self, slot: PendingQueuePublishSourceSlot) -> Result<Option<PendingQueuePublishSourceState>, PendingQueuePublishStoreError> {
        let row = self.session.execute_unpaged(&self.read_source, HeaderReadBinding { slot: slot.as_bytes().to_vec() }).await.map_err(cql)?
            .into_rows_result().map_err(cql)?.maybe_first_row::<HeaderDbRow>().map_err(cql)?;
        row.map(|row| PendingQueuePublishSourceState::decode_persisted(row.revision, &row.source_payload).map_err(model_envelope)).transpose()
    }

    async fn read_intent(&self, slot: PendingQueuePublishIntentSlot) -> Result<Option<StoredPendingQueuePublishIntent>, PendingQueuePublishStoreError> {
        let row = self.session.execute_unpaged(&self.read_intent, HeaderReadBinding { slot: slot.as_bytes().to_vec() }).await.map_err(cql)?
            .into_rows_result().map_err(cql)?.maybe_first_row::<IntentHeaderDbRow>().map_err(cql)?;
        row.map(|row| StoredPendingQueuePublishIntent::decode_persisted(slot, row.revision, &row.intent_payload).map_err(model_outbox)).transpose()
    }

    async fn read_prepared(
        &self,
        source_slot: PendingQueuePublishSourceSlot,
        intent_slot: PendingQueuePublishIntentSlot,
    ) -> Result<Option<StoredPendingQueuePublishIntent>, PendingQueuePublishStoreError> {
        let binding = PreparedReadBinding {
            source_slot: source_slot.as_bytes().to_vec(),
            intent_slot: intent_slot.as_bytes().to_vec(),
        };
        let row = self
            .session
            .execute_unpaged(&self.read_prepared, binding)
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<PreparedDbRow>()
            .map_err(cql)?;
        row.map(|row| {
            let decoded = StoredPendingQueuePublishIntent::decode_persisted(
                intent_slot,
                row.revision,
                &row.prepared_payload,
            )
            .map_err(model_outbox)?;
            if decoded.source_slot() != source_slot
                || !matches!(
                    decoded.phase(),
                    PendingQueuePublishIntentPhase::Materialized
                )
            {
                return Err(PendingQueuePublishStoreError::PreparedDescriptorMismatch);
            }
            Ok(decoded)
        })
        .transpose()
    }

    async fn bootstrap_bound_intent(
        &self,
        candidate: &StoredPendingQueuePublishIntent,
    ) -> Result<StoredPendingQueuePublishIntent, PendingQueuePublishStoreError> {
        if !matches!(candidate.phase(), PendingQueuePublishIntentPhase::Bound(_)) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        let binding = HeaderBootstrapBinding {
            slot: candidate.slot().as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            payload: candidate.to_persisted_bytes(),
        };
        let execution = self
            .session
            .execute_unpaged(&self.bootstrap_intent, binding)
            .await;
        self.finish_intent_write(execution, candidate).await
    }

    async fn cas_source_state(&self, expected: &PendingQueuePublishSourceState, candidate: &PendingQueuePublishSourceState) -> Result<PendingQueuePublishSourceState, PendingQueuePublishStoreError> {
        if expected.slot().map_err(model_envelope)? != candidate.slot().map_err(model_envelope)?
            || candidate.revision().get() != expected.revision().get().checked_add(1).ok_or(PendingQueuePublishStoreError::RevisionOverflow)?
        { return Err(PendingQueuePublishStoreError::InvalidTransition); }
        let binding = HeaderCasBinding {
            candidate_revision: candidate.revision().as_i64(), candidate_payload: candidate.to_persisted_bytes(),
            slot: expected.slot().map_err(model_envelope)?.as_bytes().to_vec(),
            expected_revision: expected.revision().as_i64(), expected_payload: expected.to_persisted_bytes(),
        };
        let execution = self.session.execute_unpaged(&self.cas_source, binding).await;
        self.finish_source_write(execution, candidate).await
    }

    async fn cas_intent_state(&self, expected: &StoredPendingQueuePublishIntent, candidate: &StoredPendingQueuePublishIntent) -> Result<StoredPendingQueuePublishIntent, PendingQueuePublishStoreError> {
        if expected.slot() != candidate.slot()
            || candidate.revision().get() != expected.revision().get().checked_add(1).ok_or(PendingQueuePublishStoreError::RevisionOverflow)?
        { return Err(PendingQueuePublishStoreError::InvalidTransition); }
        let binding = HeaderCasBinding {
            candidate_revision: candidate.revision().as_i64(), candidate_payload: candidate.to_persisted_bytes(),
            slot: expected.slot().as_bytes().to_vec(), expected_revision: expected.revision().as_i64(), expected_payload: expected.to_persisted_bytes(),
        };
        let execution = self.session.execute_unpaged(&self.cas_intent, binding).await;
        self.finish_intent_write(execution, candidate).await
    }

    async fn cancel_unpublished_source_selection(
        &self,
        selected: &PendingQueuePublishSourceState,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<(), PendingQueuePublishStoreError> {
        let plan = selected
            .cancel_unpublished_selection(envelope)
            .map_err(model_envelope)?;
        match self
            .cas_source_state(plan.expected(), plan.candidate())
            .await
        {
            Ok(_) => Ok(()),
            Err(PendingQueuePublishStoreError::CasConflict) => {
                let slot = selected.slot().map_err(model_envelope)?;
                let current = self
                    .read_source(slot)
                    .await?
                    .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?;
                if current.inflight_matches(envelope) {
                    Err(PendingQueuePublishStoreError::CasConflict)
                } else {
                    Ok(())
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn apply_intent_plan(&self, plan: PendingQueueIntentTransitionPlan) -> Result<StoredPendingQueuePublishIntent, PendingQueuePublishStoreError> {
        match plan {
            PendingQueueIntentTransitionPlan::Idempotent(current) => Ok(current),
            PendingQueueIntentTransitionPlan::Advance { expected, candidate } => self.cas_intent_state(&expected, &candidate).await,
        }
    }

    async fn finish_source_write(&self, execution: Result<QueryResult, scylla::errors::ExecutionError>, candidate: &PendingQueuePublishSourceState) -> Result<PendingQueuePublishSourceState, PendingQueuePublishStoreError> {
        let slot = candidate.slot().map_err(model_envelope)?;
        match execution {
            Ok(result) => {
                let applied = decode_applied(result)?;
                let current = self.read_source(slot).await?.ok_or(PendingQueuePublishStoreError::MissingAfterLwt)?;
                classify_exact(applied, candidate, current)
            }
            Err(execute) => match self.read_source(slot).await {
                Ok(Some(current)) if current == *candidate => Ok(current),
                Ok(_) => Err(PendingQueuePublishStoreError::Indeterminate(execute.to_string())),
                Err(read) => Err(PendingQueuePublishStoreError::IndeterminateRead { execute: execute.to_string(), read: read.to_string() }),
            },
        }
    }

    async fn finish_intent_write(&self, execution: Result<QueryResult, scylla::errors::ExecutionError>, candidate: &StoredPendingQueuePublishIntent) -> Result<StoredPendingQueuePublishIntent, PendingQueuePublishStoreError> {
        match execution {
            Ok(result) => {
                let applied = decode_applied(result)?;
                let current = self.read_intent(candidate.slot()).await?.ok_or(PendingQueuePublishStoreError::MissingAfterLwt)?;
                classify_exact(applied, candidate, current)
            }
            Err(execute) => match self.read_intent(candidate.slot()).await {
                Ok(Some(current)) if current == *candidate => Ok(current),
                Ok(_) => Err(PendingQueuePublishStoreError::Indeterminate(execute.to_string())),
                Err(read) => Err(PendingQueuePublishStoreError::IndeterminateRead { execute: execute.to_string(), read: read.to_string() }),
            },
        }
    }

    async fn persist_and_readback_fragment(&self, slot: PendingQueuePublishIntentSlot, fragment: &PendingQueuePayloadFragment) -> Result<(), PendingQueuePublishStoreError> {
        let binding = FragmentPutBinding::try_new(slot, fragment)?;
        let execution = self.session.execute_unpaged(&self.put_fragment, binding).await;
        if let Err(execute) = execution {
            return match self.read_exact_fragment(slot, fragment).await {
                Ok(Some(current)) if current == *fragment => Ok(()),
                Ok(_) => Err(PendingQueuePublishStoreError::IndeterminateFragment(execute.to_string())),
                Err(read) => Err(PendingQueuePublishStoreError::IndeterminateRead { execute: execute.to_string(), read: read.to_string() }),
            };
        }
        match self.read_exact_fragment(slot, fragment).await? {
            Some(current) if current == *fragment => Ok(()),
            Some(_) => Err(PendingQueuePublishStoreError::FragmentMismatch),
            None => Err(PendingQueuePublishStoreError::FragmentMissing),
        }
    }

    async fn persist_and_readback_prepared(
        &self,
        candidate: &StoredPendingQueuePublishIntent,
    ) -> Result<(), PendingQueuePublishStoreError> {
        if !matches!(candidate.phase(), PendingQueuePublishIntentPhase::Materialized) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        let binding = PreparedBootstrapBinding {
            source_slot: candidate.source_slot().as_bytes().to_vec(),
            intent_slot: candidate.slot().as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            payload: candidate.to_persisted_bytes(),
        };
        let execution = self
            .session
            .execute_unpaged(&self.bootstrap_prepared, binding)
            .await;
        match execution {
            Ok(result) => {
                let applied = decode_applied(result)?;
                let current = self
                    .read_prepared(candidate.source_slot(), candidate.slot())
                    .await?
                    .ok_or(PendingQueuePublishStoreError::MissingAfterLwt)?;
                classify_exact(applied, candidate, current).map(|_| ())
            }
            Err(execute) => match self
                .read_prepared(candidate.source_slot(), candidate.slot())
                .await
            {
                Ok(Some(current)) if current == *candidate => Ok(()),
                Ok(_) => Err(PendingQueuePublishStoreError::Indeterminate(
                    execute.to_string(),
                )),
                Err(read) => Err(PendingQueuePublishStoreError::IndeterminateRead {
                    execute: execute.to_string(),
                    read: read.to_string(),
                }),
            },
        }
    }

    async fn read_exact_fragment(&self, slot: PendingQueuePublishIntentSlot, expected: &PendingQueuePayloadFragment) -> Result<Option<PendingQueuePayloadFragment>, PendingQueuePublishStoreError> {
        let binding = FragmentReadBinding {
            intent_slot: slot.as_bytes().to_vec(), payload_digest: expected.payload_digest().as_bytes().to_vec(),
            fragment_bucket: i64::from(expected.fragment_bucket()),
            fragment_index: i16::try_from(expected.fragment_index()).map_err(|_| PendingQueuePublishStoreError::CoordinateOutOfRange)?,
        };
        let row = self.session.execute_unpaged(&self.read_fragment, binding).await.map_err(cql)?
            .into_rows_result().map_err(cql)?.maybe_first_row::<FragmentDbRow>().map_err(cql)?;
        row.map(decode_fragment_row).transpose()
    }

    async fn require_exact_fragment_set(&self, intent: &StoredPendingQueuePublishIntent) -> Result<(), PendingQueuePublishStoreError> {
        if intent.fragment_count() == 0 { return Ok(()); }
        let bucket_count = intent.fragment_count().div_ceil(RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS_PER_BUCKET);
        let mut observed = Vec::new();
        for bucket in 0..bucket_count {
            let binding = FragmentBucketReadBinding {
                intent_slot: intent.slot().as_bytes().to_vec(), payload_digest: intent.payload_digest().as_bytes().to_vec(), fragment_bucket: i64::from(bucket),
            };
            let result = self.session.execute_unpaged(&self.read_fragment_bucket, binding).await.map_err(cql)?;
            let rows_result = result.into_rows_result().map_err(cql)?;
            let rows = rows_result.rows::<FragmentMetadataDbRow>().map_err(cql)?;
            for row in rows { let row = row.map_err(cql)?; observed.push((row.fragment_index, row.fragment_digest)); }
        }
        observed.sort_by_key(|row| row.0);
        if observed.len() != intent.fragment_count() as usize
            || observed.iter().enumerate().any(|(index, row)| row.0 != index as i16 || row.1.len() != 32)
        { return Err(PendingQueuePublishStoreError::FragmentSetMismatch); }
        Ok(())
    }

    async fn load_payload(&self, intent: &StoredPendingQueuePublishIntent) -> Result<Vec<u8>, PendingQueuePublishStoreError> {
        if intent.request_kind() == PendingQueuePublishRequestKind::Seal { return Ok(Vec::new()); }
        self.require_exact_fragment_set(intent).await?;
        let mut fragments = Vec::with_capacity(intent.fragment_count() as usize);
        for index in 0..intent.fragment_count() {
            let fragment = self.read_fragment_by_coordinate(intent, index).await?
                .ok_or(PendingQueuePublishStoreError::FragmentMissing)?;
            if fragment.fragment_index() != index {
                return Err(PendingQueuePublishStoreError::FragmentMismatch);
            }
            fragments.push(fragment);
        }
        reconstruct_payload(intent, fragments).map_err(model_outbox)
    }

    async fn read_fragment_by_coordinate(&self, intent: &StoredPendingQueuePublishIntent, index: u16) -> Result<Option<PendingQueuePayloadFragment>, PendingQueuePublishStoreError> {
        let binding = FragmentReadBinding {
            intent_slot: intent.slot().as_bytes().to_vec(), payload_digest: intent.payload_digest().as_bytes().to_vec(),
            fragment_bucket: i64::from(index / RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS_PER_BUCKET),
            fragment_index: i16::try_from(index).map_err(|_| PendingQueuePublishStoreError::CoordinateOutOfRange)?,
        };
        let row = self.session.execute_unpaged(&self.read_fragment, binding).await.map_err(cql)?
            .into_rows_result().map_err(cql)?.maybe_first_row::<FragmentDbRow>().map_err(cql)?;
        row.map(decode_fragment_row).transpose()
    }
}

fn decode_fragment_row(row: FragmentDbRow) -> Result<PendingQueuePayloadFragment, PendingQueuePublishStoreError> {
    if row.payload_digest.len() != 32 || row.fragment_digest.len() != 32 || row.fragment_bucket < 0 {
        return Err(PendingQueuePublishStoreError::FragmentMismatch);
    }
    let fragment = PendingQueuePayloadFragment::decode_observed(
        row.payload_digest.try_into().unwrap(), row.fragment_index,
        row.fragment_count, row.payload_bytes, row.payload,
        row.fragment_digest.try_into().unwrap(),
    ).map_err(model_outbox)?;
    if i64::from(fragment.fragment_bucket()) != row.fragment_bucket {
        return Err(PendingQueuePublishStoreError::FragmentMismatch);
    }
    Ok(fragment)
}

fn classify_exact<T: Eq>(applied: bool, candidate: &T, current: T) -> Result<T, PendingQueuePublishStoreError> {
    if &current == candidate { Ok(current) }
    else if applied { Err(PendingQueuePublishStoreError::AppliedStateMismatch) }
    else { Err(PendingQueuePublishStoreError::CasConflict) }
}

fn store_fingerprint(
    keyspaces: &PendingQueuePublishKeyspaces,
    segment: &RecoverableNatsStreamSegment,
    queries: &PendingQueuePublishQueries,
) -> PendingQueuePublishStoreFingerprint {
    let mut hasher = Sha256::new();
    for part in [
        STORE_FINGERPRINT_DOMAIN,
        keyspaces.control().as_str().as_bytes(),
        keyspaces.data().as_str().as_bytes(),
        segment.digest().as_bytes(),
        queries.render_golden().as_bytes(),
    ] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    PendingQueuePublishStoreFingerprint(hasher.finalize().into())
}

async fn prepare_regular(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueuePublishStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: &str) -> Result<PreparedStatement, PendingQueuePublishStoreError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueuePublishStoreError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]").ok_or(PendingQueuePublishStoreError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueuePublishStoreError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueuePublishStoreError { PendingQueuePublishStoreError::Cql(error.to_string()) }
fn model_outbox(error: PendingQueueOutboxError) -> PendingQueuePublishStoreError { PendingQueuePublishStoreError::Model(error.to_string()) }
fn model_envelope(error: PendingQueueEnvelopeError) -> PendingQueuePublishStoreError { PendingQueuePublishStoreError::Model(error.to_string()) }
fn nats_transport(error: RecoverableNatsTransportError) -> PendingQueuePublishStoreError {
    PendingQueuePublishStoreError::Nats(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueuePublishStoreError {
    Cql(String),
    Nats(String),
    Model(String),
    Pipeline(String),
    InvalidKeyspace(String),
    DataKeyspaceMustUseTablets(String),
    AssignmentMismatch,
    CloseContextMismatch,
    CloseIntentMismatch,
    SourceUninitialized,
    SourceNotSealed,
    IntentUninitialized,
    IntentConflict,
    IntentBoundElsewhere,
    IntentPhaseMismatch,
    SourceSelectionMismatch,
    SourceCommitMismatch,
    PermitStoreMismatch,
    PermitStateMismatch,
    InvalidTransition,
    RevisionOverflow,
    CoordinateOutOfRange,
    MissingAfterLwt,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    AppliedStateMismatch,
    CasConflict,
    Indeterminate(String),
    IndeterminateRead { execute: String, read: String },
    IndeterminateFragment(String),
    FragmentMissing,
    FragmentMismatch,
    FragmentSetMismatch,
    PayloadMismatch,
    PreparedDescriptorMismatch,
}

impl fmt::Display for PendingQueuePublishStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}

impl Error for PendingQueuePublishStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_separate_small_lwt_headers_from_immutable_fragments() {
        let keyspaces = PendingQueuePublishKeyspaces::new(
            BranchExactDeploymentNoTabletKeyspace::try_new("psy_control_nt").unwrap(),
            PendingQueuePublishDataKeyspace::try_new("psy_data").unwrap(),
        );
        let queries = PendingQueuePublishQueries::new(&keyspaces);
        assert_eq!(queries.all().len(), 15);
        let golden = queries.render_golden();
        assert!(golden.contains("psy_control_nt.branch_exact_pending_queue_publish_source_v1"));
        assert!(golden.contains("psy_control_nt.branch_exact_pending_queue_publish_intent_v1"));
        assert!(golden.contains("psy_control_nt.branch_exact_pending_queue_publish_prepared_v1"));
        assert!(golden.contains("psy_data.branch_exact_pending_queue_publish_payload_fragment_v1"));
        assert_eq!(golden.matches("VALUES (?, ?, ?) IF NOT EXISTS").count(), 2);
        assert_eq!(golden.matches("IF revision = ? AND").count(), 2);
        assert_eq!(
            golden
                .matches("VALUES (?, ?, ?, ?) IF NOT EXISTS")
                .count(),
            1
        );
        assert!(!golden.contains("ALLOW FILTERING"));
        assert!(!golden.contains(" TTL "));
        assert!(!golden.contains(" BATCH "));
        assert_eq!(
            queries.get(PendingQueuePublishQueryId::PutFragment).bind_shape(),
            FRAGMENT_PUT,
        );
        assert_eq!(
            queries.get(PendingQueuePublishQueryId::CasSource).bind_shape(),
            HEADER_CAS,
        );
        assert!(PendingQueuePublishDataKeyspace::try_new("bad_nt").is_err());
    }

    #[test]
    fn nats_transport_is_confined_to_psy_node_nats() {
        let source = include_str!("pending_queue_publish_store.rs");
        assert!(!source.contains(concat!("jetstream", "::Context")));
        assert!(!source.contains(concat!("send_", "publish(")));
        assert!(!source.contains(concat!("get_last_raw_message", "_by_subject")));
    }

    #[test]
    fn exact_lwt_classifier_never_accepts_applied_mismatch() {
        assert_eq!(classify_exact(true, &7_u64, 7).unwrap(), 7);
        assert_eq!(classify_exact(false, &7_u64, 7).unwrap(), 7);
        assert_eq!(classify_exact(true, &7_u64, 8), Err(PendingQueuePublishStoreError::AppliedStateMismatch));
        assert_eq!(classify_exact(false, &7_u64, 8), Err(PendingQueuePublishStoreError::CasConflict));
    }

    #[test]
    fn commit_pending_fixture_reuses_the_private_production_boundary() {
        let source = include_str!("pending_queue_publish_store.rs");
        let publish = source
            .find("pub async fn publish_and_commit")
            .expect("production publish method");
        let observer = source[publish..]
            .find("pub(crate) async fn observe_committed_data")
            .map(|offset| publish + offset)
            .expect("historical observer");
        let production = &source[publish..observer];
        let persist = production
            .find("persist_through_source_commit_pending")
            .expect("persist durable boundary");
        let finalize = production
            .find("finalize_source_commit")
            .expect("finalize durable boundary");
        assert!(persist < finalize);

        let fixture = source
            .find("pub(crate) async fn publish_through_commit_pending_fixture")
            .expect("test-only durable stop");
        let cfg_test = source[..fixture]
            .rfind("#[cfg(test)]")
            .expect("fixture must be cfg(test)");
        assert!(fixture - cfg_test < 1_000);
        let fixture_body = &source[fixture..observer];
        assert!(fixture_body.contains("persist_through_source_commit_pending"));
        assert!(fixture_body.contains("PendingQueuePublishSourcePhase::CommitPending"));
        assert!(fixture_body.contains("PendingQueuePublishIntentPhase::NatsAccepted"));
        assert!(!fixture_body.contains("finalize_source_commit"));

        for forbidden in ["std::env", "DriveMode", "fault_flag", "set_phase"] {
            assert!(
                !production.contains(forbidden),
                "production durable path contains forbidden seam {forbidden}"
            );
        }
    }
}
