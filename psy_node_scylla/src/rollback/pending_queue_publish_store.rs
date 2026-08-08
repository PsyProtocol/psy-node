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
    PendingQueueSegmentAssignmentReceipt,
};

pub const PENDING_QUEUE_PUBLISH_SOURCE_TABLE: &str =
    "branch_exact_pending_queue_publish_source_v1";
pub const PENDING_QUEUE_PUBLISH_INTENT_TABLE: &str =
    "branch_exact_pending_queue_publish_intent_v1";
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
    queries: [PendingQueuePublishQuery; 12],
}

impl PendingQueuePublishQueries {
    pub fn new(keyspaces: &PendingQueuePublishKeyspaces) -> Self {
        let source = format!("{}.{}", keyspaces.control().as_str(), PENDING_QUEUE_PUBLISH_SOURCE_TABLE);
        let intent = format!("{}.{}", keyspaces.control().as_str(), PENDING_QUEUE_PUBLISH_INTENT_TABLE);
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
        ] }
    }

    pub fn get(&self, id: PendingQueuePublishQueryId) -> &PendingQueuePublishQuery {
        &self.queries[id as usize - 1]
    }

    pub fn all(&self) -> &[PendingQueuePublishQuery; 12] { &self.queries }

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
            put_fragment: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::PutFragment).cql()).await?,
            read_fragment: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadFragment).cql()).await?,
            read_fragment_bucket: prepare_regular(&session, queries.get(PendingQueuePublishQueryId::ReadFragmentBucket).cql()).await?,
            session, nats, segment, queries, fingerprint,
        })
    }

    pub const fn queries(&self) -> &PendingQueuePublishQueries { &self.queries }
    pub const fn fingerprint(&self) -> PendingQueuePublishStoreFingerprint { self.fingerprint }

    pub async fn bootstrap_source(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
    ) -> Result<PendingQueuePublishSourceState, PendingQueuePublishStoreError> {
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
        self.finish_source_write(execution, &candidate).await
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
        let binding = HeaderBootstrapBinding {
            slot: candidate.slot().as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            payload: candidate.to_persisted_bytes(),
        };
        let execution = self.session.execute_unpaged(&self.bootstrap_intent, binding).await;
        let current = self.finish_intent_write(execution, &candidate).await?;
        if current != candidate {
            return Err(PendingQueuePublishStoreError::IntentConflict);
        }
        Ok(candidate.slot())
    }

    pub(crate) async fn materialize_seal(
        &self,
        assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
        publisher_kind: PendingQueuePublisherKind,
        intent_id: PendingQueuePublishIntentId,
    ) -> Result<PendingQueuePublishIntentSlot, PendingQueuePublishStoreError> {
        let source = self.require_source(assignment_receipt, publisher_kind).await?;
        let candidate = StoredPendingQueuePublishIntent::materialize_seal(&source, intent_id)
            .map_err(model_outbox)?;
        let binding = HeaderBootstrapBinding {
            slot: candidate.slot().as_bytes().to_vec(),
            revision: candidate.revision().as_i64(),
            payload: candidate.to_persisted_bytes(),
        };
        let execution = self.session.execute_unpaged(&self.bootstrap_intent, binding).await;
        let current = self.finish_intent_write(execution, &candidate).await?;
        if current != candidate { return Err(PendingQueuePublishStoreError::IntentConflict); }
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
        let mut intent = self.read_intent(intent_slot).await?
            .ok_or(PendingQueuePublishStoreError::IntentUninitialized)?;
        if intent.publisher_kind() != publisher_kind || intent.assignment_digest() != assignment.digest() {
            return Err(PendingQueuePublishStoreError::AssignmentMismatch);
        }
        let payload = self.load_payload(&intent).await?;
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), publisher_kind, &self.segment,
        ).map_err(model_envelope)?;
        let mut source = self.read_source(intent.source_slot()).await?
            .ok_or(PendingQueuePublishStoreError::SourceUninitialized)?;
        let envelope = self.build_envelope(&route, assignment, &source, &intent, payload.clone())?;
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
            if let Some((expected, candidate)) = intent_plan.transition() {
                intent = self.cas_intent_state(expected, candidate).await?;
            }
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
        if matches!(intent.phase(), PendingQueuePublishIntentPhase::NatsAccepted { .. }) {
            let plan = intent.record_source_committed().map_err(model_outbox)?;
            intent = self.apply_intent_plan(plan).await?;
        }
        if !matches!(intent.phase(), PendingQueuePublishIntentPhase::SourceCommitted { .. }) {
            return Err(PendingQueuePublishStoreError::IntentPhaseMismatch);
        }
        if matches!(source.phase(), PendingQueuePublishSourcePhase::CommitPending { .. }) {
            let plan = source.finalize_published().map_err(model_envelope)?;
            source = self.cas_source_state(plan.expected(), plan.candidate()).await?;
        }
        if source.last_subject_sequence() != subject_sequence
            || source.last_envelope_digest() != *permit.envelope.digest().as_bytes()
        {
            return Err(PendingQueuePublishStoreError::SourceCommitMismatch);
        }
        let _ = payload;
        Ok(PendingQueuePublishCommitReceipt {
            intent_slot: permit.intent_slot,
            subject_sequence,
            envelope_digest: *permit.envelope.digest().as_bytes(),
            disposition,
        })
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
                source.seal_summary().map_err(model_envelope)?,
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
    InvalidKeyspace(String),
    DataKeyspaceMustUseTablets(String),
    AssignmentMismatch,
    SourceUninitialized,
    IntentUninitialized,
    IntentConflict,
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
        assert_eq!(queries.all().len(), 12);
        let golden = queries.render_golden();
        assert!(golden.contains("psy_control_nt.branch_exact_pending_queue_publish_source_v1"));
        assert!(golden.contains("psy_control_nt.branch_exact_pending_queue_publish_intent_v1"));
        assert!(golden.contains("psy_data.branch_exact_pending_queue_publish_payload_fragment_v1"));
        assert_eq!(golden.matches("VALUES (?, ?, ?) IF NOT EXISTS").count(), 2);
        assert_eq!(golden.matches("IF revision = ? AND").count(), 2);
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
}
