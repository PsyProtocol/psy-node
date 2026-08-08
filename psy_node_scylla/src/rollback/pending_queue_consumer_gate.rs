//! Default-off durable mutation gate for recoverable JetStream consumers.
//!
//! One exact stream incarnation owns one full-payload LWT row. Provisioning is
//! registered before JetStream is mutated, completion records the exact
//! server-created consumer incarnation, and sealing can close the gate only
//! when the complete expected consumer set is provisioned. A closed gate has
//! no transition back to open.

#![allow(dead_code)]

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
    sync::Arc,
};

use psy_node_nats::{
    queue::NatsJetStreamClient,
    recoverable_segment::{
        LiveRecoverableNatsStreamInstance, RecoverableNatsSegmentContractDigest,
        RecoverableNatsSegmentId, RecoverableNatsStreamInstanceId,
        RecoverableNatsStreamSegment,
    },
    recoverable_transport::{
        RecoverableNatsCaptureSpec, RecoverableNatsConsumerInstanceId,
        RecoverableNatsConsumerProvisioningOperationId,
        RecoverableNatsExistingConsumerBinding, RecoverableNatsExpectedStreamMode,
        RecoverableNatsProvisionedConsumerExpectation,
        RecoverableNatsProvisionedConsumerReceipt,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{prepared::PreparedStatement, Consistency, SerialConsistency},
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::BranchExactDeploymentNoTabletKeyspace;

pub(super) const PENDING_QUEUE_CONSUMER_GATE_TABLE: &str =
    "branch_exact_pending_queue_consumer_gate_v1";
const MAGIC: &[u8; 8] = b"PSYQCGAT";
const CODEC_VERSION: u16 = 1;
const SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-consumer-gate-slot/v1";
const DIGEST_DOMAIN: &[u8] = b"psy/rollback/pending-queue-consumer-gate/v1";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-consumer-gate-store/v1";
const MAX_SUBJECT_BYTES: usize = 512;
const MAX_CONSUMERS: usize = 4096;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_CAS_RETRIES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueConsumerGateStoreFingerprint([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueConsumerGateSlot([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct PendingQueueConsumerGateDigest([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PendingQueueConsumerGatePhase {
    Open = 1,
    Closed = 2,
}

impl PendingQueueConsumerGatePhase {
    fn try_from_byte(value: u8) -> Result<Self, PendingQueueConsumerGateError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Closed),
            _ => Err(PendingQueueConsumerGateError::UnknownPhase),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueConsumerGateIdentity {
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    stream_instance_id: RecoverableNatsStreamInstanceId,
}

impl PendingQueueConsumerGateIdentity {
    pub(super) const fn new(
        segment_id: RecoverableNatsSegmentId,
        contract_digest: RecoverableNatsSegmentContractDigest,
        stream_instance_id: RecoverableNatsStreamInstanceId,
    ) -> Self {
        Self {
            segment_id,
            contract_digest,
            stream_instance_id,
        }
    }

    fn slot(self) -> PendingQueueConsumerGateSlot {
        let mut hasher = Sha256::new();
        hasher.update(SLOT_DOMAIN);
        hasher.update(self.segment_id.get().to_be_bytes());
        hasher.update(self.contract_digest.as_bytes());
        hasher.update(self.stream_instance_id.as_bytes());
        PendingQueueConsumerGateSlot(hasher.finalize().into())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct PendingQueueExpectedConsumer {
    subject: String,
    consumer_digest: [u8; 32],
}

impl PendingQueueExpectedConsumer {
    pub(super) fn try_new(
        subject: impl Into<String>,
        consumer_digest: [u8; 32],
    ) -> Result<Self, PendingQueueConsumerGateError> {
        let subject = subject.into();
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || consumer_digest == [0; 32]
        {
            return Err(PendingQueueConsumerGateError::InvalidConsumer);
        }
        Ok(Self {
            subject,
            consumer_digest,
        })
    }

    pub(super) fn subject(&self) -> &str {
        &self.subject
    }

    pub(super) const fn consumer_digest(&self) -> &[u8; 32] {
        &self.consumer_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum PendingQueueConsumerGateEntry {
    Provisioning {
        consumer_digest: [u8; 32],
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    },
    Provisioned {
        consumer_digest: [u8; 32],
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
        consumer_instance_id: RecoverableNatsConsumerInstanceId,
    },
}

impl PendingQueueConsumerGateEntry {
    const fn consumer_digest(&self) -> &[u8; 32] {
        match self {
            Self::Provisioning { consumer_digest, .. }
            | Self::Provisioned { consumer_digest, .. } => consumer_digest,
        }
    }

    const fn operation_id(&self) -> RecoverableNatsConsumerProvisioningOperationId {
        match self {
            Self::Provisioning { operation_id, .. }
            | Self::Provisioned { operation_id, .. } => *operation_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StoredPendingQueueConsumerGate {
    slot: PendingQueueConsumerGateSlot,
    revision: u64,
    phase: PendingQueueConsumerGatePhase,
    identity: PendingQueueConsumerGateIdentity,
    entries: BTreeMap<String, PendingQueueConsumerGateEntry>,
    digest: PendingQueueConsumerGateDigest,
}

impl StoredPendingQueueConsumerGate {
    fn open(identity: PendingQueueConsumerGateIdentity) -> Self {
        let mut value = Self {
            slot: identity.slot(),
            revision: 0,
            phase: PendingQueueConsumerGatePhase::Open,
            identity,
            entries: BTreeMap::new(),
            digest: PendingQueueConsumerGateDigest([0; 32]),
        };
        value.digest = value.calculate_digest();
        value
    }

    fn begin(
        &self,
        expected: &PendingQueueExpectedConsumer,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    ) -> Result<Self, PendingQueueConsumerGateError> {
        if self.phase != PendingQueueConsumerGatePhase::Open {
            return Err(PendingQueueConsumerGateError::GateClosed);
        }
        if let Some(current) = self.entries.get(expected.subject()) {
            return match current {
                PendingQueueConsumerGateEntry::Provisioning { .. }
                    if current.consumer_digest() == expected.consumer_digest()
                        && current.operation_id() == operation_id =>
                {
                    Ok(self.clone())
                }
                PendingQueueConsumerGateEntry::Provisioned { .. }
                    if current.consumer_digest() == expected.consumer_digest()
                        && current.operation_id() == operation_id =>
                {
                    Err(PendingQueueConsumerGateError::ProvisioningAlreadyComplete)
                }
                _ => Err(PendingQueueConsumerGateError::ConsumerConflict),
            };
        }
        if self
            .entries
            .iter()
            .any(|(subject, entry)| subject != expected.subject() && entry.operation_id() == operation_id)
        {
            return Err(PendingQueueConsumerGateError::OperationReused);
        }
        if self.entries.len() >= MAX_CONSUMERS {
            return Err(PendingQueueConsumerGateError::TooManyConsumers);
        }
        let mut candidate = self.clone();
        candidate.revision = next_revision(candidate.revision)?;
        candidate.entries.insert(
            expected.subject.clone(),
            PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest: expected.consumer_digest,
                operation_id,
            },
        );
        candidate.digest = candidate.calculate_digest();
        Ok(candidate)
    }

    fn complete(
        &self,
        subject: &str,
        consumer_digest: [u8; 32],
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
        consumer_instance_id: RecoverableNatsConsumerInstanceId,
    ) -> Result<Self, PendingQueueConsumerGateError> {
        if self.phase != PendingQueueConsumerGatePhase::Open {
            return Err(PendingQueueConsumerGateError::GateClosed);
        }
        let current = self
            .entries
            .get(subject)
            .ok_or(PendingQueueConsumerGateError::ProvisioningNotFound)?;
        match current {
            PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest: current_digest,
                operation_id: current_operation,
                consumer_instance_id: current_instance,
            } if *current_digest == consumer_digest
                && *current_operation == operation_id
                && *current_instance == consumer_instance_id => return Ok(self.clone()),
            PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest: current_digest,
                operation_id: current_operation,
            } if *current_digest == consumer_digest && *current_operation == operation_id => {}
            _ => return Err(PendingQueueConsumerGateError::ProvisioningMismatch),
        }
        let mut candidate = self.clone();
        if candidate.entries.iter().any(|(other_subject, entry)| {
            other_subject != subject
                && matches!(
                    entry,
                    PendingQueueConsumerGateEntry::Provisioned {
                        consumer_instance_id: current,
                        ..
                    } if *current == consumer_instance_id
                )
        }) {
            return Err(PendingQueueConsumerGateError::ConsumerInstanceReused);
        }
        candidate.revision = next_revision(candidate.revision)?;
        candidate.entries.insert(
            subject.to_owned(),
            PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest,
                operation_id,
                consumer_instance_id,
            },
        );
        candidate.digest = candidate.calculate_digest();
        Ok(candidate)
    }

    fn close(
        &self,
        expected: &[PendingQueueExpectedConsumer],
    ) -> Result<Self, PendingQueueConsumerGateError> {
        if self.phase == PendingQueueConsumerGatePhase::Closed {
            return if self.matches_expected(expected) {
                Ok(self.clone())
            } else {
                Err(PendingQueueConsumerGateError::ExpectedSetMismatch)
            };
        }
        if !self.matches_expected(expected) {
            return Err(PendingQueueConsumerGateError::ExpectedSetMismatch);
        }
        let mut candidate = self.clone();
        candidate.revision = next_revision(candidate.revision)?;
        candidate.phase = PendingQueueConsumerGatePhase::Closed;
        candidate.digest = candidate.calculate_digest();
        Ok(candidate)
    }

    fn matches_expected(&self, expected: &[PendingQueueExpectedConsumer]) -> bool {
        if expected.len() != self.entries.len() || expected.len() > MAX_CONSUMERS {
            return false;
        }
        let mut prior = None;
        for item in expected {
            if prior.is_some_and(|value: &str| value >= item.subject()) {
                return false;
            }
            prior = Some(item.subject());
            match self.entries.get(item.subject()) {
                Some(PendingQueueConsumerGateEntry::Provisioned {
                    consumer_digest, ..
                }) if consumer_digest == item.consumer_digest() => {}
                _ => return false,
            }
        }
        true
    }

    fn calculate_digest(&self) -> PendingQueueConsumerGateDigest {
        let mut hasher = Sha256::new();
        hasher.update(DIGEST_DOMAIN);
        hasher.update(self.bytes_without_digest());
        PendingQueueConsumerGateDigest(hasher.finalize().into())
    }

    fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bytes_without_digest();
        bytes.extend_from_slice(&self.digest.0);
        bytes
    }

    fn bytes_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.entries.len() * 128);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.push(self.phase as u8);
        out.extend_from_slice(&self.identity.segment_id.get().to_be_bytes());
        out.extend_from_slice(self.identity.contract_digest.as_bytes());
        out.extend_from_slice(self.identity.stream_instance_id.as_bytes());
        out.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for (subject, entry) in &self.entries {
            out.extend_from_slice(&(subject.len() as u16).to_be_bytes());
            out.extend_from_slice(subject.as_bytes());
            match entry {
                PendingQueueConsumerGateEntry::Provisioning {
                    consumer_digest,
                    operation_id,
                } => {
                    out.push(1);
                    out.extend_from_slice(consumer_digest);
                    out.extend_from_slice(operation_id.as_bytes());
                }
                PendingQueueConsumerGateEntry::Provisioned {
                    consumer_digest,
                    operation_id,
                    consumer_instance_id,
                } => {
                    out.push(2);
                    out.extend_from_slice(consumer_digest);
                    out.extend_from_slice(operation_id.as_bytes());
                    out.extend_from_slice(consumer_instance_id.as_bytes());
                }
            }
        }
        out
    }

    fn decode(
        slot: PendingQueueConsumerGateSlot,
        cql_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueConsumerGateError> {
        if bytes.len() > MAX_PAYLOAD_BYTES || cql_revision < 0 {
            return Err(PendingQueueConsumerGateError::MalformedPayload);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC || decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueConsumerGateError::MalformedPayload);
        }
        let revision = decoder.u64()?;
        if revision != cql_revision as u64 {
            return Err(PendingQueueConsumerGateError::RevisionMismatch);
        }
        let phase = PendingQueueConsumerGatePhase::try_from_byte(decoder.u8()?)?;
        let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?;
        let contract_digest = RecoverableNatsSegmentContractDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?;
        let stream_instance_id = RecoverableNatsStreamInstanceId::try_from_bytes(decoder.array32()?)
            .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?;
        let identity = PendingQueueConsumerGateIdentity::new(
            segment_id,
            contract_digest,
            stream_instance_id,
        );
        if identity.slot() != slot {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        let count = decoder.u32()? as usize;
        if count > MAX_CONSUMERS {
            return Err(PendingQueueConsumerGateError::TooManyConsumers);
        }
        let mut entries = BTreeMap::new();
        for _ in 0..count {
            let subject_len = decoder.u16()? as usize;
            if subject_len == 0 || subject_len > MAX_SUBJECT_BYTES {
                return Err(PendingQueueConsumerGateError::InvalidConsumer);
            }
            let subject = std::str::from_utf8(decoder.take(subject_len)?)
                .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?
                .to_owned();
            let kind = decoder.u8()?;
            let consumer_digest = decoder.array32()?;
            let operation_id = RecoverableNatsConsumerProvisioningOperationId::try_new(
                decoder.array32()?,
            )
            .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?;
            if consumer_digest == [0; 32] {
                return Err(PendingQueueConsumerGateError::InvalidConsumer);
            }
            let entry = match kind {
                1 => PendingQueueConsumerGateEntry::Provisioning {
                    consumer_digest,
                    operation_id,
                },
                2 => PendingQueueConsumerGateEntry::Provisioned {
                    consumer_digest,
                    operation_id,
                    consumer_instance_id: RecoverableNatsConsumerInstanceId::try_new(
                        decoder.array32()?,
                    )
                    .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)?,
                },
                _ => return Err(PendingQueueConsumerGateError::MalformedPayload),
            };
            if entries.insert(subject, entry).is_some() {
                return Err(PendingQueueConsumerGateError::DuplicateConsumer);
            }
        }
        let digest = PendingQueueConsumerGateDigest(decoder.array32()?);
        decoder.finish()?;
        let value = Self {
            slot,
            revision,
            phase,
            identity,
            entries,
            digest,
        };
        if digest.0 == [0; 32] || digest != value.calculate_digest() {
            return Err(PendingQueueConsumerGateError::DigestMismatch);
        }
        if phase == PendingQueueConsumerGatePhase::Closed
            && value.entries.values().any(|entry| {
                matches!(entry, PendingQueueConsumerGateEntry::Provisioning { .. })
            })
        {
            return Err(PendingQueueConsumerGateError::MalformedPayload);
        }
        let mut operations = HashSet::with_capacity(value.entries.len());
        let mut instances = HashSet::with_capacity(value.entries.len());
        let mut provisioned_count = 0_u64;
        for entry in value.entries.values() {
            if !operations.insert(entry.operation_id()) {
                return Err(PendingQueueConsumerGateError::OperationReused);
            }
            if let PendingQueueConsumerGateEntry::Provisioned {
                consumer_instance_id,
                ..
            } = entry
            {
                provisioned_count = provisioned_count
                    .checked_add(1)
                    .ok_or(PendingQueueConsumerGateError::RevisionOverflow)?;
                if !instances.insert(*consumer_instance_id) {
                    return Err(PendingQueueConsumerGateError::ConsumerInstanceReused);
                }
            }
        }
        let expected_revision = u64::try_from(value.entries.len())
            .map_err(|_| PendingQueueConsumerGateError::RevisionOverflow)?
            .checked_add(provisioned_count)
            .and_then(|revision| {
                revision.checked_add(if value.phase == PendingQueueConsumerGatePhase::Closed {
                    1
                } else {
                    0
                })
            })
            .ok_or(PendingQueueConsumerGateError::RevisionOverflow)?;
        if value.revision != expected_revision {
            return Err(PendingQueueConsumerGateError::RevisionMismatch);
        }
        Ok(value)
    }
}

pub(super) struct PersistedPendingQueueConsumerGateOpenReceipt {
    store_fingerprint: PendingQueueConsumerGateStoreFingerprint,
    current: StoredPendingQueueConsumerGate,
}

pub(super) struct PersistedPendingQueueConsumerProvisioningLease {
    store_fingerprint: PendingQueueConsumerGateStoreFingerprint,
    current: StoredPendingQueueConsumerGate,
    subject: String,
    consumer_digest: [u8; 32],
    operation_id: RecoverableNatsConsumerProvisioningOperationId,
}

pub(super) struct PersistedPendingQueueConsumerProvisionedReceipt {
    store_fingerprint: PendingQueueConsumerGateStoreFingerprint,
    current: StoredPendingQueueConsumerGate,
    subject: String,
    consumer_digest: [u8; 32],
    consumer_instance_id: RecoverableNatsConsumerInstanceId,
}

pub(super) enum PendingQueueConsumerProvisioningStart {
    Lease(PersistedPendingQueueConsumerProvisioningLease),
    AlreadyProvisioned(PersistedPendingQueueConsumerProvisionedReceipt),
}

pub(super) struct PersistedPendingQueueConsumerGateClosedReceipt {
    store_fingerprint: PendingQueueConsumerGateStoreFingerprint,
    current: StoredPendingQueueConsumerGate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueConsumerGateCommitment {
    slot: [u8; 32],
    revision: u64,
    digest: [u8; 32],
}

impl PendingQueueConsumerGateCommitment {
    pub(super) fn try_new(
        slot: [u8; 32],
        revision: u64,
        digest: [u8; 32],
    ) -> Result<Self, PendingQueueConsumerGateError> {
        if slot == [0; 32]
            || revision == 0
            || revision > i64::MAX as u64
            || digest == [0; 32]
        {
            return Err(PendingQueueConsumerGateError::ReceiptMismatch);
        }
        Ok(Self {
            slot,
            revision,
            digest,
        })
    }

    pub(super) const fn slot(&self) -> &[u8; 32] {
        &self.slot
    }

    pub(super) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(super) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl PersistedPendingQueueConsumerGateClosedReceipt {
    pub(super) const fn commitment(&self) -> PendingQueueConsumerGateCommitment {
        PendingQueueConsumerGateCommitment {
            slot: self.current.slot.0,
            revision: self.current.revision,
            digest: self.current.digest.0,
        }
    }

    pub(super) fn matches(
        &self,
        store: &ScyllaPendingQueueConsumerGateStore,
        identity: PendingQueueConsumerGateIdentity,
        expected: &[PendingQueueExpectedConsumer],
    ) -> bool {
        self.store_fingerprint == store.fingerprint
            && self.current.identity == identity
            && self.current.phase == PendingQueueConsumerGatePhase::Closed
            && self.current.matches_expected(expected)
    }
}

impl PersistedPendingQueueConsumerProvisionedReceipt {
    fn existing_binding(
        &self,
        spec: &RecoverableNatsCaptureSpec,
    ) -> Result<RecoverableNatsExistingConsumerBinding, PendingQueueConsumerGateError> {
        if self.subject != spec.subject()
            || self.consumer_digest != spec.consumer_digest()
        {
            return Err(PendingQueueConsumerGateError::ProvisioningReceiptMismatch);
        }
        let entry = self
            .current
            .entries
            .get(&self.subject)
            .ok_or(PendingQueueConsumerGateError::ProvisioningNotFound)?;
        let operation_id = match entry {
            PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest,
                operation_id,
                consumer_instance_id,
            } if *consumer_digest == self.consumer_digest
                && *consumer_instance_id == self.consumer_instance_id => *operation_id,
            _ => return Err(PendingQueueConsumerGateError::ProvisioningMismatch),
        };
        RecoverableNatsExistingConsumerBinding::try_from_durable(
            self.current.identity.stream_instance_id,
            spec,
            operation_id,
            self.consumer_instance_id,
        )
        .map_err(transport)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub(super) enum PendingQueueConsumerGateQueryId {
    Create = 1,
    Read = 2,
    Bootstrap = 3,
    CompareAndSet = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueConsumerGateQuery {
    id: PendingQueueConsumerGateQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
}

impl PendingQueueConsumerGateQuery {
    pub(super) const fn id(&self) -> PendingQueueConsumerGateQueryId {
        self.id
    }

    pub(super) fn cql(&self) -> &str {
        &self.cql
    }

    pub(super) const fn bind_shape(&self) -> &'static [&'static str] {
        self.bind_shape
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueConsumerGateQueries {
    queries: [PendingQueueConsumerGateQuery; 4],
}

impl PendingQueueConsumerGateQueries {
    pub(super) fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), PENDING_QUEUE_CONSUMER_GATE_TABLE);
        Self {
            queries: [
                gate_query(
                    PendingQueueConsumerGateQueryId::Create,
                    format!("CREATE TABLE IF NOT EXISTS {table} (gate_slot blob PRIMARY KEY, revision bigint, gate_payload blob)"),
                    &[],
                ),
                gate_query(
                    PendingQueueConsumerGateQueryId::Read,
                    format!("SELECT revision, gate_payload FROM {table} WHERE gate_slot = ?"),
                    &["gate_slot:BLOB"],
                ),
                gate_query(
                    PendingQueueConsumerGateQueryId::Bootstrap,
                    format!("INSERT INTO {table} (gate_slot, revision, gate_payload) VALUES (?, ?, ?) IF NOT EXISTS"),
                    &["gate_slot:BLOB", "revision:BIGINT", "gate_payload:BLOB"],
                ),
                gate_query(
                    PendingQueueConsumerGateQueryId::CompareAndSet,
                    format!("UPDATE {table} SET revision = ?, gate_payload = ? WHERE gate_slot = ? IF revision = ? AND gate_payload = ?"),
                    &[
                        "candidate_revision:BIGINT",
                        "candidate_payload:BLOB",
                        "gate_slot:BLOB",
                        "expected_revision:BIGINT",
                        "expected_payload:BLOB",
                    ],
                ),
            ],
        }
    }

    pub(super) fn get(
        &self,
        id: PendingQueueConsumerGateQueryId,
    ) -> &PendingQueueConsumerGateQuery {
        &self.queries[id as usize - 1]
    }

    fn render_golden(&self) -> String {
        self.queries
            .iter()
            .map(|query| {
                format!(
                    "{:?}|{}\n{}\n",
                    query.id,
                    query.bind_shape.join(","),
                    query.cql
                )
            })
            .collect()
    }
}

fn gate_query(
    id: PendingQueueConsumerGateQueryId,
    cql: String,
    bind_shape: &'static [&'static str],
) -> PendingQueueConsumerGateQuery {
    PendingQueueConsumerGateQuery {
        id,
        cql,
        bind_shape,
    }
}

pub(super) struct ScyllaPendingQueueConsumerGateStore {
    session: Arc<Session>,
    fingerprint: PendingQueueConsumerGateStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
    compare_and_set: PreparedStatement,
}

impl ScyllaPendingQueueConsumerGateStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueConsumerGateError> {
        let queries = PendingQueueConsumerGateQueries::new(keyspace);
        session
            .query_unpaged(
                queries
                    .get(PendingQueueConsumerGateQueryId::Create)
                    .cql(),
                &[],
            )
            .await
            .map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueConsumerGateError> {
        let queries = PendingQueueConsumerGateQueries::new(&keyspace);
        Ok(Self {
            fingerprint: store_fingerprint(&keyspace, &queries),
            read: prepare_read(
                &session,
                queries.get(PendingQueueConsumerGateQueryId::Read).cql(),
            )
            .await?,
            bootstrap: prepare_lwt(
                &session,
                queries
                    .get(PendingQueueConsumerGateQueryId::Bootstrap)
                    .cql(),
            )
            .await?,
            compare_and_set: prepare_lwt(
                &session,
                queries
                    .get(PendingQueueConsumerGateQueryId::CompareAndSet)
                    .cql(),
            )
            .await?,
            session,
        })
    }

    async fn read(
        &self,
        slot: PendingQueueConsumerGateSlot,
    ) -> Result<Option<StoredPendingQueueConsumerGate>, PendingQueueConsumerGateError> {
        let row = self
            .session
            .execute_unpaged(&self.read, (slot.0.as_slice(),))
            .await
            .map_err(cql)?
            .into_rows_result()
            .map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>()
            .map_err(cql)?;
        let Some((revision, payload)) = row else {
            return Ok(None);
        };
        Ok(Some(StoredPendingQueueConsumerGate::decode(
            slot,
            revision.ok_or(PendingQueueConsumerGateError::MissingColumn)?,
            payload
                .as_deref()
                .ok_or(PendingQueueConsumerGateError::MissingColumn)?,
        )?))
    }

    pub(super) async fn bootstrap_open(
        &self,
        identity: PendingQueueConsumerGateIdentity,
    ) -> Result<PersistedPendingQueueConsumerGateOpenReceipt, PendingQueueConsumerGateError> {
        let candidate = StoredPendingQueueConsumerGate::open(identity);
        if let Some(current) = self.read(candidate.slot).await? {
            return self.recover_open(identity, current);
        }
        let payload = candidate.to_persisted_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.bootstrap,
                (candidate.slot.0.as_slice(), 0_i64, payload.as_slice()),
            )
            .await;
        match execution {
            Ok(result) => {
                let _ = decode_applied(result)?;
            }
            Err(error) => {
                let current = self.read(candidate.slot).await.map_err(|read| {
                    PendingQueueConsumerGateError::Indeterminate(format!(
                        "execute={error}; read={read}"
                    ))
                })?;
                let current = current.ok_or_else(|| {
                    PendingQueueConsumerGateError::Indeterminate(error.to_string())
                })?;
                return self.recover_open(identity, current);
            }
        }
        let current = self
            .read(candidate.slot)
            .await?
            .ok_or(PendingQueueConsumerGateError::MissingAfterLwt)?;
        self.recover_open(identity, current)
    }

    fn recover_open(
        &self,
        identity: PendingQueueConsumerGateIdentity,
        current: StoredPendingQueueConsumerGate,
    ) -> Result<PersistedPendingQueueConsumerGateOpenReceipt, PendingQueueConsumerGateError> {
        if current.identity != identity {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        if current.phase != PendingQueueConsumerGatePhase::Open {
            return Err(PendingQueueConsumerGateError::GateClosed);
        }
        Ok(PersistedPendingQueueConsumerGateOpenReceipt {
            store_fingerprint: self.fingerprint,
            current,
        })
    }

    pub(super) async fn begin_provisioning(
        &self,
        open: &PersistedPendingQueueConsumerGateOpenReceipt,
        expected: PendingQueueExpectedConsumer,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    ) -> Result<PendingQueueConsumerProvisioningStart, PendingQueueConsumerGateError> {
        if open.store_fingerprint != self.fingerprint {
            return Err(PendingQueueConsumerGateError::StoreMismatch);
        }
        let slot = open.current.slot;
        for _ in 0..MAX_CAS_RETRIES {
            let current = self
                .read(slot)
                .await?
                .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
            if current.identity != open.current.identity {
                return Err(PendingQueueConsumerGateError::IdentityMismatch);
            }
            if let Some(entry) = current.entries.get(expected.subject()) {
                match entry {
                    PendingQueueConsumerGateEntry::Provisioning {
                        consumer_digest,
                        operation_id: current_operation,
                    } if consumer_digest == expected.consumer_digest()
                        && *current_operation == operation_id =>
                    {
                        if current.phase != PendingQueueConsumerGatePhase::Open {
                            return Err(PendingQueueConsumerGateError::GateClosed);
                        }
                        return Ok(PendingQueueConsumerProvisioningStart::Lease(
                            PersistedPendingQueueConsumerProvisioningLease {
                                store_fingerprint: self.fingerprint,
                                current,
                                subject: expected.subject,
                                consumer_digest: expected.consumer_digest,
                                operation_id,
                            },
                        ));
                    }
                    PendingQueueConsumerGateEntry::Provisioned {
                        consumer_digest,
                        operation_id: current_operation,
                        consumer_instance_id,
                    } if consumer_digest == expected.consumer_digest()
                        && *current_operation == operation_id =>
                    {
                        return Ok(PendingQueueConsumerProvisioningStart::AlreadyProvisioned(
                            PersistedPendingQueueConsumerProvisionedReceipt {
                                store_fingerprint: self.fingerprint,
                                current: current.clone(),
                                subject: expected.subject,
                                consumer_digest: expected.consumer_digest,
                                consumer_instance_id: *consumer_instance_id,
                            },
                        ));
                    }
                    _ => return Err(PendingQueueConsumerGateError::ConsumerConflict),
                }
            }
            let candidate = current.begin(&expected, operation_id)?;
            if candidate == current {
                return Err(PendingQueueConsumerGateError::InvalidTransition);
            }
            match self.cas(&current, &candidate).await? {
                CasOutcome::Applied | CasOutcome::AlreadyCurrent => {
                    return Ok(PendingQueueConsumerProvisioningStart::Lease(
                        PersistedPendingQueueConsumerProvisioningLease {
                            store_fingerprint: self.fingerprint,
                            current: candidate,
                            subject: expected.subject,
                            consumer_digest: expected.consumer_digest,
                            operation_id,
                        },
                    ))
                }
                CasOutcome::Conflict => continue,
            }
        }
        Err(PendingQueueConsumerGateError::Contention)
    }

    pub(super) async fn provision_capture_consumer(
        &self,
        nats: &NatsJetStreamClient,
        open: &PersistedPendingQueueConsumerGateOpenReceipt,
        live: &LiveRecoverableNatsStreamInstance,
        spec: RecoverableNatsCaptureSpec,
        operation_id: RecoverableNatsConsumerProvisioningOperationId,
    ) -> Result<PersistedPendingQueueConsumerProvisionedReceipt, PendingQueueConsumerGateError> {
        if open.store_fingerprint != self.fingerprint
            || open.current.identity.segment_id != live.segment().segment_id()
            || open.current.identity.contract_digest != live.segment().digest()
            || open.current.identity.stream_instance_id != live.instance_id()
            || spec.v2_segment() != Some(live.segment())
        {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        let expected =
            PendingQueueExpectedConsumer::try_new(spec.subject(), spec.consumer_digest())?;
        let start = self
            .begin_provisioning(open, expected, operation_id)
            .await?;
        self.execute_provisioning_start(nats, live, spec, start)
            .await
    }

    /// Recovers an in-flight or completed provisioning operation using only
    /// durable gate state. The caller does not need to retain the operation
    /// id across a process crash.
    pub(super) async fn resume_capture_consumer(
        &self,
        nats: &NatsJetStreamClient,
        open: &PersistedPendingQueueConsumerGateOpenReceipt,
        live: &LiveRecoverableNatsStreamInstance,
        spec: RecoverableNatsCaptureSpec,
    ) -> Result<PersistedPendingQueueConsumerProvisionedReceipt, PendingQueueConsumerGateError> {
        if open.store_fingerprint != self.fingerprint
            || open.current.identity.segment_id != live.segment().segment_id()
            || open.current.identity.contract_digest != live.segment().digest()
            || open.current.identity.stream_instance_id != live.instance_id()
            || spec.v2_segment() != Some(live.segment())
        {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        let expected =
            PendingQueueExpectedConsumer::try_new(spec.subject(), spec.consumer_digest())?;
        let current = self
            .read(open.current.slot)
            .await?
            .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
        if current.identity != open.current.identity {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        if current.phase != PendingQueueConsumerGatePhase::Open {
            return Err(PendingQueueConsumerGateError::GateClosed);
        }
        let entry = current.entries.get(expected.subject()).cloned();
        let start = match entry {
            Some(PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest,
                operation_id,
            }) if consumer_digest == *expected.consumer_digest() => {
                PendingQueueConsumerProvisioningStart::Lease(
                    PersistedPendingQueueConsumerProvisioningLease {
                        store_fingerprint: self.fingerprint,
                        current,
                        subject: expected.subject,
                        consumer_digest: expected.consumer_digest,
                        operation_id,
                    },
                )
            }
            Some(PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest,
                consumer_instance_id,
                ..
            }) if consumer_digest == *expected.consumer_digest() => {
                PendingQueueConsumerProvisioningStart::AlreadyProvisioned(
                    PersistedPendingQueueConsumerProvisionedReceipt {
                        store_fingerprint: self.fingerprint,
                        current: current.clone(),
                        subject: expected.subject,
                        consumer_digest: expected.consumer_digest,
                        consumer_instance_id,
                    },
                )
            }
            Some(_) => return Err(PendingQueueConsumerGateError::ConsumerConflict),
            None => return Err(PendingQueueConsumerGateError::ProvisioningNotFound),
        };
        self.execute_provisioning_start(nats, live, spec, start)
            .await
    }

    async fn execute_provisioning_start(
        &self,
        nats: &NatsJetStreamClient,
        live: &LiveRecoverableNatsStreamInstance,
        spec: RecoverableNatsCaptureSpec,
        start: PendingQueueConsumerProvisioningStart,
    ) -> Result<PersistedPendingQueueConsumerProvisionedReceipt, PendingQueueConsumerGateError> {
        match start {
            PendingQueueConsumerProvisioningStart::AlreadyProvisioned(receipt) => {
                let binding = receipt.existing_binding(&spec)?;
                nats.open_existing_recoverable_capture(spec, &binding)
                    .await
                    .map_err(transport)?;
                Ok(receipt)
            }
            PendingQueueConsumerProvisioningStart::Lease(lease) => {
                let operation_id = lease.operation_id;
                let provisioned = nats
                    .provision_recoverable_capture_consumer(live, spec, operation_id)
                    .await
                    .map_err(transport)?;
                self.complete_provisioning(&lease, &provisioned).await
            }
        }
    }

    pub(super) async fn complete_provisioning(
        &self,
        lease: &PersistedPendingQueueConsumerProvisioningLease,
        provisioned: &RecoverableNatsProvisionedConsumerReceipt,
    ) -> Result<PersistedPendingQueueConsumerProvisionedReceipt, PendingQueueConsumerGateError> {
        if lease.store_fingerprint != self.fingerprint {
            return Err(PendingQueueConsumerGateError::StoreMismatch);
        }
        if provisioned.stream_instance_id()
            != lease.current.identity.stream_instance_id.as_bytes()
            || provisioned.subject() != lease.subject
            || provisioned.consumer_digest() != &lease.consumer_digest
            || provisioned.operation_id() != lease.operation_id
        {
            return Err(PendingQueueConsumerGateError::ProvisioningReceiptMismatch);
        }
        let consumer_instance_id = provisioned.consumer_instance_id();
        for _ in 0..MAX_CAS_RETRIES {
            let current = self
                .read(lease.current.slot)
                .await?
                .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
            if current.identity != lease.current.identity {
                return Err(PendingQueueConsumerGateError::IdentityMismatch);
            }
            if let Some(PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest,
                operation_id,
                consumer_instance_id: current_instance,
            }) = current.entries.get(&lease.subject)
            {
                if *consumer_digest == lease.consumer_digest
                    && *operation_id == lease.operation_id
                    && *current_instance == consumer_instance_id
                {
                    return Ok(PersistedPendingQueueConsumerProvisionedReceipt {
                        store_fingerprint: self.fingerprint,
                        current,
                        subject: lease.subject.clone(),
                        consumer_digest: lease.consumer_digest,
                        consumer_instance_id,
                    });
                }
                return Err(PendingQueueConsumerGateError::ProvisioningMismatch);
            }
            let candidate = current.complete(
                &lease.subject,
                lease.consumer_digest,
                lease.operation_id,
                consumer_instance_id,
            )?;
            match self.cas(&current, &candidate).await? {
                CasOutcome::Applied | CasOutcome::AlreadyCurrent => {
                    return Ok(PersistedPendingQueueConsumerProvisionedReceipt {
                        store_fingerprint: self.fingerprint,
                        current: candidate,
                        subject: lease.subject.clone(),
                        consumer_digest: lease.consumer_digest,
                        consumer_instance_id,
                    });
                }
                CasOutcome::Conflict => continue,
            }
        }
        Err(PendingQueueConsumerGateError::Contention)
    }

    pub(super) async fn close(
        &self,
        identity: PendingQueueConsumerGateIdentity,
        expected: &[PendingQueueExpectedConsumer],
    ) -> Result<PersistedPendingQueueConsumerGateClosedReceipt, PendingQueueConsumerGateError> {
        validate_sorted_expected(expected)?;
        for _ in 0..MAX_CAS_RETRIES {
            let current = self
                .read(identity.slot())
                .await?
                .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
            if current.identity != identity {
                return Err(PendingQueueConsumerGateError::IdentityMismatch);
            }
            let candidate = current.close(expected)?;
            if candidate == current {
                return Ok(PersistedPendingQueueConsumerGateClosedReceipt {
                    store_fingerprint: self.fingerprint,
                    current,
                });
            }
            match self.cas(&current, &candidate).await? {
                CasOutcome::Applied | CasOutcome::AlreadyCurrent => {
                    return Ok(PersistedPendingQueueConsumerGateClosedReceipt {
                        store_fingerprint: self.fingerprint,
                        current: candidate,
                    });
                }
                CasOutcome::Conflict => continue,
            }
        }
        Err(PendingQueueConsumerGateError::Contention)
    }

    pub(super) async fn revalidate_closed(
        &self,
        receipt: &PersistedPendingQueueConsumerGateClosedReceipt,
        identity: PendingQueueConsumerGateIdentity,
        expected: &[PendingQueueExpectedConsumer],
    ) -> Result<(), PendingQueueConsumerGateError> {
        validate_sorted_expected(expected)?;
        if !receipt.matches(self, identity, expected) {
            return Err(PendingQueueConsumerGateError::ReceiptMismatch);
        }
        let current = self
            .read(identity.slot())
            .await?
            .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
        if current != receipt.current {
            return Err(PendingQueueConsumerGateError::EvidenceChanged);
        }
        Ok(())
    }

    pub(super) async fn revalidate_commitment(
        &self,
        commitment: PendingQueueConsumerGateCommitment,
    ) -> Result<(), PendingQueueConsumerGateError> {
        PendingQueueConsumerGateCommitment::try_new(
            commitment.slot,
            commitment.revision,
            commitment.digest,
        )?;
        let current = self
            .read(PendingQueueConsumerGateSlot(commitment.slot))
            .await?
            .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
        if current.phase != PendingQueueConsumerGatePhase::Closed
            || current.revision != commitment.revision
            || current.digest.0 != commitment.digest
        {
            return Err(PendingQueueConsumerGateError::EvidenceChanged);
        }
        Ok(())
    }

    pub(super) async fn recover_existing_binding(
        &self,
        receipt: &PersistedPendingQueueConsumerProvisionedReceipt,
        spec: &RecoverableNatsCaptureSpec,
    ) -> Result<RecoverableNatsExistingConsumerBinding, PendingQueueConsumerGateError> {
        if receipt.store_fingerprint != self.fingerprint {
            return Err(PendingQueueConsumerGateError::StoreMismatch);
        }
        let current = self
            .read(receipt.current.slot)
            .await?
            .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
        if current.identity != receipt.current.identity
            || current.phase != PendingQueueConsumerGatePhase::Open
        {
            return Err(PendingQueueConsumerGateError::GateClosed);
        }
        let entry = current
            .entries
            .get(&receipt.subject)
            .ok_or(PendingQueueConsumerGateError::ProvisioningNotFound)?;
        let receipt_entry = receipt
            .current
            .entries
            .get(&receipt.subject)
            .ok_or(PendingQueueConsumerGateError::ProvisioningNotFound)?;
        if entry != receipt_entry {
            return Err(PendingQueueConsumerGateError::EvidenceChanged);
        }
        receipt.existing_binding(spec)
    }

    pub(super) async fn revalidate_nats_consumer_set(
        &self,
        nats: &NatsJetStreamClient,
        commitment: PendingQueueConsumerGateCommitment,
        segment: RecoverableNatsStreamSegment,
        mode: RecoverableNatsExpectedStreamMode,
    ) -> Result<(), PendingQueueConsumerGateError> {
        self.revalidate_commitment(commitment).await?;
        let current = self
            .read(PendingQueueConsumerGateSlot(*commitment.slot()))
            .await?
            .ok_or(PendingQueueConsumerGateError::Uninitialized)?;
        if current.identity.segment_id != segment.segment_id()
            || current.identity.contract_digest != segment.digest()
        {
            return Err(PendingQueueConsumerGateError::IdentityMismatch);
        }
        let mut expected = Vec::with_capacity(current.entries.len());
        for (subject, entry) in &current.entries {
            let PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest,
                operation_id,
                consumer_instance_id,
            } = entry
            else {
                return Err(PendingQueueConsumerGateError::GateClosed);
            };
            expected.push(
                RecoverableNatsProvisionedConsumerExpectation::try_new(
                    subject,
                    *consumer_digest,
                    *operation_id,
                    *consumer_instance_id,
                )
                .map_err(transport)?,
            );
        }
        nats.verify_recoverable_provisioned_consumer_set(
            segment,
            current.identity.stream_instance_id,
            mode,
            expected,
        )
        .await
        .map_err(transport)?;
        self.revalidate_commitment(commitment).await
    }

    async fn cas(
        &self,
        expected: &StoredPendingQueueConsumerGate,
        candidate: &StoredPendingQueueConsumerGate,
    ) -> Result<CasOutcome, PendingQueueConsumerGateError> {
        if expected.slot != candidate.slot
            || expected.identity != candidate.identity
            || candidate.revision != next_revision(expected.revision)?
        {
            return Err(PendingQueueConsumerGateError::InvalidTransition);
        }
        let expected_payload = expected.to_persisted_bytes();
        let candidate_payload = candidate.to_persisted_bytes();
        let execution = self
            .session
            .execute_unpaged(
                &self.compare_and_set,
                (
                    candidate.revision as i64,
                    candidate_payload.as_slice(),
                    candidate.slot.0.as_slice(),
                    expected.revision as i64,
                    expected_payload.as_slice(),
                ),
            )
            .await;
        match execution {
            Ok(result) => {
                if decode_applied(result)? {
                    let current = self
                        .read(candidate.slot)
                        .await?
                        .ok_or(PendingQueueConsumerGateError::MissingAfterLwt)?;
                    if current == *candidate {
                        Ok(CasOutcome::Applied)
                    } else {
                        Err(PendingQueueConsumerGateError::AppliedStateMismatch)
                    }
                } else {
                    match self.read(candidate.slot).await? {
                        Some(current) if current == *candidate => {
                            Ok(CasOutcome::AlreadyCurrent)
                        }
                        Some(_) => Ok(CasOutcome::Conflict),
                        None => Err(PendingQueueConsumerGateError::MissingAfterLwt),
                    }
                }
            }
            Err(error) => match self.read(candidate.slot).await {
                Ok(Some(current)) if current == *candidate => Ok(CasOutcome::AlreadyCurrent),
                Ok(_) => Err(PendingQueueConsumerGateError::Indeterminate(
                    error.to_string(),
                )),
                Err(read) => Err(PendingQueueConsumerGateError::Indeterminate(format!(
                    "execute={error}; read={read}"
                ))),
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CasOutcome {
    Applied,
    AlreadyCurrent,
    Conflict,
}

fn validate_sorted_expected(
    expected: &[PendingQueueExpectedConsumer],
) -> Result<(), PendingQueueConsumerGateError> {
    if expected.len() > MAX_CONSUMERS
        || expected.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(PendingQueueConsumerGateError::ExpectedSetMismatch);
    }
    Ok(())
}

fn next_revision(current: u64) -> Result<u64, PendingQueueConsumerGateError> {
    let next = current
        .checked_add(1)
        .ok_or(PendingQueueConsumerGateError::RevisionOverflow)?;
    if next > i64::MAX as u64 {
        Err(PendingQueueConsumerGateError::RevisionOverflow)
    } else {
        Ok(next)
    }
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueConsumerGateQueries,
) -> PendingQueueConsumerGateStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update(queries.render_golden().as_bytes());
    PendingQueueConsumerGateStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueConsumerGateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(
    session: &Session,
    cql_text: &str,
) -> Result<PreparedStatement, PendingQueueConsumerGateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueConsumerGateError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows
        .column_specs()
        .get_by_name("[applied]")
        .ok_or(PendingQueueConsumerGateError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueConsumerGateError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueConsumerGateError {
    PendingQueueConsumerGateError::Cql(error.to_string())
}

fn transport(error: impl fmt::Display) -> PendingQueueConsumerGateError {
    PendingQueueConsumerGateError::Transport(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingQueueConsumerGateError {
    Cql(String),
    Transport(String),
    Indeterminate(String),
    Uninitialized,
    StoreMismatch,
    IdentityMismatch,
    RevisionMismatch,
    RevisionOverflow,
    UnknownPhase,
    MalformedPayload,
    DigestMismatch,
    InvalidConsumer,
    DuplicateConsumer,
    TooManyConsumers,
    ConsumerConflict,
    OperationReused,
    ConsumerInstanceReused,
    ProvisioningNotFound,
    ProvisioningMismatch,
    ProvisioningAlreadyComplete,
    ProvisioningReceiptMismatch,
    ExpectedSetMismatch,
    GateClosed,
    Contention,
    Conflict,
    InvalidTransition,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    ReceiptMismatch,
    EvidenceChanged,
}

impl fmt::Display for PendingQueueConsumerGateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cql(error) => write!(formatter, "Scylla error: {error}"),
            Self::Transport(error) => write!(formatter, "NATS transport error: {error}"),
            Self::Indeterminate(error) => write!(formatter, "indeterminate LWT: {error}"),
            Self::Uninitialized => formatter.write_str("consumer gate is uninitialized"),
            Self::StoreMismatch => formatter.write_str("consumer gate store mismatch"),
            Self::IdentityMismatch => formatter.write_str("consumer gate identity mismatch"),
            Self::RevisionMismatch => formatter.write_str("consumer gate revision mismatch"),
            Self::RevisionOverflow => formatter.write_str("consumer gate revision overflow"),
            Self::UnknownPhase => formatter.write_str("unknown consumer gate phase"),
            Self::MalformedPayload => formatter.write_str("malformed consumer gate payload"),
            Self::DigestMismatch => formatter.write_str("consumer gate digest mismatch"),
            Self::InvalidConsumer => formatter.write_str("invalid expected consumer"),
            Self::DuplicateConsumer => formatter.write_str("duplicate expected consumer"),
            Self::TooManyConsumers => formatter.write_str("too many consumers"),
            Self::ConsumerConflict => formatter.write_str("consumer identity conflict"),
            Self::OperationReused => formatter.write_str("provisioning operation id reused"),
            Self::ConsumerInstanceReused => {
                formatter.write_str("consumer instance id reused")
            }
            Self::ProvisioningNotFound => formatter.write_str("provisioning lease not found"),
            Self::ProvisioningMismatch => formatter.write_str("provisioning lease mismatch"),
            Self::ProvisioningAlreadyComplete => {
                formatter.write_str("consumer provisioning already complete")
            }
            Self::ProvisioningReceiptMismatch => {
                formatter.write_str("provisioning receipt mismatch")
            }
            Self::ExpectedSetMismatch => formatter.write_str("expected consumer set mismatch"),
            Self::GateClosed => formatter.write_str("consumer mutation gate is closed"),
            Self::Contention => formatter.write_str("consumer gate contention exhausted"),
            Self::Conflict => formatter.write_str("consumer gate LWT conflict"),
            Self::InvalidTransition => formatter.write_str("invalid consumer gate transition"),
            Self::MissingColumn => formatter.write_str("consumer gate row missing column"),
            Self::MissingAppliedColumn => formatter.write_str("LWT result missing applied column"),
            Self::InvalidAppliedColumn => formatter.write_str("invalid LWT applied column"),
            Self::MissingAfterLwt => formatter.write_str("consumer gate missing after LWT"),
            Self::AppliedStateMismatch => formatter.write_str("applied consumer gate mismatch"),
            Self::ReceiptMismatch => formatter.write_str("consumer gate receipt mismatch"),
            Self::EvidenceChanged => formatter.write_str("consumer gate evidence changed"),
        }
    }
}

impl Error for PendingQueueConsumerGateError {}

struct Decoder<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, cursor: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueConsumerGateError> {
        let end = self
            .cursor
            .checked_add(len)
            .ok_or(PendingQueueConsumerGateError::MalformedPayload)?;
        let value = self
            .bytes
            .get(self.cursor..end)
            .ok_or(PendingQueueConsumerGateError::MalformedPayload)?;
        self.cursor = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueConsumerGateError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(PendingQueueConsumerGateError::MalformedPayload)?)
    }

    fn u16(&mut self) -> Result<u16, PendingQueueConsumerGateError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().map_err(
            |_| PendingQueueConsumerGateError::MalformedPayload,
        )?))
    }

    fn u32(&mut self) -> Result<u32, PendingQueueConsumerGateError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(
            |_| PendingQueueConsumerGateError::MalformedPayload,
        )?))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueConsumerGateError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(
            |_| PendingQueueConsumerGateError::MalformedPayload,
        )?))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueConsumerGateError> {
        self.take(32)?
            .try_into()
            .map_err(|_| PendingQueueConsumerGateError::MalformedPayload)
    }

    fn finish(self) -> Result<(), PendingQueueConsumerGateError> {
        if self.cursor == self.bytes.len() {
            Ok(())
        } else {
            Err(PendingQueueConsumerGateError::MalformedPayload)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PendingQueueConsumerGateIdentity {
        PendingQueueConsumerGateIdentity::new(
            RecoverableNatsSegmentId::try_new(7).unwrap(),
            RecoverableNatsSegmentContractDigest::try_new([2; 32]).unwrap(),
            RecoverableNatsStreamInstanceId::try_from_bytes([3; 32]).unwrap(),
        )
    }

    fn expected(subject: &str, byte: u8) -> PendingQueueExpectedConsumer {
        PendingQueueExpectedConsumer::try_new(subject, [byte; 32]).unwrap()
    }

    fn operation(byte: u8) -> RecoverableNatsConsumerProvisioningOperationId {
        RecoverableNatsConsumerProvisioningOperationId::try_new([byte; 32]).unwrap()
    }

    fn instance(byte: u8) -> RecoverableNatsConsumerInstanceId {
        RecoverableNatsConsumerInstanceId::try_new([byte; 32]).unwrap()
    }

    #[test]
    fn codec_is_deterministic_and_rejects_malformed_payloads() {
        let open = StoredPendingQueueConsumerGate::open(identity());
        let provisioning = open.begin(&expected("queue.a", 4), operation(5)).unwrap();
        let provisioned = provisioning
            .complete("queue.a", [4; 32], operation(5), instance(6))
            .unwrap();
        let closed = provisioned.close(&[expected("queue.a", 4)]).unwrap();
        let bytes = closed.to_persisted_bytes();
        assert_eq!(bytes, closed.to_persisted_bytes());
        assert_eq!(
            StoredPendingQueueConsumerGate::decode(closed.slot, closed.revision as i64, &bytes)
                .unwrap(),
            closed
        );
        assert!(StoredPendingQueueConsumerGate::decode(
            closed.slot,
            closed.revision as i64,
            &bytes[..bytes.len() - 1],
        )
        .is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(StoredPendingQueueConsumerGate::decode(
            closed.slot,
            closed.revision as i64,
            &trailing,
        )
        .is_err());
        assert!(StoredPendingQueueConsumerGate::decode(
            closed.slot,
            closed.revision as i64 + 1,
            &bytes,
        )
        .is_err());
    }

    #[test]
    fn operation_retry_is_exact_and_conflicts_fail_closed() {
        let open = StoredPendingQueueConsumerGate::open(identity());
        let first = open.begin(&expected("queue.a", 4), operation(5)).unwrap();
        assert_eq!(
            first.begin(&expected("queue.a", 4), operation(5)).unwrap(),
            first
        );
        assert_eq!(
            first.begin(&expected("queue.a", 4), operation(9)),
            Err(PendingQueueConsumerGateError::ConsumerConflict)
        );
        assert_eq!(
            first.begin(&expected("queue.a", 8), operation(5)),
            Err(PendingQueueConsumerGateError::ConsumerConflict)
        );
        assert_eq!(
            first.complete("queue.a", [4; 32], operation(9), instance(6)),
            Err(PendingQueueConsumerGateError::ProvisioningMismatch)
        );
        assert_eq!(
            first.begin(&expected("queue.b", 7), operation(5)),
            Err(PendingQueueConsumerGateError::OperationReused)
        );
        let completed = first
            .complete("queue.a", [4; 32], operation(5), instance(6))
            .unwrap();
        assert_eq!(
            completed.begin(&expected("queue.a", 4), operation(5)),
            Err(PendingQueueConsumerGateError::ProvisioningAlreadyComplete)
        );
        let second = completed
            .begin(&expected("queue.b", 7), operation(8))
            .unwrap();
        assert_eq!(
            second.complete("queue.b", [7; 32], operation(8), instance(6)),
            Err(PendingQueueConsumerGateError::ConsumerInstanceReused)
        );
    }

    #[test]
    fn provisioning_restart_recovers_the_operation_from_the_durable_row() {
        let open = StoredPendingQueueConsumerGate::open(identity());
        let provisioning = open.begin(&expected("queue.a", 4), operation(5)).unwrap();
        let bytes = provisioning.to_persisted_bytes();
        let recovered = StoredPendingQueueConsumerGate::decode(
            provisioning.slot,
            provisioning.revision as i64,
            &bytes,
        )
        .unwrap();

        assert_eq!(
            recovered.entries.get("queue.a"),
            Some(&PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest: [4; 32],
                operation_id: operation(5),
            })
        );
    }

    #[test]
    fn decoder_rejects_duplicate_physical_identities_and_impossible_revisions() {
        let mut duplicate_operation = StoredPendingQueueConsumerGate::open(identity());
        duplicate_operation.revision = 2;
        duplicate_operation.entries.insert(
            "queue.a".to_owned(),
            PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest: [4; 32],
                operation_id: operation(5),
            },
        );
        duplicate_operation.entries.insert(
            "queue.b".to_owned(),
            PendingQueueConsumerGateEntry::Provisioning {
                consumer_digest: [7; 32],
                operation_id: operation(5),
            },
        );
        duplicate_operation.digest = duplicate_operation.calculate_digest();
        assert_eq!(
            StoredPendingQueueConsumerGate::decode(
                duplicate_operation.slot,
                duplicate_operation.revision as i64,
                &duplicate_operation.to_persisted_bytes(),
            ),
            Err(PendingQueueConsumerGateError::OperationReused)
        );

        let mut duplicate_instance = duplicate_operation;
        duplicate_instance.revision = 4;
        duplicate_instance.entries.insert(
            "queue.a".to_owned(),
            PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest: [4; 32],
                operation_id: operation(5),
                consumer_instance_id: instance(6),
            },
        );
        duplicate_instance.entries.insert(
            "queue.b".to_owned(),
            PendingQueueConsumerGateEntry::Provisioned {
                consumer_digest: [7; 32],
                operation_id: operation(8),
                consumer_instance_id: instance(6),
            },
        );
        duplicate_instance.digest = duplicate_instance.calculate_digest();
        assert_eq!(
            StoredPendingQueueConsumerGate::decode(
                duplicate_instance.slot,
                duplicate_instance.revision as i64,
                &duplicate_instance.to_persisted_bytes(),
            ),
            Err(PendingQueueConsumerGateError::ConsumerInstanceReused)
        );

        let mut impossible_revision = StoredPendingQueueConsumerGate::open(identity());
        impossible_revision.revision = 9;
        impossible_revision.digest = impossible_revision.calculate_digest();
        assert_eq!(
            StoredPendingQueueConsumerGate::decode(
                impossible_revision.slot,
                impossible_revision.revision as i64,
                &impossible_revision.to_persisted_bytes(),
            ),
            Err(PendingQueueConsumerGateError::RevisionMismatch)
        );
    }

    #[test]
    fn close_requires_exact_fully_provisioned_sorted_set_and_is_terminal() {
        let open = StoredPendingQueueConsumerGate::open(identity());
        let a = open.begin(&expected("queue.a", 4), operation(5)).unwrap();
        assert_eq!(
            a.close(&[expected("queue.a", 4)]),
            Err(PendingQueueConsumerGateError::ExpectedSetMismatch)
        );
        let a = a
            .complete("queue.a", [4; 32], operation(5), instance(6))
            .unwrap();
        let b = a.begin(&expected("queue.b", 7), operation(8)).unwrap();
        let b = b
            .complete("queue.b", [7; 32], operation(8), instance(9))
            .unwrap();
        assert!(b.close(&[expected("queue.a", 4)]).is_err());
        assert!(b
            .close(&[expected("queue.b", 7), expected("queue.a", 4)])
            .is_err());
        let closed = b
            .close(&[expected("queue.a", 4), expected("queue.b", 7)])
            .unwrap();
        assert_eq!(
            closed
                .close(&[expected("queue.a", 4), expected("queue.b", 7)])
                .unwrap(),
            closed
        );
        assert_eq!(
            closed.begin(&expected("queue.c", 10), operation(11)),
            Err(PendingQueueConsumerGateError::GateClosed)
        );
    }

    #[test]
    fn revision_is_monotonic_and_prevents_payload_aba() {
        let open = StoredPendingQueueConsumerGate::open(identity());
        let provisioning = open.begin(&expected("queue.a", 4), operation(5)).unwrap();
        let provisioned = provisioning
            .complete("queue.a", [4; 32], operation(5), instance(6))
            .unwrap();
        let closed = provisioned.close(&[expected("queue.a", 4)]).unwrap();
        assert_eq!(open.revision, 0);
        assert_eq!(provisioning.revision, 1);
        assert_eq!(provisioned.revision, 2);
        assert_eq!(closed.revision, 3);
        assert_ne!(open.to_persisted_bytes(), closed.to_persisted_bytes());
        assert_eq!(
            next_revision(i64::MAX as u64),
            Err(PendingQueueConsumerGateError::RevisionOverflow)
        );
    }

    #[test]
    fn queries_are_full_payload_lwt_in_no_tablet_keyspace() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new(
            "psy_branch_exact_no_tablet",
        )
        .unwrap();
        let queries = PendingQueueConsumerGateQueries::new(&keyspace);
        let bootstrap = queries.get(PendingQueueConsumerGateQueryId::Bootstrap);
        let cas = queries.get(PendingQueueConsumerGateQueryId::CompareAndSet);
        assert!(bootstrap.cql().contains(" IF NOT EXISTS"));
        assert!(cas
            .cql()
            .contains("IF revision = ? AND gate_payload = ?"));
        assert_eq!(
            cas.bind_shape(),
            &[
                "candidate_revision:BIGINT",
                "candidate_payload:BLOB",
                "gate_slot:BLOB",
                "expected_revision:BIGINT",
                "expected_payload:BLOB",
            ]
        );
        assert!(queries
            .render_golden()
            .contains("psy_branch_exact_no_tablet.branch_exact_pending_queue_consumer_gate_v1"));
    }

    #[test]
    fn new_gate_is_not_in_production_setup() {
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_CONSUMER_GATE_TABLE));
    }

    #[test]
    fn seal_requested_consumes_and_revalidates_closed_gate_receipt() {
        let lifecycle = include_str!("pending_queue_segment_lifecycle.rs");
        assert!(lifecycle.contains(
            "consumer_gate_closed: &PersistedPendingQueueConsumerGateClosedReceipt"
        ));
        assert_eq!(lifecycle.matches(".revalidate_closed(").count(), 2);
        assert!(lifecycle.contains("build_expected_gate_consumers"));
    }
}
