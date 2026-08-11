//! Durable fixed-source semantic generation aggregate.
//!
//! This default-off row consumes the exact per-source semantic receipts and
//! persists one immutable Coordinator (3 sources) or Realm (1 source)
//! assignment archive with an IF-NOT-EXISTS LWT. It can perform the first
//! pipeline handoff but grants no terminal, stream-rotation, or GC authority.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use psy_node_core::{
    queue::{
        realm_processor_application_archive::RealmProcessorApplicationArchiveBinding,
        realm_processor_application_archive::RealmProcessorApplicationArchiveHeader,
        realm_processor_semantic_output::RealmProcessorSemanticOutput,
        recoverable_ephemeral::PendingQueueCaptureContextDigest,
    },
    store::{
        pending_generation_pipeline::{
            PendingEmptyQueueSealDigest, PendingPipelineReadState,
            PendingPipelineRevision, PendingPipelineWriteOutcome,
            PendingProcessingState, PendingQueueCloseIntentDigest,
            PendingWorkCaptureDigest, SealedPendingPipelineTransition,
            StoredPendingPipeline,
        },
    },
};
use psy_node_nats::{
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment, PendingQueueSegmentAssignmentDigest,
        PendingQueueSegmentLedgerSlot,
    },
    recoverable_publish::{
        PendingQueuePublishSourceSlot, PendingQueuePublisherKind,
    },
};
use scylla::{
    client::session::Session,
    response::query_result::QueryResult,
    statement::{
        prepared::PreparedStatement, Consistency, SerialConsistency,
    },
    value::{CqlValue, Row},
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactDeploymentNoTabletKeyspace, PendingQueueSegmentAssignmentReceipt,
    PersistedPendingQueueCloseReceipt, ScyllaPendingPipelineStore,
    pending_queue_semantic_terminal::{
        PendingQueueSemanticSourceCommitment, PendingQueueSemanticSourceDigest,
        PersistedPendingQueueSemanticSourceReceipt,
    },
};

pub(super) const PENDING_QUEUE_SEMANTIC_GENERATION_TABLE: &str =
    "branch_exact_pending_queue_semantic_generation_v2";
const MAGIC: &[u8; 8] = b"PSYQSGEN";
const CODEC_VERSION: u16 = 2;
const REVISION: u64 = 1;
const ARCHIVE_SLOT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-assignment-archive-slot/v1";
const DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-generation/v2";
const STORE_FINGERPRINT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-generation-store/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticGenerationSlot([u8; 32]);

impl PendingQueueSemanticGenerationSlot {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticAggregateError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticAggregateError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticGenerationDigest([u8; 32]);

impl PendingQueueSemanticGenerationDigest {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticAggregateError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticAggregateError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct PendingQueueSemanticAggregateStoreFingerprint([u8; 32]);

impl PendingQueueSemanticAggregateStoreFingerprint {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticAggregateError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticAggregateError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub(super) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SemanticSourceEntry {
    publisher_kind: PendingQueuePublisherKind,
    source_slot: PendingQueuePublishSourceSlot,
    semantic_digest: PendingQueueSemanticSourceDigest,
    artifact_slot: [u8; 32],
    artifact_owner_attempt_id: [u8; 32],
    artifact_owner_fence: u64,
    consumer_digest: [u8; 32],
    data_member_count: u32,
    data_encoded_bytes: u64,
    source_revision: u64,
    artifact_scan_revision: u64,
    artifact_scan_digest: [u8; 32],
    nats_scan_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueArchivedConsumerCommitment {
    publisher_kind: PendingQueuePublisherKind,
    consumer_digest: [u8; 32],
}

impl PendingQueueArchivedConsumerCommitment {
    pub(super) const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub(super) const fn consumer_digest(&self) -> [u8; 32] {
        self.consumer_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StoredPendingQueueSemanticGeneration {
    slot: PendingQueueSemanticGenerationSlot,
    revision: u64,
    network: NetworkId,
    authority: AuthorityScope,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    close_intent: PendingQueueCloseIntentDigest,
    pipeline_store_fingerprint: [u8; 32],
    pipeline_close_revision: u64,
    pipeline_close_receipt_digest: [u8; 32],
    publish_store_fingerprint: [u8; 32],
    assignment_store_fingerprint: [u8; 32],
    assignment_ledger_slot: [u8; 32],
    assignment_ledger_revision: u64,
    assignment_payload: Vec<u8>,
    artifact_store_fingerprint: [u8; 32],
    total_data_members: u64,
    total_data_encoded_bytes: u64,
    sources: Vec<SemanticSourceEntry>,
    digest: PendingQueueSemanticGenerationDigest,
}

#[derive(Clone)]
struct SemanticGenerationBinding {
    network: NetworkId,
    authority: AuthorityScope,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    close_intent: PendingQueueCloseIntentDigest,
    pipeline_store_fingerprint: [u8; 32],
    pipeline_close_revision: u64,
    pipeline_close_receipt_digest: [u8; 32],
    assignment_store_fingerprint: [u8; 32],
    assignment_ledger_slot: [u8; 32],
    assignment_ledger_revision: u64,
    assignment_payload: Vec<u8>,
}

impl StoredPendingQueueSemanticGeneration {
    pub(super) fn try_from_source_receipts(
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipts: Vec<PersistedPendingQueueSemanticSourceReceipt>,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let assigned = assignment.assignment();
        if !close.matches_context(assigned.context()) {
            return Err(PendingQueueSemanticAggregateError::GenerationMismatch);
        }
        let binding = SemanticGenerationBinding {
            network: assigned.context().key().network(),
            authority: assigned.context().key().authority(),
            context_digest: assigned.context().digest(),
            assignment_digest: assigned.digest(),
            close_intent: close.close_intent(),
            pipeline_store_fingerprint: *close.store_fingerprint().as_bytes(),
            pipeline_close_revision: close.revision().get(),
            pipeline_close_receipt_digest: *close.receipt_digest(),
            assignment_store_fingerprint: *assignment.store_fingerprint().as_bytes(),
            assignment_ledger_slot: *assignment.ledger_slot().as_bytes(),
            assignment_ledger_revision: assignment.ledger_revision().get(),
            assignment_payload: assigned.to_canonical_bytes(),
        };
        Self::from_commitments(
            binding,
            receipts
                .into_iter()
                .map(PersistedPendingQueueSemanticSourceReceipt::into_commitment)
                .collect(),
        )
    }

    fn from_commitments(
        binding: SemanticGenerationBinding,
        mut commitments: Vec<PendingQueueSemanticSourceCommitment>,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        if binding.pipeline_store_fingerprint == [0; 32]
            || binding.pipeline_close_revision == 0
            || binding.pipeline_close_receipt_digest == [0; 32]
            || binding.assignment_store_fingerprint == [0; 32]
            || binding.assignment_ledger_revision == 0
            || binding.assignment_payload.is_empty()
            || u16::try_from(binding.assignment_payload.len()).is_err()
        {
            return Err(PendingQueueSemanticAggregateError::AssignmentPayloadMismatch);
        }
        let ledger_slot = PendingQueueSegmentLedgerSlot::try_new(
            binding.assignment_ledger_slot,
        )
        .map_err(|_| PendingQueueSemanticAggregateError::AssignmentPayloadMismatch)?;
        let archived_assignment =
            PendingQueueGenerationSegmentAssignment::decode_canonical(
                ledger_slot,
                &binding.assignment_payload,
            )
            .map_err(|_| PendingQueueSemanticAggregateError::AssignmentPayloadMismatch)?;
        if archived_assignment.context().key().network() != binding.network
            || archived_assignment.context().key().authority() != binding.authority
            || archived_assignment.context().digest() != binding.context_digest
            || archived_assignment.digest() != binding.assignment_digest
            || archived_assignment.assigned_at_ledger_revision().get()
                != binding.assignment_ledger_revision
            || archived_assignment.to_canonical_bytes() != binding.assignment_payload
        {
            return Err(PendingQueueSemanticAggregateError::AssignmentPayloadMismatch);
        }
        let expected = expected_roles(binding.authority);
        if commitments.len() != expected.len() {
            return Err(PendingQueueSemanticAggregateError::IncompleteSourceSet);
        }
        commitments.sort_by_key(|entry| entry.publisher_kind as u8);
        if commitments
            .iter()
            .map(|entry| entry.publisher_kind)
            .ne(expected.iter().copied())
        {
            return Err(PendingQueueSemanticAggregateError::SourceSetMismatch);
        }
        let common_publish_store = commitments[0].publish_store_fingerprint;
        let common_artifact_store = commitments[0].artifact_store_fingerprint;
        if common_publish_store == [0; 32] || common_artifact_store == [0; 32] {
            return Err(PendingQueueSemanticAggregateError::EmptyDigest);
        }
        let mut total_data_members = 0u64;
        let mut total_data_encoded_bytes = 0u64;
        let mut sources = Vec::with_capacity(commitments.len());
        for source in commitments {
            if source.context_digest != binding.context_digest
                || source.assignment_digest != binding.assignment_digest
                || source.close_intent != binding.close_intent
                || source.pipeline_close_receipt_digest
                    != binding.pipeline_close_receipt_digest
                || source.publish_store_fingerprint != common_publish_store
                || source.assignment_store_fingerprint
                    != binding.assignment_store_fingerprint
                || source.assignment_ledger_slot != binding.assignment_ledger_slot
                || source.assignment_ledger_revision
                    != binding.assignment_ledger_revision
                || source.artifact_store_fingerprint != common_artifact_store
                || source.artifact_slot == [0; 32]
                || source.artifact_owner_attempt_id == [0; 32]
                || source.artifact_owner_fence == 0
                || source.consumer_digest == [0; 32]
                || source.source_revision == 0
                || source.artifact_scan_revision == 0
                || source.artifact_scan_digest == [0; 32]
                || source.nats_scan_digest == [0; 32]
            {
                return Err(PendingQueueSemanticAggregateError::GenerationMismatch);
            }
            total_data_members = total_data_members
                .checked_add(u64::from(source.data_member_count))
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
            total_data_encoded_bytes = total_data_encoded_bytes
                .checked_add(source.data_encoded_bytes)
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
            sources.push(SemanticSourceEntry {
                publisher_kind: source.publisher_kind,
                source_slot: source.source_slot,
                semantic_digest: source.semantic_digest,
                artifact_slot: source.artifact_slot,
                artifact_owner_attempt_id: source.artifact_owner_attempt_id,
                artifact_owner_fence: source.artifact_owner_fence,
                consumer_digest: source.consumer_digest,
                data_member_count: source.data_member_count,
                data_encoded_bytes: source.data_encoded_bytes,
                source_revision: source.source_revision,
                artifact_scan_revision: source.artifact_scan_revision,
                artifact_scan_digest: source.artifact_scan_digest,
                nats_scan_digest: source.nats_scan_digest,
            });
        }
        let slot = generation_slot(
            binding.assignment_ledger_slot,
            binding.assignment_digest,
        )?;
        let mut aggregate = Self {
            slot,
            revision: REVISION,
            network: binding.network,
            authority: binding.authority,
            context_digest: binding.context_digest,
            assignment_digest: binding.assignment_digest,
            close_intent: binding.close_intent,
            pipeline_store_fingerprint: binding.pipeline_store_fingerprint,
            pipeline_close_revision: binding.pipeline_close_revision,
            pipeline_close_receipt_digest: binding.pipeline_close_receipt_digest,
            publish_store_fingerprint: common_publish_store,
            assignment_store_fingerprint: binding.assignment_store_fingerprint,
            assignment_ledger_slot: binding.assignment_ledger_slot,
            assignment_ledger_revision: binding.assignment_ledger_revision,
            assignment_payload: binding.assignment_payload,
            artifact_store_fingerprint: common_artifact_store,
            total_data_members,
            total_data_encoded_bytes,
            sources,
            digest: PendingQueueSemanticGenerationDigest([1; 32]),
        };
        aggregate.digest = generation_digest(&aggregate.encode_unsigned())?;
        Ok(aggregate)
    }

    pub(super) const fn slot(&self) -> PendingQueueSemanticGenerationSlot { self.slot }

    pub(super) const fn digest(&self) -> PendingQueueSemanticGenerationDigest {
        self.digest
    }

    pub(super) const fn has_work(&self) -> bool { self.total_data_members != 0 }

    fn uses_work_handoff(&self) -> bool {
        self.authority == AuthorityScope::Coordinator || self.has_work()
    }

    fn seal_pipeline_handoff<Hash: Q256BitHash>(
        &self,
        pipeline: &StoredPendingPipeline<Hash>,
        assignment: &PendingQueueSegmentAssignmentReceipt,
    ) -> Result<SealedPendingPipelineTransition<Hash>, PendingQueueSemanticAggregateError> {
        if matches!(self.authority, AuthorityScope::Realm { .. }) {
            return Err(PendingQueueSemanticAggregateError::RealmApplicationArchiveRequired);
        }
        let context = assignment.assignment().context();
        if !self.matches_assignment(assignment)
            || pipeline.key() != context.key()
            || pipeline.activation_digest() != context.activation()
            || pipeline.processing() != context.processing()
            || pipeline.revision().get() != self.pipeline_close_revision
            || pipeline.processing_state() != PendingProcessingState::Sealing(self.close_intent)
        {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        if self.uses_work_handoff() {
            pipeline
                .seal_capture_work(
                    self.close_intent,
                    PendingWorkCaptureDigest::try_new(*self.slot.as_bytes())
                        .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?,
                )
                .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))
        } else {
            pipeline
                .seal_empty_queue(
                    self.close_intent,
                    PendingEmptyQueueSealDigest::try_new(*self.slot.as_bytes())
                        .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?,
                )
                .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))
        }
    }

    fn matches_generation_binding(
        &self,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
    ) -> bool {
        let assigned = assignment.assignment();
        self.network == assigned.context().key().network()
            && self.authority == assigned.context().key().authority()
            && self.context_digest == assigned.context().digest()
            && self.assignment_digest == assigned.digest()
            && self.close_intent == close.close_intent()
            && self.pipeline_store_fingerprint == *close.store_fingerprint().as_bytes()
            && self.pipeline_close_revision == close.revision().get()
            && self.pipeline_close_receipt_digest == *close.receipt_digest()
            && self.assignment_store_fingerprint
                == *assignment.store_fingerprint().as_bytes()
            && self.assignment_ledger_slot == *assignment.ledger_slot().as_bytes()
            && self.assignment_ledger_revision == assignment.ledger_revision().get()
            && self.assignment_payload == assigned.to_canonical_bytes()
            && close.matches_context(assigned.context())
    }

    fn matches_assignment(&self, assignment: &PendingQueueSegmentAssignmentReceipt) -> bool {
        let assigned = assignment.assignment();
        self.network == assigned.context().key().network()
            && self.authority == assigned.context().key().authority()
            && self.context_digest == assigned.context().digest()
            && self.assignment_digest == assigned.digest()
            && self.assignment_store_fingerprint
                == *assignment.store_fingerprint().as_bytes()
            && self.assignment_ledger_slot == *assignment.ledger_slot().as_bytes()
            && self.assignment_ledger_revision == assignment.ledger_revision().get()
            && self.assignment_payload == assigned.to_canonical_bytes()
    }

    pub(super) fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub(super) fn decode_persisted(
        selected_slot: PendingQueueSemanticGenerationSlot,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let revision = u64::try_from(selected_revision)
            .map_err(|_| PendingQueueSemanticAggregateError::RevisionMismatch)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(PendingQueueSemanticAggregateError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(PendingQueueSemanticAggregateError::UnknownCodecVersion);
        }
        let slot = PendingQueueSemanticGenerationSlot::try_new(decoder.array32()?)?;
        if slot != selected_slot {
            return Err(PendingQueueSemanticAggregateError::SlotMismatch);
        }
        let payload_revision = decoder.u64()?;
        if revision != REVISION || payload_revision != revision {
            return Err(PendingQueueSemanticAggregateError::RevisionMismatch);
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::InvalidAuthority)?;
        let authority_kind = decoder.u8()?;
        let realm_id = decoder.u32()?;
        let realm_sub_id = decoder.u16()?;
        let authority = match (authority_kind, realm_id, realm_sub_id) {
            (1, 0, 0) => AuthorityScope::Coordinator,
            (2, realm_id, realm_sub_id) => AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            },
            _ => return Err(PendingQueueSemanticAggregateError::InvalidAuthority),
        };
        let context_digest = PendingQueueCaptureContextDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let close_intent = PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
            .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?;
        let pipeline_store_fingerprint = decoder.array32()?;
        let pipeline_close_revision = decoder.u64()?;
        let pipeline_close_receipt_digest = decoder.array32()?;
        let publish_store_fingerprint = decoder.array32()?;
        let assignment_store_fingerprint = decoder.array32()?;
        let assignment_ledger_slot = decoder.array32()?;
        let assignment_ledger_revision = decoder.u64()?;
        let assignment_payload_len = usize::from(decoder.u16()?);
        let assignment_payload = decoder.take(assignment_payload_len)?.to_vec();
        let artifact_store_fingerprint = decoder.array32()?;
        if pipeline_store_fingerprint == [0; 32]
            || pipeline_close_revision == 0
            || pipeline_close_receipt_digest == [0; 32]
            || publish_store_fingerprint == [0; 32]
            || assignment_store_fingerprint == [0; 32]
            || assignment_ledger_slot == [0; 32]
            || assignment_ledger_revision == 0
            || assignment_payload.is_empty()
            || artifact_store_fingerprint == [0; 32]
        {
            return Err(PendingQueueSemanticAggregateError::EmptyDigest);
        }
        let total_data_members = decoder.u64()?;
        let total_data_encoded_bytes = decoder.u64()?;
        let count = usize::from(decoder.u8()?);
        if count != expected_roles(authority).len() {
            return Err(PendingQueueSemanticAggregateError::IncompleteSourceSet);
        }
        let mut sources = Vec::with_capacity(count);
        for expected in expected_roles(authority) {
            let publisher_kind = decode_publisher(decoder.u8()?)?;
            if publisher_kind != *expected {
                return Err(PendingQueueSemanticAggregateError::SourceSetMismatch);
            }
            sources.push(SemanticSourceEntry {
                publisher_kind,
                source_slot: PendingQueuePublishSourceSlot::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?,
                semantic_digest: PendingQueueSemanticSourceDigest::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueSemanticAggregateError::EmptyDigest)?,
                artifact_slot: decoder.array32()?,
                artifact_owner_attempt_id: decoder.array32()?,
                artifact_owner_fence: decoder.u64()?,
                consumer_digest: decoder.array32()?,
                data_member_count: decoder.u32()?,
                data_encoded_bytes: decoder.u64()?,
                source_revision: decoder.u64()?,
                artifact_scan_revision: decoder.u64()?,
                artifact_scan_digest: decoder.array32()?,
                nats_scan_digest: decoder.array32()?,
            });
        }
        let digest = PendingQueueSemanticGenerationDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueSemanticAggregateError::TrailingBytes);
        }
        let aggregate = Self {
            slot,
            revision,
            network,
            authority,
            context_digest,
            assignment_digest,
            close_intent,
            pipeline_store_fingerprint,
            pipeline_close_revision,
            pipeline_close_receipt_digest,
            publish_store_fingerprint,
            assignment_store_fingerprint,
            assignment_ledger_slot,
            assignment_ledger_revision,
            assignment_payload,
            artifact_store_fingerprint,
            total_data_members,
            total_data_encoded_bytes,
            sources,
            digest,
        };
        if aggregate.sources.iter().any(|source| {
            source.artifact_slot == [0; 32]
                || source.artifact_owner_attempt_id == [0; 32]
                || source.artifact_owner_fence == 0
                || source.consumer_digest == [0; 32]
                || source.source_revision == 0
                || source.artifact_scan_revision == 0
                || source.artifact_scan_digest == [0; 32]
                || source.nats_scan_digest == [0; 32]
        }) {
            return Err(PendingQueueSemanticAggregateError::EmptyDigest);
        }
        let (computed_members, computed_bytes) = checked_source_totals(&aggregate.sources)?;
        let ledger_slot = PendingQueueSegmentLedgerSlot::try_new(assignment_ledger_slot)
            .map_err(|_| PendingQueueSemanticAggregateError::AssignmentPayloadMismatch)?;
        let archived_assignment = PendingQueueGenerationSegmentAssignment::decode_canonical(
            ledger_slot,
            &aggregate.assignment_payload,
        )
        .map_err(|_| PendingQueueSemanticAggregateError::AssignmentPayloadMismatch)?;
        if generation_slot(assignment_ledger_slot, assignment_digest)? != slot
            || generation_digest(&aggregate.encode_unsigned())? != digest
            || computed_members != total_data_members
            || computed_bytes != total_data_encoded_bytes
            || archived_assignment.digest() != assignment_digest
            || archived_assignment.context().key().network() != network
            || archived_assignment.context().key().authority() != authority
            || archived_assignment.context().digest() != context_digest
            || archived_assignment.assigned_at_ledger_revision().get()
                != assignment_ledger_revision
            || archived_assignment.to_canonical_bytes()
                != aggregate.assignment_payload
        {
            return Err(PendingQueueSemanticAggregateError::DigestMismatch);
        }
        Ok(aggregate)
    }

    fn encode_unsigned(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(&self.revision.to_be_bytes());
        out.extend_from_slice(&self.network.chain_id().to_be_bytes());
        let (kind, realm, sub) = authority_parts(self.authority);
        out.push(kind);
        out.extend_from_slice(&realm.to_be_bytes());
        out.extend_from_slice(&sub.to_be_bytes());
        out.extend_from_slice(self.context_digest.as_bytes());
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(self.close_intent.as_bytes());
        out.extend_from_slice(&self.pipeline_store_fingerprint);
        out.extend_from_slice(&self.pipeline_close_revision.to_be_bytes());
        out.extend_from_slice(&self.pipeline_close_receipt_digest);
        out.extend_from_slice(&self.publish_store_fingerprint);
        out.extend_from_slice(&self.assignment_store_fingerprint);
        out.extend_from_slice(&self.assignment_ledger_slot);
        out.extend_from_slice(&self.assignment_ledger_revision.to_be_bytes());
        out.extend_from_slice(&(self.assignment_payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.assignment_payload);
        out.extend_from_slice(&self.artifact_store_fingerprint);
        out.extend_from_slice(&self.total_data_members.to_be_bytes());
        out.extend_from_slice(&self.total_data_encoded_bytes.to_be_bytes());
        out.push(self.sources.len() as u8);
        for source in &self.sources {
            out.push(source.publisher_kind as u8);
            out.extend_from_slice(source.source_slot.as_bytes());
            out.extend_from_slice(source.semantic_digest.as_bytes());
            out.extend_from_slice(&source.artifact_slot);
            out.extend_from_slice(&source.artifact_owner_attempt_id);
            out.extend_from_slice(&source.artifact_owner_fence.to_be_bytes());
            out.extend_from_slice(&source.consumer_digest);
            out.extend_from_slice(&source.data_member_count.to_be_bytes());
            out.extend_from_slice(&source.data_encoded_bytes.to_be_bytes());
            out.extend_from_slice(&source.source_revision.to_be_bytes());
            out.extend_from_slice(&source.artifact_scan_revision.to_be_bytes());
            out.extend_from_slice(&source.artifact_scan_digest);
            out.extend_from_slice(&source.nats_scan_digest);
        }
        out
    }
}

fn generation_digest(
    canonical_unsigned: &[u8],
) -> Result<PendingQueueSemanticGenerationDigest, PendingQueueSemanticAggregateError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update(canonical_unsigned);
    PendingQueueSemanticGenerationDigest::try_new(hasher.finalize().into())
}

fn checked_source_totals(
    sources: &[SemanticSourceEntry],
) -> Result<(u64, u64), PendingQueueSemanticAggregateError> {
    sources.iter().try_fold((0u64, 0u64), |(members, bytes), source| {
        Ok((
            members
                .checked_add(u64::from(source.data_member_count))
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?,
            bytes
                .checked_add(source.data_encoded_bytes)
                .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?,
        ))
    })
}

fn generation_slot(
    assignment_ledger_slot: [u8; 32],
    assignment: PendingQueueSegmentAssignmentDigest,
) -> Result<PendingQueueSemanticGenerationSlot, PendingQueueSemanticAggregateError> {
    let mut hasher = Sha256::new();
    hasher.update(ARCHIVE_SLOT_DOMAIN);
    hasher.update(assignment_ledger_slot);
    hasher.update(assignment.as_bytes());
    PendingQueueSemanticGenerationSlot::try_new(hasher.finalize().into())
}

fn expected_roles(authority: AuthorityScope) -> &'static [PendingQueuePublisherKind] {
    const COORDINATOR: &[PendingQueuePublisherKind] = &[
        PendingQueuePublisherKind::CoordinatorRegistration,
        PendingQueuePublisherKind::CoordinatorDeploy,
        PendingQueuePublisherKind::CoordinatorGuta,
    ];
    const REALM: &[PendingQueuePublisherKind] =
        &[PendingQueuePublisherKind::RealmUserUpdate];
    match authority {
        AuthorityScope::Coordinator => COORDINATOR,
        AuthorityScope::Realm { .. } => REALM,
    }
}

fn authority_parts(authority: AuthorityScope) -> (u8, u32, u16) {
    match authority {
        AuthorityScope::Coordinator => (1, 0, 0),
        AuthorityScope::Realm { realm_id, realm_sub_id } => (2, realm_id, realm_sub_id),
    }
}

fn decode_publisher(value: u8) -> Result<PendingQueuePublisherKind, PendingQueueSemanticAggregateError> {
    match value {
        1 => Ok(PendingQueuePublisherKind::CoordinatorRegistration),
        2 => Ok(PendingQueuePublisherKind::CoordinatorDeploy),
        3 => Ok(PendingQueuePublisherKind::CoordinatorGuta),
        32 => Ok(PendingQueuePublisherKind::RealmUserUpdate),
        _ => Err(PendingQueueSemanticAggregateError::SourceSetMismatch),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct PendingQueueSemanticAggregateQueries {
    create: String,
    read: String,
    bootstrap: String,
}

impl PendingQueueSemanticAggregateQueries {
    fn new(keyspace: &BranchExactDeploymentNoTabletKeyspace) -> Self {
        let table = format!("{}.{}", keyspace.as_str(), PENDING_QUEUE_SEMANTIC_GENERATION_TABLE);
        Self {
            create: format!("CREATE TABLE IF NOT EXISTS {table} (generation_slot blob PRIMARY KEY, revision bigint, aggregate_payload blob)"),
            read: format!("SELECT revision, aggregate_payload FROM {table} WHERE generation_slot = ?"),
            bootstrap: format!("INSERT INTO {table} (generation_slot, revision, aggregate_payload) VALUES (?, ?, ?) IF NOT EXISTS"),
        }
    }

    fn golden(&self) -> String {
        format!("create\n{}\n\nread\n{}\nBLOB\n\nbootstrap\n{}\nBLOB,BIGINT,BLOB\n", self.create, self.read, self.bootstrap)
    }
}

pub(super) struct ScyllaPendingQueueSemanticAggregateStore {
    session: Arc<Session>,
    fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    read: PreparedStatement,
    bootstrap: PreparedStatement,
}

#[derive(Debug)]
pub(super) struct PersistedPendingQueueSemanticGenerationReceipt {
    store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    aggregate: StoredPendingQueueSemanticGeneration,
}

/// Opaque exact readback that the immutable semantic aggregate was durable
/// before the pipeline left `Sealing(close)`. This is not a rotation or GC
/// permit.
#[derive(Debug)]
pub(super) struct PersistedPendingQueueSemanticHandoffReceipt {
    aggregate_store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    aggregate_slot: PendingQueueSemanticGenerationSlot,
    aggregate_digest: PendingQueueSemanticGenerationDigest,
    pipeline_revision: PendingPipelineRevision,
    pipeline_state: PendingProcessingState,
}

/// Exact archive plus terminal pipeline readback. This receipt can authorize
/// creation of an immutable generation-terminal row, but is deliberately not
/// itself a pipeline-rotation or segment-GC permit.
#[derive(Debug)]
pub(super) struct PersistedPendingQueueTerminalArchiveReceipt<Hash> {
    aggregate_store_fingerprint: PendingQueueSemanticAggregateStoreFingerprint,
    aggregate_slot: PendingQueueSemanticGenerationSlot,
    aggregate_digest: PendingQueueSemanticGenerationDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    pipeline_store_fingerprint: [u8; 32],
    pipeline: StoredPendingPipeline<Hash>,
}

impl<Hash> PersistedPendingQueueTerminalArchiveReceipt<Hash> {
    pub(super) const fn aggregate_store_fingerprint(
        &self,
    ) -> PendingQueueSemanticAggregateStoreFingerprint {
        self.aggregate_store_fingerprint
    }
    pub(super) const fn aggregate_slot(&self) -> PendingQueueSemanticGenerationSlot {
        self.aggregate_slot
    }

    pub(super) const fn aggregate_digest(&self) -> PendingQueueSemanticGenerationDigest {
        self.aggregate_digest
    }

    pub(super) const fn assignment_digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.assignment_digest
    }

    pub(super) const fn pipeline(&self) -> &StoredPendingPipeline<Hash> {
        &self.pipeline
    }
}

impl PersistedPendingQueueSemanticHandoffReceipt {
    pub(super) const fn aggregate_digest(&self) -> PendingQueueSemanticGenerationDigest {
        self.aggregate_digest
    }

    pub(super) const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }
}

impl PersistedPendingQueueSemanticGenerationReceipt {
    pub(super) const fn authority(&self) -> AuthorityScope { self.aggregate.authority }

    pub(super) const fn has_data_work(&self) -> bool { self.aggregate.has_work() }

    pub(super) const fn slot(&self) -> PendingQueueSemanticGenerationSlot {
        self.aggregate.slot
    }

    pub(super) const fn digest(&self) -> PendingQueueSemanticGenerationDigest {
        self.aggregate.digest
    }

    pub(super) fn realm_application_binding(
        &self,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        semantic: &RealmProcessorSemanticOutput,
    ) -> Result<RealmProcessorApplicationArchiveBinding, PendingQueueSemanticAggregateError> {
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = self.aggregate.authority
        else {
            return Err(PendingQueueSemanticAggregateError::RealmApplicationArchiveRequired);
        };
        if !self.aggregate.matches_generation_binding(assignment, close)
            || self.aggregate.context_digest.as_bytes()
                != semantic.context_digest().as_bytes()
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        RealmProcessorApplicationArchiveBinding::try_new(
            self.aggregate.network.chain_id(),
            realm_id,
            realm_sub_id,
            *self.store_fingerprint.as_bytes(),
            *self.aggregate.slot.as_bytes(),
            *self.aggregate.digest.as_bytes(),
            *self.aggregate.assignment_digest.as_bytes(),
            self.aggregate.pipeline_store_fingerprint,
            self.aggregate.pipeline_close_revision,
            self.aggregate.pipeline_close_receipt_digest,
            *self.aggregate.close_intent.as_bytes(),
        )
        .map_err(|error| PendingQueueSemanticAggregateError::ApplicationArchive(error.to_string()))
    }
}

impl ScyllaPendingQueueSemanticAggregateStore {
    pub(super) async fn create_schema(
        session: &Session,
        keyspace: &BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        let queries = PendingQueueSemanticAggregateQueries::new(keyspace);
        session.query_unpaged(queries.create, &[]).await.map_err(cql)?;
        session.await_schema_agreement().await.map_err(cql)?;
        Ok(())
    }

    pub(super) async fn prepare(
        session: Arc<Session>,
        keyspace: BranchExactDeploymentNoTabletKeyspace,
    ) -> Result<Self, PendingQueueSemanticAggregateError> {
        let queries = PendingQueueSemanticAggregateQueries::new(&keyspace);
        let fingerprint = store_fingerprint(&keyspace, &queries);
        Ok(Self {
            read: prepare_read(&session, queries.read).await?,
            bootstrap: prepare_lwt(&session, queries.bootstrap).await?,
            session,
            fingerprint,
        })
    }

    /// CAS-response-loss recovery cannot recreate the old `Sealing` receipt.
    /// Instead it point-reads the immutable transport aggregate committed by
    /// the selected application header and checks every persisted binding.
    pub(super) async fn revalidate_realm_application_header(
        &self,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        header: &RealmProcessorApplicationArchiveHeader,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        let binding = header.binding();
        if binding.transport_store_fingerprint() != self.fingerprint.as_bytes() {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        let slot = PendingQueueSemanticGenerationSlot::try_new(*binding.transport_slot())?;
        let current = self
            .read(slot)
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        let context = assignment.assignment().context();
        let AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } = current.authority
        else {
            return Err(PendingQueueSemanticAggregateError::RealmApplicationArchiveRequired);
        };
        if current.slot != slot
            || current.digest.as_bytes() != binding.transport_digest()
            || !current.matches_assignment(assignment)
            || current.network != context.key().network()
            || realm_id != binding.realm_id()
            || realm_sub_id != binding.realm_sub_id()
            || current.context_digest.as_bytes() != header.context_digest()
            || current.assignment_digest.as_bytes() != binding.assignment_digest()
            || current.pipeline_store_fingerprint != *binding.pipeline_store_fingerprint()
            || current.pipeline_close_revision != binding.pipeline_close_revision()
            || current.pipeline_close_receipt_digest
                != *binding.pipeline_close_receipt_digest()
            || current.close_intent.as_bytes() != binding.close_intent_digest()
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        Ok(())
    }

    async fn read(
        &self,
        slot: PendingQueueSemanticGenerationSlot,
    ) -> Result<Option<StoredPendingQueueSemanticGeneration>, PendingQueueSemanticAggregateError> {
        let row = self.session.execute_unpaged(&self.read, (slot.as_bytes().as_slice(),))
            .await.map_err(cql)?.into_rows_result().map_err(cql)?
            .maybe_first_row::<(Option<i64>, Option<Vec<u8>>)>().map_err(cql)?;
        let Some((revision, payload)) = row else { return Ok(None) };
        Ok(Some(StoredPendingQueueSemanticGeneration::decode_persisted(
            slot,
            revision.ok_or(PendingQueueSemanticAggregateError::MissingColumn)?,
            payload.as_deref().ok_or(PendingQueueSemanticAggregateError::MissingColumn)?,
        )?))
    }

    /// Reconstructs the expected durable-consumer commitments for one exact
    /// archived assignment. The caller supplies the archive slot/digest that
    /// was independently committed by the immutable generation terminal.
    pub(super) async fn observe_archived_consumers(
        &self,
        ledger_slot: PendingQueueSegmentLedgerSlot,
        assignment: &PendingQueueGenerationSegmentAssignment,
        archive_slot: [u8; 32],
        archive_digest: [u8; 32],
    ) -> Result<Vec<PendingQueueArchivedConsumerCommitment>, PendingQueueSemanticAggregateError>
    {
        let slot = PendingQueueSemanticGenerationSlot::try_new(archive_slot)?;
        let current = self
            .read(slot)
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        if current.slot != slot
            || current.digest.as_bytes() != &archive_digest
            || current.assignment_ledger_slot != *ledger_slot.as_bytes()
            || current.assignment_digest != assignment.digest()
            || current.assignment_payload != assignment.to_canonical_bytes()
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        Ok(current
            .sources
            .iter()
            .map(|source| PendingQueueArchivedConsumerCommitment {
                publisher_kind: source.publisher_kind,
                consumer_digest: source.consumer_digest,
            })
            .collect())
    }

    pub(super) async fn persist_verified<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        candidate: &StoredPendingQueueSemanticGeneration,
    ) -> Result<PersistedPendingQueueSemanticGenerationReceipt, PendingQueueSemanticAggregateError> {
        if !candidate.matches_generation_binding(assignment, close) {
            return Err(PendingQueueSemanticAggregateError::CandidateBindingMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        let payload = candidate.to_persisted_bytes();
        let execution = self.session.execute_unpaged(
            &self.bootstrap,
            (candidate.slot().as_bytes().as_slice(), REVISION as i64, payload.as_slice()),
        ).await;
        let applied = match execution {
            Ok(result) => decode_applied(result)?,
            Err(error) => match self.read(candidate.slot()).await {
                Ok(Some(current)) if &current == candidate => false,
                Ok(_) => return Err(PendingQueueSemanticAggregateError::Indeterminate(error.to_string())),
                Err(read) => return Err(PendingQueueSemanticAggregateError::Indeterminate(format!("execute={error}; read={read}"))),
            },
        };
        let current = self.read(candidate.slot()).await?
            .ok_or(PendingQueueSemanticAggregateError::MissingAfterLwt)?;
        if &current != candidate {
            return Err(if applied {
                PendingQueueSemanticAggregateError::AppliedStateMismatch
            } else {
                PendingQueueSemanticAggregateError::Conflict
            });
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        Ok(PersistedPendingQueueSemanticGenerationReceipt {
            store_fingerprint: self.fingerprint,
            aggregate: current,
        })
    }

    pub(super) async fn revalidate_exact<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipt: &PersistedPendingQueueSemanticGenerationReceipt,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        if receipt.store_fingerprint != self.fingerprint
            || !receipt.aggregate.matches_generation_binding(assignment, close)
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        let current = self
            .read(receipt.aggregate.slot())
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        if current != receipt.aggregate {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        pipeline_store
            .revalidate_queue_close_exact::<Hash>(assignment.assignment().context(), close)
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        Ok(())
    }

    async fn revalidate_aggregate_receipt(
        &self,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipt: &PersistedPendingQueueSemanticGenerationReceipt,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        if receipt.store_fingerprint != self.fingerprint
            || !receipt.aggregate.matches_generation_binding(assignment, close)
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        let current = self
            .read(receipt.aggregate.slot())
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        if current != receipt.aggregate {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        Ok(())
    }

    /// Publish the already-durable semantic aggregate into the authority
    /// pipeline. The aggregate row is the immutable pre-CAS handoff intent;
    /// pipeline CAS response loss is classified by exact candidate readback.
    pub(super) async fn handoff_to_pipeline<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        close: &PersistedPendingQueueCloseReceipt,
        receipt: &PersistedPendingQueueSemanticGenerationReceipt,
    ) -> Result<PersistedPendingQueueSemanticHandoffReceipt, PendingQueueSemanticAggregateError> {
        self.revalidate_aggregate_receipt(assignment, close, receipt)
            .await?;
        let context = assignment.assignment().context();
        let PendingPipelineReadState::Current(current) =
            pipeline_store.read::<Hash>(context.key()).await
                .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?
        else {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        };
        if !matches!(current.processing_state(), PendingProcessingState::Sealing(_)) {
            let recovered = self
                .recover_handoff_from_pipeline::<Hash>(pipeline_store, assignment)
                .await?;
            if recovered.aggregate_slot != receipt.aggregate.slot()
                || recovered.aggregate_digest != receipt.aggregate.digest()
            {
                return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
            }
            return Ok(recovered);
        }
        let transition = receipt.aggregate.seal_pipeline_handoff(&current, assignment)?;
        let expected_candidate = transition.candidate().clone();
        let outcome = pipeline_store.apply(&transition).await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?;
        let observed = match outcome {
            PendingPipelineWriteOutcome::Applied(current)
            | PendingPipelineWriteOutcome::Idempotent(current) => current,
            PendingPipelineWriteOutcome::Conflict(_) => {
                let recovered = self
                    .recover_handoff_from_pipeline::<Hash>(pipeline_store, assignment)
                    .await?;
                if recovered.aggregate_slot != receipt.aggregate.slot()
                    || recovered.aggregate_digest != receipt.aggregate.digest()
                {
                    return Err(PendingQueueSemanticAggregateError::PipelineHandoffConflict);
                }
                return Ok(recovered);
            }
        };
        if observed != expected_candidate {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        let exact_aggregate = self.read(receipt.aggregate.slot()).await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        if exact_aggregate != receipt.aggregate {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        Ok(PersistedPendingQueueSemanticHandoffReceipt {
            aggregate_store_fingerprint: self.fingerprint,
            aggregate_slot: exact_aggregate.slot(),
            aggregate_digest: exact_aggregate.digest(),
            pipeline_revision: observed.revision(),
            pipeline_state: observed.processing_state(),
        })
    }

    /// Recover an exact handoff after the pipeline CAS committed but the
    /// process died before returning its receipt. The pipeline evidence is the
    /// immutable aggregate row's point-read slot, so recovery needs no scan and
    /// does not try to recreate the stale `Sealing` receipt.
    pub(super) async fn recover_handoff_from_pipeline<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
    ) -> Result<PersistedPendingQueueSemanticHandoffReceipt, PendingQueueSemanticAggregateError> {
        let context = assignment.assignment().context();
        if matches!(context.key().authority(), AuthorityScope::Realm { .. }) {
            return Err(PendingQueueSemanticAggregateError::RealmApplicationArchiveRequired);
        }
        let PendingPipelineReadState::Current(current) =
            pipeline_store.read::<Hash>(context.key()).await
                .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?
        else {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        };
        if current.key() != context.key()
            || current.activation_digest() != context.activation()
            || current.processing() != context.processing()
            || current.blocked_reason().is_some()
        {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        let (slot, observed_work) = terminal_handoff_slot(current.processing_state())?;
        let aggregate = self.read(slot).await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        let first_handoff_revision = aggregate.pipeline_close_revision
            .checked_add(1)
            .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
        if !aggregate.matches_assignment(assignment)
            || aggregate.slot != slot
            || aggregate.uses_work_handoff() != observed_work
            || aggregate.pipeline_store_fingerprint
                != *pipeline_store.fingerprint().as_bytes()
            || current.revision().get() != first_handoff_revision
        {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        Ok(PersistedPendingQueueSemanticHandoffReceipt {
            aggregate_store_fingerprint: self.fingerprint,
            aggregate_slot: aggregate.slot(),
            aggregate_digest: aggregate.digest(),
            pipeline_revision: current.revision(),
            pipeline_state: current.processing_state(),
        })
    }

    /// Reconstruct terminal eligibility from durable rows after the first
    /// handoff receipt has been lost. Only exact Published/RetiredNoWork
    /// descendants are accepted, with the expected path length from the
    /// archived Sealing revision.
    pub(super) async fn revalidate_terminal_archive<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
    ) -> Result<PersistedPendingQueueTerminalArchiveReceipt<Hash>, PendingQueueSemanticAggregateError> {
        let context = assignment.assignment().context();
        if matches!(context.key().authority(), AuthorityScope::Realm { .. }) {
            return Err(PendingQueueSemanticAggregateError::RealmApplicationArchiveRequired);
        }
        let PendingPipelineReadState::Current(current) = pipeline_store
            .read::<Hash>(context.key())
            .await
            .map_err(|error| PendingQueueSemanticAggregateError::Pipeline(error.to_string()))?
        else {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        };
        if current.key() != context.key()
            || current.activation_digest() != context.activation()
            || current.processing() != context.processing()
            || current.blocked_reason().is_some()
        {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        let (slot, observed_work, revision_delta) =
            terminal_archive_slot(current.processing_state())?;
        let aggregate = self
            .read(slot)
            .await?
            .ok_or(PendingQueueSemanticAggregateError::ReceiptStale)?;
        let expected_revision = aggregate
            .pipeline_close_revision
            .checked_add(revision_delta)
            .ok_or(PendingQueueSemanticAggregateError::CounterOverflow)?;
        if !aggregate.matches_assignment(assignment)
            || aggregate.slot != slot
            || aggregate.uses_work_handoff() != observed_work
            || aggregate.pipeline_store_fingerprint
                != *pipeline_store.fingerprint().as_bytes()
            || current.revision().get() != expected_revision
        {
            return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch);
        }
        Ok(PersistedPendingQueueTerminalArchiveReceipt {
            aggregate_store_fingerprint: self.fingerprint,
            aggregate_slot: aggregate.slot(),
            aggregate_digest: aggregate.digest(),
            assignment_digest: aggregate.assignment_digest,
            pipeline_store_fingerprint: aggregate.pipeline_store_fingerprint,
            pipeline: current,
        })
    }

    pub(super) async fn revalidate_terminal_archive_receipt<Hash: Q256BitHash>(
        &self,
        pipeline_store: &ScyllaPendingPipelineStore,
        assignment: &PendingQueueSegmentAssignmentReceipt,
        receipt: &PersistedPendingQueueTerminalArchiveReceipt<Hash>,
    ) -> Result<(), PendingQueueSemanticAggregateError> {
        if receipt.aggregate_store_fingerprint != self.fingerprint
            || receipt.pipeline_store_fingerprint
                != *pipeline_store.fingerprint().as_bytes()
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptBindingMismatch);
        }
        let current = self
            .revalidate_terminal_archive::<Hash>(pipeline_store, assignment)
            .await?;
        if current.aggregate_slot != receipt.aggregate_slot
            || current.aggregate_digest != receipt.aggregate_digest
            || current.assignment_digest != receipt.assignment_digest
            || current.pipeline != receipt.pipeline
        {
            return Err(PendingQueueSemanticAggregateError::ReceiptStale);
        }
        Ok(())
    }
}

fn terminal_handoff_slot(
    state: PendingProcessingState,
) -> Result<(PendingQueueSemanticGenerationSlot, bool), PendingQueueSemanticAggregateError> {
    let (bytes, work) = match state {
        PendingProcessingState::WorkCaptured(capture) => (*capture.as_bytes(), true),
        PendingProcessingState::EmptyQueueSealed(seal) => (*seal.as_bytes(), false),
        _ => return Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch),
    };
    Ok((PendingQueueSemanticGenerationSlot::try_new(bytes)?, work))
}

fn terminal_archive_slot(
    state: PendingProcessingState,
) -> Result<(PendingQueueSemanticGenerationSlot, bool, u64), PendingQueueSemanticAggregateError> {
    let (bytes, work, revision_delta) = match state {
        PendingProcessingState::Published { capture, .. } => {
            (*capture.as_bytes(), true, 3)
        }
        PendingProcessingState::RetiredNoWork { seal, .. } => {
            (*seal.as_bytes(), false, 2)
        }
        _ => return Err(PendingQueueSemanticAggregateError::PipelineTerminalMismatch),
    };
    Ok((
        PendingQueueSemanticGenerationSlot::try_new(bytes)?,
        work,
        revision_delta,
    ))
}

fn store_fingerprint(
    keyspace: &BranchExactDeploymentNoTabletKeyspace,
    queries: &PendingQueueSemanticAggregateQueries,
) -> PendingQueueSemanticAggregateStoreFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(STORE_FINGERPRINT_DOMAIN);
    hasher.update((keyspace.as_str().len() as u64).to_be_bytes());
    hasher.update(keyspace.as_str().as_bytes());
    hasher.update((queries.golden().len() as u64).to_be_bytes());
    hasher.update(queries.golden().as_bytes());
    PendingQueueSemanticAggregateStoreFingerprint(hasher.finalize().into())
}

async fn prepare_read(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueSemanticAggregateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_is_idempotent(true);
    Ok(statement)
}

async fn prepare_lwt(session: &Session, cql_text: String) -> Result<PreparedStatement, PendingQueueSemanticAggregateError> {
    let mut statement = session.prepare(cql_text).await.map_err(cql)?;
    statement.set_consistency(Consistency::Quorum);
    statement.set_serial_consistency(Some(SerialConsistency::LocalSerial));
    statement.set_is_idempotent(true);
    Ok(statement)
}

fn decode_applied(result: QueryResult) -> Result<bool, PendingQueueSemanticAggregateError> {
    let rows = result.into_rows_result().map_err(cql)?;
    let column = rows.column_specs().get_by_name("[applied]")
        .ok_or(PendingQueueSemanticAggregateError::MissingAppliedColumn)?;
    let row = rows.single_row::<Row>().map_err(cql)?;
    match row.columns.get(column.0) {
        Some(Some(CqlValue::Boolean(value))) => Ok(*value),
        _ => Err(PendingQueueSemanticAggregateError::InvalidAppliedColumn),
    }
}

fn cql(error: impl fmt::Display) -> PendingQueueSemanticAggregateError {
    PendingQueueSemanticAggregateError::Cql(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum PendingQueueSemanticAggregateError {
    Cql(String),
    Pipeline(String),
    EmptyDigest,
    InvalidMagic,
    UnknownCodecVersion,
    SlotMismatch,
    RevisionMismatch,
    InvalidAuthority,
    IncompleteSourceSet,
    SourceSetMismatch,
    GenerationMismatch,
    CandidateBindingMismatch,
    ReceiptBindingMismatch,
    ReceiptStale,
    PipelineHandoffMismatch,
    PipelineHandoffConflict,
    PipelineTerminalMismatch,
    RealmApplicationArchiveRequired,
    ApplicationArchive(String),
    AssignmentPayloadMismatch,
    CounterOverflow,
    DigestMismatch,
    TrailingBytes,
    Truncated,
    MissingColumn,
    MissingAppliedColumn,
    InvalidAppliedColumn,
    MissingAfterLwt,
    AppliedStateMismatch,
    Conflict,
    Indeterminate(String),
}

impl fmt::Display for PendingQueueSemanticAggregateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}

impl Error for PendingQueueSemanticAggregateError {}

struct Decoder<'a> { bytes: &'a [u8], cursor: usize }

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueSemanticAggregateError> {
        let end = self.cursor.checked_add(len).ok_or(PendingQueueSemanticAggregateError::Truncated)?;
        let value = self.bytes.get(self.cursor..end).ok_or(PendingQueueSemanticAggregateError::Truncated)?;
        self.cursor = end;
        Ok(value)
    }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueSemanticAggregateError> { self.take(32)?.try_into().map_err(|_| PendingQueueSemanticAggregateError::Truncated) }
    fn u8(&mut self) -> Result<u8, PendingQueueSemanticAggregateError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueSemanticAggregateError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, PendingQueueSemanticAggregateError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueSemanticAggregateError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn done(&self) -> bool { self.cursor == self.bytes.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psy_node_core::{
        queue::recoverable_ephemeral::PendingQueueCaptureContext,
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
        store::pending_generation_pipeline::{
            PendingNoWorkReceiptDigest, PendingPipelineIntentDigest,
            PendingPublishReceiptDigest,
        },
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap, PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueSourceQuota,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    #[test]
    fn realm_transport_archive_cannot_bypass_application_archive_handoff() {
        let source = include_str!("pending_queue_semantic_aggregate.rs");
        let seal = source
            .split("fn seal_pipeline_handoff")
            .nth(1)
            .unwrap()
            .split("fn matches_generation_binding")
            .next()
            .unwrap();
        assert!(seal.contains("RealmApplicationArchiveRequired"));
        let recovery = source
            .split("pub(super) async fn recover_handoff_from_pipeline")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn revalidate_terminal_archive")
            .next()
            .unwrap();
        assert!(recovery.contains("RealmApplicationArchiveRequired"));
        let terminal = source
            .split("pub(super) async fn revalidate_terminal_archive")
            .nth(1)
            .unwrap()
            .split("pub(super) async fn revalidate_terminal_archive_receipt")
            .next()
            .unwrap();
        assert!(terminal.contains("RealmApplicationArchiveRequired"));
    }

    fn binding(authority: AuthorityScope) -> SemanticGenerationBinding {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([0xa5; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(7, 99).unwrap(),
        )
        .unwrap();
        let retention = RecoverableNatsRetentionContract::try_new(
            3,
            1024 * 1024 * 1024,
            128 * 1024 * 1024,
            3,
            16,
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention,
        )
        .unwrap();
        let attested = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let mib = 1024 * 1024_u64;
        let quotas = match authority {
            AuthorityScope::Coordinator => vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorRegistration,
                    10,
                    15 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorDeploy,
                    10,
                    47 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorGuta,
                    10,
                    63 * mib,
                    mib,
                )
                .unwrap(),
            ],
            AuthorityScope::Realm { .. } => vec![PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::RealmUserUpdate,
                10,
                127 * mib,
                mib,
            )
            .unwrap()],
        };
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            128 * mib,
        )
        .unwrap();
        let ledger = PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &attested,
            budget,
            8,
        )
        .unwrap();
        let plan = ledger.candidate().reserve_generation(context).unwrap();
        let PendingQueueSegmentReservationPlan::Advance { assignment, .. } = plan else {
            unreachable!()
        };
        SemanticGenerationBinding {
            network: NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
            context_digest: context.digest(),
            assignment_digest: assignment.digest(),
            close_intent: PendingQueueCloseIntentDigest::try_new([3; 32]).unwrap(),
            pipeline_store_fingerprint: [7; 32],
            pipeline_close_revision: 6,
            pipeline_close_receipt_digest: [4; 32],
            assignment_store_fingerprint: [5; 32],
            assignment_ledger_slot: *ledger.candidate().key().slot().as_bytes(),
            assignment_ledger_revision: assignment.assigned_at_ledger_revision().get(),
            assignment_payload: assignment.to_canonical_bytes(),
        }
    }

    fn commitment(
        binding: &SemanticGenerationBinding,
        role: PendingQueuePublisherKind,
        index: u8,
    ) -> PendingQueueSemanticSourceCommitment {
        PendingQueueSemanticSourceCommitment {
            publisher_kind: role,
            context_digest: binding.context_digest,
            assignment_digest: binding.assignment_digest,
            close_intent: binding.close_intent,
            pipeline_close_receipt_digest: binding.pipeline_close_receipt_digest,
            publish_store_fingerprint: [8; 32],
            assignment_store_fingerprint: binding.assignment_store_fingerprint,
            assignment_ledger_slot: binding.assignment_ledger_slot,
            assignment_ledger_revision: binding.assignment_ledger_revision,
            artifact_store_fingerprint: [9; 32],
            artifact_slot: [index + 20; 32],
            artifact_owner_attempt_id: [index + 30; 32],
            artifact_owner_fence: u64::from(index),
            consumer_digest: [index + 40; 32],
            source_slot: PendingQueuePublishSourceSlot::try_new([index; 32]).unwrap(),
            semantic_digest: PendingQueueSemanticSourceDigest::try_new([index + 10; 32]).unwrap(),
            data_member_count: u32::from(index),
            data_encoded_bytes: u64::from(index) * 100,
            source_revision: u64::from(index) + 50,
            artifact_scan_revision: u64::from(index) + 60,
            artifact_scan_digest: [index + 50; 32],
            nats_scan_digest: [index + 60; 32],
        }
    }

    fn coordinator_sources(
        binding: &SemanticGenerationBinding,
    ) -> Vec<PendingQueueSemanticSourceCommitment> {
        vec![
            commitment(binding, PendingQueuePublisherKind::CoordinatorGuta, 3),
            commitment(binding, PendingQueuePublisherKind::CoordinatorRegistration, 1),
            commitment(binding, PendingQueuePublisherKind::CoordinatorDeploy, 2),
        ]
    }

    #[test]
    fn fixed_three_and_one_source_sets_are_deterministic() {
        let coordinator_binding = binding(AuthorityScope::Coordinator);
        let first = StoredPendingQueueSemanticGeneration::from_commitments(
            coordinator_binding.clone(),
            coordinator_sources(&coordinator_binding),
        ).unwrap();
        let mut reversed = coordinator_sources(&coordinator_binding);
        reversed.reverse();
        let second = StoredPendingQueueSemanticGeneration::from_commitments(
            coordinator_binding,
            reversed,
        ).unwrap();
        assert_eq!(first, second);
        assert!(first.has_work());
        let realm_binding = binding(AuthorityScope::Realm { realm_id: 3, realm_sub_id: 0 });
        let realm = StoredPendingQueueSemanticGeneration::from_commitments(
            realm_binding.clone(),
            vec![commitment(&realm_binding, PendingQueuePublisherKind::RealmUserUpdate, 1)],
        ).unwrap();
        assert_eq!(realm.sources.len(), 1);
    }

    #[test]
    fn pipeline_handoff_slot_is_point_readable_and_strictly_first_phase() {
        let coordinator_binding = binding(AuthorityScope::Coordinator);
        let mut coordinator_empty = coordinator_sources(&coordinator_binding);
        for source in &mut coordinator_empty {
            source.data_member_count = 0;
            source.data_encoded_bytes = 0;
        }
        let coordinator = StoredPendingQueueSemanticGeneration::from_commitments(
            coordinator_binding.clone(),
            coordinator_empty,
        )
        .unwrap();
        assert!(!coordinator.has_work());
        assert!(coordinator.uses_work_handoff());
        let work = PendingWorkCaptureDigest::try_new(*coordinator.slot().as_bytes()).unwrap();
        assert_eq!(
            terminal_handoff_slot(PendingProcessingState::WorkCaptured(work)).unwrap(),
            (coordinator.slot(), true)
        );

        let realm_binding = binding(AuthorityScope::Realm {
            realm_id: 3,
            realm_sub_id: 0,
        });
        let mut realm_source = commitment(
            &realm_binding,
            PendingQueuePublisherKind::RealmUserUpdate,
            1,
        );
        realm_source.data_member_count = 0;
        realm_source.data_encoded_bytes = 0;
        let realm = StoredPendingQueueSemanticGeneration::from_commitments(
            realm_binding,
            vec![realm_source],
        )
        .unwrap();
        assert!(!realm.uses_work_handoff());
        assert_ne!(coordinator.slot(), realm.slot());
        let empty = PendingEmptyQueueSealDigest::try_new(*realm.slot().as_bytes()).unwrap();
        assert_eq!(
            terminal_handoff_slot(PendingProcessingState::EmptyQueueSealed(empty)).unwrap(),
            (realm.slot(), false)
        );
        assert_eq!(
            terminal_handoff_slot(PendingProcessingState::Sealing(
                coordinator_binding.close_intent,
            )),
            Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch)
        );
        assert_eq!(
            terminal_handoff_slot(PendingProcessingState::InFlight {
                capture: work,
                intent: PendingPipelineIntentDigest::try_new([91; 32]).unwrap(),
            }),
            Err(PendingQueueSemanticAggregateError::PipelineHandoffMismatch)
        );
    }

    #[test]
    fn terminal_archive_slot_accepts_only_exact_terminal_descendants() {
        let slot = PendingQueueSemanticGenerationSlot::try_new([71; 32]).unwrap();
        let capture = PendingWorkCaptureDigest::try_new(*slot.as_bytes()).unwrap();
        let seal = PendingEmptyQueueSealDigest::try_new(*slot.as_bytes()).unwrap();
        assert_eq!(
            terminal_archive_slot(PendingProcessingState::Published {
                capture,
                receipt: PendingPublishReceiptDigest::try_new([72; 32]).unwrap(),
            })
            .unwrap(),
            (slot, true, 3)
        );
        assert_eq!(
            terminal_archive_slot(PendingProcessingState::RetiredNoWork {
                seal,
                receipt: PendingNoWorkReceiptDigest::try_new([73; 32]).unwrap(),
            })
            .unwrap(),
            (slot, false, 2)
        );
        assert_eq!(
            terminal_archive_slot(PendingProcessingState::WorkCaptured(capture)),
            Err(PendingQueueSemanticAggregateError::PipelineTerminalMismatch)
        );
    }

    #[test]
    fn archive_slot_is_assignment_only_and_second_close_conflicts() {
        let first_binding = binding(AuthorityScope::Coordinator);
        let first = StoredPendingQueueSemanticGeneration::from_commitments(
            first_binding.clone(),
            coordinator_sources(&first_binding),
        )
        .unwrap();
        let mut second_binding = first_binding.clone();
        second_binding.close_intent =
            PendingQueueCloseIntentDigest::try_new([77; 32]).unwrap();
        second_binding.pipeline_close_receipt_digest = [78; 32];
        let second = StoredPendingQueueSemanticGeneration::from_commitments(
            second_binding.clone(),
            coordinator_sources(&second_binding),
        )
        .unwrap();

        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.to_persisted_bytes(), second.to_persisted_bytes());
    }

    #[test]
    fn full_assignment_payload_is_required_and_bound_to_archive_identity() {
        let valid = binding(AuthorityScope::Coordinator);
        let mut malformed = valid.clone();
        malformed.assignment_payload.pop();
        assert_eq!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                malformed.clone(),
                coordinator_sources(&malformed),
            ),
            Err(PendingQueueSemanticAggregateError::AssignmentPayloadMismatch)
        );

        let aggregate = StoredPendingQueueSemanticGeneration::from_commitments(
            valid.clone(),
            coordinator_sources(&valid),
        )
        .unwrap();
        let mut legacy_codec = aggregate.to_persisted_bytes();
        legacy_codec[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert_eq!(
            StoredPendingQueueSemanticGeneration::decode_persisted(
                aggregate.slot(),
                REVISION as i64,
                &legacy_codec,
            ),
            Err(PendingQueueSemanticAggregateError::UnknownCodecVersion)
        );
    }

    #[test]
    fn missing_duplicate_extra_and_cross_generation_sources_fail_closed() {
        let binding = binding(AuthorityScope::Coordinator);
        let mut missing = coordinator_sources(&binding);
        missing.pop();
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding.clone(), missing),
            Err(PendingQueueSemanticAggregateError::IncompleteSourceSet)
        ));
        let duplicate = vec![
            commitment(&binding, PendingQueuePublisherKind::CoordinatorRegistration, 1),
            commitment(&binding, PendingQueuePublisherKind::CoordinatorRegistration, 2),
            commitment(&binding, PendingQueuePublisherKind::CoordinatorGuta, 3),
        ];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding.clone(), duplicate),
            Err(PendingQueueSemanticAggregateError::SourceSetMismatch)
        ));
        let mut extra = coordinator_sources(&binding);
        extra.push(commitment(
            &binding,
            PendingQueuePublisherKind::RealmUserUpdate,
            4,
        ));
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding.clone(),
                extra
            ),
            Err(PendingQueueSemanticAggregateError::IncompleteSourceSet)
        ));
        let mut wrong = coordinator_sources(&binding);
        wrong[0].pipeline_close_receipt_digest = [9; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(binding, wrong),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));
    }

    #[test]
    fn cross_store_source_receipts_fail_closed() {
        let binding = binding(AuthorityScope::Coordinator);
        let mut wrong_publish_store = coordinator_sources(&binding);
        wrong_publish_store[1].publish_store_fingerprint = [88; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding.clone(),
                wrong_publish_store,
            ),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));

        let mut wrong_artifact_store = coordinator_sources(&binding);
        wrong_artifact_store[2].artifact_store_fingerprint = [99; 32];
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::from_commitments(
                binding,
                wrong_artifact_store,
            ),
            Err(PendingQueueSemanticAggregateError::GenerationMismatch)
        ));
    }

    #[test]
    fn codec_round_trip_tamper_and_trailing_bytes_fail_closed() {
        let binding = binding(AuthorityScope::Coordinator);
        let aggregate = StoredPendingQueueSemanticGeneration::from_commitments(
            binding.clone(),
            coordinator_sources(&binding),
        ).unwrap();
        let bytes = aggregate.to_persisted_bytes();
        assert_eq!(
            StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &bytes).unwrap(),
            aggregate,
        );
        let mut tampered = bytes.clone();
        tampered[100] ^= 1;
        assert!(StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &tampered).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(matches!(
            StoredPendingQueueSemanticGeneration::decode_persisted(aggregate.slot(), REVISION as i64, &trailing),
            Err(PendingQueueSemanticAggregateError::TrailingBytes)
        ));
    }

    #[test]
    fn lwt_query_is_immutable_and_production_setup_is_not_wired() {
        let keyspace = BranchExactDeploymentNoTabletKeyspace::try_new("psy_h22d3_no_tablet".to_owned()).unwrap();
        let golden = PendingQueueSemanticAggregateQueries::new(&keyspace).golden();
        assert!(golden.contains("IF NOT EXISTS"));
        assert!(!golden.contains("UPDATE "));
        assert!(golden.contains(PENDING_QUEUE_SEMANTIC_GENERATION_TABLE));
        let setup = include_str!("../psy_setup.rs");
        assert!(!setup.contains(PENDING_QUEUE_SEMANTIC_GENERATION_TABLE));
        assert!(!setup.contains("ScyllaPendingQueueSemanticAggregateStore"));
        let source = include_str!("pending_queue_semantic_aggregate.rs");
        assert!(source.contains("persist_verified<Hash: Q256BitHash>"));
        assert!(source.matches("revalidate_queue_close_exact::<Hash>").count() >= 4);
        assert!(!source.contains("pub(super) async fn persist(\n"));
    }
}
