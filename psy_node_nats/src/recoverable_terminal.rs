//! Exact per-subject NATS retained-set scans.
//!
//! A source scan succeeds only after the complete retained subject history has
//! been replayed through the same typed Data/Seal state machine used by the
//! publisher and the final retained member is Seal. The aggregate manifest
//! requires the exact Coordinator (three) or Realm (one) source set from its
//! durable segment assignment.
//!
//! This is deliberately *not* a semantic generation terminal. It does not
//! bind durable source-row readback, persisted capture artifacts, replay
//! coverage, or an authority publish marker, and therefore cannot authorize
//! pipeline publication, segment rotation, or garbage collection.

use std::{collections::BTreeMap, error::Error, fmt};

use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueBoundaryObservation, PendingQueueCaptureContext,
    PendingQueueCaptureContextDigest, PendingQueueGenerationBoundary,
};
use psy_node_core::store::pending_generation_pipeline::PendingQueueCloseIntentDigest;
use sha2::{Digest, Sha256};

use crate::{
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment, PendingQueueSegmentAssignmentDigest,
    },
    recoverable_publish::{
        PendingQueueEnvelopeError, PendingQueueGenerationBudgetDigest,
        PendingQueuePublishEnvelope, PendingQueuePublishSourcePhase,
        PendingQueuePublishSourceState, PendingQueuePublisherKind,
        PendingQueueSourceSelectionPlan,
        RecoverableNatsSourceRoute,
    },
    recoverable_segment::{
        RecoverableNatsSegmentContractDigest, RecoverableNatsSegmentId,
        RecoverableNatsStreamInstanceId, RecoverableNatsStreamStateSnapshot,
        SealedRecoverableNatsStreamInstance,
    },
};

pub const PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_CODEC_VERSION: u16 = 1;
pub const MAX_PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_BYTES: usize = 64 * 1024;
const TRUNCATION_MANIFEST_MAGIC: &[u8; 8] = b"PSYQNTSM";
const SOURCE_SCAN_DOMAIN: &[u8] = b"psy/rollback/pending-queue-source-truncation/v1";
const TRUNCATION_MANIFEST_SLOT_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-nats-truncation-manifest-slot/v1";
const TRUNCATION_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-nats-truncation-manifest/v1";
const WHOLE_STREAM_SCAN_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-nats-whole-stream-scan/v1";
const WHOLE_STREAM_MANIFEST_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-nats-whole-stream-manifest/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSourceTruncationDigest([u8; 32]);

impl PendingQueueSourceTruncationDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueTerminalError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueNatsTruncationManifestSlot([u8; 32]);

impl PendingQueueNatsTruncationManifestSlot {
    pub fn for_assignment(
        assignment: &PendingQueueGenerationSegmentAssignment,
    ) -> Result<Self, PendingQueueTerminalError> {
        let mut hasher = Sha256::new();
        hasher.update(TRUNCATION_MANIFEST_SLOT_DOMAIN);
        hasher.update(assignment.context().digest().as_bytes());
        hasher.update(assignment.digest().as_bytes());
        Self::try_new(hasher.finalize().into())
    }

    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueTerminalError::EmptySlot)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueNatsTruncationManifestDigest([u8; 32]);

impl PendingQueueNatsTruncationManifestDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueTerminalError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque proof produced only by the typed leader scanner. It is deliberately
/// not Clone and has no public constructor.
#[derive(Debug)]
pub struct PendingQueueSourceTruncationReceipt {
    source_state: PendingQueuePublishSourceState,
    first_stream_sequence: u64,
    retained_message_count: u32,
    close_intent: PendingQueueCloseIntentDigest,
    last_data_stream_sequence: u64,
    last_data_envelope_digest: [u8; 32],
    seal_marker_stream_sequence: u64,
    seal_marker_digest: [u8; 32],
    scan_digest: PendingQueueSourceTruncationDigest,
}

impl PendingQueueSourceTruncationReceipt {
    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.source_state.publisher_kind()
    }

    pub const fn source_state(&self) -> &PendingQueuePublishSourceState {
        &self.source_state
    }

    pub const fn first_stream_sequence(&self) -> u64 {
        self.first_stream_sequence
    }

    pub const fn retained_message_count(&self) -> u32 {
        self.retained_message_count
    }

    pub const fn scan_digest(&self) -> PendingQueueSourceTruncationDigest {
        self.scan_digest
    }

    pub const fn close_intent(&self) -> PendingQueueCloseIntentDigest {
        self.close_intent
    }

    pub const fn last_data_stream_sequence(&self) -> u64 {
        self.last_data_stream_sequence
    }

    pub const fn last_data_envelope_digest(&self) -> &[u8; 32] {
        &self.last_data_envelope_digest
    }

    pub const fn seal_marker_stream_sequence(&self) -> u64 {
        self.seal_marker_stream_sequence
    }

    pub const fn seal_marker_digest(&self) -> &[u8; 32] {
        &self.seal_marker_digest
    }

    pub fn matches_persisted_source(&self, persisted: &PendingQueuePublishSourceState) -> bool {
        &self.source_state == persisted
    }

    pub fn matches_data_replay(&self, replayed: &PendingQueuePublishSourceState) -> bool {
        matches!(replayed.phase(), PendingQueuePublishSourcePhase::Open)
            && replayed.artifact_identity() == self.source_state.artifact_identity()
            && replayed.publisher_kind() == self.source_state.publisher_kind()
            && replayed.segment_id() == self.source_state.segment_id()
            && replayed.contract_digest() == self.source_state.contract_digest()
            && replayed.assignment_digest() == self.source_state.assignment_digest()
            && replayed.budget_digest() == self.source_state.budget_digest()
            && replayed.quota() == self.source_state.quota()
            && replayed.data_member_count() == self.source_state.data_member_count()
            && replayed.data_payload_bytes() == self.source_state.data_payload_bytes()
            && replayed.data_encoded_bytes() == self.source_state.data_encoded_bytes()
            && replayed.total_encoded_bytes() == self.source_state.data_encoded_bytes()
            && replayed.data_rolling_digest() == self.source_state.data_rolling_digest()
            && replayed.last_subject_sequence() == self.last_data_stream_sequence
            && replayed.last_envelope_digest() == self.last_data_envelope_digest
    }

    pub fn boundary(&self) -> Result<PendingQueueGenerationBoundary, PendingQueueTerminalError> {
        PendingQueueGenerationBoundary::try_from_backend_observation(
            self.source_state.artifact_identity().context(),
            self.close_intent,
            self.source_state.artifact_identity().source().clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: self.seal_marker_stream_sequence,
                last_data_stream_sequence: self.last_data_stream_sequence,
                seal_marker_digest: self.seal_marker_digest,
            },
        )
        .map_err(|error| PendingQueueTerminalError::Core(error.to_string()))
    }
}

pub(crate) struct PendingQueueSourceTruncationScanner {
    state: PendingQueuePublishSourceState,
    first_stream_sequence: Option<u64>,
    retained_message_count: u32,
    observed_seal: Option<(
        PendingQueueCloseIntentDigest,
        u64,
        [u8; 32],
        u64,
        [u8; 32],
    )>,
    scan_hasher: Sha256,
}

impl PendingQueueSourceTruncationScanner {
    pub(crate) fn try_new(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
    ) -> Result<Self, PendingQueueTerminalError> {
        let state = PendingQueuePublishSourceState::bootstrap(route, assignment)
            .map_err(model)?;
        let mut scan_hasher = Sha256::new();
        scan_hasher.update(SOURCE_SCAN_DOMAIN);
        scan_hasher.update(assignment.digest().as_bytes());
        scan_hasher.update(state.artifact_identity().digest().as_bytes());
        scan_hasher.update([state.publisher_kind() as u8]);
        Ok(Self {
            state,
            first_stream_sequence: None,
            retained_message_count: 0,
            observed_seal: None,
            scan_hasher,
        })
    }

    pub(crate) fn observe(
        &mut self,
        stream_sequence: u64,
        canonical_envelope: &[u8],
    ) -> Result<(), PendingQueueTerminalError> {
        if stream_sequence == 0 {
            return Err(PendingQueueTerminalError::InvalidStreamSequence);
        }
        let envelope = PendingQueuePublishEnvelope::decode_canonical(canonical_envelope)
            .map_err(model)?;
        if let crate::recoverable_publish::PendingQueueEnvelopeBody::Seal(summary) =
            envelope.body()
        {
            if self.observed_seal.is_some() {
                return Err(PendingQueueTerminalError::DuplicateMember);
            }
            self.observed_seal = Some((
                summary.close_intent(),
                envelope.previous_subject_sequence(),
                envelope.previous_envelope_digest(),
                stream_sequence,
                *envelope.digest().as_bytes(),
            ));
        }
        let selected = match self.state.select(&envelope).map_err(model)? {
            PendingQueueSourceSelectionPlan::Idempotent(_) => {
                return Err(PendingQueueTerminalError::DuplicateMember)
            }
            PendingQueueSourceSelectionPlan::Advance { candidate, .. } => candidate,
        };
        let accepted = selected.record_published(stream_sequence).map_err(model)?;
        let committed = accepted.candidate().finalize_published().map_err(model)?;
        self.state = committed.candidate().clone();
        self.first_stream_sequence.get_or_insert(stream_sequence);
        self.retained_message_count = self
            .retained_message_count
            .checked_add(1)
            .ok_or(PendingQueueTerminalError::MemberCountOverflow)?;
        self.scan_hasher.update(stream_sequence.to_be_bytes());
        self.scan_hasher
            .update((canonical_envelope.len() as u64).to_be_bytes());
        self.scan_hasher.update(canonical_envelope);
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<PendingQueueSourceTruncationReceipt, PendingQueueTerminalError> {
        if !matches!(self.state.phase(), PendingQueuePublishSourcePhase::Sealed { .. }) {
            return Err(PendingQueueTerminalError::SourceNotSealed);
        }
        let first_stream_sequence = self
            .first_stream_sequence
            .ok_or(PendingQueueTerminalError::SourceNotSealed)?;
        let (
            close_intent,
            last_data_stream_sequence,
            last_data_envelope_digest,
            seal_marker_stream_sequence,
            seal_marker_digest,
        ) = self
            .observed_seal
            .ok_or(PendingQueueTerminalError::SourceNotSealed)?;
        Ok(PendingQueueSourceTruncationReceipt {
            source_state: self.state,
            first_stream_sequence,
            retained_message_count: self.retained_message_count,
            close_intent,
            last_data_stream_sequence,
            last_data_envelope_digest,
            seal_marker_stream_sequence,
            seal_marker_digest,
            scan_digest: PendingQueueSourceTruncationDigest::try_new(
                self.scan_hasher.finalize().into(),
            )?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueNatsTruncationManifestSource {
    source_state: PendingQueuePublishSourceState,
    first_stream_sequence: u64,
    retained_message_count: u32,
    scan_digest: PendingQueueSourceTruncationDigest,
}

impl PendingQueueNatsTruncationManifestSource {
    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.source_state.publisher_kind()
    }

    pub const fn source_state(&self) -> &PendingQueuePublishSourceState {
        &self.source_state
    }

    pub const fn scan_digest(&self) -> PendingQueueSourceTruncationDigest {
        self.scan_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueNatsGenerationTruncationManifest {
    slot: PendingQueueNatsTruncationManifestSlot,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    budget_digest: PendingQueueGenerationBudgetDigest,
    reserved_bytes: i64,
    total_encoded_bytes: u64,
    sources: Vec<PendingQueueNatsTruncationManifestSource>,
    digest: PendingQueueNatsTruncationManifestDigest,
}

impl PendingQueueNatsGenerationTruncationManifest {
    pub fn try_from_scans(
        assignment: &PendingQueueGenerationSegmentAssignment,
        scans: Vec<PendingQueueSourceTruncationReceipt>,
    ) -> Result<Self, PendingQueueTerminalError> {
        if scans.len() != usize::from(assignment.expected_source_count())
            || scans.len() != assignment.source_quotas().len()
        {
            return Err(PendingQueueTerminalError::IncompleteSourceManifest);
        }
        let mut sources: Vec<_> = scans
            .into_iter()
            .map(|scan| PendingQueueNatsTruncationManifestSource {
                source_state: scan.source_state,
                first_stream_sequence: scan.first_stream_sequence,
                retained_message_count: scan.retained_message_count,
                scan_digest: scan.scan_digest,
            })
            .collect();
        sources.sort_by_key(|source| source.publisher_kind() as u8);
        let mut manifest = Self {
            slot: PendingQueueNatsTruncationManifestSlot::for_assignment(assignment)?,
            context_digest: assignment.context().digest(),
            assignment_digest: assignment.digest(),
            segment_id: assignment.segment_id(),
            contract_digest: assignment.contract_digest(),
            budget_digest: assignment.budget_digest(),
            reserved_bytes: assignment.reserved_bytes(),
            total_encoded_bytes: sources.iter().try_fold(0_u64, |sum, source| {
                sum.checked_add(source.source_state.total_encoded_bytes())
                    .ok_or(PendingQueueTerminalError::ByteCountOverflow)
            })?,
            sources,
            digest: PendingQueueNatsTruncationManifestDigest([1; 32]),
        };
        manifest.validate(Some(assignment))?;
        let unsigned = manifest.encode_unsigned()?;
        manifest.digest = truncation_manifest_digest(&unsigned)?;
        Ok(manifest)
    }

    pub const fn slot(&self) -> PendingQueueNatsTruncationManifestSlot {
        self.slot
    }

    pub const fn context_digest(&self) -> PendingQueueCaptureContextDigest {
        self.context_digest
    }

    pub const fn assignment_digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.assignment_digest
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn digest(&self) -> PendingQueueNatsTruncationManifestDigest {
        self.digest
    }

    pub const fn total_encoded_bytes(&self) -> u64 {
        self.total_encoded_bytes
    }

    pub fn sources(&self) -> &[PendingQueueNatsTruncationManifestSource] {
        &self.sources
    }

    pub fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut bytes = self
            .encode_unsigned()
            .expect("validated truncation manifest remains canonical");
        bytes.extend_from_slice(self.digest.as_bytes());
        bytes
    }

    pub fn decode_persisted(
        partition_slot: PendingQueueNatsTruncationManifestSlot,
        digest_column: &[u8],
        bytes: &[u8],
    ) -> Result<Self, PendingQueueTerminalError> {
        if bytes.len() > MAX_PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_BYTES {
            return Err(PendingQueueTerminalError::PayloadTooLarge(bytes.len()));
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != TRUNCATION_MANIFEST_MAGIC {
            return Err(PendingQueueTerminalError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_CODEC_VERSION {
            return Err(PendingQueueTerminalError::UnknownCodecVersion(version));
        }
        let slot = PendingQueueNatsTruncationManifestSlot::try_new(decoder.array32()?)?;
        if slot != partition_slot {
            return Err(PendingQueueTerminalError::PartitionSlotMismatch);
        }
        let context_digest = PendingQueueCaptureContextDigest::try_new(decoder.array32()?)
            .map_err(|error| PendingQueueTerminalError::Core(error.to_string()))?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(decoder.array32()?)
            .map_err(|error| PendingQueueTerminalError::Assignment(error.to_string()))?;
        let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)
            .map_err(|error| PendingQueueTerminalError::Segment(error.to_string()))?;
        let contract_digest = RecoverableNatsSegmentContractDigest::try_new(decoder.array32()?)
            .map_err(|error| PendingQueueTerminalError::Segment(error.to_string()))?;
        let budget_digest = PendingQueueGenerationBudgetDigest::try_new(decoder.array32()?)
            .map_err(model)?;
        let reserved_bytes = decoder.i64()?;
        let total_encoded_bytes = decoder.u64()?;
        let source_count = decoder.u8()? as usize;
        let mut sources = Vec::with_capacity(source_count);
        for _ in 0..source_count {
            let publisher_kind = PendingQueuePublisherKind::try_from_u8(decoder.u8()?)
                .map_err(model)?;
            let source_revision = decoder.i64()?;
            let source_len = decoder.u32()? as usize;
            let source_state = PendingQueuePublishSourceState::decode_persisted(
                source_revision,
                decoder.take(source_len)?,
            )
            .map_err(model)?;
            if source_state.publisher_kind() != publisher_kind {
                return Err(PendingQueueTerminalError::SourceIdentityMismatch);
            }
            sources.push(PendingQueueNatsTruncationManifestSource {
                source_state,
                first_stream_sequence: decoder.u64()?,
                retained_message_count: decoder.u32()?,
                scan_digest: PendingQueueSourceTruncationDigest::try_new(decoder.array32()?)?,
            });
        }
        let encoded_digest = PendingQueueNatsTruncationManifestDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueTerminalError::TrailingBytes);
        }
        if digest_column != encoded_digest.as_bytes() {
            return Err(PendingQueueTerminalError::DigestColumnMismatch);
        }
        let manifest = Self {
            slot,
            context_digest,
            assignment_digest,
            segment_id,
            contract_digest,
            budget_digest,
            reserved_bytes,
            total_encoded_bytes,
            sources,
            digest: encoded_digest,
        };
        manifest.validate(None)?;
        if truncation_manifest_digest(&bytes[..bytes.len() - 32])? != encoded_digest {
            return Err(PendingQueueTerminalError::DigestMismatch);
        }
        Ok(manifest)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, PendingQueueTerminalError> {
        let mut out = Vec::with_capacity(1024);
        out.extend_from_slice(TRUNCATION_MANIFEST_MAGIC);
        out.extend_from_slice(&PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        out.extend_from_slice(self.context_digest.as_bytes());
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(&self.segment_id.get().to_be_bytes());
        out.extend_from_slice(self.contract_digest.as_bytes());
        out.extend_from_slice(self.budget_digest.as_bytes());
        out.extend_from_slice(&self.reserved_bytes.to_be_bytes());
        out.extend_from_slice(&self.total_encoded_bytes.to_be_bytes());
        out.push(self.sources.len() as u8);
        for source in &self.sources {
            let bytes = source.source_state.to_persisted_bytes();
            let len = u32::try_from(bytes.len())
                .map_err(|_| PendingQueueTerminalError::PayloadTooLarge(bytes.len()))?;
            out.push(source.publisher_kind() as u8);
            out.extend_from_slice(&source.source_state.revision().as_i64().to_be_bytes());
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&bytes);
            out.extend_from_slice(&source.first_stream_sequence.to_be_bytes());
            out.extend_from_slice(&source.retained_message_count.to_be_bytes());
            out.extend_from_slice(source.scan_digest.as_bytes());
        }
        if out.len() + 32 > MAX_PENDING_QUEUE_NATS_TRUNCATION_MANIFEST_BYTES {
            return Err(PendingQueueTerminalError::PayloadTooLarge(out.len() + 32));
        }
        Ok(out)
    }

    fn validate(
        &self,
        assignment: Option<&PendingQueueGenerationSegmentAssignment>,
    ) -> Result<(), PendingQueueTerminalError> {
        let context = self
            .sources
            .first()
            .ok_or(PendingQueueTerminalError::IncompleteSourceManifest)?
            .source_state
            .artifact_identity()
            .context();
        if context.digest() != self.context_digest {
            return Err(PendingQueueTerminalError::SourceIdentityMismatch);
        }
        let expected = expected_kinds(context);
        if self.sources.len() != expected.len()
            || self
                .sources
                .iter()
                .map(|source| source.publisher_kind())
                .ne(expected.iter().copied())
            || self.reserved_bytes <= 0
            || self.total_encoded_bytes > self.reserved_bytes as u64
        {
            return Err(PendingQueueTerminalError::IncompleteSourceManifest);
        }
        let mut total = 0_u64;
        for source in &self.sources {
            let state = &source.source_state;
            if state.artifact_identity().context() != context
                || state.assignment_digest() != self.assignment_digest
                || state.segment_id() != self.segment_id
                || state.contract_digest() != self.contract_digest
                || state.budget_digest() != self.budget_digest
                || !matches!(state.phase(), PendingQueuePublishSourcePhase::Sealed { .. })
                || source.first_stream_sequence == 0
                || source.retained_message_count != state.data_member_count() + 1
            {
                return Err(PendingQueueTerminalError::SourceIdentityMismatch);
            }
            total = total
                .checked_add(state.total_encoded_bytes())
                .ok_or(PendingQueueTerminalError::ByteCountOverflow)?;
        }
        if total != self.total_encoded_bytes {
            return Err(PendingQueueTerminalError::ByteCountMismatch);
        }
        if let Some(assignment) = assignment {
            if assignment.context() != context
                || assignment.digest() != self.assignment_digest
                || assignment.segment_id() != self.segment_id
                || assignment.contract_digest() != self.contract_digest
                || assignment.budget_digest() != self.budget_digest
                || assignment.reserved_bytes() != self.reserved_bytes
                || assignment.source_quotas().iter().map(|quota| quota.publisher_kind())
                    .ne(expected.iter().copied())
                || self.sources.iter().zip(assignment.source_quotas()).any(|(source, quota)| {
                    source.source_state.quota() != *quota
                })
            {
                return Err(PendingQueueTerminalError::AssignmentMismatch);
            }
            if PendingQueueNatsTruncationManifestSlot::for_assignment(assignment)? != self.slot {
                return Err(PendingQueueTerminalError::PartitionSlotMismatch);
            }
        }
        Ok(())
    }
}

/// Digest of every physical retained message in one exact sealed stream
/// incarnation. This proves transport-level closure only; the later durable
/// segment manifest must additionally bind every assignment to its immutable
/// generation terminal before deletion can be requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueNatsWholeStreamScanDigest([u8; 32]);

impl PendingQueueNatsWholeStreamScanDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueTerminalError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        Self::try_new(bytes)
    }
}

/// Digest of the exact closed assignment/source set expected in one sealed
/// stream incarnation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueNatsWholeStreamManifestDigest([u8; 32]);

impl PendingQueueNatsWholeStreamManifestDigest {
    fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        if bytes == [0; 32] {
            Err(PendingQueueTerminalError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn try_from_bytes(bytes: [u8; 32]) -> Result<Self, PendingQueueTerminalError> {
        Self::try_new(bytes)
    }

    /// Deterministic assignment-set commitment shared by the durable
    /// SealRequested row (live observation) and the later sealed scanner.
    /// This helper is not a seal/delete permit; callers must still prove the
    /// assignment list came from one exact ledger snapshot.
    pub fn for_instance_assignments(
        instance_id: RecoverableNatsStreamInstanceId,
        assignments: &[PendingQueueGenerationSegmentAssignment],
    ) -> Result<Self, PendingQueueTerminalError> {
        Self::for_instance_assignments_raw(*instance_id.as_bytes(), assignments)
    }

    pub fn for_instance_assignments_raw(
        instance_id: [u8; 32],
        assignments: &[PendingQueueGenerationSegmentAssignment],
    ) -> Result<Self, PendingQueueTerminalError> {
        let mut hasher = Sha256::new();
        hasher.update(WHOLE_STREAM_MANIFEST_DOMAIN);
        hasher.update(instance_id);
        hasher.update((assignments.len() as u64).to_be_bytes());
        for assignment in assignments {
            let bytes = assignment.to_canonical_bytes();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        Self::try_new(hasher.finalize().into())
    }
}

/// Closed-world input for a whole-stream scan. The later durable lifecycle
/// must build this from one exact ledger snapshot after revalidating every
/// generation terminal; callers cannot ask the scanner to accept an
/// unspecified or best-effort source set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueNatsWholeStreamExpectedManifest {
    instance: SealedRecoverableNatsStreamInstance,
    assignments: Vec<PendingQueueGenerationSegmentAssignment>,
    expected_source_count: u64,
    digest: PendingQueueNatsWholeStreamManifestDigest,
}

impl PendingQueueNatsWholeStreamExpectedManifest {
    pub fn try_new(
        instance: SealedRecoverableNatsStreamInstance,
        mut assignments: Vec<PendingQueueGenerationSegmentAssignment>,
    ) -> Result<Self, PendingQueueTerminalError> {
        assignments.sort_by_key(|assignment| assignment.assigned_at_ledger_revision().get());
        let segment = instance.segment();
        let mut expected_source_count = 0_u64;
        for (index, assignment) in assignments.iter().enumerate() {
            let expected = expected_kinds(assignment.context());
            if assignment.context().key() != segment.generation_key()
                || assignment.segment_id() != segment.segment_id()
                || assignment.contract_digest() != segment.digest()
                || usize::from(assignment.expected_source_count()) != expected.len()
                || assignment
                    .source_quotas()
                    .iter()
                    .map(|quota| quota.publisher_kind())
                    .ne(expected.iter().copied())
                || index > 0
                    && assignments[index - 1].assigned_at_ledger_revision().get()
                        >= assignment.assigned_at_ledger_revision().get()
            {
                return Err(PendingQueueTerminalError::WholeStreamManifestMismatch);
            }
            expected_source_count = expected_source_count
                .checked_add(expected.len() as u64)
                .ok_or(PendingQueueTerminalError::MemberCountOverflow)?;
        }
        for pair in assignments.windows(2) {
            if pair[0].digest() == pair[1].digest()
                || pair[0].context().digest() == pair[1].context().digest()
            {
                return Err(PendingQueueTerminalError::WholeStreamManifestMismatch);
            }
        }
        let state = instance.state();
        if state.subject_count() != expected_source_count
            || state.messages() < expected_source_count
        {
            return Err(PendingQueueTerminalError::WholeStreamManifestMismatch);
        }
        let digest = PendingQueueNatsWholeStreamManifestDigest::for_instance_assignments(
            instance.instance_id(),
            &assignments,
        )?;
        Ok(Self {
            instance,
            assignments,
            expected_source_count,
            digest,
        })
    }

    pub const fn instance(&self) -> &SealedRecoverableNatsStreamInstance {
        &self.instance
    }

    pub fn assignments(&self) -> &[PendingQueueGenerationSegmentAssignment] {
        &self.assignments
    }

    pub const fn expected_source_count(&self) -> u64 {
        self.expected_source_count
    }

    pub const fn digest(&self) -> PendingQueueNatsWholeStreamManifestDigest {
        self.digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueNatsWholeStreamScanReceipt {
    instance_id: RecoverableNatsStreamInstanceId,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    state: RecoverableNatsStreamStateSnapshot,
    manifest_digest: PendingQueueNatsWholeStreamManifestDigest,
    scan_digest: PendingQueueNatsWholeStreamScanDigest,
}

impl PendingQueueNatsWholeStreamScanReceipt {
    pub const fn instance_id(&self) -> RecoverableNatsStreamInstanceId {
        self.instance_id
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub const fn state(&self) -> RecoverableNatsStreamStateSnapshot {
        self.state
    }

    pub const fn scan_digest(&self) -> PendingQueueNatsWholeStreamScanDigest {
        self.scan_digest
    }

    pub const fn manifest_digest(&self) -> PendingQueueNatsWholeStreamManifestDigest {
        self.manifest_digest
    }
}

struct PendingQueueNatsExpectedSource {
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    state: PendingQueuePublishSourceState,
}

pub(crate) struct PendingQueueNatsWholeStreamScanner {
    manifest: PendingQueueNatsWholeStreamExpectedManifest,
    sources: BTreeMap<String, PendingQueueNatsExpectedSource>,
    next_sequence: u64,
    observed_messages: u64,
    hasher: Sha256,
}

impl PendingQueueNatsWholeStreamScanner {
    pub(crate) fn try_new(
        manifest: PendingQueueNatsWholeStreamExpectedManifest,
    ) -> Result<Self, PendingQueueTerminalError> {
        let mut hasher = Sha256::new();
        hasher.update(WHOLE_STREAM_SCAN_DOMAIN);
        let instance = manifest.instance();
        hasher.update(instance.instance_id().as_bytes());
        hasher.update(instance.segment().digest().as_bytes());
        hasher.update(manifest.digest().as_bytes());
        let state = instance.state();
        hasher.update(state.messages().to_be_bytes());
        hasher.update(state.bytes().to_be_bytes());
        hasher.update(state.first_sequence().to_be_bytes());
        hasher.update(state.last_sequence().to_be_bytes());
        hasher.update(state.consumer_count().to_be_bytes());
        hasher.update(state.subject_count().to_be_bytes());
        let mut sources = BTreeMap::new();
        for assignment in manifest.assignments() {
            for publisher_kind in expected_kinds(assignment.context()) {
                let route = RecoverableNatsSourceRoute::try_new(
                    assignment.context(),
                    *publisher_kind,
                    instance.segment(),
                )
                .map_err(model)?;
                let state = PendingQueuePublishSourceState::bootstrap(&route, assignment)
                    .map_err(model)?;
                if sources
                    .insert(
                        route.subject().to_owned(),
                        PendingQueueNatsExpectedSource {
                            assignment_digest: assignment.digest(),
                            state,
                        },
                    )
                    .is_some()
                {
                    return Err(PendingQueueTerminalError::WholeStreamManifestMismatch);
                }
            }
        }
        if sources.len() as u64 != manifest.expected_source_count() {
            return Err(PendingQueueTerminalError::WholeStreamManifestMismatch);
        }
        Ok(Self {
            manifest,
            sources,
            next_sequence: 1,
            observed_messages: 0,
            hasher,
        })
    }

    pub(crate) fn observe(
        &mut self,
        sequence: u64,
        subject: &str,
        canonical_envelope: &[u8],
    ) -> Result<(), PendingQueueTerminalError> {
        let state = self.manifest.instance().state();
        if sequence != self.next_sequence
            || sequence == 0
            || sequence > state.last_sequence()
        {
            return Err(PendingQueueTerminalError::WholeStreamSequenceMismatch);
        }
        let envelope = PendingQueuePublishEnvelope::decode_canonical(canonical_envelope)
            .map_err(model)?;
        if envelope.segment_id() != self.manifest.instance().segment().segment_id()
            || envelope.contract_digest() != self.manifest.instance().segment().digest()
            || envelope
                .exact_subject(self.manifest.instance().segment())
                .map_err(model)?
                != subject
        {
            return Err(PendingQueueTerminalError::WholeStreamSubjectMismatch);
        }
        let expected = self
            .sources
            .get_mut(subject)
            .ok_or(PendingQueueTerminalError::WholeStreamUnexpectedSource)?;
        if envelope.assignment_digest() != expected.assignment_digest {
            return Err(PendingQueueTerminalError::WholeStreamUnexpectedSource);
        }
        let PendingQueueSourceSelectionPlan::Advance { candidate, .. } =
            expected.state.select(&envelope).map_err(model)?
        else {
            return Err(PendingQueueTerminalError::WholeStreamSourceStateMismatch);
        };
        expected.state = candidate
            .record_published(sequence)
            .map_err(model)?
            .candidate()
            .finalize_published()
            .map_err(model)?
            .candidate()
            .clone();
        self.hasher.update(sequence.to_be_bytes());
        self.hasher.update((subject.len() as u64).to_be_bytes());
        self.hasher.update(subject.as_bytes());
        self.hasher
            .update((canonical_envelope.len() as u64).to_be_bytes());
        self.hasher.update(canonical_envelope);
        self.observed_messages = self
            .observed_messages
            .checked_add(1)
            .ok_or(PendingQueueTerminalError::MemberCountOverflow)?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PendingQueueTerminalError::WholeStreamSequenceMismatch)?;
        Ok(())
    }

    pub(crate) fn finish(
        self,
    ) -> Result<PendingQueueNatsWholeStreamScanReceipt, PendingQueueTerminalError> {
        let state = self.manifest.instance().state();
        let expected_next = state
            .last_sequence()
            .checked_add(1)
            .ok_or(PendingQueueTerminalError::WholeStreamSequenceMismatch)?;
        if self.observed_messages != state.messages()
            || self.next_sequence != expected_next
            || self.sources.values().any(|source| {
                !matches!(
                    source.state.phase(),
                    PendingQueuePublishSourcePhase::Sealed { .. }
                )
            })
        {
            return Err(PendingQueueTerminalError::WholeStreamStateMismatch);
        }
        Ok(PendingQueueNatsWholeStreamScanReceipt {
            instance_id: self.manifest.instance().instance_id(),
            segment_id: self.manifest.instance().segment().segment_id(),
            contract_digest: self.manifest.instance().segment().digest(),
            state,
            manifest_digest: self.manifest.digest(),
            scan_digest: PendingQueueNatsWholeStreamScanDigest::try_new(
                self.hasher.finalize().into(),
            )?,
        })
    }
}

fn expected_kinds(context: PendingQueueCaptureContext) -> &'static [PendingQueuePublisherKind] {
    use psy_data::protocol::chain_context::AuthorityScope;
    match context.key().authority() {
        AuthorityScope::Coordinator => &[
            PendingQueuePublisherKind::CoordinatorRegistration,
            PendingQueuePublisherKind::CoordinatorDeploy,
            PendingQueuePublisherKind::CoordinatorGuta,
        ],
        AuthorityScope::Realm { .. } => &[PendingQueuePublisherKind::RealmUserUpdate],
    }
}

fn truncation_manifest_digest(bytes: &[u8]) -> Result<PendingQueueNatsTruncationManifestDigest, PendingQueueTerminalError> {
    let mut hasher = Sha256::new();
    hasher.update(TRUNCATION_MANIFEST_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    PendingQueueNatsTruncationManifestDigest::try_new(hasher.finalize().into())
}

fn model(error: PendingQueueEnvelopeError) -> PendingQueueTerminalError {
    PendingQueueTerminalError::Envelope(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueTerminalError {
    EmptySlot,
    EmptyDigest,
    InvalidStreamSequence,
    DuplicateMember,
    SourceNotSealed,
    IncompleteSourceManifest,
    SourceIdentityMismatch,
    AssignmentMismatch,
    MemberCountOverflow,
    ByteCountOverflow,
    ByteCountMismatch,
    InvalidMagic,
    UnknownCodecVersion(u16),
    PartitionSlotMismatch,
    DigestColumnMismatch,
    DigestMismatch,
    TruncatedPayload,
    TrailingBytes,
    PayloadTooLarge(usize),
    WholeStreamSequenceMismatch,
    WholeStreamSubjectMismatch,
    WholeStreamStateMismatch,
    WholeStreamManifestMismatch,
    WholeStreamUnexpectedSource,
    WholeStreamSourceStateMismatch,
    Envelope(String),
    Assignment(String),
    Segment(String),
    Core(String),
}

impl fmt::Display for PendingQueueTerminalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueTerminalError {}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueTerminalError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PendingQueueTerminalError::TruncatedPayload)?;
        if end > self.bytes.len() {
            return Err(PendingQueueTerminalError::TruncatedPayload);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueTerminalError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PendingQueueTerminalError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, PendingQueueTerminalError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueTerminalError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, PendingQueueTerminalError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueTerminalError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap, PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueueSealSummary,
            PendingQueueSourceQuota,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsStreamSegment,
            RecoverableNatsStreamStateSnapshot,
        },
    };
    use psy_data::protocol::{
        canonical_chain::NetworkId, chain_context::AuthorityScope,
    };
    use psy_node_core::{
        queue::recoverable_ephemeral::PendingQueueCaptureContext,
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    fn assignment(authority: AuthorityScope) -> (
        RecoverableNatsStreamSegment,
        PendingQueueGenerationSegmentAssignment,
    ) {
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(7, 99).unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy",
            key,
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            RecoverableNatsRetentionContract::try_new(
                3,
                1024 * 1024 * 1024,
                128 * 1024 * 1024,
                3,
                16,
            )
            .unwrap(),
        )
        .unwrap();
        let mib = 1024 * 1024_u64;
        let kinds = expected_kinds(context);
        let total_budget = 128 * mib;
        let previous_data_budget = 10 * mib * kinds.len().saturating_sub(1) as u64;
        let all_seal_budget = mib * kinds.len() as u64;
        let quotas: Vec<_> = kinds
            .iter()
            .copied()
            .enumerate()
            .map(|(index, kind)| {
                let data = if index + 1 == kinds.len() {
                    total_budget - previous_data_budget - all_seal_budget
                } else {
                    10 * mib
                };
                PendingQueueSourceQuota::try_new(kind, 100, data, mib).unwrap()
            })
            .collect();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            total_budget,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
            key, &validated, budget, 8,
        )
        .unwrap();
        let assignment = match bootstrap
            .candidate()
            .reserve_generation(context)
            .unwrap()
        {
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => assignment,
            _ => unreachable!(),
        };
        (segment, assignment)
    }

    fn sealed_scan(
        segment: &RecoverableNatsStreamSegment,
        assignment: &PendingQueueGenerationSegmentAssignment,
        kind: PendingQueuePublisherKind,
        start_sequence: u64,
        with_data: bool,
    ) -> PendingQueueSourceTruncationReceipt {
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), kind, segment,
        )
        .unwrap();
        let mut scanner = PendingQueueSourceTruncationScanner::try_new(&route, assignment).unwrap();
        let mut state = PendingQueuePublishSourceState::bootstrap(&route, assignment).unwrap();
        let mut sequence = start_sequence;
        if with_data {
            let data = PendingQueuePublishEnvelope::data(
                &route,
                assignment,
                PendingQueuePublishIntentId::try_new([kind as u8; 32]).unwrap(),
                PendingQueueMemberOrdinal::try_new(1).unwrap(),
                0,
                [0; 32],
                vec![kind as u8],
            )
            .unwrap();
            scanner.observe(sequence, &data.to_canonical_bytes()).unwrap();
            let selected = state.select(&data).unwrap().current().clone();
            let accepted = selected.record_published(sequence).unwrap();
            state = accepted.candidate().finalize_published().unwrap().candidate().clone();
            sequence += 7;
        }
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            assignment,
            PendingQueuePublishIntentId::try_new([kind as u8 + 32; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(state.data_member_count() + 1).unwrap(),
            state.last_subject_sequence(),
            state.last_envelope_digest(),
            state
                .seal_summary(PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        scanner.observe(sequence, &seal.to_canonical_bytes()).unwrap();
        scanner.finish().unwrap()
    }

    #[test]
    fn exact_expected_source_set_builds_deterministic_nats_manifest() {
        let (segment, assignment) = assignment(AuthorityScope::Coordinator);
        let scans: Vec<_> = expected_kinds(assignment.context())
            .iter()
            .copied()
            .enumerate()
            .map(|(index, kind)| {
                sealed_scan(&segment, &assignment, kind, 10 + index as u64 * 100, true)
            })
            .collect();
        let manifest = PendingQueueNatsGenerationTruncationManifest::try_from_scans(&assignment, scans).unwrap();
        assert_eq!(manifest.sources().len(), 3);
        let bytes = manifest.to_persisted_bytes();
        let decoded = PendingQueueNatsGenerationTruncationManifest::decode_persisted(
            manifest.slot(), manifest.digest().as_bytes(), &bytes,
        )
        .unwrap();
        assert_eq!(decoded, manifest);
        assert_eq!(decoded.to_persisted_bytes(), bytes);

        let reversed_scans: Vec<_> = expected_kinds(assignment.context())
            .iter()
            .copied()
            .rev()
            .enumerate()
            .map(|(index, kind)| {
                sealed_scan(
                    &segment,
                    &assignment,
                    kind,
                    10 + (2 - index) as u64 * 100,
                    true,
                )
            })
            .collect();
        let reversed = PendingQueueNatsGenerationTruncationManifest::try_from_scans(
            &assignment,
            reversed_scans,
        )
        .unwrap();
        assert_eq!(reversed.to_persisted_bytes(), bytes);

        let mut tampered = bytes.clone();
        tampered[64] ^= 1;
        assert!(PendingQueueNatsGenerationTruncationManifest::decode_persisted(
            manifest.slot(),
            manifest.digest().as_bytes(),
            &tampered,
        )
        .is_err());
    }

    #[test]
    fn empty_realm_source_still_requires_and_accepts_a_seal() {
        let (segment, assignment) = assignment(AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 0,
        });
        let scan = sealed_scan(
            &segment,
            &assignment,
            PendingQueuePublisherKind::RealmUserUpdate,
            77,
            false,
        );
        assert_eq!(scan.retained_message_count(), 1);
        assert_eq!(scan.source_state().data_member_count(), 0);
        assert_eq!(
            scan.close_intent(),
            PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap()
        );
        assert_eq!(scan.last_data_stream_sequence(), 0);
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(),
            PendingQueuePublisherKind::RealmUserUpdate,
            &segment,
        )
        .unwrap();
        let empty_replay = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        assert!(scan.matches_data_replay(&empty_replay));
        assert_eq!(scan.boundary().unwrap().close_intent(), scan.close_intent());
        PendingQueueNatsGenerationTruncationManifest::try_from_scans(&assignment, vec![scan]).unwrap();
    }

    #[test]
    fn sealed_whole_stream_scan_is_instance_bound_contiguous_and_typed() {
        let (segment, assignment) = assignment(AuthorityScope::Realm {
            realm_id: 4,
            realm_sub_id: 0,
        });
        let kind = PendingQueuePublisherKind::RealmUserUpdate;
        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), kind, &segment,
        )
        .unwrap();
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([5; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            vec![1, 2, 3],
        )
        .unwrap();
        let selected = PendingQueuePublishSourceState::bootstrap(&route, &assignment)
            .unwrap()
            .select(&data)
            .unwrap()
            .current()
            .clone();
        let committed = selected
            .record_published(1)
            .unwrap()
            .candidate()
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([6; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            1,
            *data.digest().as_bytes(),
            committed
                .seal_summary(PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let state = RecoverableNatsStreamStateSnapshot::try_new(
            2, 999, 1, 2, 0, 1,
        )
        .unwrap();
        let instance = segment.model_sealed_instance(1_700_000_000_000_000_000, state);
        let subject = route.subject();
        let manifest = || {
            PendingQueueNatsWholeStreamExpectedManifest::try_new(
                instance.clone(),
                vec![assignment.clone()],
            )
            .unwrap()
        };
        let mut scanner = PendingQueueNatsWholeStreamScanner::try_new(manifest()).unwrap();
        scanner.observe(1, subject, &data.to_canonical_bytes()).unwrap();
        scanner.observe(2, subject, &seal.to_canonical_bytes()).unwrap();
        let receipt = scanner.finish().unwrap();
        assert_eq!(receipt.instance_id(), instance.instance_id());
        assert_eq!(receipt.state(), state);
        assert_eq!(receipt.segment_id(), segment.segment_id());
        assert_eq!(receipt.manifest_digest(), manifest().digest());

        let mut gap = PendingQueueNatsWholeStreamScanner::try_new(manifest()).unwrap();
        assert_eq!(
            gap.observe(2, subject, &data.to_canonical_bytes()),
            Err(PendingQueueTerminalError::WholeStreamSequenceMismatch),
        );
        let mut wrong_subject = PendingQueueNatsWholeStreamScanner::try_new(manifest()).unwrap();
        assert_eq!(
            wrong_subject.observe(1, "PSY_BEQ_V2.wrong", &data.to_canonical_bytes()),
            Err(PendingQueueTerminalError::WholeStreamSubjectMismatch),
        );
        let mut missing = PendingQueueNatsWholeStreamScanner::try_new(manifest()).unwrap();
        missing.observe(1, subject, &data.to_canonical_bytes()).unwrap();
        assert_eq!(
            missing.finish(),
            Err(PendingQueueTerminalError::WholeStreamStateMismatch),
        );

        let extra = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([7; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(3).unwrap(),
            2,
            *seal.digest().as_bytes(),
            vec![4],
        )
        .unwrap();
        let three = RecoverableNatsStreamStateSnapshot::try_new(3, 1200, 1, 3, 0, 1)
            .unwrap();
        let after_seal_instance =
            segment.model_sealed_instance(1_700_000_000_000_000_000, three);
        let mut after_seal = PendingQueueNatsWholeStreamScanner::try_new(
            PendingQueueNatsWholeStreamExpectedManifest::try_new(
                after_seal_instance,
                vec![assignment.clone()],
            )
            .unwrap(),
        )
        .unwrap();
        after_seal
            .observe(1, subject, &data.to_canonical_bytes())
            .unwrap();
        after_seal
            .observe(2, subject, &seal.to_canonical_bytes())
            .unwrap();
        assert!(matches!(
            after_seal.observe(3, subject, &extra.to_canonical_bytes()),
            Err(PendingQueueTerminalError::Envelope(_))
        ));

        assert_eq!(
            PendingQueueNatsWholeStreamExpectedManifest::try_new(instance, Vec::new()),
            Err(PendingQueueTerminalError::WholeStreamManifestMismatch),
        );
    }

    #[test]
    fn missing_duplicate_unsealed_and_extra_after_seal_fail_closed() {
        let (segment, assignment) = assignment(AuthorityScope::Coordinator);
        let kinds = expected_kinds(assignment.context());
        let two = vec![
            sealed_scan(&segment, &assignment, kinds[0], 10, true),
            sealed_scan(&segment, &assignment, kinds[1], 20, true),
        ];
        assert!(matches!(
            PendingQueueNatsGenerationTruncationManifest::try_from_scans(&assignment, two),
            Err(PendingQueueTerminalError::IncompleteSourceManifest)
        ));

        let route = RecoverableNatsSourceRoute::try_new(
            assignment.context(), kinds[0], &segment,
        )
        .unwrap();
        let mut scanner = PendingQueueSourceTruncationScanner::try_new(&route, &assignment).unwrap();
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([5; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            vec![1],
        )
        .unwrap();
        scanner.observe(10, &data.to_canonical_bytes()).unwrap();
        assert!(matches!(
            scanner.finish(),
            Err(PendingQueueTerminalError::SourceNotSealed)
        ));

        let mut sealed = PendingQueueSourceTruncationScanner::try_new(&route, &assignment).unwrap();
        let empty = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([6; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            PendingQueueSealSummary::try_new(
                PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap(),
                0,
                0,
                0,
                [0; 32],
            )
            .unwrap(),
        )
        .unwrap();
        sealed.observe(11, &seal.to_canonical_bytes()).unwrap();
        let late = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([7; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            empty.last_subject_sequence(),
            empty.last_envelope_digest(),
            vec![1],
        )
        .unwrap();
        assert!(sealed.observe(12, &late.to_canonical_bytes()).is_err());
    }
}
