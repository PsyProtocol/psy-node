//! Driver-independent durable outbox identity and intent state.
//!
//! Producer payloads are materialized before a per-source LWT assigns their
//! final ordinal and predecessor.  This avoids poisoning a caller intent with
//! a losing concurrent predecessor.  The concrete Scylla/NATS composition is
//! responsible for exact fragment readback and for minting publish authority.

use std::{error::Error, fmt};

use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::{
    queue::recoverable_ephemeral::PendingQueueArtifactIdentity,
    store::pending_generation_pipeline::PendingQueueCloseIntentDigest,
};
use sha2::{Digest, Sha256};

use crate::{
    recoverable_assignment::PendingQueueSegmentAssignmentDigest,
    recoverable_publish::{
        PendingQueueEnvelopeBody, PendingQueueEnvelopeDigest,
        PendingQueueEnvelopeError, PendingQueueMemberOrdinal,
        PendingQueuePublishEnvelope, PendingQueuePublishIntentId,
        PendingQueuePublishSourceSlot, PendingQueuePublishSourceState,
        PendingQueuePublisherKind,
    },
};

pub const RECOVERABLE_PENDING_INTENT_CODEC_VERSION: u16 = 2;
pub const RECOVERABLE_PENDING_PAYLOAD_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS_PER_BUCKET: u16 = 4;
pub const MAX_RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS: u16 = 16;
const INTENT_MAGIC: &[u8; 8] = b"PSYQINT1";
const INTENT_SLOT_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-intent-slot/v1";
const INTENT_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-intent-state/v1";
const PAYLOAD_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-payload/v1";
const FRAGMENT_DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-fragment/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishIntentSlot([u8; 32]);

impl PendingQueuePublishIntentSlot {
    pub fn derive(
        identity: &PendingQueueArtifactIdentity,
        publisher_kind: PendingQueuePublisherKind,
        intent_id: PendingQueuePublishIntentId,
    ) -> Result<Self, PendingQueueOutboxError> {
        let key = identity.context().key();
        let mut hasher = Sha256::new();
        hasher.update(INTENT_SLOT_DOMAIN);
        hasher.update(key.network().chain_id().to_be_bytes());
        encode_authority(key.authority(), &mut hasher);
        hasher.update([publisher_kind as u8]);
        hasher.update(intent_id.as_bytes());
        Self::try_new(hasher.finalize().into())
    }

    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueOutboxError> {
        if bytes == [0; 32] {
            Err(PendingQueueOutboxError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePayloadDigest([u8; 32]);

impl PendingQueuePayloadDigest {
    pub fn for_payload(payload: &[u8]) -> Result<Self, PendingQueueOutboxError> {
        let mut hasher = Sha256::new();
        hasher.update(PAYLOAD_DIGEST_DOMAIN);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Self::try_new(hasher.finalize().into())
    }

    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueOutboxError> {
        if bytes == [0; 32] {
            Err(PendingQueueOutboxError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePayloadFragmentDigest([u8; 32]);

impl PendingQueuePayloadFragmentDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueOutboxError> {
        if bytes == [0; 32] {
            Err(PendingQueueOutboxError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishIntentRevision(u64);

impl PendingQueuePublishIntentRevision {
    pub const fn try_new(value: u64) -> Result<Self, PendingQueueOutboxError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(PendingQueueOutboxError::RevisionOutOfRange)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, PendingQueueOutboxError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(PendingQueueOutboxError::RevisionOverflow)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingQueuePublishRequestKind {
    Data = 1,
    Seal = 2,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueBoundEnvelope {
    envelope_digest: PendingQueueEnvelopeDigest,
    member_ordinal: PendingQueueMemberOrdinal,
    previous_subject_sequence: u64,
    previous_envelope_digest: [u8; 32],
    encoded_bytes: u64,
}

impl PendingQueueBoundEnvelope {
    pub const fn envelope_digest(self) -> PendingQueueEnvelopeDigest {
        self.envelope_digest
    }

    pub const fn member_ordinal(self) -> PendingQueueMemberOrdinal {
        self.member_ordinal
    }

    pub const fn previous_subject_sequence(self) -> u64 {
        self.previous_subject_sequence
    }

    pub const fn previous_envelope_digest(self) -> [u8; 32] {
        self.previous_envelope_digest
    }

    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueuePublishIntentPhase {
    Materialized,
    Bound(PendingQueueBoundEnvelope),
    NatsAccepted {
        bound: PendingQueueBoundEnvelope,
        subject_sequence: u64,
    },
    SourceCommitted {
        bound: PendingQueueBoundEnvelope,
        subject_sequence: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPendingQueuePublishIntent {
    slot: PendingQueuePublishIntentSlot,
    revision: PendingQueuePublishIntentRevision,
    artifact_identity: PendingQueueArtifactIdentity,
    source_slot: PendingQueuePublishSourceSlot,
    publisher_kind: PendingQueuePublisherKind,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    intent_id: PendingQueuePublishIntentId,
    request_kind: PendingQueuePublishRequestKind,
    close_intent: Option<PendingQueueCloseIntentDigest>,
    payload_digest: PendingQueuePayloadDigest,
    payload_bytes: u64,
    fragment_count: u16,
    phase: PendingQueuePublishIntentPhase,
}

impl StoredPendingQueuePublishIntent {
    pub fn materialize_data(
        source: &PendingQueuePublishSourceState,
        intent_id: PendingQueuePublishIntentId,
        payload: &[u8],
    ) -> Result<(Self, Vec<PendingQueuePayloadFragment>), PendingQueueOutboxError> {
        if payload.is_empty() {
            return Err(PendingQueueOutboxError::EmptyData);
        }
        let fragments = fragment_payload(intent_id, payload)?;
        let payload_digest = PendingQueuePayloadDigest::for_payload(payload)?;
        let state = Self::materialize(
            source,
            intent_id,
            PendingQueuePublishRequestKind::Data,
            None,
            payload_digest,
            payload.len() as u64,
            fragments.len() as u16,
        )?;
        Ok((state, fragments))
    }

    pub fn materialize_seal(
        source: &PendingQueuePublishSourceState,
        intent_id: PendingQueuePublishIntentId,
        close_intent: PendingQueueCloseIntentDigest,
    ) -> Result<Self, PendingQueueOutboxError> {
        Self::materialize(
            source,
            intent_id,
            PendingQueuePublishRequestKind::Seal,
            Some(close_intent),
            PendingQueuePayloadDigest::for_payload(&[])?,
            0,
            0,
        )
    }

    fn materialize(
        source: &PendingQueuePublishSourceState,
        intent_id: PendingQueuePublishIntentId,
        request_kind: PendingQueuePublishRequestKind,
        close_intent: Option<PendingQueueCloseIntentDigest>,
        payload_digest: PendingQueuePayloadDigest,
        payload_bytes: u64,
        fragment_count: u16,
    ) -> Result<Self, PendingQueueOutboxError> {
        let artifact_identity = source.artifact_identity().clone();
        let slot = PendingQueuePublishIntentSlot::derive(
            &artifact_identity,
            source.publisher_kind(),
            intent_id,
        )?;
        let state = Self {
            slot,
            revision: PendingQueuePublishIntentRevision::try_new(1)?,
            artifact_identity,
            source_slot: source.slot().map_err(model)?,
            publisher_kind: source.publisher_kind(),
            assignment_digest: source.assignment_digest(),
            intent_id,
            request_kind,
            close_intent,
            payload_digest,
            payload_bytes,
            fragment_count,
            phase: PendingQueuePublishIntentPhase::Materialized,
        };
        state.validate()?;
        Ok(state)
    }

    pub const fn slot(&self) -> PendingQueuePublishIntentSlot {
        self.slot
    }

    pub const fn revision(&self) -> PendingQueuePublishIntentRevision {
        self.revision
    }

    pub const fn artifact_identity(&self) -> &PendingQueueArtifactIdentity {
        &self.artifact_identity
    }

    pub const fn source_slot(&self) -> PendingQueuePublishSourceSlot {
        self.source_slot
    }

    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn assignment_digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.assignment_digest
    }

    pub const fn intent_id(&self) -> PendingQueuePublishIntentId {
        self.intent_id
    }

    pub const fn request_kind(&self) -> PendingQueuePublishRequestKind {
        self.request_kind
    }

    pub const fn close_intent(&self) -> Option<PendingQueueCloseIntentDigest> {
        self.close_intent
    }

    pub const fn payload_digest(&self) -> PendingQueuePayloadDigest {
        self.payload_digest
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub const fn fragment_count(&self) -> u16 {
        self.fragment_count
    }

    pub const fn phase(&self) -> &PendingQueuePublishIntentPhase {
        &self.phase
    }

    pub const fn bound_envelope(&self) -> Option<PendingQueueBoundEnvelope> {
        match self.phase {
            PendingQueuePublishIntentPhase::Materialized => None,
            PendingQueuePublishIntentPhase::Bound(bound)
            | PendingQueuePublishIntentPhase::NatsAccepted { bound, .. }
            | PendingQueuePublishIntentPhase::SourceCommitted { bound, .. } => Some(bound),
        }
    }

    pub const fn accepted_subject_sequence(&self) -> Option<u64> {
        match self.phase {
            PendingQueuePublishIntentPhase::NatsAccepted {
                subject_sequence,
                ..
            }
            | PendingQueuePublishIntentPhase::SourceCommitted {
                subject_sequence,
                ..
            } => Some(subject_sequence),
            _ => None,
        }
    }

    pub fn bind(
        &self,
        source: &PendingQueuePublishSourceState,
        envelope: &PendingQueuePublishEnvelope,
        payload: &[u8],
    ) -> Result<PendingQueueIntentTransitionPlan, PendingQueueOutboxError> {
        let bound = self.validate_envelope(source, envelope, payload)?;
        match &self.phase {
            PendingQueuePublishIntentPhase::Materialized => {
                let mut candidate = self.clone();
                candidate.revision = self.revision.next()?;
                candidate.phase = PendingQueuePublishIntentPhase::Bound(bound);
                Ok(PendingQueueIntentTransitionPlan::Advance {
                    expected: self.clone(),
                    candidate,
                })
            }
            PendingQueuePublishIntentPhase::Bound(current) if *current == bound => {
                Ok(PendingQueueIntentTransitionPlan::Idempotent(self.clone()))
            }
            _ => Err(PendingQueueOutboxError::IntentPhaseConflict),
        }
    }

    pub fn record_nats_accepted(
        &self,
        subject_sequence: u64,
    ) -> Result<PendingQueueIntentTransitionPlan, PendingQueueOutboxError> {
        let PendingQueuePublishIntentPhase::Bound(bound) = self.phase else {
            if matches!(
                self.phase,
                PendingQueuePublishIntentPhase::NatsAccepted {
                    subject_sequence: current,
                    ..
                } if current == subject_sequence
            ) {
                return Ok(PendingQueueIntentTransitionPlan::Idempotent(self.clone()));
            }
            return Err(PendingQueueOutboxError::IntentPhaseConflict);
        };
        if subject_sequence == 0
            || subject_sequence <= bound.previous_subject_sequence
        {
            return Err(PendingQueueOutboxError::SubjectSequenceRegressed);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.phase = PendingQueuePublishIntentPhase::NatsAccepted {
            bound,
            subject_sequence,
        };
        Ok(PendingQueueIntentTransitionPlan::Advance {
            expected: self.clone(),
            candidate,
        })
    }

    pub fn record_source_committed(
        &self,
    ) -> Result<PendingQueueIntentTransitionPlan, PendingQueueOutboxError> {
        let PendingQueuePublishIntentPhase::NatsAccepted {
            bound,
            subject_sequence,
        } = self.phase
        else {
            if matches!(self.phase, PendingQueuePublishIntentPhase::SourceCommitted { .. }) {
                return Ok(PendingQueueIntentTransitionPlan::Idempotent(self.clone()));
            }
            return Err(PendingQueueOutboxError::IntentPhaseConflict);
        };
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.phase = PendingQueuePublishIntentPhase::SourceCommitted {
            bound,
            subject_sequence,
        };
        Ok(PendingQueueIntentTransitionPlan::Advance {
            expected: self.clone(),
            candidate,
        })
    }

    fn validate_envelope(
        &self,
        source: &PendingQueuePublishSourceState,
        envelope: &PendingQueuePublishEnvelope,
        payload: &[u8],
    ) -> Result<PendingQueueBoundEnvelope, PendingQueueOutboxError> {
        if self.source_slot != source.slot().map_err(model)?
            || self.artifact_identity != *source.artifact_identity()
            || self.publisher_kind != source.publisher_kind()
            || self.assignment_digest != source.assignment_digest()
            || self.intent_id != envelope.intent_id()
            || self.artifact_identity != *envelope.artifact_identity()
            || self.publisher_kind != envelope.publisher_kind()
            || self.assignment_digest != envelope.assignment_digest()
            || !source.selected_matches(envelope)
        {
            return Err(PendingQueueOutboxError::EnvelopeBindingMismatch);
        }
        match (&self.request_kind, envelope.body()) {
            (PendingQueuePublishRequestKind::Data, PendingQueueEnvelopeBody::Data(actual)) => {
                if actual.as_slice() != payload
                    || self.payload_bytes != payload.len() as u64
                    || self.payload_digest != PendingQueuePayloadDigest::for_payload(payload)?
                {
                    return Err(PendingQueueOutboxError::PayloadMismatch);
                }
            }
            (PendingQueuePublishRequestKind::Seal, PendingQueueEnvelopeBody::Seal(summary)) => {
                if !payload.is_empty() || self.payload_bytes != 0 || self.fragment_count != 0 {
                    return Err(PendingQueueOutboxError::PayloadMismatch);
                }
                if self.close_intent != Some(summary.close_intent()) {
                    return Err(PendingQueueOutboxError::CloseIntentMismatch);
                }
            }
            _ => return Err(PendingQueueOutboxError::EnvelopeBindingMismatch),
        }
        Ok(PendingQueueBoundEnvelope {
            envelope_digest: envelope.digest(),
            member_ordinal: envelope.member_ordinal(),
            previous_subject_sequence: envelope.previous_subject_sequence(),
            previous_envelope_digest: envelope.previous_envelope_digest(),
            encoded_bytes: envelope.to_canonical_bytes().len() as u64,
        })
    }

    pub fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self.encode_unsigned().expect("validated intent remains canonical");
        out.extend_from_slice(&intent_digest(&out));
        out
    }

    pub fn decode_persisted(
        slot: PendingQueuePublishIntentSlot,
        revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueOutboxError> {
        let revision = u64::try_from(revision)
            .map_err(|_| PendingQueueOutboxError::RevisionOutOfRange)
            .and_then(PendingQueuePublishIntentRevision::try_new)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != INTENT_MAGIC {
            return Err(PendingQueueOutboxError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != RECOVERABLE_PENDING_INTENT_CODEC_VERSION {
            return Err(PendingQueueOutboxError::UnknownCodecVersion(version));
        }
        let identity_len = decoder.u32()? as usize;
        let artifact_identity = PendingQueueArtifactIdentity::decode_canonical(
            decoder.take(identity_len)?,
        )
        .map_err(|_| PendingQueueOutboxError::InvalidArtifactIdentity)?;
        let source_slot = PendingQueuePublishSourceSlot::try_new(decoder.array32()?)
            .map_err(model)?;
        let publisher_kind = decode_publisher_kind(decoder.u8()?)?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueOutboxError::EmptyDigest)?;
        let intent_id = PendingQueuePublishIntentId::try_new(decoder.array32()?)
            .map_err(model)?;
        let request_kind = match decoder.u8()? {
            1 => PendingQueuePublishRequestKind::Data,
            2 => PendingQueuePublishRequestKind::Seal,
            value => return Err(PendingQueueOutboxError::UnknownRequestKind(value)),
        };
        let close_intent_bytes = decoder.array32()?;
        let close_intent = if close_intent_bytes == [0; 32] {
            None
        } else {
            Some(
                PendingQueueCloseIntentDigest::try_new(close_intent_bytes)
                    .map_err(|error| PendingQueueOutboxError::Core(error.to_string()))?,
            )
        };
        let payload_digest = PendingQueuePayloadDigest::try_new(decoder.array32()?)?;
        let payload_bytes = decoder.u64()?;
        let fragment_count = decoder.u16()?;
        let phase = match decoder.u8()? {
            0 => PendingQueuePublishIntentPhase::Materialized,
            1 => PendingQueuePublishIntentPhase::Bound(decode_bound(&mut decoder)?),
            2 => PendingQueuePublishIntentPhase::NatsAccepted {
                bound: decode_bound(&mut decoder)?,
                subject_sequence: decoder.u64()?,
            },
            3 => PendingQueuePublishIntentPhase::SourceCommitted {
                bound: decode_bound(&mut decoder)?,
                subject_sequence: decoder.u64()?,
            },
            value => return Err(PendingQueueOutboxError::UnknownIntentPhase(value)),
        };
        let encoded_digest = decoder.array32()?;
        if !decoder.done() {
            return Err(PendingQueueOutboxError::TrailingBytes);
        }
        if intent_digest(&bytes[..bytes.len() - 32]) != encoded_digest {
            return Err(PendingQueueOutboxError::DigestMismatch);
        }
        let state = Self {
            slot,
            revision,
            artifact_identity,
            source_slot,
            publisher_kind,
            assignment_digest,
            intent_id,
            request_kind,
            close_intent,
            payload_digest,
            payload_bytes,
            fragment_count,
            phase,
        };
        state.validate()?;
        Ok(state)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, PendingQueueOutboxError> {
        self.validate()?;
        let identity = self.artifact_identity.to_canonical_bytes();
        let mut out = Vec::with_capacity(identity.len() + 256);
        out.extend_from_slice(INTENT_MAGIC);
        out.extend_from_slice(&RECOVERABLE_PENDING_INTENT_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&(identity.len() as u32).to_be_bytes());
        out.extend_from_slice(&identity);
        out.extend_from_slice(self.source_slot.as_bytes());
        out.push(self.publisher_kind as u8);
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(self.intent_id.as_bytes());
        out.push(self.request_kind as u8);
        out.extend_from_slice(
            self.close_intent
                .map(|close| *close.as_bytes())
                .unwrap_or([0; 32])
                .as_slice(),
        );
        out.extend_from_slice(self.payload_digest.as_bytes());
        out.extend_from_slice(&self.payload_bytes.to_be_bytes());
        out.extend_from_slice(&self.fragment_count.to_be_bytes());
        match self.phase {
            PendingQueuePublishIntentPhase::Materialized => out.push(0),
            PendingQueuePublishIntentPhase::Bound(bound) => {
                out.push(1);
                encode_bound(bound, &mut out);
            }
            PendingQueuePublishIntentPhase::NatsAccepted {
                bound,
                subject_sequence,
            } => {
                out.push(2);
                encode_bound(bound, &mut out);
                out.extend_from_slice(&subject_sequence.to_be_bytes());
            }
            PendingQueuePublishIntentPhase::SourceCommitted {
                bound,
                subject_sequence,
            } => {
                out.push(3);
                encode_bound(bound, &mut out);
                out.extend_from_slice(&subject_sequence.to_be_bytes());
            }
        }
        Ok(out)
    }

    fn validate(&self) -> Result<(), PendingQueueOutboxError> {
        if self.slot
            != PendingQueuePublishIntentSlot::derive(
                &self.artifact_identity,
                self.publisher_kind,
                self.intent_id,
            )?
            || self.source_slot
                != PendingQueuePublishSourceSlot::for_identity(
                    &self.artifact_identity,
                    self.publisher_kind,
                    self.assignment_digest,
                )
                .map_err(model)?
        {
            return Err(PendingQueueOutboxError::IdentityMismatch);
        }
        match self.request_kind {
            PendingQueuePublishRequestKind::Data => {
                if self.close_intent.is_some()
                    || self.payload_bytes == 0
                    || self.fragment_count == 0
                    || self.fragment_count > MAX_RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS
                {
                    return Err(PendingQueueOutboxError::InvalidFragmentPlan);
                }
            }
            PendingQueuePublishRequestKind::Seal => {
                if self.close_intent.is_none()
                    || self.payload_bytes != 0
                    || self.fragment_count != 0
                {
                    return Err(PendingQueueOutboxError::InvalidFragmentPlan);
                }
            }
        }
        let accepted = match self.phase {
            PendingQueuePublishIntentPhase::NatsAccepted {
                bound,
                subject_sequence,
            }
            | PendingQueuePublishIntentPhase::SourceCommitted {
                bound,
                subject_sequence,
            } => Some((bound, subject_sequence)),
            _ => None,
        };
        if accepted.is_some_and(|(bound, sequence)| {
            sequence == 0 || sequence <= bound.previous_subject_sequence
        }) {
            return Err(PendingQueueOutboxError::SubjectSequenceRegressed);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueIntentTransitionPlan {
    Idempotent(StoredPendingQueuePublishIntent),
    Advance {
        expected: StoredPendingQueuePublishIntent,
        candidate: StoredPendingQueuePublishIntent,
    },
}

impl PendingQueueIntentTransitionPlan {
    pub const fn current(&self) -> &StoredPendingQueuePublishIntent {
        match self {
            Self::Idempotent(current) => current,
            Self::Advance { candidate, .. } => candidate,
        }
    }

    pub const fn transition(
        &self,
    ) -> Option<(&StoredPendingQueuePublishIntent, &StoredPendingQueuePublishIntent)> {
        match self {
            Self::Idempotent(_) => None,
            Self::Advance { expected, candidate } => Some((expected, candidate)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePayloadFragment {
    payload_digest: PendingQueuePayloadDigest,
    fragment_index: u16,
    fragment_count: u16,
    payload_bytes: u64,
    bytes: Vec<u8>,
    digest: PendingQueuePayloadFragmentDigest,
}

impl PendingQueuePayloadFragment {
    pub const fn payload_digest(&self) -> PendingQueuePayloadDigest {
        self.payload_digest
    }

    pub const fn fragment_index(&self) -> u16 {
        self.fragment_index
    }

    pub const fn fragment_count(&self) -> u16 {
        self.fragment_count
    }

    pub const fn fragment_bucket(&self) -> u16 {
        self.fragment_index / RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS_PER_BUCKET
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> PendingQueuePayloadFragmentDigest {
        self.digest
    }

    pub fn decode_observed(
        payload_digest: [u8; 32],
        fragment_index: i16,
        fragment_count: i16,
        payload_bytes: i64,
        bytes: Vec<u8>,
        digest: [u8; 32],
    ) -> Result<Self, PendingQueueOutboxError> {
        let payload_digest = PendingQueuePayloadDigest::try_new(payload_digest)?;
        let fragment_index = u16::try_from(fragment_index)
            .map_err(|_| PendingQueueOutboxError::InvalidFragmentPlan)?;
        let fragment_count = u16::try_from(fragment_count)
            .map_err(|_| PendingQueueOutboxError::InvalidFragmentPlan)?;
        let payload_bytes = u64::try_from(payload_bytes)
            .map_err(|_| PendingQueueOutboxError::InvalidFragmentPlan)?;
        let observed = Self {
            payload_digest,
            fragment_index,
            fragment_count,
            payload_bytes,
            digest: PendingQueuePayloadFragmentDigest::try_new(digest)?,
            bytes,
        };
        if observed.fragment_count == 0
            || observed.fragment_count > MAX_RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS
            || observed.fragment_index >= observed.fragment_count
            || observed.bytes.is_empty()
            || observed.bytes.len() > RECOVERABLE_PENDING_PAYLOAD_FRAGMENT_BYTES
            || observed.digest != fragment_digest(&observed)
        {
            return Err(PendingQueueOutboxError::InvalidFragmentPlan);
        }
        Ok(observed)
    }
}

pub fn fragment_payload(
    _intent_id: PendingQueuePublishIntentId,
    payload: &[u8],
) -> Result<Vec<PendingQueuePayloadFragment>, PendingQueueOutboxError> {
    if payload.is_empty() {
        return Err(PendingQueueOutboxError::EmptyData);
    }
    let count = payload.len().div_ceil(RECOVERABLE_PENDING_PAYLOAD_FRAGMENT_BYTES);
    let count = u16::try_from(count)
        .map_err(|_| PendingQueueOutboxError::PayloadTooLarge)?;
    if count == 0 || count > MAX_RECOVERABLE_PENDING_PAYLOAD_FRAGMENTS {
        return Err(PendingQueueOutboxError::PayloadTooLarge);
    }
    let payload_digest = PendingQueuePayloadDigest::for_payload(payload)?;
    let mut fragments = Vec::with_capacity(count as usize);
    for (index, bytes) in payload
        .chunks(RECOVERABLE_PENDING_PAYLOAD_FRAGMENT_BYTES)
        .enumerate()
    {
        let mut fragment = PendingQueuePayloadFragment {
            payload_digest,
            fragment_index: index as u16,
            fragment_count: count,
            payload_bytes: payload.len() as u64,
            bytes: bytes.to_vec(),
            digest: PendingQueuePayloadFragmentDigest([1; 32]),
        };
        fragment.digest = fragment_digest(&fragment);
        fragments.push(fragment);
    }
    Ok(fragments)
}

pub fn reconstruct_payload(
    intent: &StoredPendingQueuePublishIntent,
    fragments: Vec<PendingQueuePayloadFragment>,
) -> Result<Vec<u8>, PendingQueueOutboxError> {
    if intent.request_kind == PendingQueuePublishRequestKind::Seal {
        if fragments.is_empty() {
            return Ok(Vec::new());
        }
        return Err(PendingQueueOutboxError::ExtraFragment);
    }
    if fragments.len() != intent.fragment_count as usize {
        return Err(PendingQueueOutboxError::MissingFragment);
    }
    let mut payload = Vec::with_capacity(intent.payload_bytes as usize);
    for (expected_index, fragment) in fragments.iter().enumerate() {
        if fragment.fragment_index != expected_index as u16
            || fragment.fragment_count != intent.fragment_count
            || fragment.payload_bytes != intent.payload_bytes
            || fragment.payload_digest != intent.payload_digest
            || fragment.digest != fragment_digest(fragment)
        {
            return Err(PendingQueueOutboxError::FragmentMismatch);
        }
        payload.extend_from_slice(&fragment.bytes);
    }
    if payload.len() as u64 != intent.payload_bytes
        || PendingQueuePayloadDigest::for_payload(&payload)? != intent.payload_digest
    {
        return Err(PendingQueueOutboxError::PayloadMismatch);
    }
    Ok(payload)
}

fn fragment_digest(fragment: &PendingQueuePayloadFragment) -> PendingQueuePayloadFragmentDigest {
    let mut hasher = Sha256::new();
    hasher.update(FRAGMENT_DIGEST_DOMAIN);
    hasher.update(fragment.payload_digest.as_bytes());
    hasher.update(fragment.fragment_index.to_be_bytes());
    hasher.update(fragment.fragment_count.to_be_bytes());
    hasher.update(fragment.payload_bytes.to_be_bytes());
    hasher.update((fragment.bytes.len() as u64).to_be_bytes());
    hasher.update(&fragment.bytes);
    PendingQueuePayloadFragmentDigest(hasher.finalize().into())
}

fn intent_digest(unsigned: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(INTENT_DIGEST_DOMAIN);
    hasher.update((unsigned.len() as u64).to_be_bytes());
    hasher.update(unsigned);
    hasher.finalize().into()
}

fn encode_bound(bound: PendingQueueBoundEnvelope, out: &mut Vec<u8>) {
    out.extend_from_slice(bound.envelope_digest.as_bytes());
    out.extend_from_slice(&bound.member_ordinal.get().to_be_bytes());
    out.extend_from_slice(&bound.previous_subject_sequence.to_be_bytes());
    out.extend_from_slice(&bound.previous_envelope_digest);
    out.extend_from_slice(&bound.encoded_bytes.to_be_bytes());
}

fn decode_bound(decoder: &mut Decoder<'_>) -> Result<PendingQueueBoundEnvelope, PendingQueueOutboxError> {
    Ok(PendingQueueBoundEnvelope {
        envelope_digest: PendingQueueEnvelopeDigest::try_new(decoder.array32()?).map_err(model)?,
        member_ordinal: PendingQueueMemberOrdinal::try_new(decoder.u32()?).map_err(model)?,
        previous_subject_sequence: decoder.u64()?,
        previous_envelope_digest: decoder.array32()?,
        encoded_bytes: decoder.u64()?,
    })
}

fn decode_publisher_kind(value: u8) -> Result<PendingQueuePublisherKind, PendingQueueOutboxError> {
    match value {
        1 => Ok(PendingQueuePublisherKind::CoordinatorRegistration),
        2 => Ok(PendingQueuePublisherKind::CoordinatorDeploy),
        3 => Ok(PendingQueuePublisherKind::CoordinatorGuta),
        32 => Ok(PendingQueuePublisherKind::RealmUserUpdate),
        _ => Err(PendingQueueOutboxError::UnknownPublisherKind(value)),
    }
}

fn encode_authority(authority: AuthorityScope, hasher: &mut Sha256) {
    match authority {
        AuthorityScope::Coordinator => hasher.update([1]),
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

fn model(error: PendingQueueEnvelopeError) -> PendingQueueOutboxError {
    PendingQueueOutboxError::Envelope(error.to_string())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueOutboxError> {
        let end = self.offset.checked_add(len).ok_or(PendingQueueOutboxError::Malformed)?;
        let value = self.bytes.get(self.offset..end).ok_or(PendingQueueOutboxError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueOutboxError> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, PendingQueueOutboxError> { Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap())) }
    fn u32(&mut self) -> Result<u32, PendingQueueOutboxError> { Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap())) }
    fn u64(&mut self) -> Result<u64, PendingQueueOutboxError> { Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap())) }
    fn array32(&mut self) -> Result<[u8; 32], PendingQueueOutboxError> { Ok(self.take(32)?.try_into().unwrap()) }
    const fn done(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueOutboxError {
    EmptyDigest,
    EmptyData,
    PayloadTooLarge,
    InvalidFragmentPlan,
    MissingFragment,
    ExtraFragment,
    FragmentMismatch,
    PayloadMismatch,
    CloseIntentMismatch,
    IdentityMismatch,
    EnvelopeBindingMismatch,
    IntentPhaseConflict,
    SubjectSequenceRegressed,
    RevisionOutOfRange,
    RevisionOverflow,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownRequestKind(u8),
    UnknownIntentPhase(u8),
    UnknownPublisherKind(u8),
    InvalidArtifactIdentity,
    DigestMismatch,
    TrailingBytes,
    Malformed,
    Core(String),
    Envelope(String),
}

impl fmt::Display for PendingQueueOutboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result { write!(formatter, "{self:?}") }
}

impl Error for PendingQueueOutboxError {}

#[cfg(test)]
mod tests {
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

    use crate::{
        recoverable_assignment::{
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueSourceQuota,
            RecoverableNatsSourceRoute,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    use super::*;

    fn fixture(
        pending: u64,
    ) -> (
        RecoverableNatsStreamSegment,
        crate::recoverable_assignment::PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
        PendingQueuePublishSourceState,
    ) {
        let authority = AuthorityScope::Coordinator;
        let key = PendingGenerationLedgerKey::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            authority,
        );
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(pending, 99 + pending as u128)
                .unwrap(),
        )
        .unwrap();
        let segment = RecoverableNatsStreamSegment::try_new(
            "psy.mainnet",
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
        let quotas = vec![
            PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::CoordinatorRegistration,
                10_000,
                15 * 1024 * 1024,
                1024 * 1024,
            )
            .unwrap(),
            PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::CoordinatorDeploy,
                10_000,
                47 * 1024 * 1024,
                1024 * 1024,
            )
            .unwrap(),
            PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::CoordinatorGuta,
                10_000,
                63 * 1024 * 1024,
                1024 * 1024,
            )
            .unwrap(),
        ];
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            128 * 1024 * 1024,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let bootstrap = PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &validated,
            budget,
            8,
        )
        .unwrap();
        let assignment = match bootstrap.candidate().reserve_generation(context).unwrap() {
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => assignment,
            _ => unreachable!(),
        };
        let route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::CoordinatorGuta,
            &segment,
        )
        .unwrap();
        let source = PendingQueuePublishSourceState::bootstrap(&route, &assignment).unwrap();
        (segment, assignment, route, source)
    }

    #[test]
    fn payload_fragments_and_intent_codec_are_exact() {
        let (_, _, _, source) = fixture(7);
        let intent_id = PendingQueuePublishIntentId::try_new([8; 32]).unwrap();
        let payload = vec![9; RECOVERABLE_PENDING_PAYLOAD_FRAGMENT_BYTES + 17];
        let (intent, fragments) =
            StoredPendingQueuePublishIntent::materialize_data(&source, intent_id, &payload)
                .unwrap();
        assert_eq!(fragments.len(), 2);
        assert_eq!(fragments[0].fragment_bucket(), 0);
        assert_eq!(reconstruct_payload(&intent, fragments).unwrap(), payload);
        let encoded = intent.to_persisted_bytes();
        assert_eq!(
            StoredPendingQueuePublishIntent::decode_persisted(
                intent.slot(),
                intent.revision().as_i64(),
                &encoded,
            )
            .unwrap(),
            intent,
        );
        let mut legacy = encoded.clone();
        legacy[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            StoredPendingQueuePublishIntent::decode_persisted(
                intent.slot(),
                intent.revision().as_i64(),
                &legacy,
            ),
            Err(PendingQueueOutboxError::UnknownCodecVersion(1)),
        );
        let mut corrupted = encoded;
        corrupted[20] ^= 1;
        assert!(StoredPendingQueuePublishIntent::decode_persisted(
            intent.slot(),
            intent.revision().as_i64(),
            &corrupted,
        )
        .is_err());
    }

    #[test]
    fn source_winner_binds_final_predecessor_and_commit_anchors() {
        let (_, assignment, route, source) = fixture(7);
        let payload = b"durable-guta".to_vec();
        let (intent, fragments) = StoredPendingQueuePublishIntent::materialize_data(
            &source,
            PendingQueuePublishIntentId::try_new([11; 32]).unwrap(),
            &payload,
        )
        .unwrap();
        let payload = reconstruct_payload(&intent, fragments).unwrap();
        let envelope = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            intent.intent_id(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            payload.clone(),
        )
        .unwrap();
        let selected_source = match source.select(&envelope).unwrap() {
            crate::recoverable_publish::PendingQueueSourceSelectionPlan::Advance {
                candidate,
                ..
            } => candidate,
            _ => unreachable!(),
        };
        let bound = match intent.bind(&selected_source, &envelope, &payload).unwrap() {
            PendingQueueIntentTransitionPlan::Advance { candidate, .. } => candidate,
            _ => unreachable!(),
        };
        let accepted = match bound.record_nats_accepted(41).unwrap() {
            PendingQueueIntentTransitionPlan::Advance { candidate, .. } => candidate,
            _ => unreachable!(),
        };
        let commit_pending = selected_source
            .record_published(41)
            .unwrap()
            .candidate()
            .clone();
        assert!(matches!(
            commit_pending.phase(),
            crate::recoverable_publish::PendingQueuePublishSourcePhase::CommitPending { .. }
        ));
        let source_committed = match accepted.record_source_committed().unwrap() {
            PendingQueueIntentTransitionPlan::Advance { candidate, .. } => candidate,
            _ => unreachable!(),
        };
        assert!(matches!(
            source_committed.phase(),
            PendingQueuePublishIntentPhase::SourceCommitted { .. }
        ));
        let open = commit_pending.finalize_published().unwrap().candidate().clone();
        assert_eq!(open.data_member_count(), 1);
    }

    #[test]
    fn caller_intent_slot_is_generation_independent_but_first_binding_is_exact() {
        let (_, _, _, first_source) = fixture(7);
        let (_, _, _, second_source) = fixture(8);
        let intent_id = PendingQueuePublishIntentId::try_new([17; 32]).unwrap();
        let (first, _) = StoredPendingQueuePublishIntent::materialize_data(
            &first_source,
            intent_id,
            b"same-call",
        )
        .unwrap();
        let (second, _) = StoredPendingQueuePublishIntent::materialize_data(
            &second_source,
            intent_id,
            b"same-call",
        )
        .unwrap();
        assert_eq!(first.slot(), second.slot());
        assert_ne!(first.source_slot(), second.source_slot());
        assert_ne!(first, second);
    }

    #[test]
    fn seal_winner_leaves_only_generation_scoped_preparation_rebindable() {
        let (_, assignment, route, source) = fixture(7);
        let data_intent_id = PendingQueuePublishIntentId::try_new([21; 32]).unwrap();
        let (prepared_data, _) = StoredPendingQueuePublishIntent::materialize_data(
            &source,
            data_intent_id,
            b"prepared-before-seal",
        )
        .unwrap();
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            data_intent_id,
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            b"prepared-before-seal".to_vec(),
        )
        .unwrap();
        let seal_intent = StoredPendingQueuePublishIntent::materialize_seal(
            &source,
            PendingQueuePublishIntentId::try_new([22; 32]).unwrap(),
            PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap(),
        )
        .unwrap();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            seal_intent.intent_id(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            source
                .seal_summary(PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let sealing = source.select(&seal).unwrap().current().clone();
        assert!(seal_intent.bind(&sealing, &seal, &[]).is_ok());
        let wrong_close_seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            seal_intent.intent_id(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            source
                .seal_summary(PendingQueueCloseIntentDigest::try_new([8; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let wrong_sealing = source
            .select(&wrong_close_seal)
            .unwrap()
            .current()
            .clone();
        assert!(matches!(
            seal_intent.bind(&wrong_sealing, &wrong_close_seal, &[]),
            Err(PendingQueueOutboxError::CloseIntentMismatch)
        ));
        assert!(sealing.select(&data).is_err());
        assert!(matches!(
            prepared_data.phase(),
            PendingQueuePublishIntentPhase::Materialized
        ));

        let (_, _, _, next_source) = fixture(8);
        let (next_prepared, _) = StoredPendingQueuePublishIntent::materialize_data(
            &next_source,
            data_intent_id,
            b"prepared-before-seal",
        )
        .unwrap();
        assert_eq!(prepared_data.slot(), next_prepared.slot());
        assert_ne!(prepared_data.source_slot(), next_prepared.source_slot());
    }
}
