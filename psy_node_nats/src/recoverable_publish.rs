//! Deterministic Data/Seal envelopes for branch-exact pending queues.
//!
//! This module is driver independent.  Constructing an envelope is not
//! permission to publish it: c2b2's durable generation charge and outbox must
//! first read it back exactly and mint the execution receipt consumed by the
//! concrete NATS publisher.

use std::{error::Error, fmt};

use psy_data::protocol::chain_context::AuthorityScope;
use psy_node_core::queue::recoverable_ephemeral::{
    PendingQueueArtifactIdentity, PendingQueueCaptureContext,
    PendingQueueSourceAddress, PendingQueueSourceIdentity,
    PendingQueueSourceIdentityDigest, MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
};
use psy_node_core::store::pending_generation_pipeline::PendingQueueCloseIntentDigest;
use sha2::{Digest, Sha256};

use crate::{
    recoverable_assignment::{
        PendingQueueGenerationSegmentAssignment,
        PendingQueueSegmentAssignmentDigest,
    },
    recoverable_segment::{
        RecoverableNatsSegmentContractDigest, RecoverableNatsSegmentId,
        RecoverableNatsStreamSegment, RECOVERABLE_NATS_MAX_MESSAGE_BYTES,
    },
};

pub const RECOVERABLE_PENDING_ENVELOPE_CODEC_VERSION: u16 = 2;
pub const RECOVERABLE_PENDING_SOURCE_STATE_CODEC_VERSION: u16 = 2;
pub const MAX_RECOVERABLE_PENDING_ENVELOPE_BYTES: usize =
    RECOVERABLE_NATS_MAX_MESSAGE_BYTES as usize;
const MAGIC: &[u8; 8] = b"PSYQENV1";
const DIGEST_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-envelope/v1";
const BUDGET_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-budget/v1";
const BUDGET_MAGIC: &[u8; 8] = b"PSYQBUD1";
const ROLLING_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-dataset/v1";
const SOURCE_STATE_MAGIC: &[u8; 8] = b"PSYQSRC1";
const SOURCE_STATE_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/recoverable-pending-source-state/v1";
const SOURCE_SLOT_DOMAIN: &[u8] = b"psy/rollback/recoverable-pending-source-slot/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum PendingQueuePublisherKind {
    CoordinatorRegistration = 1,
    CoordinatorDeploy = 2,
    CoordinatorGuta = 3,
    RealmUserUpdate = 32,
}

impl PendingQueuePublisherKind {
    pub const fn expected_authority_kind(self) -> u8 {
        match self {
            Self::CoordinatorRegistration
            | Self::CoordinatorDeploy
            | Self::CoordinatorGuta => 1,
            Self::RealmUserUpdate => 2,
        }
    }

    pub(crate) fn try_from_u8(value: u8) -> Result<Self, PendingQueueEnvelopeError> {
        match value {
            1 => Ok(Self::CoordinatorRegistration),
            2 => Ok(Self::CoordinatorDeploy),
            3 => Ok(Self::CoordinatorGuta),
            32 => Ok(Self::RealmUserUpdate),
            _ => Err(PendingQueueEnvelopeError::UnknownPublisherKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSourceQuota {
    publisher_kind: PendingQueuePublisherKind,
    max_data_members: u32,
    max_data_stored_bytes: u64,
    max_seal_stored_bytes: u64,
}

impl PendingQueueSourceQuota {
    pub fn try_new(
        publisher_kind: PendingQueuePublisherKind,
        max_data_members: u32,
        max_data_stored_bytes: u64,
        max_seal_stored_bytes: u64,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        if max_data_members == 0
            || max_data_stored_bytes == 0
            || max_seal_stored_bytes == 0
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceQuota);
        }
        max_data_stored_bytes
            .checked_add(max_seal_stored_bytes)
            .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?;
        Ok(Self {
            publisher_kind,
            max_data_members,
            max_data_stored_bytes,
            max_seal_stored_bytes,
        })
    }

    pub const fn publisher_kind(self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn max_data_members(self) -> u32 {
        self.max_data_members
    }

    pub const fn max_data_stored_bytes(self) -> u64 {
        self.max_data_stored_bytes
    }

    pub const fn max_seal_stored_bytes(self) -> u64 {
        self.max_seal_stored_bytes
    }

    pub fn max_source_stored_bytes(self) -> u64 {
        self.max_data_stored_bytes + self.max_seal_stored_bytes
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueGenerationBudgetDigest([u8; 32]);

impl PendingQueueGenerationBudgetDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueEnvelopeError> {
        if bytes == [0; 32] {
            Err(PendingQueueEnvelopeError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact 3/1 source manifest and quota contract.  The sum is the generation
/// reservation, so each source can charge independently without a shared LWT
/// and the aggregate can never exceed the reserved capacity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueGenerationBudgetContract {
    authority: AuthorityScope,
    sources: Vec<PendingQueueSourceQuota>,
    max_generation_stored_bytes: u64,
    digest: PendingQueueGenerationBudgetDigest,
}

impl PendingQueueGenerationBudgetContract {
    pub fn try_new(
        authority: AuthorityScope,
        sources: Vec<PendingQueueSourceQuota>,
        max_generation_stored_bytes: u64,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        let expected: &[PendingQueuePublisherKind] = match authority {
            AuthorityScope::Coordinator => &[
                PendingQueuePublisherKind::CoordinatorRegistration,
                PendingQueuePublisherKind::CoordinatorDeploy,
                PendingQueuePublisherKind::CoordinatorGuta,
            ],
            AuthorityScope::Realm { .. } => {
                &[PendingQueuePublisherKind::RealmUserUpdate]
            }
        };
        if sources.len() != expected.len()
            || sources
                .iter()
                .zip(expected)
                .any(|(source, expected)| source.publisher_kind != *expected)
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceManifest);
        }
        let total = sources.iter().try_fold(0_u64, |sum, source| {
            sum.checked_add(source.max_source_stored_bytes())
                .ok_or(PendingQueueEnvelopeError::BudgetOverflow)
        })?;
        if total == 0 || total != max_generation_stored_bytes {
            return Err(PendingQueueEnvelopeError::GenerationBudgetMismatch);
        }
        let mut unsigned = Vec::with_capacity(128);
        encode_authority(authority, &mut unsigned);
        unsigned.extend_from_slice(&max_generation_stored_bytes.to_be_bytes());
        unsigned.push(sources.len() as u8);
        for source in &sources {
            unsigned.push(source.publisher_kind as u8);
            unsigned.extend_from_slice(&source.max_data_members.to_be_bytes());
            unsigned.extend_from_slice(&source.max_data_stored_bytes.to_be_bytes());
            unsigned.extend_from_slice(&source.max_seal_stored_bytes.to_be_bytes());
        }
        let mut hasher = Sha256::new();
        hasher.update(BUDGET_DOMAIN);
        hasher.update((unsigned.len() as u64).to_be_bytes());
        hasher.update(unsigned);
        let digest = PendingQueueGenerationBudgetDigest::try_new(
            hasher.finalize().into(),
        )?;
        Ok(Self {
            authority,
            sources,
            max_generation_stored_bytes,
            digest,
        })
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub fn sources(&self) -> &[PendingQueueSourceQuota] {
        &self.sources
    }

    pub const fn max_generation_stored_bytes(&self) -> u64 {
        self.max_generation_stored_bytes
    }

    pub const fn digest(&self) -> PendingQueueGenerationBudgetDigest {
        self.digest
    }

    pub fn quota_for(
        &self,
        kind: PendingQueuePublisherKind,
    ) -> Option<PendingQueueSourceQuota> {
        self.sources
            .iter()
            .copied()
            .find(|source| source.publisher_kind == kind)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(BUDGET_MAGIC);
        out.extend_from_slice(&1_u16.to_be_bytes());
        encode_authority(self.authority, &mut out);
        out.extend_from_slice(&self.max_generation_stored_bytes.to_be_bytes());
        out.push(self.sources.len() as u8);
        for source in &self.sources {
            out.push(source.publisher_kind as u8);
            out.extend_from_slice(&source.max_data_members.to_be_bytes());
            out.extend_from_slice(&source.max_data_stored_bytes.to_be_bytes());
            out.extend_from_slice(&source.max_seal_stored_bytes.to_be_bytes());
        }
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, PendingQueueEnvelopeError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != BUDGET_MAGIC {
            return Err(PendingQueueEnvelopeError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != 1 {
            return Err(PendingQueueEnvelopeError::UnknownCodecVersion(version));
        }
        let authority = decode_authority(&mut decoder)?;
        let max_generation_stored_bytes = decoder.u64()?;
        let count = decoder.u8()? as usize;
        if count == 0 || count > 3 {
            return Err(PendingQueueEnvelopeError::InvalidSourceManifest);
        }
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            sources.push(PendingQueueSourceQuota::try_new(
                PendingQueuePublisherKind::try_from_u8(decoder.u8()?)?,
                decoder.u32()?,
                decoder.u64()?,
                decoder.u64()?,
            )?);
        }
        let encoded_digest = PendingQueueGenerationBudgetDigest::try_new(
            decoder.array32()?,
        )?;
        if !decoder.done() {
            return Err(PendingQueueEnvelopeError::TrailingBytes);
        }
        let contract = Self::try_new(
            authority,
            sources,
            max_generation_stored_bytes,
        )?;
        if contract.digest != encoded_digest {
            return Err(PendingQueueEnvelopeError::BudgetDigestMismatch);
        }
        Ok(contract)
    }
}

/// Closed, branch-exact route for one of the four recoverable production
/// sources.  The rendered subject is derived from the complete capture
/// context and the closed publisher kind; it never accepts a caller supplied
/// suffix and does not contain a digest that recursively depends on itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoverableNatsSourceRoute {
    context: PendingQueueCaptureContext,
    publisher_kind: PendingQueuePublisherKind,
    source_identity: PendingQueueSourceIdentity,
    subject: String,
}

impl RecoverableNatsSourceRoute {
    pub fn try_new(
        context: PendingQueueCaptureContext,
        publisher_kind: PendingQueuePublisherKind,
        segment: &RecoverableNatsStreamSegment,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        validate_authority(publisher_kind, context.key().authority())?;
        let suffix = format!(
            "G{}.K{:02x}",
            hex::encode(context.digest().as_bytes()),
            publisher_kind as u8,
        );
        let subject = segment
            .exact_subject(&suffix)
            .map_err(|_| PendingQueueEnvelopeError::InvalidSubject)?;
        let source_identity = PendingQueueSourceIdentity::nats_jetstream(
            segment.base_namespace(),
            segment.stream_name(),
            &subject,
        )
        .map_err(|_| PendingQueueEnvelopeError::InvalidSubject)?;
        Ok(Self {
            context,
            publisher_kind,
            source_identity,
            subject,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn source_identity(&self) -> &PendingQueueSourceIdentity {
        &self.source_identity
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn artifact_identity(
        &self,
    ) -> Result<PendingQueueArtifactIdentity, PendingQueueEnvelopeError> {
        PendingQueueArtifactIdentity::try_new(
            self.context,
            self.source_identity.clone(),
        )
        .map_err(|_| PendingQueueEnvelopeError::InvalidArtifactIdentity)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueMemberOrdinal(u32);

impl PendingQueueMemberOrdinal {
    pub const fn try_new(value: u32) -> Result<Self, PendingQueueEnvelopeError> {
        if value == 0 {
            Err(PendingQueueEnvelopeError::ZeroMemberOrdinal)
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishIntentId([u8; 32]);

impl PendingQueuePublishIntentId {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueEnvelopeError> {
        if bytes == [0; 32] {
            Err(PendingQueueEnvelopeError::EmptyIntentId)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueEnvelopeDigest([u8; 32]);

impl PendingQueueEnvelopeDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueEnvelopeError> {
        if bytes == [0; 32] {
            Err(PendingQueueEnvelopeError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueEnvelopeBody {
    Data(Vec<u8>),
    Seal(PendingQueueSealSummary),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSealSummary {
    close_intent: PendingQueueCloseIntentDigest,
    data_member_count: u32,
    data_payload_bytes: u64,
    data_encoded_bytes: u64,
    data_rolling_digest: [u8; 32],
}

impl PendingQueueSealSummary {
    pub fn try_new(
        close_intent: PendingQueueCloseIntentDigest,
        data_member_count: u32,
        data_payload_bytes: u64,
        data_encoded_bytes: u64,
        data_rolling_digest: [u8; 32],
    ) -> Result<Self, PendingQueueEnvelopeError> {
        if data_member_count == 0 {
            if data_payload_bytes != 0
                || data_encoded_bytes != 0
                || data_rolling_digest != [0; 32]
            {
                return Err(PendingQueueEnvelopeError::InvalidEmptySeal);
            }
        } else if data_payload_bytes == 0
            || data_encoded_bytes == 0
            || data_rolling_digest == [0; 32]
        {
            return Err(PendingQueueEnvelopeError::InvalidSealSummary);
        }
        Ok(Self {
            close_intent,
            data_member_count,
            data_payload_bytes,
            data_encoded_bytes,
            data_rolling_digest,
        })
    }

    pub const fn close_intent(self) -> PendingQueueCloseIntentDigest {
        self.close_intent
    }

    pub const fn data_member_count(self) -> u32 {
        self.data_member_count
    }

    pub const fn data_payload_bytes(self) -> u64 {
        self.data_payload_bytes
    }

    pub const fn data_encoded_bytes(self) -> u64 {
        self.data_encoded_bytes
    }

    pub const fn data_rolling_digest(self) -> [u8; 32] {
        self.data_rolling_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishEnvelope {
    publisher_kind: PendingQueuePublisherKind,
    artifact_identity: PendingQueueArtifactIdentity,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    intent_id: PendingQueuePublishIntentId,
    member_ordinal: PendingQueueMemberOrdinal,
    previous_subject_sequence: u64,
    previous_envelope_digest: [u8; 32],
    body: PendingQueueEnvelopeBody,
    digest: PendingQueueEnvelopeDigest,
}

impl PendingQueuePublishEnvelope {
    pub fn data(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        intent_id: PendingQueuePublishIntentId,
        member_ordinal: PendingQueueMemberOrdinal,
        previous_subject_sequence: u64,
        previous_envelope_digest: [u8; 32],
        payload: Vec<u8>,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        if payload.is_empty() {
            return Err(PendingQueueEnvelopeError::EmptyData);
        }
        if payload.len() > MAX_RECOVERABLE_QUEUE_BATCH_BYTES {
            return Err(PendingQueueEnvelopeError::DataTooLarge);
        }
        Self::build(
            route,
            assignment,
            intent_id,
            member_ordinal,
            previous_subject_sequence,
            previous_envelope_digest,
            PendingQueueEnvelopeBody::Data(payload),
        )
    }

    pub fn seal(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        intent_id: PendingQueuePublishIntentId,
        member_ordinal: PendingQueueMemberOrdinal,
        previous_subject_sequence: u64,
        previous_envelope_digest: [u8; 32],
        summary: PendingQueueSealSummary,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        Self::build(
            route,
            assignment,
            intent_id,
            member_ordinal,
            previous_subject_sequence,
            previous_envelope_digest,
            PendingQueueEnvelopeBody::Seal(summary),
        )
    }

    fn build(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        intent_id: PendingQueuePublishIntentId,
        member_ordinal: PendingQueueMemberOrdinal,
        previous_subject_sequence: u64,
        previous_envelope_digest: [u8; 32],
        body: PendingQueueEnvelopeBody,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        if route.context != assignment.context() {
            return Err(PendingQueueEnvelopeError::AssignmentContextMismatch);
        }
        validate_authority(route.publisher_kind, route.context.key().authority())?;
        validate_predecessor(
            member_ordinal,
            previous_subject_sequence,
            previous_envelope_digest,
        )?;
        if let PendingQueueEnvelopeBody::Seal(summary) = &body {
            if member_ordinal.get().checked_sub(1)
                != Some(summary.data_member_count)
            {
                return Err(PendingQueueEnvelopeError::SealIndexMismatch);
            }
        }
        let mut envelope = Self {
            publisher_kind: route.publisher_kind,
            artifact_identity: route.artifact_identity()?,
            segment_id: assignment.segment_id(),
            contract_digest: assignment.contract_digest(),
            assignment_digest: assignment.digest(),
            intent_id,
            member_ordinal,
            previous_subject_sequence,
            previous_envelope_digest,
            body,
            digest: PendingQueueEnvelopeDigest([1; 32]),
        };
        let unsigned = envelope.encode_unsigned()?;
        envelope.digest = derive_digest(&unsigned)?;
        if envelope.to_canonical_bytes().len()
            > MAX_RECOVERABLE_PENDING_ENVELOPE_BYTES
        {
            return Err(PendingQueueEnvelopeError::EnvelopeTooLarge);
        }
        Ok(envelope)
    }

    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn artifact_identity(&self) -> &PendingQueueArtifactIdentity {
        &self.artifact_identity
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub const fn assignment_digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.assignment_digest
    }

    pub const fn intent_id(&self) -> PendingQueuePublishIntentId {
        self.intent_id
    }

    pub const fn member_ordinal(&self) -> PendingQueueMemberOrdinal {
        self.member_ordinal
    }

    pub const fn previous_subject_sequence(&self) -> u64 {
        self.previous_subject_sequence
    }

    pub const fn previous_envelope_digest(&self) -> [u8; 32] {
        self.previous_envelope_digest
    }

    pub const fn body(&self) -> &PendingQueueEnvelopeBody {
        &self.body
    }

    pub const fn digest(&self) -> PendingQueueEnvelopeDigest {
        self.digest
    }

    pub const fn source_digest(&self) -> PendingQueueSourceIdentityDigest {
        self.artifact_identity.source().digest()
    }

    pub fn payload_bytes(&self) -> usize {
        match &self.body {
            PendingQueueEnvelopeBody::Data(payload) => payload.len(),
            PendingQueueEnvelopeBody::Seal(_) => 0,
        }
    }

    pub fn message_id(&self) -> String {
        format!("psy-beq-{}", hex::encode(self.digest.as_bytes()))
    }

    pub fn exact_subject(
        &self,
        segment: &RecoverableNatsStreamSegment,
    ) -> Result<String, PendingQueueEnvelopeError> {
        if segment.segment_id() != self.segment_id
            || segment.digest() != self.contract_digest
            || segment.base_namespace()
                != source_namespace(self.artifact_identity.source())?
        {
            return Err(PendingQueueEnvelopeError::SegmentMismatch);
        }
        let route = RecoverableNatsSourceRoute::try_new(
            self.artifact_identity.context(),
            self.publisher_kind,
            segment,
        )?;
        if route.source_identity != *self.artifact_identity.source() {
            return Err(PendingQueueEnvelopeError::SourceRouteMismatch);
        }
        Ok(route.subject)
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut out = self
            .encode_unsigned()
            .expect("validated envelope remains canonical");
        out.extend_from_slice(self.digest.as_bytes());
        out
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, PendingQueueEnvelopeError> {
        if bytes.len() > MAX_RECOVERABLE_PENDING_ENVELOPE_BYTES {
            return Err(PendingQueueEnvelopeError::EnvelopeTooLarge);
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(PendingQueueEnvelopeError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != RECOVERABLE_PENDING_ENVELOPE_CODEC_VERSION {
            return Err(PendingQueueEnvelopeError::UnknownCodecVersion(version));
        }
        let kind = decoder.u8()?;
        let publisher_kind = PendingQueuePublisherKind::try_from_u8(decoder.u8()?)?;
        let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueEnvelopeError::InvalidSegment)?;
        let contract_digest = RecoverableNatsSegmentContractDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueEnvelopeError::EmptyDigest)?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueEnvelopeError::EmptyDigest)?;
        let identity_len = decoder.u32()? as usize;
        let artifact_identity = PendingQueueArtifactIdentity::decode_canonical(
            decoder.take(identity_len)?,
        )
        .map_err(|_| PendingQueueEnvelopeError::InvalidArtifactIdentity)?;
        let intent_id = PendingQueuePublishIntentId::try_new(decoder.array32()?)?;
        let member_ordinal = PendingQueueMemberOrdinal::try_new(decoder.u32()?)?;
        let previous_subject_sequence = decoder.u64()?;
        let previous_envelope_digest = decoder.array32()?;
        let body = match kind {
            1 => {
                let payload_len = decoder.u32()? as usize;
                if payload_len == 0 {
                    return Err(PendingQueueEnvelopeError::EmptyData);
                }
                PendingQueueEnvelopeBody::Data(decoder.take(payload_len)?.to_vec())
            }
            2 => PendingQueueEnvelopeBody::Seal(PendingQueueSealSummary::try_new(
                PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueEnvelopeError::InvalidCloseIntent)?,
                decoder.u32()?,
                decoder.u64()?,
                decoder.u64()?,
                decoder.array32()?,
            )?),
            _ => return Err(PendingQueueEnvelopeError::UnknownEnvelopeKind(kind)),
        };
        let encoded_digest = PendingQueueEnvelopeDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(PendingQueueEnvelopeError::TrailingBytes);
        }
        let envelope = Self {
            publisher_kind,
            artifact_identity,
            segment_id,
            contract_digest,
            assignment_digest,
            intent_id,
            member_ordinal,
            previous_subject_sequence,
            previous_envelope_digest,
            body,
            digest: encoded_digest,
        };
        validate_authority(
            envelope.publisher_kind,
            envelope.artifact_identity.context().key().authority(),
        )?;
        validate_predecessor(
            envelope.member_ordinal,
            envelope.previous_subject_sequence,
            envelope.previous_envelope_digest,
        )?;
        if derive_digest(&envelope.encode_unsigned()?)? != encoded_digest {
            return Err(PendingQueueEnvelopeError::DigestMismatch);
        }
        if let PendingQueueEnvelopeBody::Seal(summary) = &envelope.body {
            if envelope.member_ordinal.get().checked_sub(1)
                != Some(summary.data_member_count)
            {
                return Err(PendingQueueEnvelopeError::SealIndexMismatch);
            }
        }
        Ok(envelope)
    }

    fn encode_unsigned(&self) -> Result<Vec<u8>, PendingQueueEnvelopeError> {
        let identity = self.artifact_identity.to_canonical_bytes();
        let identity_len = u32::try_from(identity.len())
            .map_err(|_| PendingQueueEnvelopeError::EnvelopeTooLarge)?;
        let mut out = Vec::with_capacity(identity.len() + self.payload_bytes() + 160);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&RECOVERABLE_PENDING_ENVELOPE_CODEC_VERSION.to_be_bytes());
        out.push(match self.body {
            PendingQueueEnvelopeBody::Data(_) => 1,
            PendingQueueEnvelopeBody::Seal(_) => 2,
        });
        out.push(self.publisher_kind as u8);
        out.extend_from_slice(&self.segment_id.get().to_be_bytes());
        out.extend_from_slice(self.contract_digest.as_bytes());
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(&identity_len.to_be_bytes());
        out.extend_from_slice(&identity);
        out.extend_from_slice(self.intent_id.as_bytes());
        out.extend_from_slice(&self.member_ordinal.get().to_be_bytes());
        out.extend_from_slice(&self.previous_subject_sequence.to_be_bytes());
        out.extend_from_slice(&self.previous_envelope_digest);
        match &self.body {
            PendingQueueEnvelopeBody::Data(payload) => {
                let len = u32::try_from(payload.len())
                    .map_err(|_| PendingQueueEnvelopeError::EnvelopeTooLarge)?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(payload);
            }
            PendingQueueEnvelopeBody::Seal(summary) => {
                out.extend_from_slice(summary.close_intent.as_bytes());
                out.extend_from_slice(&summary.data_member_count.to_be_bytes());
                out.extend_from_slice(&summary.data_payload_bytes.to_be_bytes());
                out.extend_from_slice(&summary.data_encoded_bytes.to_be_bytes());
                out.extend_from_slice(&summary.data_rolling_digest);
            }
        }
        Ok(out)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishSourceRevision(u64);

impl PendingQueuePublishSourceRevision {
    pub const fn try_new(value: u64) -> Result<Self, PendingQueueEnvelopeError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(PendingQueueEnvelopeError::RevisionOutOfRange)
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

    fn next(self) -> Result<Self, PendingQueueEnvelopeError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(PendingQueueEnvelopeError::RevisionOverflow)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueuePublishSourceSlot([u8; 32]);

impl PendingQueuePublishSourceSlot {
    pub fn for_identity(
        identity: &PendingQueueArtifactIdentity,
        publisher_kind: PendingQueuePublisherKind,
        assignment_digest: PendingQueueSegmentAssignmentDigest,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        validate_authority(publisher_kind, identity.context().key().authority())?;
        let identity = identity.to_canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(SOURCE_SLOT_DOMAIN);
        hasher.update((identity.len() as u64).to_be_bytes());
        hasher.update(identity);
        hasher.update([publisher_kind as u8]);
        hasher.update(assignment_digest.as_bytes());
        let bytes: [u8; 32] = hasher.finalize().into();
        if bytes == [0; 32] {
            return Err(PendingQueueEnvelopeError::EmptyDigest);
        }
        Ok(Self(bytes))
    }

    pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueEnvelopeError> {
        if bytes == [0; 32] {
            Err(PendingQueueEnvelopeError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSelectedEnvelope {
    intent_id: PendingQueuePublishIntentId,
    envelope_digest: PendingQueueEnvelopeDigest,
    member_ordinal: PendingQueueMemberOrdinal,
    previous_subject_sequence: u64,
    previous_envelope_digest: [u8; 32],
    encoded_bytes: u64,
    payload_bytes: u64,
    body: PendingQueueSelectedBody,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingQueueSelectedBody {
    Data,
    Seal(PendingQueueSealSummary),
}

impl PendingQueueSelectedEnvelope {
    pub const fn intent_id(&self) -> PendingQueuePublishIntentId {
        self.intent_id
    }

    pub const fn envelope_digest(&self) -> PendingQueueEnvelopeDigest {
        self.envelope_digest
    }

    pub const fn member_ordinal(&self) -> PendingQueueMemberOrdinal {
        self.member_ordinal
    }

    pub const fn encoded_bytes(&self) -> u64 {
        self.encoded_bytes
    }

    pub const fn previous_subject_sequence(&self) -> u64 {
        self.previous_subject_sequence
    }

    pub const fn previous_envelope_digest(&self) -> [u8; 32] {
        self.previous_envelope_digest
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub const fn body(&self) -> PendingQueueSelectedBody {
        self.body
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueuePublishSourcePhase {
    Open,
    Publishing(PendingQueueSelectedEnvelope),
    CommitPending {
        selected: PendingQueueSelectedEnvelope,
        subject_sequence: u64,
    },
    Sealed {
        close_intent: PendingQueueCloseIntentDigest,
        seal_digest: PendingQueueEnvelopeDigest,
        seal_subject_sequence: u64,
    },
}

/// Per-source cursor and logical byte authority.  Exact source quotas make
/// the aggregate bound compositional: independent source rows cannot exceed
/// the once-per-generation reservation even though Scylla has no cross-row
/// transaction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueuePublishSourceState {
    revision: PendingQueuePublishSourceRevision,
    artifact_identity: PendingQueueArtifactIdentity,
    publisher_kind: PendingQueuePublisherKind,
    segment_id: RecoverableNatsSegmentId,
    contract_digest: RecoverableNatsSegmentContractDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    budget_digest: PendingQueueGenerationBudgetDigest,
    quota: PendingQueueSourceQuota,
    phase: PendingQueuePublishSourcePhase,
    data_member_count: u32,
    data_payload_bytes: u64,
    data_encoded_bytes: u64,
    total_encoded_bytes: u64,
    data_rolling_digest: [u8; 32],
    last_subject_sequence: u64,
    last_envelope_digest: [u8; 32],
}

impl PendingQueuePublishSourceState {
    pub fn bootstrap(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
    ) -> Result<Self, PendingQueueEnvelopeError> {
        if route.context != assignment.context() {
            return Err(PendingQueueEnvelopeError::AssignmentContextMismatch);
        }
        let quota = assignment
            .source_quotas()
            .iter()
            .copied()
            .find(|quota| quota.publisher_kind == route.publisher_kind)
            .ok_or(PendingQueueEnvelopeError::SourceQuotaMissing)?;
        if usize::from(assignment.expected_source_count())
            != assignment.source_quotas().len()
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceManifest);
        }
        Ok(Self {
            revision: PendingQueuePublishSourceRevision::try_new(1)?,
            artifact_identity: route.artifact_identity()?,
            publisher_kind: route.publisher_kind,
            segment_id: assignment.segment_id(),
            contract_digest: assignment.contract_digest(),
            assignment_digest: assignment.digest(),
            budget_digest: assignment.budget_digest(),
            quota,
            phase: PendingQueuePublishSourcePhase::Open,
            data_member_count: 0,
            data_payload_bytes: 0,
            data_encoded_bytes: 0,
            total_encoded_bytes: 0,
            data_rolling_digest: [0; 32],
            last_subject_sequence: 0,
            last_envelope_digest: [0; 32],
        })
    }

    pub const fn revision(&self) -> PendingQueuePublishSourceRevision {
        self.revision
    }

    pub fn slot(&self) -> Result<PendingQueuePublishSourceSlot, PendingQueueEnvelopeError> {
        PendingQueuePublishSourceSlot::for_identity(
            &self.artifact_identity,
            self.publisher_kind,
            self.assignment_digest,
        )
    }

    pub const fn artifact_identity(&self) -> &PendingQueueArtifactIdentity {
        &self.artifact_identity
    }

    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn segment_id(&self) -> RecoverableNatsSegmentId {
        self.segment_id
    }

    pub const fn contract_digest(&self) -> RecoverableNatsSegmentContractDigest {
        self.contract_digest
    }

    pub const fn assignment_digest(&self) -> PendingQueueSegmentAssignmentDigest {
        self.assignment_digest
    }

    pub const fn budget_digest(&self) -> PendingQueueGenerationBudgetDigest {
        self.budget_digest
    }

    pub const fn phase(&self) -> &PendingQueuePublishSourcePhase {
        &self.phase
    }

    pub const fn quota(&self) -> PendingQueueSourceQuota {
        self.quota
    }

    pub const fn data_member_count(&self) -> u32 {
        self.data_member_count
    }

    pub const fn data_payload_bytes(&self) -> u64 {
        self.data_payload_bytes
    }

    pub const fn data_encoded_bytes(&self) -> u64 {
        self.data_encoded_bytes
    }

    pub const fn total_encoded_bytes(&self) -> u64 {
        self.total_encoded_bytes
    }

    pub const fn data_rolling_digest(&self) -> [u8; 32] {
        self.data_rolling_digest
    }

    pub const fn last_subject_sequence(&self) -> u64 {
        self.last_subject_sequence
    }

    pub const fn last_envelope_digest(&self) -> [u8; 32] {
        self.last_envelope_digest
    }

    pub fn selected_envelope(&self) -> Option<&PendingQueueSelectedEnvelope> {
        match &self.phase {
            PendingQueuePublishSourcePhase::Publishing(selected) => Some(selected),
            _ => None,
        }
    }

    pub fn commit_pending(&self) -> Option<(&PendingQueueSelectedEnvelope, u64)> {
        match &self.phase {
            PendingQueuePublishSourcePhase::CommitPending {
                selected,
                subject_sequence,
            } => Some((selected, *subject_sequence)),
            _ => None,
        }
    }

    pub fn selected_matches(&self, envelope: &PendingQueuePublishEnvelope) -> bool {
        self.selected_envelope().is_some_and(|selected| {
            selected.intent_id == envelope.intent_id
                && selected.envelope_digest == envelope.digest
                && selected.member_ordinal == envelope.member_ordinal
                && selected.previous_subject_sequence
                    == envelope.previous_subject_sequence
                && selected.previous_envelope_digest
                    == envelope.previous_envelope_digest
                && selected.encoded_bytes
                    == u64::try_from(envelope.to_canonical_bytes().len()).unwrap_or(u64::MAX)
                && selected.payload_bytes
                    == u64::try_from(envelope.payload_bytes()).unwrap_or(u64::MAX)
                && selected.body
                    == match envelope.body {
                        PendingQueueEnvelopeBody::Data(_) => PendingQueueSelectedBody::Data,
                        PendingQueueEnvelopeBody::Seal(summary) => {
                            PendingQueueSelectedBody::Seal(summary)
                        }
                    }
        })
    }

    pub fn inflight_matches(&self, envelope: &PendingQueuePublishEnvelope) -> bool {
        let selected = match &self.phase {
            PendingQueuePublishSourcePhase::Publishing(selected)
            | PendingQueuePublishSourcePhase::CommitPending { selected, .. } => selected,
            _ => return false,
        };
        selected.intent_id == envelope.intent_id
            && selected.envelope_digest == envelope.digest
            && selected.member_ordinal == envelope.member_ordinal
            && selected.previous_subject_sequence == envelope.previous_subject_sequence
            && selected.previous_envelope_digest == envelope.previous_envelope_digest
            && selected.encoded_bytes
                == u64::try_from(envelope.to_canonical_bytes().len()).unwrap_or(u64::MAX)
            && selected.payload_bytes
                == u64::try_from(envelope.payload_bytes()).unwrap_or(u64::MAX)
            && selected.body
                == match envelope.body {
                    PendingQueueEnvelopeBody::Data(_) => PendingQueueSelectedBody::Data,
                    PendingQueueEnvelopeBody::Seal(summary) => {
                        PendingQueueSelectedBody::Seal(summary)
                    }
                }
    }

    pub fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = self
            .encode_persisted_unsigned()
            .expect("validated source state remains canonical");
        out.extend_from_slice(&source_state_digest(&out));
        out
    }

    pub fn decode_persisted(
        revision: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueEnvelopeError> {
        let revision = u64::try_from(revision)
            .map_err(|_| PendingQueueEnvelopeError::RevisionOutOfRange)
            .and_then(PendingQueuePublishSourceRevision::try_new)?;
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != SOURCE_STATE_MAGIC {
            return Err(PendingQueueEnvelopeError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != RECOVERABLE_PENDING_SOURCE_STATE_CODEC_VERSION {
            return Err(PendingQueueEnvelopeError::UnknownCodecVersion(version));
        }
        let identity_len = decoder.u32()? as usize;
        let artifact_identity = PendingQueueArtifactIdentity::decode_canonical(
            decoder.take(identity_len)?,
        )
        .map_err(|_| PendingQueueEnvelopeError::InvalidArtifactIdentity)?;
        let publisher_kind = PendingQueuePublisherKind::try_from_u8(decoder.u8()?)?;
        let segment_id = RecoverableNatsSegmentId::try_new(decoder.u64()?)
            .map_err(|_| PendingQueueEnvelopeError::InvalidSegment)?;
        let contract_digest = RecoverableNatsSegmentContractDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueEnvelopeError::EmptyDigest)?;
        let assignment_digest = PendingQueueSegmentAssignmentDigest::try_new(
            decoder.array32()?,
        )
        .map_err(|_| PendingQueueEnvelopeError::EmptyDigest)?;
        let budget_digest = PendingQueueGenerationBudgetDigest::try_new(
            decoder.array32()?,
        )?;
        let quota = PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::try_from_u8(decoder.u8()?)?,
            decoder.u32()?,
            decoder.u64()?,
            decoder.u64()?,
        )?;
        let phase = match decoder.u8()? {
            0 => PendingQueuePublishSourcePhase::Open,
            1 => {
                let intent_id = PendingQueuePublishIntentId::try_new(decoder.array32()?)?;
                let envelope_digest = PendingQueueEnvelopeDigest::try_new(decoder.array32()?)?;
                let member_ordinal = PendingQueueMemberOrdinal::try_new(decoder.u32()?)?;
                let previous_subject_sequence = decoder.u64()?;
                let previous_envelope_digest = decoder.array32()?;
                let encoded_bytes = decoder.u64()?;
                let payload_bytes = decoder.u64()?;
                let body = match decoder.u8()? {
                    1 => PendingQueueSelectedBody::Data,
                    2 => PendingQueueSelectedBody::Seal(PendingQueueSealSummary::try_new(
                        PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
                            .map_err(|_| PendingQueueEnvelopeError::InvalidCloseIntent)?,
                        decoder.u32()?,
                        decoder.u64()?,
                        decoder.u64()?,
                        decoder.array32()?,
                    )?),
                    value => return Err(PendingQueueEnvelopeError::UnknownEnvelopeKind(value)),
                };
                PendingQueuePublishSourcePhase::Publishing(PendingQueueSelectedEnvelope {
                    intent_id,
                    envelope_digest,
                    member_ordinal,
                    previous_subject_sequence,
                    previous_envelope_digest,
                    encoded_bytes,
                    payload_bytes,
                    body,
                })
            }
            2 => {
                let selected = decode_selected(&mut decoder)?;
                let subject_sequence = decoder.u64()?;
                PendingQueuePublishSourcePhase::CommitPending {
                    selected,
                    subject_sequence,
                }
            }
            3 => PendingQueuePublishSourcePhase::Sealed {
                close_intent: PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
                    .map_err(|_| PendingQueueEnvelopeError::InvalidCloseIntent)?,
                seal_digest: PendingQueueEnvelopeDigest::try_new(decoder.array32()?)?,
                seal_subject_sequence: decoder.u64()?,
            },
            value => return Err(PendingQueueEnvelopeError::UnknownSourcePhase(value)),
        };
        let data_member_count = decoder.u32()?;
        let data_payload_bytes = decoder.u64()?;
        let data_encoded_bytes = decoder.u64()?;
        let total_encoded_bytes = decoder.u64()?;
        let data_rolling_digest = decoder.array32()?;
        let last_subject_sequence = decoder.u64()?;
        let last_envelope_digest = decoder.array32()?;
        let encoded_digest = decoder.array32()?;
        if !decoder.done() {
            return Err(PendingQueueEnvelopeError::TrailingBytes);
        }
        if source_state_digest(&bytes[..bytes.len() - 32]) != encoded_digest {
            return Err(PendingQueueEnvelopeError::DigestMismatch);
        }
        let state = Self {
            revision,
            artifact_identity,
            publisher_kind,
            segment_id,
            contract_digest,
            assignment_digest,
            budget_digest,
            quota,
            phase,
            data_member_count,
            data_payload_bytes,
            data_encoded_bytes,
            total_encoded_bytes,
            data_rolling_digest,
            last_subject_sequence,
            last_envelope_digest,
        };
        state.validate_persisted_invariants()?;
        Ok(state)
    }

    pub fn seal_summary(
        &self,
        close_intent: PendingQueueCloseIntentDigest,
    ) -> Result<PendingQueueSealSummary, PendingQueueEnvelopeError> {
        PendingQueueSealSummary::try_new(
            close_intent,
            self.data_member_count,
            self.data_payload_bytes,
            self.data_encoded_bytes,
            self.data_rolling_digest,
        )
    }

    pub fn select(
        &self,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<PendingQueueSourceSelectionPlan, PendingQueueEnvelopeError> {
        if let PendingQueuePublishSourcePhase::Publishing(selected) = &self.phase {
            if selected.intent_id == envelope.intent_id
                && selected.envelope_digest == envelope.digest
            {
                return Ok(PendingQueueSourceSelectionPlan::Idempotent(
                    self.clone(),
                ));
            }
            return Err(PendingQueueEnvelopeError::PublishAlreadyInProgress);
        }
        if matches!(self.phase, PendingQueuePublishSourcePhase::Sealed { .. }) {
            return Err(PendingQueueEnvelopeError::SourceAlreadySealed);
        }
        if matches!(self.phase, PendingQueuePublishSourcePhase::CommitPending { .. }) {
            return Err(PendingQueueEnvelopeError::CommitAlreadyPending);
        }
        self.verify_envelope_identity(envelope)?;
        if envelope.member_ordinal.get()
            != self
                .data_member_count
                .checked_add(1)
                .ok_or(PendingQueueEnvelopeError::MemberLimitExceeded)?
            || envelope.previous_subject_sequence != self.last_subject_sequence
            || envelope.previous_envelope_digest != self.last_envelope_digest
        {
            return Err(PendingQueueEnvelopeError::SourceCursorMismatch);
        }
        let encoded_bytes = u64::try_from(envelope.to_canonical_bytes().len())
            .map_err(|_| PendingQueueEnvelopeError::EnvelopeTooLarge)?;
        let payload_bytes = u64::try_from(envelope.payload_bytes())
            .map_err(|_| PendingQueueEnvelopeError::EnvelopeTooLarge)?;
        match &envelope.body {
            PendingQueueEnvelopeBody::Data(_) => {
                if self.data_member_count >= self.quota.max_data_members
                    || self
                        .data_encoded_bytes
                        .checked_add(encoded_bytes)
                        .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?
                        > self.quota.max_data_stored_bytes
                {
                    return Err(PendingQueueEnvelopeError::SourceQuotaExceeded);
                }
            }
            PendingQueueEnvelopeBody::Seal(summary) => {
                if *summary != self.seal_summary(summary.close_intent())?
                    || encoded_bytes > self.quota.max_seal_stored_bytes
                {
                    return Err(PendingQueueEnvelopeError::InvalidSealSummary);
                }
            }
        }
        let total = self
            .total_encoded_bytes
            .checked_add(encoded_bytes)
            .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?;
        if total > self.quota.max_source_stored_bytes() {
            return Err(PendingQueueEnvelopeError::SourceQuotaExceeded);
        }
        let selected = PendingQueueSelectedEnvelope {
            intent_id: envelope.intent_id,
            envelope_digest: envelope.digest,
            member_ordinal: envelope.member_ordinal,
            previous_subject_sequence: envelope.previous_subject_sequence,
            previous_envelope_digest: envelope.previous_envelope_digest,
            encoded_bytes,
            payload_bytes,
            body: match &envelope.body {
                PendingQueueEnvelopeBody::Data(_) => PendingQueueSelectedBody::Data,
                PendingQueueEnvelopeBody::Seal(summary) => {
                    PendingQueueSelectedBody::Seal(*summary)
                }
            },
        };
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.phase = PendingQueuePublishSourcePhase::Publishing(selected);
        Ok(PendingQueueSourceSelectionPlan::Advance {
            expected: self.clone(),
            candidate,
        })
    }

    pub fn record_published(
        &self,
        subject_sequence: u64,
    ) -> Result<PendingQueueSourceApplyPlan, PendingQueueEnvelopeError> {
        let PendingQueuePublishSourcePhase::Publishing(selected) = &self.phase else {
            return Err(PendingQueueEnvelopeError::NoPublishInProgress);
        };
        if subject_sequence == 0 || subject_sequence <= self.last_subject_sequence {
            return Err(PendingQueueEnvelopeError::SubjectSequenceRegressed);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.phase = PendingQueuePublishSourcePhase::CommitPending {
            selected: selected.clone(),
            subject_sequence,
        };
        Ok(PendingQueueSourceApplyPlan {
            expected: self.clone(),
            candidate,
        })
    }

    pub fn finalize_published(
        &self,
    ) -> Result<PendingQueueSourceApplyPlan, PendingQueueEnvelopeError> {
        let PendingQueuePublishSourcePhase::CommitPending {
            selected,
            subject_sequence,
        } = &self.phase
        else {
            return Err(PendingQueueEnvelopeError::NoCommitPending);
        };
        if *subject_sequence == 0 || *subject_sequence <= self.last_subject_sequence {
            return Err(PendingQueueEnvelopeError::SubjectSequenceRegressed);
        }
        let mut candidate = self.clone();
        candidate.revision = self.revision.next()?;
        candidate.total_encoded_bytes = self
            .total_encoded_bytes
            .checked_add(selected.encoded_bytes)
            .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?;
        candidate.last_subject_sequence = *subject_sequence;
        candidate.last_envelope_digest = *selected.envelope_digest.as_bytes();
        match selected.body {
            PendingQueueSelectedBody::Data => {
                candidate.data_member_count = self
                    .data_member_count
                    .checked_add(1)
                    .ok_or(PendingQueueEnvelopeError::MemberLimitExceeded)?;
                candidate.data_payload_bytes = self
                    .data_payload_bytes
                    .checked_add(selected.payload_bytes)
                    .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?;
                candidate.data_encoded_bytes = self
                    .data_encoded_bytes
                    .checked_add(selected.encoded_bytes)
                    .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?;
                candidate.data_rolling_digest = next_rolling_digest(
                    self.data_rolling_digest,
                    selected.envelope_digest,
                    selected.member_ordinal,
                    selected.payload_bytes,
                    selected.encoded_bytes,
                );
                candidate.phase = PendingQueuePublishSourcePhase::Open;
            }
            PendingQueueSelectedBody::Seal(summary) => {
                candidate.phase = PendingQueuePublishSourcePhase::Sealed {
                    close_intent: summary.close_intent(),
                    seal_digest: selected.envelope_digest,
                    seal_subject_sequence: *subject_sequence,
                };
            }
        }
        Ok(PendingQueueSourceApplyPlan {
            expected: self.clone(),
            candidate,
        })
    }

    fn encode_persisted_unsigned(&self) -> Result<Vec<u8>, PendingQueueEnvelopeError> {
        self.validate_persisted_invariants()?;
        let identity = self.artifact_identity.to_canonical_bytes();
        let identity_len = u32::try_from(identity.len())
            .map_err(|_| PendingQueueEnvelopeError::EnvelopeTooLarge)?;
        let mut out = Vec::with_capacity(identity.len() + 384);
        out.extend_from_slice(SOURCE_STATE_MAGIC);
        out.extend_from_slice(&RECOVERABLE_PENDING_SOURCE_STATE_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&identity_len.to_be_bytes());
        out.extend_from_slice(&identity);
        out.push(self.publisher_kind as u8);
        out.extend_from_slice(&self.segment_id.get().to_be_bytes());
        out.extend_from_slice(self.contract_digest.as_bytes());
        out.extend_from_slice(self.assignment_digest.as_bytes());
        out.extend_from_slice(self.budget_digest.as_bytes());
        encode_quota(self.quota, &mut out);
        match &self.phase {
            PendingQueuePublishSourcePhase::Open => out.push(0),
            PendingQueuePublishSourcePhase::Publishing(selected) => {
                out.push(1);
                encode_selected(selected, &mut out);
            }
            PendingQueuePublishSourcePhase::CommitPending {
                selected,
                subject_sequence,
            } => {
                out.push(2);
                encode_selected(selected, &mut out);
                out.extend_from_slice(&subject_sequence.to_be_bytes());
            }
            PendingQueuePublishSourcePhase::Sealed {
                close_intent,
                seal_digest,
                seal_subject_sequence,
            } => {
                out.push(3);
                out.extend_from_slice(close_intent.as_bytes());
                out.extend_from_slice(seal_digest.as_bytes());
                out.extend_from_slice(&seal_subject_sequence.to_be_bytes());
            }
        }
        out.extend_from_slice(&self.data_member_count.to_be_bytes());
        out.extend_from_slice(&self.data_payload_bytes.to_be_bytes());
        out.extend_from_slice(&self.data_encoded_bytes.to_be_bytes());
        out.extend_from_slice(&self.total_encoded_bytes.to_be_bytes());
        out.extend_from_slice(&self.data_rolling_digest);
        out.extend_from_slice(&self.last_subject_sequence.to_be_bytes());
        out.extend_from_slice(&self.last_envelope_digest);
        Ok(out)
    }

    fn validate_persisted_invariants(&self) -> Result<(), PendingQueueEnvelopeError> {
        validate_authority(
            self.publisher_kind,
            self.artifact_identity.context().key().authority(),
        )?;
        source_namespace(self.artifact_identity.source())?;
        if self.quota.publisher_kind != self.publisher_kind
            || self.data_member_count > self.quota.max_data_members
            || self.data_encoded_bytes > self.quota.max_data_stored_bytes
            || self.total_encoded_bytes > self.quota.max_source_stored_bytes()
            || self.total_encoded_bytes < self.data_encoded_bytes
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceState);
        }
        if self.data_member_count == 0 {
            if self.data_payload_bytes != 0
                || self.data_encoded_bytes != 0
                || self.data_rolling_digest != [0; 32]
            {
                return Err(PendingQueueEnvelopeError::InvalidSourceState);
            }
            // An empty source still has one physical member once it is sealed.
            // The final cursor therefore belongs to Seal rather than Data.
            if matches!(&self.phase, PendingQueuePublishSourcePhase::Open)
                && (self.last_subject_sequence != 0
                    || self.last_envelope_digest != [0; 32])
            {
                return Err(PendingQueueEnvelopeError::InvalidSourceState);
            }
        } else if self.data_payload_bytes == 0
            || self.data_encoded_bytes == 0
            || self.data_rolling_digest == [0; 32]
            || self.last_subject_sequence == 0
            || self.last_envelope_digest == [0; 32]
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceState);
        }
        match &self.phase {
            PendingQueuePublishSourcePhase::Open => {
                if self.total_encoded_bytes != self.data_encoded_bytes {
                    return Err(PendingQueueEnvelopeError::InvalidSourceState);
                }
            }
            PendingQueuePublishSourcePhase::Publishing(selected) => {
                self.validate_selected(selected, None)?;
            }
            PendingQueuePublishSourcePhase::CommitPending {
                selected,
                subject_sequence,
            } => {
                self.validate_selected(selected, Some(*subject_sequence))?;
            }
            PendingQueuePublishSourcePhase::Sealed {
                close_intent: _,
                seal_digest,
                seal_subject_sequence,
            } => {
                if *seal_subject_sequence == 0
                    || *seal_subject_sequence != self.last_subject_sequence
                    || seal_digest.as_bytes() != &self.last_envelope_digest
                    || self.total_encoded_bytes == self.data_encoded_bytes
                    || self.total_encoded_bytes - self.data_encoded_bytes
                        > self.quota.max_seal_stored_bytes
                {
                    return Err(PendingQueueEnvelopeError::InvalidSourceState);
                }
            }
        }
        Ok(())
    }

    fn validate_selected(
        &self,
        selected: &PendingQueueSelectedEnvelope,
        accepted_sequence: Option<u64>,
    ) -> Result<(), PendingQueueEnvelopeError> {
        if selected.member_ordinal.get()
            != self
                .data_member_count
                .checked_add(1)
                .ok_or(PendingQueueEnvelopeError::MemberLimitExceeded)?
            || selected.previous_subject_sequence != self.last_subject_sequence
            || selected.previous_envelope_digest != self.last_envelope_digest
            || selected.encoded_bytes == 0
            || accepted_sequence.is_some_and(|sequence| {
                sequence == 0 || sequence <= self.last_subject_sequence
            })
            || self.total_encoded_bytes != self.data_encoded_bytes
        {
            return Err(PendingQueueEnvelopeError::InvalidSourceState);
        }
        match selected.body {
            PendingQueueSelectedBody::Data => {
                if selected.payload_bytes == 0
                    || self.data_member_count >= self.quota.max_data_members
                    || self
                        .data_encoded_bytes
                        .checked_add(selected.encoded_bytes)
                        .ok_or(PendingQueueEnvelopeError::BudgetOverflow)?
                        > self.quota.max_data_stored_bytes
                {
                    return Err(PendingQueueEnvelopeError::InvalidSourceState);
                }
            }
            PendingQueueSelectedBody::Seal(summary) => {
                if selected.payload_bytes != 0
                    || summary != self.seal_summary(summary.close_intent())?
                    || selected.encoded_bytes > self.quota.max_seal_stored_bytes
                {
                    return Err(PendingQueueEnvelopeError::InvalidSourceState);
                }
            }
        }
        Ok(())
    }

    fn verify_envelope_identity(
        &self,
        envelope: &PendingQueuePublishEnvelope,
    ) -> Result<(), PendingQueueEnvelopeError> {
        if envelope.artifact_identity != self.artifact_identity
            || envelope.publisher_kind != self.publisher_kind
            || envelope.segment_id != self.segment_id
            || envelope.contract_digest != self.contract_digest
            || envelope.assignment_digest != self.assignment_digest
        {
            return Err(PendingQueueEnvelopeError::SourceIdentityMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueSourceSelectionPlan {
    Idempotent(PendingQueuePublishSourceState),
    Advance {
        expected: PendingQueuePublishSourceState,
        candidate: PendingQueuePublishSourceState,
    },
}

impl PendingQueueSourceSelectionPlan {
    pub const fn current(&self) -> &PendingQueuePublishSourceState {
        match self {
            Self::Idempotent(current) => current,
            Self::Advance { candidate, .. } => candidate,
        }
    }

    pub const fn transition(
        &self,
    ) -> Option<(
        &PendingQueuePublishSourceState,
        &PendingQueuePublishSourceState,
    )> {
        match self {
            Self::Idempotent(_) => None,
            Self::Advance {
                expected,
                candidate,
            } => Some((expected, candidate)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueSourceApplyPlan {
    expected: PendingQueuePublishSourceState,
    candidate: PendingQueuePublishSourceState,
}

impl PendingQueueSourceApplyPlan {
    pub const fn expected(&self) -> &PendingQueuePublishSourceState {
        &self.expected
    }

    pub const fn candidate(&self) -> &PendingQueuePublishSourceState {
        &self.candidate
    }
}

fn encode_quota(quota: PendingQueueSourceQuota, out: &mut Vec<u8>) {
    out.push(quota.publisher_kind as u8);
    out.extend_from_slice(&quota.max_data_members.to_be_bytes());
    out.extend_from_slice(&quota.max_data_stored_bytes.to_be_bytes());
    out.extend_from_slice(&quota.max_seal_stored_bytes.to_be_bytes());
}

fn encode_selected(selected: &PendingQueueSelectedEnvelope, out: &mut Vec<u8>) {
    out.extend_from_slice(selected.intent_id.as_bytes());
    out.extend_from_slice(selected.envelope_digest.as_bytes());
    out.extend_from_slice(&selected.member_ordinal.get().to_be_bytes());
    out.extend_from_slice(&selected.previous_subject_sequence.to_be_bytes());
    out.extend_from_slice(&selected.previous_envelope_digest);
    out.extend_from_slice(&selected.encoded_bytes.to_be_bytes());
    out.extend_from_slice(&selected.payload_bytes.to_be_bytes());
    match selected.body {
        PendingQueueSelectedBody::Data => out.push(1),
        PendingQueueSelectedBody::Seal(summary) => {
            out.push(2);
            out.extend_from_slice(summary.close_intent.as_bytes());
            out.extend_from_slice(&summary.data_member_count.to_be_bytes());
            out.extend_from_slice(&summary.data_payload_bytes.to_be_bytes());
            out.extend_from_slice(&summary.data_encoded_bytes.to_be_bytes());
            out.extend_from_slice(&summary.data_rolling_digest);
        }
    }
}

fn decode_selected(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueSelectedEnvelope, PendingQueueEnvelopeError> {
    let intent_id = PendingQueuePublishIntentId::try_new(decoder.array32()?)?;
    let envelope_digest = PendingQueueEnvelopeDigest::try_new(decoder.array32()?)?;
    let member_ordinal = PendingQueueMemberOrdinal::try_new(decoder.u32()?)?;
    let previous_subject_sequence = decoder.u64()?;
    let previous_envelope_digest = decoder.array32()?;
    let encoded_bytes = decoder.u64()?;
    let payload_bytes = decoder.u64()?;
    let body = match decoder.u8()? {
        1 => PendingQueueSelectedBody::Data,
        2 => PendingQueueSelectedBody::Seal(PendingQueueSealSummary::try_new(
            PendingQueueCloseIntentDigest::try_new(decoder.array32()?)
                .map_err(|_| PendingQueueEnvelopeError::InvalidCloseIntent)?,
            decoder.u32()?,
            decoder.u64()?,
            decoder.u64()?,
            decoder.array32()?,
        )?),
        value => return Err(PendingQueueEnvelopeError::UnknownEnvelopeKind(value)),
    };
    Ok(PendingQueueSelectedEnvelope {
        intent_id,
        envelope_digest,
        member_ordinal,
        previous_subject_sequence,
        previous_envelope_digest,
        encoded_bytes,
        payload_bytes,
        body,
    })
}

fn source_state_digest(unsigned: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_STATE_DIGEST_DOMAIN);
    hasher.update((unsigned.len() as u64).to_be_bytes());
    hasher.update(unsigned);
    hasher.finalize().into()
}

fn next_rolling_digest(
    previous: [u8; 32],
    envelope: PendingQueueEnvelopeDigest,
    ordinal: PendingQueueMemberOrdinal,
    payload_bytes: u64,
    encoded_bytes: u64,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROLLING_DOMAIN);
    hasher.update(previous);
    hasher.update(envelope.as_bytes());
    hasher.update(ordinal.get().to_be_bytes());
    hasher.update(payload_bytes.to_be_bytes());
    hasher.update(encoded_bytes.to_be_bytes());
    hasher.finalize().into()
}

fn validate_authority(
    kind: PendingQueuePublisherKind,
    authority: AuthorityScope,
) -> Result<(), PendingQueueEnvelopeError> {
    let actual = match authority {
        AuthorityScope::Coordinator => 1,
        AuthorityScope::Realm { .. } => 2,
    };
    if actual != kind.expected_authority_kind() {
        Err(PendingQueueEnvelopeError::PublisherAuthorityMismatch)
    } else {
        Ok(())
    }
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => {
            out.push(1);
            out.extend_from_slice(&0_u32.to_be_bytes());
            out.extend_from_slice(&0_u16.to_be_bytes());
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn decode_authority(
    decoder: &mut Decoder<'_>,
) -> Result<AuthorityScope, PendingQueueEnvelopeError> {
    match (decoder.u8()?, decoder.u32()?, decoder.u16()?) {
        (1, 0, 0) => Ok(AuthorityScope::Coordinator),
        (2, realm_id, realm_sub_id) => Ok(AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        }),
        _ => Err(PendingQueueEnvelopeError::InvalidAuthority),
    }
}

fn validate_predecessor(
    ordinal: PendingQueueMemberOrdinal,
    previous_subject_sequence: u64,
    previous_envelope_digest: [u8; 32],
) -> Result<(), PendingQueueEnvelopeError> {
    let initial = ordinal.get() == 1;
    if initial != (previous_subject_sequence == 0)
        || initial != (previous_envelope_digest == [0; 32])
    {
        Err(PendingQueueEnvelopeError::InvalidPredecessor)
    } else {
        Ok(())
    }
}

fn source_namespace(source: &PendingQueueSourceIdentity) -> Result<&str, PendingQueueEnvelopeError> {
    match source.address() {
        PendingQueueSourceAddress::NatsJetStream { namespace, .. } => Ok(namespace),
        _ => Err(PendingQueueEnvelopeError::NonNatsSource),
    }
}

fn derive_digest(
    unsigned: &[u8],
) -> Result<PendingQueueEnvelopeDigest, PendingQueueEnvelopeError> {
    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN);
    hasher.update((unsigned.len() as u64).to_be_bytes());
    hasher.update(unsigned);
    PendingQueueEnvelopeDigest::try_new(hasher.finalize().into())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueEnvelopeError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PendingQueueEnvelopeError::Malformed)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(PendingQueueEnvelopeError::Malformed)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueEnvelopeError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PendingQueueEnvelopeError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, PendingQueueEnvelopeError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueEnvelopeError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueEnvelopeError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueEnvelopeError {
    EmptyData,
    DataTooLarge,
    EmptyDigest,
    EmptyIntentId,
    ZeroMemberOrdinal,
    InvalidPredecessor,
    EnvelopeTooLarge,
    AssignmentContextMismatch,
    PublisherAuthorityMismatch,
    SegmentMismatch,
    InvalidSubject,
    NonNatsSource,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownEnvelopeKind(u8),
    UnknownSourcePhase(u8),
    UnknownPublisherKind(u8),
    InvalidSegment,
    InvalidArtifactIdentity,
    SourceRouteMismatch,
    InvalidSourceQuota,
    InvalidSourceManifest,
    GenerationBudgetMismatch,
    BudgetOverflow,
    BudgetDigestMismatch,
    InvalidAuthority,
    RevisionOutOfRange,
    RevisionOverflow,
    SourceQuotaMissing,
    SourceQuotaExceeded,
    MemberLimitExceeded,
    PublishAlreadyInProgress,
    SourceAlreadySealed,
    CommitAlreadyPending,
    SourceCursorMismatch,
    NoPublishInProgress,
    NoCommitPending,
    SubjectSequenceRegressed,
    SourceIdentityMismatch,
    InvalidEmptySeal,
    InvalidCloseIntent,
    InvalidSealSummary,
    InvalidSourceState,
    SealIndexMismatch,
    DigestMismatch,
    TrailingBytes,
    Malformed,
}

impl fmt::Display for PendingQueueEnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueEnvelopeError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::{canonical_chain::NetworkId, chain_context::AuthorityScope};
    use psy_node_core::{
        queue::recoverable_ephemeral::PendingQueueCaptureContext,
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };

    use crate::{
        recoverable_assignment::PendingQueueSegmentLedgerBootstrap,
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    use super::*;

    fn fixture(
        authority: AuthorityScope,
    ) -> (
        RecoverableNatsStreamSegment,
        PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
    ) {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let key = PendingGenerationLedgerKey::new(network, authority);
        let context = PendingQueueCaptureContext::try_new(
            key,
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
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
            "psy.mainnet",
            RecoverableNatsSegmentId::try_new(1).unwrap(),
            retention,
        )
        .unwrap();
        let validated = segment
            .validate_stream_config_structure(&segment.stream_config())
            .unwrap();
        let mib = 1024 * 1024_u64;
        let quotas = match authority {
            AuthorityScope::Coordinator => vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorRegistration,
                    10_000,
                    15 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorDeploy,
                    10_000,
                    47 * mib,
                    mib,
                )
                .unwrap(),
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::CoordinatorGuta,
                    10_000,
                    63 * mib,
                    mib,
                )
                .unwrap(),
            ],
            AuthorityScope::Realm { .. } => vec![
                PendingQueueSourceQuota::try_new(
                    PendingQueuePublisherKind::RealmUserUpdate,
                    50_000,
                    127 * mib,
                    mib,
                )
                .unwrap(),
            ],
        };
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            quotas,
            128 * mib,
        )
        .unwrap();
        let ledger = PendingQueueSegmentLedgerBootstrap::try_new(
            key,
            &validated,
            budget,
            8,
        )
            .unwrap()
            .candidate()
            .clone();
        let assignment = ledger.reserve_generation(context).unwrap().assignment().clone();
        let route = RecoverableNatsSourceRoute::try_new(
            context,
            match authority {
                AuthorityScope::Coordinator => {
                    PendingQueuePublisherKind::CoordinatorRegistration
                }
                AuthorityScope::Realm { .. } => {
                    PendingQueuePublisherKind::RealmUserUpdate
                }
            },
            &segment,
        )
        .unwrap();
        (segment, assignment, route)
    }

    #[test]
    fn data_and_seal_are_deterministic_and_branch_exact() {
        let (segment, assignment, route) = fixture(AuthorityScope::Coordinator);
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([9; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            b"registration".to_vec(),
        )
        .unwrap();
        let encoded = data.to_canonical_bytes();
        let encoded_digest: [u8; 32] = Sha256::digest(&encoded).into();
        assert_eq!(
            encoded_digest,
            [
                250, 192, 132, 20, 246, 100, 62, 145, 33, 72, 97, 79, 185,
                178, 204, 35, 50, 24, 221, 172, 154, 229, 146, 210, 130, 200,
                122, 23, 52, 157, 154, 28,
            ],
        );
        assert_eq!(
            PendingQueuePublishEnvelope::decode_canonical(&encoded).unwrap(),
            data,
        );
        assert_eq!(data.to_canonical_bytes(), encoded);
        assert!(data.exact_subject(&segment).unwrap().contains(".G"));
        assert_eq!(data.message_id().len(), 72);
        let mut legacy_envelope = encoded.clone();
        legacy_envelope[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            PendingQueuePublishEnvelope::decode_canonical(&legacy_envelope),
            Err(PendingQueueEnvelopeError::UnknownCodecVersion(1)),
        );

        let summary = PendingQueueSealSummary::try_new(
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            1,
            data.payload_bytes() as u64,
            encoded.len() as u64,
            *data.digest().as_bytes(),
        )
        .unwrap();
        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([10; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            44,
            *data.digest().as_bytes(),
            summary,
        )
        .unwrap();
        assert!(matches!(seal.body(), PendingQueueEnvelopeBody::Seal(_)));
        assert_eq!(seal.member_ordinal().get(), 2);
        assert_ne!(seal.digest(), data.digest());
    }

    #[test]
    fn authority_assignment_and_tamper_fail_closed() {
        let (segment, assignment, route) = fixture(AuthorityScope::Coordinator);
        let wrong_route = RecoverableNatsSourceRoute::try_new(
            route.context(),
            PendingQueuePublisherKind::RealmUserUpdate,
            &segment,
        );
        assert_eq!(
            wrong_route,
            Err(PendingQueueEnvelopeError::PublisherAuthorityMismatch),
        );
        let envelope = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([11; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            vec![1, 2, 3],
        )
        .unwrap();
        let mut bytes = envelope.to_canonical_bytes();
        let tamper_at = bytes.len() - 33;
        bytes[tamper_at] ^= 1;
        assert_eq!(
            PendingQueuePublishEnvelope::decode_canonical(&bytes),
            Err(PendingQueueEnvelopeError::DigestMismatch),
        );
        assert_eq!(
            PendingQueueSealSummary::try_new(
                PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
                0,
                1,
                0,
                [0; 32],
            ),
            Err(PendingQueueEnvelopeError::InvalidEmptySeal),
        );
    }

    #[test]
    fn exact_manifest_and_source_cursor_charge_data_and_seal() {
        let (_, assignment, route) = fixture(AuthorityScope::Coordinator);
        let budget = PendingQueueGenerationBudgetContract::try_new(
            AuthorityScope::Coordinator,
            assignment.source_quotas().to_vec(),
            assignment.reserved_bytes() as u64,
        )
        .unwrap();
        let encoded_budget = budget.to_canonical_bytes();
        let budget_bytes_digest: [u8; 32] =
            Sha256::digest(&encoded_budget).into();
        assert_eq!(
            budget_bytes_digest,
            [
                199, 242, 105, 102, 203, 177, 66, 189, 240, 140, 154, 94, 84,
                206, 214, 96, 182, 248, 161, 116, 2, 148, 105, 171, 178, 29,
                185, 202, 221, 130, 28, 101,
            ],
        );
        assert_eq!(
            PendingQueueGenerationBudgetContract::decode_canonical(
                &encoded_budget,
            )
            .unwrap(),
            budget,
        );
        assert_eq!(budget.digest(), assignment.budget_digest());

        let state = PendingQueuePublishSourceState::bootstrap(&route, &assignment)
            .unwrap();
        assert_eq!(
            PendingQueuePublishSourceState::decode_persisted(
                state.revision().get() as i64,
                &state.to_persisted_bytes(),
            )
            .unwrap(),
            state,
        );
        let mut legacy_source = state.to_persisted_bytes();
        legacy_source[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            PendingQueuePublishSourceState::decode_persisted(
                state.revision().get() as i64,
                &legacy_source,
            ),
            Err(PendingQueueEnvelopeError::UnknownCodecVersion(1)),
        );
        let data = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([41; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            b"one".to_vec(),
        )
        .unwrap();
        let selected = match state.select(&data).unwrap() {
            PendingQueueSourceSelectionPlan::Advance { candidate, .. } => {
                candidate
            }
            _ => unreachable!(),
        };
        assert!(matches!(
            selected.select(&data).unwrap(),
            PendingQueueSourceSelectionPlan::Idempotent(_),
        ));
        let commit_pending = selected
            .record_published(100)
            .unwrap()
            .candidate()
            .clone();
        assert!(matches!(
            commit_pending.phase(),
            PendingQueuePublishSourcePhase::CommitPending { .. }
        ));
        assert_eq!(
            PendingQueuePublishSourceState::decode_persisted(
                commit_pending.revision().get() as i64,
                &commit_pending.to_persisted_bytes(),
            )
            .unwrap(),
            commit_pending,
        );
        let open = commit_pending
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(open.data_member_count(), 1);
        assert_eq!(open.data_payload_bytes(), 3);
        assert_ne!(open.data_rolling_digest(), [0; 32]);

        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([42; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            100,
            open.last_envelope_digest(),
            open
                .seal_summary(PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let sealing = match open.select(&seal).unwrap() {
            PendingQueueSourceSelectionPlan::Advance { candidate, .. } => {
                candidate
            }
            _ => unreachable!(),
        };
        let seal_commit = sealing
            .record_published(101)
            .unwrap()
            .candidate()
            .clone();
        let sealed = seal_commit
            .finalize_published()
            .unwrap()
            .candidate()
            .clone();
        assert!(matches!(
            sealed.phase(),
            PendingQueuePublishSourcePhase::Sealed { .. },
        ));
        let mut corrupted = sealed.to_persisted_bytes();
        corrupted[20] ^= 1;
        assert!(PendingQueuePublishSourceState::decode_persisted(
            sealed.revision().get() as i64,
            &corrupted,
        )
        .is_err());
        assert_eq!(
            sealed.select(&data),
            Err(PendingQueueEnvelopeError::SourceAlreadySealed),
        );
    }
}
