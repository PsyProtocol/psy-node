//! Exact production projection of one qualified Realm Edge generation.
//!
//! JetStream carries the ordered queue payload while the immutable dependency
//! store carries the matching contract-update bytes.  This module binds both
//! halves to the admission qualification that was valid before the gathering
//! generation rotated into processing.  The values remain data commitments,
//! not terminal, rotation, writer, or authority-head capabilities.

use std::{error::Error, fmt};

use parth_core::{
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase},
};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use crate::store::pending_generation_identity::{
    PendingGenerationActivationDigest, PendingGenerationContext,
    PendingGenerationLedgerKey,
};

use super::{
    realm_processor_durable_capture::{
        RealmProcessorDurableCapturedGeneration,
        RealmProcessorDurableGenerationDigest,
    },
    realm_user_update_admission::{
        RealmUserUpdateAdmissionCloseIntent, RealmUserUpdateAdmissionKey,
        RealmUserUpdateQualificationDigest, RealmUserUpdateTerminalEvidenceDigest,
    },
    realm_user_update_consumer::RealmUserUpdateDurableGeneration,
    recoverable_ephemeral::PendingQueueCaptureContext,
};

const ITEM_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-external-dependency-item/v1";
const PROJECTION_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-external-dependency-projection/v1";
const ACTOR_INPUT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-qualified-external-actor-input/v1";
const COMMITMENT_MAGIC: &[u8; 8] = b"PSYRDEPC";
const COMMITMENT_CODEC_VERSION: u16 = 1;
const COMMITMENT_UNSIGNED_LEN: usize = 209;
const COMMITMENT_LEN: usize = COMMITMENT_UNSIGNED_LEN + 32;
const COMMITMENT_RECORD_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-external-dependency-commitment-record/v1";

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(
                bytes: [u8; 32],
            ) -> Result<Self, RealmProcessorExternalDependencyInputError> {
                if bytes == [0; 32] {
                    Err(RealmProcessorExternalDependencyInputError::EmptyDigest)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

digest_type!(RealmProcessorExternalDependencyItemDigest);
digest_type!(RealmProcessorExternalDependencyProjectionDigest);
digest_type!(RealmProcessorQualifiedExternalActorInputDigest);

/// One exact published queue item plus the contract-update bytes required by
/// the Realm actor.  Subject sequence and envelope digest join the durable
/// dependency row back to the exact JetStream Data envelope.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorExternalDependencyItem {
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    terminal_evidence_digest: RealmUserUpdateTerminalEvidenceDigest,
    queue_item: Vec<u8>,
    contract_updates: Vec<u8>,
    digest: RealmProcessorExternalDependencyItemDigest,
}

impl RealmProcessorExternalDependencyItem {
    pub fn try_new(
        subject_sequence: u64,
        envelope_digest: [u8; 32],
        terminal_evidence_digest: RealmUserUpdateTerminalEvidenceDigest,
        queue_item: Vec<u8>,
        contract_updates: Vec<u8>,
    ) -> Result<Self, RealmProcessorExternalDependencyInputError> {
        if subject_sequence == 0
            || envelope_digest == [0; 32]
            || queue_item.is_empty()
            || contract_updates.is_empty()
        {
            return Err(RealmProcessorExternalDependencyInputError::MalformedItem);
        }
        let digest = item_digest(
            subject_sequence,
            envelope_digest,
            terminal_evidence_digest,
            &queue_item,
            &contract_updates,
        )?;
        Ok(Self {
            subject_sequence,
            envelope_digest,
            terminal_evidence_digest,
            queue_item,
            contract_updates,
            digest,
        })
    }

    pub const fn subject_sequence(&self) -> u64 {
        self.subject_sequence
    }

    pub const fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }

    pub const fn terminal_evidence_digest(
        &self,
    ) -> RealmUserUpdateTerminalEvidenceDigest {
        self.terminal_evidence_digest
    }

    pub fn queue_item(&self) -> &[u8] {
        &self.queue_item
    }

    pub fn contract_updates(&self) -> &[u8] {
        &self.contract_updates
    }

    pub const fn digest(&self) -> RealmProcessorExternalDependencyItemDigest {
        self.digest
    }
}

/// Compact value that a future storage-private terminal/rotation owner may
/// commit. It deliberately contains no raw payload and grants no mutation
/// authority; the actor loader must still re-read the qualified generation
/// and reproduce `projection_digest` exactly. Public construction is only a
/// checked data-model boundary, never storage authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorExternalDependencyCommitment {
    context: PendingQueueCaptureContext,
    admission_close_intent: RealmUserUpdateAdmissionCloseIntent,
    qualification_digest: RealmUserUpdateQualificationDigest,
    assignment_digest: [u8; 32],
    item_count: u32,
    projection_digest: RealmProcessorExternalDependencyProjectionDigest,
}

impl RealmProcessorExternalDependencyCommitment {
    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.context
    }

    pub const fn admission_close_intent(self) -> RealmUserUpdateAdmissionCloseIntent {
        self.admission_close_intent
    }

    pub const fn qualification_digest(self) -> RealmUserUpdateQualificationDigest {
        self.qualification_digest
    }

    pub const fn assignment_digest(&self) -> &[u8; 32] {
        &self.assignment_digest
    }

    pub const fn item_count(self) -> u32 {
        self.item_count
    }

    pub const fn is_explicit_empty(self) -> bool {
        self.item_count == 0
    }

    pub const fn projection_digest(
        self,
    ) -> RealmProcessorExternalDependencyProjectionDigest {
        self.projection_digest
    }

    pub fn to_canonical_bytes(self) -> Vec<u8> {
        let mut out = self.encode_unsigned();
        out.extend_from_slice(&commitment_record_digest(&out));
        out
    }

    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmProcessorExternalDependencyInputError> {
        if bytes.len() != COMMITMENT_LEN {
            return Err(RealmProcessorExternalDependencyInputError::InvalidCommitmentLength);
        }
        let (unsigned, encoded_digest) = bytes.split_at(COMMITMENT_UNSIGNED_LEN);
        if commitment_record_digest(unsigned) != encoded_digest {
            return Err(RealmProcessorExternalDependencyInputError::CodecDigestMismatch);
        }
        let mut decoder = CommitmentDecoder::new(unsigned);
        if decoder.take(8)? != COMMITMENT_MAGIC {
            return Err(RealmProcessorExternalDependencyInputError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != COMMITMENT_CODEC_VERSION {
            return Err(RealmProcessorExternalDependencyInputError::UnknownCodecVersion(
                version,
            ));
        }
        let network = NetworkId::try_from_chain_id(decoder.u32()?)
            .map_err(model)?;
        let authority = match decoder.u8()? {
            1 => AuthorityScope::Realm {
                realm_id: decoder.u32()?,
                realm_sub_id: decoder.u16()?,
            },
            _ => return Err(RealmProcessorExternalDependencyInputError::InvalidAuthority),
        };
        let activation = PendingGenerationActivationDigest::try_new(decoder.array32()?)
            .map_err(model)?;
        let processing = PendingGenerationContext::try_from_legacy(
            decoder.u64()?,
            u128::from_be_bytes(decoder.array16()?),
        )
        .map_err(model)?;
        let context = PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(network, authority),
            activation,
            processing,
        )
        .map_err(model)?;
        let admission_close_intent =
            RealmUserUpdateAdmissionCloseIntent::try_new(decoder.array32()?)
                .map_err(model)?;
        let qualification_digest =
            RealmUserUpdateQualificationDigest::try_new(decoder.array32()?)
                .map_err(model)?;
        let assignment_digest = decoder.array32()?;
        if assignment_digest == [0; 32] {
            return Err(RealmProcessorExternalDependencyInputError::AssignmentMismatch);
        }
        let item_count = decoder.u32()?;
        let projection_digest =
            RealmProcessorExternalDependencyProjectionDigest::try_new(decoder.array32()?)?;
        if !decoder.done() {
            return Err(RealmProcessorExternalDependencyInputError::TrailingBytes);
        }
        let commitment = Self {
            context,
            admission_close_intent,
            qualification_digest,
            assignment_digest,
            item_count,
            projection_digest,
        };
        if commitment.encode_unsigned() != unsigned {
            return Err(RealmProcessorExternalDependencyInputError::NonCanonicalCommitment);
        }
        Ok(commitment)
    }

    fn encode_unsigned(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COMMITMENT_UNSIGNED_LEN);
        out.extend_from_slice(COMMITMENT_MAGIC);
        out.extend_from_slice(&COMMITMENT_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(&self.context.key().network().chain_id().to_be_bytes());
        match self.context.key().authority() {
            AuthorityScope::Coordinator => unreachable!("validated Realm context"),
            AuthorityScope::Realm {
                realm_id,
                realm_sub_id,
            } => {
                out.push(1);
                out.extend_from_slice(&realm_id.to_be_bytes());
                out.extend_from_slice(&realm_sub_id.to_be_bytes());
            }
        }
        out.extend_from_slice(self.context.activation().as_bytes());
        out.extend_from_slice(&self.context.processing().pending_id().get().to_be_bytes());
        out.extend_from_slice(self.context.processing().proc_checkpoint_id().as_bytes());
        out.extend_from_slice(self.admission_close_intent.as_bytes());
        out.extend_from_slice(self.qualification_digest.as_bytes());
        out.extend_from_slice(&self.assignment_digest);
        out.extend_from_slice(&self.item_count.to_be_bytes());
        out.extend_from_slice(self.projection_digest.as_bytes());
        debug_assert_eq!(out.len(), COMMITMENT_UNSIGNED_LEN);
        out
    }
}

/// Complete, ordered input projection.  Construction from a durable consumer
/// proves the admission close and qualification were observed for this exact
/// generation and that every item belongs to the expected assignment.  An
/// empty `items` vector is a valid, explicitly qualified empty generation; a
/// missing projection is never interpreted as empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RealmProcessorExternalDependencyProjection {
    commitment: RealmProcessorExternalDependencyCommitment,
    items: Vec<RealmProcessorExternalDependencyItem>,
}

impl RealmProcessorExternalDependencyProjection {
    pub fn try_from_qualified_generation<F, Hash>(
        context: PendingQueueCaptureContext,
        expected_assignment_digest: [u8; 32],
        generation: &RealmUserUpdateDurableGeneration<F, Hash>,
    ) -> Result<Self, RealmProcessorExternalDependencyInputError>
    where
        F: QFelt64,
        Hash: Q256BitHash + QFHashBase<F>,
    {
        let key = RealmUserUpdateAdmissionKey::try_new(context)
            .map_err(model)?;
        if generation.key() != key {
            return Err(RealmProcessorExternalDependencyInputError::ContextMismatch);
        }
        if expected_assignment_digest == [0; 32] {
            return Err(RealmProcessorExternalDependencyInputError::AssignmentMismatch);
        }

        let qualification_digest = generation.qualification().digest();
        let mut items = Vec::with_capacity(generation.items().len());
        for item in generation.items() {
            let observed_assignment = *item.publication().assignment_digest();
            if observed_assignment != expected_assignment_digest {
                return Err(RealmProcessorExternalDependencyInputError::AssignmentMismatch);
            }
            items.push(RealmProcessorExternalDependencyItem::try_new(
                item.publication().subject_sequence(),
                *item.publication().envelope_digest(),
                item.terminal().digest(),
                item.queue_payload().to_vec(),
                item.contract_updates().to_vec(),
            )?);
        }
        Self::try_new(
            context,
            generation.close(),
            qualification_digest,
            expected_assignment_digest,
            items,
        )
    }

    pub fn try_new(
        context: PendingQueueCaptureContext,
        admission_close_intent: RealmUserUpdateAdmissionCloseIntent,
        qualification_digest: RealmUserUpdateQualificationDigest,
        assignment_digest: [u8; 32],
        mut items: Vec<RealmProcessorExternalDependencyItem>,
    ) -> Result<Self, RealmProcessorExternalDependencyInputError> {
        if assignment_digest == [0; 32] {
            return Err(RealmProcessorExternalDependencyInputError::AssignmentMismatch);
        }
        RealmUserUpdateAdmissionKey::try_new(context).map_err(model)?;
        items.sort_by_key(RealmProcessorExternalDependencyItem::subject_sequence);
        if items
            .windows(2)
            .any(|pair| pair[0].subject_sequence() >= pair[1].subject_sequence())
        {
            return Err(RealmProcessorExternalDependencyInputError::SequenceMismatch);
        }
        let item_count = u32::try_from(items.len())
            .map_err(|_| RealmProcessorExternalDependencyInputError::ItemCountOverflow)?;
        let projection_digest = projection_digest(
            context,
            admission_close_intent,
            qualification_digest,
            assignment_digest,
            &items,
        )?;
        Ok(Self {
            commitment: RealmProcessorExternalDependencyCommitment {
                context,
                admission_close_intent,
                qualification_digest,
                assignment_digest,
                item_count,
                projection_digest,
            },
            items,
        })
    }

    pub const fn commitment(&self) -> RealmProcessorExternalDependencyCommitment {
        self.commitment
    }

    pub fn items(&self) -> &[RealmProcessorExternalDependencyItem] {
        &self.items
    }

    pub fn into_items(self) -> Vec<RealmProcessorExternalDependencyItem> {
        self.items
    }
}

/// One closed transport generation joined to the exact dependency rows for
/// those same Data envelopes. The actor receives this value as a single
/// non-Clone input, so callers cannot combine generation A with dependencies
/// from generation B. Constructing it remains data validation, not mutation
/// authority; the real actor entry point is kept behind the controlled
/// Processor iteration.
#[derive(Debug)]
pub struct RealmProcessorQualifiedExternalActorInput {
    generation: RealmProcessorDurableCapturedGeneration,
    dependency_commitment: RealmProcessorExternalDependencyCommitment,
    items: Vec<RealmProcessorExternalDependencyItem>,
    digest: RealmProcessorQualifiedExternalActorInputDigest,
}

impl RealmProcessorQualifiedExternalActorInput {
    pub fn try_from_exact_sources(
        generation: RealmProcessorDurableCapturedGeneration,
        projection: RealmProcessorExternalDependencyProjection,
    ) -> Result<Self, RealmProcessorExternalDependencyInputError> {
        let dependency_commitment = projection.commitment();
        if generation.context() != dependency_commitment.context()
            || generation.item_count() != u64::from(dependency_commitment.item_count())
        {
            return Err(RealmProcessorExternalDependencyInputError::GenerationMismatch);
        }

        let captured_items = generation
            .batches()
            .iter()
            .flat_map(|batch| batch.business_items());
        for (captured, dependency) in captured_items.zip(projection.items()) {
            if captured.subject_sequence() != dependency.subject_sequence()
                || captured.envelope_digest() != dependency.envelope_digest()
            {
                return Err(RealmProcessorExternalDependencyInputError::EnvelopeMismatch);
            }
            if captured.payload() != dependency.queue_item() {
                return Err(RealmProcessorExternalDependencyInputError::PayloadMismatch);
            }
        }

        let digest = qualified_actor_input_digest(
            generation.digest(),
            dependency_commitment.projection_digest(),
            dependency_commitment.item_count(),
        )?;
        Ok(Self {
            generation,
            dependency_commitment,
            items: projection.into_items(),
            digest,
        })
    }

    pub const fn context(&self) -> PendingQueueCaptureContext {
        self.dependency_commitment.context()
    }

    pub const fn generation_digest(&self) -> RealmProcessorDurableGenerationDigest {
        self.generation.digest()
    }

    pub const fn dependency_commitment(
        &self,
    ) -> RealmProcessorExternalDependencyCommitment {
        self.dependency_commitment
    }

    pub fn items(&self) -> &[RealmProcessorExternalDependencyItem] {
        &self.items
    }

    pub const fn digest(&self) -> RealmProcessorQualifiedExternalActorInputDigest {
        self.digest
    }

    pub fn into_parts(
        self,
    ) -> (
        RealmProcessorDurableCapturedGeneration,
        Vec<RealmProcessorExternalDependencyItem>,
    ) {
        (self.generation, self.items)
    }
}

fn qualified_actor_input_digest(
    generation_digest: RealmProcessorDurableGenerationDigest,
    projection_digest: RealmProcessorExternalDependencyProjectionDigest,
    item_count: u32,
) -> Result<RealmProcessorQualifiedExternalActorInputDigest, RealmProcessorExternalDependencyInputError>
{
    let mut hasher = Sha256::new();
    hasher.update(ACTOR_INPUT_DIGEST_DOMAIN);
    hasher.update(generation_digest.as_bytes());
    hasher.update(projection_digest.as_bytes());
    hasher.update(item_count.to_be_bytes());
    RealmProcessorQualifiedExternalActorInputDigest::try_new(hasher.finalize().into())
}

fn item_digest(
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    terminal_evidence_digest: RealmUserUpdateTerminalEvidenceDigest,
    queue_item: &[u8],
    contract_updates: &[u8],
) -> Result<RealmProcessorExternalDependencyItemDigest, RealmProcessorExternalDependencyInputError>
{
    let mut hasher = Sha256::new();
    hasher.update(ITEM_DIGEST_DOMAIN);
    hasher.update(subject_sequence.to_be_bytes());
    hasher.update(envelope_digest);
    hasher.update(terminal_evidence_digest.as_bytes());
    hash_bytes(&mut hasher, queue_item)?;
    hash_bytes(&mut hasher, contract_updates)?;
    RealmProcessorExternalDependencyItemDigest::try_new(hasher.finalize().into())
}

fn projection_digest(
    context: PendingQueueCaptureContext,
    admission_close_intent: RealmUserUpdateAdmissionCloseIntent,
    qualification_digest: RealmUserUpdateQualificationDigest,
    assignment_digest: [u8; 32],
    items: &[RealmProcessorExternalDependencyItem],
) -> Result<RealmProcessorExternalDependencyProjectionDigest, RealmProcessorExternalDependencyInputError>
{
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_DIGEST_DOMAIN);
    hasher.update(context.digest().as_bytes());
    hasher.update(admission_close_intent.as_bytes());
    hasher.update(qualification_digest.as_bytes());
    hasher.update(assignment_digest);
    hasher.update((items.len() as u64).to_be_bytes());
    for item in items {
        hasher.update(item.subject_sequence().to_be_bytes());
        hasher.update(item.digest().as_bytes());
    }
    RealmProcessorExternalDependencyProjectionDigest::try_new(hasher.finalize().into())
}

fn hash_bytes(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), RealmProcessorExternalDependencyInputError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| RealmProcessorExternalDependencyInputError::ComponentTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

fn model(error: impl fmt::Display) -> RealmProcessorExternalDependencyInputError {
    RealmProcessorExternalDependencyInputError::Model(error.to_string())
}

fn commitment_record_digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_RECORD_DIGEST_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct CommitmentDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CommitmentDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(
        &mut self,
        len: usize,
    ) -> Result<&'a [u8], RealmProcessorExternalDependencyInputError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(RealmProcessorExternalDependencyInputError::TruncatedCommitment)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealmProcessorExternalDependencyInputError::TruncatedCommitment)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RealmProcessorExternalDependencyInputError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RealmProcessorExternalDependencyInputError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RealmProcessorExternalDependencyInputError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RealmProcessorExternalDependencyInputError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array16(&mut self) -> Result<[u8; 16], RealmProcessorExternalDependencyInputError> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    fn array32(&mut self) -> Result<[u8; 32], RealmProcessorExternalDependencyInputError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorExternalDependencyInputError {
    EmptyDigest,
    MalformedItem,
    ContextMismatch,
    AssignmentMismatch,
    SequenceMismatch,
    GenerationMismatch,
    EnvelopeMismatch,
    PayloadMismatch,
    InvalidCommitmentLength,
    InvalidMagic,
    UnknownCodecVersion(u16),
    InvalidAuthority,
    CodecDigestMismatch,
    TruncatedCommitment,
    TrailingBytes,
    NonCanonicalCommitment,
    ItemCountOverflow,
    ComponentTooLarge,
    Model(String),
}

impl fmt::Display for RealmProcessorExternalDependencyInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorExternalDependencyInputError {}

#[cfg(test)]
mod tests {
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };

    use crate::store::pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    };
    use crate::store::pending_generation_pipeline::PendingQueueCloseIntentDigest;
    use crate::queue::{
        realm_processor_durable_capture::{
            RealmProcessorDurableCapturedBatch,
            RealmProcessorDurableCapturedItem,
        },
        recoverable_ephemeral::{
            PendingQueueBoundaryObservation, PendingQueueCaptureCandidate,
            PendingQueueGenerationBoundary, PendingQueueSourceCursor,
            PendingQueueSourceIdentity,
        },
    };

    use super::*;

    fn context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 2,
                    realm_sub_id: 3,
                },
            ),
            PendingGenerationActivationDigest::try_new([4; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(5, 6).unwrap(),
        )
        .unwrap()
    }

    fn item(sequence: u64, marker: u8) -> RealmProcessorExternalDependencyItem {
        RealmProcessorExternalDependencyItem::try_new(
            sequence,
            [marker; 32],
            RealmUserUpdateTerminalEvidenceDigest::try_new([marker + 1; 32])
                .unwrap(),
            vec![marker, 1],
            vec![marker, 2],
        )
        .unwrap()
    }

    fn admission_close() -> RealmUserUpdateAdmissionCloseIntent {
        RealmUserUpdateAdmissionCloseIntent::derive(
            RealmUserUpdateAdmissionKey::try_new(context()).unwrap(),
            [7; 32],
        )
        .unwrap()
    }

    fn captured_generation(
        items: &[(u64, u8)],
    ) -> RealmProcessorDurableCapturedGeneration {
        let context = context();
        let source = PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "realm-updates-r2-s3",
            "psy.realm-updates.r2.s3.processing",
        )
        .unwrap();
        let batches = if items.is_empty() {
            Vec::new()
        } else {
            let sequences = items.iter().map(|(sequence, _)| *sequence).collect::<Vec<_>>();
            let candidate = PendingQueueCaptureCandidate::try_new(
                context,
                source.clone(),
                PendingQueueSourceCursor::nats_jetstream([4; 32], &sequences).unwrap(),
                items
                    .iter()
                    .map(|(_, marker)| vec![*marker, 99])
                    .collect(),
            )
            .unwrap();
            vec![RealmProcessorDurableCapturedBatch::try_from_verified_envelopes(
                candidate,
                items
                    .iter()
                    .map(|(sequence, marker)| {
                        RealmProcessorDurableCapturedItem::try_new(
                            *sequence,
                            [*marker; 32],
                            vec![*marker, 1],
                        )
                        .unwrap()
                    })
                    .collect(),
            )
            .unwrap()]
        };
        let last_data = items.last().map_or(0, |(sequence, _)| *sequence);
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source.clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: last_data + 1,
                last_data_stream_sequence: last_data,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        RealmProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
            context,
            batches,
            boundary,
        )
        .unwrap()
    }

    fn projection(
        items: Vec<RealmProcessorExternalDependencyItem>,
    ) -> RealmProcessorExternalDependencyProjection {
        RealmProcessorExternalDependencyProjection::try_new(
            context(),
            admission_close(),
            RealmUserUpdateQualificationDigest::try_new([8; 32]).unwrap(),
            [9; 32],
            items,
        )
        .unwrap()
    }

    #[test]
    fn projection_is_ordered_and_binds_admission_qualification_and_dependencies() {
        let context = context();
        let queue_close = PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap();
        let key = RealmUserUpdateAdmissionKey::try_new(context).unwrap();
        let admission_close = RealmUserUpdateAdmissionCloseIntent::derive(
            key,
            *queue_close.as_bytes(),
        )
        .unwrap();
        let qualification = RealmUserUpdateQualificationDigest::try_new([8; 32]).unwrap();
        let projection = RealmProcessorExternalDependencyProjection::try_new(
            context,
            admission_close,
            qualification,
            [9; 32],
            vec![item(12, 12), item(11, 11)],
        )
        .unwrap();
        assert_eq!(projection.items()[0].subject_sequence(), 11);
        assert_eq!(projection.items()[1].subject_sequence(), 12);
        assert_eq!(projection.commitment().context(), context);
        assert_eq!(projection.commitment().item_count(), 2);
        assert!(!projection.commitment().is_explicit_empty());

        let changed_updates = RealmProcessorExternalDependencyProjection::try_new(
            context,
            admission_close,
            qualification,
            [9; 32],
            vec![
                item(11, 11),
                RealmProcessorExternalDependencyItem::try_new(
                    12,
                    [12; 32],
                    RealmUserUpdateTerminalEvidenceDigest::try_new([13; 32])
                        .unwrap(),
                    vec![12, 1],
                    vec![12, 99],
                )
                .unwrap(),
            ],
        )
        .unwrap();
        assert_ne!(
            projection.commitment().projection_digest(),
            changed_updates.commitment().projection_digest(),
        );

        let encoded = projection.commitment().to_canonical_bytes();
        assert_eq!(
            RealmProcessorExternalDependencyCommitment::decode_canonical(&encoded)
                .unwrap(),
            projection.commitment(),
        );
        let mut tampered = encoded.clone();
        tampered[80] ^= 1;
        assert_eq!(
            RealmProcessorExternalDependencyCommitment::decode_canonical(&tampered)
                .unwrap_err(),
            RealmProcessorExternalDependencyInputError::CodecDigestMismatch,
        );
        assert_eq!(
            RealmProcessorExternalDependencyCommitment::decode_canonical(
                &encoded[..encoded.len() - 1],
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::InvalidCommitmentLength,
        );
    }

    #[test]
    fn projection_supports_explicit_empty_and_rejects_duplicates_and_malformed_items() {
        let context = context();
        let queue_close = PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap();
        let key = RealmUserUpdateAdmissionKey::try_new(context).unwrap();
        let admission_close = RealmUserUpdateAdmissionCloseIntent::derive(
            key,
            *queue_close.as_bytes(),
        )
        .unwrap();
        let qualification = RealmUserUpdateQualificationDigest::try_new([8; 32]).unwrap();
        let explicit_empty = RealmProcessorExternalDependencyProjection::try_new(
            context,
            admission_close,
            qualification,
            [9; 32],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(explicit_empty.commitment().item_count(), 0);
        assert!(explicit_empty.commitment().is_explicit_empty());
        assert_ne!(
            explicit_empty.commitment().projection_digest().as_bytes(),
            &[0; 32],
        );
        assert_ne!(
            explicit_empty.commitment().projection_digest(),
            RealmProcessorExternalDependencyProjection::try_new(
                context,
                admission_close,
                qualification,
                [9; 32],
                vec![item(11, 11)],
            )
            .unwrap()
            .commitment()
            .projection_digest(),
        );
        assert_eq!(
            RealmProcessorExternalDependencyProjection::try_new(
                context,
                admission_close,
                qualification,
                [0; 32],
                Vec::new(),
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::AssignmentMismatch,
        );
        assert_eq!(
            RealmProcessorExternalDependencyProjection::try_new(
                context,
                admission_close,
                qualification,
                [9; 32],
                vec![item(11, 11), item(11, 12)],
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::SequenceMismatch,
        );
        assert_eq!(
            RealmProcessorExternalDependencyItem::try_new(
                1,
                [1; 32],
                RealmUserUpdateTerminalEvidenceDigest::try_new([2; 32]).unwrap(),
                vec![1],
                Vec::new(),
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::MalformedItem,
        );
    }

    #[test]
    fn qualified_actor_input_joins_exact_envelopes_payloads_and_dependencies() {
        let input = RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            captured_generation(&[(11, 11), (12, 12)]),
            projection(vec![item(12, 12), item(11, 11)]),
        )
        .unwrap();
        assert_eq!(input.context(), context());
        assert_eq!(input.items().len(), 2);
        assert_eq!(input.items()[0].subject_sequence(), 11);
        assert_eq!(input.items()[1].contract_updates(), &[12, 2]);
        assert_ne!(input.digest().as_bytes(), &[0; 32]);

        let same = RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            captured_generation(&[(11, 11), (12, 12)]),
            projection(vec![item(11, 11), item(12, 12)]),
        )
        .unwrap();
        assert_eq!(input.digest(), same.digest());

        let changed_updates = RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            captured_generation(&[(11, 11), (12, 12)]),
            projection(vec![
                item(11, 11),
                RealmProcessorExternalDependencyItem::try_new(
                    12,
                    [12; 32],
                    RealmUserUpdateTerminalEvidenceDigest::try_new([13; 32]).unwrap(),
                    vec![12, 1],
                    vec![12, 77],
                )
                .unwrap(),
            ]),
        )
        .unwrap();
        assert_ne!(input.digest(), changed_updates.digest());
    }

    #[test]
    fn qualified_actor_input_rejects_cross_wired_sources_and_accepts_explicit_empty() {
        let wrong_envelope = projection(vec![
            item(11, 11),
            RealmProcessorExternalDependencyItem::try_new(
                12,
                [99; 32],
                RealmUserUpdateTerminalEvidenceDigest::try_new([13; 32]).unwrap(),
                vec![12, 1],
                vec![12, 2],
            )
            .unwrap(),
        ]);
        assert_eq!(
            RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
                captured_generation(&[(11, 11), (12, 12)]),
                wrong_envelope,
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::EnvelopeMismatch,
        );

        let wrong_payload = projection(vec![
            item(11, 11),
            RealmProcessorExternalDependencyItem::try_new(
                12,
                [12; 32],
                RealmUserUpdateTerminalEvidenceDigest::try_new([13; 32]).unwrap(),
                vec![12, 88],
                vec![12, 2],
            )
            .unwrap(),
        ]);
        assert_eq!(
            RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
                captured_generation(&[(11, 11), (12, 12)]),
                wrong_payload,
            )
            .unwrap_err(),
            RealmProcessorExternalDependencyInputError::PayloadMismatch,
        );

        let empty = RealmProcessorQualifiedExternalActorInput::try_from_exact_sources(
            captured_generation(&[]),
            projection(Vec::new()),
        )
        .unwrap();
        assert!(empty.items().is_empty());
        assert_eq!(empty.dependency_commitment().item_count(), 0);
        assert_ne!(empty.digest().as_bytes(), &[0; 32]);
    }

    #[test]
    fn captured_generation_rejects_cursor_or_cross_batch_sequence_drift() {
        let context = context();
        let source = PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "realm-updates-r2-s3",
            "psy.realm-updates.r2.s3.processing",
        )
        .unwrap();
        let candidate = PendingQueueCaptureCandidate::try_new(
            context,
            source.clone(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], &[11]).unwrap(),
            vec![vec![1]],
        )
        .unwrap();
        assert_eq!(
            RealmProcessorDurableCapturedBatch::try_from_verified_envelopes(
                candidate,
                vec![RealmProcessorDurableCapturedItem::try_new(
                    12,
                    [12; 32],
                    vec![12, 1],
                )
                .unwrap()],
            )
            .unwrap_err(),
            crate::queue::realm_processor_durable_capture::RealmProcessorDurableCaptureError::MalformedCompleteGeneration,
        );

        let make_batch = |sequence: u64, marker: u8| {
            RealmProcessorDurableCapturedBatch::try_from_verified_envelopes(
                PendingQueueCaptureCandidate::try_new(
                    context,
                    source.clone(),
                    PendingQueueSourceCursor::nats_jetstream([4; 32], &[sequence]).unwrap(),
                    vec![vec![marker]],
                )
                .unwrap(),
                vec![RealmProcessorDurableCapturedItem::try_new(
                    sequence,
                    [marker; 32],
                    vec![marker, 1],
                )
                .unwrap()],
            )
            .unwrap()
        };
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context,
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source.clone(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 13,
                last_data_stream_sequence: 12,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        assert_eq!(
            RealmProcessorDurableCapturedGeneration::try_from_exhaustive_readback(
                context,
                vec![make_batch(12, 12), make_batch(11, 11)],
                boundary,
            )
            .unwrap_err(),
            crate::queue::realm_processor_durable_capture::RealmProcessorDurableCaptureError::MalformedCompleteGeneration,
        );
    }
}
