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
use sha2::{Digest, Sha256};

use super::{
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmProcessorExternalDependencyInputError {
    EmptyDigest,
    MalformedItem,
    ContextMismatch,
    AssignmentMismatch,
    SequenceMismatch,
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
}
