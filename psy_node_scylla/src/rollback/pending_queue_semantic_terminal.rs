//! Default-off composition of the three independent per-source close proofs.
//!
//! A semantic source terminal exists only when the durable publisher row, the
//! leader-retained Data* + Seal history, and the exhaustive Scylla artifact
//! replay all describe the same branch-exact source. The receipt is not a
//! generation aggregate and cannot authorize stream rotation or GC.

#![allow(dead_code)]

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::{
    queue::recoverable_ephemeral::{
        PendingQueueCaptureCandidate, PendingQueueCaptureContextDigest,
        PendingQueueSourceCursorView,
    },
    queue::recoverable_artifact::{
        PendingQueueArtifactOwnerAttemptId, PendingQueueArtifactOwnerFence,
        PendingQueueArtifactScanDigest, PendingQueueArtifactSlot,
    },
    store::pending_generation_pipeline::PendingQueueCloseIntentDigest,
};
use psy_node_nats::{
    recoverable_assignment::{
        PendingQueueSegmentAssignmentDigest, PendingQueueSegmentLedgerRevision,
        PendingQueueSegmentLedgerSlot,
    },
    recoverable_publish::{
        PendingQueueEnvelopeBody, PendingQueuePublishEnvelope,
        PendingQueuePublishSourceSlot, PendingQueuePublishSourceState,
        PendingQueuePublisherKind,
        PendingQueueSourceSelectionPlan, RecoverableNatsSourceRoute,
    },
    recoverable_terminal::{
        PendingQueueSourceTruncationDigest,
        PendingQueueSourceTruncationReceipt,
    },
    recoverable_transport::RecoverableNatsCaptureSpec,
};
use sha2::{Digest, Sha256};

use super::{
    PendingQueueArtifactOwnerPermit, PendingQueueArtifactStoreError,
    PendingQueueArtifactStoreFingerprint,
    PendingQueuePublishStoreError, PendingQueuePublishStoreFingerprint,
    PendingQueueSegmentAssignmentReceipt, PendingQueueSegmentLedgerStoreFingerprint,
    PersistedPendingQueueCloseReceipt, PersistedPendingQueueSourceScanReceipt,
    ScyllaPendingPipelineStore, ScyllaPendingQueueArtifactStore,
    ScyllaPendingQueuePublishStore,
};

const SEMANTIC_SOURCE_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-semantic-source-terminal/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueSemanticSourceDigest([u8; 32]);

impl PendingQueueSemanticSourceDigest {
    pub(super) fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueSemanticSourceError> {
        if bytes == [0; 32] {
            Err(PendingQueueSemanticSourceError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Opaque per-source semantic terminal. Deliberately not Clone and with no
/// public constructor. A later fixed 3/1 aggregate must consume it before any
/// pipeline terminal can exist.
#[derive(Debug)]
pub struct PersistedPendingQueueSemanticSourceReceipt {
    publisher_kind: PendingQueuePublisherKind,
    context_digest: PendingQueueCaptureContextDigest,
    assignment_digest: PendingQueueSegmentAssignmentDigest,
    close_intent: PendingQueueCloseIntentDigest,
    pipeline_close_receipt_digest: [u8; 32],
    source_slot: PendingQueuePublishSourceSlot,
    publish_store_fingerprint: PendingQueuePublishStoreFingerprint,
    assignment_store_fingerprint: PendingQueueSegmentLedgerStoreFingerprint,
    assignment_ledger_slot: PendingQueueSegmentLedgerSlot,
    assignment_ledger_revision: PendingQueueSegmentLedgerRevision,
    artifact_store_fingerprint: PendingQueueArtifactStoreFingerprint,
    artifact_slot: PendingQueueArtifactSlot,
    artifact_owner_attempt_id: PendingQueueArtifactOwnerAttemptId,
    artifact_owner_fence: PendingQueueArtifactOwnerFence,
    consumer_digest: [u8; 32],
    data_member_count: u32,
    data_encoded_bytes: u64,
    source_revision: u64,
    artifact_scan_revision: u64,
    artifact_scan_digest: PendingQueueArtifactScanDigest,
    nats_scan_digest: PendingQueueSourceTruncationDigest,
    semantic_digest: PendingQueueSemanticSourceDigest,
}

pub(super) struct PendingQueueSemanticSourceCommitment {
    pub(super) publisher_kind: PendingQueuePublisherKind,
    pub(super) context_digest: PendingQueueCaptureContextDigest,
    pub(super) assignment_digest: PendingQueueSegmentAssignmentDigest,
    pub(super) close_intent: PendingQueueCloseIntentDigest,
    pub(super) pipeline_close_receipt_digest: [u8; 32],
    pub(super) publish_store_fingerprint: [u8; 32],
    pub(super) assignment_store_fingerprint: [u8; 32],
    pub(super) assignment_ledger_slot: [u8; 32],
    pub(super) assignment_ledger_revision: u64,
    pub(super) artifact_store_fingerprint: [u8; 32],
    pub(super) source_slot: PendingQueuePublishSourceSlot,
    pub(super) semantic_digest: PendingQueueSemanticSourceDigest,
    pub(super) data_member_count: u32,
    pub(super) data_encoded_bytes: u64,
}

impl PersistedPendingQueueSemanticSourceReceipt {
    pub const fn publisher_kind(&self) -> PendingQueuePublisherKind {
        self.publisher_kind
    }

    pub const fn close_intent(&self) -> PendingQueueCloseIntentDigest {
        self.close_intent
    }

    pub const fn source_slot(&self) -> PendingQueuePublishSourceSlot {
        self.source_slot
    }

    pub const fn semantic_digest(&self) -> PendingQueueSemanticSourceDigest {
        self.semantic_digest
    }

    pub(super) fn into_commitment(self) -> PendingQueueSemanticSourceCommitment {
        PendingQueueSemanticSourceCommitment {
            publisher_kind: self.publisher_kind,
            context_digest: self.context_digest,
            assignment_digest: self.assignment_digest,
            close_intent: self.close_intent,
            pipeline_close_receipt_digest: self.pipeline_close_receipt_digest,
            publish_store_fingerprint: *self.publish_store_fingerprint.as_bytes(),
            assignment_store_fingerprint: *self.assignment_store_fingerprint.as_bytes(),
            assignment_ledger_slot: *self.assignment_ledger_slot.as_bytes(),
            assignment_ledger_revision: self.assignment_ledger_revision.get(),
            artifact_store_fingerprint: *self.artifact_store_fingerprint.as_bytes(),
            source_slot: self.source_slot,
            semantic_digest: self.semantic_digest,
            data_member_count: self.data_member_count,
            data_encoded_bytes: self.data_encoded_bytes,
        }
    }
}

pub(super) async fn verify_semantic_source_terminal<Hash: Q256BitHash>(
    pipeline_store: &ScyllaPendingPipelineStore,
    publish_store: &ScyllaPendingQueuePublishStore,
    artifact_store: &ScyllaPendingQueueArtifactStore,
    assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
    artifact_owner: &PendingQueueArtifactOwnerPermit,
    close_receipt: &PersistedPendingQueueCloseReceipt,
    capture_contract: &RecoverableNatsCaptureSpec,
    publisher_kind: PendingQueuePublisherKind,
    nats_scan: PendingQueueSourceTruncationReceipt,
) -> Result<PersistedPendingQueueSemanticSourceReceipt, PendingQueueSemanticSourceError> {
    let expected_close_intent = close_receipt.close_intent();
    let assignment = assignment_receipt.assignment();
    if !close_receipt.matches_context(assignment.context()) {
        return Err(PendingQueueSemanticSourceError::CloseContextMismatch);
    }
    pipeline_store
        .revalidate_queue_close_exact::<Hash>(assignment.context(), close_receipt)
        .await
        .map_err(|error| PendingQueueSemanticSourceError::Pipeline(error.to_string()))?;
    let contract_source = capture_contract
        .source_identity()
        .map_err(|error| PendingQueueSemanticSourceError::Nats(error.to_string()))?;
    if nats_scan.publisher_kind() != publisher_kind
        || nats_scan.close_intent() != expected_close_intent
        || nats_scan.source_state().artifact_identity().source() != &contract_source
    {
        return Err(PendingQueueSemanticSourceError::CloseIdentityMismatch);
    }

    let durable_source = publish_store
        .read_sealed_source_exact(
            assignment_receipt,
            publisher_kind,
            close_receipt,
        )
        .await?;
    if !nats_scan.matches_persisted_source(durable_source.source_state()) {
        return Err(PendingQueueSemanticSourceError::DurableSourceMismatch);
    }

    let boundary = nats_scan.boundary().map_err(|error| {
        PendingQueueSemanticSourceError::Nats(error.to_string())
    })?;
    let identity = durable_source.source_state().artifact_identity();
    let artifact_scan = artifact_store
        .scan_closed_source(artifact_owner, identity, boundary)
        .await?;
    let candidates = artifact_store
        .reconstruct_scanned_candidates_exact(
            artifact_owner,
            identity,
            &artifact_scan,
        )
        .await?;

    let route = RecoverableNatsSourceRoute::try_new(
        assignment.context(),
        publisher_kind,
        publish_store.segment(),
    )
    .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?;
    let replayed = replay_data_candidates(
        &route,
        assignment,
        capture_contract.consumer_digest(),
        &candidates,
    )?;
    if !nats_scan.matches_data_replay(&replayed) {
        return Err(PendingQueueSemanticSourceError::ArtifactReplayMismatch);
    }

    Ok(build_receipt(
        durable_source.store_fingerprint(),
        durable_source.source_state(),
        assignment_receipt,
        close_receipt,
        capture_contract.consumer_digest(),
        &artifact_scan,
        &nats_scan,
    )?)
}

fn replay_data_candidates(
    route: &RecoverableNatsSourceRoute,
    assignment: &psy_node_nats::recoverable_assignment::PendingQueueGenerationSegmentAssignment,
    expected_consumer_digest: [u8; 32],
    candidates: &[PendingQueueCaptureCandidate],
) -> Result<PendingQueuePublishSourceState, PendingQueueSemanticSourceError> {
    let mut state = PendingQueuePublishSourceState::bootstrap(route, assignment)
        .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?;
    for candidate in candidates {
        if candidate.artifact_identity() != state.artifact_identity() {
            return Err(PendingQueueSemanticSourceError::ArtifactIdentityMismatch);
        }
        let PendingQueueSourceCursorView::NatsJetStream {
            consumer_digest,
            stream_sequences,
            ..
        } = candidate.source().view()
        else {
            return Err(PendingQueueSemanticSourceError::ArtifactCursorMismatch);
        };
        if *consumer_digest != expected_consumer_digest {
            return Err(PendingQueueSemanticSourceError::ConsumerDigestMismatch);
        }
        if stream_sequences.len() != candidate.items().len() {
            return Err(PendingQueueSemanticSourceError::ArtifactCursorMismatch);
        }
        for (stream_sequence, canonical_envelope) in stream_sequences
            .iter()
            .copied()
            .zip(candidate.items())
        {
            let envelope = PendingQueuePublishEnvelope::decode_canonical(
                canonical_envelope,
            )
            .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?;
            if !matches!(envelope.body(), PendingQueueEnvelopeBody::Data(_)) {
                return Err(PendingQueueSemanticSourceError::SealInBusinessArtifact);
            }
            let selected = match state
                .select(&envelope)
                .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?
            {
                PendingQueueSourceSelectionPlan::Advance { candidate, .. } => candidate,
                PendingQueueSourceSelectionPlan::Idempotent(_) => {
                    return Err(PendingQueueSemanticSourceError::DuplicateData)
                }
            };
            let accepted = selected
                .record_published(stream_sequence)
                .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?;
            state = accepted
                .candidate()
                .finalize_published()
                .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?
                .candidate()
                .clone();
        }
    }
    Ok(state)
}

fn build_receipt(
    publish_store_fingerprint: PendingQueuePublishStoreFingerprint,
    source: &PendingQueuePublishSourceState,
    assignment_receipt: &PendingQueueSegmentAssignmentReceipt,
    close_receipt: &PersistedPendingQueueCloseReceipt,
    consumer_digest: [u8; 32],
    artifact: &PersistedPendingQueueSourceScanReceipt,
    nats: &PendingQueueSourceTruncationReceipt,
) -> Result<PersistedPendingQueueSemanticSourceReceipt, PendingQueueSemanticSourceError> {
    let source_slot = source
        .slot()
        .map_err(|error| PendingQueueSemanticSourceError::Replay(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_SOURCE_DOMAIN);
    hasher.update(publish_store_fingerprint.as_bytes());
    hasher.update(close_receipt.store_fingerprint().as_bytes());
    hasher.update(close_receipt.receipt_digest());
    hasher.update(assignment_receipt.store_fingerprint().as_bytes());
    hasher.update(assignment_receipt.ledger_slot().as_bytes());
    hasher.update(assignment_receipt.ledger_revision().get().to_be_bytes());
    hasher.update(artifact.store_fingerprint().as_bytes());
    hasher.update(artifact.slot().as_bytes());
    hasher.update(artifact.owner_attempt_id().as_bytes());
    hasher.update(artifact.owner_fence().get().to_be_bytes());
    hasher.update(consumer_digest);
    hasher.update(source_slot.as_bytes());
    hasher.update([source.publisher_kind() as u8]);
    hasher.update(nats.close_intent().as_bytes());
    hasher.update(source.revision().get().to_be_bytes());
    hasher.update(artifact.source_scan_revision().to_be_bytes());
    hasher.update(artifact.scan_digest().as_bytes());
    hasher.update(nats.scan_digest().as_bytes());
    hasher.update((source.to_persisted_bytes().len() as u64).to_be_bytes());
    hasher.update(source.to_persisted_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(PendingQueueSemanticSourceError::EmptyDigest);
    }
    Ok(PersistedPendingQueueSemanticSourceReceipt {
        publisher_kind: source.publisher_kind(),
        context_digest: source.artifact_identity().context().digest(),
        assignment_digest: source.assignment_digest(),
        close_intent: nats.close_intent(),
        pipeline_close_receipt_digest: *close_receipt.receipt_digest(),
        source_slot,
        publish_store_fingerprint,
        assignment_store_fingerprint: assignment_receipt.store_fingerprint(),
        assignment_ledger_slot: assignment_receipt.ledger_slot(),
        assignment_ledger_revision: assignment_receipt.ledger_revision(),
        artifact_store_fingerprint: artifact.store_fingerprint(),
        artifact_slot: artifact.slot(),
        artifact_owner_attempt_id: artifact.owner_attempt_id(),
        artifact_owner_fence: artifact.owner_fence(),
        consumer_digest,
        data_member_count: source.data_member_count(),
        data_encoded_bytes: source.data_encoded_bytes(),
        source_revision: source.revision().get(),
        artifact_scan_revision: artifact.source_scan_revision(),
        artifact_scan_digest: artifact.scan_digest(),
        nats_scan_digest: nats.scan_digest(),
        semantic_digest: PendingQueueSemanticSourceDigest::try_new(digest)?,
    })
}

#[derive(Debug)]
pub enum PendingQueueSemanticSourceError {
    CloseIdentityMismatch,
    CloseContextMismatch,
    DurableSourceMismatch,
    ArtifactIdentityMismatch,
    ArtifactCursorMismatch,
    ConsumerDigestMismatch,
    SealInBusinessArtifact,
    DuplicateData,
    ArtifactReplayMismatch,
    EmptyDigest,
    Replay(String),
    Pipeline(String),
    Nats(String),
    ArtifactStore(PendingQueueArtifactStoreError),
    PublishStore(PendingQueuePublishStoreError),
}

impl From<PendingQueueArtifactStoreError> for PendingQueueSemanticSourceError {
    fn from(value: PendingQueueArtifactStoreError) -> Self {
        Self::ArtifactStore(value)
    }
}

impl From<PendingQueuePublishStoreError> for PendingQueueSemanticSourceError {
    fn from(value: PendingQueuePublishStoreError) -> Self {
        Self::PublishStore(value)
    }
}

impl fmt::Display for PendingQueueSemanticSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueSemanticSourceError {}

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
        },
        store::pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationContext,
            PendingGenerationLedgerKey,
        },
    };
    use psy_node_nats::{
        recoverable_assignment::{
            PendingQueueGenerationSegmentAssignment,
            PendingQueueSegmentLedgerBootstrap,
            PendingQueueSegmentReservationPlan,
        },
        recoverable_publish::{
            PendingQueueGenerationBudgetContract, PendingQueueMemberOrdinal,
            PendingQueuePublishIntentId, PendingQueueSourceQuota,
        },
        recoverable_segment::{
            RecoverableNatsRetentionContract, RecoverableNatsSegmentId,
            RecoverableNatsStreamSegment,
        },
    };

    fn fixture() -> (
        RecoverableNatsStreamSegment,
        PendingQueueGenerationSegmentAssignment,
        RecoverableNatsSourceRoute,
    ) {
        let authority = AuthorityScope::Realm {
            realm_id: 3,
            realm_sub_id: 0,
        };
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
        let quota = PendingQueueSourceQuota::try_new(
            PendingQueuePublisherKind::RealmUserUpdate,
            100,
            127 * 1024 * 1024,
            1024 * 1024,
        )
        .unwrap();
        let budget = PendingQueueGenerationBudgetContract::try_new(
            authority,
            vec![quota],
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
        let assignment = match bootstrap
            .candidate()
            .reserve_generation(context)
            .unwrap()
        {
            PendingQueueSegmentReservationPlan::Advance { assignment, .. } => assignment,
            _ => unreachable!(),
        };
        let route = RecoverableNatsSourceRoute::try_new(
            context,
            PendingQueuePublisherKind::RealmUserUpdate,
            &segment,
        )
        .unwrap();
        (segment, assignment, route)
    }

    fn candidate(
        route: &RecoverableNatsSourceRoute,
        assignment: &PendingQueueGenerationSegmentAssignment,
        sequences: &[u64],
        items: Vec<Vec<u8>>,
    ) -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            assignment.context(),
            route.source_identity().clone(),
            PendingQueueSourceCursor::nats_jetstream([8; 32], sequences).unwrap(),
            items,
        )
        .unwrap()
    }

    #[test]
    fn data_only_artifact_replays_exact_source_and_seal_is_rejected() {
        let (_, assignment, route) = fixture();
        let first = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([11; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(1).unwrap(),
            0,
            [0; 32],
            b"first".to_vec(),
        )
        .unwrap();
        let second = PendingQueuePublishEnvelope::data(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([12; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(2).unwrap(),
            10,
            *first.digest().as_bytes(),
            b"second".to_vec(),
        )
        .unwrap();
        let data = candidate(
            &route,
            &assignment,
            &[10, 20],
            vec![first.to_canonical_bytes(), second.to_canonical_bytes()],
        );
        let replayed = replay_data_candidates(&route, &assignment, [8; 32], &[data]).unwrap();
        assert_eq!(replayed.data_member_count(), 2);
        assert_eq!(replayed.last_subject_sequence(), 20);
        assert_eq!(replayed.last_envelope_digest(), *second.digest().as_bytes());
        let wrong_consumer = candidate(
            &route,
            &assignment,
            &[10, 20],
            vec![first.to_canonical_bytes(), second.to_canonical_bytes()],
        );
        assert!(matches!(
            replay_data_candidates(&route, &assignment, [7; 32], &[wrong_consumer]),
            Err(PendingQueueSemanticSourceError::ConsumerDigestMismatch)
        ));

        let seal = PendingQueuePublishEnvelope::seal(
            &route,
            &assignment,
            PendingQueuePublishIntentId::try_new([13; 32]).unwrap(),
            PendingQueueMemberOrdinal::try_new(3).unwrap(),
            20,
            *second.digest().as_bytes(),
            replayed
                .seal_summary(PendingQueueCloseIntentDigest::try_new([9; 32]).unwrap())
                .unwrap(),
        )
        .unwrap();
        let contaminated = candidate(
            &route,
            &assignment,
            &[30],
            vec![seal.to_canonical_bytes()],
        );
        assert!(matches!(
            replay_data_candidates(&route, &assignment, [8; 32], &[contaminated]),
            Err(PendingQueueSemanticSourceError::SealInBusinessArtifact)
        ));
    }
}
