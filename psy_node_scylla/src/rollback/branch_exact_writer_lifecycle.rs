//! Driver-independent, revisioned lifecycle for online branch-exact writes.
//!
//! The state machine binds h20 schema readiness and h21 frozen-baseline
//! equivalence to one continuous writer watermark.  It deliberately performs
//! no CQL and is not wired into production processors; the Scylla LWT adapter
//! and execution path are later h22 slices.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::{
        AuthorityIntentObservation, AuthorityTimestampPhase,
        AuthorityTimestampRevision, ObservedAuthorityTimestampState,
    },
    branch_exact_dual_write::{
        BranchExactDualWriteIntent, BranchExactDualWriteIntentDigest,
        SealedBranchExactDualWrite,
    },
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::{
        BranchPendingMapping, BRANCH_PENDING_CANONICAL_REF_LEN,
    },
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use sha2::{Digest, Sha256};

use super::{
    source_receipt_digest, BranchExactBackfillArtifact,
    BranchExactBackfillDatasetDigest, BranchExactFrozenLegacyExportPermit,
    BranchExactLegacyExportReceipt, BranchExactSchemaReady,
    BranchExactSchemaReadyDigest, BranchExactShadowSourceReceiptDigest,
    BranchExactShadowVerifiedDigest, BranchExactShadowVerifiedReceipt,
};

const MAGIC: [u8; 8] = *b"PSYBEXWL";
const CODEC_VERSION: u16 = 1;
const PLAN_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-activation/v1";
const SLOT_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-slot/v1";
const PREPARED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-prepared/v1";
const VERIFIED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-verified/v1";
const BLOCKED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-blocked/v1";
const STATE_DIGEST_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-state/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactWriterGeneration(u64);

impl BranchExactWriterGeneration {
    pub const fn try_new(value: u64) -> Result<Self, BranchExactWriterLifecycleError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(BranchExactWriterLifecycleError::GenerationOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BranchExactWriterRevision(u64);

impl BranchExactWriterRevision {
    pub const fn try_new(value: u64) -> Result<Self, BranchExactWriterLifecycleError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(BranchExactWriterLifecycleError::RevisionOutOfRange(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, BranchExactWriterLifecycleError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(BranchExactWriterLifecycleError::RevisionOverflow)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriterActivationDigest([u8; 32]);

impl BranchExactWriterActivationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriterSlot([u8; 32]);

impl BranchExactWriterSlot {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn for_authority(
        network: psy_data::protocol::canonical_chain::NetworkId,
        authority: AuthorityScope,
    ) -> Self {
        writer_slot(network, authority)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriterIntentDigest([u8; 32]);

impl BranchExactWriterIntentDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    const fn from_intent(digest: BranchExactDualWriteIntentDigest) -> Self {
        Self(*digest.as_bytes())
    }
}

/// Evidence and baseline from which online dual-write may begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterActivationPlan<Hash> {
    generation: BranchExactWriterGeneration,
    authority: AuthorityScope,
    schema_ready_digest: BranchExactSchemaReadyDigest,
    shadow_audit_slot: super::BranchExactShadowAuditSlot,
    shadow_verified_digest: BranchExactShadowVerifiedDigest,
    source_receipt_digest: BranchExactShadowSourceReceiptDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    baseline: BranchPendingMapping<Hash>,
    baseline_timestamp: CommitWriteTimestampUs,
    digest: BranchExactWriterActivationDigest,
    slot: BranchExactWriterSlot,
}

impl<Hash: Q256BitHash> BranchExactWriterActivationPlan<Hash> {
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        generation: BranchExactWriterGeneration,
        ready: &BranchExactSchemaReady,
        shadow: &BranchExactShadowVerifiedReceipt,
        artifact: &BranchExactBackfillArtifact<Hash>,
        source: &BranchExactLegacyExportReceipt,
        freeze: &BranchExactFrozenLegacyExportPermit<Hash>,
        timestamp_state: ObservedAuthorityTimestampState,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let view = ready.view();
        let authority = view.authority();
        if artifact.authority() != authority
            || freeze.request().plan().authority() != authority
            || freeze.request().keyspace() != view.keyspace()
        {
            return Err(BranchExactWriterLifecycleError::AuthorityOrKeyspaceMismatch);
        }
        if source.permit_digest() != freeze.digest()
            || source.dataset_digest() != artifact.dataset_digest()
            || source.pair_rows() != artifact.pair_rows_per_direction()
            || source.proof_rows() != artifact.proof_rows()
        {
            return Err(BranchExactWriterLifecycleError::SourceEvidenceMismatch);
        }
        let shadow_plan = shadow.plan();
        if shadow_plan.schema_ready_digest() != view.digest()
            || shadow_plan.dataset_digest() != artifact.dataset_digest()
            || shadow_plan.source_receipt_digest() != source_receipt_digest(source)
            || shadow_plan.mapping_rows() != artifact.pair_rows_per_direction()
            || shadow_plan.proof_rows() != artifact.proof_rows()
        {
            return Err(BranchExactWriterLifecycleError::ShadowEvidenceMismatch);
        }
        let backfill = ready.expected_receipt();
        if backfill.digest() != view.backfill_receipt_digest()
            || backfill.plan().dataset_digest() != artifact.dataset_digest()
        {
            return Err(BranchExactWriterLifecycleError::BackfillEvidenceMismatch);
        }
        let backfill_timestamp = backfill
            .plan()
            .write_timestamp()
            .ok_or(BranchExactWriterLifecycleError::MissingBackfillTimestamp)?;
        let observed_key = timestamp_state.key();
        let observed = timestamp_state.state();
        if observed_key.network() != freeze.source_head().canonical_ref().network_id()
            || observed_key.authority() != authority
            || !matches!(observed.phase(), AuthorityTimestampPhase::Idle { .. })
            || observed.high_water() < backfill_timestamp
        {
            return Err(BranchExactWriterLifecycleError::TimestampAllocatorNotReady);
        }

        let baseline = unique_artifact_tip(artifact)?;
        let source_head = freeze.source_head().canonical_ref();
        for row in artifact.rows() {
            let chain = row.mapping().canonical_chain();
            if chain.network_id() != source_head.network_id()
                || chain.chain_epoch() != source_head.chain_epoch()
                || chain.checkpoint().checkpoint_id().get()
                    > source_head.checkpoint().checkpoint_id().get()
            {
                return Err(BranchExactWriterLifecycleError::ArtifactOutsideFrozenHead);
            }
        }
        if authority == AuthorityScope::Coordinator
            && baseline.canonical_chain() != source_head
        {
            return Err(BranchExactWriterLifecycleError::CoordinatorTipMismatch);
        }

        let mut plan = Self {
            generation,
            authority,
            schema_ready_digest: view.digest(),
            shadow_audit_slot: shadow_plan.slot(),
            shadow_verified_digest: shadow.digest(),
            source_receipt_digest: source_receipt_digest(source),
            dataset_digest: artifact.dataset_digest(),
            baseline,
            baseline_timestamp: observed.high_water(),
            digest: BranchExactWriterActivationDigest([0; 32]),
            slot: BranchExactWriterSlot([0; 32]),
        };
        plan.digest = activation_digest(&plan);
        plan.slot = writer_slot(
            plan.baseline.canonical_chain().network_id(),
            authority,
        );
        Ok(plan)
    }

    pub const fn generation(&self) -> BranchExactWriterGeneration {
        self.generation
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.authority
    }

    pub const fn schema_ready_digest(&self) -> BranchExactSchemaReadyDigest {
        self.schema_ready_digest
    }

    pub const fn shadow_verified_digest(&self) -> BranchExactShadowVerifiedDigest {
        self.shadow_verified_digest
    }

    pub const fn shadow_audit_slot(&self) -> super::BranchExactShadowAuditSlot {
        self.shadow_audit_slot
    }

    pub const fn source_receipt_digest(&self) -> BranchExactShadowSourceReceiptDigest {
        self.source_receipt_digest
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub const fn baseline(&self) -> &BranchPendingMapping<Hash> {
        &self.baseline
    }

    pub const fn baseline_timestamp(&self) -> CommitWriteTimestampUs {
        self.baseline_timestamp
    }

    pub const fn digest(&self) -> BranchExactWriterActivationDigest {
        self.digest
    }

    pub const fn slot(&self) -> BranchExactWriterSlot {
        self.slot
    }

    #[cfg(test)]
    fn test_fixture(
        authority: AuthorityScope,
        baseline: BranchPendingMapping<Hash>,
        baseline_timestamp: CommitWriteTimestampUs,
        shadow_verified_digest: BranchExactShadowVerifiedDigest,
    ) -> Self {
        let mut plan = Self {
            generation: BranchExactWriterGeneration::try_new(1).unwrap(),
            authority,
            schema_ready_digest: BranchExactSchemaReadyDigest::test_fixture(7),
            shadow_audit_slot: super::BranchExactShadowAuditSlot::from_persisted([6; 32]),
            shadow_verified_digest,
            source_receipt_digest: BranchExactShadowSourceReceiptDigest::from_persisted([8; 32]),
            dataset_digest: BranchExactBackfillDatasetDigest::try_new([9; 32]).unwrap(),
            baseline,
            baseline_timestamp,
            digest: BranchExactWriterActivationDigest([0; 32]),
            slot: BranchExactWriterSlot([0; 32]),
        };
        plan.digest = activation_digest(&plan);
        plan.slot = writer_slot(plan.baseline.canonical_chain().network_id(), authority);
        plan
    }
}

fn unique_artifact_tip<Hash: Q256BitHash>(
    artifact: &BranchExactBackfillArtifact<Hash>,
) -> Result<BranchPendingMapping<Hash>, BranchExactWriterLifecycleError> {
    let mut ordered = artifact
        .rows()
        .iter()
        .map(|row| *row.mapping())
        .collect::<Vec<_>>();
    ordered.sort_unstable_by_key(|mapping| {
        mapping
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get()
    });
    for pair in ordered.windows(2) {
        let previous_height = pair[0]
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        let next_height = pair[1]
            .canonical_chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        if next_height <= previous_height {
            return Err(BranchExactWriterLifecycleError::AmbiguousArtifactTip);
        }
        if pair[1].pending_id() <= pair[0].pending_id() {
            return Err(BranchExactWriterLifecycleError::ArtifactPendingNotMonotonic);
        }
    }
    ordered
        .last()
        .copied()
        .ok_or(BranchExactWriterLifecycleError::EmptyArtifact)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriteObservationDigest([u8; 32]);

impl BranchExactWriteObservationDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterActive<Hash> {
    watermark: BranchPendingMapping<Hash>,
    timestamp_high_water: CommitWriteTimestampUs,
    committed_writes: u64,
    last_intent: Option<BranchExactWriterIntentDigest>,
}

impl<Hash> BranchExactWriterActive<Hash> {
    pub const fn watermark(&self) -> &BranchPendingMapping<Hash> {
        &self.watermark
    }

    pub const fn timestamp_high_water(&self) -> CommitWriteTimestampUs {
        self.timestamp_high_water
    }

    pub const fn committed_writes(&self) -> u64 {
        self.committed_writes
    }

    pub const fn last_intent(&self) -> Option<BranchExactWriterIntentDigest> {
        self.last_intent
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterPrepared<Hash> {
    previous: BranchExactWriterActive<Hash>,
    intent: BranchExactDualWriteIntent<Hash>,
    timestamp_revision: AuthorityTimestampRevision,
    timestamp: CommitWriteTimestampUs,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> BranchExactWriterPrepared<Hash> {
    pub const fn previous(&self) -> &BranchExactWriterActive<Hash> {
        &self.previous
    }

    pub const fn intent(&self) -> &BranchExactDualWriteIntent<Hash> {
        &self.intent
    }

    pub const fn timestamp_revision(&self) -> AuthorityTimestampRevision {
        self.timestamp_revision
    }

    pub const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Reconstitutes the executable capability only from the exact durable
    /// allocator row. A persisted timestamp alone is never sufficient.
    pub fn reseal(
        &self,
        observed: ObservedAuthorityTimestampState,
    ) -> Result<SealedBranchExactDualWrite<Hash>, BranchExactWriterLifecycleError> {
        let AuthorityIntentObservation::Active(lease) =
            observed.observe_intent(self.intent.intent_digest().authority_intent())
        else {
            return Err(BranchExactWriterLifecycleError::TimestampLeaseNotActive);
        };
        if lease.active_revision() != self.timestamp_revision
            || lease.timestamp() != self.timestamp
        {
            return Err(BranchExactWriterLifecycleError::TimestampLeaseMismatch);
        }
        self.intent
            .clone()
            .attach_timestamp_lease(lease)
            .map_err(|_| BranchExactWriterLifecycleError::TimestampLeaseMismatch)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterVerified<Hash> {
    prepared: BranchExactWriterPrepared<Hash>,
    observation: BranchExactWriteObservationDigest,
    digest: [u8; 32],
}

impl<Hash> BranchExactWriterVerified<Hash> {
    pub const fn prepared(&self) -> &BranchExactWriterPrepared<Hash> {
        &self.prepared
    }

    pub const fn observation(&self) -> BranchExactWriteObservationDigest {
        self.observation
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactWriterBlockedDigest([u8; 32]);

impl BranchExactWriterBlockedDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn from_reason(reason: &str) -> Result<Self, BranchExactWriterLifecycleError> {
        if reason.is_empty() {
            return Err(BranchExactWriterLifecycleError::EmptyBlockedReason);
        }
        let mut hasher = Sha256::new();
        hasher.update(BLOCKED_DOMAIN);
        hasher.update((reason.len() as u64).to_be_bytes());
        hasher.update(reason.as_bytes());
        Ok(Self(hasher.finalize().into()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterState<Hash> {
    ActivationPrepared,
    Active(BranchExactWriterActive<Hash>),
    WritePrepared(BranchExactWriterPrepared<Hash>),
    WritesVerified(BranchExactWriterVerified<Hash>),
    Blocked(BranchExactWriterBlockedDigest),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredBranchExactWriterLifecycle<Hash> {
    revision: BranchExactWriterRevision,
    plan: BranchExactWriterActivationPlan<Hash>,
    state: BranchExactWriterState<Hash>,
}

impl<Hash: Q256BitHash> StoredBranchExactWriterLifecycle<Hash> {
    fn activation_prepared(plan: BranchExactWriterActivationPlan<Hash>) -> Self {
        Self {
            revision: BranchExactWriterRevision(0),
            plan,
            state: BranchExactWriterState::ActivationPrepared,
        }
    }

    pub const fn revision(&self) -> BranchExactWriterRevision {
        self.revision
    }

    pub const fn plan(&self) -> &BranchExactWriterActivationPlan<Hash> {
        &self.plan
    }

    pub const fn state(&self) -> &BranchExactWriterState<Hash> {
        &self.state
    }

    pub const fn slot(&self) -> BranchExactWriterSlot {
        self.plan.slot
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_stored(self)
    }

    pub fn decode_persisted(
        selected_slot: &[u8],
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let revision = BranchExactWriterRevision::try_new(
            u64::try_from(revision)
                .map_err(|_| BranchExactWriterLifecycleError::NegativeRevision(revision))?,
        )?;
        let decoded = decode_stored(payload)?;
        if decoded.revision != revision
            || selected_slot != decoded.slot().as_bytes()
            || decoded.to_canonical_bytes() != payload
        {
            return Err(BranchExactWriterLifecycleError::PersistedIdentityMismatch);
        }
        Ok(decoded)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterBootstrap<Hash> {
    candidate: StoredBranchExactWriterLifecycle<Hash>,
}

impl<Hash: Q256BitHash> BranchExactWriterBootstrap<Hash> {
    pub fn new(plan: BranchExactWriterActivationPlan<Hash>) -> Self {
        Self {
            candidate: StoredBranchExactWriterLifecycle::activation_prepared(plan),
        }
    }

    pub const fn candidate(&self) -> &StoredBranchExactWriterLifecycle<Hash> {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactWriterCas<Hash> {
    expected: StoredBranchExactWriterLifecycle<Hash>,
    candidate: StoredBranchExactWriterLifecycle<Hash>,
}

impl<Hash: Q256BitHash> SealedBranchExactWriterCas<Hash> {
    pub fn activate(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        consumed: &super::BranchExactShadowConsumedReceipt,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        if !matches!(expected.state, BranchExactWriterState::ActivationPrepared) {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        }
        if consumed.verified().digest() != expected.plan.shadow_verified_digest
            || consumed.writer_activation_digest() != expected.plan.digest
        {
            return Err(BranchExactWriterLifecycleError::ShadowConsumptionMismatch);
        }
        let active = BranchExactWriterActive {
            watermark: *expected.plan.baseline(),
            timestamp_high_water: expected.plan.baseline_timestamp(),
            committed_writes: 0,
            last_intent: None,
        };
        Self::transition(expected, BranchExactWriterState::Active(active))
    }

    pub fn prepare_write(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let BranchExactWriterState::Active(active) = &expected.state else {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        };
        let intent = sealed.intent();
        if intent.authority() != expected.plan.authority
            || intent.predecessor() != active.watermark()
            || sealed.write_timestamp() <= active.timestamp_high_water()
        {
            return Err(BranchExactWriterLifecycleError::WriterContinuityMismatch);
        }
        let prepared = BranchExactWriterPrepared {
            previous: active.clone(),
            intent: intent.clone(),
            timestamp_revision: sealed.lease().active_revision(),
            timestamp: sealed.write_timestamp(),
            digest: prepared_digest(
                active,
                intent,
                sealed.lease().active_revision(),
                sealed.write_timestamp(),
            ),
        };
        Self::transition(expected, BranchExactWriterState::WritePrepared(prepared))
    }

    pub(crate) fn verify_writes(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        observation: &super::branch_exact_dual_write_executor::BranchExactVerifiedWriteObservation,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let BranchExactWriterState::WritePrepared(prepared) = &expected.state else {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        };
        if !observation.matches_prepared(prepared) {
            return Err(BranchExactWriterLifecycleError::ObservationIdentityMismatch);
        }
        let observation = BranchExactWriteObservationDigest(observation.digest());
        let verified = BranchExactWriterVerified {
            prepared: prepared.clone(),
            observation,
            digest: verified_digest(prepared, observation),
        };
        Self::transition(expected, BranchExactWriterState::WritesVerified(verified))
    }

    pub fn commit_published(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        published: &psy_data::protocol::canonical_chain::CanonicalChainRef<Hash>,
        timestamp_state: ObservedAuthorityTimestampState,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let BranchExactWriterState::WritesVerified(verified) = &expected.state else {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        };
        let prepared = verified.prepared();
        if prepared.intent().candidate().canonical_chain() != published {
            return Err(BranchExactWriterLifecycleError::PublishedHeadMismatch);
        }
        match timestamp_state
            .observe_intent(prepared.intent().intent_digest().authority_intent())
        {
            AuthorityIntentObservation::Completed { timestamp, revision }
                if timestamp == prepared.timestamp()
                    && revision.get()
                        == prepared
                            .timestamp_revision()
                            .get()
                            .checked_add(1)
                            .ok_or(BranchExactWriterLifecycleError::RevisionOverflow)? => {}
            _ => return Err(BranchExactWriterLifecycleError::TimestampLeaseNotCompleted),
        }
        let active = BranchExactWriterActive {
            watermark: *prepared.intent().candidate(),
            timestamp_high_water: prepared.timestamp(),
            committed_writes: prepared
                .previous()
                .committed_writes()
                .checked_add(1)
                .ok_or(BranchExactWriterLifecycleError::CommittedWritesOverflow)?,
            last_intent: Some(BranchExactWriterIntentDigest::from_intent(
                prepared.intent().intent_digest(),
            )),
        };
        Self::transition(expected, BranchExactWriterState::Active(active))
    }

    pub fn block(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        reason: BranchExactWriterBlockedDigest,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        if matches!(expected.state, BranchExactWriterState::Blocked(_)) {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        }
        Self::transition(expected, BranchExactWriterState::Blocked(reason))
    }

    fn transition(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        state: BranchExactWriterState<Hash>,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        Ok(Self {
            expected: expected.clone(),
            candidate: StoredBranchExactWriterLifecycle {
                revision: expected.revision.next()?,
                plan: expected.plan.clone(),
                state,
            },
        })
    }

    pub const fn expected(&self) -> &StoredBranchExactWriterLifecycle<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactWriterLifecycle<Hash> {
        &self.candidate
    }
}

fn activation_digest<Hash: Q256BitHash>(
    plan: &BranchExactWriterActivationPlan<Hash>,
) -> BranchExactWriterActivationDigest {
    let mut hasher = Sha256::new();
    hasher.update(PLAN_DOMAIN);
    hasher.update(plan.generation.get().to_be_bytes());
    encode_authority(plan.authority, &mut hasher);
    hasher.update(plan.schema_ready_digest.as_bytes());
    hasher.update(plan.shadow_audit_slot.as_bytes());
    hasher.update(plan.shadow_verified_digest.as_bytes());
    hasher.update(plan.source_receipt_digest.as_bytes());
    hasher.update(plan.dataset_digest.as_bytes());
    hasher.update(plan.baseline.canonical_chain_bytes());
    hasher.update(plan.baseline.pending_id().get().to_be_bytes());
    hasher.update(plan.baseline_timestamp.as_i64().to_be_bytes());
    BranchExactWriterActivationDigest(hasher.finalize().into())
}

fn writer_slot(
    network: psy_data::protocol::canonical_chain::NetworkId,
    authority: AuthorityScope,
) -> BranchExactWriterSlot {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(network.chain_id().to_be_bytes());
    encode_authority(authority, &mut hasher);
    BranchExactWriterSlot(hasher.finalize().into())
}

fn prepared_digest<Hash: Q256BitHash>(
    active: &BranchExactWriterActive<Hash>,
    intent: &BranchExactDualWriteIntent<Hash>,
    revision: AuthorityTimestampRevision,
    timestamp: CommitWriteTimestampUs,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DOMAIN);
    encode_active(active, &mut hasher);
    hasher.update((intent.to_canonical_bytes().len() as u64).to_be_bytes());
    hasher.update(intent.to_canonical_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(timestamp.as_i64().to_be_bytes());
    hasher.finalize().into()
}

fn verified_digest<Hash: Q256BitHash>(
    prepared: &BranchExactWriterPrepared<Hash>,
    observation: BranchExactWriteObservationDigest,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(VERIFIED_DOMAIN);
    hasher.update(prepared.digest);
    hasher.update(observation.as_bytes());
    hasher.finalize().into()
}

fn encode_authority(authority: AuthorityScope, hasher: &mut Sha256) {
    match authority {
        AuthorityScope::Coordinator => hasher.update([1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

fn encode_mapping<Hash: Q256BitHash>(mapping: &BranchPendingMapping<Hash>, out: &mut Vec<u8>) {
    out.extend_from_slice(&mapping.canonical_chain_bytes());
    out.extend_from_slice(&mapping.pending_id().get().to_be_bytes());
}

fn encode_active<Hash: Q256BitHash>(active: &BranchExactWriterActive<Hash>, hasher: &mut Sha256) {
    hasher.update(active.watermark.canonical_chain_bytes());
    hasher.update(active.watermark.pending_id().get().to_be_bytes());
    hasher.update(active.timestamp_high_water.as_i64().to_be_bytes());
    hasher.update(active.committed_writes.to_be_bytes());
    match active.last_intent {
        None => hasher.update([0]),
        Some(digest) => {
            hasher.update([1]);
            hasher.update(digest.as_bytes());
        }
    }
}

fn encode_plan<Hash: Q256BitHash>(plan: &BranchExactWriterActivationPlan<Hash>, out: &mut Vec<u8>) {
    out.extend_from_slice(&plan.generation.get().to_be_bytes());
    match plan.authority {
        AuthorityScope::Coordinator => out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
    out.extend_from_slice(plan.schema_ready_digest.as_bytes());
    out.extend_from_slice(plan.shadow_audit_slot.as_bytes());
    out.extend_from_slice(plan.shadow_verified_digest.as_bytes());
    out.extend_from_slice(plan.source_receipt_digest.as_bytes());
    out.extend_from_slice(plan.dataset_digest.as_bytes());
    encode_mapping(&plan.baseline, out);
    out.extend_from_slice(&plan.baseline_timestamp.as_i64().to_be_bytes());
    out.extend_from_slice(plan.digest.as_bytes());
    out.extend_from_slice(plan.slot.as_bytes());
}

fn encode_active_bytes<Hash: Q256BitHash>(active: &BranchExactWriterActive<Hash>, out: &mut Vec<u8>) {
    encode_mapping(&active.watermark, out);
    out.extend_from_slice(&active.timestamp_high_water.as_i64().to_be_bytes());
    out.extend_from_slice(&active.committed_writes.to_be_bytes());
    match active.last_intent {
        None => out.push(0),
        Some(digest) => {
            out.push(1);
            out.extend_from_slice(digest.as_bytes());
        }
    }
}

fn encode_prepared<Hash: Q256BitHash>(prepared: &BranchExactWriterPrepared<Hash>, out: &mut Vec<u8>) {
    encode_active_bytes(&prepared.previous, out);
    out.extend_from_slice(&(prepared.intent.to_canonical_bytes().len() as u32).to_be_bytes());
    out.extend_from_slice(prepared.intent.to_canonical_bytes());
    out.extend_from_slice(&prepared.timestamp_revision.get().to_be_bytes());
    out.extend_from_slice(&prepared.timestamp.as_i64().to_be_bytes());
    out.extend_from_slice(&prepared.digest);
}

fn encode_stored<Hash: Q256BitHash>(stored: &StoredBranchExactWriterLifecycle<Hash>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&stored.revision.get().to_be_bytes());
    encode_plan(&stored.plan, &mut out);
    match &stored.state {
        BranchExactWriterState::ActivationPrepared => out.push(1),
        BranchExactWriterState::Active(active) => {
            out.push(2);
            encode_active_bytes(active, &mut out);
        }
        BranchExactWriterState::WritePrepared(prepared) => {
            out.push(3);
            encode_prepared(prepared, &mut out);
        }
        BranchExactWriterState::WritesVerified(verified) => {
            out.push(4);
            encode_prepared(&verified.prepared, &mut out);
            out.extend_from_slice(verified.observation.as_bytes());
            out.extend_from_slice(&verified.digest);
        }
        BranchExactWriterState::Blocked(reason) => {
            out.push(5);
            out.extend_from_slice(reason.as_bytes());
        }
    }
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hasher.update(&out);
    out.extend_from_slice(&hasher.finalize());
    out
}

fn decode_stored<Hash: Q256BitHash>(
    bytes: &[u8],
) -> Result<StoredBranchExactWriterLifecycle<Hash>, BranchExactWriterLifecycleError> {
    let body_len = bytes
        .len()
        .checked_sub(32)
        .ok_or(BranchExactWriterLifecycleError::TruncatedPayload)?;
    let (body, encoded_digest) = bytes.split_at(body_len);
    let mut hasher = Sha256::new();
    hasher.update(STATE_DIGEST_DOMAIN);
    hasher.update(body);
    let actual_digest: [u8; 32] = hasher.finalize().into();
    if actual_digest.as_slice() != encoded_digest {
        return Err(BranchExactWriterLifecycleError::StateDigestMismatch);
    }
    let mut decoder = Decoder::new(body);
    if decoder.take(8)? != MAGIC {
        return Err(BranchExactWriterLifecycleError::InvalidMagic);
    }
    let version = decoder.u16()?;
    if version != CODEC_VERSION {
        return Err(BranchExactWriterLifecycleError::UnknownCodecVersion(version));
    }
    let revision = BranchExactWriterRevision::try_new(decoder.u64()?)?;
    let plan = decode_plan(&mut decoder)?;
    let state = match decoder.u8()? {
        1 => BranchExactWriterState::ActivationPrepared,
        2 => BranchExactWriterState::Active(decode_active(&mut decoder)?),
        3 => BranchExactWriterState::WritePrepared(decode_prepared(&mut decoder, &plan)?),
        4 => {
            let prepared = decode_prepared(&mut decoder, &plan)?;
            let observation = BranchExactWriteObservationDigest(decoder.array32()?);
            if observation.0 == [0; 32] {
                return Err(BranchExactWriterLifecycleError::EmptyObservationDigest);
            }
            let digest = decoder.array32()?;
            if digest != verified_digest(&prepared, observation) {
                return Err(BranchExactWriterLifecycleError::VerifiedDigestMismatch);
            }
            BranchExactWriterState::WritesVerified(BranchExactWriterVerified {
                prepared,
                observation,
                digest,
            })
        }
        5 => BranchExactWriterState::Blocked(BranchExactWriterBlockedDigest(decoder.array32()?)),
        kind => return Err(BranchExactWriterLifecycleError::UnknownStateKind(kind)),
    };
    if !decoder.is_done() {
        return Err(BranchExactWriterLifecycleError::TrailingBytes);
    }
    if (revision.get() == 0 && !matches!(state, BranchExactWriterState::ActivationPrepared))
        || (revision.get() > 0 && matches!(state, BranchExactWriterState::ActivationPrepared))
    {
        return Err(BranchExactWriterLifecycleError::RevisionStateMismatch);
    }
    Ok(StoredBranchExactWriterLifecycle {
        revision,
        plan,
        state,
    })
}

fn decode_plan<Hash: Q256BitHash>(
    decoder: &mut Decoder<'_>,
) -> Result<BranchExactWriterActivationPlan<Hash>, BranchExactWriterLifecycleError> {
    let generation = BranchExactWriterGeneration::try_new(decoder.u64()?)?;
    let authority = decoder.authority()?;
    let schema_ready_digest = BranchExactSchemaReadyDigest::from_persisted(decoder.array32()?);
    let shadow_audit_slot = super::BranchExactShadowAuditSlot::from_persisted(decoder.array32()?);
    let shadow_verified_digest = BranchExactShadowVerifiedDigest::from_persisted(decoder.array32()?);
    let source_receipt_digest = BranchExactShadowSourceReceiptDigest::from_persisted(decoder.array32()?);
    let dataset_digest = BranchExactBackfillDatasetDigest::try_new(decoder.array32()?)
        .map_err(|_| BranchExactWriterLifecycleError::ActivationDigestMismatch)?;
    let baseline = decoder.mapping()?;
    let baseline_timestamp = CommitWriteTimestampUs::try_from_i128(decoder.i64()? as i128)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let digest = BranchExactWriterActivationDigest(decoder.array32()?);
    let slot = BranchExactWriterSlot(decoder.array32()?);
    let plan = BranchExactWriterActivationPlan {
        generation,
        authority,
        schema_ready_digest,
        shadow_audit_slot,
        shadow_verified_digest,
        source_receipt_digest,
        dataset_digest,
        baseline,
        baseline_timestamp,
        digest,
        slot,
    };
    if plan.digest != activation_digest(&plan)
        || plan.slot
            != writer_slot(plan.baseline.canonical_chain().network_id(), authority)
    {
        return Err(BranchExactWriterLifecycleError::ActivationDigestMismatch);
    }
    Ok(plan)
}

fn decode_active<Hash: Q256BitHash>(
    decoder: &mut Decoder<'_>,
) -> Result<BranchExactWriterActive<Hash>, BranchExactWriterLifecycleError> {
    let watermark = decoder.mapping()?;
    let timestamp_high_water = CommitWriteTimestampUs::try_from_i128(decoder.i64()? as i128)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let committed_writes = decoder.u64()?;
    let last_intent = match decoder.u8()? {
        0 => None,
        1 => Some(BranchExactWriterIntentDigest(decoder.array32()?)),
        value => return Err(BranchExactWriterLifecycleError::InvalidPresence(value)),
    };
    Ok(BranchExactWriterActive {
        watermark,
        timestamp_high_water,
        committed_writes,
        last_intent,
    })
}

fn decode_prepared<Hash: Q256BitHash>(
    decoder: &mut Decoder<'_>,
    plan: &BranchExactWriterActivationPlan<Hash>,
) -> Result<BranchExactWriterPrepared<Hash>, BranchExactWriterLifecycleError> {
    let previous = decode_active(decoder)?;
    let intent_len = decoder.u32()? as usize;
    let intent = BranchExactDualWriteIntent::decode_persisted(decoder.take(intent_len)?)
        .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))?;
    let timestamp_revision = AuthorityTimestampRevision::try_new(decoder.u64()?)
        .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))?;
    let timestamp = CommitWriteTimestampUs::try_from_i128(decoder.i64()? as i128)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let digest = decoder.array32()?;
    if intent.authority() != plan.authority
        || intent.predecessor() != previous.watermark()
        || timestamp <= previous.timestamp_high_water()
        || digest != prepared_digest(&previous, &intent, timestamp_revision, timestamp)
    {
        return Err(BranchExactWriterLifecycleError::PreparedDigestMismatch);
    }
    Ok(BranchExactWriterPrepared {
        previous,
        intent,
        timestamp_revision,
        timestamp,
        digest,
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BranchExactWriterLifecycleError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BranchExactWriterLifecycleError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactWriterLifecycleError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, BranchExactWriterLifecycleError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, BranchExactWriterLifecycleError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, BranchExactWriterLifecycleError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, BranchExactWriterLifecycleError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, BranchExactWriterLifecycleError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], BranchExactWriterLifecycleError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn authority(&mut self) -> Result<AuthorityScope, BranchExactWriterLifecycleError> {
        match self.u8()? {
            1 => {
                if self.take(6)? != [0; 6] {
                    return Err(BranchExactWriterLifecycleError::InvalidAuthorityPadding);
                }
                Ok(AuthorityScope::Coordinator)
            }
            2 => Ok(AuthorityScope::Realm {
                realm_id: self.u32()?,
                realm_sub_id: self.u16()?,
            }),
            value => Err(BranchExactWriterLifecycleError::UnknownAuthority(value)),
        }
    }

    fn mapping<Hash: Q256BitHash>(
        &mut self,
    ) -> Result<BranchPendingMapping<Hash>, BranchExactWriterLifecycleError> {
        let canonical = self.take(BRANCH_PENDING_CANONICAL_REF_LEN)?;
        let pending = UniquePendingId::try_new(self.u64()?)
            .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))?;
        BranchPendingMapping::from_canonical_chain_bytes(canonical, pending)
            .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))
    }

    const fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactWriterLifecycleError {
    GenerationOutOfRange(u64),
    RevisionOutOfRange(u64),
    RevisionOverflow,
    NegativeRevision(i64),
    AuthorityOrKeyspaceMismatch,
    SourceEvidenceMismatch,
    ShadowEvidenceMismatch,
    ShadowConsumptionMismatch,
    BackfillEvidenceMismatch,
    MissingBackfillTimestamp,
    TimestampAllocatorNotReady,
    ArtifactOutsideFrozenHead,
    CoordinatorTipMismatch,
    AmbiguousArtifactTip,
    ArtifactPendingNotMonotonic,
    EmptyArtifact,
    EmptyObservationDigest,
    ObservationIdentityMismatch,
    EmptyBlockedReason,
    IllegalTransition,
    WriterContinuityMismatch,
    TimestampLeaseNotActive,
    TimestampLeaseMismatch,
    TimestampLeaseNotCompleted,
    PublishedHeadMismatch,
    CommittedWritesOverflow,
    InvalidMagic,
    UnknownCodecVersion(u16),
    UnknownStateKind(u8),
    UnknownAuthority(u8),
    InvalidAuthorityPadding,
    InvalidPresence(u8),
    TruncatedPayload,
    TrailingBytes,
    TimestampOutOfRange,
    ActivationDigestMismatch,
    PreparedDigestMismatch,
    VerifiedDigestMismatch,
    StateDigestMismatch,
    RevisionStateMismatch,
    PersistedIdentityMismatch,
    Intent(String),
}

impl fmt::Display for BranchExactWriterLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactWriterLifecycleError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        authority_commit::{
            AuthorityClockSampleUs, AuthorityTimestampBootstrap,
            AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        },
        branch_exact_dual_write::BranchExactDualWriteIntent,
        typed::ProcCheckpointUniqueId,
    };

    use super::*;
    use crate::rollback::{
        BranchExactBackfillArtifactRow, BranchExactBackfillDatasetDigest,
        BranchExactLegacyExportReceipt,
        BranchExactSchemaReadyDigest, BranchExactShadowAuditBootstrap,
        BranchExactShadowAuditGeneration, BranchExactShadowAuditObservation,
        BranchExactShadowAuditPlan, BranchExactShadowAuditState,
        BranchExactShadowVerifiedReceipt, SealedBranchExactShadowAuditCas,
    };

    fn chain(epoch: u64, height: u64, seed: u64) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(height),
                CheckpointHash::from_last_chain_hash(PHash::from_values(
                    seed,
                    seed + 1,
                    seed + 2,
                    seed + 3,
                )),
            ),
        )
    }

    fn mapping(height: u64, pending: u64) -> BranchPendingMapping<PHash> {
        BranchPendingMapping::new(
            chain(0, height, height),
            UniquePendingId::try_new(pending).unwrap(),
        )
    }

    fn verified_shadow() -> BranchExactShadowVerifiedReceipt {
        let dataset = BranchExactBackfillDatasetDigest::try_new([6; 32]).unwrap();
        let ready = BranchExactSchemaReadyDigest::test_fixture(5);
        let source = BranchExactLegacyExportReceipt::test_fixture(dataset, 10, 0);
        let plan = BranchExactShadowAuditPlan::try_new(
            BranchExactShadowAuditGeneration::try_new(1).unwrap(),
            ready,
            dataset,
            &source,
        )
        .unwrap();
        let observation = BranchExactShadowAuditObservation::test_fixture(
            ready, dataset, 10, 0,
        );
        BranchExactShadowVerifiedReceipt::try_new(plan, &observation).unwrap()
    }

    fn consumed_shadow(
        verified: BranchExactShadowVerifiedReceipt,
        activation: BranchExactWriterActivationDigest,
    ) -> crate::rollback::BranchExactShadowConsumedReceipt {
        let comparing = BranchExactShadowAuditBootstrap::new(verified.plan().clone());
        let verified_cas = SealedBranchExactShadowAuditCas::verify(
            comparing.candidate(),
            verified,
        )
        .unwrap();
        let consume = SealedBranchExactShadowAuditCas::consume(
            verified_cas.candidate(),
            activation,
        )
        .unwrap();
        let BranchExactShadowAuditState::Consumed(receipt) = consume.candidate().state() else {
            panic!("consume transition must produce consumed evidence")
        };
        receipt.clone()
    }

    fn timestamp_reservation(
        intent: &BranchExactDualWriteIntent<PHash>,
    ) -> (
        psy_node_core::store::authority_commit::StoredAuthorityTimestampState,
        psy_node_core::store::authority_commit::AuthorityTimestampLease,
    ) {
        let key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            intent.authority(),
        );
        let idle = AuthorityTimestampBootstrap::new(
            key,
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        )
        .candidate();
        let reservation = idle
            .seal_reservation(
                key,
                intent.intent_digest().authority_intent(),
                AuthorityClockSampleUs::try_from_i128(2_000).unwrap(),
            )
            .unwrap();
        (reservation.candidate(), reservation.lease())
    }

    #[test]
    fn consumed_shadow_is_required_before_activation() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
        );
        let bootstrap = BranchExactWriterBootstrap::new(plan.clone());
        let wrong_plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(11, 101),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
        );
        let wrong_consumed = consumed_shadow(shadow.clone(), wrong_plan.digest());
        assert_eq!(
            SealedBranchExactWriterCas::activate(bootstrap.candidate(), &wrong_consumed),
            Err(BranchExactWriterLifecycleError::ShadowConsumptionMismatch)
        );

        let consumed = consumed_shadow(shadow, plan.digest());
        let activated = SealedBranchExactWriterCas::activate(
            bootstrap.candidate(),
            &consumed,
        )
        .unwrap();
        assert!(matches!(activated.candidate().state(), BranchExactWriterState::Active(_)));
    }

    #[test]
    fn write_lifecycle_is_continuous_timestamp_bound_and_round_trips() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
        );
        let consumed = consumed_shadow(shadow, plan.digest());
        let bootstrap = BranchExactWriterBootstrap::new(plan);
        let active = SealedBranchExactWriterCas::activate(
            bootstrap.candidate(),
            &consumed,
        )
        .unwrap();

        let intent = BranchExactDualWriteIntent::try_coordinator(
            mapping(10, 100),
            mapping(11, 101),
            ProcCheckpointUniqueId::from_u128(9001),
        )
        .unwrap();
        let (allocator_active, lease) = timestamp_reservation(&intent);
        let sealed = intent.clone().attach_timestamp_lease(lease).unwrap();
        let prepared = SealedBranchExactWriterCas::prepare_write(
            active.candidate(),
            &sealed,
        )
        .unwrap();
        let BranchExactWriterState::WritePrepared(prepared_state) = prepared.candidate().state() else {
            panic!("expected prepared state")
        };
        let observed_active = ObservedAuthorityTimestampState::from_selected_row(
            lease.key(),
            allocator_active,
        );
        assert_eq!(prepared_state.reseal(observed_active).unwrap(), sealed);

        let bytes = prepared.candidate().to_canonical_bytes();
        let decoded = StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
            prepared.candidate().slot().as_bytes(),
            prepared.candidate().revision().as_i64(),
            &bytes,
        )
        .unwrap();
        assert_eq!(&decoded, prepared.candidate());

        let observation = crate::rollback::branch_exact_dual_write_executor::BranchExactVerifiedWriteObservation::test_fixture(prepared_state);
        let verified = SealedBranchExactWriterCas::verify_writes(
            prepared.candidate(),
            &observation,
        )
        .unwrap();
        let completed = allocator_active
            .seal_completion(lease.key(), lease)
            .unwrap()
            .candidate();
        let committed = SealedBranchExactWriterCas::commit_published(
            verified.candidate(),
            intent.candidate().canonical_chain(),
            ObservedAuthorityTimestampState::from_selected_row(lease.key(), completed),
        )
        .unwrap();
        let BranchExactWriterState::Active(active) = committed.candidate().state() else {
            panic!("expected active watermark")
        };
        assert_eq!(active.watermark(), intent.candidate());
        assert_eq!(active.timestamp_high_water(), lease.timestamp());
        assert_eq!(active.committed_writes(), 1);
    }

    #[test]
    fn wrong_predecessor_publish_and_allocator_state_fail_closed() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
        );
        let consumed = consumed_shadow(shadow, plan.digest());
        let bootstrap = BranchExactWriterBootstrap::new(plan);
        let active = SealedBranchExactWriterCas::activate(
            bootstrap.candidate(),
            &consumed,
        )
        .unwrap();
        let wrong = BranchExactDualWriteIntent::try_coordinator(
            mapping(9, 99),
            mapping(10, 100),
            ProcCheckpointUniqueId::from_u128(1),
        )
        .unwrap();
        let (_, wrong_lease) = timestamp_reservation(&wrong);
        let wrong = wrong.attach_timestamp_lease(wrong_lease).unwrap();
        assert_eq!(
            SealedBranchExactWriterCas::prepare_write(active.candidate(), &wrong),
            Err(BranchExactWriterLifecycleError::WriterContinuityMismatch)
        );
    }

    #[test]
    fn blocked_is_terminal_and_codec_tamper_fails_closed() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
        );
        let consumed = consumed_shadow(shadow, plan.digest());
        let bootstrap = BranchExactWriterBootstrap::new(plan);
        let active = SealedBranchExactWriterCas::activate(
            bootstrap.candidate(),
            &consumed,
        )
        .unwrap();
        let blocked = SealedBranchExactWriterCas::block(
            active.candidate(),
            BranchExactWriterBlockedDigest::from_reason("readback mismatch").unwrap(),
        )
        .unwrap();
        assert_eq!(
            SealedBranchExactWriterCas::block(
                blocked.candidate(),
                BranchExactWriterBlockedDigest::from_reason("again").unwrap(),
            ),
            Err(BranchExactWriterLifecycleError::IllegalTransition)
        );
        let mut bytes = blocked.candidate().to_canonical_bytes();
        *bytes.last_mut().unwrap() ^= 1;
        assert!(StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
            blocked.candidate().slot().as_bytes(),
            blocked.candidate().revision().as_i64(),
            &bytes,
        )
        .is_err());
    }

    #[test]
    fn writer_slot_is_stable_per_network_authority_and_separates_realms() {
        let shadow = verified_shadow();
        let timestamp = CommitWriteTimestampUs::try_from_i128(1_000).unwrap();
        let coordinator = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            timestamp,
            shadow.digest(),
        );
        let same = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(11, 101),
            timestamp,
            shadow.digest(),
        );
        let realm = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Realm { realm_id: 1, realm_sub_id: 0 },
            mapping(10, 100),
            timestamp,
            shadow.digest(),
        );
        assert_eq!(coordinator.slot(), same.slot());
        assert_ne!(coordinator.slot(), realm.slot());
    }

    #[test]
    fn activation_frontier_rejects_same_height_and_non_monotonic_pending() {
        let row = |height, seed, pending| {
            BranchExactBackfillArtifactRow::try_new(
                BranchPendingMapping::new(
                    chain(0, height, seed),
                    UniquePendingId::try_new(pending).unwrap(),
                ),
                None,
            )
            .unwrap()
        };

        let same_height = BranchExactBackfillArtifact::try_new(
            AuthorityScope::Coordinator,
            vec![row(10, 10, 100), row(10, 20, 101)],
        )
        .unwrap();
        assert_eq!(
            unique_artifact_tip(&same_height),
            Err(BranchExactWriterLifecycleError::AmbiguousArtifactTip)
        );

        let pending_goes_backwards = BranchExactBackfillArtifact::try_new(
            AuthorityScope::Coordinator,
            vec![row(10, 10, 101), row(11, 11, 100)],
        )
        .unwrap();
        assert_eq!(
            unique_artifact_tip(&pending_goes_backwards),
            Err(BranchExactWriterLifecycleError::ArtifactPendingNotMonotonic)
        );

        let valid = BranchExactBackfillArtifact::try_new(
            AuthorityScope::Coordinator,
            vec![row(10, 10, 100), row(11, 11, 101)],
        )
        .unwrap();
        assert_eq!(unique_artifact_tip(&valid).unwrap(), mapping(11, 101));
    }
}
