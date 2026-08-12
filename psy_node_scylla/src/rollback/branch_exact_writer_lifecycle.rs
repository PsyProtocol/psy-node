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
        AuthorityClockSampleUs, AuthorityIntentObservation, AuthorityTimestampKey,
        AuthorityTimestampPhase,
        AuthorityTimestampRevision, ObservedAuthorityTimestampState,
        SealedAuthorityTimestampReservation, StoredAuthorityTimestampState,
        AUTHORITY_TIMESTAMP_STATE_V1_LEN,
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
use psy_node_core::queue::realm_user_update_verifier_profile::{
    BoundRealmUserUpdateVerifier, RealmUserUpdateVerifierProfileId,
    RealmUserUpdateVerifierRegistry,
};
#[cfg(test)]
use psy_node_core::store::authority_commit::{
    AuthorityTimestampBootstrap, AuthorityTimestampBootstrapReason,
};
use sha2::{Digest, Sha256};

use super::{
    source_receipt_digest, BranchExactBackfillArtifact,
    BranchExactBackfillDatasetDigest, BranchExactFrozenLegacyExportPermit,
    BranchExactBackfillVerifiedReceipt, BranchExactLegacyExportReceipt,
    BranchExactSchemaReady,
    BranchExactSchemaReadyDigest, BranchExactShadowSourceReceiptDigest,
    BranchExactShadowVerifiedDigest, BranchExactShadowVerifiedReceipt,
    BranchExactWriterCutoverFence,
};

const MAGIC: [u8; 8] = *b"PSYBEXWL";
// v2 persisted the exact h16 BACKFILL_VERIFIED receipt. v3 additionally binds
// the complete allocator revision/phase/high-water in the activation plan and
// every Active state. v4 persists the exact h22e3 cutover fence in each
// managed WritePrepared/WritesVerified row. v5 binds an explicit verifier
// profile to every Realm activation; Coordinator activation records a typed
// NotApplicable value. Older rows cannot safely authorize durable proof
// recovery and are rejected.
const CODEC_VERSION: u16 = 5;
const PLAN_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-activation/v3";
const SLOT_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-slot/v1";
const PREPARED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-prepared/v2";
const VERIFIED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-verified/v2";
const BLOCKED_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-blocked/v1";
const STATE_DIGEST_DOMAIN: &[u8] = b"psy/rollback/branch-exact-writer-state/v2";

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

    pub fn try_from_hex(value: &str) -> Result<Self, BranchExactWriterLifecycleError> {
        let bytes = hex::decode(value)
            .map_err(|_| BranchExactWriterLifecycleError::InvalidActivationDigestHex)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| BranchExactWriterLifecycleError::InvalidActivationDigestHex)?;
        if bytes == [0; 32] {
            return Err(BranchExactWriterLifecycleError::InvalidActivationDigestHex);
        }
        Ok(Self(bytes))
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

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum BranchExactWriterVerifierProfile {
    NotApplicable,
    Realm(RealmUserUpdateVerifierProfileId),
}

impl BranchExactWriterVerifierProfile {
    pub fn for_authority(
        authority: AuthorityScope,
        realm_profile: Option<RealmUserUpdateVerifierProfileId>,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        match (authority, realm_profile) {
            (AuthorityScope::Coordinator, None) => Ok(Self::NotApplicable),
            (AuthorityScope::Realm { .. }, Some(profile)) => Ok(Self::Realm(profile)),
            _ => Err(BranchExactWriterLifecycleError::VerifierProfileBindingMismatch),
        }
    }

    pub const fn realm_profile(self) -> Option<RealmUserUpdateVerifierProfileId> {
        match self {
            Self::NotApplicable => None,
            Self::Realm(profile) => Some(profile),
        }
    }
}

/// Evidence and baseline from which online dual-write may begin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactWriterActivationPlan<Hash> {
    generation: BranchExactWriterGeneration,
    authority: AuthorityScope,
    schema_ready_digest: BranchExactSchemaReadyDigest,
    backfill_receipt: BranchExactBackfillVerifiedReceipt,
    shadow_audit_slot: super::BranchExactShadowAuditSlot,
    shadow_verified_digest: BranchExactShadowVerifiedDigest,
    source_receipt_digest: BranchExactShadowSourceReceiptDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    baseline: BranchPendingMapping<Hash>,
    baseline_timestamp_state: StoredAuthorityTimestampState,
    verifier_profile: BranchExactWriterVerifierProfile,
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
        verifier_profile: BranchExactWriterVerifierProfile,
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
        if BranchExactWriterVerifierProfile::for_authority(
            authority,
            verifier_profile.realm_profile(),
        )? != verifier_profile
        {
            return Err(BranchExactWriterLifecycleError::VerifierProfileBindingMismatch);
        }

        let mut plan = Self {
            generation,
            authority,
            schema_ready_digest: view.digest(),
            backfill_receipt: backfill.clone(),
            shadow_audit_slot: shadow_plan.slot(),
            shadow_verified_digest: shadow.digest(),
            source_receipt_digest: source_receipt_digest(source),
            dataset_digest: artifact.dataset_digest(),
            baseline,
            baseline_timestamp_state: observed,
            verifier_profile,
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

    /// Exact durable evidence needed to re-run the h20 setup gate after a
    /// restart. Callers must still re-read h16 and inspect the live schema;
    /// possession of this receipt is not itself a readiness capability.
    pub const fn backfill_receipt(&self) -> &BranchExactBackfillVerifiedReceipt {
        &self.backfill_receipt
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
        self.baseline_timestamp_state.high_water()
    }

    pub const fn baseline_timestamp_state(&self) -> StoredAuthorityTimestampState {
        self.baseline_timestamp_state
    }

    pub const fn verifier_profile(&self) -> BranchExactWriterVerifierProfile {
        self.verifier_profile
    }

    pub fn resolve_realm_verifier<Verifier>(
        &self,
        registry: &RealmUserUpdateVerifierRegistry<Verifier>,
    ) -> Result<BoundRealmUserUpdateVerifier<Verifier>, BranchExactWriterLifecycleError> {
        let BranchExactWriterVerifierProfile::Realm(profile) = self.verifier_profile else {
            return Err(BranchExactWriterLifecycleError::VerifierProfileBindingMismatch);
        };
        registry
            .resolve(profile)
            .map_err(|_| BranchExactWriterLifecycleError::VerifierProfileUnavailable(profile))
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
        backfill_receipt: BranchExactBackfillVerifiedReceipt,
    ) -> Self {
        let dataset_digest = backfill_receipt.plan().dataset_digest();
        let mut plan = Self {
            generation: BranchExactWriterGeneration::try_new(1).unwrap(),
            authority,
            schema_ready_digest: BranchExactSchemaReadyDigest::test_fixture(7),
            backfill_receipt,
            shadow_audit_slot: super::BranchExactShadowAuditSlot::from_persisted([6; 32]),
            shadow_verified_digest,
            source_receipt_digest: BranchExactShadowSourceReceiptDigest::from_persisted([8; 32]),
            dataset_digest,
            baseline,
            baseline_timestamp_state: AuthorityTimestampBootstrap::new(
                AuthorityTimestampKey::new(
                    baseline.canonical_chain().network_id(),
                    authority,
                ),
                baseline_timestamp,
                AuthorityTimestampBootstrapReason::ControlledWriterCutover,
            )
            .candidate(),
            verifier_profile: match authority {
                AuthorityScope::Coordinator => BranchExactWriterVerifierProfile::NotApplicable,
                AuthorityScope::Realm { .. } => BranchExactWriterVerifierProfile::Realm(
                    RealmUserUpdateVerifierProfileId::try_from_persisted([0xA5; 32]).unwrap(),
                ),
            },
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
    timestamp_state: StoredAuthorityTimestampState,
    committed_writes: u64,
    last_intent: Option<BranchExactWriterIntentDigest>,
}

impl<Hash> BranchExactWriterActive<Hash> {
    pub const fn watermark(&self) -> &BranchPendingMapping<Hash> {
        &self.watermark
    }

    pub const fn timestamp_high_water(&self) -> CommitWriteTimestampUs {
        self.timestamp_state.high_water()
    }

    pub const fn timestamp_state(&self) -> StoredAuthorityTimestampState {
        self.timestamp_state
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
    timestamp_predecessor: StoredAuthorityTimestampState,
    cutover_fence: Option<BranchExactWriterCutoverFence>,
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

    pub const fn timestamp_predecessor(&self) -> StoredAuthorityTimestampState {
        self.timestamp_predecessor
    }

    pub const fn cutover_fence(&self) -> Option<&BranchExactWriterCutoverFence> {
        self.cutover_fence.as_ref()
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[cfg(test)]
    pub(super) fn test_fixture(
        intent: BranchExactDualWriteIntent<Hash>,
        timestamp: CommitWriteTimestampUs,
        cutover_fence: BranchExactWriterCutoverFence,
    ) -> Self {
        let predecessor_timestamp = CommitWriteTimestampUs::try_from_i128(
            i128::from(timestamp.as_i64()) - 1,
        )
        .expect("fixture timestamp predecessor");
        let timestamp_key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            intent.authority(),
        );
        let timestamp_predecessor = AuthorityTimestampBootstrap::new(
            timestamp_key,
            predecessor_timestamp,
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        )
        .candidate();
        let reservation = timestamp_predecessor
            .seal_reservation(
                timestamp_key,
                intent.intent_digest().authority_intent(),
                AuthorityClockSampleUs::try_from_i128(timestamp.as_i64() as i128)
                    .expect("fixture timestamp sample"),
            )
            .expect("fixture timestamp reservation");
        let previous = BranchExactWriterActive {
            watermark: *intent.predecessor(),
            timestamp_state: timestamp_predecessor,
            committed_writes: 0,
            last_intent: None,
        };
        let digest = prepared_digest(
            &previous,
            &intent,
            reservation.lease().active_revision(),
            timestamp,
            timestamp_predecessor,
            Some(&cutover_fence),
        );
        Self {
            previous,
            intent,
            timestamp_revision: reservation.lease().active_revision(),
            timestamp,
            timestamp_predecessor,
            cutover_fence: Some(cutover_fence),
            digest,
        }
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

    /// Recovers the intentional two-row ordering used by production wiring:
    /// the complete lifecycle `WritePrepared` row is persisted first, then the
    /// allocator reservation is applied. If a crash occurs between those
    /// LWTs, the stored timestamp/revision and complete intent deterministically
    /// reconstruct the *same* reservation; wall-clock movement is irrelevant.
    pub fn reconcile_timestamp_reservation(
        &self,
        observed: ObservedAuthorityTimestampState,
    ) -> Result<BranchExactTimestampReservationRecovery<Hash>, BranchExactWriterLifecycleError>
    {
        let intent_digest = self.intent.intent_digest().authority_intent();
        match observed.observe_intent(intent_digest) {
            AuthorityIntentObservation::Active(_) => self
                .reseal(observed)
                .map(BranchExactTimestampReservationRecovery::Active),
            AuthorityIntentObservation::Idle { .. } => {
                let state = observed.state();
                if state != self.timestamp_predecessor {
                    return Err(
                        BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch,
                    );
                }
                let sample = AuthorityClockSampleUs::try_from_i128(
                    self.timestamp.as_i64() as i128,
                )
                .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
                let reservation = state
                    .seal_reservation(observed.key(), intent_digest, sample)
                    .map_err(|_| {
                        BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch
                    })?;
                let lease = reservation.lease();
                if lease.active_revision() != self.timestamp_revision
                    || lease.timestamp() != self.timestamp
                {
                    return Err(
                        BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch,
                    );
                }
                let sealed = self
                    .intent
                    .clone()
                    .attach_timestamp_lease(lease)
                    .map_err(|_| BranchExactWriterLifecycleError::TimestampLeaseMismatch)?;
                Ok(BranchExactTimestampReservationRecovery::Apply {
                    reservation,
                    sealed,
                })
            }
            AuthorityIntentObservation::Completed { .. }
            | AuthorityIntentObservation::BlockedByActive { .. } => {
                Err(BranchExactWriterLifecycleError::TimestampLeaseNotActive)
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactTimestampReservationRecovery<Hash> {
    Active(SealedBranchExactDualWrite<Hash>),
    Apply {
        reservation: SealedAuthorityTimestampReservation,
        sealed: SealedBranchExactDualWrite<Hash>,
    },
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
            timestamp_state: expected.plan.baseline_timestamp_state(),
            committed_writes: 0,
            last_intent: None,
        };
        Self::transition(expected, BranchExactWriterState::Active(active))
    }

    pub fn prepare_write(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
        reservation: SealedAuthorityTimestampReservation,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        Self::prepare_write_inner(expected, sealed, reservation, None)
    }

    pub(crate) fn prepare_write_with_cutover(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
        reservation: SealedAuthorityTimestampReservation,
        cutover_fence: BranchExactWriterCutoverFence,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        Self::prepare_write_inner(
            expected,
            sealed,
            reservation,
            Some(cutover_fence),
        )
    }

    fn prepare_write_inner(
        expected: &StoredBranchExactWriterLifecycle<Hash>,
        sealed: &SealedBranchExactDualWrite<Hash>,
        reservation: SealedAuthorityTimestampReservation,
        cutover_fence: Option<BranchExactWriterCutoverFence>,
    ) -> Result<Self, BranchExactWriterLifecycleError> {
        let BranchExactWriterState::Active(active) = &expected.state else {
            return Err(BranchExactWriterLifecycleError::IllegalTransition);
        };
        let intent = sealed.intent();
        if intent.authority() != expected.plan.authority
            || intent.predecessor() != active.watermark()
            || sealed.write_timestamp() <= active.timestamp_high_water()
            || reservation.lease() != sealed.lease()
            || reservation.expected() != active.timestamp_state()
        {
            return Err(BranchExactWriterLifecycleError::WriterContinuityMismatch);
        }
        let digest = prepared_digest(
            active,
            intent,
            sealed.lease().active_revision(),
            sealed.write_timestamp(),
            reservation.expected(),
            cutover_fence.as_ref(),
        );
        let prepared = BranchExactWriterPrepared {
            previous: active.clone(),
            intent: intent.clone(),
            timestamp_revision: sealed.lease().active_revision(),
            timestamp: sealed.write_timestamp(),
            timestamp_predecessor: reservation.expected(),
            cutover_fence,
            digest,
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
        let expected_timestamp_key = AuthorityTimestampKey::new(
            published.network_id(),
            prepared.intent().authority(),
        );
        if timestamp_state.key() != expected_timestamp_key {
            return Err(BranchExactWriterLifecycleError::TimestampKeyMismatch);
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
            timestamp_state: timestamp_state.state(),
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
    hasher.update(plan.backfill_receipt.digest().as_bytes());
    hasher.update(plan.shadow_audit_slot.as_bytes());
    hasher.update(plan.shadow_verified_digest.as_bytes());
    hasher.update(plan.source_receipt_digest.as_bytes());
    hasher.update(plan.dataset_digest.as_bytes());
    hasher.update(plan.baseline.canonical_chain_bytes());
    hasher.update(plan.baseline.pending_id().get().to_be_bytes());
    hasher.update(plan.baseline_timestamp_state.revision().get().to_be_bytes());
    hasher.update(plan.baseline_timestamp_state.encode_canonical());
    encode_verifier_profile_hash(plan.verifier_profile, &mut hasher);
    BranchExactWriterActivationDigest(hasher.finalize().into())
}

fn encode_verifier_profile_hash(
    profile: BranchExactWriterVerifierProfile,
    hasher: &mut Sha256,
) {
    match profile {
        BranchExactWriterVerifierProfile::NotApplicable => hasher.update([0]),
        BranchExactWriterVerifierProfile::Realm(profile) => {
            hasher.update([1]);
            hasher.update(profile.as_bytes());
        }
    }
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
    timestamp_predecessor: StoredAuthorityTimestampState,
    cutover_fence: Option<&BranchExactWriterCutoverFence>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PREPARED_DOMAIN);
    encode_active(active, &mut hasher);
    hasher.update((intent.to_canonical_bytes().len() as u64).to_be_bytes());
    hasher.update(intent.to_canonical_bytes());
    hasher.update(revision.get().to_be_bytes());
    hasher.update(timestamp.as_i64().to_be_bytes());
    hasher.update(timestamp_predecessor.revision().get().to_be_bytes());
    hasher.update(timestamp_predecessor.encode_canonical());
    match cutover_fence {
        None => hasher.update([0]),
        Some(fence) => {
            hasher.update([1]);
            hasher.update(fence.encode_canonical());
        }
    }
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
    hasher.update(active.timestamp_state.revision().get().to_be_bytes());
    hasher.update(active.timestamp_state.encode_canonical());
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
    let receipt = plan.backfill_receipt.to_canonical_bytes();
    out.extend_from_slice(&(receipt.len() as u32).to_be_bytes());
    out.extend_from_slice(&receipt);
    out.extend_from_slice(plan.shadow_audit_slot.as_bytes());
    out.extend_from_slice(plan.shadow_verified_digest.as_bytes());
    out.extend_from_slice(plan.source_receipt_digest.as_bytes());
    out.extend_from_slice(plan.dataset_digest.as_bytes());
    encode_mapping(&plan.baseline, out);
    out.extend_from_slice(&plan.baseline_timestamp_state.revision().get().to_be_bytes());
    out.extend_from_slice(&plan.baseline_timestamp_state.encode_canonical());
    match plan.verifier_profile {
        BranchExactWriterVerifierProfile::NotApplicable => out.push(0),
        BranchExactWriterVerifierProfile::Realm(profile) => {
            out.push(1);
            out.extend_from_slice(profile.as_bytes());
        }
    }
    out.extend_from_slice(plan.digest.as_bytes());
    out.extend_from_slice(plan.slot.as_bytes());
}

fn encode_active_bytes<Hash: Q256BitHash>(active: &BranchExactWriterActive<Hash>, out: &mut Vec<u8>) {
    encode_mapping(&active.watermark, out);
    out.extend_from_slice(&active.timestamp_state.revision().get().to_be_bytes());
    out.extend_from_slice(&active.timestamp_state.encode_canonical());
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
    out.extend_from_slice(&prepared.timestamp_predecessor.revision().get().to_be_bytes());
    out.extend_from_slice(&prepared.timestamp_predecessor.encode_canonical());
    match &prepared.cutover_fence {
        None => out.push(0),
        Some(fence) => {
            out.push(1);
            out.extend_from_slice(&fence.encode_canonical());
        }
    }
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
        2 => BranchExactWriterState::Active(decode_active(&mut decoder, &plan)?),
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
    let receipt_len = decoder.u32()? as usize;
    let backfill_receipt = BranchExactBackfillVerifiedReceipt::decode_persisted(
        decoder.take(receipt_len)?,
    )
    .map_err(|error| BranchExactWriterLifecycleError::BackfillReceipt(error.to_string()))?;
    let shadow_audit_slot = super::BranchExactShadowAuditSlot::from_persisted(decoder.array32()?);
    let shadow_verified_digest = BranchExactShadowVerifiedDigest::from_persisted(decoder.array32()?);
    let source_receipt_digest = BranchExactShadowSourceReceiptDigest::from_persisted(decoder.array32()?);
    let dataset_digest = BranchExactBackfillDatasetDigest::try_new(decoder.array32()?)
        .map_err(|_| BranchExactWriterLifecycleError::ActivationDigestMismatch)?;
    let baseline = decoder.mapping()?;
    let baseline_timestamp_revision = decoder.u64()?;
    let baseline_timestamp_state = StoredAuthorityTimestampState::decode_persisted(
        i64::try_from(baseline_timestamp_revision)
            .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?,
        decoder.take(AUTHORITY_TIMESTAMP_STATE_V1_LEN)?,
    )
    .map_err(|_| BranchExactWriterLifecycleError::TimestampAllocatorNotReady)?;
    let verifier_profile = match decoder.u8()? {
        0 => BranchExactWriterVerifierProfile::NotApplicable,
        1 => BranchExactWriterVerifierProfile::Realm(
            RealmUserUpdateVerifierProfileId::try_from_persisted(decoder.array32()?)
                .map_err(|_| BranchExactWriterLifecycleError::VerifierProfileBindingMismatch)?,
        ),
        value => return Err(BranchExactWriterLifecycleError::InvalidPresence(value)),
    };
    let digest = BranchExactWriterActivationDigest(decoder.array32()?);
    let slot = BranchExactWriterSlot(decoder.array32()?);
    let plan = BranchExactWriterActivationPlan {
        generation,
        authority,
        schema_ready_digest,
        backfill_receipt,
        shadow_audit_slot,
        shadow_verified_digest,
        source_receipt_digest,
        dataset_digest,
        baseline,
        baseline_timestamp_state,
        verifier_profile,
        digest,
        slot,
    };
    if plan.backfill_receipt.plan().dataset_digest() != plan.dataset_digest
        || plan.backfill_receipt.plan().deployment().intent().authority() != authority
        || !matches!(
            plan.baseline_timestamp_state.phase(),
            AuthorityTimestampPhase::Idle { .. }
        )
        || plan
            .backfill_receipt
            .plan()
            .write_timestamp()
            .is_some_and(|timestamp| timestamp > plan.baseline_timestamp())
        || plan.digest != activation_digest(&plan)
        || BranchExactWriterVerifierProfile::for_authority(
            authority,
            plan.verifier_profile.realm_profile(),
        )? != plan.verifier_profile
        || plan.slot
            != writer_slot(plan.baseline.canonical_chain().network_id(), authority)
    {
        return Err(BranchExactWriterLifecycleError::ActivationDigestMismatch);
    }
    Ok(plan)
}

fn decode_active<Hash: Q256BitHash>(
    decoder: &mut Decoder<'_>,
    plan: &BranchExactWriterActivationPlan<Hash>,
) -> Result<BranchExactWriterActive<Hash>, BranchExactWriterLifecycleError> {
    let watermark = decoder.mapping()?;
    let timestamp_revision = i64::try_from(decoder.u64()?)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let timestamp_state = StoredAuthorityTimestampState::decode_persisted(
        timestamp_revision,
        decoder.take(AUTHORITY_TIMESTAMP_STATE_V1_LEN)?,
    )
    .map_err(|_| BranchExactWriterLifecycleError::TimestampAllocatorNotReady)?;
    let committed_writes = decoder.u64()?;
    let last_intent = match decoder.u8()? {
        0 => None,
        1 => Some(BranchExactWriterIntentDigest(decoder.array32()?)),
        value => return Err(BranchExactWriterLifecycleError::InvalidPresence(value)),
    };
    let AuthorityTimestampPhase::Idle { last_completed } = timestamp_state.phase() else {
        return Err(BranchExactWriterLifecycleError::TimestampAllocatorNotReady);
    };
    if committed_writes == 0 {
        if last_intent.is_some()
            || watermark != plan.baseline
            || timestamp_state != plan.baseline_timestamp_state
        {
            return Err(BranchExactWriterLifecycleError::TimestampAllocatorNotReady);
        }
    } else {
        let completed = last_completed.map(|digest| *digest.as_bytes());
        let intent = last_intent.map(|digest| *digest.as_bytes());
        if completed != intent
            || intent.is_none()
            || watermark.canonical_chain().network_id()
                != plan.baseline.canonical_chain().network_id()
            || timestamp_state.bootstrap_reason()
                != plan.baseline_timestamp_state.bootstrap_reason()
            || timestamp_state.revision() < plan.baseline_timestamp_state.revision()
            || timestamp_state.high_water() < plan.baseline_timestamp_state.high_water()
        {
            return Err(BranchExactWriterLifecycleError::TimestampAllocatorNotReady);
        }
    }
    Ok(BranchExactWriterActive {
        watermark,
        timestamp_state,
        committed_writes,
        last_intent,
    })
}

fn decode_prepared<Hash: Q256BitHash>(
    decoder: &mut Decoder<'_>,
    plan: &BranchExactWriterActivationPlan<Hash>,
) -> Result<BranchExactWriterPrepared<Hash>, BranchExactWriterLifecycleError> {
    let previous = decode_active(decoder, plan)?;
    let intent_len = decoder.u32()? as usize;
    let intent = BranchExactDualWriteIntent::decode_persisted(decoder.take(intent_len)?)
        .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))?;
    let timestamp_revision = AuthorityTimestampRevision::try_new(decoder.u64()?)
        .map_err(|error| BranchExactWriterLifecycleError::Intent(error.to_string()))?;
    let timestamp = CommitWriteTimestampUs::try_from_i128(decoder.i64()? as i128)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let predecessor_revision = decoder.u64()?;
    let predecessor_revision = i64::try_from(predecessor_revision)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let timestamp_predecessor = StoredAuthorityTimestampState::decode_persisted(
        predecessor_revision,
        decoder.take(AUTHORITY_TIMESTAMP_STATE_V1_LEN)?,
    )
    .map_err(|_| BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch)?;
    let cutover_fence = match decoder.u8()? {
        0 => None,
        1 => Some(
            BranchExactWriterCutoverFence::decode_canonical(decoder.take(81)?)
                .map_err(|error| BranchExactWriterLifecycleError::CutoverFence(error.to_string()))?,
        ),
        value => return Err(BranchExactWriterLifecycleError::InvalidPresence(value)),
    };
    let reservation_key = AuthorityTimestampKey::new(
        intent.candidate().canonical_chain().network_id(),
        intent.authority(),
    );
    let reservation_sample = AuthorityClockSampleUs::try_from_i128(timestamp.as_i64() as i128)
        .map_err(|_| BranchExactWriterLifecycleError::TimestampOutOfRange)?;
    let reconstructed_reservation = timestamp_predecessor
        .seal_reservation(
            reservation_key,
            intent.intent_digest().authority_intent(),
            reservation_sample,
        )
        .map_err(|_| BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch)?;
    let digest = decoder.array32()?;
    if intent.authority() != plan.authority
        || intent.predecessor() != previous.watermark()
        || timestamp <= previous.timestamp_high_water()
        || timestamp_predecessor != previous.timestamp_state()
        || reconstructed_reservation.lease().active_revision() != timestamp_revision
        || reconstructed_reservation.lease().timestamp() != timestamp
        || digest
            != prepared_digest(
                &previous,
                &intent,
                timestamp_revision,
                timestamp,
                timestamp_predecessor,
                cutover_fence.as_ref(),
            )
    {
        return Err(BranchExactWriterLifecycleError::PreparedDigestMismatch);
    }
    Ok(BranchExactWriterPrepared {
        previous,
        intent,
        timestamp_revision,
        timestamp,
        timestamp_predecessor,
        cutover_fence,
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
    BackfillReceipt(String),
    InvalidActivationDigestHex,
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
    TimestampReservationPredecessorMismatch,
    TimestampLeaseNotCompleted,
    TimestampKeyMismatch,
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
    VerifierProfileBindingMismatch,
    VerifierProfileUnavailable(RealmUserUpdateVerifierProfileId),
    PreparedDigestMismatch,
    VerifiedDigestMismatch,
    StateDigestMismatch,
    RevisionStateMismatch,
    PersistedIdentityMismatch,
    Intent(String),
    CutoverFence(String),
}

impl fmt::Display for BranchExactWriterLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactWriterLifecycleError {}

#[cfg(test)]
mod tests {
    use parth_core::{PHash, crypto::hash::tag_tree::TagTreeMerkleProof};
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_data::protocol::chain_context::{
        AuthorityObservation, AuthorityStateCheckpointId, AuthorityStateRoot,
    };
    use psy_node_core::store::{
        authority_commit::{
            AuthorityClockSampleUs,
            AuthorityTimestampBootstrap,
            AuthorityTimestampBootstrapReason, AuthorityTimestampKey,
        },
        branch_exact_dual_write::BranchExactDualWriteIntent,
        branch_exact_schema::BranchExactSchemaMaterializationPlan,
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
        pending_generation::ProcNamespacePrefix,
        pending_generation_identity::{
            PendingGenerationActivationDigest, PendingGenerationBootstrapReason,
            PendingGenerationContext, PendingGenerationLedgerKey,
        },
        pending_generation_pipeline::{
            PendingNoWorkReceiptDigest, PendingPipelineBootstrap, PendingProcessingPhase,
            StoredPendingPipeline,
        },
        typed::ProcCheckpointUniqueId,
    };

    use super::*;
    use crate::rollback::{
        BranchExactBackfillArtifactRow, BranchExactBackfillDatasetDigest,
        BranchExactBackfillPlan, BranchExactBackfillReadbackObservation,
        BranchExactDeploymentIntent, BranchExactDeploymentLifecycleBootstrap,
        BranchExactDeploymentLifecycleState,
        BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
        BranchExactLegacyExportReceipt,
        BranchExactSchemaInspection, BranchExactSchemaMaterializationRequest,
        BranchExactSchemaOnlyReceipt, BranchExactScyllaNodeId,
        BranchExactScyllaSchemaVersion, BranchExactTopologyAttestation,
        BranchExactVerifiedDeploymentReceipt, CqlKeyspaceName,
        SealedBranchExactBackfillPlanCas,
        SealedBranchExactBackfillVerifiedCas,
        SealedBranchExactSchemaVerifiedCas, branch_exact_schema_fingerprint,
        BranchExactSchemaReadyDigest, BranchExactShadowAuditBootstrap,
        BranchExactShadowAuditGeneration, BranchExactShadowAuditObservation,
        BranchExactShadowAuditPlan, BranchExactShadowAuditState,
        BranchExactShadowVerifiedReceipt, SealedBranchExactShadowAuditCas,
    };
    use crate::rollback::branch_exact_pending_orchestration::{
        BranchExactPendingOrchestrationError,
        BranchExactPendingPublishRecovery, BranchExactPendingStartupRecovery,
        BranchExactPreparedWriterRecovery,
        PendingQueueClosePlan,
        VerifiedPendingQueueSeal,
        classify_branch_exact_pending_startup,
        classify_branch_exact_publish_recovery, seal_branch_exact_begin,
        seal_branch_exact_no_work, seal_branch_exact_publish,
        seal_branch_exact_queue_capture, seal_branch_exact_queue_close,
        validate_branch_exact_queue_terminal_pair,
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

    fn realm_observation(
        authority: AuthorityScope,
        chain_height: u64,
        state_height: u64,
        state_seed: u64,
    ) -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            chain(0, chain_height, chain_height),
            authority,
            AuthorityStateCheckpointId::new(state_height),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(
                state_seed,
                state_seed + 1,
                state_seed + 2,
                state_seed + 3,
            )),
        )
        .unwrap()
    }

    fn legacy_context(pending: u64, proc_id: u128) -> PendingGenerationContext {
        PendingGenerationContext::try_from_legacy(pending, proc_id).unwrap()
    }

    /// Test-only persisted-row simulation of the same rotation candidate the
    /// core counter reservation seals. The production API deliberately keeps
    /// reservation construction private to the durable counter implementation.
    fn simulate_rotation(
        state: &StoredPendingPipeline<PHash>,
        next_pending: u64,
    ) -> StoredPendingPipeline<PHash> {
        const PROCESSING_OFFSET: usize = 70;
        const GATHERING_OFFSET: usize = 94;
        const CONTEXT_LEN: usize = 24;
        const PHASE_OFFSET: usize = 118;
        const EVIDENCE_OFFSET: usize = 119;
        const EVIDENCE_AND_BLOCK_LEN: usize = 96;

        let mut payload = state.canonical_payload();
        let old_gathering = payload
            [GATHERING_OFFSET..GATHERING_OFFSET + CONTEXT_LEN]
            .to_vec();
        payload[PROCESSING_OFFSET..PROCESSING_OFFSET + CONTEXT_LEN]
            .copy_from_slice(&old_gathering);
        let next = PendingGenerationContext::try_from_legacy(
            next_pending,
            state
                .proc_namespace_prefix()
                .derive_proc_id(UniquePendingId::try_new(next_pending).unwrap())
                .as_u128(),
        )
        .unwrap();
        payload[GATHERING_OFFSET..GATHERING_OFFSET + 8]
            .copy_from_slice(&next.pending_id().get().to_be_bytes());
        payload[GATHERING_OFFSET + 8..GATHERING_OFFSET + CONTEXT_LEN]
            .copy_from_slice(next.proc_checkpoint_id().as_bytes());
        payload[PHASE_OFFSET] = PendingProcessingPhase::Ready as u8;
        payload[EVIDENCE_OFFSET..EVIDENCE_OFFSET + EVIDENCE_AND_BLOCK_LEN]
            .fill(0);
        StoredPendingPipeline::decode_persisted(
            state.key(),
            state.revision().as_i64() + 1,
            &payload,
        )
        .unwrap()
    }

    fn baseline_realm_pipeline(
        plan: &BranchExactWriterActivationPlan<PHash>,
        authority: AuthorityScope,
    ) -> StoredPendingPipeline<PHash> {
        let network = plan.baseline().canonical_chain().network_id();
        let prefix = ProcNamespacePrefix::for_authority(network, authority);
        let bootstrap = PendingPipelineBootstrap::try_new(
            PendingGenerationLedgerKey::new(network, authority),
            PendingGenerationActivationDigest::try_new(*plan.digest().as_bytes())
                .unwrap(),
            prefix,
            PendingGenerationBootstrapReason::LegacyActivation,
            legacy_context(100, 9_000),
            legacy_context(101, 9_001),
            realm_observation(authority, 10, 10, 500),
            100,
        )
        .unwrap();
        bootstrap.candidate().clone()
    }

    fn ready_realm_pipeline(
        plan: &BranchExactWriterActivationPlan<PHash>,
        authority: AuthorityScope,
    ) -> StoredPendingPipeline<PHash> {
        simulate_rotation(&baseline_realm_pipeline(plan, authority), 102)
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

    fn backfill_receipt(authority: AuthorityScope) -> BranchExactBackfillVerifiedReceipt {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::GenesisNative,
            chain(0, 0, 1),
        )
        .unwrap();
        let materialization = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap,
            authority,
            None,
        )
        .unwrap();
        let request = BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new("psy_h22_writer_fixture").unwrap(),
            materialization,
        )
        .unwrap();
        let fingerprint = branch_exact_schema_fingerprint(authority);
        let schema = BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            &request,
            fingerprint,
        );
        let topology = BranchExactExpectedTopology::try_new(
            [1_u8, 2, 3]
                .map(|value| BranchExactScyllaNodeId::try_new([value; 16]).unwrap())
                .to_vec(),
        )
        .unwrap();
        let observations = topology
            .nodes()
            .iter()
            .copied()
            .map(|node| {
                BranchExactNodeSchemaPostflight::try_new(
                    node,
                    BranchExactScyllaSchemaVersion::try_new([9; 16]).unwrap(),
                    BranchExactSchemaInspection::Exact { fingerprint },
                )
                .unwrap()
            })
            .collect();
        let attestation = BranchExactTopologyAttestation::try_new(
            &schema,
            topology.clone(),
            observations,
        )
        .unwrap();
        let deployment = BranchExactVerifiedDeploymentReceipt::try_new(
            BranchExactDeploymentIntent::new(&request, topology),
            attestation,
        )
        .unwrap();
        let initial = BranchExactDeploymentLifecycleBootstrap::new(
            deployment.intent().clone(),
        );
        let schema_verified = SealedBranchExactSchemaVerifiedCas::try_new(
            initial.candidate(),
            deployment.clone(),
        )
        .unwrap();
        let plan = BranchExactBackfillPlan::genesis_empty(&request, deployment).unwrap();
        let planned = SealedBranchExactBackfillPlanCas::try_new(
            schema_verified.candidate(),
            plan.clone(),
        )
        .unwrap();
        let verified = SealedBranchExactBackfillVerifiedCas::try_new(
            planned.candidate(),
            BranchExactBackfillReadbackObservation::new(
                plan.digest(),
                plan.dataset_digest(),
                0,
                0,
                0,
            ),
        )
        .unwrap();
        match verified.candidate().state() {
            BranchExactDeploymentLifecycleState::BackfillVerified(receipt) => {
                receipt.clone()
            }
            _ => unreachable!(),
        }
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
        writer: &StoredBranchExactWriterLifecycle<PHash>,
    ) -> psy_node_core::store::authority_commit::SealedAuthorityTimestampReservation {
        let key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            intent.authority(),
        );
        let BranchExactWriterState::Active(active) = writer.state() else {
            panic!("timestamp reservation fixture requires active writer")
        };
        active.timestamp_state()
            .seal_reservation(
                key,
                intent.intent_digest().authority_intent(),
                AuthorityClockSampleUs::try_from_i128(2_000).unwrap(),
            )
            .unwrap()
    }

    fn idle_timestamp(
        authority: AuthorityScope,
        active: &BranchExactWriterActive<PHash>,
    ) -> ObservedAuthorityTimestampState {
        let key = AuthorityTimestampKey::new(
            active.watermark().canonical_chain().network_id(),
            authority,
        );
        ObservedAuthorityTimestampState::from_selected_row(
            key,
            active.timestamp_state(),
        )
    }

    #[test]
    fn prepared_row_recovers_exact_allocator_reservation_after_inter_lwt_crash() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
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
        let original = idle
            .seal_reservation(
                key,
                intent.intent_digest().authority_intent(),
                AuthorityClockSampleUs::try_from_i128(2_000).unwrap(),
            )
            .unwrap();
        let prepared = SealedBranchExactWriterCas::prepare_write(
            active.candidate(),
            &intent.clone().attach_timestamp_lease(original.lease()).unwrap(),
            original,
        )
        .unwrap();
        let BranchExactWriterState::WritePrepared(prepared) = prepared.candidate().state()
        else {
            panic!("expected prepared state")
        };

        let recovered = prepared
            .reconcile_timestamp_reservation(
                ObservedAuthorityTimestampState::from_selected_row(key, idle),
            )
            .unwrap();
        let BranchExactTimestampReservationRecovery::Apply {
            reservation,
            sealed,
        } = recovered
        else {
            panic!("idle allocator must require the exact reservation LWT")
        };
        assert_eq!(reservation, original);
        assert_eq!(sealed.lease(), original.lease());

        let active_allocator = original.candidate();
        assert!(matches!(
            prepared
                .reconcile_timestamp_reservation(
                    ObservedAuthorityTimestampState::from_selected_row(
                        key,
                        active_allocator,
                    ),
                )
                .unwrap(),
            BranchExactTimestampReservationRecovery::Active(_)
        ));

        let wrong_idle = AuthorityTimestampBootstrap::new(
            key,
            CommitWriteTimestampUs::try_from_i128(999).unwrap(),
            AuthorityTimestampBootstrapReason::ControlledWriterCutover,
        )
        .candidate();
        assert_eq!(
            prepared.reconcile_timestamp_reservation(
                ObservedAuthorityTimestampState::from_selected_row(key, wrong_idle),
            ),
            Err(BranchExactWriterLifecycleError::TimestampReservationPredecessorMismatch)
        );
    }

    #[test]
    fn managed_prepared_row_persists_exact_cutover_fence() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
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
            ProcCheckpointUniqueId::from_u128(9002),
        )
        .unwrap();
        let reservation = timestamp_reservation(&intent, active.candidate());
        let sealed = intent.clone().attach_timestamp_lease(reservation.lease()).unwrap();
        let mut fence_bytes = [0u8; 81];
        fence_bytes[..8].copy_from_slice(&9u64.to_be_bytes());
        fence_bytes[8..16].copy_from_slice(&3u64.to_be_bytes());
        fence_bytes[16..48].fill(0x44);
        fence_bytes[48..80].fill(0x55);
        fence_bytes[80] = crate::rollback::BranchExactCutoverPhase::LegacyPrimaryDualWrite as u8;
        let fence = BranchExactWriterCutoverFence::decode_canonical(&fence_bytes).unwrap();
        let prepared = SealedBranchExactWriterCas::prepare_write_with_cutover(
            active.candidate(),
            &sealed,
            reservation,
            fence.clone(),
        )
        .unwrap();
        let bytes = prepared.candidate().to_canonical_bytes();
        let decoded = StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
            prepared.candidate().slot().as_bytes(),
            prepared.candidate().revision().as_i64(),
            &bytes,
        )
        .unwrap();
        let BranchExactWriterState::WritePrepared(decoded_prepared) = decoded.state() else {
            panic!("expected managed WritePrepared")
        };
        assert_eq!(decoded_prepared.cutover_fence(), Some(&fence));

        let mut different = fence_bytes;
        different[8..16].copy_from_slice(&4u64.to_be_bytes());
        let different = BranchExactWriterCutoverFence::decode_canonical(&different).unwrap();
        assert_ne!(decoded_prepared.cutover_fence(), Some(&different));
    }

    #[test]
    fn consumed_shadow_is_required_before_activation() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
        );
        let bootstrap = BranchExactWriterBootstrap::new(plan.clone());
        let wrong_plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(11, 101),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
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
    fn activation_digest_config_parser_is_strict() {
        let digest = BranchExactWriterActivationDigest::try_from_hex(
            &hex::encode([7_u8; 32]),
        )
        .unwrap();
        assert_eq!(digest.as_bytes(), &[7; 32]);
        assert_eq!(
            BranchExactWriterActivationDigest::try_from_hex("07"),
            Err(BranchExactWriterLifecycleError::InvalidActivationDigestHex)
        );
        assert_eq!(
            BranchExactWriterActivationDigest::try_from_hex(&hex::encode([0_u8; 32])),
            Err(BranchExactWriterLifecycleError::InvalidActivationDigestHex)
        );
    }

    #[test]
    fn write_lifecycle_is_continuous_timestamp_bound_and_round_trips() {
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
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
        let reservation = timestamp_reservation(&intent, active.candidate());
        let allocator_active = reservation.candidate();
        let lease = reservation.lease();
        let sealed = intent.clone().attach_timestamp_lease(lease).unwrap();
        let prepared = SealedBranchExactWriterCas::prepare_write(
            active.candidate(),
            &sealed,
            reservation,
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
        let wrong_network_key = AuthorityTimestampKey::new(
            NetworkId::try_from_chain_id(0).unwrap(),
            intent.authority(),
        );
        assert_eq!(
            SealedBranchExactWriterCas::commit_published(
                verified.candidate(),
                intent.candidate().canonical_chain(),
                ObservedAuthorityTimestampState::from_selected_row(
                    wrong_network_key,
                    completed,
                ),
            ),
            Err(BranchExactWriterLifecycleError::TimestampKeyMismatch),
        );
        let wrong_authority_key = AuthorityTimestampKey::new(
            intent.candidate().canonical_chain().network_id(),
            AuthorityScope::Realm {
                realm_id: 9,
                realm_sub_id: 1,
            },
        );
        assert_eq!(
            SealedBranchExactWriterCas::commit_published(
                verified.candidate(),
                intent.candidate().canonical_chain(),
                ObservedAuthorityTimestampState::from_selected_row(
                    wrong_authority_key,
                    completed,
                ),
            ),
            Err(BranchExactWriterLifecycleError::TimestampKeyMismatch),
        );
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
            backfill_receipt(AuthorityScope::Coordinator),
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
        let wrong_reservation = timestamp_reservation(&wrong, active.candidate());
        let wrong = wrong
            .attach_timestamp_lease(wrong_reservation.lease())
            .unwrap();
        assert_eq!(
            SealedBranchExactWriterCas::prepare_write(
                active.candidate(),
                &wrong,
                wrong_reservation,
            ),
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
            backfill_receipt(AuthorityScope::Coordinator),
        );
        let consumed = consumed_shadow(shadow, plan.digest());
        let bootstrap = BranchExactWriterBootstrap::new(plan);
        let active = SealedBranchExactWriterCas::activate(
            bootstrap.candidate(),
            &consumed,
        )
        .unwrap();
        let mut impossible_active = active.candidate().clone();
        let BranchExactWriterState::Active(impossible) = &mut impossible_active.state else {
            panic!("expected active state")
        };
        impossible.last_intent = Some(BranchExactWriterIntentDigest([0x77; 32]));
        let impossible_bytes = impossible_active.to_canonical_bytes();
        assert_eq!(
            StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
                impossible_active.slot().as_bytes(),
                impossible_active.revision().as_i64(),
                &impossible_bytes,
            ),
            Err(BranchExactWriterLifecycleError::TimestampAllocatorNotReady),
        );
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
        let mut version_two_tagged_with_v3_domain =
            blocked.candidate().to_canonical_bytes();
        version_two_tagged_with_v3_domain[8..10]
            .copy_from_slice(&2_u16.to_be_bytes());
        let body_len = version_two_tagged_with_v3_domain.len() - 32;
        let mut hasher = Sha256::new();
        hasher.update(STATE_DIGEST_DOMAIN);
        hasher.update(&version_two_tagged_with_v3_domain[..body_len]);
        let digest: [u8; 32] = hasher.finalize().into();
        version_two_tagged_with_v3_domain[body_len..].copy_from_slice(&digest);
        assert_eq!(
            StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
                blocked.candidate().slot().as_bytes(),
                blocked.candidate().revision().as_i64(),
                &version_two_tagged_with_v3_domain,
            ),
            Err(BranchExactWriterLifecycleError::UnknownCodecVersion(2)),
        );
        let mut actual_v2_domain = version_two_tagged_with_v3_domain.clone();
        let mut hasher = Sha256::new();
        hasher.update(b"psy/rollback/branch-exact-writer-state/v1");
        hasher.update(&actual_v2_domain[..body_len]);
        let digest: [u8; 32] = hasher.finalize().into();
        actual_v2_domain[body_len..].copy_from_slice(&digest);
        assert_eq!(
            StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
                blocked.candidate().slot().as_bytes(),
                blocked.candidate().revision().as_i64(),
                &actual_v2_domain,
            ),
            Err(BranchExactWriterLifecycleError::StateDigestMismatch),
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
            backfill_receipt(AuthorityScope::Coordinator),
        );
        let same = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Coordinator,
            mapping(11, 101),
            timestamp,
            shadow.digest(),
            backfill_receipt(AuthorityScope::Coordinator),
        );
        let realm = BranchExactWriterActivationPlan::test_fixture(
            AuthorityScope::Realm { realm_id: 1, realm_sub_id: 0 },
            mapping(10, 100),
            timestamp,
            shadow.digest(),
            backfill_receipt(AuthorityScope::Realm { realm_id: 1, realm_sub_id: 0 }),
        );
        assert_eq!(coordinator.slot(), same.slot());
        assert_ne!(coordinator.slot(), realm.slot());
    }

    #[test]
    fn verifier_profile_binding_is_authority_exact_durable_and_resolvable() {
        let authority = AuthorityScope::Realm {
            realm_id: 1,
            realm_sub_id: 0,
        };
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            authority,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(authority),
        );
        let BranchExactWriterVerifierProfile::Realm(profile_id) = plan.verifier_profile() else {
            panic!("Realm activation must carry a verifier profile")
        };
        assert_eq!(
            BranchExactWriterVerifierProfile::for_authority(authority, Some(profile_id)).unwrap(),
            plan.verifier_profile()
        );
        assert_eq!(
            BranchExactWriterVerifierProfile::for_authority(authority, None),
            Err(BranchExactWriterLifecycleError::VerifierProfileBindingMismatch)
        );
        assert_eq!(
            BranchExactWriterVerifierProfile::for_authority(
                AuthorityScope::Coordinator,
                Some(profile_id),
            ),
            Err(BranchExactWriterLifecycleError::VerifierProfileBindingMismatch)
        );

        let stored = BranchExactWriterBootstrap::new(plan.clone());
        let decoded = StoredBranchExactWriterLifecycle::<PHash>::decode_persisted(
            stored.candidate().slot().as_bytes(),
            stored.candidate().revision().as_i64(),
            &stored.candidate().to_canonical_bytes(),
        )
        .unwrap();
        assert_eq!(decoded.plan().verifier_profile(), plan.verifier_profile());

        let profile = psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierProfile::try_new(
            plan.baseline().canonical_chain().network_id(),
            32,
            psy_node_core::queue::realm_user_update_verifier_profile::RealmUserUpdateVerifierBackend::DeterministicTest,
            1,
            1,
            [0x71; 32],
            [0x72; 32],
        )
        .unwrap();
        let mut plan_with_profile = plan.clone();
        plan_with_profile.verifier_profile =
            BranchExactWriterVerifierProfile::Realm(profile.id());
        plan_with_profile.digest = activation_digest(&plan_with_profile);
        assert_ne!(plan_with_profile.digest(), plan.digest());
        let registry = RealmUserUpdateVerifierRegistry::try_new([(
            profile.clone(),
            std::sync::Arc::new(17_u8),
        )])
        .unwrap();
        assert_eq!(
            **plan_with_profile
                .resolve_realm_verifier(&registry)
                .unwrap()
                .verifier(),
            17
        );
        assert_eq!(
            plan.resolve_realm_verifier(&registry).err(),
            Some(BranchExactWriterLifecycleError::VerifierProfileUnavailable(
                profile_id
            ))
        );
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

    #[test]
    fn pending_bridge_survives_sparse_realm_no_work_and_binds_verified_publish() {
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let shadow = verified_shadow();
        let plan = BranchExactWriterActivationPlan::test_fixture(
            authority,
            mapping(10, 100),
            CommitWriteTimestampUs::try_from_i128(1_000).unwrap(),
            shadow.digest(),
            backfill_receipt(authority),
        );
        let consumed = consumed_shadow(shadow, plan.digest());
        let writer_bootstrap = BranchExactWriterBootstrap::new(plan.clone());
        let active = SealedBranchExactWriterCas::activate(
            writer_bootstrap.candidate(),
            &consumed,
        )
        .unwrap();
        let BranchExactWriterState::Active(initial_active) = active.candidate().state()
        else {
            unreachable!()
        };
        let baseline_timestamp = idle_timestamp(authority, initial_active);
        let baseline_pipeline = baseline_realm_pipeline(&plan, authority);
        assert_eq!(
            classify_branch_exact_pending_startup(
                &baseline_pipeline,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::AwaitPrimeOrRotate,
        );

        let ready_101 = ready_realm_pipeline(&plan, authority);
        assert_eq!(
            classify_branch_exact_pending_startup(
                &ready_101,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ReadyForQueueClose,
        );
        let wrong_key = AuthorityTimestampKey::new(
            baseline_timestamp.key().network(),
            authority,
        );
        let wrong_state = AuthorityTimestampBootstrap::new(
            wrong_key,
            initial_active.timestamp_high_water(),
            AuthorityTimestampBootstrapReason::GenesisNative,
        )
        .candidate();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &ready_101,
                active.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    wrong_key,
                    wrong_state,
                ),
            ),
            Err(BranchExactPendingOrchestrationError::TimestampMismatch),
        );
        let close_101 = PendingQueueClosePlan::model(&ready_101)
            .unwrap();
        let wrong_authority = AuthorityScope::Realm {
            realm_id: 8,
            realm_sub_id: 2,
        };
        let wrong_plan = PendingQueueClosePlan::model(
            &ready_realm_pipeline(&plan, wrong_authority),
        )
        .unwrap();
        assert_eq!(
            seal_branch_exact_queue_close(
                &ready_101,
                active.candidate(),
                wrong_plan,
            ),
            Err(BranchExactPendingOrchestrationError::QueueClosePlanMismatch),
        );
        let sealing_101 = seal_branch_exact_queue_close(
            &ready_101,
            active.candidate(),
            close_101,
        )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &sealing_101,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ResumeQueueSeal(close_101.digest()),
        );
        assert!(VerifiedPendingQueueSeal::model_stable_empty(
            close_101,
            0,
            1,
        )
        .is_err());
        let empty_seal_101 = VerifiedPendingQueueSeal::model_stable_empty(
            close_101,
            0,
            0,
        )
        .unwrap();
        let empty_101 = seal_branch_exact_queue_capture(
            &sealing_101,
            active.candidate(),
            empty_seal_101,
        )
        .unwrap()
        .candidate()
        .clone();
        let empty_digest_101 = empty_seal_101.empty_digest().unwrap();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &empty_101,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ResumeNoWorkPublication(
                empty_digest_101,
            ),
        );
        let no_work_101 = seal_branch_exact_no_work(
            &empty_101,
            active.candidate(),
            empty_seal_101,
            realm_observation(authority, 11, 10, 500),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &no_work_101,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::CompleteNoWorkAfterTrustedMarker,
        );
        validate_branch_exact_queue_terminal_pair(
            &no_work_101,
            active.candidate(),
        )
        .unwrap();
        let corrupt_no_work = empty_101
            .seal_retire_no_work(
                empty_digest_101,
                PendingNoWorkReceiptDigest::try_new([0xa5; 32]).unwrap(),
                realm_observation(authority, 11, 10, 500),
            )
            .unwrap()
            .candidate()
            .clone();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &corrupt_no_work,
                active.candidate(),
                baseline_timestamp,
            ),
            Err(BranchExactPendingOrchestrationError::NoWorkReceiptMismatch),
        );

        // A second idle generation advances processed/frontier while the
        // materialized writer intentionally remains at pending 100 / height 10.
        let ready_102 = simulate_rotation(&no_work_101, 103);
        let close_102 = PendingQueueClosePlan::model(&ready_102)
            .unwrap();
        let sealing_102 = seal_branch_exact_queue_close(
            &ready_102,
            active.candidate(),
            close_102,
        )
            .unwrap()
            .candidate()
            .clone();
        let empty_seal_102 = VerifiedPendingQueueSeal::model_stable_empty(
            close_102,
            0,
            0,
        )
        .unwrap();
        let empty_102 = seal_branch_exact_queue_capture(
            &sealing_102,
            active.candidate(),
            empty_seal_102,
        )
        .unwrap()
        .candidate()
        .clone();
        let no_work_102 = seal_branch_exact_no_work(
            &empty_102,
            active.candidate(),
            empty_seal_102,
            realm_observation(authority, 12, 10, 500),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(no_work_102.processed_pending_id(), 102);
        let BranchExactWriterState::Active(still_at_baseline) =
            active.candidate().state()
        else {
            panic!("writer must remain active at its materialized baseline")
        };
        assert_eq!(still_at_baseline.watermark().pending_id().get(), 100);

        let ready_103 = simulate_rotation(&no_work_102, 104);
        let close_103 = PendingQueueClosePlan::model(&ready_103)
            .unwrap();
        let sealing_103 = seal_branch_exact_queue_close(
            &ready_103,
            active.candidate(),
            close_103,
        )
            .unwrap()
            .candidate()
            .clone();
        let work_seal_103 = VerifiedPendingQueueSeal::model_work(
            close_103,
            1,
            [0x33; 32],
        )
        .unwrap();
        let captured_103 = seal_branch_exact_queue_capture(
            &sealing_103,
            active.candidate(),
            work_seal_103,
        )
        .unwrap()
        .candidate()
        .clone();
        let work_digest_103 = work_seal_103.work_digest().unwrap();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &captured_103,
                active.candidate(),
                baseline_timestamp,
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::AwaitRecoverableWork(
                work_digest_103,
            ),
        );
        let intent = BranchExactDualWriteIntent::try_realm(
            authority,
            mapping(10, 100),
            mapping(13, 103),
            captured_103.processing().proc_checkpoint_id(),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        let reservation = timestamp_reservation(&intent, active.candidate());
        let allocator_predecessor = reservation.expected();
        let allocator_active = reservation.candidate();
        let lease = reservation.lease();
        let sealed = intent
            .clone()
            .attach_timestamp_lease(lease)
            .unwrap();
        let prepared = SealedBranchExactWriterCas::prepare_write(
            active.candidate(),
            &sealed,
            reservation,
        )
        .unwrap();
        let BranchExactWriterState::WritePrepared(prepared_state) =
            prepared.candidate().state()
        else {
            panic!("expected prepared writer")
        };
        let inflight_103 = seal_branch_exact_begin(
            &captured_103,
            prepared.candidate(),
        )
        .unwrap()
        .candidate()
        .clone();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &captured_103,
                prepared.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_predecessor,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ApplyPipeline {
                pipeline: seal_branch_exact_begin(
                    &captured_103,
                    prepared.candidate(),
                )
                .unwrap(),
                writer: BranchExactPreparedWriterRecovery::ApplyTimestampReservation,
            },
        );
        assert_eq!(
            classify_branch_exact_pending_startup(
                &inflight_103,
                prepared.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_predecessor,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ResumeWriterVerification(
                BranchExactPreparedWriterRecovery::ApplyTimestampReservation,
            ),
        );
        assert_eq!(
            classify_branch_exact_pending_startup(
                &captured_103,
                prepared.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_active,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ApplyPipeline {
                pipeline: seal_branch_exact_begin(
                    &captured_103,
                    prepared.candidate(),
                )
                .unwrap(),
                writer: BranchExactPreparedWriterRecovery::ResumeActiveLease,
            },
        );
        assert_eq!(
            classify_branch_exact_pending_startup(
                &inflight_103,
                prepared.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_active,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::ResumeWriterVerification(
                BranchExactPreparedWriterRecovery::ResumeActiveLease,
            ),
        );
        let write_observation = crate::rollback::branch_exact_dual_write_executor::BranchExactVerifiedWriteObservation::test_fixture(prepared_state);
        let verified = SealedBranchExactWriterCas::verify_writes(
            prepared.candidate(),
            &write_observation,
        )
        .unwrap();
        assert_eq!(
            classify_branch_exact_pending_startup(
                &inflight_103,
                verified.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_active,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::AwaitTrustedMarker,
        );
        let inflight_after_writer_advanced = seal_branch_exact_begin(
            &captured_103,
            verified.candidate(),
        )
        .unwrap();
        assert_eq!(
            inflight_after_writer_advanced.candidate(),
            &inflight_103,
        );
        let marker = realm_observation(authority, 13, 13, 600);
        assert_eq!(
            classify_branch_exact_publish_recovery(
                &captured_103,
                verified.candidate(),
                marker.clone(),
            )
            .unwrap(),
            BranchExactPendingPublishRecovery::ApplyPipeline(
                inflight_after_writer_advanced,
            )
        );
        assert_eq!(
            classify_branch_exact_publish_recovery(
                &inflight_103,
                verified.candidate(),
                marker.clone(),
            )
            .unwrap(),
            BranchExactPendingPublishRecovery::ApplyPipeline(
                seal_branch_exact_publish(
                    &inflight_103,
                    verified.candidate(),
                    marker.clone(),
                )
                .unwrap(),
            )
        );
        assert_eq!(
            classify_branch_exact_publish_recovery(
                &inflight_103,
                active.candidate(),
                marker.clone(),
            ),
            Err(BranchExactPendingOrchestrationError::WriterAdvancedBeforePipeline),
        );
        let publish = seal_branch_exact_publish(
            &inflight_103,
            verified.candidate(),
            marker.clone(),
        )
        .unwrap();
        assert_eq!(
            classify_branch_exact_pending_startup(
                publish.candidate(),
                verified.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_active,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker,
        );
        let retry = seal_branch_exact_publish(
            &inflight_103,
            verified.candidate(),
            marker,
        )
        .unwrap();
        assert_eq!(publish, retry);
        assert_eq!(publish.candidate().processed_pending_id(), 103);
        assert_eq!(
            publish.candidate().phase(),
            PendingProcessingPhase::Published
        );
        // The writer deliberately remains WritesVerified until after the
        // pipeline CAS, preserving full recovery evidence in both crash gaps.
        assert!(matches!(
            verified.candidate().state(),
            BranchExactWriterState::WritesVerified(_)
        ));
        assert_eq!(
            classify_branch_exact_publish_recovery(
                publish.candidate(),
                verified.candidate(),
                realm_observation(authority, 13, 13, 600),
            )
            .unwrap(),
            BranchExactPendingPublishRecovery::FinishWriter,
        );

        let completed_allocator = allocator_active
            .seal_completion(lease.key(), lease)
            .unwrap()
            .candidate();
        assert_eq!(
            classify_branch_exact_pending_startup(
                publish.candidate(),
                verified.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    completed_allocator,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker,
        );
        assert_eq!(
            classify_branch_exact_pending_startup(
                &inflight_103,
                verified.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    completed_allocator,
                ),
            ),
            Err(BranchExactPendingOrchestrationError::TimestampMismatch),
        );
        let committed = SealedBranchExactWriterCas::commit_published(
            verified.candidate(),
            intent.candidate().canonical_chain(),
            ObservedAuthorityTimestampState::from_selected_row(
                lease.key(),
                completed_allocator,
            ),
        )
        .unwrap();
        assert_eq!(
            classify_branch_exact_pending_startup(
                publish.candidate(),
                committed.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    completed_allocator,
                ),
            )
            .unwrap(),
            BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker,
        );
        assert_eq!(
            classify_branch_exact_pending_startup(
                publish.candidate(),
                committed.candidate(),
                ObservedAuthorityTimestampState::from_selected_row(
                    lease.key(),
                    allocator_active,
                ),
            ),
            Err(BranchExactPendingOrchestrationError::TimestampMismatch),
        );
        assert_eq!(
            classify_branch_exact_publish_recovery(
                publish.candidate(),
                committed.candidate(),
                realm_observation(authority, 13, 13, 600),
            )
            .unwrap(),
            BranchExactPendingPublishRecovery::Complete,
        );
        validate_branch_exact_queue_terminal_pair(
            publish.candidate(),
            committed.candidate(),
        )
        .unwrap();
        assert!(matches!(
            classify_branch_exact_publish_recovery(
                publish.candidate(),
                committed.candidate(),
                realm_observation(authority, 13, 13, 601),
            ),
            Err(BranchExactPendingOrchestrationError::WriterFrontierMismatch)
        ));

        // Same branch/pending with another proc/proof commitment produces a
        // different last-intent and cannot validate the stored pipeline receipt.
        let wrong_intent = BranchExactDualWriteIntent::try_realm(
            authority,
            mapping(10, 100),
            mapping(13, 103),
            ProcCheckpointUniqueId::from_u128(
                inflight_103
                    .processing()
                    .proc_checkpoint_id()
                    .as_u128()
                    + 1,
            ),
            &TagTreeMerkleProof::<PHash>::new_empty(),
        )
        .unwrap();
        let wrong_reservation = timestamp_reservation(&wrong_intent, active.candidate());
        let wrong_active_allocator = wrong_reservation.candidate();
        let wrong_lease = wrong_reservation.lease();
        let wrong_prepared = SealedBranchExactWriterCas::prepare_write(
            active.candidate(),
            &wrong_intent
                .clone()
                .attach_timestamp_lease(wrong_lease)
                .unwrap(),
            wrong_reservation,
        )
        .unwrap();
        let BranchExactWriterState::WritePrepared(wrong_prepared_state) =
            wrong_prepared.candidate().state()
        else {
            panic!("expected wrong prepared writer fixture")
        };
        let wrong_write_observation = crate::rollback::branch_exact_dual_write_executor::BranchExactVerifiedWriteObservation::test_fixture(wrong_prepared_state);
        let wrong_verified = SealedBranchExactWriterCas::verify_writes(
            wrong_prepared.candidate(),
            &wrong_write_observation,
        )
        .unwrap();
        let wrong_completed = wrong_active_allocator
            .seal_completion(wrong_lease.key(), wrong_lease)
            .unwrap()
            .candidate();
        let wrong_committed = SealedBranchExactWriterCas::commit_published(
            wrong_verified.candidate(),
            wrong_intent.candidate().canonical_chain(),
            ObservedAuthorityTimestampState::from_selected_row(
                wrong_lease.key(),
                wrong_completed,
            ),
        )
        .unwrap();
        assert!(matches!(
            classify_branch_exact_publish_recovery(
                publish.candidate(),
                wrong_committed.candidate(),
                realm_observation(authority, 13, 13, 600),
            ),
            Err(BranchExactPendingOrchestrationError::PublishReceiptMismatch)
        ));
    }
}
