//! Crash-safe, sharded admission-close model for Realm user updates.
//!
//! The NATS processing close proves a queue source boundary; it does not
//! linearize new Realm claims. This independent gate first closes generation
//! admission, then stabilizes all 256 bucket manifests. A stable manifest is
//! discovery evidence only and does not authorize queue rotation.

use std::{collections::HashSet, error::Error, fmt};

use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::protocol::{
    canonical_chain::NetworkId,
    chain_context::{
        AuthorityObservation, AuthorityScope, AUTHORITY_OBSERVATION_V1_LEN,
    },
};
use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{PendingPipelineRevision, StoredPendingPipeline},
    typed::UserId,
};

use super::{
    realm_user_update_claim::{
        RealmUserUpdateAdmissionCommitment, RealmUserUpdateAdmissionOrdinal,
        RealmUserUpdateClaimBucket, RealmUserUpdateClaimPartition,
        RealmUserUpdateClaimPhase, RealmUserUpdateDependencyDigest,
        RealmUserUpdatePublishReceiptDigest, StoredRealmUserUpdateClaim,
    },
    realm_user_update_publish::{
        RealmUserUpdateIntentId, RealmUserUpdatePublishReceipt,
        RealmUserUpdatePublishRequest,
    },
    recoverable_ephemeral::PendingQueueCaptureContext,
};

const MAGIC: &[u8; 8] = b"PSYRUADM";
const CODEC_VERSION: u16 = 2;
const STATE_DOMAIN: &[u8] = b"psy/rollback/realm-user-update-admission-state/v2";
const CONTRIBUTION_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-admission-set-contribution/v1";
const BUCKET_MANIFEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-admission-bucket-manifest/v1";
const GENERATION_MANIFEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-admission-generation-manifest/v1";
const CLOSE_INTENT_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-admission-close-intent/v1";
const TERMINAL_EVIDENCE_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-terminal-evidence/v1";
const TERMINAL_SET_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-terminal-set/v1";
const QUALIFICATION_DOMAIN: &[u8] =
    b"psy/rollback/realm-user-update-generation-qualification/v1";
const MAX_CLAIM_PAYLOAD_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmUserUpdateAdmissionKey(PendingQueueCaptureContext);

impl RealmUserUpdateAdmissionKey {
    pub fn try_new(
        capture: PendingQueueCaptureContext,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        if !matches!(capture.key().authority(), AuthorityScope::Realm { .. }) {
            return Err(RealmUserUpdateAdmissionError::RealmOnly);
        }
        Ok(Self(capture))
    }

    pub const fn capture(self) -> PendingQueueCaptureContext {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealmUserUpdateAdmissionShard {
    Generation,
    Bucket(RealmUserUpdateClaimBucket),
}

impl RealmUserUpdateAdmissionShard {
    pub fn as_i16(self) -> Result<i16, RealmUserUpdateAdmissionError> {
        match self {
            Self::Generation => Ok(0),
            Self::Bucket(bucket) => i16::try_from(bucket.get() + 1)
                .map_err(|_| RealmUserUpdateAdmissionError::InvalidShard),
        }
    }

    pub fn try_from_i16(value: i16) -> Result<Self, RealmUserUpdateAdmissionError> {
        match value {
            0 => Ok(Self::Generation),
            1..=256 => Ok(Self::Bucket(
                RealmUserUpdateClaimBucket::try_new((value - 1) as u16)
                    .map_err(admission)?,
            )),
            _ => Err(RealmUserUpdateAdmissionError::InvalidShard),
        }
    }
}

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(
                bytes: [u8; 32],
            ) -> Result<Self, RealmUserUpdateAdmissionError> {
                if bytes == [0; 32] {
                    Err(RealmUserUpdateAdmissionError::EmptyDigest)
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

digest_type!(RealmUserUpdateAdmissionCloseIntent);
digest_type!(RealmUserUpdateAdmissionManifestDigest);
digest_type!(RealmUserUpdateTerminalEvidenceDigest);
digest_type!(RealmUserUpdateQualificationDigest);

impl RealmUserUpdateAdmissionCloseIntent {
    pub fn derive(
        key: RealmUserUpdateAdmissionKey,
        caller_stable_nonce: [u8; 32],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        if caller_stable_nonce == [0; 32] {
            return Err(RealmUserUpdateAdmissionError::EmptyDigest);
        }
        let mut hasher = Sha256::new();
        hasher.update(CLOSE_INTENT_DOMAIN);
        encode_key(key, &mut hasher);
        hasher.update(caller_stable_nonce);
        Self::try_new(hasher.finalize().into())
    }
}

/// Ordered commitment to the immutable accepted claim sequence in one bucket.
///
/// The gate assigns `count + 1` before the claim row can be created. Folding
/// the previous digest, ordinal and immutable claim commitment makes missing,
/// duplicated and reordered rows detectable without relying on Scylla's user
/// clustering order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateAcceptedSet {
    count: u64,
    digest: [u8; 32],
}

impl RealmUserUpdateAcceptedSet {
    pub const EMPTY: Self = Self {
        count: 0,
        digest: [0; 32],
    };

    pub const fn count(self) -> u64 {
        self.count
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    fn include<Hash: Q256BitHash>(
        self,
        claim: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let next_count = self
            .count
            .checked_add(1)
            .ok_or(RealmUserUpdateAdmissionError::CountOverflow)?;
        if claim.admission_ordinal().get() != next_count {
            return Err(RealmUserUpdateAdmissionError::AdmissionOrdinalMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(CONTRIBUTION_DOMAIN);
        hasher.update(self.digest);
        hasher.update(next_count.to_be_bytes());
        hasher.update(claim_contribution(claim)?);
        Ok(Self {
            count: next_count,
            digest: hasher.finalize().into(),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateBucketManifest {
    bucket: RealmUserUpdateClaimBucket,
    accepted: RealmUserUpdateAcceptedSet,
    digest: RealmUserUpdateAdmissionManifestDigest,
}

impl RealmUserUpdateBucketManifest {
    pub fn from_claims<Hash: Q256BitHash>(
        partition: RealmUserUpdateClaimPartition,
        claims: &[StoredRealmUserUpdateClaim<Hash>],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let mut ordered = claims.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|claim| claim.admission_ordinal().get());
        let mut accepted = RealmUserUpdateAcceptedSet::EMPTY;
        let mut users = HashSet::with_capacity(ordered.len());
        let mut hasher = Sha256::new();
        hasher.update(BUCKET_MANIFEST_DOMAIN);
        encode_key(RealmUserUpdateAdmissionKey::try_new(partition.capture())?, &mut hasher);
        hasher.update(partition.bucket().get().to_be_bytes());
        hasher.update((ordered.len() as u64).to_be_bytes());
        for claim in ordered {
            if claim.partition().map_err(admission)? != partition
                || !users.insert(claim.user_id().get())
            {
                return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
            }
            let contribution = claim_contribution(claim)?;
            accepted = accepted.include(claim)?;
            hasher.update(claim.admission_ordinal().get().to_be_bytes());
            hasher.update(claim.user_id().get().to_be_bytes());
            hasher.update(contribution);
        }
        Ok(Self {
            bucket: partition.bucket(),
            accepted,
            digest: RealmUserUpdateAdmissionManifestDigest::try_new(
                hasher.finalize().into(),
            )?,
        })
    }

    pub const fn bucket(self) -> RealmUserUpdateClaimBucket {
        self.bucket
    }

    pub const fn accepted(self) -> RealmUserUpdateAcceptedSet {
        self.accepted
    }

    pub const fn digest(self) -> RealmUserUpdateAdmissionManifestDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateGenerationManifest {
    total: RealmUserUpdateAcceptedSet,
    digest: RealmUserUpdateAdmissionManifestDigest,
}

impl RealmUserUpdateGenerationManifest {
    pub fn from_buckets(
        buckets: &[RealmUserUpdateBucketManifest],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        if buckets.len() != RealmUserUpdateClaimBucket::COUNT as usize {
            return Err(RealmUserUpdateAdmissionError::IncompleteBucketSet);
        }
        let mut ordered = buckets.to_vec();
        ordered.sort_by_key(|manifest| manifest.bucket().get());
        let mut total = RealmUserUpdateAcceptedSet::EMPTY;
        let mut hasher = Sha256::new();
        hasher.update(GENERATION_MANIFEST_DOMAIN);
        hasher.update(RealmUserUpdateClaimBucket::COUNT.to_be_bytes());
        for (expected, manifest) in ordered.iter().enumerate() {
            if manifest.bucket().get() as usize != expected {
                return Err(RealmUserUpdateAdmissionError::IncompleteBucketSet);
            }
            total.count = total
                .count
                .checked_add(manifest.accepted.count)
                .ok_or(RealmUserUpdateAdmissionError::CountOverflow)?;
            let mut aggregate = Sha256::new();
            aggregate.update(GENERATION_MANIFEST_DOMAIN);
            aggregate.update(total.digest);
            aggregate.update(manifest.bucket.get().to_be_bytes());
            aggregate.update(manifest.accepted.count.to_be_bytes());
            aggregate.update(manifest.accepted.digest);
            total.digest = aggregate.finalize().into();
            hasher.update(manifest.bucket.get().to_be_bytes());
            hasher.update(manifest.accepted.count.to_be_bytes());
            hasher.update(manifest.accepted.digest);
            hasher.update(manifest.digest.as_bytes());
        }
        Ok(Self {
            total,
            digest: RealmUserUpdateAdmissionManifestDigest::try_new(
                hasher.finalize().into(),
            )?,
        })
    }

    pub const fn total(self) -> RealmUserUpdateAcceptedSet {
        self.total
    }

    pub const fn digest(self) -> RealmUserUpdateAdmissionManifestDigest {
        self.digest
    }
}

/// Exact pending-pipeline state which a terminal claim set authorizes.
///
/// The admission key already binds the activation digest and gathering
/// generation.  The additional revision and full authority observation make
/// a qualification unusable after any frontier/pipeline transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateQualificationFence<Hash> {
    pipeline_revision: PendingPipelineRevision,
    frontier: AuthorityObservation<Hash>,
}

impl<Hash: Q256BitHash> RealmUserUpdateQualificationFence<Hash> {
    pub fn try_from_pipeline(
        key: RealmUserUpdateAdmissionKey,
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let capture = key.capture();
        if pipeline.key() != capture.key()
            || pipeline.activation_digest() != capture.activation()
            || pipeline.gathering() != capture.processing()
            || pipeline.frontier().authority() != capture.key().authority()
            || pipeline.frontier().chain().network_id() != capture.key().network()
            || pipeline.blocked_reason().is_some()
        {
            return Err(RealmUserUpdateAdmissionError::PipelineFenceMismatch);
        }
        Ok(Self {
            pipeline_revision: pipeline.revision(),
            frontier: *pipeline.frontier(),
        })
    }

    pub const fn pipeline_revision(self) -> PendingPipelineRevision {
        self.pipeline_revision
    }

    pub const fn frontier(&self) -> &AuthorityObservation<Hash> {
        &self.frontier
    }

    pub fn matches_pipeline(
        &self,
        key: RealmUserUpdateAdmissionKey,
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> bool {
        Self::try_from_pipeline(key, pipeline)
            .is_ok_and(|current| current == *self)
    }
}

/// Deterministic commitment to one accepted claim's exact durable terminal
/// evidence.  Construction checks the immutable admission identity, the
/// branch/frontier fence, the reconstructed request and the observed receipt.
/// A public receipt remains a DTO; the Scylla layer must only call this after
/// its private exact `SourceCommitted` permit has been observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateTerminalEvidence {
    bucket: RealmUserUpdateClaimBucket,
    ordinal: RealmUserUpdateAdmissionOrdinal,
    user_id: UserId,
    admission_commitment: RealmUserUpdateAdmissionCommitment,
    dependency_digest: RealmUserUpdateDependencyDigest,
    receipt_digest: RealmUserUpdatePublishReceiptDigest,
    intent_id: RealmUserUpdateIntentId,
    assignment_digest: [u8; 32],
    subject_sequence: u64,
    envelope_digest: [u8; 32],
    digest: RealmUserUpdateTerminalEvidenceDigest,
}

impl RealmUserUpdateTerminalEvidence {
    pub fn try_from_observed<F: QFelt64, Hash: Q256BitHash>(
        key: RealmUserUpdateAdmissionKey,
        fence: &RealmUserUpdateQualificationFence<Hash>,
        claim: &StoredRealmUserUpdateClaim<Hash>,
        request: &RealmUserUpdatePublishRequest<F, Hash>,
        receipt: &RealmUserUpdatePublishReceipt,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let dependency_digest = claim
            .dependency_digest()
            .ok_or(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch)?;
        let receipt_digest = claim
            .publish_receipt_digest()
            .ok_or(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch)?;
        let reconstructed_admission =
            claim.reconstruct_admission().map_err(admission)?;
        if claim.phase() != RealmUserUpdateClaimPhase::Published
            || claim.partition().map_err(admission)?.capture() != key.capture()
            || request.admission() != &reconstructed_admission
            || request.user_id() != claim.user_id()
            || request.request_digest() != claim.request_digest()
            || request.pending().chain() != fence.frontier().chain()
            || request.pending().authority() != fence.frontier().authority()
            || request.intent_id() != receipt.intent_id()
            || receipt_digest.as_bytes() != receipt.receipt_digest()
        {
            return Err(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch);
        }
        let admission_commitment = claim.admission_commitment().map_err(admission)?;
        let mut value = Self {
            bucket: claim.bucket(),
            ordinal: claim.admission_ordinal(),
            user_id: claim.user_id(),
            admission_commitment,
            dependency_digest,
            receipt_digest,
            intent_id: receipt.intent_id(),
            assignment_digest: *receipt.assignment_digest(),
            subject_sequence: receipt.subject_sequence(),
            envelope_digest: *receipt.envelope_digest(),
            digest: RealmUserUpdateTerminalEvidenceDigest::try_new([1; 32])?,
        };
        value.digest = RealmUserUpdateTerminalEvidenceDigest::try_new(
            value.compute_digest(),
        )?;
        Ok(value)
    }

    pub const fn bucket(self) -> RealmUserUpdateClaimBucket {
        self.bucket
    }

    pub const fn ordinal(self) -> RealmUserUpdateAdmissionOrdinal {
        self.ordinal
    }

    pub const fn user_id(self) -> UserId {
        self.user_id
    }

    pub const fn digest(self) -> RealmUserUpdateTerminalEvidenceDigest {
        self.digest
    }

    fn accepted_contribution(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(CONTRIBUTION_DOMAIN);
        hasher.update(self.user_id.get().to_be_bytes());
        hasher.update(self.admission_commitment.as_bytes());
        hasher.finalize().into()
    }

    fn compute_digest(self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(TERMINAL_EVIDENCE_DOMAIN);
        hasher.update(self.bucket.get().to_be_bytes());
        hasher.update(self.ordinal.get().to_be_bytes());
        hasher.update(self.user_id.get().to_be_bytes());
        hasher.update(self.admission_commitment.as_bytes());
        hasher.update(self.dependency_digest.as_bytes());
        hasher.update(self.receipt_digest.as_bytes());
        hasher.update(self.intent_id.as_bytes());
        hasher.update(self.assignment_digest);
        hasher.update(self.subject_sequence.to_be_bytes());
        hasher.update(self.envelope_digest);
        hasher.finalize().into()
    }
}

/// Full-generation terminal qualification.  It commits exactly the stable
/// admission membership, every Published/SourceCommitted claim, and the
/// pre-publish pipeline fence which must be revalidated by the consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateGenerationQualification<Hash> {
    membership: RealmUserUpdateGenerationManifest,
    fence: RealmUserUpdateQualificationFence<Hash>,
    terminal_count: u64,
    terminal_digest: RealmUserUpdateTerminalEvidenceDigest,
    digest: RealmUserUpdateQualificationDigest,
}

impl<Hash: Q256BitHash> RealmUserUpdateGenerationQualification<Hash> {
    pub fn from_terminal_evidence(
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
        membership: RealmUserUpdateGenerationManifest,
        fence: RealmUserUpdateQualificationFence<Hash>,
        evidence: &[RealmUserUpdateTerminalEvidence],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let mut ordered = evidence.to_vec();
        ordered.sort_by_key(|item| (item.bucket().get(), item.ordinal().get()));
        let observed_membership = membership_from_terminal_evidence(key, &ordered)?;
        if observed_membership != membership
            || ordered.len() as u64 != membership.total().count()
        {
            return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
        }
        let mut terminal = Sha256::new();
        terminal.update(TERMINAL_SET_DOMAIN);
        terminal.update((ordered.len() as u64).to_be_bytes());
        for item in &ordered {
            terminal.update(item.bucket().get().to_be_bytes());
            terminal.update(item.ordinal().get().to_be_bytes());
            terminal.update(item.digest().as_bytes());
        }
        let terminal_digest = RealmUserUpdateTerminalEvidenceDigest::try_new(
            terminal.finalize().into(),
        )?;
        let mut value = Self {
            membership,
            fence,
            terminal_count: ordered.len() as u64,
            terminal_digest,
            digest: RealmUserUpdateQualificationDigest::try_new([1; 32])?,
        };
        value.digest = RealmUserUpdateQualificationDigest::try_new(
            value.compute_digest(key, close),
        )?;
        Ok(value)
    }

    pub const fn membership(self) -> RealmUserUpdateGenerationManifest {
        self.membership
    }

    pub const fn fence(&self) -> &RealmUserUpdateQualificationFence<Hash> {
        &self.fence
    }

    pub const fn terminal_count(self) -> u64 {
        self.terminal_count
    }

    pub const fn digest(self) -> RealmUserUpdateQualificationDigest {
        self.digest
    }

    fn compute_digest(
        &self,
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(QUALIFICATION_DOMAIN);
        encode_key(key, &mut hasher);
        hasher.update(close.as_bytes());
        hasher.update(self.membership.total().count().to_be_bytes());
        hasher.update(self.membership.total().digest());
        hasher.update(self.membership.digest().as_bytes());
        hasher.update(self.fence.pipeline_revision().get().to_be_bytes());
        hasher.update(self.fence.frontier().to_canonical_bytes());
        hasher.update(self.terminal_count.to_be_bytes());
        hasher.update(self.terminal_digest.as_bytes());
        hasher.finalize().into()
    }
}

fn membership_from_terminal_evidence(
    key: RealmUserUpdateAdmissionKey,
    ordered: &[RealmUserUpdateTerminalEvidence],
) -> Result<RealmUserUpdateGenerationManifest, RealmUserUpdateAdmissionError> {
    let mut manifests = Vec::with_capacity(RealmUserUpdateClaimBucket::COUNT as usize);
    let mut offset = 0usize;
    for index in 0..RealmUserUpdateClaimBucket::COUNT {
        let bucket = RealmUserUpdateClaimBucket::try_new(index).map_err(admission)?;
        let start = offset;
        while offset < ordered.len() && ordered[offset].bucket() == bucket {
            offset += 1;
        }
        let slice = &ordered[start..offset];
        let mut accepted = RealmUserUpdateAcceptedSet::EMPTY;
        let mut users = HashSet::with_capacity(slice.len());
        let mut hasher = Sha256::new();
        hasher.update(BUCKET_MANIFEST_DOMAIN);
        encode_key(key, &mut hasher);
        hasher.update(bucket.get().to_be_bytes());
        hasher.update((slice.len() as u64).to_be_bytes());
        for item in slice {
            let expected = accepted
                .count()
                .checked_add(1)
                .ok_or(RealmUserUpdateAdmissionError::CountOverflow)?;
            if item.ordinal().get() != expected || !users.insert(item.user_id().get()) {
                return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
            }
            let contribution = item.accepted_contribution();
            let mut aggregate = Sha256::new();
            aggregate.update(CONTRIBUTION_DOMAIN);
            aggregate.update(accepted.digest());
            aggregate.update(expected.to_be_bytes());
            aggregate.update(contribution);
            accepted = RealmUserUpdateAcceptedSet {
                count: expected,
                digest: aggregate.finalize().into(),
            };
            hasher.update(expected.to_be_bytes());
            hasher.update(item.user_id().get().to_be_bytes());
            hasher.update(contribution);
        }
        manifests.push(RealmUserUpdateBucketManifest {
            bucket,
            accepted,
            digest: RealmUserUpdateAdmissionManifestDigest::try_new(
                hasher.finalize().into(),
            )?,
        });
    }
    if offset != ordered.len() {
        return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
    }
    RealmUserUpdateGenerationManifest::from_buckets(&manifests)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmUserUpdateAdmissionRevision(u64);

impl RealmUserUpdateAdmissionRevision {
    pub const INITIAL: Self = Self(1);

    pub const fn get(self) -> u64 {
        self.0
    }

    pub fn as_i64(self) -> Result<i64, RealmUserUpdateAdmissionError> {
        i64::try_from(self.0)
            .map_err(|_| RealmUserUpdateAdmissionError::RevisionOutOfRange)
    }

    fn next(self) -> Result<Self, RealmUserUpdateAdmissionError> {
        let next = self
            .0
            .checked_add(1)
            .ok_or(RealmUserUpdateAdmissionError::RevisionOverflow)?;
        if next > i64::MAX as u64 {
            return Err(RealmUserUpdateAdmissionError::RevisionOutOfRange);
        }
        Ok(Self(next))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RealmUserUpdateAdmissionPhase {
    GenerationOpen = 1,
    GenerationClosing = 2,
    GenerationClosed = 3,
    BucketOpen = 4,
    BucketClaiming = 5,
    BucketBlocked = 6,
    BucketClosed = 7,
    BucketStable = 8,
    GenerationQualified = 9,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RealmUserUpdateAdmissionState<Hash> {
    GenerationOpen,
    GenerationClosing {
        close: RealmUserUpdateAdmissionCloseIntent,
    },
    GenerationClosed {
        close: RealmUserUpdateAdmissionCloseIntent,
        manifest: RealmUserUpdateGenerationManifest,
    },
    GenerationQualified {
        close: RealmUserUpdateAdmissionCloseIntent,
        manifest: RealmUserUpdateGenerationManifest,
        qualification: RealmUserUpdateGenerationQualification<Hash>,
    },
    BucketOpen {
        accepted: RealmUserUpdateAcceptedSet,
    },
    BucketClaiming {
        accepted: RealmUserUpdateAcceptedSet,
        candidate: StoredRealmUserUpdateClaim<Hash>,
    },
    BucketBlocked {
        accepted: RealmUserUpdateAcceptedSet,
        candidate: StoredRealmUserUpdateClaim<Hash>,
        observed_claim_digest: [u8; 32],
    },
    BucketClosed {
        accepted: RealmUserUpdateAcceptedSet,
        close: RealmUserUpdateAdmissionCloseIntent,
    },
    BucketStable {
        accepted: RealmUserUpdateAcceptedSet,
        close: RealmUserUpdateAdmissionCloseIntent,
        manifest: RealmUserUpdateBucketManifest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredRealmUserUpdateAdmission<Hash> {
    key: RealmUserUpdateAdmissionKey,
    shard: RealmUserUpdateAdmissionShard,
    revision: RealmUserUpdateAdmissionRevision,
    state: RealmUserUpdateAdmissionState<Hash>,
    state_digest: [u8; 32],
}

impl<Hash: Q256BitHash> StoredRealmUserUpdateAdmission<Hash> {
    pub fn generation_open(
        key: RealmUserUpdateAdmissionKey,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        Self::build(
            key,
            RealmUserUpdateAdmissionShard::Generation,
            RealmUserUpdateAdmissionRevision::INITIAL,
            RealmUserUpdateAdmissionState::GenerationOpen,
        )
    }

    pub fn generation_closing(
        key: RealmUserUpdateAdmissionKey,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        Self::build(
            key,
            RealmUserUpdateAdmissionShard::Generation,
            RealmUserUpdateAdmissionRevision::INITIAL,
            RealmUserUpdateAdmissionState::GenerationClosing { close },
        )
    }

    pub fn bucket_open(
        partition: RealmUserUpdateClaimPartition,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        Self::build(
            RealmUserUpdateAdmissionKey::try_new(partition.capture())?,
            RealmUserUpdateAdmissionShard::Bucket(partition.bucket()),
            RealmUserUpdateAdmissionRevision::INITIAL,
            RealmUserUpdateAdmissionState::BucketOpen {
                accepted: RealmUserUpdateAcceptedSet::EMPTY,
            },
        )
    }

    pub fn bucket_claiming(
        candidate: StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        if candidate.admission_ordinal().get() != 1 {
            return Err(RealmUserUpdateAdmissionError::AdmissionOrdinalMismatch);
        }
        let partition = candidate.partition().map_err(admission)?;
        Self::build(
            RealmUserUpdateAdmissionKey::try_new(partition.capture())?,
            RealmUserUpdateAdmissionShard::Bucket(partition.bucket()),
            RealmUserUpdateAdmissionRevision::INITIAL,
            RealmUserUpdateAdmissionState::BucketClaiming {
                accepted: RealmUserUpdateAcceptedSet::EMPTY,
                candidate,
            },
        )
    }

    pub fn bucket_closed(
        partition: RealmUserUpdateClaimPartition,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        Self::build(
            RealmUserUpdateAdmissionKey::try_new(partition.capture())?,
            RealmUserUpdateAdmissionShard::Bucket(partition.bucket()),
            RealmUserUpdateAdmissionRevision::INITIAL,
            RealmUserUpdateAdmissionState::BucketClosed {
                accepted: RealmUserUpdateAcceptedSet::EMPTY,
                close,
            },
        )
    }

    pub fn begin_generation_close(
        expected: &Self,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        if !matches!(expected.state, RealmUserUpdateAdmissionState::GenerationOpen) {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::GenerationClosing { close },
        )
    }

    pub fn begin_claim(
        expected: &Self,
        candidate: StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketOpen { accepted } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        expected.validate_candidate(&candidate)?;
        let expected_ordinal = accepted
            .count()
            .checked_add(1)
            .ok_or(RealmUserUpdateAdmissionError::CountOverflow)?;
        if candidate.admission_ordinal().get() != expected_ordinal {
            return Err(RealmUserUpdateAdmissionError::AdmissionOrdinalMismatch);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketClaiming {
                accepted,
                candidate,
            },
        )
    }

    pub fn finish_claim(
        expected: &Self,
        persisted: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketClaiming {
            accepted,
            ref candidate,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if !candidate
            .same_admitted_identity_as(persisted)
            .map_err(admission)?
        {
            return Err(RealmUserUpdateAdmissionError::ClaimConflict);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketOpen {
                accepted: accepted.include(persisted)?,
            },
        )
    }

    pub fn block_claim(
        expected: &Self,
        observed_claim_digest: [u8; 32],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketClaiming {
            accepted,
            ref candidate,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if observed_claim_digest == [0; 32] {
            return Err(RealmUserUpdateAdmissionError::EmptyDigest);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketBlocked {
                accepted,
                candidate: candidate.clone(),
                observed_claim_digest,
            },
        )
    }

    /// Release a losing reservation when another request for the same
    /// physical user row was already accepted in this bucket's committed
    /// prefix. This is the normal IF-NOT-EXISTS first-winner race, not storage
    /// corruption: the losing ordinal is discarded and the accepted set is
    /// left byte-for-byte unchanged.
    pub fn abandon_duplicate_claim(
        expected: &Self,
        winner: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketClaiming {
            accepted,
            ref candidate,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if candidate.partition().map_err(admission)?
            != winner.partition().map_err(admission)?
            || candidate.user_id() != winner.user_id()
            || winner.admission_ordinal().get() == 0
            || winner.admission_ordinal().get() > accepted.count()
        {
            return Err(RealmUserUpdateAdmissionError::ClaimConflict);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketOpen { accepted },
        )
    }

    pub fn close_bucket(
        expected: &Self,
        close: RealmUserUpdateAdmissionCloseIntent,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketOpen { accepted } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketClosed { accepted, close },
        )
    }

    pub fn stabilize_bucket(
        expected: &Self,
        close: RealmUserUpdateAdmissionCloseIntent,
        manifest: RealmUserUpdateBucketManifest,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::BucketClosed {
            accepted,
            close: expected_close,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if close != expected_close
            || manifest.accepted() != accepted
            || expected.shard
                != RealmUserUpdateAdmissionShard::Bucket(manifest.bucket())
        {
            return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::BucketStable {
                accepted,
                close,
                manifest,
            },
        )
    }

    pub fn close_generation(
        expected: &Self,
        close: RealmUserUpdateAdmissionCloseIntent,
        buckets: &[RealmUserUpdateBucketManifest],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::GenerationClosing {
            close: expected_close,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if close != expected_close {
            return Err(RealmUserUpdateAdmissionError::CloseIntentMismatch);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::GenerationClosed {
                close,
                manifest: RealmUserUpdateGenerationManifest::from_buckets(buckets)?,
            },
        )
    }

    pub fn qualify_generation(
        expected: &Self,
        close: RealmUserUpdateAdmissionCloseIntent,
        qualification: RealmUserUpdateGenerationQualification<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionState::GenerationClosed {
            close: expected_close,
            manifest,
        } = expected.state
        else {
            return Err(RealmUserUpdateAdmissionError::InvalidTransition);
        };
        if close != expected_close
            || qualification.membership() != manifest
            || qualification.compute_digest(expected.key, close)
                != *qualification.digest().as_bytes()
        {
            return Err(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch);
        }
        Self::build(
            expected.key,
            expected.shard,
            expected.revision.next()?,
            RealmUserUpdateAdmissionState::GenerationQualified {
                close,
                manifest,
                qualification,
            },
        )
    }

    pub const fn key(&self) -> RealmUserUpdateAdmissionKey {
        self.key
    }

    pub const fn shard(&self) -> RealmUserUpdateAdmissionShard {
        self.shard
    }

    pub const fn revision(&self) -> RealmUserUpdateAdmissionRevision {
        self.revision
    }

    pub const fn phase(&self) -> RealmUserUpdateAdmissionPhase {
        match self.state {
            RealmUserUpdateAdmissionState::GenerationOpen => {
                RealmUserUpdateAdmissionPhase::GenerationOpen
            }
            RealmUserUpdateAdmissionState::GenerationClosing { .. } => {
                RealmUserUpdateAdmissionPhase::GenerationClosing
            }
            RealmUserUpdateAdmissionState::GenerationClosed { .. } => {
                RealmUserUpdateAdmissionPhase::GenerationClosed
            }
            RealmUserUpdateAdmissionState::GenerationQualified { .. } => {
                RealmUserUpdateAdmissionPhase::GenerationQualified
            }
            RealmUserUpdateAdmissionState::BucketOpen { .. } => {
                RealmUserUpdateAdmissionPhase::BucketOpen
            }
            RealmUserUpdateAdmissionState::BucketClaiming { .. } => {
                RealmUserUpdateAdmissionPhase::BucketClaiming
            }
            RealmUserUpdateAdmissionState::BucketBlocked { .. } => {
                RealmUserUpdateAdmissionPhase::BucketBlocked
            }
            RealmUserUpdateAdmissionState::BucketClosed { .. } => {
                RealmUserUpdateAdmissionPhase::BucketClosed
            }
            RealmUserUpdateAdmissionState::BucketStable { .. } => {
                RealmUserUpdateAdmissionPhase::BucketStable
            }
        }
    }

    pub fn claiming_candidate(&self) -> Option<&StoredRealmUserUpdateClaim<Hash>> {
        match &self.state {
            RealmUserUpdateAdmissionState::BucketClaiming { candidate, .. }
            | RealmUserUpdateAdmissionState::BucketBlocked { candidate, .. } => {
                Some(candidate)
            }
            _ => None,
        }
    }

    pub const fn accepted_set(&self) -> Option<RealmUserUpdateAcceptedSet> {
        match self.state {
            RealmUserUpdateAdmissionState::BucketOpen { accepted }
            | RealmUserUpdateAdmissionState::BucketClaiming { accepted, .. }
            | RealmUserUpdateAdmissionState::BucketBlocked { accepted, .. }
            | RealmUserUpdateAdmissionState::BucketClosed { accepted, .. }
            | RealmUserUpdateAdmissionState::BucketStable { accepted, .. } => {
                Some(accepted)
            }
            _ => None,
        }
    }

    pub const fn close_intent(&self) -> Option<RealmUserUpdateAdmissionCloseIntent> {
        match self.state {
            RealmUserUpdateAdmissionState::GenerationClosing { close }
            | RealmUserUpdateAdmissionState::GenerationClosed { close, .. }
            | RealmUserUpdateAdmissionState::GenerationQualified { close, .. }
            | RealmUserUpdateAdmissionState::BucketClosed { close, .. }
            | RealmUserUpdateAdmissionState::BucketStable { close, .. } => {
                Some(close)
            }
            _ => None,
        }
    }

    pub const fn bucket_manifest(&self) -> Option<RealmUserUpdateBucketManifest> {
        match self.state {
            RealmUserUpdateAdmissionState::BucketStable { manifest, .. } => {
                Some(manifest)
            }
            _ => None,
        }
    }

    pub const fn generation_manifest(
        &self,
    ) -> Option<RealmUserUpdateGenerationManifest> {
        match self.state {
            RealmUserUpdateAdmissionState::GenerationClosed { manifest, .. }
            | RealmUserUpdateAdmissionState::GenerationQualified { manifest, .. } => Some(manifest),
            _ => None,
        }
    }

    pub const fn generation_qualification(
        &self,
    ) -> Option<&RealmUserUpdateGenerationQualification<Hash>> {
        match &self.state {
            RealmUserUpdateAdmissionState::GenerationQualified {
                qualification,
                ..
            } => Some(qualification),
            _ => None,
        }
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = self.encode_without_digest();
        bytes.extend_from_slice(&self.state_digest);
        bytes
    }

    pub fn decode_selected(
        selected_key: RealmUserUpdateAdmissionKey,
        selected_shard: i16,
        selected_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != MAGIC {
            return Err(RealmUserUpdateAdmissionError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(RealmUserUpdateAdmissionError::UnknownCodecVersion);
        }
        let key = decode_key(&mut decoder)?;
        let shard = RealmUserUpdateAdmissionShard::try_from_i16(decoder.i16()?)?;
        let revision = RealmUserUpdateAdmissionRevision(decoder.u64()?);
        let phase = decoder.u8()?;
        let state = match phase {
            1 => RealmUserUpdateAdmissionState::GenerationOpen,
            2 => RealmUserUpdateAdmissionState::GenerationClosing {
                close: RealmUserUpdateAdmissionCloseIntent::try_new(decoder.array32()?)?,
            },
            3 => RealmUserUpdateAdmissionState::GenerationClosed {
                close: RealmUserUpdateAdmissionCloseIntent::try_new(decoder.array32()?)?,
                manifest: decode_generation_manifest(&mut decoder)?,
            },
            4 => RealmUserUpdateAdmissionState::BucketOpen {
                accepted: decode_accepted(&mut decoder)?,
            },
            5 | 6 => {
                let accepted = decode_accepted(&mut decoder)?;
                let user = UserId::new(decoder.u64()?);
                let claim_revision = i64::try_from(decoder.u64()?)
                    .map_err(|_| RealmUserUpdateAdmissionError::RevisionOutOfRange)?;
                let claim_bytes = decoder.bytes()?;
                let RealmUserUpdateAdmissionShard::Bucket(bucket) = shard else {
                    return Err(RealmUserUpdateAdmissionError::ShardPhaseMismatch);
                };
                let candidate = StoredRealmUserUpdateClaim::decode_selected(
                    RealmUserUpdateClaimPartition::try_new(key.capture(), bucket)
                        .map_err(admission)?,
                    i64::try_from(user.get())
                        .map_err(|_| RealmUserUpdateAdmissionError::UserOutOfRange)?,
                    claim_revision,
                    &claim_bytes,
                )
                .map_err(admission)?;
                if phase == 5 {
                    RealmUserUpdateAdmissionState::BucketClaiming {
                        accepted,
                        candidate,
                    }
                } else {
                    RealmUserUpdateAdmissionState::BucketBlocked {
                        accepted,
                        candidate,
                        observed_claim_digest: decoder.array32()?,
                    }
                }
            }
            7 => RealmUserUpdateAdmissionState::BucketClosed {
                accepted: decode_accepted(&mut decoder)?,
                close: RealmUserUpdateAdmissionCloseIntent::try_new(decoder.array32()?)?,
            },
            8 => RealmUserUpdateAdmissionState::BucketStable {
                accepted: decode_accepted(&mut decoder)?,
                close: RealmUserUpdateAdmissionCloseIntent::try_new(decoder.array32()?)?,
                manifest: decode_bucket_manifest(&mut decoder)?,
            },
            9 => {
                let close = RealmUserUpdateAdmissionCloseIntent::try_new(
                    decoder.array32()?,
                )?;
                let manifest = decode_generation_manifest(&mut decoder)?;
                RealmUserUpdateAdmissionState::GenerationQualified {
                    close,
                    manifest,
                    qualification: decode_generation_qualification(
                        key,
                        close,
                        manifest,
                        &mut decoder,
                    )?,
                }
            }
            other => return Err(RealmUserUpdateAdmissionError::UnknownPhase(other)),
        };
        let state_digest = decoder.array32()?;
        if !decoder.done() {
            return Err(RealmUserUpdateAdmissionError::TrailingBytes);
        }
        let value = Self {
            key,
            shard,
            revision,
            state,
            state_digest,
        };
        if selected_key != key
            || selected_shard != shard.as_i16()?
            || selected_revision != revision.as_i64()?
            || revision.get() == 0
            || value.compute_state_digest() != state_digest
        {
            return Err(RealmUserUpdateAdmissionError::SelectedIdentityMismatch);
        }
        value.validate_shape()?;
        Ok(value)
    }

    fn build(
        key: RealmUserUpdateAdmissionKey,
        shard: RealmUserUpdateAdmissionShard,
        revision: RealmUserUpdateAdmissionRevision,
        state: RealmUserUpdateAdmissionState<Hash>,
    ) -> Result<Self, RealmUserUpdateAdmissionError> {
        let mut value = Self {
            key,
            shard,
            revision,
            state,
            state_digest: [1; 32],
        };
        value.validate_shape()?;
        value.state_digest = value.compute_state_digest();
        Ok(value)
    }

    fn validate_candidate(
        &self,
        candidate: &StoredRealmUserUpdateClaim<Hash>,
    ) -> Result<(), RealmUserUpdateAdmissionError> {
        let RealmUserUpdateAdmissionShard::Bucket(bucket) = self.shard else {
            return Err(RealmUserUpdateAdmissionError::ShardPhaseMismatch);
        };
        let partition = candidate.partition().map_err(admission)?;
        if partition.capture() != self.key.capture() || partition.bucket() != bucket {
            return Err(RealmUserUpdateAdmissionError::ClaimSetMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), RealmUserUpdateAdmissionError> {
        match (&self.shard, &self.state) {
            (
                RealmUserUpdateAdmissionShard::Generation,
                RealmUserUpdateAdmissionState::GenerationQualified {
                    close,
                    manifest,
                    qualification,
                },
            ) => {
                if qualification.membership() != *manifest
                    || qualification.compute_digest(self.key, *close)
                        != *qualification.digest().as_bytes()
                    || qualification.fence().frontier().authority()
                        != self.key.capture().key().authority()
                    || qualification.fence().frontier().chain().network_id()
                        != self.key.capture().key().network()
                {
                    Err(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch)
                } else {
                    Ok(())
                }
            }
            (
                RealmUserUpdateAdmissionShard::Generation,
                RealmUserUpdateAdmissionState::GenerationOpen
                | RealmUserUpdateAdmissionState::GenerationClosing { .. }
                | RealmUserUpdateAdmissionState::GenerationClosed { .. },
            ) => Ok(()),
            (
                RealmUserUpdateAdmissionShard::Bucket(_),
                RealmUserUpdateAdmissionState::BucketOpen { .. }
                | RealmUserUpdateAdmissionState::BucketClaiming { .. }
                | RealmUserUpdateAdmissionState::BucketBlocked { .. }
                | RealmUserUpdateAdmissionState::BucketClosed { .. }
                | RealmUserUpdateAdmissionState::BucketStable { .. },
            ) => {
                if let Some(candidate) = self.claiming_candidate() {
                    self.validate_candidate(candidate)?;
                }
                Ok(())
            }
            _ => Err(RealmUserUpdateAdmissionError::ShardPhaseMismatch),
        }
    }

    fn encode_without_digest(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        encode_key_bytes(self.key, &mut out);
        out.extend_from_slice(
            &self
                .shard
                .as_i16()
                .expect("validated shard must remain encodable")
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.revision.get().to_be_bytes());
        out.push(self.phase() as u8);
        match &self.state {
            RealmUserUpdateAdmissionState::GenerationOpen => {}
            RealmUserUpdateAdmissionState::GenerationClosing { close } => {
                out.extend_from_slice(close.as_bytes());
            }
            RealmUserUpdateAdmissionState::GenerationClosed { close, manifest } => {
                out.extend_from_slice(close.as_bytes());
                encode_generation_manifest(*manifest, &mut out);
            }
            RealmUserUpdateAdmissionState::GenerationQualified {
                close,
                manifest,
                qualification,
            } => {
                out.extend_from_slice(close.as_bytes());
                encode_generation_manifest(*manifest, &mut out);
                encode_generation_qualification(qualification, &mut out);
            }
            RealmUserUpdateAdmissionState::BucketOpen { accepted } => {
                encode_accepted(*accepted, &mut out);
            }
            RealmUserUpdateAdmissionState::BucketClaiming {
                accepted,
                candidate,
            } => {
                encode_accepted(*accepted, &mut out);
                encode_candidate(candidate, &mut out);
            }
            RealmUserUpdateAdmissionState::BucketBlocked {
                accepted,
                candidate,
                observed_claim_digest,
            } => {
                encode_accepted(*accepted, &mut out);
                encode_candidate(candidate, &mut out);
                out.extend_from_slice(observed_claim_digest);
            }
            RealmUserUpdateAdmissionState::BucketClosed { accepted, close } => {
                encode_accepted(*accepted, &mut out);
                out.extend_from_slice(close.as_bytes());
            }
            RealmUserUpdateAdmissionState::BucketStable {
                accepted,
                close,
                manifest,
            } => {
                encode_accepted(*accepted, &mut out);
                out.extend_from_slice(close.as_bytes());
                encode_bucket_manifest(*manifest, &mut out);
            }
        }
        out
    }

    fn compute_state_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(STATE_DOMAIN);
        hasher.update(self.encode_without_digest());
        hasher.finalize().into()
    }
}

fn claim_contribution<Hash: Q256BitHash>(
    claim: &StoredRealmUserUpdateClaim<Hash>,
) -> Result<[u8; 32], RealmUserUpdateAdmissionError> {
    let mut hasher = Sha256::new();
    hasher.update(CONTRIBUTION_DOMAIN);
    hasher.update(claim.user_id().get().to_be_bytes());
    hasher.update(claim.admission_commitment().map_err(admission)?.as_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        Err(RealmUserUpdateAdmissionError::EmptyDigest)
    } else {
        Ok(digest)
    }
}

fn encode_key(hasher_key: RealmUserUpdateAdmissionKey, hasher: &mut Sha256) {
    let mut bytes = Vec::with_capacity(67);
    encode_key_bytes(hasher_key, &mut bytes);
    hasher.update(bytes);
}

fn encode_key_bytes(key: RealmUserUpdateAdmissionKey, out: &mut Vec<u8>) {
    let capture = key.capture();
    out.extend_from_slice(&capture.key().network().chain_id().to_be_bytes());
    let AuthorityScope::Realm {
        realm_id,
        realm_sub_id,
    } = capture.key().authority()
    else {
        unreachable!("admission key constructor requires Realm")
    };
    out.push(1);
    out.extend_from_slice(&realm_id.to_be_bytes());
    out.extend_from_slice(&realm_sub_id.to_be_bytes());
    out.extend_from_slice(capture.activation().as_bytes());
    out.extend_from_slice(&capture.processing().pending_id().get().to_be_bytes());
    out.extend_from_slice(capture.processing().proc_checkpoint_id().as_bytes());
}

fn decode_key(
    decoder: &mut Decoder<'_>,
) -> Result<RealmUserUpdateAdmissionKey, RealmUserUpdateAdmissionError> {
    let network = NetworkId::try_from_chain_id(decoder.u32()?)
        .map_err(|_| RealmUserUpdateAdmissionError::InvalidKey)?;
    if decoder.u8()? != 1 {
        return Err(RealmUserUpdateAdmissionError::RealmOnly);
    }
    let authority = AuthorityScope::Realm {
        realm_id: decoder.u32()?,
        realm_sub_id: decoder.u16()?,
    };
    let activation = PendingGenerationActivationDigest::try_new(decoder.array32()?)
        .map_err(admission)?;
    let processing = PendingGenerationContext::try_from_legacy(
        decoder.u64()?,
        u128::from_be_bytes(decoder.array16()?),
    )
    .map_err(admission)?;
    RealmUserUpdateAdmissionKey::try_new(
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(network, authority),
            activation,
            processing,
        )
        .map_err(admission)?,
    )
}

fn encode_accepted(value: RealmUserUpdateAcceptedSet, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.count.to_be_bytes());
    out.extend_from_slice(&value.digest);
}

fn decode_accepted(
    decoder: &mut Decoder<'_>,
) -> Result<RealmUserUpdateAcceptedSet, RealmUserUpdateAdmissionError> {
    Ok(RealmUserUpdateAcceptedSet {
        count: decoder.u64()?,
        digest: decoder.array32()?,
    })
}

fn encode_candidate<Hash: Q256BitHash>(
    candidate: &StoredRealmUserUpdateClaim<Hash>,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&candidate.user_id().get().to_be_bytes());
    out.extend_from_slice(&candidate.revision().get().to_be_bytes());
    let bytes = candidate.to_canonical_bytes();
    let length = u32::try_from(bytes.len())
        .expect("validated claim is bounded by its fixed codec");
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&bytes);
}

fn encode_bucket_manifest(value: RealmUserUpdateBucketManifest, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.bucket.get().to_be_bytes());
    encode_accepted(value.accepted, out);
    out.extend_from_slice(value.digest.as_bytes());
}

fn decode_bucket_manifest(
    decoder: &mut Decoder<'_>,
) -> Result<RealmUserUpdateBucketManifest, RealmUserUpdateAdmissionError> {
    Ok(RealmUserUpdateBucketManifest {
        bucket: RealmUserUpdateClaimBucket::try_new(decoder.u16()?)
            .map_err(admission)?,
        accepted: decode_accepted(decoder)?,
        digest: RealmUserUpdateAdmissionManifestDigest::try_new(decoder.array32()?)?,
    })
}

fn encode_generation_manifest(
    value: RealmUserUpdateGenerationManifest,
    out: &mut Vec<u8>,
) {
    encode_accepted(value.total, out);
    out.extend_from_slice(value.digest.as_bytes());
}

fn decode_generation_manifest(
    decoder: &mut Decoder<'_>,
) -> Result<RealmUserUpdateGenerationManifest, RealmUserUpdateAdmissionError> {
    Ok(RealmUserUpdateGenerationManifest {
        total: decode_accepted(decoder)?,
        digest: RealmUserUpdateAdmissionManifestDigest::try_new(decoder.array32()?)?,
    })
}

fn encode_generation_qualification<Hash: Q256BitHash>(
    value: &RealmUserUpdateGenerationQualification<Hash>,
    out: &mut Vec<u8>,
) {
    encode_generation_manifest(value.membership, out);
    out.extend_from_slice(&value.fence.pipeline_revision().get().to_be_bytes());
    out.extend_from_slice(&value.fence.frontier().to_canonical_bytes());
    out.extend_from_slice(&value.terminal_count.to_be_bytes());
    out.extend_from_slice(value.terminal_digest.as_bytes());
    out.extend_from_slice(value.digest.as_bytes());
}

fn decode_generation_qualification<Hash: Q256BitHash>(
    key: RealmUserUpdateAdmissionKey,
    close: RealmUserUpdateAdmissionCloseIntent,
    expected_membership: RealmUserUpdateGenerationManifest,
    decoder: &mut Decoder<'_>,
) -> Result<RealmUserUpdateGenerationQualification<Hash>, RealmUserUpdateAdmissionError> {
    let membership = decode_generation_manifest(decoder)?;
    let pipeline_revision = PendingPipelineRevision::try_new(decoder.u64()?)
        .map_err(admission)?;
    let frontier = AuthorityObservation::from_canonical_bytes(
        decoder.take(AUTHORITY_OBSERVATION_V1_LEN)?,
    )
    .map_err(admission)?;
    let value = RealmUserUpdateGenerationQualification {
        membership,
        fence: RealmUserUpdateQualificationFence {
            pipeline_revision,
            frontier,
        },
        terminal_count: decoder.u64()?,
        terminal_digest: RealmUserUpdateTerminalEvidenceDigest::try_new(
            decoder.array32()?,
        )?,
        digest: RealmUserUpdateQualificationDigest::try_new(decoder.array32()?)?,
    };
    if membership != expected_membership
        || value.terminal_count != membership.total().count()
        || value.compute_digest(key, close) != *value.digest.as_bytes()
    {
        return Err(RealmUserUpdateAdmissionError::TerminalEvidenceMismatch);
    }
    Ok(value)
}

fn admission(error: impl fmt::Display) -> RealmUserUpdateAdmissionError {
    RealmUserUpdateAdmissionError::Nested(error.to_string())
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], RealmUserUpdateAdmissionError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(RealmUserUpdateAdmissionError::MalformedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(RealmUserUpdateAdmissionError::MalformedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, RealmUserUpdateAdmissionError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, RealmUserUpdateAdmissionError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn i16(&mut self) -> Result<i16, RealmUserUpdateAdmissionError> {
        Ok(i16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, RealmUserUpdateAdmissionError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, RealmUserUpdateAdmissionError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array16(&mut self) -> Result<[u8; 16], RealmUserUpdateAdmissionError> {
        Ok(self.take(16)?.try_into().unwrap())
    }

    fn array32(&mut self) -> Result<[u8; 32], RealmUserUpdateAdmissionError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, RealmUserUpdateAdmissionError> {
        let length = self.u32()? as usize;
        if length == 0 || length > MAX_CLAIM_PAYLOAD_BYTES {
            return Err(RealmUserUpdateAdmissionError::MalformedPayload);
        }
        Ok(self.take(length)?.to_vec())
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmUserUpdateAdmissionError {
    EmptyDigest,
    RealmOnly,
    InvalidKey,
    InvalidShard,
    ShardPhaseMismatch,
    InvalidTransition,
    CloseIntentMismatch,
    ClaimConflict,
    ClaimSetMismatch,
    TerminalEvidenceMismatch,
    PipelineFenceMismatch,
    AdmissionOrdinalMismatch,
    IncompleteBucketSet,
    CountOverflow,
    RevisionOverflow,
    RevisionOutOfRange,
    UserOutOfRange,
    InvalidMagic,
    UnknownCodecVersion,
    UnknownPhase(u8),
    MalformedPayload,
    TrailingBytes,
    SelectedIdentityMismatch,
    Nested(String),
}

impl fmt::Display for RealmUserUpdateAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmUserUpdateAdmissionError {}

#[cfg(test)]
mod tests {
    use parth_core::{utils::QPGenRandom, PF, PHash};
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
            AuthorityStateRoot, PendingContext, WorkProcCheckpointUniqueId,
            WorkUniquePendingId,
        },
    };
    use psy_data::queue_items::realm_user_update::PsyRealmUserUpdateQueueItem;

    use super::*;
    use crate::{
        queue::{
            realm_user_update_claim::{
                RealmUserUpdateAdmissionOrdinal, RealmUserUpdateCreatedAtSeconds,
                StoredRealmUserUpdateClaim,
            },
            realm_user_update_publish::{
                GlobalUserTreeHeight, RealmUserUpdatePublishAdmission,
                RealmUserUpdatePublishReceipt, RealmUserUpdatePublishRequest,
                RealmUserUpdateRequestDigest,
            },
        },
        store::{
            pending_generation::ProcNamespacePrefix,
            pending_generation_identity::PendingGenerationBootstrapReason,
            pending_generation_pipeline::PendingPipelineBootstrap,
            typed::UniquePendingId,
        },
    };

    fn admission(epoch: u64) -> RealmUserUpdatePublishAdmission<PHash> {
        let network = NetworkId::try_from_chain_id(1337).unwrap();
        let authority = AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        };
        let pending = PendingContext::new(
            CanonicalChainRef::new(
                network,
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(10 + epoch),
                    CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([
                        epoch as u8;
                        32
                    ])),
                ),
            ),
            authority,
            WorkUniquePendingId::new(11),
            WorkProcCheckpointUniqueId::from_u128(12),
        );
        RealmUserUpdatePublishAdmission::try_from_pipeline(
            pending,
            PendingQueueCaptureContext::try_new(
                PendingGenerationLedgerKey::new(network, authority),
                PendingGenerationActivationDigest::try_new([9; 32]).unwrap(),
                PendingGenerationContext::try_from_legacy(
                    UniquePendingId::try_new(11).unwrap().get(),
                    12,
                )
                .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn claim(
        epoch: u64,
        user: u64,
        ordinal: u64,
    ) -> StoredRealmUserUpdateClaim<PHash> {
        StoredRealmUserUpdateClaim::claimed(
            admission(epoch),
            UserId::new(user),
            RealmUserUpdateRequestDigest::derive(
                &[epoch as u8, user as u8],
                &[user as u8, epoch as u8],
            )
            .unwrap(),
            RealmUserUpdateCreatedAtSeconds::try_new(100 + epoch as u32).unwrap(),
            RealmUserUpdateAdmissionOrdinal::try_new(ordinal).unwrap(),
        )
        .unwrap()
    }

    fn pipeline(epoch: u64) -> PendingPipelineBootstrap<PHash> {
        let admission = admission(epoch);
        let key = admission.capture().key();
        let authority = key.authority();
        let frontier = AuthorityObservation::try_new(
            *admission.pending().chain(),
            authority,
            AuthorityStateCheckpointId::new(10 + epoch),
            AuthorityStateRoot::from_local_state_root(PHash::from_owned_32bytes([
                7 + epoch as u8;
                32
            ])),
        )
        .unwrap();
        PendingPipelineBootstrap::try_new(
            key,
            admission.capture().activation(),
            ProcNamespacePrefix::for_authority(key.network(), authority),
            PendingGenerationBootstrapReason::LegacyActivation,
            PendingGenerationContext::try_from_legacy(10, 10).unwrap(),
            admission.capture().processing(),
            frontier,
            10,
        )
        .unwrap()
    }

    fn queue_item(
        claim: &StoredRealmUserUpdateClaim<PHash>,
    ) -> PsyRealmUserUpdateQueueItem<PF, PHash> {
        let mut item = PsyRealmUserUpdateQueueItem::<PF, PHash>::qp_rand_gen();
        item.job_id = psy_core::job::job_id::QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            claim.user_id().get(),
            32,
            claim.pending().unique_pending_id().get(),
        )
        .unwrap();
        item.expected_fake_checkpoint_id = claim.stable_status();
        item
    }

    fn all_bucket_manifests(
        key: RealmUserUpdateAdmissionKey,
        claims: &[StoredRealmUserUpdateClaim<PHash>],
    ) -> Vec<RealmUserUpdateBucketManifest> {
        (0..RealmUserUpdateClaimBucket::COUNT)
            .map(|index| {
                let bucket = RealmUserUpdateClaimBucket::try_new(index).unwrap();
                let bucket_claims = claims
                    .iter()
                    .filter(|claim| claim.bucket() == bucket)
                    .cloned()
                    .collect::<Vec<_>>();
                RealmUserUpdateBucketManifest::from_claims(
                    RealmUserUpdateClaimPartition::try_new(key.capture(), bucket)
                        .unwrap(),
                    &bucket_claims,
                )
                .unwrap()
            })
            .collect()
    }

    fn another_user_in_same_bucket(user: u64) -> u64 {
        let bucket = RealmUserUpdateClaimBucket::for_user(UserId::new(user));
        ((user + 1)..100_000)
            .find(|candidate| {
                RealmUserUpdateClaimBucket::for_user(UserId::new(*candidate))
                    == bucket
            })
            .expect("test search must find a bucket collision")
    }

    #[test]
    fn claim_reservation_is_crash_recoverable_and_set_exact() {
        let first = claim(1, 13, 1);
        let second = claim(2, another_user_in_same_bucket(13), 2);
        assert_eq!(first.partition().unwrap(), second.partition().unwrap());
        assert_ne!(first.slot(), second.slot());

        let open = StoredRealmUserUpdateAdmission::bucket_open(
            first.partition().unwrap(),
        )
        .unwrap();
        let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, first.clone())
            .unwrap();
        let bytes = claiming.to_canonical_bytes();
        assert_eq!(
            StoredRealmUserUpdateAdmission::decode_selected(
                claiming.key(),
                claiming.shard().as_i16().unwrap(),
                claiming.revision().as_i64().unwrap(),
                &bytes,
            )
            .unwrap(),
            claiming
        );
        assert_eq!(claiming.claiming_candidate(), Some(&first));
        assert!(StoredRealmUserUpdateAdmission::close_bucket(
            &claiming,
            RealmUserUpdateAdmissionCloseIntent::derive(
                claiming.key(),
                [7; 32],
            )
            .unwrap(),
        )
        .is_err());

        let open = StoredRealmUserUpdateAdmission::finish_claim(&claiming, &first)
            .unwrap();
        let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, second.clone())
            .unwrap();
        let open = StoredRealmUserUpdateAdmission::finish_claim(&claiming, &second)
            .unwrap();
        assert_eq!(open.accepted_set().unwrap().count(), 2);

        let close = RealmUserUpdateAdmissionCloseIntent::derive(open.key(), [8; 32])
            .unwrap();
        let closed = StoredRealmUserUpdateAdmission::close_bucket(&open, close).unwrap();
        let manifest = RealmUserUpdateBucketManifest::from_claims(
            first.partition().unwrap(),
            &[second.clone(), first.clone()],
        )
        .unwrap();
        let stable = StoredRealmUserUpdateAdmission::stabilize_bucket(
            &closed,
            close,
            manifest,
        )
        .unwrap();
        assert_eq!(stable.phase(), RealmUserUpdateAdmissionPhase::BucketStable);
        assert!(StoredRealmUserUpdateAdmission::begin_claim(&stable, first).is_err());
    }

    #[test]
    fn duplicate_user_first_winner_releases_losing_reservation() {
        let winner = claim(1, 13, 1);
        let open = StoredRealmUserUpdateAdmission::bucket_open(
            winner.partition().unwrap(),
        )
        .unwrap();
        let claiming =
            StoredRealmUserUpdateAdmission::begin_claim(&open, winner.clone())
                .unwrap();
        let open =
            StoredRealmUserUpdateAdmission::finish_claim(&claiming, &winner)
                .unwrap();

        let losing_request = claim(2, 13, 2);
        let losing = StoredRealmUserUpdateAdmission::begin_claim(
            &open,
            losing_request,
        )
        .unwrap();
        let recovered =
            StoredRealmUserUpdateAdmission::abandon_duplicate_claim(
                &losing,
                &winner,
            )
            .unwrap();
        assert_eq!(recovered.phase(), RealmUserUpdateAdmissionPhase::BucketOpen);
        assert_eq!(recovered.accepted_set(), open.accepted_set());

        let unrelated = claim(1, another_user_in_same_bucket(13), 1);
        assert!(StoredRealmUserUpdateAdmission::abandon_duplicate_claim(
            &losing,
            &unrelated,
        )
        .is_err());
    }

    #[test]
    fn reservation_requires_the_exact_next_ordinal() {
        let first = claim(1, 13, 1);
        let skipped = claim(1, 13, 2);
        let open = StoredRealmUserUpdateAdmission::<PHash>::bucket_open(
            first.partition().unwrap(),
        )
        .unwrap();
        assert!(matches!(
            StoredRealmUserUpdateAdmission::begin_claim(&open, skipped),
            Err(RealmUserUpdateAdmissionError::AdmissionOrdinalMismatch)
        ));

        let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, first.clone())
            .unwrap();
        let open = StoredRealmUserUpdateAdmission::finish_claim(&claiming, &first)
            .unwrap();
        let wrong_next = claim(2, another_user_in_same_bucket(13), 3);
        assert!(matches!(
            StoredRealmUserUpdateAdmission::begin_claim(&open, wrong_next),
            Err(RealmUserUpdateAdmissionError::AdmissionOrdinalMismatch)
        ));
    }

    #[test]
    fn mutable_claim_phase_preserves_membership_and_gate_recovery() {
        use crate::queue::realm_user_update_claim::{
            RealmUserUpdateDependencyDigest, RealmUserUpdatePublishReceiptDigest,
        };

        let first = claim(1, 13, 1);
        let open = StoredRealmUserUpdateAdmission::<PHash>::bucket_open(
            first.partition().unwrap(),
        )
        .unwrap();
        let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, first.clone())
            .unwrap();
        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &first,
            RealmUserUpdateDependencyDigest::try_new([4; 32]).unwrap(),
        )
        .unwrap();
        let ready = StoredRealmUserUpdateClaim::dependencies_ready(&planned).unwrap();
        let published = StoredRealmUserUpdateClaim::published(
            &ready,
            RealmUserUpdatePublishReceiptDigest::try_new([5; 32]).unwrap(),
        )
        .unwrap();
        assert!(first.same_admitted_identity_as(&published).unwrap());
        let reopened = StoredRealmUserUpdateAdmission::finish_claim(
            &claiming,
            &published,
        )
        .unwrap();
        assert_eq!(reopened.accepted_set().unwrap().count(), 1);

        let initial_manifest = RealmUserUpdateBucketManifest::from_claims(
            first.partition().unwrap(),
            &[first],
        )
        .unwrap();
        let terminal_manifest = RealmUserUpdateBucketManifest::from_claims(
            published.partition().unwrap(),
            &[published],
        )
        .unwrap();
        assert_eq!(initial_manifest, terminal_manifest);
    }

    #[test]
    fn missing_extra_or_duplicate_claim_cannot_match_closed_set() {
        let first = claim(1, 13, 1);
        let open = StoredRealmUserUpdateAdmission::bucket_open(
            first.partition().unwrap(),
        )
        .unwrap();
        let claiming = StoredRealmUserUpdateAdmission::begin_claim(&open, first.clone())
            .unwrap();
        let open = StoredRealmUserUpdateAdmission::finish_claim(&claiming, &first)
            .unwrap();
        let close = RealmUserUpdateAdmissionCloseIntent::derive(open.key(), [8; 32])
            .unwrap();
        let closed = StoredRealmUserUpdateAdmission::close_bucket(&open, close).unwrap();
        let missing = RealmUserUpdateBucketManifest::from_claims::<PHash>(
            first.partition().unwrap(),
            &[],
        )
        .unwrap();
        assert!(StoredRealmUserUpdateAdmission::stabilize_bucket(
            &closed,
            close,
            missing,
        )
        .is_err());
        let duplicate_claim = claim(1, 13, 1);
        assert!(RealmUserUpdateBucketManifest::from_claims(
            duplicate_claim.partition().unwrap(),
            &[duplicate_claim.clone(), duplicate_claim],
        )
        .is_err());
    }

    #[test]
    fn generation_requires_all_256_stable_bucket_manifests() {
        let sample = claim(1, 13, 1);
        let key = RealmUserUpdateAdmissionKey::try_new(
            sample.partition().unwrap().capture(),
        )
        .unwrap();
        let open = StoredRealmUserUpdateAdmission::<PHash>::generation_open(key).unwrap();
        let close = RealmUserUpdateAdmissionCloseIntent::derive(key, [3; 32]).unwrap();
        let closing = StoredRealmUserUpdateAdmission::begin_generation_close(&open, close)
            .unwrap();
        let mut manifests = Vec::new();
        for bucket in 0..RealmUserUpdateClaimBucket::COUNT {
            manifests.push(
                RealmUserUpdateBucketManifest::from_claims::<PHash>(
                    RealmUserUpdateClaimPartition::try_new(
                        key.capture(),
                        RealmUserUpdateClaimBucket::try_new(bucket).unwrap(),
                    )
                    .unwrap(),
                    &[],
                )
                .unwrap(),
            );
        }
        assert!(StoredRealmUserUpdateAdmission::close_generation(
            &closing,
            close,
            &manifests[..255],
        )
        .is_err());
        let closed = StoredRealmUserUpdateAdmission::close_generation(
            &closing,
            close,
            &manifests,
        )
        .unwrap();
        assert_eq!(closed.phase(), RealmUserUpdateAdmissionPhase::GenerationClosed);
        assert!(StoredRealmUserUpdateAdmission::begin_generation_close(&closed, close).is_err());
    }

    #[test]
    fn qualification_requires_exact_published_terminal_evidence_and_fence() {
        let claimed = claim(1, 13, 1);
        let key = RealmUserUpdateAdmissionKey::try_new(
            claimed.partition().unwrap().capture(),
        )
        .unwrap();
        let fence = RealmUserUpdateQualificationFence::try_from_pipeline(
            key,
            pipeline(1).candidate(),
        )
        .unwrap();
        let request = RealmUserUpdatePublishRequest::try_new(
            claimed.reconstruct_admission().unwrap(),
            claimed.user_id(),
            claimed.request_digest(),
            GlobalUserTreeHeight::try_new(32).unwrap(),
            queue_item(&claimed),
        )
        .unwrap();
        let receipt = RealmUserUpdatePublishReceipt::durable(
            request.intent_id(),
            [6; 32],
            9,
            [8; 32],
            false,
        )
        .unwrap();
        assert!(RealmUserUpdateTerminalEvidence::try_from_observed(
            key,
            &fence,
            &claimed,
            &request,
            &receipt,
        )
        .is_err());

        let planned = StoredRealmUserUpdateClaim::dependencies_planned(
            &claimed,
            RealmUserUpdateDependencyDigest::try_new([4; 32]).unwrap(),
        )
        .unwrap();
        let ready = StoredRealmUserUpdateClaim::dependencies_ready(&planned).unwrap();
        let published = StoredRealmUserUpdateClaim::published(
            &ready,
            RealmUserUpdatePublishReceiptDigest::try_new(
                *receipt.receipt_digest(),
            )
            .unwrap(),
        )
        .unwrap();
        let evidence = RealmUserUpdateTerminalEvidence::try_from_observed(
            key,
            &fence,
            &published,
            &request,
            &receipt,
        )
        .unwrap();
        let wrong_receipt = RealmUserUpdatePublishReceipt::durable(
            request.intent_id(),
            [6; 32],
            10,
            [8; 32],
            true,
        )
        .unwrap();
        assert!(RealmUserUpdateTerminalEvidence::try_from_observed(
            key,
            &fence,
            &published,
            &request,
            &wrong_receipt,
        )
        .is_err());

        let manifests = all_bucket_manifests(key, &[published.clone()]);
        let membership = RealmUserUpdateGenerationManifest::from_buckets(&manifests)
            .unwrap();
        let close = RealmUserUpdateAdmissionCloseIntent::derive(key, [3; 32]).unwrap();
        let open = StoredRealmUserUpdateAdmission::<PHash>::generation_open(key).unwrap();
        let closing = StoredRealmUserUpdateAdmission::begin_generation_close(&open, close)
            .unwrap();
        let closed = StoredRealmUserUpdateAdmission::close_generation(
            &closing,
            close,
            &manifests,
        )
        .unwrap();
        let qualification = RealmUserUpdateGenerationQualification::from_terminal_evidence(
            key,
            close,
            membership,
            fence,
            &[evidence],
        )
        .unwrap();
        let qualified = StoredRealmUserUpdateAdmission::qualify_generation(
            &closed,
            close,
            qualification,
        )
        .unwrap();
        assert_eq!(
            qualified.phase(),
            RealmUserUpdateAdmissionPhase::GenerationQualified
        );
        assert_eq!(qualified.generation_manifest(), Some(membership));
        assert_eq!(
            qualified
                .generation_qualification()
                .unwrap()
                .terminal_count(),
            1
        );
        assert!(qualified
            .generation_qualification()
            .unwrap()
            .fence()
            .matches_pipeline(key, pipeline(1).candidate()));

        let encoded = qualified.to_canonical_bytes();
        assert_eq!(
            StoredRealmUserUpdateAdmission::decode_selected(
                qualified.key(),
                qualified.shard().as_i16().unwrap(),
                qualified.revision().as_i64().unwrap(),
                &encoded,
            )
            .unwrap(),
            qualified
        );
    }

    #[test]
    fn qualification_rejects_missing_terminal_rows_and_frontier_aliases() {
        let sample = claim(1, 13, 1);
        let key = RealmUserUpdateAdmissionKey::try_new(
            sample.partition().unwrap().capture(),
        )
        .unwrap();
        let manifests = all_bucket_manifests(key, &[sample]);
        let membership = RealmUserUpdateGenerationManifest::from_buckets(&manifests)
            .unwrap();
        let close = RealmUserUpdateAdmissionCloseIntent::derive(key, [4; 32]).unwrap();
        let fence = RealmUserUpdateQualificationFence::try_from_pipeline(
            key,
            pipeline(1).candidate(),
        )
        .unwrap();
        assert!(RealmUserUpdateGenerationQualification::from_terminal_evidence(
            key,
            close,
            membership,
            fence,
            &[],
        )
        .is_err());

        let empty_membership = RealmUserUpdateGenerationManifest::from_buckets(
            &all_bucket_manifests(key, &[]),
        )
        .unwrap();
        let empty = RealmUserUpdateGenerationQualification::from_terminal_evidence(
            key,
            close,
            empty_membership,
            fence,
            &[],
        )
        .unwrap();
        assert_eq!(empty.terminal_count(), 0);
        assert_ne!(empty.digest().as_bytes(), &[0; 32]);

        let other_frontier = RealmUserUpdateQualificationFence::try_from_pipeline(
            key,
            pipeline(2).candidate(),
        )
        .unwrap();
        assert_ne!(fence, other_frontier);
        assert!(!fence.matches_pipeline(key, pipeline(2).candidate()));
    }

    #[test]
    fn malformed_or_selected_identity_mismatch_fails_closed() {
        let sample = claim(1, 13, 1);
        let open = StoredRealmUserUpdateAdmission::<PHash>::bucket_open(
            sample.partition().unwrap(),
        )
        .unwrap();
        let bytes = open.to_canonical_bytes();
        assert!(StoredRealmUserUpdateAdmission::<PHash>::decode_selected(
            open.key(),
            RealmUserUpdateAdmissionShard::Generation.as_i16().unwrap(),
            open.revision().as_i64().unwrap(),
            &bytes,
        )
        .is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(StoredRealmUserUpdateAdmission::<PHash>::decode_selected(
            open.key(),
            open.shard().as_i16().unwrap(),
            open.revision().as_i64().unwrap(),
            &trailing,
        )
        .is_err());
        let mut old_codec = open.to_canonical_bytes();
        old_codec[8..10].copy_from_slice(&1_u16.to_be_bytes());
        assert!(matches!(
            StoredRealmUserUpdateAdmission::<PHash>::decode_selected(
                open.key(),
                open.shard().as_i16().unwrap(),
                open.revision().as_i64().unwrap(),
                &old_codec,
            ),
            Err(RealmUserUpdateAdmissionError::UnknownCodecVersion)
        ));
    }
}
