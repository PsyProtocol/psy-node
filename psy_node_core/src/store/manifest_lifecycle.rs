//! Driver-independent PREPARED -> SEALED -> COMMITTED authority-manifest model.
//!
//! This module executes no storage operation. It makes post-write verification,
//! head publication and restart decisions explicit so a future durable adapter
//! cannot reinterpret an intent after a crash or head-CAS conflict.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CANONICAL_CHAIN_REF_V1_LEN, CanonicalChainRef, CheckpointHash},
    chain_context::{
        AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use sha2::{Digest, Sha256};

use super::{
    authority_commit::AuthorityTimestampKey,
    manifest_record::{
        AuthorityManifestDigest, AuthorityManifestIdentity,
        AuthorityManifestStatus, ManifestRecordError, ManifestRevision,
        PreparedAuthorityManifestRecord,
    },
};

const AUTHORITY_HEAD_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.authority-head-payload.v1\0";
const SEALED_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.sealed-authority-manifest.v1\0";
const COMMITTED_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.committed-authority-manifest.v1\0";

pub const SEALED_AUTHORITY_MANIFEST_MAGIC: [u8; 8] = *b"PSYMSEAL";
pub const COMMITTED_AUTHORITY_MANIFEST_MAGIC: [u8; 8] = *b"PSYMCOMT";
pub const AUTHORITY_MANIFEST_LIFECYCLE_CODEC_VERSION: u16 = 1;

/// Canonical length of the proof payload carried under seal-proof kind 3,
/// changed-Realm manifest evidence.
///
/// R1 M1 is Coordinator-only, so nothing here can construct kind 3 and the
/// lifecycle treats its payload as opaque bytes.  The tag and the length are
/// still reserved and encoded exactly as slice B will produce them, because a
/// manifest is a permanent record and its codec must not shift once the chain
/// has started writing manifests.  Slice B replaces the opaque payload with the
/// typed evidence and restores `verify_for`; the bytes on disk do not change.
///
/// Derived rather than written as a literal so a change to the canonical chain
/// reference propagates here instead of silently desynchronising the codec.
/// Slice B must assert its own definition equals this value.
const REALM_COMMIT_EVIDENCE_V1_LEN: usize = 8      // magic
    + 2                             // codec version
    + 6                             // authority scope
    + CANONICAL_CHAIN_REF_V1_LEN    // canonical chain reference
    + 8                             // authority state checkpoint
    + 8                             // pending id
    + 64                            // old/new authority state roots
    + 1                             // state transition kind
    + 32 * 3                        // prepared payload / proof binding / imt graph digests
    + 32; // bundle digest
pub const REALM_MANIFEST_EVIDENCE_V1_LEN: usize = 8 // magic
    + 2                             // codec version
    + 32                            // supplement digest
    + REALM_COMMIT_EVIDENCE_V1_LEN
    + 32; // evidence digest

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityLifecycleDigest([u8; 32]);

impl AuthorityLifecycleDigest {
    fn calculate(domain: &[u8], payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn from_prepared_digest(
        digest: AuthorityManifestDigest,
    ) -> Self {
        Self(*digest.as_bytes())
    }
}

/// Digest of the canonical singleton/cursor payload written with an authority
/// commit. Root verification cannot cover these cells, so SEALED must compare
/// this digest independently.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityHeadPayloadDigest([u8; 32]);

impl AuthorityHeadPayloadDigest {
    pub fn from_verified_payload_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(AUTHORITY_HEAD_PAYLOAD_DIGEST_DOMAIN);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum AuthorityManifestLifecyclePhase {
    Prepared,
    Sealed,
    Committed,
}

impl AuthorityManifestLifecyclePhase {
    pub const fn status(self) -> AuthorityManifestStatus {
        match self {
            Self::Prepared => AuthorityManifestStatus::Prepared,
            Self::Sealed => AuthorityManifestStatus::Sealed,
            Self::Committed => AuthorityManifestStatus::Committed,
        }
    }

    pub const fn revision(self) -> ManifestRevision {
        match self {
            Self::Prepared => ManifestRevision::prepared(),
            Self::Sealed => match ManifestRevision::try_new(1) {
                Ok(revision) => revision,
                Err(_) => unreachable!(),
            },
            Self::Committed => match ManifestRevision::try_new(2) {
                Ok(revision) => revision,
                Err(_) => unreachable!(),
            },
        }
    }
}

/// Exact authority head used by the lifecycle model. It deliberately excludes
/// mutable operational namespaces; those rotate under the Processor guard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityHeadView<Hash> {
    key: AuthorityTimestampKey,
    chain: CanonicalChainRef<Hash>,
    state_checkpoint: AuthorityStateCheckpointId,
    state_root: AuthorityStateRoot<Hash>,
}

impl<Hash: Q256BitHash> AuthorityHeadView<Hash> {
    pub fn try_from_observed(
        key: AuthorityTimestampKey,
        chain: CanonicalChainRef<Hash>,
        state_checkpoint: AuthorityStateCheckpointId,
        state_root: AuthorityStateRoot<Hash>,
    ) -> Result<Self, ManifestLifecycleError> {
        if key.network() != chain.network_id() {
            return Err(ManifestLifecycleError::HeadNetworkMismatch);
        }
        let chain_checkpoint = chain.checkpoint().checkpoint_id().get();
        match key.authority() {
            AuthorityScope::Coordinator
                if state_checkpoint.get() != chain_checkpoint =>
            {
                return Err(
                    ManifestLifecycleError::CoordinatorStateCheckpointMismatch {
                        state_checkpoint: state_checkpoint.get(),
                        chain_checkpoint,
                    },
                );
            }
            AuthorityScope::Realm { .. }
                if state_checkpoint.get() > chain_checkpoint =>
            {
                return Err(ManifestLifecycleError::RealmStateAheadOfChain {
                    state_checkpoint: state_checkpoint.get(),
                    chain_checkpoint,
                });
            }
            _ => {}
        }
        Ok(Self {
            key,
            chain,
            state_checkpoint,
            state_root,
        })
    }

    pub fn expected(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Self {
        let intent = prepared.intent();
        Self {
            key: intent.key(),
            chain: *intent.expected_chain(),
            state_checkpoint: intent
                .state_transition()
                .previous_state_checkpoint(),
            state_root: *intent.state_transition().old_root(),
        }
    }

    pub fn candidate(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Self {
        let intent = prepared.intent();
        Self {
            key: intent.key(),
            chain: *intent.candidate_chain(),
            state_checkpoint: intent.state_transition().state_checkpoint(),
            state_root: *intent.state_transition().new_root(),
        }
    }

    pub const fn key(&self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn chain(&self) -> &CanonicalChainRef<Hash> {
        &self.chain
    }

    pub const fn state_checkpoint(&self) -> AuthorityStateCheckpointId {
        self.state_checkpoint
    }

    pub const fn state_root(&self) -> &AuthorityStateRoot<Hash> {
        &self.state_root
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityProofObservation<Hash> {
    CoordinatorPublicInput(CheckpointHash<Hash>),
    /// Legal only when the Realm's authority-local state transition is
    /// `Unchanged`. A changed Realm must attach a live manifest supplement.
    NotApplicableForRealm,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthoritySealProofEvidence<Hash> {
    Public(AuthorityProofObservation<Hash>),
    /// Opaque until slice B; see `REALM_MANIFEST_EVIDENCE_V1_LEN`.
    ChangedRealm([u8; REALM_MANIFEST_EVIDENCE_V1_LEN]),
}

/// Raw observation returned by the state/root/proof verifier. It has no
/// authority until `SealedAuthorityManifest::verify_and_seal` matches every
/// field against the PREPARED record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityPostWriteObservation<Hash> {
    head: AuthorityHeadView<Hash>,
    mutation_digest: [u8; 32],
    head_payload_digest: AuthorityHeadPayloadDigest,
    proof: AuthoritySealProofEvidence<Hash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct VerifiedSealEvidence<Hash> {
    mutation_digest: [u8; 32],
    head_payload_digest: AuthorityHeadPayloadDigest,
    proof: AuthoritySealProofEvidence<Hash>,
}

impl<Hash: Q256BitHash> AuthorityPostWriteObservation<Hash> {
    pub const fn new(
        head: AuthorityHeadView<Hash>,
        mutation_digest: [u8; 32],
        head_payload_digest: AuthorityHeadPayloadDigest,
        proof: AuthorityProofObservation<Hash>,
    ) -> Self {
        Self {
            head,
            mutation_digest,
            head_payload_digest,
            proof: AuthoritySealProofEvidence::Public(proof),
        }
    }

    // Slice B adds `attach_changed_realm_evidence` here.  R1 M1 deliberately
    // offers no constructor for seal-proof kind 3, so a Coordinator build
    // cannot mint changed-Realm evidence it has no way to verify.
}

/// A PREPARED record whose exact physical mutation digest and post-write
/// state/proof observations have been verified. Fields are private and there
/// is no unchecked constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthorityManifest<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    verified_head: AuthorityHeadView<Hash>,
    evidence: VerifiedSealEvidence<Hash>,
    canonical_payload: Vec<u8>,
    lifecycle_digest: AuthorityLifecycleDigest,
}

impl<Hash: Q256BitHash> SealedAuthorityManifest<Hash> {
    pub fn verify_and_seal(
        prepared: PreparedAuthorityManifestRecord<Hash>,
        observation: AuthorityPostWriteObservation<Hash>,
    ) -> Result<Self, ManifestLifecycleError> {
        let candidate = AuthorityHeadView::candidate(&prepared);
        if observation.head != candidate {
            return Err(ManifestLifecycleError::PostWriteHeadMismatch);
        }
        if observation.mutation_digest
            != prepared.intent().artifacts().mutation_digest()
        {
            return Err(ManifestLifecycleError::MutationDigestMismatch);
        }
        let expected_head_payload_digest =
            AuthorityHeadPayloadDigest::from_verified_payload_bytes(
                prepared.intent().head_payload().as_bytes(),
            );
        if observation.head_payload_digest != expected_head_payload_digest {
            return Err(ManifestLifecycleError::HeadPayloadDigestMismatch);
        }
        validate_proof_evidence(&prepared, &candidate, &observation.proof)?;
        let evidence = VerifiedSealEvidence {
            mutation_digest: observation.mutation_digest,
            head_payload_digest: observation.head_payload_digest,
            proof: observation.proof,
        };
        Self::from_verified_parts(prepared, candidate, evidence)
    }

    fn from_verified_parts(
        prepared: PreparedAuthorityManifestRecord<Hash>,
        verified_head: AuthorityHeadView<Hash>,
        evidence: VerifiedSealEvidence<Hash>,
    ) -> Result<Self, ManifestLifecycleError> {
        let canonical_payload = encode_sealed_payload(&prepared, &evidence)?;
        let lifecycle_digest = AuthorityLifecycleDigest::calculate(
            SEALED_MANIFEST_DIGEST_DOMAIN,
            &canonical_payload,
        );
        Ok(Self {
            prepared,
            verified_head,
            evidence,
            canonical_payload,
            lifecycle_digest,
        })
    }

    pub fn decode_persisted(
        selected_identity: AuthorityManifestIdentity<Hash>,
        revision: i64,
        status: i8,
        prepared_digest: &[u8],
        lifecycle_digest: &[u8],
        canonical_payload: &[u8],
    ) -> Result<Self, ManifestLifecycleError> {
        validate_lifecycle_cells(
            AuthorityManifestLifecyclePhase::Sealed,
            revision,
            status,
            lifecycle_digest,
            canonical_payload,
        )?;
        let decoded = decode_sealed_payload(
            selected_identity,
            prepared_digest,
            canonical_payload,
        )?;
        let observation = AuthorityPostWriteObservation {
            head: AuthorityHeadView::candidate(&decoded.prepared),
            mutation_digest: decoded.evidence.mutation_digest,
            head_payload_digest: decoded.evidence.head_payload_digest,
            proof: decoded.evidence.proof,
        };
        let sealed = Self::verify_and_seal(decoded.prepared, observation)?;
        if sealed.canonical_payload != canonical_payload {
            return Err(ManifestLifecycleError::NonCanonicalLifecyclePayload);
        }
        Ok(sealed)
    }

    pub const fn phase(&self) -> AuthorityManifestLifecyclePhase {
        AuthorityManifestLifecyclePhase::Sealed
    }

    pub const fn revision(&self) -> ManifestRevision {
        self.phase().revision()
    }

    pub const fn status(&self) -> AuthorityManifestStatus {
        self.phase().status()
    }

    pub const fn prepared(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        &self.prepared
    }

    pub const fn verified_head(&self) -> &AuthorityHeadView<Hash> {
        &self.verified_head
    }

    /// Opaque until slice B decodes it; see `REALM_MANIFEST_EVIDENCE_V1_LEN`.
    pub fn realm_manifest_evidence(
        &self,
    ) -> Option<&[u8; REALM_MANIFEST_EVIDENCE_V1_LEN]> {
        match &self.evidence.proof {
            AuthoritySealProofEvidence::ChangedRealm(evidence) => {
                Some(evidence)
            }
            AuthoritySealProofEvidence::Public(_) => None,
        }
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub const fn lifecycle_digest(&self) -> AuthorityLifecycleDigest {
        self.lifecycle_digest
    }

    pub fn classify_head_cas(
        &self,
        applied: bool,
        current: AuthorityHeadView<Hash>,
    ) -> Result<AuthorityHeadPublishDecision<Hash>, ManifestLifecycleError> {
        let expected = AuthorityHeadView::expected(&self.prepared);
        let candidate = self.verified_head;
        if current == candidate {
            return Ok(if applied {
                AuthorityHeadPublishDecision::Published(
                    HeadPublishReceipt::for_sealed(
                        self,
                        AuthorityHeadPublicationKind::Applied,
                    ),
                )
            } else {
                AuthorityHeadPublishDecision::Idempotent(
                    HeadPublishReceipt::for_sealed(
                        self,
                        AuthorityHeadPublicationKind::Idempotent,
                    ),
                )
            });
        }
        if applied {
            return Err(ManifestLifecycleError::AppliedHeadCasMismatch);
        }
        if current == expected {
            Ok(AuthorityHeadPublishDecision::RetryExactSealedIntent)
        } else {
            Ok(AuthorityHeadPublishDecision::Conflict { current })
        }
    }

    pub fn mark_committed(
        self,
        receipt: HeadPublishReceipt<Hash>,
    ) -> Result<CommittedAuthorityManifest<Hash>, ManifestLifecycleError> {
        receipt.verify_for(&self)?;
        CommittedAuthorityManifest::from_published(self, receipt)
    }

    pub fn recovery_action(
        &self,
        current: AuthorityHeadView<Hash>,
    ) -> SealedManifestRecoveryAction<Hash> {
        let expected = AuthorityHeadView::expected(&self.prepared);
        if current == self.verified_head {
            SealedManifestRecoveryAction::MarkCommitted(
                HeadPublishReceipt::for_sealed(
                    self,
                    AuthorityHeadPublicationKind::RecoveredCandidate,
                ),
            )
        } else if current == expected {
            SealedManifestRecoveryAction::PublishExactCandidate
        } else {
            SealedManifestRecoveryAction::Conflict { current }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityHeadPublicationKind {
    Applied = 1,
    Idempotent = 2,
    RecoveredCandidate = 3,
}

impl TryFrom<u8> for AuthorityHeadPublicationKind {
    type Error = ManifestLifecycleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Applied),
            2 => Ok(Self::Idempotent),
            3 => Ok(Self::RecoveredCandidate),
            value => Err(ManifestLifecycleError::UnknownHeadPublicationKind(
                value,
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadPublishReceipt<Hash> {
    manifest_digest: AuthorityManifestDigest,
    candidate: AuthorityHeadView<Hash>,
    publication_kind: AuthorityHeadPublicationKind,
}

impl<Hash: Q256BitHash> HeadPublishReceipt<Hash> {
    fn for_sealed(
        sealed: &SealedAuthorityManifest<Hash>,
        publication_kind: AuthorityHeadPublicationKind,
    ) -> Self {
        Self {
            manifest_digest: sealed.prepared.digest(),
            candidate: sealed.verified_head,
            publication_kind,
        }
    }

    fn verify_for(
        &self,
        sealed: &SealedAuthorityManifest<Hash>,
    ) -> Result<(), ManifestLifecycleError> {
        if self.manifest_digest == sealed.prepared.digest()
            && self.candidate == sealed.verified_head
        {
            Ok(())
        } else {
            Err(ManifestLifecycleError::HeadPublishReceiptMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityHeadPublishDecision<Hash> {
    Published(HeadPublishReceipt<Hash>),
    Idempotent(HeadPublishReceipt<Hash>),
    RetryExactSealedIntent,
    Conflict { current: AuthorityHeadView<Hash> },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealedManifestRecoveryAction<Hash> {
    PublishExactCandidate,
    MarkCommitted(HeadPublishReceipt<Hash>),
    Conflict { current: AuthorityHeadView<Hash> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedAuthorityManifest<Hash> {
    sealed: SealedAuthorityManifest<Hash>,
    publication_kind: AuthorityHeadPublicationKind,
    canonical_payload: Vec<u8>,
    lifecycle_digest: AuthorityLifecycleDigest,
}

/// Strictly decoded value of one durable lifecycle row. The enum makes status
/// dispatch exhaustive and prevents callers from decoding a future phase with
/// the PREPARED-only codec.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PersistedAuthorityManifest<Hash> {
    Prepared(PreparedAuthorityManifestRecord<Hash>),
    Sealed(SealedAuthorityManifest<Hash>),
    Committed(CommittedAuthorityManifest<Hash>),
}

impl<Hash: Q256BitHash> PersistedAuthorityManifest<Hash> {
    pub fn decode_persisted(
        selected_identity: AuthorityManifestIdentity<Hash>,
        revision: i64,
        status: i8,
        prepared_digest: &[u8],
        lifecycle_digest: &[u8],
        canonical_payload: &[u8],
    ) -> Result<Self, ManifestLifecycleError> {
        match AuthorityManifestStatus::try_from(status)? {
            AuthorityManifestStatus::Prepared => {
                if prepared_digest.len() != 32 {
                    return Err(
                        ManifestLifecycleError::InvalidPreparedDigestLength(
                            prepared_digest.len(),
                        ),
                    );
                }
                if lifecycle_digest != prepared_digest {
                    return Err(
                        ManifestLifecycleError::PreparedLifecycleDigestMismatch,
                    );
                }
                Ok(Self::Prepared(
                    PreparedAuthorityManifestRecord::decode_persisted(
                        selected_identity,
                        revision,
                        status,
                        prepared_digest,
                        canonical_payload,
                    )?,
                ))
            }
            AuthorityManifestStatus::Sealed => Ok(Self::Sealed(
                SealedAuthorityManifest::decode_persisted(
                    selected_identity,
                    revision,
                    status,
                    prepared_digest,
                    lifecycle_digest,
                    canonical_payload,
                )?,
            )),
            AuthorityManifestStatus::Committed => Ok(Self::Committed(
                CommittedAuthorityManifest::decode_persisted(
                    selected_identity,
                    revision,
                    status,
                    prepared_digest,
                    lifecycle_digest,
                    canonical_payload,
                )?,
            )),
        }
    }

    pub const fn phase(&self) -> AuthorityManifestLifecyclePhase {
        match self {
            Self::Prepared(_) => AuthorityManifestLifecyclePhase::Prepared,
            Self::Sealed(_) => AuthorityManifestLifecyclePhase::Sealed,
            Self::Committed(_) => AuthorityManifestLifecyclePhase::Committed,
        }
    }

    pub const fn identity(&self) -> &AuthorityManifestIdentity<Hash> {
        self.prepared().identity()
    }

    pub const fn prepared(&self) -> &PreparedAuthorityManifestRecord<Hash> {
        match self {
            Self::Prepared(record) => record,
            Self::Sealed(record) => record.prepared(),
            Self::Committed(record) => record.sealed().prepared(),
        }
    }

    pub const fn revision(&self) -> ManifestRevision {
        self.phase().revision()
    }

    pub const fn status(&self) -> AuthorityManifestStatus {
        self.phase().status()
    }

    pub const fn lifecycle_digest(&self) -> AuthorityLifecycleDigest {
        match self {
            Self::Prepared(record) => {
                AuthorityLifecycleDigest::from_prepared_digest(record.digest())
            }
            Self::Sealed(record) => record.lifecycle_digest(),
            Self::Committed(record) => record.lifecycle_digest(),
        }
    }

    pub fn encode_canonical(&self) -> &[u8] {
        match self {
            Self::Prepared(record) => record.encode_canonical(),
            Self::Sealed(record) => record.encode_canonical(),
            Self::Committed(record) => record.encode_canonical(),
        }
    }
}

impl<Hash> From<PreparedAuthorityManifestRecord<Hash>>
    for PersistedAuthorityManifest<Hash>
{
    fn from(value: PreparedAuthorityManifestRecord<Hash>) -> Self {
        Self::Prepared(value)
    }
}

impl<Hash> From<SealedAuthorityManifest<Hash>>
    for PersistedAuthorityManifest<Hash>
{
    fn from(value: SealedAuthorityManifest<Hash>) -> Self {
        Self::Sealed(value)
    }
}

impl<Hash> From<CommittedAuthorityManifest<Hash>>
    for PersistedAuthorityManifest<Hash>
{
    fn from(value: CommittedAuthorityManifest<Hash>) -> Self {
        Self::Committed(value)
    }
}

impl<Hash: Q256BitHash> CommittedAuthorityManifest<Hash> {
    fn from_published(
        sealed: SealedAuthorityManifest<Hash>,
        receipt: HeadPublishReceipt<Hash>,
    ) -> Result<Self, ManifestLifecycleError> {
        let publication_kind = receipt.publication_kind;
        let canonical_payload =
            encode_committed_payload(&sealed, publication_kind)?;
        let lifecycle_digest = AuthorityLifecycleDigest::calculate(
            COMMITTED_MANIFEST_DIGEST_DOMAIN,
            &canonical_payload,
        );
        Ok(Self {
            sealed,
            publication_kind,
            canonical_payload,
            lifecycle_digest,
        })
    }

    pub fn decode_persisted(
        selected_identity: AuthorityManifestIdentity<Hash>,
        revision: i64,
        status: i8,
        prepared_digest: &[u8],
        lifecycle_digest: &[u8],
        canonical_payload: &[u8],
    ) -> Result<Self, ManifestLifecycleError> {
        validate_lifecycle_cells(
            AuthorityManifestLifecyclePhase::Committed,
            revision,
            status,
            lifecycle_digest,
            canonical_payload,
        )?;
        let decoded = decode_committed_payload(
            selected_identity,
            prepared_digest,
            canonical_payload,
        )?;
        if decoded.canonical_payload != canonical_payload {
            return Err(ManifestLifecycleError::NonCanonicalLifecyclePayload);
        }
        Ok(decoded)
    }

    pub const fn phase(&self) -> AuthorityManifestLifecyclePhase {
        AuthorityManifestLifecyclePhase::Committed
    }

    pub const fn revision(&self) -> ManifestRevision {
        self.phase().revision()
    }

    pub const fn status(&self) -> AuthorityManifestStatus {
        self.phase().status()
    }

    pub const fn sealed(&self) -> &SealedAuthorityManifest<Hash> {
        &self.sealed
    }

    pub const fn publication_kind(&self) -> AuthorityHeadPublicationKind {
        self.publication_kind
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub const fn lifecycle_digest(&self) -> AuthorityLifecycleDigest {
        self.lifecycle_digest
    }

    pub fn recovery_action(
        &self,
        current: AuthorityHeadView<Hash>,
    ) -> Result<CommittedManifestRecoveryAction, ManifestLifecycleError> {
        if current == self.sealed.verified_head {
            Ok(CommittedManifestRecoveryAction::CompleteTimestampLease)
        } else {
            Err(ManifestLifecycleError::CommittedHeadMismatch)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PreparedManifestRecoveryAction {
    ReapplyExactMutationsAndVerify,
}

pub const fn prepared_recovery_action<Hash>(
    _: &PreparedAuthorityManifestRecord<Hash>,
) -> PreparedManifestRecoveryAction {
    PreparedManifestRecoveryAction::ReapplyExactMutationsAndVerify
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommittedManifestRecoveryAction {
    CompleteTimestampLease,
}

struct DecodedSealedPayload<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    evidence: VerifiedSealEvidence<Hash>,
}

fn validate_proof_evidence<Hash: Q256BitHash>(
    prepared: &PreparedAuthorityManifestRecord<Hash>,
    candidate: &AuthorityHeadView<Hash>,
    proof: &AuthoritySealProofEvidence<Hash>,
) -> Result<(), ManifestLifecycleError> {
    let state_changed = prepared.intent().state_transition().state_changed();
    match (prepared.identity().authority(), state_changed, proof) {
        (
            AuthorityScope::Coordinator,
            _,
            AuthoritySealProofEvidence::Public(
                AuthorityProofObservation::CoordinatorPublicInput(hash),
            ),
        ) if hash == candidate.chain().checkpoint().checkpoint_hash() => Ok(()),
        (
            AuthorityScope::Coordinator,
            _,
            AuthoritySealProofEvidence::Public(
                AuthorityProofObservation::CoordinatorPublicInput(_),
            ),
        ) => Err(ManifestLifecycleError::ProofCheckpointHashMismatch),
        (AuthorityScope::Coordinator, _, _) => {
            Err(ManifestLifecycleError::CoordinatorProofRequired)
        }
        // A Realm carries no proof evidence, whether its state changed or not.
        //
        // It seals its own manifest and answers for its own state; the
        // Coordinator neither seals nor validates it.  The extra evidence a
        // changed Realm used to owe was designed for the other arrangement --
        // the error it raised said so, that a *Coordinator* must not seal a
        // Realm manifest it cannot validate -- and it guarded a case that does
        // not arise.
        //
        // What is checked is unchanged and is the part that matters: by this
        // point `verify_and_seal` has already compared the root observed after
        // the writes against the one the record claims, the mutation digest
        // against the rows the manifest names, and the head payload digest.  A
        // Realm has nothing further it can prove locally.
        //
        // This mattered more than it looked.  The requirement was unsatisfiable
        // -- the evidence type is a reserved placeholder nothing constructs --
        // so a Realm that genuinely changed state could never seal.  It never
        // showed because a second defect made every Realm record claim its state
        // had not changed; the two cancelled out until a crash recovery computed
        // the roots from an untouched source and met the wall.
        (
            AuthorityScope::Realm { .. },
            _,
            AuthoritySealProofEvidence::Public(
                AuthorityProofObservation::NotApplicableForRealm,
            ),
        ) => Ok(()),
        // Still refused, and now for a reason rather than for want of an
        // implementation: nothing produces it, and a record carrying it would
        // be claiming an authority this side does not have.
        (
            AuthorityScope::Realm { .. },
            _,
            AuthoritySealProofEvidence::ChangedRealm(_),
        ) => Err(ManifestLifecycleError::ChangedRealmEvidenceNotSupported),
        (
            AuthorityScope::Realm { .. },
            _,
            AuthoritySealProofEvidence::Public(
                AuthorityProofObservation::CoordinatorPublicInput(_),
            ),
        ) => Err(ManifestLifecycleError::RealmProofMustBeAbsent),
    }
}

fn encode_sealed_payload<Hash: Q256BitHash>(
    prepared: &PreparedAuthorityManifestRecord<Hash>,
    evidence: &VerifiedSealEvidence<Hash>,
) -> Result<Vec<u8>, ManifestLifecycleError> {
    let prepared_payload = prepared.encode_canonical();
    let prepared_len = u32::try_from(prepared_payload.len()).map_err(|_| {
        ManifestLifecycleError::LifecyclePayloadTooLarge(prepared_payload.len())
    })?;
    let mut out = Vec::with_capacity(143 + prepared_payload.len());
    out.extend_from_slice(&SEALED_AUTHORITY_MANIFEST_MAGIC);
    out.extend_from_slice(&AUTHORITY_MANIFEST_LIFECYCLE_CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(prepared.digest().as_bytes());
    out.extend_from_slice(&prepared_len.to_be_bytes());
    out.extend_from_slice(prepared_payload);
    out.extend_from_slice(&evidence.mutation_digest);
    out.extend_from_slice(evidence.head_payload_digest.as_bytes());
    match &evidence.proof {
        AuthoritySealProofEvidence::Public(
            AuthorityProofObservation::CoordinatorPublicInput(hash),
        ) => {
            out.push(1);
            out.extend_from_slice(&hash.as_inner().into_owned_32bytes());
        }
        AuthoritySealProofEvidence::Public(
            AuthorityProofObservation::NotApplicableForRealm,
        ) => {
            out.push(2);
            out.extend_from_slice(&[0; 32]);
        }
        AuthoritySealProofEvidence::ChangedRealm(evidence) => {
            out.push(3);
            out.extend_from_slice(evidence);
        }
    }
    Ok(out)
}

fn decode_sealed_payload<Hash: Q256BitHash>(
    selected_identity: AuthorityManifestIdentity<Hash>,
    selected_prepared_digest: &[u8],
    bytes: &[u8],
) -> Result<DecodedSealedPayload<Hash>, ManifestLifecycleError> {
    const PREFIX_LEN: usize = 46;
    const EVIDENCE_PREFIX_LEN: usize = 65;
    if bytes.len() < PREFIX_LEN + EVIDENCE_PREFIX_LEN {
        return Err(ManifestLifecycleError::TruncatedLifecyclePayload);
    }
    if bytes[..8] != SEALED_AUTHORITY_MANIFEST_MAGIC {
        return Err(ManifestLifecycleError::InvalidLifecycleMagic);
    }
    let version = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed"));
    if version != AUTHORITY_MANIFEST_LIFECYCLE_CODEC_VERSION {
        return Err(ManifestLifecycleError::UnknownLifecycleCodecVersion(
            version,
        ));
    }
    if selected_prepared_digest.len() != 32 {
        return Err(ManifestLifecycleError::InvalidPreparedDigestLength(
            selected_prepared_digest.len(),
        ));
    }
    if &bytes[10..42] != selected_prepared_digest {
        return Err(ManifestLifecycleError::PreparedDigestMismatch);
    }
    let prepared_len =
        u32::from_be_bytes(bytes[42..46].try_into().expect("fixed")) as usize;
    let prepared_end = PREFIX_LEN
        .checked_add(prepared_len)
        .ok_or(ManifestLifecycleError::LifecyclePayloadLengthOverflow)?;
    let evidence_prefix_end = prepared_end
        .checked_add(EVIDENCE_PREFIX_LEN)
        .ok_or(ManifestLifecycleError::LifecyclePayloadLengthOverflow)?;
    if bytes.len() < evidence_prefix_end {
        return Err(ManifestLifecycleError::TruncatedLifecyclePayload);
    }
    let mutation_end = prepared_end + 32;
    let head_payload_end = mutation_end + 32;
    let proof_kind = bytes[head_payload_end];
    let proof_len = match proof_kind {
        1 | 2 => 32,
        3 => REALM_MANIFEST_EVIDENCE_V1_LEN,
        value => return Err(ManifestLifecycleError::UnknownProofKind(value)),
    };
    let expected_end = evidence_prefix_end
        .checked_add(proof_len)
        .ok_or(ManifestLifecycleError::LifecyclePayloadLengthOverflow)?;
    if bytes.len() < expected_end {
        return Err(ManifestLifecycleError::TruncatedLifecyclePayload);
    }
    if bytes.len() > expected_end {
        return Err(ManifestLifecycleError::TrailingLifecyclePayloadBytes);
    }
    let prepared = PreparedAuthorityManifestRecord::decode_persisted(
        selected_identity,
        ManifestRevision::prepared().as_i64(),
        AuthorityManifestStatus::Prepared as i8,
        selected_prepared_digest,
        &bytes[PREFIX_LEN..prepared_end],
    )?;
    let proof_bytes = &bytes[evidence_prefix_end..expected_end];
    let proof = match proof_kind {
        1 => AuthoritySealProofEvidence::Public(
            AuthorityProofObservation::CoordinatorPublicInput(
                CheckpointHash::from_proof_public_inputs_hash(
                    Hash::from_owned_32bytes(
                        proof_bytes.try_into().expect("validated length"),
                    ),
                ),
            ),
        ),
        2 if proof_bytes == [0; 32] => AuthoritySealProofEvidence::Public(
            AuthorityProofObservation::NotApplicableForRealm,
        ),
        2 => return Err(ManifestLifecycleError::NonCanonicalRealmProof),
        3 => AuthoritySealProofEvidence::ChangedRealm(
            proof_bytes.try_into().expect("validated length"),
        ),
        _ => unreachable!("proof kind validated above"),
    };
    Ok(DecodedSealedPayload {
        prepared,
        evidence: VerifiedSealEvidence {
            mutation_digest: bytes[prepared_end..mutation_end]
                .try_into()
                .expect("fixed"),
            head_payload_digest: AuthorityHeadPayloadDigest::from_persisted(
                bytes[mutation_end..head_payload_end]
                    .try_into()
                    .expect("fixed"),
            ),
            proof,
        },
    })
}

fn encode_committed_payload<Hash: Q256BitHash>(
    sealed: &SealedAuthorityManifest<Hash>,
    publication_kind: AuthorityHeadPublicationKind,
) -> Result<Vec<u8>, ManifestLifecycleError> {
    let sealed_payload = sealed.encode_canonical();
    let sealed_len = u32::try_from(sealed_payload.len()).map_err(|_| {
        ManifestLifecycleError::LifecyclePayloadTooLarge(sealed_payload.len())
    })?;
    let mut out = Vec::with_capacity(47 + sealed_payload.len());
    out.extend_from_slice(&COMMITTED_AUTHORITY_MANIFEST_MAGIC);
    out.extend_from_slice(&AUTHORITY_MANIFEST_LIFECYCLE_CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(sealed.lifecycle_digest().as_bytes());
    out.extend_from_slice(&sealed_len.to_be_bytes());
    out.extend_from_slice(sealed_payload);
    out.push(publication_kind as u8);
    Ok(out)
}

fn decode_committed_payload<Hash: Q256BitHash>(
    selected_identity: AuthorityManifestIdentity<Hash>,
    selected_prepared_digest: &[u8],
    bytes: &[u8],
) -> Result<CommittedAuthorityManifest<Hash>, ManifestLifecycleError> {
    const PREFIX_LEN: usize = 46;
    if bytes.len() < PREFIX_LEN + 1 {
        return Err(ManifestLifecycleError::TruncatedLifecyclePayload);
    }
    if bytes[..8] != COMMITTED_AUTHORITY_MANIFEST_MAGIC {
        return Err(ManifestLifecycleError::InvalidLifecycleMagic);
    }
    let version = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed"));
    if version != AUTHORITY_MANIFEST_LIFECYCLE_CODEC_VERSION {
        return Err(ManifestLifecycleError::UnknownLifecycleCodecVersion(
            version,
        ));
    }
    let sealed_len =
        u32::from_be_bytes(bytes[42..46].try_into().expect("fixed")) as usize;
    let sealed_end = PREFIX_LEN
        .checked_add(sealed_len)
        .ok_or(ManifestLifecycleError::LifecyclePayloadLengthOverflow)?;
    let expected_end = sealed_end
        .checked_add(1)
        .ok_or(ManifestLifecycleError::LifecyclePayloadLengthOverflow)?;
    if bytes.len() < expected_end {
        return Err(ManifestLifecycleError::TruncatedLifecyclePayload);
    }
    if bytes.len() > expected_end {
        return Err(ManifestLifecycleError::TrailingLifecyclePayloadBytes);
    }
    let persisted_sealed_digest = &bytes[10..42];
    let sealed = SealedAuthorityManifest::decode_persisted(
        selected_identity,
        AuthorityManifestLifecyclePhase::Sealed.revision().as_i64(),
        AuthorityManifestStatus::Sealed as i8,
        selected_prepared_digest,
        persisted_sealed_digest,
        &bytes[PREFIX_LEN..sealed_end],
    )?;
    let publication_kind = AuthorityHeadPublicationKind::try_from(bytes[sealed_end])?;
    let receipt = HeadPublishReceipt::for_sealed(&sealed, publication_kind);
    CommittedAuthorityManifest::from_published(sealed, receipt)
}

fn validate_lifecycle_cells(
    expected_phase: AuthorityManifestLifecyclePhase,
    revision: i64,
    status: i8,
    persisted_digest: &[u8],
    canonical_payload: &[u8],
) -> Result<(), ManifestLifecycleError> {
    let revision = ManifestRevision::try_from_i64(revision)?;
    if revision != expected_phase.revision() {
        return Err(ManifestLifecycleError::LifecycleRevisionMismatch {
            expected: expected_phase.revision().get(),
            actual: revision.get(),
        });
    }
    let status = AuthorityManifestStatus::try_from(status)?;
    if status != expected_phase.status() {
        return Err(ManifestLifecycleError::LifecycleStatusMismatch {
            expected: expected_phase.status() as i8,
            actual: status as i8,
        });
    }
    if persisted_digest.len() != 32 {
        return Err(ManifestLifecycleError::InvalidLifecycleDigestLength(
            persisted_digest.len(),
        ));
    }
    let domain = match expected_phase {
        AuthorityManifestLifecyclePhase::Sealed => {
            SEALED_MANIFEST_DIGEST_DOMAIN
        }
        AuthorityManifestLifecyclePhase::Committed => {
            COMMITTED_MANIFEST_DIGEST_DOMAIN
        }
        AuthorityManifestLifecyclePhase::Prepared => {
            return Err(ManifestLifecycleError::PreparedUsesDedicatedCodec)
        }
    };
    if AuthorityLifecycleDigest::calculate(domain, canonical_payload)
        .as_bytes()
        != persisted_digest
    {
        return Err(ManifestLifecycleError::LifecycleDigestMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestLifecycleError {
    ManifestRecord(ManifestRecordError),
    HeadNetworkMismatch,
    CoordinatorStateCheckpointMismatch {
        state_checkpoint: u64,
        chain_checkpoint: u64,
    },
    RealmStateAheadOfChain {
        state_checkpoint: u64,
        chain_checkpoint: u64,
    },
    PostWriteHeadMismatch,
    MutationDigestMismatch,
    HeadPayloadDigestMismatch,
    CoordinatorProofRequired,
    ProofCheckpointHashMismatch,
    RealmProofMustBeAbsent,
    ChangedRealmEvidenceRequired,
    UnchangedRealmEvidenceForbidden,
    /// Seal-proof kind 3 is reserved but unusable until slice B restores the
    /// typed evidence and its `verify_for` check.  Failing closed here keeps a
    /// Coordinator build from sealing a Realm manifest it cannot validate.
    ChangedRealmEvidenceNotSupported,
    AppliedHeadCasMismatch,
    HeadPublishReceiptMismatch,
    CommittedHeadMismatch,
    LifecyclePayloadTooLarge(usize),
    InvalidPreparedDigestLength(usize),
    InvalidLifecycleDigestLength(usize),
    InvalidLifecycleMagic,
    UnknownLifecycleCodecVersion(u16),
    UnknownProofKind(u8),
    NonCanonicalRealmProof,
    UnknownHeadPublicationKind(u8),
    PreparedDigestMismatch,
    LifecycleDigestMismatch,
    LifecyclePayloadLengthOverflow,
    TruncatedLifecyclePayload,
    TrailingLifecyclePayloadBytes,
    NonCanonicalLifecyclePayload,
    LifecycleRevisionMismatch { expected: u64, actual: u64 },
    LifecycleStatusMismatch { expected: i8, actual: i8 },
    PreparedUsesDedicatedCodec,
    PreparedLifecycleDigestMismatch,
}

impl From<ManifestRecordError> for ManifestLifecycleError {
    fn from(value: ManifestRecordError) -> Self {
        Self::ManifestRecord(value)
    }
}


impl fmt::Display for ManifestLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ManifestLifecycleError {}
