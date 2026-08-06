//! Driver-independent PREPARED -> SEALED -> COMMITTED authority-manifest model.
//!
//! This module executes no storage operation. It makes post-write verification,
//! head publication and restart decisions explicit so a future durable adapter
//! cannot reinterpret an intent after a crash or head-CAS conflict.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, CheckpointHash},
    chain_context::{
        AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
    },
};
use sha2::{Digest, Sha256};

use super::{
    authority_commit::AuthorityTimestampKey,
    manifest_record::{
        AuthorityManifestDigest, AuthorityManifestStatus, ManifestRevision,
        PreparedAuthorityManifestRecord,
    },
};

const AUTHORITY_HEAD_PAYLOAD_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.authority-head-payload.v1\0";

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
    NotApplicableForRealm,
}

/// Raw observation returned by the state/root/proof verifier. It has no
/// authority until `SealedAuthorityManifest::verify_and_seal` matches every
/// field against the PREPARED record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityPostWriteObservation<Hash> {
    head: AuthorityHeadView<Hash>,
    mutation_digest: [u8; 32],
    head_payload_digest: AuthorityHeadPayloadDigest,
    proof: AuthorityProofObservation<Hash>,
}

impl<Hash> AuthorityPostWriteObservation<Hash> {
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
            proof,
        }
    }
}

/// A PREPARED record whose exact physical mutation digest and post-write
/// state/proof observations have been verified. Fields are private and there
/// is no unchecked constructor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthorityManifest<Hash> {
    prepared: PreparedAuthorityManifestRecord<Hash>,
    verified_head: AuthorityHeadView<Hash>,
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
        match (prepared.identity().authority(), observation.proof) {
            (
                AuthorityScope::Coordinator,
                AuthorityProofObservation::CoordinatorPublicInput(hash),
            ) if hash == *candidate.chain().checkpoint().checkpoint_hash() => {}
            (
                AuthorityScope::Coordinator,
                AuthorityProofObservation::CoordinatorPublicInput(_),
            ) => return Err(ManifestLifecycleError::ProofCheckpointHashMismatch),
            (AuthorityScope::Coordinator, _) => {
                return Err(ManifestLifecycleError::CoordinatorProofRequired)
            }
            (
                AuthorityScope::Realm { .. },
                AuthorityProofObservation::NotApplicableForRealm,
            ) => {}
            (AuthorityScope::Realm { .. }, _) => {
                return Err(ManifestLifecycleError::RealmProofMustBeAbsent)
            }
        }
        Ok(Self {
            prepared,
            verified_head: candidate,
        })
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
                    HeadPublishReceipt::for_sealed(self),
                )
            } else {
                AuthorityHeadPublishDecision::Idempotent(
                    HeadPublishReceipt::for_sealed(self),
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
        Ok(CommittedAuthorityManifest { sealed: self })
    }

    pub fn recovery_action(
        &self,
        current: AuthorityHeadView<Hash>,
    ) -> SealedManifestRecoveryAction<Hash> {
        let expected = AuthorityHeadView::expected(&self.prepared);
        if current == self.verified_head {
            SealedManifestRecoveryAction::MarkCommitted(
                HeadPublishReceipt::for_sealed(self),
            )
        } else if current == expected {
            SealedManifestRecoveryAction::PublishExactCandidate
        } else {
            SealedManifestRecoveryAction::Conflict { current }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HeadPublishReceipt<Hash> {
    manifest_digest: AuthorityManifestDigest,
    candidate: AuthorityHeadView<Hash>,
}

impl<Hash: Q256BitHash> HeadPublishReceipt<Hash> {
    fn for_sealed(sealed: &SealedAuthorityManifest<Hash>) -> Self {
        Self {
            manifest_digest: sealed.prepared.digest(),
            candidate: sealed.verified_head,
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
}

impl<Hash: Q256BitHash> CommittedAuthorityManifest<Hash> {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestLifecycleError {
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
    AppliedHeadCasMismatch,
    HeadPublishReceiptMismatch,
    CommittedHeadMismatch,
}

impl fmt::Display for ManifestLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ManifestLifecycleError {}
