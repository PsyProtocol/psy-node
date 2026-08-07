//! Live changed-Realm commit evidence assembled immediately before the
//! manifest lifecycle may cross PREPARED -> SEALED.
//!
//! Persisted proof, graph, bundle or supplement records cannot construct this
//! capability. Construction consumes the two live component seals, binds
//! them to one exact PREPARED manifest, attaches the resulting supplement to
//! the exact post-write observation and asks the lifecycle verifier to check
//! the complete combination once before it can be handed to the normal
//! commit orchestration.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;

use super::{
    manifest_lifecycle::{
        AuthorityPostWriteObservation, ManifestLifecycleError,
        SealedAuthorityManifest,
    },
    manifest_record::{
        AuthorityManifestDigest, PreparedAuthorityManifestRecord,
    },
    realm_commit_evidence::{
        RealmCommitEvidenceError, SealedRealmCommitEvidence,
    },
    realm_imt_mutation_graph::SealedRealmImtMutationGraph,
    realm_manifest_evidence::{
        RealmManifestEvidenceError, SealedRealmManifestEvidence,
    },
    realm_proof_binding::SealedRealmProofBinding,
};

/// Complete live evidence for one exact changed-Realm PREPARED manifest.
///
/// The value is retryable because every component is immutable and bound to
/// `prepared_manifest_digest`. It cannot be created from persisted evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChangedRealmCommitSealEvidence<Hash> {
    prepared_manifest_digest: AuthorityManifestDigest,
    observation: AuthorityPostWriteObservation<Hash>,
}

impl<Hash: Q256BitHash> ChangedRealmCommitSealEvidence<Hash> {
    pub fn try_bind<Hasher>(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        observation: AuthorityPostWriteObservation<Hash>,
        proof: SealedRealmProofBinding<Hash>,
        graph: SealedRealmImtMutationGraph<Hash, Hasher>,
    ) -> Result<Self, ChangedRealmCommitSealError> {
        let bundle = SealedRealmCommitEvidence::try_bind(proof, graph)?;
        let supplement =
            SealedRealmManifestEvidence::try_bind(prepared, bundle)?;
        let observation =
            observation.attach_changed_realm_evidence(supplement);

        // Validate the complete combination now. The normal commit boundary
        // repeats the validation after re-reading head and allocator state.
        SealedAuthorityManifest::verify_and_seal(
            prepared.clone(),
            observation.clone(),
        )?;

        Ok(Self {
            prepared_manifest_digest: prepared.digest(),
            observation,
        })
    }

    pub const fn prepared_manifest_digest(&self) -> AuthorityManifestDigest {
        self.prepared_manifest_digest
    }

    pub(crate) fn into_observation_for(
        self,
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<AuthorityPostWriteObservation<Hash>, ChangedRealmCommitSealError>
    {
        if prepared.digest() != self.prepared_manifest_digest {
            return Err(
                ChangedRealmCommitSealError::PreparedManifestDigestMismatch,
            );
        }
        Ok(self.observation)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ChangedRealmCommitSealError {
    CommitEvidence(RealmCommitEvidenceError),
    ManifestEvidence(RealmManifestEvidenceError),
    ManifestLifecycle(ManifestLifecycleError),
    PreparedManifestDigestMismatch,
}

impl From<RealmCommitEvidenceError> for ChangedRealmCommitSealError {
    fn from(value: RealmCommitEvidenceError) -> Self {
        Self::CommitEvidence(value)
    }
}

impl From<RealmManifestEvidenceError> for ChangedRealmCommitSealError {
    fn from(value: RealmManifestEvidenceError) -> Self {
        Self::ManifestEvidence(value)
    }
}

impl From<ManifestLifecycleError> for ChangedRealmCommitSealError {
    fn from(value: ManifestLifecycleError) -> Self {
        Self::ManifestLifecycle(value)
    }
}

impl fmt::Display for ChangedRealmCommitSealError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ChangedRealmCommitSealError {}
