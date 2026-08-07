//! Typed bridge between one immutable PREPARED Realm manifest and the live
//! proof-plus-mutation-graph capability that justifies its state transition.
//!
//! The persisted supplement is evidence only. Decoding it does not recreate
//! the live proof or graph seals and cannot authorize a new SEALED transition.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    chain_context::{AuthorityScope, AuthorityStateCheckpointId},
};
use sha2::{Digest, Sha256};

use super::{
    manifest_intent::AuthorityStateTransition,
    manifest_record::{AuthorityManifestDigest, PreparedAuthorityManifestRecord},
    realm_commit_evidence::{
        PersistedRealmCommitEvidence, RealmCommitEvidenceError,
        SealedRealmCommitEvidence, REALM_COMMIT_EVIDENCE_V1_LEN,
    },
};

pub const REALM_MANIFEST_EVIDENCE_MAGIC: [u8; 8] = *b"PSYRMEV1";
pub const REALM_MANIFEST_EVIDENCE_CODEC_VERSION: u16 = 1;
const REALM_MANIFEST_EVIDENCE_PAYLOAD_LEN: usize =
    8 + 2 + 32 + REALM_COMMIT_EVIDENCE_V1_LEN;
pub const REALM_MANIFEST_EVIDENCE_V1_LEN: usize =
    REALM_MANIFEST_EVIDENCE_PAYLOAD_LEN + 32;
const SUPPLEMENT_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-manifest-evidence.v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmManifestEvidenceDigest([u8; 32]);

impl RealmManifestEvidenceDigest {
    pub const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistedRealmManifestEvidence<Hash> {
    prepared_manifest_digest: AuthorityManifestDigest,
    realm_commit_evidence: PersistedRealmCommitEvidence<Hash>,
    canonical_bytes: Vec<u8>,
    digest: RealmManifestEvidenceDigest,
}

impl<Hash: Q256BitHash> PersistedRealmManifestEvidence<Hash> {
    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, RealmManifestEvidenceError> {
        if bytes.len() != REALM_MANIFEST_EVIDENCE_V1_LEN {
            return Err(RealmManifestEvidenceError::InvalidCanonicalLength {
                expected: REALM_MANIFEST_EVIDENCE_V1_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[..8] != REALM_MANIFEST_EVIDENCE_MAGIC {
            return Err(RealmManifestEvidenceError::InvalidMagic);
        }
        let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed"));
        if version != REALM_MANIFEST_EVIDENCE_CODEC_VERSION {
            return Err(RealmManifestEvidenceError::UnknownCodecVersion(version));
        }
        let prepared_manifest_digest = AuthorityManifestDigest::from_persisted(
            bytes[10..42].try_into().expect("fixed"),
        );
        let bundle_end = 42 + REALM_COMMIT_EVIDENCE_V1_LEN;
        let realm_commit_evidence =
            PersistedRealmCommitEvidence::decode_canonical(&bytes[42..bundle_end])?;
        let stored_digest: [u8; 32] = bytes[bundle_end..]
            .try_into()
            .expect("fixed");
        let expected_digest = digest(&bytes[..bundle_end]);
        if stored_digest != expected_digest {
            return Err(RealmManifestEvidenceError::SupplementDigestMismatch);
        }
        Ok(Self {
            prepared_manifest_digest,
            realm_commit_evidence,
            canonical_bytes: bytes.to_vec(),
            digest: RealmManifestEvidenceDigest(stored_digest),
        })
    }

    pub fn verify_for(
        &self,
        prepared: &PreparedAuthorityManifestRecord<Hash>,
    ) -> Result<(), RealmManifestEvidenceError> {
        validate_binding(
            prepared,
            self.prepared_manifest_digest,
            &self.realm_commit_evidence,
        )
    }

    pub const fn prepared_manifest_digest(&self) -> AuthorityManifestDigest {
        self.prepared_manifest_digest
    }

    pub const fn realm_commit_evidence(
        &self,
    ) -> &PersistedRealmCommitEvidence<Hash> {
        &self.realm_commit_evidence
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> RealmManifestEvidenceDigest {
        self.digest
    }
}

/// Live capability produced only by consuming a verified Realm commit bundle
/// and binding it to one exact immutable PREPARED manifest.
#[derive(Clone, Debug)]
pub struct SealedRealmManifestEvidence<Hash> {
    record: PersistedRealmManifestEvidence<Hash>,
}

impl<Hash: Q256BitHash> SealedRealmManifestEvidence<Hash> {
    pub fn try_bind<Hasher>(
        prepared: &PreparedAuthorityManifestRecord<Hash>,
        bundle: SealedRealmCommitEvidence<Hash, Hasher>,
    ) -> Result<Self, RealmManifestEvidenceError> {
        let prepared_manifest_digest = prepared.digest();
        let realm_commit_evidence = bundle.into_record();
        validate_binding(
            prepared,
            prepared_manifest_digest,
            &realm_commit_evidence,
        )?;

        let mut canonical_bytes =
            Vec::with_capacity(REALM_MANIFEST_EVIDENCE_V1_LEN);
        canonical_bytes.extend_from_slice(&REALM_MANIFEST_EVIDENCE_MAGIC);
        canonical_bytes.extend_from_slice(
            &REALM_MANIFEST_EVIDENCE_CODEC_VERSION.to_le_bytes(),
        );
        canonical_bytes.extend_from_slice(prepared_manifest_digest.as_bytes());
        canonical_bytes.extend_from_slice(realm_commit_evidence.encode_canonical());
        debug_assert_eq!(
            canonical_bytes.len(),
            REALM_MANIFEST_EVIDENCE_PAYLOAD_LEN
        );
        let supplement_digest = digest(&canonical_bytes);
        canonical_bytes.extend_from_slice(&supplement_digest);
        debug_assert_eq!(canonical_bytes.len(), REALM_MANIFEST_EVIDENCE_V1_LEN);

        Ok(Self {
            record: PersistedRealmManifestEvidence {
                prepared_manifest_digest,
                realm_commit_evidence,
                canonical_bytes,
                digest: RealmManifestEvidenceDigest(supplement_digest),
            },
        })
    }

    pub const fn record(&self) -> &PersistedRealmManifestEvidence<Hash> {
        &self.record
    }

    pub const fn digest(&self) -> RealmManifestEvidenceDigest {
        self.record.digest
    }

    pub fn encode_canonical(&self) -> &[u8] {
        self.record.encode_canonical()
    }

    pub fn into_record(self) -> PersistedRealmManifestEvidence<Hash> {
        self.record
    }
}

fn validate_binding<Hash: Q256BitHash>(
    prepared: &PreparedAuthorityManifestRecord<Hash>,
    prepared_manifest_digest: AuthorityManifestDigest,
    bundle: &PersistedRealmCommitEvidence<Hash>,
) -> Result<(), RealmManifestEvidenceError> {
    if prepared.digest() != prepared_manifest_digest {
        return Err(RealmManifestEvidenceError::PreparedManifestDigestMismatch);
    }
    if prepared.identity().authority() == AuthorityScope::Coordinator {
        return Err(RealmManifestEvidenceError::RealmAuthorityRequired);
    }
    if prepared.identity().authority() != bundle.authority() {
        return Err(RealmManifestEvidenceError::AuthorityMismatch);
    }
    if prepared.intent().candidate_chain() != bundle.canonical_chain() {
        return Err(RealmManifestEvidenceError::CanonicalChainMismatch);
    }
    let AuthorityStateTransition::Changed {
        previous_checkpoint,
        checkpoint,
        old_root,
        new_root,
    } = prepared.intent().state_transition()
    else {
        return Err(RealmManifestEvidenceError::ChangedRealmManifestRequired);
    };
    if *previous_checkpoint != bundle.predecessor_checkpoint() {
        return Err(RealmManifestEvidenceError::PredecessorCheckpointMismatch {
            manifest: *previous_checkpoint,
            bundle: bundle.predecessor_checkpoint(),
        });
    }
    if *checkpoint != bundle.state_checkpoint() {
        return Err(RealmManifestEvidenceError::StateCheckpointMismatch {
            manifest: *checkpoint,
            bundle: bundle.state_checkpoint(),
        });
    }
    if old_root.as_inner() != bundle.old_realm_root() {
        return Err(RealmManifestEvidenceError::OldRealmRootMismatch);
    }
    if new_root.as_inner() != bundle.new_realm_root() {
        return Err(RealmManifestEvidenceError::NewRealmRootMismatch);
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SUPPLEMENT_DIGEST_DOMAIN);
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RealmManifestEvidenceError {
    InvalidCanonicalLength { expected: usize, actual: usize },
    InvalidMagic,
    UnknownCodecVersion(u16),
    SupplementDigestMismatch,
    PreparedManifestDigestMismatch,
    RealmAuthorityRequired,
    AuthorityMismatch,
    CanonicalChainMismatch,
    ChangedRealmManifestRequired,
    PredecessorCheckpointMismatch {
        manifest: AuthorityStateCheckpointId,
        bundle: AuthorityStateCheckpointId,
    },
    StateCheckpointMismatch {
        manifest: AuthorityStateCheckpointId,
        bundle: AuthorityStateCheckpointId,
    },
    OldRealmRootMismatch,
    NewRealmRootMismatch,
    RealmCommitEvidence(RealmCommitEvidenceError),
}

impl From<RealmCommitEvidenceError> for RealmManifestEvidenceError {
    fn from(value: RealmCommitEvidenceError) -> Self {
        Self::RealmCommitEvidence(value)
    }
}

impl fmt::Display for RealmManifestEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RealmManifestEvidenceError {}
