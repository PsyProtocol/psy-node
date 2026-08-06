//! Driver-independent durable authority-local head and normal-advance CAS.
//!
//! The payload is one indivisible value: materialized authority observation,
//! commit timestamp, manifest reference and active storage binding. A normal
//! commit may only advance it from a verified SEALED manifest. Rollback and
//! namespace-cutover transitions deliberately remain unavailable here.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{
    AuthorityObservation, ChainContextCodecError, AUTHORITY_OBSERVATION_V1_LEN,
};

use super::{
    authority_commit::AuthorityTimestampKey,
    manifest_lifecycle::{
        AuthorityHeadView, ManifestLifecycleError, SealedAuthorityManifest,
    },
    manifest_record::AuthorityManifestDigest,
    timestamp::CommitWriteTimestampUs,
};

pub const AUTHORITY_LOCAL_HEAD_MAGIC: [u8; 8] = *b"PSYALHED";
pub const AUTHORITY_LOCAL_HEAD_CODEC_VERSION: u16 = 1;
pub const AUTHORITY_LOCAL_HEAD_V1_LEN: usize =
    8 + 2 + 1 + AUTHORITY_OBSERVATION_V1_LEN + 8 + 32 + 8 + 32;

/// Monotonic ABA fence for one authority-local head row.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityLocalHeadRevision(u64);

impl AuthorityLocalHeadRevision {
    pub const fn try_new(value: u64) -> Result<Self, AuthorityLocalHeadModelError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(AuthorityLocalHeadModelError::RevisionOutOfCqlRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, AuthorityLocalHeadModelError> {
        if value < 0 {
            Err(AuthorityLocalHeadModelError::NegativeRevision(value))
        } else {
            Self::try_new(value as u64)
        }
    }

    const fn initial() -> Self {
        Self(0)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    pub const fn checked_next(self) -> Result<Self, AuthorityLocalHeadModelError> {
        match self.0.checked_add(1) {
            Some(value) if value <= i64::MAX as u64 => Ok(Self(value)),
            _ => Err(AuthorityLocalHeadModelError::RevisionOverflow(self.0)),
        }
    }
}

/// Generation of the active standard/no-tablet namespace pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityStorageBindingGeneration(u64);

impl AuthorityStorageBindingGeneration {
    pub const fn try_new(value: u64) -> Result<Self, AuthorityLocalHeadModelError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(AuthorityLocalHeadModelError::BindingGenerationOutOfCqlRange(
                value,
            ))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Content-derived ID of the active storage namespace pair.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorityStorageNamespaceId([u8; 32]);

impl AuthorityStorageNamespaceId {
    /// Wrap an ID obtained from a verified namespace catalog entry.
    pub const fn from_verified_namespace_id(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Exact active namespace identity preserved by every normal commit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityStorageBindingRef {
    generation: AuthorityStorageBindingGeneration,
    namespace_id: AuthorityStorageNamespaceId,
}

impl AuthorityStorageBindingRef {
    pub const fn new(
        generation: AuthorityStorageBindingGeneration,
        namespace_id: AuthorityStorageNamespaceId,
    ) -> Self {
        Self {
            generation,
            namespace_id,
        }
    }

    pub const fn generation(self) -> AuthorityStorageBindingGeneration {
        self.generation
    }

    pub const fn namespace_id(self) -> AuthorityStorageNamespaceId {
        self.namespace_id
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum AuthorityLocalHeadBootstrapReason {
    GenesisNative = 1,
    PostGenesisFloor = 2,
}

impl AuthorityLocalHeadBootstrapReason {
    fn try_from_u8(value: u8) -> Result<Self, AuthorityLocalHeadModelError> {
        match value {
            1 => Ok(Self::GenesisNative),
            2 => Ok(Self::PostGenesisFloor),
            value => Err(AuthorityLocalHeadModelError::UnknownBootstrapReason(
                value,
            )),
        }
    }
}

/// Manifest digest stored as a reference in the serving-head row.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityHeadManifestDigest([u8; 32]);

impl AuthorityHeadManifestDigest {
    pub const fn from_manifest(digest: AuthorityManifestDigest) -> Self {
        Self(*digest.as_bytes())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Complete, indivisible durable row payload plus its LWT revision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredAuthorityLocalHead<Hash> {
    revision: AuthorityLocalHeadRevision,
    bootstrap_reason: AuthorityLocalHeadBootstrapReason,
    head: AuthorityHeadView<Hash>,
    commit_write_timestamp: CommitWriteTimestampUs,
    manifest_digest: AuthorityHeadManifestDigest,
    storage_binding: AuthorityStorageBindingRef,
}

impl<Hash: Q256BitHash> StoredAuthorityLocalHead<Hash> {
    pub const fn revision(&self) -> AuthorityLocalHeadRevision {
        self.revision
    }

    pub const fn bootstrap_reason(&self) -> AuthorityLocalHeadBootstrapReason {
        self.bootstrap_reason
    }

    pub const fn head(&self) -> &AuthorityHeadView<Hash> {
        &self.head
    }

    pub const fn commit_write_timestamp(&self) -> CommitWriteTimestampUs {
        self.commit_write_timestamp
    }

    pub const fn manifest_digest(&self) -> AuthorityHeadManifestDigest {
        self.manifest_digest
    }

    pub const fn storage_binding(&self) -> AuthorityStorageBindingRef {
        self.storage_binding
    }

    pub fn encode_canonical(&self) -> [u8; AUTHORITY_LOCAL_HEAD_V1_LEN] {
        let observation = AuthorityObservation::try_new(
            *self.head.chain(),
            self.head.key().authority(),
            self.head.state_checkpoint(),
            *self.head.state_root(),
        )
        .expect("AuthorityHeadView already validates its authority observation");
        let mut bytes = [0u8; AUTHORITY_LOCAL_HEAD_V1_LEN];
        bytes[..8].copy_from_slice(&AUTHORITY_LOCAL_HEAD_MAGIC);
        bytes[8..10].copy_from_slice(&AUTHORITY_LOCAL_HEAD_CODEC_VERSION.to_le_bytes());
        bytes[10] = self.bootstrap_reason as u8;
        bytes[11..11 + AUTHORITY_OBSERVATION_V1_LEN]
            .copy_from_slice(&observation.to_canonical_bytes());
        let timestamp_offset = 11 + AUTHORITY_OBSERVATION_V1_LEN;
        bytes[timestamp_offset..timestamp_offset + 8]
            .copy_from_slice(&self.commit_write_timestamp.as_i64().to_le_bytes());
        let digest_offset = timestamp_offset + 8;
        bytes[digest_offset..digest_offset + 32]
            .copy_from_slice(self.manifest_digest.as_bytes());
        let generation_offset = digest_offset + 32;
        bytes[generation_offset..generation_offset + 8]
            .copy_from_slice(&self.storage_binding.generation().get().to_le_bytes());
        bytes[generation_offset + 8..generation_offset + 40]
            .copy_from_slice(self.storage_binding.namespace_id().as_bytes());
        bytes
    }

    pub fn decode_persisted(
        selected_key: AuthorityTimestampKey,
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, AuthorityLocalHeadModelError> {
        if payload.len() != AUTHORITY_LOCAL_HEAD_V1_LEN {
            return Err(AuthorityLocalHeadModelError::InvalidPayloadLength {
                expected: AUTHORITY_LOCAL_HEAD_V1_LEN,
                actual: payload.len(),
            });
        }
        if payload[..8] != AUTHORITY_LOCAL_HEAD_MAGIC {
            return Err(AuthorityLocalHeadModelError::InvalidPayloadMagic);
        }
        let version = u16::from_le_bytes([payload[8], payload[9]]);
        if version != AUTHORITY_LOCAL_HEAD_CODEC_VERSION {
            return Err(AuthorityLocalHeadModelError::UnknownCodecVersion(version));
        }
        let bootstrap_reason = AuthorityLocalHeadBootstrapReason::try_from_u8(payload[10])?;
        let observation = AuthorityObservation::<Hash>::from_canonical_bytes(
            &payload[11..11 + AUTHORITY_OBSERVATION_V1_LEN],
        )?;
        let observed_key = AuthorityTimestampKey::new(
            observation.chain().network_id(),
            observation.authority(),
        );
        if observed_key != selected_key {
            return Err(AuthorityLocalHeadModelError::SelectedKeyMismatch);
        }
        let head = AuthorityHeadView::try_from_observed(
            observed_key,
            *observation.chain(),
            observation.state_checkpoint_id(),
            *observation.state_root(),
        )?;
        let timestamp_offset = 11 + AUTHORITY_OBSERVATION_V1_LEN;
        let commit_write_timestamp = CommitWriteTimestampUs::try_from_i128(
            i64::from_le_bytes(
                payload[timestamp_offset..timestamp_offset + 8]
                    .try_into()
                    .expect("fixed timestamp slice"),
            ) as i128,
        )?;
        let digest_offset = timestamp_offset + 8;
        let mut manifest_digest = [0u8; 32];
        manifest_digest.copy_from_slice(&payload[digest_offset..digest_offset + 32]);
        let generation_offset = digest_offset + 32;
        let binding_generation = AuthorityStorageBindingGeneration::try_new(
            u64::from_le_bytes(
                payload[generation_offset..generation_offset + 8]
                    .try_into()
                    .expect("fixed generation slice"),
            ),
        )?;
        let mut namespace_id = [0u8; 32];
        namespace_id.copy_from_slice(&payload[generation_offset + 8..generation_offset + 40]);
        Ok(Self {
            revision: AuthorityLocalHeadRevision::try_from_i64(revision)?,
            bootstrap_reason,
            head,
            commit_write_timestamp,
            manifest_digest: AuthorityHeadManifestDigest(manifest_digest),
            storage_binding: AuthorityStorageBindingRef::new(
                binding_generation,
                AuthorityStorageNamespaceId(namespace_id),
            ),
        })
    }
}

/// Explicit initialization request. Missing rows are never auto-created.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityLocalHeadBootstrap<Hash> {
    key: AuthorityTimestampKey,
    candidate: StoredAuthorityLocalHead<Hash>,
}

impl<Hash: Q256BitHash> AuthorityLocalHeadBootstrap<Hash> {
    pub fn seal(
        reason: AuthorityLocalHeadBootstrapReason,
        head: AuthorityHeadView<Hash>,
        commit_write_timestamp: CommitWriteTimestampUs,
        manifest_digest: AuthorityManifestDigest,
        storage_binding: AuthorityStorageBindingRef,
    ) -> Self {
        Self {
            key: head.key(),
            candidate: StoredAuthorityLocalHead {
                revision: AuthorityLocalHeadRevision::initial(),
                bootstrap_reason: reason,
                head,
                commit_write_timestamp,
                manifest_digest: AuthorityHeadManifestDigest::from_manifest(
                    manifest_digest,
                ),
                storage_binding,
            },
        }
    }

    pub const fn key(&self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn candidate(&self) -> &StoredAuthorityLocalHead<Hash> {
        &self.candidate
    }

    pub fn candidate_payload(&self) -> [u8; AUTHORITY_LOCAL_HEAD_V1_LEN] {
        self.candidate.encode_canonical()
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredAuthorityLocalHead<Hash>,
    ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadModelError> {
        classify_write(applied, current, &self.candidate)
    }
}

/// Exact normal-advance CAS. Callers cannot construct an arbitrary rewind.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthorityLocalHeadCas<Hash> {
    key: AuthorityTimestampKey,
    expected: StoredAuthorityLocalHead<Hash>,
    candidate: StoredAuthorityLocalHead<Hash>,
}

impl<Hash: Q256BitHash> SealedAuthorityLocalHeadCas<Hash> {
    pub fn seal_normal_advance(
        expected: StoredAuthorityLocalHead<Hash>,
        sealed: &SealedAuthorityManifest<Hash>,
    ) -> Result<Self, AuthorityLocalHeadModelError> {
        let prepared = sealed.prepared();
        if expected.head != AuthorityHeadView::expected(prepared) {
            return Err(AuthorityLocalHeadModelError::ExpectedHeadMismatch);
        }
        if prepared.commit_write_timestamp().as_i64()
            <= expected.commit_write_timestamp.as_i64()
        {
            return Err(AuthorityLocalHeadModelError::TimestampDidNotAdvance {
                previous: expected.commit_write_timestamp.as_i64(),
                candidate: prepared.commit_write_timestamp().as_i64(),
            });
        }
        let key = expected.head.key();
        if sealed.verified_head().key() != key {
            return Err(AuthorityLocalHeadModelError::AuthorityChanged);
        }
        let candidate = StoredAuthorityLocalHead {
            revision: expected.revision.checked_next()?,
            bootstrap_reason: expected.bootstrap_reason,
            head: *sealed.verified_head(),
            commit_write_timestamp: prepared.commit_write_timestamp(),
            manifest_digest: AuthorityHeadManifestDigest::from_manifest(
                prepared.digest(),
            ),
            storage_binding: expected.storage_binding,
        };
        Ok(Self {
            key,
            expected,
            candidate,
        })
    }

    pub const fn key(&self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn expected(&self) -> &StoredAuthorityLocalHead<Hash> {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredAuthorityLocalHead<Hash> {
        &self.candidate
    }

    pub fn expected_payload(&self) -> [u8; AUTHORITY_LOCAL_HEAD_V1_LEN] {
        self.expected.encode_canonical()
    }

    pub fn candidate_payload(&self) -> [u8; AUTHORITY_LOCAL_HEAD_V1_LEN] {
        self.candidate.encode_canonical()
    }

    pub fn classify_lwt_observation(
        &self,
        applied: bool,
        current: StoredAuthorityLocalHead<Hash>,
    ) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadModelError> {
        classify_write(applied, current, &self.candidate)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityLocalHeadReadState<Hash> {
    Uninitialized,
    Current(StoredAuthorityLocalHead<Hash>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityLocalHeadWriteOutcome<Hash> {
    Applied(StoredAuthorityLocalHead<Hash>),
    Idempotent(StoredAuthorityLocalHead<Hash>),
    Conflict(StoredAuthorityLocalHead<Hash>),
}

fn classify_write<Hash: Q256BitHash>(
    applied: bool,
    current: StoredAuthorityLocalHead<Hash>,
    candidate: &StoredAuthorityLocalHead<Hash>,
) -> Result<AuthorityLocalHeadWriteOutcome<Hash>, AuthorityLocalHeadModelError> {
    if applied {
        if current == *candidate {
            Ok(AuthorityLocalHeadWriteOutcome::Applied(current))
        } else {
            Err(AuthorityLocalHeadModelError::AppliedStateMismatch)
        }
    } else if current == *candidate {
        Ok(AuthorityLocalHeadWriteOutcome::Idempotent(current))
    } else {
        Ok(AuthorityLocalHeadWriteOutcome::Conflict(current))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityLocalHeadModelError {
    NegativeRevision(i64),
    RevisionOutOfCqlRange(u64),
    RevisionOverflow(u64),
    BindingGenerationOutOfCqlRange(u64),
    InvalidPayloadLength { expected: usize, actual: usize },
    InvalidPayloadMagic,
    UnknownCodecVersion(u16),
    UnknownBootstrapReason(u8),
    ChainContext(ChainContextCodecError),
    ManifestLifecycle(ManifestLifecycleError),
    TimestampOutOfRange,
    SelectedKeyMismatch,
    ExpectedHeadMismatch,
    AuthorityChanged,
    TimestampDidNotAdvance { previous: i64, candidate: i64 },
    AppliedStateMismatch,
}

impl From<ChainContextCodecError> for AuthorityLocalHeadModelError {
    fn from(value: ChainContextCodecError) -> Self {
        Self::ChainContext(value)
    }
}

impl From<ManifestLifecycleError> for AuthorityLocalHeadModelError {
    fn from(value: ManifestLifecycleError) -> Self {
        Self::ManifestLifecycle(value)
    }
}

impl From<super::timestamp::TimestampOutOfCqlRange>
    for AuthorityLocalHeadModelError
{
    fn from(_: super::timestamp::TimestampOutOfCqlRange) -> Self {
        Self::TimestampOutOfRange
    }
}

impl fmt::Display for AuthorityLocalHeadModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for AuthorityLocalHeadModelError {}
