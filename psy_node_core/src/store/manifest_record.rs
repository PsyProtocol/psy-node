//! Driver-independent durable PREPARED authority-manifest record.
//!
//! The record is the only value accepted by the D-03b Scylla manifest LWT.
//! It binds the exact D-03a intent, verified artifact summary and D-04a lease
//! coordinates into one canonical payload. It does not execute state writes
//! and cannot transition to SEALED or COMMITTED in this slice.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointRef, NetworkId},
    chain_context::AuthorityScope,
};
use sha2::{Digest, Sha256};

use super::{
    authority_commit::{
        AuthorityCommitModelError, AuthorityTimestampKey,
        AuthorityTimestampRevision,
    },
    manifest_intent::{
        ManifestIntentError, PreparedAuthorityManifestIntent,
        SealedAuthorityCommitIntent,
    },
    timestamp::CommitWriteTimestampUs,
};

pub const PREPARED_AUTHORITY_MANIFEST_MAGIC: [u8; 8] = *b"PSYMPREP";
pub const PREPARED_AUTHORITY_MANIFEST_CODEC_VERSION: u16 = 1;
pub const AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE: u64 = 4096;
pub const MAX_ARTIFACT_SUMMARY_BYTES: usize = 1024 * 1024;

const PREPARED_MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.prepared-authority-manifest.v1\0";
const PREPARED_PAYLOAD_FIXED_LEN: usize = 66;

/// Immutable primary-key identity of one authority checkpoint occurrence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityManifestIdentity<Hash> {
    timestamp_key: AuthorityTimestampKey,
    canonical_chain: CanonicalChainRef<Hash>,
}

impl<Hash> AuthorityManifestIdentity<Hash> {
    pub fn try_new(
        timestamp_key: AuthorityTimestampKey,
        canonical_chain: CanonicalChainRef<Hash>,
    ) -> Result<Self, ManifestRecordError> {
        if timestamp_key.network() != canonical_chain.network_id() {
            return Err(ManifestRecordError::IdentityNetworkMismatch);
        }
        Ok(Self {
            timestamp_key,
            canonical_chain,
        })
    }

    fn from_validated_parts(
        timestamp_key: AuthorityTimestampKey,
        canonical_chain: CanonicalChainRef<Hash>,
    ) -> Self {
        debug_assert_eq!(timestamp_key.network(), canonical_chain.network_id());
        Self {
            timestamp_key,
            canonical_chain,
        }
    }

    pub const fn network(&self) -> NetworkId {
        self.timestamp_key.network()
    }

    pub const fn authority(&self) -> AuthorityScope {
        self.timestamp_key.authority()
    }

    pub const fn timestamp_key(&self) -> AuthorityTimestampKey {
        self.timestamp_key
    }

    pub const fn canonical_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.canonical_chain
    }

    pub const fn chain_epoch(&self) -> ChainEpoch {
        self.canonical_chain.chain_epoch()
    }

    pub const fn checkpoint(&self) -> &CheckpointRef<Hash> {
        self.canonical_chain.checkpoint()
    }

    pub const fn checkpoint_bucket(&self) -> u64 {
        self.canonical_chain.checkpoint().checkpoint_id().get()
            / AUTHORITY_MANIFEST_CHECKPOINT_BUCKET_SIZE
    }
}

/// Revision of the immutable manifest lifecycle row. D-03b only creates
/// revision zero in PREPARED; future SEALED/COMMITTED transitions must use
/// exact `+1` CAS builders.
///
/// ```compile_fail
/// use psy_node_core::store::{manifest_record::ManifestRevision, typed::CheckpointId};
/// let revision = ManifestRevision::try_new(0).unwrap();
/// let _: CheckpointId = revision;
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ManifestRevision(u64);

impl ManifestRevision {
    pub const fn try_new(value: u64) -> Result<Self, ManifestRecordError> {
        if value <= i64::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(ManifestRecordError::RevisionOutOfCqlRange(value))
        }
    }

    pub const fn try_from_i64(value: i64) -> Result<Self, ManifestRecordError> {
        if value < 0 {
            Err(ManifestRecordError::NegativeRevision(value))
        } else {
            Self::try_new(value as u64)
        }
    }

    pub const fn prepared() -> Self {
        Self(0)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(i8)]
pub enum AuthorityManifestStatus {
    Prepared = 1,
    Sealed = 2,
    Committed = 3,
}

impl TryFrom<i8> for AuthorityManifestStatus {
    type Error = ManifestRecordError;

    fn try_from(value: i8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Sealed),
            3 => Ok(Self::Committed),
            value => Err(ManifestRecordError::UnknownManifestStatus(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AuthorityManifestDigest([u8; 32]);

impl AuthorityManifestDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Rehydrates a digest that has already been verified by the manifest
    /// codec/read path. This does not assert that an arbitrary byte array is a
    /// VERIFIED manifest; callers must obtain it from durable manifest
    /// evidence before constructing a post-genesis deployment plan.
    pub const fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn calculate(payload: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(PREPARED_MANIFEST_DIGEST_DOMAIN);
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(payload);
        Self(hasher.finalize().into())
    }
}

/// Exact durable PREPARED candidate. The payload contains all logical cells
/// that must remain inseparable even though the CQL primary key and lifecycle
/// columns are stored separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorityManifestRecord<Hash> {
    identity: AuthorityManifestIdentity<Hash>,
    revision: ManifestRevision,
    status: AuthorityManifestStatus,
    intent: SealedAuthorityCommitIntent<Hash>,
    allocator_active_revision: AuthorityTimestampRevision,
    commit_write_timestamp: CommitWriteTimestampUs,
    artifact_summary: Vec<u8>,
    canonical_payload: Vec<u8>,
    digest: AuthorityManifestDigest,
}

impl<Hash: Q256BitHash> PreparedAuthorityManifestRecord<Hash> {
    pub fn seal(
        prepared: &PreparedAuthorityManifestIntent<Hash>,
        artifact_summary: Vec<u8>,
    ) -> Result<Self, ManifestRecordError> {
        validate_artifact_summary(prepared.intent(), &artifact_summary)?;
        let identity = identity_from_intent(prepared.intent());
        let revision = ManifestRevision::prepared();
        let status = AuthorityManifestStatus::Prepared;
        let allocator_active_revision = prepared.lease().active_revision();
        let commit_write_timestamp = prepared.commit_write_timestamp();
        let canonical_payload = encode_prepared_payload(
            prepared.intent(),
            allocator_active_revision,
            commit_write_timestamp,
            &artifact_summary,
        );
        let digest = AuthorityManifestDigest::calculate(&canonical_payload);
        Ok(Self {
            identity,
            revision,
            status,
            intent: prepared.intent().clone(),
            allocator_active_revision,
            commit_write_timestamp,
            artifact_summary,
            canonical_payload,
            digest,
        })
    }

    pub fn decode_persisted(
        selected_identity: AuthorityManifestIdentity<Hash>,
        revision: i64,
        status: i8,
        persisted_digest: &[u8],
        canonical_payload: &[u8],
    ) -> Result<Self, ManifestRecordError> {
        let revision = ManifestRevision::try_from_i64(revision)?;
        if revision != ManifestRevision::prepared() {
            return Err(ManifestRecordError::UnsupportedPreparedRevision(
                revision.get(),
            ));
        }
        let status = AuthorityManifestStatus::try_from(status)?;
        if status != AuthorityManifestStatus::Prepared {
            return Err(ManifestRecordError::UnsupportedPreparedStatus(
                status as i8,
            ));
        }
        if persisted_digest.len() != 32 {
            return Err(ManifestRecordError::InvalidManifestDigestLength(
                persisted_digest.len(),
            ));
        }
        let digest = AuthorityManifestDigest::calculate(canonical_payload);
        if digest.as_bytes().as_slice() != persisted_digest {
            return Err(ManifestRecordError::ManifestDigestMismatch);
        }

        let decoded = decode_prepared_payload::<Hash>(canonical_payload)?;
        let identity = identity_from_intent(&decoded.intent);
        if identity != selected_identity {
            return Err(ManifestRecordError::SelectedIdentityMismatch);
        }
        validate_artifact_summary(&decoded.intent, &decoded.artifact_summary)?;
        let rebuilt_payload = encode_prepared_payload(
            &decoded.intent,
            decoded.allocator_active_revision,
            decoded.commit_write_timestamp,
            &decoded.artifact_summary,
        );
        if rebuilt_payload != canonical_payload {
            return Err(ManifestRecordError::NonCanonicalPreparedPayload);
        }
        Ok(Self {
            identity,
            revision,
            status,
            intent: decoded.intent,
            allocator_active_revision: decoded.allocator_active_revision,
            commit_write_timestamp: decoded.commit_write_timestamp,
            artifact_summary: decoded.artifact_summary,
            canonical_payload: rebuilt_payload,
            digest,
        })
    }

    pub const fn identity(&self) -> &AuthorityManifestIdentity<Hash> {
        &self.identity
    }

    pub const fn revision(&self) -> ManifestRevision {
        self.revision
    }

    pub const fn status(&self) -> AuthorityManifestStatus {
        self.status
    }

    pub const fn intent(&self) -> &SealedAuthorityCommitIntent<Hash> {
        &self.intent
    }

    pub const fn allocator_active_revision(
        &self,
    ) -> AuthorityTimestampRevision {
        self.allocator_active_revision
    }

    pub const fn commit_write_timestamp(&self) -> CommitWriteTimestampUs {
        self.commit_write_timestamp
    }

    pub fn artifact_summary(&self) -> &[u8] {
        &self.artifact_summary
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_payload
    }

    pub const fn digest(&self) -> AuthorityManifestDigest {
        self.digest
    }

    pub fn classify_insert_observation(
        &self,
        applied: bool,
        current: Self,
    ) -> Result<PreparedManifestWriteOutcome<Hash>, ManifestRecordError> {
        if current == *self {
            if applied {
                Ok(PreparedManifestWriteOutcome::Applied(current))
            } else {
                Ok(PreparedManifestWriteOutcome::Idempotent(current))
            }
        } else if applied {
            Err(ManifestRecordError::AppliedInsertMismatch)
        } else {
            Ok(PreparedManifestWriteOutcome::Conflict(current))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PreparedManifestWriteOutcome<Hash> {
    Applied(PreparedAuthorityManifestRecord<Hash>),
    Idempotent(PreparedAuthorityManifestRecord<Hash>),
    Conflict(PreparedAuthorityManifestRecord<Hash>),
}

struct DecodedPreparedPayload<Hash> {
    intent: SealedAuthorityCommitIntent<Hash>,
    allocator_active_revision: AuthorityTimestampRevision,
    commit_write_timestamp: CommitWriteTimestampUs,
    artifact_summary: Vec<u8>,
}

fn identity_from_intent<Hash: Q256BitHash>(
    intent: &SealedAuthorityCommitIntent<Hash>,
) -> AuthorityManifestIdentity<Hash> {
    let candidate = intent.candidate_chain();
    AuthorityManifestIdentity::from_validated_parts(
        intent.key(),
        CanonicalChainRef::new(
            candidate.network_id(),
            candidate.chain_epoch(),
            CheckpointRef::new(
                candidate.checkpoint().checkpoint_id(),
                psy_data::protocol::canonical_chain::CheckpointHash::from_last_chain_hash(
                    Hash::from_owned_32bytes(
                        candidate
                            .checkpoint()
                            .checkpoint_hash()
                            .as_inner()
                            .into_owned_32bytes(),
                    ),
                ),
            ),
        ),
    )
}

fn validate_artifact_summary<Hash: Q256BitHash>(
    intent: &SealedAuthorityCommitIntent<Hash>,
    artifact_summary: &[u8],
) -> Result<(), ManifestRecordError> {
    if artifact_summary.is_empty() {
        return Err(ManifestRecordError::EmptyArtifactSummary);
    }
    if artifact_summary.len() > MAX_ARTIFACT_SUMMARY_BYTES {
        return Err(ManifestRecordError::ArtifactSummaryTooLarge {
            actual: artifact_summary.len(),
            maximum: MAX_ARTIFACT_SUMMARY_BYTES,
        });
    }
    intent
        .artifacts()
        .verify_canonical_summary(artifact_summary)?;
    Ok(())
}

fn encode_prepared_payload<Hash: Q256BitHash>(
    intent: &SealedAuthorityCommitIntent<Hash>,
    allocator_active_revision: AuthorityTimestampRevision,
    commit_write_timestamp: CommitWriteTimestampUs,
    artifact_summary: &[u8],
) -> Vec<u8> {
    let intent_bytes = intent.encode_canonical();
    let mut out = Vec::with_capacity(
        PREPARED_PAYLOAD_FIXED_LEN + intent_bytes.len() + artifact_summary.len(),
    );
    out.extend_from_slice(&PREPARED_AUTHORITY_MANIFEST_MAGIC);
    out.extend_from_slice(&PREPARED_AUTHORITY_MANIFEST_CODEC_VERSION.to_le_bytes());
    out.extend_from_slice(&allocator_active_revision.get().to_le_bytes());
    out.extend_from_slice(&commit_write_timestamp.as_i64().to_le_bytes());
    out.extend_from_slice(intent.digest().as_bytes());
    out.extend_from_slice(&(intent_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(intent_bytes);
    out.extend_from_slice(&(artifact_summary.len() as u32).to_le_bytes());
    out.extend_from_slice(artifact_summary);
    out
}

fn decode_prepared_payload<Hash: Q256BitHash>(
    bytes: &[u8],
) -> Result<DecodedPreparedPayload<Hash>, ManifestRecordError> {
    if bytes.len() < PREPARED_PAYLOAD_FIXED_LEN {
        return Err(ManifestRecordError::TruncatedPreparedPayload {
            minimum: PREPARED_PAYLOAD_FIXED_LEN,
            actual: bytes.len(),
        });
    }
    if bytes[..8] != PREPARED_AUTHORITY_MANIFEST_MAGIC {
        return Err(ManifestRecordError::InvalidPreparedPayloadMagic);
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("fixed"));
    if version != PREPARED_AUTHORITY_MANIFEST_CODEC_VERSION {
        return Err(ManifestRecordError::UnknownPreparedPayloadVersion(version));
    }
    let allocator_active_revision = AuthorityTimestampRevision::try_new(
        u64::from_le_bytes(bytes[10..18].try_into().expect("fixed")),
    )?;
    let commit_write_timestamp = CommitWriteTimestampUs::try_from_i128(
        i64::from_le_bytes(bytes[18..26].try_into().expect("fixed")) as i128,
    )?;
    let persisted_intent_digest: [u8; 32] =
        bytes[26..58].try_into().expect("fixed");
    let intent_len =
        u32::from_le_bytes(bytes[58..62].try_into().expect("fixed")) as usize;
    let intent_end = 62usize
        .checked_add(intent_len)
        .ok_or(ManifestRecordError::PreparedPayloadLengthOverflow)?;
    let summary_length_end = intent_end
        .checked_add(4)
        .ok_or(ManifestRecordError::PreparedPayloadLengthOverflow)?;
    if bytes.len() < summary_length_end {
        return Err(ManifestRecordError::TruncatedPreparedPayload {
            minimum: summary_length_end,
            actual: bytes.len(),
        });
    }
    let intent = SealedAuthorityCommitIntent::decode_canonical(&bytes[62..intent_end])?;
    if intent.digest().as_bytes() != &persisted_intent_digest {
        return Err(ManifestRecordError::IntentDigestMismatch);
    }
    let summary_len = u32::from_le_bytes(
        bytes[intent_end..summary_length_end]
            .try_into()
            .expect("fixed"),
    ) as usize;
    let summary_start = summary_length_end;
    let summary_end = summary_start
        .checked_add(summary_len)
        .ok_or(ManifestRecordError::PreparedPayloadLengthOverflow)?;
    if bytes.len() < summary_end {
        return Err(ManifestRecordError::TruncatedPreparedPayload {
            minimum: summary_end,
            actual: bytes.len(),
        });
    }
    if bytes.len() > summary_end {
        return Err(ManifestRecordError::TrailingPreparedPayloadBytes {
            expected: summary_end,
            actual: bytes.len(),
        });
    }
    Ok(DecodedPreparedPayload {
        intent,
        allocator_active_revision,
        commit_write_timestamp,
        artifact_summary: bytes[summary_start..summary_end].to_vec(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestRecordError {
    Intent(ManifestIntentError),
    AuthorityCommit(AuthorityCommitModelError),
    Timestamp(super::timestamp::TimestampOutOfCqlRange),
    RevisionOutOfCqlRange(u64),
    NegativeRevision(i64),
    UnsupportedPreparedRevision(u64),
    UnknownManifestStatus(i8),
    UnsupportedPreparedStatus(i8),
    EmptyArtifactSummary,
    ArtifactSummaryTooLarge { actual: usize, maximum: usize },
    InvalidManifestDigestLength(usize),
    ManifestDigestMismatch,
    IdentityNetworkMismatch,
    SelectedIdentityMismatch,
    InvalidPreparedPayloadMagic,
    UnknownPreparedPayloadVersion(u16),
    PreparedPayloadLengthOverflow,
    TruncatedPreparedPayload { minimum: usize, actual: usize },
    TrailingPreparedPayloadBytes { expected: usize, actual: usize },
    IntentDigestMismatch,
    NonCanonicalPreparedPayload,
    AppliedInsertMismatch,
}

impl From<ManifestIntentError> for ManifestRecordError {
    fn from(value: ManifestIntentError) -> Self {
        Self::Intent(value)
    }
}

impl From<AuthorityCommitModelError> for ManifestRecordError {
    fn from(value: AuthorityCommitModelError) -> Self {
        Self::AuthorityCommit(value)
    }
}

impl From<super::timestamp::TimestampOutOfCqlRange> for ManifestRecordError {
    fn from(value: super::timestamp::TimestampOutOfCqlRange) -> Self {
        Self::Timestamp(value)
    }
}

impl fmt::Display for ManifestRecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for ManifestRecordError {}

#[cfg(test)]
mod tests {
    use parth_core::{protocol::core_types::Q256BitHash, PHash};
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot,
        },
    };

    use super::*;
    use crate::store::{
        authority_commit::{
            AuthorityClockSampleUs, AuthorityTimestampBootstrap,
            AuthorityTimestampBootstrapReason,
        },
        manifest_intent::{
            AuthorityHeadPayload, AuthorityStateTransition,
            ManifestArtifactSetCommitment,
        },
    };

    fn hash(seed: u8) -> PHash {
        PHash::from_owned_32bytes([seed; 32])
    }

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::PsyPublicTestnet)
    }

    fn chain(checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            network(),
            ChainEpoch::new(3),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(hash(seed)),
            ),
        )
    }

    fn prepared(
        summary: &[u8],
    ) -> PreparedAuthorityManifestIntent<PHash> {
        let key = AuthorityTimestampKey::new(
            network(),
            AuthorityScope::Realm {
                realm_id: 4,
                realm_sub_id: 2,
            },
        );
        let artifacts = ManifestArtifactSetCommitment::from_verified_artifact_summary(
            summary,
            [0x44; 32],
            1,
            1,
            0,
            2,
        )
        .unwrap();
        let intent = SealedAuthorityCommitIntent::seal_normal_advance(
            key,
            chain(40, 1),
            chain(41, 2),
            AuthorityStateTransition::Unchanged {
                checkpoint: AuthorityStateCheckpointId::new(39),
                root: AuthorityStateRoot::from_local_state_root(hash(8)),
            },
            AuthorityHeadPayload::try_new(vec![0x55; 12]).unwrap(),
            artifacts,
        )
        .unwrap();
        let bootstrap = AuthorityTimestampBootstrap::new(
            key,
            CommitWriteTimestampUs::try_from_i128(100).unwrap(),
            AuthorityTimestampBootstrapReason::GenesisNative,
        );
        let reservation = bootstrap
            .candidate()
            .seal_reservation(
                key,
                intent.digest(),
                AuthorityClockSampleUs::try_from_i128(101).unwrap(),
            )
            .unwrap();
        intent.attach_timestamp_lease(reservation.lease()).unwrap()
    }

    #[test]
    fn prepared_record_round_trip_is_canonical_and_stable() {
        let summary = b"verified-artifact-summary-v1";
        let record = PreparedAuthorityManifestRecord::seal(
            &prepared(summary),
            summary.to_vec(),
        )
        .unwrap();
        assert_eq!(record.revision(), ManifestRevision::prepared());
        assert_eq!(record.status(), AuthorityManifestStatus::Prepared);
        assert_eq!(record.identity().checkpoint_bucket(), 0);
        let decoded = PreparedAuthorityManifestRecord::<PHash>::decode_persisted(
            *record.identity(),
            record.revision().as_i64(),
            record.status() as i8,
            record.digest().as_bytes(),
            record.encode_canonical(),
        )
        .unwrap();
        assert_eq!(decoded, record);
    }

    #[test]
    fn payload_digest_identity_and_summary_tampering_fail_closed() {
        let summary = b"verified-artifact-summary-v1";
        let record = PreparedAuthorityManifestRecord::seal(
            &prepared(summary),
            summary.to_vec(),
        )
        .unwrap();
        let mut payload = record.encode_canonical().to_vec();
        *payload.last_mut().unwrap() ^= 1;
        assert_eq!(
            PreparedAuthorityManifestRecord::<PHash>::decode_persisted(
                *record.identity(),
                0,
                1,
                record.digest().as_bytes(),
                &payload,
            )
            .unwrap_err(),
            ManifestRecordError::ManifestDigestMismatch
        );

        let wrong_identity = AuthorityManifestIdentity::try_new(
            record.identity().timestamp_key(),
            CanonicalChainRef::new(
                network(),
                ChainEpoch::new(3),
                CheckpointRef::new(
                    CheckpointId::new(42),
                    CheckpointHash::from_last_chain_hash(hash(9)),
                ),
            ),
        )
        .unwrap();
        assert_eq!(
            PreparedAuthorityManifestRecord::<PHash>::decode_persisted(
                wrong_identity,
                0,
                1,
                record.digest().as_bytes(),
                record.encode_canonical(),
            )
            .unwrap_err(),
            ManifestRecordError::SelectedIdentityMismatch
        );
    }

    #[test]
    fn prepared_insert_is_idempotent_only_for_the_exact_record() {
        let first_summary = b"verified-artifact-summary-v1";
        let first = PreparedAuthorityManifestRecord::seal(
            &prepared(first_summary),
            first_summary.to_vec(),
        )
        .unwrap();
        assert!(matches!(
            first
                .classify_insert_observation(false, first.clone())
                .unwrap(),
            PreparedManifestWriteOutcome::Idempotent(_)
        ));

        let second_summary = b"verified-artifact-summary-v2";
        let second = PreparedAuthorityManifestRecord::seal(
            &prepared(second_summary),
            second_summary.to_vec(),
        )
        .unwrap();
        assert!(matches!(
            first.classify_insert_observation(false, second).unwrap(),
            PreparedManifestWriteOutcome::Conflict(_)
        ));
        let third_summary = b"verified-artifact-summary-v3";
        let third = PreparedAuthorityManifestRecord::seal(
            &prepared(third_summary),
            third_summary.to_vec(),
        )
        .unwrap();
        assert_eq!(
            first.classify_insert_observation(true, third).unwrap_err(),
            ManifestRecordError::AppliedInsertMismatch
        );
    }

    #[test]
    fn manifest_identity_includes_epoch_and_rejects_network_mismatch() {
        let key = AuthorityTimestampKey::new(
            network(),
            AuthorityScope::Realm {
                realm_id: 4,
                realm_sub_id: 2,
            },
        );
        let epoch_three = AuthorityManifestIdentity::try_new(
            key,
            chain(41, 2),
        )
        .unwrap();
        let epoch_four = AuthorityManifestIdentity::try_new(
            key,
            CanonicalChainRef::new(
                network(),
                ChainEpoch::new(4),
                CheckpointRef::new(
                    CheckpointId::new(41),
                    CheckpointHash::from_last_chain_hash(hash(2)),
                ),
            ),
        )
        .unwrap();
        assert_ne!(epoch_three, epoch_four);

        let other_network = NetworkId::try_from_chain_id(0).unwrap();
        assert_eq!(
            AuthorityManifestIdentity::try_new(
                key,
                CanonicalChainRef::new(
                    other_network,
                    ChainEpoch::new(3),
                    CheckpointRef::new(
                        CheckpointId::new(41),
                        CheckpointHash::from_last_chain_hash(hash(2)),
                    ),
                ),
            )
            .unwrap_err(),
            ManifestRecordError::IdentityNetworkMismatch
        );
    }
}
