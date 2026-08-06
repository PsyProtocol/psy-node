//! Driver-independent authority commit-intent contract for D-03.
//!
//! The intent binds one normal authority advance to its exact old/new chain
//! identity, authority-local state transition, target head payload, and the
//! verified locator/replay artifact commitment. It deliberately contains no
//! clock allocation logic and executes no storage operation.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::{
    canonical_chain::{CanonicalChainRef, CanonicalChainRefCodecError},
    chain_context::{AuthorityScope, AuthorityStateCheckpointId, AuthorityStateRoot},
};
use sha2::{Digest, Sha256};

use super::{
    authority_commit::{
        AuthorityCommitIntentDigest, AuthorityTimestampKey,
        AuthorityTimestampLease,
    },
    timestamp::CommitWriteTimestampUs,
};

pub const AUTHORITY_COMMIT_INTENT_MAGIC: [u8; 8] = *b"PSYCMINT";
pub const AUTHORITY_COMMIT_INTENT_CODEC_VERSION: u16 = 1;
pub const MAX_AUTHORITY_HEAD_PAYLOAD_BYTES: usize = 1024 * 1024;

const INTENT_DIGEST_DOMAIN: &[u8] = b"psy.rollback.authority-commit-intent.v1\0";
const ARTIFACT_SET_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.manifest-artifact-set.v1\0";
const AUTHORITY_SCOPE_LEN: usize = 7;

/// Digest and cardinality summary produced by the typed locator/replay
/// artifact builder. The constructor hashes canonical summary bytes instead
/// of accepting a caller-supplied digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestArtifactSetCommitment {
    digest: [u8; 32],
    mutation_digest: [u8; 32],
    locator_chunk_count: u32,
    replay_chunk_count: u32,
    durable_payload_chunk_count: u32,
    affected_row_count: u64,
}

impl ManifestArtifactSetCommitment {
    pub fn from_verified_artifact_summary(
        canonical_summary: &[u8],
        mutation_digest: [u8; 32],
        locator_chunk_count: u32,
        replay_chunk_count: u32,
        durable_payload_chunk_count: u32,
        affected_row_count: u64,
    ) -> Result<Self, ManifestIntentError> {
        if canonical_summary.is_empty() {
            return Err(ManifestIntentError::EmptyArtifactSummary);
        }
        let mut hasher = Sha256::new();
        hasher.update(ARTIFACT_SET_DIGEST_DOMAIN);
        hasher.update((canonical_summary.len() as u64).to_be_bytes());
        hasher.update(canonical_summary);
        Ok(Self {
            digest: hasher.finalize().into(),
            mutation_digest,
            locator_chunk_count,
            replay_chunk_count,
            durable_payload_chunk_count,
            affected_row_count,
        })
    }

    pub const fn digest(self) -> [u8; 32] {
        self.digest
    }

    pub const fn mutation_digest(self) -> [u8; 32] {
        self.mutation_digest
    }

    pub const fn locator_chunk_count(self) -> u32 {
        self.locator_chunk_count
    }

    pub const fn replay_chunk_count(self) -> u32 {
        self.replay_chunk_count
    }

    pub const fn durable_payload_chunk_count(self) -> u32 {
        self.durable_payload_chunk_count
    }

    pub const fn affected_row_count(self) -> u64 {
        self.affected_row_count
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.digest);
        out.extend_from_slice(&self.mutation_digest);
        out.extend_from_slice(&self.locator_chunk_count.to_le_bytes());
        out.extend_from_slice(&self.replay_chunk_count.to_le_bytes());
        out.extend_from_slice(&self.durable_payload_chunk_count.to_le_bytes());
        out.extend_from_slice(&self.affected_row_count.to_le_bytes());
    }
}

/// Small canonical payload needed to restore the authority's local head,
/// singleton and cursor view. This is not a state snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityHeadPayload(Vec<u8>);

impl AuthorityHeadPayload {
    pub fn try_new(bytes: Vec<u8>) -> Result<Self, ManifestIntentError> {
        if bytes.is_empty() {
            return Err(ManifestIntentError::EmptyAuthorityHeadPayload);
        }
        if bytes.len() > MAX_AUTHORITY_HEAD_PAYLOAD_BYTES {
            return Err(ManifestIntentError::AuthorityHeadPayloadTooLarge {
                actual: bytes.len(),
                maximum: MAX_AUTHORITY_HEAD_PAYLOAD_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Authority-local logical state movement within one dense Coordinator
/// checkpoint receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityStateTransition<Hash> {
    Changed {
        previous_checkpoint: AuthorityStateCheckpointId,
        checkpoint: AuthorityStateCheckpointId,
        old_root: AuthorityStateRoot<Hash>,
        new_root: AuthorityStateRoot<Hash>,
    },
    Unchanged {
        checkpoint: AuthorityStateCheckpointId,
        root: AuthorityStateRoot<Hash>,
    },
}

impl<Hash: Q256BitHash> AuthorityStateTransition<Hash> {
    pub const fn state_changed(&self) -> bool {
        matches!(self, Self::Changed { .. })
    }

    pub const fn state_checkpoint(&self) -> AuthorityStateCheckpointId {
        match self {
            Self::Changed { checkpoint, .. }
            | Self::Unchanged { checkpoint, .. } => *checkpoint,
        }
    }

    pub const fn previous_state_checkpoint(&self) -> AuthorityStateCheckpointId {
        match self {
            Self::Changed {
                previous_checkpoint,
                ..
            } => *previous_checkpoint,
            Self::Unchanged { checkpoint, .. } => *checkpoint,
        }
    }

    pub const fn old_root(&self) -> &AuthorityStateRoot<Hash> {
        match self {
            Self::Changed { old_root, .. } => old_root,
            Self::Unchanged { root, .. } => root,
        }
    }

    pub const fn new_root(&self) -> &AuthorityStateRoot<Hash> {
        match self {
            Self::Changed { new_root, .. } => new_root,
            Self::Unchanged { root, .. } => root,
        }
    }
}

/// Complete normal-advance intent before timestamp allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedAuthorityCommitIntent<Hash> {
    key: AuthorityTimestampKey,
    expected_chain: CanonicalChainRef<Hash>,
    candidate_chain: CanonicalChainRef<Hash>,
    state_transition: AuthorityStateTransition<Hash>,
    head_payload: AuthorityHeadPayload,
    artifacts: ManifestArtifactSetCommitment,
    canonical_bytes: Vec<u8>,
    digest: AuthorityCommitIntentDigest,
}

impl<Hash: Q256BitHash> SealedAuthorityCommitIntent<Hash> {
    pub fn seal_normal_advance(
        key: AuthorityTimestampKey,
        expected_chain: CanonicalChainRef<Hash>,
        candidate_chain: CanonicalChainRef<Hash>,
        state_transition: AuthorityStateTransition<Hash>,
        head_payload: AuthorityHeadPayload,
        artifacts: ManifestArtifactSetCommitment,
    ) -> Result<Self, ManifestIntentError> {
        validate_normal_advance(
            key,
            &expected_chain,
            &candidate_chain,
            &state_transition,
        )?;
        let canonical_bytes = encode_intent(
            key,
            &expected_chain,
            &candidate_chain,
            &state_transition,
            &head_payload,
            artifacts,
        );
        let mut hasher = Sha256::new();
        hasher.update(INTENT_DIGEST_DOMAIN);
        hasher.update((canonical_bytes.len() as u64).to_be_bytes());
        hasher.update(&canonical_bytes);
        let digest = AuthorityCommitIntentDigest::from_sealed_commit_digest(
            hasher.finalize().into(),
        );
        Ok(Self {
            key,
            expected_chain,
            candidate_chain,
            state_transition,
            head_payload,
            artifacts,
            canonical_bytes,
            digest,
        })
    }

    pub const fn key(&self) -> AuthorityTimestampKey {
        self.key
    }

    pub const fn expected_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.expected_chain
    }

    pub const fn candidate_chain(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate_chain
    }

    pub const fn state_transition(&self) -> &AuthorityStateTransition<Hash> {
        &self.state_transition
    }

    pub const fn head_payload(&self) -> &AuthorityHeadPayload {
        &self.head_payload
    }

    pub const fn artifacts(&self) -> ManifestArtifactSetCommitment {
        self.artifacts
    }

    pub fn encode_canonical(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub const fn digest(&self) -> AuthorityCommitIntentDigest {
        self.digest
    }

    pub fn attach_timestamp_lease(
        self,
        lease: AuthorityTimestampLease,
    ) -> Result<PreparedAuthorityManifestIntent<Hash>, ManifestIntentError> {
        if lease.key() != self.key {
            return Err(ManifestIntentError::TimestampLeaseAuthorityMismatch);
        }
        if lease.intent() != self.digest {
            return Err(ManifestIntentError::TimestampLeaseIntentMismatch);
        }
        Ok(PreparedAuthorityManifestIntent {
            intent: self,
            commit_write_timestamp: lease.timestamp(),
            lease,
        })
    }
}

/// PREPARED-ready intent: the exact sealed commit now owns one durable
/// authority timestamp lease. It still does not imply chunks were persisted.
/// Its private fields prevent callers from attaching a timestamp without the
/// allocator-issued lease and exact intent-digest check.
///
/// ```compile_fail
/// use psy_node_core::store::{
///     authority_commit::AuthorityTimestampLease,
///     manifest_intent::{PreparedAuthorityManifestIntent, SealedAuthorityCommitIntent},
///     timestamp::CommitWriteTimestampUs,
/// };
///
/// fn forge<Hash>(
///     intent: SealedAuthorityCommitIntent<Hash>,
///     timestamp: CommitWriteTimestampUs,
///     lease: AuthorityTimestampLease,
/// ) -> PreparedAuthorityManifestIntent<Hash> {
///     PreparedAuthorityManifestIntent {
///         intent,
///         commit_write_timestamp: timestamp,
///         lease,
///     }
/// }
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedAuthorityManifestIntent<Hash> {
    intent: SealedAuthorityCommitIntent<Hash>,
    commit_write_timestamp: CommitWriteTimestampUs,
    lease: AuthorityTimestampLease,
}

impl<Hash> PreparedAuthorityManifestIntent<Hash> {
    pub const fn intent(&self) -> &SealedAuthorityCommitIntent<Hash> {
        &self.intent
    }

    pub const fn commit_write_timestamp(&self) -> CommitWriteTimestampUs {
        self.commit_write_timestamp
    }

    pub const fn lease(&self) -> AuthorityTimestampLease {
        self.lease
    }
}

fn validate_normal_advance<Hash: Q256BitHash>(
    key: AuthorityTimestampKey,
    expected: &CanonicalChainRef<Hash>,
    candidate: &CanonicalChainRef<Hash>,
    state: &AuthorityStateTransition<Hash>,
) -> Result<(), ManifestIntentError> {
    if expected.network_id() != key.network()
        || candidate.network_id() != key.network()
    {
        return Err(ManifestIntentError::NetworkMismatch);
    }
    if candidate.chain_epoch() != expected.chain_epoch() {
        return Err(ManifestIntentError::ChainEpochChangedDuringNormalAdvance);
    }
    let expected_id = expected.checkpoint().checkpoint_id().get();
    let candidate_id = candidate.checkpoint().checkpoint_id().get();
    if expected_id.checked_add(1) != Some(candidate_id) {
        return Err(ManifestIntentError::CheckpointNotExactSuccessor {
            expected: expected_id,
            candidate: candidate_id,
        });
    }

    match state {
        AuthorityStateTransition::Changed {
            previous_checkpoint,
            checkpoint,
            old_root,
            new_root,
        } => {
            if checkpoint.get() != candidate_id {
                return Err(ManifestIntentError::ChangedStateCheckpointNotCandidate {
                    state_checkpoint: checkpoint.get(),
                    candidate: candidate_id,
                });
            }
            if previous_checkpoint.get() > expected_id {
                return Err(ManifestIntentError::PreviousStateCheckpointAheadOfHead {
                    previous: previous_checkpoint.get(),
                    expected_head: expected_id,
                });
            }
            if old_root.as_inner().into_owned_32bytes()
                == new_root.as_inner().into_owned_32bytes()
            {
                return Err(ManifestIntentError::ChangedStateHasSameRoot);
            }
        }
        AuthorityStateTransition::Unchanged { checkpoint, .. } => {
            if checkpoint.get() > expected_id {
                return Err(ManifestIntentError::UnchangedStateCheckpointAheadOfHead {
                    state_checkpoint: checkpoint.get(),
                    expected_head: expected_id,
                });
            }
        }
    }
    Ok(())
}

fn encode_intent<Hash: Q256BitHash>(
    key: AuthorityTimestampKey,
    expected: &CanonicalChainRef<Hash>,
    candidate: &CanonicalChainRef<Hash>,
    state: &AuthorityStateTransition<Hash>,
    head_payload: &AuthorityHeadPayload,
    artifacts: ManifestArtifactSetCommitment,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(320 + head_payload.as_bytes().len());
    out.extend_from_slice(&AUTHORITY_COMMIT_INTENT_MAGIC);
    out.extend_from_slice(&AUTHORITY_COMMIT_INTENT_CODEC_VERSION.to_le_bytes());
    out.extend_from_slice(&key.network().chain_id().to_le_bytes());
    encode_authority(key.authority(), &mut out);
    out.extend_from_slice(&expected.to_canonical_bytes());
    out.extend_from_slice(&candidate.to_canonical_bytes());
    out.push(u8::from(state.state_changed()));
    out.extend_from_slice(&state.previous_state_checkpoint().get().to_le_bytes());
    out.extend_from_slice(&state.state_checkpoint().get().to_le_bytes());
    out.extend_from_slice(&state.old_root().as_inner().into_owned_32bytes());
    out.extend_from_slice(&state.new_root().as_inner().into_owned_32bytes());
    artifacts.encode_into(&mut out);
    out.extend_from_slice(&(head_payload.as_bytes().len() as u32).to_le_bytes());
    out.extend_from_slice(head_payload.as_bytes());
    out
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    let mut bytes = [0u8; AUTHORITY_SCOPE_LEN];
    match authority {
        AuthorityScope::Coordinator => bytes[0] = 1,
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            bytes[0] = 2;
            bytes[1..5].copy_from_slice(&realm_id.to_le_bytes());
            bytes[5..7].copy_from_slice(&realm_sub_id.to_le_bytes());
        }
    }
    out.extend_from_slice(&bytes);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestIntentError {
    EmptyArtifactSummary,
    EmptyAuthorityHeadPayload,
    AuthorityHeadPayloadTooLarge { actual: usize, maximum: usize },
    NetworkMismatch,
    ChainEpochChangedDuringNormalAdvance,
    CheckpointNotExactSuccessor { expected: u64, candidate: u64 },
    ChangedStateCheckpointNotCandidate { state_checkpoint: u64, candidate: u64 },
    PreviousStateCheckpointAheadOfHead { previous: u64, expected_head: u64 },
    ChangedStateHasSameRoot,
    UnchangedStateCheckpointAheadOfHead { state_checkpoint: u64, expected_head: u64 },
    TimestampLeaseAuthorityMismatch,
    TimestampLeaseIntentMismatch,
    CanonicalChain(CanonicalChainRefCodecError),
}

impl fmt::Display for ManifestIntentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ManifestIntentError {}

#[cfg(test)]
mod tests {
    use parth_core::{
        protocol::core_types::Q256BitHash,
        PHash,
    };
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
    use crate::store::authority_commit::{
        AuthorityClockSampleUs, AuthorityTimestampBootstrap,
        AuthorityTimestampBootstrapReason,
    };

    fn hash(seed: u8) -> PHash {
        PHash::from_owned_32bytes([seed; 32])
    }

    fn network() -> NetworkId {
        NetworkId::from_network_type(PsyChainNetworkType::PsyPublicTestnet)
    }

    fn chain(epoch: u64, checkpoint: u64, seed: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            network(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(hash(seed)),
            ),
        )
    }

    fn artifacts(seed: u8) -> ManifestArtifactSetCommitment {
        ManifestArtifactSetCommitment::from_verified_artifact_summary(
            &[seed; 16],
            [seed.wrapping_add(1); 32],
            1,
            2,
            1,
            9,
        )
        .unwrap()
    }

    fn unchanged() -> AuthorityStateTransition<PHash> {
        AuthorityStateTransition::Unchanged {
            checkpoint: AuthorityStateCheckpointId::new(99),
            root: AuthorityStateRoot::from_local_state_root(hash(7)),
        }
    }

    fn key() -> AuthorityTimestampKey {
        AuthorityTimestampKey::new(
            network(),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 2,
            },
        )
    }

    fn seal(seed: u8) -> SealedAuthorityCommitIntent<PHash> {
        SealedAuthorityCommitIntent::seal_normal_advance(
            key(),
            chain(4, 100, 10),
            chain(4, 101, 11),
            unchanged(),
            AuthorityHeadPayload::try_new(vec![seed; 12]).unwrap(),
            artifacts(seed),
        )
        .unwrap()
    }

    #[test]
    fn canonical_intent_is_stable_and_binds_every_dimension() {
        let first = seal(30);
        let second = seal(30);
        assert_eq!(first, second);
        assert_eq!(first.encode_canonical(), second.encode_canonical());
        assert_eq!(first.digest(), second.digest());
        assert_ne!(first.digest(), seal(31).digest());
        assert_eq!(&first.encode_canonical()[..8], b"PSYCMINT");
    }

    #[test]
    fn normal_advance_and_sparse_state_are_fail_closed() {
        let wrong_epoch = SealedAuthorityCommitIntent::seal_normal_advance(
            key(),
            chain(4, 100, 10),
            chain(5, 101, 11),
            unchanged(),
            AuthorityHeadPayload::try_new(vec![1]).unwrap(),
            artifacts(1),
        );
        assert_eq!(
            wrong_epoch.unwrap_err(),
            ManifestIntentError::ChainEpochChangedDuringNormalAdvance
        );
        let jump = SealedAuthorityCommitIntent::seal_normal_advance(
            key(),
            chain(4, 100, 10),
            chain(4, 102, 11),
            unchanged(),
            AuthorityHeadPayload::try_new(vec![1]).unwrap(),
            artifacts(1),
        );
        assert!(matches!(
            jump,
            Err(ManifestIntentError::CheckpointNotExactSuccessor { .. })
        ));

        let changed_same_root = AuthorityStateTransition::Changed {
            previous_checkpoint: AuthorityStateCheckpointId::new(99),
            checkpoint: AuthorityStateCheckpointId::new(101),
            old_root: AuthorityStateRoot::from_local_state_root(hash(8)),
            new_root: AuthorityStateRoot::from_local_state_root(hash(8)),
        };
        assert_eq!(
            SealedAuthorityCommitIntent::seal_normal_advance(
                key(),
                chain(4, 100, 10),
                chain(4, 101, 11),
                changed_same_root,
                AuthorityHeadPayload::try_new(vec![1]).unwrap(),
                artifacts(1),
            )
            .unwrap_err(),
            ManifestIntentError::ChangedStateHasSameRoot
        );
    }

    #[test]
    fn only_the_exact_allocator_lease_can_prepare_the_manifest() {
        let intent = seal(40);
        let bootstrap = AuthorityTimestampBootstrap::new(
            key(),
            CommitWriteTimestampUs::try_from_i128(10).unwrap(),
            AuthorityTimestampBootstrapReason::GenesisNative,
        );
        let reservation = bootstrap
            .candidate()
            .seal_reservation(
                key(),
                intent.digest(),
                AuthorityClockSampleUs::try_from_i128(20).unwrap(),
            )
            .unwrap();
        let prepared = intent.clone().attach_timestamp_lease(reservation.lease()).unwrap();
        assert_eq!(prepared.intent(), &intent);
        assert_eq!(prepared.commit_write_timestamp().as_i64(), 20);

        let other = seal(41);
        assert_eq!(
            other.attach_timestamp_lease(reservation.lease()).unwrap_err(),
            ManifestIntentError::TimestampLeaseIntentMismatch
        );
    }

    #[test]
    fn empty_artifacts_and_head_payload_are_rejected() {
        assert_eq!(
            ManifestArtifactSetCommitment::from_verified_artifact_summary(
                &[], [0; 32], 0, 0, 0, 0
            )
            .unwrap_err(),
            ManifestIntentError::EmptyArtifactSummary
        );
        assert_eq!(
            AuthorityHeadPayload::try_new(Vec::new()).unwrap_err(),
            ManifestIntentError::EmptyAuthorityHeadPayload
        );
    }
}
