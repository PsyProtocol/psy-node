//! Durable source envelope for one normal Coordinator checkpoint commit.
//!
//! The legacy production writer does not yet emit the physical locator
//! manifest needed by delete-only rollback.  This envelope preserves the
//! exact canonical prepared update before any hot-table mutation.  A versioned
//! adapter can later derive and verify the physical inventory.  It is not by
//! itself delete authority: rollback catalogues must additionally require the
//! immutable COMMITTED marker written after state and checkpoint backup are
//! durable.

use std::{error::Error, fmt};

use async_trait::async_trait;

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CanonicalChainRef, CanonicalChainRefCodecError, CANONICAL_CHAIN_REF_V1_LEN,
};
use sha2::{Digest, Sha256};

use super::canonical_head::{
    CanonicalHeadModelError, CanonicalHeadTransition, StoredCanonicalHead,
};

const HEADER_MAGIC: &[u8; 8] = b"PSYCCSRC";
const MARKER_MAGIC: &[u8; 8] = b"PSYCCCOM";
const PAYLOAD_MAGIC: &[u8; 8] = b"PSYCCPAY";
const FLOOR_MAGIC: &[u8; 8] = b"PSYCCFLR";
const CODEC_VERSION: u16 = 1;
pub const COORDINATOR_PREPARED_UPDATE_CODEC_VERSION: u16 = 1;
pub const COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const COORDINATOR_COMMIT_SOURCE_MAX_BYTES: usize = 64 * 1024 * 1024;
pub const COORDINATOR_COMMIT_SOURCE_MAX_FRAGMENTS: usize =
    COORDINATOR_COMMIT_SOURCE_MAX_BYTES / COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.coordinator-commit-source-slot.v1\0";
const SOURCE_DOMAIN: &[u8] = b"psy.rollback.coordinator-commit-source-bytes.v1\0";
const OBJECT_DOMAIN: &[u8] = b"psy.rollback.coordinator-commit-source-object.v1\0";
const MARKER_DOMAIN: &[u8] = b"psy.rollback.coordinator-commit-source-committed.v1\0";
const BACKUP_EVIDENCE_DOMAIN: &[u8] =
    b"psy.rollback.coordinator-checkpoint-backup-evidence.v1\0";
const FLOOR_DOMAIN: &[u8] = b"psy.rollback.coordinator-commit-source-floor.v1\0";
const FLOOR_ROW_REVISION: i64 = 1;

/// Canonical normal-commit input persisted inside the fragmented source.
/// Besides the prepared state update it binds the exact proof/circuit bytes
/// that are written to the checkpoint proof table. This prevents two commits
/// with the same state/candidate identity but different proof payloads from
/// sharing a source object.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCommitSourcePayload {
    prepared_update: Vec<u8>,
    circuit_type: u32,
    proof: Vec<u8>,
}

impl CoordinatorCommitSourcePayload {
    pub fn try_new(
        prepared_update: Vec<u8>,
        circuit_type: u32,
        proof: Vec<u8>,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        if prepared_update.is_empty() {
            return Err(CoordinatorCommitSourceError::EmptyPreparedUpdate);
        }
        if proof.is_empty() {
            return Err(CoordinatorCommitSourceError::EmptyNormalCheckpointProof);
        }
        let encoded_len = 8_usize
            .checked_add(2 + 4 + 8 + 8)
            .and_then(|length| length.checked_add(prepared_update.len()))
            .and_then(|length| length.checked_add(proof.len()))
            .ok_or(CoordinatorCommitSourceError::PreparedUpdateTooLarge {
                actual: usize::MAX,
                maximum: COORDINATOR_COMMIT_SOURCE_MAX_BYTES,
            })?;
        if encoded_len > COORDINATOR_COMMIT_SOURCE_MAX_BYTES {
            return Err(CoordinatorCommitSourceError::PreparedUpdateTooLarge {
                actual: encoded_len,
                maximum: COORDINATOR_COMMIT_SOURCE_MAX_BYTES,
            });
        }
        Ok(Self {
            prepared_update,
            circuit_type,
            proof,
        })
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            8 + 2 + 4 + 8 + 8 + self.prepared_update.len() + self.proof.len(),
        );
        bytes.extend_from_slice(PAYLOAD_MAGIC);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.circuit_type.to_be_bytes());
        bytes.extend_from_slice(&(self.prepared_update.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(self.proof.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&self.prepared_update);
        bytes.extend_from_slice(&self.proof);
        bytes
    }

    pub fn decode_canonical(
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitSourceError> {
        if bytes.len() > COORDINATOR_COMMIT_SOURCE_MAX_BYTES {
            return Err(CoordinatorCommitSourceError::PreparedUpdateTooLarge {
                actual: bytes.len(),
                maximum: COORDINATOR_COMMIT_SOURCE_MAX_BYTES,
            });
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != PAYLOAD_MAGIC {
            return Err(CoordinatorCommitSourceError::InvalidPayloadMagic);
        }
        let version = cursor.u16()?;
        if version != CODEC_VERSION {
            return Err(CoordinatorCommitSourceError::UnknownPayloadVersion(version));
        }
        let circuit_type = cursor.u32()?;
        let prepared_len_u64 = cursor.u64()?;
        let proof_len_u64 = cursor.u64()?;
        let prepared_len = usize::try_from(prepared_len_u64).map_err(|_| {
            CoordinatorCommitSourceError::InvalidPersistedSourceLengthU64(
                prepared_len_u64,
            )
        })?;
        let proof_len = usize::try_from(proof_len_u64).map_err(|_| {
            CoordinatorCommitSourceError::InvalidPersistedSourceLengthU64(
                proof_len_u64,
            )
        })?;
        let prepared_update = cursor.take(prepared_len)?.to_vec();
        let proof = cursor.take(proof_len)?.to_vec();
        if !cursor.is_empty() {
            return Err(CoordinatorCommitSourceError::TrailingPayloadBytes);
        }
        let decoded = Self::try_new(prepared_update, circuit_type, proof)?;
        if decoded.encode_canonical() != bytes {
            return Err(CoordinatorCommitSourceError::NonCanonicalPayload);
        }
        Ok(decoded)
    }

    pub fn prepared_update(&self) -> &[u8] {
        &self.prepared_update
    }

    pub const fn circuit_type(&self) -> u32 {
        self.circuit_type
    }

    pub fn proof(&self) -> &[u8] {
        &self.proof
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorCommitSourceSlot([u8; 32]);

impl CoordinatorCommitSourceSlot {
    pub const fn as_bytes(self) -> [u8; 32] { self.0 }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CoordinatorCommitSourceDigest([u8; 32]);

impl CoordinatorCommitSourceDigest {
    pub const fn as_bytes(self) -> [u8; 32] { self.0 }
}

/// Canonical, fragmentable source persisted before normal state writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoordinatorCommitSource<Hash> {
    expected_revision: u64,
    expected: CanonicalChainRef<Hash>,
    candidate: CanonicalChainRef<Hash>,
    prepared_update_codec_version: u16,
    prepared_update: Vec<u8>,
    source_digest: [u8; 32],
    slot: CoordinatorCommitSourceSlot,
    digest: CoordinatorCommitSourceDigest,
}

/// Inert, source-bound observation of one exact local checkpoint backup.
///
/// This is intentionally not a commit marker or head-publication capability.
/// The controlled full-commit owner may consume it only after independently
/// re-reading the immutable source and full-write manifest.
#[derive(Debug, Eq, PartialEq)]
pub struct CoordinatorCheckpointBackupEvidence<Hash> {
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    candidate: CanonicalChainRef<Hash>,
    checkpoint_id: u64,
    checkpoint_hash: Hash,
    old_root: Hash,
    new_root: Hash,
    min_backed_up_checkpoint_id: u64,
    next_backup_checkpoint_id: u64,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCheckpointBackupEvidence<Hash> {
    pub fn try_from_exact_source(
        source: &CoordinatorCommitSource<Hash>,
        checkpoint_id: u64,
        checkpoint_hash: Hash,
        old_root: Hash,
        new_root: Hash,
        min_backed_up_checkpoint_id: u64,
        next_backup_checkpoint_id: u64,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        let expected_next = checkpoint_id
            .checked_add(1)
            .ok_or(CoordinatorCommitSourceError::CheckpointBackupIdOverflow)?;
        if source.candidate().checkpoint().checkpoint_id().get() != checkpoint_id
            || next_backup_checkpoint_id != expected_next
            || min_backed_up_checkpoint_id > checkpoint_id
            || old_root == new_root
        {
            return Err(CoordinatorCommitSourceError::CheckpointBackupIdentityMismatch);
        }
        let mut evidence = Self {
            source_slot: source.slot().as_bytes(),
            source_digest: source.digest().as_bytes(),
            candidate: *source.candidate(),
            checkpoint_id,
            checkpoint_hash,
            old_root,
            new_root,
            min_backed_up_checkpoint_id,
            next_backup_checkpoint_id,
            digest: [0; 32],
        };
        evidence.digest = evidence.compute_digest();
        Ok(evidence)
    }

    fn compute_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(BACKUP_EVIDENCE_DOMAIN);
        hasher.update(self.source_slot);
        hasher.update(self.source_digest);
        hasher.update(self.candidate.to_canonical_bytes());
        hasher.update(self.checkpoint_id.to_be_bytes());
        hasher.update(self.checkpoint_hash.into_owned_32bytes());
        hasher.update(self.old_root.into_owned_32bytes());
        hasher.update(self.new_root.into_owned_32bytes());
        hasher.update(self.min_backed_up_checkpoint_id.to_be_bytes());
        hasher.update(self.next_backup_checkpoint_id.to_be_bytes());
        hasher.finalize().into()
    }

    pub const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub const fn checkpoint_id(&self) -> u64 {
        self.checkpoint_id
    }

    pub const fn checkpoint_hash(&self) -> &Hash {
        &self.checkpoint_hash
    }

    pub const fn old_root(&self) -> &Hash {
        &self.old_root
    }

    pub const fn new_root(&self) -> &Hash {
        &self.new_root
    }

    pub const fn min_backed_up_checkpoint_id(&self) -> u64 {
        self.min_backed_up_checkpoint_id
    }

    pub const fn next_backup_checkpoint_id(&self) -> u64 {
        self.next_backup_checkpoint_id
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Durable normal-commit source boundary. The canonical-head writer depends
/// on this capability so neither the live commit path nor startup recovery can
/// publish a normal candidate without first making its source and COMMITTED
/// marker exact. Implementations must be append-only and fail closed on a
/// same-identity/different-content observation.
#[async_trait]
pub trait CoordinatorCommitSourceStore<Hash: Q256BitHash>: Send + Sync {
    async fn persist_coordinator_rollback_floor(
        &self,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> anyhow::Result<()>;

    async fn read_coordinator_rollback_floor(
        &self,
        network: psy_data::protocol::canonical_chain::NetworkId,
        chain_epoch: u64,
    ) -> anyhow::Result<Option<CoordinatorRollbackFloor<Hash>>>;

    /// Make the exact mutable-singleton values at the immutable rollback floor
    /// durable. Implementations must be idempotent and may create a missing
    /// anchor only while `current` is still the exact floor activation head.
    /// A floor row without this companion evidence must fail closed once the
    /// live head has advanced because the historical singleton values can no
    /// longer be inferred from the current mutable rows.
    async fn ensure_coordinator_rollback_floor_singleton_anchor(
        &self,
        current: &StoredCanonicalHead<Hash>,
        floor: &CoordinatorRollbackFloor<Hash>,
    ) -> anyhow::Result<()>;

    /// Establish the conservative lower bound for source-backed rollback in
    /// one epoch. Existing rows win only when they are valid for the exact
    /// current branch; an active rollback can never mint a missing floor.
    async fn ensure_coordinator_rollback_floor(
        &self,
        current: &StoredCanonicalHead<Hash>,
    ) -> anyhow::Result<CoordinatorRollbackFloor<Hash>> {
        let network = current.canonical_ref().network_id();
        let chain_epoch = current.canonical_ref().chain_epoch().get();
        if let Some(floor) = self
            .read_coordinator_rollback_floor(network, chain_epoch)
            .await?
        {
            floor.validate_current_head(current)?;
            self.ensure_coordinator_rollback_floor_singleton_anchor(
                current,
                &floor,
            )
            .await?;
            return Ok(floor);
        }
        let floor = CoordinatorRollbackFloor::try_new(*current)?;
        self.persist_coordinator_rollback_floor(&floor).await?;
        let persisted = self
            .read_coordinator_rollback_floor(network, chain_epoch)
            .await?
            .ok_or_else(|| anyhow::anyhow!(
                "Coordinator rollback floor is missing after exact persistence"
            ))?;
        if persisted != floor {
            anyhow::bail!(
                "Coordinator rollback floor identity contains different content"
            );
        }
        persisted.validate_current_head(current)?;
        self.ensure_coordinator_rollback_floor_singleton_anchor(
            current,
            &persisted,
        )
        .await?;
        Ok(persisted)
    }

    async fn persist_coordinator_commit_source(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()>;

    async fn read_coordinator_commit_source(
        &self,
        candidate: &CanonicalChainRef<Hash>,
    ) -> anyhow::Result<Option<CoordinatorCommitSource<Hash>>>;

    async fn mark_coordinator_commit_source_committed(
        &self,
        source: &CoordinatorCommitSource<Hash>,
    ) -> anyhow::Result<()>;
}

/// Immutable lower bound for source-backed rollback in one chain epoch.
///
/// The stable physical identity is `(network, chain_epoch)`. The payload binds
/// the exact canonical head observed when this binary first established the
/// commit-source contract. It is feasibility evidence only: it cannot archive,
/// delete, restore, or publish a head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorRollbackFloor<Hash> {
    activation_head_revision: u64,
    floor: CanonicalChainRef<Hash>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorRollbackFloor<Hash> {
    pub fn try_new(
        current: StoredCanonicalHead<Hash>,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        if !current.rollback_control().is_idle() {
            return Err(CoordinatorCommitSourceError::RollbackFloorRequiresIdleHead);
        }
        let mut floor = Self {
            activation_head_revision: current.revision().get(),
            floor: *current.canonical_ref(),
            digest: [0; 32],
        };
        floor.digest = digest_bytes(FLOOR_DOMAIN, &floor.commitment_bytes());
        Ok(floor)
    }

    pub fn decode_persisted(
        partition_network: psy_data::protocol::canonical_chain::NetworkId,
        partition_epoch: u64,
        row_revision: i64,
        bytes: &[u8],
    ) -> Result<Self, CoordinatorCommitSourceError> {
        if row_revision != FLOOR_ROW_REVISION {
            return Err(CoordinatorCommitSourceError::InvalidRollbackFloorRowRevision(
                row_revision,
            ));
        }
        let mut cursor = Cursor::new(bytes);
        if cursor.take(8)? != FLOOR_MAGIC {
            return Err(CoordinatorCommitSourceError::InvalidRollbackFloorMagic);
        }
        let version = cursor.u16()?;
        if version != CODEC_VERSION {
            return Err(CoordinatorCommitSourceError::UnknownRollbackFloorVersion(version));
        }
        let activation_head_revision = cursor.u64()?;
        if activation_head_revision > i64::MAX as u64 {
            return Err(CoordinatorCommitSourceError::RevisionOutOfCqlRange(
                activation_head_revision,
            ));
        }
        let floor = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )?;
        let source_codec_version = cursor.u16()?;
        let prepared_update_codec_version = cursor.u16()?;
        let fragment_bytes = cursor.u32()? as usize;
        let maximum_bytes_u64 = cursor.u64()?;
        let maximum_bytes = usize::try_from(maximum_bytes_u64).map_err(|_| {
            CoordinatorCommitSourceError::InvalidPersistedSourceLengthU64(
                maximum_bytes_u64,
            )
        })?;
        let digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed length");
        if !cursor.is_empty() {
            return Err(CoordinatorCommitSourceError::TrailingRollbackFloorBytes);
        }
        if source_codec_version != CODEC_VERSION
            || prepared_update_codec_version
                != COORDINATOR_PREPARED_UPDATE_CODEC_VERSION
            || fragment_bytes != COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES
            || maximum_bytes != COORDINATOR_COMMIT_SOURCE_MAX_BYTES
        {
            return Err(CoordinatorCommitSourceError::RollbackFloorContractMismatch);
        }
        if floor.network_id() != partition_network
            || floor.chain_epoch().get() != partition_epoch
        {
            return Err(CoordinatorCommitSourceError::RollbackFloorPartitionMismatch);
        }
        let decoded = Self {
            activation_head_revision,
            floor,
            digest,
        };
        if digest_bytes(FLOOR_DOMAIN, &decoded.commitment_bytes()) != decoded.digest {
            return Err(CoordinatorCommitSourceError::RollbackFloorDigestMismatch);
        }
        if decoded.encode_canonical() != bytes {
            return Err(CoordinatorCommitSourceError::NonCanonicalRollbackFloor);
        }
        Ok(decoded)
    }

    pub fn encode_canonical(&self) -> Vec<u8> {
        let mut bytes = self.commitment_bytes();
        bytes.extend_from_slice(&self.digest);
        bytes
    }

    pub const fn activation_head_revision(&self) -> u64 {
        self.activation_head_revision
    }

    pub const fn floor(&self) -> &CanonicalChainRef<Hash> {
        &self.floor
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn validate_current_head(
        &self,
        current: &StoredCanonicalHead<Hash>,
    ) -> Result<(), CoordinatorCommitSourceError> {
        let current_ref = current.canonical_ref();
        if current_ref.network_id() != self.floor.network_id()
            || current_ref.chain_epoch() != self.floor.chain_epoch()
        {
            return Err(CoordinatorCommitSourceError::RollbackFloorBranchMismatch);
        }
        let floor_checkpoint = self.floor.checkpoint().checkpoint_id().get();
        let current_checkpoint = current_ref.checkpoint().checkpoint_id().get();
        if floor_checkpoint > current_checkpoint {
            return Err(CoordinatorCommitSourceError::RollbackFloorAboveCurrentHead {
                floor: floor_checkpoint,
                current: current_checkpoint,
            });
        }
        Ok(())
    }

    fn commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            8 + 2 + 8 + CANONICAL_CHAIN_REF_V1_LEN + 2 + 2 + 4 + 8,
        );
        bytes.extend_from_slice(FLOOR_MAGIC);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.activation_head_revision.to_be_bytes());
        bytes.extend_from_slice(&self.floor.to_canonical_bytes());
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&COORDINATOR_PREPARED_UPDATE_CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(
            &(COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES as u32).to_be_bytes(),
        );
        bytes.extend_from_slice(
            &(COORDINATOR_COMMIT_SOURCE_MAX_BYTES as u64).to_be_bytes(),
        );
        bytes
    }
}

impl<Hash: Q256BitHash> CoordinatorCommitSource<Hash> {
    pub fn try_new(
        expected: StoredCanonicalHead<Hash>,
        candidate: CanonicalChainRef<Hash>,
        prepared_update: Vec<u8>,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        let transition = CanonicalHeadTransition::normal_checkpoint_advance(
            expected,
            candidate,
        )?;
        if transition.candidate().canonical_ref() != &candidate {
            return Err(CoordinatorCommitSourceError::CandidateMismatch);
        }
        Self::from_validated_parts(
            expected.revision().get(),
            *expected.canonical_ref(),
            candidate,
            COORDINATOR_PREPARED_UPDATE_CODEC_VERSION,
            prepared_update,
        )
    }

    fn from_validated_parts(
        expected_revision: u64,
        expected: CanonicalChainRef<Hash>,
        candidate: CanonicalChainRef<Hash>,
        prepared_update_codec_version: u16,
        prepared_update: Vec<u8>,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        validate_refs(&expected, &candidate)?;
        if expected_revision > i64::MAX as u64 {
            return Err(CoordinatorCommitSourceError::RevisionOutOfCqlRange(
                expected_revision,
            ));
        }
        if prepared_update_codec_version != COORDINATOR_PREPARED_UPDATE_CODEC_VERSION {
            return Err(CoordinatorCommitSourceError::UnknownPreparedUpdateCodec(
                prepared_update_codec_version,
            ));
        }
        if prepared_update.is_empty() {
            return Err(CoordinatorCommitSourceError::EmptyPreparedUpdate);
        }
        if prepared_update.len() > COORDINATOR_COMMIT_SOURCE_MAX_BYTES {
            return Err(CoordinatorCommitSourceError::PreparedUpdateTooLarge {
                actual: prepared_update.len(),
                maximum: COORDINATOR_COMMIT_SOURCE_MAX_BYTES,
            });
        }
        let source_digest = digest_bytes(SOURCE_DOMAIN, &prepared_update);
        let slot = CoordinatorCommitSourceSlot(digest_bytes(
            SLOT_DOMAIN,
            &candidate.to_canonical_bytes(),
        ));
        let mut object = Self {
            expected_revision,
            expected,
            candidate,
            prepared_update_codec_version,
            prepared_update,
            source_digest,
            slot,
            digest: CoordinatorCommitSourceDigest([0; 32]),
        };
        object.digest = CoordinatorCommitSourceDigest(digest_bytes(
            OBJECT_DOMAIN,
            &object.object_commitment_bytes(),
        ));
        Ok(object)
    }

    pub const fn expected_revision(&self) -> u64 { self.expected_revision }
    pub const fn expected(&self) -> &CanonicalChainRef<Hash> { &self.expected }
    pub const fn candidate(&self) -> &CanonicalChainRef<Hash> { &self.candidate }
    pub const fn prepared_update_codec_version(&self) -> u16 {
        self.prepared_update_codec_version
    }
    pub fn prepared_update(&self) -> &[u8] { &self.prepared_update }
    pub const fn source_digest(&self) -> &[u8; 32] { &self.source_digest }
    pub const fn slot(&self) -> CoordinatorCommitSourceSlot { self.slot }
    pub const fn digest(&self) -> CoordinatorCommitSourceDigest { self.digest }

    pub fn fragment_count(&self) -> usize {
        self.prepared_update.len().div_ceil(COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES)
    }

    pub fn fragments(&self) -> impl ExactSizeIterator<Item = &[u8]> {
        self.prepared_update.chunks(COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES)
    }

    /// Header excludes the source bytes; fragments carry them separately.
    pub fn encode_header(&self) -> Vec<u8> {
        let mut bytes = self.header_without_digest();
        bytes.extend_from_slice(&self.digest.0);
        bytes
    }

    pub fn decode_persisted(
        header: &[u8],
        fragments: Vec<Vec<u8>>,
    ) -> Result<Self, CoordinatorCommitSourceError> {
        let mut cursor = Cursor::new(header);
        if cursor.take(8)? != HEADER_MAGIC {
            return Err(CoordinatorCommitSourceError::InvalidHeaderMagic);
        }
        let version = cursor.u16()?;
        if version != CODEC_VERSION {
            return Err(CoordinatorCommitSourceError::UnknownHeaderVersion(version));
        }
        let prepared_update_codec_version = cursor.u16()?;
        let expected_revision = cursor.u64()?;
        let expected = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )?;
        let candidate = CanonicalChainRef::from_canonical_bytes(
            cursor.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )?;
        let source_len_u64 = cursor.u64()?;
        let source_len = usize::try_from(source_len_u64)
            .map_err(|_| CoordinatorCommitSourceError::InvalidPersistedSourceLengthU64(
                source_len_u64,
            ))?;
        let fragment_bytes = cursor.u32()? as usize;
        if fragment_bytes != COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES {
            return Err(CoordinatorCommitSourceError::FragmentSizeMismatch {
                actual: fragment_bytes,
            });
        }
        let fragment_count = cursor.u32()? as usize;
        let source_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed length");
        let slot: [u8; 32] = cursor.take(32)?.try_into().expect("fixed length");
        let object_digest: [u8; 32] = cursor.take(32)?.try_into().expect("fixed length");
        if !cursor.is_empty() {
            return Err(CoordinatorCommitSourceError::TrailingHeaderBytes);
        }
        if source_len == 0 || source_len > COORDINATOR_COMMIT_SOURCE_MAX_BYTES {
            return Err(CoordinatorCommitSourceError::InvalidPersistedSourceLength(source_len));
        }
        let expected_fragment_count = source_len.div_ceil(COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES);
        if fragment_count != expected_fragment_count
            || fragment_count == 0
            || fragment_count > COORDINATOR_COMMIT_SOURCE_MAX_FRAGMENTS
            || fragments.len() != fragment_count
        {
            return Err(CoordinatorCommitSourceError::FragmentCountMismatch {
                expected: expected_fragment_count,
                actual: fragments.len(),
            });
        }
        for (index, fragment) in fragments.iter().enumerate() {
            let expected_len = if index + 1 == fragment_count {
                source_len - index * COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES
            } else {
                COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES
            };
            if fragment.len() != expected_len {
                return Err(CoordinatorCommitSourceError::FragmentLengthMismatch {
                    index,
                    expected: expected_len,
                    actual: fragment.len(),
                });
            }
        }
        let mut prepared_update = Vec::with_capacity(source_len);
        for fragment in fragments { prepared_update.extend_from_slice(&fragment); }
        let decoded = Self::from_validated_parts(
            expected_revision,
            expected,
            candidate,
            prepared_update_codec_version,
            prepared_update,
        )?;
        if decoded.source_digest != source_digest {
            return Err(CoordinatorCommitSourceError::SourceDigestMismatch);
        }
        if decoded.slot.0 != slot {
            return Err(CoordinatorCommitSourceError::SlotMismatch);
        }
        if decoded.digest.0 != object_digest || decoded.encode_header() != header {
            return Err(CoordinatorCommitSourceError::ObjectDigestMismatch);
        }
        Ok(decoded)
    }

    pub fn committed_marker(&self) -> CoordinatorCommitSourceCommitted {
        CoordinatorCommitSourceCommitted::from_source(self)
    }

    fn header_without_digest(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + 2 + 2 + 8 + 65 * 2 + 8 + 4 + 4 + 32 + 32);
        bytes.extend_from_slice(HEADER_MAGIC);
        bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes.extend_from_slice(&self.prepared_update_codec_version.to_be_bytes());
        bytes.extend_from_slice(&self.expected_revision.to_be_bytes());
        bytes.extend_from_slice(&self.expected.to_canonical_bytes());
        bytes.extend_from_slice(&self.candidate.to_canonical_bytes());
        bytes.extend_from_slice(&(self.prepared_update.len() as u64).to_be_bytes());
        bytes.extend_from_slice(&(COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES as u32).to_be_bytes());
        bytes.extend_from_slice(&(self.fragment_count() as u32).to_be_bytes());
        bytes.extend_from_slice(&self.source_digest);
        bytes.extend_from_slice(&self.slot.0);
        bytes
    }

    fn object_commitment_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header_without_digest();
        bytes.extend_from_slice(&self.prepared_update);
        bytes
    }
}

/// Immutable marker written only after the normal commit and checkpoint-tree
/// backup are durable.  It still grants no rollback delete capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorCommitSourceCommitted {
    slot: CoordinatorCommitSourceSlot,
    source_digest: CoordinatorCommitSourceDigest,
    marker_digest: [u8; 32],
}

impl CoordinatorCommitSourceCommitted {
    fn from_source<Hash: Q256BitHash>(source: &CoordinatorCommitSource<Hash>) -> Self {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&source.slot.0);
        bytes.extend_from_slice(&source.digest.0);
        Self {
            slot: source.slot,
            source_digest: source.digest,
            marker_digest: digest_bytes(MARKER_DOMAIN, &bytes),
        }
    }

    pub const fn slot(self) -> CoordinatorCommitSourceSlot { self.slot }
    pub const fn source_digest(self) -> CoordinatorCommitSourceDigest { self.source_digest }

    pub fn encode_canonical(self) -> [u8; 106] {
        let mut bytes = [0_u8; 106];
        bytes[..8].copy_from_slice(MARKER_MAGIC);
        bytes[8..10].copy_from_slice(&CODEC_VERSION.to_be_bytes());
        bytes[10..42].copy_from_slice(&self.slot.0);
        bytes[42..74].copy_from_slice(&self.source_digest.0);
        bytes[74..106].copy_from_slice(&self.marker_digest);
        bytes
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, CoordinatorCommitSourceError> {
        if bytes.len() != 106 {
            return Err(CoordinatorCommitSourceError::InvalidMarkerLength(bytes.len()));
        }
        if &bytes[..8] != MARKER_MAGIC {
            return Err(CoordinatorCommitSourceError::InvalidMarkerMagic);
        }
        let version = u16::from_be_bytes(bytes[8..10].try_into().expect("fixed length"));
        if version != CODEC_VERSION {
            return Err(CoordinatorCommitSourceError::UnknownMarkerVersion(version));
        }
        let marker = Self {
            slot: CoordinatorCommitSourceSlot(bytes[10..42].try_into().expect("fixed length")),
            source_digest: CoordinatorCommitSourceDigest(bytes[42..74].try_into().expect("fixed length")),
            marker_digest: bytes[74..106].try_into().expect("fixed length"),
        };
        let mut commitment = Vec::with_capacity(64);
        commitment.extend_from_slice(&marker.slot.0);
        commitment.extend_from_slice(&marker.source_digest.0);
        if digest_bytes(MARKER_DOMAIN, &commitment) != marker.marker_digest {
            return Err(CoordinatorCommitSourceError::MarkerDigestMismatch);
        }
        if marker.encode_canonical() != bytes {
            return Err(CoordinatorCommitSourceError::NonCanonicalMarker);
        }
        Ok(marker)
    }

    pub fn matches<Hash: Q256BitHash>(&self, source: &CoordinatorCommitSource<Hash>) -> bool {
        self.slot == source.slot && self.source_digest == source.digest
    }
}

fn validate_refs<Hash: Q256BitHash>(
    expected: &CanonicalChainRef<Hash>,
    candidate: &CanonicalChainRef<Hash>,
) -> Result<(), CoordinatorCommitSourceError> {
    if expected.network_id() != candidate.network_id()
        || expected.chain_epoch() != candidate.chain_epoch()
    {
        return Err(CoordinatorCommitSourceError::BranchMismatch);
    }
    let expected_checkpoint = expected.checkpoint().checkpoint_id().get();
    let next = expected_checkpoint
        .checked_add(1)
        .ok_or(CoordinatorCommitSourceError::CheckpointOverflow(expected_checkpoint))?;
    if candidate.checkpoint().checkpoint_id().get() != next {
        return Err(CoordinatorCommitSourceError::NonSequentialCheckpoint {
            expected: next,
            actual: candidate.checkpoint().checkpoint_id().get(),
        });
    }
    Ok(())
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Cursor<'a> { bytes: &'a [u8], offset: usize }

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorCommitSourceError> {
        let end = self.offset.checked_add(len).ok_or(CoordinatorCommitSourceError::Truncated)?;
        if end > self.bytes.len() { return Err(CoordinatorCommitSourceError::Truncated); }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn u16(&mut self) -> Result<u16, CoordinatorCommitSourceError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed length")))
    }
    fn u32(&mut self) -> Result<u32, CoordinatorCommitSourceError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed length")))
    }
    fn u64(&mut self) -> Result<u64, CoordinatorCommitSourceError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed length")))
    }
    fn is_empty(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CoordinatorCommitSourceError {
    CanonicalHead(String),
    CanonicalRef(String),
    CandidateMismatch,
    BranchMismatch,
    CheckpointOverflow(u64),
    NonSequentialCheckpoint { expected: u64, actual: u64 },
    UnknownPreparedUpdateCodec(u16),
    RevisionOutOfCqlRange(u64),
    EmptyPreparedUpdate,
    EmptyNormalCheckpointProof,
    PreparedUpdateTooLarge { actual: usize, maximum: usize },
    InvalidHeaderMagic,
    UnknownHeaderVersion(u16),
    Truncated,
    TrailingHeaderBytes,
    InvalidPersistedSourceLength(usize),
    InvalidPersistedSourceLengthU64(u64),
    FragmentSizeMismatch { actual: usize },
    FragmentCountMismatch { expected: usize, actual: usize },
    FragmentLengthMismatch { index: usize, expected: usize, actual: usize },
    SourceDigestMismatch,
    SlotMismatch,
    ObjectDigestMismatch,
    InvalidMarkerLength(usize),
    InvalidMarkerMagic,
    UnknownMarkerVersion(u16),
    MarkerDigestMismatch,
    NonCanonicalMarker,
    InvalidPayloadMagic,
    UnknownPayloadVersion(u16),
    TrailingPayloadBytes,
    NonCanonicalPayload,
    RollbackFloorRequiresIdleHead,
    InvalidRollbackFloorRowRevision(i64),
    InvalidRollbackFloorMagic,
    UnknownRollbackFloorVersion(u16),
    TrailingRollbackFloorBytes,
    RollbackFloorContractMismatch,
    RollbackFloorPartitionMismatch,
    RollbackFloorDigestMismatch,
    NonCanonicalRollbackFloor,
    RollbackFloorBranchMismatch,
    RollbackFloorAboveCurrentHead { floor: u64, current: u64 },
    CheckpointBackupIdOverflow,
    CheckpointBackupIdentityMismatch,
}

impl fmt::Display for CoordinatorCommitSourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid Coordinator commit source: {self:?}")
    }
}

impl Error for CoordinatorCommitSourceError {}

impl From<CanonicalHeadModelError> for CoordinatorCommitSourceError {
    fn from(value: CanonicalHeadModelError) -> Self { Self::CanonicalHead(value.to_string()) }
}

impl From<CanonicalChainRefCodecError> for CoordinatorCommitSourceError {
    fn from(value: CanonicalChainRefCodecError) -> Self { Self::CanonicalRef(value.to_string()) }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId,
    };

    use super::*;
    use crate::store::{
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
        rollback_control::{RollbackExecutionMode, RollbackPlanDigest, RollbackRequest},
        timestamp::{CommitWriteTimestampUs, TimestampFenceWindow},
    };

    fn canonical(epoch: u64, checkpoint: u64, byte: u8) -> CanonicalChainRef<PHash> {
        CanonicalChainRef::new(
            NetworkId::try_from_chain_id(1337).unwrap(),
            ChainEpoch::new(epoch),
            CheckpointRef::new(
                CheckpointId::new(checkpoint),
                CheckpointHash::from_last_chain_hash(PHash::from_owned_32bytes([byte; 32])),
            ),
        )
    }

    fn head() -> StoredCanonicalHead<PHash> {
        let bootstrap = CanonicalHeadBootstrap::try_new(
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            canonical(0, 7, 7),
        ).unwrap();
        *bootstrap.candidate()
    }

    #[derive(Default)]
    struct MemoryFloorStore {
        floor: Mutex<Option<CoordinatorRollbackFloor<PHash>>>,
    }

    #[async_trait]
    impl CoordinatorCommitSourceStore<PHash> for MemoryFloorStore {
        async fn persist_coordinator_rollback_floor(
            &self,
            floor: &CoordinatorRollbackFloor<PHash>,
        ) -> anyhow::Result<()> {
            let mut current = self.floor.lock().unwrap();
            match *current {
                None => {
                    *current = Some(*floor);
                    Ok(())
                }
                Some(existing) if existing == *floor => Ok(()),
                Some(_) => anyhow::bail!("different floor"),
            }
        }

        async fn read_coordinator_rollback_floor(
            &self,
            network: psy_data::protocol::canonical_chain::NetworkId,
            chain_epoch: u64,
        ) -> anyhow::Result<Option<CoordinatorRollbackFloor<PHash>>> {
            Ok(self
                .floor
                .lock()
                .unwrap()
                .as_ref()
                .copied()
                .filter(|floor| {
                    floor.floor().network_id() == network
                        && floor.floor().chain_epoch().get() == chain_epoch
                }))
        }

        async fn ensure_coordinator_rollback_floor_singleton_anchor(
            &self,
            _current: &StoredCanonicalHead<PHash>,
            _floor: &CoordinatorRollbackFloor<PHash>,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn persist_coordinator_commit_source(
            &self,
            _source: &CoordinatorCommitSource<PHash>,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn read_coordinator_commit_source(
            &self,
            _candidate: &CanonicalChainRef<PHash>,
        ) -> anyhow::Result<Option<CoordinatorCommitSource<PHash>>> {
            unreachable!()
        }

        async fn mark_coordinator_commit_source_committed(
            &self,
            _source: &CoordinatorCommitSource<PHash>,
        ) -> anyhow::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn source_fragments_roundtrip_and_marker_binds_exact_object() {
        let payload = vec![9; COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES + 17];
        let source = CoordinatorCommitSource::try_new(head(), canonical(0, 8, 8), payload).unwrap();
        assert_eq!(source.fragment_count(), 2);
        let decoded = CoordinatorCommitSource::decode_persisted(
            &source.encode_header(),
            source.fragments().map(<[u8]>::to_vec).collect(),
        ).unwrap();
        assert_eq!(decoded, source);
        let marker = source.committed_marker();
        let decoded_marker = CoordinatorCommitSourceCommitted::decode_canonical(
            &marker.encode_canonical(),
        ).unwrap();
        assert!(decoded_marker.matches(&source));
    }

    #[test]
    fn persisted_source_rejects_missing_extra_or_tampered_fragments() {
        let source = CoordinatorCommitSource::try_new(
            head(),
            canonical(0, 8, 8),
            vec![3; COORDINATOR_COMMIT_SOURCE_FRAGMENT_BYTES + 1],
        ).unwrap();
        let header = source.encode_header();
        let mut fragments: Vec<Vec<u8>> = source.fragments().map(<[u8]>::to_vec).collect();
        assert!(CoordinatorCommitSource::<PHash>::decode_persisted(
            &header,
            fragments[..1].to_vec(),
        ).is_err());
        fragments.push(vec![]);
        assert!(CoordinatorCommitSource::<PHash>::decode_persisted(&header, fragments).is_err());
        let mut fragments: Vec<Vec<u8>> = source.fragments().map(<[u8]>::to_vec).collect();
        fragments[1][0] ^= 1;
        assert!(matches!(
            CoordinatorCommitSource::<PHash>::decode_persisted(&header, fragments),
            Err(CoordinatorCommitSourceError::SourceDigestMismatch)
        ));
    }

    #[test]
    fn source_rejects_wrong_branch_sequence_and_active_rollback() {
        assert!(CoordinatorCommitSource::try_new(head(), canonical(1, 8, 8), vec![1]).is_err());
        assert!(CoordinatorCommitSource::try_new(head(), canonical(0, 9, 9), vec![1]).is_err());

        let request = RollbackRequest::try_new(
            *head().canonical_ref().checkpoint(),
            *canonical(0, 5, 5).checkpoint(),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(10).unwrap(),
                11,
                12,
            ).unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([7; 32]).unwrap(),
        ).unwrap();
        let rollback_head = CanonicalHeadTransition::start_rollback(head(), request)
            .unwrap()
            .seal()
            .candidate()
            .to_owned();
        assert!(CoordinatorCommitSource::try_new(rollback_head, canonical(1, 8, 8), vec![1]).is_err());
    }

    #[test]
    fn checkpoint_backup_evidence_binds_exact_source_and_window() {
        let source = CoordinatorCommitSource::try_new(
            head(),
            canonical(0, 8, 8),
            vec![1, 2, 3],
        )
        .unwrap();
        let old_root = PHash::from_owned_32bytes([0x31; 32]);
        let new_root = PHash::from_owned_32bytes([0x32; 32]);
        let checkpoint_hash = PHash::from_owned_32bytes([0x33; 32]);
        let evidence = CoordinatorCheckpointBackupEvidence::try_from_exact_source(
            &source,
            8,
            checkpoint_hash,
            old_root,
            new_root,
            2,
            9,
        )
        .unwrap();
        assert_eq!(evidence.source_slot(), &source.slot().as_bytes());
        assert_eq!(evidence.source_digest(), &source.digest().as_bytes());
        assert_eq!(evidence.candidate(), source.candidate());
        assert_eq!(evidence.checkpoint_id(), 8);
        assert_eq!(evidence.checkpoint_hash(), &checkpoint_hash);
        assert_eq!(evidence.old_root(), &old_root);
        assert_eq!(evidence.new_root(), &new_root);
        assert_eq!(evidence.min_backed_up_checkpoint_id(), 2);
        assert_eq!(evidence.next_backup_checkpoint_id(), 9);
        assert_ne!(evidence.digest(), &[0; 32]);

        assert!(CoordinatorCheckpointBackupEvidence::try_from_exact_source(
            &source,
            7,
            checkpoint_hash,
            old_root,
            new_root,
            2,
            8,
        )
        .is_err());
        assert!(CoordinatorCheckpointBackupEvidence::try_from_exact_source(
            &source,
            8,
            checkpoint_hash,
            old_root,
            new_root,
            9,
            9,
        )
        .is_err());
    }

    #[test]
    fn marker_rejects_forged_outer_digest() {
        let source = CoordinatorCommitSource::try_new(head(), canonical(0, 8, 8), vec![1, 2, 3]).unwrap();
        let mut marker = source.committed_marker().encode_canonical();
        marker[40] ^= 1;
        assert!(matches!(
            CoordinatorCommitSourceCommitted::decode_canonical(&marker),
            Err(CoordinatorCommitSourceError::MarkerDigestMismatch)
        ));
    }

    #[test]
    fn normal_commit_payload_binds_prepared_update_circuit_and_proof() {
        let payload = CoordinatorCommitSourcePayload::try_new(
            vec![1, 2, 3],
            17,
            vec![4, 5, 6, 7],
        )
        .unwrap();
        let bytes = payload.encode_canonical();
        assert_eq!(
            CoordinatorCommitSourcePayload::decode_canonical(&bytes).unwrap(),
            payload
        );
        let mut forged = bytes.clone();
        forged.push(0);
        assert!(matches!(
            CoordinatorCommitSourcePayload::decode_canonical(&forged),
            Err(CoordinatorCommitSourceError::TrailingPayloadBytes)
        ));
        assert!(CoordinatorCommitSourcePayload::try_new(
            vec![1],
            17,
            Vec::new(),
        )
        .is_err());
    }

    #[test]
    fn rollback_floor_roundtrips_and_is_a_conservative_epoch_bound() {
        let floor = CoordinatorRollbackFloor::try_new(head()).unwrap();
        let bytes = floor.encode_canonical();
        let decoded = CoordinatorRollbackFloor::decode_persisted(
            floor.floor().network_id(),
            floor.floor().chain_epoch().get(),
            FLOOR_ROW_REVISION,
            &bytes,
        )
        .unwrap();
        assert_eq!(decoded, floor);
        decoded.validate_current_head(&head()).unwrap();
        let later = CanonicalHeadTransition::normal_checkpoint_advance(
            head(),
            canonical(0, 8, 8),
        )
        .unwrap()
        .seal()
        .candidate()
        .to_owned();
        decoded.validate_current_head(&later).unwrap();

        let mut forged = bytes;
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            CoordinatorRollbackFloor::<PHash>::decode_persisted(
                floor.floor().network_id(),
                floor.floor().chain_epoch().get(),
                FLOOR_ROW_REVISION,
                &forged,
            ),
            Err(CoordinatorCommitSourceError::RollbackFloorDigestMismatch)
        ));
    }

    #[test]
    fn rollback_floor_rejects_active_rollback_and_foreign_partition() {
        let request = RollbackRequest::try_new(
            *head().canonical_ref().checkpoint(),
            *canonical(0, 5, 5).checkpoint(),
            TimestampFenceWindow::try_new(
                CommitWriteTimestampUs::try_from_i128(10).unwrap(),
                11,
                12,
            )
            .unwrap(),
            RollbackExecutionMode::InPlace,
            RollbackPlanDigest::try_new([7; 32]).unwrap(),
        )
        .unwrap();
        let active = CanonicalHeadTransition::start_rollback(head(), request)
            .unwrap()
            .seal()
            .candidate()
            .to_owned();
        assert!(matches!(
            CoordinatorRollbackFloor::try_new(active),
            Err(CoordinatorCommitSourceError::RollbackFloorRequiresIdleHead)
        ));

        let floor = CoordinatorRollbackFloor::try_new(head()).unwrap();
        assert!(matches!(
            CoordinatorRollbackFloor::<PHash>::decode_persisted(
                canonical(1, 7, 7).network_id(),
                1,
                FLOOR_ROW_REVISION,
                &floor.encode_canonical(),
            ),
            Err(CoordinatorCommitSourceError::RollbackFloorPartitionMismatch)
        ));
    }

    #[tokio::test]
    async fn ensure_floor_keeps_the_first_idle_head_as_the_epoch_bound() {
        let store = MemoryFloorStore::default();
        let first = store.ensure_coordinator_rollback_floor(&head()).await.unwrap();
        let later = CanonicalHeadTransition::normal_checkpoint_advance(
            head(),
            canonical(0, 8, 8),
        )
        .unwrap()
        .seal()
        .candidate()
        .to_owned();
        let reread = store
            .ensure_coordinator_rollback_floor(&later)
            .await
            .unwrap();
        assert_eq!(reread, first);
        assert_eq!(reread.floor().checkpoint().checkpoint_id().get(), 7);
    }
}
