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

/// Durable normal-commit source boundary. The canonical-head writer depends
/// on this capability so neither the live commit path nor startup recovery can
/// publish a normal candidate without first making its source and COMMITTED
/// marker exact. Implementations must be append-only and fail closed on a
/// same-identity/different-content observation.
#[async_trait]
pub trait CoordinatorCommitSourceStore<Hash: Q256BitHash>: Send + Sync {
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
}
