//! Canonical immutable manifest for one fully verified Coordinator write.
//!
//! The model is intentionally separate from the non-Clone execution
//! observation. It can be persisted and decoded after a crash, but it grants
//! no source-commit or canonical-head mutation authority until a storage owner
//! re-reads the 23-domain sources and proves the same manifest again.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::canonical_chain::{
    CANONICAL_CHAIN_REF_V1_LEN, CanonicalChainRef,
};
use psy_node_core::store::{
    branch_exact_dual_write::BranchExactDualWriteMutationKind,
    coordinator_normal_commit_coverage::CoordinatorNormalCommitWriteDomain,
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    TimestampedWriteKind,
    coordinator_commit_full_write::CoordinatorCommitFullWriteObservation,
};

const MAGIC: [u8; 8] = *b"PSYCFWMF";
const CODEC_VERSION: u16 = 1;
const REVISION: u64 = 1;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.coordinator-full-write-manifest-slot.v1\0";
const DIGEST_DOMAIN: &[u8] = b"psy.rollback.coordinator-full-write-manifest.v1\0";
const MAX_PAYLOAD_BYTES: usize = 768;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct CoordinatorCommitFullManifestSlot([u8; 32]);

impl CoordinatorCommitFullManifestSlot {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CoordinatorCommitFullManifest<Hash> {
    slot: CoordinatorCommitFullManifestSlot,
    revision: u64,
    candidate: CanonicalChainRef<Hash>,
    source_slot: [u8; 32],
    source_digest: [u8; 32],
    plan_digest: [u8; 32],
    inventory_digest: [u8; 32],
    timestamp: CommitWriteTimestampUs,
    write_kind: TimestampedWriteKind,
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    narrow_observation_digest: [u8; 32],
    narrow_verified_digest: [u8; 32],
    typed_observation_digest: [u8; 32],
    semantic_domain_count: u32,
    typed_row_count: u32,
    total_physical_row_count: u32,
    full_observation_digest: [u8; 32],
    canonical_payload: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> CoordinatorCommitFullManifest<Hash> {
    pub(crate) fn try_from_exact_observation(
        observation: &CoordinatorCommitFullWriteObservation<Hash>,
    ) -> Result<Self, CoordinatorCommitFullManifestError> {
        let semantic_domain_count = u32::try_from(observation.semantic_domain_count())
            .map_err(|_| CoordinatorCommitFullManifestError::CountOutOfRange)?;
        let typed_row_count = u32::try_from(observation.typed_row_count())
            .map_err(|_| CoordinatorCommitFullManifestError::CountOutOfRange)?;
        let total_physical_row_count =
            u32::try_from(observation.total_physical_row_count())
                .map_err(|_| CoordinatorCommitFullManifestError::CountOutOfRange)?;
        validate_counts(
            semantic_domain_count,
            typed_row_count,
            total_physical_row_count,
        )?;
        let slot = manifest_slot(*observation.source_slot(), observation.candidate());
        let mut manifest = Self {
            slot,
            revision: REVISION,
            candidate: *observation.candidate(),
            source_slot: *observation.source_slot(),
            source_digest: *observation.source_digest(),
            plan_digest: *observation.plan_digest(),
            inventory_digest: *observation.inventory_digest(),
            timestamp: observation.timestamp(),
            write_kind: observation.write_kind(),
            narrow_prepared_digest: *observation.narrow_prepared_digest(),
            narrow_intent_digest: *observation.narrow_intent_digest(),
            narrow_observation_digest: *observation.narrow_observation_digest(),
            narrow_verified_digest: *observation.narrow_verified_digest(),
            typed_observation_digest: *observation.typed_observation_digest(),
            semantic_domain_count,
            typed_row_count,
            total_physical_row_count,
            full_observation_digest: *observation.digest(),
            canonical_payload: Vec::new(),
            digest: [0; 32],
        };
        manifest.canonical_payload = encode_manifest(&manifest);
        manifest.digest = manifest.canonical_payload
            [manifest.canonical_payload.len() - 32..]
            .try_into()
            .expect("manifest codec appends digest");
        Ok(manifest)
    }

    #[cfg(test)]
    pub(super) fn test_fixture(
        candidate: CanonicalChainRef<Hash>,
        source_slot: [u8; 32],
        source_digest: [u8; 32],
    ) -> Self {
        let typed_row_count = 19_u32;
        let total_physical_row_count = typed_row_count
            + u32::try_from(BranchExactDualWriteMutationKind::COORDINATOR.len())
                .expect("test narrow count");
        let mut manifest = Self {
            slot: manifest_slot(source_slot, &candidate),
            revision: REVISION,
            candidate,
            source_slot,
            source_digest,
            plan_digest: [0x41; 32],
            inventory_digest: [0x42; 32],
            timestamp: CommitWriteTimestampUs::try_from_i128(17).unwrap(),
            write_kind: TimestampedWriteKind::AuthorityCommit,
            narrow_prepared_digest: [0x43; 32],
            narrow_intent_digest: [0x44; 32],
            narrow_observation_digest: [0x45; 32],
            narrow_verified_digest: [0x46; 32],
            typed_observation_digest: [0x47; 32],
            semantic_domain_count: u32::try_from(
                CoordinatorNormalCommitWriteDomain::ALL.len(),
            )
            .expect("test domain count"),
            typed_row_count,
            total_physical_row_count,
            full_observation_digest: [0x48; 32],
            canonical_payload: Vec::new(),
            digest: [0; 32],
        };
        manifest.canonical_payload = encode_manifest(&manifest);
        manifest.digest = manifest.canonical_payload
            [manifest.canonical_payload.len() - 32..]
            .try_into()
            .expect("manifest codec appends digest");
        manifest
    }

    pub(crate) fn decode_persisted(
        selected_slot: &[u8],
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, CoordinatorCommitFullManifestError> {
        if payload.len() > MAX_PAYLOAD_BYTES {
            return Err(CoordinatorCommitFullManifestError::PayloadTooLarge {
                actual: payload.len(),
            });
        }
        if revision != REVISION as i64 {
            return Err(CoordinatorCommitFullManifestError::RevisionMismatch);
        }
        let body_len = payload
            .len()
            .checked_sub(32)
            .ok_or(CoordinatorCommitFullManifestError::TruncatedPayload)?;
        let (body, encoded_digest) = payload.split_at(body_len);
        let digest = digest_bytes(DIGEST_DOMAIN, body);
        if encoded_digest != digest {
            return Err(CoordinatorCommitFullManifestError::DigestMismatch);
        }
        let mut decoder = Decoder::new(body);
        if decoder.take(8)? != MAGIC {
            return Err(CoordinatorCommitFullManifestError::InvalidMagic);
        }
        if decoder.u16()? != CODEC_VERSION {
            return Err(CoordinatorCommitFullManifestError::UnknownCodecVersion);
        }
        if decoder.u64()? != REVISION {
            return Err(CoordinatorCommitFullManifestError::RevisionMismatch);
        }
        let candidate = CanonicalChainRef::from_canonical_bytes(
            decoder.take(CANONICAL_CHAIN_REF_V1_LEN)?,
        )
        .map_err(|_| CoordinatorCommitFullManifestError::InvalidCandidate)?;
        let source_slot = decoder.array32()?;
        let source_digest = decoder.nonzero_digest()?;
        let plan_digest = decoder.nonzero_digest()?;
        let inventory_digest = decoder.nonzero_digest()?;
        let timestamp = CommitWriteTimestampUs::try_from_i128(i128::from(decoder.i64()?))
            .map_err(|_| CoordinatorCommitFullManifestError::InvalidTimestamp)?;
        let write_kind = match decoder.u8()? {
            1 => TimestampedWriteKind::AuthorityCommit,
            2 => TimestampedWriteKind::NewBranchAfterFence,
            _ => return Err(CoordinatorCommitFullManifestError::UnknownWriteKind),
        };
        let narrow_prepared_digest = decoder.nonzero_digest()?;
        let narrow_intent_digest = decoder.nonzero_digest()?;
        let narrow_observation_digest = decoder.nonzero_digest()?;
        let narrow_verified_digest = decoder.nonzero_digest()?;
        let typed_observation_digest = decoder.nonzero_digest()?;
        let semantic_domain_count = decoder.u32()?;
        let typed_row_count = decoder.u32()?;
        let total_physical_row_count = decoder.u32()?;
        let full_observation_digest = decoder.nonzero_digest()?;
        let slot = CoordinatorCommitFullManifestSlot(decoder.array32()?);
        if !decoder.is_done() {
            return Err(CoordinatorCommitFullManifestError::TrailingBytes);
        }
        validate_counts(
            semantic_domain_count,
            typed_row_count,
            total_physical_row_count,
        )?;
        if slot != manifest_slot(source_slot, &candidate)
            || selected_slot != slot.as_bytes()
        {
            return Err(CoordinatorCommitFullManifestError::IdentityMismatch);
        }
        Ok(Self {
            slot,
            revision: REVISION,
            candidate,
            source_slot,
            source_digest,
            plan_digest,
            inventory_digest,
            timestamp,
            write_kind,
            narrow_prepared_digest,
            narrow_intent_digest,
            narrow_observation_digest,
            narrow_verified_digest,
            typed_observation_digest,
            semantic_domain_count,
            typed_row_count,
            total_physical_row_count,
            full_observation_digest,
            canonical_payload: payload.to_vec(),
            digest,
        })
    }

    pub(crate) fn revalidate_exact_observation(
        &self,
        observation: &CoordinatorCommitFullWriteObservation<Hash>,
    ) -> Result<(), CoordinatorCommitFullManifestError> {
        let expected = Self::try_from_exact_observation(observation)?;
        if &expected != self {
            return Err(CoordinatorCommitFullManifestError::SourceChanged);
        }
        Ok(())
    }

    pub(crate) const fn slot(&self) -> CoordinatorCommitFullManifestSlot {
        self.slot
    }

    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn candidate(&self) -> &CanonicalChainRef<Hash> {
        &self.candidate
    }

    pub(crate) const fn source_slot(&self) -> &[u8; 32] {
        &self.source_slot
    }

    pub(crate) const fn source_digest(&self) -> &[u8; 32] {
        &self.source_digest
    }

    pub(crate) const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub(crate) const fn inventory_digest(&self) -> &[u8; 32] {
        &self.inventory_digest
    }

    pub(crate) const fn timestamp(&self) -> CommitWriteTimestampUs {
        self.timestamp
    }

    pub(crate) const fn write_kind(&self) -> TimestampedWriteKind {
        self.write_kind
    }

    pub(crate) const fn full_observation_digest(&self) -> &[u8; 32] {
        &self.full_observation_digest
    }

    pub(crate) const fn semantic_domain_count(&self) -> u32 {
        self.semantic_domain_count
    }

    pub(crate) const fn typed_row_count(&self) -> u32 {
        self.typed_row_count
    }

    pub(crate) const fn total_physical_row_count(&self) -> u32 {
        self.total_physical_row_count
    }

    pub(crate) const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub(crate) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

pub(crate) fn coordinator_commit_full_manifest_slot<Hash: Q256BitHash>(
    source_slot: [u8; 32],
    candidate: &CanonicalChainRef<Hash>,
) -> CoordinatorCommitFullManifestSlot {
    manifest_slot(source_slot, candidate)
}

fn manifest_slot<Hash: Q256BitHash>(
    source_slot: [u8; 32],
    candidate: &CanonicalChainRef<Hash>,
) -> CoordinatorCommitFullManifestSlot {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(source_slot);
    hasher.update(candidate.to_canonical_bytes());
    CoordinatorCommitFullManifestSlot(hasher.finalize().into())
}

fn validate_counts(
    semantic_domain_count: u32,
    typed_row_count: u32,
    total_physical_row_count: u32,
) -> Result<(), CoordinatorCommitFullManifestError> {
    let expected_domains = u32::try_from(CoordinatorNormalCommitWriteDomain::ALL.len())
        .expect("Coordinator domain count fits u32");
    let narrow_count = u32::try_from(BranchExactDualWriteMutationKind::COORDINATOR.len())
        .expect("Coordinator narrow count fits u32");
    if semantic_domain_count != expected_domains {
        return Err(CoordinatorCommitFullManifestError::SemanticDomainCountMismatch);
    }
    if typed_row_count == 0
        || typed_row_count.checked_add(narrow_count) != Some(total_physical_row_count)
    {
        return Err(CoordinatorCommitFullManifestError::PhysicalRowCountMismatch);
    }
    Ok(())
}

fn encode_manifest<Hash: Q256BitHash>(
    manifest: &CoordinatorCommitFullManifest<Hash>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(512);
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    bytes.extend_from_slice(&manifest.revision.to_be_bytes());
    bytes.extend_from_slice(&manifest.candidate.to_canonical_bytes());
    bytes.extend_from_slice(&manifest.source_slot);
    bytes.extend_from_slice(&manifest.source_digest);
    bytes.extend_from_slice(&manifest.plan_digest);
    bytes.extend_from_slice(&manifest.inventory_digest);
    bytes.extend_from_slice(&manifest.timestamp.as_i64().to_be_bytes());
    bytes.push(manifest.write_kind as u8);
    bytes.extend_from_slice(&manifest.narrow_prepared_digest);
    bytes.extend_from_slice(&manifest.narrow_intent_digest);
    bytes.extend_from_slice(&manifest.narrow_observation_digest);
    bytes.extend_from_slice(&manifest.narrow_verified_digest);
    bytes.extend_from_slice(&manifest.typed_observation_digest);
    bytes.extend_from_slice(&manifest.semantic_domain_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.typed_row_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.total_physical_row_count.to_be_bytes());
    bytes.extend_from_slice(&manifest.full_observation_digest);
    bytes.extend_from_slice(manifest.slot.as_bytes());
    let digest = digest_bytes(DIGEST_DOMAIN, &bytes);
    bytes.extend_from_slice(&digest);
    bytes
}

fn digest_bytes(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
    hasher.finalize().into()
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CoordinatorCommitFullManifestError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(CoordinatorCommitFullManifestError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(CoordinatorCommitFullManifestError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, CoordinatorCommitFullManifestError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, CoordinatorCommitFullManifestError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("u16")))
    }

    fn u32(&mut self) -> Result<u32, CoordinatorCommitFullManifestError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("u32")))
    }

    fn u64(&mut self) -> Result<u64, CoordinatorCommitFullManifestError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("u64")))
    }

    fn i64(&mut self) -> Result<i64, CoordinatorCommitFullManifestError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("i64")))
    }

    fn array32(&mut self) -> Result<[u8; 32], CoordinatorCommitFullManifestError> {
        Ok(self.take(32)?.try_into().expect("array32"))
    }

    fn nonzero_digest(&mut self) -> Result<[u8; 32], CoordinatorCommitFullManifestError> {
        let value = self.array32()?;
        if value == [0; 32] {
            return Err(CoordinatorCommitFullManifestError::ZeroDigest);
        }
        Ok(value)
    }

    fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum CoordinatorCommitFullManifestError {
    CountOutOfRange,
    PayloadTooLarge { actual: usize },
    TruncatedPayload,
    InvalidMagic,
    UnknownCodecVersion,
    RevisionMismatch,
    DigestMismatch,
    InvalidCandidate,
    InvalidTimestamp,
    UnknownWriteKind,
    ZeroDigest,
    SemanticDomainCountMismatch,
    PhysicalRowCountMismatch,
    IdentityMismatch,
    TrailingBytes,
    SourceChanged,
}

impl fmt::Display for CoordinatorCommitFullManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Coordinator full-write manifest: {self:?}")
    }
}

impl Error for CoordinatorCommitFullManifestError {}
