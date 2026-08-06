//! Canonical D-03 locator/replay artifact bundle.
//!
//! This module is driver-independent. It converts the exact typed physical
//! mutation batch into content-verified chunks and one artifact-set
//! commitment suitable for a sealed authority commit intent. Persistence and
//! PREPARED/SEALED/COMMITTED transitions are intentionally separate work.

use std::{error::Error, fmt};

use psy_node_core::store::manifest_intent::{
    ManifestArtifactSetCommitment, ManifestIntentError,
};
use sha2::{Digest, Sha256};

use super::{
    CanonicalPhysicalMutationBatch, FullPhysicalDeltaRecord,
    PreparedReferencePlusSupplementRecord, ReplayPrototypeError,
    ReplayRecordKind,
};

pub const MANIFEST_ARTIFACT_ENCODING_VERSION: u16 = 1;
pub const MANIFEST_ARTIFACT_MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;
pub const MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET: u32 = 16;

const LOCATOR_MAGIC: &[u8; 4] = b"PSLA";
const ARTIFACT_SET_MAGIC: &[u8; 4] = b"PSAS";
const ZERO_MUTATION_RECEIPT_MAGIC: &[u8; 4] = b"PSZR";
const ARTIFACT_DIGEST_DOMAIN: &[u8] = b"psy.rollback.manifest-artifact.v1\0";
const CHUNK_DIGEST_DOMAIN: &[u8] = b"psy.rollback.manifest-chunk.v1\0";
const CHUNK_SET_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.manifest-chunk-set.v1\0";

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum ManifestArtifactKind {
    Locator = 1,
    ReplayRecord = 2,
    DurablePreparedPayload = 3,
}

impl TryFrom<u8> for ManifestArtifactKind {
    type Error = ManifestArtifactError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Locator),
            2 => Ok(Self::ReplayRecord),
            3 => Ok(Self::DurablePreparedPayload),
            value => Err(ManifestArtifactError::UnknownArtifactKind(value)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ManifestArtifactDigest([u8; 32]);

impl ManifestArtifactDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn calculate(
        domain: &[u8],
        kind: ManifestArtifactKind,
        parts: &[&[u8]],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(domain);
        hasher.update([kind as u8]);
        for part in parts {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part);
        }
        Self(hasher.finalize().into())
    }

    fn from_persisted(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManifestArtifactChunk {
    kind: ManifestArtifactKind,
    encoding_version: u16,
    chunk_index: u32,
    total_chunks: u32,
    chunk_bucket: u32,
    payload: Vec<u8>,
    payload_hash: ManifestArtifactDigest,
}

impl ManifestArtifactChunk {
    pub fn try_from_persisted(
        kind: u8,
        encoding_version: u16,
        chunk_index: u32,
        total_chunks: u32,
        chunk_bucket: u32,
        payload: Vec<u8>,
        payload_hash: [u8; 32],
    ) -> Result<Self, ManifestArtifactError> {
        let kind = ManifestArtifactKind::try_from(kind)?;
        if encoding_version != MANIFEST_ARTIFACT_ENCODING_VERSION {
            return Err(ManifestArtifactError::UnknownEncodingVersion(
                encoding_version,
            ));
        }
        if total_chunks == 0 || chunk_index >= total_chunks {
            return Err(ManifestArtifactError::InvalidChunkPosition {
                chunk_index,
                total_chunks,
            });
        }
        let expected_bucket = chunk_index / MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET;
        if chunk_bucket != expected_bucket {
            return Err(ManifestArtifactError::ChunkBucketMismatch {
                chunk_index,
                expected: expected_bucket,
                actual: chunk_bucket,
            });
        }
        if payload.is_empty() {
            return Err(ManifestArtifactError::EmptyPersistedChunkPayload(
                chunk_index,
            ));
        }
        if payload.len() > MANIFEST_ARTIFACT_MAX_CHUNK_BYTES {
            return Err(ManifestArtifactError::ChunkPayloadTooLarge {
                chunk_index,
                actual: payload.len(),
                maximum: MANIFEST_ARTIFACT_MAX_CHUNK_BYTES,
            });
        }
        Ok(Self {
            kind,
            encoding_version,
            chunk_index,
            total_chunks,
            chunk_bucket,
            payload,
            payload_hash: ManifestArtifactDigest::from_persisted(payload_hash),
        })
    }

    pub const fn kind(&self) -> ManifestArtifactKind {
        self.kind
    }

    pub const fn encoding_version(&self) -> u16 {
        self.encoding_version
    }

    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    pub const fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub const fn chunk_bucket(&self) -> u32 {
        self.chunk_bucket
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub const fn payload_hash(&self) -> ManifestArtifactDigest {
        self.payload_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestArtifactDescriptor {
    kind: ManifestArtifactKind,
    encoding_version: u16,
    chunk_count: u32,
    item_count: u64,
    encoded_bytes: u64,
    payload_digest: ManifestArtifactDigest,
    chunk_set_digest: ManifestArtifactDigest,
}

impl ManifestArtifactDescriptor {
    pub const fn kind(self) -> ManifestArtifactKind {
        self.kind
    }

    pub const fn encoding_version(self) -> u16 {
        self.encoding_version
    }

    pub const fn chunk_count(self) -> u32 {
        self.chunk_count
    }

    pub const fn item_count(self) -> u64 {
        self.item_count
    }

    pub const fn encoded_bytes(self) -> u64 {
        self.encoded_bytes
    }

    pub const fn payload_digest(self) -> ManifestArtifactDigest {
        self.payload_digest
    }

    pub const fn chunk_set_digest(self) -> ManifestArtifactDigest {
        self.chunk_set_digest
    }

    fn encode_into(self, out: &mut Vec<u8>) {
        out.push(self.kind as u8);
        out.extend_from_slice(&self.encoding_version.to_be_bytes());
        out.extend_from_slice(&self.chunk_count.to_be_bytes());
        out.extend_from_slice(&self.item_count.to_be_bytes());
        out.extend_from_slice(&self.encoded_bytes.to_be_bytes());
        out.extend_from_slice(self.payload_digest.as_bytes());
        out.extend_from_slice(self.chunk_set_digest.as_bytes());
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalManifestArtifact {
    descriptor: ManifestArtifactDescriptor,
    chunks: Vec<ManifestArtifactChunk>,
}

impl CanonicalManifestArtifact {
    pub const fn descriptor(&self) -> ManifestArtifactDescriptor {
        self.descriptor
    }

    pub fn chunks(&self) -> &[ManifestArtifactChunk] {
        &self.chunks
    }

    pub fn verify_and_reassemble(&self) -> Result<Vec<u8>, ManifestArtifactError> {
        verify_artifact_chunks(self.descriptor, &self.chunks)
    }
}

/// Locator/replay artifacts generated from exactly one canonical physical
/// mutation batch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalManifestArtifactSet {
    replay_record_kind: ReplayRecordKind,
    mutation_digest: [u8; 32],
    locator: CanonicalManifestArtifact,
    replay_record: CanonicalManifestArtifact,
    durable_prepared_payload: Option<CanonicalManifestArtifact>,
    canonical_summary: Vec<u8>,
    commitment: ManifestArtifactSetCommitment,
}

/// Compact receipt for a checkpoint that has no rollbackable or derived
/// physical mutation. It deliberately owns no chunk, but still commits to the
/// typed replay receipt and empty physical mutation digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalZeroMutationReceipt {
    mutation_digest: [u8; 32],
    canonical_summary: Vec<u8>,
    commitment: ManifestArtifactSetCommitment,
}

impl CanonicalZeroMutationReceipt {
    pub fn try_from_full(
        record: &FullPhysicalDeltaRecord,
    ) -> Result<Self, ManifestArtifactError> {
        if !record.batch().mutations().is_empty() {
            return Err(ManifestArtifactError::NonZeroMutationReceipt {
                actual: record.batch().mutations().len(),
            });
        }
        let mutation_digest = *record.batch().digest().as_bytes();
        let replay_bytes = record.encode_canonical();
        let replay_len = u32::try_from(replay_bytes.len()).map_err(|_| {
            ManifestArtifactError::ZeroMutationReceiptTooLarge(
                replay_bytes.len(),
            )
        })?;
        let summary_capacity = 43usize.checked_add(replay_bytes.len()).ok_or(
            ManifestArtifactError::ZeroMutationReceiptTooLarge(
                replay_bytes.len(),
            ),
        )?;
        let mut canonical_summary = Vec::with_capacity(summary_capacity);
        canonical_summary.extend_from_slice(ZERO_MUTATION_RECEIPT_MAGIC);
        canonical_summary
            .extend_from_slice(&MANIFEST_ARTIFACT_ENCODING_VERSION.to_be_bytes());
        canonical_summary.push(ReplayRecordKind::FullPhysicalDelta as u8);
        canonical_summary.extend_from_slice(&mutation_digest);
        canonical_summary.extend_from_slice(&replay_len.to_be_bytes());
        canonical_summary.extend_from_slice(&replay_bytes);
        let commitment =
            ManifestArtifactSetCommitment::from_verified_artifact_summary(
                &canonical_summary,
                mutation_digest,
                0,
                0,
                0,
                0,
            )?;
        let receipt = Self {
            mutation_digest,
            canonical_summary,
            commitment,
        };
        receipt.verify_integrity()?;
        Ok(receipt)
    }

    pub const fn mutation_digest(&self) -> &[u8; 32] {
        &self.mutation_digest
    }

    pub fn canonical_summary(&self) -> &[u8] {
        &self.canonical_summary
    }

    pub const fn commitment(&self) -> ManifestArtifactSetCommitment {
        self.commitment
    }

    pub fn verify_integrity(&self) -> Result<(), ManifestArtifactError> {
        if self.canonical_summary.len() < 43
            || &self.canonical_summary[..4] != ZERO_MUTATION_RECEIPT_MAGIC
        {
            return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
        }
        let version = u16::from_be_bytes(
            self.canonical_summary[4..6].try_into().expect("fixed"),
        );
        if version != MANIFEST_ARTIFACT_ENCODING_VERSION {
            return Err(ManifestArtifactError::UnknownEncodingVersion(version));
        }
        if self.canonical_summary[6] != ReplayRecordKind::FullPhysicalDelta as u8 {
            return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
        }
        if self.canonical_summary[7..39] != self.mutation_digest {
            return Err(ManifestArtifactError::ArtifactSummaryMismatch);
        }
        let replay_len = u32::from_be_bytes(
            self.canonical_summary[39..43]
                .try_into()
                .expect("fixed"),
        ) as usize;
        let expected_len = 43usize.checked_add(replay_len).ok_or(
            ManifestArtifactError::ZeroMutationReceiptTooLarge(replay_len),
        )?;
        if self.canonical_summary.len() != expected_len {
            return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
        }
        validate_zero_mutation_replay_record(
            &self.canonical_summary[43..],
            self.mutation_digest,
        )?;
        self.commitment
            .verify_canonical_summary(&self.canonical_summary)?;
        if self.commitment.affected_row_count() != 0
            || self.commitment.locator_chunk_count() != 0
            || self.commitment.replay_chunk_count() != 0
            || self.commitment.durable_payload_chunk_count() != 0
        {
            return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
        }
        Ok(())
    }
}

/// Complete D-03 artifact outcome for one authority checkpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalManifestArtifacts {
    Chunked(CanonicalManifestArtifactSet),
    ZeroMutation(CanonicalZeroMutationReceipt),
}

impl CanonicalManifestArtifacts {
    pub fn try_from_full(
        record: &FullPhysicalDeltaRecord,
    ) -> Result<Self, ManifestArtifactError> {
        if record.batch().mutations().is_empty() {
            Ok(Self::ZeroMutation(
                CanonicalZeroMutationReceipt::try_from_full(record)?,
            ))
        } else {
            Ok(Self::Chunked(
                CanonicalManifestArtifactSet::try_from_full(record)?,
            ))
        }
    }

    pub fn try_from_compact(
        record: &PreparedReferencePlusSupplementRecord,
        durable_payload_bytes: &[u8],
    ) -> Result<Self, ManifestArtifactError> {
        Ok(Self::Chunked(
            CanonicalManifestArtifactSet::try_from_compact(
                record,
                durable_payload_bytes,
            )?,
        ))
    }

    pub const fn commitment(&self) -> ManifestArtifactSetCommitment {
        match self {
            Self::Chunked(set) => set.commitment(),
            Self::ZeroMutation(receipt) => receipt.commitment(),
        }
    }

    pub fn canonical_summary(&self) -> &[u8] {
        match self {
            Self::Chunked(set) => set.canonical_summary(),
            Self::ZeroMutation(receipt) => receipt.canonical_summary(),
        }
    }

    pub const fn chunked(&self) -> Option<&CanonicalManifestArtifactSet> {
        match self {
            Self::Chunked(set) => Some(set),
            Self::ZeroMutation(_) => None,
        }
    }

    pub const fn is_zero_mutation(&self) -> bool {
        matches!(self, Self::ZeroMutation(_))
    }

    pub fn verify_integrity(&self) -> Result<(), ManifestArtifactError> {
        match self {
            Self::Chunked(set) => set.verify_integrity(),
            Self::ZeroMutation(receipt) => receipt.verify_integrity(),
        }
    }
}

/// Strictly decoded durable artifact plan recovered from a PREPARED manifest
/// row. It contains enough information to address and verify every immutable
/// chunk after a process restart; no in-memory commit builder is required.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedManifestArtifactPlan {
    Chunked {
        replay_record_kind: ReplayRecordKind,
        mutation_digest: [u8; 32],
        locator: ManifestArtifactDescriptor,
        replay_record: ManifestArtifactDescriptor,
        durable_prepared_payload: Option<ManifestArtifactDescriptor>,
    },
    ZeroMutation {
        mutation_digest: [u8; 32],
        replay_record: Vec<u8>,
    },
}

impl DecodedManifestArtifactPlan {
    pub const fn mutation_digest(&self) -> &[u8; 32] {
        match self {
            Self::Chunked {
                mutation_digest, ..
            }
            | Self::ZeroMutation {
                mutation_digest, ..
            } => mutation_digest,
        }
    }

    pub const fn locator(&self) -> Option<ManifestArtifactDescriptor> {
        match self {
            Self::Chunked { locator, .. } => Some(*locator),
            Self::ZeroMutation { .. } => None,
        }
    }

    pub const fn replay_record(&self) -> Option<ManifestArtifactDescriptor> {
        match self {
            Self::Chunked { replay_record, .. } => Some(*replay_record),
            Self::ZeroMutation { .. } => None,
        }
    }

    pub const fn durable_prepared_payload(
        &self,
    ) -> Option<ManifestArtifactDescriptor> {
        match self {
            Self::Chunked {
                durable_prepared_payload,
                ..
            } => *durable_prepared_payload,
            Self::ZeroMutation { .. } => None,
        }
    }

    pub fn zero_mutation_replay_record(&self) -> Option<&[u8]> {
        match self {
            Self::ZeroMutation { replay_record, .. } => Some(replay_record),
            Self::Chunked { .. } => None,
        }
    }
}

pub fn decode_manifest_artifact_plan(
    canonical_summary: &[u8],
    commitment: ManifestArtifactSetCommitment,
) -> Result<DecodedManifestArtifactPlan, ManifestArtifactError> {
    commitment.verify_canonical_summary(canonical_summary)?;
    if canonical_summary.starts_with(ZERO_MUTATION_RECEIPT_MAGIC) {
        return decode_zero_mutation_plan(canonical_summary, commitment);
    }
    if !canonical_summary.starts_with(ARTIFACT_SET_MAGIC) {
        return Err(ManifestArtifactError::InvalidArtifactSummaryEncoding);
    }
    if canonical_summary.len() < 40 {
        return Err(ManifestArtifactError::InvalidArtifactSummaryEncoding);
    }
    let version = u16::from_be_bytes(
        canonical_summary[4..6].try_into().expect("fixed"),
    );
    if version != MANIFEST_ARTIFACT_ENCODING_VERSION {
        return Err(ManifestArtifactError::UnknownEncodingVersion(version));
    }
    let replay_record_kind = ReplayRecordKind::try_from(canonical_summary[6])?;
    let mutation_digest: [u8; 32] =
        canonical_summary[7..39].try_into().expect("fixed");
    let artifact_count = canonical_summary[39];
    if !matches!(artifact_count, 2 | 3) {
        return Err(ManifestArtifactError::InvalidArtifactSummaryEncoding);
    }
    let mut offset = 40usize;
    let locator = decode_artifact_descriptor(canonical_summary, &mut offset)?;
    let replay_record =
        decode_artifact_descriptor(canonical_summary, &mut offset)?;
    let durable_prepared_payload = if artifact_count == 3 {
        Some(decode_artifact_descriptor(canonical_summary, &mut offset)?)
    } else {
        None
    };
    if offset != canonical_summary.len()
        || locator.kind() != ManifestArtifactKind::Locator
        || replay_record.kind() != ManifestArtifactKind::ReplayRecord
        || durable_prepared_payload.is_some_and(|descriptor| {
            descriptor.kind() != ManifestArtifactKind::DurablePreparedPayload
        })
        || locator.item_count() != commitment.affected_row_count()
        || replay_record.item_count() != commitment.affected_row_count()
        || locator.chunk_count() != commitment.locator_chunk_count()
        || replay_record.chunk_count() != commitment.replay_chunk_count()
        || durable_prepared_payload.map_or(0, |descriptor| descriptor.chunk_count())
            != commitment.durable_payload_chunk_count()
        || mutation_digest != commitment.mutation_digest()
    {
        return Err(ManifestArtifactError::ArtifactSummaryCardinalityMismatch);
    }
    Ok(DecodedManifestArtifactPlan::Chunked {
        replay_record_kind,
        mutation_digest,
        locator,
        replay_record,
        durable_prepared_payload,
    })
}

fn decode_zero_mutation_plan(
    canonical_summary: &[u8],
    commitment: ManifestArtifactSetCommitment,
) -> Result<DecodedManifestArtifactPlan, ManifestArtifactError> {
    if canonical_summary.len() < 43 {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let version = u16::from_be_bytes(
        canonical_summary[4..6].try_into().expect("fixed"),
    );
    if version != MANIFEST_ARTIFACT_ENCODING_VERSION {
        return Err(ManifestArtifactError::UnknownEncodingVersion(version));
    }
    if canonical_summary[6] != ReplayRecordKind::FullPhysicalDelta as u8 {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let mutation_digest: [u8; 32] =
        canonical_summary[7..39].try_into().expect("fixed");
    let replay_len = u32::from_be_bytes(
        canonical_summary[39..43].try_into().expect("fixed"),
    ) as usize;
    let expected_len = 43usize.checked_add(replay_len).ok_or(
        ManifestArtifactError::ZeroMutationReceiptTooLarge(replay_len),
    )?;
    if canonical_summary.len() != expected_len
        || mutation_digest != commitment.mutation_digest()
        || commitment.affected_row_count() != 0
        || commitment.locator_chunk_count() != 0
        || commitment.replay_chunk_count() != 0
        || commitment.durable_payload_chunk_count() != 0
    {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    validate_zero_mutation_replay_record(
        &canonical_summary[43..],
        mutation_digest,
    )?;
    Ok(DecodedManifestArtifactPlan::ZeroMutation {
        mutation_digest,
        replay_record: canonical_summary[43..].to_vec(),
    })
}

fn validate_zero_mutation_replay_record(
    bytes: &[u8],
    mutation_digest: [u8; 32],
) -> Result<(), ManifestArtifactError> {
    // FullPhysicalDelta V1: PSFD/version/kind, receipt, length-prefixed
    // canonical physical batch. A zero receipt may retain operational actions
    // but its state/metadata counts and physical batch must both be empty.
    if bytes.len() < 40
        || &bytes[..4] != b"PSFD"
        || u16::from_be_bytes(bytes[4..6].try_into().expect("fixed")) != 1
        || bytes[6] != ReplayRecordKind::FullPhysicalDelta as u8
        || !matches!(bytes[7], 1 | 2)
        || u32::from_be_bytes(bytes[16..20].try_into().expect("fixed")) != 0
        || u32::from_be_bytes(bytes[20..24].try_into().expect("fixed")) != 0
    {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let action_count =
        u16::from_be_bytes(bytes[24..26].try_into().expect("fixed")) as usize;
    let actions_end = 26usize.checked_add(action_count).ok_or(
        ManifestArtifactError::InvalidZeroMutationReceipt,
    )?;
    let batch_length_end = actions_end.checked_add(4).ok_or(
        ManifestArtifactError::InvalidZeroMutationReceipt,
    )?;
    if batch_length_end > bytes.len() {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let actions = &bytes[26..actions_end];
    if actions.iter().any(|action| !matches!(action, 1..=3))
        || actions.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let batch_len = u32::from_be_bytes(
        bytes[actions_end..batch_length_end]
            .try_into()
            .expect("fixed"),
    ) as usize;
    let batch_end = batch_length_end.checked_add(batch_len).ok_or(
        ManifestArtifactError::InvalidZeroMutationReceipt,
    )?;
    if batch_end != bytes.len() {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    let empty_batch = CanonicalPhysicalMutationBatch::try_new(Vec::new())?;
    if &bytes[batch_length_end..] != empty_batch.encode_canonical()
        || mutation_digest != *empty_batch.digest().as_bytes()
    {
        return Err(ManifestArtifactError::InvalidZeroMutationReceipt);
    }
    Ok(())
}

fn decode_artifact_descriptor(
    bytes: &[u8],
    offset: &mut usize,
) -> Result<ManifestArtifactDescriptor, ManifestArtifactError> {
    const DESCRIPTOR_LEN: usize = 87;
    let end = offset
        .checked_add(DESCRIPTOR_LEN)
        .ok_or(ManifestArtifactError::InvalidArtifactSummaryEncoding)?;
    if end > bytes.len() {
        return Err(ManifestArtifactError::InvalidArtifactSummaryEncoding);
    }
    let descriptor = &bytes[*offset..end];
    let kind = ManifestArtifactKind::try_from(descriptor[0])?;
    let encoding_version =
        u16::from_be_bytes(descriptor[1..3].try_into().expect("fixed"));
    if encoding_version != MANIFEST_ARTIFACT_ENCODING_VERSION {
        return Err(ManifestArtifactError::UnknownEncodingVersion(
            encoding_version,
        ));
    }
    let chunk_count =
        u32::from_be_bytes(descriptor[3..7].try_into().expect("fixed"));
    let item_count =
        u64::from_be_bytes(descriptor[7..15].try_into().expect("fixed"));
    let encoded_bytes =
        u64::from_be_bytes(descriptor[15..23].try_into().expect("fixed"));
    if chunk_count == 0 || encoded_bytes == 0 {
        return Err(ManifestArtifactError::InvalidArtifactDescriptor);
    }
    let payload_digest = ManifestArtifactDigest::from_persisted(
        descriptor[23..55].try_into().expect("fixed"),
    );
    let chunk_set_digest = ManifestArtifactDigest::from_persisted(
        descriptor[55..87].try_into().expect("fixed"),
    );
    *offset = end;
    Ok(ManifestArtifactDescriptor {
        kind,
        encoding_version,
        chunk_count,
        item_count,
        encoded_bytes,
        payload_digest,
        chunk_set_digest,
    })
}

impl CanonicalManifestArtifactSet {
    pub fn try_from_full(
        record: &FullPhysicalDeltaRecord,
    ) -> Result<Self, ManifestArtifactError> {
        Self::try_from_full_with_limit(record, MANIFEST_ARTIFACT_MAX_CHUNK_BYTES)
    }

    fn try_from_full_with_limit(
        record: &FullPhysicalDeltaRecord,
        chunk_limit: usize,
    ) -> Result<Self, ManifestArtifactError> {
        Self::build(
            ReplayRecordKind::FullPhysicalDelta,
            record.batch(),
            record.encode_canonical(),
            None,
            chunk_limit,
        )
    }

    pub fn try_from_compact(
        record: &PreparedReferencePlusSupplementRecord,
        durable_payload_bytes: &[u8],
    ) -> Result<Self, ManifestArtifactError> {
        Self::try_from_compact_with_limit(
            record,
            durable_payload_bytes,
            MANIFEST_ARTIFACT_MAX_CHUNK_BYTES,
        )
    }

    fn try_from_compact_with_limit(
        record: &PreparedReferencePlusSupplementRecord,
        durable_payload_bytes: &[u8],
        chunk_limit: usize,
    ) -> Result<Self, ManifestArtifactError> {
        let batch = record.expand(durable_payload_bytes)?;
        Self::build(
            ReplayRecordKind::PreparedReferencePlusSupplement,
            &batch,
            record.encode_canonical(),
            Some(durable_payload_bytes.to_vec()),
            chunk_limit,
        )
    }

    fn build(
        replay_record_kind: ReplayRecordKind,
        batch: &CanonicalPhysicalMutationBatch,
        replay_bytes: Vec<u8>,
        durable_payload_bytes: Option<Vec<u8>>,
        chunk_limit: usize,
    ) -> Result<Self, ManifestArtifactError> {
        if chunk_limit == 0 || chunk_limit > MANIFEST_ARTIFACT_MAX_CHUNK_BYTES {
            return Err(ManifestArtifactError::InvalidChunkLimit(chunk_limit));
        }
        if batch.mutations().is_empty() {
            return Err(
                ManifestArtifactError::ZeroMutationReceiptNotYetSupported,
            );
        }
        let locator_bytes = encode_locator_artifact(batch)?;
        let locator = build_artifact(
            ManifestArtifactKind::Locator,
            locator_bytes,
            batch.mutations().len() as u64,
            chunk_limit,
        )?;
        let replay_record = build_artifact(
            ManifestArtifactKind::ReplayRecord,
            replay_bytes,
            batch.mutations().len() as u64,
            chunk_limit,
        )?;
        let durable_prepared_payload = durable_payload_bytes
            .map(|bytes| {
                build_artifact(
                    ManifestArtifactKind::DurablePreparedPayload,
                    bytes,
                    1,
                    chunk_limit,
                )
            })
            .transpose()?;
        let mutation_digest = *batch.digest().as_bytes();
        let canonical_summary = encode_artifact_set_summary(
            replay_record_kind,
            mutation_digest,
            locator.descriptor,
            replay_record.descriptor,
            durable_prepared_payload
                .as_ref()
                .map(|artifact| artifact.descriptor),
        );
        let commitment = ManifestArtifactSetCommitment::from_verified_artifact_summary(
            &canonical_summary,
            mutation_digest,
            locator.descriptor.chunk_count,
            replay_record.descriptor.chunk_count,
            durable_prepared_payload
                .as_ref()
                .map_or(0, |artifact| artifact.descriptor.chunk_count),
            batch.mutations().len() as u64,
        )?;
        let set = Self {
            replay_record_kind,
            mutation_digest,
            locator,
            replay_record,
            durable_prepared_payload,
            canonical_summary,
            commitment,
        };
        set.verify_integrity()?;
        Ok(set)
    }

    pub const fn replay_record_kind(&self) -> ReplayRecordKind {
        self.replay_record_kind
    }

    pub const fn mutation_digest(&self) -> &[u8; 32] {
        &self.mutation_digest
    }

    pub const fn locator(&self) -> &CanonicalManifestArtifact {
        &self.locator
    }

    pub const fn replay_record(&self) -> &CanonicalManifestArtifact {
        &self.replay_record
    }

    pub const fn durable_prepared_payload(
        &self,
    ) -> Option<&CanonicalManifestArtifact> {
        self.durable_prepared_payload.as_ref()
    }

    pub fn canonical_summary(&self) -> &[u8] {
        &self.canonical_summary
    }

    pub const fn commitment(&self) -> ManifestArtifactSetCommitment {
        self.commitment
    }

    pub fn verify_integrity(&self) -> Result<(), ManifestArtifactError> {
        let locator = self.locator.verify_and_reassemble()?;
        decode_locator_artifact(&locator, self.commitment.affected_row_count())?;
        self.replay_record.verify_and_reassemble()?;
        if let Some(payload) = &self.durable_prepared_payload {
            payload.verify_and_reassemble()?;
        }
        let summary = encode_artifact_set_summary(
            self.replay_record_kind,
            self.mutation_digest,
            self.locator.descriptor,
            self.replay_record.descriptor,
            self.durable_prepared_payload
                .as_ref()
                .map(|artifact| artifact.descriptor),
        );
        if summary != self.canonical_summary {
            return Err(ManifestArtifactError::ArtifactSummaryMismatch);
        }
        let expected = ManifestArtifactSetCommitment::from_verified_artifact_summary(
            &summary,
            self.mutation_digest,
            self.locator.descriptor.chunk_count,
            self.replay_record.descriptor.chunk_count,
            self.durable_prepared_payload
                .as_ref()
                .map_or(0, |artifact| artifact.descriptor.chunk_count),
            self.locator.descriptor.item_count,
        )?;
        if expected != self.commitment {
            return Err(ManifestArtifactError::ArtifactCommitmentMismatch);
        }
        Ok(())
    }
}

pub fn verify_artifact_chunks(
    descriptor: ManifestArtifactDescriptor,
    chunks: &[ManifestArtifactChunk],
) -> Result<Vec<u8>, ManifestArtifactError> {
    if chunks.len() != descriptor.chunk_count as usize {
        return Err(ManifestArtifactError::ChunkCountMismatch {
            expected: descriptor.chunk_count,
            actual: chunks.len(),
        });
    }
    let mut output = Vec::with_capacity(descriptor.encoded_bytes as usize);
    let mut hashes = Vec::with_capacity(chunks.len());
    for (position, chunk) in chunks.iter().enumerate() {
        if chunk.kind != descriptor.kind
            || chunk.encoding_version != descriptor.encoding_version
            || chunk.chunk_index != position as u32
            || chunk.total_chunks != descriptor.chunk_count
            || chunk.chunk_bucket
                != chunk.chunk_index / MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET
        {
            return Err(ManifestArtifactError::ChunkSequenceMismatch(position));
        }
        let expected_hash = chunk_digest(
            chunk.kind,
            chunk.chunk_index,
            chunk.total_chunks,
            &chunk.payload,
        );
        if expected_hash != chunk.payload_hash {
            return Err(ManifestArtifactError::ChunkPayloadHashMismatch(
                chunk.chunk_index,
            ));
        }
        output.extend_from_slice(&chunk.payload);
        hashes.push(chunk.payload_hash);
    }
    if output.len() as u64 != descriptor.encoded_bytes {
        return Err(ManifestArtifactError::ArtifactLengthMismatch {
            expected: descriptor.encoded_bytes,
            actual: output.len() as u64,
        });
    }
    let payload_digest = artifact_digest(descriptor.kind, &output);
    if payload_digest != descriptor.payload_digest {
        return Err(ManifestArtifactError::ArtifactPayloadDigestMismatch);
    }
    let chunk_set_digest = chunk_set_digest(
        descriptor.kind,
        descriptor.item_count,
        descriptor.encoded_bytes,
        &hashes,
    );
    if chunk_set_digest != descriptor.chunk_set_digest {
        return Err(ManifestArtifactError::ChunkSetDigestMismatch);
    }
    Ok(output)
}

fn build_artifact(
    kind: ManifestArtifactKind,
    payload: Vec<u8>,
    item_count: u64,
    chunk_limit: usize,
) -> Result<CanonicalManifestArtifact, ManifestArtifactError> {
    if payload.is_empty() {
        return Err(ManifestArtifactError::EmptyArtifactPayload(kind));
    }
    let total_chunks_usize = payload.len().div_ceil(chunk_limit);
    let total_chunks = u32::try_from(total_chunks_usize)
        .map_err(|_| ManifestArtifactError::TooManyChunks(total_chunks_usize))?;
    let mut chunks = Vec::with_capacity(total_chunks_usize);
    for (index, bytes) in payload.chunks(chunk_limit).enumerate() {
        let chunk_index = index as u32;
        chunks.push(ManifestArtifactChunk {
            kind,
            encoding_version: MANIFEST_ARTIFACT_ENCODING_VERSION,
            chunk_index,
            total_chunks,
            chunk_bucket: chunk_index / MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET,
            payload: bytes.to_vec(),
            payload_hash: chunk_digest(
                kind,
                chunk_index,
                total_chunks,
                bytes,
            ),
        });
    }
    let hashes = chunks
        .iter()
        .map(|chunk| chunk.payload_hash)
        .collect::<Vec<_>>();
    let descriptor = ManifestArtifactDescriptor {
        kind,
        encoding_version: MANIFEST_ARTIFACT_ENCODING_VERSION,
        chunk_count: total_chunks,
        item_count,
        encoded_bytes: payload.len() as u64,
        payload_digest: artifact_digest(kind, &payload),
        chunk_set_digest: chunk_set_digest(
            kind,
            item_count,
            payload.len() as u64,
            &hashes,
        ),
    };
    let artifact = CanonicalManifestArtifact { descriptor, chunks };
    artifact.verify_and_reassemble()?;
    Ok(artifact)
}

fn artifact_digest(
    kind: ManifestArtifactKind,
    payload: &[u8],
) -> ManifestArtifactDigest {
    ManifestArtifactDigest::calculate(
        ARTIFACT_DIGEST_DOMAIN,
        kind,
        &[payload],
    )
}

fn chunk_digest(
    kind: ManifestArtifactKind,
    chunk_index: u32,
    total_chunks: u32,
    payload: &[u8],
) -> ManifestArtifactDigest {
    ManifestArtifactDigest::calculate(
        CHUNK_DIGEST_DOMAIN,
        kind,
        &[
            &chunk_index.to_be_bytes(),
            &total_chunks.to_be_bytes(),
            payload,
        ],
    )
}

fn chunk_set_digest(
    kind: ManifestArtifactKind,
    item_count: u64,
    encoded_bytes: u64,
    hashes: &[ManifestArtifactDigest],
) -> ManifestArtifactDigest {
    let mut payload = Vec::with_capacity(20 + hashes.len() * 32);
    payload.extend_from_slice(&MANIFEST_ARTIFACT_ENCODING_VERSION.to_be_bytes());
    payload.extend_from_slice(&(hashes.len() as u32).to_be_bytes());
    payload.extend_from_slice(&item_count.to_be_bytes());
    payload.extend_from_slice(&encoded_bytes.to_be_bytes());
    for hash in hashes {
        payload.extend_from_slice(hash.as_bytes());
    }
    ManifestArtifactDigest::calculate(
        CHUNK_SET_DIGEST_DOMAIN,
        kind,
        &[&payload],
    )
}

fn encode_locator_artifact(
    batch: &CanonicalPhysicalMutationBatch,
) -> Result<Vec<u8>, ManifestArtifactError> {
    let count = u32::try_from(batch.mutations().len())
        .map_err(|_| ManifestArtifactError::TooManyLocatorEntries(
            batch.mutations().len(),
        ))?;
    let mut out = Vec::new();
    out.extend_from_slice(LOCATOR_MAGIC);
    out.extend_from_slice(&MANIFEST_ARTIFACT_ENCODING_VERSION.to_be_bytes());
    out.extend_from_slice(&count.to_be_bytes());
    let mut previous: Option<&[u8]> = None;
    for mutation in batch.mutations() {
        let locator = mutation.locator_bytes();
        if previous.is_some_and(|value| value >= locator) {
            return Err(ManifestArtifactError::NonCanonicalLocatorOrdering);
        }
        out.extend_from_slice(&(locator.len() as u32).to_be_bytes());
        out.extend_from_slice(locator);
        previous = Some(locator);
    }
    Ok(out)
}

fn decode_locator_artifact(
    bytes: &[u8],
    expected_rows: u64,
) -> Result<(), ManifestArtifactError> {
    if bytes.len() < 10 || &bytes[..4] != LOCATOR_MAGIC {
        return Err(ManifestArtifactError::InvalidLocatorEncoding);
    }
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != MANIFEST_ARTIFACT_ENCODING_VERSION {
        return Err(ManifestArtifactError::UnknownEncodingVersion(version));
    }
    let count = u32::from_be_bytes(bytes[6..10].try_into().expect("fixed"));
    if u64::from(count) != expected_rows {
        return Err(ManifestArtifactError::LocatorCountMismatch {
            expected: expected_rows,
            actual: u64::from(count),
        });
    }
    let mut offset = 10usize;
    let mut previous: Option<&[u8]> = None;
    for _ in 0..count {
        if offset + 4 > bytes.len() {
            return Err(ManifestArtifactError::InvalidLocatorEncoding);
        }
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4].try_into().expect("fixed"),
        ) as usize;
        offset += 4;
        if offset + length > bytes.len() {
            return Err(ManifestArtifactError::InvalidLocatorEncoding);
        }
        let locator = &bytes[offset..offset + length];
        if previous.is_some_and(|value| value >= locator) {
            return Err(ManifestArtifactError::NonCanonicalLocatorOrdering);
        }
        previous = Some(locator);
        offset += length;
    }
    if offset != bytes.len() {
        return Err(ManifestArtifactError::InvalidLocatorEncoding);
    }
    Ok(())
}

fn encode_artifact_set_summary(
    replay_record_kind: ReplayRecordKind,
    mutation_digest: [u8; 32],
    locator: ManifestArtifactDescriptor,
    replay: ManifestArtifactDescriptor,
    durable_payload: Option<ManifestArtifactDescriptor>,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ARTIFACT_SET_MAGIC);
    out.extend_from_slice(&MANIFEST_ARTIFACT_ENCODING_VERSION.to_be_bytes());
    out.push(replay_record_kind as u8);
    out.extend_from_slice(&mutation_digest);
    out.push(if durable_payload.is_some() { 3 } else { 2 });
    locator.encode_into(&mut out);
    replay.encode_into(&mut out);
    if let Some(payload) = durable_payload {
        payload.encode_into(&mut out);
    }
    out
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManifestArtifactError {
    Replay(ReplayPrototypeError),
    Intent(ManifestIntentError),
    UnknownArtifactKind(u8),
    UnknownEncodingVersion(u16),
    InvalidChunkLimit(usize),
    ZeroMutationReceiptNotYetSupported,
    NonZeroMutationReceipt { actual: usize },
    ZeroMutationReceiptTooLarge(usize),
    InvalidZeroMutationReceipt,
    EmptyArtifactPayload(ManifestArtifactKind),
    TooManyChunks(usize),
    TooManyLocatorEntries(usize),
    InvalidChunkPosition { chunk_index: u32, total_chunks: u32 },
    ChunkBucketMismatch { chunk_index: u32, expected: u32, actual: u32 },
    EmptyPersistedChunkPayload(u32),
    ChunkPayloadTooLarge { chunk_index: u32, actual: usize, maximum: usize },
    ChunkCountMismatch { expected: u32, actual: usize },
    ChunkSequenceMismatch(usize),
    ChunkPayloadHashMismatch(u32),
    ArtifactLengthMismatch { expected: u64, actual: u64 },
    ArtifactPayloadDigestMismatch,
    ChunkSetDigestMismatch,
    InvalidLocatorEncoding,
    LocatorCountMismatch { expected: u64, actual: u64 },
    NonCanonicalLocatorOrdering,
    ArtifactSummaryMismatch,
    ArtifactCommitmentMismatch,
    InvalidArtifactSummaryEncoding,
    InvalidArtifactDescriptor,
    ArtifactSummaryCardinalityMismatch,
}

impl From<ReplayPrototypeError> for ManifestArtifactError {
    fn from(value: ReplayPrototypeError) -> Self {
        Self::Replay(value)
    }
}

impl From<ManifestIntentError> for ManifestArtifactError {
    fn from(value: ManifestIntentError) -> Self {
        Self::Intent(value)
    }
}

impl fmt::Display for ManifestArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ManifestArtifactError {}

#[cfg(test)]
mod tests {
    use psy_node_core::store::typed::{
        CheckpointId, LogicalMutation, MerkleNode, MutationValue, NodeIndex,
        TypedTableKey,
    };

    use super::*;
    use crate::rollback::{
        CanonicalPhysicalMutationBatch, FullPhysicalDeltaRecord,
        DerivedSupplementBatch, DurablePreparedPayloadReference,
        OperationalReplayAction, PreparedPayload, PreparedPayloadKind,
        PreparedPayloadSource, PreparedReferencePlusSupplementRecord,
        PreparedSemanticMutation, ReplayAuthority, ReplayReceipt,
    };

    fn full_record() -> FullPhysicalDeltaRecord {
        let checkpoint = CheckpointId::try_new(7).unwrap();
        let batch = CanonicalPhysicalMutationBatch::from_logical(vec![
            LogicalMutation::Put {
                key: TypedTableKey::GlobalUserMerkle {
                    node: MerkleNode::new(2, NodeIndex::new(9)),
                    checkpoint,
                },
                value: MutationValue::PsyCanonicalBytes(vec![0x22; 32]),
            },
            LogicalMutation::Put {
                key: TypedTableKey::CheckpointLeaf(checkpoint),
                value: MutationValue::PsyCanonicalBytes(vec![0x11; 32]),
            },
        ])
        .unwrap();
        FullPhysicalDeltaRecord::try_new(
            batch,
            ReplayReceipt::new(
                ReplayAuthority::Coordinator,
                checkpoint,
                1,
                1,
                vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
            ),
        )
        .unwrap()
    }

    #[test]
    fn artifact_set_is_deterministic_and_commitment_matches() {
        let first = CanonicalManifestArtifactSet::try_from_full(&full_record()).unwrap();
        let second = CanonicalManifestArtifactSet::try_from_full(&full_record()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.replay_record_kind(), ReplayRecordKind::FullPhysicalDelta);
        assert_eq!(first.commitment().affected_row_count(), 2);
        assert!(first.durable_prepared_payload().is_none());
        first.verify_integrity().unwrap();
    }

    #[test]
    fn compact_artifact_binds_durable_payload_and_expands_to_full_batch() {
        let checkpoint = CheckpointId::try_new(8).unwrap();
        let payload = PreparedPayload::try_v1(
            PreparedPayloadKind::Coordinator,
            vec![PreparedSemanticMutation::CheckpointLeaf {
                checkpoint,
                value: vec![0x31; 32],
            }],
        )
        .unwrap();
        let payload_bytes = payload.encode_canonical();
        let prepared = DurablePreparedPayloadReference::try_from_source(
            PreparedPayloadKind::Coordinator,
            1,
            1,
            PreparedPayloadSource::ContentAddressedBytes(&payload_bytes),
        )
        .unwrap();
        let supplements = DerivedSupplementBatch::from_logical(vec![
            LogicalMutation::Put {
                key: TypedTableKey::GlobalUserMerkle {
                    node: MerkleNode::new(3, NodeIndex::new(4)),
                    checkpoint,
                },
                value: MutationValue::PsyCanonicalBytes(vec![0x32; 32]),
            },
        ])
        .unwrap();
        let full = CanonicalPhysicalMutationBatch::from_logical(vec![
            LogicalMutation::Put {
                key: TypedTableKey::CheckpointLeaf(checkpoint),
                value: MutationValue::PsyCanonicalBytes(vec![0x31; 32]),
            },
            LogicalMutation::Put {
                key: TypedTableKey::GlobalUserMerkle {
                    node: MerkleNode::new(3, NodeIndex::new(4)),
                    checkpoint,
                },
                value: MutationValue::PsyCanonicalBytes(vec![0x32; 32]),
            },
        ])
        .unwrap();
        let receipt = ReplayReceipt::new(
            ReplayAuthority::Coordinator,
            checkpoint,
            1,
            1,
            vec![OperationalReplayAction::RotatePendingCheckpointNamespace],
        );
        let compact = PreparedReferencePlusSupplementRecord::try_v1(
            prepared,
            supplements,
            receipt,
            &payload_bytes,
            &full,
        )
        .unwrap();

        let set = CanonicalManifestArtifactSet::try_from_compact(
            &compact,
            &payload_bytes,
        )
        .unwrap();
        assert_eq!(
            set.replay_record_kind(),
            ReplayRecordKind::PreparedReferencePlusSupplement
        );
        assert_eq!(set.mutation_digest(), full.digest().as_bytes());
        assert_eq!(set.commitment().affected_row_count(), 2);
        assert_eq!(set.commitment().durable_payload_chunk_count(), 1);
        assert_eq!(
            set.durable_prepared_payload()
                .unwrap()
                .verify_and_reassemble()
                .unwrap(),
            payload_bytes
        );
        set.verify_integrity().unwrap();
    }

    #[test]
    fn zero_mutation_receipt_is_not_silently_encoded_as_header_chunks() {
        let checkpoint = CheckpointId::try_new(9).unwrap();
        let batch = CanonicalPhysicalMutationBatch::try_new(Vec::new()).unwrap();
        let record = FullPhysicalDeltaRecord::try_new(
            batch,
            ReplayReceipt::new(
                ReplayAuthority::Coordinator,
                checkpoint,
                0,
                0,
                Vec::new(),
            ),
        )
        .unwrap();
        assert_eq!(
            CanonicalManifestArtifactSet::try_from_full(&record).unwrap_err(),
            ManifestArtifactError::ZeroMutationReceiptNotYetSupported
        );

        let bundle = CanonicalManifestArtifacts::try_from_full(&record).unwrap();
        assert!(bundle.is_zero_mutation());
        assert!(bundle.chunked().is_none());
        assert_eq!(bundle.commitment().affected_row_count(), 0);
        assert_eq!(bundle.commitment().locator_chunk_count(), 0);
        assert_eq!(bundle.commitment().replay_chunk_count(), 0);
        assert_eq!(bundle.commitment().durable_payload_chunk_count(), 0);
        bundle.verify_integrity().unwrap();
    }

    #[test]
    fn small_chunk_profile_proves_index_bucket_and_reassembly() {
        let set = CanonicalManifestArtifactSet::try_from_full_with_limit(
            &full_record(),
            32,
        )
        .unwrap();
        assert!(set.locator().chunks().len() > 1);
        assert!(set.replay_record().chunks().len() > 1);
        for chunk in set
            .locator()
            .chunks()
            .iter()
            .chain(set.replay_record().chunks())
        {
            assert_eq!(
                chunk.chunk_bucket(),
                chunk.chunk_index() / MANIFEST_ARTIFACT_CHUNKS_PER_BUCKET
            );
        }
        set.verify_integrity().unwrap();
    }

    #[test]
    fn persisted_chunk_payload_tamper_fails_closed() {
        let set = CanonicalManifestArtifactSet::try_from_full(&full_record()).unwrap();
        let original = &set.locator().chunks()[0];
        let mut payload = original.payload().to_vec();
        payload[0] ^= 1;
        let tampered = ManifestArtifactChunk::try_from_persisted(
            original.kind() as u8,
            original.encoding_version(),
            original.chunk_index(),
            original.total_chunks(),
            original.chunk_bucket(),
            payload,
            *original.payload_hash().as_bytes(),
        )
        .unwrap();
        assert_eq!(
            verify_artifact_chunks(
                set.locator().descriptor(),
                &[tampered],
            )
            .unwrap_err(),
            ManifestArtifactError::ChunkPayloadHashMismatch(0)
        );
    }

    #[test]
    fn persisted_chunk_metadata_is_fail_closed() {
        assert!(matches!(
            ManifestArtifactChunk::try_from_persisted(
                99, 1, 0, 1, 0, vec![1], [0; 32]
            ),
            Err(ManifestArtifactError::UnknownArtifactKind(99))
        ));
        assert!(matches!(
            ManifestArtifactChunk::try_from_persisted(
                ManifestArtifactKind::Locator as u8,
                1,
                16,
                17,
                0,
                vec![1],
                [0; 32]
            ),
            Err(ManifestArtifactError::ChunkBucketMismatch { .. })
        ));
        assert_eq!(
            ManifestArtifactChunk::try_from_persisted(
                ManifestArtifactKind::Locator as u8,
                1,
                0,
                1,
                0,
                Vec::new(),
                [0; 32],
            )
            .unwrap_err(),
            ManifestArtifactError::EmptyPersistedChunkPayload(0)
        );
    }
}
