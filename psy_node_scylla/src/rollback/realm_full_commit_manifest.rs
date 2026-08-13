//! Storage-private composite verification manifest for one Realm commit.
//!
//! The narrow h22 writer and the remaining typed family executor deliberately
//! produce separate exact observations. This module is the first boundary
//! allowed to combine them. It performs no CQL and exposes no publish/head
//! capability; persistence and fresh revalidation are a later slice.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    branch_pending_mapping::{
        BRANCH_PENDING_CANONICAL_REF_LEN, BranchPendingMapping,
    },
    timestamp::CommitWriteTimestampUs,
    typed::UniquePendingId,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterState, StoredBranchExactWriterLifecycle,
    realm_full_commit_execution::RealmTypedRowsExactObservation,
    realm_full_commit_plan::RealmFullCommitPhysicalPlan,
};

const MAGIC: [u8; 8] = *b"PSYRFCMF";
const CODEC_VERSION: u16 = 1;
const REVISION: u64 = 1;
const SLOT_DOMAIN: &[u8] = b"psy.rollback.realm-full-commit-manifest-slot.v1\0";
const WRITER_PAYLOAD_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-writer-payload.v1\0";
const MANIFEST_DIGEST_DOMAIN: &[u8] =
    b"psy.rollback.realm-full-commit-manifest.v1\0";
const MAX_CANONICAL_PAYLOAD_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct RealmFullCommitManifestSlot([u8; 32]);

impl RealmFullCommitManifestSlot {
    pub(crate) const fn as_bytes(&self) -> &[u8; 32] { &self.0 }
}

/// Exact, storage-selected h22 evidence. The only production constructor
/// accepts the complete durable writer row in `WritesVerified`; raw digests or
/// a public prepared intent cannot create this value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmNarrowWritesVerifiedEvidence<Hash> {
    authority: AuthorityScope,
    candidate: BranchPendingMapping<Hash>,
    writer_slot: [u8; 32],
    writer_revision: u64,
    writer_payload_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    write_timestamp: CommitWriteTimestampUs,
    h22_row_count: u32,
    h22_observation_digest: [u8; 32],
    writer_verified_digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmNarrowWritesVerifiedEvidence<Hash> {
    pub(crate) fn try_from_stored(
        writer: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<Self, RealmFullCommitManifestError> {
        let BranchExactWriterState::WritesVerified(verified) = writer.state() else {
            return Err(RealmFullCommitManifestError::WriterNotWritesVerified);
        };
        let authority = writer.plan().authority();
        if !matches!(authority, AuthorityScope::Realm { .. })
            || verified.prepared().intent().authority() != authority
        {
            return Err(RealmFullCommitManifestError::RealmWriterRequired);
        }
        let h22_row_count = u32::try_from(
            verified.prepared().intent().mutations().len(),
        )
        .map_err(|_| RealmFullCommitManifestError::CountOutOfRange)?;
        let writer_payload = writer.to_canonical_bytes();
        Ok(Self {
            authority,
            candidate: *verified.prepared().intent().candidate(),
            writer_slot: *writer.slot().as_bytes(),
            writer_revision: writer.revision().get(),
            writer_payload_digest: digest_bytes(
                WRITER_PAYLOAD_DOMAIN,
                &writer_payload,
            ),
            narrow_prepared_digest: *verified.prepared().digest(),
            narrow_intent_digest: *verified
                .prepared()
                .intent()
                .intent_digest()
                .as_bytes(),
            write_timestamp: verified.prepared().timestamp(),
            h22_row_count,
            h22_observation_digest: *verified.observation().as_bytes(),
            writer_verified_digest: *verified.digest(),
        })
    }

    #[cfg(test)]
    pub(crate) fn test_fixture(
        prepared: &super::BranchExactWriterPrepared<Hash>,
    ) -> Self {
        let authority = prepared.intent().authority();
        let writer_slot = *super::BranchExactWriterSlot::for_authority(
            prepared.intent().candidate().canonical_chain().network_id(),
            authority,
        )
        .as_bytes();
        let narrow_prepared_digest = *prepared.digest();
        let narrow_intent_digest = *prepared.intent().intent_digest().as_bytes();
        let h22_observation_digest = digest_bytes(
            b"psy.rollback.realm-full-commit-test-h22-observation\0",
            prepared.intent().to_canonical_bytes(),
        );
        let mut verified = Sha256::new();
        verified.update(b"psy.rollback.realm-full-commit-test-verified\0");
        verified.update(narrow_prepared_digest);
        verified.update(h22_observation_digest);
        Self {
            authority,
            candidate: *prepared.intent().candidate(),
            writer_slot,
            writer_revision: 3,
            writer_payload_digest: digest_bytes(
                WRITER_PAYLOAD_DOMAIN,
                prepared.intent().to_canonical_bytes(),
            ),
            narrow_prepared_digest,
            narrow_intent_digest,
            write_timestamp: prepared.timestamp(),
            h22_row_count: u32::try_from(prepared.intent().mutations().len())
                .expect("h22 test mutation count must fit u32"),
            h22_observation_digest,
            writer_verified_digest: verified.finalize().into(),
        }
    }
}

/// Canonical commitment to both exact write halves. It is immutable model
/// data, not a durable receipt; later code must persist and fresh-revalidate
/// it before any production writer coverage can change.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RealmFullCommitCompositeManifest<Hash> {
    slot: RealmFullCommitManifestSlot,
    revision: u64,
    authority: AuthorityScope,
    candidate: BranchPendingMapping<Hash>,
    writer_slot: [u8; 32],
    writer_revision: u64,
    writer_payload_digest: [u8; 32],
    writer_verified_digest: [u8; 32],
    h22_observation_digest: [u8; 32],
    narrow_prepared_digest: [u8; 32],
    narrow_intent_digest: [u8; 32],
    coverage_digest: [u8; 32],
    typed_observation_digest: [u8; 32],
    typed_row_count: u32,
    total_mutation_count: u64,
    write_timestamp: CommitWriteTimestampUs,
    prepared_payload_commitment: Option<[u8; 32]>,
    mutation_graph_digest: Option<[u8; 32]>,
    canonical_payload: Vec<u8>,
    digest: [u8; 32],
}

impl<Hash: Q256BitHash> RealmFullCommitCompositeManifest<Hash> {
    pub(crate) fn try_new(
        plan: &RealmFullCommitPhysicalPlan,
        narrow: &RealmNarrowWritesVerifiedEvidence<Hash>,
        typed: &RealmTypedRowsExactObservation,
    ) -> Result<Self, RealmFullCommitManifestError> {
        if !matches!(narrow.authority, AuthorityScope::Realm { .. }) {
            return Err(RealmFullCommitManifestError::RealmWriterRequired);
        }
        if plan.narrow_prepared_digest() != &narrow.narrow_prepared_digest
            || plan.narrow_intent_digest() != &narrow.narrow_intent_digest
            || typed.narrow_prepared_digest() != &narrow.narrow_prepared_digest
        {
            return Err(RealmFullCommitManifestError::NarrowIdentityMismatch);
        }
        if plan.coverage().digest() != typed.coverage_digest() {
            return Err(RealmFullCommitManifestError::CoverageMismatch);
        }
        if plan.coverage().write_timestamp() != narrow.write_timestamp {
            return Err(RealmFullCommitManifestError::TimestampMismatch);
        }
        let expected_typed_rows = plan.remaining().iter().try_fold(
            0_usize,
            |count, batch| count.checked_add(batch.puts().len()),
        )
        .ok_or(RealmFullCommitManifestError::CountOutOfRange)?;
        if typed.row_count() != expected_typed_rows {
            return Err(RealmFullCommitManifestError::TypedRowCountMismatch);
        }
        let typed_row_count = u32::try_from(typed.row_count())
            .map_err(|_| RealmFullCommitManifestError::CountOutOfRange)?;
        let observed_total = u64::from(narrow.h22_row_count)
            .checked_add(u64::from(typed_row_count))
            .ok_or(RealmFullCommitManifestError::CountOutOfRange)?;
        if observed_total != plan.coverage().total_mutation_count() {
            return Err(RealmFullCommitManifestError::TotalMutationCountMismatch);
        }
        let prepared_payload_commitment =
            plan.prepared_payload_commitment().map(|value| value.as_bytes());
        let mutation_graph_digest =
            plan.mutation_graph_digest().map(|value| value.as_bytes());
        if prepared_payload_commitment.is_some() != mutation_graph_digest.is_some() {
            return Err(RealmFullCommitManifestError::StateCommitmentMismatch);
        }

        let slot = manifest_slot(narrow.writer_slot, &narrow.candidate);
        let mut manifest = Self {
            slot,
            revision: REVISION,
            authority: narrow.authority,
            candidate: narrow.candidate,
            writer_slot: narrow.writer_slot,
            writer_revision: narrow.writer_revision,
            writer_payload_digest: narrow.writer_payload_digest,
            writer_verified_digest: narrow.writer_verified_digest,
            h22_observation_digest: narrow.h22_observation_digest,
            narrow_prepared_digest: narrow.narrow_prepared_digest,
            narrow_intent_digest: narrow.narrow_intent_digest,
            coverage_digest: *plan.coverage().digest(),
            typed_observation_digest: *typed.digest(),
            typed_row_count,
            total_mutation_count: plan.coverage().total_mutation_count(),
            write_timestamp: narrow.write_timestamp,
            prepared_payload_commitment,
            mutation_graph_digest,
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

    pub(crate) fn decode_persisted(
        selected_slot: &[u8],
        revision: i64,
        payload: &[u8],
    ) -> Result<Self, RealmFullCommitManifestError> {
        if payload.len() > MAX_CANONICAL_PAYLOAD_BYTES {
            return Err(RealmFullCommitManifestError::PayloadTooLarge {
                actual: payload.len(),
            });
        }
        if revision != REVISION as i64 {
            return Err(RealmFullCommitManifestError::RevisionMismatch);
        }
        let body_len = payload
            .len()
            .checked_sub(32)
            .ok_or(RealmFullCommitManifestError::TruncatedPayload)?;
        let (body, encoded_digest) = payload.split_at(body_len);
        let digest = digest_bytes(MANIFEST_DIGEST_DOMAIN, body);
        if encoded_digest != digest {
            return Err(RealmFullCommitManifestError::ManifestDigestMismatch);
        }
        let mut decoder = Decoder::new(body);
        if decoder.take(8)? != MAGIC {
            return Err(RealmFullCommitManifestError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != CODEC_VERSION {
            return Err(RealmFullCommitManifestError::UnknownCodecVersion(version));
        }
        if decoder.u64()? != REVISION {
            return Err(RealmFullCommitManifestError::RevisionMismatch);
        }
        let authority = decoder.authority()?;
        if !matches!(authority, AuthorityScope::Realm { .. }) {
            return Err(RealmFullCommitManifestError::RealmWriterRequired);
        }
        let canonical_chain = decoder.take(BRANCH_PENDING_CANONICAL_REF_LEN)?;
        let pending = UniquePendingId::try_new(decoder.u64()?)
            .map_err(|_| RealmFullCommitManifestError::InvalidCandidate)?;
        let candidate = BranchPendingMapping::from_canonical_chain_bytes(
            canonical_chain,
            pending,
        )
        .map_err(|_| RealmFullCommitManifestError::InvalidCandidate)?;
        let writer_slot = decoder.array32()?;
        let writer_revision = decoder.u64()?;
        let writer_payload_digest = decoder.nonzero_digest()?;
        let writer_verified_digest = decoder.nonzero_digest()?;
        let h22_observation_digest = decoder.nonzero_digest()?;
        let narrow_prepared_digest = decoder.nonzero_digest()?;
        let narrow_intent_digest = decoder.nonzero_digest()?;
        let coverage_digest = decoder.nonzero_digest()?;
        let typed_observation_digest = decoder.nonzero_digest()?;
        let typed_row_count = decoder.u32()?;
        let total_mutation_count = decoder.u64()?;
        let write_timestamp = CommitWriteTimestampUs::try_from_i128(
            i128::from(decoder.i64()?),
        )
        .map_err(|_| RealmFullCommitManifestError::InvalidTimestamp)?;
        let prepared_payload_commitment = decoder.optional_digest()?;
        let mutation_graph_digest = decoder.optional_digest()?;
        if prepared_payload_commitment.is_some() != mutation_graph_digest.is_some() {
            return Err(RealmFullCommitManifestError::StateCommitmentMismatch);
        }
        let slot = RealmFullCommitManifestSlot(decoder.array32()?);
        if !decoder.is_done() {
            return Err(RealmFullCommitManifestError::TrailingBytes);
        }
        if typed_row_count == 0
            || total_mutation_count <= u64::from(typed_row_count)
            || slot != manifest_slot(writer_slot, &candidate)
            || selected_slot != slot.as_bytes()
        {
            return Err(RealmFullCommitManifestError::PersistedIdentityMismatch);
        }
        Ok(Self {
            slot,
            revision: REVISION,
            authority,
            candidate,
            writer_slot,
            writer_revision,
            writer_payload_digest,
            writer_verified_digest,
            h22_observation_digest,
            narrow_prepared_digest,
            narrow_intent_digest,
            coverage_digest,
            typed_observation_digest,
            typed_row_count,
            total_mutation_count,
            write_timestamp,
            prepared_payload_commitment,
            mutation_graph_digest,
            canonical_payload: payload.to_vec(),
            digest,
        })
    }

    pub(crate) fn revalidate_sources(
        &self,
        plan: &RealmFullCommitPhysicalPlan,
        narrow: &RealmNarrowWritesVerifiedEvidence<Hash>,
        typed: &RealmTypedRowsExactObservation,
    ) -> Result<(), RealmFullCommitManifestError> {
        let expected = Self::try_new(plan, narrow, typed)?;
        if &expected != self {
            return Err(RealmFullCommitManifestError::SourceRevalidationMismatch);
        }
        Ok(())
    }

    /// Validate this immutable manifest against the current durable writer
    /// during publication recovery.  The Active state is accepted only as the
    /// exact one-revision successor retaining this manifest's candidate and
    /// intent digest.
    pub(crate) fn revalidate_published_writer(
        &self,
        writer: &StoredBranchExactWriterLifecycle<Hash>,
    ) -> Result<(), RealmFullCommitManifestError> {
        if writer.plan().authority() != self.authority
            || writer.slot().as_bytes() != &self.writer_slot
        {
            return Err(RealmFullCommitManifestError::SourceRevalidationMismatch);
        }
        match writer.state() {
            BranchExactWriterState::WritesVerified(_) => {
                let narrow = RealmNarrowWritesVerifiedEvidence::try_from_stored(writer)?;
                if narrow.authority != self.authority
                    || narrow.candidate != self.candidate
                    || narrow.writer_slot != self.writer_slot
                    || narrow.writer_revision != self.writer_revision
                    || narrow.writer_payload_digest != self.writer_payload_digest
                    || narrow.writer_verified_digest != self.writer_verified_digest
                    || narrow.h22_observation_digest != self.h22_observation_digest
                    || narrow.narrow_prepared_digest != self.narrow_prepared_digest
                    || narrow.narrow_intent_digest != self.narrow_intent_digest
                    || narrow.write_timestamp != self.write_timestamp
                {
                    return Err(RealmFullCommitManifestError::SourceRevalidationMismatch);
                }
            }
            BranchExactWriterState::Active(active) => {
                if active.watermark() != &self.candidate
                    || active.last_intent().map(|digest| *digest.as_bytes())
                        != Some(self.narrow_intent_digest)
                    || self.writer_revision.checked_add(1)
                        != Some(writer.revision().get())
                {
                    return Err(RealmFullCommitManifestError::SourceRevalidationMismatch);
                }
            }
            _ => return Err(RealmFullCommitManifestError::WriterNotWritesVerified),
        }
        Ok(())
    }

    pub(crate) const fn slot(&self) -> RealmFullCommitManifestSlot { self.slot }
    pub(crate) const fn revision(&self) -> u64 { self.revision }
    pub(crate) const fn authority(&self) -> AuthorityScope { self.authority }
    pub(crate) const fn candidate(&self) -> &BranchPendingMapping<Hash> {
        &self.candidate
    }
    pub(crate) const fn writer_slot(&self) -> &[u8; 32] {
        &self.writer_slot
    }
    pub(crate) const fn writer_revision(&self) -> u64 {
        self.writer_revision
    }
    pub(crate) const fn narrow_intent_digest(&self) -> &[u8; 32] {
        &self.narrow_intent_digest
    }
    pub(crate) const fn write_timestamp(&self) -> CommitWriteTimestampUs {
        self.write_timestamp
    }
    pub(crate) const fn coverage_digest(&self) -> &[u8; 32] {
        &self.coverage_digest
    }
    pub(crate) const fn digest(&self) -> &[u8; 32] { &self.digest }
    pub(crate) const fn typed_row_count(&self) -> u32 { self.typed_row_count }
    pub(crate) const fn total_mutation_count(&self) -> u64 {
        self.total_mutation_count
    }
    pub(crate) fn canonical_payload(&self) -> &[u8] {
        &self.canonical_payload
    }
}

pub(crate) fn realm_full_commit_manifest_slot<Hash: Q256BitHash>(
    writer_slot: [u8; 32],
    candidate: &BranchPendingMapping<Hash>,
) -> RealmFullCommitManifestSlot {
    manifest_slot(writer_slot, candidate)
}

fn manifest_slot<Hash: Q256BitHash>(
    writer_slot: [u8; 32],
    candidate: &BranchPendingMapping<Hash>,
) -> RealmFullCommitManifestSlot {
    let mut hasher = Sha256::new();
    hasher.update(SLOT_DOMAIN);
    hasher.update(writer_slot);
    hasher.update(candidate.canonical_chain_bytes());
    hasher.update(candidate.pending_id().get().to_be_bytes());
    RealmFullCommitManifestSlot(hasher.finalize().into())
}

fn encode_manifest<Hash: Q256BitHash>(
    manifest: &RealmFullCommitCompositeManifest<Hash>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&CODEC_VERSION.to_be_bytes());
    out.extend_from_slice(&manifest.revision.to_be_bytes());
    encode_authority(manifest.authority, &mut out);
    out.extend_from_slice(&manifest.candidate.canonical_chain_bytes());
    out.extend_from_slice(&manifest.candidate.pending_id().get().to_be_bytes());
    out.extend_from_slice(&manifest.writer_slot);
    out.extend_from_slice(&manifest.writer_revision.to_be_bytes());
    out.extend_from_slice(&manifest.writer_payload_digest);
    out.extend_from_slice(&manifest.writer_verified_digest);
    out.extend_from_slice(&manifest.h22_observation_digest);
    out.extend_from_slice(&manifest.narrow_prepared_digest);
    out.extend_from_slice(&manifest.narrow_intent_digest);
    out.extend_from_slice(&manifest.coverage_digest);
    out.extend_from_slice(&manifest.typed_observation_digest);
    out.extend_from_slice(&manifest.typed_row_count.to_be_bytes());
    out.extend_from_slice(&manifest.total_mutation_count.to_be_bytes());
    out.extend_from_slice(&manifest.write_timestamp.as_i64().to_be_bytes());
    encode_optional_digest(manifest.prepared_payload_commitment, &mut out);
    encode_optional_digest(manifest.mutation_graph_digest, &mut out);
    out.extend_from_slice(manifest.slot.as_bytes());
    let digest = digest_bytes(MANIFEST_DIGEST_DOMAIN, &out);
    out.extend_from_slice(&digest);
    out
}

fn encode_authority(authority: AuthorityScope, out: &mut Vec<u8>) {
    match authority {
        AuthorityScope::Coordinator => out.extend_from_slice(&[1, 0, 0, 0, 0, 0, 0]),
        AuthorityScope::Realm { realm_id, realm_sub_id } => {
            out.push(2);
            out.extend_from_slice(&realm_id.to_be_bytes());
            out.extend_from_slice(&realm_sub_id.to_be_bytes());
        }
    }
}

fn encode_optional_digest(value: Option<[u8; 32]>, out: &mut Vec<u8>) {
    match value {
        None => out.push(0),
        Some(value) => {
            out.push(1);
            out.extend_from_slice(&value);
        }
    }
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
    const fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }

    fn take(&mut self, len: usize) -> Result<&'a [u8], RealmFullCommitManifestError> {
        let end = self.offset.checked_add(len)
            .ok_or(RealmFullCommitManifestError::TruncatedPayload)?;
        let value = self.bytes.get(self.offset..end)
            .ok_or(RealmFullCommitManifestError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn u16(&mut self) -> Result<u16, RealmFullCommitManifestError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().expect("fixed slice")))
    }
    fn u32(&mut self) -> Result<u32, RealmFullCommitManifestError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().expect("fixed slice")))
    }
    fn u64(&mut self) -> Result<u64, RealmFullCommitManifestError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }
    fn i64(&mut self) -> Result<i64, RealmFullCommitManifestError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().expect("fixed slice")))
    }
    fn array32(&mut self) -> Result<[u8; 32], RealmFullCommitManifestError> {
        Ok(self.take(32)?.try_into().expect("fixed slice"))
    }
    fn nonzero_digest(&mut self) -> Result<[u8; 32], RealmFullCommitManifestError> {
        let value = self.array32()?;
        if value == [0; 32] {
            return Err(RealmFullCommitManifestError::ZeroDigest);
        }
        Ok(value)
    }
    fn optional_digest(
        &mut self,
    ) -> Result<Option<[u8; 32]>, RealmFullCommitManifestError> {
        match self.take(1)?[0] {
            0 => Ok(None),
            1 => Ok(Some(self.nonzero_digest()?)),
            value => Err(RealmFullCommitManifestError::InvalidPresence(value)),
        }
    }
    fn authority(&mut self) -> Result<AuthorityScope, RealmFullCommitManifestError> {
        match self.take(1)?[0] {
            1 => {
                if self.take(6)?.iter().any(|value| *value != 0) {
                    return Err(RealmFullCommitManifestError::InvalidAuthority);
                }
                Ok(AuthorityScope::Coordinator)
            }
            2 => Ok(AuthorityScope::Realm {
                realm_id: self.u32()?,
                realm_sub_id: self.u16()?,
            }),
            _ => Err(RealmFullCommitManifestError::InvalidAuthority),
        }
    }
    const fn is_done(&self) -> bool { self.offset == self.bytes.len() }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum RealmFullCommitManifestError {
    WriterNotWritesVerified,
    RealmWriterRequired,
    NarrowIdentityMismatch,
    CoverageMismatch,
    TimestampMismatch,
    TypedRowCountMismatch,
    TotalMutationCountMismatch,
    StateCommitmentMismatch,
    CountOutOfRange,
    InvalidMagic,
    UnknownCodecVersion(u16),
    RevisionMismatch,
    InvalidAuthority,
    InvalidCandidate,
    InvalidTimestamp,
    InvalidPresence(u8),
    ZeroDigest,
    TruncatedPayload,
    PayloadTooLarge { actual: usize },
    TrailingBytes,
    ManifestDigestMismatch,
    PersistedIdentityMismatch,
    SourceRevalidationMismatch,
}

impl fmt::Display for RealmFullCommitManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Realm full-commit composite manifest: {self:?}")
    }
}

impl Error for RealmFullCommitManifestError {}
