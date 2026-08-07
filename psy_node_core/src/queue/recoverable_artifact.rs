//! Driver-independent lifecycle for one exact recoverable queue artifact.
//!
//! The durable owner is one `{generation context, stable queue source}` slot.
//! Normal batches advance through `Open -> AppendPrepared ->
//! SelectedAwaitingAck -> Open`; generation close advances through
//! `Open -> CloseObserved -> SourceScanned`. `SourceScanned` is deliberately
//! per-source and non-terminal. This model does not grant backend ACK
//! authority. The concrete Scylla adapter may mint an opaque per-batch receipt
//! only after it has persisted and read back every fragment and selected the
//! batch in the header.

use std::{collections::BTreeSet, error::Error, fmt};

use sha2::{Digest, Sha256};

use super::recoverable_ephemeral::{
    PendingQueueArtifactIdentity, PendingQueueBatchDigest,
    PendingQueueBoundaryObservation, PendingQueueCaptureCandidate,
    PendingQueueGenerationBoundary, PendingQueuePayloadDigest,
    PendingQueueSourceCursorView, MAX_RECOVERABLE_QUEUE_BATCH_BYTES,
    MAX_RECOVERABLE_QUEUE_BATCH_ITEMS,
};

pub const PENDING_QUEUE_ARTIFACT_CODEC_VERSION: u16 = 1;
pub const PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES: usize = 4 * 1024 * 1024;
pub const PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET: u64 = 16;
pub const MAX_PENDING_QUEUE_ARTIFACT_BATCHES: u32 = 1024;
pub const MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES: u64 = 72 * 1024 * 1024;
pub const MAX_PENDING_QUEUE_ARTIFACT_HEADER_COMPONENT_BYTES: usize = 8 * 1024;
pub const MAX_PENDING_QUEUE_ARTIFACT_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_PENDING_QUEUE_CANDIDATE_FRAGMENTS: u16 =
    (MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES as usize)
        .div_ceil(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES) as u16;

const SLOT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-artifact-slot/v1";
const CANDIDATE_DOMAIN: &[u8] = b"psy/rollback/pending-queue-candidate/v1";
const FRAGMENT_DOMAIN: &[u8] = b"psy/rollback/pending-queue-fragment/v1";
const DATASET_INITIAL_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-dataset-initial/v1";
const DATASET_APPEND_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-dataset-append/v1";
const COVERAGE_INITIAL_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-coverage-initial/v1";
const COVERAGE_APPEND_DOMAIN: &[u8] =
    b"psy/rollback/pending-queue-coverage-append/v1";
const SCAN_DOMAIN: &[u8] = b"psy/rollback/pending-queue-scan/v1";

macro_rules! digest_type {
    ($name:ident, $error:ident) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name([u8; 32]);

        impl $name {
            pub fn try_new(bytes: [u8; 32]) -> Result<Self, PendingQueueArtifactError> {
                if bytes == [0; 32] {
                    Err(PendingQueueArtifactError::$error)
                } else {
                    Ok(Self(bytes))
                }
            }

            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }
    };
}

digest_type!(PendingQueueArtifactSlot, EmptySlotDigest);
digest_type!(PendingQueueCandidateDigest, EmptyCandidateDigest);
digest_type!(PendingQueueFragmentDigest, EmptyFragmentDigest);
digest_type!(PendingQueueDatasetDigest, EmptyDatasetDigest);
digest_type!(PendingQueueCoverageDigest, EmptyCoverageDigest);
digest_type!(PendingQueueArtifactScanDigest, EmptyScanDigest);

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingQueueArtifactRevision(u64);

impl PendingQueueArtifactRevision {
    pub const fn try_new(value: u64) -> Result<Self, PendingQueueArtifactError> {
        if value == 0 || value > i64::MAX as u64 {
            Err(PendingQueueArtifactError::RevisionOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn as_i64(self) -> i64 {
        self.0 as i64
    }

    fn next(self) -> Result<Self, PendingQueueArtifactError> {
        Self::try_new(
            self.0
                .checked_add(1)
                .ok_or(PendingQueueArtifactError::RevisionOverflow)?,
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingQueueArtifactBatchIndex(u32);

impl PendingQueueArtifactBatchIndex {
    pub const fn try_new(value: u32) -> Result<Self, PendingQueueArtifactError> {
        if value >= MAX_PENDING_QUEUE_ARTIFACT_BATCHES {
            Err(PendingQueueArtifactError::BatchIndexOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PendingQueueArtifactFragmentIndex(u64);

impl PendingQueueArtifactFragmentIndex {
    pub const fn try_new(value: u64) -> Result<Self, PendingQueueArtifactError> {
        let maximum = MAX_PENDING_QUEUE_ARTIFACT_BATCHES as u64
            * MAX_PENDING_QUEUE_CANDIDATE_FRAGMENTS as u64;
        if value >= maximum || value > i64::MAX as u64 {
            Err(PendingQueueArtifactError::FragmentIndexOutOfRange(value))
        } else {
            Ok(Self(value))
        }
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    pub const fn bucket(self) -> u64 {
        self.0 / PENDING_QUEUE_ARTIFACT_FRAGMENTS_PER_BUCKET
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactBatchDescriptor {
    batch_index: PendingQueueArtifactBatchIndex,
    first_fragment_index: PendingQueueArtifactFragmentIndex,
    fragment_count: u16,
    canonical_bytes: u64,
    item_count: u64,
    payload_bytes: u64,
    candidate_digest: PendingQueueCandidateDigest,
    batch_digest: PendingQueueBatchDigest,
    payload_digest: PendingQueuePayloadDigest,
}

impl PendingQueueArtifactBatchDescriptor {
    pub const fn batch_index(&self) -> PendingQueueArtifactBatchIndex {
        self.batch_index
    }

    pub const fn first_fragment_index(&self) -> PendingQueueArtifactFragmentIndex {
        self.first_fragment_index
    }

    pub const fn fragment_count(&self) -> u16 {
        self.fragment_count
    }

    pub const fn canonical_bytes(&self) -> u64 {
        self.canonical_bytes
    }

    pub const fn item_count(&self) -> u64 {
        self.item_count
    }

    pub const fn payload_bytes(&self) -> u64 {
        self.payload_bytes
    }

    pub const fn candidate_digest(&self) -> PendingQueueCandidateDigest {
        self.candidate_digest
    }

    pub const fn batch_digest(&self) -> PendingQueueBatchDigest {
        self.batch_digest
    }

    pub const fn payload_digest(&self) -> PendingQueuePayloadDigest {
        self.payload_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactProgress {
    next_batch_index: u32,
    next_fragment_index: u64,
    selected_item_count: u64,
    selected_payload_bytes: u64,
    selected_canonical_bytes: u64,
    dataset_digest: PendingQueueDatasetDigest,
    coverage_digest: PendingQueueCoverageDigest,
    last_selected: Option<PendingQueueArtifactBatchDescriptor>,
}

impl PendingQueueArtifactProgress {
    fn initial(identity: &PendingQueueArtifactIdentity) -> Self {
        let dataset_digest = PendingQueueDatasetDigest(hash_parts(&[
            DATASET_INITIAL_DOMAIN,
            identity.digest().as_bytes(),
        ]));
        let coverage_digest = PendingQueueCoverageDigest(hash_parts(&[
            COVERAGE_INITIAL_DOMAIN,
            identity.digest().as_bytes(),
        ]));
        Self {
            next_batch_index: 0,
            next_fragment_index: 0,
            selected_item_count: 0,
            selected_payload_bytes: 0,
            selected_canonical_bytes: 0,
            dataset_digest,
            coverage_digest,
            last_selected: None,
        }
    }

    fn advance(
        &self,
        descriptor: &PendingQueueArtifactBatchDescriptor,
    ) -> Result<Self, PendingQueueArtifactError> {
        if descriptor.batch_index.get() != self.next_batch_index
            || descriptor.first_fragment_index.get() != self.next_fragment_index
        {
            return Err(PendingQueueArtifactError::NonContiguousDescriptor);
        }
        let next_batch_index = self
            .next_batch_index
            .checked_add(1)
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        if next_batch_index > MAX_PENDING_QUEUE_ARTIFACT_BATCHES {
            return Err(PendingQueueArtifactError::TooManyBatches);
        }
        let next_fragment_index = self
            .next_fragment_index
            .checked_add(u64::from(descriptor.fragment_count))
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        let maximum_fragments = MAX_PENDING_QUEUE_ARTIFACT_BATCHES as u64
            * MAX_PENDING_QUEUE_CANDIDATE_FRAGMENTS as u64;
        if next_fragment_index > maximum_fragments {
            return Err(PendingQueueArtifactError::TooManyFragments);
        }
        let selected_item_count = self
            .selected_item_count
            .checked_add(descriptor.item_count)
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        let selected_payload_bytes = self
            .selected_payload_bytes
            .checked_add(descriptor.payload_bytes)
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        let selected_canonical_bytes = self
            .selected_canonical_bytes
            .checked_add(descriptor.canonical_bytes)
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        if selected_canonical_bytes > MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES {
            return Err(PendingQueueArtifactError::ArtifactTooLarge {
                actual: selected_canonical_bytes,
                maximum: MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES,
            });
        }
        let encoded = encode_descriptor(descriptor);
        let dataset_digest = PendingQueueDatasetDigest(hash_parts(&[
            DATASET_APPEND_DOMAIN,
            self.dataset_digest.as_bytes(),
            &encoded,
        ]));
        let coverage_digest = PendingQueueCoverageDigest(hash_parts(&[
            COVERAGE_APPEND_DOMAIN,
            self.coverage_digest.as_bytes(),
            &descriptor.batch_index.get().to_be_bytes(),
            descriptor.batch_digest.as_bytes(),
        ]));
        Ok(Self {
            next_batch_index,
            next_fragment_index,
            selected_item_count,
            selected_payload_bytes,
            selected_canonical_bytes,
            dataset_digest,
            coverage_digest,
            last_selected: Some(descriptor.clone()),
        })
    }

    pub const fn next_batch_index(&self) -> u32 {
        self.next_batch_index
    }

    pub const fn next_fragment_index(&self) -> u64 {
        self.next_fragment_index
    }

    pub const fn selected_item_count(&self) -> u64 {
        self.selected_item_count
    }

    pub const fn selected_payload_bytes(&self) -> u64 {
        self.selected_payload_bytes
    }

    pub const fn selected_canonical_bytes(&self) -> u64 {
        self.selected_canonical_bytes
    }

    pub const fn dataset_digest(&self) -> PendingQueueDatasetDigest {
        self.dataset_digest
    }

    pub const fn coverage_digest(&self) -> PendingQueueCoverageDigest {
        self.coverage_digest
    }

    pub const fn last_selected(&self) -> Option<&PendingQueueArtifactBatchDescriptor> {
        self.last_selected.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueArtifactPhase {
    Open(PendingQueueArtifactProgress),
    AppendPrepared {
        before: PendingQueueArtifactProgress,
        descriptor: PendingQueueArtifactBatchDescriptor,
    },
    SelectedAwaitingAck {
        before: PendingQueueArtifactProgress,
        after: PendingQueueArtifactProgress,
        descriptor: PendingQueueArtifactBatchDescriptor,
    },
    CloseObserved {
        progress: PendingQueueArtifactProgress,
        boundary: PendingQueueGenerationBoundary,
    },
    /// All rows for this one source slot were structurally scanned. This is
    /// not a terminal generation seal: c2/c3 must still prove the concrete
    /// backend fence and the configured expected-source set.
    SourceScanned {
        progress: PendingQueueArtifactProgress,
        boundary: PendingQueueGenerationBoundary,
        scan_digest: PendingQueueArtifactScanDigest,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredPendingQueueArtifact {
    slot: PendingQueueArtifactSlot,
    identity: PendingQueueArtifactIdentity,
    revision: PendingQueueArtifactRevision,
    phase: PendingQueueArtifactPhase,
}

impl StoredPendingQueueArtifact {
    pub const fn slot(&self) -> PendingQueueArtifactSlot {
        self.slot
    }

    pub const fn identity(&self) -> &PendingQueueArtifactIdentity {
        &self.identity
    }

    pub const fn revision(&self) -> PendingQueueArtifactRevision {
        self.revision
    }

    pub const fn phase(&self) -> &PendingQueueArtifactPhase {
        &self.phase
    }

    pub fn to_persisted_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(b"PSYQARTF");
        out.extend_from_slice(&PENDING_QUEUE_ARTIFACT_CODEC_VERSION.to_be_bytes());
        out.extend_from_slice(self.slot.as_bytes());
        let identity = self.identity.to_canonical_bytes();
        out.extend_from_slice(&(identity.len() as u32).to_be_bytes());
        out.extend_from_slice(&identity);
        out.extend_from_slice(&self.revision.get().to_be_bytes());
        match &self.phase {
            PendingQueueArtifactPhase::Open(progress) => {
                out.push(1);
                encode_progress(progress, &mut out);
            }
            PendingQueueArtifactPhase::AppendPrepared { before, descriptor } => {
                out.push(2);
                encode_progress(before, &mut out);
                encode_descriptor_into(descriptor, &mut out);
            }
            PendingQueueArtifactPhase::SelectedAwaitingAck {
                before,
                after,
                descriptor,
            } => {
                out.push(3);
                encode_progress(before, &mut out);
                encode_progress(after, &mut out);
                encode_descriptor_into(descriptor, &mut out);
            }
            PendingQueueArtifactPhase::CloseObserved { progress, boundary } => {
                out.push(4);
                encode_progress(progress, &mut out);
                encode_sized(&boundary.to_canonical_bytes(), &mut out);
            }
            PendingQueueArtifactPhase::SourceScanned {
                progress,
                boundary,
                scan_digest,
            } => {
                out.push(5);
                encode_progress(progress, &mut out);
                encode_sized(&boundary.to_canonical_bytes(), &mut out);
                out.extend_from_slice(scan_digest.as_bytes());
            }
        }
        out
    }

    pub fn decode_persisted(
        partition_slot: PendingQueueArtifactSlot,
        revision_column: i64,
        bytes: &[u8],
    ) -> Result<Self, PendingQueueArtifactError> {
        if bytes.len() > MAX_PENDING_QUEUE_ARTIFACT_HEADER_BYTES {
            return Err(PendingQueueArtifactError::HeaderTooLarge(bytes.len()));
        }
        let mut decoder = Decoder::new(bytes);
        if decoder.take(8)? != b"PSYQARTF" {
            return Err(PendingQueueArtifactError::InvalidMagic);
        }
        let version = decoder.u16()?;
        if version != PENDING_QUEUE_ARTIFACT_CODEC_VERSION {
            return Err(PendingQueueArtifactError::UnknownCodecVersion(version));
        }
        let encoded_slot = PendingQueueArtifactSlot::try_new(decoder.array32()?)?;
        if encoded_slot != partition_slot {
            return Err(PendingQueueArtifactError::PartitionSlotMismatch);
        }
        let identity = PendingQueueArtifactIdentity::decode_canonical(decoder.sized()?)
            .map_err(|error| PendingQueueArtifactError::CaptureModel(error.to_string()))?;
        if slot_for(&identity) != partition_slot {
            return Err(PendingQueueArtifactError::IdentitySlotMismatch);
        }
        let revision = PendingQueueArtifactRevision::try_new(decoder.u64()?)?;
        if revision.as_i64() != revision_column {
            return Err(PendingQueueArtifactError::RevisionColumnMismatch);
        }
        let phase = match decoder.u8()? {
            1 => PendingQueueArtifactPhase::Open(decode_progress(&mut decoder)?),
            2 => {
                let before = decode_progress(&mut decoder)?;
                let descriptor = decode_descriptor(&mut decoder)?;
                before.advance(&descriptor)?;
                PendingQueueArtifactPhase::AppendPrepared { before, descriptor }
            }
            3 => {
                let before = decode_progress(&mut decoder)?;
                let after = decode_progress(&mut decoder)?;
                let descriptor = decode_descriptor(&mut decoder)?;
                if before.advance(&descriptor)? != after {
                    return Err(PendingQueueArtifactError::SelectedProgressMismatch);
                }
                PendingQueueArtifactPhase::SelectedAwaitingAck {
                    before,
                    after,
                    descriptor,
                }
            }
            tag @ (4 | 5) => {
                let progress = decode_progress(&mut decoder)?;
                let boundary = PendingQueueGenerationBoundary::decode_canonical(decoder.sized()?)
                    .map_err(|error| PendingQueueArtifactError::CaptureModel(error.to_string()))?;
                verify_boundary_identity(&identity, &boundary)?;
                if tag == 4 {
                    PendingQueueArtifactPhase::CloseObserved { progress, boundary }
                } else {
                    let scan_digest = PendingQueueArtifactScanDigest::try_new(decoder.array32()?)?;
                    PendingQueueArtifactPhase::SourceScanned {
                        progress,
                        boundary,
                        scan_digest,
                    }
                }
            }
            value => return Err(PendingQueueArtifactError::UnknownPhase(value)),
        };
        validate_zero_progress(&identity, &phase)?;
        if !decoder.is_done() {
            return Err(PendingQueueArtifactError::TrailingBytes);
        }
        Ok(Self {
            slot: partition_slot,
            identity,
            revision,
            phase,
        })
    }
}

fn validate_zero_progress(
    identity: &PendingQueueArtifactIdentity,
    phase: &PendingQueueArtifactPhase,
) -> Result<(), PendingQueueArtifactError> {
    let progress = match phase {
        PendingQueueArtifactPhase::Open(progress)
        | PendingQueueArtifactPhase::CloseObserved { progress, .. }
        | PendingQueueArtifactPhase::SourceScanned { progress, .. } => progress,
        PendingQueueArtifactPhase::AppendPrepared { before, .. }
        | PendingQueueArtifactPhase::SelectedAwaitingAck { before, .. } => before,
    };
    if progress.next_batch_index == 0
        && progress != &PendingQueueArtifactProgress::initial(identity)
    {
        return Err(PendingQueueArtifactError::InvalidInitialProgress);
    }
    Ok(())
}

/// Explicit bootstrap. Missing durable state is never inferred from queue data.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactBootstrap {
    candidate: StoredPendingQueueArtifact,
    payload: Vec<u8>,
}

impl PendingQueueArtifactBootstrap {
    pub fn try_new(
        identity: PendingQueueArtifactIdentity,
    ) -> Result<Self, PendingQueueArtifactError> {
        let candidate = StoredPendingQueueArtifact {
            slot: slot_for(&identity),
            phase: PendingQueueArtifactPhase::Open(PendingQueueArtifactProgress::initial(
                &identity,
            )),
            identity,
            revision: PendingQueueArtifactRevision::try_new(1)?,
        };
        let payload = candidate.to_persisted_bytes();
        Ok(Self { candidate, payload })
    }

    pub const fn candidate(&self) -> &StoredPendingQueueArtifact {
        &self.candidate
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactFragment {
    global_index: PendingQueueArtifactFragmentIndex,
    batch_index: PendingQueueArtifactBatchIndex,
    batch_fragment_index: u16,
    batch_fragment_count: u16,
    candidate_digest: PendingQueueCandidateDigest,
    candidate_bytes: u64,
    payload: Vec<u8>,
    payload_digest: PendingQueueFragmentDigest,
}

impl PendingQueueArtifactFragment {
    pub fn try_from_parts(
        global_index: u64,
        batch_index: u32,
        batch_fragment_index: u16,
        batch_fragment_count: u16,
        candidate_digest: PendingQueueCandidateDigest,
        candidate_bytes: u64,
        payload: Vec<u8>,
        persisted_payload_digest: PendingQueueFragmentDigest,
    ) -> Result<Self, PendingQueueArtifactError> {
        if batch_fragment_count == 0
            || batch_fragment_index >= batch_fragment_count
            || payload.is_empty()
            || payload.len() > PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES
        {
            return Err(PendingQueueArtifactError::InvalidFragmentShape);
        }
        if candidate_bytes == 0
            || candidate_bytes > MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES
        {
            return Err(PendingQueueArtifactError::InvalidCandidateLength(
                candidate_bytes,
            ));
        }
        let global_index = PendingQueueArtifactFragmentIndex::try_new(global_index)?;
        let batch_index = PendingQueueArtifactBatchIndex::try_new(batch_index)?;
        let computed = fragment_digest(
            global_index,
            batch_index,
            batch_fragment_index,
            batch_fragment_count,
            candidate_digest,
            candidate_bytes,
            &payload,
        );
        if computed != persisted_payload_digest {
            return Err(PendingQueueArtifactError::FragmentDigestMismatch);
        }
        Ok(Self {
            global_index,
            batch_index,
            batch_fragment_index,
            batch_fragment_count,
            candidate_digest,
            candidate_bytes,
            payload,
            payload_digest: persisted_payload_digest,
        })
    }

    pub const fn global_index(&self) -> PendingQueueArtifactFragmentIndex {
        self.global_index
    }

    pub const fn batch_index(&self) -> PendingQueueArtifactBatchIndex {
        self.batch_index
    }

    pub const fn batch_fragment_index(&self) -> u16 {
        self.batch_fragment_index
    }

    pub const fn batch_fragment_count(&self) -> u16 {
        self.batch_fragment_count
    }

    pub const fn candidate_digest(&self) -> PendingQueueCandidateDigest {
        self.candidate_digest
    }

    pub const fn candidate_bytes(&self) -> u64 {
        self.candidate_bytes
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub const fn payload_digest(&self) -> PendingQueueFragmentDigest {
        self.payload_digest
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactAppendPlan {
    expected_open: StoredPendingQueueArtifact,
    prepared: StoredPendingQueueArtifact,
    selected: StoredPendingQueueArtifact,
    descriptor: PendingQueueArtifactBatchDescriptor,
    fragments: Vec<PendingQueueArtifactFragment>,
}

impl PendingQueueArtifactAppendPlan {
    pub fn try_new(
        expected_open: &StoredPendingQueueArtifact,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::Open(before) = &expected_open.phase else {
            return Err(PendingQueueArtifactError::ExpectedOpen);
        };
        verify_candidate_identity(&expected_open.identity, candidate)?;
        if before.next_batch_index >= MAX_PENDING_QUEUE_ARTIFACT_BATCHES {
            return Err(PendingQueueArtifactError::TooManyBatches);
        }
        let canonical = candidate.to_canonical_bytes();
        let canonical_bytes = canonical.len() as u64;
        if canonical_bytes > MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES {
            return Err(PendingQueueArtifactError::InvalidCandidateLength(
                canonical_bytes,
            ));
        }
        let selected_total = before
            .selected_canonical_bytes
            .checked_add(canonical_bytes)
            .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
        if selected_total > MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES {
            return Err(PendingQueueArtifactError::ArtifactTooLarge {
                actual: selected_total,
                maximum: MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES,
            });
        }
        let fragment_count_usize = canonical.len().div_ceil(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES);
        let fragment_count = u16::try_from(fragment_count_usize)
            .map_err(|_| PendingQueueArtifactError::TooManyFragments)?;
        let candidate_digest = PendingQueueCandidateDigest(hash_parts(&[
            CANDIDATE_DOMAIN,
            &canonical,
        ]));
        let descriptor = PendingQueueArtifactBatchDescriptor {
            batch_index: PendingQueueArtifactBatchIndex::try_new(before.next_batch_index)?,
            first_fragment_index: PendingQueueArtifactFragmentIndex::try_new(
                before.next_fragment_index,
            )?,
            fragment_count,
            canonical_bytes,
            item_count: candidate.item_count(),
            payload_bytes: candidate.total_payload_bytes() as u64,
            candidate_digest,
            batch_digest: candidate.batch_digest(),
            payload_digest: candidate.payload_digest(),
        };
        let after = before.advance(&descriptor)?;
        let prepared = StoredPendingQueueArtifact {
            slot: expected_open.slot,
            identity: expected_open.identity.clone(),
            revision: expected_open.revision.next()?,
            phase: PendingQueueArtifactPhase::AppendPrepared {
                before: before.clone(),
                descriptor: descriptor.clone(),
            },
        };
        let selected = StoredPendingQueueArtifact {
            slot: expected_open.slot,
            identity: expected_open.identity.clone(),
            revision: prepared.revision.next()?,
            phase: PendingQueueArtifactPhase::SelectedAwaitingAck {
                before: before.clone(),
                after,
                descriptor: descriptor.clone(),
            },
        };
        let fragments = canonical
            .chunks(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES)
            .enumerate()
            .map(|(offset, payload)| {
                let global = descriptor
                    .first_fragment_index
                    .get()
                    .checked_add(offset as u64)
                    .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
                let global_index = PendingQueueArtifactFragmentIndex::try_new(global)?;
                let batch_fragment_index = u16::try_from(offset)
                    .map_err(|_| PendingQueueArtifactError::TooManyFragments)?;
                let payload = payload.to_vec();
                let payload_digest = fragment_digest(
                    global_index,
                    descriptor.batch_index,
                    batch_fragment_index,
                    fragment_count,
                    candidate_digest,
                    canonical_bytes,
                    &payload,
                );
                Ok(PendingQueueArtifactFragment {
                    global_index,
                    batch_index: descriptor.batch_index,
                    batch_fragment_index,
                    batch_fragment_count: fragment_count,
                    candidate_digest,
                    candidate_bytes: canonical_bytes,
                    payload,
                    payload_digest,
                })
            })
            .collect::<Result<Vec<_>, PendingQueueArtifactError>>()?;
        Ok(Self {
            expected_open: expected_open.clone(),
            prepared,
            selected,
            descriptor,
            fragments,
        })
    }

    pub fn try_resume(
        current_prepared: &StoredPendingQueueArtifact,
        candidate: &PendingQueueCaptureCandidate,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::AppendPrepared { before, .. } =
            &current_prepared.phase
        else {
            return Err(PendingQueueArtifactError::ExpectedAppendPrepared);
        };
        let previous_revision = current_prepared
            .revision
            .get()
            .checked_sub(1)
            .ok_or(PendingQueueArtifactError::RevisionOverflow)?;
        let expected_open = StoredPendingQueueArtifact {
            slot: current_prepared.slot,
            identity: current_prepared.identity.clone(),
            revision: PendingQueueArtifactRevision::try_new(previous_revision)?,
            phase: PendingQueueArtifactPhase::Open(before.clone()),
        };
        let plan = Self::try_new(&expected_open, candidate)?;
        if &plan.prepared != current_prepared {
            return Err(PendingQueueArtifactError::PreparedCandidateConflict);
        }
        Ok(plan)
    }

    pub const fn expected_open(&self) -> &StoredPendingQueueArtifact {
        &self.expected_open
    }

    pub const fn prepared(&self) -> &StoredPendingQueueArtifact {
        &self.prepared
    }

    pub const fn selected(&self) -> &StoredPendingQueueArtifact {
        &self.selected
    }

    pub const fn descriptor(&self) -> &PendingQueueArtifactBatchDescriptor {
        &self.descriptor
    }

    pub fn fragments(&self) -> &[PendingQueueArtifactFragment] {
        &self.fragments
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedPendingQueueArtifactTransition {
    expected: StoredPendingQueueArtifact,
    candidate: StoredPendingQueueArtifact,
    expected_payload: Vec<u8>,
    candidate_payload: Vec<u8>,
}

impl SealedPendingQueueArtifactTransition {
    fn new(
        expected: StoredPendingQueueArtifact,
        candidate: StoredPendingQueueArtifact,
    ) -> Self {
        let expected_payload = expected.to_persisted_bytes();
        let candidate_payload = candidate.to_persisted_bytes();
        Self {
            expected,
            candidate,
            expected_payload,
            candidate_payload,
        }
    }

    /// Computes the post-ACK header payload only. It does not perform or prove
    /// a backend ACK. A concrete composition may apply it only after consuming
    /// its backend-private token with the matching opaque Scylla readback
    /// receipt; the Scylla adapter must not expose a generic transition CAS.
    pub fn confirm_selected_ack(
        selected: &StoredPendingQueueArtifact,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::SelectedAwaitingAck { after, .. } = &selected.phase else {
            return Err(PendingQueueArtifactError::ExpectedSelectedAwaitingAck);
        };
        let candidate = StoredPendingQueueArtifact {
            slot: selected.slot,
            identity: selected.identity.clone(),
            revision: selected.revision.next()?,
            phase: PendingQueueArtifactPhase::Open(after.clone()),
        };
        Ok(Self::new(selected.clone(), candidate))
    }

    pub fn observe_close(
        open: &StoredPendingQueueArtifact,
        boundary: PendingQueueGenerationBoundary,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::Open(progress) = &open.phase else {
            return Err(PendingQueueArtifactError::ExpectedOpen);
        };
        verify_boundary_identity(&open.identity, &boundary)?;
        let candidate = StoredPendingQueueArtifact {
            slot: open.slot,
            identity: open.identity.clone(),
            revision: open.revision.next()?,
            phase: PendingQueueArtifactPhase::CloseObserved {
                progress: progress.clone(),
                boundary,
            },
        };
        Ok(Self::new(open.clone(), candidate))
    }

    /// Builds a structural per-source scan transition. The concrete Scylla
    /// adapter must not expose a generic transition executor: it may apply
    /// this plan only after exhaustive legal-bucket enumeration and exact
    /// row readback. This plan never authorizes backend ACK or generation
    /// terminal publication.
    pub fn record_source_scan(
        close_observed: &StoredPendingQueueArtifact,
        observation: &PendingQueueArtifactScanObservation,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::CloseObserved { progress, boundary } =
            &close_observed.phase
        else {
            return Err(PendingQueueArtifactError::ExpectedCloseObserved);
        };
        if observation.slot != close_observed.slot
            || observation.close_revision != close_observed.revision
            || observation.dataset_digest != progress.dataset_digest
            || observation.boundary_digest != *boundary.digest().as_bytes()
        {
            return Err(PendingQueueArtifactError::ScanObservationMismatch);
        }
        let candidate = StoredPendingQueueArtifact {
            slot: close_observed.slot,
            identity: close_observed.identity.clone(),
            revision: close_observed.revision.next()?,
            phase: PendingQueueArtifactPhase::SourceScanned {
                progress: progress.clone(),
                boundary: boundary.clone(),
                scan_digest: observation.scan_digest,
            },
        };
        Ok(Self::new(close_observed.clone(), candidate))
    }

    pub const fn expected(&self) -> &StoredPendingQueueArtifact {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredPendingQueueArtifact {
        &self.candidate
    }

    pub fn expected_payload(&self) -> &[u8] {
        &self.expected_payload
    }

    pub fn candidate_payload(&self) -> &[u8] {
        &self.candidate_payload
    }
}

/// Structural result of scanning rows supplied by a concrete store.  It is not
/// a trusted backend close receipt; c1b keeps the durable receipt constructor
/// private and c2 must combine it with a linearizable source fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingQueueArtifactScanObservation {
    slot: PendingQueueArtifactSlot,
    close_revision: PendingQueueArtifactRevision,
    dataset_digest: PendingQueueDatasetDigest,
    boundary_digest: [u8; 32],
    scan_digest: PendingQueueArtifactScanDigest,
}

impl PendingQueueArtifactScanObservation {
    pub fn verify(
        close_observed: &StoredPendingQueueArtifact,
        mut fragments: Vec<PendingQueueArtifactFragment>,
    ) -> Result<Self, PendingQueueArtifactError> {
        let PendingQueueArtifactPhase::CloseObserved { progress, boundary } =
            &close_observed.phase
        else {
            return Err(PendingQueueArtifactError::ExpectedCloseObserved);
        };
        fragments.sort_by_key(|fragment| {
            (
                fragment.global_index,
                fragment.candidate_digest.0,
                fragment.batch_fragment_index,
            )
        });
        if fragments.len() as u64 != progress.next_fragment_index {
            return Err(PendingQueueArtifactError::FragmentSetCardinality {
                expected: progress.next_fragment_index,
                actual: fragments.len() as u64,
            });
        }
        let mut rebuilt_progress = PendingQueueArtifactProgress::initial(
            &close_observed.identity,
        );
        let mut offset = 0usize;
        let mut nats_last = None;
        let mut staged_generation = None;
        let mut staged_last_revision = 0u64;
        let mut staged_captures = BTreeSet::new();
        while offset < fragments.len() {
            let first = &fragments[offset];
            if first.global_index.get() != rebuilt_progress.next_fragment_index
                || first.batch_index.get() != rebuilt_progress.next_batch_index
                || first.batch_fragment_index != 0
            {
                return Err(PendingQueueArtifactError::NonContiguousFragmentSet);
            }
            let count = usize::from(first.batch_fragment_count);
            let end = offset
                .checked_add(count)
                .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
            if end > fragments.len() {
                return Err(PendingQueueArtifactError::MissingFragment);
            }
            let group = &fragments[offset..end];
            let mut canonical = Vec::with_capacity(first.candidate_bytes as usize);
            for (fragment_offset, fragment) in group.iter().enumerate() {
                if fragment.global_index.get()
                    != first.global_index.get() + fragment_offset as u64
                    || fragment.batch_index != first.batch_index
                    || fragment.batch_fragment_index != fragment_offset as u16
                    || fragment.batch_fragment_count != first.batch_fragment_count
                    || fragment.candidate_digest != first.candidate_digest
                    || fragment.candidate_bytes != first.candidate_bytes
                {
                    return Err(PendingQueueArtifactError::FragmentMetadataMismatch);
                }
                let recomputed = fragment_digest(
                    fragment.global_index,
                    fragment.batch_index,
                    fragment.batch_fragment_index,
                    fragment.batch_fragment_count,
                    fragment.candidate_digest,
                    fragment.candidate_bytes,
                    &fragment.payload,
                );
                if recomputed != fragment.payload_digest {
                    return Err(PendingQueueArtifactError::FragmentDigestMismatch);
                }
                canonical.extend_from_slice(&fragment.payload);
            }
            if canonical.len() as u64 != first.candidate_bytes
                || PendingQueueCandidateDigest(hash_parts(&[CANDIDATE_DOMAIN, &canonical]))
                    != first.candidate_digest
            {
                return Err(PendingQueueArtifactError::CandidateReassemblyMismatch);
            }
            let candidate = PendingQueueCaptureCandidate::decode_canonical(&canonical)
                .map_err(|error| PendingQueueArtifactError::CaptureModel(error.to_string()))?;
            verify_candidate_identity(&close_observed.identity, &candidate)?;
            verify_source_sequence(
                &candidate,
                &mut nats_last,
                &mut staged_generation,
                &mut staged_last_revision,
                &mut staged_captures,
            )?;
            let rebuilt = PendingQueueArtifactAppendPlan::try_new(
                &StoredPendingQueueArtifact {
                    slot: close_observed.slot,
                    identity: close_observed.identity.clone(),
                    revision: PendingQueueArtifactRevision::try_new(1)?,
                    phase: PendingQueueArtifactPhase::Open(rebuilt_progress.clone()),
                },
                &candidate,
            )?;
            if rebuilt.descriptor != descriptor_from_fragments(first, &candidate) {
                return Err(PendingQueueArtifactError::DescriptorMismatch);
            }
            let PendingQueueArtifactPhase::SelectedAwaitingAck { after, .. } =
                rebuilt.selected.phase
            else {
                unreachable!()
            };
            rebuilt_progress = after;
            offset = end;
        }
        if rebuilt_progress != *progress {
            return Err(PendingQueueArtifactError::ProgressDigestMismatch);
        }
        verify_source_boundary(
            boundary,
            nats_last,
            staged_generation,
            staged_last_revision,
        )?;
        let scan_digest = PendingQueueArtifactScanDigest(hash_parts(&[
            SCAN_DOMAIN,
            close_observed.slot.as_bytes(),
            &close_observed.revision.get().to_be_bytes(),
            progress.dataset_digest.as_bytes(),
            progress.coverage_digest.as_bytes(),
            boundary.digest().as_bytes(),
        ]));
        Ok(Self {
            slot: close_observed.slot,
            close_revision: close_observed.revision,
            dataset_digest: progress.dataset_digest,
            boundary_digest: *boundary.digest().as_bytes(),
            scan_digest,
        })
    }

    pub const fn scan_digest(&self) -> PendingQueueArtifactScanDigest {
        self.scan_digest
    }
}

pub fn slot_for(identity: &PendingQueueArtifactIdentity) -> PendingQueueArtifactSlot {
    PendingQueueArtifactSlot(hash_parts(&[
        SLOT_DOMAIN,
        identity.context().digest().as_bytes(),
        identity.source().digest().as_bytes(),
        identity.digest().as_bytes(),
    ]))
}

fn verify_candidate_identity(
    identity: &PendingQueueArtifactIdentity,
    candidate: &PendingQueueCaptureCandidate,
) -> Result<(), PendingQueueArtifactError> {
    if candidate.artifact_identity() != identity {
        Err(PendingQueueArtifactError::CandidateIdentityMismatch)
    } else {
        Ok(())
    }
}

fn verify_boundary_identity(
    identity: &PendingQueueArtifactIdentity,
    boundary: &PendingQueueGenerationBoundary,
) -> Result<(), PendingQueueArtifactError> {
    if boundary.context() != identity.context()
        || boundary.source_identity() != identity.source()
    {
        Err(PendingQueueArtifactError::BoundaryIdentityMismatch)
    } else {
        Ok(())
    }
}

fn descriptor_from_fragments(
    first: &PendingQueueArtifactFragment,
    candidate: &PendingQueueCaptureCandidate,
) -> PendingQueueArtifactBatchDescriptor {
    PendingQueueArtifactBatchDescriptor {
        batch_index: first.batch_index,
        first_fragment_index: first.global_index,
        fragment_count: first.batch_fragment_count,
        canonical_bytes: first.candidate_bytes,
        item_count: candidate.item_count(),
        payload_bytes: candidate.total_payload_bytes() as u64,
        candidate_digest: first.candidate_digest,
        batch_digest: candidate.batch_digest(),
        payload_digest: candidate.payload_digest(),
    }
}

fn verify_source_sequence(
    candidate: &PendingQueueCaptureCandidate,
    nats_last: &mut Option<u64>,
    staged_generation: &mut Option<[u8; 32]>,
    staged_last_revision: &mut u64,
    staged_captures: &mut BTreeSet<[u8; 32]>,
) -> Result<(), PendingQueueArtifactError> {
    match candidate.source().view() {
        PendingQueueSourceCursorView::NatsJetStream {
            stream_sequences, ..
        } => {
            if staged_generation.is_some() {
                return Err(PendingQueueArtifactError::MixedSourceCursorKinds);
            }
            let first = *stream_sequences
                .first()
                .ok_or(PendingQueueArtifactError::EmptySourceCursor)?;
            if nats_last.is_some_and(|last| last >= first) {
                return Err(PendingQueueArtifactError::NatsSequenceOverlap);
            }
            *nats_last = stream_sequences.last().copied();
        }
        PendingQueueSourceCursorView::Staged {
            source_generation_id,
            staging_capture_id,
            source_revision,
            item_count,
            ..
        } => {
            if nats_last.is_some() {
                return Err(PendingQueueArtifactError::MixedSourceCursorKinds);
            }
            let generation = *source_generation_id;
            if staged_generation.is_some_and(|value| value != generation) {
                return Err(PendingQueueArtifactError::StagedGenerationMismatch);
            }
            *staged_generation = Some(generation);
            if !staged_captures.insert(*staging_capture_id) {
                return Err(PendingQueueArtifactError::DuplicateStagingCapture);
            }
            let expected_last = staged_last_revision
                .checked_add(item_count)
                .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
            if source_revision != expected_last {
                return Err(PendingQueueArtifactError::StagedRevisionGap {
                    expected: expected_last,
                    actual: source_revision,
                });
            }
            *staged_last_revision = source_revision;
        }
    }
    Ok(())
}

fn verify_source_boundary(
    boundary: &PendingQueueGenerationBoundary,
    nats_last: Option<u64>,
    staged_generation: Option<[u8; 32]>,
    staged_last_revision: u64,
) -> Result<(), PendingQueueArtifactError> {
    match boundary.observation() {
        PendingQueueBoundaryObservation::NatsJetStream {
            seal_marker_stream_sequence,
            last_data_stream_sequence,
            ..
        } => {
            if staged_generation.is_some()
                || nats_last.unwrap_or(0) != *last_data_stream_sequence
                || nats_last.is_some_and(|last| last >= *seal_marker_stream_sequence)
            {
                return Err(PendingQueueArtifactError::NatsBoundaryMismatch);
            }
        }
        PendingQueueBoundaryObservation::InMemory {
            source_generation_id,
            closed_source_revision,
            ..
        }
        | PendingQueueBoundaryObservation::Redis {
            source_generation_id,
            closed_source_revision,
            ..
        } => {
            if nats_last.is_some()
                || staged_generation.unwrap_or(*source_generation_id)
                    != *source_generation_id
                || staged_last_revision.checked_add(1) != Some(*closed_source_revision)
            {
                return Err(PendingQueueArtifactError::StagedBoundaryMismatch);
            }
        }
    }
    Ok(())
}

fn fragment_digest(
    global_index: PendingQueueArtifactFragmentIndex,
    batch_index: PendingQueueArtifactBatchIndex,
    batch_fragment_index: u16,
    batch_fragment_count: u16,
    candidate_digest: PendingQueueCandidateDigest,
    candidate_bytes: u64,
    payload: &[u8],
) -> PendingQueueFragmentDigest {
    PendingQueueFragmentDigest(hash_parts(&[
        FRAGMENT_DOMAIN,
        &global_index.get().to_be_bytes(),
        &batch_index.get().to_be_bytes(),
        &batch_fragment_index.to_be_bytes(),
        &batch_fragment_count.to_be_bytes(),
        candidate_digest.as_bytes(),
        &candidate_bytes.to_be_bytes(),
        &(payload.len() as u64).to_be_bytes(),
        payload,
    ]))
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    hasher.finalize().into()
}

fn encode_descriptor(descriptor: &PendingQueueArtifactBatchDescriptor) -> Vec<u8> {
    let mut out = Vec::with_capacity(160);
    encode_descriptor_into(descriptor, &mut out);
    out
}

fn encode_descriptor_into(
    descriptor: &PendingQueueArtifactBatchDescriptor,
    out: &mut Vec<u8>,
) {
    out.extend_from_slice(&descriptor.batch_index.get().to_be_bytes());
    out.extend_from_slice(&descriptor.first_fragment_index.get().to_be_bytes());
    out.extend_from_slice(&descriptor.fragment_count.to_be_bytes());
    out.extend_from_slice(&descriptor.canonical_bytes.to_be_bytes());
    out.extend_from_slice(&descriptor.item_count.to_be_bytes());
    out.extend_from_slice(&descriptor.payload_bytes.to_be_bytes());
    out.extend_from_slice(descriptor.candidate_digest.as_bytes());
    out.extend_from_slice(descriptor.batch_digest.as_bytes());
    out.extend_from_slice(descriptor.payload_digest.as_bytes());
}

fn decode_descriptor(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueArtifactBatchDescriptor, PendingQueueArtifactError> {
    let descriptor = PendingQueueArtifactBatchDescriptor {
        batch_index: PendingQueueArtifactBatchIndex::try_new(decoder.u32()?)?,
        first_fragment_index: PendingQueueArtifactFragmentIndex::try_new(decoder.u64()?)?,
        fragment_count: decoder.u16()?,
        canonical_bytes: decoder.u64()?,
        item_count: decoder.u64()?,
        payload_bytes: decoder.u64()?,
        candidate_digest: PendingQueueCandidateDigest::try_new(decoder.array32()?)?,
        batch_digest: PendingQueueBatchDigest::try_new(decoder.array32()?)
            .map_err(|error| PendingQueueArtifactError::CaptureModel(error.to_string()))?,
        payload_digest: PendingQueuePayloadDigest::try_new(decoder.array32()?)
            .map_err(|error| PendingQueueArtifactError::CaptureModel(error.to_string()))?,
    };
    if descriptor.fragment_count == 0
        || descriptor.fragment_count > MAX_PENDING_QUEUE_CANDIDATE_FRAGMENTS
        || descriptor.canonical_bytes == 0
        || descriptor.canonical_bytes > MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES
        || usize::from(descriptor.fragment_count)
            != (descriptor.canonical_bytes as usize)
                .div_ceil(PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES)
        || descriptor.item_count == 0
        || descriptor.item_count > MAX_RECOVERABLE_QUEUE_BATCH_ITEMS as u64
        || descriptor.payload_bytes == 0
        || descriptor.payload_bytes > MAX_RECOVERABLE_QUEUE_BATCH_BYTES as u64
    {
        return Err(PendingQueueArtifactError::InvalidDescriptor);
    }
    Ok(descriptor)
}

fn encode_progress(progress: &PendingQueueArtifactProgress, out: &mut Vec<u8>) {
    out.extend_from_slice(&progress.next_batch_index.to_be_bytes());
    out.extend_from_slice(&progress.next_fragment_index.to_be_bytes());
    out.extend_from_slice(&progress.selected_item_count.to_be_bytes());
    out.extend_from_slice(&progress.selected_payload_bytes.to_be_bytes());
    out.extend_from_slice(&progress.selected_canonical_bytes.to_be_bytes());
    out.extend_from_slice(progress.dataset_digest.as_bytes());
    out.extend_from_slice(progress.coverage_digest.as_bytes());
    match &progress.last_selected {
        None => out.push(0),
        Some(descriptor) => {
            out.push(1);
            encode_descriptor_into(descriptor, out);
        }
    }
}

fn decode_progress(
    decoder: &mut Decoder<'_>,
) -> Result<PendingQueueArtifactProgress, PendingQueueArtifactError> {
    let progress = PendingQueueArtifactProgress {
        next_batch_index: decoder.u32()?,
        next_fragment_index: decoder.u64()?,
        selected_item_count: decoder.u64()?,
        selected_payload_bytes: decoder.u64()?,
        selected_canonical_bytes: decoder.u64()?,
        dataset_digest: PendingQueueDatasetDigest::try_new(decoder.array32()?)?,
        coverage_digest: PendingQueueCoverageDigest::try_new(decoder.array32()?)?,
        last_selected: match decoder.u8()? {
            0 => None,
            1 => Some(decode_descriptor(decoder)?),
            value => return Err(PendingQueueArtifactError::InvalidOptionTag(value)),
        },
    };
    let maximum_selected_items = u64::from(progress.next_batch_index)
        .checked_mul(MAX_RECOVERABLE_QUEUE_BATCH_ITEMS as u64)
        .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
    let maximum_selected_payload = u64::from(progress.next_batch_index)
        .checked_mul(MAX_RECOVERABLE_QUEUE_BATCH_BYTES as u64)
        .ok_or(PendingQueueArtifactError::ProgressOverflow)?;
    let maximum_selected_canonical = u64::from(progress.next_batch_index)
        .checked_mul(MAX_PENDING_QUEUE_CANDIDATE_CANONICAL_BYTES)
        .ok_or(PendingQueueArtifactError::ProgressOverflow)?
        .min(MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES);
    if progress.next_batch_index > MAX_PENDING_QUEUE_ARTIFACT_BATCHES
        || progress.next_fragment_index
            > MAX_PENDING_QUEUE_ARTIFACT_BATCHES as u64
                * MAX_PENDING_QUEUE_CANDIDATE_FRAGMENTS as u64
        || progress.selected_canonical_bytes > MAX_PENDING_QUEUE_ARTIFACT_CANONICAL_BYTES
        || progress.selected_item_count > maximum_selected_items
        || progress.selected_payload_bytes > maximum_selected_payload
        || progress.selected_canonical_bytes > maximum_selected_canonical
        || (progress.next_batch_index == 0
            && (progress.next_fragment_index != 0
                || progress.selected_item_count != 0
                || progress.selected_payload_bytes != 0
                || progress.selected_canonical_bytes != 0
                || progress.last_selected.is_some()))
        || (progress.next_batch_index > 0
            && (progress.selected_item_count == 0
                || progress.selected_payload_bytes == 0
                || progress.selected_canonical_bytes == 0
                || progress.last_selected.as_ref().is_none_or(|descriptor| {
                    descriptor.batch_index.get() + 1 != progress.next_batch_index
                        || descriptor.first_fragment_index.get()
                            + u64::from(descriptor.fragment_count)
                            != progress.next_fragment_index
                })))
    {
        return Err(PendingQueueArtifactError::InvalidProgress);
    }
    Ok(progress)
}

fn encode_sized(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], PendingQueueArtifactError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PendingQueueArtifactError::TruncatedPayload)?;
        if end > self.bytes.len() {
            return Err(PendingQueueArtifactError::TruncatedPayload);
        }
        let result = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(result)
    }

    fn sized(&mut self) -> Result<&'a [u8], PendingQueueArtifactError> {
        let len = self.u32()? as usize;
        if len == 0 || len > MAX_PENDING_QUEUE_ARTIFACT_HEADER_COMPONENT_BYTES {
            return Err(PendingQueueArtifactError::InvalidSizedPayload(len));
        }
        self.take(len)
    }

    fn u8(&mut self) -> Result<u8, PendingQueueArtifactError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, PendingQueueArtifactError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, PendingQueueArtifactError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, PendingQueueArtifactError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], PendingQueueArtifactError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    const fn is_done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PendingQueueArtifactError {
    EmptySlotDigest,
    EmptyCandidateDigest,
    EmptyFragmentDigest,
    EmptyDatasetDigest,
    EmptyCoverageDigest,
    EmptyScanDigest,
    RevisionOutOfRange(u64),
    RevisionOverflow,
    BatchIndexOutOfRange(u32),
    FragmentIndexOutOfRange(u64),
    TooManyBatches,
    TooManyFragments,
    ProgressOverflow,
    ArtifactTooLarge { actual: u64, maximum: u64 },
    InvalidCandidateLength(u64),
    InvalidFragmentShape,
    FragmentDigestMismatch,
    NonContiguousDescriptor,
    CandidateIdentityMismatch,
    BoundaryIdentityMismatch,
    ExpectedOpen,
    ExpectedAppendPrepared,
    ExpectedSelectedAwaitingAck,
    ExpectedCloseObserved,
    PreparedCandidateConflict,
    ScanObservationMismatch,
    InvalidMagic,
    UnknownCodecVersion(u16),
    PartitionSlotMismatch,
    IdentitySlotMismatch,
    RevisionColumnMismatch,
    UnknownPhase(u8),
    InvalidOptionTag(u8),
    InvalidDescriptor,
    InvalidProgress,
    InvalidInitialProgress,
    SelectedProgressMismatch,
    TruncatedPayload,
    TrailingBytes,
    InvalidSizedPayload(usize),
    HeaderTooLarge(usize),
    CaptureModel(String),
    FragmentSetCardinality { expected: u64, actual: u64 },
    NonContiguousFragmentSet,
    MissingFragment,
    FragmentMetadataMismatch,
    CandidateReassemblyMismatch,
    DescriptorMismatch,
    ProgressDigestMismatch,
    EmptySourceCursor,
    MixedSourceCursorKinds,
    NatsSequenceOverlap,
    StagedGenerationMismatch,
    DuplicateStagingCapture,
    StagedRevisionGap { expected: u64, actual: u64 },
    NatsBoundaryMismatch,
    StagedBoundaryMismatch,
}

impl fmt::Display for PendingQueueArtifactError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for PendingQueueArtifactError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        queue::recoverable_ephemeral::{
            PendingQueueCaptureContext, PendingQueueSourceCursor,
            PendingQueueSourceIdentity,
        },
        store::{
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationContext,
                PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::PendingQueueCloseIntentDigest,
        },
    };
    use psy_data::protocol::{
        canonical_chain::NetworkId,
        chain_context::AuthorityScope,
    };

    fn context() -> PendingQueueCaptureContext {
        PendingQueueCaptureContext::try_new(
            PendingGenerationLedgerKey::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                AuthorityScope::Realm {
                    realm_id: 7,
                    realm_sub_id: 2,
                },
            ),
            PendingGenerationActivationDigest::try_new([3; 32]).unwrap(),
            PendingGenerationContext::try_from_legacy(101, 9001).unwrap(),
        )
        .unwrap()
    }

    fn source() -> PendingQueueSourceIdentity {
        PendingQueueSourceIdentity::nats_jetstream(
            "psy",
            "psy_stream",
            "psy.pq.r7.rs2.u65.qt9.g0",
        )
        .unwrap()
    }

    fn candidate(sequences: &[u64], items: &[&[u8]]) -> PendingQueueCaptureCandidate {
        PendingQueueCaptureCandidate::try_new(
            context(),
            source(),
            PendingQueueSourceCursor::nats_jetstream([4; 32], sequences).unwrap(),
            items.iter().map(|item| item.to_vec()).collect(),
        )
        .unwrap()
    }

    fn bootstrap() -> PendingQueueArtifactBootstrap {
        PendingQueueArtifactBootstrap::try_new(
            PendingQueueArtifactIdentity::try_new(context(), source()).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn bootstrap_and_header_codec_are_exact_and_strict() {
        let bootstrap = bootstrap();
        let stored = bootstrap.candidate();
        assert_eq!(stored.revision().get(), 1);
        assert!(matches!(stored.phase(), PendingQueueArtifactPhase::Open(_)));
        let header_digest: [u8; 32] = Sha256::digest(bootstrap.payload()).into();
        assert_eq!(bootstrap.payload().len(), 309);
        assert_eq!(
            stored.slot().as_bytes(),
            &[
                167, 138, 116, 1, 221, 115, 210, 238, 86, 187, 127, 236, 240, 27,
                171, 211, 159, 196, 67, 107, 218, 209, 73, 167, 31, 122, 79, 91,
                221, 113, 247, 254,
            ],
        );
        assert_eq!(
            header_digest,
            [
                76, 75, 51, 138, 50, 110, 98, 146, 182, 74, 190, 22, 112, 73, 79,
                159, 164, 67, 226, 75, 97, 149, 72, 83, 98, 91, 15, 81, 242,
                107, 158, 22,
            ],
        );
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                stored.slot(),
                stored.revision().as_i64(),
                bootstrap.payload(),
            )
            .unwrap(),
            *stored,
        );
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                PendingQueueArtifactSlot::try_new([9; 32]).unwrap(),
                stored.revision().as_i64(),
                bootstrap.payload(),
            ),
            Err(PendingQueueArtifactError::PartitionSlotMismatch),
        );
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                stored.slot(),
                2,
                bootstrap.payload(),
            ),
            Err(PendingQueueArtifactError::RevisionColumnMismatch),
        );
        let PendingQueueArtifactPhase::Open(progress) = stored.phase() else {
            unreachable!()
        };
        let mut bad_initial = bootstrap.payload().to_vec();
        let digest_offset = bad_initial
            .windows(32)
            .position(|window| window == progress.dataset_digest().as_bytes())
            .unwrap();
        bad_initial[digest_offset] ^= 1;
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                stored.slot(),
                stored.revision().as_i64(),
                &bad_initial,
            ),
            Err(PendingQueueArtifactError::InvalidInitialProgress),
        );
        let mut trailing = bootstrap.payload().to_vec();
        trailing.push(0);
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                stored.slot(),
                stored.revision().as_i64(),
                &trailing,
            ),
            Err(PendingQueueArtifactError::TrailingBytes),
        );
        assert_eq!(
            StoredPendingQueueArtifact::decode_persisted(
                stored.slot(),
                stored.revision().as_i64(),
                &vec![0; MAX_PENDING_QUEUE_ARTIFACT_HEADER_BYTES + 1],
            ),
            Err(PendingQueueArtifactError::HeaderTooLarge(
                MAX_PENDING_QUEUE_ARTIFACT_HEADER_BYTES + 1,
            )),
        );
    }

    #[test]
    fn append_is_reserved_fragmented_selected_and_ack_confirmed() {
        let open = bootstrap().candidate().clone();
        let candidate = candidate(&[10, 11], &[b"first", b"second"]);
        let plan = PendingQueueArtifactAppendPlan::try_new(&open, &candidate).unwrap();
        assert_eq!(plan.descriptor().batch_index().get(), 0);
        assert_eq!(plan.fragments().len(), 1);
        assert!(matches!(
            plan.prepared().phase(),
            PendingQueueArtifactPhase::AppendPrepared { .. }
        ));
        assert!(matches!(
            plan.selected().phase(),
            PendingQueueArtifactPhase::SelectedAwaitingAck { .. }
        ));
        assert_eq!(
            PendingQueueArtifactAppendPlan::try_resume(plan.prepared(), &candidate)
                .unwrap(),
            plan,
        );
        let ack = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan.selected(),
        )
        .unwrap();
        assert!(matches!(
            ack.candidate().phase(),
            PendingQueueArtifactPhase::Open(progress)
                if progress.next_batch_index() == 1
        ));
        assert_eq!(ack.candidate().revision().get(), 4);
    }

    #[test]
    fn large_candidate_uses_ordered_immutable_fragments() {
        let open = bootstrap().candidate().clone();
        let payload = vec![7_u8; PENDING_QUEUE_ARTIFACT_FRAGMENT_BYTES + 17];
        let candidate = candidate(&[10], &[payload.as_slice()]);
        let plan = PendingQueueArtifactAppendPlan::try_new(&open, &candidate).unwrap();
        assert_eq!(plan.fragments().len(), 2);
        assert_eq!(plan.fragments()[0].batch_fragment_index(), 0);
        assert_eq!(plan.fragments()[1].batch_fragment_index(), 1);
        assert_eq!(plan.fragments()[0].global_index().get(), 0);
        assert_eq!(plan.fragments()[1].global_index().get(), 1);
        assert_ne!(
            plan.fragments()[0].payload_digest(),
            plan.fragments()[1].payload_digest(),
        );
    }

    #[test]
    fn close_scan_reconstructs_order_and_rejects_missing_or_extra() {
        let open0 = bootstrap().candidate().clone();
        let first = candidate(&[10, 11], &[b"a", b"b"]);
        let plan0 = PendingQueueArtifactAppendPlan::try_new(&open0, &first).unwrap();
        let open1 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan0.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let second = candidate(&[12], &[b"c"]);
        let plan1 = PendingQueueArtifactAppendPlan::try_new(&open1, &second).unwrap();
        let open2 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan1.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context(),
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 13,
                last_data_stream_sequence: 12,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        let close = SealedPendingQueueArtifactTransition::observe_close(&open2, boundary)
            .unwrap();
        let mut fragments = plan0.fragments().to_vec();
        fragments.extend_from_slice(plan1.fragments());
        let observation = PendingQueueArtifactScanObservation::verify(
            close.candidate(),
            fragments.clone(),
        )
        .unwrap();
        let verified = SealedPendingQueueArtifactTransition::record_source_scan(
            close.candidate(),
            &observation,
        )
        .unwrap();
        assert!(matches!(
            verified.candidate().phase(),
            PendingQueueArtifactPhase::SourceScanned { .. }
        ));

        assert!(matches!(
            PendingQueueArtifactScanObservation::verify(
                close.candidate(),
                fragments[..fragments.len() - 1].to_vec(),
            ),
            Err(PendingQueueArtifactError::FragmentSetCardinality { .. })
        ));
        fragments.push(fragments[0].clone());
        assert!(matches!(
            PendingQueueArtifactScanObservation::verify(close.candidate(), fragments),
            Err(PendingQueueArtifactError::FragmentSetCardinality { .. })
        ));
    }

    #[test]
    fn scanner_rejects_cross_batch_overlap_and_staged_revision_gap() {
        let open0 = bootstrap().candidate().clone();
        let first = candidate(&[10], &[b"a"]);
        let plan0 = PendingQueueArtifactAppendPlan::try_new(&open0, &first).unwrap();
        let open1 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan0.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let overlap = candidate(&[10], &[b"b"]);
        let plan1 = PendingQueueArtifactAppendPlan::try_new(&open1, &overlap).unwrap();
        let open2 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan1.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context(),
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 11,
                last_data_stream_sequence: 10,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        let close = SealedPendingQueueArtifactTransition::observe_close(&open2, boundary)
            .unwrap();
        let mut fragments = plan0.fragments().to_vec();
        fragments.extend_from_slice(plan1.fragments());
        assert_eq!(
            PendingQueueArtifactScanObservation::verify(close.candidate(), fragments),
            Err(PendingQueueArtifactError::NatsSequenceOverlap),
        );
    }

    #[test]
    fn staged_scanner_requires_one_generation_and_contiguous_item_revisions() {
        let staged_source = PendingQueueSourceIdentity::redis("psy", "queue:7").unwrap();
        let identity = PendingQueueArtifactIdentity::try_new(
            context(),
            staged_source.clone(),
        )
        .unwrap();
        let open0 = PendingQueueArtifactBootstrap::try_new(identity)
            .unwrap()
            .candidate()
            .clone();
        let first = PendingQueueCaptureCandidate::try_new(
            context(),
            staged_source.clone(),
            PendingQueueSourceCursor::redis([9; 32], [1; 32], 1, 1, [5; 32])
                .unwrap(),
            vec![b"a".to_vec()],
        )
        .unwrap();
        let plan0 = PendingQueueArtifactAppendPlan::try_new(&open0, &first).unwrap();
        let open1 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan0.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let gap = PendingQueueCaptureCandidate::try_new(
            context(),
            staged_source.clone(),
            PendingQueueSourceCursor::redis([9; 32], [2; 32], 3, 1, [6; 32])
                .unwrap(),
            vec![b"b".to_vec()],
        )
        .unwrap();
        let plan1 = PendingQueueArtifactAppendPlan::try_new(&open1, &gap).unwrap();
        let open2 = SealedPendingQueueArtifactTransition::confirm_selected_ack(
            plan1.selected(),
        )
        .unwrap()
        .candidate()
        .clone();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context(),
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            staged_source,
            PendingQueueBoundaryObservation::Redis {
                source_generation_id: [9; 32],
                closed_source_revision: 4,
                seal_digest: [8; 32],
            },
        )
        .unwrap();
        let close = SealedPendingQueueArtifactTransition::observe_close(&open2, boundary)
            .unwrap();
        let mut fragments = plan0.fragments().to_vec();
        fragments.extend_from_slice(plan1.fragments());
        assert_eq!(
            PendingQueueArtifactScanObservation::verify(close.candidate(), fragments),
            Err(PendingQueueArtifactError::StagedRevisionGap {
                expected: 2,
                actual: 3,
            }),
        );
    }

    #[test]
    fn empty_artifact_requires_an_explicit_close_boundary() {
        let open = bootstrap().candidate().clone();
        let boundary = PendingQueueGenerationBoundary::try_from_backend_observation(
            context(),
            PendingQueueCloseIntentDigest::try_new([7; 32]).unwrap(),
            source(),
            PendingQueueBoundaryObservation::NatsJetStream {
                seal_marker_stream_sequence: 10,
                last_data_stream_sequence: 0,
                seal_marker_digest: [8; 32],
            },
        )
        .unwrap();
        let close = SealedPendingQueueArtifactTransition::observe_close(&open, boundary)
            .unwrap();
        PendingQueueArtifactScanObservation::verify(close.candidate(), Vec::new())
            .unwrap();
        assert_eq!(
            PendingQueueArtifactScanObservation::verify(&open, Vec::new()),
            Err(PendingQueueArtifactError::ExpectedCloseObserved),
        );
    }
}
