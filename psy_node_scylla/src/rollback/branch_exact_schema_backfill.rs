//! Typed, crash-resumable branch-exact backfill lifecycle.
//!
//! This module only authorizes and records an exact copy plus read-back
//! verification. It deliberately exposes no reader/writer cutover capability.

use std::{error::Error, fmt};

use psy_node_core::store::{
    branch_exact_schema::AuthorityScope,
    canonical_head::CanonicalHeadBootstrapProfile,
    timestamp::CommitWriteTimestampUs,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactDeploymentLifecycleError,
    BranchExactDeploymentLifecycleState, BranchExactDeploymentSlotId,
    BranchExactSchemaMaterializationRequest,
    BranchExactVerifiedDeploymentReceipt,
    StoredBranchExactDeploymentLifecycle,
};

pub(crate) const BACKFILL_PLANNED_PAYLOAD_KIND: u8 = 3;
pub(crate) const BACKFILL_PROGRESS_PAYLOAD_KIND: u8 = 4;
pub(crate) const BACKFILL_VERIFIED_PAYLOAD_KIND: u8 = 5;

const BACKFILL_CODEC_VERSION: u16 = 2;
const BACKFILL_PLAN_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-plan/v1";
const BACKFILL_EMPTY_DATASET_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-empty-dataset/v1";
const BACKFILL_PROGRESS_INITIAL_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-progress-initial/v1";
const BACKFILL_PROGRESS_STEP_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-progress-step/v1";
const BACKFILL_PROGRESS_STATE_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-progress-state/v1";
const BACKFILL_VERIFIED_RECEIPT_DOMAIN: &[u8] =
    b"psy/rollback/branch-exact-backfill-verified/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactBackfillDatasetDigest([u8; 32]);

impl BranchExactBackfillDatasetDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, BranchExactBackfillError> {
        if bytes == [0; 32] {
            Err(BranchExactBackfillError::ZeroDatasetDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    fn empty() -> Self {
        let mut hasher = Sha256::new();
        hasher.update(BACKFILL_EMPTY_DATASET_DOMAIN);
        Self(hasher.finalize().into())
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactBackfillPlanDigest([u8; 32]);

impl BranchExactBackfillPlanDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactBackfillChunkDigest([u8; 32]);

impl BranchExactBackfillChunkDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, BranchExactBackfillError> {
        if bytes == [0; 32] {
            Err(BranchExactBackfillError::ZeroChunkDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactBackfillProgressDigest([u8; 32]);

impl BranchExactBackfillProgressDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BranchExactBackfillReceiptDigest([u8; 32]);

impl BranchExactBackfillReceiptDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BranchExactBackfillMode {
    GenesisEmpty = 1,
    PostGenesisArtifact = 2,
}

impl TryFrom<u8> for BranchExactBackfillMode {
    type Error = BranchExactBackfillError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::GenesisEmpty),
            2 => Ok(Self::PostGenesisArtifact),
            value => Err(BranchExactBackfillError::UnknownBackfillMode(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillPlan {
    deployment: BranchExactVerifiedDeploymentReceipt,
    mode: BranchExactBackfillMode,
    dataset_digest: BranchExactBackfillDatasetDigest,
    write_timestamp: Option<CommitWriteTimestampUs>,
    total_chunks: u32,
    pair_rows_per_direction: u64,
    proof_rows: u64,
    digest: BranchExactBackfillPlanDigest,
}

impl BranchExactBackfillPlan {
    pub fn genesis_empty(
        request: &BranchExactSchemaMaterializationRequest,
        deployment: BranchExactVerifiedDeploymentReceipt,
    ) -> Result<Self, BranchExactBackfillError> {
        Self::try_from_parts(
            request,
            deployment,
            BranchExactBackfillMode::GenesisEmpty,
            BranchExactBackfillDatasetDigest::empty(),
            None,
            0,
            0,
            0,
        )
    }

    pub fn post_genesis_artifact(
        request: &BranchExactSchemaMaterializationRequest,
        deployment: BranchExactVerifiedDeploymentReceipt,
        dataset_digest: BranchExactBackfillDatasetDigest,
        write_timestamp: CommitWriteTimestampUs,
        total_chunks: u32,
        pair_rows_per_direction: u64,
        proof_rows: u64,
    ) -> Result<Self, BranchExactBackfillError> {
        Self::try_from_parts(
            request,
            deployment,
            BranchExactBackfillMode::PostGenesisArtifact,
            dataset_digest,
            Some(write_timestamp),
            total_chunks,
            pair_rows_per_direction,
            proof_rows,
        )
    }

    fn try_from_parts(
        request: &BranchExactSchemaMaterializationRequest,
        deployment: BranchExactVerifiedDeploymentReceipt,
        mode: BranchExactBackfillMode,
        dataset_digest: BranchExactBackfillDatasetDigest,
        write_timestamp: Option<CommitWriteTimestampUs>,
        total_chunks: u32,
        pair_rows_per_direction: u64,
        proof_rows: u64,
    ) -> Result<Self, BranchExactBackfillError> {
        if !deployment.intent().matches_request(request) {
            return Err(BranchExactBackfillError::DeploymentRequestMismatch);
        }
        let plan = Self::from_decoded_parts(
            deployment,
            mode,
            dataset_digest,
            write_timestamp,
            total_chunks,
            pair_rows_per_direction,
            proof_rows,
        )?;
        if request.plan().profile()
            == CanonicalHeadBootstrapProfile::PostGenesisFloor
            && request.plan().floor_evidence().is_none()
        {
            return Err(BranchExactBackfillError::MissingFloorEvidence);
        }
        Ok(plan)
    }

    fn from_decoded_parts(
        deployment: BranchExactVerifiedDeploymentReceipt,
        mode: BranchExactBackfillMode,
        dataset_digest: BranchExactBackfillDatasetDigest,
        write_timestamp: Option<CommitWriteTimestampUs>,
        total_chunks: u32,
        pair_rows_per_direction: u64,
        proof_rows: u64,
    ) -> Result<Self, BranchExactBackfillError> {
        let profile = deployment.intent().profile();
        match (mode, profile) {
            (
                BranchExactBackfillMode::GenesisEmpty,
                CanonicalHeadBootstrapProfile::GenesisNative,
            ) => {
                if total_chunks != 0
                    || pair_rows_per_direction != 0
                    || proof_rows != 0
                    || dataset_digest != BranchExactBackfillDatasetDigest::empty()
                    || write_timestamp.is_some()
                {
                    return Err(BranchExactBackfillError::GenesisMustBeEmpty);
                }
            }
            (
                BranchExactBackfillMode::PostGenesisArtifact,
                CanonicalHeadBootstrapProfile::PostGenesisFloor,
            ) => {
                if total_chunks == 0
                    || pair_rows_per_direction == 0
                    || write_timestamp.is_none()
                {
                    return Err(BranchExactBackfillError::EmptyPostGenesisBackfill);
                }
                if u64::from(total_chunks) > pair_rows_per_direction {
                    return Err(BranchExactBackfillError::TooManyChunksForRows);
                }
            }
            _ => return Err(BranchExactBackfillError::ProfileModeMismatch),
        }
        match deployment.intent().authority() {
            AuthorityScope::Coordinator if proof_rows != 0 => {
                return Err(BranchExactBackfillError::CoordinatorProofRows)
            }
            AuthorityScope::Realm { .. }
                if proof_rows > pair_rows_per_direction =>
            {
                return Err(BranchExactBackfillError::ProofRowsExceedPairs)
            }
            _ => {}
        }
        let mut plan = Self {
            deployment,
            mode,
            dataset_digest,
            write_timestamp,
            total_chunks,
            pair_rows_per_direction,
            proof_rows,
            digest: BranchExactBackfillPlanDigest([0; 32]),
        };
        plan.digest = calculate_plan_digest(&plan);
        Ok(plan)
    }

    pub const fn deployment(&self) -> &BranchExactVerifiedDeploymentReceipt {
        &self.deployment
    }

    pub const fn mode(&self) -> BranchExactBackfillMode {
        self.mode
    }

    pub const fn dataset_digest(&self) -> BranchExactBackfillDatasetDigest {
        self.dataset_digest
    }

    pub const fn write_timestamp(&self) -> Option<CommitWriteTimestampUs> {
        self.write_timestamp
    }

    pub const fn total_chunks(&self) -> u32 {
        self.total_chunks
    }

    pub const fn pair_rows_per_direction(&self) -> u64 {
        self.pair_rows_per_direction
    }

    pub const fn proof_rows(&self) -> u64 {
        self.proof_rows
    }

    pub const fn digest(&self) -> BranchExactBackfillPlanDigest {
        self.digest
    }

    fn initial_progress_digest(&self) -> BranchExactBackfillProgressDigest {
        let mut hasher = Sha256::new();
        hasher.update(BACKFILL_PROGRESS_INITIAL_DOMAIN);
        hasher.update(self.digest.as_bytes());
        BranchExactBackfillProgressDigest(hasher.finalize().into())
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_plan(self)
    }

    pub fn decode_persisted(bytes: &[u8]) -> Result<Self, BranchExactBackfillError> {
        decode_plan(bytes)
    }
}

fn calculate_plan_digest(plan: &BranchExactBackfillPlan) -> BranchExactBackfillPlanDigest {
    let mut hasher = Sha256::new();
    hasher.update(BACKFILL_PLAN_DIGEST_DOMAIN);
    hasher.update(plan.deployment.to_canonical_bytes());
    hasher.update([plan.mode as u8]);
    hasher.update(plan.dataset_digest.as_bytes());
    match plan.write_timestamp {
        None => hasher.update([0]),
        Some(timestamp) => {
            hasher.update([1]);
            hasher.update(timestamp.as_i64().to_be_bytes());
        }
    }
    hasher.update(plan.total_chunks.to_be_bytes());
    hasher.update(plan.pair_rows_per_direction.to_be_bytes());
    hasher.update(plan.proof_rows.to_be_bytes());
    BranchExactBackfillPlanDigest(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillChunkReceipt {
    plan_digest: BranchExactBackfillPlanDigest,
    chunk_index: u32,
    pair_rows: u64,
    proof_rows: u64,
    chunk_digest: BranchExactBackfillChunkDigest,
}

impl BranchExactBackfillChunkReceipt {
    pub fn try_new(
        plan_digest: BranchExactBackfillPlanDigest,
        chunk_index: u32,
        pair_rows: u64,
        proof_rows: u64,
        chunk_digest: BranchExactBackfillChunkDigest,
    ) -> Result<Self, BranchExactBackfillError> {
        if pair_rows == 0 && proof_rows == 0 {
            return Err(BranchExactBackfillError::EmptyChunk);
        }
        Ok(Self {
            plan_digest,
            chunk_index,
            pair_rows,
            proof_rows,
            chunk_digest,
        })
    }

    pub const fn chunk_index(&self) -> u32 {
        self.chunk_index
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillProgress {
    plan: BranchExactBackfillPlan,
    next_chunk_index: u32,
    copied_pair_rows: u64,
    copied_proof_rows: u64,
    progress_digest: BranchExactBackfillProgressDigest,
}

impl BranchExactBackfillProgress {
    fn start(plan: BranchExactBackfillPlan) -> Self {
        let progress_digest = plan.initial_progress_digest();
        Self {
            plan,
            next_chunk_index: 0,
            copied_pair_rows: 0,
            copied_proof_rows: 0,
            progress_digest,
        }
    }

    fn append(
        mut self,
        chunk: BranchExactBackfillChunkReceipt,
    ) -> Result<Self, BranchExactBackfillError> {
        if chunk.plan_digest != self.plan.digest() {
            return Err(BranchExactBackfillError::ChunkPlanMismatch);
        }
        if chunk.chunk_index != self.next_chunk_index {
            return Err(BranchExactBackfillError::NonContiguousChunk {
                expected: self.next_chunk_index,
                actual: chunk.chunk_index,
            });
        }
        if self.next_chunk_index >= self.plan.total_chunks() {
            return Err(BranchExactBackfillError::AllChunksAlreadyCopied);
        }
        let copied_pair_rows = self
            .copied_pair_rows
            .checked_add(chunk.pair_rows)
            .ok_or(BranchExactBackfillError::RowCountOverflow)?;
        let copied_proof_rows = self
            .copied_proof_rows
            .checked_add(chunk.proof_rows)
            .ok_or(BranchExactBackfillError::RowCountOverflow)?;
        if copied_pair_rows > self.plan.pair_rows_per_direction()
            || copied_proof_rows > self.plan.proof_rows()
        {
            return Err(BranchExactBackfillError::ChunkCountExceedsPlan);
        }
        let next_chunk_index = self
            .next_chunk_index
            .checked_add(1)
            .ok_or(BranchExactBackfillError::ChunkIndexOverflow)?;
        let final_chunk = next_chunk_index == self.plan.total_chunks();
        let exact_counts = copied_pair_rows
            == self.plan.pair_rows_per_direction()
            && copied_proof_rows == self.plan.proof_rows();
        if final_chunk != exact_counts {
            return Err(if final_chunk {
                BranchExactBackfillError::FinalChunkCountMismatch
            } else {
                BranchExactBackfillError::CountsCompleteBeforeFinalChunk
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(BACKFILL_PROGRESS_STEP_DOMAIN);
        hasher.update(self.progress_digest.as_bytes());
        hasher.update(chunk.plan_digest.as_bytes());
        hasher.update(chunk.chunk_index.to_be_bytes());
        hasher.update(chunk.pair_rows.to_be_bytes());
        hasher.update(chunk.proof_rows.to_be_bytes());
        hasher.update(chunk.chunk_digest.as_bytes());
        self.next_chunk_index = next_chunk_index;
        self.copied_pair_rows = copied_pair_rows;
        self.copied_proof_rows = copied_proof_rows;
        self.progress_digest = BranchExactBackfillProgressDigest(hasher.finalize().into());
        Ok(self)
    }

    pub const fn plan(&self) -> &BranchExactBackfillPlan {
        &self.plan
    }

    pub const fn next_chunk_index(&self) -> u32 {
        self.next_chunk_index
    }

    pub const fn copied_pair_rows(&self) -> u64 {
        self.copied_pair_rows
    }

    pub const fn copied_proof_rows(&self) -> u64 {
        self.copied_proof_rows
    }

    pub const fn progress_digest(&self) -> BranchExactBackfillProgressDigest {
        self.progress_digest
    }

    pub const fn is_complete(&self) -> bool {
        self.next_chunk_index == self.plan.total_chunks
            && self.copied_pair_rows == self.plan.pair_rows_per_direction
            && self.copied_proof_rows == self.plan.proof_rows
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_progress(self)
    }

    pub fn decode_persisted(bytes: &[u8]) -> Result<Self, BranchExactBackfillError> {
        decode_progress(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillReadbackObservation {
    plan_digest: BranchExactBackfillPlanDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    forward_rows: u64,
    reverse_rows: u64,
    proof_rows: u64,
}

impl BranchExactBackfillReadbackObservation {
    /// Only trusted Scylla read-back adapters inside this crate may construct
    /// an observation. External deployment tooling can pass through the
    /// opaque value returned by the scanner, but cannot forge row counts.
    pub(crate) const fn new(
        plan_digest: BranchExactBackfillPlanDigest,
        dataset_digest: BranchExactBackfillDatasetDigest,
        forward_rows: u64,
        reverse_rows: u64,
        proof_rows: u64,
    ) -> Self {
        Self {
            plan_digest,
            dataset_digest,
            forward_rows,
            reverse_rows,
            proof_rows,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BranchExactBackfillVerifiedReceipt {
    plan: BranchExactBackfillPlan,
    progress_digest: BranchExactBackfillProgressDigest,
    dataset_digest: BranchExactBackfillDatasetDigest,
    forward_rows: u64,
    reverse_rows: u64,
    proof_rows: u64,
    digest: BranchExactBackfillReceiptDigest,
}

impl BranchExactBackfillVerifiedReceipt {
    fn verify(
        plan: BranchExactBackfillPlan,
        progress: Option<&BranchExactBackfillProgress>,
        observation: BranchExactBackfillReadbackObservation,
    ) -> Result<Self, BranchExactBackfillError> {
        let progress_digest = if plan.total_chunks() == 0 {
            if progress.is_some() {
                return Err(BranchExactBackfillError::UnexpectedProgressForEmptyPlan);
            }
            plan.initial_progress_digest()
        } else {
            let progress = progress.ok_or(BranchExactBackfillError::MissingCompletedProgress)?;
            if progress.plan() != &plan || !progress.is_complete() {
                return Err(BranchExactBackfillError::IncompleteProgress);
            }
            progress.progress_digest()
        };
        if observation.plan_digest != plan.digest() {
            return Err(BranchExactBackfillError::ReadbackPlanMismatch);
        }
        if observation.dataset_digest != plan.dataset_digest() {
            return Err(BranchExactBackfillError::ReadbackDatasetMismatch);
        }
        if observation.forward_rows != plan.pair_rows_per_direction()
            || observation.reverse_rows != plan.pair_rows_per_direction()
            || observation.proof_rows != plan.proof_rows()
        {
            return Err(BranchExactBackfillError::ReadbackCountMismatch);
        }
        let mut receipt = Self {
            plan,
            progress_digest,
            dataset_digest: observation.dataset_digest,
            forward_rows: observation.forward_rows,
            reverse_rows: observation.reverse_rows,
            proof_rows: observation.proof_rows,
            digest: BranchExactBackfillReceiptDigest([0; 32]),
        };
        receipt.digest = calculate_receipt_digest(&receipt);
        Ok(receipt)
    }

    pub const fn plan(&self) -> &BranchExactBackfillPlan {
        &self.plan
    }

    pub const fn progress_digest(&self) -> BranchExactBackfillProgressDigest {
        self.progress_digest
    }

    pub const fn digest(&self) -> BranchExactBackfillReceiptDigest {
        self.digest
    }

    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        encode_verified_receipt(self)
    }

    pub fn decode_persisted(bytes: &[u8]) -> Result<Self, BranchExactBackfillError> {
        decode_verified_receipt(bytes)
    }
}

fn calculate_receipt_digest(
    receipt: &BranchExactBackfillVerifiedReceipt,
) -> BranchExactBackfillReceiptDigest {
    let mut hasher = Sha256::new();
    hasher.update(BACKFILL_VERIFIED_RECEIPT_DOMAIN);
    hasher.update(receipt.plan.digest().as_bytes());
    hasher.update(receipt.progress_digest.as_bytes());
    hasher.update(receipt.dataset_digest.as_bytes());
    hasher.update(receipt.forward_rows.to_be_bytes());
    hasher.update(receipt.reverse_rows.to_be_bytes());
    hasher.update(receipt.proof_rows.to_be_bytes());
    BranchExactBackfillReceiptDigest(hasher.finalize().into())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactBackfillPlanCas {
    expected: StoredBranchExactDeploymentLifecycle,
    candidate: StoredBranchExactDeploymentLifecycle,
}

impl SealedBranchExactBackfillPlanCas {
    pub fn try_new(
        expected: &StoredBranchExactDeploymentLifecycle,
        plan: BranchExactBackfillPlan,
    ) -> Result<Self, BranchExactBackfillTransitionError> {
        let BranchExactDeploymentLifecycleState::SchemaVerified(deployment) =
            expected.state()
        else {
            return Err(BranchExactBackfillTransitionError::ExpectedSchemaVerified);
        };
        if deployment != plan.deployment() {
            return Err(BranchExactBackfillTransitionError::DeploymentMismatch);
        }
        let candidate = StoredBranchExactDeploymentLifecycle::try_new(
            expected.revision().next()?,
            BranchExactDeploymentLifecycleState::BackfillPlanned(plan),
        )?;
        Ok(Self {
            expected: expected.clone(),
            candidate,
        })
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.expected.slot()
    }

    pub const fn expected(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactBackfillChunkCas {
    expected: StoredBranchExactDeploymentLifecycle,
    candidate: StoredBranchExactDeploymentLifecycle,
}

impl SealedBranchExactBackfillChunkCas {
    pub fn try_new(
        expected: &StoredBranchExactDeploymentLifecycle,
        chunk: BranchExactBackfillChunkReceipt,
    ) -> Result<Self, BranchExactBackfillTransitionError> {
        let progress = match expected.state() {
            BranchExactDeploymentLifecycleState::BackfillPlanned(plan) => {
                BranchExactBackfillProgress::start(plan.clone()).append(chunk)?
            }
            BranchExactDeploymentLifecycleState::BackfillProgress(progress) => {
                progress.clone().append(chunk)?
            }
            _ => return Err(BranchExactBackfillTransitionError::ExpectedBackfillCopy),
        };
        let candidate = StoredBranchExactDeploymentLifecycle::try_new(
            expected.revision().next()?,
            BranchExactDeploymentLifecycleState::BackfillProgress(progress),
        )?;
        Ok(Self {
            expected: expected.clone(),
            candidate,
        })
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.expected.slot()
    }

    pub const fn expected(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.candidate
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedBranchExactBackfillVerifiedCas {
    expected: StoredBranchExactDeploymentLifecycle,
    candidate: StoredBranchExactDeploymentLifecycle,
}

impl SealedBranchExactBackfillVerifiedCas {
    pub fn try_new(
        expected: &StoredBranchExactDeploymentLifecycle,
        observation: BranchExactBackfillReadbackObservation,
    ) -> Result<Self, BranchExactBackfillTransitionError> {
        let receipt = match expected.state() {
            BranchExactDeploymentLifecycleState::BackfillPlanned(plan) => {
                BranchExactBackfillVerifiedReceipt::verify(
                    plan.clone(),
                    None,
                    observation,
                )?
            }
            BranchExactDeploymentLifecycleState::BackfillProgress(progress) => {
                BranchExactBackfillVerifiedReceipt::verify(
                    progress.plan().clone(),
                    Some(progress),
                    observation,
                )?
            }
            _ => return Err(BranchExactBackfillTransitionError::ExpectedCompletedCopy),
        };
        let candidate = StoredBranchExactDeploymentLifecycle::try_new(
            expected.revision().next()?,
            BranchExactDeploymentLifecycleState::BackfillVerified(receipt),
        )?;
        Ok(Self {
            expected: expected.clone(),
            candidate,
        })
    }

    pub const fn slot(&self) -> BranchExactDeploymentSlotId {
        self.expected.slot()
    }

    pub const fn expected(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.expected
    }

    pub const fn candidate(&self) -> &StoredBranchExactDeploymentLifecycle {
        &self.candidate
    }
}

fn encode_plan(plan: &BranchExactBackfillPlan) -> Vec<u8> {
    let deployment = plan.deployment.to_canonical_bytes();
    let mut output = Vec::with_capacity(
        2 + 1 + 4 + deployment.len() + 1 + 32 + 1 + 8 + 4 + 8 + 8 + 32,
    );
    output.extend_from_slice(&BACKFILL_CODEC_VERSION.to_be_bytes());
    output.push(BACKFILL_PLANNED_PAYLOAD_KIND);
    output.extend_from_slice(&(deployment.len() as u32).to_be_bytes());
    output.extend_from_slice(&deployment);
    output.push(plan.mode as u8);
    output.extend_from_slice(plan.dataset_digest.as_bytes());
    match plan.write_timestamp {
        None => output.push(0),
        Some(timestamp) => {
            output.push(1);
            output.extend_from_slice(&timestamp.as_i64().to_be_bytes());
        }
    }
    output.extend_from_slice(&plan.total_chunks.to_be_bytes());
    output.extend_from_slice(&plan.pair_rows_per_direction.to_be_bytes());
    output.extend_from_slice(&plan.proof_rows.to_be_bytes());
    output.extend_from_slice(plan.digest.as_bytes());
    output
}

fn decode_plan(bytes: &[u8]) -> Result<BranchExactBackfillPlan, BranchExactBackfillError> {
    let mut decoder = BackfillDecoder::new(bytes);
    decoder.expect_header(BACKFILL_PLANNED_PAYLOAD_KIND)?;
    let deployment = BranchExactVerifiedDeploymentReceipt::decode_persisted(
        decoder.len_prefixed()?,
    )?;
    let mode = BranchExactBackfillMode::try_from(decoder.u8()?)?;
    let dataset_digest = BranchExactBackfillDatasetDigest::try_new(decoder.array32()?)?;
    let write_timestamp = match decoder.u8()? {
        0 => None,
        1 => Some(CommitWriteTimestampUs::try_from_i128(
            i128::from(decoder.i64()?),
        )?),
        value => return Err(BranchExactBackfillError::InvalidTimestampPresence(value)),
    };
    let total_chunks = decoder.u32()?;
    let pair_rows_per_direction = decoder.u64()?;
    let proof_rows = decoder.u64()?;
    let persisted_digest = BranchExactBackfillPlanDigest(decoder.array32()?);
    decoder.finish()?;
    let plan = BranchExactBackfillPlan::from_decoded_parts(
        deployment,
        mode,
        dataset_digest,
        write_timestamp,
        total_chunks,
        pair_rows_per_direction,
        proof_rows,
    )?;
    if plan.digest != persisted_digest || plan.to_canonical_bytes() != bytes {
        return Err(BranchExactBackfillError::PlanDigestMismatch);
    }
    Ok(plan)
}

fn encode_progress(progress: &BranchExactBackfillProgress) -> Vec<u8> {
    let plan = progress.plan.to_canonical_bytes();
    let mut output = Vec::with_capacity(2 + 1 + 4 + plan.len() + 4 + 8 + 8 + 32 + 32);
    output.extend_from_slice(&BACKFILL_CODEC_VERSION.to_be_bytes());
    output.push(BACKFILL_PROGRESS_PAYLOAD_KIND);
    output.extend_from_slice(&(plan.len() as u32).to_be_bytes());
    output.extend_from_slice(&plan);
    output.extend_from_slice(&progress.next_chunk_index.to_be_bytes());
    output.extend_from_slice(&progress.copied_pair_rows.to_be_bytes());
    output.extend_from_slice(&progress.copied_proof_rows.to_be_bytes());
    output.extend_from_slice(progress.progress_digest.as_bytes());
    let checksum = state_checksum(&output);
    output.extend_from_slice(&checksum);
    output
}

fn decode_progress(bytes: &[u8]) -> Result<BranchExactBackfillProgress, BranchExactBackfillError> {
    let mut decoder = BackfillDecoder::new(bytes);
    decoder.expect_header(BACKFILL_PROGRESS_PAYLOAD_KIND)?;
    let plan = BranchExactBackfillPlan::decode_persisted(decoder.len_prefixed()?)?;
    let next_chunk_index = decoder.u32()?;
    let copied_pair_rows = decoder.u64()?;
    let copied_proof_rows = decoder.u64()?;
    let progress_digest = BranchExactBackfillProgressDigest(decoder.array32()?);
    let checksum_offset = decoder.offset;
    let persisted_checksum = decoder.array32()?;
    decoder.finish()?;
    if state_checksum(&bytes[..checksum_offset]) != persisted_checksum {
        return Err(BranchExactBackfillError::ProgressStateChecksumMismatch);
    }
    if next_chunk_index == 0
        || next_chunk_index > plan.total_chunks()
        || copied_pair_rows > plan.pair_rows_per_direction()
        || copied_proof_rows > plan.proof_rows()
    {
        return Err(BranchExactBackfillError::InvalidPersistedProgress);
    }
    let complete = next_chunk_index == plan.total_chunks();
    let exact_counts = copied_pair_rows == plan.pair_rows_per_direction()
        && copied_proof_rows == plan.proof_rows();
    if complete != exact_counts {
        return Err(BranchExactBackfillError::InvalidPersistedProgress);
    }
    let progress = BranchExactBackfillProgress {
        plan,
        next_chunk_index,
        copied_pair_rows,
        copied_proof_rows,
        progress_digest,
    };
    if progress.to_canonical_bytes() != bytes {
        return Err(BranchExactBackfillError::NonCanonicalPayload);
    }
    Ok(progress)
}

fn encode_verified_receipt(receipt: &BranchExactBackfillVerifiedReceipt) -> Vec<u8> {
    let plan = receipt.plan.to_canonical_bytes();
    let mut output = Vec::with_capacity(2 + 1 + 4 + plan.len() + 32 + 32 + 8 + 8 + 8 + 32);
    output.extend_from_slice(&BACKFILL_CODEC_VERSION.to_be_bytes());
    output.push(BACKFILL_VERIFIED_PAYLOAD_KIND);
    output.extend_from_slice(&(plan.len() as u32).to_be_bytes());
    output.extend_from_slice(&plan);
    output.extend_from_slice(receipt.progress_digest.as_bytes());
    output.extend_from_slice(receipt.dataset_digest.as_bytes());
    output.extend_from_slice(&receipt.forward_rows.to_be_bytes());
    output.extend_from_slice(&receipt.reverse_rows.to_be_bytes());
    output.extend_from_slice(&receipt.proof_rows.to_be_bytes());
    output.extend_from_slice(receipt.digest.as_bytes());
    output
}

fn decode_verified_receipt(
    bytes: &[u8],
) -> Result<BranchExactBackfillVerifiedReceipt, BranchExactBackfillError> {
    let mut decoder = BackfillDecoder::new(bytes);
    decoder.expect_header(BACKFILL_VERIFIED_PAYLOAD_KIND)?;
    let plan = BranchExactBackfillPlan::decode_persisted(decoder.len_prefixed()?)?;
    let progress_digest = BranchExactBackfillProgressDigest(decoder.array32()?);
    let dataset_digest = BranchExactBackfillDatasetDigest::try_new(decoder.array32()?)?;
    let forward_rows = decoder.u64()?;
    let reverse_rows = decoder.u64()?;
    let proof_rows = decoder.u64()?;
    let persisted_digest = BranchExactBackfillReceiptDigest(decoder.array32()?);
    decoder.finish()?;
    if dataset_digest != plan.dataset_digest()
        || forward_rows != plan.pair_rows_per_direction()
        || reverse_rows != plan.pair_rows_per_direction()
        || proof_rows != plan.proof_rows()
    {
        return Err(BranchExactBackfillError::ReadbackCountMismatch);
    }
    let mut receipt = BranchExactBackfillVerifiedReceipt {
        plan,
        progress_digest,
        dataset_digest,
        forward_rows,
        reverse_rows,
        proof_rows,
        digest: BranchExactBackfillReceiptDigest([0; 32]),
    };
    receipt.digest = calculate_receipt_digest(&receipt);
    if receipt.digest != persisted_digest || receipt.to_canonical_bytes() != bytes {
        return Err(BranchExactBackfillError::ReceiptDigestMismatch);
    }
    Ok(receipt)
}

fn state_checksum(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(BACKFILL_PROGRESS_STATE_DOMAIN);
    hasher.update(bytes);
    hasher.finalize().into()
}

struct BackfillDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> BackfillDecoder<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], BranchExactBackfillError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(BranchExactBackfillError::TruncatedPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(BranchExactBackfillError::TruncatedPayload)?;
        self.offset = end;
        Ok(value)
    }

    fn expect_header(&mut self, kind: u8) -> Result<(), BranchExactBackfillError> {
        let version = u16::from_be_bytes(self.take(2)?.try_into().unwrap());
        if version != BACKFILL_CODEC_VERSION {
            return Err(BranchExactBackfillError::UnknownCodecVersion(version));
        }
        let actual = self.u8()?;
        if actual != kind {
            return Err(BranchExactBackfillError::WrongPayloadKind {
                expected: kind,
                actual,
            });
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, BranchExactBackfillError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, BranchExactBackfillError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, BranchExactBackfillError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn i64(&mut self) -> Result<i64, BranchExactBackfillError> {
        Ok(i64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn array32(&mut self) -> Result<[u8; 32], BranchExactBackfillError> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn len_prefixed(&mut self) -> Result<&'a [u8], BranchExactBackfillError> {
        let length = self.u32()? as usize;
        self.take(length)
    }

    fn finish(self) -> Result<(), BranchExactBackfillError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(BranchExactBackfillError::TrailingBytes)
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactBackfillTransitionError {
    Model(BranchExactBackfillError),
    Lifecycle(BranchExactDeploymentLifecycleError),
    ExpectedSchemaVerified,
    DeploymentMismatch,
    ExpectedBackfillCopy,
    ExpectedCompletedCopy,
}

impl From<BranchExactBackfillError> for BranchExactBackfillTransitionError {
    fn from(value: BranchExactBackfillError) -> Self {
        Self::Model(value)
    }
}

impl From<BranchExactDeploymentLifecycleError> for BranchExactBackfillTransitionError {
    fn from(value: BranchExactDeploymentLifecycleError) -> Self {
        Self::Lifecycle(value)
    }
}

impl fmt::Display for BranchExactBackfillTransitionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactBackfillTransitionError {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactBackfillError {
    DeploymentCodec(super::BranchExactDeploymentError),
    DeploymentRequestMismatch,
    MissingFloorEvidence,
    ZeroDatasetDigest,
    ZeroChunkDigest,
    TimestampOutOfRange(psy_node_core::store::timestamp::TimestampOutOfCqlRange),
    InvalidTimestampPresence(u8),
    UnknownBackfillMode(u8),
    ProfileModeMismatch,
    GenesisMustBeEmpty,
    EmptyPostGenesisBackfill,
    TooManyChunksForRows,
    CoordinatorProofRows,
    ProofRowsExceedPairs,
    EmptyChunk,
    ChunkPlanMismatch,
    NonContiguousChunk { expected: u32, actual: u32 },
    AllChunksAlreadyCopied,
    ChunkCountExceedsPlan,
    ChunkIndexOverflow,
    RowCountOverflow,
    FinalChunkCountMismatch,
    CountsCompleteBeforeFinalChunk,
    UnexpectedProgressForEmptyPlan,
    MissingCompletedProgress,
    IncompleteProgress,
    ReadbackPlanMismatch,
    ReadbackDatasetMismatch,
    ReadbackCountMismatch,
    UnknownCodecVersion(u16),
    WrongPayloadKind { expected: u8, actual: u8 },
    TruncatedPayload,
    TrailingBytes,
    PlanDigestMismatch,
    ProgressStateChecksumMismatch,
    InvalidPersistedProgress,
    ReceiptDigestMismatch,
    NonCanonicalPayload,
}

impl From<super::BranchExactDeploymentError> for BranchExactBackfillError {
    fn from(value: super::BranchExactDeploymentError) -> Self {
        Self::DeploymentCodec(value)
    }
}

impl From<psy_node_core::store::timestamp::TimestampOutOfCqlRange>
    for BranchExactBackfillError
{
    fn from(
        value: psy_node_core::store::timestamp::TimestampOutOfCqlRange,
    ) -> Self {
        Self::TimestampOutOfRange(value)
    }
}

impl fmt::Display for BranchExactBackfillError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactBackfillError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_data::protocol::canonical_chain::{
        CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
        CheckpointRef, NetworkId,
    };
    use psy_node_core::store::{
        branch_exact_schema::{
            BaselineSnapshotArtifactDigest,
            BranchExactPostGenesisFloorEvidence,
            BranchExactSchemaMaterializationPlan,
        },
        canonical_head::{CanonicalHeadBootstrap, CanonicalHeadBootstrapProfile},
        manifest_record::AuthorityManifestDigest,
        timestamp::CommitWriteTimestampUs,
    };

    use super::*;
    use crate::rollback::{
        branch_exact_schema_fingerprint, BranchExactDeploymentIntent,
        BranchExactDeploymentLifecycleBootstrap,
        BranchExactExpectedTopology, BranchExactNodeSchemaPostflight,
        BranchExactSchemaInspection, BranchExactSchemaOnlyReceipt,
        BranchExactScyllaNodeId, BranchExactScyllaSchemaVersion,
        BranchExactTopologyAttestation, CqlKeyspaceName,
        SealedBranchExactSchemaVerifiedCas,
    };

    fn realm() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 7,
            realm_sub_id: 2,
        }
    }

    fn request(
        keyspace: &str,
        profile: CanonicalHeadBootstrapProfile,
        authority: AuthorityScope,
    ) -> BranchExactSchemaMaterializationRequest {
        let checkpoint = match profile {
            CanonicalHeadBootstrapProfile::GenesisNative => 0,
            CanonicalHeadBootstrapProfile::PostGenesisFloor => 100,
        };
        let bootstrap = CanonicalHeadBootstrap::try_new(
            profile,
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(1337).unwrap(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        1, 2, 3, 4,
                    )),
                ),
            ),
        )
        .unwrap();
        let floor = (profile == CanonicalHeadBootstrapProfile::PostGenesisFloor)
            .then(|| {
                BranchExactPostGenesisFloorEvidence::new(
                    authority,
                    BaselineSnapshotArtifactDigest::try_new([7; 32]).unwrap(),
                    AuthorityManifestDigest::from_persisted([8; 32]),
                )
            });
        let plan = BranchExactSchemaMaterializationPlan::try_new(
            &bootstrap, authority, floor,
        )
        .unwrap();
        BranchExactSchemaMaterializationRequest::try_new(
            CqlKeyspaceName::try_new(keyspace).unwrap(),
            plan,
        )
        .unwrap()
    }

    fn topology() -> BranchExactExpectedTopology {
        BranchExactExpectedTopology::try_new(
            [1_u8, 2, 3]
                .map(|value| {
                    BranchExactScyllaNodeId::try_new([value; 16]).unwrap()
                })
                .to_vec(),
        )
        .unwrap()
    }

    fn verified(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> BranchExactVerifiedDeploymentReceipt {
        let fingerprint = branch_exact_schema_fingerprint(request.plan().authority());
        let schema = BranchExactSchemaOnlyReceipt::from_verified_parts_for_deployment(
            request,
            fingerprint,
        );
        let topology = topology();
        let observations = topology
            .nodes()
            .iter()
            .copied()
            .map(|node| {
                BranchExactNodeSchemaPostflight::try_new(
                    node,
                    BranchExactScyllaSchemaVersion::try_new([9; 16]).unwrap(),
                    BranchExactSchemaInspection::Exact { fingerprint },
                )
                .unwrap()
            })
            .collect();
        let attestation = BranchExactTopologyAttestation::try_new(
            &schema,
            topology.clone(),
            observations,
        )
        .unwrap();
        BranchExactVerifiedDeploymentReceipt::try_new(
            BranchExactDeploymentIntent::new(request, topology),
            attestation,
        )
        .unwrap()
    }

    fn schema_verified(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> StoredBranchExactDeploymentLifecycle {
        let deployment = verified(request);
        let bootstrap = BranchExactDeploymentLifecycleBootstrap::new(
            deployment.intent().clone(),
        );
        SealedBranchExactSchemaVerifiedCas::try_new(
            bootstrap.candidate(),
            deployment,
        )
        .unwrap()
        .candidate()
        .clone()
    }

    fn floor_plan(
        request: &BranchExactSchemaMaterializationRequest,
    ) -> BranchExactBackfillPlan {
        BranchExactBackfillPlan::post_genesis_artifact(
            request,
            verified(request),
            BranchExactBackfillDatasetDigest::try_new([0xA5; 32]).unwrap(),
            backfill_timestamp(),
            2,
            4,
            2,
        )
        .unwrap()
    }

    fn backfill_timestamp() -> CommitWriteTimestampUs {
        CommitWriteTimestampUs::try_from_i128(1_700_000_000_000_000).unwrap()
    }

    fn chunk(
        plan: &BranchExactBackfillPlan,
        index: u32,
        pairs: u64,
        proofs: u64,
    ) -> BranchExactBackfillChunkReceipt {
        BranchExactBackfillChunkReceipt::try_new(
            plan.digest(),
            index,
            pairs,
            proofs,
            BranchExactBackfillChunkDigest::try_new([index as u8 + 1; 32])
                .unwrap(),
        )
        .unwrap()
    }

    fn exact_observation(
        plan: &BranchExactBackfillPlan,
    ) -> BranchExactBackfillReadbackObservation {
        BranchExactBackfillReadbackObservation::new(
            plan.digest(),
            plan.dataset_digest(),
            plan.pair_rows_per_direction(),
            plan.pair_rows_per_direction(),
            plan.proof_rows(),
        )
    }

    #[test]
    fn profile_selects_empty_or_artifact_backfill_fail_closed() {
        let genesis = request(
            "psy_h16_genesis",
            CanonicalHeadBootstrapProfile::GenesisNative,
            realm(),
        );
        let empty = BranchExactBackfillPlan::genesis_empty(
            &genesis,
            verified(&genesis),
        )
        .unwrap();
        assert_eq!(empty.mode(), BranchExactBackfillMode::GenesisEmpty);
        assert_eq!(empty.total_chunks(), 0);
        assert_eq!(empty.pair_rows_per_direction(), 0);
        assert_eq!(
            BranchExactBackfillPlan::post_genesis_artifact(
                &genesis,
                verified(&genesis),
                BranchExactBackfillDatasetDigest::try_new([1; 32]).unwrap(),
                backfill_timestamp(),
                1,
                1,
                0,
            ),
            Err(BranchExactBackfillError::ProfileModeMismatch)
        );

        let floor = request(
            "psy_h16_floor",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        assert_eq!(floor_plan(&floor).mode(), BranchExactBackfillMode::PostGenesisArtifact);
        assert_eq!(
            BranchExactBackfillPlan::genesis_empty(&floor, verified(&floor)),
            Err(BranchExactBackfillError::ProfileModeMismatch)
        );
    }

    #[test]
    fn authority_and_dataset_shape_are_exact() {
        let coordinator = request(
            "psy_h16_coordinator",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            AuthorityScope::Coordinator,
        );
        assert_eq!(
            BranchExactBackfillPlan::post_genesis_artifact(
                &coordinator,
                verified(&coordinator),
                BranchExactBackfillDatasetDigest::try_new([1; 32]).unwrap(),
                backfill_timestamp(),
                1,
                1,
                1,
            ),
            Err(BranchExactBackfillError::CoordinatorProofRows)
        );
        let realm_request = request(
            "psy_h16_shape",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        assert_eq!(
            BranchExactBackfillPlan::post_genesis_artifact(
                &realm_request,
                verified(&realm_request),
                BranchExactBackfillDatasetDigest::try_new([1; 32]).unwrap(),
                backfill_timestamp(),
                1,
                1,
                2,
            ),
            Err(BranchExactBackfillError::ProofRowsExceedPairs)
        );
        assert_eq!(
            BranchExactBackfillDatasetDigest::try_new([0; 32]),
            Err(BranchExactBackfillError::ZeroDatasetDigest)
        );
    }

    #[test]
    fn post_genesis_timestamp_is_durable_and_part_of_plan_identity() {
        let request = request(
            "psy_h17_timestamp",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        let first = floor_plan(&request);
        assert_eq!(first.write_timestamp(), Some(backfill_timestamp()));
        assert_eq!(
            BranchExactBackfillPlan::decode_persisted(
                &first.to_canonical_bytes()
            )
            .unwrap(),
            first
        );
        let second = BranchExactBackfillPlan::post_genesis_artifact(
            &request,
            verified(&request),
            first.dataset_digest(),
            CommitWriteTimestampUs::try_from_i128(
                backfill_timestamp().as_i64() as i128 + 1,
            )
            .unwrap(),
            first.total_chunks(),
            first.pair_rows_per_direction(),
            first.proof_rows(),
        )
        .unwrap();
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.to_canonical_bytes(), second.to_canonical_bytes());
    }

    #[test]
    fn chunk_progress_is_contiguous_bounded_and_crash_resumable() {
        let request = request(
            "psy_h16_progress",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        let plan = floor_plan(&request);
        let planned = SealedBranchExactBackfillPlanCas::try_new(
            &schema_verified(&request),
            plan.clone(),
        )
        .unwrap();
        assert_eq!(planned.candidate().revision().get(), 2);
        assert_eq!(
            SealedBranchExactBackfillChunkCas::try_new(
                planned.candidate(),
                chunk(&plan, 1, 2, 1),
            ),
            Err(BranchExactBackfillTransitionError::Model(
                BranchExactBackfillError::NonContiguousChunk {
                    expected: 0,
                    actual: 1,
                }
            ))
        );
        let first = SealedBranchExactBackfillChunkCas::try_new(
            planned.candidate(),
            chunk(&plan, 0, 2, 1),
        )
        .unwrap();
        assert_eq!(first.candidate().revision().get(), 3);
        let recovered = StoredBranchExactDeploymentLifecycle::decode_persisted(
            first.candidate().slot().as_bytes(),
            3,
            first.candidate().payload(),
        )
        .unwrap();
        assert_eq!(recovered, *first.candidate());
        let second = SealedBranchExactBackfillChunkCas::try_new(
            &recovered,
            chunk(&plan, 1, 2, 1),
        )
        .unwrap();
        assert_eq!(second.candidate().revision().get(), 4);
        let BranchExactDeploymentLifecycleState::BackfillProgress(progress) =
            second.candidate().state()
        else {
            panic!("expected backfill progress")
        };
        assert!(progress.is_complete());
    }

    #[test]
    fn last_chunk_and_counts_must_finish_together() {
        let request = request(
            "psy_h16_counts",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        let plan = floor_plan(&request);
        let planned = SealedBranchExactBackfillPlanCas::try_new(
            &schema_verified(&request),
            plan.clone(),
        )
        .unwrap();
        assert_eq!(
            SealedBranchExactBackfillChunkCas::try_new(
                planned.candidate(),
                chunk(&plan, 0, 4, 2),
            ),
            Err(BranchExactBackfillTransitionError::Model(
                BranchExactBackfillError::CountsCompleteBeforeFinalChunk
            ))
        );
        let first = SealedBranchExactBackfillChunkCas::try_new(
            planned.candidate(),
            chunk(&plan, 0, 1, 1),
        )
        .unwrap();
        assert_eq!(
            SealedBranchExactBackfillChunkCas::try_new(
                first.candidate(),
                chunk(&plan, 1, 1, 1),
            ),
            Err(BranchExactBackfillTransitionError::Model(
                BranchExactBackfillError::FinalChunkCountMismatch
            ))
        );
    }

    #[test]
    fn verified_requires_complete_copy_and_exact_bidirectional_readback() {
        let request = request(
            "psy_h16_verify",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        let plan = floor_plan(&request);
        let planned = SealedBranchExactBackfillPlanCas::try_new(
            &schema_verified(&request),
            plan.clone(),
        )
        .unwrap();
        assert_eq!(
            SealedBranchExactBackfillVerifiedCas::try_new(
                planned.candidate(),
                exact_observation(&plan),
            ),
            Err(BranchExactBackfillTransitionError::Model(
                BranchExactBackfillError::MissingCompletedProgress
            ))
        );
        let first = SealedBranchExactBackfillChunkCas::try_new(
            planned.candidate(),
            chunk(&plan, 0, 2, 1),
        )
        .unwrap();
        let second = SealedBranchExactBackfillChunkCas::try_new(
            first.candidate(),
            chunk(&plan, 1, 2, 1),
        )
        .unwrap();
        let wrong_reverse = BranchExactBackfillReadbackObservation::new(
            plan.digest(),
            plan.dataset_digest(),
            4,
            3,
            2,
        );
        assert_eq!(
            SealedBranchExactBackfillVerifiedCas::try_new(
                second.candidate(),
                wrong_reverse,
            ),
            Err(BranchExactBackfillTransitionError::Model(
                BranchExactBackfillError::ReadbackCountMismatch
            ))
        );
        let verified = SealedBranchExactBackfillVerifiedCas::try_new(
            second.candidate(),
            exact_observation(&plan),
        )
        .unwrap();
        assert_eq!(verified.candidate().revision().get(), 5);
        let decoded = StoredBranchExactDeploymentLifecycle::decode_persisted(
            verified.candidate().slot().as_bytes(),
            5,
            verified.candidate().payload(),
        )
        .unwrap();
        assert_eq!(decoded, *verified.candidate());
    }

    #[test]
    fn genesis_uses_explicit_zero_copy_then_verified_receipt() {
        let request = request(
            "psy_h16_genesis_lifecycle",
            CanonicalHeadBootstrapProfile::GenesisNative,
            realm(),
        );
        let plan = BranchExactBackfillPlan::genesis_empty(
            &request,
            verified(&request),
        )
        .unwrap();
        let planned = SealedBranchExactBackfillPlanCas::try_new(
            &schema_verified(&request),
            plan.clone(),
        )
        .unwrap();
        let verified = SealedBranchExactBackfillVerifiedCas::try_new(
            planned.candidate(),
            exact_observation(&plan),
        )
        .unwrap();
        assert_eq!(planned.candidate().revision().get(), 2);
        assert_eq!(verified.candidate().revision().get(), 3);
        assert!(matches!(
            verified.candidate().state(),
            BranchExactDeploymentLifecycleState::BackfillVerified(_)
        ));
    }

    #[test]
    fn canonical_payload_tamper_and_wrong_deployment_fail_closed() {
        let first = request(
            "psy_h16_tamper",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        let plan = floor_plan(&first);
        let mut bytes = plan.to_canonical_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        assert_eq!(
            BranchExactBackfillPlan::decode_persisted(&bytes),
            Err(BranchExactBackfillError::PlanDigestMismatch)
        );
        let other = request(
            "psy_h16_other",
            CanonicalHeadBootstrapProfile::PostGenesisFloor,
            realm(),
        );
        assert_eq!(
            SealedBranchExactBackfillPlanCas::try_new(
                &schema_verified(&other),
                plan,
            ),
            Err(BranchExactBackfillTransitionError::DeploymentMismatch)
        );
    }
}
