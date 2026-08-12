//! Typed bridge between the durable pending pipeline and the branch-exact writer.
//!
//! This module performs no CQL.  It prevents processor code from inventing the
//! 32-byte evidence carried by the pending-pipeline state machine. Queue close
//! is a separate durable phase, materialized begin is bound to the exact
//! `WritePrepared` intent, publish requires durable `WritesVerified`, and
//! no-work requires an exact post-switch empty-generation seal.
//!
//! The module is deliberately private to `psy_node_scylla`. The constructors
//! below remain model-only until a queue backend can persist-before-ack and a
//! narrow runtime facade can mint the corresponding opaque receipt.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityObservation, AuthorityScope};
use psy_node_core::store::{
    authority_commit::{AuthorityIntentObservation, ObservedAuthorityTimestampState},
    pending_generation_identity::{
        PendingGenerationActivationDigest, PendingGenerationContext,
        PendingGenerationLedgerKey,
    },
    pending_generation_pipeline::{
        PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
        PendingPipelineError, PendingPipelineIntentDigest,
        PendingProcessingState, PendingPublishReceiptDigest,
        PendingPipelineRevision, PendingQueueCloseIntentDigest,
        PendingWorkCaptureDigest,
        SealedPendingPipelineTransition, StoredPendingPipeline,
    },
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterActive, BranchExactWriterState,
    PersistedRealmUserUpdateGenerationQualifiedReceipt,
    StoredBranchExactWriterLifecycle,
};

const CLOSE_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-close/v2";
const WORK_SEAL_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-work-seal/v2";
const EMPTY_SEAL_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-empty-seal/v2";
const BEGIN_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-begin/v2";
const NO_WORK_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-no-work/v2";
const PUBLISH_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-publish/v2";

/// Exact, replay-stable request to close one processing queue generation.
///
/// Production constructs this only from a freshly selected durable pipeline;
/// callers cannot provide the generation identity, source revision or digest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PendingQueueClosePlan {
    key: PendingGenerationLedgerKey,
    activation_digest: PendingGenerationActivationDigest,
    processing: PendingGenerationContext,
    source_revision: PendingPipelineRevision,
    digest: PendingQueueCloseIntentDigest,
}

impl PendingQueueClosePlan {
    pub(crate) fn from_storage_selected<Hash: Q256BitHash>(
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> Result<Self, BranchExactPendingOrchestrationError> {
        let key = pipeline.key();
        let activation_digest = pipeline.activation_digest();
        let processing = pipeline.processing();
        let source_revision = pipeline.revision();
        let mut hasher = Sha256::new();
        hasher.update(CLOSE_DOMAIN);
        hasher.update(key.network().chain_id().to_be_bytes());
        encode_authority(&mut hasher, key.authority());
        hasher.update(activation_digest.as_bytes());
        encode_context(&mut hasher, processing);
        hasher.update(source_revision.get().to_be_bytes());
        let digest = PendingQueueCloseIntentDigest::try_new(hasher.finalize().into())
            .map_err(BranchExactPendingOrchestrationError::Pipeline)?;
        Ok(Self {
            key,
            activation_digest,
            processing,
            source_revision,
            digest,
        })
    }

    #[cfg(test)]
    pub(crate) fn model<Hash: Q256BitHash>(
        pipeline: &StoredPendingPipeline<Hash>,
    ) -> Result<Self, BranchExactPendingOrchestrationError> {
        Self::from_storage_selected(pipeline)
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn source_revision(&self) -> PendingPipelineRevision {
        self.source_revision
    }

    pub const fn digest(&self) -> PendingQueueCloseIntentDigest {
        self.digest
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct VerifiedPendingQueueSeal {
    inner: VerifiedPendingQueueSealKind,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum VerifiedPendingQueueSealKind {
    Work {
        plan: PendingQueueClosePlan,
        item_count: u64,
        dataset_digest: [u8; 32],
        digest: PendingWorkCaptureDigest,
    },
    Empty {
        plan: PendingQueueClosePlan,
        digest: PendingEmptyQueueSealDigest,
    },
}

impl VerifiedPendingQueueSeal {
    #[cfg(test)]
    pub(crate) fn model_work(
        plan: PendingQueueClosePlan,
        item_count: u64,
        dataset_digest: [u8; 32],
    ) -> Result<Self, BranchExactPendingOrchestrationError> {
        if item_count == 0 || dataset_digest == [0; 32] {
            return Err(BranchExactPendingOrchestrationError::InvalidWorkSeal);
        }
        let digest = queue_seal_digest(
            WORK_SEAL_DOMAIN,
            &plan,
            item_count,
            &dataset_digest,
        )?;
        Ok(Self {
            inner: VerifiedPendingQueueSealKind::Work {
                plan,
                item_count,
                dataset_digest,
                digest: PendingWorkCaptureDigest::try_new(digest)
                    .map_err(BranchExactPendingOrchestrationError::Pipeline)?,
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn model_stable_empty(
        plan: PendingQueueClosePlan,
        finalized_items: usize,
        post_switch_late_items: usize,
    ) -> Result<Self, BranchExactPendingOrchestrationError> {
        if finalized_items != 0 || post_switch_late_items != 0 {
            return Err(BranchExactPendingOrchestrationError::GenerationNotStableEmpty {
                finalized_items,
                post_switch_late_items,
            });
        }
        let digest = queue_seal_digest(EMPTY_SEAL_DOMAIN, &plan, 0, &[0; 32])?;
        Ok(Self {
            inner: VerifiedPendingQueueSealKind::Empty {
                plan,
                digest: PendingEmptyQueueSealDigest::try_new(digest)
                    .map_err(BranchExactPendingOrchestrationError::Pipeline)?,
            },
        })
    }

    pub const fn plan(&self) -> PendingQueueClosePlan {
        match self.inner {
            VerifiedPendingQueueSealKind::Work { plan, .. }
            | VerifiedPendingQueueSealKind::Empty { plan, .. } => plan,
        }
    }

    #[cfg(test)]
    pub(crate) const fn work_digest(&self) -> Option<PendingWorkCaptureDigest> {
        match self.inner {
            VerifiedPendingQueueSealKind::Work { digest, .. } => Some(digest),
            VerifiedPendingQueueSealKind::Empty { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) const fn empty_digest(&self) -> Option<PendingEmptyQueueSealDigest> {
        match self.inner {
            VerifiedPendingQueueSealKind::Empty { digest, .. } => Some(digest),
            VerifiedPendingQueueSealKind::Work { .. } => None,
        }
    }
}

/// Persist the close intent before any queue backend is allowed to fetch or
/// acknowledge the processing generation.
pub fn seal_branch_exact_queue_close<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    plan: PendingQueueClosePlan,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    let active = require_active_writer(pipeline, writer)?;
    if pipeline.processing_state() != PendingProcessingState::Ready {
        return Err(BranchExactPendingOrchestrationError::PipelineNotReady);
    }
    if plan.processing != pipeline.processing() {
        return Err(BranchExactPendingOrchestrationError::GenerationMismatch);
    }
    if plan.key != pipeline.key()
        || plan.activation_digest != pipeline.activation_digest()
        || plan.source_revision != pipeline.revision()
    {
        return Err(BranchExactPendingOrchestrationError::QueueClosePlanMismatch);
    }
    require_writer_frontier(pipeline, active)?;
    pipeline
        .seal_begin_queue_close(plan.digest())
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

/// Persist the independently verified result of the exact close plan.
pub fn seal_branch_exact_queue_capture<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    seal: VerifiedPendingQueueSeal,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    let active = require_active_writer(pipeline, writer)?;
    let plan = seal.plan();
    if plan.processing != pipeline.processing()
        || plan.key != pipeline.key()
        || plan.activation_digest != pipeline.activation_digest()
        || plan.source_revision.get().checked_add(1)
            != Some(pipeline.revision().get())
        || pipeline.processing_state() != PendingProcessingState::Sealing(plan.digest())
    {
        return Err(BranchExactPendingOrchestrationError::QueueSealMismatch);
    }
    require_writer_frontier(pipeline, active)?;
    match seal.inner {
        VerifiedPendingQueueSealKind::Work { digest, .. } => pipeline
            .seal_capture_work(plan.digest(), digest)
            .map_err(BranchExactPendingOrchestrationError::Pipeline),
        VerifiedPendingQueueSealKind::Empty { digest, .. } => pipeline
            .seal_empty_queue(plan.digest(), digest)
            .map_err(BranchExactPendingOrchestrationError::Pipeline),
    }
}

/// Seal `WorkCaptured -> InFlight` only from the exact durable
/// `WritePrepared` writer intent retained either directly or inside
/// `WritesVerified`. A generation-derived digest is insufficient.
pub fn seal_branch_exact_begin<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    require_common_identity(pipeline, writer)?;
    let prepared = match writer.state() {
        BranchExactWriterState::WritePrepared(prepared) => prepared,
        BranchExactWriterState::WritesVerified(verified) => verified.prepared(),
        _ => {
            return Err(
                BranchExactPendingOrchestrationError::WriterNotPreparedOrVerified,
            )
        }
    };
    require_writer_frontier(pipeline, prepared.previous())?;
    let PendingProcessingState::WorkCaptured(capture) = pipeline.processing_state() else {
        return Err(BranchExactPendingOrchestrationError::WorkNotCaptured);
    };
    let intent = prepared.intent();
    if intent.authority() != pipeline.key().authority()
        || intent.predecessor() != prepared.previous().watermark()
        || intent.candidate().pending_id() != pipeline.processing().pending_id()
        || intent.proc_checkpoint_id() != pipeline.processing().proc_checkpoint_id()
    {
        return Err(BranchExactPendingOrchestrationError::WriterGenerationMismatch);
    }
    let digest = begin_digest(pipeline, intent.intent_digest().as_bytes(), capture)?;
    pipeline
        .seal_begin_processing(capture, digest)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

/// Seal a Realm no-work terminal state only from the exact active writer
/// predecessor and the already persisted stable-empty queue seal.
pub fn seal_branch_exact_no_work<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    empty: VerifiedPendingQueueSeal,
    observed: AuthorityObservation<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    let active = require_active_writer(pipeline, writer)?;
    if pipeline.key().authority() == AuthorityScope::Coordinator {
        return Err(BranchExactPendingOrchestrationError::CoordinatorNoWork);
    }
    let VerifiedPendingQueueSealKind::Empty { plan, digest } = empty.inner else {
        return Err(BranchExactPendingOrchestrationError::ExpectedEmptySeal);
    };
    if plan.processing != pipeline.processing()
        || pipeline.processing_state() != PendingProcessingState::EmptyQueueSealed(digest)
    {
        return Err(BranchExactPendingOrchestrationError::GenerationMismatch);
    }
    require_writer_frontier(pipeline, active)?;
    let receipt = generation_receipt_digest(
        NO_WORK_DOMAIN,
        pipeline,
        &[digest.as_bytes(), observed.to_canonical_bytes().as_slice()],
    )?;
    let receipt = PendingNoWorkReceiptDigest::try_new(receipt)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)?;
    pipeline
        .seal_retire_no_work(digest, receipt, observed)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

/// Production-shaped no-work frontier transition. The empty processing seal
/// is insufficient by itself: the current gathering generation must also be
/// terminal-qualified at this exact pre-transition pipeline revision.
pub(crate) fn seal_branch_exact_no_work_qualified<Hash: Q256BitHash>(
    qualification: &PersistedRealmUserUpdateGenerationQualifiedReceipt<Hash>,
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    empty: VerifiedPendingQueueSeal,
    observed: AuthorityObservation<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    qualification
        .revalidate_pipeline(pipeline)
        .map_err(|error| {
            BranchExactPendingOrchestrationError::UserUpdateQualification(
                error.to_string(),
            )
        })?;
    seal_branch_exact_no_work(pipeline, writer, empty, observed)
}

/// Seal publish only from the exact durable `WritesVerified` writer state and
/// an independently persisted authority observation for its candidate.
pub fn seal_branch_exact_publish<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    observed: AuthorityObservation<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    require_common_identity(pipeline, writer)?;
    let BranchExactWriterState::WritesVerified(verified) = writer.state() else {
        return Err(BranchExactPendingOrchestrationError::WriterNotWritesVerified);
    };
    let prepared = verified.prepared();
    let intent = prepared.intent();
    require_writer_frontier(pipeline, prepared.previous())?;
    if intent.authority() != pipeline.key().authority()
        || intent.predecessor() != prepared.previous().watermark()
        || intent.candidate().pending_id() != pipeline.processing().pending_id()
        || intent.proc_checkpoint_id() != pipeline.processing().proc_checkpoint_id()
        || intent.candidate().canonical_chain() != observed.chain()
        || observed.authority() != pipeline.key().authority()
    {
        return Err(BranchExactPendingOrchestrationError::WriterGenerationMismatch);
    }
    let expected_intent = require_inflight_begin(
        pipeline,
        intent.intent_digest().as_bytes(),
    )?;
    let receipt = publish_receipt(pipeline, writer, &observed)?;
    pipeline
        .seal_publish(expected_intent, receipt, observed)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

/// Production-shaped publish frontier transition. The opaque qualification
/// is consumed only after a fresh revision/frontier comparison; a stale or
/// foreign generation cannot authorize this call.
pub(crate) fn seal_branch_exact_publish_qualified<Hash: Q256BitHash>(
    qualification: &PersistedRealmUserUpdateGenerationQualifiedReceipt<Hash>,
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    observed: AuthorityObservation<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    qualification
        .revalidate_pipeline(pipeline)
        .map_err(|error| {
            BranchExactPendingOrchestrationError::UserUpdateQualification(
                error.to_string(),
            )
        })?;
    seal_branch_exact_publish(pipeline, writer, observed)
}

/// Pure crash-gap classifier for the required cross-row publication order:
///
/// `WritesVerified -> durable marker -> pipeline Published -> writer Active`.
///
/// `observed` is still a model input in h22d3b0. Production wiring must replace
/// it with a private verified marker receipt before this API is reachable from
/// a Processor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactPendingPublishRecovery<Hash> {
    ApplyPipeline(SealedPendingPipelineTransition<Hash>),
    FinishWriter,
    Complete,
}

/// Read-only startup classification for the three durable rows owned by the
/// pending/writer runtime.  It deliberately stops before queue access and
/// before authority-marker publication: those operations require opaque
/// receipts from their respective production backends.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactPendingStartupRecovery<Hash> {
    AwaitPrimeOrRotate,
    ReadyForQueueClose,
    ResumeQueueSeal(PendingQueueCloseIntentDigest),
    AwaitRecoverableWork(PendingWorkCaptureDigest),
    ApplyPipeline {
        pipeline: SealedPendingPipelineTransition<Hash>,
        writer: BranchExactPreparedWriterRecovery,
    },
    ResumeWriterVerification(BranchExactPreparedWriterRecovery),
    AwaitTrustedMarker,
    ResumeNoWorkPublication(PendingEmptyQueueSealDigest),
    CompleteNoWorkAfterTrustedMarker,
    FinishWriterAfterTrustedMarker,
    CompleteAfterTrustedMarker,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchExactPreparedWriterRecovery {
    ApplyTimestampReservation,
    ResumeActiveLease,
}

/// Classify a restart without mutating either row.  Every accepted pair is
/// identity-checked.  Cross-row transitions that can be reproduced from
/// durable evidence return their exact sealed candidate; queue and marker
/// actions remain explicit boundaries rather than accepting a caller-supplied
/// digest or observation.
pub fn classify_branch_exact_pending_startup<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    timestamp: ObservedAuthorityTimestampState,
) -> Result<BranchExactPendingStartupRecovery<Hash>, BranchExactPendingOrchestrationError> {
    if pipeline.blocked_reason().is_some() {
        return Err(BranchExactPendingOrchestrationError::PipelineBlocked);
    }
    require_common_identity(pipeline, writer)?;
    match (pipeline.processing_state(), writer.state()) {
        (PendingProcessingState::Baseline(_), BranchExactWriterState::Active(active)) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::AwaitPrimeOrRotate)
        }
        (PendingProcessingState::Ready, BranchExactWriterState::Active(active)) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::ReadyForQueueClose)
        }
        (PendingProcessingState::Sealing(close), BranchExactWriterState::Active(active)) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::ResumeQueueSeal(close))
        }
        (PendingProcessingState::WorkCaptured(capture), BranchExactWriterState::Active(active)) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::AwaitRecoverableWork(capture))
        }
        (PendingProcessingState::WorkCaptured(_), BranchExactWriterState::WritePrepared(prepared)) => {
            let recovery = classify_prepared_timestamp(pipeline, prepared, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::ApplyPipeline {
                pipeline: seal_branch_exact_begin(pipeline, writer)?,
                writer: recovery,
            })
        }
        (PendingProcessingState::WorkCaptured(_), BranchExactWriterState::WritesVerified(verified)) => {
            require_verified_active_timestamp(pipeline, verified.prepared(), timestamp)?;
            Ok(BranchExactPendingStartupRecovery::ApplyPipeline {
                pipeline: seal_branch_exact_begin(pipeline, writer)?,
                writer: BranchExactPreparedWriterRecovery::ResumeActiveLease,
            })
        }
        (PendingProcessingState::InFlight { .. }, BranchExactWriterState::WritePrepared(prepared)) => {
            require_inflight_writer(pipeline, prepared)?;
            Ok(BranchExactPendingStartupRecovery::ResumeWriterVerification(
                classify_prepared_timestamp(pipeline, prepared, timestamp)?,
            ))
        }
        (PendingProcessingState::InFlight { .. }, BranchExactWriterState::WritesVerified(verified)) => {
            require_inflight_writer(pipeline, verified.prepared())?;
            require_verified_active_timestamp(pipeline, verified.prepared(), timestamp)?;
            Ok(BranchExactPendingStartupRecovery::AwaitTrustedMarker)
        }
        (PendingProcessingState::EmptyQueueSealed(seal), BranchExactWriterState::Active(active)) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            Ok(BranchExactPendingStartupRecovery::ResumeNoWorkPublication(seal))
        }
        (
            PendingProcessingState::RetiredNoWork { seal, receipt },
            BranchExactWriterState::Active(active),
        ) => {
            require_writer_frontier(pipeline, active)?;
            require_active_timestamp(pipeline, active, timestamp)?;
            if no_work_receipt(pipeline, seal, pipeline.frontier())? != receipt {
                return Err(BranchExactPendingOrchestrationError::NoWorkReceiptMismatch);
            }
            Ok(
                BranchExactPendingStartupRecovery::CompleteNoWorkAfterTrustedMarker,
            )
        }
        (PendingProcessingState::Published { .. }, BranchExactWriterState::WritesVerified(verified)) => {
            require_published_verified_timestamp(pipeline, verified.prepared(), timestamp)?;
            if classify_branch_exact_publish_recovery(
                pipeline,
                writer,
                pipeline.frontier().clone(),
            )? != BranchExactPendingPublishRecovery::FinishWriter
            {
                return Err(BranchExactPendingOrchestrationError::StartupStateMismatch);
            }
            Ok(BranchExactPendingStartupRecovery::FinishWriterAfterTrustedMarker)
        }
        (PendingProcessingState::Published { .. }, BranchExactWriterState::Active(active)) => {
            require_active_timestamp(pipeline, active, timestamp)?;
            if classify_branch_exact_publish_recovery(
                pipeline,
                writer,
                pipeline.frontier().clone(),
            )? != BranchExactPendingPublishRecovery::Complete
            {
                return Err(BranchExactPendingOrchestrationError::StartupStateMismatch);
            }
            Ok(BranchExactPendingStartupRecovery::CompleteAfterTrustedMarker)
        }
        (PendingProcessingState::InFlight { .. }, BranchExactWriterState::Active(_)) => {
            Err(BranchExactPendingOrchestrationError::WriterAdvancedBeforePipeline)
        }
        _ => Err(BranchExactPendingOrchestrationError::StartupStateMismatch),
    }
}

pub fn classify_branch_exact_publish_recovery<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    observed: AuthorityObservation<Hash>,
) -> Result<BranchExactPendingPublishRecovery<Hash>, BranchExactPendingOrchestrationError> {
    require_common_identity(pipeline, writer)?;
    if observed.authority() != pipeline.key().authority() {
        return Err(BranchExactPendingOrchestrationError::MarkerMismatch);
    }
    match (pipeline.processing_state(), writer.state()) {
        (PendingProcessingState::WorkCaptured(_), BranchExactWriterState::WritesVerified(_)) => {
            seal_branch_exact_begin(pipeline, writer)
                .map(BranchExactPendingPublishRecovery::ApplyPipeline)
        }
        (PendingProcessingState::InFlight { .. }, BranchExactWriterState::WritesVerified(_)) => {
            seal_branch_exact_publish(pipeline, writer, observed)
                .map(BranchExactPendingPublishRecovery::ApplyPipeline)
        }
        (PendingProcessingState::Published { receipt: stored, .. }, BranchExactWriterState::WritesVerified(_)) => {
            if observed != *pipeline.frontier() {
                return Err(BranchExactPendingOrchestrationError::MarkerMismatch);
            }
            if publish_receipt(pipeline, writer, &observed)? != stored {
                return Err(BranchExactPendingOrchestrationError::PublishReceiptMismatch);
            }
            Ok(BranchExactPendingPublishRecovery::FinishWriter)
        }
        (PendingProcessingState::Published { receipt: stored, .. }, BranchExactWriterState::Active(active)) => {
            if observed != *pipeline.frontier()
                || active.watermark().pending_id() != pipeline.processing().pending_id()
                || active.watermark().canonical_chain() != pipeline.frontier().chain()
            {
                return Err(BranchExactPendingOrchestrationError::WriterFrontierMismatch);
            }
            let intent = active
                .last_intent()
                .ok_or(BranchExactPendingOrchestrationError::MissingActiveIntent)?;
            let expected = active_publish_receipt(pipeline, intent.as_bytes(), &observed)?;
            if expected != stored {
                return Err(BranchExactPendingOrchestrationError::PublishReceiptMismatch);
            }
            Ok(BranchExactPendingPublishRecovery::Complete)
        }
        (PendingProcessingState::InFlight { .. }, BranchExactWriterState::Active(_)) => {
            Err(BranchExactPendingOrchestrationError::WriterAdvancedBeforePipeline)
        }
        _ => Err(BranchExactPendingOrchestrationError::PublishRecoveryStateMismatch),
    }
}

/// Exact terminal pair required before a durable queue-terminal marker may be
/// written. This deliberately requires the writer to have reached Active;
/// the authority-local head is checked independently by the terminal store.
pub(crate) fn validate_branch_exact_queue_terminal_pair<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
) -> Result<(), BranchExactPendingOrchestrationError> {
    match (pipeline.processing_state(), writer.state()) {
        (
            PendingProcessingState::Published { .. },
            BranchExactWriterState::Active(_),
        ) => {
            if classify_branch_exact_publish_recovery(
                pipeline,
                writer,
                *pipeline.frontier(),
            )? != BranchExactPendingPublishRecovery::Complete
            {
                return Err(BranchExactPendingOrchestrationError::StartupStateMismatch);
            }
            Ok(())
        }
        (
            PendingProcessingState::RetiredNoWork { seal, receipt },
            BranchExactWriterState::Active(active),
        ) => {
            require_common_identity(pipeline, writer)?;
            require_writer_frontier(pipeline, active)?;
            if no_work_receipt(pipeline, seal, pipeline.frontier())? != receipt {
                return Err(BranchExactPendingOrchestrationError::NoWorkReceiptMismatch);
            }
            Ok(())
        }
        _ => Err(BranchExactPendingOrchestrationError::StartupStateMismatch),
    }
}

fn publish_receipt<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    observed: &AuthorityObservation<Hash>,
) -> Result<PendingPublishReceiptDigest, BranchExactPendingOrchestrationError> {
    let BranchExactWriterState::WritesVerified(verified) = writer.state() else {
        return Err(BranchExactPendingOrchestrationError::WriterNotWritesVerified);
    };
    let receipt = active_publish_receipt(
        pipeline,
        verified.prepared().intent().intent_digest().as_bytes(),
        observed,
    )?;
    Ok(receipt)
}

fn active_publish_receipt<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    intent_digest: &[u8; 32],
    observed: &AuthorityObservation<Hash>,
) -> Result<PendingPublishReceiptDigest, BranchExactPendingOrchestrationError> {
    let receipt = generation_receipt_digest(
        PUBLISH_DOMAIN,
        pipeline,
        &[
            intent_digest.as_slice(),
            observed.to_canonical_bytes().as_slice(),
        ],
    )?;
    PendingPublishReceiptDigest::try_new(receipt)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

fn no_work_receipt<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    seal: PendingEmptyQueueSealDigest,
    observed: &AuthorityObservation<Hash>,
) -> Result<PendingNoWorkReceiptDigest, BranchExactPendingOrchestrationError> {
    let receipt = generation_receipt_digest(
        NO_WORK_DOMAIN,
        pipeline,
        &[seal.as_bytes(), observed.to_canonical_bytes().as_slice()],
    )?;
    PendingNoWorkReceiptDigest::try_new(receipt)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

fn require_active_writer<'a, Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &'a StoredBranchExactWriterLifecycle<Hash>,
) -> Result<&'a BranchExactWriterActive<Hash>, BranchExactPendingOrchestrationError> {
    require_common_identity(pipeline, writer)?;
    let BranchExactWriterState::Active(active) = writer.state() else {
        return Err(BranchExactPendingOrchestrationError::WriterNotActive);
    };
    Ok(active)
}

/// The materialized writer watermark and the processed pipeline frontier are
/// deliberately different axes for sparse Realms. A no-work generation
/// advances `processed_pending_id` and may advance the observed Coordinator
/// head while leaving the last materialized mapping untouched.
fn require_writer_frontier<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    active: &BranchExactWriterActive<Hash>,
) -> Result<(), BranchExactPendingOrchestrationError> {
    let watermark = active.watermark();
    let writer_chain = watermark.canonical_chain();
    let frontier_chain = pipeline.frontier().chain();
    if writer_chain.network_id() != frontier_chain.network_id()
        || writer_chain.chain_epoch() != frontier_chain.chain_epoch()
        || watermark.pending_id().get() > pipeline.processed_pending_id()
    {
        return Err(BranchExactPendingOrchestrationError::WriterFrontierMismatch);
    }
    match pipeline.key().authority() {
        AuthorityScope::Coordinator => {
            if writer_chain != frontier_chain
                || watermark.pending_id().get() != pipeline.processed_pending_id()
            {
                return Err(BranchExactPendingOrchestrationError::WriterFrontierMismatch);
            }
        }
        AuthorityScope::Realm { .. } => {
            let materialized_height = writer_chain.checkpoint().checkpoint_id().get();
            let state_height = pipeline.frontier().state_checkpoint_id().get();
            if materialized_height != state_height
                || (materialized_height
                    == frontier_chain.checkpoint().checkpoint_id().get()
                    && writer_chain != frontier_chain)
            {
                return Err(BranchExactPendingOrchestrationError::WriterFrontierMismatch);
            }
        }
    }
    Ok(())
}

fn require_common_identity<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
) -> Result<(), BranchExactPendingOrchestrationError> {
    if writer.plan().authority() != pipeline.key().authority()
        || writer.plan().baseline().canonical_chain().network_id()
            != pipeline.key().network()
        || writer.plan().digest().as_bytes() != pipeline.activation_digest().as_bytes()
    {
        return Err(BranchExactPendingOrchestrationError::ActivationMismatch);
    }
    Ok(())
}

fn require_inflight_begin<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer_intent_digest: &[u8; 32],
) -> Result<PendingPipelineIntentDigest, BranchExactPendingOrchestrationError> {
    let PendingProcessingState::InFlight { capture, intent } =
        pipeline.processing_state()
    else {
        return Err(BranchExactPendingOrchestrationError::InFlightIdentityMismatch);
    };
    let expected = begin_digest(pipeline, writer_intent_digest, capture)?;
    if intent != expected {
        return Err(BranchExactPendingOrchestrationError::InFlightIdentityMismatch);
    }
    Ok(intent)
}

fn require_inflight_writer<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    prepared: &super::BranchExactWriterPrepared<Hash>,
) -> Result<(), BranchExactPendingOrchestrationError> {
    require_writer_frontier(pipeline, prepared.previous())?;
    let intent = prepared.intent();
    if intent.authority() != pipeline.key().authority()
        || intent.predecessor() != prepared.previous().watermark()
        || intent.candidate().pending_id() != pipeline.processing().pending_id()
        || intent.proc_checkpoint_id() != pipeline.processing().proc_checkpoint_id()
    {
        return Err(BranchExactPendingOrchestrationError::WriterGenerationMismatch);
    }
    require_inflight_begin(pipeline, intent.intent_digest().as_bytes())?;
    Ok(())
}

fn classify_prepared_timestamp<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    prepared: &super::BranchExactWriterPrepared<Hash>,
    observed: ObservedAuthorityTimestampState,
) -> Result<BranchExactPreparedWriterRecovery, BranchExactPendingOrchestrationError> {
    require_timestamp_key(pipeline, observed)?;
    match prepared
        .reconcile_timestamp_reservation(observed)
        .map_err(|_| BranchExactPendingOrchestrationError::TimestampMismatch)?
    {
        super::BranchExactTimestampReservationRecovery::Active(_) => {
            Ok(BranchExactPreparedWriterRecovery::ResumeActiveLease)
        }
        super::BranchExactTimestampReservationRecovery::Apply { .. } => {
            Ok(BranchExactPreparedWriterRecovery::ApplyTimestampReservation)
        }
    }
}

fn require_verified_active_timestamp<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    prepared: &super::BranchExactWriterPrepared<Hash>,
    observed: ObservedAuthorityTimestampState,
) -> Result<(), BranchExactPendingOrchestrationError> {
    require_timestamp_key(pipeline, observed)?;
    prepared
        .reseal(observed)
        .map(|_| ())
        .map_err(|_| BranchExactPendingOrchestrationError::TimestampMismatch)
}

fn require_published_verified_timestamp<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    prepared: &super::BranchExactWriterPrepared<Hash>,
    observed: ObservedAuthorityTimestampState,
) -> Result<(), BranchExactPendingOrchestrationError> {
    require_timestamp_key(pipeline, observed)?;
    match observed.observe_intent(prepared.intent().intent_digest().authority_intent()) {
        AuthorityIntentObservation::Active(_) => {
            prepared
                .reseal(observed)
                .map(|_| ())
                .map_err(|_| BranchExactPendingOrchestrationError::TimestampMismatch)
        }
        AuthorityIntentObservation::Completed { timestamp, revision }
            if timestamp == prepared.timestamp()
                && prepared.timestamp_revision().checked_next().ok() == Some(revision) =>
        {
            Ok(())
        }
        _ => Err(BranchExactPendingOrchestrationError::TimestampMismatch),
    }
}

fn require_active_timestamp<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    active: &BranchExactWriterActive<Hash>,
    observed: ObservedAuthorityTimestampState,
) -> Result<(), BranchExactPendingOrchestrationError> {
    require_timestamp_key(pipeline, observed)?;
    if observed.state() != active.timestamp_state() {
        return Err(BranchExactPendingOrchestrationError::TimestampMismatch);
    }
    Ok(())
}

fn require_timestamp_key<Hash>(
    pipeline: &StoredPendingPipeline<Hash>,
    observed: ObservedAuthorityTimestampState,
) -> Result<(), BranchExactPendingOrchestrationError> {
    let key = observed.key();
    if key.network() != pipeline.key().network()
        || key.authority() != pipeline.key().authority()
    {
        Err(BranchExactPendingOrchestrationError::TimestampMismatch)
    } else {
        Ok(())
    }
}

fn begin_digest<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer_intent_digest: &[u8; 32],
    capture: PendingWorkCaptureDigest,
) -> Result<PendingPipelineIntentDigest, BranchExactPendingOrchestrationError> {
    let digest = receipt_digest(
        BEGIN_DOMAIN,
        pipeline,
        &[capture.as_bytes(), writer_intent_digest],
    )?;
    PendingPipelineIntentDigest::try_new(digest)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

fn queue_seal_digest(
    domain: &[u8],
    plan: &PendingQueueClosePlan,
    item_count: u64,
    dataset_digest: &[u8; 32],
) -> Result<[u8; 32], BranchExactPendingOrchestrationError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(plan.key.network().chain_id().to_be_bytes());
    encode_authority(&mut hasher, plan.key.authority());
    hasher.update(plan.activation_digest.as_bytes());
    encode_context(&mut hasher, plan.processing);
    hasher.update(plan.source_revision.get().to_be_bytes());
    hasher.update(plan.digest.as_bytes());
    hasher.update(item_count.to_be_bytes());
    hasher.update(dataset_digest);
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        Err(BranchExactPendingOrchestrationError::EmptyDerivedDigest)
    } else {
        Ok(digest)
    }
}

fn receipt_digest<Hash: Q256BitHash>(
    domain: &[u8],
    pipeline: &StoredPendingPipeline<Hash>,
    evidence: &[&[u8]],
) -> Result<[u8; 32], BranchExactPendingOrchestrationError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(pipeline.key().network().chain_id().to_be_bytes());
    encode_authority(&mut hasher, pipeline.key().authority());
    hasher.update(pipeline.activation_digest().as_bytes());
    encode_context(&mut hasher, pipeline.processing());
    hasher.update(pipeline.processed_pending_id().to_be_bytes());
    hasher.update(pipeline.frontier().to_canonical_bytes());
    for item in evidence {
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(BranchExactPendingOrchestrationError::EmptyDerivedDigest);
    }
    Ok(digest)
}

/// Terminal evidence must be reproducible after the transition has advanced
/// `frontier` and `processed_pending_id`. Therefore it binds only immutable
/// generation identity here; the exact old/new observations are part of the
/// typed evidence supplied by each caller.
fn generation_receipt_digest<Hash: Q256BitHash>(
    domain: &[u8],
    pipeline: &StoredPendingPipeline<Hash>,
    evidence: &[&[u8]],
) -> Result<[u8; 32], BranchExactPendingOrchestrationError> {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(pipeline.key().network().chain_id().to_be_bytes());
    encode_authority(&mut hasher, pipeline.key().authority());
    hasher.update(pipeline.activation_digest().as_bytes());
    encode_context(&mut hasher, pipeline.processing());
    for item in evidence {
        hasher.update((item.len() as u64).to_be_bytes());
        hasher.update(item);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest == [0; 32] {
        return Err(BranchExactPendingOrchestrationError::EmptyDerivedDigest);
    }
    Ok(digest)
}

fn encode_context(hasher: &mut Sha256, context: PendingGenerationContext) {
    hasher.update(context.pending_id().get().to_be_bytes());
    hasher.update(context.proc_checkpoint_id().as_bytes());
}

fn encode_authority(hasher: &mut Sha256, authority: AuthorityScope) {
    match authority {
        AuthorityScope::Coordinator => {
            hasher.update([1]);
            hasher.update(0_u32.to_be_bytes());
            hasher.update(0_u16.to_be_bytes());
        }
        AuthorityScope::Realm {
            realm_id,
            realm_sub_id,
        } => {
            hasher.update([2]);
            hasher.update(realm_id.to_be_bytes());
            hasher.update(realm_sub_id.to_be_bytes());
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BranchExactPendingOrchestrationError {
    Pipeline(PendingPipelineError),
    PipelineBlocked,
    TimestampMismatch,
    ActivationMismatch,
    PipelineNotReady,
    WriterNotActive,
    WriterNotPreparedOrVerified,
    WriterNotWritesVerified,
    WriterFrontierMismatch,
    WriterGenerationMismatch,
    InFlightIdentityMismatch,
    WorkNotCaptured,
    QueueClosePlanMismatch,
    QueueSealMismatch,
    ExpectedEmptySeal,
    InvalidWorkSeal,
    GenerationMismatch,
    CoordinatorNoWork,
    MarkerMismatch,
    PublishReceiptMismatch,
    NoWorkReceiptMismatch,
    PublishRecoveryStateMismatch,
    StartupStateMismatch,
    MissingActiveIntent,
    WriterAdvancedBeforePipeline,
    UserUpdateQualification(String),
    GenerationNotStableEmpty {
        finalized_items: usize,
        post_switch_late_items: usize,
    },
    EmptyDerivedDigest,
}

impl fmt::Display for BranchExactPendingOrchestrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for BranchExactPendingOrchestrationError {}

#[cfg(test)]
mod terminal_qualification_tests {
    #[test]
    fn production_shaped_frontier_wrappers_require_fresh_qualification() {
        let source = include_str!("branch_exact_pending_orchestration.rs");
        for (qualified, legacy) in [
            (
                "seal_branch_exact_no_work_qualified",
                "seal_branch_exact_no_work(",
            ),
            (
                "seal_branch_exact_publish_qualified",
                "seal_branch_exact_publish(",
            ),
        ] {
            let body = source.split(qualified).nth(1).unwrap();
            let revalidate = body.find("revalidate_pipeline").unwrap();
            let transition = body.find(legacy).unwrap();
            assert!(revalidate < transition);
        }
    }
}
