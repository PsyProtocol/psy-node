//! Typed bridge between the durable pending pipeline and the branch-exact writer.
//!
//! This module performs no CQL.  It prevents processor code from inventing the
//! 32-byte evidence carried by the pending-pipeline state machine: begin
//! evidence is derived from the exact generation, publish evidence requires a
//! durable `WritesVerified` writer row, and no-work evidence requires an exact
//! post-switch empty-generation witness.
//!
//! The module is deliberately private to `psy_node_scylla`. In h22d3b0 a
//! generation-derived `InFlight` digest is not yet proof that dequeued work was
//! durably captured. Production composition must add a Gathering/queue-seal
//! boundary (or delay InFlight until `WritePrepared`) and expose only an
//! effectful facade that rereads live durable state.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::protocol::chain_context::{AuthorityObservation, AuthorityScope};
use psy_node_core::store::{
    pending_generation_identity::PendingGenerationContext,
    pending_generation_pipeline::{
        PendingNoWorkReceiptDigest, PendingPipelineError,
        PendingPipelineIntentDigest, PendingProcessingState,
        PendingPublishReceiptDigest, SealedPendingPipelineTransition,
        StoredPendingPipeline,
    },
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterActive, BranchExactWriterState,
    StoredBranchExactWriterLifecycle,
};

const BEGIN_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-begin/v1";
const STABLE_EMPTY_DOMAIN: &[u8] =
    b"psy/rollback/pending-pipeline-stable-empty/v1";
const NO_WORK_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-no-work/v1";
const PUBLISH_DOMAIN: &[u8] = b"psy/rollback/pending-pipeline-publish/v1";

/// Evidence that both the finalized generation and the post-switch drain were
/// empty for one exact pending/proc context.
///
/// This witness is intentionally not constructible outside `psy_node_scylla`.
/// h22d3b3 must replace its crate-private model constructor with evidence
/// obtained by independently verifying the durable queue seal/barrier. Merely
/// seeing an empty finalized output is not enough: the second, post-switch
/// drain must also have completed with zero late items.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct StableEmptyPendingGeneration {
    processing: PendingGenerationContext,
    digest: [u8; 32],
}

impl StableEmptyPendingGeneration {
    pub(crate) fn try_after_post_switch_barrier(
        processing: PendingGenerationContext,
        finalized_items: usize,
        post_switch_late_items: usize,
    ) -> Result<Self, BranchExactPendingOrchestrationError> {
        if finalized_items != 0 || post_switch_late_items != 0 {
            return Err(BranchExactPendingOrchestrationError::GenerationNotStableEmpty {
                finalized_items,
                post_switch_late_items,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(STABLE_EMPTY_DOMAIN);
        encode_context(&mut hasher, processing);
        // Commit the two independently observed zero counts.  Keeping them in
        // the domain is deliberate even though both are constrained to zero.
        hasher.update((finalized_items as u64).to_be_bytes());
        hasher.update((post_switch_late_items as u64).to_be_bytes());
        Ok(Self {
            processing,
            digest: hasher.finalize().into(),
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }
}

/// Seal `Ready -> InFlight` only when the writer and pipeline represent the
/// same authority, activation, and durable predecessor frontier.
pub fn seal_branch_exact_begin<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    let active = require_active_writer(pipeline, writer)?;
    if pipeline.processing_state() != PendingProcessingState::Ready {
        return Err(BranchExactPendingOrchestrationError::PipelineNotReady);
    }
    require_writer_frontier(pipeline, active)?;
    let digest = begin_digest(pipeline)?;
    pipeline
        .seal_begin_processing(digest)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
}

/// Seal a Realm no-work terminal state only from the exact active writer
/// predecessor and a stable-empty witness for the processing generation.
pub fn seal_branch_exact_no_work<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
    writer: &StoredBranchExactWriterLifecycle<Hash>,
    empty: StableEmptyPendingGeneration,
    observed: AuthorityObservation<Hash>,
) -> Result<SealedPendingPipelineTransition<Hash>, BranchExactPendingOrchestrationError> {
    let active = require_active_writer(pipeline, writer)?;
    if pipeline.key().authority() == AuthorityScope::Coordinator {
        return Err(BranchExactPendingOrchestrationError::CoordinatorNoWork);
    }
    if empty.processing != pipeline.processing() {
        return Err(BranchExactPendingOrchestrationError::GenerationMismatch);
    }
    require_writer_frontier(pipeline, active)?;
    let expected_intent = require_inflight_begin(pipeline)?;
    let receipt = generation_receipt_digest(
        NO_WORK_DOMAIN,
        pipeline,
        &[empty.digest.as_slice(), observed.to_canonical_bytes().as_slice()],
    )?;
    let receipt = PendingNoWorkReceiptDigest::try_new(receipt)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)?;
    pipeline
        .seal_retire_no_work(expected_intent, receipt, observed)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
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
    let expected_intent = require_inflight_begin(pipeline)?;
    let receipt = publish_receipt(pipeline, writer, &observed)?;
    pipeline
        .seal_publish(expected_intent, receipt, observed)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
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
    AwaitDurableAttempt,
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
        (PendingProcessingState::InFlight(_), BranchExactWriterState::WritesVerified(_)) => {
            seal_branch_exact_publish(pipeline, writer, observed)
                .map(BranchExactPendingPublishRecovery::ApplyPipeline)
        }
        (PendingProcessingState::Published(stored), BranchExactWriterState::WritesVerified(_)) => {
            if observed != *pipeline.frontier() {
                return Err(BranchExactPendingOrchestrationError::MarkerMismatch);
            }
            if publish_receipt(pipeline, writer, &observed)? != stored {
                return Err(BranchExactPendingOrchestrationError::PublishReceiptMismatch);
            }
            Ok(BranchExactPendingPublishRecovery::FinishWriter)
        }
        (PendingProcessingState::Published(stored), BranchExactWriterState::Active(active)) => {
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
        (PendingProcessingState::InFlight(_), BranchExactWriterState::Active(_)) => {
            // This is still a valid pre-intent/gathering state in h22d3b0.
            // It must never be treated as published or complete. h22d3b1 will
            // make Gathering versus materialized InFlight explicit.
            Ok(BranchExactPendingPublishRecovery::AwaitDurableAttempt)
        }
        _ => Err(BranchExactPendingOrchestrationError::PublishRecoveryStateMismatch),
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
) -> Result<PendingPipelineIntentDigest, BranchExactPendingOrchestrationError> {
    let digest = begin_digest(pipeline)?;
    if pipeline.processing_state() != PendingProcessingState::InFlight(digest) {
        return Err(BranchExactPendingOrchestrationError::InFlightIdentityMismatch);
    }
    Ok(digest)
}

fn begin_digest<Hash: Q256BitHash>(
    pipeline: &StoredPendingPipeline<Hash>,
) -> Result<PendingPipelineIntentDigest, BranchExactPendingOrchestrationError> {
    let digest = receipt_digest(BEGIN_DOMAIN, pipeline, &[])?;
    PendingPipelineIntentDigest::try_new(digest)
        .map_err(BranchExactPendingOrchestrationError::Pipeline)
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
    ActivationMismatch,
    PipelineNotReady,
    WriterNotActive,
    WriterNotWritesVerified,
    WriterFrontierMismatch,
    WriterGenerationMismatch,
    InFlightIdentityMismatch,
    GenerationMismatch,
    CoordinatorNoWork,
    MarkerMismatch,
    PublishReceiptMismatch,
    PublishRecoveryStateMismatch,
    MissingActiveIntent,
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
