//! Read-only, restart-safe classification of one Realm processing generation.
//!
//! The observation deliberately carries no terminal, writer, head, or
//! rotation capability.  It lets the single Processor owner recover the
//! storage-selected processing generation without consulting legacy mutable
//! singletons.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::PendingGenerationContext,
    pending_generation_pipeline::PendingPipelineRevision,
};

use super::{
    realm_processor_application_archive::{
        RealmProcessorApplicationArchiveDigest, RealmProcessorApplicationArchiveSlot,
    },
    realm_processor_semantic_output::{
        RealmProcessorSemanticOutput, RealmProcessorSemanticOutputDigest,
    },
};

const DEFERRED_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-deferred-carryover/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorGenerationContinuationPhase {
    /// Baseline. A later activation/rotation owner must prime the generation.
    AwaitPrimeOrRotate,
    /// Ready. Queue close has not selected an application yet.
    AwaitQueueClose,
    /// Sealing.  The c4a capture owner may resume the exact closed source.
    CaptureClosedSource,
    /// WorkCaptured.  A later writer capability must begin the commit.
    AwaitWriter,
    /// InFlight.  A later writer/head owner must finish or recover the commit.
    AwaitWriterCompletion,
    /// EmptyQueueSealed.  A later no-work authority must retire it.
    AwaitNoWorkTerminal,
    /// Published.  A later terminal authorization must persist the terminal.
    AwaitPublishedTerminal,
    /// Retired without a current-state write. This covers both an entirely
    /// empty application and a deferred-only application whose jobs are
    /// committed for the successor. A later terminal authorization must
    /// persist the terminal.
    AwaitRetiredTerminal,
}

impl RealmProcessorGenerationContinuationPhase {
    pub const fn requires_application(self) -> bool {
        !matches!(
            self,
            Self::AwaitPrimeOrRotate | Self::AwaitQueueClose | Self::CaptureClosedSource
        )
    }

    pub const fn expects_application_work(self) -> Option<bool> {
        match self {
            Self::AwaitWriter
            | Self::AwaitWriterCompletion
            | Self::AwaitPublishedTerminal => Some(true),
            Self::AwaitNoWorkTerminal => Some(false),
            // The retired pipeline state may bind either an empty archive or
            // a deferred-only archive. Exact semantic validation happens at
            // the storage-owned retirement and terminal boundaries.
            Self::AwaitRetiredTerminal => None,
            Self::AwaitPrimeOrRotate | Self::AwaitQueueClose | Self::CaptureClosedSource => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorDeferredCarryoverDigest([u8; 32]);

impl RealmProcessorDeferredCarryoverDigest {
    pub fn try_new(
        bytes: [u8; 32],
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        if bytes == [0; 32] {
            Err(RealmProcessorGenerationContinuationError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub fn from_semantic(
        semantic: &RealmProcessorSemanticOutput,
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        Self::from_jobs(semantic.deferred_jobs())
    }

    pub fn from_jobs(
        jobs: &[super::realm_processor_semantic_output::RealmProcessorDeferredJob],
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        let mut hasher = Sha256::new();
        hasher.update(DEFERRED_DIGEST_DOMAIN);
        hasher.update((jobs.len() as u64).to_be_bytes());
        for job in jobs {
            hasher.update(job.ordinal().to_be_bytes());
            encode_component(job.queue_item(), &mut hasher)?;
            encode_component(job.contract_updates(), &mut hasher)?;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        if digest == [0; 32] {
            return Err(RealmProcessorGenerationContinuationError::EmptyDigest);
        }
        Ok(Self(digest))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn encode_component(
    bytes: &[u8],
    hasher: &mut Sha256,
) -> Result<(), RealmProcessorGenerationContinuationError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| RealmProcessorGenerationContinuationError::ComponentTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorApplicationContinuation {
    archive_slot: RealmProcessorApplicationArchiveSlot,
    archive_digest: RealmProcessorApplicationArchiveDigest,
    semantic_digest: RealmProcessorSemanticOutputDigest,
    has_application_work: bool,
    deferred_count: u32,
    deferred_digest: RealmProcessorDeferredCarryoverDigest,
}

impl RealmProcessorApplicationContinuation {
    pub fn try_from_storage(
        archive_slot: RealmProcessorApplicationArchiveSlot,
        archive_digest: RealmProcessorApplicationArchiveDigest,
        semantic: &RealmProcessorSemanticOutput,
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        let deferred_count = u32::try_from(semantic.deferred_jobs().len())
            .map_err(|_| RealmProcessorGenerationContinuationError::ComponentTooLarge)?;
        Ok(Self {
            archive_slot,
            archive_digest,
            semantic_digest: semantic.digest(),
            has_application_work: semantic.has_application_work(),
            deferred_count,
            deferred_digest: RealmProcessorDeferredCarryoverDigest::from_semantic(semantic)?,
        })
    }

    /// Rebuild the read-only commitment from an immutable storage row.
    ///
    /// This constructor does not grant archive, terminal, writer, head, or
    /// rotation authority. Storage remains responsible for exact readback and
    /// for minting any later affine capability.
    #[allow(clippy::too_many_arguments)]
    pub fn try_from_committed_parts(
        archive_slot: RealmProcessorApplicationArchiveSlot,
        archive_digest: RealmProcessorApplicationArchiveDigest,
        semantic_digest: RealmProcessorSemanticOutputDigest,
        has_application_work: bool,
        deferred_count: u32,
        deferred_digest: RealmProcessorDeferredCarryoverDigest,
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        Ok(Self {
            archive_slot,
            archive_digest,
            semantic_digest,
            has_application_work,
            deferred_count,
            deferred_digest,
        })
    }

    pub const fn archive_slot(&self) -> RealmProcessorApplicationArchiveSlot {
        self.archive_slot
    }

    pub const fn archive_digest(&self) -> RealmProcessorApplicationArchiveDigest {
        self.archive_digest
    }

    pub const fn semantic_digest(&self) -> RealmProcessorSemanticOutputDigest {
        self.semantic_digest
    }

    pub const fn has_application_work(&self) -> bool {
        self.has_application_work
    }

    pub const fn deferred_count(&self) -> u32 {
        self.deferred_count
    }

    pub const fn deferred_digest(&self) -> RealmProcessorDeferredCarryoverDigest {
        self.deferred_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RealmProcessorGenerationContinuation {
    processing: PendingGenerationContext,
    pipeline_revision: PendingPipelineRevision,
    phase: RealmProcessorGenerationContinuationPhase,
    application: Option<RealmProcessorApplicationContinuation>,
}

impl RealmProcessorGenerationContinuation {
    pub fn try_from_storage(
        processing: PendingGenerationContext,
        pipeline_revision: PendingPipelineRevision,
        phase: RealmProcessorGenerationContinuationPhase,
        application: Option<RealmProcessorApplicationContinuation>,
    ) -> Result<Self, RealmProcessorGenerationContinuationError> {
        if phase.requires_application() != application.is_some()
            || application
                .zip(phase.expects_application_work())
                .is_some_and(|(application, expected)| {
                    application.has_application_work() != expected
                })
        {
            return Err(RealmProcessorGenerationContinuationError::PhaseApplicationMismatch);
        }
        Ok(Self {
            processing,
            pipeline_revision,
            phase,
            application,
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn pipeline_revision(&self) -> PendingPipelineRevision {
        self.pipeline_revision
    }

    pub const fn phase(&self) -> RealmProcessorGenerationContinuationPhase {
        self.phase
    }

    pub const fn application(&self) -> Option<RealmProcessorApplicationContinuation> {
        self.application
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorGenerationContinuationError {
    EmptyDigest,
    ComponentTooLarge,
    PhaseApplicationMismatch,
}

impl fmt::Display for RealmProcessorGenerationContinuationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorGenerationContinuationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        queue::{
            realm_processor_semantic_output::{
                RealmProcessorDeferredJob, RealmProcessorSemanticOutputParts,
            },
            recoverable_ephemeral::{
                PendingQueueBoundaryDigest, PendingQueueCaptureContextDigest,
            },
            realm_processor_durable_capture::RealmProcessorDurableGenerationDigest,
        },
        store::pending_generation_identity::PendingGenerationContext,
    };

    fn semantic_with_deferred(deferred: Vec<(Vec<u8>, Vec<u8>)>) -> RealmProcessorSemanticOutput {
        RealmProcessorSemanticOutput::try_from_candidate_parts(
            RealmProcessorSemanticOutputParts {
                context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
                generation_digest: RealmProcessorDurableGenerationDigest::try_new([2; 32])
                    .unwrap(),
                boundary_digest: PendingQueueBoundaryDigest::try_new([3; 32]).unwrap(),
                item_count: 0,
                input_binding: crate::queue::realm_processor_semantic_output::RealmProcessorSemanticInputBinding::LegacyUnbound,
                processing_checkpoint_id: 7,
                processing_checkpoint_root: [4; 32],
                processing_realm_start_root: [4; 32],
                old_realm_root: [4; 32],
                new_realm_root: [4; 32],
                total_users_updated: 0,
                total_proofs_generated: 0,
                global_user_tree_nodes: vec![],
                user_contract_tree_nodes: vec![],
                contract_state_tree_nodes: vec![],
                user_leaves: vec![],
                contract_state_imt_leaves: vec![],
                guta_header: vec![5],
                jobs: vec![],
                deferred_jobs: deferred
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, (queue, updates))| {
                        RealmProcessorDeferredJob::try_new(
                            u32::try_from(ordinal).unwrap(),
                            queue,
                            updates,
                        )
                        .unwrap()
                    })
                    .collect(),
            },
        )
        .unwrap()
    }

    fn semantic(deferred: bool) -> RealmProcessorSemanticOutput {
        semantic_with_deferred(if deferred {
            vec![(vec![6], vec![7])]
        } else {
            vec![]
        })
    }

    fn application(deferred: bool) -> RealmProcessorApplicationContinuation {
        let semantic = semantic(deferred);
        RealmProcessorApplicationContinuation::try_from_storage(
            RealmProcessorApplicationArchiveSlot::try_new([8; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([9; 32]).unwrap(),
            &semantic,
        )
        .unwrap()
    }

    #[test]
    fn phase_application_matrix_is_exhaustive_and_fail_closed() {
        let processing = PendingGenerationContext::try_from_legacy(11, 13).unwrap();
        let revision = PendingPipelineRevision::try_new(17).unwrap();
        for phase in [
            RealmProcessorGenerationContinuationPhase::AwaitPrimeOrRotate,
            RealmProcessorGenerationContinuationPhase::AwaitQueueClose,
            RealmProcessorGenerationContinuationPhase::CaptureClosedSource,
        ] {
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing, revision, phase, None,
            )
            .is_ok());
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                phase,
                Some(application(true)),
            )
            .is_err());
        }
        for phase in [
            RealmProcessorGenerationContinuationPhase::AwaitWriter,
            RealmProcessorGenerationContinuationPhase::AwaitWriterCompletion,
            RealmProcessorGenerationContinuationPhase::AwaitPublishedTerminal,
        ] {
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                phase,
                Some(application(true)),
            )
            .is_ok());
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                phase,
                Some(application(false)),
            )
            .is_err());
        }
        for phase in [RealmProcessorGenerationContinuationPhase::AwaitNoWorkTerminal] {
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                phase,
                Some(application(false)),
            )
            .is_ok());
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                phase,
                Some(application(true)),
            )
            .is_err());
        }
        for work in [false, true] {
            assert!(RealmProcessorGenerationContinuation::try_from_storage(
                processing,
                revision,
                RealmProcessorGenerationContinuationPhase::AwaitRetiredTerminal,
                Some(application(work)),
            )
            .is_ok());
        }
    }

    #[test]
    fn deferred_commitment_is_order_and_payload_exact() {
        let first = application(true);
        let second = application(true);
        assert_eq!(first, second);
        assert_eq!(first.deferred_count(), 1);
        assert_ne!(first.deferred_digest().as_bytes(), &[0; 32]);
        assert_ne!(first.deferred_digest(), application(false).deferred_digest());

        let ordered = semantic_with_deferred(vec![
            (vec![1], vec![2]),
            (vec![3], vec![4]),
        ]);
        let reordered = semantic_with_deferred(vec![
            (vec![3], vec![4]),
            (vec![1], vec![2]),
        ]);
        let queue_drift = semantic_with_deferred(vec![
            (vec![9], vec![2]),
            (vec![3], vec![4]),
        ]);
        let update_drift = semantic_with_deferred(vec![
            (vec![1], vec![8]),
            (vec![3], vec![4]),
        ]);
        let digest = RealmProcessorDeferredCarryoverDigest::from_semantic(&ordered).unwrap();
        assert_ne!(
            digest,
            RealmProcessorDeferredCarryoverDigest::from_semantic(&reordered).unwrap(),
        );
        assert_ne!(
            digest,
            RealmProcessorDeferredCarryoverDigest::from_semantic(&queue_drift).unwrap(),
        );
        assert_ne!(
            digest,
            RealmProcessorDeferredCarryoverDigest::from_semantic(&update_drift).unwrap(),
        );
    }
}
