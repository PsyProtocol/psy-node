//! Exact successor-keyed deferred input for one Realm command-only actor.
//!
//! The storage adapter reconstructs this value from the durable successor
//! locator and, for a predecessor lineage, the immutable application archive.
//! Missing carryover is represented separately and is never interpreted as an
//! empty input. This type is deliberately non-Clone and grants no terminal,
//! writer, authority-head, or pipeline-mutation capability.

use std::{error::Error, fmt};

use sha2::{Digest, Sha256};

use crate::store::{
    pending_generation_identity::{
        PendingGenerationBootstrapReason, PendingGenerationContext,
    },
};

use super::{
    realm_processor_generation_continuation::{
        RealmProcessorApplicationContinuation, RealmProcessorDeferredCarryoverDigest,
        RealmProcessorGenerationContinuation,
    },
    realm_processor_generation_terminal::{
        RealmProcessorDeferredCarryover, RealmProcessorDeferredCarryoverRecordDigest,
        RealmProcessorDeferredCarryoverSource, RealmProcessorGenerationTerminalDigest,
    },
    realm_processor_semantic_output::{
        RealmProcessorDeferredJob, RealmProcessorSemanticOutput,
    },
};

const INPUT_DIGEST_DOMAIN: &[u8] =
    b"psy/rollback/realm-processor-deferred-actor-input/v1";

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RealmProcessorDeferredActorInputDigest([u8; 32]);

impl RealmProcessorDeferredActorInputDigest {
    pub fn try_new(bytes: [u8; 32]) -> Result<Self, RealmProcessorDeferredActorInputError> {
        if bytes == [0; 32] {
            Err(RealmProcessorDeferredActorInputError::EmptyDigest)
        } else {
            Ok(Self(bytes))
        }
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorDeferredActorInputSource {
    BootstrapEmpty {
        reason: PendingGenerationBootstrapReason,
        carryover_record_digest: RealmProcessorDeferredCarryoverRecordDigest,
    },
    Predecessor {
        predecessor: PendingGenerationContext,
        carryover_record_digest: RealmProcessorDeferredCarryoverRecordDigest,
        terminal_digest: RealmProcessorGenerationTerminalDigest,
        application: RealmProcessorApplicationContinuation,
    },
}

/// Storage-reconstructed actor input. It is non-Clone so a caller cannot
/// accidentally fork one loaded input across two actor attempts.
#[derive(Debug, Eq, PartialEq)]
pub struct RealmProcessorDeferredActorInput {
    successor: PendingGenerationContext,
    source: RealmProcessorDeferredActorInputSource,
    deferred_jobs: Vec<RealmProcessorDeferredJob>,
    digest: RealmProcessorDeferredActorInputDigest,
}

impl RealmProcessorDeferredActorInput {
    /// Checked cross-crate constructor used by the storage adapter after exact
    /// readback. It validates the durable model, but it is not a storage or
    /// mutation receipt; the installed runtime must fresh-revalidate before
    /// the actor may consume it.
    pub fn try_from_storage(
        successor: PendingGenerationContext,
        pipeline_bootstrap_reason: PendingGenerationBootstrapReason,
        carryover: RealmProcessorDeferredCarryover,
        semantic: Option<&RealmProcessorSemanticOutput>,
    ) -> Result<Self, RealmProcessorDeferredActorInputError> {
        if carryover.successor() != successor {
            return Err(RealmProcessorDeferredActorInputError::SuccessorMismatch);
        }

        let (source, deferred_jobs) = match carryover.source() {
            RealmProcessorDeferredCarryoverSource::BootstrapEmpty { reason } => {
                if reason != pipeline_bootstrap_reason {
                    return Err(RealmProcessorDeferredActorInputError::BootstrapReasonMismatch);
                }
                if semantic.is_some() || carryover.deferred_count() != 0 {
                    return Err(RealmProcessorDeferredActorInputError::SourcePayloadMismatch);
                }
                (
                    RealmProcessorDeferredActorInputSource::BootstrapEmpty {
                        reason,
                        carryover_record_digest: carryover.digest(),
                    },
                    Vec::new(),
                )
            }
            RealmProcessorDeferredCarryoverSource::Predecessor {
                predecessor,
                terminal_digest,
                application,
                ..
            } => {
                let semantic = semantic.ok_or(
                    RealmProcessorDeferredActorInputError::SourcePayloadMismatch,
                )?;
                let observed = RealmProcessorApplicationContinuation::try_from_storage(
                    application.archive_slot(),
                    application.archive_digest(),
                    semantic,
                )
                .map_err(|_| RealmProcessorDeferredActorInputError::ApplicationMismatch)?;
                let deferred_count = u32::try_from(semantic.deferred_jobs().len())
                    .map_err(|_| RealmProcessorDeferredActorInputError::CountOverflow)?;
                let deferred_digest =
                    RealmProcessorDeferredCarryoverDigest::from_jobs(semantic.deferred_jobs())
                        .map_err(|_| RealmProcessorDeferredActorInputError::ApplicationMismatch)?;
                if observed != application
                    || carryover.deferred_count() != deferred_count
                    || carryover.deferred_digest() != deferred_digest
                {
                    return Err(RealmProcessorDeferredActorInputError::ApplicationMismatch);
                }
                (
                    RealmProcessorDeferredActorInputSource::Predecessor {
                        predecessor,
                        carryover_record_digest: carryover.digest(),
                        terminal_digest,
                        application,
                    },
                    semantic.deferred_jobs().to_vec(),
                )
            }
        };

        let digest = input_digest(successor, source, &deferred_jobs)?;
        Ok(Self {
            successor,
            source,
            deferred_jobs,
            digest,
        })
    }

    pub const fn successor(&self) -> PendingGenerationContext {
        self.successor
    }

    pub const fn source(&self) -> RealmProcessorDeferredActorInputSource {
        self.source
    }

    pub fn deferred_jobs(&self) -> &[RealmProcessorDeferredJob] {
        &self.deferred_jobs
    }

    pub const fn digest(&self) -> RealmProcessorDeferredActorInputDigest {
        self.digest
    }

    pub fn into_deferred_jobs(self) -> Vec<RealmProcessorDeferredJob> {
        self.deferred_jobs
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum RealmProcessorDeferredActorInputOutcome {
    AwaitExplicitCarryover {
        continuation: RealmProcessorGenerationContinuation,
    },
    Ready(RealmProcessorDeferredActorInput),
}

fn input_digest(
    successor: PendingGenerationContext,
    source: RealmProcessorDeferredActorInputSource,
    jobs: &[RealmProcessorDeferredJob],
) -> Result<RealmProcessorDeferredActorInputDigest, RealmProcessorDeferredActorInputError> {
    let mut hasher = Sha256::new();
    hasher.update(INPUT_DIGEST_DOMAIN);
    hash_context(&mut hasher, successor);
    match source {
        RealmProcessorDeferredActorInputSource::BootstrapEmpty {
            reason,
            carryover_record_digest,
        } => {
            hasher.update([1, reason as u8]);
            hasher.update(carryover_record_digest.as_bytes());
        }
        RealmProcessorDeferredActorInputSource::Predecessor {
            predecessor,
            carryover_record_digest,
            terminal_digest,
            application,
        } => {
            hasher.update([2]);
            hash_context(&mut hasher, predecessor);
            hasher.update(carryover_record_digest.as_bytes());
            hasher.update(terminal_digest.as_bytes());
            hasher.update(application.archive_slot().as_bytes());
            hasher.update(application.archive_digest().as_bytes());
            hasher.update(application.semantic_digest().as_bytes());
            hasher.update([u8::from(application.has_application_work())]);
            hasher.update(application.deferred_count().to_be_bytes());
            hasher.update(application.deferred_digest().as_bytes());
        }
    }
    hasher.update((jobs.len() as u64).to_be_bytes());
    for job in jobs {
        hasher.update(job.ordinal().to_be_bytes());
        hash_bytes(&mut hasher, job.queue_item())?;
        hash_bytes(&mut hasher, job.contract_updates())?;
    }
    RealmProcessorDeferredActorInputDigest::try_new(hasher.finalize().into())
}

fn hash_context(hasher: &mut Sha256, context: PendingGenerationContext) {
    hasher.update(context.pending_id().get().to_be_bytes());
    hasher.update(context.proc_checkpoint_id().as_bytes());
}

fn hash_bytes(
    hasher: &mut Sha256,
    bytes: &[u8],
) -> Result<(), RealmProcessorDeferredActorInputError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| RealmProcessorDeferredActorInputError::ComponentTooLarge)?;
    hasher.update(len.to_be_bytes());
    hasher.update(bytes);
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorDeferredActorInputError {
    EmptyDigest,
    SuccessorMismatch,
    BootstrapReasonMismatch,
    SourcePayloadMismatch,
    ApplicationMismatch,
    CountOverflow,
    ComponentTooLarge,
}

impl fmt::Display for RealmProcessorDeferredActorInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorDeferredActorInputError {}

#[cfg(test)]
mod tests {
    use parth_core::PHash;
    use psy_core::constants::chain_id::PsyChainNetworkType;
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{
            AuthorityObservation, AuthorityScope, AuthorityStateCheckpointId,
            AuthorityStateRoot,
        },
    };

    use crate::{
        queue::{
            realm_processor_application_archive::{
                RealmProcessorApplicationArchiveDigest,
                RealmProcessorApplicationArchiveSlot,
            },
            realm_processor_durable_capture::RealmProcessorDurableGenerationDigest,
            realm_processor_generation_continuation::RealmProcessorApplicationContinuation,
            realm_processor_generation_terminal::{
                RealmProcessorDeferredCarryover,
                RealmProcessorGenerationTerminal,
                RealmProcessorGenerationTerminalStoreFingerprint,
            },
            realm_processor_semantic_output::{
                RealmProcessorDeferredJob, RealmProcessorSemanticOutput,
                RealmProcessorSemanticOutputParts,
            },
            recoverable_ephemeral::{
                PendingQueueBoundaryDigest, PendingQueueCaptureContextDigest,
            },
        },
        store::{
            pending_generation::{ProcNamespacePrefix, ReservedPendingGeneration},
            pending_generation_identity::{
                PendingGenerationActivationDigest, PendingGenerationLedgerKey,
            },
            pending_generation_pipeline::{
                PendingEmptyQueueSealDigest, PendingNoWorkReceiptDigest,
                PendingPipelineBootstrap, PendingPipelineIntentDigest,
                PendingPublishReceiptDigest, PendingQueueCloseIntentDigest,
                PendingWorkCaptureDigest, StoredPendingPipeline,
            },
            typed::UniquePendingId,
        },
    };

    use super::*;

    fn key() -> PendingGenerationLedgerKey {
        PendingGenerationLedgerKey::new(
            NetworkId::from(PsyChainNetworkType::PsyMainnet),
            AuthorityScope::Realm {
                realm_id: 3,
                realm_sub_id: 4,
            },
        )
    }

    fn activation() -> PendingGenerationActivationDigest {
        PendingGenerationActivationDigest::try_new([7; 32]).unwrap()
    }

    fn prefix() -> ProcNamespacePrefix {
        ProcNamespacePrefix::for_authority(key().network(), key().authority())
    }

    fn context(pending: u64) -> PendingGenerationContext {
        let pending_id = UniquePendingId::try_new(pending).unwrap();
        PendingGenerationContext::try_from_legacy(
            pending,
            prefix().derive_proc_id(pending_id).as_u128(),
        )
        .unwrap()
    }

    fn observation(checkpoint: u64) -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                key().network(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        checkpoint,
                        checkpoint + 1,
                        checkpoint + 2,
                        checkpoint + 3,
                    )),
                ),
            ),
            key().authority(),
            AuthorityStateCheckpointId::new(checkpoint),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(
                checkpoint + 4,
                checkpoint + 5,
                checkpoint + 6,
                checkpoint + 7,
            )),
        )
        .unwrap()
    }

    fn no_work_observation(checkpoint: u64) -> AuthorityObservation<PHash> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                key().network(),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint),
                    CheckpointHash::from_last_chain_hash(PHash::from_values(
                        checkpoint,
                        checkpoint + 1,
                        checkpoint + 2,
                        checkpoint + 3,
                    )),
                ),
            ),
            key().authority(),
            AuthorityStateCheckpointId::new(1),
            AuthorityStateRoot::from_local_state_root(PHash::from_values(5, 6, 7, 8)),
        )
        .unwrap()
    }

    fn ready() -> StoredPendingPipeline<PHash> {
        PendingPipelineBootstrap::try_new(
            key(),
            activation(),
            prefix(),
            PendingGenerationBootstrapReason::LegacyActivation,
            context(1),
            context(2),
            observation(1),
            1,
        )
        .unwrap()
        .candidate()
        .seal_rotation(ReservedPendingGeneration::try_from_prefix(3, prefix()).unwrap())
        .unwrap()
        .candidate()
        .clone()
    }

    fn semantic(job_bytes: &[(u8, u8)]) -> RealmProcessorSemanticOutput {
        RealmProcessorSemanticOutput::try_from_candidate_parts(
            RealmProcessorSemanticOutputParts {
                context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
                generation_digest: RealmProcessorDurableGenerationDigest::try_new([2; 32])
                    .unwrap(),
                boundary_digest: PendingQueueBoundaryDigest::try_new([3; 32]).unwrap(),
                item_count: 2,
                processing_checkpoint_id: 17,
                processing_checkpoint_root: [4; 32],
                processing_realm_start_root: [5; 32],
                old_realm_root: [5; 32],
                new_realm_root: [5; 32],
                total_users_updated: 0,
                total_proofs_generated: 0,
                global_user_tree_nodes: vec![],
                user_contract_tree_nodes: vec![],
                contract_state_tree_nodes: vec![],
                user_leaves: vec![],
                contract_state_imt_leaves: vec![],
                guta_header: vec![8],
                jobs: vec![],
                deferred_jobs: job_bytes
                    .iter()
                    .enumerate()
                    .map(|(ordinal, (queue, updates))| {
                        RealmProcessorDeferredJob::try_new(
                            ordinal as u32,
                            vec![*queue],
                            vec![*updates],
                        )
                        .unwrap()
                    })
                    .collect(),
            },
        )
        .unwrap()
    }

    fn predecessor_carryover(
        semantic: &RealmProcessorSemanticOutput,
    ) -> RealmProcessorDeferredCarryover {
        let application = RealmProcessorApplicationContinuation::try_from_storage(
            RealmProcessorApplicationArchiveSlot::try_new([21; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([22; 32]).unwrap(),
            semantic,
        )
        .unwrap();
        let sealing = ready()
            .seal_begin_queue_close(PendingQueueCloseIntentDigest::try_new([20; 32]).unwrap())
            .unwrap()
            .candidate()
            .clone();
        let terminal_pipeline = if semantic.has_application_work() {
            let captured = sealing
                .seal_capture_work(
                    PendingQueueCloseIntentDigest::try_new([20; 32]).unwrap(),
                    PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes())
                        .unwrap(),
                )
                .unwrap()
                .candidate()
                .clone();
            let inflight = captured
                .seal_begin_processing(
                    PendingWorkCaptureDigest::try_new(*application.archive_slot().as_bytes())
                        .unwrap(),
                    PendingPipelineIntentDigest::try_new([23; 32]).unwrap(),
                )
                .unwrap()
                .candidate()
                .clone();
            inflight
                .seal_publish(
                    PendingPipelineIntentDigest::try_new([23; 32]).unwrap(),
                    PendingPublishReceiptDigest::try_new([24; 32]).unwrap(),
                    observation(2),
                )
                .unwrap()
                .candidate()
                .clone()
        } else {
            let empty = sealing
                .seal_empty_queue(
                    PendingQueueCloseIntentDigest::try_new([20; 32]).unwrap(),
                    PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes())
                        .unwrap(),
                )
                .unwrap()
                .candidate()
                .clone();
            empty
                .seal_retire_no_work(
                    PendingEmptyQueueSealDigest::try_new(*application.archive_slot().as_bytes())
                        .unwrap(),
                    PendingNoWorkReceiptDigest::try_new([24; 32]).unwrap(),
                    no_work_observation(2),
                )
                .unwrap()
                .candidate()
                .clone()
        };
        let terminal = RealmProcessorGenerationTerminal::try_new(
            &terminal_pipeline,
            ReservedPendingGeneration::try_from_prefix(4, prefix()).unwrap(),
            [25; 32],
            [26; 32],
            application,
            vec![27],
        )
        .unwrap();
        RealmProcessorDeferredCarryover::try_from_terminal_commitment(
            &terminal,
            RealmProcessorGenerationTerminalStoreFingerprint::try_new([28; 32]).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn explicit_bootstrap_empty_is_typed_and_reason_bound() {
        let genesis = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            key(),
            activation(),
            context(3),
            PendingGenerationBootstrapReason::Genesis,
        )
        .unwrap();
        let legacy = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            key(),
            activation(),
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
        )
        .unwrap();

        let genesis_input = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::Genesis,
            genesis,
            None,
        )
        .unwrap();
        let legacy_input = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
            legacy,
            None,
        )
        .unwrap();
        assert!(genesis_input.deferred_jobs().is_empty());
        assert!(legacy_input.deferred_jobs().is_empty());
        assert_ne!(genesis_input.digest(), legacy_input.digest());
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(3),
                PendingGenerationBootstrapReason::LegacyActivation,
                genesis,
                None,
            ),
            Err(RealmProcessorDeferredActorInputError::BootstrapReasonMismatch),
        );
    }

    #[test]
    fn predecessor_jobs_are_ordered_and_retry_stable() {
        let reference = semantic(&[(31, 41), (32, 42), (33, 43)]);
        let carryover = predecessor_carryover(&reference);
        let first = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
            carryover,
            Some(&reference),
        )
        .unwrap();
        let second = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
            carryover,
            Some(&reference),
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(first.deferred_jobs()[0].queue_item(), &[31]);
        assert_eq!(first.deferred_jobs()[2].contract_updates(), &[43]);

        let reordered = semantic(&[(33, 43), (32, 42), (31, 41)]);
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(3),
                PendingGenerationBootstrapReason::LegacyActivation,
                carryover,
                Some(&reordered),
            ),
            Err(RealmProcessorDeferredActorInputError::ApplicationMismatch),
        );
        let queue_drift = semantic(&[(31, 41), (99, 42), (33, 43)]);
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(3),
                PendingGenerationBootstrapReason::LegacyActivation,
                carryover,
                Some(&queue_drift),
            ),
            Err(RealmProcessorDeferredActorInputError::ApplicationMismatch),
        );
        let update_drift = semantic(&[(31, 41), (32, 98), (33, 43)]);
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(3),
                PendingGenerationBootstrapReason::LegacyActivation,
                carryover,
                Some(&update_drift),
            ),
            Err(RealmProcessorDeferredActorInputError::ApplicationMismatch),
        );
    }

    #[test]
    fn missing_semantic_and_wrong_successor_fail_closed() {
        let reference = semantic(&[(31, 41)]);
        let carryover = predecessor_carryover(&reference);
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(3),
                PendingGenerationBootstrapReason::LegacyActivation,
                carryover,
                None,
            ),
            Err(RealmProcessorDeferredActorInputError::SourcePayloadMismatch),
        );
        assert_eq!(
            RealmProcessorDeferredActorInput::try_from_storage(
                context(4),
                PendingGenerationBootstrapReason::LegacyActivation,
                carryover,
                Some(&reference),
            ),
            Err(RealmProcessorDeferredActorInputError::SuccessorMismatch),
        );
    }

    #[test]
    fn predecessor_zero_and_bootstrap_empty_remain_distinct() {
        let empty_semantic = semantic(&[]);
        let predecessor = predecessor_carryover(&empty_semantic);
        let predecessor_input = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
            predecessor,
            Some(&empty_semantic),
        )
        .unwrap();
        let bootstrap = RealmProcessorDeferredCarryover::try_bootstrap_empty(
            key(),
            activation(),
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
        )
        .unwrap();
        let bootstrap_input = RealmProcessorDeferredActorInput::try_from_storage(
            context(3),
            PendingGenerationBootstrapReason::LegacyActivation,
            bootstrap,
            None,
        )
        .unwrap();
        assert!(predecessor_input.deferred_jobs().is_empty());
        assert!(bootstrap_input.deferred_jobs().is_empty());
        assert_ne!(predecessor_input.source(), bootstrap_input.source());
        assert_ne!(predecessor_input.digest(), bootstrap_input.digest());
    }

    #[test]
    fn actor_input_is_non_clone_and_has_no_default() {
        let source = include_str!("realm_processor_deferred_actor_input.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for RealmProcessorDeferredActorInput"));
        assert!(!production.contains("impl Default for RealmProcessorDeferredActorInput"));
        assert!(!production.contains("pub deferred_jobs:"));
    }
}
