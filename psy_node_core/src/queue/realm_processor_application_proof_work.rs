//! Exact, read-only proof work recovered from a selected Realm application.
//!
//! The value is deliberately not mutation authority. A storage adapter must
//! reconstruct the immutable application archive and bracket it with exact
//! pipeline reads before returning this model to the Processor. Later writer
//! mutation still requires a separately sealed, verified proof capability.

use std::{error::Error, fmt};

use parth_core::protocol::core_types::Q256BitHash;
use psy_data::prepared_block::realm::PsyPreparedRealmBlockStateUpdates;

use crate::store::pending_generation_identity::PendingGenerationContext;

use super::{
    realm_processor_generation_continuation::RealmProcessorApplicationContinuation,
    realm_processor_semantic_output::RealmProcessorSemanticOutput,
};

/// A checked, non-Clone application payload ready for proof reconstruction.
#[derive(Debug)]
pub struct RealmProcessorApplicationProofWork {
    processing: PendingGenerationContext,
    application: RealmProcessorApplicationContinuation,
    semantic: RealmProcessorSemanticOutput,
}

impl RealmProcessorApplicationProofWork {
    pub fn try_from_storage(
        processing: PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
        semantic: RealmProcessorSemanticOutput,
    ) -> Result<Self, RealmProcessorApplicationProofWorkError> {
        let observed = RealmProcessorApplicationContinuation::try_from_storage(
            application.archive_slot(),
            application.archive_digest(),
            &semantic,
        )
        .map_err(|_| RealmProcessorApplicationProofWorkError::ApplicationMismatch)?;
        if observed != application
            || !application.has_application_work()
            || semantic.actor_input_digest().is_none()
        {
            return Err(RealmProcessorApplicationProofWorkError::ApplicationMismatch);
        }
        Ok(Self {
            processing,
            application,
            semantic,
        })
    }

    pub const fn processing(&self) -> PendingGenerationContext {
        self.processing
    }

    pub const fn application(&self) -> RealmProcessorApplicationContinuation {
        self.application
    }

    pub const fn semantic(&self) -> &RealmProcessorSemanticOutput {
        &self.semantic
    }

    pub fn into_semantic(self) -> RealmProcessorSemanticOutput {
        self.semantic
    }

    /// Reconstruct the exact prepared-update payload committed by the
    /// immutable semantic archive. The caller supplies only the installed
    /// Realm identity; pending/proc comes from the storage-selected work.
    pub fn prepared_update<Hash: Q256BitHash>(
        &self,
        realm_id: u32,
        realm_sub_id: u16,
    ) -> PsyPreparedRealmBlockStateUpdates<Hash> {
        PsyPreparedRealmBlockStateUpdates {
            realm_id: u64::from(realm_id),
            realm_sub_id: u64::from(realm_sub_id),
            unique_pending_id: self.processing.pending_id().get(),
            proc_checkpoint_unique_id: self
                .processing
                .proc_checkpoint_id()
                .as_u128(),
            old_realm_root: Hash::from_owned_32bytes(*self.semantic.old_realm_root()),
            new_realm_root: Hash::from_owned_32bytes(*self.semantic.new_realm_root()),
            update_global_user_tree_nodes_ffs: self
                .semantic
                .global_user_tree_nodes()
                .to_vec(),
            update_user_contract_tree_nodes_ffs: self
                .semantic
                .user_contract_tree_nodes()
                .to_vec(),
            update_contract_state_tree_nodes_ffs: self
                .semantic
                .contract_state_tree_nodes()
                .to_vec(),
            update_user_leaves_ffs: self.semantic.user_leaves().to_vec(),
            update_contract_state_imt_leaves_ffs: self
                .semantic
                .contract_state_imt_leaves()
                .to_vec(),
        }
    }
}

/// Proof work is explicit about the deferred-only edge case. Such an
/// application remains durable work, but it cannot manufacture a checkpoint
/// proof or advance the narrow writer without a real proof-bearing output.
#[derive(Debug)]
pub enum RealmProcessorApplicationProofWorkOutcome {
    AwaitProoflessApplication {
        processing: PendingGenerationContext,
        application: RealmProcessorApplicationContinuation,
    },
    Ready(RealmProcessorApplicationProofWork),
}

impl RealmProcessorApplicationProofWorkOutcome {
    pub fn from_exact_work(work: RealmProcessorApplicationProofWork) -> Self {
        if work.semantic().jobs().is_empty() {
            Self::AwaitProoflessApplication {
                processing: work.processing(),
                application: work.application(),
            }
        } else {
            Self::Ready(work)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RealmProcessorApplicationProofWorkError {
    ApplicationMismatch,
}

impl fmt::Display for RealmProcessorApplicationProofWorkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl Error for RealmProcessorApplicationProofWorkError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{
        realm_processor_actor_input::RealmProcessorActorInputDigest,
        realm_processor_application_archive::{
            RealmProcessorApplicationArchiveDigest,
            RealmProcessorApplicationArchiveSlot,
        },
        realm_processor_durable_capture::RealmProcessorDurableGenerationDigest,
        realm_processor_semantic_output::{
            RealmProcessorDeferredJob, RealmProcessorSemanticInputBinding,
            RealmProcessorSemanticJob, RealmProcessorSemanticOutputParts,
        },
        recoverable_ephemeral::{
            PendingQueueBoundaryDigest, PendingQueueCaptureContextDigest,
        },
    };

    fn semantic(with_proof: bool) -> RealmProcessorSemanticOutput {
        RealmProcessorSemanticOutput::try_from_candidate_parts(
            RealmProcessorSemanticOutputParts {
                context_digest: PendingQueueCaptureContextDigest::try_new([1; 32]).unwrap(),
                generation_digest: RealmProcessorDurableGenerationDigest::try_new([2; 32])
                    .unwrap(),
                boundary_digest: PendingQueueBoundaryDigest::try_new([3; 32]).unwrap(),
                item_count: 1,
                input_binding: RealmProcessorSemanticInputBinding::SuccessorQualified(
                    RealmProcessorActorInputDigest::try_new([4; 32]).unwrap(),
                ),
                processing_checkpoint_id: 7,
                processing_checkpoint_root: [5; 32],
                processing_realm_start_root: [6; 32],
                old_realm_root: [6; 32],
                new_realm_root: if with_proof { [7; 32] } else { [6; 32] },
                total_users_updated: if with_proof { 1 } else { 0 },
                total_proofs_generated: if with_proof { 1 } else { 0 },
                global_user_tree_nodes: Vec::new(),
                user_contract_tree_nodes: Vec::new(),
                contract_state_tree_nodes: Vec::new(),
                user_leaves: Vec::new(),
                contract_state_imt_leaves: Vec::new(),
                guta_header: vec![8],
                jobs: if with_proof {
                    vec![RealmProcessorSemanticJob::try_new(
                        0,
                        0,
                        vec![9],
                        vec![10],
                    )
                    .unwrap()]
                } else {
                    Vec::new()
                },
                deferred_jobs: if with_proof {
                    Vec::new()
                } else {
                    vec![RealmProcessorDeferredJob::try_new(
                        0,
                        vec![11],
                        vec![12],
                    )
                    .unwrap()]
                },
            },
        )
        .unwrap()
    }

    fn work(with_proof: bool) -> RealmProcessorApplicationProofWork {
        let semantic = semantic(with_proof);
        let application = RealmProcessorApplicationContinuation::try_from_storage(
            RealmProcessorApplicationArchiveSlot::try_new([13; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([14; 32]).unwrap(),
            &semantic,
        )
        .unwrap();
        RealmProcessorApplicationProofWork::try_from_storage(
            PendingGenerationContext::try_from_legacy(15, 17).unwrap(),
            application,
            semantic,
        )
        .unwrap()
    }

    #[test]
    fn proof_bearing_and_deferred_only_outcomes_are_distinct() {
        assert!(matches!(
            RealmProcessorApplicationProofWorkOutcome::from_exact_work(work(true)),
            RealmProcessorApplicationProofWorkOutcome::Ready(_)
        ));
        assert!(matches!(
            RealmProcessorApplicationProofWorkOutcome::from_exact_work(work(false)),
            RealmProcessorApplicationProofWorkOutcome::AwaitProoflessApplication { .. }
        ));
    }

    #[test]
    fn application_commitment_and_v3_binding_are_required() {
        let semantic = semantic(true);
        let wrong = RealmProcessorApplicationContinuation::try_from_storage(
            RealmProcessorApplicationArchiveSlot::try_new([15; 32]).unwrap(),
            RealmProcessorApplicationArchiveDigest::try_new([16; 32]).unwrap(),
            &semantic,
        )
        .unwrap();
        let legacy_parts = RealmProcessorSemanticOutputParts {
            context_digest: semantic.context_digest(),
            generation_digest: semantic.generation_digest(),
            boundary_digest: semantic.boundary_digest(),
            item_count: semantic.item_count(),
            input_binding: RealmProcessorSemanticInputBinding::LegacyUnbound,
            processing_checkpoint_id: semantic.processing_checkpoint_id(),
            processing_checkpoint_root: *semantic.processing_checkpoint_root(),
            processing_realm_start_root: *semantic.processing_realm_start_root(),
            old_realm_root: *semantic.old_realm_root(),
            new_realm_root: *semantic.new_realm_root(),
            total_users_updated: semantic.total_users_updated(),
            total_proofs_generated: semantic.total_proofs_generated(),
            global_user_tree_nodes: semantic.global_user_tree_nodes().to_vec(),
            user_contract_tree_nodes: semantic.user_contract_tree_nodes().to_vec(),
            contract_state_tree_nodes: semantic.contract_state_tree_nodes().to_vec(),
            user_leaves: semantic.user_leaves().to_vec(),
            contract_state_imt_leaves: semantic.contract_state_imt_leaves().to_vec(),
            guta_header: semantic.guta_header().to_vec(),
            jobs: semantic.jobs().to_vec(),
            deferred_jobs: semantic.deferred_jobs().to_vec(),
        };
        let legacy = RealmProcessorSemanticOutput::try_from_candidate_parts(legacy_parts)
            .unwrap();
        assert_eq!(
            RealmProcessorApplicationProofWork::try_from_storage(
                PendingGenerationContext::try_from_legacy(15, 17).unwrap(),
                wrong,
                legacy,
            )
            .unwrap_err(),
            RealmProcessorApplicationProofWorkError::ApplicationMismatch
        );
    }

    #[test]
    fn proof_work_is_non_clone_and_not_mutation_authority() {
        let source = include_str!("realm_processor_application_proof_work.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(!production.contains("impl Clone for RealmProcessorApplicationProofWork"));
        assert!(!production.contains("pipeline.apply"));
        assert!(!production.contains("seal_rotation"));
        assert!(!production.contains("authority_head"));
    }
}
