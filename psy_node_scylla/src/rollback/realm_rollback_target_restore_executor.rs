//! Storage-private executor for one Realm's post-delete control-state restore.
//!
//! The immutable plan is persisted before this executor can run. Every mutable
//! row is classified as either the exact predecessor or exact deterministic
//! candidate, making each step restartable without accepting a mixed branch.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::{
        AuthorityClockSampleUs, AuthorityIntentObservation, AuthorityTimestampKey,
        AuthorityTimestampPhase, AuthorityTimestampReadState, ObservedAuthorityTimestampState,
    },
    authority_local_head::{
        AuthorityLocalHeadReadState, SealedAuthorityLocalHeadCas,
    },
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::PendingPipelineReadState,
};
use sha2::{Digest, Sha256};

use super::{
    BranchExactWriterAuthorityKey, BranchExactWriterReadState,
    PendingCounterAdapter, PendingCounterAllocationOutcome,
    ScyllaAuthorityLocalHeadStore, ScyllaAuthorityTimestampStore,
    ScyllaBranchExactWriterLifecycleStore, ScyllaPendingPipelineStore,
    SealedBranchExactWriterCas,
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackTargetRestoreCompletion,
        PersistedRealmRollbackTargetRestorePlan, ScyllaRealmRollbackPhysicalArchiveStore,
    },
    realm_rollback_target_restore_planner::ScyllaRealmRollbackTargetRestorePlanner,
    rollback_global_delete_barrier::{
        ScyllaRollbackGlobalDeleteBarrierStore, SelectedRealmRollbackDeleteCompletion,
    },
};

/// Exact final control rows after one Realm restoration. Deliberately
/// non-Clone and not yet the global publish capability.
#[derive(Debug)]
pub(super) struct ExecutedRealmRollbackTargetRestore<Hash> {
    plan: PersistedRealmRollbackTargetRestorePlan<Hash>,
    final_rows_digest: [u8; 32],
}

impl<Hash> ExecutedRealmRollbackTargetRestore<Hash> {
    pub(super) const fn plan(&self) -> &PersistedRealmRollbackTargetRestorePlan<Hash> {
        &self.plan
    }

    pub(super) const fn final_rows_digest(&self) -> &[u8; 32] {
        &self.final_rows_digest
    }
}

pub(super) struct ScyllaRealmRollbackTargetRestoreExecutor {
    planner: Arc<ScyllaRealmRollbackTargetRestorePlanner>,
    global_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
    archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
    local_head: Arc<ScyllaAuthorityLocalHeadStore>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
    timestamp: Arc<ScyllaAuthorityTimestampStore>,
    counter: Arc<PendingCounterAdapter>,
}

impl ScyllaRealmRollbackTargetRestoreExecutor {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        planner: Arc<ScyllaRealmRollbackTargetRestorePlanner>,
        global_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
        archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
        local_head: Arc<ScyllaAuthorityLocalHeadStore>,
        pipeline: Arc<ScyllaPendingPipelineStore>,
        writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
        timestamp: Arc<ScyllaAuthorityTimestampStore>,
        counter: Arc<PendingCounterAdapter>,
    ) -> Self {
        Self {
            planner,
            global_barrier,
            archive,
            local_head,
            pipeline,
            writer,
            timestamp,
            counter,
        }
    }

    pub(super) async fn restore<Hash: Q256BitHash>(
        &self,
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
    ) -> Result<PersistedRealmRollbackTargetRestoreCompletion<Hash>, RealmRollbackTargetRestoreExecutorError>
    {
        let persisted = self.planner.persist_or_recover(selected).await.map_err(backend)?;
        self.global_barrier
            .revalidate_selected_realm(selected)
            .await
            .map_err(backend)?;
        self.archive
            .revalidate_target_restore_plan(&persisted)
            .await
            .map_err(backend)?;
        let plan = persisted.plan();
        let key = AuthorityTimestampKey::new(plan.target().network_id(), plan.authority());

        let reservation = plan
            .source_timestamp()
            .seal_reservation(
                key,
                plan.timestamp_intent(),
                AuthorityClockSampleUs::try_from_i128(
                    i128::from(plan.new_branch_write().as_commit_timestamp().as_i64()),
                )
                .map_err(backend)?,
            )
            .map_err(backend)?;
        if reservation.lease().timestamp()
            != plan.new_branch_write().as_commit_timestamp()
        {
            return Err(RealmRollbackTargetRestoreExecutorError::IdentityMismatch(
                "timestamp reservation",
            ));
        }
        let completion = reservation
            .candidate()
            .seal_completion(key, reservation.lease())
            .map_err(backend)?;

        self.ensure_timestamp_reserved(plan, reservation).await?;
        self.ensure_allocations(plan).await?;
        self.ensure_pipeline(plan).await?;
        self.ensure_timestamp_completed(plan, completion).await?;
        self.ensure_writer(plan).await?;
        self.ensure_local_head(plan).await?;

        // Final bracket: neither global membership nor immutable plan may have
        // changed, and every mutable row must equal its deterministic candidate.
        self.global_barrier
            .revalidate_selected_realm(selected)
            .await
            .map_err(backend)?;
        self.archive
            .revalidate_target_restore_plan(&persisted)
            .await
            .map_err(backend)?;
        let final_rows_digest = self.require_final_rows(plan).await?;
        let executed = ExecutedRealmRollbackTargetRestore {
            plan: persisted,
            final_rows_digest,
        };
        let completion = self.archive.persist_target_restore_completion(&executed).await.map_err(backend)?;
        self.archive.revalidate_target_restore_completion(&completion).await.map_err(backend)?;
        Ok(completion)
    }

    async fn ensure_timestamp_reserved<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
        reservation: psy_node_core::store::authority_commit::SealedAuthorityTimestampReservation,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        let key = reservation.key();
        let current = self.read_timestamp(key).await?;
        match ObservedAuthorityTimestampState::from_selected_row(key, current)
            .observe_intent(plan.timestamp_intent())
        {
            AuthorityIntentObservation::Idle { .. } if current == plan.source_timestamp() => {
                self.timestamp.reserve(reservation).await.map_err(backend)?;
            }
            AuthorityIntentObservation::Active(lease)
                if lease == reservation.lease() => {}
            AuthorityIntentObservation::Completed { timestamp, revision }
                if timestamp == reservation.lease().timestamp()
                    && revision == reservation.lease().active_revision().checked_next().map_err(backend)? => {}
            _ => return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("timestamp")),
        }
        Ok(())
    }

    async fn ensure_allocations<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        for allocation in [plan.processing_allocation().map_err(backend)?, plan.gathering_allocation().map_err(backend)?] {
            let PendingCounterAllocationOutcome::Owned(owned) =
                self.counter.allocate(&allocation).await.map_err(backend)?
            else {
                return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("pending counter"));
            };
            if owned.pending() != allocation.candidate()
                || owned.proc_id() != allocation.proc_id()
                || owned.plan_digest() != allocation.digest()
                || owned.write_timestamp_us() != allocation.write_timestamp_us()
                || owned.write_kind() != allocation.write_kind()
            {
                return Err(RealmRollbackTargetRestoreExecutorError::IdentityMismatch("pending allocation"));
            }
        }
        Ok(())
    }

    async fn ensure_pipeline<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        let transition = plan.source_pipeline().seal_rollback_reset_from_synced_head_contexts(
            plan.processing(),
            plan.gathering(),
            *plan.source_head().head().chain(),
            plan.restored_observation().map_err(backend)?,
            plan.target_processed_pending_id(),
        ).map_err(backend)?;
        let key = PendingGenerationLedgerKey::new(plan.target().network_id(), plan.authority());
        match self.pipeline.read::<Hash>(key).await.map_err(backend)? {
            PendingPipelineReadState::Current(current) if &current == transition.expected() => {
                self.pipeline.apply(&transition).await.map_err(backend)?;
            }
            PendingPipelineReadState::Current(current) if &current == transition.candidate() => {}
            _ => return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("pipeline")),
        }
        Ok(())
    }

    async fn ensure_timestamp_completed<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
        completion: psy_node_core::store::authority_commit::SealedAuthorityTimestampCompletion,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        let current = self.read_timestamp(completion.key()).await?;
        if current == completion.expected() {
            self.timestamp.complete(completion).await.map_err(backend)?;
        } else if current != completion.candidate() {
            return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("timestamp completion"));
        }
        let final_state = self.read_timestamp(completion.key()).await?;
        if final_state != completion.candidate()
            || !matches!(
                final_state.phase(),
                AuthorityTimestampPhase::Idle { last_completed: Some(intent) }
                    if intent == plan.timestamp_intent()
            )
        {
            return Err(RealmRollbackTargetRestoreExecutorError::IdentityMismatch("timestamp completion"));
        }
        Ok(())
    }

    async fn ensure_writer<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        let key = AuthorityTimestampKey::new(plan.target().network_id(), plan.authority());
        let completed = self.read_timestamp(key).await?;
        let transition = SealedBranchExactWriterCas::rollback_restore(
            plan.source_writer(),
            plan.restored_writer_watermark().map_err(backend)?,
            ObservedAuthorityTimestampState::from_selected_row(key, completed),
            *plan.digest(),
        ).map_err(backend)?;
        let writer_key = BranchExactWriterAuthorityKey::new(plan.target().network_id(), plan.authority());
        match self.writer.read::<Hash>(writer_key).await.map_err(backend)? {
            BranchExactWriterReadState::Current(current) if &current == transition.expected() => {
                self.writer.compare_and_set(&transition).await.map_err(backend)?;
            }
            BranchExactWriterReadState::Current(current) if &current == transition.candidate() => {}
            _ => return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("writer")),
        }
        Ok(())
    }

    async fn ensure_local_head<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
    ) -> Result<(), RealmRollbackTargetRestoreExecutorError> {
        let transition = SealedAuthorityLocalHeadCas::seal_rollback_restore(
            plan.source_head().clone(),
            plan.target_head(),
            plan.rollback_epoch(),
            plan.new_branch_write().as_commit_timestamp(),
        ).map_err(backend)?;
        match self.local_head.read(transition.key()).await.map_err(backend)? {
            AuthorityLocalHeadReadState::Current(current) if &current == transition.expected() => {
                self.local_head.compare_and_set(&transition).await.map_err(backend)?;
            }
            AuthorityLocalHeadReadState::Current(current) if &current == transition.candidate() => {}
            _ => return Err(RealmRollbackTargetRestoreExecutorError::ConcurrentMutation("local head")),
        }
        Ok(())
    }

    async fn require_final_rows<Hash: Q256BitHash>(
        &self,
        plan: &super::realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan<Hash>,
    ) -> Result<[u8; 32], RealmRollbackTargetRestoreExecutorError> {
        let timestamp_key = AuthorityTimestampKey::new(plan.target().network_id(), plan.authority());
        let reservation = plan.source_timestamp().seal_reservation(
            timestamp_key,
            plan.timestamp_intent(),
            AuthorityClockSampleUs::try_from_i128(i128::from(plan.new_branch_write().as_commit_timestamp().as_i64())).map_err(backend)?,
        ).map_err(backend)?;
        let timestamp = reservation.candidate().seal_completion(timestamp_key, reservation.lease()).map_err(backend)?.candidate();
        let pipeline = plan.source_pipeline().seal_rollback_reset_contexts(
            plan.processing(), plan.gathering(), plan.restored_observation().map_err(backend)?,
            plan.target_processed_pending_id(),
        ).map_err(backend)?;
        let writer = SealedBranchExactWriterCas::rollback_restore(
            plan.source_writer(), plan.restored_writer_watermark().map_err(backend)?,
            ObservedAuthorityTimestampState::from_selected_row(timestamp_key, timestamp), *plan.digest(),
        ).map_err(backend)?;
        let head = SealedAuthorityLocalHeadCas::seal_rollback_restore(
            plan.source_head().clone(), plan.target_head(), plan.rollback_epoch(),
            plan.new_branch_write().as_commit_timestamp(),
        ).map_err(backend)?;
        let pipeline_key = PendingGenerationLedgerKey::new(plan.target().network_id(), plan.authority());
        let writer_key = BranchExactWriterAuthorityKey::new(plan.target().network_id(), plan.authority());
        let current_pipeline = self.pipeline.read::<Hash>(pipeline_key).await.map_err(backend)?;
        let current_writer = self.writer.read::<Hash>(writer_key).await.map_err(backend)?;
        let current_head = self.local_head.read(timestamp_key).await.map_err(backend)?;
        let current_timestamp = self.read_timestamp(timestamp_key).await?;
        let current_counter = self.counter.observe_counter().await.map_err(backend)?;
        if current_timestamp != timestamp
            || !matches!(current_pipeline, PendingPipelineReadState::Current(current) if current == *pipeline.candidate())
            || !matches!(current_writer, BranchExactWriterReadState::Current(current) if current == *writer.candidate())
            || !matches!(current_head, AuthorityLocalHeadReadState::Current(current) if current == *head.candidate())
            || current_counter != super::PendingCounterReadState::Current(plan.gathering().pending_id())
        {
            return Err(RealmRollbackTargetRestoreExecutorError::IdentityMismatch("final control rows"));
        }
        let mut hasher = Sha256::new();
        hasher.update(b"psy.rollback.realm-target-restored-rows.v1\0");
        hasher.update(current_timestamp.revision().get().to_be_bytes());
        hasher.update(current_timestamp.encode_canonical());
        hasher.update(pipeline.candidate().revision().get().to_be_bytes());
        hasher.update(pipeline.candidate().canonical_payload());
        hasher.update(writer.candidate().revision().get().to_be_bytes());
        hasher.update(writer.candidate().to_canonical_bytes());
        hasher.update(head.candidate().revision().get().to_be_bytes());
        hasher.update(head.candidate().encode_canonical());
        hasher.update(plan.gathering().pending_id().get().to_be_bytes());
        hasher.update(plan.processing_allocation().map_err(backend)?.digest().as_bytes());
        hasher.update(plan.gathering_allocation().map_err(backend)?.digest().as_bytes());
        Ok(hasher.finalize().into())
    }

    async fn read_timestamp(
        &self,
        key: AuthorityTimestampKey,
    ) -> Result<psy_node_core::store::authority_commit::StoredAuthorityTimestampState, RealmRollbackTargetRestoreExecutorError> {
        match self.timestamp.read(key).await.map_err(backend)? {
            AuthorityTimestampReadState::Current(current) => Ok(current),
            AuthorityTimestampReadState::Uninitialized => Err(RealmRollbackTargetRestoreExecutorError::Missing("timestamp")),
        }
    }
}

fn backend(error: impl fmt::Display) -> RealmRollbackTargetRestoreExecutorError {
    RealmRollbackTargetRestoreExecutorError::Backend(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackTargetRestoreExecutorError {
    Missing(&'static str),
    IdentityMismatch(&'static str),
    ConcurrentMutation(&'static str),
    Backend(String),
}

impl fmt::Display for RealmRollbackTargetRestoreExecutorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm target restore executor error: {self:?}")
    }
}

impl Error for RealmRollbackTargetRestoreExecutorError {}

#[cfg(test)]
mod tests {
    #[test]
    fn executor_is_plan_first_and_head_last() {
        let source = include_str!("realm_rollback_target_restore_executor.rs");
        let method = source.split("pub(super) async fn restore").nth(1).unwrap();
        let plan = method.find("persist_or_recover").unwrap();
        let reserve = method.find("ensure_timestamp_reserved").unwrap();
        let allocations = method.find("ensure_allocations").unwrap();
        let pipeline = method.find("ensure_pipeline").unwrap();
        let writer = method.find("ensure_writer").unwrap();
        let head = method.find("ensure_local_head").unwrap();
        assert!(plan < reserve && reserve < allocations && allocations < pipeline);
        assert!(pipeline < writer && writer < head);
        assert!(!method.contains("seal_rollback_reset("));
    }
}
