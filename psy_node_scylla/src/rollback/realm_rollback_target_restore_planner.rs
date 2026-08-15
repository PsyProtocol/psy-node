//! Storage-selected persistence owner for one Realm target-restore plan.
//!
//! An existing immutable plan is selected before any mutable source row is
//! inspected, which permits deterministic recovery after one or more later
//! control-state mutations. A missing plan is formed only from two equal,
//! fresh snapshots bracketing its exact IF-NOT-EXISTS persistence.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::{
    authority_commit::{AuthorityTimestampKey, AuthorityTimestampReadState},
    authority_local_head::AuthorityLocalHeadReadState,
    pending_generation_identity::PendingGenerationLedgerKey,
    pending_generation_pipeline::PendingPipelineReadState,
};

use super::{
    BranchExactWriterAuthorityKey, BranchExactWriterReadState, PendingCounterAdapter,
    PendingCounterReadState, ScyllaAuthorityLocalHeadStore,
    ScyllaAuthorityTimestampStore, ScyllaBranchExactWriterLifecycleStore,
    ScyllaPendingPipelineStore,
    realm_rollback_commit_inventory_store::ScyllaRealmRollbackCommitInventoryStore,
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackTargetRestorePlan, ScyllaRealmRollbackPhysicalArchiveStore,
    },
    realm_rollback_target_restore_plan::RealmRollbackTargetRestorePlan,
    rollback_global_delete_barrier::{
        ScyllaRollbackGlobalDeleteBarrierStore, SelectedRealmRollbackDeleteCompletion,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
struct RealmRollbackRestoreSourceSnapshot<Hash> {
    head: psy_node_core::store::authority_local_head::StoredAuthorityLocalHead<Hash>,
    pipeline: psy_node_core::store::pending_generation_pipeline::StoredPendingPipeline<Hash>,
    writer: super::StoredBranchExactWriterLifecycle<Hash>,
    timestamp: psy_node_core::store::authority_commit::ObservedAuthorityTimestampState,
    counter: PendingCounterReadState,
}

pub(super) struct ScyllaRealmRollbackTargetRestorePlanner {
    global_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
    archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
    inventory: Arc<ScyllaRealmRollbackCommitInventoryStore>,
    local_head: Arc<ScyllaAuthorityLocalHeadStore>,
    pipeline: Arc<ScyllaPendingPipelineStore>,
    writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
    timestamp: Arc<ScyllaAuthorityTimestampStore>,
    counter: Arc<PendingCounterAdapter>,
}

impl ScyllaRealmRollbackTargetRestorePlanner {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        global_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
        archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
        inventory: Arc<ScyllaRealmRollbackCommitInventoryStore>,
        local_head: Arc<ScyllaAuthorityLocalHeadStore>,
        pipeline: Arc<ScyllaPendingPipelineStore>,
        writer: Arc<ScyllaBranchExactWriterLifecycleStore>,
        timestamp: Arc<ScyllaAuthorityTimestampStore>,
        counter: Arc<PendingCounterAdapter>,
    ) -> Self {
        Self { global_barrier, archive, inventory, local_head, pipeline, writer, timestamp, counter }
    }

    pub(super) async fn persist_or_recover<Hash: Q256BitHash>(
        &self,
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
    ) -> Result<PersistedRealmRollbackTargetRestorePlan<Hash>, RealmRollbackTargetRestorePlannerError> {
        self.global_barrier.revalidate_selected_realm(selected).await.map_err(backend)?;
        // The product target is a global height. Select the immutable
        // authority-local marker at that height; never copy the Coordinator
        // hash into a Realm restore plan.
        let target = self.read_target(selected).await?;
        if let Some(existing) = self.archive.read_target_restore_plan_selected(selected).await.map_err(backend)? {
            existing.plan().revalidate_target_entry(&target).map_err(backend)?;
            self.archive.revalidate_target_restore_plan(&existing).await.map_err(backend)?;
            self.global_barrier.revalidate_selected_realm(selected).await.map_err(backend)?;
            let final_target = self.read_target(selected).await?;
            existing.plan().revalidate_target_entry(&final_target).map_err(backend)?;
            return Ok(existing);
        }

        let first = self.read_source(selected).await?;
        let plan = RealmRollbackTargetRestorePlan::try_from_selected(
            selected,
            &target,
            first.head.clone(),
            first.pipeline.clone(),
            first.writer.clone(),
            first.timestamp,
            first.counter,
            *self.archive.fingerprint(),
        ).map_err(backend)?;
        let persisted = self.archive.persist_target_restore_plan(plan).await.map_err(backend)?;

        self.global_barrier.revalidate_selected_realm(selected).await.map_err(backend)?;
        let second_target = self.read_target(selected).await?;
        persisted.plan().revalidate_target_entry(&second_target).map_err(backend)?;
        let second = self.read_source(selected).await?;
        if second != first {
            // The immutable plan may exist, but no mutation authority is
            // returned from a torn predecessor snapshot. A fresh retry sees
            // the same plan first and can classify the durable current state.
            return Err(RealmRollbackTargetRestorePlannerError::ConcurrentMutation);
        }
        self.archive.revalidate_target_restore_plan(&persisted).await.map_err(backend)?;
        Ok(persisted)
    }

    async fn read_target<Hash: Q256BitHash>(
        &self,
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
    ) -> Result<super::realm_rollback_commit_inventory_store::VerifiedRealmRollbackTarget<Hash>, RealmRollbackTargetRestorePlannerError> {
        self.inventory.read_rollback_target(
            selected.completion().authority(),
            selected.barrier().target().network_id(),
            selected.barrier().target().chain_epoch(),
            selected.barrier().target().checkpoint().checkpoint_id().get(),
        ).await.map_err(backend)
    }

    async fn read_source<Hash: Q256BitHash>(
        &self,
        selected: &SelectedRealmRollbackDeleteCompletion<Hash>,
    ) -> Result<RealmRollbackRestoreSourceSnapshot<Hash>, RealmRollbackTargetRestorePlannerError> {
        let network = selected.barrier().target().network_id();
        let authority = selected.completion().authority();
        let timestamp_key = AuthorityTimestampKey::new(network, authority);
        let pipeline_key = PendingGenerationLedgerKey::new(network, authority);
        let writer_key = BranchExactWriterAuthorityKey::new(network, authority);
        let AuthorityLocalHeadReadState::Current(head) = self.local_head.read(timestamp_key).await.map_err(backend)? else {
            return Err(RealmRollbackTargetRestorePlannerError::MissingSource("local head"));
        };
        let PendingPipelineReadState::Current(pipeline) = self.pipeline.read(pipeline_key).await.map_err(backend)? else {
            return Err(RealmRollbackTargetRestorePlannerError::MissingSource("pipeline"));
        };
        let BranchExactWriterReadState::Current(writer) = self.writer.read(writer_key).await.map_err(backend)? else {
            return Err(RealmRollbackTargetRestorePlannerError::MissingSource("writer"));
        };
        let AuthorityTimestampReadState::Current(timestamp) = self.timestamp.read(timestamp_key).await.map_err(backend)? else {
            return Err(RealmRollbackTargetRestorePlannerError::MissingSource("timestamp"));
        };
        let counter = self.counter.observe_counter().await.map_err(backend)?;
        Ok(RealmRollbackRestoreSourceSnapshot {
            head,
            pipeline,
            writer,
            timestamp: psy_node_core::store::authority_commit::ObservedAuthorityTimestampState::from_selected_row(timestamp_key, timestamp),
            counter,
        })
    }
}

fn backend(error: impl fmt::Display) -> RealmRollbackTargetRestorePlannerError {
    RealmRollbackTargetRestorePlannerError::Backend(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RealmRollbackTargetRestorePlannerError {
    MissingSource(&'static str),
    ConcurrentMutation,
    Backend(String),
}

impl fmt::Display for RealmRollbackTargetRestorePlannerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Realm target restore planner error: {self:?}")
    }
}
impl Error for RealmRollbackTargetRestorePlannerError {}

#[cfg(test)]
mod tests {
    #[test]
    fn planner_source_order_is_plan_before_any_counter_allocation() {
        let source = include_str!("realm_rollback_target_restore_planner.rs");
        let method = source.split("pub(super) async fn persist_or_recover").nth(1).unwrap();
        assert!(method.find("read_target_restore_plan_selected").unwrap()
            < method.find("read_source(selected)").unwrap());
        assert!(method.find("persist_target_restore_plan").unwrap()
            < method.find("let second = self.read_source").unwrap());
        assert!(!method.contains(".allocate("));
    }
}
