//! Storage-private global control-state restore orchestration.
//!
//! This owner advances `DELETING -> RESTORING -> VERIFYING` only after exact
//! durable barriers. It deliberately cannot mark runtime backups ready or
//! publish the target; those require a later runtime-rebuild receipt.

#![allow(dead_code)]

use std::{error::Error, fmt, sync::Arc};

use parth_core::protocol::core_types::Q256BitHash;
use psy_node_core::store::canonical_head::{
    CanonicalHeadReadState, CanonicalHeadTransition, StoredCanonicalHead,
};

use super::{
    ScyllaCanonicalHeadStore,
    coordinator_rollback_delete_completion_store::{
        PersistedCoordinatorRollbackDeleteCompletion,
        ScyllaCoordinatorRollbackDeleteCompletionStore,
    },
    realm_rollback_physical_archive_store::{
        PersistedRealmRollbackDeleteCompletion,
        PersistedRealmRollbackTargetRestoreCompletion,
        ScyllaRealmRollbackPhysicalArchiveStore,
    },
    rollback_global_archive_barrier::DeletingRollbackGlobalArchiveBarrier,
    rollback_global_delete_barrier::{
        PersistedRollbackGlobalDeleteBarrier, ScyllaRollbackGlobalDeleteBarrierStore,
    },
    rollback_global_restore_barrier::{
        PersistedRollbackGlobalRestoreBarrier, ScyllaRollbackGlobalRestoreBarrierStore,
    },
    rollback_runtime_rebuild_store::ScyllaRollbackRuntimeRebuildStore,
};

pub(super) struct ScyllaRollbackGlobalRestoreOrchestrator {
    canonical_head: Arc<ScyllaCanonicalHeadStore>,
    coordinator_completion: Arc<ScyllaCoordinatorRollbackDeleteCompletionStore>,
    delete_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
    realm_archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
    restore_barrier: Arc<ScyllaRollbackGlobalRestoreBarrierStore>,
    runtime_rebuild: Arc<ScyllaRollbackRuntimeRebuildStore>,
    counter: Arc<super::PendingCounterAdapter>,
}

impl ScyllaRollbackGlobalRestoreOrchestrator {
    pub(super) fn new(
        canonical_head: Arc<ScyllaCanonicalHeadStore>,
        coordinator_completion: Arc<ScyllaCoordinatorRollbackDeleteCompletionStore>,
        delete_barrier: Arc<ScyllaRollbackGlobalDeleteBarrierStore>,
        realm_archive: Arc<ScyllaRealmRollbackPhysicalArchiveStore>,
        restore_barrier: Arc<ScyllaRollbackGlobalRestoreBarrierStore>,
        runtime_rebuild: Arc<ScyllaRollbackRuntimeRebuildStore>,
        counter: Arc<super::PendingCounterAdapter>,
    ) -> Self {
        Self {
            canonical_head,
            coordinator_completion,
            delete_barrier,
            realm_archive,
            restore_barrier,
            runtime_rebuild,
            counter,
        }
    }

    /// Cross into RESTORING only from the exact DELETING row committed into
    /// the all-participant delete barrier.
    pub(super) async fn begin_restoring<Hash: Q256BitHash>(
        &self,
        delete_barrier: &PersistedRollbackGlobalDeleteBarrier<Hash>,
    ) -> Result<StoredCanonicalHead<Hash>, RollbackGlobalRestoreOrchestratorError> {
        self.delete_barrier.revalidate(delete_barrier).await.map_err(backend)?;
        let transition = CanonicalHeadTransition::begin_rollback_restore(
            *delete_barrier.barrier().deleting_head(),
        )
        .map_err(backend)?
        .seal();
        self.ensure_head_transition(&transition).await?;
        self.delete_barrier.revalidate(delete_barrier).await.map_err(backend)?;
        Ok(*transition.candidate())
    }

    /// Persist the plan-ordered all-Realm control restore barrier and then
    /// enter VERIFYING. A returned receipt remains inert: it is not a runtime
    /// backup-ready or target-publication capability.
    #[allow(clippy::too_many_arguments)]
    pub(super) async fn persist_and_begin_verifying<Hash: Q256BitHash>(
        &self,
        authority: &DeletingRollbackGlobalArchiveBarrier<Hash>,
        delete_barrier: &PersistedRollbackGlobalDeleteBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realm_deletes: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        realm_restores: &[PersistedRealmRollbackTargetRestoreCompletion<Hash>],
    ) -> Result<PersistedRollbackGlobalRestoreBarrier<Hash>, RollbackGlobalRestoreOrchestratorError> {
        let restoring = CanonicalHeadTransition::begin_rollback_restore(
            *delete_barrier.barrier().deleting_head(),
        )
        .map_err(backend)?;
        self.require_head(restoring.candidate()).await?;
        self.revalidate_inputs(delete_barrier, coordinator, realm_deletes, realm_restores).await?;
        let barrier = self.restore_barrier.persist_or_recover(
            authority,
            delete_barrier,
            coordinator,
            realm_deletes,
            realm_restores,
            *self.realm_archive.fingerprint(),
        ).await.map_err(backend)?;
        self.revalidate_inputs(delete_barrier, coordinator, realm_deletes, realm_restores).await?;
        self.restore_barrier.revalidate(&barrier).await.map_err(backend)?;

        // Every local participant must have a durable, storage-selected task
        // before the global phase says VERIFYING. Partial directive writes are
        // harmless and are resumed by exact IFNE readback on retry.
        let coordinator_directive = self
            .runtime_rebuild
            .persist_or_recover_coordinator_directive(&self.counter, &barrier, coordinator)
            .await
            .map_err(backend)?;
        let realm_directives = self
            .runtime_rebuild
            .realm_directives(&barrier, realm_restores)
            .map_err(backend)?;
        for directive in &realm_directives {
            self.runtime_rebuild
                .persist_directive(*directive)
                .await
                .map_err(backend)?;
        }
        self.revalidate_inputs(delete_barrier, coordinator, realm_deletes, realm_restores).await?;
        self.restore_barrier.revalidate(&barrier).await.map_err(backend)?;
        self.runtime_rebuild
            .revalidate_directive(&coordinator_directive)
            .await
            .map_err(backend)?;
        for directive in &realm_directives {
            self.runtime_rebuild
                .revalidate_directive(directive)
                .await
                .map_err(backend)?;
        }

        let verifying = CanonicalHeadTransition::begin_rollback_verify(*restoring.candidate())
            .map_err(backend)?
            .seal();
        self.ensure_head_transition(&verifying).await?;

        self.revalidate_inputs(delete_barrier, coordinator, realm_deletes, realm_restores).await?;
        self.restore_barrier.revalidate(&barrier).await.map_err(backend)?;
        self.runtime_rebuild
            .revalidate_directive(&coordinator_directive)
            .await
            .map_err(backend)?;
        for directive in &realm_directives {
            self.runtime_rebuild
                .revalidate_directive(directive)
                .await
                .map_err(backend)?;
        }
        self.require_head(verifying.candidate()).await?;
        Ok(barrier)
    }

    async fn revalidate_inputs<Hash: Q256BitHash>(
        &self,
        delete_barrier: &PersistedRollbackGlobalDeleteBarrier<Hash>,
        coordinator: &PersistedCoordinatorRollbackDeleteCompletion<Hash>,
        realm_deletes: &[PersistedRealmRollbackDeleteCompletion<Hash>],
        realm_restores: &[PersistedRealmRollbackTargetRestoreCompletion<Hash>],
    ) -> Result<(), RollbackGlobalRestoreOrchestratorError> {
        if realm_deletes.len() != realm_restores.len() {
            return Err(RollbackGlobalRestoreOrchestratorError::IdentityMismatch(
                "Realm completion count",
            ));
        }
        self.delete_barrier.revalidate(delete_barrier).await.map_err(backend)?;
        self.coordinator_completion.revalidate(coordinator).await.map_err(backend)?;
        for (deleted, restored) in realm_deletes.iter().zip(realm_restores) {
            self.realm_archive.revalidate_delete_completion(deleted).await.map_err(backend)?;
            self.realm_archive.revalidate_target_restore_completion(restored).await.map_err(backend)?;
        }
        Ok(())
    }

    async fn ensure_head_transition<Hash: Q256BitHash>(
        &self,
        transition: &psy_node_core::store::canonical_head::SealedCanonicalHeadCas<Hash>,
    ) -> Result<(), RollbackGlobalRestoreOrchestratorError> {
        match self.read_head(transition.candidate().canonical_ref().network_id()).await? {
            current if &current == transition.expected() => {
                self.canonical_head.compare_and_set(transition).await.map_err(backend)?;
            }
            current if &current == transition.candidate() => {}
            _ => return Err(RollbackGlobalRestoreOrchestratorError::ConcurrentMutation("canonical head")),
        }
        self.require_head(transition.candidate()).await
    }

    async fn require_head<Hash: Q256BitHash>(
        &self,
        expected: &StoredCanonicalHead<Hash>,
    ) -> Result<(), RollbackGlobalRestoreOrchestratorError> {
        if self.read_head(expected.canonical_ref().network_id()).await? != *expected {
            return Err(RollbackGlobalRestoreOrchestratorError::ConcurrentMutation("canonical head"));
        }
        Ok(())
    }

    async fn read_head<Hash: Q256BitHash>(
        &self,
        network: psy_data::protocol::canonical_chain::NetworkId,
    ) -> Result<StoredCanonicalHead<Hash>, RollbackGlobalRestoreOrchestratorError> {
        match self.canonical_head.read(network).await.map_err(backend)? {
            CanonicalHeadReadState::Current(current) => Ok(current),
            CanonicalHeadReadState::Uninitialized => {
                Err(RollbackGlobalRestoreOrchestratorError::Missing("canonical head"))
            }
        }
    }
}

fn backend(error: impl fmt::Display) -> RollbackGlobalRestoreOrchestratorError {
    RollbackGlobalRestoreOrchestratorError::Backend(error.to_string())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum RollbackGlobalRestoreOrchestratorError {
    Missing(&'static str),
    IdentityMismatch(&'static str),
    ConcurrentMutation(&'static str),
    Backend(String),
}

impl fmt::Display for RollbackGlobalRestoreOrchestratorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "global restore orchestrator error: {self:?}")
    }
}

impl Error for RollbackGlobalRestoreOrchestratorError {}

#[cfg(test)]
mod tests {
    #[test]
    fn orchestrator_stops_before_runtime_ready_and_target_publish() {
        let source = include_str!("rollback_global_restore_orchestrator.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        assert!(source.contains("begin_rollback_restore"));
        assert!(source.contains("begin_rollback_verify"));
        assert!(source.contains("revalidate_target_restore_completion"));
        assert!(source.contains("persist_directive"));
        assert!(source.contains("revalidate_directive"));
        assert!(!source.contains("complete_rollback_realm_barrier"));
        assert!(!source.contains("complete_rollback("));
        assert!(!source.contains("hard_reset_and_truncate"));
    }
}
