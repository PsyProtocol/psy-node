//! Production seam for Coordinator rollback maintenance before the global
//! archive barrier.
//!
//! The returned values are observations only.  In particular, an archive
//! preparation does not authorize a delete, target restore, or head publish.

use async_trait::async_trait;
use parth_core::{felt::QFelt64, protocol::core_types::Q256BitHash};
use psy_data::protocol::canonical_chain::{CanonicalChainRef, NetworkId};

use super::canonical_head::StoredCanonicalHead;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorRollbackArchivePreparation<Hash> {
    archiving_head: StoredCanonicalHead<Hash>,
    target: CanonicalChainRef<Hash>,
    plan_digest: [u8; 32],
    readiness_digest: [u8; 32],
    execution_plan_digest: [u8; 32],
    entry_count: u64,
    dataset_digest: [u8; 32],
}

impl<Hash> CoordinatorRollbackArchivePreparation<Hash> {
    pub fn from_storage(
        archiving_head: StoredCanonicalHead<Hash>,
        target: CanonicalChainRef<Hash>,
        plan_digest: [u8; 32],
        readiness_digest: [u8; 32],
        execution_plan_digest: [u8; 32],
        entry_count: u64,
        dataset_digest: [u8; 32],
    ) -> Self {
        Self {
            archiving_head,
            target,
            plan_digest,
            readiness_digest,
            execution_plan_digest,
            entry_count,
            dataset_digest,
        }
    }

    pub const fn archiving_head(&self) -> &StoredCanonicalHead<Hash> {
        &self.archiving_head
    }

    pub const fn target(&self) -> &CanonicalChainRef<Hash> {
        &self.target
    }

    pub const fn plan_digest(&self) -> &[u8; 32] {
        &self.plan_digest
    }

    pub const fn readiness_digest(&self) -> &[u8; 32] {
        &self.readiness_digest
    }

    pub const fn execution_plan_digest(&self) -> &[u8; 32] {
        &self.execution_plan_digest
    }

    pub const fn entry_count(&self) -> u64 {
        self.entry_count
    }

    pub const fn dataset_digest(&self) -> &[u8; 32] {
        &self.dataset_digest
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorRollbackMaintenanceOutcome<Hash> {
    Normal(StoredCanonicalHead<Hash>),
    ArchivePrepared(CoordinatorRollbackArchivePreparation<Hash>),
    AwaitingDownstream(StoredCanonicalHead<Hash>),
}

#[async_trait]
pub trait CoordinatorRollbackMaintenanceExecutor<F, Hash>: Send + Sync
where
    F: QFelt64,
    Hash: Q256BitHash,
{
    async fn prepare_coordinator_archive(
        &self,
        network: NetworkId,
        checkpoint_tree_height: u8,
    ) -> anyhow::Result<CoordinatorRollbackMaintenanceOutcome<Hash>>;
}

#[cfg(test)]
mod tests {
    #[test]
    fn observations_have_no_delete_restore_or_barrier_api() {
        let source = include_str!("rollback_participant_maintenance.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        for forbidden in [
            "delete_suffix",
            "restore_target",
            "publish_head",
            "enter_deleting",
            "archive_barrier_receipt",
        ] {
            assert!(!production.contains(forbidden));
        }
    }
}
