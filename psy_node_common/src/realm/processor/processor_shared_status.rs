use std::sync::{Arc, RwLock};

use parth_core::{felt::QFelt, protocol::core_types::QHashBase};
use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyRealmProcessorSharedStatus<F, Hash> {
    pub last_committed_checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub last_committed_checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub should_revert_last_changes: bool,
    pub block_state: QEDL2BlockState,
}

#[derive(Clone, Debug)]
pub struct PsyRealmProcessorSharedStatusWrapper<F, Hash> {
    pub inner: Arc<RwLock<PsyRealmProcessorSharedStatus<F, Hash>>>,
}

impl<F: QFelt, Hash: QHashBase> PsyRealmProcessorSharedStatusWrapper<F, Hash> {
    pub fn new(initial_status: PsyRealmProcessorSharedStatus<F, Hash>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial_status)),
        }
    }
    pub fn revert_last_changes(&self, new_unique_pending_id: u64) -> anyhow::Result<()> {
        {
            let mut status = self.inner.write().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            status.should_revert_last_changes = true;
            status.unique_pending_id = new_unique_pending_id;
        }
        Ok(())
    }
    pub fn update_status(
        &self,
        gathering_unique_pending_id: u64,
        checkpoint_id: u64,
        checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
        checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
        block_state: QEDL2BlockState,
        should_revert_last_changes: bool,
    ) -> anyhow::Result<()> {
        {
            let mut status = self.inner.write().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            status.unique_pending_id = gathering_unique_pending_id;
            status.last_committed_checkpoint_id = checkpoint_id;
            status.last_committed_checkpoint_leaf = checkpoint_leaf;
            status.last_committed_checkpoint_state_roots = checkpoint_state_roots;
            status.block_state = block_state;
            status.should_revert_last_changes = should_revert_last_changes;
        }
        Ok(())
    }
    pub fn update_status_from_shared_status(
        &self,
        shared_status: PsyRealmProcessorSharedStatus<F, Hash>,
    ) -> anyhow::Result<()> {
        {
            let mut status = self.inner.write().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            status.unique_pending_id = shared_status.unique_pending_id;
            status.last_committed_checkpoint_id = shared_status.last_committed_checkpoint_id;
            status.last_committed_checkpoint_leaf = shared_status.last_committed_checkpoint_leaf;
            status.last_committed_checkpoint_state_roots = shared_status.last_committed_checkpoint_state_roots;
            status.block_state = shared_status.block_state;
            status.should_revert_last_changes = shared_status.should_revert_last_changes;
        }
        Ok(())
    }
}