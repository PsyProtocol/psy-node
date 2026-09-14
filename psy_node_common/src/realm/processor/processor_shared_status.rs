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
#[cfg(test)]
mod shared_status_tests {
    use crate::realm::processor::db::realm_db_test_env::RealmDbTestEnv;

    use super::*;

    #[tokio::test]
    async fn shared_status_wrapper_publishes_and_reverts_fields() -> anyhow::Result<()> {
        let env = RealmDbTestEnv::create().await?;
        let sync_info = &env.genesis.coordinator_update.checkpoint_sync_info;
        let leaf = sync_info.checkpoint_leaf.clone();
        let roots = sync_info.state_roots.clone();
        let block_state = sync_info.block_state.clone();

        let initial = PsyRealmProcessorSharedStatus {
            last_committed_checkpoint_id: 0,
            unique_pending_id: 0,
            last_committed_checkpoint_leaf: leaf.clone(),
            last_committed_checkpoint_state_roots: roots.clone(),
            should_revert_last_changes: false,
            block_state: block_state.clone(),
        };
        let wrapper = PsyRealmProcessorSharedStatusWrapper::new(initial);

        // a full status update replaces every published field
        wrapper.update_status(5, 9, leaf.clone(), roots.clone(), block_state.clone(), false)?;
        {
            let status = wrapper.inner.read().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            assert_eq!(status.unique_pending_id, 5);
            assert_eq!(status.last_committed_checkpoint_id, 9);
            assert_eq!(status.last_committed_checkpoint_leaf, leaf);
            assert_eq!(status.last_committed_checkpoint_state_roots, roots);
            assert_eq!(status.block_state, block_state);
            assert!(!status.should_revert_last_changes);
        }

        // a revert only flags the revert and moves the pending id
        wrapper.revert_last_changes(7)?;
        {
            let status = wrapper.inner.read().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            assert!(status.should_revert_last_changes);
            assert_eq!(status.unique_pending_id, 7);
            assert_eq!(status.last_committed_checkpoint_id, 9);
        }

        // bulk copy from another shared status replaces everything again
        let replacement = PsyRealmProcessorSharedStatus {
            last_committed_checkpoint_id: 12,
            unique_pending_id: 8,
            last_committed_checkpoint_leaf: leaf.clone(),
            last_committed_checkpoint_state_roots: roots.clone(),
            should_revert_last_changes: false,
            block_state: block_state.clone(),
        };
        wrapper.update_status_from_shared_status(replacement)?;
        {
            let status = wrapper.inner.read().map_err(|e| anyhow::anyhow!("{:?}", e))?;
            assert_eq!(status.unique_pending_id, 8);
            assert_eq!(status.last_committed_checkpoint_id, 12);
            assert!(!status.should_revert_last_changes);
        }
        Ok(())
    }
}
