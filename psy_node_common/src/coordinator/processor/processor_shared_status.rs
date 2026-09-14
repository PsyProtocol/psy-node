use std::sync::{Arc, RwLock};

use parth_core::{felt::QFelt, protocol::core_types::QHashBase};
use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState};

#[pderive::serialize_copy_f_hash_ts]
#[ts(export, concrete(F = parth_core::PF, Hash = parth_core::PHash))]
pub struct PsyCoordinatorProcessorSharedStatus<F, Hash> {
    pub last_committed_checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub last_committed_checkpoint_leaf: PQEDCheckpointLeaf<F, Hash>,
    pub last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots<Hash>,
    pub should_revert_last_changes: bool,
    pub block_state: QEDL2BlockState,
}

#[derive(Clone, Debug)]
pub struct PsyCoordinatorProcessorSharedStatusWrapper<F, Hash> {
    pub inner: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>>,
}

impl<F: QFelt, Hash: QHashBase> PsyCoordinatorProcessorSharedStatusWrapper<F, Hash> {
    pub fn new(initial_status: PsyCoordinatorProcessorSharedStatus<F, Hash>) -> Self {
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
        shared_status: PsyCoordinatorProcessorSharedStatus<F, Hash>,
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
mod tests {
    use parth_core::{utils::QPGenRandom, PHash, PF};
    use psy_data::v1::qdata::checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState};

    use super::{PsyCoordinatorProcessorSharedStatus, PsyCoordinatorProcessorSharedStatusWrapper};

    fn sample_status(unique_pending_id: u64, checkpoint_id: u64) -> PsyCoordinatorProcessorSharedStatus<PF, PHash> {
        PsyCoordinatorProcessorSharedStatus {
            last_committed_checkpoint_id: checkpoint_id,
            unique_pending_id,
            last_committed_checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots::qp_rand_gen(),
            should_revert_last_changes: false,
            block_state: QEDL2BlockState {
                checkpoint_id,
                next_add_withdrawal_id: 0,
                next_process_withdrawal_id: 0,
                next_deposit_id: 0,
                total_deposits_claimed_epoch: 0,
                next_user_id: 42,
                end_balance: 0,
                next_contract_id: 0,
            },
        }
    }

    #[test]
    fn revert_last_changes_flags_revert_and_updates_pending_id() -> anyhow::Result<()> {
        let wrapper = PsyCoordinatorProcessorSharedStatusWrapper::<PF, PHash>::new(sample_status(1, 5));
        wrapper.revert_last_changes(9)?;

        let status = wrapper.inner.read().unwrap();
        assert!(status.should_revert_last_changes);
        assert_eq!(status.unique_pending_id, 9);
        // the committed checkpoint fields are untouched by a revert request
        assert_eq!(status.last_committed_checkpoint_id, 5);
        Ok(())
    }

    #[test]
    fn update_status_overwrites_every_tracked_field() -> anyhow::Result<()> {
        let wrapper = PsyCoordinatorProcessorSharedStatusWrapper::<PF, PHash>::new(sample_status(1, 5));
        let leaf = PQEDCheckpointLeaf::<PF, PHash>::qp_rand_gen();
        let expected_chain_root = leaf.global_chain_root;
        let state_roots = PQEDCheckpointGlobalStateRoots::<PHash>::qp_rand_gen();
        let expected_user_tree_root = state_roots.user_tree_root;
        let block_state = QEDL2BlockState {
            checkpoint_id: 6,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: 50,
            end_balance: 0,
            next_contract_id: 0,
        };

        wrapper.update_status(2, 6, leaf, state_roots, block_state, true)?;

        let status = wrapper.inner.read().unwrap();
        assert_eq!(status.unique_pending_id, 2);
        assert_eq!(status.last_committed_checkpoint_id, 6);
        assert_eq!(status.last_committed_checkpoint_leaf.global_chain_root, expected_chain_root);
        assert_eq!(status.last_committed_checkpoint_state_roots.user_tree_root, expected_user_tree_root);
        assert_eq!(status.block_state.checkpoint_id, 6);
        assert_eq!(status.block_state.next_user_id, 50);
        assert!(status.should_revert_last_changes);
        Ok(())
    }

    #[test]
    fn update_status_from_shared_status_copies_the_full_snapshot() -> anyhow::Result<()> {
        let wrapper = PsyCoordinatorProcessorSharedStatusWrapper::<PF, PHash>::new(sample_status(1, 5));
        let new_status = sample_status(3, 8);
        let expected_chain_root = new_status.last_committed_checkpoint_leaf.global_chain_root;
        let expected_next_user_id = new_status.block_state.next_user_id;

        wrapper.update_status_from_shared_status(new_status)?;

        let status = wrapper.inner.read().unwrap();
        assert_eq!(status.unique_pending_id, 3);
        assert_eq!(status.last_committed_checkpoint_id, 8);
        assert_eq!(status.last_committed_checkpoint_leaf.global_chain_root, expected_chain_root);
        assert_eq!(status.block_state.next_user_id, expected_next_user_id);
        assert!(!status.should_revert_last_changes);
        Ok(())
    }

    #[test]
    fn wrapper_clones_share_one_lock() -> anyhow::Result<()> {
        let wrapper = PsyCoordinatorProcessorSharedStatusWrapper::<PF, PHash>::new(sample_status(1, 5));
        let clone = wrapper.clone();
        clone.revert_last_changes(77)?;

        let status = wrapper.inner.read().unwrap();
        assert!(status.should_revert_last_changes);
        assert_eq!(status.unique_pending_id, 77);
        Ok(())
    }
}