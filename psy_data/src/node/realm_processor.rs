use std::sync::{Arc, RwLock};

use parth_core::{
    generic_traits::psy_debug_printable::PsyDebugPrintable,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::QHashBase,
    QCoreProcCheckpointUniqueId,
};


#[pderive::serialize_copy_hash]
pub struct RealmProcessorCoreState<Hash> {
    pub chain_id: u32,
    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub last_committed_checkpoint_id: u64,
    pub last_committed_unique_pending_id: u64,
    pub last_committed_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub last_committed_checkpoint_root: Hash,
    pub last_committed_realm_start_root: Hash,
    pub last_committed_realm_end_root: Hash,

    pub processing_checkpoint_id: u64,
    pub processing_unique_pending_id: u64,
    pub processing_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub processing_checkpoint_root: Hash,
    pub processing_realm_start_root: Hash,
    pub processing_realm_end_root: Hash,

    pub gathering_checkpoint_id: u64,
    pub gathering_unique_pending_id: u64,
    pub gathering_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    pub gathering_checkpoint_root: Hash,
    pub gathering_realm_start_root: Hash,

    pub coordinator_head_synced_checkpoint_id: u64,
    pub coordinator_head_synced_checkpoint_root: Hash,
    pub should_revert_processing_changes: bool,
}

impl<Hash: QHashBase> PsyDebugPrintable for RealmProcessorCoreState<Hash> {
    fn psy_debug_print(&self) -> String {
        format!("{:#?}", self)
    }
}

impl<Hash: Copy> RealmProcessorCoreState<Hash> {
    #[inline]
    pub fn copy_from(&mut self, source: &RealmProcessorCoreState<Hash>) {
        self.last_committed_checkpoint_id = source.last_committed_checkpoint_id;
        self.last_committed_realm_start_root = source.last_committed_realm_start_root;
        self.last_committed_realm_end_root = source.last_committed_realm_end_root;
        self.last_committed_checkpoint_root = source.last_committed_checkpoint_root;
        self.last_committed_unique_pending_id = source.last_committed_unique_pending_id;
        self.last_committed_proc_checkpoint_unique_id = source.last_committed_proc_checkpoint_unique_id;

        self.processing_checkpoint_id = source.processing_checkpoint_id;
        self.processing_realm_start_root = source.processing_realm_start_root;
        self.processing_realm_end_root = source.processing_realm_end_root;
        self.processing_checkpoint_root = source.processing_checkpoint_root;
        self.processing_unique_pending_id = source.processing_unique_pending_id;
        self.processing_proc_checkpoint_unique_id = source.processing_proc_checkpoint_unique_id;
        self.gathering_checkpoint_id = source.gathering_checkpoint_id;
        self.gathering_realm_start_root = source.gathering_realm_start_root;
        self.gathering_checkpoint_root = source.gathering_checkpoint_root;
        self.gathering_unique_pending_id = source.gathering_unique_pending_id;
        self.gathering_proc_checkpoint_unique_id = source.gathering_proc_checkpoint_unique_id;
        self.coordinator_head_synced_checkpoint_id = source.coordinator_head_synced_checkpoint_id;
        self.coordinator_head_synced_checkpoint_root = source.coordinator_head_synced_checkpoint_root;
        self.should_revert_processing_changes = source.should_revert_processing_changes;
    }
    pub fn new_basic(
        chain_id: u32,
        realm_identifier: QRealmIdentifier,
        last_committed_checkpoint_id: u64,
        last_committed_unique_pending_id: u64,
        last_committed_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
        last_committed_checkpoint_root: Hash,
        last_committed_realm_root: Hash,
    ) -> Self {
        Self {
            chain_id,
            realm_identifier,
            realm_id_u64: realm_identifier.realm_id as u64,
            realm_sub_id_u64: realm_identifier.realm_sub_id as u64,
            last_committed_checkpoint_id,
            last_committed_unique_pending_id,
            last_committed_proc_checkpoint_unique_id,
            last_committed_checkpoint_root,
            last_committed_realm_start_root: last_committed_realm_root,
            last_committed_realm_end_root: last_committed_realm_root,
            processing_checkpoint_id: last_committed_checkpoint_id,
            processing_unique_pending_id: last_committed_unique_pending_id,
            processing_proc_checkpoint_unique_id: last_committed_proc_checkpoint_unique_id,
            processing_checkpoint_root: last_committed_checkpoint_root,
            processing_realm_start_root: last_committed_realm_root,
            processing_realm_end_root: last_committed_realm_root,
            gathering_checkpoint_id: last_committed_checkpoint_id,
            gathering_unique_pending_id: last_committed_unique_pending_id,
            gathering_proc_checkpoint_unique_id: last_committed_proc_checkpoint_unique_id,
            gathering_checkpoint_root: last_committed_checkpoint_root,
            gathering_realm_start_root: last_committed_realm_root,
            coordinator_head_synced_checkpoint_id: last_committed_checkpoint_id,
            coordinator_head_synced_checkpoint_root: last_committed_checkpoint_root,
            should_revert_processing_changes: false,
        }
    }
    pub fn commit_processing(&mut self) -> anyhow::Result<()> {
        self.last_committed_checkpoint_id = self.processing_checkpoint_id;
        self.last_committed_realm_start_root = self.processing_realm_start_root;
        self.last_committed_realm_end_root = self.processing_realm_end_root;
        self.last_committed_checkpoint_root = self.processing_checkpoint_root;
        self.last_committed_unique_pending_id = self.processing_unique_pending_id;
        self.last_committed_proc_checkpoint_unique_id = self.processing_proc_checkpoint_unique_id;
        self.should_revert_processing_changes = false;
        Ok(())
    }
    pub fn finish_gathering(
        &mut self,
        gathering_realm_end_root: Hash,
        new_synced_checkpoint_id: u64,
        new_sycned_checkpoint_root: Hash,
        new_gathering_unique_pending_id: u64,
        new_gathering_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<()> {
        if self.should_revert_processing_changes {
            anyhow::bail!("needs to revert before applying new unique ids")
        }
        self.processing_checkpoint_id = self.gathering_checkpoint_id;
        self.processing_realm_start_root = self.gathering_realm_start_root;
        self.processing_realm_end_root = gathering_realm_end_root;
        self.processing_checkpoint_root = self.gathering_checkpoint_root;
        self.processing_unique_pending_id = self.gathering_unique_pending_id;
        self.processing_proc_checkpoint_unique_id = self.gathering_proc_checkpoint_unique_id;

        self.gathering_checkpoint_id = new_synced_checkpoint_id;
        self.gathering_checkpoint_root = new_sycned_checkpoint_root;
        self.gathering_realm_start_root = gathering_realm_end_root;
        self.gathering_unique_pending_id = new_gathering_unique_pending_id;
        self.gathering_proc_checkpoint_unique_id = new_gathering_proc_checkpoint_unique_id;
        self.should_revert_processing_changes = false;
        Ok(())
    }
    pub fn revert_processing(
        &mut self,
        new_processing_unique_pending_id: u64,
        new_processing_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
        new_gathering_unique_pending_id: u64,
        new_gathering_proc_checkpoint_unique_id: QCoreProcCheckpointUniqueId,
    ) -> anyhow::Result<()> {
        self.processing_checkpoint_id = self.last_committed_checkpoint_id;
        self.processing_unique_pending_id = new_processing_unique_pending_id;
        self.processing_proc_checkpoint_unique_id = new_processing_proc_checkpoint_unique_id;
        self.processing_realm_start_root = self.last_committed_realm_start_root;
        self.processing_realm_end_root = self.last_committed_realm_end_root;
        self.processing_checkpoint_root = self.last_committed_checkpoint_root;

        self.gathering_checkpoint_id = self.coordinator_head_synced_checkpoint_id;
        self.gathering_unique_pending_id = new_gathering_unique_pending_id;
        self.gathering_proc_checkpoint_unique_id = new_gathering_proc_checkpoint_unique_id;
        self.gathering_realm_start_root = self.last_committed_realm_start_root;
        self.gathering_checkpoint_root = self.coordinator_head_synced_checkpoint_root;
        self.should_revert_processing_changes = true;
        Ok(())
    }

    pub fn update_synced_checkpoint(&mut self, new_synced_checkpoint_id: u64, new_sycned_checkpoint_root: Hash) -> anyhow::Result<()> {
        self.coordinator_head_synced_checkpoint_id = new_synced_checkpoint_id;
        self.coordinator_head_synced_checkpoint_root = new_sycned_checkpoint_root;
        Ok(())
    }
}

impl<Hash: Copy> RealmProcessorCoreState<Hash> {}

#[derive(Clone, Debug)]
pub struct RealmProcessorCoreStateWrapper<Hash> {
    pub inner: Arc<RwLock<RealmProcessorCoreState<Hash>>>,
}

impl<Hash: QHashBase> RealmProcessorCoreStateWrapper<Hash> {
    pub fn new(initial_status: RealmProcessorCoreState<Hash>) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial_status)),
        }
    }
    pub async fn update_from_core_state(&self, source: &RealmProcessorCoreState<Hash>) -> anyhow::Result<()> {
        {
            self.inner.write().map_err(|_| anyhow::anyhow!("error writing to core state rwlock"))?.copy_from(source);
        }
        Ok(())
    }
    pub async fn load_core_state(&self) -> anyhow::Result<RealmProcessorCoreState<Hash>> {
        let state = {
            self.inner.read().map_err(|_| anyhow::anyhow!("error reading from core state rwlock"))?.clone()
        };
        Ok(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{pgoldilocks::QHashOut, utils::QPGenRandom, PF};

    type Hash = QHashOut<PF>;

    fn state() -> RealmProcessorCoreState<Hash> {
        RealmProcessorCoreState::new_basic(
            9,
            QRealmIdentifier::new(3, 4),
            10,
            11,
            QCoreProcCheckpointUniqueId::qp_rand_gen(),
            Hash::qp_rand_gen(),
            Hash::qp_rand_gen(),
        )
    }

    #[test]
    fn lifecycle_moves_gathering_processing_and_committed_state() {
        let mut value = state();
        assert_eq!(value.realm_id_u64, value.realm_identifier.realm_id as u64);
        assert_eq!(value.realm_sub_id_u64, value.realm_identifier.realm_sub_id as u64);
        assert!(value.psy_debug_print().contains("RealmProcessorCoreState"));

        value.update_synced_checkpoint(20, Hash::qp_rand_gen()).unwrap();
        let end_root = Hash::qp_rand_gen();
        value.finish_gathering(
            end_root,
            21,
            Hash::qp_rand_gen(),
            22,
            QCoreProcCheckpointUniqueId::qp_rand_gen(),
        ).unwrap();
        assert_eq!(value.processing_realm_end_root, end_root);
        value.commit_processing().unwrap();
        assert_eq!(value.last_committed_realm_end_root, end_root);

        value.revert_processing(
            30,
            QCoreProcCheckpointUniqueId::qp_rand_gen(),
            31,
            QCoreProcCheckpointUniqueId::qp_rand_gen(),
        ).unwrap();
        assert!(value.should_revert_processing_changes);
        assert!(value.finish_gathering(Hash::qp_rand_gen(), 40, Hash::qp_rand_gen(), 41, QCoreProcCheckpointUniqueId::qp_rand_gen()).is_err());
    }

    #[tokio::test]
    async fn wrapper_loads_and_replaces_core_state() {
        let original = state();
        let wrapper = RealmProcessorCoreStateWrapper::new(original);
        assert_eq!(wrapper.load_core_state().await.unwrap().chain_id, 9);
        let mut replacement = state();
        replacement.chain_id = 77;
        replacement.processing_checkpoint_id = 88;
        wrapper.update_from_core_state(&replacement).await.unwrap();
        let loaded = wrapper.load_core_state().await.unwrap();
        assert_eq!(loaded.chain_id, 9, "copy_from intentionally preserves identity fields");
        assert_eq!(loaded.processing_checkpoint_id, 88);
    }
}
