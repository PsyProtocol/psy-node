use std::sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}};
#[derive(Debug, Clone)]
pub struct GathererMetadata {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub pending_unique_id: Arc<AtomicU64>,
    pub pending_core_proc_id: Arc<RwLock<u128>>,
    pub last_checkpoint_id: Arc<AtomicU64>,
    

    pub next_user_id: Arc<AtomicU64>,
    pub next_contract_id: Arc<AtomicU64>,
}


impl GathererMetadata {
    pub fn new(
        realm_id_u64: u64,
        realm_sub_id_u64: u64,
        pending_unique_id: u64,
        pending_core_proc_id: u128,
        last_checkpoint_id: u64,
        next_user_id: u64,
        next_contract_id: u64,
    ) -> Self {
        Self {
            realm_id_u64,
            realm_sub_id_u64,
            pending_unique_id: Arc::new(AtomicU64::new(pending_unique_id)),
            pending_core_proc_id: Arc::new(RwLock::new(pending_core_proc_id)),
            last_checkpoint_id: Arc::new(AtomicU64::new(last_checkpoint_id)),
            next_user_id: Arc::new(AtomicU64::new(next_user_id)),
            next_contract_id: Arc::new(AtomicU64::new(next_contract_id)),
        }
    }
    pub fn set_next_user_id(&self, user_id: u64) {
        self.next_user_id.store(user_id, Ordering::Relaxed);
    }
    pub fn set_next_contract_id(&self, contract_id: u64) {
        self.next_contract_id.store(contract_id, Ordering::Relaxed);
    }
    pub fn get_next_user_id(&self) -> u64 {
        self.next_user_id.load(Ordering::Relaxed)
    }
    pub fn get_next_contract_id(&self) -> u64 {
        self.next_contract_id.load(Ordering::Relaxed)
    }
    pub fn set_last_checkpoint_id(&self, checkpoint_id: u64) {
        self.last_checkpoint_id.store(checkpoint_id, Ordering::Relaxed);
    }
    pub fn get_last_checkpoint_id(&self) -> u64 {
        self.last_checkpoint_id.load(Ordering::Relaxed)
    }
    pub fn set_pending_unique_id(&self, unique_id: u64) {
        self.pending_unique_id.store(unique_id, Ordering::Relaxed);
    }
    pub fn get_pending_unique_id(&self) -> u64 {
        self.pending_unique_id.load(Ordering::Relaxed)
    }
    pub fn set_pending_core_proc_id(&self, core_proc_id: u128) {
        let mut id_lock = self.pending_core_proc_id.write().unwrap();
        *id_lock = core_proc_id;
    }
    pub fn get_pending_core_proc_id(&self) -> u128 {
        let id_lock = self.pending_core_proc_id.read().unwrap();
        id_lock.clone()
    }
}