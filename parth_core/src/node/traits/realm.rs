pub trait QRealmEdgeStoreManager {
    fn has_submitted_user_id_for_current_checkpoint(&self, uuid: u128, user_id: u64) -> u64;
    fn mark_user_id_as_submitted_for_current_checkpoint(&self, uuid: u128, user_id: u64, random_number: u64);
}