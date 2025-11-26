
#[derive(Clone, Debug, Copy, PartialEq, Eq, Default)]
pub struct CoordinatorProcessorInitData {
    pub db_tree_next_contract_id: u64,
    pub db_tree_next_user_registration_id: u64,
}