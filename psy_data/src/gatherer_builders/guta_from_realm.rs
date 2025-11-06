use crate::v1::qdata::contract::ContractCodeDefinitionWithContractId;

pub struct RealmGUTANodeUpdateWithJobId<Hash, JobId> {
    pub job_id: JobId,
    pub node_index: u64,
    pub new_node_hash: Hash,
}
#[pderive::serialize_clone]
pub struct PsyCoordinatorGUTAFromRealmGathererBuilderResult {
    pub new_next_contract_id_u64: u64,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
}