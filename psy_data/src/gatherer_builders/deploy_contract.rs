use crate::v1::qdata::contract::ContractCodeDefinitionWithContractId;


#[pderive::serialize_clone]
pub struct PsyDeployContractsGathererBuilderResult {
    pub new_next_contract_id_u64: u64,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
}