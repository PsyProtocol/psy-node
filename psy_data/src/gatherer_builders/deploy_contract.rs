use crate::v1::qdata::contract::ContractCodeDefinitionWithContractId;


#[pderive::serialize_clone]
pub struct PsyDeployContractsGathererBuilderResult {
    pub new_next_contract_id_u64: u64,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
}

#[cfg(test)]
mod tests {
    use crate::v1::qdata::contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId};

    use super::*;

    fn sample_result() -> PsyDeployContractsGathererBuilderResult {
        PsyDeployContractsGathererBuilderResult {
            new_next_contract_id_u64: 7,
            update_global_contract_tree_nodes_ffs: vec![1, 2, 3],
            update_contract_function_tree_nodes_ffs: vec![4, 5],
            new_contract_leaves_ffs: vec![6],
            new_contract_code_definitions: vec![ContractCodeDefinitionWithContractId::new(
                3,
                ContractCodeDefinition { state_tree_height: 16, functions: vec![] },
            )],
        }
    }

    #[test]
    fn result_clones_compares_and_hashes_by_value() {
        let result = sample_result();
        let clone = result.clone();
        assert_eq!(clone, result);
        assert_eq!(clone.new_next_contract_id_u64, 7);
        assert_eq!(clone.update_global_contract_tree_nodes_ffs, vec![1, 2, 3]);
        assert_eq!(clone.new_contract_code_definitions[0].contract_id, 3);

        let mut set = std::collections::HashSet::new();
        assert!(set.insert(result));
        assert!(!set.insert(clone));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn result_serde_roundtrip_preserves_fields() {
        let result = sample_result();
        let json = serde_json::to_string(&result).unwrap();
        let restored: PsyDeployContractsGathererBuilderResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, result);
        assert_eq!(restored.new_contract_code_definitions.len(), 1);
        assert_eq!(restored.new_contract_code_definitions[0].code_definition.state_tree_height, 16);
    }
}