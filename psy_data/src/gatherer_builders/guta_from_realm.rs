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

#[cfg(test)]
mod tests {
    use crate::v1::qdata::contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId};

    use super::*;

    #[test]
    fn node_update_exposes_job_id_index_and_hash() {
        let update = RealmGUTANodeUpdateWithJobId::<u64, u64> {
            job_id: 42,
            node_index: 9,
            new_node_hash: 0xdead_beef,
        };
        assert_eq!(update.job_id, 42);
        assert_eq!(update.node_index, 9);
        assert_eq!(update.new_node_hash, 0xdead_beef);
    }

    #[test]
    fn gatherer_result_clones_compares_and_serializes() {
        let result = PsyCoordinatorGUTAFromRealmGathererBuilderResult {
            new_next_contract_id_u64: 11,
            update_contract_function_tree_nodes_ffs: vec![1, 2],
            new_contract_leaves_ffs: vec![3],
            new_contract_code_definitions: vec![ContractCodeDefinitionWithContractId::new(
                5,
                ContractCodeDefinition { state_tree_height: 8, functions: vec![] },
            )],
        };
        let clone = result.clone();
        assert_eq!(clone, result);
        assert_eq!(clone.new_next_contract_id_u64, 11);
        assert_eq!(clone.new_contract_code_definitions[0].contract_id, 5);

        let mut set = std::collections::HashSet::new();
        assert!(set.insert(result));
        assert!(!set.insert(clone.clone()));
        assert_eq!(set.len(), 1);

        let json = serde_json::to_string(&clone).unwrap();
        let restored: PsyCoordinatorGUTAFromRealmGathererBuilderResult = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, clone);
    }
}