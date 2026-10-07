use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use psy_client_data::qdata::contract::ContractCodeDefinition;

// Function resolution and common circuit data for each contract a prove-proxy
// client has called. Every contract call used to fetch both again, uploading
// the whole contract code (about 440 KB for the token contract) each time.
//
// Entries are tied to the contract code they were resolved for. A lookup with
// different code misses, and storing a resolution for new code drops all of
// the contract's old entries, so an upgraded contract is never served stale
// data. Common data is only cached under a contract whose code was seen.
// `R` is a resolved function, `V` a function's common circuit data.
pub struct ContractFunctionCache<R, V> {
    contracts: Mutex<HashMap<u64, ContractEntry<R, V>>>,
}

struct ContractEntry<R, V> {
    code: Arc<ContractCodeDefinition>,
    by_method_id: HashMap<u32, R>,
    by_method_name: HashMap<String, R>,
    common_data: HashMap<u32, V>,
}

#[derive(Clone, Copy)]
pub enum Method<'a> {
    Id(u32),
    Name(&'a str),
}

impl<R, V> std::fmt::Debug for ContractFunctionCache<R, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContractFunctionCache").finish_non_exhaustive()
    }
}

impl<R, V> Default for ContractFunctionCache<R, V> {
    fn default() -> Self {
        Self {
            contracts: Mutex::new(HashMap::new()),
        }
    }
}

impl<R: Clone, V: Clone> ContractFunctionCache<R, V> {
    pub fn resolved(&self, contract_id: u64, code: &ContractCodeDefinition, method: Method<'_>) -> Option<R> {
        let contracts = self.contracts.lock().unwrap();
        let entry = contracts.get(&contract_id).filter(|entry| *entry.code == *code)?;
        match method {
            Method::Id(id) => entry.by_method_id.get(&id).cloned(),
            Method::Name(name) => entry.by_method_name.get(name).cloned(),
        }
    }

    pub fn store_resolved(&self, contract_id: u64, code: &ContractCodeDefinition, method: Method<'_>, resolved: R) {
        let mut contracts = self.contracts.lock().unwrap();
        let entry = contracts.entry(contract_id).or_insert_with(|| ContractEntry::new(code));
        if *entry.code != *code {
            *entry = ContractEntry::new(code);
        }
        match method {
            Method::Id(id) => entry.by_method_id.insert(id, resolved),
            Method::Name(name) => entry.by_method_name.insert(name.to_string(), resolved),
        };
    }

    pub fn common_data(&self, contract_id: u64, fn_id: u32) -> Option<V> {
        let contracts = self.contracts.lock().unwrap();
        contracts.get(&contract_id)?.common_data.get(&fn_id).cloned()
    }

    pub fn store_common_data(&self, contract_id: u64, fn_id: u32, data: V) {
        let mut contracts = self.contracts.lock().unwrap();
        if let Some(entry) = contracts.get_mut(&contract_id) {
            entry.common_data.insert(fn_id, data);
        }
    }
}

impl<R, V> ContractEntry<R, V> {
    fn new(code: &ContractCodeDefinition) -> Self {
        Self {
            code: Arc::new(code.clone()),
            by_method_id: HashMap::new(),
            by_method_name: HashMap::new(),
            common_data: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(state_tree_height: u16) -> ContractCodeDefinition {
        ContractCodeDefinition {
            state_tree_height,
            functions: vec![],
        }
    }

    #[test]
    fn resolution_is_served_only_for_the_same_code() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        assert!(cache.resolved(5, &code(1), Method::Id(0)).is_none());
        cache.store_resolved(5, &code(1), Method::Id(0), 3);
        assert_eq!(cache.resolved(5, &code(1), Method::Id(0)).unwrap(), 3);
        assert!(cache.resolved(5, &code(2), Method::Id(0)).is_none());
        assert!(cache.resolved(6, &code(1), Method::Id(0)).is_none());
        assert!(cache.resolved(5, &code(1), Method::Name("faucet")).is_none());
        cache.store_resolved(5, &code(1), Method::Name("faucet"), 4);
        assert_eq!(cache.resolved(5, &code(1), Method::Name("faucet")).unwrap(), 4);
    }

    #[test]
    fn new_code_drops_the_contracts_old_entries() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        cache.store_resolved(5, &code(1), Method::Id(0), 3);
        cache.store_common_data(5, 3, 77);
        assert_eq!(cache.common_data(5, 3), Some(77));

        cache.store_resolved(5, &code(2), Method::Id(1), 4);
        assert!(cache.resolved(5, &code(1), Method::Id(0)).is_none());
        assert!(cache.resolved(5, &code(2), Method::Id(0)).is_none());
        assert_eq!(cache.common_data(5, 3), None);
        assert_eq!(cache.resolved(5, &code(2), Method::Id(1)).unwrap(), 4);
    }

    #[test]
    fn common_data_needs_a_resolved_contract() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        cache.store_common_data(5, 3, 77);
        assert_eq!(cache.common_data(5, 3), None);
        cache.store_resolved(5, &code(1), Method::Id(0), 3);
        cache.store_common_data(5, 3, 77);
        assert_eq!(cache.common_data(5, 3), Some(77));
        assert_eq!(cache.common_data(5, 4), None);
    }
}
