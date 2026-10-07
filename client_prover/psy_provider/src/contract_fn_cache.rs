use std::{collections::HashMap, sync::Mutex};

use psy_client_data::qdata::contract::ContractCodeDefinition;

// Function resolution and common circuit data for each contract a prove-proxy
// client has called. Every contract call used to fetch both again, uploading
// the whole contract code (about 440 KB for the token contract) each time.
//
// A contract's entry belongs to one version of its code, identified by a
// generation. A request with different code starts a new generation and drops
// the old entries. Every fetch carries the generation it started under, and
// its response is stored only while that generation is current, so a response
// for an older version that arrives late is discarded rather than served for
// the new one.
//
// Limit: the common-data request names only (contract, fn_id), and the proxy
// answers from whatever version it has registered. While callers use two code
// versions of one contract at once, around an upgrade, an entry can hold data
// the proxy computed for the other version. Closing that needs the code or a
// version in the proxy request.
pub struct ContractFunctionCache<R, V> {
    state: Mutex<CacheState<R, V>>,
}

// `R` is a resolved function, `V` a function's common circuit data.
struct CacheState<R, V> {
    contracts: HashMap<u64, ContractEntry<R, V>>,
    next_generation: u64,
}

struct ContractEntry<R, V> {
    generation: Generation,
    code: ContractCodeDefinition,
    by_method_id: HashMap<u32, R>,
    by_method_name: HashMap<String, R>,
    common_data: HashMap<u32, V>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Generation(u64);

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
            state: Mutex::new(CacheState {
                contracts: HashMap::new(),
                next_generation: 0,
            }),
        }
    }
}

impl<R: Clone, V: Clone> ContractFunctionCache<R, V> {
    // Returns the cached resolution, or the generation a fetch must store
    // under. Code that differs from the cached version becomes the current one.
    pub fn resolved(&self, contract_id: u64, code: &ContractCodeDefinition, method: Method<'_>) -> Result<R, Generation> {
        let mut state = self.state.lock().unwrap();
        let entry = state.current_entry(contract_id, code);
        let hit = match method {
            Method::Id(id) => entry.by_method_id.get(&id).cloned(),
            Method::Name(name) => entry.by_method_name.get(name).cloned(),
        };
        hit.ok_or(entry.generation)
    }

    pub fn store_resolved(&self, contract_id: u64, generation: Generation, method: Method<'_>, resolved: R) {
        let mut state = self.state.lock().unwrap();
        let Some(entry) = state.entry_at(contract_id, generation) else {
            return;
        };
        match method {
            Method::Id(id) => entry.by_method_id.insert(id, resolved),
            Method::Name(name) => entry.by_method_name.insert(name.to_string(), resolved),
        };
    }

    // Returns the cached common data, or the generation a fetch must store
    // under. With no known code version there is nothing to tie the data to,
    // so it is fetched without being cached.
    pub fn common_data(&self, contract_id: u64, fn_id: u32) -> Result<V, Option<Generation>> {
        let state = self.state.lock().unwrap();
        let Some(entry) = state.contracts.get(&contract_id) else {
            return Err(None);
        };
        entry.common_data.get(&fn_id).cloned().ok_or(Some(entry.generation))
    }

    pub fn store_common_data(&self, contract_id: u64, generation: Generation, fn_id: u32, data: V) {
        let mut state = self.state.lock().unwrap();
        if let Some(entry) = state.entry_at(contract_id, generation) {
            entry.common_data.insert(fn_id, data);
        }
    }
}

impl<R, V> CacheState<R, V> {
    fn current_entry(&mut self, contract_id: u64, code: &ContractCodeDefinition) -> &mut ContractEntry<R, V> {
        let outdated = self.contracts.get(&contract_id).is_none_or(|entry| entry.code != *code);
        if outdated {
            let generation = Generation(self.next_generation);
            self.next_generation += 1;
            self.contracts.insert(
                contract_id,
                ContractEntry {
                    generation,
                    code: code.clone(),
                    by_method_id: HashMap::new(),
                    by_method_name: HashMap::new(),
                    common_data: HashMap::new(),
                },
            );
        }
        self.contracts.get_mut(&contract_id).unwrap()
    }

    fn entry_at(&mut self, contract_id: u64, generation: Generation) -> Option<&mut ContractEntry<R, V>> {
        self.contracts.get_mut(&contract_id).filter(|entry| entry.generation == generation)
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
        let generation = cache.resolved(5, &code(1), Method::Id(0)).unwrap_err();
        cache.store_resolved(5, generation, Method::Id(0), 3);
        assert_eq!(cache.resolved(5, &code(1), Method::Id(0)), Ok(3));
        assert!(cache.resolved(6, &code(1), Method::Id(0)).is_err());

        let generation = cache.resolved(5, &code(1), Method::Name("faucet")).unwrap_err();
        cache.store_resolved(5, generation, Method::Name("faucet"), 4);
        assert_eq!(cache.resolved(5, &code(1), Method::Name("faucet")), Ok(4));
        assert!(cache.resolved(5, &code(2), Method::Id(0)).is_err());
    }

    #[test]
    fn new_code_drops_the_contracts_old_entries() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        let old = cache.resolved(5, &code(1), Method::Id(0)).unwrap_err();
        cache.store_resolved(5, old, Method::Id(0), 3);
        cache.store_common_data(5, old, 3, 77);
        assert_eq!(cache.common_data(5, 3), Ok(77));

        let new = cache.resolved(5, &code(2), Method::Id(0)).unwrap_err();
        assert_ne!(old, new);
        assert_eq!(cache.common_data(5, 3), Err(Some(new)));
        assert_eq!(cache.resolved(5, &code(2), Method::Id(0)), Err(new));
    }

    #[test]
    fn common_data_needs_a_known_code_version() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        assert_eq!(cache.common_data(5, 3), Err(None));
        let generation = cache.resolved(5, &code(1), Method::Id(0)).unwrap_err();
        cache.store_common_data(5, generation, 3, 77);
        assert_eq!(cache.common_data(5, 3), Ok(77));
        assert_eq!(cache.common_data(5, 4), Err(Some(generation)));
    }

    // A fetch for the old version is still in flight when the contract is
    // updated. Its late response must not land in the new version's entry.
    #[test]
    fn late_common_data_for_an_old_version_is_discarded() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        cache.resolved(5, &code(1), Method::Id(0)).unwrap_err();
        let old_fetch = cache.common_data(5, 3).unwrap_err().unwrap();

        let new = cache.resolved(5, &code(2), Method::Id(0)).unwrap_err();
        cache.store_common_data(5, old_fetch, 3, 77);
        assert_eq!(cache.common_data(5, 3), Err(Some(new)));

        cache.store_common_data(5, new, 3, 88);
        assert_eq!(cache.common_data(5, 3), Ok(88));
    }

    #[test]
    fn late_resolution_for_an_old_version_is_discarded() {
        let cache = ContractFunctionCache::<u64, u32>::default();
        let old_fetch = cache.resolved(5, &code(1), Method::Id(0)).unwrap_err();
        let new = cache.resolved(5, &code(2), Method::Id(0)).unwrap_err();
        cache.store_resolved(5, old_fetch, Method::Id(0), 3);
        assert_eq!(cache.resolved(5, &code(2), Method::Id(0)), Err(new));
    }
}
