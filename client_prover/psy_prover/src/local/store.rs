use std::collections::HashMap;

use psy_client_common::data::base_types::hash256::Hash256;

#[derive(Clone, Debug)]
pub struct UserProverWorkerStore {
    pub results: HashMap<Hash256, Vec<u8>>,
}
impl UserProverWorkerStore {
    pub fn new() -> Self {
        Self { results: HashMap::new() }
    }
    pub fn get_result(&self, key: &Hash256) -> Option<&Vec<u8>> {
        self.results.get(key)
    }
    pub fn get_result_and_clear(&mut self, key: &Hash256) -> Option<Vec<u8>> {
        self.results.remove(key)
    }
    pub fn set_result(&mut self, key: Hash256, value: Vec<u8>) {
        self.results.insert(key, value);
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn result_lifecycle_supports_read_replace_and_clear() {
        let key = Hash256([9; 32]);
        let mut store = UserProverWorkerStore::new();

        assert!(store.get_result(&key).is_none());
        assert!(store.get_result_and_clear(&key).is_none());

        store.set_result(key, vec![1, 2, 3]);
        assert_eq!(store.get_result(&key), Some(&vec![1, 2, 3]));

        store.set_result(key, vec![4, 5]);
        assert_eq!(store.get_result_and_clear(&key), Some(vec![4, 5]));
        assert!(store.get_result(&key).is_none());
    }
}
