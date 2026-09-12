use hashbrown::HashMap;

use super::traits::EvalCache;
use crate::dpn::ops::sym_felt::SymFeltRef;

pub struct SimpleEvalCache {
    pub felt_cache: HashMap<SymFeltRef, u64>,
    pub arr_cache: HashMap<SymFeltRef, Box<Vec<u64>>>,
}
impl SimpleEvalCache {
    pub fn new() -> SimpleEvalCache {
        SimpleEvalCache {
            felt_cache: HashMap::new(),
            arr_cache: HashMap::new(),
        }
    }
}
impl EvalCache for SimpleEvalCache {
    fn contains(&self, key: SymFeltRef) -> bool {
        self.felt_cache.contains_key(&key)
    }

    fn get(&self, key: SymFeltRef) -> u64 {
        *self.felt_cache.get(&key).unwrap()
    }

    fn insert(&mut self, key: SymFeltRef, value: u64) {
        self.felt_cache.insert(key, value);
    }

    fn contains_arr(&self, key: SymFeltRef) -> bool {
        self.arr_cache.contains_key(&key)
    }

    fn get_arr_ref(&self, key: SymFeltRef) -> Box<Vec<u64>> {
        Box::clone(self.arr_cache.get(&key).unwrap())
    }

    fn insert_arr(&mut self, key: SymFeltRef, value: Vec<u64>) {
        self.arr_cache.insert(key, Box::new(value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stores_scalar_and_array_values_independently() {
        let scalar_key = SymFeltRef::new_constant(7);
        let array_key = SymFeltRef::new_constant(8);
        let mut cache = SimpleEvalCache::new();

        assert!(!cache.contains(scalar_key));
        assert!(!cache.contains_arr(array_key));

        cache.insert(scalar_key, 42);
        cache.insert_arr(array_key, vec![1, 2, 3]);

        assert!(cache.contains(scalar_key));
        assert_eq!(cache.get(scalar_key), 42);
        assert!(cache.contains_arr(array_key));
        assert_eq!(*cache.get_arr_ref(array_key), vec![1, 2, 3]);
    }

    #[test]
    fn array_reads_are_owned_copies() {
        let key = SymFeltRef::new_constant(9);
        let mut cache = SimpleEvalCache::new();
        cache.insert_arr(key, vec![5]);

        let mut read = cache.get_arr_ref(key);
        read.push(6);

        assert_eq!(*cache.get_arr_ref(key), vec![5]);
    }
}
