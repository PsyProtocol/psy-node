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
