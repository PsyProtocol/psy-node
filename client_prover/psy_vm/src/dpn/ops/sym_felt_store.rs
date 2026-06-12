use super::sym_felt::{SymFeltDef, SymFeltRef, SymFeltRefValue};

#[derive(Debug, Clone)]
pub struct SymFeltStore {
    pub store: hashbrown::HashMap<SymFeltRef, SymFeltRefValue>,
    /*
    pub ref_points: Vec<Vec<SymFeltRef>>,
    pub current_phase_ref_points: Vec<SymFeltRef>,*/
}

impl SymFeltStore {
    pub fn new() -> SymFeltStore {
        SymFeltStore {
            store: hashbrown::HashMap::new(),
            //ref_points: Vec::new(),
        }
    }
    pub fn get_opt(&self, key: SymFeltRef) -> Option<&SymFeltRefValue> {
        self.store.get(&key)
    }

    pub fn get(&self, key: SymFeltRef) -> &SymFeltRefValue {
        self.store.get(&key).unwrap()
    }

    pub fn insert(&mut self, value: SymFeltRefValue) -> SymFeltRef {
        let key = value.get_ref_key();
        if key.needs_store() && !self.store.contains_key(&key) {
            self.store.insert(key, value);
        }
        key
    }

    pub fn contains(&self, key: SymFeltRef) -> bool {
        self.store.contains_key(&key)
    }
    pub fn get_direct_children(&self, key: SymFeltRef) -> Vec<SymFeltRef> {
        let mut result = vec![];
        if key.needs_store() {
            let base = self.get(key);
            for input in base.inputs.iter() {
                result.push(*input);
            }
        }
        result
    }
    pub fn get_def(&self, key: SymFeltRef) -> SymFeltDef {
        if key.needs_store() {
            let base = self.get(key);
            SymFeltDef {
                op_type: base.op_type,
                const_param: base.const_param,
                inputs: base.inputs.iter().map(|x| self.get_def(*x)).collect(),
            }
        } else {
            key.get_inline_def()
        }
    }
}
