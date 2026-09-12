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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dpn::ops::op_types::DPNOpType;

    #[test]
    fn stores_derived_references_and_rebuilds_their_definition_tree() {
        let mut store = SymFeltStore::new();
        let left = SymFeltRef::new_constant(2);
        let right = SymFeltRef::new_constant(3);
        let add = store.insert(SymFeltRefValue {
            op_type: DPNOpType::Add,
            const_param: 0,
            inputs: vec![left, right],
        });

        assert!(store.contains(add));
        assert_eq!(store.get_opt(add).unwrap().inputs, vec![left, right]);
        assert_eq!(store.get_direct_children(add), vec![left, right]);
        assert_eq!(store.get_def(add), SymFeltDef {
            op_type: DPNOpType::Add,
            const_param: 0,
            inputs: vec![left.get_inline_def(), right.get_inline_def()],
        });
    }

    #[test]
    fn inline_references_do_not_consume_store_entries() {
        let mut store = SymFeltStore::new();
        let constant = SymFeltRef::new_constant(7);
        let key = store.insert(SymFeltRefValue {
            op_type: DPNOpType::Constant,
            const_param: 7,
            inputs: vec![],
        });

        assert_eq!(key, constant);
        assert!(!store.contains(key));
        assert!(store.get_opt(key).is_none());
        assert!(store.get_direct_children(key).is_empty());
        assert_eq!(store.get_def(key), constant.get_inline_def());
    }
}
