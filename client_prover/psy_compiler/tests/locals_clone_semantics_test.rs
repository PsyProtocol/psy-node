use std::collections::HashMap;

use psy_compiler::lower::context::SymValue;
use psy_vm::dpn::ops::sym_felt::SymFeltRef;

fn extract_nested_leaf(v: &SymValue) -> SymFeltRef {
    match v {
        SymValue::Struct { fields, .. } => {
            let (_, inner) = fields.iter().find(|(name, _)| name == "a").expect("field a must exist");
            match inner {
                SymValue::Array(items) => match &items[0] {
                    SymValue::Felt(r) => *r,
                    other => panic!("expected Felt leaf, got {:?}", other),
                },
                other => panic!("expected array field, got {:?}", other),
            }
        }
        other => panic!("expected struct value, got {:?}", other),
    }
}

#[test]
fn locals_clone_is_deep_for_containers_but_shallow_for_leaf_refs() {
    let shared_leaf = SymFeltRef(42);

    let original_value = SymValue::Struct {
        name: "S".to_string(),
        fields: vec![("a".to_string(), SymValue::Array(vec![SymValue::Felt(shared_leaf)]))],
    };

    let mut locals: HashMap<String, SymValue> = HashMap::new();
    locals.insert("x".to_string(), original_value);

    // Before mutation, cloned container carries the same SymFeltRef leaf value.
    let pre_mutation_clone = locals.clone();
    let left_leaf = extract_nested_leaf(locals.get("x").expect("x exists"));
    let right_leaf = extract_nested_leaf(pre_mutation_clone.get("x").expect("x exists"));
    assert_eq!(left_leaf, right_leaf);
    assert_eq!(left_leaf, SymFeltRef(42));

    // Mutate only the clone's container structure.
    let mut mutated_clone = locals.clone();
    let cloned_x = mutated_clone.get_mut("x").expect("x exists");
    match cloned_x {
        SymValue::Struct { fields, .. } => {
            let (_, field_val) = fields.iter_mut().find(|(name, _)| name == "a").expect("field a exists");
            *field_val = SymValue::Array(vec![SymValue::Felt(SymFeltRef(99))]);
        }
        other => panic!("expected struct, got {:?}", other),
    }

    // Original remains unchanged -> deep clone at container level.
    let original_leaf_after = extract_nested_leaf(locals.get("x").expect("x exists"));
    let clone_leaf_after = extract_nested_leaf(mutated_clone.get("x").expect("x exists"));
    assert_eq!(original_leaf_after, SymFeltRef(42));
    assert_eq!(clone_leaf_after, SymFeltRef(99));
}
