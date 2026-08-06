use std::collections::BTreeSet;

fn rpc_method_names(source: &str, production_trait: &str) -> Vec<String> {
    let source = source
        .split_once(production_trait)
        .map(|(_, body)| body)
        .expect("production RPC trait declaration must exist");
    let mut in_block_comment = false;
    let mut names = Vec::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if in_block_comment {
            if trimmed.contains("*/") {
                in_block_comment = false;
            }
            continue;
        }
        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                in_block_comment = true;
            }
            continue;
        }
        if trimmed.starts_with("//") || !trimmed.starts_with("#[method(name = \"") {
            continue;
        }

        let name = trimmed
            .strip_prefix("#[method(name = \"")
            .and_then(|rest| rest.split_once('\"').map(|(name, _)| name))
            .expect("RPC method attribute must use the canonical name syntax");
        names.push(name.to_owned());
    }

    names
}

fn assert_inventory(
    source: &str,
    production_trait: &str,
    expected_count: usize,
) -> BTreeSet<String> {
    let names = rpc_method_names(source, production_trait);
    let unique = names.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        names.len(),
        expected_count,
        "production RPC method count changed; classify the new surface in B-02 and update this Gate"
    );
    assert_eq!(
        unique.len(),
        names.len(),
        "RPC method names must be unique within one production trait"
    );
    unique
}

#[test]
fn production_rpc_inventory_is_explicit_and_excludes_commented_methods() {
    let coordinator = assert_inventory(
        include_str!("coordinator/standard_edge_rpc.rs"),
        "pub trait CoordinatorEdgeRpc<",
        47,
    );
    let realm = assert_inventory(
        include_str!("realm/standard_edge_rpc.rs"),
        "pub trait RealmEdgeRpc<",
        43,
    );
    let worker = assert_inventory(
        include_str!("worker/standard_worker_rpc.rs"),
        "pub trait NodeEdgeWorkerRpc<",
        6,
    );

    assert!(coordinator.contains("get_canonical_chain_ref"));
    assert!(realm.contains("get_realm_authority_observation"));
    assert!(worker.contains("submit_proof_raw"));

    assert!(!coordinator.contains("build_block"));
    assert!(!coordinator.contains("get_checkpoint_sync_info"));
    assert!(!realm.contains("get_user_registration_tree_root"));
    assert!(!realm.contains("get_sum"));
}
