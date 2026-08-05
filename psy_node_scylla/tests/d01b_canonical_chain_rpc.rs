use std::{fs, path::Path};

fn source(path: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn rpc_reads_the_injected_authority_and_never_assembles_a_head() {
    let handler = source("../psy_node_common/src/coordinator/edge/handler.rs");
    let method = handler
        .split_once("pub async fn get_canonical_chain_ref_internal")
        .expect("canonical head handler method")
        .1
        .split_once("pub async fn get_job_stats_internal")
        .expect("next handler method")
        .0;

    assert!(method.contains("canonical_head_reader"));
    assert!(method.contains("read_canonical_head"));
    assert!(method.contains("CANONICAL_HEAD_UNINITIALIZED"));
    for forbidden in [
        "get_latest_checkpoint_id",
        "get_verifiable_checkpoint_state_transition_and_zkp",
        "checkpoint_tree_get_root_hash",
        "ChainEpoch::new(0)",
    ] {
        assert!(
            !method.contains(forbidden),
            "canonical RPC path must not assemble authority from {forbidden}"
        );
    }
}

#[test]
fn coordinator_edges_prepare_authority_but_realm_edges_do_not() {
    for (path, realm_marker) in [
        (
            "../psy_cli/psy_node_cli/src/node/startup_edge_jtmb_scylla.rs",
            "async fn start_realm_edge_rpc_server_jtmb_scylla_node",
        ),
        (
            "../psy_cli/psy_node_cli/src/node/startup_edge_plonky2_scylla.rs",
            "pub async fn run_startup_plonky2_scylla_realm_edge_node",
        ),
    ] {
        let startup = source(path);
        let coordinator_section = startup
            .split_once("pub async fn run_startup")
            .expect("coordinator startup")
            .1
            .split_once(realm_marker)
            .expect("realm startup boundary")
            .0;
        assert!(coordinator_section.contains(
            "setup_coordinator_psy_scylla_database_store_from_connection_string"
        ));
        assert!(coordinator_section.contains("let canonical_head_reader = db.store.clone()"));

        let realm_section = startup
            .split_once(realm_marker)
            .expect("realm startup")
            .1;
        assert!(!realm_section.contains(
            "setup_coordinator_psy_scylla_database_store_from_connection_string"
        ));
    }
}

#[test]
fn realm_height_polling_is_derived_from_the_atomic_rpc() {
    let client = source("../psy_node_common/src/p2p/realm_coordinator.rs");
    let latest = client
        .split_once("async fn rc_get_latest_checkpoint_id")
        .expect("realm latest method")
        .1
        .split_once("async fn rc_wait_for_next_checkpoint")
        .expect("next realm method")
        .0;
    assert!(latest.contains("rc_get_canonical_chain_ref"));
    assert!(!latest.contains("client.get_latest_checkpoint_id"));

    let wait = client
        .split_once("async fn rc_wait_for_next_checkpoint")
        .expect("realm wait method")
        .1
        .split_once("async fn rc_get_realm_sync_info")
        .expect("next realm method")
        .0;
    assert_eq!(wait.matches("rc_get_canonical_chain_ref").count(), 2);
    assert!(!wait.contains("client.get_latest_checkpoint_id"));
}

#[test]
fn public_rpc_name_and_response_type_are_stable() {
    let api = source("../psy_api_core/src/coordinator/standard_edge_rpc.rs");
    assert!(api.contains("#[method(name = \"get_canonical_chain_ref\")]"));
    assert!(api.contains(
        "async fn get_canonical_chain_ref(&self) -> RpcResult<CanonicalChainRef<Hash>>"
    ));
}
