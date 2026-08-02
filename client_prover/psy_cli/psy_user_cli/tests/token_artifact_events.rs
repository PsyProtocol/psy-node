use std::{fs, path::PathBuf};

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn read_methods(path: &PathBuf) -> Vec<Value> {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str::<Vec<Value>>(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

fn method<'a>(methods: &'a [Value], name: &str) -> &'a Value {
    methods
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("method {} missing from artifact", name))
}

fn event_len(methods: &[Value], name: &str) -> usize {
    method(methods, name)
        .get("events")
        .and_then(Value::as_array)
        .map(|xs| xs.len())
        .unwrap_or(0)
}

#[test]
fn deployed_token_artifact_exposes_claim_events_for_all_claim_paths() {
    let path = workspace_root().join("client_prover/token.json");
    let methods = read_methods(&path);

    assert!(
        event_len(&methods, "simple_claim") >= 1,
        "client_prover/token.json simple_claim must expose ClaimEvent"
    );
    assert!(
        event_len(&methods, "private_claim") >= 1,
        "client_prover/token.json private_claim must expose PrivateClaimEvent"
    );
    assert!(
        event_len(&methods, "claim_deposit") >= 1,
        "client_prover/token.json claim_deposit must expose DepositClaimEvent"
    );
}

#[test]
fn deployed_token_artifact_matches_compiler_for_claim_event_presence() {
    let deployed = workspace_root().join("client_prover/token.json");
    let compiler = workspace_root().join("../psy-compiler/psy-precompiles/token/target/token.json");

    let deployed_methods = read_methods(&deployed);
    let compiler_methods = read_methods(&compiler);

    for name in ["simple_claim", "private_claim", "claim_deposit"] {
        let deployed_len = event_len(&deployed_methods, name);
        let compiler_len = event_len(&compiler_methods, name);
        assert_eq!(
            deployed_len, compiler_len,
            "client_prover/token.json is out of sync with psy-compiler token artifact for {} event emission",
            name
        );
    }
}
