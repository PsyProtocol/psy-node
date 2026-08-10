use std::{
    fs,
    path::{Path, PathBuf},
    sync::LazyLock,
};

use serde_json::Value;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn genesis_root() -> PathBuf {
    workspace_root().join("psy-genesis")
}

fn read_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

fn read_methods(path: &Path) -> Vec<Value> {
    read_json(path)
        .as_array()
        .unwrap_or_else(|| panic!("{} is not a method array", path.display()))
        .clone()
}

fn genesis_contracts() -> &'static Value {
    static GENESIS: LazyLock<Value> = LazyLock::new(|| {
        let path = genesis_root().join("genesis_contracts.json");
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let plain = zstd::stream::decode_all(bytes.as_slice())
            .unwrap_or_else(|e| panic!("failed to zstd-decode {}: {}", path.display(), e));
        serde_json::from_slice(&plain).unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
    });
    &GENESIS
}

fn genesis_methods(contract_name: &str) -> Vec<Value> {
    let contract = genesis_contracts()
        .as_array()
        .and_then(|contracts| contracts.iter().find(|contract| contract.get("name").and_then(Value::as_str) == Some(contract_name)))
        .unwrap_or_else(|| panic!("psy-genesis/genesis_contracts.json has no {} entry", contract_name));
    contract
        .pointer("/code_definition/functions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("genesis {} entry has no code_definition.functions", contract_name))
        .iter()
        .map(|function| {
            let bytes = function
                .get("code")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("genesis {} function has no byte-array code", contract_name))
                .iter()
                .map(|byte| byte.as_u64().filter(|value| *value <= 255).map(|value| value as u8))
                .collect::<Option<Vec<u8>>>()
                .unwrap_or_else(|| panic!("genesis {} function code contains a non-byte element", contract_name));
            serde_cbor::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("failed to CBOR-decode genesis {} function code: {}", contract_name, e))
        })
        .collect()
}

fn genesis_private_claim(contract_name: &str) -> Value {
    genesis_methods(contract_name)
        .into_iter()
        .find(|method| method.get("name").and_then(Value::as_str) == Some("private_claim"))
        .unwrap_or_else(|| panic!("genesis {} entry has no private_claim function", contract_name))
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
fn embedded_genesis_private_claims_are_structurally_aligned() {
    assert_eq!(
        genesis_private_claim("token"),
        genesis_private_claim("usdt_token"),
        "psy-genesis token and usdt_token private_claim definitions diverged"
    );
}

#[test]
fn deployed_token_private_claim_matches_authoritative_genesis() {
    let deployed = read_methods(&workspace_root().join("client_prover/token.json"));
    assert_eq!(
        method(&deployed, "private_claim"),
        &genesis_private_claim("token"),
        "client_prover/token.json private_claim is out of sync with psy-genesis/genesis_contracts.json"
    );
}

#[test]
fn generated_private_claim_abis_match_genesis_shape() {
    for (file_name, contract_name) in [("PsyTokenContract.json", "token"), ("USDTTokenContract.json", "usdt_token")] {
        let abi_path = genesis_root().join("genesis_abi").join(file_name);
        let abi = read_json(&abi_path);
        let abi_method = abi
            .pointer("/contract/methods")
            .and_then(Value::as_array)
            .and_then(|methods| methods.iter().find(|method| method.get("name").and_then(Value::as_str) == Some("private_claim")))
            .unwrap_or_else(|| panic!("{} has no private_claim method", abi_path.display()));
        let embedded = genesis_private_claim(contract_name);
        assert_eq!(abi_method.get("method_id"), embedded.get("method_id"));
        assert_eq!(
            abi_method.get("input_felt_count").and_then(Value::as_u64),
            embedded.get("circuit_inputs").and_then(Value::as_array).map(|inputs| inputs.len() as u64),
        );
        assert_eq!(
            abi_method.get("output_felt_count").and_then(Value::as_u64),
            embedded.get("circuit_outputs").and_then(Value::as_array).map(|outputs| outputs.len() as u64),
        );
    }
}
