use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::LazyLock,
};

use serde_json::Value;
use sha2::{Digest, Sha256};

// --- Paths ---------------------------------------------------------------

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

fn compiler_root() -> PathBuf {
    std::env::var_os("PSY_PROJECTS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| workspace_root().join(".."))
        .join("psy-compiler")
}

fn provenance_stamp_path() -> PathBuf {
    workspace_root().join("psy-genesis/.genesis_contracts.compiler-artifact.json")
}

fn genesis_contracts_path() -> PathBuf {
    workspace_root().join("psy-genesis/genesis_contracts.json")
}

fn token_artifact_path() -> PathBuf {
    workspace_root().join("psy-genesis/token.json")
}

fn token_abi_path() -> PathBuf {
    workspace_root().join("psy-genesis/genesis_abi/PsyTokenContract.json")
}

fn usdt_abi_path() -> PathBuf {
    workspace_root().join("psy-genesis/genesis_abi/USDTTokenContract.json")
}
fn abi_manifest_path() -> PathBuf {
    workspace_root().join("psy-genesis/genesis_abi/abi_list.json")
}

// --- JSON helpers --------------------------------------------------------

fn read_json(path: &Path) -> Value {
    let raw = fs::read_to_string(path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
}

fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn read_methods(path: &Path) -> Vec<Value> {
    let artifact = read_json(path);
    match artifact {
        Value::Array(methods) => methods,
        Value::Object(mut fields) => fields
            .remove("circuit_definitions")
            .and_then(|value| value.as_array().cloned())
            .unwrap_or_else(|| panic!("{} has no circuit_definitions method array", path.display())),
        other => panic!("{} is not a method array or artifact object (found {})", path.display(), json_kind(&other)),
    }
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

// --- Genesis contracts (tracked, authoritative) --------------------------
//
// genesis_contracts.json is a zstd-compressed JSON array whose per-contract
// `code_definition.functions[].code` fields are CBOR-encoded method
// definitions. Because the file is git-tracked in this repo it is the
// authoritative reference: the gitignored psy-compiler `target/` outputs are
// only trusted when they agree with it.

fn genesis_contracts() -> &'static Value {
    static GENESIS: LazyLock<Value> = LazyLock::new(|| {
        let path = genesis_contracts_path();
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        let plain = zstd::stream::decode_all(bytes.as_slice())
            .unwrap_or_else(|e| panic!("failed to zstd-decode {}: {}", path.display(), e));
        serde_json::from_slice(&plain).unwrap_or_else(|e| panic!("failed to parse {}: {}", path.display(), e))
    });
    &GENESIS
}

fn genesis_contract(contract_name: &str) -> &'static Value {
    genesis_contracts()
        .as_array()
        .and_then(|contracts| {
            contracts
                .iter()
                .find(|contract| contract.get("name").and_then(Value::as_str) == Some(contract_name))
        })
        .unwrap_or_else(|| panic!("genesis_contracts.json has no {} entry", contract_name))
}

/// CBOR-decode every function body embedded in the named genesis contract.
fn genesis_methods(contract_name: &str) -> Vec<Value> {
    let contract = genesis_contract(contract_name);
    let functions = contract
        .pointer("/code_definition/functions")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("genesis {} entry has no code_definition.functions", contract_name));
    functions
        .iter()
        .map(|f| {
            let code = f
                .get("code")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("genesis {} function has no byte-array code", contract_name));
            let bytes: Vec<u8> = code
                .iter()
                .map(|b| b.as_u64().filter(|&v| v <= 255).map(|v| v as u8))
                .collect::<Option<Vec<u8>>>()
                .unwrap_or_else(|| panic!("genesis {} function code contains a non-byte element", contract_name));
            serde_cbor::from_slice::<Value>(&bytes)
                .unwrap_or_else(|e| panic!("failed to CBOR-decode genesis {} function code: {}", contract_name, e))
        })
        .collect()
}

fn genesis_private_claim(contract_name: &str) -> Value {
    let methods = genesis_methods(contract_name);
    methods
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some("private_claim"))
        .cloned()
        .unwrap_or_else(|| panic!("genesis {} entry has no private_claim function", contract_name))
}

// --- Compiler provenance fingerprint ------------------------------------
//
// Mirrors dev/locSetupV4.ts (resolveCompilerArtifactFingerprint +
// isCompilerFingerprintSource): compilerRevision is `git rev-parse HEAD` of
// the psy-compiler checkout and compilerSourcesHash is a SHA-256 over each
// fingerprint source's `path \0 bytes \0`, byte-sorted by path.

fn git_output(repo: &Path, args: &[&str]) -> Vec<u8> {
    let joined = args.join(" ");
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .unwrap_or_else(|e| panic!("failed to run `git {}` in {}: {}", joined, repo.display(), e));
    assert!(
        out.status.success(),
        "`git {}` in {} failed: {}",
        joined,
        repo.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

fn is_fingerprint_source(path: &[u8]) -> bool {
    let path_str = String::from_utf8_lossy(path);
    let normalized = path_str.replace('\\', "/");
    let lower = normalized.to_lowercase();
    let basename = lower.rsplit('/').next().unwrap_or(&lower);
    let contains_sensitive_name = ["credential", "credentials", "secret", "secrets", "auth"]
        .iter()
        .any(|name| lower.contains(name));
    if basename.starts_with(".env")
        || contains_sensitive_name
        || lower.ends_with(".pem")
        || lower.ends_with(".key")
        || normalized == ".compiler-artifact.json"
    {
        return false;
    }
    normalized == "Cargo.toml"
        || normalized == "Cargo.lock"
        || normalized == "rust-toolchain.toml"
        || normalized == "Makefile"
        || basename == "build.rs"
        || basename == "precompiles.json"
        || basename == "package.json"
        || lower.ends_with(".rs")
        || lower.ends_with(".psy")
        || lower.ends_with(".toml")
        || lower.ends_with(".lock")
}

fn compiler_sources_hash(repo: &Path) -> String {
    let stdout = git_output(repo, &["ls-files", "--cached", "--others", "--exclude-standard", "-z"]);
    let mut paths: Vec<&[u8]> = stdout.split(|b| *b == 0).filter(|path| !path.is_empty() && is_fingerprint_source(path)).collect();
    paths.sort_unstable();
    let mut hasher = Sha256::new();
    for path in paths {
        let path_str = String::from_utf8_lossy(path);
        let full = repo.join(Path::new(path_str.as_ref()));
        let meta = fs::symlink_metadata(&full).unwrap_or_else(|e| panic!("failed to stat {}: {}", full.display(), e));
        let file_type = meta.file_type();
        let content: Vec<u8> = if file_type.is_file() {
            fs::read(&full).unwrap_or_else(|e| panic!("failed to read {}: {}", full.display(), e))
        } else if file_type.is_symlink() {
            fs::read_link(&full)
                .unwrap_or_else(|e| panic!("failed to read link {}: {}", full.display(), e))
                .to_string_lossy()
                .into_owned()
                .into_bytes()
        } else {
            continue;
        };
        hasher.update(path);
        hasher.update([0u8]);
        hasher.update(&content);
        hasher.update([0u8]);
    }
    hex::encode(hasher.finalize())
}

fn is_lower_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn current_compiler_fingerprint() -> (String, String) {
    let repo = compiler_root();
    let revision = String::from_utf8(git_output(&repo, &["rev-parse", "HEAD"]))
        .expect("psy-compiler git revision is not UTF-8")
        .trim()
        .to_string();
    (revision, compiler_sources_hash(&repo))
}

// --- Tests ---------------------------------------------------------------

#[test]
fn deployed_token_artifact_exposes_claim_events_for_all_claim_paths() {
    let methods = read_methods(&token_artifact_path());

    assert!(
        event_len(&methods, "simple_claim") >= 1,
        "psy-genesis/token.json simple_claim must expose ClaimEvent"
    );
    assert!(
        event_len(&methods, "private_claim") >= 1,
        "psy-genesis/token.json private_claim must expose PrivateClaimEvent"
    );
    assert!(
        event_len(&methods, "claim_deposit") >= 1,
        "psy-genesis/token.json claim_deposit must expose DepositClaimEvent"
    );

    assert_eq!(
        method(&methods, "claim_deposit")
            .get("events")
            .and_then(Value::as_array)
            .and_then(|events| events.first())
            .and_then(|event| event.get("data"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(15),
        "psy-genesis/token.json claim_deposit must expose the exact 15-felt DepositClaimEvent",
    );
}

#[test]
fn genesis_contracts_provenance_stamp_matches_checked_out_compiler_and_artifact() {
    let stamp_path = provenance_stamp_path();
    let stamp = read_json(&stamp_path);
    let revision = stamp
        .get("compilerRevision")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} is missing a string compilerRevision", stamp_path.display()));
    let sources_hash = stamp
        .get("compilerSourcesHash")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} is missing a string compilerSourcesHash", stamp_path.display()));
    let artifact_sha256 = stamp
        .get("artifactSha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} is missing a string artifactSha256", stamp_path.display()));
    let artifact_byte_size = stamp
        .get("artifactByteSize")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{} is missing an integer artifactByteSize", stamp_path.display()));
    let token_sha256 = stamp
        .get("tokenArtifactSha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} is missing a string tokenArtifactSha256", stamp_path.display()));
    let token_byte_size = stamp
        .get("tokenArtifactByteSize")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{} is missing an integer tokenArtifactByteSize", stamp_path.display()));
    let token_update_sha256 = stamp
        .get("tokenUpdateArtifactSha256")
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{} is missing a string tokenUpdateArtifactSha256", stamp_path.display()));
    let token_update_byte_size = stamp
        .get("tokenUpdateArtifactByteSize")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| panic!("{} is missing an integer tokenUpdateArtifactByteSize", stamp_path.display()));
    assert!(is_lower_hex(revision, 40) || is_lower_hex(revision, 64));
    assert!(is_lower_hex(sources_hash, 64));
    assert!(is_lower_hex(artifact_sha256, 64));
    assert!(is_lower_hex(token_sha256, 64));
    assert!(is_lower_hex(token_update_sha256, 64));

    let (current_revision, current_hash) = current_compiler_fingerprint();
    assert_eq!(
        revision, current_revision,
        "{} is stale: compilerRevision no longer matches the checked-out psy-compiler",
        stamp_path.display()
    );
    assert_eq!(
        sources_hash, current_hash,
        "{} is stale: compilerSourcesHash no longer matches the checked-out psy-compiler sources",
        stamp_path.display()
    );

    let artifact_path = genesis_contracts_path();
    let artifact = fs::read(&artifact_path).unwrap_or_else(|e| panic!("failed to read {}: {}", artifact_path.display(), e));
    assert_eq!(
        artifact_sha256,
        hex::encode(Sha256::digest(&artifact)),
        "{} is stale: artifactSha256 does not match genesis_contracts.json",
        stamp_path.display()
    );
    assert_eq!(
        artifact_byte_size,
        artifact.len() as u64,
        "{} is stale: artifactByteSize does not match genesis_contracts.json",
        stamp_path.display()
    );

    for (label, path, expected_hash, expected_size) in [
        ("token.json", token_artifact_path(), token_sha256, token_byte_size),
        ("token.update.json", workspace_root().join("psy-genesis/token.update.json"), token_update_sha256, token_update_byte_size),
    ] {
        let bytes = fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {}", path.display(), e));
        assert_eq!(expected_hash, hex::encode(Sha256::digest(&bytes)), "{} is stale: hash mismatch", label);
        assert_eq!(expected_size, bytes.len() as u64, "{} is stale: byte-size mismatch", label);
    }
}

#[test]
fn embedded_genesis_private_claims_are_structurally_aligned() {
    assert_eq!(
        genesis_private_claim("token"),
        genesis_private_claim("usdt_token"),
        "genesis token and usdt_token private_claim definitions diverged"
    );
}

#[test]
fn deployed_token_private_claim_matches_authoritative_genesis() {
    let deployed = read_methods(&token_artifact_path());
    let deployed_private_claim = method(&deployed, "private_claim");
    let embedded = genesis_private_claim("token");
    if deployed_private_claim != &embedded {
        panic!(
            "psy-genesis/token.json is stale: its private_claim no longer matches the authoritative token entry embedded in genesis_contracts.json; regenerate via `make gen-deploy-json`"
        );
    }
}

#[test]
fn deployed_token_artifact_matches_genesis_for_claim_event_presence() {
    let deployed = read_methods(&token_artifact_path());
    let genesis_token = genesis_methods("token");
    let genesis_usdt = genesis_methods("usdt_token");

    for name in ["simple_claim", "private_claim", "claim_deposit"] {
        assert_eq!(
            event_len(&deployed, name),
            event_len(&genesis_token, name),
            "psy-genesis/token.json is stale: {} event emission no longer matches the authoritative genesis token entry",
            name
        );
        assert_eq!(
            event_len(&genesis_token, name),
            event_len(&genesis_usdt, name),
            "genesis token and usdt_token {} event emission diverged",
            name
        );
    }
}

fn abi_private_claim(abi: &Value) -> &Value {
    abi.pointer("/contract/methods")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("ABI has no /contract/methods"))
        .iter()
        .find(|m| m.get("name").and_then(Value::as_str) == Some("private_claim"))
        .unwrap_or_else(|| panic!("ABI has no private_claim method"))
}

fn assert_abi_private_claim_shape(abi_path: &Path, contract_name: &str) {
    let abi = read_json(abi_path);
    let abi_private_claim = abi_private_claim(&abi);
    let embedded = genesis_private_claim(contract_name);

    assert_eq!(
        abi_private_claim.get("method_id").and_then(Value::as_u64),
        embedded.get("method_id").and_then(Value::as_u64),
        "{} is stale: private_claim method_id no longer matches the authoritative {} genesis method",
        abi_path.display(), contract_name
    );

    let embedded_inputs = embedded
        .get("circuit_inputs")
        .and_then(Value::as_array)
        .map(|inputs| inputs.len() as u64);
    assert_eq!(
        abi_private_claim.get("input_felt_count").and_then(Value::as_u64),
        embedded_inputs,
        "{} is stale: private_claim input_felt_count no longer matches the authoritative {} genesis method",
        abi_path.display(), contract_name
    );

    let embedded_outputs = embedded
        .get("circuit_outputs")
        .and_then(Value::as_array)
        .map(|outputs| outputs.len() as u64);
    assert_eq!(
        abi_private_claim.get("output_felt_count").and_then(Value::as_u64),
        embedded_outputs,
        "{} is stale: private_claim output_felt_count no longer matches the authoritative {} genesis method",
        abi_path.display(), contract_name
    );
}

#[test]
fn generated_token_abi_private_claim_matches_genesis() {
    assert_abi_private_claim_shape(&token_abi_path(), "token");
}

#[test]
fn generated_usdt_abi_private_claim_matches_genesis() {
    assert_abi_private_claim_shape(&usdt_abi_path(), "usdt_token");
}

fn assert_manifest_precompile(contract_id: u64, name: &str, abi_path: &str, abi_contract_name: &str, genesis_contract_name: &str) {
    let manifest_path = abi_manifest_path();
    let manifest = read_json(&manifest_path);
    let precompile = manifest
        .get("precompiles")
        .and_then(Value::as_array)
        .and_then(|precompiles| {
            precompiles
                .iter()
                .find(|precompile| precompile.get("contract_id").and_then(Value::as_u64) == Some(contract_id))
        })
        .unwrap_or_else(|| panic!("{} has no precompile contract_id {}", manifest_path.display(), contract_id));
    assert_eq!(precompile.get("name").and_then(Value::as_str), Some(name));
    assert_eq!(precompile.get("abi_path").and_then(Value::as_str), Some(abi_path));

    let referenced_abi_path = workspace_root().join("psy-genesis/genesis_abi").join(abi_path);
    let referenced_abi = read_json(&referenced_abi_path);
    assert_eq!(
        referenced_abi.pointer("/contract/name").and_then(Value::as_str),
        Some(abi_contract_name),
        "{} routes contract_id {} to an ABI for the wrong contract",
        manifest_path.display(),
        contract_id
    );

    let manifest_height = precompile.get("state_tree_height").and_then(Value::as_u64);
    let abi_height = referenced_abi.pointer("/contract/state_tree_height").and_then(Value::as_u64);
    let genesis_height = genesis_contract(genesis_contract_name)
        .pointer("/code_definition/state_tree_height")
        .and_then(Value::as_u64);
    assert_eq!(
        manifest_height,
        abi_height,
        "{} state_tree_height disagrees with {}",
        manifest_path.display(),
        referenced_abi_path.display()
    );
    assert_eq!(
        manifest_height,
        genesis_height,
        "{} state_tree_height for contract_id {} disagrees with genesis_contracts.json",
        manifest_path.display(),
        contract_id
    );
}

#[test]
fn canonical_abi_manifest_matches_genesis_contracts() {
    assert_manifest_precompile(0, "token", "PsyTokenContract.json", "PsyTokenContract", "token");
    assert_manifest_precompile(
        1,
        "mining_rewards",
        "PsyPOWMiningRewardsClaimContract.json",
        "PsyPOWMiningRewardsClaimContract",
        "mining_rewards",
    );
    assert_manifest_precompile(2, "deposit_tree", "PsyDepositTreeContract.json", "PsyDepositTreeContract", "deposit_tree");
    assert_manifest_precompile(
        3,
        "withdrawal_tree",
        "PsyWithdrawalTreeContract.json",
        "PsyWithdrawalTreeContract",
        "withdrawal_tree",
    );
    assert_manifest_precompile(4, "usdt", "USDTTokenContract.json", "USDTTokenContract", "usdt_token");
    assert_manifest_precompile(5, "faucet", "PsyFaucetContract.json", "PsyFaucetContract", "faucet");
}
