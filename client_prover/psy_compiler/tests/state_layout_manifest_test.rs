use psy_compiler::{abi::TypeRef, compile};

#[test]
#[ignore = "writes ABI fixtures for the update-contract end-to-end test"]
fn generate_contract6_old_and_new_abi_fixtures() {
    let old_source = r#"
#[derive(FeltSized)]
pub struct TokenState {
    pub balance: Felt,
}

#[contract]
pub struct TokenContract {
    pub token_state: TokenState,
}

#[contract_implementation]
impl TokenContract {
    #[contract_method]
    pub fn add_balance(&mut self, ctx: &mut ChainContext, amount: Felt) {
        self.token_state.balance += amount;
    }
}
"#;
    let new_source = old_source.replace(
        "    pub token_state: TokenState,",
        "    pub token_state: TokenState,\n    pub update_nonce: Felt,",
    );

    let old_output = compile(old_source).expect("old contract must compile");
    let new_output = compile(&new_source).expect("new contract must compile");
    new_output
        .abi
        .validate_layout_update_from(&old_output.abi)
        .expect("new ABI must be an append-only update of old ABI");

    let output_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/state_layout_test_artifacts");
    std::fs::create_dir_all(&output_dir).expect("create ABI fixture output directory");
    let old_path = output_dir.join("contract6.old.abi.json");
    let new_path = output_dir.join("contract6.new.abi.json");
    let update_contract_path = output_dir.join("contract6.update.json");
    std::fs::write(
        &old_path,
        serde_json::to_string_pretty(&old_output.abi).expect("serialize old ABI"),
    )
    .expect("write old ABI");
    std::fs::write(
        &new_path,
        serde_json::to_string_pretty(&new_output.abi).expect("serialize new ABI"),
    )
    .expect("write new ABI");
    std::fs::write(
        &update_contract_path,
        serde_json::to_string_pretty(&new_output.circuit_definitions)
            .expect("serialize update circuit definitions"),
    )
    .expect("write update circuit definitions");

    println!("old ABI: {}", old_path.display());
    println!("new ABI: {}", new_path.display());
    println!("update contract: {}", update_contract_path.display());
}

#[test]
fn compiler_emits_field_oriented_state_layout_manifest() {
    let source = r#"
#[derive(FeltSized)]
pub struct Account {
    pub balance: Felt,
    pub nonce: U32,
}

#[contract]
pub struct LayoutContract {
    pub owner: Hash,
    pub account: Account,
    pub flags: [Bool; 3],
}

#[contract_implementation]
impl LayoutContract {
    #[contract_method]
    pub fn touch(&mut self, ctx: &mut ChainContext) {
        self.account.nonce = 1;
    }
}
"#;
    let output = compile(source).expect("layout contract must compile");
    let layout = &output.abi.contract.state_layout;

    assert_eq!(layout.layout_version, 1);
    assert_eq!(layout.encoding_version, 1);
    assert_eq!(layout.field_count, 3);
    assert_eq!(layout.slot_count, 9);
    assert_eq!(
        layout
            .fields
            .iter()
            .map(|field| { (field.field_id, field.start_slot, field.payload_offset, field.slot_count,) })
            .collect::<Vec<_>>(),
        vec![(1, 0, 0, 4), (2, 4, 0, 2), (3, 6, 0, 3)]
    );
    assert!(matches!(
        &layout.fields[1].ty,
        TypeRef::Struct { name } if name == "Account"
    ));
    assert_eq!(layout.type_proof_plan.field_nodes.len(), 3);
    assert!(layout
        .type_proof_plan
        .nodes
        .iter()
        .all(|node| node.dependencies.iter().all(|dependency| *dependency < node.node_id)));

    let json = output.abi_to_json().expect("ABI must serialize");
    assert!(json.contains("\"state_layout\""));
    assert!(json.contains("\"field_id\": 1"));
    layout.validate().expect("compiler manifest must be canonical");

    let appended_source = source.replace("    pub flags: [Bool; 3],", "    pub flags: [Bool; 3],\n    pub epoch: Felt,");
    let appended = compile(&appended_source).expect("appended contract must compile");
    appended
        .abi
        .validate_layout_update_from(&output.abi)
        .expect("new top-level suffix field must be accepted");

    let mut modified_field = output.abi.clone();
    modified_field.contract.state_layout.fields[0].slot_count = 3;
    assert!(modified_field.validate_layout_update_from(&output.abi).is_err());

    let mut modified_struct = output.abi.clone();
    modified_struct
        .types
        .iter_mut()
        .find(|item| item.name == "Account")
        .expect("Account ABI type")
        .fields[0]
        .felt_size = 2;
    assert!(modified_struct.validate_layout_update_from(&output.abi).is_err());
}

#[test]
fn compiler_deduplicates_equal_types_in_type_proof_dag() {
    let source = r#"
#[derive(FeltSized)]
pub struct Account {
    pub balance: Felt,
    pub nonce: U32,
}

#[contract]
pub struct SharedTypeContract {
    pub first: Account,
    pub second: Account,
}

#[contract_implementation]
impl SharedTypeContract {
    #[contract_method]
    pub fn touch(&mut self, ctx: &mut ChainContext) {
        self.first.nonce = 1;
    }
}
"#;
    let output = compile(source).expect("shared type contract must compile");
    let plan = &output.abi.contract.state_layout.type_proof_plan;
    assert_eq!(plan.field_nodes[0], plan.field_nodes[1]);
    assert_eq!(plan.nodes.iter().filter(|node| node.type_key.starts_with("struct:Account:")).count(), 1);
}

#[test]
fn compiler_assigns_alignment_padding_to_map_field() {
    let source = r#"
#[contract]
pub struct MapLayoutContract {
    pub nonce: Felt,
    pub entries: ContractHashMap<Hash, Hash, 8>,
}

#[contract_implementation]
impl MapLayoutContract {
    #[contract_method]
    pub fn touch(&mut self, ctx: &mut ChainContext) {
        self.nonce = 1;
    }
}
"#;
    let output = compile(source).expect("map layout contract must compile");
    let layout = &output.abi.contract.state_layout;
    layout.validate().expect("map manifest must be contiguous");
    assert_eq!(
        layout
            .fields
            .iter()
            .map(|field| { (field.start_slot, field.payload_offset, field.slot_count,) })
            .collect::<Vec<_>>(),
        vec![(0, 0, 1), (1, 3, 35)]
    );
    assert_eq!(layout.slot_count, 36);
}

#[test]
fn compiler_rejects_aligned_map_nested_in_struct_or_array() {
    let struct_source = r#"
#[derive(FeltSized)]
pub struct Bucket {
    pub entries: ContractHashMap<Hash, Hash, 8>,
}

#[contract]
pub struct NestedMapContract {
    pub bucket: Bucket,
}
"#;
    let error = compile(struct_source).expect_err("nested map must be rejected");
    assert!(
        error.to_string().contains("aligned maps must be direct top-level contract fields"),
        "{error:#}"
    );

    let array_source = r#"
#[contract]
pub struct NestedMapArrayContract {
    pub buckets: [ContractHashMap<Hash, Hash, 8>; 2],
}
"#;
    let error = compile(array_source).expect_err("map array must be rejected");
    assert!(
        error.to_string().contains("aligned maps must be direct top-level contract fields"),
        "{error:#}"
    );
}

/// The checked-in token.json predates the compiler emitting `state_layout`.
/// Make sure it still deserializes and produces a computed layout that
/// round-trips through the ABI serializer.
#[test]
fn legacy_token_artifact_deserializes_with_computed_state_layout() {
    use psy_compiler::output::serialize::CompilationArtifact;

    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let token_path = manifest_dir.join("../token.json");
    let raw = std::fs::read_to_string(&token_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {}", token_path.display(), e));
    let artifact: CompilationArtifact = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to deserialize {}: {}", token_path.display(), e));

    let layout = &artifact.abi.contract.state_layout;
    assert!(
        !layout.fields.is_empty(),
        "computed state layout must have fields"
    );
    assert_eq!(
        layout.field_count as usize,
        layout.fields.len(),
        "field count must match fields vector"
    );
    layout.validate().expect("computed layout must be valid");

    // Re-serializing the ABI must now include the computed state_layout.
    let abi_json = artifact.abi.to_json().expect("ABI must serialize");
    assert!(abi_json.contains("\"state_layout\""));
}
