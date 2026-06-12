use psy_compiler::{
    parse::parser::Parser,
    types::{checker::TypeChecker, resolver::Resolver},
};

const EXAMPLE_CONTRACT: &str = r#"
const PSY_TOTAL_USERS: usize = 1073741824;

#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,
    pub total_received: Felt,
}

#[derive(FeltSized)]
pub struct UserTokenState {
    pub balance: Felt,
    pub padding: [Felt; 3],
}

#[contract]
pub struct ExampleContract {
    pub token_state: UserTokenState,
    pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
}

#[derive(FeltSized)]
pub struct TransferTokenParams {
    pub to: Felt,
    pub amount: Felt,
}

#[contract_implementation]
impl ExampleContract {
    fn transfer_helper(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(self.token_state.balance >= amount, "Insufficient balance");
        require(to != ctx.user_id, "cannot transfer to self");
        self.token_state.balance -= amount;
    }
    #[contract_method]
    pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        self.transfer_helper(ctx, to, amount);
    }
    #[contract_method]
    pub fn mint(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(to != ctx.user_id, "cannot mint to self");
        require(ctx.calling_contract == 1337, "Unauthorized caller");
    }
    #[contract_method]
    pub fn claim(&mut self, ctx: &mut ChainContext, sender: Felt) {
        require(sender != ctx.user_id, "cannot claim from self");
        let previous_claimed = self.other_users[sender].total_received;
        let total_sent_by_sender = ctx.users[sender].contract_state::<Self::ABI>(ctx.contract_id).other_users[ctx.user_id].total_sent;
        require(total_sent_by_sender > previous_claimed, "No new tokens to claim");
        let claimable_amount = total_sent_by_sender - previous_claimed;
        self.token_state.balance += claimable_amount;
        self.other_users[sender].total_received = total_sent_by_sender;
    }
}
"#;

// ─── Parser tests ────────────────────────────────────────────────────────────

#[test]
fn test_parse_const_decl() {
    let source = "const FOO: usize = 42;\n";
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    assert_eq!(program.items.len(), 1);
    match &program.items[0] {
        psy_compiler::parse::ast::Item::ConstDecl(cd) => {
            assert_eq!(cd.name, "FOO");
        }
        _ => panic!("Expected ConstDecl"),
    }
}

#[test]
fn test_parse_struct_def() {
    let source = r#"
#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,
    pub total_received: Felt,
}
"#;
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    assert_eq!(program.items.len(), 1);
    match &program.items[0] {
        psy_compiler::parse::ast::Item::StructDef(sd) => {
            assert_eq!(sd.name, "TokenMailbox");
            assert_eq!(sd.fields.len(), 2);
            assert_eq!(sd.fields[0].name, "total_sent");
            assert_eq!(sd.fields[1].name, "total_received");
        }
        _ => panic!("Expected StructDef"),
    }
}

#[test]
fn test_parse_contract_def() {
    let source = r#"
const N: usize = 100;

#[contract]
pub struct MyContract {
    pub balance: Felt,
    pub users: ContractStateArray<N, Felt>,
}
"#;
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    assert_eq!(program.items.len(), 2); // const + contract
    match &program.items[1] {
        psy_compiler::parse::ast::Item::ContractDef(cd) => {
            assert_eq!(cd.name, "MyContract");
            assert_eq!(cd.fields.len(), 2);
        }
        _ => panic!("Expected ContractDef"),
    }
}

#[test]
fn test_parse_full_example() {
    let mut parser = Parser::new(EXAMPLE_CONTRACT);
    let program = parser.parse_program().unwrap();

    // Should have: 1 const + 3 structs + 1 contract + 1 impl
    assert_eq!(program.items.len(), 6);

    // Check impl block
    match &program.items[5] {
        psy_compiler::parse::ast::Item::ImplBlock(ib) => {
            assert_eq!(ib.contract_name, "ExampleContract");
            assert_eq!(ib.methods.len(), 4); // transfer_helper, transfer, mint, claim
            assert!(!ib.methods[0].is_contract_method); // transfer_helper
            assert!(ib.methods[1].is_contract_method); // transfer
            assert!(ib.methods[2].is_contract_method); // mint
            assert!(ib.methods[3].is_contract_method); // claim
        }
        _ => panic!("Expected ImplBlock"),
    }
}

#[test]
fn test_parse_expressions() {
    let source = r#"
#[derive(FeltSized)]
pub struct S { pub x: Felt, }

#[contract]
pub struct C { pub val: Felt, }

#[contract_implementation]
impl C {
    #[contract_method]
    pub fn test(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let x = a + b;
        let y = a * b - x;
        let z = a >= b;
        require(z, "test");
    }
}
"#;
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    assert_eq!(program.items.len(), 3);
}

// ─── Resolver tests ──────────────────────────────────────────────────────────

#[test]
fn test_resolve_example() {
    let mut parser = Parser::new(EXAMPLE_CONTRACT);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    // Check constants
    assert_eq!(resolved.constants["PSY_TOTAL_USERS"], 1073741824);

    // Check struct layouts
    let mailbox = &resolved.struct_layouts["TokenMailbox"];
    assert_eq!(mailbox.felt_size, 2);
    assert_eq!(mailbox.fields[0].name, "total_sent");
    assert_eq!(mailbox.fields[0].offset, 0);
    assert_eq!(mailbox.fields[1].name, "total_received");
    assert_eq!(mailbox.fields[1].offset, 1);

    let token_state = &resolved.struct_layouts["UserTokenState"];
    assert_eq!(token_state.felt_size, 4);
    assert_eq!(token_state.fields[0].name, "balance");
    assert_eq!(token_state.fields[1].name, "padding");
    assert_eq!(token_state.fields[1].felt_size, 3);

    // Check contract layout
    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.contract_name, "ExampleContract");
    assert_eq!(layout.inline_felt_size, 4); // UserTokenState
    assert_eq!(layout.fields[0].name, "token_state");
    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[0].felt_size, 4);
    assert_eq!(layout.fields[1].name, "other_users");
    assert_eq!(layout.fields[1].base_offset, 4);
    assert!(layout.fields[1].is_array);
    assert_eq!(layout.fields[1].array_count, Some(1073741824));
    assert_eq!(layout.fields[1].element_felt_size, Some(2));

    // state_tree_height = ceil(log2(4 + 1073741824*2)) = 32
    assert_eq!(layout.state_tree_height, 32);
}

#[test]
fn test_resolve_struct_layout() {
    let source = r#"
#[derive(FeltSized)]
pub struct Inner {
    pub a: Felt,
    pub b: Felt,
}

#[derive(FeltSized)]
pub struct Outer {
    pub x: Inner,
    pub y: Felt,
    pub z: [Felt; 4],
}
"#;
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let inner = &resolved.struct_layouts["Inner"];
    assert_eq!(inner.felt_size, 2);

    let outer = &resolved.struct_layouts["Outer"];
    assert_eq!(outer.felt_size, 7); // 2 (Inner) + 1 (Felt) + 4 ([Felt;4])
    assert_eq!(outer.fields[0].offset, 0); // x: Inner at 0
    assert_eq!(outer.fields[1].offset, 2); // y: Felt at 2
    assert_eq!(outer.fields[2].offset, 3); // z: [Felt;4] at 3
}

#[test]
fn test_contract_hash_map_base_offset_after_two_felts() {
    let source = r#"
const CAP: usize = 128;

#[contract]
pub struct ExampleContract {
    pub a: Felt,
    pub b: Felt,
    pub c: ContractHashMap<Hash, Hash, CAP>,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 3);

    assert_eq!(layout.fields[0].name, "a");
    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[0].felt_size, 1);

    assert_eq!(layout.fields[1].name, "b");
    assert_eq!(layout.fields[1].base_offset, 1);
    assert_eq!(layout.fields[1].felt_size, 1);

    assert_eq!(layout.fields[2].name, "c");
    assert_eq!(layout.fields[2].base_offset, 4); // aligned to 4-felt boundary
    assert_eq!(layout.fields[2].felt_size, 512); // capacity * value_size = 128 * 4
    assert!(layout.fields[2].is_imt_map);
    assert_eq!(layout.fields[2].imt_capacity, Some(128));
}

#[test]
fn test_contract_hash_map_next_field_base_offset() {
    let source = r#"
const CAP: usize = 128;

#[contract]
pub struct ExampleContract {
    pub a: Felt,
    pub b: Felt,
    pub c: ContractHashMap<Hash, Hash, CAP>,
    pub d: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 4);

    assert_eq!(layout.fields[0].name, "a");
    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[0].felt_size, 1);

    assert_eq!(layout.fields[1].name, "b");
    assert_eq!(layout.fields[1].base_offset, 1);
    assert_eq!(layout.fields[1].felt_size, 1);

    assert_eq!(layout.fields[2].name, "c");
    assert_eq!(layout.fields[2].base_offset, 4); // aligned to 4-felt boundary
    assert_eq!(layout.fields[2].felt_size, 512); // capacity * value_size = 128 * 4
    assert!(layout.fields[2].is_imt_map);

    assert_eq!(layout.fields[3].name, "d");
    assert_eq!(layout.fields[3].base_offset, 516); // 4 + 512
    assert_eq!(layout.fields[3].felt_size, 1);
}

// ─── Type checker tests ──────────────────────────────────────────────────────

#[test]
fn test_type_check_example() {
    let mut parser = Parser::new(EXAMPLE_CONTRACT);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();
    let checked = TypeChecker::new().check(&resolved).unwrap();

    assert_eq!(checked.contract_name, "ExampleContract");
    assert_eq!(checked.methods.len(), 4);

    // transfer_helper is not a contract method
    assert!(!checked.methods[0].is_contract_method);
    assert_eq!(checked.methods[0].name, "transfer_helper");

    // transfer is a contract method
    assert!(checked.methods[1].is_contract_method);
    assert_eq!(checked.methods[1].name, "transfer");
}

#[test]
fn test_reject_contract_with_multiple_imt_maps() {
    let source = r#"
const CAP_B: usize = 8;
const CAP_D: usize = 16;

#[contract]
pub struct MultiMapContract {
    pub a: Felt,
    pub b: ContractHashMap<Hash, Hash, CAP_B>,
    pub c: [Felt; 3],
    pub d: ContractHashMap<Hash, Hash, CAP_D>,
    pub e: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let err = Resolver::new().resolve(&program).unwrap_err();
    assert!(
        err.to_string().contains("Only one ContractHashMap is currently supported per contract"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_abi_marks_single_imt_map_field() {
    let source = r#"
const CAP_B: usize = 8;

#[contract]
pub struct SingleMapContract {
    pub a: Felt,
    pub b: ContractHashMap<Hash, Hash, CAP_B>,
    pub c: [Felt; 3],
    pub e: Felt,
}

#[contract_implementation]
impl SingleMapContract {
    #[contract_method]
    pub fn noop(&mut self, ctx: &mut ChainContext) {
        let _ = ctx.user_id;
    }
}
"#;

    let output = psy_compiler::compile(source).expect("compilation should succeed");
    assert!(!output.abi.state_layout[0].is_imt_map);
    assert!(output.abi.state_layout[1].is_imt_map);
    assert_eq!(output.abi.state_layout[1].imt_capacity, Some(8));
    assert!(!output.abi.state_layout[2].is_imt_map);
    assert!(!output.abi.state_layout[3].is_imt_map);
}

#[test]
fn test_type_check_missing_self() {
    let source = r#"
#[derive(FeltSized)]
pub struct S { pub x: Felt, }

#[contract]
pub struct C { pub val: Felt, }

#[contract_implementation]
impl C {
    #[contract_method]
    pub fn bad(ctx: &mut ChainContext) {
        require(true, "always");
    }
}
"#;
    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();
    let result = TypeChecker::new().check(&resolved);
    assert!(result.is_err());
}

// ─── Full compilation test ───────────────────────────────────────────────────

#[test]
fn test_compile_simple_contract() {
    let source = r#"
#[derive(FeltSized)]
pub struct Dummy { pub x: Felt, }

#[contract]
pub struct SimpleContract {
    pub value: Felt,
}

#[contract_implementation]
impl SimpleContract {
    #[contract_method]
    pub fn set_value(&mut self, ctx: &mut ChainContext, new_value: Felt) {
        self.value = new_value;
    }
    #[contract_method]
    pub fn check_value(&mut self, ctx: &mut ChainContext, expected: Felt) {
        let current = self.value;
        require(current == expected, "value mismatch");
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();

    assert_eq!(output.method_count(), 2);
    assert_eq!(output.state_tree_height(), 1); // ceil(log2(1)) = 1 (single felt)
    assert_eq!(output.abi.contract_name, "SimpleContract");
    assert_eq!(output.abi.methods.len(), 2);
    assert_eq!(output.abi.methods[0].name, "set_value");
    assert_eq!(output.abi.methods[1].name, "check_value");

    // Circuit definitions should exist for both methods
    assert_eq!(output.circuit_definitions.len(), 2);
    for def in &output.circuit_definitions {
        assert!(!def.name.is_empty());
        assert!(def.method_id != 0);
    }
}

#[test]
fn test_compile_with_require() {
    let source = r#"
#[contract]
pub struct GuardedContract {
    pub balance: Felt,
}

#[contract_implementation]
impl GuardedContract {
    #[contract_method]
    pub fn withdraw(&mut self, ctx: &mut ChainContext, amount: Felt) {
        let bal = self.balance;
        require(bal >= amount, "Insufficient balance");
        let new_bal = bal - amount;
        self.balance = new_bal;
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();

    // Should have one assertion in the circuit
    let def = &output.circuit_definitions[0];
    assert!(!def.assertions.is_empty(), "Expected at least one assertion");
}

#[test]
fn test_compile_context_access() {
    let source = r#"
#[contract]
pub struct CtxContract {
    pub owner: Felt,
}

#[contract_implementation]
impl CtxContract {
    #[contract_method]
    pub fn check_caller(&mut self, ctx: &mut ChainContext) {
        require(ctx.calling_contract == 42, "wrong caller");
        let uid = ctx.user_id;
        let cid = ctx.contract_id;
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_compile_if_else() {
    let source = r#"
#[contract]
pub struct BranchContract {
    pub value: Felt,
}

#[contract_implementation]
impl BranchContract {
    #[contract_method]
    pub fn conditional_set(&mut self, ctx: &mut ChainContext, flag: Felt, a: Felt, b: Felt) {
        if flag == 1 {
            self.value = a;
        } else {
            self.value = b;
        }
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_abi_json_serialization() {
    let source = r#"
#[derive(FeltSized)]
pub struct Params { pub x: Felt, pub y: Felt, }

#[contract]
pub struct AbiTestContract {
    pub state: Felt,
}

#[contract_implementation]
impl AbiTestContract {
    #[contract_method]
    pub fn do_thing(&mut self, ctx: &mut ChainContext, val: Felt) {
        self.state = val;
    }
}
"#;
    let output = psy_compiler::compile(source).unwrap();
    let json = output.abi_to_json().unwrap();
    assert!(json.contains("AbiTestContract"));
    assert!(json.contains("do_thing"));
    assert!(json.contains("state_tree_height"));
}

#[test]
fn test_compile_contract_state_array() {
    let source = r#"
const USERS: usize = 1024;

#[derive(FeltSized)]
pub struct Entry {
    pub value: Felt,
    pub count: Felt,
}

#[contract]
pub struct ArrayContract {
    pub total: Felt,
    pub entries: ContractStateArray<USERS, Entry>,
}

#[contract_implementation]
impl ArrayContract {
    #[contract_method]
    pub fn read_entry(&mut self, ctx: &mut ChainContext, user_id: Felt) {
        let val = self.entries[user_id].value;
        require(val > 0, "empty entry");
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();

    // State tree height: ceil(log2(1 + 1024*2)) = ceil(log2(2049)) = 12
    assert_eq!(output.state_tree_height(), 12);

    // ABI should describe the array
    assert!(output.abi.state_layout.len() == 2);
    assert!(output.abi.state_layout[1].is_array);
    assert_eq!(output.abi.state_layout[1].array_count, Some(1024));
}

// ─── Bug fix tests ──────────────────────────────────────────────────────────

/// Regression test: accessing a field on a struct contract state field
/// that happens to have felt_size == 4 (same as Hash) should work correctly.
/// Previously, compile_self_field_read would return SymValue::Hash for any
/// 4-felt field, causing "Cannot access field X on non-struct value" errors.
#[test]
fn test_compile_struct_field_access_on_4_felt_struct() {
    let source = r#"
const PSY_TOTAL_USERS: usize = 1073741824;

#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,
    pub total_received: Felt,
}

#[derive(FeltSized)]
pub struct UserTokenState {
    pub balance: Felt,
    pub padding: [Felt; 3],
}

#[contract]
pub struct ExampleContract {
    pub token_state: UserTokenState,
    pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
}

#[derive(FeltSized)]
pub struct TransferTokenParams {
    pub to: Felt,
    pub amount: Felt,
}

#[contract_implementation]
impl ExampleContract {

    #[contract_method]
    pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(self.token_state.balance >= amount, "Insufficient balance");
        require(to != ctx.user_id, "cannot transfer to self");
        self.token_state.balance -= amount;
        self.other_users[to].total_sent += amount;
    }

    #[contract_method]
    pub fn mint(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(to != ctx.user_id, "cannot mint to self");
        require(ctx.calling_contract == 1337, "Unauthorized caller");
        self.other_users[to].total_sent += amount;
    }

    #[contract_method]
    pub fn claim(&mut self, ctx: &mut ChainContext, sender: Felt) {
        require(sender != ctx.user_id, "cannot claim from self");
        let previous_claimed = self.other_users[sender].total_received;
        let total_sent_by_sender = ctx.users[sender]
            .contract_state::<Self::ABI>(ctx.contract_id)
            .other_users[ctx.user_id]
            .total_sent;
        require(total_sent_by_sender > previous_claimed, "No new tokens to claim");
        let claimable_amount = total_sent_by_sender - previous_claimed;
        self.token_state.balance += claimable_amount;
        self.other_users[sender].total_received = total_sent_by_sender;
    }

}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();
    assert_eq!(output.abi.contract_name, "ExampleContract");
    assert_eq!(output.method_count(), 3);
}

/// Regression test: contracts with helper methods, const generics, for loops,
/// and array element field access (e.g. transfers[i].to) should compile.
/// Previously, the parser would misinterpret `N {` (uppercase const generic
/// before a for-loop body brace) as a struct literal, causing
/// "Expected Colon, got Dot" parse errors.
#[test]
fn test_compile_contract_with_const_generics_and_for_loop() {
    let source = r#"
const PSY_TOTAL_USERS: usize = 1073741824;

#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,
    pub total_received: Felt,
}

#[derive(FeltSized)]
pub struct UserTokenState {
    pub balance: Felt,
    pub padding: [Felt; 3],
}

#[contract]
pub struct ExampleContract {
    pub token_state: UserTokenState,
    pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
}

#[derive(FeltSized)]
pub struct TransferTokenParams {
    pub to: Felt,
    pub amount: Felt,
}

#[contract_implementation]
impl ExampleContract {
    fn transfer_helper(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(self.token_state.balance >= amount, "Insufficient balance");
        require(to != ctx.user_id, "cannot transfer to self");
        self.token_state.balance -= amount;
        self.other_users[to].total_sent += amount;
    }

    fn bulk_transfer_helper<const N: usize>(
        &mut self,
        ctx: &mut ChainContext,
        transfers: &[TransferTokenParams; N],
    ) {
        for i in 0..N {
            self.transfer_helper(ctx, transfers[i].to, transfers[i].amount);
        }
    }

    #[contract_method]
    pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        self.transfer_helper(ctx, to, amount);
    }

    #[contract_method]
    pub fn mint(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(to != ctx.user_id, "cannot mint to self");
        require(ctx.calling_contract == 1337, "Unauthorized caller");
        self.other_users[to].total_sent += amount;
    }

    #[contract_method]
    pub fn claim(&mut self, ctx: &mut ChainContext, sender: Felt) {
        require(sender != ctx.user_id, "cannot claim from self");
        let previous_claimed = self.other_users[sender].total_received;
        let total_sent_by_sender = ctx.users[sender]
            .contract_state::<Self::ABI>(ctx.contract_id)
            .other_users[ctx.user_id]
            .total_sent;
        require(total_sent_by_sender > previous_claimed, "No new tokens to claim");
        let claimable_amount = total_sent_by_sender - previous_claimed;
        self.token_state.balance += claimable_amount;
        self.other_users[sender].total_received = total_sent_by_sender;
    }

    #[contract_method]
    pub fn transfer_token_3(
        &mut self,
        ctx: &mut ChainContext,
        transfers: [TransferTokenParams; 3],
    ) {
        self.bulk_transfer_helper(ctx, &transfers);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
    let output = result.unwrap();
    assert_eq!(output.abi.contract_name, "ExampleContract");
    assert_eq!(output.method_count(), 4);
}

/// Test that uppercase constant identifiers before blocks don't get
/// misinterpreted as struct literals in various expression contexts.
#[test]
fn test_parse_uppercase_ident_before_block_not_struct_literal() {
    // This tests the parser specifically: `N` (uppercase) followed by `{`
    // in a for loop range should NOT be parsed as a struct literal.
    let source = r#"
const LIMIT: usize = 10;

#[contract]
pub struct LoopContract {
    pub total: Felt,
}

#[contract_implementation]
impl LoopContract {
    #[contract_method]
    pub fn accumulate(&mut self, ctx: &mut ChainContext, values: [Felt; 10]) {
        for i in 0..LIMIT {
            self.total += values[i];
        }
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test that struct literals still work correctly after the parser fix.
#[test]
fn test_struct_literal_still_works() {
    let source = r#"
#[derive(FeltSized)]
pub struct Pair {
    pub x: Felt,
    pub y: Felt,
}

#[contract]
pub struct StructLitContract {
    pub val: Felt,
}

#[contract_implementation]
impl StructLitContract {
    #[contract_method]
    pub fn use_struct(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let p = Pair { x: a, y: b };
        self.val = p.x;
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test nested struct field access through contract state (e.g.
/// self.struct_field.sub_field) for structs of various sizes, not just 4-felt
/// ones.
#[test]
fn test_nested_struct_field_access_various_sizes() {
    let source = r#"
#[derive(FeltSized)]
pub struct TwoFeltStruct {
    pub a: Felt,
    pub b: Felt,
}

#[derive(FeltSized)]
pub struct FiveFeltStruct {
    pub x: Felt,
    pub y: Felt,
    pub z: Felt,
    pub w: Felt,
    pub v: Felt,
}

#[contract]
pub struct MultiStructContract {
    pub pair: TwoFeltStruct,
    pub big: FiveFeltStruct,
}

#[contract_implementation]
impl MultiStructContract {
    #[contract_method]
    pub fn read_pair(&mut self, ctx: &mut ChainContext) {
        let val = self.pair.a;
        require(val > 0, "pair.a must be positive");
    }

    #[contract_method]
    pub fn read_big(&mut self, ctx: &mut ChainContext) {
        let val = self.big.v;
        require(val > 0, "big.v must be positive");
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

// ─── psystd::poseidon_two_to_one with array arguments ──────────────────────

/// Regression test: poseidon_two_to_one should accept [Felt; 4] array
/// arguments, not just Hash type. This was the original reported bug.
#[test]
fn test_poseidon_two_to_one_with_array_args() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub value: Hash,
}

#[contract_implementation]
impl ExampleContract {
    #[contract_method]
    pub fn test1(&mut self, ctx: &mut ChainContext, x: Felt, y: Felt) {
        let hash_ex = [x, y, x*y, x+y];
        let two_to_one_ex = psystd::poseidon_two_to_one(hash_ex, hash_ex);
        self.value = [two_to_one_ex[0], two_to_one_ex[1]*x, two_to_one_ex[2], two_to_one_ex[3]];
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test that poseidon_two_to_one also works with Hash typed variables.
#[test]
fn test_poseidon_two_to_one_with_hash_args() {
    let source = r#"
#[contract]
pub struct HashContract {
    pub result: Hash,
}

#[contract_implementation]
impl HashContract {
    #[contract_method]
    pub fn combine(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let h1 = psystd::poseidon_hash(a, b);
        let h2 = psystd::poseidon_hash(b, a);
        self.result = psystd::poseidon_two_to_one(h1, h2);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test that mixed Hash and [Felt; 4] arguments work with poseidon_two_to_one.
#[test]
fn test_poseidon_two_to_one_mixed_args() {
    let source = r#"
#[contract]
pub struct MixedHashContract {
    pub result: Hash,
}

#[contract_implementation]
impl MixedHashContract {
    #[contract_method]
    pub fn combine(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
        let h1 = psystd::poseidon_hash(a, b);
        let arr = [a, b, c, d];
        self.result = psystd::poseidon_two_to_one(h1, arr);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

#[test]
fn test_keccak_two_to_one_with_mixed_args() {
    let source = r#"
#[contract]
pub struct MixedKeccakContract {
    pub result: Hash,
}

#[contract_implementation]
impl MixedKeccakContract {
    #[contract_method]
    pub fn combine(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
        let h1 = psystd::keccak256(a, b);
        let h2 = psystd::keccak256(c, d);
        self.result = psystd::keccak_two_to_one(h1, h2);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

// ─── psystd standard library ────────────────────────────────────────────────

/// Test that psystd::poseidon_hash and psystd::poseidon_two_to_one work
/// as qualified function calls.
#[test]
fn test_psystd_qualified_calls() {
    let source = r#"
#[contract]
pub struct PsyStdContract {
    pub result: Hash,
}

#[contract_implementation]
impl PsyStdContract {
    #[contract_method]
    pub fn test_hash(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let h = psystd::poseidon_hash(a, b);
        let arr = [a, b, a, b];
        self.result = psystd::poseidon_two_to_one(h, arr);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

// ─── Type conversion methods ────────────────────────────────────────────────

/// Test .to_felt() on Bool and U32 values.
#[test]
fn test_to_felt_method() {
    let source = r#"
#[contract]
pub struct ConvContract {
    pub val: Felt,
}

#[contract_implementation]
impl ConvContract {
    #[contract_method]
    pub fn test_to_felt(&mut self, ctx: &mut ChainContext, b: Bool, u: U32) {
        let felt_from_bool = b.to_felt();
        let felt_from_u32 = u.to_felt();
        self.val = felt_from_bool + felt_from_u32;
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test .to_felts() flattening.
#[test]
fn test_to_felts_method() {
    let source = r#"
#[contract]
pub struct FlattenContract {
    pub val: Felt,
}

#[contract_implementation]
impl FlattenContract {
    #[contract_method]
    pub fn test_flatten(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let h = psystd::poseidon_hash(a, b);
        let felts = h.to_felts();
        self.val = felts[0] + felts[1];
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test .into() conversions: [Felt; 4] -> Hash.
#[test]
fn test_into_method() {
    let source = r#"
#[contract]
pub struct IntoContract {
    pub result: Hash,
}

#[contract_implementation]
impl IntoContract {
    #[contract_method]
    pub fn test_into(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
        let arr = [a, b, c, d];
        self.result = arr.into();
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test use psystd import in multi-file compilation (use declarations are
/// accepted but psystd functions must still be called with psystd:: prefix).
#[test]
fn test_psystd_use_import() {
    let sources = vec![(
        vec![],
        r#"
use psystd::poseidon_hash;
use psystd::poseidon_two_to_one;

#[contract]
pub struct ImportContract {
    pub result: Hash,
}

#[contract_implementation]
impl ImportContract {
    #[contract_method]
    pub fn test_import(&mut self, ctx: &mut ChainContext, a: Felt, b: Felt) {
        let h = psystd::poseidon_hash(a, b);
        let arr = [a, b, a, b];
        self.result = psystd::poseidon_two_to_one(h, arr);
    }
}
"#
        .to_string(),
    )];

    let result = psy_compiler::compile_crate_from_sources(&sources);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

// ─── psystd extended standard library ───────────────────────────────────

/// Test psystd::exp (field exponentiation).
#[test]
fn test_psystd_exp() {
    let source = r#"
#[contract]
pub struct ExpContract {
    pub result: Felt,
}

#[contract_implementation]
impl ExpContract {
    #[contract_method]
    pub fn compute_exp(&mut self, ctx: &mut ChainContext, base: Felt, power: Felt) {
        self.result = psystd::exp(base, power);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test psystd::field_inverse.
#[test]
fn test_psystd_field_inverse() {
    let source = r#"
#[contract]
pub struct InverseContract {
    pub result: Felt,
}

#[contract_implementation]
impl InverseContract {
    #[contract_method]
    pub fn compute_inverse(&mut self, ctx: &mut ChainContext, x: Felt) {
        self.result = psystd::field_inverse(x);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test psystd::split_bits and psystd::sum_bits.
#[test]
fn test_psystd_split_and_sum_bits() {
    let source = r#"
#[contract]
pub struct BitsContract {
    pub result: Felt,
}

#[contract_implementation]
impl BitsContract {
    #[contract_method]
    pub fn roundtrip_bits(&mut self, ctx: &mut ChainContext, x: Felt) {
        let bits = psystd::split_bits(x, 32);
        self.result = psystd::sum_bits(bits);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test psystd::cast_bool and psystd::cast_u32.
#[test]
fn test_psystd_casts() {
    let source = r#"
#[contract]
pub struct CastContract {
    pub bool_val: Felt,
    pub u32_val: Felt,
}

#[contract_implementation]
impl CastContract {
    #[contract_method]
    pub fn test_casts(&mut self, ctx: &mut ChainContext, x: Felt, y: Felt) {
        let b = psystd::cast_bool(x);
        let u = psystd::cast_u32(y);
        self.bool_val = b.to_felt();
        self.u32_val = u.to_felt();
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test psystd::emit_event.
#[test]
fn test_psystd_emit_event() {
    let source = r#"
#[contract]
pub struct EventContract {
    pub val: Felt,
}

#[contract_implementation]
impl EventContract {
    #[contract_method]
    pub fn do_something(&mut self, ctx: &mut ChainContext, x: Felt) {
        self.val = x;
        psystd::emit_event(x, self.val);
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

/// Test psystd::secp256k1_verify.
#[test]
fn test_psystd_secp256k1_verify() {
    let source = r#"
#[contract]
pub struct SigContract {
    pub verified: Felt,
}

#[contract_implementation]
impl SigContract {
    #[contract_method]
    pub fn verify_sig(
        &mut self,
        ctx: &mut ChainContext,
        pk: [Felt; 16],
        msg_hash: Hash,
        sig: [Felt; 16],
    ) {
        let valid = psystd::secp256k1_verify(pk, msg_hash, sig);
        require(valid, "invalid signature");
        self.verified = valid.to_felt();
    }
}
"#;
    let result = psy_compiler::compile(source);
    assert!(result.is_ok(), "Compilation failed: {:?}", result.err());
}

// ─── ContractHashMap layout / validation tests ───────────────────────────────

#[test]
fn test_contract_hash_map_at_start_aligned_to_zero() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub c: ContractHashMap<Hash, Hash, 64>,
    pub d: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 2);

    assert_eq!(layout.fields[0].name, "c");
    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[0].felt_size, 256); // capacity * value_size = 64 * 4
    assert!(layout.fields[0].is_imt_map);

    assert_eq!(layout.fields[1].name, "d");
    assert_eq!(layout.fields[1].base_offset, 256);
}

#[test]
fn test_contract_hash_map_after_three_felts_aligns_to_four() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: Felt,
    pub b: Felt,
    pub c: Felt,
    pub d: ContractHashMap<Hash, Hash, 32>,
    pub e: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 5);

    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[1].base_offset, 1);
    assert_eq!(layout.fields[2].base_offset, 2);
    // 3 felts consumed → map aligned to next 4-felt boundary
    assert_eq!(layout.fields[3].base_offset, 4);
    assert_eq!(layout.fields[3].felt_size, 128); // capacity * value_size = 32 * 4
    assert!(layout.fields[3].is_imt_map);

    assert_eq!(layout.fields[4].base_offset, 132); // 4 + 128
}

#[test]
fn test_reject_map_with_non_four_felt_key() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: ContractHashMap<Felt, Hash, 8>,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let err = Resolver::new().resolve(&program).unwrap_err();
    assert!(
        err.to_string().contains("ContractHashMap key type must be exactly 4 felts (256-bit)"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_map_with_non_four_felt_value() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: ContractHashMap<Hash, Felt, 8>,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let err = Resolver::new().resolve(&program).unwrap_err();
    assert!(
        err.to_string().contains("ContractHashMap value type must be exactly 4 felts (256-bit)"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_reject_map_with_zero_capacity() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: ContractHashMap<Hash, Hash, 0>,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let err = Resolver::new().resolve(&program).unwrap_err();
    assert!(
        err.to_string().contains("ContractHashMap capacity must be > 0"),
        "unexpected error: {err:?}"
    );
}

#[test]
fn test_contract_hash_map_value_type_felt_array() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: Felt,
    pub b: ContractHashMap<Hash, [Felt; 4], 16>,
    pub c: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 3);
    // a at 0, then map aligned to 4
    assert_eq!(layout.fields[1].base_offset, 4);
    assert_eq!(layout.fields[1].felt_size, 64); // capacity * value_size = 16 * 4
    assert!(layout.fields[1].is_imt_map);
    assert_eq!(layout.fields[2].base_offset, 68); // 4 + 64
}

#[test]
fn test_contract_hash_map_after_array_offset_correct() {
    let source = r#"
#[contract]
pub struct ExampleContract {
    pub a: Felt,
    pub b: [Felt; 5],
    pub c: ContractHashMap<Hash, Hash, 32>,
    pub d: Felt,
}
"#;

    let mut parser = Parser::new(source);
    let program = parser.parse_program().unwrap();
    let resolved = Resolver::new().resolve(&program).unwrap();

    let layout = resolved.contract_layout.as_ref().unwrap();
    assert_eq!(layout.fields.len(), 4);

    assert_eq!(layout.fields[0].base_offset, 0);
    assert_eq!(layout.fields[1].base_offset, 1);
    // 1 + 5 = 6 → aligned to 8
    assert_eq!(layout.fields[2].base_offset, 8);
    assert_eq!(layout.fields[2].felt_size, 128); // capacity * value_size = 32 * 4
    assert!(layout.fields[2].is_imt_map);
    assert_eq!(layout.fields[3].base_offset, 136); // 8 + 128
}
