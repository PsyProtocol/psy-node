//! Integration tests: compile a PSY contract then execute with VmExecutor
//!
//! These tests verify the full pipeline: source → compile → VM execute → verify
//! result.

use psy_compiler::compile;
use psy_vm::dpn::eval::executor::{ExecutionContext, InMemoryStateBackend, VmExecutor};

fn default_context() -> ExecutionContext {
    ExecutionContext {
        user_id: 1,
        contract_id: 1,
        caller_contract_id: 0,
        checkpoint_id: 100,
        nonce: 0,
        user_public_key_hash: [0; 4],
        transaction_log: vec![],
        transaction_stack_hash: [0; 4],
    }
}

#[test]
fn test_compile_and_execute_set_value() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                self.value = new_value;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    assert_eq!(output.method_count(), 1);

    let method = output.abi.contract.methods.iter().find(|m| m.name == "set_value").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor.execute(circuit, &default_context(), &[42]).expect("execution should succeed");

    assert!(result.success, "execution should pass all assertions: {:?}", result.failure);
    assert!(result.op_counts.total_operations > 0, "should have operations");
}

#[test]
fn test_compile_and_execute_with_require_pass() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub balance: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn deposit(&mut self, ctx: &ChainContext, amount: Felt) {
                require(amount != 0, "amount must not be zero");
                self.balance = self.balance + amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "deposit").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);

    let result = executor.execute(circuit, &default_context(), &[100]).expect("execution should succeed");
    assert!(result.success, "deposit with non-zero amount should pass: {:?}", result.failure);
}

#[test]
fn test_compile_and_execute_with_require_fail() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub balance: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn deposit(&mut self, ctx: &ChainContext, amount: Felt) {
                require(amount != 0, "amount must not be zero");
                self.balance = self.balance + amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "deposit").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);

    let result = executor.execute(circuit, &default_context(), &[0]).expect("execution should complete");
    assert!(!result.success, "deposit with zero amount should fail");
    assert!(result.failure.is_some(), "should have failure details");
}

#[test]
fn test_compile_and_execute_if_else() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn conditional_set(&mut self, ctx: &ChainContext, flag: Bool, a: Felt, b: Felt) {
                if flag {
                    self.value = a;
                } else {
                    self.value = b;
                }
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "conditional_set").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);

    let result = executor
        .execute(circuit, &default_context(), &[1, 10, 20])
        .expect("execution should succeed");
    assert!(result.success, "conditional_set should succeed: {:?}", result.failure);
}

#[test]
fn test_compile_and_execute_context_access() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub last_caller: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn record_caller(&mut self, ctx: &ChainContext) {
                self.last_caller = ctx.user_id;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "record_caller").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let mut ctx = default_context();
    ctx.user_id = 42;

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);

    let result = executor.execute(circuit, &ctx, &[]).expect("execution should succeed");
    assert!(result.success, "record_caller should succeed: {:?}", result.failure);
}

#[test]
fn test_compile_and_execute_contract_state_array() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct TokenBalance {
            pub amount: Felt,
        }

        #[contract]
        pub struct TokenContract {
            pub total_supply: Felt,
            pub balances: ContractStateArray<PSY_TOTAL_USERS, TokenBalance>,
        }

        #[contract_implementation]
        impl TokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &ChainContext, amount: Felt) {
                let sender = ctx.user_id;
                self.total_supply = self.total_supply + amount;
                self.balances[sender].amount = self.balances[sender].amount + amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    assert_eq!(output.method_count(), 1);

    let method = output.abi.contract.methods.iter().find(|m| m.name == "mint").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor.execute(circuit, &default_context(), &[1000]).expect("execution should succeed");

    assert!(result.success, "mint should succeed: {:?}", result.failure);
}

#[test]
fn test_abi_method_resolution() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub a: Felt,
            pub b: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_a(&mut self, ctx: &ChainContext, val: Felt) {
                self.a = val;
            }

            #[contract_method]
            pub fn set_b(&mut self, ctx: &ChainContext, val: Felt) {
                self.b = val;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    assert_eq!(output.method_count(), 2);
    assert_eq!(output.abi.contract.methods.len(), 2);

    for method in &output.abi.contract.methods {
        let circuit = output
            .circuit_definitions
            .iter()
            .find(|d| d.method_id == method.method_id)
            .unwrap_or_else(|| panic!("circuit for method '{}' should exist", method.name));

        let state = InMemoryStateBackend::new();
        let mut executor = VmExecutor::new(state);
        let result = executor
            .execute(circuit, &default_context(), &[99])
            .unwrap_or_else(|e| panic!("execution of '{}' should succeed: {}", method.name, e));

        assert!(
            result.success,
            "method '{}' should pass all assertions: {:?}",
            method.name, result.failure
        );
    }
}

#[test]
fn test_op_counts_nonzero() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn compute(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
                let sum = a + b;
                let product = a * b;
                self.value = sum + product;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "compute").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor.execute(circuit, &default_context(), &[3, 5]).expect("execution should succeed");

    assert!(result.success, "compute should succeed: {:?}", result.failure);
    assert!(result.op_counts.total_operations > 0, "should have operations");
}

#[test]
fn test_compilation_output_structure() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct UserData {
            pub balance: Felt,
            pub nonce: Felt,
        }

        #[contract]
        pub struct MyContract {
            pub owner_id: Felt,
            pub users: ContractStateArray<PSY_TOTAL_USERS, UserData>,
        }

        #[contract_implementation]
        impl MyContract {
            #[contract_method]
            pub fn set_owner(&mut self, ctx: &ChainContext, new_owner: Felt) {
                self.owner_id = new_owner;
            }

            #[contract_method]
            pub fn get_balance(&mut self, ctx: &ChainContext) -> Felt {
                let uid = ctx.user_id;
                return self.users[uid].balance;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");

    // Verify ABI
    assert_eq!(output.abi.contract.name, "MyContract");
    assert!(output.abi.contract.state_tree_height > 0, "state tree height should be > 0");
    assert_eq!(output.abi.contract.methods.len(), 2);
    assert!(output.abi.contract.state.len() >= 2, "should have owner_id and users in layout");

    // Verify contract code
    assert_eq!(output.contract_code.functions.len(), 2);
    assert!(output.contract_code.state_tree_height > 0);

    // Verify circuit definitions
    assert_eq!(output.circuit_definitions.len(), 2);

    // Method IDs should be unique
    let method_ids: Vec<u32> = output.abi.contract.methods.iter().map(|m| m.method_id).collect();
    assert_ne!(method_ids[0], method_ids[1], "method IDs should be unique");
}

#[test]
fn test_multifile_compile_from_sources() {
    use psy_compiler::compile_crate_from_sources;

    let root_source = r#"
        pub mod types;
        use types::*;

        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_value(&mut self, ctx: &ChainContext, new_value: Felt) {
                self.value = new_value;
            }
        }
    "#;

    let types_source = r#"
        #[derive(FeltSized)]
        pub struct TokenInfo {
            pub amount: Felt,
        }
    "#;

    let sources = vec![(vec![], root_source.to_string()), (vec!["types".to_string()], types_source.to_string())];

    let output = compile_crate_from_sources(&sources).expect("multi-file compilation should succeed");
    assert_eq!(output.method_count(), 1);
    assert_eq!(output.abi.contract.name, "TestContract");
}

#[test]
fn test_nested_struct_field_compound_assign_produces_state_write() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct TokenState {
            pub balance: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub token_state: TokenState,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn add_balance(&mut self, ctx: &ChainContext, amount: Felt) {
                self.token_state.balance += amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "add_balance").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    // Verify that the circuit has state commands (writes)
    assert!(
        !circuit.state_commands.is_empty(),
        "add_balance should have state commands for the nested struct write"
    );

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor.execute(circuit, &default_context(), &[500]).expect("execution should succeed");

    assert!(result.success, "add_balance should succeed: {:?}", result.failure);

    // Verify that state writes were recorded
    let actual_writes: Vec<_> = result.state_writes.iter().filter(|w| w.condition).collect();
    assert!(
        !actual_writes.is_empty(),
        "add_balance should produce at least one conditional state write, got state_writes={:?}",
        result.state_writes,
    );

    // Verify the written value is 500
    assert_eq!(actual_writes[0].new_value, vec![500], "balance should be set to 500");

    // Verify the overlay was applied
    let overlay = executor.write_overlay();
    assert!(!overlay.is_empty(),);
}

#[test]
fn test_poseidon_hash_with_to_felts() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct UserTokenState {
            pub balance: Felt,
            pub padding: [Felt; 3],
        }

        #[contract]
        pub struct TestContract {
            pub token_state: UserTokenState,
            pub hm: ContractHashMap<Hash, Hash, 1024>,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.token_state.balance += amount;
                let h = psystd::poseidon_hash(self.token_state.to_felts());
                self.hm.insert(h, h);
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "mint").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();
    println!("circuit: {}", serde_json::to_string_pretty(&circuit).unwrap());
    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor
        .execute(circuit, &default_context(), &[100])
        .expect("execution should succeed (poseidon_hash with to_felts)");

    assert!(result.success, "mint with poseidon_hash should succeed: {:?}", result.failure);
    assert!(result.op_counts.hash_ops > 0, "should have hash operations");
}

#[test]
fn test_poseidon_two_to_one_execution() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub stored_hash: Hash,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn hash_two(&mut self, ctx: &mut ChainContext) {
                let a = psystd::poseidon_hash([1, 2, 3, 4]);
                let b = psystd::poseidon_hash([5, 6, 7, 8]);
                self.stored_hash = psystd::poseidon_two_to_one(a, b);
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "hash_two").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor
        .execute(circuit, &default_context(), &[])
        .expect("execution should succeed (poseidon_two_to_one)");

    assert!(result.success, "hash_two should succeed: {:?}", result.failure);
    assert!(
        result.op_counts.hash_ops >= 3,
        "should have at least 3 hash operations (2 hash_no_pad + 1 two_to_one)"
    );
}

#[test]
fn test_keccak_two_to_one_execution() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub stored_hash: Hash,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn hash_two(&mut self, ctx: &mut ChainContext) {
                let a = psystd::keccak256([1, 2, 3, 4]);
                let b = psystd::keccak256([5, 6, 7, 8]);
                self.stored_hash = psystd::keccak_two_to_one(a, b);
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "hash_two").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor
        .execute(circuit, &default_context(), &[])
        .expect("execution should succeed (keccak_two_to_one)");

    assert!(result.success, "hash_two should succeed: {:?}", result.failure);
    assert!(
        result.op_counts.hash_ops >= 3,
        "should have at least 3 hash operations (2 keccak256 + 1 keccak_two_to_one)"
    );
}

// Verify overlay was applied (continuation of test above)
#[test]
fn test_nested_struct_overlay_applied() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct TokenState {
            pub balance: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub token_state: TokenState,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn add_balance(&mut self, ctx: &ChainContext, amount: Felt) {
                self.token_state.balance += amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "add_balance").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor.execute(circuit, &default_context(), &[500]).expect("execution should succeed");
    assert!(result.success);

    let overlay = executor.write_overlay();
    assert!(!overlay.is_empty(), "write overlay should have the balance update");
}

// ─── Token contract tests ─────────────────────────────────────────────────

#[test]
fn test_simple_token_contract_compiles() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 1024;

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
        pub struct SimpleTokenContract {
            pub token_state: UserTokenState,
            pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
        }

        #[contract_implementation]
        impl SimpleTokenContract {
            #[contract_method]
            pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
                require(self.token_state.balance >= amount, "Insufficient balance");
                require(to != ctx.user_id, "cannot transfer to self");
                self.token_state.balance -= amount;
                self.other_users[to].total_sent += amount;
            }

            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.token_state.balance += amount;
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

    let output = compile(source).expect("SimpleTokenContract should compile");
    assert_eq!(output.abi.contract.name, "SimpleTokenContract");
    assert_eq!(output.method_count(), 3);

    // Verify all three methods exist
    let method_names: Vec<&str> = output.abi.contract.methods.iter().map(|m| m.name.as_str()).collect();
    assert!(method_names.contains(&"transfer"), "should have transfer method");
    assert!(method_names.contains(&"mint"), "should have mint method");
    assert!(method_names.contains(&"claim"), "should have claim method");
}

#[test]
fn test_simple_token_contract_mint_executes() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 1024;

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
        pub struct SimpleTokenContract {
            pub token_state: UserTokenState,
            pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
        }

        #[contract_implementation]
        impl SimpleTokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.token_state.balance += amount;
            }

            #[contract_method]
            pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
                require(self.token_state.balance >= amount, "Insufficient balance");
                require(to != ctx.user_id, "cannot transfer to self");
                self.token_state.balance -= amount;
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

    let output = compile(source).expect("compilation should succeed");
    let method = output.abi.contract.methods.iter().find(|m| m.name == "mint").unwrap();
    let circuit = output.circuit_definitions.iter().find(|d| d.method_id == method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let result = executor
        .execute(circuit, &default_context(), &[1000])
        .expect("mint execution should succeed");

    assert!(result.success, "mint should succeed: {:?}", result.failure);

    // Verify state was written
    let actual_writes: Vec<_> = result.state_writes.iter().filter(|w| w.condition).collect();
    assert!(!actual_writes.is_empty(), "mint should produce state writes");
}

#[test]
fn test_simple_token_contract_transfer_executes() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 1024;

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
        pub struct SimpleTokenContract {
            pub token_state: UserTokenState,
            pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
        }

        #[contract_implementation]
        impl SimpleTokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.token_state.balance += amount;
            }

            #[contract_method]
            pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
                require(self.token_state.balance >= amount, "Insufficient balance");
                require(to != ctx.user_id, "cannot transfer to self");
                self.token_state.balance -= amount;
                self.other_users[to].total_sent += amount;
            }
        }
    "#;

    let output = compile(source).expect("compilation should succeed");

    // First mint some tokens
    let mint_method = output.abi.contract.methods.iter().find(|m| m.name == "mint").unwrap();
    let mint_circuit = output.circuit_definitions.iter().find(|d| d.method_id == mint_method.method_id).unwrap();

    let state = InMemoryStateBackend::new();
    let mut executor = VmExecutor::new(state);
    let mut ctx = default_context();
    ctx.user_id = 1;

    let mint_result = executor.execute(mint_circuit, &ctx, &[1000]).expect("mint should succeed");
    assert!(mint_result.success, "mint should succeed: {:?}", mint_result.failure);

    // Now transfer
    let transfer_method = output.abi.contract.methods.iter().find(|m| m.name == "transfer").unwrap();
    let transfer_circuit = output
        .circuit_definitions
        .iter()
        .find(|d| d.method_id == transfer_method.method_id)
        .unwrap();

    // Transfer 500 from user 1 to user 2
    let state2 = InMemoryStateBackend::new();
    let mut executor2 = VmExecutor::new(state2);
    // Note: state is fresh here, so balance starts at 0. We need to test with fresh
    // state. The transfer will fail due to insufficient balance on fresh state
    // — this validates the require.
    let transfer_result = executor2
        .execute(transfer_circuit, &ctx, &[2, 500])
        .expect("transfer execution should complete");

    // Should fail because balance is 0 on fresh state
    assert!(!transfer_result.success, "transfer with no balance should fail");
}

// ─── Trait tests ──────────────────────────────────────────────────────────

#[test]
fn test_trait_definition_and_implementation() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;

        pub trait Mintable {
            fn mint(&mut self, ctx: &mut ChainContext, amount: Felt);
        }

        #[derive(FeltSized)]
        pub struct TokenState {
            pub balance: Felt,
        }

        #[contract]
        pub struct TokenContract {
            pub state: TokenState,
        }

        impl Mintable for TokenContract {
            fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance += amount;
            }
        }

        #[contract_implementation]
        impl TokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance += amount;
            }
        }
    "#;

    let output = compile(source).expect("trait compilation should succeed");
    assert_eq!(output.abi.contract.name, "TokenContract");
    assert_eq!(output.method_count(), 1);
}

#[test]
fn test_trait_missing_method_error() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;

        pub trait Transferable {
            fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt);
            fn get_balance(&self, ctx: &ChainContext) -> Felt;
        }

        #[derive(FeltSized)]
        pub struct TokenState {
            pub balance: Felt,
        }

        #[contract]
        pub struct TokenContract {
            pub state: TokenState,
        }

        impl Transferable for TokenContract {
            fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
                self.state.balance -= amount;
            }
            // Missing: get_balance
        }

        #[contract_implementation]
        impl TokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance += amount;
            }
        }
    "#;

    let result = compile(source);
    assert!(result.is_err(), "should fail due to missing trait method");
    let err = result.unwrap_err().to_string();
    assert!(err.contains("get_balance"), "error should mention missing method: {}", err);
}

#[test]
fn test_multiple_traits() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;

        pub trait Mintable {
            fn mint(&mut self, ctx: &mut ChainContext, amount: Felt);
        }

        pub trait Burnable {
            fn burn(&mut self, ctx: &mut ChainContext, amount: Felt);
        }

        #[derive(FeltSized)]
        pub struct TokenState {
            pub balance: Felt,
        }

        #[contract]
        pub struct TokenContract {
            pub state: TokenState,
        }

        impl Mintable for TokenContract {
            fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance += amount;
            }
        }

        impl Burnable for TokenContract {
            fn burn(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance -= amount;
            }
        }

        #[contract_implementation]
        impl TokenContract {
            #[contract_method]
            pub fn mint(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance += amount;
            }

            #[contract_method]
            pub fn burn(&mut self, ctx: &mut ChainContext, amount: Felt) {
                self.state.balance -= amount;
            }
        }
    "#;

    let output = compile(source).expect("multiple traits should compile");
    assert_eq!(output.method_count(), 2);
}

#[test]
fn test_trait_with_default_method() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;

        pub trait HasName {
            fn get_version(&self, ctx: &ChainContext) -> Felt {
                return 1;
            }
        }

        #[contract]
        pub struct MyContract {
            pub value: Felt,
        }

        impl HasName for MyContract {
            // Using default implementation for get_version
        }

        #[contract_implementation]
        impl MyContract {
            #[contract_method]
            pub fn set_value(&mut self, ctx: &mut ChainContext, val: Felt) {
                self.value = val;
            }
        }
    "#;

    let output = compile(source).expect("trait with default method should compile");
    assert_eq!(output.method_count(), 1);
}
