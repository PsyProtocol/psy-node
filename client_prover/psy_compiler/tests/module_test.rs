use psy_compiler::{compile_crate_from_sources, parse::ast::ModulePath};
use psy_vm::dpn::{
    eval::executor::{ExecutionContext, InMemoryStateBackend, VmExecutor},
    vm::def::DPNFunctionCircuitDefinition,
};

fn default_context() -> ExecutionContext {
    ExecutionContext {
        user_id: 1,
        contract_id: 1,
        caller_contract_id: 0,
        checkpoint_id: 77,
        nonce: 0,
        user_public_key_hash: [0; 4],
    }
}

fn compile_method_from_sources(sources: &[(ModulePath, String)], method_name: &str) -> DPNFunctionCircuitDefinition {
    let output = compile_crate_from_sources(sources).expect("multi-file compilation should succeed");
    let method = output
        .abi
        .methods
        .iter()
        .find(|m| m.name == method_name)
        .unwrap_or_else(|| panic!("method '{}' not found in ABI", method_name));
    output
        .circuit_definitions
        .iter()
        .find(|d| d.method_id == method.method_id)
        .unwrap_or_else(|| panic!("circuit for method '{}' not found", method_name))
        .clone()
}

#[test]
fn multifile_module_struct_and_const_import_execute() {
    let root = r#"
        pub mod types;
        pub mod config;
        use types::*;
        use config::*;

        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct ModuleContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl ModuleContract {
            #[contract_method]
            pub fn apply_pair(&mut self, ctx: &ChainContext, x: Felt, y: Felt) {
                let p = Pair { left: x, right: y };
                self.value = p.left + p.right + EXTRA;
            }
        }
    "#;

    let types = r#"
        #[derive(FeltSized)]
        pub struct Pair {
            pub left: Felt,
            pub right: Felt,
        }
    "#;

    let config = r#"
        const EXTRA: Felt = 5;
    "#;

    let sources = vec![
        (vec![], root.to_string()),
        (vec!["types".to_string()], types.to_string()),
        (vec!["config".to_string()], config.to_string()),
    ];

    let circuit = compile_method_from_sources(&sources, "apply_pair");
    let mut executor = VmExecutor::new(InMemoryStateBackend::new());
    let ctx = default_context();
    let result = executor.execute(&circuit, &ctx, &[3, 4]).expect("execution should complete");

    assert!(result.success, "failure={:?}", result.failure);
    assert!(
        result
            .state_writes
            .iter()
            .any(|w| { w.condition && w.user_id == ctx.user_id && w.contract_id == ctx.contract_id && w.slot_index == 0 && w.new_value == vec![12] }),
        "expected slot0 write = 12, got writes={:?}",
        result.state_writes
    );
}
