use psy_compiler::{
    parse::parser::Parser,
    types::{checker::TypeChecker, resolver::Resolver},
};

fn run_typecheck(source: &str) -> anyhow::Result<()> {
    let ast = Parser::new(source).parse_program()?;
    let resolved = Resolver::new().resolve(&ast)?;
    TypeChecker::new().check(&resolved)?;
    Ok(())
}

#[test]
fn typecheck_contract_method_signature_ok() {
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
            pub fn set_value(&mut self, ctx: &ChainContext, x: Felt) {
                self.value = x;
            }
        }
    "#;

    run_typecheck(source).expect("typecheck should pass");
}

#[test]
fn typecheck_contract_method_missing_self_fails() {
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
            pub fn bad(ctx: &ChainContext, x: Felt) {
                self.value = x;
            }
        }
    "#;

    let err = run_typecheck(source).expect_err("missing &mut self should fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("must have &mut self as first parameter"), "unexpected error: {msg}");
}

#[test]
fn typecheck_contract_method_wrong_ctx_type_fails() {
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
            pub fn bad(&mut self, ctx: Felt, x: Felt) {
                self.value = x + ctx;
            }
        }
    "#;

    let err = run_typecheck(source).expect_err("wrong ctx type should fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("second parameter must be &mut ChainContext"), "unexpected error: {msg}");
}

#[test]
fn typecheck_for_bounds_must_be_const() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub total: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn bad_for(&mut self, ctx: &ChainContext, n: Felt) {
                for i in 0..n {
                    self.total += i;
                }
            }
        }
    "#;

    let err = run_typecheck(source).expect_err("non-const for bounds should fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("For loop bounds must be compile-time constants"), "unexpected error: {msg}");
}

#[test]
fn typecheck_for_const_bounds_pass() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;
        const N: usize = 5;

        #[contract]
        pub struct TestContract {
            pub total: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn good_for(&mut self, ctx: &ChainContext) {
                for i in 0..N {
                    self.total += i;
                }
            }
        }
    "#;

    run_typecheck(source).expect("const for bounds should pass");
}

#[test]
fn typecheck_while_dynamic_condition_currently_passes() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub total: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn dynamic_while(&mut self, ctx: &ChainContext, n: Felt) {
                let i = 0;
                while i < n {
                    self.total += i;
                    i += 1;
                }
            }
        }
    "#;

    // Current type checker does not enforce compile-time-evaluable while
    // conditions.
    run_typecheck(source).expect("dynamic while currently passes typecheck");
}

#[test]
fn lowercase_bool_type_name_fails() {
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
            pub fn bad_bool_name(&mut self, ctx: &ChainContext) {
                let a: bool = 1;
                self.value = 0;
            }
        }
    "#;

    let err = run_typecheck(source).expect_err("lowercase bool should fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("Unknown type: bool"), "unexpected error: {msg}");
}

#[test]
fn uppercase_bool_with_int_literal_currently_passes_typecheck() {
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
            pub fn bool_from_int(&mut self, ctx: &ChainContext) {
                let b: Bool = 1;
                self.value = b.to_felt();
            }
        }
    "#;

    // Current checker does not strictly validate let explicit type vs initializer
    // type.
    run_typecheck(source).expect("Bool = 1 currently passes typecheck");
}
