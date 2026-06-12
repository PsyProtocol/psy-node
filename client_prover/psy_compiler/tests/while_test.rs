mod common;

use common::{assert_write, default_context, execute};
use psy_compiler::compile;

const WHILE_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct TestContract {
        pub total: Felt, // slot 0
    }

    #[contract_implementation]
    impl TestContract {
        #[contract_method]
        pub fn sum_while(&mut self, ctx: &ChainContext, n: Felt) {
            let i = 0;
            while i < n {
                self.total += i;
                i += 1;
            }
        }

        #[contract_method]
        pub fn while_dynamic_from_one(&mut self, ctx: &ChainContext, n: Felt) {
            let i = 1;
            while i < n {
                self.total += i;
                i += 1;
            }
        }

        #[contract_method]
        pub fn while_const_false(&mut self, ctx: &ChainContext) {
            let i = 0;
            while i < 0 {
                self.total += 99;
                i += 1;
            }
        }

        #[contract_method]
        pub fn while_with_if_in_body(&mut self, ctx: &ChainContext, n: Felt) {
            let i = 1;
            while i < n {
                if i % 2 == 0 {
                    self.total += 100;
                } else {
                    self.total += 7;
                }
                i += 1;
            }
        }

        #[contract_method]
        pub fn while_inside_if(&mut self, ctx: &ChainContext, flag: Bool, n: Felt) {
            if flag {
                let i = 1;
                while i < n {
                    self.total += i;
                    i += 1;
                }
            } else {
                let j = 2;
                while j < n {
                    self.total += j + 5;
                    j += 1;
                }
            }
        }
    }
"#;

#[test]
fn while_loop_executes_and_writes_state() {
    let ctx = default_context();
    let result = execute(WHILE_SOURCE, "sum_while", &ctx, &[4]);
    assert!(result.success);
    // Current lowering emits a single guarded while iteration for dynamic
    // conditions. So with i initialized to 0, the first write is total += 0 =>
    // 0.
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[0]);
    assert!(result.op_counts.state_write_ops > 0, "writes={:?}", result.state_writes);
    assert!(result.op_counts.comparison_ops > 0);
}

#[test]
fn while_dynamic_condition_runs_single_guarded_iteration() {
    let ctx = default_context();
    let result = execute(WHILE_SOURCE, "while_dynamic_from_one", &ctx, &[5]);
    assert!(result.success, "failure={:?}", result.failure);
    // Current behavior: one guarded iteration only, so total += 1 once.
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[1]);
}

#[test]
fn while_const_false_has_no_effective_writes() {
    let ctx = default_context();
    let result = execute(WHILE_SOURCE, "while_const_false", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert!(
        !result.state_writes.iter().any(|w| w.condition),
        "expected no effective writes, writes={:?}",
        result.state_writes
    );
}

#[test]
fn while_body_with_if_else_respects_first_iteration_value() {
    let ctx = default_context();
    let result = execute(WHILE_SOURCE, "while_with_if_in_body", &ctx, &[10]);
    assert!(result.success, "failure={:?}", result.failure);
    // i starts at 1, so first (and currently only) iteration takes else branch =>
    // +7
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[7]);
}

#[test]
fn while_constant_true_fails_compile() {
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
            pub fn bad_while(&mut self, ctx: &ChainContext) {
                while true {
                    self.total += 1;
                }
            }
        }
    "#;

    let err = compile(source).expect_err("constant-true while must fail");
    let msg = format!("{err:#}");
    assert!(msg.contains("loop forever") || msg.contains("constant-true"), "unexpected error: {msg}");
}

#[test]
fn while_loop_inside_if_else_branches() {
    let ctx = default_context();

    let t = execute(WHILE_SOURCE, "while_inside_if", &ctx, &[1, 10]);
    assert!(t.success, "failure={:?}", t.failure);
    // Current behavior: dynamic while emits one guarded iteration.
    assert_write(&t, ctx.user_id, ctx.contract_id, 0, &[1]);

    let f = execute(WHILE_SOURCE, "while_inside_if", &ctx, &[0, 10]);
    assert!(f.success, "failure={:?}", f.failure);
    // Else branch first iteration uses j=2 => 2+5
    assert_write(&f, ctx.user_id, ctx.contract_id, 0, &[7]);
}
