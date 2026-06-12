mod common;

use common::{assert_write, default_context, execute};
use psy_compiler::compile;

const FOR_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;
    const LOOP_END: usize = 5;
    const ZERO: usize = 0;

    #[contract]
    pub struct TestContract {
        pub total: Felt, // slot 0
    }

    #[contract_implementation]
    impl TestContract {
        #[contract_method]
        pub fn sum_for(&mut self, ctx: &ChainContext) {
            for i in 0..LOOP_END {
                self.total += i;
            }
        }

        #[contract_method]
        pub fn nested_for(&mut self, ctx: &ChainContext) {
            for i in 0..3 {
                for j in 0..2 {
                    self.total += i + j;
                }
            }
        }

        #[contract_method]
        pub fn for_with_if(&mut self, ctx: &ChainContext) {
            for i in 0..6 {
                if i % 2 == 0 {
                    self.total += i;
                } else {
                    self.total += 1;
                }
            }
        }

        #[contract_method]
        pub fn for_zero_iterations(&mut self, ctx: &ChainContext) {
            for i in 0..ZERO {
                self.total += i + 100;
            }
        }

        #[contract_method]
        pub fn for_inside_if(&mut self, ctx: &ChainContext, flag: Bool) {
            if flag {
                for i in 0..4 {
                    self.total += i;
                }
            } else {
                for i in 0..3 {
                    self.total += i + 10;
                }
            }
        }
    }
"#;

#[test]
fn for_loop_accumulates_sum() {
    let ctx = default_context();
    let result = execute(FOR_SOURCE, "sum_for", &ctx, &[]);
    assert!(result.success);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[10]);
    assert!(result.op_counts.state_write_ops > 0);
}

#[test]
fn nested_for_loop_accumulates_expected_value() {
    let ctx = default_context();
    let result = execute(FOR_SOURCE, "nested_for", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[9]);
}

#[test]
fn for_loop_with_if_else_in_body() {
    let ctx = default_context();
    let result = execute(FOR_SOURCE, "for_with_if", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    // even i: 0+2+4=6, odd i contributes 1+1+1=3, total=9
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[9]);
}

#[test]
fn for_loop_zero_iterations_emits_no_effective_write() {
    let ctx = default_context();
    let result = execute(FOR_SOURCE, "for_zero_iterations", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert!(
        !result.state_writes.iter().any(|w| w.condition),
        "expected no effective writes, writes={:?}",
        result.state_writes
    );
}

#[test]
fn for_loop_non_const_range_fails_compile() {
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

    let err = compile(source).expect_err("for range end must be compile-time const");
    let msg = format!("{err:#}");
    assert!(msg.contains("constant") || msg.contains("const"), "unexpected error: {msg}");
}

#[test]
fn for_loop_inside_if_else_branches() {
    let ctx = default_context();

    let t = execute(FOR_SOURCE, "for_inside_if", &ctx, &[1]);
    assert!(t.success, "failure={:?}", t.failure);
    assert_write(&t, ctx.user_id, ctx.contract_id, 0, &[6]); // 0+1+2+3

    let f = execute(FOR_SOURCE, "for_inside_if", &ctx, &[0]);
    assert!(f.success, "failure={:?}", f.failure);
    assert_write(&f, ctx.user_id, ctx.contract_id, 0, &[33]); // (0+10)+(1+10)+(2+10)
}
