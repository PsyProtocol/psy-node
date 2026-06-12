mod common;

use common::{assert_write, default_context, execute};

const ASSERT_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct TestContract {
        pub value: Felt, // slot 0
    }

    #[contract_implementation]
    impl TestContract {
        #[contract_method]
        pub fn set_positive(&mut self, ctx: &ChainContext, x: Felt) {
            require(x > 0, "x must be > 0");
            self.value = x;
        }

        #[contract_method]
        pub fn require_in_if_else(&mut self, ctx: &ChainContext, flag: Bool, x: Felt) {
            if flag {
                require(x > 10, "true branch: x must be > 10");
                self.value = x;
            } else {
                require(x < 10, "false branch: x must be < 10");
                self.value = x + 100;
            }
        }

        #[contract_method]
        pub fn nested_require_in_if_else(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            if a > b {
                if b > c {
                    require(a > c, "nested path 1");
                    self.value = 11;
                } else {
                    require(c > 0, "nested path 2");
                    self.value = 22;
                }
            } else {
                require(a + b > c, "nested path 3");
                self.value = 33;
            }
        }
    }
"#;

#[test]
fn require_success_and_failure_paths() {
    let ctx = default_context();
    let ok = execute(ASSERT_SOURCE, "set_positive", &ctx, &[5]);
    assert!(ok.success);
    assert_write(&ok, ctx.user_id, ctx.contract_id, 0, &[5]);

    let fail = execute(ASSERT_SOURCE, "set_positive", &ctx, &[0]);
    assert!(!fail.success);
    assert!(fail.failure.is_some());
}

#[test]
fn require_inside_if_else_branches() {
    let ctx = default_context();

    let t_ok = execute(ASSERT_SOURCE, "require_in_if_else", &ctx, &[1, 11]);
    assert!(t_ok.success, "failure={:?}", t_ok.failure);
    assert_write(&t_ok, ctx.user_id, ctx.contract_id, 0, &[11]);

    let t_fail = execute(ASSERT_SOURCE, "require_in_if_else", &ctx, &[1, 9]);
    assert!(!t_fail.success);
    assert!(t_fail.failure.is_some());

    let f_ok = execute(ASSERT_SOURCE, "require_in_if_else", &ctx, &[0, 9]);
    assert!(f_ok.success, "failure={:?}", f_ok.failure);
    assert_write(&f_ok, ctx.user_id, ctx.contract_id, 0, &[109]);

    let f_fail = execute(ASSERT_SOURCE, "require_in_if_else", &ctx, &[0, 10]);
    assert!(!f_fail.success);
    assert!(f_fail.failure.is_some());
}

#[test]
fn nested_if_else_require_paths() {
    let ctx = default_context();

    let p1 = execute(ASSERT_SOURCE, "nested_require_in_if_else", &ctx, &[5, 4, 1]);
    assert!(p1.success, "failure={:?}", p1.failure);
    assert_write(&p1, ctx.user_id, ctx.contract_id, 0, &[11]);

    let p2 = execute(ASSERT_SOURCE, "nested_require_in_if_else", &ctx, &[5, 1, 3]);
    assert!(p2.success, "failure={:?}", p2.failure);
    assert_write(&p2, ctx.user_id, ctx.contract_id, 0, &[22]);

    let p2_fail = execute(ASSERT_SOURCE, "nested_require_in_if_else", &ctx, &[5, 0, 0]);
    assert!(!p2_fail.success);
    assert!(p2_fail.failure.is_some());

    let p3 = execute(ASSERT_SOURCE, "nested_require_in_if_else", &ctx, &[2, 4, 5]);
    assert!(p3.success, "failure={:?}", p3.failure);
    assert_write(&p3, ctx.user_id, ctx.contract_id, 0, &[33]);

    let p3_fail = execute(ASSERT_SOURCE, "nested_require_in_if_else", &ctx, &[1, 1, 2]);
    assert!(!p3_fail.success);
    assert!(p3_fail.failure.is_some());
}
