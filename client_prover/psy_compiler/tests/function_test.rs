mod common;

use common::{assert_write, default_context, execute};

const FUNCTION_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct FunctionContract {
        pub v0: Felt, // slot 0
        pub v1: Felt, // slot 1
    }

    #[contract_implementation]
    impl FunctionContract {
        fn add_to_v0(&mut self, ctx: &ChainContext, x: Felt) {
            self.v0 += x;
        }

        fn set_v1_twice(&mut self, ctx: &ChainContext, x: Felt) {
            self.v1 = x * 2;
        }

        fn nested_set_v1(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            let t = a + b;
            self.set_v1_twice(ctx, t);
        }

        fn helper_add_one(&mut self, ctx: &ChainContext, x: Felt) -> Felt {
            return x + 1;
        }

        fn helper_set_max(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            if a > b {
                self.v0 = a;
            } else {
                self.v0 = b;
            }
        }

        fn helper_set_min(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            if a < b {
                self.v1 = a;
            } else {
                self.v1 = b;
            }
        }

        fn helper_set_sum3(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            self.v0 = a + b + c;
        }

        fn helper_max_return(&mut self, ctx: &ChainContext, a: Felt, b: Felt) -> Felt {
            if a > b {
                return a;
            }
            return b;
        }

        fn effect_add_v1(&mut self, ctx: &ChainContext, x: Felt) {
            self.v1 += x;
        }

        fn effect_add_expr(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.effect_add_v1(ctx, a + b);
        }

        fn effect_chain(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            self.effect_add_expr(ctx, a, b);
            self.effect_add_v1(ctx, c * 2);
        }

        #[contract_method]
        pub fn call_helpers(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.add_to_v0(ctx, a);
            self.add_to_v0(ctx, b);
        }

        #[contract_method]
        pub fn call_nested_helpers(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.nested_set_v1(ctx, a, b);
        }

        #[contract_method]
        pub fn classify_with_return(&mut self, ctx: &ChainContext, x: Felt) {
            if x == 0 {
                self.v0 = 11;
                return;
            }
            if x == 1 {
                self.v0 = 22;
                return;
            }
            self.v0 = 33;
        }

        #[contract_method]
        pub fn use_helper_return(&mut self, ctx: &ChainContext, x: Felt) {
            // Desired behavior: helper return value is usable as an expression.
            self.v0 = self.helper_add_one(ctx, x);
        }

        #[contract_method]
        pub fn call_max_min_sum_helpers(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            self.helper_set_max(ctx, a, b);
            self.helper_set_min(ctx, a, b);
            self.helper_set_sum3(ctx, a, b, c);
        }

        #[contract_method]
        pub fn use_helper_max_return(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.v0 = self.helper_max_return(ctx, a, b);
        }

        #[contract_method]
        pub fn call_effect_chain(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            self.effect_chain(ctx, a, b, c);
        }
    }
"#;

const FUNCTION_NESTED_RETURN_EXPR_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct FunctionContract {
        pub v0: Felt,
    }

    #[contract_implementation]
    impl FunctionContract {
        fn helper_add_one(&mut self, ctx: &ChainContext, x: Felt) -> Felt {
            return x + 1;
        }

        fn helper_add_twice_return(&mut self, ctx: &ChainContext, x: Felt) -> Felt {
            return self.helper_add_one(ctx, x) + self.helper_add_one(ctx, x);
        }

        fn helper_nested_return_expr(&mut self, ctx: &ChainContext, a: Felt, b: Felt) -> Felt {
            let left = self.helper_add_twice_return(ctx, a);
            let right = self.helper_add_one(ctx, b) * 3;
            return left + right;
        }

        #[contract_method]
        pub fn use_nested_helper_return_expr(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.v0 = self.helper_nested_return_expr(ctx, a, b) + 5;
        }
    }
"#;

#[test]
fn helper_function_basic_calls_work() {
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "call_helpers", &ctx, &[3, 4]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[7]);
}

#[test]
fn nested_helper_function_calls_work() {
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "call_nested_helpers", &ctx, &[5, 4]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[18]);
}

#[test]
fn contract_method_return_paths_work() {
    let ctx = default_context();
    let r0 = execute(FUNCTION_SOURCE, "classify_with_return", &ctx, &[0]);
    let r1 = execute(FUNCTION_SOURCE, "classify_with_return", &ctx, &[1]);
    let r2 = execute(FUNCTION_SOURCE, "classify_with_return", &ctx, &[9]);

    assert!(r0.success && r1.success && r2.success);
    assert_write(&r0, ctx.user_id, ctx.contract_id, 0, &[11]);
    assert_write(&r1, ctx.user_id, ctx.contract_id, 0, &[22]);
    assert_write(&r2, ctx.user_id, ctx.contract_id, 0, &[33]);
}

#[test]
fn helper_return_value_should_work_but_currently_fails() {
    // Intentionally failing regression test:
    // helper return values should be usable in expressions and state writes.
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "use_helper_return", &ctx, &[7]);
    assert!(result.success, "expected success, failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[8]);
}

#[test]
fn helper_max_min_sum_side_effect_style_works() {
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "call_max_min_sum_helpers", &ctx, &[3, 10, 4]);
    assert!(result.success, "failure={:?}", result.failure);

    // helper_set_sum3 runs last, so v0 = 3 + 10 + 4 = 17
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[17]);
    // v1 from helper_set_min(3,10)
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[3]);
}

#[test]
fn helper_max_return_should_work_but_currently_fails() {
    // Intentionally failing regression test:
    // max/min style helper return value should be usable in expressions.
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "use_helper_max_return", &ctx, &[3, 10]);
    assert!(result.success, "expected success, failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[10]);
}

#[test]
fn multi_layer_helper_side_effect_calls_with_expression_args_work() {
    let ctx = default_context();
    let result = execute(FUNCTION_SOURCE, "call_effect_chain", &ctx, &[3, 4, 5]);
    assert!(result.success, "failure={:?}", result.failure);
    // v1 starts at 0, then +(3+4), then +(5*2) => 17
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[17]);
}

#[test]
fn multi_layer_helper_return_calls_inside_expression_should_work_but_currently_fails() {
    // Intentionally failing regression test:
    // nested helper return values should compose in expressions.
    let ctx = default_context();
    let result = execute(FUNCTION_NESTED_RETURN_EXPR_SOURCE, "use_nested_helper_return_expr", &ctx, &[2, 7]);
    assert!(result.success, "expected success, failure={:?}", result.failure);
    // helper_add_twice_return(2)=6, helper_add_one(7)*3=24, sum=30, +5 => 35
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[35]);
}
