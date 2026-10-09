mod common;

use common::{assert_write, default_context, execute};

#[test]
fn local_struct_temp_variable_read_write() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct TempPair {
            pub a: Felt,
            pub b: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub value: Felt, // slot 0
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn local_struct_rw(&mut self, ctx: &ChainContext, x: Felt, y: Felt) {
                let t = TempPair { a: x, b: y };
                let sum = t.a + t.b;

                // "write" to local struct by rebinding a new struct value
                let t = TempPair { a: sum, b: x };
                self.value = t.a + t.b; // (x + y) + x
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "local_struct_rw", &ctx, &[7, 3]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[17]);
}

#[test]
fn local_struct_field_compound_assign_updates_the_local_value() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct TempPair {
            pub a: Felt,
            pub b: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn local_struct_compound_assign(&mut self, ctx: &ChainContext, x: Felt) {
                let t = TempPair { a: x, b: 0 };
                t.a += 3;
                self.value = t.a;
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "local_struct_compound_assign", &ctx, &[7]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[10]);
}

#[test]
fn non_state_struct_methods_update_local_value() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct Counter {
            pub value: Felt,
        }

        impl Counter {
            pub fn inc(&mut self, delta: Felt) {
                self.value += delta;
            }

            pub fn get(&self) -> Felt {
                return self.value;
            }
        }

        #[contract]
        pub struct TestContract {
            pub value: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn use_non_state_struct_methods(&mut self, ctx: &ChainContext, x: Felt, y: Felt) {
                let c = Counter { value: x };
                c.inc(y);
                self.value = c.get();
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "use_non_state_struct_methods", &ctx, &[7, 3]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[10]);
}
