mod common;

use common::{assert_write, default_context, execute};

#[test]
fn contract_state_array_struct_field_mutation() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct Pair {
            pub a: Felt,
            pub b: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub users: ContractStateArray<PSY_TOTAL_USERS, Pair>,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn update(&mut self, ctx: &ChainContext, x: Felt, y: Felt) {
                let uid = ctx.user_id;
                self.users[uid].a = x;
                self.users[uid].b = self.users[uid].a + y;
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "update", &ctx, &[7, 3]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[7]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 3, &[10]);
}

#[test]
fn contract_state_array_struct_field_mutation_in_if_else() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct Pair {
            pub a: Felt,
            pub b: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub users: ContractStateArray<PSY_TOTAL_USERS, Pair>,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn update_if_else(&mut self, ctx: &ChainContext, flag: Bool, x: Felt, y: Felt) {
                let uid = ctx.user_id;
                if flag {
                    self.users[uid].a = x;
                    self.users[uid].b = x + 1;
                } else {
                    self.users[uid].a = y;
                    self.users[uid].b = y + 2;
                }
            }
        }
    "#;

    let ctx = default_context();

    let t = execute(source, "update_if_else", &ctx, &[1, 7, 20]);
    assert!(t.success, "failure={:?}", t.failure);
    assert_write(&t, ctx.user_id, ctx.contract_id, 2, &[7]);
    assert_write(&t, ctx.user_id, ctx.contract_id, 3, &[8]);

    let f = execute(source, "update_if_else", &ctx, &[0, 7, 20]);
    assert!(f.success, "failure={:?}", f.failure);
    assert_write(&f, ctx.user_id, ctx.contract_id, 2, &[20]);
    assert_write(&f, ctx.user_id, ctx.contract_id, 3, &[22]);
}

#[test]
fn local_nested_array_reads_work() {
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[contract]
        pub struct TestContract {
            pub v0: Felt,
            pub v1: Felt,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn nested_local_array(&mut self, ctx: &ChainContext) {
                let m: [[Felt; 2]; 2] = [[1, 2], [3, 4]];
                self.v0 = m[0][1];
                self.v1 = m[1][0] + m[1][1];
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "nested_local_array", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[2]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[7]);
}

#[test]
fn nested_array_inside_contract_state_array_element_should_write_second_slot_but_currently_fails() {
    // Intentionally failing regression test:
    // self.users[uid].vals[1] should update the second felt in `vals`,
    // but current lowering may collapse this to the start offset of `vals`.
    let source = r#"
        const PSY_TOTAL_USERS: usize = 4;
        const PSY_TOTAL_CONTRACTS: usize = 4;

        #[derive(FeltSized)]
        pub struct Bucket {
            pub vals: [Felt; 2],
            pub tag: Felt,
        }

        #[contract]
        pub struct TestContract {
            pub users: ContractStateArray<PSY_TOTAL_USERS, Bucket>,
        }

        #[contract_implementation]
        impl TestContract {
            #[contract_method]
            pub fn set_second(&mut self, ctx: &ChainContext, x: Felt) {
                let uid = ctx.user_id;
                self.users[uid].vals[1] = x;
            }
        }
    "#;

    let ctx = default_context();
    let result = execute(source, "set_second", &ctx, &[9]);
    assert!(result.success, "failure={:?}", result.failure);
    // Element size is 3 felts; uid=1 starts at slot 3.
    // `vals[1]` should map to slot 4.
    assert_write(&result, ctx.user_id, ctx.contract_id, 4, &[9]);
}
