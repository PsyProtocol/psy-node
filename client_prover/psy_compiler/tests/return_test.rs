mod common;

use common::{assert_write, default_context, execute};

#[test]
fn return_paths_write_expected_values() {
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
            pub fn classify(&mut self, ctx: &ChainContext, x: Felt) {
                if x == 0 {
                    self.value = 11;
                    return;
                }
                if x == 1 {
                    self.value = 22;
                    return;
                }
                self.value = 33;
            }
        }
    "#;

    let ctx = default_context();
    let r0 = execute(source, "classify", &ctx, &[0]);
    let r1 = execute(source, "classify", &ctx, &[1]);
    let r2 = execute(source, "classify", &ctx, &[9]);

    assert_write(&r0, ctx.user_id, ctx.contract_id, 0, &[11]);
    assert_write(&r1, ctx.user_id, ctx.contract_id, 0, &[22]);
    assert_write(&r2, ctx.user_id, ctx.contract_id, 0, &[33]);
}
