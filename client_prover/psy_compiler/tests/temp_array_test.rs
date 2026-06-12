mod common;

use common::{assert_write, default_context, execute};

const TEMP_ARRAY_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct TestContract {
        pub value: Felt, // slot 0
    }

    #[contract_implementation]
    impl TestContract {
        #[contract_method]
        pub fn local_array_sum(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
            let arr = [a, b, c, d];
            let left = arr[0] + arr[1];
            let right = arr[2] + arr[3];
            self.value = left + right;
        }

        #[contract_method]
        pub fn local_array_branch(&mut self, ctx: &ChainContext, flag: Bool, x: Felt, y: Felt) {
            if flag {
                let arr = [x, y, x, y];
                self.value = arr[2] + arr[3];
            } else {
                let arr = [y, x, y, x];
                self.value = arr[0] - arr[1];
            }
        }
    }
"#;

#[test]
fn local_temp_array_constant_index_reads() {
    let ctx = default_context();
    let result = execute(TEMP_ARRAY_SOURCE, "local_array_sum", &ctx, &[1, 2, 3, 4]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[10]);
}

#[test]
fn local_temp_array_inside_if_else_branches() {
    let ctx = default_context();

    let t = execute(TEMP_ARRAY_SOURCE, "local_array_branch", &ctx, &[1, 7, 3]);
    assert!(t.success, "failure={:?}", t.failure);
    assert_write(&t, ctx.user_id, ctx.contract_id, 0, &[10]); // arr[2] + arr[3] = x + y

    let f = execute(TEMP_ARRAY_SOURCE, "local_array_branch", &ctx, &[0, 7, 3]);
    assert!(f.success, "failure={:?}", f.failure);
    assert_write(&f, ctx.user_id, ctx.contract_id, 0, &[18446744069414584317]); // 3
                                                                                // -
                                                                                // 7
                                                                                // mod
                                                                                // Goldilocks
                                                                                // prime
}
