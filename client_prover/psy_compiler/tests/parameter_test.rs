mod common;

use common::{assert_write, default_context, execute};

const PARAMETER_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[derive(FeltSized)]
    pub struct Point {
        pub x: Felt,
        pub y: Felt,
    }

    #[contract]
    pub struct ParameterContract {
        pub v0: Felt,
        pub v1: Felt,
        pub v2: Felt,
    }

    #[contract_implementation]
    impl ParameterContract {
        #[contract_method]
        pub fn accept_struct(&mut self, ctx: &ChainContext, p: Point) {
            self.v0 = p.x;
            self.v1 = p.y;
            self.v2 = p.x + p.y;
        }

        #[contract_method]
        pub fn accept_struct_array(&mut self, ctx: &ChainContext, arr: [Point; 2]) {
            self.v0 = arr[0].x + arr[0].y;
            self.v1 = arr[1].x + arr[1].y;
            self.v2 = arr[0].x + arr[1].y;
        }
    }
"#;

#[test]
fn struct_parameter_is_supported() {
    let ctx = default_context();
    // Input flatten order for Point { x, y } is [x, y].
    let result = execute(PARAMETER_SOURCE, "accept_struct", &ctx, &[3, 4]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[3]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[4]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[7]);
}

#[test]
fn struct_array_parameter_is_supported() {
    let ctx = default_context();
    // Input flatten order for [Point; 2] is [p0.x, p0.y, p1.x, p1.y].
    let result = execute(PARAMETER_SOURCE, "accept_struct_array", &ctx, &[1, 2, 10, 20]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[3]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[30]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[21]);
}
