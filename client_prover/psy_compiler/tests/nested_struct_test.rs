mod common;

use common::{assert_write, default_context, execute};

const NESTED_STRUCT_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[derive(FeltSized)]
    pub struct Inner {
        pub x: Felt,
        pub y: Felt,
    }

    #[derive(FeltSized)]
    pub struct Outer {
        pub inner: Inner,
        pub z: Felt,
    }

    #[contract]
    pub struct NestedStructContract {
        pub a: Outer,   // slots 0,1,2
        pub b: Felt,    // slot 3
    }

    #[contract_implementation]
    impl NestedStructContract {
        #[contract_method]
        pub fn set_nested(&mut self, ctx: &ChainContext, x: Felt, y: Felt, z: Felt) {
            self.a.inner.x = x;
            self.a.inner.y = y;
            self.a.z = z;
            self.b = self.a.inner.x + self.a.z;
        }

        #[contract_method]
        pub fn bump_nested(&mut self, ctx: &ChainContext, dx: Felt, dz: Felt) {
            self.a.inner.x += dx;
            self.a.z += dz;
            self.b = self.a.inner.x + self.a.z;
        }
    }
"#;

#[test]
fn nested_struct_single_level_writes_expected_slots() {
    let ctx = default_context();
    let result = execute(NESTED_STRUCT_SOURCE, "set_nested", &ctx, &[5, 7, 11]);
    assert!(result.success, "failure={:?}", result.failure);

    // a.inner.x -> slot 0, a.inner.y -> slot 1, a.z -> slot 2, b -> slot 3
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[5]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[7]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[11]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 3, &[16]);
}

#[test]
fn nested_struct_single_level_compound_assign_works() {
    let ctx = default_context();
    let result = execute(NESTED_STRUCT_SOURCE, "bump_nested", &ctx, &[3, 4]);
    assert!(result.success, "failure={:?}", result.failure);

    // Fresh state starts at zero.
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[3]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[4]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 3, &[7]);
}
