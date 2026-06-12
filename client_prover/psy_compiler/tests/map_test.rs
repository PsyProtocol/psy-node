mod common;

use common::{assert_write, default_context, execute};
use psy_compiler::compile;

const MAP_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct TestContract {
        pub hm: ContractHashMap<Hash, Hash, 1024>,
        pub out0: Felt, // slot 1024 (map reserves [0..1023])
        pub out1: Felt, // slot 1025
        pub out2: Felt, // slot 1026
    }

    #[contract_implementation]
    impl TestContract {
        #[contract_method]
        pub fn map_insert_then_get_and_contains(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            let value = [11, 22, 33, 44];
            self.hm.insert(key, value);
            let got = self.hm.get(key);
            self.out0 = got[1];
            if self.hm.contains(key) {
                self.out1 = 1;
            } else {
                self.out1 = 0;
            }
        }

        #[contract_method]
        pub fn map_update_returns_old_value_and_persists_new_value(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [10, 20, 30, 40]);
            let old = self.hm.update(key, [100, 200, 300, 400]);
            let got = self.hm.get(key);
            self.out0 = old[2];
            self.out1 = got[0];
        }

        #[contract_method]
        pub fn map_contains_existing_and_absent_keys(&mut self, ctx: &ChainContext) {
            let existing = [55, 66, 77, 88];
            let absent = [99, 88, 77, 66];
            self.hm.insert(existing, [3, 4, 5, 6]);

            if self.hm.contains(existing) {
                self.out0 = 1;
            } else {
                self.out0 = 0;
            }

            if self.hm.contains(absent) {
                self.out1 = 1;
            } else {
                self.out1 = 0;
            }
        }

        #[contract_method]
        pub fn map_ops_in_if_else_cover_insert_update_contains(&mut self, ctx: &ChainContext, flag: Bool) {
            let key = [77, 66, 55, 44];
            if flag {
                self.hm.insert(key, [7, 8, 9, 10]);
            } else {
                self.hm.insert(key, [1, 1, 1, 1]);
                self.hm.update(key, [2, 2, 2, 2]);
            }
            let got = self.hm.get(key);
            self.out0 = got[0];
            if self.hm.contains(key) {
                self.out1 = 1;
            } else {
                self.out1 = 0;
            }
            self.out2 = got[3];
        }
    }
"#;

#[test]
fn map_insert_then_get_and_contains() {
    let ctx = default_context();
    let result = execute(MAP_SOURCE, "map_insert_then_get_and_contains", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4096, &[22]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4097, &[1]);
}

#[test]
fn map_update_returns_old_value_and_persists_new_value() {
    let ctx = default_context();
    let result = execute(MAP_SOURCE, "map_update_returns_old_value_and_persists_new_value", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4096, &[30]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4097, &[100]);
}

#[test]
fn map_contains_existing_and_absent_keys() {
    let ctx = default_context();
    let result = execute(MAP_SOURCE, "map_contains_existing_and_absent_keys", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4096, &[1]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4097, &[0]);
}

#[test]
fn map_ops_in_if_else_cover_insert_update_contains() {
    let ctx = default_context();

    let t = execute(MAP_SOURCE, "map_ops_in_if_else_cover_insert_update_contains", &ctx, &[1]);
    assert!(t.success, "failure in true branch={:?}", t.failure);
    assert_write(&t, ctx.user_id, ctx.contract_id, 4096, &[7]);
    assert_write(&t, ctx.user_id, ctx.contract_id, 4097, &[1]);
    assert_write(&t, ctx.user_id, ctx.contract_id, 4098, &[10]);

    let f = execute(MAP_SOURCE, "map_ops_in_if_else_cover_insert_update_contains", &ctx, &[0]);
    assert!(f.success, "failure in false branch={:?}", f.failure);
    assert_write(&f, ctx.user_id, ctx.contract_id, 4096, &[2]);
    assert_write(&f, ctx.user_id, ctx.contract_id, 4097, &[1]);
    assert_write(&f, ctx.user_id, ctx.contract_id, 4098, &[2]);
}

const MULTI_MAP_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct MultiMapContract {
        pub a: Felt,                             // slot 0
        pub b: ContractHashMap<Hash, Hash, 8>,  // slots [1..8]
        pub c: Felt,                             // slot 9
        pub d: ContractHashMap<Hash, Hash, 16>, // slots [10..25]
        pub e: Felt,                             // slot 26
    }

    #[contract_implementation]
    impl MultiMapContract {
        #[contract_method]
        pub fn mixed_fields_and_two_maps_offsets(&mut self, ctx: &ChainContext) {
            let kb = [1, 2, 3, 4];
            let kd = [9, 8, 7, 6];

            self.a = 11;
            self.c = 22;
            self.e = 33;

            self.b.insert(kb, [100, 200, 300, 400]);
            self.d.insert(kd, [500, 600, 700, 800]);

            let vb = self.b.get(kb);
            let vd = self.d.get(kd);
            self.a = self.a + vb[0];
            self.c = self.c + vd[1];
            self.e = self.e + vb[3] + vd[2];
        }
    }
"#;

#[test]
fn multi_map_contract_should_be_rejected() {
    let err = compile(MULTI_MAP_SOURCE).expect_err("multi-map contract should fail to compile");
    assert!(
        err.to_string().contains("Only one ContractHashMap is currently supported per contract"),
        "unexpected failure: {err:?}"
    );
}

const MAP_EDGE_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct EdgeMapContract {
        pub before: Felt, // slot 0
        pub hm: ContractHashMap<Hash, Hash, 1024>, // slots [4..1028] (aligned to 4)
        pub after: Felt, // slot 1028
        pub out0: Felt, // slot 1029
        pub out1: Felt, // slot 1030
        pub out2: Felt, // slot 1031
    }

    #[contract_implementation]
    impl EdgeMapContract {
        #[contract_method]
        pub fn map_set_same_as_insert(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            let value = [11, 22, 33, 44];
            let old1 = self.hm.set(key, value);
            let old2 = self.hm.insert(key, [55, 66, 77, 88]);
            self.out0 = old1[0];
            self.out1 = old2[0];
            let got = self.hm.get(key);
            self.out2 = got[0];
        }

        #[contract_method]
        pub fn map_get_absent_key(&mut self, ctx: &ChainContext) {
            let absent = [99, 88, 77, 66];
            let got = self.hm.get(absent);
            self.out0 = got[0];
            self.out1 = got[1];
            self.out2 = got[2];
        }

        #[contract_method]
        pub fn map_insert_overwrite_returns_old(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [10, 20, 30, 40]);
            let old = self.hm.insert(key, [100, 200, 300, 400]);
            self.out0 = old[0];
            self.out1 = old[1];
            self.out2 = old[2];
        }

        #[contract_method]
        pub fn map_ops_preserve_adjacent_fields(&mut self, ctx: &ChainContext) {
            self.before = 111;
            self.after = 222;
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [11, 22, 33, 44]);
            self.before = self.before + 1;
            self.after = self.after + 1;
            self.out0 = self.before;
            self.out1 = self.after;
        }

        #[contract_method]
        pub fn map_multiple_keys(&mut self, ctx: &ChainContext) {
            let k1 = [1, 2, 3, 4];
            let k2 = [5, 6, 7, 8];
            let k3 = [9, 10, 11, 12];
            self.hm.insert(k1, [100, 200, 300, 400]);
            self.hm.insert(k2, [500, 600, 700, 800]);
            self.hm.insert(k3, [900, 1000, 1100, 1200]);
            let v1 = self.hm.get(k1);
            let v2 = self.hm.get(k2);
            let v3 = self.hm.get(k3);
            self.out0 = v1[0];
            self.out1 = v2[0];
            self.out2 = v3[0];
        }

        #[contract_method]
        pub fn map_update_non_existing(&mut self, ctx: &ChainContext) {
            let absent = [99, 88, 77, 66];
            let old = self.hm.update(absent, [1, 2, 3, 4]);
            self.out0 = old[0];
            self.out1 = old[1];
            self.out2 = old[2];
        }

        #[contract_method]
        pub fn map_chain_updates(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [10, 20, 30, 40]);
            let v1 = self.hm.update(key, [100, 200, 300, 400]);
            let v2 = self.hm.update(key, [1000, 2000, 3000, 4000]);
            self.out0 = v1[0];
            self.out1 = v2[0];
            let got = self.hm.get(key);
            self.out2 = got[0];
        }

        #[contract_method]
        pub fn map_insert_then_immediate_get(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [10, 20, 30, 40]);
            let got = self.hm.get(key);
            self.out0 = got[0];
            self.out1 = got[1];
            self.out2 = got[2];
        }

        #[contract_method]
        pub fn map_insert_update_then_get(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            self.hm.insert(key, [10, 20, 30, 40]);
            self.hm.update(key, [100, 200, 300, 400]);
            let got = self.hm.get(key);
            self.out0 = got[0];
            self.out1 = got[1];
            self.out2 = got[2];
        }

        #[contract_method]
        pub fn map_contains_after_insert(&mut self, ctx: &ChainContext) {
            let key = [1, 2, 3, 4];
            let before = self.hm.contains(key);
            self.hm.insert(key, [10, 20, 30, 40]);
            let after = self.hm.contains(key);
            if before {
                self.out0 = 1;
            } else {
                self.out0 = 0;
            }
            if after {
                self.out1 = 1;
            } else {
                self.out1 = 0;
            }
        }

        #[contract_method]
        pub fn map_loop_insert(&mut self, ctx: &ChainContext) {
            for i in 0..3 {
                let key = [i + 1, 0, 0, 0];
                let value = [(i + 1) * 10, 0, 0, 0];
                self.hm.insert(key, value);
            }
            let v0 = self.hm.get([1, 0, 0, 0]);
            let v1 = self.hm.get([2, 0, 0, 0]);
            let v2 = self.hm.get([3, 0, 0, 0]);
            self.out0 = v0[0];
            self.out1 = v1[0];
            self.out2 = v2[0];
        }
    }
"#;

#[test]
fn map_set_equivalent_to_insert() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_set_same_as_insert", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    // .set on absent key returns zero old value; .insert on existing key returns previous value
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[0]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[11]);
    // final value is [55,66,77,88]
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[55]);
}

#[test]
fn map_get_absent_key_returns_zeros() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_get_absent_key", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[0]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[0]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[0]);
}

#[test]
fn map_insert_overwrite_returns_old_value() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_insert_overwrite_returns_old", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    // overwrite insert returns the old value
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[10]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[20]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[30]);
}

#[test]
fn map_operations_preserve_adjacent_fields() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_ops_preserve_adjacent_fields", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[112]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[223]);
}

#[test]
fn map_multiple_keys_independent() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_multiple_keys", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[100]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[500]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[900]);
}

#[test]
fn map_update_non_existing_returns_zero_old_value() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_update_non_existing", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    // update on absent key returns zero old value
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[0]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[0]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[0]);
}

#[test]
fn map_chain_updates_in_single_call() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_chain_updates", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    // update returns old value each time
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[10]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[100]);
    // final get value
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[1000]);
}

#[test]
fn map_insert_visible_to_immediate_get() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_insert_then_immediate_get", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[10]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[20]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[30]);
}

#[test]
fn map_insert_update_then_get_persists() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_insert_update_then_get", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[100]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[200]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[300]);
}

#[test]
fn map_contains_reflects_insert_in_same_call() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_contains_after_insert", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[0]); // before: false
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[1]); // after: true
}

#[test]
fn map_loop_insert_multiple_keys() {
    let ctx = default_context();
    let result = execute(MAP_EDGE_SOURCE, "map_loop_insert", &ctx, &[]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4101, &[10]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4102, &[20]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4103, &[30]);
}
