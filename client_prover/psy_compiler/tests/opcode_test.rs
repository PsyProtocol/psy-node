mod common;

use common::{assert_write, default_context, execute};

const OPCODE_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct OpcodeContract {
        pub arithmetic_value: Felt, // slot 0
        pub compare_bool_value: Felt, // slot 1
        pub bitwise_value: Felt, // slot 2
        pub shift_value: Felt, // slot 3
        pub mod_value: Felt, // slot 4
        pub cast_value: Felt, // slot 5
        pub hash_value: Felt, // slot 6
        pub u32_value: Felt, // slot 7
    }

    #[contract_implementation]
    impl OpcodeContract {
        #[contract_method]
        pub fn arithmetic_ops(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            let x = a + b;
            let y = x * c;
            require(y > a && b != 0, "invalid inputs");
            self.arithmetic_value = y - b / b;
            require(self.arithmetic_value == (a + b) * c - 1, "arithmetic mismatch");
        }

        #[contract_method]
        pub fn compare_bool_ops(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            let lt = a < b;
            let gte = c >= b;
            let both = lt && gte;
            self.compare_bool_value = both.to_felt();
            require(self.compare_bool_value == 1, "compare/bool mismatch");
        }

        #[contract_method]
        pub fn bitwise_ops(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            let and_v = a & b;
            let or_v = a | b;
            let xor_v = a ^ b;
            self.bitwise_value = and_v + or_v + xor_v;
            require(self.bitwise_value == 28, "bitwise mismatch");
        }

        #[contract_method]
        pub fn shift_ops(&mut self, ctx: &ChainContext, a: Felt, n: Felt) {
            self.shift_value = (a << n) + (32 >> 2);
            require(self.shift_value == 40, "shift mismatch");
        }

        #[contract_method]
        pub fn mod_ops(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            self.mod_value = a % b;
            require(self.mod_value == 4, "mod mismatch");
        }

        #[contract_method]
        pub fn cast_ops(&mut self, ctx: &ChainContext, b: Felt, y: Felt) {
            let b_cast = psystd::cast_bool(b);
            let u_cast = psystd::cast_u32(y);
            self.cast_value = b_cast.to_felt() + u_cast.to_felt();
            require(self.cast_value == 10, "cast mismatch");
        }

        #[contract_method]
        pub fn hash_ops(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
            let h = psystd::poseidon_hash([a, b, c, d]);
            self.hash_value = h[0];
        }

        #[contract_method]
        pub fn u32_ops(&mut self, ctx: &ChainContext, a: U32, b: U32) {
            let add = a + b;
            let sub = add - b;
            let mul = b * b;
            let div = mul / b;
            require(sub == a, "u32 sub mismatch");
            require(div == b, "u32 div mismatch");
            self.u32_value = add.to_felt() + sub.to_felt() + div.to_felt();
            require(self.u32_value == 20, "u32 mismatch");
        }
    }
"#;

#[test]
fn opcode_arithmetic_ops() {
    let ctx = default_context();
    let ok = execute(OPCODE_SOURCE, "arithmetic_ops", &ctx, &[2, 3, 4]);
    assert!(ok.success, "failure={:?}", ok.failure);
    assert_write(&ok, ctx.user_id, ctx.contract_id, 0, &[19]);
}

#[test]
fn opcode_compare_and_bool_ops() {
    let ctx = default_context();
    let result = execute(OPCODE_SOURCE, "compare_bool_ops", &ctx, &[2, 3, 4]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[1]);
}

#[test]
fn opcode_bitwise_and_shift_ops() {
    let ctx = default_context();
    let bitwise = execute(OPCODE_SOURCE, "bitwise_ops", &ctx, &[12, 10]);
    assert!(bitwise.success, "failure={:?}", bitwise.failure);
    assert_write(&bitwise, ctx.user_id, ctx.contract_id, 2, &[28]);

    let shift = execute(OPCODE_SOURCE, "shift_ops", &ctx, &[1, 5]);
    assert!(shift.success, "failure={:?}", shift.failure);
    assert_write(&shift, ctx.user_id, ctx.contract_id, 3, &[40]);
}

#[test]
fn opcode_mod_cast_and_bits_ops() {
    let ctx = default_context();
    let mod_result = execute(OPCODE_SOURCE, "mod_ops", &ctx, &[29, 5]);
    assert!(mod_result.success, "failure={:?}", mod_result.failure);
    assert_write(&mod_result, ctx.user_id, ctx.contract_id, 4, &[4]);

    let cast_result = execute(OPCODE_SOURCE, "cast_ops", &ctx, &[1, 9]);
    assert!(cast_result.success, "failure={:?}", cast_result.failure);
    assert_write(&cast_result, ctx.user_id, ctx.contract_id, 5, &[10]);
}

#[test]
fn opcode_hash_and_u32_ops() {
    let ctx = default_context();
    let hash_result = execute(OPCODE_SOURCE, "hash_ops", &ctx, &[1, 2, 3, 4]);
    assert!(hash_result.success, "failure={:?}", hash_result.failure);
    assert!(
        hash_result
            .state_writes
            .iter()
            .any(|w| w.condition && w.user_id == ctx.user_id && w.contract_id == ctx.contract_id && w.slot_index == 6),
        "expected effective hash write at slot 6 with matching ctx, writes={:?}",
        hash_result.state_writes
    );
    assert!(hash_result.op_counts.hash_ops > 0);

    let u32_result = execute(OPCODE_SOURCE, "u32_ops", &ctx, &[7, 3]);
    assert!(u32_result.success, "failure={:?}", u32_result.failure);
    assert_write(&u32_result, ctx.user_id, ctx.contract_id, 7, &[20]);
}

#[test]
fn opcode_invalid_path_fails() {
    // Invalid arithmetic path should fail on require(y > a) without
    // division-by-zero.
    let ctx = default_context();
    let fail = execute(OPCODE_SOURCE, "arithmetic_ops", &ctx, &[0, 3, 0]);
    assert!(!fail.success);
    assert!(fail.failure.is_some());
}
