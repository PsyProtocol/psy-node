mod common;

use common::{assert_write, default_context, execute};

const STD_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct StdContract {
        pub out0: Felt, // slot 0
        pub out1: Felt, // slot 1
        pub out2: Felt, // slot 2
        pub h: Hash,    // slots 3..=6
    }

    #[contract_implementation]
    impl StdContract {
        #[contract_method]
        pub fn hash_and_two_to_one(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
            let x = psystd::poseidon_hash([a, b, c, d]);
            let y = psystd::poseidon_two_to_one(x, x);
            self.h = y;
            self.out0 = y[0];
        }

        #[contract_method]
        pub fn cast_and_exp(&mut self, ctx: &ChainContext, b: Felt, x: Felt) {
            let bb = psystd::cast_bool(b);
            let xx = psystd::cast_u32(x);
            let p = psystd::exp(xx.to_felt(), 3);
            self.out0 = bb.to_felt() + xx.to_felt();
            self.out1 = p;
            require(self.out0 == 8, "cast result mismatch");
            require(self.out1 == 343, "exp result mismatch");
        }

        #[contract_method]
        pub fn field_inverse_and_event(&mut self, ctx: &ChainContext, v: Felt) {
            let inv = psystd::field_inverse(v);
            require(inv * v == 1, "inverse mismatch");
            self.out2 = inv * v;
            psystd::emit_event(v, self.out2);
        }

        #[contract_method]
        pub fn split_bits_should_work(&mut self, ctx: &ChainContext, x: Felt) {
            let bits = psystd::split_bits(x, 4);
            let sum = psystd::sum_bits(bits);
            self.out0 = sum;
        }
    }
"#;

#[test]
fn psystd_hash_functions_work() {
    let ctx = default_context();
    let result = execute(STD_SOURCE, "hash_and_two_to_one", &ctx, &[1, 2, 3, 4]);
    assert!(result.success, "failure={:?}", result.failure);

    // hash stored in h: Hash at slots 3..=6
    assert!(result
        .state_writes
        .iter()
        .any(|w| { w.condition && w.user_id == ctx.user_id && w.contract_id == ctx.contract_id && (3..=6).contains(&w.slot_index) }));
    assert!(result.op_counts.hash_ops >= 2);
}

#[test]
fn psystd_cast_and_exp_work() {
    let ctx = default_context();
    let result = execute(STD_SOURCE, "cast_and_exp", &ctx, &[1, 7]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[8]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[343]);
}

#[test]
fn psystd_field_inverse_and_emit_event_work() {
    let ctx = default_context();
    let result = execute(STD_SOURCE, "field_inverse_and_event", &ctx, &[5]);
    assert!(result.success, "failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[1]);

    assert_eq!(result.events.len(), 1, "events={:?}", result.events);
    let evt = &result.events[0];
    assert_eq!(evt.user_id, ctx.user_id);
    assert_eq!(evt.contract_id, ctx.contract_id);
    assert_eq!(evt.data, vec![5, 1]);
}

#[test]
fn psystd_split_bits_should_work_but_currently_fails() {
    // Intentionally failing regression test:
    // split_bits/sum_bits should be executable end-to-end.
    let ctx = default_context();
    let result = execute(STD_SOURCE, "split_bits_should_work", &ctx, &[13]);
    assert!(result.success, "expected success, failure={:?}", result.failure);
    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[3]);
}
