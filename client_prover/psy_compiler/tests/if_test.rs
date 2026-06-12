mod common;

use common::{assert_write, default_context, execute};

const IF_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[contract]
    pub struct IfContract {
        pub value: Felt, // slot 0
    }

    #[contract_implementation]
    impl IfContract {
        #[contract_method]
        pub fn choose(&mut self, ctx: &ChainContext, flag: Bool, a: Felt, b: Felt) {
            if flag {
                self.value = a;
            } else {
                self.value = b;
            }
        }

        #[contract_method]
        pub fn choose_three(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            if a > b {
                self.value = 10;
            } else if b > c {
                self.value = 20;
            } else {
                self.value = 30;
            }
        }

        #[contract_method]
        pub fn nested_choose(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt) {
            if a > b {
                if b > c {
                    self.value = 100;
                } else {
                    self.value = 200;
                }
            } else {
                self.value = 300;
            }
        }

        #[contract_method]
        pub fn branch_with_locals(&mut self, ctx: &ChainContext, a: Felt, b: Felt) {
            if a > b {
                let t0 = a + b;
                let t1 = t0 + 1;
                self.value = t1;
            } else {
                let t2 = b - a;
                self.value = t2 + 2;
            }
        }

        #[contract_method]
        pub fn guarded_if(&mut self, ctx: &ChainContext, x: Felt) {
            if x > 0 {
                self.value = x;
            } else {
                self.value = 0;
            }
            require(self.value != 0, "value must be non-zero");
        }

        #[contract_method]
        pub fn deeply_nested_if(&mut self, ctx: &ChainContext, a: Felt, b: Felt, c: Felt, d: Felt) {
            if a > b {
                if b > c {
                    if c > d {
                        let t0 = a + b;
                        self.value = t0 + c; // path 111 -> 12 for 5,4,3,2
                    } else if a > d {
                        let t1 = a + d;
                        self.value = t1 + 100; // path 110 -> 109 for 5,4,2,4
                    } else {
                        self.value = 999;
                    }
                } else if a > c {
                    if d > b {
                        self.value = 200;
                    } else {
                        self.value = 300;
                    }
                } else {
                    self.value = 400;
                }
            } else if b > c {
                if c > d {
                    self.value = 500;
                } else {
                    self.value = 600;
                }
            } else if c > d {
                let t2 = c - d;
                self.value = t2 + 700; // 701 for 2,3,5,4
            } else {
                self.value = 800;
            }
        }

        #[contract_method]
        pub fn fee_with_temp_var(&mut self, ctx: &ChainContext, caller_is_vip: Bool, low_fee: Felt, high_fee: Felt) {
            let fee: Felt;
            if caller_is_vip {
                fee = low_fee;
            } else {
                fee = high_fee;
            }
            self.value = 100 - fee;
        }
    }
"#;

#[test]
fn if_else_branch_writes_expected_value() {
    let ctx = default_context();
    let r_true = execute(IF_SOURCE, "choose", &ctx, &[1, 11, 99]);
    let r_false = execute(IF_SOURCE, "choose", &ctx, &[0, 11, 99]);

    assert!(r_true.success);
    assert_write(&r_true, ctx.user_id, ctx.contract_id, 0, &[11]);
    assert!(r_false.success);
    assert_write(&r_false, ctx.user_id, ctx.contract_id, 0, &[99]);
}

#[test]
fn if_else_if_else_paths() {
    let ctx = default_context();

    let p1 = execute(IF_SOURCE, "choose_three", &ctx, &[5, 3, 1]);
    assert!(p1.success);
    assert_write(&p1, ctx.user_id, ctx.contract_id, 0, &[10]);

    let p2 = execute(IF_SOURCE, "choose_three", &ctx, &[1, 5, 3]);
    assert!(p2.success);
    assert_write(&p2, ctx.user_id, ctx.contract_id, 0, &[20]);

    let p3 = execute(IF_SOURCE, "choose_three", &ctx, &[1, 2, 3]);
    assert!(p3.success);
    assert_write(&p3, ctx.user_id, ctx.contract_id, 0, &[30]);
}

#[test]
fn nested_if_paths() {
    let ctx = default_context();

    let n1 = execute(IF_SOURCE, "nested_choose", &ctx, &[5, 4, 3]);
    assert!(n1.success);
    assert_write(&n1, ctx.user_id, ctx.contract_id, 0, &[100]);

    let n2 = execute(IF_SOURCE, "nested_choose", &ctx, &[5, 2, 3]);
    assert!(n2.success);
    assert_write(&n2, ctx.user_id, ctx.contract_id, 0, &[200]);

    let n3 = execute(IF_SOURCE, "nested_choose", &ctx, &[1, 2, 3]);
    assert!(n3.success);
    assert_write(&n3, ctx.user_id, ctx.contract_id, 0, &[300]);
}

#[test]
fn if_branch_with_local_bindings() {
    let ctx = default_context();

    let b1 = execute(IF_SOURCE, "branch_with_locals", &ctx, &[9, 2]);
    assert!(b1.success);
    assert_write(&b1, ctx.user_id, ctx.contract_id, 0, &[12]); // (9+2)+1

    let b2 = execute(IF_SOURCE, "branch_with_locals", &ctx, &[2, 9]);
    assert!(b2.success);
    assert_write(&b2, ctx.user_id, ctx.contract_id, 0, &[9]); // (9-2)+2
}

#[test]
fn if_guarded_success_and_failure() {
    let ctx = default_context();

    let ok = execute(IF_SOURCE, "guarded_if", &ctx, &[7]);
    assert!(ok.success);
    assert_write(&ok, ctx.user_id, ctx.contract_id, 0, &[7]);

    let fail = execute(IF_SOURCE, "guarded_if", &ctx, &[0]);
    assert!(!fail.success);
    assert!(fail.failure.is_some());
}

#[test]
fn deeply_nested_if_else_paths() {
    let ctx = default_context();

    // a>b, b>c, c>d
    let p1 = execute(IF_SOURCE, "deeply_nested_if", &ctx, &[5, 4, 3, 2]);
    assert!(p1.success);
    assert_write(&p1, ctx.user_id, ctx.contract_id, 0, &[12]);

    // a>b, b>c, !(c>d), a>d
    let p2 = execute(IF_SOURCE, "deeply_nested_if", &ctx, &[5, 4, 2, 4]);
    assert!(p2.success);
    assert_write(&p2, ctx.user_id, ctx.contract_id, 0, &[109]);

    // !(a>b), b>c, !(c>d)
    let p3 = execute(IF_SOURCE, "deeply_nested_if", &ctx, &[2, 5, 3, 4]);
    assert!(p3.success);
    assert_write(&p3, ctx.user_id, ctx.contract_id, 0, &[600]);

    // !(a>b), !(b>c), c>d
    let p4 = execute(IF_SOURCE, "deeply_nested_if", &ctx, &[2, 3, 5, 4]);
    assert!(p4.success);
    assert_write(&p4, ctx.user_id, ctx.contract_id, 0, &[701]);

    // fallthrough else
    let p5 = execute(IF_SOURCE, "deeply_nested_if", &ctx, &[1, 2, 3, 4]);
    assert!(p5.success);
    assert_write(&p5, ctx.user_id, ctx.contract_id, 0, &[800]);
}

#[test]
fn temp_variable_assigned_in_if_else() {
    let ctx = default_context();
    let vip = execute(IF_SOURCE, "fee_with_temp_var", &ctx, &[1, 3, 9]);
    assert!(vip.success);
    assert_write(&vip, ctx.user_id, ctx.contract_id, 0, &[97]);

    let normal = execute(IF_SOURCE, "fee_with_temp_var", &ctx, &[0, 3, 9]);
    assert!(normal.success);
    assert_write(&normal, ctx.user_id, ctx.contract_id, 0, &[91]);
}
