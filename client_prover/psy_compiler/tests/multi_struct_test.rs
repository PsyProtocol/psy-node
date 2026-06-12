mod common;

use common::{assert_write, default_context, execute};

const MULTI_STRUCT_SOURCE: &str = r#"
    const PSY_TOTAL_USERS: usize = 4;
    const PSY_TOTAL_CONTRACTS: usize = 4;

    #[derive(FeltSized)]
    pub struct Profile {
        pub age: Felt,
        pub level: Felt,
    }

    #[derive(FeltSized)]
    pub struct Stats {
        pub wins: Felt,
        pub losses: Felt,
    }

    #[contract]
    pub struct MultiStructContract {
        pub profile: Profile, // slots 0,1
        pub stats: Stats,     // slots 2,3
        pub total: Felt,      // slot 4
    }

    #[contract_implementation]
    impl MultiStructContract {
        #[contract_method]
        pub fn set_values(&mut self, ctx: &ChainContext, age: Felt, level: Felt, wins: Felt, losses: Felt) {
            self.profile.age = age;
            self.profile.level = level;
            self.stats.wins = wins;
            self.stats.losses = losses;
            self.total = self.profile.age + self.stats.wins;
        }

        #[contract_method]
        pub fn bump_fields(&mut self, ctx: &ChainContext, delta: Felt) {
            self.profile.level += delta;
            self.stats.losses += 1;
            self.total = self.profile.level + self.stats.losses;
        }
    }
"#;

#[test]
fn multiple_struct_fields_write_expected_slots() {
    let ctx = default_context();
    let result = execute(MULTI_STRUCT_SOURCE, "set_values", &ctx, &[30, 7, 11, 2]);
    assert!(result.success, "failure={:?}", result.failure);

    assert_write(&result, ctx.user_id, ctx.contract_id, 0, &[30]); // profile.age
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[7]); // profile.level
    assert_write(&result, ctx.user_id, ctx.contract_id, 2, &[11]); // stats.wins
    assert_write(&result, ctx.user_id, ctx.contract_id, 3, &[2]); // stats.losses
    assert_write(&result, ctx.user_id, ctx.contract_id, 4, &[41]); // total = 30
                                                                   // + 11
}

#[test]
fn multiple_struct_fields_compound_assign_work() {
    let ctx = default_context();
    let result = execute(MULTI_STRUCT_SOURCE, "bump_fields", &ctx, &[5]);
    assert!(result.success, "failure={:?}", result.failure);

    // On fresh state: profile.level starts 0 -> 5, stats.losses starts 0 -> 1
    assert_write(&result, ctx.user_id, ctx.contract_id, 1, &[5]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 3, &[1]);
    assert_write(&result, ctx.user_id, ctx.contract_id, 4, &[6]); // total = 5 +
                                                                  // 1
}
