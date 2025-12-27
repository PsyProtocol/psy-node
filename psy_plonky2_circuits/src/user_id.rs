use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};
use psy_core::user_id::UserIdGeneratorBuilderBridge;


// --- Plonky2 Bridge (For Circuits) ---
pub struct Plonky2UserIdGeneratorBuilderBridge;

impl<F: RichField + Extendable<D>, const D: usize> UserIdGeneratorBuilderBridge<CircuitBuilder<F, D>, Target, BoolTarget> for Plonky2UserIdGeneratorBuilderBridge {
    fn bridge_le_sum(
        builder: &mut CircuitBuilder<F, D>,
        bits: &[BoolTarget],
    ) -> Target {
        builder.le_sum(bits.iter())
    }
}


#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::{Field, PrimeField64},
        iop::{target::{BoolTarget, Target}, witness::{PartialWitness, WitnessWrite}},
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::{CircuitConfig, CircuitData}, config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig}
        },
    };
    use psy_core::user_id::{ExU64UserIdGeneratorBuilderBridge, UserIdBitsStrategy4, UserIdBitsStrategy5, UserIdGeneratorStrategy};
    use rand::{thread_rng, RngCore};

    use super::Plonky2UserIdGeneratorBuilderBridge;


    /// Helper to split a u64 into a vector of booleans (LSB first).
    fn split_u64_le(value: u64, num_bits: usize) -> Vec<bool> {
        (0..num_bits).map(|i| ((value >> i) & 1) == 1).collect()
    }


    // --- Circuit Verification Helper ---
    struct CircuitTester<C: GenericConfig<D>, const D: usize> {
        pub user_registration_ids: Vec<Target>,
        pub circuit_data: CircuitData<C::F, C, D>,
    }

    impl<C: GenericConfig<D>, const D: usize> CircuitTester<C, D> where C::Hasher: AlgebraicHasher<C::F> {
        pub fn new<UIDGen: UserIdGeneratorStrategy>(
            count: usize,
            coordinator_global_user_tree_height: u8,
            realm_global_user_tree_height: u8,
            group_realm_height: u8,
        ) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<C::F, D>::new(config);
            let user_registration_ids = builder.add_virtual_targets(count);

            let user_ids = user_registration_ids.iter().map(|&idx| {
                let global_user_tree_height = (coordinator_global_user_tree_height + realm_global_user_tree_height) as usize;
                let bits = builder.split_le(idx, global_user_tree_height);
                UIDGen::circuit_get_user_id_from_user_registration_id::<Plonky2UserIdGeneratorBuilderBridge, CircuitBuilder<C::F, D>, Target, BoolTarget>(
                    &mut builder, &bits, coordinator_global_user_tree_height, realm_global_user_tree_height, group_realm_height
                )
            }).collect::<Vec<_>>();

            builder.register_public_inputs(&user_ids);
            Self { user_registration_ids, circuit_data: builder.build::<C>() }
        }

        pub fn verify_against_optimized<UIDGen: UserIdGeneratorStrategy>(
            &self,
            inputs: &[u64],
            coordinator_global_user_tree_height: u8,
            realm_global_user_tree_height: u8,
            group_realm_height: u8,
        ) {
            let mut pw = PartialWitness::<C::F>::new();
            for (t, v) in self.user_registration_ids.iter().zip(inputs.iter()) {
                pw.set_target(*t, C::F::from_noncanonical_u64(*v)).unwrap();
            }
            let proof = self.circuit_data.prove(pw).expect("Proof failed");
            
            for (circuit_out, &native_in) in proof.public_inputs.iter().zip(inputs.iter()) {
                let circuit_val = circuit_out.to_canonical_u64();
                let expected = UIDGen::get_user_id_from_user_registration_id(
                    native_in,
                    coordinator_global_user_tree_height,
                    realm_global_user_tree_height,
                    group_realm_height
                );
                assert_eq!(circuit_val, expected, "Circuit != Optimized Native for input {}", native_in);
            }
        }
    }

    // Constants based on QNetworkTreeConstants
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 12;
    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 20;
    const GROUP_REALM_HEIGHT: u8 = 4; // Set to 4 to test 16-realm load balancing
    const GLOBAL_USER_TREE_HEIGHT: usize = 32;

    fn verify_strategy_full_coverage<S: UserIdGeneratorStrategy>(
        name: &str,
        coordinator_global_user_tree_height: u8,
        realm_global_user_tree_height: u8,
        group_realm_height: u8,
    ) {
        println!("Verifying {} with Coord={}, Realm={}, Group={}", 
            name, coordinator_global_user_tree_height, realm_global_user_tree_height, group_realm_height);
        
        let mut rng = thread_rng();
        let global_user_tree_height = (coordinator_global_user_tree_height + realm_global_user_tree_height) as usize;
        let limit = 1u64 << global_user_tree_height;
        
        let mut test_user_registration_ids = Vec::new();
        // Sequential ranges for edge cases
        test_user_registration_ids.extend(0..2000); 
        test_user_registration_ids.extend((limit - 2000)..limit);
        // Random fuzzing
        for _ in 0..5000 {
            test_user_registration_ids.push(rng.next_u64() & (limit - 1));
        }

        for &user_registration_id in &test_user_registration_ids {
            let bits = split_u64_le(user_registration_id, global_user_tree_height);
            
            // 1. Generic (simulates Circuit Logic via Bridge)
            let generic = S::circuit_get_user_id_from_user_registration_id::<ExU64UserIdGeneratorBuilderBridge, (), u64, bool>(
                &mut (), 
                &bits, 
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );
            
            // 2. Optimized Native Logic
            let optimized = S::get_user_id_from_user_registration_id(
                user_registration_id,
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );

            assert_eq!(generic, optimized, "Generic vs Optimized mismatch for ID {}", user_registration_id);

            // 3. Inverse Logic
            let recovered = S::get_user_registration_id_from_user_id(
                optimized,
                coordinator_global_user_tree_height, 
                realm_global_user_tree_height, 
                group_realm_height
            );
            assert_eq!(user_registration_id, recovered, "Inverse failed for ID {}", user_registration_id);
        }
    }

    #[test]
    fn test_strategy_5_equivalence() { verify_strategy_full_coverage::<UserIdBitsStrategy5>("S5", COORDINATOR_GLOBAL_USER_TREE_HEIGHT, REALM_GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT); }

    #[test]
    fn test_strategy_5_distribution() {
        // Specific test to prove Strategy 5 maximizes distance and balances load
        println!("Testing S5 Distribution Logic...");
        
        // Setup: Group=4 (16 Realms), UserHeight=10
        let g_h = 4;
        let r_h = 10;
        let c_h = 10; // arbitrary, just needs to be >= g_h

        // Case 1: Load Balancing across Realms
        // RegID 0 should be Realm 0
        // RegID 1 should be Realm 8 (since we reverse the realm index bits 0001 -> 1000)
        let id0 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(0, c_h, r_h, g_h);
        let id1 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(1, c_h, r_h, g_h);
        
        let realm0 = id0 >> r_h;
        let realm1 = id1 >> r_h;
        
        println!("RegID 0 -> Realm {}", realm0);
        println!("RegID 1 -> Realm {}", realm1);
        
        assert_ne!(realm0, realm1, "Sequential IDs should go to different realms");
        assert_eq!(realm0 & 0xF, 0, "RegID 0 -> Realm 0");
        assert_eq!(realm1 & 0xF, 8, "RegID 1 -> Realm 8 (Bit reversal check)");

        // Case 2: Max Distance within a Realm
        // RegID 0 -> Realm 0, User Index 0
        // RegID 16 -> Realm 0, User Index 1 (Cycle repeats after 16)
        let id16 = UserIdBitsStrategy5::get_user_id_from_user_registration_id(16, c_h, r_h, g_h);
        
        let user_idx_0 = id0 & ((1 << r_h) - 1);
        let user_idx_16 = id16 & ((1 << r_h) - 1);

        println!("RegID 0  (Realm 0, User 0) -> Tree Index: {:010b} ({})", user_idx_0, user_idx_0);
        println!("RegID 16 (Realm 0, User 1) -> Tree Index: {:010b} ({})", user_idx_16, user_idx_16);

        // Expectation: 
        // User 0 (00...0) -> Reversal -> 00...0 (Far Left)
        // User 1 (00...1) -> Reversal -> 10...0 (Far Right)
        assert_eq!(user_idx_0, 0);
        assert_eq!(user_idx_16, 1 << (r_h - 1), "User 1 should be at max distance from User 0");
    }

    #[test]
    fn test_strategy_5_circuit_execution() {
        let mut rng = thread_rng();
        let limit = 1u64 << GLOBAL_USER_TREE_HEIGHT;
        let batch_size = 5;
        let tester = CircuitTester::<PoseidonGoldilocksConfig, 2>::new::<UserIdBitsStrategy5>(
            batch_size, COORDINATOR_GLOBAL_USER_TREE_HEIGHT, REALM_GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT
        );
        
        let inputs: Vec<u64> = (0..batch_size).map(|_| rng.next_u64() & (limit - 1)).collect();
        tester.verify_against_optimized::<UserIdBitsStrategy5>(&inputs, COORDINATOR_GLOBAL_USER_TREE_HEIGHT, REALM_GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT);
    }

    #[test]
    fn test_strategy_4_edge_cases() {
        // Strategy 4 has integer division logic (R_H / 2). Test odd height.
        let odd_r_h = 13;
        let odd_c_h = 10;
        let odd_g_h = 1;
        let total = (odd_c_h + odd_r_h) as usize;
        
        let id = 12345u64;
        let bits = split_u64_le(id, total);
        
        let generic = UserIdBitsStrategy4::circuit_get_user_id_from_user_registration_id::<ExU64UserIdGeneratorBuilderBridge, (), u64, bool>(
            &mut (), &bits, odd_c_h, odd_r_h, odd_g_h
        );
        let optimized = UserIdBitsStrategy4::get_user_id_from_user_registration_id(id, odd_c_h, odd_r_h, odd_g_h);
        
        assert_eq!(generic, optimized, "Mismatch on odd Realm Height");
        
        let recovered = UserIdBitsStrategy4::get_user_registration_id_from_user_id(optimized, odd_c_h, odd_r_h, odd_g_h);
        assert_eq!(id, recovered, "Inverse failed on odd Realm Height");
    }
}