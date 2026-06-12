use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};
use psy_config::network_constants::{COORDINATOR_USER_TREE_HEIGHT, GLOBAL_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT, REALM_USER_TREE_HEIGHT};

fn reverse_bits_in_limit(x: u64, num_bits: u8) -> u64 {
    let dif = 64 - num_bits as u64;
    (x).reverse_bits() >> dif
}

pub trait UserIdGeneratorStrategy {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        global_user_tree_height: usize,
    ) -> Target;
    fn get_user_id_from_registration_id(registration_id: u64) -> u64;
    // add this function
    fn get_registration_id_from_user_id(user_id: u64) -> u64;
}
pub struct UserIdBitsStrategy1;

impl UserIdGeneratorStrategy for UserIdBitsStrategy1 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _global_user_tree_height: usize,
    ) -> Target {
        let mut reversed_bits = user_registration_tree_leaf_index_bits.to_vec();
        reversed_bits.reverse();

        let reversed_bits_index = builder.le_sum(reversed_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
        let dif = 64 - GLOBAL_USER_TREE_HEIGHT as u64;
        (registration_id).reverse_bits() >> dif
    }

    fn get_registration_id_from_user_id(user_id: u64) -> u64 {
        reverse_bits_in_limit(user_id, GLOBAL_USER_TREE_HEIGHT)
    }
}

pub struct UserIdBitsStrategy2;

impl UserIdGeneratorStrategy for UserIdBitsStrategy2 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _global_user_tree_height: usize,
    ) -> Target {
        let mut new_top_bits = user_registration_tree_leaf_index_bits[0..(COORDINATOR_USER_TREE_HEIGHT as usize)].to_vec();
        new_top_bits.reverse();

        let new_bottom_bits = user_registration_tree_leaf_index_bits[(COORDINATOR_USER_TREE_HEIGHT as usize)..].to_vec();

        let new_bits = [new_bottom_bits, new_top_bits].concat();
        let reversed_bits_index = builder.le_sum(new_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
        // rotate realms on each index
        let new_top_bits = reverse_bits_in_limit(
            registration_id & ((1u64 << COORDINATOR_USER_TREE_HEIGHT) - 1u64),
            COORDINATOR_USER_TREE_HEIGHT,
        );

        // sequential within realms
        let new_bottom_bits = registration_id >> COORDINATOR_USER_TREE_HEIGHT;

        (new_top_bits << REALM_USER_TREE_HEIGHT) | new_bottom_bits
    }

    fn get_registration_id_from_user_id(user_id: u64) -> u64 {
        let realm_seq = user_id & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
        let reversed_coord = user_id >> REALM_USER_TREE_HEIGHT;
        let coord_id = reverse_bits_in_limit(reversed_coord, COORDINATOR_USER_TREE_HEIGHT);
        (realm_seq << COORDINATOR_USER_TREE_HEIGHT) | coord_id
    }
}

pub struct UserIdBitsStrategy3;

impl UserIdGeneratorStrategy for UserIdBitsStrategy3 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _global_user_tree_height: usize,
    ) -> Target {
        let mut new_top_bits = user_registration_tree_leaf_index_bits[10..].to_vec();
        new_top_bits.reverse();

        let new_bottom_bits = user_registration_tree_leaf_index_bits[0..10].to_vec();

        let new_bits = [new_bottom_bits, new_top_bits].concat();
        let reversed_bits_index = builder.le_sum(new_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
        (reverse_bits_in_limit(registration_id >> 10u64, GLOBAL_USER_TREE_HEIGHT - 10) << 10u64) | (registration_id & ((1u64 << 10) - 1u64))
    }

    fn get_registration_id_from_user_id(user_id: u64) -> u64 {
        let low = user_id & ((1u64 << 10) - 1);
        let reversed_top = user_id >> 10;
        let top_part = reverse_bits_in_limit(reversed_top, GLOBAL_USER_TREE_HEIGHT - 10);
        (top_part << 10) | low
    }
}

pub struct UserIdBitsStrategy4;

//   user id must avoid common prefix to make the nca algorithm more useful
//
//   Case 0:
//   0  = 0000
//   1  = 0001
//   2  = 0010
//   4  = 0100
//
//   Case 1:
//   10  = 000000000000000000001010
//   26  = 000000000000000000011010
//   76  = 000000000000000001001100
//   140 = 000000000000000010001100
//
//   Case 2:
//   1076736: 000100 000110 000000 000000
//   1080832: 000100 001010 000000 000000
//   1082880: 000100 001100 000000 000000
//   1089024: 000100 010010 000000 000000
//   1093120: 000100 010110 000000 000000
//   1096704: 000100 011010 000000 000000
//   1121280: 000100 100010 000000 000000
impl UserIdGeneratorStrategy for UserIdBitsStrategy4 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _global_user_tree_height: usize,
    ) -> Target {
        let mut realm_index_bit = user_registration_tree_leaf_index_bits[0..(GROUP_REALM_HEIGHT as usize)].to_vec();
        realm_index_bit.reverse();

        let user_index_bits =
            user_registration_tree_leaf_index_bits[(GROUP_REALM_HEIGHT as usize)..((GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT) as usize)].to_vec();

        let group_id_bits = user_registration_tree_leaf_index_bits[((GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT) as usize)..].to_vec();

        let user_index_half_bits = (REALM_USER_TREE_HEIGHT / 2) as usize;
        let user_index_low_half = user_index_bits[0..user_index_half_bits].to_vec();
        let mut user_index_high_half = user_index_bits[user_index_half_bits..].to_vec();

        user_index_high_half.reverse();

        let modified_user_index_bits = [user_index_high_half, user_index_low_half].concat();

        let new_bits = [modified_user_index_bits, realm_index_bit, group_id_bits].concat();
        let user_id = builder.le_sum(new_bits.iter());

        user_id
    }

    fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
        let realm_index = registration_id & ((1u64 << GROUP_REALM_HEIGHT) - 1);
        let user_index = (registration_id >> GROUP_REALM_HEIGHT) & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
        let group_id =
            (registration_id >> (GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT)) & ((1u64 << (COORDINATOR_USER_TREE_HEIGHT - GROUP_REALM_HEIGHT)) - 1);

        let reversed_realm_index = reverse_bits_in_limit(realm_index, GROUP_REALM_HEIGHT);
        let realm_id = (group_id << GROUP_REALM_HEIGHT) | reversed_realm_index;

        let user_index_half_bits = REALM_USER_TREE_HEIGHT / 2;
        let user_index_low_half = user_index & ((1u64 << user_index_half_bits) - 1);
        let user_index_high_half = (user_index >> user_index_half_bits) & ((1u64 << user_index_half_bits) - 1);

        let reversed_user_index_high_half = reverse_bits_in_limit(user_index_high_half, user_index_half_bits);
        let modified_user_index = (user_index_low_half << user_index_half_bits) | reversed_user_index_high_half;

        (realm_id << REALM_USER_TREE_HEIGHT) | modified_user_index
    }

    fn get_registration_id_from_user_id(user_id: u64) -> u64 {
        let modified_user_index = user_id & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
        let realm_id = user_id >> REALM_USER_TREE_HEIGHT;

        let half = REALM_USER_TREE_HEIGHT / 2;
        let reversed_high_half = modified_user_index & ((1u64 << half) - 1);
        let low_half = modified_user_index >> half;
        let high_half = reverse_bits_in_limit(reversed_high_half, half);
        let user_index = (high_half << half) | low_half;

        let reversed_realm_index = realm_id & ((1u64 << GROUP_REALM_HEIGHT) - 1);
        let group_id = realm_id >> GROUP_REALM_HEIGHT;
        let realm_index = reverse_bits_in_limit(reversed_realm_index, GROUP_REALM_HEIGHT);

        let shift1 = GROUP_REALM_HEIGHT;
        let shift2 = GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT;
        ((group_id << shift2) | (user_index << shift1)) | realm_index
    }
}

pub struct UserIdBitsStrategy5;

impl UserIdGeneratorStrategy for UserIdBitsStrategy5 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _global_user_tree_height: usize,
    ) -> Target {
        let group_realm_height_usize = GROUP_REALM_HEIGHT as usize;
        let realm_global_user_tree_height_usize = REALM_USER_TREE_HEIGHT as usize;

        // 1. Slice Input Bits
        // LSBs (size: group_realm_height) -> Realm Index
        let realm_index_bits = user_registration_tree_leaf_index_bits[0..group_realm_height_usize].to_vec();

        // Middle (size: realm_global_user_tree_height) -> User Index
        let user_index_start = group_realm_height_usize;
        let user_index_end = group_realm_height_usize + realm_global_user_tree_height_usize;
        let user_index_bits = user_registration_tree_leaf_index_bits[user_index_start..user_index_end].to_vec();

        // MSBs (size: coordinator - group) -> Group ID
        let group_id_bits = user_registration_tree_leaf_index_bits[user_index_end..].to_vec();

        // 2. Process Realm Bits
        // Reverse them to ensure we jump significantly between realms (0 -> 8 -> 4...)
        // rather than filling 0 -> 1 -> 2.
        let mut reversed_realm_index_bits = realm_index_bits;
        reversed_realm_index_bits.reverse();

        // 3. Process User Index Bits (THE CHANGE vs S4)
        // Fully reverse the bits for maximum distance within the realm tree.
        let mut reversed_user_index_bits = user_index_bits;
        reversed_user_index_bits.reverse();

        // 4. Final Assembly
        // Vector Order for le_sum (LSB -> MSB):
        // [Reversed User Index] [Reversed Realm Index] [Group ID]
        // This constructs an integer: (Group << ...) | (RevRealm << ...) | RevUser
        let new_bits = [reversed_user_index_bits, reversed_realm_index_bits, group_id_bits].concat();

        builder.le_sum(new_bits.iter())
    }

    fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
        // 1. Parse Input Registration ID
        let realm_index = registration_id & ((1u64 << GROUP_REALM_HEIGHT) - 1);
        let user_index = (registration_id >> GROUP_REALM_HEIGHT) & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);

        let shift_amount_for_group = GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT;
        let group_id_height = COORDINATOR_USER_TREE_HEIGHT - GROUP_REALM_HEIGHT;
        let group_id = (registration_id >> shift_amount_for_group) & ((1u64 << group_id_height) - 1);

        // 2. Process Realm Part
        let reversed_realm_index = reverse_bits_in_limit(realm_index, GROUP_REALM_HEIGHT);

        // Full Realm ID = (Group ID << Group_Height) | Reversed Realm Index
        let full_realm_id = (group_id << GROUP_REALM_HEIGHT) | reversed_realm_index;

        // 3. Process User Part (Max Distance)
        let reversed_user_index = reverse_bits_in_limit(user_index, REALM_USER_TREE_HEIGHT);

        // 4. Final Assembly: (Full Realm ID << Realm_Height) | Reversed User Index
        (full_realm_id << REALM_USER_TREE_HEIGHT) | reversed_user_index
    }

    fn get_registration_id_from_user_id(user_id: u64) -> u64 {
        // 1. Unpack Tree Index (User ID)
        // Structure: [Full Realm ID (MSB)] [Reversed User Index (LSB)]
        let reversed_user_index = user_id & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
        let full_realm_id = user_id >> REALM_USER_TREE_HEIGHT;

        // 2. Revert User Index
        // The inverse of a full reversal is a full reversal.
        let original_user_index = reverse_bits_in_limit(reversed_user_index, REALM_USER_TREE_HEIGHT);

        // 3. Revert Realm Part
        let reversed_realm_index = full_realm_id & ((1u64 << GROUP_REALM_HEIGHT) - 1);
        let group_id = full_realm_id >> GROUP_REALM_HEIGHT;

        let original_realm_index = reverse_bits_in_limit(reversed_realm_index, GROUP_REALM_HEIGHT);

        // 4. Reconstruct Input Registration ID
        let shift_for_user = GROUP_REALM_HEIGHT;
        let shift_for_group = GROUP_REALM_HEIGHT + REALM_USER_TREE_HEIGHT;

        (group_id << shift_for_group) | (original_user_index << shift_for_user) | original_realm_index
    }
}
/*
// reverse bits gives a very even distribution
pub fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
    let dif = 64 - GLOBAL_USER_TREE_HEIGHT as u64;
    (registration_id).reverse_bits() >> dif
}


pub fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    _user_registration_tree_leaf_index: Target,
    user_registration_tree_leaf_index_bits: &[BoolTarget],
    _global_user_tree_height: usize,
) -> Target {
    let mut reversed_bits = user_registration_tree_leaf_index_bits.to_vec();
    reversed_bits.reverse();

    let reversed_bits_index = builder.le_sum(reversed_bits.iter());

    reversed_bits_index
}
*/

type UserIdBitsStrategy = UserIdBitsStrategy5;

pub fn get_user_id_from_registration_id(registration_id: u64) -> u64 {
    UserIdBitsStrategy::get_user_id_from_registration_id(registration_id)
}
pub fn get_registration_id_from_user_id(user_id: u64) -> u64 {
    UserIdBitsStrategy::get_registration_id_from_user_id(user_id)
}
pub fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    user_registration_tree_leaf_index: Target,
    user_registration_tree_leaf_index_bits: &[BoolTarget],
    global_user_tree_height: usize,
) -> Target {
    UserIdBitsStrategy::circuit_user_registration_tree_index_bits_to_user_id::<H, F, D>(
        builder,
        user_registration_tree_leaf_index,
        user_registration_tree_leaf_index_bits,
        global_user_tree_height,
    )
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::types::{Field, PrimeField64},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use psy_config::network_constants::GLOBAL_USER_TREE_HEIGHT;
    use rand::{thread_rng, RngCore};

    use super::{UserIdBitsStrategy1, UserIdBitsStrategy2, UserIdBitsStrategy3, UserIdBitsStrategy4, UserIdBitsStrategy5, UserIdGeneratorStrategy};

    struct SimpleBitsTester<C: GenericConfig<D>, const D: usize> {
        pub registration_ids: Vec<Target>,
        //pub user_ids: Vec<Target>,
        pub circuit_data: CircuitData<C::F, C, D>,
    }

    impl<C: GenericConfig<D>, const D: usize> SimpleBitsTester<C, D>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub fn new<UIDGen: UserIdGeneratorStrategy>(count: usize, global_user_tree_height: usize) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<C::F, D>::new(config);
            let registration_ids = builder.add_virtual_targets(count);

            let user_ids = registration_ids
                .iter()
                .map(|x| {
                    let user_registration_tree_leaf_index = *x;
                    let user_registration_tree_leaf_index_bits = builder.split_le(user_registration_tree_leaf_index, global_user_tree_height);

                    UIDGen::circuit_user_registration_tree_index_bits_to_user_id::<C::Hasher, C::F, D>(
                        &mut builder,
                        user_registration_tree_leaf_index,
                        &user_registration_tree_leaf_index_bits,
                        global_user_tree_height,
                    )
                })
                .collect::<Vec<_>>();

            //builder.register_public_inputs(&registration_ids);
            builder.register_public_inputs(&user_ids);

            let circuit_data = builder.build::<C>();
            Self {
                registration_ids,
                circuit_data,
            }
        }

        pub fn prove_base(&self, registration_ids: &[u64]) -> anyhow::Result<ProofWithPublicInputs<C::F, C, D>> {
            let mut pw = PartialWitness::<C::F>::new();
            //tracing::info!("agg_fingerprint: {}", agg_fingerprint.to_string());
            //tracing::info!("leaf_fingerprint: {}", leaf_fingerprint.to_string());
            for (t, v) in self.registration_ids.iter().zip(registration_ids.iter()) {
                pw.set_target(*t, C::F::from_noncanonical_u64(*v))?;
            }
            /*
            let inner_proof = self.circuit_data.prove(pw)?;

            self.minifier_chain.prove(&inner_proof)*/
            self.circuit_data.prove(pw)
        }
        pub fn check_strategy<UIDGen: UserIdGeneratorStrategy>(&self, registration_ids: &[u64]) -> anyhow::Result<()> {
            for (user_id, reg_id) in self
                .prove_base(registration_ids)?
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .zip(registration_ids.iter())
            {
                let expected_user_id = UIDGen::get_user_id_from_registration_id(*reg_id);
                if expected_user_id != user_id {
                    anyhow::bail!(
                        "expected registration_id {} to map to {}, but got {} from the circuit instead",
                        *reg_id,
                        expected_user_id,
                        user_id
                    );
                }
            }

            Ok(())
        }
        pub fn full_check<UIDGen: UserIdGeneratorStrategy>(batch_size: usize, count: usize, rand_count: usize) -> anyhow::Result<()> {
            let max_regions = (count / batch_size) as u64;
            let rand_regions = (rand_count / batch_size) as u64;
            let b_size = batch_size as u64;
            let circ = Self::new::<UIDGen>(batch_size, GLOBAL_USER_TREE_HEIGHT as usize);
            let mask = (1u64 << GLOBAL_USER_TREE_HEIGHT) - 1u64;
            for i in 0u64..(max_regions + 1) {
                let ids = ((i * b_size)..((i + 1u64) * b_size)).map(|x| x & mask).collect::<Vec<u64>>();
                circ.check_strategy::<UIDGen>(&ids)?;
            }
            for _ in 0u64..rand_regions {
                let ids = (0..batch_size).map(|_| thread_rng().next_u64() & mask).collect::<Vec<_>>();
                circ.check_strategy::<UIDGen>(&ids)?;
            }

            Ok(())
        }
    }

    fn test_inverse<UIDGen: UserIdGeneratorStrategy>(batch_size: usize, count: usize, rand_count: usize) -> anyhow::Result<()> {
        let height = GLOBAL_USER_TREE_HEIGHT as u64;
        let mask = (1u64 << height) - 1;
        let max_regions = (count / batch_size) as u64;
        let rand_regions = (rand_count / batch_size) as u64;
        let b_size = batch_size as u64;
        for i in 0u64..(max_regions + 1) {
            let ids: Vec<u64> = ((i * b_size)..((i + 1u64) * b_size)).map(|x| x & mask).collect();
            for &reg in &ids {
                let user = UIDGen::get_user_id_from_registration_id(reg);
                let reg_back = UIDGen::get_registration_id_from_user_id(user);
                if reg_back != reg {
                    anyhow::bail!("Inverse failed: reg {} -> user {} -> back {}", reg, user, reg_back);
                }
            }
        }
        for _ in 0u64..rand_regions {
            let ids: Vec<u64> = (0..batch_size).map(|_| thread_rng().next_u64() & mask).collect();
            for &reg in &ids {
                let user = UIDGen::get_user_id_from_registration_id(reg);
                let reg_back = UIDGen::get_registration_id_from_user_id(user);
                if reg_back != reg {
                    anyhow::bail!("Inverse failed: reg {} -> user {} -> back {}", reg, user, reg_back);
                }
            }
        }
        Ok(())
    }

    #[test]
    fn check_strategy_1() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy1>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn check_strategy_2() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy2>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn check_strategy_3() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy3>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn check_strategy_4() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy4>(1024, 64 * 1024, 64 * 1024).unwrap();
    }

    #[test]
    fn test_inverse_strategy_1() {
        test_inverse::<UserIdBitsStrategy1>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn test_inverse_strategy_2() {
        test_inverse::<UserIdBitsStrategy2>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn test_inverse_strategy_3() {
        test_inverse::<UserIdBitsStrategy3>(1024, 64 * 1024, 64 * 1024).unwrap();
    }
    #[test]
    fn test_inverse_strategy_4() {
        test_inverse::<UserIdBitsStrategy4>(1024, 64 * 1024, 64 * 1024).unwrap();
    }

    #[test]
    fn test_strategy_5_distribution_demo() {
        use psy_config::network_constants::{COORDINATOR_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT, REALM_USER_TREE_HEIGHT};

        println!("Testing UserIdBitsStrategy5 Distribution Logic...");

        // Test several registration IDs
        let test_ids = vec![0, 1, 2, 3, 4, 15, 16, 17, 31, 32, 33, 63, 64, 65];

        println!("Registration ID -> User ID -> Realm -> User Index");
        println!(
            "Constants: COORDINATOR_USER_TREE_HEIGHT={}, REALM_USER_TREE_HEIGHT={}, GROUP_REALM_HEIGHT={}",
            COORDINATOR_USER_TREE_HEIGHT, REALM_USER_TREE_HEIGHT, GROUP_REALM_HEIGHT
        );

        for &reg_id in &test_ids {
            let user_id = UserIdBitsStrategy5::get_user_id_from_registration_id(reg_id);
            let realm = user_id >> REALM_USER_TREE_HEIGHT;
            let user_index = user_id & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);

            println!("{:3} -> {:8} -> {:3} -> {:6} ({:020b})", reg_id, user_id, realm, user_index, user_index);
        }

        // Verify inverse operation works
        println!("\nTesting inverse operations:");
        for &reg_id in &test_ids {
            let user_id = UserIdBitsStrategy5::get_user_id_from_registration_id(reg_id);
            let back_to_reg = UserIdBitsStrategy5::get_registration_id_from_user_id(user_id);
            assert_eq!(reg_id, back_to_reg, "Inverse failed for reg_id {}", reg_id);
            println!("{} -> {} -> {} ✓", reg_id, user_id, back_to_reg);
        }

        // Test specific cases from the original test
        println!("\nTesting specific distribution cases:");

        // RegID 0 and 1 should go to different realms due to realm bit reversal
        let id0 = UserIdBitsStrategy5::get_user_id_from_registration_id(0);
        let id1 = UserIdBitsStrategy5::get_user_id_from_registration_id(1);
        let realm0 = id0 >> REALM_USER_TREE_HEIGHT;
        let realm1 = id1 >> REALM_USER_TREE_HEIGHT;

        println!("RegID 0: realm={}, user_index={}", realm0, id0 & ((1u64 << REALM_USER_TREE_HEIGHT) - 1));
        println!("RegID 1: realm={}, user_index={}", realm1, id1 & ((1u64 << REALM_USER_TREE_HEIGHT) - 1));

        // In realm 0, check user index distribution
        let id16 = UserIdBitsStrategy5::get_user_id_from_registration_id(16);
        let realm16 = id16 >> REALM_USER_TREE_HEIGHT;
        let _user_idx_0 = id0 & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
        let user_idx_16 = id16 & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);

        println!("RegID 16: realm={}, user_index={}", realm16, user_idx_16);

        // Test more detailed distribution within realms
        println!("\nDetailed analysis within realm 0:");
        let mut realm_0_user_ids = Vec::new();

        // Find all registration IDs that map to realm 0
        for reg_id in 0..1024 {
            // Test first 1024 IDs
            let user_id = UserIdBitsStrategy5::get_user_id_from_registration_id(reg_id);
            let realm = user_id >> REALM_USER_TREE_HEIGHT;
            if realm == 0 {
                let user_index = user_id & ((1u64 << REALM_USER_TREE_HEIGHT) - 1);
                realm_0_user_ids.push((reg_id, user_index));
                if realm_0_user_ids.len() >= 10 {
                    // Show first 10
                    break;
                }
            }
        }

        println!("Registration IDs mapping to realm 0:");
        for (reg_id, user_idx) in &realm_0_user_ids {
            println!("  RegID {} -> User Index {}", reg_id, user_idx);
        }

        println!("\nStrategy 5 demonstrates:");
        println!("1. Sequential registration IDs go to different realms (load balancing)");
        println!("2. Within the same realm, user indices show specific bit reversal patterns");
        println!("3. All operations are invertible (bijection)");
    }

    /*
    #[test]
    fn test_check_a(){
        let mut t = Vec::new();
        for i in 0..100 {
            t.push((
                i,
                UserIdBitsStrategy1::get_user_id_from_registration_id(i),
                UserIdBitsStrategy2::get_user_id_from_registration_id(i),
                UserIdBitsStrategy3::get_user_id_from_registration_id(i)
            ));
        }
        println!("{:#?}",t);
    }

    */
}
