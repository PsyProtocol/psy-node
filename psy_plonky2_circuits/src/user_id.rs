use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{circuit_builder::CircuitBuilder, config::AlgebraicHasher},
};

fn reverse_bits_in_limit(x: u64, num_bits: u8) -> u64 {
    let dif = 64 - num_bits as u64;
    (x).reverse_bits() >> dif
}

pub trait UserIdGeneratorStrategy {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,
    ) -> Target;
    fn get_user_id_from_registration_id(registration_id: u64, coordinator_user_tree_height: u8, realm_user_tree_height: u8, group_realm_height: u8) -> u64;
}
pub struct UserIdBitsStrategy1;

impl UserIdGeneratorStrategy for UserIdBitsStrategy1 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        _coordinator_user_tree_height: u8,
        _realm_user_tree_height: u8,
        _group_realm_height: u8,
    ) -> Target {
        let mut reversed_bits = user_registration_tree_leaf_index_bits.to_vec();
        reversed_bits.reverse();

        let reversed_bits_index = builder.le_sum(reversed_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64, coordinator_user_tree_height: u8, realm_user_tree_height: u8,
        _group_realm_height: u8) -> u64 {
        let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as u64;

        let dif = 64 - global_user_tree_height;
        (registration_id).reverse_bits() >> dif
    }
}

pub struct UserIdBitsStrategy2;

impl UserIdGeneratorStrategy for UserIdBitsStrategy2 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        coordinator_user_tree_height: u8,
        realm_user_tree_height: u8,

        _group_realm_height: u8,
    ) -> Target {
        let mut new_top_bits = user_registration_tree_leaf_index_bits[0..(coordinator_user_tree_height as usize)].to_vec();
        new_top_bits.reverse();

        let new_bottom_bits = user_registration_tree_leaf_index_bits[(coordinator_user_tree_height as usize)..].to_vec();

        let new_bits = [new_bottom_bits, new_top_bits].concat();
        let reversed_bits_index = builder.le_sum(new_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64, coordinator_user_tree_height: u8, realm_user_tree_height: u8, 
        _group_realm_height: u8) -> u64 {
        // rotate realms on each index
        let new_top_bits = reverse_bits_in_limit(
            registration_id & ((1u64 << coordinator_user_tree_height) - 1u64),
            coordinator_user_tree_height,
        );

        // sequential within realms
        let new_bottom_bits = registration_id >> coordinator_user_tree_height;

        (new_top_bits << realm_user_tree_height) | new_bottom_bits
    }
}

pub struct UserIdBitsStrategy3;

impl UserIdGeneratorStrategy for UserIdBitsStrategy3 {
    fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        _user_registration_tree_leaf_index: Target,
        user_registration_tree_leaf_index_bits: &[BoolTarget],
        coordinator_user_tree_height: u8,
        realm_user_tree_height: u8,

        _group_realm_height: u8,
    ) -> Target {
        let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as usize;

        let mut new_top_bits = user_registration_tree_leaf_index_bits[10..].to_vec();
        new_top_bits.reverse();

        let new_bottom_bits = user_registration_tree_leaf_index_bits[0..10].to_vec();

        let new_bits = [new_bottom_bits, new_top_bits].concat();
        let reversed_bits_index = builder.le_sum(new_bits.iter());

        reversed_bits_index
    }

    fn get_user_id_from_registration_id(registration_id: u64, coordinator_user_tree_height: u8, realm_user_tree_height: u8, 
        _group_realm_height: u8) -> u64 {
        let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as usize;

        (reverse_bits_in_limit(registration_id >> 10u64, (global_user_tree_height - 10) as u8) << 10u64) | (registration_id & ((1u64 << 10) - 1u64))
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
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,
    ) -> Target {
        let mut realm_index_bit = user_registration_tree_leaf_index_bits[0..(group_realm_height as usize)].to_vec();
        realm_index_bit.reverse();

        let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as usize;
        let user_index_bits =
            user_registration_tree_leaf_index_bits[(group_realm_height as usize)..((group_realm_height + realm_user_tree_height) as usize)].to_vec();
        let group_id_bits = user_registration_tree_leaf_index_bits[((group_realm_height + realm_user_tree_height) as usize)..].to_vec();

        let user_index_half_bits = (realm_user_tree_height / 2) as usize;
        let user_index_low_half = user_index_bits[0..user_index_half_bits].to_vec();
        let mut user_index_high_half = user_index_bits[user_index_half_bits..].to_vec();

        user_index_high_half.reverse();

        let modified_user_index_bits = [user_index_high_half, user_index_low_half].concat();

        let new_bits = [modified_user_index_bits, realm_index_bit, group_id_bits].concat();
        let user_id = builder.le_sum(new_bits.iter());

        user_id
    }

    fn get_user_id_from_registration_id(registration_id: u64, coordinator_user_tree_height: u8, realm_user_tree_height: u8, group_realm_height: u8) -> u64 {
        let realm_index = registration_id & ((1u64 << group_realm_height) - 1);
        let user_index = (registration_id >> group_realm_height) & ((1u64 << realm_user_tree_height) - 1);
        let group_id =
            (registration_id >> (group_realm_height + realm_user_tree_height)) & ((1u64 << (coordinator_user_tree_height - group_realm_height)) - 1);

        let reversed_realm_index = reverse_bits_in_limit(realm_index, group_realm_height);
        let realm_id = (group_id << group_realm_height) | reversed_realm_index;

        let user_index_half_bits = realm_user_tree_height / 2;
        let user_index_low_half = user_index & ((1u64 << user_index_half_bits) - 1);
        let user_index_high_half = (user_index >> user_index_half_bits) & ((1u64 << user_index_half_bits) - 1);

        let reversed_user_index_high_half = reverse_bits_in_limit(user_index_high_half, user_index_half_bits);
        let modified_user_index = (user_index_low_half << user_index_half_bits) | reversed_user_index_high_half;

        (realm_id << realm_user_tree_height) | modified_user_index
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

type UserIdBitsStrategy = UserIdBitsStrategy4;

pub fn get_user_id_from_registration_id(registration_id: u64, 
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,) -> u64 {
    UserIdBitsStrategy::get_user_id_from_registration_id(registration_id, coordinator_user_tree_height, realm_user_tree_height, group_realm_height)
}
pub fn circuit_user_registration_tree_index_bits_to_user_id<H: AlgebraicHasher<F>, F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    user_registration_tree_leaf_index: Target,
    user_registration_tree_leaf_index_bits: &[BoolTarget],
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,
) -> Target {
    UserIdBitsStrategy::circuit_user_registration_tree_index_bits_to_user_id::<H, F, D>(
        builder,
        user_registration_tree_leaf_index,
        user_registration_tree_leaf_index_bits,
        coordinator_user_tree_height,
            realm_user_tree_height,
            group_realm_height,
    )
}

#[cfg(test)]
mod tests {
    use plonky2::{
        field::{
            extension::Extendable,
            types::{Field, PrimeField64},
        },
        hash::hash_types::RichField,
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
        },
    };
    use rand::{thread_rng, RngCore};

    const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 14;
    const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 10;
    const GROUP_REALM_HEIGHT: u8 = 1;
    const GLOBAL_USER_TREE_HEIGHT: u8 = REALM_GLOBAL_USER_TREE_HEIGHT + COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

    use super::{UserIdBitsStrategy1, UserIdBitsStrategy2, UserIdBitsStrategy3, UserIdBitsStrategy4, UserIdGeneratorStrategy};

    struct SimpleBitsTester<C: GenericConfig<D>, const D: usize> {
        pub registration_ids: Vec<Target>,
        //pub user_ids: Vec<Target>,
        pub circuit_data: CircuitData<C::F, C, D>,
    }

    impl<C: GenericConfig<D>, const D: usize> SimpleBitsTester<C, D>
    where
        C::Hasher: AlgebraicHasher<C::F>,
    {
        pub fn new<UIDGen: UserIdGeneratorStrategy>(count: usize, 
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,) -> Self {
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<C::F, D>::new(config);
            let registration_ids = builder.add_virtual_targets(count);

            let user_ids = registration_ids
                .iter()
                .map(|x| {
                    let user_registration_tree_leaf_index = *x;
                    let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as usize;
                    let user_registration_tree_leaf_index_bits = builder.split_le(user_registration_tree_leaf_index, global_user_tree_height);

                    UIDGen::circuit_user_registration_tree_index_bits_to_user_id::<C::Hasher, C::F, D>(
                        &mut builder,
                        user_registration_tree_leaf_index,
                        &user_registration_tree_leaf_index_bits,
                        coordinator_user_tree_height,
                            realm_user_tree_height,
                            group_realm_height,
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
        pub fn check_strategy<UIDGen: UserIdGeneratorStrategy>(&self, registration_ids: &[u64], 
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8,) -> anyhow::Result<()> {
            for (user_id, reg_id) in self
                .prove_base(registration_ids)?
                .public_inputs
                .iter()
                .map(|x| x.to_canonical_u64())
                .zip(registration_ids.iter())
            {
                let expected_user_id = UIDGen::get_user_id_from_registration_id(*reg_id, coordinator_user_tree_height, realm_user_tree_height, group_realm_height);
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
        pub fn full_check<UIDGen: UserIdGeneratorStrategy>(batch_size: usize, count: usize, rand_count: usize, 
        coordinator_user_tree_height: u8,
            realm_user_tree_height: u8,
            group_realm_height: u8) -> anyhow::Result<()> {
            type C = PoseidonGoldilocksConfig;
            let max_regions = (count / batch_size) as u64;
            let rand_regions = (rand_count / batch_size) as u64;
            let b_size = batch_size as u64;
            let circ = Self::new::<UIDGen>(batch_size, coordinator_user_tree_height, realm_user_tree_height, group_realm_height);
            let global_user_tree_height = (coordinator_user_tree_height + realm_user_tree_height) as u8;
            let mask = (1u64 << global_user_tree_height) - 1u64;
            for i in 0u64..(max_regions + 1) {
                let ids = ((i * b_size)..((i + 1u64) * b_size)).map(|x| x & mask).collect::<Vec<u64>>();
                circ.check_strategy::<UIDGen>(&ids, coordinator_user_tree_height, realm_user_tree_height, group_realm_height)?;
            }
            for _ in 0u64..rand_regions {
                let ids = (0..batch_size).map(|_| thread_rng().next_u64() & mask).collect::<Vec<_>>();
                circ.check_strategy::<UIDGen>(&ids, coordinator_user_tree_height, realm_user_tree_height, group_realm_height)?;
            }

            Ok(())
        }
    }

    #[test]
    fn check_strategy_1() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy1>(1024, 64 * 1024, 64 * 1024, 10, 14, 1).unwrap();
    }
    #[test]
    fn check_strategy_2() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy2>(1024, 64 * 1024, 64 * 1024, 10, 14, 1).unwrap();
    }
    #[test]
    fn check_strategy_3() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy3>(1024, 64 * 1024, 64 * 1024, 10, 14, 1).unwrap();
    }
    #[test]
    fn check_strategy_4() {
        SimpleBitsTester::<PoseidonGoldilocksConfig, 2>::full_check::<UserIdBitsStrategy4>(1024, 64 * 1024, 64 * 1024, 10, 14, 1).unwrap();
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
