use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::{crypto::hash::traits::MerkleHasher, data::{hash::hash256::Hash256, maybe_serialization::MaybeSpeedy, serializable::FastFixedSerializable}, felt::{QFelt, QFelt64}, generic_traits::QNamedType, pgoldilocks::{PGoldilocksFelt, PGoldilocksHash, PoseidonHasher}, protocol::core_types::{QDBHashBase, QFHashBase, QHash256Base, QHashBase}, utils::QPGenRandom};
use psy_data::v1::qdata::user::PQEDUserLeaf;

use speedy::{Readable, Writable};
trait BenchFastRand {
    fn bench_rand_gen_fast() -> Self;
}
impl BenchFastRand for Hash256 {
    fn bench_rand_gen_fast() -> Self {
        Hash256::rand()
    }
}
impl BenchFastRand for PGoldilocksHash {
    fn bench_rand_gen_fast() -> Self {
        PGoldilocksHash::from_hash256_le(Hash256::rand())
    }
}
impl BenchFastRand for PGoldilocksFelt {
    fn bench_rand_gen_fast() -> Self {
        PGoldilocksFelt::qp_rand_gen()
    }
}

impl<F: BenchFastRand, Hash: BenchFastRand> BenchFastRand for PQEDUserLeaf<F, Hash> {
    fn bench_rand_gen_fast() -> Self {
        PQEDUserLeaf {
            user_id: F::bench_rand_gen_fast(),
            user_state_tree_root: Hash::bench_rand_gen_fast(),
            public_key: Hash::bench_rand_gen_fast(),
            balance: F::bench_rand_gen_fast(),
            nonce: F::bench_rand_gen_fast(),
            last_checkpoint_id: F::bench_rand_gen_fast(),
            event_index: F::bench_rand_gen_fast(),
        }
    }
}
fn gen_random_user_leaves<F: BenchFastRand, Hash: BenchFastRand>(count: usize) -> Vec<PQEDUserLeaf<F, Hash>> {
    let mut users = Vec::with_capacity(count);
    for _ in 0..count {
        users.push(PQEDUserLeaf::bench_rand_gen_fast());
    }
    users
}
fn benckmark_serialize_round_trip_user_leaf_internal<F: BenchFastRand + QFelt64 + QFelt + MaybeSpeedy,  Hash: BenchFastRand + QDBHashBase + QFHashBase<F>>(c: &mut Criterion, user_counts: &[usize]) {
    let mut group = c.benchmark_group(format!("ser_user_leaf_{}_v1", Hash::q_type_name()));


    // We test with a variety of input sizes to see how performance scales.
    for count in user_counts.iter() {
        // Generate the test data once per size.
        let items = gen_random_user_leaves::<F, Hash>(*count);
        let speedy_bytes = items.write_to_vec().expect("Serialization should succeed");
        //let ex_1 = items[0].user_id.write_to_vec()
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("serialize_user_leaves_bincode", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||bincode::serialize(black_box(l)).unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_user_leaves_speedy", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||black_box(l).write_to_vec().unwrap());
        });
        group.bench_with_input(BenchmarkId::new("serialize_user_leaves_ffs", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            //b.iter(|| Vec::<PQEDUserLeaf::<F, Hash>>::read_from(black_box(l)));
            b.iter(||black_box(l));
        });
    }
    group.finish();
}


pub fn benckmark_serialization(c: &mut Criterion) {
    //let linear_hash_counts = vec![1, 10, 100, 1_000, 10_000];
    //let hash_iterations = vec![1, 10, 100, 1_000, 10_000, 100_000];
    //let merkle_tree_heights = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];


    let linear_hash_counts = vec![10_000];
    let hash_iterations = vec![10_000];
    let merkle_tree_heights = vec![16];
}


    
