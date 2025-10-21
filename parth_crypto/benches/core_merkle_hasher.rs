// allow dead code for benchmark files
#![allow(dead_code)]

use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::{crypto::hash::traits::MerkleHasher, data::hash::hash256::Hash256, generic_traits::QNamedType, pgoldilocks::{PGoldilocksHash, PoseidonHasher}, protocol::core_types::QHashBase};
use parth_crypto::hash::sha256::CoreSha256Hasher;


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

fn gen_rand_hashes_fast_rand<Hash: BenchFastRand>(count: usize) -> Vec<Hash> {
    let mut hashes = Vec::with_capacity(count);
    for _ in 0..count {
        hashes.push(Hash::bench_rand_gen_fast());
    }
    hashes
}


fn iterate_hash_self<Hash: QHashBase, Hasher: MerkleHasher<Hash>>(base: &Hash, count: usize) -> Hash {
    let mut current = *base;
    for _ in 0..count {
        current = Hasher::two_to_one(&current, &current);
    }
    current
}
fn linear_hash<Hash: QHashBase, Hasher: MerkleHasher<Hash>>(base: &Hash, items: &[Hash]) -> Hash {
    let mut current = *base;
    for item in items.iter() {
        current = Hasher::two_to_one(&current, item);
    }
    current
}
fn hash_merkle_tree<Hash: QHashBase, Hasher: MerkleHasher<Hash>>(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::get_zero_value();
    }
    let mut current_level = leaves.to_vec();
    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for i in (0..current_level.len()).step_by(2) {
            if i + 1 < current_level.len() {
                let parent = Hasher::two_to_one(&current_level[i], &current_level[i + 1]);
                next_level.push(parent);
            } else {
                // Odd number of nodes, promote the last one.
                next_level.push(current_level[i]);
            }
        }
        current_level = next_level;
    }
    current_level[0]
}
fn gen_merkle_leaves_for_height<Hash: BenchFastRand>(height: usize) -> Vec<Hash> {
    let num_leaves = 1 << height; // 2^height
    gen_rand_hashes_fast_rand(num_leaves)
}
fn benchmark_linear_hasher_internal<Hash: BenchFastRand + QHashBase, Hasher: QNamedType + MerkleHasher<Hash>>(c: &mut Criterion, linear_hash_counts: &[usize]) {
    let mut group = c.benchmark_group(format!("linear_hasher_{}_v1", Hasher::q_type_name()));

    let base = Hash::bench_rand_gen_fast();

    // We test with a variety of input sizes to see how performance scales.
    for count in linear_hash_counts.iter() {
        // Generate the test data once per size.
        let items = gen_rand_hashes_fast_rand(*count);
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("linear_hash", *count), &items, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            b.iter(|| linear_hash::<Hash, Hasher>(&base, black_box(l)));
        });
    }
    group.finish();
}

fn benchmark_iterated_hasher_internal<Hash: BenchFastRand + QHashBase, Hasher: QNamedType + MerkleHasher<Hash>>(c: &mut Criterion, hash_iterations: &[usize]) {
    let mut group = c.benchmark_group(format!("iterated_hasher_{}_v1", Hasher::q_type_name()));

    let base = Hash::bench_rand_gen_fast();

    // We test with a variety of input sizes to see how performance scales.
    for count in hash_iterations.iter() {
        // Generate the test data once per size.
        
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("iterated_hash", *count), count, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            b.iter(|| iterate_hash_self::<Hash, Hasher>(&base, black_box(*l)));
        });
    }
    group.finish();

}



fn benchmark_merkle_hasher_internal<Hash: BenchFastRand + QHashBase, Hasher: QNamedType + MerkleHasher<Hash>>(c: &mut Criterion, merkle_tree_heights: &[usize]) {
    let mut group = c.benchmark_group(format!("merkle_hasher_{}_v1", Hasher::q_type_name()));

    // We test with a variety of input sizes to see how performance scales.
    for count in merkle_tree_heights.iter() {
        // Generate the test data once per size.
        let leaves = gen_merkle_leaves_for_height::<Hash>(*count);
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("merkle_hash", *count), &leaves, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            b.iter(|| hash_merkle_tree::<Hash, Hasher>(&black_box(l)));
        });
    }
    group.finish();

}

pub fn benchmark_core_hashers(c: &mut Criterion) {
    //let linear_hash_counts = vec![1, 10, 100, 1_000, 10_000];
    //let hash_iterations = vec![1, 10, 100, 1_000, 10_000, 100_000];
    //let merkle_tree_heights = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];


    let linear_hash_counts = vec![10_000];
    let hash_iterations = vec![10_000];
    let merkle_tree_heights = vec![16];
    benchmark_linear_hasher_internal::<Hash256, CoreSha256Hasher>(c, &linear_hash_counts);
    benchmark_iterated_hasher_internal::<Hash256, CoreSha256Hasher>(c, &hash_iterations);
    benchmark_merkle_hasher_internal::<Hash256, CoreSha256Hasher>(c, &merkle_tree_heights);

    benchmark_linear_hasher_internal::<PGoldilocksHash, PoseidonHasher>(c, &linear_hash_counts);
    benchmark_iterated_hasher_internal::<PGoldilocksHash, PoseidonHasher>(c, &hash_iterations);
    benchmark_merkle_hasher_internal::<PGoldilocksHash, PoseidonHasher>(c, &merkle_tree_heights);
}


    