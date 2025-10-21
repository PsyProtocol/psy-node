// for benches, allow unused functions
#![allow(dead_code)]
use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::data::hash::merkle_node_key::{generate_nca_tree_groups_v1, generate_nca_tree_groups_naive, SimpleMerkleNodeKey};
use std::collections::HashSet;

fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
    let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
    hset.into_iter().collect::<Vec<_>>()
}

fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey> {
    let max_node_id = 1u64 << (height as u64);

    let mut result = Vec::with_capacity(count);
    for _ in 0..count {
        result.push(SimpleMerkleNodeKey {
            level: height,
            index: rand::random::<u64>() % max_node_id,
        });
    }

    get_unique_node_set(result)
}


// --- The Benchmark ---

pub fn benchmark_nca_group_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("NCA Group Generation 2");
    let tree_height: u8 = 24;

    // We test with a variety of input sizes to see how performance scales.
    for size in [1_000_000].iter() {
        // Generate the test data once per size.
        let leaves = random_nodes_in_tree(tree_height, *size);

        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("Naive", size), &leaves, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            b.iter(|| generate_nca_tree_groups_naive(black_box(l), tree_height));
        });

        // Benchmark the efficient implementation
        group.bench_with_input(BenchmarkId::new("Efficient", size), &leaves, |b, l| {
            b.iter(|| generate_nca_tree_groups_v1(black_box(l), tree_height));
        });
    }
    group.finish();
}

// Criterion boilerplate to register and run the benchmarks
//criterion_group!(benches, benchmark_nca_group_generation);
//criterion_main!(benches);