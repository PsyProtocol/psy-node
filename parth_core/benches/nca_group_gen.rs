// for benches, allow unused functions
#![allow(dead_code)]

use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::data::hash::merkle_node_key::{generate_nca_tree_groups_naive, SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation};
use std::collections::HashSet;

// --- Add this new helper function ---

/// A truly efficient recursive helper that avoids HashMap lookups in the hot path.
///
/// It returns a tuple `(SimpleMerkleNodeKey, usize)` representing the NCA key and its
/// calculated dependency level. This avoids the need for a shared map to store levels,
/// passing the state up the call stack instead.
fn build_recursive_truly_efficient_2(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
    // We still collect the aggregations with their levels as we go.
    aggregations_with_levels: &mut Vec<(SimpleMerkleNodeNCAAggregation, usize)>,
) -> Option<(SimpleMerkleNodeKey, usize)> { // Return type changed!
    if nodes.is_empty() {
        return None;
    }
    // Base case: A single node is a leaf in the NCA tree. Its level is 0.
    if nodes.len() == 1 {
        return Some((nodes[0], 0)); // Return key and level 0.
    }

    // --- Divide Phase ---
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    // --- Conquer Phase ---
    let left_result = build_recursive_truly_efficient_2(
        left_nodes,
        subtree_root.left_child(),
        tree_height,
        aggregations_with_levels,
    );
    let right_result = build_recursive_truly_efficient_2(
        right_nodes,
        right_child,
        tree_height,
        aggregations_with_levels,
    );

    // --- Combine Phase ---
    match (left_result, right_result) {
        (Some((l_key, l_level)), Some((r_key, r_level))) => {
            let combined_nca_key = l_key.find_nearest_common_ancestor(&r_key);
            
            // The new level is 1 greater than the maximum level of its children.
            let new_level = 1 + std::cmp::max(l_level, r_level);

            let agg = SimpleMerkleNodeNCAAggregation {
                nca: combined_nca_key,
                left: l_key,
                right: r_key,
            };
            aggregations_with_levels.push((agg, new_level));
            
            // Pass the new key and its calculated level up the call stack.
            Some((combined_nca_key, new_level))
        }
        // If only one side has a result, pass it up directly.
        (Some(l_res), None) => Some(l_res),
        (None, Some(r_res)) => Some(r_res),
        (None, None) => None,
    }
}


// --- New top-level function. Can replace the old `efficient` one ---

pub fn generate_nca_tree_groups_v1(leaves: &[SimpleMerkleNodeKey], _leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    if leaves.len() < 2 {
        return vec![];
    }
    
    let tree_height = leaves[0].level;

    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations_with_levels = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    // This single call builds the tree and determines the level for each aggregation.
    build_recursive_truly_efficient_2(
        &sorted_leaves, 
        root_node, 
        tree_height, 
        &mut aggregations_with_levels,
    );

    if aggregations_with_levels.is_empty() {
        return vec![];
    }

    // This bucketing logic remains the same.
    let max_level = match aggregations_with_levels.iter().map(|(_, level)| *level).max() {
        Some(level) => level,
        None => return vec![],
    };
    
    let mut groups: Vec<Vec<SimpleMerkleNodeNCAAggregation>> = vec![Vec::new(); max_level];

    for (agg, level) in aggregations_with_levels {
        // Levels are 1-based, but vector indices are 0-based.
        if level > 0 {
            let group_idx = level - 1;
            groups[group_idx].push(agg);
        }
    }
    // Filter out potential empty groups if max_level calculation has gaps, though unlikely.
    groups.into_iter().filter(|g| !g.is_empty()).collect()
}
// --- Helper functions to generate test data (copied from your tests) ---

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
    let mut group = c.benchmark_group("NCA Group Generation");
    let tree_height: u8 = 24;

    // We test with a variety of input sizes to see how performance scales.
    for size in [5_000, 10_000, 100_000].iter() {
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