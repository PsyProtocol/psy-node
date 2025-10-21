// for benches, allow unused functions
#![allow(dead_code)]
use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::data::hash::merkle_node_key::{generate_nca_tree_groups_naive, SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation};
use std::collections::HashSet;
use rayon::prelude::*;
use dashmap::DashMap;

fn generate_nca_tree_par(sorted_leaves: &[SimpleMerkleNodeKey], tree_height: u8) -> Vec<SimpleMerkleNodeNCAAggregation> {
    if sorted_leaves.is_empty() {
        return vec![];
    }
    let root_node = SimpleMerkleNodeKey::new(0, 0);
    let (_, aggs) = build_recursive_par(sorted_leaves, root_node, tree_height);
    aggs
}

fn build_recursive_par(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
) -> (Option<SimpleMerkleNodeKey>, Vec<SimpleMerkleNodeNCAAggregation>) {
    if nodes.is_empty() {
        return (None, vec![]);
    }
    if nodes.len() == 1 {
        return (Some(nodes[0]), vec![]);
    }

    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    let ((left_nca, mut left_aggs), (right_nca, right_aggs)) = rayon::join(
        || build_recursive_par(left_nodes, subtree_root.left_child(), tree_height),
        || build_recursive_par(right_nodes, right_child, tree_height),
    );

    left_aggs.extend(right_aggs);

    match (left_nca, right_nca) {
        (Some(l), Some(r)) => {
            let combined_nca = l.find_nearest_common_ancestor(&r);
            left_aggs.push(SimpleMerkleNodeNCAAggregation {
                nca: combined_nca,
                left: l,
                right: r,
            });
            (Some(combined_nca), left_aggs)
        }
        (Some(l), None) => (Some(l), left_aggs),
        (None, Some(r)) => (Some(r), left_aggs),
        (None, None) => (None, left_aggs),
    }
}

pub fn generate_nca_tree_groups_naive_rayon(leaves: &[SimpleMerkleNodeKey], leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    if leaves.len() < 2 {
        return vec![];
    }

    let tree_height = leaves[0].level;

    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.par_sort();

    let ncas = generate_nca_tree_par(&sorted_leaves, tree_height);

    if ncas.is_empty() {
        return vec![];
    }

    let nca_map: DashMap<SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation> = DashMap::with_capacity(ncas.len());
    ncas.par_iter().for_each(|x| {
        nca_map.insert(x.nca.clone(), x.clone());
    });

    let mut levels = Vec::with_capacity(leaf_level as usize + 1);

    let root = ncas.last().unwrap().clone();
    if root.left.level == leaf_level && root.right.level == leaf_level {
        return vec![vec![root]];
    }

    let mut has_non_leaf_children = true;
    let mut current_level = vec![root];

    while has_non_leaf_children {
        levels.push(current_level.clone());

        let next_level: Vec<SimpleMerkleNodeNCAAggregation> = current_level.par_iter().flat_map(|agg| {
            let mut res: Vec<SimpleMerkleNodeNCAAggregation> = vec![];
            if agg.left.level != leaf_level {
                if let Some(left_agg) = nca_map.get(&agg.left) {
                    res.push(left_agg.clone());
                }
            }
            if agg.right.level != leaf_level {
                if let Some(right_agg) = nca_map.get(&agg.right) {
                    res.push(right_agg.clone());
                }
            }
            res
        }).collect();

        has_non_leaf_children = !next_level.is_empty();
        current_level = next_level;
    }
    if !current_level.is_empty() {
        levels.push(current_level);
    }
    levels.reverse();
    levels
}


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



// --- Add this new helper function ---

/// A truly v1 recursive helper that avoids HashMap lookups in the hot
/// path.
///
/// It returns a tuple `(SimpleMerkleNodeKey, usize)` representing the NCA key
/// and its calculated dependency level. This avoids the need for a shared map
/// to store levels, passing the state up the call stack instead.
fn build_recursive_truly_v1(
    nodes: &[SimpleMerkleNodeKey],
    subtree_root: SimpleMerkleNodeKey,
    tree_height: u8,
    // We still collect the aggregations with their levels as we go.
    aggregations: &mut Vec<SimpleMerkleNodeNCAAggregation>,
) -> Option<SimpleMerkleNodeKey> {
    // Return type changed!
    if nodes.is_empty() {
        return None;
    }
    // Base case: A single node is a leaf in the NCA tree. Its level is 0.
    if nodes.len() == 1 {
        return Some(nodes[0]); // Return key and level 0.
    }

    // --- Divide Phase ---
    let right_child = subtree_root.right_child();
    let split_leaf_index = right_child.first_leaf_child(tree_height).index;
    let partition_idx = nodes.partition_point(|node| node.index < split_leaf_index);
    let (left_nodes, right_nodes) = nodes.split_at(partition_idx);

    // --- Conquer Phase ---
    let left_result = build_recursive_truly_v1(left_nodes, subtree_root.left_child(), tree_height, aggregations);
    let right_result = build_recursive_truly_v1(right_nodes, right_child, tree_height, aggregations);

    // --- Combine Phase ---
    match (left_result, right_result) {
        (Some(l_key), Some(r_key)) => {
            let combined_nca_key = l_key.find_nearest_common_ancestor(&r_key);

            let agg = SimpleMerkleNodeNCAAggregation {
                nca: combined_nca_key,
                left: l_key,
                right: r_key,
            };
            aggregations.push(agg);

            // Pass the new key and its calculated level up the call stack.
            Some(combined_nca_key)
        }
        // If only one side has a result, pass it up directly.
        (Some(l_res), None) => Some(l_res),
        (None, Some(r_res)) => Some(r_res),
        (None, None) => None,
    }
}

// --- New top-level function. Can replace the old `v1` one ---

pub fn generate_nca_tree_groups_v1(leaves: &[SimpleMerkleNodeKey], _leaf_level: u8) -> Vec<Vec<SimpleMerkleNodeNCAAggregation>> {
    if leaves.len() < 2 {
        return vec![];
    }

    let tree_height = leaves[0].level;

    let mut sorted_leaves = leaves.to_vec();
    sorted_leaves.sort();

    let mut aggregations = Vec::new();
    let root_node = SimpleMerkleNodeKey::new(0, 0);

    // This single call builds the tree and determines the level for each
    // aggregation.
    build_recursive_truly_v1(&sorted_leaves, root_node, tree_height, &mut aggregations);

    if aggregations.is_empty() {
        return vec![];
    }

    let mut nca_map: std::collections::HashMap<SimpleMerkleNodeKey, SimpleMerkleNodeNCAAggregation> = std::collections::HashMap::new();
    aggregations.iter().for_each(|x| {
        nca_map.insert(x.nca.clone(), x.clone());
    });
    let mut levels = Vec::with_capacity(tree_height as usize + 1);

    let root = aggregations.last().unwrap().clone();
    if root.left.level == tree_height && root.right.level == tree_height {
        return vec![vec![root]];
    }

    let mut has_non_leaf_children = true;
    let mut current_level = vec![root];

    while has_non_leaf_children {
        levels.push(current_level.clone());
        let mut next_level = Vec::new();
        has_non_leaf_children = false;
        for agg in current_level.iter() {
            if agg.left.level != tree_height {
                if let Some(left_agg) = nca_map.get(&agg.left) {
                    next_level.push(left_agg.clone());
                    has_non_leaf_children = true;
                }
            }
            if agg.right.level != tree_height {
                if let Some(right_agg) = nca_map.get(&agg.right) {
                    next_level.push(right_agg.clone());
                    has_non_leaf_children = true;
                }
            }
        }
        current_level = next_level;
    }
    if current_level.len() > 0 {
        levels.push(current_level);
    }
    levels.reverse();
    levels
}
// --- Function Implementation ---

// --- The Benchmark ---

pub fn benchmark_nca_group_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("NCA Group Generation 3");
    let tree_height: u8 = 24;

    // We test with a variety of input sizes to see how performance scales.
    for size in [1_000_000].iter() {
        // Generate the test data once per size.
        let leaves = random_nodes_in_tree(tree_height, *size);

        // Benchmark the efficient implementation
        group.bench_with_input(BenchmarkId::new("Efficient", size), &leaves, |b, l| {
            b.iter(|| generate_nca_tree_groups_v1(black_box(l), tree_height));
        });
        // Benchmark the naive implementation
        group.bench_with_input(BenchmarkId::new("Naive", size), &leaves, |b, l| {
            // `b.iter` runs the closure multiple times to get a stable measurement.
            // `black_box` prevents the compiler from optimizing away the function call.
            b.iter(|| generate_nca_tree_groups_naive(black_box(l), tree_height));
        });

    }
    group.finish();
}

// Criterion boilerplate to register and run the benchmarks
//criterion_group!(benches, benchmark_nca_group_generation);
//criterion_main!(benches);