// allow dead code for benchmark files
#![allow(dead_code)]

use criterion::{black_box, BenchmarkId, Criterion};
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::hash256::Hash256, generic_traits::QNamedType, pgoldilocks::PGoldilocksHash, protocol::core_types::QHashBase};
use parth_crypto::hash::sha256::CoreSha256Hasher;



// A function to create a 32-byte seed from any hashable input (like a string)
fn get_seed_for_rng(s: &str) -> [u8; 32] {
    CoreSha256Hasher::hash_bytes(s.as_bytes()).0
}



trait BenchFastRand: Sized {
    fn bench_rand_gen_fast() -> Self;
    fn brg_fast_vec(count: usize) -> Vec<Self> {
        let mut vec = Vec::with_capacity(count);
        for _ in 0..count {
            vec.push(Self::bench_rand_gen_fast());
        }
        vec
    }
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



fn hash_merkle_from_leaves_1<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    leaves: &[Hash],
) -> anyhow::Result<Hash> {
    if leaves.len() == 0 {
        anyhow::bail!("Cannot compute Merkle root of zero leaves");
    }else if leaves.len() == 1 {
        return Ok(leaves[0]);
    }else if leaves.len() == 2 {
        return Ok(Hasher::two_to_one(&leaves[0], &leaves[1]));
    }
    let mut current_nodes_level_from_bottom = 0;
    let nodes_len = leaves.len();
    let has_odd_nodes = nodes_len & 1;
    let even_pairs_count = nodes_len / 2;
    let next_count = even_pairs_count + has_odd_nodes;
    let mut current_level = Vec::with_capacity(next_count);
    for i in 0..even_pairs_count {
        current_level.push(Hasher::two_to_one(&leaves[2*i], &leaves[2*i+1]));
    }
    if has_odd_nodes == 1 {
        current_level.push(Hasher::two_to_one(&leaves[nodes_len - 1], &Hasher::get_zero_hash(current_nodes_level_from_bottom)));
    }

    current_nodes_level_from_bottom += 1;
    while current_level.len() > 1 {
        for i in 0..(current_level.len() / 2) {
            current_level[i] = Hasher::two_to_one(&current_level[2*i], &current_level[2*i+1]);
        }
        let has_odd_nodes = current_level.len() & 1;
        let even_pairs_count = current_level.len() / 2;
        let next_count = even_pairs_count + has_odd_nodes;
        if has_odd_nodes == 1 {
            current_level[even_pairs_count] = Hasher::two_to_one(&current_level[current_level.len() - 1], &Hasher::get_zero_hash(current_nodes_level_from_bottom));
        }
        current_level.truncate(next_count);
        current_nodes_level_from_bottom += 1;
    }

    Ok(current_level[0])
}


// --- Optimized Function ---

/// Computes the Merkle root from a slice of leaves in an efficient, in-place manner.
///
/// This version avoids allocations within the loop by reusing a single vector,
/// making it significantly faster for trees with many leaves.
fn hash_merkle_from_leaves_2<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    leaves: &[Hash],
) -> anyhow::Result<Hash> {
    if leaves.is_empty() {
        // The loop condition `nodes.len() > 1` handles the `len == 1` case automatically.
        anyhow::bail!("Cannot compute Merkle root of zero leaves");
    }

    // Clone the leaves into a mutable vector. This is the *only* allocation.
    let mut nodes = leaves.to_vec();
    let mut level = 0;

    // Continue collapsing the tree until only the root hash remains.
    while nodes.len() > 1 {
        let num_nodes = nodes.len();
        let mut write_idx = 0;

        // Process nodes in pairs. The result of hash(nodes[2*i], nodes[2*i+1])
        // is written to nodes[i], effectively halving the vector size in place.
        for i in 0..(num_nodes / 2) {
            nodes[write_idx] = Hasher::two_to_one(&nodes[2 * i], &nodes[2 * i + 1]);
            write_idx += 1;
        }

        // If there's an odd number of nodes, hash the last one with a zero hash.
        if num_nodes % 2 == 1 {
            let last_node = nodes[num_nodes - 1]; // Important: read before potential overwrite
            let zero_hash = Hasher::get_zero_hash(level);
            nodes[write_idx] = Hasher::two_to_one(&last_node, &zero_hash);
            write_idx += 1;
        }

        // The vector now logically contains `write_idx` elements. Truncate it.
        nodes.truncate(write_idx);
        level += 1;
    }

    // The single remaining element is the Merkle root.
    Ok(nodes[0])
}




/// Computes the Merkle root from a slice of leaf hashes in an efficient, in-place manner.
///
/// This implementation minimizes memory allocations by performing the hashing level-by-level
/// within a single mutable vector.
fn hash_merkle_from_leaves_3<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    leaves: &[Hash],
) -> anyhow::Result<Hash> {
    // --- Handle edge cases first for clarity and to avoid allocation ---
    if leaves.is_empty() {
        // As in the original, though one could argue the root of zero leaves
        // is a zero hash. We will preserve the original behavior.
        anyhow::bail!("Cannot compute Merkle root of zero leaves");
    }
    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }

    // --- Main efficient implementation ---

    // The only significant allocation: create a mutable copy of the leaves to work with.
    let mut nodes = leaves.to_vec();
    let mut current_level_from_bottom = 0;

    // Continue collapsing the tree until only the root hash remains.
    while nodes.len() > 1 {
        let num_nodes = nodes.len();
        let mut write_cursor = 0;

        // Process nodes in pairs. `step_by(2)` is perfect for this.
        // We read from further in the vector and write to the beginning.
        for i in (0..num_nodes).step_by(2) {
            // Check if there's a pair or if this is the last odd node.
            if i + 1 < num_nodes {
                // It's a pair, hash them together.
                let left = &nodes[i];
                let right = &nodes[i + 1];
                nodes[write_cursor] = Hasher::two_to_one(left, right);
            } else {
                // It's the last odd node. Hash it with the zero hash for this level.
                let last_node = &nodes[i];
                let zero_hash = Hasher::get_zero_hash(current_level_from_bottom);
                nodes[write_cursor] = Hasher::two_to_one(last_node, &zero_hash);
            }
            write_cursor += 1;
        }

        // Shrink the vector to the new size of the parent level.
        nodes.truncate(write_cursor);
        current_level_from_bottom += 1;
    }

    // The last remaining node is the root.
    Ok(nodes[0])
}



fn benchmark_merkle_hasher_internal<Hash: BenchFastRand + QHashBase, Hasher: QNamedType + MerkleZeroHasher<Hash>>(c: &mut Criterion, _sizes_seed: &str, merkle_tree_heights: &[u64]) {
    let mut group = c.benchmark_group(format!("merkle_hasher_{}_v1", Hasher::q_type_name()));

    // We test with a variety of input sizes to see how performance scales.
    for height in merkle_tree_heights.iter().map(|x|x.to_owned()) {
        if height < 3 {
            continue;
        }
        let height: u64 = height;
        let leaves_count = 1u64 << height;
        let count = leaves_count as usize;
        //let seed_str = format!("merkle_hasher_{}_height_{}", sizes_seed, height);
        // Generate the test data once per size.
        let leaves = Hash::brg_fast_vec((1u64 << height) as usize);
        let fewest_leaves_at_height = (1u64 << (height - 1u64)) as usize;
        let leaves_minus_one = count - 1;
        let percent_leaves_62_5 = 5 * count / 8;
        let percent_leaves_75 = 3 * count / 4;
        let percent_leaves_87_5 = 7 * count / 8;
        let percent_leaves_95 = 19 * count / 20;

        let benches = vec![
            ("all_leaves", count),
            ("fewest_leaves_at_height", fewest_leaves_at_height),
            ("leaves_minus_one", leaves_minus_one),
            ("percent_leaves_62_5", percent_leaves_62_5),
            ("percent_leaves_75", percent_leaves_75),
            ("percent_leaves_87_5", percent_leaves_87_5),
            ("percent_leaves_95", percent_leaves_95),
        ];
        for bench in benches {
            group.bench_with_input(BenchmarkId::new::<&str, _>(&format!("hash_merkle_from_leaves_1_h{}_l{}", height, bench.0), height), &leaves[0..bench.1], |b, l| {
                // `b.iter` runs the closure multiple times to get a stable measurement.
                // `black_box` prevents the compiler from optimizing away the function call.
                b.iter(|| hash_merkle_from_leaves_1::<Hash, Hasher>(&black_box(l)).unwrap());
            });
            group.bench_with_input(BenchmarkId::new::<&str, _>(&format!("hash_merkle_from_leaves_2_h{}_l{}", height, bench.0), height), &leaves[0..bench.1], |b, l| {
                // `b.iter` runs the closure multiple times to get a stable measurement.
                // `black_box` prevents the compiler from optimizing away the function call.
                b.iter(|| hash_merkle_from_leaves_2::<Hash, Hasher>(&black_box(l)).unwrap());
            });
            group.bench_with_input(BenchmarkId::new::<&str, _>(&format!("hash_merkle_from_leaves_3_h{}_l{}", height, bench.0), height), &leaves[0..bench.1], |b, l| {
                // `b.iter` runs the closure multiple times to get a stable measurement.
                // `black_box` prevents the compiler from optimizing away the function call.
                b.iter(|| hash_merkle_from_leaves_3::<Hash, Hasher>(&black_box(l)).unwrap());
            });
        }
    }
    group.finish();

}

pub fn benchmark_merkle_leaf_hashers(c: &mut Criterion) {
    //let linear_hash_counts = vec![1, 10, 100, 1_000, 10_000];
    //let hash_iterations = vec![1, 10, 100, 1_000, 10_000, 100_000];
    //let merkle_tree_heights = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];


    //let linear_hash_counts = vec![10_000];
    //let hash_iterations = vec![10_000];
    //let merkle_tree_heights = vec![16];
    benchmark_merkle_hasher_internal::<Hash256, CoreSha256Hasher>(c, "test", &[4, 10, 12, 14, 16, 18]);

}

