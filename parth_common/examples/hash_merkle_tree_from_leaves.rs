
use parth_core::{crypto::hash::traits::{MerkleHasher, MerkleLeafHasher, MerkleZeroHasher, ZeroableHash}, data::hash::hash256::Hash256, utils::{math::log2_ceil, QPGenRandom}};
use parth_crypto::hash::sha256::CoreSha256Hasher;

fn hash_merkle_leaves_to_root_naive_pad<Hash: PartialEq + Copy + ZeroableHash, Hasher: MerkleHasher<Hash>>(
    leaves: &[Hash],
) -> Hash {
    let target_leaves_count = 1 << log2_ceil(leaves.len());


    let mut current_level = Vec::with_capacity(target_leaves_count);
    current_level.extend_from_slice(leaves);
    let zero_hash = Hash::get_zero_value();
    while current_level.len() < target_leaves_count {
        current_level.push(zero_hash);
    }
    let lib_root = Hasher::compute_root_from_leaves(&current_level).unwrap();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        for i in (0..current_level.len()).step_by(2) {
            let left = current_level[i];
            let right = if i + 1 < current_level.len() {
                current_level[i + 1]
            } else {
                zero_hash
            };
            let parent_hash = Hasher::two_to_one(&left, &right);
            next_level.push(parent_hash);
        }
        current_level = next_level;
    }
    assert!(current_level[0] == lib_root, "Roots must match in naive padding method");

    current_level[0]
}


fn hash_merkle_leaves_v2<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
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

fn _hash_level_with_left_over<Hash: PartialEq + Copy, Hasher: MerkleZeroHasher<Hash>>(
    current_nodes_level_from_bottom: u8,
    nodes: &[Hash],
) -> Vec<Hash> {
    let nodes_len = nodes.len();
    let has_odd_nodes = (nodes_len & 1) == 1;
    let even_pairs_count = nodes_len / 2;
    let next_count = even_pairs_count + if has_odd_nodes { 1 } else { 0 };
    let mut current_level = Vec::with_capacity(next_count);
    for i in 0..even_pairs_count {
        let left = nodes[2 * i];
        let right = nodes[2 * i + 1];
        let parent_hash = Hasher::two_to_one(&left, &right);
        current_level.push(parent_hash);
    }
    if has_odd_nodes {
        current_level.push(Hasher::two_to_one(&nodes[nodes_len - 1], &Hasher::get_zero_hash(current_nodes_level_from_bottom as usize)));
    }

    current_level
}

fn test_trees_with_rand_leaves<Hash: QPGenRandom + PartialEq + Copy + std::fmt::Debug + ZeroableHash, Hasher: MerkleZeroHasher<Hash>>(leaves_count: usize) -> anyhow::Result<Hash> {
    let leaves = Hash::qp_rand_gen_vec(leaves_count);
    let naive_root = hash_merkle_leaves_to_root_naive_pad::<Hash, Hasher>(&leaves);
    let smart_hash = hash_merkle_leaves_v2::<Hash, Hasher>(&leaves)?;
    assert_eq!(naive_root, smart_hash, "Roots must match for {} leaves", leaves_count);
    Ok(smart_hash)
}
fn main() {


    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(1).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(2).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(3).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(4).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(5).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(15).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(16).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(17).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(31).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(32).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(33).unwrap();
    test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(500).unwrap();


    for i in 1..10000 {
        println!("Testing merkle tree with {} leaves", i);
        test_trees_with_rand_leaves::<Hash256, CoreSha256Hasher>(i).unwrap();
    }
    

}