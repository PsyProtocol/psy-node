use std::collections::HashMap;

use cf_utils::timer::DebugTimer;
use parth_common::memory_stores::{dash_tree::PsyDashMemoryMerkleStore, mem_tree_v3::SimpleMemoryMerkleStoreV3, traits::PsyMemoryMerkleStoreImm};
use parth_core::{PHash, crypto::hash::traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash}, data::hash::{hash256::Hash256, merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}}, node, pgoldilocks::PoseidonHasher, protocol::core_types::{Q256BitHash, QDBHashBase}, utils::{QPGenRandom, math::log2_ceil}};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use parth_core::crypto::hash::traits::MerkleLeafHasher;
pub fn dash_time_it<Hash: Copy + PartialEq + ZeroableHash + Default + QPGenRandom + QDBHashBase, Hasher: MerkleZeroHasher<Hash>>(height: u8) {
    let mut timer = DebugTimer::new(&format!("dash_time_it height {}", height));

    let max_leaves = 1u64 << height;
    let mut tree = PsyDashMemoryMerkleStore::<Hasher, Hash>::new(height);
    timer.lap("starting generate random leaves");
    let mut leaves = Vec::with_capacity(max_leaves as usize);
    for _ in 0..max_leaves {
        leaves.push(Hash::from_owned_32bytes(Hash256::rand().0));
    }
    timer.lap_batch("generated random leaves", "leaf", max_leaves as usize);


    timer.lap("starting inserting to tree...");
    for i in 0..max_leaves {
        tree.set_node_value(SimpleMerkleNodeKey::new(height, i), leaves[i as usize]);
    }

    timer.lap_batch("set leaves", "leaf", max_leaves as usize);

    timer.lap("starting to rehash tree");
    tree.recompute_entire_tree();
    timer.lap("done rehashing tree");






}


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

pub struct BaseMerkleStore<const HEIGHT: u8, const MAX_NODES: usize, Hash: Q256BitHash> {
    pub node_store: [Hash; MAX_NODES],
}
pub const fn get_flat_index_for_node_key<const HEIGHT: u8>(node_key: SimpleMerkleNodeKey) -> usize {
    let offset = (1usize << (HEIGHT + 1)) - (1usize << (HEIGHT + 1 - node_key.level));
    offset + node_key.index as usize
}
impl<const HEIGHT: u8, const MAX_NODES: usize, Hash: Q256BitHash> BaseMerkleStore<HEIGHT, MAX_NODES, Hash> {
    pub fn set_node_value(&mut self, node_key: SimpleMerkleNodeKey, value: Hash) {
        self.node_store[get_flat_index_for_node_key::<HEIGHT>(node_key)] = value;
    }
    pub fn get_node_value(&self, node_key: SimpleMerkleNodeKey) -> Hash {
        self.node_store[get_flat_index_for_node_key::<HEIGHT>(node_key)]
    }
    
}

fn test_trees_with_rand_leaves<Hash: QPGenRandom + PartialEq + Copy + std::fmt::Debug + ZeroableHash, Hasher: MerkleZeroHasher<Hash>>(leaves_count: usize) -> anyhow::Result<Hash> {


    let leaves = Hash::qp_rand_gen_vec(leaves_count);
    let mut timer = DebugTimer::new(&format!("test_trees_with_rand_leaves {}", leaves_count));
    let naive_root = hash_merkle_leaves_to_root_naive_pad::<Hash, Hasher>(&leaves);
    timer.lap("hash_merkle_leaves_to_root_naive_pad");
    let smart_hash = hash_merkle_leaves_v2::<Hash, Hasher>(&leaves)?;
    timer.lap("hash_merkle_leaves_v2");
    assert_eq!(naive_root, smart_hash, "Roots must match for {} leaves", leaves_count);
    Ok(smart_hash)
}
fn main() {


    test_trees_with_rand_leaves::<PHash, PoseidonHasher>(1usize<<20).unwrap();

    dash_time_it::<Hash256, CoreSha256Hasher>(20);


    dash_time_it::<PHash, PoseidonHasher>(20);


}