
use std::collections::HashMap;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::{fast_node_serializer::QMerkleStoreFastZeroNodeSerializer, merkle_node_key::SimpleMerkleNodeKey, merkle_node_nest::MerkleLeafNode}, protocol::core_types::Q256BitHash};

use crate::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;

pub fn serialize_zero_id_merkle_tree_nodes_from_leaves<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash>(tree_height: u8, leaves: &[MerkleLeafNode<Hash>]) -> Vec<u8> {
    let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(tree_height);
    for leaf in leaves.iter() {
        tree.set_leaf_no_proof(leaf.index, leaf.value);
    }
    QMerkleStoreFastZeroNodeSerializer::serialize_zero_id_hash_map_to_vec(&tree.into_nodes())
}


pub fn zero_id_merkle_tree_nodes_hash_map_from_leaves<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash>(tree_height: u8, leaves: &[MerkleLeafNode<Hash>]) -> (Hash, HashMap<SimpleMerkleNodeKey, Hash>) {
    let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(tree_height);
    for leaf in leaves.iter() {
        tree.set_leaf_no_proof(leaf.index, leaf.value);
    }
    let root = tree.get_root();
    let nodes = tree.into_nodes();
    (root, nodes)
}