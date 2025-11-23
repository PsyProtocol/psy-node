
use std::collections::HashMap;

use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::{fast_node_serializer::{QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE, QMerkleStoreFastSingleNodeSerializer}, merkle_node_nest::MerkleLeafNode}, protocol::core_types::Q256BitHash};

use crate::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
use parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey;


pub fn serialize_single_id_merkle_tree_nodes_from_leaves<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash>(tree_id: u64, tree_height: u8, leaves: &[MerkleLeafNode<Hash>]) -> Vec<u8> {
    let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(tree_height);
    for leaf in leaves.iter() {
        tree.set_leaf_no_proof(leaf.index, leaf.value);
    }
    QMerkleStoreFastSingleNodeSerializer::serialize_single_id_hash_map_with_common_tree_id_to_vec(tree_id, &tree.into_nodes())
}

#[derive(Debug, Clone)]
pub struct SingleIdMerkleNodeBatchSerializer<Hash> {
    pub node_maps: Vec<(u64, HashMap<SimpleMerkleNodeKey, Hash>)>,
    pub total_nodes: usize,
}
impl<Hash: Q256BitHash + Default> SingleIdMerkleNodeBatchSerializer<Hash> {
    pub fn new() -> Self {
        Self {
            node_maps: Vec::new(),
            total_nodes: 0,
        }
    }

    pub fn add_merkle_leaves<Hasher: MerkleZeroHasher<Hash>>(&mut self, tree_id: u64, tree_height: u8, leaves: &[MerkleLeafNode<Hash>]) -> Hash {
        let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(tree_height);
        for leaf in leaves.iter() {
            tree.set_leaf_no_proof(leaf.index, leaf.value);
        }
        let root = tree.get_root();
        let node_map = tree.into_nodes();
        self.total_nodes += node_map.len();
        self.node_maps.push((tree_id, node_map));
        root
    }
    pub fn add_merkle_leaves_save_optional<Hasher: MerkleZeroHasher<Hash>>(&mut self, tree_id: u64, tree_height: u8, leaves: &[MerkleLeafNode<Hash>], save: bool) -> Hash {
        let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(tree_height);
        for leaf in leaves.iter() {
            tree.set_leaf_no_proof(leaf.index, leaf.value);
        }
        let root = tree.get_root();
        if save {
            let node_map = tree.into_nodes();
            self.total_nodes += node_map.len();
            self.node_maps.push((tree_id, node_map));
        }
        root
    }

    pub fn add_node_map(&mut self, tree_id: u64, node_map: HashMap<SimpleMerkleNodeKey, Hash>) {
        self.total_nodes += node_map.len();
        self.node_maps.push((tree_id, node_map));
    }

    pub fn serialize_into_bytes(self) -> Vec<u8> {
        let mut serialized_bytes = Vec::with_capacity(self.total_nodes * QMS_FAST_SERIALIZER_SINGLE_ID_NODE_SIZE);
        for (tree_id, node_map) in self.node_maps {
            QMerkleStoreFastSingleNodeSerializer::serialize_single_id_hash_map_with_common_tree_id_to_slice(tree_id, &node_map, &mut serialized_bytes);
        }
        serialized_bytes
    }
}