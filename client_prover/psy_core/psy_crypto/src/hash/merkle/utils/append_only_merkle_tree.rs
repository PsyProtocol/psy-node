use std::fmt::Debug;

use super::{common::SimpleMerkleNodeKey, simple_merkle_tree::SimpleMerkleTree};
use crate::hash::{merkle::core::MerkleProofCore, traits::hasher::MerkleZeroHasherWithMarkedLeaf};

pub fn get_merkle_proofs_for_compact<Hasher: MerkleZeroHasherWithMarkedLeaf<Hash>, Hash: Copy + PartialEq + Default + Debug>(
    from_index: u64,
    siblings: &[Hash],
    values: &[Hash],
) -> Vec<MerkleProofCore<Hash>> {
    let mut tree = SimpleMerkleTree::<Hasher, Hash>::new(siblings.len() as u8);
    let key = SimpleMerkleNodeKey {
        index: from_index,
        level: siblings.len() as u8,
    };
    let mut sibling_key = key.sibling();
    for s in siblings.iter() {
        tree.set_node_value(sibling_key, *s);
        sibling_key = sibling_key.parent().sibling();
    }
    for i in 0..values.len() {
        tree.set_leaf(from_index + i as u64, values[i]);
    }

    (0..values.len()).map(|i| tree.get_leaf(i as u64 + from_index)).collect()
}
