use std::{collections::HashMap, marker::PhantomData};

use crate::common::{
    data::core::merkle::{
        merkle_proof::MerkleProofCore,
        node::{SimpleMerkleNode, SimpleMerkleNodeKey},
    },
    traits::merkle::MerkleHasher,
};

pub struct SimpleMerkleDeltaBuilder<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>> {
    node_map: HashMap<SimpleMerkleNodeKey, Hash>,
    _phantom: PhantomData<Hasher>,
}

impl<Hash: PartialEq + Copy, Hasher: MerkleHasher<Hash>> SimpleMerkleDeltaBuilder<Hash, Hasher> {
    pub fn new() -> Self {
        Self {
            node_map: HashMap::new(),
            _phantom: PhantomData,
        }
    }
    pub fn get_node_value(&self, key: &SimpleMerkleNodeKey) -> Option<&Hash> {
        self.node_map.get(key)
    }
    // preferentially fetch the node from the stored node map, but if it is not
    // present, use the merkle proof siblings to compute the parent hashes
    pub fn add_leaf_with_stored_node_or_merkle_proof(&mut self, old_merkle_proof: &MerkleProofCore<Hash>, new_value: Hash) {
        let leaf_key = SimpleMerkleNodeKey {
            level: old_merkle_proof.siblings.len() as u8,
            index: old_merkle_proof.index,
        };
        self.node_map.insert(leaf_key, new_value);

        let mut current_hash = new_value;
        let mut current_node_key = leaf_key;

        for proof_sibling_hash in old_merkle_proof.siblings.iter() {
            let is_right_node = (current_node_key.index & 1) == 1;
            current_hash = Hasher::two_to_one_swap(
                is_right_node,
                &current_hash,
                if let Some(stored_sibling_hash) = self.node_map.get(&current_node_key.sibling()) {
                    stored_sibling_hash
                } else {
                    proof_sibling_hash
                },
            );

            let parent_key = current_node_key.parent();
            self.node_map.insert(parent_key, current_hash);
            current_node_key = parent_key;
        }
    }

    pub fn add_node(&mut self, key: SimpleMerkleNodeKey, value: Hash) {
        self.node_map.insert(key, value);
    }

    pub fn finalize(self) -> Vec<SimpleMerkleNode<Hash>> {
        self.node_map.into_iter().map(|(key, value)| SimpleMerkleNode { key, value }).collect()
    }
}





#[cfg(test)]
mod tests {
    use crate::{common::{data::core::{hash::hash256::Hash256, merkle::{merkle_proof::MerkleProofCore, node::SimpleMerkleNodeKey}}, traits::merkle::MerkleHasher}, crypto::hash::sha256::CoreSha256Hasher};

    use super::SimpleMerkleDeltaBuilder;
    #[test]
    fn test_simple_merkle_delta_builder() {
        
        // Create a simple Merkle tree with 4 leaves
        // Leaf hashes (level 0)
        let leaf_hashes = vec![
            Hash256::from_hex_string("0101010101010101010101010101010101010101010101010101010101010101").unwrap(),
            Hash256::from_hex_string("0202020202020202020202020202020202020202020202020202020202020202").unwrap(),
            Hash256::from_hex_string("0303030303030303030303030303030303030303030303030303030303030303").unwrap(),
            Hash256::from_hex_string("0404040404040404040404040404040404040404040404040404040404040404").unwrap(),
        ];
        // Compute parent hashes (level 1)
        let parent_hashes = vec![
            CoreSha256Hasher::two_to_one(&leaf_hashes[0], &leaf_hashes[1]),
            CoreSha256Hasher::two_to_one(&leaf_hashes[2], &leaf_hashes[3]),
        ];
        // Compute root hash (level 2)
        //let root_hash = CoreSha256Hasher::two_to_one(&parent_hashes[0], &parent_hashes[1]);
        // Create Merkle proofs for each leaf
        let merkle_proofs = vec![
            // Proof for leaf 0
            MerkleProofCore::new_from_params::<CoreSha256Hasher>(0, leaf_hashes[0], vec![leaf_hashes[1], parent_hashes[1]]),
            // Proof for leaf 1
            MerkleProofCore::new_from_params::<CoreSha256Hasher>(1, leaf_hashes[1], vec![leaf_hashes[0], parent_hashes[1]]),
            // Proof for leaf 2
            MerkleProofCore::new_from_params::<CoreSha256Hasher>(2, leaf_hashes[2], vec![leaf_hashes[3], parent_hashes[0]]),
            // Proof for leaf 3
            MerkleProofCore::new_from_params::<CoreSha256Hasher>(3, leaf_hashes[3], vec![leaf_hashes[2], parent_hashes[0]]),
        ];

        assert!(merkle_proofs[0].verify::<CoreSha256Hasher>());
        assert!(merkle_proofs[1].verify::<CoreSha256Hasher>());
        assert!(merkle_proofs[2].verify::<CoreSha256Hasher>());
        assert!(merkle_proofs[3].verify::<CoreSha256Hasher>());

        // Now, let's say we want to update leaf 1 and leaf 3
        let new_leaf_hashes = vec![
            Hash256::from_hex_string("0808080808080808080808080808080808080808080808080808080808080808").unwrap(), // new hash for leaf 1
            Hash256::from_hex_string("0909090909090909090909090909090909090909090909090909090909090909").unwrap(),
        ];
        // Create a delta builder
        let mut delta_builder = SimpleMerkleDeltaBuilder::<Hash256, CoreSha256Hasher>::new();
        // Add updated leaves using their Merkle proofs
        delta_builder.add_leaf_with_stored_node_or_merkle_proof(&merkle_proofs[1], new_leaf_hashes[0]);
        delta_builder.add_leaf_with_stored_node_or_merkle_proof(&merkle_proofs[3], new_leaf_hashes[1]);
        // Finalize the delta
        let delta = delta_builder.finalize();
        // The delta should contain the updated leaves and the affected parent and root nodes
        // Let's verify the contents of the delta
        let height = merkle_proofs[0].siblings.len();
        let mut expected_nodes = vec![
            // Updated root
            (SimpleMerkleNodeKey { level: height as u8 - 2, index: 0 }, CoreSha256Hasher::two_to_one(
                &CoreSha256Hasher::two_to_one(&leaf_hashes[0], &new_leaf_hashes[0]),
                &CoreSha256Hasher::two_to_one(&leaf_hashes[2], &new_leaf_hashes[1]),
            )),
            // Updated parent of leaf 0 and new leaf 1
            (SimpleMerkleNodeKey { level: height as u8 - 1, index: 0 }, CoreSha256Hasher::two_to_one(&leaf_hashes[0], &new_leaf_hashes[0])),
            // Updated parent of new leaf 2 and leaf 3
            (SimpleMerkleNodeKey { level: height as u8 - 1, index: 1 }, CoreSha256Hasher::two_to_one(&leaf_hashes[2], &new_leaf_hashes[1])),
            // Updated leaf 1
            (SimpleMerkleNodeKey { level: height as u8, index: 1 }, new_leaf_hashes[0]),
            // Updated leaf 3
            (SimpleMerkleNodeKey { level: height as u8, index: 3 }, new_leaf_hashes[1]),
        ];
        expected_nodes.sort_by_key(|(key, _)| (key.level, key.index));
        let mut actual_nodes: Vec<(SimpleMerkleNodeKey, Hash256)> = delta.into_iter().map(|node| (node.key, node.value)).collect();
        actual_nodes.sort_by_key(|(key, _)| (key.level, key.index));
        assert_eq!(expected_nodes, actual_nodes);
    }
}
