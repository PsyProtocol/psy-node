use std::{fmt::Debug, marker::PhantomData};

use parth_core::{crypto::hash::{tag_tree::{TagTreeMerkleProof, TagTreeMerkleProofPartial, TagTreeNodePreimage, TagTreeProofNode, TagTreeStorageNode}, traits::MerkleHasher}, data::hash::merkle_node_key::SimpleMerkleNodeKey};

#[derive(Debug, Clone)]
pub struct SimpleMemoryTagTreeStore<Hasher, Hash: Copy + PartialEq + Default> {
    nodes: hashbrown::HashMap<SimpleMerkleNodeKey, TagTreeStorageNode<Hash>>,
    height: u8,
    _hasher: PhantomData<Hasher>,
}

impl<Hasher: MerkleHasher<Hash>, Hash: Copy + PartialEq + Default>
    SimpleMemoryTagTreeStore<Hasher, Hash>
{
    pub fn new(height: u8) -> Self {
        Self {
            nodes: hashbrown::HashMap::new(),
            height,
            _hasher: PhantomData::default(),
        }
    }


    pub fn set_node_split(&mut self, key: SimpleMerkleNodeKey, value: Hash, tag: Hash) {
        self.nodes
            .insert(key, TagTreeStorageNode { value, tag });
    }

    pub fn set_tag(&mut self, key: SimpleMerkleNodeKey, tag: Hash) {
        if key.level == self.height {
            self.nodes.insert(key, TagTreeStorageNode {
                value: Hasher::two_to_one(&Hasher::two_to_one(&Hash::default(), &Hash::default()), &tag),
                tag,
            });
        }else {
            let left = self.get_node_value(&key.left_child());
            let right = self.get_node_value(&key.right_child());
            self.nodes.insert(key, TagTreeStorageNode { value: Hasher::two_to_one(&Hasher::two_to_one(&left, &right), &tag), tag });
        }
    }

    pub fn set_node(&mut self, key: SimpleMerkleNodeKey, value: TagTreeStorageNode<Hash>) {
        self.nodes.insert(key, value);
    }
    pub fn get_node(&self, key: &SimpleMerkleNodeKey) -> Option<&TagTreeStorageNode<Hash>> {
        self.nodes.get(key)
    }

    pub fn get_node_value(&self, key: &SimpleMerkleNodeKey) -> Hash {
        if self.nodes.contains_key(key) {
            self.nodes[key].value
        } else {
            Hash::default()
        }
    }
    pub fn get_node_tag(&self, key: &SimpleMerkleNodeKey) -> Hash {
        if self.nodes.contains_key(key) {
            self.nodes[key].tag
        } else {
            Hash::default()
        }
    }
    pub fn get_proof_node(&self, sibling_key: &SimpleMerkleNodeKey) -> TagTreeProofNode<Hash> {
        TagTreeProofNode { sibling: self.get_node_value(sibling_key), parent_tag: self.get_node_tag(&sibling_key.parent()) }
    }
    pub fn get_preimage_node(&self, key: &SimpleMerkleNodeKey) -> TagTreeNodePreimage<Hash> {
        if key.level == self.height {
            let tag = self.get_node_tag(key);
            return TagTreeNodePreimage {
                left: Hash::default(),
                right: Hash::default(),
                tag,
            };
        }else{
            let left = self.get_node_value(&key.left_child());
            let right = self.get_node_value(&key.right_child());
            let tag = self.get_node_tag(key);
            TagTreeNodePreimage { left, right, tag }
        }
    }


    pub fn get_proof(&self, node: SimpleMerkleNodeKey) -> TagTreeMerkleProofPartial<Hash> {
        let siblings = node.siblings().iter().map(|x| self.get_proof_node(x))
            .collect::<Vec<_>>();
        let leaf = self.get_preimage_node(&node);
        TagTreeMerkleProofPartial {
            index: node.index,
            leaf,
            siblings,
        }
    }
    pub fn get_root_hash(&self) -> Hash {
        self.get_node_value(&SimpleMerkleNodeKey { level: 0, index: 0 })
    }

    pub fn get_proof_full(&self, node: SimpleMerkleNodeKey) -> TagTreeMerkleProof<Hash> {
        let siblings = node.siblings().iter().map(|x| self.get_proof_node(x))
            .collect::<Vec<_>>();
        let leaf = self.get_preimage_node(&node);
        TagTreeMerkleProof {
            index: node.index,
            leaf,
            siblings,
            root: self.get_root_hash(),
        }
    }
}

#[cfg(test)]
mod tests {
    

    use std::collections::{HashMap, HashSet};

    use parth_core::{crypto::hash::traits::MerkleHasher, data::hash::{hash256::Hash256, merkle_node_key::{generate_nca_tree_groups_v1, generate_nca_tree_groups_naive, SimpleMerkleNodeKey}}};
    
    use super::SimpleMemoryTagTreeStore;
    use parth_crypto::hash::sha256::CoreSha256Hasher;

    fn get_unique_node_set(node_set: Vec<SimpleMerkleNodeKey>) -> Vec<SimpleMerkleNodeKey> {
        let hset = HashSet::<SimpleMerkleNodeKey>::from_iter(node_set.into_iter());
        hset.into_iter().collect::<Vec<_>>()
    }

    fn random_nodes_in_tree(height: u8, count: usize) -> Vec<SimpleMerkleNodeKey>{

        let max_node_id = 1u64 << (height as u64);

        let mut result = Vec::with_capacity(count);
        for _ in 0..count {
            result.push(SimpleMerkleNodeKey {
                level: height,
                index: rand::random::<u64>()%max_node_id,
            });
        }

        get_unique_node_set(result)
        

    }
    #[test]
    fn test_merkle_tree_sha256_tiny() {
        type Hash = Hash256;
        type Hasher = CoreSha256Hasher;
        let guta_height = 1u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let mut tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(guta_height);
        let tag_1 = Hash::from_u64_le_values(1, 2, 3, 4);
        let tag_2 = Hash::from_u64_le_values(5, 6, 7, 8);
        let tag_root = Hash::from_u64_le_values(9, 10, 11, 12);
        tree.set_tag(leaf_1, tag_1);
        tree.set_tag(leaf_2, tag_2);
        tree.set_tag(SimpleMerkleNodeKey::new(0, 0), tag_root);
        let expected_left_value = Hasher::two_to_one(&Hasher::two_to_one(&Hash::default(), &Hash::default()), &tag_1);
        let expected_right_value = Hasher::two_to_one(&Hasher::two_to_one(&Hash::default(), &Hash::default()), &tag_2);
        assert_eq!(tree.get_node_tag(&leaf_1), tag_1, "leaf tags do not match expected values");
        assert_eq!(tree.get_node_tag(&leaf_2), tag_2, "leaf tags do not match expected values");
        assert_eq!(tree.get_node_tag(&SimpleMerkleNodeKey::new(0, 0)), tag_root, "root tag does not match expected value");

        assert_eq!(tree.get_node_value(&leaf_1), expected_left_value, "left leaf value does not match expected value");
        assert_eq!(tree.get_node_value(&leaf_2), expected_right_value, "right leaf value does not match expected value");

        let expected_root_value = Hasher::two_to_one(&Hasher::two_to_one(&expected_left_value, &expected_right_value), &tag_root);

        let root = tree.get_root_hash();
        assert_eq!(root, expected_root_value, "root hash does not match expected value");
        let proof_1 = tree.get_proof_full(leaf_1);
        let proof_2 = tree.get_proof_full(leaf_2);
        assert!(proof_1.verify::<Hasher>(), "proof 1 verification failed");
        assert!(proof_2.verify::<Hasher>(), "proof 2 verification failed");

    }
    #[test]
    fn test_merkle_tree_sha256_small_1() {
        type Hash = Hash256;
        type Hasher = CoreSha256Hasher;
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        assert_eq!(group_levels.len(), 3);
        let tree_height = group_levels.len()-1;
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);
        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
        for (level, gl) in group_levels.iter().enumerate() {    
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::rand();
                let key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                simple_tree.set_tag(key, hash);
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            assert!(proof.verify::<Hasher>(), "proof verification failed"); 
        }


    }
    #[test]
    fn test_merkle_tree_sha256_small() {
        type Hash = Hash256;
        type Hasher = CoreSha256Hasher;
        let guta_height = 3u8;
        let leaf_1 = SimpleMerkleNodeKey::new(guta_height, 0);
        let leaf_2 = SimpleMerkleNodeKey::new(guta_height, 1);
        let leaf_3 = SimpleMerkleNodeKey::new(guta_height, 2);
        let leaf_5 = SimpleMerkleNodeKey::new(guta_height, 5);
        let leaf_6 = SimpleMerkleNodeKey::new(guta_height, 6);
        let leaves = vec![leaf_1, leaf_2, leaf_3, leaf_5, leaf_6];
        let e_group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);
        println!("e_group_levels: {:#?}", e_group_levels);
        let group_levels = generate_nca_tree_groups_naive(&leaves, guta_height);
        println!("n_group_levels: {:#?}", group_levels);
        let tree_height = group_levels.len()-1;
        assert_eq!(e_group_levels, group_levels);
        assert_eq!(group_levels.len(), 3);
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);
        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();
        for (level, gl) in group_levels.iter().enumerate() {    
            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::rand();
                let key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                simple_tree.set_tag(key, hash);
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            assert!(proof.verify::<Hasher>(), "proof verification failed"); 
        }


    }
    #[test]
    fn test_merkle_tree_sha256() {
        type Hash = Hash256;
        type Hasher = CoreSha256Hasher;
        let guta_height: u8 = 32;
        let leaves = random_nodes_in_tree(guta_height, 1337);
        let group_levels = generate_nca_tree_groups_v1(&leaves, guta_height);

        let tree_height = group_levels.len() - 1;
        let mut simple_tree = SimpleMemoryTagTreeStore::<Hasher, Hash>::new(tree_height as u8);

        let mut hash_map_dat = HashMap::<SimpleMerkleNodeKey, SimpleMerkleNodeKey>::new();

        for (level, gl) in group_levels.iter().enumerate() {

            for (index, g) in gl.iter().enumerate() {
                let hash = Hash::rand();
                let key = SimpleMerkleNodeKey::new((tree_height-level) as u8, index as u64);
                hash_map_dat.insert(g.nca, key);
                simple_tree.set_tag(key, hash);
            }
        }
        for g in group_levels.iter().flatten() {
            let key = hash_map_dat[&g.nca];
            let proof = simple_tree.get_proof_full(key);
            assert!(proof.verify::<Hasher>(), "proof verification failed");
        }
        


    }

}



