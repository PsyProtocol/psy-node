/*use std::{fmt::Debug, marker::PhantomData};

use hashbrown::HashMap;
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        spiderman::SpidermanUpdateProof,
        traits::MerkleZeroHasher,
    },
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    utils::math::ceil_div_usize,
};

#[derive(Debug, Clone)]
pub struct SimpleMemoryMerkleStore<Hasher, Hash: Copy + PartialEq + Default> {
    /// Stores only non-zero nodes for a sparse representation.
    nodes: HashMap<SimpleMerkleNodeKey, Hash>,
    height: u8,
    /// Pre-computed zero-hashes for each level of the tree.
    /// `zero_value_hashes[0]` is the zero-hash for the root (level 0).
    /// `zero_value_hashes[height]` is the zero-hash for leaves (level `height`).
    zero_value_hashes: Vec<Hash>,
    _hasher: PhantomData<Hasher>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default>
    SimpleMemoryMerkleStore<Hasher, Hash>
{
    pub fn new(height: u8) -> Self {
        let zero_value_hashes = (0..=height)
            .map(|level| Hasher::get_zero_hash((height - level) as usize))
            .collect();

        Self {
            nodes: HashMap::new(),
            height,
            zero_value_hashes,
            _hasher: PhantomData::default(),
        }
    }

    /// Returns the height of the tree. Level 0 is the root, level `height` contains the leaves.
    pub fn height(&self) -> u8 {
        self.height
    }

    /// Returns the maximum possible leaf index for this tree.
    pub fn max_leaf_index(&self) -> u64 {
        (1u64 << self.height) - 1
    }

    /// Gets the value of a node, returning the appropriate pre-computed zero-hash if not present.
    pub fn get_node_value(&self, key: &SimpleMerkleNodeKey) -> Hash {
        self.nodes
            .get(key)
            .copied()
            .unwrap_or(self.zero_value_hashes[key.level as usize])
    }
    pub fn get_leaf_value(&self, index: u64) -> Hash {
        self.get_node_value(&SimpleMerkleNodeKey::new(self.height, index))
    }

    /// Sets the value of a node. If the value is the zero-hash for its level, it's removed to maintain sparsity.
    pub fn set_node_value(&mut self, key: SimpleMerkleNodeKey, value: Hash) {
        if value == self.zero_value_hashes[key.level as usize] {
            self.nodes.remove(&key);
        } else {
            self.nodes.insert(key, value);
        }
    }

    /// Gets the root hash of the tree.
    pub fn get_root(&self) -> Hash {
        self.get_node_value(&SimpleMerkleNodeKey::new_root())
    }
    
    /// Finds the index of the first empty (zero) leaf, which is the next position for an append operation.
    pub fn find_next_append_index(&self) -> anyhow::Result<u64> {
        let root_zero_hash = self.zero_value_hashes[0];
        if self.get_root() == root_zero_hash {
            return Ok(0);
        }

        let mut current_node = SimpleMerkleNodeKey::new_root();
        while current_node.level < self.height {
            let left_child = current_node.left_child();
            let left_val = self.get_node_value(&left_child);
            
            // A "full" subtree is one whose hash is NOT the pre-computed zero hash for its level.
            let is_left_subtree_full = left_val != self.zero_value_hashes[left_child.level as usize];

            if is_left_subtree_full {
                // Left is full, so the first empty slot must be in the right subtree.
                current_node = current_node.right_child();
            } else {
                // Left is not full, so the first empty slot is there.
                current_node = left_child;
            }
        }
        
        if current_node.index > self.max_leaf_index() {
             anyhow::bail!("tree is full");
        }
        
        Ok(current_node.index)
    }

    /// Recursively re-hashes a subtree from its leaves up to its root node.
    /// Returns the new hash of the subtree's root.
    fn _rehash_subtree_recursive(&mut self, node_key: SimpleMerkleNodeKey) -> Hash {
        if node_key.level == self.height {
            // Base case: at a leaf, just return its value.
            return self.get_node_value(&node_key);
        }

        let left_hash = self._rehash_subtree_recursive(node_key.left_child());
        let right_hash = self._rehash_subtree_recursive(node_key.right_child());

        let parent_hash = Hasher::two_to_one(&left_hash, &right_hash);
        self.set_node_value(node_key, parent_hash);
        parent_hash
    }

    /// Re-calculates all hashes within a given subtree and propagates the changes up to the main root.
    pub fn rehash_sub_tree(&mut self, sub_tree_height: u8, sub_tree_index: u64) {
        let sub_tree_root_level = self.height - sub_tree_height;
        let sub_root_key = SimpleMerkleNodeKey::new(sub_tree_root_level, sub_tree_index);

        self._rehash_subtree_recursive(sub_root_key);

        // After rehashing the subtree itself, we still need to update the path from its root to the main tree root.
        if sub_root_key.level > 0 {
             self.rehash_path_to_root(sub_root_key.parent());
        }
    }

    /// Hashes a path from the given node up to the root. Assumes children of the path are already correct.
    fn rehash_path_to_root(&mut self, mut key: SimpleMerkleNodeKey) {
        loop {
            let left_val = self.get_node_value(&key.left_child());
            let right_val = self.get_node_value(&key.right_child());
            let new_val = Hasher::two_to_one(&left_val, &right_val);
            self.set_node_value(key, new_val);

            if key.level == 0 {
                break;
            }
            key = key.parent();
        }
    }

    /// Sets a single leaf value and re-hashes the path to the root, returning a proof of the change.
    pub fn set_leaf(&mut self, index: u64, value: Hash) -> DeltaMerkleProofCore<Hash> {
        let old_proof = self.get_leaf(index);
        
        self.set_node_value(SimpleMerkleNodeKey::new(self.height, index), value);
        
        if self.height > 0 {
            self.rehash_path_to_root(SimpleMerkleNodeKey::new(self.height - 1, index / 2));
        }

        let new_root = self.get_root();

        DeltaMerkleProofCore {
            old_root: old_proof.root,
            old_value: old_proof.value,
            new_root,
            new_value: value,
            index, // Bug Fix: was using the wrong variable here.
            siblings: old_proof.siblings,
        }
    }
    
    /// Generates the Merkle proof for a given leaf index.
    pub fn get_leaf(&self, index: u64) -> MerkleProofCore<Hash> {
        let mut siblings = Vec::with_capacity(self.height as usize);
        let mut current_key = SimpleMerkleNodeKey::new(self.height, index);
        
        while current_key.level > 0 {
            siblings.push(self.get_node_value(&current_key.sibling()));
            current_key = current_key.parent();
        }
        
        MerkleProofCore {
            root: self.get_root(),
            value: self.get_node_value(&SimpleMerkleNodeKey::new(self.height, index)),
            index,
            siblings,
        }
    }

    /// Appends a batch of leaves and generates the most efficient "Spiderman" proofs for the operation.
    pub fn append_leaves_spider_man(
        &mut self,
        sub_tree_height: u8,
        leaves: &[Hash],
    ) -> anyhow::Result<Vec<SpidermanUpdateProof<Hash>>> {
        if leaves.is_empty() {
            return Ok(Vec::new());
        }

        let leaves_per_subtree = 1usize << sub_tree_height;
        let append_index = self.find_next_append_index()?;
        
        if append_index + leaves.len() as u64 > (1u64 << self.height) {
            anyhow::bail!("tree cannot fit an additional {} leaves", leaves.len());
        }

        let mut proofs = Vec::new();
        let mut remaining_leaves = leaves;
        let mut current_append_pos = append_index;

        // --- Handle the first (potentially partial) subtree ---
        let sub_tree_index = current_append_pos / leaves_per_subtree as u64;
        let sub_tree_start_leaf = (current_append_pos % leaves_per_subtree as u64) as usize;

        let leaves_for_first_tree = (leaves_per_subtree - sub_tree_start_leaf).min(remaining_leaves.len());
        let (first_chunk, rest) = remaining_leaves.split_at(leaves_for_first_tree);
        remaining_leaves = rest;

        let proof = self._set_subtree_get_spiderman_proof(sub_tree_height, sub_tree_index, sub_tree_start_leaf, first_chunk)?;
        proofs.push(proof);
        current_append_pos += leaves_for_first_tree as u64;

        // --- Handle all subsequent (full or final partial) subtrees ---
        let mut next_sub_tree_index = sub_tree_index + 1;
        for chunk in remaining_leaves.chunks(leaves_per_subtree) {
            let proof = self._set_subtree_get_spiderman_proof(sub_tree_height, next_sub_tree_index, 0, chunk)?;
            proofs.push(proof);
            next_sub_tree_index += 1;
        }

        Ok(proofs)
    }

    /// Helper function to update a subtree and generate its Spiderman proof.
    fn _set_subtree_get_spiderman_proof(
        &mut self,
        sub_tree_height: u8,
        sub_tree_index: u64,
        start_leaf_in_subtree: usize,
        leaves_to_set: &[Hash],
    ) -> anyhow::Result<SpidermanUpdateProof<Hash>> {
        let leaves_per_subtree = 1usize << sub_tree_height;
        let zero_hash = self.zero_value_hashes[self.height as usize];

        // 1. Capture the "before" state
        let old_root = self.get_root();
        let sub_tree_root_level = self.height - sub_tree_height;
        let sub_root_key = SimpleMerkleNodeKey::new(sub_tree_root_level, sub_tree_index);
        let old_sub_tree_root = self.get_node_value(&sub_root_key);
        let siblings = (0..sub_root_key.level)
            .map(|i| self.get_node_value(&sub_root_key.parent_at_level(i+1).sibling()))
            .collect::<Vec<_>>();

        // Construct old leaves for the proof
        let mut web_proof_old_leaves = vec![zero_hash; leaves_per_subtree];
        let sub_tree_base_index = sub_tree_index * leaves_per_subtree as u64;
        for i in 0..start_leaf_in_subtree {
            web_proof_old_leaves[i] = self.get_leaf_value(sub_tree_base_index + i as u64);
        }
        
        // 2. Apply the update
        for (i, leaf) in leaves_to_set.iter().enumerate() {
            let leaf_key = SimpleMerkleNodeKey::new(self.height, sub_tree_base_index + (start_leaf_in_subtree + i) as u64);
            self.set_node_value(leaf_key, *leaf);
        }
        self.rehash_sub_tree(sub_tree_height, sub_tree_index);

        // 3. Capture the "after" state
        let new_root = self.get_root();
        let new_sub_tree_root = self.get_node_value(&sub_root_key);

        // Construct new leaves for the proof
        let mut web_proof_new_leaves = web_proof_old_leaves.clone();
        web_proof_new_leaves[start_leaf_in_subtree..start_leaf_in_subtree + leaves_to_set.len()]
            .copy_from_slice(leaves_to_set);

        let top_line_proof = DeltaMerkleProofCore {
            old_root,
            old_value: old_sub_tree_root,
            new_root,
            new_value: new_sub_tree_root,
            index: sub_tree_index,
            siblings,
        };

        Ok(SpidermanUpdateProof {
            top_line_proof,
            web_proof_old_leaves,
            web_proof_new_leaves,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::data::hash::hash256::Hash256;
    use parth_core::utils::QPGenRandom;
    use parth_crypto::hash::sha256::CoreSha256Hasher;

    // --- Type Aliases for Convenience ---
    type TestHash = Hash256;
    type TestHasher = CoreSha256Hasher;
    type TestStore = SimpleMemoryMerkleStore<TestHasher, TestHash>;

    // --- Helper Functions ---
    fn rand_hash() -> TestHash {
        TestHash::qp_rand_gen()
    }
    
    // --- Test Cases ---

    #[test]
    fn test_initialization() {
        let height = 8;
        let store = TestStore::new(height);

        assert_eq!(store.height(), height, "Store height should match");
        assert!(store.nodes.is_empty(), "A new store should have no non-zero nodes");
        assert_eq!(store.zero_value_hashes.len(), (height + 1) as usize, "Should have a zero hash for each level plus the root");
        assert_ne!(store.get_root(), TestHash::default(), "Root of an empty tree should be a specific zero-hash, not the default zero");
    }

    #[test]
    fn test_set_and_get_leaf_proofs() {
        let mut store = TestStore::new(16);
        let leaf_index = 1337;
        let leaf_value = rand_hash();

        // 1. Set the leaf and verify the delta proof
        let dmp = store.set_leaf(leaf_index, leaf_value);
        assert!(dmp.verify::<TestHasher>(), "set_leaf must produce a valid delta proof");
        assert_eq!(dmp.new_value, leaf_value);

        // 2. Get the leaf and verify the inclusion proof
        let mp = store.get_leaf(leaf_index);
        assert!(mp.verify::<TestHasher>(), "get_leaf must produce a valid inclusion proof");
        assert_eq!(mp.value, leaf_value, "get_leaf should return the value that was set");
        
        // 3. Ensure consistency
        assert_eq!(dmp.new_root, mp.root, "The new root from the delta proof should match the root for the inclusion proof");
        assert_ne!(dmp.old_root, dmp.new_root, "Root should change after setting a leaf in an empty tree");
    }

    #[test]
    fn test_sparsity_and_zero_hashes() {
        let mut store = TestStore::new(8);
        let leaf_index = 42;
        let leaf_value = rand_hash();
        let initial_zero_root = store.get_root();

        // Set a non-zero leaf
        store.set_leaf(leaf_index, leaf_value);
        assert_ne!(store.get_root(), initial_zero_root, "Root should change after setting a non-zero leaf");
        assert!(!store.nodes.is_empty(), "Nodes map should not be empty after setting a value");

        // Set the same leaf back to the zero hash
        let zero_leaf_hash = store.zero_value_hashes[store.height as usize];
        store.set_leaf(leaf_index, zero_leaf_hash);
        assert_eq!(store.get_root(), initial_zero_root, "Root should revert to the initial zero root after clearing the only leaf");
        assert!(store.nodes.is_empty(), "Nodes map should be empty when all leaves are zero");
    }

    #[test]
    fn test_find_next_append_index_logic() {
        let mut store = TestStore::new(4); // 16 leaves max

        // 1. Empty tree
        assert_eq!(store.find_next_append_index().unwrap(), 0, "Next index of empty tree should be 0");

        // 2. Sequential appends
        store.set_leaf(0, rand_hash());
        assert_eq!(store.find_next_append_index().unwrap(), 1, "Should find next index after one append");
        store.set_leaf(1, rand_hash());
        assert_eq!(store.find_next_append_index().unwrap(), 2, "Should find next index after two appends");

        // 3. With a gap
        store.set_leaf(3, rand_hash()); // creates a gap at index 2
        assert_eq!(store.find_next_append_index().unwrap(), 2, "Should find the first gap");
        store.set_leaf(2, rand_hash());
        assert_eq!(store.find_next_append_index().unwrap(), 4, "Should find next index after filling the gap");

        // 4. Full tree
        let height = 3; // 8 leaves
        let mut full_store = TestStore::new(height);
        for i in 0..(1 << height) {
            full_store.set_leaf(i, rand_hash());
        }
        assert!(full_store.find_next_append_index().is_err(), "Should return an error for a full tree");
    }

    #[test]
    fn test_rehash_subtree() {
        let height = 6;
        let sub_tree_height = 4; // 16 leaves per subtree
        let sub_tree_index = 1;

        // Create two identical trees
        let mut tree_a = TestStore::new(height);
        let mut tree_b = TestStore::new(height);

        // Populate a subtree with leaves
        let leaves_to_set = (0..(1 << sub_tree_height)).map(|_| rand_hash()).collect::<Vec<_>>();
        let base_leaf_index = sub_tree_index * (1 << sub_tree_height);

        for (i, leaf) in leaves_to_set.iter().enumerate() {
            // In tree_a, use the public API which rehashes on every set
            tree_a.set_leaf(base_leaf_index + i as u64, *leaf);

            // In tree_b, just place the leaves without rehashing the path
            let key = SimpleMerkleNodeKey::new(height, base_leaf_index + i as u64);
            tree_b.set_node_value(key, *leaf);
        }

        // Roots should be different before rehashing tree_b
        assert_ne!(tree_a.get_root(), tree_b.get_root());

        // Now, rehash the entire subtree in tree_b
        tree_b.rehash_sub_tree(sub_tree_height as u8, sub_tree_index);

        // The roots should now be identical
        assert_eq!(tree_a.get_root(), tree_b.get_root(), "rehash_sub_tree should produce the correct root");
    }

    /// A helper to run and validate spiderman append scenarios
    fn run_spiderman_scenario(
        height: u8,
        sub_tree_height: u8,
        initial_leaves_count: u64,
        leaves_to_append_count: usize,
    ) {
        let mut store = TestStore::new(height);
        let mut ground_truth_store = TestStore::new(height);

        // 1. Setup initial state
        for i in 0..initial_leaves_count {
            let val = rand_hash();
            store.set_leaf(i, val);
            ground_truth_store.set_leaf(i, val);
        }
        let initial_root = store.get_root();

        // 2. Prepare leaves to append
        let leaves_to_append = (0..leaves_to_append_count)
            .map(|_| rand_hash())
            .collect::<Vec<_>>();

        // 3. Perform the spiderman append
        let proofs = store
            .append_leaves_spider_man(sub_tree_height, &leaves_to_append)
            .unwrap();
        
        if leaves_to_append_count == 0 {
            assert!(proofs.is_empty());
            return;
        }

        // 4. Verify each proof and the chain
        let mut expected_old_root = initial_root;
        for (i, proof) in proofs.iter().enumerate() {
            assert!(proof.verify::<TestHasher>(), "Spiderman proof #{} must be valid", i);
            assert_eq!(
                proof.top_line_proof.old_root, expected_old_root,
                "Proof #{} old root does not chain correctly", i
            );
            expected_old_root = proof.top_line_proof.new_root;
        }

        // 5. Verify the final root against ground truth
        for (i, leaf) in leaves_to_append.iter().enumerate() {
            ground_truth_store.set_leaf(initial_leaves_count + i as u64, *leaf);
        }
        assert_eq!(
            store.get_root(),
            ground_truth_store.get_root(),
            "Final root after spiderman append must match ground truth"
        );
        assert_eq!(
            store.get_root(),
            proofs.last().unwrap().top_line_proof.new_root,
            "Final root must match the new_root of the last proof"
        );
    }
    
    #[test]
    fn test_spiderman_simple_append() {
        // Append a few leaves into the first subtree of an empty tree.
        run_spiderman_scenario(10, 4, 0, 5);
    }

    #[test]
    fn test_spiderman_append_cross_boundary() {
        let sub_tree_height = 4; // 16 leaves per subtree
        // Start with 14 leaves, then append 5. This should cross the boundary
        // from the first subtree (using 2 slots) to the second (using 3 slots).
        // This should generate 2 proofs.
        run_spiderman_scenario(10, sub_tree_height, 14, 5);
    }

    #[test]
    fn test_spiderman_multiple_full_subtrees() {
        let sub_tree_height = 3; // 8 leaves per subtree
        // Start with 6 leaves. Append 20 more.
        // Proof 1: Fills the last 2 slots of subtree 0. (leaves: 2)
        // Proof 2: Fills all 8 slots of subtree 1. (leaves: 8)
        // Proof 3: Fills all 8 slots of subtree 2. (leaves: 8)
        // Proof 4: Fills the first 2 slots of subtree 3. (leaves: 2)
        // Total leaves: 2 + 8 + 8 + 2 = 20.
        // Total proofs: 4.
        run_spiderman_scenario(10, sub_tree_height, 6, 20);
    }
    
    #[test]
    fn test_spiderman_exactly_one_subtree() {
        let sub_tree_height = 5; // 32 leaves
        run_spiderman_scenario(10, sub_tree_height, 0, 32);
    }
    
    #[test]
    fn test_spiderman_append_to_empty() {
        let sub_tree_height = 4;
        // Append a large number that crosses many boundaries, starting from an empty tree.
        run_spiderman_scenario(10, sub_tree_height, 0, 100);
    }

    #[test]
    fn test_spiderman_zero_append() {
        // Appending zero leaves should do nothing and return an empty vec of proofs.
        run_spiderman_scenario(10, 4, 10, 0);
    }
}*/