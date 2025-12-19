use async_trait::async_trait;
use dashmap::DashMap;
use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore, compute_root_merkle_proof_generic}, traits::MerkleZeroHasher}, data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}};
use std::marker::PhantomData;

use crate::memory_stores::traits::{PsyMemoryMerkleStoreAppendOnlyReaderBase, PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync, PsyMemoryMerkleStoreImm};

// --- Start of Refactored Code ---
#[derive(Debug, Clone)]
pub struct PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash> {
    pub nodes: DashMap<SimpleMerkleNodeKey, Hash>,
    pub roots: DashMap<Hash, u64>,
    height: u8,
    /// Pre-computed hashes for empty subtrees of a given height.
    /// `zero_value_hashes[h]` is the hash of an empty tree of height `h`.
    zero_value_hashes: Vec<Hash>,
    _hasher: PhantomData<Hasher>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + Eq + PartialEq + Default + std::hash::Hash>
    PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>
{
    pub fn new(height: u8) -> Self {
        let zero_value_hashes = (0..=height)
            .map(|h| Hasher::get_zero_hash(h as usize))
            .collect();

        Self {
            nodes: DashMap::new(),
            roots: DashMap::new(),
            height,
            zero_value_hashes,
            _hasher: PhantomData::default(),
        }
    }
    pub fn get_nodes_between_leaves(&self, min_include_leaf_index: u64, max_include_leaf_index: u64) -> Vec<SimpleMerkleNode<Hash>> {
        let mut result = Vec::new();

        let tree_height = self.get_height();
        for level in 0..=tree_height {
            let start_index = min_include_leaf_index >> (tree_height - level);
            let end_index = max_include_leaf_index >> (tree_height - level);

            for index in start_index..=end_index {
                let key = SimpleMerkleNodeKey::new(level, index);
                if let Some(node) = self.nodes.get(&key) {
                    result.push(SimpleMerkleNode {
                        key,
                        value: *node.value(),
                    });
                }
            }
        }
/* 
        for node in self.nodes.iter() {
            let key = node.key();
            let level = key.level;
            let index = key.index;

            let start_index = min_include_leaf_index >> (tree_height - level);
            let end_index = max_include_leaf_index >> (tree_height - level);

            if index >= start_index && index <= end_index {
                result.push(SimpleMerkleNode {
                    key: *key,
                    value: *node.value(),
                });
            }
        }*/
        result
    }
    pub fn get_historical_append_only_merkle_proof_for_root(
        &self,
        checkpoint_tree_root: Hash,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        match self.roots.get(&checkpoint_tree_root) {
            Some(v) => {
                let index = *v;
                Ok(self.get_leaf(index))
            },
            None => anyhow::bail!("Root not found in append-only store"),
        }
    }
    pub fn get_historical_index_append_only_merkle_proof_for_root(
        &self,
        checkpoint_tree_root: Hash,
        historical_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        match self.roots.get(&checkpoint_tree_root) {
            Some(v) => {
                let index = *v;
                Ok(self.get_historical_merkle_proof_at_historical_index(index, historical_index))
            },
            None => anyhow::bail!("Root not found in append-only store"),
        }
    }
    pub fn recompute_entire_level(&self, level: u8) {
        if level >= self.height {
            return; // Nothing to rehash
        }

        let end_index = 1u64 << (level);
        
        for i in 0..end_index {
            let node_key = SimpleMerkleNodeKey::new(level, i);
            let left_child_key = node_key.left_child();
            let right_child_key = node_key.right_child();

            // Safely get child values. The read locks are released immediately
            // within the get_node_value function.
            let left_hash = self.get_node_value(&left_child_key);
            let right_hash = self.get_node_value(&right_child_key);

            // Now, with no locks held, compute the parent's hash.
            let parent_hash = Hasher::two_to_one(&left_hash, &right_hash);

            // Safely set the parent's value. This function will acquire a brief
            // write lock and then release it.
            self.set_node_value(node_key, parent_hash);
        }
    }
    pub fn recompute_entire_tree(&self) {
        for level in (0..self.height).rev() {
            self.recompute_entire_level(level);
        }
    }
    pub fn ensure_leaf_root_recorded(&self, index: u64) {
        let leaf_proof = self.get_leaf(index);
        let root = leaf_proof.get_append_root::<Hasher>();
        self.roots.insert(root, index);
    }
    pub fn append_leaf(&self, index: u64, leaf: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let max_leaves = 1u64 << self.height;
        if index >= max_leaves {
            anyhow::bail!("Tree is full, cannot append more leaves");
        }
        if self.nodes.contains_key(&SimpleMerkleNodeKey::new(self.height, index+1)) {
            anyhow::bail!("Leaf at index {} already exists, so we cannot append at the index before it", index+1);
        }
        let proof = self.set_leaf(index, leaf);
        self.roots.insert(proof.new_root, index);
        Ok(proof)
    }

    pub fn get_leaf_index_for_root(&self, root: Hash) -> Option<u64> {
        match self.roots.get(&root) {
            Some(v) => Some(*v),
            None => None,
        }
    }
    pub fn get_historical_node_value(&self, key: &SimpleMerkleNodeKey, historical_index: u64) -> Hash {
        let level_offset = self.height - key.level;
        let node_first_leaf = key.index << level_offset;
        let node_last_leaf = ((key.index + 1) << level_offset) - 1;

        if node_last_leaf <= historical_index {
            // Node is fully contained in historical state - all leaves existed, use current value
            match self.nodes.get(key) {
                Some(v) => *v,
                None => self.get_zero_hash_for_level(key.level),
            }
        } else if node_first_leaf > historical_index {
            // Node is fully outside historical state - no leaves existed yet, return zero hash
            self.get_zero_hash_for_level(key.level)
        } else {
            // Node straddles the boundary - some leaves existed, some didn't
            // We need to recursively compute the historical value
            if key.level >= self.height {
                // Leaf level - this specific leaf is beyond historical_index
                self.get_zero_hash_for_level(key.level)
            } else {
                let left = self.get_historical_node_value(&key.left_child(), historical_index);
                let right = self.get_historical_node_value(&key.right_child(), historical_index);
                Hasher::two_to_one(&left, &right)
            }
        }
    }
    pub fn get_historical_merkle_proof_at_historical_index(
        &self,
        index: u64,
        historical_index: u64,
    ) -> MerkleProofCore<Hash> {
        // get the merkle proof showing the inclusion of a leaf at index n, at the point in time where the leaf at historical index is the last non-zero leaf

        let leaf_key = SimpleMerkleNodeKey::new(self.get_height(), index);
        let siblings = leaf_key.siblings();
        let mut sibling_values = Vec::with_capacity(siblings.len());

        for sibling_key in &siblings {
            // Use get_historical_node_value which correctly handles:
            // 1. Fully contained nodes (all leaves <= historical_index) -> current value
            // 2. Fully outside nodes (all leaves > historical_index) -> zero hash
            // 3. Straddling nodes (some leaves <= historical_index, some >) -> recursive computation
            sibling_values.push(self.get_historical_node_value(sibling_key, historical_index));
        }

        let value = self.get_historical_node_value(&leaf_key, historical_index);
        let root = compute_root_merkle_proof_generic::<Hash, Hasher>(value, index, &sibling_values);
        MerkleProofCore {
            index,
            siblings: sibling_values,
            root,
            value,
        }
    }

}
#[async_trait]
impl<Hasher: MerkleZeroHasher<Hash> + Send + Sync, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Send + Sync> PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync<Hash> for PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash> {

    async fn get_merkle_proof_for_leaf_async(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        Ok(self.get_leaf(leaf_index))
    }
    async fn get_historical_merkle_proof_for_leaf_async(
        &self,
        leaf_index: u64,
    ) -> anyhow::Result<MerkleProofCore<Hash>> {
        Ok(self.get_historical_merkle_proof(leaf_index))
    }
    async fn get_append_leaf_index_for_root_async(
        &self,
        checkpoint_tree_root: Hash,
    ) -> anyhow::Result<u64>{
        match self.roots.get(&checkpoint_tree_root) {
            Some(v) => Ok(*v),
            None => anyhow::bail!("Root not found in append-only store"),
        }
    }
}

impl<Hasher: MerkleZeroHasher<Hash> + Send + Sync, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Send + Sync> PsyMemoryMerkleStoreAppendOnlyReaderBase<Hash> for PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash> {

    #[inline]
    fn get_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> MerkleProofCore<Hash> {
        self.get_leaf(leaf_index)
    }

    #[inline]
    fn get_historical_merkle_proof_for_leaf(
        &self,
        leaf_index: u64,
    ) -> MerkleProofCore<Hash> {
        self.get_historical_merkle_proof(leaf_index)
    }

    #[inline]
    fn get_append_leaf_index_for_root(
        &self,
        checkpoint_tree_root: Hash,
    ) -> Option<u64>{
        match self.roots.get(&checkpoint_tree_root) {
            Some(v) => Some(*v),
            None => None,
        }
    }
}


impl<Hasher: MerkleZeroHasher<Hash>, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash> PsyMemoryMerkleStoreImm<Hasher, Hash> for PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash> {
    #[inline]
    fn get_height(&self) -> u8 {
        self.height
    }

    /// Helper to get the zero hash for a node at a given level.
    #[inline]
    fn get_zero_hash_for_level(&self, level: u8) -> Hash {
        // The height of a subtree rooted at `level` is `self.height - level`.
        let subtree_height = self.height - level;
        self.zero_value_hashes[subtree_height as usize]
    }
    
    #[inline]
    fn set_node_value(&self, key: SimpleMerkleNodeKey, value: Hash) {
        // Optimization: If a node's value is the default for its level (i.e., it represents
        // an empty subtree), we can remove it from the map to save space.
        if value.eq(&self.get_zero_hash_for_level(key.level)) {
            self.nodes.remove(&key);
        } else {
            self.nodes.insert(key, value);
        }
    }
    
    #[inline]
    fn get_node_value(&self, key: &SimpleMerkleNodeKey) -> Hash {
        match self.nodes.get(key) {
            Some(v) => *v,
            None => self.get_zero_hash_for_level(key.level),
        }
    }

}



// --- Test Setup ---
#[cfg(test)]
mod tests {
    use super::*; // Import everything from the parent module
    use anyhow::Result;
    use parth_core::{crypto::hash::merkle_proof::{verify_delta_merkle_proof_core, verify_merkle_proof_core}, data::hash::hash256::Hash256, utils::QPGenRandom};
    use parth_crypto::hash::sha256::CoreSha256Hasher;

    // Concrete types for testing
    type TestHash = Hash256;
    type TestHasher = CoreSha256Hasher;
    type TestMerkleStore = PsyDashMemoryAppendOnlyMerkleStore<TestHasher, TestHash>;

    // Helper functions for generating test data
    fn gen_random_hash() -> TestHash {
        TestHash::qp_rand_gen()
    }

    fn gen_random_hashes(count: usize) -> Vec<TestHash> {
        TestHash::qp_rand_gen_vec(count)
    }

    // --- Unit Tests ---

    #[test]
    fn test_new_store() {
        let height = 10;
        let store = TestMerkleStore::new(height);
        assert_eq!(store.get_height(), height);
        assert_eq!(store.get_max_leaf_index(), (1 << height) - 1);
        
        // The root of a new tree should be the zero hash for its height
        let expected_root = TestHasher::get_zero_hash(height as usize);
        assert_eq!(store.get_root(), expected_root);
    }

    #[test]
    fn test_set_and_get_node() {
        let store = TestMerkleStore::new(8);
        let key = SimpleMerkleNodeKey::new(8, 5); // A leaf node
        let value = gen_random_hash();

        // Get value before setting (should be zero hash)
        assert_eq!(store.get_node_value(&key), TestHasher::get_zero_hash(0));

        // Set and get
        store.set_node_value(key, value);
        assert_eq!(store.get_node_value(&key), value);

        // Setting a node to its level's zero hash should remove it from the map
        let zero_leaf_hash = TestHasher::get_zero_hash(0);
        store.set_node_value(key, zero_leaf_hash);
        assert_eq!(store.get_node_value(&key), zero_leaf_hash);
        assert!(!store.nodes.contains_key(&key), "Node should be removed when set to zero hash");
    }

    #[test]
    fn test_set_leaf_and_verify_proof() {
        let height = 4;
        let store = TestMerkleStore::new(height);
        let leaf_index = 5;
        let leaf_value = gen_random_hash();

        let old_root = store.get_root();
        let old_value = store.get_leaf_value(leaf_index);

        let dmp = store.set_leaf(leaf_index, leaf_value);

        // Verify the DeltaMerkleProofCore
        assert_eq!(dmp.index, leaf_index);
        assert_eq!(dmp.old_root, old_root);
        assert_eq!(dmp.new_value, leaf_value);
        assert_eq!(dmp.old_value, old_value);
        assert_ne!(dmp.new_root, old_root);
        assert!(verify_delta_merkle_proof_core::<TestHash, TestHasher>(&dmp));
        
        // Verify the store's state
        assert_eq!(store.get_root(), dmp.new_root);
        assert_eq!(store.get_leaf_value(leaf_index), leaf_value);
    }

    #[test]
    fn test_get_leaf_proof() {
        let height = 5;
        let store = TestMerkleStore::new(height);
        let leaf_index = 12;
        let leaf_value = gen_random_hash();
        store.set_leaf(leaf_index, leaf_value);

        // Get proof for the set leaf
        let proof = store.get_leaf(leaf_index);
        assert_eq!(proof.index, leaf_index);
        assert_eq!(proof.value, leaf_value);
        assert_eq!(proof.root, store.get_root());
        assert_eq!(proof.siblings.len(), height as usize);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));

        // Get proof for an empty leaf
        let empty_leaf_index = 13;
        let empty_proof = store.get_leaf(empty_leaf_index);
        assert_eq!(empty_proof.index, empty_leaf_index);
        assert_eq!(empty_proof.value, TestHasher::get_zero_hash(0));
        assert_eq!(empty_proof.root, store.get_root());
        assert_eq!(empty_proof.siblings.len(), height as usize);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&empty_proof));
    }

    #[test]
    fn test_find_next_append_index() {
        let height = 3; // 8 leaves max
        let store = TestMerkleStore::new(height);
        
        assert_eq!(store.find_next_append_index().unwrap(), 0);
        
        store.set_leaf(0, gen_random_hash());
        assert_eq!(store.find_next_append_index().unwrap(), 1);

        store.set_leaf(1, gen_random_hash());
        store.set_leaf(2, gen_random_hash());
        assert_eq!(store.find_next_append_index().unwrap(), 3);
        
        // Fill the tree
        for i in 3..8 {
            store.set_leaf(i, gen_random_hash());
        }
        assert!(store.find_next_append_index().is_err()); // This is out of bounds, but indicates the next *slot*
        
        // An append of 1 would fail, but the *index* exists conceptually.
        // A truly full tree (where the next index > max_leaves) should error
        let full_store = TestMerkleStore::new(1); // 2 leaves max
        full_store.set_leaf(0, gen_random_hash());
        full_store.set_leaf(1, gen_random_hash());
        assert!(full_store.find_next_append_index().is_err(), "Should fail on a full tree");
    }

    #[test]
    fn test_rehash_sub_tree() {
        let height = 6; // 64 leaves
        let sub_tree_height = 4; // 16 leaves per subtree
        let sub_tree_index = 2; // The 3rd subtree (indices 32-47)
        let store = TestMerkleStore::new(height);
        
        // Manually set some leaves without updating hashes
        let leaf1_idx = (sub_tree_index << sub_tree_height) + 3;
        let leaf2_idx = (sub_tree_index << sub_tree_height) + 8;
        let leaf1_val = gen_random_hash();
        let leaf2_val = gen_random_hash();

        store.set_node_value(SimpleMerkleNodeKey::new(height, leaf1_idx), leaf1_val);
        store.set_node_value(SimpleMerkleNodeKey::new(height, leaf2_idx), leaf2_val);
        
        // The root should still be the zero root because we haven't rehashed
        assert_eq!(store.get_root(), TestHasher::get_zero_hash(height as usize));
        
        // Now, rehash the subtree
        store.rehash_sub_tree(sub_tree_height, sub_tree_index);

        // The root should now be updated and non-zero
        assert_ne!(store.get_root(), TestHasher::get_zero_hash(height as usize));

        // Verify with a fresh tree
        let expected_store = TestMerkleStore::new(height);
        expected_store.set_leaf(leaf1_idx, leaf1_val);
        expected_store.set_leaf(leaf2_idx, leaf2_val);
        assert_eq!(store.get_root(), expected_store.get_root());
    }

    #[test]
    fn test_spiderman_append_simple() -> Result<()> {
        let height = 8;
        let sub_tree_height = 4; // 16 leaves per sub-tree
        let store = TestMerkleStore::new(height);
        let leaves_to_append = gen_random_hashes(5);

        let old_root = store.get_root();
        let proofs = store.append_leaves_spider_man(sub_tree_height, &leaves_to_append)?;
        
        assert_eq!(proofs.len(), 1);
        let proof = &proofs[0];
        
        // Verify the spiderman proof itself
        assert!(proof.verify::<TestHasher>());
        
        // Check consistency
        assert_eq!(proof.top_line_proof.old_root, old_root);
        assert_eq!(store.get_root(), proof.top_line_proof.new_root);
        assert_eq!(proof.web_proof_old_leaves.len(), 1 << sub_tree_height);
        assert_eq!(proof.web_proof_new_leaves.len(), 1 << sub_tree_height);

        // Check content of the proofs
        for i in 0..leaves_to_append.len() {
            assert_eq!(store.get_leaf_value(i as u64), leaves_to_append[i]);
            assert_eq!(proof.web_proof_new_leaves[i], leaves_to_append[i]);
        }

        Ok(())
    }

    #[test]
    fn test_spiderman_append_across_subtrees() -> Result<()> {
        let height = 8;
        let sub_tree_height = 3; // 8 leaves per sub-tree
        let store = TestMerkleStore::new(height);

        // First, add 5 leaves, partially filling the first sub-tree
        let initial_leaves = gen_random_hashes(5);
        store.append_leaves_spider_man(sub_tree_height, &initial_leaves)?;
        assert_eq!(store.find_next_append_index()?, 5);
        let root_after_first_append = store.get_root();

        // Now append 10 more leaves. This will fill the first sub-tree (3 slots),
        // fill the second sub-tree (8 slots), and spill into the third (1 slot).
        // Expected proofs: 2 (one for sub-tree 0, one for sub-tree 1)
        // Wait, the logic is simpler: one for sub-tree 0, one for 1, one for 2. 3 proofs.
        let leaves_to_append = gen_random_hashes(10);
        let proofs = store.append_leaves_spider_man(sub_tree_height, &leaves_to_append)?;

        assert_eq!(proofs.len(), 2, "Should span 2 subtrees: 3 leaves in first, 7 in second");

        // --- Verify Proof 1 (sub-tree index 0) ---
        let proof1 = &proofs[0];
        assert!(proof1.verify::<TestHasher>());
        assert_eq!(proof1.top_line_proof.old_root, root_after_first_append);
        assert_eq!(proof1.web_proof_old_leaves[0..5], initial_leaves); // Existing leaves
        let expected_new_leaves_1 = [&initial_leaves[..], &leaves_to_append[0..3]].concat();
        assert_eq!(proof1.web_proof_new_leaves[0..8], expected_new_leaves_1);

        // --- Verify Proof 2 (sub-tree index 1) ---
        let proof2 = &proofs[1];
        assert!(proof2.verify::<TestHasher>());
        assert_eq!(proof2.top_line_proof.old_root, proof1.top_line_proof.new_root);
        let zero_hash = TestHasher::get_zero_hash(0);
        assert!(proof2.web_proof_old_leaves.iter().all(|&h| h == zero_hash)); // Was empty
        assert_eq!(proof2.web_proof_new_leaves[0..7], leaves_to_append[3..10]);
        
        // --- Verify final store state ---
        assert_eq!(store.get_root(), proof2.top_line_proof.new_root);
        assert_eq!(store.find_next_append_index()?, 15);
        
        // Check some leaf values
        assert_eq!(store.get_leaf_value(4), initial_leaves[4]); // old
        assert_eq!(store.get_leaf_value(5), leaves_to_append[0]); // new
        assert_eq!(store.get_leaf_value(14), leaves_to_append[9]); // new

        Ok(())
    }


    #[test]
    fn test_historical_append() -> anyhow::Result<()> {
        let height = 32;
        let store = TestMerkleStore::new(height);
        let count = 100;
        let leaves_to_append = gen_random_hashes(count);
        for (i, leaf) in leaves_to_append.iter().enumerate() {
            for n in 0..i {
                let historical_proof = store.get_historical_merkle_proof_at_historical_index(n as u64, i as u64);
                assert_eq!(historical_proof.verify::<TestHasher>(), true, "Failed to verify historical proof for leaf index {} at historical index {}", n, i);
            }
            let res = store.append_leaf(i as u64, *leaf)?;
            assert_eq!(res.verify::<TestHasher>(), true, "Failed to verify delta merkle proof for appended leaf at index {}", i);
            for n in 0..i {
                let historical_proof = store.get_historical_merkle_proof_at_historical_index(n as u64, i as u64);
                assert_eq!(historical_proof.verify::<TestHasher>(), true, "Failed to verify historical proof for leaf index {} at historical index {}", n, i);
            }
        }
        for i in 0..count {
            for n in 0..i {
                let historical_proof = store.get_historical_merkle_proof_at_historical_index(n as u64, i as u64);
                assert_eq!(historical_proof.verify::<TestHasher>(), true, "Failed to verify historical proof for leaf index {} at historical index {}", n, i);
            }
        }
        Ok(())
    }
    // --- Scenario Test ---

    #[test]
    fn test_full_lifecycle_scenario() -> Result<()> {
        let height = 8;
        let sub_tree_height = 4; // 16 leaves per sub-tree
        let store = TestMerkleStore::new(height);

        // 1. Initial State
        println!("Step 1: Initial State Verification");
        assert_eq!(store.get_root(), TestHasher::get_zero_hash(height as usize));
        assert_eq!(store.find_next_append_index()?, 0);

        // 2. Append initial set of leaves
        println!("Step 2: Append 10 initial leaves");
        let initial_leaves = gen_random_hashes(10);
        let sp_proofs1 = store.append_leaves_spider_man(sub_tree_height, &initial_leaves)?;
        assert_eq!(sp_proofs1.len(), 1);
        assert!(sp_proofs1[0].verify::<TestHasher>());
        let root1 = store.get_root();
        assert_ne!(root1, TestHasher::get_zero_hash(height as usize));
        assert_eq!(store.find_next_append_index()?, 10);
        
        // 3. Get a proof for one of the leaves
        println!("Step 3: Get and verify a leaf proof");
        let leaf_to_check_idx = 7;
        let leaf_proof = store.get_leaf(leaf_to_check_idx);
        assert_eq!(leaf_proof.value, initial_leaves[leaf_to_check_idx as usize]);
        assert_eq!(leaf_proof.root, root1);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&leaf_proof));

        // 4. Update that leaf
        println!("Step 4: Update a leaf");
        let new_value = gen_random_hash();
        let dmp = store.set_leaf(leaf_to_check_idx, new_value);
        assert!(verify_delta_merkle_proof_core::<TestHash, TestHasher>(&dmp));
        assert_eq!(dmp.old_root, root1);
        assert_eq!(dmp.old_value, initial_leaves[leaf_to_check_idx as usize]);
        assert_eq!(dmp.new_value, new_value);
        let root2 = store.get_root();
        assert_ne!(root1, root2);
        assert_eq!(dmp.new_root, root2);

        // 5. Get a new proof for the updated leaf
        println!("Step 5: Verify state after update");
        let updated_leaf_proof = store.get_leaf(leaf_to_check_idx);
        assert_eq!(updated_leaf_proof.value, new_value);
        assert_eq!(updated_leaf_proof.root, root2);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&updated_leaf_proof));

        // 6. Append more leaves, crossing a sub-tree boundary
        println!("Step 6: Append more leaves across sub-tree boundary");
        // We are at index 10. sub-tree size is 16. We need 6 to fill, then more.
        let more_leaves = gen_random_hashes(15); // Will go from index 10 to 24
        let sp_proofs2 = store.append_leaves_spider_man(sub_tree_height, &more_leaves)?;
        assert_eq!(sp_proofs2.len(), 2);
        assert!(sp_proofs2[0].verify::<TestHasher>());
        assert!(sp_proofs2[1].verify::<TestHasher>());
        
        // Check proof chain consistency
        assert_eq!(sp_proofs2[0].top_line_proof.old_root, root2);
        assert_eq!(sp_proofs2[1].top_line_proof.old_root, sp_proofs2[0].top_line_proof.new_root);

        let root3 = store.get_root();
        assert_eq!(root3, sp_proofs2[1].top_line_proof.new_root);
        assert_eq!(store.find_next_append_index()?, 25);

        // Final check of a leaf from the last append
        assert_eq!(store.get_leaf_value(24), *more_leaves.last().unwrap());

        println!("Scenario test completed successfully!");
        Ok(())
    }

    #[test]
    fn test_historical_merkle_proof_full_consistency() -> Result<()> {
        let height = 16;
        let store = TestMerkleStore::new(height);
        let count = 1000u64;

        // Generate random leaf
        let leaves = gen_random_hashes(count as usize);
        for (i, leaf) in leaves.iter().enumerate() {
            store.append_leaf(i as u64, *leaf)?;
        }

        // ========================
        // 1. Basic consistency
        // ========================
        let checkpoint = count - 2;
        let base_root = store.get_historical_merkle_proof_at_historical_index(0, checkpoint).root;

        for i in 0..=checkpoint {
            let p = store.get_historical_merkle_proof_at_historical_index(i, checkpoint);
            assert_eq!(p.root, base_root, "Base consistency mismatch at i={}", i);
        }

        // ========================
        // 2. Boundary index test
        // ========================
        let checkpoints = [0, 1, 2, 3, 7, 15, 31, 63, 86, 128, 511, 999, count - 1];
        for &cp in &checkpoints {
            let root = store.get_historical_merkle_proof_at_historical_index(cp, cp).root;
            // leftmost
            assert_eq!(store.get_historical_merkle_proof_at_historical_index(0, cp).root, root);
            // rightmost
            assert_eq!(store.get_historical_merkle_proof_at_historical_index(cp, cp).root, root);
        }

        // ========================
        // 3. Check root changes across checkpoints
        // ========================
        let root1 = store.get_historical_merkle_proof_at_historical_index(0, 40).root;
        let root2 = store.get_historical_merkle_proof_at_historical_index(0, 60).root;
        assert_ne!(root1, root2, "Roots should differ across checkpoints");

        // ========================
        // 4. Replay Oracle comparison
        // ========================
        let replay_checkpoints = [10, 20, 33, 64, 89, 299, 512, 999];   
        for &cp in &replay_checkpoints {
            let replay = TestMerkleStore::new(height);
            for i in 0..=cp {
                replay.append_leaf(i, leaves[i as usize])?;
            }
            let replay_root = replay.get_root();
            for i in 0..=cp {
                let p = store.get_historical_merkle_proof_at_historical_index(i, cp);
                assert_eq!(p.root, replay_root, "Replay root mismatch at checkpoint={}, index={}", cp, i);
            }
        }

        // ========================
        // 5. Random fuzz testing
        // ========================
        for _ in 0..5000 {
            let checkpoint = rand::random::<u64>() % count;
            let index = rand::random::<u64>() % (checkpoint + 1);
            let p = store.get_historical_merkle_proof_at_historical_index(index, checkpoint);

            let replay = TestMerkleStore::new(height);
            for i in 0..=checkpoint {
                replay.append_leaf(i, leaves[i as usize])?;
            }
            assert_eq!(
                p.root,
                replay.get_root(),
                "Fuzz root mismatch at checkpoint={}, index={}",
                checkpoint,
                index
            );
        }

        Ok(())
    }
}
