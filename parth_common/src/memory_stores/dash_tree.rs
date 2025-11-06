use dashmap::DashMap;
use parth_core::{crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher}, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use std::marker::PhantomData;

use crate::memory_stores::traits::PsyMemoryMerkleStoreImm;

// --- Start of Refactored Code ---

#[derive(Debug, Clone)]
pub struct PsyDashMemoryMerkleStore<Hasher, Hash: Copy + PartialEq + Default> {
    nodes: DashMap<SimpleMerkleNodeKey, Hash>,
    height: u8,
    /// Pre-computed hashes for empty subtrees of a given height.
    /// `zero_value_hashes[h]` is the hash of an empty tree of height `h`.
    zero_value_hashes: Vec<Hash>,
    _hasher: PhantomData<Hasher>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug>
    PsyDashMemoryMerkleStore<Hasher, Hash>
{
    pub fn new(height: u8) -> Self {
        let zero_value_hashes = (0..=height)
            .map(|h| Hasher::get_zero_hash(h as usize))
            .collect();

        Self {
            nodes: DashMap::new(),
            height,
            zero_value_hashes,
            _hasher: PhantomData::default(),
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
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug> PsyMemoryMerkleStoreImm<Hasher, Hash> for
    PsyDashMemoryMerkleStore<Hasher, Hash>
{

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


/// PERFORMANCE: This function was very inefficient because it called `set_leaf` in a loop,
/// causing N full re-hashes of the tree.
/// This version sets all nodes first, then generates proofs, requiring only one logical "re-hash".
pub fn get_merkle_proofs_for_compact_imm<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default + std::fmt::Debug>(
    from_index: u64,
    siblings: &[Hash],
    values: &[Hash],
) -> Vec<MerkleProofCore<Hash>> {
    let height = siblings.len() as u8;
    let tree = PsyDashMemoryMerkleStore::<Hasher, Hash>::new(height);
    
    // 1. Set up the sibling path.
    let mut current_key = SimpleMerkleNodeKey::new(height, from_index);
    for sibling_hash in siblings {
        tree.set_node_value(current_key.sibling(), *sibling_hash);
        current_key = current_key.parent();
    }
    
    // 2. Set all the leaf values.
    for (i, value) in values.iter().enumerate() {
        tree.set_node_value(SimpleMerkleNodeKey::new(height, from_index + i as u64), *value);
    }
    
    // 3. Re-hash all affected paths. Since `set_leaf` isn't used, we do it manually.
    //    The most straightforward way is to rehash from each leaf.
    for i in 0..values.len() {
        tree.rehash_from_node_to_level(SimpleMerkleNodeKey::new(height, from_index + i as u64), 0);
    }

    // 4. Now that the tree is in its final state, generate all proofs.
    (0..values.len())
        .map(|i| tree.get_leaf(from_index + i as u64))
        .collect()
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
    type TestMerkleStore = PsyDashMemoryMerkleStore<TestHasher, TestHash>;

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
    fn test_get_merkle_proofs_for_compact() {
        let height = 5;
        let from_index = 10;
        let values = gen_random_hashes(4);
        
        // Generate a valid sibling path from a temporary full tree
        let temp_store = TestMerkleStore::new(height);
        temp_store.set_leaf(from_index - 1, gen_random_hash()); // Set a neighbour to ensure siblings are non-zero
        let proof_for_siblings = temp_store.get_leaf(from_index);
        let siblings = proof_for_siblings.siblings;

        // The function being tested
        let proofs = get_merkle_proofs_for_compact_imm::<TestHasher, TestHash>(from_index, &siblings, &values);
        
        assert_eq!(proofs.len(), values.len());

        let final_root = proofs.last().unwrap().root;

        for (i, proof) in proofs.iter().enumerate() {
            assert_eq!(proof.index, from_index + i as u64);
            assert_eq!(proof.value, values[i]);
            assert_eq!(proof.root, final_root, "All proofs in a compact set must have the same root");
            assert!(verify_merkle_proof_core::<TestHash, TestHasher>(proof));
        }
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
}