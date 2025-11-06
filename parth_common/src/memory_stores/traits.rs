use anyhow::bail;
use parth_core::{crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, data::hash::merkle_node_key::SimpleMerkleNodeKey};


pub trait PsyMemoryMerkleStoreImm<Hasher: MerkleZeroHasher<Hash>, Hash: Copy + PartialEq + Default>
{

    fn get_height(&self) -> u8;
    fn get_zero_hash_for_level(&self, level: u8) -> Hash;
    fn set_node_value(&self, key: SimpleMerkleNodeKey, value: Hash);
    fn get_node_value(&self, key: &SimpleMerkleNodeKey) -> Hash;

    #[inline]
    fn get_max_leaf_index(&self) -> u64 {
        (1u64 << self.get_height()) - 1
    }

    #[inline]
    fn get_root(&self) -> Hash {
        self.get_node_value(&SimpleMerkleNodeKey::new_root())
    }

    #[inline]
    fn get_leaf_value(&self, index: u64) -> Hash {
        self.get_node_value(&SimpleMerkleNodeKey::new(self.get_height(), index))
    }

    fn get_leaf(&self, index: u64) -> MerkleProofCore<Hash> {
        let leaf_key = SimpleMerkleNodeKey::new(self.get_height(), index);
        let value = self.get_node_value(&leaf_key);

        let mut siblings = Vec::with_capacity(self.get_height() as usize);
        let mut current_key = leaf_key;

        while current_key.level > 0 {
            siblings.push(self.get_node_value(&current_key.sibling()));
            current_key = current_key.parent();
        }

        let root = self.get_node_value(&current_key);

        MerkleProofCore { index, siblings, root, value }
    }

    /// BUG FIX & REFACTOR:
    /// Renamed from `find_first_non_zero_leaf` to be accurate.
    /// Finds the index of the first-from-left leaf that is a zero-value node.
    /// This is used to find where to append new leaves.
    fn find_first_zero_leaf_index(&self, node: SimpleMerkleNodeKey) -> Option<u64> {
        // If the current node is an empty subtree, its first leaf is the target.
        if self.get_node_value(&node) == self.get_zero_hash_for_level(node.level) {
            return Some(node.first_leaf_child(self.get_height()).index);
        }

        // If we are at a non-zero leaf, this path is full.
        if node.level == self.get_height() {
            return None;
        }

        // Recurse: check left child first, then right.
        self.find_first_zero_leaf_index(node.left_child())
            .or_else(|| self.find_first_zero_leaf_index(node.right_child()))
    }

    fn find_next_append_index(&self) -> anyhow::Result<u64> {
        self.find_first_zero_leaf_index(SimpleMerkleNodeKey::new_root())
            .ok_or_else(|| anyhow::anyhow!("tree is full"))
    }
    
    /// Updates hashes from a starting node up to a specified level.
    fn rehash_from_node_to_level(&self, mut node: SimpleMerkleNodeKey, stop_level: u8) {
        while node.level > stop_level {
            let sibling_value = self.get_node_value(&node.sibling());
            let node_value = self.get_node_value(&node);

            let (left, right) = if node.index & 1 == 0 {
                (node_value, sibling_value) // Node is a left child
            } else {
                (sibling_value, node_value) // Node is a right child
            };

            let parent_key = node.parent();
            let parent_value = Hasher::two_to_one(&left, &right);
            self.set_node_value(parent_key, parent_value);
            
            node = parent_key;
        }
    }

    /// REFACTOR & PERFORMANCE:
    /// Rewritten to be recursive, avoiding heap allocations in loops and simplifying logic.
    fn _rehash_recursive(&self, node: SimpleMerkleNodeKey) -> Hash {
        if node.level >= self.get_height() {
            // Base case: leaf node or below. Just return its existing value.
            return self.get_node_value(&node);
        }

        // Recursive step: rehash children, then compute and store this node's hash.
        let left_hash = self._rehash_recursive(node.left_child());
        let right_hash = self._rehash_recursive(node.right_child());

        let new_hash = Hasher::two_to_one(&left_hash, &right_hash);
        self.set_node_value(node, new_hash);
        new_hash
    }

    /// Re-calculates all hashes within a given sub-tree and propagates changes to the root.
    fn rehash_sub_tree(&self, sub_tree_height: u8, sub_tree_index: u64) -> Hash {
        let sub_tree_root_level = self.get_height() - sub_tree_height;
        let sub_root_node = SimpleMerkleNodeKey::new(sub_tree_root_level, sub_tree_index);

        // Recursively re-hash everything within the sub-tree.
        let new_sub_root_hash = self._rehash_recursive(sub_root_node);

        // Propagate the changes from the sub-tree's root up to the main tree root.
        self.rehash_from_node_to_level(sub_root_node, 0);

        new_sub_root_hash
    }

    /// A more efficient way to rehash a sub-tree and get the delta proof.
    fn rehash_sub_tree_dmp(
        &self,
        sub_tree_height: u8,
        sub_tree_index: u64,
    ) -> DeltaMerkleProofCore<Hash> {
        let sub_tree_root_level = self.get_height() - sub_tree_height;
        let sub_root_node = SimpleMerkleNodeKey::new(sub_tree_root_level, sub_tree_index);

        let old_sub_tree_root = self.get_node_value(&sub_root_node);
        let old_tree_root = self.get_root();
        
        // Collect siblings *before* rehashing, as their values might change.
        let siblings = sub_root_node
            .siblings()
            .iter()
            .map(|key| self.get_node_value(key))
            .collect::<Vec<_>>();

        self.rehash_sub_tree(sub_tree_height, sub_tree_index);

        let new_sub_tree_root = self.get_node_value(&sub_root_node);
        let new_tree_root = self.get_root();

        DeltaMerkleProofCore {
            old_root: old_tree_root,
            old_value: old_sub_tree_root,
            new_root: new_tree_root,
            new_value: new_sub_tree_root,
            index: sub_tree_index,
            siblings,
        }
    }
    
    /// Updates a slice of leaves within a sub-tree and re-hashes it.
    fn update_sub_tree(
        &self,
        sub_tree_height: u8,
        sub_tree_index: u64,
        sub_tree_offset: u64,
        values: &[Hash],
    ) -> anyhow::Result<Hash> {
        let leaves_per_sub_tree = 1u64 << sub_tree_height;
        if sub_tree_offset + (values.len() as u64) > leaves_per_sub_tree {
            bail!("update exceeds sub-tree bounds");
        }
        
        let start_index = (leaves_per_sub_tree * sub_tree_index) + sub_tree_offset;
        for (i, v) in values.iter().enumerate() {
            let key = SimpleMerkleNodeKey::new(self.get_height(), start_index + i as u64);
            self.set_node_value(key, *v);
        }

        Ok(self.rehash_sub_tree(sub_tree_height, sub_tree_index))
    }

    /// Sets all leaves of a sub-tree and returns the delta proof.
    fn set_sub_tree_dmp(
        &self,
        sub_tree_height: u8,
        sub_tree_index: u64,
        leaves: &[Hash],
    ) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        let max_leaves = 1usize << sub_tree_height;
        if leaves.len() > max_leaves {
            bail!("cannot set more leaves than can fit in a subtree");
        }

        let offset_index = (1u64 << sub_tree_height) * sub_tree_index;
        for i in 0..max_leaves {
            // Use the provided leaf if available, otherwise use the zero hash.
            let value = leaves.get(i).copied().unwrap_or_else(|| self.get_zero_hash_for_level(self.get_height()));
            let key = SimpleMerkleNodeKey::new(self.get_height(), offset_index + i as u64);
            self.set_node_value(key, value);
        }

        Ok(self.rehash_sub_tree_dmp(sub_tree_height, sub_tree_index))
    }

    /// REFACTOR & SIMPLIFICATION:
    /// The original implementation was extremely complex and hard to follow.
    /// This version is unified into a single, clear loop.
    fn append_leaves_spider_man(
        &self,
        sub_tree_height: u8,
        leaves_to_append: &[Hash],
    ) -> anyhow::Result<Vec<SpidermanUpdateProof<Hash>>> {
        if leaves_to_append.is_empty() {
            return Ok(Vec::new());
        }

        let leaves_per_subtree = 1usize << sub_tree_height;
        let max_leaves = 1u64 << self.get_height();
        let append_index = self.find_next_append_index()?;

        if append_index + leaves_to_append.len() as u64 > max_leaves {
            bail!("tree cannot fit an additional {} leaves", leaves_to_append.len());
        }

        let mut results = Vec::new();
        let mut leaves_remaining = leaves_to_append;

        // --- Handle the first sub-tree (which may be partially filled) ---
        let mut current_subtree_idx = append_index / leaves_per_subtree as u64;
        let leaf_idx_in_subtree = (append_index % leaves_per_subtree as u64) as usize;

        let mut old_leaves = Vec::with_capacity(leaves_per_subtree);
        let mut new_leaves = Vec::with_capacity(leaves_per_subtree);
        let zero_leaf_hash = self.get_zero_hash_for_level(self.get_height());
        
        // Populate existing leaves for the first sub-tree
        let subtree_start_leaf = current_subtree_idx * leaves_per_subtree as u64;
        for i in 0..leaf_idx_in_subtree {
            let val = self.get_leaf_value(subtree_start_leaf + i as u64);
            old_leaves.push(val);
            new_leaves.push(val);
        }

        // Fill the rest of `old_leaves` with zero hashes
        old_leaves.resize(leaves_per_subtree, zero_leaf_hash);

        // Add new leaves to the first sub-tree
        let space_in_first_subtree = leaves_per_subtree - leaf_idx_in_subtree;
        let (first_chunk, rest) = leaves_remaining.split_at(std::cmp::min(space_in_first_subtree, leaves_remaining.len()));
        new_leaves.extend_from_slice(first_chunk);
        new_leaves.resize(leaves_per_subtree, zero_leaf_hash); // Pad with zeros if needed

        results.push(SpidermanUpdateProof {
            top_line_proof: self.set_sub_tree_dmp(sub_tree_height, current_subtree_idx, &new_leaves)?,
            web_proof_old_leaves: old_leaves.clone(), // `old_leaves` is now all zeros for subsequent iterations
            web_proof_new_leaves: new_leaves,
        });

        leaves_remaining = rest;
        current_subtree_idx += 1;

        // --- Handle subsequent full and final partial sub-trees ---
        old_leaves.fill(zero_leaf_hash); // All subsequent old sub-trees are empty

        for new_leaves_chunk in leaves_remaining.chunks(leaves_per_subtree) {
            let mut new_leaves = new_leaves_chunk.to_vec();
            new_leaves.resize(leaves_per_subtree, zero_leaf_hash);

            results.push(SpidermanUpdateProof {
                top_line_proof: self.set_sub_tree_dmp(sub_tree_height, current_subtree_idx, &new_leaves)?,
                web_proof_old_leaves: old_leaves.clone(),
                web_proof_new_leaves: new_leaves,
            });
            current_subtree_idx += 1;
        }

        Ok(results)
    }

    /// Updates a single leaf and returns a proof of the change.
    fn set_leaf(&self, index: u64, value: Hash) -> DeltaMerkleProofCore<Hash> {
        let leaf_key = SimpleMerkleNodeKey::new(self.get_height(), index);
        
        // Get old state before making changes
        let old_value = self.get_leaf_value(index);
        let old_root = self.get_root();

        let mut siblings = Vec::with_capacity(self.get_height() as usize);
        let mut current_key = leaf_key;
        while current_key.level > 0 {
            siblings.push(self.get_node_value(&current_key.sibling()));
            current_key = current_key.parent();
        }

        // Set the new leaf value
        self.set_node_value(leaf_key, value);
        
        // Re-hash up the tree from the changed leaf
        self.rehash_from_node_to_level(leaf_key, 0);

        let new_root = self.get_root();

        DeltaMerkleProofCore {
            old_root,
            old_value,
            new_root,
            new_value: value,
            siblings,
            index,
        }
    }
}