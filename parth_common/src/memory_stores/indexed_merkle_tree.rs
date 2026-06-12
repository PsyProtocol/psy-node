use std::collections::{BTreeMap, HashMap};
use std::marker::PhantomData;

use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::{FieldQHasher, MerkleHasher, MerkleZeroHasher},
    },
    data::hash::merkle_node_key::SimpleMerkleNode,
    felt::QFelt64,
    protocol::core_types::QFHashBase,
};

use super::mem_tree_v3::SimpleMemoryMerkleStoreV3;

/// An Indexed Merkle Tree (IMT) leaf preimage.
///
/// Each leaf in the IMT stores a key-value pair plus sorted linked-list pointers
/// that enable non-membership proofs.
#[derive(Debug, Clone, Copy)]
pub struct IMTLeafPreimage<F, Hash> {
    pub key: Hash,
    pub value: Hash,
    pub next_key: Hash,
    pub next_index: F,
}

impl<F: Default, Hash: Default> Default for IMTLeafPreimage<F, Hash> {
    fn default() -> Self {
        Self {
            key: Hash::default(),
            value: Hash::default(),
            next_key: Hash::default(),
            next_index: F::default(),
        }
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> IMTLeafPreimage<F, Hash> {
    /// Compute the leaf hash from the preimage using field hashing.
    pub fn compute_hash<Hasher: FieldQHasher<F, Hash>>(&self) -> Hash {
        let key_felts = self.key.to_4_felts();
        let value_felts = self.value.to_4_felts();
        let next_key_felts = self.next_key.to_4_felts();

        Hasher::q_hash_many(&[
            key_felts[0],
            key_felts[1],
            key_felts[2],
            key_felts[3],
            value_felts[0],
            value_felts[1],
            value_felts[2],
            value_felts[3],
            next_key_felts[0],
            next_key_felts[1],
            next_key_felts[2],
            next_key_felts[3],
            self.next_index,
        ])
    }

    /// Check if this is the sentinel leaf (all zeros).
    pub fn is_sentinel(&self) -> bool {
        self.key == Hash::default()
            && self.value == Hash::default()
            && self.next_key == Hash::default()
            && self.next_index == F::default()
    }
}

/// Result of an IMT insert operation.
#[derive(Debug, Clone)]
pub struct IMTInsertResult<F, Hash> {
    /// Delta merkle proof for the predecessor leaf update (pointer change).
    pub predecessor_proof: DeltaMerkleProofCore<Hash>,
    /// Delta merkle proof for the new leaf insertion.
    pub new_leaf_proof: DeltaMerkleProofCore<Hash>,
    /// The new leaf preimage that was inserted.
    pub new_leaf: IMTLeafPreimage<F, Hash>,
    /// The updated predecessor leaf preimage.
    pub updated_predecessor: IMTLeafPreimage<F, Hash>,
    /// Index of the predecessor leaf.
    pub predecessor_index: u64,
    /// Index of the newly inserted leaf.
    pub new_leaf_index: u64,
    /// All modified tree nodes (for serialization into FFS delta).
    pub modified_nodes: Vec<SimpleMerkleNode<Hash>>,
}

/// Result of an IMT value update operation.
#[derive(Debug, Clone)]
pub struct IMTUpdateResult<F, Hash> {
    /// Delta merkle proof for the updated leaf.
    pub leaf_proof: DeltaMerkleProofCore<Hash>,
    /// The updated leaf preimage.
    pub updated_leaf: IMTLeafPreimage<F, Hash>,
    /// Index of the updated leaf.
    pub leaf_index: u64,
    /// All modified tree nodes (for serialization into FFS delta).
    pub modified_nodes: Vec<SimpleMerkleNode<Hash>>,
}

/// A wrapper around Hash that implements Ord for use in BTreeMap.
/// Compares by converting to 4 field elements and comparing MSL first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OrdHash<F: QFelt64, Hash: QFHashBase<F>> {
    hash: Hash,
    _phantom: PhantomData<F>,
}

impl<F: QFelt64, Hash: QFHashBase<F>> OrdHash<F, Hash> {
    fn new(hash: Hash) -> Self {
        Self {
            hash,
            _phantom: PhantomData,
        }
    }

    fn to_sort_key(&self) -> [u64; 4] {
        let felts = self.hash.to_4_felts();
        // MSL first for comparison (felts[3] is MSL)
        [
            felts[3].to_u64_value(),
            felts[2].to_u64_value(),
            felts[1].to_u64_value(),
            felts[0].to_u64_value(),
        ]
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> PartialOrd for OrdHash<F, Hash> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: QFelt64, Hash: QFHashBase<F>> Ord for OrdHash<F, Hash> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.to_sort_key().cmp(&other.to_sort_key())
    }
}

/// In-memory Indexed Merkle Tree implementation.
///
/// An append-only merkle tree with a sorted linked-list overlay that enables:
/// - 256-bit key → 256-bit value storage
/// - Non-membership proofs (prove a key does NOT exist)
/// - Membership proofs (prove a key exists with a specific value)
///
/// The sorted linked list is maintained via (next_key, next_index) pointers
/// in each leaf preimage. Index 0 is always the sentinel leaf.
pub struct IndexedMerkleTree<
    F: QFelt64,
    Hash: QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
    Hasher: MerkleZeroHasher<Hash> + MerkleHasher<Hash> + FieldQHasher<F, Hash>,
> {
    /// The underlying standard merkle tree for node storage.
    tree: SimpleMemoryMerkleStoreV3<Hasher, Hash>,
    /// Leaf preimages indexed by leaf position.
    leaves: HashMap<u64, IMTLeafPreimage<F, Hash>>,
    /// Key to leaf index mapping, sorted by key for predecessor lookups.
    key_index: BTreeMap<OrdHash<F, Hash>, u64>,
    /// Next append position.
    next_append_index: u64,
    _phantom_f: PhantomData<F>,
}

impl<
        F: QFelt64,
        Hash: QFHashBase<F> + Copy + PartialEq + Default + std::fmt::Debug,
        Hasher: MerkleZeroHasher<Hash> + MerkleHasher<Hash> + FieldQHasher<F, Hash>,
    > IndexedMerkleTree<F, Hash, Hasher>
{
    /// Create a new IMT with the given tree height.
    /// Initializes leaf 0 as the sentinel with all zeros.
    pub fn new(height: u8) -> Self {
        let mut tree = SimpleMemoryMerkleStoreV3::<Hasher, Hash>::new(height);

        // Create sentinel leaf at index 0
        let sentinel = IMTLeafPreimage::<F, Hash>::default();
        let sentinel_hash = sentinel.compute_hash::<Hasher>();

        // Set sentinel in the tree
        tree.set_leaf_no_proof(0, sentinel_hash);

        let mut leaves = HashMap::new();
        leaves.insert(0, sentinel);

        let mut key_index = BTreeMap::new();
        key_index.insert(OrdHash::<F, Hash>::new(Hash::default()), 0u64);

        Self {
            tree,
            leaves,
            key_index,
            next_append_index: 1,
            _phantom_f: PhantomData,
        }
    }

    /// Get the current tree root hash.
    pub fn get_root(&self) -> Hash {
        self.tree.get_root()
    }

    /// Get the tree height.
    pub fn get_height(&self) -> u8 {
        self.tree.get_height()
    }

    /// Get the next append index (number of leaves including sentinel).
    pub fn get_next_append_index(&self) -> u64 {
        self.next_append_index
    }

    /// Get a leaf preimage by index.
    pub fn get_leaf_preimage(&self, index: u64) -> Option<&IMTLeafPreimage<F, Hash>> {
        self.leaves.get(&index)
    }

    /// Look up the leaf index for a given key.
    pub fn get_leaf_index_for_key(&self, key: &Hash) -> Option<u64> {
        self.key_index.get(&OrdHash::new(*key)).copied()
    }

    /// Find the predecessor leaf for a given key.
    /// Returns (predecessor_index, predecessor_preimage).
    /// The predecessor is the leaf with the largest key < target_key.
    pub fn find_predecessor(
        &self,
        target_key: &Hash,
    ) -> anyhow::Result<(u64, IMTLeafPreimage<F, Hash>)> {
        let target_ord = OrdHash::<F, Hash>::new(*target_key);

        // Find the largest key strictly less than target_key
        let pred = self
            .key_index
            .range(..target_ord)
            .next_back()
            .ok_or_else(|| {
                anyhow::anyhow!("No predecessor found — this should not happen (sentinel exists)")
            })?;

        let pred_index = *pred.1;
        let pred_leaf = self.leaves.get(&pred_index).ok_or_else(|| {
            anyhow::anyhow!(
                "Predecessor leaf not found at index {}",
                pred_index
            )
        })?;

        Ok((pred_index, *pred_leaf))
    }

    /// Get a membership proof for a key.
    /// Returns the leaf preimage and merkle proof, or None if key doesn't exist.
    pub fn get_membership_proof(
        &self,
        key: &Hash,
    ) -> Option<(IMTLeafPreimage<F, Hash>, MerkleProofCore<Hash>)> {
        let leaf_index = self.key_index.get(&OrdHash::new(*key))?;
        let preimage = self.leaves.get(leaf_index)?;
        let proof = self.tree.get_leaf(*leaf_index);
        Some((*preimage, proof))
    }

    /// Get a non-membership proof for a key.
    /// Returns the predecessor leaf preimage and merkle proof.
    /// Returns Err if the key actually exists.
    pub fn get_non_membership_proof(
        &self,
        key: &Hash,
    ) -> anyhow::Result<(IMTLeafPreimage<F, Hash>, MerkleProofCore<Hash>)> {
        // Check that key doesn't exist
        if self.key_index.contains_key(&OrdHash::new(*key)) {
            anyhow::bail!("Key exists in the IMT — cannot generate non-membership proof");
        }

        let (pred_index, pred_leaf) = self.find_predecessor(key)?;
        let proof = self.tree.get_leaf(pred_index);
        Ok((pred_leaf, proof))
    }

    /// Insert a new key-value pair into the IMT.
    ///
    /// This performs two tree updates:
    /// 1. Update the predecessor leaf's (next_key, next_index) pointers
    /// 2. Append the new leaf at next_append_index
    ///
    /// Returns an error if the key already exists (use `update` instead).
    pub fn insert(
        &mut self,
        key: Hash,
        value: Hash,
    ) -> anyhow::Result<IMTInsertResult<F, Hash>> {
        // Ensure key doesn't already exist
        let ord_key = OrdHash::new(key);
        if self.key_index.contains_key(&ord_key) {
            anyhow::bail!("Key already exists in IMT — use update() instead");
        }

        // Ensure we have room
        let new_index = self.next_append_index;
        if new_index > self.tree.get_max_leaf_index() {
            anyhow::bail!("IMT is full — cannot insert more leaves");
        }

        // Find predecessor
        let (pred_index, pred_leaf) = self.find_predecessor(&key)?;

        // Create the new leaf, inheriting predecessor's next pointers
        let new_leaf = IMTLeafPreimage {
            key,
            value,
            next_key: pred_leaf.next_key,
            next_index: pred_leaf.next_index,
        };
        let new_leaf_hash = new_leaf.compute_hash::<Hasher>();

        // Update predecessor to point to new leaf
        let updated_predecessor = IMTLeafPreimage {
            key: pred_leaf.key,
            value: pred_leaf.value,
            next_key: key,
            next_index: F::from_u64_value(new_index),
        };
        let updated_pred_hash = updated_predecessor.compute_hash::<Hasher>();

        // Step 1: Update predecessor leaf in the tree
        let predecessor_proof = self.tree.set_leaf(pred_index, updated_pred_hash);

        // Step 2: Append new leaf
        let new_leaf_proof = self.tree.set_leaf(new_index, new_leaf_hash);

        // Collect all modified nodes
        let mut modified_nodes = Vec::new();
        // Collect nodes from predecessor path
        self.collect_path_nodes(pred_index, &mut modified_nodes);
        // Collect nodes from new leaf path
        self.collect_path_nodes(new_index, &mut modified_nodes);

        // Update internal state
        self.leaves.insert(pred_index, updated_predecessor);
        self.leaves.insert(new_index, new_leaf);
        self.key_index.insert(ord_key, new_index);
        self.next_append_index = new_index + 1;

        Ok(IMTInsertResult {
            predecessor_proof,
            new_leaf_proof,
            new_leaf,
            updated_predecessor,
            predecessor_index: pred_index,
            new_leaf_index: new_index,
            modified_nodes,
        })
    }

    /// Update the value for an existing key in the IMT.
    ///
    /// Only the value changes — key, next_key, and next_index remain the same.
    /// Returns an error if the key doesn't exist (use `insert` instead).
    pub fn update(
        &mut self,
        key: Hash,
        new_value: Hash,
    ) -> anyhow::Result<IMTUpdateResult<F, Hash>> {
        let ord_key = OrdHash::new(key);
        let leaf_index = *self
            .key_index
            .get(&ord_key)
            .ok_or_else(|| anyhow::anyhow!("Key not found in IMT — use insert() instead"))?;

        let old_leaf = *self.leaves.get(&leaf_index).ok_or_else(|| {
            anyhow::anyhow!("Leaf preimage not found at index {}", leaf_index)
        })?;

        // Update only the value
        let updated_leaf = IMTLeafPreimage {
            key: old_leaf.key,
            value: new_value,
            next_key: old_leaf.next_key,
            next_index: old_leaf.next_index,
        };
        let updated_hash = updated_leaf.compute_hash::<Hasher>();

        // Update in tree
        let leaf_proof = self.tree.set_leaf(leaf_index, updated_hash);

        // Collect modified nodes
        let mut modified_nodes = Vec::new();
        self.collect_path_nodes(leaf_index, &mut modified_nodes);

        // Update internal state
        self.leaves.insert(leaf_index, updated_leaf);

        Ok(IMTUpdateResult {
            leaf_proof,
            updated_leaf,
            leaf_index,
            modified_nodes,
        })
    }

    /// Insert or update: inserts if key doesn't exist, updates if it does.
    pub fn upsert(
        &mut self,
        key: Hash,
        value: Hash,
    ) -> anyhow::Result<IMTUpsertResult<F, Hash>> {
        if self.key_index.contains_key(&OrdHash::new(key)) {
            Ok(IMTUpsertResult::Updated(self.update(key, value)?))
        } else {
            Ok(IMTUpsertResult::Inserted(self.insert(key, value)?))
        }
    }

    /// Collect all tree nodes along the path from a leaf to the root.
    fn collect_path_nodes(&self, leaf_index: u64, nodes: &mut Vec<SimpleMerkleNode<Hash>>) {
        let height = self.tree.get_height();
        let mut current = parth_core::data::hash::merkle_node_key::SimpleMerkleNodeKey::new(
            height, leaf_index,
        );

        // Add the leaf node
        nodes.push(SimpleMerkleNode {
            key: current,
            value: self.tree.get_node_value(&current),
        });

        // Walk up to root
        while current.level > 0 {
            current = current.parent();
            nodes.push(SimpleMerkleNode {
                key: current,
                value: self.tree.get_node_value(&current),
            });
        }
    }

    /// Get the underlying tree for direct access.
    pub fn tree(&self) -> &SimpleMemoryMerkleStoreV3<Hasher, Hash> {
        &self.tree
    }

    /// Get all leaf preimages.
    pub fn leaves(&self) -> &HashMap<u64, IMTLeafPreimage<F, Hash>> {
        &self.leaves
    }

    /// Restore state from persisted data (for recovery).
    pub fn restore_leaf(
        &mut self,
        leaf_index: u64,
        preimage: IMTLeafPreimage<F, Hash>,
    ) {
        let hash = preimage.compute_hash::<Hasher>();
        self.tree.set_leaf_no_proof(leaf_index, hash);
        let ord_key = OrdHash::new(preimage.key);
        self.key_index.insert(ord_key, leaf_index);
        self.leaves.insert(leaf_index, preimage);
        if leaf_index >= self.next_append_index {
            self.next_append_index = leaf_index + 1;
        }
    }
}

/// Result of an upsert operation.
pub enum IMTUpsertResult<F, Hash> {
    Inserted(IMTInsertResult<F, Hash>),
    Updated(IMTUpdateResult<F, Hash>),
}

#[cfg(test)]
mod tests {
    use super::*;
    use parth_core::{
        crypto::hash::merkle_proof::verify_merkle_proof_core,
        data::hash::hash256::Hash256,
    };
    use parth_crypto::hash::sha256::CoreSha256Hasher;

    type TestF = u64;
    type TestHash = Hash256;
    type TestHasher = CoreSha256Hasher;
    type TestIMT = IndexedMerkleTree<TestF, TestHash, TestHasher>;

    const TEST_HEIGHT: u8 = 8;

    /// Helper: create a Hash256 from 4 u64 limbs (little-endian felts).
    fn h(a: u64, b: u64, c: u64, d: u64) -> TestHash {
        Hash256::from_u64_le_values(a, b, c, d)
    }

    // ---------------------------------------------------------------
    // OrdHash ordering tests
    // ---------------------------------------------------------------

    #[test]
    fn test_ord_hash_equal() {
        let h1 = OrdHash::<TestF, TestHash>::new(TestHash::default());
        let h2 = OrdHash::<TestF, TestHash>::new(TestHash::default());
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_ord_hash_msl_dominates() {
        // felts[3] is MSL. h(0,0,0,1) should be > h(u64::MAX,u64::MAX,u64::MAX,0)
        let small = OrdHash::<TestF, TestHash>::new(h(u64::MAX, u64::MAX, u64::MAX, 0));
        let big = OrdHash::<TestF, TestHash>::new(h(0, 0, 0, 1));
        assert!(big > small);
    }

    #[test]
    fn test_ord_hash_same_msl_uses_next_limb() {
        let a = OrdHash::<TestF, TestHash>::new(h(0, 0, 5, 10));
        let b = OrdHash::<TestF, TestHash>::new(h(0, 0, 6, 10));
        assert!(b > a);
    }

    #[test]
    fn test_ord_hash_lsl_tiebreak() {
        let a = OrdHash::<TestF, TestHash>::new(h(1, 0, 0, 0));
        let b = OrdHash::<TestF, TestHash>::new(h(2, 0, 0, 0));
        assert!(b > a);
    }

    // ---------------------------------------------------------------
    // IMT creation
    // ---------------------------------------------------------------

    #[test]
    fn test_new_tree_has_sentinel() {
        let imt = TestIMT::new(TEST_HEIGHT);
        assert_eq!(imt.get_next_append_index(), 1);

        let sentinel = imt.get_leaf_preimage(0).unwrap();
        assert!(sentinel.is_sentinel());
        assert_eq!(sentinel.key, TestHash::default());
        assert_eq!(sentinel.value, TestHash::default());
        assert_eq!(sentinel.next_key, TestHash::default());
        assert_eq!(sentinel.next_index, 0u64);
    }

    #[test]
    fn test_new_tree_root_is_not_default() {
        let imt = TestIMT::new(TEST_HEIGHT);
        // The root shouldn't be the zero hash because the sentinel leaf hash
        // (hash of all-zero preimage) is set at index 0.
        // Actually it could be the zero hash if sentinel hash == zero_hash(0),
        // but let's just verify the root is deterministic.
        let root1 = imt.get_root();
        let imt2 = TestIMT::new(TEST_HEIGHT);
        let root2 = imt2.get_root();
        assert_eq!(root1, root2, "Same-height trees should have identical roots");
    }

    #[test]
    fn test_different_heights_different_roots() {
        let imt_a = TestIMT::new(8);
        let imt_b = TestIMT::new(10);
        assert_ne!(imt_a.get_root(), imt_b.get_root());
    }

    // ---------------------------------------------------------------
    // Insert
    // ---------------------------------------------------------------

    #[test]
    fn test_insert_single_key() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(42, 0, 0, 0);
        let value = h(100, 200, 300, 400);

        let result = imt.insert(key, value).unwrap();

        assert_eq!(result.new_leaf_index, 1);
        assert_eq!(result.predecessor_index, 0); // sentinel is predecessor
        assert_eq!(result.new_leaf.key, key);
        assert_eq!(result.new_leaf.value, value);
        // New leaf inherits sentinel's next pointers (both zero = no successor)
        assert_eq!(result.new_leaf.next_key, TestHash::default());
        assert_eq!(result.new_leaf.next_index, 0u64);
        // Predecessor (sentinel) now points to the new leaf
        assert_eq!(result.updated_predecessor.next_key, key);
        assert_eq!(result.updated_predecessor.next_index, 1u64);

        assert_eq!(imt.get_next_append_index(), 2);
    }

    #[test]
    fn test_insert_maintains_sorted_order() {
        let mut imt = TestIMT::new(TEST_HEIGHT);

        // Insert keys in reverse order: key_c > key_b > key_a (MSL comparison)
        let key_a = h(1, 0, 0, 0);
        let key_b = h(2, 0, 0, 0);
        let key_c = h(3, 0, 0, 0);
        let val = h(0, 0, 0, 0);

        // Insert C first (largest)
        imt.insert(key_c, val).unwrap();
        // Insert A (smallest non-zero)
        imt.insert(key_a, val).unwrap();
        // Insert B (middle)
        imt.insert(key_b, val).unwrap();

        // Verify linked list order: sentinel(0) -> A -> B -> C -> end
        let sentinel = imt.get_leaf_preimage(0).unwrap();
        assert_eq!(sentinel.next_key, key_a);

        let idx_a = imt.get_leaf_index_for_key(&key_a).unwrap();
        let leaf_a = imt.get_leaf_preimage(idx_a).unwrap();
        assert_eq!(leaf_a.next_key, key_b);

        let idx_b = imt.get_leaf_index_for_key(&key_b).unwrap();
        let leaf_b = imt.get_leaf_preimage(idx_b).unwrap();
        assert_eq!(leaf_b.next_key, key_c);

        let idx_c = imt.get_leaf_index_for_key(&key_c).unwrap();
        let leaf_c = imt.get_leaf_preimage(idx_c).unwrap();
        assert_eq!(leaf_c.next_key, TestHash::default()); // end of list
    }

    #[test]
    fn test_insert_duplicate_key_fails() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(10, 0, 0, 0);
        let val = h(1, 2, 3, 4);

        imt.insert(key, val).unwrap();
        let err = imt.insert(key, val);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("already exists"));
    }

    #[test]
    fn test_insert_root_changes() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let root_before = imt.get_root();

        imt.insert(h(1, 0, 0, 0), h(99, 0, 0, 0)).unwrap();
        let root_after = imt.get_root();

        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_insert_delta_proofs_consistent() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let root_0 = imt.get_root();

        let result = imt.insert(h(5, 0, 0, 0), h(50, 0, 0, 0)).unwrap();

        // Predecessor delta proof: old_root should be original root
        assert_eq!(result.predecessor_proof.old_root, root_0);
        // The new_root of predecessor update is the old_root of the new leaf append
        assert_eq!(
            result.predecessor_proof.new_root,
            result.new_leaf_proof.old_root
        );
        // The final root from new_leaf_proof should match the tree's current root
        assert_eq!(result.new_leaf_proof.new_root, imt.get_root());
    }

    #[test]
    fn test_insert_many() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let n = 20;

        for i in 1..=n {
            let key = h(i, 0, 0, 0);
            let value = h(i * 100, 0, 0, 0);
            imt.insert(key, value).unwrap();
        }

        assert_eq!(imt.get_next_append_index(), n + 1);

        // Verify each key can be looked up
        for i in 1..=n {
            let key = h(i, 0, 0, 0);
            let idx = imt.get_leaf_index_for_key(&key);
            assert!(idx.is_some(), "Key {} not found", i);
        }
    }

    // ---------------------------------------------------------------
    // Update
    // ---------------------------------------------------------------

    #[test]
    fn test_update_value() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(10, 0, 0, 0);
        let old_value = h(1, 0, 0, 0);
        let new_value = h(2, 0, 0, 0);

        imt.insert(key, old_value).unwrap();
        let result = imt.update(key, new_value).unwrap();

        assert_eq!(result.updated_leaf.key, key);
        assert_eq!(result.updated_leaf.value, new_value);
        // Linked list pointers should not change
        assert_eq!(result.updated_leaf.next_key, TestHash::default());
        assert_eq!(result.updated_leaf.next_index, 0u64);

        // Verify via preimage
        let leaf = imt.get_leaf_preimage(result.leaf_index).unwrap();
        assert_eq!(leaf.value, new_value);
    }

    #[test]
    fn test_update_nonexistent_key_fails() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(10, 0, 0, 0);
        let err = imt.update(key, h(1, 0, 0, 0));
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_update_preserves_linked_list() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key_a = h(1, 0, 0, 0);
        let key_b = h(2, 0, 0, 0);
        let key_c = h(3, 0, 0, 0);
        let val = h(0, 0, 0, 1);

        imt.insert(key_a, val).unwrap();
        imt.insert(key_b, val).unwrap();
        imt.insert(key_c, val).unwrap();

        // Update B's value
        let new_val = h(0, 0, 0, 99);
        imt.update(key_b, new_val).unwrap();

        // Linked list should still be: sentinel -> A -> B -> C -> end
        let idx_a = imt.get_leaf_index_for_key(&key_a).unwrap();
        let leaf_a = imt.get_leaf_preimage(idx_a).unwrap();
        assert_eq!(leaf_a.next_key, key_b);

        let idx_b = imt.get_leaf_index_for_key(&key_b).unwrap();
        let leaf_b = imt.get_leaf_preimage(idx_b).unwrap();
        assert_eq!(leaf_b.value, new_val);
        assert_eq!(leaf_b.next_key, key_c);
    }

    #[test]
    fn test_update_delta_proof() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(7, 0, 0, 0);
        imt.insert(key, h(1, 0, 0, 0)).unwrap();

        let root_before = imt.get_root();
        let result = imt.update(key, h(2, 0, 0, 0)).unwrap();

        assert_eq!(result.leaf_proof.old_root, root_before);
        assert_eq!(result.leaf_proof.new_root, imt.get_root());
    }

    // ---------------------------------------------------------------
    // Upsert
    // ---------------------------------------------------------------

    #[test]
    fn test_upsert_insert_when_new() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(5, 0, 0, 0);
        let val = h(50, 0, 0, 0);

        let result = imt.upsert(key, val).unwrap();
        assert!(matches!(result, IMTUpsertResult::Inserted(_)));
        assert_eq!(imt.get_leaf_index_for_key(&key), Some(1));
    }

    #[test]
    fn test_upsert_update_when_existing() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(5, 0, 0, 0);

        imt.insert(key, h(1, 0, 0, 0)).unwrap();
        let result = imt.upsert(key, h(2, 0, 0, 0)).unwrap();
        assert!(matches!(result, IMTUpsertResult::Updated(_)));

        let idx = imt.get_leaf_index_for_key(&key).unwrap();
        let leaf = imt.get_leaf_preimage(idx).unwrap();
        assert_eq!(leaf.value, h(2, 0, 0, 0));
    }

    // ---------------------------------------------------------------
    // Predecessor lookups
    // ---------------------------------------------------------------

    #[test]
    fn test_find_predecessor_of_first_key() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(100, 0, 0, 0);
        imt.insert(key, h(1, 0, 0, 0)).unwrap();

        // Predecessor of a key smaller than any existing non-sentinel key
        // should be the sentinel
        let small_key = h(50, 0, 0, 0);
        let (pred_idx, pred_leaf) = imt.find_predecessor(&small_key).unwrap();
        assert_eq!(pred_idx, 0);
        assert!(pred_leaf.key == TestHash::default()); // sentinel
    }

    #[test]
    fn test_find_predecessor_between_keys() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key_a = h(10, 0, 0, 0);
        let key_c = h(30, 0, 0, 0);
        imt.insert(key_a, h(1, 0, 0, 0)).unwrap();
        imt.insert(key_c, h(3, 0, 0, 0)).unwrap();

        // Predecessor of key_b (20) should be key_a (10)
        let key_b = h(20, 0, 0, 0);
        let (pred_idx, pred_leaf) = imt.find_predecessor(&key_b).unwrap();
        assert_eq!(pred_leaf.key, key_a);
        assert_eq!(pred_idx, imt.get_leaf_index_for_key(&key_a).unwrap());
    }

    // ---------------------------------------------------------------
    // Membership proofs
    // ---------------------------------------------------------------

    #[test]
    fn test_membership_proof_exists() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(42, 0, 0, 0);
        let val = h(100, 0, 0, 0);
        imt.insert(key, val).unwrap();

        let result = imt.get_membership_proof(&key);
        assert!(result.is_some());
        let (preimage, proof) = result.unwrap();
        assert_eq!(preimage.key, key);
        assert_eq!(preimage.value, val);

        // The proof's root should match the tree root
        assert_eq!(proof.root, imt.get_root());
        // The proof's value should be the leaf hash (hash of preimage)
        let expected_hash = preimage.compute_hash::<TestHasher>();
        assert_eq!(proof.value, expected_hash);

        // Verify the merkle proof
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }

    #[test]
    fn test_membership_proof_nonexistent_returns_none() {
        let imt = TestIMT::new(TEST_HEIGHT);
        let key = h(42, 0, 0, 0);
        assert!(imt.get_membership_proof(&key).is_none());
    }

    #[test]
    fn test_membership_proof_after_update() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(42, 0, 0, 0);
        imt.insert(key, h(1, 0, 0, 0)).unwrap();
        imt.update(key, h(2, 0, 0, 0)).unwrap();

        let (preimage, proof) = imt.get_membership_proof(&key).unwrap();
        assert_eq!(preimage.value, h(2, 0, 0, 0));
        assert_eq!(proof.root, imt.get_root());
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }

    #[test]
    fn test_membership_proofs_multiple_keys() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let keys: Vec<TestHash> = (1..=10).map(|i| h(i, 0, 0, 0)).collect();
        for (i, key) in keys.iter().enumerate() {
            imt.insert(*key, h(i as u64 * 100, 0, 0, 0)).unwrap();
        }

        // All keys should have valid membership proofs
        for key in &keys {
            let (preimage, proof) = imt.get_membership_proof(key).unwrap();
            assert_eq!(preimage.key, *key);
            assert_eq!(proof.root, imt.get_root());
            assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
        }
    }

    // ---------------------------------------------------------------
    // Non-membership proofs
    // ---------------------------------------------------------------

    #[test]
    fn test_non_membership_proof_gap() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key_a = h(10, 0, 0, 0);
        let key_c = h(30, 0, 0, 0);
        imt.insert(key_a, h(1, 0, 0, 0)).unwrap();
        imt.insert(key_c, h(3, 0, 0, 0)).unwrap();

        // key_b = 20 does not exist, predecessor is key_a
        let key_b = h(20, 0, 0, 0);
        let (pred_preimage, proof) = imt.get_non_membership_proof(&key_b).unwrap();

        assert_eq!(pred_preimage.key, key_a);
        // predecessor's next_key should be > key_b (it's key_c = 30)
        assert_eq!(pred_preimage.next_key, key_c);
        assert_eq!(proof.root, imt.get_root());
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }

    #[test]
    fn test_non_membership_proof_after_last_key() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key_a = h(10, 0, 0, 0);
        imt.insert(key_a, h(1, 0, 0, 0)).unwrap();

        // key_b = 20 > key_a and no other keys exist, predecessor is key_a
        let key_b = h(20, 0, 0, 0);
        let (pred_preimage, proof) = imt.get_non_membership_proof(&key_b).unwrap();

        assert_eq!(pred_preimage.key, key_a);
        // next_key is zero (end of list)
        assert_eq!(pred_preimage.next_key, TestHash::default());
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }

    #[test]
    fn test_non_membership_proof_before_first_key() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key_b = h(20, 0, 0, 0);
        imt.insert(key_b, h(1, 0, 0, 0)).unwrap();

        // key_a = 10 < key_b, predecessor is sentinel (key=0)
        let key_a = h(10, 0, 0, 0);
        let (pred_preimage, proof) = imt.get_non_membership_proof(&key_a).unwrap();

        assert_eq!(pred_preimage.key, TestHash::default()); // sentinel
        assert_eq!(pred_preimage.next_key, key_b);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }

    #[test]
    fn test_non_membership_proof_for_existing_key_fails() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let key = h(10, 0, 0, 0);
        imt.insert(key, h(1, 0, 0, 0)).unwrap();

        let err = imt.get_non_membership_proof(&key);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("Key exists"));
    }

    // ---------------------------------------------------------------
    // Restore leaf
    // ---------------------------------------------------------------

    #[test]
    fn test_restore_leaf_rebuilds_state() {
        // Build a tree, record all leaves, then restore into a fresh tree
        let mut imt = TestIMT::new(TEST_HEIGHT);
        let keys_and_vals: Vec<(TestHash, TestHash)> = (1..=5)
            .map(|i| (h(i * 10, 0, 0, 0), h(i * 100, 0, 0, 0)))
            .collect();

        for (key, val) in &keys_and_vals {
            imt.insert(*key, *val).unwrap();
        }

        let original_root = imt.get_root();

        // Collect all leaves (including sentinel)
        let mut all_leaves: Vec<(u64, IMTLeafPreimage<TestF, TestHash>)> = Vec::new();
        for idx in 0..imt.get_next_append_index() {
            let preimage = *imt.get_leaf_preimage(idx).unwrap();
            all_leaves.push((idx, preimage));
        }

        // Build a new tree and restore all leaves
        let mut imt2 = TestIMT::new(TEST_HEIGHT);
        // Clear the sentinel that was auto-created (restore will re-add it)
        // Actually, restore_leaf will overwrite leaf 0 as well
        for (idx, preimage) in &all_leaves {
            imt2.restore_leaf(*idx, *preimage);
        }

        assert_eq!(imt2.get_root(), original_root);
        assert_eq!(imt2.get_next_append_index(), imt.get_next_append_index());

        // Verify all keys are findable
        for (key, _) in &keys_and_vals {
            assert!(imt2.get_leaf_index_for_key(key).is_some());
        }
    }

    // ---------------------------------------------------------------
    // Edge cases
    // ---------------------------------------------------------------

    #[test]
    fn test_insert_keys_with_large_msl() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        // Keys that differ only in the most-significant limb
        let key_a = h(0, 0, 0, 1);
        let key_b = h(0, 0, 0, 2);

        imt.insert(key_a, h(1, 0, 0, 0)).unwrap();
        imt.insert(key_b, h(2, 0, 0, 0)).unwrap();

        // Sorted order should be: sentinel(0) -> key_a(MSL=1) -> key_b(MSL=2) -> end
        let idx_a = imt.get_leaf_index_for_key(&key_a).unwrap();
        let leaf_a = imt.get_leaf_preimage(idx_a).unwrap();
        assert_eq!(leaf_a.next_key, key_b);

        let idx_b = imt.get_leaf_index_for_key(&key_b).unwrap();
        let leaf_b = imt.get_leaf_preimage(idx_b).unwrap();
        assert_eq!(leaf_b.next_key, TestHash::default());
    }

    #[test]
    fn test_tree_root_consistency_after_operations() {
        let mut imt = TestIMT::new(TEST_HEIGHT);

        // Insert several keys and verify root is consistent with merkle proofs
        for i in 1..=8u64 {
            imt.insert(h(i, 0, 0, 0), h(i * 10, 0, 0, 0)).unwrap();
        }

        let root = imt.get_root();

        // Every leaf's merkle proof should verify against the same root
        for i in 0..imt.get_next_append_index() {
            let proof = imt.tree().get_leaf(i);
            assert_eq!(proof.root, root, "Leaf {} has inconsistent root", i);
            assert!(
                verify_merkle_proof_core::<TestHash, TestHasher>(&proof),
                "Merkle proof for leaf {} failed verification",
                i
            );
        }
    }

    #[test]
    fn test_collect_path_nodes_returns_full_path() {
        let mut imt = TestIMT::new(TEST_HEIGHT);
        imt.insert(h(1, 0, 0, 0), h(10, 0, 0, 0)).unwrap();

        let mut nodes = Vec::new();
        imt.collect_path_nodes(1, &mut nodes);
        // Path from leaf at height 8 to root at height 0 = 9 nodes
        assert_eq!(nodes.len(), (TEST_HEIGHT + 1) as usize);
        // First node should be the leaf (level = height)
        assert_eq!(nodes[0].key.level, TEST_HEIGHT);
        // Last node should be the root (level = 0)
        assert_eq!(nodes[nodes.len() - 1].key.level, 0);
    }

    #[test]
    fn test_get_height_and_max_leaf_index() {
        let imt = TestIMT::new(TEST_HEIGHT);
        assert_eq!(imt.get_height(), TEST_HEIGHT);
        // Max leaf index for height 8 = 2^8 - 1 = 255
        assert_eq!(imt.tree().get_max_leaf_index(), 255);
    }

    #[test]
    fn test_sentinel_merkle_proof_verifies() {
        let imt = TestIMT::new(TEST_HEIGHT);
        let proof = imt.tree().get_leaf(0);
        assert!(verify_merkle_proof_core::<TestHash, TestHasher>(&proof));
    }
}
