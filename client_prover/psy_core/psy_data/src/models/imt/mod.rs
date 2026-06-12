use std::collections::BTreeMap;

use kvq::{adapters::standard::KVQStandardAdapter, traits::KVQStoreAdapter};
use plonky2::hash::hash_types::RichField;
use psy_client_common::data::qhashout::QHashOut;
use psy_crypto::hash::{
    merkle::core::MerkleProofCore,
    traits::{
        hasher::{FieldQHasher, MerkleZeroHasherWithMarkedLeaf},
        qhashable::QFieldHashable,
    },
};

use super::user::contract_state_tree::UserContractStateTreeId;
use crate::{
    config::store_config::USER_CONTRACT_STATE_TREE_TABLE_TYPE,
    models::kvq_merkle::key::KVQMerkleNodeKey,
    qdata::{
        imt_contract_state::{compare_qhashout_keys, IMTContractStateLeaf},
        imt_proof::{IMTContractStateUpdate, IMTMembershipProof, IMTNonMembershipProof, IMTPredecessorResult},
    },
};

/// Wrapper around a key ordering for BTreeMap that uses MSL-first comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OrdHash<F: RichField>(QHashOut<F>);

impl<F: RichField> PartialOrd for OrdHash<F> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: RichField> Ord for OrdHash<F> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        compare_qhashout_keys(&self.0, &other.0)
    }
}

/// In-memory Indexed Merkle Tree for contract state.
///
/// Wraps the existing `UserContractStateTreeId` for merkle node storage
/// and adds IMT-specific leaf preimage tracking and sorted key index.
///
/// The IMT is append-only with a sorted linked list overlay:
/// - Leaf 0 is always a sentinel with all-zero fields
/// - New leaves are appended at `next_append_index`
/// - Each leaf's `next_key`/`next_index` points to the next-larger key
pub struct IndexedMerkleTree<
    S,
    F: RichField,
    H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F>,
    IDKVA = KVQStandardAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
> where
    IDKVA: KVQStoreAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
{
    /// The underlying merkle tree for node storage
    tree_id: UserContractStateTreeId<S, F, H, IDKVA>,
    /// Leaf preimages indexed by leaf position
    leaves: BTreeMap<u64, IMTContractStateLeaf<F>>,
    /// Key to leaf index mapping (sorted by key for predecessor lookups)
    key_index: BTreeMap<OrdHash<F>, u64>,
    /// Next append position
    next_append_index: u64,
    /// Checkpoint ID for current operations
    checkpoint_id: u64,
}

impl<S, F, H, IDKVA> IndexedMerkleTree<S, F, H, IDKVA>
where
    F: RichField,
    H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F>,
    IDKVA: KVQStoreAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
{
    /// Create a new IndexedMerkleTree and initialize with the sentinel leaf.
    pub fn new(store: &S, user_id: u64, contract_id: u32, height: u8, checkpoint_id: u64) -> anyhow::Result<Self> {
        let tree_id = UserContractStateTreeId::<S, F, H, IDKVA>::new(user_id, contract_id, height);

        // Initialize sentinel leaf at index 0
        let sentinel = IMTContractStateLeaf::sentinel();
        let sentinel_hash = sentinel.qfhash::<H>();

        // Set sentinel in the underlying merkle tree
        tree_id.set_leaf_ucs(store, checkpoint_id, 0, sentinel_hash)?;

        let mut leaves = BTreeMap::new();
        leaves.insert(0, sentinel);

        let mut key_index = BTreeMap::new();
        key_index.insert(OrdHash(QHashOut::ZERO), 0u64);

        Ok(Self {
            tree_id,
            leaves,
            key_index,
            next_append_index: 1,
            checkpoint_id,
        })
    }

    /// Create from an existing tree state (for loading from database).
    pub fn from_existing(
        user_id: u64,
        contract_id: u32,
        height: u8,
        checkpoint_id: u64,
        leaves: BTreeMap<u64, IMTContractStateLeaf<F>>,
        next_append_index: u64,
    ) -> Self {
        let tree_id = UserContractStateTreeId::<S, F, H, IDKVA>::new(user_id, contract_id, height);

        let mut key_index = BTreeMap::new();
        for (&index, leaf) in &leaves {
            key_index.insert(OrdHash(leaf.key), index);
        }

        Self {
            tree_id,
            leaves,
            key_index,
            next_append_index,
            checkpoint_id,
        }
    }

    /// Get the current tree root.
    pub fn get_root(&self, store: &S) -> anyhow::Result<QHashOut<F>> {
        self.tree_id.get_root(store, self.checkpoint_id)
    }

    /// Get a leaf preimage by its position index.
    pub fn get_leaf_preimage(&self, leaf_index: u64) -> Option<&IMTContractStateLeaf<F>> {
        self.leaves.get(&leaf_index)
    }

    /// Get the leaf index for a given key, or None if the key doesn't exist.
    pub fn get_leaf_index_for_key(&self, key: &QHashOut<F>) -> Option<u64> {
        self.key_index.get(&OrdHash(*key)).copied()
    }

    /// Get the next append index.
    pub fn get_next_append_index(&self) -> u64 {
        self.next_append_index
    }

    /// Find the predecessor: the leaf with the largest key < target key.
    /// Returns (leaf_index, leaf_preimage).
    pub fn find_predecessor(&self, key: &QHashOut<F>) -> anyhow::Result<(u64, IMTContractStateLeaf<F>)> {
        let target = OrdHash(*key);

        // Find the largest key strictly less than the target
        let pred = self
            .key_index
            .range(..target)
            .next_back()
            .ok_or_else(|| anyhow::anyhow!("no predecessor found (should not happen with sentinel)"))?;

        let pred_index = *pred.1;
        let pred_leaf = self
            .leaves
            .get(&pred_index)
            .ok_or_else(|| anyhow::anyhow!("predecessor leaf not found at index {}", pred_index))?;

        Ok((pred_index, *pred_leaf))
    }

    /// Get a membership proof: proves key K exists with value V.
    pub fn get_membership_proof(&self, store: &S, key: &QHashOut<F>) -> anyhow::Result<IMTMembershipProof<F>> {
        let leaf_index = self.get_leaf_index_for_key(key).ok_or_else(|| anyhow::anyhow!("key not found in IMT"))?;

        let leaf = *self
            .leaves
            .get(&leaf_index)
            .ok_or_else(|| anyhow::anyhow!("leaf preimage not found at index {}", leaf_index))?;

        let merkle_proof = self.tree_id.get_leaf_ucs(store, self.checkpoint_id, leaf_index)?;

        Ok(IMTMembershipProof { leaf, merkle_proof })
    }

    /// Get a non-membership proof: proves key K does NOT exist.
    pub fn get_non_membership_proof(&self, store: &S, key: &QHashOut<F>) -> anyhow::Result<IMTNonMembershipProof<F>> {
        // Key must NOT exist
        if self.get_leaf_index_for_key(key).is_some() {
            anyhow::bail!("key exists in IMT, cannot create non-membership proof");
        }

        let (pred_index, predecessor_leaf) = self.find_predecessor(key)?;
        let merkle_proof = self.tree_id.get_leaf_ucs(store, self.checkpoint_id, pred_index)?;

        // Verify the non-membership invariant:
        // predecessor.key < target_key < predecessor.next_key (or next_key == 0)
        if predecessor_leaf.key != QHashOut::ZERO || *key != QHashOut::ZERO {
            anyhow::ensure!(
                compare_qhashout_keys(&predecessor_leaf.key, key) == std::cmp::Ordering::Less || predecessor_leaf.key == QHashOut::ZERO,
                "predecessor key must be less than target key"
            );
        }
        if predecessor_leaf.next_key != QHashOut::ZERO {
            anyhow::ensure!(
                compare_qhashout_keys(key, &predecessor_leaf.next_key) == std::cmp::Ordering::Less,
                "target key must be less than predecessor's next_key"
            );
        }

        Ok(IMTNonMembershipProof {
            predecessor_leaf,
            merkle_proof,
        })
    }

    /// Get predecessor info for a key (used by clients to construct insertion
    /// deltas).
    pub fn get_predecessor_info(&self, store: &S, key: &QHashOut<F>) -> anyhow::Result<IMTPredecessorResult<F>> {
        let (pred_index, predecessor_leaf) = self.find_predecessor(key)?;
        let predecessor_merkle_proof = self.tree_id.get_leaf_ucs(store, self.checkpoint_id, pred_index)?;

        Ok(IMTPredecessorResult {
            predecessor_leaf_index: pred_index,
            predecessor_leaf,
            predecessor_merkle_proof,
            next_append_index: self.next_append_index,
        })
    }

    /// Insert a new key-value pair into the IMT.
    /// Returns an `IMTContractStateUpdate::Insert` with both delta merkle
    /// proofs.
    ///
    /// Algorithm:
    /// 1. Find predecessor (largest key < new key)
    /// 2. Create new leaf at next_append_index inheriting predecessor's forward
    ///    pointers
    /// 3. Update predecessor's forward pointers to point to new leaf
    /// 4. Produce two DeltaMerkleProofs: predecessor update + new leaf append
    pub fn insert(&mut self, store: &S, key: QHashOut<F>, value: QHashOut<F>) -> anyhow::Result<IMTContractStateUpdate<F>> {
        // Check key doesn't already exist
        if self.get_leaf_index_for_key(&key).is_some() {
            anyhow::bail!("key already exists in IMT, use update() instead");
        }

        let new_leaf_index = self.next_append_index;
        let (pred_index, pred_old_leaf) = self.find_predecessor(&key)?;

        // Step 1: Create new leaf inheriting predecessor's forward pointers
        let new_leaf = IMTContractStateLeaf::new(key, value, pred_old_leaf.next_key, pred_old_leaf.next_index);

        // Step 2: Update predecessor's forward pointers
        let pred_new_leaf = IMTContractStateLeaf::new(pred_old_leaf.key, pred_old_leaf.value, key, F::from_canonical_u64(new_leaf_index));

        // Step 3: Compute hashes
        let pred_new_hash = pred_new_leaf.qfhash::<H>();
        let new_leaf_hash = new_leaf.qfhash::<H>();

        // Step 4: Apply predecessor update to merkle tree -> DeltaMerkleProof #1
        let predecessor_delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, pred_index, pred_new_hash)?;

        // Step 5: Append new leaf to merkle tree -> DeltaMerkleProof #2
        let new_leaf_delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, new_leaf_index, new_leaf_hash)?;

        // Step 6: Update internal state
        self.leaves.insert(pred_index, pred_new_leaf);
        self.leaves.insert(new_leaf_index, new_leaf);
        self.key_index.insert(OrdHash(key), new_leaf_index);
        self.next_append_index += 1;

        Ok(IMTContractStateUpdate::Insert {
            predecessor_old_preimage: pred_old_leaf,
            predecessor_new_preimage: pred_new_leaf,
            new_leaf_preimage: new_leaf,
            predecessor_delta_proof,
            new_leaf_delta_proof,
        })
    }

    /// Update an existing key's value in the IMT.
    /// Returns an `IMTContractStateUpdate::Update` with one delta merkle proof.
    ///
    /// Only the value field changes; key, next_key, and next_index remain
    /// unchanged.
    pub fn update(&mut self, store: &S, key: QHashOut<F>, new_value: QHashOut<F>) -> anyhow::Result<IMTContractStateUpdate<F>> {
        let leaf_index = self
            .get_leaf_index_for_key(&key)
            .ok_or_else(|| anyhow::anyhow!("key not found in IMT, use insert() instead"))?;

        let old_preimage = *self
            .leaves
            .get(&leaf_index)
            .ok_or_else(|| anyhow::anyhow!("leaf preimage not found at index {}", leaf_index))?;

        // Only value changes
        let new_preimage = IMTContractStateLeaf::new(old_preimage.key, new_value, old_preimage.next_key, old_preimage.next_index);

        let new_hash = new_preimage.qfhash::<H>();
        let delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, leaf_index, new_hash)?;

        // Update internal state
        self.leaves.insert(leaf_index, new_preimage);

        Ok(IMTContractStateUpdate::Update {
            old_preimage,
            new_preimage,
            delta_proof,
        })
    }

    /// Insert or update: if the key exists, update its value; otherwise insert.
    pub fn upsert(&mut self, store: &S, key: QHashOut<F>, value: QHashOut<F>) -> anyhow::Result<IMTContractStateUpdate<F>> {
        if self.get_leaf_index_for_key(&key).is_some() {
            self.update(store, key, value)
        } else {
            self.insert(store, key, value)
        }
    }

    /// Inject a merkle proof from an external source (e.g., from the database).
    pub fn injest_merkle_proof(&self, store: &S, merkle_proof: &MerkleProofCore<QHashOut<F>>) -> anyhow::Result<()> {
        self.tree_id.injest_merkle_proof_ucs(store, self.checkpoint_id, merkle_proof)
    }
}

#[cfg(test)]
mod tests {
    use kvq::memory::simple::KVQSimpleMemoryBackingStore;
    use plonky2::field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    };

    use super::*;
    use crate::config::store_config::PsyHasher;

    type F = GoldilocksField;
    type H = PsyHasher;
    type Store = KVQSimpleMemoryBackingStore;
    type IMT = IndexedMerkleTree<Store, F, H>;

    fn make_key(v: u64) -> QHashOut<F> {
        QHashOut::from_values(v, 0, 0, 0)
    }

    fn make_value(v: u64) -> QHashOut<F> {
        QHashOut::from_values(v, 0, 0, 0)
    }

    #[test]
    fn test_new_imt_has_sentinel() {
        let store = Store::new();
        let imt = IMT::new(&store, 1, 1, 8, 100).unwrap();
        assert_eq!(imt.get_next_append_index(), 1);

        let sentinel = imt.get_leaf_preimage(0).unwrap();
        assert!(sentinel.is_sentinel());
        assert_eq!(sentinel.key, QHashOut::ZERO);
    }

    #[test]
    fn test_insert_single_key() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        let value = make_value(100);
        let update = imt.insert(&store, key, value).unwrap();

        match &update {
            IMTContractStateUpdate::Insert { new_leaf_preimage, .. } => {
                assert_eq!(new_leaf_preimage.key, key);
                assert_eq!(new_leaf_preimage.value, value);
                // Last leaf, so next_key == ZERO
                assert_eq!(new_leaf_preimage.next_key, QHashOut::ZERO);
            }
            _ => panic!("expected Insert"),
        }

        assert_eq!(imt.get_next_append_index(), 2);
        assert_eq!(imt.get_leaf_index_for_key(&key), Some(1));
    }

    #[test]
    fn test_insert_maintains_sorted_order() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        // Insert keys out of order: 30, 10, 20
        let k30 = make_key(30);
        let k10 = make_key(10);
        let k20 = make_key(20);

        imt.insert(&store, k30, make_value(300)).unwrap();
        imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k20, make_value(200)).unwrap();

        // Verify sorted linked list: sentinel(0) -> k10(2) -> k20(3) -> k30(1) -> end
        let sentinel = imt.get_leaf_preimage(0).unwrap();
        assert_eq!(sentinel.next_key, k10);

        let leaf_10_idx = imt.get_leaf_index_for_key(&k10).unwrap();
        let leaf_10 = imt.get_leaf_preimage(leaf_10_idx).unwrap();
        assert_eq!(leaf_10.next_key, k20);

        let leaf_20_idx = imt.get_leaf_index_for_key(&k20).unwrap();
        let leaf_20 = imt.get_leaf_preimage(leaf_20_idx).unwrap();
        assert_eq!(leaf_20.next_key, k30);

        let leaf_30_idx = imt.get_leaf_index_for_key(&k30).unwrap();
        let leaf_30 = imt.get_leaf_preimage(leaf_30_idx).unwrap();
        assert_eq!(leaf_30.next_key, QHashOut::ZERO);
        assert!(leaf_30.is_last());
    }

    #[test]
    fn test_update_existing_key() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();

        let new_value = make_value(200);
        let update = imt.update(&store, key, new_value).unwrap();

        match &update {
            IMTContractStateUpdate::Update {
                old_preimage, new_preimage, ..
            } => {
                assert_eq!(old_preimage.value, make_value(100));
                assert_eq!(new_preimage.value, new_value);
                // Key and pointers unchanged
                assert_eq!(old_preimage.key, new_preimage.key);
                assert_eq!(old_preimage.next_key, new_preimage.next_key);
                assert_eq!(old_preimage.next_index, new_preimage.next_index);
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn test_upsert_insert_then_update() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);

        // First upsert should insert
        let update1 = imt.upsert(&store, key, make_value(100)).unwrap();
        assert!(matches!(update1, IMTContractStateUpdate::Insert { .. }));

        // Second upsert should update
        let update2 = imt.upsert(&store, key, make_value(200)).unwrap();
        assert!(matches!(update2, IMTContractStateUpdate::Update { .. }));
    }

    #[test]
    fn test_insert_duplicate_key_fails() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();
        assert!(imt.insert(&store, key, make_value(200)).is_err());
    }

    #[test]
    fn test_update_nonexistent_key_fails() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        assert!(imt.update(&store, key, make_value(100)).is_err());
    }

    #[test]
    fn test_membership_proof() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        let value = make_value(100);
        imt.insert(&store, key, value).unwrap();

        let proof = imt.get_membership_proof(&store, &key).unwrap();
        assert_eq!(proof.leaf.key, key);
        assert_eq!(proof.leaf.value, value);
        // Verify the merkle proof root matches the tree root
        assert_eq!(proof.merkle_proof.root, imt.get_root(&store).unwrap());
    }

    #[test]
    fn test_non_membership_proof() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let k10 = make_key(10);
        let k30 = make_key(30);
        imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k30, make_value(300)).unwrap();

        // Prove that key 20 does NOT exist
        let k20 = make_key(20);
        let proof = imt.get_non_membership_proof(&store, &k20).unwrap();

        // Predecessor should be k10
        assert_eq!(proof.predecessor_leaf.key, k10);
        // And its next_key should be k30 (which is > k20)
        assert_eq!(proof.predecessor_leaf.next_key, k30);
    }

    #[test]
    fn test_predecessor_info() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let k10 = make_key(10);
        let k30 = make_key(30);
        imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k30, make_value(300)).unwrap();

        let k20 = make_key(20);
        let result = imt.get_predecessor_info(&store, &k20).unwrap();

        assert_eq!(result.predecessor_leaf.key, k10);
        assert_eq!(result.next_append_index, 3);
    }

    #[test]
    fn test_insert_produces_chaining_proofs() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let root_before = imt.get_root(&store).unwrap();

        let update = imt.insert(&store, make_key(42), make_value(100)).unwrap();

        match update {
            IMTContractStateUpdate::Insert {
                predecessor_delta_proof,
                new_leaf_delta_proof,
                ..
            } => {
                // Predecessor proof starts from the initial root
                assert_eq!(predecessor_delta_proof.old_root, root_before);
                // New leaf proof starts from predecessor's new root
                assert_eq!(new_leaf_delta_proof.old_root, predecessor_delta_proof.new_root);
                // Final root matches tree
                assert_eq!(new_leaf_delta_proof.new_root, imt.get_root(&store).unwrap());
            }
            _ => panic!("expected Insert"),
        }
    }

    #[test]
    fn test_update_produces_single_proof() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();

        let root_before = imt.get_root(&store).unwrap();
        let update = imt.update(&store, key, make_value(200)).unwrap();

        match update {
            IMTContractStateUpdate::Update { delta_proof, .. } => {
                assert_eq!(delta_proof.old_root, root_before);
                assert_eq!(delta_proof.new_root, imt.get_root(&store).unwrap());
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn test_multiple_inserts_sequential_roots() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 8, 100).unwrap();

        let mut last_root = imt.get_root(&store).unwrap();

        for i in 1..=5u64 {
            let update = imt.insert(&store, make_key(i * 10), make_value(i * 100)).unwrap();
            let old_root = update.old_root();
            let new_root = update.new_root();

            assert_eq!(old_root, last_root, "update {} old_root mismatch", i);
            last_root = new_root;
        }

        assert_eq!(last_root, imt.get_root(&store).unwrap());
    }

    #[test]
    fn test_many_operations() {
        let store = Store::new();
        let mut imt = IMT::new(&store, 1, 1, 16, 100).unwrap();

        // Insert 20 keys
        for i in 1..=20u64 {
            imt.insert(&store, make_key(i * 7), make_value(i * 100)).unwrap();
        }

        assert_eq!(imt.get_next_append_index(), 21);

        // Update 10 keys
        for i in 1..=10u64 {
            imt.update(&store, make_key(i * 7), make_value(i * 1000)).unwrap();
        }

        // Verify all keys exist with correct values
        for i in 1..=10u64 {
            let leaf_idx = imt.get_leaf_index_for_key(&make_key(i * 7)).unwrap();
            let leaf = imt.get_leaf_preimage(leaf_idx).unwrap();
            assert_eq!(leaf.value, make_value(i * 1000));
        }
        for i in 11..=20u64 {
            let leaf_idx = imt.get_leaf_index_for_key(&make_key(i * 7)).unwrap();
            let leaf = imt.get_leaf_preimage(leaf_idx).unwrap();
            assert_eq!(leaf.value, make_value(i * 100));
        }

        // Verify sorted linked list integrity
        let mut current_index = 0u64;
        let mut visited = vec![];
        loop {
            let leaf = imt.get_leaf_preimage(current_index).unwrap();
            visited.push(leaf.key);
            if leaf.is_last() {
                break;
            }
            current_index = leaf.next_index.to_canonical_u64();
        }

        // Verify the visited keys are in sorted order
        for i in 1..visited.len() {
            assert_eq!(
                compare_qhashout_keys(&visited[i - 1], &visited[i]),
                std::cmp::Ordering::Less,
                "linked list not sorted at position {}",
                i
            );
        }
    }
}
