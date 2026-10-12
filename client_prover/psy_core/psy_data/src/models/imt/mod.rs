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

/// In-memory Indexed Merkle Tree for one contract-state map.
///
/// Wraps the existing `UserContractStateTreeId` for merkle node storage
/// and adds IMT-specific leaf preimage tracking and sorted key index.
///
/// A map occupies physical base `B` and capacity `C`. Slot `B` is the
/// counted sentinel: stable virgin state is physical zero, while an
/// initialized sentinel hashes value `[n,0,0,0]`. Members occupy
/// `B+1..=B+n` and are never deleted.
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
    /// Authenticated allocated member count.
    count: u64,
    /// Physical sentinel slot `B`.
    state_slot_base: u64,
    /// Positive map capacity `C`.
    capacity: u64,
    /// Checkpoint ID for current operations
    checkpoint_id: u64,
}

impl<S, F, H, IDKVA> IndexedMerkleTree<S, F, H, IDKVA>
where
    F: RichField,
    H: MerkleZeroHasherWithMarkedLeaf<QHashOut<F>> + FieldQHasher<F>,
    IDKVA: KVQStoreAdapter<S, KVQMerkleNodeKey<USER_CONTRACT_STATE_TREE_TABLE_TYPE>, QHashOut<F>>,
{
    /// Create a virgin map. No leaf is written: physical zero at `B` is the
    /// stable virgin sentinel and is distinct from the hash of an all-zero leaf.
    pub fn new(
        store: &S,
        user_id: u64,
        contract_id: u32,
        height: u8,
        checkpoint_id: u64,
        state_slot_base: u64,
        capacity: u64,
    ) -> anyhow::Result<Self> {
        let tree_id = UserContractStateTreeId::<S, F, H, IDKVA>::new(user_id, contract_id, height);
        Self::validate_map(height, state_slot_base, capacity)?;
        let _ = store;

        Ok(Self {
            tree_id,
            leaves: BTreeMap::new(),
            key_index: BTreeMap::new(),
            count: 0,
            state_slot_base,
            capacity,
            checkpoint_id,
        })
    }

    fn validate_map(height: u8, state_slot_base: u64, capacity: u64) -> anyhow::Result<()> {
        let end = state_slot_base.checked_add(capacity).ok_or_else(|| anyhow::anyhow!("IMT range overflow"))?;
        anyhow::ensure!(capacity > 0 && height < 64 && end < (1u64 << height), "invalid IMT map bounds");
        Ok(())
    }

    fn count_value(count: u64) -> QHashOut<F> {
        QHashOut::from_values(count, 0, 0, 0)
    }

    fn validate_successor(leaf: &IMTContractStateLeaf<F>, base: u64, count: u64) -> anyhow::Result<()> {
        let next = leaf.next_index.to_canonical_u64();
        anyhow::ensure!(
            (next == 0 && leaf.next_key == QHashOut::ZERO) || (next > base && next <= base + count && leaf.next_key != QHashOut::ZERO),
            "invalid IMT successor"
        );
        Ok(())
    }

    fn sentinel_at(&self, count: u64) -> anyhow::Result<IMTContractStateLeaf<F>> {
        if count == 0 {
            return Ok(IMTContractStateLeaf::default());
        }
        let leaf = self.leaves.get(&self.state_slot_base).copied().ok_or_else(|| anyhow::anyhow!("initialized sentinel missing"))?;
        anyhow::ensure!(
            leaf.key == QHashOut::ZERO && leaf.value == Self::count_value(count) && leaf.value.0.elements[1..].iter().all(|limb| *limb == F::ZERO),
            "invalid initialized sentinel"
        );
        Self::validate_successor(&leaf, self.state_slot_base, count)?;
        Ok(leaf)
    }

    /// Load one existing map. A zero count has no stored sentinel; a positive
    /// count requires the counted sentinel at `B` and every allocated member.
    pub fn from_existing(
        user_id: u64,
        contract_id: u32,
        height: u8,
        checkpoint_id: u64,
        leaves: BTreeMap<u64, IMTContractStateLeaf<F>>,
        count: u64,
        state_slot_base: u64,
        capacity: u64,
    ) -> anyhow::Result<Self> {
        Self::validate_map(height, state_slot_base, capacity)?;
        anyhow::ensure!(count <= capacity, "IMT count exceeds capacity");
        let tree_id = UserContractStateTreeId::<S, F, H, IDKVA>::new(user_id, contract_id, height);
        let mut tree = Self {
            tree_id,
            leaves,
            key_index: BTreeMap::new(),
            count,
            state_slot_base,
            capacity,
            checkpoint_id,
        };
        if count == 0 {
            anyhow::ensure!(tree.leaves.is_empty(), "virgin IMT stores no leaf");
            return Ok(tree);
        }
        let _ = tree.sentinel_at(count)?;
        for index in state_slot_base + 1..=state_slot_base + count {
            let leaf = tree.leaves.get(&index).copied().ok_or_else(|| anyhow::anyhow!("allocated member missing"))?;
            anyhow::ensure!(leaf.key != QHashOut::ZERO, "allocated member has zero key");
            Self::validate_successor(&leaf, state_slot_base, count)?;
            anyhow::ensure!(tree.key_index.insert(OrdHash(leaf.key), index).is_none(), "duplicate IMT key");
        }
        anyhow::ensure!(tree.leaves.len() == count as usize + 1, "unexpected leaf outside allocated map");
        Ok(tree)
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

    /// Get the authenticated allocated count.
    pub fn get_count(&self) -> u64 {
        self.count
    }

    /// Get the physical sentinel slot.
    pub fn get_state_slot_base(&self) -> u64 {
        self.state_slot_base
    }

    /// Get the positive map capacity.
    pub fn get_capacity(&self) -> u64 {
        self.capacity
    }

    /// Get the next member index, `B+n+1`.
    pub fn get_next_append_index(&self) -> u64 {
        self.state_slot_base + self.count + 1
    }

    /// Find the predecessor: the allocated leaf with the largest key < target key.
    /// A virgin map or a target below every member returns the sentinel at `B`.
    pub fn find_predecessor(&self, key: &QHashOut<F>) -> anyhow::Result<(u64, IMTContractStateLeaf<F>)> {
        let target = OrdHash(*key);
        let pred = self.key_index.range(..target).next_back();
        let Some((_, &pred_index)) = pred else {
            return Ok((self.state_slot_base, self.sentinel_at(self.count)?));
        };
        let pred_leaf = self
            .leaves
            .get(&pred_index)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("predecessor leaf not found at index {}", pred_index))?;
        Ok((pred_index, pred_leaf))
    }

    /// Get a membership proof: proves key K exists with value V.
    pub fn get_membership_proof(&self, store: &S, key: &QHashOut<F>) -> anyhow::Result<IMTMembershipProof<F>> {
        let leaf_index = self.get_leaf_index_for_key(key).ok_or_else(|| anyhow::anyhow!("key not found in IMT"))?;
        anyhow::ensure!(
            leaf_index > self.state_slot_base && leaf_index <= self.state_slot_base + self.count,
            "membership index is outside the allocated map"
        );

        let leaf = self
            .leaves
            .get(&leaf_index)
            .copied()
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
            next_append_index: self.get_next_append_index(),
        })
    }

    /// Insert a new key-value pair into the IMT.
    /// Returns an `IMTContractStateUpdate::Insert` with predecessor, member,
    /// and sentinel-count delta proofs.
    ///
    /// Root order is R0 -> R1 -> R2 -> R3:
    /// 1. Authenticate the sentinel and predecessor at R0.
    /// 2. Splice the predecessor to `(key, B+n+1)`, producing R1.
    /// 3. Insert the member into the zero slot, producing R2.
    /// 4. Increment the sentinel count, producing R3.
    ///
    /// Virgin insertion writes physical zero to the transient count-zero
    /// sentinel, then hashes that transient leaf when changing the count to one.
    /// A sentinel predecessor keeps both physical version transitions.
    pub fn insert(&mut self, store: &S, key: QHashOut<F>, value: QHashOut<F>) -> anyhow::Result<IMTContractStateUpdate<F>> {
        if key == QHashOut::ZERO {
            anyhow::bail!("IMT member key must be nonzero");
        }
        if self.get_leaf_index_for_key(&key).is_some() {
            anyhow::bail!("key already exists in IMT, use update() instead");
        }
        if self.count == self.capacity {
            anyhow::bail!("IMT map is at capacity");
        }

        let base = self.state_slot_base;
        let old_count = self.count;
        let new_leaf_index = base + old_count + 1;
        let (pred_index, pred_old_leaf) = self.find_predecessor(&key)?;
        anyhow::ensure!(
            compare_qhashout_keys(&pred_old_leaf.key, &key) == std::cmp::Ordering::Less,
            "predecessor key must be less than inserted key"
        );
        if pred_old_leaf.next_key != QHashOut::ZERO {
            anyhow::ensure!(
                compare_qhashout_keys(&key, &pred_old_leaf.next_key) == std::cmp::Ordering::Less,
                "inserted key must be less than predecessor successor"
            );
        }
        Self::validate_successor(&pred_old_leaf, base, old_count)?;

        let new_leaf = IMTContractStateLeaf::new(key, value, pred_old_leaf.next_key, pred_old_leaf.next_index);
        let pred_new_leaf = pred_old_leaf.with_new_next(key, F::from_canonical_u64(new_leaf_index));
        let starting_sentinel = self.sentinel_at(old_count)?;
        if pred_index == base {
            anyhow::ensure!(pred_old_leaf == starting_sentinel, "sentinel predecessor mismatch");
        }

        let sentinel_old_leaf = if pred_index == base { pred_new_leaf } else { starting_sentinel };
        let sentinel_new_leaf = sentinel_old_leaf.with_new_value(Self::count_value(old_count + 1));
        let pred_new_hash = pred_new_leaf.qfhash::<H>();
        let new_leaf_hash = new_leaf.qfhash::<H>();
        let sentinel_new_hash = sentinel_new_leaf.qfhash::<H>();

        let predecessor_delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, pred_index, pred_new_hash)?;
        let expected_old = if old_count == 0 { QHashOut::ZERO } else { pred_old_leaf.qfhash::<H>() };
        anyhow::ensure!(predecessor_delta_proof.old_value == expected_old, "predecessor authentication mismatch");

        let new_leaf_delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, new_leaf_index, new_leaf_hash)?;
        anyhow::ensure!(new_leaf_delta_proof.old_value == QHashOut::ZERO, "member slot was not empty");

        let sentinel_delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, base, sentinel_new_hash)?;
        anyhow::ensure!(sentinel_delta_proof.old_value == sentinel_old_leaf.qfhash::<H>(), "invalid transient sentinel hash");
        anyhow::ensure!(
            predecessor_delta_proof.new_root == new_leaf_delta_proof.old_root && new_leaf_delta_proof.new_root == sentinel_delta_proof.old_root,
            "IMT insert delta roots are not adjacent"
        );

        if pred_index != base {
            self.leaves.insert(pred_index, pred_new_leaf);
        }
        self.leaves.insert(new_leaf_index, new_leaf);
        self.leaves.insert(base, sentinel_new_leaf);
        self.key_index.insert(OrdHash(key), new_leaf_index);
        self.count += 1;

        Ok(IMTContractStateUpdate::Insert {
            predecessor_old_preimage: pred_old_leaf,
            predecessor_new_preimage: pred_new_leaf,
            new_leaf_preimage: new_leaf,
            predecessor_delta_proof,
            new_leaf_delta_proof,
            sentinel_old_preimage: sentinel_old_leaf,
            sentinel_new_preimage: sentinel_new_leaf,
            sentinel_delta_proof,
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
        anyhow::ensure!(
            leaf_index > self.state_slot_base && leaf_index <= self.state_slot_base + self.count,
            "update index is outside the allocated map"
        );

        let old_preimage = self
            .leaves
            .get(&leaf_index)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("leaf preimage not found at index {}", leaf_index))?;

        // Only value changes; key, successor, and sentinel count remain unchanged.
        let new_preimage = old_preimage.with_new_value(new_value);

        let new_hash = new_preimage.qfhash::<H>();
        let delta_proof = self.tree_id.set_leaf_ucs(store, self.checkpoint_id, leaf_index, new_hash)?;
        anyhow::ensure!(delta_proof.old_value == old_preimage.qfhash::<H>(), "update preimage mismatch");

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

    fn fresh(height: u8, base: u64, capacity: u64) -> (Store, IMT) {
        let store = Store::new();
        let imt = IMT::new(&store, 1, 1, height, 100, base, capacity).unwrap();
        (store, imt)
    }

    #[test]
    fn test_new_imt_has_virgin_sentinel() {
        let (store, imt) = fresh(8, 4, 8);
        assert_eq!(imt.get_count(), 0);
        assert_eq!(imt.get_next_append_index(), 5);
        assert!(imt.get_leaf_preimage(4).is_none());
        let proof = imt.tree_id.get_leaf_ucs(&store, 100, 4).unwrap();
        assert_eq!(proof.value, QHashOut::ZERO);
        assert_ne!(proof.value, IMTContractStateLeaf::<F>::default().qfhash::<H>());
    }

    #[test]
    fn test_insert_single_key() {
        let (store, mut imt) = fresh(8, 4, 8);

        let key = make_key(42);
        let value = make_value(100);
        let update = imt.insert(&store, key, value).unwrap();

        match &update {
            IMTContractStateUpdate::Insert {
                new_leaf_preimage,
                sentinel_old_preimage,
                sentinel_new_preimage,
                predecessor_delta_proof,
                new_leaf_delta_proof,
                sentinel_delta_proof,
                ..
            } => {
                assert_eq!(new_leaf_preimage.key, key);
                assert_eq!(new_leaf_preimage.value, value);
                assert_eq!(new_leaf_preimage.next_key, QHashOut::ZERO);
                assert_eq!(predecessor_delta_proof.index, 4);
                assert_eq!(predecessor_delta_proof.old_value, QHashOut::ZERO);
                assert_eq!(new_leaf_delta_proof.index, 5);
                assert_eq!(sentinel_delta_proof.index, 4);
                assert_eq!(predecessor_delta_proof.new_value, sentinel_old_preimage.qfhash::<H>());
                assert_eq!(sentinel_old_preimage.value, QHashOut::ZERO);
                assert_eq!(sentinel_new_preimage.value, make_value(1));
                assert_eq!(sentinel_new_preimage.next_key, key);
                assert_eq!(sentinel_delta_proof.old_value, sentinel_old_preimage.qfhash::<H>());
                assert_ne!(sentinel_delta_proof.old_value, QHashOut::ZERO);
            }
            _ => panic!("expected Insert"),
        }

        assert_eq!(imt.get_count(), 1);
        assert_eq!(imt.get_next_append_index(), 6);
        assert_eq!(imt.get_leaf_index_for_key(&key), Some(5));
    }


    #[test]
    fn test_insert_maintains_sorted_order() {
        let (store, mut imt) = fresh(8, 4, 8);

        let k30 = make_key(30);
        let k10 = make_key(10);
        let k20 = make_key(20);

        imt.insert(&store, k30, make_value(300)).unwrap();
        let middle = imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k20, make_value(200)).unwrap();

        match middle {
            IMTContractStateUpdate::Insert {
                predecessor_delta_proof,
                sentinel_old_preimage,
                sentinel_new_preimage,
                ..
            } => {
                assert_ne!(predecessor_delta_proof.index, imt.get_state_slot_base());
                assert_eq!(sentinel_old_preimage.next_key, k30);
                assert_eq!(sentinel_new_preimage.value, make_value(2));
                assert_eq!(sentinel_old_preimage.next_key, sentinel_new_preimage.next_key);
            }
            _ => panic!("expected Insert"),
        }

        let sentinel = imt.get_leaf_preimage(4).unwrap();
        assert_eq!(sentinel.next_key, k10);
        assert_eq!(sentinel.value, make_value(3));

        let leaf_10 = imt.get_leaf_preimage(imt.get_leaf_index_for_key(&k10).unwrap()).unwrap();
        assert_eq!(leaf_10.next_key, k20);
        let leaf_20 = imt.get_leaf_preimage(imt.get_leaf_index_for_key(&k20).unwrap()).unwrap();
        assert_eq!(leaf_20.next_key, k30);
        let leaf_30 = imt.get_leaf_preimage(imt.get_leaf_index_for_key(&k30).unwrap()).unwrap();
        assert_eq!(leaf_30.next_key, QHashOut::ZERO);
        assert!(leaf_30.is_last());
    }

    #[test]
    fn test_update_existing_key() {
        let (store, mut imt) = fresh(8, 4, 8);

        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();
        let sentinel_before = *imt.get_leaf_preimage(4).unwrap();

        let new_value = make_value(200);
        let update = imt.update(&store, key, new_value).unwrap();

        match &update {
            IMTContractStateUpdate::Update {
                old_preimage, new_preimage, ..
            } => {
                assert_eq!(old_preimage.value, make_value(100));
                assert_eq!(new_preimage.value, new_value);
                assert_eq!(old_preimage.key, new_preimage.key);
                assert_eq!(old_preimage.next_key, new_preimage.next_key);
                assert_eq!(old_preimage.next_index, new_preimage.next_index);
            }
            _ => panic!("expected Update"),
        }
        assert_eq!(imt.get_leaf_preimage(4), Some(&sentinel_before));
        assert_eq!(imt.get_count(), 1);
    }

    #[test]
    fn test_upsert_insert_then_update() {
        let (store, mut imt) = fresh(8, 4, 8);
        let key = make_key(42);
        let update1 = imt.upsert(&store, key, make_value(100)).unwrap();
        assert!(matches!(update1, IMTContractStateUpdate::Insert { .. }));
        let update2 = imt.upsert(&store, key, make_value(200)).unwrap();
        assert!(matches!(update2, IMTContractStateUpdate::Update { .. }));
    }

    #[test]
    fn test_insert_duplicate_key_fails() {
        let (store, mut imt) = fresh(8, 4, 8);
        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();
        assert!(imt.insert(&store, key, make_value(200)).is_err());
    }

    #[test]
    fn test_update_nonexistent_key_fails() {
        let (store, mut imt) = fresh(8, 4, 8);
        assert!(imt.update(&store, make_key(42), make_value(100)).is_err());
    }

    #[test]
    fn test_membership_proof() {
        let (store, mut imt) = fresh(8, 4, 8);
        let key = make_key(42);
        let value = make_value(100);
        imt.insert(&store, key, value).unwrap();

        let proof = imt.get_membership_proof(&store, &key).unwrap();
        assert_eq!(proof.leaf.key, key);
        assert_eq!(proof.leaf.value, value);
        assert_eq!(proof.merkle_proof.index, 5);
        assert_eq!(proof.merkle_proof.root, imt.get_root(&store).unwrap());
    }

    #[test]
    fn test_non_membership_proof() {
        let (store, mut imt) = fresh(8, 4, 8);
        let k10 = make_key(10);
        let k30 = make_key(30);
        imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k30, make_value(300)).unwrap();

        let proof = imt.get_non_membership_proof(&store, &make_key(20)).unwrap();
        assert_eq!(proof.predecessor_leaf.key, k10);
        assert_eq!(proof.predecessor_leaf.next_key, k30);
        assert_eq!(proof.merkle_proof.root, imt.get_root(&store).unwrap());
    }

    #[test]
    fn test_predecessor_info() {
        let (store, mut imt) = fresh(8, 4, 8);
        let k10 = make_key(10);
        let k30 = make_key(30);
        imt.insert(&store, k10, make_value(100)).unwrap();
        imt.insert(&store, k30, make_value(300)).unwrap();

        let result = imt.get_predecessor_info(&store, &make_key(20)).unwrap();
        assert_eq!(result.predecessor_leaf.key, k10);
        assert_eq!(result.predecessor_leaf_index, 6);
        assert_eq!(result.next_append_index, 7);
    }

    #[test]
    fn test_insert_produces_chaining_proofs() {
        let (store, mut imt) = fresh(8, 4, 8);
        let root_before = imt.get_root(&store).unwrap();
        let update = imt.insert(&store, make_key(42), make_value(100)).unwrap();

        match &update {
            IMTContractStateUpdate::Insert {
                predecessor_delta_proof,
                new_leaf_delta_proof,
                sentinel_delta_proof,
                ..
            } => {
                assert_eq!(predecessor_delta_proof.old_root, root_before);
                assert_eq!(new_leaf_delta_proof.old_root, predecessor_delta_proof.new_root);
                assert_eq!(sentinel_delta_proof.old_root, new_leaf_delta_proof.new_root);
                assert_eq!(sentinel_delta_proof.new_root, imt.get_root(&store).unwrap());
                assert_eq!(update.new_root(), sentinel_delta_proof.new_root);
            }
            _ => panic!("expected Insert"),
        }
    }

    #[test]
    fn test_update_produces_single_proof() {
        let (store, mut imt) = fresh(8, 4, 8);
        let key = make_key(42);
        imt.insert(&store, key, make_value(100)).unwrap();
        let root_before = imt.get_root(&store).unwrap();
        let update = imt.update(&store, key, make_value(200)).unwrap();

        match update {
            IMTContractStateUpdate::Update { delta_proof, .. } => {
                assert_eq!(delta_proof.old_root, root_before);
                assert_eq!(delta_proof.index, 5);
                assert_eq!(delta_proof.new_root, imt.get_root(&store).unwrap());
            }
            _ => panic!("expected Update"),
        }
    }

    #[test]
    fn test_multiple_inserts_sequential_roots() {
        let (store, mut imt) = fresh(8, 4, 8);
        let mut last_root = imt.get_root(&store).unwrap();

        for i in 1..=5u64 {
            let update = imt.insert(&store, make_key(i * 10), make_value(i * 100)).unwrap();
            assert_eq!(update.old_root(), last_root, "update {} old_root mismatch", i);
            assert!(update.validate_imt_update().is_ok());
            last_root = update.new_root();
            assert_eq!(imt.get_leaf_preimage(4).unwrap().value, make_value(i));
        }

        assert_eq!(last_root, imt.get_root(&store).unwrap());
    }

    #[test]
    fn test_many_operations() {
        let (store, mut imt) = fresh(16, 4, 32);

        for i in 1..=20u64 {
            imt.insert(&store, make_key(i * 7), make_value(i * 100)).unwrap();
        }
        assert_eq!(imt.get_count(), 20);
        assert_eq!(imt.get_next_append_index(), 25);

        for i in 1..=10u64 {
            imt.update(&store, make_key(i * 7), make_value(i * 1000)).unwrap();
        }
        for i in 1..=10u64 {
            let leaf = imt.get_leaf_preimage(imt.get_leaf_index_for_key(&make_key(i * 7)).unwrap()).unwrap();
            assert_eq!(leaf.value, make_value(i * 1000));
        }
        for i in 11..=20u64 {
            let leaf = imt.get_leaf_preimage(imt.get_leaf_index_for_key(&make_key(i * 7)).unwrap()).unwrap();
            assert_eq!(leaf.value, make_value(i * 100));
        }

        let mut current_index = 4u64;
        let mut visited = vec![];
        loop {
            let leaf = imt.get_leaf_preimage(current_index).unwrap();
            visited.push(leaf.key);
            if leaf.is_last() {
                break;
            }
            let next = leaf.next_index.to_canonical_u64();
            assert!(next > 4 && next <= 24);
            current_index = next;
        }
        assert_eq!(visited.len(), 21);
        for i in 1..visited.len() {
            assert_eq!(compare_qhashout_keys(&visited[i - 1], &visited[i]), std::cmp::Ordering::Less);
        }
    }

    #[test]
    fn test_malformed_count_capacity_and_splice_rejected() {
        let (store, imt) = fresh(8, 4, 1);
        assert!(IMT::new(&store, 1, 1, 8, 100, 4, 0).is_err());
        assert!(IMT::new(&store, 1, 1, 8, 100, 250, 8).is_err());
        let mut full = imt;
        full.insert(&store, make_key(10), make_value(1)).unwrap();
        assert!(full.insert(&store, make_key(20), make_value(2)).is_err());
        assert!(full.insert(&store, QHashOut::ZERO, make_value(2)).is_err());

        let _ = IMT::from_existing(1, 1, 8, 100, BTreeMap::new(), 1, 4, 8).unwrap_err();
        let mut leaves = BTreeMap::new();
        leaves.insert(4, IMTContractStateLeaf::new(QHashOut::ZERO, make_value(1), make_key(10), F::from_canonical_u64(9)));
        leaves.insert(5, IMTContractStateLeaf::new(make_key(10), make_value(1), QHashOut::ZERO, F::ZERO));
        assert!(IMT::from_existing(1, 1, 8, 100, leaves, 1, 4, 8).is_err());
    }

}
