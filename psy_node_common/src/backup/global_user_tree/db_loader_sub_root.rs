use std::collections::HashMap;

use cf_utils::timer::TraceTimer;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_common::tree_sync::traits::rehash_sparse_paths;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use psy_node_core::psy_core_db::traits::full::PsyNodeGlobalUserTreeDatabaseReader;


pub async fn fetch_global_user_tree_from_db_with_sub_root<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalUserTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,

    tree_height: u8,
    sub_root: SimpleMerkleNodeKey,
    checkpoint_id: u64,
    min_user_id_inclusive: u64,
    max_user_id_exclusive: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<SimpleMemoryMerkleRecorderStore<Hasher, Hash>> {
    let mut timer = TraceTimer::new("fetch_global_user_tree_from_db");

    tracing::info!(
        "Fetching global user tree nodes from DB (checkpoint_id={}, tree_height={}, sub_root={:?}, user_id_range=[{}, {}), fetch_batch_size={})",
        checkpoint_id,
        tree_height,
        sub_root,
        min_user_id_inclusive,
        max_user_id_exclusive,
        fetch_batch_size
    );
    let mut node_hash_map = HashMap::<SimpleMerkleNodeKey, Hash>::new();
    if sub_root.level > tree_height {
        anyhow::bail!("sub root {:?} level exceeds tree_height {}", sub_root, tree_height);
    }
    if min_user_id_inclusive > max_user_id_exclusive {
        anyhow::bail!("invalid user ID range [{}, {})", min_user_id_inclusive, max_user_id_exclusive);
    }
    let shift = tree_height - sub_root.level;
    let sub_tree_width = 1u64
        .checked_shl(shift as u32)
        .ok_or_else(|| anyhow::anyhow!("sub-root level shift overflow for {:?}", sub_root))?;
    let leaf_min_index = sub_root
        .index
        .checked_mul(sub_tree_width)
        .ok_or_else(|| anyhow::anyhow!("sub-root index shift overflow for {:?}", sub_root))?;
    let leaf_max_exclusive = leaf_min_index
        .checked_add(sub_tree_width)
        .ok_or_else(|| anyhow::anyhow!("sub-root leaf range overflow for {:?}", sub_root))?;
    if leaf_min_index > min_user_id_inclusive || leaf_max_exclusive < max_user_id_exclusive {
        anyhow::bail!("Sub root {:?} does not cover the requested user ID range [{}, {})", sub_root, min_user_id_inclusive, max_user_id_exclusive);
    }
    let sub_tree_leaf_level = shift;
    // DB returns zero leaves as the leaf-level zero hash, not the sub-tree-root level zero.
    let leaf_zero_hash = Hasher::get_zero_hash(0);
    timer.start();
    let dumped = user_db_reader
        .global_user_tree_dump_leaves_range(checkpoint_id, min_user_id_inclusive, max_user_id_exclusive)
        .await?;
    for (index, hash) in dumped {
        if index < min_user_id_inclusive || index >= max_user_id_exclusive {
            anyhow::bail!(
                "range dump returned index {} outside requested [{}, {})",
                index,
                min_user_id_inclusive,
                max_user_id_exclusive
            );
        }
        if hash == leaf_zero_hash {
            continue;
        }
        let local_index = index
            .checked_sub(leaf_min_index)
            .ok_or_else(|| anyhow::anyhow!("range dump index {} is below sub-root leaf min {}", index, leaf_min_index))?;
        let local_key = SimpleMerkleNodeKey {
            level: sub_tree_leaf_level,
            index: local_index,
        };
        node_hash_map.insert(local_key, hash);
    }
    timer.lap_batch(
        "fetched global user tree nodes from DB",
        "node",
        (max_user_id_exclusive - min_user_id_inclusive) as usize,
    );

    let total_count = (max_user_id_exclusive - min_user_id_inclusive) as usize;
    tracing::info!(
        "Fetched {} / {} non-zero nodes from global user tree from DB (checkpoint_id={}, tree_height={}, user_id_range=[{}, {}))",
        node_hash_map.len(),
        total_count,
        checkpoint_id,
        tree_height,
        min_user_id_inclusive,
        max_user_id_exclusive
    );

    let sparse_keys: Vec<SimpleMerkleNodeKey> = node_hash_map.keys().copied().collect();
    let mut tree = SimpleMemoryMerkleRecorderStore::from_hash_map(shift, node_hash_map);

    timer.start();
    rehash_sparse_paths(&mut tree, &sparse_keys, 0);
    timer.lap_batch("rehashed sparse leaf paths", "path", sparse_keys.len());
    tree.commit_changes();
    timer.lap("committed changes to memory global user tree");

    Ok(tree)
}

pub async fn load_global_user_tree_from_db_with_sub_root<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalUserTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,
    tree_height: u8,
    sub_root: SimpleMerkleNodeKey,
    checkpoint_id: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<SimpleMemoryMerkleRecorderStore<Hasher, Hash>> {
    let mut current_key = sub_root;
    let mut current_value = user_db_reader.global_user_tree_get_node(checkpoint_id, current_key).await?;
    println!("Current root hash: {:?}", current_value);
    println!("Zero hash at root level: {:?}", Hasher::get_zero_hash((tree_height-sub_root.level) as usize));
    println!("zero hash of at leaves: {:?}", Hasher::get_zero_hash(0));

    if current_value == Hasher::get_zero_hash((tree_height-sub_root.level) as usize) {
        // Tree is empty
        return Ok(SimpleMemoryMerkleRecorderStore::new(tree_height-sub_root.level));
    }
    while current_key.level < tree_height {
        let right_child_key = current_key.right_child();
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - right_child_key.level) as usize);

        let right_child_value = user_db_reader.global_user_tree_get_node(checkpoint_id, right_child_key).await?;
        let right_is_empty = right_child_value == zero_hash_at_level;

        if !right_is_empty {
            current_key = right_child_key;
            current_value = right_child_value;
        } else {
            let left_child_key = current_key.left_child();

            let left_child_value = user_db_reader.global_user_tree_get_node(checkpoint_id, left_child_key).await?;
            let left_is_empty = left_child_value == zero_hash_at_level;

            if !left_is_empty {
                current_key = left_child_key;
                current_value = left_child_value;
            } else {
                // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
                // ensure the root is not a zero hash
                anyhow::bail!("Failed to load global user tree from DB: reached leaf node with zero hash, but root is not zero hash");
            }
        }
    }
    // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
    // ensure the root is not a zero hash
    if current_value == Hasher::get_zero_hash(0) {
        // Tree is empty
        anyhow::bail!("Failed to load global user tree from DB: reached leaf node with zero hash, but root is not zero hash");
    }
    let max_user_id_exclusive = current_key.index + 1;
    println!("max_user_id_exclusive: {}", max_user_id_exclusive);
    let expected_sub_root = user_db_reader
        .global_user_tree_get_node(checkpoint_id, sub_root)
        .await?;
    let tree = fetch_global_user_tree_from_db_with_sub_root::<Hasher, Store, Hash>(
        user_db_reader,
        tree_height,
        sub_root,
        checkpoint_id,
        sub_root.index << (tree_height - sub_root.level),
        max_user_id_exclusive,
        fetch_batch_size,
    )
    .await?;
    let loaded_root = tree.get_root();
    if loaded_root != expected_sub_root {
        anyhow::bail!(
            "Loaded in-memory sub-tree root {:?} does not match DB sub_root {:?} at (level={}, index={}, checkpoint_id={}); refusing to start with a corrupt tree",
            loaded_root,
            expected_sub_root,
            sub_root.level,
            sub_root.index,
            checkpoint_id
        );
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use parth_core::{
        crypto::hash::{merkle_proof::MerkleProofCore, traits::MerkleZeroHasher},
        data::hash::{
            checkpointed_merkle_node::CheckpointedMerkleHash, hash256::Hash256,
            merkle_node_key::SimpleMerkleNodeKey,
        },
    };
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_crypto::hash::sha256::CoreSha256Hasher;
    use psy_node_core::psy_core_db::traits::full::PsyNodeGlobalUserTreeDatabaseReader;

    use super::{fetch_global_user_tree_from_db_with_sub_root, load_global_user_tree_from_db_with_sub_root};

    /// Minimal in-memory reader: stores leaves and computes parents on demand using
    /// the same hasher the loader uses. Returns the leaf-level zero hash for absent
    /// leaves and the appropriate level zero for absent internal nodes.
    struct MockUserTreeReader {
        height: u8,
        leaves: Mutex<HashMap<u64, Hash256>>,
        node_overrides: Mutex<HashMap<SimpleMerkleNodeKey, Hash256>>,
    }

    impl MockUserTreeReader {
        fn new(height: u8) -> Self {
            Self {
                height,
                leaves: Mutex::new(HashMap::new()),
                node_overrides: Mutex::new(HashMap::new()),
            }
        }
        fn set_leaf(&self, index: u64, value: Hash256) {
            self.leaves.lock().unwrap().insert(index, value);
        }
        fn set_node_override(&self, key: SimpleMerkleNodeKey, value: Hash256) {
            self.node_overrides.lock().unwrap().insert(key, value);
        }
        fn node(&self, key: SimpleMerkleNodeKey) -> Hash256 {
            if let Some(value) = self.node_overrides.lock().unwrap().get(&key).copied() {
                return value;
            }
            if key.level == self.height {
                return self
                    .leaves
                    .lock()
                    .unwrap()
                    .get(&key.index)
                    .copied()
                    .unwrap_or_else(|| <CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(0));
            }
            let left = self.node(SimpleMerkleNodeKey::new(key.level + 1, key.index << 1));
            let right = self.node(SimpleMerkleNodeKey::new(key.level + 1, (key.index << 1) | 1));
            <CoreSha256Hasher as parth_core::crypto::hash::traits::MerkleHasher<Hash256>>::two_to_one(&left, &right)
        }
    }

    #[async_trait]
    impl PsyNodeGlobalUserTreeDatabaseReader<Hash256> for MockUserTreeReader {
        async fn global_user_tree_get_leaf_hash(&self, _cp: u64, leaf_index: u64) -> anyhow::Result<Hash256> {
            Ok(self.node(SimpleMerkleNodeKey::new(self.height, leaf_index)))
        }
        async fn global_user_tree_get_root_hash(&self, _cp: u64) -> anyhow::Result<Hash256> {
            Ok(self.node(SimpleMerkleNodeKey::new(0, 0)))
        }
        async fn global_user_tree_get_merkle_proof(&self, _cp: u64, _leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash256>> {
            unimplemented!()
        }
        async fn global_user_tree_get_merkle_proof_sub_tree(
            &self,
            _cp: u64,
            _root_level: u8,
            _leaf_level: u8,
            _leaf_index: u64,
        ) -> anyhow::Result<MerkleProofCore<Hash256>> {
            unimplemented!()
        }
        async fn global_user_tree_get_nodes(&self, _cp: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash256>> {
            Ok(keys.iter().map(|k| self.node(*k)).collect())
        }
        async fn global_user_tree_get_node(&self, _cp: u64, key: SimpleMerkleNodeKey) -> anyhow::Result<Hash256> {
            Ok(self.node(key))
        }
        async fn global_user_tree_dump_all_leaves(&self, _cp: u64) -> anyhow::Result<HashMap<u64, Hash256>> {
            unimplemented!()
        }
        async fn global_user_tree_dump_leaves_range(
            &self,
            _cp: u64,
            min_user_id_inclusive: u64,
            max_user_id_exclusive: u64,
        ) -> anyhow::Result<HashMap<u64, Hash256>> {
            if min_user_id_inclusive >= max_user_id_exclusive {
                return Ok(HashMap::new());
            }
            let zero = <CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(0);
            let leaves = self.leaves.lock().unwrap();
            Ok(leaves
                .iter()
                .filter(|(index, hash)| **index >= min_user_id_inclusive && **index < max_user_id_exclusive && **hash != zero)
                .map(|(index, hash)| (*index, *hash))
                .collect())
        }
        async fn global_user_tree_get_node_and_checkpoint_id_max_checkpoint(
            &self,
            _max_cp: u64,
            _key: &SimpleMerkleNodeKey,
        ) -> anyhow::Result<CheckpointedMerkleHash<Hash256>> {
            unimplemented!()
        }
    }

    /// Reproduces the production scenario: a sub-root at (level=12, index=1)
    /// in a tree of height 16 with many populated leaves spanning many fetch
    /// batches. Pre-fix the loader corrupted level on subsequent batches and
    /// returned an empty in-memory tree; post-fix the loaded tree's root must
    /// equal the DB sub-root value.
    #[tokio::test(flavor = "current_thread")]
    async fn loader_returns_correct_root_across_many_batches() {
        let tree_height: u8 = 16;
        let sub_root_level: u8 = 12;
        let sub_root_index: u64 = 1;
        let sub_tree_height = tree_height - sub_root_level; // 4
        let leaves_in_realm: u64 = 1u64 << sub_tree_height; // 16
        let leaf_min_index: u64 = sub_root_index << sub_tree_height;

        // Use a small fetch_batch_size so that many batches are exercised
        // (this is what triggers the level-mutation bug in the original code).
        let fetch_batch_size: usize = 3;

        let reader = MockUserTreeReader::new(tree_height);
        for i in 0..leaves_in_realm {
            // Non-zero leaf values
            let v = Hash256::from_u64_le_values(i + 1, 7, 9, 13);
            reader.set_leaf(leaf_min_index + i, v);
        }

        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let expected_root = reader.node(sub_root_key);

        let tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            17_198,
            leaf_min_index,
            leaf_min_index + leaves_in_realm,
            fetch_batch_size,
        )
        .await
        .expect("loader should succeed");

        assert_eq!(
            tree.get_root(),
            expected_root,
            "loaded in-memory sub-tree root must match DB sub-root value"
        );
    }

    /// Bonus: very small range (single batch + remainder) — also catches the
    /// remainder branch's level mutation.
    #[tokio::test(flavor = "current_thread")]
    async fn loader_returns_correct_root_with_remainder_only() {
        let tree_height: u8 = 8;
        let sub_root_level: u8 = 4;
        let sub_root_index: u64 = 3;
        let sub_tree_height = tree_height - sub_root_level; // 4
        let leaves_in_realm: u64 = 1u64 << sub_tree_height; // 16
        let leaf_min_index: u64 = sub_root_index << sub_tree_height;

        let reader = MockUserTreeReader::new(tree_height);
        for i in 0..leaves_in_realm {
            reader.set_leaf(leaf_min_index + i, Hash256::from_u64_le_values(i * 17 + 1, 0, 0, 0));
        }

        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let expected_root = reader.node(sub_root_key);

        // 5 leaves per batch, 16 / 5 = 3 full batches + remainder of 1
        let tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            1,
            leaf_min_index,
            leaf_min_index + leaves_in_realm,
            5,
        )
        .await
        .expect("loader should succeed");

        assert_eq!(tree.get_root(), expected_root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn empty_range_returns_empty_tree() {
        let tree_height: u8 = 8;
        let sub_root_key = SimpleMerkleNodeKey { level: 4, index: 1 };
        let leaf_min = 1u64 << 4;
        let reader = MockUserTreeReader::new(tree_height);
        let tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            1,
            leaf_min,
            leaf_min,
            8,
        )
        .await
        .expect("empty range should succeed");
        assert_eq!(
            tree.get_root(),
            <CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(4)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn current_overwrite_then_zero_filters_leaf_zero_hash() {
        let tree_height: u8 = 8;
        let sub_root_level: u8 = 4;
        let sub_root_index: u64 = 2;
        let leaf_min = sub_root_index << (tree_height - sub_root_level);
        let reader = MockUserTreeReader::new(tree_height);
        let idx = leaf_min + 3;
        let first = Hash256::from_u64_le_values(11, 0, 0, 0);
        let second = Hash256::from_u64_le_values(22, 0, 0, 0);
        reader.set_leaf(idx, first);
        reader.set_leaf(idx, second);
        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let expected = reader.node(sub_root_key);
        let tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            9,
            leaf_min,
            leaf_min + 16,
            4,
        )
        .await
        .expect("overwrite fetch");
        assert_eq!(tree.get_root(), expected);

        reader.set_leaf(idx, <CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(0));
        let expected_zeroed = reader.node(sub_root_key);
        let tree_zeroed = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            9,
            leaf_min,
            leaf_min + 16,
            4,
        )
        .await
        .expect("zeroed fetch");
        assert_eq!(tree_zeroed.get_root(), expected_zeroed);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nonzero_realm_offset_loads_local_indexes() {
        let tree_height: u8 = 8;
        let sub_root_level: u8 = 4;
        let sub_root_index: u64 = 3;
        let leaf_min = sub_root_index << (tree_height - sub_root_level);
        let reader = MockUserTreeReader::new(tree_height);
        reader.set_leaf(leaf_min + 1, Hash256::from_u64_le_values(3, 1, 4, 1));
        reader.set_leaf(leaf_min + 15, Hash256::from_u64_le_values(5, 9, 2, 6));
        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let expected = reader.node(sub_root_key);
        let tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            4,
            leaf_min,
            leaf_min + 16,
            7,
        )
        .await
        .expect("offset realm");
        assert_eq!(tree.get_root(), expected);
    }

    /// Corrupt leaf inside the dumped range, with only the sub-root node
    /// overridden to the honest value. No parent nodes are stored. Loader's
    /// root-equality check must fail.
    #[tokio::test(flavor = "current_thread")]
    async fn corrupt_dumped_leaf_mismatches_honest_sub_root() {
        let tree_height: u8 = 8;
        let sub_root_level: u8 = 4;
        let sub_root_index: u64 = 1;
        let leaf_min = sub_root_index << (tree_height - sub_root_level);
        let honest = MockUserTreeReader::new(tree_height);
        honest.set_leaf(leaf_min + 2, Hash256::from_u64_le_values(8, 8, 8, 8));
        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let honest_root = honest.node(sub_root_key);

        let corrupt = MockUserTreeReader::new(tree_height);
        corrupt.set_leaf(leaf_min + 2, Hash256::from_u64_le_values(9, 9, 9, 9));
        corrupt.set_node_override(sub_root_key, honest_root);

        let err = load_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &corrupt,
            tree_height,
            sub_root_key,
            1,
            8,
        )
        .await
        .expect_err("corrupt leaf must fail root equality");
        let msg = format!("{err:#}");
        assert!(msg.contains("does not match DB sub_root"), "{msg}");
    }

    /// Test-only D0 dense `rehash_range` vs production sparse loader on the same leaves.
    #[tokio::test(flavor = "current_thread")]
    async fn old_point_batches_match_range_same_leaf_set() {
        let tree_height: u8 = 8;
        let sub_root_level: u8 = 4;
        let sub_root_index: u64 = 1;
        let leaf_min = sub_root_index << (tree_height - sub_root_level);
        let reader = MockUserTreeReader::new(tree_height);
        for i in 0..16u64 {
            if i % 3 == 0 {
                continue;
            }
            reader.set_leaf(leaf_min + i, Hash256::from_u64_le_values(i + 1, 2, 3, 4));
        }
        let sub_root_key = SimpleMerkleNodeKey { level: sub_root_level, index: sub_root_index };
        let expected = reader.node(sub_root_key);

        let range_tree = fetch_global_user_tree_from_db_with_sub_root::<CoreSha256Hasher, _, Hash256>(
            &reader,
            tree_height,
            sub_root_key,
            1,
            leaf_min,
            leaf_min + 16,
            5,
        )
        .await
        .expect("range path");

        let mut keys = Vec::with_capacity(16);
        for i in 0..16u64 {
            keys.push(SimpleMerkleNodeKey { level: tree_height, index: leaf_min + i });
        }
        let point = reader.global_user_tree_get_nodes(1, &keys).await.unwrap();
        let zero = <CoreSha256Hasher as MerkleZeroHasher<Hash256>>::get_zero_hash(0);
        let mut point_map = HashMap::new();
        for (i, hash) in point.into_iter().enumerate() {
            if hash != zero {
                point_map.insert(
                    SimpleMerkleNodeKey { level: 4, index: i as u64 },
                    hash,
                );
            }
        }
        // D0 dense writer, test-only — production loader no longer calls rehash_range.
        let mut point_tree = SimpleMemoryMerkleRecorderStore::<CoreSha256Hasher, Hash256>::from_hash_map(4, point_map);
        point_tree.rehash_range(4, 0, 16);

        assert_eq!(range_tree.get_root(), expected);
        assert_eq!(point_tree.get_root(), expected);
        assert_eq!(range_tree.get_root(), point_tree.get_root());

    }
}
