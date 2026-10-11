use std::collections::HashMap;

use cf_utils::timer::TraceTimer;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use psy_node_core::psy_core_db::traits::full::PsyNodeGlobalUserTreeDatabaseReader;

pub async fn fetch_global_user_tree_from_db<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalUserTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,

    tree_height: u8,
    effective_tree_height: u8,
    checkpoint_id: u64,
    min_user_id_inclusive: u64,
    max_user_id_exclusive: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<SimpleMemoryMerkleRecorderStore<Hasher, Hash>> {
    let mut timer = TraceTimer::new("fetch_global_user_tree_from_db");

    tracing::info!(
        "Fetching global user tree nodes from DB (checkpoint_id={}, tree_height={}, effective_tree_height={}, user_id_range=[{}, {}), fetch_batch_size={})",
        checkpoint_id,
        tree_height,
        effective_tree_height,
        min_user_id_inclusive,
        max_user_id_exclusive,
        fetch_batch_size
    );
    let mut node_hash_map = HashMap::<SimpleMerkleNodeKey, Hash>::new();
    let total = max_user_id_exclusive - min_user_id_inclusive;
    // DB stores nodes at `effective_tree_height`; each entry is the root of a sub-tree of
    // height `tree_height - effective_tree_height`, so empty entries come back as that
    // sub-tree's zero hash, not the full-tree-root zero hash.
    let zero_hash = Hasher::get_zero_hash((tree_height - effective_tree_height) as usize);
    let full_batches = total / fetch_batch_size as u64;
    let remainder = total % fetch_batch_size as u64;
    let mut keys = if full_batches > 0 {
        vec![
            SimpleMerkleNodeKey {
                level: effective_tree_height,
                index: 0,
            };
            fetch_batch_size
        ]
    } else {
        vec![
            SimpleMerkleNodeKey {
                level: effective_tree_height,
                index: 0,
            };
            remainder as usize
        ]
    };
    timer.start();
    for batch_index in 0..full_batches {
        let start_user_id = min_user_id_inclusive + batch_index * fetch_batch_size as u64;
        for i in 0..fetch_batch_size {
            let index = start_user_id + i as u64;
            keys[i].index = index;
        }
        let batch_results = user_db_reader.global_user_tree_get_nodes(checkpoint_id, &keys).await?;
        for (i, hash) in batch_results.iter().enumerate() {
            if hash != &zero_hash {
                node_hash_map.insert(keys[i], *hash);
            }
        }
    }
    if remainder > 0 {
        let start_user_id = min_user_id_inclusive + full_batches * fetch_batch_size as u64;
        for i in 0..remainder as usize {
            let index = start_user_id + i as u64;
            keys[i].index = index;
        }
        let batch_results = user_db_reader
            .global_user_tree_get_nodes(checkpoint_id, &keys[0..remainder as usize])
            .await?;
        for (i, hash) in batch_results.iter().enumerate() {
            if hash != &zero_hash {
                node_hash_map.insert(keys[i], *hash);
            }
        }
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

    let mut tree = SimpleMemoryMerkleRecorderStore::from_hash_map(tree_height, node_hash_map);

    tree.set_effective_height(effective_tree_height);
    timer.start();
    tree.rehash_range(effective_tree_height, min_user_id_inclusive, max_user_id_exclusive);
    timer.lap_batch("rehashed global user tree nodes", "node", (max_user_id_exclusive - min_user_id_inclusive) as usize);
    tree.commit_changes();
    timer.lap("committed changes to memory global user tree");

    Ok(tree)
}

pub async fn load_global_user_tree_from_db<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalUserTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,
    tree_height: u8,
    effective_tree_height: u8,
    checkpoint_id: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<SimpleMemoryMerkleRecorderStore<Hasher, Hash>> {
    assert!(effective_tree_height <= tree_height, "effective_tree_height must be less than or equal to tree_height");
    let mut current_key = SimpleMerkleNodeKey::new_root();
    let mut current_value = user_db_reader.global_user_tree_get_node(checkpoint_id, current_key).await?;
    // Capture the actual tree root BEFORE descent overwrites current_value with sub-tree
    // node values. The post-load sanity check compares the loaded in-memory root against
    // this, not against current_value which gets clobbered during the descent.
    let root_value = current_value;
    println!("Current root hash: {:?}", current_value);
    println!("Zero hash at root level: {:?}", Hasher::get_zero_hash(tree_height as usize));
    println!("zero hash of effective tree height: {:?}", Hasher::get_zero_hash((effective_tree_height) as usize));
    println!("zero hash of at leaves: {:?}", Hasher::get_zero_hash((tree_height - effective_tree_height) as usize));
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
        // Tree is empty
        let mut tree = SimpleMemoryMerkleRecorderStore::new(tree_height);
        tree.set_effective_height(effective_tree_height);
        return Ok(tree);
    }
    while current_key.level < effective_tree_height {
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
    if current_value == Hasher::get_zero_hash((tree_height - effective_tree_height) as usize) {
        // Tree is empty
        anyhow::bail!("Failed to load global user tree from DB: reached leaf node with zero hash, but root is not zero hash");
    }
    // current_key sits at level = effective_tree_height after descent, so its index is
    // already in effective-level units. The inner fetcher queries at (level=effective_tree_height,
    // index=...), so we must keep the upper bound in the same unit — do NOT shift it up to
    // tree_height units, otherwise we'd iterate ~2^(tree_height-effective_tree_height) times
    // more than there are valid level-effective_tree_height indices and end up filling the
    // hashmap with out-of-range garbage that breaks rehash.
    let max_user_id_exclusive = current_key.index + 1;
    println!("max_user_id_exclusive: {}", max_user_id_exclusive);
    let tree = fetch_global_user_tree_from_db::<Hasher, Store, Hash>(
        user_db_reader,
        tree_height,
        effective_tree_height,
        checkpoint_id,
        0,
        max_user_id_exclusive,
        fetch_batch_size,
    )
    .await?;

    let loaded_root = tree.get_root();
    if loaded_root != root_value {
        anyhow::bail!(
            "Loaded in-memory global user tree root {:?} does not match DB root {:?} at checkpoint_id={}; refusing to start with a corrupt tree",
            loaded_root,
            root_value,
            checkpoint_id
        );
    }
    Ok(tree)
}

#[cfg(test)]
mod tests {
    use parth_core::{data::hash::merkle_node_key::SimpleMerkleNodeKey, pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeGlobalUserTreeDatabaseReader,
        PsyNodeGlobalUserTreeDatabaseWriter,
    };

    use crate::test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore};

    use super::*;

    type Hasher = PoseidonHasher;
    type Hash = PHash;

    const TREE_HEIGHT: u8 = TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT;
    const EFFECTIVE_HEIGHT: u8 = TestNetworkConfig::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;
    /// leaves of the full tree covered by one effective-level node
    const SUB_LEAVES: u64 = 1u64 << (TREE_HEIGHT - EFFECTIVE_HEIGHT);
    const CP: u64 = 7;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn leaf(i: u64) -> Hash {
        PHash::from_values(i * 16 + 3, 0x1F2E_3D4C_5B6A_7988, i + 29, 0x8879_6A5B_4C3D_2E1F)
    }

    /// Seeds leaves so exactly effective-level nodes 0 and 1 are non-zero.
    async fn seed_two_effective_slots(db: &TestUnifiedDatabaseStore) -> anyhow::Result<()> {
        db.global_user_tree_set_leaf_hash(CP, 0, leaf(0)).await?;
        db.global_user_tree_set_leaf_hash(CP, SUB_LEAVES + 3, leaf(1)).await?;
        Ok(())
    }

    #[tokio::test]
    async fn fetch_rebuilds_tree_root_from_effective_level_nodes() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_two_effective_slots(&db).await?;

        let tree = fetch_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(
            &db,
            TREE_HEIGHT,
            EFFECTIVE_HEIGHT,
            CP,
            0,
            2,
            2,
        )
        .await?;

        assert_eq!(tree.get_height(), TREE_HEIGHT);
        assert_eq!(tree.get_effective_height(), EFFECTIVE_HEIGHT);
        assert_eq!(tree.get_root(), db.global_user_tree_get_root_hash(CP).await?);
        assert_eq!(
            tree.get_e_leaf_value(0),
            db.global_user_tree_get_node(CP, SimpleMerkleNodeKey::new(EFFECTIVE_HEIGHT, 0)).await?
        );
        assert_eq!(
            tree.get_e_leaf_value(1),
            db.global_user_tree_get_node(CP, SimpleMerkleNodeKey::new(EFFECTIVE_HEIGHT, 1)).await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn fetch_of_empty_range_yields_empty_root() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        // nothing seeded: every fetched node is the sub-tree zero hash and filtered out
        let tree = fetch_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(
            &db,
            TREE_HEIGHT,
            EFFECTIVE_HEIGHT,
            CP,
            0,
            4,
            2,
        )
        .await?;

        assert_eq!(tree.get_root(), zh(TREE_HEIGHT as usize));
        assert_eq!(tree.get_root(), db.global_user_tree_get_root_hash(CP).await?);
        Ok(())
    }

    #[tokio::test]
    async fn fetch_handles_full_batches_plus_remainder() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_two_effective_slots(&db).await?;

        // range of 5 with batch 2: two complete batches + one remainder item;
        // effective slots 2..=4 are empty and must be filtered as zeros
        let tree = fetch_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(
            &db,
            TREE_HEIGHT,
            EFFECTIVE_HEIGHT,
            CP,
            0,
            5,
            2,
        )
        .await?;

        assert_eq!(tree.get_root(), db.global_user_tree_get_root_hash(CP).await?);
        assert_eq!(tree.get_e_leaf_value(2), zh((TREE_HEIGHT - EFFECTIVE_HEIGHT) as usize));
        Ok(())
    }

    #[tokio::test]
    async fn load_on_empty_db_returns_empty_tree_with_effective_height_set() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        let tree = load_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, TREE_HEIGHT, EFFECTIVE_HEIGHT, 0, 100).await?;

        assert_eq!(tree.get_root(), zh(TREE_HEIGHT as usize));
        assert_eq!(tree.get_height(), TREE_HEIGHT);
        assert_eq!(tree.get_effective_height(), EFFECTIVE_HEIGHT);
        Ok(())
    }

    #[tokio::test]
    async fn load_descends_to_rightmost_effective_node_and_matches_db_root() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_two_effective_slots(&db).await?;

        let tree = load_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, TREE_HEIGHT, EFFECTIVE_HEIGHT, CP, 1000).await?;

        assert_eq!(tree.get_root(), db.global_user_tree_get_root_hash(CP).await?);
        assert_eq!(
            tree.get_e_leaf_value(0),
            db.global_user_tree_get_node(CP, SimpleMerkleNodeKey::new(EFFECTIVE_HEIGHT, 0)).await?
        );
        assert_eq!(
            tree.get_e_leaf_value(1),
            db.global_user_tree_get_node(CP, SimpleMerkleNodeKey::new(EFFECTIVE_HEIGHT, 1)).await?
        );
        Ok(())
    }

    #[tokio::test]
    #[should_panic(expected = "effective_tree_height must be less than or equal to tree_height")]
    async fn load_rejects_effective_height_above_tree_height() {
        let db = create_test_unified_db().await.expect("db");
        let _ = load_global_user_tree_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, TREE_HEIGHT, TREE_HEIGHT + 1, 0, 10).await;
    }
}
