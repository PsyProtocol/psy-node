use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use psy_node_core::psy_core_db::traits::full::PsyNodeUserRegistrationTreeDatabaseReader;

pub async fn load_append_only_user_registration_tree_into_memory<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeUserRegistrationTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    checkpoint_id: u64,
    start_index: u64,
    end_index: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<()> {
    let first = user_db_reader.user_registration_tree_get_merkle_proof(checkpoint_id, start_index).await?;
    tree.injest_merkle_proof(&first)?;

    let tree_height = tree.get_height();
    let complete_batches = (end_index - start_index) / fetch_batch_size as u64;
    let remainder = (end_index - start_index) % fetch_batch_size as u64;
    let mut keys = if complete_batches > 0 {
        vec![
            SimpleMerkleNodeKey {
                level: tree_height,
                index: 0,
            };
            fetch_batch_size
        ]
    } else {
        vec![
            SimpleMerkleNodeKey {
                level: tree_height,
                index: 0,
            };
            remainder as usize
        ]
    };

    for batch_index in 0..complete_batches {
        let start_user_id = start_index + batch_index * fetch_batch_size as u64;
        for i in 0..fetch_batch_size {
            let index = start_user_id + i as u64;
            keys[i].index = index;
        }
        let nodes = user_db_reader.user_registration_tree_get_nodes(checkpoint_id, &keys).await?;
        for (i, node) in nodes.iter().enumerate() {
            tree.set_leaf(keys[i].index, *node);
        }
    }
    for i in 0..remainder as usize {
        let index = start_index + complete_batches * fetch_batch_size as u64 + i as u64;
        keys[i].index = index;
    }
    if remainder > 0 {
        let nodes = user_db_reader
            .user_registration_tree_get_nodes(checkpoint_id, &keys[..remainder as usize])
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            tree.set_leaf(keys[i].index, *node);
        }
    }
    tree.injest_merkle_proof(&first)?;
    let last = user_db_reader.user_registration_tree_get_merkle_proof(checkpoint_id, end_index).await?;
    tree.injest_merkle_proof(&last)?;

    Ok(())
}

pub async fn load_global_user_registration_tree_append_only_pivot_from_db<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeUserRegistrationTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,
    tree_height: u8,
    checkpoint_id: u64,
    required_previous_leaves: usize,
) -> anyhow::Result<(u64, SimpleMemoryMerkleRecorderStore<Hasher, Hash>)> {
    let mut current_key = SimpleMerkleNodeKey::new_root();
    let mut current_value = user_db_reader.user_registration_tree_get_node(checkpoint_id, current_key).await?;
    let root = current_value;
    println!("Current root hash: {:?}", current_value);
    println!("Zero hash at root level: {:?}", Hasher::get_zero_hash(tree_height as usize));
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
        tracing::info!("User registration tree is empty at checkpoint ID {}", checkpoint_id);
        // Tree is empty
        return Ok((0, SimpleMemoryMerkleRecorderStore::new(tree_height)));
    }
    while current_key.level < tree_height {
        let right_child_key = current_key.right_child();
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - right_child_key.level) as usize);

        let right_child_value = user_db_reader.user_registration_tree_get_node(checkpoint_id, right_child_key).await?;
        let right_is_empty = right_child_value == zero_hash_at_level;

        if !right_is_empty {
            current_key = right_child_key;
            current_value = right_child_value;
        } else {
            let left_child_key = current_key.left_child();

            let left_child_value = user_db_reader.user_registration_tree_get_node(checkpoint_id, left_child_key).await?;
            let left_is_empty = left_child_value == zero_hash_at_level;

            if !left_is_empty {
                current_key = left_child_key;
                current_value = left_child_value;
            } else {
                // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
                // ensure the root is not a zero hash
                anyhow::bail!("Failed to load user registration tree from DB: reached leaf node with zero hash, but root is not zero hash");
            }
        }
    }
    // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
    // ensure the root is not a zero hash
    if current_value == Hasher::get_zero_hash(0) {
        // Tree is empty
        anyhow::bail!("Failed to load user registration tree from DB: reached leaf node with zero hash, but root is not zero hash");
    }
    let merkle_proof_a = user_db_reader
        .user_registration_tree_get_merkle_proof(checkpoint_id, current_key.index)
        .await?;
    println!("merkle_proof_a: {:#?}", merkle_proof_a);
    if !merkle_proof_a.verify::<Hasher>() {
        anyhow::bail!(
            "Failed to verify merkle proof for user registration tree up to user ID {}",
            current_key.index
        );
    }
    if merkle_proof_a.root != root {
        anyhow::bail!(
            "Loaded user registration tree root hash {:?} does not match expected root hash {:?}",
            merkle_proof_a.root,
            root
        );
    }
    let mut tree = SimpleMemoryMerkleRecorderStore::new(tree_height);
    let real_required_previous_leaves = (required_previous_leaves as u64).min(current_key.index);
    let start_required_user_id = current_key.index - real_required_previous_leaves;
    println!("start_required_user_id: {}", start_required_user_id);
    if start_required_user_id > current_key.index {
        anyhow::bail!(
            "start_required_user_id {} is greater than current key index {}",
            start_required_user_id,
            current_key.index
        );
    }

    if start_required_user_id != current_key.index {
        // We need to fetch the previous leaves to ensure we have enough leaves for the
        // append operation
        let value = user_db_reader
            .user_registration_tree_get_node(checkpoint_id, SimpleMerkleNodeKey::new(tree_height, start_required_user_id))
            .await?;
        if value == Hasher::get_zero_hash(0) {
            anyhow::bail!(
                "Failed to load user registration tree from DB: leaf node for user ID {} is zero hash, but tree root is not zero hash",
                start_required_user_id
            );
        }
        load_append_only_user_registration_tree_into_memory::<Hasher, Store, Hash>(
            user_db_reader,
            &mut tree,
            checkpoint_id,
            start_required_user_id,
            current_key.index,
            128,
        )
        .await?;
    }

    let next_user_id = current_key.index + 1;
    let merkle_proof_b = user_db_reader
        .user_registration_tree_get_merkle_proof(checkpoint_id, next_user_id)
        .await?;

    if !merkle_proof_b.verify::<Hasher>() {
        anyhow::bail!("Failed to verify merkle proof for user registration tree up to user ID {}", next_user_id);
    }

    tree.injest_merkle_proof(&merkle_proof_b)?;
    tree.injest_merkle_proof(&merkle_proof_a)?;
    if tree.get_root() != root {
        anyhow::bail!(
            "Loaded user registration tree root hash {:?} does not match expected root hash {:?}",
            tree.get_root(),
            root
        );
    }

    let pre_next_leaf_id = tree.get_leaf_value(next_user_id - 1);
    if pre_next_leaf_id == Hasher::get_zero_hash(0) {
        anyhow::bail!(
            "Failed to load user registration tree from DB: leaf node for user ID {} is zero hash, but tree root is not zero hash",
            next_user_id - 1
        );
    }
    println!("next_user_id: {}", next_user_id);

    println!(
        "Loaded user registration tree up to user ID {}, with root hash {:?}",
        next_user_id,
        tree.get_root()
    );
    Ok((next_user_id, tree))
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::psy_core_db::traits::full::{
        PsyNodeUserRegistrationTreeDatabaseReader,
        PsyNodeUserRegistrationTreeDatabaseWriter,
    };

    use crate::test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore};

    use super::*;

    type Hasher = PoseidonHasher;
    type Hash = PHash;

    const HEIGHT: u8 = TestNetworkConfig::GLOBAL_USER_TREE_HEIGHT;
    const CP: u64 = 3;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    fn leaf(i: u64) -> Hash {
        PHash::from_values(i * 16 + 1, 0x0AAA_1BBB_2CCC_3DDD, i + 17, 0x7DDD_6CCC_5BBB_4AAA)
    }

    async fn seed_leaves(db: &TestUnifiedDatabaseStore, checkpoint_id: u64, count: u64) -> anyhow::Result<()> {
        for i in 0..count {
            db.user_registration_tree_set_leaf_hash(checkpoint_id, i, leaf(i)).await?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn append_only_load_populates_leaves_across_complete_batches_and_remainder() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 13).await?;

        // 12 leaves to load with batch size 5: two complete batches + remainder of 2
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(HEIGHT);
        load_append_only_user_registration_tree_into_memory(&db, &mut tree, CP, 0, 12, 5).await?;

        for i in 0..=12u64 {
            assert_eq!(tree.get_leaf_value(i), leaf(i), "leaf {i} must match the db value");
        }
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        Ok(())
    }

    #[tokio::test]
    async fn append_only_load_with_exact_batch_multiple_skips_remainder() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 11).await?;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(HEIGHT);
        load_append_only_user_registration_tree_into_memory(&db, &mut tree, CP, 0, 10, 5).await?;

        for i in 0..=10u64 {
            assert_eq!(tree.get_leaf_value(i), leaf(i));
        }
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        Ok(())
    }

    #[tokio::test]
    async fn append_only_load_from_non_zero_start_index() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 9).await?;

        // loading a tail window [4, 8) still reconstructs the full root because
        // the leading proof at index 4 pulls in all left-side siblings
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(HEIGHT);
        load_append_only_user_registration_tree_into_memory(&db, &mut tree, CP, 4, 8, 3).await?;

        for i in 4..=8u64 {
            assert_eq!(tree.get_leaf_value(i), leaf(i));
        }
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_on_empty_tree_returns_zero_next_id_and_empty_root() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        let (next_user_id, tree) =
            load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, HEIGHT, 0, 4).await?;

        assert_eq!(next_user_id, 0);
        assert_eq!(tree.get_root(), zh(HEIGHT as usize));
        assert_eq!(tree.get_leaf_value(0), zh(0));
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_returns_next_user_id_with_matching_root_and_last_leaf() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 5).await?;

        // pivot lands on the rightmost non-zero leaf (id 4); two previous leaves
        // are pulled in on top of it
        let (next_user_id, tree) =
            load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, HEIGHT, CP, 2).await?;

        assert_eq!(next_user_id, 5);
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        assert_eq!(tree.get_leaf_value(4), leaf(4));
        assert_eq!(tree.get_leaf_value(2), leaf(2));
        // the next append slot is still empty
        assert_eq!(tree.get_leaf_value(5), zh(0));
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_rejects_gap_in_append_only_user_registration_tree() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        // An append-only tree cannot have an empty history followed by an occupied
        // leaf. With the pivot at 4 and a two-leaf history window, leaf 2 is the
        // integrity-check target and must be rejected as an empty leaf.
        db.user_registration_tree_set_leaf_hash(CP, 4, leaf(4)).await?;

        let result = load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(
            &db, HEIGHT, CP, 2,
        )
        .await;

        assert!(result.is_err(), "sparse append-only user-registration tree must be rejected");
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_clamps_required_previous_leaves_to_available_history() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 5).await?;

        // required=100 but only ids 0..=4 exist: the whole history is loaded
        let (next_user_id, tree) =
            load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, HEIGHT, CP, 100).await?;

        assert_eq!(next_user_id, 5);
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        assert_eq!(tree.get_leaf_value(0), leaf(0));
        assert_eq!(tree.get_leaf_value(4), leaf(4));
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_with_zero_required_previous_leaves_skips_bulk_fetch() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, CP, 5).await?;

        let (next_user_id, tree) =
            load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, HEIGHT, CP, 0).await?;

        // only the two pivot proofs are injested, but the root still matches
        assert_eq!(next_user_id, 5);
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(CP).await?);
        assert_eq!(tree.get_leaf_value(4), leaf(4));
        Ok(())
    }

    #[tokio::test]
    async fn pivot_load_reads_the_latest_committed_version_at_or_before_checkpoint() -> anyhow::Result<()> {
        let db = create_test_unified_db().await?;
        seed_leaves(&db, 1, 5).await?;
        // checkpoint 2 adds nothing, so reading at 2 must still see version 1
        let (next_user_id, tree) =
            load_global_user_registration_tree_append_only_pivot_from_db::<Hasher, TestUnifiedDatabaseStore, Hash>(&db, HEIGHT, 2, 2).await?;

        assert_eq!(next_user_id, 5);
        assert_eq!(tree.get_root(), db.user_registration_tree_get_root_hash(1).await?);
        Ok(())
    }
}
