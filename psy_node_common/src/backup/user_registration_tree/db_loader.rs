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
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
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
        if value == Hasher::get_zero_hash(tree_height as usize) {
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
