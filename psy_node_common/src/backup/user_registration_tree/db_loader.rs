use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use psy_node_core::psy_core_db::traits::full::PsyNodeUserRegistrationTreeDatabaseReader;

pub async fn load_global_user_registration_tree_append_only_pivot_from_db<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeUserRegistrationTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    user_db_reader: &Store,
    tree_height: u8,
    checkpoint_id: u64,
) -> anyhow::Result<(u64, SimpleMemoryMerkleRecorderStore<Hasher, Hash>)> {
    let mut current_key = SimpleMerkleNodeKey::new_root();
    let mut current_value = user_db_reader.user_registration_tree_get_leaf_hash(checkpoint_id, current_key.index).await?;
    if current_value == Hasher::get_zero_hash(0) {
        // Tree is empty
        return Ok((0, SimpleMemoryMerkleRecorderStore::new(tree_height)));
    }
    while current_key.level < tree_height {
        let right_child_key = current_key.right_child();
        let zero_hash_at_level = Hasher::get_zero_hash(right_child_key.level as usize);

        let right_child_value = user_db_reader.user_registration_tree_get_leaf_hash(checkpoint_id, right_child_key.index).await?;
        let right_is_empty = right_child_value == zero_hash_at_level;

        if !right_is_empty {
            current_key = right_child_key;
            current_value = right_child_value;
        } else {
            let left_child_key = current_key.left_child();

            let left_child_value = user_db_reader.user_registration_tree_get_leaf_hash(checkpoint_id, left_child_key.index).await?;
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
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
        // Tree is empty
        anyhow::bail!("Failed to load global user tree from DB: reached leaf node with zero hash, but root is not zero hash");
    }
    let merkle_proof_a = user_db_reader.user_registration_tree_get_merkle_proof(checkpoint_id, current_key.index).await?;
    let next_user_id = current_key.index + 1;
    let merkle_proof_b = user_db_reader.user_registration_tree_get_merkle_proof(checkpoint_id, next_user_id).await?;

    let mut tree = SimpleMemoryMerkleRecorderStore::new(tree_height);
    tree.injest_merkle_proof(&merkle_proof_a)?;
    tree.injest_merkle_proof(&merkle_proof_b)?;
    println!("Loaded user registration tree up to user ID {}, with root hash {:?}", next_user_id, tree.get_root());
    Ok((next_user_id, tree))
}
