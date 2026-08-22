use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey};
use psy_node_core::psy_core_db::traits::full::PsyNodeGlobalContractTreeDatabaseReader;

pub async fn load_append_only_global_contract_tree_into_memory<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalContractTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    contract_db_reader: &Store,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    checkpoint_id: u64,
    start_index: u64,
    end_index: u64,
    fetch_batch_size: usize,
) -> anyhow::Result<()> {
    let first = contract_db_reader.global_contract_tree_get_merkle_proof(checkpoint_id, start_index).await?;
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
        let nodes = contract_db_reader.global_contract_tree_get_nodes(checkpoint_id, &keys).await?;
        for (i, node) in nodes.iter().enumerate() {
            tree.set_leaf(keys[i].index, *node);
        }
    }
    for i in 0..remainder as usize {
        let index = start_index + complete_batches * fetch_batch_size as u64 + i as u64;
        keys[i].index = index;
    }
    if remainder > 0 {
        let nodes = contract_db_reader
            .global_contract_tree_get_nodes(checkpoint_id, &keys[..remainder as usize])
            .await?;
        for (i, node) in nodes.iter().enumerate() {
            tree.set_leaf(keys[i].index, *node);
        }
    }
    tree.injest_merkle_proof(&first)?;
    let last = contract_db_reader.global_contract_tree_get_merkle_proof(checkpoint_id, end_index).await?;
    tree.injest_merkle_proof(&last)?;

    Ok(())
}
pub async fn load_global_contract_tree_append_only_pivot_from_db<
    Hasher: MerkleZeroHasher<Hash>,
    Store: PsyNodeGlobalContractTreeDatabaseReader<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug,
>(
    contract_db_reader: &Store,
    tree_height: u8,
    checkpoint_id: u64,
    required_previous_leaves: usize,
) -> anyhow::Result<(u64, SimpleMemoryMerkleRecorderStore<Hasher, Hash>)> {let mut current_key = SimpleMerkleNodeKey::new_root();
    let mut current_value = contract_db_reader.global_contract_tree_get_node(checkpoint_id, current_key).await?;
    let root = current_value;
    println!("Current root hash: {:?}", current_value);
    println!("Zero hash at root level: {:?}", Hasher::get_zero_hash(tree_height as usize));
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
        tracing::info!("Global Contract Tree is empty at checkpoint ID {}", checkpoint_id);
        // Tree is empty
        return Ok((0, SimpleMemoryMerkleRecorderStore::new(tree_height)));
    }
    while current_key.level < tree_height {
        let right_child_key = current_key.right_child();
        let zero_hash_at_level = Hasher::get_zero_hash((tree_height - right_child_key.level) as usize);

        let right_child_value = contract_db_reader.global_contract_tree_get_node(checkpoint_id, right_child_key).await?;
        let right_is_empty = right_child_value == zero_hash_at_level;

        if !right_is_empty {
            current_key = right_child_key;
            current_value = right_child_value;
        } else {
            let left_child_key = current_key.left_child();

            let left_child_value = contract_db_reader.global_contract_tree_get_node(checkpoint_id, left_child_key).await?;
            let left_is_empty = left_child_value == zero_hash_at_level;

            if !left_is_empty {
                current_key = left_child_key;
                current_value = left_child_value;
            } else {
                // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
                // ensure the root is not a zero hash
                anyhow::bail!("Failed to load Global Contract Tree from DB: reached leaf node with zero hash, but root is not zero hash");
            }
        }
    }
    // SANITY CHECK: ensure the leaf node is not zero hash, as we already checked to
    // ensure the root is not a zero hash
    if current_value == Hasher::get_zero_hash(tree_height as usize) {
        // Tree is empty
        anyhow::bail!("Failed to load Global Contract Tree from DB: reached leaf node with zero hash, but root is not zero hash");
    }
    let merkle_proof_a = contract_db_reader
        .global_contract_tree_get_merkle_proof(checkpoint_id, current_key.index)
        .await?;
    println!("merkle_proof_a: {:#?}", merkle_proof_a);
    if !merkle_proof_a.verify::<Hasher>() {
        anyhow::bail!(
            "Failed to verify merkle proof for Global Contract Tree up to contract id {}",
            current_key.index
        );
    }
    if merkle_proof_a.root != root {
        anyhow::bail!(
            "Loaded Global Contract Tree root hash {:?} does not match expected root hash {:?}",
            merkle_proof_a.root,
            root
        );
    }
    let mut tree = SimpleMemoryMerkleRecorderStore::new(tree_height);
    let real_required_previous_leaves = (required_previous_leaves as u64).min(current_key.index);
    // Aligned down to the sub-tree the append will be proved over, not simply
    // counted back from the frontier.
    //
    // `required_previous_leaves` is the number of leaves one batch sub-tree
    // holds, so counting back that many covers *enough* leaves -- but starting
    // part way into an older sub-tree leaves the leaves below the start absent,
    // and absent is not a state this tree can express: `get_node_value` answers
    // any node it does not hold with the zero hash for that level.
    //
    // What that costs is not a wasted read.  `find_next_append_index` looks for
    // the first node whose value is the zero hash, so it walks into the hole and
    // returns an index that is already taken.  The append then proves against
    // the wrong sub-tree with fabricated empty old leaves, and the circuit --
    // which joins the proof's record of the sub-tree root to the root it
    // recomputes from those leaves, unconditionally -- dies during witness
    // generation naming a wire and nothing else.
    //
    // Seen exactly once and it stopped the chain: 264 contracts, a window
    // starting at 7, leaves 0..5 absent, and every deploy afterwards proved
    // against sub-tree 0 while the next free slot was 264.
    //
    // Rounding down adds fewer than one sub-tree's worth of leaves, so the cost
    // is bounded however large the tree gets.
    let alignment = (required_previous_leaves as u64).max(1);
    let start_required_contract_id =
        ((current_key.index - real_required_previous_leaves) / alignment) * alignment;
    println!("start_required_contract_id: {}", start_required_contract_id);
    if start_required_contract_id > current_key.index {
        anyhow::bail!(
            "start_required_contract_id {} is greater than current key index {}",
            start_required_contract_id,
            current_key.index
        );
    }

    if start_required_contract_id != current_key.index {
        // We need to fetch the previous leaves to ensure we have enough leaves for the
        // append operation
        let value = contract_db_reader
            .global_contract_tree_get_node(checkpoint_id, SimpleMerkleNodeKey::new(tree_height, start_required_contract_id))
            .await?;
        if value == Hasher::get_zero_hash(tree_height as usize) {
            anyhow::bail!(
                "Failed to load Global Contract Tree from DB: leaf node for contract id {} is zero hash, but tree root is not zero hash",
                start_required_contract_id
            );
        }
        load_append_only_global_contract_tree_into_memory::<Hasher, Store, Hash>(
            contract_db_reader,
            &mut tree,
            checkpoint_id,
            start_required_contract_id,
            current_key.index,
            128,
        )
        .await?;
    }

    // Every leaf up to the frontier must actually be here.
    //
    // The store answers a node it never loaded with the zero hash -- absence and
    // emptiness are the same value in it -- so a partial load is not an error
    // here, it is silently wrong data that surfaces much later as a circuit
    // witness contradiction naming a wire and nothing else.  Measured rather
    // than assumed, because the window this loader computes and the leaves an
    // append proof will read are two different ranges.
    {
        // Over the window this load claims, not the whole tree: below the
        // window the tree is deliberately absent, and demanding otherwise would
        // refuse to start any chain with more contracts than one sub-tree holds.
        //
        // That the window is enough is a separate promise, kept by appending at
        // an index the caller knows rather than at the first apparently-empty
        // leaf -- see `append_leaves_spider_man_at`.  Without that, a hole
        // anywhere in the tree is fatal and no bounded window can be checked.
        let mut missing: Vec<u64> = Vec::new();
        for index in start_required_contract_id..=current_key.index {
            let in_memory = tree.get_leaf_value(index);
            if in_memory == Hasher::get_zero_hash(0) {
                missing.push(index);
            }
        }
        if !missing.is_empty() {
            let first = missing.first().copied().unwrap_or_default();
            let last = missing.last().copied().unwrap_or_default();
            anyhow::bail!(
                "the contract tree loaded from checkpoint {checkpoint_id} is missing {} of the \
                 leaves it meant to load, {start_required_contract_id} through {} (first {first}, \
                 last {last}). A missing leaf reads as an empty one, so the append would be \
                 proved against a sub-tree that is already occupied -- refusing to start rather \
                 than producing a witness nothing can prove",
                missing.len(),
                current_key.index
            );
        }
    }

    let next_contract_id = current_key.index + 1;
    let merkle_proof_b = contract_db_reader
        .global_contract_tree_get_merkle_proof(checkpoint_id, next_contract_id)
        .await?;

    if !merkle_proof_b.verify::<Hasher>() {
        anyhow::bail!("Failed to verify merkle proof for Global Contract Tree up to contract id {}", next_contract_id);
    }

    tree.injest_merkle_proof(&merkle_proof_b)?;
    tree.injest_merkle_proof(&merkle_proof_a)?;
    if tree.get_root() != root {
        anyhow::bail!(
            "Loaded Global Contract Tree root hash {:?} does not match expected root hash {:?}",
            tree.get_root(),
            root
        );
    }

    let pre_next_leaf_id = tree.get_leaf_value(next_contract_id - 1);
    if pre_next_leaf_id == Hasher::get_zero_hash(0) {
        anyhow::bail!(
            "Failed to load Global Contract Tree from DB: leaf node for contract id {} is zero hash, but tree root is not zero hash",
            next_contract_id - 1
        );
    }
    println!("next_contract_id: {}", next_contract_id);

    println!(
        "Loaded Global Contract Tree up to contract id {}, with root hash {:?}",
        next_contract_id,
        tree.get_root()
    );
    Ok((next_contract_id, tree))
}
