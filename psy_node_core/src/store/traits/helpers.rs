
use parth_core::{
    crypto::hash::{merkle_node_cache::QMerkleNodeCacheReader, merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, merkle_update_builder::{QMerkleUpdaterReaderSync, QMerkleUpdaterWriterSyncMut, SimpleMemoryMerkleUpdaterUnique}, traits::MerkleZeroHasher},
    data::hash::{merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey}, merkle_store_key::QMerkleStoreDoubleIdNode},
    protocol::core_types::{Q256BitHash, QHashBase},
};

use crate::{qblob::{data_views::double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, structs::common::tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE}, store::traits::core_db::{CoreDatabaseDoubleIdMerkleReader, CoreDatabaseDoubleIdMerkleWriter, CoreDatabaseSingleIdMerkleReader, CoreDatabaseSingleIdMerkleWriter, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter}};


async fn db_select_many_zero_id_merkle_node_max_checkpoint_with_cache<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
    C: QMerkleNodeCacheReader<Hash> + Sync + Send,
>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    keys: &[SimpleMerkleNodeKey],
    cache: &C,
) -> anyhow::Result<Vec<Hash>>{
    let mut results = Vec::with_capacity(keys.len());
    let mut keys_to_fetch = Vec::new();
    let mut indices_to_fetch = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        if let Some(cached) = cache.get(key) {
            results.push(cached);
        } else {
            keys_to_fetch.push(key.clone());
            indices_to_fetch.push(i);
            results.push(Hash::default()); // placeholder
        }
    }
    if !keys_to_fetch.is_empty() {
        let fetched = reader.db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &keys_to_fetch).await?;
        for (i, fetched_node) in fetched.into_iter().enumerate() {
            let index = indices_to_fetch[i];
            results[index] = fetched_node;
        }
    }
    Ok(results)

}
async fn db_select_many_single_id_merkle_node_max_checkpoint_with_cache<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
    C: QMerkleNodeCacheReader<Hash> + Sync + Send>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    keys: &[SimpleMerkleNodeKey],
    cache: &C,
) -> anyhow::Result<Vec<Hash>>{
    let mut results = Vec::with_capacity(keys.len());
    let mut keys_to_fetch = Vec::new();
    let mut indices_to_fetch = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        if let Some(cached) = cache.get(key) {
            results.push(cached);
        } else {
            keys_to_fetch.push(key.clone());
            indices_to_fetch.push(i);
            results.push(Hash::default()); // placeholder
        }
    }
    if !keys_to_fetch.is_empty() {
        let fetched = reader.db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, &keys_to_fetch).await?;
        for (i, fetched_node) in fetched.into_iter().enumerate() {
            let index = indices_to_fetch[i];
            results[index] = fetched_node;
        }
    }
    Ok(results)

}

pub async fn db_helper_select_double_id_merkle_proof_max_checkpoint<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    key: &SimpleMerkleNodeKey,
) -> anyhow::Result<MerkleProofCore<Hash>> {
    let mut lookup = key.siblings();
    lookup.push(key.clone());
    lookup.push(SimpleMerkleNodeKey::new_root());
    let mut results = reader
        .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup)
        .await?;
    let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    Ok(MerkleProofCore {
        root,
        value,
        index: key.index,
        siblings: results,
    })
}


pub async fn db_helper_record_update_double_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings();
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = reader
        .db_select_many_double_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);


    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}

pub async fn db_helper_select_single_id_merkle_proof_max_checkpoint<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    key: SimpleMerkleNodeKey,
) -> anyhow::Result<MerkleProofCore<Hash>> {
    let mut lookup = key.siblings();
    lookup.push(key.clone());
    lookup.push(SimpleMerkleNodeKey::new_root());
    let mut results = reader
        .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &lookup)
        .await?;
    let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node value found in merkle proof"))?;
    Ok(MerkleProofCore {
        root,
        value,
        siblings: results,
        index: key.index,
    })
}


pub async fn db_helper_record_update_single_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings_to_level(sub_root_level);
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = reader
        .db_select_many_single_id_merkle_nodes_max_checkpoint(table, checkpoint_id, tree_id, tree_height, &lookup)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);


    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}

pub async fn db_helper_record_cache_update_single_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleNodeCacheReader<Hash> + QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings_to_level(sub_root_level);
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = db_select_many_single_id_merkle_node_max_checkpoint_with_cache(reader, table, checkpoint_id, tree_id, tree_height, &lookup, merkle_updater)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);



    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}

pub async fn db_helper_select_zero_id_merkle_proof_max_checkpoint<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    key: &SimpleMerkleNodeKey,
) -> anyhow::Result<MerkleProofCore<Hash>> {
    let mut lookup = key.siblings();
    lookup.push(key.clone());
    lookup.push(SimpleMerkleNodeKey::new_root());
    let mut results = reader
        .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
        .await?;
    let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    Ok(MerkleProofCore {
        root,
        value,
        index: key.index,
        siblings: results,
    })
}
pub async fn db_helper_select_zero_id_merkle_proof_max_checkpoint_to_root_level<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    root_level: u8,
    key: &SimpleMerkleNodeKey,
) -> anyhow::Result<MerkleProofCore<Hash>> {
    let mut lookup = key.siblings_to_level(root_level);
    lookup.push(key.clone());
    lookup.push(key.parent_at_level(root_level));
    let mut results = reader
        .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
        .await?;
    let root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    Ok(MerkleProofCore {
        root,
        value,
        index: key.index,
        siblings: results,
    })
}



pub async fn db_helper_record_update_zero_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings_to_level(sub_root_level);
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = reader
        .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, checkpoint_id, &lookup)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);


    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}


/* 
pub async fn db_helper_zero_id_merkle_node_simple_set_leaves<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();



    for (i, node) in nodes.iter().enumerate() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_update_zero_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)
}

*/

pub async fn db_helper_single_id_merkle_node_simple_set_leaves<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
    if sub_root_level > tree_height {
        return Err(anyhow::anyhow!("Sub root level cannot be greater than tree height"));
    }

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();



    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_single_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, tree_id, tree_height, sub_root_level, &node).await?;

        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)

}

/*

pub async fn db_helper_double_id_merkle_node_simple_set_leaves<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
    if sub_root_level > tree_height {
        return Err(anyhow::anyhow!("Sub root level cannot be greater than tree height"));
    }

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();



    for (i, node) in nodes.iter().enumerate() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_update_double_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, tree_id, tree_sub_id, tree_height, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)

}
*/
async fn db_select_many_double_id_merkle_node_max_checkpoint_with_cache<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
    C: QMerkleNodeCacheReader<Hash> + Sync + Send,
>(
    reader: &Reader,
    table: &TableIdentifier,
    max_checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    keys: &[SimpleMerkleNodeKey],
    cache: &C,
) -> anyhow::Result<Vec<Hash>> {
    let mut results = Vec::with_capacity(keys.len());
    let mut keys_to_fetch = Vec::new();
    let mut indices_to_fetch = Vec::new();
    for (i, key) in keys.iter().enumerate() {
        if let Some(cached) = cache.get(key) {
            results.push(cached);
        } else {
            keys_to_fetch.push(key.clone());
            indices_to_fetch.push(i);
            results.push(Hash::default()); // placeholder
        }
    }
    if !keys_to_fetch.is_empty() {
        let fetched = reader.db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &keys_to_fetch).await?;
        for (i, fetched_node) in fetched.into_iter().enumerate() {
            let index = indices_to_fetch[i];
            results[index] = fetched_node;
        }
    }
    Ok(results)
}

pub async fn db_helper_record_cache_update_double_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleNodeCacheReader<Hash> + QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings();
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = db_select_many_double_id_merkle_node_max_checkpoint_with_cache(reader, table, checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup, merkle_updater)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);

    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}

pub async fn db_helper_record_cache_update_zero_id_merkle_node_to_level_dmp<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    MerkleUpdater: QMerkleNodeCacheReader<Hash> + QMerkleUpdaterWriterSyncMut<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Reader: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    reader: &Reader,
    table: &TableIdentifier,
    merkle_updater: &mut MerkleUpdater,
    mark_root: bool,
    checkpoint_id: u64,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings();
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = db_select_many_zero_id_merkle_node_max_checkpoint_with_cache(reader, table, checkpoint_id, &lookup, merkle_updater)
        .await?;
    let old_root = results.pop().ok_or_else(|| anyhow::anyhow!("No root found in merkle proof"))?;
    let old_value = results.pop().ok_or_else(|| anyhow::anyhow!("No node found in merkle proof"))?;
    let new_root = merkle_updater.mark_updates_from_siblings::<Hasher>(node.key, node.value, &results, mark_root);

    Ok(DeltaMerkleProofCore {
        old_root,
        old_value,
        new_root,
        new_value: node.value,
        index: node.key.index,
        siblings: results,
    })
}

pub async fn db_helper_zero_id_merkle_node_simple_set_leaves<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();

    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_zero_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)
}

pub async fn db_helper_double_id_merkle_node_simple_set_leaves<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
    if sub_root_level > tree_height {
        return Err(anyhow::anyhow!("Sub root level cannot be greater than tree height"));
    }

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();

    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_double_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, tree_id, tree_sub_id, tree_height, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_double_id_merkle_nodes_batch(table, checkpoint_id, tree_id, tree_sub_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)
}



pub async fn db_helper_zero_id_merkle_node_simple_set_leaves_fast_serialize<
    Hash: QHashBase + Q256BitHash + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();

    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_zero_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)
}



pub async fn db_helper_single_id_merkle_node_simple_set_leaves_fast_serialize<
    Hash: QHashBase + Q256BitHash + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseSingleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseSingleIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
    if sub_root_level > tree_height {
        return Err(anyhow::anyhow!("Sub root level cannot be greater than tree height"));
    }

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();



    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_single_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, tree_id, tree_height, sub_root_level, &node).await?;

        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            store.db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, &drained).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
        let drained = recorder.drain_updates();
        store.db_set_single_id_merkle_nodes_batch(table, checkpoint_id, tree_id, &drained).await?;
    }
    Ok(delta_merkle_proofs)

}



pub async fn db_helper_double_id_merkle_node_simple_set_leaves_fast_serialize<
    Hash: QHashBase + Q256BitHash + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseDoubleIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseDoubleIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    tree_id: u64,
    tree_sub_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    max_batch_size: usize,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<Vec<DeltaMerkleProofCore<Hash>>> {
    if sub_root_level > tree_height {
        return Err(anyhow::anyhow!("Sub root level cannot be greater than tree height"));
    }

    type Recorder<Hash> = SimpleMemoryMerkleUpdaterUnique<Hash>;
    if nodes.is_empty() {
        return Ok(vec![]);
    }

    let mut delta_merkle_proofs = Vec::with_capacity(nodes.len());
    let mut recorder = Recorder::<Hash>::new();

    for node in nodes.iter() {
        if sub_root_level > node.key.level {
            return Err(anyhow::anyhow!("Sub root level cannot be greater than node height"));
        }
        let current_dmp = db_helper_record_cache_update_double_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, tree_id, tree_sub_id, tree_height, sub_root_level, &node).await?;
        delta_merkle_proofs.push(current_dmp);
        if recorder.get_total_node_count() >=  max_batch_size {
            let drained = recorder.drain_updates();
            let double_nodes = QMerkleStoreDoubleIdNode::from_simple_merkle_nodes_for_tree_clone(tree_id, tree_sub_id, &drained);
            let double_nodes_serialized = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref_default_context(&double_nodes);

            store.db_set_double_id_merkle_nodes_from_fast_serialized(table, checkpoint_id, &double_nodes_serialized[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..]).await?;
            recorder = Recorder::<Hash>::new_clean();
        }
    }
    if recorder.get_total_node_count() > 0 {
            let drained = recorder.drain_updates();
            let double_nodes = QMerkleStoreDoubleIdNode::from_simple_merkle_nodes_for_tree_clone(tree_id, tree_sub_id, &drained);
            let double_nodes_serialized = QBlobDoubleMerkleNodeBatchDataView::generate_double_merkle_node_batch_blob_data_from_ref_default_context(&double_nodes);

            store.db_set_double_id_merkle_nodes_from_fast_serialized(table, checkpoint_id, &double_nodes_serialized[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..]).await?;
    }
    Ok(delta_merkle_proofs)
}