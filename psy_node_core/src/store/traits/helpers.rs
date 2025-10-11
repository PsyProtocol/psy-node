use parth_core::{
    crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, merkle_update_builder::{QMerkleUpdaterReaderSync, QMerkleUpdaterWriterSyncMut, SimpleMemoryMerkleUpdater}, traits::MerkleZeroHasher},
    data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey},
    protocol::core_types::QHashBase,
};

use crate::store::traits::core_db::{CoreDatabaseDoubleIdMerkleReader, CoreDatabaseSingleIdMerkleReader, CoreDatabaseZeroIdMerkleReader, CoreDatabaseZeroIdMerkleWriter};

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
    max_checkpoint_id: u64,
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
        .db_select_many_double_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_sub_id, tree_height, &lookup)
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
    max_checkpoint_id: u64,
    tree_id: u64,
    tree_height: u8,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings();
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = reader
        .db_select_many_single_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, tree_id, tree_height, &lookup)
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
    let mut lookup = key.siblings();
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
    max_checkpoint_id: u64,
    sub_root_level: u8,
    node: &SimpleMerkleNode<Hash>,
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    let mut lookup = node.key.siblings();
    lookup.push(node.key.clone());
    lookup.push(node.key.parent_at_level(sub_root_level));
    let mut results = reader
        .db_select_many_zero_id_merkle_nodes_max_checkpoint(table, max_checkpoint_id, &lookup)
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



pub async fn db_helper_zero_id_merkle_node_simple_set_leaf<
    Hash: QHashBase + Send + Sync,
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    TableIdentifier: Clone + Send + Sync,
    Store: CoreDatabaseZeroIdMerkleReader<Hash, Hasher, TableIdentifier> + CoreDatabaseZeroIdMerkleWriter<Hash, Hasher, TableIdentifier> + Send + Sync,
>(
    store: &Store,
    table: &TableIdentifier,
    checkpoint_id: u64,
    sub_root_level: u8,
    nodes: &[SimpleMerkleNode<Hash>],
) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
    if nodes.is_empty() {
        return Err(anyhow::anyhow!("No nodes provided for merkle update"));
    }
    let mut last_delta_merkle_proof = None;

    let node_len_minus_1 = nodes.len() - 1;


    for (i, node) in nodes.iter().enumerate() {
        let mut recorder = SimpleMemoryMerkleUpdater::<Hash>::new();
        let current_dmp = db_helper_record_update_zero_id_merkle_node_to_level_dmp(store, table, &mut recorder, true, checkpoint_id, sub_root_level, &node).await?;
        store.db_set_zero_id_merkle_nodes_batch(table, checkpoint_id, &recorder.drain_updates()).await?;
        if i == node_len_minus_1 {
            last_delta_merkle_proof = Some(current_dmp);
        }
    }
    Ok(last_delta_merkle_proof.unwrap())
}