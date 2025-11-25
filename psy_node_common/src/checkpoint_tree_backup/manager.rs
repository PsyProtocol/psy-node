use std::sync::Arc;

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_node_nest::MerkleLeafNode},
    protocol::core_types::Q256BitHash,
};
use psy_core::constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF;
use psy_node_core::{
    psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader,
    utils::fragmented_split::{self, FragmentedSplits},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub struct CheckpointTreeBackupManager<Hasher: MerkleZeroHasher<Hash>, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash> {
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>>,
    pub next_backup_index: u64,
    pub max_checkpoints_to_keep: u64,
    pub min_backed_up_checkpoint_id: u64,
    pub total_checkpoint_writes: u64,
    pub next_backup_checkpoint_id: u64,
    pub backup_file: tokio::fs::File,
}

const CHECKPOINT_BACKUP_MAGIC_LEN: usize = 8;
const CHECKPOINT_BACKUP_MAGIC_BYTES: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74]; // "PsyChkpt"
const CHECKPOINT_BACKUP_MAGIC_U64_LE: u64 = 0x74_70_6B_68_43_79_73_50; // "PsyChkpt" in little-endian u64
const CHECKPOINT_BACKUP_ITEM_SIZE: usize = 8 + 32; // u64 checkpoint id + 32 bytes checkpoint hash

async fn setup_checkpoint_backup_file_dashmap<Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash>(
    file: &mut tokio::fs::File,
    allow_new_file_creation: bool,
) -> anyhow::Result<(u64, u64, u64, u64, Vec<MerkleLeafNode<Hash>>)> {
    let metadata = file.metadata().await?;
    let mut file_size = metadata.len();
    let checkpoint_list_count = if file_size == 0 {
        if allow_new_file_creation {
            file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;
            file_size = CHECKPOINT_BACKUP_MAGIC_LEN as u64;
            0u64
        } else {
            anyhow::bail!("Checkpoint backup file is empty and new file creation is not allowed");
        }
    } else if file_size < CHECKPOINT_BACKUP_MAGIC_LEN as u64 {
        anyhow::bail!("Checkpoint backup file is too small to contain magic bytes");
    } else {
        let file_size_minus_magic = file_size - CHECKPOINT_BACKUP_MAGIC_LEN as u64;
        if file_size_minus_magic % (CHECKPOINT_BACKUP_ITEM_SIZE as u64) != 0 {
            anyhow::bail!("Checkpoint backup file is corrupted or invalid (size minus magic is not multiple of item size)");
        }
        let checkpoint_list_count = file_size_minus_magic / (CHECKPOINT_BACKUP_ITEM_SIZE as u64);
        let mut magic_bytes = [0u8; CHECKPOINT_BACKUP_MAGIC_LEN];
        file.read_exact(&mut magic_bytes).await?;
        if magic_bytes != CHECKPOINT_BACKUP_MAGIC_BYTES {
            anyhow::bail!("Checkpoint backup file has invalid magic bytes");
        }
        checkpoint_list_count
    };
    if checkpoint_list_count == 0 {
        return Ok((0u64, 0u64, 0u64, file_size, Vec::new()));
    }
    let mut leaf_nodes = Vec::with_capacity(checkpoint_list_count as usize);

    let first_checkpoint_id = file.read_u64_le().await?;
    let mut checkpoint_hash_buffer = [0u8; 32];
    file.read_exact(&mut checkpoint_hash_buffer).await?;
    let first_checkpoint_hash_bytes = Hash::from_ref_32bytes(&checkpoint_hash_buffer);
    leaf_nodes.push(MerkleLeafNode {
        index: first_checkpoint_id,
        value: first_checkpoint_hash_bytes,
    });
    let mut fragmented_splits = FragmentedSplits::new(first_checkpoint_id);
    for _ in 1..checkpoint_list_count {
        let checkpoint_id = file.read_u64_le().await?;
        let mut checkpoint_hash_buffer = [0u8; 32];
        file.read_exact(&mut checkpoint_hash_buffer).await?;
        if !fragmented_splits.add_index_get_contained(checkpoint_id, false, true) {
            let checkpoint_hash_bytes = Hash::from_ref_32bytes(&checkpoint_hash_buffer);
            let value = MerkleLeafNode {
                index: checkpoint_id,
                value: checkpoint_hash_bytes,
            };
            leaf_nodes.push(value);
        } else {
            anyhow::bail!(
                "Got duplicate checkpoint ids in checkpoint backup file, for checkpoint id {}",
                checkpoint_id
            );
        }
    }
    let (start_chunk, end_chunk, counter) = fragmented_splits.get_max_range();
    let chunk_len = end_chunk - start_chunk;
    let hash_offset = chunk_len + counter;
    if fragmented_splits.fragments.len() != 0 {
        anyhow::bail!("Checkpoint backup file has non-contiguous checkpoint ids");
    }
    fragmented_splits.finalize();
    let (max_checkpoint_id_range_start, max_checkpoint_id_range_end, _) = fragmented_splits.get_max_range();
    let good_leaves = leaf_nodes
        .into_iter()
        .filter(|leaf| leaf.index >= max_checkpoint_id_range_start && leaf.index < max_checkpoint_id_range_end)
        .collect::<Vec<_>>();
    Ok((
        max_checkpoint_id_range_start,
        max_checkpoint_id_range_end,
        hash_offset,
        file_size,
        good_leaves,
    ))
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash>
    CheckpointTreeBackupManager<Hasher, Hash>
{
    pub async fn new_from_file_path<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        backup_file_path: &str,
        allow_create_file: bool,
    ) -> anyhow::Result<Self> {
        let mut backup_file = tokio::fs::File::create(backup_file_path).await?;
        let (checkpoint_tree_start, checkpoint_tree_end, hash_offset, file_size, leaf_nodes) =
            setup_checkpoint_backup_file_dashmap::<Hash>(&mut backup_file, allow_create_file).await?;
        let file_size_minus_magic = if file_size >= CHECKPOINT_BACKUP_MAGIC_LEN as u64 {
            file_size - CHECKPOINT_BACKUP_MAGIC_LEN as u64
        } else {
            anyhow::bail!("Checkpoint backup file is too small to contain magic bytes");
        };
        let real_max_checkpoints_to_keep = (file_size_minus_magic / (CHECKPOINT_BACKUP_ITEM_SIZE as u64)).max(max_checkpoints_to_keep);
        let next_backup_index = hash_offset;
        let checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(checkpoint_tree_height));

        let merkle_proof = checkpoint_tree_store
            .checkpoint_tree_get_merkle_proof(checkpoint_tree_start, checkpoint_tree_start)
            .await?;
        checkpoint_tree.injest_merkle_proof(&merkle_proof)?;
        for leaf in leaf_nodes.iter() {
            checkpoint_tree.set_leaf_no_proof(leaf.index, leaf.value);
        }
        let is_empty = checkpoint_tree_end == checkpoint_tree_start;
        if !is_empty {
            let expected_leaf_at_start_of_seek = (file_size_minus_magic + hash_offset * CHECKPOINT_BACKUP_ITEM_SIZE as u64
                - CHECKPOINT_BACKUP_ITEM_SIZE as u64)
                % file_size_minus_magic;
            backup_file
                .seek(std::io::SeekFrom::Start(
                    CHECKPOINT_BACKUP_MAGIC_LEN as u64 + expected_leaf_at_start_of_seek,
                ))
                .await?;
            let actual_checkpoint_id = backup_file.read_u64_le().await?;
            if actual_checkpoint_id != checkpoint_tree_end - 1 {
                anyhow::bail!("Checkpoint backup file's last checkpoint id does not match the expected last checkpoint id from the checkpoint tree");
            }
            let mut checkpoint_hash_buffer = [0u8; 32];
            backup_file.read_exact(&mut checkpoint_hash_buffer).await?;
            let actual_checkpoint_hash = Hash::from_ref_32bytes(&checkpoint_hash_buffer);
            let expected_checkpoint_hash = checkpoint_tree.get_leaf_value(checkpoint_tree_end - 1);
            if actual_checkpoint_hash != expected_checkpoint_hash {
                anyhow::bail!(
                    "Checkpoint backup file's last checkpoint hash does not match the expected last checkpoint hash from the checkpoint tree"
                );
            }
        }
        backup_file
            .seek(std::io::SeekFrom::Start(
                CHECKPOINT_BACKUP_MAGIC_LEN as u64 + next_backup_index * CHECKPOINT_BACKUP_ITEM_SIZE as u64,
            ))
            .await?;

        Ok(Self {
            checkpoint_tree,
            next_backup_index: next_backup_index,
            min_backed_up_checkpoint_id: checkpoint_tree_start,
            max_checkpoints_to_keep: real_max_checkpoints_to_keep,
            next_backup_checkpoint_id: checkpoint_tree_end,
            total_checkpoint_writes: hash_offset,
            backup_file,
        })
    }
    pub fn has_appropriate_checkpoint_history_for_stale_proofs(&self, max_stale_checkpoint_age: u64, current_checkpoint_id: u64) -> bool {
        if current_checkpoint_id <= max_stale_checkpoint_age {
            self.min_backed_up_checkpoint_id == 0
        } else {
            if self.next_backup_checkpoint_id <= max_stale_checkpoint_age {
                return false;
            }
            self.min_backed_up_checkpoint_id > current_checkpoint_id - max_stale_checkpoint_age
        }
    }
    pub fn get_checkpoint_history_missing_ranges_for_current_checkpoint_id(
        &self,
        max_stale_checkpoint_age: u64,
        current_checkpoint_id: u64,
    ) -> (Option<(u64, u64)>, Option<(u64, u64)>) {
        if current_checkpoint_id <= max_stale_checkpoint_age {
            if self.min_backed_up_checkpoint_id > 0 {
                (Some((0, self.min_backed_up_checkpoint_id)), None)
            } else {
                (None, None)
            }
        } else {
            let target_min_checkpoint_id = current_checkpoint_id - max_stale_checkpoint_age;
            let start_range = if self.next_backup_checkpoint_id <= target_min_checkpoint_id {
                Some((target_min_checkpoint_id, self.next_backup_checkpoint_id))
            } else if self.min_backed_up_checkpoint_id < target_min_checkpoint_id {
                Some((target_min_checkpoint_id, self.min_backed_up_checkpoint_id))
            } else {
                None
            };
            let end_range = if self.next_backup_checkpoint_id < current_checkpoint_id + 1 {
                Some((self.next_backup_checkpoint_id, current_checkpoint_id + 1))
            } else {
                None
            };
            (start_range, end_range)
        }
    }
    pub async fn append_checkpoint_leaf_hash(&mut self, checkpoint_id: u64, checkpoint_hash: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        if checkpoint_id != self.next_backup_checkpoint_id {
            anyhow::bail!(
                "Can only append checkpoint ids in sequential order. Expected {}, got {}",
                self.next_backup_checkpoint_id,
                checkpoint_id
            );
        }
        self.backup_file.write_u64_le(checkpoint_id).await?;
        let checkpoint_hash_bytes = checkpoint_hash.into_owned_32bytes();
        self.backup_file.write_all(&checkpoint_hash_bytes).await?;
        self.next_backup_index += 1;
        if self.next_backup_index >= self.max_checkpoints_to_keep {
            self.next_backup_index = 0;
            self.backup_file
                .seek(std::io::SeekFrom::Start(CHECKPOINT_BACKUP_MAGIC_LEN as u64))
                .await?;
        }
        self.total_checkpoint_writes += 1;
        if self.total_checkpoint_writes > self.max_checkpoints_to_keep {
            self.min_backed_up_checkpoint_id += 1;
        }
        self.next_backup_checkpoint_id = checkpoint_id + 1;
        Ok(self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash))
    }

    pub async fn populate_from_database<CheckpointTreeReader: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        &mut self,
        checkpoint_tree_reader: &CheckpointTreeReader,
        batch_size: usize,
        start_checkpoint_id: u64,
        count: usize,
    ) -> anyhow::Result<()> {
        if batch_size == 0 {
            return Err(anyhow::anyhow!("Batch size cannot be zero"));
        }
        let checkpoint_tree_height = self.checkpoint_tree.get_height();
        let start_merkle_proof = checkpoint_tree_reader
            .checkpoint_tree_get_merkle_proof(start_checkpoint_id, start_checkpoint_id)
            .await?;
        self.checkpoint_tree.injest_merkle_proof(&start_merkle_proof);
        self.append_checkpoint_leaf_hash(start_checkpoint_id, start_merkle_proof.value).await?;
        let total_batches = count / batch_size + if count % batch_size == 0 { 0 } else { 1 };
        let end_checkpoiont_id = start_checkpoint_id + (count as u64) - 1;
        for batch_index in 0..total_batches {
            let batch_start_checkpoint_id = start_checkpoint_id + (batch_index as u64) * (batch_size as u64);
            let batch_end_checkpoint_id = std::cmp::min(batch_start_checkpoint_id + (batch_size as u64) - 1, end_checkpoiont_id);
            let node_keys = (batch_start_checkpoint_id..=batch_end_checkpoint_id)
                .map(|checkpoint_id| SimpleMerkleNodeKey::new(checkpoint_tree_height, checkpoint_id))
                .collect::<Vec<_>>();
            let values = checkpoint_tree_reader
                .checkpoint_tree_get_nodes(start_checkpoint_id + count as u64 + 1, &node_keys)
                .await?;
            for (node_key, value) in node_keys.into_iter().zip(values.into_iter()) {
                self.append_checkpoint_leaf_hash(node_key.index, value).await?;
            }
        }
        Ok(())
    }

    pub async fn sync_from_database<CheckpointTreeReader: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        &mut self,
        checkpoint_tree_reader: &CheckpointTreeReader,
        sync_batch_size: usize,
        last_committed_checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        if last_committed_checkpoint_id < self.min_backed_up_checkpoint_id {
            anyhow::bail!("The last committed checkpoint ID {} is less than the minimum backed up checkpoint ID {} in the checkpoint tree backup manager. This indicates a serious inconsistency between the database and the checkpoint tree backup manager.", last_committed_checkpoint_id, self.min_backed_up_checkpoint_id);
        }

        let min_backed_up_checkpoint_id = self.min_backed_up_checkpoint_id;
        let next_backup_checkpoint_id = self.next_backup_checkpoint_id;

        let (fetch_missing_checkpoints_prefix_range, fetch_missing_checkpoints_suffix_range) = self
            .get_checkpoint_history_missing_ranges_for_current_checkpoint_id(
                STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF,
                last_committed_checkpoint_id,
            );
        if fetch_missing_checkpoints_prefix_range.is_some() || fetch_missing_checkpoints_suffix_range.is_some() {
            tracing::warn!("The checkpoint tree backup manager is missing some checkpoint history for stale proofs. Filling in from the database (this may take a while)...");
            if let Some((start_checkpoint_id, end_checkpoint_id)) = fetch_missing_checkpoints_prefix_range {
                self.populate_from_database::<CheckpointTreeReader>(checkpoint_tree_reader, sync_batch_size, start_checkpoint_id, (end_checkpoint_id - start_checkpoint_id) as usize)
                    .await?;
            }
            for i in min_backed_up_checkpoint_id..next_backup_checkpoint_id {
                let leaf = self.checkpoint_tree.get_leaf_value(i);
                self.append_checkpoint_leaf_hash(i, leaf).await?;
            }
            if let Some((start_checkpoint_id, end_checkpoint_id)) = fetch_missing_checkpoints_suffix_range {
                self.populate_from_database::<CheckpointTreeReader>(checkpoint_tree_reader, sync_batch_size, start_checkpoint_id, (end_checkpoint_id - start_checkpoint_id) as usize)
                    .await?;
            }
        }
        if !self.has_appropriate_checkpoint_history_for_stale_proofs(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF, last_committed_checkpoint_id) {
            anyhow::bail!("The checkpoint tree backup manager failed to sync...");
        }
        let current_checkpoint_tree_root = self.checkpoint_tree.get_root();
        let known_correct_checkpoint_tree_root = checkpoint_tree_reader.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await?;
        if current_checkpoint_tree_root != known_correct_checkpoint_tree_root {
            anyhow::bail!("The checkpoint tree backup manager root does not match the known correct root from the database...");
        }

        Ok(())
    }
}
