use std::sync::Arc;

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_node_nest::MerkleLeafNode},
    protocol::core_types::Q256BitHash,
};
use psy_core::constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF;
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    p2p::traits::realm_coordinantor::RealmCoordinatorClient,
    psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

pub const CHECKPOINT_BACKUP_MAGIC_LEN: usize = 8;
pub const CHECKPOINT_BACKUP_MAGIC_BYTES: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74];
pub const CHECKPOINT_BACKUP_MAGIC_U64_LE: u64 = 0x74_70_6B_68_43_79_73_50;
pub const CHECKPOINT_BACKUP_ITEM_SIZE: usize = 8 + 32;
pub const CHECKPOINTS_PER_BUCKET: u64 = 1024;

pub struct CheckpointTreeBackupManager<
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash,
    FileSystem: TokioLikeFileSystem,
> {
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>>,
    pub max_checkpoints_to_keep: u64,

    // Range is [min_backed_up_checkpoint_id, next_backup_checkpoint_id)
    pub min_backed_up_checkpoint_id: u64,
    pub next_backup_checkpoint_id: u64,

    pub backup_file_path: String,
    pub backup_file: FileSystem::File,
    pub file_system: Arc<FileSystem>,
    pub active_bucket: Option<(u64, FileSystem::File)>,
}

impl<Hasher: MerkleZeroHasher<Hash>, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Q256BitHash, FileSystem: TokioLikeFileSystem>
    CheckpointTreeBackupManager<Hasher, Hash, FileSystem>
{
    pub fn get_current_checkpoint_id_head(&self) -> u64 {
        if self.next_backup_checkpoint_id == 0 {
            0
        } else {
            self.next_backup_checkpoint_id - 1
        }
    }

    pub fn get_current_checkpoint_tree_root_head(&self) -> Hash {
        self.checkpoint_tree.get_root()
    }
    fn bucket_file_path(&self, bucket_index: u64) -> String {
        format!("{}.bucket.{:020}.bin", self.backup_file_path, bucket_index)
    }

    async fn append_bucket_record(&mut self, checkpoint_id: u64, checkpoint_hash: Hash) -> anyhow::Result<()> {
        let bucket_index = checkpoint_id / CHECKPOINTS_PER_BUCKET;
        let bucket_path = self.bucket_file_path(bucket_index);
        let record_index = checkpoint_id % CHECKPOINTS_PER_BUCKET;
        let expected_len = (CHECKPOINT_BACKUP_MAGIC_LEN as u64)
            .checked_add(
                record_index
                    .checked_mul(CHECKPOINT_BACKUP_ITEM_SIZE as u64)
                    .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} record offset overflow", bucket_index))?,
            )
            .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} length overflow", bucket_index))?;
        let exists = self
            .file_system
            .file_like_exists(&bucket_path)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to inspect checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error))?;
        let initialized = if exists {
            self.file_system
                .file_like_metadata(&bucket_path)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to read checkpoint bucket {} metadata at {}: {}", bucket_index, bucket_path, error))?
                .len()
                > 0
        } else {
            false
        };

        let mut prefix = Vec::new();
        if !initialized && record_index > 0 {
            let bucket_start = bucket_index
                .checked_mul(CHECKPOINTS_PER_BUCKET)
                .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} start overflow", bucket_index))?;
            if bucket_start < self.min_backed_up_checkpoint_id {
                anyhow::bail!(
                    "Cannot backfill missing checkpoint bucket {} at {} from checkpoint {} because the backed-up range starts at {}",
                    bucket_index,
                    bucket_path,
                    bucket_start,
                    self.min_backed_up_checkpoint_id
                );
            }
            prefix.reserve(record_index as usize);
            for prefix_checkpoint_id in bucket_start..checkpoint_id {
                let prefix_hash = self.checkpoint_tree.get_leaf_value(prefix_checkpoint_id);
                if prefix_hash == Hasher::get_zero_hash(0) {
                    anyhow::bail!(
                        "Cannot backfill missing checkpoint bucket {} at {} because checkpoint {} is zero",
                        bucket_index,
                        bucket_path,
                        prefix_checkpoint_id
                    );
                }
                prefix.push((prefix_checkpoint_id, prefix_hash));
            }
        }

        let stale_active_bucket = matches!(self.active_bucket.as_ref(), Some((active_index, _)) if *active_index == bucket_index) && !initialized;
        if stale_active_bucket {
            self.active_bucket = None;
        }
        if !matches!(self.active_bucket.as_ref(), Some((active_index, _)) if *active_index == bucket_index) {
            if let Some((old_index, mut old_file)) = self.active_bucket.take() {
                let old_path = self.bucket_file_path(old_index);
                self.file_system
                    .file_like_fs_flush_file_with_path(&old_path, &mut old_file)
                    .await
                    .map_err(|error| anyhow::anyhow!("Failed to flush checkpoint bucket {} at {}: {}", old_index, old_path, error))?;
            }

            let mut bucket_file = self
                .file_system
                .file_like_fs_create(&bucket_path)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to open checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error))?;
            if !initialized {
                bucket_file.file_like_set_len(0).await.map_err(|error| {
                    anyhow::anyhow!("Failed to truncate checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
                })?;
                bucket_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await.map_err(|error| {
                    anyhow::anyhow!("Failed to write checkpoint bucket {} magic at {}: {}", bucket_index, bucket_path, error)
                })?;
                for (prefix_checkpoint_id, prefix_hash) in prefix {
                    bucket_file.write_u64_le(prefix_checkpoint_id).await.map_err(|error| {
                        anyhow::anyhow!(
                            "Failed to backfill checkpoint {} in bucket {} at {}: {}",
                            prefix_checkpoint_id,
                            bucket_index,
                            bucket_path,
                            error
                        )
                    })?;
                    bucket_file.write_all(&prefix_hash.into_owned_32bytes()).await.map_err(|error| {
                        anyhow::anyhow!(
                            "Failed to backfill checkpoint {} hash in bucket {} at {}: {}",
                            prefix_checkpoint_id,
                            bucket_index,
                            bucket_path,
                            error
                        )
                    })?;
                }
            }
            self.file_system
                .file_like_fs_flush_file_with_path(&bucket_path, &mut bucket_file)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to flush checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error))?;
            self.active_bucket = Some((bucket_index, bucket_file));
        }

        let Some((active_index, bucket_file)) = self.active_bucket.as_mut() else {
            anyhow::bail!("Checkpoint bucket {} at {} has no active file", bucket_index, bucket_path);
        };
        if *active_index != bucket_index {
            anyhow::bail!(
                "Checkpoint bucket {} at {} is active while appending bucket {}",
                active_index,
                bucket_path,
                bucket_index
            );
        }

        let actual_len = bucket_file
            .file_like_metadata()
            .await
            .map_err(|error| anyhow::anyhow!("Failed to read checkpoint bucket {} metadata at {}: {}", bucket_index, bucket_path, error))?
            .len();
        bucket_file.seek(std::io::SeekFrom::Start(0)).await.map_err(|error| {
            anyhow::anyhow!("Failed to seek checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
        })?;
        let magic = bucket_file.read_u64_le().await.map_err(|error| {
            anyhow::anyhow!("Failed to read checkpoint bucket {} magic at {}: {}", bucket_index, bucket_path, error)
        })?;
        if magic != CHECKPOINT_BACKUP_MAGIC_U64_LE {
            anyhow::bail!("Checkpoint bucket {} at {} has invalid magic", bucket_index, bucket_path);
        }

        let appended_len = expected_len
            .checked_add(CHECKPOINT_BACKUP_ITEM_SIZE as u64)
            .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} appended length overflow", bucket_index))?;
        if actual_len == appended_len {
            bucket_file.seek(std::io::SeekFrom::Start(expected_len)).await.map_err(|error| {
                anyhow::anyhow!("Failed to seek checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
            })?;
            let stored_checkpoint_id = bucket_file.read_u64_le().await.map_err(|error| {
                anyhow::anyhow!("Failed to read checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
            })?;
            let mut stored_hash = [0u8; 32];
            bucket_file.read_exact(&mut stored_hash).await.map_err(|error| {
                anyhow::anyhow!("Failed to read checkpoint {} hash from bucket {} at {}: {}", checkpoint_id, bucket_index, bucket_path, error)
            })?;
            if stored_checkpoint_id == checkpoint_id && Hash::from_ref_32bytes(&stored_hash) == checkpoint_hash {
                return Ok(());
            }
            anyhow::bail!(
                "Checkpoint bucket {} at {} already contains a different record at checkpoint {}",
                bucket_index,
                bucket_path,
                checkpoint_id
            );
        }
        if actual_len != expected_len {
            anyhow::bail!(
                "Checkpoint bucket {} at {} has length {}, expected {} before appending checkpoint {}",
                bucket_index,
                bucket_path,
                actual_len,
                expected_len,
                checkpoint_id
            );
        }
        if record_index > 0 {
            let previous_offset = expected_len - CHECKPOINT_BACKUP_ITEM_SIZE as u64;
            bucket_file.seek(std::io::SeekFrom::Start(previous_offset)).await.map_err(|error| {
                anyhow::anyhow!("Failed to seek checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
            })?;
            let previous_id = bucket_file.read_u64_le().await.map_err(|error| {
                anyhow::anyhow!("Failed to read checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
            })?;
            if previous_id != checkpoint_id - 1 {
                anyhow::bail!(
                    "Checkpoint bucket {} at {} ends with checkpoint {}, expected {}",
                    bucket_index,
                    bucket_path,
                    previous_id,
                    checkpoint_id - 1
                );
            }
        }

        bucket_file.seek(std::io::SeekFrom::Start(expected_len)).await.map_err(|error| {
            anyhow::anyhow!("Failed to position checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error)
        })?;
        bucket_file.write_u64_le(checkpoint_id).await.map_err(|error| {
            anyhow::anyhow!("Failed to write checkpoint {} to bucket {} at {}: {}", checkpoint_id, bucket_index, bucket_path, error)
        })?;
        bucket_file.write_all(&checkpoint_hash.into_owned_32bytes()).await.map_err(|error| {
            anyhow::anyhow!("Failed to write checkpoint {} hash to bucket {} at {}: {}", checkpoint_id, bucket_index, bucket_path, error)
        })?;
        self.file_system
            .file_like_fs_flush_file_with_path(&bucket_path, bucket_file)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to flush checkpoint bucket {} at {}: {}", bucket_index, bucket_path, error))?;
        Ok(())
    }

    pub async fn new_from_file_path<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        file_system: Arc<FileSystem>,
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        backup_file_path: &str,
        allow_create_file: bool,
    ) -> anyhow::Result<Self> {
        if max_checkpoints_to_keep == 0 {
            anyhow::bail!("Checkpoint backup ring capacity must be greater than zero");
        }

        let backup_file = if allow_create_file {
            file_system.file_like_fs_create(backup_file_path).await?
        } else {
            file_system.file_like_fs_open(backup_file_path).await?
        };

        Self::new_from_initialized_file(
            file_system,
            backup_file_path.to_string(),
            max_checkpoints_to_keep,
            checkpoint_tree_height,
            checkpoint_tree_store,
            backup_file,
            allow_create_file,
        )
        .await
    }

    async fn new_from_initialized_file<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        file_system: Arc<FileSystem>,
        backup_file_path: String,
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        mut backup_file: FileSystem::File,
        allow_create_file: bool,
    ) -> anyhow::Result<Self> {
        if max_checkpoints_to_keep == 0 {
            anyhow::bail!("Checkpoint backup ring capacity must be greater than zero");
        }

        let file_len = backup_file.file_like_metadata().await?.len();

        if file_len == 0 {
            if !allow_create_file {
                anyhow::bail!("Checkpoint backup file is empty and creation not allowed");
            }
            backup_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;
            file_system.file_like_fs_flush_file_with_path(&backup_file_path, &mut backup_file).await?;
        } else {
            if file_len < CHECKPOINT_BACKUP_MAGIC_LEN as u64 {
                anyhow::bail!("Checkpoint backup file too small");
            }
            backup_file.seek(std::io::SeekFrom::Start(0)).await?;
            let mut magic = [0u8; CHECKPOINT_BACKUP_MAGIC_LEN];
            backup_file.read_exact(&mut magic).await?;
            if magic != CHECKPOINT_BACKUP_MAGIC_BYTES {
                anyhow::bail!("Invalid magic bytes in checkpoint backup file");
            }
        }

        let capacity = max_checkpoints_to_keep;
        let file_len = backup_file.file_like_metadata().await?.len();
        let data_len = file_len - CHECKPOINT_BACKUP_MAGIC_LEN as u64;
        if data_len % CHECKPOINT_BACKUP_ITEM_SIZE as u64 != 0 {
            anyhow::bail!(
                "Checkpoint backup file has a trailing partial record: {} data bytes is not a multiple of {}",
                data_len,
                CHECKPOINT_BACKUP_ITEM_SIZE,
            );
        }
        let num_entries = data_len / CHECKPOINT_BACKUP_ITEM_SIZE as u64;

        let mut entries: Vec<MerkleLeafNode<Hash>> = Vec::with_capacity(num_entries as usize);

        backup_file.seek(std::io::SeekFrom::Start(CHECKPOINT_BACKUP_MAGIC_LEN as u64)).await?;
        for _ in 0..num_entries {
            let id = backup_file.read_u64_le().await?;
            let mut hash_buf = [0u8; 32];
            backup_file.read_exact(&mut hash_buf).await?;
            entries.push(MerkleLeafNode {
                index: id,
                value: Hash::from_ref_32bytes(&hash_buf),
            });
        }

        entries.sort_by_key(|e| e.index);

        let (start_id, end_id, valid_leaves) = if entries.is_empty() {
            (0, 0, Vec::new())
        } else {
            let best_chain_end_idx = entries.len() - 1;
            let mut best_chain_start_idx = best_chain_end_idx;

            for i in (0..entries.len() - 1).rev() {
                if entries[i + 1].index == entries[i].index + 1 {
                    best_chain_start_idx = i;
                } else if entries[i + 1].index == entries[i].index {
                } else {
                    break;
                }
            }

            let chain = entries[best_chain_start_idx..=best_chain_end_idx].to_vec();
            let start = chain.first().map(|e| e.index).unwrap_or(0);
            let end = chain.last().map(|e| e.index + 1).unwrap_or(0);
            (start, end, chain)
        };

        let checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(checkpoint_tree_height));

        if !valid_leaves.is_empty() {
            tracing::info!("Initializing Checkpoint Backup from disk. Range: [{}, {})", start_id, end_id);
            let mut init_proof = checkpoint_tree_store.checkpoint_tree_get_merkle_proof(start_id, start_id).await?;

            // Starting proof right siblings must be zeroed for historical reconstruct.
            for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
                let is_path_left = (start_id >> layer_idx) & 1 == 0;
                if is_path_left {
                    *sibling = Hasher::get_zero_hash(layer_idx);
                }
            }

            if init_proof.value != valid_leaves[0].value {
                anyhow::bail!("Integrity Error: DB proof {:?} for checkpoint {} differs from backup file proof {:?}", init_proof.value, start_id, valid_leaves[0].value);
            }

            checkpoint_tree.injest_merkle_proof(&init_proof)?;

            for leaf in valid_leaves.iter() {
                let p = checkpoint_tree.set_leaf(leaf.index, leaf.value);
                checkpoint_tree.roots.insert(p.new_root, leaf.index);
            }
            checkpoint_tree.ensure_leaf_root_recorded(start_id);
        }

        Ok(Self {
            checkpoint_tree,
            max_checkpoints_to_keep: capacity,
            min_backed_up_checkpoint_id: start_id,
            next_backup_checkpoint_id: end_id,
            backup_file_path,
            backup_file,
            file_system,
            active_bucket: None,
        })
    }

    pub async fn rebuild_from_database_at_checkpoint<CheckpointTreeReader: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        &mut self,
        checkpoint_tree_reader: &CheckpointTreeReader,
        target_checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        if self.max_checkpoints_to_keep == 0 {
            anyhow::bail!("Cannot rebuild checkpoint backup with zero ring capacity");
        }

        let old_last_bucket = self
            .next_backup_checkpoint_id
            .checked_sub(1)
            .map(|checkpoint_id| checkpoint_id / CHECKPOINTS_PER_BUCKET);
        let next_checkpoint_id = target_checkpoint_id
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Target checkpoint ID cannot be represented as a ring head"))?;
        let target_bucket_index = target_checkpoint_id / CHECKPOINTS_PER_BUCKET;
        let bucket_start = target_bucket_index
            .checked_mul(CHECKPOINTS_PER_BUCKET)
            .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} start overflow", target_bucket_index))?;
        let temporary_path = format!("{}.rollback.tmp", self.backup_file_path);
        let bucket_path = self.bucket_file_path(target_bucket_index);
        let bucket_temporary_path = format!("{}.rollback.tmp", bucket_path);
        for path in [&temporary_path, &bucket_temporary_path] {
            if self.file_system.file_like_exists(path).await? {
                self.file_system.file_like_remove_file(path).await?;
            }
        }

        let stale_window_start = target_checkpoint_id.saturating_sub(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF);
        let capacity_window_start = next_checkpoint_id.saturating_sub(self.max_checkpoints_to_keep);
        let window_start = std::cmp::max(stale_window_start, capacity_window_start);
        let checkpoint_tree_height = self.checkpoint_tree.get_height();
        let checkpoint_tree_capacity = 1u64
            .checked_shl(checkpoint_tree_height as u32)
            .ok_or_else(|| anyhow::anyhow!("Unsupported checkpoint tree height {}", checkpoint_tree_height))?;
        if target_checkpoint_id >= checkpoint_tree_capacity {
            anyhow::bail!(
                "Target checkpoint {} exceeds checkpoint tree capacity for height {}",
                target_checkpoint_id,
                checkpoint_tree_height
            );
        }

        let target_root = checkpoint_tree_reader.checkpoint_tree_get_root_hash(target_checkpoint_id).await?;
        let mut leaves = Vec::with_capacity((next_checkpoint_id - window_start) as usize);
        for checkpoint_id in window_start..=target_checkpoint_id {
            let leaf_hash = checkpoint_tree_reader
                .checkpoint_tree_get_leaf_hash(checkpoint_id, checkpoint_id)
                .await?;
            if leaf_hash == Hasher::get_zero_hash(0) {
                anyhow::bail!("Missing or zero checkpoint leaf at checkpoint {}", checkpoint_id);
            }
            leaves.push(MerkleLeafNode {
                index: checkpoint_id,
                value: leaf_hash,
            });
        }

        for pair in leaves.windows(2) {
            if pair[1].index != pair[0].index + 1 {
                anyhow::bail!(
                    "Non-contiguous checkpoint leaves: {} followed by {}",
                    pair[0].index,
                    pair[1].index
                );
            }
        }

        let candidate_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(checkpoint_tree_height));
        let mut init_proof = checkpoint_tree_reader
            .checkpoint_tree_get_merkle_proof(window_start, window_start)
            .await?;
        if init_proof.index != window_start || init_proof.value != leaves[0].value {
            anyhow::bail!("Checkpoint proof does not match the first rollback window leaf at {}", window_start);
        }
        for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
            if (window_start >> layer_idx) & 1 == 0 {
                *sibling = Hasher::get_zero_hash(layer_idx);
            }
        }
        candidate_tree.injest_merkle_proof(&init_proof)?;
        for leaf in &leaves {
            let proof = candidate_tree.set_leaf(leaf.index, leaf.value);
            candidate_tree.roots.insert(proof.new_root, leaf.index);
        }
        candidate_tree.ensure_leaf_root_recorded(window_start);

        let candidate_root = candidate_tree.get_root();
        if candidate_root != target_root {
            anyhow::bail!(
                "Checkpoint rollback rebuild root mismatch at target {}: rebuilt {:?}, database {:?}",
                target_checkpoint_id,
                candidate_root,
                target_root
            );
        }

        let mut bucket_leaves = Vec::with_capacity((target_checkpoint_id - bucket_start + 1) as usize);
        for checkpoint_id in bucket_start..=target_checkpoint_id {
            let checkpoint_hash = checkpoint_tree_reader
                .checkpoint_tree_get_leaf_hash(checkpoint_id, checkpoint_id)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to read checkpoint {} for rollback bucket {} at {}: {}", checkpoint_id, target_bucket_index, bucket_path, error))?;
            if checkpoint_hash == Hasher::get_zero_hash(0) {
                anyhow::bail!(
                    "Checkpoint {} for rollback bucket {} at {} is missing or zero",
                    checkpoint_id,
                    target_bucket_index,
                    bucket_path
                );
            }
            bucket_leaves.push((checkpoint_id, checkpoint_hash));
        }

        let mut candidate_file = self.file_system.file_like_fs_create(&temporary_path).await?;
        candidate_file.file_like_set_len(0).await?;
        candidate_file.seek(std::io::SeekFrom::Start(0)).await?;
        candidate_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;
        for leaf in &leaves {
            let record_offset = (leaf.index % self.max_checkpoints_to_keep)
                .checked_mul(CHECKPOINT_BACKUP_ITEM_SIZE as u64)
                .and_then(|offset| offset.checked_add(CHECKPOINT_BACKUP_MAGIC_LEN as u64))
                .ok_or_else(|| anyhow::anyhow!("Checkpoint rollback ring offset overflow at checkpoint {}", leaf.index))?;
            candidate_file.seek(std::io::SeekFrom::Start(record_offset)).await?;
            candidate_file.write_u64_le(leaf.index).await?;
            candidate_file.write_all(&leaf.value.into_owned_32bytes()).await?;
        }
        candidate_file.seek(std::io::SeekFrom::Start(0)).await?;
        if candidate_file.read_u64_le().await? != CHECKPOINT_BACKUP_MAGIC_U64_LE {
            anyhow::bail!("Checkpoint rollback candidate has invalid magic");
        }
        for leaf in &leaves {
            let record_offset = (leaf.index % self.max_checkpoints_to_keep)
                .checked_mul(CHECKPOINT_BACKUP_ITEM_SIZE as u64)
                .and_then(|offset| offset.checked_add(CHECKPOINT_BACKUP_MAGIC_LEN as u64))
                .ok_or_else(|| anyhow::anyhow!("Checkpoint rollback ring offset overflow at checkpoint {}", leaf.index))?;
            candidate_file.seek(std::io::SeekFrom::Start(record_offset)).await?;
            let stored_checkpoint_id = candidate_file.read_u64_le().await?;
            let mut stored_hash = [0u8; 32];
            candidate_file.read_exact(&mut stored_hash).await?;
            if stored_checkpoint_id != leaf.index || Hash::from_ref_32bytes(&stored_hash) != leaf.value {
                anyhow::bail!("Checkpoint rollback candidate ring validation failed at checkpoint {}", leaf.index);
            }
        }
        self.file_system
            .file_like_fs_sync_file_with_path(&temporary_path, &mut candidate_file)
            .await?;

        let mut bucket_file = self
            .file_system
            .file_like_fs_create(&bucket_temporary_path)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to create rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_temporary_path, error))?;
        bucket_file.file_like_set_len(0).await.map_err(|error| {
            anyhow::anyhow!("Failed to truncate rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_temporary_path, error)
        })?;
        bucket_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await.map_err(|error| {
            anyhow::anyhow!("Failed to write rollback checkpoint bucket {} magic at {}: {}", target_bucket_index, bucket_temporary_path, error)
        })?;
        for (checkpoint_id, checkpoint_hash) in &bucket_leaves {
            bucket_file.write_u64_le(*checkpoint_id).await.map_err(|error| {
                anyhow::anyhow!("Failed to write checkpoint {} to rollback bucket {} at {}: {}", checkpoint_id, target_bucket_index, bucket_temporary_path, error)
            })?;
            bucket_file.write_all(&checkpoint_hash.into_owned_32bytes()).await.map_err(|error| {
                anyhow::anyhow!("Failed to write checkpoint {} hash to rollback bucket {} at {}: {}", checkpoint_id, target_bucket_index, bucket_temporary_path, error)
            })?;
        }
        bucket_file.seek(std::io::SeekFrom::Start(0)).await.map_err(|error| {
            anyhow::anyhow!("Failed to seek rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_temporary_path, error)
        })?;
        if bucket_file.read_u64_le().await.map_err(|error| {
            anyhow::anyhow!("Failed to validate rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_temporary_path, error)
        })? != CHECKPOINT_BACKUP_MAGIC_U64_LE {
            anyhow::bail!("Rollback checkpoint bucket {} at {} has invalid magic", target_bucket_index, bucket_temporary_path);
        }
        for (expected_checkpoint_id, expected_hash) in &bucket_leaves {
            let stored_checkpoint_id = bucket_file.read_u64_le().await.map_err(|error| {
                anyhow::anyhow!("Failed to validate checkpoint {} in rollback bucket {} at {}: {}", expected_checkpoint_id, target_bucket_index, bucket_temporary_path, error)
            })?;
            let mut stored_hash = [0u8; 32];
            bucket_file.read_exact(&mut stored_hash).await.map_err(|error| {
                anyhow::anyhow!("Failed to validate checkpoint {} hash in rollback bucket {} at {}: {}", expected_checkpoint_id, target_bucket_index, bucket_temporary_path, error)
            })?;
            if stored_checkpoint_id != *expected_checkpoint_id || Hash::from_ref_32bytes(&stored_hash) != *expected_hash {
                anyhow::bail!(
                    "Rollback checkpoint bucket {} validation failed at checkpoint {} in {}",
                    target_bucket_index,
                    expected_checkpoint_id,
                    bucket_temporary_path
                );
            }
        }
        self.file_system
            .file_like_fs_sync_file_with_path(&bucket_temporary_path, &mut bucket_file)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to sync rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_temporary_path, error))?;

        self.file_system
            .file_like_rename(&bucket_temporary_path, &bucket_path)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to install rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_path, error))?;
        if let Some(old_last_bucket) = old_last_bucket {
            let first_later_bucket = target_bucket_index
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket index overflow after target {}", target_checkpoint_id))?;
            if first_later_bucket <= old_last_bucket {
                for bucket_index in first_later_bucket..=old_last_bucket {
                    let later_bucket_path = self.bucket_file_path(bucket_index);
                    let exists = self
                        .file_system
                        .file_like_exists(&later_bucket_path)
                        .await
                        .map_err(|error| anyhow::anyhow!("Failed to inspect checkpoint bucket {} at {} during rollback: {}", bucket_index, later_bucket_path, error))?;
                    if exists {
                        self.file_system
                            .file_like_remove_file(&later_bucket_path)
                            .await
                            .map_err(|error| anyhow::anyhow!("Failed to remove checkpoint bucket {} at {} during rollback: {}", bucket_index, later_bucket_path, error))?;
                    }
                }
            }
        }
        self.file_system
            .file_like_fs_sync_parent_dir(&bucket_path)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to sync parent for rollback checkpoint bucket {} at {}: {}", target_bucket_index, bucket_path, error))?;

        self.file_system
            .file_like_rename(&temporary_path, &self.backup_file_path)
            .await?;
        self.backup_file = candidate_file;
        self.checkpoint_tree = candidate_tree;
        self.min_backed_up_checkpoint_id = window_start;
        self.next_backup_checkpoint_id = next_checkpoint_id;
        self.active_bucket = Some((target_bucket_index, bucket_file));
        self.file_system
            .file_like_fs_sync_parent_dir(&self.backup_file_path)
            .await?;
        Ok(())
    }

    pub async fn append_checkpoint_leaf_hash(&mut self, checkpoint_id: u64, checkpoint_hash: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        tracing::info!(
            "Appending checkpoint leaf hash. ID: {}, Hash: {:?} ({})",
            checkpoint_id,
            checkpoint_hash,
            hex::encode(checkpoint_hash.into_owned_32bytes())
        );
        let old_root = self.checkpoint_tree.get_root();
        if checkpoint_id != self.next_backup_checkpoint_id {
            if checkpoint_id == self.next_backup_checkpoint_id.saturating_sub(1) {
                if self.checkpoint_tree.get_leaf_value(checkpoint_id) == checkpoint_hash {
                    self.append_bucket_record(checkpoint_id, checkpoint_hash).await?;
                    let p = self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash);
                    self.checkpoint_tree.ensure_leaf_root_recorded(checkpoint_id);
                    return Ok(p);
                }
            }
            if checkpoint_id != 0 || self.next_backup_checkpoint_id != 0 {
                anyhow::bail!(
                    "Sequential append required. Expected {}, got {}",
                    self.next_backup_checkpoint_id,
                    checkpoint_id
                );
            }
        }

        let offset = CHECKPOINT_BACKUP_MAGIC_LEN as u64 + (checkpoint_id % self.max_checkpoints_to_keep) * CHECKPOINT_BACKUP_ITEM_SIZE as u64;

        self.backup_file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.backup_file.write_u64_le(checkpoint_id).await?;
        self.backup_file.write_all(&checkpoint_hash.into_owned_32bytes()).await?;

        self.file_system
            .file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file)
            .await?;

        self.append_bucket_record(checkpoint_id, checkpoint_hash).await?;

        let p = self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash);
        self.checkpoint_tree.roots.insert(p.new_root, checkpoint_id);

        self.next_backup_checkpoint_id = checkpoint_id + 1;

        let count = self.next_backup_checkpoint_id - self.min_backed_up_checkpoint_id;
        if count > self.max_checkpoints_to_keep {
            self.min_backed_up_checkpoint_id += 1;
        }
        let new_root = self.checkpoint_tree.get_root();
        tracing::info!(
            "Appended checkpoint leaf hash. ID: {}, Old Root: {:?} ({}), New Root: {:?} ({})",
            checkpoint_id,
            old_root,
            hex::encode(old_root.into_owned_32bytes()),
            new_root,
            hex::encode(new_root.into_owned_32bytes())
        );

        Ok(p)
    }

    pub fn has_appropriate_checkpoint_history_for_stale_proofs(&self, max_stale_checkpoint_age: u64, current_checkpoint_id: u64) -> bool {
        let required_min = current_checkpoint_id.saturating_sub(max_stale_checkpoint_age);
        self.next_backup_checkpoint_id > current_checkpoint_id && self.min_backed_up_checkpoint_id <= required_min
    }

    pub async fn hard_reset_and_truncate(&mut self, start_checkpoint_id: u64) -> anyhow::Result<()> {
        tracing::warn!("Hard reset of Checkpoint Backup Manager at ID {}", start_checkpoint_id);
        let old_last_bucket = self
            .next_backup_checkpoint_id
            .checked_sub(1)
            .map(|checkpoint_id| checkpoint_id / CHECKPOINTS_PER_BUCKET);
        self.active_bucket = None;
        let start_bucket = start_checkpoint_id / CHECKPOINTS_PER_BUCKET;
        let start_record_index = start_checkpoint_id % CHECKPOINTS_PER_BUCKET;
        let start_bucket_path = self.bucket_file_path(start_bucket);
        let start_bucket_exists = self
            .file_system
            .file_like_exists(&start_bucket_path)
            .await
            .map_err(|error| anyhow::anyhow!("Failed to inspect checkpoint bucket {} at {} during hard reset: {}", start_bucket, start_bucket_path, error))?;
        if start_bucket_exists {
            let mut start_bucket_file = self
                .file_system
                .file_like_fs_create(&start_bucket_path)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to open checkpoint bucket {} at {} during hard reset: {}", start_bucket, start_bucket_path, error))?;
            let retained_len = start_record_index
                .checked_mul(CHECKPOINT_BACKUP_ITEM_SIZE as u64)
                .and_then(|len| len.checked_add(CHECKPOINT_BACKUP_MAGIC_LEN as u64))
                .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket {} truncate length overflow during hard reset", start_bucket))?;
            start_bucket_file.file_like_set_len(retained_len).await.map_err(|error| {
                anyhow::anyhow!("Failed to truncate checkpoint bucket {} at {} during hard reset: {}", start_bucket, start_bucket_path, error)
            })?;
            start_bucket_file.seek(std::io::SeekFrom::Start(0)).await.map_err(|error| {
                anyhow::anyhow!("Failed to seek checkpoint bucket {} at {} during hard reset: {}", start_bucket, start_bucket_path, error)
            })?;
            start_bucket_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await.map_err(|error| {
                anyhow::anyhow!("Failed to write checkpoint bucket {} magic at {} during hard reset: {}", start_bucket, start_bucket_path, error)
            })?;
            self.file_system
                .file_like_fs_flush_file_with_path(&start_bucket_path, &mut start_bucket_file)
                .await
                .map_err(|error| anyhow::anyhow!("Failed to flush checkpoint bucket {} at {} during hard reset: {}", start_bucket, start_bucket_path, error))?;
        }

        if let Some(old_last_bucket) = old_last_bucket {
            let first_removed_bucket = start_bucket
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("Checkpoint bucket index overflow during hard reset at checkpoint {}", start_checkpoint_id))?;
            if first_removed_bucket <= old_last_bucket {
                for bucket_index in first_removed_bucket..=old_last_bucket {
                    let bucket_path = self.bucket_file_path(bucket_index);
                    let exists = self
                        .file_system
                        .file_like_exists(&bucket_path)
                        .await
                        .map_err(|error| anyhow::anyhow!("Failed to inspect checkpoint bucket {} at {} during hard reset: {}", bucket_index, bucket_path, error))?;
                    if exists {
                        self.file_system
                            .file_like_remove_file(&bucket_path)
                            .await
                            .map_err(|error| anyhow::anyhow!("Failed to remove checkpoint bucket {} at {} during hard reset: {}", bucket_index, bucket_path, error))?;
                    }
                }
            }
        }

        let height = self.checkpoint_tree.get_height();
        self.checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(height));
        self.backup_file.file_like_set_len(CHECKPOINT_BACKUP_MAGIC_LEN as u64).await?;
        self.backup_file.seek(std::io::SeekFrom::Start(0)).await?;
        self.backup_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;
        self.file_system
            .file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file)
            .await?;

        self.min_backed_up_checkpoint_id = start_checkpoint_id;
        self.next_backup_checkpoint_id = start_checkpoint_id;
        Ok(())
    }

    pub async fn sync_from_coordinator_client<CoordinatorClient: RealmCoordinatorClient<F, Hash>, F>(
        &mut self,
        coordinator_client: &CoordinatorClient,
        sync_batch_size: usize,
    ) -> anyhow::Result<()> {
        let remote_latest_checkpoint_id: u64 = coordinator_client.rc_get_latest_checkpoint_id().await?;

        let required_min_checkpoint = if remote_latest_checkpoint_id >= STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF {
            remote_latest_checkpoint_id - STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF
        } else {
            0
        };

        let mut needs_reset = false;

        if self.min_backed_up_checkpoint_id > required_min_checkpoint {
            tracing::warn!(
                "Checkpoint history gap detected. Local Min: {}, Required Min: {}. Triggering Reset.",
                self.min_backed_up_checkpoint_id,
                required_min_checkpoint
            );
            needs_reset = true;
        }
        if !needs_reset && self.next_backup_checkpoint_id > 0 {
            if self.next_backup_checkpoint_id > remote_latest_checkpoint_id + 1 {
                tracing::warn!(
                    "Local checkpoint ID {} is ahead of remote {}. Triggering Reset.",
                    self.next_backup_checkpoint_id,
                    remote_latest_checkpoint_id
                );
                needs_reset = true;
            } else {
                let overlap_check_id = self.next_backup_checkpoint_id - 1;
                let local_hash = self.checkpoint_tree.get_leaf_value(overlap_check_id);

                let remote_leaves = coordinator_client.rc_get_checkpoint_leaves_batch(overlap_check_id, 1).await?;

                if remote_leaves.is_empty() {
                    tracing::warn!("Coordinator returned empty batch for overlap check at {}. Triggering Reset.", overlap_check_id);
                    needs_reset = true;
                } else if remote_leaves[0] != local_hash {
                    tracing::warn!(
                        "Checkpoint Fork detected at {}. Local: {:?}, Remote: {:?}. Triggering Reset.",
                        overlap_check_id,
                        local_hash,
                        remote_leaves[0]
                    );
                    needs_reset = true;
                }
            }
        }

        if needs_reset {
            self.hard_reset_and_truncate(required_min_checkpoint).await?;
        }

        if self.next_backup_checkpoint_id > remote_latest_checkpoint_id {
            return Ok(());
        }

        let start_id = self.next_backup_checkpoint_id;
        let total_to_fetch = remote_latest_checkpoint_id - start_id + 1;

        tracing::info!(
            "Syncing {} checkpoints from Coordinator. Range: [{}, {}]",
            total_to_fetch,
            start_id,
            remote_latest_checkpoint_id
        );

        let num_full_batches = total_to_fetch / sync_batch_size as u64;
        let partial_batch_size = total_to_fetch % sync_batch_size as u64;

        for i in 0..num_full_batches {
            let batch_start_id = start_id + i * sync_batch_size as u64;
            let leaves = coordinator_client
                .rc_get_checkpoint_leaves_batch(batch_start_id, sync_batch_size as u32)
                .await?;
            
            if leaves.len() != sync_batch_size {
                anyhow::bail!("Coordinator returned insufficient leaves for batch starting at {}", batch_start_id);
            }
            
            for (j, hash) in leaves.into_iter().enumerate() {
                let checkpoint_id = batch_start_id + j as u64;
                self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
            }
        }

        if partial_batch_size > 0 {
            let batch_start_id = start_id + num_full_batches * sync_batch_size as u64;
            let leaves = coordinator_client
                .rc_get_checkpoint_leaves_batch(batch_start_id, partial_batch_size as u32)
                .await?;
            
            if leaves.len() != partial_batch_size as usize {
                anyhow::bail!("Coordinator returned insufficient leaves for partial batch at {}", batch_start_id);
            }
            
            for (j, hash) in leaves.into_iter().enumerate() {
                let checkpoint_id = batch_start_id + j as u64;
                self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
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
        let protocol_start = last_committed_checkpoint_id.saturating_sub(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF);

        let capacity_start = if last_committed_checkpoint_id >= self.max_checkpoints_to_keep {
            last_committed_checkpoint_id - self.max_checkpoints_to_keep + 1
        } else {
            0
        };

        let required_history_start = std::cmp::max(protocol_start, capacity_start);

        tracing::info!(
            "Syncing Checkpoint Manager. Target: {}. ReqStart: {}. Local: [{}, {})",
            last_committed_checkpoint_id,
            required_history_start,
            self.min_backed_up_checkpoint_id,
            self.next_backup_checkpoint_id
        );

        let needs_reset =
            (self.next_backup_checkpoint_id == 0 && self.min_backed_up_checkpoint_id == 0) ||
            (self.min_backed_up_checkpoint_id > required_history_start) ||
            (self.next_backup_checkpoint_id < required_history_start) ||
            (last_committed_checkpoint_id > self.next_backup_checkpoint_id + self.max_checkpoints_to_keep * 2);

        if needs_reset {
            self.hard_reset_and_truncate(required_history_start).await?;
        }

        let is_tree_empty = self.checkpoint_tree.get_root() == Hasher::get_zero_hash(self.checkpoint_tree.get_height() as usize);

        if is_tree_empty || self.next_backup_checkpoint_id == required_history_start {
            let start = self.next_backup_checkpoint_id;
            let mut init_proof = checkpoint_tree_reader.checkpoint_tree_get_merkle_proof(start, start).await?;

            // Starting proof right siblings must be zeroed for historical reconstruct.
            for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
                let is_path_left = (start >> layer_idx) & 1 == 0;
                if is_path_left {
                    *sibling = Hasher::get_zero_hash(layer_idx);
                }
            }

            self.checkpoint_tree.injest_merkle_proof(&init_proof)?;
            if init_proof.value != Hasher::get_zero_hash(0) {
                self.append_checkpoint_leaf_hash(start, init_proof.value).await?;
            } else if last_committed_checkpoint_id != 0 {
                anyhow::bail!(
                    "DB sync integrity error at checkpoint {}, the last committed checkpoint was supposed to be {}, but it is a zero leaf",
                    start,
                    last_committed_checkpoint_id
                );
            } else {
            }
        }

        let mut current_sync_idx = self.next_backup_checkpoint_id;
        while current_sync_idx <= last_committed_checkpoint_id {
            let batch_end = std::cmp::min(current_sync_idx + sync_batch_size as u64 - 1, last_committed_checkpoint_id);
            let count = (batch_end - current_sync_idx + 1) as usize;

            let height = self.checkpoint_tree.get_height();
            let keys: Vec<SimpleMerkleNodeKey> = (current_sync_idx..=batch_end).map(|idx| SimpleMerkleNodeKey::new(height, idx)).collect();

            let hashes = checkpoint_tree_reader
                .checkpoint_tree_get_nodes(last_committed_checkpoint_id, &keys)
                .await?;
            if hashes.len() != count {
                anyhow::bail!("DB sync mismatch");
            }

            for (i, hash) in hashes.into_iter().enumerate() {
                if hash != Hasher::get_zero_hash(0) {
                    self.append_checkpoint_leaf_hash(current_sync_idx + i as u64, hash).await?;
                } else if last_committed_checkpoint_id != 0 || i != 0 {
                    anyhow::bail!(
                        "DB sync integrity error at checkpoint {}, the last committed checkpoint was supposed to be {}, but it is a zero leaf",
                        current_sync_idx + i as u64,
                        last_committed_checkpoint_id
                    );
                } else {
                }
            }
            current_sync_idx = batch_end + 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::HashMap,
        io,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use async_trait::async_trait;
    use parth_common::memory_stores::{
        dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore,
        traits::PsyMemoryMerkleStoreImm,
    };
    use parth_core::{
        crypto::hash::{
            merkle_proof::MerkleProofCore,
            traits::{FromU64x4, MerkleZeroHasher},
        },
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        pgoldilocks::PoseidonHasher,
        PHash,
        protocol::core_types::Q256BitHash,
    };
    use psy_io::tokio::{FileLikeMetadata, TokioLikeFileSystem, TokioStdFileSystem};
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader,
    };

    use super::{
        CheckpointTreeBackupManager, CHECKPOINTS_PER_BUCKET, CHECKPOINT_BACKUP_ITEM_SIZE,
        CHECKPOINT_BACKUP_MAGIC_BYTES, CHECKPOINT_BACKUP_MAGIC_LEN,
    };
    const TREE_HEIGHT: u8 = 8;
    const BUCKET_TREE_HEIGHT: u8 = 12;
    const LIVE_PATH: &str = "local_checkpoints/checkpoint_tree.bin";

    struct CheckpointReader {
        leaves: HashMap<u64, PHash>,
        tree: PsyDashMemoryAppendOnlyMerkleStore<PoseidonHasher, PHash>,
        root_override: Option<PHash>,
    }

    impl CheckpointReader {
        fn new(last_checkpoint_id: u64) -> Self {
            Self::new_with_height(last_checkpoint_id, TREE_HEIGHT)
        }

        fn new_with_height(last_checkpoint_id: u64, tree_height: u8) -> Self {
            let tree = PsyDashMemoryAppendOnlyMerkleStore::<PoseidonHasher, PHash>::new(tree_height);
            let mut leaves = HashMap::new();
            for checkpoint_id in 0..=last_checkpoint_id {
                let leaf = PHash::from_u64x4([checkpoint_id + 1, 0, 0, 0]);
                tree.set_leaf(checkpoint_id, leaf);
                leaves.insert(checkpoint_id, leaf);
            }
            Self {
                leaves,
                tree,
                root_override: None,
            }
        }
    }

    #[async_trait]
    impl PsyNodeCheckpointTreeDatabaseReader<PHash> for CheckpointReader {
        async fn checkpoint_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<PHash> {
            if checkpoint_id != leaf_index {
                anyhow::bail!("test reader requires checkpoint_id == leaf_index");
            }
            self.leaves
                .get(&leaf_index)
                .copied()
                .ok_or_else(|| anyhow::anyhow!("missing checkpoint leaf {}", leaf_index))
        }

        async fn checkpoint_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<PHash> {
            Ok(self
                .root_override
                .unwrap_or_else(|| self.tree.get_historical_merkle_proof_at_historical_index(checkpoint_id, checkpoint_id).root))
        }

        async fn checkpoint_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<PHash>> {
            Ok(self.tree.get_historical_merkle_proof_at_historical_index(leaf_index, checkpoint_id))
        }

        async fn checkpoint_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<PHash>> {
            Ok(keys
                .iter()
                .map(|key| self.tree.get_historical_node_value(key, checkpoint_id))
                .collect())
        }
    }

    struct FailingInstallFileSystem {
        inner: SimpleMockMemoryFileSystem,
        fail_live_rename: AtomicBool,
    }

    impl FailingInstallFileSystem {
        fn new() -> Self {
            Self {
                inner: SimpleMockMemoryFileSystem::new(),
                fail_live_rename: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl TokioLikeFileSystem for FailingInstallFileSystem {
        type File = std::io::Cursor<Vec<u8>>;

        async fn file_like_fs_create_dir_all(&self, path: &str) -> io::Result<()> {
            self.inner.file_like_fs_create_dir_all(path).await
        }

        async fn file_like_fs_create(&self, path: &str) -> io::Result<Self::File> {
            self.inner.file_like_fs_create(path).await
        }

        async fn file_like_fs_open(&self, path: &str) -> io::Result<Self::File> {
            self.inner.file_like_fs_open(path).await
        }

        async fn file_like_fs_flush_file_with_path(&self, path: &str, file: &mut Self::File) -> io::Result<()> {
            self.inner.file_like_fs_flush_file_with_path(path, file).await
        }

        async fn file_like_fs_sync_file_with_path(&self, path: &str, file: &mut Self::File) -> io::Result<()> {
            self.inner.file_like_fs_sync_file_with_path(path, file).await
        }

        async fn file_like_exists(&self, path: &str) -> io::Result<bool> {
            self.inner.file_like_exists(path).await
        }

        async fn file_like_remove_file(&self, path: &str) -> io::Result<()> {
            self.inner.file_like_remove_file(path).await
        }

        async fn file_like_rename(&self, old_path: &str, new_path: &str) -> io::Result<()> {
            if new_path == LIVE_PATH && self.fail_live_rename.load(Ordering::SeqCst) {
                return Err(io::Error::new(io::ErrorKind::Other, "injected live rename failure"));
            }
            self.inner.file_like_rename(old_path, new_path).await
        }

        async fn file_like_fs_sync_parent_dir(&self, path: &str) -> io::Result<()> {
            self.inner.file_like_fs_sync_parent_dir(path).await
        }

        async fn file_like_metadata(&self, path: &str) -> io::Result<FileLikeMetadata> {
            self.inner.file_like_metadata(path).await
        }
    }

    async fn manager_with_live_file(
        file_system: Arc<FailingInstallFileSystem>,
        reader: &CheckpointReader,
    ) -> anyhow::Result<CheckpointTreeBackupManager<PoseidonHasher, PHash, FailingInstallFileSystem>> {
        CheckpointTreeBackupManager::new_from_file_path(file_system, 4, TREE_HEIGHT, reader, LIVE_PATH, true).await
    }

    #[tokio::test]
    async fn existing_ring_rejects_trailing_partial_record() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut bytes = CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec();
        bytes.push(1);
        file_system.inner.files.insert(LIVE_PATH.to_string(), bytes);

        let error = CheckpointTreeBackupManager::<PoseidonHasher, PHash, FailingInstallFileSystem>::new_from_file_path(
            file_system,
            4,
            TREE_HEIGHT,
            &reader,
            LIVE_PATH,
            false,
        )
        .await
        .err()
        .expect("trailing partial record must fail");

        assert!(error.to_string().contains("trailing partial record"), "{error}");
        Ok(())
    }

    #[tokio::test]
    async fn failure_after_bucket_commit_preserves_live_ring_and_retry_succeeds() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(5);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        manager.append_checkpoint_leaf_hash(0, reader.leaves[&0]).await?;
        let bucket_path = manager.bucket_file_path(0);
        let live_before = file_system.inner.files.get(LIVE_PATH).unwrap().clone();
        let bucket_before = file_system.inner.files.get(&bucket_path).unwrap().clone();
        let head_before = manager.get_current_checkpoint_id_head();
        let root_before = manager.get_current_checkpoint_tree_root_head();

        file_system.fail_live_rename.store(true, Ordering::SeqCst);
        let error = manager.rebuild_from_database_at_checkpoint(&reader, 5).await.unwrap_err();

        assert!(error.to_string().contains("injected live rename failure"), "{error}");
        assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
        assert_ne!(*file_system.inner.files.get(&bucket_path).unwrap(), bucket_before);
        assert_eq!(manager.get_current_checkpoint_id_head(), head_before);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);

        file_system.fail_live_rename.store(false, Ordering::SeqCst);
        manager.rebuild_from_database_at_checkpoint(&reader, 5).await?;

        assert_eq!(manager.get_current_checkpoint_id_head(), 5);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reader.checkpoint_tree_get_root_hash(5).await?);
        Ok(())
    }


    #[tokio::test]
    async fn successful_rebuild_installs_valid_ring_with_target_head_and_root() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(6);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;

        manager.rebuild_from_database_at_checkpoint(&reader, 5).await?;

        assert_eq!(manager.get_current_checkpoint_id_head(), 5);
        assert_eq!(manager.min_backed_up_checkpoint_id, 2);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reader.checkpoint_tree_get_root_hash(5).await?);
        let live = file_system.inner.files.get(LIVE_PATH).unwrap();
        assert_eq!(&live[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        for checkpoint_id in 2..=5 {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + (checkpoint_id as usize % 4) * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(live[offset..offset + 8].try_into().unwrap()), checkpoint_id);
        }
        drop(live);
        manager.append_checkpoint_leaf_hash(6, reader.leaves[&6]).await?;
        let live = file_system.inner.files.get(LIVE_PATH).unwrap();
        let offset = CHECKPOINT_BACKUP_MAGIC_LEN + (6usize % 4) * CHECKPOINT_BACKUP_ITEM_SIZE;
        assert_eq!(u64::from_le_bytes(live[offset..offset + 8].try_into().unwrap()), 6);
        Ok(())
    }
    #[tokio::test]
    async fn append_crossing_bucket_boundary_creates_second_bucket_with_records() -> anyhow::Result<()> {
        let reader = CheckpointReader::new_with_height(CHECKPOINTS_PER_BUCKET, BUCKET_TREE_HEIGHT);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = CheckpointTreeBackupManager::<PoseidonHasher, PHash, FailingInstallFileSystem>::new_from_file_path(
            file_system.clone(),
            4,
            BUCKET_TREE_HEIGHT,
            &reader,
            LIVE_PATH,
            true,
        )
        .await?;
        for checkpoint_id in 0..=CHECKPOINTS_PER_BUCKET {
            manager.append_checkpoint_leaf_hash(checkpoint_id, reader.leaves[&checkpoint_id]).await?;
        }

        let first_path = manager.bucket_file_path(0);
        let second_path = manager.bucket_file_path(1);
        let first = file_system.inner.files.get(&first_path).unwrap();
        let second = file_system.inner.files.get(&second_path).unwrap();
        assert_eq!(first.len(), CHECKPOINT_BACKUP_MAGIC_LEN + CHECKPOINTS_PER_BUCKET as usize * CHECKPOINT_BACKUP_ITEM_SIZE);
        assert_eq!(&first[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        let last_offset = CHECKPOINT_BACKUP_MAGIC_LEN + (CHECKPOINTS_PER_BUCKET as usize - 1) * CHECKPOINT_BACKUP_ITEM_SIZE;
        assert_eq!(u64::from_le_bytes(first[last_offset..last_offset + 8].try_into().unwrap()), CHECKPOINTS_PER_BUCKET - 1);
        assert_eq!(second.len(), CHECKPOINT_BACKUP_MAGIC_LEN + CHECKPOINT_BACKUP_ITEM_SIZE);
        assert_eq!(&second[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        assert_eq!(u64::from_le_bytes(second[CHECKPOINT_BACKUP_MAGIC_LEN..CHECKPOINT_BACKUP_MAGIC_LEN + 8].try_into().unwrap()), CHECKPOINTS_PER_BUCKET);
        assert_eq!(&second[CHECKPOINT_BACKUP_MAGIC_LEN + 8..CHECKPOINT_BACKUP_MAGIC_LEN + CHECKPOINT_BACKUP_ITEM_SIZE], &reader.leaves[&CHECKPOINTS_PER_BUCKET].into_owned_32bytes());
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_cleanup_skips_missing_middle_bucket_and_deletes_later_buckets() -> anyhow::Result<()> {
        let target_checkpoint_id = CHECKPOINTS_PER_BUCKET + 6;
        let reader = CheckpointReader::new_with_height(target_checkpoint_id, BUCKET_TREE_HEIGHT);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = CheckpointTreeBackupManager::<PoseidonHasher, PHash, FailingInstallFileSystem>::new_from_file_path(
            file_system.clone(),
            4,
            BUCKET_TREE_HEIGHT,
            &reader,
            LIVE_PATH,
            true,
        )
        .await?;
        manager.next_backup_checkpoint_id = CHECKPOINTS_PER_BUCKET * 4;
        let later_path = manager.bucket_file_path(3);
        file_system.inner.files.insert(later_path.clone(), CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec());

        manager.rebuild_from_database_at_checkpoint(&reader, target_checkpoint_id).await?;

        assert!(!file_system.inner.files.contains_key(&later_path));
        let target_path = manager.bucket_file_path(1);
        let bucket = file_system.inner.files.get(&target_path).unwrap();
        assert_eq!(bucket.len(), CHECKPOINT_BACKUP_MAGIC_LEN + 7 * CHECKPOINT_BACKUP_ITEM_SIZE);
        for checkpoint_id in CHECKPOINTS_PER_BUCKET..=target_checkpoint_id {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + (checkpoint_id - CHECKPOINTS_PER_BUCKET) as usize * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(bucket[offset..offset + 8].try_into().unwrap()), checkpoint_id);
            assert_eq!(&bucket[offset + 8..offset + CHECKPOINT_BACKUP_ITEM_SIZE], &reader.leaves[&checkpoint_id].into_owned_32bytes());
        }
        assert_eq!(manager.active_bucket.as_ref().map(|(index, _)| *index), Some(1));
        Ok(())
    }

    #[tokio::test]
    async fn hard_reset_preserves_start_bucket_prefix_and_removes_later_buckets() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        let start_checkpoint_id = CHECKPOINTS_PER_BUCKET + 2;
        manager.next_backup_checkpoint_id = CHECKPOINTS_PER_BUCKET * 3;
        let start_path = manager.bucket_file_path(1);
        let removed_path = manager.bucket_file_path(2);
        let mut start_bucket = CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec();
        for checkpoint_id in CHECKPOINTS_PER_BUCKET..CHECKPOINTS_PER_BUCKET + 4 {
            start_bucket.extend_from_slice(&checkpoint_id.to_le_bytes());
            start_bucket.extend_from_slice(&PHash::from_u64x4([checkpoint_id + 1, 0, 0, 0]).into_owned_32bytes());
        }
        let retained_prefix = start_bucket[..CHECKPOINT_BACKUP_MAGIC_LEN + 2 * CHECKPOINT_BACKUP_ITEM_SIZE].to_vec();
        file_system.inner.files.insert(start_path.clone(), start_bucket);
        file_system.inner.files.insert(removed_path.clone(), CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec());

        manager.hard_reset_and_truncate(start_checkpoint_id).await?;

        assert_eq!(*file_system.inner.files.get(&start_path).unwrap(), retained_prefix);
        assert!(!file_system.inner.files.contains_key(&removed_path));
        assert!(manager.active_bucket.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn hard_reset_truncates_existing_mid_bucket_on_real_filesystem() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(3);
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!("checkpoint_manager_reset_{}_{}", std::process::id(), unique));
        tokio::fs::create_dir_all(&directory).await?;
        let live_path = directory.join("checkpoint_tree.bin");
        let live_path = live_path.to_string_lossy().into_owned();
        let file_system = Arc::new(TokioStdFileSystem);
        let mut manager = CheckpointTreeBackupManager::<PoseidonHasher, PHash, TokioStdFileSystem>::new_from_file_path(
            file_system,
            4,
            TREE_HEIGHT,
            &reader,
            &live_path,
            true,
        )
        .await?;
        for checkpoint_id in 0..=3 {
            manager.append_checkpoint_leaf_hash(checkpoint_id, reader.leaves[&checkpoint_id]).await?;
        }
        let bucket_path = manager.bucket_file_path(0);

        manager.hard_reset_and_truncate(2).await?;
        manager.checkpoint_tree.set_leaf(0, reader.leaves[&0]);
        manager.checkpoint_tree.set_leaf(1, reader.leaves[&1]);
        manager.append_checkpoint_leaf_hash(2, reader.leaves[&2]).await?;

        let bucket = tokio::fs::read(&bucket_path).await?;
        assert_eq!(bucket.len(), CHECKPOINT_BACKUP_MAGIC_LEN + 3 * CHECKPOINT_BACKUP_ITEM_SIZE);
        for checkpoint_id in 0..=2 {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + checkpoint_id as usize * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(bucket[offset..offset + 8].try_into().unwrap()), checkpoint_id);
            assert_eq!(&bucket[offset + 8..offset + CHECKPOINT_BACKUP_ITEM_SIZE], &reader.leaves[&checkpoint_id].into_owned_32bytes());
        }
        tokio::fs::remove_dir_all(directory).await?;
        Ok(())
    }

    #[tokio::test]
    async fn append_initializes_existing_empty_bucket_on_real_filesystem() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let unique = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let directory = std::env::temp_dir().join(format!("checkpoint_manager_empty_bucket_{}_{}", std::process::id(), unique));
        tokio::fs::create_dir_all(&directory).await?;
        let live_path = directory.join("checkpoint_tree.bin").to_string_lossy().into_owned();
        let file_system = Arc::new(TokioStdFileSystem);
        let mut manager = CheckpointTreeBackupManager::<PoseidonHasher, PHash, TokioStdFileSystem>::new_from_file_path(
            file_system,
            4,
            TREE_HEIGHT,
            &reader,
            &live_path,
            true,
        )
        .await?;
        let bucket_path = manager.bucket_file_path(0);
        tokio::fs::File::create(&bucket_path).await?;

        manager.append_checkpoint_leaf_hash(0, reader.leaves[&0]).await?;

        let bucket = tokio::fs::read(&bucket_path).await?;
        assert_eq!(bucket.len(), CHECKPOINT_BACKUP_MAGIC_LEN + CHECKPOINT_BACKUP_ITEM_SIZE);
        assert_eq!(&bucket[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        tokio::fs::remove_dir_all(directory).await?;
        Ok(())
    }


    #[tokio::test]
    async fn missing_mid_bucket_backfills_real_prefix_before_target_record() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(3);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        for checkpoint_id in 0..=2 {
            manager.append_checkpoint_leaf_hash(checkpoint_id, reader.leaves[&checkpoint_id]).await?;
        }
        let bucket_path = manager.bucket_file_path(0);
        file_system.inner.files.remove(&bucket_path);

        manager.append_checkpoint_leaf_hash(3, reader.leaves[&3]).await?;

        let bucket = file_system.inner.files.get(&bucket_path).unwrap();
        assert_eq!(bucket.len(), CHECKPOINT_BACKUP_MAGIC_LEN + 4 * CHECKPOINT_BACKUP_ITEM_SIZE);
        for checkpoint_id in 0..=3 {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + checkpoint_id as usize * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(bucket[offset..offset + 8].try_into().unwrap()), checkpoint_id);
            assert_eq!(&bucket[offset + 8..offset + CHECKPOINT_BACKUP_ITEM_SIZE], &reader.leaves[&checkpoint_id].into_owned_32bytes());
        }
        Ok(())
    }

    #[tokio::test]
    async fn missing_mid_bucket_without_memory_prefix_fails_closed() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(3);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        manager.min_backed_up_checkpoint_id = 2;
        manager.next_backup_checkpoint_id = 3;
        manager.checkpoint_tree.set_leaf(3, reader.leaves[&3]);

        let error = manager.append_checkpoint_leaf_hash(3, reader.leaves[&3]).await.unwrap_err();

        assert!(error.to_string().contains("backed-up range starts at 2"), "{error}");
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        assert!(!file_system.inner.files.contains_key(&manager.bucket_file_path(0)));
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_retry_repairs_missing_final_bucket_record() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(2);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        for checkpoint_id in 0..=2 {
            manager.append_checkpoint_leaf_hash(checkpoint_id, reader.leaves[&checkpoint_id]).await?;
        }
        let bucket_path = manager.bucket_file_path(0);
        let mut truncated = file_system.inner.files.get(&bucket_path).unwrap().clone();
        truncated.truncate(CHECKPOINT_BACKUP_MAGIC_LEN + 2 * CHECKPOINT_BACKUP_ITEM_SIZE);
        file_system.inner.files.insert(bucket_path.clone(), truncated);
        manager.active_bucket = None;

        manager.append_checkpoint_leaf_hash(2, reader.leaves[&2]).await?;

        let bucket = file_system.inner.files.get(&bucket_path).unwrap();
        assert_eq!(bucket.len(), CHECKPOINT_BACKUP_MAGIC_LEN + 3 * CHECKPOINT_BACKUP_ITEM_SIZE);
        let offset = CHECKPOINT_BACKUP_MAGIC_LEN + 2 * CHECKPOINT_BACKUP_ITEM_SIZE;
        assert_eq!(u64::from_le_bytes(bucket[offset..offset + 8].try_into().unwrap()), 2);
        assert_eq!(&bucket[offset + 8..offset + CHECKPOINT_BACKUP_ITEM_SIZE], &reader.leaves[&2].into_owned_32bytes());
        Ok(())
    }

    #[tokio::test]
    async fn idempotent_repeated_append_leaves_bucket_unchanged() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        manager.append_checkpoint_leaf_hash(0, reader.leaves[&0]).await?;
        let bucket_path = manager.bucket_file_path(0);
        let bucket_before = file_system.inner.files.get(&bucket_path).unwrap().clone();

        manager.append_checkpoint_leaf_hash(0, reader.leaves[&0]).await?;

        assert_eq!(*file_system.inner.files.get(&bucket_path).unwrap(), bucket_before);
        Ok(())
    }

    #[tokio::test]
    async fn validation_failures_leave_live_ring_untouched() -> anyhow::Result<()> {
        for invalid_reader in [
            {
                let mut reader = CheckpointReader::new(5);
                reader.leaves.remove(&3);
                reader
            },
            {
                let mut reader = CheckpointReader::new(5);
                reader.leaves.insert(3, PoseidonHasher::get_zero_hash(0));
                reader
            },
            {
                let mut reader = CheckpointReader::new(5);
                reader.root_override = Some(PHash::from_u64x4([999, 0, 0, 0]));
                reader
            },
        ] {
            let seed_reader = CheckpointReader::new(0);
            let file_system = Arc::new(FailingInstallFileSystem::new());
            let mut manager = manager_with_live_file(file_system.clone(), &seed_reader).await?;
            manager.append_checkpoint_leaf_hash(0, seed_reader.leaves[&0]).await?;
            let live_before = file_system.inner.files.get(LIVE_PATH).unwrap().clone();

            assert!(manager.rebuild_from_database_at_checkpoint(&invalid_reader, 5).await.is_err());
            assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
            assert_eq!(manager.get_current_checkpoint_id_head(), 0);
        }
        Ok(())
    }

    #[tokio::test]
    async fn genesis_rebuild_installs_single_genesis_head() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;

        manager.rebuild_from_database_at_checkpoint(&reader, 0).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 1);
        assert_eq!(manager.get_current_checkpoint_id_head(), 0);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reader.checkpoint_tree_get_root_hash(0).await?);
        let live = file_system.inner.files.get(LIVE_PATH).unwrap();
        assert_eq!(&live[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        assert_eq!(u64::from_le_bytes(live[CHECKPOINT_BACKUP_MAGIC_LEN..CHECKPOINT_BACKUP_MAGIC_LEN + 8].try_into().unwrap()), 0);
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_uses_capacity_window_without_touching_older_slots() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(9);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;

        manager.rebuild_from_database_at_checkpoint(&reader, 9).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 6);
        assert_eq!(manager.next_backup_checkpoint_id, 10);
        assert_eq!(manager.get_current_checkpoint_id_head(), 9);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reader.checkpoint_tree_get_root_hash(9).await?);
        let live = file_system.inner.files.get(LIVE_PATH).unwrap();
        for checkpoint_id in 6..=9 {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + (checkpoint_id as usize % 4) * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(live[offset..offset + 8].try_into().unwrap()), checkpoint_id);
        }
        Ok(())
    }

    #[tokio::test]
    async fn zero_capacity_constructor_rejects_before_creating_ring() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(5);
        let zero_capacity_fs = Arc::new(FailingInstallFileSystem::new());
        let error = CheckpointTreeBackupManager::<PoseidonHasher, PHash, FailingInstallFileSystem>::new_from_file_path(
            zero_capacity_fs.clone(),
            0,
            TREE_HEIGHT,
            &reader,
            LIVE_PATH,
            true,
        )
        .await
        .err()
        .expect("zero capacity constructor must fail");
        assert!(error.to_string().contains("capacity must be greater than zero"), "{error}");
        assert!(!zero_capacity_fs.inner.files.contains_key(LIVE_PATH));
        Ok(())
    }

    #[tokio::test]
    async fn tree_capacity_overflow_rejects_before_install() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(5);
        let overflow_fs = Arc::new(FailingInstallFileSystem::new());
        let mut overflow = manager_with_live_file(overflow_fs.clone(), &reader).await?;
        let overflow_live_before = overflow_fs.inner.files.get(LIVE_PATH).map(|value| value.value().clone());
        let err = overflow.rebuild_from_database_at_checkpoint(&reader, 1u64 << TREE_HEIGHT).await.unwrap_err();
        assert!(err.to_string().contains("exceeds checkpoint tree capacity"), "{err}");
        assert_eq!(overflow_fs.inner.files.get(LIVE_PATH).map(|value| value.value().clone()), overflow_live_before);
        Ok(())
    }
    #[tokio::test]
    async fn undersized_or_bad_magic_backup_file_is_rejected() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let mut bad_magic = CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec();
        bad_magic[0] ^= 0xff;

        for (bytes, expected_error) in [
            (
                CHECKPOINT_BACKUP_MAGIC_BYTES[..CHECKPOINT_BACKUP_MAGIC_LEN - 1].to_vec(),
                "Checkpoint backup file too small",
            ),
            (bad_magic, "Invalid magic bytes in checkpoint backup file"),
        ] {
            let file_system = Arc::new(FailingInstallFileSystem::new());
            file_system.inner.files.insert(LIVE_PATH.to_string(), bytes.clone());

            let error = CheckpointTreeBackupManager::<PoseidonHasher, PHash, FailingInstallFileSystem>::new_from_file_path(
                file_system.clone(),
                4,
                TREE_HEIGHT,
                &reader,
                LIVE_PATH,
                false,
            )
            .await
            .err()
            .expect("invalid checkpoint backup header must fail");

            assert!(error.to_string().contains(expected_error), "{error}");
            assert_eq!(
                file_system.inner.files.get(LIVE_PATH).map(|value| value.value().clone()),
                Some(bytes),
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_rejects_unrepresentable_target_head() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        manager.append_checkpoint_leaf_hash(0, reader.leaves[&0]).await?;
        let live_before = file_system.inner.files.get(LIVE_PATH).unwrap().clone();
        let min_before = manager.min_backed_up_checkpoint_id;
        let next_before = manager.next_backup_checkpoint_id;
        let root_before = manager.get_current_checkpoint_tree_root_head();

        let error = manager.rebuild_from_database_at_checkpoint(&reader, u64::MAX).await.unwrap_err();

        assert!(error.to_string().contains("cannot be represented as a ring head"), "{error}");
        assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
        assert_eq!(manager.min_backed_up_checkpoint_id, min_before);
        assert_eq!(manager.next_backup_checkpoint_id, next_before);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_rejects_proof_mismatch_at_window_start() -> anyhow::Result<()> {
        let mut invalid_reader = CheckpointReader::new(5);
        invalid_reader.leaves.insert(2, PHash::from_u64x4([999, 0, 0, 0]));
        let seed_reader = CheckpointReader::new(0);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &seed_reader).await?;
        manager.append_checkpoint_leaf_hash(0, seed_reader.leaves[&0]).await?;
        let live_before = file_system.inner.files.get(LIVE_PATH).unwrap().clone();
        let min_before = manager.min_backed_up_checkpoint_id;
        let next_before = manager.next_backup_checkpoint_id;
        let root_before = manager.get_current_checkpoint_tree_root_head();

        let error = manager.rebuild_from_database_at_checkpoint(&invalid_reader, 5).await.unwrap_err();

        assert!(
            error.to_string().contains("first rollback window leaf at 2"),
            "{error}",
        );
        assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
        assert_eq!(manager.min_backed_up_checkpoint_id, min_before);
        assert_eq!(manager.next_backup_checkpoint_id, next_before);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);
        Ok(())
    }

    #[tokio::test]
    async fn rebuild_window_bounded_by_genesis_when_capacity_covers_history() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(2);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;

        manager.rebuild_from_database_at_checkpoint(&reader, 2).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        assert_eq!(manager.get_current_checkpoint_id_head(), 2);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reader.checkpoint_tree_get_root_hash(2).await?);
        let live = file_system.inner.files.get(LIVE_PATH).unwrap();
        assert_eq!(&live[..CHECKPOINT_BACKUP_MAGIC_LEN], &CHECKPOINT_BACKUP_MAGIC_BYTES);
        for checkpoint_id in 0..=2 {
            let offset = CHECKPOINT_BACKUP_MAGIC_LEN + checkpoint_id as usize * CHECKPOINT_BACKUP_ITEM_SIZE;
            assert_eq!(u64::from_le_bytes(live[offset..offset + 8].try_into().unwrap()), checkpoint_id);
        }
        Ok(())
    }

    #[tokio::test]
    async fn append_replayed_checkpoint_id_is_idempotent_and_hash_mismatch_rejected() -> anyhow::Result<()> {
        let reader = CheckpointReader::new(2);
        let file_system = Arc::new(FailingInstallFileSystem::new());
        let mut manager = manager_with_live_file(file_system.clone(), &reader).await?;
        for checkpoint_id in 0..=2 {
            manager.append_checkpoint_leaf_hash(checkpoint_id, reader.leaves[&checkpoint_id]).await?;
        }
        let live_before = file_system.inner.files.get(LIVE_PATH).unwrap().clone();
        let min_before = manager.min_backed_up_checkpoint_id;
        let next_before = manager.next_backup_checkpoint_id;
        let root_before = manager.get_current_checkpoint_tree_root_head();

        let replay_proof = manager.append_checkpoint_leaf_hash(2, reader.leaves[&2]).await?;

        assert_eq!(replay_proof.index, 2);
        assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
        assert_eq!(manager.min_backed_up_checkpoint_id, min_before);
        assert_eq!(manager.next_backup_checkpoint_id, next_before);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);

        let error = manager
            .append_checkpoint_leaf_hash(2, PHash::from_u64x4([999, 0, 0, 0]))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("Sequential append required. Expected 3, got 2"), "{error}");
        assert_eq!(*file_system.inner.files.get(LIVE_PATH).unwrap(), live_before);
        assert_eq!(manager.min_backed_up_checkpoint_id, min_before);
        assert_eq!(manager.next_backup_checkpoint_id, next_before);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);
        Ok(())
    }
}
