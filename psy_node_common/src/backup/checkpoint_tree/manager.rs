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
pub const CHECKPOINT_BACKUP_MAGIC_BYTES: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74]; // "PsyChkpt"
pub const CHECKPOINT_BACKUP_MAGIC_U64_LE: u64 = 0x74_70_6B_68_43_79_73_50; // little-endian representation
pub const CHECKPOINT_BACKUP_ITEM_SIZE: usize = 8 + 32; // u64 checkpoint id + 32 bytes checkpoint hash

pub struct CheckpointTreeBackupManager<
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash,
    FileSystem: TokioLikeFileSystem,
> {
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>>,
    pub max_checkpoints_to_keep: u64,

    // The range of checkpoint IDs currently held in memory/file.
    // Range is [min_backed_up_checkpoint_id, next_backup_checkpoint_id)
    pub min_backed_up_checkpoint_id: u64,
    pub next_backup_checkpoint_id: u64,

    pub backup_file_path: String,
    pub backup_file: FileSystem::File,
    pub file_system: Arc<FileSystem>,
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

    pub async fn new_from_file_path<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        file_system: Arc<FileSystem>,
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        backup_file_path: &str,
        allow_create_file: bool,
    ) -> anyhow::Result<Self> {
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
        // 1. Validate or Initialize File Header
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

        // 2. Read all entries to find contiguous history
        let capacity = max_checkpoints_to_keep;
        let file_len = backup_file.file_like_metadata().await?.len();
        let data_len = file_len - CHECKPOINT_BACKUP_MAGIC_LEN as u64;
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

        // Sort by index to handle the ring buffer order
        entries.sort_by_key(|e| e.index);

        // Find the longest contiguous range ending at the highest ID
        let (start_id, end_id, valid_leaves) = if entries.is_empty() {
            (0, 0, Vec::new())
        } else {
            let best_chain_end_idx = entries.len() - 1;
            let mut best_chain_start_idx = best_chain_end_idx;

            for i in (0..entries.len() - 1).rev() {
                if entries[i + 1].index == entries[i].index + 1 {
                    best_chain_start_idx = i;
                } else if entries[i + 1].index == entries[i].index {
                    // Duplicate, ignore
                } else {
                    break;
                }
            }

            let chain = entries[best_chain_start_idx..=best_chain_end_idx].to_vec();
            let start = chain.first().map(|e| e.index).unwrap_or(0);
            let end = chain.last().map(|e| e.index + 1).unwrap_or(0);
            (start, end, chain)
        };

        // 3. Initialize Memory Tree
        let checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(checkpoint_tree_height));

        if !valid_leaves.is_empty() {
            tracing::info!("Initializing Checkpoint Backup from disk. Range: [{}, {})", start_id, end_id);
            // Injest proof for the start to populate path
            let mut init_proof = checkpoint_tree_store.checkpoint_tree_get_merkle_proof(start_id, start_id).await?;

            // FIX: Sanitize the proof.
            // The DB might return a proof based on the *current* state (e.g., tip at 100),
            // containing right-side siblings for indices > start_id.
            // To correctly reconstruct the *historical* append-only roots as we iterate
            // forward, we must treat all right-side siblings as Zero for the
            // starting state.
            for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
                // Check direction of path at this layer.
                // If bit is 0, path is Left, Sibling is Right.
                let is_path_left = (start_id >> layer_idx) & 1 == 0;
                if is_path_left {
                    *sibling = Hasher::get_zero_hash(layer_idx);
                }
            }

            if init_proof.value != valid_leaves[0].value {
                anyhow::bail!("Integrity Error: DB proof {:?} for checkpoint {} differs from backup file proof {:?}", init_proof.value, start_id, valid_leaves[0].value);
            }

            checkpoint_tree.injest_merkle_proof(&init_proof)?;

            // Populate subsequent leaves using set_leaf to verify/update and register roots
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
        })
    }

    /// Appends a new checkpoint to the file (ring buffer) and memory tree.
    pub async fn append_checkpoint_leaf_hash(&mut self, checkpoint_id: u64, checkpoint_hash: Hash) -> anyhow::Result<DeltaMerkleProofCore<Hash>> {
        tracing::info!(
            "Appending checkpoint leaf hash. ID: {}, Hash: {:?} ({})",
            checkpoint_id,
            checkpoint_hash,
            hex::encode(checkpoint_hash.into_owned_32bytes())
        );
        let old_root = self.checkpoint_tree.get_root();
        if checkpoint_id != self.next_backup_checkpoint_id {
            // Idempotency check for retries
            if checkpoint_id == self.next_backup_checkpoint_id.saturating_sub(1) {
                if self.checkpoint_tree.get_leaf_value(checkpoint_id) == checkpoint_hash {
                    let p = self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash);
                    self.checkpoint_tree.ensure_leaf_root_recorded(checkpoint_id);
                    return Ok(p);
                }
            }
            if checkpoint_id == 0 && self.next_backup_checkpoint_id == 0 {
                // proceed
            } else {
                anyhow::bail!(
                    "Sequential append required. Expected {}, got {}",
                    self.next_backup_checkpoint_id,
                    checkpoint_id
                );
            }
        }

        // Calculate Ring Buffer Offset
        let offset = CHECKPOINT_BACKUP_MAGIC_LEN as u64 + (checkpoint_id % self.max_checkpoints_to_keep) * CHECKPOINT_BACKUP_ITEM_SIZE as u64;

        self.backup_file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.backup_file.write_u64_le(checkpoint_id).await?;
        self.backup_file.write_all(&checkpoint_hash.into_owned_32bytes()).await?;

        // Critical: Flush via FileSystem trait
        self.file_system
            .file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file)
            .await?;

        // Update Memory State
        // Use set_leaf to safely handle collisions with future siblings generated by
        // injest, while also registering the root.
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
        let height = self.checkpoint_tree.get_height();
        self.checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(height));

        // Use file_like_set_len for truncation
        self.backup_file.file_like_set_len(CHECKPOINT_BACKUP_MAGIC_LEN as u64).await?;

        self.backup_file.seek(std::io::SeekFrom::Start(0)).await?;
        self.backup_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;

        // Flush via FileSystem trait
        self.file_system
            .file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file)
            .await?;

        self.min_backed_up_checkpoint_id = start_checkpoint_id;
        self.next_backup_checkpoint_id = start_checkpoint_id;
        Ok(())
    }

    /// Syncs local checkpoint history with the Coordinator.
    /// Critical for resolving forks and ensuring the local Merkle Tree is consistent with the canonical chain.
    pub async fn sync_from_coordinator_client<CoordinatorClient: RealmCoordinatorClient<F, Hash>, F>(
        &mut self,
        coordinator_client: &CoordinatorClient,
        sync_batch_size: usize,
    ) -> anyhow::Result<()> {
        // 1. Fetch current remote status
        let remote_latest_checkpoint_id: u64 = coordinator_client.rc_get_latest_checkpoint_id().await?;
        
        // 2. Determine mandatory history requirement
        let required_min_checkpoint = if remote_latest_checkpoint_id >= STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF {
            remote_latest_checkpoint_id - STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF
        } else {
            0
        };

        // 3. Check for Divergence / Inconsistency
        let mut needs_reset = false;

        // Condition A: Gap in history. 
        // If our oldest checkpoint is newer than what is required, we are missing history.
        if self.min_backed_up_checkpoint_id > required_min_checkpoint {
            tracing::warn!(
                "Checkpoint history gap detected. Local Min: {}, Required Min: {}. Triggering Reset.",
                self.min_backed_up_checkpoint_id,
                required_min_checkpoint
            );
            needs_reset = true;
        }

        // Condition B: Fork detection.
        // Check if our tip (next_backup_checkpoint_id - 1) actually matches the coordinator.
        if !needs_reset && self.next_backup_checkpoint_id > 0 {
            // We check the overlap.
            // If next_backup_checkpoint_id is > remote_latest + 1, we are ahead (impossible if synced correctly, likely a local fork or devnet reset).
            if self.next_backup_checkpoint_id > remote_latest_checkpoint_id + 1 {
                tracing::warn!(
                    "Local checkpoint ID {} is ahead of remote {}. Triggering Reset.",
                    self.next_backup_checkpoint_id,
                    remote_latest_checkpoint_id
                );
                needs_reset = true;
            } else {
                // Verify the hash of our tip against the coordinator
                let overlap_check_id = self.next_backup_checkpoint_id - 1;
                let local_hash = self.checkpoint_tree.get_leaf_value(overlap_check_id);
                
                // Fetch just the overlap block to verify integrity
                let remote_leaves = coordinator_client.rc_get_checkpoint_leaves_batch(overlap_check_id, 1).await?;
                
                if remote_leaves.is_empty() {
                    // Should not happen if remote_latest >= overlap_check_id
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

        // 4. Perform Reset if necessary
        if needs_reset {
            self.hard_reset_and_truncate(required_min_checkpoint).await?;
        }

        // 5. Short-circuit if fully synced
        if self.next_backup_checkpoint_id > remote_latest_checkpoint_id {
            // We are up to date (or ahead, which is handled by reset logic above if it was invalid)
            // tracing::debug!(
            //     "Checkpoint Backup Manager up-to-date. Local Tip: {}, Remote Tip: {}",
            //     self.next_backup_checkpoint_id.saturating_sub(1),
            //     remote_latest_checkpoint_id
            // );
            return Ok(());
        }

        // 6. Sync Missing Blocks
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
        // 1. Determine the start based on Protocol Rules (Stale proofs)
        let protocol_start = last_committed_checkpoint_id.saturating_sub(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF);

        // 2. Determine the start based on Capacity Rules (Max items to keep)
        let capacity_start = if last_committed_checkpoint_id >= self.max_checkpoints_to_keep {
            last_committed_checkpoint_id - self.max_checkpoints_to_keep + 1
        } else {
            0
        };

        // 3. The effective start is the maximum of the two.
        let required_history_start = std::cmp::max(protocol_start, capacity_start);

        tracing::info!(
            "Syncing Checkpoint Manager. Target: {}. ReqStart: {}. Local: [{}, {})",
            last_committed_checkpoint_id,
            required_history_start,
            self.min_backed_up_checkpoint_id,
            self.next_backup_checkpoint_id
        );

        // 4. Determine if a Hard Reset is needed.
        let needs_reset =
            // Case A: Manager is empty/uninitialized.
            (self.next_backup_checkpoint_id == 0 && self.min_backed_up_checkpoint_id == 0) ||
            // Case B: Our current history starts *after* the required start (we are missing historical data).
            (self.min_backed_up_checkpoint_id > required_history_start) ||
            // Case C: Our current head is *behind* the required start window.
            (self.next_backup_checkpoint_id < required_history_start) ||
            // Case D: Gap is too massive (Performance heuristic).
            (last_committed_checkpoint_id > self.next_backup_checkpoint_id + self.max_checkpoints_to_keep * 2);

        if needs_reset {
            self.hard_reset_and_truncate(required_history_start).await?;
        }

        // Check if tree is empty using root hash check
        let is_tree_empty = self.checkpoint_tree.get_root() == Hasher::get_zero_hash(self.checkpoint_tree.get_height() as usize);

        if is_tree_empty || self.next_backup_checkpoint_id == required_history_start {
            let start = self.next_backup_checkpoint_id;
            let mut init_proof = checkpoint_tree_reader.checkpoint_tree_get_merkle_proof(start, start).await?;

            // FIX: Sanitize proof from future siblings
            for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
                let is_path_left = (start >> layer_idx) & 1 == 0;
                if is_path_left {
                    *sibling = Hasher::get_zero_hash(layer_idx);
                }
            }

            self.checkpoint_tree.injest_merkle_proof(&init_proof)?;
            if init_proof.value != Hasher::get_zero_hash(0) {
                // Persist the start leaf
                self.append_checkpoint_leaf_hash(start, init_proof.value).await?;
            } else if last_committed_checkpoint_id != 0 {
                anyhow::bail!(
                    "DB sync integrity error at checkpoint {}, the last committed checkpoint was supposed to be {}, but it is a zero leaf",
                    start,
                    last_committed_checkpoint_id
                );
            } else {
                // genesis initialization, do nothing
            }
        }

        // Fill gap
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
                    // genesis initialization, do nothing
                }
            }
            current_sync_idx = batch_end + 1;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
    use parth_core::{crypto::hash::merkle_proof::MerkleProofCore, pgoldilocks::PoseidonHasher, protocol::core_types::QNetworkTreeConstants, PHash};
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::{PsyNodeCheckpointTreeDatabaseReader, PsyNodeCheckpointTreeDatabaseWriter},
    };

    use crate::realm::processor::db::realm_db_test_env::FakeRealmCoordinatorClient;
    use crate::test_common::{create_test_unified_db, TestNetworkConfig, TestUnifiedDatabaseStore};

    use super::*;

    type Hasher = PoseidonHasher;
    type Hash = PHash;
    type Fs = SimpleMockMemoryFileSystem;
    type Manager = CheckpointTreeBackupManager<Hasher, Hash, Fs>;

    const HEIGHT: u8 = TestNetworkConfig::CHECKPOINT_TREE_HEIGHT;
    const PATH: &str = "checkpoint_tree_backup.bin";

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    /// Deterministic, pairwise-distinct, non-zero leaf values.
    fn leaf(i: u64) -> Hash {
        PHash::from_values(i * 16 + 1, 0x1111_2222_3333_4444, i + 7, 0x5555_6666_7777_8888)
    }

    fn leaves(n: u64) -> Vec<Hash> {
        (0..n).map(leaf).collect()
    }

    /// Serializes backup file bytes: magic + entries of (id, hash).
    fn file_bytes(entries: &[(u64, Hash)]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(CHECKPOINT_BACKUP_MAGIC_LEN + entries.len() * CHECKPOINT_BACKUP_ITEM_SIZE);
        bytes.extend_from_slice(&CHECKPOINT_BACKUP_MAGIC_BYTES);
        for (id, hash) in entries {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&hash.into_owned_32bytes());
        }
        bytes
    }

    async fn seed_db_leaves(db: &TestUnifiedDatabaseStore, values: &[Hash]) -> anyhow::Result<()> {
        for (i, value) in values.iter().enumerate() {
            db.checkpoint_tree_set_leaf_hash(i as u64, *value).await?;
        }
        Ok(())
    }

    /// Reference append-only tree built the plain way (append_leaf per index).
    fn reference_tree(values: &[Hash]) -> PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash> {
        let tree = PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(HEIGHT);
        for (i, value) in values.iter().enumerate() {
            tree.append_leaf(i as u64, *value).expect("reference append must succeed");
        }
        tree
    }

    async fn new_manager(fs: &Arc<Fs>, db: &TestUnifiedDatabaseStore, path: &str, max_keep: u64) -> anyhow::Result<Manager> {
        CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(fs),
            max_keep,
            HEIGHT,
            db,
            path,
            true,
        )
        .await
    }

    #[tokio::test]
    async fn new_from_file_path_creates_file_and_starts_empty() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let manager = new_manager(&fs, &db, PATH, 10).await?;

        assert_eq!(manager.get_current_checkpoint_id_head(), 0);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), zh(HEIGHT as usize));
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 0);

        // the file was created containing only the magic header
        let bytes = fs.files.get(PATH).expect("backup file must exist").value().clone();
        assert_eq!(bytes, CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec());
        Ok(())
    }

    #[tokio::test]
    async fn new_from_file_path_rejects_missing_file_without_create() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let err = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            "missing.bin",
            false,
        )
        .await
        .err()
        .expect("opening a missing file without create must fail");
        assert!(err.to_string().contains("not found"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn new_from_file_path_rejects_empty_file_without_create() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        fs.files.insert(PATH.to_string(), Vec::new());
        let err = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            PATH,
            false,
        )
        .await
        .err()
        .expect("an empty file without create must fail");
        assert!(err.to_string().contains("empty and creation not allowed"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn new_from_file_path_rejects_truncated_header_and_bad_magic() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;

        fs.files.insert("short.bin".to_string(), vec![1, 2, 3, 4]);
        let err = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            "short.bin",
            true,
        )
        .await
        .err()
        .expect("a file below the magic length must fail");
        assert!(err.to_string().contains("too small"), "unexpected error: {err}");

        fs.files.insert("badmagic.bin".to_string(), vec![0xABu8; CHECKPOINT_BACKUP_MAGIC_LEN]);
        let err = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            "badmagic.bin",
            true,
        )
        .await
        .err()
        .expect("a wrong magic must fail");
        assert!(err.to_string().contains("Invalid magic bytes"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn append_sequential_checkpoints_updates_heads_root_and_file() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;

        let values = leaves(3);
        for (i, value) in values.iter().enumerate() {
            let proof = manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
            assert_eq!(proof.index, i as u64);
            assert_eq!(proof.new_value, *value);
        }

        assert_eq!(manager.next_backup_checkpoint_id, 3);
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.get_current_checkpoint_id_head(), 2);
        assert_eq!(
            manager.get_current_checkpoint_tree_root_head(),
            reference_tree(&values).get_root()
        );

        // every append-only prefix root is indexed by its checkpoint id
        let reference = PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(HEIGHT);
        for (i, value) in values.iter().enumerate() {
            reference.append_leaf(i as u64, *value)?;
            assert_eq!(manager.checkpoint_tree.get_leaf_index_for_root(reference.get_root()), Some(i as u64));
        }

        // the file contains magic + one item per checkpoint in slot order
        let bytes = fs.files.get(PATH).expect("backup file must exist").value().clone();
        assert_eq!(bytes.len(), CHECKPOINT_BACKUP_MAGIC_LEN + 3 * CHECKPOINT_BACKUP_ITEM_SIZE);
        assert_eq!(
            bytes,
            file_bytes(&[(0, values[0]), (1, values[1]), (2, values[2])])
        );
        Ok(())
    }

    #[tokio::test]
    async fn append_retry_of_last_checkpoint_is_idempotent() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        let values = leaves(3);
        for (i, value) in values.iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }
        let root_before = manager.get_current_checkpoint_tree_root_head();

        // replaying the last append with the same hash must not advance the head
        manager.append_checkpoint_leaf_hash(2, values[2]).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        assert_eq!(manager.get_current_checkpoint_id_head(), 2);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), root_before);
        Ok(())
    }

    #[tokio::test]
    async fn append_rejects_out_of_order_checkpoint_ids() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        let values = leaves(3);
        for (i, value) in values.iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }

        let err = manager
            .append_checkpoint_leaf_hash(5, leaf(5))
            .await
            .expect_err("skipping checkpoint ids must fail");
        assert!(err.to_string().contains("Sequential append required"), "unexpected error: {err}");
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        Ok(())
    }

    #[tokio::test]
    async fn reload_from_file_rebuilds_identical_state() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        seed_db_leaves(&db, &leaves(4)).await?;

        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        for (i, value) in leaves(4).iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }
        let expected_root = manager.get_current_checkpoint_tree_root_head();
        drop(manager);

        // a second manager over the same file rebuilds the same window
        let reloaded = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            PATH,
            false,
        )
        .await?;
        assert_eq!(reloaded.min_backed_up_checkpoint_id, 0);
        assert_eq!(reloaded.next_backup_checkpoint_id, 4);
        assert_eq!(reloaded.get_current_checkpoint_id_head(), 3);
        assert_eq!(reloaded.get_current_checkpoint_tree_root_head(), expected_root);
        assert_eq!(reloaded.checkpoint_tree.get_leaf_value(2), leaf(2));
        Ok(())
    }

    #[tokio::test]
    async fn reload_from_file_handles_ring_buffer_wraparound() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(7);
        seed_db_leaves(&db, &values).await?;

        let mut manager = new_manager(&fs, &db, PATH, 4).await?;
        for (i, value) in values.iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }
        // the window advanced past the overwritten slots
        assert_eq!(manager.min_backed_up_checkpoint_id, 3);
        assert_eq!(manager.next_backup_checkpoint_id, 7);

        // on disk the ring buffer holds [4, 5, 6, 3] in slot order (id % 4)
        let bytes = fs.files.get(PATH).expect("backup file must exist").value().clone();
        assert_eq!(
            bytes,
            file_bytes(&[(4, values[4]), (5, values[5]), (6, values[6]), (3, values[3])])
        );

        let expected_root = manager.get_current_checkpoint_tree_root_head();
        drop(manager);

        let reloaded = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            4,
            HEIGHT,
            &db,
            PATH,
            false,
        )
        .await?;
        // the longest contiguous chain [3, 6] is recovered
        assert_eq!(reloaded.min_backed_up_checkpoint_id, 3);
        assert_eq!(reloaded.next_backup_checkpoint_id, 7);
        assert_eq!(reloaded.get_current_checkpoint_id_head(), 6);
        assert_eq!(reloaded.get_current_checkpoint_tree_root_head(), expected_root);
        Ok(())
    }

    #[tokio::test]
    async fn reload_from_file_ignores_duplicate_entries() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(3);
        seed_db_leaves(&db, &values).await?;

        // a duplicated entry for id 1 must be ignored, not break the chain
        fs.files.insert(
            PATH.to_string(),
            file_bytes(&[(0, values[0]), (1, values[1]), (1, values[1]), (2, values[2])]),
        );
        let manager = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            10,
            HEIGHT,
            &db,
            PATH,
            false,
        )
        .await?;
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&values).get_root());
        Ok(())
    }

    #[tokio::test]
    async fn has_appropriate_checkpoint_history_flag_bounds() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(7);
        seed_db_leaves(&db, &values).await?;
        let mut manager = new_manager(&fs, &db, PATH, 4).await?;
        for (i, value) in values.iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }
        // window is [3, 7)
        assert_eq!(manager.min_backed_up_checkpoint_id, 3);
        assert_eq!(manager.next_backup_checkpoint_id, 7);

        // head covers current=6 and the window reaches exactly the required min
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(3, 6));
        // required min (6 - 3 = 3 == min) is the boundary; one more stale slot breaks it
        assert!(!manager.has_appropriate_checkpoint_history_for_stale_proofs(4, 6));
        // history does not reach far enough back
        assert!(!manager.has_appropriate_checkpoint_history_for_stale_proofs(100, 6));
        // current checkpoint beyond the local head
        assert!(!manager.has_appropriate_checkpoint_history_for_stale_proofs(3, 7));
        Ok(())
    }

    #[tokio::test]
    async fn hard_reset_truncates_file_and_restarts_at_given_id() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        for (i, value) in leaves(3).iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }

        manager.hard_reset_and_truncate(5).await?;
        assert_eq!(manager.min_backed_up_checkpoint_id, 5);
        assert_eq!(manager.next_backup_checkpoint_id, 5);
        assert_eq!(manager.get_current_checkpoint_id_head(), 4);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), zh(HEIGHT as usize));
        // the file was truncated back to just the magic header
        let bytes = fs.files.get(PATH).expect("backup file must exist").value().clone();
        assert_eq!(bytes, CHECKPOINT_BACKUP_MAGIC_BYTES.to_vec());

        // appending continues from the reset id
        manager.append_checkpoint_leaf_hash(5, leaf(5)).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 6);
        assert_eq!(manager.get_current_checkpoint_id_head(), 5);
        assert_eq!(manager.checkpoint_tree.get_leaf_value(5), leaf(5));
        Ok(())
    }

    fn fake_with_leaves(values: &[Hash], latest: u64) -> Arc<FakeRealmCoordinatorClient> {
        let client = FakeRealmCoordinatorClient::new();
        for value in values {
            client.push_checkpoint_leaf(*value);
        }
        client.set_latest_checkpoint_id(latest);
        Arc::new(client)
    }

    #[tokio::test]
    async fn sync_from_coordinator_client_bootstraps_empty_manager() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(5);
        let client = fake_with_leaves(&values, 4);

        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        manager.sync_from_coordinator_client(client.as_ref(), 2).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 5);
        assert_eq!(manager.get_current_checkpoint_id_head(), 4);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&values).get_root());
        assert_eq!(manager.checkpoint_tree.get_leaf_value(3), values[3]);
        // the synced leaves were persisted to the backup file
        let bytes = fs.files.get(PATH).expect("backup file must exist").value().clone();
        assert_eq!(
            bytes,
            file_bytes(&[(0, values[0]), (1, values[1]), (2, values[2]), (3, values[3]), (4, values[4])])
        );

        // a second sync is a no-op when already at the coordinator head
        manager.sync_from_coordinator_client(client.as_ref(), 2).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 5);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&values).get_root());
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_coordinator_client_recovers_from_fork() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        // local chain: [leaf(0), leaf(1)]
        manager.append_checkpoint_leaf_hash(0, leaf(0)).await?;
        manager.append_checkpoint_leaf_hash(1, leaf(1)).await?;

        // coordinator chain forks at checkpoint 1
        let forked = vec![leaf(0), PHash::from_values(999, 1, 2, 3)];
        let client = fake_with_leaves(&forked, 1);

        manager.sync_from_coordinator_client(client.as_ref(), 8).await?;
        // after the fork the local state was rebuilt from the coordinator's chain
        assert_eq!(manager.next_backup_checkpoint_id, 2);
        assert_eq!(manager.get_current_checkpoint_id_head(), 1);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&forked).get_root());
        assert_eq!(manager.checkpoint_tree.get_leaf_value(1), forked[1]);
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_coordinator_client_resets_when_local_is_ahead() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        for (i, value) in leaves(5).iter().enumerate() {
            manager.append_checkpoint_leaf_hash(i as u64, *value).await?;
        }
        assert_eq!(manager.next_backup_checkpoint_id, 5);

        // the coordinator only knows checkpoints 0 and 1 with different hashes
        let remote = leaves_with_offset(100, 2);
        let client = fake_with_leaves(&remote, 1);

        manager.sync_from_coordinator_client(client.as_ref(), 8).await?;
        // the local fork was discarded and re-synced to the remote chain
        assert_eq!(manager.next_backup_checkpoint_id, 2);
        assert_eq!(manager.get_current_checkpoint_id_head(), 1);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&remote).get_root());
        Ok(())
    }

    fn leaves_with_offset(offset: u64, n: u64) -> Vec<Hash> {
        (0..n).map(|i| PHash::from_values(offset + i * 16 + 1, 0x1111_2222_3333_4444, i + 7, 0x5555_6666_7777_8888)).collect()
    }

    #[tokio::test]
    async fn sync_from_coordinator_client_bails_on_insufficient_batch() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        // latest=3 promises four checkpoints but only two leaves are available
        let client = fake_with_leaves(&leaves(2), 3);

        let mut manager = new_manager(&fs, &db, PATH, 10).await?;
        let err = manager
            .sync_from_coordinator_client(client.as_ref(), 2)
            .await
            .expect_err("a short batch must fail the sync");
        assert!(err.to_string().contains("insufficient leaves for batch starting at 2"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_database_replays_committed_checkpoints() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(6);
        seed_db_leaves(&db, &values).await?;

        let mut manager = new_manager(&fs, &db, PATH, 100).await?;
        manager.sync_from_database(&db, 3, 5).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 6);
        assert_eq!(manager.get_current_checkpoint_id_head(), 5);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), db.checkpoint_tree_get_root_hash(5).await?);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), reference_tree(&values).get_root());
        assert_eq!(manager.checkpoint_tree.get_leaf_value(4), values[4]);
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_database_on_genesis_only_database_stays_empty() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        // no checkpoint leaves committed: last_committed = 0 with a zero leaf at
        // index 0 is the genesis initialization case
        let mut manager = new_manager(&fs, &db, PATH, 100).await?;
        manager.sync_from_database(&db, 4, 0).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 0);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), zh(HEIGHT as usize));
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_database_resyncs_when_history_falls_out_of_window() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        let values = leaves(6);
        seed_db_leaves(&db, &values).await?;

        // a manager holding only the last two checkpoints must hard-reset and
        // rebuild from the required history start
        fs.files.insert(
            PATH.to_string(),
            file_bytes(&[(4, values[4]), (5, values[5])]),
        );
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, Fs>::new_from_file_path(
            Arc::clone(&fs),
            100,
            HEIGHT,
            &db,
            PATH,
            false,
        )
        .await?;
        assert_eq!(manager.min_backed_up_checkpoint_id, 4);

        manager.sync_from_database(&db, 10, 5).await?;
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 6);
        assert_eq!(manager.get_current_checkpoint_tree_root_head(), db.checkpoint_tree_get_root_hash(5).await?);
        Ok(())
    }

    #[tokio::test]
    async fn sync_from_database_bails_when_a_committed_leaf_is_zero() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        // checkpoint 3 was committed with a zero leaf: an integrity violation
        let values = [leaf(0), leaf(1), leaf(2), zh(0), leaf(4), leaf(5)];
        for (i, value) in values.iter().enumerate() {
            db.checkpoint_tree_set_leaf_hash(i as u64, *value).await?;
        }

        let mut manager = new_manager(&fs, &db, PATH, 100).await?;
        let err = manager
            .sync_from_database(&db, 5, 5)
            .await
            .err()
            .expect("a zero leaf inside the committed history must fail the sync");
        assert!(err.to_string().contains("DB sync integrity error at checkpoint 3"), "unexpected error: {err}");
        // the sync stopped before the corrupt checkpoint was appended
        assert_eq!(manager.get_current_checkpoint_id_head(), 2);
        assert_eq!(manager.next_backup_checkpoint_id, 3);
        Ok(())
    }

    /// Reader wrapper that drops the last entry of every bulk `get_nodes`
    /// response, simulating a truncated DB batch.
    struct ShortBatchReader<'a> {
        db: &'a TestUnifiedDatabaseStore,
    }

    #[async_trait]
    impl PsyNodeCheckpointTreeDatabaseReader<Hash> for ShortBatchReader<'_> {
        async fn checkpoint_tree_get_leaf_hash(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash> {
            self.db.checkpoint_tree_get_leaf_hash(checkpoint_id, leaf_index).await
        }

        async fn checkpoint_tree_get_root_hash(&self, checkpoint_id: u64) -> anyhow::Result<Hash> {
            self.db.checkpoint_tree_get_root_hash(checkpoint_id).await
        }

        async fn checkpoint_tree_get_merkle_proof(&self, checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>> {
            self.db.checkpoint_tree_get_merkle_proof(checkpoint_id, leaf_index).await
        }

        async fn checkpoint_tree_get_nodes(&self, checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
            let mut hashes = self.db.checkpoint_tree_get_nodes(checkpoint_id, keys).await?;
            hashes.pop();
            Ok(hashes)
        }
    }

    #[tokio::test]
    async fn sync_from_database_bails_when_db_returns_a_short_batch() -> anyhow::Result<()> {
        let fs = Arc::new(Fs::new());
        let db = create_test_unified_db().await?;
        seed_db_leaves(&db, &leaves(6)).await?;

        let reader = ShortBatchReader { db: &db };
        let mut manager = new_manager(&fs, &db, PATH, 100).await?;
        let err = manager
            .sync_from_database(&reader, 5, 5)
            .await
            .err()
            .expect("a truncated bulk response must fail the sync");
        assert!(err.to_string().contains("DB sync mismatch"), "unexpected error: {err}");
        Ok(())
    }
}
