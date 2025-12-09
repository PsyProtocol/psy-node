use std::sync::Arc;
use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    crypto::hash::{merkle_proof::DeltaMerkleProofCore, traits::MerkleZeroHasher},
    data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_node_nest::MerkleLeafNode},
    protocol::core_types::Q256BitHash,
};
use psy_core::constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF;
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{p2p::traits::realm_coordinantor::RealmCoordinatorClient, psy_core_db::traits::full::{PsyNodeCheckpointTreeDatabaseReader, PsyNodeCheckpointTreeDatabaseWriter}};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

const CHECKPOINT_BACKUP_MAGIC_LEN: usize = 8;
const CHECKPOINT_BACKUP_MAGIC_BYTES: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74]; // "PsyChkpt"
const CHECKPOINT_BACKUP_MAGIC_U64_LE: u64 = 0x74_70_6B_68_43_79_73_50; // little-endian representation
const CHECKPOINT_BACKUP_ITEM_SIZE: usize = 8 + 32; // u64 checkpoint id + 32 bytes checkpoint hash

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
            allow_create_file
        ).await
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
                if entries[i+1].index == entries[i].index + 1 {
                    best_chain_start_idx = i;
                } else if entries[i+1].index == entries[i].index {
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
            let mut init_proof = checkpoint_tree_store
                .checkpoint_tree_get_merkle_proof(start_id, start_id)
                .await?;

            println!("Init proof for checkpoint {}: {:?}", start_id, init_proof);

            // FIX: Sanitize the proof.
            // The DB might return a proof based on the *current* state (e.g., tip at 100),
            // containing right-side siblings for indices > start_id.
            // To correctly reconstruct the *historical* append-only roots as we iterate forward,
            // we must treat all right-side siblings as Zero for the starting state.
            for (layer_idx, sibling) in init_proof.siblings.iter_mut().enumerate() {
                // Check direction of path at this layer.
                // If bit is 0, path is Left, Sibling is Right.
                let is_path_left = (start_id >> layer_idx) & 1 == 0;
                if is_path_left {
                    *sibling = Hasher::get_zero_hash(layer_idx);
                }
            }

            if init_proof.value != valid_leaves[0].value {
                anyhow::bail!("Integrity Error: DB proof for checkpoint {} differs from backup file", start_id);
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
        tracing::info!("Appending checkpoint leaf hash. ID: {}, Hash: {:?} ({})", checkpoint_id, checkpoint_hash, hex::encode(checkpoint_hash.into_owned_32bytes()));
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
        let offset = CHECKPOINT_BACKUP_MAGIC_LEN as u64 +
            (checkpoint_id % self.max_checkpoints_to_keep) * CHECKPOINT_BACKUP_ITEM_SIZE as u64;

        self.backup_file.seek(std::io::SeekFrom::Start(offset)).await?;
        self.backup_file.write_u64_le(checkpoint_id).await?;
        self.backup_file.write_all(&checkpoint_hash.into_owned_32bytes()).await?;

        // Critical: Flush via FileSystem trait
        self.file_system.file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file).await?;

        // Update Memory State
        // Use set_leaf to safely handle collisions with future siblings generated by injest,
        // while also registering the root.
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
        self.next_backup_checkpoint_id > current_checkpoint_id &&
        self.min_backed_up_checkpoint_id <= required_min
    }

    async fn hard_reset_and_truncate(&mut self, start_checkpoint_id: u64) -> anyhow::Result<()> {
        tracing::warn!("Hard reset of Checkpoint Backup Manager at ID {}", start_checkpoint_id);
        let height = self.checkpoint_tree.get_height();
        self.checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(height));

        // Use file_like_set_len for truncation
        self.backup_file.file_like_set_len(CHECKPOINT_BACKUP_MAGIC_LEN as u64).await?;

        self.backup_file.seek(std::io::SeekFrom::Start(0)).await?;
        self.backup_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;

        // Flush via FileSystem trait
        self.file_system.file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file).await?;

        self.min_backed_up_checkpoint_id = start_checkpoint_id;
        self.next_backup_checkpoint_id = start_checkpoint_id;
        Ok(())
    }
    pub async fn sync_from_coordinator_client<CoordinatorClient: RealmCoordinatorClient<F, Hash>, F>(
        &mut self,
        coordinator_client: &CoordinatorClient,
        sync_batch_size: usize,
    ) -> anyhow::Result<()> {
        let latest_checkpoint_id: u64 = coordinator_client.rc_get_latest_checkpoint_id().await?;
        let min_checkpoint = if latest_checkpoint_id >= STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF {
            latest_checkpoint_id - STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF
        } else {
            0
        };
        let max_needed_checkpoint_id = latest_checkpoint_id;
        if self.min_backed_up_checkpoint_id <= min_checkpoint && self.next_backup_checkpoint_id > max_needed_checkpoint_id {
            tracing::info!("Checkpoint Backup Manager already up-to-date with coordinator. Current: {}, Latest: {}", self.next_backup_checkpoint_id - 1, latest_checkpoint_id);
            return Ok(());
        }
        if self.min_backed_up_checkpoint_id > min_checkpoint {
            let suffix_leaves = if self.next_backup_checkpoint_id > self.min_backed_up_checkpoint_id {
                let mut leaves = Vec::with_capacity((self.next_backup_checkpoint_id - self.min_backed_up_checkpoint_id) as usize);

                for i in self.min_backed_up_checkpoint_id..self.next_backup_checkpoint_id {
                    let hash = self.checkpoint_tree.get_leaf_value(i);
                    leaves.push(hash);
                }
                leaves
            }else{
                Vec::new()
            };

            let num_full_batches = (self.min_backed_up_checkpoint_id - min_checkpoint) / sync_batch_size as u64;
            let partial_batch_size = (self.min_backed_up_checkpoint_id - min_checkpoint) % sync_batch_size as u64;

            self.hard_reset_and_truncate(min_checkpoint).await?;

            for i in 0..num_full_batches {
                let start_id = min_checkpoint + i * sync_batch_size as u64;
                let leaves = coordinator_client.rc_get_checkpoint_leaves_batch(start_id, sync_batch_size as u32).await?;
                if leaves.len() != sync_batch_size {
                    anyhow::bail!("Coordinator returned insufficient leaves for batch starting at {}", start_id);
                }
                for (i, hash) in leaves.into_iter().enumerate() {
                    let checkpoint_id = start_id + i as u64;
                    self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
                }
            }
            if partial_batch_size > 0 {
                let start_id = min_checkpoint + num_full_batches * sync_batch_size as u64;
                let leaves = coordinator_client.rc_get_checkpoint_leaves_batch(start_id, partial_batch_size as u32).await?;
                if leaves.len() != partial_batch_size as usize {
                    anyhow::bail!("Coordinator returned insufficient leaves for partial batch at {}", start_id);
                }
                for (i, hash) in leaves.into_iter().enumerate() {
                    let checkpoint_id = start_id + i as u64;
                    self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
                }
            }
            for (i, hash) in suffix_leaves.into_iter().enumerate() {
                let checkpoint_id = min_checkpoint + num_full_batches * sync_batch_size as u64 + partial_batch_size + i as u64;
                self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
            }
        }
        if self.next_backup_checkpoint_id <= max_needed_checkpoint_id {
            let start_id = self.next_backup_checkpoint_id;
            let total_to_fetch = max_needed_checkpoint_id - self.next_backup_checkpoint_id + 1;
            let num_full_batches = total_to_fetch / sync_batch_size as u64;
            let partial_batch_size = total_to_fetch % sync_batch_size as u64;

            for i in 0..num_full_batches {
                let batch_start_id = start_id + i * sync_batch_size as u64;
                let leaves = coordinator_client.rc_get_checkpoint_leaves_batch(batch_start_id, sync_batch_size as u32).await?;
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
                let leaves = coordinator_client.rc_get_checkpoint_leaves_batch(batch_start_id, partial_batch_size as u32).await?;
                if leaves.len() != partial_batch_size as usize {
                    anyhow::bail!("Coordinator returned insufficient leaves for partial batch at {}", batch_start_id);
                }
                for (j, hash) in leaves.into_iter().enumerate() {
                    let checkpoint_id = batch_start_id + j as u64;
                    self.append_checkpoint_leaf_hash(checkpoint_id, hash).await?;
                }
            }
        }
        Ok(())

    }
pub async fn sync_to_database<CheckpointTreeReader: PsyNodeCheckpointTreeDatabaseReader<Hash> + PsyNodeCheckpointTreeDatabaseWriter<Hash>>(
        &mut self,
        checkpoint_tree_reader: &CheckpointTreeReader,
        sync_batch_size: usize,
        last_committed_checkpoint_id: u64,
    ) -> anyhow::Result<()> {
        todo!()
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
        // If we want to keep 500 items ending at 9999, we start at 9500.
        // Formula: (Target - Max + 1).
        let capacity_start = if last_committed_checkpoint_id >= self.max_checkpoints_to_keep {
            last_committed_checkpoint_id - self.max_checkpoints_to_keep + 1
        } else {
            0
        };

        // 3. The effective start is the maximum of the two.
        // We cannot start earlier than allowed by capacity, even if protocol desires it
        // (assuming configuration intends to limit memory usage).
        let required_history_start = std::cmp::max(protocol_start, capacity_start);

        tracing::info!(
            "Syncing Checkpoint Manager. Target: {}. ReqStart: {}. Local: [{}, {})",
            last_committed_checkpoint_id, required_history_start,
            self.min_backed_up_checkpoint_id, self.next_backup_checkpoint_id
        );

        // 4. Determine if a Hard Reset is needed.
        let needs_reset =
            // Case A: Manager is empty/uninitialized.
            (self.next_backup_checkpoint_id == 0 && self.min_backed_up_checkpoint_id == 0) ||
            // Case B: Our current history starts *after* the required start (we are missing historical data).
            // We must reset to fetch the earlier data because we can't prepend to this append-only store.
            (self.min_backed_up_checkpoint_id > required_history_start) ||
            // Case C: Our current head is *behind* the required start window.
            // Example: We have 9000..9200. ReqStart is 9500.
            // If we don't reset, we would fill 9201..9999, resulting in 9000..9999 (Size 1000 > Max 500).
            // Resetting jumps us forward to 9500, dropping the old tail (9000..9200).
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
            let mut init_proof = checkpoint_tree_reader
                .checkpoint_tree_get_merkle_proof(start, start)
                .await?;

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
            }else if last_committed_checkpoint_id != 0 {
                anyhow::bail!("DB sync integrity error at checkpoint {}, the last committed checkpoint was supposed to be {}, but it is a zero leaf", start, last_committed_checkpoint_id);
            }else{
                // genesis initialization, do nothing
            }
        }

        // Fill gap
        let mut current_sync_idx = self.next_backup_checkpoint_id;
        while current_sync_idx <= last_committed_checkpoint_id {
            let batch_end = std::cmp::min(current_sync_idx + sync_batch_size as u64 - 1, last_committed_checkpoint_id);
            let count = (batch_end - current_sync_idx + 1) as usize;

            let height = self.checkpoint_tree.get_height();
            let keys: Vec<SimpleMerkleNodeKey> = (current_sync_idx..=batch_end)
                .map(|idx| SimpleMerkleNodeKey::new(height, idx))
                .collect();

            let hashes = checkpoint_tree_reader.checkpoint_tree_get_nodes(last_committed_checkpoint_id, &keys).await?;
            if hashes.len() != count {
                anyhow::bail!("DB sync mismatch");
            }

            for (i, hash) in hashes.into_iter().enumerate() {
                if hash != Hasher::get_zero_hash(0) {
                    self.append_checkpoint_leaf_hash(current_sync_idx + i as u64, hash).await?;
                } else if last_committed_checkpoint_id != 0 || i != 0 {
                    anyhow::bail!("DB sync integrity error at checkpoint {}, the last committed checkpoint was supposed to be {}, but it is a zero leaf", current_sync_idx + i as u64, last_committed_checkpoint_id);
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
mod test {
    use std::sync::Arc;
    use super::*;
    use cf_utils::timer::DebugTimer;
    use parth_common::memory_stores::dash_tree::PsyDashMemoryMerkleStore;
    use parth_core::{
        PHash, crypto::hash::{merkle_proof::{DeltaMerkleProofCore, MerkleProofCore}, traits::ZeroableHash}, data::hash::merkle_node_key::SimpleMerkleNodeKey, pgoldilocks::PoseidonHasher, utils::QPGenRandom
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader,
    };

    type Hash = PHash;
    type Hasher = PoseidonHasher;

    pub struct SimpleMockDBProvider {
        pub tree: PsyDashMemoryMerkleStore<Hasher, Hash>,
    }
    impl SimpleMockDBProvider {
        pub fn new(tree_height: u8) -> Self {
            Self { tree: PsyDashMemoryMerkleStore::<Hasher, Hash>::new(tree_height) }
        }
    }
    #[async_trait::async_trait]
    impl PsyNodeCheckpointTreeDatabaseReader<Hash> for SimpleMockDBProvider {
        async fn checkpoint_tree_get_leaf_hash(&self, _checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<Hash> {
            Ok(self.tree.get_leaf_value(leaf_index))
        }
        async fn checkpoint_tree_get_root_hash(&self, _checkpoint_id: u64) -> anyhow::Result<Hash> {
            Ok(self.tree.get_root())
        }
        async fn checkpoint_tree_get_merkle_proof(&self, _checkpoint_id: u64, leaf_index: u64) -> anyhow::Result<MerkleProofCore<Hash>> {
            Ok(self.tree.get_leaf(leaf_index))
        }
        async fn checkpoint_tree_get_nodes(&self, _checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> anyhow::Result<Vec<Hash>> {
            Ok(keys.iter().map(|k| self.tree.get_node_value(k)).collect())
        }
    }

    #[tokio::test]
    async fn test_basic_ring_buffer_persistence() -> anyhow::Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db = SimpleMockDBProvider::new(10);
        let path = "backup.dat";
        let max_keep = 5;

        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), max_keep, 10, &db, path, true
        ).await?;

        let hashes: Vec<Hash> = (0..10).map(|_| Hash::qp_rand_gen()).collect();
        // Write 0..6. Ring buffer of 5.
        // Should contain [2, 3, 4, 5, 6].
        for i in 0..7 {
            // Populate the MockDB so the backup manager can verify integrity on reload
            db.tree.set_leaf(i as u64, hashes[i]);
            manager.append_checkpoint_leaf_hash(i as u64, hashes[i]).await?;
        }

        assert_eq!(manager.min_backed_up_checkpoint_id, 2);
        assert_eq!(manager.next_backup_checkpoint_id, 7);
        drop(manager);

        let manager2 = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), max_keep, 10, &db, path, false
        ).await?;

        assert_eq!(manager2.min_backed_up_checkpoint_id, 2);
        assert_eq!(manager2.next_backup_checkpoint_id, 7);
        assert_eq!(manager2.checkpoint_tree.get_leaf_value(2), hashes[2]);
        assert_eq!(manager2.checkpoint_tree.get_leaf_value(6), hashes[6]);

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_logic_reset() -> anyhow::Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db = SimpleMockDBProvider::new(20);
        let path = "sync.dat";

        let mut db_hashes = Vec::new();
        for i in 0..2000 {
            let h = Hash::qp_rand_gen();
            db.tree.set_leaf(i, h);
            db_hashes.push(h);
        }

        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 100, 20, &db, path, true
        ).await?;

        manager.sync_from_database(&db, 50, 500).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 501);
        assert_eq!(manager.min_backed_up_checkpoint_id, 401);
        assert_eq!(manager.checkpoint_tree.get_leaf_value(500), db_hashes[500]);

        manager.sync_from_database(&db, 50, 1500).await?;
        assert_eq!(manager.next_backup_checkpoint_id, 1501);
        assert_eq!(manager.min_backed_up_checkpoint_id, 1401);
        assert_eq!(manager.checkpoint_tree.get_leaf_value(1500), db_hashes[1500]);

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_reset_on_prefix_gap() -> anyhow::Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db = SimpleMockDBProvider::new(20);
        let path = "prefix_gap.dat";
        for i in 0..2000 { db.tree.set_leaf(i, Hash::qp_rand_gen()); }

        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 100, 20, &db, path, true
        ).await?;

        // Initialize state at 1300
        let start_proof = db.checkpoint_tree_get_merkle_proof(1300, 1300).await?;
        manager.checkpoint_tree.injest_merkle_proof(&start_proof)?;
        manager.min_backed_up_checkpoint_id = 1300;
        manager.next_backup_checkpoint_id = 1300;
        for i in 1300..1350 {
            manager.append_checkpoint_leaf_hash(i, db.tree.get_leaf_value(i)).await?;
        }

        // Target 1800. Req start ~1200. Manager min 1300. Gap [1200..1300].
        // Reset required.
        manager.sync_from_database(&db, 50, 1800).await?;

        assert_eq!(manager.next_backup_checkpoint_id, 1801);
        assert_eq!(manager.min_backed_up_checkpoint_id, 1701);

        Ok(())
    }

    fn ensure_dmps_are_in_checkpoint_manager<Hasher: MerkleZeroHasher<Hash>, Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + std::fmt::Debug>(
        manager: &CheckpointTreeBackupManager<Hasher, Hash, SimpleMockMemoryFileSystem>,
        proofs: &[DeltaMerkleProofCore<Hash>],
    ) -> anyhow::Result<()> {
        for (_i, proof) in proofs.iter().enumerate() {
            let start_root = proof.old_root;
            let end_root = proof.new_root;
            //println!("Verifying proof {}: start_root={:?}, end_root={:?}", i, start_root, end_root);
            let res: Option<u64> = manager.checkpoint_tree.get_leaf_index_for_root(end_root);
            if !res.is_some() {
                anyhow::bail!("No index found for root {:?}", end_root);
            }
            assert_eq!(res.unwrap(), proof.index, "Index mismatch for root {:?}", end_root);
            let proof_for_root = manager.checkpoint_tree.get_historical_append_only_merkle_proof_for_root(end_root)?;
            assert!(proof_for_root.verify::<Hasher>());
            assert_eq!(proof_for_root.get_append_root::<Hasher>(), proof.get_append_root::<Hasher>(), "Root mismatch for root {:?}", end_root);
            assert_eq!(proof_for_root.index, proof.index, "Index mismatch in proof for root {:?}", end_root);
            assert_eq!(proof_for_root.value, proof.new_value, "Value mismatch for root {:?}", end_root);
            assert_eq!(
                manager.checkpoint_tree.get_leaf_value(proof.index),
                proof.new_value,
                "Leaf value mismatch for index {}",
                proof.index
            );

            if proof.index > 0 && proof.index > manager.min_backed_up_checkpoint_id {
                let res: Option<u64> = manager.checkpoint_tree.get_leaf_index_for_root(start_root);
                if !res.is_some() {
                    anyhow::bail!("No index found for root {:?}", start_root);
                }
                assert_eq!(res.unwrap(), proof.index - 1, "Index mismatch for root {:?}", start_root);
                let proof_for_root = manager.checkpoint_tree.get_historical_append_only_merkle_proof_for_root(start_root)?;
                assert!(proof_for_root.verify::<Hasher>());
                assert_eq!(proof_for_root.get_append_root::<Hasher>(), proof.old_root, "Root mismatch for root {:?}", start_root);
                assert_eq!(proof_for_root.index, proof.index - 1, "Index mismatch in proof for root {:?}", start_root);
            }

        }
        Ok(())
    }

    #[tokio::test]
    async fn test_root_access() -> anyhow::Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = PsyDashMemoryMerkleStore::new(32);
        let db = SimpleMockDBProvider { tree: db_tree };
        let path = "checkpoint_tree.dat";

        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 1000000, 32, &db, path, true
        ).await?;

        let mut results = Vec::new();
        for i in 0..15 {
            let hash = Hash::qp_rand_gen();
            let proof = manager.append_checkpoint_leaf_hash(i, hash).await?;
            db.tree.set_leaf(i, hash);
            results.push(proof);
        }
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results)?;

        let head = 14;

        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(5, head));
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(8, head));
        println!("start of the test completed");


        let manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 1000000, 32, &db, path, true
        ).await?;
        //println!("manager reloaded");
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results)?;


        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(5, head));
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(8, head));


        // move db ahead of manager
        let new_proofs = (15..20).map(|x| {
            db.tree.set_leaf(x, Hash::qp_rand_gen())
        }).collect::<Vec<_>>();

        let mut results = [results, new_proofs].concat();


        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 1000000, 32, &db, path, true
        ).await?;
        manager.sync_from_database(&db, 2, 19).await?;
        //println!("manager reloaded with unapplied updates in the db");


        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results)?;

        let head = 19;

        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(5, head));
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(8, head));

        // Test sync entirely from db
        let file_path = "sync_from_db.dat";
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 1000000, 32, &db, file_path, true
        ).await?;
        manager.sync_from_database(&db, 2, 19).await?;

        assert_eq!(manager.next_backup_checkpoint_id, 20);
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results)?;
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(5, head));
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(30, head));


        for i in 20..10000 {
            let hash = Hash::qp_rand_gen();
            //let proof = manager.append_checkpoint_leaf_hash(i, hash).await?;
            let proof = db.tree.set_leaf(i, hash);
            results.push(proof);
        }
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 1000000, 32, &db, file_path, true
        ).await?;
        let mut timer = DebugTimer::new("sync_from_db_large");
        manager.sync_from_database(&db, 200, 9999).await?;
        timer.lap_batch("sync from db", "checkpoint", 9980);
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results)?;



        let file_path = "sync_from_db_2.dat";
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 500, 32, &db, file_path, true
        ).await?;
        let mut timer = DebugTimer::new("sync small");
        manager.sync_from_database(&db, 100, 9999).await?;
        timer.lap_batch("sync from db", "checkpoint", 500);
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 500..])?;
        for i in 0..(10000-500){
            // we should only have synced the last 500
            assert_eq!(manager.checkpoint_tree.get_leaf_value(i as u64), Hash::get_zero_value(), "the manager synced more than the checkpoints needed to cover the max history (checkpoint {} should not be saved)", i);
        }
        let result_for_ditched = ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 600..results.len()]);
        assert!(result_for_ditched.is_err());

        for i in 10000..10400 {
            let hash = Hash::qp_rand_gen();
            let proof = db.tree.set_leaf(i, hash);
            results.push(proof);
        }
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 500, 32, &db, file_path, true
        ).await?;
        let mut timer = DebugTimer::new("sync small 2");
        manager.sync_from_database(&db, 100, 10399).await?;
        timer.lap_batch("sync from db", "checkpoint", 500);
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 500..])?;
        for i in 0..(10400-500){
            // we should only have synced the last 500
            assert_eq!(manager.checkpoint_tree.get_leaf_value(i as u64), Hash::get_zero_value(), "the manager synced more than the checkpoints needed to cover the max history (checkpoint {} should not be saved)", i);
        }
        let result_for_ditched = ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 600..results.len()]);
        assert!(result_for_ditched.is_err());

        for i in 10400..10600 {
            let hash = Hash::qp_rand_gen();
            let proof = db.tree.set_leaf(i, hash);
            results.push(proof);
        }
        let mut manager = CheckpointTreeBackupManager::<Hasher, Hash, SimpleMockMemoryFileSystem>::new_from_file_path(
            fs.clone(), 2000, 32, &db, file_path, true
        ).await?;
        let mut timer = DebugTimer::new("sync small 2");
        manager.sync_from_database(&db, 100, 10599).await?;
        timer.lap_batch("sync from db", "checkpoint", 2000);
        ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 2000..])?;
        for i in 0..(10600-2000){
            // we should only have synced the last 2000
            assert_eq!(manager.checkpoint_tree.get_leaf_value(i as u64), Hash::get_zero_value(), "the manager synced more than the checkpoints needed to cover the max history (checkpoint {} should not be saved)", i);
        }
        let result_for_ditched = ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 2100..results.len()]);
        assert!(result_for_ditched.is_err());

        let result_for_ditched = ensure_dmps_are_in_checkpoint_manager::<Hasher, Hash>(&manager, &results[results.len()- 2001..results.len()]);
        assert!(result_for_ditched.is_err());

        Ok(())
    }

}

