use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::{
    PsyMemoryMerkleStoreAppendOnlyReaderBaseAsync, PsyMemoryMerkleStoreImm,
}};
use parth_core::{
    crypto::hash::{
        merkle_proof::{DeltaMerkleProofCore, MerkleProofCore},
        traits::MerkleZeroHasher,
    },
    data::hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_node_nest::MerkleLeafNode},
    protocol::core_types::Q256BitHash,
};
use psy_core::constants::stale_checkpoint::STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF;
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::psy_core_db::traits::full::PsyNodeCheckpointTreeDatabaseReader;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};


// --- Constants ---
const CHECKPOINT_BACKUP_MAGIC_LEN: usize = 8;
const CHECKPOINT_BACKUP_MAGIC_BYTES: [u8; 8] = [0x50, 0x73, 0x79, 0x43, 0x68, 0x6B, 0x70, 0x74]; // "PsyChkpt"
const CHECKPOINT_BACKUP_MAGIC_U64_LE: u64 = 0x74_70_6B_68_43_79_73_50;
const CHECKPOINT_BACKUP_ITEM_SIZE: usize = 8 + 32; // u64 ID + 32 bytes Hash

pub struct CheckpointTreeBackupManager<
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Send + Sync + Q256BitHash,
    FileSystem: TokioLikeFileSystem,
> {
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>>,
    pub max_checkpoints_to_keep: u64,
    pub min_backed_up_checkpoint_id: u64,
    pub next_backup_checkpoint_id: u64,
    pub backup_file_path: String,
    pub backup_file: FileSystem::File,
    pub file_system: Arc<FileSystem>,
}

impl<
    Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    Hash: Eq + Copy + PartialEq + Default + std::hash::Hash + Send + Sync + Q256BitHash,
    FileSystem: TokioLikeFileSystem,
> CheckpointTreeBackupManager<Hasher, Hash, FileSystem>
{
    pub async fn new_from_file_path<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        file_system: Arc<FileSystem>,
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        backup_file_path: &str,
        allow_create_file: bool,
    ) -> Result<Self> {
        let exists = file_system.file_like_exists(backup_file_path).await?;
        
        let mut backup_file = if exists {
             file_system.file_like_fs_open(backup_file_path).await?
        } else if allow_create_file {
             file_system.file_like_fs_create(backup_file_path).await?
        } else {
            anyhow::bail!("Backup file {} does not exist and creation is not allowed.", backup_file_path);
        };

        Self::init_from_open_file(
            file_system,
            backup_file_path.to_string(),
            max_checkpoints_to_keep,
            checkpoint_tree_height,
            checkpoint_tree_store,
            backup_file,
        ).await
    }

    async fn init_from_open_file<CheckpointTreeStore: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        file_system: Arc<FileSystem>,
        backup_file_path: String,
        max_checkpoints_to_keep: u64,
        checkpoint_tree_height: u8,
        checkpoint_tree_store: &CheckpointTreeStore,
        mut backup_file: FileSystem::File,
    ) -> Result<Self> {
        let file_len = backup_file.file_like_metadata().await?.len();
        
        if file_len == 0 {
            // Write Magic
            backup_file.write_u64_le(CHECKPOINT_BACKUP_MAGIC_U64_LE).await?;
            // Important: Flush to the FileSystem map
            file_system.file_like_fs_flush_file_with_path(&backup_file_path, &mut backup_file).await?;
        } else {
            if file_len < CHECKPOINT_BACKUP_MAGIC_LEN as u64 {
                anyhow::bail!("Corrupted backup file: Too small for magic bytes.");
            }
            backup_file.seek(SeekFrom::Start(0)).await?;
            let mut magic = [0u8; CHECKPOINT_BACKUP_MAGIC_LEN];
            backup_file.read_exact(&mut magic).await?;
            if magic != CHECKPOINT_BACKUP_MAGIC_BYTES {
                anyhow::bail!("Invalid magic bytes in checkpoint backup file.");
            }
        }

        let (min_id, next_id, valid_leaves) = load_and_parse_backup_file::<Hash, FileSystem::File>(
            &mut backup_file, 
            max_checkpoints_to_keep
        ).await?;

        let checkpoint_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::<Hasher, Hash>::new(checkpoint_tree_height));

        if !valid_leaves.is_empty() {
             // 1. Initialize the tree path using the first valid leaf from the DB
             let start_idx = valid_leaves[0].index;
             let _proof = checkpoint_tree_store.checkpoint_tree_get_merkle_proof(start_idx, start_idx).await
                 .context(format!("Failed to get initial merkle proof for checkpoint {}", start_idx))?;
             
             // 2. Reconstruct the tree state in memory.
             // We use set_leaf for the first item to initialize the path (assumes store handles init), 
             // then append_leaf for the rest to ensure internal consistency.
             checkpoint_tree.set_leaf(valid_leaves[0].index, valid_leaves[0].value); 

             for leaf in valid_leaves.iter().skip(1) {
                 checkpoint_tree.append_leaf(leaf.index, leaf.value)?;
             }
        }

        Ok(Self {
            checkpoint_tree,
            max_checkpoints_to_keep,
            min_backed_up_checkpoint_id: min_id,
            next_backup_checkpoint_id: next_id,
            backup_file_path,
            backup_file,
            file_system,
        })
    }

    pub async fn append_checkpoint_leaf_hash(&mut self, checkpoint_id: u64, checkpoint_hash: Hash) -> Result<DeltaMerkleProofCore<Hash>> {
        if checkpoint_id != self.next_backup_checkpoint_id {
             // Check for idempotency (retrying the last write)
             if checkpoint_id == self.next_backup_checkpoint_id.saturating_sub(1) {
                 let existing = self.checkpoint_tree.get_leaf_value(checkpoint_id);
                 if existing == checkpoint_hash {
                     tracing::warn!("Checkpoint {} already exists, skipping append.", checkpoint_id);
                     return Ok(self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash));
                 }
             }
             
             if checkpoint_id == 0 && self.next_backup_checkpoint_id == 0 {
                 // Allowed: Initial write
             } else {
                 anyhow::bail!("Non-sequential checkpoint append. Expected {}, got {}.", self.next_backup_checkpoint_id, checkpoint_id);
             }
        }

        // Calculate Ring Buffer Offset
        let slot = checkpoint_id % self.max_checkpoints_to_keep;
        let offset = (CHECKPOINT_BACKUP_MAGIC_LEN as u64) + (slot * CHECKPOINT_BACKUP_ITEM_SIZE as u64);

        // Perform I/O
        self.backup_file.seek(SeekFrom::Start(offset)).await?;
        self.backup_file.write_u64_le(checkpoint_id).await?;
        self.backup_file.write_all(&checkpoint_hash.into_owned_32bytes()).await?;
        
        // CRITICAL: Flush the file to the file system abstraction.
        // For standard FS, this is a normal flush. For MockFS, this commits Cursor data to the DashMap.
        self.file_system.file_like_fs_flush_file_with_path(&self.backup_file_path, &mut self.backup_file).await?;
        
        let proof = if checkpoint_id == 0 {
             self.checkpoint_tree.set_leaf(checkpoint_id, checkpoint_hash)
        } else {
             self.checkpoint_tree.append_leaf(checkpoint_id, checkpoint_hash)?
        };

        self.next_backup_checkpoint_id = checkpoint_id + 1;
        
        // Update window if full
        if (self.next_backup_checkpoint_id - self.min_backed_up_checkpoint_id) > self.max_checkpoints_to_keep {
            self.min_backed_up_checkpoint_id += 1;
        }

        Ok(proof)
    }

    pub async fn sync_from_database<CheckpointTreeReader: PsyNodeCheckpointTreeDatabaseReader<Hash>>(
        &mut self,
        checkpoint_tree_reader: &CheckpointTreeReader,
        sync_batch_size: usize,
        last_committed_checkpoint_id: u64,
    ) -> Result<()> {
        let start_fetch_id = self.next_backup_checkpoint_id;
        
        if start_fetch_id > last_committed_checkpoint_id {
            return Ok(());
        }

        let count_to_fetch = (last_committed_checkpoint_id - start_fetch_id) + 1;
        tracing::info!("Syncing backup manager: fetching {} checkpoints starting from {}.", count_to_fetch, start_fetch_id);

        let mut current_id = start_fetch_id;
        let end_id = last_committed_checkpoint_id;

        while current_id <= end_id {
            let batch_end = std::cmp::min(current_id + (sync_batch_size as u64) - 1, end_id);
            let needed_keys: Vec<SimpleMerkleNodeKey> = (current_id..=batch_end)
                .map(|id| SimpleMerkleNodeKey::new(self.checkpoint_tree.get_height(), id))
                .collect();
            
            let values = checkpoint_tree_reader.checkpoint_tree_get_nodes(last_committed_checkpoint_id, &needed_keys).await?;
            
            if values.len() != needed_keys.len() {
                anyhow::bail!("Database returned incomplete batch during sync.");
            }

            for (i, value) in values.into_iter().enumerate() {
                self.append_checkpoint_leaf_hash(current_id + i as u64, value).await?;
            }

            current_id = batch_end + 1;
        }
        
        if !self.has_appropriate_checkpoint_history_for_stale_proofs(STALE_CHECKPOINT_AGE_REALM_TO_COORDINATOR_PROOF, last_committed_checkpoint_id) {
            tracing::warn!("Synced, but backup history is shorter than stale proof window.");
        }

        let my_root = self.checkpoint_tree.get_root();
        let db_root = checkpoint_tree_reader.checkpoint_tree_get_root_hash(last_committed_checkpoint_id).await?;
        
        if my_root != db_root {
            anyhow::bail!("Sync failed: Backup Manager Root {:?} != DB Root {:?}", my_root, db_root);
        }

        Ok(())
    }

    pub fn has_appropriate_checkpoint_history_for_stale_proofs(&self, max_stale_age: u64, current_head: u64) -> bool {
        if current_head < max_stale_age {
            self.min_backed_up_checkpoint_id == 0
        } else {
            let required_min = current_head - max_stale_age;
            self.min_backed_up_checkpoint_id <= required_min
        }
    }
}

/// Helper to parse the file. Returns (min_id, next_id, valid_leaves_sorted).
async fn load_and_parse_backup_file<Hash, File>(
    file: &mut File,
    max_checkpoints: u64,
) -> Result<(u64, u64, Vec<MerkleLeafNode<Hash>>)> 
where 
    Hash: Q256BitHash + Copy + Default,
    File: TokioFileLike,
{
    let meta = file.file_like_metadata().await?;
    let len = meta.len();
    
    if len < CHECKPOINT_BACKUP_MAGIC_LEN as u64 {
        return Ok((0, 0, vec![]));
    }
    
    let content_len = len - CHECKPOINT_BACKUP_MAGIC_LEN as u64;
    // Integer division implicitly handles trailing partial writes by ignoring them
    let num_items = content_len / CHECKPOINT_BACKUP_ITEM_SIZE as u64;

    if num_items == 0 {
        return Ok((0, 0, vec![]));
    }

    file.seek(SeekFrom::Start(CHECKPOINT_BACKUP_MAGIC_LEN as u64)).await?;

    // Load all potential checkpoints into a Map
    let mut found_checkpoints = BTreeMap::new();
    let mut buffer = [0u8; CHECKPOINT_BACKUP_ITEM_SIZE];

    for _ in 0..num_items {
        file.read_exact(&mut buffer).await?;
        
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&buffer[0..8]);
        let id = u64::from_le_bytes(id_bytes);
        
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&buffer[8..40]);
        let hash = Hash::from_ref_32bytes(&hash_bytes);

        found_checkpoints.insert(id, hash);
    }

    if found_checkpoints.is_empty() {
        return Ok((0, 0, vec![]));
    }

    // Logic: The "latest" data is the sequence ending at the highest ID found.
    // In a ring buffer, stale data (old IDs) might exist 'ahead' of the head.
    
    let (&max_id, _) = found_checkpoints.last_key_value().unwrap();
    let mut valid_leaves = Vec::new();
    
    // Walk backwards from max_id to find the contiguous chain
    let mut curr = max_id;
    loop {
        if let Some(hash) = found_checkpoints.get(&curr) {
            valid_leaves.push(MerkleLeafNode { index: curr, value: *hash });
            if curr == 0 { break; }
            curr -= 1;
        } else {
            break;
        }
    }

    // Sanity check: If we found more items than max_checkpoints, imply truncation
    if valid_leaves.len() as u64 > max_checkpoints {
        valid_leaves.truncate(max_checkpoints as usize);
    }

    // We built it backwards (Max -> Min). Reverse it to be sorted (Min -> Max).
    valid_leaves.reverse();

    let min_id = valid_leaves.first().map(|l| l.index).unwrap_or(0);
    let next_id = max_id + 1;
    
    Ok((min_id, next_id, valid_leaves))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use async_trait::async_trait;
    use parth_core::{
        data::hash::merkle_node_key::SimpleMerkleNode,
        pgoldilocks::PoseidonHasher,
        PHash, PF,
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_core_db::traits::full::{PsyNodeCheckpointTreeDatabaseReader, PsyNodeCheckpointTreeDatabaseWriter},
    };
    
    type TestHash = PHash;
    type TestHasher = PoseidonHasher;
    type TestManager = CheckpointTreeBackupManager<TestHasher, TestHash, SimpleMockMemoryFileSystem>;

    // --- Mocks ---
    pub struct SimpleMockDBProvider {
        pub tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<TestHasher, TestHash>>,
    }
    
    #[async_trait]
    impl PsyNodeCheckpointTreeDatabaseReader<TestHash> for SimpleMockDBProvider {
        async fn checkpoint_tree_get_leaf_hash(&self, _checkpoint_id: u64, leaf_index: u64) -> Result<TestHash> {
            Ok(self.tree.get_leaf_value(leaf_index))
        }
        async fn checkpoint_tree_get_root_hash(&self, _checkpoint_id: u64) -> Result<TestHash> {
            Ok(self.tree.get_root())
        }
        async fn checkpoint_tree_get_merkle_proof(&self, _checkpoint_id: u64, leaf_index: u64) -> Result<MerkleProofCore<TestHash>> {
            Ok(self.tree.get_leaf(leaf_index))
        }
        async fn checkpoint_tree_get_nodes(&self, _checkpoint_id: u64, keys: &[SimpleMerkleNodeKey]) -> Result<Vec<TestHash>> {
            Ok(keys.iter().map(|k| self.tree.get_node_value(k)).collect())
        }
    }

    fn rand_hash() -> TestHash {
        use parth_core::utils::QPGenRandom;
        TestHash::qp_rand_gen()
    }

    // --- Tests ---

    #[tokio::test]
    async fn test_new_manager_empty_file() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(10));
        let db = SimpleMockDBProvider { tree: db_tree };
        
        let path = "backup_empty.dat";
        let manager = TestManager::new_from_file_path(
            fs.clone(), 100, 10, &db, path, true
        ).await?;

        assert_eq!(manager.min_backed_up_checkpoint_id, 0);
        assert_eq!(manager.next_backup_checkpoint_id, 0);
        
        assert!(fs.file_like_exists(path).await?);
        let len = fs.file_like_metadata(path).await?.len();
        assert_eq!(len, 8); // Magic bytes
        Ok(())
    }

    #[tokio::test]
    async fn test_append_and_persistence() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(5));
        let db = SimpleMockDBProvider { tree: db_tree };
        let path = "backup_persist.dat";

        // 1. Create and Append
        {
            let mut manager = TestManager::new_from_file_path(fs.clone(), 5, 5, &db, path, true).await?;
            for i in 0..3 {
                let h = rand_hash();
                manager.append_checkpoint_leaf_hash(i, h).await?;
            }
            assert_eq!(manager.next_backup_checkpoint_id, 3);
            // Manager drops here
        }

        // 2. Re-open to verify the flush worked
        {
            let manager = TestManager::new_from_file_path(fs.clone(), 5, 5, &db, path, false).await?;
            assert_eq!(manager.min_backed_up_checkpoint_id, 0);
            assert_eq!(manager.next_backup_checkpoint_id, 3);
            
            // Verify tree state restored
            assert_ne!(manager.checkpoint_tree.get_root(), TestHasher::get_zero_hash(5));
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_ring_buffer_wrapping() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(5));
        let db = SimpleMockDBProvider { tree: db_tree };
        let path = "ring.dat";
        let capacity = 4;

        let mut manager = TestManager::new_from_file_path(fs.clone(), capacity, 5, &db, path, true).await?;

        // Append 6 items (Capacity 4)
        for i in 0..6 {
            let h = rand_hash();
            manager.append_checkpoint_leaf_hash(i, h).await?;
        }

        assert_eq!(manager.next_backup_checkpoint_id, 6);
        assert_eq!(manager.min_backed_up_checkpoint_id, 2); // 6 - 4

        // Verify File Size
        let expected_size = 8 + (capacity * (8 + 32));
        let actual_size = fs.file_like_metadata(path).await?.len();
        assert_eq!(actual_size, expected_size as u64);

        // Re-load
        let manager2 = TestManager::new_from_file_path(fs.clone(), capacity, 5, &db, path, false).await?;
        assert_eq!(manager2.min_backed_up_checkpoint_id, 2);
        assert_eq!(manager2.next_backup_checkpoint_id, 6);

        Ok(())
    }

    #[tokio::test]
    async fn test_sync_from_database() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(5));
        let path = "sync.dat";
        
        let mut leaves = Vec::new();
        for i in 0..10 {
            let h = rand_hash();
            leaves.push(h);
            if i == 0 { db_tree.set_leaf(i, h); } 
            else { db_tree.append_leaf(i, h).unwrap(); }
        }
        let db = SimpleMockDBProvider { tree: db_tree.clone() };

        let mut manager = TestManager::new_from_file_path(fs.clone(), 20, 5, &db, path, true).await?;

        // Append first 3 manually
        for i in 0..3 {
            manager.append_checkpoint_leaf_hash(i, leaves[i as usize]).await?;
        }
        
        assert_eq!(manager.next_backup_checkpoint_id, 3);

        // Sync up to ID 9
        manager.sync_from_database(&db, 2, 9).await?;

        assert_eq!(manager.next_backup_checkpoint_id, 10);
        assert_eq!(manager.checkpoint_tree.get_root(), db_tree.get_root());
        
        let manager2 = TestManager::new_from_file_path(fs.clone(), 20, 5, &db, path, false).await?;
        assert_eq!(manager2.next_backup_checkpoint_id, 10);

        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted_file_recovery() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(5));
        let db = SimpleMockDBProvider { tree: db_tree };
        let path = "corrupt.dat";

        // 1. Create valid file with 2 entries
        // Size = 8 (magic) + 40 (id 0) + 40 (id 1) = 88 bytes.
        {
            let mut manager = TestManager::new_from_file_path(fs.clone(), 5, 5, &db, path, true).await?;
            manager.append_checkpoint_leaf_hash(0, rand_hash()).await?;
            manager.append_checkpoint_leaf_hash(1, rand_hash()).await?;
        }

        // 2. Corrupt it manually in the DashMap
        // We want to simulate a power failure during the write of the second item.
        // We truncate to 85 bytes (Magic + Item0 + 37 bytes of Item1).
        // Since SimpleMockFileSystem::create doesn't truncate existing files by default (in your impl),
        // we must manually manipulate the map to ensure the manager reads bad data.
        {
            if let Some(mut entry) = fs.files.get_mut(path) {
                let data = entry.value_mut();
                assert_eq!(data.len(), 88, "Setup failed: File size should be 88");
                data.truncate(85); // Corrupt the last 3 bytes
            } else {
                panic!("File not found in MockFS");
            }
        }
        
        // Verify size is actually corrupted
        let size = fs.file_like_metadata(path).await?.len();
        assert_eq!(size, 85, "Manual corruption failed");

        // 3. Load. Should recover 0, discard partial 1.
        let manager = TestManager::new_from_file_path(fs.clone(), 5, 5, &db, path, false).await?;
        
        assert_eq!(manager.next_backup_checkpoint_id, 1, "Should have recovered exactly 1 checkpoint");
        assert_eq!(manager.min_backed_up_checkpoint_id, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_stale_history_logic() -> Result<()> {
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let db_tree = Arc::new(PsyDashMemoryAppendOnlyMerkleStore::new(5));
        let db = SimpleMockDBProvider { tree: db_tree };
        
        let mut manager = TestManager::new_from_file_path(fs.clone(), 10, 5, &db, "stale.dat", true).await?;

        for i in 0..15 {
             manager.append_checkpoint_leaf_hash(i, rand_hash()).await?;
        }

        let head = 14; 
        
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(5, head));
        assert!(manager.has_appropriate_checkpoint_history_for_stale_proofs(8, head));
        assert!(!manager.has_appropriate_checkpoint_history_for_stale_proofs(10, head));

        Ok(())
    }
}