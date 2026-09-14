use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::traits::MerkleZeroHasher,
    data::{
        db::hash_id_u64::{get_data_buffer_for_hash256_and_u64s, QHash256AndU64},
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE},
    },
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QDBHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId,
};
use psy_core::{job::job_id::{ProvingJobCircuitType, QProvingJobDataID}, user_id::get_user_id_from_user_registration_id};
use psy_data::{
    agg::{
        tree_agg_v2::{plan_jobs_for_tree_agg_offset_root, BasicTreePlannerHelper},
        AggStateTrackableInput, AggStateTransitionInputV2, AggStateTransitionWithStats, DummyAggStateTransition,
    },
    protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput,
    rewards_tree::offsets::{REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_INDEX, REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_LEVEL},
    v1::qdata::public_key::PZKPublicKeyInfo,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase, qblob::data_views::zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::AsyncWriteExt;

use crate::{
    coordinator::processor::processor_shared_status::PsyCoordinatorProcessorSharedStatus, queue::gatherer_builder::QueueGathererItemBuilderWithTree,
};

pub const REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x52, 0x55, 0x42, 0x31]; // 'RUB1' in ASCII
pub const REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31425552; // 'RUB1' in little-endian u32
// Millisecond-only wire format; writers must not emit this, and readers reject it.
pub const REGISTER_USER_GATHERER_BACKUP_V2_MAGIC_U32: u32 = 0x32425552; // 'RUB2' in little-endian u32
const MAX_BLOCK_TIME_SECONDS: u64 = (1u64 << 60) - 1;

fn get_current_block_time() -> anyhow::Result<u64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock is before the Unix epoch: {error}"))?;
    Ok(duration.as_secs())
}
pub fn get_new_register_user_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> String {
    PathBuf::from(backup_file_directory).join(format!(
        "register_user_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    )).to_string_lossy().to_string()
}

fn hash_two_from_slice<Hash: Q256BitHash, Hasher: MerkleZeroHasher<Hash>>(data: &[u8]) -> Hash {
    assert_eq!(data.len(), 64);
    let left = Hash::from_owned_32bytes(data[0..32].try_into().expect("Slice with incorrect length"));
    let right = Hash::from_owned_32bytes(data[32..64].try_into().expect("Slice with incorrect length"));
    Hasher::two_to_one(&left, &right)
}

pub async fn read_register_user_gatherer_backup_file_path<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase, FileSystem: TokioLikeFileSystem>(
    file_system: &FileSystem,
    file_path: &str,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<RegisterUserGathererOutputDatabase<Hash>> {
    tracing::info!("Reading register user gatherer backup file from path: {}", file_path);
    let file: FileSystem::File = file_system.file_like_fs_open(file_path).await?;
    read_register_user_gatherer_backup_file::<Hasher, Hash, FileSystem::File>(file, tree).await
}
pub async fn read_register_user_gatherer_backup_file<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase, File: TokioFileLike>(
    mut file: File,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<RegisterUserGathererOutputDatabase<Hash>> {
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();
    if file_len < 4 + 8 + 32 + 8 + 8{
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }

    let file_len_without_metadata = file_len - 4 - 8 - 32 - 8 - 8;
    if file_len_without_metadata % (64 as u64) != 0 {
        return Err(anyhow::anyhow!(
            "Backup file length without metadata is not a multiple of 64: {} bytes",
            file_len_without_metadata
        ));
    }

    let expected_count = file_len_without_metadata / (64 as u64);
    let magic_u32 = file.read_u32_le().await?;
    if magic_u32 != REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Register user gatherer backup magic mismatch: expected RUB1 (0x{:08x}), got 0x{:08x}; RUB2 (millisecond-based) backups are not supported",
            REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32,
            magic_u32
        ));
    }
    let start_next_user_id = file.read_u64_le().await?;
    if tree.get_leaf_value(start_next_user_id) != Hasher::get_zero_hash(0) {
        return Err(anyhow::anyhow!(
            "Backup file start user id {} does not match tree zero hash {:?}",
            start_next_user_id,
            tree.get_leaf_value(start_next_user_id)
        ));
    }
    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?;
    let start_root_hash = Hash::from_owned_32bytes(start_root_hash_bytes);

    let pivot_proof = tree.get_historical_pivot_leaf(start_next_user_id);
    if pivot_proof.root != start_root_hash {
        return Err(anyhow::anyhow!(
            "Backup file start root hash {:?} does not match tree computed root hash {:?}",
            start_root_hash,
            pivot_proof.root
        ));
    }

    let mut public_keys_no_id = vec![0u8; file_len_without_metadata as usize];
    let mut new_user_public_keys_ffs = Vec::with_capacity(expected_count as usize * 72);
    file.read_exact(&mut public_keys_no_id).await?;
    let mut new_public_key_hash_to_user_id_rows = Vec::with_capacity(expected_count as usize);

    let mut new_leaf_hashes = Vec::with_capacity(expected_count as usize);
    for i in 0..expected_count {
        let offset = (i * 64) as usize;
        new_user_public_keys_ffs.extend_from_slice(&(start_next_user_id + i).to_le_bytes());
        new_user_public_keys_ffs.extend_from_slice(&public_keys_no_id[offset..offset + 64]);
        let leaf_hash = hash_two_from_slice::<Hash, Hasher>(&public_keys_no_id[offset..offset + 64]);
        new_public_key_hash_to_user_id_rows.push(QHash256AndU64 {
            hash: leaf_hash,
            value_u64: start_next_user_id + i,
        });
        tree.set_leaf(start_next_user_id + i, leaf_hash);
        new_leaf_hashes.push(leaf_hash);
    }

    let new_public_key_hash_to_user_id_rows_ffs = get_data_buffer_for_hash256_and_u64s(&new_public_key_hash_to_user_id_rows);

    let end_root = tree.get_root();
    let next_user_id = start_next_user_id + expected_count;
    let mut update_user_registration_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len() * PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE);

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
        node.pio_write_to_io(&mut update_user_registration_tree_nodes_ffs)?;
    }
    let total_jobs = file.read_u64_le().await?;
    let block_time = file.read_u64_le().await?;
    if block_time == 0 || block_time > MAX_BLOCK_TIME_SECONDS {
        return Err(anyhow::anyhow!(
            "Register user gatherer backup block_time {} must be within 1..={}",
            block_time,
            MAX_BLOCK_TIME_SECONDS
        ));
    }
    tree.commit_changes();
    let output_db = RegisterUserGathererOutputDatabase {
        start_next_user_id,
        start_user_registration_tree_hash: start_root_hash,
        new_user_public_keys_ffs,
        next_user_id,
        end_user_registration_tree_hash: end_root,
        user_registration_tree_update_pivot_siblings: pivot_proof.siblings,
        new_public_key_hash_to_user_id_rows_ffs,
        update_user_registration_tree_nodes_ffs,
        total_jobs,
        block_time,
    };
    Ok(output_db)
}
pub struct RegisterUserGathererConfig<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>>>,

    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub temp_db: Arc<TempDatabase>,
    pub backup_file_directory: String,
    pub register_users_circuit_whitelist: N::QHash,
    pub last_job_next_user_id: Arc<RwLock<u64>>,
    pub file_system: Arc<FileSystem>,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for RegisterUserGathererConfig<N, TempDatabase, FileSystem>
{
    fn clone(&self) -> Self {
        Self {
            realm_id_u64: self.realm_id_u64,
            realm_sub_id_u64: self.realm_sub_id_u64,
            status: Arc::clone(&self.status),
            temp_db: Arc::clone(&self.temp_db),
            backup_file_directory: self.backup_file_directory.clone(),
            register_users_circuit_whitelist: self.register_users_circuit_whitelist.clone(),
            last_job_next_user_id: Arc::clone(&self.last_job_next_user_id),
            file_system: Arc::clone(&self.file_system),
            _phantom_n: std::marker::PhantomData,
        }
    }
}

pub struct RegisterUserGatherer<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub shared_status: PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>,
    pub config: RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub new_user_registration_tree_leaves: Vec<N::QHash>,
    pub new_user_public_keys_file: FileSystem::File,
    pub pending_file_path: String,
    pub next_user_id: u64,
}
impl<
        N: QNetworkTypesConfig,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
        FileSystem: TokioLikeFileSystem,
    >
    RegisterUserGatherer<N, TempDatabase, FileSystem>
{
    pub fn reset_for_revert(&mut self) -> anyhow::Result<()> {
        self.new_user_public_keys_ffs.clear();
        self.new_public_key_hash_to_user_id_rows_ffs.clear();
        self.new_user_registration_tree_leaves.clear();
        self.next_user_id = self.shared_status.block_state.next_user_id;

        self.config
            .last_job_next_user_id
            .write()
            .map_err(|e| anyhow::anyhow!("error writing last job next user id {:?}", e))?
            .clone_from(&self.shared_status.block_state.next_user_id);

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct RegisterUserGathererOutputDatabase<Hash> {
    pub start_next_user_id: u64,
    pub start_user_registration_tree_hash: Hash,
    pub new_user_public_keys_ffs: Vec<u8>,
    // end backup format
    pub next_user_id: u64,
    pub end_user_registration_tree_hash: Hash,
    pub user_registration_tree_update_pivot_siblings: Vec<Hash>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
    pub total_jobs: u64,
    pub block_time: u64,
}
#[derive(Debug, Clone)]
pub struct RegisterUserGathererOutput<Hash, JobId> {
    pub db_output: RegisterUserGathererOutputDatabase<Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
#[async_trait]
impl<
        FileSystem: TokioLikeFileSystem,
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    >
    QueueGathererItemBuilderWithTree<
        RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
        SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    > for RegisterUserGatherer<N, TempDatabase, FileSystem>
{
    type Output = RegisterUserGathererOutput<N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: RegisterUserGathererConfig<N, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        tracing::info!("Creating new RegisterUserGatherer with pending unique id {:?}", unique_id);
        let shared_status = config.status.read().unwrap().clone();
        let new_user_public_keys_file_path = get_new_register_user_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            shared_status.unique_pending_id,
        );
        let mut new_user_public_keys_file = config
            .file_system
            .file_like_fs_create(&new_user_public_keys_file_path)
            .await?;
        let start_next_user_id = config.last_job_next_user_id.read().unwrap().clone();
        if tree.get_leaf_value(start_next_user_id) != N::HasherBase::get_zero_hash(0) {
            return Err(anyhow::anyhow!(
                "Starting next user id {} does not match tree zero hash {:?}",
                start_next_user_id,
                tree.get_leaf_value(start_next_user_id)
            ));
        }
        if start_next_user_id != 0 {
            tracing::info!("tree: root: {:?}", tree.get_root());
            tracing::info!("zero hash for tree_root: {:?}", N::HasherBase::get_zero_hash(tree.get_height() as usize));
            if tree.get_leaf_value(start_next_user_id - 1) == N::HasherBase::get_zero_hash(0) {
                return Err(anyhow::anyhow!(
                    "The leaf before the next user id {} minus one does not exist in tree, cannot continue",
                    start_next_user_id
                ));
            }
        }
        new_user_public_keys_file.write_u32_le(REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32).await?;
        new_user_public_keys_file.write_u64_le(start_next_user_id).await?;
        new_user_public_keys_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        tracing::info!(
            "Created new RegisterUserGatherer with starting next user id {} and tree root {:?}",
            start_next_user_id,
            tree.get_root()
        );
        Ok(Self {
            config,
            shared_status,
            pending_core_proc_id: unique_id,
            new_user_public_keys_ffs: Vec::new(),
            new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
            new_user_registration_tree_leaves: Vec::new(),
            new_user_public_keys_file,
            pending_file_path: new_user_public_keys_file_path,
            next_user_id: start_next_user_id,
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        _tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        if item.len() != PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE || PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE != 64 {
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for RegisterUserGatherer: expected {}, got {}",
                PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE,
                item.len()
            ));
        }
        self.new_user_public_keys_file.write_all(&item).await?;
        self.new_user_public_keys_ffs
            .extend_from_slice(self.next_user_id.to_le_bytes().as_slice());
        self.new_user_public_keys_ffs.extend_from_slice(&item);
        let hash = hash_two_from_slice::<N::QHash, N::HasherBase>(&item);
        let u64_hash_mapping_row = QHash256AndU64 {
            hash,
            value_u64: get_user_id_from_user_registration_id(
                self.next_user_id,
                N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                N::REALM_GLOBAL_USER_TREE_HEIGHT,
                N::GROUP_REALM_HEIGHT,
            ),
        };
        self.new_public_key_hash_to_user_id_rows_ffs
            .extend_from_slice(&u64_hash_mapping_row.ffs_to_bytes());

        tracing::info!("new user registered with user id {}", self.next_user_id);
        self.next_user_id += 1;
        self.new_user_registration_tree_leaves.push(hash);

        Ok(())
    }
    async fn update_from_many_queue_items_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        items: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        tracing::info!("Updating RegisterUserGatherer with {} new users", items.len());
        for item in items {
            self.update_from_queue_item_with_tree(tree, item).await?;
        }
        Ok(())
    }
    async fn finalize_with_tree(mut self, tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>) -> anyhow::Result<Self::Output> {
        tracing::info!("Finalizing RegisterUserGatherer with {} new users", self.new_user_registration_tree_leaves.len());
        let needs_revert = {
            self.config
                .status
                .read()
                .map_err(|e| anyhow::anyhow!("error reading status {:?}", e))?
                .should_revert_last_changes
        };

        if needs_revert {
            {
                self.config
                    .last_job_next_user_id
                    .write()
                    .map_err(|e| anyhow::anyhow!("error writing last job next user id {:?}", e))?
                    .clone_from(&self.shared_status.block_state.next_user_id);
            }
            self.reset_for_revert()?;
            

            // TODO: maybe we regenerate the job witnesses if we need to revert instead of
            // making the users resubmit
            tree.revert_changes();
            tree.clear_changes_remove_committed_leaves_and_rehash(self.shared_status.block_state.next_user_id, self.next_user_id);
            if tree.get_root() != self.shared_status.last_committed_checkpoint_state_roots.user_tree_root {
                return Err(anyhow::anyhow!(
                    "After revert, user registration tree root mismatch: expected {:?}, got {:?}",
                    self.shared_status.last_committed_checkpoint_state_roots.user_tree_root,
                    tree.get_root()
                ));
            }
            // remove the backup file since we are reverting
            //tokio::fs::remove_file(&self.pending_file_path).await?;
            
        }else{
            tree.commit_changes();
        }
        let last_job_next_user_id = {
            self.config
                .last_job_next_user_id
                .read()
                .map_err(|e| anyhow::anyhow!("error reading last job next user id {:?}", e))?
                .clone()
        };
        // ensure the new user public keys file is flushed to disk
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_user_public_keys_file)
            .await?;

        let start_state_root = tree.get_root();

        let pending_unique_id = self.shared_status.unique_pending_id;
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let spider_man_groups = if self.new_user_registration_tree_leaves.len() == 0 {
            vec![]
        } else {
            let append_index = self.next_user_id - self.new_user_registration_tree_leaves.len() as u64;
            let spider_map_proofs =
                tree.append_leaves_spider_man_at_index(N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT as u8, append_index, &self.new_user_registration_tree_leaves)?;
            spider_map_proofs
                .chunks(N::BATCH_USER_REGISTRATION_MAX_SUB_TREES)
                .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                    register_users_circuit_whitelist: self.config.register_users_circuit_whitelist,
                    spiderman_append_proofs: chunk.to_vec(),
                })
                .collect::<Vec<_>>()
        };
        for i in last_job_next_user_id..self.next_user_id {
            if tree.get_leaf_value(i) == N::HasherBase::get_zero_hash(0) {
                tracing::error!("After finalize, user registration tree leaf for user id {} is zero hash, expected non-zero hash", i);
                return Err(anyhow::anyhow!(
                    "After finalize, user registration tree leaf for user id {} is zero hash, expected non-zero hash",
                    i
                ));
            }
        }
        
        let (jobs_for_queue, job_temp_data) = plan_jobs_for_tree_agg_offset_root::<
            QProvingJobDataID,
            N::F,
            N::QHash,
            N::HasherBase,
            QCAppendUserRegistrationTreeCircuitInput<N::QHash>,
            AggRegisterUserHelper,
        >(
            pending_unique_id,
            start_state_root,
            self.config.register_users_circuit_whitelist,
            &spider_man_groups,
            REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_INDEX,
            REGISTER_USERS_REWARDS_TREE_OFFSET_ROOT_LEVEL,
        )?;
        let total_jobs = jobs_for_queue.iter().map(|v| v.len()).sum::<usize>() as u64;
        self.new_user_public_keys_file.write_u64_le(total_jobs).await?;
        let block_time = get_current_block_time()?;
        self.new_user_public_keys_file.write_u64_le(block_time).await?;

        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_user_public_keys_file)
            .await?;

        let update_user_registration_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;

        let start_next_user_id = self.shared_status.block_state.next_user_id;
        let output_database = RegisterUserGathererOutputDatabase {
            start_next_user_id,
            start_user_registration_tree_hash: start_state_root,
            new_user_public_keys_ffs: self.new_user_public_keys_ffs,
            next_user_id: self.next_user_id,
            end_user_registration_tree_hash: tree.get_root(),
            user_registration_tree_update_pivot_siblings: tree.get_historical_pivot_leaf(start_next_user_id).siblings,
            new_public_key_hash_to_user_id_rows_ffs: self.new_public_key_hash_to_user_id_rows_ffs,
            update_user_registration_tree_nodes_ffs,
            total_jobs,
            block_time,
        };
        let output = RegisterUserGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };

        {
            self.config
                .last_job_next_user_id
                .write()
                .map_err(|e| anyhow::anyhow!("error writing last job next user id {:?}", e))?
                .clone_from(&self.next_user_id);
        }
        tracing::info!("Finished finalizing RegisterUserGatherer with {} new users", self.new_user_registration_tree_leaves.len());
        Ok(output)
    }
}

pub struct AggRegisterUserHelper {}
impl<Hash: Q256BitHash>
    BasicTreePlannerHelper<
        QProvingJobDataID,
        Hash,
        QCAppendUserRegistrationTreeCircuitInput<Hash>,
        AggStateTransitionInputV2<Hash>,
        DummyAggStateTransition<Hash>,
    > for AggRegisterUserHelper
{
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            0,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            0,
            0,
        )
        .get_input_witness_id()
    }

    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
            0,
            node_key.index as u32,
        )
        .get_input_witness_id()
    }

    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::AppendUserRegistrationTree,
            0,
            node_key.index as u32,
        )
        .get_input_witness_id()
    }

    fn create_dummy_witness(allowed_circuit_hashes_root: Hash, tree_root: Hash) -> DummyAggStateTransition<Hash> {
        DummyAggStateTransition {
            unmodified_state_tree_root: tree_root,
            allowed_circuit_hashes_root,
            is_deploy_contracts: false,
            is_register_users: true,
        }
    }

    fn create_agg_two_leaf_witness(
        left: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
        right: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
    ) -> AggStateTransitionInputV2<Hash> {
        let left_state_transition = left.get_state_transition();
        let right_state_transition = right.get_state_transition();
        AggStateTransitionInputV2 {
            left_input: AggStateTransitionWithStats {
                state_transition_start: left_state_transition.state_transition_start,
                state_transition_end: left_state_transition.state_transition_end,
                total_proofs_generated: 1,
            },
            right_input: AggStateTransitionWithStats {
                state_transition_start: right_state_transition.state_transition_start,
                state_transition_end: right_state_transition.state_transition_end,
                total_proofs_generated: 1,
            },
            left_proof_is_leaf: true,
            right_proof_is_leaf: true,
        }
    }

    fn create_agg_left_leaf_right_agg_witness(
        left: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
        right: &AggStateTransitionInputV2<Hash>,
    ) -> AggStateTransitionInputV2<Hash> {
        let left_state_transition = left.get_state_transition();
        let right_state_transition = right.condense_add_one();

        AggStateTransitionInputV2 {
            left_input: AggStateTransitionWithStats {
                state_transition_start: left_state_transition.state_transition_start,
                state_transition_end: left_state_transition.state_transition_end,
                total_proofs_generated: 1,
            },
            right_input: right_state_transition,
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }

    fn create_agg_left_agg_right_leaf_witness(
        left: &AggStateTransitionInputV2<Hash>,
        right: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
    ) -> AggStateTransitionInputV2<Hash> {
        let right_state_transition = right.get_state_transition();
        let left_state_transition = left.condense_add_one();

        AggStateTransitionInputV2 {
            left_input: left_state_transition,
            right_input: AggStateTransitionWithStats {
                state_transition_start: right_state_transition.state_transition_start,
                state_transition_end: right_state_transition.state_transition_end,
                total_proofs_generated: 1,
            },
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }

    fn create_agg_to_agg_witness(left: &AggStateTransitionInputV2<Hash>, right: &AggStateTransitionInputV2<Hash>) -> AggStateTransitionInputV2<Hash> {
        let left_state_transition = left.condense_add_one();
        let right_state_transition = right.condense_add_one();

        AggStateTransitionInputV2 {
            left_input: left_state_transition,
            right_input: right_state_transition,
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{pgoldilocks::PoseidonHasher, utils::QPGenRandom};
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::agg::tree_agg_v2::plan_jobs_for_tree_agg;

    use super::*;

    #[test]
    fn current_block_time_uses_unix_seconds() -> anyhow::Result<()> {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs();
        let block_time = get_current_block_time()?;
        let after = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)?
            .as_secs();

        assert!(block_time >= before);
        assert!(block_time <= after);
        // Protocol block_time is Unix seconds: must sit below the millisecond epoch floor.
        assert!(block_time < 1_000_000_000_000);
        assert!(block_time >= 1_000_000_000);
        Ok(())
    }

    #[test]
    fn test_fake_agg() -> anyhow::Result<()> {
        type Hash = parth_core::PHash;
        type F = parth_core::PF;
        type JobId = QProvingJobDataID;
        type Hasher = PoseidonHasher;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let random_leaves = Hash::qp_rand_gen_vec(17);
        let register_users_circuit_whitelist = Hash::qp_rand_gen();
        let start_root = tree.get_root();
        let spider_map_proofs = tree.append_leaves_spider_man(2, &random_leaves)?;
        println!("Spiderman proofs len: {}", spider_map_proofs.len());

        let spider_man_groups = spider_map_proofs
            .chunks(2)
            .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                register_users_circuit_whitelist: register_users_circuit_whitelist,
                spiderman_append_proofs: chunk.to_vec(),
            })
            .collect::<Vec<_>>();
        println!("spiderman groups len: {}", spider_man_groups.len());

        let unique_pending_id = 1337u64;
        let (jobs_for_queue, _witneses) =
            plan_jobs_for_tree_agg::<JobId, F, Hash, Hasher, QCAppendUserRegistrationTreeCircuitInput<Hash>, AggRegisterUserHelper>(
                unique_pending_id,
                start_root,
                register_users_circuit_whitelist,
                &spider_man_groups,
            )?;
        println!("Jobs for queue len: {}", jobs_for_queue.len());
        for row in jobs_for_queue.iter() {
            for job in row.iter() {
                println!("Job id: {:?}", job.job_id);
                println!("Metadata: {:?}", job.metadata);
            }
        }

        Ok(())
    }
}

/*




running 1 test
Spiderman proofs len: 5
spiderman groups len: 3
Jobs for queue len: 3
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [12390451264743676018, 8304973432661659895, 3781840995643076068, 10132581250177410994] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [10334449205758273826, 12066373173403079634, 1053597563067968013, 6237065607049177422] }), reward_tree_node_index: 1, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [7095128601763881389, 14640763668863926621, 6914635675784815755, 6508350705276371674] }), reward_tree_node_index: 0, reward_tree_node_level: 1, reward_tree_hash_mode: 0, reward_tree_node_children: 2, dependencies: [QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }, QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 1, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [1297856571266094013, 6684537187575756546, 15809828805894705281, 15948219461984833794] }), reward_tree_node_index: 1, reward_tree_node_level: 1, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17884585634982125226, 6187098926797097119, 3004161071059206768, 6204218450729565222] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 0, reward_tree_node_children: 2, dependencies: [QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }, QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 1, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }] }
test coordinator::processor::gatherers::register_user_gatherer::tests::test_fake_agg ... ok



*/
#[cfg(test)]
mod tests3 {
    use std::collections::{HashMap, HashSet};

    use anyhow::{anyhow, Result};
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{pgoldilocks::PoseidonHasher, utils::QPGenRandom, PHash, PF};
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::{
        agg::tree_agg_v2::plan_jobs_for_tree_agg,
        protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput,
        worker::metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
    };

    use super::*;

    fn validate_tree_structure(
        layers: &Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>,
        expected_num_leaves: usize,
        unique_id: u64,
    ) -> Result<()> {
        let mut key_to_info: HashMap<SimpleMerkleNodeKey, (QProvingJobDataID, u8, u16, Vec<QProvingJobDataID>)> = HashMap::new();
        let mut leaf_count = 0;

        for layer in layers {
            for item in layer {
                let key = SimpleMerkleNodeKey {
                    level: item.metadata.reward_tree_node_level,
                    index: item.metadata.reward_tree_node_index,
                };
                let hash_mode = item.metadata.reward_tree_hash_mode;
                let num_children = item.metadata.reward_tree_node_children;
                let deps = item.metadata.dependencies.clone();
                key_to_info.insert(key, (item.job_id, hash_mode, num_children, deps));

                if hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                    leaf_count += 1;
                }
            }
        }

        assert_eq!(leaf_count, expected_num_leaves);

        let root_key = SimpleMerkleNodeKey { level: 0, index: 0 };
        let mut visited: HashSet<SimpleMerkleNodeKey> = HashSet::new();

        fn recurse(
            key: SimpleMerkleNodeKey,
            key_to_info: &HashMap<SimpleMerkleNodeKey, (QProvingJobDataID, u8, u16, Vec<QProvingJobDataID>)>,
            visited: &mut HashSet<SimpleMerkleNodeKey>,
            unique_id: u64,
        ) -> Result<()> {
            if !visited.insert(key) {
                return Err(anyhow!("Duplicate visit to key {:?}", key));
            }

            let Some(&(job_id, hash_mode, num_children, ref deps)) = key_to_info.get(&key) else {
                return Err(anyhow!("Missing key {:?}", key));
            };

            if hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                assert_eq!(num_children, 0);
                assert_eq!(deps.len(), 0);
                assert_eq!(
                    job_id,
                    <AggRegisterUserHelper as BasicTreePlannerHelper<
                        QProvingJobDataID,
                        PHash,
                        QCAppendUserRegistrationTreeCircuitInput<PHash>,
                        AggStateTransitionInputV2<PHash>,
                        DummyAggStateTransition<PHash>,
                    >>::get_leaf_job_id(unique_id, key)
                );
            } else if hash_mode == PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD {
                assert_eq!(num_children, 2);
                assert_eq!(deps.len(), 2);
                assert_eq!(
                    job_id,
                    <AggRegisterUserHelper as BasicTreePlannerHelper<
                        QProvingJobDataID,
                        PHash,
                        QCAppendUserRegistrationTreeCircuitInput<PHash>,
                        AggStateTransitionInputV2<PHash>,
                        DummyAggStateTransition<PHash>,
                    >>::get_agg_job_id(unique_id, key)
                );

                let left_key = SimpleMerkleNodeKey {
                    level: key.level + 1,
                    index: key.index * 2,
                };
                let right_key = SimpleMerkleNodeKey {
                    level: key.level + 1,
                    index: key.index * 2 + 1,
                };

                let left_info = key_to_info.get(&left_key).ok_or(anyhow!("Missing left child {:?}", left_key))?;
                let right_info = key_to_info.get(&right_key).ok_or(anyhow!("Missing right child {:?}", right_key))?;

                assert_eq!(deps[0], left_info.0);
                assert_eq!(deps[1], right_info.0);

                recurse(left_key, key_to_info, visited, unique_id)?;
                recurse(right_key, key_to_info, visited, unique_id)?;
            } else {
                return Err(anyhow!("Unknown hash_mode {} for key {:?}", hash_mode, key));
            }

            Ok(())
        }

        recurse(root_key, &key_to_info, &mut visited, unique_id)?;

        assert_eq!(visited.len(), key_to_info.len(), "Not all nodes were visited");

        Ok(())
    }

    fn setup_and_plan_jobs(num_groups: usize) -> Result<Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(32);
        let height = 0u8; // Use height=0 for single-leaf subtrees to control the number of proofs exactly
        let num_raw_leaves = num_groups;
        let random_leaves = PHash::qp_rand_gen_vec(num_raw_leaves);
        let spider_map_proofs = tree.append_leaves_spider_man(height, &random_leaves)?;
        assert_eq!(spider_map_proofs.len(), num_groups);

        let whitelist = PHash::qp_rand_gen();
        let spider_man_groups: Vec<QCAppendUserRegistrationTreeCircuitInput<PHash>> = spider_map_proofs
            .into_iter()
            .map(|proof| QCAppendUserRegistrationTreeCircuitInput {
                register_users_circuit_whitelist: whitelist,
                spiderman_append_proofs: vec![proof],
            })
            .collect();
        assert_eq!(spider_man_groups.len(), num_groups);

        let unique_checkpoint_id = 1337u64;
        let start_tree_root = tree.get_root();
        let (layers, _witnesses) = plan_jobs_for_tree_agg::<
            QProvingJobDataID,
            PF,
            PHash,
            PoseidonHasher,
            QCAppendUserRegistrationTreeCircuitInput<PHash>,
            AggRegisterUserHelper,
        >(unique_checkpoint_id, start_tree_root, whitelist, &spider_man_groups)?;

        Ok(layers)
    }

    #[test]
    fn test_tree_agg_num_leaves_0() -> Result<()> {
        let unique_id = 1337u64;
        let start_root = PHash::qp_rand_gen();
        let allowed = PHash::qp_rand_gen();
        let leaves: &[QCAppendUserRegistrationTreeCircuitInput<PHash>] = &[];
        let (layers, _witnesses) = plan_jobs_for_tree_agg::<
            QProvingJobDataID,
            PF,
            PHash,
            PoseidonHasher,
            QCAppendUserRegistrationTreeCircuitInput<PHash>,
            AggRegisterUserHelper,
        >(unique_id, start_root, allowed, leaves)?;

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 1);
        let item = &layers[0][0];
        assert_eq!(
            item.job_id,
            <AggRegisterUserHelper as BasicTreePlannerHelper<
                QProvingJobDataID,
                PHash,
                QCAppendUserRegistrationTreeCircuitInput<PHash>,
                AggStateTransitionInputV2<PHash>,
                DummyAggStateTransition<PHash>,
            >>::get_dummy_job_id(unique_id)
        );
        assert_eq!(item.metadata.reward_tree_node_level, 0);
        assert_eq!(item.metadata.reward_tree_node_index, 0);
        assert_eq!(item.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(item.metadata.reward_tree_node_children, 0);
        assert_eq!(item.metadata.dependencies.len(), 0);

        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_1() -> Result<()> {
        let layers = setup_and_plan_jobs(1)?;
        validate_tree_structure(&layers, 1, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_2() -> Result<()> {
        let layers = setup_and_plan_jobs(2)?;
        validate_tree_structure(&layers, 2, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_3() -> Result<()> {
        let layers = setup_and_plan_jobs(3)?;
        validate_tree_structure(&layers, 3, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_4() -> Result<()> {
        let layers = setup_and_plan_jobs(4)?;
        validate_tree_structure(&layers, 4, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_5() -> Result<()> {
        let layers = setup_and_plan_jobs(5)?;
        validate_tree_structure(&layers, 5, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_6() -> Result<()> {
        let layers = setup_and_plan_jobs(6)?;
        validate_tree_structure(&layers, 6, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_7() -> Result<()> {
        let layers = setup_and_plan_jobs(7)?;
        validate_tree_structure(&layers, 7, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_8() -> Result<()> {
        let layers = setup_and_plan_jobs(8)?;
        validate_tree_structure(&layers, 8, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_large() -> Result<()> {
        let layers = setup_and_plan_jobs(100)?;
        validate_tree_structure(&layers, 100, 1337)?;
        Ok(())
    }

    #[test]
    fn test_fake_agg() -> anyhow::Result<()> {
        type Hash = parth_core::PHash;
        type F = parth_core::PF;
        type JobId = QProvingJobDataID;
        type Hasher = PoseidonHasher;

        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let random_leaves = Hash::qp_rand_gen_vec(17);
        let allowed_circuit_hashes_root = Hash::qp_rand_gen();
        let start_root = tree.get_root();
        let spider_map_proofs = tree.append_leaves_spider_man(2, &random_leaves)?;
        println!("Spiderman proofs len: {}", spider_map_proofs.len());

        let spider_man_groups = spider_map_proofs
            .chunks(2)
            .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                register_users_circuit_whitelist: allowed_circuit_hashes_root,
                spiderman_append_proofs: chunk.to_vec(),
            })
            .collect::<Vec<_>>();
        println!("spiderman groups len: {}", spider_man_groups.len());

        let unique_pending_id = 1337u64;
        let (jobs_for_queue, _witneses) =
            plan_jobs_for_tree_agg::<JobId, F, Hash, Hasher, QCAppendUserRegistrationTreeCircuitInput<Hash>, AggRegisterUserHelper>(
                unique_pending_id,
                start_root,
                allowed_circuit_hashes_root,
                &spider_man_groups,
            )?;
        println!("Jobs for queue len: {}", jobs_for_queue.len());
        for row in jobs_for_queue.iter() {
            for job in row.iter() {
                println!("Job id: {:?}", job.job_id);
                println!("Metadata: {:?}", job.metadata);
            }
        }

        validate_tree_structure(&jobs_for_queue, spider_man_groups.len(), unique_pending_id)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests2 {
    use anyhow::{anyhow, Result};
    use parth_core::{
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        pgoldilocks::PoseidonHasher,
        utils::QPGenRandom,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::{
        agg::
            tree_agg_v2::plan_jobs_for_tree_agg
        ,
        worker::metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
    };

    use super::*;
    fn compute_max_level(mut num: usize) -> u8 {
        let mut h = 0u8;
        while num > 1 {
            num = (num + 1) / 2;
            h += 1;
        }
        h
    }
    type F = parth_core::PF; // Assuming QFelt64 is defined elsewhere, e.g., as u64 or a field element
    type Hash = parth_core::PHash; // Assuming PHash is a 256-bit hash
    type Hasher = PoseidonHasher; // Using PoseidonHasher as the FieldQHasher
    type JobId = QProvingJobDataID;
    type LeafWitness = QCAppendUserRegistrationTreeCircuitInput<Hash>;

    // Helper function to generate dummy leaf witnesses
    fn generate_dummy_leaves(num_leaves: usize, whitelist: Hash) -> Vec<LeafWitness> {
        (0..num_leaves)
            .map(|_| LeafWitness {
                register_users_circuit_whitelist: whitelist,
                spiderman_append_proofs: QPGenRandom::qp_rand_gen_vec(3), // Empty for dummy
            })
            .collect()
    }

    // Validate the planner output for the current skewed-split semantics:
    // layers[0] is the deepest level, layers[last] the root (level 0), and
    // leaves may sit at any level because the planner splits subtrees as
    // left = ceil(n/2), right = floor(n/2) and stops descending at size 1.
    fn validate_tree_structure(layers: &[Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>], max_level: u8, num_leaves: usize) -> Result<()> {
        use std::collections::HashMap;

        if layers.len() != (max_level as usize) + 1 {
            return Err(anyhow!("Incorrect number of layers: expected {}, got {}", max_level + 1, layers.len()));
        }

        let mut jobs_by_key: HashMap<(u8, u64), &PsyProvingJobMetadataWithJobId<Hash, JobId>> = HashMap::new();
        let mut total_jobs = 0usize;
        let mut leaf_jobs = 0usize;

        for (layer_idx, layer) in layers.iter().enumerate() {
            let level = max_level - layer_idx as u8;
            let mut last_index: Option<u64> = None;
            for job in layer {
                let index = job.metadata.reward_tree_node_index;
                if job.metadata.reward_tree_node_level != level {
                    return Err(anyhow!(
                        "Level mismatch: expected {}, got {}",
                        level,
                        job.metadata.reward_tree_node_level
                    ));
                }
                if let Some(last) = last_index {
                    if index <= last {
                        return Err(anyhow!("Indices within level {} are not strictly increasing", level));
                    }
                }
                last_index = Some(index);
                if index >= (1u64 << level) {
                    return Err(anyhow!("Index {} out of range for level {}", index, level));
                }
                if job.job_id.group_id != level as u32 {
                    return Err(anyhow!("Job level mismatch: expected {}, got {}", level, job.job_id.group_id));
                }
                if job.job_id.task_index != index as u32 {
                    return Err(anyhow!("Job index mismatch: expected {}, got {}", index, job.job_id.task_index));
                }
                jobs_by_key.insert((level, index), job);
                total_jobs += 1;

                if job.metadata.reward_tree_node_children == 0 {
                    leaf_jobs += 1;
                    if job.metadata.reward_tree_hash_mode != PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                        return Err(anyhow!("Leaf hash mode incorrect"));
                    }
                    if !job.metadata.dependencies.is_empty() {
                        return Err(anyhow!("Leaf should have no dependencies"));
                    }
                    if job.job_id.circuit_type != ProvingJobCircuitType::AppendUserRegistrationTree {
                        return Err(anyhow!("Incorrect circuit type for leaf"));
                    }
                } else {
                    if job.metadata.reward_tree_node_children != 2 {
                        return Err(anyhow!("Aggregation nodes must have exactly two children"));
                    }
                    if job.metadata.reward_tree_hash_mode != PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD {
                        return Err(anyhow!("Agg hash mode incorrect"));
                    }
                    if job.job_id.circuit_type != ProvingJobCircuitType::AppendUserRegistrationTreeAggregate {
                        return Err(anyhow!("Incorrect circuit type for agg"));
                    }
                    // children may live in any deeper layer, not just the one
                    // directly below, because leaves stop descending early
                    let left_child = *jobs_by_key
                        .get(&(level + 1, index * 2))
                        .ok_or_else(|| anyhow!("Missing left child for node at level {}, index {}", level, index))?;
                    let right_child = *jobs_by_key
                        .get(&(level + 1, index * 2 + 1))
                        .ok_or_else(|| anyhow!("Missing right child for node at level {}, index {}", level, index))?;
                    if job.metadata.dependencies != vec![left_child.job_id, right_child.job_id] {
                        return Err(anyhow!("Dependency mismatch for node at level {}, index {}", level, index));
                    }
                }
            }
        }

        let expected_total = if num_leaves == 0 { 1 } else { 2 * num_leaves - 1 };
        if total_jobs != expected_total {
            return Err(anyhow!("Incorrect number of jobs: expected {}, got {}", expected_total, total_jobs));
        }
        if leaf_jobs != num_leaves {
            return Err(anyhow!("Incorrect number of leaves: expected {}, got {}", num_leaves, leaf_jobs));
        }

        // Root should be at last layer, single node
        let root_layer = &layers[layers.len() - 1];
        if root_layer.len() != 1 {
            return Err(anyhow!("Root layer should have exactly 1 node"));
        }
        if root_layer[0].metadata.reward_tree_node_level != 0 {
            return Err(anyhow!("Root level should be 0"));
        }
        if root_layer[0].metadata.reward_tree_node_index != 0 {
            return Err(anyhow!("Root index should be 0"));
        }

        Ok(())
    }

    // Test for specific leaf counts
    fn test_tree_agg_for_num_leaves(num_leaves: usize) -> anyhow::Result<()> {
        let whitelist = Hash::qp_rand_gen();
        let start_root = Hash::qp_rand_gen();
        let unique_id = 1337u64;
        let leaves = generate_dummy_leaves(num_leaves, whitelist);

        let (layers, witnesses) =
            plan_jobs_for_tree_agg::<JobId, F, Hash, Hasher, LeafWitness, AggRegisterUserHelper>(unique_id, start_root, whitelist, &leaves)?;

        let max_level = compute_max_level(num_leaves);
        assert_eq!(layers.len(), (max_level as usize) + 1);

        // Validate witnesses count
        if witnesses.len() != layers.iter().map(|l| l.len()).sum::<usize>() {
            return Err(anyhow!(
                "Witness count mismatch: expected {}, got {}",
                layers.iter().map(|l| l.len()).sum::<usize>(),
                witnesses.len()
            ));
        }

        // Programmatic validation
        validate_tree_structure(&layers, max_level, num_leaves)?;

        Ok(())
    }

    #[test]
    fn test_tree_agg_1_leaf() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(1)
    }

    #[test]
    fn test_tree_agg_2_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(2)
    }

    #[test]
    fn test_tree_agg_3_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(3)
    }

    #[test]
    fn test_tree_agg_4_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(4)
    }

    #[test]
    fn test_tree_agg_5_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(5)
    }

    #[test]
    fn test_tree_agg_6_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(6)
    }

    #[test]
    fn test_tree_agg_7_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(7)
    }

    #[test]
    fn test_tree_agg_8_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(8)
    }

    #[test]
    fn test_tree_agg_large() -> anyhow::Result<()> {
        // Test with a larger tree, e.g., 17 as in the original
        test_tree_agg_for_num_leaves(17)?;

        // Even larger, say 100
        test_tree_agg_for_num_leaves(100)?;

        // Power of 2 - 1
        test_tree_agg_for_num_leaves(15)?;

        Ok(())
    }

    #[test]
    fn test_tree_agg_0_leaves() -> anyhow::Result<()> {
        let whitelist = Hash::qp_rand_gen();
        let start_root = Hash::qp_rand_gen();
        let unique_id = 1337u64;
        let leaves: Vec<LeafWitness> = vec![];

        let (layers, witnesses) =
            plan_jobs_for_tree_agg::<JobId, F, Hash, Hasher, LeafWitness, AggRegisterUserHelper>(unique_id, start_root, whitelist, &leaves)?;

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 1);
        let job = &layers[0][0];
        assert_eq!(job.metadata.reward_tree_node_level, 0);
        assert_eq!(job.metadata.reward_tree_node_index, 0);
        assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(job.metadata.reward_tree_node_children, 0);
        assert!(job.metadata.dependencies.is_empty());
        assert_eq!(job.job_id.circuit_type, ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate);
        assert_eq!(witnesses.len(), 1);

        Ok(())
    }

    // Additional test for expected public inputs hash, etc., if needed
    // But focusing on structure as per the task
}

#[cfg(test)]
mod tests_backup_v1 {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{pgoldilocks::PoseidonHasher, protocol::core_types::Q256BitHash, PHash};
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;

    use super::read_register_user_gatherer_backup_file_path;

    type Hasher = PoseidonHasher;
    type Hash = PHash;

    // Millisecond-only RUB2 magic. Rejected by the RUB1 seconds reader.
    const RUB2_MAGIC_U32: u32 = 0x32425552;

    // A plausible Unix-second timestamp (year ~2023). Exact seconds semantics
    // for the accepted RUB1 wire format.
    const PLAUSIBLE_BLOCK_TIME_SECONDS: u64 = 1_700_000_000;

    // A plausible Unix-millisecond timestamp (year ~2023). Must never be accepted
    // on the wire once RUB1 seconds is restored.
    const MILLISECOND_BLOCK_TIME: u64 = 1_700_000_000_000;

    /// Builds the on-disk byte layout of a register-user gatherer backup for the
    /// given magic, using the supplied tree's current root and start id. Mirrors
    /// the writer's layout exactly (magic | start_next_user_id | start_root |
    /// 64-byte public keys... | total_jobs | block_time).
    fn build_backup_bytes(
        magic_u32: u32,
        start_next_user_id: u64,
        start_root: &Hash,
        public_keys: &[&[u8; 64]],
        total_jobs: u64,
        block_time: u64,
    ) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&magic_u32.to_le_bytes());
        data.extend_from_slice(&start_next_user_id.to_le_bytes());
        data.extend_from_slice(&start_root.clone().into_owned_32bytes());
        for pk in public_keys {
            data.extend_from_slice(pk.as_slice());
        }
        data.extend_from_slice(&total_jobs.to_le_bytes());
        data.extend_from_slice(&block_time.to_le_bytes());
        data
    }

    #[tokio::test]
    async fn rejects_rub2_millisecond_backup_before_footer_enters_checkpoint() -> anyhow::Result<()> {
        let file_system = SimpleMockMemoryFileSystem::new();
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let start_root = tree.get_root();
        let path = "register_user_gatherer_realm_0_sub_0_pending_1.backup";

        // A RUB2 backup carrying a millisecond block_time footer.
        let data = build_backup_bytes(
            RUB2_MAGIC_U32,
            0,
            &start_root,
            &[],
            0,
            MILLISECOND_BLOCK_TIME,
        );
        assert!(
            data.len() >= 4 + 8 + 32 + 8 + 8,
            "test fixture must clear the reader's minimum-size guard so the magic is actually read"
        );
        file_system.files.insert(path.to_string(), data);

        let mut read_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let result =
            read_register_user_gatherer_backup_file_path::<Hasher, Hash, SimpleMockMemoryFileSystem>(
                &file_system,
                path,
                &mut read_tree,
            )
            .await;

        let err = result.expect_err("RUB2 backup must be rejected by the RUB1-only reader");
        let message = err.to_string();
        assert!(
            message.to_lowercase().contains("magic"),
            "rejection must happen at the magic check, got: {message}"
        );
        assert!(
            message.contains("RUB1"),
            "error must name the expected RUB1 format, got: {message}"
        );
        // The millisecond footer must never be parsed into a checkpoint: the magic
        // check returns before total_jobs / block_time are read, so no
        // RegisterUserGathererOutputDatabase is constructed.
        assert!(
            !message.to_lowercase().contains("block_time"),
            "rejection must precede any block_time handling, got: {message}"
        );

        Ok(())
    }

    #[tokio::test]
    async fn rejects_rub1_block_time_outside_protocol_field_range() -> anyhow::Result<()> {
        for block_time in [0, (1u64 << 60)] {
            let file_system = SimpleMockMemoryFileSystem::new();
            let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
            let start_root = tree.get_root();
            let path = format!("invalid_block_time_{block_time}.backup");
            let data = build_backup_bytes(
                super::REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32,
                0,
                &start_root,
                &[],
                0,
                block_time,
            );
            file_system.files.insert(path.clone(), data);

            let mut read_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
            let error = read_register_user_gatherer_backup_file_path::<
                Hasher,
                Hash,
                SimpleMockMemoryFileSystem,
            >(&file_system, &path, &mut read_tree)
            .await
            .expect_err("invalid block_time must be rejected before checkpoint construction");

            assert!(error.to_string().contains("block_time"));
            assert_eq!(read_tree.get_root(), start_root);
        }

        Ok(())
    }

    #[tokio::test]
    async fn accepts_valid_rub1_seconds_backup() -> anyhow::Result<()> {
        let file_system = SimpleMockMemoryFileSystem::new();
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let start_root = tree.get_root();
        let path = "register_user_gatherer_realm_0_sub_0_pending_2.backup";

        // A valid RUB1 backup with zero new users and a plausible seconds
        // block_time footer.
        let data = build_backup_bytes(
            super::REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32,
            0,
            &start_root,
            &[],
            0,
            PLAUSIBLE_BLOCK_TIME_SECONDS,
        );
        file_system.files.insert(path.to_string(), data);

        let mut read_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let output =
            read_register_user_gatherer_backup_file_path::<Hasher, Hash, SimpleMockMemoryFileSystem>(
                &file_system,
                path,
                &mut read_tree,
            )
            .await?;

        assert_eq!(output.start_next_user_id, 0);
        assert_eq!(output.next_user_id, 0);
        assert_eq!(output.total_jobs, 0);
        assert_eq!(output.block_time, PLAUSIBLE_BLOCK_TIME_SECONDS);
        assert_eq!(output.start_user_registration_tree_hash, start_root);
        // The reader must commit the (empty) tree changes and leave the root intact.
        assert_eq!(read_tree.get_root(), start_root);

        Ok(())
    }
}

/// Tests for the `RegisterUserGatherer` builder (backup writer/reader round
/// trip, cursor validation, finalize and revert), running fully offline
/// against the in-memory temp store and mock file system.
#[cfg(test)]
mod gatherer_builder_tests {
    use std::sync::{Arc, RwLock};

    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::MerkleZeroHasher,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::Q256BitHash,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_data::v1::qdata::checkpoint::{
        PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState,
    };
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    use crate::{
        coordinator::processor::processor_shared_status::PsyCoordinatorProcessorSharedStatus,
        test_common::TestNetworkConfig,
    };

    use super::*;

    type N = TestNetworkConfig;
    type Hash = PHash;
    type F = PF;
    type Hasher = PoseidonHasher;
    type TempDb = InMemoryTempStore;
    type Fs = SimpleMockMemoryFileSystem;

    const REALM_ID: u64 = 1;
    const REALM_SUB_ID: u64 = 2;
    const UNIQUE_PENDING_ID: u64 = 600;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    /// `unwrap_err` needs the Ok type to be Debug; keep the helper style of
    /// the other gatherer test modules.
    fn err_str<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected the call to fail, but it succeeded"),
            Err(e) => e.to_string(),
        }
    }

    /// One 64-byte PZKPublicKeyInfo-shaped queue item (the gatherer only
    /// checks the fixed size and hashes the raw bytes).
    fn rand_public_key_bytes() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&Hash::qp_rand_gen().into_owned_32bytes());
        bytes.extend_from_slice(&Hash::qp_rand_gen().into_owned_32bytes());
        bytes
    }

    fn expected_leaf(item: &[u8]) -> Hash {
        hash_two_from_slice::<Hash, Hasher>(item)
    }

    fn block_state(next_user_id: u64) -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id: 0,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id,
            end_balance: 0,
            next_contract_id: 0,
        }
    }

    fn shared_status(user_tree_root: Hash, should_revert: bool) -> Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>> {
        Arc::new(RwLock::new(PsyCoordinatorProcessorSharedStatus {
            last_committed_checkpoint_id: 0,
            unique_pending_id: UNIQUE_PENDING_ID,
            last_committed_checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root: zh(2),
                deposit_tree_root: zh(2),
                user_tree_root,
                withdrawal_tree_root: zh(2),
                user_registration_tree_root: user_tree_root,
            },
            should_revert_last_changes: should_revert,
            block_state: block_state(0),
        }))
    }

    fn test_config(
        status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>>,
        temp_db: Arc<TempDb>,
        fs: Arc<Fs>,
        last_job_next_user_id: Arc<RwLock<u64>>,
    ) -> RegisterUserGathererConfig<N, TempDb, Fs> {
        RegisterUserGathererConfig {
            status,
            realm_id_u64: REALM_ID,
            realm_sub_id_u64: REALM_SUB_ID,
            temp_db,
            backup_file_directory: "gatherer_backups".to_string(),
            register_users_circuit_whitelist: zh(31),
            last_job_next_user_id,
            file_system: fs,
            _phantom_n: std::marker::PhantomData,
        }
    }

    /// Writer layout: magic | start_next_user_id | start_root | keys... |
    /// total_jobs | block_time.
    fn backup_bytes(start_next_user_id: u64, start_root: Hash, keys: &[Vec<u8>], total_jobs: u64, block_time: u64) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&REGISTER_USER_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        data.extend_from_slice(&start_next_user_id.to_le_bytes());
        data.extend_from_slice(&start_root.into_owned_32bytes());
        for key in keys {
            data.extend_from_slice(key);
        }
        data.extend_from_slice(&total_jobs.to_le_bytes());
        data.extend_from_slice(&block_time.to_le_bytes());
        data
    }

    #[test]
    fn backup_file_path_contains_realm_and_pending_ids() {
        let path = get_new_register_user_gatherer_backup_file_path("/tmp/backups", 4, 6, 99);
        assert!(path.starts_with("/tmp/backups"));
        assert!(path.ends_with("register_user_gatherer_realm_4_sub_6_pending_99.backup"));
    }

    #[tokio::test]
    async fn read_backup_rejects_header_level_errors() -> anyhow::Result<()> {
        let fs = SimpleMockMemoryFileSystem::new();

        // below the minimum header size of 4 + 8 + 32 + 8 + 8 bytes
        fs.files.insert("too_small".to_string(), vec![0u8; 59]);
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let err = err_str(read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, "too_small", &mut tree).await);
        assert!(err.contains("too small to be valid"), "got: {err}");

        // body length not a multiple of the 64-byte public key size
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let mut data = backup_bytes(0, tree.get_root(), &[], 0, 1_700_000_000);
        data.push(0u8);
        fs.files.insert("bad_multiple".to_string(), data);
        let err = err_str(read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, "bad_multiple", &mut tree).await);
        assert!(err.contains("not a multiple of 64"), "got: {err}");

        // start user id already occupied in the tree
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        tree.set_leaf(1, Hash::qp_rand_gen());
        tree.commit_changes();
        let data = backup_bytes(1, tree.get_root(), &[], 0, 1_700_000_000);
        fs.files.insert("occupied".to_string(), data);
        let err = err_str(read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, "occupied", &mut tree).await);
        assert!(err.contains("does not match tree zero hash"), "got: {err}");

        // start root that does not match the computed pivot root
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let data = backup_bytes(0, Hash::qp_rand_gen(), &[], 0, 1_700_000_000);
        fs.files.insert("wrong_root".to_string(), data);
        let err = err_str(read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, "wrong_root", &mut tree).await);
        assert!(err.contains("does not match tree computed root hash"), "got: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn read_backup_happy_path_applies_public_keys_and_commits() -> anyhow::Result<()> {
        let fs = SimpleMockMemoryFileSystem::new();
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let start_root = tree.get_root();
        let key_a = rand_public_key_bytes();
        let key_b = rand_public_key_bytes();
        let data = backup_bytes(0, start_root, &[key_a.clone(), key_b.clone()], 5, 1_700_000_000);
        fs.files.insert("happy".to_string(), data);

        let output = read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, "happy", &mut tree).await?;
        assert_eq!(output.start_next_user_id, 0);
        assert_eq!(output.next_user_id, 2);
        assert_eq!(output.start_user_registration_tree_hash, start_root);
        assert_eq!(output.total_jobs, 5);
        assert_eq!(output.block_time, 1_700_000_000);

        // ffs rows are (user id || 64-byte public key) pairs in order
        let mut expected_ffs = Vec::new();
        expected_ffs.extend_from_slice(&0u64.to_le_bytes());
        expected_ffs.extend_from_slice(&key_a);
        expected_ffs.extend_from_slice(&1u64.to_le_bytes());
        expected_ffs.extend_from_slice(&key_b);
        assert_eq!(output.new_user_public_keys_ffs, expected_ffs);
        assert!(!output.new_public_key_hash_to_user_id_rows_ffs.is_empty());

        // the leaves were applied to the tree and committed
        assert_eq!(tree.get_leaf_value(0), expected_leaf(&key_a));
        assert_eq!(tree.get_leaf_value(1), expected_leaf(&key_b));
        let mut expected_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        expected_tree.set_leaf(0, expected_leaf(&key_a));
        expected_tree.set_leaf(1, expected_leaf(&key_b));
        assert_eq!(output.end_user_registration_tree_hash, expected_tree.get_root());
        assert_eq!(tree.get_root(), expected_tree.get_root());
        // pivot siblings for a height-32 tree
        assert_eq!(output.user_registration_tree_update_pivot_siblings.len(), 32);
        Ok(())
    }

    #[tokio::test]
    async fn create_new_validates_tree_cursor_state() -> anyhow::Result<()> {
        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());

        // start id already occupied: leaf 0 exists but the cursor points at 0
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        tree.set_leaf(0, Hash::qp_rand_gen());
        tree.commit_changes();
        let config = test_config(shared_status(tree.get_root(), false), Arc::clone(&temp_db), Arc::clone(&fs), Arc::new(RwLock::new(0u64)));
        let err = err_str(RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await);
        assert!(err.contains("Starting next user id 0 does not match tree zero hash"), "got: {err}");

        // gap behind the cursor: cursor at 3 but the tree is empty
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let config = test_config(shared_status(tree.get_root(), false), Arc::clone(&temp_db), Arc::clone(&fs), Arc::new(RwLock::new(3u64)));
        let err = err_str(RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await);
        assert!(err.contains("minus one does not exist in tree"), "got: {err}");

        // valid cursor: one registered user, cursor at 1
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        tree.set_leaf(0, Hash::qp_rand_gen());
        tree.commit_changes();
        let config = test_config(shared_status(tree.get_root(), false), Arc::clone(&temp_db), Arc::clone(&fs), Arc::new(RwLock::new(1u64)));
        let gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;
        assert_eq!(gatherer.next_user_id, 1);
        assert!(gatherer.pending_file_path.ends_with("register_user_gatherer_realm_1_sub_2_pending_600.backup"));
        Ok(())
    }

    #[tokio::test]
    async fn builder_accepts_registrations_and_finalizes() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let start_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let last_job_next_user_id = Arc::new(RwLock::new(0u64));
        let config = test_config(
            shared_status(start_root, false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::clone(&last_job_next_user_id),
        );
        let mut gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let key_a = rand_public_key_bytes();
        let key_b = rand_public_key_bytes();
        gatherer.update_from_many_queue_items_with_tree(&mut tree, vec![key_a.clone(), key_b.clone()]).await?;
        assert_eq!(gatherer.next_user_id, 2);
        assert_eq!(gatherer.new_user_registration_tree_leaves.len(), 2);
        // the tree only changes at finalize
        assert_eq!(tree.get_leaf_value(0), zh(0));
        assert_eq!(tree.get_leaf_value(1), zh(0));

        let output = RegisterUserGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        assert_eq!(output.db_output.start_next_user_id, 0);
        assert_eq!(output.db_output.next_user_id, 2);
        assert_eq!(output.db_output.start_user_registration_tree_hash, start_root);
        let mut expected_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        expected_tree.set_leaf(0, expected_leaf(&key_a));
        expected_tree.set_leaf(1, expected_leaf(&key_b));
        assert_eq!(output.db_output.end_user_registration_tree_hash, expected_tree.get_root());
        assert_eq!(tree.get_root(), expected_tree.get_root());

        let mut expected_ffs = Vec::new();
        expected_ffs.extend_from_slice(&0u64.to_le_bytes());
        expected_ffs.extend_from_slice(&key_a);
        expected_ffs.extend_from_slice(&1u64.to_le_bytes());
        expected_ffs.extend_from_slice(&key_b);
        assert_eq!(output.db_output.new_user_public_keys_ffs, expected_ffs);
        assert!(!output.db_output.new_public_key_hash_to_user_id_rows_ffs.is_empty());

        let total: u64 = output.job_ids.iter().map(|v| v.len() as u64).sum();
        assert!(total >= 1);
        assert_eq!(output.db_output.total_jobs, total);
        // protocol block_time is unix seconds
        assert!(output.db_output.block_time >= 1 && output.db_output.block_time < 1_000_000_000_000);
        // the shared cursor advanced past the registered users
        assert_eq!(*last_job_next_user_id.read().unwrap(), 2);

        // the backup file is a faithful round trip for the reader
        let backup_path = get_new_register_user_gatherer_backup_file_path("gatherer_backups", 1, 2, 600);
        let bytes = fs.files.get(&backup_path).unwrap().value().clone();
        assert_eq!(bytes.len(), 4 + 8 + 32 + 128 + 8 + 8);
        let mut read_tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let read_output = read_register_user_gatherer_backup_file_path::<Hasher, Hash, Fs>(&fs, &backup_path, &mut read_tree).await?;
        assert_eq!(read_output.next_user_id, 2);
        assert_eq!(read_output.end_user_registration_tree_hash, output.db_output.end_user_registration_tree_hash);
        assert_eq!(read_output.total_jobs, total);
        Ok(())
    }

    #[tokio::test]
    async fn builder_rejects_invalid_queue_item_size() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let config = test_config(shared_status(tree.get_root(), false), temp_db, fs, Arc::new(RwLock::new(0u64)));
        let mut gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let err = err_str(gatherer.update_from_queue_item_with_tree(&mut tree, vec![0u8; 63]).await);
        assert!(err.contains("Invalid queue item size"), "got: {err}");
        let err = err_str(gatherer.update_from_queue_item_with_tree(&mut tree, vec![0u8; 65]).await);
        assert!(err.contains("Invalid queue item size"), "got: {err}");
        // no partial state was recorded
        assert_eq!(gatherer.next_user_id, 0);
        assert!(gatherer.new_user_registration_tree_leaves.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn finalize_without_users_writes_empty_backup() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let start_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let config = test_config(shared_status(start_root, false), temp_db, Arc::clone(&fs), Arc::new(RwLock::new(0u64)));
        let gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let output = RegisterUserGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        assert_eq!(output.db_output.next_user_id, 0);
        assert_eq!(output.db_output.start_next_user_id, 0);
        assert_eq!(output.db_output.end_user_registration_tree_hash, start_root);
        assert_eq!(tree.get_root(), start_root);
        assert!(output.db_output.new_user_public_keys_ffs.is_empty());
        // the planner emits the root promotion job even with zero inputs
        let total: u64 = output.job_ids.iter().map(|v| v.len() as u64).sum();
        assert!(total >= 1);
        assert_eq!(output.db_output.total_jobs, total);
        assert!(output.db_output.block_time >= 1 && output.db_output.block_time < 1_000_000_000_000);

        let backup_path = get_new_register_user_gatherer_backup_file_path("gatherer_backups", 1, 2, 600);
        let bytes = fs.files.get(&backup_path).unwrap().value().clone();
        assert_eq!(bytes.len(), 4 + 8 + 32 + 8 + 8);
        assert_eq!(u64::from_le_bytes(bytes[44..52].try_into()?), total);
        Ok(())
    }

    #[tokio::test]
    async fn finalize_revert_restores_tree_and_cursors() -> anyhow::Result<()> {
        // two committed users, cursor at 2
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        tree.set_leaf(0, Hash::qp_rand_gen());
        tree.set_leaf(1, Hash::qp_rand_gen());
        tree.commit_changes();
        let committed_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let status = shared_status(committed_root, false);
        // flip the block into revert mode while the gatherer is alive: the
        // decision is read live from the shared status at finalize time
        status.write().unwrap().should_revert_last_changes = true;
        status.write().unwrap().block_state = block_state(2);
        let config = test_config(status, temp_db, fs, Arc::new(RwLock::new(2u64)));
        let mut gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        gatherer.update_from_queue_item_with_tree(&mut tree, rand_public_key_bytes()).await?;
        assert_eq!(gatherer.next_user_id, 3);

        let output = RegisterUserGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        // the revert branch never touches the tree mid-block (leaves are only
        // applied at finalize), so the committed state survives unchanged
        assert_eq!(tree.get_root(), committed_root);
        assert_eq!(output.db_output.next_user_id, 2);
        assert_eq!(output.db_output.end_user_registration_tree_hash, committed_root);
        assert!(output.db_output.new_user_public_keys_ffs.is_empty());
        // the cursor was reset to the last committed value
        assert_eq!(output.db_output.start_next_user_id, 2);
        // planner still emits the dummy root job
        assert!(output.db_output.total_jobs >= 1);
        Ok(())
    }

    #[tokio::test]
    async fn finalize_revert_with_wrong_committed_root_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let temp_db = Arc::new(InMemoryTempStore::new("register_user_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        // the committed user tree root in the (create-time) shared status
        // snapshot does not match the live tree
        let config = test_config(shared_status(Hash::qp_rand_gen(), true), temp_db, fs, Arc::new(RwLock::new(0u64)));
        let gatherer = RegisterUserGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let err = err_str(RegisterUserGatherer::finalize_with_tree(gatherer, &mut tree).await);
        assert!(err.contains("user registration tree root mismatch"), "got: {err}");
        Ok(())
    }
}
