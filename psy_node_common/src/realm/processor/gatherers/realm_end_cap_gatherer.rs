use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm,
};
use parth_core::{
    crypto::hash::traits::{MerkleZeroHasher, ZeroableHash},
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::{QFelt64, ZeroableFelt},
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId, QJobIdBase,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        header_extended::{GlobalUserTreeAggregatorHeaderWithJobId, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID},
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    node::realm_processor::RealmProcessorCoreState,
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF,
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::{
        data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
            zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset,
        },
        structs::common::tree_node_batch_header::QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
    },
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    guta_planner::realm_guta_planner::{PlannedFutureEndCapJob, RealmGUTAPlanner},
    queue::gatherer_builder::QueueGathererItemBuilderWithTree,
};
pub const REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x52, 0x47, 0x45, 0x31]; // 'RGE1' in ASCII
pub const REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31_45_47_52; // 'RGE1' in little-endian u32

pub fn get_new_realm_end_cap_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> PathBuf {
    PathBuf::from(backup_file_directory).join(format!(
        "realm_end_cap_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    ))
}

pub async fn read_realm_end_cap_gatherer_backup_file<
    Hasher: MerkleZeroHasher<Hash>,
    Hash: QDBHashBase + QFHashBase<F>,
    F: QFelt64,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: &FileSystem,
    file_path: &str,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    realm_id_u64: u64,
    realm_global_user_tree_height: u8,
    coordinator_global_user_tree_height: u8,
    insert_old_leaves: bool,
) -> anyhow::Result<RealmGUTAEndCapGathererOutputDatabase<F, Hash>> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(&file_path).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();
    let const_size_len = 4 + 32 + 32 + 8;
    if file_len < const_size_len as u64 {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }

    let magic_u32 = file.read_u32_le().await?;
    if magic_u32 != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
            magic_u32
        ));
    }

    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?;
    let start_global_user_tree_root = Hash::from_owned_32bytes(start_root_hash_bytes);
    if start_global_user_tree_root != tree.get_root() {
        return Err(anyhow::anyhow!(
            "Backup file start global user tree root {:?} does not match tree root {:?}",
            start_global_user_tree_root,
            tree.get_root()
        ));
    }
    let mut end_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut end_root_hash_bytes).await?;
    let expected_end_global_user_tree_root = Hash::from_owned_32bytes(end_root_hash_bytes);

    let expected_end_caps_processed = file.read_u64_le().await?;

    let guta_header_size = GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE;
    let end_caps_data_len = file_len
        .saturating_sub(const_size_len)
        .saturating_sub(guta_header_size as u64) as usize;
    let mut end_caps_data = vec![0u8; end_caps_data_len];
    file.read_exact(&mut end_caps_data).await?;

    let mut cursor = Cursor::new(end_caps_data);
    let mut actual_end_caps_processed = 0usize;
    let mut update_user_leaves_ffs = Vec::new();
    let mut update_user_contract_tree_nodes_ffs = Vec::new();
    let mut update_contract_state_tree_nodes_ffs = Vec::new();

    let min_user_id = realm_id_u64 << (realm_global_user_tree_height as u64);
    let max_user_id = ((realm_id_u64 + 1) << (realm_global_user_tree_height as u64)) - 1;
    let mut merkle_header = [0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE];

    for _ in 0..expected_end_caps_processed {
        // A. Read variable-length queue item via stream deserialization (handles events correctly)
        let queue_item =
            PsyRealmUserUpdateQueueItem::<F, Hash>::pio_read_from_io(&mut cursor)?;

        let user_leaf_node = queue_item.new_user_leaf;
        let user_id = user_leaf_node.user_id.to_u64_value();
        if user_id < min_user_id || user_id > max_user_id {
            return Err(anyhow::anyhow!(
                "User ID {} in end cap gatherer backup file is out of realm {} bounds ({} - {})",
                user_id,
                realm_id_u64,
                min_user_id,
                max_user_id
            ));
        }

        // B. Read Variable Contract Blobs
        // 1. Single Tree Nodes (User Contract Tree)
        Read::read_exact(&mut cursor, &mut merkle_header)?;

        let single_header_parsed = QBlobSingleMerkleNodeBatchDataView::try_read_single_node_blob_header(&merkle_header)?;

        let user_contract_tree_nodes_size = single_header_parsed.total_size as usize - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut user_contract_tree_nodes = vec![0u8; user_contract_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut user_contract_tree_nodes)?;

        // 2. Double Tree Nodes (Contract State Tree)
        Read::read_exact(&mut cursor, &mut merkle_header)?;

        let double_header_parsed = QBlobDoubleMerkleNodeBatchDataView::try_read_double_node_blob_header(&merkle_header)?;

        let contract_state_tree_nodes_size = double_header_parsed.total_size as usize - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut contract_state_tree_nodes = vec![0u8; contract_state_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut contract_state_tree_nodes)?;

        // C. Apply Logic
        user_leaf_node.pio_write_to_io(&mut update_user_leaves_ffs)?;
        update_user_contract_tree_nodes_ffs.extend_from_slice(&user_contract_tree_nodes);
        update_contract_state_tree_nodes_ffs.extend_from_slice(&contract_state_tree_nodes);

        if insert_old_leaves {
            tree.set_leaf(user_id - min_user_id, queue_item.old_user_leaf_hash);
        } else {
            tree.set_leaf(user_id - min_user_id, queue_item.new_user_leaf_hash);
        }
        actual_end_caps_processed += 1;
    }

    if actual_end_caps_processed != expected_end_caps_processed as usize {
        anyhow::bail!(
            "Backup file corruption: expected {} end caps, but recovered {}. This indicates file corruption or incomplete write.",
            expected_end_caps_processed,
            actual_end_caps_processed
        );
    }

    tracing::info!(
        "Expected end_global_user_tree_root: {:?},  actual end_global_user_tree_root: {:?}",
        expected_end_global_user_tree_root,
        tree.get_root(),
    );

    let mut header_bytes = vec![0u8; GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE];
    file.read_exact(&mut header_bytes).await?;
    let guta_header = GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::psy_ser_from_owned_bytes_vec(header_bytes)?;

    let update_global_user_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset::<Hash>(
        tree.get_changes(),
        SimpleMerkleNodeKey {
            level: coordinator_global_user_tree_height,
            index: realm_id_u64,
        },
    );

    Ok(RealmGUTAEndCapGathererOutputDatabase {
        old_realm_root: start_global_user_tree_root,
        new_realm_root: expected_end_global_user_tree_root,
        update_global_user_tree_nodes_ffs,
        update_user_contract_tree_nodes_ffs,
        update_contract_state_tree_nodes_ffs,
        update_user_leaves_ffs,
        total_proofs_generated: 0,
        total_users_updated: actual_end_caps_processed as u64,
        guta_header,
    })
}
pub struct RealmGUTAEndCapGathererConfig<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub status: Arc<RwLock<RealmProcessorCoreState<N::QHash>>>,
    pub temp_db: Arc<TempDatabase>,
    pub file_system: Arc<FileSystem>,
    pub backup_file_directory: String,
    pub coordinator_guta_updates_circuit_whitelist: N::QHash,
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>>,
    pub future_pending_end_cap_jobs: Arc<RwLock<Vec<PlannedFutureEndCapJob<N::F, N::QHash>>>>,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>
{
    fn clone(&self) -> Self {
        Self {
            realm_id_u64: self.realm_id_u64,
            realm_sub_id_u64: self.realm_sub_id_u64,
            status: self.status.clone(),
            temp_db: self.temp_db.clone(),
            backup_file_directory: self.backup_file_directory.clone(),
            file_system: self.file_system.clone(),
            coordinator_guta_updates_circuit_whitelist: self.coordinator_guta_updates_circuit_whitelist,
            checkpoint_tree: self.checkpoint_tree.clone(),
            future_pending_end_cap_jobs: self.future_pending_end_cap_jobs.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}
pub struct RealmGUTAEndCapGatherer<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub config: RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
    pub last_committed_checkpoint_root: N::QHash,
    pub guta_planner: RealmGUTAPlanner<N::F, N::QHash>,
    pub status: RealmProcessorCoreState<N::QHash>,
    pub start_global_user_tree_root: N::QHash,
    pub total_users_updated: u64,
    pub new_realm_end_cap_gatherer_file: FileSystem::File,
    pub pending_file_path: String,
}
/*
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>
{
    fn update_status(&mut self) -> anyhow::Result<()> {

        let status: RealmProcessorCoreState<<N as QNetworkHashTypes>::QHash> = self.config.status.read().map_err(|e| anyhow::anyhow!("{:?}", e))?.clone();
        self.status = status;
        Ok(())
    }
}
    */
#[derive(Clone)]
pub struct RealmGUTAEndCapGathererOutputDatabase<F, Hash> {
    pub old_realm_root: Hash,
    pub new_realm_root: Hash,
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub update_user_contract_tree_nodes_ffs: Vec<u8>,
    pub update_contract_state_tree_nodes_ffs: Vec<u8>,
    pub update_user_leaves_ffs: Vec<u8>,
    pub total_users_updated: u64,
    pub total_proofs_generated: u64,
    pub guta_header: GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>,
}

impl<F: QFelt64, Hash: QDBHashBase> RealmGUTAEndCapGathererOutputDatabase<F, Hash> {
    pub fn is_noop(&self) -> bool {
        self.old_realm_root == self.new_realm_root
    }
    pub fn get_empty(realm_root: Hash) -> Self {
        Self {
            old_realm_root: realm_root,
            new_realm_root: realm_root,
            total_users_updated: 0,
            total_proofs_generated: 0,
            update_global_user_tree_nodes_ffs: vec![],
            update_user_contract_tree_nodes_ffs: vec![],
            update_contract_state_tree_nodes_ffs: vec![],
            update_user_leaves_ffs: vec![],
            guta_header: GlobalUserTreeAggregatorHeaderWithJobId {
                job_id: QProvingJobDataID::new_invalid_job_id(),
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: Hash::get_zero_value(),
                    checkpoint_tree_root: Hash::get_zero_value(),
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: Hash::get_zero_value(),
                        new_node_value: Hash::get_zero_value(),
                        node_index: F::ZERO_VALUE,
                        node_level: F::ZERO_VALUE,
                    },
                    stats: GUTAStats::<F>::get_zero_value(),
                    total_aggregation_proofs_generated: F::ZERO_VALUE,
                },
            },
        }
    }
}
#[derive(Clone)]
pub struct RealmGUTAEndCapGathererOutput<F, Hash, JobId> {
    pub db_output: RealmGUTAEndCapGathererOutputDatabase<F, Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
#[async_trait]
impl<
        FileSystem: TokioLikeFileSystem,
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    >
    QueueGathererItemBuilderWithTree<
        RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
        SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    > for RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>
{
    type Output = RealmGUTAEndCapGathererOutput<N::F, N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        _unique_id: QCoreProcCheckpointUniqueId,
        config: RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        let status = config.status.read().unwrap().clone();
        let new_realm_end_cap_gatherer_file_path = get_new_realm_end_cap_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            status.gathering_unique_pending_id,
        );
        let mut new_realm_end_cap_gatherer_file = config
            .file_system
            .file_like_fs_create(&new_realm_end_cap_gatherer_file_path.to_string_lossy())
            .await?;
        new_realm_end_cap_gatherer_file
            .write_u32_le(REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32)
            .await?;
        new_realm_end_cap_gatherer_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        new_realm_end_cap_gatherer_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        new_realm_end_cap_gatherer_file.write_u64_le(0).await?; // place holder for total number end caps processed
        config
            .file_system
            .file_like_fs_flush_file_with_path(
                &new_realm_end_cap_gatherer_file_path.to_string_lossy(),
                &mut new_realm_end_cap_gatherer_file,
            )
            .await?;

        let mut guta_planner = RealmGUTAPlanner::<N::F, N::QHash>::new(
            status.chain_id,
            status.realm_identifier,
            status.gathering_checkpoint_root,
            status.gathering_checkpoint_id,
            status.gathering_unique_pending_id,
            tree.get_root(),
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_USER_TREE_HEIGHT,
            config.coordinator_guta_updates_circuit_whitelist,
        );
        let future_end_cap_jobs = {
            std::mem::take(
                config
                    .future_pending_end_cap_jobs
                    .write()
                    .map_err(|_| anyhow::anyhow!("error writing to future pending end cap jobs"))?
                    .as_mut(),
            )
        };
        let end_cap_jobs_added = guta_planner
            .add_future_end_cap_jobs(
                &config.checkpoint_tree,
                tree,
                &mut new_realm_end_cap_gatherer_file,
                config.temp_db.clone(),
                future_end_cap_jobs,
            )
            .await?;
        config
            .file_system
            .file_like_fs_flush_file_with_path(
                &new_realm_end_cap_gatherer_file_path.to_string_lossy(),
                &mut new_realm_end_cap_gatherer_file,
            )
            .await?;
        let last_committed_checkpoint_root = config.checkpoint_tree.get_root();
        Ok(Self {
            config,
            status,
            guta_planner,
            last_committed_checkpoint_root,
            total_users_updated:end_cap_jobs_added as u64,
            new_realm_end_cap_gatherer_file,
            start_global_user_tree_root: tree.get_root(),
            pending_file_path: new_realm_end_cap_gatherer_file_path.to_string_lossy().to_string(),
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        tracing::info!("RealmGUTAEndCapGatherer processing queue item of size {}", item.len());
        if PsyRealmUserUpdateQueueItem::<N::F, N::QHash>::IS_FIXED_SIZE && item.len() != PsyRealmUserUpdateQueueItem::<N::F, N::QHash>::FIXED_SIZE {
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for RealmGUTAEndCapGatherer: expected {}, got {}",
                PsyRealmUserUpdateQueueItem::<N::F, N::QHash>::FIXED_SIZE,
                item.len()
            ));
        }
        let update_header = PsyRealmUserUpdateQueueItem::<N::F, N::QHash>::psy_ser_from_slice(&item)?;
        tracing::info!("RealmGUTAEndCapGatherer processing queue item update_header {:?}", update_header);
        self.guta_planner
            .add_end_cap_job(
                &self.config.checkpoint_tree,
                tree,
                &mut self.new_realm_end_cap_gatherer_file,
                self.config.temp_db.clone(),
                &item,
                update_header,
            )
            .await?;
        tracing::info!("RealmGUTAEndCapGatherer finished processing queue item");
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
            .await?;
        tracing::info!("RealmGUTAEndCapGatherer flushed changes to disk for pending file path {}", self.pending_file_path);
        Ok(())
    }
    async fn update_from_many_queue_items_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        items: Vec<Vec<u8>>,
    ) -> anyhow::Result<()> {
        for item in items {
            self.update_from_queue_item_with_tree(tree, item).await?;
        }
        Ok(())
    }
    async fn finalize_with_tree(mut self, tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>) -> anyhow::Result<Self::Output> {
        tracing::info!(
            "Finalizing RealmGUTAEndCapGatherer for pending id {} with tree root {:?}",
            self.status.gathering_unique_pending_id,
            tree.get_root()
        );
        let needs_revert = {
            self.config
                .status
                .read()
                .map_err(|e| anyhow::anyhow!("error reading status {:?}", e))?
                .should_revert_processing_changes
        };

        let total_end_caps_processed = self.guta_planner.total_end_caps_processed;

        if needs_revert {
            tracing::info!(
                "Reverting GUTA updates gatherer changes for pending id {}, abandoning root {:?}",
                self.status.gathering_unique_pending_id,
                tree.get_root()
            );
            tree.revert_changes();
            todo!("Handle revert properly in GUTA end cap gatherer by reading from the previous backup file");
        } else {
            tracing::info!(
                "Committing GUTA updates gatherer changes for pending id {}, finalizing root {:?}",
                self.status.gathering_unique_pending_id,
                tree.get_root()
            );
            self.config
                .file_system
                .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
                .await?;
            tracing::info!(
                "GUTA updates gatherer for pending id {} flushed to disk before finalize.",
                self.status.gathering_unique_pending_id
            );
            let result = self
                .guta_planner
                .finalize_with_reward_ids(&self.config.checkpoint_tree, tree, self.config.temp_db.clone(), 0, 0)
                .await;
            if result.is_err() {
                tracing::error!(
                    "GUTA updates gatherer for pending id {} finalize failed: {:?}",
                    self.status.gathering_unique_pending_id,
                    result.err()
                );
                anyhow::bail!("GUTA updates gatherer finalize failed");
            }
            let result = result?;
            tracing::info!(
                "GUTA updates gatherer for pending id {} finalized planner.",
                self.status.gathering_unique_pending_id
            );
            if result.is_some() {
                let result = result.unwrap();
                self.new_realm_end_cap_gatherer_file
                    .write_all(&result.db_output.guta_header.psy_ser_to_bytes_vec()?)
                    .await?;
                self.config
                    .file_system
                    .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
                    .await?;

                self.new_realm_end_cap_gatherer_file.seek(tokio::io::SeekFrom::Start(4 + 32)).await?;
                self.new_realm_end_cap_gatherer_file
                    .write_all(&tree.get_root().into_owned_32bytes())
                    .await?;
                self.new_realm_end_cap_gatherer_file.write_u64_le(total_end_caps_processed as u64).await?;
                self.config
                    .file_system
                    .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
                    .await?;

                tracing::info!(
                    "GUTA updates gatherer for pending id {} finalized with changes.",
                    self.status.gathering_unique_pending_id
                );
                tree.commit_changes();
                return Ok(result);
            }
        }

        let guta_header = GlobalUserTreeAggregatorHeaderWithJobId {
            job_id: QProvingJobDataID::new_invalid_job_id(),
            header: GlobalUserTreeAggregatorHeader {
                guta_circuit_whitelist: N::QHash::get_zero_value(),
                checkpoint_tree_root: self.last_committed_checkpoint_root,
                state_transition: SubTreeNodeStateTransition {
                    old_node_value: N::QHash::get_zero_value(),
                    new_node_value: N::QHash::get_zero_value(),
                    node_index: N::F::ZERO_VALUE,
                    node_level: N::F::ZERO_VALUE,
                },
                stats: GUTAStats::<N::F>::get_zero_value(),
                total_aggregation_proofs_generated: N::F::ZERO_VALUE,
            },
        };
        self.new_realm_end_cap_gatherer_file
            .write_all(&guta_header.psy_ser_into_bytes_vec()?)
            .await?;
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
            .await?;

        self.new_realm_end_cap_gatherer_file.seek(tokio::io::SeekFrom::Start(4 + 32)).await?;
        self.new_realm_end_cap_gatherer_file
            .write_all(&tree.get_root().into_owned_32bytes())
            .await?;
        self.new_realm_end_cap_gatherer_file.write_u64_le(total_end_caps_processed as u64).await?;
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
            .await?;
        Ok(RealmGUTAEndCapGathererOutput {
            db_output: RealmGUTAEndCapGathererOutputDatabase::<N::F, N::QHash>::get_empty(tree.get_root()),
            job_ids: vec![],
        })
    }
}
