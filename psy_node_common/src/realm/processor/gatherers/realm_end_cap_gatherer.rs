use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, RwLock},
};

use anyhow::Context as _;
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
    v1::qdata::{ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF, user::PQEDUserLeaf},
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::{
        blob_type::{QBlobDataType, QBlobMerkleNodeTreeType},
        data_views::{
            double_merkle_node_batch::QBlobDoubleMerkleNodeBatchDataView, single_merkle_node_batch::QBlobSingleMerkleNodeBatchDataView,
            zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset,
        },
        structs::common::tree_node_batch_header::{QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE},
        traits::common::QBlobStructHeaderBase,
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

/// Reads only the end_root hash from a realm gatherer backup file header.
/// This is a lightweight check to find which backup matches a target root
/// without mutating any in-memory tree.
pub async fn read_realm_backup_end_root<FileSystem: TokioLikeFileSystem, Hash: QDBHashBase>(
    file_system: &FileSystem,
    path: &str,
) -> anyhow::Result<Hash> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(path).await?;
    let magic_u32 = file.read_u32_le().await?;
    if magic_u32 != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
            magic_u32
        ));
    }
    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?; // discard start_root
    let mut end_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut end_root_hash_bytes).await?;
    Ok(Hash::from_owned_32bytes(end_root_hash_bytes))
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
    let mut file: FileSystem::File = match file_system.file_like_fs_open(file_path).await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(
                "Failed to open realm backup file: path={}, realm_id={}, error={:?}",
                file_path,
                realm_id_u64,
                e
            );
            return Err(e.into());
        }
    };
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

    let remaining_data_len = file_len.saturating_sub(const_size_len) as usize;
    let mut remaining_data = vec![0u8; remaining_data_len];
    file.read_exact(&mut remaining_data).await?;

    let mut cursor = Cursor::new(remaining_data);
    let mut actual_end_caps_processed = 0usize;
    let mut update_user_leaves_ffs = Vec::new();
    let mut update_user_contract_tree_nodes_ffs = Vec::new();
    let mut update_contract_state_tree_nodes_ffs = Vec::new();
    let mut update_contract_state_imt_leaves_ffs = Vec::new();

    let min_user_id = realm_id_u64 << (realm_global_user_tree_height as u64);
    let max_user_id = ((realm_id_u64 + 1) << (realm_global_user_tree_height as u64)) - 1;
    let mut merkle_header = [0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE];

    for _ in 0..expected_end_caps_processed {
        // A. Read queue item fields manually to match backup body layout
        // Layout: job_id(24) + expected_checkpoint(8) + old_hash(32) + new_hash(32)
        //         + user_leaf(104) + stats(40) + events_len(4) + events(variable)
        let mut job_id_bytes = [0u8; 24];
        Read::read_exact(&mut cursor, &mut job_id_bytes)?;

        let mut expected_checkpoint_bytes = [0u8; 8];
        Read::read_exact(&mut cursor, &mut expected_checkpoint_bytes)?;

        let mut old_hash_bytes = [0u8; 32];
        Read::read_exact(&mut cursor, &mut old_hash_bytes)?;
        let old_user_leaf_hash = Hash::from_owned_32bytes(old_hash_bytes);

        let mut new_hash_bytes = [0u8; 32];
        Read::read_exact(&mut cursor, &mut new_hash_bytes)?;
        let new_user_leaf_hash = Hash::from_owned_32bytes(new_hash_bytes);

        let user_leaf_node = PQEDUserLeaf::<F, Hash>::pio_read_from_io(&mut cursor)?;
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

        // Skip stats (40 bytes)
        let mut stats_bytes = [0u8; 40];
        Read::read_exact(&mut cursor, &mut stats_bytes)?;

        // Read events_len and skip events
        let mut events_len_bytes = [0u8; 4];
        Read::read_exact(&mut cursor, &mut events_len_bytes)?;
        let events_len = u32::from_le_bytes(events_len_bytes);
        for _ in 0..events_len {
            // Skip fixed event fields: checkpoint_id(8) + user_id(8) + contract_id(8) + method_id(8) + event_index(8) + data_len(4) = 44 bytes
            let mut event_fixed = [0u8; 44];
            Read::read_exact(&mut cursor, &mut event_fixed)?;
            let data_len = u32::from_le_bytes(event_fixed[40..44].try_into().unwrap());
            // Skip event data: data_len * 8 bytes
            let mut event_data = vec![0u8; (data_len as usize) * 8];
            Read::read_exact(&mut cursor, &mut event_data)?;
        }

        // B. Read Variable Contract Blobs
        // 1. Single Tree Nodes (User Contract Tree)
        Read::read_exact(&mut cursor, &mut merkle_header)?;

        let single_header_parsed = QBlobSingleMerkleNodeBatchDataView::try_read_single_node_blob_header(&merkle_header)?;

        let single_blob_remaining = backup_cursor_remaining_bytes(&cursor)?;
        let single_blob_total_size = bound_declared_qblob_allocation(single_header_parsed.total_size, single_blob_remaining, "User contract tree node")?;
        let user_contract_tree_nodes_size = single_blob_total_size - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut user_contract_tree_nodes = vec![0u8; user_contract_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut user_contract_tree_nodes)?;

        // 2. Double Tree Nodes (Contract State Tree)
        Read::read_exact(&mut cursor, &mut merkle_header)?;

        let double_header_parsed = QBlobDoubleMerkleNodeBatchDataView::try_read_double_node_blob_header(&merkle_header)?;

        let double_blob_remaining = backup_cursor_remaining_bytes(&cursor)?;
        let double_blob_total_size = bound_declared_qblob_allocation(double_header_parsed.total_size, double_blob_remaining, "Contract state tree node")?;
        let contract_state_tree_nodes_size = double_blob_total_size - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut contract_state_tree_nodes = vec![0u8; contract_state_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut contract_state_tree_nodes)?;

        // 3. IMT leaf QBlob, mandatory third segment
        Read::read_exact(&mut cursor, &mut merkle_header)?;
        let imt_stream_header =
            QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(&merkle_header).context("End cap backup is missing the mandatory IMT leaf QBlob header")?;
        let imt_blob_remaining = backup_cursor_remaining_bytes(&cursor)?;
        let imt_blob_size = bound_declared_qblob_allocation(imt_stream_header.total_size, imt_blob_remaining, "IMT leaf")?;
        if imt_blob_size < QBLOB_TREE_NODE_BATCH_HEADER_SIZE {
            anyhow::bail!("IMT leaf QBlob declared total_size {} is smaller than the header size", imt_blob_size);
        }
        let mut imt_blob = vec![0u8; imt_blob_size];
        imt_blob[..QBLOB_TREE_NODE_BATCH_HEADER_SIZE].copy_from_slice(&merkle_header);
        Read::read_exact(&mut cursor, &mut imt_blob[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])
            .context("Failed to read the mandatory IMT leaf QBlob payload")?;
        let (_imt_blob_header, imt_leaves) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree(
            imt_blob,
            QBlobDataType::GenericIMTLeafBatch,
            QBlobMerkleNodeTreeType::IMTContractStateLeaf,
            true,
        )?;
        update_contract_state_imt_leaves_ffs.extend_from_slice(&imt_leaves);
        user_leaf_node.pio_write_to_io(&mut update_user_leaves_ffs)?;
        update_user_contract_tree_nodes_ffs.extend_from_slice(&user_contract_tree_nodes);
        update_contract_state_tree_nodes_ffs.extend_from_slice(&contract_state_tree_nodes);

        if insert_old_leaves {
            tree.set_leaf(user_id - min_user_id, old_user_leaf_hash);
        } else {
            tree.set_leaf(user_id - min_user_id, new_user_leaf_hash);
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

    let footer_start = cursor.position() as usize;
    if footer_start + GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE > cursor.get_ref().len() {
        anyhow::bail!(
            "Realm backup file {} is missing GUTA footer: footer_start={}, remaining_len={}",
            file_path,
            footer_start,
            cursor.get_ref().len()
        );
    }
    let mut header_bytes = vec![0u8; GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE];
    Read::read_exact(&mut cursor, &mut header_bytes)?;
    let guta_header = read_guta_header_with_job_id_from_backup_bytes::<F, Hash>(&header_bytes)?;

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
        update_contract_state_imt_leaves_ffs,
        total_proofs_generated: 0,
        total_users_updated: actual_end_caps_processed as u64,
        guta_header,
    })
}

fn backup_cursor_remaining_bytes(cursor: &Cursor<Vec<u8>>) -> anyhow::Result<usize> {
    let position = usize::try_from(cursor.position())
        .map_err(|_| anyhow::anyhow!("Backup cursor position {} exceeds usize range", cursor.position()))?;
    cursor
        .get_ref()
        .len()
        .checked_sub(position)
        .ok_or_else(|| anyhow::anyhow!("Backup cursor position {} exceeds buffer length {}", position, cursor.get_ref().len()))
}

fn bound_declared_qblob_allocation(declared_total_size: u64, remaining_bytes: usize, segment: &str) -> anyhow::Result<usize> {
    let declared_size = usize::try_from(declared_total_size)
        .map_err(|_| anyhow::anyhow!("{} QBlob declared total_size {} exceeds usize range", segment, declared_total_size))?;
    if declared_size > remaining_bytes {
        anyhow::bail!(
            "{} QBlob header declared total_size {} bytes but only {} bytes remain in the backup payload",
            segment,
            declared_total_size,
            remaining_bytes
        );
    }
    Ok(declared_size)
}

fn write_guta_header_with_job_id_backup_bytes<F: QFelt64, Hash: Q256BitHash>(
    guta_header: &GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE);
    bytes.extend_from_slice(&guta_header.header.guta_circuit_whitelist.into_owned_32bytes());
    bytes.extend_from_slice(&guta_header.header.checkpoint_tree_root.into_owned_32bytes());
    bytes.extend_from_slice(&guta_header.header.state_transition.old_node_value.into_owned_32bytes());
    bytes.extend_from_slice(&guta_header.header.state_transition.new_node_value.into_owned_32bytes());
    bytes.extend_from_slice(&guta_header.header.state_transition.node_index.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.state_transition.node_level.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.stats.guta_fees_collected.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.stats.da_fees_collected.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.stats.user_ops_processed.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.stats.total_transactions.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.stats.slots_modified.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.header.total_aggregation_proofs_generated.to_u64_value().to_le_bytes());
    bytes.extend_from_slice(&guta_header.job_id.to_fixed_bytes());
    debug_assert_eq!(bytes.len(), GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE);
    Ok(bytes)
}

fn read_guta_header_with_job_id_from_backup_bytes<F: QFelt64, Hash: Q256BitHash>(
    bytes: &[u8],
) -> anyhow::Result<GlobalUserTreeAggregatorHeaderWithJobId<F, Hash>> {
    if bytes.len() != GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE {
        anyhow::bail!(
            "invalid GUTA header footer size: expected {}, got {}",
            GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE,
            bytes.len()
        );
    }

    let read_hash = |offset: usize| -> Hash { Hash::from_owned_32bytes(bytes[offset..offset + 32].try_into().unwrap()) };
    let read_felt = |offset: usize| -> F { F::from_u64_value(u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())) };

    let job_id_start = GlobalUserTreeAggregatorHeader::<F, Hash>::FIXED_SIZE;
    let job_id = QProvingJobDataID::from_bytes_fixed(&bytes[job_id_start..job_id_start + 24].try_into().unwrap())?;

    Ok(GlobalUserTreeAggregatorHeaderWithJobId {
        header: GlobalUserTreeAggregatorHeader {
            guta_circuit_whitelist: read_hash(0),
            checkpoint_tree_root: read_hash(32),
            state_transition: SubTreeNodeStateTransition {
                old_node_value: read_hash(64),
                new_node_value: read_hash(96),
                node_index: read_felt(128),
                node_level: read_felt(136),
            },
            stats: GUTAStats {
                guta_fees_collected: read_felt(144),
                da_fees_collected: read_felt(152),
                user_ops_processed: read_felt(160),
                total_transactions: read_felt(168),
                slots_modified: read_felt(176),
            },
            total_aggregation_proofs_generated: read_felt(184),
        },
        job_id,
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
    /// IMT leaf preimage data for indexed merkle tree contract state updates.
    pub update_contract_state_imt_leaves_ffs: Vec<u8>,
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
            update_contract_state_imt_leaves_ffs: vec![],
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
        let initial_total_end_caps_processed = self.guta_planner.total_end_caps_processed;


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
            let total_end_caps_processed = self.guta_planner.total_end_caps_processed;
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
                self.config
                    .file_system
                    .file_like_fs_sync_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
                    .await?;

                tracing::info!(
                    "GUTA updates gatherer for pending id {} finalized with changes.",
                    self.status.gathering_unique_pending_id
                );
                tree.commit_changes();
                return Ok(result);
            }
        }

        let total_end_caps_processed = initial_total_end_caps_processed;
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
        self.config
            .file_system
            .file_like_fs_sync_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
            .await?;
        Ok(RealmGUTAEndCapGathererOutput {
            db_output: RealmGUTAEndCapGathererOutputDatabase::<N::F, N::QHash>::get_empty(tree.get_root()),
            job_ids: vec![],
        })
    }
}

#[cfg(test)]
mod backup_file_tests {
    use std::fs;
    use std::path::Path;

    use psy_core::job::job_id::QProvingJobDataID;
    use psy_node_core::qblob::{
        structs::common::tree_node_batch_header::{QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE},
        traits::common::QBlobStructHeaderBase,
    };

    const REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31_45_47_52;
    const HEADER_SIZE: usize = 4 + 32 + 32 + 8;
    const FOOTER_SIZE: usize = 216;
    const JOB_ID_SIZE: usize = 24;
    const EXPECTED_CHECKPOINT_SIZE: usize = 8;
    const HASH_SIZE: usize = 32;
    const USER_LEAF_SIZE: usize = 104;
    const GUTA_STATS_SIZE: usize = 40;
    const EVENTS_LEN_SIZE: usize = 4;
    const QUEUE_ITEM_FIXED_PREFIX_SIZE: usize =
        JOB_ID_SIZE + EXPECTED_CHECKPOINT_SIZE + HASH_SIZE + HASH_SIZE + USER_LEAF_SIZE + GUTA_STATS_SIZE + EVENTS_LEN_SIZE;
    const END_CAP_EVENT_FIXED_FIELDS_SIZE: usize = 8 * 5 + 4;

    #[test]
    fn test_all_local_end_cap_backup_files() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap();
        let base_dirs = [
            workspace_root.join("local_checkpoints/realm_0_1/guta_updates_backup"),
            workspace_root.join("local_checkpoints/realm_1_1/guta_updates_backup"),
        ];

        let mut total_files = 0usize;
        let mut ok_files = 0usize;
        let mut bad_files = Vec::new();

        for dir in &base_dirs {
            let path = Path::new(dir);
            if !path.exists() {
                continue;
            }
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                let file_path = entry.path();
                if !file_path.extension().map(|e| e == "backup").unwrap_or(false) {
                    continue;
                }
                total_files += 1;
                match verify_backup_file(&file_path) {
                    Ok(()) => ok_files += 1,
                    Err(e) => {
                        eprintln!("BAD: {} -> {}", file_path.display(), e);
                        bad_files.push((file_path.display().to_string(), e.to_string()));
                    }
                }
            }
        }

        println!("Total: {}, OK: {}, Bad: {}", total_files, ok_files, bad_files.len());
        if !bad_files.is_empty() {
            panic!("{} backup files failed verification. See stderr for details.", bad_files.len());
        }
    }

    fn verify_backup_file(path: &Path) -> anyhow::Result<()> {
        let data = fs::read(path)?;
        let file_len = data.len();

        if file_len < HEADER_SIZE {
            anyhow::bail!("file too small: {} bytes (minimum {})", file_len, HEADER_SIZE);
        }

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if magic != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 {
            anyhow::bail!("bad magic: expected {:x}, got {:x}", REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32, magic);
        }

        let expected_end_caps = u64::from_le_bytes(data[68..76].try_into().unwrap());

        if file_len == HEADER_SIZE && expected_end_caps == 0 {
            // Header-only files are in-progress gatherer files that have not finalized yet.
            return Ok(());
        }

        let mut offset = 0usize;
        let body = &data[HEADER_SIZE..];

        for actual_end_caps in 0..expected_end_caps as usize {
            let queue_item_size = parse_queue_item_size(body, offset).map_err(|e| {
                anyhow::anyhow!(
                    "queue_item #{} parse failed at body offset {}: {}",
                    actual_end_caps,
                    offset,
                    e
                )
            })?;
            offset += queue_item_size;

            offset += parse_qblob_total_size(body, offset)
                .map_err(|e| anyhow::anyhow!("user blob parse failed for queue_item #{}: {}", actual_end_caps, e))?;
            offset += parse_qblob_total_size(body, offset)
                .map_err(|e| anyhow::anyhow!("state blob parse failed for queue_item #{}: {}", actual_end_caps, e))?;

            offset += parse_qblob_total_size(body, offset)
                .map_err(|e| anyhow::anyhow!("IMT blob parse failed for queue_item #{}: {}", actual_end_caps, e))?;
        }

        if HEADER_SIZE + offset + FOOTER_SIZE > file_len {
            anyhow::bail!(
                "file too small for footer after {} end-cap records: file_len={}, footer_offset={}",
                expected_end_caps,
                file_len,
                HEADER_SIZE + offset
            );
        }
        verify_footer(&data[HEADER_SIZE + offset..HEADER_SIZE + offset + FOOTER_SIZE])?;

        Ok(())
    }

    fn verify_footer(footer: &[u8]) -> anyhow::Result<()> {
        if footer.len() != FOOTER_SIZE {
            anyhow::bail!("invalid footer size: expected {}, got {}", FOOTER_SIZE, footer.len());
        }

        let job_id_start = FOOTER_SIZE - JOB_ID_SIZE;
        QProvingJobDataID::try_from_byte_vec(&footer[job_id_start..])?;
        Ok(())
    }

    fn parse_queue_item_size(data: &[u8], offset: usize) -> anyhow::Result<usize> {
        if offset + QUEUE_ITEM_FIXED_PREFIX_SIZE > data.len() {
            anyhow::bail!(
                "truncated queue item prefix: need {} bytes, have {}",
                QUEUE_ITEM_FIXED_PREFIX_SIZE,
                data.len().saturating_sub(offset)
            );
        }

        let events_len_offset = offset + QUEUE_ITEM_FIXED_PREFIX_SIZE - EVENTS_LEN_SIZE;
        let events_len = read_u32_le(data, events_len_offset)? as usize;
        let mut cursor = offset + QUEUE_ITEM_FIXED_PREFIX_SIZE;

        for _ in 0..events_len {
            if cursor + END_CAP_EVENT_FIXED_FIELDS_SIZE > data.len() {
                anyhow::bail!("truncated event header at offset {}", cursor);
            }

            let event_data_len = read_u32_le(data, cursor + 8 * 5)? as usize;
            cursor += END_CAP_EVENT_FIXED_FIELDS_SIZE;
            let event_data_size = event_data_len
                .checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("event data length overflow: {}", event_data_len))?;
            if cursor + event_data_size > data.len() {
                anyhow::bail!("truncated event data at offset {}", cursor);
            }
            cursor += event_data_size;
        }

        Ok(cursor - offset)
    }

    fn parse_qblob_total_size(data: &[u8], offset: usize) -> anyhow::Result<usize> {
        if offset + QBLOB_TREE_NODE_BATCH_HEADER_SIZE > data.len() {
            anyhow::bail!("truncated qblob header at offset {}", offset);
        }

        let header = QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(&data[offset..offset + QBLOB_TREE_NODE_BATCH_HEADER_SIZE])?;
        let total_size = header.total_size as usize;
        if total_size < QBLOB_TREE_NODE_BATCH_HEADER_SIZE {
            anyhow::bail!("invalid qblob total_size {} at offset {}", total_size, offset);
        }
        if offset + total_size > data.len() {
            anyhow::bail!("truncated qblob payload at offset {}: total_size {}", offset, total_size);
        }

        Ok(total_size)
    }

    fn read_u32_le(data: &[u8], offset: usize) -> anyhow::Result<u32> {
        let bytes = data
            .get(offset..offset + 4)
            .ok_or_else(|| anyhow::anyhow!("failed to read u32 at offset {}", offset))?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    mod reader_tests {
        use anyhow::Context as _;
        use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
        use parth_core::{
            crypto::hash::traits::ZeroableHash,
            felt::{QFelt64, ToU64Value, ZeroableFelt},
            pgoldilocks::PoseidonHasher,
            protocol::core_types::Q256BitHash,
            QJobIdBase, PHash, PF,
        };
        use psy_core::job::job_id::QProvingJobDataID;
        use psy_data::{
            guta::{header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithJobId, stats::GUTAStats, sub_tree_transition::SubTreeNodeStateTransition},
            v1::qdata::user::PQEDUserLeaf,
        };
        use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
        use psy_serialize::PsyIOReadWrite;

        use super::super::{
            read_realm_end_cap_gatherer_backup_file, write_guta_header_with_job_id_backup_bytes, QBlobDataType, QBlobMerkleNodeTreeType,
            QBlobMerkleTreeNodeBatchHeaderV1, QBLOB_TREE_NODE_BATCH_HEADER_SIZE, RealmGUTAEndCapGathererOutputDatabase,
            REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32,
        };
        use super::{GUTA_STATS_SIZE, HASH_SIZE, JOB_ID_SIZE};

        type ReaderHasher = PoseidonHasher;
        type ReaderHash = PHash;
        type ReaderF = PF;
        const READER_REALM_GLOBAL_USER_TREE_HEIGHT: u8 = 4;
        const READER_COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = 32;

        async fn read_backup_with_records(records: &[Vec<u8>]) -> anyhow::Result<RealmGUTAEndCapGathererOutputDatabase<ReaderF, ReaderHash>> {
            let file_system = SimpleMockMemoryFileSystem::new();
            let path = "realm_end_cap_reader_test.backup";
            let mut tree = SimpleMemoryMerkleRecorderStore::<ReaderHasher, ReaderHash>::new(READER_REALM_GLOBAL_USER_TREE_HEIGHT);
            let start_root = tree.get_root();
            let mut data = Vec::new();
            data.extend_from_slice(&REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
            data.extend_from_slice(&start_root.into_owned_32bytes());
            data.extend_from_slice(&start_root.into_owned_32bytes());
            data.extend_from_slice(&(records.len() as u64).to_le_bytes());
            for record in records {
                data.extend_from_slice(record);
            }
            let guta_header = GlobalUserTreeAggregatorHeaderWithJobId::<ReaderF, ReaderHash> {
                job_id: QProvingJobDataID::new_invalid_job_id(),
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: ReaderHash::get_zero_value(),
                    checkpoint_tree_root: ReaderHash::get_zero_value(),
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: ReaderHash::get_zero_value(),
                        new_node_value: ReaderHash::get_zero_value(),
                        node_index: ReaderF::ZERO_VALUE,
                        node_level: ReaderF::ZERO_VALUE,
                    },
                    stats: GUTAStats::<ReaderF>::get_zero_value(),
                    total_aggregation_proofs_generated: ReaderF::ZERO_VALUE,
                },
            };
            data.extend_from_slice(&write_guta_header_with_job_id_backup_bytes::<ReaderF, ReaderHash>(&guta_header)?);
            file_system.files.insert(path.to_string(), data);

            read_realm_end_cap_gatherer_backup_file::<ReaderHasher, ReaderHash, ReaderF, SimpleMockMemoryFileSystem>(
                &file_system,
                path,
                &mut tree,
                0,
                READER_REALM_GLOBAL_USER_TREE_HEIGHT,
                READER_COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                false,
            )
            .await
        }

        fn end_cap_record(imt_blob: Option<Vec<u8>>) -> anyhow::Result<Vec<u8>> {
            let mut record = Vec::new();
            record.extend_from_slice(&[0u8; JOB_ID_SIZE]);
            record.extend_from_slice(&1u64.to_le_bytes());
            record.extend_from_slice(&[3u8; HASH_SIZE]);
            record.extend_from_slice(&[4u8; HASH_SIZE]);
            PQEDUserLeaf::<ReaderF, ReaderHash>::new_user_default(
                ReaderF::from_owned_u64(5),
                ReaderHash::from_owned_32bytes([7u8; 32]),
                ReaderHash::get_zero_value(),
            )
            .pio_write_to_io(&mut record)?;
            record.extend_from_slice(&[0u8; GUTA_STATS_SIZE]);
            record.extend_from_slice(&0u32.to_le_bytes());
            record.extend_from_slice(&node_blob(32u32, QBlobDataType::GenericSingleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractTree)?);
            record.extend_from_slice(&node_blob(57u32, QBlobDataType::GenericDoubleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::UserContractStateTree)?);
            if let Some(imt_blob) = imt_blob {
                record.extend_from_slice(&imt_blob);
            }
            Ok(record)
        }
        fn node_blob(item_size: u32, blob_type: QBlobDataType, tree_type: QBlobMerkleNodeTreeType) -> anyhow::Result<Vec<u8>> {
            let mut header = match blob_type {
                QBlobDataType::GenericSingleIdMerkleNodeBatch => QBlobMerkleTreeNodeBatchHeaderV1::new_single_id_header(tree_type, 0, 0, 0, 0, 1, 5),
                QBlobDataType::GenericDoubleIdMerkleNodeBatch => QBlobMerkleTreeNodeBatchHeaderV1::new_double_id_header(tree_type, 0, 0, 0, 0, 1, 5),
                QBlobDataType::GenericIMTLeafBatch => QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(tree_type, 0, 0, 0, 0, 1, 5),
                _ => anyhow::bail!("unsupported blob type"),
            };
            header.modify_for_final_count_and_size(item_size, 1);
            let mut blob = header.to_bytes_fixed_size_array().to_vec();
            blob.resize(header.total_size as usize, 0xAB);
            Ok(blob)
        }

        fn imt_blob(item_size: u32, item_count: u64, tree_type: QBlobMerkleNodeTreeType) -> anyhow::Result<Vec<u8>> {
            let mut header = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(tree_type, 0, 0, 0, 0, 1, 5);
            header.modify_for_final_count_and_size(item_size, item_count);
            let mut blob = header.to_bytes_fixed_size_array().to_vec();
            blob.resize(header.total_size as usize, 0xAB);
            Ok(blob)
        }

        fn empty_imt_blob() -> anyhow::Result<Vec<u8>> {
            imt_blob(161, 0, QBlobMerkleNodeTreeType::IMTContractStateLeaf)
        }

        #[tokio::test]
        async fn reader_parses_end_cap_with_empty_imt_segment_as_empty_ffs() -> anyhow::Result<()> {
            let output = read_backup_with_records(&[end_cap_record(Some(empty_imt_blob()?))?]).await?;
            assert_eq!(output.total_users_updated, 1);
            assert!(output.update_contract_state_imt_leaves_ffs.is_empty());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_end_cap_missing_imt_segment() -> anyhow::Result<()> {
            assert!(read_backup_with_records(&[end_cap_record(None)?]).await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_imt_segment_with_wrong_blob_type() -> anyhow::Result<()> {
            let record = end_cap_record(Some(node_blob(57u32, QBlobDataType::GenericDoubleIdMerkleNodeBatch, QBlobMerkleNodeTreeType::IMTContractStateLeaf)?))?;
            assert!(read_backup_with_records(&[record]).await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_imt_segment_with_wrong_tree_type() -> anyhow::Result<()> {
            let record = end_cap_record(Some(imt_blob(161, 1, QBlobMerkleNodeTreeType::UserContractStateTree)?))?;
            assert!(read_backup_with_records(&[record]).await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_imt_segment_with_non_multiple_payload() -> anyhow::Result<()> {
            let record = end_cap_record(Some(imt_blob(160, 1, QBlobMerkleNodeTreeType::IMTContractStateLeaf)?))?;
            assert!(read_backup_with_records(&[record]).await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_undersized_imt_segment() -> anyhow::Result<()> {
            let mut header = QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(QBlobMerkleNodeTreeType::IMTContractStateLeaf, 0, 0, 0, 0, 1, 5);
            header.modify_for_final_count_and_size(161, 0);
            header.total_size = QBLOB_TREE_NODE_BATCH_HEADER_SIZE as u64 - 1;
            let blob = header.to_bytes_fixed_size_array().to_vec();
            let record = end_cap_record(Some(blob))?;
            assert!(read_backup_with_records(&[record]).await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_imt_segment_declaring_size_beyond_remaining_bytes() -> anyhow::Result<()> {
            let mut header =
                QBlobMerkleTreeNodeBatchHeaderV1::new_imt_leaf_header(QBlobMerkleNodeTreeType::IMTContractStateLeaf, 0, 0, 0, 0, 1, 5);
            header.total_size = 1_000_000;
            let blob = header.to_bytes_fixed_size_array().to_vec();
            let record = end_cap_record(Some(blob))?;
            let err = match read_backup_with_records(&[record]).await {
                Ok(_) => anyhow::bail!("Reader accepted an IMT header declaring 1_000_000 bytes with far fewer remaining"),
                Err(e) => e,
            };
            let message = format!("{err:#}");
            assert!(
                message.contains("declared total_size 1000000") && message.contains("bytes remain"),
                "Allocation bound error not surfaced, got: {message}"
            );
            Ok(())
        }

        #[tokio::test]
        async fn reader_rejects_truncated_imt_segment() -> anyhow::Result<()> {
            let mut record = end_cap_record(Some(imt_blob(161, 0, QBlobMerkleNodeTreeType::IMTContractStateLeaf)?))?;
            record.truncate(record.len() - 1);
            assert!(read_backup_with_records(&[record]).await.is_err());
            Ok(())
        }
    }
}
