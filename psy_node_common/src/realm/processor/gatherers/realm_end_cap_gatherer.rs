use std::{
    io::{Cursor, Read},
    path::PathBuf,
    sync::{Arc, Mutex, RwLock},
};

use anyhow::Context as _;
use async_trait::async_trait;
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm,
};
use parth_core::{
    crypto::hash::{merkle_proof::MerkleProofCore, traits::{FieldQHasher, HashTo4Felts, QFieldHashable, MerkleZeroHasher, ZeroableHash}},
    data::hash::{
        fast_node_serializer::{QMerkleStoreFastZeroNodeSerializer, QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE},
        merkle_node_key::SimpleMerkleNodeKey,
    },
    felt::{QFelt64, ToU64Value, ZeroableFelt},
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId, QJobIdBase,
};

use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    guta::{
        header::GlobalUserTreeAggregatorHeader,
        header_extended::{GlobalUserTreeAggregatorHeaderWithJobId, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID},
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    },
    node::realm_processor::RealmProcessorCoreState,
    prepared_block::realm::PsyPreparedRealmBlockStateUpdates,
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::{ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF, user::PQEDUserLeaf},
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    p2p::validator_lookup::load_realm_validators_from_tree,
    psy_core_db::traits::full::{
        PsyNodeCheckpointRealmSpecificDatabaseReader, PsyNodeGlobalUserTreeDatabaseReader, PsyRealmProcessorStore,
    },
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
    guta_planner::realm_guta_planner::{PlannedFutureEndCapJob, RealmGUTAPlanner, RealmGUTAValidatorProofs},
    queue::gatherer_builder::QueueGathererItemBuilderWithTree,
};
pub const REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x52, 0x47, 0x45, 0x31]; // 'RGE1' in ASCII
pub const REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31_45_47_52; // 'RGE1' in little-endian u32
// RGE2 adds a pre-footer effect: tag 0 for empty batches, or tag 1 + pre/post-fee user leaves.
pub const REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32: u32 = 0x32_45_47_52;


/// Typed failure raised when a realm end-cap backup's declared start global
/// user tree root does not match `tree.get_root()`. The check runs
/// before any tree mutation, so the backup is left completely unapplied and
/// recovery can rebuild a certified start tree and replay the same candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealmBackupStartRootMismatch<Hash> {
    pub backup_start_root: Hash,
    pub tree_root: Hash,
}

impl<Hash: std::fmt::Debug> std::fmt::Display for RealmBackupStartRootMismatch<Hash> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Realm proposal backup start global user tree root {:?} does not match tree root {:?}",
            self.backup_start_root, self.tree_root
        )
    }
}

impl<Hash: std::fmt::Debug> std::error::Error for RealmBackupStartRootMismatch<Hash> {}

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

/// Discovery hint only; replay and checkpoint/proposal binding must authenticate the root before commit.
pub async fn read_realm_backup_end_root<FileSystem: TokioLikeFileSystem, Hash: QDBHashBase>(
    file_system: &FileSystem,
    path: &str,
) -> anyhow::Result<Hash> {
    const END_ROOT_HEADER_LEN: usize = 4 + 32 + 32;
    let mut file = file_system.file_like_fs_open(path).await?;
    let metadata = file.file_like_metadata().await?;
    anyhow::ensure!(
        metadata.len() >= END_ROOT_HEADER_LEN as u64,
        "Realm backup header is too small to contain an end root: {} bytes",
        metadata.len()
    );
    let mut header = [0u8; END_ROOT_HEADER_LEN];
    file.read_exact(&mut header).await?;
    let magic = u32::from_le_bytes(header[..4].try_into().expect("4-byte magic"));
    anyhow::ensure!(
        magic == REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 || magic == REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32,
        "Realm backup magic mismatch: expected RGE1 or RGE2, got {:x}",
        magic
    );
    Ok(Hash::from_owned_32bytes(header[36..68].try_into().expect("end root")))
}


pub fn read_realm_end_cap_gatherer_backup_bytes<
    Hasher: FieldQHasher<F, Hash>,
    Hash: QDBHashBase + QFHashBase<F>,
    F: QFelt64,
>(
    backup: &[u8],
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    realm_id_u64: u64,
    realm_global_user_tree_height: u8,
    coordinator_global_user_tree_height: u8,
    insert_old_leaves: bool,
) -> anyhow::Result<RealmGUTAEndCapGathererOutputDatabase<F, Hash>> {
    let snapshot = tree.snapshot();
    let result = apply_realm_end_cap_gatherer_backup_bytes::<Hasher, Hash, F>(
        backup, tree, realm_id_u64, realm_global_user_tree_height, coordinator_global_user_tree_height,
    );
    if result.is_err() || insert_old_leaves {
        // Old-leaf reads validate forward replay, then restore the prebatch tree and prior changes.
        tree.revert_to(snapshot);
    }
    result.map(|mut output| {
        if insert_old_leaves {
            output.update_global_user_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map_with_offset::<Hash>(
                tree.get_changes(),
                SimpleMerkleNodeKey { level: coordinator_global_user_tree_height, index: realm_id_u64 },
            );
        }
        output
    })
}

fn apply_realm_end_cap_gatherer_backup_bytes<
    Hasher: FieldQHasher<F, Hash>,
    Hash: QDBHashBase + QFHashBase<F>,
    F: QFelt64,
>(
    backup: &[u8],
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    realm_id_u64: u64,
    realm_global_user_tree_height: u8,
    coordinator_global_user_tree_height: u8,
) -> anyhow::Result<RealmGUTAEndCapGathererOutputDatabase<F, Hash>> {
    const HEADER_LEN: usize = 4 + 32 + 32 + 8;
    anyhow::ensure!(
        backup.len() >= HEADER_LEN,
        "Realm proposal backup is too small to be valid: {} bytes",
        backup.len()
    );
    let magic_u32 = u32::from_le_bytes(backup[0..4].try_into().expect("4-byte magic"));
    anyhow::ensure!(
        magic_u32 == REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 || magic_u32 == REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32,
        "Realm proposal backup magic mismatch: expected RGE1 or RGE2, got {:x}",
        magic_u32
    );
    let start_global_user_tree_root = Hash::from_owned_32bytes(backup[4..36].try_into().expect("start root"));
    let current_tree_root = tree.get_root();
    if start_global_user_tree_root != current_tree_root {
        return Err(anyhow::Error::new(RealmBackupStartRootMismatch::<Hash> {
            backup_start_root: start_global_user_tree_root,
            tree_root: current_tree_root,
        }));
    }
    let expected_end_global_user_tree_root = Hash::from_owned_32bytes(backup[36..68].try_into().expect("end root"));
    let expected_end_caps_processed = u64::from_le_bytes(backup[68..76].try_into().expect("end-cap count"));
    let mut cursor = Cursor::new(&backup[HEADER_LEN..]);
    let mut actual_end_caps_processed = 0usize;
    let mut update_user_leaves_ffs = Vec::new();
    let mut update_user_contract_tree_nodes_ffs = Vec::new();
    let mut update_contract_state_tree_nodes_ffs = Vec::new();
    let mut update_contract_state_imt_leaves_ffs = Vec::new();
    let mut user_leaf_offsets = std::collections::HashMap::new();
    let mut da_fees_collected = 0u64;
    anyhow::ensure!(realm_global_user_tree_height < 64 && tree.get_height() == realm_global_user_tree_height,
        "Realm backup tree height mismatch");
    let realm_size = 1u64 << realm_global_user_tree_height;
    let min_user_id = realm_id_u64.checked_mul(realm_size).context("Realm backup user range overflow")?;
    let max_user_id = min_user_id.checked_add(realm_size - 1).context("Realm backup user range overflow")?;
    let mut merkle_header = [0u8; QBLOB_TREE_NODE_BATCH_HEADER_SIZE];

    for _ in 0..expected_end_caps_processed {
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
                "User ID {} in end cap gatherer backup is out of realm {} bounds ({} - {})",
                user_id,
                realm_id_u64,
                min_user_id,
                max_user_id
            ));
        }
        let mut stats_bytes = [0u8; 40];
        Read::read_exact(&mut cursor, &mut stats_bytes)?;
        let stats = GUTAStats::<F>::psy_ser_from_slice(&stats_bytes)?;
        da_fees_collected = da_fees_collected.checked_add(stats.da_fees_collected.to_u64_value())
            .context("Realm backup DA fee total overflow")?;
        let mut events_len_bytes = [0u8; 4];
        Read::read_exact(&mut cursor, &mut events_len_bytes)?;
        let events_len = usize::try_from(u32::from_le_bytes(events_len_bytes))?;
        for _ in 0..events_len {
            let mut event_fixed = [0u8; 44];
            Read::read_exact(&mut cursor, &mut event_fixed)?;
            let data_len = usize::try_from(u32::from_le_bytes(event_fixed[40..44].try_into().unwrap()))?;
            let event_data_size = data_len
                .checked_mul(8)
                .ok_or_else(|| anyhow::anyhow!("End cap event data length {} overflows usize", data_len))?;
            check_backup_segment_size(event_data_size, remaining_backup_bytes(&cursor)?, "End cap event data")?;
            let mut event_data = vec![0u8; event_data_size];
            Read::read_exact(&mut cursor, &mut event_data)?;
        }
        Read::read_exact(&mut cursor, &mut merkle_header)?;
        let single_header_parsed = QBlobSingleMerkleNodeBatchDataView::try_read_single_node_blob_header(&merkle_header)?;
        let single_blob_total_size = check_qblob_size(
            single_header_parsed.total_size,
            remaining_backup_bytes(&cursor)?,
            "User contract tree node",
        )?;
        let user_contract_tree_nodes_size = single_blob_total_size - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut user_contract_tree_nodes = vec![0u8; user_contract_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut user_contract_tree_nodes)?;

        Read::read_exact(&mut cursor, &mut merkle_header)?;
        let double_header_parsed = QBlobDoubleMerkleNodeBatchDataView::try_read_double_node_blob_header(&merkle_header)?;
        let double_blob_total_size = check_qblob_size(
            double_header_parsed.total_size,
            remaining_backup_bytes(&cursor)?,
            "Contract state tree node",
        )?;
        let contract_state_tree_nodes_size = double_blob_total_size - QBLOB_TREE_NODE_BATCH_HEADER_SIZE;
        let mut contract_state_tree_nodes = vec![0u8; contract_state_tree_nodes_size];
        Read::read_exact(&mut cursor, &mut contract_state_tree_nodes)?;

        Read::read_exact(&mut cursor, &mut merkle_header)
            .context("End cap backup is missing the mandatory IMT leaf QBlob header")?;
        let imt_header = QBlobMerkleTreeNodeBatchHeaderV1::try_read_header_from_slice(&merkle_header)
            .context("End cap backup has an invalid mandatory IMT leaf QBlob header")?;
        let imt_blob_size = check_qblob_size(
            imt_header.total_size,
            remaining_backup_bytes(&cursor)?,
            "IMT leaf",
        )?;
        let mut imt_blob = vec![0u8; imt_blob_size];
        imt_blob[..QBLOB_TREE_NODE_BATCH_HEADER_SIZE].copy_from_slice(&merkle_header);
        Read::read_exact(&mut cursor, &mut imt_blob[QBLOB_TREE_NODE_BATCH_HEADER_SIZE..])
            .context("Failed to read the mandatory IMT leaf QBlob payload")?;
        let (_, imt_leaves) = QBlobMerkleTreeNodeBatchHeaderV1::clip_header_get_payload_for_blob_type_and_tree(
            imt_blob,
            QBlobDataType::GenericIMTLeafBatch,
            QBlobMerkleNodeTreeType::IMTContractStateLeaf,
            true,
        )?;
        update_contract_state_imt_leaves_ffs.extend_from_slice(&imt_leaves);
        anyhow::ensure!(tree.get_leaf_value(user_id - min_user_id) == old_user_leaf_hash,
            "Realm backup EndCap old leaf mismatch for user {}", user_id);
        anyhow::ensure!(user_leaf_node.qfhash::<Hasher>() == new_user_leaf_hash,
            "Realm backup EndCap new leaf preimage mismatch for user {}", user_id);
        write_realm_backup_user_leaf(&mut update_user_leaves_ffs, &mut user_leaf_offsets, &user_leaf_node)?;
        update_user_contract_tree_nodes_ffs.extend_from_slice(&user_contract_tree_nodes);
        update_contract_state_tree_nodes_ffs.extend_from_slice(&contract_state_tree_nodes);
        tree.set_leaf(user_id - min_user_id, new_user_leaf_hash);
        actual_end_caps_processed += 1;
    }
    if actual_end_caps_processed != expected_end_caps_processed as usize {
        anyhow::bail!(
            "Realm proposal backup corruption: expected {} end caps, but recovered {}",
            expected_end_caps_processed,
            actual_end_caps_processed
        );
    }
    let finalizer_effect = if magic_u32 == REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32 {
        let mut tag = [0u8; 1];
        Read::read_exact(&mut cursor, &mut tag).context("Realm backup missing finalizer effect")?;
        match tag[0] {
            0 => None,
            1 => Some((PQEDUserLeaf::<F, Hash>::pio_read_from_io(&mut cursor)?, PQEDUserLeaf::<F, Hash>::pio_read_from_io(&mut cursor)?)),
            tag => anyhow::bail!("Realm backup invalid finalizer effect tag {}", tag),
        }
    } else {
        None
    };
    let footer_size = GlobalUserTreeAggregatorHeaderWithJobId::<F, Hash>::FIXED_SIZE;
    let remaining_backup_bytes = remaining_backup_bytes(&cursor)?;
    anyhow::ensure!(
        remaining_backup_bytes == footer_size,
        "Realm proposal backup footer size mismatch: expected {}, got {}",
        footer_size,
        remaining_backup_bytes
    );
    let mut header_bytes = vec![0u8; footer_size];
    Read::read_exact(&mut cursor, &mut header_bytes)?;
    let guta_header = read_guta_header_with_job_id_from_backup_bytes::<F, Hash>(&header_bytes)?;
    let is_finalizer = guta_header.job_id.circuit_type == ProvingJobCircuitType::RealmFinalizeGUTA;
    anyhow::ensure!(magic_u32 != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 || !is_finalizer,
        "RGE1 finalizer backup is missing the validator fee effect; cannot recover safely");
    anyhow::ensure!(guta_header.header.stats.da_fees_collected.to_u64_value() == da_fees_collected,
        "Realm backup DA fee total does not match GUTA footer");
    if let Some((old_leaf, new_leaf)) = finalizer_effect {
        anyhow::ensure!(is_finalizer && actual_end_caps_processed > 0,
            "Realm backup finalizer effect requires a nonempty circuit-63 batch");
        anyhow::ensure!(guta_header.job_id == QProvingJobDataID::realm_finalize_guta(guta_header.job_id.goal_id, u32::try_from(realm_id_u64)?),
            "Realm backup finalizer job identity mismatch");
        let user_id = old_leaf.user_id.to_u64_value();
        anyhow::ensure!(user_id >= min_user_id && user_id <= max_user_id, "Realm backup finalizer user outside realm");
        anyhow::ensure!(tree.get_leaf_value(user_id - min_user_id) == old_leaf.qfhash::<Hasher>(),
            "Realm backup finalizer old leaf preimage mismatch");
        let balance = old_leaf.balance.to_u64_value().checked_add(da_fees_collected)
            .filter(|balance| *balance < (1u64 << 60)).context("Realm backup finalizer balance overflow")?;
        let mut expected_leaf = old_leaf;
        expected_leaf.balance = F::from_u64_value(balance);
        if da_fees_collected != 0 {
            expected_leaf.last_checkpoint_id = F::from_u64_value(guta_header.job_id.goal_id);
        }
        anyhow::ensure!(new_leaf == expected_leaf, "Realm backup finalizer fee leaf mismatch");
        tree.set_leaf(user_id - min_user_id, new_leaf.qfhash::<Hasher>());
        write_realm_backup_user_leaf(&mut update_user_leaves_ffs, &mut user_leaf_offsets, &new_leaf)?;
    } else if magic_u32 == REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32 {
        anyhow::ensure!(actual_end_caps_processed == 0 && !is_finalizer, "Realm backup missing finalizer effect for nonempty batch");
    }
    anyhow::ensure!(tree.get_root() == expected_end_global_user_tree_root,
        "Realm backup reconstructed end root does not match advertised end root");
    if actual_end_caps_processed == 0 {
        anyhow::ensure!(guta_header.job_id == QProvingJobDataID::new_invalid_job_id()
            && guta_header.header.state_transition.old_node_value == Hash::get_zero_value()
            && guta_header.header.state_transition.new_node_value == Hash::get_zero_value(),
            "Realm backup empty batch has a nonempty GUTA footer");
    } else {
        anyhow::ensure!(guta_header.header.state_transition.old_node_value == start_global_user_tree_root
            && guta_header.header.state_transition.new_node_value == tree.get_root()
            && guta_header.header.state_transition.node_index.to_u64_value() == realm_id_u64
            && guta_header.header.state_transition.node_level.to_u64_value() == coordinator_global_user_tree_height as u64,
            "Realm backup GUTA footer transition mismatch");
    }
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

async fn write_realm_backup_header<File: TokioFileLike, Hash: Q256BitHash>(file: &mut File, start_root: Hash) -> anyhow::Result<()> {
    file.file_like_set_len(0).await?;
    file.seek(tokio::io::SeekFrom::Start(0)).await?;
    file.write_u32_le(REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32).await?;
    file.write_all(&start_root.into_owned_32bytes()).await?;
    file.write_all(&start_root.into_owned_32bytes()).await?;
    file.write_u64_le(0).await?;
    Ok(())
}

fn write_realm_backup_user_leaf<F: QFelt64, Hash: QDBHashBase + QFHashBase<F>>(
    bytes: &mut Vec<u8>,
    offsets: &mut std::collections::HashMap<u64, usize>,
    leaf: &PQEDUserLeaf<F, Hash>,
) -> anyhow::Result<()> {
    let serialized = leaf.psy_ser_to_bytes_vec()?;
    anyhow::ensure!(serialized.len() == PSY_OBJECT_FFS_SIZE_USER_LEAF, "Realm backup user leaf FFS size mismatch");
    let offset = *offsets.entry(leaf.user_id.to_u64_value()).or_insert(bytes.len());
    if offset == bytes.len() {
        bytes.extend_from_slice(&serialized);
    } else {
        bytes[offset..offset + PSY_OBJECT_FFS_SIZE_USER_LEAF].copy_from_slice(&serialized);
    }
    Ok(())
}

fn remaining_backup_bytes(cursor: &Cursor<&[u8]>) -> anyhow::Result<usize> {
    let position = usize::try_from(cursor.position())
        .map_err(|_| anyhow::anyhow!("Backup position {} exceeds usize range", cursor.position()))?;
    cursor
        .get_ref()
        .len()
        .checked_sub(position)
        .ok_or_else(|| anyhow::anyhow!("Backup position {} exceeds buffer length {}", position, cursor.get_ref().len()))
}

fn check_backup_segment_size(segment_size: usize, remaining_backup_bytes: usize, segment: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        segment_size <= remaining_backup_bytes,
        "{} declared {} bytes but only {} bytes remain in the backup",
        segment,
        segment_size,
        remaining_backup_bytes
    );
    Ok(())
}

fn check_qblob_size(declared_total_size: u64, remaining_payload_bytes: usize, segment: &str) -> anyhow::Result<usize> {
    let qblob_size = usize::try_from(declared_total_size)
        .map_err(|_| anyhow::anyhow!("{} QBlob size {} exceeds usize range", segment, declared_total_size))?;
    anyhow::ensure!(
        qblob_size >= QBLOB_TREE_NODE_BATCH_HEADER_SIZE,
        "{} QBlob size {} is smaller than header size {}",
        segment,
        qblob_size,
        QBLOB_TREE_NODE_BATCH_HEADER_SIZE
    );
    let remaining_qblob_bytes = remaining_payload_bytes
        .checked_add(QBLOB_TREE_NODE_BATCH_HEADER_SIZE)
        .ok_or_else(|| anyhow::anyhow!("{} QBlob remaining byte count overflows", segment))?;
    check_backup_segment_size(qblob_size, remaining_qblob_bytes, segment)?;
    Ok(qblob_size)
}


pub async fn read_realm_end_cap_gatherer_backup_file<
    Hasher: FieldQHasher<F, Hash>,
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
    let file_len_u64 = file.file_like_metadata().await?.len();
    let file_len = usize::try_from(file_len_u64)
        .map_err(|_| anyhow::anyhow!("Realm backup file length {} exceeds usize range", file_len_u64))?;
    let mut backup = Vec::new();
    backup.try_reserve_exact(file_len)?;
    backup.resize(file_len, 0);
    file.read_exact(&mut backup).await?;
    read_realm_end_cap_gatherer_backup_bytes(
        &backup,
        tree,
        realm_id_u64,
        realm_global_user_tree_height,
        coordinator_global_user_tree_height,
        insert_old_leaves,
    )
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
    /// Process-lifetime shared validator account leaf: the single authority
    /// for the validator's balance/nonce across builder recreates. Fed by
    /// EndCaps, finalize fee credits and follower FFS user-leaf preimages;
    /// never read back from the DB gathering checkpoint.
    pub current_validator_user_leaf: Arc<Mutex<PQEDUserLeaf<N::F, N::QHash>>>,
    pub tree_store: Arc<dyn PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync>,
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
            current_validator_user_leaf: self.current_validator_user_leaf.clone(),
            tree_store: self.tree_store.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}

/// Checkpoint-bound validator: the authenticated validator-tree preimage, its
/// membership proof, and the checkpoint state roots at the gathering checkpoint.
pub(crate) async fn load_checkpoint_validator<N, S>(
    tree_store: &S,
    status: &RealmProcessorCoreState<N::QHash>,
    checkpoint_id: u64,
) -> anyhow::Result<(
    psy_data::p2p::ValidatorLeafPreimage,
    MerkleProofCore<N::QHash>,
    psy_data::v1::qdata::checkpoint::PQEDCheckpointGlobalStateRoots<N::QHash>,
)>
where
    N: QNetworkTypesConfig,
    S: PsyRealmProcessorStore<N::F, N::QHash> + Send + Sync + ?Sized,
{
    let realm_id = status.realm_identifier.realm_id as u32;
    let realm_sub_id = status.realm_identifier.realm_sub_id;
    let validator_index = psy_data::guta::realm_finalize::validator_tree_index(realm_id, realm_sub_id);
    let preimage = tree_store.validator_tree_get_leaf_preimage(checkpoint_id, validator_index).await?
        .ok_or_else(|| anyhow::anyhow!("no persisted validator-tree preimage at checkpoint {} index {}", checkpoint_id, validator_index))?;
    anyhow::ensure!(preimage.chain_id == status.chain_id,
        "Validator preimage chain {} does not match local chain {}",
        preimage.chain_id, status.chain_id);
    anyhow::ensure!(preimage.realm_id == realm_id && preimage.realm_sub_id == realm_sub_id,
        "Validator preimage realm {} sub {} does not match local realm {} sub {}",
        preimage.realm_id, preimage.realm_sub_id, realm_id, realm_sub_id);
    let roots = tree_store.get_checkpoint_global_state_roots(checkpoint_id).await?;
    let validator_tree_proof = tree_store.validator_tree_get_merkle_proof(checkpoint_id, validator_index).await?;
    anyhow::ensure!(validator_tree_proof.root == roots.validator_tree_root
        && validator_tree_proof.verify::<N::HasherBase>(),
        "Validator-tree proof does not match the checkpoint validator-tree root");
    psy_data::p2p::authenticate_validator_preimage(&preimage, &validator_tree_proof.value)?;
    Ok((preimage, validator_tree_proof, roots))
}


impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>
{
    pub(crate) async fn load_realm_guta_validator_proofs(
        &self,
        status: &RealmProcessorCoreState<N::QHash>,
        checkpoint_id: u64,
    ) -> anyhow::Result<RealmGUTAValidatorProofs<N::F, N::QHash>> {
        anyhow::ensure!(psy_config::CHECKPOINTS_PER_EPOCH > 0, "Realm finalization requires rotation");
        let checkpoint_root = self.tree_store.checkpoint_tree_get_root_hash(checkpoint_id).await?;
        let target = checkpoint_id.checked_add(1).ok_or_else(|| anyhow::anyhow!("Checkpoint overflow"))?;
        let epoch = parth_common::realm_rotation::epoch(target, psy_config::CHECKPOINTS_PER_EPOCH);
        let anchor_id = parth_common::realm_rotation::anchor_checkpoint_id(epoch, psy_config::CHECKPOINTS_PER_EPOCH);
        let (preimage, validator_tree_proof, roots) =
            load_checkpoint_validator::<N, _>(self.tree_store.as_ref(), status, checkpoint_id).await?;
        let user_id = preimage.validator_user_id;
        let min_user_id = self.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let max_user_id = (self.realm_id_u64 + 1) << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        anyhow::ensure!(user_id >= min_user_id && user_id < max_user_id, "Validator user is outside its realm");
        let leaf = self.tree_store.get_user_leaf(checkpoint_id, user_id).await?;
        // No wallet key material: BLS authorization stays with the processor's
        // own P2P key; the identity is public validator-tree/leaf evidence only.
        let checkpoint_leaf = self.tree_store.get_checkpoint_leaf_data(checkpoint_id).await?;
        let checkpoint_tree_proof = self.tree_store.checkpoint_tree_get_merkle_proof(checkpoint_id, checkpoint_id).await?;
        let anchor_checkpoint_leaf = self.tree_store.get_checkpoint_leaf_data(anchor_id).await?;
        let anchor_checkpoint_tree_proof = self.tree_store.checkpoint_tree_get_merkle_proof(checkpoint_id, anchor_id).await?;
        let (validator_user_tree_proof, old_realm_root_proof) = validator_user_tree_proofs::<N, _>(
            self.tree_store.as_ref(), checkpoint_id, user_id, self.realm_id_u64).await?;
        anyhow::ensure!(checkpoint_tree_proof.root == checkpoint_root
            && checkpoint_tree_proof.value == checkpoint_leaf.qfhash::<N::HasherBase>()
            && checkpoint_tree_proof.verify::<N::HasherBase>()
            && anchor_checkpoint_tree_proof.root == checkpoint_root
            && anchor_checkpoint_tree_proof.value == anchor_checkpoint_leaf.qfhash::<N::HasherBase>()
            && anchor_checkpoint_tree_proof.verify::<N::HasherBase>(), "Checkpoint proofs do not match proof base");
        anyhow::ensure!(validator_user_tree_proof.root == roots.user_tree_root,
            "Validator user proof root {:?} does not match stored user tree root {:?}",
            validator_user_tree_proof.root, roots.user_tree_root);
        anyhow::ensure!(validator_user_tree_proof.value == leaf.qfhash::<N::HasherBase>(),
            "Validator user proof value {:?} does not match validator leaf hash",
            validator_user_tree_proof.value);
        anyhow::ensure!(validator_user_tree_proof.verify::<N::HasherBase>(),
            "Validator user proof fails verification");
        anyhow::ensure!(old_realm_root_proof.root == roots.user_tree_root,
            "Realm root proof root {:?} does not match stored user tree root {:?}",
            old_realm_root_proof.root, roots.user_tree_root);
        anyhow::ensure!(old_realm_root_proof.value == status.gathering_realm_start_root,
            "Realm root proof value {:?} does not match gathering_realm_start_root {:?}",
            old_realm_root_proof.value, status.gathering_realm_start_root);
        anyhow::ensure!(old_realm_root_proof.verify::<N::HasherBase>(),
            "Realm root proof fails verification");
        Ok(RealmGUTAValidatorProofs {
            validator: preimage,
            validator_user_leaf: leaf,
            anchor_checkpoint_leaf,
            anchor_checkpoint_tree_proof,
            checkpoint_leaf: psy_data::v1::qdata::checkpoint::PQEDCheckpointLeafCompactWithStateRoots {
                checkpoint_leaf: checkpoint_leaf.to_compact::<N::HasherBase>(), global_state_roots: roots,
            },
            checkpoint_tree_proof,
            old_realm_root_proof,
            validator_tree_proof,
            validator_user_tree_proof,
        })
    }
}

pub(crate) async fn validator_user_tree_proofs<N, S>(
    store: &S,
    checkpoint_id: u64,
    user_id: u64,
    realm_id: u64,
) -> anyhow::Result<(MerkleProofCore<N::QHash>, MerkleProofCore<N::QHash>)>
where
    N: parth_core::protocol::core_types::QNetworkDatabaseTypes,
    S: PsyNodeCheckpointRealmSpecificDatabaseReader<N::F, N::QHash>
        + PsyNodeGlobalUserTreeDatabaseReader<N::QHash>
        + Send
        + Sync
        + ?Sized,
{
    let top = store.get_top_global_user_tree_proof_to_realm_root_at_checkpoint_id(checkpoint_id).await?;
    anyhow::ensure!(N::GLOBAL_USER_TREE_HEIGHT as usize == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as usize + N::REALM_GLOBAL_USER_TREE_HEIGHT as usize
        && top.siblings.len() == N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT as usize
        && top.index == realm_id
        && user_id.checked_shr(N::REALM_GLOBAL_USER_TREE_HEIGHT as u32) == Some(realm_id),
        "Validator user proof has an invalid realm boundary at checkpoint {}", checkpoint_id);
    let mut bottom = store.global_user_tree_get_merkle_proof_sub_tree(
        checkpoint_id, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, N::GLOBAL_USER_TREE_HEIGHT, user_id).await?;
    anyhow::ensure!(bottom.siblings.len() == N::REALM_GLOBAL_USER_TREE_HEIGHT as usize
        && bottom.index == user_id && bottom.root == top.value,
        "Finalizer local realm root does not match stored top proof at checkpoint {}", checkpoint_id);
    // Merkle siblings run from leaf to root; stop local reads at the realm boundary.
    bottom.siblings.extend_from_slice(&top.siblings);
    bottom.root = top.root;
    anyhow::ensure!(top.verify::<N::HasherBase>() && bottom.verify::<N::HasherBase>(),
        "Finalizer composed user proof is invalid at checkpoint {}", checkpoint_id);
    Ok((bottom, top))
}

fn apply_state_updates_to_tree<Hasher, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    old_root: Hash,
    new_root: Hash,
    gut_ffs: &[u8],
    coordinator_global_user_tree_height: u8,
    realm_id: u64,
) -> anyhow::Result<()>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash,
{
    if tree.get_last_commit_root() == new_root {
        return Ok(());
    }

    tree.revert_changes();
    anyhow::ensure!(
        tree.get_last_commit_root() == old_root,
        "gatherer FastForward committed root {:?} is not old_root {:?}",
        tree.get_last_commit_root(),
        old_root
    );
    apply_zero_id_ffs_nodes(tree, gut_ffs, coordinator_global_user_tree_height, realm_id)?;
    if tree.get_root() != new_root {
        tree.revert_changes();
        anyhow::bail!(
            "gatherer FastForward root {:?} is not new_root {:?}",
            tree.get_root(),
            new_root
        );
    }
    tree.commit_changes();
    anyhow::ensure!(
        tree.get_last_commit_root() == new_root,
        "gatherer FastForward committed root {:?} is not new_root {:?}",
        tree.get_last_commit_root(),
        new_root
    );
    Ok(())
}


fn apply_zero_id_ffs_nodes<Hasher, Hash>(
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    ffs: &[u8],
    coordinator_global_user_tree_height: u8,
    realm_id: u64,
) -> anyhow::Result<()>
where
    Hasher: MerkleZeroHasher<Hash>,
    Hash: Copy + PartialEq + Default + std::fmt::Debug + Q256BitHash,
{
    if ffs.is_empty() {
        return Ok(());
    }
    anyhow::ensure!(
        ffs.len() % QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE == 0,
        "global user tree FFS length {} is not a multiple of {}",
        ffs.len(),
        QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE
    );
    let nodes = QMerkleStoreFastZeroNodeSerializer::deserialize_zero_id_nodes_from_slice::<Hash>(ffs);
    for node in nodes {
        let local_key = realm_local_key_from_offset_ffs_key(
            node.key,
            coordinator_global_user_tree_height,
            realm_id,
        )?;
        tree.set_node_value(local_key, node.value);
    }
    Ok(())
}

fn realm_local_key_from_offset_ffs_key(
    key: SimpleMerkleNodeKey,
    coordinator_height: u8,
    realm_id: u64,
) -> anyhow::Result<SimpleMerkleNodeKey> {
    anyhow::ensure!(
        key.level >= coordinator_height,
        "global user tree FFS node level {} is below coordinator height {}",
        key.level,
        coordinator_height
    );
    let local_level = key.level - coordinator_height;
    let expected_realm_id = if local_level >= 64 {
        anyhow::ensure!(
            key.index == 0,
            "global user tree FFS node index {} does not fit in local level {}",
            key.index,
            local_level
        );
        0
    } else {
        key.index >> local_level
    };
    anyhow::ensure!(
        expected_realm_id == realm_id,
        "global user tree FFS node realm_id {} does not match {}",
        expected_realm_id,
        realm_id
    );
    let local_index = if local_level == 0 {
        0
    } else if local_level >= 64 {
        key.index
    } else {
        key.index & ((1u64 << local_level) - 1)
    };
    Ok(SimpleMerkleNodeKey {
        level: local_level,
        index: local_index,
    })
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
    gathering_start_validator_user_leaf: PQEDUserLeaf<N::F, N::QHash>,
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    Drop for RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>
{
    /// Return checkpoint-ahead EndCaps to the shared list whenever a builder is dropped.
    fn drop(&mut self) {
        let pending = std::mem::take(&mut self.guta_planner.future_pending_end_cap_jobs);
        if pending.is_empty() {
            return;
        }
        match self.config.future_pending_end_cap_jobs.write() {
            Ok(mut slot) => slot.extend(pending),
            Err(_) => tracing::error!(
                "Failed to restore {} future pending end cap jobs on gatherer drop for pending id {}",
                pending.len(),
                self.status.gathering_unique_pending_id
            ),
        }
    }
}

impl<
        FileSystem: TokioLikeFileSystem + 'static,
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    > RealmGUTAEndCapGatherer<N, TempDatabase, FileSystem>
{
    /// Replays the cycle's accepted EndCaps on a newer same-epoch gathering checkpoint that authenticates
    /// the cycle start; returns false when no such proof base exists.
    async fn recreate_planner_on_proof_base(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        authenticated: &RealmProcessorCoreState<N::QHash>,
    ) -> anyhow::Result<bool> {
        let planner_checkpoint_id = self.guta_planner.current_checkpoint_id;
        let proof_base_id = authenticated.gathering_checkpoint_id;
        let target_epoch = |base: u64| base.checked_add(1)
            .map(|target| parth_common::realm_rotation::epoch(target, psy_config::CHECKPOINTS_PER_EPOCH));
        if proof_base_id <= planner_checkpoint_id || target_epoch(proof_base_id) != target_epoch(planner_checkpoint_id) {
            return Ok(false);
        }
        let validator_user_id = self.gathering_start_validator_user_leaf.user_id.to_u64_value();
        let (_, realm_root_proof) = validator_user_tree_proofs::<N, _>(
            self.config.tree_store.as_ref(), proof_base_id, validator_user_id, self.config.realm_id_u64).await?;
        if realm_root_proof.value != self.start_global_user_tree_root {
            return Ok(false);
        }
        tree.revert_changes();
        anyhow::ensure!(tree.get_root() == self.start_global_user_tree_root,
            "gatherer committed root {:?} is not cycle start {:?}", tree.get_root(), self.start_global_user_tree_root);
        let mut planner = RealmGUTAPlanner::<N::F, N::QHash>::new(
            authenticated.chain_id,
            authenticated.realm_identifier,
            authenticated.gathering_checkpoint_root,
            proof_base_id,
            self.status.gathering_unique_pending_id,
            self.start_global_user_tree_root,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_USER_TREE_HEIGHT,
            self.config.coordinator_guta_updates_circuit_whitelist,
        );
        planner.current_validator_user_leaf = Some(self.gathering_start_validator_user_leaf.clone());
        let mut previous_planner = std::mem::replace(&mut self.guta_planner, planner);
        // Deferred EndCaps belong to the live planner first so a failed replay returns them on drop.
        self.guta_planner.future_pending_end_cap_jobs = std::mem::take(&mut previous_planner.future_pending_end_cap_jobs);
        let mut accepted_end_cap_jobs = previous_planner.accepted_end_cap_jobs;
        anyhow::ensure!(self.total_users_updated as usize <= accepted_end_cap_jobs.len(),
            "cycle accepted {} EndCaps but restored {} at creation", accepted_end_cap_jobs.len(), self.total_users_updated);
        let intake_end_cap_jobs = accepted_end_cap_jobs.split_off(self.total_users_updated as usize);
        write_realm_backup_header(&mut self.new_realm_end_cap_gatherer_file, self.start_global_user_tree_root).await?;
        let file = &mut self.new_realm_end_cap_gatherer_file;
        let mut end_cap_count = self.guta_planner.add_future_end_cap_jobs(
            &self.config.checkpoint_tree, tree, file, self.config.temp_db.clone(), accepted_end_cap_jobs).await?;
        for accepted_end_cap_job in intake_end_cap_jobs {
            end_cap_count += self.guta_planner.add_accepted_end_cap_job(
                &self.config.checkpoint_tree, tree, file, self.config.temp_db.clone(), accepted_end_cap_job).await?;
        }
        anyhow::ensure!(end_cap_count == previous_planner.total_end_caps_processed,
            "proof base {} replayed {} of {} accepted EndCaps", proof_base_id, end_cap_count, previous_planner.total_end_caps_processed);
        let deferred_end_cap_jobs = std::mem::take(&mut self.guta_planner.future_pending_end_cap_jobs);
        self.guta_planner.add_future_end_cap_jobs(
            &self.config.checkpoint_tree, tree, file, self.config.temp_db.clone(), deferred_end_cap_jobs).await?;
        self.config.file_system.file_like_fs_flush_file_with_path(&self.pending_file_path, file).await?;
        tracing::info!(
            "Moved EndCap generation for pending id {} from proof base {} to {} with {} accepted EndCaps",
            self.status.gathering_unique_pending_id, planner_checkpoint_id, proof_base_id, end_cap_count
        );
        Ok(true)
    }
}


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
        FileSystem: TokioLikeFileSystem + 'static,
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
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
        unique_id: QCoreProcCheckpointUniqueId,
        config: RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        Self::create_with_fast_forward(tree, unique_id, config, &[]).await
    }

    async fn create_with_fast_forward(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        _unique_id: QCoreProcCheckpointUniqueId,
        config: RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
        state_updates: &[u8],
    ) -> anyhow::Result<Self> {
        if !state_updates.is_empty() {
            Self::apply_fast_forward_with_tree(tree, &config, state_updates.to_vec()).await?;
        }
        let status = config.status.read()
            .map_err(|_| anyhow::anyhow!("error reading gathering snapshot"))?.clone();
        // The validator is checkpoint-bound: authenticated from the persisted
        // validator tree at the gathering checkpoint, never from Genesis.
        let (validator_preimage, _, _) = load_checkpoint_validator::<N, _>(
            config.tree_store.as_ref(), &status, status.gathering_checkpoint_id).await?;
        let user_id = validator_preimage.validator_user_id;
        let min_user_id = config.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        anyhow::ensure!(user_id >= min_user_id && user_id - min_user_id < (1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT),
            "validator user is outside realm");
        // The shared validator account leaf must hash to the current tree leaf.
        let current_leaf = config.current_validator_user_leaf.lock()
            .map_err(|_| anyhow::anyhow!("error reading current validator leaf"))?.clone();
        anyhow::ensure!(current_leaf.user_id.to_u64_value() == user_id, "current validator leaf belongs to another user");
        anyhow::ensure!(tree.get_leaf(user_id - min_user_id).value == current_leaf.qfhash::<N::HasherBase>(),
            "current validator leaf preimage does not match current tree");
        let current_tree_root = tree.get_root();
        anyhow::ensure!(current_tree_root == status.gathering_realm_start_root || current_tree_root == status.processing_realm_end_root,
            "current tree root {:?} matches neither gathering_realm_start_root {:?} nor processing_realm_end_root {:?}",
            current_tree_root, status.gathering_realm_start_root, status.processing_realm_end_root);
        let new_realm_end_cap_gatherer_file_path = get_new_realm_end_cap_gatherer_backup_file_path(
            &config.backup_file_directory, config.realm_id_u64, config.realm_sub_id_u64,
            status.gathering_unique_pending_id);
        let backup_path = new_realm_end_cap_gatherer_file_path.to_string_lossy().to_string();
        // file_like_fs_create does not truncate: leftover tail bytes from a
        // prior cycle at the same pending id are cut here.
        let mut new_realm_end_cap_gatherer_file = config.file_system.file_like_fs_create(&backup_path).await?;
        write_realm_backup_header(&mut new_realm_end_cap_gatherer_file, current_tree_root).await?;
        config
            .file_system
            .file_like_fs_flush_file_with_path(&backup_path, &mut new_realm_end_cap_gatherer_file)
            .await?;
        let mut guta_planner = RealmGUTAPlanner::<N::F, N::QHash>::new(
            status.chain_id,
            status.realm_identifier,
            status.gathering_checkpoint_root,
            status.gathering_checkpoint_id,
            status.gathering_unique_pending_id,
            current_tree_root,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_USER_TREE_HEIGHT,
            config.coordinator_guta_updates_circuit_whitelist,
        );
        guta_planner.current_validator_user_leaf = Some(current_leaf);
        let future_end_cap_jobs: Vec<PlannedFutureEndCapJob<N::F, N::QHash>> = {
            std::mem::take(&mut *config.future_pending_end_cap_jobs.write()
                .map_err(|_| anyhow::anyhow!("error writing to future pending end cap jobs"))?)
        };
        let restore_future_jobs = future_end_cap_jobs.clone();
        // Return checkpoint-ahead EndCaps if construction fails after taking the shared list.
        let (end_cap_jobs_added, gathering_start_validator_user_leaf) = match async {
            let gathering_start_validator_user_leaf = guta_planner.current_validator_user_leaf.clone()
                .context("missing current validator leaf")?;
            let end_cap_jobs_added = guta_planner
                .add_future_end_cap_jobs(&config.checkpoint_tree, tree, &mut new_realm_end_cap_gatherer_file,
                    config.temp_db.clone(), future_end_cap_jobs)
                .await?;
            config
                .file_system
                .file_like_fs_flush_file_with_path(&backup_path, &mut new_realm_end_cap_gatherer_file)
                .await?;
            anyhow::Ok((end_cap_jobs_added, gathering_start_validator_user_leaf))
        }
        .await
        {
            Ok(result) => result,
            Err(error) => {
                match config.future_pending_end_cap_jobs.write() {
                    Ok(mut pending) => pending.extend(restore_future_jobs),
                    Err(_) => {
                        return Err(anyhow::anyhow!("{error:#}; also failed to restore {} future pending end cap jobs after failed gatherer construction", restore_future_jobs.len()))
                    }
                }
                return Err(error);
            }
        };
        let last_committed_checkpoint_root = config.checkpoint_tree.get_root();
        Ok(Self {
            config,
            status,
            gathering_start_validator_user_leaf,
            guta_planner,
            last_committed_checkpoint_root,
            total_users_updated: end_cap_jobs_added as u64,
            new_realm_end_cap_gatherer_file,
            start_global_user_tree_root: current_tree_root,
            pending_file_path: backup_path,
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
        // EndCap overlay: the slot is only advanced when the tree leaf moved
        // in the same operation. A lone (straggler) EndCap stages the planner
        // leaf without touching the tree, so publishing it here would break
        let tree_leaf_value = self.guta_planner.current_validator_user_leaf.as_ref()
            .map(|leaf| tree.get_leaf(leaf.user_id.to_u64_value() - self.guta_planner.realm_user_min_id).value);
        if let (Some(tree_value), Some(leaf)) = (&tree_leaf_value, self.guta_planner.current_validator_user_leaf.as_ref()) {
            if leaf.qfhash::<N::HasherBase>() == *tree_value {
                *self.config.current_validator_user_leaf.lock()
                    .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? = leaf.clone();
            }
        }
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
            self.guta_planner.current_validator_user_leaf = Some(self.gathering_start_validator_user_leaf.clone());
            *self.config.current_validator_user_leaf.lock()
                .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? =
                self.gathering_start_validator_user_leaf.clone();
            {
                let mut shared = self
                    .config
                    .status
                    .write()
                    .map_err(|e| anyhow::anyhow!("error writing status {:?}", e))?;
                shared.should_revert_processing_changes = false;
            }
            let reverted_root = tree.get_root();
            tracing::info!(
                "Reverted GUTA updates gatherer for pending id {} to committed root {:?}",
                self.status.gathering_unique_pending_id,
                reverted_root
            );
            self.config.status.write()
                .map_err(|_| anyhow::anyhow!("error writing gathering start root"))?
                .gathering_realm_start_root = reverted_root;
            return Ok(RealmGUTAEndCapGathererOutput {
                db_output: RealmGUTAEndCapGathererOutputDatabase::<N::F, N::QHash>::get_empty(reverted_root),
                job_ids: vec![],
            });
        }

        let authenticated = self.config.status.read()
            .map_err(|_| anyhow::anyhow!("error reading finalization checkpoint"))?.clone();
        if authenticated.gathering_realm_start_root != self.start_global_user_tree_root {
            // Fail closed: an unauthenticated cycle must not return empty
            // success, which would discard owned accepted/deferred inputs
            // (consuming finalize + runner clears cycle_items). The original
            // cause reaches the processor through the halted owner.
            anyhow::bail!(
                "gathering snapshot root {:?} does not authenticate cycle start {:?}; \
                 owned accepted/deferred inputs are retained by the halted owner",
                authenticated.gathering_realm_start_root,
                self.start_global_user_tree_root
            );
        }
        let planner_checkpoint_id = self.guta_planner.current_checkpoint_id;
        let (_, planner_realm_root_proof) = validator_user_tree_proofs::<N, _>(
            self.config.tree_store.as_ref(),
            planner_checkpoint_id,
            self.gathering_start_validator_user_leaf.user_id.to_u64_value(),
            self.config.realm_id_u64,
        )
        .await?;
        if planner_realm_root_proof.value != self.start_global_user_tree_root
            && !self.recreate_planner_on_proof_base(tree, &authenticated).await?
        {
            tracing::warn!(
                "Discarding EndCap generation whose proof base {} does not authenticate cycle start {:?}",
                planner_checkpoint_id,
                self.start_global_user_tree_root
            );
            tree.revert_changes();
            self.guta_planner.current_validator_user_leaf = Some(self.gathering_start_validator_user_leaf.clone());
            *self.config.current_validator_user_leaf.lock()
                .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? =
                self.gathering_start_validator_user_leaf.clone();
            let reverted_root = tree.get_root();
            self.config.status.write()
                .map_err(|_| anyhow::anyhow!("error writing gathering start root"))?
                .gathering_realm_start_root = reverted_root;
            return Ok(RealmGUTAEndCapGathererOutput {
                db_output: RealmGUTAEndCapGathererOutputDatabase::<N::F, N::QHash>::get_empty(reverted_root),
                job_ids: vec![],
            });
        }
        let planner_checkpoint_id = self.guta_planner.current_checkpoint_id;
        let proof_checkpoint_root = self
            .config
            .tree_store
            .checkpoint_tree_get_root_hash(planner_checkpoint_id)
            .await?;
        let proofs = self
            .config
            .load_realm_guta_validator_proofs(&authenticated, planner_checkpoint_id)
            .await?;
        self.guta_planner.current_checkpoint_root = proof_checkpoint_root;
        self.guta_planner.set_validator_proofs(proofs)?;
        tracing::info!(
            "Committing GUTA updates gatherer changes for pending id {}, finalizing root {:?}",
            self.status.gathering_unique_pending_id,
            tree.get_root()
        );
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_realm_end_cap_gatherer_file)
            .await?;
        let total_end_caps_processed = self.guta_planner.total_end_caps_processed;
        let validator_leaf_before_fee = self.guta_planner.current_validator_user_leaf.clone()
            .context("missing validator leaf before finalizer backup effect")?;
        let result = self
            .guta_planner
            .finalize_with_reward_ids(&self.config.checkpoint_tree, tree, self.config.temp_db.clone(), 0, 0)
            .await
            .context("GUTA updates gatherer planner finalize failed")?;
        if let Some(result) = result {
            let validator_leaf_after_fee = self.guta_planner.current_validator_user_leaf.as_ref()
                .context("missing validator leaf after finalizer backup effect")?;
            let mut finalizer_effect = vec![1u8];
            validator_leaf_before_fee.pio_write_to_io(&mut finalizer_effect)?;
            validator_leaf_after_fee.pio_write_to_io(&mut finalizer_effect)?;
            self.new_realm_end_cap_gatherer_file.write_all(&finalizer_effect).await?;
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
            self.config.status.write()
                .map_err(|_| anyhow::anyhow!("error writing gathering start root"))?
                .gathering_realm_start_root = tree.get_root();
            *self.config.current_validator_user_leaf.lock()
                .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? =
                self.guta_planner.current_validator_user_leaf.clone()
                    .ok_or_else(|| anyhow::anyhow!("missing current validator leaf after finalize"))?;
            return Ok(result);
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
        self.new_realm_end_cap_gatherer_file.write_all(&[0u8]).await?;
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
        self.config.status.write()
            .map_err(|_| anyhow::anyhow!("error writing gathering start root"))?
            .gathering_realm_start_root = tree.get_root();
        *self.config.current_validator_user_leaf.lock()
            .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? =
            self.guta_planner.current_validator_user_leaf.clone()
                .ok_or_else(|| anyhow::anyhow!("missing current validator leaf after finalize"))?;
        Ok(RealmGUTAEndCapGathererOutput {
            db_output: RealmGUTAEndCapGathererOutputDatabase::<N::F, N::QHash>::get_empty(tree.get_root()),
            job_ids: vec![],
        })
    }

    async fn apply_fast_forward_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        config: &RealmGUTAEndCapGathererConfig<N, TempDatabase, FileSystem>,
        state_updates: Vec<u8>,
    ) -> anyhow::Result<()> {
        let updates = PsyPreparedRealmBlockStateUpdates::<N::QHash>::psy_ser_from_slice(&state_updates)?;
        anyhow::ensure!(updates.realm_id == config.realm_id_u64,
            "FFS belongs to another realm");
        anyhow::ensure!(updates.update_user_leaves_ffs.len() % PSY_OBJECT_FFS_SIZE_USER_LEAF == 0,
            "invalid FFS user leaf length");
        let status = config.status.read()
            .map_err(|_| anyhow::anyhow!("error reading gathering snapshot"))?.clone();
        let (preimage, _, _) = load_checkpoint_validator::<N, _>(
            config.tree_store.as_ref(), &status, status.gathering_checkpoint_id).await?;
        let user_id = preimage.validator_user_id;
        apply_state_updates_to_tree(
            tree,
            updates.old_realm_root,
            updates.new_realm_root,
            &updates.update_global_user_tree_nodes_ffs,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            config.realm_id_u64,
        )?;
        let min_user_id = config.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        // FFS validator leaves are last-wins. Without one, the retained account leaf
        // must still hash to the updated tree leaf.
        let mut ffs_validator_leaf: Option<PQEDUserLeaf<N::F, N::QHash>> = None;
        for bytes in updates.update_user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF) {
            let leaf = PQEDUserLeaf::<N::F, N::QHash>::psy_ser_from_slice(bytes)?;
            if leaf.user_id.to_u64_value() == user_id {
                ffs_validator_leaf = Some(leaf);
            }
        }
        if let Some(leaf) = ffs_validator_leaf {
            anyhow::ensure!(tree.get_leaf(user_id - min_user_id).value == leaf.qfhash::<N::HasherBase>(),
                "FFS validator preimage does not match updated tree");
            *config.current_validator_user_leaf.lock()
                .map_err(|_| anyhow::anyhow!("error writing current validator leaf"))? = leaf;
        } else {
            let current_leaf = config.current_validator_user_leaf.lock()
                .map_err(|_| anyhow::anyhow!("error reading current validator leaf"))?.clone();
            anyhow::ensure!(current_leaf.user_id.to_u64_value() == user_id, "FFS validator leaf belongs to another user");
            anyhow::ensure!(tree.get_leaf(user_id - min_user_id).value == current_leaf.qfhash::<N::HasherBase>(),
                "FFS validator preimage does not match updated tree");
        }
        tracing::info!(
            "Applied Realm gatherer FastForward old_root={:?} new_root={:?}",
            updates.old_realm_root,
            updates.new_realm_root
        );
        Ok(())
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
        if magic != REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32 && magic != super::REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32 {
            anyhow::bail!("bad magic: expected RGE1 or RGE2, got {:x}", magic);
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

        if magic == super::REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32 {
            let tag = *body.get(offset).ok_or_else(|| anyhow::anyhow!("missing finalizer effect"))?;
            offset += match tag {
                0 => 1,
                1 => 1 + 2 * USER_LEAF_SIZE,
                _ => anyhow::bail!("invalid finalizer effect tag {}", tag),
            };
        }
        if HEADER_SIZE + offset + FOOTER_SIZE != file_len {
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
        use parth_core::crypto::hash::traits::QFieldHashable;

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
            read_backup_with_declared_start_root(records, None).await
        }

        async fn read_backup_with_declared_start_root(
            records: &[Vec<u8>],
            declared_start_root_override: Option<ReaderHash>,
        ) -> anyhow::Result<RealmGUTAEndCapGathererOutputDatabase<ReaderF, ReaderHash>> {
            let file_system = SimpleMockMemoryFileSystem::new();
            let path = "realm_end_cap_reader_test.backup";
            let mut tree = SimpleMemoryMerkleRecorderStore::<ReaderHasher, ReaderHash>::new(READER_REALM_GLOBAL_USER_TREE_HEIGHT);
            let start_root = tree.get_root();
            let mut expected_tree = tree.clone();
            for record in records {
                expected_tree.set_leaf(5, ReaderHash::from_owned_32bytes(record[64..96].try_into().unwrap()));
            }
            let end_root = expected_tree.get_root();
            let declared_start_root = declared_start_root_override.unwrap_or(start_root);
            let mut data = Vec::new();
            data.extend_from_slice(&REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
            data.extend_from_slice(&declared_start_root.into_owned_32bytes());
            data.extend_from_slice(&end_root.into_owned_32bytes());
            data.extend_from_slice(&(records.len() as u64).to_le_bytes());
            for record in records {
                data.extend_from_slice(record);
            }
            let guta_header = GlobalUserTreeAggregatorHeaderWithJobId::<ReaderF, ReaderHash> {
                job_id: QProvingJobDataID::guta_single_end_cap_witness(1, 0, 0, 0),
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: ReaderHash::get_zero_value(),
                    checkpoint_tree_root: ReaderHash::get_zero_value(),
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: start_root,
                        new_node_value: end_root,
                        node_index: ReaderF::ZERO_VALUE,
                        node_level: ReaderF::from_owned_u64(READER_COORDINATOR_GLOBAL_USER_TREE_HEIGHT as u64),
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
            record.extend_from_slice(&ReaderHash::get_zero_value().into_owned_32bytes());
            let leaf = PQEDUserLeaf::<ReaderF, ReaderHash>::new_user_default(
                ReaderF::from_owned_u64(5),
                ReaderHash::from_owned_32bytes([7u8; 32]),
                ReaderHash::get_zero_value(),
            );
            record.extend_from_slice(&leaf.qfhash::<ReaderHasher>().into_owned_32bytes());
            leaf.pio_write_to_io(&mut record)?;
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
                message.contains("declared 1000000 bytes") && message.contains("bytes remain"),
                "Allocation bound error not surfaced, got: {message}"
            );
            Ok(())
        }


        #[tokio::test]
        async fn start_root_mismatch_is_typed_and_leaves_tree_unmutated() -> anyhow::Result<()> {
            use super::super::RealmBackupStartRootMismatch;

            let forged_start_root = ReaderHash::from_owned_32bytes([0x5Au8; 32]);
            let error = match read_backup_with_declared_start_root(&[end_cap_record(Some(empty_imt_blob()?))?], Some(forged_start_root)).await {
                Ok(_) => anyhow::bail!("a backup whose declared start root differs from the current tree root must be rejected"),
                Err(error) => error,
            };
            let mismatch = error
                .downcast_ref::<RealmBackupStartRootMismatch<ReaderHash>>()
                .expect("start-root rejection must be the typed error so recovery can extract the declared start root");
            assert_eq!(mismatch.backup_start_root, forged_start_root);
            assert_ne!(mismatch.tree_root, forged_start_root);
            Ok(())
        }

        #[tokio::test]
        async fn start_root_mismatch_check_fires_before_any_tree_mutation() -> anyhow::Result<()> {
            let mut tree = SimpleMemoryMerkleRecorderStore::<ReaderHasher, ReaderHash>::new(READER_REALM_GLOBAL_USER_TREE_HEIGHT);
            let forged_start_root = ReaderHash::from_owned_32bytes([0xA5u8; 32]);
            let mut data = Vec::new();
            data.extend_from_slice(&REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
            data.extend_from_slice(&forged_start_root.into_owned_32bytes());
            data.extend_from_slice(&tree.get_root().into_owned_32bytes());
            data.extend_from_slice(&1u64.to_le_bytes());
            data.extend_from_slice(&end_cap_record(Some(empty_imt_blob()?))?);
            let file_system = SimpleMockMemoryFileSystem::new();
            file_system.files.insert("realm_end_cap_mutation_test.backup".to_string(), data);

            assert!(read_realm_end_cap_gatherer_backup_file::<ReaderHasher, ReaderHash, ReaderF, SimpleMockMemoryFileSystem>(
                &file_system,
                "realm_end_cap_mutation_test.backup",
                &mut tree,
                0,
                READER_REALM_GLOBAL_USER_TREE_HEIGHT,
                READER_COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
                false,
            )
            .await
            .is_err());
            assert!(
                tree.get_changes().is_empty(),
                "the start-root check must fire before the backup mutates the journal, or a failed candidate poisons the next one"
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

#[cfg(test)]
mod history_overlap_tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        pgoldilocks::PoseidonHasher,
        protocol::core_types::Q256BitHash,
        PHash,
    };

    use super::apply_state_updates_to_tree;

    #[test]
    fn history_live_overlap_regression() {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(4);
        let start = tree.get_root();
        apply_state_updates_to_tree(&mut tree, start, start, &[], 32, 0).unwrap();
        assert_eq!(tree.get_last_commit_root(), start);
        apply_state_updates_to_tree(&mut tree, start, start, &[], 32, 0).unwrap();
        assert_eq!(tree.get_last_commit_root(), start);
        let other = PHash::from_owned_32bytes([0xAB; 32]);
        let error = apply_state_updates_to_tree(&mut tree, start, other, &[], 32, 0).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("new_root"),
            "{message}"
        );
        assert_eq!(tree.get_last_commit_root(), start);
    }
}

#[cfg(test)]
mod guta_header_backup_tests {
    use parth_core::{utils::QPGenRandom, PHash, PF};
    use psy_data::guta::header_extended::GlobalUserTreeAggregatorHeaderWithJobId;
    use psy_serialize::PsyCanonicalSerializeMetadata;

    use super::{
        read_guta_header_with_job_id_from_backup_bytes, write_guta_header_with_job_id_backup_bytes,
        RealmGUTAEndCapGathererOutputDatabase,
    };

    #[test]
    fn guta_header_backup_bytes_roundtrip() -> anyhow::Result<()> {
        let header = GlobalUserTreeAggregatorHeaderWithJobId::<PF, PHash>::qp_rand_gen();
        let bytes = write_guta_header_with_job_id_backup_bytes(&header)?;
        assert_eq!(bytes.len(), GlobalUserTreeAggregatorHeaderWithJobId::<PF, PHash>::FIXED_SIZE);

        let restored = read_guta_header_with_job_id_from_backup_bytes::<PF, PHash>(&bytes)?;
        // no PartialEq on the header: re-serializing the restored value must
        // reproduce the exact backup bytes
        let bytes_again = write_guta_header_with_job_id_backup_bytes(&restored)?;
        assert_eq!(bytes, bytes_again);
        Ok(())
    }

    #[test]
    fn guta_header_backup_rejects_wrong_length() {
        let too_short = vec![0u8; 10];
        assert!(read_guta_header_with_job_id_from_backup_bytes::<PF, PHash>(&too_short).is_err());
        let too_long = vec![0u8; GlobalUserTreeAggregatorHeaderWithJobId::<PF, PHash>::FIXED_SIZE + 1];
        assert!(read_guta_header_with_job_id_from_backup_bytes::<PF, PHash>(&too_long).is_err());
    }

    #[test]
    fn empty_end_cap_output_is_a_noop() {
        let realm_root = PHash::qp_rand_gen();
        let output = RealmGUTAEndCapGathererOutputDatabase::<PF, PHash>::get_empty(realm_root);
        assert!(output.is_noop());
        assert_eq!(output.old_realm_root, realm_root);
        assert_eq!(output.new_realm_root, realm_root);
        assert_eq!(output.total_users_updated, 0);
        assert_eq!(output.total_proofs_generated, 0);
        assert!(output.update_global_user_tree_nodes_ffs.is_empty());
        assert!(output.update_user_contract_tree_nodes_ffs.is_empty());
        assert!(output.update_contract_state_tree_nodes_ffs.is_empty());
        assert!(output.update_user_leaves_ffs.is_empty());
        assert!(output.update_contract_state_imt_leaves_ffs.is_empty());

        // any root change means the output is no longer a noop
        let mut changed = RealmGUTAEndCapGathererOutputDatabase::<PF, PHash>::get_empty(realm_root);
        changed.new_realm_root = PHash::qp_rand_gen();
        assert!(!changed.is_noop());
    }
}

#[cfg(test)]
pub(crate) mod gatherer_builder_tests {
    use std::sync::{Arc, RwLock};

    use parth_common::memory_stores::{
        mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm,
    };
    use parth_core::{
        crypto::hash::traits::QFieldHashable,
        felt::{FromPrimitiveValuesFelt, ToU64Value},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{Q256BitHash, QNetworkTreeConstants},
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::{
        guta::header_extended::GlobalUserTreeAggregatorHeaderWithJobId,
        node::realm_processor::RealmProcessorCoreState,
        v1::qdata::{ffs_sizes::PSY_OBJECT_FFS_SIZE_USER_LEAF, user::PQEDUserLeaf},
    };
    use psy_io::tokio::TokioLikeFileSystem;
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
    use psy_node_store_memory::temp_store::InMemoryTempStore;
    use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata};

    use crate::guta_planner::realm_guta_planner_tests::test_env::{RGPContractUpdate, RGPTestChainState};
    use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;
    use crate::test_common::TestNetworkConfig;

    use super::{
        get_new_realm_end_cap_gatherer_backup_file_path, read_realm_backup_end_root, read_realm_end_cap_gatherer_backup_file,
        RealmGUTAEndCapGatherer, RealmGUTAEndCapGathererConfig,
    };

    type N = TestNetworkConfig;
    type Hash = PHash;
    type RecTree = SimpleMemoryMerkleRecorderStore<PoseidonHasher, PHash>;

    pub(crate) struct GatherFixture {
        pub(crate) file_system: Arc<SimpleMockMemoryFileSystem>,
        pub(crate) backup_path: String,
        pub(crate) realm_id_u64: u64,
        pub(crate) user_a: u64,
        pub(crate) user_b: u64,
        pub(crate) old_hash_a: Hash,
        pub(crate) old_hash_b: Hash,
        pub(crate) root_job_id: QProvingJobDataID,
        pub(crate) old_realm_root: Hash,
        pub(crate) new_realm_root: Hash,
        pub(crate) prebatch_tree: RecTree,
        pub(crate) validator_leaf_before: PQEDUserLeaf<PF, Hash>,
        pub(crate) validator_leaf_after: PQEDUserLeaf<PF, Hash>,
        pub(crate) da_fees_collected: u64,
        pub(crate) update_user_leaves_ffs: Vec<u8>,
        pub(crate) update_global_user_tree_nodes_ffs: Vec<u8>,
        pub(crate) chain_state: RGPTestChainState,
    }

    /// Runs the full RealmGUTAEndCapGatherer lifecycle (create -> two queue
    /// items -> finalize) over the in-memory realm planner test env and returns
    /// everything needed to inspect the committed backup file.
    pub(crate) async fn gather_two_user_backup() -> anyhow::Result<GatherFixture> {
        let mut chain_state = RGPTestChainState::create_for_tests().await?;
        let user_a = chain_state.register_new_random_user().await?;
        let user_b = chain_state.register_new_random_user().await?;
        chain_state.add_new_contract(12).await?;
        chain_state.unique_pending_id += 1;
        let updates = || {
            vec![RGPContractUpdate {
                contract_id: 0,
                leaves: vec![(0, Hash::qp_rand_gen()), (1, Hash::qp_rand_gen())],
            }]
        };
        let item_a = chain_state.run_ups_for_user(user_a, &updates()).await?;
        let item_b = chain_state.run_ups_for_user(user_b, &updates()).await?;

        let mut realm_tree = chain_state.first_realm_global_user_tree.clone();
        realm_tree.commit_changes();
        let prebatch_tree = realm_tree.clone();
        use psy_node_core::psy_core_db::traits::full::{
            PsyNodeCoreDatabaseUserStoreWriter, PsyNodeGlobalUserTreeDatabaseWriter,
            PsyNodeValidatorTreeDatabaseWriter, PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointTreeDatabaseWriter,
        };
        use parth_core::crypto::hash::traits::QFieldHashable;
        let db = &chain_state.db;
        let validator = &chain_state.finalizer_user;
        db.set_user_leaf(0, &validator.user_leaf).await?;
        db.global_user_tree_set_leaf_hash(0, validator.user_id, validator.user_leaf.qfhash::<PoseidonHasher>()).await?;
        db.global_user_tree_set_top_tree_merkle_proof(0, &chain_state.coordinator_global_user_tree.get_e_leaf(chain_state.realm_id_u64)).await?;
        let validator_index = (chain_state.realm_id_u64 << 8) | chain_state.realm_sub_id_u64;
        let validator_hash = psy_data::guta::realm_finalize::realm_validator_leaf_hash::<PF, Hash, PoseidonHasher>(
            validator.user_id, chain_state.validator_node_limbs, chain_state.validator_bls_limbs,
        );
        db.validator_tree_set_leaf_hash(0, validator_index, validator_hash).await?;
        db.validator_tree_set_leaf_preimage(0, validator_index, &chain_state.validator_preimage).await?;
        db.set_checkpoint_global_state_roots(0, &chain_state.finalizer_state_roots).await?;
        db.set_checkpoint_leaf_data(0, &chain_state.finalizer_checkpoint_leaf).await?;
        db.checkpoint_tree_set_leaf_hash(0, chain_state.finalizer_checkpoint_leaf.qfhash::<PoseidonHasher>()).await?;
        let file_system = Arc::new(SimpleMockMemoryFileSystem::new());
        let status = Arc::new(RwLock::new(RealmProcessorCoreState::new_basic(
            chain_state.chain_id,
            chain_state.realm_identifier,
            chain_state.checkpoint_id,
            chain_state.unique_pending_id,
            chain_state.unique_cord_proc_id,
            chain_state.checkpoint_tree_root,
            realm_tree.get_root(),
        )));
        let config = RealmGUTAEndCapGathererConfig::<N, InMemoryTempStore, SimpleMockMemoryFileSystem> {
            realm_id_u64: chain_state.realm_id_u64,
            realm_sub_id_u64: chain_state.realm_sub_id_u64,
            status,
            temp_db: chain_state.temp_db.clone(),
            file_system: file_system.clone(),
            backup_file_directory: "backups".to_string(),
            coordinator_guta_updates_circuit_whitelist: chain_state.guta_circuit_whitelist,
            checkpoint_tree: Arc::new(chain_state.checkpoint_tree.clone()),
            future_pending_end_cap_jobs: Arc::new(RwLock::new(Vec::new())),
            current_validator_user_leaf: Arc::new(std::sync::Mutex::new(chain_state.finalizer_user.user_leaf.clone())),
            tree_store: chain_state.db.clone(),
            _phantom_n: std::marker::PhantomData,
        };

        let mut gatherer =
            RealmGUTAEndCapGatherer::<N, InMemoryTempStore, SimpleMockMemoryFileSystem>::create_new_with_tree(
                &mut realm_tree,
                chain_state.unique_cord_proc_id,
                config,
            )
            .await?;
        gatherer
            .update_from_many_queue_items_with_tree(
                &mut realm_tree,
                vec![item_a.psy_ser_to_bytes_vec()?, item_b.psy_ser_to_bytes_vec()?],
            )
            .await?;
        let output = gatherer.finalize_with_tree(&mut realm_tree).await?;

        assert_eq!(output.job_ids.len(), 2);
        assert_eq!(output.job_ids[0].len(), 1);
        assert_eq!(output.job_ids[0][0].job_id.circuit_type, ProvingJobCircuitType::GUTATwoEndCap);
        assert_eq!(output.job_ids[1].len(), 1);
        assert_eq!(output.job_ids[1][0].job_id.circuit_type, ProvingJobCircuitType::RealmFinalizeGUTA);
        assert_eq!(output.db_output.total_users_updated, 2);
        assert_eq!(output.db_output.total_proofs_generated, 2);
        assert!(!output.db_output.is_noop());
        let da_fees_collected = output.db_output.guta_header.header.stats.da_fees_collected.to_u64_value();
        assert!(da_fees_collected > 0, "the backup regression must exercise a nonzero validator fee");
        let mut validator_leaf_after = chain_state.finalizer_user.user_leaf.clone();
        validator_leaf_after.balance += PF::from_u64_value(da_fees_collected);
        validator_leaf_after.last_checkpoint_id = PF::from_u64_value(chain_state.checkpoint_id);
        let validator_index = chain_state.finalizer_user.user_id - (chain_state.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT);
        assert_eq!(realm_tree.get_leaf_value(validator_index), validator_leaf_after.qfhash::<PoseidonHasher>());
        assert_eq!(realm_tree.get_root(), output.db_output.new_realm_root);
        let live_leaves = output.db_output.update_user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF);
        assert!(live_leaves.remainder().is_empty());
        let live_validator_leaves = live_leaves
            .map(PQEDUserLeaf::<PF, Hash>::psy_ser_from_slice)
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .filter(|leaf| leaf.user_id == validator_leaf_after.user_id)
            .collect::<Vec<_>>();
        assert_eq!(live_validator_leaves, vec![validator_leaf_after.clone()]);

        let backup_path = get_new_realm_end_cap_gatherer_backup_file_path(
            "backups",
            chain_state.realm_id_u64,
            chain_state.realm_sub_id_u64,
            chain_state.unique_pending_id,
        )
        .to_string_lossy()
        .to_string();
        assert!(file_system.file_like_exists(&backup_path).await?);

        Ok(GatherFixture {
            file_system,
            backup_path,
            realm_id_u64: chain_state.realm_id_u64,
            user_a,
            user_b,
            old_hash_a: item_a.old_user_leaf_hash,
            old_hash_b: item_b.old_user_leaf_hash,
            root_job_id: output.job_ids[1][0].job_id.clone(),
            old_realm_root: output.db_output.old_realm_root,
            new_realm_root: output.db_output.new_realm_root,
            prebatch_tree,
            validator_leaf_before: chain_state.finalizer_user.user_leaf.clone(),
            validator_leaf_after,
            da_fees_collected,
            update_user_leaves_ffs: output.db_output.update_user_leaves_ffs,
            update_global_user_tree_nodes_ffs: output.db_output.update_global_user_tree_nodes_ffs,
            chain_state,
        })
    }

    #[tokio::test]
    async fn end_cap_gatherer_round_trips_through_backup_file() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;

        // the lightweight probe reads the end root committed by finalize
        let end_root =
            read_realm_backup_end_root::<SimpleMockMemoryFileSystem, Hash>(fixture.file_system.as_ref(), &fixture.backup_path).await?;
        assert_eq!(end_root, fixture.new_realm_root);

        // a full restore with new leaves reproduces the gatherer output
        let mut restored_tree = fixture.prebatch_tree.clone();
        let restored = read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &fixture.backup_path,
            &mut restored_tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        )
        .await?;
        assert_eq!(restored.total_users_updated, 2);
        assert_eq!(restored.total_proofs_generated, 0);
        assert_eq!(restored.old_realm_root, fixture.old_realm_root);
        assert_eq!(restored.new_realm_root, fixture.new_realm_root);
        assert_eq!(restored_tree.get_root(), fixture.new_realm_root, "backup replay must apply the finalizer fee, not only advertise its root");
        assert_eq!(restored.guta_header.job_id, fixture.root_job_id);
        assert!(!restored.update_user_leaves_ffs.is_empty());
        assert!(!restored.update_user_contract_tree_nodes_ffs.is_empty());
        assert!(!restored.update_contract_state_tree_nodes_ffs.is_empty());
        assert!(!restored.update_global_user_tree_nodes_ffs.is_empty());
        assert_eq!(restored.update_user_leaves_ffs, fixture.update_user_leaves_ffs);
        let sorted_nodes = |bytes: &[u8]| {
            let chunks = bytes.chunks_exact(super::QMS_FAST_SERIALIZER_ZERO_ID_NODE_SIZE);
            assert!(chunks.remainder().is_empty());
            let mut nodes = chunks.map(|node| node.to_vec()).collect::<Vec<_>>();
            nodes.sort_unstable();
            nodes
        };
        assert_eq!(sorted_nodes(&restored.update_global_user_tree_nodes_ffs), sorted_nodes(&fixture.update_global_user_tree_nodes_ffs));

        // restoring with insert_old_leaves rebuilds the pre-update tree state
        let mut old_tree = fixture.prebatch_tree.clone();
        read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &fixture.backup_path,
            &mut old_tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            true,
        )
        .await?;
        let min_user_id = fixture.realm_id_u64 << (N::REALM_GLOBAL_USER_TREE_HEIGHT as u64);
        assert_eq!(old_tree.get_leaf_value(fixture.user_a - min_user_id), fixture.old_hash_a);
        assert_eq!(old_tree.get_leaf_value(fixture.user_b - min_user_id), fixture.old_hash_b);
        assert_eq!(old_tree.get_root(), fixture.old_realm_root);
        Ok(())
    }

    #[tokio::test]
    async fn end_cap_backup_replays_validator_fee_leaf_ffs() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;
        let mut tree = fixture.prebatch_tree.clone();
        let restored = read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &fixture.backup_path,
            &mut tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        ).await?;
        assert_eq!(restored.guta_header.header.stats.da_fees_collected.to_u64_value(), fixture.da_fees_collected);
        let leaves = restored.update_user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF);
        assert!(leaves.remainder().is_empty());
        let validator_leaves = leaves
            .map(PQEDUserLeaf::<PF, Hash>::psy_ser_from_slice)
            .collect::<anyhow::Result<Vec<_>>>()?
            .into_iter()
            .filter(|leaf| leaf.user_id == fixture.validator_leaf_before.user_id)
            .collect::<Vec<_>>();
        assert_eq!(validator_leaves.len(), 1, "backup replay must emit the finalizer validator leaf exactly once");
        assert_eq!(validator_leaves[0].balance.to_u64_value(), fixture.validator_leaf_before.balance.to_u64_value() + fixture.da_fees_collected);
        assert_eq!(validator_leaves[0], fixture.validator_leaf_after);
        assert_eq!(restored.update_user_leaves_ffs, fixture.update_user_leaves_ffs);
        Ok(())
    }

    fn assert_backup_rejected_without_tree_changes(fixture: &GatherFixture, bytes: &[u8], expected_error: &str) {
        // An uncommitted validator seed checks preservation of the caller's journal and root on failure.
        let mut tree = RecTree::new(N::REALM_GLOBAL_USER_TREE_HEIGHT);
        for (index, hash) in fixture.prebatch_tree.get_leaves_slow_all() {
            tree.set_leaf(index, hash);
        }
        assert_eq!(tree.get_root(), fixture.old_realm_root);
        let changes = tree.get_changes().clone();
        for insert_old_leaves in [false, true] {
            let error = match super::read_realm_end_cap_gatherer_backup_bytes::<PoseidonHasher, Hash, PF>(
                bytes, &mut tree, fixture.realm_id_u64,
                N::REALM_GLOBAL_USER_TREE_HEIGHT, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, insert_old_leaves,
            ) {
                Ok(_) => panic!("corrupted backup must fail: {expected_error}"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected_error), "expected {expected_error}, got {error:#}");
            assert_eq!(tree.get_root(), fixture.old_realm_root);
            assert_eq!(tree.get_changes(), &changes);
        }
    }

    #[tokio::test]
    async fn finalizer_backup_rejects_tampering_without_tree_changes() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;
        let raw = fixture.file_system.files.get(&fixture.backup_path).unwrap().value().clone();
        let footer_start = raw.len() - GlobalUserTreeAggregatorHeaderWithJobId::<PF, Hash>::FIXED_SIZE;
        let effect_start = footer_start - 1 - 2 * PSY_OBJECT_FFS_SIZE_USER_LEAF;
        assert_eq!(&raw[..4], &super::REALM_END_CAP_GATHERER_BACKUP_V2_MAGIC_U32.to_le_bytes());
        assert_eq!(raw[effect_start], 1);

        let mut bad = raw.clone();
        bad[effect_start] = 2;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "invalid finalizer effect tag");
        let mut bad = raw.clone();
        let mut old_leaf = fixture.validator_leaf_before.clone();
        old_leaf.balance += PF::from_u64_value(1);
        bad[effect_start + 1..effect_start + 1 + PSY_OBJECT_FFS_SIZE_USER_LEAF].copy_from_slice(&old_leaf.psy_ser_to_bytes_vec()?);
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "finalizer old leaf preimage mismatch");
        for change_nonce in [false, true] {
            let mut bad = raw.clone();
            let mut new_leaf = fixture.validator_leaf_after.clone();
            if change_nonce {
                new_leaf.nonce += PF::from_u64_value(1);
            } else {
                new_leaf.balance += PF::from_u64_value(1);
            }
            bad[effect_start + 1 + PSY_OBJECT_FFS_SIZE_USER_LEAF..footer_start].copy_from_slice(&new_leaf.psy_ser_to_bytes_vec()?);
            assert_backup_rejected_without_tree_changes(&fixture, &bad, "finalizer fee leaf mismatch");
        }
        let mut bad = raw.clone();
        bad[36] ^= 1;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "reconstructed end root");
        let mut bad = raw.clone();
        bad[footer_start + 96] ^= 1;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "GUTA footer transition mismatch");
        let mut bad = raw.clone();
        bad[footer_start + 152] ^= 1;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "DA fee total");
        let mut bad = raw.clone();
        bad[76 + 32] ^= 1;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "EndCap old leaf mismatch");
        let mut bad = raw.clone();
        bad[76 + 64] ^= 1;
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "EndCap new leaf preimage mismatch");
        let mut bad = raw[..effect_start].to_vec();
        bad.push(0);
        bad.extend_from_slice(&raw[footer_start..]);
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "missing finalizer effect for nonempty batch");
        let mut bad = raw.clone();
        bad.push(0);
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "footer size mismatch");
        assert_backup_rejected_without_tree_changes(&fixture, &raw[..raw.len() - 1], "footer size mismatch");
        Ok(())
    }

    #[tokio::test]
    async fn rge1_backup_accepts_complete_replay_and_rejects_missing_finalizer() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;
        let raw = fixture.file_system.files.get(&fixture.backup_path).unwrap().value().clone();
        let footer_start = raw.len() - GlobalUserTreeAggregatorHeaderWithJobId::<PF, Hash>::FIXED_SIZE;
        let effect_start = footer_start - 1 - 2 * PSY_OBJECT_FFS_SIZE_USER_LEAF;
        let mut legacy = raw[..effect_start].to_vec();
        legacy[..4].copy_from_slice(&super::REALM_END_CAP_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        legacy.extend_from_slice(&raw[footer_start..]);
        assert_backup_rejected_without_tree_changes(&fixture, &legacy, "RGE1 finalizer backup is missing");

        // A pre-finalizer RGE1 backup contains just the two EndCap effects.
        let mut expected_tree = fixture.prebatch_tree.clone();
        for bytes in fixture.update_user_leaves_ffs.chunks_exact(PSY_OBJECT_FFS_SIZE_USER_LEAF) {
            let leaf = PQEDUserLeaf::<PF, Hash>::psy_ser_from_slice(bytes)?;
            if leaf.user_id != fixture.validator_leaf_before.user_id {
                expected_tree.set_leaf(leaf.user_id.to_u64_value() - (fixture.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT), leaf.qfhash::<PoseidonHasher>());
            }
        }
        let mut header = super::read_guta_header_with_job_id_from_backup_bytes::<PF, Hash>(&raw[footer_start..])?;
        header.job_id = QProvingJobDataID::guta_two_end_cap_witness(0, fixture.realm_id_u64 as u32, 0);
        header.header.state_transition.new_node_value = expected_tree.get_root();
        header.header.total_aggregation_proofs_generated = PF::from_u64_value(1);
        legacy.truncate(effect_start);
        legacy[36..68].copy_from_slice(&expected_tree.get_root().into_owned_32bytes());
        legacy.extend_from_slice(&super::write_guta_header_with_job_id_backup_bytes(&header)?);
        let mut tree = fixture.prebatch_tree.clone();
        let restored = super::read_realm_end_cap_gatherer_backup_bytes::<PoseidonHasher, Hash, PF>(
            &legacy, &mut tree, fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, false,
        )?;
        assert_eq!(tree.get_root(), expected_tree.get_root());
        assert_eq!(restored.new_realm_root, expected_tree.get_root());
        assert_eq!(restored.update_user_leaves_ffs.len(), 2 * PSY_OBJECT_FFS_SIZE_USER_LEAF);
        let mut bad = legacy;
        bad[36..68].copy_from_slice(&fixture.new_realm_root.into_owned_32bytes());
        assert_backup_rejected_without_tree_changes(&fixture, &bad, "reconstructed end root");
        Ok(())
    }

    #[tokio::test]
    async fn finalizer_backup_old_leaf_read_preserves_validator_and_journal() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;
        let raw = fixture.file_system.files.get(&fixture.backup_path).unwrap().value().clone();
        let mut tree = RecTree::new(N::REALM_GLOBAL_USER_TREE_HEIGHT);
        for (index, hash) in fixture.prebatch_tree.get_leaves_slow_all() {
            tree.set_leaf(index, hash);
        }
        let changes = tree.get_changes().clone();
        let restored = super::read_realm_end_cap_gatherer_backup_bytes::<PoseidonHasher, Hash, PF>(
            &raw, &mut tree, fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT, N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT, true,
        )?;
        assert_eq!(tree.get_root(), fixture.old_realm_root);
        assert_eq!(tree.get_changes(), &changes);
        let index = fixture.validator_leaf_before.user_id.to_u64_value() - (fixture.realm_id_u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT);
        assert_eq!(tree.get_leaf_value(index), fixture.validator_leaf_before.qfhash::<PoseidonHasher>());
        assert_eq!(restored.update_user_leaves_ffs, fixture.update_user_leaves_ffs);
        assert_eq!(restored.new_realm_root, fixture.new_realm_root);
        Ok(())
    }

    #[tokio::test]
    async fn backup_readers_reject_corrupted_files() -> anyhow::Result<()> {
        let fixture = gather_two_user_backup().await?;
        let raw = fixture.file_system.files.get(&fixture.backup_path).unwrap().value().clone();
        assert!(raw.len() > 4 + 32 + 32 + 8);

        // wrong magic is rejected by both readers
        let bad_magic_path = "backups/bad_magic.backup".to_string();
        let mut bad_magic = raw.clone();
        bad_magic[0] ^= 0xff;
        fixture.file_system.files.insert(bad_magic_path.clone(), bad_magic);
        let err = match read_realm_backup_end_root::<SimpleMockMemoryFileSystem, Hash>(fixture.file_system.as_ref(), &bad_magic_path).await {
            Err(e) => e,
            Ok(_) => anyhow::bail!("bad magic must fail the end root reader"),
        };
        assert!(err.to_string().contains("magic mismatch"), "unexpected error: {err}");
        let mut tree = fixture.prebatch_tree.clone();
        let err = match read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &bad_magic_path,
            &mut tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => anyhow::bail!("bad magic must fail the full reader"),
        };
        assert!(err.to_string().contains("magic mismatch"), "unexpected error: {err}");

        // a file shorter than the fixed header is rejected
        let too_small_path = "backups/too_small.backup".to_string();
        fixture.file_system.files.insert(too_small_path.clone(), vec![0u8; 16]);
        let mut tree = fixture.prebatch_tree.clone();
        let err = match read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &too_small_path,
            &mut tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => anyhow::bail!("short file must fail"),
        };
        assert!(err.to_string().contains("too small"), "unexpected error: {err}");

        // a start root that disagrees with the in-memory tree is rejected
        let mut wrong_tree = RecTree::new(N::REALM_GLOBAL_USER_TREE_HEIGHT);
        wrong_tree.set_leaf(9, Hash::from_values(1, 2, 3, 4));
        let err = match read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &fixture.backup_path,
            &mut wrong_tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => anyhow::bail!("start root mismatch must fail"),
        };
        assert!(err.to_string().contains("does not match tree root"), "unexpected error: {err}");

        // cutting the footer off the end of a valid backup is detected
        let footer_size = GlobalUserTreeAggregatorHeaderWithJobId::<PF, Hash>::FIXED_SIZE;
        let truncated_path = "backups/truncated.backup".to_string();
        fixture
            .file_system
            .files
            .insert(truncated_path.clone(), raw[..raw.len() - footer_size].to_vec());
        let mut tree = fixture.prebatch_tree.clone();
        let err = match read_realm_end_cap_gatherer_backup_file::<PoseidonHasher, Hash, PF, _>(
            fixture.file_system.as_ref(),
            &truncated_path,
            &mut tree,
            fixture.realm_id_u64,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            false,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => anyhow::bail!("truncated footer must fail"),
        };
        assert!(err.to_string().contains("footer size mismatch"), "unexpected error: {err}");

        // a path that was never written simply fails to open
        assert!(
            read_realm_backup_end_root::<SimpleMockMemoryFileSystem, Hash>(fixture.file_system.as_ref(), "backups/never_written.backup")
                .await
                .is_err()
        );
        Ok(())
    }
}
