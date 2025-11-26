use std::{
    path::PathBuf,
    sync::{
        Arc, RwLock, atomic::{AtomicU64, Ordering}
    },
};

use async_trait::async_trait;
use futures::{
    stream::{self, StreamExt},
    TryFutureExt,
};
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm,
};
use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{MerkleZeroHasher, QFieldHashable},
    },
    data::{
        db::hash_id_u64::{get_data_buffer_for_hash256_and_u64s, QHash256AndU64},
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE},
    },
    felt::{FromPrimitiveValuesFelt, QFelt64, ToU64Value, ZeroableFelt},
    node::realm_identifier::QRealmIdentifier,
    protocol::{
        core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
        provider::jobs,
    },
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::{
        tree_agg_v2::{plan_jobs_for_tree_agg, plan_jobs_for_tree_agg_offset_root, BasicTreePlannerHelper},
        AggStateTrackableInput, AggStateTransitionInputV2, AggStateTransitionWithStats, DummyAggStateTransition,
    },
    guta::{
        header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID},
        stats::GUTAStats,
    },
    protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput,
    rewards_tree::offsets::{GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX, GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL},
    v1::qdata::public_key::PZKPublicKeyInfo,
    worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId},
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    guta_planner, psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::data_views::zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use rand::RngCore;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, sync::Mutex};
use tower_http::ServiceExt;

use crate::{
    coordinator::processor::processor_shared_status::PsyCoordinatorProcessorSharedStatus,
    guta_planner::coordinator_guta_planner::CoordinatorGUTAPlanner, queue::gatherer_builder::QueueGathererItemBuilderWithTree,
};
pub const COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x43, 0x47, 0x42, 0x31]; // 'CGB1' in ASCII
pub const COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31424743; // 'CGB1' in little-endian u32

fn get_temp_guta_rand_seed<Hash: Q256BitHash>() -> Hash {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    Hash::from_owned_32bytes(bytes)
}
pub fn get_new_coordinator_guta_update_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> PathBuf {
    PathBuf::from(backup_file_directory).join(format!(
        "coordinator_guta_update_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    ))
}

pub async fn read_coordinator_guta_update_gatherer_backup_file<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase + QFHashBase<F>, F: QFelt64, FileSystem: TokioLikeFileSystem>(
    file_system: &FileSystem,
    file_path: &PathBuf,
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<(
    CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash>,
    SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
)> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(&file_path.to_string_lossy()).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();
    let const_size_len = 4 + 32 + 32;
    if file_len < const_size_len as u64 {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }

    let file_len_without_metadata = file_len as usize - const_size_len;
    if file_len_without_metadata % (GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE) != 0 {
        return Err(anyhow::anyhow!(
            "Backup file length without metadata is not a multiple of 64: {} bytes",
            file_len_without_metadata
        ));
    }

    let magic_u32 = file.read_u32_le().await?;
    if magic_u32 != COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32,
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

    let expected_count = file_len_without_metadata / GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE;

    let mut cur_guta_stats = GUTAStats::<F>::get_zero_value();

    let mut total_guta_proofs_generated = F::ZERO_VALUE;

    // ensure any existing changes are already commited

    tree.commit_changes();

    let mut changes: Vec<(u64, Hash)> = Vec::new();
    for _ in 0..expected_count {
        let mut header_bytes = vec![0u8; GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE];
        file.read_exact(&mut header_bytes).await?;
        let header = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::psy_ser_from_owned_bytes_vec(header_bytes)?;
        cur_guta_stats.add_from_mut(&header.header.header.stats);
        total_guta_proofs_generated += header.header.header.total_aggregation_proofs_generated;
        let state_transition = header.header.header.state_transition;
        changes.push((state_transition.node_index.to_u64_value(), state_transition.new_node_value));
    }

    let mut random_seed_guta_bytes = [0u8; 32];
    file.read_exact(&mut random_seed_guta_bytes).await?;
    let random_seed_guta = Hash::from_owned_32bytes(random_seed_guta_bytes);

    let end_global_user_tree_root = tree.get_root();

    let mut update_global_user_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len() * PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE);

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
        node.pio_write_to_io(&mut update_global_user_tree_nodes_ffs)?;
    }
    tree.commit_changes();
    let output_db = CoordinatorGUTAUpdateGathererOutputDatabase {
        update_global_user_tree_nodes_ffs,
        guta_stats: cur_guta_stats,
        total_guta_proofs_generated,
        start_global_user_tree_root,
        end_global_user_tree_root,
        random_seed_guta,
    };
    Ok((output_db, tree))
}
pub struct CoordinatorGUTAUpdateGathererConfig<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>>>,
    pub temp_db: Arc<TempDatabase>,
    pub file_system: Arc<FileSystem>,
    pub last_old_realm_roots: Arc<RwLock<Vec<(u64, N::QHash)>>>,
    pub backup_file_directory: String,
    pub coordinator_guta_updates_circuit_whitelist: N::QHash,
    pub checkpoint_tree: Arc<PsyDashMemoryAppendOnlyMerkleStore<N::HasherBase, N::QHash>>,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl <N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone for CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem> {
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
            last_old_realm_roots: self.last_old_realm_roots.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}
pub struct CoordinatorGUTAUpdateGatherer<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> {
    pub config: CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>,
    pub last_committed_checkpoint_root: N::QHash,
    pub guta_planner: CoordinatorGUTAPlanner<N::F, N::QHash>,
    pub status: PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub guta_stats: GUTAStats<N::F>,
    pub total_guta_proofs_generated: N::F,
    pub old_realm_roots: Vec<(u64, N::QHash)>,
    pub start_global_user_tree_root: N::QHash,
    pub new_coordinator_guta_file: FileSystem::File,
    pub pending_file_path: String,
}
#[derive(Clone)]
pub struct CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash> {
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub guta_stats: GUTAStats<F>,
    pub total_guta_proofs_generated: F,

    pub start_global_user_tree_root: Hash,
    pub end_global_user_tree_root: Hash,

    pub random_seed_guta: Hash,
}
#[derive(Clone)]
pub struct CoordinatorGUTAUpdateGathererOutput<F, Hash, JobId> {
    pub db_output: CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
#[async_trait]
impl<
        FileSystem: TokioLikeFileSystem,
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    > QueueGathererItemBuilderWithTree<CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>, SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>>
    for CoordinatorGUTAUpdateGatherer<N, TempDatabase, FileSystem>
{
    type Output = CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        let status = config.status.read().unwrap().clone();
        let new_coordinator_guta_file_path = get_new_coordinator_guta_update_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            status.unique_pending_id,
        );
        let mut new_coordinator_guta_file = config.file_system.file_like_fs_create(&new_coordinator_guta_file_path.to_string_lossy()).await?;
        new_coordinator_guta_file
            .write_u32_le(COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32)
            .await?;
        new_coordinator_guta_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        
        let guta_planner = CoordinatorGUTAPlanner::new();
        let last_committed_checkpoint_root = config.checkpoint_tree.get_root();
        Ok(Self {
            config,
            status,
            guta_planner,
            last_committed_checkpoint_root,
            pending_core_proc_id: unique_id,
            old_realm_roots: Vec::new(),
            guta_stats: GUTAStats::get_zero_value(),
            total_guta_proofs_generated: N::F::ZERO_VALUE,
            new_coordinator_guta_file,
            start_global_user_tree_root: tree.get_root(),
            pending_file_path: new_coordinator_guta_file_path.to_string_lossy().to_string(),
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        if item.len() != GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<N::F, N::QHash>::FIXED_SIZE {
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for CoordinatorGUTAUpdateGatherer: expected {}, got {}",
                GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<N::F, N::QHash>::FIXED_SIZE,
                item.len()
            ));
        }
        let update_header = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<N::F, N::QHash>::psy_ser_from_slice(&item)?;
        let unique_pending_id = self.status.unique_pending_id;
        let current_checkpoint_root = self.last_committed_checkpoint_root;

        self.config
            .temp_db
            .set_proof_miner_rewards_tree_value(
                &QRealmIdentifier {
                    realm_id: self.config.realm_id_u64 as u32,
                    realm_sub_id: self.config.realm_sub_id_u64 as u16,
                },
                self.status.unique_pending_id,
                update_header.job_id,
                update_header.header.new_tag_tree_node_value,
            )
            .await?;
        self.new_coordinator_guta_file.write_all(&item).await?;
        self.guta_stats.add_from_mut(&update_header.header.header.stats);
        self.total_guta_proofs_generated += update_header.header.header.total_aggregation_proofs_generated;
        self.old_realm_roots.push((
            update_header.header.header.state_transition.node_index.to_u64_value(),
            update_header.header.header.state_transition.old_node_value,
        ));
        self.guta_planner
            .add_realm_job(
                unique_pending_id,
                &current_checkpoint_root,
                &self.config.checkpoint_tree,
                tree,
                self.config.temp_db.clone(),
                &update_header,
            )
            .await?;
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
        let needs_revert = {
            self.config
                .status
                .read()
                .map_err(|e| anyhow::anyhow!("error reading status {:?}", e))?
                .should_revert_last_changes
        };

        if needs_revert {
            tracing::info!(
                "Reverting GUTA updates gatherer changes for pending id {}, abandoning root {:?}",
                self.status.unique_pending_id,
                tree.get_root()
            );
            tree.revert_changes();
            {
                let tree_height = tree.get_height();
                let last_old_realm_roots = self.config.last_old_realm_roots.read().map_err(|e| anyhow::anyhow!("error reading last old realm roots {:?}", e))?;
                for (index, old_root) in self.old_realm_roots.iter() {
                    tree.set_leaf_no_proof(*index, *old_root);
                }
            }
            tracing::info!("Reverted to root {:?}", tree.get_root());
            self.guta_planner = CoordinatorGUTAPlanner::new();
        } else {
            tracing::info!(
                "Committing GUTA updates gatherer changes for pending id {}, committing root {:?}",
                self.status.unique_pending_id,
                tree.get_root()
            );
            tree.commit_changes();
        }

        // ensure the new user public keys file is flushed to disk
        self.config.file_system.file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_coordinator_guta_file).await?;

        let end_global_user_tree_root = tree.get_root();

        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };


        let jobs_for_queue: Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, QProvingJobDataID>>> = self
            .guta_planner
            .finalize_with_reward_ids(
                &realm_identifier,
                self.status.unique_pending_id,
                &self.last_committed_checkpoint_root,
                &self.config.checkpoint_tree,
                tree,
                self.config.temp_db.clone(),
                GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL,
                GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX,
                self.status.last_committed_checkpoint_state_roots,
                self.status.last_committed_checkpoint_leaf.stats.qfhash::<N::HasherBase>(),
                self.config.coordinator_guta_updates_circuit_whitelist,
            )
            .await?;

        let added_proofs = jobs_for_queue.iter().map(|v| v.len() as u64).sum::<u64>();
        let added_proofs_felt = N::F::from_u64_value(added_proofs);
        self.total_guta_proofs_generated += added_proofs_felt;

        let update_global_user_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());

        let output_database = CoordinatorGUTAUpdateGathererOutputDatabase {
            update_global_user_tree_nodes_ffs,
            guta_stats: self.guta_stats,
            total_guta_proofs_generated: self.total_guta_proofs_generated,
            start_global_user_tree_root: self.start_global_user_tree_root,
            end_global_user_tree_root,
            random_seed_guta: get_temp_guta_rand_seed::<N::QHash>(),
        };

        let output = CoordinatorGUTAUpdateGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };

        let last_old_realm_roots = Arc::clone(&self.config.last_old_realm_roots);
        {
            let mut last_old_roots = last_old_realm_roots.write().map_err(|e| anyhow::anyhow!("error writing last old realm roots {:?}", e))?;
            *last_old_roots = self.old_realm_roots;
        }
        Ok(output)
    }
}
