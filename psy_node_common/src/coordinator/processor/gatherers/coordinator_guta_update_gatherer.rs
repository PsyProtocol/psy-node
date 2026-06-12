use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use parth_common::memory_stores::{
    dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, mem_tree_recorder::SimpleMemoryMerkleRecorderStore, traits::PsyMemoryMerkleStoreImm,
};
use parth_core::{
    crypto::hash::traits::{MerkleZeroHasher, QFieldHashable},
    data::hash::merkle_node_key::{SimpleMerkleNode, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY},
    felt::{FromPrimitiveValuesFelt, QFelt64, ToU64Value, ZeroableFelt},
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    guta::{header::GlobalUserTreeAggregatorHeader, header_extended::GlobalUserTreeAggregatorHeaderWithTagValueAndJobID, stats::GUTAStats},
    rewards_tree::offsets::{GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX, GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL},
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase, qblob::data_views::zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
};
use psy_serialize::{PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use rand::RngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

pub async fn read_coordinator_guta_update_gatherer_backup_file<
    Hasher: MerkleZeroHasher<Hash>,
    Hash: QDBHashBase + QFHashBase<F>,
    F: QFelt64,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: &FileSystem,
    file_path: &str,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash>> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(&file_path).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();
    // Coordinator backup format: magic(4) + start_root(32) + [queue_items...] + random_seed(32)
    // NOTE: There is NO end_root in this format (unlike realm backup).
    let const_size_len = 4 + 32; // magic + start_root
    let item_size = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID::<F, Hash>::FIXED_SIZE;

    if file_len < const_size_len {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
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

    // File layout after header: N * item_size bytes of queue items, then 32 bytes random_seed
    let remaining_after_start = file_len as usize - (4 + 32);
    if remaining_after_start == 0 {
        // Empty file (no random_seed written by old code), return empty result
        return Ok(CoordinatorGUTAUpdateGathererOutputDatabase {
            update_global_user_tree_nodes_ffs: vec![],
            new_realm_guta_reward_tree_node_keys_ffs: vec![],
            guta_stats: GUTAStats::<F>::get_zero_value(),
            total_guta_proofs_generated: F::ZERO_VALUE,
            total_guta_inputs: 0,
            start_global_user_tree_root,
            end_global_user_tree_root: tree.get_root(),
            random_seed_guta: Hash::get_zero_value(),
            root_guta_header: None,
        });
    }

    let file_len_without_metadata = remaining_after_start - 32; // exclude trailing random_seed
    if file_len_without_metadata % item_size != 0 {
        return Err(anyhow::anyhow!(
            "Backup file length without metadata is not a multiple of {}: {} bytes",
            item_size,
            file_len_without_metadata
        ));
    }

    let expected_count = file_len_without_metadata / item_size;

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
        tree.set_e_leaf(state_transition.node_index.to_u64_value(), state_transition.new_node_value);
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
        total_guta_inputs: changes.len() as u64,
        new_realm_guta_reward_tree_node_keys_ffs: vec![],
        root_guta_header: None,
    };
    Ok(output_db)
}
pub struct CoordinatorGUTAUpdateGathererConfig<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
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
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>
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
            last_old_realm_roots: self.last_old_realm_roots.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}
pub struct CoordinatorGUTAUpdateGatherer<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
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
    pub total_guta_inputs: u64,
}
/*
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> CoordinatorGUTAUpdateGatherer<N, TempDatabase, FileSystem>
{
    fn update_status(&mut self) -> anyhow::Result<()> {

        let status = self.config.status.read().map_err(|e| anyhow::anyhow!("{:?}", e))?.clone();
        self.status = status;
        Ok(())
    }
}
*/
#[derive(Clone)]
pub struct CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash> {
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub new_realm_guta_reward_tree_node_keys_ffs: Vec<u8>,
    pub guta_stats: GUTAStats<F>,
    pub total_guta_proofs_generated: F,
    pub total_guta_inputs: u64,

    pub start_global_user_tree_root: Hash,
    pub end_global_user_tree_root: Hash,
    pub root_guta_header: Option<GlobalUserTreeAggregatorHeader<F, Hash>>,

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
    >
    QueueGathererItemBuilderWithTree<
        CoordinatorGUTAUpdateGathererConfig<N, TempDatabase, FileSystem>,
        SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    > for CoordinatorGUTAUpdateGatherer<N, TempDatabase, FileSystem>
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
        let mut new_coordinator_guta_file = config
            .file_system
            .file_like_fs_create(&new_coordinator_guta_file_path.to_string_lossy())
            .await?;
        new_coordinator_guta_file
            .write_u32_le(COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32)
            .await?;
        new_coordinator_guta_file.write_all(&tree.get_root().into_owned_32bytes()).await?;

        let guta_planner = CoordinatorGUTAPlanner::new(config.checkpoint_tree.get_root());
        let last_committed_checkpoint_root = config.checkpoint_tree.get_root();
        Ok(Self {
            config,
            status,
            guta_planner,
            last_committed_checkpoint_root,
            pending_core_proc_id: unique_id,
            total_guta_inputs: 0,
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
        tracing::info!("[CoordinatorGUTAUpdateGatherer] got update_header: {:#?}", update_header);
        let current_checkpoint_root = self.config.checkpoint_tree.get_root();
        if self.last_committed_checkpoint_root != current_checkpoint_root {
            //self.update_status()?;
            self.last_committed_checkpoint_root = current_checkpoint_root;
        }
        let unique_pending_id = self.status.unique_pending_id;

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
                update_header,
            )
            .await?;
        self.total_guta_inputs += 1;
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
                let last_old_realm_roots = self
                    .config
                    .last_old_realm_roots
                    .read()
                    .map_err(|e| anyhow::anyhow!("error reading last old realm roots {:?}", e))?;
                for (index, old_root) in last_old_realm_roots.iter() {
                    tree.set_e_leaf_no_proof(*index, *old_root);
                }
            }
            tracing::info!("Reverted to root {:?}", tree.get_root());
            self.guta_planner = CoordinatorGUTAPlanner::new(self.config.checkpoint_tree.get_root());
        }

        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_coordinator_guta_file)
            .await?;

        let current_checkpoint_root = self.config.checkpoint_tree.get_root();
        if self.last_committed_checkpoint_root != current_checkpoint_root {
            //self.update_status()?;
            self.last_committed_checkpoint_root = current_checkpoint_root;
        }

        //let end_global_user_tree_root = tree.get_root();

        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let new_status = self.config.status.read().map_err(|e| anyhow::anyhow!("error reading status {:?}", e))?.clone();
        let jobs_for_queue_result = self.guta_planner
            .finalize_with_reward_ids(
                &realm_identifier,
                self.status.unique_pending_id,
                &self.last_committed_checkpoint_root,
                &self.config.checkpoint_tree,
                tree,
                self.config.temp_db.clone(),
                GUTA_REWARDS_TREE_OFFSET_ROOT_LEVEL,
                GUTA_REWARDS_TREE_OFFSET_ROOT_INDEX,
                new_status.last_committed_checkpoint_state_roots,
                new_status.last_committed_checkpoint_leaf.stats.qfhash::<N::HasherBase>(),
                self.config.coordinator_guta_updates_circuit_whitelist,
            )
            .await;
        if jobs_for_queue_result.is_err() {
            tracing::error!(
                "Error finalizing GUTA updates gatherer for pending id {}: {:?}",
                self.status.unique_pending_id,
                jobs_for_queue_result.as_ref().err()
            );
            anyhow::bail!("Error finalizing GUTA updates gatherer: {:?}", jobs_for_queue_result.err());
        }
        let (jobs_for_queue, input_realm_reward_keys, root_guta_header) = jobs_for_queue_result?;
        tracing::info!(
            "Finalized GUTA updates gatherer for pending id {}, total jobs created: {}",
            self.status.unique_pending_id,
            jobs_for_queue.iter().map(|v| v.len()).sum::<usize>()
        );

        let end_global_user_tree_root = tree.get_root();

        tracing::info!(
            "Finalizing GUTA updates gatherer for pending id {}, start root {:?}, end root {:?}",
            self.status.unique_pending_id,
            self.start_global_user_tree_root,
            end_global_user_tree_root
        );

        let added_proofs = jobs_for_queue.iter().map(|v| v.len() as u64).sum::<u64>();
        let added_proofs_felt = N::F::from_u64_value(added_proofs);
        self.total_guta_proofs_generated += added_proofs_felt;

        let update_global_user_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        tracing::info!(
            "Committing GUTA updates gatherer changes for pending id {}, committing root {:?}",
            self.status.unique_pending_id,
            tree.get_root()
        );
        tree.commit_changes();

        let mut new_realm_guta_reward_tree_node_keys_ffs = Vec::with_capacity(input_realm_reward_keys.len() * (8 + PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE_KEY));
        for (realm_id, key) in input_realm_reward_keys.iter() {
            new_realm_guta_reward_tree_node_keys_ffs.extend_from_slice(&realm_id.to_le_bytes());
            key.pio_write_to_io(&mut new_realm_guta_reward_tree_node_keys_ffs)?;
        }

        let random_seed_guta = get_temp_guta_rand_seed::<N::QHash>();

        // Write trailing metadata to backup file so reader can verify length.
        // Format: magic(4) + start_root(32) + [items...] + random_seed(32)
        self.new_coordinator_guta_file
            .write_all(&random_seed_guta.into_owned_32bytes())
            .await?;
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_coordinator_guta_file)
            .await?;

        let output_database = CoordinatorGUTAUpdateGathererOutputDatabase {
            update_global_user_tree_nodes_ffs,
            guta_stats: self.guta_stats,
            total_guta_proofs_generated: self.total_guta_proofs_generated,
            start_global_user_tree_root: self.start_global_user_tree_root,
            end_global_user_tree_root,
            root_guta_header: Some(root_guta_header),
            random_seed_guta,
            new_realm_guta_reward_tree_node_keys_ffs,
            total_guta_inputs: self.total_guta_inputs,
        };

        let output = CoordinatorGUTAUpdateGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };

        let last_old_realm_roots = Arc::clone(&self.config.last_old_realm_roots);
        {
            let mut last_old_roots = last_old_realm_roots
                .write()
                .map_err(|e| anyhow::anyhow!("error writing last old realm roots {:?}", e))?;
            *last_old_roots = self.old_realm_roots;
        }
        tracing::info!(
            "GUTA updates gatherer for pending id {} finalized successfully.",
            self.status.unique_pending_id
        );
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path};

    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{
        crypto::hash::traits::ZeroableHash,
        data::hash::merkle_node_key::SimpleMerkleNodeKey,
        felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::Q256BitHash,
        PHash, PF, QJobIdBase,
    };
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::guta::{
        header::GlobalUserTreeAggregatorHeader,
        header_extended::{GlobalUserTreeAggregatorHeaderWithTagValue, GlobalUserTreeAggregatorHeaderWithTagValueAndJobID},
        stats::GUTAStats,
        sub_tree_transition::SubTreeNodeStateTransition,
    };
    use psy_node_core::file::memory_fs::SimpleMockMemoryFileSystem;
    use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

    use super::{
        read_coordinator_guta_update_gatherer_backup_file, COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32,
    };

    #[tokio::test]
    async fn reads_coordinator_guta_backup_with_trailing_random_seed() -> anyhow::Result<()> {
        type Hasher = PoseidonHasher;
        type Hash = PHash;
        type F = PF;

        let path = "coordinator_guta_update_gatherer_realm_0_sub_1_pending_1.backup";
        let file_system = SimpleMockMemoryFileSystem::new();
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(4);
        let start_root = tree.get_root();
        let new_leaf = Hash::from_owned_32bytes([7u8; 32]);
        let random_seed = Hash::from_owned_32bytes([9u8; 32]);

        let item = GlobalUserTreeAggregatorHeaderWithTagValueAndJobID {
            header: GlobalUserTreeAggregatorHeaderWithTagValue {
                header: GlobalUserTreeAggregatorHeader {
                    guta_circuit_whitelist: Hash::get_zero_value(),
                    checkpoint_tree_root: Hash::get_zero_value(),
                    state_transition: SubTreeNodeStateTransition {
                        old_node_value: Hash::get_zero_value(),
                        new_node_value: new_leaf,
                        node_index: F::from_u64_value(0),
                        node_level: F::ZERO_VALUE,
                    },
                    stats: GUTAStats {
                        guta_fees_collected: F::from_u64_value(11),
                        da_fees_collected: F::from_u64_value(12),
                        user_ops_processed: F::from_u64_value(13),
                        total_transactions: F::from_u64_value(14),
                        slots_modified: F::from_u64_value(15),
                    },
                    total_aggregation_proofs_generated: F::from_u64_value(2),
                },
                new_tag_tree_node_value: Hash::from_owned_32bytes([8u8; 32]),
            },
            job_id: QProvingJobDataID::new_invalid_job_id(),
        };

        let mut data = Vec::new();
        data.extend_from_slice(&COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32.to_le_bytes());
        data.extend_from_slice(&start_root.into_owned_32bytes());
        data.extend_from_slice(&item.psy_ser_to_bytes_vec()?);
        data.extend_from_slice(&random_seed.into_owned_32bytes());
        file_system.files.insert(path.to_string(), data);

        let output =
            read_coordinator_guta_update_gatherer_backup_file::<Hasher, Hash, F, SimpleMockMemoryFileSystem>(&file_system, path, &mut tree)
                .await?;

        assert_eq!(output.total_guta_inputs, 1);
        assert_eq!(output.total_guta_proofs_generated.to_u64_value(), 2);
        assert_eq!(output.guta_stats.user_ops_processed.to_u64_value(), 13);
        assert_eq!(output.random_seed_guta, random_seed);
        assert_eq!(output.end_global_user_tree_root, tree.get_root());

        Ok(())
    }

    #[tokio::test]
    async fn reads_all_local_coordinator_backups() -> anyhow::Result<()> {
        type Hasher = PoseidonHasher;
        type Hash = PHash;

        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir.parent().unwrap();
        let backup_dir = workspace_root.join("local_checkpoints/coordinator_0_0/guta_updates_backup");

        if !backup_dir.exists() {
            return Ok(());
        }

        let mut total_files = 0usize;
        let mut ok_files = 0usize;
        let mut bad_files = Vec::new();

        for entry in fs::read_dir(&backup_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|e| e == "backup").unwrap_or(false) {
                total_files += 1;
        match verify_local_coordinator_backup_file(&path).await {
                    Ok(()) => ok_files += 1,
                    Err(e) => {
                        eprintln!("BAD: {} -> {}", path.display(), e);
                        bad_files.push((path.display().to_string(), e.to_string()));
                    }
                }
            }
        }

        println!("Total: {}, OK: {}, Bad: {}", total_files, ok_files, bad_files.len());
        if !bad_files.is_empty() {
            anyhow::bail!("{} coordinator backup files failed verification", bad_files.len());
        }

        Ok(())
    }

    async fn verify_local_coordinator_backup_file(path: &Path) -> anyhow::Result<()> {
        let data = fs::read(path)?;
        if data.len() < 36 {
            anyhow::bail!("file too small: {} bytes", data.len());
        }

        let start_root = PHash::from_owned_32bytes(data[4..36].try_into().unwrap());
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(4);
        tree.set_node_value(SimpleMerkleNodeKey::new_root(), start_root);
        tree.commit_changes();

        let file_system = SimpleMockMemoryFileSystem::new();
        let path_str = path.to_string_lossy().to_string();
        file_system.files.insert(path_str.clone(), data);

        let output =
            read_coordinator_guta_update_gatherer_backup_file::<PoseidonHasher, PHash, PF, SimpleMockMemoryFileSystem>(&file_system, &path_str, &mut tree)
                .await?;

        if output.total_guta_inputs == 0 && output.total_guta_proofs_generated.to_u64_value() == 0 {
            tracing::debug!("coordinator backup {} is empty after parse", path.display());
        }

        Ok(())
    }
}
