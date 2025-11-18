use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use async_trait::async_trait;
use futures::{
    stream::{self, StreamExt},
    TryFutureExt,
};
use parth_core::felt::FromPrimitiveValuesFelt;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, data::{
        db::hash_id_u64::{QHash256AndU64, get_data_buffer_for_hash256_and_u64s},
        hash::merkle_node_key::{PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE, SimpleMerkleNode, SimpleMerkleNodeKey},
    }, felt::{QFelt64, ToU64Value, ZeroableFelt}, node::realm_identifier::QRealmIdentifier, protocol::{core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig}, provider::jobs}
};
use rand::RngCore;
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
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase, qblob::data_views::zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;
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

pub async fn read_coordinator_guta_update_gatherer_backup_file<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase + QFHashBase<F>, F: QFelt64>(
    file_path: &PathBuf,
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<(
    CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash>,
    SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
)> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let metadata = file.metadata().await?;
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
        cur_guta_stats.add_from_mut(&header.header.header_with_stats.base_header.stats);
        total_guta_proofs_generated += header.header.header_with_stats.total_guta_proofs_generated;
        let state_transition = header.header.header_with_stats.base_header.state_transition;
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
pub struct CoordinatorGUTAUpdateGathererConfig<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub pending_unique_id: Arc<AtomicU64>,
    pub last_checkpoint_id: Arc<AtomicU64>,
    pub temp_db: Arc<TempDatabase>,
    pub backup_file_directory: String,
    pub coordinator_guta_updates_circuit_whitelist: N::QHash,

    pub _phantom_n: std::marker::PhantomData<N>,
}
pub struct CoordinatorGUTAUpdateGatherer<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
    pub config: CoordinatorGUTAUpdateGathererConfig<N, TempDatabase>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub guta_stats: GUTAStats<N::F>,
    pub total_guta_proofs_generated: N::F,
    pub updated_realm_roots: Vec<(u64, N::QHash)>,
    pub start_global_user_tree_root: N::QHash,
    pub new_coordinator_guta_file: tokio::fs::File,
    pub pending_file_path: String,
}

pub struct CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash> {
    pub update_global_user_tree_nodes_ffs: Vec<u8>,
    pub guta_stats: GUTAStats<F>,
    pub total_guta_proofs_generated: F,

    pub start_global_user_tree_root: Hash,
    pub end_global_user_tree_root: Hash,

    pub random_seed_guta: Hash,
}

pub struct CoordinatorGUTAUpdateGathererOutput<F, Hash, JobId> {
    pub db_output: CoordinatorGUTAUpdateGathererOutputDatabase<F, Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    > QueueGathererItemBuilderWithTree<CoordinatorGUTAUpdateGathererConfig<N, TempDatabase>, SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>>
    for CoordinatorGUTAUpdateGatherer<N, TempDatabase>
{
    type Output = CoordinatorGUTAUpdateGathererOutput<N::F, N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: CoordinatorGUTAUpdateGathererConfig<N, TempDatabase>,
    ) -> anyhow::Result<Self> {
        let new_coordinator_guta_file_path = get_new_coordinator_guta_update_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            config.pending_unique_id.load(std::sync::atomic::Ordering::Relaxed),
        );
        let mut new_coordinator_guta_file = tokio::fs::File::create(&new_coordinator_guta_file_path).await?;
        new_coordinator_guta_file
            .write_u32_le(COORDINATOR_GUTA_UPDATE_GATHERER_BACKUP_V1_MAGIC_U32)
            .await?;
        new_coordinator_guta_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        // ensure uncommited changes are committed
        tree.commit_changes();

        Ok(Self {
            config,
            pending_core_proc_id: unique_id,
            updated_realm_roots: Vec::new(),
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
        self.new_coordinator_guta_file.write_all(&item).await?;
        self.guta_stats.add_from_mut(&update_header.header.header_with_stats.base_header.stats);
        self.total_guta_proofs_generated += update_header.header.header_with_stats.total_guta_proofs_generated;
        self.updated_realm_roots.push((
            update_header
                .header
                .header_with_stats
                .base_header
                .state_transition
                .node_index
                .to_u64_value(),
            update_header.header.header_with_stats.base_header.state_transition.new_node_value,
        ));
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
        // ensure the new user public keys file is flushed to disk
        self.new_coordinator_guta_file.flush().await?;

        let end_global_user_tree_root = tree.get_root();

        let pending_unique_id = self.config.pending_unique_id.load(Ordering::Relaxed);
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        // todo prepare job temp data
        let job_temp_data = Vec::new();

        let update_global_user_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        tree.commit_changes();

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;


            //todo actually collect job ids
        let jobs_for_queue: Vec<Vec<PsyProvingJobMetadataWithJobId<N::QHash, QProvingJobDataID>>> = Vec::new();

        let added_proofs = jobs_for_queue.iter().map(|v| v.len() as u64).sum::<u64>();
        let added_proofs_felt = N::F::from_u64_value(added_proofs);
        self.total_guta_proofs_generated += added_proofs_felt;

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
        Ok(output)
    }
}
