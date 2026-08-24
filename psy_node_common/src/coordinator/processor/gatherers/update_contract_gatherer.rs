use std::{
    collections::HashMap,
    io::SeekFrom,
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable},
    data::hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE},
    felt::QFelt64,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::{
        tree_agg_v2::{plan_jobs_for_tree_agg_offset_root, BasicTreePlannerHelper},
        AggStateTrackableInput, AggStateTransitionInputV2, AggStateTransitionWithStats, DummyAggStateTransition,
    },
    protocol::circuit_inputs::update_contracts::QCBatchUpdateContractsCircuitInput,
    rewards_tree::offsets::{UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX, UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL},
    v1::qdata::{
        contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeafV2, PsyUpdateContractQueueItem, CONTRACT_LEAF_SERIALIZED_SIZE},
    },
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
    psy_core_db::traits::full::PsyNodeCoreDatabaseContractObjectStoreReader,
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::data_views::{
        single_merkle_node_batch::{generate_single_merkle_node_blob_from_leaves, generate_single_merkle_node_blob_from_leaves_with_tree_height}, zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
    },
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::{
    coordinator::processor::processor_shared_status::PsyCoordinatorProcessorSharedStatus, queue::gatherer_builder::QueueGathererItemBuilderWithTree,
};
pub const UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x55, 0x43, 0x42, 0x31]; // 'UCB1' in ASCII
pub const UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31424355; // 'UCB1' in little-endian u32

pub const MAX_UPDATE_CONTRACTS_GATHERER_PER_BLOCK: usize = 2097152;
pub const UPDATE_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH: usize = 10 * 1024 * 1024; // 10 MB

/// checkpoint id used to read the latest committed state from the core db

pub fn get_new_update_contract_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> String {
    PathBuf::from(backup_file_directory).join(format!(
        "update_contract_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    )).to_string_lossy().to_string()
}

/// Core validation for a single contract code update.
///
/// - the contract must already exist in the in-memory global contract tree
///   (leaf hash at `contract_id` must be non-zero), and the provided old leaf
///   must match the current in-memory leaf exactly (stale reads from the edge,
///   e.g. another update in the same block, are rejected);
/// - only the original deployer may update the contract;
/// - the state tree height is immutable.
///
/// NOTE: this function does NOT mutate the tree. The new leaf is applied by
/// `update_leaves_spider_man` at finalize time (same pattern as the deploy
/// contract gatherer) so the generated spiderman proofs see the pre-update
/// old leaves. Returns the hash of the new contract leaf.
pub fn validate_contract_update<
    Hasher: FieldQHasher<F, Hash> + MerkleZeroHasher<Hash>,
    F: QFelt64,
    Hash: QFHashBase<F> + QDBHashBase,
>(
    tree: &SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
    contract_id: u64,
    old_contract_leaf: &PQEDContractLeafV2<F, Hash>,
    new_contract_leaf: &PQEDContractLeafV2<F, Hash>,
) -> anyhow::Result<Hash> {
    if contract_id == 0 {
        anyhow::bail!("contract id 0 is reserved and cannot be updated");
    }
    let current_leaf_hash = tree.get_leaf_value(contract_id);
    if current_leaf_hash == Hasher::get_zero_hash(0) {
        anyhow::bail!("cannot update contract id {}: contract does not exist", contract_id);
    }
    let old_leaf_hash = old_contract_leaf.qfhash::<Hasher>();
    if current_leaf_hash != old_leaf_hash {
        anyhow::bail!(
            "cannot update contract id {}: old contract leaf does not match the current contract tree state (stale read or conflicting update in the same block)",
            contract_id
        );
    }
    if old_contract_leaf.deployer != new_contract_leaf.deployer {
        anyhow::bail!(
            "cannot update contract id {}: only the original deployer can update the contract",
            contract_id
        );
    }
    if old_contract_leaf.state_tree_height != new_contract_leaf.state_tree_height {
        anyhow::bail!(
            "cannot update contract id {}: contract state tree height is immutable",
            contract_id
        );
    }
    Ok(new_contract_leaf.qfhash::<Hasher>())
}

pub async fn read_update_contract_gatherer_backup_file_path<
    Hasher: FieldQHasher<F, Hash> + MerkleZeroHasher<Hash>,
    Hash: QFHashBase<F> + QDBHashBase,
    F: QFelt64,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: &FileSystem,
    file_path: &str,
    max_contract_function_tree_leaves: usize,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<UpdateContractGathererOutputDatabase<Hash>> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(file_path).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();

    // ensure tree is up to date and pending changes are clean
    tree.commit_changes();

    if file_len < 4 + 32 + 4 + 8 {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }
    let magic = file.read_u32_le().await?;
    if magic != UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32,
            magic
        ));
    }
    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?;
    let start_root_hash = Hash::from_owned_32bytes(start_root_hash_bytes);

    let num_updated_contracts = (file.read_u32_le().await?) as usize;
    if num_updated_contracts > MAX_UPDATE_CONTRACTS_GATHERER_PER_BLOCK {
        return Err(anyhow::anyhow!(
            "Backup file num updated contracts {} exceeds maximum {}",
            num_updated_contracts,
            MAX_UPDATE_CONTRACTS_GATHERER_PER_BLOCK
        ));
    }
    if tree.get_root() != start_root_hash && num_updated_contracts > 0 {
        return Err(anyhow::anyhow!(
            "Backup file start root hash {:?} does not match tree root hash {:?}",
            start_root_hash,
            tree.get_root()
        ));
    }
    // the pivot proof is captured lazily before the first update is applied
    let mut pivot_proof: Option<parth_core::crypto::hash::merkle_proof::MerkleProofCore<Hash>> = None;

    let mut update_contract_function_tree_nodes_ffs = Vec::<u8>::new();
    let mut updated_contract_leaves_ffs = Vec::<u8>::with_capacity(num_updated_contracts * (CONTRACT_LEAF_SERIALIZED_SIZE + 8));
    let mut updated_contract_code_definitions = Vec::<ContractCodeDefinitionWithContractId>::with_capacity(num_updated_contracts);
    let mut updated_contract_ids = Vec::<u64>::with_capacity(num_updated_contracts);
    let mut contract_leaf_bytes: [u8; CONTRACT_LEAF_SERIALIZED_SIZE] = [0u8; CONTRACT_LEAF_SERIALIZED_SIZE];

    for _ in 0..num_updated_contracts {
        let contract_id = file.read_u64_le().await?;
        updated_contract_ids.push(contract_id);

        // old contract leaf data (must match the current tree state)
        file.read_exact(&mut contract_leaf_bytes[..]).await?;
        let old_leaf: PQEDContractLeafV2<F, Hash> = PQEDContractLeafV2::<F, Hash>::pio_read_from_io(&mut &contract_leaf_bytes[..])?;
        let old_leaf_hash = old_leaf.qfhash::<Hasher>();
        if tree.get_leaf_value(contract_id) != old_leaf_hash {
            return Err(anyhow::anyhow!(
                "Backup file old leaf for contract id {} does not match the current contract tree state",
                contract_id
            ));
        }

        // new contract leaf data
        file.read_exact(&mut contract_leaf_bytes[..]).await?;
        let new_leaf: PQEDContractLeafV2<F, Hash> = PQEDContractLeafV2::<F, Hash>::pio_read_from_io(&mut &contract_leaf_bytes[..])?;
        if pivot_proof.is_none() {
            let pivot = tree.get_historical_pivot_leaf(contract_id);
            if pivot.root != start_root_hash {
                return Err(anyhow::anyhow!(
                    "Backup file start root hash {:?} does not match tree computed root hash {:?}",
                    start_root_hash,
                    pivot.root
                ));
            }
            pivot_proof = Some(pivot);
        }
        let new_leaf_hash = validate_contract_update::<Hasher, F, Hash>(tree, contract_id, &old_leaf, &new_leaf)?;
        tree.set_leaf(contract_id, new_leaf_hash);
        updated_contract_leaves_ffs.extend_from_slice(&contract_id.to_le_bytes());
        updated_contract_leaves_ffs.extend_from_slice(&contract_leaf_bytes);

        // contract function leaves
        let contract_function_leaves_count = file.read_u32_le().await? as usize;
        if contract_function_leaves_count > max_contract_function_tree_leaves {
            return Err(anyhow::anyhow!(
                "Backup file contract {} function leaves count {} exceeds maximum {}",
                contract_id,
                contract_function_leaves_count,
                max_contract_function_tree_leaves
            ));
        } else if contract_function_leaves_count == 0 {
            return Err(anyhow::anyhow!(
                "Backup file contract {} function leaves count cannot be zero",
                contract_id,
            ));
        }
        let mut function_leaves = Vec::<Hash>::with_capacity(contract_function_leaves_count);
        for _ in 0..contract_function_leaves_count {
            let mut function_leaf_bytes = [0u8; 32];
            file.read_exact(&mut function_leaf_bytes).await?;
            let function_leaf = Hash::from_owned_32bytes(function_leaf_bytes);
            function_leaves.push(function_leaf);
        }

        let (computed_contract_function_tree_root, contract_function_tree_ffs) =
            generate_single_merkle_node_blob_from_leaves::<Hash, Hasher>(contract_id, &function_leaves);
        if computed_contract_function_tree_root != new_leaf.function_tree_root {
            return Err(anyhow::anyhow!(
                "Backup file contract {} function tree root {:?} does not match computed root {:?}",
                contract_id,
                new_leaf.function_tree_root,
                computed_contract_function_tree_root
            ));
        }
        update_contract_function_tree_nodes_ffs.extend_from_slice(&contract_function_tree_ffs);

        // contract code definition
        let contract_code_definition_length = file.read_u32_le().await? as usize;
        if contract_code_definition_length > (UPDATE_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH + 8) {
            return Err(anyhow::anyhow!(
                "Backup file contract {} code definition length {} exceeds maximum size {}",
                contract_id,
                contract_code_definition_length,
                UPDATE_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH
            ));
        } else if contract_code_definition_length == 0 {
            return Err(anyhow::anyhow!(
                "Backup file contract {} code definition length cannot be zero",
                contract_id,
            ));
        }
        let mut contract_code_definition_bytes = vec![0u8; contract_code_definition_length];
        file.read_exact(&mut contract_code_definition_bytes).await?;
        let contract_code_definition = ContractCodeDefinitionWithContractId::pio_read_from_io(&mut &contract_code_definition_bytes[..])?;
        if contract_id != contract_code_definition.contract_id {
            return Err(anyhow::anyhow!(
                "Backup file contract {} code definition id {} does not match expected id",
                contract_id,
                contract_code_definition.contract_id
            ));
        }
        updated_contract_code_definitions.push(contract_code_definition);
    }

    let end_root = tree.get_root();
    let pivot_siblings = pivot_proof.map(|p| p.siblings).unwrap_or_default();
    let mut update_global_contract_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len() * PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE);

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
        node.pio_write_to_io(&mut update_global_contract_tree_nodes_ffs)?;
    }
    let total_jobs = file.read_u64_le().await?;
    tree.commit_changes();

    let output_db = UpdateContractGathererOutputDatabase {
        start_global_contract_tree_root: start_root_hash,
        updated_contract_ids,
        updated_contract_leaves_ffs,
        update_contract_function_tree_nodes_ffs,
        updated_contract_code_definitions,
        total_jobs,
        end_global_contract_tree_root: end_root,
        global_contract_tree_update_pivot_siblings: pivot_siblings,
        update_global_contract_tree_nodes_ffs,
    };

    Ok(output_db)
}

#[derive(Debug, Clone)]
pub struct UpdateContractGathererOutputDatabase<Hash> {
    pub start_global_contract_tree_root: Hash,
    pub updated_contract_ids: Vec<u64>,
    pub updated_contract_leaves_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub updated_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
    pub total_jobs: u64,

    // end backup format
    pub end_global_contract_tree_root: Hash,

    pub global_contract_tree_update_pivot_siblings: Vec<Hash>,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
}

impl<Hash: Clone> UpdateContractGathererOutputDatabase<Hash> {
    /// An empty update output (no contract updates in the block); start == end
    /// root. Used by backup/recovery paths where no update gatherer output is
    /// available.
    pub fn empty(contract_tree_root: Hash) -> Self {
        Self {
            start_global_contract_tree_root: contract_tree_root.clone(),
            updated_contract_ids: Vec::new(),
            updated_contract_leaves_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            updated_contract_code_definitions: Vec::new(),
            total_jobs: 0,
            end_global_contract_tree_root: contract_tree_root,
            global_contract_tree_update_pivot_siblings: Vec::new(),
            update_global_contract_tree_nodes_ffs: Vec::new(),
        }
    }

    pub fn has_updates(&self) -> bool {
        !self.updated_contract_ids.is_empty()
    }
}

#[derive(Debug, Clone)]
pub struct UpdateContractGathererOutput<Hash, JobId> {
    pub db_output: UpdateContractGathererOutputDatabase<Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
pub struct UpdateContractGathererConfig<
    N: QNetworkTypesConfig,
    S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub shared_status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>>>,
    pub temp_db: Arc<TempDatabase>,
    pub contract_leaf_reader: Arc<S>,
    pub backup_file_directory: String,
    pub update_contract_circuit_whitelist: N::QHash,
    pub file_system: Arc<FileSystem>,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl<N: QNetworkTypesConfig, S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>
{
    fn clone(&self) -> Self {
        Self {
            realm_id_u64: self.realm_id_u64,
            realm_sub_id_u64: self.realm_sub_id_u64,
            shared_status: self.shared_status.clone(),
            temp_db: self.temp_db.clone(),
            contract_leaf_reader: self.contract_leaf_reader.clone(),
            backup_file_directory: self.backup_file_directory.clone(),
            update_contract_circuit_whitelist: self.update_contract_circuit_whitelist.clone(),
            file_system: self.file_system.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}
impl<N: QNetworkTypesConfig, S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>
{
    pub fn get_realm_identifier(&self) -> QRealmIdentifier {
        QRealmIdentifier {
            realm_id: self.realm_id_u64 as u32,
            realm_sub_id: self.realm_sub_id_u64 as u16,
        }
    }
}
pub struct UpdateContractGatherer<
    N: QNetworkTypesConfig,
    S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub config: UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>,
    pub shared_status: PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub updated_contract_ids: Vec<u64>,
    // (old leaf, new leaf) per update, in the order updates were applied
    pub updated_contract_leaves: Vec<(PQEDContractLeafV2<N::F, N::QHash>, PQEDContractLeafV2<N::F, N::QHash>)>,
    pub updated_contract_layout_proofs: Vec<Vec<u8>>,
    // contract_id -> index into updated_contract_ids, used both to reject
    // conflicting duplicate updates and to keep the first old leaf for revert
    pub updated_contract_id_to_index: HashMap<u64, usize>,
    pub updated_contract_leaves_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub updated_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    pub unique_pending_id: u64,
    pub updates_file: FileSystem::File,
    pub pending_file_path: String,
}

impl<N: QNetworkTypesConfig, S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash>, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    UpdateContractGatherer<N, S, TempDatabase, FileSystem>
{
    pub fn reset_for_revert(&mut self) -> anyhow::Result<()> {
        self.updated_contract_ids.clear();
        self.updated_contract_leaves.clear();
        self.updated_contract_layout_proofs.clear();
        self.updated_contract_id_to_index.clear();
        self.updated_contract_leaves_ffs.clear();
        self.update_contract_function_tree_nodes_ffs.clear();
        self.updated_contract_code_definitions.clear();

        Ok(())
    }
}
#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyNodeCoreDatabaseContractObjectStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        FileSystem: TokioLikeFileSystem,
    >
    QueueGathererItemBuilderWithTree<
        UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>,
        SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    > for UpdateContractGatherer<N, S, TempDatabase, FileSystem>
{
    type Output = UpdateContractGathererOutput<N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: UpdateContractGathererConfig<N, S, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        let shared_status = config.shared_status.read().unwrap().clone();
        let new_update_contract_file_path = get_new_update_contract_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            shared_status.unique_pending_id,
        );

        println!("created update contract gatherer with unique_pending_id: {}, proc_id: {}", shared_status.unique_pending_id, unique_id);
        let mut updates_file: FileSystem::File = config
            .file_system
            .file_like_fs_create(&new_update_contract_file_path)
            .await?;

        updates_file.write_u32_le(UPDATE_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32).await?;
        updates_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        updates_file.write_u32_le(0).await?; // placeholder for num updated contracts

        Ok(Self {
            config,
            unique_pending_id: shared_status.unique_pending_id,
            shared_status,
            pending_core_proc_id: unique_id,
            updated_contract_ids: Vec::new(),
            updated_contract_leaves: Vec::new(),
            updated_contract_layout_proofs: Vec::new(),
            updated_contract_id_to_index: HashMap::new(),
            updated_contract_leaves_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            updated_contract_code_definitions: Vec::new(),

            updates_file,
            pending_file_path: new_update_contract_file_path,
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        _tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        println!("update contract gatherer update_from_queue_item_with_tree with unique_pending_id: {}, proc_id: {}", self.unique_pending_id, self.pending_core_proc_id);

        if item.len() < PQEDContractLeafV2::<N::F, N::QHash>::FIXED_SIZE + 16 + 8 + 4 + 32 {
            // min size for an update with one leaf
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for UpdateContractGatherer: expected at least {}, got {}",
                PQEDContractLeafV2::<N::F, N::QHash>::FIXED_SIZE + 16 + 8 + 4 + 32,
                item.len()
            ));
        }
        let read_item = &mut &item[..];
        let update_contract_item: PsyUpdateContractQueueItem<N::F, N::QHash> =
            PsyUpdateContractQueueItem::<N::F, N::QHash>::pio_read_from_io(read_item)?;
        let contract_id = update_contract_item.contract_id;

        if self.updated_contract_id_to_index.contains_key(&contract_id) {
            return Err(anyhow::anyhow!(
                "UpdateContractGatherer contract id {} is already being updated in this block",
                contract_id
            ));
        }

        let (cfc_tree_root, contract_function_tree_leaves_ffs) =
            generate_single_merkle_node_blob_from_leaves_with_tree_height::<N::QHash, N::HasherBase>(contract_id, &update_contract_item.function_leaves, N::CONTRACT_FUNCTION_TREE_HEIGHT);
        if cfc_tree_root != update_contract_item.contract_leaf.function_tree_root {
            return Err(anyhow::anyhow!(
                "UpdateContractGatherer function tree root mismatch for contract id {}: expected {:?}, got {:?}",
                contract_id,
                update_contract_item.contract_leaf.function_tree_root,
                cfc_tree_root
            ));
        }

        // second (authoritative) validation against the in-memory global
        // contract tree: the edge handler checked against the last committed
        // checkpoint state, here we see the state including this block's
        // changes. The old leaf preimage comes from the core db (committed
        // state); the in-memory tree leaf hash check ensures it is not stale.
        let committed_checkpoint_id =
            self.shared_status.block_state.checkpoint_id;
        let old_contract_leaf = self
            .config
            .contract_leaf_reader
            .get_contract_leaf(committed_checkpoint_id, contract_id)
            .await
            .map_err(|_| anyhow::anyhow!("UpdateContractGatherer could not find existing contract leaf for contract id {}", contract_id))?;

        // validation only: the new leaf is applied at finalize time by
        // update_leaves_spider_man so the spiderman proofs see the pre-update
        // old leaves
        validate_contract_update::<N::HasherBase, N::F, N::QHash>(
            _tree,
            contract_id,
            &old_contract_leaf,
            &update_contract_item.contract_leaf,
        )?;

        let realm_identifier = self.config.get_realm_identifier();
        let unique_pending_id = self.unique_pending_id;

        tracing::info!("getting update contract code definition from temp db for pending id {} with rand key {:?}", unique_pending_id, &update_contract_item.rand_key_id);

        let contract_code_defintion_bytes: Option<Vec<u8>> = self
            .config
            .temp_db
            .get_deploy_contract_code_definition_raw(&realm_identifier, unique_pending_id, &update_contract_item.rand_key_id)
            .await?;

        if contract_code_defintion_bytes.is_none() {
            return Err(anyhow::anyhow!(
                "UpdateContractGatherer could not find contract code definition for rand key id {:?} in temp db",
                &update_contract_item.rand_key_id
            ));
        }
        let contract_code_definition = ContractCodeDefinition::pio_read_from_io(&mut &contract_code_defintion_bytes.unwrap()[..])?;
        let contract_code_definition_with_id = ContractCodeDefinitionWithContractId {
            contract_id,
            code_definition: contract_code_definition,
        };
        println!("UpdateContractGatherer updating contract id {}", contract_id);

        let old_contract_leaf_data_bytes = old_contract_leaf.psy_ser_to_bytes_vec()?;
        let new_contract_leaf_data_bytes = update_contract_item.contract_leaf.psy_ser_to_bytes_vec()?;

        // START: write contract id + old/new contract leaf data to file
        self.updates_file.write_u64_le(contract_id).await?;
        self.updates_file.write_all(&old_contract_leaf_data_bytes).await?;
        self.updates_file.write_all(&new_contract_leaf_data_bytes).await?;
        // END: write contract id + old/new contract leaf data to file

        // START: write function leaves count and leaves to file
        self.updates_file
            .write_u32_le(update_contract_item.function_leaves.len() as u32)
            .await?;
        for function_leaf in &update_contract_item.function_leaves {
            self.updates_file.write_all(&function_leaf.into_owned_32bytes()).await?;
        }
        // END: write function leaves count and leaves to file

        // START: write contract code definition length and data to file
        let contract_code_definition_bytes = contract_code_definition_with_id.psy_ser_to_bytes_vec()?;
        self.updates_file.write_u32_le(contract_code_definition_bytes.len() as u32).await?;
        self.updates_file.write_all(&contract_code_definition_bytes).await?;

        // END: write contract code definition length and data to file

        // START: update in-memory state
        self.updated_contract_id_to_index.insert(contract_id, self.updated_contract_ids.len());
        self.updated_contract_ids.push(contract_id);
        self.updated_contract_leaves.push((old_contract_leaf, update_contract_item.contract_leaf));
        self.updated_contract_layout_proofs
            .push(update_contract_item.canonical_layout_proof);
        self.updated_contract_leaves_ffs.extend_from_slice(&contract_id.to_le_bytes());
        self.updated_contract_leaves_ffs.extend_from_slice(&new_contract_leaf_data_bytes);
        self.update_contract_function_tree_nodes_ffs
            .extend_from_slice(&contract_function_tree_leaves_ffs);
        self.updated_contract_code_definitions.push(contract_code_definition_with_id);

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
                .shared_status
                .read()
                .map_err(|e| anyhow::anyhow!("error reading status {:?}", e))?
                .should_revert_last_changes
        };
        if needs_revert {
            {
                // drop any pending uncommitted changes, then restore the
                // original leaf values (covers the case where this block's
                // updates were committed into the tree mid-block)
                tree.revert_changes();
                for (contract_id, (old_leaf, _)) in self.updated_contract_ids.iter().zip(self.updated_contract_leaves.iter()) {
                    tree.set_leaf(*contract_id, old_leaf.qfhash::<N::HasherBase>());
                }
                tree.commit_changes();
            }
            self.reset_for_revert()?;

            // TODO: maybe we regenerate the job witnesses if we need to revert instead of
            // making the users resubmit
            if tree.get_root() != self.shared_status.last_committed_checkpoint_state_roots.contract_tree_root {
                return Err(anyhow::anyhow!(
                    "After revert, contract registration tree root mismatch: expected {:?}, got {:?}",
                    self.shared_status.last_committed_checkpoint_state_roots.contract_tree_root,
                    tree.get_root()
                ));
            }
            // remove the backup file since we are reverting
            //tokio::fs::remove_file(&self.pending_file_path).await?;
        }
        // flush before seeking to update num updated contracts
        //self.updates_file.flush().await?;

        let total_updated_contracts = self.updated_contract_ids.len() as u32;

        let start_state_root = tree.get_root();

        let pending_unique_id = self.shared_status.unique_pending_id;
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let update_contract_circuit_inputs = if self.updated_contract_ids.len() == 0 {
            vec![]
        } else {
            let new_leaf_hashes = self
                .updated_contract_leaves
                .iter()
                .map(|(_, new_leaf)| new_leaf.qfhash::<N::HasherBase>())
                .collect::<Vec<_>>();
            let spider_map_proofs =
                tree.update_leaves_spider_man(N::BATCH_CONTRACT_SUB_TREE_HEIGHT as u8, &self.updated_contract_ids, &new_leaf_hashes)?;

            // the proofs come back in ascending sub-tree order; assign the
            // changed leaf preimages of each sub-tree window to its proof
            let leaves_per_subtree = 1usize << (N::BATCH_CONTRACT_SUB_TREE_HEIGHT as u8);
            let mut sorted_indices = (0..self.updated_contract_ids.len()).collect::<Vec<_>>();
            sorted_indices.sort_by_key(|i| self.updated_contract_ids[*i]);

            let mut inputs = Vec::with_capacity(spider_map_proofs.len());
            let mut pos = 0usize;
            for proof in spider_map_proofs {
                let sub_tree_id = self.updated_contract_ids[sorted_indices[pos]] / leaves_per_subtree as u64;
                let mut old_contract_leaves = Vec::new();
                let mut new_contract_leaves = Vec::new();
                let mut updated_contract_ids = Vec::new();
                while pos < sorted_indices.len() && (self.updated_contract_ids[sorted_indices[pos]] / leaves_per_subtree as u64) == sub_tree_id {
                    let (old_leaf, new_leaf) = &self.updated_contract_leaves[sorted_indices[pos]];
                    old_contract_leaves.push(*old_leaf);
                    new_contract_leaves.push(*new_leaf);
                    updated_contract_ids.push(self.updated_contract_ids[sorted_indices[pos]]);
                    pos += 1;
                }
                let layout_update_proofs = sorted_indices
                    [(pos - old_contract_leaves.len())..pos]
                    .iter()
                    .map(|index| {
                        self.updated_contract_layout_proofs[*index].clone()
                    })
                    .collect();
                inputs.push(QCBatchUpdateContractsCircuitInput {
                    update_contract_circuit_whitelist: self.config.update_contract_circuit_whitelist,
                    spiderman_update_proof: proof,
                    updated_contract_ids,
                    old_contract_leaves,
                    new_contract_leaves,
                    layout_update_proofs,
                });
            }
            inputs
        };
        let (jobs_for_queue, job_temp_data) = plan_jobs_for_tree_agg_offset_root::<
            QProvingJobDataID,
            N::F,
            N::QHash,
            N::HasherBase,
            QCBatchUpdateContractsCircuitInput<N::F, N::QHash>,
            AggUpdateContractHelper,
        >(
            pending_unique_id,
            start_state_root,
            self.config.update_contract_circuit_whitelist,
            &update_contract_circuit_inputs,
            UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX,
            UPDATE_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL,
        )?;
        let total_jobs = jobs_for_queue.iter().map(|v| v.len()).sum::<usize>() as u64;
        self.updates_file.write_u64_le(total_jobs).await?;
        self.updates_file.seek(SeekFrom::Start(4 + 32)).await?;
        // UCB1 encodes integer fields in little-endian. Using `write_u32`
        // here writes big-endian and makes one update look like 16,777,216
        // updates to readers such as psy-services.
        self.updates_file.write_u32_le(total_updated_contracts).await?;
        // ensure the new total contracts length is flushed correctly
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.updates_file)
            .await?;

        let update_global_contract_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        //tree.commit_changes();

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;

        let first_updated_contract_id = self.updated_contract_ids.iter().min().copied().unwrap_or(0);
        let output_database = UpdateContractGathererOutputDatabase {
            start_global_contract_tree_root: start_state_root,
            updated_contract_ids: self.updated_contract_ids,
            updated_contract_leaves_ffs: self.updated_contract_leaves_ffs,
            update_contract_function_tree_nodes_ffs: self.update_contract_function_tree_nodes_ffs,
            updated_contract_code_definitions: self.updated_contract_code_definitions,
            total_jobs,
            end_global_contract_tree_root: tree.get_root(),
            global_contract_tree_update_pivot_siblings: tree.get_historical_pivot_leaf(first_updated_contract_id).siblings,
            update_global_contract_tree_nodes_ffs,
        };
        let output = UpdateContractGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };

        Ok(output)
    }
}

pub struct AggUpdateContractHelper {}
impl<F: Copy, Hash: Q256BitHash>
    BasicTreePlannerHelper<
        QProvingJobDataID,
        Hash,
        QCBatchUpdateContractsCircuitInput<F, Hash>,
        AggStateTransitionInputV2<Hash>,
        DummyAggStateTransition<Hash>,
    > for AggUpdateContractHelper
{
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(unique_checkpoint_id, 0, ProvingJobCircuitType::DummyBatchUpdateContractsAggregate, 0, 0)
            .get_input_witness_id()
    }

    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::BatchUpdateContractsAggregate,
            0,
            node_key.index as u32,
        )
        .get_input_witness_id()
    }

    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::BatchUpdateContracts,
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
        left: &QCBatchUpdateContractsCircuitInput<F, Hash>,
        right: &QCBatchUpdateContractsCircuitInput<F, Hash>,
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
        left: &QCBatchUpdateContractsCircuitInput<F, Hash>,
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
            right_input: AggStateTransitionWithStats {
                state_transition_start: right_state_transition.state_transition_start,
                state_transition_end: right_state_transition.state_transition_end,
                total_proofs_generated: 1,
            },
            left_proof_is_leaf: true,
            right_proof_is_leaf: false,
        }
    }

    fn create_agg_left_agg_right_leaf_witness(
        left: &AggStateTransitionInputV2<Hash>,
        right: &QCBatchUpdateContractsCircuitInput<F, Hash>,
    ) -> AggStateTransitionInputV2<Hash> {
        let right_state_transition = right.get_state_transition();
        let left_state_transition = left.condense_add_one();

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
            left_proof_is_leaf: false,
            right_proof_is_leaf: true,
        }
    }

    fn create_agg_to_agg_witness(left: &AggStateTransitionInputV2<Hash>, right: &AggStateTransitionInputV2<Hash>) -> AggStateTransitionInputV2<Hash> {
        let left_state_transition = left.condense_add_one();
        let right_state_transition = right.condense_add_one();

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
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{felt::FromPrimitiveValuesFelt, pgoldilocks::PoseidonHasher, protocol::core_types::Q256BitHash, utils::QPGenRandom, PHash, PF};

    use super::*;

    type Hash = PHash;
    type F = PF;
    type Hasher = PoseidonHasher;

    fn rand_contract_leaf(deployer: Hash, state_tree_height: u16) -> PQEDContractLeafV2<F, Hash> {
        PQEDContractLeafV2 {
            deployer,
            function_tree_root: Hash::qp_rand_gen(),
            code_root: Hash::qp_rand_gen(),
            state_tree_height: F::from_u16_value(state_tree_height),
            state_layout_root: Hash::default(),
            state_layout_field_count: F::default(),
            state_layout_slot_count: F::default(),
        }
    }

    fn deploy_contract(tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>, contract_id: u64, leaf: &PQEDContractLeafV2<F, Hash>) {
        tree.set_leaf(contract_id, leaf.qfhash::<Hasher>());
        tree.commit_changes();
    }

    #[test]
    fn test_update_after_deploy_succeeds() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        deploy_contract(&mut tree, 5, &old_leaf);

        let mut new_leaf = old_leaf;
        new_leaf.code_root = Hash::qp_rand_gen();
        new_leaf.function_tree_root = Hash::qp_rand_gen();

        // validation does not mutate the tree
        let new_leaf_hash = validate_contract_update::<Hasher, F, Hash>(&tree, 5, &old_leaf, &new_leaf)?;
        assert_eq!(tree.get_leaf_value(5), old_leaf.qfhash::<Hasher>());

        // the spiderman update proof applies the update and must carry the
        // real (non-zero) old leaves
        let proofs = tree.update_leaves_spider_man(2, &[5], &[new_leaf_hash])?;
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].web_proof_old_leaves[1], old_leaf.qfhash::<Hasher>());
        assert_eq!(proofs[0].web_proof_new_leaves[1], new_leaf_hash);
        assert_ne!(proofs[0].top_line_proof.old_root, proofs[0].top_line_proof.new_root);
        assert_eq!(tree.get_leaf_value(5), new_leaf_hash);
        Ok(())
    }

    #[test]
    fn test_update_nonexistent_contract_fails() -> anyhow::Result<()> {
        let tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        let new_leaf = rand_contract_leaf(deployer, 10);

        let result = validate_contract_update::<Hasher, F, Hash>(&tree, 7, &old_leaf, &new_leaf);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_update_with_wrong_deployer_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        deploy_contract(&mut tree, 3, &old_leaf);

        let mut new_leaf = old_leaf;
        new_leaf.deployer = Hash::qp_rand_gen();

        let result = validate_contract_update::<Hasher, F, Hash>(&tree, 3, &old_leaf, &new_leaf);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_update_with_stale_old_leaf_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        deploy_contract(&mut tree, 3, &old_leaf);

        // simulate a first update committed in the same block
        let mut newer_leaf = old_leaf;
        newer_leaf.code_root = Hash::qp_rand_gen();
        let newer_hash = validate_contract_update::<Hasher, F, Hash>(&tree, 3, &old_leaf, &newer_leaf)?;
        tree.set_leaf(3, newer_hash);
        tree.commit_changes();

        // a second update built from the now-stale original old leaf must fail
        let mut another_leaf = old_leaf;
        another_leaf.code_root = Hash::qp_rand_gen();
        let result = validate_contract_update::<Hasher, F, Hash>(&tree, 3, &old_leaf, &another_leaf);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_update_state_tree_height_change_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        deploy_contract(&mut tree, 3, &old_leaf);

        let mut new_leaf = old_leaf;
        new_leaf.state_tree_height = F::from_u16_value(12);

        let result = validate_contract_update::<Hasher, F, Hash>(&tree, 3, &old_leaf, &new_leaf);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_update_contract_id_zero_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf = rand_contract_leaf(deployer, 10);
        deploy_contract(&mut tree, 0, &old_leaf);

        let mut new_leaf = old_leaf;
        new_leaf.code_root = Hash::qp_rand_gen();

        // contract_id 0 is reserved for the audit sentinel and must not be updatable
        let result = validate_contract_update::<Hasher, F, Hash>(&tree, 0, &old_leaf, &new_leaf);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn test_revert_restores_original_root() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let deployer = Hash::qp_rand_gen();
        let old_leaf_a = rand_contract_leaf(deployer, 10);
        let old_leaf_b = rand_contract_leaf(deployer, 12);
        deploy_contract(&mut tree, 2, &old_leaf_a);
        deploy_contract(&mut tree, 9, &old_leaf_b);
        let committed_root = tree.get_root();

        // apply two updates (simulating mid-block commit by the tree manager)
        let mut new_leaf_a = old_leaf_a;
        new_leaf_a.code_root = Hash::qp_rand_gen();
        let mut new_leaf_b = old_leaf_b;
        new_leaf_b.code_root = Hash::qp_rand_gen();
        let new_hash_a = validate_contract_update::<Hasher, F, Hash>(&tree, 2, &old_leaf_a, &new_leaf_a)?;
        let new_hash_b = validate_contract_update::<Hasher, F, Hash>(&tree, 9, &old_leaf_b, &new_leaf_b)?;
        tree.set_leaf(2, new_hash_a);
        tree.set_leaf(9, new_hash_b);
        tree.commit_changes();
        assert_ne!(tree.get_root(), committed_root);

        // mirror of the gatherer finalize revert path
        tree.revert_changes();
        tree.set_leaf(2, old_leaf_a.qfhash::<Hasher>());
        tree.set_leaf(9, old_leaf_b.qfhash::<Hasher>());
        tree.commit_changes();

        assert_eq!(tree.get_root(), committed_root);
        assert_eq!(tree.get_leaf_value(2), old_leaf_a.qfhash::<Hasher>());
        assert_eq!(tree.get_leaf_value(9), old_leaf_b.qfhash::<Hasher>());
        Ok(())
    }
}
