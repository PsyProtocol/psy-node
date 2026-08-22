use std::{
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
    protocol::circuit_inputs::deploy_contracts::QCBatchDeployContractsCircuitInput,
    rewards_tree::offsets::{DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX, DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL},
    v1::qdata::{
        contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeaf, PsyDeployContractQueueItem},
        ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
    },
    worker::metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_io::tokio::{TokioFileLike, TokioLikeFileSystem};
use psy_node_core::{
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
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x44, 0x43, 0x42, 0x31]; // 'DCB1' in ASCII
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31424344; // 'DCB1' in little-endian u32

pub const MAX_DEPLOY_CONTRACTS_GATHERER_PER_BLOCK: usize = 2097152;
pub const DEPLOY_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH: usize = 10 * 1024 * 1024; // 10 MB

pub fn get_new_deploy_contract_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> String {
    PathBuf::from(backup_file_directory).join(format!(
        "deploy_contract_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    )).to_string_lossy().to_string()
}

pub async fn read_deploy_contract_gatherer_backup_file_path<
    Hasher: FieldQHasher<F, Hash>,
    Hash: QFHashBase<F> + QDBHashBase,
    F: QFelt64,
    FileSystem: TokioLikeFileSystem,
>(
    file_system: &FileSystem,
    file_path: &str,
    max_contract_function_tree_leaves: usize,
    tree: &mut SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<DeployContractGathererOutputDatabase<Hash>> {
    let mut file: FileSystem::File = file_system.file_like_fs_open(file_path).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();

    // ensure tree is up to date and pending changes are clean
    tree.commit_changes();

    if file_len < 4 + 8 + 32 + 4 + 8 {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }
    let magic = file.read_u32_le().await?;
    if magic != DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32,
            magic
        ));
    }
    let start_next_contract_id = file.read_u64_le().await?;
    if tree.get_leaf_value(start_next_contract_id) != Hasher::get_zero_hash(0) {
        return Err(anyhow::anyhow!(
            "Backup file start contract id {} does not match tree zero hash {:?}",
            start_next_contract_id,
            tree.get_leaf_value(start_next_contract_id)
        ));
    }
    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?;
    let start_root_hash = Hash::from_owned_32bytes(start_root_hash_bytes);

    let pivot_proof = tree.get_historical_pivot_leaf(start_next_contract_id);
    if pivot_proof.root != start_root_hash {
        return Err(anyhow::anyhow!(
            "Backup file start root hash {:?} does not match tree computed root hash {:?}",
            start_root_hash,
            pivot_proof.root
        ));
    }

    let num_new_contracts = (file.read_u32_le().await?) as usize;
    if num_new_contracts > MAX_DEPLOY_CONTRACTS_GATHERER_PER_BLOCK {
        return Err(anyhow::anyhow!(
            "Backup file num new contracts {} exceeds maximum {}",
            num_new_contracts,
            MAX_DEPLOY_CONTRACTS_GATHERER_PER_BLOCK
        ));
    }

    let mut update_contract_function_tree_nodes_ffs = Vec::<u8>::new();
    //let mut contract_function_leaves =
    // Vec::<Vec::<Hash>>::with_capacity(num_new_contracts);
    let mut new_contract_leaves_ffs = Vec::<u8>::with_capacity((num_new_contracts) * (PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF + 8));
    let mut new_contract_code_definitions = Vec::<ContractCodeDefinitionWithContractId>::with_capacity(num_new_contracts as usize);
    let mut contract_leaf_bytes: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];

    for i in 0..num_new_contracts {
        let contract_id = start_next_contract_id + (i as u64);

        // contract leaf data
        file.read_exact(&mut contract_leaf_bytes[..]).await?;
        let leaf: PQEDContractLeaf<F, Hash> = PQEDContractLeaf::<F, Hash>::pio_read_from_io(&mut &contract_leaf_bytes[..])?;
        let leaf_hash = leaf.qfhash::<Hasher>();
        tree.set_leaf(contract_id, leaf_hash);
        new_contract_leaves_ffs.extend_from_slice(&contract_id.to_le_bytes());
        new_contract_leaves_ffs.extend_from_slice(&contract_leaf_bytes);

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
        //contract_function_leaves.push(function_leaves);

        let (computed_contract_function_tree_root, contract_function_tree_ffs) =
            generate_single_merkle_node_blob_from_leaves::<Hash, Hasher>(contract_id, &function_leaves);
        if computed_contract_function_tree_root != leaf.function_tree_root {
            return Err(anyhow::anyhow!(
                "Backup file contract {} function tree root {:?} does not match computed root {:?}",
                contract_id,
                leaf.function_tree_root,
                computed_contract_function_tree_root
            ));
        }
        update_contract_function_tree_nodes_ffs.extend_from_slice(&contract_function_tree_ffs);

        // contract code definition
        let contract_code_definition_length = file.read_u32_le().await? as usize;
        if contract_code_definition_length > (DEPLOY_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH + 8) {
            // be forgiving and allow slightly larger with contract id
            return Err(anyhow::anyhow!(
                "Backup file contract {} code definition length {} exceeds maximum size {}",
                contract_id,
                contract_code_definition_length,
                DEPLOY_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH
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
        new_contract_code_definitions.push(contract_code_definition);
    }

    let end_root = tree.get_root();
    let next_contract_id = start_next_contract_id + num_new_contracts as u64;
    let mut update_global_contract_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len() * PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE);

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
        node.pio_write_to_io(&mut update_global_contract_tree_nodes_ffs)?;
    }
    let total_jobs = file.read_u64_le().await?;
    tree.commit_changes();

    let output_db = DeployContractGathererOutputDatabase {
        start_next_contract_id,
        start_global_contract_tree_root: start_root_hash,
        new_contract_leaves_ffs,
        update_contract_function_tree_nodes_ffs,
        new_contract_code_definitions,
        total_jobs,
        next_contract_id,
        end_global_contract_tree_root: end_root,
        global_contract_tree_update_pivot_siblings: pivot_proof.siblings,
        update_global_contract_tree_nodes_ffs,
    };

    Ok(output_db)
}

#[derive(Debug, Clone)]
pub struct DeployContractGathererOutputDatabase<Hash> {
    pub start_next_contract_id: u64,
    pub start_global_contract_tree_root: Hash,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,
    pub total_jobs: u64,

    // end backup format
    pub next_contract_id: u64,
    pub end_global_contract_tree_root: Hash,

    pub global_contract_tree_update_pivot_siblings: Vec<Hash>,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct DeployContractGathererOutput<Hash, JobId> {
    pub db_output: DeployContractGathererOutputDatabase<Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
pub struct DeployContractGathererConfig<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,

    pub shared_status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>>>,
    pub temp_db: Arc<TempDatabase>,
    pub backup_file_directory: String,
    pub deploy_contract_circuit_whitelist: N::QHash,
    pub last_job_next_contract_id: Arc<RwLock<u64>>,
    pub file_system: Arc<FileSystem>,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem> Clone
    for DeployContractGathererConfig<N, TempDatabase, FileSystem>
{
    fn clone(&self) -> Self {
        Self {
            realm_id_u64: self.realm_id_u64,
            realm_sub_id_u64: self.realm_sub_id_u64,
            shared_status: self.shared_status.clone(),
            temp_db: self.temp_db.clone(),
            backup_file_directory: self.backup_file_directory.clone(),
            deploy_contract_circuit_whitelist: self.deploy_contract_circuit_whitelist.clone(),
            last_job_next_contract_id: self.last_job_next_contract_id.clone(),
            file_system: self.file_system.clone(),
            _phantom_n: std::marker::PhantomData,
        }
    }
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    DeployContractGathererConfig<N, TempDatabase, FileSystem>
{
    pub fn get_realm_identifier(&self) -> QRealmIdentifier {
        QRealmIdentifier {
            realm_id: self.realm_id_u64 as u32,
            realm_sub_id: self.realm_sub_id_u64 as u16,
        }
    }
}
pub struct DeployContractGatherer<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
    FileSystem: TokioLikeFileSystem,
> {
    pub config: DeployContractGathererConfig<N, TempDatabase, FileSystem>,
    pub shared_status: PsyCoordinatorProcessorSharedStatus<N::F, N::QHash>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_leaves: Vec<PQEDContractLeaf<N::F, N::QHash>>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    pub unique_pending_id: u64,
    pub new_global_contract_tree_leaves: Vec<N::QHash>,
    pub new_contracts_file: FileSystem::File,
    pub pending_file_path: String,
    pub next_contract_id: u64,
}

impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>, FileSystem: TokioLikeFileSystem>
    DeployContractGatherer<N, TempDatabase, FileSystem>
{
    pub fn reset_for_revert(&mut self) -> anyhow::Result<()> {
        self.new_contract_leaves_ffs.clear();
        self.new_contract_leaves.clear();
        self.update_contract_function_tree_nodes_ffs.clear();
        self.new_contract_code_definitions.clear();
        self.new_global_contract_tree_leaves.clear();
        self.next_contract_id = self.shared_status.block_state.next_contract_id as u64;

        self.config
            .last_job_next_contract_id
            .write()
            .map_err(|e| anyhow::anyhow!("error writing last job next contract id {:?}", e))?
            .clone_from(&self.next_contract_id);

        Ok(())
    }
}
#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        FileSystem: TokioLikeFileSystem,
    >
    QueueGathererItemBuilderWithTree<
        DeployContractGathererConfig<N, TempDatabase, FileSystem>,
        SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
    > for DeployContractGatherer<N, TempDatabase, FileSystem>
{
    type Output = DeployContractGathererOutput<N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: DeployContractGathererConfig<N, TempDatabase, FileSystem>,
    ) -> anyhow::Result<Self> {
        let shared_status = config.shared_status.read().unwrap().clone();
        let new_deploy_contract_file_path = get_new_deploy_contract_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            shared_status.unique_pending_id,
        );

        println!("created contract gatherer with unique_pending_id: {}, proc_id: {}", shared_status.unique_pending_id, unique_id);
        let mut new_contracts_file: FileSystem::File = config
            .file_system
            .file_like_fs_create(&new_deploy_contract_file_path)
            .await?;
        let start_next_contract_id = config.last_job_next_contract_id.read().unwrap().clone();
        if tree.get_leaf_value(start_next_contract_id) != N::HasherBase::get_zero_hash(0) {
            return Err(anyhow::anyhow!(
                "Starting next contract id {} does not match tree zero hash {:?}",
                start_next_contract_id,
                tree.get_leaf_value(start_next_contract_id)
            ));
        }
        if start_next_contract_id != 0 {
            if tree.get_leaf_value(start_next_contract_id - 1) == N::HasherBase::get_zero_hash(0) {
                return Err(anyhow::anyhow!(
                    "The leaf before the next contract id {} minus one does not exist in tree, cannot continue",
                    start_next_contract_id - 1
                ));
            }
        }
        new_contracts_file.write_u32_le(DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32).await?;
        new_contracts_file.write_u64_le(start_next_contract_id).await?;
        new_contracts_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        new_contracts_file.write_u32_le(0).await?; // placeholder for num new contracts

        Ok(Self {
            config,
            unique_pending_id: shared_status.unique_pending_id,
            shared_status,
            pending_core_proc_id: unique_id,
            new_contract_leaves: Vec::new(),
            new_contract_leaves_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            new_contract_code_definitions: Vec::new(),
            new_global_contract_tree_leaves: Vec::new(),

            new_contracts_file,
            pending_file_path: new_deploy_contract_file_path,
            next_contract_id: start_next_contract_id,
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        _tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
                println!("update_from_queue_item_with_tree with unique_pending_id: {}, proc_id: {}", self.unique_pending_id, self.pending_core_proc_id);

        if item.len() < PQEDContractLeaf::<N::F, N::QHash>::FIXED_SIZE + 16 + 4 + 32 {
            // min size for a deploy with one leaf
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for DeployContractGatherer: expected at least {}, got {}",
                PQEDContractLeaf::<N::F, N::QHash>::FIXED_SIZE + 16 + 4 + 32,
                item.len()
            ));
        }
        let read_item = &mut &item[..];
        let deploy_contract_item: PsyDeployContractQueueItem<N::F, N::QHash> =
            PsyDeployContractQueueItem::<N::F, N::QHash>::pio_read_from_io(read_item)?;
        let contract_id = self.next_contract_id;

        let leaf_hash = deploy_contract_item.contract_leaf.qfhash::<N::HasherBase>();
        let contract_leaf_data_bytes = deploy_contract_item.contract_leaf.ffs_to_bytes();

        let realm_identifier = self.config.get_realm_identifier();
        let unique_pending_id = self.unique_pending_id;

        let (cfc_tree_root, contract_function_tree_leaves_ffs) =
            generate_single_merkle_node_blob_from_leaves_with_tree_height::<N::QHash, N::HasherBase>(contract_id, &deploy_contract_item.function_leaves, N::CONTRACT_FUNCTION_TREE_HEIGHT);
        if cfc_tree_root != deploy_contract_item.contract_leaf.function_tree_root {
            return Err(anyhow::anyhow!(
                "DeployContractGatherer function tree root mismatch for contract id {}: expected {:?}, got {:?}",
                contract_id,
                deploy_contract_item.contract_leaf.function_tree_root,
                cfc_tree_root
            ));
        }

        tracing::info!("getting deploy contract code definition from temp db for pending id {} with rand key {:?}", unique_pending_id, &deploy_contract_item.rand_key_id);

        let contract_code_defintion_bytes: Option<Vec<u8>> = self
            .config
            .temp_db
            .get_deploy_contract_code_definition_raw(&realm_identifier, unique_pending_id, &deploy_contract_item.rand_key_id)
            .await?;

        if contract_code_defintion_bytes.is_none() {
            return Err(anyhow::anyhow!(
                "DeployContractGatherer could not find contract code definition for rand key id {:?} in temp db",
                &deploy_contract_item.rand_key_id
            ));
        }
        let contract_code_definition = ContractCodeDefinition::pio_read_from_io(&mut &contract_code_defintion_bytes.unwrap()[..])?;
        let contract_code_definition_with_id = ContractCodeDefinitionWithContractId {
            contract_id,
            code_definition: contract_code_definition,
        };
        println!("DeployContractGatherer adding contract id {} with code state tree height {}", contract_id, contract_code_definition_with_id.code_definition.state_tree_height);
        // START: write contract leaf data to file
        self.new_contracts_file.write_all(&contract_leaf_data_bytes).await?;
        // END: write contract leaf data to file

        // START: write function leaves count and leaves to file
        self.new_contracts_file
            .write_u32_le(deploy_contract_item.function_leaves.len() as u32)
            .await?;
        for function_leaf in &deploy_contract_item.function_leaves {
            self.new_contracts_file.write_all(&function_leaf.into_owned_32bytes()).await?;
        }
        // END: write function leaves count and leaves to file

        // START: write contract code definition length and data to file
        let contract_code_definition_bytes = contract_code_definition_with_id.psy_ser_to_bytes_vec()?;
        self.new_contracts_file.write_u32_le(contract_code_definition_bytes.len() as u32).await?;
        self.new_contracts_file.write_all(&contract_code_definition_bytes).await?;

        // END: write contract code definition length and data to file

        // START: update in-memory state
        self.new_contract_leaves.push(deploy_contract_item.contract_leaf);
        self.new_contract_leaves_ffs.extend_from_slice(&contract_id.to_le_bytes());
        self.new_contract_leaves_ffs.extend_from_slice(&contract_leaf_data_bytes);
        self.new_global_contract_tree_leaves.push(leaf_hash);
        self.update_contract_function_tree_nodes_ffs
            .extend_from_slice(&contract_function_tree_leaves_ffs);
        self.new_contract_code_definitions.push(contract_code_definition_with_id);
        self.next_contract_id += 1;

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
            let new_next_contract_id = self.shared_status.block_state.next_contract_id as u64;
            {
                self.config
                    .last_job_next_contract_id
                    .write()
                    .map_err(|e| anyhow::anyhow!("error writing last job next contract id {:?}", e))?
                    .clone_from(&new_next_contract_id);
            }
            self.reset_for_revert()?;

            // TODO: maybe we regenerate the job witnesses if we need to revert instead of
            // making the users resubmit
            tree.revert_changes();
            tree.clear_changes_remove_committed_leaves_and_rehash(new_next_contract_id, self.next_contract_id);
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
        // flush before seeking to update num new contracts
        //self.new_contracts_file.flush().await?;

        let total_new_contracts = self.new_global_contract_tree_leaves.len() as u32;
      
        let start_state_root = tree.get_root();

        let pending_unique_id = self.shared_status.unique_pending_id;
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let deploy_contract_circuit_inputs = if self.new_global_contract_tree_leaves.len() == 0 {
            vec![]
        } else {
            // Where these leaves go is known, not discovered: `next_contract_id`
            // comes from the block state and has already been advanced past the
            // ones being appended.  Letting the tree look for the first empty
            // leaf instead is what put a deploy into sub-tree 0 while the next
            // free slot was 264 -- a frontier-loaded tree answers the leaves it
            // never loaded with the zero hash, and the search cannot tell that
            // from an empty slot.
            let append_index = self
                .next_contract_id
                .checked_sub(self.new_global_contract_tree_leaves.len() as u64)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "next contract id {} is below the {} leaves about to be appended",
                        self.next_contract_id,
                        self.new_global_contract_tree_leaves.len()
                    )
                })?;
            let spider_map_proofs = tree.append_leaves_spider_man_at_index(
                N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT as u8,
                append_index,
                &self.new_global_contract_tree_leaves,
            )?;
            // NOTE: I made a change in the DeployContractCircuit so we don't have to
            // provide the old contract leaves in the append proof, can just make them
            // anything
            let dummy_leaf = self.new_contract_leaves[0].clone();

            let mut inputs = Vec::with_capacity(spider_map_proofs.len());
            let mut contract_leaf_data_ind = 0;
            for (proof_index, proof) in spider_map_proofs.into_iter().enumerate() {
                let leaf_count = proof.get_modified_leaves_count();
                // The circuit decides `is_added` per position -- `old[i] !=
                // new[i]` -- while the vector built below assumes every
                // differing position is contiguous and starts right after the
                // leading run of equal ones.  Where those two disagree, a real
                // leaf lands in a slot the circuit believes holds a different
                // one, and witness generation dies on a copy constraint with
                // nothing but a wire number to say why.
                //
                // So the two views are compared here, where the data still has
                // names.  Silent when they agree, which is the ordinary case.
                {
                    let prepended =
                        proof.get_existing_prepended_leaves_count_including_non_zero();
                    let differing: Vec<usize> = proof
                        .web_proof_old_leaves
                        .iter()
                        .zip(proof.web_proof_new_leaves.iter())
                        .enumerate()
                        .filter(|(_, (old, new))| old != new)
                        .map(|(i, _)| i)
                        .collect();
                    let contiguous_from_prepended = differing
                        .iter()
                        .enumerate()
                        .all(|(offset, position)| *position == prepended + offset);
                    if !contiguous_from_prepended || differing.len() != leaf_count {
                        tracing::error!(
                            "[DEPLOY_BATCH] proof {proof_index}: the circuit and the witness \
                             disagree about which leaves are new. prepended={prepended} \
                             modified={leaf_count} differing_positions={differing:?} \
                             non_zero={} old_len={} new_len={} available_leaves={}",
                            proof.get_non_zero_leaves_count(),
                            proof.web_proof_old_leaves.len(),
                            proof.web_proof_new_leaves.len(),
                            self.new_contract_leaves.len() - contract_leaf_data_ind,
                        );
                    }
                }
                let prepend_leaves = (0..proof.get_existing_prepended_leaves_count_including_non_zero())
                    .map(|_| dummy_leaf.clone())
                    .collect::<Vec<_>>();
                let new_contract_leaves = self.new_contract_leaves[contract_leaf_data_ind..(contract_leaf_data_ind + leaf_count)].to_vec();
                let contract_leaves = [prepend_leaves, new_contract_leaves].concat();
                // The circuit joins the append proof's record of the subtree
                // root to the root it recomputes from the leaves, with a plain
                // `connect_hashes` on both the old and the new side.  Nothing
                // conditional about it: if the tree's internal nodes and its
                // leaves came from different branches, this is where it shows,
                // and it shows as a wire number.
                {
                    let recomputed_old = merkle_root_from_leaves::<N::HasherBase, N::QHash>(
                        &proof.web_proof_old_leaves,
                    );
                    let recomputed_new = merkle_root_from_leaves::<N::HasherBase, N::QHash>(
                        &proof.web_proof_new_leaves,
                    );
                    // Which side is stale cannot be told from the roots alone:
                    // the leaves in this proof come from the in-memory tree, so
                    // a memory that drifted from the database looks exactly like
                    // a database that is inconsistent with itself.  Printing a
                    // couple of leaves settles it against a direct read.
                    if recomputed_old != proof.top_line_proof.old_value {
                        for probe in [0usize, 250] {
                            if let Some(leaf) = proof.web_proof_old_leaves.get(probe) {
                                tracing::error!(
                                    "[DEPLOY_BATCH] proof {proof_index}: old leaf[{probe}] as the \
                                     in-memory tree has it = {leaf:?}"
                                );
                            }
                        }
                    }
                    if recomputed_old != proof.top_line_proof.old_value {
                        tracing::error!(
                            "[DEPLOY_BATCH] proof {proof_index}: the subtree's OLD leaves hash to \
                             {recomputed_old:?} but the append proof records the subtree root as \
                             {:?}; the tree's internal nodes and its leaves disagree",
                            proof.top_line_proof.old_value
                        );
                    }
                    if recomputed_new != proof.top_line_proof.new_value {
                        tracing::error!(
                            "[DEPLOY_BATCH] proof {proof_index}: the subtree's NEW leaves hash to \
                             {recomputed_new:?} but the append proof records the subtree root as \
                             {:?}",
                            proof.top_line_proof.new_value
                        );
                    }
                }
                // The exact quantity the circuit constrains: at every position
                // it considers added, the hash of the leaf data must equal the
                // leaf hash the append proof carries.  When it does not, witness
                // generation dies on a copy constraint that names a wire and
                // nothing else -- so the comparison is made here, where the
                // position and the leaf are still nameable.
                for (i, (old_leaf, new_leaf)) in proof
                    .web_proof_old_leaves
                    .iter()
                    .zip(proof.web_proof_new_leaves.iter())
                    .enumerate()
                {
                    if old_leaf == new_leaf {
                        continue;
                    }
                    let Some(leaf): Option<&PQEDContractLeaf<N::F, N::QHash>> =
                        contract_leaves.get(i)
                    else {
                        tracing::error!(
                            "[DEPLOY_BATCH] proof {proof_index}: position {i} is added but the \
                             witness has only {} leaves for it",
                            contract_leaves.len()
                        );
                        continue;
                    };
                    let hashed = leaf.qfhash::<N::HasherBase>();
                    if &hashed != new_leaf {
                        tracing::error!(
                            "[DEPLOY_BATCH] proof {proof_index}: position {i} is added, but the \
                             leaf hashes to {hashed:?} while the append proof says {new_leaf:?} \
                             (old there was {old_leaf:?}); leaf = {leaf:?}"
                        );
                    }
                }
                contract_leaf_data_ind += leaf_count;
                inputs.push(QCBatchDeployContractsCircuitInput {
                    deploy_contract_circuit_whitelist: self.config.deploy_contract_circuit_whitelist,
                    spiderman_append_proof: proof,
                    contract_leaves,
                });
            }
            inputs
        };
        let (jobs_for_queue, job_temp_data) = plan_jobs_for_tree_agg_offset_root::<
            QProvingJobDataID,
            N::F,
            N::QHash,
            N::HasherBase,
            QCBatchDeployContractsCircuitInput<N::F, N::QHash>,
            AggDeployContractHelper,
        >(
            pending_unique_id,
            start_state_root,
            self.config.deploy_contract_circuit_whitelist,
            &deploy_contract_circuit_inputs,
            DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX,
            DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL,
        )?;
        let total_jobs = jobs_for_queue.iter().map(|v| v.len()).sum::<usize>() as u64;
        self.new_contracts_file.write_u64_le(total_jobs).await?;
        self.new_contracts_file.seek(SeekFrom::Start(4 + 8 + 32)).await?;
        self.new_contracts_file.write_u32_le(total_new_contracts).await?;
        // ensure the new total contracts length is flushed correctly
        self.config
            .file_system
            .file_like_fs_flush_file_with_path(&self.pending_file_path, &mut self.new_contracts_file)
            .await?;

        let update_global_contract_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        //tree.commit_changes();

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;

        let start_next_contract_id = self.shared_status.block_state.next_contract_id as u64;
        let output_database = DeployContractGathererOutputDatabase {
            start_next_contract_id,
            start_global_contract_tree_root: start_state_root,
            new_contract_leaves_ffs: self.new_contract_leaves_ffs,
            update_contract_function_tree_nodes_ffs: self.update_contract_function_tree_nodes_ffs,
            new_contract_code_definitions: self.new_contract_code_definitions,
            total_jobs,
            next_contract_id: self.next_contract_id,
            end_global_contract_tree_root: tree.get_root(),
            global_contract_tree_update_pivot_siblings: tree.get_historical_pivot_leaf(start_next_contract_id).siblings,
            update_global_contract_tree_nodes_ffs,
        };
        let output = DeployContractGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };

        {
            self.config
                .last_job_next_contract_id
                .write()
                .map_err(|e| anyhow::anyhow!("error writing last job next contract id {:?}", e))?
                .clone_from(&self.next_contract_id);
        }
        Ok(output)
    }
}

pub struct AggDeployContractHelper {}
impl<F: Copy, Hash: Q256BitHash>
    BasicTreePlannerHelper<
        QProvingJobDataID,
        Hash,
        QCBatchDeployContractsCircuitInput<F, Hash>,
        AggStateTransitionInputV2<Hash>,
        DummyAggStateTransition<Hash>,
    > for AggDeployContractHelper
{
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(unique_checkpoint_id, 0, ProvingJobCircuitType::DummyBatchDeployContractsAggregate, 0, 0)
            .get_input_witness_id()
    }

    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::BatchDeployContractsAggregate,
            0,
            node_key.index as u32,
        )
        .get_input_witness_id()
    }

    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::BatchDeployContracts,
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
        left: &QCBatchDeployContractsCircuitInput<F, Hash>,
        right: &QCBatchDeployContractsCircuitInput<F, Hash>,
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
        left: &QCBatchDeployContractsCircuitInput<F, Hash>,
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
        right: &QCBatchDeployContractsCircuitInput<F, Hash>,
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

/// The root of a full binary tree over `leaves`, folded pairwise the way the
/// append gadget folds it.
///
/// Written out rather than borrowed from the tree store because the question is
/// whether the store agrees with its own leaves, and an answer that came from
/// the store could not tell.
fn merkle_root_from_leaves<Hasher, Hash>(leaves: &[Hash]) -> Hash
where
    Hash: Copy,
    Hasher: parth_core::crypto::hash::traits::MerkleHasher<Hash>,
{
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| Hasher::two_to_one(&pair[0], &pair[1]))
            .collect();
    }
    level[0]
}
