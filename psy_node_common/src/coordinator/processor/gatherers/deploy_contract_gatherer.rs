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
        contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeafV2, PsyDeployContractQueueItemV2, CONTRACT_LEAF_SERIALIZED_SIZE},
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
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_BYTES: [u8; 4] = [0x44, 0x43, 0x42, 0x31];
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32: u32 = 0x31424344;

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
    anyhow::ensure!(
        max_contract_function_tree_leaves.is_power_of_two(),
        "maximum contract function tree leaves must be a power of two"
    );
    let contract_function_tree_height = max_contract_function_tree_leaves.trailing_zeros() as u8;
    let mut file: FileSystem::File = file_system.file_like_fs_open(file_path).await?;
    let metadata = file.file_like_metadata().await?;
    let file_len = metadata.len();

    // ensure tree is up to date and pending changes are clean
    tree.commit_changes();

    if file_len < 4 + 8 + 32 + 4 + 8 {
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }
    let magic = file.read_u32_le().await?;
    if magic != DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32 {
        return Err(anyhow::anyhow!(
            "Backup file magic number mismatch: expected {:x}, got {:x}",
            DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32,
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
    let mut new_contract_leaves_ffs = Vec::<u8>::with_capacity((num_new_contracts) * (CONTRACT_LEAF_SERIALIZED_SIZE + 8));
    let mut new_contract_code_definitions = Vec::<ContractCodeDefinitionWithContractId>::with_capacity(num_new_contracts as usize);
    let mut contract_leaf_bytes: [u8; CONTRACT_LEAF_SERIALIZED_SIZE] = [0u8; CONTRACT_LEAF_SERIALIZED_SIZE];

    for i in 0..num_new_contracts {
        let contract_id = start_next_contract_id + (i as u64);

        // contract leaf data
        file.read_exact(&mut contract_leaf_bytes[..]).await?;
        let leaf: PQEDContractLeafV2<F, Hash> = PQEDContractLeafV2::<F, Hash>::pio_read_from_io(&mut &contract_leaf_bytes[..])?;
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
            generate_single_merkle_node_blob_from_leaves_with_tree_height::<Hash, Hasher>(
                contract_id,
                &function_leaves,
                contract_function_tree_height,
            );
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
    // Do not commit here: the update contract gatherer (when present) runs on
    // the same in-memory tree and its backup recovery relies on seeing the
    // deploy changes as part of tree.get_changes() so that its
    // update_global_contract_tree_nodes_ffs is the union of deploy + update
    // changes, matching normal operation.

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
    pub new_contract_leaves: Vec<PQEDContractLeafV2<N::F, N::QHash>>,
    pub new_contract_layout_proofs: Vec<Vec<u8>>,
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
        self.new_contract_layout_proofs.clear();
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
        new_contracts_file.write_u32_le(DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32).await?;
        new_contracts_file.write_u64_le(start_next_contract_id).await?;
        new_contracts_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        new_contracts_file.write_u32_le(0).await?; // placeholder for num new contracts

        Ok(Self {
            config,
            unique_pending_id: shared_status.unique_pending_id,
            shared_status,
            pending_core_proc_id: unique_id,
            new_contract_leaves: Vec::new(),
            new_contract_layout_proofs: Vec::new(),
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

        if item.len() < PQEDContractLeafV2::<N::F, N::QHash>::FIXED_SIZE + 16 + 4 + 32 {
            // min size for a deploy with one leaf
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for DeployContractGatherer: expected at least {}, got {}",
                PQEDContractLeafV2::<N::F, N::QHash>::FIXED_SIZE + 16 + 4 + 32,
                item.len()
            ));
        }
        let read_item = &mut &item[..];
        let deploy_contract_item: PsyDeployContractQueueItemV2<N::F, N::QHash> =
            PsyDeployContractQueueItemV2::<N::F, N::QHash>::pio_read_from_io(read_item)?;
        let contract_id = self.next_contract_id;

        let leaf_hash = deploy_contract_item.contract_leaf.qfhash::<N::HasherBase>();
        let contract_leaf_data_bytes = deploy_contract_item.contract_leaf.psy_ser_to_bytes_vec()?;

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
        self.new_contract_layout_proofs
            .push(deploy_contract_item.canonical_layout_proof);
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
        // `shared_status.block_state.next_contract_id` is the last committed
        // checkpoint and can lag behind `last_job_next_contract_id` while a
        // previous block is still being committed. Derive this batch's start
        // from the cursor that was actually used to assign the gathered IDs.
        let start_next_contract_id = self
            .next_contract_id
            .checked_sub(total_new_contracts as u64)
            .ok_or_else(|| anyhow::anyhow!("deploy contract id cursor underflow"))?;
      
        let start_state_root = tree.get_root();

        let pending_unique_id = self.shared_status.unique_pending_id;
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let deploy_contract_circuit_inputs = if self.new_global_contract_tree_leaves.len() == 0 {
            vec![]
        } else {
            let append_contract_id = start_next_contract_id;
            let appended_contract_ids =
                (append_contract_id
                    ..append_contract_id
                        + self.new_global_contract_tree_leaves.len()
                            as u64)
                    .collect::<Vec<_>>();
            for contract_id in &appended_contract_ids {
                anyhow::ensure!(
                    tree.get_leaf_value(*contract_id)
                        == N::HasherBase::get_zero_hash(0),
                    "deploy contract id {} is already occupied",
                    contract_id,
                );
            }
            // Proof generation mutates the recorder. Keep the coordinator's
            // live tree unchanged unless every generated proof validates.
            let mut candidate_tree = tree.clone();
            let spider_map_proofs =
                candidate_tree.update_leaves_spider_man(
                    N::BATCH_CONTRACT_SUB_TREE_HEIGHT as u8,
                    &appended_contract_ids,
                    &self.new_global_contract_tree_leaves,
                )?;
            let proof_batch_count = spider_map_proofs.len();
            let mut inputs = Vec::with_capacity(spider_map_proofs.len());
            let mut contract_leaf_data_ind = 0;
            println!(
                "BatchDeployContracts gatherer planning: pending_id={}, new_contracts={}, subtree_height={}, proof_batches={}, start_contract_id={}",
                pending_unique_id,
                self.new_global_contract_tree_leaves.len(),
                N::BATCH_CONTRACT_SUB_TREE_HEIGHT,
                proof_batch_count,
                start_next_contract_id,
            );
            for (batch_index, proof) in spider_map_proofs.into_iter().enumerate() {
                anyhow::ensure!(
                    proof.verify::<N::HasherBase>(),
                    "gatherer produced an invalid contract-tree Spiderman deploy proof at contract id {} batch {}",
                    append_contract_id,
                    batch_index,
                );
                let leaf_count = proof.get_modified_leaves_count();
                let contract_leaves = self.new_contract_leaves
                    [contract_leaf_data_ind..(contract_leaf_data_ind + leaf_count)]
                    .to_vec();
                let initial_layout_proofs = self.new_contract_layout_proofs
                    [contract_leaf_data_ind..(contract_leaf_data_ind + leaf_count)]
                    .to_vec();
                let contract_ids =
                    (start_next_contract_id
                        + contract_leaf_data_ind as u64
                        ..start_next_contract_id
                            + (contract_leaf_data_ind + leaf_count) as u64)
                        .collect::<Vec<_>>();
                println!(
                    "BatchDeployContracts gatherer batch {}/{}: leaf_count={}, data_offset={}, ids={:?}, leaves_len={}, layout_proofs_len={}, layout_proof_bytes={:?}, spiderman_old_leaves_len={}, spiderman_new_leaves_len={}, top_line_index={}",
                    batch_index + 1,
                    proof_batch_count,
                    leaf_count,
                    contract_leaf_data_ind,
                    contract_ids,
                    contract_leaves.len(),
                    initial_layout_proofs.len(),
                    initial_layout_proofs
                        .iter()
                        .map(|layout_proof| layout_proof.len())
                        .collect::<Vec<_>>(),
                    proof.web_proof_old_leaves.len(),
                    proof.web_proof_new_leaves.len(),
                    proof.top_line_proof.index,
                );
                contract_leaf_data_ind += leaf_count;
                inputs.push(QCBatchDeployContractsCircuitInput {
                    deploy_contract_circuit_whitelist: self.config.deploy_contract_circuit_whitelist,
                    spiderman_append_proof: proof,
                    contract_ids,
                    contract_leaves,
                    initial_layout_proofs,
                });
            }
            println!(
                "BatchDeployContracts gatherer planning completed: inputs={}, consumed_contracts={}, expected_contracts={}",
                inputs.len(),
                contract_leaf_data_ind,
                self.new_global_contract_tree_leaves.len(),
            );
            *tree = candidate_tree;
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

/// Tests for the backup-file reader and the full
/// `QueueGathererItemBuilderWithTree` implementation, running fully offline
/// against the in-memory temp store and mock file system.
#[cfg(test)]
mod gatherer_builder_tests {
    use std::sync::{Arc, RwLock};

    use parth_core::{
        felt::FromPrimitiveValuesFelt,
        pgoldilocks::PoseidonHasher,
        protocol::core_types::QNetworkTreeConstants,
        utils::QPGenRandom,
        PHash, PF,
    };
    use psy_data::v1::qdata::{
        checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
        contract::ContractCodeDefinition,
    };
    use psy_node_core::{
        file::memory_fs::SimpleMockMemoryFileSystem,
        psy_temp_db::QTempDBDeployContractDataWriter,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    use crate::test_common::TestNetworkConfig;

    use super::*;

    type N = TestNetworkConfig;
    type Hash = PHash;
    type F = PF;
    type Hasher = PoseidonHasher;
    type TempDb = InMemoryTempStore;
    type Fs = SimpleMockMemoryFileSystem;

    const REALM_ID: u64 = 1;
    const REALM_SUB_ID: u64 = 2;
    const UNIQUE_PENDING_ID: u64 = 700;

    fn zh(level: usize) -> Hash {
        PoseidonHasher::get_zero_hash(level)
    }

    /// `unwrap_err` needs the Ok type to be Debug; the gatherer is not.
    fn err_str<T>(result: anyhow::Result<T>) -> String {
        match result {
            Ok(_) => panic!("expected the call to fail, but it succeeded"),
            Err(e) => e.to_string(),
        }
    }

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

    fn function_leaves() -> Vec<Hash> {
        vec![Hash::qp_rand_gen(), Hash::qp_rand_gen()]
    }

    /// Root exactly the way the gatherer WRITER computes it (full height 16).
    fn fn_tree_root_full_height(contract_id: u64, leaves: &[Hash]) -> Hash {
        generate_single_merkle_node_blob_from_leaves_with_tree_height::<Hash, Hasher>(
            contract_id,
            leaves,
            N::CONTRACT_FUNCTION_TREE_HEIGHT,
        )
        .0
    }

    fn block_state() -> QEDL2BlockState {
        QEDL2BlockState {
            checkpoint_id: 0,
            next_add_withdrawal_id: 0,
            next_process_withdrawal_id: 0,
            next_deposit_id: 0,
            total_deposits_claimed_epoch: 0,
            next_user_id: 0,
            end_balance: 0,
            next_contract_id: 0,
        }
    }

    fn shared_status(contract_tree_root: Hash, should_revert: bool) -> Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>> {
        Arc::new(RwLock::new(PsyCoordinatorProcessorSharedStatus {
            last_committed_checkpoint_id: 0,
            unique_pending_id: UNIQUE_PENDING_ID,
            last_committed_checkpoint_leaf: PQEDCheckpointLeaf::qp_rand_gen(),
            last_committed_checkpoint_state_roots: PQEDCheckpointGlobalStateRoots {
                contract_tree_root,
                deposit_tree_root: zh(2),
                user_tree_root: zh(3),
                withdrawal_tree_root: zh(2),
                user_registration_tree_root: zh(3),
            },
            should_revert_last_changes: should_revert,
            block_state: block_state(),
        }))
    }

    fn test_config(
        status: Arc<RwLock<PsyCoordinatorProcessorSharedStatus<F, Hash>>>,
        temp_db: Arc<TempDb>,
        fs: Arc<Fs>,
        last_job_next_contract_id: Arc<RwLock<u64>>,
    ) -> DeployContractGathererConfig<N, TempDb, Fs> {
        DeployContractGathererConfig {
            realm_id_u64: REALM_ID,
            realm_sub_id_u64: REALM_SUB_ID,
            shared_status: status,
            temp_db,
            backup_file_directory: "gatherer_backups".to_string(),
            deploy_contract_circuit_whitelist: zh(23),
            last_job_next_contract_id,
            file_system: fs,
            _phantom_n: std::marker::PhantomData,
        }
    }

    async fn seed_code_definition(temp_db: &TempDb, rand_key_id: &[u8; 16]) -> anyhow::Result<()> {
        temp_db
            .set_deploy_contract_code_definition_raw(
                &QRealmIdentifier { realm_id: REALM_ID as u32, realm_sub_id: REALM_SUB_ID as u16 },
                UNIQUE_PENDING_ID,
                rand_key_id,
                ContractCodeDefinition { state_tree_height: 10, functions: vec![] }.psy_ser_to_bytes_vec()?,
            )
            .await?;
        Ok(())
    }

    fn deploy_item_bytes(
        contract_leaf: PQEDContractLeafV2<F, Hash>,
        leaves: Vec<Hash>,
        rand_key_id: [u8; 16],
    ) -> anyhow::Result<Vec<u8>> {
        let item = PsyDeployContractQueueItemV2::<F, Hash> {
            rand_key_id,
            contract_leaf,
            function_leaves: leaves,
            layout_protocol_version: 1,
            canonical_layout_verifier_fingerprint: Hash::default(),
            canonical_layout_proof: vec![1, 2, 3, 4],
        };
        item.psy_ser_to_bytes_vec()
    }

    #[test]
    fn backup_file_path_contains_realm_and_pending_ids() {
        let path = get_new_deploy_contract_gatherer_backup_file_path("/tmp/backups", 4, 6, 99);
        assert!(path.starts_with("/tmp/backups"));
        assert!(path.ends_with("deploy_contract_gatherer_realm_4_sub_6_pending_99.backup"));
    }

    #[tokio::test]
    async fn read_backup_rejects_header_level_errors() -> anyhow::Result<()> {
        let fs = SimpleMockMemoryFileSystem::new();
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);

        // below the minimum header size of 4 + 8 + 32 + 4 + 8 bytes
        fs.files.insert("too_small".to_string(), vec![0u8; 55]);
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "too_small", 4, &mut tree).await);
        assert!(err.to_string().contains("too small to be valid"), "got: {err}");

        // wrong magic
        let mut bad_magic = Vec::new();
        bad_magic.extend_from_slice(&0x31424358u32.to_le_bytes());
        bad_magic.extend_from_slice(&[0u8; 52]);
        fs.files.insert("bad_magic".to_string(), bad_magic);
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "bad_magic", 4, &mut tree).await);
        assert!(err.to_string().contains("magic number mismatch"), "got: {err}");

        // start contract id already occupied in the tree
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let existing = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        tree.set_leaf(2, existing.qfhash::<Hasher>());
        tree.commit_changes();
        let mut occupied = Vec::new();
        occupied.extend_from_slice(&DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32.to_le_bytes());
        occupied.extend_from_slice(&2u64.to_le_bytes());
        occupied.extend_from_slice(&[0u8; 44]);
        fs.files.insert("occupied".to_string(), occupied);
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "occupied", 4, &mut tree).await);
        assert!(err.to_string().contains("does not match tree zero hash"), "got: {err}");

        // start root that does not match the computed pivot root
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let existing = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        tree.set_leaf(1, existing.qfhash::<Hasher>());
        tree.commit_changes();
        let mut wrong_root = Vec::new();
        wrong_root.extend_from_slice(&DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32.to_le_bytes());
        wrong_root.extend_from_slice(&2u64.to_le_bytes());
        wrong_root.extend_from_slice(&Hash::qp_rand_gen().into_owned_32bytes());
        wrong_root.extend_from_slice(&[0u8; 36]);
        fs.files.insert("wrong_root".to_string(), wrong_root);
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "wrong_root", 4, &mut tree).await);
        assert!(err.to_string().contains("does not match tree computed root hash"), "got: {err}");

        // contract count above the per-block maximum
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let mut too_many = Vec::new();
        too_many.extend_from_slice(&DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32.to_le_bytes());
        too_many.extend_from_slice(&0u64.to_le_bytes());
        too_many.extend_from_slice(&tree.get_root().into_owned_32bytes());
        too_many.extend_from_slice(&((MAX_DEPLOY_CONTRACTS_GATHERER_PER_BLOCK + 1) as u32).to_le_bytes());
        too_many.extend_from_slice(&[0u8; 8]);
        fs.files.insert("too_many".to_string(), too_many);
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "too_many", 4, &mut tree).await);
        assert!(err.to_string().contains("exceeds maximum"), "got: {err}");
        Ok(())
    }

    /// Serializes one deployed contract record (leaf + function leaves + code
    /// definition) for a crafted backup body.
    fn backup_contract_body(
        leaf: &PQEDContractLeafV2<F, Hash>,
        function_leaves: &[Hash],
        contract_id: u64,
    ) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&leaf.psy_ser_to_bytes_vec()?);
        bytes.extend_from_slice(&(function_leaves.len() as u32).to_le_bytes());
        for leaf_hash in function_leaves {
            bytes.extend_from_slice(&leaf_hash.into_owned_32bytes());
        }
        let code_with_id = ContractCodeDefinitionWithContractId {
            contract_id,
            code_definition: ContractCodeDefinition { state_tree_height: 10, functions: vec![] },
        };
        let code_bytes = code_with_id.psy_ser_to_bytes_vec()?;
        bytes.extend_from_slice(&(code_bytes.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&code_bytes);
        Ok(bytes)
    }

    fn backup_with_body(start_next_contract_id: u64, start_root: Hash, count: u32, body: &[u8], total_jobs: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DEPLOY_CONTRACT_GATHERER_BACKUP_MAGIC_U32.to_le_bytes());
        bytes.extend_from_slice(&start_next_contract_id.to_le_bytes());
        bytes.extend_from_slice(&start_root.into_owned_32bytes());
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(body);
        bytes.extend_from_slice(&total_jobs.to_le_bytes());
        bytes
    }

    #[tokio::test]
    async fn read_backup_happy_path_deploys_two_contracts() -> anyhow::Result<()> {
        let fs = SimpleMockMemoryFileSystem::new();
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();

        let leaf_a = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        let leaf_b = rand_contract_leaf(Hash::qp_rand_gen(), 12);
        let leaves_a = function_leaves();
        let leaves_b = function_leaves();
        // Model a backup produced by the writer, which always computes the
        // function tree at the configured protocol height.
        let mut leaf_a = leaf_a;
        leaf_a.function_tree_root = fn_tree_root_full_height(0, &leaves_a);
        let mut leaf_b = leaf_b;
        leaf_b.function_tree_root = fn_tree_root_full_height(1, &leaves_b);

        let mut body = backup_contract_body(&leaf_a, &leaves_a, 0)?;
        body.extend_from_slice(&backup_contract_body(&leaf_b, &leaves_b, 1)?);
        fs.files.insert("good".to_string(), backup_with_body(0, start_root, 2, &body, 5));

        let output = read_deploy_contract_gatherer_backup_file_path(
            &fs,
            "good",
            1 << N::CONTRACT_FUNCTION_TREE_HEIGHT,
            &mut tree,
        )
        .await?;
        assert_eq!(output.start_next_contract_id, 0);
        assert_eq!(output.next_contract_id, 2);
        assert_eq!(output.start_global_contract_tree_root, start_root);
        assert_eq!(output.end_global_contract_tree_root, tree.get_root());
        assert_ne!(output.end_global_contract_tree_root, start_root);
        assert_eq!(output.total_jobs, 5);
        assert_eq!(output.new_contract_code_definitions.len(), 2);
        assert_eq!(output.new_contract_code_definitions[0].contract_id, 0);
        assert_eq!(output.new_contract_code_definitions[1].contract_id, 1);
        assert_eq!(output.new_contract_leaves_ffs.len(), 2 * (8 + CONTRACT_LEAF_SERIALIZED_SIZE));
        assert!(!output.update_contract_function_tree_nodes_ffs.is_empty());
        assert!(!output.update_global_contract_tree_nodes_ffs.is_empty());
        assert!(!output.global_contract_tree_update_pivot_siblings.is_empty());
        // the leaves were applied to the in-memory tree (left uncommitted)
        assert_eq!(tree.get_leaf_value(0), leaf_a.qfhash::<Hasher>());
        assert_eq!(tree.get_leaf_value(1), leaf_b.qfhash::<Hasher>());
        assert!(!tree.get_changes().is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn read_backup_rejects_malformed_contract_records() -> anyhow::Result<()> {
        let fs = SimpleMockMemoryFileSystem::new();

        // zero function leaves
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        let leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        let body = backup_contract_body(&leaf, &[], 0)?;
        fs.files.insert("zero_fn".to_string(), backup_with_body(0, start_root, 1, &body, 0));
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "zero_fn", 4, &mut tree).await);
        assert!(err.to_string().contains("function leaves count cannot be zero"), "got: {err}");

        // more function leaves than the allowed maximum
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        let leaves = vec![Hash::qp_rand_gen(); 3];
        let body = backup_contract_body(&leaf, &leaves, 0)?;
        fs.files.insert("too_many_fn".to_string(), backup_with_body(0, start_root, 1, &body, 0));
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "too_many_fn", 2, &mut tree).await);
        assert!(err.to_string().contains("function leaves count 3 exceeds maximum 2"), "got: {err}");

        // function tree root that does not match the serialized leaves
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        let leaves = function_leaves();
        let body = backup_contract_body(&leaf, &leaves, 0)?;
        fs.files.insert("bad_fn_root".to_string(), backup_with_body(0, start_root, 1, &body, 0));
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "bad_fn_root", 4, &mut tree).await);
        assert!(err.to_string().contains("function tree root"), "got: {err}");

        // zero-length code definition
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        let leaves = function_leaves();
        let mut leaf = leaf;
        leaf.function_tree_root =
            generate_single_merkle_node_blob_from_leaves_with_tree_height::<Hash, Hasher>(0, &leaves, 2).0;
        let mut body = Vec::new();
        body.extend_from_slice(&leaf.psy_ser_to_bytes_vec()?);
        body.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
        for leaf_hash in &leaves {
            body.extend_from_slice(&leaf_hash.into_owned_32bytes());
        }
        body.extend_from_slice(&0u32.to_le_bytes());
        fs.files.insert("zero_code".to_string(), backup_with_body(0, start_root, 1, &body, 0));
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "zero_code", 4, &mut tree).await);
        assert!(err.to_string().contains("code definition length cannot be zero"), "got: {err}");

        // code definition carrying a different contract id
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        let body = backup_contract_body(&leaf, &leaves, 9)?;
        fs.files.insert("bad_code_id".to_string(), backup_with_body(0, start_root, 1, &body, 0));
        let err = err_str(read_deploy_contract_gatherer_backup_file_path(&fs, "bad_code_id", 4, &mut tree).await);
        assert!(err.to_string().contains("does not match expected id"), "got: {err}");

        // empty backup (count 0) succeeds and reports no changes
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let start_root = tree.get_root();
        fs.files.insert("empty".to_string(), backup_with_body(3, start_root, 0, &[], 8));
        let output = read_deploy_contract_gatherer_backup_file_path(&fs, "empty", 4, &mut tree).await?;
        assert_eq!(output.next_contract_id, 3);
        assert_eq!(output.start_next_contract_id, 3);
        assert_eq!(output.total_jobs, 8);
        assert!(output.new_contract_leaves_ffs.is_empty());
        assert_eq!(output.end_global_contract_tree_root, start_root);
        Ok(())
    }

    #[tokio::test]
    async fn create_new_validates_tree_cursor_state() -> anyhow::Result<()> {
        let temp_db = Arc::new(InMemoryTempStore::new("deploy_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());

        // start id already occupied: leaf 0 exists but the cursor still points at 0
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let existing = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        tree.set_leaf(0, existing.qfhash::<Hasher>());
        tree.commit_changes();
        let config = test_config(
            shared_status(tree.get_root(), false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::new(RwLock::new(0u64)),
        );
        let err = err_str(DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await);
        assert!(err.to_string().contains("does not match tree zero hash"), "got: {err}");

        // gap behind the cursor: cursor at 3 but the tree is empty, so leaf 2
        // does not exist
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let config = test_config(
            shared_status(tree.get_root(), false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::new(RwLock::new(3u64)),
        );
        let err = err_str(DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await);
        assert!(err.to_string().contains("minus one does not exist in tree"), "got: {err}");

        // valid cursor: one deployed contract, cursor at 1
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        tree.set_leaf(0, existing.qfhash::<Hasher>());
        tree.commit_changes();
        let committed_root = tree.get_root();
        let config = test_config(
            shared_status(committed_root, false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::new(RwLock::new(1u64)),
        );
        let gatherer = DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await?;
        assert_eq!(gatherer.next_contract_id, 1);
        assert_eq!(gatherer.unique_pending_id, UNIQUE_PENDING_ID);
        assert!(gatherer.pending_file_path.ends_with("deploy_contract_gatherer_realm_1_sub_2_pending_700.backup"));
        Ok(())
    }

    #[tokio::test]
    async fn builder_assigns_sequential_ids_and_finalizes() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let committed_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("deploy_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let last_job_next_contract_id = Arc::new(RwLock::new(0u64));
        seed_code_definition(&temp_db, &[1u8; 16]).await?;
        seed_code_definition(&temp_db, &[2u8; 16]).await?;

        let config = test_config(
            shared_status(committed_root, false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::clone(&last_job_next_contract_id),
        );
        assert_eq!(config.get_realm_identifier().realm_id, 1);
        assert_eq!(config.get_realm_identifier().realm_sub_id, 2);

        let mut gatherer = DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let leaves_a = function_leaves();
        let mut leaf_a = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        leaf_a.function_tree_root = fn_tree_root_full_height(0, &leaves_a);
        let leaves_b = function_leaves();
        let mut leaf_b = rand_contract_leaf(Hash::qp_rand_gen(), 12);
        leaf_b.function_tree_root = fn_tree_root_full_height(1, &leaves_b);
        let item_a = deploy_item_bytes(leaf_a.clone(), leaves_a, [1u8; 16])?;
        let item_b = deploy_item_bytes(leaf_b.clone(), leaves_b, [2u8; 16])?;

        gatherer.update_from_many_queue_items_with_tree(&mut tree, vec![item_a, item_b]).await?;
        assert_eq!(gatherer.next_contract_id, 2);
        assert_eq!(gatherer.new_contract_leaves.len(), 2);
        // the tree only changes at finalize
        assert_eq!(tree.get_leaf_value(0), zh(0));
        assert_eq!(tree.get_leaf_value(1), zh(0));

        let output = DeployContractGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        assert_eq!(output.db_output.start_next_contract_id, 0);
        assert_eq!(output.db_output.next_contract_id, 2);
        assert_eq!(output.db_output.start_global_contract_tree_root, committed_root);
        assert_ne!(output.db_output.end_global_contract_tree_root, committed_root);
        assert_eq!(tree.get_leaf_value(0), leaf_a.qfhash::<Hasher>());
        assert_eq!(tree.get_leaf_value(1), leaf_b.qfhash::<Hasher>());
        assert_eq!(output.db_output.new_contract_code_definitions.len(), 2);
        assert!(!output.job_ids.is_empty());
        assert!(output.db_output.total_jobs >= 1);
        // the shared cursor advanced past the deployed contracts
        assert_eq!(*last_job_next_contract_id.read().unwrap(), 2);

        // backup file flushed with the real count patched at the fixed offset
        let backup_path = get_new_deploy_contract_gatherer_backup_file_path("gatherer_backups", 1, 2, 700);
        let bytes = fs.files.get(&backup_path).unwrap().value().clone();
        assert_eq!(u64::from_le_bytes(bytes[4..12].try_into()?), 0);
        assert_eq!(u32::from_le_bytes(bytes[44..48].try_into()?), 2);
        Ok(())
    }

    #[tokio::test]
    async fn builder_rejects_invalid_queue_items() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let temp_db = Arc::new(InMemoryTempStore::new("deploy_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        seed_code_definition(&temp_db, &[1u8; 16]).await?;

        let config = test_config(
            shared_status(tree.get_root(), false),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::new(RwLock::new(0u64)),
        );
        let mut gatherer = DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        // undersized item
        let err = err_str(gatherer.update_from_queue_item_with_tree(&mut tree, vec![0u8; 16]).await);
        assert!(err.to_string().contains("Invalid queue item size"), "got: {err}");

        // function tree root that does not match the serialized leaves
        let leaves = function_leaves();
        let bad_fn_leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        let item = deploy_item_bytes(bad_fn_leaf, leaves, [1u8; 16])?;
        let err = err_str(gatherer.update_from_queue_item_with_tree(&mut tree, item).await);
        assert!(err.to_string().contains("function tree root mismatch"), "got: {err}");

        // missing code definition in the temp db: the memory temp store errors
        // on the missing key before the gatherer's own not-found branch
        let leaves = function_leaves();
        let mut leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        leaf.function_tree_root = fn_tree_root_full_height(0, &leaves);
        let item = deploy_item_bytes(leaf, leaves, [9u8; 16])?;
        let err = err_str(gatherer.update_from_queue_item_with_tree(&mut tree, item).await);
        assert!(err.to_string().contains("deploy contract code definition not found"), "got: {err}");

        // nothing was recorded for the failed items
        assert_eq!(gatherer.next_contract_id, 0);
        assert!(gatherer.new_contract_leaves.is_empty());
        assert!(gatherer.new_contract_leaves_ffs.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn finalize_revert_restores_empty_tree_and_cursors() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let committed_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("deploy_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        let last_job_next_contract_id = Arc::new(RwLock::new(0u64));
        seed_code_definition(&temp_db, &[1u8; 16]).await?;

        let config = test_config(
            shared_status(committed_root, true),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::clone(&last_job_next_contract_id),
        );
        let mut gatherer = DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let leaves = function_leaves();
        let mut leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        leaf.function_tree_root = fn_tree_root_full_height(0, &leaves);
        let item = deploy_item_bytes(leaf, leaves, [1u8; 16])?;
        gatherer.update_from_queue_item_with_tree(&mut tree, item).await?;

        // simulate the deployed leaf being applied to the tree as a pending
        // (uncommitted) change, which is the state the revert branch is
        // designed for: revert_changes drops it and the committed root returns
        tree.set_leaf(0, leaf.qfhash::<Hasher>());
        assert_ne!(tree.get_root(), committed_root);

        let output = DeployContractGatherer::finalize_with_tree(gatherer, &mut tree).await?;
        assert!(output.db_output.new_contract_leaves_ffs.is_empty());
        assert_eq!(output.db_output.next_contract_id, 0);
        assert_eq!(output.db_output.end_global_contract_tree_root, committed_root);
        // the tree is emptied back to the committed state
        assert_eq!(tree.get_root(), committed_root);
        assert_eq!(tree.get_leaf_value(0), zh(0));
        // both cursors were reset to the committed next contract id
        assert_eq!(*last_job_next_contract_id.read().unwrap(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn finalize_revert_with_wrong_committed_root_fails() -> anyhow::Result<()> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(24);
        let committed_root = tree.get_root();

        let temp_db = Arc::new(InMemoryTempStore::new("deploy_gatherer_test".to_string(), 1, 2));
        let fs = Arc::new(SimpleMockMemoryFileSystem::new());
        seed_code_definition(&temp_db, &[1u8; 16]).await?;

        // the shared status claims a different last committed contract root
        let config = test_config(
            shared_status(Hash::qp_rand_gen(), true),
            Arc::clone(&temp_db),
            Arc::clone(&fs),
            Arc::new(RwLock::new(0u64)),
        );
        let mut gatherer = DeployContractGatherer::create_new_with_tree(&mut tree, 55, config).await?;

        let leaves = function_leaves();
        let mut leaf = rand_contract_leaf(Hash::qp_rand_gen(), 10);
        leaf.function_tree_root = fn_tree_root_full_height(0, &leaves);
        let item = deploy_item_bytes(leaf, leaves, [1u8; 16])?;
        gatherer.update_from_queue_item_with_tree(&mut tree, item).await?;

        let err = err_str(DeployContractGatherer::finalize_with_tree(gatherer, &mut tree).await);
        assert!(err.to_string().contains("tree root mismatch"), "got: {err}");
        assert_eq!(tree.get_root(), committed_root);
        Ok(())
    }
}
