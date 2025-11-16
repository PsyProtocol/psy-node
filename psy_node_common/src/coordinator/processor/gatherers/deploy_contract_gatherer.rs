use std::{
    io::SeekFrom,
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
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::{
        spiderman::SpidermanUpdateProof,
        traits::{FieldQHasher, MerkleZeroHasher, QFieldHashable},
    },
    data::{
        db::hash_id_u64::{get_data_buffer_for_hash256_and_u64s, QHash256AndU64},
        hash::merkle_node_key::{SimpleMerkleNode, SimpleMerkleNodeKey, PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE},
    },
    felt::QFelt64,
    node::realm_identifier::QRealmIdentifier,
    protocol::core_types::{Q256BitHash, QDBHashBase, QFHashBase, QNetworkTypesConfig},
    QCoreProcCheckpointUniqueId,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    agg::{
        AggStateTrackableInput, AggStateTransitionInputV2, AggStateTransitionWithStats, DummyAggStateTransition, tree_agg_v2::{BasicTreePlannerHelper, plan_jobs_for_tree_agg, plan_jobs_for_tree_agg_offset_root}
    }, protocol::circuit_inputs::{
        append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput, deploy_contracts::QCBatchDeployContractsCircuitInput,
    }, rewards_tree::offsets::{DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_INDEX, DEPLOY_CONTRACTS_REWARDS_TREE_OFFSET_ROOT_LEVEL}, v1::qdata::{
        contract::{ContractCodeDefinition, ContractCodeDefinitionWithContractId, PQEDContractLeaf, PsyDeployContractQueueItem},
        ffs_sizes::PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF,
        public_key::PZKPublicKeyInfo,
    }, worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId}
};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase,
    qblob::data_views::{
        single_merkle_node_batch::generate_single_merkle_node_blob_from_leaves, zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
    },
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalDatabaseSerializeBaseSingle, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;
pub const MAX_DEPLOY_CONTRACTS_GATHERER_PER_BLOCK: usize = 2097152;
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_BYTES: [u8; 4] = [0x44, 0x43, 0x42, 0x31];
pub const DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32: u32 = 0x31424344;
pub const DEPLOY_CONTRACT_GATHERER_MAX_CONTRACT_CODE_DEFINITION_LENGTH: usize = 10 * 1024 * 1024; // 10 MB
pub fn get_new_deploy_contract_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> PathBuf {
    PathBuf::from(backup_file_directory).join(format!(
        "deploy_contract_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    ))
}

pub async fn read_deploy_contract_gatherer_backup_file<Hasher: FieldQHasher<F, Hash>, Hash: QFHashBase<F> + QDBHashBase, F: QFelt64>(
    file_path: &PathBuf,
    max_contract_function_tree_leaves: usize,
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<(DeployContractGathererOutputDatabase<Hash>, SimpleMemoryMerkleRecorderStore<Hasher, Hash>)> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let metadata = file.metadata().await?;
    let file_len = metadata.len();

    // ensure tree is up to date and pending changes are clean
    tree.commit_changes();

    if file_len < 4 + 8 + 32 + 4 {
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
    let mut new_contract_leaves_ffs = Vec::<u8>::with_capacity((num_new_contracts) * PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF);
    let mut new_contract_code_definitions = Vec::<ContractCodeDefinitionWithContractId>::with_capacity(num_new_contracts as usize);
    let mut contract_leaf_bytes: [u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF] = [0u8; PSY_OBJECT_FFS_SIZE_CONTRACT_LEAF];

    for i in 0..num_new_contracts {
        let contract_id = start_next_contract_id + (i as u64);

        // contract leaf data
        file.read_exact(&mut contract_leaf_bytes[..]).await?;
        let leaf: PQEDContractLeaf<F, Hash> = PQEDContractLeaf::<F, Hash>::pio_read_from_io(&mut &contract_leaf_bytes[..])?;
        let leaf_hash = leaf.qfhash::<Hasher>();
        tree.set_leaf(contract_id, leaf_hash);
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
    tree.commit_changes();

    let output_db = DeployContractGathererOutputDatabase {
        start_next_contract_id,
        start_global_contract_tree_root: start_root_hash,
        new_contract_leaves_ffs,
        update_contract_function_tree_nodes_ffs,
        new_contract_code_definitions,
        next_contract_id,
        end_global_contract_tree_root: end_root,
        global_contract_tree_update_pivot_siblings: pivot_proof.siblings,
        update_global_contract_tree_nodes_ffs,
    };

    Ok((output_db, tree))
}

pub struct DeployContractGathererOutputDatabase<Hash> {
    pub start_next_contract_id: u64,
    pub start_global_contract_tree_root: Hash,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    // end backup format
    pub next_contract_id: u64,
    pub end_global_contract_tree_root: Hash,

    pub global_contract_tree_update_pivot_siblings: Vec<Hash>,
    pub update_global_contract_tree_nodes_ffs: Vec<u8>,
}

pub struct DeployContractGathererOutput<Hash, JobId> {
    pub db_output: DeployContractGathererOutputDatabase<Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
pub struct DeployContractGathererConfig<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub start_next_contract_id: Arc<AtomicU64>,
    pub pending_unique_id: Arc<AtomicU64>,
    pub last_checkpoint_id: Arc<AtomicU64>,
    pub temp_db: Arc<TempDatabase>,
    pub backup_file_directory: String,
    pub deploy_contract_circuit_whitelist: N::QHash,

    pub _phantom_n: std::marker::PhantomData<N>,
}
impl<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> DeployContractGathererConfig<N, TempDatabase> {
    pub fn new(
        realm_id_u64: u64,
        realm_sub_id_u64: u64,
        start_next_contract_id: Arc<AtomicU64>,
        pending_unique_id: Arc<AtomicU64>,
        last_checkpoint_id: Arc<AtomicU64>,
        temp_db: Arc<TempDatabase>,
        backup_file_directory: String,
        deploy_contract_circuit_whitelist: N::QHash,
    ) -> Self {
        Self {
            realm_id_u64,
            realm_sub_id_u64,
            start_next_contract_id,
            pending_unique_id,
            last_checkpoint_id,
            temp_db,
            backup_file_directory,
            deploy_contract_circuit_whitelist,
            _phantom_n: std::marker::PhantomData,
        }
    }
    pub fn get_realm_identifier(&self) -> QRealmIdentifier {
        QRealmIdentifier {
            realm_id: self.realm_id_u64 as u32,
            realm_sub_id: self.realm_sub_id_u64 as u16,
        }
    }
    pub fn get_pending_unique_id(&self) -> u64 {
        self.pending_unique_id.load(Ordering::Relaxed)
    }
}
pub struct DeployContractGatherer<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
    pub config: DeployContractGathererConfig<N, TempDatabase>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub new_contract_leaves_ffs: Vec<u8>,
    pub new_contract_leaves: Vec<PQEDContractLeaf<N::F, N::QHash>>,
    pub update_contract_function_tree_nodes_ffs: Vec<u8>,
    pub new_contract_code_definitions: Vec<ContractCodeDefinitionWithContractId>,

    pub new_global_contract_tree_leaves: Vec<N::QHash>,
    pub new_contracts_file: tokio::fs::File,
    pub pending_file_path: String,
    pub next_contract_id: u64,
}

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    > QueueGathererItemBuilderWithTree<DeployContractGathererConfig<N, TempDatabase>, SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>>
    for DeployContractGatherer<N, TempDatabase>
{
    type Output = DeployContractGathererOutput<N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: DeployContractGathererConfig<N, TempDatabase>,
    ) -> anyhow::Result<Self> {
        let new_deploy_contract_file_path = get_new_deploy_contract_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            config.pending_unique_id.load(std::sync::atomic::Ordering::Relaxed),
        );
        let mut new_contracts_file = tokio::fs::File::create(&new_deploy_contract_file_path).await?;
        let start_next_contract_id = config.start_next_contract_id.load(Ordering::Relaxed);
        new_contracts_file.write_u32_le(DEPLOY_CONTRACT_GATHERER_BACKUP_V1_MAGIC_U32).await?;
        new_contracts_file.write_u64_le(start_next_contract_id).await?;
        new_contracts_file.write_all(&tree.get_root().into_owned_32bytes()).await?;
        new_contracts_file.write_u32_le(0).await?; // placeholder for num new contracts

        Ok(Self {
            config,
            pending_core_proc_id: unique_id,
            new_contract_leaves: Vec::new(),
            new_contract_leaves_ffs: Vec::new(),
            update_contract_function_tree_nodes_ffs: Vec::new(),
            new_contract_code_definitions: Vec::new(),
            new_global_contract_tree_leaves: Vec::new(),

            new_contracts_file,
            pending_file_path: new_deploy_contract_file_path.to_string_lossy().to_string(),
            next_contract_id: start_next_contract_id,
        })
    }
    async fn update_from_queue_item_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        if item.len() <= PQEDContractLeaf::<N::F, N::QHash>::FIXED_SIZE + 16 + 4 + 32 {
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
        let unique_pending_id = self.config.get_pending_unique_id();

        let (cfc_tree_root, contract_function_tree_leaves_ffs) =
            generate_single_merkle_node_blob_from_leaves::<N::QHash, N::HasherBase>(contract_id, &deploy_contract_item.function_leaves);
        if cfc_tree_root != deploy_contract_item.contract_leaf.function_tree_root {
            return Err(anyhow::anyhow!(
                "DeployContractGatherer function tree root mismatch for contract id {}: expected {:?}, got {:?}",
                contract_id,
                deploy_contract_item.contract_leaf.function_tree_root,
                cfc_tree_root
            ));
        }

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
        // flush before seeking to update num new contracts
        self.new_contracts_file.flush().await?;

        let total_new_contracts = self.new_global_contract_tree_leaves.len() as u32;
        self.new_contracts_file.seek(SeekFrom::Start(4 + 8 + 32)).await?;
        self.new_contracts_file.write_u32(total_new_contracts).await?;
        // ensure the new total contracts length is flushed correctly
        self.new_contracts_file.flush().await?;

        let start_state_root = tree.get_root();

        let pending_unique_id = self.config.pending_unique_id.load(Ordering::Relaxed);
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let deploy_contract_circuit_inputs = if self.new_global_contract_tree_leaves.len() == 0 {
            vec![]
        } else {
            let spider_map_proofs =
                tree.append_leaves_spider_man(N::BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT as u8, &self.new_global_contract_tree_leaves)?;
            // NOTE: I made a change in the DeployContractCircuit so we don't have to provide the old contract leaves in the append proof, can just make them anything
            let dummy_leaf = self.new_contract_leaves[0].clone();

            let mut inputs = Vec::with_capacity(spider_map_proofs.len());
            let mut contract_leaf_data_ind = 0;
            for proof in spider_map_proofs {
                let leaf_count = proof.get_non_zero_leaves_count();
                let prepend_leaves = (0..proof.get_existing_prepended_leaves_count()).map(|_| dummy_leaf.clone()).collect::<Vec<_>>();
                let new_contract_leaves = self.new_contract_leaves[contract_leaf_data_ind..(contract_leaf_data_ind + leaf_count)].to_vec();
                let contract_leaves = [prepend_leaves, new_contract_leaves].concat();
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

        let update_global_contract_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        tree.commit_changes();

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;

        let start_next_contract_id = self.config.start_next_contract_id.load(Ordering::Relaxed);
        let output_database = DeployContractGathererOutputDatabase {
            start_next_contract_id,
            start_global_contract_tree_root: start_state_root,
            new_contract_leaves_ffs: self.new_contract_leaves_ffs,
            update_contract_function_tree_nodes_ffs: self.update_contract_function_tree_nodes_ffs,
            new_contract_code_definitions: self.new_contract_code_definitions,
            next_contract_id: self.next_contract_id,
            end_global_contract_tree_root: tree.get_root(),
            global_contract_tree_update_pivot_siblings: tree.get_historical_pivot_leaf(start_next_contract_id).siblings,
            update_global_contract_tree_nodes_ffs,
        };
        let output = DeployContractGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };
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
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            0,
            ProvingJobCircuitType::DummyBatchDeployContractsAggregate,
            0,
            0,
        )
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
        let right_state_transition = right.condense();

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
        let left_state_transition = left.condense();

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
        let left_state_transition = left.condense();
        let right_state_transition = right.condense();

        AggStateTransitionInputV2 {
            left_input: left_state_transition,
            right_input: right_state_transition,
            left_proof_is_leaf: false,
            right_proof_is_leaf: false,
        }
    }
}
