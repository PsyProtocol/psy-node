use std::{path::PathBuf, sync::{Arc, RwLock, atomic::{AtomicU64, Ordering}}};

use psy_core::job::job_id::QProvingJobDataID;
use psy_serialize::{FastFixedSerializable, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{QCoreProcCheckpointUniqueId, crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher}, data::{db::hash_id_u64::{QHash256AndU64, get_data_buffer_for_hash256_and_u64s}, hash::merkle_node_key::{PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE, SimpleMerkleNode}}, protocol::core_types::{Q256BitHash, QDBHashBase, QNetworkTypesConfig}};
use psy_node_core::psy_temp_db::StandardProcessorTempDBStoreBase;
use psy_data::{protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput, v1::qdata::public_key::PZKPublicKeyInfo, worker::metadata::PsyProvingJobMetadata};
use async_trait::async_trait;
use crate::queue::gatherer_builder::QueueGathererItemBuilderWithTree;

pub fn get_new_register_user_gatherer_backup_file_path(
    backup_file_directory: &str,
    realm_id_u64: u64,
    realm_sub_id_u64: u64,
    pending_unique_id: u64,
) -> PathBuf {
    PathBuf::from(backup_file_directory).join(format!(
        "register_user_gatherer_realm_{}_sub_{}_pending_{}.backup",
        realm_id_u64, realm_sub_id_u64, pending_unique_id
    ))
}

fn hash_two_from_slice<Hash: Q256BitHash, Hasher: MerkleZeroHasher<Hash>>(data: &[u8]) -> Hash {
    assert_eq!(data.len(), 64);
    let left = Hash::from_owned_32bytes(
        data[0..32].try_into().expect("Slice with incorrect length"),
    );
    let right = Hash::from_owned_32bytes(
        data[32..64].try_into().expect("Slice with incorrect length"),
    );
    Hasher::two_to_one(&left, &right)
}

pub async fn read_register_user_gatherer_backup_file<Hasher: MerkleZeroHasher<Hash>, Hash: QDBHashBase>(
    file_path: &PathBuf,
    mut tree: SimpleMemoryMerkleRecorderStore<Hasher, Hash>,
) -> anyhow::Result<(RegisterUserGathererOutputDatabase<Hash>, SimpleMemoryMerkleRecorderStore<Hasher, Hash>)> {
    let mut file = tokio::fs::File::open(file_path).await?;
    let metadata = file.metadata().await?;
    let file_len = metadata.len();
    if file_len < 8 + 32 {
        return Err(anyhow::anyhow!(
            "Backup file too small to be valid: {} bytes",
            metadata.len()
        ));
    }

    let file_len_without_metadata = file_len-8-32;
    if file_len_without_metadata % (64 as u64) != 0 {
        return Err(anyhow::anyhow!(
            "Backup file length without metadata is not a multiple of 64: {} bytes",
            file_len_without_metadata
        ));
    }

    let expected_count= file_len_without_metadata / (64 as u64);
    let start_next_user_id = file.read_u64().await?;
    if tree.get_leaf_value(start_next_user_id) != Hasher::get_zero_hash(0) {
        return Err(anyhow::anyhow!(
            "Backup file start user id {} does not match tree zero hash {:?}",
            start_next_user_id,
            tree.get_leaf_value(start_next_user_id)
        ));
    }
    let mut start_root_hash_bytes = [0u8; 32];
    file.read_exact(&mut start_root_hash_bytes).await?;
    let start_root_hash = Hash::from_owned_32bytes(start_root_hash_bytes);


    let pivot_proof = tree.get_historical_pivot_leaf(start_next_user_id);
    if pivot_proof.root != start_root_hash {
        return Err(anyhow::anyhow!(
            "Backup file start root hash {:?} does not match tree computed root hash {:?}",
            start_root_hash,
            pivot_proof.root
        ));
    }


    let mut new_user_public_keys_ffs = Vec::with_capacity(file_len_without_metadata as usize);
    file.read_exact(&mut new_user_public_keys_ffs).await?;
    let mut new_public_key_hash_to_user_id_rows = Vec::with_capacity(expected_count as usize);

    let mut new_leaf_hashes = Vec::with_capacity(expected_count as usize);
    for i in 0..expected_count {
        let offset = (i * 64) as usize;
        let leaf_hash = hash_two_from_slice::<Hash, Hasher>(&new_user_public_keys_ffs[offset..offset + 64]);
        new_public_key_hash_to_user_id_rows.push(QHash256AndU64{
            hash: leaf_hash,
            value_u64: start_next_user_id + i,
        });
        tree.set_leaf(start_next_user_id+i, leaf_hash);
        new_leaf_hashes.push(leaf_hash);
    }

    let new_public_key_hash_to_user_id_rows_ffs = get_data_buffer_for_hash256_and_u64s(&new_public_key_hash_to_user_id_rows);

    let end_root = tree.get_root();
    let next_user_id = start_next_user_id + expected_count;
    let mut update_user_registration_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len());

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode {
            key: *key,
            value: *hash,
        };
        node.pio_write_to_io(&mut update_user_registration_tree_nodes_ffs)?;
    }
    let output_db = RegisterUserGathererOutputDatabase {
        start_next_user_id,
        start_user_registration_tree_hash: start_root_hash,
        new_user_public_keys_ffs,
        next_user_id,
        end_user_registration_tree_hash: end_root,
        user_registration_tree_update_pivot_siblings: pivot_proof.siblings,
        new_public_key_hash_to_user_id_rows_ffs,
        update_user_registration_tree_nodes_ffs,
    };
    Ok((output_db, tree))
}
pub struct RegisterUserGathererConfig<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
> {
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub start_next_user_id: Arc<AtomicU64>,
    pub pending_unique_id: Arc<AtomicU64>,
    pub last_checkpoint_id: Arc<AtomicU64>,
    pub temp_db: Arc<TempDatabase>,
    pub backup_file_directory: String,
    pub register_users_circuit_whitelist: N::QHash,
    
    pub _phantom_n: std::marker::PhantomData<N>,
}
pub struct RegisterUserGatherer<
    N: QNetworkTypesConfig,
    TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>,
> {
    pub config: RegisterUserGathererConfig<N, TempDatabase>,
    pub pending_core_proc_id: QCoreProcCheckpointUniqueId,
    pub new_user_public_keys_ffs: Vec<u8>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub new_user_registration_tree_leaves: Vec<N::QHash>,
    pub new_user_public_keys_file: tokio::fs::File,
    pub pending_file_path: String,
    pub next_user_id: u64,

}


pub struct RegisterUserGathererOutputDatabase<Hash> {
    pub start_next_user_id: u64,
    pub start_user_registration_tree_hash: Hash,
    pub new_user_public_keys_ffs: Vec<u8>,
    // end backup format
    pub next_user_id: u64,
    pub end_user_registration_tree_hash: Hash,
    pub user_registration_tree_update_pivot_siblings: Vec<Hash>,
    pub new_public_key_hash_to_user_id_rows_ffs: Vec<u8>,
    pub update_user_registration_tree_nodes_ffs: Vec<u8>,
}


pub struct RegisterUserGathererOutput<Hash, JobId> {
    pub db_output: RegisterUserGathererOutputDatabase<Hash>,
    pub job_ids: Vec<Vec<PsyProvingJobMetadata<Hash, JobId>>>,
}
#[async_trait]
impl<N: QNetworkTypesConfig<JobId = QProvingJobDataID>, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static> QueueGathererItemBuilderWithTree<RegisterUserGathererConfig<N, TempDatabase>, SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>> for RegisterUserGatherer<N, TempDatabase>  {
    type Output= RegisterUserGathererOutput<N::QHash, N::JobId>;


    async fn create_new_with_tree(tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>, unique_id: QCoreProcCheckpointUniqueId, config: RegisterUserGathererConfig<N, TempDatabase>) -> anyhow::Result<Self>{

        let new_user_public_keys_file_path = get_new_register_user_gatherer_backup_file_path(
            &config.backup_file_directory,
            config.realm_id_u64,
            config.realm_sub_id_u64,
            config.pending_unique_id.load(std::sync::atomic::Ordering::Relaxed),
        );
        let mut new_user_public_keys_file = tokio::fs::File::create(&new_user_public_keys_file_path).await?;
        let start_next_user_id = config.start_next_user_id.load(Ordering::Relaxed);
        new_user_public_keys_file.write_u64(start_next_user_id).await?;
        new_user_public_keys_file.write_all(&tree.get_root().into_owned_32bytes()).await?;

        
        
        Ok(Self{
            config,
            pending_core_proc_id: unique_id,
            new_user_public_keys_ffs: Vec::new(),
            new_public_key_hash_to_user_id_rows_ffs: Vec::new(),
            new_user_registration_tree_leaves: Vec::new(),
            new_user_public_keys_file,
            pending_file_path: new_user_public_keys_file_path.to_string_lossy().to_string(),
            next_user_id: start_next_user_id,
        })

    }
    async fn update_from_queue_item_with_tree(&mut self, tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>, item: Vec<u8>) -> anyhow::Result<()>{
        if item.len() != PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE || PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE != 64 { // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for RegisterUserGatherer: expected {}, got {}",
                PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE,
                item.len()
            ));
        }
        self.new_user_public_keys_ffs.extend_from_slice(&item);
        let hash = hash_two_from_slice::<N::QHash, N::HasherBase>(&item);
        let u64_hash_mapping_row = QHash256AndU64{
            hash,
            value_u64: self.next_user_id,
        };
        self.new_public_key_hash_to_user_id_rows_ffs.extend_from_slice(&u64_hash_mapping_row.ffs_to_bytes());

        self.next_user_id += 1;
        self.new_user_registration_tree_leaves.push(hash);

        Ok(())
    }
    async fn update_from_many_queue_items_with_tree(&mut self, tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>, items: Vec<Vec<u8>>) -> anyhow::Result<()>{
        for item in items {
            self.update_from_queue_item_with_tree(tree, item).await?;
        }
        Ok(())
    }
    async fn finalize_with_tree(self, tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>) -> anyhow::Result<Self::Output>{


        if self.new_user_registration_tree_leaves.len() == 0 {
            todo!("handle empty case with a dummy");
        }else{
            let spider_map_proofs = tree.append_leaves_spider_man(N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT as u8, &self.new_user_registration_tree_leaves)?;
            let spider_man_groups = spider_map_proofs.chunks(N::BATCH_USER_REGISTRATION_MAX_SUB_TREES).map(|chunk| QCAppendUserRegistrationTreeCircuitInput{ register_users_circuit_whitelist: self.config.register_users_circuit_whitelist, spiderman_append_proofs: chunk.to_vec()}).collect::<Vec<_>>();

            for (i, group) in spider_man_groups.iter().enumerate(){

            }

            //let job_ids: Vec<Vec<PsyProvingJobMetadata<N::QHash, N::JobId>>> = (0..spider_man_groups.len()).map(|group_index| {
              //  let job_id = 




        }
        todo!("implement this");
    }
}