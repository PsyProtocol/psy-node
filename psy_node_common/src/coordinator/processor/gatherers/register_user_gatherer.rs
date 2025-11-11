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
use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
use parth_core::{
    crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher},
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
        tree_agg_v2::{plan_jobs_for_tree_agg, BasicTreePlannerHelper},
        AggStateTrackableInput, AggStateTransitionInputV2, AggStateTransitionWithStats, DummyAggStateTransition,
    },
    protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput,
    v1::qdata::public_key::PZKPublicKeyInfo,
    worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId},
};
use psy_node_core::{
    psy_temp_db::StandardProcessorTempDBStoreBase, qblob::data_views::zero_merkle_node_batch::create_ffs_merkle_nodes_zero_id_from_hash_map,
};
use psy_serialize::{FastFixedSerializable, PsyCanonicalSerializeMetadata, PsyIOReadWrite};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
    let left = Hash::from_owned_32bytes(data[0..32].try_into().expect("Slice with incorrect length"));
    let right = Hash::from_owned_32bytes(data[32..64].try_into().expect("Slice with incorrect length"));
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
        return Err(anyhow::anyhow!("Backup file too small to be valid: {} bytes", metadata.len()));
    }

    let file_len_without_metadata = file_len - 8 - 32;
    if file_len_without_metadata % (64 as u64) != 0 {
        return Err(anyhow::anyhow!(
            "Backup file length without metadata is not a multiple of 64: {} bytes",
            file_len_without_metadata
        ));
    }

    let expected_count = file_len_without_metadata / (64 as u64);
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
        new_public_key_hash_to_user_id_rows.push(QHash256AndU64 {
            hash: leaf_hash,
            value_u64: start_next_user_id + i,
        });
        tree.set_leaf(start_next_user_id + i, leaf_hash);
        new_leaf_hashes.push(leaf_hash);
    }

    let new_public_key_hash_to_user_id_rows_ffs = get_data_buffer_for_hash256_and_u64s(&new_public_key_hash_to_user_id_rows);

    let end_root = tree.get_root();
    let next_user_id = start_next_user_id + expected_count;
    let mut update_user_registration_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len());

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
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
pub struct RegisterUserGathererConfig<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
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
pub struct RegisterUserGatherer<N: QNetworkTypesConfig, TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash>> {
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
    pub job_ids: Vec<Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>>,
}
#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        TempDatabase: StandardProcessorTempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    > QueueGathererItemBuilderWithTree<RegisterUserGathererConfig<N, TempDatabase>, SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>>
    for RegisterUserGatherer<N, TempDatabase>
{
    type Output = RegisterUserGathererOutput<N::QHash, N::JobId>;

    async fn create_new_with_tree(
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        unique_id: QCoreProcCheckpointUniqueId,
        config: RegisterUserGathererConfig<N, TempDatabase>,
    ) -> anyhow::Result<Self> {
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

        Ok(Self {
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
    async fn update_from_queue_item_with_tree(
        &mut self,
        tree: &mut SimpleMemoryMerkleRecorderStore<N::HasherBase, N::QHash>,
        item: Vec<u8>,
    ) -> anyhow::Result<()> {
        if item.len() != PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE || PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE != 64 {
            // added sanity check
            return Err(anyhow::anyhow!(
                "Invalid queue item size for RegisterUserGatherer: expected {}, got {}",
                PZKPublicKeyInfo::<N::QHash>::FIXED_SIZE,
                item.len()
            ));
        }
        self.new_user_public_keys_ffs.extend_from_slice(&item);
        let hash = hash_two_from_slice::<N::QHash, N::HasherBase>(&item);
        let u64_hash_mapping_row = QHash256AndU64 {
            hash,
            value_u64: self.next_user_id,
        };
        self.new_public_key_hash_to_user_id_rows_ffs
            .extend_from_slice(&u64_hash_mapping_row.ffs_to_bytes());

        self.next_user_id += 1;
        self.new_user_registration_tree_leaves.push(hash);

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
        self.new_user_public_keys_file.flush().await?;

        let start_state_root = tree.get_root();

        let pending_unique_id = self.config.pending_unique_id.load(Ordering::Relaxed);
        let realm_identifier = QRealmIdentifier {
            realm_id: self.config.realm_id_u64 as u32,
            realm_sub_id: self.config.realm_sub_id_u64 as u16,
        };

        let spider_man_groups = if self.new_user_registration_tree_leaves.len() == 0 {
            vec![]
        } else {
            let spider_map_proofs =
                tree.append_leaves_spider_man(N::BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT as u8, &self.new_user_registration_tree_leaves)?;
            spider_map_proofs
                .chunks(N::BATCH_USER_REGISTRATION_MAX_SUB_TREES)
                .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                    register_users_circuit_whitelist: self.config.register_users_circuit_whitelist,
                    spiderman_append_proofs: chunk.to_vec(),
                })
                .collect::<Vec<_>>()
        };
        let (jobs_for_queue, job_temp_data) = plan_jobs_for_tree_agg::<
            QProvingJobDataID,
            N::F,
            N::QHash,
            N::HasherBase,
            QCAppendUserRegistrationTreeCircuitInput<N::QHash>,
            AggRegisterUserHelper,
        >(
            pending_unique_id,
            start_state_root,
            self.config.register_users_circuit_whitelist,
            &spider_man_groups,
        )?;

        let update_user_registration_tree_nodes_ffs = create_ffs_merkle_nodes_zero_id_from_hash_map::<N::QHash>(tree.get_changes());
        tree.commit_changes();

        self.config
            .temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(&realm_identifier, pending_unique_id, job_temp_data)
            .await?;

        let start_next_user_id = self.config.start_next_user_id.load(Ordering::Relaxed);
        let output_database = RegisterUserGathererOutputDatabase {
            start_next_user_id,
            start_user_registration_tree_hash: start_state_root,
            new_user_public_keys_ffs: self.new_user_public_keys_ffs,
            next_user_id: self.next_user_id,
            end_user_registration_tree_hash: tree.get_root(),
            user_registration_tree_update_pivot_siblings: tree.get_historical_pivot_leaf(start_next_user_id).siblings,
            new_public_key_hash_to_user_id_rows_ffs: self.new_public_key_hash_to_user_id_rows_ffs,
            update_user_registration_tree_nodes_ffs,
        };
        let output = RegisterUserGathererOutput {
            db_output: output_database,
            job_ids: jobs_for_queue,
        };
        Ok(output)
    }
}

pub struct AggRegisterUserHelper {}
impl<Hash: Q256BitHash>
    BasicTreePlannerHelper<
        QProvingJobDataID,
        Hash,
        QCAppendUserRegistrationTreeCircuitInput<Hash>,
        AggStateTransitionInputV2<Hash>,
        DummyAggStateTransition<Hash>,
    > for AggRegisterUserHelper
{
    fn get_dummy_job_id(unique_checkpoint_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            0,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            0,
            0,
        )
        .get_input_witness_id()
    }

    fn get_agg_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate,
            0,
            node_key.index as u32,
        )
        .get_input_witness_id()
    }

    fn get_leaf_job_id(unique_checkpoint_id: u64, node_key: SimpleMerkleNodeKey) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            unique_checkpoint_id,
            node_key.level as u32,
            ProvingJobCircuitType::AppendUserRegistrationTree,
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
        left: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
        right: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
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
        left: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
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
        right: &QCAppendUserRegistrationTreeCircuitInput<Hash>,
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
