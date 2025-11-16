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
    let mut update_user_registration_tree_nodes_ffs = Vec::with_capacity(tree.get_changes().len() * PSY_OBJECT_FFS_SIZE_SIMPLE_MERKLE_NODE);

    for (key, hash) in tree.get_changes().iter() {
        let node = SimpleMerkleNode { key: *key, value: *hash };
        node.pio_write_to_io(&mut update_user_registration_tree_nodes_ffs)?;
    }
    tree.commit_changes();
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
        // ensure the new user public keys file is flushed to disk
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
            ProvingJobCircuitType::AppendUserRegistrationTreeAggregate,
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



#[cfg(test)]
mod tests {
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{crypto::hash::spiderman, pgoldilocks::PoseidonHasher, utils::QPGenRandom};
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::gatherer_builders::register_user;
    use super::*;

    #[test]
    fn test_fake_agg() -> anyhow::Result<()> {
        type Hash = parth_core::PHash;
        type F = parth_core::PF;
        type JobId = QProvingJobDataID;
        type Hasher = PoseidonHasher;
        
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let random_leaves = Hash::qp_rand_gen_vec(17);
        let register_users_circuit_whitelist = Hash::qp_rand_gen();
        let start_root= tree.get_root();
        let spider_map_proofs = tree.append_leaves_spider_man(2, &random_leaves)?;
        println!("Spiderman proofs len: {}", spider_map_proofs.len());


        let spider_man_groups=spider_map_proofs
                .chunks(2)
                .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                    register_users_circuit_whitelist: register_users_circuit_whitelist,
                    spiderman_append_proofs: chunk.to_vec(),
                })
                .collect::<Vec<_>>();
        println!("spiderman groups len: {}", spider_man_groups.len());

        let unique_pending_id = 1337u64;
         let (jobs_for_queue, witneses) = plan_jobs_for_tree_agg::<
            JobId,
            F,
            Hash,
            Hasher,
            QCAppendUserRegistrationTreeCircuitInput<Hash>,
            AggRegisterUserHelper,
        >(
            unique_pending_id,
            start_root,
            register_users_circuit_whitelist,
            &spider_man_groups,
        )?;
        println!("Jobs for queue len: {}", jobs_for_queue.len());
        for row in jobs_for_queue.iter() {
            for job in row.iter() {
                println!("Job id: {:?}", job.job_id);
                println!("Metadata: {:?}", job.metadata);
            }
        }



        






        Ok(())

    }
}


/*




running 1 test
Spiderman proofs len: 5
spiderman groups len: 3
Jobs for queue len: 3
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [12390451264743676018, 8304973432661659895, 3781840995643076068, 10132581250177410994] }), reward_tree_node_index: 0, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [10334449205758273826, 12066373173403079634, 1053597563067968013, 6237065607049177422] }), reward_tree_node_index: 1, reward_tree_node_level: 2, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [7095128601763881389, 14640763668863926621, 6914635675784815755, 6508350705276371674] }), reward_tree_node_index: 0, reward_tree_node_level: 1, reward_tree_hash_mode: 0, reward_tree_node_children: 2, dependencies: [QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }, QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 2, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 1, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [1297856571266094013, 6684537187575756546, 15809828805894705281, 15948219461984833794] }), reward_tree_node_index: 1, reward_tree_node_level: 1, reward_tree_hash_mode: 1, reward_tree_node_children: 0, dependencies: [] }
Job id: QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 0, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }
Metadata: PsyProvingJobMetadata { expected_public_inputs_hash: QHashOut(HashOut { elements: [17884585634982125226, 6187098926797097119, 3004161071059206768, 6204218450729565222] }), reward_tree_node_index: 0, reward_tree_node_level: 0, reward_tree_hash_mode: 0, reward_tree_node_children: 2, dependencies: [QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: DummyAppendUserRegistrationTreeAggregate, group_id: 1, sub_group_id: 0, task_index: 0, data_type: InputWitness, data_index: 0 }, QProvingJobDataID { topic: GenerateStandardProof, goal_id: 1337, circuit_type: AppendUserRegistrationTree, group_id: 1, sub_group_id: 0, task_index: 1, data_type: InputWitness, data_index: 0 }] }
test coordinator::processor::gatherers::register_user_gatherer::tests::test_fake_agg ... ok



*/
#[cfg(test)]
mod tests3 {
    use super::*;
    use anyhow::{anyhow, Result};
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use parth_core::{crypto::hash::spiderman, pgoldilocks::PoseidonHasher, utils::QPGenRandom};
    use parth_core::PF;
    use parth_core::PHash;
    use psy_core::job::job_id::QProvingJobDataID;
    use psy_data::agg::tree_agg_v2::{ plan_jobs_for_tree_agg};
    use psy_data::protocol::circuit_inputs::append_user_registration_tree::QCAppendUserRegistrationTreeCircuitInput;
    use psy_data::worker::metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN};
    use std::collections::{HashMap, HashSet};

    fn validate_tree_structure(layers: &Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>, expected_num_leaves: usize, unique_id: u64) -> Result<()> {
        let mut key_to_info: HashMap<SimpleMerkleNodeKey, (QProvingJobDataID, u8, u16, Vec<QProvingJobDataID>)> = HashMap::new();
        let mut leaf_count = 0;

        for layer in layers {
            for item in layer {
                let key = SimpleMerkleNodeKey {
                    level: item.metadata.reward_tree_node_level,
                    index: item.metadata.reward_tree_node_index,
                };
                let hash_mode = item.metadata.reward_tree_hash_mode;
                let num_children = item.metadata.reward_tree_node_children;
                let deps = item.metadata.dependencies.clone();
                key_to_info.insert(key, (item.job_id, hash_mode, num_children, deps));

                if hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                    leaf_count += 1;
                }
            }
        }

        assert_eq!(leaf_count, expected_num_leaves);

        let root_key = SimpleMerkleNodeKey { level: 0, index: 0 };
        let mut visited: HashSet<SimpleMerkleNodeKey> = HashSet::new();

        fn recurse(
            key: SimpleMerkleNodeKey,
            key_to_info: &HashMap<SimpleMerkleNodeKey, (QProvingJobDataID, u8, u16, Vec<QProvingJobDataID>)>,
            visited: &mut HashSet<SimpleMerkleNodeKey>,
            unique_id: u64,
        ) -> Result<()> {
            if !visited.insert(key) {
                return Err(anyhow!("Duplicate visit to key {:?}", key));
            }

            let Some(&(job_id, hash_mode, num_children, ref deps)) = key_to_info.get(&key) else {
                return Err(anyhow!("Missing key {:?}", key));
            };

            if hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                assert_eq!(num_children, 0);
                assert_eq!(deps.len(), 0);
                assert_eq!(job_id, <AggRegisterUserHelper as BasicTreePlannerHelper<QProvingJobDataID, PHash, QCAppendUserRegistrationTreeCircuitInput<PHash>, AggStateTransitionInputV2<PHash>, DummyAggStateTransition<PHash>>>::get_leaf_job_id(unique_id, key));
            } else if hash_mode == PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD {
                assert_eq!(num_children, 2);
                assert_eq!(deps.len(), 2);
                assert_eq!(job_id, <AggRegisterUserHelper as BasicTreePlannerHelper<QProvingJobDataID, PHash, QCAppendUserRegistrationTreeCircuitInput<PHash>, AggStateTransitionInputV2<PHash>, DummyAggStateTransition<PHash>>>::get_agg_job_id(unique_id, key));

                let left_key = SimpleMerkleNodeKey {
                    level: key.level + 1,
                    index: key.index * 2,
                };
                let right_key = SimpleMerkleNodeKey {
                    level: key.level + 1,
                    index: key.index * 2 + 1,
                };

                let left_info = key_to_info.get(&left_key).ok_or(anyhow!("Missing left child {:?}", left_key))?;
                let right_info = key_to_info.get(&right_key).ok_or(anyhow!("Missing right child {:?}", right_key))?;

                assert_eq!(deps[0], left_info.0);
                assert_eq!(deps[1], right_info.0);

                recurse(left_key, key_to_info, visited, unique_id)?;
                recurse(right_key, key_to_info, visited, unique_id)?;
            } else {
                return Err(anyhow!("Unknown hash_mode {} for key {:?}", hash_mode, key));
            }

            Ok(())
        }

        recurse(root_key, &key_to_info, &mut visited, unique_id)?;

        assert_eq!(visited.len(), key_to_info.len(), "Not all nodes were visited");

        Ok(())
    }

    fn setup_and_plan_jobs(num_groups: usize) -> Result<Vec<Vec<PsyProvingJobMetadataWithJobId<PHash, QProvingJobDataID>>>> {
        let mut tree = SimpleMemoryMerkleRecorderStore::<PoseidonHasher, PHash>::new(32);
        let height = 0u8; // Use height=0 for single-leaf subtrees to control the number of proofs exactly
        let num_raw_leaves = num_groups;
        let random_leaves = PHash::qp_rand_gen_vec(num_raw_leaves);
        let spider_map_proofs = tree.append_leaves_spider_man(height, &random_leaves)?;
        assert_eq!(spider_map_proofs.len(), num_groups);

        let whitelist = PHash::qp_rand_gen();
        let spider_man_groups: Vec<QCAppendUserRegistrationTreeCircuitInput<PHash>> = spider_map_proofs
            .into_iter()
            .map(|proof| QCAppendUserRegistrationTreeCircuitInput {
                register_users_circuit_whitelist: whitelist,
                spiderman_append_proofs: vec![proof],
            })
            .collect();
        assert_eq!(spider_man_groups.len(), num_groups);

        let unique_checkpoint_id = 1337u64;
        let start_tree_root = tree.get_root();
        let (layers, _witnesses) = plan_jobs_for_tree_agg::<
            QProvingJobDataID,
            PF,
            PHash,
            PoseidonHasher,
            QCAppendUserRegistrationTreeCircuitInput<PHash>,
            AggRegisterUserHelper,
        >(unique_checkpoint_id, start_tree_root, whitelist, &spider_man_groups)?;

        Ok(layers)
    }

    #[test]
    fn test_tree_agg_num_leaves_0() -> Result<()> {
        let unique_id = 1337u64;
        let start_root = PHash::qp_rand_gen();
        let allowed = PHash::qp_rand_gen();
        let leaves: &[QCAppendUserRegistrationTreeCircuitInput<PHash>] = &[];
        let (layers, _witnesses) = plan_jobs_for_tree_agg::<
            QProvingJobDataID,
            PF,
            PHash,
            PoseidonHasher,
            QCAppendUserRegistrationTreeCircuitInput<PHash>,
            AggRegisterUserHelper,
        >(unique_id, start_root, allowed, leaves)?;

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 1);
        let item = &layers[0][0];
        assert_eq!(item.job_id, <AggRegisterUserHelper as BasicTreePlannerHelper<QProvingJobDataID, PHash, QCAppendUserRegistrationTreeCircuitInput<PHash>, AggStateTransitionInputV2<PHash>, DummyAggStateTransition<PHash>>>::get_dummy_job_id(unique_id));
        assert_eq!(item.metadata.reward_tree_node_level, 0);
        assert_eq!(item.metadata.reward_tree_node_index, 0);
        assert_eq!(item.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(item.metadata.reward_tree_node_children, 0);
        assert_eq!(item.metadata.dependencies.len(), 0);

        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_1() -> Result<()> {
        let layers = setup_and_plan_jobs(1)?;
        validate_tree_structure(&layers, 1, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_2() -> Result<()> {
        let layers = setup_and_plan_jobs(2)?;
        validate_tree_structure(&layers, 2, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_3() -> Result<()> {
        let layers = setup_and_plan_jobs(3)?;
        validate_tree_structure(&layers, 3, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_4() -> Result<()> {
        let layers = setup_and_plan_jobs(4)?;
        validate_tree_structure(&layers, 4, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_5() -> Result<()> {
        let layers = setup_and_plan_jobs(5)?;
        validate_tree_structure(&layers, 5, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_6() -> Result<()> {
        let layers = setup_and_plan_jobs(6)?;
        validate_tree_structure(&layers, 6, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_7() -> Result<()> {
        let layers = setup_and_plan_jobs(7)?;
        validate_tree_structure(&layers, 7, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_num_leaves_8() -> Result<()> {
        let layers = setup_and_plan_jobs(8)?;
        validate_tree_structure(&layers, 8, 1337)?;
        Ok(())
    }

    #[test]
    fn test_tree_agg_large() -> Result<()> {
        let layers = setup_and_plan_jobs(100)?;
        validate_tree_structure(&layers, 100, 1337)?;
        Ok(())
    }

    #[test]
    fn test_fake_agg() -> anyhow::Result<()> {
        type Hash = parth_core::PHash;
        type F = parth_core::PF;
        type JobId = QProvingJobDataID;
        type Hasher = PoseidonHasher;
        
        let mut tree = SimpleMemoryMerkleRecorderStore::<Hasher, Hash>::new(32);
        let random_leaves = Hash::qp_rand_gen_vec(17);
        let allowed_circuit_hashes_root = Hash::qp_rand_gen();
        let start_root= tree.get_root();
        let spider_map_proofs = tree.append_leaves_spider_man(2, &random_leaves)?;
        println!("Spiderman proofs len: {}", spider_map_proofs.len());


        let spider_man_groups=spider_map_proofs
                .chunks(2)
                .map(|chunk| QCAppendUserRegistrationTreeCircuitInput {
                    register_users_circuit_whitelist: allowed_circuit_hashes_root,
                    spiderman_append_proofs: chunk.to_vec(),
                })
                .collect::<Vec<_>>();
        println!("spiderman groups len: {}", spider_man_groups.len());

        let unique_pending_id = 1337u64;
         let (jobs_for_queue, _witneses) = plan_jobs_for_tree_agg::<
            JobId,
            F,
            Hash,
            Hasher,
            QCAppendUserRegistrationTreeCircuitInput<Hash>,
            AggRegisterUserHelper,
        >(
            unique_pending_id,
            start_root,
            allowed_circuit_hashes_root,
            &spider_man_groups,
        )?;
        println!("Jobs for queue len: {}", jobs_for_queue.len());
        for row in jobs_for_queue.iter() {
            for job in row.iter() {
                println!("Job id: {:?}", job.job_id);
                println!("Metadata: {:?}", job.metadata);
            }
        }

        validate_tree_structure(&jobs_for_queue, spider_man_groups.len(), unique_pending_id)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests2 {
    use super::*;
    use parth_core::{
        crypto::hash::{spiderman::SpidermanUpdateProof, traits::MerkleZeroHasher, }, data::hash::merkle_node_key::SimpleMerkleNodeKey, felt::QFelt64, pgoldilocks::PoseidonHasher, protocol::core_types::{Q256BitHash, QFHashBase}, utils::QPGenRandom
    };
    use parth_common::memory_stores::mem_tree_recorder::SimpleMemoryMerkleRecorderStore;
    use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
    use psy_data::{agg::{
        AggStateTransitionInputV2, DummyAggStateTransition, tree_agg_v2::{BasicTreePlannerHelper, plan_jobs_for_tree_agg}
    }, worker::metadata::{PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN}};
    use psy_serialize::PsySerializeCanonicalAsyncSafe;

    use anyhow::{anyhow, Result};
fn compute_max_level(mut num: usize) -> u8 {
    let mut h = 0u8;
    while num > 1 {
        num = (num + 1) / 2;
        h += 1;
    }
    h
}
    type F = parth_core::PF; // Assuming QFelt64 is defined elsewhere, e.g., as u64 or a field element
    type Hash = parth_core::PHash; // Assuming PHash is a 256-bit hash
    type Hasher = PoseidonHasher; // Using PoseidonHasher as the FieldQHasher
    type JobId = QProvingJobDataID;
    type LeafWitness = QCAppendUserRegistrationTreeCircuitInput<Hash>;

    // Helper function to generate dummy leaf witnesses
    fn generate_dummy_leaves(num_leaves: usize, whitelist: Hash) -> Vec<LeafWitness> {
        (0..num_leaves)
            .map(|_| LeafWitness {
                register_users_circuit_whitelist: whitelist,
                spiderman_append_proofs: QPGenRandom::qp_rand_gen_vec(3), // Empty for dummy
            })
            .collect()
    }

    // Helper function to validate the tree structure programmatically
    fn validate_tree_structure(
        layers: &[Vec<PsyProvingJobMetadataWithJobId<Hash, JobId>>],
        max_level: u8,
        num_leaves: usize,
    ) -> Result<()> {
        // layers[0] is the leaves (highest level), layers[last] is the root (level 0)
        if layers.len() != (max_level as usize) + 1 {
            return Err(anyhow!("Incorrect number of layers: expected {}, got {}", max_level + 1, layers.len()));
        }

        // Check leaf layer
        let leaf_layer = &layers[0];
        if leaf_layer.len() != num_leaves {
            return Err(anyhow!("Incorrect number of leaves: expected {}, got {}", num_leaves, leaf_layer.len()));
        }
        for (i, job) in leaf_layer.iter().enumerate() {
            let expected_key = SimpleMerkleNodeKey {
                level: max_level,
                index: i as u64,
            };
            if job.metadata.reward_tree_node_level != max_level {
                return Err(anyhow!("Leaf level mismatch: expected {}, got {}", max_level, job.metadata.reward_tree_node_level));
            }
            if job.metadata.reward_tree_node_index != i as u64 {
                return Err(anyhow!("Leaf index mismatch: expected {}, got {}", i, job.metadata.reward_tree_node_index));
            }
            if job.metadata.reward_tree_hash_mode != PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                return Err(anyhow!("Leaf hash mode incorrect"));
            }
            if !job.metadata.dependencies.is_empty() {
                return Err(anyhow!("Leaf should have no dependencies"));
            }
            // Check job_id is leaf type
            if job.job_id.circuit_type != ProvingJobCircuitType::AppendUserRegistrationTree {
                return Err(anyhow!("Incorrect circuit type for leaf"));
            }
            if job.job_id.group_id != max_level as u32 {
                return Err(anyhow!("Job level mismatch for leaf"));
            }
            if job.job_id.task_index != i as u32 {
                return Err(anyhow!("Job index mismatch for leaf"));
            }
        }

        // Check intermediate layers up to root
        for layer_idx in 1..layers.len() {
            let current_level = (max_level as usize - layer_idx) as u8;
            let current_layer = &layers[layer_idx];
            let child_layer = &layers[layer_idx - 1];

            // Expected number of nodes: ceil(child_layer.len() / 2)
            let expected_nodes = (child_layer.len() + 1) / 2;
            if current_layer.len() != expected_nodes {
                return Err(anyhow!("Incorrect number of nodes at level {}: expected {}, got {}", current_level, expected_nodes, current_layer.len()));
            }

            for (i, job) in current_layer.iter().enumerate() {
                let expected_key = SimpleMerkleNodeKey {
                    level: current_level,
                    index: i as u64,
                };
                if job.metadata.reward_tree_node_level != current_level {
                    return Err(anyhow!("Level mismatch: expected {}, got {}", current_level, job.metadata.reward_tree_node_level));
                }
                if job.metadata.reward_tree_node_index != i as u64 {
                    return Err(anyhow!("Index mismatch: expected {}, got {}", i, job.metadata.reward_tree_node_index));
                }
                if job.metadata.reward_tree_hash_mode != PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD {
                    return Err(anyhow!("Agg hash mode incorrect"));
                }

                // Check dependencies: should be 1 or 2 children
                let left_child_idx = 2 * i;
                let right_child_idx = left_child_idx + 1;
                if left_child_idx >= child_layer.len() {
                    return Err(anyhow!("Missing left child for node at level {}, index {}", current_level, i));
                }
                let left_child = &child_layer[left_child_idx];
                let has_right = right_child_idx < child_layer.len();
                if has_right {
                    let right_child = &child_layer[right_child_idx];
                    if job.metadata.dependencies != vec![left_child.job_id, right_child.job_id] {
                        return Err(anyhow!("Dependency mismatch for node at level {}, index {}", current_level, i));
                    }
                    if job.metadata.reward_tree_node_children != 2 {
                        return Err(anyhow!("Num children mismatch: expected 2, got {}", job.metadata.reward_tree_node_children));
                    }
                } else {
                    if job.metadata.dependencies != vec![left_child.job_id] {
                        return Err(anyhow!("Dependency mismatch for unbalanced node at level {}, index {}", current_level, i));
                    }
                    if job.metadata.reward_tree_node_children != 1 {
                        return Err(anyhow!("Num children mismatch: expected 1, got {}", job.metadata.reward_tree_node_children));
                    }
                }

                // Check job_id is agg type
                if job.job_id.circuit_type != ProvingJobCircuitType::AppendUserRegistrationTreeAggregate {
                    return Err(anyhow!("Incorrect circuit type for agg"));
                }
                if job.job_id.group_id != current_level as u32 {
                    return Err(anyhow!("Job level mismatch for agg"));
                }
                if job.job_id.task_index != i as u32 {
                    return Err(anyhow!("Job index mismatch for agg"));
                }
            }
        }

        // Root should be at last layer, single node
        let root_layer = &layers[layers.len() - 1];
        if root_layer.len() != 1 {
            return Err(anyhow!("Root layer should have exactly 1 node"));
        }
        if root_layer[0].metadata.reward_tree_node_level != 0 {
            return Err(anyhow!("Root level should be 0"));
        }
        if root_layer[0].metadata.reward_tree_node_index != 0 {
            return Err(anyhow!("Root index should be 0"));
        }

        Ok(())
    }

    // Test for specific leaf counts
    fn test_tree_agg_for_num_leaves(num_leaves: usize) -> anyhow::Result<()> {
        let whitelist = Hash::qp_rand_gen();
        let start_root = Hash::qp_rand_gen();
        let unique_id = 1337u64;
        let leaves = generate_dummy_leaves(num_leaves, whitelist);

        let (layers, witnesses) = plan_jobs_for_tree_agg::<
            JobId,
            F,
            Hash,
            Hasher,
            LeafWitness,
            AggRegisterUserHelper,
        >(unique_id, start_root, whitelist, &leaves)?;

        let max_level = compute_max_level(num_leaves);
        assert_eq!(layers.len(), (max_level as usize) + 1);

        // Validate witnesses count
        if witnesses.len() != layers.iter().map(|l| l.len()).sum::<usize>() {
            return Err(anyhow!("Witness count mismatch: expected {}, got {}", layers.iter().map(|l| l.len()).sum::<usize>(), witnesses.len()));
        }

        // Programmatic validation
        validate_tree_structure(&layers, max_level, num_leaves)?;

        Ok(())
    }

    #[test]
    fn test_tree_agg_1_leaf() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(1)
    }

    #[test]
    fn test_tree_agg_2_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(2)
    }

    #[test]
    fn test_tree_agg_3_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(3)
    }

    #[test]
    fn test_tree_agg_4_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(4)
    }

    #[test]
    fn test_tree_agg_5_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(5)
    }

    #[test]
    fn test_tree_agg_6_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(6)
    }

    #[test]
    fn test_tree_agg_7_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(7)
    }

    #[test]
    fn test_tree_agg_8_leaves() -> anyhow::Result<()> {
        test_tree_agg_for_num_leaves(8)
    }

    #[test]
    fn test_tree_agg_large() -> anyhow::Result<()> {
        // Test with a larger tree, e.g., 17 as in the original
        test_tree_agg_for_num_leaves(17)?;

        // Even larger, say 100
        test_tree_agg_for_num_leaves(100)?;

        // Power of 2 - 1
        test_tree_agg_for_num_leaves(15)?;

        Ok(())
    }

    #[test]
    fn test_tree_agg_0_leaves() -> anyhow::Result<()> {
        let whitelist = Hash::qp_rand_gen();
        let start_root = Hash::qp_rand_gen();
        let unique_id = 1337u64;
        let leaves: Vec<LeafWitness> = vec![];

        let (layers, witnesses) = plan_jobs_for_tree_agg::<
            JobId,
            F,
            Hash,
            Hasher,
            LeafWitness,
            AggRegisterUserHelper,
        >(unique_id, start_root, whitelist, &leaves)?;

        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].len(), 1);
        let job = &layers[0][0];
        assert_eq!(job.metadata.reward_tree_node_level, 0);
        assert_eq!(job.metadata.reward_tree_node_index, 0);
        assert_eq!(job.metadata.reward_tree_hash_mode, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN);
        assert_eq!(job.metadata.reward_tree_node_children, 0);
        assert!(job.metadata.dependencies.is_empty());
        assert_eq!(job.job_id.circuit_type, ProvingJobCircuitType::DummyAppendUserRegistrationTreeAggregate);
        assert_eq!(witnesses.len(), 1);

        Ok(())
    }

    // Additional test for expected public inputs hash, etc., if needed
    // But focusing on structure as per the task
}