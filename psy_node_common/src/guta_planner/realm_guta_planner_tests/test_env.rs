use std::{collections::HashMap, sync::Arc};

use parth_common::memory_stores::{dash_tree_append_only::PsyDashMemoryAppendOnlyMerkleStore, traits::PsyMemoryMerkleStoreImm};
use parth_core::{
    QCoreProcCheckpointUniqueId, QJobIdBase, crypto::hash::traits::{FromU64x4, MerkleZeroHasher, QFieldHashable, ZeroableHash}, data::
        hash::merkle_store_key::{QMerkleStoreDoubleIdKey, QMerkleStoreSingleIdKey}, felt::{FromPrimitiveValuesFelt, ToU64Value, ZeroableFelt}, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants}, utils::{QPGenRandom, math::{ceil_div_usize, log2_ceil}}
};
use psy_core::{job::{self, job_id::{ProvingJobCircuitType, QProvingJobDataID}}, user_id};
use psy_data::{
    guta::{header::GlobalUserTreeAggregatorHeader, stats::GUTAStats},
    proof_input::guta::{GUTAVerifyLeftGUTARightEndCapCircuitInputV2, GUTAVerifyTwoEndCapCircuitInputV2, GUTAVerifyTwoGUTALinearCircuitInput, SubmitUserEndCapNonProofCoreInput, VerifySingleEndCapInputV2, VerifyTwoEndCapCircuitInput, end_cap_input::SubmitUserEndCapNonProofInput},
    queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
    v1::qdata::{
        contract::{DashMapContractHeightCache, PSimpleContractHeightCache, QEDContractStateUpdateHistory},
        public_key::PZKPublicKeyInfo,
        user::PQEDUserLeaf,
        user_end_cap_result::PUPSEndCapResultCompact,
    }, worker::{metadata::PsyProvingJobMetadata, metadata_with_job_id::PsyProvingJobMetadataWithJobId},
};
use psy_io::tokio::TokioLikeFileSystem;
use psy_node_core::{
    file::memory_fs::SimpleMockMemoryFileSystem,
    psy_core_db::traits::full::{
        PsyNodeContractStateTreeTreeDatabaseReader, PsyNodeContractStateTreeTreeDatabaseWriter,
        PsyNodeCoreDatabaseUserStoreReader, PsyNodeCoreDatabaseUserStoreWriter, PsyNodeGlobalUserTreeDatabaseReader,
        PsyNodeGlobalUserTreeDatabaseWriter, PsyNodeUserContractTreeDatabaseReader, PsyNodeUserContractTreeDatabaseWriter,
        PsyNodeUserRegistrationTreeDatabaseWriter,
    },
    psy_temp_db::{QTempDBProofWitnessReader, QTempDBSubmitStatusWriter, QTempDBUserContractUpdatesWriter},
    qblob::structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use rand::{seq::SliceRandom, thread_rng, Rng};

use super::core::{Hash, Hasher, PsyRGPTestDatabase, F};
use crate::{
    guta_planner::{
        realm_guta_planner::RealmGUTAPlanner,
        realm_guta_planner_tests::core::{PsyRGPNetworkConfig, RecTree, TempStore, create_rgp_test_db},
    },
    realm::{
        edge::utils::end_cap::validate_end_cap_and_generate_node_data_for_edge,
        processor::gatherers::realm_end_cap_gatherer::{RealmGUTAEndCapGathererOutput, RealmGUTAEndCapGathererOutputDatabase},
    },
};

type N = PsyRGPNetworkConfig;

#[derive(Clone)]
pub struct RGPContractUpdate {
    pub contract_id: u32,
    pub leaves: Vec<(u64, Hash)>,
}


#[derive(Clone)]
pub struct RGPUser {
    pub user_id: u64,
    pub uct: RecTree,
    pub contract_trees: HashMap<u32, RecTree>,
    pub user_leaf: PQEDUserLeaf<F, Hash>,
}
impl RGPUser {
    pub fn new(user_id: u64, public_key: Hash) -> Self {
        Self {
            user_id,
            uct: RecTree::new(N::GLOBAL_CONTRACT_TREE_HEIGHT),
            contract_trees: HashMap::new(),
            user_leaf: PQEDUserLeaf::new(
                public_key,
                Hash::from_u64x4(N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4),
                F::ZERO_VALUE,
                F::ZERO_VALUE,
                F::ZERO_VALUE,
                F::ZERO_VALUE,
                F::from_u64_value(user_id),
            ),
        }
    }
    pub fn _ensure_user_leaf_synced(&mut self) {
        let uct_root = self.uct.get_root();
        self.user_leaf.user_state_tree_root = uct_root;
    }

    pub fn run_ups(
        &mut self,
        contract_height_cache: &DashMapContractHeightCache<Hash>,
        latest_checkpoint_id: u64,
        latest_checkpoint_tree_root: Hash,
        txs: &[RGPContractUpdate],
    ) -> anyhow::Result<SubmitUserEndCapNonProofInput<F, Hash>> {
        let start_leaf_hash = if self
            .user_leaf
            .is_first_transaction_old_user_leaf_with_state(Hash::from_u64x4(N::DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4))
        {
            Hash::get_zero_value()
        } else {
            self.user_leaf.qfhash::<Hasher>()
        };
        let mut state_history = Vec::with_capacity(txs.len());
        let mut total_slots_modified = 0;
        for tx in txs {
            if !self.contract_trees.contains_key(&tx.contract_id) {
                self.contract_trees
                    .insert(tx.contract_id, RecTree::new(contract_height_cache.get_contract_height(tx.contract_id)?));
            }
            let contract_tree = self.contract_trees.get_mut(&tx.contract_id).unwrap();
            let mut contract_state_tree_updates = Vec::with_capacity(txs.len());
            for (leaf_index, leaf_hash) in tx.leaves.iter() {
                let proof = contract_tree.set_leaf(*leaf_index, *leaf_hash);
                contract_state_tree_updates.push(proof);
                total_slots_modified += 1;
            }
            state_history.push(QEDContractStateUpdateHistory {
                contract_state_tree_updates,
                user_contract_tree_update_proof: self.uct.set_leaf(tx.contract_id as u64, contract_tree.get_root()),
            });
            contract_tree.commit_changes();
        }
        self.uct.commit_changes();
        let new_user_state_root = self.uct.get_root();
        self.user_leaf.user_state_tree_root = new_user_state_root;
        self.user_leaf.nonce += F::from_u8_value(1);
        self.user_leaf.last_checkpoint_id = F::from_u64_value(latest_checkpoint_id);
        let end_leaf_hash = self.user_leaf.qfhash::<Hasher>();
        let core_input = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: F::from_u64_value(latest_checkpoint_id),
            stats: GUTAStats {
                fees_collected: F::from_u64_value(1000 * total_slots_modified + 1000),
                user_ops_processed: F::from_u8_value(1),
                total_transactions: F::from_u64_value(txs.len() as u64),
                slots_modified: F::from_u64_value(total_slots_modified as u64),
            },
            state_transition: PUPSEndCapResultCompact {
                start_user_leaf_hash: start_leaf_hash,
                end_user_leaf_hash: end_leaf_hash,
                checkpoint_tree_root_hash: latest_checkpoint_tree_root,
                user_id: F::from_u64_value(self.user_id),
            },
            new_user_leaf: self.user_leaf.clone(),
        };

        Ok(SubmitUserEndCapNonProofInput {
            core: core_input,
            contract_state_updates: state_history,
        })
    }
}

#[derive(Clone)]
pub struct RGPTestChainState {
    pub db: Arc<PsyRGPTestDatabase>,
    pub temp_db: Arc<TempStore>,
    pub backup_file_system: SimpleMockMemoryFileSystem,
    pub coordinator_global_user_tree: RecTree,
    pub checkpoint_tree: PsyDashMemoryAppendOnlyMerkleStore<Hasher, Hash>,
    pub users: HashMap<u64, RGPUser>,
    pub contract_height_cache: DashMapContractHeightCache<Hash>,
    pub chain_id: u32,
    pub node_id: u32,
    pub checkpoint_id: u64,
    pub unique_pending_id: u64,
    pub unique_cord_proc_id: QCoreProcCheckpointUniqueId,
    pub checkpoint_tree_root: Hash,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub realm_identifier: QRealmIdentifier,
    pub next_user_registration_id: u64,
    pub next_contract_id: u32,
    pub guta_circuit_whitelist: Hash,
    pub first_realm_global_user_tree: RecTree,
}

impl RGPTestChainState {
    pub async fn create_for_tests() -> anyhow::Result<Self> {
        let db = Arc::new(create_rgp_test_db().await?);
        Ok(Self::new(db, 0, 0))
    }
    pub fn new(db: Arc<PsyRGPTestDatabase>, realm_id_u64: u64, realm_sub_id_u64: u64) -> Self {
        let realm_identifier = QRealmIdentifier::new(realm_id_u64 as u32, realm_sub_id_u64 as u16);
        let checkpoint_tree = PsyDashMemoryAppendOnlyMerkleStore::new(N::CHECKPOINT_TREE_HEIGHT);
        let mut coordinator_global_user_tree = RecTree::new(N::GLOBAL_USER_TREE_HEIGHT);
        coordinator_global_user_tree.set_effective_height(N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT);
        checkpoint_tree.append_leaf(0, Hash::qp_rand_gen()).unwrap();
        Self {
            db,
            chain_id: 0,
            node_id: 0,
            checkpoint_tree_root: checkpoint_tree.get_root(),
            temp_db: Arc::new(TempStore::new("rgp_test".to_string(), realm_id_u64, realm_sub_id_u64)),
            backup_file_system: SimpleMockMemoryFileSystem::new(),
            users: HashMap::new(),
            coordinator_global_user_tree,
            first_realm_global_user_tree: RecTree::new(N::REALM_GLOBAL_USER_TREE_HEIGHT),
            guta_circuit_whitelist: Hash::from_u64x4([1337, 69, 420, 9696]),
            checkpoint_tree: checkpoint_tree,
            contract_height_cache: DashMapContractHeightCache::new(),
            checkpoint_id: 0,
            unique_pending_id: 0,
            unique_cord_proc_id: QCoreProcCheckpointUniqueId::qp_rand_gen(),
            realm_id_u64,
            realm_sub_id_u64,
            realm_identifier,
            next_contract_id: 0,
            next_user_registration_id: 0,
        }
    }
    pub fn gen_rand_contract_updates_for_ups(&self, max_num_txs: usize, max_leaves_per_tx: usize) -> anyhow::Result<Vec<RGPContractUpdate>> {
        if max_leaves_per_tx == 0 || max_num_txs == 0 {
            return Ok(vec![]);
        }
        let mut rng = thread_rng();
        let num_tx = rng.gen_range(1..=max_num_txs);
        let mut updates = Vec::with_capacity(num_tx);
        for _ in 0..num_tx {
            let contract_id = rng.gen_range(0..self.next_contract_id);
            let contract_height = self.contract_height_cache.get_contract_height(contract_id)?;
            let state_slots = 1u64 << contract_height;

            let num_leaves = rng.gen_range(1..=max_leaves_per_tx);
            let mut leaves = Vec::with_capacity(num_leaves);
            for _ in 0..num_leaves {
                let leaf_index = rng.gen_range(0..state_slots);
                let leaf_value = Hash::qp_rand_gen();
                leaves.push((leaf_index, leaf_value));
            }
            updates.push(RGPContractUpdate { contract_id, leaves });
        }
        Ok(updates)
    }
    pub async fn ensure_user_matches_db(&self, user_id: u64) -> anyhow::Result<()> {
        let user = self.users.get(&user_id).unwrap();
        let db_user_leaf = self.db.get_user_leaf(self.checkpoint_id, user_id).await?;
        if db_user_leaf != user.user_leaf {
            anyhow::bail!("user leaf does not match db for user {}", user_id);
        }
        let leaf_hash = db_user_leaf.qfhash::<Hasher>();
        if leaf_hash != user.user_leaf.qfhash::<Hasher>() {
            anyhow::bail!("user leaf hash does not match db for user {}", user_id);
        }
        let db_leaf_hash = self.db.global_user_tree_get_leaf_hash(self.checkpoint_id, user_id).await?;
        if db_leaf_hash != leaf_hash {
            anyhow::bail!("global user tree leaf hash does not match db for user {} (db_leaf_hash = {:?}, expected leaf hash = {:?})", user_id, db_leaf_hash, leaf_hash);
        }

        let uct_nodes = user.uct.get_all_non_zero_nodes_including_changes();

        let uct_keys = uct_nodes
            .iter()
            .map(|x| QMerkleStoreSingleIdKey {
                tree_id: user_id,
                level: x.key.level,
                index: x.key.index,
            })
            .collect::<Vec<_>>();

        let db_uct_nodes: Vec<Hash> = self.db.user_contract_tree_get_nodes(self.checkpoint_id, &uct_keys).await?;
        for (i, db_node) in db_uct_nodes.iter().enumerate() {
            let local_node = &uct_nodes[i];
            if *db_node != local_node.value {
                anyhow::bail!(
                    "user contract tree node value does not match db for user {} (level: {}, index: {}, local in memory: {:?}, in db: {:?})",
                    user_id,
                    local_node.key.level,
                    local_node.key.index,
                    local_node.value,
                    *db_node
                );
            }
        }
        for (contract_id, ct) in user.contract_trees.iter() {
            let contract_id = *contract_id;
            let contract_state_tree = ct.get_all_non_zero_nodes_including_changes();
            let contract_state_tree_keys = contract_state_tree
                .iter()
                .map(|x| QMerkleStoreDoubleIdKey {
                    tree_id: user_id,
                    level: x.key.level,
                    index: x.key.index,
                    tree_sub_id: contract_id as u64,
                })
                .collect::<Vec<_>>();

            let db_contract_tree_nodes: Vec<Hash> = self
                .db
                .contract_state_tree_get_nodes(self.checkpoint_id, &contract_state_tree_keys)
                .await?;
            for (i, db_node) in db_contract_tree_nodes.iter().enumerate() {
                let local_node = &contract_state_tree[i];
                if *db_node != local_node.value {
                    anyhow::bail!("contract state tree node value does not match db for user {} contract {} (level: {}, index: {}, local in memory: {:?}, in db: {:?})", user_id, contract_id, local_node.key.level, local_node.key.index, local_node.value, *db_node);
                }
            }
        }
        Ok(())
    }
    pub async fn ensure_state_matches_db(&self) -> anyhow::Result<()> {
        //let checkpoint_id = self.checkpoint_id;

        for user in self.users.values() {
            self.ensure_user_matches_db(user.user_id).await?;
        }
        Ok(())
    }
    pub async fn register_new_random_user(&mut self) -> anyhow::Result<u64> {
        let registration_id = self.next_user_registration_id;
        let user_id = /*get_user_id_from_registration_id(
            registration_id,
            N::COORDINATOR_GLOBAL_USER_TREE_HEIGHT,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::GROUP_REALM_HEIGHT,
        );*/ registration_id;
        //println!("registering new user with id {}", user_id);
        let public_key = PZKPublicKeyInfo {
            public_key_param: Hash::qp_rand_gen(),
            fingerprint: Hash::qp_rand_gen(),
        };
        let public_key_hash = public_key.qfhash::<Hasher>();
        self.db
            .user_registration_tree_set_leaf_hash(self.checkpoint_id, registration_id, public_key_hash)
            .await?;
        self.db.set_zk_public_key(self.checkpoint_id, user_id, &public_key).await?;
        self.db.set_public_key_for_user_id(user_id, public_key_hash).await?;

        self.users.insert(user_id, RGPUser::new(user_id, public_key_hash));
        self.next_user_registration_id += 1;
        Ok(user_id)
    }
    pub async fn add_new_contract(&mut self, contract_height: u8) -> anyhow::Result<u32> {
        let contract_id = self.next_contract_id;
        self.contract_height_cache
            .add_contract(contract_id, contract_height, Hasher::get_zero_hash(contract_height as usize));
        self.next_contract_id += 1;

        // todo actually add a contract to the db
        Ok(contract_id)
    }

    pub fn get_backup_file_path_for_unique_pending_id(&self, unique_pending_id: u64) -> String {
        format!("backups/rp_{}", unique_pending_id)
    }

    pub async fn run_ups_for_user(&mut self, user_id: u64, txs: &[RGPContractUpdate]) -> anyhow::Result<PsyRealmUserUpdateQueueItem<F, Hash>> {
        let checkpoint_id = self.checkpoint_id;
        let unique_pending_id = self.unique_pending_id;
        let job_id =
            QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(user_id, N::GLOBAL_USER_TREE_HEIGHT, unique_pending_id)?;
        let checkpoint_tree_root = self.checkpoint_tree_root;
        let user = self.users.get_mut(&user_id).unwrap();
        let old_user_leaf = user.user_leaf.clone();
        //println!("user leaf: {:?}", old_user_leaf);
        let old_leaf_hash = if user.user_leaf.is_first_transaction_old_user_leaf_with_state(Hasher::get_zero_hash(N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE)){
            Hash::get_zero_value()
        }else{
            old_user_leaf.qfhash::<Hasher>()
        };
        let end_cap_input = user.run_ups(&self.contract_height_cache, checkpoint_id, checkpoint_tree_root, txs)?;

        let rand_status = rand::random::<u64>();

        let fake_checkpoint_id = rand_status;
        let context = QBlobWriterContextMetadataHeader::new_at_now(
            self.chain_id,
            self.node_id,
            self.realm_id_u64,
            self.realm_sub_id_u64,
            unique_pending_id,
            fake_checkpoint_id,
            user_id,
        );
        let contract_update_data_for_user = validate_end_cap_and_generate_node_data_for_edge::<F, Hash, Hasher>(&context, user_id, &end_cap_input)?;

        self.temp_db
            .set_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id, rand_status)
            .await?;

        self.temp_db
            .set_contract_updates_for_user(&self.realm_identifier, unique_pending_id, user_id, contract_update_data_for_user)
            .await?;
        /*
        let queue_key = RealmUserUpdateQueueKey::<F, Hash> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: self.unique_cord_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        };*/
        let new_user_leaf = end_cap_input.core.new_user_leaf.clone();
        let new_user_leaf_hash = new_user_leaf.qfhash::<Hasher>();

        let queue_item = PsyRealmUserUpdateQueueItem {
            job_id: job_id,
            expected_fake_checkpoint_id: fake_checkpoint_id,
            old_user_leaf_hash: old_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats: end_cap_input.core.stats,
        };
        Ok(queue_item)
    }

    pub async fn process_checkpoint(
        &mut self,
        contracts_to_deploy: &[u8],
        user_ups_list: &[(u64, Vec<RGPContractUpdate>)],
        apply_updates: bool,
    ) -> anyhow::Result<Option<RealmGUTAEndCapGathererOutput<F, Hash, QProvingJobDataID>>> {
        self.unique_pending_id += 1;
        let checkpoint_id = self.checkpoint_id;
        let unique_pending_id = self.unique_pending_id;
        let start_realm_root = self.first_realm_global_user_tree.get_root();
        let old_checkpoint_root = self.checkpoint_tree_root;
        for contract_height in contracts_to_deploy.iter() {
            self.add_new_contract(*contract_height).await?;
        }
        let backup_file_path = self.get_backup_file_path_for_unique_pending_id(unique_pending_id);

        let mut backup_file = self.backup_file_system.file_like_fs_create(&backup_file_path).await?;

        let mut realm_planner = RealmGUTAPlanner::<F, Hash>::new(
            0,
            self.realm_identifier,
            old_checkpoint_root,
            checkpoint_id,
            unique_pending_id,
            start_realm_root,
            N::REALM_GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_USER_TREE_HEIGHT,
            self.guta_circuit_whitelist,
        );

        for (user_id, ups) in user_ups_list.iter() {
            let queue_item = self.run_ups_for_user(*user_id, ups).await?;
            realm_planner
                .add_end_cap_job(
                    &self.checkpoint_tree,
                    &mut self.first_realm_global_user_tree,
                    &mut backup_file,
                    self.temp_db.clone(),
                    &queue_item.psy_ser_to_bytes_vec()?,
                    queue_item,
                )
                .await?;
        }
        self.backup_file_system
            .file_like_fs_flush_file_with_path(&backup_file_path, &mut backup_file)
            .await?;

        let result = realm_planner
            .finalize_with_reward_ids(&self.checkpoint_tree, &mut self.first_realm_global_user_tree, self.temp_db.clone(), 0, 0)
            .await?;

        if result.is_none() && user_ups_list.len() > 0 {
            anyhow::bail!("Expected some jobs to be processed in the checkpoint, but none were");
        }

        self.checkpoint_id += 1;
        self.unique_cord_proc_id = QCoreProcCheckpointUniqueId::qp_rand_gen();
        self.checkpoint_tree_root = self.checkpoint_tree.append_leaf(self.checkpoint_id, Hash::qp_rand_gen())?.new_root;
        if result.is_none() {
            return Ok(None);
        }
        let result = result.unwrap();

        if apply_updates {
            let new_checkpoint_id = self.checkpoint_id;
            self.coordinator_global_user_tree.set_e_leaf(self.realm_id_u64, result.db_output.new_realm_root);
            let pn = self.coordinator_global_user_tree.get_e_leaf(self.realm_id_u64).get_all_merkle_nodes_and_verify::<Hasher>()?;
            self.db.global_user_tree_set_nodes(new_checkpoint_id, &pn).await?;



            self.db
                .set_user_leaves_ffs(new_checkpoint_id, &result.db_output.update_user_leaves_ffs)
                .await?;
            self.db
                .global_user_tree_set_nodes_ffs(new_checkpoint_id, &result.db_output.update_global_user_tree_nodes_ffs)
                .await?;
            self.db
                .user_contract_tree_set_nodes_ffs(new_checkpoint_id, &result.db_output.update_user_contract_tree_nodes_ffs)
                .await?;
            self.db
                .contract_state_tree_set_nodes_ffs(new_checkpoint_id, &result.db_output.update_contract_state_tree_nodes_ffs)
                .await?;
        }

        Ok(Some(result))
    }
    pub async fn run_random_test_checkpoint(
        &mut self,
        num_users: usize,
        max_contracts_per_checkpoint: usize,
        max_txs_per_user_per_checkpoint: usize,
        max_leaves_per_tx: usize,
    ) -> anyhow::Result<(RealmGUTAEndCapGathererOutput<F, Hash, QProvingJobDataID>, Vec<u64>)> {
        if num_users == 0 {
            anyhow::bail!("num_users must be greater than 0");
        }
        if self.users.len() < num_users {
            for _ in self.users.len()..num_users {
                self.register_new_random_user().await?;
            }
        }
        if self.contract_height_cache.mapping.len() < max_contracts_per_checkpoint {
            for _ in self.contract_height_cache.mapping.len()..max_contracts_per_checkpoint {
                let contract_height = thread_rng().gen_range(12..=N::MAX_CONTRACT_STATE_TREE_HEIGHT as u8);
                self.add_new_contract(contract_height).await?;
            }
        }
        let mut user_ids = self.users.keys().cloned().collect::<Vec<u64>>();
        user_ids.shuffle(&mut thread_rng());
        user_ids.truncate(num_users.min(user_ids.len()));
        let mut user_ups_list = Vec::with_capacity(user_ids.len());
        for user_id in user_ids.iter() {
            let txs = self.gen_rand_contract_updates_for_ups(max_txs_per_user_per_checkpoint, max_leaves_per_tx)?;
            user_ups_list.push((*user_id, txs));
        }
        let result: Option<RealmGUTAEndCapGathererOutput<F, Hash, QProvingJobDataID>> =
            self.process_checkpoint(&vec![], &user_ups_list, true).await?;
        if result.is_none() {
            anyhow::bail!("Expected some jobs to be processed in the checkpoint, but none were");
        }
        let result = result.unwrap();
        self.ensure_state_matches_db().await?;

        Ok((result, user_ids))
    }
    pub async fn run_random_test_checkpoint_get_dbg_info(
        &mut self,
        num_users: usize,
        max_contracts_per_checkpoint: usize,
        max_txs_per_user_per_checkpoint: usize,
        max_leaves_per_tx: usize,
    ) -> anyhow::Result<(RealmGUTAEndCapGathererOutputDatabase<F, Hash>, Vec<Vec<RGPJobInfo>>, Vec<QProvingJobDataID>)> {
        let (res, user_ids) = self
            .run_random_test_checkpoint(
                num_users,
                max_contracts_per_checkpoint,
                max_txs_per_user_per_checkpoint,
                max_leaves_per_tx,
            )
            .await?;

        let end_cap_job_ids = user_ids.iter()
            .map(|user_id| {
                QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
                    *user_id,
                    N::GLOBAL_USER_TREE_HEIGHT,
                    self.unique_pending_id,
                )
            })
            .collect::<anyhow::Result<Vec<QProvingJobDataID>>>()?;


        let (job_levels, output) = {
            (res.job_ids, res.db_output)
        };

        basic_validate_job_results_singlet_case(&end_cap_job_ids, &job_levels)?;



        let mut outputs = Vec::with_capacity(job_levels.len());
        for (level_index, level) in job_levels.iter().enumerate() {
            let mut level_outputs = Vec::with_capacity(level.len());
            for (job_index, j) in level.iter().enumerate() {
                let raw_witness = self.temp_db.get_tdb_proof_witness_bytes(&self.realm_identifier, self.unique_pending_id, j.job_id).await.map_err(|e|{
                    anyhow::anyhow!("error fetching witness for job: {:?}: {:?}", j.job_id, e)
                })?;
                let info = RGPJobInfo::new_from_metadata_and_raw_witness(j, level_index, job_index, &raw_witness).map_err(|e|{
                    anyhow::anyhow!("error deserializing witness for job: {:?}: {:?}", j.job_id, e)
                })?;
                level_outputs.push(info);
            }
            outputs.push(level_outputs);
        }


        Ok((output, outputs, end_cap_job_ids))




    }
}

pub fn basic_validate_job_results_singlet_case(end_cap_job_ids: &[QProvingJobDataID], results: &[Vec<PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>>]) -> anyhow::Result<()> {
    if end_cap_job_ids.len() == 0 {
        anyhow::bail!("end_cap_job_ids cannot be empty");
    }else if end_cap_job_ids.len() == 1 {
        if results.len() != 1 {
            anyhow::bail!("Expected 1 level of results for 1 end cap job id, but got {}", results.len());
        }else if results[0].len() != 1 {
            anyhow::bail!("Expected 1 job result for 1 end cap job id, but got {}", results[0].len());
        }
        let single_result = &results[0][0];
        if single_result.job_id.circuit_type != ProvingJobCircuitType::GUTASingleEndCap {
            anyhow::bail!("Expected GUTASingleEndCap job for 1 end cap job id, but got {:?}", single_result.job_id.circuit_type);
        }
        if single_result.metadata.dependencies.len() != 1 || single_result.metadata.dependencies[0] != end_cap_job_ids[0] {
            anyhow::bail!("Expected dependency to be the end cap job id for 1 end cap job id, but got {:?}", single_result.metadata.dependencies);
        }
    }else if end_cap_job_ids.len() == 2 {
        if results.len() != 1 {
            anyhow::bail!("Expected 1 level of results for 2 end cap job ids, but got {}", results.len());
        }else if results[0].len() != 1 {
            anyhow::bail!("Expected 1 job result for 2 end cap job ids, but got {}", results[0].len());
        }
        let single_result = &results[0][0];
        if single_result.job_id.circuit_type != ProvingJobCircuitType::GUTATwoEndCap {
            anyhow::bail!("Expected GUTATwoEndCap job for 2 end cap job ids, but got {:?}", single_result.job_id.circuit_type);
        }
        if &end_cap_job_ids != &single_result.metadata.dependencies {
            anyhow::bail!("Expected dependencies to be the end cap job ids for 2 end cap job ids, but got {:?}", single_result.metadata.dependencies);
        }
    }
    Ok(())
}
#[derive(Clone, Debug)]
pub enum RGPJobWitness {
    TwoLinear(GUTAVerifyTwoGUTALinearCircuitInput<F, Hash>),
    TwoEndCap(GUTAVerifyTwoEndCapCircuitInputV2<F, Hash>),
    LeftGUTARightEndCap(GUTAVerifyLeftGUTARightEndCapCircuitInputV2<F, Hash>),
    SingleEndCap(VerifySingleEndCapInputV2<F, Hash>),
}
impl RGPJobWitness {
    pub fn from_witness_bytes_for_circuit_type(
        circuit_type: ProvingJobCircuitType,
        witness_bytes: &[u8],
    ) -> anyhow::Result<Self> {
        match circuit_type {
            ProvingJobCircuitType::GUTATwoGUTALinear => {
                Ok(RGPJobWitness::TwoLinear(GUTAVerifyTwoGUTALinearCircuitInput::psy_ser_from_slice(witness_bytes)?))
            }
            ProvingJobCircuitType::GUTATwoEndCap => {
                Ok(RGPJobWitness::TwoEndCap(GUTAVerifyTwoEndCapCircuitInputV2::psy_ser_from_slice(witness_bytes)?))
            }
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
                Ok(RGPJobWitness::LeftGUTARightEndCap(GUTAVerifyLeftGUTARightEndCapCircuitInputV2::psy_ser_from_slice(witness_bytes)?))
            }
            ProvingJobCircuitType::GUTASingleEndCap => {
                Ok(RGPJobWitness::SingleEndCap(VerifySingleEndCapInputV2::psy_ser_from_slice(witness_bytes)?))
            }
            _ => {
                anyhow::bail!("Unsupported circuit type for RGPJobWitness: {:?}", circuit_type);
            }
        }
    }
    pub fn get_guta_header(&self, guta_circuit_whitelist: Hash) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        match self {
            RGPJobWitness::TwoLinear(witness) => witness.get_new_guta_header(),
            RGPJobWitness::TwoEndCap(witness) => witness.get_new_guta_header(N::GLOBAL_USER_TREE_HEIGHT_USIZE, guta_circuit_whitelist),
            RGPJobWitness::LeftGUTARightEndCap(witness) => witness.get_new_guta_header(),
            RGPJobWitness::SingleEndCap(witness) => witness.get_new_guta_header(N::GLOBAL_USER_TREE_HEIGHT),
        }
    }
    pub fn get_left_child_guta_header(&self, guta_circuit_whitelist: Hash) -> GlobalUserTreeAggregatorHeader<F, Hash> {
        match self {
            RGPJobWitness::TwoLinear(witness) => witness.get_guta_header_a(),
            RGPJobWitness::LeftGUTARightEndCap(witness) => witness.get_guta_header_a(),
            RGPJobWitness::SingleEndCap(witness) => witness.get_guta_header_a(N::GLOBAL_USER_TREE_HEIGHT),
            RGPJobWitness::TwoEndCap(witness) => witness.get_guta_header_a(N::GLOBAL_USER_TREE_HEIGHT_USIZE, guta_circuit_whitelist),
        }
    }
    pub fn get_right_child_guta_header(&self, guta_circuit_whitelist: Hash) -> anyhow::Result<GlobalUserTreeAggregatorHeader<F, Hash>> {
        Ok(match self {
            RGPJobWitness::TwoLinear(witness) => witness.get_guta_header_b(),
            RGPJobWitness::LeftGUTARightEndCap(witness) => witness.get_guta_header_b(N::GLOBAL_USER_TREE_HEIGHT_USIZE),
            RGPJobWitness::TwoEndCap(witness) => witness.get_guta_header_b(N::GLOBAL_USER_TREE_HEIGHT_USIZE, guta_circuit_whitelist),
            RGPJobWitness::SingleEndCap(_) => {
                anyhow::bail!("No right child for SingleEndCap witness");
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct RGPJobInfo {
    pub job_id: QProvingJobDataID,
    pub job_level: usize,
    pub job_index_in_level: usize,
    pub parent_job_id: QProvingJobDataID, // if none, then use invalid job
    pub metadata: PsyProvingJobMetadata<Hash, QProvingJobDataID>,
    pub witness: RGPJobWitness,
}

impl RGPJobInfo {
    pub fn new_from_metadata_and_raw_witness(
        job_with_metadata: &PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>,
        job_level: usize,
        job_index_in_level: usize,
        witness_bytes: &[u8],
    ) -> anyhow::Result<Self> {
        let witness = RGPJobWitness::from_witness_bytes_for_circuit_type(job_with_metadata.job_id.circuit_type, witness_bytes)?;
        let parent_job_id = QProvingJobDataID::new_invalid_job_id();
        //println!("witness for job {:?}: {:?}", job_with_metadata.job_id, witness);
        Ok(Self {
            job_id: job_with_metadata.job_id.clone(),
            parent_job_id,
            metadata: job_with_metadata.metadata.clone(),
            witness,
            job_level,
            job_index_in_level,
        })
    }
    pub fn test_basic_continuity_check(&self, guta_circuit_whitelist: Hash) -> anyhow::Result<()> {

        if self.metadata.dependencies.len() == 1 {
            let w = match &self.witness {
                RGPJobWitness::SingleEndCap(w) => w,
                _ => {
                    anyhow::bail!("Expected SingleEndCap witness for 1 dependency, but got {:?}", self.job_id.circuit_type);
                }
            };
            if !w.global_user_tree_sub_root_transition.verify::<Hasher>() {
                anyhow::bail!("Global user tree sub root transition verification failed for job {:?}", self.job_id);
            }
            

            return Ok(())
        }else if self.metadata.dependencies.len() == 2 {
            match &self.witness {
                RGPJobWitness::TwoLinear(w) => {
                    if w.left_header.state_transition.node_index != w.right_header.state_transition.node_index {
                        anyhow::bail!("Node index mismatch between left and right child for TwoLinear witness for job {:?} (left node_index: {}, right node_index: {})", self.job_id, w.left_header.state_transition.node_index, w.right_header.state_transition.node_index);
                    }
                    if w.left_header.state_transition.node_level != w.right_header.state_transition.node_level {
                        anyhow::bail!("Node level mismatch between left and right child for TwoLinear witness for job {:?} (left node_level: {}, right node_level: {})", self.job_id, w.left_header.state_transition.node_level, w.right_header.state_transition.node_level);
                    }
                    if w.left_header.state_transition.new_node_value != w.right_header.state_transition.old_node_value {
                        anyhow::bail!("Node value mismatch between left and right child for TwoLinear witness for job, as it must be 'back-to-back' for linear {:?} (left new_node_value: {:?}, right old_node_value: {:?})", self.job_id, w.left_header.state_transition.new_node_value, w.right_header.state_transition.old_node_value);
                    }
                    if w.left_header.checkpoint_tree_root != w.right_header.checkpoint_tree_root {
                        anyhow::bail!("Checkpoint tree root mismatch between left and right child for TwoLinear witness for job {:?} (left checkpoint_tree_root: {:?}, right checkpoint_tree_root: {:?})", self.job_id, w.left_header.checkpoint_tree_root, w.right_header.checkpoint_tree_root);
                    }
                },
                RGPJobWitness::TwoEndCap(w) => {
                    if w.left_global_user_tree_delta_merkle_proof.siblings.len() != w.right_global_user_tree_delta_merkle_proof.siblings.len() {
                        anyhow::bail!("Global user tree delta merkle proof siblings len mismatch between left and right child for TwoEndCap witness for job {:?} (left siblings len: {:?}, right siblings len: {:?})", self.job_id, w.left_global_user_tree_delta_merkle_proof.siblings.len(), w.right_global_user_tree_delta_merkle_proof.siblings.len());
                    }
                    let left_parent = w.left_global_user_tree_delta_merkle_proof.index >> w.left_global_user_tree_delta_merkle_proof.siblings.len();
                    let right_parent = w.right_global_user_tree_delta_merkle_proof.index >> w.right_global_user_tree_delta_merkle_proof.siblings.len();
                    if left_parent != right_parent {
                        anyhow::bail!("Global user tree delta merkle proof parent index mismatch between left and right child for TwoEndCap witness for job {:?} (left parent index: {:?}, right parent index: {:?})", self.job_id, left_parent, right_parent);
                    }
                    if !w.left_end_cap.checkpoint_historical_merkle_proof.verify::<Hasher>() {
                        anyhow::bail!("Left end cap checkpoint historical merkle proof verification failed for job {:?}", self.job_id);
                    }
                    if !w.right_end_cap.checkpoint_historical_merkle_proof.verify::<Hasher>() {
                        anyhow::bail!("Right end cap checkpoint historical merkle proof verification failed for job {:?}", self.job_id);
                    }
                    if w.left_end_cap.checkpoint_historical_merkle_proof.root != w.right_end_cap.checkpoint_historical_merkle_proof.root {
                        anyhow::bail!("Checkpoint historical merkle proof root mismatch between left and right child for TwoEndCap witness for job {:?} (left root: {:?}, right root: {:?})", self.job_id, w.left_end_cap.checkpoint_historical_merkle_proof.root, w.right_end_cap.checkpoint_historical_merkle_proof.root);
                    }
                    if w.left_global_user_tree_delta_merkle_proof.new_root != w.right_global_user_tree_delta_merkle_proof.old_root {
                        anyhow::bail!("Global user tree delta merkle proof root mismatch between left and right child for TwoEndCap witness for job {:?} (left new_root: {:?}, right old_root: {:?})", self.job_id, w.left_global_user_tree_delta_merkle_proof.new_root, w.right_global_user_tree_delta_merkle_proof.old_root);
                    }
                },
                RGPJobWitness::LeftGUTARightEndCap(w) => {
                    let left_level = w.left_header.state_transition.node_level.to_u64_value() as usize;
                    let left_index = w.left_header.state_transition.node_index.to_u64_value();
                    let right_level = N::GLOBAL_USER_TREE_HEIGHT_USIZE - w.right_global_user_tree_delta_merkle_proof.siblings.len();
                    let right_index = w.right_global_user_tree_delta_merkle_proof.index>>&w.right_global_user_tree_delta_merkle_proof.siblings.len();
                    if !w.right_global_user_tree_delta_merkle_proof.verify::<Hasher>() {
                        anyhow::bail!("Right end cap global user tree delta merkle proof verification failed for job {:?}", self.job_id);
                    }
                    if left_level != right_level {
                        anyhow::bail!("Node level mismatch between left GUTA and right end cap child for LeftGUTARightEndCap witness for job {:?} (left node_level: {}, right node_level: {})", self.job_id, left_level, right_level);
                    }
                    if left_index != right_index {
                        anyhow::bail!("Node index mismatch between left GUTA and right end cap child for LeftGUTARightEndCap witness for job {:?} (left node_index: {}, right node_index: {})", self.job_id, left_index, right_index);
                    }
                    if w.left_header.state_transition.new_node_value != w.right_global_user_tree_delta_merkle_proof.old_root {
                        anyhow::bail!("Node value mismatch between left GUTA and right end cap child for LeftGUTARightEndCap witness for job {:?} (left new_node_value: {:?}, right old_root: {:?})", self.job_id, w.left_header.state_transition.new_node_value, w.right_global_user_tree_delta_merkle_proof.old_root);
                    }
                    if w.left_header.checkpoint_tree_root != w.right_end_cap.checkpoint_historical_merkle_proof.root {
                        anyhow::bail!("Checkpoint tree root mismatch between left GUTA and right end cap child for LeftGUTARightEndCap witness for job {:?} (left checkpoint_tree_root: {:?}, right root: {:?})", self.job_id, w.left_header.checkpoint_tree_root, w.right_end_cap.checkpoint_historical_merkle_proof.root);
                    }
                },
                _ => {
                    anyhow::bail!("Expected TwoLinear, TwoEndCap, or LeftGUTARightEndCap witness for 2 dependencies, but got {:?}", self.job_id.circuit_type);
                }
            }


        }else{
            anyhow::bail!("Expected 1 or 2 dependencies, but got {} for job {:?}", self.metadata.dependencies.len(), self.job_id);
        }
        Ok(())
        
    }

    pub fn basic_dependency_type_verify(&self) -> anyhow::Result<()> {
        let dependency_types = self.metadata.dependencies.iter().map(|d| d.circuit_type).collect::<Vec<_>>();
        let left_child_type = dependency_types[0];
        let right_child_type = if dependency_types.len() > 1 {
            dependency_types[1]
        } else {
            ProvingJobCircuitType::Invalid 
        };
        match self.job_id.circuit_type {
            ProvingJobCircuitType::GUTATwoGUTALinear => {
                if !matches!(left_child_type, ProvingJobCircuitType::GUTATwoGUTALinear | ProvingJobCircuitType::GUTALeftGUTARightEndCap | ProvingJobCircuitType::GUTATwoEndCap) {
                    anyhow::bail!("Invalid left dependency type for GUTATwoGUTALinear: {:?}", left_child_type);
                }else if !matches!(right_child_type, ProvingJobCircuitType::GUTATwoGUTALinear | ProvingJobCircuitType::GUTALeftGUTARightEndCap | ProvingJobCircuitType::GUTATwoEndCap) {
                    anyhow::bail!("Invalid right dependency type for GUTATwoGUTALinear: {:?}", right_child_type);
                }
            }
            ProvingJobCircuitType::GUTATwoEndCap => {
                if left_child_type != ProvingJobCircuitType::UserEndCap {
                    anyhow::bail!("Invalid left dependency type for GUTATwoEndCap: {:?}", left_child_type);
                }else if right_child_type != ProvingJobCircuitType::UserEndCap {
                    anyhow::bail!("Invalid right dependency type for GUTATwoEndCap: {:?}", right_child_type);
                }
            }
            ProvingJobCircuitType::GUTALeftGUTARightEndCap => {
                if !matches!(left_child_type, ProvingJobCircuitType::GUTATwoGUTALinear | ProvingJobCircuitType::GUTALeftGUTARightEndCap | ProvingJobCircuitType::GUTATwoEndCap) {
                    anyhow::bail!("Invalid left dependency type for GUTALeftGUTARightEndCap: {:?}", left_child_type);
                }else if right_child_type != ProvingJobCircuitType::UserEndCap {
                    anyhow::bail!("Invalid right dependency type for GUTALeftGUTARightEndCap: {:?}", right_child_type);
                }
            }
            ProvingJobCircuitType::GUTASingleEndCap => {
                if left_child_type != ProvingJobCircuitType::UserEndCap {
                    anyhow::bail!("Invalid dependency type for GUTASingleEndCap: {:?}", left_child_type);
                }else if right_child_type != ProvingJobCircuitType::Invalid {
                    anyhow::bail!("GUTASingleEndCap should not have a right dependency, but got {:?}", right_child_type);
                }
            }
            _ => {
                anyhow::bail!("Unsupported circuit type for RGPJobInfo: {:?}", self.job_id.circuit_type);
            }
        }
        Ok(())
    }
}


// Helper function to make Rust Debug strings safe for DOT IDs
fn sanitize_dot_id(id: &str) -> String {
    id.replace(" ", "")
      .replace("(", "_")
      .replace(")", "_")
      .replace("[", "_")
      .replace("]", "_")
      .replace(",", "_")
      .replace(":", "")
      .replace("\"", "")
}

#[derive(Clone)]
pub struct RGPTestResultValidator {
    pub end_cap_job_ids: Vec<QProvingJobDataID>,
    pub job_levels: Vec<Vec<QProvingJobDataID>>,
    pub job_map: HashMap<QProvingJobDataID, RGPJobInfo>,
    pub child_to_parent_map: HashMap<QProvingJobDataID, QProvingJobDataID>,
    pub output_database: RealmGUTAEndCapGathererOutputDatabase<F, Hash>,
    pub guta_circuit_whitelist: Hash,
}

// Simple sanitizer for the unique leaf IDs
fn sanitize_dot_id_simple(id: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    // Hashing is safer/shorter for generated leaf IDs than sanitizing arbitrary strings
    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}
impl RGPTestResultValidator {
    pub fn new(
        guta_circuit_whitelist: Hash,
        output_database: RealmGUTAEndCapGathererOutputDatabase<F, Hash>,
        rgp_job_info: Vec<Vec<RGPJobInfo>>,
        end_cap_job_ids: Vec<QProvingJobDataID>,
    ) -> anyhow::Result<Self> {

        let job_levels: Vec<Vec<QProvingJobDataID>> = rgp_job_info
            .iter()
            .map(|level| level.iter().map(|job_info| job_info.job_id.clone()).collect())
            .collect();

        let mut job_map: HashMap<QProvingJobDataID, RGPJobInfo> = HashMap::new();
        let mut child_to_parent_map: HashMap<QProvingJobDataID, QProvingJobDataID> = HashMap::new();
        for l in rgp_job_info.iter() {
            for job_info in l.iter() {
                job_info.basic_dependency_type_verify()?;
                job_info.test_basic_continuity_check(guta_circuit_whitelist)?;
                if job_info.metadata.dependencies.len() == 2 {
                    if child_to_parent_map.contains_key(&job_info.metadata.dependencies[0]) {
                        anyhow::bail!("Job {:?} dependency {:?} already has a parent assigned", job_info.job_id, job_info.metadata.dependencies[0]);
                    }
                    if child_to_parent_map.contains_key(&job_info.metadata.dependencies[1]) {
                        anyhow::bail!("Job {:?} dependency {:?} already has a parent assigned", job_info.job_id, job_info.metadata.dependencies[1]);
                    }
                    child_to_parent_map.insert(job_info.metadata.dependencies[0].clone(), job_info.job_id.clone());
                    child_to_parent_map.insert(job_info.metadata.dependencies[1].clone(), job_info.job_id.clone());
                } else if job_info.metadata.dependencies.len() == 1 {
                    if child_to_parent_map.contains_key(&job_info.metadata.dependencies[0]) {
                        anyhow::bail!("Job {:?} dependency {:?} already has a parent assigned", job_info.job_id, job_info.metadata.dependencies[0]);
                    }
                    child_to_parent_map.insert(job_info.metadata.dependencies[0].clone(), job_info.job_id.clone());
                }else{
                    anyhow::bail!("Job {:?} has invalid number of dependencies: {}", job_info.job_id, job_info.metadata.dependencies.len());
                }
            }
        }

        for l in rgp_job_info {
            for job_info in l {
                let mut ji = job_info.clone();
                ji.parent_job_id = child_to_parent_map.get(&job_info.job_id).cloned().unwrap_or(QProvingJobDataID::new_invalid_job_id());
                job_map.insert(job_info.job_id.clone(), ji);
            }
        }

        Ok(Self {
            end_cap_job_ids,
            job_levels,
            job_map,
            child_to_parent_map,
            output_database,
            guta_circuit_whitelist,
        })
    }pub fn generate_graph_viz(&self) -> String {
        use std::fmt::Write;
        use std::collections::HashMap;

        let mut dot = String::new();
        // 1. Graph Attributes - Clean, Binary Tree Style
        writeln!(dot, "digraph G {{").unwrap();
        writeln!(dot, "  rankdir=BT;").unwrap();
        writeln!(dot, "  ordering=in;").unwrap(); // Preserves left-to-right order of dependencies
        writeln!(dot, "  node [shape=box, fontname=\"Courier\", fontsize=10, style=filled, fillcolor=\"#FFFFFF\"];").unwrap();
        writeln!(dot, "  edge [color=\"black\"];").unwrap();

        // Helpers to map Job IDs to Graph Node IDs
        let mut job_id_to_node_id: HashMap<QProvingJobDataID, String> = HashMap::new();
        
        // 2. Define Internal Nodes (Grouped by Level)
        for (level_idx, level_jobs) in self.job_levels.iter().enumerate() {
            writeln!(dot, "  subgraph cluster_level_{} {{", level_idx).unwrap();
            writeln!(dot, "    rank=same;").unwrap(); // Force alignment
            writeln!(dot, "    style=invis;").unwrap();

            for (job_index, job_id) in level_jobs.iter().enumerate() {
                let info = self.job_map.get(job_id).expect("Job ID must exist in map");
                let node_id = format!("job_{}_{}", level_idx, job_index);
                
                job_id_to_node_id.insert(job_id.clone(), node_id.clone());

                // Format: CircuitType \n RewLvl | RewIdx
                let type_str = format!("{:?}", info.job_id.circuit_type).replace("ProvingJobCircuitType::", "");
                
                // Optional: Color coding based on type
                let fill_color = match info.job_id.circuit_type {
                    ProvingJobCircuitType::GUTATwoGUTALinear => "#FFE0B2", // Orange
                    ProvingJobCircuitType::GUTATwoEndCap => "#BBDEFB",     // Blue
                    ProvingJobCircuitType::GUTASingleEndCap => "#FFCDD2",  // Red
                    ProvingJobCircuitType::GUTALeftGUTARightEndCap => "#E1BEE7", // Purple
                    _ => "#FFFFFF"
                };

                let label = format!(
                    "{}\\nRewLvl: {}\\nRewIdx: {}", 
                    type_str,
                    info.metadata.reward_tree_node_level,
                    info.metadata.reward_tree_node_index
                );

                writeln!(dot, "    {} [label=\"{}\", fillcolor=\"{}\"];", node_id, label, fill_color).unwrap();

                // Horizontal Constraint (Invisible edge)
                if job_index > 0 {
                    let prev_node_id = format!("job_{}_{}", level_idx, job_index - 1);
                    writeln!(dot, "    {} -> {} [style=invis, weight=2];", prev_node_id, node_id).unwrap();
                }
            }
            writeln!(dot, "  }}").unwrap();
        }

        // 3. Define Leaf Nodes (User Inputs)
        // These are dependencies of Level 0 (or others) that are NOT in the job_map
        let mut leaf_ids: Vec<(QProvingJobDataID, String)> = Vec::new();
        let mut leaf_counter = 0;

        writeln!(dot, "  subgraph cluster_inputs {{").unwrap();
        writeln!(dot, "    rank=same;").unwrap();
        writeln!(dot, "    style=invis;").unwrap();

        // We iterate specifically through existing jobs to find their inputs
        // to maintain a deterministic order corresponding to the tree structure
        for level_jobs in &self.job_levels {
            for job_id in level_jobs {
                let info = self.job_map.get(job_id).unwrap();
                for dep in &info.metadata.dependencies {
                    if !self.job_map.contains_key(dep) {
                        // This is a leaf (User Input)
                        // Check if we already assigned a node ID (in case of DAG re-use), 
                        // though typically in Merkle trees these are unique per path.
                        // We generate a new visual node to keep the tree visually expanded 
                        // (like the reference image) unless strict DAG is required. 
                        // The reference image implies expanded tree.
                        
                        let node_id = format!("leaf_{}", leaf_counter);
                        leaf_counter += 1;
                        leaf_ids.push((dep.clone(), node_id.clone()));

                        // Direct access to task_index as requested
                        let label = format!("User: {}", dep.task_index);
                        
                        writeln!(dot, "    {} [label=\"{}\", fillcolor=\"#C8E6C9\"];", node_id, label).unwrap();

                        // Horizontal Constraint for leaves
                        if leaf_counter > 1 {
                            let prev_node_id = format!("leaf_{}", leaf_counter - 2);
                            writeln!(dot, "    {} -> {} [style=invis, weight=2];", prev_node_id, node_id).unwrap();
                        }
                    }
                }
            }
        }
        writeln!(dot, "  }}").unwrap();

        // 4. Draw Logic Edges
        // We use a counter for leaves to consume them in order (since we generated them in order)
        // This ensures the edges connect to the specific visual instance of the leaf
        let mut leaf_consumption_idx = 0;

        for job_id_vec in &self.job_levels {
            for job_id in job_id_vec {
                let info = self.job_map.get(job_id).unwrap();
                let parent_node = job_id_to_node_id.get(job_id).unwrap();

                for dep in &info.metadata.dependencies {
                    if let Some(child_node) = job_id_to_node_id.get(dep) {
                        // Edge to internal node
                        writeln!(dot, "  {} -> {};", child_node, parent_node).unwrap();
                    } else {
                        // Edge to leaf node
                        // We find the specific visual leaf node we created in step 3
                        if leaf_consumption_idx < leaf_ids.len() {
                            let (dep_id, leaf_node_id) = &leaf_ids[leaf_consumption_idx];
                            // Sanity check: ensure IDs match
                            if dep_id == dep {
                                writeln!(dot, "  {} -> {};", leaf_node_id, parent_node).unwrap();
                                leaf_consumption_idx += 1;
                            } else {
                                // Fallback if order drifted (shouldn't happen with single thread)
                                // Just find the leaf node by iterating
                                let match_leaf = leaf_ids.iter().find(|(d, _)| d == dep).map(|(_, n)| n);
                                if let Some(n) = match_leaf {
                                     writeln!(dot, "  {} -> {};", n, parent_node).unwrap();
                                }
                            }
                        }
                    }
                }
            }
        }

        writeln!(dot, "}}").unwrap();
        dot
    }


    pub fn run_full_tests(&self) -> anyhow::Result<()> {

        for l in self.job_levels.iter() {
            for j in l.iter() {
                let job_info = self.job_map.get(j).ok_or_else(|| anyhow::anyhow!("Job {:?} not found in job map", j))?;
                if job_info.metadata.dependencies.len() == 2 && job_info.job_id.circuit_type == ProvingJobCircuitType::GUTATwoGUTALinear{
                    let left_child_id = &job_info.metadata.dependencies[0];
                    let right_child_id = &job_info.metadata.dependencies[1];
                    let left_child_info = self.job_map.get(left_child_id).ok_or_else(|| anyhow::anyhow!("Left child job {:?} not found in job map", left_child_id))?;
                    let right_child_info = self.job_map.get(right_child_id).ok_or_else(|| anyhow::anyhow!("Right child job {:?} not found in job map", right_child_id))?;

                    let left_guta_header = left_child_info.witness.get_guta_header(self.guta_circuit_whitelist);
                    let right_guta_header = right_child_info.witness.get_guta_header(self.guta_circuit_whitelist);

                    let expected_left_guta_header = job_info.witness.get_left_child_guta_header(self.guta_circuit_whitelist);
                    let expected_right_guta_header = job_info.witness.get_right_child_guta_header(self.guta_circuit_whitelist)?;
                    if left_guta_header.qfhash::<Hasher>() != expected_left_guta_header.qfhash::<Hasher>() {
                        anyhow::bail!("Left GUTA header mismatch for job {:?}: expected {:?}, got {:?}", j, expected_left_guta_header, left_guta_header);
                    }
                    if right_guta_header.qfhash::<Hasher>() != expected_right_guta_header.qfhash::<Hasher>() {
                        anyhow::bail!("Right GUTA header mismatch for job {:?}: expected {:?}, got {:?}", j, expected_right_guta_header, right_guta_header);
                    }
                } else if job_info.metadata.dependencies.len() == 1 || job_info.job_id.circuit_type == ProvingJobCircuitType::GUTALeftGUTARightEndCap {
                    let child_id = &job_info.metadata.dependencies[0];
                    let child_info = self.job_map.get(child_id).ok_or_else(|| anyhow::anyhow!("Child job {:?} not found in job map", child_id))?;
                    let child_guta_header = child_info.witness.get_guta_header(self.guta_circuit_whitelist);
                    let expected_child_guta_header = job_info.witness.get_left_child_guta_header(self.guta_circuit_whitelist);
                    if child_guta_header.qfhash::<Hasher>() != expected_child_guta_header.qfhash::<Hasher>() {
                        anyhow::bail!("Child GUTA header mismatch for job {:?}: expected {:?}, got {:?}", j, expected_child_guta_header, child_guta_header);
                    }
                }
            }
        }

        if self.job_levels.len() != log2_ceil(self.end_cap_job_ids.len()) {
            anyhow::bail!("job levels length {} should be equal to log2_ceil of end cap job ids length {}", self.job_levels.len(), log2_ceil(self.end_cap_job_ids.len()));
        }
        Ok(())
    }
}
#[tokio::test]
async fn test_rgp_chain_state_basic() -> anyhow::Result<()> {
    cf_utils::logging::setup_logging()?;
    let guta_circuit_whitelist = Hash::from_u64x4([1337, 69, 420, 9696]);
    let mut chain_state = RGPTestChainState::create_for_tests().await?;
    for i in 2..500 {
        println!("Running RGP random test checkpoint with {} users", i);
        let (db_output, job_info, end_cap_jobs) = chain_state.run_random_test_checkpoint_get_dbg_info(i, 3, 2, 5).await?;
        let validation_results = RGPTestResultValidator::new(guta_circuit_whitelist, db_output, job_info, end_cap_jobs)?;
        validation_results.run_full_tests().map_err(|e| anyhow::anyhow!("failed {i} users run_full tests with error: {:?}", e))?;
        //println!("{}", validation_results.generate_graph_viz());
    }




    Ok(())
}



#[tokio::test]
async fn check_many_and_print_errors() -> anyhow::Result<()> {
    //cf_utils::logging::setup_logging()?;
    let guta_circuit_whitelist = Hash::from_u64x4([1337, 69, 420, 9696]);
    let mut chain_state = RGPTestChainState::create_for_tests().await?;
    for i in 2..200 {
        println!("Running RGP random test checkpoint with {} users", i);
        let (db_output, job_info, end_cap_jobs) = chain_state.run_random_test_checkpoint_get_dbg_info(i, 3, 2, 5).await?;
        let res = RGPTestResultValidator::new(guta_circuit_whitelist, db_output, job_info, end_cap_jobs).map(|x| x.run_full_tests()).map_err(|e| anyhow::anyhow!("failed {i} users run_full tests with error: {:?}", e));
        if res.is_err() {
            println!("ERROR detected for {i} jobs: {:#?}", res.err().unwrap());
        }else{
            println!("Successfully procesed batch of {i} jobs");
        }
        
    }




    Ok(())
}
