use std::{sync::Arc, u64};

use async_trait::async_trait;
use cf_utils::timer::DebugTimer;
use jsonrpsee::core::RpcResult;
use parth_core::{
    QProvingJobDataIDWithRewardPath, crypto::{
        hash::{
            merkle_proof::MerkleProofCore,
            traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest},
    }, data::{hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey}}, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QNetworkTypesConfig, QZKProofPublicInputsHasherReader, QZKProofVerifier}
};
use psy_api_core::{realm::standard_edge_rpc::RealmEdgeRpcServer, worker::standard_worker_rpc::NodeEdgeWorkerRpcServer};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    node::node_proving_state::PsyNodeProvingState, proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, queue_items::realm_user_update::PsyRealmUserUpdateQueueItem, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{DashMapContractHeightCache, PSimpleContractHeightCache},
            user::PQEDUserLeaf,
        },
    }, worker::api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse}
};
use psy_node_core::{
    psy_core_db::
        traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader}
    ,
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    qblob::structs::common::blob_metadata_header::QBlobWriterContextMetadataHeader,
    queue::{
        ephemeral::QStandardEphemeralQueuePublisher,
        worker_queue::QStandardWorkerQueueSubscriber,
    },
    store::traits::
        proof_store::QParthProofStore
    ,
};

use crate::realm::{
    edge::{error::RpcError, utils::end_cap::validate_end_cap_and_generate_node_data_for_edge},
    queue_key::RealmUserUpdateQueueKey,
};

const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
pub struct RealmEdgeHandler<
    N: QNetworkTypesConfig,
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    UserUpdateQueue: QStandardEphemeralQueuePublisher,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
> {
    pub db_reader: Arc<S>,
    pub tag_tree_rewards_store: Arc<STagTreeRewards>,
    pub temp_db: Arc<TempDatabase>,
    pub proof_store: Arc<ProofStore>,

    pub user_update_queue: Arc<UserUpdateQueue>,
    pub get_proof_work_queue: Arc<GetProofWorkQueue>,

    pub realm_identifier: QRealmIdentifier,
    pub realm_id_u64: u64,
    pub realm_sub_id_u64: u64,
    pub chain_id: u32,
    pub node_id: u32,

    pub proof_verifier: Arc<N::ZKVerifier>,
    pub contract_state_tree_height_cache: Arc<DashMapContractHeightCache<N::QHash>>,
}
impl<
        N: QNetworkTypesConfig,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > Clone for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    fn clone(&self) -> Self {
        Self {
            db_reader: self.db_reader.clone(),
            tag_tree_rewards_store: self.tag_tree_rewards_store.clone(),
            temp_db: self.temp_db.clone(),
            proof_store: self.proof_store.clone(),
            user_update_queue: self.user_update_queue.clone(),
            get_proof_work_queue: self.get_proof_work_queue.clone(),
            realm_identifier: self.realm_identifier.clone(),
            realm_id_u64: self.realm_id_u64.clone(),
            realm_sub_id_u64: self.realm_sub_id_u64.clone(),
            chain_id: self.chain_id.clone(),
            node_id: self.node_id.clone(),
            proof_verifier: self.proof_verifier.clone(),
            contract_state_tree_height_cache: self.contract_state_tree_height_cache.clone(),
        }
    }
}
impl<
        N: QNetworkTypesConfig,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    pub fn new(
        db: Arc<S>,
        tag_tree_rewards_store: Arc<STagTreeRewards>,
        temp_db: Arc<TempDatabase>,
        proof_store: Arc<ProofStore>,
        user_update_queue: Arc<UserUpdateQueue>,
        get_proof_work_queue: Arc<GetProofWorkQueue>,
        realm_identifier: QRealmIdentifier,
        chain_id: u32,
        node_id: u32,
        proof_verifier: Arc<N::ZKVerifier>,
    ) -> Self {
        let realm_id_u64 = realm_identifier.realm_id as u64;
        let realm_sub_id_u64 = realm_identifier.realm_sub_id as u64;
        Self {
            db_reader: db,
            tag_tree_rewards_store,
            temp_db,
            proof_store,
            user_update_queue,
            get_proof_work_queue,
            realm_identifier,
            realm_id_u64,
            realm_sub_id_u64,
            chain_id,
            node_id,
            proof_verifier,
            contract_state_tree_height_cache: Arc::new(DashMapContractHeightCache::new()),
        }
    }
    pub fn user_belongs_to_realm(&self, user_id: u64) -> bool {
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let min_user_id = self.realm_id_u64 * users_per_realm;
        let max_user_id = min_user_id + users_per_realm;
        user_id >= min_user_id && user_id < max_user_id
    }
    pub async fn get_latest_checkpoint_id(&self) -> anyhow::Result<u64> {
        self.db_reader.get_latest_checkpoint_id().await
    }
    pub async fn ensure_user_has_not_submitted(&self, user_id: u64, unique_pending_id: u64) -> anyhow::Result<()> {
        //tracing::info!("here");
        let submitted_status = self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id)
            .await?;
        //tracing::info!("submitted_status: {}", submitted_status);
        if submitted_status != 0 {
            anyhow::bail!(
                "end cap for user_id {} at unique_pending_id {} has already been submitted",
                user_id,
                unique_pending_id
            );
        }

        Ok(())
    }

    pub async fn generate_batch_proof_miner_reward_proofs_internal(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> anyhow::Result<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        //let top_proof =
        // self.db_reader.
        // get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id).
        // await?;

        //let (unique_pending_id, proc_checkpoint_id) =
        // self.temp_db.get_unique_pending_ids(&self.realm_identifier).await?;
        let merkle_node_keys = job_ids
            .iter()
            .map(|job_id_with_path| SimpleMerkleNodeKey::from_reward_path_info(job_id_with_path.reward_path_info))
            .collect::<Vec<_>>();

        self.tag_tree_rewards_store
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &merkle_node_keys)
            .await?
            .into_iter()
            .zip(job_ids.iter())
            .map(|(proof, job_id_with_path)| {
                Ok(PsyProoffMinerRewardProof {
                    job_id: job_id_with_path.job_data_id.clone(),
                    tag_tree_proof: proof,
                })
            })
            .collect()
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
        ProofStore: QParthProofStore,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    pub async fn ensure_contract_heights_in_cache(&self, contract_ids: &[u32]) -> anyhow::Result<()> {
        // TODO: make this actually work in the db
        let mut contract_heights_to_fetch = Vec::new();
        for &contract_id in contract_ids {
            if !self.contract_state_tree_height_cache.mapping.contains_key(&contract_id) {
                contract_heights_to_fetch.push(contract_id as u64);
            }
        }
        if contract_heights_to_fetch.is_empty() {
            return Ok(());
        } else {
            let height = self
                .db_reader
                .get_contract_tree_heights(MAX_CHECKPOINT_ID, &contract_heights_to_fetch)
                .await?;

            height.iter().zip(contract_heights_to_fetch.iter()).for_each(|(&height, &contract_id)| {
                self.contract_state_tree_height_cache
                    .add_contract(contract_id as u32, height, N::HasherBase::get_zero_hash(height as usize));
            });
        }
        Ok(())
    }
    pub async fn handle_user_end_cap_proof_submission(
        &self,
        user_end_cap_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let mut timer = DebugTimer::new("handle_user_end_cap_proof_submission");
        let end_cap_checkpoint_id = user_end_cap_input.core.checkpoint_id.to_u64_value();

        let secondary_end_cap_checkpoint_id = user_end_cap_input.core.new_user_leaf.last_checkpoint_id.to_u64_value();
        if end_cap_checkpoint_id != secondary_end_cap_checkpoint_id {
            anyhow::bail!(
                "end cap checkpoint id {} does not match new_user_leaf last_checkpoint_id {}",
                end_cap_checkpoint_id,
                secondary_end_cap_checkpoint_id
            );
        }
        let user_id: u64 = user_end_cap_input.core.state_transition.user_id.to_u64_value();
        if !self.user_belongs_to_realm(user_id) {
            anyhow::bail!("user_id {} does not belong to this realm", user_id);
        }
        if user_end_cap_input.contract_state_updates.len() == 0 {
            anyhow::bail!("invalid contract_state_updates: cannot be empty");
        }

        let (unique_pending_id, proc_checkpoint_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;
        timer.lap_micros("get_gathering_unique_pending_ids");
        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted");

        let current_checkpoint_id = self.get_latest_checkpoint_id().await?;
        let global_user_tree_proof = self.db_reader.global_user_tree_get_merkle_proof(current_checkpoint_id, user_id)
.await?;

        timer.lap_micros("get_latest_checkpoint_id");
        let old_user_leaf = self.get_user_leaf_data_internal(current_checkpoint_id, user_id).await?;
        timer.lap_micros("get_user_leaf_data_internal");
        let user_last_checkpoint_id = old_user_leaf.last_checkpoint_id.to_u64_value();

        if user_last_checkpoint_id!= 0 && user_last_checkpoint_id > secondary_end_cap_checkpoint_id {
            anyhow::bail!(
                "Submitted end cap for checkpoint {}, but user's last checkpoint is {}",
                end_cap_checkpoint_id,
                user_last_checkpoint_id
            );
        }

        if end_cap_checkpoint_id > current_checkpoint_id {
            anyhow::bail!(
                "Submitted end cap for checkpoint {}, but current checkpoint is {}",
                end_cap_checkpoint_id,
                current_checkpoint_id
            );
        }

        let old_leaf_hash = if 
            global_user_tree_proof.value == N::QHash::get_zero_value()
        {
            N::QHash::get_zero_value()
        }else{
            old_user_leaf.qfhash::<N::HasherBase>()
        };
        
        if user_end_cap_input.core.state_transition.start_user_leaf_hash != old_leaf_hash {
            tracing::error!(
                "Invalid start_user_leaf_hash, left: {:?}, right: {:?}",
                user_end_cap_input.core.state_transition.start_user_leaf_hash,
                old_leaf_hash
            );
            anyhow::bail!(
                "Invalid start_user_leaf_hash, left: {:?}, right: {:?}",
                user_end_cap_input.core.state_transition.start_user_leaf_hash,
                old_leaf_hash
            );
        }

        let checkpoint_tree_proof: MerkleProofCore<N::QHash> = self
            .db_reader
            .checkpoint_tree_get_merkle_proof(u64::MAX-0xFFFF, end_cap_checkpoint_id)
            .await?;
        timer.lap_micros("checkpoint_tree_get_merkle_proof");

        let job_id =
            QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(user_id, N::GLOBAL_USER_TREE_HEIGHT, unique_pending_id)?;
        //println!("checkpoint_tree_proof: {:#?}", checkpoint_tree_proof);
        //println!("verify_checkpoint_tree_proof: {}", checkpoint_tree_proof.verify::<N::HasherBase>());
        let historical_root = checkpoint_tree_proof.get_append_root::<N::HasherBase>();
        //let (historical_root, current_root) = compute_historical_and_current_merkle_roots_core_gt::<N::QHash, N::HasherBase>(&checkpoint_tree_proof);
        if historical_root != user_end_cap_input.core.state_transition.checkpoint_tree_root_hash {
            anyhow::bail!(
                "Invalid checkpoint tree proof historical root, left: {:?}, right: {:?}",
                historical_root,
                user_end_cap_input.core.state_transition.checkpoint_tree_root_hash
            );
        }
        //tracing::info!("[{:?}] checkpoint_tree_proof ({} @ LATEST) (append_root: {:?}): {:?}", job_id, end_cap_checkpoint_id, checkpoint_tree_proof.get_append_root::<N::HasherBase>(), checkpoint_tree_proof);



        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted (2)");

        let expected_public_inputs_hash: N::QHash = user_end_cap_input
            .core
            .get_proof_public_inputs_hash::<N::HasherBase>(N::GLOBAL_USER_TREE_HEIGHT);
        let proof = N::ZKVerifier::try_proof_from_slice(&proof_bytes)?;

        let public_inputs = N::ZKVerifier::get_proof_public_inputs_hash(&proof)?;
        if public_inputs != expected_public_inputs_hash {
            anyhow::bail!(
                "Public inputs hash mismatch: expected {:?}, got {:?}",
                expected_public_inputs_hash,
                public_inputs
            );
        }
        let mut contract_ids = user_end_cap_input
            .contract_state_updates
            .iter()
            .map(|x| x.user_contract_tree_update_proof.index as u32)
            .collect::<Vec<u32>>();
        contract_ids.sort_unstable();
        contract_ids.dedup();
        self.ensure_contract_heights_in_cache(&contract_ids).await?;
        timer.lap_micros("ensure_contract_heights_in_cache");
        //println!("old_user_leaf: {:?}", old_user_leaf);

        user_end_cap_input.ensure_simple_self_consistent::<N::HasherBase, _>(
            &old_user_leaf,
            public_inputs,
            &self.contract_state_tree_height_cache,
            N::GLOBAL_USER_TREE_HEIGHT,
            N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE,
        )?;
        timer.lap_micros("ensure_simple_self_consistent");

        self.proof_verifier.verify_zk_proof(END_CAP_PROOF_CIRCUIT_TYPE_U32, &proof)?;
        timer.lap_micros("verify_zk_proof");

        // TODO: maybe modify the job_id.sub_group_id
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
        let contract_update_data_for_user =
            validate_end_cap_and_generate_node_data_for_edge::<N::F, N::QHash, N::HasherBase>(&context, user_id, &user_end_cap_input)?;
        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted (3)");
        self.temp_db
            .set_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id, rand_status)
            .await?;
        timer.lap_micros("set_submitted_status_for_pending");

        if self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id)
            .await?
            != rand_status
        {
            // check for race condition
            anyhow::bail!(
                "end cap for user_id {} at unique_pending_id {} has already been submitted (race)",
                user_id,
                unique_pending_id
            );
        }

        timer.lap_micros("get_submitted_status_for_pending (final)");
        self.proof_store.put_proof_bytes_for_job_id(job_id, &proof_bytes).await?;
        timer.lap_micros("put_proof_bytes_for_job_id");
        if self
            .temp_db
            .get_submitted_status_for_pending(&self.realm_identifier, unique_pending_id, user_id)
            .await?
            != rand_status
        {
            // check for race condition
            anyhow::bail!(
                "end cap for user_id {} at unique_pending_id {} has already been submitted (race)",
                user_id,
                unique_pending_id
            );
        }
        timer.lap_micros("get_submitted_status_for_pending (final 2)");

        self.temp_db
            .set_contract_updates_for_user(&self.realm_identifier, unique_pending_id, user_id, contract_update_data_for_user)
            .await?;
        timer.lap_micros("set_contract_updates_for_user");
        let queue_key = RealmUserUpdateQueueKey {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: proc_checkpoint_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let new_user_leaf = user_end_cap_input.core.new_user_leaf.clone();
        let new_user_leaf_hash = new_user_leaf.qfhash::<N::HasherBase>();

        let queue_item = PsyRealmUserUpdateQueueItem {
            job_id,
            expected_fake_checkpoint_id: fake_checkpoint_id,
            old_user_leaf_hash: old_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats: user_end_cap_input.core.stats,
        };
        //println!("Publishing to user update queue: {:?}", queue_item);
        self.user_update_queue
            .publish_ephemeral_queue_item_owned(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, proc_checkpoint_id, 0, queue_item)
            .await?;
        timer.lap_micros("publish_ephemeral_queue_item_owned");
        timer.lap_group("handle_user_end_cap_proof_submission total");

        Ok(())
    }
}
type QRpcResult<T> = RpcResult<T>;

fn res<T>(data: anyhow::Result<T>) -> QRpcResult<T> {
    Ok(data.map_err(RpcError::Anyhow)?)
}

const MAX_CHECKPOINT_ID: u64 = i64::MAX as u64;

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > RealmEdgeRpcServer<N::F, N::QHash, N::JobId, N::ZKProof>
    for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    /// Check if a user id belongs to this realm

    async fn get_latest_checkpoint_id(&self) -> RpcResult<u64> {
        res(self.get_latest_checkpoint_id().await)
    }
    
    async fn get_contract_tree_state_heights(&self, checkpoint_id: u64, contract_ids: Vec<u64>) -> RpcResult<Vec<u8>>{
        let result = self
            .db_reader
            .get_contract_tree_heights(checkpoint_id, &contract_ids)
            .await;
        if result.is_err() {
            tracing::error!("Error getting contract tree state heights");

        } else {
            //println!("Got contract tree state heights for checkpoint_id {}: {:?}", checkpoint_id, result.as_ref().unwrap());
            //tracing::info!("Got contract tree state heights for checkpoint_id {}", checkpoint_id);
        }
        res(result)

    }
    async fn check_user_id_in_realm(&self, user_id: u64) -> QRpcResult<bool> {
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;
        let min_user_id = self.realm_id_u64 * users_per_realm;
        let max_user_id = min_user_id + users_per_realm;
        Ok(user_id >= min_user_id && user_id < max_user_id)
    }

    /// Submit user end cap proof

    async fn get_user_contract_state_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreDoubleIdKeyWithHeight>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .contract_state_tree_get_nodes(checkpoint_id, &keys)
            .await  )
    }

    async fn get_user_contract_tree_nodes(
        &self,
        checkpoint_id: u64,
        keys: Vec<QMerkleStoreSingleIdKey>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .user_contract_tree_get_nodes(checkpoint_id, &keys)
            .await
        )

    }

    async fn submit_user_end_cap(&self, user_ec_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>, proof: Vec<u8>) -> QRpcResult<String> {
        res(self.handle_user_end_cap_proof_submission(user_ec_input, proof).await)?;
        Ok("ok".to_string())
    }

    async fn submit_user_end_cap_batch(&self, requests: Vec<(SubmitUserEndCapNonProofInput<N::F, N::QHash>, Vec<u8>)>) -> QRpcResult<(Vec<u64>,Vec<u64>)> {
        let mut failed_user_ids = vec![];
        let mut success_user_ids = vec![];
        for (user_ec_input, proof) in requests {
            let user_id: u64 = user_ec_input.core.state_transition.user_id.to_u64_value();
            if let Err(err) = self.handle_user_end_cap_proof_submission(user_ec_input, proof).await {
                failed_user_ids.push(user_id);
                tracing::warn!("Failed to handle user end cap proof submission for user_id {}: {}", user_id, err);
            }else {
                success_user_ids.push(user_id);
            }
        }
        Ok((success_user_ids,failed_user_ids))
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointLeaf<N::F, N::QHash>> {
        res(self.db_reader.get_checkpoint_leaf_data(checkpoint_id).await)
    }

    async fn get_latest_l2_block_state(&self) -> QRpcResult<QEDL2BlockState> {
        res(self.db_reader.get_latest_l2_block_state().await)
    }

    async fn get_l2_block_state(&self, checkpoint_id: u64) -> QRpcResult<QEDL2BlockState> {
        res(self.db_reader.get_l2_block_state(checkpoint_id).await)
    }

    async fn get_latest_checkpoint_tree_root(&self) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_root_hash(MAX_CHECKPOINT_ID).await)
    }

    async fn get_checkpoint_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_checkpoint_tree_leaf_hash(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.checkpoint_tree_get_leaf_hash(checkpoint_id, leaf_checkpoint_id).await)
    }

    async fn get_checkpoint_tree_merkle_proof(&self, checkpoint_id: u64, leaf_checkpoint_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self.db_reader.checkpoint_tree_get_merkle_proof(checkpoint_id, leaf_checkpoint_id).await)
    }

    async fn get_checkpoint_global_state_roots(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointGlobalStateRoots<N::QHash>> {
        res(self.db_reader.get_checkpoint_global_state_roots(checkpoint_id).await)
    }

    async fn get_user_leaf_data(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<PQEDUserLeaf<N::F, N::QHash>> {
        res(self.get_user_leaf_data_internal(checkpoint_id, user_id).await)
    }
    async fn get_user_leaves_batch(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<PQEDUserLeaf<N::F, N::QHash>>>{
        res(self.get_user_leaves_data_internal(checkpoint_id, &user_ids).await)
    }
    async fn get_user_tree_leaf_hashes(
        &self,
        checkpoint_id: u64,
        user_ids: Vec<u64>,
    ) -> RpcResult<Vec<N::QHash>>{
        res(self
            .db_reader
            .global_user_tree_get_nodes(checkpoint_id, &user_ids.into_iter().map(|id| SimpleMerkleNodeKey::new(N::GLOBAL_USER_TREE_HEIGHT, id)).collect::<Vec<_>>())
            .await)
    }
    async fn get_user_contract_state_tree_root(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .contract_state_tree_get_root_hash(checkpoint_id, user_id, contract_id as u64)
            .await)
    }

    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        _height: u8, // height is not used in the db call
        leaf_id: u64,
    ) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .contract_state_tree_get_leaf_hash(checkpoint_id, user_id, contract_id as u64, leaf_id)
            .await)
    }

    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        height: u8, // height is not used in the db call
        leaf_id: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, leaf_id)
            .await)
    }

    async fn get_user_contract_tree_root(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.user_contract_tree_get_root_hash(checkpoint_id, user_id).await)
    }

    async fn get_user_contract_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<N::QHash> {
        res(self
            .db_reader
            .user_contract_tree_get_leaf_hash(checkpoint_id, user_id, contract_id as u64)
            .await)
    }

    async fn get_user_contract_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64, contract_id: u32) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .user_contract_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64)
            .await)
    }

    async fn get_user_tree_root(&self, checkpoint_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_user_tree_get_root_hash(checkpoint_id).await)
    }

    async fn get_user_tree_leaf_hash(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<N::QHash> {
        res(self.db_reader.global_user_tree_get_leaf_hash(checkpoint_id, user_id).await)
    }

    async fn get_user_bottom_tree_merkle_proof(&self, root_level: u8, checkpoint_id: u64, user_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, root_level, N::GLOBAL_USER_TREE_HEIGHT, user_id)
            .await)
    }

    async fn get_user_sub_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        root_level: u8,
        leaf_level: u8,
        leaf_index: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self
            .db_reader
            .global_user_tree_get_merkle_proof_sub_tree(checkpoint_id, root_level, leaf_level, leaf_index)
            .await)
    }

    async fn get_user_tree_merkle_proof(&self, checkpoint_id: u64, user_id: u64) -> QRpcResult<MerkleProofCore<N::QHash>> {
        res(self.db_reader.global_user_tree_get_merkle_proof(checkpoint_id, user_id).await)
    }

    async fn generate_batch_proof_miner_reward_proofs(
        &self,
        unique_pending_id: u64,
        job_ids: Vec<QProvingJobDataIDWithRewardPath<N::JobId>>,
    ) -> QRpcResult<Vec<PsyProoffMinerRewardProof<N::QHash, N::JobId>>> {
        res(self.generate_batch_proof_miner_reward_proofs_internal(unique_pending_id, job_ids).await)
    }
}

#[async_trait]
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
        UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
        ProofStore: QParthProofStore + Send + Sync + 'static,
    > NodeEdgeWorkerRpcServer<N::QHash, N::JobId>
    for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    async fn get_proving_work(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> RpcResult<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        res(self.get_proving_work_internal(signature, request).await)
    }
    async fn get_proving_work_with_child_proofs(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> RpcResult<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        res(self.get_proving_work_with_child_proofs_internal(signature, request).await)
    }
    async fn submit_proof_raw(&self, job_id: N::JobId, tag: N::QHash, proof: Vec<u8>) -> RpcResult<()> {
        res(self.submit_proof_raw_internal(job_id, tag, proof).await)
    }
    async fn get_realm_identifier_worker_api(&self) -> RpcResult<QRealmIdentifier> {
        Ok(self.realm_identifier.clone())
    }

    async fn get_node_proving_state(&self) -> RpcResult<PsyNodeProvingState>{
        res(self.temp_db.get_psy_node_proving_state(&self.realm_identifier).await)
    }
}
