use std::{sync::Arc, u64};
use tokio::task;
use futures::stream::{self, StreamExt};

use async_trait::async_trait;
use cf_utils::timer::DebugTimer;
use jsonrpsee::core::RpcResult;
use parth_core::{
    QProvingJobDataIDWithRewardPath, crypto::{
        hash::{
            merkle_proof::MerkleProofCore,
            tag_tree::TagTreeMerkleProof,
            traits::{MerkleZeroHasher, QFieldHashable, ZeroableHash},
        },
        secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest},
    }, data::{hash::{merkle_node_key::SimpleMerkleNodeKey, merkle_store_key::{QMerkleStoreDoubleIdKeyWithHeight, QMerkleStoreSingleIdKey}}, queue::queue_key::QPBaseQueueType}, felt::ToU64Value, node::realm_identifier::QRealmIdentifier, protocol::core_types::{QNetworkTypesConfig, QZKProofPublicInputsHasherReader, QZKProofVerifier}
};
use psy_api_core::{
    realm::standard_edge_rpc::{
        RealmContractSlotUpdates, RealmEdgeRpcServer, RealmEndCapSlotUpdates, RealmSlotUpdate,
    },
    worker::standard_worker_rpc::NodeEdgeWorkerRpcServer,
    CheckpointJobStats,
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    node::node_proving_state::PsyNodeProvingState, proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, queue_items::realm_user_update::PsyRealmUserUpdateQueueItem, v1::{
        common_api::PsyProoffMinerRewardProof,
        qdata::{
            checkpoint::{PQEDCheckpointGlobalStateRoots, PQEDCheckpointLeaf, QEDL2BlockState},
            contract::{DashMapContractHeightCache, IMTContractStateLeaf, IMTMembershipProof,
                IMTNonMembershipProof, IMTPredecessorResult, PSimpleContractHeightCache},
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
    pub async fn get_job_stats_internal(&self, checkpoint_id: u64) -> anyhow::Result<CheckpointJobStats> {
        let (unique_pending_id, _) = self
            .db_reader
            .get_unique_pending_id_for_checkpoint_id(checkpoint_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("no unique pending id found for checkpoint id {}", checkpoint_id))?;
        let stats = self
            .temp_db
            .get_job_stats(&self.realm_identifier, unique_pending_id)
            .await?
            .unwrap_or_default();

        Ok(CheckpointJobStats {
            unique_pending_id,
            total_completed: stats.total_completed,
            total_duration_ms: stats.total_duration_ms,
            min_duration_ms: stats.min_duration_ms,
            max_duration_ms: stats.max_duration_ms,
        })
    }
    pub async fn get_checkpoint_id_for_unique_pending_id_internal(&self, unique_pending_id: u64) -> anyhow::Result<Option<u64>> {
        self.db_reader.get_checkpoint_id_for_unique_pending_id(unique_pending_id).await
    }

    pub async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id_internal(&self, checkpoint_id: u64) -> anyhow::Result<TagTreeMerkleProof<N::QHash>> {
        self.db_reader.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(checkpoint_id).await
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
        let merkle_node_keys = job_ids
            .iter()
            .map(|job_id_with_path| SimpleMerkleNodeKey::from_reward_path_info(job_id_with_path.reward_path_info))
            .collect::<Vec<_>>();

        let mut tag_proofs = self.tag_tree_rewards_store
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(unique_pending_id, &merkle_node_keys).await?;

        // Merge the realm-local reward proof with the coordinator-level proof so
        // the final root matches the checkpoint's global rewards root. The realm
        // processor persists this top proof keyed by unique_pending_id.
        let top_proof = self
            .db_reader
            .get_top_global_user_rewards_tree_proof_to_realm_at_unique_pending_id(unique_pending_id)
            .await?;
        for proof in &mut tag_proofs {
            let local_proof_height = proof.siblings.len();
            proof.siblings.extend(top_proof.siblings.clone());
            proof.root = top_proof.root;
            proof.index |= top_proof.index << local_proof_height;
        }

        // Wrap into PsyProoffMinerRewardProof
        let miner_proofs = job_ids.into_iter().zip(tag_proofs.into_iter()).map(|(job_id_with_path, tag_proof)| {
            PsyProoffMinerRewardProof {
                job_id: job_id_with_path.job_data_id,
                tag_tree_proof: tag_proof,
            }
        }).collect::<Vec<_>>();

        Ok(miner_proofs)
    }
}

impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        UserUpdateQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
        ProofStore: QParthProofStore,
    > RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    pub async fn ensure_contract_heights_in_cache(&self, contract_ids: &[u32]) -> anyhow::Result<()> {
        // TODO: make this actually work in the db
        let mut contract_heights_to_fetch = Vec::new();
        for &contract_id in contract_ids {
            let cached_height = self
                .contract_state_tree_height_cache
                .mapping
                .get(&contract_id)
                .map(|entry| entry.value().0);
            if cached_height.is_none() || cached_height == Some(0) {
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

            for (&height, &contract_id) in height.iter().zip(contract_heights_to_fetch.iter()) {
                anyhow::ensure!(
                    height > 0,
                    "contract {} state tree height metadata is not available in Realm DB yet",
                    contract_id
                );
                self.contract_state_tree_height_cache
                    .add_contract(contract_id as u32, height, N::HasherBase::get_zero_hash(height as usize));
            }
        }
        Ok(())
    }

    pub async fn contract_state_tree_height(&self, contract_id: u32) -> anyhow::Result<u8> {
        self.ensure_contract_heights_in_cache(&[contract_id]).await?;
        self.contract_state_tree_height_cache.get_contract_height(contract_id)
    }

    fn build_user_end_cap_slot_updates(
        &self,
        unique_pending_id: u64,
        user_id: u64,
        user_end_cap_input: &SubmitUserEndCapNonProofInput<N::F, N::QHash>,
    ) -> anyhow::Result<RealmEndCapSlotUpdates> {
        let contracts = user_end_cap_input
            .get_slot_updates()?
            .into_iter()
            .map(|contract| RealmContractSlotUpdates {
                contract_id: contract.contract_id,
                slot_updates: contract
                    .slot_updates
                    .into_iter()
                    .map(|slot_update| RealmSlotUpdate {
                        slot: slot_update.slot,
                        old_value: slot_update.old_value.to_u64_value(),
                        new_value: slot_update.new_value.to_u64_value(),
                    })
                    .collect(),
            })
            .filter(|contract| !contract.slot_updates.is_empty())
            .collect();

        Ok(RealmEndCapSlotUpdates {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            user_id,
            contracts,
        })
    }

    pub async fn get_user_end_cap_slot_updates_internal(
        &self,
        unique_pending_id: u64,
        user_id: u64,
    ) -> anyhow::Result<Option<RealmEndCapSlotUpdates>> {
        let Some(bytes) = self
            .temp_db
            .get_user_end_cap_slot_updates(&self.realm_identifier, unique_pending_id, user_id)
            .await?
        else {
            return Ok(None);
        };

        let payload = bincode::deserialize(&bytes)?;
        Ok(Some(payload))
    }

    pub async fn handle_user_end_cap_proof_submission(
        &self,
        user_end_cap_input: SubmitUserEndCapNonProofInput<N::F, N::QHash>,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
        N::ZKProof: 'static,
    {
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
        if user_end_cap_input.contract_state_updates.is_empty() {
            anyhow::bail!("invalid end cap updates: contract_state_updates cannot be empty");
        }

        let (unique_pending_id, proc_checkpoint_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;
        println!("unique_pending_id: {}, proc_checkpoint_id: {}", unique_pending_id, proc_checkpoint_id);
        timer.lap_micros("get_gathering_unique_pending_ids");
        self.ensure_user_has_not_submitted(user_id, unique_pending_id).await?;
        timer.lap_micros("ensure_user_has_not_submitted");

        let current_checkpoint_id = self.get_latest_checkpoint_id().await?;
        let global_user_tree_proof = self.db_reader.global_user_tree_get_merkle_proof(current_checkpoint_id, user_id).await?;

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

        let proof_verifier = self.proof_verifier.clone();
        task::spawn_blocking(move || {
            proof_verifier.verify_zk_proof(END_CAP_PROOF_CIRCUIT_TYPE_U32, &proof)
        }).await??;
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
        self.proof_store
            .put_proof_bytes_for_job_id(job_id, unique_pending_id, &proof_bytes)
            .await?;
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

        let slot_updates_payload = match self.build_user_end_cap_slot_updates(
            unique_pending_id,
            user_id,
            &user_end_cap_input,
        ) {
            Ok(payload) => Some(payload),
            Err(err) => {
                tracing::warn!(
                    user_id,
                    unique_pending_id,
                    error = ?err,
                    "Failed to extract user end-cap slot updates"
                );
                None
            }
        };

        self.temp_db
            .set_contract_updates_for_user(&self.realm_identifier, unique_pending_id, user_id, contract_update_data_for_user)
            .await?;
        timer.lap_micros("set_contract_updates_for_user");

        if let Some(slot_updates_payload) = slot_updates_payload {
            if !slot_updates_payload.contracts.is_empty() {
                match bincode::serialize(&slot_updates_payload) {
                    Ok(bytes) => {
                        if let Err(err) = self
                            .temp_db
                            .set_user_end_cap_slot_updates(
                                &self.realm_identifier,
                                unique_pending_id,
                                user_id,
                                bytes,
                            )
                            .await
                        {
                            tracing::warn!(
                                user_id,
                                unique_pending_id,
                                error = ?err,
                                "Failed to store user end-cap slot updates"
                            );
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            user_id,
                            unique_pending_id,
                            error = ?err,
                            "Failed to serialize user end-cap slot updates"
                        );
                    }
                }
            }
        }
        timer.lap_micros("set_user_end_cap_slot_updates");

        // Re-read gathering proc ID right before publish to avoid a race with
        // process_block.set_new_unique_ids, which may have advanced the ID
        // during the async proof verification / storage calls above. Publishing
        // to a stale (already-drained) queue silently drops the endcap.
        let (_, live_proc_id) = self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await?;

        let queue_key = RealmUserUpdateQueueKey {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: live_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::StandardEphemeral,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let new_user_leaf = user_end_cap_input.core.new_user_leaf.clone();
        let new_user_leaf_hash = new_user_leaf.qfhash::<N::HasherBase>();
        // Keep original job_id (proof stored under it). Only refresh queue key.

        let queue_item = PsyRealmUserUpdateQueueItem {
            job_id: job_id,
            expected_fake_checkpoint_id: fake_checkpoint_id,
            old_user_leaf_hash: old_leaf_hash,
            new_user_leaf_hash,
            new_user_leaf,
            stats: user_end_cap_input.core.stats,
            events: user_end_cap_input.events,
        };

        // Ensure the consumer for live_proc_id exists BEFORE publishing. If
        // the processor has already drained and deleted the consumer for this
        // generation, publishing to an ephemeral queue with no consumer silently
        // drops the message. By ensuring the consumer here, we guarantee the
        // message will be buffered and picked up by the gatherer on its next
        // drain cycle — even if the processor has already rotated past this ID.
        // The consumer we create is idempotent: if it already exists this is a
        // no-op; if it was deleted, it is recreated with DeliverPolicy::All so
        // all pending messages are replayed.
        if let Err(e) = self.user_update_queue.ensure_consumer(
            &queue_key,
            self.realm_id_u64,
            self.realm_sub_id_u64,
            live_proc_id,
            0,
        ).await {
            tracing::warn!(
                "Failed to ensure consumer for live_proc_id {} before publish (continuing): {}",
                live_proc_id, e
            );
        }

        self.user_update_queue
            .publish_ephemeral_queue_item_owned(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, live_proc_id, 0, queue_item)
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
    async fn get_checkpoint_id_for_unique_pending_id(&self, unique_pending_id: u64) -> RpcResult<Option<u64>> {
        res(self.get_checkpoint_id_for_unique_pending_id_internal(unique_pending_id).await)
    }
    async fn get_unique_pending_id_for_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<Option<(u64, u128)>> {
        res(self.db_reader.get_unique_pending_id_for_checkpoint_id(checkpoint_id).await)
    }
    async fn get_user_end_cap_slot_updates(
        &self,
        unique_pending_id: u64,
        user_id: u64,
    ) -> RpcResult<Option<RealmEndCapSlotUpdates>> {
        res(self
            .get_user_end_cap_slot_updates_internal(unique_pending_id, user_id)
            .await)
    }
    async fn get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(&self, checkpoint_id: u64) -> RpcResult<TagTreeMerkleProof<N::QHash>> {
        res(self.get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id_internal(checkpoint_id).await)
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

    async fn submit_user_end_cap_batch(
        &self,
        requests: Vec<(SubmitUserEndCapNonProofInput<N::F, N::QHash>, Vec<u8>)>,
    ) -> QRpcResult<(Vec<u64>, Vec<u64>)> {
        let results: Vec<(u64, bool)> = stream::iter(requests.into_iter().map(|(user_ec_input, proof)| async move {
            let user_id: u64 = user_ec_input.core.state_transition.user_id.to_u64_value();
            match self.handle_user_end_cap_proof_submission(user_ec_input, proof).await {
                Ok(_) => (user_id, true),
                Err(err) => {
                    tracing::warn!("Failed to handle user end cap proof submission for user_id {}: {}", user_id, err);
                    (user_id, false)
                }
            }
        }))
        .buffered(16)
        .collect()
        .await;

        let mut failed_user_ids = vec![];
        let mut success_user_ids = vec![];
        for (user_id, success) in results {
            if success {
                success_user_ids.push(user_id);
            } else {
                failed_user_ids.push(user_id);
            }
        }
        Ok((success_user_ids, failed_user_ids))
    }

    async fn get_checkpoint_leaf_data(&self, checkpoint_id: u64) -> QRpcResult<PQEDCheckpointLeaf<N::F, N::QHash>> {
        res(self.db_reader.get_checkpoint_leaf_data(checkpoint_id).await)
    }

    async fn get_job_stats(&self, checkpoint_id: u64) -> QRpcResult<CheckpointJobStats> {
        res(self.get_job_stats_internal(checkpoint_id).await)
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
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        res(self
            .db_reader
            .contract_state_tree_get_root_hash(checkpoint_id, user_id, contract_id as u64, height)
            .await)
    }

    async fn get_user_contract_state_tree_leaf_hash(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_id: u64,
    ) -> QRpcResult<N::QHash> {
        let height = res(self.contract_state_tree_height(contract_id).await)?;
        res(self
            .db_reader
            .contract_state_tree_get_leaf_hash(checkpoint_id, user_id, contract_id as u64, height, leaf_id)
            .await)
    }

    async fn get_user_contract_state_tree_merkle_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_id: u64,
    ) -> QRpcResult<MerkleProofCore<N::QHash>> {
        let height = res(self.contract_state_tree_height(contract_id).await)?;
        tracing::warn!(
            checkpoint_id,
            user_id,
            contract_id,
            height,
            leaf_id,
            "[CONTRACT_HEIGHT_DEBUG] serving user contract state proof"
        );
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

    // IMT endpoints

    async fn get_imt_leaf_preimage(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        leaf_index: u64,
    ) -> QRpcResult<IMTContractStateLeaf<N::F, N::QHash>> {
        res(res(self
            .db_reader
            .contract_state_imt_get_leaf_preimage(checkpoint_id, user_id, contract_id as u64, leaf_index)
            .await.transpose().ok_or(anyhow::format_err!("Leaf preimage not found at index {}", leaf_index)))?)
    }

    async fn get_imt_leaf_index_for_key(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<u64> {
        res(res(self
            .db_reader
            .contract_state_imt_get_leaf_index_for_key(checkpoint_id, user_id, contract_id as u64, &key)
            .await.transpose().ok_or(anyhow::format_err!("Key not found in IMT")))?)
    }

    async fn get_imt_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<IMTMembershipProof<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        // Get the leaf index for the key
        let leaf_index = self
            .db_reader
            .contract_state_imt_get_leaf_index_for_key(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?
            .ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("Key not found in IMT")))?;

        // Get the leaf preimage
        let leaf = self
            .db_reader
            .contract_state_imt_get_leaf_preimage(checkpoint_id, user_id, contract_id as u64, leaf_index)
            .await
            .map_err(RpcError::Anyhow)?
            .ok_or_else(|| RpcError::Anyhow(anyhow::anyhow!("Leaf preimage not found at index {}", leaf_index)))?;

        // Get the merkle proof for the leaf's position in the tree
        let merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, leaf_index)
            .await
            .map_err(RpcError::Anyhow)?;

        Ok(IMTMembershipProof {
            leaf,
            merkle_proof,
        })
    }

    async fn get_imt_non_membership_proof(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<IMTNonMembershipProof<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        // Find the predecessor leaf
        let (predecessor_index, predecessor_leaf) = self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get the merkle proof for the predecessor's position
        let merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, predecessor_index)
            .await
            .map_err(RpcError::Anyhow)?;

        Ok(IMTNonMembershipProof {
            predecessor_leaf,
            merkle_proof,
        })
    }

    async fn get_imt_predecessor_info(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u32,
        key: N::QHash,
    ) -> QRpcResult<IMTPredecessorResult<N::F, N::QHash>> {
        let height = self.contract_state_tree_height(contract_id).await.map_err(RpcError::Anyhow)?;
        // Find predecessor leaf
        let (predecessor_index, predecessor_leaf) = self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get merkle proof for predecessor
        let predecessor_merkle_proof = self
            .db_reader
            .contract_state_tree_get_merkle_proof(checkpoint_id, user_id, contract_id as u64, height, predecessor_index)
            .await
            .map_err(RpcError::Anyhow)?;

        // Get next append index
        let next_append_index = self
            .db_reader
            .contract_state_imt_get_next_append_index(user_id, contract_id as u64)
            .await
            .map_err(RpcError::Anyhow)?;

        Ok(IMTPredecessorResult {
            predecessor_leaf_index: predecessor_index,
            predecessor_leaf,
            predecessor_merkle_proof,
            next_append_index,
        })
    }

    async fn find_imt_predecessor(
        &self,
        checkpoint_id: u64,
        user_id: u64,
        contract_id: u64,
        key: N::QHash,
    ) -> QRpcResult<(u64, IMTContractStateLeaf<N::F, N::QHash>)> {
        res(self
            .db_reader
            .contract_state_imt_find_predecessor(checkpoint_id, user_id, contract_id as u64, &key)
            .await)
    }

    async fn get_imt_next_append_index(&self, user_id: u64, contract_id: u64) -> QRpcResult<u64> {
        res(self
            .db_reader
            .contract_state_imt_get_next_append_index(user_id, contract_id as u64)
            .await)
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
    async fn submit_proof_raw(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
        job_id: N::JobId,
        tag: N::QHash,
        proof: Vec<u8>,
    ) -> RpcResult<()> {
        res(self.submit_proof_raw_internal(signature, request, job_id, tag, proof).await)
    }
    async fn get_realm_identifier_worker_api(&self) -> RpcResult<QRealmIdentifier> {
        Ok(self.realm_identifier.clone())
    }

    async fn get_node_proving_state(&self) -> RpcResult<PsyNodeProvingState>{
        res(self.temp_db.get_psy_node_proving_state(&self.realm_identifier).await)
    }

    async fn get_worker_reputation(&self, public_key: Vec<u8>) -> RpcResult<u64> {
        let key: [u8; 33] = public_key
            .try_into()
            .map_err(|_| RpcError::InvalidInput("public_key must be 33 bytes (compressed secp256k1)".to_string()))?;
        res(self.get_worker_reputation_internal(&key).await)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::test_common::{
        create_test_unified_db, FakeEphemeralQueuePublisher, FakeWorkerQueueSubscriber, TestNetworkConfig,
        TestUnifiedDatabaseStore, TestZKVerifier,
    };
    use parth_common::memory_stores::mem_tree_v3::SimpleMemoryMerkleStoreV3;
    use parth_core::{
        crypto::hash::tag_tree::{TagTreeMerkleProof, TagTreeNodePreimage, TagTreeProofNode},
        data::queue::queue_key::PCoreQueueItemBase,
        felt::{FromPrimitiveValuesFelt, ZeroableFelt},
        pgoldilocks::PoseidonHasher,
        protocol::core_types::{
            Q256BitHash, QNetworkHashTypes, QNetworkTreeCircuitSpecificConstants, QNetworkTreeConstants,
            QNetworkZKTypes,
        },
        utils::QPGenRandom,
        PF, PHash,
    };
    use psy_data::{
        guta::stats::GUTAStats,
        proof_input::guta::{
            end_cap_input::{ContractStateUpdate, ContractStateUpdateHistory},
            SubmitUserEndCapNonProofCoreInput,
        },
        queue_items::realm_user_update::PsyRealmUserUpdateQueueItem,
        v1::qdata::user_end_cap_result::PUPSEndCapResultCompact,
    };
    use psy_node_core::{
        psy_core_db::traits::full::{
            PsyNodeCheckpointObjectDatabaseWriter, PsyNodeCheckpointTreeDatabaseReader,
            PsyNodeCoreDatabaseBasicContractInfoStoreWriter, PsyNodeCoreDatabaseUserStoreWriter,
        },
        psy_temp_db::{
            QTempDBJobStatsStore, QTempDBPendingIdWriter, QTempDBSubmitStatusWriter,
            QTempDBUserEndCapSlotUpdatesWriter,
        },
        store::traits::proof_store::QParthProofStoreReader,
    };
    use psy_node_store_memory::temp_store::InMemoryTempStore;

    pub(crate) type N = TestNetworkConfig;

    pub(crate) const TEST_CHAIN_ID: u32 = 9;
    pub(crate) const TEST_NODE_ID: u32 = 4;
    pub(crate) const TEST_REALM_ID: u64 = 1;
    pub(crate) const TEST_REALM_SUB_ID: u64 = 2;
    /// A user id that lives inside realm 1 (user ids are partitioned by
    /// `realm_id * (1 << REALM_GLOBAL_USER_TREE_HEIGHT)`).
    pub(crate) const REALM_USER_ID: u64 = (1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT) + 42;
    /// A user id that lives inside the next realm (realm 2).
    const OTHER_REALM_USER_ID: u64 = (2u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT) + 42;
    const CONTRACT_COUNT: usize = 5;
    /// All contract state trees and the user contract tree live at the global
    /// contract tree height, so an untouched UCT leaf (zero hash at that height)
    /// equals the empty-root of a fresh contract state tree.
    const CONTRACT_TREE_HEIGHT: u8 = N::GLOBAL_CONTRACT_TREE_HEIGHT;

    pub(crate) fn zh(level: usize) -> PHash {
        PoseidonHasher::get_zero_hash(level)
    }

    pub(crate) fn test_realm_identifier() -> QRealmIdentifier {
        QRealmIdentifier::new(TEST_REALM_ID as u32, TEST_REALM_SUB_ID as u16)
    }

    /// A ZK "verifier" whose proof type is the public-inputs hash itself: proofs
    /// are the 32-byte hash, and reading the public inputs echoes the proof back.
    /// This lets the end-cap submission happy path carry a genuinely matching
    /// public-inputs hash without any real proving, while staying fully
    /// deterministic and parallel-safe (no shared mutable state).
    pub(crate) struct EndCapEchoVerifier {}

    impl QZKProofPublicInputsHasherReader<PHash, PHash> for EndCapEchoVerifier {
        fn get_proof_public_inputs_hash(proof: &PHash) -> anyhow::Result<PHash> {
            Ok(*proof)
        }
        fn try_proof_from_slice(bytes: &[u8]) -> anyhow::Result<PHash> {
            Ok(PHash::from_ref_32bytes(&bytes.try_into()?))
        }
    }

    impl QZKProofVerifier<PHash, PHash> for EndCapEchoVerifier {
        fn verify_zk_proof(&self, _circuit_type: u32, _proof: &PHash) -> anyhow::Result<PHash> {
            Ok(PoseidonHasher::get_zero_hash(1))
        }
        fn verify_zk_proof_from_slice_check_public_inputs_hash(
            &self,
            _circuit_type: u32,
            _proof_bytes: &[u8],
            _expected_public_inputs_hash: PHash,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    /// Network config identical to TestNetworkConfig except the ZK verifier is
    /// the echo verifier above; used for the end-cap submission paths that check
    /// the public-inputs hash of the submitted proof.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct EndCapTestNetworkConfig {}

    impl QNetworkTreeCircuitSpecificConstants for EndCapTestNetworkConfig {
        const GUTA_CIRCUIT_WHITELIST_TREE_HEIGHT: u8 = 4;
        const MAX_USERS_TO_REGISTER_PER_PROOF: usize = 32;
        const ONLY_REGISTER_USERS_MAX_USERS_PER_PROOF: usize = 64;
        const BATCH_USER_REGISTRATION_SUB_TREE_HEIGHT: usize = 8;
        const BATCH_USER_REGISTRATION_MAX_SUB_TREES: usize = 4;
        const BATCH_DEPLOY_CONTRACT_SUB_TREE_HEIGHT: usize = 8;

        const DEFAULT_USER_STATE_TREE_ROOT_HASH_U64_X4: [u64; 4] =
            [3896366420105793420, 17410332186442776169, 7329967984378645716, 6310665049578686403];

        const END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4: [u64; 4] =
            [1412692327731855940, 17963365021580141687, 10532510199226356508, 3943799806037696098];
    }

    impl QNetworkTreeConstants for EndCapTestNetworkConfig {
        const CHECKPOINT_TREE_HEIGHT_USIZE: usize = 32;
        const CHECKPOINT_TREE_HEIGHT: u8 = Self::CHECKPOINT_TREE_HEIGHT_USIZE as u8;

        const GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 32;
        const GLOBAL_USER_TREE_HEIGHT: u8 = Self::GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const GLOBAL_CONTRACT_TREE_HEIGHT_USIZE: usize = 24;
        const GLOBAL_CONTRACT_TREE_HEIGHT: u8 = Self::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE as u8;

        const CONTRACT_FUNCTION_TREE_HEIGHT_USIZE: usize = 16;
        const CONTRACT_FUNCTION_TREE_HEIGHT: u8 = Self::CONTRACT_FUNCTION_TREE_HEIGHT_USIZE as u8;

        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 12;
        const COORDINATOR_GLOBAL_USER_TREE_HEIGHT: u8 = Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const REALM_GLOBAL_USER_TREE_HEIGHT_USIZE: usize = 20;
        const REALM_GLOBAL_USER_TREE_HEIGHT: u8 = Self::REALM_GLOBAL_USER_TREE_HEIGHT_USIZE as u8;

        const MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE: usize = 32;
        const MAX_CONTRACT_STATE_TREE_HEIGHT: u8 = Self::MAX_CONTRACT_STATE_TREE_HEIGHT_USIZE as u8;

        const GROUP_REALM_HEIGHT: u8 = 1;

        const MAX_USERS: u64 = 1 << Self::GLOBAL_USER_TREE_HEIGHT;

        const MAX_REALMS: u32 = 1 << Self::COORDINATOR_GLOBAL_USER_TREE_HEIGHT;

        const MAX_USERS_PER_REALM: u32 = 1 << Self::REALM_GLOBAL_USER_TREE_HEIGHT;
    }

    impl QNetworkHashTypes for EndCapTestNetworkConfig {
        type QHash = PHash;
        type HasherBase = PoseidonHasher;
        type F = PF;
    }

    impl QNetworkZKTypes for EndCapTestNetworkConfig {
        type ZKProof = PHash;
        type ZKVerifier = EndCapEchoVerifier;
    }

    impl QNetworkTypesConfig for EndCapTestNetworkConfig {
        type JobId = QProvingJobDataID;
    }

    pub(crate) type RealmEdgeHandlerFor<N> = RealmEdgeHandler<
        N,
        TestUnifiedDatabaseStore,
        TestUnifiedDatabaseStore,
        FakeEphemeralQueuePublisher,
        FakeWorkerQueueSubscriber,
        InMemoryTempStore,
        InMemoryTempStore,
    >;

    /// Realm edge handler wired to a fresh in-memory database, temp/proof store
    /// and fake queues, mirroring how `server.rs` builds the production handler.
    /// The hash/field types are pinned to the in-memory store's config, so any
    /// network config sharing them (TestNetworkConfig, the echo config) fits.
    pub(crate) struct RealmEdgeTestEnv<N>
    where
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + QNetworkHashTypes<F = PF, QHash = PHash>,
    {
        pub(crate) handler: RealmEdgeHandlerFor<N>,
        pub(crate) db: Arc<TestUnifiedDatabaseStore>,
        pub(crate) temp_db: Arc<InMemoryTempStore>,
        pub(crate) user_update_queue: Arc<FakeEphemeralQueuePublisher>,
        pub(crate) work_queue: Arc<FakeWorkerQueueSubscriber>,
    }

    impl<N> RealmEdgeTestEnv<N>
    where
        N: QNetworkTypesConfig<JobId = QProvingJobDataID> + QNetworkHashTypes<F = PF, QHash = PHash>,
    {
        pub(crate) async fn create(proof_verifier: Arc<N::ZKVerifier>) -> anyhow::Result<Self> {
            let db = Arc::new(create_test_unified_db().await?);
            let tag_tree_rewards_store = Arc::clone(&db);
            let temp_db = Arc::new(InMemoryTempStore::new("realm_edge_test".to_string(), 1, 2));
            let proof_store = Arc::clone(&temp_db);
            let user_update_queue = Arc::new(FakeEphemeralQueuePublisher::new());
            let work_queue = Arc::new(FakeWorkerQueueSubscriber::new());
            let handler = RealmEdgeHandler::new(
                Arc::clone(&db),
                tag_tree_rewards_store,
                Arc::clone(&temp_db),
                proof_store,
                Arc::clone(&user_update_queue),
                Arc::clone(&work_queue),
                test_realm_identifier(),
                TEST_CHAIN_ID,
                TEST_NODE_ID,
                proof_verifier,
            );
            // A fresh InMemoryTempStore errors on pending-id reads; seed both
            // counters so handler reads behave like production (ids at 0).
            let rid = test_realm_identifier();
            temp_db.set_unique_pending_ids(&rid, 0, 0).await?;
            temp_db.set_gathering_unique_pending_ids(&rid, 0, 0).await?;
            Ok(Self { handler, db, temp_db, user_update_queue, work_queue })
        }
    }

    pub(crate) type StandardEnv = RealmEdgeTestEnv<TestNetworkConfig>;
    pub(crate) type EndCapEnv = RealmEdgeTestEnv<EndCapTestNetworkConfig>;

    async fn end_cap_env() -> anyhow::Result<EndCapEnv> {
        RealmEdgeTestEnv::create(Arc::new(EndCapEchoVerifier {})).await
    }

    /// Seeds contract state tree height metadata for contracts 0..CONTRACT_COUNT
    /// at checkpoint 0 (reads use max-checkpoint semantics, so this is visible
    /// at MAX_CHECKPOINT_ID).
    async fn seed_contract_heights(env: &EndCapEnv) -> anyhow::Result<()> {
        let heights = (0..CONTRACT_COUNT as u64).map(|id| (id, CONTRACT_TREE_HEIGHT)).collect::<Vec<_>>();
        env.db.set_contract_tree_heights(0, &heights).await
    }

    /// The append root the handler will compute for the checkpoint-tree proof of
    /// leaf 0 (the only committed checkpoint on a fresh database is 0).
    pub(crate) async fn checkpoint_tree_append_root_zero(db: &TestUnifiedDatabaseStore) -> anyhow::Result<PHash> {
        let proof = db.checkpoint_tree_get_merkle_proof(u64::MAX - 0xFFFF, 0).await?;
        Ok(proof.get_append_root::<PoseidonHasher>())
    }

    /// Builds a self-consistent end-cap submission input for `user_id` whose
    /// every gate matches a fresh realm database:
    /// - the user has no committed leaf, so the start hash is the zero value
    ///   (the handler derives the same from the empty global user tree);
    /// - the user contract tree starts empty (root = zero hash at the contract
    ///   tree height), matching the handler's fallback zero user leaf;
    /// - checkpoint ids are 0 on both sides.
    fn gen_end_cap_input(user_id: u64, checkpoint_tree_root: PHash) -> SubmitUserEndCapNonProofInput<PF, PHash> {
        type Hasher = PoseidonHasher;
        let mut user_contract_tree = SimpleMemoryMerkleStoreV3::<Hasher, PHash>::new(CONTRACT_TREE_HEIGHT);
        let mut contract_state_updates = Vec::with_capacity(CONTRACT_COUNT);
        for contract_id in 0..CONTRACT_COUNT as u64 {
            let mut contract_state_tree = SimpleMemoryMerkleStoreV3::<Hasher, PHash>::new(CONTRACT_TREE_HEIGHT);
            // deterministic per-contract leaf writes: distinct slots per contract
            let updates = (0..8u64)
                .map(|i| {
                    let leaf_id = contract_id * 16 + i;
                    let value = PHash::from_values(1000 + contract_id * 10 + i, 0, 0, 0);
                    contract_state_tree.set_leaf(leaf_id, value)
                })
                .collect::<Vec<_>>();
            let end_root = contract_state_tree.get_root();
            let user_contract_tree_update_proof = user_contract_tree.set_leaf(contract_id, end_root);
            contract_state_updates.push(ContractStateUpdateHistory {
                user_contract_tree_update_proof,
                updates: updates
                    .into_iter()
                    .map(|delta_proof| ContractStateUpdate::Positional { delta_proof })
                    .collect(),
            });
        }
        let new_user_contract_tree_root = user_contract_tree.get_root();

        let user_id_f = PF::from_u64_value(user_id);
        // exactly the fallback leaf the handler serves for a missing user
        let old_user_leaf = PQEDUserLeaf {
            public_key: PHash::get_zero_value(),
            user_state_tree_root: zh(CONTRACT_TREE_HEIGHT as usize),
            balance: PF::ZERO_VALUE,
            nonce: PF::ZERO_VALUE,
            last_checkpoint_id: PF::ZERO_VALUE,
            event_index: PF::ZERO_VALUE,
            user_id: user_id_f,
        };
        assert!(old_user_leaf.is_first_transaction_old_user_leaf());

        let new_user_leaf = PQEDUserLeaf {
            user_id: user_id_f,
            last_checkpoint_id: PF::ZERO_VALUE,
            user_state_tree_root: new_user_contract_tree_root,
            public_key: PHash::from_values(user_id, 7, 8, 9),
            balance: PF::from_u64_value(1_000_000),
            nonce: PF::from_u64_value(1),
            event_index: PF::from_u64_value(1),
        };
        let state_transition = PUPSEndCapResultCompact {
            start_user_leaf_hash: PHash::get_zero_value(),
            end_user_leaf_hash: new_user_leaf.qfhash::<Hasher>(),
            checkpoint_tree_root_hash: checkpoint_tree_root,
            user_id: user_id_f,
        };
        let stats = GUTAStats {
            guta_fees_collected: PF::from_u64_value(1000),
            da_fees_collected: PF::from_u64_value(1000 * 8 * CONTRACT_COUNT as u64),
            user_ops_processed: PF::from_u64_value(1),
            total_transactions: PF::from_u64_value(CONTRACT_COUNT as u64),
            slots_modified: PF::from_u64_value(8 * CONTRACT_COUNT as u64),
        };
        let core = SubmitUserEndCapNonProofCoreInput {
            checkpoint_id: PF::ZERO_VALUE,
            state_transition,
            new_user_leaf,
            stats,
        };
        SubmitUserEndCapNonProofInput { core, contract_state_updates, events: vec![] }
    }

    /// A submission input + proof bytes pair that passes every gate of
    /// `handle_user_end_cap_proof_submission` on the given fresh env.
    async fn valid_end_cap_submission(env: &EndCapEnv) -> anyhow::Result<(SubmitUserEndCapNonProofInput<PF, PHash>, Vec<u8>)> {
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
        let input = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        let expected_hash = input
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT);
        let proof_bytes = expected_hash.into_owned_32bytes().to_vec();
        Ok((input, proof_bytes))
    }

    #[tokio::test]
    async fn user_belongs_to_realm_partitions_ids_by_realm_prefix() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;
        let users_per_realm = 1u64 << N::REALM_GLOBAL_USER_TREE_HEIGHT;

        // realm 1 owns [1 * users_per_realm, 2 * users_per_realm)
        assert!(!handler.user_belongs_to_realm(users_per_realm - 1));
        assert!(handler.user_belongs_to_realm(users_per_realm));
        assert!(handler.user_belongs_to_realm(REALM_USER_ID));
        assert!(handler.user_belongs_to_realm(2 * users_per_realm - 1));
        assert!(!handler.user_belongs_to_realm(2 * users_per_realm));
        assert!(!handler.user_belongs_to_realm(OTHER_REALM_USER_ID));

        // the RPC mirror computes the same partition
        assert!(RealmEdgeRpcServer::check_user_id_in_realm(handler, REALM_USER_ID).await?);
        assert!(!RealmEdgeRpcServer::check_user_id_in_realm(handler, OTHER_REALM_USER_ID).await?);
        Ok(())
    }

    #[tokio::test]
    async fn pending_id_mappings_and_submit_guard() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // no mappings exist on a fresh database
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(0).await?, None);
        assert_eq!(
            RealmEdgeRpcServer::get_unique_pending_id_for_checkpoint_id(handler, 0).await?,
            None
        );

        // seed both directions of the mapping
        env.db.set_unique_pending_id_checkpoint_id_mapping(7, 3).await?;
        env.db.set_checkpoint_id_to_unique_pending_id_mapping(3, 7, &11u128).await?;
        assert_eq!(handler.get_checkpoint_id_for_unique_pending_id_internal(7).await?, Some(3));
        assert_eq!(
            RealmEdgeRpcServer::get_unique_pending_id_for_checkpoint_id(handler, 3).await?,
            Some((7, 11u128))
        );

        // the submit guard passes while no status is recorded, then rejects
        handler.ensure_user_has_not_submitted(REALM_USER_ID, 0).await?;
        env.temp_db
            .set_submitted_status_for_pending(&handler.realm_identifier, 0, REALM_USER_ID, 5)
            .await?;
        let err = handler
            .ensure_user_has_not_submitted(REALM_USER_ID, 0)
            .await
            .expect_err("a submitted user must be rejected");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn job_stats_require_pending_mapping_and_aggregate_durations() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // no pending-id mapping exists on a fresh database
        let err = handler
            .get_job_stats_internal(0)
            .await
            .expect_err("stats for a checkpoint without pending mapping must fail");
        assert!(err.to_string().contains("no unique pending id"), "unexpected error: {err}");

        // map checkpoint 3 to pending id 7 in both directions; stats default to zero
        env.db.set_unique_pending_id_checkpoint_id_mapping(7, 3).await?;
        env.db.set_checkpoint_id_to_unique_pending_id_mapping(3, 7, &11u128).await?;
        let stats = handler.get_job_stats_internal(3).await?;
        assert_eq!(stats.unique_pending_id, 7);
        assert_eq!(stats.total_completed, 0);
        assert_eq!(stats.total_duration_ms, 0);
        assert_eq!(stats.min_duration_ms, None);
        assert_eq!(stats.max_duration_ms, None);

        // recorded job durations aggregate through the temp db
        env.temp_db.increment_job_stats(&handler.realm_identifier, 7, 25).await?;
        env.temp_db.increment_job_stats(&handler.realm_identifier, 7, 40).await?;
        let stats = RealmEdgeRpcServer::get_job_stats(handler, 3).await?;
        assert_eq!(stats.unique_pending_id, 7);
        assert_eq!(stats.total_completed, 2);
        assert_eq!(stats.total_duration_ms, 65);
        assert_eq!(stats.min_duration_ms, Some(25));
        assert_eq!(stats.max_duration_ms, Some(40));
        Ok(())
    }

    #[tokio::test]
    async fn contract_height_cache_fetches_from_db_and_gates_unknown_contracts() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // unknown contract: no height metadata in the realm db yet
        let err = handler
            .contract_state_tree_height(0)
            .await
            .expect_err("missing height metadata must be rejected");
        assert!(
            err.to_string().contains("contract 0 state tree height metadata is not available"),
            "unexpected error: {err}"
        );

        // seed heights for contracts 0..5 at checkpoint 0; the fetch reads at
        // MAX_CHECKPOINT_ID but max-checkpoint semantics finds them
        let heights = (0..CONTRACT_COUNT as u64).map(|id| (id, CONTRACT_TREE_HEIGHT)).collect::<Vec<_>>();
        env.db.set_contract_tree_heights(0, &heights).await?;
        handler.ensure_contract_heights_in_cache(&[0, 2, 4]).await?;
        assert_eq!(handler.contract_state_tree_height(0).await?, CONTRACT_TREE_HEIGHT);
        assert!(handler.contract_state_tree_height_cache.mapping.get(&2).is_some());

        // heights already cached are not re-fetched, so an unknown id beside a
        // cached one is only rejected when it actually misses the cache
        let err = handler
            .contract_state_tree_height(9)
            .await
            .expect_err("unknown contract id must still be rejected");
        assert!(
            err.to_string().contains("contract 9 state tree height metadata is not available"),
            "unexpected error: {err}"
        );

        // RPC surface: raw heights from the db and a height-dependent root read
        let raw = RealmEdgeRpcServer::get_contract_tree_state_heights(handler, 0, vec![0, 2]).await?;
        assert_eq!(raw, vec![CONTRACT_TREE_HEIGHT; 2]);
        let root = RealmEdgeRpcServer::get_user_contract_state_tree_root(handler, 0, REALM_USER_ID, 0).await?;
        assert_eq!(root, zh(CONTRACT_TREE_HEIGHT as usize));
        Ok(())
    }

    #[tokio::test]
    async fn user_end_cap_slot_updates_round_trip_through_temp_db() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // nothing stored yet
        assert!(handler.get_user_end_cap_slot_updates_internal(0, REALM_USER_ID).await?.is_none());

        let payload = RealmEndCapSlotUpdates {
            realm_id: TEST_REALM_ID,
            realm_sub_id: TEST_REALM_SUB_ID,
            unique_pending_id: 3,
            user_id: REALM_USER_ID,
            contracts: vec![RealmContractSlotUpdates {
                contract_id: 1,
                slot_updates: vec![RealmSlotUpdate { slot: 5, old_value: 0, new_value: 7 }],
            }],
        };
        env.temp_db
            .set_user_end_cap_slot_updates(
                &handler.realm_identifier,
                3,
                REALM_USER_ID,
                bincode::serialize(&payload)?,
            )
            .await?;
        // the structs are not PartialEq, so compare through the bincode bytes
        // the handler round-trips
        let read_back = handler
            .get_user_end_cap_slot_updates_internal(3, REALM_USER_ID)
            .await?
            .expect("stored slot updates must be readable");
        assert_eq!(bincode::serialize(&read_back)?, bincode::serialize(&payload)?);
        let rpc_read = RealmEdgeRpcServer::get_user_end_cap_slot_updates(handler, 3, REALM_USER_ID)
            .await?
            .expect("stored slot updates must be readable via RPC");
        assert_eq!(bincode::serialize(&rpc_read)?, bincode::serialize(&payload)?);
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_rejects_invalid_submissions() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;

        // checkpoint id must match the new user leaf's last checkpoint id
        let mut mismatch = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        mismatch.core.new_user_leaf.last_checkpoint_id = PF::from_u64_value(1);
        let err = handler
            .handle_user_end_cap_proof_submission(mismatch, vec![])
            .await
            .expect_err("checkpoint mismatch must fail");
        assert!(
            err.to_string().contains("does not match new_user_leaf last_checkpoint_id"),
            "unexpected error: {err}"
        );

        // user from another realm
        let foreign = gen_end_cap_input(OTHER_REALM_USER_ID, checkpoint_root);
        let err = handler
            .handle_user_end_cap_proof_submission(foreign, vec![])
            .await
            .expect_err("user outside the realm must fail");
        assert!(err.to_string().contains("does not belong to this realm"), "unexpected error: {err}");

        // empty contract state updates
        let mut empty = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        empty.contract_state_updates = vec![];
        let err = handler
            .handle_user_end_cap_proof_submission(empty, vec![])
            .await
            .expect_err("empty updates must fail");
        assert!(err.to_string().contains("contract_state_updates cannot be empty"), "unexpected error: {err}");

        // end-cap checkpoint ahead of the node's current checkpoint
        let mut future = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        future.core.checkpoint_id = PF::from_u64_value(1);
        future.core.new_user_leaf.last_checkpoint_id = PF::from_u64_value(1);
        let err = handler
            .handle_user_end_cap_proof_submission(future, vec![])
            .await
            .expect_err("future checkpoint must fail");
        assert!(err.to_string().contains("but current checkpoint is"), "unexpected error: {err}");

        // stale start leaf hash
        let mut bad_start = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        bad_start.core.state_transition.start_user_leaf_hash = PHash::from_values(4242, 0, 0, 0);
        let err = handler
            .handle_user_end_cap_proof_submission(bad_start, vec![])
            .await
            .expect_err("wrong start hash must fail");
        assert!(err.to_string().contains("Invalid start_user_leaf_hash"), "unexpected error: {err}");

        // wrong checkpoint tree root
        let bad_root = gen_end_cap_input(REALM_USER_ID, PHash::from_values(777, 0, 0, 0));
        let proof_bytes = bad_root
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT)
            .into_owned_32bytes()
            .to_vec();
        let err = handler
            .handle_user_end_cap_proof_submission(bad_root, proof_bytes)
            .await
            .expect_err("wrong checkpoint tree root must fail");
        assert!(
            err.to_string().contains("Invalid checkpoint tree proof historical root"),
            "unexpected error: {err}"
        );

        // proof bytes that decode to a different public-inputs hash
        let (input, _) = valid_end_cap_submission(&env).await?;
        let err = handler
            .handle_user_end_cap_proof_submission(input, PHash::get_zero_value().into_owned_32bytes().to_vec())
            .await
            .expect_err("mismatched public inputs hash must fail");
        assert!(err.to_string().contains("Public inputs hash mismatch"), "unexpected error: {err}");

        // inconsistent new user leaf (end hash does not hash to the new leaf)
        let mut bad_leaf = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        bad_leaf.core.state_transition.end_user_leaf_hash = PHash::from_values(8888, 0, 0, 0);
        let proof_bytes = bad_leaf
            .core
            .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT)
            .into_owned_32bytes()
            .to_vec();
        let err = handler
            .handle_user_end_cap_proof_submission(bad_leaf, proof_bytes)
            .await
            .expect_err("inconsistent new user leaf must fail");
        assert!(err.to_string().contains("invalid new_user_leaf"), "unexpected error: {err}");

        // user whose committed leaf is already at a later checkpoint
        env.db
            .set_user_leaf(
                0,
                &PQEDUserLeaf {
                    public_key: PHash::from_values(77, 0, 0, 0),
                    user_state_tree_root: zh(CONTRACT_TREE_HEIGHT as usize),
                    balance: PF::from_u64_value(1),
                    nonce: PF::ZERO_VALUE,
                    last_checkpoint_id: PF::from_u64_value(5),
                    event_index: PF::ZERO_VALUE,
                    user_id: PF::from_u64_value(REALM_USER_ID),
                },
            )
            .await?;
        let stale = gen_end_cap_input(REALM_USER_ID, checkpoint_root);
        let err = handler
            .handle_user_end_cap_proof_submission(stale, vec![])
            .await
            .expect_err("stale user checkpoint must fail");
        assert!(err.to_string().contains("but user's last checkpoint is 5"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_happy_path_publishes_and_stores() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;
        let (input, proof_bytes) = valid_end_cap_submission(&env).await?;
        let new_user_leaf = input.core.new_user_leaf.clone();

        handler.handle_user_end_cap_proof_submission(input, proof_bytes.clone()).await?;

        // the end-cap queue item was published under the live proc id
        assert_eq!(env.user_update_queue.published_count(), 1);
        let published = env.user_update_queue.published_bytes_for(0);
        assert_eq!(published.len(), 1);
        let queue_item = PsyRealmUserUpdateQueueItem::<PF, PHash>::decode_queue_item_ref(&published[0])?;
        assert_eq!(queue_item.job_id.circuit_type, ProvingJobCircuitType::UserEndCap);
        assert_eq!(queue_item.job_id.task_index, REALM_USER_ID as u32);
        assert_eq!(queue_item.job_id.goal_id, 0);
        assert_eq!(queue_item.new_user_leaf.user_id, new_user_leaf.user_id);
        assert_eq!(queue_item.new_user_leaf.user_state_tree_root, new_user_leaf.user_state_tree_root);
        assert_eq!(queue_item.new_user_leaf.balance, new_user_leaf.balance);
        assert_eq!(queue_item.old_user_leaf_hash, PHash::get_zero_value());
        assert_eq!(queue_item.new_user_leaf_hash, new_user_leaf.qfhash::<PoseidonHasher>());

        // the proof is stored under the derived end-cap job id
        let job_id = QProvingJobDataID::try_get_realm_edge_proof_store_output_proof_id_for_end_cap(
            REALM_USER_ID,
            N::GLOBAL_USER_TREE_HEIGHT,
            0,
        )?;
        assert!(env.temp_db.contains_proof_for_job_id(job_id, 0).await?);

        // the slot updates payload is stored and readable back
        let slot_updates = handler.get_user_end_cap_slot_updates_internal(0, REALM_USER_ID).await?;
        let slot_updates = slot_updates.expect("slot updates must be stored");
        assert_eq!(slot_updates.realm_id, TEST_REALM_ID);
        assert_eq!(slot_updates.realm_sub_id, TEST_REALM_SUB_ID);
        assert_eq!(slot_updates.unique_pending_id, 0);
        assert_eq!(slot_updates.user_id, REALM_USER_ID);
        assert_eq!(slot_updates.contracts.len(), CONTRACT_COUNT);
        for (index, contract) in slot_updates.contracts.iter().enumerate() {
            assert_eq!(contract.contract_id, index as u32);
            assert!(!contract.slot_updates.is_empty());
        }

        // a second submission for the same user is rejected by the status guard
        let (second, second_proof) = valid_end_cap_submission(&env).await?;
        let err = handler
            .handle_user_end_cap_proof_submission(second, second_proof)
            .await
            .expect_err("double submission must fail");
        assert!(err.to_string().contains("already been submitted"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn submit_user_end_cap_batch_splits_success_and_failure() -> anyhow::Result<()> {
        let env = end_cap_env().await?;
        seed_contract_heights(&env).await?;
        let handler = &env.handler;

        let (valid, valid_proof) = valid_end_cap_submission(&env).await?;
        let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
        let invalid = gen_end_cap_input(OTHER_REALM_USER_ID, checkpoint_root);

        let (success, failed) = RealmEdgeRpcServer::submit_user_end_cap_batch(
            handler,
            vec![(valid, valid_proof), (invalid, vec![])],
        )
        .await?;
        assert_eq!(success, vec![REALM_USER_ID]);
        assert_eq!(failed, vec![OTHER_REALM_USER_ID]);
        // exactly the valid submission reached the queue
        assert_eq!(env.user_update_queue.published_count(), 1);

        // the single-submit RPC wrapper reports "ok" for a fresh valid user
        let (again, again_proof) = {
            let checkpoint_root = checkpoint_tree_append_root_zero(&env.db).await?;
            let input = gen_end_cap_input(REALM_USER_ID + 1, checkpoint_root);
            let expected_hash = input
                .core
                .get_proof_public_inputs_hash::<PoseidonHasher>(EndCapTestNetworkConfig::GLOBAL_USER_TREE_HEIGHT);
            (input, expected_hash.into_owned_32bytes().to_vec())
        };
        let result = RealmEdgeRpcServer::submit_user_end_cap(handler, again, again_proof).await?;
        assert_eq!(result, "ok");
        Ok(())
    }

    #[tokio::test]
    async fn batch_reward_proofs_merge_top_proof_root() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // the coordinator-level top proof must exist for the pending id
        let err = handler
            .generate_batch_proof_miner_reward_proofs_internal(0, vec![])
            .await
            .expect_err("missing top proof must fail");
        assert!(err.to_string().contains("Rewards tree proof not found"), "unexpected error: {err}");

        // seed one rewards tag tree node and a non-trivial top proof
        let root_key = SimpleMerkleNodeKey::new_root();
        env.db.rewards_tag_tree_set_node_tag(0, root_key, zh(40), zh(41)).await?;
        let top_proof = TagTreeMerkleProof {
            root: zh(50),
            leaf: TagTreeNodePreimage {
                left: zh(51),
                right: zh(52),
                tag: zh(53),
            },
            index: 1,
            siblings: vec![TagTreeProofNode { sibling: zh(54), parent_tag: zh(55) }],
        };
        env.db.set_realm_rewards_tag_tree_top_proof_at_unique_pending_id(0, &top_proof).await?;

        // capture the realm-local proof before the merge
        let local = env
            .db
            .rewards_tag_tree_get_tag_tree_merkle_proof_at_unique_pending_id(0, &[root_key])
            .await?;
        assert_eq!(local.len(), 1);

        // empty request: no proofs
        let empty = handler.generate_batch_proof_miner_reward_proofs_internal(0, vec![]).await?;
        assert!(empty.is_empty());

        let job_ids = vec![QProvingJobDataIDWithRewardPath::new(
            QProvingJobDataID::qp_rand_gen(),
            root_key.to_reward_path_info(),
        )];
        let proofs = handler.generate_batch_proof_miner_reward_proofs_internal(0, job_ids).await?;
        assert_eq!(proofs.len(), 1);
        // the merged proof is re-rooted at the top proof with the merged index
        assert_eq!(proofs[0].tag_tree_proof.root, top_proof.root);
        assert_eq!(
            proofs[0].tag_tree_proof.index,
            local[0].index | (top_proof.index << local[0].siblings.len())
        );
        assert_eq!(
            proofs[0].tag_tree_proof.siblings.len(),
            local[0].siblings.len() + top_proof.siblings.len()
        );
        Ok(())
    }

    #[tokio::test]
    async fn rpc_reader_wrappers_serve_fresh_database_state() -> anyhow::Result<()> {
        let env = RealmEdgeTestEnv::<N>::create(Arc::new(TestZKVerifier {})).await?;
        let handler = &env.handler;

        // fresh database: latest checkpoint id is 0 and tree reads succeed
        assert_eq!(RealmEdgeRpcServer::get_latest_checkpoint_id(handler).await?, 0);
        let root = RealmEdgeRpcServer::get_latest_checkpoint_tree_root(handler).await?;
        assert_eq!(root, RealmEdgeRpcServer::get_checkpoint_tree_root(handler, 0).await?);
        assert_eq!(root, zh(N::CHECKPOINT_TREE_HEIGHT_USIZE));
        let user_root = RealmEdgeRpcServer::get_user_tree_root(handler, 0).await?;
        assert_eq!(user_root, zh(N::GLOBAL_USER_TREE_HEIGHT_USIZE));
        assert_eq!(
            RealmEdgeRpcServer::get_user_tree_leaf_hash(handler, 0, REALM_USER_ID).await?,
            PHash::get_zero_value()
        );

        // batch user leaf reads validate the id list
        let err = RealmEdgeRpcServer::get_user_leaves_batch(handler, 0, vec![])
            .await
            .expect_err("empty user id list must fail");
        assert!(err.to_string().contains("user_ids cannot be empty"), "unexpected error: {err}");

        // the top rewards-tree proof for a checkpoint that has none must fail
        let err = RealmEdgeRpcServer::get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id(handler, 0)
            .await
            .expect_err("missing rewards tree proof must fail");
        assert!(err.to_string().contains("Rewards tree proof not found"), "unexpected error: {err}");

        // IMT endpoints report missing leaves and keys
        let err = RealmEdgeRpcServer::get_imt_leaf_preimage(handler, 0, REALM_USER_ID, 0, 0)
            .await
            .expect_err("missing IMT leaf must fail");
        assert!(err.to_string().contains("Leaf preimage not found at index 0"), "unexpected error: {err}");
        let err = RealmEdgeRpcServer::get_imt_leaf_index_for_key(handler, 0, REALM_USER_ID, 0, zh(1))
            .await
            .expect_err("missing IMT key must fail");
        assert!(err.to_string().contains("Key not found in IMT"), "unexpected error: {err}");

        // membership proofs first resolve the contract height, which is unknown
        let err = RealmEdgeRpcServer::get_imt_membership_proof(handler, 0, REALM_USER_ID, 9, zh(1))
            .await
            .expect_err("unknown contract height must fail");
        assert!(
            err.to_string().contains("contract 9 state tree height metadata is not available"),
            "unexpected error: {err}"
        );
        Ok(())
    }
}
