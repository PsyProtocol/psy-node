use std::{future::Future, sync::Arc, u64};
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
    node::node_proving_state::PsyNodeProvingState, proof_input::guta::end_cap_input::SubmitUserEndCapNonProofInput, protocol::chain_context::{AuthorityObservation, AuthorityScope, CanonicalResponse}, queue_items::realm_user_update::PsyRealmUserUpdateQueueItem, v1::{
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
    store::traits::proof_store::{QCanonicalProofStoreV2, QParthProofStore},
};

use crate::realm::{
    edge::{error::RpcError, utils::end_cap::validate_end_cap_and_generate_node_data_for_edge},
    queue_key::RealmUserUpdateQueueKey,
};

const END_CAP_PROOF_CIRCUIT_TYPE_U32: u32 = ProvingJobCircuitType::UserEndCap as u32;
const REALM_STABLE_READ_MAX_ATTEMPTS: usize = 3;

fn require_realm_authority_observation<Hash>(
    observation: Option<AuthorityObservation<Hash>>,
    expected_chain_id: u32,
    expected_realm: &QRealmIdentifier,
) -> anyhow::Result<AuthorityObservation<Hash>> {
    let observation = observation
        .ok_or_else(|| anyhow::anyhow!("REALM_AUTHORITY_OBSERVATION_UNINITIALIZED"))?;
    if observation.chain().network_id().chain_id() != expected_chain_id {
        anyhow::bail!(
            "REALM_AUTHORITY_OBSERVATION_NETWORK_MISMATCH:expected={},observed={}",
            expected_chain_id,
            observation.chain().network_id().chain_id(),
        );
    }
    let expected_authority = AuthorityScope::Realm {
        realm_id: expected_realm.realm_id,
        realm_sub_id: expected_realm.realm_sub_id,
    };
    if observation.authority() != expected_authority {
        anyhow::bail!(
            "REALM_AUTHORITY_OBSERVATION_SCOPE_MISMATCH:expected={:?},observed={:?}",
            expected_authority,
            observation.authority(),
        );
    }
    Ok(observation)
}

fn realm_checkpoint_id_response<Hash>(
    observation: AuthorityObservation<Hash>,
) -> CanonicalResponse<Hash, u64> {
    let checkpoint_id = observation
        .chain()
        .checkpoint()
        .checkpoint_id()
        .get();
    CanonicalResponse::new(observation, checkpoint_id)
}

async fn read_stable_realm_value<
    Hash,
    Value,
    ReadObservation,
    ObservationFuture,
    ReadValue,
    ValueFuture,
>(
    mut read_observation: ReadObservation,
    mut read_value: ReadValue,
) -> anyhow::Result<CanonicalResponse<Hash, Value>>
where
    Hash: PartialEq,
    ReadObservation: FnMut() -> ObservationFuture,
    ObservationFuture: Future<Output = anyhow::Result<AuthorityObservation<Hash>>>,
    ReadValue: FnMut(u64) -> ValueFuture,
    ValueFuture: Future<Output = anyhow::Result<Value>>,
{
    for _ in 0..REALM_STABLE_READ_MAX_ATTEMPTS {
        let observation_before = read_observation().await?;
        let target_checkpoint_id = observation_before
            .chain()
            .checkpoint()
            .checkpoint_id()
            .get();
        let value_result = read_value(target_checkpoint_id).await;
        let observation_after = read_observation().await?;

        if observation_before != observation_after {
            continue;
        }

        return value_result.map(|value| CanonicalResponse::new(observation_before, value));
    }

    anyhow::bail!(
        "REALM_STABLE_READ_RETRY_EXHAUSTED:attempts={}",
        REALM_STABLE_READ_MAX_ATTEMPTS
    )
}

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
    pub async fn get_realm_authority_observation_internal(
        &self,
    ) -> anyhow::Result<AuthorityObservation<N::QHash>> {
        require_realm_authority_observation(
            self.db_reader.get_realm_authority_observation().await?,
            self.chain_id,
            &self.realm_identifier,
        )
    }
    pub async fn get_latest_checkpoint_id_v2_internal(
        &self,
    ) -> anyhow::Result<CanonicalResponse<N::QHash, u64>> {
        self.get_realm_authority_observation_internal()
            .await
            .map(realm_checkpoint_id_response)
    }
    pub async fn get_latest_l2_block_state_v2_internal(
        &self,
    ) -> anyhow::Result<CanonicalResponse<N::QHash, QEDL2BlockState>> {
        read_stable_realm_value(
            || self.get_realm_authority_observation_internal(),
            |checkpoint_id| self.db_reader.get_l2_block_state(checkpoint_id),
        )
        .await
    }
    pub async fn get_latest_checkpoint_tree_root_v2_internal(
        &self,
    ) -> anyhow::Result<CanonicalResponse<N::QHash, N::QHash>> {
        read_stable_realm_value(
            || self.get_realm_authority_observation_internal(),
            |checkpoint_id| self.db_reader.checkpoint_tree_get_root_hash(checkpoint_id),
        )
        .await
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2,
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
        let pending_context = self
            .temp_db
            .require_pending_context_for_pending_id(
                &self.realm_identifier,
                unique_pending_id,
            )
            .await?;
        if pending_context.proc_checkpoint_unique_id().as_u128() != proc_checkpoint_id {
            anyhow::bail!(
                "current pending context proc ID {} does not match gathering proc ID {}",
                pending_context.proc_checkpoint_unique_id().as_u128(),
                proc_checkpoint_id,
            );
        }
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
        let current_context = self
            .temp_db
            .get_current_pending_context(&self.realm_identifier)
            .await?
            .ok_or_else(|| anyhow::anyhow!("current pending context disappeared during end-cap verification"))?;
        if current_context != pending_context {
            anyhow::bail!("pending context changed during end-cap verification");
        }
        let proof_address = self
            .proof_store
            .resolve_proof_address(&pending_context, &job_id)?;
        self.proof_store
            .put_proof_bytes_exact(&proof_address, &proof_bytes)
            .await?;
        timer.lap_micros("put_proof_bytes_exact");
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
    > RealmEdgeRpcServer<N::F, N::QHash, N::JobId, N::ZKProof>
    for RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
{
    /// Check if a user id belongs to this realm

    async fn get_realm_authority_observation(
        &self,
    ) -> RpcResult<AuthorityObservation<N::QHash>> {
        res(self.get_realm_authority_observation_internal().await)
    }

    async fn get_latest_checkpoint_id_v2(
        &self,
    ) -> RpcResult<CanonicalResponse<N::QHash, u64>> {
        res(self.get_latest_checkpoint_id_v2_internal().await)
    }

    async fn get_latest_l2_block_state_v2(
        &self,
    ) -> RpcResult<CanonicalResponse<N::QHash, QEDL2BlockState>> {
        res(self.get_latest_l2_block_state_v2_internal().await)
    }

    async fn get_latest_checkpoint_tree_root_v2(
        &self,
    ) -> RpcResult<CanonicalResponse<N::QHash, N::QHash>> {
        res(self.get_latest_checkpoint_tree_root_v2_internal().await)
    }

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
        height: u8,
        leaf_id: u64,
    ) -> QRpcResult<N::QHash> {
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

#[cfg(test)]
mod authority_observation_rpc_tests {
    use super::*;
    use parth_core::data::hash::hash256::Hash256;
    use std::{collections::VecDeque, future::ready};
    use psy_data::protocol::{
        canonical_chain::{
            CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId,
            CheckpointRef, NetworkId,
        },
        chain_context::{AuthorityStateCheckpointId, AuthorityStateRoot},
    };

    const TEST_CHAIN_ID: u32 = 0x6979_7350;

    fn observation(
        chain_id: u32,
        authority: AuthorityScope,
    ) -> AuthorityObservation<Hash256> {
        observation_at(chain_id, authority, 7, 367, 0x11, 360, 0x22)
    }

    fn observation_at(
        chain_id: u32,
        authority: AuthorityScope,
        epoch: u64,
        checkpoint_id: u64,
        checkpoint_hash_byte: u8,
        state_checkpoint_id: u64,
        state_root_byte: u8,
    ) -> AuthorityObservation<Hash256> {
        AuthorityObservation::try_new(
            CanonicalChainRef::new(
                NetworkId::try_from_chain_id(chain_id).unwrap(),
                ChainEpoch::new(epoch),
                CheckpointRef::new(
                    CheckpointId::new(checkpoint_id),
                    CheckpointHash::from_last_chain_hash(Hash256([
                        checkpoint_hash_byte;
                        32
                    ])),
                ),
            ),
            authority,
            AuthorityStateCheckpointId::new(state_checkpoint_id),
            AuthorityStateRoot::from_local_state_root(Hash256([state_root_byte; 32])),
        )
        .unwrap()
    }

    fn realm_scope() -> AuthorityScope {
        AuthorityScope::Realm {
            realm_id: 9,
            realm_sub_id: 2,
        }
    }

    fn rust_function_body<'a>(source: &'a str, signature: &str) -> &'a str {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("missing function signature: {signature}"));
        let relative_open = source[start..]
            .find('{')
            .unwrap_or_else(|| panic!("missing function body: {signature}"));
        let open = start + relative_open;
        let mut depth = 0usize;

        for (offset, byte) in source.as_bytes()[open..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &source[open..=open + offset];
                    }
                }
                _ => {}
            }
        }

        panic!("unterminated function body: {signature}")
    }

    #[test]
    fn realm_rpc_observation_accepts_only_configured_network_and_scope() {
        let realm = QRealmIdentifier::new(9, 2);
        let valid = observation(TEST_CHAIN_ID, realm_scope());
        assert_eq!(
            require_realm_authority_observation(
                Some(valid),
                TEST_CHAIN_ID,
                &realm,
            )
                .unwrap(),
            valid,
        );

        assert!(
            require_realm_authority_observation::<Hash256>(
                None,
                TEST_CHAIN_ID,
                &realm,
            )
            .unwrap_err()
            .to_string()
            .contains("UNINITIALIZED")
        );

        let wrong_scope = observation(
            TEST_CHAIN_ID,
            AuthorityScope::Realm {
                realm_id: 10,
                realm_sub_id: 2,
            },
        );
        assert!(
            require_realm_authority_observation(
                Some(wrong_scope),
                TEST_CHAIN_ID,
                &realm,
            )
            .unwrap_err()
            .to_string()
            .contains("SCOPE_MISMATCH")
        );

        let other_network = psy_core::constants::chain_id::PsyChainNetworkType::LocalDevnet
            .get_chain_id();
        if other_network != TEST_CHAIN_ID {
            let wrong_network = observation(
                other_network,
                AuthorityScope::Realm {
                    realm_id: 9,
                    realm_sub_id: 2,
                },
            );
            assert!(
                require_realm_authority_observation(
                    Some(wrong_network),
                    TEST_CHAIN_ID,
                    &realm,
                )
                .unwrap_err()
                .to_string()
                .contains("NETWORK_MISMATCH")
            );
        }
    }

    #[test]
    fn checkpoint_id_response_is_derived_from_the_same_observation() {
        let observation = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            11,
            912,
            0x31,
            906,
            0x41,
        );
        let response = realm_checkpoint_id_response(observation);

        assert_eq!(*response.value(), 912);
        assert_eq!(response.observed(), &observation);
        assert_eq!(
            *response.value(),
            response
                .observed()
                .chain()
                .checkpoint()
                .checkpoint_id()
                .get()
        );
    }

    #[test]
    fn v2_handlers_are_checkpoint_addressed_not_legacy_latest_reads() {
        let source = include_str!("handler.rs");
        let checkpoint_id = rust_function_body(
            source,
            "pub async fn get_latest_checkpoint_id_v2_internal",
        );
        assert!(checkpoint_id.contains("get_realm_authority_observation_internal"));
        assert!(!checkpoint_id.contains("self.get_latest_checkpoint_id()"));
        assert!(!checkpoint_id.contains("db_reader.get_latest_checkpoint_id"));

        let l2 = rust_function_body(
            source,
            "pub async fn get_latest_l2_block_state_v2_internal",
        );
        assert!(l2.contains("get_l2_block_state(checkpoint_id)"));
        assert!(!l2.contains("get_latest_l2_block_state()"));

        let checkpoint_tree = rust_function_body(
            source,
            "pub async fn get_latest_checkpoint_tree_root_v2_internal",
        );
        assert!(checkpoint_tree.contains("checkpoint_tree_get_root_hash(checkpoint_id)"));
        assert!(!checkpoint_tree.contains("MAX_CHECKPOINT_ID"));
    }

    #[tokio::test]
    async fn stable_read_reselects_value_after_observation_changes() {
        let old = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            367,
            0x11,
            360,
            0x22,
        );
        let new = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            368,
            0x12,
            368,
            0x23,
        );
        let mut observations = VecDeque::from([old, new, new, new]);
        let mut selected_checkpoints = Vec::new();

        let response = read_stable_realm_value(
            || {
                ready(
                    observations
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("observation script exhausted")),
                )
            },
            |checkpoint_id| {
                selected_checkpoints.push(checkpoint_id);
                ready(Ok(checkpoint_id))
            },
        )
        .await
        .unwrap();

        assert_eq!(selected_checkpoints, vec![367, 368]);
        assert_eq!(*response.value(), 368);
        assert_eq!(response.observed(), &new);
    }

    #[tokio::test]
    async fn stable_read_retries_same_height_hash_or_local_state_changes() {
        let old = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            367,
            0x11,
            360,
            0x22,
        );
        let different_hash = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            367,
            0x12,
            360,
            0x22,
        );
        let different_local_state = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            367,
            0x12,
            361,
            0x23,
        );
        let mut observations = VecDeque::from([
            old,
            different_hash,
            different_hash,
            different_local_state,
            different_local_state,
            different_local_state,
        ]);
        let mut value_reads = 0usize;

        let response = read_stable_realm_value(
            || {
                ready(
                    observations
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("observation script exhausted")),
                )
            },
            |checkpoint_id| {
                value_reads += 1;
                ready(Ok(checkpoint_id))
            },
        )
        .await
        .unwrap();

        assert_eq!(value_reads, 3);
        assert_eq!(response.observed(), &different_local_state);
    }

    #[tokio::test]
    async fn changed_observation_discards_value_error_but_stable_error_is_returned() {
        let old = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            367,
            0x11,
            360,
            0x22,
        );
        let new = observation_at(
            TEST_CHAIN_ID,
            realm_scope(),
            7,
            368,
            0x12,
            368,
            0x23,
        );
        let mut observations = VecDeque::from([old, new, new, new]);

        let response = read_stable_realm_value(
            || {
                ready(
                    observations
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("observation script exhausted")),
                )
            },
            |checkpoint_id| {
                ready(if checkpoint_id == 367 {
                    Err(anyhow::anyhow!("transient old-branch read error"))
                } else {
                    Ok(checkpoint_id)
                })
            },
        )
        .await
        .unwrap();
        assert_eq!(*response.value(), 368);

        let mut stable_observations = VecDeque::from([new, new]);
        let error = read_stable_realm_value(
            || {
                ready(
                    stable_observations
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("observation script exhausted")),
                )
            },
            |_| ready(Err::<u64, _>(anyhow::anyhow!("stable data error"))),
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("stable data error"));
    }

    #[tokio::test]
    async fn continuously_changing_observation_exhausts_the_bounded_retry() {
        let observations = (0..(REALM_STABLE_READ_MAX_ATTEMPTS * 2))
            .map(|index| {
                observation_at(
                    TEST_CHAIN_ID,
                    realm_scope(),
                    7 + index as u64,
                    367,
                    0x11,
                    360,
                    0x22,
                )
            })
            .collect::<VecDeque<_>>();
        let mut observations = observations;
        let mut value_reads = 0usize;

        let error = read_stable_realm_value(
            || {
                ready(
                    observations
                        .pop_front()
                        .ok_or_else(|| anyhow::anyhow!("observation script exhausted")),
                )
            },
            |checkpoint_id| {
                value_reads += 1;
                ready(Ok(checkpoint_id))
            },
        )
        .await
        .unwrap_err();

        assert_eq!(value_reads, REALM_STABLE_READ_MAX_ATTEMPTS);
        assert!(error.to_string().contains("REALM_STABLE_READ_RETRY_EXHAUSTED"));
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
        ProofStore: QParthProofStore + QCanonicalProofStoreV2 + Send + Sync + 'static,
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
        work_context: psy_data::protocol::chain_context::WorkContextToken,
        tag: N::QHash,
        proof: Vec<u8>,
    ) -> RpcResult<()> {
        res(self.submit_proof_raw_internal(signature, request, work_context, tag, proof).await)
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
