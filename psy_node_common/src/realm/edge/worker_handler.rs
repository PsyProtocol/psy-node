use cf_utils::timer::DebugTimer;
use futures::future::try_join_all;
use std::sync::Arc;
use tokio::task;
use parth_core::{
    QCoreProcCheckpointUniqueId, crypto::{
        hash::
            traits::{MerkleHasher, MerkleZeroHasher, ZeroableHash}
        ,
        secp256k1::{QEDCompressedSecp256K1Signature, Secp256K1Verifier, SimpleTimedRequest},
    }, data::queue::queue_key::QPBaseQueueType, felt::{FromPrimitiveValuesFelt, ZeroableFelt}, protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier}
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{v1::qdata::user::PQEDUserLeaf,
    worker::{
        api_response::{PROVING_JOB_NODE_TYPE_REALM, PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse},
        metadata::{
            PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN, PsyProvingJobMetadata
        },
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    }}
;
use psy_node_core::{
 psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader}, psy_temp_db::StandardEdgeAPITempDBStoreBase, queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber}, store::traits::proof_store::QParthProofStore
};

use parth_core::crypto::secp256k1::REQUEST_TYPE_SUBMIT_PROOF;

use crate::{
    reputation::WorkerReputationOps,
    realm::{edge::handler::RealmEdgeHandler, queue_key::RealmProvingWorkQueueKey},
};

use parth_core::protocol::core_types::QZKProofPublicInputsHasherReader;
fn verify_api_signature(signature: &QEDCompressedSecp256K1Signature, request: &SimpleTimedRequest) -> bool {
    request.get_sig_hash::<parth_crypto::hash::sha256::CoreSha256Hasher>() == signature.message
        && parth_common::secp256k1::Secp256K1VerifierHelper::secp256k1_verify(signature).is_ok()
}
fn print_hash<H: Q256BitHash + std::fmt::Debug>(label: &str, hash: &H) {
    tracing::debug!("{}: {:?} ({})", label, hash, hex::encode(&hash.into_owned_32bytes()));
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
    pub async fn get_current_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.temp_db.get_unique_pending_ids(&self.realm_identifier).await
    }

    pub async fn get_current_gathering_unique_pending_id_internal(&self) -> anyhow::Result<(u64, QCoreProcCheckpointUniqueId)> {
        self.temp_db.get_gathering_unique_pending_ids(&self.realm_identifier).await
    }


    pub async fn has_job_id_already_been_submitted(&self, unique_pending_id: u64, job_id: N::JobId) -> anyhow::Result<bool> {
        Ok(self
            .temp_db
            .get_proof_miner_rewards_tree_value_or_none(&self.realm_identifier, unique_pending_id, job_id)
            .await?
            .is_some())
    }
    pub async fn get_job_id_submission_status(&self, _unique_checkpoint_id: u64, _job_id: &N::JobId) -> anyhow::Result<bool> {
        Ok(false)
    }
    pub async fn verify_miner_api_signature_and_check_reputation(
        &self,
        signature: &QEDCompressedSecp256K1Signature,
        request: &SimpleTimedRequest,
    ) -> anyhow::Result<()> {
        if !verify_api_signature(&signature, &request) {
            anyhow::bail!("invalid signature from miner");
        }
        let reputation = self.temp_db.get_worker_reputation(&self.realm_identifier, &signature.public_key).await?;
        if reputation <= 0 {
            anyhow::bail!("worker not eligible: reputation must be positive");
        }
        Ok(())
    }

    pub async fn get_worker_reputation_internal(&self, public_key: &[u8; 33]) -> anyhow::Result<u64> {
        self.temp_db.get_worker_reputation(&self.realm_identifier, public_key).await
    }

    pub async fn get_user_leaf_data_internal(&self, checkpoint_id: u64, user_id: u64) -> anyhow::Result<PQEDUserLeaf<N::F, N::QHash>> {
        tracing::debug!("get_user_leaf_data_internal: checkpoint_id={}, user_id={}", checkpoint_id, user_id);
        let leaf = self
            .db_reader
            .get_user_leaf(checkpoint_id, user_id)
            .await;

        if leaf.is_err(){
            let err = leaf.err().unwrap();
            let err_msg  = format!("{:?}", err);
            if err_msg.contains("User leaf not found for"){
                return Ok(PQEDUserLeaf {
                    public_key: N::QHash::get_zero_value(),
                    user_state_tree_root: N::HasherBase::get_zero_hash(N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE),
                    balance: N::F::ZERO_VALUE,
                    nonce: N::F::ZERO_VALUE,
                    last_checkpoint_id: N::F::ZERO_VALUE,
                    event_index: N::F::ZERO_VALUE,
                    user_id: N::F::from_u64_value(user_id),
                })
            }else{
                return Err(err);
            }
        }
        Ok(leaf.unwrap())
    }

    pub async fn get_user_leaves_data_internal(&self, checkpoint_id: u64, user_ids: &[u64]) -> anyhow::Result<Vec<PQEDUserLeaf<N::F, N::QHash>>> {
        if user_ids.len() == 0 {
            anyhow::bail!("user_ids cannot be empty");
        }else if user_ids.len() > 10000 {
            anyhow::bail!("user_ids length greater than 10000 not supported in get_user_leaves");
        }
        let leaves = self
            .db_reader
            .get_user_leaves_batch(checkpoint_id, user_ids)
            .await?;
        Ok(leaves.into_iter().enumerate().map(|(index, l)| {
            match l {
                Some(leaf) => leaf,
                None => PQEDUserLeaf {
                    public_key: N::QHash::get_zero_value(),
                    user_state_tree_root: N::HasherBase::get_zero_hash(N::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE),
                    balance: N::F::ZERO_VALUE,
                    nonce: N::F::ZERO_VALUE,
                    last_checkpoint_id: N::F::ZERO_VALUE,
                    event_index: N::F::ZERO_VALUE,
                    user_id: N::F::from_u64_value(user_ids[index]),
                }
            }
        }).collect())
    }
    pub async fn get_proving_work_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        self.verify_miner_api_signature_and_check_reputation(&signature, &request).await?;

        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;

        let queue_key = RealmProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let work_item: Option<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> = self
            .get_proof_work_queue
            .get_next_worker_queue_item_or_none(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0)
            .await?;

        if work_item.is_none() {
            anyhow::bail!("no proving work available");
        }
        let work_item = work_item.unwrap();

        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id.get_input_witness_id())
            .await?;

        let children_reward_tree_values = {
            if work_item.metadata.dependencies.len() == 0 || work_item.metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN
            {
                vec![]
            } else {
                let mut values = Vec::with_capacity(work_item.metadata.dependencies.len());
                for dependency in work_item.metadata.dependencies.iter() {
                    if dependency.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
                        values.push(N::QHash::get_zero_value());
                    } else {
                        let value: N::QHash = self
                            .temp_db
                            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, *dependency)
                            .await?;
                        values.push(value);
                    }
                }
                values
            }
        };
        let response = PsyWorkerGetProvingWorkAPIResponse {
            job: work_item,
            child_proof_tag_values: children_reward_tree_values,
            witness: witness_bytes,
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            node_type: PROVING_JOB_NODE_TYPE_REALM,
        };
        Ok(response)
    }
    pub async fn get_proving_work_with_child_proofs_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        let mut timer = DebugTimer::new("get_proving_work_with_child_proofs_internal");
        //tracing::debug!("get_proving_work_with_child_proofs_internal called");
        self.verify_miner_api_signature_and_check_reputation(&signature, &request).await?;
        timer.lap_micros("verify_miner_api_signature_and_check_reputation");


        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;
        timer.lap_micros("get_current_unique_pending_id_internal");

        let queue_key = RealmProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let work_item: Option<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> = self
            .get_proof_work_queue
            .get_next_worker_queue_item_or_none(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0)
            .await?;

        timer.lap_micros("get_next_worker_queue_item_or_none");
        if work_item.is_none() {
            anyhow::bail!("no proving work available");
        } else {
            //println!("unique_pending_id: {:?}", unique_pending_id);
            //println!("unique_proc_id: {:?}", unique_proc_id);
        }
        let work_item = work_item.unwrap();
        //println!("work_item.job_id: {:?}", work_item.job_id);
        //tracing::debug!("work item dependencies: {:?}", work_item.metadata.dependencies);
        let child_proofs = work_item
            .metadata
            .dependencies
            .iter()
            .map(|id| self.proof_store.get_proof_bytes_by_job_id(id.get_output_id()))
            .collect::<Vec<_>>()
            .into_iter();
        timer.lap_micros("collect get_proof_bytes_by_job_id futures");
        let res: Vec<Option<Vec<u8>>> = try_join_all(child_proofs).await?;
        timer.lap_micros("try_join_all get_proof_bytes_by_job_id futures");
        let mut final_child_proofs: Vec<Vec<u8>> = Vec::with_capacity(res.len());

        for (index, item) in res.into_iter().enumerate() {
            if let Some(proof) = item {
                final_child_proofs.push(proof);
            } else {
                tracing::error!("missing dependency proof for job id: {:?}", work_item.metadata.dependencies[index]);
                anyhow::bail!("missing child proof for job id");
            }
        }

        //println!("getting proof witness bytes: {:?}", work_item.job_id.get_input_witness_id());
        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id.get_input_witness_id())
            .await?;
        timer.lap_micros("get_tdb_proof_witness_bytes");
        //println!("got proof witness bytes, len: {}", witness_bytes.len());
        let children_reward_tree_values = {
            if work_item.metadata.dependencies.len() == 0 || work_item.metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN
            {
                vec![]
            } else {
                let mut values = Vec::with_capacity(work_item.metadata.dependencies.len());
                for dependency in work_item.metadata.dependencies.iter() {
                    if dependency.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof || dependency.circuit_type == ProvingJobCircuitType::UserEndCap {
                        values.push(N::QHash::get_zero_value());
                    } else {
                        let value: N::QHash = self
                            .temp_db
                            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, *dependency)
                            .await?;
                        values.push(value);
                    }
                }
                values
            }
        };
        timer.lap_micros("children_reward_tree_values");
        let response = PsyWorkerGetProvingWorkAPIResponse {
            job: work_item,
            child_proof_tag_values: children_reward_tree_values,
            witness: witness_bytes,
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            node_type: PROVING_JOB_NODE_TYPE_REALM,
        };
        self.temp_db
            .set_proving_job_metadata(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                &response.job.metadata,
            )
            .await?;

        timer.lap_micros("set_proving_job_metadata");

        // HACK: in the future we should create a new table for the expected proving
        // tag, but for now this ok i guess, but a HACK HACK: for now we set
        // self.temp_db.set_proof_miner_rewards_tree_value( with the expected proving
        // tag and then update it later to the actual value once the proof is submitted
        // this ensures the right person submits the proof AND the proof can only be
        // submitted once
        self.temp_db
            .set_proof_miner_rewards_tree_value(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;
        timer.lap_micros("set_proof_miner_rewards_tree_value");
        let claim_time_ms = chrono::Utc::now().timestamp_millis() as u64;
        self.temp_db
            .set_job_claim(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                &signature.public_key,
                claim_time_ms,
            )
            .await?;
        timer.lap_micros("set_job_claim");
        timer.lap_group("get_proving_work_with_child_proofs_internal");

        Ok(PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: response,
            input_proofs: final_child_proofs,
        })
    }
    pub async fn submit_proof_raw_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
        mut job_id: N::JobId,
        tag: N::QHash,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
    {
        if !verify_api_signature(&signature, &request) || request.request_type != REQUEST_TYPE_SUBMIT_PROOF {
            anyhow::bail!("invalid signature for submit_proof_raw");
        }
        job_id = job_id.get_output_id();
        let mut timer = DebugTimer::new("submit_proof_raw_internal");
        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;
        timer.lap_micros("get_current_unique_pending_id_internal");
        let proof_bytes = Arc::new(proof_bytes);

        // HACK: check to make sure the tag matches. If not, job was completed by another worker (stolen) - slash submitter.
        let expected_tag = self
            .temp_db
            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id.get_output_id())
            .await?;
        if expected_tag != tag {
            self.temp_db
                .apply_reputation_slash_on_tag_mismatch(&self.realm_identifier, &signature.public_key)
                .await?;
            anyhow::bail!("Submitted tag does not match expected tag for job id");
        }
        timer.lap_micros("get_proof_miner_rewards_tree_value");

        let metadata: PsyProvingJobMetadata<N::QHash, N::JobId> = self
            .temp_db
            .get_proving_job_metadata(&self.realm_identifier, unique_pending_id, job_id.get_output_id())
            .await?;

        timer.lap_micros("get_proving_job_metadata");
        let children_reward_tree_values = {
            if metadata.dependencies.len() == 0 || metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                vec![]
            } else {
                let mut values = Vec::with_capacity(metadata.dependencies.len());
                for dependency in metadata.dependencies.iter() {
                    let value: N::QHash = if dependency.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof || dependency.circuit_type == ProvingJobCircuitType::UserEndCap {
                        N::QHash::get_zero_value()
                    } else {
                        self.temp_db
                            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, dependency.get_output_id())
                            .await?
                    };
                    values.push(value);
                }
                values
            }
        };
        timer.lap_micros("children_reward_tree_values");

        let reward_tree_value = metadata.get_new_rewards_tag_tree_value::<N::HasherBase>(tag, &children_reward_tree_values)?;

        //print_hash("reward_tree_value", &reward_tree_value);
        let full_expected_public_inputs_hash =
            N::HasherBase::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value);

        //print_hash("full_expected_public_inputs_hash", &full_expected_public_inputs_hash);
        //print_hash("metadata.expected_public_inputs_hash", &metadata.expected_public_inputs_hash);

        tracing::debug!(
            "Verifying proof for job id: {:?} with expected public inputs hash: {:?} (from metadata: {:?})",
            job_id,
            hex::encode(&full_expected_public_inputs_hash.into_owned_32bytes()),
            hex::encode(&metadata.expected_public_inputs_hash.into_owned_32bytes())
        );
        let debug_public_inputs = N::ZKVerifier::get_proof_public_inputs_hash(&N::ZKVerifier::try_proof_from_slice(&proof_bytes)?)?;
        timer.lap_micros("get_proof_public_inputs_hash");
        tracing::debug!(
            "Debug: extracted public inputs hash from proof: {:?}",
            hex::encode(&debug_public_inputs.into_owned_32bytes())
        );
        print_hash("debug_public_inputs", &debug_public_inputs);

        let proof_verifier = self.proof_verifier.clone();
        task::spawn_blocking({
            let proof_bytes = proof_bytes.clone();
            move || {
                proof_verifier.verify_zk_proof_from_slice_check_public_inputs_hash(
                    job_id.circuit_type.to_u8() as u32,
                    &proof_bytes,
                    full_expected_public_inputs_hash,
                )
            }
        }).await??;
        timer.lap_micros("verify_zk_proof_from_slice_check_public_inputs_hash");

        // HACK: now set the correct reward tree value
        self.temp_db
            .set_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id, reward_tree_value)
            .await?;

        timer.lap_micros("set_proof_miner_rewards_tree_value");
        if self
            .temp_db
            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id)
            .await?
            != reward_tree_value
        {
            anyhow::bail!("Failed to set rewards tree value for job id");
        }

        timer.lap_micros("get_proof_miner_rewards_tree_value");
        self.proof_store.put_proof_bytes_for_job_id(job_id.get_output_id(), &proof_bytes).await?;
        timer.lap_micros("put_proof_bytes_for_job_id");

        if let Ok(Some((public_key, claim_time_ms))) = self
            .temp_db
            .get_job_claim(&self.realm_identifier, unique_pending_id, job_id)
            .await
        {
            self.temp_db
                .apply_reputation_on_submit(&self.realm_identifier, &public_key, claim_time_ms)
                .await?;
            timer.lap_micros("update_worker_reputation");
        } else {
            tracing::debug!("submit_proof_raw: no job_claim record for job_id {:?}, skipping reputation update", job_id);
        }

        /*
        self.tag_tree_rewards_store
            .rewards_tag_tree_set_node_tag(unique_pending_id, metadata.get_reward_tree_node_key(), tag, reward_tree_value)
            .await?;

        // now update the tag tree

        if metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD {
            // special case for 3 children
            if metadata.dependencies.len() != 3 || children_reward_tree_values.len() != 3 {
                anyhow::bail!(
                    "Expected 3 children for 3-children double reward hash mode, got {}",
                    metadata.dependencies.len()
                );
            }
            let zero = N::QHash::get_zero_value();

            let left_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&children_reward_tree_values[0], &children_reward_tree_values[1], &tag);
            let right_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&children_reward_tree_values[2], &zero, &tag);
            let top_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&left_value, &right_value, &tag);
            if top_value != reward_tree_value {
                anyhow::bail!("Computed top value does not match reward tree value for 3-children double reward hash mode");
            }
            let self_key = metadata.get_reward_tree_node_key();
            let left_key = self_key.left_child();
            let right_key = self_key.right_child();
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, left_key, tag, left_value)
                .await?;
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, right_key, tag, right_value)
                .await?;
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, self_key, tag, top_value)
                .await?;
        } else if metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD {
            // do nothing
        } else {
            let self_key = metadata.get_reward_tree_node_key();
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, self_key, tag, reward_tree_value)
                .await?;
        }
        */

        {
            let expected_updates =
                metadata.get_new_rewards_tag_tree_updates::<N::HasherBase>(tag, &children_reward_tree_values, reward_tree_value)?;

            for (key, node) in expected_updates {
                self.tag_tree_rewards_store
                    .rewards_tag_tree_set_node_tag(unique_pending_id, key, node.tag, node.value)
                    .await?;
            }

            timer.lap_micros("rewards_tag_tree_set_node_tag for all updates");
            if job_id.circuit_type.needs_to_save_child_reward_tree_values_to_database() {
                let node_key = metadata.get_reward_tree_node_key();
                let left_key = node_key.left_child();
                let right_key = node_key.right_child();
                if children_reward_tree_values.len() == 1 {
                    self.tag_tree_rewards_store
                        .rewards_tag_tree_set_node_value_only(unique_pending_id, left_key, children_reward_tree_values[0])
                        .await?;
                } else if children_reward_tree_values.len() == 2 {
                    self.tag_tree_rewards_store
                        .rewards_tag_tree_set_node_value_only(unique_pending_id, left_key, children_reward_tree_values[0])
                        .await?;
                    self.tag_tree_rewards_store
                        .rewards_tag_tree_set_node_value_only(unique_pending_id, right_key, children_reward_tree_values[1])
                        .await?;
                } else if children_reward_tree_values.len() != 0 {
                    anyhow::bail!("Invalid number of children for saving tag tree values to database, this should never happen");
                }
                timer.lap_micros("rewards_tag_tree_set_node_tag for child values");
            }
        }

        // ack the queue item as completed
        let queue_key = RealmProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };

        let item = PsyProvingJobMetadataWithJobId {
            job_id: job_id.get_output_id(),
            metadata,
        };
        self.get_proof_work_queue
            .worker_queue_report_job_completed(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0, &item)
            .await?;
        timer.lap_micros("worker_queue_report_job_completed");
        timer.lap_group("submit_proof_raw_internal");

        Ok(())
    }
    /*
    pub async fn get_proving_work_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        self.verify_miner_api_signature_and_check_reputation(&signature, &request).await?;

        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;

        let queue_key = CoordinatorProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let work_item: Option<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> = self
            .get_proof_work_queue
            .get_next_worker_queue_item_or_none(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0)
            .await?;

        if work_item.is_none() {
            anyhow::bail!("no proving work available");
        }
        let work_item = work_item.unwrap();

        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id)
            .await?;

        let children_reward_tree_values = {
            if work_item.metadata.dependencies.len() == 0 || work_item.metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                vec![]
            } else {
                let mut values = Vec::with_capacity(work_item.metadata.dependencies.len());
                for dependency in work_item.metadata.dependencies.iter() {
                    let value: N::QHash = self
                        .temp_db
                        .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, *dependency)
                        .await?;
                    values.push(value);
                }
                values
            }
        };
        let response = PsyWorkerGetProvingWorkAPIResponse {
            job: work_item,
            child_proof_tag_values: children_reward_tree_values,
            witness: witness_bytes,
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            node_type: PROVING_JOB_NODE_TYPE_REALM,
        };
        self.temp_db
            .set_proving_job_metadata(&self.realm_identifier, unique_pending_id, response.job.job_id, &response.job.metadata)
            .await?;

        // HACK: in the future we should create a new table for the expected proving
        // tag, but for now this ok i guess, but a HACK HACK: for now we set
        // self.temp_db.set_proof_miner_rewards_tree_value( with the expected proving
        // tag and then update it later to the actual value once the proof is submitted
        // this ensures the right person submits the proof AND the proof can only be
        // submitted once
        self.temp_db
            .set_proof_miner_rewards_tree_value(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id,
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;
        Ok(response)
    }
    pub async fn get_proving_work_with_child_proofs_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        self.verify_miner_api_signature_and_check_reputation(&signature, &request).await?;

        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;

        let queue_key = CoordinatorProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };
        let work_item: Option<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> = self
            .get_proof_work_queue
            .get_next_worker_queue_item_or_none(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0)
            .await?;

        if work_item.is_none() {
            anyhow::bail!("no proving work available");
        }
        let work_item = work_item.unwrap();

        let child_proofs = work_item
            .metadata
            .dependencies
            .iter()
            .map(|id| self.proof_store.get_proof_bytes_by_job_id(*id))
            .collect::<Vec<_>>()
            .into_iter();
        let res: Vec<Option<Vec<u8>>> = try_join_all(child_proofs).await?;
        let mut final_child_proofs: Vec<Vec<u8>> = Vec::with_capacity(res.len());

        for item in res {
            if let Some(proof) = item {
                final_child_proofs.push(proof);
            } else {
                anyhow::bail!("missing child proof for job id");
            }
        }

        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id)
            .await?;

        let children_reward_tree_values = {
            if work_item.metadata.dependencies.len() == 0 || work_item.metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                vec![]
            } else {
                let mut values = Vec::with_capacity(work_item.metadata.dependencies.len());
                for dependency in work_item.metadata.dependencies.iter() {
                    let value: N::QHash = self
                        .temp_db
                        .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, *dependency)
                        .await?;
                    values.push(value);
                }
                values
            }
        };
        let response = PsyWorkerGetProvingWorkAPIResponse {
            job: work_item,
            child_proof_tag_values: children_reward_tree_values,
            witness: witness_bytes,
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            node_type: PROVING_JOB_NODE_TYPE_REALM,
        };
        self.temp_db
            .set_proving_job_metadata(&self.realm_identifier, unique_pending_id, response.job.job_id, &response.job.metadata)
            .await?;

        // HACK: in the future we should create a new table for the expected proving
        // tag, but for now this ok i guess, but a HACK HACK: for now we set
        // self.temp_db.set_proof_miner_rewards_tree_value( with the expected proving
        // tag and then update it later to the actual value once the proof is submitted
        // this ensures the right person submits the proof AND the proof can only be
        // submitted once
        self.temp_db
            .set_proof_miner_rewards_tree_value(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id,
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;

        Ok(PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: response,
            input_proofs: final_child_proofs,
        })
    }
    pub async fn submit_proof_raw_internal(
        &self,
        job_id: N::JobId,
        tag: N::QHash,
        proof_bytes: Vec<u8>,
    ) -> anyhow::Result<()> {
        let (unique_pending_id, unique_proc_id) = self.get_current_gathering_unique_pending_id_internal().await?;

        //HACK: check to make sure the tag matches
        if self
            .temp_db
            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id)
            .await?
            != tag
        {
            anyhow::bail!("Submitted tag does not match expected tag for job id");
        }

        let metadata: PsyProvingJobMetadata<N::QHash, N::JobId> = self
            .temp_db
            .get_proving_job_metadata(&self.realm_identifier, unique_pending_id, job_id)
            .await?;

        let children_reward_tree_values = {
            if metadata.dependencies.len() == 0 || metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                vec![]
            } else {
                let mut values = Vec::with_capacity(metadata.dependencies.len());
                for dependency in metadata.dependencies.iter() {
                    let value: N::QHash = self
                        .temp_db
                        .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, *dependency)
                        .await?;
                    values.push(value);
                }
                values
            }
        };

        let reward_tree_value = metadata.get_new_rewards_tag_tree_value::<N::HasherBase>(tag, &children_reward_tree_values)?;

        let full_expected_public_inputs_hash = N::HasherBase::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value);

        self.proof_verifier.verify_zk_proof_from_slice_check_public_inputs_hash(
            job_id.circuit_type.to_u8() as u32,
            &proof_bytes,
            full_expected_public_inputs_hash,
        )?;

        // HACK: now set the correct reward tree value
        self.temp_db
            .set_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id, reward_tree_value)
            .await?;
        if self
            .temp_db
            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id)
            .await?
            != reward_tree_value
        {
            anyhow::bail!("Failed to set rewards tree value for job id");
        }

        self.proof_store.put_proof_bytes_for_job_id(job_id, &proof_bytes).await?;


        /*
        self.tag_tree_rewards_store
            .rewards_tag_tree_set_node_tag(unique_pending_id, metadata.get_reward_tree_node_key(), tag, reward_tree_value)
            .await?;

        // now update the tag tree

        if metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_3_CHILDREN_DOUBLE_REWARD {
            // special case for 3 children
            if metadata.dependencies.len() != 3 || children_reward_tree_values.len() != 3 {
                anyhow::bail!(
                    "Expected 3 children for 3-children double reward hash mode, got {}",
                    metadata.dependencies.len()
                );
            }
            let zero = N::QHash::get_zero_value();

            let left_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&children_reward_tree_values[0], &children_reward_tree_values[1], &tag);
            let right_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&children_reward_tree_values[2], &zero, &tag);
            let top_value = hash_tag_tree_node::<N::QHash, N::HasherBase>(&left_value, &right_value, &tag);
            if top_value != reward_tree_value {
                anyhow::bail!("Computed top value does not match reward tree value for 3-children double reward hash mode");
            }
            let self_key = metadata.get_reward_tree_node_key();
            let left_key = self_key.left_child();
            let right_key = self_key.right_child();
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, left_key, tag, left_value)
                .await?;
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, right_key, tag, right_value)
                .await?;
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, self_key, tag, top_value)
                .await?;
        } else if metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_LIFT_CHILD {
            // do nothing
        } else {
            let self_key = metadata.get_reward_tree_node_key();
            self.tag_tree_rewards_store
                .rewards_tag_tree_set_node_tag(unique_pending_id, self_key, tag, reward_tree_value)
                .await?;
        }
        */
        {
            let expected_updates = metadata.get_new_rewards_tag_tree_updates::<N::HasherBase>(tag, &children_reward_tree_values, reward_tree_value)?;

            for (key, node) in expected_updates {
                self.tag_tree_rewards_store
                    .rewards_tag_tree_set_node_tag(unique_pending_id, key, node.tag, node.value)
                    .await?;
            }
        }

        // ack the queue item as completed
        let queue_key = RealmProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };

        let item = PsyProvingJobMetadataWithJobId {
            job_id: job_id,
            metadata,
        };
        self.get_proof_work_queue
            .worker_queue_report_job_completed(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, unique_proc_id, 0, &item)
            .await?;

        Ok(())
    }
    */
}
