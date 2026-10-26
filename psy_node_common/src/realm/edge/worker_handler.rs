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

const SUBMIT_PROOF_PENDING_LOOKBACK: u64 = 256;

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
    async fn resolve_unique_pending_id_for_submitted_job(
        &self,
        current_unique_pending_id: u64,
        job_id: N::JobId,
    ) -> anyhow::Result<(u64, Option<([u8; 33], u64)>)> {
        for offset in 0..=SUBMIT_PROOF_PENDING_LOOKBACK {
            let candidate = current_unique_pending_id.saturating_sub(offset);
            if let Some(claim) = self
                .temp_db
                .get_job_claim(&self.realm_identifier, candidate, job_id)
                .await?
            {
                if candidate != current_unique_pending_id {
                    tracing::warn!(
                        "submit_proof_raw resolved job {:?} from historical unique_pending_id {} (current={})",
                        job_id,
                        candidate,
                        current_unique_pending_id
                    );
                }
                return Ok((candidate, Some(claim)));
            }
            if candidate == 0 {
                break;
            }
        }

        tracing::warn!(
            "submit_proof_raw found no claim record for job {:?} within lookback window; falling back to current unique_pending_id {}",
            job_id,
            current_unique_pending_id
        );
        Ok((current_unique_pending_id, None))
    }

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
    /// Legacy compatibility path; the in-tree worker does not call it.
    ///
    /// This path currently does not create the claim records consumed by
    /// `submit_proof_raw_internal`. New callers must use
    /// `get_proving_work_with_child_proofs_internal` instead.
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
            .map(|id| self.proof_store.get_proof_bytes_by_job_id(id.get_output_id(), unique_pending_id))
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

        // Store the worker's claim tag under the dedicated claim-tag key namespace
        // (TEMP_TABLE_ID_PROOF_CLAIM_TAG), which is distinct from the finalized reward-tree
        // value key (TEMP_TABLE_ID_TAG_TREE_VALUES). Input/output JobId alone does not
        // guarantee separation, since a job's output id can equal another job's input
        // witness id across the dependency graph; the distinct table-id prefix does.
        self.temp_db
            .set_proof_claim_tag(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_input_witness_id(),
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;
        timer.lap_micros("set_proof_claim_tag");
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
        let (current_unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;
        let (unique_pending_id, job_claim) = self
            .resolve_unique_pending_id_for_submitted_job(current_unique_pending_id, job_id)
            .await?;
        timer.lap_micros("get_current_unique_pending_id_internal");
        let proof_bytes = Arc::new(proof_bytes);

        // HACK: check to make sure the tag matches. If not, job was completed by another worker (stolen) - slash submitter.
        // The expected tag is read from the dedicated claim-tag key namespace, not the
        // finalized reward-tree value key, so it can never observe a finalized reward value.
        let expected_tag = self
            .temp_db
            .get_proof_claim_tag(&self.realm_identifier, unique_pending_id, job_id.get_input_witness_id())
            .await?;
        if expected_tag != tag {
            self.temp_db
                .apply_reputation_slash_on_tag_mismatch(&self.realm_identifier, &signature.public_key)
                .await?;
            anyhow::bail!("Submitted tag does not match expected tag for job id");
        }
        timer.lap_micros("get_proof_claim_tag");

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
        self.proof_store
            .put_proof_bytes_for_job_id(job_id.get_output_id(), unique_pending_id, &proof_bytes)
            .await?;
        timer.lap_micros("put_proof_bytes_for_job_id");

        let job_duration_ms = job_claim.as_ref().map(|(_, claim_time_ms)| {
            (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(*claim_time_ms)
        });
        if let Some((public_key, claim_time_ms)) = job_claim.as_ref() {
            self.temp_db
                .apply_reputation_on_submit(&self.realm_identifier, public_key, *claim_time_ms)
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

        if let Some(duration_ms) = job_duration_ms {
            if let Err(error) = self
                .temp_db
                .increment_job_stats(&self.realm_identifier, unique_pending_id, duration_ms)
                .await
            {
                tracing::warn!(
                    checkpoint_unique_pending_id = unique_pending_id,
                    duration_ms,
                    ?job_id,
                    %error,
                    "failed to record realm proof job statistics"
                );
            }
        }

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
            .map(|id| self.proof_store.get_proof_bytes_by_job_id(*id, unique_pending_id))
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

        self.proof_store
            .put_proof_bytes_for_job_id(job_id, unique_pending_id, &proof_bytes)
            .await?;


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

#[cfg(test)]
mod signature_tests {
    use parth_common::secp256k1::MemorySecp256K1Wallet;
    use parth_core::{
        crypto::secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest},
        data::hash::hash256::Hash256,
    };

    use super::verify_api_signature;


    #[test]
    fn accepts_genuine_signature_and_rejects_tampering() -> anyhow::Result<()> {
        let mut wallet = MemorySecp256K1Wallet::new();
        let public_key = wallet.add_private_key(Hash256([7u8; 32]))?;
        let (signature, request) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<
            MemorySecp256K1Wallet,
            parth_crypto::hash::sha256::CoreSha256Hasher,
        >(&wallet, &public_key, 60_000, [9u8; 32]);

        // a genuinely signed request verifies
        assert!(verify_api_signature(&signature, &request));

        // the same signature over a different request fails the message check
        let tampered = SimpleTimedRequest {
            for_target: request.for_target,
            request_type: request.request_type,
            valid_until: request.valid_until,
            nonce: request.nonce + 1,
            tag: request.tag,
        };
        assert!(!verify_api_signature(&signature, &tampered));

        // a corrupted signature fails secp256k1 verification
        let mut corrupted_signature = signature.signature;
        corrupted_signature[0] ^= 0xFF;
        let bad_signature = QEDCompressedSecp256K1Signature {
            public_key: signature.public_key,
            signature: corrupted_signature,
            message: signature.message,
        };
        assert!(!verify_api_signature(&bad_signature, &request));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::realm::edge::handler::tests::{
        zh, RealmEdgeTestEnv, StandardEnv, TEST_REALM_ID, TEST_REALM_SUB_ID, REALM_USER_ID,
    };
    use crate::test_common::TestZKVerifier;
    use parth_core::{
        crypto::secp256k1::Secp256K1WalletProvider,
        data::queue::queue_key::PCoreQueueItemBase,
        protocol::core_types::QNetworkTreeConstants,
        PF, PHash,
    };
    use psy_api_core::worker::standard_worker_rpc::NodeEdgeWorkerRpcServer;
    use psy_data::worker::metadata::PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD;
    use psy_node_core::{
        psy_core_db::traits::full::PsyNodeCoreDatabaseUserStoreWriter,
        psy_temp_db::{
            QTempDBJobClaimInfoReader, QTempDBJobClaimInfoWriter, QTempDBJobStatsStore,
            QTempDBPendingIdWriter, QTempDBProofWitnessWriter, QTempDBProvingJobMetadataReader,
            QTempDBProvingJobMetadataWriter, QTempDBRewardsTreeReader, QTempDBRewardsTreeWriter,
            QTempDBWorkerReputationWriter,
        },
        store::traits::proof_store::{QParthProofStoreReader, QParthProofStoreWriter},
    };

    /// Deterministic secp256k1 wallet whose signatures satisfy the miner API
    /// signature checks in the handler.
    struct TestWallet {
        wallet: parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet,
    }

    impl TestWallet {
        fn new() -> anyhow::Result<Self> {
            Ok(Self {
                wallet: parth_common::secp256k1::MemorySecp256K1SinglePrivateKeyWallet::new_from_private_key_bytes(&[7u8; 32])?,
            })
        }
        fn public_key(&self) -> [u8; 33] {
            self.wallet.get_public_key().0
        }
        fn submit_request(&self) -> anyhow::Result<(QEDCompressedSecp256K1Signature, SimpleTimedRequest)> {
            let request = SimpleTimedRequest {
                for_target: 0,
                request_type: REQUEST_TYPE_SUBMIT_PROOF,
                valid_until: parth_core::crypto::secp256k1::get_current_time_ms() + 60_000,
                nonce: 1,
                tag: [0u8; 32],
            };
            let sig_hash = request.get_sig_hash::<parth_crypto::hash::sha256::CoreSha256Hasher>();
            let signature = self.wallet.sign(&self.wallet.get_public_key(), sig_hash)?;
            Ok((signature, request))
        }
    }

    fn leaf_metadata() -> PsyProvingJobMetadata<PHash, QProvingJobDataID> {
        PsyProvingJobMetadata {
            expected_public_inputs_hash: PHash::from_values(31, 0, 0, 0),
            reward_tree_node_index: 0,
            reward_tree_node_level: 3,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN,
            reward_tree_node_children: 0,
            dependencies: vec![],
        }
    }

    /// Metadata with one rollup dependency; rollup children contribute the zero
    /// reward-tree value without needing a seeded rewards value.
    fn dep_metadata(dependency: QProvingJobDataID) -> PsyProvingJobMetadata<PHash, QProvingJobDataID> {
        PsyProvingJobMetadata {
            expected_public_inputs_hash: PHash::from_values(32, 0, 0, 0),
            reward_tree_node_index: 0,
            reward_tree_node_level: 3,
            reward_tree_hash_mode: PROOF_REWARD_TREE_HASH_MODE_HASH_CHILDREN_STANDARD,
            reward_tree_node_children: 1,
            dependencies: vec![dependency],
        }
    }

    fn test_job_id(goal_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            goal_id,
            1,
            ProvingJobCircuitType::GUTASingleEndCap,
            0,
            goal_id as u32,
        )
    }

    fn rollup_job_id(goal_id: u64) -> QProvingJobDataID {
        QProvingJobDataID::new_proof_job_id(
            goal_id,
            2,
            ProvingJobCircuitType::GenerateRollupStateTransitionProof,
            0,
            goal_id as u32,
        )
    }

    async fn standard_env() -> anyhow::Result<StandardEnv> {
        RealmEdgeTestEnv::<crate::test_common::TestNetworkConfig>::create(Arc::new(TestZKVerifier {})).await
    }

    #[tokio::test]
    async fn signature_and_reputation_gate_worker_access() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;

        // signature from a different key over the same request is rejected
        let mut bad_signature = signature.clone();
        bad_signature.signature = [9u8; 64];
        let err = handler
            .verify_miner_api_signature_and_check_reputation(&bad_signature, &request)
            .await
            .expect_err("invalid signature must be rejected");
        assert!(err.to_string().contains("invalid signature"), "unexpected error: {err}");

        // valid signature but zero reputation is rejected; a fresh wallet
        // defaults to INITIAL_WORKER_REPUTATION = 5, so seed 0 explicitly
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 0)
            .await?;
        let err = handler
            .verify_miner_api_signature_and_check_reputation(&signature, &request)
            .await
            .expect_err("zero reputation must be rejected");
        assert!(err.to_string().contains("reputation must be positive"), "unexpected error: {err}");

        // positive reputation passes
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;
        handler.verify_miner_api_signature_and_check_reputation(&signature, &request).await?;
        assert_eq!(handler.get_worker_reputation_internal(&wallet.public_key()).await?, 5);
        Ok(())
    }

    #[tokio::test]
    async fn job_submission_status_tracks_rewards_tree_value() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let job_id = test_job_id(101);

        // fresh pending counters read back at zero
        assert_eq!(handler.get_current_unique_pending_id_internal().await?, (0, 0));
        assert_eq!(handler.get_current_gathering_unique_pending_id_internal().await?, (0, 0));

        assert!(!handler.has_job_id_already_been_submitted(0, job_id).await?);
        // the dedicated status probe always reports not-submitted
        assert!(!handler.get_job_id_submission_status(0, &job_id).await?);

        // finalizing the rewards tree value marks the job as submitted
        env.temp_db
            .set_proof_miner_rewards_tree_value(&handler.realm_identifier, 0, job_id, PHash::from_values(41, 0, 0, 0))
            .await?;
        assert!(handler.has_job_id_already_been_submitted(0, job_id).await?);

        // advancing the pending id does not leak the old flag to the new id
        env.temp_db.set_unique_pending_ids(&handler.realm_identifier, 5, 5).await?;
        assert!(!handler.has_job_id_already_been_submitted(5, job_id).await?);
        assert_eq!(handler.get_current_unique_pending_id_internal().await?, (5, 5));
        Ok(())
    }

    #[tokio::test]
    async fn get_proving_work_returns_next_queue_item() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        // empty queue: no work available
        let err = handler
            .get_proving_work_internal(signature.clone(), request.clone())
            .await
            .expect_err("empty work queue must fail");
        assert!(err.to_string().contains("no proving work available"), "unexpected error: {err}");

        // preload one leaf job without dependencies and its witness
        let work_item = PsyProvingJobMetadataWithJobId::<PHash, QProvingJobDataID> {
            job_id: test_job_id(202),
            metadata: leaf_metadata(),
        };
        let witness = vec![1u8; 16];
        env.temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(
                &handler.realm_identifier,
                0,
                vec![(work_item.job_id.get_input_witness_id(), witness.clone())],
            )
            .await?;
        env.work_queue.add_items(vec![work_item.encode_queue_item_vec()?]);

        let response = NodeEdgeWorkerRpcServer::get_proving_work(handler, signature, request).await?;
        assert_eq!(response.realm_id, TEST_REALM_ID);
        assert_eq!(response.realm_sub_id, TEST_REALM_SUB_ID);
        assert_eq!(response.unique_pending_id, 0);
        assert_eq!(response.node_type, PROVING_JOB_NODE_TYPE_REALM);
        assert_eq!(response.witness, witness);
        assert!(response.child_proof_tag_values.is_empty());
        assert_eq!(response.job.job_id.goal_id, 202);
        assert_eq!(response.job.metadata.expected_public_inputs_hash, PHash::from_values(31, 0, 0, 0));
        Ok(())
    }

    #[tokio::test]
    async fn get_proving_work_with_child_proofs_requires_dependency_proofs() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        // a job whose dependency proof is not in the proof store must fail
        let dependency = rollup_job_id(301);
        let work_item = PsyProvingJobMetadataWithJobId::<PHash, QProvingJobDataID> {
            job_id: test_job_id(302),
            metadata: dep_metadata(dependency),
        };
        env.work_queue.add_items(vec![work_item.encode_queue_item_vec()?]);

        let err = handler
            .get_proving_work_with_child_proofs_internal(signature, request)
            .await
            .expect_err("missing dependency proof must fail");
        assert!(err.to_string().contains("missing child proof for job id"), "unexpected error: {err}");
        Ok(())
    }

    #[tokio::test]
    async fn get_proving_work_with_child_proofs_records_claim() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        let dependency = rollup_job_id(311);
        let work_item = PsyProvingJobMetadataWithJobId::<PHash, QProvingJobDataID> {
            job_id: test_job_id(312),
            metadata: dep_metadata(dependency),
        };
        let witness = vec![7u8; 24];
        env.temp_db
            .set_tdb_proof_witnesses_tuple_owned_raw(
                &handler.realm_identifier,
                0,
                vec![(work_item.job_id.get_input_witness_id(), witness.clone())],
            )
            .await?;
        // the dependency's proof is already finalized in the proof store
        let dep_proof = vec![9u8; 40];
        env.temp_db
            .put_proof_bytes_for_job_id(dependency.get_output_id(), 0, &dep_proof)
            .await?;
        env.work_queue.add_items(vec![work_item.encode_queue_item_vec()?]);

        let response = handler
            .get_proving_work_with_child_proofs_internal(signature, request.clone())
            .await?;
        // the child proof is served alongside the job
        assert_eq!(response.input_proofs, vec![dep_proof]);
        assert_eq!(response.base.witness, witness);
        assert_eq!(response.base.node_type, PROVING_JOB_NODE_TYPE_REALM);
        // the rollup dependency contributes the zero reward-tree value
        assert_eq!(response.base.child_proof_tag_values, vec![PHash::get_zero_value()]);

        // the handler recorded the job metadata, claim tag and job claim
        let rid = &handler.realm_identifier;
        let metadata: PsyProvingJobMetadata<PHash, QProvingJobDataID> = env
            .temp_db
            .get_proving_job_metadata(rid, 0, work_item.job_id.get_output_id())
            .await?;
        assert_eq!(metadata.expected_public_inputs_hash, PHash::from_values(32, 0, 0, 0));
        assert_eq!(metadata.dependencies.len(), 1);
        let claim_tag: PHash = env
            .temp_db
            .get_proof_claim_tag(rid, 0, work_item.job_id.get_input_witness_id())
            .await?;
        assert_eq!(claim_tag, PHash::from_ref_32bytes(&request.tag));
        let job_claim = env
            .temp_db
            .get_job_claim(rid, 0, work_item.job_id.get_output_id())
            .await?
            .expect("job claim must be recorded");
        assert_eq!(job_claim.0, wallet.public_key());
        Ok(())
    }

    #[tokio::test]
    async fn submit_proof_raw_rejects_wrong_request_type_and_mismatched_tag() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;
        let job_id = test_job_id(401);
        let tag = PHash::from_values(55, 0, 0, 0);

        // wrong request type is rejected even though the signature is genuine
        let mut wrong_type_req = request.clone();
        wrong_type_req.request_type = REQUEST_TYPE_SUBMIT_PROOF + 1;
        let mut wrong_type_sig = signature.clone();
        wrong_type_sig.message = wrong_type_req.get_sig_hash::<parth_crypto::hash::sha256::CoreSha256Hasher>();
        let err = handler
            .submit_proof_raw_internal(wrong_type_sig, wrong_type_req, job_id, tag, vec![])
            .await
            .expect_err("wrong request type must fail");
        assert!(err.to_string().contains("invalid signature for submit_proof_raw"), "unexpected error: {err}");

        // seed a different expected claim tag: the submitted tag cannot match,
        // so the worker's reputation is slashed
        let output_id = job_id.get_output_id();
        env.temp_db
            .set_proof_claim_tag(&handler.realm_identifier, 0, output_id.get_input_witness_id(), PHash::from_values(56, 0, 0, 0))
            .await?;
        let err = handler
            .submit_proof_raw_internal(signature, request, job_id, tag, vec![])
            .await
            .expect_err("tag mismatch must fail");
        assert!(err.to_string().contains("does not match expected tag"), "unexpected error: {err}");
        // DEFAULT_REPUTATION_SLASH = 5 saturates the seeded 5 down to 0
        assert_eq!(handler.get_worker_reputation_internal(&wallet.public_key()).await?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn submit_proof_raw_happy_path_finalizes_job() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        let (signature, request) = wallet.submit_request()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        let job_id = test_job_id(501);
        // submit_proof_raw_internal rewrites the submitted id to its output id
        // FIRST and resolves the claim/tag/metadata under that id
        let output_id = job_id.get_output_id();
        let tag = PHash::from_values(55, 0, 0, 0);
        let metadata = leaf_metadata();

        // seed the claim tag, job metadata and the claim record for the worker
        env.temp_db
            .set_proof_claim_tag(&handler.realm_identifier, 0, output_id.get_input_witness_id(), tag)
            .await?;
        env.temp_db
            .set_proving_job_metadata(&handler.realm_identifier, 0, output_id.get_output_id(), &metadata)
            .await?;
        env.temp_db
            .set_job_claim(&handler.realm_identifier, 0, output_id, &wallet.public_key(), parth_core::crypto::secp256k1::get_current_time_ms())
            .await?;

        let proof_bytes = vec![1u8, 2, 3];
        NodeEdgeWorkerRpcServer::submit_proof_raw(handler, signature, request, job_id, tag, proof_bytes.clone()).await?;

        // the reward tree value is finalized (keyed by the output id), marking
        // the job as submitted
        assert!(handler.has_job_id_already_been_submitted(0, output_id).await?);
        // the proof bytes are stored under the job's output id
        assert!(env.temp_db.contains_proof_for_job_id(output_id.get_output_id(), 0).await?);
        // the on-time claim bumped the worker reputation
        assert_eq!(handler.get_worker_reputation_internal(&wallet.public_key()).await?, 6);
        // the completed job recorded a duration sample
        let stats = env
            .temp_db
            .get_job_stats(&handler.realm_identifier, 0)
            .await?
            .expect("job stats must be recorded");
        assert_eq!(stats.total_completed, 1);
        Ok(())
    }

    #[tokio::test]
    async fn submit_proof_resolves_historical_pending_ids_within_lookback() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        let job_id = test_job_id(601);
        let output_id = job_id.get_output_id();

        // with no claim anywhere the resolver falls back to the current id
        assert_eq!(handler.resolve_unique_pending_id_for_submitted_job(0, output_id).await?, (0, None));

        // seed the full claim triple under pending id 0
        let tag = PHash::from_values(66, 0, 0, 0);
        env.temp_db
            .set_proof_claim_tag(&handler.realm_identifier, 0, output_id.get_input_witness_id(), tag)
            .await?;
        env.temp_db
            .set_proving_job_metadata(&handler.realm_identifier, 0, output_id.get_output_id(), &leaf_metadata())
            .await?;
        let claim_time = parth_core::crypto::secp256k1::get_current_time_ms();
        env.temp_db
            .set_job_claim(&handler.realm_identifier, 0, output_id, &wallet.public_key(), claim_time)
            .await?;

        // from a later pending id the claim is still resolved historically
        let (resolved, claim) = handler.resolve_unique_pending_id_for_submitted_job(5, output_id).await?;
        assert_eq!(resolved, 0);
        assert_eq!(claim.expect("claim must be found").0, wallet.public_key());

        // beyond the 256-id lookback window the resolver falls back again
        let (resolved, claim) = handler.resolve_unique_pending_id_for_submitted_job(300, output_id).await?;
        assert_eq!(resolved, 300);
        assert!(claim.is_none());

        // a full submission still succeeds against the historical pending id
        env.temp_db.set_unique_pending_ids(&handler.realm_identifier, 5, 5).await?;
        let (signature, request) = wallet.submit_request()?;
        handler
            .submit_proof_raw_internal(signature, request, job_id, tag, vec![4u8, 5])
            .await?;
        assert!(handler.has_job_id_already_been_submitted(0, output_id).await?);
        assert_eq!(handler.get_worker_reputation_internal(&wallet.public_key()).await?, 6);
        Ok(())
    }

    #[tokio::test]
    async fn user_leaf_accessors_fallback_and_batch_gates() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;

        // a user with no committed leaf gets the deterministic fallback leaf
        let fallback = handler.get_user_leaf_data_internal(0, REALM_USER_ID).await?;
        assert_eq!(fallback.public_key, PHash::get_zero_value());
        assert_eq!(fallback.user_state_tree_root, zh(crate::test_common::TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE));
        assert_eq!(fallback.user_id, PF::from_u64_value(REALM_USER_ID));
        assert!(fallback.is_first_transaction_old_user_leaf());

        // once a leaf is committed the same accessor serves it
        let seeded = PQEDUserLeaf {
            public_key: PHash::from_values(77, 0, 0, 0),
            user_state_tree_root: zh(crate::test_common::TestNetworkConfig::GLOBAL_CONTRACT_TREE_HEIGHT_USIZE),
            balance: PF::from_u64_value(42),
            nonce: PF::from_u64_value(3),
            last_checkpoint_id: PF::ZERO_VALUE,
            event_index: PF::ZERO_VALUE,
            user_id: PF::from_u64_value(REALM_USER_ID),
        };
        env.db.set_user_leaf(0, &seeded).await?;
        let read_back = handler.get_user_leaf_data_internal(0, REALM_USER_ID).await?;
        assert_eq!(read_back.public_key, seeded.public_key);
        assert_eq!(read_back.balance, seeded.balance);
        assert_eq!(read_back.nonce, seeded.nonce);

        // batch accessors validate the id list
        let err = handler
            .get_user_leaves_data_internal(0, &[])
            .await
            .expect_err("empty user id list must fail");
        assert!(err.to_string().contains("user_ids cannot be empty"), "unexpected error: {err}");
        let too_many = vec![REALM_USER_ID; 10001];
        let err = handler
            .get_user_leaves_data_internal(0, &too_many)
            .await
            .expect_err("oversized user id list must fail");
        assert!(err.to_string().contains("greater than 10000"), "unexpected error: {err}");

        // a mixed batch substitutes the fallback leaf for missing users
        let missing_id = REALM_USER_ID + 1;
        let batch = handler.get_user_leaves_data_internal(0, &[missing_id, REALM_USER_ID]).await?;
        assert_eq!(batch.len(), 2);
        assert_eq!(batch[0].user_id, PF::from_u64_value(missing_id));
        assert_eq!(batch[0].public_key, PHash::get_zero_value());
        assert_eq!(batch[1].balance, seeded.balance);
        Ok(())
    }

    #[tokio::test]
    async fn rpc_worker_wrappers_validate_public_key_and_serve_state() -> anyhow::Result<()> {
        let env = standard_env().await?;
        let handler = &env.handler;
        let wallet = TestWallet::new()?;
        env.temp_db
            .set_worker_reputation(&handler.realm_identifier, &wallet.public_key(), 5)
            .await?;

        // the reputation RPC demands a 33-byte compressed public key
        let err = NodeEdgeWorkerRpcServer::get_worker_reputation(handler, vec![0u8; 32])
            .await
            .expect_err("short public key must fail");
        assert!(err.to_string().contains("public_key must be 33 bytes"), "unexpected error: {err}");
        assert_eq!(
            NodeEdgeWorkerRpcServer::get_worker_reputation(handler, wallet.public_key().to_vec()).await?,
            5
        );

        // the worker API serves this node's realm identifier
        let rid = NodeEdgeWorkerRpcServer::get_realm_identifier_worker_api(handler).await?;
        assert_eq!(rid.realm_id as u64, TEST_REALM_ID);
        assert_eq!(rid.realm_sub_id as u64, TEST_REALM_SUB_ID);

        // a fresh node reports the default (all-zero) proving state
        let state = NodeEdgeWorkerRpcServer::get_node_proving_state(handler).await?;
        assert_eq!(state.realm_id, 0);
        assert_eq!(state.unique_pending_id, 0);
        assert_eq!(state.last_committed_checkpoint_id, 0);
        Ok(())
    }
}
