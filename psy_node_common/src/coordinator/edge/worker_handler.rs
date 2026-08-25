use futures::future::try_join_all;
use std::sync::Arc;
use tokio::task;
use parth_core::{
    crypto::{
        hash::{tag_tree::hash_tag_tree_node_single, traits::{MerkleHasher, ZeroableHash}},
        secp256k1::{QEDCompressedSecp256K1Signature, Secp256K1Verifier, SimpleTimedRequest},
    },
    data::queue::queue_key::QPBaseQueueType,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofPublicInputsHasherReader, QZKProofVerifier},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    protocol::circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput,
    worker::{
        api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse, PROVING_JOB_NODE_TYPE_COORDINATOR},
        metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
    },
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyCoordinatorEdgeAPIStoreReader, PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter},
    psy_temp_db::{StandardEdgeAPITempDBStoreBase, WorkerJobClaim},
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use parth_core::crypto::secp256k1::{
    get_current_time_ms, REQUEST_TYPE_REQUEST_PROOF_WORK, REQUEST_TYPE_SUBMIT_PROOF,
};

use crate::{
    coordinator::{edge::handler::CoordinatorEdgeHandler, queue_key::CoordinatorProvingWorkQueueKey},
    reputation::WorkerReputationOps,
};

pub(crate) fn validate_worker_request_boundary(
    signature_is_valid: bool,
    valid_until: u64,
    current_time: u64,
    for_target: u64,
    request_type: u64,
    expected_request_type: u64,
) -> anyhow::Result<()> {
    if !signature_is_valid {
        anyhow::bail!("invalid worker signature");
    }
    if valid_until < current_time {
        anyhow::bail!("worker request has expired");
    }
    if for_target != 0 {
        anyhow::bail!("unexpected worker request target");
    }
    if request_type != expected_request_type {
        anyhow::bail!("unexpected worker request type");
    }
    Ok(())
}

pub(crate) fn validate_whitelist_membership(is_whitelisted: bool) -> anyhow::Result<()> {
    if !is_whitelisted {
        anyhow::bail!("worker public key is not whitelisted");
    }
    Ok(())
}

pub(crate) fn validate_positive_reputation(reputation: u64) -> anyhow::Result<()> {
    if reputation == 0 {
        anyhow::bail!("worker not eligible: reputation must be positive");
    }
    Ok(())
}

pub(crate) fn validate_submit_claimant(
    stored_public_key: &[u8; 33],
    submitting_public_key: &[u8; 33],
) -> anyhow::Result<()> {
    if stored_public_key != submitting_public_key {
        anyhow::bail!("submitted proof is not owned by this worker");
    }
    Ok(())
}

pub(crate) fn validate_submit_tags(
    request_tag: &[u8; 32],
    rpc_tag: &[u8; 32],
    stored_claim_tag: &[u8; 32],
) -> anyhow::Result<()> {
    if request_tag != rpc_tag {
        anyhow::bail!("signed request tag does not match submitted tag");
    }
    if stored_claim_tag != rpc_tag {
        anyhow::bail!("submitted tag does not match stored claim tag");
    }
    Ok(())
}

pub(crate) fn verify_api_signature(signature: &QEDCompressedSecp256K1Signature, request: &SimpleTimedRequest) -> bool {
    request.get_sig_hash::<parth_crypto::hash::sha256::CoreSha256Hasher>() == signature.message
        && parth_common::secp256k1::Secp256K1VerifierHelper::secp256k1_verify(signature).is_ok()
}

const SUBMIT_PROOF_PENDING_LOOKBACK: u64 = 256;
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
        ProofStore: QParthProofStore,
    >
    CoordinatorEdgeHandler<
        N,
        S,
        STagTreeRewards,
        GUTAUpdateQueue,
        RegisterUserQueue,
        DeployContractQueue,
        GetProofWorkQueue,
        TempDatabase,
        ProofStore,
    >
{
    async fn load_dependency_proof_bytes(&self, unique_pending_id: u64, job_id: &N::JobId) -> anyhow::Result<Option<Vec<u8>>> {
        if let Some(proof) = self
            .proof_store
            .get_proof_bytes_by_job_id(job_id.get_output_id(), unique_pending_id)
            .await?
        {
            return Ok(Some(proof));
        }

        if job_id.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
            let transition = self
                .db_reader
                .get_verifiable_checkpoint_state_transition_and_zkp(job_id.goal_id)
                .await?;
            return Ok(Some(transition.zk_proof));
        }

        Ok(None)
    }

    async fn resolve_unique_pending_id_for_submitted_job(
        &self,
        current_unique_pending_id: u64,
        job_id: N::JobId,
    ) -> anyhow::Result<(u64, WorkerJobClaim)> {
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
                return Ok((candidate, claim));
            }
            if candidate == 0 {
                break;
            }
        }

        anyhow::bail!("no stored claim found for submitted job");
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
        expected_request_type: u64,
    ) -> anyhow::Result<u64> {
        validate_worker_request_boundary(
            verify_api_signature(signature, request),
            request.valid_until,
            get_current_time_ms(),
            request.for_target,
            request.request_type,
            expected_request_type,
        )?;
        validate_whitelist_membership(self.worker_whitelist.is_allowed(&signature.public_key)?)?;
        let reputation = self
            .temp_db
            .get_worker_reputation(&self.realm_identifier, &signature.public_key)
            .await?;
        validate_positive_reputation(reputation)?;
        Ok(reputation)
    }

    pub async fn get_worker_reputation_internal(&self, public_key: &[u8; 33]) -> anyhow::Result<u64> {
        self.temp_db.get_worker_reputation(&self.realm_identifier, public_key).await
    }

    pub async fn get_proving_work_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        let reputation = self
            .verify_miner_api_signature_and_check_reputation(&signature, &request, REQUEST_TYPE_REQUEST_PROOF_WORK)
            .await?;

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
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id.get_input_witness_id())
            .await?;

        let children_reward_tree_values = if work_item.metadata.dependencies.is_empty()
            || work_item.metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN
        {
            vec![]
        } else {
            let temp_db = self.temp_db.clone();
            let realm_identifier = self.realm_identifier.clone();
            let futures = work_item
                .metadata
                .dependencies
                .iter()
                .map(|dependency| {
                    let dep = dependency.clone();
                    let temp_db = temp_db.clone();
                    let realm_identifier = realm_identifier.clone();
                    async move {
                        if dep.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
                            Ok(N::QHash::get_zero_value())
                        } else {
                            temp_db
                                .get_proof_miner_rewards_tree_value(&realm_identifier, unique_pending_id, dep)
                                .await
                        }
                    }
                })
                .collect::<Vec<_>>();

            try_join_all(futures).await?
        };
        let response = PsyWorkerGetProvingWorkAPIResponse {
            job: work_item,
            child_proof_tag_values: children_reward_tree_values,
            witness: witness_bytes,
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_pending_id,
            node_type: PROVING_JOB_NODE_TYPE_COORDINATOR,
        };
        self.temp_db
            .set_proving_job_metadata(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                &response.job.metadata,
            )
            .await?;
        self.temp_db
            .set_proof_claim_tag(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_input_witness_id(),
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;
        self.temp_db
            .record_job_claim(
                self.worker_reputation_update_lock.as_ref(),
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                WorkerJobClaim {
                    public_key: signature.public_key,
                    claim_time_ms: chrono::Utc::now().timestamp_millis() as u64,
                    proc_checkpoint_unique_id: unique_proc_id,
                    reputation_at_claim: reputation,
                    is_finalized: false,
                    has_reputation_update: false,
                },
            )
            .await?;

        Ok(response)
    }
    pub async fn get_proving_work_with_child_proofs_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        let reputation = self
            .verify_miner_api_signature_and_check_reputation(&signature, &request, REQUEST_TYPE_REQUEST_PROOF_WORK)
            .await?;

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
        tracing::info!("work item dependencies: {:?}", work_item.metadata.dependencies);
        let child_proofs = work_item
            .metadata
            .dependencies
            .iter()
            .map(|id| self.load_dependency_proof_bytes(unique_pending_id, id))
            .collect::<Vec<_>>()
            .into_iter();
        let res: Vec<Option<Vec<u8>>> = try_join_all(child_proofs).await?;
        let mut final_child_proofs: Vec<Vec<u8>> = Vec::with_capacity(res.len());

        for (index, item) in res.into_iter().enumerate() {
            if let Some(proof) = item {
                final_child_proofs.push(proof);
            } else {
                tracing::error!("missing dependency proof for job id: {:?}", work_item.metadata.dependencies[index]);
                anyhow::bail!("missing child proof for job id");
            }
        }

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
            node_type: PROVING_JOB_NODE_TYPE_COORDINATOR,
        };
        self.temp_db
            .set_proving_job_metadata(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                &response.job.metadata,
            )
            .await?;

        // Claim tags use a distinct key namespace from finalized reward values.
        self.temp_db
            .set_proof_claim_tag(
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_input_witness_id(),
                N::QHash::from_ref_32bytes(&request.tag),
            )
            .await?;

        let claim_time_ms = chrono::Utc::now().timestamp_millis() as u64;
        self.temp_db
            .record_job_claim(
                self.worker_reputation_update_lock.as_ref(),
                &self.realm_identifier,
                unique_pending_id,
                response.job.job_id.get_output_id(),
                WorkerJobClaim {
                    public_key: signature.public_key,
                    claim_time_ms,
                    proc_checkpoint_unique_id: unique_proc_id,
                    reputation_at_claim: reputation,
                    is_finalized: false,
                    has_reputation_update: false,
                },
            )
            .await?;

        Ok(PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: response,
            input_proofs: final_child_proofs,
        })
    }
    pub async fn get_root_state_transition_expected_public_inputs_hash_internal(
        &self,
        job_id: N::JobId,
        unique_pending_id: u64,
        new_reward_root: N::QHash,
    ) -> anyhow::Result<N::QHash> {
        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, job_id.get_input_witness_id())
            .await?;
        let witness: QCQEDCheckpointStateTransitionInput<N::F, N::QHash> =
            QCQEDCheckpointStateTransitionInput::<N::F, N::QHash>::psy_ser_from_owned_bytes_vec(witness_bytes)?;
        let expected_public_inputs_hash = witness.get_chain_hash_with_fingerprint_and_reward_root::<N::HasherBase>(
            witness.previous_chain_hash,
            self.checkpoint_state_transition_circuit_fingerprint,
            new_reward_root,
        );

        Ok(expected_public_inputs_hash)
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
        self.verify_miner_api_signature_and_check_reputation(&signature, &request, REQUEST_TYPE_SUBMIT_PROOF).await?;
        job_id = job_id.get_output_id();
        let (current_unique_pending_id, _) = self.get_current_unique_pending_id_internal().await?;
        let (unique_pending_id, mut claim) = self
            .resolve_unique_pending_id_for_submitted_job(current_unique_pending_id, job_id)
            .await?;
        if claim.is_finalized {
            anyhow::bail!("proof has already been submitted for this job");
        }
        validate_submit_claimant(&claim.public_key, &signature.public_key)?;
        let rpc_tag = tag.into_owned_32bytes();
        let expected_tag = self
            .temp_db
            .get_proof_claim_tag(&self.realm_identifier, unique_pending_id, job_id.get_input_witness_id())
            .await?;
        validate_submit_tags(&request.tag, &rpc_tag, &expected_tag.into_owned_32bytes())?;
        if self.has_job_id_already_been_submitted(unique_pending_id, job_id).await? {
            tracing::warn!(?job_id, unique_pending_id, "resuming an incomplete proof submission");
        }
        let proof_bytes = Arc::new(proof_bytes);

        let metadata: PsyProvingJobMetadata<N::QHash, N::JobId> = self
            .temp_db
            .get_proving_job_metadata(&self.realm_identifier, unique_pending_id, job_id.get_output_id())
            .await?;

        let children_reward_tree_values = {
            if metadata.dependencies.len() == 0 || metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
                vec![]
            } else {
                let mut values = Vec::with_capacity(metadata.dependencies.len());
                for dependency in metadata.dependencies.iter() {
                    let value: N::QHash = if dependency.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
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

        let reward_tree_value = metadata.get_new_rewards_tag_tree_value::<N::HasherBase>(tag, &children_reward_tree_values)?;

        let full_expected_public_inputs_hash = if job_id.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
            self.get_root_state_transition_expected_public_inputs_hash_internal(
                job_id,
                unique_pending_id,
                reward_tree_value,
            )
            .await?
        } else if job_id.circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition {
            metadata.expected_public_inputs_hash
        } else {
            N::HasherBase::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value)
        };


        tracing::info!(
            "Verifying proof for job id: {:?} with expected public inputs hash: {:?} (from metadata: {:?})",
            job_id,
            hex::encode(&full_expected_public_inputs_hash.into_owned_32bytes()),
            hex::encode(&metadata.expected_public_inputs_hash.into_owned_32bytes())
        );
        let debug_public_inputs = N::ZKVerifier::get_proof_public_inputs_hash(&N::ZKVerifier::try_proof_from_slice(&proof_bytes)?)?;
        tracing::info!(
            "Debug: extracted public inputs hash from proof: {:?}",
            hex::encode(&debug_public_inputs.into_owned_32bytes())
        );
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
            .put_proof_bytes_for_job_id(job_id.get_output_id(), unique_pending_id, &proof_bytes)
            .await?;

        let job_duration_ms = (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(claim.claim_time_ms);
        self.temp_db
            .apply_reputation_once(
                &self.realm_identifier,
                unique_pending_id,
                job_id,
                &mut claim,
            )
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
            let expected_updates =
                metadata.get_new_rewards_tag_tree_updates::<N::HasherBase>(tag, &children_reward_tree_values, reward_tree_value)?;

            for (key, node) in expected_updates {
                self.tag_tree_rewards_store
                    .rewards_tag_tree_set_node_tag(unique_pending_id, key, node.tag, node.value)
                    .await?;
            }
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
            }
        }

        // ack the queue item as completed
        let queue_key = CoordinatorProvingWorkQueueKey::<N::QHash, N::JobId> {
            realm_id: self.realm_id_u64,
            realm_sub_id: self.realm_sub_id_u64,
            unique_id: claim.proc_checkpoint_unique_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        };

        let item = PsyProvingJobMetadataWithJobId {
            job_id: job_id.get_output_id(),
            metadata,
        };
        let was_acknowledged = self.get_proof_work_queue
            .worker_queue_report_job_completed(&queue_key, self.realm_id_u64, self.realm_sub_id_u64, claim.proc_checkpoint_unique_id, 0, &item)
            .await?;
        if !was_acknowledged {
            anyhow::bail!("worker queue acknowledgement token not found for completed proof job");
        }
        claim.is_finalized = true;
        self.temp_db
            .set_job_claim(&self.realm_identifier, unique_pending_id, job_id, &claim)
            .await?;

        if let Err(error) = self
            .temp_db
            .increment_job_stats(&self.realm_identifier, unique_pending_id, job_duration_ms)
            .await
        {
            tracing::warn!(
                checkpoint_unique_pending_id = unique_pending_id,
                duration_ms = job_duration_ms,
                ?job_id,
                %error,
                "failed to record coordinator proof job statistics"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        validate_positive_reputation, validate_submit_claimant, validate_submit_tags,
        validate_whitelist_membership, validate_worker_request_boundary,
    };

    const CLAIM_TYPE: u64 = 1;

    #[test]
    fn worker_request_boundary_accepts_valid_admission() {
        assert!(validate_worker_request_boundary(true, 10, 10, 0, CLAIM_TYPE, CLAIM_TYPE).is_ok());
    }

    #[test]
    fn worker_request_boundary_rejects_invalid_signature() {
        assert!(validate_worker_request_boundary(false, 10, 10, 0, CLAIM_TYPE, CLAIM_TYPE).is_err());
    }

    #[test]
    fn worker_request_boundary_rejects_expired_request() {
        assert!(validate_worker_request_boundary(true, 9, 10, 0, CLAIM_TYPE, CLAIM_TYPE).is_err());
    }

    #[test]
    fn worker_request_boundary_rejects_wrong_request_type() {
        assert!(validate_worker_request_boundary(true, 10, 10, 0, 2, CLAIM_TYPE).is_err());
    }

    #[test]
    fn worker_request_boundary_rejects_wrong_target() {
        assert!(validate_worker_request_boundary(true, 10, 10, 1, CLAIM_TYPE, CLAIM_TYPE).is_err());
    }

    #[test]
    fn whitelist_membership_rejects_unlisted_worker() {
        assert!(validate_whitelist_membership(false).is_err());
    }

    #[test]
    fn reputation_rejects_zero() {
        assert!(validate_positive_reputation(0).is_err());
    }

    #[test]
    fn submit_claimant_must_match_signing_key() {
        assert!(validate_submit_claimant(&[1; 33], &[1; 33]).is_ok());
        assert!(validate_submit_claimant(&[1; 33], &[2; 33]).is_err());
    }

    #[test]
    fn submit_tags_must_match_signed_rpc_and_stored_values() {
        assert!(validate_submit_tags(&[1; 32], &[1; 32], &[1; 32]).is_ok());
        assert!(validate_submit_tags(&[2; 32], &[1; 32], &[1; 32]).is_err());
        assert!(validate_submit_tags(&[1; 32], &[1; 32], &[2; 32]).is_err());
    }
}
