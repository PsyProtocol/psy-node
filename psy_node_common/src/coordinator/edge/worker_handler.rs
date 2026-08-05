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
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::QStandardWorkerQueueSubscriber},
    store::traits::proof_store::QParthProofStore,
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use parth_core::crypto::secp256k1::REQUEST_TYPE_SUBMIT_PROOF;

use crate::{
    reputation::WorkerReputationOps,
    coordinator::{
        edge::handler::{CoordinatorEdgeHandler, CoordinatorMutatingEdgeOperation},
        queue_key::CoordinatorProvingWorkQueueKey,
    },
};
fn verify_api_signature(signature: &QEDCompressedSecp256K1Signature, request: &SimpleTimedRequest) -> bool {
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

    pub async fn get_proving_work_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkAPIResponse<N::QHash, N::JobId>> {
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::GetProvingWork,
        )
        .await?;
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
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::GetProvingWork,
        )
        .await?;
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
        Ok(response)
    }
    pub async fn get_proving_work_with_child_proofs_internal(
        &self,
        signature: QEDCompressedSecp256K1Signature,
        request: SimpleTimedRequest,
    ) -> anyhow::Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<N::QHash, N::JobId>> {
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::GetProvingWorkWithChildProofs,
        )
        .await?;
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
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::GetProvingWorkWithChildProofs,
        )
        .await?;
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
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::SubmitProofRaw,
        )
        .await?;
        if !verify_api_signature(&signature, &request) || request.request_type != REQUEST_TYPE_SUBMIT_PROOF {
            anyhow::bail!("invalid signature for submit_proof_raw");
        }
        job_id = job_id.get_output_id();
        let (current_unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;
        let (unique_pending_id, job_claim) = self
            .resolve_unique_pending_id_for_submitted_job(current_unique_pending_id, job_id)
            .await?;
        let proof_bytes = Arc::new(proof_bytes);

        // HACK: check to make sure the tag matches. If not, job was completed by another worker (stolen) - slash submitter.
        // The expected tag is read from the dedicated claim-tag key namespace, not the
        // finalized reward-tree value key, so it can never observe a finalized reward value.
        let expected_tag = self
            .temp_db
            .get_proof_claim_tag(&self.realm_identifier, unique_pending_id, job_id.get_input_witness_id())
            .await?;
        if expected_tag != tag {
            self.require_mutating_service_available_internal(
                CoordinatorMutatingEdgeOperation::SubmitProofRaw,
            )
            .await?;
            self.temp_db
                .apply_reputation_slash_on_tag_mismatch(&self.realm_identifier, &signature.public_key)
                .await?;
            anyhow::bail!("Submitted tag does not match expected tag for job id");
        }

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

        // Complete proof validation before the final maintenance check. Once
        // this boundary is passed, finish the existing multi-store submission
        // sequence so a mid-sequence rejection cannot create a new partial
        // proof record.
        self.require_mutating_service_available_internal(
            CoordinatorMutatingEdgeOperation::SubmitProofRaw,
        )
        .await?;

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
            .put_proof_bytes_for_job_id(job_id.get_output_id(), unique_pending_id, &proof_bytes)
            .await?;

        let job_duration_ms = job_claim.as_ref().map(|(_, claim_time_ms)| {
            (chrono::Utc::now().timestamp_millis() as u64).saturating_sub(*claim_time_ms)
        });
        if let Some((public_key, claim_time_ms)) = job_claim.as_ref() {
            self.temp_db
                .apply_reputation_on_submit(&self.realm_identifier, public_key, *claim_time_ms)
                .await?;
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
                    "failed to record coordinator proof job statistics"
                );
            }
        }

        Ok(())
    }
}
