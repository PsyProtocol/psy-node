use futures::future::try_join_all;
use std::sync::Arc;
use tokio::task;
use parth_core::{
    crypto::{
        hash::traits::{MerkleHasher, ZeroableHash},
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

use crate::coordinator::{edge::handler::CoordinatorEdgeHandler, queue_key::CoordinatorProvingWorkQueueKey};
fn verify_api_signature(signature: &QEDCompressedSecp256K1Signature, request: &SimpleTimedRequest) -> bool {
    request.get_sig_hash::<parth_crypto::hash::sha256::CoreSha256Hasher>() == signature.message
        && parth_common::secp256k1::Secp256K1VerifierHelper::secp256k1_verify(signature).is_ok()
}
fn print_hash<H: Q256BitHash + std::fmt::Debug>(label: &str, hash: &H) {
    tracing::info!("{}: {:?} ({})", label, hash, hex::encode(&hash.into_owned_32bytes()));
}
impl<
        N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
        S: PsyCoordinatorEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
        STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
        GUTAUpdateQueue: QStandardEphemeralQueuePublisher,
        RegisterUserQueue: QStandardEphemeralQueuePublisher,
        DeployContractQueue: QStandardEphemeralQueuePublisher,
        GetProofWorkQueue: QStandardWorkerQueueSubscriber,
        TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
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

        // todo, check miner reputation here to prevent miners who request jobs but
        // don't finish them in a reasonable amount of time

        Ok(())
    }
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
        } else {
            println!("unique_pending_id: {:?}", unique_pending_id);
            println!("unique_proc_id: {:?}", unique_proc_id);
        }
        let work_item = work_item.unwrap();
        println!("work_item.job_id: {:?}", work_item.job_id);
        tracing::info!("work item dependencies: {:?}", work_item.metadata.dependencies);
        let child_proofs = work_item
            .metadata
            .dependencies
            .iter()
            .map(|id| self.proof_store.get_proof_bytes_by_job_id(id.get_output_id()))
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

        println!("getting proof witness bytes: {:?}", work_item.job_id.get_input_witness_id());
        let witness_bytes: Vec<u8> = self
            .temp_db
            .get_tdb_proof_witness_bytes(&self.realm_identifier, unique_pending_id, work_item.job_id.get_input_witness_id())
            .await?;
        println!("got proof witness bytes, len: {}", witness_bytes.len());
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
        let expected_public_inputs_hash = witness.get_public_inputs_hash_with_fingerprint_and_reward_root::<N::HasherBase>(
            self.checkpoint_state_transition_circuit_fingerprint,
            new_reward_root,
        );

        Ok(expected_public_inputs_hash)
    }
    pub async fn submit_proof_raw_internal(&self, mut job_id: N::JobId, tag: N::QHash, proof_bytes: Vec<u8>) -> anyhow::Result<()>
    where
        N::ZKVerifier: 'static,
    {
        job_id = job_id.get_output_id();
        let (unique_pending_id, unique_proc_id) = self.get_current_unique_pending_id_internal().await?;
        let proof_bytes = Arc::new(proof_bytes);

        //HACK: check to make sure the tag matches
        if self
            .temp_db
            .get_proof_miner_rewards_tree_value(&self.realm_identifier, unique_pending_id, job_id.get_output_id())
            .await?
            != tag
        {
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

        print_hash("reward_tree_value", &reward_tree_value);
        let full_expected_public_inputs_hash = if job_id.circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition {
            metadata.expected_public_inputs_hash
        } else if job_id.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof {
            self.get_root_state_transition_expected_public_inputs_hash_internal(job_id, unique_pending_id, reward_tree_value)
                .await?
        } else {
            N::HasherBase::two_to_one(&metadata.expected_public_inputs_hash, &reward_tree_value)
        };


        print_hash("full_expected_public_inputs_hash", &full_expected_public_inputs_hash);
        print_hash("metadata.expected_public_inputs_hash", &metadata.expected_public_inputs_hash);

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

        self.proof_store.put_proof_bytes_for_job_id(job_id.get_output_id(), &proof_bytes).await?;
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

        Ok(())
    }
}
