//! Realm edge implementation of the V2 task flow's queue and proof pipeline.
//! Mirrors the legacy claim and submit paths, without their claim records and
//! reputation writes: leases, scoring and ACK timing belong to the flow.
use std::sync::Arc;

use async_trait::async_trait;
use futures::future::try_join_all;
use parth_core::{
    crypto::hash::traits::{MerkleHasher, ZeroableHash},
    data::queue::queue_key::QPBaseQueueType,
    protocol::core_types::{Q256BitHash, QNetworkTypesConfig, QZKProofVerifier},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::worker::{
    api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse, PROVING_JOB_NODE_TYPE_REALM},
    metadata::{PsyProvingJobMetadata, PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN},
    metadata_with_job_id::PsyProvingJobMetadataWithJobId,
};
use psy_node_core::{
    psy_core_db::traits::full::{PsyNodeCoreRewardsTagTreeStoreReader, PsyNodeCoreRewardsTagTreeStoreWriter, PsyRealmEdgeAPIStoreReader},
    psy_temp_db::StandardEdgeAPITempDBStoreBase,
    queue::{ephemeral::QStandardEphemeralQueuePublisher, worker_queue::{QStandardWorkerQueueSubscriber, WorkerJobControl}},
    store::traits::proof_store::QParthProofStore,
};
use psy_worker_admission::{
    digest,
    flow::{ClaimContext, ProofPipeline, TaskDelivery, TaskFailure, TaskQueue, Verdict},
    lease::{JobBinding, JobIdBytes, JobInstance, LeaseRecord},
    redis_store::RedisAdmissionStore,
};
use tokio::task;

use crate::realm::{edge::handler::RealmEdgeHandler, queue_key::RealmProvingWorkQueueKey};

type Failure<T> = std::result::Result<T, TaskFailure>;

const PREPARE_ATTEMPTS: usize = 4;
const PREPARE_FAILURE_DELAY_MS: u64 = 30_000;

pub struct RealmTaskAdapter<N: QNetworkTypesConfig, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
where
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    UserUpdateQueue: QStandardEphemeralQueuePublisher,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash>,
    ProofStore: QParthProofStore,
{
    pub handler: RealmEdgeHandler<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>,
    pub staging: Arc<RedisAdmissionStore>,
    /// Hard deadline given to every lease; the legacy completion window.
    pub lease_ms: u64,
    pub staging_ttl_ms: u64,
}

fn job_id(job: &JobInstance) -> Failure<QProvingJobDataID> {
    let bytes: [u8; 24] = job.job_id.0.as_slice().try_into().map_err(|_| TaskFailure("job id is not 24 bytes".into()))?;
    Ok(QProvingJobDataID::try_from(bytes)?)
}

impl<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
    RealmTaskAdapter<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
where
    N: QNetworkTypesConfig<JobId = QProvingJobDataID>,
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync,
    UserUpdateQueue: QStandardEphemeralQueuePublisher,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync,
    ProofStore: QParthProofStore,
{
    fn queue_key(&self, unique_proc_id: u128) -> RealmProvingWorkQueueKey<N::QHash, N::JobId> {
        RealmProvingWorkQueueKey {
            realm_id: self.handler.realm_id_u64,
            realm_sub_id: self.handler.realm_sub_id_u64,
            unique_id: unique_proc_id,
            task_group: 0,
            queue_type: QPBaseQueueType::WorkerQueue,
            _phantom_queue_item: std::marker::PhantomData,
        }
    }

    async fn control(&self, job: &JobInstance, control: WorkerJobControl) -> Failure<bool> {
        let h = &self.handler;
        Ok(h.get_proof_work_queue
            .worker_queue_control_job(&self.queue_key(job.unique_proc_id), h.realm_id_u64, h.realm_sub_id_u64, job.unique_proc_id, 0, &job.job_id.0, control)
            .await?)
    }

    /// Reward-tree values of the children, exactly as the legacy child-proof claim path computes them.
    async fn child_tag_values(&self, unique_pending_id: u64, metadata: &PsyProvingJobMetadata<N::QHash, N::JobId>) -> Failure<Vec<N::QHash>> {
        if metadata.dependencies.is_empty() || metadata.reward_tree_hash_mode == PROOF_REWARD_TREE_HASH_MODE_NO_HASH_CHILDREN {
            return Ok(vec![]);
        }
        let mut values = Vec::with_capacity(metadata.dependencies.len());
        for dependency in metadata.dependencies.iter() {
            if dependency.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof || dependency.circuit_type == ProvingJobCircuitType::UserEndCap {
                values.push(N::QHash::get_zero_value());
            } else {
                values.push(self.handler.temp_db
                    .get_proof_miner_rewards_tree_value(&self.handler.realm_identifier, unique_pending_id, dependency.get_output_id()).await?);
            }
        }
        Ok(values)
    }

    async fn prepare(&self, unique_pending_id: u64, item: PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>) -> Failure<Vec<u8>> {
        let h = &self.handler;
        // User end caps live in the checkpoint named by their goal ID, as in the legacy claim path.
        let proofs = item.metadata.dependencies.iter()
            .map(|id| h.proof_store.get_proof_bytes_by_job_id(id.get_output_id(),
                if id.circuit_type == ProvingJobCircuitType::UserEndCap { id.goal_id } else { unique_pending_id }));
        let mut input_proofs = Vec::with_capacity(item.metadata.dependencies.len());
        for proof in try_join_all(proofs).await? {
            input_proofs.push(proof.ok_or_else(|| TaskFailure("missing child proof".into()))?);
        }
        let witness = h.temp_db.get_tdb_proof_witness_bytes(&h.realm_identifier, unique_pending_id, item.job_id.get_input_witness_id()).await?;
        let child_proof_tag_values = self.child_tag_values(unique_pending_id, &item.metadata).await?;
        let response = PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: PsyWorkerGetProvingWorkAPIResponse {
                job: item, child_proof_tag_values, witness, realm_id: h.realm_id_u64, realm_sub_id: h.realm_sub_id_u64,
                unique_pending_id, node_type: PROVING_JOB_NODE_TYPE_REALM,
            },
            input_proofs,
        };
        Ok(serde_json::to_vec(&response)?)
    }

    async fn metadata(&self, job: &JobInstance) -> Failure<(QProvingJobDataID, PsyProvingJobMetadata<N::QHash, N::JobId>)> {
        let id = job_id(job)?;
        let metadata = self.handler.temp_db
            .get_proving_job_metadata(&self.handler.realm_identifier, job.unique_pending_id, id.get_output_id()).await?;
        Ok((id, metadata))
    }

    /// Reward-tree value this lease's proof must commit to, with the lease's own
    /// tag, and the values hashed under it. RealmFinalizeGUTA hashes [c0, A] with
    /// A recomputed from the stored witness, exactly as the legacy submit path.
    async fn reward_value(&self, lease: &LeaseRecord, id: QProvingJobDataID, metadata: &PsyProvingJobMetadata<N::QHash, N::JobId>) -> Failure<(N::QHash, Vec<N::QHash>, N::QHash)> {
        let tag = N::QHash::from_ref_32bytes(&lease.reward_tag.0);
        let mut values = self.child_tag_values(lease.job.unique_pending_id, metadata).await?;
        let output_id = id.get_output_id();
        if output_id.circuit_type == ProvingJobCircuitType::RealmFinalizeGUTA {
            let commitment = self.handler.finalize_output_commitment_a(output_id, lease.job.unique_pending_id, &values).await?;
            values.push(commitment);
        }
        let value = metadata.get_new_rewards_tag_tree_value::<N::HasherBase>(tag, &values)?;
        Ok((tag, values, value))
    }
}

#[async_trait]
impl<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore> TaskQueue
    for RealmTaskAdapter<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
where
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
{
    async fn next(&self, claim: &ClaimContext) -> Failure<Option<TaskDelivery>> {
        let h = &self.handler;
        let mut last_failure = None;
        for _ in 0..PREPARE_ATTEMPTS {
            let (unique_pending_id, unique_proc_id) = h.get_current_unique_pending_id_internal().await?;
            let item: Option<PsyProvingJobMetadataWithJobId<N::QHash, N::JobId>> = h.get_proof_work_queue
                .get_next_worker_queue_item_or_none(&self.queue_key(unique_proc_id), h.realm_id_u64, h.realm_sub_id_u64, unique_proc_id, 0)
                .await?;
            let Some(item) = item else { break };
            let job = JobInstance { unique_pending_id, unique_proc_id, job_id: JobIdBytes(item.job_id.to_fixed_bytes().to_vec()) };
            let output_id = item.job_id.get_output_id();
            let metadata = item.metadata.clone();
            let prepared = async {
                h.temp_db.set_proving_job_metadata(&h.realm_identifier, unique_pending_id, output_id, &metadata).await?;
                self.prepare(unique_pending_id, item).await
            }.await;
            match prepared {
                Ok(payload) => return Ok(Some(TaskDelivery {
                    binding: JobBinding { job, reward_tag: claim.reward_tag, task_digest: digest(&payload), lease_ms: self.lease_ms },
                    payload,
                })),
                Err(failure) => {
                    // Inputs not ready (or a transient store fault): park this job
                    // as long as the legacy ack_wait would, and try the next one,
                    // so one job cannot block the head of the queue.
                    tracing::warn!(failure = %failure.0, "worker task inputs failed to load; delaying the job");
                    if let Err(delay) = self.control(&job, WorkerJobControl::Delay(PREPARE_FAILURE_DELAY_MS)).await {
                        tracing::warn!(failure = %delay.0, "delaying an unprepared job failed");
                    }
                    last_failure = Some(failure);
                }
            }
        }
        match last_failure { Some(failure) => Err(failure), None => Ok(None) }
    }

    async fn reload(&self, lease: &LeaseRecord) -> Failure<Vec<u8>> {
        let (id, metadata) = self.metadata(&lease.job).await?;
        self.prepare(lease.job.unique_pending_id, PsyProvingJobMetadataWithJobId { job_id: id, metadata }).await
    }

    async fn progress(&self, job: &JobInstance) -> Failure<()> {
        if self.control(job, WorkerJobControl::Progress).await? { Ok(()) } else { Err(TaskFailure("no delivery handle".into())) }
    }

    async fn delay(&self, job: &JobInstance, delay_ms: u64) -> Failure<()> {
        self.control(job, WorkerJobControl::Delay(delay_ms)).await.map(|_| ())
    }

    async fn release(&self, job: &JobInstance) -> Failure<()> {
        self.control(job, WorkerJobControl::Release).await.map(|_| ())
    }

    async fn complete(&self, job: &JobInstance) -> Failure<()> {
        if !self.control(job, WorkerJobControl::Complete).await? {
            tracing::debug!(unique_pending_id = job.unique_pending_id, "no delivery handle at final ACK; already acknowledged");
        }
        Ok(())
    }
}

#[async_trait]
impl<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore> ProofPipeline
    for RealmTaskAdapter<N, S, STagTreeRewards, UserUpdateQueue, GetProofWorkQueue, TempDatabase, ProofStore>
where
    N: QNetworkTypesConfig<JobId = QProvingJobDataID> + Send + Sync + 'static,
    N::ZKVerifier: 'static,
    S: PsyRealmEdgeAPIStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    STagTreeRewards: PsyNodeCoreRewardsTagTreeStoreWriter<N::F, N::QHash> + PsyNodeCoreRewardsTagTreeStoreReader<N::F, N::QHash> + Send + Sync + 'static,
    UserUpdateQueue: QStandardEphemeralQueuePublisher + Send + Sync + 'static,
    GetProofWorkQueue: QStandardWorkerQueueSubscriber + Send + Sync + 'static,
    TempDatabase: StandardEdgeAPITempDBStoreBase<N::JobId, N::QHash> + Send + Sync + 'static,
    ProofStore: QParthProofStore + Send + Sync + 'static,
{
    async fn verify(&self, lease: &LeaseRecord, proof: &[u8]) -> Failure<Verdict> {
        // Everything loaded from the edge's own stores is the edge's responsibility.
        let (id, metadata) = self.metadata(&lease.job).await?;
        let (_, _, reward_value) = self.reward_value(lease, id, &metadata).await?;
        let expected = N::HasherBase::two_to_one(&metadata.expected_public_inputs_hash, &reward_value);
        let verifier = self.handler.proof_verifier.clone();
        let proof = proof.to_vec();
        let circuit = id.circuit_type.to_u8() as u32;
        let result = task::spawn_blocking(move || verifier.verify_zk_proof_from_slice_check_public_inputs_hash(circuit, &proof, expected)).await?;
        // Only a verdict on these bytes against complete inputs counts as invalid.
        Ok(if result.is_ok() { Verdict::Valid } else { Verdict::Invalid })
    }

    async fn stage(&self, _lease: &LeaseRecord, proof: &[u8]) -> Failure<psy_worker_admission::Hash32> {
        Ok(self.staging.put_staged_proof(proof, self.staging_ttl_ms).await.map_err(|e| TaskFailure(e.to_string()))?)
    }

    async fn publish(&self, lease: &LeaseRecord) -> Failure<()> {
        let h = &self.handler;
        let receipt = lease.accepted.as_ref().ok_or_else(|| TaskFailure("lease not accepted".into()))?;
        let proof = self.staging.get_staged_proof(receipt.staged_proof).await.map_err(|e| TaskFailure(e.to_string()))?
            .ok_or_else(|| TaskFailure("staged proof missing".into()))?;
        let (id, metadata) = self.metadata(&lease.job).await?;
        let (tag, children, reward_value) = self.reward_value(lease, id, &metadata).await?;
        let unique_pending_id = lease.job.unique_pending_id;
        let output_id = id.get_output_id();
        // Every write below is an overwrite with the same value: safe to repeat.
        h.temp_db.set_proof_miner_rewards_tree_value(&h.realm_identifier, unique_pending_id, output_id, reward_value).await?;
        h.proof_store.put_proof_bytes_for_job_id(output_id, unique_pending_id, &proof).await?;
        for (key, node) in metadata.get_new_rewards_tag_tree_updates::<N::HasherBase>(tag, &children, reward_value)? {
            h.tag_tree_rewards_store.rewards_tag_tree_set_node_tag(unique_pending_id, key, node.tag, node.value).await?;
        }
        if id.circuit_type.needs_to_save_child_reward_tree_values_to_database() {
            let node_key = metadata.get_reward_tree_node_key();
            match children.as_slice() {
                [] => {}
                [left] => h.tag_tree_rewards_store.rewards_tag_tree_set_node_value_only(unique_pending_id, node_key.left_child(), *left).await?,
                [left, right] => {
                    h.tag_tree_rewards_store.rewards_tag_tree_set_node_value_only(unique_pending_id, node_key.left_child(), *left).await?;
                    h.tag_tree_rewards_store.rewards_tag_tree_set_node_value_only(unique_pending_id, node_key.right_child(), *right).await?;
                }
                _ => return Err(TaskFailure("unexpected child count for saved reward values".into())),
            }
        }
        let duration_ms = receipt.accepted_at_ms.saturating_sub(lease.claimed_at_ms);
        if let Err(error) = h.temp_db.increment_job_stats(&h.realm_identifier, unique_pending_id, duration_ms).await {
            tracing::warn!(%error, "failed to record realm proof job statistics");
        }
        Ok(())
    }
}
