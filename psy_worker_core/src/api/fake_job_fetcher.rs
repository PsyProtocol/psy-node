use std::sync::Arc;

use async_trait::async_trait;
use dashmap::DashMap;
use parth_common::memory_stores::dash_tag_tree_store::SimpleDashTagTreeStore;
use parth_core::{
    crypto::hash::{tag_tree::hash_tag_tree_node_single, traits::{FieldQHasher, MerkleZeroHasher, ZeroableHash}},
    data::hash::merkle_node_key::SimpleMerkleNodeKey,
    felt::QFelt64,
    protocol::core_types::{Q256BitHash, QFHashBase, QHashBase, QZKProofVerifier},
};
use psy_core::job::job_id::{ProvingJobCircuitType, QProvingJobDataID};
use psy_data::{
    protocol::{
        canonical_chain::{CanonicalChainRef, ChainEpoch, CheckpointHash, CheckpointId, CheckpointRef, NetworkId},
        chain_context::{AuthorityScope, WorkContext, WorkContextToken, WorkProcCheckpointUniqueId, WorkUniquePendingId},
        circuit_inputs::checkpoint_transition::QCQEDCheckpointStateTransitionInput,
    },
    worker::{
        api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse, PROVING_JOB_NODE_TYPE_COORDINATOR},
        metadata::PsyProvingJobMetadata,
        metadata_with_job_id::PsyProvingJobMetadataWithJobId,
        proving_work_history::PsyProvingJobClaimMetadata,
    },
};
use psy_core::constants::chain_id::PsyChainNetworkType;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use tokio::{io::AsyncWriteExt, sync::RwLock};

use crate::{
    utils::{simple_proving_job_queue::SimpleProvingJobQueue, time::get_current_time_ms},
    worker::prover_trait::PsyWorkerJobFetcher,
};

pub struct FakeJobFetcher<F, Hash: Copy + Eq + Default, JobId: std::hash::Hash + Eq, Hasher, Verifier, Proof> {
    pub jobs_queue: Arc<SimpleProvingJobQueue<Hash, JobId>>,
    pub verifier: Arc<Verifier>,
    pub tag_tree: SimpleDashTagTreeStore<Hasher, Hash>,
    pub job_id_to_rewards_tree_location: DashMap<JobId, SimpleMerkleNodeKey>,
    pub completed_jobs: Arc<RwLock<Vec<PsyProvingJobClaimMetadata<Hash, JobId>>>>,
    pub reward_preimage_map: DashMap<([u8; 32], WorkContextToken), (PsyProvingJobClaimMetadata<Hash, JobId>, u64)>,
    pub proof_map: DashMap<JobId, Vec<u8>>,
    pub witness_map: DashMap<JobId, Vec<u8>>,
    pub proving_job_metadata_map: DashMap<JobId, PsyProvingJobMetadata<Hash, JobId>>,
    pub backup_file: Option<tokio::fs::File>,
    pub user_id: u64,
    pub api_url_hash: [u8; 32],
    pub use_tag_tree: bool,
    pub checkpoint_state_transition_circuit_fingerprint: Hash,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
    _phantom_proof: std::marker::PhantomData<Proof>,
    _phantom_field: std::marker::PhantomData<F>,
}

impl<
        F: QFelt64,
        Hash: Q256BitHash
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Send
            + Sync
            + 'static
            + Default
            + Copy
            + Eq
            + ZeroableHash
            + QHashBase
            + QFHashBase<F>,
        Hasher: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash> + Send + Sync,
        Verifier: Send + Sync + 'static + QZKProofVerifier<Hash, Proof>,
        Proof: Send + Sync + 'static,
    > FakeJobFetcher<F, Hash, QProvingJobDataID, Hasher, Verifier, Proof>
{
    pub fn new(user_id: u64, tag_tree_height: u8, verifier: Arc<Verifier>, checkpoint_state_transition_circuit_fingerprint: Hash) -> Self {
        Self {
            verifier: verifier,
            proof_map: DashMap::new(),
            proving_job_metadata_map: DashMap::new(),
            witness_map: DashMap::new(),
            job_id_to_rewards_tree_location: DashMap::new(),
            use_tag_tree: tag_tree_height > 0,
            tag_tree: SimpleDashTagTreeStore::new(tag_tree_height),
            jobs_queue: Arc::new(SimpleProvingJobQueue::new()),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file: None,
            user_id,
            api_url_hash: [1u8; 32],
            checkpoint_state_transition_circuit_fingerprint,
            _phantom_hasher: std::marker::PhantomData,
            _phantom_proof: std::marker::PhantomData,
            _phantom_field: std::marker::PhantomData,
        }
    }
    pub async fn new_with_backup_file_path(
        user_id: u64,
        tag_tree_height: u8,
        backup_file_path: Option<String>,
        verifier: Arc<Verifier>,
        checkpoint_state_transition_circuit_fingerprint: Hash,
    ) -> Self {
        let backup_file = if let Some(path) = backup_file_path {
            match tokio::fs::OpenOptions::new().create(true).append(true).open(path).await {
                Ok(file) => Some(file),
                Err(e) => {
                    println!("Failed to open backup file: {}", e);
                    None
                }
            }
        } else {
            None
        };
        Self {
            proof_map: DashMap::new(),
            proving_job_metadata_map: DashMap::new(),
            witness_map: DashMap::new(),
            job_id_to_rewards_tree_location: DashMap::new(),
            use_tag_tree: tag_tree_height > 0,
            tag_tree: SimpleDashTagTreeStore::new(tag_tree_height),
            jobs_queue: Arc::new(SimpleProvingJobQueue::new()),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file,
            verifier,
            user_id,
            api_url_hash: [1u8; 32],
            checkpoint_state_transition_circuit_fingerprint,
            _phantom_hasher: std::marker::PhantomData,
            _phantom_proof: std::marker::PhantomData,
            _phantom_field: std::marker::PhantomData,
        }
    }
    pub fn get_reward_tag_location(&self, job_id: QProvingJobDataID) -> anyhow::Result<SimpleMerkleNodeKey> {
        if let Some(entry) = self.job_id_to_rewards_tree_location.get(&job_id) {
            Ok(entry.clone())
        } else {
            Err(anyhow::anyhow!("Reward tag location not found for job_id"))
        }
    }
    pub fn get_tag_value_for_job_id(&self, job_id: QProvingJobDataID) -> anyhow::Result<Hash> {
        if job_id.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof
            || job_id.circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
            || job_id.circuit_type == ProvingJobCircuitType::UserEndCap
        {
            Ok(Hash::default())
        } else {
            let tag_tree_location = self.get_reward_tag_location(job_id.clone())?;
            Ok(self.tag_tree.get_node_value(&tag_tree_location))
        }
    }
    pub fn get_proof_for_job_id(&self, job_id: &QProvingJobDataID) -> anyhow::Result<Vec<u8>> {
        if let Some(entry) = self.proof_map.get(job_id) {
            Ok(entry.clone())
        } else {
            Err(anyhow::anyhow!("Proof not found for job_id"))
        }
    }
    pub async fn set_known_proof_for_job_id(&self, job_id: QProvingJobDataID, proof: Vec<u8>) -> anyhow::Result<()> {
        self.proof_map.insert(job_id, proof);
        Ok(())
    }
    pub async fn enqueue_jobs(&self, jobs: Vec<(PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>, Vec<u8>)>) -> anyhow::Result<()> {
        for (job_metadata, witness) in jobs {
            self.enqueue_job(job_metadata, witness).await?;
        }
        Ok(())
    }

    pub async fn enqueue_job(&self, job_metadata: PsyProvingJobMetadataWithJobId<Hash, QProvingJobDataID>, witness: Vec<u8>) -> anyhow::Result<()> {
        let mut child_proof_tag_values = Vec::with_capacity(job_metadata.metadata.dependencies.len());
        let mut child_proofs = Vec::with_capacity(job_metadata.metadata.dependencies.len());
        for dep in &job_metadata.metadata.dependencies {
            if let Some(tag_value) = self.get_tag_value_for_job_id(dep.clone()).ok() {
                child_proof_tag_values.push(tag_value);
            }
            let proof = self.get_proof_for_job_id(dep)?;
            child_proofs.push(proof);
        }

        let work_context = WorkContext::try_new(
            CanonicalChainRef::new(
                NetworkId::from(PsyChainNetworkType::LocalDevnet),
                ChainEpoch::new(0),
                CheckpointRef::new(
                    CheckpointId::new(0),
                    CheckpointHash::from_last_chain_hash(Hash::default()),
                ),
            ),
            AuthorityScope::Coordinator,
            WorkUniquePendingId::new(0),
            WorkProcCheckpointUniqueId::from_u128(0),
            job_metadata.job_id,
        )?;
        let api_response = PsyWorkerGetProvingWorkWithChildProofsAPIResponse {
            base: PsyWorkerGetProvingWorkAPIResponse {
                job: job_metadata.clone(),
                child_proof_tag_values,
                realm_id: 0,
                realm_sub_id: 0,
                work_context: WorkContextToken::from_work_context(&work_context),
                node_type: PROVING_JOB_NODE_TYPE_COORDINATOR,
                witness,
            },
            input_proofs: child_proofs,
        };
        self.proving_job_metadata_map
            .insert(job_metadata.job_id.clone(), job_metadata.metadata.clone());

        self.jobs_queue.enqueue_proving_job(api_response).await?;
        Ok(())
    }
    pub fn get_random_reward_tree_tag_for_job_id(&self) -> (Hash, Hash) {
        let random_a = rand::random::<u64>();
        let random_b = rand::random::<u64>();

        let base_hash = Hash::from_u64x4([self.user_id, 0, random_a, random_b]);
        let tag = Hasher::two_to_one(&base_hash, &base_hash);
        (base_hash, tag)
    }
    pub fn get_remove_reward_tree_tag_preimage_for_job_id(
        &self,
        work_context: WorkContextToken,
    ) -> Option<(PsyProvingJobClaimMetadata<Hash, QProvingJobDataID>, u64)> {
        if let Some(entry) = self.reward_preimage_map.remove(&(self.api_url_hash, work_context)) {
            Some(entry.1)
        } else {
            None
        }
    }

    pub async fn notify_job_completed_with_claim_metadata(
        &self,
        claim_metadata: PsyProvingJobClaimMetadata<Hash, QProvingJobDataID>,
    ) -> anyhow::Result<()> {
        {
            let mut completed_jobs_guard = self.completed_jobs.write().await;
            completed_jobs_guard.push(claim_metadata);
        }
        {
            if self.backup_file.is_some() {
                let data = claim_metadata.psy_ser_to_bytes_vec()?;
                let mut backup_file = self.backup_file.as_ref().unwrap().try_clone().await?;
                backup_file.write_all(&data).await?;
                backup_file.flush().await?;
            }
        }
        Ok(())
    }
    pub async fn fetch_next_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>)>> {
        let api_url_hash = self.api_url_hash;

        let (tag_preimage, tag) = self.get_random_reward_tree_tag_for_job_id();

        let fetch_result: Result<Option<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>>, _> =
            self.jobs_queue.dequeue_proving_job().await;

        match fetch_result {
            Ok(response) => {
                match response {
                    None => Err(anyhow::anyhow!("Failed to fetch job from API URL: No job available")),
                    Some(response) => {
                        let work_context = response.base.decode_and_validate_work_context()?;
                        if response.base.job.job_id.circuit_type == ProvingJobCircuitType::GenerateRollupStateTransitionProof
                            || response.base.job.job_id.circuit_type == ProvingJobCircuitType::GenesisBlockCheckpointStateTransition
                        {
                            self.witness_map.insert(response.base.job.job_id, response.base.witness.clone());
                        }
                        self.job_id_to_rewards_tree_location
                            .insert(response.base.job.job_id.clone(), response.base.job.get_reward_tree_node_key());
                        // use resp
                        let claim_metadata = PsyProvingJobClaimMetadata {
                            job_id: response.base.job.job_id.clone(),
                            reward_tree_tag: tag.clone(),
                            reward_tree_tag_preimage: tag_preimage.clone(),
                            proving_duration_ms: 0,
                            job_submitted_at: 0,
                            unique_pending_id: work_context.unique_pending_id().get(),
                            realm_id: response.base.realm_id,
                            realm_sub_id: response.base.realm_sub_id,
                            reward_tree_node_key: response.base.job.get_reward_tree_node_key(),
                            reward_tree_hash_mode: response.base.job.metadata.reward_tree_hash_mode,
                            reward_tree_node_children: response.base.job.metadata.reward_tree_node_children,
                            node_type: response.base.node_type,
                            api_url_hash: api_url_hash,
                        };
                        self.reward_preimage_map
                            .insert((api_url_hash, response.base.work_context), (claim_metadata, get_current_time_ms()));
                        Ok(Some((api_url_hash, tag.clone(), response)))
                    }
                }
            }
            Err(e) => Err(anyhow::anyhow!("Failed to fetch job from API URL: {}", e)),
        }
    }
    pub fn get_child_proof_tag_values_for_job_ids(&self, dependencies: &[QProvingJobDataID]) -> anyhow::Result<Vec<Hash>> {
        let mut child_proof_tag_values = Vec::with_capacity(dependencies.len());
        for dep in dependencies.iter() {
            if let Some(tag_value) = self.get_tag_value_for_job_id(dep.clone()).ok() {
                child_proof_tag_values.push(tag_value);
            } else {
                anyhow::bail!("Tag value not found for dependency job ID");
            }
        }
        Ok(child_proof_tag_values)
    }
    pub fn get_reward_tree_value_and_validate_job_proof_and_public_inputs(
        &self,
        job_id: QProvingJobDataID,
        metadata: &PsyProvingJobMetadata<Hash, QProvingJobDataID>,
        tag: Hash,
        proof_bytes: &[u8],
    ) -> anyhow::Result<(Hash, Vec<Hash>)> {
        let child_proof_tag_values = self.get_child_proof_tag_values_for_job_ids(&metadata.dependencies)?;
        let rewards_value = metadata.get_new_rewards_tag_tree_value::<Hasher>(tag, &child_proof_tag_values)?;
        let expected_final_public_inputs = match job_id.circuit_type {
            ProvingJobCircuitType::GenerateRollupStateTransitionProof => {
                if !self.witness_map.contains_key(&job_id) {
                    anyhow::bail!("Witness not found for state transition job ID {:?}", job_id);
                }
                let witness: QCQEDCheckpointStateTransitionInput<F, Hash> =
                    QCQEDCheckpointStateTransitionInput::psy_ser_from_slice(
                        &self.witness_map.get(&job_id).unwrap(),
                    )?;
                let part1_reward_value = *child_proof_tag_values
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("missing part1 reward value for rollup"))?;
                let rollup_reward_root =
                    hash_tag_tree_node_single::<Hash, Hasher>(&part1_reward_value, &tag);
                witness.get_chain_hash_with_fingerprint_and_reward_root::<Hasher>(
                    witness.previous_chain_hash,
                    self.checkpoint_state_transition_circuit_fingerprint,
                    rollup_reward_root,
                )
            }
            ProvingJobCircuitType::GenesisBlockCheckpointStateTransition | ProvingJobCircuitType::UserEndCap => metadata.expected_public_inputs_hash,
            _ => metadata.compute_reward_tagged_expected_public_inputs::<Hasher>(tag, &child_proof_tag_values)?,
        };

        self.verifier
            .verify_zk_proof_from_slice_check_public_inputs_hash(job_id.circuit_type as u32, proof_bytes, expected_final_public_inputs)?;
        Ok((rewards_value, child_proof_tag_values))
    }

    pub async fn submit_proof_inner(&self, api_url_hash: [u8; 32], work_context: WorkContextToken, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()> {
        let decoded = work_context.decode::<Hash, QProvingJobDataID>()?;
        let job_id = *decoded.job_id();
        if !self.job_id_to_rewards_tree_location.contains_key(&job_id) {
            anyhow::bail!("Job ID not found in rewards tree location map");
        }
        let metadata = match self.proving_job_metadata_map.get(&job_id) {
            Some(entry) => entry.clone(),
            None => {
                anyhow::bail!("Proving job metadata not found for job ID");
            }
        };
        let (reward_tree_value, child_proof_tag_values) =
            self.get_reward_tree_value_and_validate_job_proof_and_public_inputs(job_id.clone(), &metadata, tag.clone(), &proof)?;

        let current_time = get_current_time_ms();
        let (mut claim_metadata, tag_creation_time) = match self.reward_preimage_map.remove(&(api_url_hash, work_context)) {
            Some((_, v)) => v,
            None => {
                anyhow::bail!("Reward tree tag preimage not found for job ID");
            }
        };

        claim_metadata.proving_duration_ms = current_time - tag_creation_time;
        claim_metadata.job_submitted_at = current_time;

        self.proof_map.insert(job_id.clone(), proof.clone());

        let tag_tree_updates = metadata.get_new_rewards_tag_tree_updates::<Hasher>(tag, &child_proof_tag_values, reward_tree_value)?;
        for (key, node) in tag_tree_updates {
            self.tag_tree.set_node(key, node);
        }

        self.notify_job_completed_with_claim_metadata(claim_metadata).await?;
        Ok(())
    }
}

#[async_trait]
impl<
        F: QFelt64,
        Hash: Q256BitHash
            + serde::Serialize
            + serde::de::DeserializeOwned
            + Send
            + Sync
            + 'static
            + Default
            + Copy
            + Eq
            + ZeroableHash
            + QHashBase
            + QFHashBase<F>,
        Hasher: MerkleZeroHasher<Hash> + FieldQHasher<F, Hash> + Send + Sync,
        Verifier: Send + Sync + 'static + QZKProofVerifier<Hash, Proof>,
        Proof: Send + Sync + 'static,
    > PsyWorkerJobFetcher<Hash, QProvingJobDataID> for FakeJobFetcher<F, Hash, QProvingJobDataID, Hasher, Verifier, Proof>
{
    async fn fetch_new_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>)>> {
        self.fetch_next_job().await
    }
    async fn submit_proof_raw_to_api(&self, api_url_hash: [u8; 32], work_context: WorkContextToken, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()> {
        self.submit_proof_inner(api_url_hash, work_context, tag, proof).await
    }
}
