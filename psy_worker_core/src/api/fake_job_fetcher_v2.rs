use std::sync::{Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use parth_common::memory_stores::dash_tag_tree_store::SimpleDashTagTreeStore;
use parth_core::{crypto::hash::traits::MerkleZeroHasher, data::hash::merkle_node_key::SimpleMerkleNodeKey, protocol::core_types::Q256BitHash};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::{
    protocol::chain_context::WorkContextToken,
    worker::{
        api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse,
        proving_work_history::PsyProvingJobClaimMetadata,
    },
};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use tokio::{io::AsyncWriteExt, sync::RwLock};

use crate::{utils::{simple_proving_job_queue::SimpleProvingJobQueue, time::get_current_time_ms}, worker::prover_trait::PsyWorkerJobFetcher};


pub struct FakeJobFetcherV2<Hash: Copy + Eq + Default, JobId: std::hash::Hash + Eq, Hasher> {
    pub jobs_queue: Arc<SimpleProvingJobQueue<Hash, JobId>>,
    pub tag_tree: SimpleDashTagTreeStore<Hasher, Hash>,
    pub job_id_to_rewards_tree_location: DashMap<JobId, SimpleMerkleNodeKey>,
    pub completed_jobs: Arc<RwLock<Vec<PsyProvingJobClaimMetadata<Hash, JobId>>>>,
    pub reward_preimage_map: DashMap<([u8; 32], WorkContextToken), (PsyProvingJobClaimMetadata<Hash, JobId>, u64)>,
    pub proof_map: DashMap<JobId, Vec<u8>>,
    pub backup_file: Option<tokio::fs::File>,
    pub user_id: u64,
    pub api_url_hash: [u8; 32],
    pub use_tag_tree: bool,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}

impl<
        Hash: Q256BitHash + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static + Default + Copy + Eq,
        Hasher: MerkleZeroHasher<Hash>,
    > FakeJobFetcherV2<Hash, QProvingJobDataID, Hasher>
{

    pub fn new(user_id: u64, tag_tree_height: u8) -> Self {
        Self {
            proof_map: DashMap::new(),
            job_id_to_rewards_tree_location: DashMap::new(),
            use_tag_tree: tag_tree_height > 0,
            tag_tree: SimpleDashTagTreeStore::new(tag_tree_height),
            jobs_queue: Arc::new(SimpleProvingJobQueue::new()),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file: None,
            user_id,
            api_url_hash: [1u8; 32],
            _phantom_hasher: std::marker::PhantomData,
        }
    }
    pub async fn new_with_backup_file_path(user_id: u64, tag_tree_height: u8, backup_file_path: Option<String>) -> Self {
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
            job_id_to_rewards_tree_location: DashMap::new(),
            use_tag_tree: tag_tree_height > 0,
            tag_tree: SimpleDashTagTreeStore::new(tag_tree_height),
            jobs_queue: Arc::new(SimpleProvingJobQueue::new()),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file,
            user_id,
            api_url_hash: [1u8; 32],
            _phantom_hasher: std::marker::PhantomData,
        }
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
    pub async fn get_proof_for_job_id(&self, job_id: &QProvingJobDataID) -> Option<Vec<u8>> {
        if let Some(entry) = self.proof_map.get(job_id) {
            Some(entry.value().clone())
        } else {
            None
        }
    }
    pub async fn fetch_next_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>)>> {
        
        let api_url_hash = self.api_url_hash;
        

        let (tag_preimage, tag) = self.get_random_reward_tree_tag_for_job_id();
        
        let fetch_result: Result<Option<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>>, _> = self.jobs_queue.dequeue_proving_job().await;
        
        match fetch_result {
            Ok(response) => {
                match response {
                    None => {
                        Err(anyhow::anyhow!("Failed to fetch job from API URL: No job available"))
                    }
                    Some(response) => {
                        let work_context = response.base.decode_and_validate_work_context()?;
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
            Err(e) => {
                Err(anyhow::anyhow!("Failed to fetch job from API URL: {}", e))
            }
        }
    }

    pub async fn submit_proof_inner(&self, api_url_hash: [u8; 32], work_context: WorkContextToken, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()> {
        let decoded = work_context.decode::<Hash, QProvingJobDataID>()?;
        let job_id = *decoded.job_id();
        

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
        if self.job_id_to_rewards_tree_location.contains_key(&job_id) {
            let (_, reward_tree_location) = self.job_id_to_rewards_tree_location.remove(&job_id).unwrap();
            if self.use_tag_tree{
                self.tag_tree.set_tag(reward_tree_location, tag);
            }
        }else{
            anyhow::bail!("Job ID not found in rewards tree location map");
        }
        self.notify_job_completed_with_claim_metadata(claim_metadata).await?;
        Ok(())
    }
}

#[async_trait]
impl<
        Hash: Q256BitHash + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static + Default + Copy + Eq,
        Hasher: MerkleZeroHasher<Hash> + Send + Sync,
    > PsyWorkerJobFetcher<Hash, QProvingJobDataID> for FakeJobFetcherV2<Hash, QProvingJobDataID, Hasher>
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
