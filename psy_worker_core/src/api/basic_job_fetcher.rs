use std::sync::{atomic::AtomicBool, Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use parth_core::{
    crypto::{
        hash::traits::MerkleHasher,
        secp256k1::{CompressedPublicKey, Secp256K1WalletProvider, SimpleTimedRequest},
    },
    protocol::core_types::Q256BitHash,
};
use parth_crypto::hash::sha256::CoreSha256Hasher;
use psy_api_core::worker::standard_worker_rpc::NodeEdgeWorkerRpcClient;
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::worker::{api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse, proving_work_history::PsyProvingJobClaimMetadata};
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;
use tokio::{io::AsyncWriteExt, sync::RwLock};

use crate::{
    api::url_manager::{APIURLRotationStrategy, PsyWorkerAPIURLManager}, utils::time::get_current_time_ms, worker::prover_trait::PsyWorkerJobFetcher
};

const API_REQUEST_SIGNATURE_VALID_DURATION_MS: u64 = 30000; // 30 seconds
#[derive(Debug)]
pub struct PsyWorkerBasicAPIJobFetcher<Hash, JobId: std::hash::Hash + Eq, Signer, Hasher> {
    pub realm_api_url_manager: PsyWorkerAPIURLManager,
    pub coordinator_api_url_manager: PsyWorkerAPIURLManager,
    pub is_in_realm_mode: AtomicBool,
    pub completed_jobs: Arc<RwLock<Vec<PsyProvingJobClaimMetadata<Hash, JobId>>>>,
    pub reward_preimage_map: DashMap<([u8; 32], JobId), (PsyProvingJobClaimMetadata<Hash, JobId>, u64)>,
    pub backup_file: Option<tokio::fs::File>,
    pub api_signer: Arc<Signer>,
    pub api_signer_public_key: CompressedPublicKey,
    pub user_id: u64,
    _phantom_hasher: std::marker::PhantomData<Hasher>,
}


impl<
        Hash: Q256BitHash + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
        Signer: Clone + Secp256K1WalletProvider,
        Hasher: MerkleHasher<Hash>,
    > PsyWorkerBasicAPIJobFetcher<Hash, QProvingJobDataID, Signer, Hasher>
{
    pub fn new(api_signer: Signer, api_signer_public_key: CompressedPublicKey, user_id: u64, url_rotation_strategy: APIURLRotationStrategy) -> Self {
        Self {
            realm_api_url_manager: PsyWorkerAPIURLManager::new(url_rotation_strategy),
            coordinator_api_url_manager: PsyWorkerAPIURLManager::new(url_rotation_strategy),
            is_in_realm_mode: AtomicBool::new(true),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file: None,
            api_signer: Arc::new(api_signer),
            api_signer_public_key: api_signer_public_key,
            user_id,
            _phantom_hasher: std::marker::PhantomData,
        }
    }
    pub async fn new_with_backup_file_path(api_signer: Signer, api_signer_public_key: CompressedPublicKey, user_id: u64, url_rotation_strategy: APIURLRotationStrategy, backup_file_path: Option<String>) -> Self {
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
            realm_api_url_manager: PsyWorkerAPIURLManager::new(url_rotation_strategy),
            coordinator_api_url_manager: PsyWorkerAPIURLManager::new(url_rotation_strategy),
            is_in_realm_mode: AtomicBool::new(true),
            completed_jobs: Arc::new(RwLock::new(Vec::new())),
            reward_preimage_map: DashMap::new(),
            backup_file,
            api_signer: Arc::new(api_signer),
            api_signer_public_key: api_signer_public_key,
            user_id,
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
        api_url_hash: [u8; 32],
        job_id: QProvingJobDataID,
    ) -> Option<(PsyProvingJobClaimMetadata<Hash, QProvingJobDataID>, u64)> {
        if let Some(entry) = self.reward_preimage_map.remove(&(api_url_hash, job_id)) {
            Some(entry.1)
        } else {
            None
        }
    }

    pub async fn notify_job_completed_with_claim_metadata(
        &self,
        api_url_hash: [u8; 32],
        claim_metadata: PsyProvingJobClaimMetadata<Hash, QProvingJobDataID>,
    ) -> anyhow::Result<()> {
        {
            let mut completed_jobs_guard = self.completed_jobs.write().await;
            completed_jobs_guard.push(claim_metadata);
        }
        {
            if self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst) {
                self.realm_api_url_manager.report_api_url_success(&api_url_hash)
            } else {
                self.coordinator_api_url_manager.report_api_url_success(&api_url_hash)
            }
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
    pub async fn report_fetch_job_failure(&self, api_url_hash: [u8; 32]) {
        let is_in_realm_mode = self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst);
        if is_in_realm_mode {
            self.realm_api_url_manager.report_api_url_failure(&api_url_hash)
        } else {
            self.coordinator_api_url_manager.report_api_url_failure(&api_url_hash)
        }
        if is_in_realm_mode && self.coordinator_api_url_manager.has_urls() {
            self.is_in_realm_mode.store(false, std::sync::atomic::Ordering::SeqCst);
        } else if !is_in_realm_mode && self.realm_api_url_manager.has_urls() {
            self.is_in_realm_mode.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub async fn report_submit_proof_failure(&self, api_url_hash: [u8; 32]) {
        let is_in_realm_mode = self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst);
        if is_in_realm_mode {
            self.realm_api_url_manager.report_api_url_failure(&api_url_hash)
        } else {
            self.coordinator_api_url_manager.report_api_url_failure(&api_url_hash)
        }
        if is_in_realm_mode && self.coordinator_api_url_manager.has_urls() {
            self.is_in_realm_mode.store(false, std::sync::atomic::Ordering::SeqCst);
        } else if !is_in_realm_mode && self.realm_api_url_manager.has_urls() {
            self.is_in_realm_mode.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
    pub async fn report_fetch_job_success(&self, api_url_hash: [u8; 32]) {
        let is_in_realm_mode = self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst);
        if is_in_realm_mode {
            self.realm_api_url_manager.report_api_url_success(&api_url_hash)
        } else {
            self.coordinator_api_url_manager.report_api_url_success(&api_url_hash)
        }
    }
    pub async fn fetch_next_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>)>> {
        if !self.realm_api_url_manager.has_urls() && !self.coordinator_api_url_manager.has_urls() {
            anyhow::bail!("No API URLs available to fetch new job (realm and coordinator URL lists are empty)");
        }

        // println!("realm_api_urls_len: {}", self.realm_api_url_manager.get_total_api_urls());
        // println!("coordinator_api_urls_len: {}", self.coordinator_api_url_manager.get_total_api_urls());

        let realm_has_urls = self.realm_api_url_manager.has_urls();
        let coord_has_urls = self.coordinator_api_url_manager.has_urls();
        let mut is_in_realm_mode = match (realm_has_urls, coord_has_urls) {
            (true, false) => true,
            (false, true) => false,
            (true, true) => self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst),
            (false, false) => unreachable!(),
        };
        self.is_in_realm_mode
            .store(is_in_realm_mode, std::sync::atomic::Ordering::SeqCst);
        println!("Fetching next job. Current mode: {}", if is_in_realm_mode { "Realm" } else { "Coordinator" });

        let result = if is_in_realm_mode {
            self.realm_api_url_manager.get_next_api_url_hash().await
        } else {
            self.coordinator_api_url_manager.get_next_api_url_hash().await
        };
        let api_url_hash = result.ok_or_else(|| anyhow::anyhow!("No API URLs available to fetch new job"))?;
        let api_client = if is_in_realm_mode {
            self.realm_api_url_manager.api_url_hash_to_client.get(&api_url_hash)
        } else {
            self.coordinator_api_url_manager.api_url_hash_to_client.get(&api_url_hash)
        };
        if api_client.is_none() {
            anyhow::bail!("API client not found for URL hash");
        }

        let (tag_preimage, tag) = self.get_random_reward_tree_tag_for_job_id();
        let (signature, timed_request) = SimpleTimedRequest::create_signed_timed_request_for_request_proof_work::<Signer, CoreSha256Hasher>(
            &self.api_signer,
            &self.api_signer_public_key,
            API_REQUEST_SIGNATURE_VALID_DURATION_MS,
            tag.clone().into_owned_32bytes(),
        );

        let fetch_result: Result<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>, _> =
            api_client.unwrap().get_proving_work_with_child_proofs(signature, timed_request).await;
        match fetch_result {
            Ok(response) => {
                let claim_metadata = PsyProvingJobClaimMetadata {
                    job_id: response.base.job.job_id.clone(),
                    reward_tree_tag: tag.clone(),
                    reward_tree_tag_preimage: tag_preimage.clone(),
                    proving_duration_ms: 0,
                    job_submitted_at: 0,
                    unique_pending_id: response.base.unique_pending_id,
                    realm_id: response.base.realm_id,
                    realm_sub_id: response.base.realm_sub_id,
                    reward_tree_node_key: response.base.job.get_reward_tree_node_key(),
                    reward_tree_hash_mode: response.base.job.metadata.reward_tree_hash_mode,
                    reward_tree_node_children: response.base.job.metadata.reward_tree_node_children,
                    node_type: response.base.node_type,
                    api_url_hash: api_url_hash,
                };
                self.reward_preimage_map
                    .insert((api_url_hash, response.base.job.job_id.clone()), (claim_metadata, get_current_time_ms()));
                self.report_fetch_job_success(api_url_hash).await;
                Ok(Some((api_url_hash, tag.clone(), response)))
            }
            Err(e) => {
                self.report_fetch_job_failure(api_url_hash).await;
                Err(anyhow::anyhow!("Failed to fetch job from API URL: {}", e))
            }
        }
    }

    pub async fn submit_proof_inner(&self, api_url_hash: [u8; 32], job_id: QProvingJobDataID, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()> {
        let is_in_realm_mode = self.is_in_realm_mode.load(std::sync::atomic::Ordering::SeqCst);
        let api_client = if is_in_realm_mode {
            self.realm_api_url_manager.api_url_hash_to_client.get(&api_url_hash)
        } else {
            self.coordinator_api_url_manager.api_url_hash_to_client.get(&api_url_hash)
        };
        if api_client.is_none() {
            anyhow::bail!("API client not found for URL hash");
        }

        let current_time = get_current_time_ms();
        let (mut claim_metadata, tag_creation_time) = match self.reward_preimage_map.remove(&(api_url_hash, job_id.clone())) {
            Some((_, v)) => v,
            None => {
                anyhow::bail!("Reward tree tag preimage not found for job ID");
            }
        };

        claim_metadata.proving_duration_ms = current_time - tag_creation_time;
        claim_metadata.job_submitted_at = current_time;

        let submit_result: Result<(), _> = api_client.unwrap().submit_proof_raw(job_id, tag, proof).await;
        match submit_result {
            Ok(_) => {
                self.notify_job_completed_with_claim_metadata(api_url_hash, claim_metadata).await?;
                self.report_fetch_job_success(api_url_hash).await;
                Ok(())
            }
            Err(e) => {
                self.report_submit_proof_failure(api_url_hash).await;
                Err(anyhow::anyhow!("Failed to submit proof to API URL: {}", e))
            }
        }
    }
}

#[async_trait]
impl<
        Hash: Q256BitHash + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
        Signer: Clone + Secp256K1WalletProvider + Send + Sync,
        Hasher: MerkleHasher<Hash> + Send + Sync,
    > PsyWorkerJobFetcher<Hash, QProvingJobDataID> for PsyWorkerBasicAPIJobFetcher<Hash, QProvingJobDataID, Signer, Hasher>
{
    async fn fetch_new_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, QProvingJobDataID>)>> {
        self.fetch_next_job().await
    }
    async fn submit_proof_raw_to_api(&self, api_url_hash: [u8; 32], job_id: QProvingJobDataID, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()> {
        self.submit_proof_inner(api_url_hash, job_id, tag, proof).await
    }
}
