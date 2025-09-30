
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{common::job_manager, job_mgr::n_job_id::QProvingJobDataID};



pub type QJobManagerID = [u8; 24];

pub struct QJobManagerConfig {
    pub job_timeout_ms: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub worker_reputation_threshold: i32,
    pub worker_blacklist_duration_ms: u64,
}

pub trait QJobManagerBase {
    async fn get_config(&self) -> anyhow::Result<QJobManagerConfig>;
    // adds a job with dependencies -- the job will not be assigned to a worker until all its dependencies are completed
    async fn add_job_with_dependencies(&self, job_id: QProvingJobDataID, dependencies: &[QProvingJobDataID]) -> anyhow::Result<()>;
    // notifies the job manager that the job has been completed -- this will update the job's status and potentially allow dependent jobs to be assigned to workers
    // returns true if the job was a real job was waiting to be completed, false if the job was already marked as completed or does not exist
    async fn notify_job_completed(&self, job_id: QProvingJobDataID) -> anyhow::Result<bool>;
    // if there are no available jobs or the worker's reputation score is too low, return None -- if the worker does not complete the job in less than the QJobManagerConfig.job_timeout_ms, then the worker's reputation score is negatively impacted
    // if the worker completes the job successfully, then the worker's reputation score is positively impacted
    // if the worker fails to complete the job (e.g., crashes, disconnects, etc.), then the worker's reputation score is negatively impacted
    // if the worker's reputation score falls below QJobManagerConfig.worker_reputation_threshold, then the worker is temporarily blacklisted from receiving new jobs
    // if a worker is blacklisted, they can still complete any jobs they have already been assigned, but they will not receive new jobs until their reputation score improves
    async fn request_job_for_worker(&self, worker_id: u64) -> anyhow::Result<Option<QProvingJobDataID>>;
    // gets the current reputation score for a worker -- higher scores indicate better reliability
    async fn get_worker_reputation_score(&self, worker_id: u64) -> anyhow::Result<i32>;
    // returns the time when the worker can next request a job (in ms since UNIX epoch) -- if the worker is not blacklisted, return 0
    async fn get_worker_blacklist_end_time(&self, worker_id: u64) -> anyhow::Result<u64>;
    // manually resets a worker's reputation score to the default value and removes any blacklist -- this can be used for testing or to give a worker a fresh start
    async fn reset_worker_reputation_score(&self, worker_id: u64) -> anyhow::Result<()>;
    // checks if a job is completed -- returns true if the job is completed, false otherwise
    async fn is_job_completed(&self, job_id: QProvingJobDataID) -> anyhow::Result<bool>;
    // waits for a job to be completed -- returns when the job is completed or an error occurs
    async fn wait_for_job_completion(&self, job_id: QProvingJobDataID) -> anyhow::Result<()>;
    // checks if there are any pending jobs (not yet completed) in the system -- returns true if there are pending jobs, false otherwise
    async fn has_pending_jobs(&self) -> anyhow::Result<bool>;
}


#[async_trait]
pub trait QJobKVStore {
    async fn set_data(&self, job_id: QProvingJobDataID, result: &[u8]) -> anyhow::Result<()>;
    async fn get_data(&self, job_id: QProvingJobDataID) -> anyhow::Result<Option<Vec<u8>>>;
    async fn get_serialized<T: serde::de::DeserializeOwned>(&self, job_id: QProvingJobDataID) -> anyhow::Result<Option<T>> {
        if let Some(data) = self.get_data(job_id).await? {
            let deserialized: T = bincode::deserialize(&data)?;
            Ok(Some(deserialized))
        } else {
            Ok(None)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Copy, Hash, PartialOrd, Ord, Deserialize, Serialize)]
pub struct QProofRecursionInputWitness {
    pub left_child_proof_id: QProvingJobDataID,
    pub right_child_proof_id: QProvingJobDataID,
    pub job_id: QProvingJobDataID,
}


pub struct QJobProcessorConfig {
    realm_id: u32,
    checkpoint_id: u64,
}
impl QJobProcessorConfig {
    pub fn new(realm_id: u32, checkpoint_id: u64) -> Self {
        Self { realm_id, checkpoint_id }
    }
    pub async fn process_jobs<
        JobManager: QJobManagerBase,
        JobKVStore: QJobKVStore,
    >(
        &self,
        job_manager: Arc<JobManager>,
        job_kv_store: Arc<JobKVStore>,
        mut jobs_from_edge_api_queue: Vec<QProvingJobDataID>
    ) -> anyhow::Result<()> {
        if jobs_from_edge_api_queue.len() <= 1 {
            // nothing to do
            return Ok(());
        }
        jobs_from_edge_api_queue.sort_by(|a, b| if a.task_index != b.task_index {
            a.task_index.cmp(&b.task_index)
        }else {a.cmp(b)});
        let mut new_jobs = Vec::new();
        let mut index = 0;
        for (job_a, job_b) in jobs_from_edge_api_queue.windows(2).map(|w| (w[0], w[1])) {
            let new_job_id = QProvingJobDataID::guta_two_end_cap_witness(self.checkpoint_id, self.realm_id, 0, index);
            
            job_kv_store.set_data(new_job_id, &bincode::serialize(&QProofRecursionInputWitness {
                left_child_proof_id: job_a,
                right_child_proof_id: job_b,
                job_id: new_job_id,
            })?).await?;

            job_manager.add_job_with_dependencies(new_job_id, &[]).await?;

            new_jobs.push(new_job_id);
            index += 1;
        }
        let mut group_id = 1;
        while new_jobs.len() > 1 {
            let mut next_level_jobs = Vec::new();
            index = 0;
            for (job_a, job_b) in new_jobs.windows(2).map(|w| (w[0], w[1])) {
                let new_job_id = QProvingJobDataID::guta_two_agg_witness(self.checkpoint_id, self.realm_id, 0, group_id);
                
                job_kv_store.set_data(new_job_id, &bincode::serialize(&QProofRecursionInputWitness {
                    left_child_proof_id: job_a,
                    right_child_proof_id: job_b,
                    job_id: new_job_id,
                })?).await?;

                job_manager.add_job_with_dependencies(new_job_id, &[
                    job_a,
                    job_b,
                ]).await?;

                next_level_jobs.push(new_job_id);
                index += 1;
            }
            if new_jobs.len() % 2 == 1 {
                next_level_jobs.push(*new_jobs.last().unwrap());
            }
            group_id += 1;
            new_jobs = next_level_jobs;
        }
        if jobs_from_edge_api_queue.len() % 2 == 1 {
            // if odd, the last job is not paired, so we need to promote it to the next level directly
            let left_job = new_jobs.last().unwrap();
            let right_job = jobs_from_edge_api_queue.last().unwrap();
            let new_job_id = QProvingJobDataID::guta_left_guta_right_end_cap_witness(self.checkpoint_id, self.realm_id, group_id, 0);
            
            job_kv_store.set_data(new_job_id, &bincode::serialize(&QProofRecursionInputWitness {
                left_child_proof_id: *left_job,
                right_child_proof_id: *right_job,
                job_id: new_job_id,
            })?).await?;

            job_manager.add_job_with_dependencies(new_job_id, &[
                *left_job,
                *right_job,
            ]).await?;
        }
        Ok(())
    }
}


pub fn example_job_processor(){

}


