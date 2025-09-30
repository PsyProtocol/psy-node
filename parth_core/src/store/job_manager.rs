use serde::{Deserialize, Serialize};
use async_trait::async_trait;
use crate::data::{hash::hash256::Hash256, serializable::{QPDSerializable, QPDSerializableFixed}};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct QJobManagerConfig {
    pub job_timeout_ms: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub worker_reputation_threshold: i32,
    pub worker_blacklist_duration_ms: u64,
}

impl QPDSerializable for QJobManagerConfig {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow::anyhow!(e))
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(bytes).map_err(|e| anyhow::anyhow!(e))
    }
}

impl QPDSerializableFixed for QJobManagerConfig {
    fn get_fixed_size() -> usize {
        32
    }
}


#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Copy)]
pub struct QRetryJob<T: QPDSerializableFixed + Send + Sync + Copy> {
    pub retry_at_ms: u64,
    pub worker_id: Hash256,
    pub job_id: T,
}

impl<T: QPDSerializableFixed + Send + Sync + Copy> QPDSerializable for QRetryJob<T> {
    fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(8 + 32 + T::get_fixed_size());
        bytes.extend_from_slice(&self.retry_at_ms.to_le_bytes());
        bytes.extend_from_slice(&self.worker_id.0);
        bytes.extend_from_slice(&self.job_id.to_bytes()?);
        Ok(bytes)
    }

    fn from_bytes(bytes: &[u8]) -> anyhow::Result<Self> {
        if bytes.len() != 8 + 32 + T::get_fixed_size() {
            anyhow::bail!("Invalid bytes length for QRetryJob");
        }
        let retry_at_ms = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let worker_id = Hash256(bytes[8..40].try_into().unwrap());
        let job_id = T::from_bytes(&bytes[40..])?;
        Ok(Self {
            retry_at_ms,
            worker_id,
            job_id,
        })
    }
}
impl<T: QPDSerializableFixed + Send + Sync + Copy> QPDSerializableFixed for QRetryJob<T> {
    fn get_fixed_size() -> usize {
        8 + 32 + T::get_fixed_size()
    }
}


#[async_trait]
pub trait QJobManagerBase<JobID: QPDSerializableFixed + Send + Sync + Copy> {
    async fn get_config(&self) -> anyhow::Result<QJobManagerConfig>;
    async fn add_jobs(&self, realm_id: u64, channel_id: u128, task_group_id: u64, job_ids: &[JobID]) -> anyhow::Result<()>;
    async fn get_pending_task_groups(&self, realm_id: u64, channel_id: u128) -> anyhow::Result<Vec<u64>>;

    async fn get_remaining_jobs_count(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<u64>;
    // notifies the job manager that the job has been completed -- this will update the job's status and potentially allow dependent jobs to be assigned to workers
    // returns true if the job was a real job was waiting to be completed, false if the job was already marked as completed or does not exist
    async fn notify_job_completed(&self, realm_id: u64, channel_id: u128, task_group_id: u64, job_id: &JobID) -> anyhow::Result<bool>;

    // if there are no available jobs or the worker's reputation score is too low, return None -- if the worker does not complete the job in less than the QJobManagerConfig.job_timeout_ms, then the worker's reputation score is negatively impacted
    // if the worker completes the job successfully, then the worker's reputation score is positively impacted
    // if the worker fails to complete the job (e.g., crashes, disconnects, etc.), then the worker's reputation score is negatively impacted
    // if the worker's reputation score falls below QJobManagerConfig.worker_reputation_threshold, then the worker is temporarily blacklisted from receiving new jobs
    // if a worker is blacklisted, they can still complete any jobs they have already been assigned, but they will not receive new jobs until their reputation score improves
    async fn request_job_for_worker(&self, realm_id: u64, channel_id: u128, worker_id: Hash256) -> anyhow::Result<Option<JobID>>;
    // gets the current reputation score for a worker -- higher scores indicate better reliability
    async fn get_worker_reputation_score(&self, worker_id: Hash256) -> anyhow::Result<i32>;
    async fn report_worker_failure(&self, worker_id: Hash256) -> anyhow::Result<()>;
    // returns the time when the worker can next request a job (in ms since UNIX epoch) -- if the worker is not blacklisted, return 0
    async fn get_worker_blacklist_end_time(&self, worker_id: Hash256) -> anyhow::Result<u64>;
    // manually resets a worker's reputation score to the default value and removes any blacklist -- this can be used for testing or to give a worker a fresh start
    async fn reset_worker_reputation_score(&self, worker_id: Hash256) -> anyhow::Result<()>;
    // checks if a job is completed -- returns true if the job is completed, false otherwise
    async fn is_job_completed(&self, realm_id: u64, channel_id: u128, job_id: &JobID) -> anyhow::Result<bool>;
    // checks if there are any pending jobs (not yet completed) in the system -- returns true if there are pending jobs, false otherwise
    async fn has_pending_jobs(&self, realm_id: u64, channel_id: u128) -> anyhow::Result<bool>;


    // waits for a task group to be completed -- returns when the task group is completed or an error occurs
    async fn wait_for_task_group(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<()>;

    // refreshes the state of all retry task groups
    async fn refresh_retry_task_groups(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<()>;

}
