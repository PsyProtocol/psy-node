use std::time::{SystemTime, UNIX_EPOCH};

use parth_core::{data::{hash::hash256::Hash256, serializable::QPDSerializableFixed}, store::job_manager::{QJobManagerBase, QJobManagerConfig, QRetryJob}};
use redis::AsyncCommands;

use crate::redis::core::{ProofStoreRedisAsync, QueuePrefixKey};
use async_trait::async_trait;

fn get_timestamp_in_milliseconds() -> u64 {
    let current_system_time = SystemTime::now();
    let duration_since_epoch = current_system_time
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards"); // Handle potential errors if the system clock goes backward
    let milliseconds_timestamp = duration_since_epoch.as_millis();
    milliseconds_timestamp as u64
}
#[async_trait]
impl<JobID: QPDSerializableFixed + Send + Sync + Copy + Sized + Clone> QJobManagerBase<JobID> for ProofStoreRedisAsync {
    
    async fn get_config(&self) -> anyhow::Result<QJobManagerConfig>{
        Ok(self.job_manager_config)
    }
    async fn add_jobs(&self, realm_id: u64, channel_id: u128, task_group_id: u64, job_ids: &[JobID]) -> anyhow::Result<()>{

        todo!("not implemented");
    }
    async fn get_pending_task_groups(&self, realm_id: u64, channel_id: u128) -> anyhow::Result<Vec<u64>>{
        self.get_set_u64(&self.job_manager_task_groups_set_key(realm_id, channel_id)).await
    }

    async fn get_remaining_jobs_count(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<u64>{
        self.get_iu64_generic(&self.job_manager_task_group_counter_key(realm_id, channel_id, task_group_id), &[0u8]).await
    }
    // notifies the job manager that the job has been completed -- this will update the job's status and potentially allow dependent jobs to be assigned to workers
    // returns true if the job was a real job was waiting to be completed, false if the job was already marked as completed or does not exist
    async fn notify_job_completed(&self, realm_id: u64, channel_id: u128, task_group_id: u64, job_id: &JobID) -> anyhow::Result<bool>{

        let has_job = self.get_iu64_generic(&self.job_manager_completed_jobs_store_key(realm_id, channel_id), &job_id.to_bytes()?).await?;
        if has_job > 0 {
            return Ok(false);
        }
        self.set_iu64_generic(&self.job_manager_completed_jobs_store_key(realm_id, channel_id), &job_id.to_bytes()?, 1).await?;


        let new_value = self.inc_iu64_generic(&self.job_manager_task_group_counter_key(realm_id, channel_id, task_group_id), &[0u8], -1).await?;
        if new_value == 0 { 
            self.remove_from_set_u64(&self.job_manager_task_groups_set_key(realm_id, channel_id), task_group_id).await?;
            self.push_to_generic_u64_queue(&self.job_manager_completed_tasks_group_queue_key(realm_id, channel_id, task_group_id), task_group_id).await?;
        }
        Ok(true)


    }

    // if there are no available jobs or the worker's reputation score is too low, return None -- if the worker does not complete the job in less than the QJobManagerConfig.job_timeout_ms, then the worker's reputation score is negatively impacted
    // if the worker completes the job successfully, then the worker's reputation score is positively impacted
    // if the worker fails to complete the job (e.g., crashes, disconnects, etc.), then the worker's reputation score is negatively impacted
    // if the worker's reputation score falls below QJobManagerConfig.worker_reputation_threshold, then the worker is temporarily blacklisted from receiving new jobs
    // if a worker is blacklisted, they can still complete any jobs they have already been assigned, but they will not receive new jobs until their reputation score improves
    async fn request_job_for_worker(&self, realm_id: u64, channel_id: u128, worker_id: Hash256) -> anyhow::Result<Option<JobID>>{
        let pending_sets = self.get_set_u64(&self.job_manager_task_groups_set_key(realm_id, channel_id)).await?;

        for task_group_id in pending_sets {
            let task = self.pop_from_generic_obj_queue_or_none::<JobID>(&self.job_manager_pending_jobs_queue_key(realm_id, channel_id, task_group_id)).await?;
            if task.is_some() {
                let retry_job = QRetryJob {
                    job_id: task.unwrap(),
                    retry_at_ms: get_timestamp_in_milliseconds() + self.job_manager_config.job_timeout_ms,
                    worker_id,
                };
                self.push_to_generic_obj_queue(&self.job_manager_retry_jobs_queue_key(realm_id, channel_id, task_group_id), &retry_job).await?;
                return Ok(task);
            }
        }
        return Ok(None);
    }
    // gets the current reputation score for a worker -- higher scores indicate better reliability
    async fn get_worker_reputation_score(&self, worker_id: Hash256) -> anyhow::Result<i32>{
        Ok(100) // TODO: implement in future?
    }
    async fn report_worker_failure(&self, worker_id: Hash256) -> anyhow::Result<()>{
        Ok(()) // TODO: implement in future?
    }
    // returns the time when the worker can next request a job (in ms since UNIX epoch) -- if the worker is not blacklisted, return 0
    async fn get_worker_blacklist_end_time(&self, worker_id: Hash256) -> anyhow::Result<u64>{
        Ok(0) // TODO: implement in future?
    }
    // manually resets a worker's reputation score to the default value and removes any blacklist -- this can be used for testing or to give a worker a fresh start
    async fn reset_worker_reputation_score(&self, worker_id: Hash256) -> anyhow::Result<()>{
        Ok(()) // TODO: implement in future?
    }
    // checks if a job is completed -- returns true if the job is completed, false otherwise
    async fn is_job_completed(&self, realm_id: u64, channel_id: u128, job_id: &JobID) -> anyhow::Result<bool>{
        let has_job = self.get_iu64_generic(&self.job_manager_completed_jobs_store_key(realm_id, channel_id), &job_id.to_bytes()?).await?;
        Ok(has_job > 0)
    }
    // checks if there are any pending jobs (not yet completed) in the system -- returns true if there are pending jobs, false otherwise
    async fn has_pending_jobs(&self, realm_id: u64, channel_id: u128) -> anyhow::Result<bool>{
        let pending_groups: Vec<u64> = self.get_set_u64(&self.job_manager_task_groups_set_key(realm_id, channel_id)).await?;
        Ok(!pending_groups.is_empty())
    }


    // waits for a task group to be completed -- returns when the task group is completed or an error occurs
    async fn wait_for_task_group(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<()>{
        self.wait_for_generic_u64_queue(&self.job_manager_completed_tasks_group_queue_key(realm_id, channel_id, task_group_id)).await?;
        Ok(())
    }

    // refreshes the state of all retry task groups
    async fn refresh_retry_task_groups(&self, realm_id: u64, channel_id: u128, task_group_id: u64) -> anyhow::Result<()>{
        
        let mut need_retry_jobs =  Vec::new();
        let mut still_pending_retry_jobs = Vec::new();
        let mt = self.dump_ro_generic_obj_queue::<QRetryJob<JobID>>(&self.job_manager_retry_jobs_queue_key(realm_id, channel_id, task_group_id)).await?;
        let now_ms = get_timestamp_in_milliseconds();

        for job in mt.into_iter() {
            if job.retry_at_ms <= now_ms {
                need_retry_jobs.push(job);
            } else {
                still_pending_retry_jobs.push(job);
            }
        }
        if need_retry_jobs.len() > 0 {
            let mut con = self.pool.get().await?;
            let jobs = need_retry_jobs.iter().map(|x| x.job_id).collect::<Vec<_>>();
            self.push_many_to_generic_obj_queue(&self.job_manager_pending_jobs_queue_key(realm_id, channel_id, task_group_id), &jobs).await?;
            let _: () = con.del(&self.job_manager_retry_jobs_queue_key(realm_id, channel_id, task_group_id)).await?;
            if still_pending_retry_jobs.len() > 0 {
                self.push_many_to_generic_obj_queue(&self.job_manager_retry_jobs_queue_key(realm_id, channel_id, task_group_id), &still_pending_retry_jobs).await?;
            }
        }
        Ok(())
    }
}