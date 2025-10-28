
pub trait QNextGenWorkerGenericInfo<JobId> {
    fn can_process_job(&self, job_id: JobId) -> bool;
}
