use parth_core::{QJobIdBase, protocol::core_types::Q256BitHash};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use psy_serialize::PsyCanonicalDatabaseSerializeBaseSingle;

use crate::utils::simple_queue::{CompletionAsyncBytesQueue, SimpleAsyncBytesQueue};

pub struct SimpleProvingJobQueue<Hash, JobId> {
    pub inner_queue: CompletionAsyncBytesQueue,
    _marker_hash: std::marker::PhantomData<Hash>,
    _marker_job_id: std::marker::PhantomData<JobId>,
}

impl<Hash: Q256BitHash, JobId: QJobIdBase> SimpleProvingJobQueue<Hash, JobId> {
    pub fn new() -> Self {
        Self {
            inner_queue: CompletionAsyncBytesQueue::new(),
            _marker_hash: std::marker::PhantomData,
            _marker_job_id: std::marker::PhantomData,
        }
    }

    pub async fn enqueue_proving_job(&self, job: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>) -> anyhow::Result<()> {
        let job_id_bytes = job.base.job.job_id.to_bytes_fixed();
        let job_bytes = job.psy_ser_into_bytes_vec()?;
        self.inner_queue.enqueue_job(job_id_bytes, job_bytes).await
    }
    pub async fn enqueue_proving_jobs(&self, job: Vec<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>>) -> anyhow::Result<()> {
        for single_job in job {
            self.enqueue_proving_job(single_job).await?;
        }
        Ok(())
    }
    pub async fn report_proving_job_complete(&self, job_id: &JobId) -> anyhow::Result<()> {
        let job_id_bytes = job_id.to_bytes_fixed();
        self.inner_queue.report_job_complete(job_id_bytes).await
    }
    pub async fn dequeue_proving_job(&self) -> anyhow::Result<Option<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>>> {
        if let Some((_, job_bytes)) = self.inner_queue.dequeue_job().await? {
            let job: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId> = PsyWorkerGetProvingWorkWithChildProofsAPIResponse::psy_ser_from_slice(&job_bytes)?;
            Ok(Some(job))
        } else {
            Ok(None)
        }
    }
}