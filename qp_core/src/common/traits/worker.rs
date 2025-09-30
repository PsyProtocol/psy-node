use async_trait::async_trait;

use crate::common::data::protocol::core::{QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest, QPEdgeWorkerSubmitJobResponse};



#[async_trait]
pub trait QPWorkerEdgeClient {
    async fn request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse>;
    async fn submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse>;
}