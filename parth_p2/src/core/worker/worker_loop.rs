use std::time::Duration;

use qp_core::common::traits::worker::QPWorkerEdgeClient;

use crate::core::worker::core_logic::QPWorkerNodeCoreLogic;

pub async fn run_worker_loop<C: QPWorkerEdgeClient>(worker_id: u64, retry_delay_ms: u64, client: &C) -> anyhow::Result<()> {
    let core_logic = QPWorkerNodeCoreLogic::new(worker_id);

    loop {
        // Request a job from the coordinator
        let mut job_response = client.request_proving_job_for_worker(worker_id).await;
        while job_response.is_err() {
            tracing::error!("Failed to request job, retrying in {} milliseconds (Reason: {})...", retry_delay_ms, job_response.unwrap_err());
            tokio::time::sleep(Duration::from_millis(retry_delay_ms)).await;
            job_response = client.request_proving_job_for_worker(worker_id).await;
        }

        let job_response = job_response.unwrap();

        

        // Process the job using core logic
        let submit_request = core_logic.process_edge_job_response(job_response)?;

        // Submit the completed job back to the coordinator
        let mut submit_response = client.submit_completed_job(&submit_request).await;

        if submit_response.is_err() {
            tracing::error!("Failed to submit job result: {}", submit_response.unwrap_err());
            tokio::time::sleep(Duration::from_millis(500)).await;
            submit_response = client.submit_completed_job(&submit_request).await;
        }

        if submit_response.is_err() {
            // try again
            tracing::error!("Failed to submit job result: {}", submit_response.unwrap_err());
            tokio::time::sleep(Duration::from_millis(500)).await;
        } else {
            let submit_response = submit_response.unwrap();
            if submit_response.has_error {
                tracing::error!("Coordinator reported error on job submission: {}", submit_response.error_message);
            } else {
                tracing::info!("Job submitted successfully: {:?}", submit_response);
            }
        }
    }

   // Ok(())
}