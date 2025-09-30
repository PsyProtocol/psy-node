use std::sync::atomic::{AtomicU32, Ordering};

use qp_core::common::{data::protocol::core::{QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest, QPEdgeWorkerSubmitJobResponse}, traits::worker::QPWorkerEdgeClient};

use async_trait::async_trait;
pub struct MultiNodeWorkerConnections<ConnectionTypeA: QPWorkerEdgeClient, ConnectionTypeB: QPWorkerEdgeClient> {
    connections_a: Vec<ConnectionTypeA>,
    connections_b: Vec<ConnectionTypeB>,
    connections_a_count: u32,
    connections_b_count: u32,
    last_used_connection: AtomicU32,
}


impl<ConnectionTypeA: QPWorkerEdgeClient, ConnectionTypeB: QPWorkerEdgeClient> MultiNodeWorkerConnections<ConnectionTypeA, ConnectionTypeB> {
    pub fn connections_count(&self) -> u32 {
        self.connections_a_count + self.connections_b_count
    }
    pub fn new(connections_a: Vec<ConnectionTypeA>, connections_b: Vec<ConnectionTypeB>) -> Self {
        let connections_a_count = connections_a.len() as u32;
        let connections_b_count = connections_b.len() as u32;
        tracing::info!("MultiNodeWorkerConnections: connections_a_count: {}, connections_b_count: {}", connections_a_count, connections_b_count);
        Self {
            connections_a,
            connections_b,
            connections_a_count,
            connections_b_count,
            last_used_connection: AtomicU32::new(0),
        }
    }
    pub async fn g_request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse> {


        let new_last_used_connection = rand::random::<u32>() % self.connections_count();
        self.last_used_connection.store(new_last_used_connection, Ordering::SeqCst);
        if new_last_used_connection < self.connections_a_count {
            return self.connections_a[new_last_used_connection as usize].request_proving_job_for_worker(worker_id).await;
        }
        let new_last_used_connection = new_last_used_connection - self.connections_a_count;
        self.connections_b[new_last_used_connection as usize].request_proving_job_for_worker(worker_id).await
    }

    pub async fn g_submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse> {
        if self.connections_count() == 0 {
            return Err(anyhow::anyhow!("No connections available"));
        }
        let last_used_connection = self.last_used_connection.load(Ordering::SeqCst);
        if last_used_connection < self.connections_a_count {
            self.connections_a[last_used_connection as usize].submit_completed_job(request).await
        }else{
            let last_used_connection = last_used_connection - self.connections_a_count;
            self.connections_b[last_used_connection as usize].submit_completed_job(request).await
        }

    }
    
}

#[async_trait]
impl <ConnectionTypeA: QPWorkerEdgeClient + Sync, ConnectionTypeB: QPWorkerEdgeClient + Sync> QPWorkerEdgeClient for MultiNodeWorkerConnections<ConnectionTypeA, ConnectionTypeB> {
    async fn request_proving_job_for_worker(&self, worker_id: u64) -> anyhow::Result<QPEdgeWorkerJobResponse> {
       self.g_request_proving_job_for_worker(worker_id).await
    }

    async fn submit_completed_job(&self, request: &QPEdgeWorkerSubmitJobRequest) -> anyhow::Result<QPEdgeWorkerSubmitJobResponse> {
        self.g_submit_completed_job(request).await
    }
}

