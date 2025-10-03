use qp_core::{common::{compression::gzip::GZipHelper, data::{core::hash::hash256::Hash256, protocol::{core::{QPEdgeWorkerJobResponse, QPEdgeWorkerSubmitJobRequest}, job::QJobTopic}}}, crypto::{hash::sha256::CoreSha256Hasher, merkle::core::compute_partial_merkle_root_from_leaves}};




pub struct QPWorkerNodeCoreLogic {
    worker_id: u64,
}

impl QPWorkerNodeCoreLogic {
    pub fn new(worker_id: u64) -> Self {
        Self { worker_id }
    }

    pub fn process_edge_job_response(&self, response: QPEdgeWorkerJobResponse) -> anyhow::Result<QPEdgeWorkerSubmitJobRequest>{
        // Core logic for processing a job

        let job_id = response.job_response.job_id;


        match job_id.topic  {
            QJobTopic::CompressGzip => {
                let compressed_data = GZipHelper::compress_data(&response.data)?;
                Ok(QPEdgeWorkerSubmitJobRequest {
                    worker_id: self.worker_id,
                    job_id,
                    wip_checkpoint_id: response.wip_checkpoint_id,
                    data: compressed_data,
                })
            },
            QJobTopic::ComputeCombinedRealmRootUpdateMerkleRoot => {
                // Perform the computation to get the merkle root

                let leaves: Vec<Hash256> = pser::deserialize(&response.data)?;
                let computed_root = compute_partial_merkle_root_from_leaves::<Hash256, CoreSha256Hasher>(&leaves);

            

                Ok(QPEdgeWorkerSubmitJobRequest {
                    worker_id: self.worker_id,
                    job_id,
                    wip_checkpoint_id: response.wip_checkpoint_id,
                    data: computed_root.0.to_vec(),
                })
            },
        }
        
    }
}