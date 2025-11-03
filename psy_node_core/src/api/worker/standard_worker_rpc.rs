use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{QProvingJobDataIDWithRewardPath, crypto::secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest}};
use psy_data::worker::api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse};




#[rpc(server, client, namespace = "psy_worker")]
pub trait NodeEdgeWorkerRpc<JobId> {
    #[method(name = "get_proving_work")]
    async fn get_proving_work(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkAPIResponse<JobId>>;
    #[method(name = "get_proving_work_with_child_proofs")]
    async fn get_proving_work_with_child_proofs(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<JobId>>;
    #[method(name = "submit_proof_raw")]
    async fn submit_proof_raw(&self, job_id: QProvingJobDataIDWithRewardPath<JobId>, proof: Vec<u8>) -> RpcResult<()>;
}

