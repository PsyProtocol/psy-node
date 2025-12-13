use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use parth_core::{crypto::secp256k1::{QEDCompressedSecp256K1Signature, SimpleTimedRequest}, node::realm_identifier::QRealmIdentifier};
use psy_data::worker::api_response::{PsyWorkerGetProvingWorkAPIResponse, PsyWorkerGetProvingWorkWithChildProofsAPIResponse};




#[rpc(server, client, namespace = "psy_worker")]
pub trait NodeEdgeWorkerRpc<Hash, JobId> {
    #[method(name = "get_proving_work")]
    async fn get_proving_work(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkAPIResponse<Hash, JobId>>;
    #[method(name = "get_proving_work_with_child_proofs")]
    async fn get_proving_work_with_child_proofs(&self, signature:  QEDCompressedSecp256K1Signature, request: SimpleTimedRequest) -> RpcResult<PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>>;
    #[method(name = "submit_proof_raw")]
    async fn submit_proof_raw(&self, job_id: JobId, tag: Hash, proof: Vec<u8>) -> RpcResult<()>;
    
    #[method(name = "get_realm_identifier_worker_api")]
    async fn get_realm_identifier_worker_api(&self) -> RpcResult<QRealmIdentifier>;
}

