use async_trait::async_trait;
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;


pub trait PsyWorkerGenericLibraryProverInfoProvider<JobId> {
    fn prover_can_process_job(&self, job_id: JobId) -> bool;
}

pub trait PsyWorkerGenericLibraryProver<
    Hash,
    JobId,
    Library,
>: PsyWorkerGenericLibraryProverInfoProvider<JobId> {
    fn prove_job_from_api(
        &self,
        library: &Library,
        input: PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>,
        worker_reward_tag: Hash,
    ) -> anyhow::Result<Vec<u8>>;
}

#[async_trait]
pub trait PsyWorkerJobFetcher<Hash, JobId> {
    async fn fetch_new_job(
        &self,
    ) -> anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>)>>;
    async fn submit_proof_raw_to_api(&self, api_url_hash: [u8; 32], job_id: JobId, tag: Hash, proof: Vec<u8>) -> anyhow::Result<()>;
}