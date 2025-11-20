use crate::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerJobFetcher};

pub struct PsyProofMinerWorkerManager<
    Hash,
    JobId,
    JobFetcher,
    CircuitLibrary,
    Prover,
>{
    pub job_fetcher: JobFetcher,
    pub circuit_library: CircuitLibrary,
    pub prover: Prover,
    pub _phantom_hash: std::marker::PhantomData<Hash>,
    pub _phantom_job_id: std::marker::PhantomData<JobId>,
}

impl<
    Hash: Copy + std::fmt::Debug,
    JobId: Copy + std::fmt::Debug,
    JobFetcher: PsyWorkerJobFetcher<Hash, JobId>,
    Library,
    Prover: PsyWorkerGenericLibraryProver<Hash, JobId, Library>,
> PsyProofMinerWorkerManager<
    Hash,
    JobId,
    JobFetcher,
    Library,
    Prover,
> {
    pub fn new(
        job_fetcher: JobFetcher,
        circuit_library: Library,
        prover: Prover,
    ) -> Self {
        Self {
            job_fetcher,
            circuit_library,
            prover,
            _phantom_hash: std::marker::PhantomData,
            _phantom_job_id: std::marker::PhantomData,
        }
    }

    pub async fn process_job(&self) -> anyhow::Result<()> {
        if let Some((api_url_hash, tag, job_response)) = self.job_fetcher.fetch_new_job().await? {
            let job_id = job_response.base.job.job_id;
            tracing::info!("Fetched new job: {:?} from API URL hash: {:?}", job_id, api_url_hash);
            let start_time = std::time::Instant::now();
            let proof = self.prover.prove_job_from_api(
                &self.circuit_library,
                job_response,
                tag,
            )?;
            let proving_time = start_time.elapsed();
            tracing::info!("Proved job: {:?} in {:?}, submitting proof to API", job_id, proving_time);
            self.job_fetcher.submit_proof_raw_to_api(api_url_hash, job_id, tag, proof).await?;
            tracing::info!("Submitted proof for job: {:?} to API URL hash: {}", job_id, hex::encode(api_url_hash));
        }
        Ok(())
    }
    pub async fn run_worker_loop(&self, poll_interval_ms: u64) -> anyhow::Result<()> {
        loop {
            if let Err(e) = self.process_job().await {
                tracing::error!("Error processing job: {:?}", e);
            }
            tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
        }
    }
}