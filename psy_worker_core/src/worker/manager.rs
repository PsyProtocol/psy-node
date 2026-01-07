use cf_utils::{log_indicator::print_cf_log_indicator, timer::DebugTimer};

use crate::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerJobFetcher};
use psy_core::job::job_id::QProvingJobDataID;
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use futures::future;
use futures::stream::{self, StreamExt};
use std::sync::Arc;
use tokio::task;

pub struct PsyProofMinerWorkerManager<
    Hash,
    JobId,
    JobFetcher,
    CircuitLibrary,
    Prover,
>{
    pub job_fetcher: JobFetcher,
    pub circuit_library: Arc<CircuitLibrary>,
    pub prover: Arc<Prover>,
    pub _phantom_hash: std::marker::PhantomData<Hash>,
    pub _phantom_job_id: std::marker::PhantomData<JobId>,
}

impl<
    Hash: Copy + std::fmt::Debug + Send + 'static,
    JobId: Copy + std::fmt::Debug + Send + 'static,
    JobFetcher: PsyWorkerJobFetcher<Hash, JobId>,
    CircuitLibrary: Send + Sync + 'static,
    Prover: PsyWorkerGenericLibraryProver<Hash, JobId, CircuitLibrary> + Send + Sync + 'static,
> PsyProofMinerWorkerManager<Hash, JobId, JobFetcher, CircuitLibrary, Prover> {
    pub fn new(
        job_fetcher: JobFetcher,
        circuit_library: Arc<CircuitLibrary>,
        prover: Arc<Prover>,
    ) -> Self {
        Self {
            job_fetcher,
            circuit_library,
            prover,
            _phantom_hash: std::marker::PhantomData,
            _phantom_job_id: std::marker::PhantomData,
        }
    }

    pub async fn process_jobs(&self, batch_size: usize) -> anyhow::Result<()> {
        let mut timer = DebugTimer::new("process_jobs");
        let fetch_futures = (0..batch_size).map(|_| self.job_fetcher.fetch_new_job());
        let fetch_results: Vec<anyhow::Result<Option<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>)>>> = futures::future::join_all(fetch_futures).await;
        let jobs: Vec<_> = fetch_results.into_iter().filter_map(|res| res.ok().flatten()).collect();
        if jobs.is_empty() {
            return Ok(());
        }
        timer.lap("fetched jobs");
        tracing::info!("Fetched {} new jobs", jobs.len());

        let prove_futures = jobs.into_iter().map(|(api_url_hash, tag, job_response)| {
            let job_id = job_response.base.job.job_id;
            tracing::info!("Starting to prove job: {:?} from API URL hash: {:?}", job_id, api_url_hash);
            let library = Arc::clone(&self.circuit_library);
            let prover = Arc::clone(&self.prover);
            async move {
                let start_time = std::time::Instant::now();
                let proof = task::spawn_blocking(move || {
                    prover.prove_job_from_api(&*library, job_response, tag)
                }).await??;
                let proving_time = start_time.elapsed();
                tracing::info!("Proved job: {:?} in {:?}", job_id, proving_time);
                Ok::<([u8; 32], JobId, Hash, Vec<u8>), anyhow::Error>((api_url_hash, job_id, tag, proof))
            }
        });

        let proofs: Vec<([u8; 32], JobId, Hash, Vec<u8>)> = future::join_all(prove_futures).await.into_iter().filter_map(|res: Result<_, _>| res.ok()).collect();
        timer.lap("proved all jobs");
        tracing::info!("Successfully proved {} jobs", proofs.len());

        let submit_futures = proofs.into_iter().map(|(api_url_hash, job_id, tag, proof)| {
            async move {
                tracing::info!("Submitting proof for job: {:?}", job_id);
                self.job_fetcher.submit_proof_raw_to_api(api_url_hash, job_id, tag, proof).await?;
                tracing::info!("Submitted proof for job: {:?} to API URL hash: {}", job_id, hex::encode(api_url_hash));
                Ok::<(), anyhow::Error>(())
            }
        });

        future::try_join_all(submit_futures).await?;
        timer.lap("submitted all proofs");
        Ok(())
    }
    pub async fn run_worker_loop(&self, poll_interval_ms: u64, batch_size: usize) -> anyhow::Result<()> {
        print_cf_log_indicator("PSY_PROOF_MINER_WORKER_STARTED", "");
        loop {
            if let Err(e) = self.process_jobs(batch_size).await {
                let error = format!("Error processing jobs: {:?}", e);
                if error.contains("no proving work available") {
                    //tracing::debug!("{}", error);
                } else {
                    tracing::error!("{}", error);
                }
                //tracing::error!("Error processing job: {:?}", e);
            }
            tokio::time::sleep(std::time::Duration::from_millis(poll_interval_ms)).await;
        }
    }
}
