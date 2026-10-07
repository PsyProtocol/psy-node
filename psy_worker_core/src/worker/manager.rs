use cf_utils::log_indicator::print_cf_log_indicator;

use crate::worker::proving_pools::ProvingPools;
use crate::worker::prover_trait::{PsyWorkerGenericLibraryProver, PsyWorkerJobFetcher};
use psy_data::worker::api_response::PsyWorkerGetProvingWorkWithChildProofsAPIResponse;
use std::sync::Arc;
use tokio::sync::{mpsc, Semaphore};
use tokio::task;

pub struct PsyProofMinerWorkerManager<
    Hash,
    JobId,
    JobFetcher,
    CircuitLibrary,
    Prover,
>{
    pub job_fetcher: Arc<JobFetcher>,
    pub circuit_library: Arc<CircuitLibrary>,
    pub prover: Arc<Prover>,
    pub _phantom_hash: std::marker::PhantomData<Hash>,
    pub _phantom_job_id: std::marker::PhantomData<JobId>,
}

impl<
    Hash: Copy + std::fmt::Debug + Send + 'static,
    JobId: Copy + std::fmt::Debug + Send + 'static,
    JobFetcher: PsyWorkerJobFetcher<Hash, JobId> + Send + Sync + 'static,
    CircuitLibrary: Send + Sync + 'static,
    Prover: PsyWorkerGenericLibraryProver<Hash, JobId, CircuitLibrary> + Send + Sync + 'static,
> PsyProofMinerWorkerManager<Hash, JobId, JobFetcher, CircuitLibrary, Prover> {
    pub fn new(
        job_fetcher: Arc<JobFetcher>,
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

    pub async fn run_worker_loop(&self, poll_interval_ms: u64, batch_size: usize) -> anyhow::Result<()> {
        self.run_worker_loop_with_pools(poll_interval_ms, batch_size, None).await
    }

    /// Like `run_worker_loop`; with `pools`, each job is proved in a thread
    /// pool of its own instead of rayon's global pool.
    pub async fn run_worker_loop_with_pools(&self, poll_interval_ms: u64, batch_size: usize, pools: Option<Arc<ProvingPools>>) -> anyhow::Result<()> {
        print_cf_log_indicator("PSY_PROOF_MINER_WORKER_STARTED", "");

        let (job_tx, job_rx) = mpsc::channel::<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>)>(batch_size);

        let (proof_tx, proof_rx) = mpsc::channel::<([u8; 32], JobId, Hash, Vec<u8>)>(batch_size);

        let fetcher_handle = Self::spawn_fetcher_task(
            self.job_fetcher.clone(),
            job_tx,
            poll_interval_ms,
        );

        let submitter_handle = Self::spawn_submitter_task(
            self.job_fetcher.clone(),
            proof_rx,
        );

        let worker_handle = Self::spawn_worker_task(
            self.circuit_library.clone(),
            self.prover.clone(),
            job_rx,
            proof_tx,
            batch_size,
            pools,
        );

        let _ = tokio::try_join!(fetcher_handle, submitter_handle, worker_handle);

        Ok(())
    }

    fn spawn_fetcher_task(
        fetcher: Arc<JobFetcher>,
        job_tx: mpsc::Sender<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>)>,
        poll_interval_ms: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!("Fetcher role started - ensuring job queue stays full");
            println!("[worker/fetcher] started");

            loop {
                match job_tx.reserve().await {
                    Ok(permit) => {
                        match fetcher.fetch_new_job().await {
                            Ok(Some(job)) => {
                                permit.send(job);
                                tracing::debug!("Fetcher: Added job to queue");
                                println!("[worker/fetcher] fetched job");
                            }
                            Ok(None) => {
                                tracing::debug!("Fetcher: no proving work available (Ok(None))");
                                println!("[worker/fetcher] no work");
                                drop(permit);
                                tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
                            }
                            Err(e) => {
                                let error = format!("Error fetching job: {:?}", e);
                                if !error.contains("no proving work available") {
                                    tracing::error!("Fetcher: {}", error);
                                    println!("[worker/fetcher] error: {}", error);
                                }
                                drop(permit);
                                tokio::time::sleep(tokio::time::Duration::from_millis(poll_interval_ms)).await;
                            }
                        }
                    }
                    Err(_) => {
                        tracing::info!("Fetcher: Job queue receiver dropped, shutting down");
                        break;
                    }
                }
            }
        })
    }

    fn spawn_worker_task(
        circuit_library: Arc<CircuitLibrary>,
        prover: Arc<Prover>,
        mut job_rx: mpsc::Receiver<([u8; 32], Hash, PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash, JobId>)>,
        proof_tx: mpsc::Sender<([u8; 32], JobId, Hash, Vec<u8>)>,
        batch_size: usize,
        pools: Option<Arc<ProvingPools>>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!("Worker role started - processing jobs from fetch queue");
            println!("[worker/prover] started");

            let semaphore = Arc::new(Semaphore::new(batch_size));

            while let Some((api_url_hash, tag, job_response)) = job_rx.recv().await {
                let job_id = job_response.base.job.job_id;
                tracing::info!("Worker: Picked up job {:?}", job_id);
                println!("[worker/prover] picked job: {:?}", job_id);

                let permit = semaphore.clone().acquire_owned().await.unwrap();

                let library = circuit_library.clone();
                let prover_clone = prover.clone();
                let proof_tx_clone = proof_tx.clone();
                let pools = pools.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    tracing::info!("Worker: Starting proof generation for job {:?}", job_id);
                    println!("[worker/prover] proving start: {:?}", job_id);
                    let start_time = std::time::Instant::now();

                    let result = task::spawn_blocking(move || match pools {
                        Some(pools) => pools.run(move || prover_clone.prove_job_from_api(&*library, job_response, tag)),
                        None => prover_clone.prove_job_from_api(&*library, job_response, tag),
                    }).await;

                    match result {
                        Ok(Ok(proof)) => {
                            let proving_time = start_time.elapsed();
                            tracing::info!("Worker: Proved job {:?} in {:?}", job_id, proving_time);
                            println!("[worker/prover] proving done: {:?}, elapsed={:?}, proof_bytes={}", job_id, proving_time, proof.len());

                            if let Err(e) = proof_tx_clone.send((api_url_hash, job_id, tag, proof)).await {
                                tracing::error!("Worker: Failed to send proof to submitter: {:?}", e);
                                println!("[worker/prover] send to submitter failed: {:?}", e);
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::error!("Worker: Proving failed for job {:?}: {:?}", job_id, e);
                            println!("[worker/prover] proving failed: {:?}, err={:?}", job_id, e);
                        }
                        Err(e) => {
                            tracing::error!("Worker: Proving task panicked for job {:?}: {:?}", job_id, e);
                            println!("[worker/prover] proving panic: {:?}, err={:?}", job_id, e);
                        }
                    }
                });
            }

            tracing::info!("Worker: Job queue closed, shutting down");
        })
    }

    fn spawn_submitter_task(
        submitter: Arc<JobFetcher>,
        mut proof_rx: mpsc::Receiver<([u8; 32], JobId, Hash, Vec<u8>)>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            tracing::info!("Submitter role started - submitting proofs from proof queue");
            println!("[worker/submitter] started");

            while let Some((api_url_hash, job_id, tag, proof)) = proof_rx.recv().await {
                tracing::info!("Submitter: Received proof for job {:?}", job_id);
                println!("[worker/submitter] submit start: {:?}, proof_bytes={}", job_id, proof.len());

                match submitter.submit_proof_raw_to_api(api_url_hash, job_id, tag, proof).await {
                    Ok(_) => {
                        tracing::info!("Submitter: Successfully submitted proof for job {:?}", job_id);
                        println!("[worker/submitter] submit ok: {:?}", job_id);
                    }
                    Err(e) => {
                        tracing::error!("Submitter: Error submitting proof for job {:?}: {:?}", job_id, e);
                        println!("[worker/submitter] submit fail: {:?}, err={:?}", job_id, e);
                    }
                }
            }

            tracing::info!("Submitter: Proof queue closed, shutting down");
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker::prover_trait::PsyWorkerGenericLibraryProverInfoProvider;
    use async_trait::async_trait;
    use parth_core::{data::hash::hash256::Hash256, utils::QPGenRandom};
    use psy_core::job::job_id::QProvingJobDataID;
    use std::sync::Mutex;

    type Job = PsyWorkerGetProvingWorkWithChildProofsAPIResponse<Hash256, QProvingJobDataID>;

    /// Hands out a fixed list of jobs and forwards every submitted proof.
    struct ListedJobs {
        jobs: Mutex<Vec<Job>>,
        submitted: mpsc::UnboundedSender<Vec<u8>>,
    }

    #[async_trait]
    impl PsyWorkerJobFetcher<Hash256, QProvingJobDataID> for ListedJobs {
        async fn fetch_new_job(&self) -> anyhow::Result<Option<([u8; 32], Hash256, Job)>> {
            Ok(self.jobs.lock().unwrap().pop().map(|job| ([0u8; 32], Hash256::qp_rand_gen(), job)))
        }
        async fn submit_proof_raw_to_api(&self, _api_url_hash: [u8; 32], _job_id: QProvingJobDataID, _tag: Hash256, proof: Vec<u8>) -> anyhow::Result<()> {
            let _ = self.submitted.send(proof);
            Ok(())
        }
    }

    /// Its "proof" is the name of the thread rayon work runs on during the
    /// job. Two jobs must be inside at once before either returns.
    struct WhereRayonRuns {
        both_inside: std::sync::Barrier,
    }

    impl PsyWorkerGenericLibraryProverInfoProvider<QProvingJobDataID> for WhereRayonRuns {
        fn prover_can_process_job(&self, _job_id: QProvingJobDataID) -> bool {
            true
        }
    }

    impl PsyWorkerGenericLibraryProver<Hash256, QProvingJobDataID, ()> for WhereRayonRuns {
        fn prove_job_from_api(&self, _library: &(), _input: Job, _tag: Hash256) -> anyhow::Result<Vec<u8>> {
            self.both_inside.wait();
            let (name, _) = rayon::join(|| std::thread::current().name().unwrap_or("").to_string(), || ());
            Ok(name.into_bytes())
        }
    }

    /// Runs the worker loop on two jobs that overlap and returns where each did its rayon work.
    async fn prove_two_overlapping_jobs(pools: Option<Arc<ProvingPools>>) -> Vec<String> {
        let (submitted, mut proofs) = mpsc::unbounded_channel();
        let jobs = (0..2).map(|_| Job::qp_rand_gen()).collect();
        let prover = WhereRayonRuns { both_inside: std::sync::Barrier::new(2) };
        let manager = PsyProofMinerWorkerManager::new(Arc::new(ListedJobs { jobs: Mutex::new(jobs), submitted }), Arc::new(()), Arc::new(prover));
        let worker = tokio::spawn(async move { manager.run_worker_loop_with_pools(1, 2, pools).await });
        let mut names = Vec::new();
        for _ in 0..2 {
            let proof = tokio::time::timeout(std::time::Duration::from_secs(30), proofs.recv()).await.expect("a proof within 30 s").expect("the worker is running");
            names.push(String::from_utf8(proof).unwrap());
        }
        worker.abort();
        names.sort();
        names
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_job_that_overlaps_another_is_proved_in_a_narrow_pool() {
        let pools = Arc::new(ProvingPools::new(4, 2, None).unwrap());
        let names = prove_two_overlapping_jobs(Some(pools)).await;
        // The job that started first stays in the global pool, whose threads have no name.
        assert!(!names[0].starts_with("prove-") && names[1].starts_with("prove-narrow"), "{:?}", names);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn without_pools_every_job_uses_the_global_pool() {
        let names = prove_two_overlapping_jobs(None).await;
        assert!(names.iter().all(|n| !n.starts_with("prove-")), "{:?}", names);
    }
}
