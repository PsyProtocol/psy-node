mod common;
use std::{collections::{HashMap, VecDeque}, sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}}};

use async_trait::async_trait;
use common::*;
use psy_worker_admission::{*, flow::*, lease::*, store::*};
use secp256k1::SecretKey;

#[derive(Default)]
struct FakeQueue {
    pending: Mutex<VecDeque<u64>>,
    fail_next: AtomicBool,
    log: Mutex<Vec<(&'static str, u64)>>,
    delays: Mutex<Vec<u64>>,
    pulls: Mutex<u32>,
}
impl FakeQueue {
    fn push(&self, n: u64) { self.pending.lock().unwrap().push_back(n); }
    fn count(&self, event: &str, n: u64) -> usize { self.log.lock().unwrap().iter().filter(|(e, j)| *e == event && *j == n).count() }
    fn record(&self, event: &'static str, job: &JobInstance) { self.log.lock().unwrap().push((event, job.unique_pending_id - 40)); }
}
#[async_trait]
impl TaskQueue for FakeQueue {
    async fn next(&self, claim: &ClaimContext) -> std::result::Result<Option<TaskDelivery>, TaskFailure> {
        *self.pulls.lock().unwrap() += 1;
        if self.fail_next.swap(false, Ordering::SeqCst) { return Err(TaskFailure("nats down".into())); }
        Ok(self.pending.lock().unwrap().pop_front().map(|n| TaskDelivery { binding: JobBinding { reward_tag: claim.reward_tag, ..binding(n, 60_000) }, payload: format!("task {n}").into_bytes() }))
    }
    async fn reload(&self, lease: &LeaseRecord) -> std::result::Result<Vec<u8>, TaskFailure> { Ok(format!("task {}", lease.job.unique_pending_id - 40).into_bytes()) }
    async fn progress(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure> { self.record("progress", job); Ok(()) }
    async fn delay(&self, job: &JobInstance, delay_ms: u64) -> std::result::Result<(), TaskFailure> {
        self.delays.lock().unwrap().push(delay_ms); self.record("delay", job); Ok(())
    }
    async fn release(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure> { self.record("release", job); Ok(()) }
    async fn complete(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure> { self.record("complete", job); Ok(()) }
}

#[derive(Default)]
struct FakePipeline { fail_publish: AtomicBool, published: Mutex<HashMap<Hash32, u32>>, staged: Mutex<Vec<Hash32>> }
#[async_trait]
impl ProofPipeline for FakePipeline {
    async fn verify(&self, _: &LeaseRecord, proof: &[u8]) -> std::result::Result<Verdict, TaskFailure> {
        match proof { b"bad" => Ok(Verdict::Invalid), b"boom" => Err(TaskFailure("verifier crashed".into())), _ => Ok(Verdict::Valid) }
    }
    async fn stage(&self, _: &LeaseRecord, proof: &[u8]) -> std::result::Result<Hash32, TaskFailure> {
        let address = digest(proof); self.staged.lock().unwrap().push(address); Ok(address)
    }
    async fn publish(&self, lease: &LeaseRecord) -> std::result::Result<(), TaskFailure> {
        if self.fail_publish.load(Ordering::SeqCst) { return Err(TaskFailure("scylla timeout".into())); }
        *self.published.lock().unwrap().entry(lease.job_key).or_default() += 1; Ok(())
    }
}

fn claim_request(signer: &SecretKey) -> ClaimRequest { ClaimRequest { reward_tag: digest(&key(signer).0) } }

struct Env { store: Arc<MemoryStore>, queue: Arc<FakeQueue>, pipeline: Arc<FakePipeline>, flow: TaskFlow<FakeQueue, FakePipeline> }

async fn env(workers: &[&SecretKey]) -> Env {
    let store = MemoryStore::new();
    let leases = lease_service(store.clone(), AdmissionPolicy::for_base_bits(8));
    for signer in workers { activate(leases.admission(), signer, 0, store.time()).await; }
    let (queue, pipeline) = (Arc::new(FakeQueue::default()), Arc::new(FakePipeline::default()));
    let config = FlowConfig { attribute_invalid_proofs: true, ..FlowConfig::default() };
    let flow = TaskFlow::new(leases, queue.clone(), pipeline.clone(), config);
    Env { store, queue, pipeline, flow }
}

impl Env {
    async fn claim(&self, signer: &SecretKey) -> std::result::Result<ClaimedTask, AdmissionError> {
        let request = claim_request(signer);
        self.flow.claim(auth(signer, AdmissionMethod::ClaimTask, 0, request.payload_hash(), self.store.time()), request).await
    }
    async fn submit(&self, signer: &SecretKey, lease: &LeaseRecord, proof: &[u8]) -> std::result::Result<SubmitOutcome, AdmissionError> {
        let submission = submission(lease, proof);
        self.flow.submit(submit_auth(signer, 0, &submission, self.store.time()), submission, proof.to_vec()).await
    }
    async fn reputation(&self, signer: &SecretKey) -> (u8, u64) {
        let status = self.flow.leases().admission().get_status(auth(signer, AdmissionMethod::GetStatus, 0, empty_payload(), self.store.time())).await.unwrap();
        (status.reputation, status.generation)
    }
    fn inflight(&self, signer: &SecretKey) -> u64 { self.store.counter(StoreKey::Inflight(key(signer))) }
}

#[tokio::test]
async fn valid_proof_is_accepted_published_and_acked_once() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    let body = claim_request(&signer);
    let request = auth(&signer, AdmissionMethod::ClaimTask, 0, body.payload_hash(), env.store.time());
    let task = env.flow.claim(request.clone(), body.clone()).await.unwrap();
    assert_eq!(task.payload, b"task 1");
    // A lost response: the retry gets the same lease without pulling the queue again.
    let retry = env.flow.claim(request, body).await.unwrap();
    assert_eq!((retry.lease.lease_id, retry.payload), (task.lease.lease_id, task.payload.clone()));
    assert_eq!(*env.queue.pulls.lock().unwrap(), 1);
    let SubmitOutcome::Accepted { published: true, .. } = env.submit(&signer, &task.lease, b"proof").await.unwrap() else { panic!() };
    assert_eq!(env.pipeline.published.lock().unwrap()[&task.lease.job_key], 1);
    assert_eq!(env.queue.count("complete", 1), 1);
    assert_eq!(env.reputation(&signer).await, (4, 0));
    assert_eq!(env.inflight(&signer), 0);
}

#[tokio::test]
async fn no_job_or_a_failing_queue_returns_the_reservation() {
    let signer = secret(1); let env = env(&[&signer]).await;
    assert_eq!(env.claim(&signer).await.unwrap_err(), AdmissionError::NoWork);
    env.queue.fail_next.store(true, Ordering::SeqCst);
    assert_eq!(env.claim(&signer).await.unwrap_err(), AdmissionError::TaskInfrastructure);
    assert_eq!(env.inflight(&signer), 0);
    assert_eq!(env.store.counter(StoreKey::TaskBudget), 0);
    assert_eq!(env.reputation(&signer).await, (3, 0));
}

#[tokio::test]
async fn early_redelivery_is_delayed_not_reassigned() {
    let (a, b) = (secret(1), secret(2)); let env = env(&[&a, &b]).await;
    env.queue.push(1);
    let held = env.claim(&a).await.unwrap();
    env.store.advance(45_000);
    env.queue.push(1); env.queue.push(2);
    let other = env.claim(&b).await.unwrap();
    assert_eq!(other.payload, b"task 2");
    assert_eq!(env.queue.count("delay", 1), 1);
    assert_eq!(*env.queue.delays.lock().unwrap(), vec![15_000], "redeliver when the lease can expire, not a full lease later");
    assert_eq!(env.flow.leases().lease_record(&job(1)).await.unwrap().unwrap().owner, held.lease.owner);
}

#[tokio::test]
async fn invalid_proof_revokes_and_frees_the_job() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    let task = env.claim(&signer).await.unwrap();
    let SubmitOutcome::Revoked(receipt) = env.submit(&signer, &task.lease, b"bad").await.unwrap() else { panic!() };
    assert_eq!(receipt.new_generation, 1);
    assert_eq!(env.reputation(&signer).await, (0, 1));
    assert_eq!(env.queue.count("release", 1), 1);
    assert_eq!(env.inflight(&signer), 0);
    assert!(env.pipeline.published.lock().unwrap().is_empty());
}

#[tokio::test]
async fn verifier_failure_and_tampered_bytes_never_punish() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    let task = env.claim(&signer).await.unwrap();
    // Bytes that do not match the signed proof hash.
    let signed = submission(&task.lease, b"proof");
    let request = submit_auth(&signer, 0, &signed, env.store.time());
    assert_eq!(env.flow.submit(request, signed, b"other bytes".to_vec()).await.unwrap_err(), AdmissionError::InvalidRequest);
    assert_eq!(env.flow.leases().lease_record(&job(1)).await.unwrap().unwrap().state, LeaseState::Leased);
    assert_eq!(env.submit(&signer, &task.lease, b"boom").await.unwrap_err(), AdmissionError::TaskInfrastructure);
    assert_eq!(env.reputation(&signer).await, (3, 0));
    assert_eq!((env.inflight(&signer), env.queue.count("release", 1)), (0, 1));
    // The job comes back as a new lease version.
    env.queue.push(1);
    let again = env.claim(&signer).await.unwrap();
    assert_eq!(again.lease.lease_version, 1);
    let SubmitOutcome::Accepted { .. } = env.submit(&signer, &again.lease, b"proof").await.unwrap() else { panic!() };
    assert_eq!(env.reputation(&signer).await, (4, 0));
}

#[tokio::test]
async fn publication_failure_is_retried_from_the_outbox_without_rescoring() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    let task = env.claim(&signer).await.unwrap();
    env.pipeline.fail_publish.store(true, Ordering::SeqCst);
    let SubmitOutcome::Accepted { published: false, receipt } = env.submit(&signer, &task.lease, b"proof").await.unwrap() else { panic!() };
    assert_eq!(env.queue.count("complete", 1), 0, "no ACK before durable publication");
    // The worker retries: same receipt, still unpublished, no extra score.
    let SubmitOutcome::Accepted { published: false, receipt: again } = env.submit(&signer, &task.lease, b"proof").await.unwrap() else { panic!() };
    assert_eq!(again, receipt);
    let report = env.flow.maintain(10).await.unwrap();
    assert_eq!((report.published, report.publish_failures), (0, 1));
    env.pipeline.fail_publish.store(false, Ordering::SeqCst);
    assert_eq!(env.flow.maintain(10).await.unwrap().published, 1);
    assert_eq!(env.flow.maintain(10).await.unwrap().published, 0);
    assert_eq!(env.pipeline.published.lock().unwrap()[&task.lease.job_key], 1);
    assert_eq!(env.queue.count("complete", 1), 1);
    assert_eq!(env.reputation(&signer).await, (4, 0));
    assert_eq!(env.pipeline.staged.lock().unwrap().len(), 1, "one verification, one staged proof");
}

#[tokio::test]
async fn maintenance_keeps_live_leases_and_reclaims_silent_workers() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    env.claim(&signer).await.unwrap();
    let report = env.flow.maintain(10).await.unwrap();
    assert_eq!((report.kept_alive, report.reconcile.leases_expired), (1, 0));
    env.store.advance(60_000);
    let report = env.flow.maintain(10).await.unwrap();
    assert_eq!((report.kept_alive, report.reconcile.leases_expired), (0, 1));
    assert_eq!(env.reputation(&signer).await, (2, 0));
}

#[tokio::test]
async fn invalid_proofs_only_return_the_job_unless_attribution_is_enabled() {
    let signer = secret(1); let mut env = env(&[&signer]).await;
    env.flow = TaskFlow::new(env.flow.leases().clone(), env.queue.clone(), env.pipeline.clone(), FlowConfig::default());
    env.queue.push(1);
    let task = env.claim(&signer).await.unwrap();
    assert_eq!(task.lease.reward_tag, digest(&key(&signer).0), "the worker's own signed tag");
    assert_eq!(env.submit(&signer, &task.lease, b"bad").await.unwrap(), SubmitOutcome::Rejected);
    assert_eq!(env.reputation(&signer).await, (3, 0));
    assert_eq!((env.inflight(&signer), env.queue.count("release", 1)), (0, 1));
}

#[tokio::test]
async fn redelivery_of_a_published_job_is_acknowledged_not_looped() {
    let signer = secret(1); let env = env(&[&signer]).await;
    env.queue.push(1);
    let task = env.claim(&signer).await.unwrap();
    env.submit(&signer, &task.lease, b"proof").await.unwrap();
    assert_eq!(env.queue.count("complete", 1), 1);
    // The fire-and-forget ACK was lost and the message comes back.
    env.queue.push(1);
    assert_eq!(env.claim(&signer).await.unwrap_err(), AdmissionError::NoWork);
    assert_eq!((env.queue.count("complete", 1), env.queue.count("delay", 1)), (2, 0));
    assert_eq!(env.pipeline.published.lock().unwrap()[&task.lease.job_key], 1);
}
