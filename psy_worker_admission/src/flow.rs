//! The V2 task flow: claim, verify, accept, publish and ACK, in the order the
//! design requires. Edges supply the queue and the proof pipeline; this module
//! owns every decision about who is scored, when the queue is told what, and
//! what happens when a step fails half way.
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{lease::*, protocol::*, store::RevocationReceipt, AdmissionError as Error, LeaseService, Result};

/// Who a job is being prepared for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimContext { pub owner: WorkerKey, pub reward_tag: Hash32 }

/// One queue delivery the edge has pulled and prepared for a worker.
pub struct TaskDelivery {
    pub binding: JobBinding,
    /// Response body for the worker (job metadata, witness, child proofs and tags).
    pub payload: Vec<u8>,
}

/// Queue side of an edge. Implementations keep the ACK handle of each delivery
/// they returned and must never acknowledge one delivery through a handle a
/// later delivery can overwrite.
#[async_trait]
pub trait TaskQueue: Send + Sync {
    /// Pull and prepare the next job. `Err` means the queue or its inputs failed.
    /// The returned binding must carry `claim.reward_tag`.
    async fn next(&self, claim: &ClaimContext) -> std::result::Result<Option<TaskDelivery>, TaskFailure>;
    /// Rebuild the payload of a job this edge or another one already leased,
    /// for a claim retried after its response was lost.
    async fn reload(&self, lease: &LeaseRecord) -> std::result::Result<Vec<u8>, TaskFailure>;
    /// Keep a delivery whose lease is live from being redelivered.
    async fn progress(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure>;
    /// Redeliver no sooner than `delay_ms`: the job is held by a live lease.
    async fn delay(&self, job: &JobInstance, delay_ms: u64) -> std::result::Result<(), TaskFailure>;
    /// Make the job available again now. Nobody holds it.
    async fn release(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure>;
    /// Final ACK. Only after the result is durably published.
    async fn complete(&self, job: &JobInstance) -> std::result::Result<(), TaskFailure>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict { Valid, Invalid }

/// Proof side of an edge.
#[async_trait]
pub trait ProofPipeline: Send + Sync {
    /// `Invalid` only for a deterministic verification failure of these bytes
    /// against the lease's inputs. Anything that may be the edge's fault is `Err`.
    async fn verify(&self, lease: &LeaseRecord, proof: &[u8]) -> std::result::Result<Verdict, TaskFailure>;
    /// Write the proof to immutable, content-addressed storage; return the address.
    async fn stage(&self, lease: &LeaseRecord, proof: &[u8]) -> std::result::Result<Hash32, TaskFailure>;
    /// Write canonical proof, reward tree and dependents from the staged proof.
    /// Must be idempotent: it is retried after crashes.
    async fn publish(&self, lease: &LeaseRecord) -> std::result::Result<(), TaskFailure>;
}

/// An infrastructure failure inside an adapter, with a message for logs only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskFailure(pub String);

impl<E: std::fmt::Display> From<E> for TaskFailure {
    fn from(error: E) -> Self { Self(error.to_string()) }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowConfig {
    pub max_proof_bytes: usize,
    /// ZK verifications running at once on this edge.
    pub verify_concurrency: usize,
    /// Deliveries skipped per claim because a live lease holds them.
    pub max_busy_skips: usize,
    /// Zero a worker on a deterministic verification failure. Off by default:
    /// until the verifier's failure classes are proven, an `Invalid` verdict
    /// only returns the job, so a verifier fault cannot punish honest workers.
    pub attribute_invalid_proofs: bool,
}

impl Default for FlowConfig {
    fn default() -> Self { Self { max_proof_bytes: 4 << 20, verify_concurrency: 4, max_busy_skips: 8, attribute_invalid_proofs: false } }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimedTask { pub claim: ClaimRecord, pub lease: LeaseRecord, pub payload: Vec<u8> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmitOutcome {
    Accepted { receipt: AcceptedReceipt, published: bool },
    /// The identical submission is being verified by another request.
    InProgress,
    /// The lease lost its owner generation while verifying; nothing counted.
    Stale,
    /// Deterministically invalid or a signed tag mismatch: identity revoked.
    Revoked(RevocationReceipt),
    /// Verification failed but punishment is disabled; the job was returned.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct MaintenanceReport {
    pub reconcile: ReconcileReport,
    pub kept_alive: u32,
    pub published: u32,
    pub publish_failures: u32,
}

#[derive(Clone)]
pub struct TaskFlow<Q, P> {
    leases: LeaseService,
    queue: Arc<Q>,
    pipeline: Arc<P>,
    config: FlowConfig,
    verifications: Arc<Semaphore>,
}

impl<Q: TaskQueue, P: ProofPipeline> TaskFlow<Q, P> {
    pub fn new(leases: LeaseService, queue: Arc<Q>, pipeline: Arc<P>, config: FlowConfig) -> Self {
        let verifications = Arc::new(Semaphore::new(config.verify_concurrency.max(1)));
        Self { leases, queue, pipeline, config, verifications }
    }
    pub fn leases(&self) -> &LeaseService { &self.leases }

    /// Reserve capacity, then pull a job, then bind it. Capacity is returned if
    /// no job could be bound; a retried request gets its original task back.
    pub async fn claim(&self, auth: RequestAuth, request: ClaimRequest) -> Result<ClaimedTask> {
        let owner = auth.public_key;
        let request_id = auth.request_id;
        let reserved = self.leases.reserve_claim(auth, request.payload_hash()).await?;
        match reserved.claim.state {
            ClaimState::Leased => {
                let lease = reserved.lease.ok_or(Error::StateCorrupt)?;
                // A lease the request created but that has since closed is not a task any more.
                if !lease.state.holds_capacity() || reserved.claim.lease.as_ref().map(|l| l.lease_id) != Some(lease.lease_id) {
                    return Err(Error::LeaseStale);
                }
                let payload = self.queue.reload(&lease).await.map_err(|_| Error::TaskInfrastructure)?;
                return Ok(ClaimedTask { claim: reserved.claim, lease, payload });
            }
            ClaimState::Released => return Err(Error::NoWork),
            ClaimState::Reserved => {}
        }
        match self.bind_next(ClaimContext { owner, reward_tag: request.reward_tag }, request_id).await {
            Ok(task) => Ok(task),
            Err(error) => {
                // Whatever went wrong, the reservation must not linger until its TTL.
                match self.leases.release_claim(owner, request_id).await {
                    Ok(_) | Err(Error::RequestConflict) => {}
                    Err(release_error) => tracing::warn!(%release_error, "claim release failed; the reconciler will return it"),
                }
                Err(error)
            }
        }
    }

    async fn bind_next(&self, context: ClaimContext, request_id: RequestId) -> Result<ClaimedTask> {
        let owner = context.owner;
        for _ in 0..=self.config.max_busy_skips {
            let delivery = match self.queue.next(&context).await {
                Ok(Some(delivery)) => delivery,
                Ok(None) => return Err(Error::NoWork),
                Err(failure) => { tracing::warn!(failure = %failure.0, "task queue failed"); return Err(Error::TaskInfrastructure); }
            };
            let job = delivery.binding.job.clone();
            if delivery.binding.reward_tag != context.reward_tag {
                self.queue_call(self.queue.release(&job).await);
                return Err(Error::TaskInfrastructure);
            }
            match self.leases.attach_lease(owner, request_id, delivery.binding).await {
                Ok(lease) => {
                    let claim = self.leases.claim_record(owner, request_id).await?.ok_or(Error::StateCorrupt)?;
                    return Ok(ClaimedTask { claim, lease, payload: delivery.payload });
                }
                Err(Error::LeaseBusy) => {
                    // Early redelivery of a job someone holds: push it past the
                    // lease and try the next one. Never reassign it.
                    let now = self.leases.store_time().await?;
                    let wait = match self.leases.lease_record(&job).await? {
                        Some(lease) => lease.hard_deadline_ms.max(lease.verification_deadline_ms).saturating_sub(now).max(1_000),
                        None => 1_000,
                    };
                    self.queue_call(self.queue.delay(&job, wait).await);
                }
                Err(Error::JobAlreadyAccepted) => {
                    // Accepted but maybe not published yet: the publisher ACKs it.
                    self.queue_call(self.queue.delay(&job, 5_000).await);
                }
                Err(error) => {
                    self.queue_call(self.queue.release(&job).await);
                    return Err(error);
                }
            }
        }
        Err(Error::NoWork)
    }

    fn queue_call(&self, result: std::result::Result<(), TaskFailure>) {
        if let Err(failure) = result { tracing::warn!(failure = %failure.0, "queue control message failed"); }
    }

    /// Verify a signed submission for the submitter's own current lease, then
    /// accept it, publish it and ACK the queue, or punish only what is
    /// attributable.
    pub async fn submit(&self, auth: RequestAuth, submission: ProofSubmission, proof: Vec<u8>) -> Result<SubmitOutcome> {
        // The signature covers the proof hash, not the bytes. Mismatched bytes
        // are someone else's tampering until proven otherwise: reject, no penalty.
        if proof.len() > self.config.max_proof_bytes || digest(&proof) != submission.proof_hash { return Err(Error::InvalidRequest); }
        let job_key = submission.job.key(self.leases.admission().scope());
        let ticket = match self.leases.begin_verification(auth, submission).await? {
            SubmissionOutcome::Verify(ticket) => ticket,
            SubmissionOutcome::InProgress(_) => return Ok(SubmitOutcome::InProgress),
            SubmissionOutcome::Accepted(receipt) => {
                let accepted = self.leases.lease_by_key(job_key).await?.ok_or(Error::StateCorrupt)?;
                let published = self.publish_job(&accepted).await;
                return Ok(SubmitOutcome::Accepted { receipt, published });
            }
            SubmissionOutcome::TagMismatch(evidence) => {
                return Ok(SubmitOutcome::Revoked(self.leases.apply_attributable_violation(&evidence).await?));
            }
        };
        let lease = self.leases.lease_by_key(ticket.job_key).await?.ok_or(Error::StateCorrupt)?;
        let verdict = {
            let _permit = self.verifications.acquire().await.map_err(|_| Error::TaskInfrastructure)?;
            self.pipeline.verify(&lease, &proof).await
        };
        match verdict {
            Ok(Verdict::Valid) => {}
            Ok(Verdict::Invalid) if !self.config.attribute_invalid_proofs => {
                tracing::warn!(job_key = ?ticket.job_key, "proof failed verification; punishment disabled, job returned");
                self.leases.fail_verification(&ticket).await?;
                self.queue_call(self.queue.release(&lease.job).await);
                return Ok(SubmitOutcome::Rejected);
            }
            Ok(Verdict::Invalid) => {
                let receipt = self.leases.apply_attributable_violation(&ticket.invalid_proof()).await?;
                self.queue_call(self.queue.release(&lease.job).await);
                return Ok(SubmitOutcome::Revoked(receipt));
            }
            Err(failure) => {
                tracing::warn!(failure = %failure.0, "proof verification failed internally");
                return self.give_back(&ticket, &lease).await;
            }
        }
        let staged = match self.pipeline.stage(&lease, &proof).await {
            Ok(staged) => staged,
            Err(failure) => {
                tracing::warn!(failure = %failure.0, "proof staging failed");
                return self.give_back(&ticket, &lease).await;
            }
        };
        match self.leases.accept_verified_result(&ticket, staged).await? {
            AcceptOutcome::Stale => {
                self.queue_call(self.queue.release(&lease.job).await);
                Ok(SubmitOutcome::Stale)
            }
            AcceptOutcome::Accepted(receipt) => {
                let accepted = self.leases.lease_by_key(ticket.job_key).await?.ok_or(Error::StateCorrupt)?;
                let published = self.publish_job(&accepted).await;
                Ok(SubmitOutcome::Accepted { receipt, published })
            }
        }
    }

    async fn give_back(&self, ticket: &VerificationTicket, lease: &LeaseRecord) -> Result<SubmitOutcome> {
        self.leases.fail_verification(ticket).await?;
        self.queue_call(self.queue.release(&lease.job).await);
        Err(Error::TaskInfrastructure)
    }

    /// Publish, mark published, then ACK. A failure anywhere leaves the outbox
    /// entry for `maintain` to retry; nothing is scored again.
    async fn publish_job(&self, lease: &LeaseRecord) -> bool {
        let Some(receipt) = lease.accepted.as_ref() else { return false };
        if lease.state == LeaseState::Accepted {
            if let Err(failure) = self.pipeline.publish(lease).await {
                tracing::warn!(failure = %failure.0, "publication failed; left in the outbox");
                return false;
            }
            if let Err(error) = self.leases.mark_published(lease.job_key, receipt.event_id).await {
                tracing::warn!(%error, "marking publication failed; left in the outbox");
                return false;
            }
        }
        match self.queue.complete(&lease.job).await {
            Ok(()) => true,
            Err(failure) => { tracing::warn!(failure = %failure.0, "final ACK failed; redelivery will find the job accepted"); false }
        }
    }

    /// Run periodically on every edge: reclaim what is due, keep live leases'
    /// deliveries from being redelivered, and drain the outbox.
    pub async fn maintain(&self, limit: usize) -> Result<MaintenanceReport> {
        let mut report = MaintenanceReport { reconcile: self.leases.reconcile(limit).await?, ..Default::default() };
        for lease in self.leases.live_leases(limit).await? {
            match self.queue.progress(&lease.job).await {
                Ok(()) => report.kept_alive += 1,
                Err(failure) => tracing::debug!(failure = %failure.0, "progress ACK failed"),
            }
        }
        for lease in self.leases.pending_publications(limit).await? {
            if self.publish_job(&lease).await { report.published += 1 } else { report.publish_failures += 1 }
        }
        Ok(report)
    }
}
