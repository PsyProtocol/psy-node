//! Task reservations and leases. Every change to a worker's reputation caused
//! by a task, and every change to a lease, goes through one multi-record
//! transaction here; nothing in this module is wired into the legacy task RPCs.
use std::{fmt, sync::Arc};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::{protocol::*, service::AdmissionService, store::*, AdmissionError as Error, Result};

const RETRIES: usize = 32;

/// Canonical serialized job ID of 1 to 64 bytes, lowercase hex on the wire.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct JobIdBytes(pub Vec<u8>);

impl fmt::Debug for JobIdBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&hex::encode(&self.0)) }
}
impl Serialize for JobIdBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}
impl<'de> Deserialize<'de> for JobIdBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.is_empty() || text.len() > 128 || text.len() % 2 != 0
            || text.bytes().any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b)) {
            return Err(de::Error::custom("invalid job ID hex"));
        }
        hex::decode(text).map(Self).map_err(de::Error::custom)
    }
}

/// One proving task instance. The same job ID in another checkpoint or
/// processing instance is a different task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobInstance {
    #[serde(with = "decimal")]
    pub unique_pending_id: u64,
    #[serde(with = "decimal")]
    pub unique_proc_id: u64,
    pub job_id: JobIdBytes,
}

impl JobInstance {
    pub fn validate(&self) -> Result<()> {
        if self.job_id.0.is_empty() || self.job_id.0.len() > 64 { return Err(Error::InvalidRequest); }
        Ok(())
    }
    pub fn key(&self, scope: &AdmissionScope) -> Hash32 {
        let mut bytes = b"psy-worker-job-instance-v1\0".to_vec();
        scope.encode(&mut bytes);
        bytes.extend(self.unique_pending_id.to_le_bytes());
        bytes.extend(self.unique_proc_id.to_le_bytes());
        bytes.push(self.job_id.0.len() as u8);
        bytes.extend(&self.job_id.0);
        digest(&bytes)
    }
}

/// Capacity pool a reservation was charged to. Release always uses the pool
/// recorded at reservation time, whatever the reputation is by then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pool { Low, Standard }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimState {
    /// Holds capacity; waiting for the edge to attach a job.
    Reserved,
    /// Capacity moved to the lease.
    Leased,
    /// No job was attached; capacity returned without penalty.
    Released,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRef {
    pub job_key: Hash32,
    pub lease_id: Hash32,
    #[serde(with = "decimal")]
    pub lease_version: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub schema_version: u16,
    pub scope_hash: Hash32,
    pub public_key: WorkerKey,
    pub request_id: RequestId,
    pub request_hash: Hash32,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub pool: Pool,
    pub state: ClaimState,
    #[serde(with = "decimal")]
    pub reserved_at_ms: u64,
    #[serde(with = "decimal")]
    pub reserved_until_ms: u64,
    pub lease: Option<LeaseRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Leased,
    /// One submission is being verified; its digest is fixed.
    Verifying,
    /// The single point where a result counts: scored once and queued for publication.
    Accepted,
    Published,
    /// Hard deadline passed without a submission accepted for verification.
    Expired,
    /// Returned without penalty: verification overran or failed internally.
    Released,
    /// Owner was revoked or changed generation; the result can never count.
    Revoked,
}

impl LeaseState {
    pub fn holds_capacity(self) -> bool { matches!(self, Self::Leased | Self::Verifying) }
    pub fn is_accepted(self) -> bool { matches!(self, Self::Accepted | Self::Published) }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseReason { Timeout, VerificationTimeout, InfrastructureFailure, GenerationChanged, Violation }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedReceipt {
    pub event_id: Hash32,
    pub submission_digest: Hash32,
    /// Content address of the immutable staged proof the publisher reads.
    pub staged_proof: Hash32,
    #[serde(with = "decimal")]
    pub accepted_at_ms: u64,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub reputation_after: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LeaseRecord {
    pub schema_version: u16,
    pub scope_hash: Hash32,
    pub job: JobInstance,
    pub job_key: Hash32,
    pub lease_id: Hash32,
    #[serde(with = "decimal")]
    pub lease_version: u64,
    pub owner: WorkerKey,
    #[serde(with = "decimal")]
    pub owner_generation: u64,
    pub pool: Pool,
    pub claim_request_id: RequestId,
    pub reward_tag: Hash32,
    pub task_digest: Hash32,
    #[serde(with = "decimal")]
    pub claimed_at_ms: u64,
    #[serde(with = "decimal")]
    pub hard_deadline_ms: u64,
    /// Zero unless verifying.
    #[serde(with = "decimal")]
    pub verification_deadline_ms: u64,
    pub state: LeaseState,
    pub submission_digest: Option<Hash32>,
    /// Signing hash of the request that started verification: punishment evidence.
    pub submission_request: Option<Hash32>,
    pub accepted: Option<AcceptedReceipt>,
    pub close_reason: Option<CloseReason>,
}

impl LeaseRecord {
    fn lease_ref(&self) -> LeaseRef {
        LeaseRef { job_key: self.job_key, lease_id: self.lease_id, lease_version: self.lease_version }
    }
    fn ticket(&self) -> Result<VerificationTicket> {
        Ok(VerificationTicket { job_key: self.job_key, lease_id: self.lease_id, lease_version: self.lease_version,
            owner: self.owner, owner_generation: self.owner_generation,
            submission_digest: self.submission_digest.ok_or(Error::StateCorrupt)?,
            submission_request: self.submission_request.ok_or(Error::StateCorrupt)? })
    }
}

/// What the edge attaches to a reservation once it has a queue message and its inputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobBinding {
    pub job: JobInstance,
    pub reward_tag: Hash32,
    /// Digest of metadata, witness and expected inputs handed to the worker.
    pub task_digest: Hash32,
    /// Hard deadline for this circuit class, fixed at claim time.
    #[serde(with = "decimal")]
    pub lease_ms: u64,
}

/// Signed by the worker; every field enters the request's payload hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofSubmission {
    pub job: JobInstance,
    pub lease_id: Hash32,
    #[serde(with = "decimal")]
    pub lease_version: u64,
    pub reward_tag: Hash32,
    pub proof_hash: Hash32,
}

impl ProofSubmission {
    pub fn payload_hash(&self, scope: &AdmissionScope) -> Hash32 {
        let mut bytes = b"psy-worker-proof-submission-v1\0".to_vec();
        bytes.extend(self.job.key(scope).0);
        bytes.extend(self.lease_id.0);
        bytes.extend(self.lease_version.to_le_bytes());
        bytes.extend(self.reward_tag.0);
        bytes.extend(self.proof_hash.0);
        digest(&bytes)
    }
}

/// Exactly one verification slot per lease. Identical submissions share it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationTicket {
    pub job_key: Hash32,
    pub lease_id: Hash32,
    #[serde(with = "decimal")]
    pub lease_version: u64,
    pub owner: WorkerKey,
    #[serde(with = "decimal")]
    pub owner_generation: u64,
    pub submission_digest: Hash32,
    pub submission_request: Hash32,
}

impl VerificationTicket {
    /// Evidence for a deterministic verification failure of this exact submission.
    pub fn invalid_proof(&self) -> ViolationEvidence {
        ViolationEvidence { kind: ViolationKind::InvalidProof, job_key: self.job_key, lease_id: self.lease_id,
            lease_version: self.lease_version, owner: self.owner, owner_generation: self.owner_generation,
            submission_digest: self.submission_digest, submission_request: self.submission_request }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationKind { InvalidProof, TagMismatch }

/// Attributable only because the current owner signed `submission_request`
/// against its own current lease. Never built from an unsigned or stale request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationEvidence {
    pub kind: ViolationKind,
    pub job_key: Hash32,
    pub lease_id: Hash32,
    #[serde(with = "decimal")]
    pub lease_version: u64,
    pub owner: WorkerKey,
    #[serde(with = "decimal")]
    pub owner_generation: u64,
    pub submission_digest: Hash32,
    pub submission_request: Hash32,
}

impl ViolationEvidence {
    pub fn hash(&self) -> Hash32 {
        let mut bytes = b"psy-worker-violation-evidence-v1\0".to_vec();
        bytes.push(match self.kind { ViolationKind::InvalidProof => 1, ViolationKind::TagMismatch => 2 });
        bytes.extend(self.job_key.0);
        bytes.extend(self.lease_id.0);
        bytes.extend(self.lease_version.to_le_bytes());
        bytes.extend(self.owner.0);
        bytes.extend(self.owner_generation.to_le_bytes());
        bytes.extend(self.submission_digest.0);
        bytes.extend(self.submission_request.0);
        digest(&bytes)
    }
    /// One violation per lease instance, whatever the retry.
    pub fn event_id(&self) -> Hash32 {
        lease_event(b"psy-worker-violation-v1\0", self.job_key, self.lease_id, self.lease_version)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimResponse { pub claim: ClaimRecord, pub lease: Option<LeaseRecord> }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionOutcome {
    /// The caller now owns the verification slot and must run ZK verification.
    Verify(VerificationTicket),
    /// The same submission is already being verified elsewhere.
    InProgress(VerificationTicket),
    Accepted(AcceptedReceipt),
    /// Signed by the current owner with a tag other than its lease's.
    TagMismatch(ViolationEvidence),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptOutcome { Accepted(AcceptedReceipt), Stale }

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReconcileReport {
    pub claims_released: u32,
    pub leases_expired: u32,
    pub reputation_decrements: u32,
    pub revocations: u32,
    pub verifications_released: u32,
}

fn lease_event(domain: &[u8], job_key: Hash32, lease_id: Hash32, lease_version: u64) -> Hash32 {
    let mut bytes = domain.to_vec();
    bytes.extend(job_key.0);
    bytes.extend(lease_id.0);
    bytes.extend(lease_version.to_le_bytes());
    digest(&bytes)
}

fn json<T: Serialize>(value: &T) -> Result<Vec<u8>> { serde_json::to_vec(value).map_err(|_| Error::StateCorrupt) }

fn set(key: StoreKey, expected: &Option<Vec<u8>>, value: Vec<u8>, ttl_ms: Option<u64>) -> RecordWrite {
    RecordWrite { key, expected: expected.clone(), put: Put::Set { value, ttl_ms } }
}
fn keep(key: StoreKey, expected: &Option<Vec<u8>>) -> RecordWrite {
    RecordWrite { key, expected: expected.clone(), put: Put::Keep }
}
fn due(member: StoreKey, score: Option<u64>) -> IndexWrite { IndexWrite { index: StoreIndex::Due, member, score } }

#[derive(Clone)]
pub struct LeaseService {
    admission: AdmissionService,
    store: Arc<dyn AtomicLeaseStore>,
}

impl LeaseService {
    pub fn new<S: AtomicLeaseStore + 'static>(scope: AdmissionScope, policy: AdmissionPolicy, store: Arc<S>) -> Result<Self> {
        let admission = AdmissionService::new(scope, policy, store.clone())?;
        Ok(Self { admission, store })
    }
    pub fn admission(&self) -> &AdmissionService { &self.admission }
    fn scope(&self) -> &AdmissionScope { self.admission.scope() }
    fn policy(&self) -> &AdmissionPolicy { self.admission.policy() }

    fn worker(&self, key: WorkerKey, raw: &Option<Vec<u8>>, now_ms: u64) -> Result<WorkerRecord> {
        self.admission.decode(key, &Snapshot { raw: raw.clone(), now_ms })
    }
    fn claim(&self, raw: &Option<Vec<u8>>, key: WorkerKey, request_id: RequestId) -> Result<Option<ClaimRecord>> {
        let Some(raw) = raw else { return Ok(None) };
        let claim: ClaimRecord = serde_json::from_slice(raw).map_err(|_| Error::StateCorrupt)?;
        let leased = claim.state == ClaimState::Leased;
        if claim.schema_version != 1 || claim.scope_hash != self.scope().hash() || claim.public_key != key
            || claim.request_id != request_id || leased != claim.lease.is_some() || claim.reserved_until_ms <= claim.reserved_at_ms {
            return Err(Error::StateCorrupt);
        }
        Ok(Some(claim))
    }
    fn lease(&self, raw: &Option<Vec<u8>>, job_key: Hash32) -> Result<Option<LeaseRecord>> {
        let Some(raw) = raw else { return Ok(None) };
        let lease: LeaseRecord = serde_json::from_slice(raw).map_err(|_| Error::StateCorrupt)?;
        let verifying = lease.state == LeaseState::Verifying;
        if lease.schema_version != 1 || lease.scope_hash != self.scope().hash() || lease.job_key != job_key
            || lease.job.key(self.scope()) != job_key || lease.job.validate().is_err()
            || lease.hard_deadline_ms <= lease.claimed_at_ms
            || (verifying && (lease.submission_digest.is_none() || lease.submission_request.is_none() || lease.verification_deadline_ms == 0))
            || lease.state.is_accepted() != lease.accepted.is_some() {
            return Err(Error::StateCorrupt);
        }
        Ok(Some(lease))
    }
    /// Capacity charged on reservation and returned exactly once when the
    /// reservation or its lease stops holding it.
    fn capacity(&self, owner: WorkerKey, pool: Pool, delta: i32, reputation: u8) -> Vec<CounterDelta> {
        let limit = |value: u64| if delta > 0 { value } else { u64::MAX };
        let mut counters = vec![
            CounterDelta { key: StoreKey::Inflight(owner), delta, limit: limit(AdmissionPolicy::max_inflight(reputation) as u64) },
            CounterDelta { key: StoreKey::TaskBudget, delta, limit: limit(self.policy().task_budget as u64) },
        ];
        if pool == Pool::Low {
            counters.push(CounterDelta { key: StoreKey::LowReputationBudget, delta, limit: limit(self.policy().low_reputation_budget as u64) });
        }
        counters
    }
    fn audit(&self, event: &str, member: &StoreKey, now_ms: u64, detail: serde_json::Value) -> Result<Vec<u8>> {
        json(&serde_json::json!({ "event": event, "member": member.name(), "at_ms": now_ms.to_string(), "detail": detail }))
    }

    async fn claim_response(&self, claim: ClaimRecord) -> Result<ClaimResponse> {
        let lease = match &claim.lease {
            Some(lease_ref) => {
                let snapshot = self.store.load_many(&[StoreKey::Lease(lease_ref.job_key)]).await?;
                let lease = self.lease(&snapshot.values[0], lease_ref.job_key)?.ok_or(Error::StateCorrupt)?;
                // The receipt names the lease this request created, even if the job
                // has since been reassigned; callers compare lease IDs.
                Some(lease)
            }
            None => None,
        };
        Ok(ClaimResponse { claim, lease })
    }

    /// Step 1 of a claim: charge one unit of per-identity and scope capacity to
    /// this request ID. Retrying the same signed request returns the original
    /// claim, and its lease once attached, without charging again.
    pub async fn reserve_claim(&self, auth: RequestAuth, payload_hash: Hash32) -> Result<ClaimResponse> {
        self.admission.authenticate(&auth, AdmissionMethod::ClaimTask, payload_hash).await?;
        let owner = auth.public_key;
        let claim_key = StoreKey::Claim(owner, auth.request_id);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[StoreKey::Worker(owner), claim_key]).await?;
            let now = snapshot.now_ms;
            if let Some(claim) = self.claim(&snapshot.values[1], owner, auth.request_id)? {
                if claim.request_hash != auth.signing_hash() { return Err(Error::RequestConflict); }
                return self.claim_response(claim).await;
            }
            if now >= auth.valid_until_ms { return Err(Error::RequestExpired); }
            let worker = self.worker(owner, &snapshot.values[0], now)?;
            if worker.generation != auth.expected_generation { return Err(Error::AdmissionStale); }
            if worker.state != AdmissionState::Active { return Err(Error::PowRequired); }
            let pool = if worker.reputation <= 3 { Pool::Low } else { Pool::Standard };
            let reserved_until_ms = now.checked_add(self.policy().reservation_ttl_ms).ok_or(Error::StateCorrupt)?;
            let claim = ClaimRecord { schema_version: 1, scope_hash: self.scope().hash(), public_key: owner,
                request_id: auth.request_id, request_hash: auth.signing_hash(), generation: worker.generation, pool,
                state: ClaimState::Reserved, reserved_at_ms: now, reserved_until_ms, lease: None };
            // No TTL while reserved: an expiring key would leak its capacity.
            let transaction = Transaction { valid_before_ms: auth.valid_until_ms,
                records: vec![keep(StoreKey::Worker(owner), &snapshot.values[0]), set(claim_key, &None, json(&claim)?, None)],
                counters: self.capacity(owner, pool, 1, worker.reputation),
                indexes: vec![due(claim_key, Some(reserved_until_ms))],
                audit_json: self.audit("claim_reserved", &claim_key, now, serde_json::json!({ "pool": pool }))? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(ClaimResponse { claim, lease: None }),
                Commit::Retry => continue,
                Commit::Limit(0) => return Err(Error::InflightLimit),
                Commit::Limit(_) => return Err(Error::Capacity),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Step 2: bind the reserved capacity to one job instance. A job held by a
    /// live lease is never reassigned: an early queue redelivery gets LeaseBusy
    /// and must be delayed, not handed to another worker.
    pub async fn attach_lease(&self, owner: WorkerKey, request_id: RequestId, binding: JobBinding) -> Result<LeaseRecord> {
        binding.job.validate()?;
        if binding.lease_ms == 0 || binding.lease_ms > self.policy().max_lease_ms { return Err(Error::InvalidRequest); }
        let job_key = binding.job.key(self.scope());
        let claim_key = StoreKey::Claim(owner, request_id);
        let lease_key = StoreKey::Lease(job_key);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[claim_key, lease_key, StoreKey::Worker(owner)]).await?;
            let now = snapshot.now_ms;
            let mut claim = self.claim(&snapshot.values[0], owner, request_id)?.ok_or(Error::LeaseStale)?;
            match claim.state {
                ClaimState::Released => return Err(Error::LeaseStale),
                ClaimState::Leased => {
                    let lease_ref = claim.lease.as_ref().ok_or(Error::StateCorrupt)?;
                    if lease_ref.job_key != job_key { return Err(Error::RequestConflict); }
                    let lease = self.lease(&snapshot.values[1], job_key)?.ok_or(Error::StateCorrupt)?;
                    if lease.lease_id != lease_ref.lease_id { return Err(Error::LeaseStale); }
                    return Ok(lease);
                }
                ClaimState::Reserved => {}
            }
            if now >= claim.reserved_until_ms { return Err(Error::LeaseStale); }
            let worker = self.worker(owner, &snapshot.values[2], now)?;
            if worker.generation != claim.generation || worker.state != AdmissionState::Active {
                // Revoked between reservation and attach: return the capacity
                // now so the queue message can go to someone else.
                self.release_claim(owner, request_id).await?;
                return Err(Error::AdmissionStale);
            }
            let lease_version = match self.lease(&snapshot.values[1], job_key)? {
                None => 0,
                Some(existing) if existing.state.holds_capacity() => return Err(Error::LeaseBusy),
                Some(existing) if existing.state.is_accepted() => return Err(Error::JobAlreadyAccepted),
                Some(existing) => existing.lease_version.checked_add(1).ok_or(Error::StateCorrupt)?,
            };
            let mut id_bytes = b"psy-worker-lease-id-v1\0".to_vec();
            id_bytes.extend(job_key.0);
            id_bytes.extend(lease_version.to_le_bytes());
            id_bytes.extend(claim.request_hash.0);
            let lease_id = digest(&id_bytes);
            let hard_deadline_ms = now.checked_add(binding.lease_ms).ok_or(Error::StateCorrupt)?;
            let lease = LeaseRecord { schema_version: 1, scope_hash: self.scope().hash(), job: binding.job.clone(), job_key,
                lease_id, lease_version, owner, owner_generation: claim.generation, pool: claim.pool, claim_request_id: request_id,
                reward_tag: binding.reward_tag, task_digest: binding.task_digest, claimed_at_ms: now, hard_deadline_ms,
                verification_deadline_ms: 0, state: LeaseState::Leased, submission_digest: None, submission_request: None,
                accepted: None, close_reason: None };
            claim.state = ClaimState::Leased;
            claim.lease = Some(lease.lease_ref());
            let receipt_ttl = binding.lease_ms.saturating_add(self.policy().receipt_retention_ms);
            let transaction = Transaction { valid_before_ms: claim.reserved_until_ms,
                records: vec![set(claim_key, &snapshot.values[0], json(&claim)?, Some(receipt_ttl)),
                    set(lease_key, &snapshot.values[1], json(&lease)?, None), keep(StoreKey::Worker(owner), &snapshot.values[2])],
                counters: vec![], indexes: vec![due(claim_key, None), due(lease_key, Some(hard_deadline_ms))],
                audit_json: self.audit("lease_attached", &lease_key, now, serde_json::json!({ "lease_version": lease_version.to_string() }))? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(lease),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Return a reservation that got no job (empty queue, missing inputs, edge
    /// error). Never a penalty. Idempotent.
    pub async fn release_claim(&self, owner: WorkerKey, request_id: RequestId) -> Result<ClaimRecord> {
        self.release_reserved(owner, request_id, false).await?.ok_or(Error::LeaseStale)
    }

    async fn release_reserved(&self, owner: WorkerKey, request_id: RequestId, only_if_due: bool) -> Result<Option<ClaimRecord>> {
        let claim_key = StoreKey::Claim(owner, request_id);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[claim_key]).await?;
            let now = snapshot.now_ms;
            let Some(mut claim) = self.claim(&snapshot.values[0], owner, request_id)? else {
                if only_if_due { self.drop_due_member(claim_key, &snapshot.values[0], now).await?; }
                return Ok(None);
            };
            match claim.state {
                ClaimState::Released => return Ok(Some(claim)),
                ClaimState::Leased if only_if_due => { self.drop_due_member(claim_key, &snapshot.values[0], now).await?; return Ok(None); }
                ClaimState::Leased => return Err(Error::RequestConflict),
                ClaimState::Reserved if only_if_due && now < claim.reserved_until_ms => return Ok(None),
                ClaimState::Reserved => {}
            }
            claim.state = ClaimState::Released;
            let transaction = Transaction { valid_before_ms: u64::MAX,
                records: vec![set(claim_key, &snapshot.values[0], json(&claim)?, Some(self.policy().receipt_retention_ms))],
                counters: self.capacity(owner, claim.pool, -1, 0), indexes: vec![due(claim_key, None)],
                audit_json: self.audit("claim_released", &claim_key, now, serde_json::json!({ "due": only_if_due }))? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(Some(claim)),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    async fn drop_due_member(&self, member: StoreKey, expected: &Option<Vec<u8>>, now: u64) -> Result<()> {
        let transaction = Transaction { valid_before_ms: u64::MAX, records: vec![keep(member, expected)], counters: vec![],
            indexes: vec![due(member, None)], audit_json: self.audit("due_dropped", &member, now, serde_json::Value::Null)? };
        self.store.commit(transaction).await.map(|_| ())
    }

    /// Admit a signed submission to the lease's single verification slot. Only
    /// the current owner, in the lease's generation and before its hard
    /// deadline, gets a slot. Nothing here punishes anyone.
    pub async fn begin_verification(&self, auth: RequestAuth, submission: ProofSubmission) -> Result<SubmissionOutcome> {
        submission.job.validate()?;
        let payload = submission.payload_hash(self.scope());
        self.admission.authenticate(&auth, AdmissionMethod::SubmitProof, payload).await?;
        let owner = auth.public_key;
        let job_key = submission.job.key(self.scope());
        let lease_key = StoreKey::Lease(job_key);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[lease_key, StoreKey::Worker(owner)]).await?;
            let now = snapshot.now_ms;
            // No lease, or someone else's: reject without guessing ownership.
            let mut lease = self.lease(&snapshot.values[0], job_key)?.ok_or(Error::LeaseStale)?;
            if lease.owner != owner || lease.lease_id != submission.lease_id || lease.lease_version != submission.lease_version {
                return Err(Error::LeaseStale);
            }
            match lease.state {
                LeaseState::Accepted | LeaseState::Published => {
                    let receipt = lease.accepted.clone().ok_or(Error::StateCorrupt)?;
                    if receipt.submission_digest == payload { return Ok(SubmissionOutcome::Accepted(receipt)); }
                    return Err(Error::JobAlreadyAccepted);
                }
                LeaseState::Verifying if lease.submission_digest == Some(payload) => return Ok(SubmissionOutcome::InProgress(lease.ticket()?)),
                LeaseState::Verifying => return Err(Error::LeaseBusy),
                LeaseState::Expired | LeaseState::Released | LeaseState::Revoked => return Err(Error::LeaseStale),
                LeaseState::Leased => {}
            }
            if auth.expected_generation != lease.owner_generation { return Err(Error::AdmissionStale); }
            let worker = self.worker(owner, &snapshot.values[1], now)?;
            if worker.generation != lease.owner_generation || worker.state != AdmissionState::Active { return Err(Error::AdmissionStale); }
            // Expiry and its single penalty belong to the reconciler.
            if now >= lease.hard_deadline_ms { return Err(Error::LeaseStale); }
            if now >= auth.valid_until_ms { return Err(Error::RequestExpired); }
            if submission.reward_tag != lease.reward_tag {
                return Ok(SubmissionOutcome::TagMismatch(ViolationEvidence { kind: ViolationKind::TagMismatch, job_key,
                    lease_id: lease.lease_id, lease_version: lease.lease_version, owner, owner_generation: lease.owner_generation,
                    submission_digest: payload, submission_request: auth.signing_hash() }));
            }
            let verification_deadline_ms = now.checked_add(self.policy().verification_ttl_ms).ok_or(Error::StateCorrupt)?;
            lease.state = LeaseState::Verifying;
            lease.submission_digest = Some(payload);
            lease.submission_request = Some(auth.signing_hash());
            lease.verification_deadline_ms = verification_deadline_ms;
            let transaction = Transaction { valid_before_ms: lease.hard_deadline_ms.min(auth.valid_until_ms),
                records: vec![set(lease_key, &snapshot.values[0], json(&lease)?, None), keep(StoreKey::Worker(owner), &snapshot.values[1])],
                counters: vec![], indexes: vec![due(lease_key, Some(verification_deadline_ms))],
                audit_json: self.audit("verification_started", &lease_key, now, serde_json::Value::Null)? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(SubmissionOutcome::Verify(lease.ticket()?)),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// The only place a task result counts. Call after ZK verification passed
    /// and the proof is staged immutably under `staged_proof`. Re-checks the
    /// owner's generation: a revocation that committed first wins.
    pub async fn accept_verified_result(&self, ticket: &VerificationTicket, staged_proof: Hash32) -> Result<AcceptOutcome> {
        let lease_key = StoreKey::Lease(ticket.job_key);
        let worker_key = StoreKey::Worker(ticket.owner);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[lease_key, worker_key]).await?;
            let now = snapshot.now_ms;
            let mut lease = self.lease(&snapshot.values[0], ticket.job_key)?.ok_or(Error::LeaseStale)?;
            if lease.owner != ticket.owner || lease.lease_id != ticket.lease_id || lease.lease_version != ticket.lease_version {
                return Err(Error::LeaseStale);
            }
            match lease.state {
                LeaseState::Accepted | LeaseState::Published => {
                    let receipt = lease.accepted.clone().ok_or(Error::StateCorrupt)?;
                    if receipt.submission_digest != ticket.submission_digest { return Err(Error::LeaseStale); }
                    return Ok(AcceptOutcome::Accepted(receipt));
                }
                LeaseState::Verifying if lease.submission_digest == Some(ticket.submission_digest) => {}
                LeaseState::Verifying => return Err(Error::LeaseStale),
                _ => return Ok(AcceptOutcome::Stale),
            }
            let mut worker = self.worker(ticket.owner, &snapshot.values[1], now)?;
            let counters = self.capacity(lease.owner, lease.pool, -1, 0);
            let current = worker.generation == lease.owner_generation && worker.state == AdmissionState::Active;
            let (records, indexes, event, outcome) = if current {
                let reputation_after = worker.reputation.saturating_add(1).min(10);
                let receipt = AcceptedReceipt { event_id: lease_event(b"psy-worker-accepted-v1\0", lease.job_key, lease.lease_id, lease.lease_version),
                    submission_digest: ticket.submission_digest, staged_proof, accepted_at_ms: now,
                    generation: lease.owner_generation, reputation_after };
                worker.reputation = reputation_after;
                worker.validate(self.scope(), self.policy(), ticket.owner)?;
                lease.state = LeaseState::Accepted;
                lease.accepted = Some(receipt.clone());
                (vec![set(lease_key, &snapshot.values[0], json(&lease)?, None), set(worker_key, &snapshot.values[1], json(&worker)?, None)],
                    vec![due(lease_key, None), IndexWrite { index: StoreIndex::Outbox, member: lease_key, score: Some(now) }],
                    "result_accepted", AcceptOutcome::Accepted(receipt))
            } else {
                lease.state = LeaseState::Revoked;
                lease.close_reason = Some(CloseReason::GenerationChanged);
                (vec![set(lease_key, &snapshot.values[0], json(&lease)?, None), keep(worker_key, &snapshot.values[1])],
                    vec![due(lease_key, None)], "result_stale", AcceptOutcome::Stale)
            };
            let transaction = Transaction { valid_before_ms: u64::MAX, records, counters, indexes,
                audit_json: self.audit(event, &lease_key, now, serde_json::Value::Null)? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(outcome),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Verification crashed, timed out internally or a dependency was missing:
    /// an infrastructure failure. The job returns to the queue; nobody is scored.
    pub async fn fail_verification(&self, ticket: &VerificationTicket) -> Result<()> {
        let lease_key = StoreKey::Lease(ticket.job_key);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[lease_key]).await?;
            let mut lease = self.lease(&snapshot.values[0], ticket.job_key)?.ok_or(Error::LeaseStale)?;
            if lease.lease_id != ticket.lease_id || lease.lease_version != ticket.lease_version { return Err(Error::LeaseStale); }
            match lease.state {
                LeaseState::Verifying if lease.submission_digest == Some(ticket.submission_digest) => {}
                LeaseState::Released => return Ok(()),
                _ => return Err(Error::LeaseStale),
            }
            if !self.close_without_penalty(&mut lease, &snapshot, CloseReason::InfrastructureFailure).await? { continue; }
            return Ok(());
        }
        Err(Error::RequestConflict)
    }

    async fn close_without_penalty(&self, lease: &mut LeaseRecord, snapshot: &MultiSnapshot, reason: CloseReason) -> Result<bool> {
        let lease_key = StoreKey::Lease(lease.job_key);
        lease.state = LeaseState::Released;
        lease.close_reason = Some(reason);
        let transaction = Transaction { valid_before_ms: u64::MAX,
            records: vec![set(lease_key, &snapshot.values[0], json(lease)?, None)],
            counters: self.capacity(lease.owner, lease.pool, -1, 0), indexes: vec![due(lease_key, None)],
            audit_json: self.audit("lease_released", &lease_key, snapshot.now_ms, serde_json::json!({ "reason": reason }))? };
        match self.store.commit(transaction).await? {
            Commit::Done => Ok(true),
            Commit::Retry => Ok(false),
            Commit::Limit(_) => Err(Error::StateCorrupt),
        }
    }

    /// Zero the owner's reputation and close the lease in one transaction.
    /// Only for evidence produced by `begin_verification` (tag mismatch) or
    /// by a deterministic ZK failure of a ticket's submission.
    pub async fn apply_attributable_violation(&self, evidence: &ViolationEvidence) -> Result<RevocationReceipt> {
        let lease_key = StoreKey::Lease(evidence.job_key);
        let worker_key = StoreKey::Worker(evidence.owner);
        let event_id = evidence.event_id();
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[lease_key, worker_key]).await?;
            let now = snapshot.now_ms;
            let mut worker = self.worker(evidence.owner, &snapshot.values[1], now)?;
            if let Some(receipt) = &worker.last_revocation {
                if receipt.event_id == event_id {
                    if receipt.evidence_hash != evidence.hash() { return Err(Error::RequestConflict); }
                    return Ok(receipt.clone());
                }
            }
            let mut lease = self.lease(&snapshot.values[0], evidence.job_key)?.ok_or(Error::LeaseStale)?;
            if lease.owner != evidence.owner || lease.lease_id != evidence.lease_id || lease.lease_version != evidence.lease_version
                || lease.owner_generation != evidence.owner_generation {
                return Err(Error::LeaseStale);
            }
            let applies = match evidence.kind {
                ViolationKind::InvalidProof => lease.state == LeaseState::Verifying
                    && lease.submission_digest == Some(evidence.submission_digest)
                    && lease.submission_request == Some(evidence.submission_request),
                ViolationKind::TagMismatch => lease.state == LeaseState::Leased,
            };
            if !applies { return Err(Error::LeaseStale); }
            if worker.generation != lease.owner_generation { return Err(Error::AdmissionStale); }
            let receipt = self.admission.revoke(&mut worker, now, event_id, evidence.hash(), true)?;
            worker.validate(self.scope(), self.policy(), evidence.owner)?;
            lease.state = LeaseState::Revoked;
            lease.close_reason = Some(CloseReason::Violation);
            let transaction = Transaction { valid_before_ms: u64::MAX,
                records: vec![set(lease_key, &snapshot.values[0], json(&lease)?, None), set(worker_key, &snapshot.values[1], json(&worker)?, None)],
                counters: self.capacity(lease.owner, lease.pool, -1, 0), indexes: vec![due(lease_key, None)],
                audit_json: self.audit("verified_violation", &lease_key, now, serde_json::json!({ "kind": evidence.kind, "revocation": receipt }))? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(receipt),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Reclaim everything past its deadline, whether or not the worker ever
    /// comes back. Safe to run concurrently on every edge.
    pub async fn reconcile(&self, limit: usize) -> Result<ReconcileReport> {
        let (members, _) = self.store.range(StoreIndex::Due, None, limit).await?;
        let mut report = ReconcileReport::default();
        for member in members {
            match member {
                StoreKey::Claim(owner, request_id) => {
                    if self.release_reserved(owner, request_id, true).await?.is_some_and(|c| c.state == ClaimState::Released) {
                        report.claims_released += 1;
                    }
                }
                StoreKey::Lease(job_key) => self.expire_lease(job_key, &mut report).await?,
                _ => return Err(Error::StateCorrupt),
            }
        }
        Ok(report)
    }

    async fn expire_lease(&self, job_key: Hash32, report: &mut ReconcileReport) -> Result<()> {
        let lease_key = StoreKey::Lease(job_key);
        for _ in 0..RETRIES {
            let first = self.store.load_many(&[lease_key]).await?;
            let Some(owner) = self.lease(&first.values[0], job_key)?.map(|l| l.owner) else {
                return self.drop_due_member(lease_key, &first.values[0], first.now_ms).await;
            };
            let worker_key = StoreKey::Worker(owner);
            let snapshot = self.store.load_many(&[lease_key, worker_key]).await?;
            let now = snapshot.now_ms;
            let mut lease = self.lease(&snapshot.values[0], job_key)?.ok_or(Error::StateCorrupt)?;
            if lease.owner != owner { continue; }
            match lease.state {
                LeaseState::Verifying if now >= lease.verification_deadline_ms => {
                    if !self.close_without_penalty(&mut lease, &snapshot, CloseReason::VerificationTimeout).await? { continue; }
                    report.verifications_released += 1;
                    return Ok(());
                }
                LeaseState::Leased if now >= lease.hard_deadline_ms => {}
                LeaseState::Leased | LeaseState::Verifying => return Ok(()),
                _ => return self.drop_due_member(lease_key, &snapshot.values[0], now).await,
            }
            let mut worker = self.worker(owner, &snapshot.values[1], now)?;
            let mut decremented = false;
            let mut revoked = false;
            let worker_write = if worker.generation == lease.owner_generation && worker.state == AdmissionState::Active {
                decremented = true;
                if worker.reputation == 1 {
                    // Down to zero. Not attributable: no violation count, no longer cooldown.
                    let event = lease_event(b"psy-worker-timeout-v1\0", lease.job_key, lease.lease_id, lease.lease_version);
                    self.admission.revoke(&mut worker, now, event, event, false)?;
                    revoked = true;
                } else {
                    worker.reputation -= 1;
                }
                worker.validate(self.scope(), self.policy(), owner)?;
                set(worker_key, &snapshot.values[1], json(&worker)?, None)
            } else {
                // A previous generation's lease: reclaim it, score nothing.
                keep(worker_key, &snapshot.values[1])
            };
            lease.state = LeaseState::Expired;
            lease.close_reason = Some(CloseReason::Timeout);
            let transaction = Transaction { valid_before_ms: u64::MAX,
                records: vec![set(lease_key, &snapshot.values[0], json(&lease)?, None), worker_write],
                counters: self.capacity(owner, lease.pool, -1, 0), indexes: vec![due(lease_key, None)],
                audit_json: self.audit("lease_expired", &lease_key, now, serde_json::json!({ "decremented": decremented, "revoked": revoked }))? };
            match self.store.commit(transaction).await? {
                Commit::Done => {
                    report.leases_expired += 1;
                    report.reputation_decrements += decremented as u32;
                    report.revocations += revoked as u32;
                    return Ok(());
                }
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Accepted results the publisher still has to write durably, oldest first.
    pub async fn pending_publications(&self, limit: usize) -> Result<Vec<LeaseRecord>> {
        let (members, _) = self.store.range(StoreIndex::Outbox, Some(u64::MAX), limit).await?;
        let mut leases = Vec::with_capacity(members.len());
        for member in members {
            let StoreKey::Lease(job_key) = member else { return Err(Error::StateCorrupt) };
            let snapshot = self.store.load_many(&[member]).await?;
            let lease = self.lease(&snapshot.values[0], job_key)?.ok_or(Error::StateCorrupt)?;
            if lease.state.is_accepted() { leases.push(lease); }
        }
        Ok(leases)
    }

    /// Call only after canonical proof, reward tree and dependents are durably
    /// written; the final queue ACK follows this. Idempotent.
    pub async fn mark_published(&self, job_key: Hash32, event_id: Hash32) -> Result<()> {
        let lease_key = StoreKey::Lease(job_key);
        for _ in 0..RETRIES {
            let snapshot = self.store.load_many(&[lease_key]).await?;
            let mut lease = self.lease(&snapshot.values[0], job_key)?.ok_or(Error::LeaseStale)?;
            if lease.accepted.as_ref().map(|r| r.event_id) != Some(event_id) { return Err(Error::LeaseStale); }
            if lease.state == LeaseState::Published { return Ok(()); }
            lease.state = LeaseState::Published;
            let transaction = Transaction { valid_before_ms: u64::MAX,
                records: vec![set(lease_key, &snapshot.values[0], json(&lease)?, None)], counters: vec![],
                indexes: vec![IndexWrite { index: StoreIndex::Outbox, member: lease_key, score: None }],
                audit_json: self.audit("result_published", &lease_key, snapshot.now_ms, serde_json::Value::Null)? };
            match self.store.commit(transaction).await? {
                Commit::Done => return Ok(()),
                Commit::Retry => continue,
                Commit::Limit(_) => return Err(Error::StateCorrupt),
            }
        }
        Err(Error::RequestConflict)
    }

    /// Leases still holding capacity, for queue keepalive. Oldest deadline first.
    pub async fn live_leases(&self, limit: usize) -> Result<Vec<LeaseRecord>> {
        let (members, _) = self.store.range(StoreIndex::Due, Some(u64::MAX), limit).await?;
        let mut leases = Vec::new();
        for member in members {
            let StoreKey::Lease(job_key) = member else { continue };
            let snapshot = self.store.load_many(&[member]).await?;
            if let Some(lease) = self.lease(&snapshot.values[0], job_key)? {
                if lease.state.holds_capacity() { leases.push(lease); }
            }
        }
        Ok(leases)
    }

    pub async fn lease_record(&self, job: &JobInstance) -> Result<Option<LeaseRecord>> {
        self.lease_by_key(job.key(self.scope())).await
    }

    /// The authoritative clock all deadlines are measured against.
    pub async fn store_time(&self) -> Result<u64> { Ok(self.store.load_many(&[]).await?.now_ms) }

    pub async fn lease_by_key(&self, job_key: Hash32) -> Result<Option<LeaseRecord>> {
        let snapshot = self.store.load_many(&[StoreKey::Lease(job_key)]).await?;
        self.lease(&snapshot.values[0], job_key)
    }

    pub async fn claim_record(&self, owner: WorkerKey, request_id: RequestId) -> Result<Option<ClaimRecord>> {
        let snapshot = self.store.load_many(&[StoreKey::Claim(owner, request_id)]).await?;
        self.claim(&snapshot.values[0], owner, request_id)
    }
}
