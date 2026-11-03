use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{protocol::*, AdmissionError as Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionState { NeedsPow, Active }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationReceipt {
    pub receipt_id: Hash32,
    pub request_id: RequestId,
    pub request_hash: Hash32,
    pub challenge_id: Hash32,
    #[serde(with = "decimal")]
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationReceipt {
    pub event_id: Hash32,
    pub evidence_hash: Hash32,
    #[serde(with = "decimal")]
    pub from_generation: u64,
    #[serde(with = "decimal")]
    pub new_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRecord {
    pub schema_version: u16,
    pub scope_hash: Hash32,
    pub policy_hash: Hash32,
    pub public_key: WorkerKey,
    #[serde(with = "decimal")]
    pub generation: u64,
    pub state: AdmissionState,
    pub reputation: u8,
    #[serde(with = "decimal")]
    pub violations: u64,
    #[serde(with = "decimal")]
    pub cooldown_until_ms: u64,
    pub pending_challenge: Option<PowChallenge>,
    pub last_activation: Option<ActivationReceipt>,
    pub last_revocation: Option<RevocationReceipt>,
}

impl WorkerRecord {
    pub fn new(scope: &AdmissionScope, policy: &AdmissionPolicy, public_key: WorkerKey) -> Self {
        Self { schema_version: 1, scope_hash: scope.hash(), policy_hash: policy.hash(), public_key,
            generation: 0, state: AdmissionState::NeedsPow, reputation: 0, violations: 0, cooldown_until_ms: 0,
            pending_challenge: None, last_activation: None, last_revocation: None }
    }
    pub fn validate(&self, scope: &AdmissionScope, policy: &AdmissionPolicy, key: WorkerKey) -> Result<()> {
        if self.schema_version != 1 || self.scope_hash != scope.hash() || self.policy_hash != policy.hash()
            || self.public_key != key || self.reputation > 10
            || (self.state == AdmissionState::Active) != (self.reputation > 0)
            || (self.state == AdmissionState::Active && (self.pending_challenge.is_some() || self.last_activation.is_none())) {
            return Err(Error::StateCorrupt);
        }
        if let Some(challenge) = &self.pending_challenge {
            challenge.validate().map_err(|_| Error::StateCorrupt)?;
            if challenge.scope != *scope || challenge.worker_public_key != key || challenge.generation != self.generation
                || challenge.policy_version != policy.version || challenge.difficulty_bits != policy.bits_for(self.violations) {
                return Err(Error::StateCorrupt);
            }
        }
        if self.last_activation.as_ref().is_some_and(|r| r.generation > self.generation)
            || (self.state == AdmissionState::Active && self.last_activation.as_ref().is_some_and(|r| r.generation != self.generation)) {
            return Err(Error::StateCorrupt);
        }
        Ok(())
    }
    pub fn provisional(&self) -> bool {
        self.generation == 0 && self.last_activation.is_none() && self.last_revocation.is_none() && self.violations == 0
    }
}

pub struct Snapshot { pub raw: Option<Vec<u8>>, pub now_ms: u64 }

pub struct CasWrite {
    pub expected: Option<Vec<u8>>,
    pub replacement: Vec<u8>,
    pub valid_before_ms: u64,
    /// Only never-activated, never-penalized records may expire.
    pub provisional_ttl_ms: Option<u64>,
    /// None removes this identity from the pending-challenge capacity index.
    pub pending_expires_at_ms: Option<u64>,
    pub audit_json: Vec<u8>,
}

/// Trusted storage primitive. All admission state changes go through the
/// service's typed transitions, never a public arbitrary reputation setter.
#[async_trait]
pub trait AtomicAdmissionStore: Send + Sync {
    /// None consumes the shared request budget; Some consumes the authenticated
    /// public key budget. Invalid signatures must not consume a victim's budget.
    async fn request_budget(&self, key: Option<WorkerKey>) -> Result<u64>;
    async fn load(&self, key: WorkerKey) -> Result<Snapshot>;
    async fn compare_exchange(&self, key: WorkerKey, write: CasWrite) -> Result<bool>;
}

/// A record the lease transactions may read or write. The store maps each one
/// to a key inside the scope's hash slot; callers never supply raw key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreKey {
    Worker(WorkerKey),
    /// Claim receipt, keyed by the claimant and its request ID.
    Claim(WorkerKey, RequestId),
    /// Lease state of one job instance, keyed by `JobInstance::key`.
    Lease(Hash32),
    /// Number of reservations and leases one public key holds, across generations.
    Inflight(WorkerKey),
    TaskBudget,
    LowReputationBudget,
}

impl StoreKey {
    /// Stable, prefix-free name inside the scope namespace. Index members use it too.
    pub fn name(&self) -> String {
        match self {
            Self::Worker(key) => format!("worker:{}", hex::encode(key.0)),
            Self::Claim(key, request) => format!("claim:{}:{}", hex::encode(key.0), hex::encode(request.0)),
            Self::Lease(job) => format!("lease:{}", hex::encode(job.0)),
            Self::Inflight(key) => format!("inflight:{}", hex::encode(key.0)),
            Self::TaskBudget => "tasks:total".into(),
            Self::LowReputationBudget => "tasks:low".into(),
        }
    }
    pub fn parse(name: &str) -> Result<Self> {
        fn fixed<const N: usize>(text: &str) -> Result<FixedBytes<N>> {
            serde_json::from_value(serde_json::Value::String(text.into())).map_err(|_| Error::StateCorrupt)
        }
        let parts: Vec<&str> = name.split(':').collect();
        match parts.as_slice() {
            ["worker", key] => Ok(Self::Worker(fixed(key)?)),
            ["claim", key, request] => Ok(Self::Claim(fixed(key)?, fixed(request)?)),
            ["lease", job] => Ok(Self::Lease(fixed(job)?)),
            ["inflight", key] => Ok(Self::Inflight(fixed(key)?)),
            ["tasks", "total"] => Ok(Self::TaskBudget),
            ["tasks", "low"] => Ok(Self::LowReputationBudget),
            _ => Err(Error::StateCorrupt),
        }
    }
}

/// Sorted sets whose members are `StoreKey::name` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StoreIndex {
    /// Reservations and leases by the time they must be reclaimed.
    Due,
    /// Accepted results not yet durably published, by acceptance time.
    Outbox,
}

impl StoreIndex {
    pub fn name(self) -> &'static str { match self { Self::Due => "due", Self::Outbox => "outbox" } }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Put {
    /// Compare only.
    Keep,
    /// Replace the value; `None` keeps no TTL, removing any existing one.
    Set { value: Vec<u8>, ttl_ms: Option<u64> },
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordWrite { pub key: StoreKey, pub expected: Option<Vec<u8>>, pub put: Put }

/// Counter change. Increments fail the whole transaction when the result would
/// exceed `limit`; decrements below zero are corrupt state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterDelta { pub key: StoreKey, pub delta: i32, pub limit: u64 }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexWrite { pub index: StoreIndex, pub member: StoreKey, pub score: Option<u64> }

/// One atomic multi-record change. Every comparison, type check and counter
/// bound is evaluated before any write, so a refused transaction writes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Refused when the store's clock has reached this time; u64::MAX disables.
    pub valid_before_ms: u64,
    pub records: Vec<RecordWrite>,
    pub counters: Vec<CounterDelta>,
    pub indexes: Vec<IndexWrite>,
    pub audit_json: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {
    Done,
    /// A compared record changed or the deadline passed; reload and retry.
    Retry,
    /// Counter at this position in `Transaction::counters` would exceed its limit.
    Limit(usize),
}

pub struct MultiSnapshot { pub values: Vec<Option<Vec<u8>>>, pub now_ms: u64 }

/// Trusted multi-record primitive for leases. The lease service is the only
/// caller; it never exposes arbitrary writes.
#[async_trait]
pub trait AtomicLeaseStore: AtomicAdmissionStore {
    async fn load_many(&self, keys: &[StoreKey]) -> Result<MultiSnapshot>;
    async fn commit(&self, transaction: Transaction) -> Result<Commit>;
    /// Members scored at or below `max_score` (None: the store's current time),
    /// lowest first, plus the store time.
    async fn range(&self, index: StoreIndex, max_score: Option<u64>, limit: usize) -> Result<(Vec<StoreKey>, u64)>;
}
