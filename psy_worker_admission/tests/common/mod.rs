#![allow(dead_code)]
use std::{collections::{BTreeMap, HashMap}, sync::{Arc, Mutex}, sync::atomic::{AtomicBool, AtomicU64, Ordering}};

use async_trait::async_trait;
use psy_worker_admission::{*, store::*};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub fn scope() -> AdmissionScope {
    AdmissionScope { network_id: FixedBytes([1; 32]), admission_epoch: FixedBytes([2; 32]), node_type: 1, realm_id: 7, realm_sub_id: 3 }
}
pub fn secret(n: u8) -> SecretKey { SecretKey::from_byte_array([n; 32]).unwrap() }
pub fn key(secret: &SecretKey) -> WorkerKey { FixedBytes(PublicKey::from_secret_key(&Secp256k1::new(), secret).serialize()) }
pub fn auth(secret: &SecretKey, method: AdmissionMethod, generation: u64, payload_hash: Hash32, now: u64) -> RequestAuth {
    let mut request = RequestAuth { scope: scope(), public_key: key(secret), method, request_id: FixedBytes::random(),
        issued_at_ms: now, valid_until_ms: now + 60_000, expected_generation: generation, payload_hash, signature: FixedBytes([0; 64]) };
    request.sign(secret).unwrap();
    request
}
pub fn solve(challenge: &PowChallenge) -> PowSolution {
    PowSolution { challenge_id: challenge.id(), nonce: solve_batch(challenge, 0, 1_000_000, &AtomicBool::new(false)).unwrap().unwrap() }
}

pub struct MemoryStore {
    pub now: AtomicU64,
    pub available: AtomicBool,
    pub records: Mutex<HashMap<WorkerKey, Vec<u8>>>,
    /// Lease-side records and counters by `StoreKey::name`; worker records stay in `records`.
    pub kv: Mutex<HashMap<String, Vec<u8>>>,
    pub indexes: Mutex<HashMap<&'static str, BTreeMap<String, u64>>>,
    /// Serializes every mutation, as a single Redis primary would.
    serial: Mutex<()>,
}
impl MemoryStore {
    pub fn new() -> Arc<Self> { Arc::new(Self { now: AtomicU64::new(1_000_000), available: AtomicBool::new(true), records: Mutex::new(HashMap::new()),
            kv: Mutex::new(HashMap::new()), indexes: Mutex::new(HashMap::new()), serial: Mutex::new(()) }) }
    pub fn time(&self) -> u64 { self.now.load(Ordering::SeqCst) }
    pub fn advance(&self, duration: u64) { self.now.fetch_add(duration, Ordering::SeqCst); }
    fn check(&self) -> Result<()> { if self.available.load(Ordering::SeqCst) { Ok(()) } else { Err(AdmissionError::StoreUnavailable) } }
}
#[async_trait]
impl AtomicAdmissionStore for MemoryStore {
    async fn request_budget(&self, _: Option<WorkerKey>) -> Result<u64> { self.check()?; Ok(self.time()) }
    async fn load(&self, key: WorkerKey) -> Result<Snapshot> {
        self.check()?;
        let raw = self.records.lock().unwrap().get(&key).cloned();
        // Force transitions to encounter stale snapshots in concurrent tests.
        tokio::task::yield_now().await;
        Ok(Snapshot { raw, now_ms: self.time() })
    }
    async fn compare_exchange(&self, key: WorkerKey, write: CasWrite) -> Result<bool> {
        self.check()?;
        let _serial = self.serial.lock().unwrap();
        let mut records = self.records.lock().unwrap();
        if records.get(&key) != write.expected.as_ref() || self.time() >= write.valid_before_ms { return Ok(false); }
        records.insert(key, write.replacement);
        Ok(true)
    }
}

impl MemoryStore {
    fn get(&self, key: &StoreKey) -> Option<Vec<u8>> {
        match key {
            StoreKey::Worker(worker) => self.records.lock().unwrap().get(worker).cloned(),
            other => self.kv.lock().unwrap().get(&other.name()).cloned(),
        }
    }
    fn put(&self, key: &StoreKey, value: Option<Vec<u8>>) {
        match (key, value) {
            (StoreKey::Worker(worker), Some(value)) => { self.records.lock().unwrap().insert(*worker, value); }
            (StoreKey::Worker(worker), None) => { self.records.lock().unwrap().remove(worker); }
            (other, Some(value)) => { self.kv.lock().unwrap().insert(other.name(), value); }
            (other, None) => { self.kv.lock().unwrap().remove(&other.name()); }
        }
    }
    pub fn counter(&self, key: StoreKey) -> u64 {
        self.get(&key).map(|v| String::from_utf8(v).unwrap().parse().unwrap()).unwrap_or(0)
    }
    pub fn index_len(&self, index: StoreIndex) -> usize {
        self.indexes.lock().unwrap().get(index.name()).map_or(0, |i| i.len())
    }
}

/// Same semantics as the Redis script: all checks, then all writes, under one lock.
#[async_trait]
impl AtomicLeaseStore for MemoryStore {
    async fn load_many(&self, keys: &[StoreKey]) -> Result<MultiSnapshot> {
        self.check()?;
        let values = keys.iter().map(|k| self.get(k)).collect();
        tokio::task::yield_now().await;
        Ok(MultiSnapshot { values, now_ms: self.time() })
    }
    async fn commit(&self, transaction: Transaction) -> Result<Commit> {
        self.check()?;
        let _serial = self.serial.lock().unwrap();
        if self.time() >= transaction.valid_before_ms { return Ok(Commit::Retry); }
        for record in &transaction.records {
            if self.get(&record.key) != record.expected { return Ok(Commit::Retry); }
        }
        let mut counts = Vec::new();
        for (i, counter) in transaction.counters.iter().enumerate() {
            let value = self.counter(counter.key) as i64 + counter.delta as i64;
            if value < 0 { return Err(AdmissionError::StateCorrupt); }
            if counter.delta > 0 && value as u64 > counter.limit { return Ok(Commit::Limit(i)); }
            counts.push(value as u64);
        }
        for record in transaction.records {
            match record.put {
                Put::Keep => {}
                Put::Delete => self.put(&record.key, None),
                Put::Set { value, .. } => self.put(&record.key, Some(value)),
            }
        }
        for (counter, value) in transaction.counters.iter().zip(counts) {
            self.put(&counter.key, (value > 0).then(|| value.to_string().into_bytes()));
        }
        let mut indexes = self.indexes.lock().unwrap();
        for write in transaction.indexes {
            let index = indexes.entry(write.index.name()).or_default();
            match write.score { Some(score) => { index.insert(write.member.name(), score); } None => { index.remove(&write.member.name()); } }
        }
        Ok(Commit::Done)
    }
    async fn range(&self, index: StoreIndex, max_score: Option<u64>, limit: usize) -> Result<(Vec<StoreKey>, u64)> {
        self.check()?;
        let now = self.time();
        let max = max_score.unwrap_or(now);
        let indexes = self.indexes.lock().unwrap();
        let mut members: Vec<(u64, String)> = indexes.get(index.name()).map(|i| i.iter().filter(|(_, s)| **s <= max).map(|(m, s)| (*s, m.clone())).collect()).unwrap_or_default();
        members.sort();
        Ok((members.into_iter().take(limit).map(|(_, m)| StoreKey::parse(&m)).collect::<Result<_>>()?, now))
    }
}

pub fn memory_service(store: Arc<MemoryStore>) -> AdmissionService {
    AdmissionService::new(scope(), AdmissionPolicy::for_base_bits(8), store).unwrap()
}

pub fn lease_service(store: Arc<MemoryStore>, policy: AdmissionPolicy) -> LeaseService {
    LeaseService::new(scope(), policy, store).unwrap()
}

pub fn job(n: u64) -> lease::JobInstance {
    lease::JobInstance { unique_pending_id: 40 + n, unique_proc_id: 9, job_id: lease::JobIdBytes(n.to_le_bytes().to_vec()) }
}

pub fn binding(n: u64, lease_ms: u64) -> lease::JobBinding {
    lease::JobBinding { job: job(n), reward_tag: digest(&n.to_le_bytes()), task_digest: digest(b"task"), lease_ms }
}

pub fn claim_auth(secret: &SecretKey, generation: u64, now: u64) -> RequestAuth {
    auth(secret, AdmissionMethod::ClaimTask, generation, digest(b"claim"), now)
}

pub fn submission(lease: &lease::LeaseRecord, proof: &[u8]) -> lease::ProofSubmission {
    lease::ProofSubmission { job: lease.job.clone(), lease_id: lease.lease_id, lease_version: lease.lease_version,
        reward_tag: lease.reward_tag, proof_hash: digest(proof) }
}

pub fn submit_auth(secret: &SecretKey, generation: u64, submission: &lease::ProofSubmission, now: u64) -> RequestAuth {
    auth(secret, AdmissionMethod::SubmitProof, generation, submission.payload_hash(&scope()), now)
}

pub async fn activate(service: &AdmissionService, secret: &SecretKey, generation: u64, now: u64) -> (RequestAuth, PowSolution, service::ActivationResponse) {
    let challenge = service.get_challenge(auth(secret, AdmissionMethod::GetChallenge, generation, empty_payload(), now)).await.unwrap();
    let solution = solve(&challenge.challenge);
    let request = auth(secret, AdmissionMethod::SubmitPow, generation, solution.payload_hash(), now);
    let response = service.submit_pow(request.clone(), solution.clone()).await.unwrap();
    (request, solution, response)
}
