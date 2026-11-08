mod common;
use std::{process::{Child, Command, Stdio}, sync::Arc, time::Duration};

use common::*;
use psy_worker_admission::{*, redis_store::RedisAdmissionStore, store::*};
use redis::AsyncCommands;
use tempfile::TempDir;

struct RedisProcess { child: Child, directory: TempDir, url: String }
impl RedisProcess {
    async fn start() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let child = Self::spawn(&directory);
        let url = format!("redis+unix://{}", directory.path().join("redis.sock").display());
        let process = Self { child, directory, url };
        process.wait_ready().await;
        process
    }
    fn spawn(directory: &TempDir) -> Child {
        Command::new("redis-server").args(["--port", "0", "--save", "", "--appendonly", "yes", "--appendfsync", "always", "--loglevel", "warning"])
            .arg("--dir").arg(directory.path()).arg("--unixsocket").arg(directory.path().join("redis.sock"))
            .stdout(Stdio::null()).stderr(Stdio::null()).spawn().expect("redis-server is required for this ignored test")
    }
    async fn wait_ready(&self) {
        for _ in 0..100 {
            if self.connection().await.is_ok() { return; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("Redis test process did not become ready");
    }
    async fn connection(&self) -> redis::RedisResult<redis::aio::MultiplexedConnection> {
        redis::Client::open(self.url.as_str())?.get_multiplexed_async_connection().await
    }
    async fn restart(&mut self) {
        self.child.kill().unwrap(); self.child.wait().unwrap();
        self.child = Self::spawn(&self.directory); self.wait_ready().await;
    }
    async fn service(&self, policy: &AdmissionPolicy) -> (AdmissionService, RedisAdmissionStore) {
        let store = RedisAdmissionStore::connect(&self.url, &scope(), policy).await.unwrap();
        (AdmissionService::new(scope(), policy.clone(), Arc::new(store.clone())).unwrap(), store)
    }
    async fn lease_service(&self, policy: &AdmissionPolicy) -> LeaseService {
        let store = RedisAdmissionStore::connect(&self.url, &scope(), policy).await.unwrap();
        LeaseService::new(scope(), policy.clone(), Arc::new(store)).unwrap()
    }
    async fn namespace(&self, policy: &AdmissionPolicy) -> String {
        RedisAdmissionStore::connect(&self.url, &scope(), policy).await.unwrap().namespace().to_string()
    }
    async fn time(&self) -> u64 {
        let (seconds, micros): (u64, u64) = redis::cmd("TIME").query_async(&mut self.connection().await.unwrap()).await.unwrap();
        seconds * 1000 + micros / 1000
    }
}
impl Drop for RedisProcess { fn drop(&mut self) { let _ = self.child.kill(); let _ = self.child.wait(); } }

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires redis-server; uses an isolated Unix socket and disposable AOF directory"]
async fn redis_multi_edge_activation_is_atomic_and_survives_restart() {
    let mut process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let (edge_a, store) = process.service(&policy).await;
    let (edge_b, _) = process.service(&policy).await;
    let signer = secret(1); let now = process.time().await;
    let request = auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), now);
    let mut jobs = Vec::new();
    for i in 0..20 {
        let edge = if i % 2 == 0 { edge_a.clone() } else { edge_b.clone() }; let request = request.clone();
        jobs.push(tokio::spawn(async move { edge.get_challenge(request).await.unwrap() }));
    }
    let challenge = jobs.remove(0).await.unwrap();
    for job in jobs { assert_eq!(job.await.unwrap(), challenge); }
    let mut connection = process.connection().await.unwrap();
    let worker_key = format!("{}:worker:{}", store.namespace(), hex::encode(key(&signer).0));
    let ttl: i64 = connection.pttl(&worker_key).await.unwrap(); assert!(ttl > 0);
    let solution = solve(&challenge.challenge);
    let request = auth(&signer, AdmissionMethod::SubmitPow, 0, solution.payload_hash(), now);
    let mut jobs = Vec::new();
    for i in 0..20 {
        let edge = if i % 2 == 0 { edge_a.clone() } else { edge_b.clone() }; let request = request.clone(); let solution = solution.clone();
        jobs.push(tokio::spawn(async move { edge.submit_pow(request, solution).await.unwrap() }));
    }
    let activated = jobs.remove(0).await.unwrap();
    for job in jobs { assert_eq!(job.await.unwrap(), activated); }
    assert_eq!(activated.current.reputation, 3);
    let ttl: i64 = connection.pttl(&worker_key).await.unwrap(); assert_eq!(ttl, -1);
    let audit_count: usize = redis::cmd("XLEN").arg(format!("{}:audit", store.namespace())).query_async(&mut connection).await.unwrap(); assert_eq!(audit_count, 2);
    let pending_count: usize = connection.zcard(format!("{}:pending", store.namespace())).await.unwrap(); assert_eq!(pending_count, 0);
    process.restart().await;
    let (edge, _) = process.service(&policy).await;
    let status = edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), process.time().await)).await.unwrap();
    assert_eq!(status.reputation, 3);
    let event = digest(b"verified violation"); let evidence = digest(b"signed bad proof");
    edge.revoke_for_verified_violation(key(&signer), 0, event, evidence).await.unwrap();
    let retry = edge.submit_pow(request, solution).await.unwrap();
    assert_eq!((retry.current.reputation, retry.current.generation), (0, 1));
    process.restart().await;
    let (edge, _) = process.service(&policy).await;
    let status = edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), process.time().await)).await.unwrap();
    assert_eq!((status.reputation, status.generation), (0, 1));
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_capacity_rate_limits_and_policy_mismatch() {
    let process = RedisProcess::start().await;
    let mut policy = AdmissionPolicy::for_base_bits(8); policy.max_pending_challenges = 1;
    let (edge, store) = process.service(&policy).await;
    let first = secret(1); let second = secret(2); let now = process.time().await;
    edge.get_challenge(auth(&first, AdmissionMethod::GetChallenge, 0, empty_payload(), now)).await.unwrap();
    assert_eq!(edge.get_challenge(auth(&second, AdmissionMethod::GetChallenge, 0, empty_payload(), now)).await.unwrap_err(), AdmissionError::Capacity);
    // Consuming the first challenge frees capacity for a different identity.
    activate(&edge, &first, 0, now).await;
    edge.get_challenge(auth(&second, AdmissionMethod::GetChallenge, 0, empty_payload(), now)).await.unwrap();
    let mut mismatch = policy.clone(); mismatch.base_bits += 1;
    assert!(matches!(RedisAdmissionStore::connect(&process.url, &scope(), &mismatch).await, Err(AdmissionError::ConfigMismatch)));
    // Shared budget, not one independent budget per edge.
    let mut connection = process.connection().await.unwrap();
    let _: () = connection.set_ex(format!("{}:budget:global", store.namespace()), policy.requests_per_minute, 60).await.unwrap();
    assert!(matches!(edge.get_status(auth(&first, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await, Err(AdmissionError::RateLimited { .. })));
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_bad_signatures_do_not_spend_the_victims_key_budget() {
    let process = RedisProcess::start().await;
    let mut policy = AdmissionPolicy::for_base_bits(8); policy.requests_per_key_per_minute = 1;
    let (edge, _) = process.service(&policy).await;
    let now = process.time().await; let signer = secret(1);
    let mut invalid = auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now); invalid.signature.0[0] ^= 1;
    for _ in 0..3 { assert_eq!(edge.get_status(invalid.clone()).await.unwrap_err(), AdmissionError::InvalidSignature); }
    edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await.unwrap();
    assert!(matches!(edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await, Err(AdmissionError::RateLimited { .. })));
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_claim_polling_cannot_starve_a_proof_submission() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let service = process.lease_service(&policy).await;
    let namespace = process.namespace(&policy).await;
    let signer = secret(1); let now = process.time().await;
    activate(service.admission(), &signer, 0, now).await;
    let lease = leased(&service, &signer, 1, 60_000, now).await;
    let worker = hex::encode(key(&signer).0);
    let mut connection = process.connection().await.unwrap();
    // Claims and status reads used up the key budget.
    let _: () = connection.set_ex(format!("{namespace}:budget:{worker}"), policy.requests_per_key_per_minute, 60).await.unwrap();
    assert!(matches!(service.admission().get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await,
        Err(AdmissionError::RateLimited { .. })));
    let proof = submission(&lease, b"proof");
    assert!(matches!(service.begin_verification(submit_auth(&signer, 0, &proof, now), proof.clone()).await.unwrap(),
        lease::SubmissionOutcome::Verify(_)));
    // Submissions are still limited, by their own counter.
    let _: () = connection.set_ex(format!("{namespace}:budget:submit:{worker}"), policy.requests_per_key_per_minute, 60).await.unwrap();
    assert!(matches!(service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await,
        Err(AdmissionError::RateLimited { .. })));
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_corruption_is_fail_closed_and_script_does_not_partially_activate() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8); let (edge, store) = process.service(&policy).await;
    let signer = secret(1); let now = process.time().await;
    let challenge = edge.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), now)).await.unwrap();
    let mut connection = process.connection().await.unwrap();
    let worker_key = format!("{}:worker:{}", store.namespace(), hex::encode(key(&signer).0));
    let original: Vec<u8> = connection.get(&worker_key).await.unwrap();
    let _: () = connection.set(format!("{}:audit", store.namespace()), "wrong type").await.unwrap();
    let solution = solve(&challenge.challenge);
    assert_eq!(edge.submit_pow(auth(&signer, AdmissionMethod::SubmitPow, 0, solution.payload_hash(), now), solution).await.unwrap_err(), AdmissionError::StateCorrupt);
    let after: Vec<u8> = connection.get(&worker_key).await.unwrap(); assert_eq!(after, original);
    let _: () = connection.set(&worker_key, "").await.unwrap();
    assert_eq!(edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await.unwrap_err(), AdmissionError::StateCorrupt);
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_generation_above_js_precision_remains_exact() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8); let (edge, store) = process.service(&policy).await;
    let signer = secret(1); let now = process.time().await;
    activate(&edge, &signer, 0, now).await;
    let mut connection = process.connection().await.unwrap();
    let worker_key = format!("{}:worker:{}", store.namespace(), hex::encode(key(&signer).0));
    let original: Vec<u8> = connection.get(&worker_key).await.unwrap();
    let mut record: WorkerRecord = serde_json::from_slice(&original).unwrap();
    let generation = (1u64 << 53) + 7;
    record.generation = generation; record.last_activation.as_mut().unwrap().generation = generation;
    let _: () = connection.set(&worker_key, serde_json::to_vec(&record).unwrap()).await.unwrap();
    let receipt = edge.revoke_for_verified_violation(key(&signer), generation, digest(b"event"), digest(b"evidence")).await.unwrap();
    assert_eq!(receipt.new_generation, generation + 1);
    let status = edge.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await.unwrap();
    assert_eq!(status.generation, generation + 1);
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_outage_is_bounded_and_never_grants_admission() {
    let mut process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let (edge, _) = process.service(&policy).await;
    let now = process.time().await;
    process.child.kill().unwrap(); process.child.wait().unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), edge.get_status(auth(&secret(1), AdmissionMethod::GetStatus, 0, empty_payload(), now))).await;
    assert_eq!(result.expect("store outage must not hang the edge").unwrap_err(), AdmissionError::StoreUnavailable);
}

async fn counter(process: &RedisProcess, namespace: &str, key: StoreKey) -> Option<String> {
    process.connection().await.unwrap().get(format!("{namespace}:{}", key.name())).await.unwrap()
}

async fn leased(service: &LeaseService, signer: &secp256k1::SecretKey, n: u64, lease_ms: u64, now: u64) -> lease::LeaseRecord {
    let claim = service.reserve_claim(claim_auth(signer, 0, now), digest(b"claim")).await.unwrap();
    service.attach_lease(key(signer), claim.claim.request_id, binding(n, lease_ms)).await.unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires redis-server"]
async fn redis_multi_edge_claims_respect_identity_and_pool_limits() {
    let process = RedisProcess::start().await;
    let mut policy = AdmissionPolicy::for_base_bits(8); policy.task_budget = 8; policy.low_reputation_budget = 4;
    let edges = [process.lease_service(&policy).await, process.lease_service(&policy).await];
    let namespace = process.namespace(&policy).await;
    let now = process.time().await;
    let first = secret(1);
    activate(edges[0].admission(), &first, 0, now).await;
    let jobs: Vec<_> = (0..20).map(|i| { let edge = edges[i % 2].clone(); let request = claim_auth(&first, 0, now);
        tokio::spawn(async move { edge.reserve_claim(request, digest(b"claim")).await }) }).collect();
    let mut granted = 0;
    for job in jobs { match job.await.unwrap() { Ok(_) => granted += 1, Err(e) => assert_eq!(e, AdmissionError::InflightLimit) } }
    assert_eq!(granted, 1);
    // One request retried on both edges is one claim.
    let second = secret(2); activate(edges[1].admission(), &second, 0, now).await;
    let request = claim_auth(&second, 0, now);
    let jobs: Vec<_> = (0..20).map(|i| { let edge = edges[i % 2].clone(); let request = request.clone();
        tokio::spawn(async move { edge.reserve_claim(request, digest(b"claim")).await.unwrap() }) }).collect();
    let claim = jobs.into_iter().next().unwrap().await.unwrap();
    assert_eq!(claim.claim.request_id, request.request_id);
    assert_eq!(counter(&process, &namespace, StoreKey::Inflight(key(&second))).await.as_deref(), Some("1"));
    // Ten fresh identities race for the two low-reputation slots left.
    let newcomers: Vec<_> = (10..20).map(secret).collect();
    for signer in &newcomers { activate(edges[0].admission(), signer, 0, now).await; }
    let jobs: Vec<_> = newcomers.iter().enumerate().map(|(i, signer)| { let edge = edges[i % 2].clone(); let request = claim_auth(signer, 0, now);
        tokio::spawn(async move { edge.reserve_claim(request, digest(b"claim")).await }) }).collect();
    let mut granted = 0;
    for job in jobs { match job.await.unwrap() { Ok(_) => granted += 1, Err(e) => assert_eq!(e, AdmissionError::Capacity) } }
    assert_eq!(granted, 2);
    assert_eq!(counter(&process, &namespace, StoreKey::LowReputationBudget).await.as_deref(), Some("4"));
    assert_eq!(counter(&process, &namespace, StoreKey::TaskBudget).await.as_deref(), Some("4"));
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_lease_lifecycle_survives_restarts_and_publishes_once() {
    let mut process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let service = process.lease_service(&policy).await;
    let namespace = process.namespace(&policy).await;
    let signer = secret(1); let now = process.time().await;
    activate(service.admission(), &signer, 0, now).await;
    let lease = leased(&service, &signer, 1, 60_000, now).await;
    let proof = submission(&lease, b"proof");
    let lease::SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap() else { panic!() };
    process.restart().await;
    let service = process.lease_service(&policy).await;
    let lease::AcceptOutcome::Accepted(receipt) = service.accept_verified_result(&ticket, digest(b"staged")).await.unwrap() else { panic!() };
    process.restart().await;
    let service = process.lease_service(&policy).await;
    assert_eq!(service.accept_verified_result(&ticket, digest(b"staged")).await.unwrap(), lease::AcceptOutcome::Accepted(receipt.clone()));
    let pending = service.pending_publications(10).await.unwrap();
    assert_eq!(pending.len(), 1);
    service.mark_published(lease.job_key, receipt.event_id).await.unwrap();
    assert!(service.pending_publications(10).await.unwrap().is_empty());
    let status = service.admission().get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), process.time().await)).await.unwrap();
    assert_eq!(status.reputation, 4);
    for key_name in [StoreKey::Inflight(key(&signer)), StoreKey::TaskBudget, StoreKey::LowReputationBudget] {
        assert_eq!(counter(&process, &namespace, key_name).await, None);
    }
    let mut connection = process.connection().await.unwrap();
    for index in ["due", "outbox"] {
        let size: usize = connection.zcard(format!("{namespace}:{index}")).await.unwrap(); assert_eq!(size, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires redis-server"]
async fn redis_concurrent_reconcilers_score_a_timeout_once() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let edges = [process.lease_service(&policy).await, process.lease_service(&policy).await];
    let signer = secret(1); let now = process.time().await;
    activate(edges[0].admission(), &signer, 0, now).await;
    leased(&edges[0], &signer, 1, 1_000, now).await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let jobs: Vec<_> = (0..8).map(|i| { let edge = edges[i % 2].clone(); tokio::spawn(async move { edge.reconcile(10).await.unwrap() }) }).collect();
    let mut expired = 0;
    for job in jobs { let report = job.await.unwrap(); expired += report.leases_expired; assert!(report.reputation_decrements <= 1); }
    assert_eq!(expired, 1);
    let status = edges[1].admission().get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), process.time().await)).await.unwrap();
    assert_eq!(status.reputation, 2);
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_refused_transactions_write_nothing() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let service = process.lease_service(&policy).await;
    let namespace = process.namespace(&policy).await;
    let signer = secret(1); let now = process.time().await;
    activate(service.admission(), &signer, 0, now).await;
    let mut connection = process.connection().await.unwrap();
    // A corrupt counter fails the reservation before the claim or other counters are written.
    let low = format!("{namespace}:{}", StoreKey::LowReputationBudget.name());
    let _: () = connection.set(&low, "abc").await.unwrap();
    let request = claim_auth(&signer, 0, now);
    assert_eq!(service.reserve_claim(request.clone(), digest(b"claim")).await.unwrap_err(), AdmissionError::StateCorrupt);
    assert_eq!(counter(&process, &namespace, StoreKey::Inflight(key(&signer))).await, None);
    assert_eq!(counter(&process, &namespace, StoreKey::TaskBudget).await, None);
    let claim_exists: bool = connection.exists(format!("{namespace}:{}", StoreKey::Claim(key(&signer), request.request_id).name())).await.unwrap();
    assert!(!claim_exists);
    let _: () = connection.del(&low).await.unwrap();
    let claim = service.reserve_claim(request.clone(), digest(b"claim")).await.unwrap();
    // A wrong-typed index fails the attach with claim and lease untouched.
    let _: () = connection.del(format!("{namespace}:due")).await.unwrap();
    let _: () = connection.rpush(format!("{namespace}:due"), "x").await.unwrap();
    assert_eq!(service.attach_lease(key(&signer), request.request_id, binding(1, 60_000)).await.unwrap_err(), AdmissionError::StateCorrupt);
    assert!(service.lease_record(&job(1)).await.unwrap().is_none());
    let retried = service.reserve_claim(request, digest(b"claim")).await.unwrap();
    assert_eq!(retried, claim);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires redis-server"]
async fn redis_accept_and_revoke_race_resolves_to_one_order() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let edges = [process.lease_service(&policy).await, process.lease_service(&policy).await];
    let now = process.time().await;
    let (mut accepted, mut stale) = (0, 0);
    for n in 0..12u8 {
        let signer = secret(n + 1);
        activate(edges[0].admission(), &signer, 0, now).await;
        let lease = leased(&edges[0], &signer, n as u64, 60_000, now).await;
        let proof = submission(&lease, b"p");
        let lease::SubmissionOutcome::Verify(ticket) = edges[0].begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap() else { panic!() };
        let (a, b) = (edges[0].clone(), edges[1].clone()); let public = key(&signer);
        let accept = tokio::spawn(async move { a.accept_verified_result(&ticket, digest(b"s")).await.unwrap() });
        let revoke = tokio::spawn(async move { b.admission().revoke_for_verified_violation(public, 0, digest(b"e"), digest(b"v")).await.unwrap() });
        let outcome = accept.await.unwrap(); revoke.await.unwrap();
        let published = edges[1].pending_publications(100).await.unwrap().iter().any(|l| l.job_key == lease.job_key);
        match outcome {
            lease::AcceptOutcome::Accepted(receipt) => { accepted += 1; assert!(published); assert_eq!(receipt.reputation_after, 4); }
            lease::AcceptOutcome::Stale => { stale += 1; assert!(!published); }
        }
        let status = edges[1].admission().get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), process.time().await)).await.unwrap();
        assert_eq!((status.reputation, status.generation), (0, 1));
    }
    assert_eq!(accepted + stale, 12);
    eprintln!("accept first: {accepted}, revoke first: {stale}");
}

#[tokio::test]
#[ignore = "requires redis-server"]
async fn redis_staged_proofs_are_content_addressed_and_checked() {
    let process = RedisProcess::start().await;
    let policy = AdmissionPolicy::for_base_bits(8);
    let store = RedisAdmissionStore::connect(&process.url, &scope(), &policy).await.unwrap();
    let address = store.put_staged_proof(b"proof bytes", 60_000).await.unwrap();
    assert_eq!(address, digest(b"proof bytes"));
    assert_eq!(store.put_staged_proof(b"proof bytes", 60_000).await.unwrap(), address);
    assert_eq!(store.get_staged_proof(address).await.unwrap().unwrap(), b"proof bytes");
    assert_eq!(store.get_staged_proof(digest(b"absent")).await.unwrap(), None);
    let _: () = process.connection().await.unwrap().set(format!("{}:staged:{}", store.namespace(), hex::encode(address.0)), "tampered").await.unwrap();
    assert_eq!(store.get_staged_proof(address).await.unwrap_err(), AdmissionError::StateCorrupt);
}
