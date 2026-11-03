mod common;
use common::*;
use psy_worker_admission::{*, lease::*, store::*};
use secp256k1::SecretKey;

fn policy() -> AdmissionPolicy { AdmissionPolicy::for_base_bits(8) }

async fn lease_one(service: &LeaseService, signer: &SecretKey, generation: u64, n: u64, now: u64) -> LeaseRecord {
    let claim = service.reserve_claim(claim_auth(signer, generation, now), digest(b"claim")).await.unwrap();
    service.attach_lease(key(signer), claim.claim.request_id, binding(n, 60_000)).await.unwrap()
}

async fn status(service: &LeaseService, signer: &SecretKey, now: u64) -> service::AdmissionStatus {
    service.admission().get_status(auth(signer, AdmissionMethod::GetStatus, 0, empty_payload(), now)).await.unwrap()
}

fn held(store: &MemoryStore, signer: &SecretKey) -> (u64, u64, u64) {
    (store.counter(StoreKey::Inflight(key(signer))), store.counter(StoreKey::TaskBudget), store.counter(StoreKey::LowReputationBudget))
}

#[tokio::test]
async fn accepted_result_scores_once_and_waits_in_the_outbox() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    activate(service.admission(), &signer, 0, now).await;
    let lease = lease_one(&service, &signer, 0, 1, now).await;
    assert_eq!(held(&store, &signer), (1, 1, 1));
    let proof = submission(&lease, b"proof");
    let SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&signer, 0, &proof, now), proof.clone()).await.unwrap() else { panic!() };
    let AcceptOutcome::Accepted(receipt) = service.accept_verified_result(&ticket, digest(b"staged")).await.unwrap() else { panic!() };
    assert_eq!(receipt.reputation_after, 4);
    // Every retry path returns the same receipt and never scores again.
    assert_eq!(service.accept_verified_result(&ticket, digest(b"staged")).await.unwrap(), AcceptOutcome::Accepted(receipt.clone()));
    assert_eq!(service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap(), SubmissionOutcome::Accepted(receipt.clone()));
    assert_eq!(status(&service, &signer, now).await.reputation, 4);
    assert_eq!(held(&store, &signer), (0, 0, 0));
    assert_eq!(service.attach_lease(key(&signer), FixedBytes::random(), binding(1, 60_000)).await.unwrap_err(), AdmissionError::LeaseStale);
    let pending = service.pending_publications(10).await.unwrap();
    assert_eq!(pending.len(), 1); assert_eq!(pending[0].accepted.as_ref().unwrap(), &receipt);
    service.mark_published(lease.job_key, receipt.event_id).await.unwrap();
    service.mark_published(lease.job_key, receipt.event_id).await.unwrap();
    assert!(service.pending_publications(10).await.unwrap().is_empty());
    assert_eq!(store.index_len(StoreIndex::Due), 0);
}

#[tokio::test]
async fn claim_retry_returns_the_original_and_limits_hold() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    assert_eq!(service.reserve_claim(claim_auth(&signer, 0, now), digest(b"claim")).await.unwrap_err(), AdmissionError::PowRequired);
    activate(service.admission(), &signer, 0, now).await;
    let request = claim_auth(&signer, 0, now);
    let first = service.reserve_claim(request.clone(), digest(b"claim")).await.unwrap();
    assert_eq!(service.reserve_claim(request.clone(), digest(b"claim")).await.unwrap(), first);
    // Reputation 3 allows exactly one task in flight.
    assert_eq!(service.reserve_claim(claim_auth(&signer, 0, now), digest(b"claim")).await.unwrap_err(), AdmissionError::InflightLimit);
    let lease = service.attach_lease(key(&signer), request.request_id, binding(1, 60_000)).await.unwrap();
    let retried = service.reserve_claim(request.clone(), digest(b"claim")).await.unwrap();
    assert_eq!(retried.lease.unwrap(), lease);
    assert_eq!(service.attach_lease(key(&signer), request.request_id, binding(1, 60_000)).await.unwrap(), lease);
    assert_eq!(service.attach_lease(key(&signer), request.request_id, binding(2, 60_000)).await.unwrap_err(), AdmissionError::RequestConflict);
    // Same request ID, different signed contents.
    let mut forged = claim_auth(&signer, 0, now + 1); forged.request_id = request.request_id; forged.sign(&signer).unwrap();
    assert_eq!(service.reserve_claim(forged, digest(b"claim")).await.unwrap_err(), AdmissionError::RequestConflict);
    assert_eq!(held(&store, &signer), (1, 1, 1));
}

#[tokio::test]
async fn low_reputation_pool_is_an_absolute_cap() {
    let store = MemoryStore::new();
    let mut policy = policy(); policy.task_budget = 3; policy.low_reputation_budget = 2;
    let service = lease_service(store.clone(), policy);
    let now = store.time();
    // A worker at reputation 4 claims from the standard pool.
    let veteran = secret(9);
    activate(service.admission(), &veteran, 0, now).await;
    let lease = lease_one(&service, &veteran, 0, 100, now).await;
    let proof = submission(&lease, b"p");
    let SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&veteran, 0, &proof, now), proof).await.unwrap() else { panic!() };
    service.accept_verified_result(&ticket, digest(b"s")).await.unwrap();
    let newcomers: Vec<_> = (1..=3).map(secret).collect();
    for signer in &newcomers { activate(service.admission(), signer, 0, now).await; }
    service.reserve_claim(claim_auth(&newcomers[0], 0, now), digest(b"claim")).await.unwrap();
    service.reserve_claim(claim_auth(&newcomers[1], 0, now), digest(b"claim")).await.unwrap();
    assert_eq!(service.reserve_claim(claim_auth(&newcomers[2], 0, now), digest(b"claim")).await.unwrap_err(), AdmissionError::Capacity);
    let standard = service.reserve_claim(claim_auth(&veteran, 0, now), digest(b"claim")).await.unwrap();
    assert_eq!(standard.claim.pool, Pool::Standard);
    assert_eq!(service.reserve_claim(claim_auth(&veteran, 0, now), digest(b"claim")).await.unwrap_err(), AdmissionError::Capacity);
    assert_eq!((store.counter(StoreKey::TaskBudget), store.counter(StoreKey::LowReputationBudget)), (3, 2));
}

#[tokio::test]
async fn a_worker_that_never_returns_is_reclaimed_scored_once_and_needs_pow() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1);
    activate(service.admission(), &signer, 0, store.time()).await;
    for (round, expected) in [(1, 2u8), (2, 1)] {
        lease_one(&service, &signer, 0, round, store.time()).await;
        store.advance(60_000);
        let report = service.reconcile(10).await.unwrap();
        assert_eq!((report.leases_expired, report.reputation_decrements, report.revocations), (1, 1, 0));
        assert_eq!(service.reconcile(10).await.unwrap(), ReconcileReport::default());
        assert_eq!(status(&service, &signer, store.time()).await.reputation, expected);
    }
    lease_one(&service, &signer, 0, 3, store.time()).await;
    store.advance(60_000);
    assert_eq!(service.reconcile(10).await.unwrap().revocations, 1);
    let current = status(&service, &signer, store.time()).await;
    assert_eq!((current.status, current.reputation, current.generation), (AdmissionState::NeedsPow, 0, 1));
    assert_eq!(held(&store, &signer), (0, 0, 0));
    // A timeout is not attributable: no cooldown, recovery at generation 1.
    let recovered = activate(service.admission(), &signer, 1, store.time()).await.2;
    assert_eq!((recovered.current.reputation, recovered.current.generation), (3, 1));
}

#[tokio::test]
async fn live_lease_is_never_reassigned_and_stale_owner_is_not_punished() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let (a, b) = (secret(1), secret(2)); let now = store.time();
    activate(service.admission(), &a, 0, now).await; activate(service.admission(), &b, 0, now).await;
    let old = lease_one(&service, &a, 0, 1, now).await;
    // Early redelivery while the lease is live.
    let claim = service.reserve_claim(claim_auth(&b, 0, now), digest(b"claim")).await.unwrap();
    assert_eq!(service.attach_lease(key(&b), claim.claim.request_id, binding(1, 60_000)).await.unwrap_err(), AdmissionError::LeaseBusy);
    assert_eq!(service.lease_record(&job(1)).await.unwrap().unwrap(), old);
    service.release_claim(key(&b), claim.claim.request_id).await.unwrap();
    store.advance(60_000);
    service.reconcile(10).await.unwrap();
    let now = store.time();
    let new = lease_one(&service, &b, 0, 1, now).await;
    assert_eq!(new.lease_version, 1); assert_ne!(new.lease_id, old.lease_id);
    let late = submission(&old, b"late");
    assert_eq!(service.begin_verification(submit_auth(&a, 0, &late, now), late).await.unwrap_err(), AdmissionError::LeaseStale);
    assert_eq!(status(&service, &a, now).await.reputation, 2, "only the one timeout");
    // A signs a submission for B's lease: rejected, B untouched.
    let hijack = submission(&new, b"x");
    assert_eq!(service.begin_verification(submit_auth(&a, 0, &hijack, now), hijack.clone()).await.unwrap_err(), AdmissionError::LeaseStale);
    // B's signature reused over different proof bytes.
    let mut tampered = hijack.clone(); tampered.proof_hash = digest(b"y");
    assert_eq!(service.begin_verification(submit_auth(&b, 0, &hijack, now), tampered).await.unwrap_err(), AdmissionError::InvalidSignature);
    assert_eq!(service.lease_record(&job(1)).await.unwrap().unwrap().state, LeaseState::Leased);
    assert_eq!(status(&service, &b, now).await.reputation, 3);
}

#[tokio::test]
async fn revocation_during_verification_wins_but_accepted_results_still_publish() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let (a, b) = (secret(1), secret(2)); let now = store.time();
    for signer in [&a, &b] { activate(service.admission(), signer, 0, now).await; }
    let lease = lease_one(&service, &a, 0, 1, now).await;
    let proof = submission(&lease, b"p");
    let SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&a, 0, &proof, now), proof).await.unwrap() else { panic!() };
    service.admission().revoke_for_verified_violation(key(&a), 0, digest(b"e"), digest(b"v")).await.unwrap();
    assert_eq!(service.accept_verified_result(&ticket, digest(b"s")).await.unwrap(), AcceptOutcome::Stale);
    assert!(service.pending_publications(10).await.unwrap().is_empty());
    assert_eq!(held(&store, &a), (0, 0, 0));
    assert_eq!(status(&service, &a, now).await.reputation, 0);
    // Accept first, then revoke: the result stays accepted and publishable.
    let lease = lease_one(&service, &b, 0, 2, now).await;
    let proof = submission(&lease, b"p");
    let SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&b, 0, &proof, now), proof).await.unwrap() else { panic!() };
    let AcceptOutcome::Accepted(receipt) = service.accept_verified_result(&ticket, digest(b"s")).await.unwrap() else { panic!() };
    service.admission().revoke_for_verified_violation(key(&b), 0, digest(b"e2"), digest(b"v2")).await.unwrap();
    assert_eq!(service.pending_publications(10).await.unwrap()[0].accepted.as_ref().unwrap(), &receipt);
    assert_eq!(status(&service, &b, now).await.reputation, 0);
}

#[tokio::test]
async fn concurrent_identical_submissions_share_one_verification() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    activate(service.admission(), &signer, 0, now).await;
    let lease = lease_one(&service, &signer, 0, 1, now).await;
    let proof = submission(&lease, b"p"); let request = submit_auth(&signer, 0, &proof, now);
    let jobs: Vec<_> = (0..16).map(|_| { let s = service.clone(); let (r, p) = (request.clone(), proof.clone());
        tokio::spawn(async move { s.begin_verification(r, p).await.unwrap() }) }).collect();
    let mut verify = 0;
    for job in jobs { if matches!(job.await.unwrap(), SubmissionOutcome::Verify(_)) { verify += 1; } }
    assert_eq!(verify, 1);
    let other = submission(&lease, b"other");
    assert_eq!(service.begin_verification(submit_auth(&signer, 0, &other, now), other).await.unwrap_err(), AdmissionError::LeaseBusy);
    let ticket = service.lease_record(&job(1)).await.unwrap().unwrap();
    let ticket = VerificationTicket { job_key: ticket.job_key, lease_id: ticket.lease_id, lease_version: 0, owner: key(&signer),
        owner_generation: 0, submission_digest: ticket.submission_digest.unwrap(), submission_request: ticket.submission_request.unwrap() };
    let jobs: Vec<_> = (0..16).map(|_| { let s = service.clone(); let t = ticket.clone();
        tokio::spawn(async move { s.accept_verified_result(&t, digest(b"s")).await.unwrap() }) }).collect();
    let mut results = Vec::new();
    for job in jobs { results.push(job.await.unwrap()); }
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    assert_eq!(status(&service, &signer, now).await.reputation, 4);
}

#[tokio::test]
async fn infrastructure_failures_never_score() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    activate(service.admission(), &signer, 0, now).await;
    let lease = lease_one(&service, &signer, 0, 1, now).await;
    let proof = submission(&lease, b"p");
    let SubmissionOutcome::Verify(ticket) = service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap() else { panic!() };
    service.fail_verification(&ticket).await.unwrap();
    service.fail_verification(&ticket).await.unwrap();
    assert_eq!(held(&store, &signer), (0, 0, 0));
    assert_eq!(service.accept_verified_result(&ticket, digest(b"s")).await.unwrap(), AcceptOutcome::Stale);
    // Verification overrunning its server deadline is released, not punished.
    let lease = lease_one(&service, &signer, 0, 1, now).await;
    assert_eq!(lease.lease_version, 1);
    let proof = submission(&lease, b"p");
    service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap();
    store.advance(policy().verification_ttl_ms);
    assert_eq!(service.reconcile(10).await.unwrap().verifications_released, 1);
    // A reservation abandoned by a crashed edge is returned after its TTL.
    let now = store.time();
    service.reserve_claim(claim_auth(&signer, 0, now), digest(b"claim")).await.unwrap();
    assert_eq!(service.reconcile(10).await.unwrap(), ReconcileReport::default());
    store.advance(policy().reservation_ttl_ms);
    assert_eq!(service.reconcile(10).await.unwrap().claims_released, 1);
    assert_eq!(held(&store, &signer), (0, 0, 0));
    assert_eq!(status(&service, &signer, store.time()).await.reputation, 3);
}

#[tokio::test]
async fn signed_tag_mismatch_by_the_owner_zeroes_once() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    activate(service.admission(), &signer, 0, now).await;
    let lease = lease_one(&service, &signer, 0, 1, now).await;
    let mut proof = submission(&lease, b"p"); proof.reward_tag = digest(b"someone else's tag");
    let SubmissionOutcome::TagMismatch(evidence) = service.begin_verification(submit_auth(&signer, 0, &proof, now), proof).await.unwrap() else { panic!() };
    let receipt = service.apply_attributable_violation(&evidence).await.unwrap();
    assert_eq!(service.apply_attributable_violation(&evidence).await.unwrap(), receipt);
    let current = status(&service, &signer, now).await;
    assert_eq!((current.reputation, current.generation), (0, 1));
    assert!(current.cooldown_until_ms > now, "attributable violations cool down");
    assert_eq!(held(&store, &signer), (0, 0, 0));
    assert_eq!(service.lease_record(&job(1)).await.unwrap().unwrap().state, LeaseState::Revoked);
}

#[tokio::test]
async fn revoked_between_reserve_and_attach_returns_the_capacity() {
    let store = MemoryStore::new(); let service = lease_service(store.clone(), policy());
    let signer = secret(1); let now = store.time();
    activate(service.admission(), &signer, 0, now).await;
    let claim = service.reserve_claim(claim_auth(&signer, 0, now), digest(b"claim")).await.unwrap();
    service.admission().revoke_for_verified_violation(key(&signer), 0, digest(b"e"), digest(b"v")).await.unwrap();
    assert_eq!(service.attach_lease(key(&signer), claim.claim.request_id, binding(1, 60_000)).await.unwrap_err(), AdmissionError::AdmissionStale);
    assert_eq!(held(&store, &signer), (0, 0, 0));
    assert!(service.lease_record(&job(1)).await.unwrap().is_none());
}
