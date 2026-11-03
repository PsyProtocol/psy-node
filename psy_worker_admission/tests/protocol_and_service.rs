mod common;
use std::sync::atomic::{AtomicBool, Ordering};

use common::*;
use jsonrpsee::rpc_params;
use psy_worker_admission::{*, rpc::{AdmissionRpc, WorkerAdmissionRpcServer}, store::*};

#[test]
fn independent_protocol_vectors_and_partial_bits() {
    let public_key: WorkerKey = serde_json::from_str("\"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\"").unwrap();
    let challenge = PowChallenge { protocol_version: 1, algorithm: 1, scope: scope(), worker_public_key: public_key,
        generation: 0, policy_version: 1, issued_at_ms: 1_000_000, expires_at_ms: 1_600_000, difficulty_bits: 8, random: FixedBytes([3; 32]) };
    assert_eq!(hex::encode(challenge.id().0), "b67dd942252b847d89471ad9d3de05db4738e5cb4941ef91a27795b279f447af");
    let nonce = FixedBytes(46u128.to_le_bytes());
    assert_eq!(hex::encode(solution_hash(challenge.id(), nonce).0), "0019073db723658115bca98271b8e2c847eefb80b54576426ef97bd9c7111d6a");
    challenge.verify(nonce).unwrap();
    let request = RequestAuth { scope: scope(), public_key, method: AdmissionMethod::GetStatus, request_id: FixedBytes([4; 16]),
        issued_at_ms: 1_000_000, valid_until_ms: 1_060_000, expected_generation: 0, payload_hash: empty_payload(), signature: FixedBytes([0;64]) };
    assert_eq!(hex::encode(request.signing_hash().0), "ae3a589be36fcc9ef6c93ef5a103208c47dbeeeacfcaca5a1fe845fbc2854983");
    let mut bytes = [0; 32]; bytes[1] = 0b0001_0000;
    assert_eq!(leading_zero_bits(&bytes), 11);
    assert_eq!(leading_zero_bits(&[0; 32]), 256);
}

#[test]
fn every_challenge_field_is_bound_to_its_id() {
    let challenge = PowChallenge {
        protocol_version: 1, algorithm: 1, scope: scope(), worker_public_key: key(&secret(1)),
        generation: 0, policy_version: 1, issued_at_ms: 1_000_000, expires_at_ms: 1_600_000,
        difficulty_bits: 8, random: FixedBytes([3; 32]),
    };
    let mut variants = Vec::new();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{ let mut other = challenge.clone(); other.$field = $value; variants.push(other); }};
    }
    changed!(protocol_version, 2);
    changed!(algorithm, 2);
    changed!(worker_public_key, key(&secret(2)));
    changed!(generation, 1);
    changed!(policy_version, 2);
    changed!(issued_at_ms, 1_000_001);
    changed!(expires_at_ms, 1_600_001);
    changed!(difficulty_bits, 9);
    changed!(random, FixedBytes([4; 32]));
    for index in 0..5 {
        let mut other = challenge.clone();
        match index {
            0 => other.scope.network_id.0[0] ^= 1,
            1 => other.scope.admission_epoch.0[0] ^= 1,
            2 => other.scope.node_type = 2,
            3 => other.scope.realm_id += 1,
            _ => other.scope.realm_sub_id += 1,
        }
        variants.push(other);
    }
    for variant in variants { assert_ne!(variant.id(), challenge.id()); }
}

#[test]
fn strict_wire_format_and_u64_precision() {
    let mut request = auth(&secret(1), AdmissionMethod::GetStatus, u64::MAX, empty_payload(), 1_000_000);
    let encoded = serde_json::to_value(&request).unwrap();
    assert_eq!(encoded["expected_generation"], u64::MAX.to_string());
    assert_eq!(serde_json::from_value::<RequestAuth>(encoded.clone()).unwrap(), request);
    let mut invalid = encoded.clone(); invalid["expected_generation"] = serde_json::json!(42);
    assert!(serde_json::from_value::<RequestAuth>(invalid).is_err());
    let mut invalid = encoded.clone(); invalid["expected_generation"] = serde_json::json!("01");
    assert!(serde_json::from_value::<RequestAuth>(invalid).is_err());
    let mut invalid = encoded.clone(); invalid["public_key"] = serde_json::json!("aa");
    assert!(serde_json::from_value::<RequestAuth>(invalid).is_err());
    let mut invalid = encoded; invalid["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<RequestAuth>(invalid).is_err());
    request.expected_generation -= 1;
    assert_eq!(request.verify(&scope(), &AdmissionPolicy::for_base_bits(8), AdmissionMethod::GetStatus, empty_payload(), 1_000_000), Err(AdmissionError::InvalidSignature));
}

#[test]
fn signature_binds_method_scope_payload_generation_and_deadline() {
    let policy = AdmissionPolicy::for_base_bits(8);
    let request = auth(&secret(1), AdmissionMethod::SubmitPow, 4, digest(b"solution"), 1_000_000);
    request.verify(&scope(), &policy, AdmissionMethod::SubmitPow, digest(b"solution"), 1_000_000).unwrap();
    assert_eq!(request.verify(&scope(), &policy, AdmissionMethod::GetChallenge, digest(b"solution"), 1_000_000), Err(AdmissionError::InvalidSignature));
    assert_eq!(request.verify(&scope(), &policy, AdmissionMethod::SubmitPow, digest(b"other nonce"), 1_000_000), Err(AdmissionError::InvalidSignature));
    let mut other = scope(); other.node_type = 2;
    assert_eq!(request.verify(&other, &policy, AdmissionMethod::SubmitPow, digest(b"solution"), 1_000_000), Err(AdmissionError::AdmissionStale));
    assert_eq!(request.verify(&scope(), &policy, AdmissionMethod::SubmitPow, digest(b"solution"), request.valid_until_ms), Err(AdmissionError::RequestExpired));
    assert_eq!(request.verify(&scope(), &policy, AdmissionMethod::SubmitPow, digest(b"solution"), 1), Err(AdmissionError::RequestExpired));
}

#[test]
fn solver_is_bounded_and_cancellable_and_rejects_unknown_algorithms() {
    let mut challenge = PowChallenge { protocol_version: 1, algorithm: 1, scope: scope(), worker_public_key: key(&secret(1)),
        generation: 0, policy_version: 1, issued_at_ms: 1, expires_at_ms: 2, difficulty_bits: 8, random: FixedBytes([0; 32]) };
    assert_eq!(solve_batch(&challenge, 0, 100, &AtomicBool::new(true)).unwrap(), None);
    assert_eq!(solve_batch(&challenge, 0, 0, &AtomicBool::new(false)).unwrap(), None);
    challenge.algorithm = 2;
    assert_eq!(solve_batch(&challenge, 0, 100, &AtomicBool::new(false)), Err(AdmissionError::InvalidRequest));
    assert!(rpc::validate_mode("enforce").is_err());
    assert!(rpc::validate_mode("observe").is_ok());
}

#[tokio::test]
async fn new_identity_is_zero_and_status_allocates_no_record() {
    let store = MemoryStore::new(); let service = memory_service(store.clone());
    let status = service.get_status(auth(&secret(1), AdmissionMethod::GetStatus, 0, empty_payload(), store.time())).await.unwrap();
    assert_eq!((status.status, status.reputation, status.max_inflight), (AdmissionState::NeedsPow, 0, 0));
    assert!(!status.task_enforcement);
    assert!(store.records.lock().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn multiple_edges_issue_one_challenge_and_activate_exactly_once() {
    let store = MemoryStore::new();
    let edges = [memory_service(store.clone()), memory_service(store.clone())];
    let request = auth(&secret(1), AdmissionMethod::GetChallenge, 0, empty_payload(), store.time());
    let mut jobs = Vec::new();
    for i in 0..24 {
        let edge = edges[i%2].clone(); let request = request.clone();
        jobs.push(tokio::spawn(async move { edge.get_challenge(request).await.unwrap() }));
    }
    let first = jobs.remove(0).await.unwrap();
    for job in jobs { assert_eq!(job.await.unwrap(), first); }
    let solution = solve(&first.challenge);
    let request = auth(&secret(1), AdmissionMethod::SubmitPow, 0, solution.payload_hash(), store.time());
    let mut jobs = Vec::new();
    for i in 0..24 {
        let edge = edges[i%2].clone(); let request = request.clone(); let solution = solution.clone();
        jobs.push(tokio::spawn(async move { edge.submit_pow(request, solution).await.unwrap() }));
    }
    let first = jobs.remove(0).await.unwrap();
    for job in jobs { assert_eq!(job.await.unwrap(), first); }
    assert_eq!(first.current.reputation, 3);
    assert_eq!(edges[0].get_challenge(auth(&secret(1), AdmissionMethod::GetChallenge, 0, empty_payload(), store.time())).await.unwrap_err(), AdmissionError::AlreadyActive);
}

#[tokio::test]
async fn revoke_cooldown_recovery_and_old_replay_never_restore_score() {
    let store = MemoryStore::new(); let service = memory_service(store.clone()); let signer = secret(1);
    let (old_request, old_solution, activation) = activate(&service, &signer, 0, store.time()).await;
    let event = digest(b"invalid proof event"); let evidence = digest(b"signed evidence");
    let receipt = service.revoke_for_verified_violation(key(&signer), 0, event, evidence).await.unwrap();
    assert_eq!(receipt.new_generation, 1);
    assert_eq!(service.revoke_for_verified_violation(key(&signer), 0, event, evidence).await.unwrap(), receipt);
    let replay = service.submit_pow(old_request, old_solution).await.unwrap();
    assert_eq!(replay.receipt, activation.receipt);
    assert_eq!((replay.current.reputation, replay.current.generation), (0, 1));
    assert!(matches!(service.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 1, empty_payload(), store.time())).await, Err(AdmissionError::Cooldown { .. })));
    store.advance(60_000);
    let challenge = service.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 1, empty_payload(), store.time())).await.unwrap();
    assert_eq!(challenge.challenge.difficulty_bits, 9);
    let (_, _, recovered) = activate(&service, &signer, 1, store.time()).await;
    assert_eq!((recovered.current.reputation, recovered.current.generation), (3, 1));
    assert_eq!(service.revoke_for_verified_violation(key(&signer), 0, digest(b"late old event"), evidence).await, Err(AdmissionError::AdmissionStale));
    let query = auth(&signer, AdmissionMethod::GetRequestStatus, 0, request_status_payload(recovered.receipt.request_id), store.time());
    assert!(service.get_request_status(query, recovered.receipt.request_id).await.unwrap().currently_active);
}

#[tokio::test]
async fn bad_or_expired_solution_does_not_consume_challenge() {
    let store = MemoryStore::new(); let service = memory_service(store.clone()); let signer = secret(1);
    let challenge = service.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), store.time())).await.unwrap();
    let invalid = PowSolution { challenge_id: challenge.challenge_id, nonce: (0u128..100).map(|n| FixedBytes(n.to_le_bytes())).find(|n| challenge.challenge.verify(*n).is_err()).unwrap() };
    assert_eq!(service.submit_pow(auth(&signer, AdmissionMethod::SubmitPow, 0, invalid.payload_hash(), store.time()), invalid).await.unwrap_err(), AdmissionError::InvalidPow);
    assert_eq!(service.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), store.time())).await.unwrap(), challenge);
    store.advance(600_000);
    let solution = solve(&challenge.challenge);
    assert_eq!(service.submit_pow(auth(&signer, AdmissionMethod::SubmitPow, 0, solution.payload_hash(), store.time()), solution).await.unwrap_err(), AdmissionError::ChallengeExpired);
    let next = service.get_challenge(auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), store.time())).await.unwrap();
    assert_ne!(next.challenge_id, challenge.challenge_id);
}

#[tokio::test]
async fn damaged_state_or_store_failure_never_becomes_positive_reputation() {
    let store = MemoryStore::new(); let service = memory_service(store.clone()); let signer = secret(1);
    for raw in [vec![], b"not json".to_vec(), b"{}".to_vec()] {
        store.records.lock().unwrap().insert(key(&signer), raw);
        assert_eq!(service.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), store.time())).await.unwrap_err(), AdmissionError::StateCorrupt);
    }
    store.available.store(false, Ordering::SeqCst);
    assert_eq!(service.get_status(auth(&signer, AdmissionMethod::GetStatus, 0, empty_payload(), store.time())).await.unwrap_err(), AdmissionError::StoreUnavailable);
}

#[tokio::test]
async fn rpc_round_trip_signed_flow_and_no_public_revocation() {
    let store = MemoryStore::new(); let service = memory_service(store.clone()); let signer = secret(1);
    let module = AdmissionRpc::new(service).into_rpc();
    let info: rpc::AdmissionInfo = module.call("psy_worker_get_admission_info", rpc_params![]).await.unwrap();
    assert!(!info.task_enforcement);
    let challenge: service::ChallengeResponse = module.call("psy_worker_get_pow_challenge", rpc_params![auth(&signer, AdmissionMethod::GetChallenge, 0, empty_payload(), store.time())]).await.unwrap();
    let solution = solve(&challenge.challenge);
    let response: service::ActivationResponse = module.call("psy_worker_submit_pow", rpc_params![auth(&signer, AdmissionMethod::SubmitPow, 0, solution.payload_hash(), store.time()), solution]).await.unwrap();
    assert_eq!(response.current.reputation, 3);
    assert_eq!(module.method_names().count(), 5);
    assert!(!module.method_names().any(|m| m.contains("revoke") || m.contains("set_reputation")));
    let bad = auth(&secret(2), AdmissionMethod::GetStatus, 0, empty_payload(), store.time());
    let result: std::result::Result<service::ChallengeResponse, _> = module.call("psy_worker_get_pow_challenge", rpc_params![bad]).await;
    assert!(result.unwrap_err().to_string().contains("INVALID_SIGNATURE"));
}
