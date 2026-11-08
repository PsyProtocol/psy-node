//! Worker side of the V2 task protocol: signed claims and submissions bound to
//! a lease, and automatic PoW recovery when the edge reports POW_REQUIRED.
//! Enabled with `PSY_WORKER_TASK_PROTOCOL=v2`; admission state is kept per
//! scope, so switching between edges of one scope never recomputes PoW.
use std::sync::atomic::AtomicBool;

use dashmap::DashMap;
use jsonrpsee::{core::ClientError, http_client::HttpClient};
use parth_core::{crypto::secp256k1::{CompressedPublicKey, Secp256K1WalletProvider}, data::hash::hash256::Hash256};
use psy_core::job::job_id::QProvingJobDataID;
use psy_worker_admission::{
    digest, empty_payload, lease::{ClaimRequest, LeaseRecord, ProofSubmission}, rpc::{WorkerAdmissionRpcClient, WorkerTaskRpcClient},
    solve_batch, store::AdmissionState, AdmissionMethod, AdmissionScope, FixedBytes, Hash32, HexBytes, RequestAuth,
    flow::SubmitOutcome,
};

const REQUEST_VALID_MS: u64 = 30_000;
const SOLVE_BATCH: u64 = 1 << 20;
/// Edges allow 120 signed requests per key per minute for claims and status
/// reads, and a separate 120 for proof submissions; claims at this pace leave
/// room for status reads.
const CLAIM_INTERVAL_MS: u64 = 600;
/// Longest single wait before a submission is sent again.
const SUBMIT_RETRY_MAX_MS: u64 = 30_000;
/// Wait before resending after a transport failure, such as an edge restart.
const SUBMIT_TRANSPORT_RETRY_MS: u64 = 1_000;
/// Stop resending this long before the lease's hard deadline.
const SUBMIT_DEADLINE_MARGIN_MS: u64 = 5_000;

impl std::fmt::Debug for V2State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("V2State").field("leases", &self.leases.len()).field("max_bits", &self.max_bits).finish()
    }
}

pub struct V2State {
    /// Admission scope and current generation by scope hash.
    generations: DashMap<Hash32, u64>,
    scopes: DashMap<[u8; 32], AdmissionScope>,
    leases: DashMap<([u8; 32], QProvingJobDataID), LeaseRecord>,
    /// One PoW recovery at a time; other claims wait for its result.
    recovery: tokio::sync::Mutex<()>,
    /// Earliest time of the next claim request, in ms since the epoch.
    next_claim_ms: tokio::sync::Mutex<u64>,
    max_bits: u16,
}

pub fn enabled_from_env() -> anyhow::Result<Option<V2State>> {
    let protocol = std::env::var("PSY_WORKER_TASK_PROTOCOL");
    match protocol.as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("legacy") => Ok(None),
        Ok("v2") => {
            let max_bits = match std::env::var("PSY_WORKER_ADMISSION_MAX_BITS") {
                Ok(v) => v.parse()?,
                Err(_) => 30,
            };
            Ok(Some(V2State { generations: DashMap::new(), scopes: DashMap::new(), leases: DashMap::new(),
                recovery: tokio::sync::Mutex::new(()), next_claim_ms: tokio::sync::Mutex::new(0), max_bits }))
        }
        Ok(other) => anyhow::bail!("unsupported PSY_WORKER_TASK_PROTOCOL {other}"),
        Err(_) => anyhow::bail!("PSY_WORKER_TASK_PROTOCOL is not valid unicode"),
    }
}

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

fn category(error: &ClientError) -> Option<&str> {
    match error { ClientError::Call(object) => Some(object.message()), _ => None }
}

fn retry_after_ms(error: &ClientError) -> Option<u64> {
    let ClientError::Call(object) = error else { return None };
    let data: serde_json::Value = serde_json::from_str(object.data()?.get()).ok()?;
    match &data["retry_after_ms"] {
        serde_json::Value::String(ms) => ms.parse().ok(),
        value => value.as_u64(),
    }
}

impl V2State {
    fn sign<S: Secp256K1WalletProvider>(&self, signer: &S, public_key: &CompressedPublicKey, scope: &AdmissionScope,
        method: AdmissionMethod, generation: u64, payload_hash: Hash32) -> anyhow::Result<RequestAuth> {
        let now = now_ms();
        let mut auth = RequestAuth { scope: scope.clone(), public_key: FixedBytes(public_key.0), method, request_id: FixedBytes::random(),
            issued_at_ms: now, valid_until_ms: now + REQUEST_VALID_MS, expected_generation: generation, payload_hash, signature: FixedBytes([0; 64]) };
        auth.sign_with(|digest| signer.sign(public_key, Hash256(digest.0)).map(|s| s.signature).map_err(|e| e.to_string()))
            .map_err(|e| anyhow::anyhow!("signing V2 request: {e}"))?;
        Ok(auth)
    }

    async fn scope(&self, client: &HttpClient, url_hash: [u8; 32]) -> anyhow::Result<AdmissionScope> {
        if let Some(scope) = self.scopes.get(&url_hash) { return Ok(scope.clone()); }
        let info = client.get_admission_info().await?;
        if info.protocol_version != 1 { anyhow::bail!("unsupported admission protocol {}", info.protocol_version); }
        self.scopes.insert(url_hash, info.scope.clone());
        Ok(info.scope)
    }

    /// Read the authoritative state; if PoW is required, solve and submit it.
    async fn recover<S: Secp256K1WalletProvider>(&self, client: &HttpClient, scope: &AdmissionScope, signer: &S, public_key: &CompressedPublicKey) -> anyhow::Result<u64> {
        let _guard = self.recovery.lock().await;
        let status = client.get_admission_status(self.sign(signer, public_key, scope, AdmissionMethod::GetStatus, 0, empty_payload())?).await?;
        if status.status == AdmissionState::Active {
            self.generations.insert(scope.hash(), status.generation);
            return Ok(status.generation);
        }
        if status.cooldown_until_ms > now_ms() {
            anyhow::bail!("PoW cooldown for {} ms", status.cooldown_until_ms - now_ms());
        }
        let challenge = client.get_pow_challenge(self.sign(signer, public_key, scope, AdmissionMethod::GetChallenge, status.generation, empty_payload())?).await?;
        if challenge.challenge.difficulty_bits > self.max_bits {
            anyhow::bail!("PoW difficulty {} exceeds the local limit {}", challenge.challenge.difficulty_bits, self.max_bits);
        }
        println!("[worker/v2] solving admission PoW at {} bits", challenge.challenge.difficulty_bits);
        let started = std::time::Instant::now();
        let task = challenge.challenge.clone();
        let nonce = tokio::task::spawn_blocking(move || -> anyhow::Result<Option<FixedBytes<16>>> {
            let cancel = AtomicBool::new(false);
            let mut start = rand::random::<u64>() as u128;
            loop {
                if now_ms() >= task.expires_at_ms { return Ok(None); }
                if let Some(nonce) = solve_batch(&task, start, SOLVE_BATCH, &cancel).map_err(|e| anyhow::anyhow!("{e}"))? { return Ok(Some(nonce)); }
                start += SOLVE_BATCH as u128;
            }
        }).await??.ok_or_else(|| anyhow::anyhow!("PoW challenge expired before it was solved"))?;
        let solution = psy_worker_admission::PowSolution { challenge_id: challenge.challenge_id, nonce };
        let auth = self.sign(signer, public_key, scope, AdmissionMethod::SubmitPow, status.generation, solution.payload_hash())?;
        let activated = client.submit_pow(auth, solution).await?;
        println!("[worker/v2] admitted at generation {} after {:?}", activated.current.generation, started.elapsed());
        self.generations.insert(scope.hash(), activated.current.generation);
        Ok(activated.current.generation)
    }

    async fn back_off(&self, error: &ClientError) {
        let wait = retry_after_ms(error).unwrap_or(60_000).min(120_000);
        println!("[worker/v2] rate limited, next claim in {wait} ms");
        *self.next_claim_ms.lock().await = now_ms() + wait;
    }

    /// Claim one task, recovering admission once if the edge requires it.
    pub async fn claim<S: Secp256K1WalletProvider>(&self, client: &HttpClient, url_hash: [u8; 32], signer: &S, public_key: &CompressedPublicKey, tag: Hash32)
        -> anyhow::Result<Option<serde_json::Value>> {
        let scope = self.scope(client, url_hash).await?;
        let request = ClaimRequest { reward_tag: tag };
        for attempt in 0..2 {
            {
                let mut next = self.next_claim_ms.lock().await;
                let now = now_ms();
                if *next > now { tokio::time::sleep(std::time::Duration::from_millis(*next - now)).await; }
                *next = now_ms() + CLAIM_INTERVAL_MS;
            }
            let generation = match self.generations.get(&scope.hash()).map(|g| *g) {
                Some(generation) => generation,
                None => match self.recover(client, &scope, signer, public_key).await {
                    Ok(generation) => generation,
                    Err(error) => match error.downcast_ref::<ClientError>().filter(|e| category(e) == Some("RATE_LIMITED")) {
                        Some(limited) => { self.back_off(limited).await; return Ok(None); }
                        None => return Err(error),
                    },
                },
            };
            let auth = self.sign(signer, public_key, &scope, AdmissionMethod::ClaimTask, generation, request.payload_hash())?;
            match client.claim_task_v2(auth, request.clone()).await {
                Ok(response) => {
                    let job_id: QProvingJobDataID = serde_json::from_value(response.task["base"]["job"]["job_id"].clone())?;
                    self.leases.insert((url_hash, job_id), response.lease);
                    return Ok(Some(response.task));
                }
                Err(error) if category(&error) == Some("NO_WORK") => return Ok(None),
                Err(error) if category(&error) == Some("RATE_LIMITED") => { self.back_off(&error).await; return Ok(None); }
                Err(error) if attempt == 0 && matches!(category(&error), Some("POW_REQUIRED" | "ADMISSION_STALE")) => {
                    self.generations.remove(&scope.hash());
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("admission did not settle")
    }

    /// Submit a proof for a leased job. A proof is expensive and the edge holds
    /// the job until the lease ends, so a rate limited or undelivered
    /// submission is sent again, with a fresh signature, until shortly before
    /// the lease's hard deadline. The edge treats a repeat of the same
    /// submission as the same request.
    pub async fn submit<S: Secp256K1WalletProvider>(&self, client: &HttpClient, url_hash: [u8; 32], signer: &S, public_key: &CompressedPublicKey,
        job_id: QProvingJobDataID, tag: Hash32, proof: Vec<u8>) -> anyhow::Result<()> {
        let scope = self.scope(client, url_hash).await?;
        let (_, lease) = self.leases.remove(&(url_hash, job_id)).ok_or_else(|| anyhow::anyhow!("no V2 lease for job {job_id:?}"))?;
        if lease.reward_tag != tag { anyhow::bail!("lease tag differs from the job's tag"); }
        let submission = ProofSubmission { job: lease.job.clone(), lease_id: lease.lease_id, lease_version: lease.lease_version,
            reward_tag: tag, proof_hash: digest(&proof) };
        let payload_hash = submission.payload_hash(&scope);
        let proof = HexBytes(proof);
        let give_up_at_ms = lease.hard_deadline_ms.saturating_sub(SUBMIT_DEADLINE_MARGIN_MS);
        let outcome = send_with_retry(give_up_at_ms, |wait, error| {
            println!("[worker/v2] submission of {job_id:?} not delivered ({error}), sending again in {wait} ms");
        }, || async {
            let auth = self.sign(signer, public_key, &scope, AdmissionMethod::SubmitProof, lease.owner_generation, payload_hash)
                .map_err(|e| ClientError::Custom(e.to_string()))?;
            client.submit_proof_v2(auth, submission.clone(), proof.clone()).await
        }).await?;
        match outcome {
            SubmitOutcome::Accepted { .. } | SubmitOutcome::InProgress => Ok(()),
            SubmitOutcome::Revoked(receipt) => {
                self.generations.remove(&scope.hash());
                anyhow::bail!("admission revoked, now generation {}", receipt.new_generation)
            }
            other => anyhow::bail!("submission not accepted: {other:?}"),
        }
    }
}

/// How long to wait before sending a request again, or None if the error is
/// final: the edge answered with anything other than RATE_LIMITED, or the
/// request could not be built.
fn retry_wait_ms(error: &ClientError) -> Option<u64> {
    match error {
        ClientError::Call(_) if category(error) == Some("RATE_LIMITED") =>
            Some(retry_after_ms(error).unwrap_or(SUBMIT_TRANSPORT_RETRY_MS).clamp(100, SUBMIT_RETRY_MAX_MS)),
        ClientError::Transport(_) | ClientError::RequestTimeout | ClientError::RestartNeeded(_) => Some(SUBMIT_TRANSPORT_RETRY_MS),
        _ => None,
    }
}

/// Run `attempt` until it succeeds, fails finally, or the next try would start
/// at or after `give_up_at_ms`.
async fn send_with_retry<T, F, Fut>(give_up_at_ms: u64, mut on_retry: impl FnMut(u64, &ClientError), mut attempt: F) -> Result<T, ClientError>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, ClientError>>,
{
    loop {
        let error = match attempt().await {
            Ok(value) => return Ok(value),
            Err(error) => error,
        };
        let Some(wait) = retry_wait_ms(&error) else { return Err(error) };
        if now_ms().saturating_add(wait) >= give_up_at_ms { return Err(error); }
        on_retry(wait, &error);
        tokio::time::sleep(std::time::Duration::from_millis(wait)).await;
    }
}

#[cfg(test)]
mod tests {
    use parth_common::secp256k1::MemorySecp256K1Wallet;
    use psy_worker_admission::{AdmissionPolicy, AdmissionScope};

    use super::*;

    fn edge_error(code: i32, category: &str, retry_after_ms: Option<&str>) -> ClientError {
        let data = match retry_after_ms {
            Some(ms) => serde_json::json!({ "category": category, "retry_after_ms": ms }),
            None => serde_json::json!({ "category": category, "retry_after_ms": null }),
        };
        ClientError::Call(jsonrpsee::types::ErrorObjectOwned::owned(code, category.to_string(), Some(data)))
    }

    async fn run_script(script: Vec<Result<u32, ClientError>>, give_up_at_ms: u64) -> (Result<u32, ClientError>, usize, Vec<u64>) {
        let script = std::sync::Mutex::new(std::collections::VecDeque::from(script));
        let attempts = std::sync::atomic::AtomicUsize::new(0);
        let mut waits = Vec::new();
        let result = send_with_retry(give_up_at_ms, |wait, _| waits.push(wait), || {
            attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let next = script.lock().unwrap().pop_front().expect("script exhausted");
            async move { next }
        }).await;
        (result, attempts.into_inner(), waits)
    }

    #[tokio::test]
    async fn rate_limited_submission_is_sent_again_after_retry_after() {
        let started = std::time::Instant::now();
        let (result, attempts, waits) = run_script(vec![
            Err(edge_error(-32109, "RATE_LIMITED", Some("150"))),
            Err(edge_error(-32109, "RATE_LIMITED", Some("120"))),
            Ok(7),
        ], now_ms() + 60_000).await;
        assert_eq!(result.unwrap(), 7);
        assert_eq!(attempts, 3);
        assert_eq!(waits, vec![150, 120]);
        assert!(started.elapsed() >= std::time::Duration::from_millis(270));
    }

    #[tokio::test]
    async fn transport_failure_is_retried() {
        let (result, attempts, waits) = run_script(vec![Err(ClientError::RequestTimeout), Ok(1)], now_ms() + 60_000).await;
        assert_eq!(result.unwrap(), 1);
        assert_eq!(attempts, 2);
        assert_eq!(waits, vec![SUBMIT_TRANSPORT_RETRY_MS]);
    }

    #[tokio::test]
    async fn edge_rejection_other_than_rate_limit_is_final() {
        let (result, attempts, waits) = run_script(vec![Err(edge_error(-32114, "LEASE_STALE", None))], now_ms() + 60_000).await;
        assert!(matches!(result, Err(ClientError::Call(ref object)) if object.message() == "LEASE_STALE"));
        assert_eq!(attempts, 1);
        assert!(waits.is_empty());
    }

    #[tokio::test]
    async fn retries_stop_before_the_lease_deadline() {
        let (result, attempts, waits) = run_script(vec![Err(edge_error(-32109, "RATE_LIMITED", Some("20000")))], now_ms() + 10_000).await;
        assert!(matches!(result, Err(ClientError::Call(ref object)) if object.message() == "RATE_LIMITED"));
        assert_eq!(attempts, 1);
        assert!(waits.is_empty());
    }

    #[test]
    fn retry_wait_is_bounded() {
        assert_eq!(retry_wait_ms(&edge_error(-32109, "RATE_LIMITED", Some("600000"))), Some(SUBMIT_RETRY_MAX_MS));
        assert_eq!(retry_wait_ms(&edge_error(-32109, "RATE_LIMITED", Some("1"))), Some(100));
        assert_eq!(retry_wait_ms(&edge_error(-32109, "RATE_LIMITED", None)), Some(SUBMIT_TRANSPORT_RETRY_MS));
        assert_eq!(retry_wait_ms(&ClientError::Custom("signing".into())), None);
    }

    #[test]
    fn worker_wallet_signatures_verify_on_the_edge() {
        let state = V2State { generations: DashMap::new(), scopes: DashMap::new(), leases: DashMap::new(),
            recovery: tokio::sync::Mutex::new(()), next_claim_ms: tokio::sync::Mutex::new(0), max_bits: 30 };
        let scope = AdmissionScope { network_id: FixedBytes([1; 32]), admission_epoch: FixedBytes([2; 32]), node_type: 1, realm_id: 0, realm_sub_id: 0 };
        let policy = AdmissionPolicy::for_base_bits(8);
        for seed in 1..=32u8 {
            let mut wallet = MemorySecp256K1Wallet::new();
            let public_key = wallet.add_private_key(Hash256([seed; 32])).unwrap();
            let request = ClaimRequest { reward_tag: FixedBytes([seed; 32]) };
            let auth = state.sign(&wallet, &public_key, &scope, AdmissionMethod::ClaimTask, 0, request.payload_hash()).unwrap();
            auth.verify(&scope, &policy, AdmissionMethod::ClaimTask, request.payload_hash(), now_ms()).unwrap();
        }
    }
}
