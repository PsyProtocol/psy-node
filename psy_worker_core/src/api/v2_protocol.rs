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
                recovery: tokio::sync::Mutex::new(()), max_bits }))
        }
        Ok(other) => anyhow::bail!("unsupported PSY_WORKER_TASK_PROTOCOL {other}"),
        Err(_) => anyhow::bail!("PSY_WORKER_TASK_PROTOCOL is not valid unicode"),
    }
}

fn now_ms() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0) }

fn category(error: &ClientError) -> Option<&str> {
    match error { ClientError::Call(object) => Some(object.message()), _ => None }
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

    /// Claim one task, recovering admission once if the edge requires it.
    pub async fn claim<S: Secp256K1WalletProvider>(&self, client: &HttpClient, url_hash: [u8; 32], signer: &S, public_key: &CompressedPublicKey, tag: Hash32)
        -> anyhow::Result<Option<serde_json::Value>> {
        let scope = self.scope(client, url_hash).await?;
        let request = ClaimRequest { reward_tag: tag };
        for attempt in 0..2 {
            let generation = match self.generations.get(&scope.hash()).map(|g| *g) {
                Some(generation) => generation,
                None => self.recover(client, &scope, signer, public_key).await?,
            };
            let auth = self.sign(signer, public_key, &scope, AdmissionMethod::ClaimTask, generation, request.payload_hash())?;
            match client.claim_task_v2(auth, request.clone()).await {
                Ok(response) => {
                    let job_id: QProvingJobDataID = serde_json::from_value(response.task["base"]["job"]["job_id"].clone())?;
                    self.leases.insert((url_hash, job_id), response.lease);
                    return Ok(Some(response.task));
                }
                Err(error) if category(&error) == Some("NO_WORK") => return Ok(None),
                Err(error) if attempt == 0 && matches!(category(&error), Some("POW_REQUIRED" | "ADMISSION_STALE")) => {
                    self.generations.remove(&scope.hash());
                }
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("admission did not settle")
    }

    pub async fn submit<S: Secp256K1WalletProvider>(&self, client: &HttpClient, url_hash: [u8; 32], signer: &S, public_key: &CompressedPublicKey,
        job_id: QProvingJobDataID, tag: Hash32, proof: Vec<u8>) -> anyhow::Result<()> {
        let scope = self.scope(client, url_hash).await?;
        let (_, lease) = self.leases.remove(&(url_hash, job_id)).ok_or_else(|| anyhow::anyhow!("no V2 lease for job {job_id:?}"))?;
        if lease.reward_tag != tag { anyhow::bail!("lease tag differs from the job's tag"); }
        let submission = ProofSubmission { job: lease.job.clone(), lease_id: lease.lease_id, lease_version: lease.lease_version,
            reward_tag: tag, proof_hash: digest(&proof) };
        let auth = self.sign(signer, public_key, &scope, AdmissionMethod::SubmitProof, lease.owner_generation, submission.payload_hash(&scope))?;
        match client.submit_proof_v2(auth, submission, HexBytes(proof)).await? {
            SubmitOutcome::Accepted { .. } | SubmitOutcome::InProgress => Ok(()),
            SubmitOutcome::Revoked(receipt) => {
                self.generations.remove(&scope.hash());
                anyhow::bail!("admission revoked, now generation {}", receipt.new_generation)
            }
            other => anyhow::bail!("submission not accepted: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use parth_common::secp256k1::MemorySecp256K1Wallet;
    use psy_worker_admission::{AdmissionPolicy, AdmissionScope};

    use super::*;

    #[test]
    fn worker_wallet_signatures_verify_on_the_edge() {
        let state = V2State { generations: DashMap::new(), scopes: DashMap::new(), leases: DashMap::new(),
            recovery: tokio::sync::Mutex::new(()), max_bits: 30 };
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
