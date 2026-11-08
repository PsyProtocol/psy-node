//! Run only against an explicitly configured observe-mode test edge. Identity
//! comes from an environment variable and is never printed or passed in argv.
use std::{sync::atomic::AtomicBool, time::{Duration, SystemTime, UNIX_EPOCH}};

use jsonrpsee::http_client::HttpClientBuilder;
use psy_worker_admission::{*, rpc::WorkerAdmissionRpcClient, store::AdmissionState};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fn now() -> u64 { SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_millis() as u64 }

fn signed(scope: &AdmissionScope, secret: &SecretKey, method: AdmissionMethod, generation: u64, payload_hash: Hash32) -> RequestAuth {
    let issued_at_ms = now();
    let mut auth = RequestAuth { scope: scope.clone(), public_key: FixedBytes(PublicKey::from_secret_key(&Secp256k1::new(), secret).serialize()),
        method, request_id: FixedBytes::random(), issued_at_ms, valid_until_ms: issued_at_ms + 60_000,
        expected_generation: generation, payload_hash, signature: FixedBytes([0; 64]) };
    auth.sign(secret).expect("matching signing key");
    auth
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let endpoint = std::env::args().nth(1).ok_or("usage: pow_probe <trusted-edge-url>")?;
    let mut secret_bytes = [0; 32];
    hex::decode_to_slice(std::env::var("PSY_WORKER_ADMISSION_PROBE_PRIVATE_KEY")?, &mut secret_bytes).map_err(|_| "invalid private key encoding")?;
    let secret = SecretKey::from_byte_array(secret_bytes)?;
    let expected_network: Hash32 = serde_json::from_value(serde_json::Value::String(std::env::var("PSY_WORKER_ADMISSION_NETWORK_ID")?))?;
    let max_bits: u16 = std::env::var("PSY_WORKER_ADMISSION_PROBE_MAX_BITS").unwrap_or_else(|_| "30".into()).parse()?;
    let client = HttpClientBuilder::default().request_timeout(Duration::from_secs(10)).build(endpoint)?;
    let info = client.get_admission_info().await?;
    if info.scope.network_id != expected_network || info.protocol_version != 1 || info.algorithm != "sha256"
        || info.mode != "observe" || info.task_enforcement {
        return Err("edge does not match the expected network and observe protocol".into());
    }
    let status = client.get_admission_status(signed(&info.scope, &secret, AdmissionMethod::GetStatus, 0, empty_payload())).await?;
    if status.status == AdmissionState::Active {
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }
    if status.cooldown_until_ms > now() { return Err("identity is cooling down; retry after its cooldown deadline".into()); }
    let response = client.get_pow_challenge(signed(&info.scope, &secret, AdmissionMethod::GetChallenge, status.generation, empty_payload())).await?;
    let challenge = response.challenge;
    challenge.validate()?;
    if response.challenge_id != challenge.id() || challenge.scope != info.scope
        || challenge.worker_public_key.0 != PublicKey::from_secret_key(&Secp256k1::new(), &secret).serialize()
        || challenge.generation != status.generation || challenge.difficulty_bits > max_bits {
        return Err("unexpected challenge identity, generation or work budget".into());
    }
    let mut start = 0u128;
    let nonce = loop {
        if now() >= challenge.expires_at_ms { return Err("challenge expired; request a fresh challenge".into()); }
        let batch = challenge.clone();
        let found = tokio::task::spawn_blocking(move || solve_batch(&batch, start, 65_536, &AtomicBool::new(false))).await??;
        if let Some(nonce) = found { break nonce; }
        start = start.checked_add(65_536).ok_or("nonce space exhausted")?;
    };
    let solution = PowSolution { challenge_id: challenge.id(), nonce };
    let auth = signed(&info.scope, &secret, AdmissionMethod::SubmitPow, status.generation, solution.payload_hash());
    let response = client.submit_pow(auth, solution).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
