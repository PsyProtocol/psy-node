//! Single-thread PoW hash rate on this machine, and the expected solve time
//! per difficulty. The worker solves on one blocking thread, so this is the
//! admission cost a worker pays. Usage: pow_bench [seconds]
use std::{sync::atomic::AtomicBool, time::Instant};

use psy_worker_admission::*;

fn main() {
    let seconds: f64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(5.0);
    let scope = AdmissionScope { network_id: FixedBytes([1; 32]), admission_epoch: FixedBytes([2; 32]), node_type: 1, realm_id: 0, realm_sub_id: 1 };
    // 255 bits is never met, so every batch runs to the end.
    // A fixed valid public key (the secp256k1 generator); it is only hashed.
    let generator = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").expect("hex");
    let challenge = PowChallenge { protocol_version: 1, algorithm: 1, scope, worker_public_key: FixedBytes(generator.try_into().expect("33 bytes")),
        generation: 0, policy_version: 1, issued_at_ms: 1, expires_at_ms: u64::MAX, difficulty_bits: 255, random: FixedBytes([3; 32]) };
    let cancel = AtomicBool::new(false);
    let batch = 1u64 << 20;
    let (started, mut hashes, mut start) = (Instant::now(), 0u64, 0u128);
    while started.elapsed().as_secs_f64() < seconds {
        let _ = solve_batch(&challenge, start, batch, &cancel).expect("valid challenge");
        hashes += batch;
        start += batch as u128;
    }
    let rate = hashes as f64 / started.elapsed().as_secs_f64();
    println!("hash_rate_per_s={rate:.0}");
    for bits in [20u32, 22, 24, 26, 28, 30, 32] {
        let mean = 2f64.powi(bits as i32) / rate;
        // Solve time is geometric: the 95th percentile is about 3x the mean.
        println!("bits={bits} mean_s={mean:.2} p95_s={:.2}", mean * 3.0);
    }
}
