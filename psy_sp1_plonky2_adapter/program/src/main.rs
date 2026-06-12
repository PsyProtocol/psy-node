//! SP1 Plonky2 Verifier Program
//!
//! This is the main entry point for the SP1 zkVM program that:
//! 1. Reads Plonky2 proof data
//! 2. Verifies the Plonky2 proof
//! 3. Commits public values for Groth16 output

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_plonky2_program::verifier::{
    compute_public_inputs_hash, split_hash_to_bn254, verify_plonky2_artifacts,
};
use sp1_plonky2_lib::Groth16PublicValues;

/// Main entry point for SP1
fn main() {
    // Read full input payload in canonical order.
    let proof_bytes = sp1_zkvm::io::read_vec();
    let verifier_only_bytes = sp1_zkvm::io::read_vec();
    let common_data_bytes = sp1_zkvm::io::read_vec();
    let context_bytes = sp1_zkvm::io::read_vec();

    let public_inputs = match verify_plonky2_artifacts(
        proof_bytes,
        verifier_only_bytes,
        common_data_bytes,
        &context_bytes,
    ) {
        Ok(v) => v,
        Err(e) => {
            panic!("Plonky2 verification failed: {}", e);
        }
    };

    let public_inputs_hash = compute_public_inputs_hash(&public_inputs);
    let (hi, lo) = split_hash_to_bn254(&public_inputs_hash);

    let groth16_public_values = Groth16PublicValues {
        digest_hi: hi,
        digest_lo: lo,
        num_public_inputs: public_inputs.len() as u32,
        schema_version: sp1_plonky2_lib::PUBLIC_VALUES_SCHEMA_VERSION,
    };

    let encoded = groth16_public_values.abi_encode();
    sp1_zkvm::io::commit_slice(&encoded);
}
