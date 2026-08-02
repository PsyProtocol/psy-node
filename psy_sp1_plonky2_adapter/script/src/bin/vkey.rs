//! SP1 Plonky2 Adapter - Get Verification Key
//!
//! This binary outputs the verification key for the SP1 program.
//! The vkey is used in on-chain verification of SP1 proofs.
//!
//! Usage:
//!   cargo run --release --bin vkey

use sp1_sdk::{
    blocking::{Prover, ProverClient},
    include_elf, Elf,
    HashableKey,
    ProvingKey,
};
use anyhow::{Context, Result};

/// The ELF for the SP1 zkVM
const PLONKY2_ADAPTER_ELF: Elf = include_elf!("sp1-plonky2-program");

fn main() -> Result<()> {
    // Setup logger
    sp1_sdk::utils::setup_logger();

    println!("Setting up program...");

    let client = ProverClient::from_env();
    let pk = client
        .setup(PLONKY2_ADAPTER_ELF)
        .context("failed to setup SP1 program")?;

    let vk = pk.verifying_key();

    // Print the vkey in various formats
    println!("========================================");
    println!("SP1 Plonky2 Adapter Verification Key");
    println!("========================================");
    println!("vkey (bytes32): 0x{}", hex::encode(vk.bytes32()));
    println!("========================================");

    // Save vkey to file
    let vkey_path = "vkey.txt";
    std::fs::write(
        vkey_path,
        format!("0x{}", hex::encode(vk.bytes32())),
    )
    .with_context(|| format!("failed to write vkey: {vkey_path}"))?;

    println!("Verification key saved to {}", vkey_path);
    Ok(())
}
