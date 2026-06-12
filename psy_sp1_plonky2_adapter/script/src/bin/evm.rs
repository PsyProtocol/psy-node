//! SP1 Plonky2 Adapter - EVM Proof Generation
//!
//! This binary generates EVM-compatible proofs (Groth16 or PLONK)
//! that can be verified on-chain.
//!
//! Usage:
//!   cargo run --release --bin evm -- --system groth16
//!   cargo run --release --bin evm -- --system plonk
//!   cargo run --release --bin evm -- --system groth16 --input fixture.json
//! Note: --input is required and must point to a real fixture.

use clap::{Parser, ValueEnum};
use anyhow::{Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, Elf, HashableKey,
    ProvingKey,
    SP1ProofWithPublicValues,
};
use serde::{Deserialize, Serialize};
use sp1_plonky2_lib::{Groth16PublicValues, PlonkProofFixture};
use std::path::PathBuf;

/// The ELF for the SP1 zkVM
const PLONKY2_ADAPTER_ELF: Elf = include_elf!("sp1-plonky2-program");
const EXPECTED_NUM_PUBLIC_INPUTS: u32 = 52;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Proof system to use
    #[arg(long, value_enum, default_value = "groth16")]
    system: ProofSystem,

    /// Input fixture file (required)
    #[arg(long)]
    input: Option<String>,
}

/// Available proof systems
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProofSystem {
    Groth16,
    Plonk,
}

/// EVM proof fixture for on-chain verification
#[derive(Debug, Serialize, Deserialize)]
struct EvmProofFixture {
    /// Verification key (hash of the program vkey)
    vkey: String,
    /// Public values committed to by the proof
    public_values: String,
    /// Encoded proof bytes
    proof: String,
}

impl EvmProofFixture {
    fn new(proof: &SP1ProofWithPublicValues, vk_bytes: String) -> Self {
        Self {
            vkey: vk_bytes,
            public_values: format!("0x{}", hex::encode(proof.public_values.as_slice())),
            proof: format!("0x{}", hex::encode(proof.bytes())),
        }
    }
}

fn main() -> Result<()> {
    // Setup logger
    sp1_sdk::utils::setup_logger();

    // Parse arguments
    let args = Args::parse();

    // Setup prover client
    let client = ProverClient::from_env();

    // Setup the program
    let pk = client
        .setup(PLONKY2_ADAPTER_ELF)
        .context("failed to setup SP1 program")?;

    println!("Proof system: {:?}", args.system);

    // Load or create fixture
    let path = args
        .input
        .as_deref()
        .context("missing --input: please provide a real Plonky2 fixture JSON")?;
    println!("Loading fixture from: {}", path);
    let fixture = PlonkProofFixture::from_json(path).with_context(|| format!("failed to load fixture: {path}"))?;
    fixture.validate().context("invalid fixture payload")?;

    // Write inputs
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&fixture.proof_bytes);
    stdin.write_slice(&fixture.verifier_only_bytes);
    stdin.write_slice(&fixture.common_data_bytes);
    stdin.write_slice(&fixture.context_bytes);

    // Generate proof based on selected system
    let proof: SP1ProofWithPublicValues = match args.system {
        ProofSystem::Groth16 => {
            println!("Generating Groth16 proof...");
            client
                .prove(&pk, stdin)
                .groth16()
                .run()
                .context("failed to generate Groth16 proof")?
        }
        ProofSystem::Plonk => {
            println!("Generating PLONK proof...");
            client
                .prove(&pk, stdin)
                .plonk()
                .run()
                .context("failed to generate PLONK proof")?
        }
    };

    println!("Proof generated successfully!");

    let pv = Groth16PublicValues::abi_decode(proof.public_values.as_slice())
        .map_err(anyhow::Error::msg)
        .context("failed to decode Groth16 public values from proof")?;
    if pv.schema_version != sp1_plonky2_lib::PUBLIC_VALUES_SCHEMA_VERSION {
        anyhow::bail!(
            "invalid schema version from proof: got {}, expected {}",
            pv.schema_version,
            sp1_plonky2_lib::PUBLIC_VALUES_SCHEMA_VERSION
        );
    }
    if pv.num_public_inputs != EXPECTED_NUM_PUBLIC_INPUTS {
        anyhow::bail!(
            "invalid num_public_inputs from proof: got {}, expected {}",
            pv.num_public_inputs,
            EXPECTED_NUM_PUBLIC_INPUTS
        );
    }

    // Get verifying key bytes
    let vk = pk.verifying_key();
    let vk_bytes = vk.bytes32();

    // Create fixture
    let evm_fixture = EvmProofFixture::new(&proof, vk_bytes);

    // Print results
    println!("========================================");
    println!("Verification Key: {}", evm_fixture.vkey);
    println!("Public Values: {}", evm_fixture.public_values);
    println!("Proof (first 100 chars): {}...", &evm_fixture.proof[..std::cmp::min(100, evm_fixture.proof.len())]);
    println!("========================================");

    // Save fixture to file
    let fixture_filename = format!("{:?}-fixture.json", args.system).to_lowercase();
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../contracts/src/fixtures")
        .join(&fixture_filename);

    // Create directory if it doesn't exist
    if let Some(parent) = fixture_path.parent() {
        std::fs::create_dir_all(parent).with_context(|| format!("failed to create fixture directory: {:?}", parent))?;
    }

    std::fs::write(
        &fixture_path,
        serde_json::to_string_pretty(&evm_fixture).context("failed to serialize evm fixture")?,
    )
    .with_context(|| format!("failed to write fixture: {:?}", fixture_path))?;

    println!("Fixture saved to {:?}", fixture_path);

    println!(
        "Decoded public values: digest_hi={}, digest_lo={}, num_public_inputs={}, schema={}",
        pv.digest_hi, pv.digest_lo, pv.num_public_inputs, pv.schema_version
    );
    Ok(())
}
