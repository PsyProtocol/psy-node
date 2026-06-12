//! SP1 Plonky2 Adapter - Execute or Prove
//!
//! This binary can:
//! - Execute the program without generating a proof (--execute)
//! - Generate a core SP1 proof (--prove)
//!
//! Usage:
//!   cargo run --release --bin main -- --execute --input proof.json
//!   cargo run --release --bin main -- --prove --input proof.json

use clap::Parser;
use anyhow::{Context, Result};
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, Elf,
    ProvingKey,
};
use sp1_plonky2_lib::{Groth16PublicValues, PlonkProofFixture};

/// The ELF (executable and linkable format) for the SP1 zkVM
const PLONKY2_ADAPTER_ELF: Elf = include_elf!("sp1-plonky2-program");
const EXPECTED_NUM_PUBLIC_INPUTS: u32 = 52;

/// Command line arguments
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Execute the program without generating a proof
    #[arg(long)]
    execute: bool,

    /// Generate a core SP1 proof
    #[arg(long)]
    prove: bool,

    /// Input JSON file containing real proof fixture
    #[arg(long)]
    input: Option<String>,

    /// Print full execution report details
    #[arg(long, default_value_t = false)]
    verbose_report: bool,
}

fn main() -> Result<()> {
    // Setup logger
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();

    // Parse arguments
    let args = Args::parse();

    // Must specify exactly one of --execute or --prove
    if args.execute == args.prove {
        anyhow::bail!("You must specify exactly one of --execute or --prove");
    }

    // Setup prover client
    let client = ProverClient::from_env();

    // Load proof fixture
    let path = args
        .input
        .as_deref()
        .context("missing --input: please provide a real Plonky2 fixture JSON")?;
    println!("Loading fixture from: {}", path);
    let fixture = PlonkProofFixture::from_json(path).with_context(|| format!("failed to load fixture: {path}"))?;
    fixture.validate().context("invalid fixture payload")?;

    // Setup inputs
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&fixture.proof_bytes);
    stdin.write_slice(&fixture.verifier_only_bytes);
    stdin.write_slice(&fixture.common_data_bytes);
    stdin.write_slice(&fixture.context_bytes);

    if args.execute {
        // ============ Execute (no proof) ============
        println!("Executing program...");

        let (output, report) = client
            .execute(PLONKY2_ADAPTER_ELF, stdin)
            .run()
            .context("failed to execute SP1 program")?;

        println!("Program executed successfully!");

        // Decode and print public values
        let decoded = Groth16PublicValues::abi_decode(output.as_slice());
        match decoded {
            Ok(pv) => {
                if pv.schema_version != sp1_plonky2_lib::PUBLIC_VALUES_SCHEMA_VERSION {
                    anyhow::bail!(
                        "invalid schema version from program: got {}, expected {}",
                        pv.schema_version,
                        sp1_plonky2_lib::PUBLIC_VALUES_SCHEMA_VERSION
                    );
                }
                if pv.num_public_inputs != EXPECTED_NUM_PUBLIC_INPUTS {
                    anyhow::bail!(
                        "invalid num_public_inputs from program: got {}, expected {}",
                        pv.num_public_inputs,
                        EXPECTED_NUM_PUBLIC_INPUTS
                    );
                }
                println!(
                    "Public values: digest_hi={}, digest_lo={}, num_public_inputs={}, schema={}",
                    pv.digest_hi, pv.digest_lo, pv.num_public_inputs, pv.schema_version
                );
            }
            Err(e) => {
                anyhow::bail!("failed to decode public values: {e}");
            }
        }

        // Print statistics
        println!("Number of cycles: {}", report.total_instruction_count());
        println!("syscall counter: {}", report.total_syscall_count());
        if let Some(gas) = report.gas() {
            println!("normalized gas: {}", gas);
        }
        if args.verbose_report {
            println!("Detailed execution report:\n{}", report);
        }
    } else {
        // ============ Generate Proof ============
        println!("Setting up program...");

        let pk = client
            .setup(PLONKY2_ADAPTER_ELF)
            .context("failed to setup SP1 program")?;

        println!("Generating proof...");

        let proof = client
            .prove(&pk, stdin)
            .run()
            .context("failed to generate core SP1 proof")?;

        println!("Proof generated successfully!");

        // Verify the proof
        println!("Verifying proof...");

        client
            .verify(&proof, pk.verifying_key(), None)
            .context("failed to verify generated SP1 proof")?;

        println!("Proof verified successfully!");

        // Save proof to file
        let proof_path = "proof.json";
        std::fs::write(
            proof_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "publicValues": hex::encode(&proof.public_values),
                "proof": hex::encode(&proof.bytes()),
            }))
            .context("failed to serialize proof artifact")?,
        )
        .with_context(|| format!("failed to write proof artifact: {proof_path}"))?;

        println!("Proof saved to {}", proof_path);
    }
    Ok(())
}
