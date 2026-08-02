use anyhow::{Context, Result};
use clap::Parser;
use sp1_plonky2_lib::{Groth16PublicValues, PlonkProofFixture, PUBLIC_VALUES_SCHEMA_VERSION};
use sp1_sdk::{
    blocking::{Prover, ProverClient, SP1Stdin},
    include_elf, Elf,
};

const PLONKY2_ADAPTER_ELF: Elf = include_elf!("sp1-plonky2-program");
const EXPECTED_NUM_PUBLIC_INPUTS: u32 = 52;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    valid: String,
    #[arg(long, default_value = "fixtures/invalid_context_fixture.json")]
    invalid: String,
}

fn main() -> Result<()> {
    sp1_sdk::utils::setup_logger();
    let args = Args::parse();

    run_valid_case(&args.valid)?;
    run_invalid_case(&args.invalid)?;
    run_invalid_crypto_case(&args.valid)?;

    println!("Matrix check passed: valid+invalid cases behaved as expected.");
    Ok(())
}

fn run_valid_case(path: &str) -> Result<()> {
    let fixture = PlonkProofFixture::from_json(path).with_context(|| format!("load valid fixture failed: {path}"))?;
    fixture.validate().context("valid fixture should pass validate")?;

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&fixture.proof_bytes);
    stdin.write_slice(&fixture.verifier_only_bytes);
    stdin.write_slice(&fixture.common_data_bytes);
    stdin.write_slice(&fixture.context_bytes);

    let (output, _) = client
        .execute(PLONKY2_ADAPTER_ELF, stdin)
        .run()
        .context("execute failed on valid fixture")?;

    let pv = Groth16PublicValues::abi_decode(output.as_slice()).map_err(anyhow::Error::msg)?;
    if pv.schema_version != PUBLIC_VALUES_SCHEMA_VERSION {
        anyhow::bail!(
            "invalid schema_version from program: got {}, expected {}",
            pv.schema_version,
            PUBLIC_VALUES_SCHEMA_VERSION
        );
    }
    if pv.num_public_inputs != EXPECTED_NUM_PUBLIC_INPUTS {
        anyhow::bail!(
            "invalid num_public_inputs from program: got {}, expected {}",
            pv.num_public_inputs,
            EXPECTED_NUM_PUBLIC_INPUTS
        );
    }

    Ok(())
}

fn run_invalid_case(path: &str) -> Result<()> {
    let fixture = PlonkProofFixture::from_json(path).with_context(|| format!("load invalid fixture failed: {path}"))?;
    if fixture.validate().is_ok() {
        anyhow::bail!("invalid fixture unexpectedly passed validate");
    }
    Ok(())
}

fn run_invalid_crypto_case(valid_path: &str) -> Result<()> {
    let mut fixture = PlonkProofFixture::from_json(valid_path)
        .with_context(|| format!("load valid fixture for crypto-invalid case failed: {valid_path}"))?;
    fixture
        .validate()
        .context("valid fixture should pass validate before crypto mutation")?;

    if fixture.proof_bytes.is_empty() {
        anyhow::bail!("valid fixture has empty proof_bytes");
    }

    // Keep serialization shape valid while breaking proof integrity.
    fixture.proof_bytes[0] ^= 0x01;

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(&fixture.proof_bytes);
    stdin.write_slice(&fixture.verifier_only_bytes);
    stdin.write_slice(&fixture.common_data_bytes);
    stdin.write_slice(&fixture.context_bytes);

    let result = client.execute(PLONKY2_ADAPTER_ELF, stdin).run();
    if result.is_ok() {
        anyhow::bail!("crypto-invalid case unexpectedly succeeded");
    }

    Ok(())
}
