use std::{fs, path::PathBuf};

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use anyhow::{Context, Result};
use clap::{Args, ValueEnum};
use psy_client_data::bridge_aggregate::{AOpening, BOpening, NetworkConfig};
use psy_plonky2_circuits::bridge::circuits::bridge_wrap::UncompressedGroth16ProofData;
use crate::bridge::constants::DEFAULT_L1_RPC_URL;
use crate::bridge::daemon::AggregateLimits;
use crate::bridge::l1_client::L1Client;
use crate::bridge::l1_signer::load_l1_wallet;

sol! {
    function applyDepositAggregate(uint256[8] proof, bytes completeOpening);
    function finalizeCheckpointAggregate(uint256[8] proof, bytes completeOpening);
}

pub(crate) fn apply_deposit_aggregate_call(proof: [U256; 8], complete_opening: Bytes) -> Bytes {
    Bytes::from(
        applyDepositAggregateCall {
            proof,
            completeOpening: complete_opening,
        }
        .abi_encode(),
    )
}

pub(crate) fn finalize_checkpoint_aggregate_call(proof: [U256; 8], complete_opening: Bytes) -> Bytes {
    Bytes::from(
        finalizeCheckpointAggregateCall {
            proof,
            completeOpening: complete_opening,
        }
        .abi_encode(),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum AggregateArtifact {
    A,
    B,
}

#[derive(Clone, Args)]
pub struct FinalizeBridgeAggArgs {
    #[arg(long, value_enum)]
    pub artifact: AggregateArtifact,
    #[arg(long)]
    pub proof_json: PathBuf,
    #[arg(long)]
    pub config: PathBuf,
    #[arg(long)]
    pub opening: PathBuf,
    #[arg(long)]
    pub chain_index: u8,
    #[arg(long)]
    pub aggregate_limits: PathBuf,
    #[arg(long, default_value = DEFAULT_L1_RPC_URL)]
    pub l1_rpc_url: String,
    #[arg(long, env = "PRIVATE_KEY")]
    pub private_key: Option<String>,
    #[arg(long, env = "KEYSTORE_PATH")]
    pub keystore_path: Option<PathBuf>,
    #[arg(long, env = "KEYSTORE_PASSWORD_ENV", default_value = "WALLET_PASSWORD")]
    pub password_env: String,
}

pub async fn run(args: FinalizeBridgeAggArgs) -> Result<()> {
    let config_bytes = fs::read(&args.config)
        .with_context(|| format!("failed to read {}", args.config.display()))?;
    let config = NetworkConfig::decode(&config_bytes)
        .context("failed to decode canonical network config")?;
    let limits_text = fs::read_to_string(&args.aggregate_limits)
        .with_context(|| format!("failed to read {}", args.aggregate_limits.display()))?;
    let limits: AggregateLimits = serde_json::from_str(&limits_text)
        .with_context(|| format!("failed to decode {}", args.aggregate_limits.display()))?;
    limits.validate(&config)?;
    let opening_bytes = fs::read(&args.opening)
        .with_context(|| format!("failed to read {}", args.opening.display()))?;
    let proof_text = fs::read_to_string(&args.proof_json)
        .with_context(|| format!("failed to read {}", args.proof_json.display()))?;
    let proof: UncompressedGroth16ProofData = serde_json::from_str(&proof_text)
        .with_context(|| format!("failed to parse {}", args.proof_json.display()))?;
    let chain = config
        .chains
        .iter()
        .find(|chain| chain.chain_index == args.chain_index)
        .context("configured chain index not found")?;
    let (statement, destination) = match args.artifact {
        AggregateArtifact::A => {
            let opening = AOpening::decode(&opening_bytes).context("failed to decode canonical A opening")?;
            opening.validate(&config).context("canonical A opening does not match config")?;
            (
                opening.statement_digest(&config).context("failed to derive A statement")?,
                Address::from(chain.bridge),
            )
        }
        AggregateArtifact::B => {
            let opening = BOpening::decode(&opening_bytes).context("failed to decode canonical B opening")?;
            opening.validate(&config).context("canonical B opening does not match config")?;
            (
                opening.statement_digest(&config).context("failed to derive B statement")?,
                Address::from(chain.state_manager),
            )
        }
    };
    let words = crate::bridge::daemon::parse_aggregate_proof(&proof, statement)
        .context("native proof does not match opening statement")?;
    let call_data = match args.artifact {
        AggregateArtifact::A => apply_deposit_aggregate_call(words, Bytes::from(opening_bytes)),
        AggregateArtifact::B => finalize_checkpoint_aggregate_call(words, Bytes::from(opening_bytes)),
    };
    let wallet = load_l1_wallet(
        args.private_key.as_deref(),
        args.keystore_path.as_deref(),
        Some(&args.password_env),
        None,
        "aggregate L1 signer",
    )?;
    let sender = L1Client::bind_endpoint(&args.l1_rpc_url, wallet)?;
    let tx = sender
        .preflight_aggregate(&config, args.chain_index, destination, call_data, &limits)
        .await?;
    let hash = sender.broadcast_prepared(tx).await?;
    println!("{hash}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolCall;

    #[test]
    fn aggregate_calls_preserve_identical_proof_and_opening() {
        let proof = [
            U256::from(1u8),
            U256::from(2u8),
            U256::from(3u8),
            U256::from(4u8),
            U256::from(5u8),
            U256::from(6u8),
            U256::from(7u8),
            U256::from(8u8),
        ];
        let opening = Bytes::from(vec![0x11, 0x22, 0x33, 0x44]);
        let deposit = apply_deposit_aggregate_call(proof, opening.clone());
        let checkpoint = finalize_checkpoint_aggregate_call(proof, opening.clone());

        assert_eq!(&deposit[..4], applyDepositAggregateCall::SELECTOR.as_slice());
        assert_eq!(&checkpoint[..4], finalizeCheckpointAggregateCall::SELECTOR.as_slice());
        let decoded_deposit = applyDepositAggregateCall::abi_decode(&deposit).unwrap();
        let decoded_checkpoint = finalizeCheckpointAggregateCall::abi_decode(&checkpoint).unwrap();
        assert_eq!(decoded_deposit.proof, proof);
        assert_eq!(decoded_checkpoint.proof, proof);
        assert_eq!(decoded_deposit.completeOpening, opening);
        assert_eq!(decoded_checkpoint.completeOpening, opening);
    }
}
