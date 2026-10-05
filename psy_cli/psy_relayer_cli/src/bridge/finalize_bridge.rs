use std::{fs, path::PathBuf};

use alloy_primitives::{Address, Bytes, U256};
use alloy_sol_types::{sol, SolCall};
use anyhow::{Context, Result};
use clap::Args;
use serde::{Deserialize, Serialize};
use crate::bridge::constants::DEFAULT_L1_RPC_URL;
use crate::bridge::daemon::AggregateLimits;
use crate::bridge::l1_client::L1Client;
use crate::bridge::l1_signer::load_l1_wallet;

sol! {
    function applyBridgeWindow(uint256[8] finalizeProof, uint256[] checkpointPI, uint256[8] depositProof, bytes depositOpening, uint256[8] withdrawalProof, bytes withdrawalOpening, uint256[8] rewardProof, bytes rewardOpening);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgeWindowCall {
    pub finalize_proof: [U256; 8],
    pub checkpoint_pi: Vec<U256>,
    pub deposit_proof: [U256; 8],
    pub deposit_opening: Bytes,
    pub withdrawal_proof: [U256; 8],
    pub withdrawal_opening: Bytes,
    pub reward_proof: [U256; 8],
    pub reward_opening: Bytes,
}

impl BridgeWindowCall {
    pub(crate) fn encode(&self) -> Bytes {
        applyBridgeWindowCall {
            finalizeProof: self.finalize_proof,
            checkpointPI: self.checkpoint_pi.clone(),
            depositProof: self.deposit_proof,
            depositOpening: self.deposit_opening.clone(),
            withdrawalProof: self.withdrawal_proof,
            withdrawalOpening: self.withdrawal_opening.clone(),
            rewardProof: self.reward_proof,
            rewardOpening: self.reward_opening.clone(),
        }.abi_encode().into()
    }
}

pub(crate) fn finalize_statement(inputs: &[U256]) -> Result<[u8; 32]> {
    anyhow::ensure!(inputs.len() >= 35 && inputs.len() <= 26 + 9 * 256 && (inputs.len() - 26) % 9 == 0, "finalize endpoint PI width mismatch");
    let mut bytes = vec![0u8; 144 + 8 * (inputs.len() - 26)];
    let mut offset = 0;
    for index in 0..inputs.len() {
        if (4..20).contains(&index) {
            let value = u32::try_from(inputs[index ^ 1]).context("finalize slot exceeds u32")?;
            bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
            offset += 4;
        } else {
            let value = u64::try_from(inputs[index]).context("finalize input exceeds u64")?;
            bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
            offset += 8;
        }
    }
    Ok(alloy_primitives::keccak256(bytes).0)
}

#[derive(Clone, Args)]
pub struct FinalizeBridgeAggArgs {
    #[arg(long)]
    pub window_json: PathBuf,
    #[arg(long)]
    pub config: PathBuf,
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
    let config = psy_client_data::bridge_aggregate::NetworkConfig::decode(&fs::read(&args.config)?)?;
    let limits: AggregateLimits = serde_json::from_slice(&fs::read(&args.aggregate_limits)?)?;
    limits.validate(&config)?;
    let window: BridgeWindowCall = serde_json::from_slice(&fs::read(&args.window_json)?)?;
    let chain = config.chains.iter().find(|chain| chain.chain_index == args.chain_index)
        .context("configured chain index not found")?;
    let wallet = load_l1_wallet(args.private_key.as_deref(), args.keystore_path.as_deref(),
        Some(&args.password_env), None, "aggregate L1 signer")?;
    let sender = L1Client::bind_endpoint(&args.l1_rpc_url, wallet)?;
    let tx = sender.preflight_aggregate(&config, args.chain_index, Address::from(chain.state_manager), window.encode(), &limits).await?;
    let hash = sender.broadcast_prepared(tx).await?;
    println!("{hash}");
    Ok(())
}
