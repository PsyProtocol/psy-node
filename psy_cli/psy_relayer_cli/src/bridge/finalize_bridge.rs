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
    function applyBridgeOpening(uint256[8] proof, bytes opening);
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BridgeOpeningCall {
    pub proof: [U256; 8],
    pub opening: Bytes,
}

impl BridgeOpeningCall {
    pub(crate) fn encode(&self) -> Bytes {
        applyBridgeOpeningCall { proof: self.proof, opening: self.opening.clone() }.abi_encode().into()
    }

    pub(crate) fn validated(&self, config: &psy_client_data::bridge_aggregate::NetworkConfig) -> Result<psy_client_data::bridge_aggregate::BridgeOpening> {
        let opening = psy_client_data::bridge_aggregate::BridgeOpening::decode(&self.opening)
            .map_err(|error| anyhow::anyhow!("bridge opening: {error:?}"))?;
        let canonical = opening.encode().map_err(|error| anyhow::anyhow!("bridge opening: {error:?}"))?;
        anyhow::ensure!(canonical.as_slice() == self.opening.as_ref(), "bridge opening bytes are not canonical");
        opening.validate_config(config).map_err(|error| anyhow::anyhow!("bridge opening config: {error:?}"))?;
        let _ = opening.opening_digest().map_err(|error| anyhow::anyhow!("bridge opening digest: {error:?}"))?;
        Ok(opening)
    }
}

#[derive(Clone, Args)]
pub struct FinalizeBridgeAggArgs {
    #[arg(long)]
    pub opening_json: PathBuf,
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
    let opening_call: BridgeOpeningCall = serde_json::from_slice(&fs::read(&args.opening_json)?)?;
    let _opening = opening_call.validated(&config)?;
    let chain = config.chains.iter().find(|chain| chain.chain_index == args.chain_index)
        .context("configured chain index not found")?;
    let wallet = load_l1_wallet(args.private_key.as_deref(), args.keystore_path.as_deref(),
        Some(&args.password_env), None, "aggregate L1 signer")?;
    let sender = L1Client::bind_endpoint(&args.l1_rpc_url, wallet)?;
    let tx = sender.preflight_aggregate(&config, args.chain_index, Address::from(chain.state_manager), opening_call.encode(), &limits).await?;
    let hash = sender.broadcast_prepared(tx).await?;
    println!("{hash}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{applyBridgeOpeningCall, BridgeOpeningCall};
    use alloy_primitives::{Bytes, U256};
    use alloy_sol_types::SolCall;

    #[test]
    fn one_proof_selector_carries_opening_bytes() {
        let opening = vec![4u8, 12, 0, 0, 9];
        let call = BridgeOpeningCall { proof: [U256::from(3u8); 8], opening: Bytes::from(opening.clone()) };
        let encoded = call.encode();
        assert_eq!(&encoded[..4], applyBridgeOpeningCall::SELECTOR.as_slice());
        let decoded = applyBridgeOpeningCall::abi_decode(&encoded).unwrap();
        assert_eq!(decoded.proof, [U256::from(3u8); 8]);
        assert_eq!(decoded.opening.as_ref(), opening.as_slice());
        assert!(std::str::from_utf8(applyBridgeOpeningCall::SIGNATURE.as_bytes()).unwrap().contains("uint256[8],bytes")
            && !std::str::from_utf8(applyBridgeOpeningCall::SIGNATURE.as_bytes()).unwrap().contains("depositOpening"));
    }

    #[test]
    fn noncanonical_opening_never_reaches_preflight() {
        let config = psy_client_data::bridge_aggregate::NetworkConfig {
            version: 1, network_magic: 0, bridge_user_id: psy_client_data::bridge_aggregate::BRIDGE_USER_ID,
            circuit_set_hash: [7; 32], chains: Vec::new(), ethereum_index: 0,
            reward_payer: [3; 20], reward_token: [4; 20], reward_per_claim: [0; 32],
            reward_token_decimals: 0, max_withdrawals: 1, max_rewards: 1,
        };
        let call = BridgeOpeningCall { proof: [U256::ZERO; 8], opening: Bytes::from(vec![0u8, 1, 2, 3]) };
        assert!(call.validated(&config).is_err(), "a noncanonical opening must fail before preflight");
    }
}
