use std::str::FromStr;

use alloy_primitives::U256;
use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_config::network_constants::TOKEN_CONTRACT_ID;
use psy_provider::provider::RpcProvider;

use super::{args::WithdrawArgs, submit_end_cap_proof};
use crate::result::{CommandResult, TransactionResult, TransactionStatus};

/// Parse a 20-byte EVM address or 32-byte hex string into 8 big-endian u32
/// words. 20-byte inputs are left-padded to bytes32 so callers can pass normal
/// `0x...` addresses without manual conversion.
fn parse_hash_hex_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
    let raw = hex_str.trim().trim_start_matches("0x").trim_start_matches("0X");
    let byte_offset = match raw.len() {
        40 => 12,
        64 => 0,
        len => anyhow::bail!("hash hex must be 40 or 64 hex chars (20 or 32 bytes), got {}: {}", len, raw),
    };
    let mut bytes = [0u8; 32];
    for (i, hex_index) in (0..raw.len()).step_by(2).enumerate() {
        bytes[byte_offset + i] = u8::from_str_radix(&raw[hex_index..hex_index + 2], 16).map_err(|e| anyhow::anyhow!("hex decode error: {}", e))?;
    }
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    Ok(words)
}

fn u64_to_u32x8_be(value: u64) -> [u32; 8] {
    [0, 0, 0, 0, 0, 0, (value >> 32) as u32, (value & 0xffff_ffff) as u32]
}

/// Resolve the Router contract address from deployment artifacts.
fn resolve_router_address(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Router_Proxy", "Router", "Router_Proxy.json")
}

/// Query Router.l1ToL2Token(address) → bytes32 via eth_call on L1.
async fn query_l1_to_l2_token(l1_rpc_url: &str, router_addr: &str, token_address: &str) -> anyhow::Result<U256> {
    // selector = keccak256("l1ToL2Token(address)")[:4]
    let selector = "8a2dc014";
    let raw_token = token_address.trim().trim_start_matches("0x").trim_start_matches("0X");
    let raw_address = match raw_token.len() {
        40 => raw_token,
        64 => &raw_token[24..],
        len => anyhow::bail!("token address must be 20 or 32 bytes, got {} hex chars", len),
    };
    let token_padded = format!("{:0>64}", raw_address.to_lowercase());

    let call_data = format!("0x{}{}", selector, token_padded);

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_call",
        "params": [{"to": router_addr, "data": call_data}, "latest"],
    });
    let client = reqwest::Client::new();
    let resp = client.post(l1_rpc_url).json(&body).send().await?;
    let result: serde_json::Value = resp.json().await?;

    if let Some(err) = result.get("error") {
        anyhow::bail!("eth_call error: {} - {:?}", err["message"], err.get("data"));
    }

    let hex_result = result["result"].as_str().unwrap_or("0x0");
    let u256 = U256::from_str(hex_result).map_err(|e| anyhow::anyhow!("parse hex result: {}", e))?;
    Ok(u256)
}

pub async fn run(args: WithdrawArgs) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    // 1. Determine L2 contract ID
    let contract_id = if let Some(override_id) = args.contract_id {
        tracing::info!(contract_id = override_id, "using explicit contract_id override");
        override_id
    } else {
        // Query Router.l1ToL2Token to auto-detect
        let router_addr = resolve_router_address("localhost").unwrap_or_else(|_| "0x23D7517b23756C322AEE30d068c107301fFb3470".to_string());
        match query_l1_to_l2_token(&args.l1_rpc_url, &router_addr, &args.token_address).await {
            Ok(l2_token_bytes) if !l2_token_bytes.is_zero() => {
                // The bytes32 is big-endian u64; the last 8 bytes encode the contract_id
                let bytes = l2_token_bytes.to_be_bytes::<32>();
                let cid = u64::from_be_bytes(bytes[24..32].try_into().unwrap());
                tracing::info!(
                    l1_token = %args.token_address,
                    l2_contract_id = cid,
                    "resolved L2 contract ID from Router"
                );
                cid
            }
            _ => {
                tracing::warn!(
                    "Router returned zero for token {}, falling back to TOKEN_CONTRACT_ID={}",
                    args.token_address,
                    TOKEN_CONTRACT_ID,
                );
                TOKEN_CONTRACT_ID as u64
            }
        }
    };

    // 2. Parse hex inputs → 8 u32 felts each
    let token_address = parse_hash_hex_u32x8(&args.token_address)?;
    let amount = u64_to_u32x8_be(args.amount);
    let recipient = parse_hash_hex_u32x8(&args.recipient)?;

    // 3. Build contract call inputs withdraw(destination_chain_index,
    //    token_address[8], amount[8], recipient[8], nonce[8]) = 33 felts total
    let nonce_u32x8 = parse_hash_hex_u32x8(&args.nonce)?;
    let mut inputs: Vec<u64> = Vec::with_capacity(33);
    inputs.push(args.destination_chain_index);
    inputs.extend(token_address.into_iter().map(|x| x as u64));
    inputs.extend(amount.into_iter().map(|x| x as u64));
    inputs.extend(recipient.into_iter().map(|x| x as u64));
    inputs.extend(nonce_u32x8.into_iter().map(|x| x as u64));

    let contract_call = ContractCallArgs {
        contract_id, // resolved from Router or override
        method_name: "withdraw".to_string(),
        inputs,
    };
    let contract_call_data = ContractCallData::new(vec![contract_call]);

    // 4. Submit through the trace-based CLI path
    let info = load_wallet_key_info(&args.wallet, false)?;
    let user_id = provider
        .get_user_ids_for_public_key(info.public_key_hash)
        .await?
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No user id found for sender public key"))?;
    let checkpoint_before = provider.get_coordinator_latest_block_state().await?.checkpoint_id;
    let (tx_hash, end_user_leaf_hash) =
        submit_end_cap_proof::prove_contract_call_data_once(&args.rpc_config, &args.wallet, contract_call_data).await?;

    tracing::info!(
        contract_id,
        destination_chain_index = args.destination_chain_index,
        amount = args.amount,
        nonce = %args.nonce,
        tx_hash = %tx_hash,
        end_user_leaf_hash = %end_user_leaf_hash,
        "withdraw tx submitted"
    );
    let confirmed_checkpoint = provider
        .wait_for_endcap_inclusion(user_id, end_user_leaf_hash, checkpoint_before, Some(180), 1)
        .await?;
    tracing::info!(
        checkpoint_id = confirmed_checkpoint,
        user_id,
        tx_hash = %tx_hash,
        end_user_leaf_hash = %end_user_leaf_hash,
        "withdraw tx included"
    );

    Ok(CommandResult::Transaction(TransactionResult {
        transaction_hash: tx_hash,
        user_id: Some(user_id),
        status: TransactionStatus::Confirmed,
        confirmed_checkpoint: Some(confirmed_checkpoint),
        network: psy_config.current_network_name().to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::parse_hash_hex_u32x8;

    #[test]
    fn parse_20_byte_address_matches_equivalent_bytes32() {
        let addr20 = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let addr32 = "0x0000000000000000000000001f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        assert_eq!(parse_hash_hex_u32x8(addr20).unwrap(), parse_hash_hex_u32x8(addr32).unwrap());
    }

    #[test]
    fn parse_rejects_non_address_lengths() {
        let err = parse_hash_hex_u32x8("0x1234").unwrap_err().to_string();
        assert!(err.contains("40 or 64 hex chars"));
    }
}
