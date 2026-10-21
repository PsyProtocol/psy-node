use psy_cli_common::key_utils::load_wallet_key_info;
use psy_client_common::args::{ContractCallArgs, ContractCallData};
use psy_config::network_constants::TOKEN_CONTRACT_ID;
use psy_provider::provider::RpcProvider;

use super::{args::WithdrawArgs, submit_end_cap_proof};
use crate::result::{CommandResult, TransactionResult, TransactionStatus};

/// Parse a 20-byte EVM address or 32-byte hex string into 8 big-endian u32
/// words. 20-byte inputs are left-padded to bytes32 so callers can pass normal
/// `0x...` addresses without manual conversion.
pub(super) fn parse_hash_hex_u32x8(hex_str: &str) -> anyhow::Result<[u32; 8]> {
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

use psy_config::USDT_TOKEN_CONTRACT_ID;

pub async fn run(args: WithdrawArgs) -> anyhow::Result<CommandResult> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(&args.rpc_config)?;
    let rpc_config = psy_config.get_current_network()?.clone();
    let provider = RpcProvider::new_with_config(&rpc_config)?;

    // 1. Determine L2 contract ID from the token selection.
    let contract_id = if let Some(override_id) = args.contract_id {
        tracing::info!(contract_id = override_id, "using explicit contract_id override");
        override_id
    } else {
        match args.token.to_ascii_lowercase().as_str() {
            "psy" => TOKEN_CONTRACT_ID as u64,
            "usdt" => u64::from(USDT_TOKEN_CONTRACT_ID),
            other => anyhow::bail!("--token must be psy or usdt, got {other:?}"),
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
        contract_id,
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
        "withdraw tx submitted (l1 token address checked against the governance mapping)"
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
        let addr32 = "0x00000000000000000000001f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        assert_eq!(parse_hash_hex_u32x8(addr20).unwrap(), parse_hash_hex_u32x8(addr32).unwrap());
    }

    #[test]
    fn parse_rejects_non_address_lengths() {
        let err = parse_hash_hex_u32x8("0x1234").unwrap_err().to_string();
        assert!(err.contains("40 or 64 hex chars"));
    }
}
