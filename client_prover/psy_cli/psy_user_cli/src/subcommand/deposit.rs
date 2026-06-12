//! Subcommand: deposit — initiate an L1→L2 deposit via the Router contract.
//!
//! Calls Router.deposit(token, amount, shieldAddress, noteSecretHash) on L1.
//! The Router forwards the call to the appropriate Gateway (ERC20 or ETH),
//! which then calls Bridge.recordDepositFromGateway.
//!
//! Usage:
//!   psy_user_cli deposit \
//!     --private-key <key> \
//!     --router-address <addr> \
//!     --token <addr> --amount <wei> \
//!     --shield-address <hex> --note-secret-hash <hex>
//!
//! Or with r0/r1 (auto-derives shield_address):
//!   psy_user_cli deposit \
//!     --private-key <key> \
//!     --router-address <addr> \
//!     --token <addr> --amount <wei> \
//!     --note-secret-hash <hex> \
//!     --r0 <n> --r1 <n> --user-id <id>

use alloy_primitives::{Address, TxHash, U256, B256};
use alloy_signer_local::PrivateKeySigner;
use alloy_signer::Signer;
use alloy_consensus::{SignableTransaction, TxEip1559};
use psy_crypto::shield_address::{derive_shield_address, shield_address_to_bytes32};

use super::args::DepositArgs;

fn resolve_shield_address(args: &DepositArgs) -> anyhow::Result<String> {
    match (args.r0, args.r1, args.user_id) {
        (Some(r0), Some(r1), Some(user_id)) => {
            let shield = derive_shield_address(user_id, r0, r1);
            let shield_bytes32 = shield_address_to_bytes32(shield);
            let shield_hex = format!("0x{}", hex::encode(shield_bytes32));
            tracing::info!(
                user_id = user_id, r0 = r0, r1 = r1,
                shield_address_display = %shield,
                shield_address_bytes32 = %shield_hex,
                "shield address derived from r0/r1"
            );
            Ok(shield_hex)
        }
        _ => {
            let sa = args.shield_address.trim();
            if sa.is_empty() || sa == "0x" || sa == "0x0" {
                anyhow::bail!("either --shield-address or (--r0 --r1 --user-id) is required");
            }
            Ok(sa.to_string())
        }
    }
}

/// Selector for Router.deposit(address,uint256,bytes32,bytes32)
const DEPOSIT_SELECTOR: [u8; 4] = [0x7d, 0xcc, 0x9f, 0x07];

fn encode_deposit_call(token: &str, amount: &str, shield_address: &str, note_secret_hash: &str) -> anyhow::Result<Vec<u8>> {
    let token_addr: Address = token.parse().map_err(|e| anyhow::anyhow!("invalid token address: {}", e))?;
    let amount_val: U256 = amount.parse::<U256>().map_err(|e| anyhow::anyhow!("invalid amount: {}", e))?;
    let shield: [u8; 32] = hex::decode(shield_address.strip_prefix("0x").unwrap_or(shield_address))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("shield_address must be 32 bytes"))?;
    let nsh: [u8; 32] = hex::decode(note_secret_hash.strip_prefix("0x").unwrap_or(note_secret_hash))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("note_secret_hash must be 32 bytes"))?;

    let mut data = Vec::with_capacity(4 + 32 * 4);
    data.extend_from_slice(&DEPOSIT_SELECTOR);
    let mut addr_padded = [0u8; 32];
    addr_padded[12..].copy_from_slice(token_addr.as_slice());
    data.extend_from_slice(&addr_padded);
    let amount_bytes = amount_val.to_be_bytes::<32>();
    data.extend_from_slice(&amount_bytes);
    data.extend_from_slice(&shield);
    data.extend_from_slice(&nsh);
    Ok(data)
}

fn resolve_router_address(deployments_network: &str) -> anyhow::Result<String> {
    use std::fs;
    let summary_path = format!("./psy-contracts/deployments/{}/deployed-contracts.json", deployments_network);
    if let Ok(raw) = fs::read_to_string(&summary_path) {
        #[derive(serde::Deserialize)]
        struct Summary { core: Option<std::collections::HashMap<String, String>>, proxies: Option<std::collections::HashMap<String, String>> }
        if let Ok(s) = serde_json::from_str::<Summary>(&raw) {
            if let Some(addr) = s.proxies.and_then(|m| m.get("Router_Proxy").cloned()) { return Ok(addr); }
            if let Some(addr) = s.core.and_then(|m| m.get("Router").cloned()) { return Ok(addr); }
        }
    }
    let artifact_path = format!("./psy-contracts/deployments/{}/Router_Proxy.json", deployments_network);
    #[derive(serde::Deserialize)]
    struct Artifact { address: String }
    let raw = fs::read_to_string(&artifact_path)?;
    let artifact: Artifact = serde_json::from_str(&raw)?;
    Ok(artifact.address)
}

async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let client = reqwest::Client::new();
    let resp = client.post(url).json(&body).send().await?;
    let result: serde_json::Value = resp.json().await?;
    if let Some(err) = result.get("error") {
        anyhow::bail!("RPC error ({}): {} - data: {:?}",
            method, err["message"].as_str().unwrap_or("unknown"), err.get("data"));
    }
    Ok(result["result"].clone())
}

fn u256_to_hex(v: U256) -> String {
    if v.is_zero() {
        return "0x0".into();
    }
    let bytes = v.to_be_bytes::<32>();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(31);
    format!("0x{}", hex::encode(&bytes[start..]))
}

pub async fn run(args: DepositArgs) -> anyhow::Result<()> {
    let shield_address = resolve_shield_address(&args)?;
    let router_addr = if !args.router_address.is_empty() && args.router_address != "auto" {
        args.router_address.clone()
    } else {
        resolve_router_address("localhost")?
    };
    tracing::info!("Router address: {}", router_addr);

    let signer: PrivateKeySigner = args.private_key.parse()?;
    let from_addr = signer.address();
    let router: Address = router_addr.parse()?;
    let data = encode_deposit_call(&args.token, &args.amount, &shield_address, &args.note_secret_hash)?;

    let is_native = args.token == "0x0000000000000000000000000000000000000000"
        || args.token == "0x0"
        || args.token == "0x";
    let value = if is_native { args.amount.parse::<U256>()? } else { U256::ZERO };

    let rpc_url = &args.l1_rpc_url;

    // 1. Chain ID
    let chain_id_hex: String = serde_json::from_value(rpc_call(rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
    let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)?;
    tracing::debug!("chain_id: {}", chain_id);

    // 2. Nonce
    let nonce_hex: String = serde_json::from_value(
        rpc_call(rpc_url, "eth_getTransactionCount", serde_json::json!([format!("0x{}", hex::encode(from_addr)), "latest"])).await?
)?;
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;
    tracing::debug!("nonce: {}", nonce);

    // 3. Gas estimation
    let gas_estimate = rpc_call(rpc_url, "eth_estimateGas", serde_json::json!([{
        "from": format!("0x{}", hex::encode(from_addr)),
        "to": format!("0x{}", hex::encode(router)),
        "data": format!("0x{}", hex::encode(&data)),
        "value": u256_to_hex(value),
    }])).await?;
    let gas_hex: String = serde_json::from_value(gas_estimate)?;
    let gas_limit = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
    let gas_limit = (gas_limit as f64 * 1.2) as u64;
    tracing::debug!("gas_limit: {}", gas_limit);

    // 4. Fee data (EIP-1559)
    let fee_history = rpc_call(rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
    let base_fee_str = fee_history["baseFeePerGas"][0].as_str().unwrap_or("0x0");
    let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).unwrap_or(1_000_000_000u128);
    let max_priority_fee = u128::from_str_radix(
        fee_history["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"), 16
    ).unwrap_or(1_500_000_000u128);
    let max_fee_per_gas = base_fee * 2 + max_priority_fee;
    tracing::debug!("base_fee={}, max_priority_fee={}, max_fee={}", base_fee, max_priority_fee, max_fee_per_gas);

    // 5. Build & sign EIP-1559 tx
    use alloy_primitives::TxKind;
    use alloy_consensus::TxEnvelope;

    let tx = TxEip1559 {
        chain_id,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas: max_priority_fee,
        gas_limit,
        to: TxKind::Call(router),
        value,
        input: alloy_primitives::Bytes::from(data.clone()),
        access_list: Default::default(),
    };

    let sig = signer.sign_hash(&tx.signature_hash()).await?;
    let signed = tx.into_signed(sig);

    // EIP-2718 encode: 0x02 || rlp([chain_id, nonce, ... , y_parity, r, s])
    use alloy_eips::Encodable2718;
    let mut encoded = Vec::new();
    signed.encode_2718(&mut encoded);
    tracing::debug!("encoded tx len: {}", encoded.len());

    // 6. Send raw transaction
    let tx_hash_raw: String = serde_json::from_value(
        rpc_call(rpc_url, "eth_sendRawTransaction", serde_json::json!([format!("0x{}", hex::encode(&encoded))])).await?
    )?;
    let tx_hash: TxHash = tx_hash_raw.parse()?;
    tracing::info!("Deposit tx submitted: {}", tx_hash);
    println!("deposit tx: {}", tx_hash);

    // 7. Wait for receipt
    let receipt = loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let result = rpc_call(rpc_url, "eth_getTransactionReceipt",
            serde_json::json!([format!("{:#x}", tx_hash)])).await;
        match result {
            Ok(val) if !val.is_null() => break val,
            _ => continue,
        }
    };

    let status_str = receipt["status"].as_str().unwrap_or("0x0");
    let status = u64::from_str_radix(status_str.trim_start_matches("0x"), 16).unwrap_or(0);
    println!("status: {}", if status == 1 { "success" } else { "failed" });
    println!("gas_used: {}", receipt["gasUsed"].as_str().unwrap_or("?"));

    if status != 1 {
        // Try to extract revert reason
        let tx_hash_str = format!("{:#x}", tx_hash);
        let trace = rpc_call(rpc_url, "debug_traceTransaction",
            serde_json::json!([tx_hash_str, {"tracer": "callTracer"}])).await;
        if let Ok(t) = trace {
            if let Some(revert) = t["revertReason"].as_str() {
                tracing::error!("Revert: {}", revert);
            }
        }
        return Ok(());
    }

    // 8. Parse DepositRecorded event
    let record_topic: B256 = "0x59e100f1202f99727a545c60a4db130a4c257764a6cf6dc81ca974855c6eb8eb".parse()?;
    if let Some(logs) = receipt["logs"].as_array() {
        for log in logs {
            let topics = log["topics"].as_array().map(|a| a.clone()).unwrap_or_default();
            if topics.first().and_then(|t| t.as_str()) == Some(&format!("{:#x}", record_topic)) {
                let t1 = topics.get(1).and_then(|t| t.as_str()).unwrap_or("0x0");
                let t1b = hex::decode(t1.strip_prefix("0x").unwrap_or("0")).unwrap_or_default();
                let deposit_index = if t1b.len() >= 32 {
                    u32::from_be_bytes([t1b[28], t1b[29], t1b[30], t1b[31]])
                } else { 0 };
                let raw_data = log["data"].as_str().unwrap_or("0x");
                let log_data = hex::decode(raw_data.strip_prefix("0x").unwrap_or("0")).unwrap_or_default();
                if log_data.len() >= 128 {
                    println!("deposit_index: {}", deposit_index);
                    println!("leaf_hash: 0x{}", hex::encode(&log_data[96..128]));
                }
            }
        }
    }

    Ok(())
}
