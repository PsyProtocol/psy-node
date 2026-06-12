//! Subcommand: claim-withdrawal — get withdrawal Merkle proof from psy-services,
//! optionally generate a Groth16 proof via prove-proxy, and submit to L1 Bridge.
//!
//! If --prove-proxy-url is provided, the subcommand will attempt to generate a
//! Groth16 proof and call Bridge.batchClaimWithdrawal on L1.
//! Otherwise, it prints the Merkle proof for manual relay.

use alloy_primitives::{Address, TxHash, U256};
use alloy_signer_local::PrivateKeySigner;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;
use reqwest::Client;
use serde::Deserialize;

use super::args::ClaimWithdrawalArgs;

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofResponse {
    found: bool,
    leaf_index: Option<u64>,
    leaf_hash: Option<String>,
    #[serde(rename = "siblings")]
    subtree_proof: Option<Vec<String>>,
    withdrawal_root: Option<String>,
    checkpoint_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

fn compute_withdrawal_leaf_hash(
    recipient: &str,
    token_address: &str,
    amount: &str,
    nonce: u64,
    destination_chain_id: u64,
) -> anyhow::Result<String> {
    let recipient_words = hex_to_u32x8_be(recipient)?;
    let token_words = hex_to_u32x8_be(token_address)?;
    let amount_words = u256_to_u32x8_be(amount)?;
    let nonce_u32 = u32::try_from(nonce)
        .map_err(|_| anyhow::anyhow!("nonce exceeds u32"))?;
    let chain_u32 = u32::try_from(destination_chain_id)
        .map_err(|_| anyhow::anyhow!("destination_chain_id exceeds u32"))?;

    // Poseidon hash matching psy-services and L2 withdrawal tree:
    // hash_no_pad(recipient[8] ++ token[8] ++ amount[8] ++ nonce ++ dest_chain)
    let felts: Vec<GoldilocksField> = recipient_words.iter()
        .chain(token_words.iter())
        .chain(amount_words.iter())
        .map(|&w| GoldilocksField::from_canonical_u64(w as u64))
        .chain([
            GoldilocksField::from_canonical_u64(nonce_u32 as u64),
            GoldilocksField::from_canonical_u64(chain_u32 as u64),
        ])
        .collect();
    let leaf_hash = PoseidonHash::hash_no_pad(&felts);
    let elems = leaf_hash.elements;
    let words: [u32; 8] = [
        (elems[0].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[0].to_canonical_u64() >> 32) as u32,
        (elems[1].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[1].to_canonical_u64() >> 32) as u32,
        (elems[2].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[2].to_canonical_u64() >> 32) as u32,
        (elems[3].to_canonical_u64() & 0xffff_ffff) as u32,
        (elems[3].to_canonical_u64() >> 32) as u32,
    ];
    let mut hex_str = String::with_capacity(66);
    hex_str.push_str("0x");
    for w in &words {
        hex_str.push_str(&format!("{:08x}", w));
    }
    Ok(hex_str)
}

fn resolve_bridge_address(deployments_network: &str) -> anyhow::Result<String> {
    use std::fs;

    let summary_path = format!("./psy-contracts/deployments/{}/deployed-contracts.json", deployments_network);
    if let Ok(raw) = fs::read_to_string(&summary_path) {
        #[derive(serde::Deserialize)]
        struct DeployedContractsSummary {
            core: Option<std::collections::HashMap<String, String>>,
            proxies: Option<std::collections::HashMap<String, String>>,
        }
        if let Ok(summary) = serde_json::from_str::<DeployedContractsSummary>(&raw) {
            if let Some(addr) = summary.proxies.as_ref().and_then(|m| m.get("Bridge_Proxy").cloned()) {
                return Ok(addr);
            }
            if let Some(addr) = summary.core.as_ref().and_then(|m| m.get("Bridge").cloned()) {
                return Ok(addr);
            }
        }
    }

    let artifact_path = format!("./psy-contracts/deployments/{}/Bridge_Proxy.json", deployments_network);
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

fn hex_to_u32x8_be(hex_str: &str) -> anyhow::Result<Vec<u64>> {
    let raw = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(raw)?;
    let padded = match bytes.len() {
        20 => {
            let mut b = vec![0u8; 32];
            b[12..].copy_from_slice(&bytes);
            b
        }
        32 => bytes.to_vec(),
        n => anyhow::bail!("expected 20 or 32 bytes, got {}", n),
    };
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let start = i * 4;
        let val = u32::from_be_bytes(padded[start..start+4].try_into().unwrap());
        words.push(val as u64);
    }
    Ok(words)
}

fn u256_to_u32x8_be(s: &str) -> anyhow::Result<Vec<u64>> {
    let val: alloy_primitives::U256 = s.parse()
        .map_err(|e| anyhow::anyhow!("invalid uint256: {}", e))?;
    let bytes = val.to_be_bytes::<32>();
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let start = i * 4;
        let v = u32::from_be_bytes(bytes[start..start+4].try_into().unwrap());
        words.push(v as u64);
    }
    Ok(words)
}

fn urlencoding(s: &str) -> String {
    s.to_string()
}

fn to_32byte_hex(hex_str: &str) -> String {
    let raw = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if raw.len() <= 40 {
        format!("0x{:0>64}", raw.to_lowercase())
    } else {
        format!("0x{:0>64}", raw.to_lowercase())
    }
}

fn decimal_amount_to_hex(dec_str: &str) -> String {
    let val: U256 = dec_str.parse()
        .unwrap_or_else(|_| U256::from_str_radix(dec_str, 16).unwrap_or_default());
    let bytes = val.to_be_bytes::<32>();
    format!("0x{}", hex::encode(bytes))
}

pub async fn run(args: ClaimWithdrawalArgs) -> anyhow::Result<()> {
    let expected_leaf_hash = compute_withdrawal_leaf_hash(
        &args.recipient,
        &args.token_address,
        &args.amount,
        args.nonce,
        args.destination_chain_id,
    )?;

    tracing::info!("Expected leaf hash: {}", expected_leaf_hash);

    // Fetch withdrawal proof from psy-services
    let services_url = args.services_url.trim_end_matches('/');
    let proof_url = format!(
        "{}/api/v1/bridge/withdrawal-claim-proof?recipient={}&token_address={}&amount={}&nonce={}&destination_chain_id={}",
        services_url,
        urlencoding(&to_32byte_hex(&args.recipient)),
        urlencoding(&to_32byte_hex(&args.token_address)),
        decimal_amount_to_hex(&args.amount),
        args.nonce,
        args.destination_chain_id,
    );

    tracing::info!("Fetching proof from: {}", proof_url);
    let http_client = Client::new();
    let resp = http_client
        .get(&proof_url)
        .send()
        .await?
        .json::<ApiResponse<WithdrawalClaimProofResponse>>()
        .await?;

    if !resp.success {
        anyhow::bail!("psy-services error: {}", resp.error.unwrap_or_else(|| "unknown".into()));
    }
    let proof = resp.data.ok_or_else(|| anyhow::anyhow!("psy-services returned success but no data"))?;

    if !proof.found {
        println!("Withdrawal not found in tree. Is the withdrawal event indexed by psy-services?");
        println!("  leaf_hash: {}", expected_leaf_hash);
        return Ok(());
    }

    let leaf_index = proof.leaf_index.unwrap_or(0);
    let leaf_hash = proof.leaf_hash.unwrap_or_default();
    let siblings = proof.subtree_proof.unwrap_or_default();
    let withdrawal_root = proof.withdrawal_root.unwrap_or_default();

    println!("=== Withdrawal Claim Proof ===");
    println!("leaf_index:     {}", leaf_index);
    println!("leaf_hash:      {}", leaf_hash);
    println!("withdrawal_root: {}", withdrawal_root);
    println!("siblings:       [");
    for (i, s) in siblings.iter().enumerate() {
        println!("  {}: {}", i, s);
    }
    println!("]");
    println!("sibling_count:  {}", siblings.len());

    if leaf_hash.to_lowercase() != expected_leaf_hash.to_lowercase() {
        tracing::warn!(
            "Leaf hash mismatch! Expected: {}, got: {}",
            expected_leaf_hash, leaf_hash
        );
    }

    // If prove-proxy is available, generate Groth16 proof
    if let Some(prove_proxy_url) = &args.prove_proxy_url {
        tracing::info!("Generating Groth16 proof via prove-proxy: {}", prove_proxy_url);

        let recipient_u32x8 = hex_to_u32x8_be(&args.recipient)?;
        let token_u32x8 = hex_to_u32x8_be(&args.token_address)?;
        let amount_u32x8 = u256_to_u32x8_be(&args.amount)?;
        let nonce_u32 = args.nonce as u32;
        let dest_chain_u32 = args.destination_chain_id as u32;
        let bridge_user_id: u32 = 524288;

        let witness = serde_json::json!({
            "bridge_user_id": bridge_user_id,
            "withdrawals": [{
                "withdrawal_root": withdrawal_root,
                "recipient": recipient_u32x8,
                "token": token_u32x8,
                "amount": amount_u32x8,
                "nonce": nonce_u32,
                "dest_chain_id": dest_chain_u32,
                "leaf_index": leaf_index as u32,
                "bridge_user_id": bridge_user_id,
                "siblings": siblings,
            }]
        });

        let req_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "psy_prove_withdrawal_batch_claim_groth16",
            "params": [witness],
        });

        let mut req = http_client.post(prove_proxy_url).json(&req_body);
        if let Some(token) = &args.prove_proxy_token {
            req = req.bearer_auth(token);
        }

        let prove_resp = req.send().await?;
        let prove_result: serde_json::Value = prove_resp.json().await?;

        if let Some(err) = prove_result.get("error") {
            if let Some(message) = err.get("message").and_then(|v| v.as_str()) {
                let data = err.get("data").cloned().unwrap_or(serde_json::Value::Null);
                anyhow::bail!("prove-proxy error: {} data={}", message, data);
            }
            anyhow::bail!("prove-proxy error: {}", err);
        }

        let proof_data = &prove_result["result"];
        tracing::info!("Groth16 proof generated successfully");

        let bridge_addr = if !args.bridge_address.is_empty() && args.bridge_address != "auto" {
            args.bridge_address.clone()
        } else {
            resolve_bridge_address("localhost")?
        };

        let signer: PrivateKeySigner = args.private_key.parse()?;
        let bridge: Address = bridge_addr.parse()?;

        let sol_proof = proof_data["solidity_proof"]
            .as_array()
            .map(|a| a.iter().map(|v| v.as_str().unwrap_or("0")).collect::<Vec<_>>())
            .unwrap_or_default();
        let public_inputs: Vec<String> = proof_data["public_inputs"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        if let Some(n) = v.as_u64() {
                            n.to_string()
                        } else if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            "0".to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let slot_data: Vec<String> = proof_data["slot_data"]
            .as_array()
            .map(|a| {
                a.iter()
                    .map(|v| {
                        if let Some(n) = v.as_u64() {
                            n.to_string()
                        } else if let Some(s) = v.as_str() {
                            s.to_string()
                        } else {
                            "0".to_string()
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();

        println!("\n=== L1 Claim Data ===");
        println!("bridge_address: {}", bridge_addr);
        println!("solidity_proof: {:?}", sol_proof);
        println!("public_inputs count: {}", public_inputs.len());
        println!("slot_data count: {}", slot_data.len());

        // Build calldata for batchClaimWithdrawal(uint256[8],uint256[18],uint256[832])
        let selector = alloy_primitives::keccak256("batchClaimWithdrawal(uint256[8],uint256[18],uint256[832])".as_bytes());
        let mut data = Vec::with_capacity(4 + (8 + 18 + 832) * 32);
        data.extend_from_slice(&selector[..4]);
        let encode_u256_arr = |data: &mut Vec<u8>, arr: &[&str]| -> anyhow::Result<()> {
            for val in arr {
                let u: U256 = val.parse()?;
                data.extend_from_slice(&u.to_be_bytes::<32>());
            }
            Ok(())
        };
        encode_u256_arr(&mut data, &sol_proof)?;
        let pi_refs: Vec<&str> = public_inputs.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &pi_refs)?;
        let sd_refs: Vec<&str> = slot_data.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &sd_refs)?;

        let rpc_url = &args.l1_rpc_url;
        let from_addr = signer.address();
        use alloy_signer::Signer;

        let chain_id_hex: String = serde_json::from_value(rpc_call(rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
        let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)?;

        let nonce_hex: String = serde_json::from_value(
            rpc_call(rpc_url, "eth_getTransactionCount", serde_json::json!([format!("0x{}", hex::encode(from_addr)), "latest"])).await?
        )?;
        let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;

        let gas_estimate = rpc_call(rpc_url, "eth_estimateGas", serde_json::json!([{
            "from": format!("0x{}", hex::encode(from_addr)),
            "to": format!("0x{}", hex::encode(bridge)),
            "data": format!("0x{}", hex::encode(&data)),
        }])).await?;
        let gas_hex: String = serde_json::from_value(gas_estimate)?;
        let gas_limit = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
        let gas_limit = (gas_limit as f64 * 1.2) as u64;

        let fee_history = rpc_call(rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
        let base_fee_str = fee_history["baseFeePerGas"][0].as_str().unwrap_or("0x0");
        let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).unwrap_or(1_000_000_000u128);
        let max_priority_fee = u128::from_str_radix(
            fee_history["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"), 16
        ).unwrap_or(1_500_000_000u128);
        let max_fee_per_gas = base_fee * 2 + max_priority_fee;

        let tx = alloy_consensus::TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas,
            max_priority_fee_per_gas: max_priority_fee,
            gas_limit,
            to: alloy_primitives::TxKind::Call(bridge),
            value: U256::ZERO,
            input: alloy_primitives::Bytes::from(data),
            access_list: Default::default(),
        };
        use alloy_consensus::SignableTransaction;
        let sig = signer.sign_hash(&tx.signature_hash()).await?;
        let signed = tx.into_signed(sig);
        use alloy_eips::Encodable2718;
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);

        let tx_hash_raw: String = serde_json::from_value(
            rpc_call(rpc_url, "eth_sendRawTransaction", serde_json::json!([format!("0x{}", hex::encode(&encoded))])).await?
        )?;
        let tx_hash: alloy_primitives::TxHash = tx_hash_raw.parse()?;
        tracing::info!("claim_withdrawal tx submitted: {}", tx_hash);
        println!("claim_withdrawal tx: {}", tx_hash);

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
        if status != 1 {
            let trace = rpc_call(rpc_url, "debug_traceTransaction",
                serde_json::json!([format!("{:#x}", tx_hash), {"tracer": "callTracer"}])).await;
            if let Ok(t) = trace {
                if let Some(revert) = t["revertReason"].as_str() {
                    tracing::error!("Revert: {}", revert);
                }
            }
        }
    } else {
        println!("\nℹ️  No prove-proxy URL provided. Proof data printed above.");
        println!("   To claim: pass --prove-proxy-url or manually relay the proof to the relayer.");
    }

    Ok(())
}
