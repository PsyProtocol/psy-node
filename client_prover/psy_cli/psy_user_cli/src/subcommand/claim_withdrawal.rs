//! Subcommand: claim-withdrawal — get withdrawal Merkle proof from
//! psy-services, optionally generate a Groth16 proof via prove-proxy, and
//! submit to L1 Bridge.
//!
//! If --prove-proxy-url is provided, the subcommand will attempt to generate a
//! Groth16 proof and call Bridge.batchClaimWithdrawal on L1.
//! Otherwise, it prints the Merkle proof for manual relay.

use alloy_primitives::{keccak256, Address, U256};
use alloy_signer_local::PrivateKeySigner;
use plonky2::{
    field::{
        goldilocks_field::GoldilocksField,
        types::{Field, PrimeField64},
    },
    hash::poseidon::PoseidonHash,
    plonk::config::Hasher,
};
use reqwest::Client;
use serde::Deserialize;

use super::args::ClaimWithdrawalArgs;
use crate::result::{CommandResult, L1TransactionResult, L1TransactionStatus};

const WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS: usize = 1088;
const WITHDRAWAL_BATCH_CLAIM_SIGNATURE: &str = "batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])";
#[cfg(test)]
const LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE: &str = "batchClaimWithdrawal(uint256[8],uint256[18],uint256[864])";

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofPayload {
    sender_user_id: Option<u64>,
    withdrawal_index: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct WithdrawalClaimProofResponse {
    found: bool,
    leaf_index: Option<u64>,
    leaf_hash: Option<String>,
    #[serde(rename = "siblings")]
    subtree_proof: Option<Vec<String>>,
    withdrawal_root: Option<String>,
    checkpoint_id: Option<u64>,
    withdrawal: Option<WithdrawalClaimProofPayload>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

fn compute_withdrawal_leaf_hash(
    sender_user_id: u64,
    recipient: &str,
    token_address: &str,
    amount: &str,
    nonce_hex: &str,
    destination_chain_index: u64,
) -> anyhow::Result<String> {
    let sender_user_id_u32 = u32::try_from(sender_user_id).map_err(|_| anyhow::anyhow!("sender_user_id exceeds u32"))?;
    let recipient_words = hex_to_u32x8_be(recipient)?;
    let token_words = hex_to_u32x8_be(token_address)?;
    let amount_words = u256_to_u32x8_be(amount)?;
    let nonce_words = bytes32_hex_to_u32x8_be(nonce_hex, "nonce")?;
    let chain_u32 = u32::try_from(destination_chain_index).map_err(|_| anyhow::anyhow!("destination_chain_index exceeds u32"))?;

    let felts: Vec<GoldilocksField> = std::iter::once(GoldilocksField::from_canonical_u64(sender_user_id_u32 as u64))
        .chain(recipient_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(token_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(amount_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(nonce_words.iter().map(|&w| GoldilocksField::from_canonical_u64(w as u64)))
        .chain(std::iter::once(GoldilocksField::from_canonical_u64(chain_u32 as u64)))
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

fn resolve_bridge_address_for_network(deployments_network: &str) -> anyhow::Result<String> {
    super::deployments::resolve_proxy_or_core_address(deployments_network, "Bridge_Proxy", "Bridge", "Bridge_Proxy.json")
}

fn resolve_current_deployments_network(rpc_config_path: &str) -> anyhow::Result<String> {
    let psy_config = psy_config::PsyConfigGoldilocks::from_file(rpc_config_path)?;
    Ok(psy_config.current_network_name().to_string())
}

async fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> anyhow::Result<serde_json::Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params,
    });
    let client = reqwest::Client::new();
    let resp = client.post(url).json(&body).send().await?;
    let result: serde_json::Value = resp.json().await?;
    if let Some(err) = result.get("error") {
        anyhow::bail!(
            "RPC error ({}): {} - data: {:?}",
            method,
            err["message"].as_str().unwrap_or("unknown"),
            err.get("data")
        );
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
        let val = u32::from_be_bytes(padded[start..start + 4].try_into().unwrap());
        words.push(val as u64);
    }
    Ok(words)
}

fn normalize_u256_hex_32bytes(value: &str) -> anyhow::Result<String> {
    let raw = value.trim();
    let parsed = if raw.starts_with("0x") || raw.starts_with("0X") {
        U256::from_str_radix(raw.trim_start_matches("0x").trim_start_matches("0X"), 16)?
    } else {
        raw.parse::<U256>()
            .or_else(|_| U256::from_str_radix(raw, 16))
            .map_err(|e| anyhow::anyhow!("invalid uint256 '{}': {}", value, e))?
    };
    Ok(format!("0x{}", hex::encode(parsed.to_be_bytes::<32>())))
}

fn bytes32_hex_to_u32x8_be(hex_str: &str, field: &str) -> anyhow::Result<[u32; 8]> {
    let normalized = normalize_u256_hex_32bytes(hex_str)?;
    let raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let bytes = hex::decode(raw)?;
    anyhow::ensure!(bytes.len() == 32, "{} must encode exactly 32 bytes", field);
    let mut words = [0u32; 8];
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        words[i] = u32::from_be_bytes(chunk.try_into().expect("4-byte chunk"));
    }
    Ok(words)
}

fn u256_to_u32x8_be(s: &str) -> anyhow::Result<Vec<u64>> {
    let val: alloy_primitives::U256 = s.parse().map_err(|e| anyhow::anyhow!("invalid uint256: {}", e))?;
    let bytes = val.to_be_bytes::<32>();
    let mut words = Vec::with_capacity(8);
    for i in 0..8 {
        let start = i * 4;
        let v = u32::from_be_bytes(bytes[start..start + 4].try_into().unwrap());
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
    let val: U256 = dec_str.parse().unwrap_or_else(|_| U256::from_str_radix(dec_str, 16).unwrap_or_default());
    let bytes = val.to_be_bytes::<32>();
    format!("0x{}", hex::encode(bytes))
}

async fn read_claimed_withdrawal_nonce(rpc_url: &str, bridge_address: &str, nonce_hex: &str) -> anyhow::Result<bool> {
    let data = build_claimed_withdrawal_nonce_call_data(nonce_hex)?;

    let result: String = serde_json::from_value(
        rpc_call(
            rpc_url,
            "eth_call",
            serde_json::json!([{
                "to": bridge_address,
                "data": format!("0x{}", hex::encode(&data)),
            }, "latest"]),
        )
        .await?,
    )?;
    Ok(U256::from_str_radix(result.trim_start_matches("0x"), 16).unwrap_or_default() != U256::ZERO)
}

fn build_claimed_withdrawal_nonce_call_data(nonce_hex: &str) -> anyhow::Result<Vec<u8>> {
    let normalized = normalize_u256_hex_32bytes(nonce_hex)?;
    let nonce_raw = normalized.strip_prefix("0x").unwrap_or(&normalized);
    let nonce_bytes = hex::decode(nonce_raw)?;
    anyhow::ensure!(nonce_bytes.len() == 32, "nonce must be 32 bytes");

    let mut data = Vec::with_capacity(4 + 32);
    data.extend_from_slice(&keccak256("claimedNullifiers(bytes32)".as_bytes())[..4]);
    data.extend_from_slice(&nonce_bytes);
    Ok(data)
}

fn parse_u256_word_array(proof_data: &serde_json::Value, field: &str, expected_len: usize) -> anyhow::Result<Vec<String>> {
    let values = proof_data[field]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("prove-proxy result missing {}", field))?;
    anyhow::ensure!(
        values.len() == expected_len,
        "prove-proxy {} length mismatch: expected {}, got {}",
        field,
        expected_len,
        values.len()
    );
    values
        .iter()
        .map(|value| {
            if let Some(n) = value.as_u64() {
                Ok(n.to_string())
            } else if let Some(s) = value.as_str() {
                Ok(s.to_string())
            } else {
                anyhow::bail!("prove-proxy {} contains non-u256 value: {}", field, value)
            }
        })
        .collect()
}

pub async fn run(args: ClaimWithdrawalArgs) -> anyhow::Result<CommandResult> {
    let services_url = args.services_url.trim_end_matches('/');
    let sender_user_id_q = args.sender_user_id.map(|v| format!("&sender_user_id={}", v)).unwrap_or_default();
    let nonce_hex = normalize_u256_hex_32bytes(&args.nonce)?;
    let proof_url = format!(
        "{}/api/v1/bridge/withdrawal-claim-proof?recipient={}&token_address={}&amount={}&nonce={}&destination_chain_index={}{}",
        services_url,
        urlencoding(&to_32byte_hex(&args.recipient)),
        urlencoding(&to_32byte_hex(&args.token_address)),
        decimal_amount_to_hex(&args.amount),
        nonce_hex,
        args.destination_chain_index,
        sender_user_id_q,
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
        return Ok(CommandResult::L1Transaction(L1TransactionResult {
            transaction_hash: None,
            status: L1TransactionStatus::NotFound,
            chain_id: None,
        }));
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

    let sender_user_id = proof
        .withdrawal
        .as_ref()
        .and_then(|w| w.sender_user_id)
        .or(args.sender_user_id)
        .ok_or_else(|| anyhow::anyhow!("withdrawal proof response missing sender_user_id; re-run with --sender-user-id"))?;
    let expected_leaf_hash = compute_withdrawal_leaf_hash(
        sender_user_id,
        &args.recipient,
        &args.token_address,
        &args.amount,
        &nonce_hex,
        args.destination_chain_index,
    )?;
    tracing::info!("Expected leaf hash: {}", expected_leaf_hash);
    anyhow::ensure!(
        leaf_hash.eq_ignore_ascii_case(&expected_leaf_hash),
        "withdrawal leaf hash mismatch: expected {}, got {}",
        expected_leaf_hash,
        leaf_hash
    );

    // Bridge.claimedNullifiers is keyed by the raw bytes32 withdrawal nonce.
    if let Some(prove_proxy_url) = &args.prove_proxy_url {
        let deployments_network = resolve_current_deployments_network(&args.rpc_config)?;
        let bridge_addr = resolve_bridge_address_for_network(&deployments_network)?;
        if read_claimed_withdrawal_nonce(&args.l1_rpc_url, &bridge_addr, &nonce_hex).await? {
            println!("withdrawal already claimed on L1 for nonce {}", nonce_hex);
            return Ok(CommandResult::L1Transaction(L1TransactionResult {
                transaction_hash: None,
                status: L1TransactionStatus::AlreadyClaimed,
                chain_id: None,
            }));
        }

        tracing::info!("Generating Groth16 proof via prove-proxy: {}", prove_proxy_url);

        let recipient_u32x8 = hex_to_u32x8_be(&args.recipient)?;
        let token_u32x8 = hex_to_u32x8_be(&args.token_address)?;
        let amount_u32x8 = u256_to_u32x8_be(&args.amount)?;
        let nonce_u32x8 = bytes32_hex_to_u32x8_be(&nonce_hex, "nonce")?;
        let dest_chain_u32 = args.destination_chain_index as u32;
        let bridge_user_id: u32 = 524288;

        let witness = serde_json::json!({
            "bridge_user_id": bridge_user_id,
            "withdrawals": [{
                "withdrawal_root": withdrawal_root,
                "sender_user_id": sender_user_id as u32,
                "recipient": recipient_u32x8,
                "token": token_u32x8,
                "amount": amount_u32x8,
                "nonce": nonce_u32x8,
                "destination_chain_index": dest_chain_u32,
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

        let signer: PrivateKeySigner = args.private_key.parse()?;
        let bridge: Address = bridge_addr.parse()?;
        let sol_proof = parse_u256_word_array(proof_data, "solidity_proof", 8)?;
        let public_inputs = parse_u256_word_array(proof_data, "public_inputs", 18)?;
        let slot_data = parse_u256_word_array(proof_data, "slot_data", WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS)?;

        println!("\n=== L1 Claim Data ===");
        println!("bridge_address: {}", bridge_addr);
        println!("public_inputs count: {}", public_inputs.len());
        println!("slot_data count: {}", slot_data.len());

        // Build calldata for batchClaimWithdrawal(uint256[8],uint256[18],uint256[1088])
        let selector = alloy_primitives::keccak256(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes());
        let mut data = Vec::with_capacity(4 + (8 + 18 + WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS) * 32);
        data.extend_from_slice(&selector[..4]);
        let encode_u256_arr = |data: &mut Vec<u8>, arr: &[&str]| -> anyhow::Result<()> {
            for val in arr {
                let u: U256 = val.parse()?;
                data.extend_from_slice(&u.to_be_bytes::<32>());
            }
            Ok(())
        };
        let sol_proof_refs: Vec<&str> = sol_proof.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &sol_proof_refs)?;
        let pi_refs: Vec<&str> = public_inputs.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &pi_refs)?;
        let sd_refs: Vec<&str> = slot_data.iter().map(|s| s.as_str()).collect();
        encode_u256_arr(&mut data, &sd_refs)?;

        let rpc_url = &args.l1_rpc_url;
        let from_addr = signer.address();
        use alloy_signer::Signer;

        let chain_id_hex: String = serde_json::from_value(rpc_call(rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
        let chain_id = u64::from_str_radix(chain_id_hex.trim_start_matches("0x"), 16)?;

        let account_nonce_hex: String = serde_json::from_value(
            rpc_call(
                rpc_url,
                "eth_getTransactionCount",
                serde_json::json!([format!("0x{}", hex::encode(from_addr)), "latest"]),
            )
            .await?,
        )?;
        let nonce = u64::from_str_radix(account_nonce_hex.trim_start_matches("0x"), 16)?;

        let gas_estimate = match rpc_call(
            rpc_url,
            "eth_estimateGas",
            serde_json::json!([{
                "from": format!("0x{}", hex::encode(from_addr)),
                "to": format!("0x{}", hex::encode(bridge)),
                "data": format!("0x{}", hex::encode(&data)),
            }]),
        )
        .await
        {
            Ok(val) => val,
            Err(err) => {
                if read_claimed_withdrawal_nonce(rpc_url, &bridge_addr, &nonce_hex).await.unwrap_or(false) {
                    println!("withdrawal already claimed on L1 for nonce {}", nonce_hex);
                    return Ok(CommandResult::L1Transaction(L1TransactionResult {
                        transaction_hash: None,
                        status: L1TransactionStatus::AlreadyClaimed,
                        chain_id: Some(chain_id),
                    }));
                }
                return Err(err);
            }
        };
        let gas_hex: String = serde_json::from_value(gas_estimate)?;
        let gas_limit = u64::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
        let gas_limit = (gas_limit as f64 * 1.2) as u64;

        let fee_history = rpc_call(rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
        let base_fee_str = fee_history["baseFeePerGas"][0].as_str().unwrap_or("0x0");
        let base_fee = u128::from_str_radix(base_fee_str.trim_start_matches("0x"), 16).unwrap_or(1_000_000_000u128);
        let max_priority_fee = u128::from_str_radix(fee_history["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"), 16)
            .unwrap_or(1_500_000_000u128);
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

        let tx_hash_raw: String = match rpc_call(
            rpc_url,
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(&encoded))]),
        )
        .await
        {
            Ok(val) => serde_json::from_value(val)?,
            Err(err) => {
                if read_claimed_withdrawal_nonce(rpc_url, &bridge_addr, &nonce_hex).await.unwrap_or(false) {
                    println!("withdrawal already claimed on L1 for nonce {}", nonce_hex);
                    return Ok(CommandResult::L1Transaction(L1TransactionResult {
                        transaction_hash: None,
                        status: L1TransactionStatus::AlreadyClaimed,
                        chain_id: Some(chain_id),
                    }));
                }
                return Err(err);
            }
        };
        let tx_hash: alloy_primitives::TxHash = tx_hash_raw.parse()?;
        tracing::info!("claim_withdrawal tx submitted: {}", tx_hash);
        println!("claim_withdrawal tx: {}", tx_hash);

        let receipt = loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let result = rpc_call(rpc_url, "eth_getTransactionReceipt", serde_json::json!([format!("{:#x}", tx_hash)])).await;
            match result {
                Ok(val) if !val.is_null() => break val,
                _ => continue,
            }
        };
        let status_str = receipt["status"].as_str().unwrap_or("0x0");
        let status = u64::from_str_radix(status_str.trim_start_matches("0x"), 16).unwrap_or(0);
        println!("status: {}", if status == 1 { "success" } else { "failed" });
        if status != 1 {
            let trace = rpc_call(
                rpc_url,
                "debug_traceTransaction",
                serde_json::json!([format!("{:#x}", tx_hash), {"tracer": "callTracer"}]),
            )
            .await;
            let revert_reason = trace.ok().and_then(|value| value["revertReason"].as_str().map(str::to_owned));
            anyhow::bail!(
                "L1 claim-withdrawal transaction reverted: tx_hash={:#x}, reason={}",
                tx_hash,
                revert_reason.as_deref().unwrap_or("unknown")
            );
        }
        Ok(CommandResult::L1Transaction(L1TransactionResult {
            transaction_hash: Some(format!("{:#x}", tx_hash)),
            status: L1TransactionStatus::Confirmed,
            chain_id: Some(chain_id),
        }))
    } else {
        Ok(CommandResult::L1Transaction(L1TransactionResult {
            transaction_hash: None,
            status: L1TransactionStatus::ProofOnly,
            chain_id: None,
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    use super::{
        build_claimed_withdrawal_nonce_call_data, bytes32_hex_to_u32x8_be, compute_withdrawal_leaf_hash, hex_to_u32x8_be, keccak256,
        normalize_u256_hex_32bytes, parse_u256_word_array, resolve_bridge_address_for_network, run, to_32byte_hex,
        LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE, WITHDRAWAL_BATCH_CLAIM_SIGNATURE, WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS,
    };
    use crate::{
        result::{CommandResult, L1TransactionStatus},
        subcommand::args::ClaimWithdrawalArgs,
    };

    fn spawn_single_response_server(body: serde_json::Value) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let body = body.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        format!("http://{}", addr)
    }

    #[test]
    fn claim_withdrawal_helpers_left_pad_20_byte_addresses() {
        let addr20 = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let addr32 = "0x0000000000000000000000001f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        assert_eq!(to_32byte_hex(addr20), addr32);
        assert_eq!(hex_to_u32x8_be(addr20).unwrap(), hex_to_u32x8_be(addr32).unwrap());
    }

    #[test]
    fn claim_withdrawal_nonce_normalization_matches_decimal_and_hex() {
        let decimal = normalize_u256_hex_32bytes("13").unwrap();
        let hex = normalize_u256_hex_32bytes("0x0d").unwrap();
        assert_eq!(decimal, hex);
        assert_eq!(bytes32_hex_to_u32x8_be(&decimal, "nonce").unwrap(), [0, 0, 0, 0, 0, 0, 0, 13]);
    }

    #[test]
    fn claim_withdrawal_signature_matches_current_slot_width() {
        assert_eq!(WITHDRAWAL_BATCH_CLAIM_SLOT_DATA_WORDS, 1088);
        assert!(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.contains("[1088]"));
        assert_ne!(
            keccak256(WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes())[..4],
            keccak256(LEGACY_WITHDRAWAL_BATCH_CLAIM_SIGNATURE.as_bytes())[..4]
        );
    }

    #[test]
    fn claim_withdrawal_claimed_precheck_uses_raw_bytes32_nonce() {
        let nonce = "13";
        let normalized = normalize_u256_hex_32bytes(nonce).unwrap();
        let expected_nonce = hex::decode(normalized.trim_start_matches("0x")).unwrap();
        let calldata = build_claimed_withdrawal_nonce_call_data(nonce).unwrap();
        assert_eq!(&calldata[..4], &keccak256("claimedNullifiers(bytes32)".as_bytes())[..4]);
        assert_eq!(&calldata[4..], expected_nonce.as_slice());
    }

    #[test]
    fn claim_withdrawal_rejects_wrong_prove_proxy_array_lengths() {
        let proof_data = serde_json::json!({
            "solidity_proof": ["1", "2"],
        });
        let err = parse_u256_word_array(&proof_data, "solidity_proof", 8).unwrap_err();
        assert!(err.to_string().contains("prove-proxy solidity_proof length mismatch: expected 8, got 2"));
    }

    #[tokio::test]
    async fn claim_withdrawal_proof_only_mode_does_not_touch_l1_or_rpc_config() {
        let recipient = "0x1f1a375ecf83fc0524de82a53b7f3e9a2ff5d8a9";
        let token_address = "0xd970407ff0af85d90d936c1c457504e5415af424";
        let amount = "990000000";
        let nonce = "13";
        let destination_chain_index = 0u64;
        let sender_user_id = 42u64;
        let normalized_nonce = normalize_u256_hex_32bytes(nonce).unwrap();
        let leaf_hash = compute_withdrawal_leaf_hash(
            sender_user_id,
            recipient,
            token_address,
            amount,
            &normalized_nonce,
            destination_chain_index,
        )
        .unwrap();
        let services_url = spawn_single_response_server(serde_json::json!({
            "success": true,
            "data": {
                "found": true,
                "leaf_index": 0,
                "leaf_hash": leaf_hash,
                "siblings": [],
                "withdrawal_root": "0x1234",
                "withdrawal": {
                    "sender_user_id": sender_user_id
                }
            }
        }));

        let args = ClaimWithdrawalArgs {
            rpc_config: "definitely-missing-config.json".to_string(),
            services_url,
            l1_rpc_url: "http://127.0.0.1:9".to_string(),
            private_key: "unused-in-proof-only-mode".to_string(),
            recipient: recipient.to_string(),
            token_address: token_address.to_string(),
            amount: amount.to_string(),
            nonce: nonce.to_string(),
            destination_chain_index,
            sender_user_id: None,
            prove_proxy_url: None,
            prove_proxy_token: None,
        };

        let result = run(args).await.unwrap();
        let CommandResult::L1Transaction(result) = result else {
            panic!("expected L1 transaction result");
        };
        assert!(matches!(result.status, L1TransactionStatus::ProofOnly));
        assert_eq!(result.transaction_hash, None);
        assert_eq!(result.chain_id, None);
    }

    #[test]
    fn claim_withdrawal_resolves_localhost_bridge_from_checked_in_deployments() {
        let bridge = resolve_bridge_address_for_network("localhost").unwrap();
        let summary_path = super::super::deployments::resolve_deployments_file("localhost", "deployed-contracts.json");
        let summary: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(summary_path).unwrap()).unwrap();
        let expected = summary["proxies"]["Bridge_Proxy"]
            .as_str()
            .or_else(|| summary["core"]["Bridge"].as_str())
            .unwrap();
        assert_eq!(bridge, expected);
    }
}
