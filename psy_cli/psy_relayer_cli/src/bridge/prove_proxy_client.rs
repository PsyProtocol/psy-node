use std::time::Duration;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ─────────────────────────────────────────────────────────────────────────
//  Input / Output types mirroring those in prove_proxy.rs
// ─────────────────────────────────────────────────────────────────────────

/// Single input for the withdrawal batch claim RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeWithdrawalWitnessInput {
    pub withdrawal_root: String,
    pub sender_user_id: u32,
    pub recipient: [u32; 8],
    pub token: [u32; 8],
    pub amount: [u32; 8],
    pub nonce: [u32; 8],
    pub destination_chain_index: u32,
    pub leaf_index: u32,
    pub bridge_user_id: u32,
    pub siblings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeWithdrawalBatchWitnessInput {
    pub bridge_user_id: u32,
    pub withdrawals: Vec<BridgeWithdrawalWitnessInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeWithdrawalBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
    pub slot_data: Vec<u64>,
}

/// Single deposit leaf for the deposit batch append RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDepositLeafInput {
    pub shield_address: [u32; 8],
    pub token: [u32; 8],
    pub l2_token_contract_id: [u32; 8],
    pub amount: [u32; 8],
    pub chain_index: u32,
    pub note_commitment: [u32; 8],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDepositBatchWitnessInput {
    pub from_index: u32,
    pub bridge_user_id: u32,
    pub old_frontier: Vec<String>,
    pub deposits: Vec<BridgeDepositLeafInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeDepositBatchGroth16Proof {
    pub solidity_proof: [String; 8],
    pub public_inputs: Vec<u64>,
}


// ─────────────────────────────────────────────────────────────────────────
//  JSON-RPC types for jsonrpsee-compatible HTTP calls
// ─────────────────────────────────────────────────────────────────────────

#[derive(Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    method: String,
    params: serde_json::Value,
    id: u64,
}

#[derive(Deserialize)]
struct JsonRpcResponse<R> {
    jsonrpc: String,
    result: Option<R>,
    error: Option<JsonRpcError>,
    id: u64,
}

#[derive(Deserialize, Debug)]
struct JsonRpcError {
    code: i32,
    message: String,
    data: Option<serde_json::Value>,
}

/// HTTP client for the Prove Proxy server (JSON-RPC over HTTP).
pub struct ProveProxyClient {
    http_client: reqwest::Client,
    base_url: String,
    next_id: std::sync::atomic::AtomicU64,
}

impl ProveProxyClient {
    pub fn new(base_url: &str) -> Self {
        Self {
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(600)) // proof generation can be slow
                .build()
                .expect("failed to build reqwest client"),
            base_url: base_url.trim_end_matches('/').to_string(),
            next_id: std::sync::atomic::AtomicU64::new(1),
        }
    }

    fn next_id(&self) -> u64 {
        self.next_id.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    async fn call<R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> anyhow::Result<R> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params,
            id: self.next_id(),
        };

        let response = self
            .http_client
            .post(&self.base_url)
            .json(&request)
            .send()
            .await
            .with_context(|| format!("HTTP request to Prove Proxy {}/{} failed", self.base_url, method))?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!(
                "Prove Proxy returned HTTP {} for method {}: {}",
                status,
                method,
                body
            );
        }

        let rpc_response: JsonRpcResponse<R> = response
            .json()
            .await
            .with_context(|| format!("failed to parse JSON-RPC response for {}", method))?;

        if let Some(err) = rpc_response.error {
            anyhow::bail!(
                "Prove Proxy error (code={}) for {}: {} (data: {:?})",
                err.code,
                method,
                err.message,
                err.data
            );
        }

        rpc_response
            .result
            .ok_or_else(|| anyhow::anyhow!("Prove Proxy returned null result for {}", method))
    }

    // ── RPC methods ────────────────────────────────────────────────────

    /// Delegate deposit batch append proof generation to Prove Proxy.
    pub async fn prove_deposit_batch_append_groth16(
        &self,
        input: BridgeDepositBatchWitnessInput,
    ) -> anyhow::Result<BridgeDepositBatchGroth16Proof> {
        self.call("psy_prove_deposit_batch_append_groth16", json!([input])).await
    }

    /// Delegate withdrawal batch claim proof generation to Prove Proxy.
    pub async fn prove_withdrawal_batch_claim_groth16(
        &self,
        input: BridgeWithdrawalBatchWitnessInput,
    ) -> anyhow::Result<BridgeWithdrawalBatchGroth16Proof> {
        self.call("psy_prove_withdrawal_batch_claim_groth16", json!([input])).await
    }

}

