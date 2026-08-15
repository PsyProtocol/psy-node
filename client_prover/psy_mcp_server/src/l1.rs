//! Minimal Ethereum L1 client for the deposit flow: sign EIP-1559 locally,
//! broadcast over plain JSON-RPC, wait for the receipt.
//!
//! Custody is deliberate and narrow: the L1 key comes from `PSY_MCP_L1_KEY`,
//! provisioned by the OWNER at server start. It is never a tool argument, so it
//! never passes through the model's context — the agent can trigger a deposit
//! but can never see or exfiltrate the key that funds it.
//!
//! The signing recipe mirrors the CLI reference (psy_user_cli deposit.rs):
//! chain id → nonce → estimateGas ×1.2 → feeHistory → TxEip1559 → sign →
//! EIP-2718 encode → eth_sendRawTransaction → poll the receipt.

use anyhow::{anyhow, bail, Context, Result};
use alloy_consensus::{SignableTransaction, TxEip1559};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{keccak256, Address, TxKind, U256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;

/// Selector for `Router.deposit(address,uint256,bytes32,bytes32)` — the same
/// constant the CLI uses; a wrong selector burns gas on a revert.
const DEPOSIT_SELECTOR: [u8; 4] = [0x7d, 0xcc, 0x9f, 0x07];

pub struct L1Client {
    signer: PrivateKeySigner,
    pub rpc_url: String,
}

async fn rpc(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
    let resp: serde_json::Value = reqwest::Client::new()
        .post(url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("L1 rpc {url} unreachable"))?
        .json()
        .await
        .context("L1 rpc returned non-JSON")?;
    if let Some(err) = resp.get("error") {
        bail!("{method}: {err}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("{method}: no result"))
}

fn hex_u64(v: &serde_json::Value) -> Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow!("expected hex string"))?;
    Ok(u64::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

fn abi_word_addr(addr: Address) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(addr.as_slice());
    w
}

impl L1Client {
    /// Build from `PSY_MCP_L1_KEY` (owner-provisioned). Absent key is a clear,
    /// actionable error — not a fallback to some bundled key.
    /// Keyless read-only client — the proved-count check in claim_deposit needs
    /// ONLY an eth_call; requiring PSY_MCP_L1_KEY there made every keyless
    /// claim read a fake 0 and report "relayer still working" while the chain
    /// had long proved the deposit (live-verified 2026-08-17, idx53: ~40 min
    /// of misleading polls, instant claim once the key was present).
    pub fn read_only(rpc_url: String) -> Self {
        Self { signer: PrivateKeySigner::from_bytes(&[1u8; 32].into()).expect("constant key"), rpc_url }
    }

    pub fn from_env(rpc_url: String) -> Result<Self> {
        let key = std::env::var("PSY_MCP_L1_KEY").map_err(|_| {
            anyhow!(
                "no L1 signer: set PSY_MCP_L1_KEY (an Ethereum private key holding gas + tokens) \
                 in the server's environment. It is owner-provisioned on purpose — the agent \
                 cannot supply or read it."
            )
        })?;
        let signer: PrivateKeySigner =
            key.trim().parse().context("PSY_MCP_L1_KEY is not a valid private key")?;
        Ok(Self { signer, rpc_url })
    }

    pub fn address(&self) -> Address {
        self.signer.address()
    }

    /// ERC20 `allowance(owner, spender)`.
    pub async fn erc20_allowance(&self, token: Address, spender: Address) -> Result<U256> {
        let mut data = keccak256(b"allowance(address,address)")[..4].to_vec();
        data.extend_from_slice(&abi_word_addr(self.address()));
        data.extend_from_slice(&abi_word_addr(spender));
        let out = rpc(
            &self.rpc_url,
            "eth_call",
            serde_json::json!([{ "to": format!("{token}"), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )
        .await?;
        let s = out.as_str().unwrap_or("0x0");
        Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO))
    }

    /// ERC20 `balanceOf(us)`.
    pub async fn erc20_balance(&self, token: Address) -> Result<U256> {
        let mut data = keccak256(b"balanceOf(address)")[..4].to_vec();
        data.extend_from_slice(&abi_word_addr(self.address()));
        let out = rpc(
            &self.rpc_url,
            "eth_call",
            serde_json::json!([{ "to": format!("{token}"), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )
        .await?;
        let s = out.as_str().unwrap_or("0x0");
        Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(U256::ZERO))
    }

    /// A contract view returning one uint (e.g. `pendingDepositCount()`).
    pub async fn call_u64(&self, to: Address, signature: &str) -> Result<u64> {
        let data = &keccak256(signature.as_bytes())[..4];
        let out = rpc(
            &self.rpc_url,
            "eth_call",
            serde_json::json!([{ "to": format!("{to}"), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )
        .await?;
        hex_u64(&out)
    }

    pub fn encode_approve(spender: Address, amount: U256) -> Vec<u8> {
        let mut data = keccak256(b"approve(address,uint256)")[..4].to_vec();
        data.extend_from_slice(&abi_word_addr(spender));
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        data
    }

    pub fn encode_deposit(
        token: Address,
        amount: U256,
        shield_address: [u8; 32],
        note_commitment: [u8; 32],
    ) -> Vec<u8> {
        let mut data = DEPOSIT_SELECTOR.to_vec();
        data.extend_from_slice(&abi_word_addr(token));
        data.extend_from_slice(&amount.to_be_bytes::<32>());
        data.extend_from_slice(&shield_address);
        data.extend_from_slice(&note_commitment);
        data
    }

    /// Sign, broadcast, and wait for a successful receipt. A reverted receipt
    /// is an error — "it mined" is not "it worked".
    pub async fn send(&self, to: Address, data: Vec<u8>, value: U256) -> Result<String> {
        let from = format!("{}", self.address());
        let chain_id = hex_u64(&rpc(&self.rpc_url, "eth_chainId", serde_json::json!([])).await?)?;
        let nonce = hex_u64(
            &rpc(&self.rpc_url, "eth_getTransactionCount", serde_json::json!([from, "pending"])).await?,
        )?;
        let gas_est = hex_u64(
            &rpc(
                &self.rpc_url,
                "eth_estimateGas",
                serde_json::json!([{
                    "from": from, "to": format!("{to}"),
                    "data": format!("0x{}", hex::encode(&data)),
                    "value": format!("0x{value:x}"),
                }]),
            )
            .await
            .context("estimateGas failed — the call would revert; nothing was sent")?,
        )?;
        let gas_limit = (gas_est as f64 * 1.2) as u64;

        let fees = rpc(&self.rpc_url, "eth_feeHistory", serde_json::json!([1, "latest", [50.0]])).await?;
        let base = u128::from_str_radix(
            fees["baseFeePerGas"][0].as_str().unwrap_or("0x3b9aca00").trim_start_matches("0x"),
            16,
        )
        .unwrap_or(1_000_000_000);
        let tip = u128::from_str_radix(
            fees["reward"][0][0].as_str().unwrap_or("0x59682f00").trim_start_matches("0x"),
            16,
        )
        .unwrap_or(1_500_000_000)
        .max(1_000_000);

        let tx = TxEip1559 {
            chain_id,
            nonce,
            max_fee_per_gas: base * 2 + tip,
            max_priority_fee_per_gas: tip,
            gas_limit,
            to: TxKind::Call(to),
            value,
            input: data.into(),
            access_list: Default::default(),
        };
        let sig = self.signer.sign_hash_sync(&tx.signature_hash())?;
        let signed = tx.into_signed(sig);
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        let raw = format!("0x{}", hex::encode(encoded)); // full hex — never strip; leading zero bytes matter
        let tx_hash = rpc(&self.rpc_url, "eth_sendRawTransaction", serde_json::json!([raw]))
            .await?
            .as_str()
            .ok_or_else(|| anyhow!("no tx hash returned"))?
            .to_string();

        // Wait for the receipt; a deposit whose fate is unknown must not be
        // reported as sent-and-done.
        for _ in 0..60 {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let r = rpc(&self.rpc_url, "eth_getTransactionReceipt", serde_json::json!([tx_hash])).await;
            if let Ok(receipt) = r {
                if receipt.is_null() {
                    continue;
                }
                let status = receipt.get("status").and_then(|s| s.as_str()).unwrap_or("0x0");
                if status == "0x1" {
                    return Ok(tx_hash);
                }
                bail!("transaction {tx_hash} REVERTED on L1");
            }
        }
        bail!("transaction {tx_hash} was broadcast but no receipt appeared within 5 minutes — check it before retrying, do NOT resend blindly")
    }
}
