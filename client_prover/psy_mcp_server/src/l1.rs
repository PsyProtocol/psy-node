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

    pub async fn chain_id(&self) -> Result<u64> {
        hex_u64(&rpc(&self.rpc_url, "eth_chainId", serde_json::json!([])).await?)
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

    /// `claimedNullifiers(bytes32)` on the destination Bridge — the bytes32
    /// key IS the withdraw nonce. True means the nonce is already consumed
    /// (the relayer registered the pending withdrawal), so burning with it
    /// again would settle nothing new.
    pub async fn is_withdrawal_claimed(&self, bridge: Address, nonce: &[u8; 32]) -> Result<bool> {
        let mut data = keccak256(b"claimedNullifiers(bytes32)")[..4].to_vec();
        data.extend_from_slice(nonce);
        let out = rpc(
            &self.rpc_url,
            "eth_call",
            serde_json::json!([{ "to": format!("{bridge}"), "data": format!("0x{}", hex::encode(data)) }, "latest"]),
        )
        .await?;
        decode_bool_word(&out)
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
        let chain_id = self.chain_id().await?;
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

/// Strict bool-word decoder for one-word eth_call results: `0x` + exactly 64
/// hex digits encoding 0 or 1. Deliberately stricter than erc20_allowance's
/// `unwrap_or` default — a malformed response must refuse the burn, never
/// read as "unclaimed".
fn decode_bool_word(v: &serde_json::Value) -> Result<bool> {
    let s = v.as_str().ok_or_else(|| anyhow!("eth_call returned {v}, not a hex bool word"))?;
    let raw = s.strip_prefix("0x").ok_or_else(|| anyhow!("eth_call bool word `{s}` is not 0x-prefixed"))?;
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("eth_call bool word `{s}` is not a 32-byte word");
    }
    let word = U256::from_str_radix(raw, 16).map_err(|e| anyhow!("eth_call bool word `{s}` is not hex: {e}"))?;
    if word.is_zero() {
        return Ok(false);
    }
    if word == U256::from(1u8) {
        return Ok(true);
    }
    bail!("eth_call bool word is {word}, not 0 or 1");
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    pub(crate) fn rpc_ok(result: serde_json::Value) -> serde_json::Value {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result })
    }

    pub(crate) fn rpc_err(message: &str) -> serde_json::Value {
        serde_json::json!({ "jsonrpc": "2.0", "id": 1, "error": { "code": -32000, "message": message } })
    }

    /// Minimal JSON-RPC HTTP fixture: std TcpListener, one request per
    /// connection (responses are `Connection: close`, so reqwest never reuses
    /// the socket), no test-only server dependency. The responder sees each
    /// parsed request body; the counter counts handled requests.
    pub(crate) fn spawn_json_rpc_fixture(
        respond: impl Fn(serde_json::Value) -> serde_json::Value + Send + Sync + 'static,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let responder = std::sync::Arc::new(respond);
        let count_for_server = count.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => head.push(byte[0]),
                    }
                }
                let content_length = String::from_utf8_lossy(&head)
                    .split("\r\n")
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .and_then(|v| v.trim().parse::<usize>().ok())
                    })
                    .unwrap_or(0);
                let mut body = vec![0u8; content_length];
                if stream.read_exact(&mut body).is_err() {
                    continue;
                }
                count_for_server.fetch_add(1, Ordering::SeqCst);
                let request: serde_json::Value =
                    serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);
                let response = serde_json::to_vec(&responder(request)).expect("fixture response serializes");
                let _ = stream.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        response.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(&response);
            }
        });
        (url, count)
    }

    fn test_bridge() -> Address {
        "0x00000000000000000000000000000000000000b2".parse().unwrap()
    }

    /// Only `0x` + 64 hex digits encoding exactly 0 or 1 decode — every other
    /// shape is an error, never a default.
    #[test]
    fn decode_bool_word_accepts_only_canonical_zero_and_one() {
        assert!(!decode_bool_word(&serde_json::json!(format!("0x{}", "0".repeat(64)))).unwrap());
        assert!(decode_bool_word(&serde_json::json!(format!("0x{}1", "0".repeat(63)))).unwrap());
        let bads = [
            serde_json::json!("0x"),
            serde_json::json!(format!("0x{}1", "0".repeat(62))),  // 63 digits
            serde_json::json!(format!("0x{}1", "0".repeat(64))),  // 65 digits
            serde_json::json!(format!("0x{}2", "0".repeat(63))),  // not a bool
            serde_json::json!(format!("0x{}", "g".repeat(64))),   // not hex
            serde_json::json!("0".repeat(64)),                     // missing 0x
            serde_json::json!(null),
            serde_json::json!(1u8),
            serde_json::json!({}),
        ];
        for bad in &bads {
            assert!(decode_bool_word(bad).is_err(), "{bad} must be refused");
        }
    }

    #[tokio::test]
    async fn the_claimed_nullifier_call_sends_the_selector_and_the_full_nonce_word() {
        let seen = std::sync::Arc::new(std::sync::Mutex::new(None));
        let seen_for_fixture = seen.clone();
        let nonce = [0xA5u8; 32];
        let (url, _) = spawn_json_rpc_fixture(move |req| {
            *seen_for_fixture.lock().unwrap() = Some(req);
            rpc_ok(serde_json::json!(format!("0x{}1", "0".repeat(63))))
        });
        let claimed = L1Client::read_only(url)
            .is_withdrawal_claimed(test_bridge(), &nonce)
            .await
            .unwrap();
        assert!(claimed);
        let req = seen.lock().unwrap().take().expect("the fixture saw the eth_call");
        assert_eq!(req["method"], "eth_call");
        assert_eq!(
            req["params"][0]["to"].as_str().unwrap().parse::<Address>().unwrap(),
            test_bridge(),
            "the call must go to the configured destination bridge"
        );
        let raw = req["params"][0]["data"].as_str().unwrap().strip_prefix("0x").unwrap();
        let expected_selector = hex::encode(&keccak256(b"claimedNullifiers(bytes32)")[..4]);
        assert_eq!(&raw[..8], expected_selector, "selector is the computed keccak of claimedNullifiers(bytes32)");
        assert_eq!(&raw[8..], hex::encode(nonce), "the FULL 256-bit nonce is the mapping key, unchanged");
    }

    #[tokio::test]
    async fn a_malformed_bool_word_fails_closed() {
        for result in ["0x", "not-hex", "0xzz"] {
            let value = serde_json::json!(result);
            let (url, _) = spawn_json_rpc_fixture(move |_| rpc_ok(value.clone()));
            assert!(
                L1Client::read_only(url).is_withdrawal_claimed(test_bridge(), &[1u8; 32]).await.is_err(),
                "`{result}` must fail closed, never read as unclaimed"
            );
        }
    }

    #[tokio::test]
    async fn an_rpc_error_response_is_an_error_not_unclaimed() {
        let (url, _) = spawn_json_rpc_fixture(|_| rpc_err("execution reverted"));
        assert!(
            L1Client::read_only(url).is_withdrawal_claimed(test_bridge(), &[1u8; 32]).await.is_err(),
            "a JSON-RPC error must refuse the burn, not read as unclaimed"
        );
    }
}
