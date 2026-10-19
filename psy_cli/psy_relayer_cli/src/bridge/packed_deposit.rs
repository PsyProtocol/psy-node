//! Lossless, opt-in transport for existing deposit proofs. No proving inputs change.
use alloy_primitives::{Address, Bytes, U256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;

use super::prove_bridge::{batchAppendCall, provedDepositCountCall, DepositBatchAppendCall};

pub(crate) const RECORD_BYTES: usize = 8684;
const PUBLIC_INPUT_WORDS: usize = 795;
const MAX_BATCHES: usize = 14;
const SAFE_CALLDATA_BYTES: usize = 120 * 1024;

sol! {
    function appendPackedBatches(bytes batches);
    function BRIDGE() external view returns (address);
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PackedDepositConfig {
    pub adapter_address: Address,
    pub max_calls_per_tx: usize,
    /// Includes a 4% margin above eth_estimateGas. No guessed gas fallback.
    pub max_gas_per_tx: u64,
    pub max_fee_per_gas_wei: u64,
    pub max_tx_fee_wei: u64,
}

impl PackedDepositConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(self.adapter_address != Address::ZERO, "packed deposit adapter cannot be zero");
        ensure!((1..=MAX_BATCHES).contains(&self.max_calls_per_tx), "packed deposit max_calls_per_tx must be 1..=14");
        ensure!(self.max_gas_per_tx >= 21_000, "packed deposit gas budget is too small");
        ensure!(self.max_fee_per_gas_wei > 0 && self.max_tx_fee_wei > 0, "packed deposit fee caps must be positive");
        Ok(())
    }

    pub(crate) async fn prepare_fees(&self, provider: &impl Provider, tx: &mut TransactionRequest,
        policy: Option<&super::l1_fees::BscFeePolicy>) -> Result<()> {
        super::l1_fees::prepare_l1_fees(provider, tx, policy).await?;
        if tx.max_fee_per_gas.is_none() {
            let fees = provider.estimate_eip1559_fees().await.context("estimate packed deposit fees failed")?;
            tx.max_fee_per_gas = Some(fees.max_fee_per_gas);
            tx.max_priority_fee_per_gas = Some(fees.max_priority_fee_per_gas);
        }
        let price = tx.max_fee_per_gas.context("missing packed deposit max fee")?;
        ensure!(price > 0 && tx.max_priority_fee_per_gas.is_some_and(|tip| tip <= price), "invalid packed deposit fee estimate");
        ensure!(price <= u128::from(self.max_fee_per_gas_wei), "packed deposit gas price exceeds configured cap");
        Ok(())
    }

    pub(crate) async fn validate_bridge(&self, provider: &impl Provider, bridge: Address) -> Result<()> {
        self.validate()?;
        let tx = TransactionRequest::default().to(self.adapter_address).input(BRIDGECall {}.abi_encode().into());
        let raw = provider.call(tx).await.context("read packed deposit adapter Bridge failed")?;
        let actual = BRIDGECall::abi_decode_returns(&raw).context("decode packed deposit adapter Bridge failed")?;
        ensure!(actual == bridge, "packed deposit adapter points to a different Bridge");
        let chain_id = provider.get_chain_id().await.context("read packed deposit chain ID failed")?;
        if matches!(chain_id, 1 | 11155111) {
            ensure!(self.max_gas_per_tx <= 16_777_216, "packed deposit gas budget exceeds Ethereum transaction gas cap");
        }
        Ok(())
    }
}

/// Encode from the already-built legacy ABI, rejecting overflow instead of truncating.
fn encode_record(call: &DepositBatchAppendCall) -> Result<Vec<u8>> {
    let decoded = batchAppendCall::abi_decode(&call.call_data).context("decode legacy deposit call failed")?;
    ensure!(decoded.abi_encode().as_slice() == call.call_data.as_ref(), "noncanonical legacy deposit calldata");
    ensure!(decoded.publicInputs.len() == PUBLIC_INPUT_WORDS, "packed deposit needs exactly 795 public input words");
    ensure!(call.to_index > call.from_index && call.to_index - call.from_index <= 32, "invalid packed deposit range");
    ensure!(decoded.publicInputs[16] == U256::from(call.from_index)
        && decoded.publicInputs[17] == U256::from(call.to_index), "deposit range disagrees with calldata");
    ensure!(call.slot_data.as_slice() == decoded.slotData.as_slice(), "deposit slots disagree with calldata");
    let mut packed = Vec::with_capacity(RECORD_BYTES);
    for coordinate in decoded.proof {
        packed.extend_from_slice(&coordinate.to_be_bytes::<32>());
    }
    for word in decoded.publicInputs.iter().chain(decoded.slotData.iter()) {
        let word = u32::try_from(*word).context("packed deposit word exceeds uint32")?;
        packed.extend_from_slice(&word.to_be_bytes());
    }
    ensure!(packed.len() == RECORD_BYTES, "invalid packed deposit record size");
    Ok(packed)
}

fn encode_group(records: &[Vec<u8>]) -> Result<Bytes> {
    ensure!(!records.is_empty() && records.len() <= MAX_BATCHES, "invalid packed deposit group count");
    ensure!(records.iter().all(|record| record.len() == RECORD_BYTES), "invalid packed deposit record length");
    let calldata = appendPackedBatchesCall { batches: records.concat().into() }.abi_encode();
    ensure!(calldata.len() <= SAFE_CALLDATA_BYTES, "packed deposit calldata exceeds safe budget");
    Ok(calldata.into())
}

fn gas_with_margin(estimate: u64) -> Result<u64> {
    let margin = estimate / 25 + u64::from(estimate % 25 != 0);
    estimate.checked_add(margin).context("packed deposit gas overflow")
}

pub(crate) fn finish_pipeline(produced: Result<()>, sent: Result<()>) -> Result<()> {
    match (produced, sent) {
        (Err(proof), Err(send)) if proof.is::<super::prove_bridge::DepositStreamConsumerStopped>() => Err(send),
        (Err(proof), _) => Err(proof),
        (Ok(()), sent) => sent,
    }
}

fn estimate_hit_limit(error: &alloy_transport::TransportError) -> bool {
    let alloy_transport::TransportError::ErrorResp(error) = error else { return false; };
    let message = error.message.to_ascii_lowercase();
    let no_revert_data = error.data.as_ref().is_none_or(|data| matches!(data.get(), "null" | "\"0x\""));
    // Some RPCs report their transaction gas ceiling as a data-less revert.
    // A one-call failure is always returned; custom proof/range reverts and
    // transport/quota errors must never be converted into a gas estimate.
    (error.code == 3 && message == "execution reverted" && no_revert_data)
        || (error.code == -32000 && (message.contains("gas required exceeds allowance")
            || message.contains("exceeds block gas limit") || message == "out of gas"))
}

async fn estimate_group(
    provider: &impl Provider, adapter: Address, records: &[Vec<u8>],
    fees: &TransactionRequest, gas_budget: u64,
) -> Result<(TransactionRequest, usize)> {
    let mut low = 1;
    let mut high = records.len();
    let mut best = None;
    while low <= high {
        // First establish that a single call is valid and affordable. Then
        // find the largest prefix within both the RPC and operator ceilings.
        let count = if best.is_none() { 1 } else { low + (high - low) / 2 };
        let mut tx = fees.clone().to(adapter).input(encode_group(&records[..count])?.into());
        tx.gas = Some(gas_budget);
        match provider.estimate_gas(tx.clone()).await {
            Ok(estimate) => {
                let gas = gas_with_margin(estimate)?;
                if gas <= gas_budget {
                    tx.gas = Some(gas);
                    best = Some((tx, count));
                    low = count + 1;
                } else {
                    ensure!(count > 1, "one packed deposit call exceeds configured gas or total fee budget");
                    high = count - 1;
                }
            }
            Err(error) if count > 1 && estimate_hit_limit(&error) => {
                tracing::warn!(count, "packed deposit estimate hit execution gas ceiling; reducing group");
                high = count - 1;
            }
            Err(error) => return Err(error).context("estimate packed deposit gas failed"),
        }
    }
    best.context("no packed deposit call fits the configured budget")
}

/// Wait for one ready call, then drain only what is already available. There
/// is no minimum batch count and no timer to accumulate additional proofs.
async fn next_ready_group(
    receiver: &mut tokio::sync::mpsc::Receiver<DepositBatchAppendCall>,
    max_calls: usize,
) -> Option<Vec<DepositBatchAppendCall>> {
    let first = receiver.recv().await?;
    let mut group = vec![first];
    while group.len() < max_calls {
        match receiver.try_recv() {
            Ok(call) => group.push(call),
            Err(_) => break,
        }
    }
    Some(group)
}

pub(crate) async fn submit_ready(
    provider: &impl Provider, config: &PackedDepositConfig, bridge: Address, sender: Address,
    mut receiver: tokio::sync::mpsc::Receiver<DepositBatchAppendCall>, target: u32,
    fee_policy: Option<&super::l1_fees::BscFeePolicy>,
) -> Result<()> {
    config.validate()?;
    while let Some(group) = next_ready_group(&mut receiver, config.max_calls_per_tx).await {
        let end = group.last().unwrap().to_index;
        ensure!(end <= target, "ready deposit group exceeds target");
        submit(provider, config, bridge, sender, &group, end, fee_policy).await?;
    }
    let after = super::daemon::fetch_proved_deposit_count(provider, bridge).await?;
    ensure!(after == target, "deposit stream ended before target: expected={} actual={}", target, after);
    Ok(())
}

/// Estimate only the next prefix against the current cursor. Later groups are
/// estimated after prior receipts, because they depend on prior Bridge state.
pub(crate) async fn submit(
    provider: &impl Provider,
    config: &PackedDepositConfig,
    bridge: Address,
    sender: Address,
    calls: &[DepositBatchAppendCall],
    target: u32,
    fee_policy: Option<&super::l1_fees::BscFeePolicy>,
) -> Result<()> {
    config.validate_bridge(provider, bridge).await?;
    ensure!(!calls.is_empty(), "empty packed deposit plan");
    for pair in calls.windows(2) {
        ensure!(pair[0].to_index == pair[1].from_index, "nonconsecutive packed deposit calls");
    }
    ensure!(calls.last().unwrap().to_index == target, "packed deposit plan ends before target");
    // Validate every record before broadcasting the first transaction.
    let records: Vec<_> = calls.iter().map(encode_record).collect::<Result<_>>()?;
    let mut start = 0;
    while start < calls.len() {
        let before = super::daemon::fetch_proved_deposit_count(provider, bridge).await?;
        ensure!(before == calls[start].from_index, "Bridge cursor changed before packed deposit send");
        let mut fees = TransactionRequest::default().from(sender);
        config.prepare_fees(provider, &mut fees, fee_policy).await?;
        let price = fees.max_fee_per_gas.context("missing packed deposit max fee")?;
        let fee_gas_budget = u64::try_from(u128::from(config.max_tx_fee_wei) / price).unwrap_or(u64::MAX);
        let gas_budget = config.max_gas_per_tx.min(fee_gas_budget);
        let end = (start + config.max_calls_per_tx).min(calls.len());
        let (tx, count) = estimate_group(provider, config.adapter_address, &records[start..end], &fees, gas_budget).await?;
        provider.call(tx.clone()).await.context("packed deposit simulation failed")?;
        tracing::info!(start, count, gas_limit = ?tx.gas, "sending packed deposit transaction");
        let receipt = provider.send_transaction(tx).await.context("send packed deposit failed")?
            .get_receipt().await.context("wait packed deposit receipt failed")?;
        ensure!(receipt.status(), "packed deposit transaction reverted: {}", receipt.transaction_hash);
        let after = super::daemon::fetch_proved_deposit_count(provider, bridge).await?;
        let expected = calls[start + count - 1].to_index;
        ensure!(after == expected, "packed deposit cursor mismatch: expected={} actual={}", expected, after);
        tracing::info!(tx_hash = %receipt.transaction_hash, count, proved_before = before,
            proved_after = after, gas_used = receipt.gas_used, "packed deposit transaction confirmed");
        start += count;
    }
    let after = super::api_client::eth_call_u256(provider, bridge, provedDepositCountCall {}).await?;
    ensure!(after == U256::from(target), "packed deposit final cursor mismatch");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(from: u32) -> DepositBatchAppendCall {
        let mut pi = vec![U256::from(u32::MAX); PUBLIC_INPUT_WORDS];
        pi[16] = U256::from(from);
        pi[17] = U256::from(from + 32);
        let decoded = batchAppendCall {
            proof: [U256::MAX; 8], publicInputs: pi,
            slotData: std::array::from_fn(|i| U256::from(i as u32)),
        };
        DepositBatchAppendCall { from_index: from, to_index: from + 32, batch_commit: [0; 8],
            slot_data: decoded.slotData.to_vec(), call_data: decoded.abi_encode().into() }
    }

    #[test]
    fn every_word_roundtrips_and_proof_coordinates_keep_all_bits() {
        let call = fixture(32);
        let packed = encode_record(&call).unwrap();
        let decoded = batchAppendCall::abi_decode(&call.call_data).unwrap();
        assert_eq!(&packed[..256], &[255; 256]);
        let restored: Vec<_> = packed[256..].chunks_exact(4)
            .map(|bytes| U256::from(u32::from_be_bytes(bytes.try_into().unwrap()))).collect();
        assert_eq!(restored, [decoded.publicInputs, decoded.slotData.to_vec()].concat());
    }

    #[test]
    fn rejects_overflow_and_inconsistent_metadata() {
        let mut call = fixture(0);
        let mut decoded = batchAppendCall::abi_decode(&call.call_data).unwrap();
        decoded.publicInputs[0] = U256::from(u32::MAX) + U256::from(1);
        call.call_data = decoded.abi_encode().into();
        assert!(encode_record(&call).is_err());
        let mut call = fixture(0);
        call.to_index = 31;
        assert!(encode_record(&call).is_err());
        let mut call = fixture(0);
        call.slot_data[0] = U256::MAX;
        assert!(encode_record(&call).is_err());
    }

    #[test]
    fn group_sizes_include_selector_offset_length_and_padding() {
        let record = encode_record(&fixture(0)).unwrap();
        for (n, expected) in [(1, 8772), (2, 17444), (3, 26148), (14, 121668)] {
            assert_eq!(encode_group(&vec![record.clone(); n]).unwrap().len(), expected);
        }
        assert!(encode_group(&vec![record; 15]).is_err());
        assert!(encode_group(&[]).is_err());
    }

    #[test]
    fn gas_margin_and_configuration_bounds() {
        assert_eq!(gas_with_margin(1_000_000).unwrap(), 1_040_000);
        assert_eq!(gas_with_margin(14_388_825).unwrap(), 14_964_378);
        assert!(gas_with_margin(u64::MAX).is_err());
        let mut config = PackedDepositConfig { adapter_address: Address::repeat_byte(1), max_calls_per_tx: 12,
            max_gas_per_tx: 8_000_000, max_fee_per_gas_wei: 5_000_000_000, max_tx_fee_wei: 40_000_000_000_000_000 };
        assert!(config.validate().is_ok());
        config.max_calls_per_tx = 15;
        assert!(config.validate().is_err());
    }

    #[tokio::test]
    async fn ready_groups_send_one_or_three_without_waiting_for_twelve() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(24);
        sender.send(fixture(0)).await.unwrap();
        let first = tokio::time::timeout(std::time::Duration::from_millis(100), next_ready_group(&mut receiver, 12))
            .await.unwrap().unwrap();
        assert_eq!(first.len(), 1);
        for from in [32, 64, 96] { sender.send(fixture(from)).await.unwrap(); }
        assert_eq!(next_ready_group(&mut receiver, 12).await.unwrap().len(), 3);
        for i in 0..13 { sender.send(fixture(i * 32)).await.unwrap(); }
        assert_eq!(next_ready_group(&mut receiver, 12).await.unwrap().len(), 12);
        assert_eq!(next_ready_group(&mut receiver, 12).await.unwrap().len(), 1);
        drop(sender);
        assert!(next_ready_group(&mut receiver, 12).await.is_none());
    }

    #[tokio::test]
    async fn estimates_shrink_to_gas_budget_and_refuse_single_over_budget() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        let server = tokio::spawn(async move {
            loop {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let (offset, length) = loop {
                    let mut bytes = [0; 8192];
                    let n = socket.read(&mut bytes).await.unwrap();
                    if n == 0 { return; }
                    data.extend_from_slice(&bytes[..n]);
                    if let Some(end) = data.windows(4).position(|b| b == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&data[..end]).unwrap();
                        let length = headers.lines().filter_map(|line| line.split_once(':'))
                            .find(|(k, _)| k.eq_ignore_ascii_case("content-length")).unwrap().1.trim().parse::<usize>().unwrap();
                        break (end + 4, length);
                    }
                };
                while data.len() < offset + length {
                    let mut bytes = [0; 8192];
                    let n = socket.read(&mut bytes).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&bytes[..n]);
                }
                let request: serde_json::Value = serde_json::from_slice(&data[offset..offset + length]).unwrap();
                assert_eq!(request["method"], "eth_estimateGas");
                let tx = &request["params"][0];
                let input = tx.get("input").or_else(|| tx.get("data")).unwrap().as_str().unwrap();
                let input: Bytes = input.parse().unwrap();
                let group = appendPackedBatchesCall::abi_decode(&input).unwrap();
                let count = group.batches.len() / RECORD_BYTES;
                let result = if count > 3 {
                    serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "error":{"code":3,"message":"execution reverted"}})
                } else {
                    serde_json::json!({"jsonrpc":"2.0", "id":request["id"], "result":format!("0x{:x}", count * 3_500_000)})
                }.to_string();
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{result}", result.len());
                socket.write_all(response.as_bytes()).await.unwrap();
            }
        });
        let provider = alloy_provider::ProviderBuilder::new().connect_http(url);
        let record = encode_record(&fixture(0)).unwrap();
        let records = vec![record; 12];
        let (tx, count) = estimate_group(&provider, Address::repeat_byte(1), &records, &TransactionRequest::default(), 15_000_000).await.unwrap();
        assert_eq!(count, 3);
        assert_eq!(tx.gas, Some(10_920_000));
        let (_, count) = estimate_group(&provider, Address::repeat_byte(1), &records, &TransactionRequest::default(), 9_000_000).await.unwrap();
        assert_eq!(count, 2);
        assert!(estimate_group(&provider, Address::repeat_byte(1), &records, &TransactionRequest::default(), 3_500_000).await.is_err());
        server.abort();
    }

    #[test]
    fn custom_proof_reverts_and_rpc_outages_are_not_gas_limits() {
        fn error(value: serde_json::Value) -> alloy_transport::TransportError {
            alloy_transport::TransportError::ErrorResp(serde_json::from_value(value).unwrap())
        }
        assert!(estimate_hit_limit(&error(serde_json::json!({"code":3,"message":"execution reverted"}))));
        assert!(!estimate_hit_limit(&error(serde_json::json!({"code":3,"message":"execution reverted","data":"0x12345678"}))));
        assert!(!estimate_hit_limit(&error(serde_json::json!({"code":429,"message":"quota exceeded"}))));
        assert!(!estimate_hit_limit(&error(serde_json::json!({"code":-32000,"message":"invalid proof"}))));
    }

    #[test]
    fn preserves_fee_error_when_consumer_closes_and_independent_proving_errors() {
        let result = finish_pipeline(
            Err(super::super::prove_bridge::DepositStreamConsumerStopped.into()),
            Err(super::super::l1_fees::FeeSourceError("test refusal").into()),
        ).unwrap_err();
        assert!(super::super::l1_fees::is_fee_preparation_error(&result));
        let result = finish_pipeline(Err(anyhow::anyhow!("actual proof failure")),
            Err(anyhow::anyhow!("stream ended before target"))).unwrap_err();
        assert_eq!(result.to_string(), "actual proof failure");
    }
}
