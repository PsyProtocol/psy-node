use super::*;
use alloy_consensus::Transaction;
use alloy_network::EthereumWallet;
use alloy_provider::ProviderBuilder;
use alloy_signer_local::PrivateKeySigner;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{atomic::{AtomicBool, Ordering}, Arc, Mutex},
    thread,
};

fn policy() -> BscFeePolicy {
    BscFeePolicy {
        expected_chain_id: 97,
        min_priority_fee_wei: 100_000_000,
        max_priority_fee_wei: 2_000_000_000,
        max_fee_per_gas_wei: 10_000_000_000,
        quote_strategy: BscQuoteStrategy::Conservative,
    }
}

fn calculate_fees(p: &BscFeePolicy, base: u128, priority: Option<u128>, rewards: &[Vec<u128>]) -> Result<(u128, u128)> {
    estimate_fees(p, base, priority, rewards).map(|fees| (fees.tip, fees.max_fee))
}

fn economical_policy() -> BscFeePolicy {
    BscFeePolicy {
        min_priority_fee_wei: 100_000_000,
        max_priority_fee_wei: 1_000_000_000,
        max_fee_per_gas_wei: 1_000_000_000,
        quote_strategy: BscQuoteStrategy::RecentHistory,
        ..policy()
    }
}

#[test]
fn recent_history_avoids_static_provider_overquote_with_headroom() {
    // Observed BSC scenario: local quote 0.1 gwei, Alchemy quote 1 gwei,
    // recent positive rewards mostly 0.1 gwei interspersed with zero rewards.
    let rewards = vec![vec![0], vec![100_000_000], vec![100_000_000],
        vec![], vec![110_000_000], vec![100_000_000], vec![900_000_000]];
    for priority in [None, Some(0), Some(100_000_000), Some(1_000_000_000), Some(u128::MAX)] {
        let fees = estimate_fees(&economical_policy(), 0, priority, &rewards).unwrap();
        assert_eq!((fees.tip, fees.max_fee), (120_000_000, 120_000_000));
        assert_eq!(fees.source, "recent_history_with_headroom");
        assert_eq!(fees.positive_history_samples, 5);
    }
    assert_eq!(calculate_fees(&policy(), 0, Some(1_000_000_000), &rewards).unwrap(),
        (1_000_000_000, 1_000_000_000));
}

#[test]
fn sparse_or_zero_history_falls_back_but_never_invents_a_quote() {
    for rewards in [vec![], vec![vec![0]; 10], vec![vec![100_000_000]],
        vec![vec![100_000_000]; 2]] {
        for priority in [100_000_000, 1_000_000_000] {
            let fees = estimate_fees(&economical_policy(), 0, Some(priority), &rewards).unwrap();
            assert_eq!(fees.tip, priority);
            assert_eq!(fees.source, "priority_fallback");
        }
        for priority in [None, Some(0)] {
            assert!(estimate_fees(&economical_policy(), 0, priority, &rewards)
                .unwrap_err().downcast_ref::<FeeSourceError>().is_some());
        }
    }
    assert_eq!(calculate_fees(&economical_policy(), 0, Some(1), &[]).unwrap(),
        (100_000_000, 100_000_000));
}

#[test]
fn recent_history_preserves_floor_caps_and_base_fee_budget() {
    let rewards = vec![vec![100_000_000]; 3];
    let mut p = economical_policy();
    p.min_priority_fee_wei = 1_000_000_000;
    assert_eq!(calculate_fees(&p, 0, Some(100_000_000), &rewards).unwrap(),
        (1_000_000_000, 1_000_000_000));
    p = economical_policy();
    assert_eq!(calculate_fees(&p, 100_000_000, None, &rewards).unwrap(),
        (120_000_000, 320_000_000));
    assert!(calculate_fees(&p, 500_000_000, None, &rewards).is_err());
    assert!(calculate_fees(&p, 0, Some(1), &vec![vec![900_000_000]; 3]).is_err());
    assert!(calculate_fees(&p, 0, None, &vec![vec![u128::MAX]; 3]).is_err());
    assert!(calculate_fees(&p, u128::MAX, None, &rewards).is_err());
    assert!(calculate_fees(&p, 0, Some(2_000_000_000), &[]).is_err());
}

#[test]
fn history_headroom_rounds_up_and_filters_empty_zero_rewards() {
    let mut p = economical_policy();
    p.min_priority_fee_wei = 1;
    assert_eq!(calculate_fees(&p, 0, None,
        &[vec![], vec![0], vec![6], vec![8], vec![7], vec![9]]).unwrap(), (10, 10));
}

#[test]
fn quote_strategy_is_explicit_and_old_configs_keep_their_behavior() {
    let old = r#"{"expected_chain_id":97,"min_priority_fee_wei":1000000000,"max_priority_fee_wei":1000000000,"max_fee_per_gas_wei":1000000000}"#;
    let p: BscFeePolicy = old.parse().unwrap();
    assert_eq!(p.quote_strategy, BscQuoteStrategy::Conservative);
    let new = r#"{"expected_chain_id":97,"min_priority_fee_wei":100000000,"max_priority_fee_wei":1000000000,"max_fee_per_gas_wei":1000000000,"quote_strategy":"recent_history"}"#;
    let p: BscFeePolicy = new.parse().unwrap();
    assert_eq!(p.quote_strategy, BscQuoteStrategy::RecentHistory);
    assert!(new.replace("recent_history", "typo").parse::<BscFeePolicy>().is_err());
}

#[test]
fn zero_history_reproduces_old_one_wei_and_new_floor() {
    for rewards in [vec![], vec![vec![]], vec![vec![0]], vec![vec![0]; 10]] {
        let old = alloy_provider::utils::eip1559_default_estimator(0, &rewards);
        assert_eq!(old.max_priority_fee_per_gas, 1);
        assert_eq!(calculate_fees(&policy(), 0, Some(100_000_000), &rewards).unwrap(),
            (100_000_000, 100_000_000));
    }
}

#[test]
fn valid_history_can_replace_unavailable_priority_rpc() {
    for suggestion in [None, Some(0)] {
        assert_eq!(calculate_fees(&policy(), 0, suggestion, &[vec![200_000_000]]).unwrap(),
            (200_000_000, 200_000_000));
        assert!(calculate_fees(&policy(), 0, suggestion, &[vec![0]]).is_err());
    }
}

#[test]
fn one_wei_suggestion_cannot_override_configured_floor() {
    let mut p = policy();
    p.min_priority_fee_wei = 1_000_000_000;
    assert_eq!(calculate_fees(&p, 0, Some(1), &vec![vec![0]; 10]).unwrap(),
        (1_000_000_000, 1_000_000_000));
}

#[test]
fn base_fee_caps_overflow_and_explicit_fees_are_guarded() {
    let p = policy();
    assert_eq!(calculate_fees(&p, 500_000_000, Some(200_000_000), &[]).unwrap(),
        (200_000_000, 1_200_000_000));
    assert!(calculate_fees(&p, 0, Some(3_000_000_000), &[]).is_err());
    assert!(calculate_fees(&p, 6_000_000_000, Some(100_000_000), &[]).is_err());
    assert!(calculate_fees(&p, u128::MAX, Some(100_000_000), &[]).is_err());
    let mut tx = TransactionRequest::default();
    fill_or_validate(&mut tx, &p, 100_000_000, 100_000_000).unwrap();
    tx.max_priority_fee_per_gas = Some(200_000_000);
    tx.max_fee_per_gas = Some(300_000_000);
    let before = tx.clone();
    fill_or_validate(&mut tx, &p, 100_000_000, 100_000_000).unwrap();
    assert_eq!(tx, before);
    assert!(fill_or_validate(&mut tx, &p, 400_000_000, 400_000_000).is_err());
    tx.max_priority_fee_per_gas = None;
    assert!(fill_or_validate(&mut tx, &p, 1, 1).is_err());
    tx.gas_price = Some(1);
    assert!(fill_or_validate(&mut tx, &p, 1, 1).is_err());
}

#[test]
fn invalid_configuration_fails_and_old_configuration_loads() {
    #[derive(Deserialize)]
    struct Chain { #[serde(default)] fee_policy: Option<BscFeePolicy> }
    assert!(toml::from_str::<Chain>("").unwrap().fee_policy.is_none());
    let mut p = policy();
    p.expected_chain_id = 1;
    assert!(p.validate().is_err());
    p = policy();
    p.min_priority_fee_wei = 0;
    assert!(p.validate().is_err());
    p.min_priority_fee_wei = p.max_priority_fee_wei + 1;
    assert!(p.validate().is_err());
    p = policy();
    p.max_fee_per_gas_wei = 1;
    assert!(p.validate().is_err());
    let p: BscFeePolicy = toml::from_str("expected_chain_id = 97\nmin_priority_fee_wei = 100000000\nmax_priority_fee_wei = 2000000000\nmax_fee_per_gas_wei = 10000000000\n").unwrap();
    p.validate().unwrap();
}

// Method-dispatching HTTP fixture exercises the real Alloy provider/fillers.
// It never connects to a real chain or accepts a broadcast method.
struct MockRpc {
    url: url::Url,
    calls: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl MockRpc {
    fn new(chain_id: u64, priority: Value, reward: Value) -> Self {
        Self::with_overrides(chain_id, priority, reward, std::collections::HashMap::new())
    }

    fn with_overrides(chain_id: u64, priority: Value, reward: Value, overrides: std::collections::HashMap<String, Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap()).parse().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = stop.clone();
        let thread_calls = calls.clone();
        let handle = thread::spawn(move || {
            let mut stalled = Vec::new();
            while !thread_stop.load(Ordering::Relaxed) {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(1));
                    continue;
                };
                socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                let (header_end, length) = loop {
                    let n = socket.read(&mut buf).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                    if let Some(pos) = data.windows(4).position(|v| v == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&data[..pos]);
                        let length = headers.lines().find_map(|line| {
                            let (key, value) = line.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length").then(|| value.trim().parse::<usize>().unwrap())
                        }).unwrap();
                        break (pos + 4, length);
                    }
                };
                while data.len() < header_end + length {
                    let n = socket.read(&mut buf).unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                }
                let req: Value = serde_json::from_slice(&data[header_end..header_end + length]).unwrap();
                let method = req["method"].as_str().unwrap();
                thread_calls.lock().unwrap().push(method.to_owned());
                if (method == "eth_maxPriorityFeePerGas" && priority == json!("timeout"))
                    || overrides.get(method) == Some(&json!("timeout")) {
                    stalled.push(socket);
                    continue;
                }
                let result = overrides.get(method).cloned().unwrap_or_else(|| match method {
                    "eth_chainId" => json!(format!("0x{chain_id:x}")),
                    "eth_maxPriorityFeePerGas" => priority.clone(),
                    "eth_feeHistory" => json!({"oldestBlock":"0x1","baseFeePerGas":["0x0","0x0"],
                        "gasUsedRatio":[0.5],"reward":reward}),
                    "eth_getBlockByNumber" => {
                        let mut block: alloy_rpc_types_eth::Block = Default::default();
                        block.header.inner.base_fee_per_gas = Some(0);
                        serde_json::to_value(block).unwrap()
                    }
                    "eth_estimateGas" => json!("0x5208"),
                    "eth_getTransactionCount" => json!("0x7"),
                    other => panic!("unexpected RPC (broadcast forbidden): {other}"),
                });
                let response = if result.is_null() {
                    json!({"jsonrpc":"2.0","id":req["id"],"error":{"code":-32601,"message":"unsupported"}})
                } else {
                    json!({"jsonrpc":"2.0","id":req["id"],"result":result})
                }.to_string();
                write!(socket, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", response.len(), response).unwrap();
            }
        });
        Self { url, calls, stop, thread: Some(handle) }
    }
}

impl Drop for MockRpc {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
async fn real_alloy_fillers_preserve_fees_and_sign_without_broadcast() {
    for reward in [json!([["0x0"]]), json!([["0x5f5e100"]]), Value::Null] {
        let rpc = MockRpc::new(97, json!("0x5f5e100"), reward);
        let wallet = EthereumWallet::from(PrivateKeySigner::random());
        let provider = ProviderBuilder::new().wallet(wallet).connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default().to(alloy_primitives::Address::ZERO);
        prepare_l1_fees(&provider, &mut tx, Some(&policy())).await.unwrap();
        let signed = provider.fill(tx).await.unwrap();
        let envelope = signed.as_envelope().unwrap();
        assert!(envelope.is_eip1559());
        assert_eq!(envelope.chain_id(), Some(97));
        assert_eq!(envelope.max_priority_fee_per_gas(), Some(100_000_000));
        assert_eq!(envelope.max_fee_per_gas(), 100_000_000);
        assert_eq!(envelope.nonce(), 7);
        assert_eq!(envelope.gas_limit(), 21000);
        let calls = rpc.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|m| *m == "eth_feeHistory").count(), 1);
        assert!(!calls.iter().any(|m| m.starts_with("eth_send")));
    }
}

#[tokio::test]
async fn recent_history_is_preserved_by_real_fillers_without_broadcast() {
    let rewards = json!([["0x5f5e100"], ["0x0"], ["0x5f5e100"], ["0x5f5e100"]]);
    for priority in [json!("0x3b9aca00"), Value::Null] {
        let rpc = MockRpc::new(97, priority, rewards.clone());
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default().to(alloy_primitives::Address::ZERO);
        prepare_l1_fees(&provider, &mut tx, Some(&economical_policy())).await.unwrap();
        let signed = provider.fill(tx).await.unwrap();
        let envelope = signed.as_envelope().unwrap();
        assert!(envelope.is_eip1559());
        assert_eq!(envelope.chain_id(), Some(97));
        assert_eq!(envelope.max_priority_fee_per_gas(), Some(120_000_000));
        assert_eq!(envelope.max_fee_per_gas(), 120_000_000);
        let calls = rpc.calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|m| *m == "eth_feeHistory").count(), 1);
        assert!(!calls.iter().any(|m| m.starts_with("eth_send")));
    }
}

#[tokio::test]
async fn recent_history_refuses_over_budget_or_unusable_sources_before_fill() {
    for (priority, rewards) in [
        (json!("0x5f5e100"), json!(vec![vec!["0x3b9aca00"]; 3])),
        (Value::Null, json!([["0x5f5e100"]])),
        (Value::Null, Value::Null),
    ] {
        let rpc = MockRpc::new(97, priority, rewards);
        let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default();
        let before = tx.clone();
        let error = prepare_l1_fees(&provider, &mut tx, Some(&economical_policy())).await.unwrap_err();
        assert!(is_fee_preparation_error(&error));
        assert_eq!(tx, before);
        assert!(!rpc.calls.lock().unwrap().iter().any(|m| m.starts_with("eth_send")));
    }
}

#[tokio::test]
async fn priority_rpc_timeout_can_use_valid_history_within_deadline() {
    let rpc = MockRpc::new(97, json!("timeout"), json!([["0x5f5e100"]]));
    let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
    let mut tx = TransactionRequest::default();
    tokio::time::timeout(FEE_RPC_TIMEOUT + Duration::from_secs(3),
        prepare_l1_fees(&provider, &mut tx, Some(&policy()))).await.unwrap().unwrap();
    assert_eq!(tx.max_priority_fee_per_gas, Some(100_000_000));
}

#[tokio::test]
async fn missing_policy_is_noop_for_other_chains() {
    for chain_id in [11155111, 84532] {
        let rpc = MockRpc::new(chain_id, Value::Null, Value::Null);
        let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default();
        let before = tx.clone();
        prepare_l1_fees(&provider, &mut tx, None).await.unwrap();
        assert_eq!(tx, before);
        assert!(rpc.calls.lock().unwrap().is_empty());
    }
}

#[tokio::test]
async fn wrong_chain_and_unusable_sources_refuse_before_signing() {
    for (chain, priority, reward) in [
        (1, json!("0x5f5e100"), json!([["0x0"]])),
        (97, Value::Null, json!([["0x0"]])),
        (97, json!("malformed"), json!([["0x0"]])),
        (97, json!("0x0"), json!([])),
        (97, json!("0xffffffffffff"), json!([["0x0"]])),
    ] {
        let rpc = MockRpc::new(chain, priority, reward);
        let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default();
        let err = prepare_l1_fees(&provider, &mut tx, Some(&policy())).await.unwrap_err();
        assert!(is_fee_preparation_error(&err));
        assert!(tx.max_priority_fee_per_gas.is_none());
        assert!(!rpc.calls.lock().unwrap().iter().any(|m| m.starts_with("eth_send")));
    }
}

#[tokio::test]
async fn pooled_fee_requests_fail_over_without_replaying_business_operation() {
    let bad = MockRpc::new(97, Value::Null, json!([["0x0"]]));
    let good = MockRpc::new(97, json!("0x5f5e100"), json!([["0x0"]]));
    let client = super::super::l1_client::L1Client::from_finalize_config(&super::super::daemon::DaemonFinalizeConfig {
        l1_rpc_url: Some(bad.url.to_string()),
        l1_rpc_fallback_url: Some(good.url.to_string()),
        ..Default::default()
    }, "bscTestnet").unwrap();
    let mut business_calls = 0;
    let tx = client.with_rpc_failover("fees", |url| {
        business_calls += 1;
        let scoped = super::super::l1_provider::connect_l1_readonly(url.parse().unwrap()).unwrap();
        let provider = ProviderBuilder::new()
            .wallet(EthereumWallet::from(PrivateKeySigner::random()))
            .connect_provider(scoped.root().clone());
        async move {
            let mut tx = TransactionRequest::default().to(alloy_primitives::Address::ZERO);
            prepare_l1_fees(&provider, &mut tx, Some(&policy())).await?;
            let signed = provider.fill(tx.clone()).await?;
            assert_eq!(signed.as_envelope().unwrap().max_fee_per_gas(), 100_000_000);
            Ok(tx)
        }
    }).await.unwrap();
    assert_eq!(business_calls, 1);
    assert_eq!(tx.max_priority_fee_per_gas, Some(100_000_000));
    assert!(!good.calls.lock().unwrap().is_empty());
    for rpc in [&bad, &good] {
        assert!(!rpc.calls.lock().unwrap().iter().any(|m| m.starts_with("eth_send")));
    }

    let error = client.with_rpc_failover::<(), _, _>("fees", |_| async {
        Err(FeeSourceError("unavailable test fee source").into())
    }).await.unwrap_err();
    assert!(error.downcast_ref::<FeeSourceError>().is_some());
    assert!(is_fee_preparation_error(&error));
}

#[tokio::test]
async fn pooled_slow_fee_rpc_gets_full_attempt_budget_then_fails_over() {
    let slow = MockRpc::new(97, json!("timeout"), json!([["0x0"]]));
    let good = MockRpc::new(97, json!("0x3b9aca00"), json!([["0x0"]]));
    let client = super::super::l1_client::L1Client::from_finalize_config(
        &super::super::daemon::DaemonFinalizeConfig {
            l1_rpc_url: Some(slow.url.to_string()),
            l1_rpc_fallback_url: Some(good.url.to_string()),
            ..Default::default()
        }, "bscTestnet",
    ).unwrap();
    let mut calls = 0;
    let tx = tokio::time::timeout(Duration::from_secs(34), client.with_rpc_failover("fees", |url| {
        calls += 1;
        let provider = super::super::l1_provider::connect_l1_readonly(url.parse().unwrap()).unwrap();
        async move {
            let mut tx = TransactionRequest::default();
            prepare_l1_fees(&provider, &mut tx, Some(&policy())).await?;
            Ok(tx)
        }
    })).await.unwrap().unwrap();
    assert_eq!(calls, 1);
    assert_eq!(tx.max_priority_fee_per_gas, Some(1_000_000_000));
    assert!(good.calls.lock().unwrap().iter().any(|m| m == "eth_maxPriorityFeePerGas"));
}

#[test]
fn preparing_fees_preserves_transaction_identity_and_rejects_unknown_config() {
    let tx = TransactionRequest::default()
        .to(alloy_primitives::Address::repeat_byte(1))
        .input(alloy_primitives::Bytes::from(vec![1, 2, 3]).into())
        .nonce(123)
        .gas_limit(456_789)
        .value(alloy_primitives::U256::from(99));
    let mut filled = tx.clone();
    fill_or_validate(&mut filled, &policy(), 100_000_000, 100_000_000).unwrap();
    filled.max_priority_fee_per_gas = None;
    filled.max_fee_per_gas = None;
    filled.transaction_type = None;
    assert_eq!(filled, tx);
    assert!(serde_json::from_value::<BscFeePolicy>(json!({
        "expected_chain_id":97, "min_priority_fee_wei":1, "max_priority_fee_wei":2,
        "max_fee_per_gas_wei":3, "unknown": true,
    })).is_err());
}

#[test]
fn conflicting_transaction_type_is_rejected() {
    for kind in [0, 1, 3] {
        let mut tx = TransactionRequest { transaction_type: Some(kind), ..Default::default() };
        assert!(fill_or_validate(&mut tx, &policy(), 100_000_000, 100_000_000).is_err());
        assert!(tx.max_fee_per_gas.is_none());
    }
}

#[tokio::test]
async fn missing_block_base_fee_and_rpc_failure_remain_retryable() {
    let block: alloy_rpc_types_eth::Block = Default::default();
    let missing_base = serde_json::to_value(block).unwrap();
    for (method, result) in [
        ("eth_chainId", Value::Null),
        ("eth_getBlockByNumber", Value::Null),
        ("eth_getBlockByNumber", missing_base),
    ] {
        let rpc = MockRpc::with_overrides(97, json!("0x5f5e100"), json!([["0x0"]]),
            std::collections::HashMap::from([(method.to_owned(), result)]));
        let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
        let mut tx = TransactionRequest::default();
        let error = prepare_l1_fees(&provider, &mut tx, Some(&policy())).await.unwrap_err();
        assert!(error.downcast_ref::<FeeSourceError>().is_some());
        assert!(tx.max_fee_per_gas.is_none());
    }
}

#[tokio::test]
async fn chain_query_has_overall_deadline_and_conflicting_tx_chain_is_rejected() {
    let rpc = MockRpc::with_overrides(97, json!("0x5f5e100"), json!([["0x0"]]),
        std::collections::HashMap::from([("eth_chainId".to_owned(), json!("timeout"))]));
    let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
    let mut tx = TransactionRequest::default();
    let error = tokio::time::timeout(FEE_RPC_TIMEOUT + Duration::from_secs(3),
        prepare_l1_fees(&provider, &mut tx, Some(&policy()))).await.unwrap().unwrap_err();
    assert!(error.downcast_ref::<FeeSourceError>().is_some());
    assert!(error.to_string().contains("eth_chainId timed out"));

    let rpc = MockRpc::new(97, json!("0x5f5e100"), json!([["0x0"]]));
    let provider = ProviderBuilder::new().connect_http(rpc.url.clone());
    tx.chain_id = Some(1);
    let error = prepare_l1_fees(&provider, &mut tx, Some(&policy())).await.unwrap_err();
    assert!(error.downcast_ref::<FeePolicyError>().is_some());
    assert!(tx.max_fee_per_gas.is_none());
}

#[tokio::test]
async fn withdrawal_policy_refusal_precedes_proof_and_does_not_fail_claims() {
    let rpc = MockRpc::new(97, json!("0xffffffffffff"), json!([["0x0"]]));
    let withdrawal = super::super::propose_withdrawals::PendingWithdrawal {
        event_id: 1, checkpoint_id: 1, user_id: 1, sender_user_id: 1,
        contract_id: 1, destination_chain_index: 1,
        token_address: [0; 8], amount: [0; 8], recipient: [0; 8], nonce: [0; 8],
        leaf_hash: "test-only-leaf".to_owned(),
    };
    let test_key = "11".repeat(32);
    let report = super::super::claim_withdrawals::submit_batch(
        &[withdrawal], "http://127.0.0.1:1", rpc.url.as_str(),
        "0x0000000000000000000000000000000000000001", None, "bscTestnet",
        Some(&test_key), None, "UNUSED_TEST_PASSWORD", None, Some(&policy()),
    ).await.unwrap();
    assert_eq!(report.requested, 1);
    assert_eq!(report.submitted_count, 0);
    assert!(report.failure_reasons.is_empty());
    assert!(report.deferrals.contains_key("test-only-leaf"));
    // Any proof, contract-state or broadcast call would panic in this fixture.
    assert_eq!(rpc.calls.lock().unwrap().len(), 4);
}
