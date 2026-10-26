use super::*;
use alloy_provider::ProviderBuilder;
use alloy_rpc_types_eth::{Block, Log};
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

const BRIDGE: Address = Address::repeat_byte(0x42);

fn deposit(index: u32, block: u64) -> Value {
    let event = DepositRecorded {
        index,
        shieldAddress: B256::repeat_byte(1),
        token: Address::repeat_byte(2),
        l2TokenContractId: B256::repeat_byte(3),
        amount: alloy_primitives::U256::from(100),
        chainIndex: 2,
        noteCommitment: B256::repeat_byte(4),
        leafHash: B256::repeat_byte(5),
    };
    json!(Log {
        inner: alloy_primitives::Log { address: BRIDGE, data: event.encode_log_data() },
        block_number: Some(block),
        ..Default::default()
    })
}

fn log_request(start: u64, end: u64, index: Option<u32>, result: Value) -> Value {
    let topics = match index {
        Some(index) => json!([DepositRecorded::SIGNATURE_HASH, indexed_u32_topic(index)]),
        None => json!([DepositRecorded::SIGNATURE_HASH]),
    };
    json!({
        "method": "eth_getLogs",
        "params": [{
            "address": BRIDGE,
            "topics": topics,
            "fromBlock": format!("0x{start:x}"),
            "toBlock": format!("0x{end:x}"),
        }],
        "result": result,
    })
}

// Exercise the real Alloy JSON-RPC serialization; a fixture also rejects extra
// requests, moving-head queries, wrong topics and unbounded block ranges.
async fn fetch_fixture(
    head: u64,
    mut requests: Vec<Value>,
    from_block: BlockNumberOrTag,
    from_index: u32,
    to_index: u32,
) -> anyhow::Result<HashMap<u32, DepositRecorded>> {
    if from_index < to_index {
        requests.insert(0, json!({"method": "eth_blockNumber", "result": format!("0x{head:x}")}));
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        for expected in requests {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = BufReader::new(socket);
            let mut line = String::new();
            let mut length = 0;
            loop {
                line.clear();
                assert!(socket.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" { break; }
                if let Some((name, value)) = line.split_once(':') {
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse::<usize>().unwrap();
                    }
                }
            }
            let mut body = vec![0; length];
            socket.read_exact(&mut body).await.unwrap();
            let actual: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(actual["method"], expected["method"]);
            if let Some(params) = expected.get("params") {
                assert_eq!(&actual["params"], params);
            }
            let mut response = json!({"jsonrpc": "2.0", "id": actual["id"]});
            let key = if expected.get("error").is_some() { "error" } else { "result" };
            response[key] = expected[key].clone();
            let body = response.to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(), body
            );
            socket.get_mut().write_all(response.as_bytes()).await.unwrap();
        }
    });
    let provider = ProviderBuilder::new().connect_http(url.parse().unwrap());
    let result = tokio::time::timeout(Duration::from_secs(10), bulk_fetch_deposit_records(
        &provider, BRIDGE, from_block, from_index, to_index,
    )).await;
    let mut server = server;
    let joined = tokio::time::timeout(Duration::from_secs(2), &mut server).await;
    server.abort();
    joined.expect("unused fixture requests").expect("RPC request mismatch");
    result.expect("deposit fetch timed out")
}

#[test]
fn block_ranges_are_inclusive_bounded_and_lazy() {
    assert_eq!(bounded_block_ranges(10, 110_009).collect::<Vec<_>>(),
        vec![(10, 50_009), (50_010, 100_009), (100_010, 110_009)]);
    assert_eq!(bounded_block_ranges(5, 50_004).collect::<Vec<_>>(), vec![(5, 50_004)]);
    assert_eq!(bounded_block_ranges(7, 7).collect::<Vec<_>>(), vec![(7, 7)]);
    assert_eq!(bounded_block_ranges(6, 5).next(), None);
    assert_eq!(bounded_block_ranges(u64::MAX - 1, u64::MAX).collect::<Vec<_>>(),
        vec![(u64::MAX - 1, u64::MAX)]);
    assert_eq!(bounded_block_ranges(0, u64::MAX).take(2).collect::<Vec<_>>(),
        vec![(0, 49_999), (50_000, 99_999)]);
}

#[tokio::test]
async fn both_search_and_collection_are_chunked_and_stop_when_complete() {
    let first = deposit(7, 50_010);
    let second = deposit(8, 100_010);
    let records = fetch_fixture(200_000, vec![
        log_request(10, 50_009, Some(7), json!([])),
        log_request(50_010, 100_009, Some(7), json!([first])),
        log_request(50_010, 100_009, None, json!([deposit(6, 50_010), first])),
        log_request(100_010, 150_009, None, json!([second, deposit(9, 100_010)])),
    ], BlockNumberOrTag::Number(10), 7, 9).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[&7].amount, alloy_primitives::U256::from(100));
    assert_eq!(records[&8].chainIndex, 2);
}

#[tokio::test]
async fn empty_index_range_makes_no_rpc_requests() {
    assert!(fetch_fixture(10, vec![], BlockNumberOrTag::Earliest, 7, 7).await.unwrap().is_empty());
}

#[tokio::test]
async fn latest_start_uses_the_same_head_for_both_log_queries() {
    let event = deposit(0, 42);
    let records = fetch_fixture(42, vec![
        log_request(42, 42, Some(0), json!([event])),
        log_request(42, 42, None, json!([event])),
    ], BlockNumberOrTag::Latest, 0, 1).await.unwrap();
    assert_eq!(records.len(), 1);
}

#[tokio::test]
async fn finalized_start_is_resolved_before_scanning() {
    let mut block: Block = Block::default();
    block.header.inner.number = 20;
    let event = deposit(0, 21);
    assert_eq!(fetch_fixture(42, vec![
        json!({"method": "eth_getBlockByNumber", "params": ["finalized", false], "result": block}),
        log_request(20, 42, Some(0), json!([event])),
        log_request(21, 42, None, json!([event])),
    ], BlockNumberOrTag::Finalized, 0, 1).await.unwrap().len(), 1);
}

#[tokio::test]
async fn future_start_does_not_issue_an_inverted_log_range() {
    let error = fetch_fixture(10, vec![], BlockNumberOrTag::Number(11), 0, 1).await.err().unwrap();
    assert!(error.to_string().contains("not found on L1"));
}

#[tokio::test]
async fn missing_first_index_is_reported_after_all_search_chunks() {
    let error = fetch_fixture(50_000, vec![
        log_request(0, 49_999, Some(0), json!([])),
        log_request(50_000, 50_000, Some(0), json!([])),
    ], BlockNumberOrTag::Earliest, 0, 1).await.err().unwrap();
    assert!(error.to_string().contains("from_index=0"));
}

#[tokio::test]
async fn missing_and_duplicate_indices_are_not_silently_accepted() {
    let first = deposit(7, 0);
    for (events, expected) in [
        (json!([first]), "missing DepositRecorded log for index 8"),
        (json!([first, first]), "duplicate DepositRecorded log for index 7"),
    ] {
        let error = fetch_fixture(10, vec![
            log_request(0, 10, Some(7), json!([first])),
            log_request(0, 10, None, events),
        ], BlockNumberOrTag::Earliest, 7, 9).await.err().unwrap();
        assert!(error.to_string().contains(expected), "{error:#}");
    }
}

#[tokio::test]
async fn rpc_failures_report_the_failed_chunk_without_skipping_it() {
    let mut failure = log_request(50_000, 50_000, Some(0), Value::Null);
    failure["error"] = json!({"code": -32000, "message": "provider unavailable"});
    let error = fetch_fixture(50_000, vec![
        log_request(0, 49_999, Some(0), json!([])), failure,
    ], BlockNumberOrTag::Earliest, 0, 1).await.err().unwrap();
    let error = format!("{error:#}");
    assert!(error.contains("50000..=50000"));
    assert!(error.contains("provider unavailable"));
}
