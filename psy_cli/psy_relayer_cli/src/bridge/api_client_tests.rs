use super::*;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

// Inspect the actual HTTP query, rather than testing a duplicate URL builder.
async fn fetch_fixture(
    chain: u64,
    count: DepositTreeRootCount,
    expected_query: &[(&str, &str)],
    response: Value,
) -> anyhow::Result<DepositTreeRootState> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let expected_query: Vec<(String, String)> = expected_query.iter()
        .map(|(key, value)| (key.to_string(), value.to_string())).collect();
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut socket = BufReader::new(socket);
        let mut request = String::new();
        socket.read_line(&mut request).await.unwrap();
        let path = request.split_whitespace().nth(1).unwrap();
        let request_url = reqwest::Url::parse(&format!("http://localhost{path}")).unwrap();
        assert_eq!(request_url.path(), "/api/v1/bridge/deposit-tree-root");
        assert_eq!(request_url.query_pairs().into_owned().collect::<Vec<_>>(), expected_query);
        loop {
            let mut line = String::new();
            assert!(socket.read_line(&mut line).await.unwrap() > 0);
            if line == "\r\n" { break; }
        }
        let body = response.to_string();
        socket.get_mut().write_all(format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        ).as_bytes()).await.unwrap();
    });
    let client = reqwest::Client::builder().no_proxy()
        .timeout(Duration::from_secs(5)).build().unwrap();
    let result = fetch_services_deposit_tree_root(&client, &url, chain, count).await;
    let mut server = server;
    let joined = tokio::time::timeout(Duration::from_secs(2), &mut server).await;
    server.abort();
    joined.expect("mock did not complete").expect("mock request assertion failed");
    result
}

fn snapshot_response(chain: u64, count: u64) -> Value {
    json!({"success": true, "data": {
        "found": true, "source_chain_index": chain,
        "snapshot_deposit_count": count, "tree_count": count,
        "indexed_deposit_count": count + 72,
        "deposit_root": "0000000100000002000000030000000400000005000000060000000700000008",
    }})
}

#[tokio::test]
async fn exact_snapshots_use_per_chain_parameter_on_all_three_chains() {
    for (chain, pending) in [(0, 91327), (1, 743), (2, 45137)] {
        let chain_string = chain.to_string();
        let count_string = pending.to_string();
        let result = fetch_fixture(chain, DepositTreeRootCount::ChainSnapshot(pending), &[
            ("source_chain_index", &chain_string), ("snapshot_deposit_count", &count_string),
        ], snapshot_response(chain, pending)).await.unwrap();
        assert_eq!(result.snapshot_deposit_count(), Some(pending));
        assert!(result.deposit_root.is_some());
    }
}

#[tokio::test]
async fn legacy_global_target_keeps_its_parameter_and_allows_a_smaller_chain_snapshot() {
    // The production reproduction: the global prefix contains 91326 chain-0
    // deposits. That response is valid only for a global-target request.
    let mut response = snapshot_response(0, 91326);
    response["data"]["target_deposit_count"] = json!(91327);
    let result = fetch_fixture(0, DepositTreeRootCount::GlobalTarget(91327), &[
        ("source_chain_index", "0"), ("target_deposit_count", "91327"),
    ], response).await.unwrap();
    assert_eq!(result.snapshot_deposit_count(), Some(91326));
}

#[tokio::test]
async fn exact_snapshot_rejects_the_reproduced_count_mismatch() {
    let error = fetch_fixture(0, DepositTreeRootCount::ChainSnapshot(91327), &[
        ("source_chain_index", "0"), ("snapshot_deposit_count", "91327"),
    ], snapshot_response(0, 91326)).await.unwrap_err();
    assert!(error.to_string().contains("requested 91327 returned 91326"));
}

#[tokio::test]
async fn exact_snapshot_rejects_wrong_or_missing_chain_identity() {
    for returned_chain in [json!(1), Value::Null] {
        let mut response = snapshot_response(0, 91327);
        response["data"]["source_chain_index"] = returned_chain;
        let error = fetch_fixture(0, DepositTreeRootCount::ChainSnapshot(91327), &[
            ("source_chain_index", "0"), ("snapshot_deposit_count", "91327"),
        ], response).await.unwrap_err();
        assert!(error.to_string().contains("deposit snapshot chain mismatch"));
    }
}

#[tokio::test]
async fn exact_snapshot_does_not_accept_an_echoed_global_target_as_a_count() {
    let mut response = snapshot_response(0, 91327);
    response["data"]["snapshot_deposit_count"] = Value::Null;
    response["data"]["tree_count"] = Value::Null;
    response["data"]["target_deposit_count"] = json!(91327);
    let error = fetch_fixture(0, DepositTreeRootCount::ChainSnapshot(91327), &[
        ("source_chain_index", "0"), ("snapshot_deposit_count", "91327"),
    ], response).await.unwrap_err();
    assert!(error.to_string().contains("missing per-chain count"));
}

#[tokio::test]
async fn exact_snapshot_rejects_not_found_and_services_failure() {
    for (response, message) in [
        (json!({"success": true, "data": {
            "found": false, "reason": "indexer_not_ready", "source_chain_index": 0,
        }}), "indexer_not_ready"),
        (json!({"success": false, "error": "upstream unavailable"}), "upstream unavailable"),
        (json!({"success": true}), "response missing data"),
    ] {
        let error = fetch_fixture(0, DepositTreeRootCount::ChainSnapshot(91327), &[
            ("source_chain_index", "0"), ("snapshot_deposit_count", "91327"),
        ], response).await.unwrap_err();
        assert!(error.to_string().contains(message), "{error}");
    }
}
