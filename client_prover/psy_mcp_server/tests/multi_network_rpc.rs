//! Two network configs in one process must route RPC traffic to different
//! coordinator endpoints, including when both requests are in flight together.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use psy_config::PsyConfigGoldilocks;
use psy_provider::provider::RpcProvider;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn checkpoint_endpoint(checkpoint_id: u64) -> std::io::Result<(String, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_in_task = Arc::clone(&calls);
    tokio::spawn(async move {
        // The provider first pins the committed checkpoint, then fetches its
        // state. Both requests must stay on this network's coordinator.
        for step in 0..2 {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.unwrap();
                assert!(read > 0, "connection closed before the HTTP request completed");
                bytes.extend_from_slice(&chunk[..read]);
                if let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&bytes[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::trim)
                                .map(str::to_string)
                        })
                        .and_then(|value| value.parse::<usize>().ok())
                        .unwrap_or(0);
                    if bytes.len() >= header_end + 4 + content_length {
                        break;
                    }
                }
            }
            let body_start = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let request: serde_json::Value = serde_json::from_slice(&bytes[body_start..]).unwrap();
            let result = if step == 0 {
                assert_eq!(request["method"], "psy_get_latest_checkpoint_id");
                serde_json::json!(checkpoint_id)
            } else {
                assert_eq!(request["method"], "psy_get_l2_block_state");
                assert_eq!(request["params"]["checkpoint_id"], checkpoint_id);
                serde_json::json!({
                    "checkpoint_id": checkpoint_id,
                    "next_add_withdrawal_id": 0,
                    "next_process_withdrawal_id": 0,
                    "next_deposit_id": 0,
                    "total_deposits_claimed_epoch": 0,
                    "next_user_id": 0,
                    "end_balance": 0,
                    "next_contract_id": 0
                })
            };
            calls_in_task.fetch_add(1, Ordering::SeqCst);

            let body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": request["id"],
                "result": result
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
    });
    Ok((format!("http://{address}"), calls))
}

#[tokio::test]
async fn concurrent_network_requests_reach_only_their_own_coordinator() {
    let (url_a, calls_a) = match checkpoint_endpoint(101).await {
        Ok(endpoint) => endpoint,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping loopback RPC test: sandbox denied TcpListener");
            return;
        }
        Err(e) => panic!("failed to start network-a mock endpoint: {e}"),
    };
    let (url_b, calls_b) = match checkpoint_endpoint(202).await {
        Ok(endpoint) => endpoint,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping loopback RPC test: sandbox denied TcpListener");
            return;
        }
        Err(e) => panic!("failed to start network-b mock endpoint: {e}"),
    };

    let config_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../psy-genesis/config.json");
    let config = PsyConfigGoldilocks::from_file(config_path.to_str().unwrap()).unwrap();
    let mut network_a = config.get_current_network().unwrap().clone();
    let mut network_b = network_a.clone();
    network_a.coordinator_configs[0].rpc_url = vec![url_a];
    network_b.coordinator_configs[0].rpc_url = vec![url_b];

    let provider_a = RpcProvider::new_with_config(&network_a).unwrap();
    let provider_b = RpcProvider::new_with_config(&network_b).unwrap();
    let (state_a, state_b) = tokio::join!(
        provider_a.get_coordinator_latest_block_state(),
        provider_b.get_coordinator_latest_block_state(),
    );

    assert_eq!(state_a.unwrap().checkpoint_id, 101);
    assert_eq!(state_b.unwrap().checkpoint_id, 202);
    assert_eq!(calls_a.load(Ordering::SeqCst), 2);
    assert_eq!(calls_b.load(Ordering::SeqCst), 2);
}
