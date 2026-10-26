use std::future::Future;

use alloy_primitives::{Address, B256};
use alloy_provider::Provider;
use alloy_rpc_types_eth::TransactionRequest;
use alloy_sol_types::{sol, SolCall};
use anyhow::{ensure, Context, Result};

sol! {
    function lastFinalizedCheckpointId() external view returns (uint64);
    function lastVerifiedCheckpointRoot() external view returns (bytes32);
    function lastVerifiedDepositTreeRoot() external view returns (bytes32);
    function lastVerifiedWithdrawalTreeRoot() external view returns (bytes32);
}

#[derive(Clone, Copy)]
pub(super) struct FinalizeTarget {
    pub checkpoint: u64,
    pub checkpoint_root: B256,
    pub deposit_root: B256,
    pub withdrawal_root: B256,
}

async fn read_at<P: Provider, C: SolCall>(
    provider: &P,
    state_manager: Address,
    block: u64,
    call: C,
) -> Result<C::Return> {
    let raw = provider
        .call(TransactionRequest::default().to(state_manager).input(call.abi_encode().into()))
        .block(block.into())
        .await
        .with_context(|| format!("finalize preflight: {} eth_call failed", C::SIGNATURE))?;
    C::abi_decode_returns(&raw)
        .with_context(|| format!("finalize preflight: invalid {} response", C::SIGNATURE))
}

pub(super) async fn submit_unless_finalized<P, F, Fut>(
    provider: &P,
    state_manager: Address,
    target: FinalizeTarget,
    submit: F,
) -> Result<()>
where
    P: Provider,
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<()>>,
{
    // The cursor and all three global roots must come from the same block.
    let block = provider.get_block_number().await.context("finalize preflight: block query failed")?;
    let checkpoint = read_at(provider, state_manager, block, lastFinalizedCheckpointIdCall {}).await?;
    ensure!(
        checkpoint <= target.checkpoint,
        "finalize preflight: chain is ahead of target (chain={} target={}); cannot verify historical roots; refusing to resend",
        checkpoint, target.checkpoint
    );
    if checkpoint == target.checkpoint {
        let checkpoint_root = read_at(provider, state_manager, block, lastVerifiedCheckpointRootCall {}).await?;
        let deposit_root = read_at(provider, state_manager, block, lastVerifiedDepositTreeRootCall {}).await?;
        let withdrawal_root = read_at(provider, state_manager, block, lastVerifiedWithdrawalTreeRootCall {}).await?;
        ensure!(
            checkpoint_root == target.checkpoint_root
                && deposit_root == target.deposit_root
                && withdrawal_root == target.withdrawal_root,
            "finalize preflight: finalized target {} has different roots; refusing to resend",
            target.checkpoint
        );
        tracing::info!(
            %state_manager, to_checkpoint = target.checkpoint, l1_block = block,
            "finalize already completed on chain with matching roots; skipping submission"
        );
        return Ok(());
    }
    submit().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_provider::ProviderBuilder;
    use serde_json::{json, Value};
    use std::cell::Cell;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::TcpListener;
    use tokio::time::{timeout, Duration};

    const STATE_MANAGER: Address = Address::repeat_byte(0x53);

    struct PreflightRead {
        selector: Option<Vec<u8>>,
        block: u64,
        response: Value,
    }

    fn target() -> FinalizeTarget {
        FinalizeTarget {
            checkpoint: 26225,
            checkpoint_root: B256::repeat_byte(1),
            deposit_root: B256::repeat_byte(2),
            withdrawal_root: B256::repeat_byte(3),
        }
    }

    fn preflight_reads(block: u64, checkpoint: u64, roots: Option<FinalizeTarget>) -> Vec<PreflightRead> {
        let mut reads = vec![
            PreflightRead { selector: None, block, response: json!({"result": format!("0x{block:x}")}) },
            PreflightRead {
                selector: Some(lastFinalizedCheckpointIdCall {}.abi_encode()), block,
                response: json!({"result": format!("0x{checkpoint:064x}")}),
            },
        ];
        if let Some(roots) = roots {
            for (selector, root) in [
                (lastVerifiedCheckpointRootCall {}.abi_encode(), roots.checkpoint_root),
                (lastVerifiedDepositTreeRootCall {}.abi_encode(), roots.deposit_root),
                (lastVerifiedWithdrawalTreeRootCall {}.abi_encode(), roots.withdrawal_root),
            ] {
                reads.push(PreflightRead { selector: Some(selector), block, response: json!({"result": root}) });
            }
        }
        reads
    }

    async fn run_preflight<F, Fut>(reads: Vec<PreflightRead>, target: FinalizeTarget, submit: F) -> Result<()>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<()>>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let mut server = tokio::spawn(async move {
            for read in reads {
                let (socket, _) = listener.accept().await.unwrap();
                let mut socket = BufReader::new(socket);
                let mut length = 0;
                loop {
                    let mut line = String::new();
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
                if let Some(selector) = read.selector {
                    assert_eq!(actual["method"], "eth_call");
                    assert_eq!(actual["params"].as_array().unwrap().len(), 2);
                    assert_eq!(actual["params"][1], format!("0x{:x}", read.block));
                    let tx = &actual["params"][0];
                    assert_eq!(tx["to"], json!(STATE_MANAGER));
                    let input = tx.get("input").or_else(|| tx.get("data")).unwrap();
                    assert_eq!(input, &json!(format!("0x{}", hex::encode(selector))));
                } else {
                    assert_eq!(actual["method"], "eth_blockNumber");
                }
                let mut response = read.response;
                response["jsonrpc"] = json!("2.0");
                response["id"] = actual["id"].clone();
                let body = response.to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(), body
                );
                socket.get_mut().write_all(response.as_bytes()).await.unwrap();
            }
        });
        let client = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(2)).build().unwrap();
        let provider = ProviderBuilder::new().connect_reqwest(client, url.parse().unwrap());
        let result = timeout(Duration::from_secs(5), submit_unless_finalized(&provider, STATE_MANAGER, target, submit)).await;
        let joined = timeout(Duration::from_secs(2), &mut server).await;
        server.abort();
        joined.expect("preflight must consume every expected read").expect("preflight RPC assertions");
        result.expect("preflight must finish within the deadline")
    }

    #[tokio::test]
    async fn lost_send_response_does_not_resubmit_successful_finalize() {
        let sends = Cell::new(0);
        let first = run_preflight(preflight_reads(42, 26217, None), target(), || async {
            sends.set(sends.get() + 1);
            anyhow::bail!("send response lost after L1 finalized")
        }).await;
        assert!(first.is_err());
        run_preflight(preflight_reads(43, target().checkpoint, Some(target())), target(), || async {
            sends.set(sends.get() + 1);
            anyhow::bail!("must not resend")
        }).await.unwrap();
        assert_eq!(sends.get(), 1);
    }

    #[tokio::test]
    async fn lost_receipt_response_does_not_resubmit_successful_finalize() {
        let sends = Cell::new(0);
        let first = run_preflight(preflight_reads(42, 26217, None), target(), || async {
            sends.set(sends.get() + 1);
            anyhow::bail!("wait finalize receipt timed out")
        }).await;
        assert!(first.is_err());
        run_preflight(preflight_reads(44, target().checkpoint, Some(target())), target(), || async {
            sends.set(sends.get() + 1);
            anyhow::bail!("must not resend")
        }).await.unwrap();
        assert_eq!(sends.get(), 1);
    }

    #[tokio::test]
    async fn genuinely_failed_submission_can_retry() {
        let sends = Cell::new(0);
        for attempt in 0..2 {
            let result = run_preflight(preflight_reads(42 + attempt, 26217, None), target(), || async {
                sends.set(sends.get() + 1);
                ensure!(attempt == 1, "first send failed before broadcast");
                Ok(())
            }).await;
            assert_eq!(result.is_ok(), attempt == 1);
        }
        assert_eq!(sends.get(), 2);
    }

    #[tokio::test]
    async fn any_root_mismatch_or_ahead_cursor_refuses_submission() {
        for mismatch in 0..4 {
            let mut actual = target();
            match mismatch {
                0 => actual.checkpoint_root = B256::ZERO,
                1 => actual.deposit_root = B256::ZERO,
                2 => actual.withdrawal_root = B256::ZERO,
                _ => actual.checkpoint += 1,
            }
            let reads = preflight_reads(42, actual.checkpoint, (mismatch != 3).then_some(actual));
            assert!(run_preflight(reads, target(), || async {
                panic!("must not send on conflicting state")
            }).await.is_err());
        }
    }

    #[tokio::test]
    async fn every_query_failure_and_malformed_return_refuses_submission() {
        for malformed in [false, true] {
            for failed_query in 0..5 {
                let mut reads = preflight_reads(42, target().checkpoint, Some(target()));
                reads.truncate(failed_query + 1);
                reads[failed_query].response = if malformed {
                    json!({"result": if failed_query == 0 { "not valid hex" } else { "0x" }})
                } else {
                    json!({"error": {"code": -32000, "message": "RPC unavailable"}})
                };
                assert!(run_preflight(reads, target(), || async {
                    panic!("must not send when state is unknown")
                }).await.is_err(), "query {failed_query}, malformed={malformed}");
            }
        }
    }

    #[tokio::test]
    async fn matching_global_roots_are_read_at_one_block_without_sending() {
        for withdrawal_root in [target().withdrawal_root, B256::ZERO] {
            let target = FinalizeTarget { withdrawal_root, ..target() };
            run_preflight(preflight_reads(0x1234, target.checkpoint, Some(target)), target, || async {
                panic!("matching global roots must skip the send")
            }).await.unwrap();
        }
    }
}
