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
    address: Address,
    block: u64,
    call: C,
) -> Result<C::Return> {
    let raw = provider
        .call(TransactionRequest::default().to(address).input(call.abi_encode().into()))
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
    // Every attempt, including a retry after a lost send/receipt response, reads
    // one block's state. Never combine a new cursor with roots from another block.
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
    use alloy_transport::mock::Asserter;
    use std::cell::Cell;

    fn target() -> FinalizeTarget {
        FinalizeTarget {
            checkpoint: 26225,
            checkpoint_root: B256::repeat_byte(1),
            deposit_root: B256::repeat_byte(2),
            withdrawal_root: B256::repeat_byte(3),
        }
    }

    fn cursor(asserter: &Asserter, checkpoint: u64) {
        asserter.push_success(&"0x2cf79fe");
        asserter.push_success(&format!("0x{checkpoint:064x}"));
    }

    fn roots(asserter: &Asserter, target: FinalizeTarget) {
        asserter.push_success(&target.checkpoint_root);
        asserter.push_success(&target.deposit_root);
        asserter.push_success(&target.withdrawal_root);
    }

    #[tokio::test]
    async fn lost_send_response_does_not_resubmit_successful_finalize() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let submissions = Cell::new(0);
        cursor(&asserter, 26217);
        let first = submit_unless_finalized(&provider, Address::ZERO, target(), || async {
            submissions.set(submissions.get() + 1);
            // L1 applied the transaction, but its response did not reach the sender.
            anyhow::bail!("send finalize transaction failed: operation timed out")
        }).await;
        assert!(first.is_err());
        cursor(&asserter, target().checkpoint);
        roots(&asserter, target());
        submit_unless_finalized(&provider, Address::ZERO, target(), || async {
            submissions.set(submissions.get() + 1);
            anyhow::bail!("must not resend")
        }).await.unwrap();
        assert_eq!(submissions.get(), 1);
        assert!(asserter.read_q().is_empty());
    }

    #[tokio::test]
    async fn genuinely_failed_submission_can_retry() {
        let asserter = Asserter::new();
        let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
        let submissions = Cell::new(0);
        for attempt in 0..2 {
            cursor(&asserter, 26217);
            let result = submit_unless_finalized(&provider, Address::ZERO, target(), || async {
                submissions.set(submissions.get() + 1);
                ensure!(attempt == 1, "first submission failed before broadcast");
                Ok(())
            }).await;
            assert_eq!(result.is_ok(), attempt == 1);
        }
        assert_eq!(submissions.get(), 2);
    }

    #[tokio::test]
    async fn any_root_mismatch_or_ahead_cursor_refuses_submission() {
        for mismatch in 0..4 {
            let asserter = Asserter::new();
            let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
            cursor(&asserter, target().checkpoint + u64::from(mismatch == 3));
            if mismatch != 3 {
                let mut actual = target();
                match mismatch {
                    0 => actual.checkpoint_root = B256::ZERO,
                    1 => actual.deposit_root = B256::ZERO,
                    _ => actual.withdrawal_root = B256::ZERO,
                }
                roots(&asserter, actual);
            }
            let result = submit_unless_finalized(&provider, Address::ZERO, target(), || async {
                panic!("must not submit on conflicting state")
            }).await;
            assert!(result.is_err());
            assert!(asserter.read_q().is_empty());
        }
    }

    #[tokio::test]
    async fn every_query_failure_and_malformed_return_refuses_submission() {
        for malformed in [false, true] {
            for failed_query in 0..5 {
                let asserter = Asserter::new();
                let provider = ProviderBuilder::new().connect_mocked_client(asserter.clone());
                let responses = [
                    "0x2cf79fe".to_string(), format!("0x{:064x}", target().checkpoint),
                    target().checkpoint_root.to_string(), target().deposit_root.to_string(),
                    target().withdrawal_root.to_string(),
                ];
                for response in &responses[..failed_query] {
                    asserter.push_success(response);
                }
                if malformed {
                    asserter.push_success(&"not valid hex");
                } else {
                    asserter.push_failure_msg("RPC unavailable");
                }
                let result = submit_unless_finalized(&provider, Address::ZERO, target(), || async {
                    panic!("must not submit when state is unknown")
                }).await;
                assert!(result.is_err(), "query {failed_query}, malformed={malformed}");
            }
        }
    }
}
