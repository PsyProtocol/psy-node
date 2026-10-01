# Finalize retry state check

## Scope

Relayer-only fix based on deployed runtime
`32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`. No contract, circuit, Genesis,
SDK, configuration, or deployment changes are required by this source change.

A transaction may succeed on L1 even when sending it or waiting for its
receipt reports a timeout. Previously, `L1Client::finalize` retried the same
proof without checking whether StateManager had already applied it.

## Behavior

Every `finalize_bridge::run` attempt now checks StateManager before submitting:

- Select an L1 block number and pin all preflight calls to that number.
- If the finalized checkpoint is below the target, use the existing send and
  receipt path.
- If it equals the target, compare checkpoint, deposit, and withdrawal roots
  with the proof. All three must match to return success without sending.
- If it exceeds the target, or roots conflict, return an error without sending.
  This patch does not infer historical success from height alone.
- RPC and decoding errors also return without sending.

The existing maximum of 10 attempts per configured RPC endpoint and backoff
remain unchanged. Successful preflight reconciliation exits that retry loop
normally, so the daemon can advance its existing finalization bookkeeping.

Expected reconciliation log:

```text
finalize already completed on chain with matching roots; skipping submission
```

## Validation

```bash
PSY_NETWORK=testnet cargo test --offline -p psy_relayer_cli finalize_preflight
PSY_NETWORK=testnet cargo test --offline -p psy_relayer_cli -- --test-threads=4
```

The full relayer test binary passed 162 tests locally. The new tests cover a
lost response after L1 success (one submission across two attempts), a genuine
failure followed by retry, each root mismatch, an ahead cursor, and RPC failure
or malformed responses at every preflight query. Existing HTTP mock tests need
permission to listen on ephemeral loopback ports. No live transactions were
sent and no online services were changed during validation.

## Limits

This is not pending-transaction management. An unmined transaction, a stale
RPC endpoint, or a transaction mined between the check and the next send can
still lead to another submission attempt. Existing contract continuity checks
remain in force. Conflicting or ahead state remains an error under the existing
retry policy; no historical event scan is added. This does not change L1 reorg
handling or confirmation policy.
