# Live-compatible BSC fee policy

Candidate base: `db37dce542f10570dfb66b75b222ca76fab29912` (the deployed
Relayer RPC pool source). This selectively ports the fee policy from the
uncommitted `psy-node-relayer-bsc-fee-20261006` candidate. It is not a merge of
that candidate or a new network release.

## Scope

One opt-in helper prepares fees for deposit `aggregate3`, bridge finalization,
and withdrawal claims before Alloy fills gas/nonce and signs. The live RPC pool,
provider order, endpoint failover, signing, calldata, and contract addresses are
preserved. No circuit, Genesis, dependency pin, or persisted schema changes.

The observed incident involved a BSC type-2 transaction with both fee fields
equal to 1 wei. Alloy's default estimator can produce this result from a zero
base fee and empty/zero reward history. The configured minimum prevents that
result when this policy is enabled. This patch does not recover that pending
transaction, replace its nonce, or authorize any live transaction.

## Configuration

Old configs load unchanged. **Installing the binary alone does not enable the
policy.** Add this table to the BSC `[[chains]]` entry, before the next chain:

```toml
[chains.fee_policy]
expected_chain_id = 97
min_priority_fee_wei = 1000000000
max_priority_fee_wei = 2000000000
max_fee_per_gas_wei = 10000000000
```

These are example values in wei, not an approved live gas budget. The 1 gwei
minimum must be checked against current BSC acceptance and the operator's budget;
caps are per gas, not total transaction expenditure. Do not copy the policy to
Sepolia or Base. Named `rpc_providers` and legacy `rpc_urls` both remain supported.

Daemon policies are restricted to `network_id = "bscTestnet"`, matching
`deployments_network`, and EVM chain ID 97. With `[[chains]]`, a global
`[finalize.fee_policy]` is rejected rather than inherited. Single-chain configs
can use `[finalize.fee_policy]`. Standalone finalize/withdrawal commands accept
`--l1-fee-policy` as JSON with the same fields. Unknown policy fields, zero
minimum, inverted caps, and an expected chain ID other than 97 are rejected.

## Fee preparation

- Check the RPC chain ID and reject a conflicting explicit transaction chain ID.
- Require a latest block with a base fee; a zero base fee is valid, a missing
  field is not silently converted to zero.
- Read `eth_maxPriorityFeePerGas` and ten-block fee history at percentile 20.
  Take the greater positive suggestion/median positive reward, then apply the
  configured minimum. Empty, zero, or failed history can use a positive priority
  suggestion; failed priority can use positive history. Without either, refuse.
- Compute `maxFeePerGas = 2 * baseFee + priorityFee` with checked arithmetic.
  Exceeding either cap refuses the send; never clamp a quote down to the cap.
- Fill both type-2 fee fields. Explicit fees must be supplied together and satisfy
  current bounds; conflicting legacy gas price or transaction type is rejected.
- Each source RPC is bounded by 35 seconds and preparation by 70 seconds. This
  permits the existing pool's 15-second attempts / 30-second total RPC deadline
  to finish failover. The old candidate's 4-second source timeout is not copied.
- Absent policy is a strict no-op, with no extra fee RPCs or transaction changes.

Deposit and withdrawal paths probe before proof work and refresh fees before
each send. Pre-broadcast withdrawal fee failures are deferrals, not failed claim
attempts; earlier successful chunks stay in the report. Standalone withdrawal
execution reports an error if the enabled policy leaves claims deferred.

## Durable deposit deferral and remaining limits

After a confirmed round's landing endpoint is selected, save its pending range
and claims before any L1 deposit synchronization. Both fresh and resumed ranges
then synchronize every unfinished chain at that saved endpoint before proof or
finalization. Chains already finalized through that endpoint need no append.
The append helper rechecks the L1 proved count and does not send if already done.
Fee refusals defer the round without spending claim attempts; other errors retain
the saved ledger and propagate. A state-save failure blocks deposit dispatch.
This selectively includes the old candidate's durable ordering, without changing
the state schema or restoring operation-level RPC retries.

This does not close the earlier crash window between L2 submission and saving
its confirmed endpoint, nor the append-only/no-confirmed-range path. Existing
orphan claims still require event/leaf/nullifier reconciliation before restart.
The deposit receipt wait also remains unbounded, unlike finalize/withdrawal
receipt waits. Do not claim this fee patch
fixes general settlement recovery, all pending transactions, or every future
stall. Runtime RPC failover executes each business callback once; this patch does
not restore the old operation-level retry loop.

Before rollout, reconcile the incident transaction and chain state separately,
review these residuals, preserve the old binary/config/state, and approve the
exact per-chain policy. No config generation, restart, replacement transaction,
or deployment is included. Existing submission logs use INFO; a WARN-only log
filter does not retain their transaction details.

## Local verification

Use the pinned baseline Genesis submodule and the existing test target cache:

```bash
PSY_NETWORK=testnet cargo +nightly-2025-09-20 test --offline --locked -p psy_relayer_cli l1_fees -- --test-threads=4
PSY_NETWORK=testnet cargo +nightly-2025-09-20 test --offline --locked -p psy_relayer_cli -p psy_rpc_pool -- --test-threads=4
```

Fee fixtures bind loopback only and forbid all broadcast methods. They exercise
Alloy signing without sending, zero-history/1-wei regressions, explicit bounds,
wrong-chain rejection, no-policy behavior, named-pool isolation, RPC failover,
timeouts, and claim deferral. Fault injection covers save-before-deposit,
fee refusal with restart, resumed deposit synchronization, state-save failure,
and preservation on non-fee RPC errors. They are not live acceptance or funded
E2E tests.
