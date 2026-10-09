# Live-compatible BSC fee policy

Original protection: `d1f0e4fc3b69d9bed90c1e829d4928cc68125bc8`, based on
the deployed RPC pool `db37dce542f10570dfb66b75b222ca76fab29912`.
The cost-aware extension is prepared against maintenance baseline
`6eb535003bdab1fcdb27386dbcb93e8aa9727998`; its fee helper matches the live
protection before this extension. This is not an authorization to deploy the
whole maintenance branch over a component-specific live release.

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

### Cost-aware BSC mode (explicit opt-in)

The October 9 audit found 650 successful transactions costing 0.213767839 tBNB
by 20:21 UTC+8, all at 1 gwei. The live minimum, priority cap and total cap were
all 1 gwei. Local priority quotes were 0.1 gwei; Alchemy quoted 1 gwei while its
positive recent fee-history samples were typically 0.1 gwei. Thus simply lowering
the minimum does not prevent provider failover from raising the price again.

Proposed BSC-only configuration, requiring a separate approved rollout:

```toml
[chains.fee_policy]
expected_chain_id = 97
quote_strategy = "recent_history"
min_priority_fee_wei = 100000000
max_priority_fee_wei = 1000000000
max_fee_per_gas_wei = 1000000000
```

- Use the same ten-block, 20th-percentile history request (no additional RPCs).
  Ignore empty/zero reward rows. With at least three positive rows, take their
  upper median and add 20% headroom, rounded up; do not take the maximum with
  the provider priority quote in this mode. Three rows are a minimum evidence
  threshold, not a guarantee of inclusion; a single outlier cannot lift the median.
- If history has fewer than three positive rows, use a positive priority quote.
  This supports the local node's observed one-row/zero-reward response. If the
  priority quote is also missing/zero, refuse to send rather than invent a quote
  or trust a single low history sample. Alchemy fallback may still cost 1 gwei
  when history is insufficient; safety takes precedence over savings.
- Apply the configured minimum and enforce both caps as before. An over-budget
  history estimate is refused, not replaced with a cheaper provider suggestion
  or clamped to the cap. Base-fee budget and overflow checks remain unchanged.
- At a 0.1 gwei median the bid is 0.12 gwei; with empty local history and a
  0.1 gwei priority quote it is 0.1 gwei. Identical gas usage would cost roughly
  88–90% less than at 1 gwei; actual confirmation latency must be validated.
- Omitted `quote_strategy` defaults to `"conservative"` and preserves old behavior.
  Changing the binary alone or retaining a 1 gwei minimum will not lower fees.
  Unknown strategy names are rejected. Both TOML and standalone JSON accept it.
- Logs include strategy, selected source, positive sample count, configured floor
  and final prices, without RPC credentials.

No checkpoint cadence, automatic fee escalation, replacement transactions or
nonce handling changes are included. Before activation, record latest/pending
nonces and reconcile any pending transaction. Preserve the old binary and TOML;
update the candidate binary and BSC table together, then verify real receipt
prices, confirmation latency and progression of all three chains. If lower bids
stall, do not blindly restart/rebroadcast: preserve the hash/nonce and use a
separately authorized pending-transaction recovery. Binary rollback also requires
restoring the old TOML because old binaries reject the new strategy field.

## Fee preparation

- Check the RPC chain ID and reject a conflicting explicit transaction chain ID.
- Require a latest block with a base fee; a zero base fee is valid, a missing
  field is not silently converted to zero.
- In the default `conservative` mode, read `eth_maxPriorityFeePerGas` and ten-block fee history at percentile 20.
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
