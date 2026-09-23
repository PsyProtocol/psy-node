# Relayer RPC primary / backup policy

## Scope

This change applies to relayer L1 JSON-RPC requests, not Psy RPC, Envio,
psy-services or prove-proxy HTTP calls. Each configured chain owns one client
and one shared cooldown across providers, receipt polling and daemon rounds.
It is based on the finalize state-reconciliation fix (93dc14ad).
No contract, Genesis or circuit changes are needed. No live deployment is
part of the implementation tests.

## Request lifecycle

1. Use the primary while healthy.
2. On a transport, malformed-response or recognized provider availability
   error, log WARN and record a 300-second primary cooldown.
3. Retry the same replay-safe JSON-RPC packet on the backup once.
4. During cooldown, send subsequent requests directly to the backup.
5. The first request after cooldown probes the primary. Success restores it;
   another endpoint failure starts a new cooldown and uses the backup.
6. Backup failure returns an error immediately. It does not extend cooldown,
   retry ten times, sleep for five minutes or restart the business operation.

There is no background recovery timer. The five minutes are monotonic time
from detecting primary failure, not from completing the backup request.
Without a distinct backup, a failed primary request returns immediately.
Existing business-level round scheduling and receipt polling remain separate
from endpoint failover. An unmined receipt (`result: null`) is not a failed RPC.

Recognized contract reverts and ordinary invalid parameters remain business
errors. HTTP-200 quota/rate-limit errors still trigger failover. Endpoint
classification is deliberately narrower than retrying every `anyhow::Error`.
New transition logs omit endpoint URLs, provider messages and request params.

## Transaction safety

Read-only requests use an explicit replay allowlist. `eth_sendRawTransaction`
may resend exactly the same signed bytes, with the same nonce and hash. The
transport never invokes a signer or nonce filler again. Node-signed
`eth_sendTransaction`, filter creation and unknown methods are not replayed
after ambiguous primary failure. They still update primary health.

A receipt fetch failure retries the receipt fetch only. A proof, L2 call plan,
withdrawal workflow or finalize operation is invoked once, not replayed as
an RPC retry. A primary may accept a signed transaction before its response
is lost; backup `already known` is returned as an error, not interpreted as
settlement. Existing finalize state reconciliation remains necessary on the
next daemon round. This is not persistent in-flight transaction management.

## Implementation boundaries

- `rpc_failover.rs`: Alloy packet transport, shared cooldown, classification.
- `l1_provider.rs`: HTTP timeouts (5s connect, 15s total), provider factories.
- `l1_client.rs`: one-shot operation scope, never an outer retry loop.

The operation scope supplies the shared client to provider constructors via
Tokio task-local storage. Construct providers inside that scope; providers
then retain the shared client across scope exit or spawned background tasks.
Task-local scope itself is not inherited by newly spawned tasks. Future code
must pass an already constructed provider to those tasks, or explicitly
establish the scope before construction. A mismatched URL fails closed.

One mutex serializes each chain's individual requests, including recovery
probes. It is not held over entire workflows, proof generation or polling
sleeps. HTTP timeouts bound active requests, not time waiting for this mutex.
Other chains have independent locks. Request cancellation releases the lock.

The old Alloy RetryBackoffLayer is removed; it would otherwise wrap typed
errors even with zero retries. `L1_HTTP_CU_PER_SEC` no longer applies here;
it previously controlled retry backoff, not a strict request-rate limiter.
Local HTTP endpoints retain Alloy's local receipt polling cadence.

## Configuration and rollout prerequisites

Existing primary/fallback URL configuration is reused. Multi-chain
`rpc_urls[0]` is primary and `rpc_urls[1]` is backup. Use endpoints for the
same L1 chain, preferably from independent providers. This patch does not
configure subscriptions or change running services.

Before deployment, ensure config generators preserve URL order: `jq unique`
sorts strings and can swap primary and backup. Replace that in the deployment
branch with order-preserving deduplication. Validate chain ID and required
RPC capabilities on both endpoints, including `eth_getLogs` range limits.
Provider limits, stale data, reorgs and both endpoints failing are not solved
by failover. A failed chain can still delay a shared multi-chain round.

## Validation

```bash
PSY_NETWORK=testnet cargo test --offline -p psy_relayer_cli -- --test-threads=4
```

Tests cover cooldown boundaries, recovery, concurrent probes, chain isolation,
typed errors, cancellation, signed packet identity and receipt-query failover.
Loopback HTTP tests exercise the full provider stack for HTTP 503, HTTP-200
quota errors and reverts, scope exit, spawned providers and local polling.
No funded wallets, online transactions or production RPCs are used.

Local result on 2026-09-23: 187 passed, 0 failed (162 existing tests plus
25 new tests). This is unit/loopback integration validation, not a live
three-chain transaction E2E or proof of any provider subscription's limits.
