# Relayer L1 RPC provider pool

## Scope

This applies to relayer L1 JSON-RPC requests only, not Psy RPC, Envio,
psy-services or prove-proxy HTTP calls. Each configured L1 chain owns one
`ProviderPool` (crate `psy_rpc_pool`), shared across clones and daemon rounds.
Chains never share health state. It replaces the earlier per-request
primary/backup cooldown policy.

Full design: `psy-memory/rpc_provider_pool/design.md`. That document is the
source of truth for scoring, quarantine and selection; this page covers
configuration, log lines and known risks for this delivery.

## Configuration

Per EVM chain in the multichain daemon config:

```toml
[[chains.rpc_providers]]
name = "alchemy"
url = "https://..."
priority_weight = 11   # optional, default 10
```

- `rpc_providers` takes precedence when present on a chain.
- The existing `rpc_urls = [...]` stays valid: each URL becomes a provider
  with weight 10 and a generated name (`<chain>-rpc-<index>`), so declaration
  order is the priority.
- Duplicate URLs are dropped, keeping the first occurrence. The check is a
  plain string comparison on the trimmed URL, not a normalized comparison.

A single-chain config may also set `[finalize] l1_rpc_providers`, the same
`{ name, url, priority_weight }` table shape as `[[chains.rpc_providers]]`.
It takes the same precedence over `l1_rpc_url`/`l1_rpc_fallback_url`. In any
provider entry, `name` is optional: when blank it is generated as
`<label>-rpc-<n>` (`<chain>-rpc-<index>` for `chains.rpc_providers`, the
finalize label for `finalize.l1_rpc_providers`).

### Legacy mapping

The single-chain `l1_rpc_url` / `l1_rpc_fallback_url` fields map to a
two-provider list in that order: `l1_rpc_url` (or the default L1 RPC URL)
first, then `l1_rpc_fallback_url` when present. Both become weight-10
providers with generated names.

## v1 parameters

| Parameter | Value |
|---|---|
| Penalty: Timeout | 30 |
| Penalty: InvalidResponse | 30 |
| Penalty: Transport | 25 |
| Penalty: RateLimited | 20 |
| Penalty: Server | 15 |
| Penalty: Success / Application | 0 |
| Penalty half-life | 60s |
| Selection tolerance | 2 (health points) |
| Quarantine after | 5 consecutive failures |
| Quarantine duration | 30 minutes |
| Attempt timeout | 15s |
| Total request timeout | 30s |
| Max attempts | 3 (capped at provider count) |
| Latency EWMA alpha | 0.2 (observational only; does not affect health) |

These are tunable v1 guesses. Adjust from observed production logs.

## Logs to watch

- `RPC provider attempt failed` (WARN) — fields: `pool` (chain name),
  `provider`, `outcome`, `method`, `failover` (whether another attempt will
  run). Emitted on every failed attempt.
- `RPC provider quarantined` (INFO, field `minutes`) — a provider entered or
  renewed quarantine: 5 consecutive failures triggered it, a failed
  post-quarantine probe renewed it, or a least-bad fallback attempt failed on
  a provider that was already quarantined. The provider stops receiving
  normal traffic for `minutes` (30 by default).
- `RPC provider restored` (INFO) — a quarantined provider succeeded and its
  quarantine was lifted: either a post-quarantine probe succeeded, or a
  least-bad fallback attempt succeeded on a still-quarantined provider.

**Operator note:** a pool where every provider is quarantined keeps serving
traffic through the least-bad provider (the selection fallback picks the
best-scoring provider even when none is technically "available"), so
`RPC provider quarantined` log lines alone do not mean the chain is down.
Every failed attempt logs `RPC provider attempt failed` (WARN), including
the final attempt in a request (`failover=false` on that one) — a WARN by
itself is not necessarily an operator-actionable event.

Logs and errors returned to callers never contain provider URLs, request
parameters or provider response bodies. Provider URLs can embed API keys.
`PoolTransport` redacts errors before they leave the pool: reqwest errors are
stripped `without_url`, `HttpError` bodies are cleared (status kept),
`DeserError` response text is cleared (parse error kept). JSON-RPC error
responses (`ErrorResp`, including revert data) are left untouched — callers
need that data and it never contains a URL.

## Behavior notes

- `ProviderPool::new` returns `Result<Self, PoolBuildError>`: an empty
  provider list or a duplicate provider name is rejected at construction,
  not at call time.
- After a provider's quarantine expires, only one probe attempt is in flight
  at a time. Concurrent requests during that window treat the provider as
  unavailable and go to another provider; they do not each send their own
  probe. If the probing attempt is cancelled before it completes, its slot
  is released so a later request can probe again.
- The pool's HTTP client has a 20s total timeout, above the pool's 15s
  per-attempt timeout, so a hung connection is classified as `Timeout` by the
  pool rather than surfacing as a raw reqwest error.
- **Local polling:** `build_pool_client` treats the pooled transport as
  local (250ms poll interval) only when every configured provider URL passes
  alloy's `guess_local` check. One remote provider in the list switches the
  whole pool to the non-local polling cadence.

## Implementation boundaries / rollout prerequisites

- Pooled L1 providers only exist inside `L1Client::with_rpc_failover`'s
  task-local scope (`l1_provider.rs`'s `L1_RPC_CONTEXT`). `L1Client` builds
  the pool once, in `L1Client::from_finalize_config`, and each business
  operation re-enters the scope through `with_rpc_failover`. A newly spawned
  task does **not** inherit that scope. Provider construction outside it
  (`connect_l1_readonly` / `connect_l1_with_wallet` called with no scope on
  the stack) silently falls back to `build_rpc_client`, a standalone
  single-URL client with no pooling, scoring or failover. Known pre-existing
  standalone paths in this codebase, unaffected by this delivery:
  - the `finalize-bridge-agg` CLI subcommand (`finalize_bridge::run` takes a
    single `l1_rpc_url: String` argument, not a provider list)
  - the `claim-withdrawals` CLI subcommand (`claim_withdrawals::run`, same
    single-URL shape)
  - the indexer source mode in `main.rs` (`ProviderBuilder::new()
    .connect_http(rpc_url)`, built from one configured chain RPC URL)
- Before rollout, verify per configured provider — not just the pool as a
  whole: chain ID matches the deployment, contract reads succeed, receipt
  lookup works, raw transaction submission (`eth_sendRawTransaction`) is
  supported, and `eth_getLogs` range limits accommodate the relayer's
  requests (it can request up to 50,000 blocks in one call). There is no
  per-provider chain ID check at startup: alloy's `ChainIdFiller` (part of
  the default filler stack in `connect_l1_readonly` /
  `connect_l1_with_wallet`) queries whichever provider the pool currently
  routes the request to, since a fresh provider is built per RPC operation.

## Safety boundaries (unchanged)

- The relayer invokes each business callback once; a lost RPC response never
  replays proof generation, an L2 action or a finalize operation.
- `eth_sendRawTransaction` may resend exactly the same signed bytes, with the
  same nonce and hash. The transport never invokes a signer or nonce filler
  again.
- Node-signed `eth_sendTransaction`, filter creation and unknown methods are
  `NoRetry`: not replayed after an ambiguous failure. They still update
  provider health.
- Reverts and ordinary invalid parameters remain business errors
  (`Application`), not endpoint failures: no failover, no penalty.
- HTTP-200 quota/rate-limit errors and recognized provider-unavailability
  responses still trigger failover.
- Existing finalize state reconciliation (parent commit `93dc14ad`) remains
  the reconciliation path after a lost `eth_sendRawTransaction` response
  followed by `already known`.

## Known risks

- **Provider divergence:** L1 providers can be at different heights. A
  failover to a lagging provider can return an older `eth_blockNumber` or
  miss recent logs. Not solved here; the relayer's existing confirmation
  depth is the only guard.
- **Lost `eth_sendRawTransaction` response:** a resend may return
  `already known`. That is classified as `Application` and returned to the
  caller, not treated as settlement confirmation.
- **Shared rounds:** the daemon's multichain round is still shared. A slow
  chain can still delay others, bounded by the pool's 30s total timeout per
  RPC.
- **Tuning:** penalties, half-life, thresholds and timeouts are v1 guesses
  and have not been validated against production traffic.
- **Split receipt view:** alloy's `get_receipt()` can see the block that
  mined a transaction from one provider, then poll a lagging provider on the
  next call and get a null receipt — reported as a receipt failure even
  though the transaction is mined.
- **Resend can surface `nonce too low`, not just `already known`:** on fast
  chains, resending `eth_sendRawTransaction` after a lost response can come
  back `nonce too low` (classified `Application`), not only `already known`.
- **Nonce read from whichever provider is current:** the nonce manager
  (alloy's `NonceFiller`, part of `connect_l1_with_wallet`'s default
  fillers) fetches the pending nonce per provider instance, and that
  instance is built fresh per operation — so the pending-nonce read can come
  from a lagging provider, risking `nonce too low` or a transaction that
  never mines. `finalize` and `claim_withdrawals` wrap `get_receipt()` in a
  180s timeout (`L1_TX_RECEIPT_TIMEOUT_SECS`); the deposit batchAppend
  send/receipt path (`daemon.rs` ~1627-1631) has no timeout on either
  `send_transaction` or `get_receipt` — pre-existing, recommended fix before
  rollout.

## Known follow-ups (not fixed in this delivery)

- Some pre-existing error strings still interpolate the configured URL
  outside the pool transport: `invalid L1 rpc url: {url}` (or `{owned}`) in
  `l1_client.rs` (3 call sites), `daemon.rs` (2 call sites), and one call
  site each in `finalize_bridge.rs`, `claim_withdrawals.rs` and
  `prove_bridge.rs`. These are URL-parse errors raised at call time inside
  per-request operation closures (re-parsing an already-scoped URL string on
  every invocation), not config-validation errors checked once at startup.
  They are unchanged by this delivery.
- The duplicate-URL check in provider resolution is a textual comparison on
  the trimmed URL string, not a normalized one (e.g. trailing slash or
  scheme case differences are not deduplicated).
- A request that is cut short by the pool's total-timeout deadline mid
  attempt is still penalized as a `Timeout` on that provider, even though the
  deadline — not necessarily the provider — ended the attempt early.
- The worker (jsonrpsee, Psy Edge Worker RPC) is not migrated to
  `psy_rpc_pool` in this delivery; see design §9.
- The GCP deploy config generator (`deploy/gcp/lib/multichain.sh`) does not
  exist in this runtime branch at all; it lives only on the deployment
  branch/worktree. There it built `rpc_urls` with `jq unique`, which can
  reorder providers. That is fixed on local branch
  `fix/deploy-relayer-rpc-order-20260923` (commit `79778b79`, worktree
  `psy-node-deploy-rpc-order-20260923`), not in this runtime source commit.
