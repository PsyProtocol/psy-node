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
- `RPC provider quarantined` (INFO) — a provider hit 5 consecutive failures
  and stopped receiving normal traffic for 30 minutes.
- `RPC provider restored` (INFO) — a post-quarantine probe succeeded and the
  provider resumed normal selection.

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

## Known follow-ups (not fixed in this delivery)

- Some pre-existing error strings still interpolate the configured URL
  outside the pool transport, e.g. `invalid L1 rpc url: {url}` in
  `l1_client.rs`, `finalize_bridge.rs`, `claim_withdrawals.rs` and
  `prove_bridge.rs`. These are config-validation errors at startup, not pool
  request errors, and are unchanged by this delivery.
- The duplicate-URL check in provider resolution is a textual comparison on
  the trimmed URL string, not a normalized one (e.g. trailing slash or
  scheme case differences are not deduplicated).
- A request that is cut short by the pool's total-timeout deadline mid
  attempt is still penalized as a `Timeout` on that provider, even though the
  deadline — not necessarily the provider — ended the attempt early.
- The worker (jsonrpsee, Psy Edge Worker RPC) is not migrated to
  `psy_rpc_pool` in this delivery; see design §9.
- The GCP deploy config generator (`deploy/gcp/lib/multichain.sh`) still
  builds `rpc_urls` with `jq unique`, which can reorder providers. The fix
  lives on a separate, local-only deploy branch
  (`fix/deploy-relayer-rpc-order-20260923`), not in this runtime source
  commit.
