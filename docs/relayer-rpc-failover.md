# Relayer L1 RPC provider pool

## Scope

This applies to relayer L1 JSON-RPC requests only, not Psy RPC, Envio,
psy-services or prove-proxy HTTP calls. Each configured L1 chain owns one
`ProviderPool` (crate `psy_rpc_pool`), shared across clones and daemon rounds.
Chains never share health state. It replaces the earlier per-request
primary/backup cooldown policy.

The ordered adaptive policy below supersedes the earlier weight and
failure-domain routing in `psy-memory/rpc_provider_pool/design.md`.
This is a local candidate change, not an online rollout.

## Configuration

Per EVM chain in the multichain daemon config:

```toml
[[chains.rpc_providers]]
name = "alchemy-jason"
url = "https://..."
weight = 11   # legacy metadata only; no longer overrides list order
operator = "alchemy"                   # optional
quota_group = "alchemy-account-jason"  # optional
```

- `rpc_providers` takes precedence when present on a chain.
- `weight` is accepted as an alias of `priority_weight` for config compatibility
  (same field; set one or the other, not both). Neither affects selection now.
- The existing `rpc_urls = [...]` stays valid: each URL becomes a provider
  with legacy weight 10 and a generated name (`<chain>-rpc-<index>`).
  Declaration order expresses preference initially and whenever health scores
  are within tolerance. See Routing order and Upgrading existing configs below.
- Duplicate URLs are dropped, keeping the first occurrence. The check is a
  plain string comparison on the trimmed URL, not a normalized comparison.

A single-chain config may also set `[finalize] l1_rpc_providers`, the same
`{ name, url, priority_weight, operator, quota_group }` table shape as
`[[chains.rpc_providers]]` (`name`, `priority_weight`, `operator` and
`quota_group` are all optional; `weight` is accepted as an alias of
`priority_weight`, same as above). It takes the same precedence over
`l1_rpc_url`/`l1_rpc_fallback_url`. In any provider entry, `name` is
optional: when blank it is generated as `<label>-rpc-<n>`
(`<chain>-rpc-<index>` for `chains.rpc_providers`, the finalize label for
`finalize.l1_rpc_providers`).

### Legacy mapping

The single-chain `l1_rpc_url` / `l1_rpc_fallback_url` fields map to a
two-provider list in that order: `l1_rpc_url` (or the default L1 RPC URL)
first, then `l1_rpc_fallback_url` when present. Both become weight-10
providers with generated names, and their `operator` is still inferred from
the URL (see below).

### Operator and quota group

Each provider entry may also set `operator` and `quota_group` (spec
§5.1, §7.2.1):

- `operator`: diagnostic shared infrastructure label, e.g. `alchemy`,
  `infura`, `nodereal`. It does not override the ordered health selection.
- `quota_group`: the shared rate-limit/credit domain, e.g. an account or
  subscription. It is diagnostic metadata, not a routing tier.
- Health, penalties, consecutive failures and quarantine stay per provider.
  A failure never penalizes a sibling provider that shares the same operator
  or quota group.

**Defaults:**

- `operator` default: inferred from the URL host when `operator` is blank
  or omitted (this applies to every provider, including ones generated from
  legacy `rpc_urls`/`l1_rpc_url`). The host is lowercased; a trailing `.` is
  stripped. An IPv4 address, a bracketed IPv6 address, or a single-label
  host (e.g. `localhost`) uses the whole host. Otherwise the second-to-last
  dot-separated label is used, e.g. `eth-sepolia.g.alchemy.com` ->
  `alchemy`, `sepolia.infura.io` -> `infura`. An unparseable URL infers
  `"unknown"` (a real startup error is still raised separately for an
  invalid provider URL). **Caveat:** the heuristic ignores multi-part public
  suffixes such as `co.uk` — `foo.co.uk` infers `co`, not `foo`. Set
  `operator` explicitly for hosts under such a suffix.
- `quota_group` default: the exact provider name (case preserved), so
  providers are quota-independent unless explicitly grouped.
- An explicit `operator`/`quota_group` value is trimmed and lowercased; a
  blank value is treated as unset and the default above applies.
- **Case trap:** the `quota_group` default preserves the provider name's
  case exactly, but an *explicit* `quota_group` value is always lowercased.
  Do not rely on one provider's default `quota_group` (its own name) to
  group it with another provider — the strings will not match unless the
  case happens to line up, and never will if any member's `quota_group` is
  explicit (lowercased) while another's is the mixed-case default. To group
  providers, set the same explicit `quota_group` value on every member of
  the group.

**Routing order** uses health and the declared list:

- New providers start equally healthy, so the first entry is selected.
- Normally select the earliest eligible entry within two health points of
  the healthiest entry. Scores reflect availability failures, not latency;
  EWMA latency remains observational. Healthy traffic does not fan out to
  benchmark every endpoint.
- A failure lowers only that provider's score and starts a 30-second cooldown.
  A request marked safe to replay tries untried eligible candidates; an
  unsafe request still gets at most one attempt.
- After an attempt fails, an earlier failed entry whose cooldown has expired
  gets a limited recovery trial before moving farther down the list. If it
  also fails, continue to the next candidate. Each entry is attempted at
  most once per logical request, within the total deadline.
- While the current endpoint works, an earlier failed entry can be selected
  for a trial once its decayed penalty puts it within the normal tolerance.
  Cooldown expiry alone is not a promise of an immediate probe: probes are
  driven by incoming requests, not a background loop.
- Only one recovery trial per provider may be in flight. Success clears its
  failure streak and penalty, so an earlier recovered provider can remain
  preferred. Cancellation releases the slot without adding a penalty.
- Business errors return immediately without failover or penalty. A valid
  JSON-RPC response carrying a revert or invalid-params error still confirms
  endpoint recovery in the Relayer adapter. The generic pool's separate
  `Application` outcome clears cooldown without resetting historical penalty.
- Five consecutive failures quarantine a provider for 30 minutes. A failed
  post-quarantine trial renews quarantine. If every untried provider is
  cooling down, quarantined or already being probed, return the last attempt
  error (or `Unavailable` if none ran); never bypass those protections.

Example: A fails and B succeeds. After A's cooldown, if B fails, try A;
if A still fails, try C, then D as needed. A successful candidate returns
the current request immediately; subsequent requests use the updated scores.
The pool does not replay a business workflow or create a second transaction
to compare endpoints. Raw-transaction retries keep the exact signed bytes.

**Startup WARN:** once per pool (chain), if every provider ends up with the
same operator (after defaults/inference), a WARN logs `label` and
`operator`: `"all L1 RPC providers share one operator; no
infrastructure-level backup"`. This also fires for a single-provider chain.
Never includes a URL.

### Upgrading existing configs

Both legacy URL lists and explicit provider tables use the same new policy.
Reorder the list to express preference (for example local, public, paid);
old weights and operator/quota labels remain parseable and visible in snapshots,
but no longer override that order. Shared-account keys are still not independent
backups: selecting meaningful alternatives is the operator's responsibility.

This changes single-provider behavior too: a failed provider is not hammered
by every subsequent request during cooldown. Callers must handle temporary
unavailability without discarding pending business work. This candidate does
not add durable transaction tracking or change daemon scheduling.

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
| Cooldown after each failure | 30s |
| Quarantine after | 5 consecutive failures |
| Quarantine duration | 30 minutes |
| Attempt timeout | 15s |
| Total request timeout | 30s |
| Max attempts | Provider count by default, each at most once; optional lower PoolConfig cap |
| Latency EWMA alpha | 0.2 (observational only; does not affect health) |

These are tunable v1 guesses. Adjust from observed production logs.

## Logs to watch

- `RPC provider attempt failed` (WARN) — fields: `pool` (chain name),
  `provider`, `outcome`, `method`, `failover` (whether policy and budget permit
  another attempt). Emitted on every failed attempt.
- `RPC provider quarantined` (INFO, field `minutes`) — a provider entered or
  renewed quarantine: 5 consecutive failures triggered it or a failed
  post-quarantine probe renewed it. The provider stops receiving
  normal traffic for `minutes` (30 by default).
- `RPC provider restored` (INFO) — a post-quarantine trial returned a
  non-provider-fault result and its quarantine was lifted.

**Operator note:** all endpoints unavailable produces a bounded error, not
forced traffic through a quarantined endpoint. Every failed attempt logs
`RPC provider attempt failed` (WARN). `failover=true` means the policy and
budget permit another attempt, not that an eligible endpoint is guaranteed
to remain available. A WARN alone is not necessarily an actionable outage.

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
- After a provider's cooldown or quarantine expires, only one probe attempt is in flight
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

### Provider certification probe

Before a provider is configured (added to `rpc_providers`), certify it with
`psy_cli/psy_relayer_cli/tools/probe_rpc_providers.py` (Python 3, standard
library only; see `probe_rpc_providers.example.json` for the input shape).

- **Input:** a JSON file listing chains (`chain_id`, `bridge`,
  `state_manager`, `start_block`) and candidate providers. Each candidate
  names its chain and either `url_env` (an environment variable holding the
  URL — secrets stay in the environment or an `--env-file`, never in the
  input file) or a literal `url` for a keyless public endpoint. Only
  `http`/`https` URLs are probed. A URL with userinfo
  (`https://user:pass@host/...`, e.g. a basic-auth provider) works: the
  userinfo is stripped before the request is built and sent as an
  `Authorization: Basic` header (percent-decoded first), so the DNS
  resolver only ever sees the bare host; the header is not forwarded on a
  redirect. The tool only ever prints the bare host of a URL, never its
  path, query, or userinfo. Proxy environment variables (`http_proxy`,
  `https_proxy`, `HTTP_PROXY`, `HTTPS_PROXY`) are ignored by default and
  every request goes directly to the provider, because a proxy would
  receive the full candidate URL. `--use-env-proxy` opts back in to them;
  the proxy then sees full provider URLs, including API keys in the path
  or query, plus any userinfo credentials in the `Authorization` header,
  and the tool prints a warning to stderr. The input is
  validated up front: a missing input file, malformed JSON, a non-object
  top-level value, an unknown chain referenced by a candidate, a malformed
  chain field, or a non-string `url`/`url_env` all exit **2** with a clear
  message instead of running any check.
- **Flags:** `--chain NAME` (only probe that chain's candidates),
  `--env-file PATH` (adds URL env vars from a file; the shell environment
  wins on collision), `--confirmations N` (blocks subtracted from the
  shared scan-end block described below; default `12`), `--use-env-proxy`
  (honour proxy environment variables; the proxy then sees full provider
  URLs including API keys, see **Input** above), `--self-test` (run the
  tool's own unit tests; no external network access, only mocks and
  loopback HTTP servers on `127.0.0.1`).
- **Shared scan window:** for each chain, the tool first fetches
  `eth_chainId` and `eth_blockNumber` from every candidate, then scans
  `start_block` through one shared end block for every candidate on that
  chain — `min(head among candidates that reported the correct chain id) -
  confirmations` — instead of each candidate's own head, which is sampled
  at a slightly different moment per candidate and would otherwise make
  deposit counts incomparable. Each candidate's own head is still reported,
  along with its lag behind the fastest candidate (`head_lag`). If a
  chain's confirmed scan window ends up before its own `start_block`, the
  summary prints `WARNING: <chain>: scan window is empty (scan_end <
  start_block)` and no candidate on that chain can be `CERTIFIED`.
- **Checks per candidate:** chain ID; `eth_call` plus `eth_getCode` on the
  StateManager (an empty `eth_getCode` result fails the check even if the
  call itself returned data — the address may simply be wrong for this
  chain); `eth_sendRawTransaction("0x00")` service (a decode error counts
  as served, even one arriving as an HTTP 4xx response whose body carries a
  JSON-RPC error; only a JSON-RPC error response that is not
  method-not-found/unsupported counts — a timeout, connection failure,
  malformed URL, bare HTTP status, or non-JSON body is not served); the
  largest successful `eth_getLogs` span near the candidate's own head; a fixed 50,000-block full-history scan over the
  shared window, counting `DepositRecorded` logs (this is what the
  relayer's own fixed-size chunking needs the provider to sustain — the
  scan is deliberately not adaptive, and stops after 3 consecutive chunk
  failures since the candidate is already `REJECTED` by then); and a
  receipt lookup for the most recent deposit tx found anywhere (visible as
  `receipt: "skipped: no deposit tx"` when none exists — a skipped check is
  never silently omitted). Per-chunk scan progress
  (`<host>: scanning blocks <from>-<to>`, host only, never a URL) is
  printed to stderr.
- **Verdicts**, per candidate:
  - `CERTIFIED`: no check errored and its deposit count equals the chain's
    max (a candidate with the wrong chain ID never counts toward that max).
  - `INCOMPLETE`: silent data loss — its count is lower than the chain's
    max with no error reported. This is the dangerous case: the provider
    looks healthy but would quietly under-report events.
  - `REJECTED`: any check errored — unreachable, wrong chain ID, missing
    method support, an empty scan window, or another explicit error.
  A chain whose max deposit count is 0, or that ends the probe with at most
  one non-`REJECTED` candidate, gets an explicit `WARNING: <chain>: nothing
  to compare against -- certification is vacuous` line in the summary —
  there was nothing to compare the winner against. When the chain's scan
  window is empty (`scan_end < start_block`), only the more specific
  `WARNING: <chain>: scan window is empty (scan_end < start_block)` line is
  printed for that chain, not both warnings.
- **Exit codes:**
  - `0`: every selected chain has at least one `CERTIFIED` candidate (or
    `--self-test` passed).
  - `1`: `--chain` matched no candidates, any selected chain ends the probe
    with no `CERTIFIED` candidate, or `--self-test` failed.
  - `2`: usage or input error, before any check runs — the input fails
    validation, no input file argument was given, the input file is
    missing, unreadable, not UTF-8, or not JSON, the `--env-file` is
    missing, a directory, unreadable, or not UTF-8, or `--confirmations`
    is negative (argparse's own usage errors also exit `2`).
  - `3`: an unexpected internal error; only `ERROR: probe crashed:
    <Type>` is printed (the exception type, never its message or a
    traceback, which could embed a URL).
  - `130`: interrupted with Ctrl-C.
- A provider must be `CERTIFIED` before it is added to `rpc_providers`/
  `rpc_urls` for that chain.

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
- This integration does not include finalize state reconciliation from
  `93dc14ad`. After a lost `eth_sendRawTransaction` response, `already known`
  is returned as an application error, not proof of successful settlement.
  The pool does not add persistent in-flight transaction recovery.

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

## Live-baseline backport (2026-10-08)

This delivery selects the RPC pool and Relayer integration from
`a2f56b6475e648bb6619df96d040a8aff3ae9728` onto the running Relayer's
`32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6` baseline. It excludes the candidate
branch's protocol/circuit changes, gnark dependency revision change, submodule
updates, deposit snapshot API change, and the unrelated finalize-preflight
patch. The existing deposit API call and all live signing/contracts/state
formats stay at the baseline. Only the Relayer binary is an activation target;
no worker, proxy, Services, Genesis, or database rollout is implied.
