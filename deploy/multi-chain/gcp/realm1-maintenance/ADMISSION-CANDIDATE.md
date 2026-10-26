# Admission candidate: isolated verification only

Date: 2026-10-13. This is NOT a live traffic cutover or a completed migration.

Historical preparation record. V3 was subsequently activated and admission
reopened after migration; see [ROLLOUT-20261013.md](ROLLOUT-20261013.md).

## Current candidate: V3 prepared at 13:33 UTC

This section supersedes the historical v1/v2 preparation details below.

- Binary SHA256: `d2739378a269547ad2ef9eb3ba1baa68d8115fef09c3f80d6e7b0494576bc83a`.
- Host: gcp-nostr; persistent systemd gate `parth-realm1-admission.service`,
  PID 142343, listener `10.148.0.29:21340`, **closed and not public**.
- Upstream: separate `parth-realm1-edge-pool.service`, PID 142344, listening
  only `127.0.0.1:21342`, retaining the original three Edge upstreams,
  round-robin and active/passive health-check configuration. This is not the
  public `nostr-caddy` process.
- Private admin: `/run/parth-realm1-admission/admin.sock`.
- Installed source/binary root: `/opt/parth/realm1-maintenance-20261013`.
- Protected original/candidate configs and preparation receipt:
  `/var/lib/parth-realm1-maintenance-audit` on gcp-nostr.
- `ingress.py prepare` completed with `public_changed=false`. Both new services
  are enabled, but no public/WireGuard route has been changed.

V3 adds incremental batch decoding, a 1024-item cap and 32 goroutines per batch,
bounded waiting for read capacity, and a context-expiry check under the admission
lock. Large batches no longer silently lose query responses or create unbounded
goroutines. Expired queued submissions cannot subsequently be admitted.

Actually tested: 22 top-level Go race tests; real mixed HTTP and WebSocket calls
through the private gate and original public endpoint; queries return a numeric
checkpoint, and both empty-parameter EndCap methods return `-32098` at the closed
gate. Caddy-container-to-gate and gcp-gateway-to-gate HTTP queries also pass.
These probes do not submit real transactions. Production Worker proof traffic
through this gate has not yet been exercised.

Public Caddy is 2.11.2, with PID1 command `caddy run --config
/etc/caddy/Caddyfile --adapter caddyfile`, no supervisor or `--resume`, and
Docker restart policy `unless-stopped`. Its host Caddyfile adapts to the current
live config after normalizing only generated file-server hide entries. The
existing container bind mount still references an older inode.

The candidate is loaded explicitly from `/config/realm1-maintenance-20261013/`
after atomically replacing the host restart source. A same-image isolated
container experiment (no network, no ports) confirmed that atomic replacement
leaves the running bind on its old inode, while `docker restart` rebinds to the
new host file. The temporary container was removed; production was not restarted.
Do not reload the stale container `/etc/caddy/Caddyfile` manually.

`ingress.py` now writes through a same-directory temporary file, fsync, rename,
and directory fsync, preserving ownership and rejecting symlinks. If directory
fsync fails after replacement, inspect actual state; failure does not imply no
change. Independent review cleared the previous truncation issue.

`gateway.py prepare` also completed on gcp-gateway, with
`live_changed=false`. Its backup is `/var/lib/parth-realm1-gateway-20261013`.
Activation would replace only the Realm1 TCP relay destination, not its socket,
other relays, DBs, Workers or Processors. This has NOT been activated.

### Remaining activation conditions

- The user has been asked to accept short reconnections of existing public WS
  and WireGuard Realm1 `:11339` TCP/WS connections. No answer recorded yet.
  HTTP query admission remains open, but that is not a zero-interruption promise
  for every existing connection. Do not activate before resolving this constraint.
- After activation, verify both public aliases and the actual WG endpoint, then
  reconcile pre-gate/ambiguous calls and all relevant queue generations.
- The private gate is clean/closed, but **this does not mean public admission is
  closed or the Processor is drained**. No Processor has been stopped.
- Keep the v1 transient candidate separate; do not route production to its
  loopback address or use the obsolete v2 `stage_admission.py` as the V3 installer.

## What was built

Go HTTP/JSON-RPC and WebSocket request-response admission component under
`admission/`. It uses gorilla/websocket 1.5.3 (pinned go.sum), not a handwritten
WebSocket implementation. Only these methods are rejected in closed mode:

- psy_submit_user_end_cap
- psy_submit_user_end_cap_batch

Queries and Worker methods are allowed. Consequently, closed mode is NOT a
general read-only mode: do not send real proof submissions during smoke tests.

Mixed batches retain their query results; notifications receive no JSON-RPC
response; top-level duplicate fields are rejected; integer IDs are not converted
to floating point; escaped method names are decoded. Existing candidate WS
connections observe subsequent mode changes. Uncertain upstream submissions are
not blindly retried. Pending submission markers survive the process.

This component deliberately never declares a Processor safe to stop. Handler
completion is not proof of queue drain or chain inclusion.

## Initial v1 verification actually run

- `go test -race -count=1 -timeout=60s ./...`: passed, 11 top-level tests.
- `go vet ./...`: passed.
- Six Python tests across pre-copy and isolated launch cleanup: passed.
- Static Linux amd64 build completed.
- Independent model reviewed all 787 staged lines across five Go/module files.
  Public rollout was NOT approved; bounded isolated smoke was acceptable after
  fixing guarded cleanup of launch failures.

## Isolated v1 host instance

- Host: gcp-nostr (10.148.0.29).
- Unit: parth-realm1-admission-candidate.service, transient, not enabled at boot.
- Listener: **127.0.0.1:21340 only**. No public or WireGuard route points here.
- Private upstream: http://10.148.0.25:1339/.
- Control socket: /run/parth-realm1-admission-candidate/admin.sock (0600).
- DynamicUser, private StateDirectory/RuntimeDirectory, CPU quota 100%,
  MemoryMax 768M, no restart, egress limited to loopback and 10.148.0.25.
- Initial PID 140420, zero restarts, observed cgroup memory about 2.6 MiB.
- Binary SHA256:
  42a547f81502e4dbd44fa6eb8b40053cf132acead5385c03429cf2a322ffff1a.
- Installed binary:
  /opt/parth/realm-rpc-admission-candidates/42a547f81502e4dbd44fa6eb8b40053cf132acead5385c03429cf2a322ffff1a/admission.
- Launch helper SHA256:
  218264196c6138d77fa6af8a87041ab70f3225ec9a14e3bf5c231519935c2d52.

Actual mixed batch smoke returned checkpoint 267133 for the query and -32098
for an empty-params EndCap request. No real transaction/proof was submitted.
Post-test status: closed, active_submissions=0, pending_or_ambiguous=0,
responded=0, safe_to_stop_processor=false.

Only this candidate can be stopped for cleanup:

```sh
ssh gcp-nostr 'sudo -n systemctl stop parth-realm1-admission-candidate.service'
```

Do not stop nostr-caddy, Realm Edge, any Processor or Worker as candidate cleanup.

## Original review findings (v1)

1. CORS: candidate does not supply CORS headers. Existing Caddy supplies them,
   but actual candidate public routing/browser behavior still needs validation.
2. No aggregate byte/concurrency/body-read-time/ledger-retention budgets.
   Per-message 512 MiB and per-batch/per-WS concurrency limits are insufficient.
   A systemd MemoryMax is containment, not evidence of query availability.
3. Standalone restart leaves a Unix socket after ungraceful exit. Isolated unit
   RuntimeDirectory mitigates this; production unit/restart tests still required.
4. Persistence-error handling needs strengthening. Rename then directory fsync
   can report failure after replacement; completion currently replaces the
   pending record. Add sticky uncertainty / immutable admission records and
   fail-closed recovery tests. Any mode-update failure forbids migration.
5. Slow open-mode submissions can occupy batch/WS slots before a later read.
   Reserve query capacity and test saturation -> close -> same-connection query.
6. Launch cleanup was fixed in stage_admission.py: launch is inside the guarded
   try, cleanup checks candidate description and binary path, and cleanup errors
   do not mask the original failure. It never cleans up other services.

Separate migration gates remain: old public WS/HTTP handler reconciliation,
direct private admission paths, Caddy restart-persistent configuration, all
pending queue generations, GUTA commitment and final stopped-state file sync.

No production method-level gate has been activated. Do NOT change Caddy to this
candidate or run the old `cutover 1` on the strength of this smoke result.

## V2 local preparation

The source now includes a v2 candidate; the v1 host process above has NOT been
replaced by simply editing these files. The installer pins a distinct v2 unit,
state directory and localhost port 21341. No public route is changed by it.

Changes addressing the original review:

- Separate 32-slot non-EndCap and four-slot EndCap upstream capacity; overload
  is rejected before forwarding, without blindly retrying submissions.
- Process-wide message, WebSocket, batch and conservative buffered-byte limits;
  a small-message reserve; bounded upload/write deadlines and ledger growth.
- CORS headers, including OPTIONS, without opening the Unix admin interface.
- Immutable admission records plus separate completion files. A persistence
  failure closes admission and latches uncertainty. Every restart starts closed,
  even when the previously persisted mode was open.
- Graceful signal handling, no reopening during shutdown, and waiting for
  admitted WebSocket writes. RuntimeDirectory remains required for crash cleanup.
- Exact launch-cleanup executable-path comparison, not a substring comparison.

Actually run locally: **19 top-level Go race tests**, Go vet, **10 Python tests**,
and static Linux amd64 build. Tests include six injected persistence failures
(admission/completion/close, before/after replacement), four blocked in-flight
submissions followed by a query on the same WebSocket, byte-budget release and
reserve, limits, CORS, and real child-process SIGTERM/socket cleanup.

Binary SHA256: f900490c353dcff2bd09b502971d5bb49034c9728c0cb29f72a1835f9aaf03b7.
This section records preparation, not approval for public deployment.

Limitations that tests do NOT establish away:

- A normal mixed JSON-RPC batch response still waits for all admitted members.
  Independent queries and queries in a closed-mode batch have separate capacity;
  this is not streaming individual responses out of one HTTP batch.
- Resource guards can reject overload. Large real proof payloads and actual
  Worker traffic compatibility still need characterization before public use.
- The five-minute WebSocket idle deadline is a candidate behavior change.
- The isolated backend is one Edge; the public three-Edge pool is unchanged.
- Candidate ledger responses are not chain-inclusion evidence. Its API always
  reports safe_to_stop_processor=false. No automated migration stop is wired up.
