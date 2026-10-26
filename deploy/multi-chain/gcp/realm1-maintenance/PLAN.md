# Realm1 Processor migration, method-level admission

Completed 2026-10-13 22:20 UTC. Historical planning evidence below; actual
timeline, downtime and acceptance are in [ROLLOUT-20261013.md](ROLLOUT-20261013.md).
Use [RUNBOOK.md](RUNBOOK.md) for operational gates and command restrictions.

Date: 2026-10-13. Authorized: prepare and advance Realm1 migration; preserve
queries and existing user state. No commit/push authorization is implied.

## Scope and current evidence

- Source: gcp-cp-ce, 10.148.0.25, Realm1 PID 1672024.
- Target: gcp-realm-processor, 10.148.0.37. Realm0 PID 15182 remains untouched.
- Target Realm1 unit already installed, disabled, inactive, startup permit absent.
- Existing runtime SHA256:
  bda82589c26bd914ead5bd77b8e6de136e0703797d0135fcddf3c2ff8dd8bb03.
- Genesis SHA256:
  569e58c901cdf7bd9edfc25bab70c4b0aafe0f5d2ec782781290d963ae63b710.
- Source checkpoint directory approximately 3.6 GiB; target prior copy 2.8 GiB.
- Target available memory 6.6 GiB; disk 36 GiB free at initial inspection.
- All DB access stays on 10.148.0.0/20. No DB or queue reset, circuit change,
  Worker change, or Coordinator restart.

## Ordered stages

1. **Prepare while online.** Verify runtime, Genesis, wrapper, effective config
   and target fencing. Pre-copy checkpoint files over private-IP SSH/rsync.
   Repeat checksum pre-sync to warm filesystem caches. Live copies are NOT a
   consistent snapshot and do not authorize starting the target.
2. **Prepare the admission layer.** Caddy continues routing Realm1 Edge traffic.
   A JSON-RPC-aware component must reject only `psy_submit_user_end_cap` and
   `psy_submit_user_end_cap_batch` before forwarding. Keep queries and Worker
   fetch/submit operational. Caddy's ordinary path/method matcher is insufficient.
3. **Validate before closing.** Test HTTP single calls, mixed JSON-RPC batches,
   notifications, large integer IDs, malformed input, escaped method names,
   compressed requests, and WebSocket messages (including existing connections).
   A mixed batch must still execute its query items. Never replay a write after
   uncertain upstream failure. Maintenance controls must not be public RPCs.
4. **Close new admission.** Cover both Realm1 domain aliases and all private
   admission paths; make state persistent across proxy reload/restart. Keep an
   audit epoch and a ledger of admitted/finished/ambiguous writes. Do not time out
   into automatic reopening while a Processor is stopped.
5. **Drain with the old Processor still running.** Reconcile pre-gate handlers,
   every relevant pending queue generation, outstanding proofs/GUTAs, and their
   committed state at Coordinator and Realm. Queue depth zero, a quiet interval,
   or checkpoint progress by itself is not a safe-stop barrier. Any unresolved
   entry prevents stopping the old Processor.
6. **Short stop window.** Fence and stop only old Realm1. Confirm clean exit and
   no second writer. Final delta/checksum sync (no vanished files accepted),
   preserve displaced files needed for rollback, then permit and start target.
   Do not repeat expensive full artifact preparation in this window.
7. **Verify before reopening.** Check exact running executable, ready log,
   checkpoint/state continuity, Worker task completion and new errors. Observe
   Coordinator and Realm0 concurrently. Reopen admission only after acceptance.
8. **Observe and document.** At least 15 minutes; use natural traffic or separately
   authorized minimal transactions. Transfer collector ownership and preserve
   old files plus explicit rollback commands.

Expected service effect: Realm1 reads remain served by existing Edges, but its
latest state can remain unchanged during Processor startup. No promise of zero
latency change or continuously fresh Realm1 state. Prior Realm0 startup rebuilt
about one million tree nodes and took about four minutes; pre-copy removes file
transfer from the window, not initialization. Reserve 10-15 minutes after drain.

## Entry inventory and unresolved preconditions

- Caddy on gcp-nostr, 10.148.0.29, routes both Realm1 host aliases to
  10.148.0.25:1339, 10.148.0.36:1339, 10.148.0.35:1339.
- Faucet and Relayer have already moved to TLS Caddy Realm URLs using private
  host mappings. Preserve those namespace-bound configs.
- WireGuard 10.250.0.1:11339 still forwards directly to 10.148.0.25:1339.
  It must receive method-level filtering too; blocking the port breaks reads.
- Direct cp-ce connections observed from 10.148.0.34 are the two cloud Realm1
  Workers; local connections are indexer and collector. This sample identifies
  current connections, not an exhaustive prohibition of future direct writes.
- Edge server uses jsonrpsee ServerBuilder without http_only: WebSocket must be
  tested, not assumed absent. Reloading Caddy alone does not fence old sessions.
- No runtime admission counter / explicit Processor safe-stop barrier has been
  demonstrated. An external filter cannot infer completion of a handler after
  an ambiguous disconnect without further reconciliation evidence.
- Caddy live JSON and its container-mounted Caddyfile differ (old bind inode).
  Preserve active routes and private-access logging; fix restart persistence
  without reverting unrelated routes. Do not restart the container blindly.
- Oct10 rsync key expired Oct12. Use a NEW short-lived key limited to this
  Realm1 directory and target private IP; do not broaden the old key.

## Rollback

While admission is closed, stop/fence the new writer first. If it has run,
return its latest local checkpoint files to the old host before restarting old
Realm1 against current shared DB state. Never restore a stale database snapshot
or start both writers. Keep queries and Worker APIs available throughout.

## Implementation status

- Read-only topology/artifact inspection: completed.
- Online-only pre-copy helper: `presync.py`; never stops/starts services.
- First checksum pre-copy completed: 587,833 files checked, about 664 MB of
  file data transferred, 534 seconds, exit 0. See PREPARATION-20261013.md.
- Method-level ingress filter: V3 prepared with its private three-Edge pool;
  HTTP/WS mixed-batch smoke and container/gateway reachability passed. Public
  configuration is unchanged. See ADMISSION-CANDIDATE.md for remaining gates.
- Second pre-copy: 588,244 files, 411 new, 412 transferred, 323.77 seconds,
  exit 0, no deletions. Final stopped-state synchronization is still mandatory.
- Recent Realm1 range: 1,255 archived updates each match their exact historical
  user-leaf hash at the pending-ID-mapped checkpoint. This is a baseline sample,
  not coverage of all retained history and not a Processor stop authorization.
- WireGuard switch helper prepared on gateway; no relay restart or route change.
- User confirmation pending for existing public WS and WG :11339 reconnects.
- Authoritative drain evidence: not complete.
- Live admission closure / Processor cutover: not performed.

Do not call the Oct10 `cutover 1` directly: its sequential helper does not prove
method-level admission closure or a lossless drain.
