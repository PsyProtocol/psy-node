# Realm Processor Maintenance Runbook

Updated 2026-10-14. Realm1 migration completed at 2026-10-13 22:20 UTC.
This runbook is not authorization for another live operation.

The Chinese operational procedure and postmortem live in the psy-memory repo:
`issues/realm-processor-relocation-20261010/REALM1-MIGRATION-RUNBOOK-20261014.md`.
Exact evidence: [ROLLOUT-20261013.md](ROLLOUT-20261013.md).
Earlier plans are historical, not the current service state.

## What This Procedure Does

Migrate the same Realm Processor binary and state without changing Node runtime
code or circuits. It DOES introduce an operational JSON-RPC admission gateway.
Caddy routes to that gateway; ordinary URL matching is not method-level gating.
Queries and Worker APIs remain served by existing Edges. Realm state may stay
stale while its Processor is stopped. This is not zero-downtime maintenance.

## Ordered Gates

| Stage | Required exit condition |
| --- | --- |
| Prepare online | Reviewed scripts/permissions, pinned binary/Genesis/config, target fenced, private DB access, pre-copy and rollback materials ready |
| Close admission | Both aliases, HTTP/WS and WG covered; old bypass sessions drained; only user End Cap submissions denied |
| Drain old writer | All relevant admitted writes and pending generations reconciled with committed Realm/Coordinator state; ambiguous outcomes resolved |
| Stop/fence source | Clean exit, disabled, PID 0, empty cgroup; target still stopped |
| Final copy | Source before/after and target inventories match, correct ownership/mode, strict rsync exit 0, displaced files preserved |
| Activate target | Fresh gate/fence evidence, locked rehash, one writer, actual executable hash matches |
| Ready/open | Root match at one fixed checkpoint, caught up, stable progress; explicitly open admission |
| Accept | Enable target, retain source fence, move Processor monitoring, observe business traffic or state the E2E gap |

Do not wait for human approval after stopping the source. Confirm the whole
bounded cutover authority and recovery procedure BEFORE closing submissions.
No automatic reopening or restarting the source on timeout.

Gate `safe_to_stop_processor=false` is intentional: external request accounting
cannot certify chain-level drain. Queue depth zero or growing height is not a
substitute for inspecting admitted updates, proof completion and GUTA settlement.
The reviewed migration reconciliation is a separate manual acceptance decision.

## Existing Realm1 Gate Commands

These paths describe the deployed October 13 installation. First confirm host,
unit and socket identity. Read-only status:

```bash
ssh gcp-nostr 'sudo -n curl -fsS --max-time 10 --unix-socket /run/parth-realm1-admission/admin.sock http://localhost/status'
ssh gcp-nostr '~/realm1-maintenance-v3-20261013/realm1-gate-smoke --url https://realm1-stg.psy-protocol.xyz/'
ssh gcp-nostr '~/realm1-maintenance-v3-20261013/realm1-gate-smoke --url https://realm1.psy-protocol.xyz/'
```

The following changes LIVE submission availability. Run only in a newly
authorized maintenance window after the gates above, never as a casual test:

```bash
# Close new user submissions; keep the old Processor running to drain.
ssh gcp-nostr 'sudo -n curl -fsS --max-time 10 --unix-socket /run/parth-realm1-admission/admin.sock -X PUT -H "Content-Type: application/json" --data "{\"mode\":\"closed\"}" http://localhost/mode'
# When closed, validate both aliases with --closed and verify WG separately.
ssh gcp-nostr '~/realm1-maintenance-v3-20261013/realm1-gate-smoke --url https://realm1-stg.psy-protocol.xyz/ --closed'
ssh gcp-nostr '~/realm1-maintenance-v3-20261013/realm1-gate-smoke --url https://realm1.psy-protocol.xyz/ --closed'
```

STOP HERE. These probes do not authorize stopping the Processor or reopening.
Complete the drain, fenced copy and activation stages. Before the SEPARATE open
command below, verify target executable identity, no second writer, matched
subtree roots at the same checkpoint, caught-up height and stable progress.

```bash
# Open ONLY after verified target recovery, not merely systemctl active.
ssh gcp-nostr 'sudo -n curl -fsS --max-time 10 --unix-socket /run/parth-realm1-admission/admin.sock -X PUT -H "Content-Type: application/json" --data "{\"mode\":\"open\"}" http://localhost/mode'
```

Blocked methods: `psy_submit_user_end_cap`, `psy_submit_user_end_cap_batch`.
`-32098` means not admitted; unknown upstream outcome `-32097` must not be blindly
retried. The gate always starts CLOSED after restart, even if previously open.
Monitor admission state separately from systemd. Mixed batches must preserve
query results; preserve Worker fetch/submit while draining.

## Script Map and Reuse Restrictions

| File | Purpose / limit |
| --- | --- |
| `presync.py` | Online pre-copy and target checks; live copies cannot authorize start |
| `stage_admission.py`, `ingress.py`, `gateway.py` | One-time gate/route preparation, including WG; re-inspect active Caddy config and old WS connections |
| `observe.py`, `reconcile.py` | Read-only observations and historical update checks; never assert automatic safe-stop |
| `final_files.py` | Fenced inventories and final copy, not a stop/start command |
| `activate_target.py` | Fresh evidence, locked rehash and target start; NOT safe to repeat on an already-started target |
| `collector.py` | Target-first monitoring move; not idempotent when already applied |

These scripts pin this migration's IPs, hashes, credentials and inventory limits.
They are NOT a general one-command runner. Generate a fresh reviewed manifest
for another migration; do not reuse old audit paths or the obsolete Oct10
`cutover` / `target-start` helpers. Stop/activation commands are deliberately
not offered here as a blindly repeatable sequence.

The acceptance helper used in this run waited 60 seconds for advancing Realm
height and lag <=10, verified PID/hash/restarts, then enabled the unit. It did
not prove a business transaction. Root comparison must use the Coordinator's
Realm subtree value, not its global user-tree root, at the SAME checkpoint.

## Timing and Recovery

- Measured final delta copy: 232.89 s; inventories/checks add overhead.
- Measured 1,048,449 leaf-position scan: 479.312 s, rehash: 1.518 s.
- Startup plus catch-up: about 10 min. Plan 15-25 min after drain as an initial
  budget, not a guaranteed bound; database load and file count can change it.
- The actual 8h10 submission pause was primarily an approval sequencing failure,
  not normal migration cost. See the rollout record; do not hide that duration.
- If the target never started, revalidate that fact before source recovery.
- Once the target may have run, never restart the source with stale local files.
  Fence/stop target, reconcile current state and copy latest files back first.
- SSH timeout is not evidence of failed activation. Inspect actual PIDs and
  permits. Preserve DBs/queues; never clear them to make startup pass.
- `RUST_LOG=warn` hides INFO initialization progress. Do not restart merely to
  obtain more verbose logs and repeat the scan.

Keep artifacts and root-protected audit records; do not commit private proof
payloads, keys or environment credentials. This candidate still needs separate
review/commit/push to the deployment branch before it is a durable release.

Publication hardening, October 14: both copy helpers recheck target fencing AFTER
acquiring the activation/copy lock. Two regression tests reject activation
between the initial check and lock acquisition before rsync can run. This change
is for the archived tools; no remote script replacement or new migration occurs
as part of publishing them. It is not evidence of corruption in the completed run.
