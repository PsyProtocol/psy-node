# R3 Realm Accepted-EndCap Recovery Rollout

Execution evidence: [2026-10-29 release](DEPLOYED-20261029.md) and
[per-component source/artifact mapping](live-release.json).

This is a state-preserving, per-unit hotfix, not a fresh deployment runner.
Keep Genesis, databases, pending IDs, queues, keys and existing configuration.

## Immutable Inputs

- Reviewed public PR head: `61c1636b53b0d9db61c28cad020b4d2b060277f3`, PR #30.
- Live-compatible source: `396ea8df7526abf9f711a291425190a892237e50`.
- Source base: `5f4f5c905ca6a9fd797f69bd92f45bbd5007ba08`, already deployed
  processor replay hotfix. The five subsequent PR commits are backported without
  unrelated Genesis/source-baseline changes. All 17 changed files match PR head.
- Candidate `psy_node_cli` SHA256:
  `aba982032894347c13fd767c1fdebf8427a3d5e85feeee119569131918cb5338`.
- New immutable executable:
  `/opt/psy-core/hotfixes/realm-pr30-61c1636b/psy_node_cli`.
- Existing R3 Genesis SHA256:
  `f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173`.
- Network remains `testnet`, magic `0x1337CF514544CF69`, Plonky2.

The reproducible build uses the existing `core-only/build_runtime.py` recipe,
pinned Bookworm image, R3 compiler bundle and config. It does not generate new
circuits, Genesis or proving keys. Build output includes five CLIs, but this
rollout deploys ONLY `psy_node_cli` to the twelve named Realm units.

## Scope

| Host / private IP | Units |
| --- | --- |
| gcp-edge-1 / 10.148.0.36 | Realm0 Edge v1, v2, v3 |
| gcp-edge-2 / 10.148.0.35 | Realm1 Edge v1, v2, v3 |
| Processor A / 10.148.0.37 | Realm0 and Realm1 Processor v1 |
| Processor B / 10.148.0.42 | Realm0 and Realm1 Processor v2 |
| Processor C / 10.148.0.43 | Realm0 and Realm1 Processor v3 |

Never replace the shared R3 executable: Coordinator units also use it. Do not
restart Coordinator, Workers, Relayer, Services, Guardians or backing databases.
Keep database traffic on the private network and preserve gateway routing.

## Per-Unit Procedure

1. Reconfirm source, candidate SHA256, existing binary identities and configuration.
   Record a bounded baseline of checkpoints, commits, proving, discards, sync
   errors, restarts and unrelated unit PIDs. Checkpoint equality once is not
   progress evidence.
2. Stage the candidate under `/var/tmp/psy-realm-pr30-61c1636b/psy_node_cli` on all
   five hosts. Install the reviewed helper as root-owned
   `/opt/psy-maintenance/realm-pr30-20261029/update_unit.py` and verify its hash.
3. Run `check` for ALL twelve units before the first restart. Pass the exact unit
   and candidate SHA256 explicitly; an unknown host, unit, network, prover,
   override or previous binary is a stop condition.
4. Upgrade Realm0's three Edges, one at a time. After each activation wait for its
   individual JSON-RPC listener to return an integer checkpoint. Process identity
   can become active before its socket is ready. A refused connection immediately
   after start requires a bounded readiness retry, not an automatic second restart.
5. Allow existing requests to settle before restarting processors. Newly accepted
   EndCaps have recovery records only after the upgraded Edge admits them; this
   update does not reconstruct previously lost records from old admissions.
6. Upgrade Realm0's three Processors, one at a time. Preserve quorum and wait for
   startup, catch-up, loop activity and shared-state synchronization before the
   next processor. Realm1 remains on its previous version as a control.
7. Observe real Realm0 proof completion and canonical inclusion, checkpoint
   progress, new replay/redelivery logs and absence of hard invariants or exits.
   An idle proposer alone is not a failure. Do not manufacture financial test
   transactions under this rollout authorization.
8. Only after Realm0's gate passes repeat the Edge/Processor sequence for Realm1.
   Continue observing both Realms and confirm Coordinator PIDs stayed unchanged.

Example (run on the matching host, using one of the twelve exact unit names):

```sh
sudo python3 -I -B /opt/psy-maintenance/realm-pr30-20261029/update_unit.py check --unit psy-core-r3-realm-0-v1-edge.service --sha256 aba982032894347c13fd767c1fdebf8427a3d5e85feeee119569131918cb5338
sudo python3 -I -B /opt/psy-maintenance/realm-pr30-20261029/update_unit.py activate --unit psy-core-r3-realm-0-v1-edge.service --sha256 aba982032894347c13fd767c1fdebf8427a3d5e85feeee119569131918cb5338
```

The helper retains processor override `70-realm-replay-20261028.conf` and adds
only `80-realm-pr30-20261029.conf`. It verifies executable path and SHA256,
backs up per-unit configuration, checks unrelated local PIDs and records results
under `/var/backups/psy-realm-pr30-20261029/`. Configuration drift or unsafe cleanup
prevents an unverified restart. If stopping completed, the unit remains stopped
for inspection; if stopping itself timed out, inspect its actual process state.
It does not verify RPC readiness or workload acceptance; the operator must do so.

## Rollback

Use the same helper's `rollback` action for one affected unit, with the same
candidate SHA256. It removes only the exact owned `80` override. Processor units
return to `5f4f5c90`; Edges return to the R3 base. Keep retained binaries and audit
records. An unexpected override is not permission to delete it.

The explicit `rollback` action requires the new process to be running with the
expected identity. A failed or stopped unit needs inspected manual recovery; do
not assume that action can recover every failed service state.

A binary rollback does NOT rewind database counters. Do not clear ER/EU/EC,
pending IDs, NATS data or backups. A database rewind is a separate, explicitly
authorized recovery operation and requires reconciliation of accepted EndCaps.

## Acceptance Limits

- Runtime source author: 677 common tests passed, one pre-existing ignore; core
  56 and memory store six passed, CLI build passed.
- Independent live-backport check: common 675 passed, one ignored, two random
  stress tests filtered on the bounded rerun; core 56 and memory six passed.
  The shorter random test passed in the first run; the longer unchanged random
  test was deliberately interrupted, not reported as independently passing.
- Helper: 11 planning/failure-path tests passed; independent staged-code review.
- Keep the known nonblocking orphan-list race, split-write limitations and local
  pending-ID progress prerequisite visible. This is not a claim of transactional
  crash-proof delivery under every possible failure.
- A short canary does not establish a statistically improved long-term loss rate.
  Continue the `(realm, user, nonce)` re-prove audit after deployment.

Deployment evidence and review history belong in psy-memory, not in the runtime
source. Local preparation branches and live rollout do not imply remote merge or
push. Record the exact maintained-branch integration status in the release record.
