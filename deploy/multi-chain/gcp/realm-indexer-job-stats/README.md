# Realm Indexer job statistics hotfix

This guarded one-off updater changes only the two Realm Indexers on
`gcp-realm-processor`, one at a time. It is not a fresh-deployment command.
Services must already be ready. Never replace the Coordinator Indexer, processor
or Edge binaries with this package.

## Scope and compatibility

The maintenance-based source classifies a checkpoint using its local pending
batch mapping and, when absent, the committed Coordinator's historical Realm
root. A confirmed sync-only checkpoint needs neither job statistics nor batch
backup. An actual update with missing mapping, failed metadata RPC or unavailable
backup remains a retry barrier. Startup metadata discovery retries failures
instead of falling back into pruned history. Existing cursors are preserved.

The required new setting is installed in both per-unit drop-ins:

```text
PSY_COORDINATOR_EDGE_RPC_URL=http://10.148.0.25:1337
```

The existing Realm RPC URLs, private database endpoints, Services URL, backup
paths, environment files, permit files and systemd restrictions stay unchanged.
No schema, protocol dependency, circuit, Genesis or account change is included.

## Procedure

1. Build and test the exact published source commit. Record it and the binary
   SHA256 in `manifest.json`. Independently review source and rollout changes.
2. Upload `rollout.py`, `manifest.json`, and `psy-indexer` into
   `~/realm-indexer-job-stats-20261014/` on `gcp-realm-processor`.
3. Run preflight for each Realm before modifying either service:

```sh
sudo python3 ~/realm-indexer-job-stats-20261014/rollout.py preflight --realm 0 \
  --binary ~/realm-indexer-job-stats-20261014/psy-indexer \
  --manifest ~/realm-indexer-job-stats-20261014/manifest.json
```

Repeat with `--realm 1`. Both checks pin the old running executable and original
unit layout, validate dependency availability and Coordinator RPC reachability,
and require both processors active. Any baseline difference stops this updater.

4. Run the same command with `activate --realm 0`. The updater saves protected
   configuration hashes, process identities and cursor observations, installs
   an immutable release and a single new drop-in, then stops/starts only that
   Indexer. It never writes its cursor. Readiness requires three checkpoints
   beyond the cursor observed **after the old process exits**, the exact candidate
   executable hash and the expected environment.
5. Inspect new-process logs: sync-only false warnings should disappear, while
   real mapped batches still transfer nonempty End Caps and statistics. Check
   Services acceptance, persisted cursors and unaffected processor PIDs.
6. Only after Realm0 passes, activate and observe Realm1 in the same way.

Restart causes a brief indexing delay, not a chain stop. Check the complete
interval after rollout as well as the initial three-checkpoint readiness gate.

## Rollback

```sh
sudo python3 ~/realm-indexer-job-stats-20261014/rollout.py rollback --realm 0
```

Use Realm1 separately if needed. Rollback removes only this updater's verified
drop-in and uses the original binary, current valid cursor and original config.
An unrelated Processor restart cannot block restoration of the old Indexer.
Automatic rollback follows failed activation; inspect the audit if it also fails.
Never restore old cursor snapshots, delete backup files or reset indexing.

Audits: `/var/lib/parth/realm-indexer-job-stats-20261014/{0,1}/state.json`.
Secrets stay in root-protected local backups; do not commit environment files.
Atomic drop-in linking requires `/var/lib` and `/etc` on the same filesystem.
Tests cover stop-time cursor progress, a still-running old process, the candidate
progress threshold and rollback's independence from Processor identities.

## Limits

This prevents new unsafe classification/skipping; it does not repair any past
omissions. Source-level retry tests use simulated RPC faults; rollout tests mock
systemd. Persisted cursor writes are not newly made atomic by this patch.
An empty historical Realm with no stored root version can still require a
separate historical catch-up design; do not bypass a retry barrier to hide it.
