# Guarded Realm Edge EndCap handoff (2026-10-09)

Adapted from `../edge-reputation/rollout.py` at deployment base
`21af7e5fe9fa6414682f0ccf4d619ddf382b01fe`. This is a partial, state-preserving
update, not a fresh deployment. Only `realm-0` and `realm-1` are actionable.
Coordinator Edge is observed and PID-protected, never restarted. All other
host-local `parth-*` service PIDs, including Processors, remain protected.
Services on other hosts require the operator's separate verification.

Do not replace Genesis, configuration, contracts, keys, Processors, Workers,
Services, Redis data, or `/opt/parth/current`. Keep every existing drop-in,
especially `99-worker-reputation-20261008.conf`. The only owned override is
`zz-endcap-handoff-20261009.conf`, sorting after the reputation override.
Rollback removes only this exact owned override and restarts only its Realm Edge.

## Artifact identity

| Identity | Value |
| --- | --- |
| Both old Realm binaries SHA256 | `55abcc1bee0683e3529ab9f3e86c6711d0492f12999ec0a2f20ad20584ee4702` |
| Old source | `876c1432da302941acfba8485763e3f0549ec284` |
| Live candidate source | `4ff86c815de7c904c3c141b02926540a68e9a74b` |
| Candidate binary SHA256 | `ced042f895026fc3fe0086d983a2e1a20b6a6ecbbb91664d4207137599c4618b` |
| Stable integration | `6eb535003bdab1fcdb27386dbcb93e8aa9727998` |

The operator built the live candidate from `psy-node-endcap-live-20261009` on
the old source, using CPU-portable Bookworm, Rust nightly-2025-09-20 and
`PSY_NETWORK=testnet`. Release build succeeded. Candidate identity/build/test
results below are operator-reported; script preparation did not rebuild or
independently hash the runtime artifact. Use the live candidate source, not the
stable integration or later deployment merge SHA, as binary provenance.

## Private package and guards

Stage a root-owned private package containing `rollout.py`, `psy_node_cli`, and
`manifest.json`. Generate the manifest from the actual frozen artifact and
reviewed installer, with these fields:

- `source_commit`: the full live binary source SHA.
- `baseline_source_commit`: the full old source SHA above.
- `binary_sha256`: SHA256 of the packaged binary.
- `installer_sha256`: SHA256 of the exact packaged `rollout.py`.
- `baseline`: the unmodified JSON returned by this installer's `capture` action.

Never copy the prior reputation installer's manifest or fabricate a baseline.
No executable manifest or private capture is checked into this directory.
The release root is `/opt/parth-endcap-handoff/20261009-<source-first-12>`.
An existing release manifest must match; existing binaries/backups/foreign
overrides are not overwritten. Keep the package and original executable paths
available for rollback. Backups and recovery records remain private on-host.

Capture/check/apply verify Genesis, synchronized clock, shared Redis URL/database
for all three Edges, and Redis `ROLE` returning `master`. The inherited Redis
client previously used read-only AUTH/SELECT/SCAN/HSCAN; this installer allows
only AUTH/SELECT/ROLE. It never scans, snapshots, resets, rewrites or restores
reputation records. Credentials and Redis replies are not stored in captures.
ROLE is a point-in-time check, not a failover fence.

Loaded and on-disk Edge unit/drop-in files, existing environment files, shared
configuration, original artifacts and other-service PIDs are guarded. Drift
fails closed. Serialize this rollout with all other installers/operators; the
local lock does not coordinate other deployment tools. Do not refresh a
baseline or loosen a guard merely to bypass a failure.

## Operator workflow

Independent different-model review of the exact staged delivery is required
before any commit. Runtime integration, package generation, live approval and
execution belong to the operator. Script preparation performed no live actions.

```sh
sudo python3 /opt/private-endcap-package/rollout.py capture
sudo python3 /opt/private-endcap-package/rollout.py check
sudo python3 /opt/private-endcap-package/rollout.py apply --unit realm-0
# Observe real work and checkpoint progress before proceeding.
sudo python3 /opt/private-endcap-package/rollout.py apply --unit realm-1
# If recovery is needed, target only the affected Realm:
sudo python3 /opt/private-endcap-package/rollout.py rollback --unit realm-0
```

After each activation verify the running executable hash, unchanged Coordinator
Edge/Processor/other-service PIDs, stable restarts, advancing checkpoints and
real successful Worker pickup/prove/submit. Readiness alone is not EndCap-path
coverage. Stop for operator investigation if a protected process exits during
the Edge outage. No Processor restart is authorized by this script.

Recovery ownership binds the manifest, baseline and drop-in bytes. Durable
`rollback_pending` intent permits retry after unlink/reload/restart failures.
Rollback deliberately does not require the failed Edge's RPC or Redis to be
healthy; it still validates protected state and the original executable before
removing its override. A changed/missing original binary, foreign override,
protected-state drift or ambiguous recovery state requires operator action.
Rollback is executable selection only, never database restoration.

## Verification record and residuals

Offline installer tests: **44 passed**, also independently rerun by the operator.
They cover recovery fault injection, path safety, non-clobbering installation,
Coordinator exclusion/PID protection, reputation drop-in preservation, and Redis
master/command restrictions. Run from the deployment worktree:

```sh
python3 -B -m unittest discover -s deploy/multi-chain/gcp/endcap-handoff -p 'test_*.py' -v
```

Runtime is **not all green**. The operator ran 13 targeted tests in both debug
and release modes; all passed in both modes.
Expanded candidate release tests had **161 passed, 6 failed**, with **2 long tests
excluded**. All six failures are unchanged Coordinator paths. A debug rerun on
exact baseline `876c1432da302941acfba8485763e3f0549ec284` reproduced the same six
failures with the same assertions; five other selected baseline tests passed.
This is debug baseline reproduction, not a full baseline release-suite result.
The six known failures remain recorded, not silently waived or called passing.

Operator-reported read-only live capture at **2026-10-09 06:40:41 UTC** observed
checkpoint **208170** consistently on all three Edges and unchanged Processor
PIDs. The operator uploaded the binary, installer and manifest for pre-commit
checking; this is staging/capture evidence, not proof of activation. No secrets,
raw logs or private captures belong in this repository.

This rollout does **not** fix late Gatherer behavior or historical 39, and does
not repair historical state. Existing reputation-policy residuals are unchanged.
No DB migration, score reset, cross-Realm reputation synchronization or broader
runtime repair is included. Actual post-activation EndCap behavior and remote
service health remain operator verification obligations.
