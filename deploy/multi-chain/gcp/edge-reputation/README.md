# Existing-testnet Edge reputation update (2026-10-08)

This is an Edge-only component hotfix, not a fresh deployment. Never run the
fresh-deploy reset scripts for this update. Do not replace Workers, Processors,
Services, Genesis, contracts, proving keys or the `/opt/parth/current` link.

## Source identity

- Runtime topic: `fix/worker-reputation-replay-20261008`, commit `1c0863fa`.
- Minimal live candidate: `hotfix/edge-reputation-20261008`, commit `876c1432`.
- Candidate base: Coordinator Edge `72da74e3`; includes the deployed Realm IMT
  predecessor fix `5f1d3070` and the reviewed reputation/replay patches.
- The candidate deliberately excludes newer stable-branch dependency, circuit,
  Faucet and Processor changes. Its Cargo manifests/lockfile, Genesis gitlink and
  circuit sources are unchanged from the Coordinator Edge baseline.
- Reputation remains namespace/Realm-local. Only signed-fetch replay reservations
  share a global Redis key: old Worker signatures do not bind a Realm, so a
  per-Realm replay key would allow the same request to be spent in another Realm.

## Build

Use `psy-bookworm-builder:nightly-2025-09-20`, Rust nightly-2025-09-20,
Go 1.22.3, `PSY_NETWORK=testnet`, initialized pinned `psy-genesis`, and:

```sh
cargo +nightly-2025-09-20 build --offline --locked --release -p psy_node_cli
```

Do not use `target-cpu=native` or AVX-512 flags for this cloud Edge binary.
Build from the clean immutable candidate, not the current deployment checkout.
Record the complete source SHA, image identity and binary SHA256 in the package.

## Package and guarded activation

The root-owned private package contains `rollout.py`, `psy_node_cli`, and
`manifest.json`. The manifest contains `source_commit`, `binary_sha256`,
`installer_sha256`, and `baseline` (the exact JSON returned by `capture`).
The runtime baseline includes only configuration hashes, process IDs and public
checkpoints, not secrets. Reputation snapshots are private operational data and
must stay on the server, outside Git.

```sh
sudo python3 /path/to/rollout.py capture
sudo python3 /path/to/rollout.py check
sudo python3 /path/to/rollout.py apply --unit realm-0
# Observe actual pickup/prove/submit and checkpoint progress for 15 minutes.
sudo python3 /path/to/rollout.py apply --unit realm-1
# Verify again before proceeding.
sudo python3 /path/to/rollout.py apply --unit coordinator
```

The checked-in updater is intentionally pinned to the observed old artifacts.
Do not loosen guards or refresh the baseline merely to bypass a failure.
All three Edge processes must use the same Redis database, a synchronized clock,
and a 30000 ms worker ACK wait. Independently inspect actual NATS consumer
`ack_wait` (30000000000 ns) before activation.

The script never modifies Redis records or restarts a Processor. It adds only its
owned `99-worker-reputation-20261008.conf` drop-in. Rollback removes that override
and restarts only the selected Edge after validating the preserved configuration.
Check Processor PIDs and status after every Edge restart: a downstream Processor
can fail on a transient Edge outage even though the script did not restart it.
Stop rollout for operator investigation if this happens.

```sh
sudo python3 /path/to/rollout.py rollback --unit realm-0
```

## Verification and limits

Before activation, require a reviewed staged diff, a release build, focused
reputation tests, real Redis replay tests and deployment fault-injection tests.
After activation verify the running `/proc/<PID>/exe` hash, unchanged protected
configuration and other-service PIDs, stable restarts, advancing Coordinator and
Realm checkpoints, and a real successful Worker submission for each updated Edge.
An idle Realm does not prove the repaired submit path has been exercised.

Do not manufacture an expired lease or penalize a production Worker to test the
new policy. Zero-score probation, signed-fetch replay and invalid-proof behavior
are tested in isolation. Natural live activity establishes integration evidence.

Two nonblocking review residuals remain: reputation settlement and its reward CAS
are not one Redis transaction, and delayed old claims can extend recovery after a
cooldown. This release does not claim to solve either case. No cross-Realm score
synchronization or manual score reset is performed.

Keep the full-cohort `source-versions.env` unchanged for this partial rollout.
Store the observed component artifact identity and verification next to this file
after successful activation; the full-cohort manifest alone is not a live inventory.
