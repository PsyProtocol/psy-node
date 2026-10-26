# Faucet cancellation hotfix

Scope: only `gcp-faucet` / `parth-faucet-server.service`. Preserve all ten existing
operator accounts, keys, config, Genesis, ABI, circuits, and every other service.
Do not use a fresh-deployment runner for this change.

## Source and compatibility

- Live Faucet baseline: `32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`.
- Narrow deployed candidate: `153b8ca6594c4b6f78c2832577e219bf4ece5e64`.
- Stable-branch backport: `b105752e` (same patch, newer maintenance ancestry).
- Candidate SHA256: `af79853480889e6a01142b84167aba82fcef861fa38de7e17d170b650e7baa74`.
- Original SHA256: `1b87493f71125294ce9451e1022a90e8445532bb19b5daa264186e57e6b945fa`.

The three changed runtime files are Faucet request lifecycle, lock guards and
tests. Cargo.lock, Genesis, proving code and contract definitions are unchanged.
The candidate intentionally does not deploy other accumulated stable hotfixes.
The bundle source manifest remains the shared baseline; this component override
is an additional live version, not a replacement for every `psy_user_cli`.

The HTTP waiter no longer owns claim completion. A detached task keeps recipient
and operator ownership until proving/submission returns, records successful
submission even if the client disconnected, and releases guards. Do not add an
outer timeout that unlocks an operator while its blocking prover is still alive.

## Build and test

```bash
bash deploy/multi-chain/gcp/hotfixes/20261001/faucet/build.sh \
  /path/to/clean/narrow-candidate /path/to/artifact
python3 -m unittest discover \
  -s deploy/multi-chain/gcp/hotfixes/20261001/faucet -p test_rollout.py -v
```

The build uses the pinned Debian image, offline dependencies, the unchanged
lockfile and Genesis gitlink, portable CPU target, and existing CF69 magic. Six
runtime regressions include HTTP disconnects, cancellation during blocking work,
mutual exclusion, error and panic cleanup. Three deployment tests cover launcher
PID transitions, configuration mismatch and readiness timeout.

## Rollout

Upload `psy_user_cli`, `manifest.json`, `SHA256SUMS` and `rollout.py` into a private
staging directory on gcp-faucet. After checking uploaded hashes:

```bash
sudo python3 rollout.py /absolute/path/to/staging-directory
```

The installer requires the original executable hash and exact original argv. It
creates an immutable release under `/opt/parth/faucet/releases/`, adds only
`95-faucet-cancel-safe.conf` to the Faucet unit, and restarts only that service.
It preserves both existing EnvironmentFiles. A final environment file enables
Faucet lifecycle INFO logs while keeping other logging at WARN.

Readiness requires the running executable SHA and all original public Faucet
config fields to match. Relayer PID/hash and four protected configuration hashes
must remain unchanged. Failure rolls back only this drop-in, unless unexpected
configuration changes make rollback unsafe. Never overwrite the shared binary.

The installer intentionally refuses a second activation. Inspect the saved
`rollout-state.json` before attempting a retry. To roll back a verified deployment,
check no one has changed the drop-in/config, remove only this drop-in, daemon-reload
and restart only Faucet; then verify the original executable hash and readiness.

## Verification and limits

Check `faucet operator acquired/released` pairs, actual operator transactions and
checkpoint advancement, not merely systemd active. With separate permission, use
the existing E2E recipient 868352 for one claim, disconnect the HTTP client during
work, wait for the original result, and repeat the same request in the same window.
It must return `already_submitted=true` and the same transaction hash. Confirm
chain inclusion and Services indexing before declaring full business recovery.

This is not crash-durable idempotency. Restart loses the in-memory claim cache;
timeouts with an uncertain submission result still require reconciliation. The
patch does not solve permanently hung downstream RPCs or all wallet concurrency
issues. It fixes the independently reproduced HTTP-cancellation lock leak.
