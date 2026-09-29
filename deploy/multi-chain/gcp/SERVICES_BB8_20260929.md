# Services-only Redis pool fix

Operator authorized CI integration and online deployment on 2026-09-29.
Source maintenance branch: PsyProtocol/psy-services `release/testnet-stable`.
Runtime fix: `53a8b330ac9f4d62ba117a088fd60b46f9ae2d01`.
CI integration: `3e0dac657a0a1231459d179d567920dca9247f19`.
The latter changes no Rust source or dependencies.

The immutable component override is `releases/services-bb8-20260929.json`.
It applies only to Services, not to the original whole-node release manifest.
Do not use the full fresh-deployment runner or the four-unit indexer updater.

## Validation

- Exact reviewed source files and binary hashes checked against the build record.
- New CI entrypoint: `bash scripts/test-cache-pool-regression.sh` creates its own
  loopback-only PostgreSQL/Redis, waits for PostgreSQL TCP readiness, runs all
  five tests serially, and stops/removes both containers on exit.
- CI has an independent regression job so another test job failing cannot skip it.
- Local Bookworm run of that entrypoint: 5 passed, 0 failed. ShellCheck and
  Bash syntax passed. Release build repeated at final source commit; SHA
  remains `b51b8b282c3d05b82c6efedd466338b4189825da74908545febb04d3e6e6ed40`.
- No dependency, migration, Genesis, circuit, ABI, RPC credential, key, Nostr,
  or existing cache-format change. Preserve the separate Envio history fix.

## Procedure

Stage the manifest, `deploy/gcp/remote/update-services-only.py`, and the verified
binary on `gcp-cp-ce` under `/tmp/psy-services-bb8-staged/`. Use `manifest.json`
and `psy-services` as their remote filenames. Check hashes after copying.

```sh
ssh gcp-cp-ce 'sudo -n python3 /tmp/psy-services-bb8-staged/update-services-only.py /tmp/psy-services-bb8-staged/manifest.json /tmp/psy-services-bb8-staged/psy-services'
# Only after preflight succeeds and the operator authorizes activation:
ssh gcp-cp-ce 'sudo -n python3 /tmp/psy-services-bb8-staged/update-services-only.py /tmp/psy-services-bb8-staged/manifest.json /tmp/psy-services-bb8-staged/psy-services --activate'
```

The helper checks the actual baseline executable, rollback executable, source
manifest and candidate hash. It preserves release ownership (including protected
directory modes), checks execution as the real service user, keeps all other
release files and indexer provenance, then changes only PSY_SERVICES_HOME and the
independent Services symlink. Only `parth-psy-services.service` is restarted.
Candidate acceptance requires the running executable hash AND `/health/ready`.
Other unit PIDs/states, node release and unrelated environment hashes must stay
unchanged. A failure rolls back only Services; concurrent env changes block
automatic rollback and require operator inspection.

Protected recovery evidence and saved original env are on CP under
`/var/lib/parth-services-maintenance/20260929-bb8-3e0dac6-b51b8b28/`.
Do not restore databases or clear Redis for rollback. Retain the old immutable
release. A failed activation may leave a prepared release/audit directory; the
helper intentionally refuses blind retries.

## Acceptance

Observe normal traffic for at least five minutes. Check readiness, dashboard
and transaction-hash latency, new bb8 errors, Nostr live state, three realm and
coordinator indexers, and checkpoint progress. Do not run CLIENT PAUSE or the
regression fixture against online Redis. No transaction E2E is authorized by
these read-only acceptance probes.

## Live result

Activated at 2026-09-29 03:21:29 UTC (11:21:29 UTC+8). Running PID 1239222,
NRestarts=0, executable SHA matches the pinned artifact. Protected activation
result confirms the other 12 CP-host unit PIDs/states and environments unchanged.
The three indexer PIDs remain 787475 / 787481 / 787483, all active.

Read-only samples at 30-second intervals, 03:23:00 through 03:28:00 UTC:

- Readiness, dashboard and transaction-hash queries: 33/33 HTTP 200.
- Readiness reports database and cache healthy throughout.
- Dashboard loopback latency: 3.74-8.24 ms; transaction hash: 1.95-4.60 ms.
- Coordinator height: 80000 -> 80027; realm0: 79999 -> 80027;
  realm1: 79999 -> 80026. Sequential samples can differ by one checkpoint.
- Since activation through 03:28:00: 0 bb8 error records, 0 Services ERROR
  records, 0 dashboard cache warnings, 0 Nostr relay-unavailable warnings.
- Nostr live_connected=true, reconnects/history_failures/lagged_notifications=0;
  persisted timestamp advances from 1790652118 to 1790652433.
- Public readiness/dashboard/hash spot checks: HTTP 200, TTFB 88/74/57 ms.
- Three 2-second post-rollout pidstat samples: Services average CPU 0.50%.

These are normal-traffic observations, not a production load test or transaction
E2E. The old process's cache happened to be healthy just before activation;
the earlier 60-second latency was an incident sample, not the immediate baseline.

## Final CI and source refs

Both `fix/redis-pool-starvation-20260929` and `release/testnet-stable` are pushed
through `e2e61e059067e739be764d0e1a067119ebfe8805`. Changes after deployed source
`3e0dac657a0a1231459d179d567920dca9247f19` are CI-only:

- `358b40a`: register two already-existing independent Explorer feed routes in
  the coverage classification manifest. The same manifest failure was reproduced
  on the old runtime baseline; no coverage assertion was disabled.
- `e2e61e0`: run CI automatically on stable-branch pushes. This does NOT deploy.

https://github.com/PsyProtocol/psy-services/actions/runs/36516927640 succeeded:
unit tests, database tests, Redis pool regressions, format/clippy and route
manifest. The optional coverage job was skipped by its existing event policy.
An earlier manual run at 3e0dac6 failed the old route manifest check; do not use
that run as the final CI verdict. The live manifest intentionally continues to
identify the exact deployed source, not a later CI-only branch tip.

Rollback release remains
`/opt/parth/psy-services/releases/6ce3c2ac1d73-timestamps-93f18343`.
Restoring that release requires changing only the saved Services environment,
the independent symlink, and restarting Services. It restores the old bug too;
retain the fixed release and evidence when investigating any separate failure.
