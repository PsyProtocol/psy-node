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

Live result will be appended after activation and observation.
