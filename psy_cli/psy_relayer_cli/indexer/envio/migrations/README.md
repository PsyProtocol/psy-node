# Deposit block timestamp: state-preserving upgrade

Scope: persist the timestamp already present on `DepositRecorded.event.block`.
No new RPC, historical scan, circuit/ABI/Genesis change, or cross-service cache.
`Deposit.block_timestamp` is nullable Unix seconds (`BigInt` / PostgreSQL
`NUMERIC`). Existing rows and rollback history remain null. New/replayed events
store their own block timestamp; it is not the ingestion or wall-clock time.

## Source provenance and compatibility

- Envio candidate base: stable `32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`.
  Its schema.graphql, schema.ts and handlers.ts were byte-identical to the live
  Envio input files when checked on 2026-09-28. Envio remains pinned at 2.32.10.
- Services companion candidate base: live standalone
  `7c1e1f61673949bb7343529d4dd51d66f631d236`, not the newer multichain branch.
  Only the bridge handler changes. Preserve its existing Cargo pins/lockfile,
  old-token compatibility, ABI metadata and shared HTTP-client fix.
- No maintained branch or deployment manifest has been advanced by preparing
  these candidates. Commits, forward ports, publication and rollout need their
  respective review/authorization. Do not replace other running components with
  the stable baseline: it does not contain all their independent hotfixes.

## Services behavior

The deposit-list and deposit-claim-proof queries request `block_timestamp`.
When populated, Services formats it into the unchanged RFC3339 `created_at`
response without an L1 timestamp RPC. For null/absent legacy values, Services
keeps the existing RPC lookup (one lookup per distinct missing block per list
request). There is no new persistent cache or bulk backfill.

During a rolling upgrade against the old Hasura schema, Services retries the
legacy query only for the exact `validation-failed` error naming the missing
`Deposit.block_timestamp` field. Other errors still fail closed. Old Services
can keep reading the augmented schema because the new field is additive.

## Future rollout (NOT performed by this change)

1. Record current Envio and Services release identities, config and polling
   patch. Back up the Envio database and Hasura metadata; record per-chain
   progress, deposit counts and helper-tree metadata. Retain compatible old
   binaries/bundles. Do not alter keys, start blocks, contract addresses or the
   12-second RPC polling policy.
2. Build Envio from the reviewed source with the **real existing configuration**
   and run codegen in an isolated release directory. The
   `config.timestamp-test.yaml` fixture is offline-only and must never be
   deployed. Preserve the live `RpcSource` polling patch when installing
   dependencies. Inspect the generated `Deposit` and `envio_history_Deposit`
   definitions: both must have nullable numeric `block_timestamp`.
3. Stop only the Envio writer. Confirm the exact target database and schema.
   Apply `001-deposit-block-timestamp.sql` using `psql -X`,
   `ON_ERROR_STOP=1`, and an explicit `envio_schema` variable. It only adds the
   nullable column to the existing Deposit and, if present, its rollback history
   table. It aborts on lock timeout or an incompatible existing column. Do not
   run against Services' own database.
4. Reload Hasura metadata and confirm the nullable field is queryable with the
   Services role/credentials. Switch to the new generated Envio bundle and use
   the ordinary `envio start` **without `--restart` / `-r`**. Never use `envio dev`,
   a reset migration, or any fresh-deployment installer that clears schemas.
   If Envio requests a reset or rejects existing state, stop the rollout and
   investigate; do not bypass state checks or edit hash records blindly.
5. Confirm it resumes saved checkpoints and all three chains progress. Confirm
   a naturally arriving new deposit has its chain block timestamp, with existing
   rows/counts/helper-tree state preserved. This must not manufacture a deposit.
6. Deploy the reviewed Services artifact. Verify both API responses keep their
   existing fields/types and correct timestamps. With a controlled RPC mock or
   approved bounded tracing, confirm indexed rows do not call
   `eth_getBlockByNumber` for timestamps and null legacy rows still work.

The optimization affects populated/new rows first. Old rows still consume RPC
until separately backfilled or replayed through normal indexing; do not claim
that this eliminates all `eth_getBlockByNumber` traffic or a fixed CU percentage.

Rollback: retain the additive nullable columns and history; switch back to the
previous compatible application bundles using the ordinary resume path. Do not
drop columns, wipe checkpoints, or restore an old database snapshot over new
deposits merely to roll back this metadata optimization.

## Local validation

From the Envio directory:

```sh
pnpm install --ignore-scripts --lockfile=false
node tests/deposit-timestamp.test.cjs
pnpm exec envio codegen --config config.timestamp-test.yaml
```

Run `tests/deposit-timestamp-migration.sql` with `psql -X` only in a disposable
PostgreSQL database. It checks existing rows/progress preservation, idempotence,
new timestamp inserts, old-history null restoration and history-disabled setups.
This fixture creates dedicated schemas and intentionally performs no cleanup on
an existing database; destroy only the disposable test database afterward.

Validated locally on 2026-09-28:

- Two handler/schema tests passed, including all three L1 chain IDs.
- Envio 2.32.10 codegen completed; the generated timestamp is nullable BigInt
  and the generated database type is nullable NUMERIC.
- The SQL fixture passed against an isolated PostgreSQL 17.5 instance.
- Companion Services bridge tests: 48 passed, 0 failed, 0 ignored, including
  PostgreSQL/Redis integration tests. Both actual API routes returned unchanged
  timestamps with zero `eth_getBlockByNumber` calls for indexed rows.
- Native Services release build and Rust formatting checks passed.

No production migration, service restart, commit, push or maintained-ref update
was performed. Build the eventual deployment artifact with the existing target
platform release process; these checks are not a live rollout verification.
