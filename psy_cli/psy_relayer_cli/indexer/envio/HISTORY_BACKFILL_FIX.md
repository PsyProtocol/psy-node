# Envio 2.32.10 history-backfill restart repair

Base: `e77f48ca3e54aa0ae978aa24f0a2c25d6264ab22`, the deployed timestamp
candidate on stable `32bfd3da`. This is a framework SQL compatibility repair;
no Genesis, ABI, circuit, Rust dependency, signing key or wire format changes.
No other live component should be replaced from this baseline.

## Failure

On 2026-09-28, Envio failed a persistence batch with PostgreSQL error 42804:
`column "envio_change" is of type envio.envio_history_change but expression is of type integer`.
systemd's restart policy restarted the process but could not repair the SQL.

The additive migration appends `block_timestamp` after the entity columns in
Deposit, but after `checkpoint_id, envio_change` in its history. Envio's original
`INSERT INTO history SELECT e.*, 0, 'SET'` assumes both physical orders match.
The error occurs even when the SELECT produces no rows because PostgreSQL checks
types before executing it. The initial migration tests missed this framework
history-baseline insertion path; their hand-written column mappings were valid.

## Repair and persistence

`scripts/patch-history-backfill.py` pins Envio 2.32.10 and the original file
hashes, validates all package copies before writing, and atomically replaces
files instead of editing shared pnpm hardlink inodes. Unknown versions/layouts
fail closed. It changes only `EntityHistory.res` and `EntityHistory.res.js`.

The query converts each source row to the history table's named PostgreSQL
composite using `jsonb_populate_record`. Fields map by name, and the resulting
row follows the destination table's actual order. PostgreSQL NUMERIC remains
exact: no values pass through JavaScript Number. NULLs, arrays, existing
history, checkpoint 0 and SET semantics are preserved. No extra database query
or blockchain RPC is added. SQL identifiers are quoted/escaped. The generated
IO API, history names, pruning and rollback interfaces are unchanged.

The source patch survives ReScript rebuilds. `postinstall` applies it, the
`codegen` script reapplies it around generation, and `start` verifies it before
running Envio. If scripts are disabled or deployment invokes `pnpm exec envio`
directly, the deployment must explicitly apply and verify the patch. Python 3
is required. Preserve the separate deployed `RpcSource` polling/metering patch
and its 12000 ms interval; this script does not modify it.

## Validation

Use a disposable local PostgreSQL container, never production:

```sh
# Before applying: demonstrates the actual installed runtime's original error.
HISTORY_TEST_PORT=<local test port> HISTORY_EXPECT_UNPATCHED=1 node tests/history-backfill.integration.cjs
python3 scripts/patch-history-backfill.py
python3 scripts/patch-history-backfill.py --check
HISTORY_TEST_PORT=<local test port> node tests/history-backfill.integration.cjs
python3 tests/test_history_patch.py
node tests/deposit-timestamp.test.cjs
# Rebuild generated/ with pnpm exec rescript build, then repeat check + tests.
```

The PostgreSQL test covers migrated physical layout, all Deposit fields,
large NUMERIC, legacy NULL, repeated/duplicate/missing IDs, generated rollback
selection, actual history pruning, transaction rollback, other entities,
quoted identifiers, arrays, reordered history columns, fresh layouts and long
history names. Fixtures are confined to newly created test schemas and removed
after the run. It uses the same prepared query path as Envio's runtime.

## Narrow rollout / rollback

1. Review and commit the exact source candidate before computing release
   provenance. Publishing and advancing maintained branches remain separate.
2. Record the live release, process identity, three-chain DB progress and full
   Deposit rows. Back up the database and changed application files. Preserve
   `.env`, `config.yaml`, all generated schema/handler files and RPC patch hashes.
3. Prepare an isolated copy of the current live release. Add only the reviewed
   package scripts, patch script and this source provenance; apply/check history
   patch without reinstalling dependencies or running codegen against live DB.
4. Verify on a disposable clone of the live DB inside a rollback-only transaction
   using the real installed backfill function; preserve every Deposit field.
5. Stop only `parth-envio.service`, switch to the prepared compatible release,
   and resume normally. Never use `--restart`, `envio dev`, reset, truncate,
   column reorder, schema recreation or a fresh-deployment installer.
6. Verify stable PID/restart count, resumed and advancing checkpoints on all
   three chains, no failed DB batches, unchanged existing deposit fields and
   timestamp coverage. Leave Services, relayer, proxies and workers untouched.

Keep the previous application release and the fresh backup for investigation.
Switching back to the unpatched timestamp release reintroduces this crash;
it is not a healthy fallback. Do not restore the pre-backfill database over
new deposits or drop timestamp columns. If activation fails, stop this Envio
writer and investigate/forward-fix rather than repeatedly running broken SQL.
