# Live Envio end-to-end test of the Bridge Reader

The test is the existing Envio reorg test with an opt-in flag. It lives in
`psy_cli/psy_relayer_cli/indexer/envio/tests/reorg/`:

- `run-reorg-test.cjs` runs Anvil, Envio 2.32.10 and a throwaway PostgreSQL
  database through the reorg scenarios, and with `--with-reader` also the Reader.
- `reader-check.cjs` starts and stops the Reader and holds the assertions.

Without `--with-reader` the test behaves exactly as before.

## Prerequisites

- `anvil` and `cast` (Foundry), and `psql`.
- A PostgreSQL server reachable through `ENVIO_PG_HOST`, `ENVIO_PG_PORT`,
  `ENVIO_PG_USER` and `ENVIO_PG_PASSWORD`. The test creates and drops its own
  databases; never point it at a shared server. A throwaway container works:
  `docker run -d --rm --name reorg-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55447:5432 postgres:16.13`.
- `pnpm install` done in `psy_cli/psy_relayer_cli/indexer/envio`.
- Node 22 or older for Envio. Set `REORG_TEST_NODE_BIN_DIR` to a Node 22 `bin`
  directory (for example
  `/home/peter/git/bridge_zilong/psy-node-jtmb-bridge/logs/jtmb-bridge-toolchain/node/bin`);
  it is put first on `PATH` for the Envio process only.
- The Reader binary, built outside psy-node's own `target/`:
  `CARGO_TARGET_DIR=$HOME/.cache/psy-bridge-reader-target cargo build -p psy_bridge_reader_cli`.

## Run

```
cd psy_cli/psy_relayer_cli/indexer/envio
ENVIO_PG_HOST=127.0.0.1 ENVIO_PG_PORT=55447 ENVIO_PG_USER=postgres ENVIO_PG_PASSWORD=pw \
  PSY_ENVIO_FRESH_REORG_PARENT=1 REORG_TEST_NODE_BIN_DIR=<node22 bin> \
  node tests/reorg/run-reorg-test.cjs \
  --with-reader $HOME/.cache/psy-bridge-reader-target/debug/psy-bridge-reader
```

A path that is missing or not executable fails at once with
`reader binary not found: <path>`, before Anvil or Envio start.

The Reader runs as a child process against the test's database with
`PSY_BRIDGE_READER_LISTEN=127.0.0.1:<free port>`, a token file (mode 0600) in a
temp directory, `PSY_BRIDGE_READER_DATABASE_URL`, `PSY_BRIDGE_READER_DB_SCHEMA=public`
and `PSY_BRIDGE_READER_TICK_MS=200`. Its stderr goes to
`reorg-reader-*/reader-<database>.log` in the OS temp directory; failures print
the log tail. The test kills exactly that child at the end (and when it moves to
the next database).

## What is asserted

A baseline is taken once Envio has indexed fork A (scenario 1) or the initial sync
(scenario 3): the Reader's `/v1/status` shows `ready` and its chain `deposit_count`
equals `DepositTreeMeta.last_count`, and `revision.epoch` is recorded. After the
final state of scenarios 1, 2 (with `PSY_ENVIO_FRESH_REORG_PARENT=1`, i.e. 2b), 3a
and 3b the test waits (30 s) for the Reader to reach `last_count` again, then checks:

1. Root at `last_count` equals `DepositTreeMeta.poseidon_deposit_tree_root`
   (and so does `/v1/status` `tree_root`).
2. Root at every count `1..=last_count` equals the root of a replay of the first
   `count` canonical deposits through `handlers.ts` (the test's handler harness).
3. `/v1/deposits/by-address`, `/by-index`, `/by-tx`, `/prefix`,
   `/v1/withdrawal-claims` and `/v1/explorer` equal the registered SQL
   (`deposit_list_offset_page`, `deposit_by_deposit_index`, `deposit_by_tx_hash`,
   `global_to_local_probe` plus `foreign_prefix_probe`, `withdrawal_claims_by_nullifier`,
   `explorer_latest_deposits`) run with `psql` on the same database. The SQL text
   is read from `psy_bridge_reader_api/sql/queries.sql` and its `$n` parameters are
   bound as typed literals per the `-- params:` comments. Each field the SQL row
   carries is compared as a string with the Reader's field (the SQL returns
   `amount` and `block_timestamp` as text or numeric, the wire as number or string).
   `/by-address` also checks `total` and the row order (`chain_local_deposit_index`);
   `/by-index` asks one index past the end (must be `null`); `/prefix` is asked at
   every target 0..=last_count.
4. Across a reorg `revision.epoch` is greater than the baseline (scenarios 1, 2b
   and 3a, where Envio rolls back; 3b needs no rollback and checks no epoch).
5. After the rollback no response served in the final state contains a discarded
   `tx_hash`: transactions of the orphaned forks that are not also canonical (a
   re-included deposit can have the same hash). `/by-tx` for a discarded hash and
   `/v1/withdrawal-claims` for a discarded nullifier must return nothing.

### Explorer ordering

The SQL `explorer_latest_deposits` orders by `deposit_index` desc within one
`chain_index`; the Reader's explorer orders by `(block_number desc, id desc)`
(the current Services feed, filtered by `chain_id`). The test therefore compares
the two deposit lists as sets keyed by `deposit_index`, and separately checks the
Reader's own order rule on its list. The batch list is checked by count
(`FinalizedBatch` is empty in this test).

## Acceptance coverage

Acceptance 5 and 8
are covered at the Reader level only. The Services part is plan 2.
