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
and `PSY_BRIDGE_READER_TICK_MS=200`. Its stdout (the tracing log) and stderr go to
`reorg-reader-*/reader-<database>.log` in the OS temp directory; failures print
the log tail. The test kills exactly that child at the end (and when it moves to
the next database). The temp directory is removed at the end; set
`REORG_TEST_KEEP_LOGS=<dir>` to keep a copy of the Envio log and the Reader logs
there. Each Reader check prints how long the Reader took to reach `last_count`
after the test started waiting for it.

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
   At each such count, `/v1/tree/proof` for every leaf below it returns that root,
   the replay's leaf hash and all 32 siblings equal to the replay's
   `DepositTreeNode` values (a node the replay never wrote is the empty subtree
   of its level).
3. `/v1/deposits/by-address`, `/by-index`, `/by-tx`, `/prefix`,
   `/v1/withdrawal-claims` and `/v1/explorer` equal the registered SQL
   (`deposit_list_offset_page`, `deposit_by_deposit_index`, `deposit_by_tx_hash`,
   `global_to_local_probe` plus `foreign_prefix_probe`, `withdrawal_claims_by_nullifier`,
   `explorer_feed_current`, `explorer_latest_deposits`) run with `psql` on the same
   database. The SQL text is read from `psy_bridge_reader_api/sql/queries.sql` and
   its `$n` parameters are bound as typed literals per the `-- params:` comments.
   Each field the SQL row carries is compared as a string with the Reader's field.
   - `/by-address`: per shield address (and one unknown address), pages
     (limit, offset) = (100, 0), (100, 1), (100, total), (100, total+5), (1, 0),
     (1, total-1), each compared ordered, row by row, with the SQL page
     (`deposit_list_offset_page` is `LIMIT 100`; a limit-1 page is its first row),
     plus `total`.
   - `/by-index`: every index, plus one past the end (must be `null`).
   - `/by-tx`: ordered (`deposit_index` desc) against `deposit_by_tx_hash`. Known
     coverage gap: every scenario puts one deposit in each transaction, so the
     multi-row order of a shared transaction is not exercised here.
   - `/prefix`: every target 0..=last_count. Targets `last_count + 1` and
     `last_count + 1000`, ahead of the index, go to `/v1/tree/root`: the answer
     is the root at the chain-local count `global_to_local_probe` resolves them
     to, never `count_not_indexed`.
   - `/explorer`: see below.
4. Across a reorg `revision.epoch` is greater than the baseline (scenarios 1, 2b
   and 3a, where Envio rolls back; 3b needs no rollback and checks no epoch).
5. After the rollback no response served in the final state contains a discarded
   `tx_hash`: transactions of the orphaned forks that are not also canonical (a
   re-included deposit can have the same hash). `/by-tx` for a discarded hash and
   `/v1/withdrawal-claims` for a discarded nullifier must return nothing.

### Explorer ordering

The Reader's explorer deposits are compared ordered, field by field, against the
query they replace, `explorer_feed_current` (`ORDER BY block_number DESC, id DESC
LIMIT 100`, bound by `chain_id`); the SQL defines the tie order. As a second check
the same rows are compared as a set against `explorer_latest_deposits`
(`deposit_index` desc within a `chain_index`, a different order). The batch list is
checked by count (`FinalizedBatch` is empty in this test).

## Acceptance coverage

Acceptance 5 and 8
are covered at the Reader level only. The Services part is plan 2.

## Reader-only bench (`reader_bench`)

`psy_bridge_reader_core/examples/reader_bench.rs` is an open-loop load generator
for the Reader's internal API (the Python wallets top out near 2,000 req/s).

```
CARGO_TARGET_DIR=$HOME/.cache/psy-bridge-reader-target-tree \
cargo run --release -p psy_bridge_reader_core --example reader_bench -- \
  --url http://127.0.0.1:<port> --token-file <token> \
  --rates 2000,5000,10000,15000 --step-secs 120 \
  --mix A4 --addresses-from status --out bench.json
```

- Open loop: request `i` of a step is due at `i / rate`; a request is never
  delayed by an earlier response. Latency is measured from the due time and
  only for successful (HTTP 200) responses: failed requests, including
  timeouts, are excluded from the latency percentiles and counted in `errors`
  (`timeouts` is also reported separately). `send_lag` is the moment just
  before `client.request` minus the due time, so worker queueing in a
  CPU-bound generator shows up; `emit_lag` is the scheduler's own lag (tokio's
  1 ms timer gives a ~1 ms floor). A step with send or emit lag p99 over 5 ms,
  or one that hit `--concurrency-cap`, has `"valid": false` with the reasons
  listed. Throughput counts only successes that completed inside the send
  window, and generator CPU covers the same interval.
- To find saturation, keep raising the rate: `--rates 20000,25000,30000,...`
  until a step is invalid or the Reader's errors/latency climb. The bench
  raises its open-files soft limit to the hard limit and warns if that is
  under 4x `--concurrency-cap`. Pin it away from the Reader (`taskset`), and
  away from the SMT siblings of the Reader's CPUs too
  (`/sys/devices/system/cpu/cpuN/topology/thread_siblings_list`; on a
  16-core/32-thread host CPU `n` and `n+16` share a core, so a Reader on 26-29
  shares cores with 10-13).
- Host check. Without `--reader-pid` the bench warns on stderr and every
  step carries `"host_check": "not performed"`: contention on the Reader's
  CPUs is then not checked, and a stall caused by another process cannot be
  told apart from a Reader result. With `--reader-pid <pid>` (Reader on the
  same host) each step carries `"host_check": "performed"` and `host`, with
  one entry per second of the send window under `host.per_second`:
  `reader_cpu_cores`; `reader_runq_wait` (seconds per second the Reader's
  threads were runnable but not running, from `schedstat`; `null` when
  unreadable); `foreign_cpu_cores`, an estimate: busy time of the Reader's
  allowed CPUs (irq, softirq and steal included) minus the Reader's own CPU
  time; `sibling_busy_cores`, load from any process on the SMT siblings of
  those CPUs; and, in a second over either limit, `top_other_process` (pid,
  comm, cores): the busiest process on the whole host other than the Reader
  and the bench, from one `/proc/*/stat` scan per second (host-wide, not
  per CPU). The step is invalid when:
  - foreign load exceeded `--max-foreign-cores` (default 0.5) in any second:
    another process took CPU time on the Reader's own CPUs. The reason notes
    when the Reader is not pinned (its allowed CPUs are every online CPU);
  - sibling load exceeded `--max-sibling-cores` (default 1.0) in any second:
    the Reader's physical cores were shared, which slowed its CPU-bound
    work (claim proofs cost about 45% more with busy siblings);
  - host samples are missing ("host samples missing (n/expected)"): always
    when the sampler thread panicked or a read of the Reader's `/proc`
    entry failed (the error is appended), and otherwise when fewer than
    `max(1, step_secs - 1)` seconds were sampled. With no sample, the
    `max_*` and `mean_*` fields are `null`, not 0.
  An unpinned process on a shared host can stall the Reader's lanes (first
  the 4-slot `claim_proof` lane), and such a step must not be read as a
  Reader result. The bench warns when its own CPUs include the Reader's CPUs
  or their siblings. When the online CPU list or the SMT topology cannot be
  read, it warns and the step records the gap under
  `host.host_check_degradations` (`is_reader_unpinned` is then `null`, or
  `sibling_cpus` is empty and sibling load is not checked).
- Mix `A4` (by request count): 70% `by-address`, 10% `by-tx`, 10%
  `withdrawal-claims` (10 nullifiers), 5% `tree/root`, 5% `tree/proof`; or
  `--mix by_address=70,by_tx=10,claims=10,root=5,proof=5`. `by-address` limits
  are drawn from 1/10/50/100 with weights 40/30/20/10 (offset 0); the output
  states the counts sent per limit.
- `--addresses-from status`: reads `/v1/status` (first ready chain; `count` is
  its `committed_count`) and `/v1/explorer` (its 100 newest deposits give the
  shield addresses and tx hashes). `--addresses-from file.json`: a file
  `{"chain_id":..,"chain_index":..,"count":..,"addresses":[..],"tx_hashes":[..],"nullifiers":[..]}`
  (`nullifiers` optional). Without nullifiers the bench uses 1,000 synthetic
  ones that no claim matches, so `withdrawal-claims` returns empty reads.
  `tree/root` and `tree/proof` use the fixed `count`, with a random `leaf`.
- `--out` is rewritten after every step and starts with a `config` object (url,
  cap, timeout, step_secs, start time, git sha, open-files limit). Each step
  also has `per_second`: sent, ok, errors, latency p50/p99 and send-lag p99 for
  every second (by due time), and `peak_inflight`. Per step: rate, sent, ok, errors keyed
  `status:code` (or `transport:*`, `timeout`, `cap`), ok throughput, p50/p95/p99
  per endpoint, response-byte histogram (upper bounds 256 B to 64 KiB) plus
  mean/max bytes per endpoint, generator CPU (`/proc/self/stat`), lag
  percentiles and the `valid` flag.
- Unit tests: `cargo test -p psy_bridge_reader_core --example reader_bench`.
