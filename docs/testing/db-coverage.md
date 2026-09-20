# Database crate coverage

Run from the repository root:

```sh
git submodule update --init psy-genesis
rustup component add rust-src llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
make test-db-coverage
```

The runner requires Docker and Python 3. It tests Scylla, NATS, then Redis
**separately and sequentially**: start only that service, run only that crate,
export its independent coverage report, and remove the service before continuing.
It uses Redis 7.4, NATS 2.10 with JetStream, and Scylla 2026.1.5 on dynamically
allocated loopback ports. Scylla and NATS data live in tmpfs; Redis persistence is
disabled. Compilation defaults to two jobs and test execution uses one thread.

Run just one module with:

```sh
make test-db-coverage-scylla
make test-db-coverage-nats
make test-db-coverage-redis
```

Each invocation has its own 80% gate and only starts its matching service. Scylla uses two CPUs, 4 GiB RAM, and a disposable tmpfs data directory.
The runner removes only the containers it created, including after a failure.
It does not reuse the development network's databases.

For iterative development against a disposable stack you already own:

```sh
PSY_TEST_SCYLLA=127.0.0.1:19042 ./dev/run-db-coverage.sh scylla --existing
```

`--existing` requires the selected endpoint (all three when no module is selected)
and does not manage service lifecycles.
Never point it at a persistent development or production database: the tests
create random keyspaces, keys, streams and consumers. Full-run isolation is
provided by disposable containers; not every legacy test removes its namespace.

## Coverage contract

Each of `psy_node_scylla`, `psy_node_nats`, and `psy_node_redis` must independently
reach **at least 80% line coverage**. This is the default-feature compiled
production source, including the Scylla table implementations and store adapters.
Files which are not declared as Rust modules are not compiled and do not appear
in LLVM's coverage map. No compiled production modules are excluded.

- All three crates' library tests and integration tests run, including ignored
  database tests. Explicitly enabled live tests fail if their endpoint is absent.
- Integration test files and dependencies are excluded from the per-crate gate
  by selecting only the corresponding `crate/src/` paths.
- Inline unit test modules use `cfg_attr(coverage_nightly, coverage(off))` so their
  assertions and fixtures do not inflate production coverage.
- The runner cleans previous instrumentation/profile artifacts before running.
  It does not combine evidence from old worktrees or previous failed attempts.
- A missing crate, empty coverage map, failing test or sub-80% crate fails the
  command. The threshold uses unrounded counts, not displayed percentages.
- This is a line coverage gate, not a branch-coverage or full fault-tolerance
  guarantee. It exercises real single-node services rather than multi-node
  consistency, failover or network-partition scenarios.

Outputs under `target/db-coverage/`:

| File | Evidence |
|---|---|
| `summary.md` | Separate line counts, percentages and gate result per crate |
| `<module>/coverage.json` | LLVM per-file line/function/region summaries |
| `<module>/tests.log` | Complete build and test results |
| `provenance.txt` | HEAD revision/tree, tracked changes relative to HEAD (empty on clean checkouts), and tool versions |
| `<container-id>.log` | Service logs, captured before teardown |

The GitHub workflow `db-coverage.yml` runs the same command for `multi_chain` PRs,
pushes and manual dispatch, and uploads the outputs even after failures. Private
dependency fetches use the existing `PSY_RELEASE_REPOSITORY_TOKEN` secret, as in
the release workflow. Fork PRs without that secret cannot run this job.

## Regression scenarios

- Scylla: checkpoint history, object serialization and packed rows, batch
  boundaries, bidirectional mappings, IMT predecessor order and tree isolation,
  bridge chain isolation, signed counters, overflow, tag proofs, production
  schema creation and preparation, and sparse leaf dump overwrite history.
- NATS: publishing variants, ACK modes, completion barriers, consumers,
  empty queues, timeouts and queue/KV operations.
- Redis: binary/typed KV and queues, FIFO behavior, concurrent producer/consumer,
  wrong-type and command-timeout propagation, proof field TTL, pending/realm
  isolation, deletion, empty values and corrupt payloads.

The existing Scylla dump stress test now has a deterministic CI mode with six
batches crossing the 128/256/512 boundaries and guaranteed overwritten leaves.
Set `PSY_SCYLLA_STRESS=1` to retain the larger 100-batch stress workload.

Tests exposed three implementation defects repaired alongside the tests:

1. Scylla's signed counter adapter cast negative increments to `u64`. It now
   applies signed deltas through the same compare-and-set loop, clamps at zero,
   and rejects values above `i64::MAX` without mutating stored state.
2. Two Scylla Merkle batch writers built zero statements for a full first batch
   of 256 nodes. Full and partial batches now both construct matching statements.
3. Redis blocking consumers could occupy a pooled connection needed by their
   producers. Each blocking wait now uses a dedicated connection, whose router
   is aborted on completion, error or future cancellation. This adds one
   connection setup per blocking wait. The raw BLPOP command preserves the
   distinction between server nil (`None`) and command/transport errors.

The shared checkpoint-tree test helper also now reads leaf index 1 after writing
checkpoint 1, matching the production append-by-checkpoint-ID contract.

To test the coverage gate itself:

```sh
python3 dev/check-db-coverage.test.py
```
