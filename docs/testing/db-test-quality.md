# Database test quality

The 80% production-line coverage gate is a minimum execution check. A passing
percentage does not establish correct behavior. Tests also need independent
expected results, adversarial data, and sensitivity to plausible regressions.

## Contracts checked against real services

| Module | Observable contract |
|---|---|
| Scylla | Each writer persists its own complete batch; checkpoint reads return the requested historical version; missing objects remain missing; caller key order is preserved; chain/tree IDs isolate data; negative increments clamp and overflow leaves stored state intact; asymmetric Merkle proofs verify against the expected root. |
| NATS | Every published payload arrives in order without omissions/duplicates; a limited read leaves later messages available; ACK modes change server-side unacknowledged counts; unacknowledged worker jobs redeliver; completion waits for ACK; zero-limit reads leave messages available. |
| Redis | Binary and typed values round-trip exactly; FIFO and namespace isolation hold; command errors are distinct from an empty queue; blocked consumers cannot exhaust producer connections; cancelling a wait releases its blocked connection; proof fields carry a bounded TTL. |

Scylla KIV writers use disjoint IDs and are read back immediately. Checkpoint
writers use different values at each checkpoint and history is reread after later
writes. These choices prevent an earlier successful write from masking a later
no-op. Tag-tree left/right children use different tags and hashes, so swapping
children or returning the wrong proof cannot pass through symmetric fixtures.

NATS assertions compare complete expected payload sequences and explicit ACK
state, rather than only nonempty results or minimum lengths. This exposed a real
limited-read defect: the byte dump could fetch a full batch, return only the
requested prefix, and leave the remainder delivered but unavailable to the next
read. The fetch now respects both limits, and zero limits return before fetching.

## Directed fault checks

`dev/check-db-test-sensitivity.py` checks a bounded selection of plausible faults:

- Scylla: replace each of the three KIV batch writers with a successful no-op;
  replace the checkpoint chunk writer with a successful no-op.
- NATS: restore overfetch beyond the caller's limit; make NoAck send an ACK.
- Redis: use a shared pool connection for a blocking consumer; convert command
  timeouts into an empty queue result.

Run one module at a time against its **disposable** service, with the endpoint
variable used by the coverage runner:

```sh
NATS_INTEGRATION_URL=nats://127.0.0.1:14222 python3 dev/check-db-test-sensitivity.py nats
PSY_TEST_SCYLLA=127.0.0.1:19042 python3 dev/check-db-test-sensitivity.py scylla
REDIS_URL=redis://127.0.0.1:16379 python3 dev/check-db-test-sensitivity.py redis
```

The script temporarily changes only the selected implementation file, saves its
original bytes, and restores them in a `finally` block. It shares the coverage
runner's worktree lock. Each case must pass before injection, fail inside the
named test after injection, then pass again after restoration. Compilation errors,
hangs, and service failures in the baseline do not count as detected faults.
Results, original-source backups, and all three logs per case are saved under
`target/db-test-quality/<module>/`. SIGINT/SIGTERM restore the source; after an
uncatchable process kill, use the saved backup and inspect the diff before running
anything else. Do not edit the selected source concurrently with this check.

This sample is not an exhaustive mutation score. These tests do not establish
multi-node consistency, service restart recovery, network-partition behavior,
long-duration durability, or production throughput. Single-node tmpfs tests
especially cannot prove disk crash durability. The proof TTL check verifies the
assigned lifetime; it does not wait the full ten minutes for natural expiration.
