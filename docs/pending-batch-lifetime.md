# Pending Batch Lifetime

## Contract

A repairable witness failure must not destroy its batch's recovery inputs.
While the Processor is waiting, successful sibling proofs, the current worker
consumer and pre-created successor consumers remain available. Correcting the
failed witness lets the original unacknowledged job retry, after which the
existing publication barrier and dependency checks allow the next level.

This is ownership-based retention, not an increase from a ten-minute timeout
to a longer timeout. It does not automatically generate a correct witness.

## Original Candidate and Integration

- Base: `release/testnet-stable`, `32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`.
- Branch: `fix/pending-batch-lifetime-20260929`.
- Redis proof retention follows the approach of existing local commit
  `207af626d3758af7adf3e97d5a284ae91ada3303`, reviewed without merging its older
  runtime ancestry. This patch retains the shared proof-writer helper.
- No circuit, Genesis, ABI, serialization, reward calculation or worker identity
  changes. The only Cargo.lock change adds a workspace test dependency.
- These identifiers describe the original September 29 candidate, not the head
  of every branch carrying this document. On October 1 the operator authorized
  integration into multi_chain and compatible stable/deployment branches.
  Source integration does not authorize live deployment.
- The October 1 set also imports NATS fetch-limit fixes from b7cd7b8f and
  historical Scylla dump fixes from 65ace190, with nats_live_surface and
  merkle_contract tests. The September 29 results below do not cover these
  additional changes or the combined integration tree.

## Changes

1. Both Fred proof writers use HSET without HEXPIRE. The existing Processor
   `delete_all_proofs_for_pending_id` calls reclaim previous committed batches.
   Reads are not keepalives: an unreferenced sibling must survive too.
2. Production gathering and worker consumers have no inactivity deletion.
   The deprecated `NATS_*_INACTIVE_THRESHOLD_MS` settings cannot re-enable it;
   nonzero settings log a warning. AckWait settings are unchanged.
3. Worker `max_deliver` is unlimited. Failed proving does not ACK; successful
   verified submission still controls ACK. This prevents silent exhaustion
   while waiting for an operator's witness repair, but does not reduce the CPU
   cost of repeatedly proving an unchanged invalid witness.
4. The generic `QStandardQueueBase::ensure_consumer` now uses the same
   server-validated implementation as the inherent method. Previously it
   returned success for a cached handle even if the consumer no longer existed.
5. Existing consumers' lifetime settings update in place, including on a cache
   miss. ACK position, delivery position and identity are preserved. Effective
   server settings are checked; server-imposed expiry must not silently win.
6. Publication sequence barriers are unchanged. A missing consumer during an
   outstanding barrier remains an error, not false success. This patch does NOT
   recreate it while waiting on that barrier. In contrast, ensure_consumer can
   recreate a missing consumer before publication, using DeliverPolicy::All.
   Do not call that path blindly on a legacy subject containing rewarded jobs:
   admission-time recreation is not a reward-preserving recovery procedure.

## Verification

On 2026-09-29: six existing queue unit tests passed. Five integration tests
passed three consecutive final runs against isolated NATS 2.11.17 and Redis
7.4 containers, with nonzero legacy inactivity environment settings supplied.

- All publication API variants retain their sequence barriers.
- Existing consumer lifetime updates preserve creation time and ACK positions.
- A failed task keeps redelivering beyond a short legacy limit after migration
  before exhaustion; idle successor/gathering consumers survive a repair pause.
- Cold-cache updates and stale-cache consumer recreation before publication.
- Combined Redis/NATS dependency pipeline: child A succeeds, child B fails
  repeatedly, only B's witness changes, B succeeds, parent and successor run.
  No client restart, successful-child replay or failed-job republication.
- Both proof writer APIs have field TTL -1. Rewriting a legacy expiring field
  clears its TTL. Explicit cleanup is idempotent and isolated by pending ID.

The combined test uses synthetic proof bytes, NOT cryptographic proofs. It does
not start a Coordinator, Realms, Edge or Worker and is NOT full-chain acceptance.
Short test inactivity thresholds model a repair delay; Redis TTL is asserted
directly, rather than claiming a real hour-long soak was performed.

Run only against isolated local test servers:

```sh
cargo +nightly-2025-09-20 test --offline --locked \
  -p psy_node_nats -p psy_node_redis --lib

NATS_INTEGRATION_URL='nats://127.0.0.1:<isolated-nats-port>' \
REDIS_INTEGRATION_URL='redis://127.0.0.1:<isolated-redis-port>' \
NATS_EPHEMERAL_INACTIVE_THRESHOLD_MS=200 \
NATS_WORKER_INACTIVE_THRESHOLD_MS=200 \
cargo +nightly-2025-09-20 test --offline --locked \
  -p psy_node_nats --test worker_queue_barrier \
  -p psy_node_redis --test proof_lifetime -- --include-ignored
```

## Remaining Release Gates

- Independently review the runtime diff, then run real Coordinator/Realm/Worker
  fault injection with a recoverable bad witness. Require unchanged Processor
  PIDs, dependency verification, original reward ownership, one committed result,
  and progress of the following batch after witness correction.
- Verify both Realm inclusion and Coordinator commit before declaring end-to-end
  success. The adapter test does not exercise either commit path.
- Build the target-platform node binary. This session compiled/tested the adapter
  crates only, not a deployable node release.
- Inventory existing pending batches before rollout. Old untouched Redis fields
  retain their existing TTL until explicitly migrated; expired data cannot be
  restored by this patch. Do not indiscriminately rewrite proofs or reward tags.
- NATS 2.11.17 testing showed that changing MaxDeliver AFTER exhaustion does not
  revive that delivery. Detect and reconcile such legacy jobs separately; do not
  delete/recreate active consumers as a shortcut.
- Upgrade all relevant Processor/Edge users of the shared queue/proof adapters
  coherently. Mixed old/new binaries can reintroduce old expiry settings.
- An already parked Error-state Processor, erased stream data, or lost Redis
  data is outside this candidate's automatic recovery guarantee. Recovery from
  these requires persisted batch manifests and reward-preserving replay, not
  blind retries of the entire block.
- Existing explicit cleanup is best-effort. Failed cleanup or abandoned batches
  can leave retained objects. Monitor storage and retry cleanup only when durable
  checkpoint ownership proves the objects are no longer needed; never introduce
  an age-only collector for pending work.

Do not deploy this candidate merely because the adapter tests pass. Preserve
the live component-specific proxy hotfixes and the stable branch agreement.
