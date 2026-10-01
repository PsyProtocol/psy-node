# Stateful node hotfix candidate, 2026-10-01

This is source integration, not an activation record or a fresh deployment.
Use the compatible `release/testnet-stable` runtime integrated by the merge
containing this document. Never build this live-chain update from `multi_chain`.

Pinned runtime candidate: `be16bf76859b0de7d88dd56bb45e4c6d65fc3b3c`,
published to `release/testnet-stable`. Upstream integration:
`f462ed56530acacdc1669803aad26d229153e2db` on `multi_chain`.
The deployment merge's runtime patch is byte-for-byte identical to the reviewed
stable diff (SHA256 `1dd183198bd95d20042cb1bf712ae6f142a436c31962b248939f75d14748d5fd`).

## Included fixes

| Source | Selected changes |
| --- | --- |
| 6a308225 | Remove proof field TTL; keep pending consumers alive, unlimited worker redelivery, validate consumer state against NATS |
| 590d6a53, 65f201e8, 5b3c38e0, 175b04db | Realm GUTA resend and tests |
| dcedb5db, 432ca06a, ac6cb62d | Coordinator Edge in-flight admission guard and tests |
| a8faea69 (upstream 1b95969b) | Validate contract layout-proof endpoints before admission, preserving the live old ABI |
| 3dd65ba8 (selected hunks only) | Contract deploy/update backup recovery and focused tests |
| b7cd7b8f (selected hunks only) | Bound NATS fetches by the requested total allowance |
| 65ace190 (selected hunks only) | Historical Scylla dumps select visible versions before deduplication |
| Integration regression fix | Preserve the deploy/update union of changed Merkle nodes during backup recovery |

The full upstream test commits were not imported. Old-ABI test fixtures were
adapted to hash-valued deployers. The Edge realm-ID bound now rejects IDs equal
to the Realm tree capacity as well as larger IDs. Contract circuit construction, Genesis, method names,
signing magic and backup wire layout are not changed by this candidate.

## Verification recorded on the stable candidate

- `psy_node_common` focused library selection: 124 passed. Excluded
  `guta_planner::realm_guta_planner_tests` and `register_user_gatherer::tests2`.
- Isolated NATS: 6 live-surface tests and 4 barrier/lifetime tests passed.
- Isolated Redis: 3 compare-and-set tests and 1 proof-lifetime test passed.
- Isolated Scylla: 4 historical/serialization integration tests passed.
- In-memory GUTA admission: 4 integration tests passed.
- In-memory compare-and-set: 6 unit tests passed.
- `cargo build --locked -p psy_node_cli --bin psy_node_cli` passed locally
  (debug, Arch, PSY_NETWORK=localhost; not a Bookworm release artifact).
- `cargo check --locked -p psy_user_cli --bin psy_user_cli` passed. A release
  user CLI build and workspace-wide all-targets check were not performed.
- The new mixed deploy/update recovery regression failed before the union fix
  and passed afterward on both stable and upstream candidates.
- Baseline comparison at unmodified 32bfd3da reproduced the same 5 failing
  `register_user_gatherer::tests2` tests and Scylla `get_best_batch_size` failure.
  Broad suites are NOT claimed green. Long GUTA planner tests were stopped
  before completion; their coverage remains unverified. A Redis timeout test
  also failed during broad testing; no baseline comparison was completed for it.
- First Scylla integration attempts failed because the disposable instance
  was unavailable / rejected the nearly-full host disk. Final runs used an
  isolated tmpfs-backed instance, not production databases.

Local evidence: `/tmp/psy-hotfix-stable-common-final.log`,
`/tmp/psy-hotfix-stable-common.log` (initial broad run),
`/tmp/psy-hotfix-stable-adapters.log`, `/tmp/psy-hotfix-stable-scylla-final.log`,
`/tmp/psy-hotfix-stable-memory-final.log`, `/tmp/psy-hotfix-stable-memory-unit.log`,
`/tmp/psy-hotfix-stable-node-build.log`, `/tmp/psy-hotfix-stable-user-check.log`,
`/tmp/psy-hotfix-backup-regression-before.log`,
`/tmp/psy-hotfix-main-backup-final.log`, `/tmp/psy-hotfix-baseline-register.log`,
and `/tmp/psy-hotfix-baseline-scylla.log`. These temporary files are not durable
release artifacts; archive evidence with the eventual immutable binary manifest.

No live node restart, full-stack fault injection, production rollout or
end-to-end transaction acceptance was performed for this integration.

## Release boundary

The top-level `source-versions.env` still describes the previous full cohort.
It is intentionally NOT repinned: it couples runtime and relayer and cannot
represent this partial update or the optimized live Worker/Proxy exceptions.
Do not use that full deployment runner to activate these changes. Before a
separate rollout, create an immutable component manifest with the exact stable
commit, Bookworm build inputs, binary SHA256 and the preserved live artifacts.

Do not replace Services/indexers, relayer, wallet, SDK, Worker or Prove Proxy
from this base. In particular, this stable tree does not consolidate their
per-component allocator, cache or AVX optimizations.

## Required rollout gates

1. Inventory running binaries, overrides, active pending IDs, consumer delivery
   states and field expirations. Preserve Genesis, contracts, setup, keys and
   all databases, processor working directories, checkpoint_tree.bin and local
   gatherer backup volumes. Agree protected backups with the operator before
   activation. No reset, reindex, queue purge or full-deploy clear step.
   Inspect mixed deploy/update pending batches: old backups can contain a stale
   update start root and will fail the corrected reader. Drain such work or
   prepare a separately validated recovery; do not rewrite headers blindly.
2. Build and verify the actual Linux target artifact. Local debug compilation
   and adapter tests are not production artifact or fingerprint attestations.
   Record the exact PSY_NETWORK/config inputs; verify compiled magic equals
   live 0x1337CF514544CF69 and verify live circuit fingerprints. Do not select a
   different network block merely because the environment is called testnet.
3. Run an isolated real Processor/Edge/Worker witness-repair recovery test.
   Require unchanged reward ownership, one durable commit, preserved sibling
   proofs and progress of the following batch. Synthetic adapter recovery is
   not equivalent to this acceptance test.
4. Confirm Valkey EVAL is permitted. Record maxmemory, maxmemory-policy and memory
   headroom: proof eviction is unacceptable, while noeviction still needs enough
   headroom to avoid rejected writes. Verify checkpoint-owned cleanup and alarms.
   Upgrade all active Coordinator Edges before starting any Realm with resend.
   Validate REALM_GUTA_RESEND_AFTER_CHECKPOINTS >= 2 before startup
   (default 10; a first rollout may explicitly choose 50).
5. Coordinate CP, Realm and Edge updates and inventory all proof writers/queue
   clients. Old clients must not reinstall expiry or consumer lifetime settings.
   Plan compatible optimized Worker updates separately if their adapter usage
   requires it; never replace them with the stable baseline worker blindly.
6. Untouched legacy proof fields keep their existing TTL. Prepare a separately
   approved, pending-ID-scoped expiry migration, completed before activation
   unless the operator explicitly accepts the remaining expiry window.
   Expired proofs do not reappear.
   Raising MaxDeliver after a job has exhausted it does not revive delivery.
   Missing consumers must not be blindly recreated over rewarded jobs.
7. Verify all L2 heights and per-chain bridge progress, recovery and admission
   behavior, error/restart counts and retained-data growth after activation.
   Alert on sustained worker redelivery, NATS consumer growth and Redis memory.

Keep rollback binaries and configs. Binary rollback has not been exercised for
this combined candidate; verify consumer ACK/delivery positions before and after
any rollback. GF is the persistent per-submitting-Realm in-flight record in the
Coordinator temporary store, not a per-job history or a timed lock.
The GUTA GF record is ignored by old code,
but a rollback also loses its admission protection and can restore old expiry
policies. Height rollback requires explicit reconciliation of future GF records;
do not treat binary rollback as a database repair.

See `docs/pending-batch-lifetime.md` for the lifetime contract and limits. An
already Error-state processor, missing proof or exhausted delivery still needs
an explicit recovery plan; this code does not claim to repair such state on its
own. All live changes require the operator's separate rollout approval.
