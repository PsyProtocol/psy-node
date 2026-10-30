# Realm IMT Coverage Deployment

Authorized state-preserving rollout on October 30, 2026. Runtime source:
`48a490e2b4101f546d162fa10bb2d5214d1fdb4b`, the compatible integration of
`a9b9ac38`, including the reviewed final-value admission correction.
See [source integration](IMT-COVERAGE-INTEGRATION-20261030.md) and
[live source/artifact mapping](admission-live-release.json).

## Release And Scope

Only six Realm Edges and six Realm Processors were updated. The first activation
was at 03:37:57 UTC; the last Processor passed startup, loop and catch-up checks
at 03:53:46 UTC. Realm0 was completed and accepted before Realm1 was changed.

- Node binary SHA256:
  `4edb97b04c1c8543376eb6b2bf69c298cf51892ae678c23a0537237895ab1bf0`.
- Immutable executable:
  `/opt/psy-core/hotfixes/realm-imt-admission-48a490e2/psy_node_cli`.
- Build used a clean, read-only checkout of the published runtime commit and the
  existing pinned Bookworm/R3 recipe. It retained the external R3 config and
  compiler contract bundle rather than adopting another Genesis from a gitlink.
- Generic build output contains five CLIs, with maximum GLIBC 2.34; only
  `psy_node_cli` was installed. Its manifest hash is
  `49927fbbf9bfb60bde71b7f9e4cea4594cfba458897360848786db493ae1de9b`.
  Fresh-deployment approval flags in that generic build manifest remain false;
  the state-preserving acceptance here is not approval to start a fresh network.
- Network remains `testnet`, magic `0x1337CF514544CF69`, real Plonky2.
- Genesis SHA256 remains
  `f839b453ab130c29998620c4c5d4bf9a30ce341a2e7c480aa9dbd8ed10902173`.
- No database, queue, pending ID, key, signing configuration, L1 contract or
  setup material was cleared or regenerated. Database routes remain private.

The Coordinator Processor and all three Coordinator Edges retained PIDs
3669112, 2847782, 2847863 and 2847947. Relayer retained PID 72999. Workers,
Services/indexers, Guardians, Faucet, USER/SYSTEM proxies and clients were not
released or restarted by this rollout.

## Procedure And Rollback

The reviewed `update_unit.py` gained profile `imt-admission` in `f9211698`.
Its SHA256 is
`30410806c0ec46c20f4e2e5cddc5bae87f9a4b61a1dbc1a6cfd8ec78c47408f2`.
It is installed root-owned at
`/opt/psy-maintenance/realm-imt-admission-20261030/update_unit.py`.

1. All twelve units passed source/binary/configuration/host preflight before the
   first restart. Candidate bytes were staged on all five private hosts first.
2. Updated Realm0 Edges sequentially, then its Processors sequentially. Every
   Edge passed its own RPC check. Every Processor passed its startup marker,
   processing-loop and checkpoint catch-up gate before the next replacement.
3. Required actual Realm0 proving, P2P certification, submission and canonical
   commits before beginning Realm1. Repeated the same sequence for Realm1.
4. Verified final process hashes, restart counts, checkpoints, fixed-checkpoint
   user proofs, public RPC access and protected component identities.

Existing base units and overrides 70/80, optional 90, and Processor 95 were
retained. Only `96-realm-imt-admission-20261030.conf` was added. Do not replace
the shared R3 executable, because unrelated services still use it.

For an inspected, running candidate unit, use the same helper with `rollback`,
`--profile imt-admission`, its exact unit name, and the candidate SHA above.
It removes only the owned 96 override. Edge rollback returns to PR30; Processor
rollback returns to the immediately previous IMT metadata binary. Unexpected
configuration drift is a stop condition, not permission to delete overrides.
Retain `/var/backups/psy-realm-imt-admission-20261030/` on each host. A binary
rollback does not rewind database counters or recover previously lost inputs.

## Acceptance And Remaining Issues

- Release tests: common 687 passed, zero failed, one existing ignore and the
  unchanged long random stress test filtered; client data 196 passed. The four
  new Edge coverage tests are included in common. Helper tests: 26 passed.
  Independent runtime and deployment-helper reviews approved the exact changes.
- All twelve running executable hashes match the release, all are active, and
  all restart counters are zero. All six Processors reported checkpoint 18768
  during the 03:55:55-03:55:57 UTC sample.
- Realm0 canary completed real GUTA proving/P2P submission and canonical commits
  18713, 18714 and 18715. Realm1 validator 3 completed commits 18761 and 18763.
  These are natural workload observations; no new test transaction was sent.
- Nine post-ready Realm0 canary proof queries passed. Thirty final explicit-
  checkpoint queries across both Realms and all validators matched Coordinator
  user roots, with no errors. Public Coordinator/Realm0/Realm1 samples advanced
  together from 18764 to 18775.
- Exploratory reads during validator 3 startup included three requests ahead
  of its local head; they failed before readiness and are not counted as passes.
- Existing transient `Local database is stale` and `MissingHistoryProof` retries
  still occurred. Realm0 validator 1 also logged a gatherer FastForward failure
  during abort/re-entry at 03:50:14 UTC; it stayed alive and subsequently committed
  18749. These recovery diagnostics remain follow-up work, not evidence that all
  Realm stability problems have been eliminated.
- No new baseline-replay/record-coverage invariant failure was observed in the
  bounded sample. Processor hosts retained approximately 5.8-6.5 GiB available
  memory and Edge hosts approximately 2.2 GiB at final identity sampling. This
  is not a peak-load, latency or long-term memory benchmark.
- The separate Relayer `DepositMismatch` and RPC 429 conditions remain visible.
  This deployment does not fix native-token mapping or refund/replay a deposit.
- Client-data source is integrated, but SDK, wallet, Faucet and proxy binaries
  were not upgraded; do not claim their no-op output fix is live.

Local evidence is under `tmp/realm-imt-coverage-rollout-20261030/`: immutable
build manifest/logs, all-unit preflight, per-unit activation/readiness JSON,
current-invocation logs, public samples, and fixed-checkpoint proof readbacks.
