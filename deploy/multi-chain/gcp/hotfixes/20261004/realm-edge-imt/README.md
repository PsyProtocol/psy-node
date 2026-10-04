# Realm Edge IMT predecessor hotfix

## Live artifact, not a full-cohort upgrade

On 2026-10-04, only the two Realm Edges on `gcp-cp-ce` were upgraded.
The deployed binary was built from the dedicated old-chain hotfix
`5f1d3070cdc127715c4ad899afcc3bdcf46ded2b`, based on
`32bfd3da73b4f05b9dfe2f3aa2f6b2278aa2a3b6`.
See `live-artifact.json` for immutable provenance.

The maintenance integration accompanying this record carries only the same
three-file query-ordering fix into `release/testnet-stable` and the deployment
branch. That combined source tree is NOT the source of the already deployed
binary. It also contains previous maintenance fixes for other components.
Do not rebuild or replace the entire network from this record.

The full-cohort `source-versions.env` remains unchanged: its coupled runtime
and Relayer pins cannot describe per-component hotfixes. This component record
does not reconfigure that full-deploy runner or authorize its use on live state.
Keep all other component manifests and exceptions.

## Fault and repair

The previous-bucket Scylla query returns keys in descending order. The old
Realm Edge reversed them again, choosing a smaller, invalid predecessor.
The fix preserves DESC order while retaining historical birth filtering,
missing-leaf handling and error propagation. No circuit, ABI, Genesis, signing
magic, dependency pin, database schema or persistent format is changed.

The existing LIMIT 5 before filtering remains a limitation; this patch does
not claim to resolve every possible historical predecessor lookup failure.

## Verified recovery

All timestamps below are UTC; local time is UTC+8.

- The frozen checkpoint 141342 query for user 524288, contract 2 now returns
  predecessor **18577**, not **18204**, through both the actual Relayer Realm
  endpoint and the public Realm0 endpoint.
- At 02:52:32, L1 proved/pending deposit counters were Sepolia **944/944**,
  BSC **125/125**, Base **133/133**. Previously outstanding: six Sepolia and
  one Base deposits. This confirms bridge recording, not recipient claiming.
- All three L1 finalized checkpoints advanced from **142108 to 142139**,
  then **142165** at 02:54:28. New Sepolia deposits had arrived by that second
  observation, so pending increased to 946; the old backlog was not recurring.
- Relayer PID **1749968**, started 2026-10-03 09:04:46, was unchanged.
  It recovered by automatic retry, without manual transaction resubmission.
- Edge0 PID **1486212**, Edge1 PID **1486361**: active, NRestarts=0.
- Installer checks preserved unrelated service PIDs and protected config hashes.
  Shared `/opt/parth/current` was not changed. No database writes or resets were
  performed by the deployment procedure.
- Realm1 Edge restarted at 02:47:41. Worker `SendRequest` errors in that short
  restart window were transient: x2 Realm1 Worker subsequently proved and
  submitted jobs at 02:53:51 and 02:54:54 without a Worker restart.

Successful release build, target-host linking/CLI smoke checks and the targeted
`psy_node_core` release regression (1 passed) preceded activation. The original
handoff also records an isolated Scylla query test and offline witness replay.
These results do not imply a full workspace test pass or resolution of unrelated
Services capacity issues. Insertion-path IMT lookup-miss logs still occurred.

## Installed layout and rollback

Release: `/opt/parth/edge-hotfix/20261004-imt-5f1d3070`.
Each Realm Edge has its own `95-imt-predecessor-20261004.conf` drop-in, retaining
the existing launcher and overriding only `PARTH_TARGET_DIR`.
The release contains `before.json`, `result.json`, the verified installer,
candidate binary and an independent `rollback-target` binary directory.

Only if a separately assessed regression requires rollback:

```bash
ssh gcp-cp-ce 'sudo -n python3 -I /opt/parth/edge-hotfix/20261004-imt-5f1d3070/install.py rollback'
```

This restarts the two Realm Edges using preserved artifacts. It does not revert
database state. Do not rerun the apply action against an existing release.
No Relayer, Processor, Coordinator Edge, Worker, Services or Proxy restart is
required for this fix.
