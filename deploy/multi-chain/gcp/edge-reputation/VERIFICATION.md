# Completed Edge rollout, 2026-10-08

All three Edge services now run the reviewed minimal candidate. Realm 0 was
observed for over 30 minutes before proceeding. The temporary pause for the
operator-requested SYSTEM proxy route migration ended before Realm 1 activation.
This is an Edge rollout acceptance, not a complete three-chain bridge E2E audit.

## Published source and deployment tooling

- `release/testnet-stable`: `1c0863fa5c2aa48197e9d820d0271633d70fd6cb`.
- Minimal live candidate: `876c1432da302941acfba8485763e3f0549ec284`.
- Deployment integration: `b23fb0bd` (four reviewed deployment files plus stable
  source integration; **not** the source used for the live binary).
- Binary SHA256: `55abcc1bee0683e3529ab9f3e86c6711d0492f12999ec0a2f20ad20584ee4702`.
- Installer SHA256: `f63ca3761cb58934c8819025d9c37e0224c0a6add1bd0050256569c2702494a6`.
- Host package: `/opt/parth-edge-reputation-package-876c1432` on `gcp-cp-ce`.
- Release: `/opt/parth-edge-reputation/20261008-876c1432da30`.

## Runtime evidence

| Edge | Activation (UTC) | Running PID | Source |
| --- | --- | --- | --- |
| Realm 0 | 08:24:29 | 1700568 | 876c1432 |
| Realm 1 | 08:56:47 | 1702734 | 876c1432 |
| Coordinator 0 | 08:59:05 | 1703518 | 876c1432 |

All three running executable hashes match the binary SHA256 above, with
`NRestarts=0`. Protected configuration fingerprints and all non-Edge process IDs
remain equal to the original baseline, including all three Processors.

At 08:56:27 UTC Realm 0 logs contained 20 recorded claims and 20 completed Worker
queue ACKs since activation. At 08:58:46 UTC Realm 1 contained 7 claims and 7 ACKs
since activation. Neither observation matched error/panic/expiry/invalid-proof/
settlement-failure records. These are log counts, not exactly-once audits.

Coordinator worker completion is verified from x2 Worker logs, not those Realm
log counters (the Coordinator emits different messages): at 08:59:49 UTC, job
197585 `AggUserRegisterDeployContractsGUTA` and job 197581
`GenerateRollupStateTransitionProof` were picked, proved and successfully
submitted. Further successful submissions continued through 09:00:37 UTC.

Realm 0's initial readiness checkpoint was `197240`. After all activations,
all three were `197578` at 08:59:37 UTC. A subsequent guarded check returned
Realm 0/Realm 1 `197591`, Coordinator `197592`; these are sequential RPC samples,
not simultaneous snapshots. Chain progress continued after the Coordinator
restart.

## Authorized transaction acceptance

Exactly one minimal `simple_transfer` (one raw unit) was submitted from each
existing E2E account, with no automatic retry, new registration or cross-chain
transaction. No private keys or raw proof payloads are included here.

| Source Realm | User | Nonce | Confirmed checkpoint | Transaction hash |
| --- | --- | --- | --- | --- |
| 1 | 1916928 | 5 -> 6 | 197573 | 237910d334d9b6ecd4d3bc7da633dc4ec4adeb70641b428b6283b601e9387268 |
| 0 | 868352 | 9 -> 10 | 197585 | 50d49c86aa4415200f0154a1fdefc4afb27b7c9e93072c2007fd38dda98b34ae |

x2 Realm 1 job 499310 `GUTASingleEndCap` was picked/proved/submitted at
08:58:36 UTC (313.9 ms proving). Realm 0 job 487225 followed the same complete
path at 09:00:09 UTC (134.2 ms proving). Private intent/result files remain in
`tmp/edge-reputation-rollout-20261008/private-smoke/` outside this repository.

## Maintenance-window symptoms

x2 Worker fetches saw transient connection errors during Realm 0 restart,
08:24:31-08:24:32 UTC; the Worker processes were not restarted. Do not mistake
these bounded maintenance-window errors for continuing rejection by the new
reputation policy. Realm 1 also had transient fetch connection failures at
08:56:49-08:56:50 UTC, followed by successful real work.

Coordinator Edge restarted at 08:59:05 UTC and logged RPC startup at 08:59:24
UTC. The operator's checkpoint-probe-failed alert at 16:59:19 UTC+8 falls inside
this approximately 19-second RPC initialization gap and subsequently resolved.
Processors remained running with their original PIDs. Existing
`CONTRACT_HEIGHT_DEBUG` WARN-level diagnostics still occur; do not describe the
deployment as having no warnings at all.

## Guards and tests

- 36 reputation tests, 52 Core tests, 6 Memory tests, 2 real Valkey replay tests
  and 34 deployment fault-injection tests passed.
- Release built in the pinned Bookworm image; target-host libraries resolved.
- Live NATS worker consumers: ACK wait 30000000000 ns; Edge default 30000 ms.
- Genesis, configuration, proof setup and all unaffected services unchanged.
- Reputation snapshots stay private in the release's per-Edge `rollback/` directories.
- No database clear/reset or manual reputation score changes were performed.
- x2 and the two reachable Aliyun Realm hosts reported synchronized clocks.
  The operator confirmed other stopped Aliyun hosts are intentionally offline.

No production lease was deliberately expired and no invalid proof was injected.
Zero-score probation, replay rejection and invalid-proof policy are covered by
isolated regression tests, not destructive production experiments. Longer-term
observation remains necessary. Do not rerun apply or overwrite the backups;
use the guarded per-Edge rollback command if needed.
