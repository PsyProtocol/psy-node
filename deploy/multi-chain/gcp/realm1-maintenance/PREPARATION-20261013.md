# Realm1 preparation evidence

This file records preparation, NOT a completed migration.

The subsequent migration completed at 2026-10-13 22:20 UTC; see
[ROLLOUT-20261013.md](ROLLOUT-20261013.md) for final evidence and limitations.

## Before pre-copy

- Source original Realm1 PID 1672024, Coordinator PID 1259828, active.
- Target Realm0 PID 15182, active; Realm1 inactive, disabled, no permit.
- Source running Realm1 executable and target on-disk executable SHA256 match:
  bda82589c26bd914ead5bd77b8e6de136e0703797d0135fcddf3c2ff8dd8bb03.
- Genesis SHA256 matches:
  569e58c901cdf7bd9edfc25bab70c4b0aafe0f5d2ec782781290d963ae63b710.
- Wrapper SHA256 matches:
  192b22fe65fd9f49c2bde75e16fd81293edaf8cff03f9c68aedd324c96dde568.
- Realm1 env file SHA256 matches:
  99128d6359f6da09da3f3192601449b625d2dd897e297df98f150502d5de82eb.
- Seven common env values compared by hash, zero differences after excluding
  intentionally relocated PARTH_HOME and GENESIS_DATA_PATH.
- Target DB endpoints confirmed private: Scylla .23:9042, Redis .12:6379,
  NATS .20:4222 on 10.148.0.0/20.

## Script and limited access

`presync.py` SHA256:
9acb4c8a0cfa2572c985e6fbb9337ed37291f3dc2d718088b47557722dce332d.

Same bytes copied to both hosts:
`/home/ubuntu/realm1-maintenance-20261013/presync.py`.

Three local unit tests passed (target fencing, restricted key construction,
invalid/injected key rejection). These are pre-copy tests, not drain tests.

New target-only SSH key is stored under root-private
`/var/lib/parth/realm1-presync-20261013/`. Source authorized_keys backup is in
the same root-private directory on source. The key permits only read-only rsync
of `/var/lib/parth/checkpoints/realm_1_1`, from 10.148.0.37, expires
2026-10-15 00:00 UTC. Existing authorized keys were not replaced.

Pre-copy command (never starts or stops a service):

```sh
ssh gcp-realm-processor \
  'sudo -n python3 -I /home/ubuntu/realm1-maintenance-20261013/presync.py copy'
```

Per-run statistics and exit status are kept on target in protected
`/var/lib/parth/realm1-presync-20261013/presync-*.json`.
Exit 24 is permitted ONLY for online pre-copy; a stopped final sync must require
exit 0. No --delete or --inplace is used. A final reconciliation must also account
for target-only old files, not assume pre-copy produces an exact snapshot.

Source rsync PID 1967735 was lowered to nice 10 / best-effort I/O priority 7 after
observing source I/O pressure. Target rsync PIDs 122969/122971 also received I/O
priority 7. These were copying processes only; no node priorities changed.

## During pre-copy: read-only public sample

2026-10-13 12:00:51 to 12:01:52 UTC:

| Component | First checkpoint | Second checkpoint |
| --- | --- | --- |
| Coordinator | 266718 | 266728 |
| Realm0 | 266717 | 266727 |
| Realm1 | 266718 | 266727 |

Services and Hasura HTTP 200; public proxy reports user role; Faucet enabled.
This is a public subset check, not full bridge E2E or proof of no latency impact.

## Still required before stopping old Realm1

Method-level filtering implementation and tests, private bypass coverage,
pre-gate request reconciliation, old/new pending generation drain evidence,
durable state verification and guarded final sync/cutover. No Caddy change or
Processor restart has been performed by this preparation.

## Pre-copy completion

Completed around 12:08 UTC (20:08 UTC+8), exit 0, 534.01 seconds.

- Files checked: 587,833 (587,831 regular files, two directories).
- New files: 52,994; transferred regular files: 52,995.
- Total logical file size: 1,592,265,397 bytes (disk allocation is larger).
- Transferred file size: 663,795,278 bytes; received: 683,126,791 bytes.
- Deleted files: zero.
- Target post-copy check: fenced, disabled/inactive, pinned artifacts match.
- Source Realm1 PID 1672024, Coordinator PID 1259828, target Realm0 PID 15182:
  unchanged and active, zero systemd restarts.

This successful live pre-copy is explicitly NOT permission to start the target.
The old writer continued changing files during the scan.

WebSocket Upgrade probes returned HTTP 101 both through the public Realm1
domain and directly to 10.148.0.25:1339. The probes intentionally timed out
after the handshake; they did not submit a transaction. This confirms that a
filter covering only HTTP request bodies would leave an actual supported path
uncovered, not merely a theoretical one.
# Read-only follow-up, 13:00-13:01 UTC

`observe.py --interval 15` ran successfully through existing SSH aliases. It
does not pull/ack NATS messages, mutate DBs, change ingress, or stop services.
Snapshots are sequential observations, not an atomic snapshot of the chain.

- 13:00:48 UTC: Coordinator 267318, Realm0 267317, Realm1 267318.
- 13:01:09 UTC: all three 267321.
- Realm1 live consumers included one with four unacknowledged Worker jobs;
  all sampled `num_pending` values were zero. This is direct evidence that an
  empty pending count alone cannot establish drain completion.
- NATS retained stream: first sequence 1, last observed 576256, 576256 messages.
  These are stream messages, NOT a count of unprocessed user transactions.
- Old Realm1 PID 1672024 and Coordinator PID 1259828 remained active, zero
  restarts. Target Realm0 PID 15182 remained active; target Realm1 remained
  inactive, disabled and PID 0.
- Active Caddy JSON still routes both Realm1 aliases to .25/.36/.35:1339.
- No public gate closure, Processor migration, restart or queue mutation occurred.

The observer deliberately returns `safe_to_stop_processor: false`. Old queue
generations, pre-gate handlers, all ingress paths and committed user outcomes
still require reconciliation before a stop.

## Follow-up preparation, 13:33-13:54 UTC

- New V3 private gate and private Caddy Edge pool were installed/enabled on
  gcp-nostr, PIDs 142343/142344. Public Caddy config unchanged. Gate is closed,
  zero active/pending submissions, no persistence uncertainty. Actual mixed
  HTTP/WS query/rejection tests passed. No business transaction was submitted.
- Protected gateway backup/preparation completed; existing Realm1 WG relay
  still points directly to `.25:1339`. No relay restart occurred.
- Repeated online checksum pre-copy: 588,244 files, 411 new files, 412 regular
  files transferred, total logical size 1,629,209,598 bytes, transferred file
  data 47,576,478 bytes, 323.77 seconds, exit 0. No deletions.
- Source Realm1 PID 1672024 and Coordinator PID 1259828 remained active with
  zero restarts. Target Realm1 remains fenced/inactive; Realm0 was not restarted.
- Read-only snapshot on cp-ce:
  `/var/lib/parth/realm1-maintenance-reconciliation/snapshot-1791898993561287362`.
  Range starts at NATS sequence 580000, ends at 582434; 1,255 qt20 updates.
  Verification `verification-1791899046798756638.json`: all 1,255 match exact
  historical leaf hashes, unresolved 0. No NATS consumers created, pulled or
  acknowledged; no Redis/Scylla writes. Current Redis processing/gathering IDs
  can be read with `reconcile.py pending` via one HMGET of the two existing fields.
- The earlier snapshot `snapshot-1791898864381859657` had an audit-tool endian
  error: it compared canonical little-endian bytes to QHashOut JSON big-endian
  hex. That failed report is retained, not evidence of 1,103 lost transactions.
  The tool was corrected against `qhashout.rs` serialization and the successful
  later snapshot above reran the exact historical comparisons.
- Coverage is explicitly limited to the selected range. Earlier history and
  pre-gate in-flight handlers are not declared reconciled by this result.
- Caddy atomic configuration persistence tested with an isolated same-image
  container; production container untouched. See ADMISSION-CANDIDATE.md.
- Public/WG admission closure, final drain, source stop and target start have
  NOT occurred. User confirmation of WS/WG connection reconnection is pending.

The old migration helpers differ by host (source SHA `2fa4d51e...`, target
`e6e72d6c...`); target has the startup wrapper grace fix. Do not copy over either
blindly or invoke the old `cutover 1`, whose rsync key is expired and whose
controller does not enforce the new admission/drain boundary.

## Rechecked with committed-height bounds, 13:56-13:58 UTC

The newer snapshot is
`/var/lib/parth/realm1-maintenance-reconciliation/snapshot-1791899762158628329`:
2,175 qt20 updates, sequence range 580000 through 584225. The new audit requires
mapped checkpoint <= both sampled committed heads, not only matching leaf data.

- First verification `verification-1791899826477340643.json` had 12 unresolved
  updates, all pending 588286 mapped to checkpoint 267874. Sampled committed
  heads were Realm1 267871 and Coordinator 267873. Those rows therefore correctly
  failed the commit-boundary check at that time.
- Re-verification `verification-1791899906791131305.json` passed all 2,175 rows,
  unresolved 0. The first report was retained, not overwritten.
- Stream metadata before and after collection had no retained sequence holes;
  this supports the sampled range only. Earlier history, pre-gate active calls
  and completeness across all relevant generations remain explicitly unproven.
- 25 Python tests, 22 top-level Go race tests, Go vet and staged whitespace
  checks passed. Independent review cleared the commit-boundary and coverage
  wording issues; it did not approve stopping the Processor.
- Public Caddy JSON was again checked equal to its protected original. Original
  Realm1 WG relay PID 1224809 still points to `.25:1339`. Target Realm1 remains
  inactive/disabled, PID 0; target Realm0 PID 15182 is unchanged with no restarts.
- This remains preparation, not a completed migration. User confirmation of the
  public WS plus WG connection reconnection scope is still pending.
