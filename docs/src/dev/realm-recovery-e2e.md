# Realm Recovery E2E Runbook

Internal developer runbook for the devnet E2E validation of the Realm recovery,
proposal-store, and P2P consensus pipeline. Not part of the published mdBook tree.

Status: Review. Runtime observations below distinguish fresh evidence from
user-reported prior acceptance; source references describe checks, not test passes.

## Environment

Use the repository's configured devnet environment and launch `make run-all`
in the foreground under tmux, never with `&`. Do not copy credentials or
machine-specific environment paths into this runbook. Runtime operations are
owned by the session operator; the verification snippets below are read-only.

Logs land in `logs/<service>_<logs,errs>.txt`. RPC surfaces:
coordinator edge `:1337`, realm edges `:13380/:13381` (realm 0) and
`:13390/:13391` (realm 1), faucet `:9998`, psy-services `:3000`,
prove proxy `:9999`, L1 anvil `:8545`.

Snapshot logs before destructive reruns:

```bash
archive_dir="$(mktemp -d)"
cp logs/realm_*processor_logs.txt logs/coordinator_edge_0_logs.txt "$archive_dir/"
```

## Logging prerequisite

A prior run observed comma-separated `RUST_LOG` directives being truncated by
the launcher's `--env` parser (`LOG_LEVEL`, `Makefile:9`). Check the effective
child configuration when targets are missing; empty logs alone do not prove
that a follower accepted or rejected a proposal. The fresh run below contains
proposal, vote, certificate, and debug sync evidence; the prior logging
observation is not a fresh-run diagnosis.

## Case 1 — normal block production plus transaction sequence

Purpose: prove the full pipeline — EndCap intake, scheduled proposer, P2P
votes, certificate, coordinator inclusion, and per-checkpoint root agreement
across all four keyspaces.

Steps:

1. Launch the stack. Wait for readiness:

```bash
grep -c "\[REALM_CREATE\] processor new done" logs/realm_0_sub_1_processor_logs.txt
```

   Expect `>= 1` for each of the four `realm_{0,1}_{sub_1,sub_2}_processor` logs
   (`create.rs:103`).

2. Confirm the coordinator produces blocks:

```bash
grep -c "Generated block in" logs/coordinator_processor_logs.txt
```

   One line per checkpoint (`runner.rs:73`). Query all five tips to observe
   progress; sequential tip reads can differ while the chain advances. Root
   agreement must instead compare global roots at one fixed checkpoint:

```bash
for p in 1337 13380 13381 13390 13391; do
  curl -s -X POST http://127.0.0.1:$p -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_latest_checkpoint_id","params":[]}'
done
```

3. Scenario F uses a **fresh registered user**, not genesis user 0. The
   public faucet RPC still grants only 100 raw units and does not take an
   amount. Fee-reserved funding used genesis user 0 calling contract 5
   `faucet(user_id, amount)` once, which deferred token `simple_transfer`
   (`../psy-compiler/psy-precompiles/faucet/src/main.psy:17-45`). Amount was
   `100 + 3 * 1_000_002_000` raw so the recipient's later `simple_claim` and
   two successful `simple_transfer` EndCaps could pay
   `GUTA_FEE + DA_FEE * slots` (`psy-genesis/config.json:65-66`;
   `client_prover/psy_circuit/psy_ups_circuit/src/session.rs:1311-1338`).
   Protocol fees were not changed.

4. Recipient spendable balance requires `simple_claim(sender)` against the
   faucet caller (`../psy-compiler/psy-precompiles/token/src/main.psy:445-465`).
   Scenario F then used `psy_user_cli call ... --method-name simple_transfer`
   for 50, 49, and rejected 10. `private-transfer` still exists, but that CLI
   requires `--private-key` on argv (`args.rs:679-683`) and was not used.

Judgment criteria (grep the proposer's and follower's processor logs):

| Criterion | Greppable string | Source |
| --- | --- | --- |
| Proposal published | `realm P2P proposal published proposal=` | `process_block.rs:786` |
| Follower saved the body | body file appears under `local_checkpoints/realm_{R}_{S}/proposal_backups/bodies/` | `realm_p2p.rs:616` |
| Follower voted | `realm P2P vote published proposal= signer_sub_id=` (peer's sub id) | `drive.rs:221` |
| Proposer collected the vote | `realm P2P vote received proposal= signer_sub_id=` | `drive.rs:336` |
| Certificate formed | `realm P2P certificate formed proposal=` | `process_block.rs:853` |
| Submitted to coordinator | `Submitting GUTA proof to Coordinator proposal=` | `process_block.rs:606` |
| Coordinator admitted | `realm P2P certificate admitted realm=` | coordinator `handler.rs:889` |
| Inclusion applied | `Committed Realm proposal FFS checkpoint_id=` | `process_block.rs:397` |
| GUTA root changed | proposal `new_root != old_root` (body file name halves differ) | `replay_state_updates_into_tree` |
| 4th transfer rejected | `assertion failed: insufficient balance` from `simple_transfer`, not an RPC crash | `token/src/main.psy:423` |

Failure signatures and what they mean:

| String | Meaning | Where to look |
| --- | --- | --- |
| `dropped unauthenticated Realm vote` | a vote arrived for a proposal whose vote-auth context is not registered locally | `drive.rs:328`; expected on the follower for the proposer's self-vote, abnormal if the follower never votes |
| `follower baseline replay rejected proposal=` | the follower's baseline replay rejected the proposal (coverage or root binding) | `realm_p2p.rs:633`; reason comes from `recovery.rs` |
| `timed out: wait_votes` | proposer never reached the replication threshold; 120 s deadline | `runner.rs:122` |
| `InvalidStateUpdates: ... has no IMT record` | nonzero changed leaf on an IMT-indexed tree lacks its required IMT record; see limitations below, not a universal positional-write rejection | `psy_node_common/src/realm/processor/recovery.rs:389-393,570-603` |

## H — lagging follower body catch-up

Status: **passed on this stack after `aa6c252c`.** The earlier validator-leaf
restart loop is historical (`cf93c58c` coalescing + later preserved-state
docs). This run used the frozen C765 gap, not a new faucet grant.

Frozen before resume:

1. Realm-0 `sub_2` was SIGSTOP'd at tip 762, then SIGKILL'd; applications
   stayed down through `make rollback-stop` with infrastructure retained.
2. Faucet grant `recipient_user_id=31` returned
   `tx=85c6836ea13f53c8a6d74369b779aef87c1db72f1a4e5b49b4e9462c4dea6933`,
   operator `786432`, `already_submitted=false`, request checkpoint 762.
3. Realm-0 `sub_1` certified proposal
   `c3a316c118efab1aeace85baf4274860449b286245485777f8b9d87f6438e488`
   (`signers=[1]`, base 763, target 764, pending 2399) and coordinator
   included it at **C765**. Exact body name
   `3927e571..._0e4e642f...` existed only under
   `local_checkpoints/realm_0_1/proposal_backups/bodies/` (144231 bytes)
   and was absent on `realm_0_2`.
4. Pre-fix follower recovery logged
   `MissingHistoryProof at C=765: proof-base P=763 roots unavailable`.

Fix and same-state resume:

1. `aa6c252c` persists authenticated metadata for unchanged checkpoints
   before verifying a later proof base (`init.rs:806-820`,
   `require_checkpoint_metadata` in `sync.rs`). GPT and agentlo approved
   the code; focused tests
   `require_checkpoint_metadata_accepts_genesis_and_historical_proofs` and
   `require_checkpoint_metadata_rejects_altered_bindings` passed.
2. Rebuilt release `psy_node_cli`, then `make rollback-resume` (not
   `make run-all`). Follower local tip was still 762; coordinator tip 872.
3. `logs/realm_0_sub_2_processor_logs.txt` `14:58:06.988719Z` /
   `14:58:06.992807Z`:
   `Recovered unchanged Realm checkpoint metadata checkpoint_id=763`
   and `...764`.
4. Same file `14:58:07.035320Z`:
   `Committed coordinator processor state for checkpoint ID: 765`.
   No post-resume `MissingHistoryProof at C=765`. Catch-up then continued
   through the retained tip; `[REALM_STARTUP] reloaded gatherer tree after catch-up`
   at `14:58:08.248172Z`.
5. The exact C765 body file appeared on `realm_0_2` at `14:58:06` with the
   same 144231 bytes as `realm_0_1`. That is `proposal_store.install` of a
   staged catch-up candidate (`init.rs:667-668`), not gossip
   `Realm P2P proposal body complete` (that string is absent after resume).
   Pre-resume `no verified candidate for pair=(3927e571...,0e4e642f...)`
   is gone after the metadata persist.
6. `psy_get_checkpoint_global_state_roots [765]` is identical on
   `:1337/:13380/:13381/:13390/:13391`. Realm-0 edges `:13380` and `:13381`
   agree at C765: operator `786432` `psy_get_user_tree_leaf_hash` equals
   `85c6836e...` (the faucet tx) and user `0` hashes match each other.
   Realm-1 edges `:13390/:13391` have their own non-empty leaves for those
   numeric ids; compare only same-realm edges, not across realms.

Do not treat gossip `body complete` as the H peer-fetch proof. The
peer-fetch evidence here is: body absent on the follower before resume,
present and byte-identical after `install` of the catch-up staged file,
and C765 committed without ghost-pair retries.

## Case 2 — proposer misses its epoch

Purpose: pausing the scheduled proposer must not stall the coordinator
tip. Epoch is `target / CHECKPOINTS_PER_EPOCH` (`10` on localhost).
N=2 self-certification means `wait_votes` timeout is not required.

Status: **closed on the H-resumed stack.** Two windows:

1. Pause. Realm-0 `sub_1` PID 2472240 was `SIGSTOP`'d at coordinator
   tip **962** (epoch 96) and `SIGCONT`'d at tip **995** (epoch 99).
   While frozen, `:1337` advanced 962 → 995 without that processor.
   After continue, five edges agreed at 998 then 1047;
   `no peer offered pair` stayed 0 on both realm-0 processors.
2. Other sub_id. After recovery, a realm-0 faucet (`psy_claim_faucet`
   on `:9998`, recipient 47, tx `5251c931…`, operator 393216, request
   checkpoint 1147) produced the first realm-0 `sub_2` transaction
   proposal of the run.

Scheduled-proposer logs (`process_block.rs:744`) on this stack:

| time | sub_id | epoch | target | note |
|---|---|---|---|---|
| 13:04:59Z | 1 | 76 | 764 | H faucet |
| 15:18:35Z | 1 | 96 | 963 | wake on pre-stop base, then catch-up to 997 |
| 15:23:11Z | 1 | 102 | 1025 | post-CONT transaction |
| 15:35:44Z | 1 | 110 | 1105 | later sub_1 epoch |
| 15:42:47Z | 2 | 114 | 1149 | first logged sub_2 takeover |

The 15:42:47Z lines are:

```text
realm P2P scheduled proposer realm=0 sub_id=2 epoch=114 target=1149 base=1148
realm P2P certificate formed proposal=6dc6f946… realm=0 target=1149 epoch=114 signers=[2] verified_votes=1
```

`sub_2` then committed realm checkpoint **1150**
(`Committed new realm block with checkpoint_id = 1150` at
15:42:54Z). Operator 393216 leaf hash on `:13380`/`:13381` stayed
`45371105…` through 1149 and became `5251c931…` at 1150 (equals the
faucet tx). Empty checkpoints do not print `scheduled proposer`
(`No GUTA jobs ... skipping` at `process_block.rs:446`); freeze-window
epochs that rotation assigned to `sub_2` were empty, so the takeover
log is after SIGCONT, not during the pause. Acceptance does not require
the other sub_id's transaction log while the pause is held.

Do not treat wall-clock alone as rotation evidence. Epoch came from
checkpoint ids. JSON `random_seed` bytes are reversed relative to
in-memory Goldilocks limbs (`QHashOut` serde).

## W — realm proving-worker freeze

Purpose: freeze the observed realm proving worker without a TCP
disconnect. Coordinator CST workers stay running so checkpoints can
advance and rotation can change. Epoch is still
`target / CHECKPOINTS_PER_EPOCH`.

Freeze-set: `psy_worker_cli` PID **2477876**
(`--completed-jobs-log-file ./local_checkpoints/realm_worker_0.backup`,
four `--realm-api-url` to `:13380/:13381/:13390/:13391`).
Leave running: coordinator workers 2476236 / 2477056
(`coordinator_worker_{0,1}.backup`) and every `psy_node_cli` processor
and edge.

| step | evidence |
|---|---|
| W0 | Five edges **1276**. Epoch 127 (anchor 1269) computed r0 `sub_1`, r1 `sub_2`. `logs/worker_0_logs.txt` size 35285; last live proving was RealmFinalizeGUTA goal 1148 submit ok. |
| W1 | SIGSTOP 2477876 at 16:04:11Z; `/proc` state `T`. Log size stayed 35285 for 8s (mtime 15:42:47Z). Coordinator workers remained `S`; tip 1279→1283. |
| W2 | Faucet recipient 48, tx `3673b143…`, operator 1441792, request C1284. Realm-1 `sub_1` logged `Realm worker publication acknowledged` at 16:05:09Z (`process_block.rs:118`) checkpoint 1286 unique_pending_id 4058, then no `waited for jobs` / `Persisted worker artifact ready`. Timeout is `u64::MAX` (`startup.rs:126`); `persisted_artifact.rs:16-17` skips the deadline. Classified unbounded silent await. Proofs not weakened. Second faucet recipient 49, tx `58f7ca64…`, operator 917504, request C1288. |
| W3 | Five `psy_get_checkpoint_global_state_roots[1286]` identical (`user_tree_root=cc23dad2…`). No post-16:04 Fatal / RESTART / channel-closed / preimage-mismatch. Live tips diverged only because r1s1 sat in the wait (`:13390` stayed 1286). |
| W4 | While 2477876 remained `T`, coordinator tip reached **1300** epoch **130**. Computed r0 `sub_2` / r1 `sub_2` from committed anchor 1299. W0 identity was r0 `sub_1` at epoch 127. Not wall-clock. |
| W5 | SIGCONT 2477876 at 16:07:41Z; state `T`→`S`; cmdline unchanged. `worker_0_logs.txt` grew past 35285. Post-CONT proving start/done/submit ok for GUTASingleEndCap goal **4058** and RealmFinalizeGUTA 1285/1290. r1s1 persisted the root proof at 16:07:45Z. |
| W6 | New proposer is realm-0 `sub_2`. Faucet recipient 51, tx `6f959773…`, operator 786432, request C1330. `16:12:17Z` `scheduled proposer realm=0 sub_id=2 epoch=133 target=1333`; certificate `signers=[2]`; follower r0s1 `proposal start accepted` + `proposal body complete` proposal=`9a079760…` body_len=143789; `Committed new realm block with checkpoint_id = 1334`. Operator leaf on `:13380`/`:13381` equals the tx at C1334; five-edge roots at 1334 identical. Freeze-window tx `58f7ca64…` operator 917504 first equals its leaf at C1306 on `:13380`/`:13381`; tx `3673b143…` operator 1441792 first equals its leaf at C1306 on `:13390`/`:13391`. Both are resume catch-up by epoch-129/128 `sub_1`, not the new proposer. |


## Case 3 — two proposers race the same target

Purpose: verify an atomic single winner and a retryable loser without rollback.
Status: not executed; the literal two-author setup requires a revised injection
design before any test-tool changes.

The coordinator permits exactly one scheduled proposer per realm and target;
a different author is rejected before the claim operation
(`psy_node_common/src/coordinator/edge/handler.rs:858-870`). Replaying a genuine
same-author request can exercise duplicate admission, but is not evidence of
two distinct legitimate proposers racing.

The atomic claim is `put_submitted_status_if_absent`, keyed by coordinator
generation and submitting realm. A losing claim returns retryable
`AlreadyClaimed` (`psy_node_common/src/coordinator/edge/handler.rs:698-712`).
The submit error propagates before inclusion waiting and `commit_state`
(`psy_node_common/src/realm/processor/core/process_block.rs:611-651`); this
loser does not enter the foreign-root divergence path and needs no rollback.

`realm P2P certificate admitted` is emitted during certificate verification,
before the atomic claim (`psy_node_common/src/coordinator/edge/handler.rs:681,698-712,888-895`).
Counting that log cannot prove a single winner. Acceptance needs the winning
queue publication, the loser's typed rejection and processor retry path,
no losing `commit_state` execution, and fixed-checkpoint root convergence.
A replay client alone cannot prove the processor retry branch. Report the
proposed injection and obtain approval before modifying any test tool.

## Case 4 — restarts

### 4a. Graceful restart (supervisor)

`make restart` (control socket) or SIGTERM a child; the supervisor recreates
it with the saved template. Judgment: the restarted sub logs
`Recovering checkpoint N...` walking from `local_latest_checkpoint_id + 1`
(`init.rs:805`), reaches the tip, and its
`already synced to latest checkpoint ID` cadence resumes (`sync.rs:88`).
No `Local database is stale.` (`init.rs:491`) and no
`ahead of coordinator` (`init.rs:476`, `sync.rs:160`) lines.

### 4b. Crash restart (kill -9)

```bash
kill -9 <realm_processor_pid>
```

Judgment:

- startup sweep removes unparseable residue from the ACTIVE bodies dir:
  `remove_staged_files` deletes files whose name fails
  `parse_transition_file_name` (`proposal_store.rs:374-385`) — plant
  `.tmp-<n>-junk` and a garbage name before the kill; both must vanish.
- valid bodies survive: `<hex>_<hex>` files created before the crash are still
  on disk after restart.
- damaged bodies (valid name, corrupt bytes) are deleted on hydrate — flip the
  last byte of a body, restart, and the file disappears (damage path
  `remove_transition`, `proposal_store.rs:242-256`).
- DB opens clean; no `Local database is stale.` / `ahead of coordinator`.

### 4c. Full-network restart preserving state

Executed: `PURGE=0 make shutdown` then `make run-all` with rebuilt
`psy_node_cli` at `5cc40680`. Relayer used a temporary `KEYSTORE_PATH`; HOME
relayer keystore was not overwritten.

After restart, five surfaces returned identical
`psy_get_checkpoint_global_state_roots([452])` matching the pre-restart F
snapshot, including `user_tree_root=9f031366bb141a5ab2fde8cad4ada0b2322e99cc584d7b7ba402913e352f4e77`.
Realm-1 GUTA at last-modified checkpoint 452 remained
`578fa7dcb208e5e000a8fc737603d3b8d418eba9c8490aea429127969c4419fd`.
Tips had advanced (empty blocks); committed F roots did not regress.

### 4d. Business continues after restart

Executed after 4c, before attempting H: user 0
`simple_transfer([1966080,1])` confirmed at checkpoint **600**,
`tx=f3207be4c2236ee409f8fda004a7aeab2333cbab566338c41ad18b39be5aa7a2`.
The transfer's own certificate was `signers=[1]` (proposal `857bd515...`).
User-0 leaf at 599 was still the C434 grant hash `3a681304...`; at 600 it
changed. Global roots at 600 matched on the five RPC surfaces then live.

## Abandoned-directory rule

The retired `local_checkpoints/realm_{R}_{S}/proposal_store/` directory must be
ignored: plant it with junk (`bodies/deadbeef_00c0ffee`), restart the sub, and
verify (a) zero log references to the old path and (b) the file survives. The
active path is `proposal_backups/bodies/` (`RealmProcessorStartConfig::get_proposal_backups_path`,
batch H).

## Read-only verification of the fresh checkpoint

These commands inspect the existing stack; they do not launch, restart, fund,
or transfer. They require `curl` and `jq`. Checkpoint 62 must still be retained.
Compare all six fields of the **global checkpoint roots** at checkpoint 62 on
all five surfaces. Different realms' local subtree roots are not expected to
equal each other. Latest-tip equality is not a substitute for this comparison.

```bash
for p in 1337 13380 13381 13390 13391; do
  curl --fail-with-body -sS "http://127.0.0.1:$p" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"psy_get_checkpoint_global_state_roots","params":[62]}'
  printf '\n'
done | jq -s -e '
  if length == 5 and all(.[]; .error == null and (.result | type) == "object" and (.result | length) == 6)
  then map(.result) | .[0] as $expected | if all(.[]; . == $expected) then . else error("global roots differ") end
  else error("missing or invalid checkpoint roots response") end'
```

Inspect recipient user 0, contract 0, slot 0 at that same checkpoint on its
realm-0 edge; this is not the operator's realm-1 root:

```bash
curl --fail-with-body -sS http://127.0.0.1:13380 \
  -H 'content-type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"psy_get_user_contract_state_tree_leaf_hash","params":[62,0,0,0]}'
```

Bind the included operator leaf to the claim response hash:

```bash
for checkpoint in 61 62; do
  curl --fail-with-body -sS http://127.0.0.1:13390 \
    -H 'content-type: application/json' \
    --data "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"psy_get_user_tree_leaf_hash\",\"params\":[$checkpoint,1310720]}"
  printf '\n'
done
```

## Session validation status (2026-09-16)

**Prior acceptance, preserved as user-reported:** A, B, C, D, E, G (deletion
half), I, and 4b. These are not newly rerun passes.

**Fresh run:** the operator rebuilt `psy_node_cli` and `psy_user_cli` in release
after `7877145b` (detached faucet task) and `6d28e2f6` (per-tree pairing), then
started a fresh devnet. A single long-lived recipient-0 claim returned
`amount="100"`, `operator_user_id=1310720`, request checkpoint 58, window 0,
`already_submitted=false`, and transaction hash
`c8f3393d5175f7682284ca186b8aadd8b7a23dbd6d4218ece13f270e8e0b1b0a`.
A repeat at checkpoint 64 returned the same hash with
`already_submitted=true`. These response observations are reported by the
session operator. No short-client-timeout claim probes ran on the fresh
stack. Long-lived claim success is **not cancellation end-to-end proof**.

The checked log chain for proposal
`129fd57a55727ceeb7263e1321f5420f87184aa6ff5c39d6d6ac8ec37a0ab959`
is below. All timestamps are UTC on 2026-09-16.

| Event | Timestamp / value | Current evidence |
| --- | --- | --- |
| Operator leaf lookup | 07:35:35.524137Z; user 1310720, checkpoint 59 | `logs/realm_1_sub_2_edge_0_logs.txt:2092` |
| Queue publish completed | 611 microseconds | `logs/realm_1_sub_2_edge_0_logs.txt:2103` |
| EndCap accepted | 07:35:35.529285Z; checkpoint 60; `872c109c3fd0b644e62928b159ca2b72afa103084fdf275967ccf22cd1379bd9` | `logs/realm_1_sub_2_edge_0_logs.txt:2105` |
| Gatherer dequeued operator EndCap | 07:35:35.540678Z; goal 102, `UserEndCap`, group 32, task index 1310720 | `logs/realm_1_sub_2_processor_logs.txt:7683` |
| EndCap job populated | 07:35:35.540804Z; user 1310720, checkpoint 58 | `logs/realm_1_sub_2_processor_logs.txt:7684` |
| Sub 2 published | 07:35:38.673377Z; base 59, target 60 | `logs/realm_1_sub_2_processor_logs.txt:7788` |
| Sub 1 accepted Start | 07:35:38.673848Z; 3 parts, 143561 bytes | `logs/realm_1_sub_1_processor_logs.txt:10413` |
| Sub 1 completed body | 07:35:38.673998Z | `logs/realm_1_sub_1_processor_logs.txt:10416` |
| Sub 2 received sub 1 vote | 07:35:41.806811Z | `logs/realm_1_sub_2_processor_logs.txt:7789` |
| Certificate formed | 07:35:41.813707Z; signers `[2, 1]` | `logs/realm_1_sub_2_processor_logs.txt:7791` |
| Inclusion confirmed | 07:35:54.871892Z; checkpoint 62 | `logs/realm_1_sub_2_processor_logs.txt:7816` |

Group 32 alone does not identify a queue subject. The EndCap request checkpoint,
edge acceptance checkpoint, proposal target, and inclusion checkpoint are
distinct observations, not conflicting labels for one checkpoint.

The session operator's RPC verification found the **operator realm-1 root**:

- Before, checkpoint 58: `76985030cd9a34fc05636e59b590bf5b5fa0c38066dd58fff953cd447fff3c32`.
- After, checkpoint 62: `8c51952d7b24af61b93ad54a70e48d9d092fe8ed48cea3fdc4790c46e051e418`.
- All six fields of `psy_get_checkpoint_global_state_roots([62])` were
  identical on ports 1337, 13380, 13381, 13390, and 13391.
- `psy_get_user_contract_state_tree_leaf_hash([62,0,0,0])` on port 13380
  remained raw `1_000_000_000_000_000`. This is recipient user 0's token
  balance; the realm-1 root change is not evidence of a recipient root change.

The operator's RPC reads also bind this specific EndCap to inclusion:
`psy_get_user_tree_leaf_hash([61,1310720])` on port 13390 was
`fc08f4575f01cd4d23e1aaf6d7f9586bda2b3eb8f3d8225bead35e8470d940bf`;
at `[62,1310720]` it was
`c8f3393d5175f7682284ca186b8aadd8b7a23dbd6d4218ece13f270e8e0b1b0a`,
exactly the claim response's transaction hash, not merely an unrelated
realm-root change.

### F sequence (executed 2026-09-16)

Fresh zk wallet registered as user **1966080**
(`public_key_hash=f5b5774c0c5dae283572149a9d8d93238b03169a9b4580ebf49ae17edb6a6552`).
Genesis user 0 called `faucet(1966080, 3000006100)`; inclusion
`tx=8d7efdff36a2ab0dfd6879a7bc416b7755e95ef1c0f9589bf1370a66a3102847` at
checkpoint **434**. Realm-0 user-0 leaf at 433 was
`5c9482a7c2fbf9c4188dd8a805c2aec148aec47098c8e52ddad4435cf2b4193c`; at 434 it
matched the grant EndCap hash
`3a68130440bda5e26bb9cdec70eff355679b8ef52b969cc490a74f5c95fdca21`.

| Step | Checkpoint | tx / result | User 1966080 contract-0 slot 0 raw |
| --- | --- | --- | --- |
| After grant, before claim | 434 | operator grant only | `0` |
| `simple_claim([0])` | 442 | `06f295093c715661dd22da53c04534b33b0f1492d0f084a99f6885ea8fbe79d4` | `2000004100` |
| `simple_transfer([1,50])` | 448 | `76f1f058aeab5878ae9176f25d55d11a20508c6b2f811fa3c368efe0d5c8835c` | `1000002050` |
| `simple_transfer([1,49])` | 452 | `05b36954a5d7c6e0410747b1297073a5224e94c62342e257386892c475557203` | `1` |
| `simple_transfer([1,10])` | not submitted | CLI error `assertion failed: insufficient balance (left: 0, right: 1)` | still `1` |

Recipient EndCap hashes at inclusion:

- C442 `7c55ca8e15b5a8c4f0a0d055494680216794e8306b223ef11045bbede43153d2`
- C448 `d8bde3c9f2ef7dfa64a446a1192a5dd16a91b5ee5ec89a3934394afb48f8c46c`
- C452 `f7371c9dc162d22837cda9c764d60080eda59d9f43bd186c94500f768d143b48`

`psy_get_checkpoint_global_state_roots` at **434, 442, 448, and 452** returned
identical six-field objects on ports 1337, 13380, 13381, 13390, and 13391.

Observed burn per recipient EndCap was `1_000_002_000` raw (claim left
`2000004100`; first transfer left `1000002050`; second left `1`).

**F is passed under the fee-reserved fresh-account interpretation.** It is not
a pass of raw faucet RPC amount 100 covering three EndCaps, and it is not a
`private-transfer` pass.

Pending: **H → Case 2 → Case 3**. 4c/4d passed. H and Case 2 remain blocked
because the preserved validator user-leaf row does not hash to the
persisted tree leaf. `cf93c58c` is not validated against a fresh
`signers=[1]` inclusion. Case 3 still cannot create two distinct scheduled
proposers without a harness change.

### Accepted limitations, not fixes

- The approximately 105 MB / 1711 gossip-parts case remains an accepted known
  limitation, not fixed. The fresh proposal's 143561-byte / 3-part body does
  not exercise it.
- Two-validator realms accept a certificate signed by the proposer alone
  (`ceil(2 / 2) = 1`). This gives up "no unilateral certification" at
  `n == 2` in exchange for liveness under a single-node fault. Reachable
  only when a realm has exactly two validators; at `n >= 3` the
  `ceil(n / 2)` threshold already forces a non-proposer signer, so this is
  a no-op for production realms.
- Per-tree pairing classifies a tree using a **positive LIVE next-append
  pointer**, then requires IMT records for its nonzero changed leaves,
  including new indices on an IMT-indexed tree
  (`psy_node_common/src/realm/processor/recovery.rs:570-603,389-393`).
  Zero-valued changed leaves remain exempt. The pointer read is not
  checkpoint-versioned
  (`psy_node_core/src/psy_core_db/v3_implementation/full.rs:4142-4151`).
  A completely zero-pointer tree's first insertion remains exempt from this
  pairing classification. This is not a claim of universal IMT soundness.

## Post-squash rerun (2026-09-16)

Stack: existing H-resumed chain, no PURGE. HEAD `47ce6a33` after
thematic squash (`backup/pre-squash-8b7b2e8e` tree
`5ecf0d24` identical). RPC dumps live under local gitignored
`e2e-evidence/round1-*`. Case 3 not run.

### F — fee-reserved sequence — PASS

Fresh zk wallet registered as user **1966080**
(`public_key_hash=b3ad81eb…`, `e2e-evidence/round1-f/get-user-id.json`). Genesis user 0 called
`faucet(1966080, 3000006100)`; confirmed C**1597**
`tx=d9162c00…` (`grant.json`). Recipient `simple_claim([0])` C**1603**
`tx=b2ceadb7…`. `simple_transfer([1,50])` C**1608** `tx=2853b540…`.
`simple_transfer([1,49])` C**1613** `tx=b2ab6b51…`. Fourth
`simple_transfer([1,10])` failed at trace:
`assertion failed: insufficient balance (left: 0, right: 1)`
(`xfer10-reject.stderr.txt`). Five-edge
`psy_get_checkpoint_global_state_roots` equal at 1597, 1603, 1608,
1613 (`*-rpc.json`). Pipeline grep:
`e2e-evidence/round1-f/pipeline-grep.txt`.

### H — lagging follower body catch-up — PASS

SIGSTOP r0s2 PID **2474005** at 16:59:08Z tip **1623** (`freeze.json`,
`/proc` `T`). User-0 `simple_transfer([1,1])` CLI timed out waiting
inclusion, but r0s1 published proposal `570580d5…` epoch 163 target
1633 at 17:00:44Z and committed C**1635**. Operator/user-0 leaf on
`:13380` stayed `95e5b506…` through 1634 and became `e910b259…` at
1635 (`inclusion-rpc.json`). While frozen, `:13381` stayed 1623.
SIGCONT 17:04:22Z (`cont.json`). r0s2 logged
`Realm P2P proposal body complete` proposal=`570580d5…` then
`Committed coordinator processor state for checkpoint ID: 1635`.
Body file
`a6170ddb…_74feba83…` (140880 bytes) appeared on both r0s1 (mtime
17:00:44Z) and r0s2 (mtime 17:04:22Z); `cmp` identical
(`body-cmp.json`). Five-edge roots at 1635 identical; `no peer
offered pair` stayed 0. Gossip `body complete` is the follower
receipt; install is the 17:04:22Z body file plus C1635 commit.

### Case 2 — missed epoch nonempty takeover — FAIL

SIGSTOP r0s1 PID **2472240** at 17:06:14Z tip **1665** epoch **166**
(computed r0 `sub_1`). Coordinator tip advanced 1665→**1679+** while
that processor stayed `T`; `:13380` stayed 1665; ghost 0
(`freeze.json`, `epoch-scan.json`). Epoch **168** (anchor 1679) computed
r0 `sub_2` (`epoch-scan.json` last sample 01:08:03, tip 1679,
`r0_168=2`). r0s2 logged only
`No GUTA jobs to process in this block, skipping.` (`process_block.rs:446`);
last `scheduled proposer realm=0 sub_id=2` remains 16:54:33Z epoch 159
(`r0s2-scheduled.txt`). Faucet returns on `:9998` used stale request
checkpoint **1665** (frozen r0s1 edge). User-0 EndCap hit
`already been submitted` unique_pending_id 5174 on `:13380`. SIGCONT
17:16:53Z; five edges later 1742. **Tip continued is not rotation
takeover.** Nonempty sub_2 proposal during the pause was not obtained.


### W — realm proving-worker freeze — PASS

| step | evidence |
|---|---|
| W0 | Five edges **1746**. Epoch 174 (anchor 1739) computed r0 `sub_2`, r1 `sub_2`. Realm worker PID **2477876** `S`; `logs/worker_0_logs.txt` size 68357. Coordinator workers 2476236/2477056 `S`. `e2e-evidence/round1-w/w0.json`. |
| W1 | SIGSTOP 2477876 at 17:17:42Z; `/proc` `T`. Size stayed 68357 for 8s. Coordinator workers `S`; tip 1746→1747 (`w1.json`). |
| W2 | Faucet recipient 55, tx `b68c038e…`, operator 655360, request C1749 (`w2-faucet.json`). r0s1 `Realm worker publication acknowledged` 17:18:30Z checkpoint 1751 unique_pending_id **5206** (`w2-ack.txt`); no `waited for jobs` before SIGCONT. Timeout `u64::MAX` (`startup.rs:126`). Unbounded silent await. Proofs not weakened. |
| W3 | Five `psy_get_checkpoint_global_state_roots[1746]` identical (`user_tree_root=daa3bc6a…`). Live tips during wait: `:13380`=1751 others 1753 (r0s1 blocked). No 17:17–17:19 Fatal/RESTART/channel-closed/preimage-mismatch (`w3-rpc.json`, `w3-fatals.txt`). |
| W4 | W0 identity r0 `sub_2` epoch 174. While worker `T`, tip 1753 epoch **175** computed r0 `sub_1` from committed anchor 1749 (`w4-scan.json`). Not wall-clock. |
| W5 | SIGCONT 17:19:14Z; `T`→`S`; `size_before=68357` (`w5-cont.json`). `logs/worker_0_logs.txt` then contains `proving start` goal **5206** GUTASingleEndCap (`w5-proving.txt`). |
| W6 | New proposer r0 `sub_1` epoch 175. 17:19:16Z `scheduled proposer realm=0 sub_id=1 epoch=175 target=1751`; certificate `signers=[1]`; follower r0s2 `proposal start accepted` + `proposal body complete` proposal=`0c2868a7…` body_len=**143789**; `Committed new realm block with checkpoint_id = 1757`. Operator 655360 leaf on `:13380` first equals tx `b68c038e…` at C1757 (C1756 still `8ce29ee7…`). Five-edge roots at 1757 identical (`w6-rpc.json`). |

### 4c — PURGE=0 full-network restart — PASS

Frozen checkpoint **1915** before teardown (`e2e-evidence/round2-4c/pre-summary.json`).
Five tips **1938**. `user_tree_root=367179a0bcebb17b…`,
`gutas_root=712d7ea35db8ce89…`. User-0 leaf `:13380/:13381`
`b667ba9a…`; `:13390/:13391` `5c9482a7…` (same-realm only).
L1 `eth_blockNumber=0x1a37`, StateManager `0x93df5526…`
(`pre-l1.json`). `PURGE=0 make shutdown` then
`PSY_SKIP_BUILD=1 PSY_SKIP_BRANCH_CHECK=1 PSY_SKIP_KEYSTORE=1 make run-all`
in the foreground. After restart:
`[COORD_CREATE] processor new done` 17:50:55.455843Z;
`[REALM_CREATE] processor new done` r0s1 17:52:34, r1s1 17:53:09,
r0s2 17:53:44, r1s2 17:54:19 (`*-create.txt`). Five tips **1974**
then continuing. C1915 roots, GUTA, user-0 leaves, L1 addresses, and
`eth_blockNumber` unchanged (`post-summary.json`, `post-rpc.json`).
Anvil reused `db/anvil/state.json`; launcher printed
`Reusing persisted localhost deployment`. No
`Local database is stale.` / `ahead of coordinator`.

### 4d — post-restart transfer — PASS

User 0 `call` contract 0 `simple_transfer([1966080,1])` after
`[CFLI:PSY_PROVE_PROXY_STARTED][0.0.0.0:9999]`. First EndCap
`tx=dc0e026d…` `end_user_leaf_hash=9117c287…` submitted 18:00:53Z
and CLI timed out at latest 2018 (`xfer-key.txt`, `xfer.stderr.txt`).
That hash never appeared on `:13380`. User-0 leaf instead changed at
C**2001** to `82f1237e…` (nonce 5→6, balance 22000→24000,
`last_checkpoint_id` 1750→1999; `competing-leaf.json`). Not replayed.

Second call from the C2001 leaf confirmed C**2036**
`tx=baee8fa164b7b193…` `end_user_leaf_hash=8b7afa0d60a226af…`
(`xfer2.json`). r0 `sub_2` epoch 203 target 2035 published proposal
`3b76bb9f…`, certificate `signers=[2]`; r0s1
`proposal start accepted` + `proposal body complete` +
`vote published` then `Applied Realm gatherer FastForward` at C2036;
r0s2 `Committed new realm block with checkpoint_id = 2036`
(`w-commit.txt`). Operator/user-0 leaf on `:13380/:13381` stayed
`82f1237e…` at 2035 and became `8b7afa0d…` at 2036 (nonce 6→7)
(`inclusion-rpc.json`). Five-edge
`psy_get_checkpoint_global_state_roots([2036])` identical.
C1915 `user_tree_root` still `367179a0…` after 4d
(`inclusion-rpc.json`). Recipient 1966080 lives on
realm 1; its user leaf on `:13390/:13391` stayed `0e49b588…` at both
C2035 and C2036 (`inclusion-rpc.json`; token contract leaf already
`…0001` from the earlier F transfers).

## Rename-head rerun (2026-09-17)

Fresh Plonky2 stack after HEAD `e5d03fd5` (`recovery/` → `ffs/`). Anvil
state and localhost deployments were absent, so this is a new chain, not
`PURGE=0` resume. Release CLIs rebuilt; `make run-all` in `tmux` pane
`%12`. Evidence under `e2e-evidence/round3-*` (wallet files not committed).
Case 3 not run.

`[COORD_CREATE] processor new done` 22:56:47Z;
`[REALM_CREATE] processor new done` r0s1 22:58:41, r1s1 22:59:31,
r0s2 23:00:21, r1s2 23:01:11. Prove-proxy
`[CFLI:PSY_PROVE_PROXY_STARTED][0.0.0.0:9999]` before F.

### F — fee-reserved sequence — PASS

Fresh zk wallet registered as user **1966080**
(`public_key_hash=9882911b…`, `get-user-id.json`; wallet-create
`9256a8fd…` is unused). Genesis user 0 `faucet(1966080, 3000006100)`:
first EndCap `tx=f1f377fc…` timed out (`grant.stderr.txt`); user-0 leaf
changed at C**61** to `e3fae7f6…` (nonce 0→1, balance 0→3000) instead
of the submitted hash (`first-grant.json`). Not replayed. Second call
from that leaf confirmed C**87** `tx=1ec4daa8…` (`grant.json`).
Recipient `simple_claim([0])` C**92** `tx=80f1b918…`.
`simple_transfer([1,50])` C**97** `tx=5a42d8c4…`.
`simple_transfer([1,49])` C**102** `tx=851d5057…`. Fourth
`simple_transfer([1,10])` **confirmed** C**106** `tx=99f46732…` because
leftover token still covered fee+10 (`xfer10.json`). Fifth
`simple_transfer([1,2000004092])` (leftover+1) failed at trace:
`assertion failed: insufficient balance (left: 0, right: 1)`
(`xfer-over.stderr.txt`). Five-edge roots equal at 87, 92, 97, 102,
106 (`*-rpc.json`). Pipeline grep: `pipeline-grep.txt`.

### H — lagging follower body catch-up — PASS

SIGSTOP r0s2 PID **3294194** at 23:17:41Z tip **120** (`freeze.json`,
`/proc` `T`). While frozen, `:13381` stayed 120. Epoch **14** (anchor
139) computed r0 `sub_1`. User-0 EndCap submitted 23:21:10Z
`tx=67a15b29…` then CLI timed out (`xfer.stderr.txt`); that hash
`2849e0f7…` never appeared on `:13380`. r0s1 published proposal
`95d8835f…` epoch 14 target 143 and committed C**144**. Operator/user-0
leaf on `:13380` stayed `4cb2adb8…` through 143 and became `a540849a…`
at 144 (`inclusion-rpc.json`). SIGCONT 23:24:55Z (`cont.json`). r0s2
logged `Realm P2P proposal body complete` proposal=`95d8835f…` then
`Committed coordinator processor state for checkpoint ID: 144`
(`catchup-log.txt`). Body
file `9f3156d0…_74269643…` (142020 bytes) appeared on r0s1 (mtime
23:21:14Z) and r0s2 (mtime 23:24:55Z); `cmp` identical
(`body-cmp.json`). Gossip `body_len=141806`; docs cite disk `cmp`.
Five-edge roots at 144 identical (`catchup-rpc.json`);
`no peer offered pair` count 0 (`ghost.txt`).


### Case 2 — missed epoch nonempty takeover — FAIL

SIGSTOP r0s2 PID **3294194** at 23:31:43Z tip **207** epoch **20**
(computed r0 `sub_2`). Coordinator tip advanced 207→**219+** while that
processor stayed `T`; `:13381` stayed 207 (`freeze.json`,
`epoch-scan.json`). Epoch **21** (anchor 209) computed r0 `sub_2`
(`epoch-scan.json`). r0s1 logged only
`No GUTA jobs to process in this block, skipping.` (`process_block.rs:446`,
`r0s1-skip.txt`);
last `scheduled proposer realm=0 sub_id=1` remains 23:21:14Z epoch 14
(`r0s1-scheduled.txt`).
Last r0s2 `scheduled proposer` remains 23:11:26Z epoch 8
(`r0s2-scheduled.txt`). SIGCONT 23:34:03Z; five edges 220 then 221.
**Tip continued is not rotation takeover.** Nonempty sub_1 proposal
during the pause was not obtained.

### W — realm proving-worker freeze — PASS

| step | evidence |
|---|---|
| W0 | Five edges **223**. Realm worker PID **3296594** `S`; `logs/worker_0_logs.txt` size 26515. Coordinator workers 3290766/3291435 `S`. `w0.json`. |
| W1 | SIGSTOP 3296594 at 23:34:41Z; `/proc` `T`. Size stayed 26515 for 8s. Coordinator workers `S`; tip 223→224 (`w1.json`). |
| W2 | User-0 `simple_transfer` CLI timed out. r0s2 `Realm worker publication acknowledged` 23:35:36Z checkpoint 230 unique_pending_id **509** (`w2-ack.txt`). Worker log did not grow before SIGCONT. |
| W3 | Five `psy_get_checkpoint_global_state_roots[223]` identical (`user_tree_root=c44af9cd…`). Live tips during wait: `:13381`=230 others 237+. No 23:34–23:37 Fatal/RESTART (`w3-rpc.json`, `w3-fatals.txt`). |
| W4 | Frozen-window identity r0 `sub_2` epoch 23 (anchor 229). Epoch **24** (anchor 239) computed r0 `sub_1` (`w4-scan.json`). Not wall-clock. |
| W5 | SIGCONT 23:37:06Z; `T`→`S`; `size_before=26515` (`w5-cont.json`). `proving start` goal **509** GUTASingleEndCap (`w5-proving.txt`). |
| W6 | Same-epoch proposer r0 `sub_2` epoch 23. 23:37:09Z `scheduled proposer realm=0 sub_id=2 epoch=23 target=230`; certificate `signers=[2]`; follower r0s1 `proposal start accepted` + `proposal body complete` proposal=`cde5de6d…` body_len=**142689**; r0s2 `Committed new realm block with checkpoint_id = 241` (`w6-commit.txt`, `w6-body.txt`). Operator/user-0 leaf on `:13380/:13381` first equals `0069e3ee…` at C241 (C240 still `a540849a…`). Five-edge roots at 241 identical (`w6-rpc.json`). |

