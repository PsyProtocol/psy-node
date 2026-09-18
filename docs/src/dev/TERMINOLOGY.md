# TERMINOLOGY

Internal developer vocabulary for the PsyProtocol cohort. English only.
Not part of the published mdBook (`SUMMARY.md`). This file is the naming
authority for functions, variables, fields, and types. `AGENTS.md` requires
reading it before choosing a name. Role-specific docs still own their
pipelines.

One concept, one term. Reuse an existing word. Do not add a synonym. If a
needed term is absent, add it here in the same change that introduces the
symbol.

Current sources: `AGENTS.md` naming verbs; `docs/src/protocol/` circuit and
architecture docs; `docs/src/dev/processors.md`; `docs/src/dev/gatherers.md`;
`docs/src/dev/deposit-withdrawal.md`; `docs/src/dev/private-transfer.md`;
`psy_data/src/node/realm_processor.rs`; `psy_node_common/src/realm/processor/`.

Pipeline internals stay in their owners: reward-tree layouts, gatherers,
processors, circuit operations.

## 1. Verbs

Use one verb for one act. Do not invent a synonym.

| Verb | Means | Examples |
|---|---|---|
| `get` | Read an existing value | `get_latest_checkpoint_id` |
| `load` | Assemble a domain value from durable storage | `load_proposal`, `load_realm_memory_trees_from_db` |
| `read` | Decode a file or byte stream | `read_body_chunk`, `read_staged` |
| `build` | Assemble a composite value without persistence | planner job trees, `build_proposal_with_body` |
| `create` | Make a new stored or runtime object | `create_staged` |
| `recreate` | Abort a runtime object and create a replacement | `recreate_guta_gatherer` |
| `abort` | Cancel a runtime task | `abort_guta_gatherer` |
| `set` | Replace a whole value | `set_latest_checkpoint_id` |
| `update` | Change part of a value | `update_from_core_state` |
| `save` | Write durable bytes | `save_proposal` |
| `apply` | Execute a state transition | `apply_history_proposal`, `apply_proposal_ffs`, `apply_fast_forward_with_tree` |
| `commit` | Write the durable checkpoint records and marker | `commit_state` |
| `verify` | Check an untrusted or reconstructed candidate | `verify_history_transition`, `verify_history_proposal` |
| `validate` | Check untrusted or serialized input | wire/body checks |
| `ensure` | Enforce an internal invariant; return an error | `ensure_db_matches_coordinator_head` |
| `check` | Classify state or health | `get_database_check_state` |
| `sync` | Copy authenticated coordinator metadata locally | `sync_with_coordinator`, `sync_to_coordinator_checkpoint_id` |
| `install` | Verify staged bytes, atomically rename them into their destination, then fsync the parent directory | `ProposalBackup::install` |
| `stage` | Write a candidate that is not yet retained | `create_staged`, `stage_transition_blocks` |
| `derive` | Compute a deterministic hash or identity from known inputs | `derive_shield_address`, `derive-shield` |

`persist` is banned. Do not add `store_*` as a verb synonym for `save`/`write`.

## 2. Include versus apply versus commit

These three words are not interchangeable.

```text
Proposer submits GUTA + Proposal + Certificate
        |
        v
Coordinator include     realm root appears in a coordinator checkpoint
        |               wait log: "Waiting for Coordinator to include Realm Root"
        v
Realm apply FFS         execute the proposal body against local trees
        |               apply_history_proposal / apply_proposal_ffs
        v
Realm commit            durable mappings, FFS rows, then set_latest_checkpoint_id
                        commit_state; last_committed_* advances
```

| Word | Owner | Meaning | Do not use it for |
|---|---|---|---|
| Include | Coordinator | The checkpoint tree now carries this realm root. Noun: **inclusion**. | Local durable writes. Function names that apply FFS. |
| Apply | Realm (or gatherer FastForward) | Execute the FFS / tree transition. Pair of **unapplied**. | The checkpoint marker write. |
| Commit | Local processor | `commit_state` writes records and the marker. Adjective: **last_committed_**. | Coordinator inclusion. A proposal that is only certified. |

`included` is the coordinator checkpoint that already carries the transition
(`first_root_change` returns it with the `RealmTransition`). It is not a good
function adjective: the ready-path function *applies* FFS, then *commits* locally.

Rejected names for the ready-path function:

| Name | Why not |
|---|---|
| `commit_included_proposal_ffs` | `commit_state` already owns commit. |
| `apply_included_proposal_ffs` | `included` names coordinator inclusion, not the local act. |
| `apply_committed_proposal_ffs` | `committed` is `last_committed_*`, which this function produces, not consumes. |

Chosen name: **`apply_proposal_ffs`**. Verb `apply`, object `proposal_ffs`, same
family as `apply_history_proposal` and `first_root_change`.

Catch-up sibling: `apply_history_transitions` walks `C+1..=tip`. The ready path
applies the next unapplied proposal FFS once per `sync_and_verify`.

`CheckpointIdentity` contains `checkpoint_id` and `checkpoint_leaf_hash`; the latter is the
coordinator checkpoint hash leaf, matching `checkpoint_sync_info.checkpoint_leaf_hash`.
The parameter name is `included`.

## 3. Realm epochs

`RealmProcessorCoreState` (`psy_data/src/node/realm_processor.rs`) keeps three
epochs. Name the epoch; do not invent a fourth.

| Epoch | Fields | Meaning |
|---|---|---|
| Gathering | `gathering_*` | Live EndCap intake. Gatherer-owned trees. May sit on N+1 while N proves. |
| Processing | `processing_*` | The batch being proved / submitted. Speculative until commit. |
| Committed | `last_committed_*` | Durable head. Marker is `set_latest_checkpoint_id`. |

`unique_pending_id` isolates one gathering / processing / committed batch.

## 4. Protocol objects

| Term | Meaning |
|---|---|
| PARTH | Parallelizable Account-based Recursive Transaction History. Hierarchical Merkle forest, not a single global state machine. |
| Coordinator | Single writer of the canonical checkpoint tree. |
| Realm | Shard. Two subs (`sub_id` 1 and 2) replicate one realm. |
| Processor | Long-lived loop: gather, prove, wait for inclusion, commit. |
| Gatherer | Background NATS consumer + planner. Owns the live in-memory tree. |
| Planner | Builds proving jobs and FFS for one gatherer cycle. |
| Edge | HTTP admission surface in front of a processor. EndCaps enter a Realm edge; GUTA submit enters the Coordinator edge. |
| Worker | Proves claimed jobs and submits tagged proofs back through the edge. |
| Relayer | L1/L2 bridge daemon (`psy_relayer_cli`): deposit append, withdrawal claim, Groth16. |
| EndCap | Final proof of one user proving session (`UPSStandardEndCapCircuit`). |
| GUTA | Global user-tree aggregator proof (realm circuit 63 at submit). |
| Proposal | Signed realm transition: old/new realm root plus body hash. |
| Proposal body | Finalizer output, proof, FFS bytes. Retained under `proposal_backups/bodies/`. |
| Certificate | Aggregated BLS votes for a proposal. |
| Vote | One validator signature on a proposal. |
| FFS | Fast-forward synchronization: Merkle-node / leaf updates. The payload followers apply. |
| FastForward | Gatherer command that applies FFS to the live tree, then recreates the builder. |
| CST | Coordinator checkpoint state-transition root job (circuit 32). |
| Checkpoint | Coordinator height `C`. Contiguous. Empty checkpoints still exist. |
| Realm transition | `(old_root, new_root)`. Local name: **`transition`**. Equal roots are leaf rewrites, not bodies. Not a `pair`. |
| Last-modified | Coordinator checkpoint where this realm root last changed. |
| UPS | User proving session. Local recursive proof chain that ends in an EndCap. |
| CFC | Contract function circuit. Verifiable contract method compiled by DPN. |
| DPN | Dapen. Compiles `.psy` contract methods into CFCs. |
| PI | Circuit public input. Recursive GUTA and coordinator proofs expose `H(header, R)`. |
| Tag | Worker claim tag hashed into every reward-tree node. |
| R | Reward-tree node value produced by the circuit for this job. |

Rejected protocol names: `ProcessUserOp`, `AggregateUserOps`, `RealmStateTransition`,
`WrappedSignatureProof` / type 64 as a live circuit 63 child.

## 5. State trees

PARTH is a forest. Do not invent a second name for a tree that already has one.

| Term | Meaning |
|---|---|
| CHKP | Checkpoint tree. Root of one block's global snapshot. |
| GUSR | Global user tree. Leaves are user accounts (`ULEAF`). |
| ULEAF | User leaf: public-key hash, balance, nonce, last checkpoint, `UCON` root. |
| UCON | Per-user contract tree. Maps contract id to that user's `CSTATE` root. |
| CSTATE | Per-user per-contract storage tree. |
| GCON | Global contract tree. Leaves are contract definitions (`CLEAF`). |
| CLEAF | Contract leaf: deployer hash, `CFT` root, `CSTATE` height. |
| CFT | Contract function tree. Function id to CFC fingerprint. |
| URT | User registration tree. |
| GDT | Global deposit tree. |
| GWT | Global withdrawal tree. |
| IMT-indexed tree | Previous `next_append_index != 0` for that `(user_id, contract_id)` contract-state tree. |
| Positional tree | Previous `next_append_index == 0`. Changed leaves on this tree do not require IMT records. |

## 6. Privacy and bridge

| Term | Meaning |
|---|---|
| Shield address | `PoseidonHash(user_id, 1337, r0, r1)`. Receiver identity for private notes and deposit claims. CLI: `derive-shield`. JSON field: `shield_address`. Not `note_owner`. |
| Note commitment | `PoseidonHash(nullifier_secret \|\| note_secret)`. |
| Nullifier hash | `PoseidonHash(nullifier_secret)`. Spend / claim tracker. |
| Private note | Shielded transfer note proved by `PrivateNoteInclusionCircuit`. |
| Deposit | L1→L2 lock via `Router` / `ERC20Gateway` / `Bridge`, claimed on L2 with `claim_deposit`. |
| Withdrawal | L2 burn then L1 release via Groth16 `batchClaimWithdrawal` / `claimPendingWithdrawal`. |
| Groth16 | Bridge wrapper proving system with circuit-specific setup material. |
| Plonky2 | Recursive proving backend for UPS, GUTA, CST, and live E2E. |
| JTMB | Test-only proving backend. Not rollback or live E2E evidence. |

`derive-note-owner` and `note_owner` are retired CLI/result names for shield address.

## 7. Runtime and CLI

| Term | Meaning |
|---|---|
| `psy_node_cli` | Coordinator and Realm node binary. |
| `psy_worker_cli` | Job prover. |
| `psy_user_cli` | Wallet, contract, tree, bridge, and private-note CLI. |
| `psy_relayer_cli` | Bridge relayer. |
| `psy_dev_cli` | Operator CLI, including rollback. |
| Prove proxy | `psy_user_cli prove-proxy`. Groth16 helper for withdrawal claims. |
| ScyllaDB | Primary committed state backend. |
| NATS | Ephemeral gatherer queues. |
| RP | One role-local rollback plan, serialized as JSON. |

## 8. Proposal backup

On-disk directory: `local_checkpoints/realm_{R}_{S}/proposal_backups/`.

| Symbol | Meaning |
|---|---|
| `ProposalBackup` | Runtime object over retained proposal bodies. |
| `proposal_backup` | Field / parameter holding that object. |
| `save_proposal` | Trusted local write: stage then install. |
| `create_staged` | Write a candidate file with RAII cleanup. |
| `install` | Verify staged bytes, atomically rename them into their destination, then fsync the parent directory; the destination is the transition-pair body path, and the backup's in-memory indexes are updated after the rename. |
| `retained` | A proposal body occupies its transition-pair path rather than a staging path; it survives close/reopen until replacement or removal. |
| `RetainedBodies` | In-memory indexes over retained proposal bodies. |
| `load_retained_transitions` | Assemble sorted transition pairs from retained filenames; body verification is separate. |
| `install_staged_proposals` | Test helper installing each staged proposal in fetch outcomes; returns the installed count. |
| `installed_proposal_count` | Number of proposals installed by that helper. |
| `build_proposal_with_body` / `build_proposal_with_body_at_checkpoint` | Test helpers deriving a proposal and its encoded body without persistence. |
| Retired `proposal_store/` | Abandoned directory name. Ignore it. |

## 9. Recovery words

| Term | Meaning |
|---|---|
| Catch-up | Walk coordinator checkpoints from `last_committed + 1` and apply missing transitions. |
| Recovery | Startup path when local state and coordinator head disagree; may rebuild backups. |
| Rollback | Operator-driven rewind of local durable head. Separate from catch-up. |
| Baseline replay | Re-verify FFS against the authenticated previous checkpoint before a vote or durable write. |
| Proof base | Checkpoint that authenticates a gatherer cycle start. |
| `load_changed_leaves_on_imt_indexed_trees` | Nonempty FFS-changed contract-state leaves on IMT-indexed trees. |

## 10. Naming checklist

1. The name says the object (`proposal`, `guta_gatherer`, `checkpoint`, `shield_address`), not a
   category (`data`, `store`, `production`).
2. State qualifiers precede the object: `last_committed_realm_end_root`,
   `processing_checkpoint_id`, `gathering_realm_start_root`.
3. Lifecycle labels (`legacy`, `old`, `deprecated`, `official`, `v1`) never
   name code.
4. Prefer the existing verb table over a new synonym.
5. A verb-table gloss uses only registered verbs plus concrete OS mechanics, never a synonym.
6. A `RealmTransition` is `transition`. Do not name it `pair`.
7. Receiver identity for private notes and deposit claims is `shield_address`. Do not name it `note_owner`.
