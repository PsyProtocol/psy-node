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
| Rollback IMT key-index entry (`RollbackImtKeyIndexEntry`) | Frozen physical key `(tree_id, tree_sub_id, key_bucket, encoded_key)` and explicit nullable target for `set_imt_key_index`; null deletes, a row restores. |
| Rollback IMT key-index row (`RollbackImtKeyIndexRow`) | Canonical sentinel target `(leaf_key, birth_checkpoint, leaf_index)` derived from the earliest retained leaf version at or before the rollback target, not the latest update. |

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
| RewardTree | Existing checkpoint reward commitment over tagged proving jobs. |
| UserRewardTree | Rebuildable binary proof aggregation for one user's selected GUTA jobs at one checkpoint; no persistent consumed-job history. |
| UserRewardLeafCircuit | Authenticates one selected job and one empty-to-occupied transition in the claim-local nullifier tree. |
| UserRewardAggregateCircuit | Verifies two consecutive child transitions or lifts one UserRewardLeaf proof; binds common user, source checkpoint and complete source checkpoint leaf hash. |
| UserRewardRootCircuit | Authorizes the chosen recipient through a pinned key-ownership relation and authenticated registration membership; requires empty initial nullifier root, historical source-leaf inclusion and exact checkpoint fee payout. |
| RewardClaimWrapCircuit | Plonky2 wrapper for one pinned complete-list UserRewardCheckpointAggregate proof and its cyclic suffix; computes the full token-domain message Keccak commitment and emits its 256 bits for SharedGroth16Wrapper. Singleton uses the same protocol. Keystore directory: `reward_claim`. |
| register_reward_claim_commitment | Circuit operation hashing the complete reward claim message with legacy Keccak-256 and registering only its 256 digest bits, grouped as little-endian bits of successive big-endian 64-bit digest chunks. |
| rewardRootCheckpointId | StateManager mapping from checkpoint tree root to verified finalize checkpoint id; recognition requires `rewardRootsClean` and a nonzero id within `lastFinalizedCheckpointId`. Sole checkpoint-id source for the enumerated roots. |
| finalizedRewardRoots / finalizedRewardRootCount | StateManager's unique `bytes32[]` enumeration of registered proof-tip roots and its length getter. No mirrored checkpoint IDs or cleanup cursor. |
| rewardRootsClean | StateManager flag initialized true on fresh deployment, false atomically on a real force-set with registered roots, true again only when bounded cleanup empties the enumeration. Finalization and reward recognition require true. |
| revokeAbandonedRewardRoots | Admin-only bounded deletion of at most `maxEntries` roots from the enumeration and mapping after a real force-set; governance command `state-manager:revoke-abandoned-reward-roots --max-entries`. |
| RewardRootCleanupRequired / InvalidRewardRootCleanup / RewardRootAlreadyRegistered | StateManager errors for paused finalize, zero-bound or inactive/uninitialized cleanup, and duplicate root registration, respectively. |
| Claim-local nullifier tree | Temporary positional tree initialized empty for each claim; its index is `(2^(height - 2) - 1) + path_index` for the authenticated GUTA coordinate. |
| old_nullifier_root / new_nullifier_root | Paired endpoints of a claim-local nullifier-tree transition; not durable user consumption history. |
| nullifier_siblings | Authentication path for one insertion into the claim-local nullifier tree. |
| job_count | Number of selected, authenticated jobs represented by a reward proof. |
| checkpoint_fees / checkpoint_jobs_completed | Authenticated GUTA fee total and completed-job count from the source checkpoint; payout is `floor(job_count * checkpoint_fees / checkpoint_jobs_completed)`. |
| source_checkpoint_leaf_hash | Poseidon hash of the complete reward-source checkpoint leaf, computed in each UserRewardLeaf proof and authenticated against the finalized checkpoint tree in UserRewardRoot. |
| UserRewardCheckpointAggregateCircuit | Fixed binary recursion over one user's independently calculated checkpoint payouts; exposes the entire padded checkpoint-ID list, checked sum and common identity/recipient/root. No per-node payout hash. |
| UserRewardCheckpointAggregateWitness::{Root, Pair} | Lift one independently pinned registration-aware UserRewardRoot proof or combine exactly two ordered checkpoint-aggregate proofs. |
| checkpoint_ids / checkpointIds | Circuit/Rust and Solidity spellings for the complete claimed checkpoint list. Active prefix is determined by checkpoint_count; inactive circuit/message slots are zero. Checkpoint zero is valid. |
| checkpoint_count | Checked u32 number of active checkpoint IDs, bounded by the one compiled transaction capacity; distinct from per-checkpoint job_count. |
| total_amount / totalAmount | Checked u128 sum of independently calculated checkpoint payouts; Solidity ABI uses uint256 with an explicit u128 bound. |
| recipient | Nonzero 160-bit EVM mint destination chosen by the authenticated user and bound throughout the proof/message. Conversational `psyout` refers to this destination only; it is not a source symbol or a public-key hash/address equivalence. |
| claimed | Token-owned `mapping(uint32 => mapping(uint32 => bool))`, keyed by userId then checkpointId; authoritative successful-claim state, not local proof-cache state. |
| RewardClaimWrapWitness | Wrapper witness containing the token and StateManager address bytes. |
| RewardClaimed | Token event containing userId, recipient, authenticated checkpointRoot, complete active checkpointIds and totalAmount for one successful atomic mint. |
| RewardJobAggregate | Rebuildable proof of one user's exact selected jobs against one complete source leaf; no recipient, finality or payment authority. |
| RewardJobOriginals | User ID, source checkpoint ID and original selected UserRewardJobWitness values retained separately from the disposable proof cache; recovery also requires historical source/path material. |
| RewardJobAggregateCache | Disposable serialized job Aggregate plus schema, network magic, user, source checkpoint, complete source leaf and hash, exact selection identity, leaf and aggregate fingerprints, common digests, verifier digests, and the proof. It stores neither originals, an external setup document, a circuit-set hash, nor paid state. |
| RewardSelectedJob | Source checkpoint ID, authenticated height and path index identifying one selected job coordinate; not the full UserRewardJobWitness or an ownership proof. |
| FinalizedCheckpointAnchor | Source inclusion and authorization-anchor checkpoint IDs/leaves/paths, shared checkpoint-tree root and authenticated global roots; registration leaf, registration index and registration path authenticate membership. Its name alone does not establish L1 root recognition. |
| reuse_reward_job_aggregate | RewardClient operation validating a disposable cached proof against network magic, source fingerprints, common and verifier digests, the proof, current originals, and the complete source leaf before returning a reusable RewardJobAggregate. A mismatch is not payment or consumption. |
| get_reward_job_originals | RewardJobAggregate accessor returning user ID, source checkpoint ID and cloned original selected job witnesses for retention independently of the proof cache. |
| build_reward_job_aggregate_cache | RewardJobAggregate method assembling the disposable cache from the session network magic and the built circuits' source fingerprints, common digests, and verifier digests. It returns that cache with separately retained RewardJobOriginals and performs no durable write. |
| prove_reward_job_aggregate | RewardClient function proving selected jobs from an empty temporary tree before finality is required. |
| prove_finalized_reward_root | RewardClient function authenticating a validated job aggregate's exact source leaf under a recognized root and authorizing its recipient. |
| claimReward | Permissionless PsyToken entry verifying a complete checkpoint list and recognized root, consuming pairs and minting the proved sum once. |
| REWARD_CLAIM_VERIFIER_ID | Dedicated reward verifier registry key: keccak256("REWARD_CLAIM_VERIFIER"); finalize retains ZK_VERIFIER_ID. |
| CLAIM_DOMAIN | One compiled domain constant for the token-owned full-checkpoint-list message. Solidity keeps the keccak256 expression; Rust keeps the matching compiled bytes. The exact expression and byte encoding belong only to checkpoint-claim-cutover.md. |
| REWARD_CLAIM_MAX_CHECKPOINTS | One compiled artifact and transaction capacity. |
| skip_reward_claim | CLI flag on RegenerateGroth16KeystoreArgs. With no skip flags, regenerate-groth16-keystore generates bridge_agg, deposit_append, withdrawal_claim, and reward_claim. skip_bridge_agg, skip_deposit_append, skip_withdrawal_claim, and skip_reward_claim each omit one cohort. |
| regenerate_reward_claim | Internal helper in the existing keystore generator, producing the reward_claim artifact set through RewardClaimWrapCircuit and SharedGroth16Wrapper. |
| `PrepareRewardClaimRequest` | Browser prepare input: `rewardToken`, `userId`, nonzero `recipient`, original `RewardPendingSelection`, existing L1 and prove-proxy URLs, optional proxy bearer, and `RewardJobAggregateCache` values. It carries no external setup document. |
| `RewardClaimPreparation` | Tagged prepare result: `ready` carries one `PreparedRewardClaim` and excludes that claim's jobs from `remainingJobs`; `proof_only` carries at least one validated job Aggregate and retains every unpaid original; `nothing_to_claim` means no unclaimed original remains, including an empty input. Deferred work without a completed aggregate is an error, not `proof_only`. |
| `PreparedRewardClaim` | One unsigned `claimReward` transaction whose observed `chainId` is exactly `1`, `31337`, or `11155111`: `to`, `value` `0x0`, calldata, `stateManager`, checkpoint root, user, recipient, strictly increasing checkpoint ids, decimal `u128` total, and pinned block hash. It has no reported config hash. Confirm rediscovers the token and StateManager from the provider at the receipt block and requires `chainId` to equal that observed `eth_chainId`. |
| `DeferredRewardCheckpoint` | One source checkpoint deferred because its historical read failed or because the source is temporarily unrecognized or unavailable. The record holds that checkpoint id and the reason; its original jobs stay in `remainingJobs`. |
| `RewardClaimConfirmation` | Tagged confirm result: `pending` is only a transaction hash with no receipt; `confirmed` requires that hash to match the transaction and receipt, the receipt block hash to equal the block hash at its number, both `RewardClaimed` and the zero-address mint `Transfer` to be emitted by the prepared token, and `claimed` true for every id at that block. |
| `prepare_reward_claim_json` / `prepareRewardClaim` | Async WASM and TypeScript prepare calls. WASM parses with `serde_json`; TypeScript uses `PsyJSON` only at its queue boundary. They prove with the held ZK key and circuits built from the existing RPC config, and return `RewardClaimPreparation`. |
| `confirm_reward_claim_json` / `confirmRewardClaim` | Async WASM and TypeScript confirm calls. Arguments are the L1 URL, the `PreparedRewardClaim`, and the transaction hash. They do not receive an external setup document and do not rebuild circuits. They return `RewardClaimConfirmation` and do not poll. |
| `prove_reward_root` | `SignatureUser` method taking `&RewardClient`, `&UserRewardCircuits`, the job Aggregate, the finalized anchor, and the recipient. The trait default returns `anyhow::bail!` for an unsupported signer. Only `ZKUser` overrides it and calls `RewardClient::prove_finalized_reward_root` with its held private key. |
| `RewardCheckpointStatement` | Result of `bind_reward_checkpoint_statement`: `checkpoint_tree_root: [u8; 32]`, `checkpoint_ids: Vec<u32>`, and `total_amount: [u8; 32]`. The root is the recognized checkpoint-tree root packed from four Goldilocks limbs. The ids are the active, strictly increasing checkpoint ids. The total is the checked `u128` as a 32-byte big-endian word. User and recipient are checked against the request and are not fields. |
| `bind_reward_checkpoint_statement` | Shared check that the checkpoint-aggregate public inputs match the user, recipient, recognized root, active checkpoint ids, zero inactive slots, and total. It returns `RewardCheckpointStatement`. |
| `encode_reward_claim_calldata` | Shared encoder of unsigned `claimReward` calldata from 256-bit proof words, root, user, recipient, ids, and total. |
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

### Unsigned integers

`uint` names the checked unsigned integer family: language types `u32`, `u64`,
`u128`, and `u256`. `Uint<N>` holds N little-endian `u32` limbs; a limb is one
base-2^32 digit. `UintValue<F, N>` holds the corresponding DPN scalar values.
`U64`, `U128`, `U256` and their `*Value` forms are width-specific aliases.
The generic `DPNContext::op_uint_*` methods expose these operations to callers
and delegate to `UintValue`; they add no serialized opcode. N=1 arithmetic,
bitwise, and shift methods use existing native `op_u32_*` operations. Wider
widths expand into existing
range-checked scalar DPN operations. `mul` computes a full 2N-limb product and
rejects overflow beyond N limbs. `div_rem` computes the unsigned quotient and
remainder, rejecting a zero divisor. Shifts take a `u32` distance: bits moved
past the 32N-bit width are dropped, and a distance of 32N or more yields zero.
Carry and borrow name the digits propagated between adjacent limbs.
The deployment ABI preserves `U256` as a primitive name; its state-layout
proof uses the existing fixed array of eight `U32` limbs (eight slots), not
packed `U64`, `U128`, or `Hash` storage. No new circuit or primitive tag is introduced.
`get_value`, `set_value`, and `get_value_other` are lossless u256 map operations.
`u256_map_key_hash` derives the two physical IMT keys from namespace, key hash,
and half index under the ASCII `U256MAP` domain. Each logical value consumes two
entries of the existing map capacity; generic map methods retain digest semantics.

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
8. `explicit` is not a domain name. A keystore path is `set` or `default`.
9. `config.json` is the one public `GuardianConfig` file: `network`, `guardians`, and `client`. Keystore paths reference `~/.psy/keystore` and the file holds no key bytes.
10. `guardian-id` is `1`, `2`, or `3`. It selects `guardians.<id>` and member-hash slot `id - 1`.
11. `GuardianRuntimeConfig` is the in-memory view of one selected guardian, including the operator-supplied `--db-path`. It is not a file and has no TLS or signing-authorization field.
12. `GuardianDb` is the exclusive redb owner of one signing key. `guardian-service` creates a missing `--db-path` once and opens an existing nonempty file. `guardian-create-db` is not a command.
13. `HaltReason` has five values: `FinalityConflict`, `CheckpointConflict`, `NonceConsumedDifferently`, `IncludedTransitionMissing`, and `AppendHistoryMismatch`. No signing-authorization reason exists.
14. `guardian_common` is the shared guardian protocol, runtime, database and EndCap-bound crate. The generator and relayer consume it; it depends on neither binary.
15. `GuardianConfig` is the public config root containing the typed network, three signer configurations and the client configuration. `GuardianConfig::load` is its sole Rust file decoder.
   `guardian_user_operation` is the acceptance-only isolated worker for one existing deposit, claim, or withdrawal API call. Its public outcome contains operation, transaction hash and status; it is not a production command.
16. `GuardianSignerConfig` contains one guardian's bind address and two absolute standard-keystore references. It has no database path.
17. `GuardianClientConfig` contains the public client endpoints, archive path, history bind and L1 endpoint mapping nested in `GuardianConfig.client`; it is not a separate file.
18. `load_authorization_archive` loads the fixed config-relative authorization index and version files and verifies their hashes and authorization bounds.
19. `build_runtime_config` derives one `GuardianRuntimeConfig` from the public root, guardian id, operator database path and active authorization index.
20. `validate_rpc_network` compares the external compiled-stage typed network with the embedded guardian network after clearing only external `prove_proxy_url` and materializing empty system-proxy arrays on both sides.

### Naming governance — guardians-root

The guardian domain owns the `Guardian` type head and `guardian_common` crate. `GuardianConfig`, `GuardianSignerConfig`, `GuardianClientConfig`, and `GuardianRuntimeConfig` have different contents, not equivalent-type aliases. Their three-instance signer collection uses one type. Existing cryptographic labels, request preimages and redb table/codec identifiers are unchanged by configuration consolidation.

| Occurrence in guardians-root design | Disposition | Basis |
|---|---|---|
| `generate-genesis-data`, `get_populated_checkpoint_leaf` | Existing API spelling, unchanged | Existing CLI and node-builder entry points; this task changes their wiring, not their names. |
| `parse_canonical_json` | Existing API spelling, unchanged | Existing shared protocol decoder and its wire-validation semantics; extraction keeps the spelling and behavior. |
| `ApprovedContract.compiler_artifact_json` and `contract_leaf_json` | Protected serialized keys | Existing authorization JSON encoding at `psy_cli/guardian_common/src/protocol.rs:156-161`. |
| `archive/relayer-journal` | Protected public path | User-approved single-file guardians-root/archive layout. |
| `canonical` in hash-limb description | Non-violation | Mathematical field encoding property, not a newly named code component. |
| `old` inside `threshold` | Non-violation | Quantity threshold, not a lifecycle qualifier. |

The scope of this disposition is the guardians-root sections of `genesis-generation.md` and the vocabulary rows above, not unrelated terminology entries or a future production-source naming sweep.

### Naming governance — checkpoint reward claims

Retain UserRewardLeaf, UserRewardAggregate, UserRewardRoot, UserRewardCheckpointAggregate and RewardClient. Checkpoint composition and advance job aggregation stay distinct operations. `canonical` in a Goldilocks range check is the mathematical field predicate, not a lifecycle label. `verifyProof(uint256[8], uint256[2])` and `keccak256("REWARD_CLAIM_VERIFIER")` are protected API and cryptographic literals. Registration leaf, registration index and the pinned public-key parameter stay distinct from userId and recipient; do not register every private local as a term.


SDK prepare and confirm names are `PrepareRewardClaimRequest`, `RewardClaimPreparation`, `PreparedRewardClaim`, `DeferredRewardCheckpoint`, `RewardClaimConfirmation`, `RewardCheckpointStatement`, `prepare_reward_claim_json`, `prepareRewardClaim`, `confirm_reward_claim_json`, `confirmRewardClaim`, `prove_reward_root`, `bind_reward_checkpoint_statement`, and `encode_reward_claim_calldata`. `RewardClaimPreparation` is the status outcome, not a wrapper around an unspecified body. `RewardCheckpointStatement` is the bound checkpoint root, active checkpoint ids, and total. `prove_reward_root` has one `anyhow` failure for an unsupported signer and one `ZKUser` override. `getClaimRewardsCallArgs` and `claimRewards` are removed rather than aliased. The relation and encodings stay in checkpoint-claim-cutover.md section 6.

`ensure_eval_cache` evaluates a symbolic expression graph in postorder using a heap stack. `resolve_felt_ref_ready` and `resolve_array_ref_ready` evaluate one node after its scalar and array dependencies are cached. Compilation preserves the same child postorder and register allocation order with a heap stack.
