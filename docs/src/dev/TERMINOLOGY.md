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
`docs/src/dev/bridge-common-operations.md`; `docs/src/dev/private-transfer.md`;
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
| `PSYGS002` | Inner guardian business request. `GuardianSignRequest::canonical_bytes` is little-endian `PSYGS002`, `schema_version` `2`, network magic, user id, session nonce, operation, the original trace text, deposit anchors, and withdrawal records. `request_id` is `sha256` of those bytes (`GuardianSignRequest::request_id`). Compression does not change this preimage. |
| `PSYGR001` | Outer storage and HTTP envelope, not a business schema. `encode_record` / `decode_record` write little-endian magic `PSYGR001`, version `u32` `1`, uncompressed length `u64`, then one zstd frame at level `3`. Decode returns the original inner bytes. Caps: compressed frame `MAX_COMPRESSED_RECORD_BYTES` (128 MiB, header included); inner payload `MAX_BODY_BYTES` (128 MiB). `MAX_SESSION_RECORD_BYTES` is that same 128 MiB for a session or relayer row, because `GuardianSessionsResponse::to_bytes` rejects anything larger. |
| `application/vnd.psy.guardian-record+zstd` | `Content-Type` of a `PSYGR001` body. Not `Content-Encoding: zstd`. `POST /v1/sign-session` requires it around the canonical request JSON; other media types are `415`. `GET /v1/sessions` returns it only when `Accept` prefers it (`session_representation`); absent or accepted `application/json` stays the JSON page. `Vary: accept`. |
| Guardian journal schema 3 | The eight-table guardian redb set with `guardian_schema` marker `u32` `3`. `guardian_signed` and `guardian_session` values are `PSYGR001` envelopes. A successful `import_session` of nonce `N` deletes `guardian_signed` rows through `N` and `guardian_session` rows strictly below `N`. Session `N` and signed rows above `N` stay. Deposit, account, and withdrawal-index rows stay. |
| Relayer journal schema 3 | The eight-table relayer redb set with `journal_schema` marker `u64` `3`. `relayer_request` values are `PSYGR001` envelopes of the canonical JSON stage row, keyed by `session_nonce`. Steady state keeps the latest `Included` row and at most one unresolved next request. Compression migration is lossless, bumps the schema marker 2→3, and keeps every row until the next authenticated import prunes older request rows in that commit. Bounded retention required no further marker bump. Only those rows are bounded: withdrawal indexes and `retired_claim_withdrawals` still grow. Freed redb pages are reused; the file shrinks only by an offline compact. Exact one-behind Guardian catch-up uses the retained `Included` row. A larger gap stays unavailable. Deleting the database is not a supported recovery, and a saved previous `Included` row does not recover the gap without the checkpoint's canonical conditions. Pruning is not a rollback or timeout repair. |
| `migrate-guardian-journals` | Offline `psy_relayer_cli` command. Required flags: `--rpc-config`, `--guardian-root`. Repeatable `--l1-config` replaces `l1_config_url`. It holds all four exclusive database handles before any migration call, then commits each existing journal in its own transaction, guardian 1, 2, 3, then relayer. Failure before a database's commit leaves that database unchanged. Failure after its commit can leave that database already migrated. Earlier commits remain. It reads each `guardian_signer` singleton and does not prove key possession. It does not open keystores or read password env vars, and it does not write config, keystores, or password files. |
| RewardTree | Existing checkpoint reward commitment over tagged proving jobs. |
| UserRewardTree | Rebuildable binary proof aggregation for one user's selected GUTA jobs at one checkpoint; no persistent consumed-job history. |
| UserRewardLeafCircuit | Authenticates one selected job and one empty-to-occupied transition in the claim-local nullifier tree. |
| UserRewardAggregateCircuit | Verifies two consecutive child transitions or lifts one UserRewardLeaf proof; binds common user, source checkpoint and complete source checkpoint leaf hash. |
| UserRewardRootCircuit | Authorizes the chosen recipient through a pinned key-ownership relation and authenticated registration membership; requires empty initial nullifier root, historical source-leaf inclusion and exact checkpoint fee payout. |
| RewardClaimWrapCircuit | Plonky2 wrapper for one pinned complete-list UserRewardCheckpointAggregate proof and its cyclic suffix; computes the full token-domain message Keccak commitment and emits its 256 bits for SharedGroth16Wrapper. Singleton uses the same protocol. Keystore directory: `reward_claim`. |
| register_reward_claim_commitment | Circuit operation hashing the complete reward claim message with legacy Keccak-256 and registering only its 256 digest bits, grouped as little-endian bits of successive big-endian 64-bit digest chunks. |
| checkpointTreeRootCheckpointId | StateManager's public mapping from a checkpoint-tree root to the checkpoint id registered by verified finalize (`psy-contracts/src/StateManager.sol:46`). Recognition requires `checkpointTreeRootsClean()` and a nonzero id no greater than `lastFinalizedCheckpointId()`. The mapping is the only root registry: there is no root array, no count getter and no enumeration, so abandoned roots are identified from settlement evidence, not on-chain queries. |
| checkpointTreeRootsClean | StateManager flag initialized true. A real `forceSetState` — any actual state change, including a same-height replacement with a different root and an empty registry — sets it false; an exact no-op (target hash equal to the current state hash) returns before the flag write (`psy-contracts/src/StateManager.sol:47,117,138,153`). Finalize and reward recognition require true. No cleanup call restores it implicitly; completion is an explicit admin write. |
| revokeCheckpointTreeRoots / setCheckpointTreeRootsClean | StateManager-admin named revocation and clean-flag setter. `revokeCheckpointTreeRoots(bytes32[] roots)` zeroes exactly the named nonzero `checkpointTreeRootCheckpointId` entries, accepts repeated or already-revoked roots, reverts `InvalidCheckpointTreeRoot` on a zero root, and never changes the clean flag (`psy-contracts/src/StateManager.sol:166-171`). After revoking the approved abandoned list, the admin explicitly calls `setCheckpointTreeRootsClean(bool)` (`psy-contracts/src/StateManager.sol:173-175`). Governance tasks: `state-manager:revoke-checkpoint-tree-roots --roots-json <file-or-json-array>` and `state-manager:set-checkpoint-tree-roots-clean --clean true` (`psy-contracts/tasks/upgrade.ts:82-108`). Neither operation resets claimed pairs. |
| revokeKnownSubtreeRoots | Separate StateManager-admin `revokeKnownSubtreeRoots(bytes32[] depositSubtreeRoots, bytes32[] withdrawalSubtreeRoots)` that flips only the named `knownDepositSubtreeRoots`/`knownWithdrawalSubtreeRoots` membership entries to false (`psy-contracts/src/StateManager.sol:177-187`). It is independent of checkpoint-tree-root revocation, does not touch the clean flag or current state fields, and clearing the current `withdrawalSubtreeRoot` membership does not stop Bridge from accepting equality with that field. |
| CheckpointTreeRootCleanupRequired / InvalidCheckpointTreeRoot / CheckpointTreeRootAlreadyRegistered | StateManager errors for finalize while `checkpointTreeRootsClean` is false, a zero root in the named revocation list, and duplicate registration of a nonzero `checkpointTreeRootCheckpointId`, respectively. |
| read_reward_root_recognized | Recognition read behind the automated claim path, not a second recognition API. `RewardClient::read_reward_root_recognized` selects the `checkpointTreeRootsClean()` and `checkpointTreeRootCheckpointId(bytes32)` selectors (`client_prover/psy_prover/src/local/reward_client.rs:979-987`), matching this contract revision (`psy-contracts/src/StateManager.sol:46-47`; recognition: `psy-contracts/src/PsyToken.sol:90-94`). |
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
| CLAIM_DOMAIN | One compiled domain constant for the token-owned full-checkpoint-list message. Solidity keeps the keccak256 expression; Rust keeps the matching compiled bytes. The exact expression and byte encoding belong only to reward-claim-operations.md. |
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
| `psy_bridge_reader_core` | Bridge Reader deposit-tree core: Poseidon node hashing and the Envio display hex encoding. |
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
8. `explicit` is not a domain name. A keystore path is `set` or `default`.
9. `psy-genesis/config.json` is the one public configuration. Its selected `CURRENT_NETWORK` carries `guardian_configs`, `guardian_history`, optional `l1_config_url`, and the stable public guardian field `guardian_initial_member_hashes`. It holds no `l1_endpoints`, no keystore paths, and no runtime root.
10. `guardian-id` is `1`, `2`, or `3`. It selects `guardian_configs` entry `id` and member-hash slot `id - 1`.
11. `GuardianRuntimeConfig` is the in-memory view of one selected guardian. Its database path is derived as `<guardian_root>/db/guardian-{id}.redb`. It is not a file and has no TLS field. `journal/<id>.redb` is not the runtime path (`psy_cli/guardian_common/src/runtime.rs:178`).
12. `GuardianDb` is the exclusive redb owner of one signing key. `guardian-service` creates a missing derived database file once and opens an existing nonempty file. An existing empty file returns `DatabaseUnavailable`; the service does not delete or reinitialize it. There is no journal error for that case. `guardian-create-db` is not a command.
13. `HaltReason` has five values: `FinalityConflict`, `CheckpointConflict`, `NonceConsumedDifferently`, `IncludedTransitionMissing`, and `AppendHistoryMismatch`. No signing-authorization reason exists.
14. `guardian_common` is the shared guardian protocol, runtime, database and EndCap-bound crate. The generator and relayer consume it; it depends on neither binary.
15. `GuardianConfig` is the in-memory runtime value of the selected canonical network plus the explicit guardian root and the loaded chain documents. `GuardianConfig::load(rpc_config, guardian_root, local_documents)` builds it; it is not serialized and has no file of its own.
   `guardian_user_operation` is the acceptance-only isolated worker for one existing deposit, claim, or withdrawal API call. Its public outcome contains operation, transaction hash and status; it is not a production command.
16. `GuardianPublicConfig` is one canonical-network entry: `id`, `listen_address`, and an optional `rpc_url`. `listen_address` uses a nonzero port. The advertised origin is `rpc_url` when present, otherwise `http://` plus `listen_address`. That origin must be unique across the three guardians after URL normalization. A wildcard host (`0.0.0.0` or `::`) is rejected. The entry holds no keystore path and no database path (`dev/locSetupV4.ts:3988-3994,4036-4047`).
17. `GuardianHistoryConfig` is the canonical-network history listener: `listen_address` and an optional `rpc_url`. Its advertised origin follows the same nonzero-port and non-wildcard rule. It is not a separate file, and there is no serialized `client.endpoints` list (`dev/locSetupV4.ts:3997-4002`).
18. `guardian_initial_member_hashes` is the selected network's only stable public guardian field: exactly three distinct nonzero hashes; `GuardianConfig::from_network` rejects a missing, zero, or duplicate entry (`psy_cli/guardian_common/src/runtime.rs:137-142`). Protocol required-fee, overflow, and burn accounting remain authoritative. `initial_account` derives the `MultisigAccount` from those hashes with the fixed Rust contract id `MULTISIG_POLICY_CONTRACT_ID` (1), version 1, threshold 2, member count 3, and slots 0-2 filled (`psy_cli/guardian_common/src/protocol.rs:413-426`). There is no `guardian_authorization` object, policy JSON field, policy digest, authorization table, or authorization file; the runtime databases hold no policy record. `multisig_fingerprint()` is compiled Rust (`protocol.rs:424`), and the EndCap verifier fingerprint is the existing compiled `END_CAP_CIRCUIT_FINGERPRINT_HASH_U64_X4` constant, not config; proxy verifier data is compared against it (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:450-471`). Contract ids and state-tree heights are fixed Rust constants. Calls are accepted from checkpoint, contract, and function Merkle proofs against the authenticated state roots, not from a configured code allowlist (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:88-91,132-148`).
19. `build_runtime_config(guardian_id)` derives one `GuardianRuntimeConfig` from the selected network and the explicit guardian root. `guardian_id` is `u8` and is not an index into any authorization record. `guardian_keystore_path(id)` returns the `$HOME`-derived keystore path and `guardian_password_env(id)` returns `GUARDIAN_1_KEYSTORE_PASSWORD`, `GUARDIAN_2_KEYSTORE_PASSWORD`, or `GUARDIAN_3_KEYSTORE_PASSWORD`; neither value is serialized and no password file exists (`psy_cli/guardian_common/src/runtime.rs:101-113,178`).
20. `ChainEndpoint` is the in-memory `{ chain_index, chain_id, bridge, deployment_block, rpc_url }` parsed from the selected deployment documents, not an `l1_endpoints` field and not configuration. `deployment_block` is the inclusive cold-scan bound from Bridge deployment metadata. Repeatable `--l1-config` paths replace the selected network's `l1_config_url`. A local summary has no `l1_chains` key: its sibling `Bridge_Proxy.json` `address` must match the summary `bridge`, and `deployment_block` is that file's `receipt.blockNumber`. A remote `l1_config_url` document is an `l1_chains` registry: each entry must already carry `deployment_block`. A missing or unparsable value fails startup. There is no block-zero fallback and no remote migration. Indexes and chain ids must be unique, `bridge` must parse, and no URL may use port `0` or a wildcard host. The runtime rejects a selected network that omits its guardian endpoints; there is no fallback to daemon TOML L1 URLs (`psy_cli/guardian_common/src/protocol.rs:184-193`; `psy_cli/guardian_common/src/runtime.rs:188-315`; `dev/locSetupV4.ts:358-375`).
21. `GuardianSignError` is the one guardian signing error enum (`psy_cli/guardian_common/src/protocol.rs:125-137`), carried as `code` in `GuardianSignErrorResponse`. Per-variant `http_status`: 400 `MalformedRequest`; 401 `UnauthorizedCaller`; 403 `AccountIdentityConflict`, `UnsupportedCall`, `PolicyMismatch`, `ProofMismatch`, `TraceMismatch`, `DepositMismatch`, `WithdrawalMismatch`, `L1ResponseMismatch`; 409 `AuthorizationMismatch`, `StateMismatch`, `NonceConflict`, `WithdrawalNonceConflict`; 503 every other variant, including `AccountHalted`, `ListenerUnavailable`, and `SignalHandlerUnavailable`. `retry_after_ms` is 1000 only for `L1RpcUnavailable`, `L2RpcUnavailable`, `DepositLogsUnavailable`, `SignatureQuorumUnavailable`, `FinalityPending`, `CheckpointProofUnavailable`, `DatabaseUnavailable`, `SessionHistoryUnavailable`, `ObserverTimeout`, `SigningPreparationTimeout`, `SigningBusy`, `IndexCheckpointTimeout`, and `KeyUnavailable`; every other variant, including 503 `AccountHalted`, `ListenerUnavailable`, and `SignalHandlerUnavailable`, retries 0 (`psy_cli/guardian_common/src/protocol.rs:144-164`). `GuardianAccountError` wraps it as `Unavailable(GuardianSignError)` or `Conflict(HaltReason)` (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:555-557`).
22. `MissingCheckpointProof` is the provider's typed error (`psy_provider::lps`, `client_prover/psy_provider/src/lps.rs:29-51`) for a user-tree Merkle proof whose checkpoint is not yet readable. `classify_user_tree_proof` matches it only for the same checkpoint id and retries until the caller deadline: waiting ends in `IndexCheckpointTimeout`, every other failure stays fail-fast with `CheckpointProofUnavailable` (`psy_cli/psy_relayer_cli/src/guardian/verify.rs:582-610`).
23. `DepositTreeState` is the incremental per-chain deposit-tree state: `count`, 32-slot `frontier`, `root`, `anchor`, `event_block`, `previous_count`, `previous_root`, and occupied partial-page hashes; `validate` recomputes the frontier root (`psy_cli/guardian_common/src/protocol.rs:317-351`). `event_block` is the log cursor, not a string prefix. `GuardianDb::load_deposit_tree_states` reads it point-keyed from `deposit_tree_states` by `DepositTreeKey` (`network_magic`, `user_id`, `chain_index`; type name `guardian_common::DepositTreeKey`). `GuardianDb::contains_included_withdrawal_burn` reads `included_withdrawal_burns` by `WithdrawalBurnKey` (`network_magic`, `user_id`, sender, token contract, burn nonce; type name `guardian_common::WithdrawalBurnKey`); that key is not an identity. `guardian_withdrawal_nonce` remains the second point index (`network_magic`, `user_id`, `chain_index`, nonce). Lookups are exact point reads, never session scans (`psy_cli/guardian_common/src/db.rs:20-34,417-425`).
24. `encode_record` and `decode_record` are the only `PSYGR001` codec (`psy_cli/guardian_common/src/protocol.rs:14-60`). The envelope is representation, not a second business identity. Inner sign requests stay `PSYGS002` with `schema_version` `2`. Full code, trace, signature, and proof bytes remain inside the inflated payload; nothing is rehydrated from RPC.
25. Guardian schema 3 is marker `guardian_schema` `u32` `3` and exactly `deposit_tree_states`, `guardian_account`, `guardian_schema`, `guardian_session`, `guardian_signed`, `guardian_signer`, `guardian_withdrawal_nonce`, `included_withdrawal_burns` (`psy_cli/guardian_common/src/db.rs:20-30`). Only `guardian_signed` (`MAX_BODY_BYTES`) and `guardian_session` (`MAX_SESSION_RECORD_BYTES`) values are `PSYGR001` envelopes. Successful `import_session` of nonce `N` deletes this account's signed keys through `N` (`Bound::Included`) and session keys strictly below `N` (`Bound::Excluded`). Session `N` and signed keys above `N` remain, as do deposit, account, and withdrawal-index rows (`psy_cli/guardian_common/src/db.rs:777-787`).
26. Relayer schema 3 is marker `journal_schema` `u64` `3` and exactly `journal_schema`, `chain_claims`, `finalization_batch`, `guardian_account`, `deposit_tree_states`, `included_withdrawal_burns`, `guardian_withdrawal_nonce`, `relayer_request` (`psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:217-277`). `relayer_request` is keyed by `u64` `session_nonce` and stores `encode_record` of the canonical JSON stage at `MAX_SESSION_RECORD_BYTES`. Steady state keeps the latest `Included` row and at most one unresolved next request. The lossless compression migration bumps the schema marker 2→3 and keeps every row until the next authenticated import deletes older request rows in that commit. Bounded retention required no further marker bump. Only those rows are bounded: `included_withdrawal_burns`, `guardian_withdrawal_nonce`, and `retired_claim_withdrawals` still grow. Freed redb pages are reused; the file shrinks only by an offline compact. Exact one-behind Guardian catch-up uses the retained `Included` row. A larger gap stays unavailable. Deleting the database is not a supported recovery, and a saved previous `Included` row does not recover the gap without the checkpoint's canonical conditions. Pruning is not a rollback or timeout repair.
27. `migrate-guardian-journals` is the operator command on `psy_relayer_cli` (`psy_cli/psy_relayer_cli/src/main.rs:39-48,284-328`). Flags are `--rpc-config`, `--guardian-root`, and repeatable `--l1-config`. `open_migration_database` takes all four exclusive handles before any migration call; each database then commits alone, guardians 1–3 then relayer. Failure before a database's commit leaves that database unchanged. Failure after its commit can leave that database already migrated. Earlier commits remain. Marker 3 is checked and not rewritten. Signer identity comes from the existing `guardian_signer` row (`migration_signer`); the command does not call `load_signing_key`, does not prove key possession, and does not read `GUARDIAN_{1,2,3}_KEYSTORE_PASSWORD`. Normal guardian startup still does. The command creates no database and writes no config or password file.
28. `application/vnd.psy.guardian-record+zstd` is the `Content-Type` for a `PSYGR001` HTTP body (`psy_cli/psy_relayer_cli/src/guardian/service.rs:47-48,458-469,667-728`). `POST /v1/sign-session` rejects every other type with `415`. `GET /v1/sessions` uses `Accept`: missing or accepted `application/json` returns JSON; the custom type wins only when its positive quality is at least the JSON and `*/*` qualities. Quality `0` excludes a type. Neither path uses `Content-Encoding`.

### Naming governance — guardians-root

The guardian domain owns the `Guardian` type head and `guardian_common` crate. `GuardianConfig`, `GuardianPublicConfig`, `GuardianHistoryConfig`, and `GuardianRuntimeConfig` have different contents, not equivalent-type aliases. Their three-instance signer collection uses one type. Existing cryptographic labels, request preimages and redb table/codec identifiers are unchanged by configuration consolidation.

| Occurrence in guardians-root design | Disposition | Basis |
|---|---|---|
| `generate-genesis-data`, `get_populated_checkpoint_leaf` | Existing API spelling, unchanged | Existing CLI and node-builder entry points; this task changes their wiring, not their names. |
| `parse_canonical_json` | Existing API spelling, unchanged | Existing shared protocol decoder and its wire-validation semantics; extraction keeps the spelling and behavior. |
| `guardian_initial_member_hashes` | Stable public guardian field | The only guardian policy input on the selected network: three distinct nonzero member hashes. There is no `guardian_authorization`, `approved_contracts`, `contract_leaf_json`, policy JSON string, or digest field (`psy_cli/guardian_common/src/runtime.rs:137-142`; `dev/locSetupV4.ts` guardian preflight). |
| `MULTISIG_POLICY_CONTRACT_ID` | Fixed Rust account contract id | The derived `MultisigAccount` always uses contract 1 with version 1, threshold 2, and member count 3. `multisig_fingerprint()` is compiled Rust, not config. No configurable contract id or 2-of-3 policy JSON exists (`psy_cli/guardian_common/src/protocol.rs:413-432`). |
| `db/guardian-1.redb`, `db/guardian-2.redb`, `db/guardian-3.redb`, `db/relayer.redb` | Runtime databases under `<guardian_root>/db` | Schema 3, eight tables each, one transaction per file. Guardian marker `guardian_schema` `u32` `3`: `deposit_tree_states`, `guardian_account`, `guardian_schema`, `guardian_session`, `guardian_signed`, `guardian_signer`, `guardian_withdrawal_nonce`, `included_withdrawal_burns`. `guardian_signed` and `guardian_session` values are `PSYGR001` envelopes; successful import of nonce `N` deletes signed rows through `N` and session rows below `N`, and keeps session `N` plus signed rows above `N`. Relayer marker `journal_schema` `u64` `3`: `journal_schema`, `chain_claims` (key `u8` `chain_index`; `pending_claim_withdrawals`, `claim_retry`, `retired_claim_withdrawals`), `finalization_batch` (singleton key `()`; `pending_finalization_range` of `from_checkpoint` and `to_checkpoint`, plus `finalized_chains`), `guardian_account`, `deposit_tree_states`, `included_withdrawal_burns`, `guardian_withdrawal_nonce`, and `relayer_request` (`PSYGR001` of the JSON stage). Lossless compression migration bumps the schema marker 2→3 and keeps every request row; bounded retention required no further marker bump. The next authenticated import prunes to the latest `Included` plus at most one unresolved next request. Only those rows are bounded: withdrawal indexes and `retired_claim_withdrawals` still grow. Freed redb pages are reused; the file shrinks only by an offline compact. Neither file stores `producing_session`, `last_finalized_checkpoint`, or `identity_namespace`. `retired_claim_withdrawals` keeps that name. `guardian1.redb` is not a filename. These files hold no policy record (`psy_cli/guardian_common/src/db.rs:20-30,777-787`; `psy_cli/psy_relayer_cli/src/bridge/guardian_client.rs:217-277`). `archive/relayer-journal`, `pending.json`, `included.json`, and `account.lock` stay unadded. `migrate-guardian-journals` is the offline per-database migration; failure before a commit leaves that database unchanged, failure after a commit can leave it migrated, and earlier commits remain. It is not a config or password writer. |
| `canonical` in hash-limb description | Non-violation | Mathematical field encoding property, not a newly named code component. |
| `old` inside `threshold` | Non-violation | Quantity threshold, not a lifecycle qualifier. |


The scope of this disposition is the guardians-root sections of `genesis-generation.md` and the vocabulary rows above, not unrelated terminology entries or a future production-source naming sweep.

### Naming governance — checkpoint reward claims

Retain UserRewardLeaf, UserRewardAggregate, UserRewardRoot, UserRewardCheckpointAggregate and RewardClient. Checkpoint composition and advance job aggregation stay distinct operations. `canonical` in a Goldilocks range check is the mathematical field predicate, not a lifecycle label. `verifyProof(uint256[8], uint256[2])` and `keccak256("REWARD_CLAIM_VERIFIER")` are protected API and cryptographic literals. Registration leaf, registration index and the pinned public-key parameter stay distinct from userId and recipient; do not register every private local as a term.


SDK prepare and confirm names are `PrepareRewardClaimRequest`, `RewardClaimPreparation`, `PreparedRewardClaim`, `DeferredRewardCheckpoint`, `RewardClaimConfirmation`, `RewardCheckpointStatement`, `prepare_reward_claim_json`, `prepareRewardClaim`, `confirm_reward_claim_json`, `confirmRewardClaim`, `prove_reward_root`, `bind_reward_checkpoint_statement`, and `encode_reward_claim_calldata`. `RewardClaimPreparation` is the status outcome, not a wrapper around an unspecified body. `RewardCheckpointStatement` is the bound checkpoint root, active checkpoint ids, and total. `prove_reward_root` has one `anyhow` failure for an unsupported signer and one `ZKUser` override. `getClaimRewardsCallArgs` and `claimRewards` are removed rather than aliased. The relation and encodings stay in reward-claim-operations.md § SDK prepare and confirm.
