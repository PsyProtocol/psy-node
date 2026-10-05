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
8. `explicit` is not a domain name. A keystore path is `set` or `default`.

## 11. Mutable multisig authentication

| Term | Meaning |
|---|---|
| `MultisigPolicy` | Nonzero `version: u32`, fixed `threshold: u8 = 2`, fixed `member_count: u8 = 3`, and `member_hashes: [QHashOut<GoldilocksField>; 8]`. Entries 0 through 2 are nonzero, strictly ordered member commitments; entries 3 through 7 are zero padding, not additional members. |
| `StoredMultisigPolicy` | Policy precompile fields: `header: QHashOut<GoldilocksField>` containing `[version, 2, 3, 0]` in slot 0 and `members: [QHashOut<GoldilocksField>; 3]` in slots 1 through 3. Precompile contract identifier 6, state-tree height 4. |
| Policy commitment | Derived Poseidon hash of a validated `MultisigPolicy`. The initial-policy commitment binds immutable identity; no opaque policy commitment is stored as the on-chain authority. |
| Initial policy | Version-1 policy in `MultisigAccount`; its derived commitment is bound into immutable `public_key_param`. |
| Current policy | Policy derived from authenticated starting self-state fields; its two-member quorum authorizes every operation, including replacement. During pristine bootstrap it is the initial policy. |
| Ending policy | Policy derived from authenticated ending self-state fields; equal to the current policy or changed members with exactly the next version outside bootstrap. Threshold and member count remain fixed. |
| `MultisigAccount` | Public enrollment configuration: `contract_id` fixed to 6 and `initial_policy`. No master secret or signer private key. |
| `MultisigSignatures` | Exactly two external secp256k1 signatures over the exact session sighash bytes and two strictly increasing current-member indices in 0 through 2. |
| `MultisigSignatureWitness` | Unsigned trace fields: `account`, `start_state`, `end_state`, `sig_data`, `sign_context`, `start_session_user_leaf`, and `nonce`. Each state has four self-slot commands and eight alternating contract-tree/slot proofs; current and ending policies are derived, not separate supplied preimages. |
| `MultisigSignatureInput` | `MultisigSignatureWitness` plus `MultisigSignatures`, combined when signing the trace. |
| `MultisigSignatureCircuit` | Fixed two-of-three, no-secret authentication circuit; checks authenticated starting-policy signatures and ending-policy validity. |
| `TraceSignCircuitSource::Multisig` | Saved-trace selector for the fixed multisig circuit; not a ZK-key fallback. |
| `set_policy(expected_header, expected_members, next_members)` | Policy precompile operation comparing all four current slots and writing three next members with version 1 on all-zero bootstrap or the next version on replacement. Replacement requires changed members; the authentication circuit owns account authorization. No local wallet policy setter exists. |
| Bootstrap | First multisig session: all four policy slots zero, zero starting nonce, and default starting user-state root; two initial-member signatures must install the exact initial policy. Cannot be re-entered after initialization. |

Sources: `client_prover/psy_vm/src/ups/multisig.rs:20-175`; `client_prover/psy_prover/src/signature/users/multisig_user.rs:30-99`; `../psy-compiler/psy-precompiles/multisig_policy/src/main.psy:3-83`. Current first-milestone quality assurance is pending; these definitions are not runtime validation evidence.

### Scoped membership and Guardian evidence

| Term | Meaning |
|---|---|
| IMT | Indexed Merkle tree. A scoped membership request identifies one map within a contract-state tree, not the entire tree. |
| `QIMTMembershipProofRPCRequest<F>` | `checkpoint_id: u64`, `user_id: u64`, `contract_id: u32`, `key: QHashOut<F>`, `state_slot_base: u64`, and `capacity: u64`. Membership index and nonzero successor index must be in the checked inclusive range `state_slot_base + 1 ..= state_slot_base + capacity`; the sentinel is excluded and capacity must be nonzero. |
| `psy_provider::lps::WithdrawalBurnProof` | Process-local checkpoint-pinned burn evidence (`client_prover/psy_provider/src/lps.rs:28-39`): `checkpoint_id: u64`, `checkpoint_leaf: PsyCheckpointLeaf<F>`, `global_roots: PsyCheckpointGlobalStateRoots<F>`, `checkpoint_path: MerkleProofCore<QHashOut<F>>`, `user_leaf: PsyUserLeaf<F>`, `user_path: MerkleProofCore<QHashOut<F>>`, `contract_path: MerkleProofCore<QHashOut<F>>`, `contract_leaf: PsyContractLeaf<F>`, `global_contract_path: MerkleProofCore<QHashOut<F>>`, and `record_membership: IMTMembershipProof<F>`, where `F = GoldilocksField`. The provider assembles it; the verifier authenticates it against the approved operational committed checkpoint root and approved complete contract artifact/map interpretation. It is not a Guardian request field or a duplicate JSON wire type. |
| `GuardianAuthorization` | Versioned account/network identity, approved contract definitions, fees, chain authorization, and token mappings used to constrain Guardian signing. Distinct from current multisig policy and runtime endpoint configuration. |
| `ApprovedContract` | `contract_id`, approved `contract_leaf_json`, original `compiler_artifact_json: JsonText<CompilerArtifact>`, and `compiler_artifact_sha256: Hex32`. The digest covers the exact retained UTF-8 artifact text, including its ABI; no canonical layout root substitutes for this approval. |
| `CompilerArtifact` | Complete approved artifact fields: `state_tree_height: u16`, compiled `circuit_definitions`, and current `abi`. ABI schema version must be `2.0.0` and its declared height must match the artifact. |
| `GuardianRuntimeConfig` | Guardian runtime paths, transport configuration, endpoint URLs, and secret-file paths; not the signing authorization. `signing_authorization_path` is required. `custody_attestation_path` is rejected, not accepted as an alias. |
| `GuardianDb` | Exclusive redb owner for one guardian signing key in `psy_cli/psy_relayer_cli/src/guardian/db.rs`. Field and local name when the value is this type: `db`. `db_path` is its protected config-relative file path; `guardian-create-db` creates a new signing-key journal, while `guardian-service` only reopens retained state. Not a wire error name. |
| `SigningAuthorization` | Protected local JSON asserting one guardian signing key's `exclusive_key_use`, `complete_journal`, validity interval, and `revoked` state. Distinct from `GuardianAuthorization`. Old key `exclusive_custody` is rejected, not aliased. |
| `SigningAuthorizationFile` | Process-local retained bytes and database identity for one `SigningAuthorization`. Not serialized. |
| `SigningAuthorizationInvalid` | Sixth `HaltReason`, fixed-integer bincode ordinal 5. Covers readable changed approval bytes, `revoked`, `!exclusive_key_use`, and `!complete_journal`. Missing, unreadable, expired, or not-yet-valid approval stays unavailable. Not a separate file-changed or revoked variant. |
| `GuardianOperation` | Request operation: `Bridge`, `Bootstrap`, or `ReplacePolicy`; JSON values are `bridge`, `bootstrap`, and `replace_policy`. |
| `GuardianSignRequest` | Request schema and authorization versions, network/account identity, session nonce, operation, original trace JSON, deposit anchors, and withdrawal records. Request data is not an independently trusted checkpoint root. |
| `GuardianSignResponse` | Request/account/session identity, derived current `policy_commitment`, `member_index`, exact `message`, compressed `public_key`, and external `signature`. Not a stored policy update. |
| `WithdrawalBurnRecord` | Sender user identifier, token contract identifier, destination chain index, and eight-`u32` representations of token, amount, recipient, and withdrawal nonce. |
| `DepositAnchor` | Chain index, block number, block hash, and old/new deposit counts that identify the requested deposit evidence. |
| Decision signature | `None` means the nonce is reserved; `Some` means it is signed. At response time, `request_id` is derived from retained request bytes, `public_key` comes from the immutable signer identity, and `member_index` is that key's position in the exact retained session's historically reverified starting policy. These fields are not stored on the decision row. |
| `JsonText<T>` | Validated JSON text retained with its original UTF-8 bytes; decoding does not replace the retained source text. |
| `Hex<N>` | Fixed-width `N` bytes encoded as lowercase hexadecimal JSON text with a `0x` prefix. |
| `Hash4` | Guardian alias for `QHashOut<GoldilocksField>`; not a separate hash representation. |

Sources: `client_prover/psy_provider/src/request.rs:1213-1229`; `client_prover/psy_provider/src/lps.rs:26-38`; `psy_cli/psy_relayer_cli/src/guardian/protocol.rs:16-73,152-240`. These names describe implemented protocol types, not a claim that Guardian runtime validation has passed.

Artifact approval source: `psy_cli/psy_relayer_cli/src/guardian/protocol.rs:150-185`.

## 12. Bridge proof aggregation

| Term | Meaning |
|---|---|
| Deposit aggregate | Shared Groth16 artifact authenticating every configured chain's deposit transition and complete deposit opening. |
| Withdrawal batch | Shared flat family-7 Groth16 artifact authenticating the complete ordered withdrawal opening, including its configured withdrawal-root vector. |
| Reward batch | Shared flat family-7 Groth16 artifact authenticating the complete ordered reward opening. Reward opening bytes remain `256+192*N`. |
| Complete opening | Canonical preimages for every configured chain and every real aggregate record, supplied on each executing chain. |
| `batchCommit` | Context-bound Keccak commitment to one ordered chunk of at most 32 real records. Withdrawal no longer uses this nested batch root in its statement. |
| `DepositLeafRange` | Global first-leaf ordinal and count defining one chain's interval in the complete deposit opening. Fields are `first_leaf: u32` and `leaf_count: u32`. |
| `DepositAggregateOpening` | Canonical complete deposit opening. Its domain identifier is `DepositAggregate`; its domain label remains `A`. |
| Opening bytes | The one encoded byte string for one aggregate opening. Rust name: `opening_bytes`. Not a second encoding of the same opening. |
| `opening_digest` | `keccak256(family domain \|\| opening_bytes)`. Rust method on `DepositAggregateOpening`, `WithdrawalAggregateOpening`, and `RewardAggregateOpening`. Deposit preimage is domain `A` plus the existing deposit projection, count, chunk count, and aggregate root. Withdrawal and reward preimages are frozen labels `WithdrawalBatch` and `RewardBatch` plus `encode()` bytes. Not `header_digest`. Not a process-stage `statement`: do not name this digest `aggregate_statement`, `statement`, or `statementB`. |
| `deposit_opening_digest` | Rust name for the deposit family's `opening_digest`. Solidity field and event argument: `depositOpeningDigest`. |
| `openingDigest` | JSON object field and Solidity field for one family's `opening_digest`. Solidity: field on `WithdrawalAggregateOpening` and `RewardAggregateOpening`, and the indexed argument of `WithdrawalAggregateApplied` and `RewardAggregateApplied`. JSON wire field on aggregation status, disposition, and acknowledgment objects, replacing `aggregateStatement` with no alias. Same bytes as that family's `opening_digest`. |
| `header_digest` | Digest of header-domain plus header bytes. Different preimage from `opening_digest`. Do not use it as a name for the opening digest. |
| `WithdrawalAggregateOpening` | Canonical complete withdrawal opening. `withdrawal_roots: Vec<Hash4>` has one root per configured ordinal, followed by `withdrawals`. Crypto domain `Domain::WithdrawalAggregate`; its frozen label remains `WithdrawalBatch`. Do not rename that byte string. |
| `RewardAggregateOpening` | Canonical complete reward opening. It has no root vector. Crypto domain `Domain::RewardAggregate`; its frozen label remains `RewardBatch`. Do not rename that byte string. |
| `AggregateWindow` | Witness value for one withdrawal or reward aggregate: `config_hash: Bytes32`, `window_id: Bytes32`, `end_id: u64`, and `end_root: Hash4`. It is not a wire object and has no public-input layout of its own. Not `BatchContext`. |
| `AggregateLeaf` | Private codec trait in `bridge_aggregate.rs`, implemented by `WithdrawalLeaf` and `RewardLeaf`. `LEAF_WORDS` is 6; `write_leaf` and `read_leaf` encode and decode each existing leaf as six 32-byte words. It is not a new wire family. Distinct from circuit `AggregateLeafTarget`. |
| `AggregateLeafTarget` | Public circuit enum in `aggregate_commitment.rs`: `Deposit`, `Withdrawal`, and `Reward` leaf targets. Not the private codec trait `AggregateLeaf`. |
| `InclusionAggregateCircuit` | Withdrawal and reward inclusion aggregate circuit in `inclusion_aggregate.rs`. Source enum: `InclusionAggregateSource`. Public inputs: `AGGREGATE_PI_LEN` is 12. Slot bound: `AGGREGATE_SLOT_COUNT` is 1024. Crypto domain `Domain::Aggregate`; its frozen label remains `Batch`. Do not rename that byte string. |
| Withdrawal root path | Private height-eight Poseidon path authenticating one opening withdrawal root. It is not serialized. |
| Global deposit leaf root | Internal ordered height-ten Merkle root from `deposit_leaf_tree`: leaf commitments, their positions, and total count. Shared by web proofs and complete-opening normalization. |
| Finalize endpoint extension | For each configured ordinal, nine public inputs after the retained 26-word prefix: deposit root, absolute deposit count, and withdrawal root. Total width is `26+9*C`. |
| `endpointChainListHash` | Pure getter on the generated finalize verifier. It returns `keccak256("PsyBridge/FinalizeChainList/1" || uint16_big_endian(C) || ordered raw chain indices)`. |
| `DigestBitsAdapter` | Source-pinned proof adapter exposing one `opening_digest` as 256 MSB-first bits. |
| `EthereumRewardPayer` | Ethereum-only funded contract that consumes canonical reward keys and pays the configured fixed amount through its StateManager. |
| `REWARD_PER_CLAIM` | Required positive immutable reward amount in the configured token's smallest units; no production value is inferred. |
| `rewardNullifierDomain` | Stable network, bridge-user and Ethereum payer/token domain for reward consumption. |
| Consumed reward key | Domain-bound claim checkpoint and full-root tagged-tree position; recipient changes cannot create another entitlement. |
| Historical checkpoint Merkle proof | Claim that one checkpoint leaf at its checkpoint id is a member of the authenticated target checkpoint-tree root. Canonical name: `historical_merkle_proof`. Future adopted source filename: `historical_merkle_proof.rs`; not present, and logere is not already renamed to it. Same concept as `reward_inclusion`'s existing `claim_path`: `claim_checkpoint_path` binds the claim checkpoint leaf hash and claim checkpoint id under the end checkpoint root (`reward_inclusion.rs`). Not a state upgrade: `upgrade_checkpoint_historical_merkle_proof_gadget` (`HistoricalRootMerkleProofGadget` in `verify_guta_to_cap_upgrade_checkpoint.rs`) rewrites a header from `historical_root` to `current_root`. Distinct from the reward tag-tree path (`RewardTagTarget`) and from planner job-tree paths. No hash, public-input, user-counter, or state change. |
| Nullifier tree | Circuit transition tree for one claim-replay key. Canonical names: `nullifier_tree`, `nullifier_key`. Adopted public inputs: `old_nullifier_root`, `new_nullifier_root`. Adopt `SPENT_TREE_HEIGHT` as `NULLIFIER_TREE_HEIGHT`; the historical branch name is explanatory only (`bridge-merkle-settlement.md` job-spent transition, height 63), and current source has neither constant. The L1 mapping is a distinct representation of the same claim-replay key domain: reward `spentRewards[keccak256(abi.encode(rewardNullifierDomain, claimCheckpointId, nullifierIndex))]` (`EthereumRewardPayer.sol`) and withdrawal `claimedNullifiers[nonce]` (`Bridge.sol`). Do not equate an index, a path, or a root with that mapping. Not `claimed_tree` or `claimed_key`. |
| `checkpoint_tree_root` | Four-limb Poseidon checkpoint-tree root. Approved proposed user statement is exactly 34 fields: root `[0..4)`, `user_id[4]`, recipient `[5..13)` as eight little-endian u32 limbs, `total_amount[13..21)` as eight little-endian u32 limbs, `count[21]`, `jobs_commitment[22..26)`, `old_nullifier_root[26..30)`, `new_nullifier_root[30..34)`. This replaces only the user 19/27-field proposal; publication 28 and finalize `26+9*C` are distinct. Existing checkpoint-header upgrade names stay unchanged. |
| `deposit_leaf_hash` | Private Poseidon `q_hash_many` of one `DepositLeaf` in `prove_bridge.rs`: `shield_address`, `token`, `l2_token_contract_id`, `amount`, `chain_index`, `note_commitment`, in that order. Replaces `deposit_custody_hash`. Not `DepositLeaf::leaf_commit` and not Solidity `_computeDepositLeafHash`. |
| `append_deposit_leaf` | Private height-32 frontier update in `prove_bridge.rs`: writes the leaf into the frontier and returns the new Poseidon deposit-tree root. Replaces `append_custody_leaf`. Not guardian `append_leaf`, which stays. |
| Deposit prefix | The per-chain `DepositLeaf` vector supplied to `build_deposit_spiderman_inputs`. Error text names a deposit prefix, deposit suffix, or deposit web, never custody. |
| Proved deposit count | L1 `provedDepositCount` compared with the L2 deposit-tree next index. A proved count above that L2 count, or a new session whose two counts differ, is a deposit-count mismatch, not custody. The two greater-than failures use `proved deposit count exceeds L2 deposit count`; the equality failure uses `L2 deposit count differs from proved deposit count`. |
| Reward circuit kind | One of exactly three proposed kinds: self-recursive user accumulator, reward inclusion aggregate, Groth16 wrapper. Kind count is not recursion depth; depth grows with jobs and benchmark-selected per-step capacity `k`. No distinct job/closing/four-signature/re-anchor circuit is added. |
| `jobs_commitment` | Proposed user rolling Poseidon commitment `H(previous commitment || new jobs)` with domain/context/count/order encoding in Bridge Merkle Settlement. It is not a global transcript or terminal-user-summary root. |
| `CumulativeRewardLeaf` | Proposed economic domain, u32 user id, uint256 `total_amount` in eight little-endian u32 limbs, 20-byte immutable recipient and initialized flag. Payout codec is 160 bytes under new cumulative domains, not the existing six-word `RewardLeaf` codec. |
| `reward_accumulator_root` | Proposed checkpoint-authenticated earned-state root. Producer completeness establishes lifetime entitlement independently of L1 presented-job bits and delivered totals. Not currently a seventh source field. |
| `paid_total` | Payer-owned delivered amount per economic domain/user; claim transfers only a positive cumulative delta and never changes earned authority. |
| `InclusionAggregateHeader` | Proposed packed family-specific publication header, binding opening digest, claim root, capacity/count/segment context and configured withdrawal roots or reward nullifier endpoints. |
| `InclusionAggregateRoot` | Proposed StateManager registry entry authenticated by publication; distinct from an accumulator leaf or payment record. |
| `claim_tree_root` | Proposed marker-12 Keccak root over one segment's payout leaves and canonical padding. |
| `Hash4Encoding` | Proposed explicit selector `CanonicalU64x4` or `LittleEndianU32x8`; no decoder fallback. Canonical limbs remain below Goldilocks modulus. Keccak big-endian u32 words are a different representation. |
| `ActiveWindow` | Proposed per-destination retained manifest/progress state. Incomplete withdrawal or reward segments block the next window; root publication does not mark claims paid. |
| Interleaved terminal-proof join | Unclosed relation proving every per-user terminal proof belongs to the selected global nullifier history. Independent valid forks and host sorting are insufficient. No wider user statement or summary root is adopted. |
| `RewardAccumulatorLeaf` | Proposed checkpoint-owned leaf: u32 `user_id`, eight little-endian u32 `total_amount`, five little-endian u32 recipient limbs. No stored cumulative count, initialized flag, cursor or nullifier root. Recipient zero means unset. |
| `RewardPosition` | Proposed transient producer contribution: relative level u8, relative index u32, owner user id u32, canonical Hash4 owner tag. Exact complete-list commitment is `positions_commitment`; not an L1 payout record. |
| `positions_commitment` | Proposed authenticated commitment to a producer's complete ordered reward-position list. Separate from per-user rolling `jobs_commitment`. |
| `set_recipient` | Proposed one-time authenticated L2 session method, not an existing precompile or claim-time signature. Proposed contract identifier7 remains unapproved and not globally collision-checked. |

Design contract: `docs/src/dev/bridge-merkle-settlement.md`; `bridge-proof-aggregation.md` is only an operational pointer. Existing-source terms above do not assert that proposed cumulative storage, 34-input user proofs, 28-input inclusion publication, or pull delivery are implemented. The interleaved terminal-proof join remains a design blocker. Runtime validation, setup generation and activation remain unexecuted for this proposal.
