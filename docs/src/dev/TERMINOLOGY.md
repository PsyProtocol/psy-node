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
| Edge | HTTP surface in front of a processor: proven claims enter the aggregation edge; EndCaps enter a Realm edge; GUTA submit enters the Coordinator edge. |
| `AggregationClaimRequest` | The wire packet that hands one proven claim (record plus proof, tagged by kind and aggregation context) to the aggregation edge. One spelling across the prover, relayer, and services ends. |
| `build_aggregation_claim` | Builds an `AggregationClaimRequest` from a proven record and its proof. |
| `AggregateClaimResult::AggregationClaim` | CLI outcome variant carrying the built `AggregationClaimRequest`. |
| `AggregationClaim` | Services domain value passed to `apply_claim` for a proven aggregation claim; distinct from the stored `DbBridgeAggregationClaim` row. |
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
| `batchCommit` / `batch_commit` | Settlement Keccak-256 commitment to at most 32 ordered records of one family: `K(D(Batch) \|\| config_hash \|\| window_id \|\| W(end_id) \|\| H4(end_root) \|\| W(family) \|\| W(global_chunk_ordinal) \|\| W(first_family_leaf_ordinal) \|\| W(chunk_leaf_count) \|\| encoded_active_leaves)`. Here `K` is Keccak-256, `D(x)=K(ASCII("PsyBridge/TwoArtifact/2/") \|\| ASCII(x))`, `W` is one big-endian 32-byte integer word, and `H4` is four such words. Withdrawal chunks precede reward chunks; families never mix inside a chunk. |
| `DepositLeafRange` | Global first-leaf ordinal and count defining one chain's interval in the complete deposit opening. Fields are `first_leaf: u32` and `leaf_count: u32`. |
| `DepositAggregateOpening` | Canonical complete deposit opening. Its domain identifier is `DepositAggregate`; its domain label remains `A`. |
| Opening bytes | The one encoded byte string for one aggregate opening. Rust name: `opening_bytes`. Not a second encoding of the same opening. |
| `opening_digest` | Native method on `DepositAggregateOpening`, `WithdrawalAggregateOpening`, `SourceCheckpointRewardOpening`, and `SettlementOpening`. Deposit preserves the `PsyBridge/TwoArtifact/1/A` projection; withdrawal hashes its `WithdrawalBatch` domain plus encoded opening; source-checkpoint reward hashes `PsyBridge/SourceCheckpointReward/1/Opening` domain plus encoded opening. Settlement uses the F4 preimage registered below, not its encoded opening bytes directly. These are distinct family relations, not `header_digest`. |
| `deposit_opening_digest` | Rust name for the deposit family's `opening_digest`. Solidity field and event argument: `depositOpeningDigest`. |
| `openingDigest` | JSON object field and Solidity field for one family's `opening_digest`. Solidity: field on `WithdrawalAggregateOpening` and `RewardAggregateOpening`, and the indexed argument of `WithdrawalAggregateApplied` and `RewardAggregateApplied`. JSON wire field on aggregation status, disposition, and acknowledgment objects, replacing `aggregateStatement` with no alias. Same bytes as that family's `opening_digest`. |
| `header_digest` | Digest of header-domain plus header bytes. Different preimage from `opening_digest`. Do not use it as a name for the opening digest. |
| `WithdrawalAggregateOpening` | Canonical complete withdrawal opening. `withdrawal_roots: Vec<Hash4>` has one root per configured ordinal, followed by `withdrawals`. Crypto domain `Domain::WithdrawalAggregate`; its frozen label remains `WithdrawalBatch`. Do not rename that byte string. |
| `SourceCheckpointRewardOpening` | Complete source-checkpoint reward opening: config hash, window id, end checkpoint id/root, and ordered `SourceCheckpointRewardLeaf` records. Its digest is `K(K(ASCII("PsyBridge/SourceCheckpointReward/1/Opening")) \|\| encode())`, where `K` is Keccak-256. The removed Rust `RewardAggregateOpening` is not an alias; retained external Solidity names and frozen `RewardBatch` bytes do not rename this type or preimage. |
| `AggregateWindow` | Witness value for one withdrawal or reward aggregate: `config_hash: Bytes32`, `window_id: Bytes32`, `end_id: u64`, and `end_root: Hash4`. It is not a wire object and has no public-input layout of its own. Not `BatchContext`. |
| `config_hash_for_domain_derivation` | The existing Keccak `config_hash`: `commit(Domain::Config, encode())`, returned as `Bytes32`. Its input is the fixed `NetworkConfig::encode()` projection in field order `version`, `network_magic`, `bridge_user_id`, `circuit_set_hash`, chain count, each `ChainConfig`, `ethereum_index`, `reward_payer`, `reward_token`, `reward_per_claim`, `reward_token_decimals`, `reward_cutover`, `reward_end_exclusive`, `max_deposits`, `max_withdrawals`, `max_rewards`. Every derived field is excluded from this preimage. `economic_domain` is excluded, and any future derived field is excluded by the same fixed-input projection. No derived field is an input to the hash that produces it. While no derived field is encoded, these bytes equal `config_hash`. `network_magic` stays in this projection. It is not a Poseidon hash. |
| `LoadedBridgeConfig` | Load boundary owning one fixed `NetworkConfig` and its computed `economic_domain: Bytes32`. `config()` returns a shared reference. `economic_domain()` returns the computed bytes. Neither field is public and there is no setter, so the loaded config cannot be changed and the computed domain cannot become stale. It is not a second config authority. The fixed input is the existing `encode()` projection. The domain's outer Poseidon input ends with those raw Keccak bytes, serialized nowhere as `Hash4`. |
| `economic_domain` derivation | Poseidon at config load. Inner input is one canonical Goldilocks field per byte of `ASCII("PsyBridge/SourceCheckpointReward/2/EconomicDomain")`. Its `Hash4` is serialized limb 0 through 3 as little-endian `u64`. Outer input is those 32 bytes followed by the raw 32-byte `config_hash_for_domain_derivation`. That config hash is not serialized as `Hash4` and is not hashed with Poseidon again. Outer `Hash4` is serialized limb 0 through 3 as little-endian `u64` to `economic_domain`. The `/2` label is the accepted F1 byte string. Its schema-version owner is not identified, so the label is not rewritten to `/1`. |
| `SettlementOpening` | Complete F4 opening for joint proof B: common window fields, paired-u32 global roots, positive-span finalization slots, configured endpoints, withdrawals, old/new reward ledger roots, economic domain, and rewards. Native owner is `bridge_aggregate.rs`; encoded length is `1152 + 448*n + 192*w + 192*r`, with `1<=n<=8`. |
| `SettlementAggregateCircuit` / `settlement_aggregate` | Joint Plonky2 source circuit and its module/manager field. It unconditionally verifies the real pinned withdrawal and reward children plus configured finalizations. Source prefix `[2,12,2,0]` and eight digest words give 12 public inputs; the Groth16 wrapper publishes two uint128 halves. |
| `SETTLEMENT_AGGREGATE_PI_LEN` / `SETTLEMENT_OPENING_HEADER_BYTES` | Source public-input width 12 and native opening fixed header width 1152 bytes, respectively. Neither constant is the Groth16 public-input count. |
| `settlement_digest` | Circuit F4 Keccak-256 digest matching `SettlementOpening::opening_digest`: `K(D(B) \|\| config_hash \|\| window_id \|\| W(end_id) \|\| H4(end_root) \|\| aDigest \|\| global_deposit_root_words \|\| global_withdrawal_root_words \|\| W(n) \|\| slots \|\| endpoints \|\| W(w) \|\| W(r) \|\| H4(old_reward_ledger_root) \|\| H4(new_reward_ledger_root) \|\| economic_domain \|\| W(batch_count) \|\| batch_root)`. Here `K` is Keccak-256, not the economic-domain Poseidon hash. Both native and circuit digest builders write one chain-count word, followed by slots and endpoints with no second count, then the two adjacent payout counts. This describes the digest preimage, not `SettlementOpening::encode()` wire serialization. |
| `chunk_count` / `batch_count` | A family's chunk count is `ceil(record_count/32)`, zero for no records. Settlement `batch_count` is withdrawal chunk count plus reward chunk count; it is derived, not independently supplied authority. |
| `batch_root` / `batch_leaf` / `batch_empty` / `batch_parent` / `batch_depth` | Tree width is `next_power_of_two(max(1,batch_count))`; depth is its base-two logarithm. With `K` denoting Keccak-256, real leaf `j` is `K(D(Leaf)\|\|W(batch_count)\|\|W(j)\|\|W(family)\|\|batchCommit)`, padding is `K(D(Empty)\|\|W(batch_count)\|\|W(j))`, and a parent is `K(D(Node)\|\|W(height)\|\|left\|\|right)` with height starting at 1. Zero batches give `batch_empty(0)` directly, not a zero digest or a fixed-depth padded root. |
| `AggregateLeaf` | Private codec trait in `bridge_aggregate.rs`, implemented by `WithdrawalLeaf` and `RewardLeaf`. `LEAF_WORDS` is 6; `write_leaf` and `read_leaf` encode and decode each existing leaf as six 32-byte words. It is not a new wire family. Distinct from circuit `AggregateLeafTarget`. |
| `AggregateLeafTarget` | Public circuit enum in `aggregate_commitment.rs`: `Deposit`, `Withdrawal`, and `Reward` leaf targets. Not the private codec trait `AggregateLeaf`. |
| `WithdrawalInclusionAggregateCircuit` | Withdrawal inclusion publication circuit in `inclusion_aggregate.rs`. Its public-input width is `AGGREGATE_PI_LEN`, the sole owner registered below. Crypto domain `Domain::Aggregate`; its frozen label remains `Batch`. Do not rename that byte string. |
| `RewardInclusionAggregateCircuit` | Reward inclusion publication circuit in `inclusion_aggregate.rs`. Its public-input width is the same `AGGREGATE_PI_LEN`. It verifies one `RewardSessionCircuit` proof per user. It is not the session circuit. |
| Withdrawal root path | Private Poseidon path authenticating one opening withdrawal root. It is not serialized. |
| Global deposit leaf root | Internal ordered Merkle root from `deposit_leaf_tree`: leaf commitments, their positions, and total count. Shared by web proofs and complete-opening normalization. |
| Finalize endpoint extension | For each configured ordinal, public inputs after the retained prefix: deposit root, absolute deposit count, and withdrawal root. The prefix is not the full width. |
| `endpointChainListHash` | Pure getter on the generated finalize verifier. It returns `keccak256("PsyBridge/FinalizeChainList/1" || uint16_big_endian(C) || ordered raw chain indices)`. |
| `DigestBitsAdapter` | Source-pinned proof adapter exposing one `opening_digest` as 256 MSB-first bits. |
| `EthereumRewardPayer` | Ethereum-only funded contract. Current `payRewards` consumes one boolean per job and pays immutable `REWARD_PER_CLAIM` (`EthereumRewardPayer.sol:52-95`). It is not the proposed one-session payer. |
| `REWARD_PER_CLAIM` | Current positive immutable per-job amount in the configured token's smallest units. Not the proposed session sum `W`. No production value is inferred. |
| `rewardNullifierDomain` | Current domain for the per-job `spentRewards` key: `keccak256(abi.encode(keccak256("PsyBridge/TwoArtifact/1/Reward"), uint256(1), networkMagic, uint32(524288), chainId, ethereumIndex, payer, rewardToken))`. |
| Consumed reward key | Current L1 key `keccak256(abi.encode(rewardNullifierDomain, claimCheckpointId, nullifierIndex))`. One boolean per job. Not the proposed source-and-user key. |
| Historical checkpoint Merkle proof | Claim that one checkpoint leaf at its checkpoint id is a member of the authenticated target checkpoint-tree root. Canonical name: `historical_merkle_proof`. Existing source is `historical_merkle_proof.rs`. Same membership concept as `reward_inclusion`'s `claim_path`: `claim_checkpoint_path` binds the claim checkpoint leaf hash and claim checkpoint id under the end checkpoint root. Not a state upgrade: `upgrade_checkpoint_historical_merkle_proof_gadget` (`HistoricalRootMerkleProofGadget`) rewrites a header from `historical_root` to `current_root`. Distinct from the reward tag-tree path. |
| Session nullifier | Private temporary zero-to-one tree inside one reward session. Canonical names: `nullifier_tree`, `nullifier_key`. The key packs source, level, and index. The first own step starts empty; later own steps carry the private root through the verified predecessor's session state. It is not a publication input and is not L1 `spentRewards`. Not `claimed_tree` or `claimed_key`. |
| `checkpoint_tree_root` | Poseidon checkpoint-tree root in `RewardSessionStatement`. That statement also carries `user_id`, `recipient`, `total_amount`, `count`, `jobs_commitment`, and the composite ledger endpoints `old_ledger_state_root` and `new_ledger_state_root`. Those endpoints are ledger state, not the private session root. Publication width and finalize width are distinct and are owned by their own registered names. Existing checkpoint-header upgrade names stay unchanged. |
| `deposit_leaf_hash` | Private Poseidon `q_hash_many` of one `DepositLeaf` in `prove_bridge.rs`: `shield_address`, `token`, `l2_token_contract_id`, `amount`, `chain_index`, `note_commitment`, in that order. Distinct from `DepositLeaf::leaf_commit` and Solidity `_computeDepositLeafHash`. |
| `append_deposit_leaf` | Private deposit-tree frontier update in `prove_bridge.rs`: writes the leaf into the frontier and returns the new Poseidon deposit-tree root. Distinct from guardian `append_leaf`. |
| Deposit prefix | The per-chain `DepositLeaf` vector supplied to `build_deposit_spiderman_inputs`. Error text names a deposit prefix, deposit suffix, or deposit web, never custody. |
| Proved deposit count | L1 `provedDepositCount` compared with the L2 deposit-tree next index. A proved count above that L2 count, or a new session whose two counts differ, is a deposit-count mismatch, not custody. The two greater-than failures use `proved deposit count exceeds L2 deposit count`; the equality failure uses `L2 deposit count differs from proved deposit count`. |
| Reward circuit kind | One of exactly three kinds: `RewardSessionCircuit`, `RewardInclusionAggregateCircuit`, and the Groth16 wrapper. Kind count is not recursion depth. Depth grows with included jobs and the per-step capacity `REWARD_SESSION_STEP_CAPACITY`. No debit, ticket, closing, or re-anchor circuit is added. |
| Reward session | One proof chain for one `(economic_domain, source_checkpoint_id, user_id)`, proved by `RewardSessionCircuit`. Its terminal amount is `W`, the full sum of included jobs. Jobs omitted from it are forfeited. |
| Reward ledger key | Two path limbs, user bits then source bits. Never one Goldilocks target. Economic domain is pinned tree context, not a limb. `RewardLedgerLeafTargets` writes the occupied leaf under `PsyRewardLedger/Issued/1` and never clears it. |
| `jobs_commitment` | Session rolling Poseidon commitment. Its base is `reward_session_seed` over `PsyRewardJobs/Session/1`. `rolling_jobs_commitment` in `reward_session.rs` absorbs the step domain, the previous commitment, the counts, and each active job record. Inactive padding is excluded. Each included job contributes the configured per-claim amount; `RewardLeaf` has no amount field. |
| `SourceCheckpointRewardLeaf` | Payout leaf: economic domain, source checkpoint id, user id, amount `W`, recipient, and initialized flag. Its commit is `source_checkpoint_reward_leaf_commit` under `PsyBridge/SourceCheckpointReward/1/Leaf`. Not the per-job `RewardLeaf` and not the reward-ledger occupancy leaf. |
| Consumption key | Payout boolean, `keccak256(abi.encode(consumption_domain, economic_domain, uint256(source_checkpoint_id), uint256(user_id)))`. It does not replace reward-ledger occupancy. Distinct from the per-job `spentRewards` key. |
| `InclusionAggregateHeader` | Packed family-specific publication header. It binds the opening digest, claim root, and capacity, count, and segment context. Reward hash slots are `old_ledger_state_root` and `new_ledger_state_root`, not a stored persistent job-nullifier cursor. |
| `InclusionAggregateRoot` | StateManager registry entry authenticated by publication. Distinct from a payment record and from reward-ledger occupancy. |
| `claim_tree_root` | Keccak root over one segment's payout leaves and canonical padding. |
| `Hash4Encoding` | Explicit selector `CanonicalU64x4` or `LittleEndianU32x8`; no decoder fallback. Canonical limbs remain below the Goldilocks modulus. Keccak big-endian u32 words are a different representation. |
| `ActiveWindow` | Per-destination retained manifest and progress state. Incomplete withdrawal or reward segments block the next window. Root publication does not mark claims paid. |
| Interleaved acceptance gap | Unclosed connection from the private ledger targets to one selected publication history. Independent valid sessions and host sorting are insufficient. No wider user statement, balance, or persistent job root is adopted. |
| `W` | Checked full sum of one reward session and the payout-leaf amount. Not a balance, debit, partial prefix, or per-job `REWARD_PER_CLAIM`. |

Design contract: `docs/src/dev/bridge-merkle-settlement.md`; `bridge-proof-aggregation.md` is only an operational pointer. Reward-session, reward-ledger, and inclusion-publication names are the registered vocabulary below. The current payer remains per-job. Runtime validation, setup generation, and activation remain unexecuted.

## Naming governance

This section is the machinery for the `AGENTS.md` naming rules (18, 23, 24). It records dispositions and freeze state; it does not rename anything by itself.

### Rule 18 dispositions

| Occurrence | Class | Basis |
|---|---|---|
| `statement` in `reward_session.rs` (the per-step public-input statement and its accessors) | Genuine ZK statement | Rule 18 exempts a genuine ZK statement; the field roles are pinned by the `checkpoint_tree_root` entry above. |
| `old_*` (`old_root`, `old_summary`, `old_state`, `old_session_root`, `old_user_root`) | State-transition qualifier | Rule 14 state qualifier; each pairs with the `new` endpoint of one transition. |
| `old_ledger_state_root` / `new_ledger_state_root` | Registered ledger endpoints | Composite ledger-state endpoints. `nullifier` stays reserved for the session and tag trees. |
| `to_canonical_biguint` | External API | Dependency-provided method. |
| `tracing::info!` | External API | Log macro, not a symbol. |
| `manifest` in four error strings: `empty withdrawal manifests carry no proof` (`aggregate_circuits.rs:95`, `inclusion_aggregate.rs:824`) and `empty reward manifests carry no proof` (`aggregate_circuits.rs:118`, `inclusion_aggregate.rs:488`) | Prose | Error text only. Each names an empty publication header that carries no proof. Not a registered publication type. |
| `canonical_scalar` (`reward_session_witness.rs:123`) | Established external domain term | ECDSA canonical scalar form. The low flag requires low-S. Keep with this basis or rename in the same cutover that touches the file. |
| `anyhow::Context` and `.context()` | External API | Dependency trait and method. Not the reward-ledger window. Do not rename these occurrences. |
| `terminal` in auth and multisig-policy error strings | Prose | Error text only. It does not name a frozen cryptographic byte string. |
| `canonical_scalar`, `canonical_bytes`, `read_canonical_hash4`, and `CanonicalU64x4` | Cryptographic encoding | Canonical field, scalar, or Hash4 encoding owned by this protocol. |
| `from_canonical_*` and `to_canonical_*` | External API | Dependency field and integer conversion methods. Do not rename them. |
| `statement` | Genuine ZK statement | The per-step public-input statement. Rule 18 exempts it. |
| `manifest` in error strings | Prose | Error text only. It is not a registered publication type. |
| `context` on a live external contract or generic JSON compatibility field | External API | Classify the occurrence as external. Do not rename it without an explicit mapping. |

### Banned-substring sweep

Run before review closes on a change and before any push, over exactly the files the change touches:

```bash
grep -inE 'context|entry|metadata|manifest|payload|blob|misc|legacy|deprecat|canonical|official|explicit|custody|persist|isolat|submission|envelope|admission' <changed files>
grep -inE '\b(info|details|items)\b' <changed files>
```

Every hit is classified in the disposition table above or renamed; an unclassified hit blocks the review.

### Frozen domain labels

A label freezes when it first enters an executed test, a generated circuit artifact, or a deployment (AGENTS.md naming rule 24).

| Label | Status |
|---|---|
| `PsyBridge/TwoArtifact/1/*` | Frozen by the shipped mainnet-beta verifier artifacts and the `BridgeOpening.sol` constants. |
| `PsyRewardJobs/Session/1`, `PsyRewardSession/Summary/1`, `PsyRewardLedger/{State,Window,Verifier,Node,Empty,Issued,Proof}/1`, `PsyBridge/SourceCheckpointReward/1/Leaf` | Unfrozen. Source or authored tests may contain them; that presence is not execution. No executed test, generated artifact, or deployment was supplied for these labels. |
| `PsyBridge/TwoArtifact/2/B`, `PsyBridge/TwoArtifact/2/Batch`, `PsyBridge/TwoArtifact/2/Leaf`, `PsyBridge/TwoArtifact/2/Empty`, `PsyBridge/TwoArtifact/2/Node` | Unfrozen settlement digest/tree domains. Source edits and authored tests are not execution; no executed test, generated artifact, or deployment has been provided for this batch. |
| `PsyBridge/SourceCheckpointReward/1/Opening` | Source-checkpoint reward opening domain. Freeze status is unverified against earlier reward test artifacts; preserve these existing bytes and do not rename them without that evidence. |
| `PsyRewardAuthorization/CreditSession/1` | Frozen. Host-domain bytes were actually executed and remain protected. Do not rename that byte string. |

### Module head words

A public domain name starts with its owning module's head word, and two modules never share one (AGENTS.md naming rule 23). Registered head words: `reward` owns reward `inclusion`, `session`, `ledger`, and `aggregate`; `settlement` owns the joint bridge opening and aggregate circuit, with `opening`, `digest`, and `batch` sub-words. Settlement batch helpers use the registered `batch` prefix and `chunk_count` derivation above. The existing `deposit`, `withdrawal`, and `checkpoint` families retain their heads.

### Registered reward vocabulary (pending implementation)

Final spellings registered before implementation per the registration gate; this file carries no former names. Grouped by sub-module; each name means exactly the following and nothing else.

Session (`reward_session.rs`) - one proof chain per (economic domain, source checkpoint, user):

| Name | Meaning |
|---|---|
| `RewardSessionCircuit` | Self-recursive step circuit that aggregates one session's jobs. |
| `RewardSessionStatement` | The 34-field per-step public-input statement. |
| `REWARD_SESSION_PROOF_FIELD_COUNT` / `REWARD_SESSION_STEP_CAPACITY` | Statement width and per-step job capacity. |
| `RewardSessionProofFields` | Wire codec for one step proof's field set. |
| `RewardSessionTargets`, `reward_session_seed`, `reward_session_summary` | Session targets and the two Poseidon preimages over `PsyRewardJobs/Session/1` and `PsyRewardSession/Summary/1`. |
| `RewardSessionJobTargets` / `RewardSessionJobWitness` | One included job's circuit targets and host witness in `reward_session.rs`. |
| `job_amount` | Amount contributed by one included job. Not the session sum `W`. |
| `constrain_reward_session_step` | Circuit constraint for one session step in `reward_session.rs`. |
| `set_reward_session_witness` | Witness setter for one session step in `reward_session.rs`. |
| `SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES` | Width of the source-checkpoint reward opening header in `bridge_aggregate.rs`. `inclusion_aggregate.rs` imports it to bound the opening preimage. Not a cryptographic domain string. |
| `WITHDRAWAL_HEADER_BYTES` | Fixed prefix of one withdrawal `InclusionAggregateHeader` in `bridge_aggregate.rs`: family byte, config hash, window id, end checkpoint id, end checkpoint root, and the six segment counters, then `opening_digest` and `claim_tree_root`. Configured withdrawal roots follow this prefix. Not a cryptographic domain string. |
| `RewardSessionAuthorization`, `REWARD_SESSION_AUTHORIZATION_DOMAIN` | Host-side authorization for one session. |
| `is_final_step` | Flag marking the session's closing step, the only step that authenticates the claimant. |
| `EndCheckpointTargets` | Authentication of the end checkpoint leaf, its historical path, and its global state roots. |
| `AuthUserLeafTargets` | Registered user leaf, its height-32 membership path, and the `H(identity, param) == public_key` binding. |
| `UserAuthTargets` | The complete claimant identity proof: scheme selector with compile-time fingerprints, registered leaf authentication, unified `public_key_param`, signature gadgets, and `auth_message`. |
| `MultisigPolicyTargets` | Multisig scheme enrollment-policy machinery: contract 6 policy, slot and contract tree paths, two selected members. |
| `AuthSignatureValues`, `auth_secp_signature`, `auth_message` | Canonical signature values, the secp gadget, and the signed message binding recipient, `W`, and identity. |
| `MultisigPolicyValues` | Host values of the multisig enrollment-policy verification. |
| `set_auth_signature` / `set_multisig_policy` | Witness setters for the auth signature and the multisig policy. |
| `is_active_scheme` | Flag selecting the active identity scheme at the final step. |

Ledger - the global once-only issuance state:

| Name | Meaning |
|---|---|
| `RewardLedgerStateTargets` / `RewardLedgerStateValues` | Circuit targets and host values of the ledger state: `ledger_window_hash`, `ledger_root`, `user_root`, `session_count`, `unfinished_session_count`. |
| `reward_ledger_window_hash` | Poseidon binding of config, economic domain, window, end checkpoint, tree root, start state, and verifier. |
| `RewardLedgerWindowTargets` | The same window binding in circuit word form. |
| `RewardLedgerWindowValues` | Host window values in `reward_ledger.rs`: `config_hash`, `economic_domain`, `window_id`, `end_checkpoint_id`, `end_checkpoint_root`, and `start_root`. The window hash also binds the verifier. The next window's `start_root` is the previous window's published and verified `new_ledger_state_root`. The first window of an economic domain starts at `origin_state_root()`. |
| `origin_state_root()` | Function in `bridge_aggregate.rs`. One call returns the fixed protocol Poseidon hash of the origin state. `RewardSessionCircuit::new` calls it. The store does not call it and does not initialize the first window; that initialization is blocked on the configured economic domain. There is no lock. The origin state is the existing `RewardLedgerStateValues`: `ledger_window_hash` is the zero Hash4, `ledger_root` is the 64-level empty issued tree, `user_root` is the 32-level empty summary tree, and both counts are zero. The hash is not the zero Hash4. The old state root equals statement `[26..30)` on every step, so that hash already binds the opening. The first-window gap is initialization and publication of this start, not a second host pin. |
| `ledger_window` | Wrapper field holding `RewardLedgerWindowTargets`. Not a second window type. |
| `RewardLedgerLeafTargets` | One occupancy-leaf write at the reward ledger key under `PsyRewardLedger/Issued/1`. |
| `RewardLedgerNodeUpdate` | One host-visible sparse user-tree write in `reward_ledger.rs`: `height`, `index`, and `hash`. Height 0 is the user-tree leaf. |
| `RewardLedgerStep` | Public host step input in `reward_ledger.rs`: canonical proof bytes, `old_state`, `new_state`, source checkpoint, source leaf and path, `old_summary`, `session_root`, summary siblings, and `is_final_step`. Proof bytes are the only proof material. |
| `RewardLedgerTransition` | Verified public host transition in `reward_ledger.rs`: canonical old and new ledger-state roots, `proof_id`, `transition_bytes`, and the user-tree node updates. `transition_bytes` encodes the public step, not the proof alone. |
| `reward_ledger_proof_id` | `SHA-256(UTF8("PsyRewardLedger/Proof/1") \|\| complete user-verifier Hash4 as canonical little-endian u64 limbs \|\| canonical proof bytes)`. SHA-256, not Poseidon. The label is unfrozen. |
| `verify_reward_ledger_step` | Host verifier of one `RewardLedgerStep` in `reward_ledger.rs`. `expected_old_root` is the store's locked trusted baseline, not a caller-selected root. It returns one `RewardLedgerTransition`. |
| `old_ledger_state_root` / `new_ledger_state_root` | Composite ledger-state endpoints in `RewardSessionStatement` fields `[26..30)` and `[30..34)`. They are not publication public inputs. Publication is the 28-word `AGGREGATE_PI_LEN` schema: `[1,7,family,0]`, then `opening_digest`, `claim_tree_root`, and `header_digest`. Host roots use canonical little-endian Hash4 bytes. |
| Origin state | `RewardLedgerStateValues` hashed by `origin_state_root()`: `ledger_window_hash` is the zero Hash4, `ledger_root` is the 64-level Poseidon two-to-one issued tree from the zero Hash4, `user_root` is the 32-level summary tree from `PsyRewardLedger/Empty/1`, and both counts are zero. A later window keeps its previous opening and resets only its working user root and working counts. |
| Reward ledger key | Two u32 path limbs, user bits then source bits. |
| `PsyRewardLedger/State/1` | Poseidon state preimage in `reward_ledger.rs`: domain, then `ledger_window_hash`, `ledger_root`, and `user_root` as canonical little-endian Hash4, then `session_count` and `unfinished_session_count` as little-endian u32. Unfrozen. |
| `PsyRewardLedger/Window/1` | Poseidon window preimage in `reward_ledger.rs`: domain, `config_hash`, `economic_domain`, `window_id`, little-endian `end_checkpoint_id`, then `end_checkpoint_root`, `start_root`, and verifier hash as canonical little-endian Hash4. Unfrozen. |
| `PsyRewardLedger/Verifier/1` | Poseidon verifier preimage in `reward_ledger.rs`: domain, `circuit_digest` as canonical little-endian Hash4, little-endian cap length, then each cap hash as canonical little-endian Hash4. Unfrozen. |
| `PsyRewardLedger/Node/1` | Poseidon node preimage in `reward_ledger.rs`: domain, height byte, then left and right hashes as canonical little-endian Hash4. Unfrozen. |
| `PsyRewardLedger/Empty/1` | Poseidon of the domain bytes alone. It is the empty summary. The empty user root repeats the node preimage above it. Unfrozen. |
| `PsyRewardLedger/Proof/1` | SHA-256 proof-id domain. Its preimage is the `reward_ledger_proof_id` entry. Not a Poseidon label. Unfrozen. |

Aggregate - the family-7 batch publication consumer:

| Name | Meaning |
|---|---|
| `AGGREGATE_PI_LEN` | Sole owner of the 28-word publication width. |
| `aggregate_segment` | Segment arithmetic gadget for one aggregate. |
| `InclusionAggregateProof` / `prove_inclusion_aggregate` | Shared adapter proof and its constructor. |
| `RewardLedgerFinalProof`, `final_proof`, `final_state`, `ledger_final_user_root` | The window's closing ledger state, its proof, and its user tree root. |
| `reward_inclusion`, `reward_session`, `reward_aggregate` | Aggregate manager fields, one per sub-module. |
| `RewardPayoutSlot` | One payout slot in `RewardInclusionAggregateCircuit`: session proof, ledger state, source checkpoint, and payout leaf. |
| `constrain_reward_payout` | Circuit constraint for one `RewardPayoutSlot` in `inclusion_aggregate.rs`. |

Payout leaf and registry:

| Name | Meaning |
|---|---|
| `source_checkpoint_reward_leaf_commit` | Keccak commit of one payout leaf under `PsyBridge/SourceCheckpointReward/1/Leaf`. |
| `SourceCheckpointRewardOpening.leaves` | The opening's payout leaves. |
| `CircuitSetRegistration`, `circuit_set_registration`, `build_registrations`, `validate_registrations`, `registrations` | One registered circuit triplet and its registry operations. |

Domain strings: `PsyRewardJobs/Session/1`, `PsyRewardSession/Summary/1`, `PsyRewardLedger/{State,Window,Verifier,Node,Empty,Issued,Proof}/1`, `PsyBridge/SourceCheckpointReward/1/Leaf`.
