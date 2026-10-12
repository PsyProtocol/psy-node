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
| IMT sentinel | Map leaf at physical `state_slot_base`, derived as the ceiling of the subslot `base_offset` divided by four. Its zero key and value `[n,0,0,0]` bind the allocated member count; stable virgin state is physical zero with an all-zero preimage. |
| `sentinel_preimage` / `sentinel_merkle_proof` | Starting sentinel and its membership path under the operation's starting CSTATE root, shared by scoped membership, absence and writes. |
| `sentinel_old_leaf` / `sentinel_new_leaf` | Sentinel preimages immediately before and after the insertion's final count write; the former includes any predecessor splice already applied at the sentinel slot. History uses `sentinel_old_preimage` and `sentinel_new_preimage` for the same encoded leaves. |
| `sentinel_delta_proof` | Third insertion delta, following predecessor splice and member insertion; its new root is the insertion's final CSTATE root. |
| Current IMT path | Membership path assembled from immutable start-checkpoint nodes and matching live versions through the write checkpoint, authenticated against the session's current CSTATE root. `build_current_path` performs this typed-node assembly without changing live storage. |
| IMT operation scratch | Independently owned storage seeded with current paths for one operation; predecessor, member and sentinel-count writes complete here before one live batch write. |
| IMT replay scratch | Independently owned storage starting at authenticated historical CSTATE and UCON roots; complete history and enclosing UCON writes validate here before publication. |
| `get_contract_state_slot_for_staging` / `get_self_user_contract_tree_leaf_for_staging` | Read-only preparation of current CSTATE or UCON membership paths; immutable RPC caching is allowed, but live session storage and tracker writes are forbidden. |
| `verify_imt_map_bounds` | Constrain subslot base `b=4*q+r`, `0<=r<4`, physical base `B=q+(r!=0)`, positive capacity C and `B+C<2^h` at authenticated height h. |
| `validate_imt_update` | Validate insertion history's predecessor-to-member-to-sentinel root joins and equal path heights before consuming its deltas; does not replace leaf authentication or map-bound checks. |
| `load_stable_imt_sentinel` / `load_other_user_imt_sentinel` | Load and validate a positive-count sentinel with its membership path from the current contract or another user's authenticated contract state. |
| `load_imt_member` | Resolve a nonzero map key to an allocated leaf and membership path, checking the key and successor bounds. |
| `resolve_imt_absence_predecessor` | Resolve and validate the predecessor or sentinel that proves a query key absent from the map. |
| `validate_authenticated_sentinel` | Check the sentinel path index, canonical count and capacity, distinguishing a physical-zero virgin sentinel from a positive-count sentinel with an allocated successor. |
| `imt_sentinel_count` / `imt_sentinel_with_count` | Read a canonical allocated count, or replace only that count while preserving the sentinel key and successor. |
| `validate_imt_allocated_index` / `validate_imt_predecessor_leaf_index` | Validate an index within the allocated member range; predecessor validation also permits the sentinel slot. |
| `IMT_SET_DISABLED_DELTA_LEN` / `IMT_SET_UPDATE_DELTA_LEN` / `IMT_SET_INSERT_DELTA_LEN` | Delta-vector length constants for a disabled conditional write, an ordinary update and an insertion. |
| `DPNIMTSetWitness::delta_proofs` | Return the delta slice only after validating its length against the write kind. |
| `DPNIMTContainsOtherUserWitness` | Cross-user map membership witness containing the existence flag, user and contract paths, member preimage and sentinel authentication. |
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
| `BridgeTokenPolicy` | Immutable claim-circuit constructor policy: `chain_index: u8`, `token_contract_id: u32`, `token_address: [u32; 8]`, `approved_leaf: PsyContractLeaf<F>`, physical `map_base: u32`, and `capacity: u32`. The approved contract leaf supplies the authenticated state height; the installed mapping must match before generation. |
| `withdrawalTokenPolicyHash` | Opening verifier getter for the installed withdrawal policy: Keccak of ABI-padded chain u8, contract identifier u32, token address, complete approved contract leaf hash bytes32, physical map base u32, capacity u32, and state height u8. Setup derives it from the same `BridgeTokenPolicy` used to construct the claim circuit; L1 installation and dispatch compare it to the stored policy hash. |
| `policy_ordinal` | Per-withdrawal index into the sorted installed `BridgeTokenPolicy` collection compiled into the claim verifier; selects the same token contract for UCON and GCON authentication. |
| `AggregateSetupConfig` | Shared setup artifact containing encoded `network_config`, reviewed source identities, and the complete installed `withdrawal_policies` collection used to build the aggregate graph. |
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
| `batchCommit` / `batch_commit` | Window aggregate Keccak-256 commitment to at most 32 ordered records of one family: `K(D(Batch) \|\| config_hash \|\| window_id \|\| W(end_id) \|\| H4(end_root) \|\| W(family) \|\| W(global_chunk_ordinal) \|\| W(first_family_leaf_ordinal) \|\| W(chunk_leaf_count) \|\| encoded_active_leaves)`. Here `K` is Keccak-256, `D(x)=K(ASCII("PsyBridge/TwoArtifact/2/") \|\| ASCII(x))`, `W` is one big-endian 32-byte integer word, and `H4` is four such words. Withdrawal chunks precede reward chunks; families never mix inside a chunk. |
| `DepositLeafRange` | Global first-leaf ordinal and count defining one chain's interval in the complete deposit opening. Fields are `first_leaf: u32` and `leaf_count: u32`. |
| `DepositAggregateOpening` | Canonical complete deposit opening. Its domain identifier is `DepositAggregate`; its domain label remains `A`. |
| Opening bytes | The one encoded byte string for one aggregate opening. Rust name: `opening_bytes`. Not a second encoding of the same opening. |
| `opening_digest` | Native method on the aggregate opening types. The selected deposit relation uses the complete version-4 opening digest specified in bridge-design.md §26.4. The current native deposit codec still carries `window_id`; that field and its validation are pre-cutover. Do not use the internal deposit-child codec digest as a second L1 identity. |
| `deposit_opening_digest` | Rust name for the deposit family's `opening_digest`. Solidity field and event argument: `depositOpeningDigest`. |
| `openingDigest` | JSON object field and Solidity field for one family's `opening_digest`. Solidity: field on `WithdrawalAggregateOpening` and `RewardAggregateOpening`, and the indexed argument of `WithdrawalAggregateApplied` and `RewardAggregateApplied`. JSON wire field on aggregation status, disposition, and acknowledgment objects, replacing `aggregateStatement` with no alias. Same bytes as that family's `opening_digest`. |
| `header_digest` | Digest of header-domain plus header bytes. Different preimage from `opening_digest`. Do not use it as a name for the opening digest. |
| `WithdrawalAggregateOpening` | Canonical complete withdrawal opening. `withdrawal_roots: Vec<Hash4>` has one root per configured ordinal, followed by `withdrawals`. Crypto domain `Domain::WithdrawalAggregate`; its frozen label remains `WithdrawalBatch`. Do not rename that byte string. |
| `SourceCheckpointRewardOpening` | Complete source-checkpoint reward opening: config hash, window id, end checkpoint id/root, and ordered `SourceCheckpointRewardLeaf` records. Its digest is `K(K(ASCII("PsyBridge/SourceCheckpointReward/1/Opening")) \|\| encode())`, where `K` is Keccak-256. The removed Rust `RewardAggregateOpening` is not an alias; retained external Solidity names and frozen `RewardBatch` bytes do not rename this type or preimage. |
| `AggregateWindow` | Witness value for one withdrawal or reward aggregate: `config_hash: Bytes32`, `window_id: Bytes32`, `end_id: u64`, and `end_root: Hash4`. It is not a wire object and has no public-input layout of its own. Not `BatchContext`. |
| `config_hash_for_domain_derivation` | Keccak `config_hash`: `commit(Domain::Config, encode())`, returned as `Bytes32`. `NetworkConfig::encode()` field order is `version`, `network_magic`, `bridge_user_id`, `circuit_set_hash`, chain count, each `ChainConfig`, `ethereum_index`, `reward_payer`, `reward_token`, `reward_per_claim`, `reward_token_decimals`, `max_withdrawals`, `max_rewards`. Every derived field is excluded. Source: `client_prover/psy_core/psy_data/src/bridge_aggregate.rs:596-606`. |
| `LoadedBridgeConfig` | Load boundary owning one fixed `NetworkConfig` and its computed `economic_domain: Bytes32`. `config()` returns a shared reference. `economic_domain()` returns the computed bytes. Neither field is public and there is no setter, so the loaded config cannot be changed and the computed domain cannot become stale. It is not a second config authority. The fixed input is the existing `encode()` projection. The domain's outer Poseidon input ends with those raw Keccak bytes, serialized nowhere as `Hash4`. |
| `economic_domain` derivation | Poseidon at config load. Inner input is one canonical Goldilocks field per byte of `ASCII("PsyBridge/SourceCheckpointReward/2/EconomicDomain")`. Its `Hash4` is serialized limb 0 through 3 as little-endian `u64`. Outer input is those 32 bytes followed by the raw 32-byte `config_hash_for_domain_derivation`. That config hash is not serialized as `Hash4` and is not hashed with Poseidon again. Outer `Hash4` is serialized limb 0 through 3 as little-endian `u64` to `economic_domain`. The `/2` label is the accepted F1 byte string. Its schema-version owner is not identified, so the label is not rewritten to `/1`. |
| `WindowFinalizationOpening` | Complete F4 opening for joint proof B: common window fields, paired-u32 global roots, positive-span finalization slots, configured endpoints, withdrawals, old/new reward ledger roots, economic domain, and rewards. Native owner is `bridge_aggregate.rs`; encoded length is `1152 + 448*n + 192*w + 192*r`, with `1<=n<=8`. The encoded opening still contains `window_id`. The direct standalone 32-byte `window_id` word is removed from the parent preimage. |
| `WindowFinalizationCircuit` / `window_finalization` | Joint Plonky2 source circuit, its module, and the manager field. It unconditionally verifies the real pinned withdrawal and reward children plus configured finalizations. Source prefix `[2,12,2,0]` and eight digest words give 12 public inputs; the Groth16 wrapper publishes two uint128 halves. |
| `WINDOW_FINALIZATION_PI_LEN` / `WINDOW_FINALIZATION_OPENING_HEADER_BYTES` | Source public-input width 12 and native opening fixed header width 1152 bytes, respectively. Neither constant is the Groth16 public-input count. Header width stays 1152 because encoded `window_id` remains. |
| `window_finalization_digest` | Circuit F4 Keccak-256 digest matching `WindowFinalizationOpening::opening_digest`: `K(D(B) \|\| config_hash \|\| W(end_id) \|\| H4(end_root) \|\| aDigest \|\| global_deposit_root_words \|\| global_withdrawal_root_words \|\| W(n) \|\| slots \|\| endpoints \|\| W(w) \|\| W(r) \|\| H4(old_reward_ledger_root) \|\| H4(new_reward_ledger_root) \|\| economic_domain \|\| W(batch_count) \|\| batch_root)`. The direct standalone 32-byte `window_id` word is removed from this parent preimage. `aDigest` binds `window_id` indirectly because the deposit opening digest includes that word. A nonempty `batch_root` binds it indirectly through `batch_commit`. An empty `batch_root` is independent of `window_id`; `aDigest` and the L1 equality of the two opening window ids still bind it. The word remains a private input to both `build_opening_digest` child reconstructions. Here `K` is Keccak-256, not the economic-domain Poseidon hash. Both native and circuit digest builders write one chain-count word, followed by slots and endpoints with no second count, then the two adjacent payout counts. This describes the digest preimage, not `WindowFinalizationOpening::encode()` wire serialization. Child opening domains and preimages are unchanged. |
| `build_window_finalization_opening` | Host constructor in `daemon.rs`. |
| `window_finalization_domain` | Native Keccak helper. Its byte string remains `PsyBridge/TwoArtifact/2/B`. |
| `window_finalization_tree_domain` | Native Keccak helper. Its prefix remains `PsyBridge/TwoArtifact/2/`, followed by `Batch`, `Leaf`, `Empty`, or `Node`. |
| `window_finalization_proof` | Host proof value. |
| `window_finalization_reference` | Host file reference. |
| `readWindowFinalizationOpening` | Solidity reader. |
| `windowFinalizationOpeningDigest` | Solidity parent-digest function. |
| `windowFinalizationProof` | Historical section-6 ABI argument of the superseded four-argument publication function. It is not an argument of current `applyBridgeOpening(uint256[8] proof, bytes opening)`. |
| `windowFinalizationOpening` | ABI and Solidity argument. It is not the persisted daemon JSON key `window_opening`. |
| `chunk_count` / `batch_count` | A family's chunk count is `ceil(record_count/32)`, zero for no records. Window aggregate `batch_count` is withdrawal chunk count plus reward chunk count; it is derived, not independently supplied authority. |
| `batch_root` / `batch_leaf` / `batch_empty` / `batch_parent` / `batch_depth` | Tree width is `next_power_of_two(max(1,batch_count))`; depth is its base-two logarithm. With `K` denoting Keccak-256, real leaf `j` is `K(D(Leaf)\|\|W(batch_count)\|\|W(j)\|\|W(family)\|\|batchCommit)`, padding is `K(D(Empty)\|\|W(batch_count)\|\|W(j))`, and a parent is `K(D(Node)\|\|W(height)\|\|left\|\|right)` with height starting at 1. Zero batches give `batch_empty(0)` directly, not a zero digest or a fixed-depth padded root. |
| `AggregateLeaf` | Private codec trait in `bridge_aggregate.rs`, implemented by `WithdrawalLeaf` and `RewardLeaf`. `LEAF_WORDS` is 6; `write_leaf` and `read_leaf` encode and decode each existing leaf as six 32-byte words. It is not a new wire family. Distinct from circuit `AggregateLeafTarget`. |
| `AggregateLeafTarget` | Public circuit enum in `aggregate_commitment.rs`: `Deposit`, `Withdrawal`, and `Reward` leaf targets. Not the private codec trait `AggregateLeaf`. |
| `WithdrawalAggregateCircuit` | Withdrawal window aggregate publication circuit in `aggregate.rs`. Its public-input width is `AGGREGATE_PI_LEN`, the sole owner registered below. Crypto domain `Domain::Aggregate`; its frozen label remains `Batch`. Do not rename that byte string. Not `WithdrawalInclusionCircuit`, and not `ClaimPublicationHeader`. |
| `RewardAggregateCircuit` | Reward aggregate adapter in `aggregate.rs`. Its public `circuit_data` is only the adapter graph. Public-input width is `AGGREGATE_PI_LEN`, 28 words: `[1,7,3,0]`, `opening_digest`, `claim_tree_root`, and `header_digest`. It verifies one family-13 level-8 root and one real 34-field `RewardSessionCircuit` tip. It does not verify one session proof per user and it is not the session circuit. Not `RewardInclusionChunkCircuit` or `RewardInclusionCombineCircuit`. |
| Bridge claim circuit | The two fixed-slot Plonky2 children in `circuits::bridge_claim`. `BridgeWithdrawalClaimCircuit` authenticates namespace-6 burns under the finalized checkpoint. `BridgeRewardClaimCircuit` verifies one pinned `RewardClaimBatchCircuit` proof and binds each active claim to one batch statement. Not `RewardInclusionChunkCircuit`, `RewardInclusionCombineCircuit`, `WithdrawalAggregateCircuit`, or `RewardAggregateCircuit`. Not `ClaimPublication`, `ClaimPublicationHeader`, or `ClaimPublicationProof`. |
| `BridgeWithdrawalClaimCircuit` / `BridgeRewardClaimCircuit` | Sibling claim circuits. Each registers its business statement before any verifier suffix. The withdrawal circuit also authenticates the raw CSTATE root through UCON and the installed contract definition through GCON. |
| `BridgeWithdrawalClaimWitness` / `BridgeRewardClaimWitness` | One active claim inside its circuit. The withdrawal witness carries the user, contract, IMT membership, sentinel, and payment words. The reward witness carries one batch statement index, the claim's checkpoint anchor, and that anchor's historical path. |
| `BridgeWithdrawalClaimInput` / `BridgeRewardClaimInput` | Host input for one claim proof. `claims` is the ordered active prefix. It is a Rust field only: its name is not a serialized key, and the circuit copies the claim words into registered public inputs. |
| `BridgeWithdrawalClaimTargets` / `BridgeRewardClaimTargets` | Circuit targets for one claim proof, including the fixed `claims` word array. |
| `BRIDGE_CLAIM_CAPACITY` | Fixed active-prefix capacity shared by both claim circuits. |
| `BRIDGE_WITHDRAWAL_CLAIM_WORDS` / `BRIDGE_REWARD_CLAIM_WORDS` | Opening-word counts of one withdrawal claim (10) and one reward claim (15). [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `BRIDGE_WITHDRAWAL_CLAIM_STATEMENT_LEN` / `BRIDGE_REWARD_CLAIM_STATEMENT_LEN` | Public-input widths. Withdrawal width is `14 + BRIDGE_CLAIM_CAPACITY * BRIDGE_WITHDRAWAL_CLAIM_WORDS * 8`. Reward width is `6 + BRIDGE_CLAIM_CAPACITY * BRIDGE_REWARD_CLAIM_WORDS * 8` = `6+32*15*8` = 3846 (`bridge_claim.rs:59-60`). [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `BRIDGE_CLAIM_DEGREE_BITS` | Degree padding shared by both claim circuits. |
| `withdrawal_claim` / `reward_claim` | `AggregateCircuits` fields holding the two claim circuits. `withdrawal_claim_data` and `reward_claim_data` return their `CircuitData`. |
| `from_policy` | Private conversion from one `BridgeTokenPolicy` to the opening wrapper's token-policy projection. |
| `claim_common` / `claim_verifier` | Private `BridgeOpeningWrapper::build` parameters: common data and verifier data of the pinned claim child. Serialized identity keys `child_common_json`, `child_verifier_json`, and `child_fingerprint` stay; they are not these parameters. |
| `claim_words` | Private copier in `bridge_aggregate.rs` that copies one claim circuit's registered public inputs into the fixed opening word array. |
| `prove_withdrawal_claims` / `prove_reward_claims` | Relayer producers of one withdrawal claim proof and one reward claim proof. |
| `withdrawal_burn_key` | Poseidon key of one namespace-6 withdrawal burn. It is not a serialized key. |
| `fetch_withdrawal_claim_witness` | Relayer constructor of one `BridgeWithdrawalClaimWitness` from the installed policy and the burn proof. |
| `withdrawal_burn` | Relayer conversion of one pending withdrawal into one `WithdrawalBurnRecord`. |
| Withdrawal root path | Private Poseidon path authenticating one opening withdrawal root. It is not serialized. |
| `deposit_accumulator_seed` | Poseidon of field constant `0x44465331`, config hash as big-endian u32 words, checkpoint identifier as low/high u32 words, checkpoint root as native fields, and global deposit count, in that order. The numeric domain is a design candidate with no executed artifact freeze. |
| `deposit_accumulator_fold` | Poseidon of field constant `0x44464631`, preceding accumulator, global ordinal, chain index, absolute deposit index, and the unchanged claim-compatible Poseidon deposit leaf, in that order. Inactive record positions retain the preceding accumulator. The numeric domain is a design candidate with no executed artifact freeze. |
| `DEPOSIT_ACCUMULATOR_SEED_DOMAIN`, `DEPOSIT_ACCUMULATOR_FOLD_DOMAIN` | Native field constants for the registered seed and fold, respectively `0x44465331` and `0x44464631`; circuit helpers import the same constants. |
| `DepositLeafTarget::poseidon_hash` | Computes the unchanged 41-word claim-compatible Poseidon deposit leaf from this record's constrained field targets; the same returned hash feeds both append and accumulator constraints. |
| `DepositSpidermanAppendTarget` | Private full-page append targets inside the global deposit circuit, corresponding to `DepositSpidermanAppendInputs`; not a separately proved circuit. |
| `DEPOSIT_SPIDERMAN_PAGE_CAPACITY` | Fixed pool of sixteen full 32-leaf pages, sufficient for thirty-two records distributed across up to eight unaligned configured chains; the tight bound is `2C + floor((K - 2C) / 32)` when `K > 2C`. |
| `deposit_aggregate_pi_len` | Selected deposit-child public-input width: `19 + 17 * chain_count + 39 * 32`. The current helper returns the pre-cutover width `27 + 17 * chain_count + 39 * 32`, including eight window fields. |
| `DEPOSIT_RECORD_CAPACITY` | Single fixed record bound owned by native `bridge_aggregate`: one 32-leaf page width. Circuit unroll, native and Solidity opening validation, and setup identity use this bound; local scheduling budgets may be smaller. |
| Finalize endpoint extension | For each configured ordinal, public inputs after the retained prefix: deposit root, absolute deposit count, and withdrawal root. The prefix is not the full width. |
| `endpointChainListHash` | Pure getter on the generated finalize verifier. It returns `keccak256("PsyBridge/FinalizeChainList/1" || uint16_big_endian(C) || ordered raw chain indices)`. |
| `DigestBitsAdapter` | Source-pinned proof adapter exposing one `opening_digest` as 256 MSB-first bits. |
| `DepositOpeningWrapper` | Deposit-owned cross-config proof conversion: verifies the pinned global deposit source, forwards its compact raw opening public inputs unchanged and builds with PoseidonBN254GoldilocksConfig. No page or chain proof aggregation. |
| `DepositOpeningIdentity` | Deposit-owned setup binding: raw public-input schema, record capacity, installed config hash and bootstrap policies, configured chain order, source fingerprints and source/wrapper common plus verifier data. Serialized and hashed with the existing setup identity convention. |
| `DepositOpeningChain` | Product-owned configured chain index, bootstrap checkpoint identifier and bootstrap root. It is not compiled into the generic verifier. |
| Deposit opening identity hash | Product-owned setup hash over the raw schema, capacities, chain order, source identities, fingerprints, common/verifier bytes, config hash and bootstrap values. The label has no executed artifact freeze yet. |
| `CRVerifierCircuit` | Generic proof-conversion circuit under F5. It verifies the pinned converted proof and exposes its complete ordered public-input vector. It does not reconstruct an opening, apply business policy, or expose digest halves. |
| `EthereumRewardPayer` | Ethereum-only funded contract. Current `payRewards` consumes one boolean per job and pays immutable `REWARD_PER_CLAIM` (`EthereumRewardPayer.sol:52-95`). It is not the proposed one-session payer. |
| `REWARD_PER_CLAIM` | Current positive immutable per-job amount in the configured token's smallest units. Not the proposed session sum `W`. No production value is inferred. |
| `rewardNullifierDomain` | Current domain for the per-job `spentRewards` key: `keccak256(abi.encode(keccak256("PsyBridge/TwoArtifact/1/Reward"), uint256(1), networkMagic, uint32(524288), chainId, ethereumIndex, payer, rewardToken))`. |
| Consumed reward key | Current L1 key `keccak256(abi.encode(rewardNullifierDomain, claimCheckpointId, nullifierIndex))`. One boolean per job. Not the proposed source-and-user key. |
| Historical checkpoint Merkle proof | Claim that one checkpoint leaf at its checkpoint id is a member of the authenticated target checkpoint-tree root. Canonical name: `historical_merkle_proof`. Existing source is `historical_merkle_proof.rs`. Same membership concept as `reward_inclusion`'s `claim_path`: `claim_checkpoint_path` binds the claim checkpoint leaf hash and claim checkpoint id under the end checkpoint root. Not a state upgrade: `upgrade_checkpoint_historical_merkle_proof_gadget` (`HistoricalRootMerkleProofGadget`) rewrites a header from `historical_root` to `current_root`. Distinct from the reward tag-tree path. |
| `AnchorToEndTarget` | Historical checkpoint fold targets connecting a claim's checkpoint-tree anchor to the finalized end root, with anchor checkpoint id at most end checkpoint id. The record circuit binds both roots and the end id; zero inactive record paths select level-specific empty-tree siblings internally. |
| Session nullifier | Private temporary zero-to-one tree inside one reward session. Canonical names: `nullifier_tree`, `nullifier_key`. The key packs source, level, and index. The first own step starts empty; later own steps carry the private root through the verified predecessor's session state. It is not a publication input and is not L1 `spentRewards`. Not `claimed_tree` or `claimed_key`. |
| Reward nullifier root | `rewardNullifierRoot[userId]`, claim fields `old_nullifier_root` and `new_nullifier_root`, constant `EMPTY_REWARD_NULLIFIER_ROOT` (§26.2). One bytes32 per user: the height-32 outer root whose leaves are height-22 inner roots. This is the only L1 reward replay commitment. A user with no stored root starts at `EMPTY_REWARD_NULLIFIER_ROOT`. |
| `RewardConsumptionState` | User-held occupied reward coordinates and one pending claim, bound to config hash, Ethereum chain, payer and user. Its confirmed tree is reconstructed and compared with the payer root before proving; it contains no private key. |
| `RewardPendingClaim` | One unconfirmed coordinate addition set, its `RewardPendingSelection`, and its admission request. Its reconstructed resulting root confirms consumption only when equal to the payer root. |
| `RewardPendingSelection` | Original loader inputs retained on `RewardPendingClaim`: `realm_jobs` is `(realm_id, unique_pending_id, job)` and `coordinator_jobs` is `(unique_pending_id, job)`. A changed admission context reloads witnesses through these tuples; only a new claim reads the jobs file. |
| `reward_root_bytes` | Four canonical Goldilocks root limbs serialized in field order as big-endian u64 values into the payer's bytes32 representation. |
| `rebuild_reward_tree` | Construct source inner trees and the outer reward nullifier tree from unique occupied coordinates; insert each inner occupancy leaf as `[1,0,0,0]`. |
| `load_reward_state` / `save_reward_state` | Read and atomically write the one user reward consumption file under exclusive access; neither operation changes payer authority. |
| `read_reward_root` | Read `rewardNullifierRoot(userId)` from the configured Ethereum payer at a fixed block after checking chain identity. |
| `RewardSegmentCircuit` / `RewardSegmentTargets` / `RewardSegmentWitness` | One authenticated source's nonempty reward job prefix and its nullifier transition, without a predecessor proof. Witness fields are user_id, anchor_checkpoint_id, checkpoint_tree_root, old_nullifier_root and source. Public fields are user, anchor, old/new nullifier roots, count and amount. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `RewardMergeCircuit` / `RewardMergeTargets` / `RewardMergeWitness` | Pairwise reward composition. Witness is a closed enum: Leaf carries one segment proof; Pair carries left and right merge proofs. Leaf copies the segment's 22 fields. Pair requires the same user and anchor, joins left.new_nullifier_root to right.old_nullifier_root, and adds counts and amounts with checked arithmetic. [user-ruling: `mem_no_duplicate_defense_2026_10_11`] |
| `REWARD_LEAF_CAPACITY` | Maximum jobs in one reward segment; changing this bound does not change either nullifier tree's coordinate domain. |
| `RewardRootCircuit` / `RewardRootTargets` | Reward claim authentication circuit and targets: verify the final merge proof, authenticate the user's registered leaf beneath the claim checkpoint anchor, and prove knowledge of the pinned zk scheme's private key. |
| `RewardRootStatement` | `RewardRootCircuit`'s published 30-field public-input statement: user, recipient, initial and final nullifier roots, consumed job count, token sum, and checkpoint-tree anchor. Sibling of `RewardSessionStatement`; carried by `RewardRootTargets`; one statement fills each `RewardClaimBatchCircuit` slot. Not the native fifteen-word `RewardClaim` opening row and not the Solidity six-word payer tuple. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `RewardSegmentProof` / `RewardMergeProof` / `RewardRootProof` | One segment proof, one merge proof, and the root authentication proof. `RewardRootProof` is the `reward_chain.rs` proof alias over `ProofWithPublicInputs` at the pinned root verifier; it is the published claim proof carried in the services `proof` field and bound by the `RewardClaimBatchCircuit` leaf tip. |
| `RewardSkipReason` | Payer row failure category: StaleRoot=1, InvalidClaim=2, InsufficientReserve=3, TransferFailed=4, InsufficientGas=5. Services store the category from authenticated `RewardSkipped` event evidence; a skipped row is not payment. |
| `rewardCallGasCap` | Immutable deployment limit on gas forwarded to one reward payment self-call; exceeding it fails that row without payment. Parent continuation and tail-log reserves are separate compiled bounds, not deployer settings. |
| `claim_context_id` | Queue admission scope derived as Keccak of the Keccak domain `PsyBridge/ClaimContext/4`, installed config hash, W32 end checkpoint identifier and four canonical W32 end-root limbs; not an opening digest or payment identity. |
| `RewardClaim` | Native fifteen-word reward opening record: chain, user, contract 7, initial and final nullifier roots, count, recipient and token amount, with constant kind 2. Its byte length is 480. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| Solidity `RewardClaim` | The payer's six-word ABI tuple `(uint32 userId,bytes32 oldNullifierRoot,bytes32 newNullifierRoot,uint32 count,uint256 amount,address recipient)` consumed by `payRewards`. Language-scoped: the same spelling as, and a different representation from, the native fifteen-word `RewardClaim` record above; each of its fields projects from the verified `RewardRootStatement` and opening record (bridge-design.md §26.5). |
| `BridgeChainRow` | Opening chain endpoint row containing its index, starting checkpoint identifier/root, deposit roots and absolute deposit counts. |
| `WithdrawalBurnRecord` | Native ten-word withdrawal opening record containing kind 1, chain, user, token contract, full nonce, three zero words, recipient and positive token amount. |
| `RewardClaimBatchCircuit` / `RewardClaimBatchTargets` / `RewardClaimBatchProof` | Relayer-side three-mode node folding at most 32 claim tips. Empty proves the all-zero statement, leaf binds slot 0 to one root tip, and pair concatenates two positive-count children. `RewardClaimBatchProof` is the batch proof alias (`reward_claim_batch.rs:60`). |
| `AuthenticatedJobWitness` | Reward claim job witness: source checkpoint, tagged-node coordinate, owner tag preimage, child hashes, and tagged authentication path. |
| `INNER_EMPTY_ROOT` | Reward nullifier inner-tree root obtained by repeatedly hashing the zero Hash4 with itself using Poseidon over the complete inner-tree height; outer empty leaves equal this root. |
| `RewardNullifierSourceTargets` / `RewardNullifierSourceWitness` | One reward source's inner/outer update targets and sibling-path witnesses. Each inserted job changes its inner leaf from zero Hash4 to `[1,0,0,0]`; outer leaves hold the resulting inner roots. The reward segment owns the delta wiring directly. |
| `RewardSegmentSourceWitness` | One segment's authenticated source checkpoint, leaf and siblings, token amount, authenticated jobs and nullifier paths. |
| `RewardRootWitness` | Host witness for claim authentication: recipient, anchor checkpoint and leaf path, global state roots, registered user leaf and path, private key, and final merge proof. |
| `REWARD_SEGMENT_DEGREE_BITS` / `REWARD_MERGE_DEGREE_BITS` | Construction padding for the segment and merge circuits respectively; actual built common data determines whether construction succeeds. |
| `REWARD_SEGMENT_STATEMENT_LEN` / `REWARD_MERGE_STATEMENT_LEN` | Business public-input width of the segment and of the merge, 22 fields each, excluding the merge verifier suffix. Merge public inputs are 22 plus the cap-height-4 suffix `4+4*16`, equal to 90. Ordered fields are in bridge-design.md §26.2. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `REWARD_ROOT_STATEMENT_LEN` | Reward-root public-input width, 30 fields. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |
| `checkpoint_tree_root` | Poseidon checkpoint-tree root in `RewardSessionStatement`. That statement also carries `user_id`, `recipient`, `total_amount`, `count`, `jobs_commitment`, and the composite ledger endpoints `old_ledger_state_root` and `new_ledger_state_root`. Those endpoints are ledger state, not the private session root. Publication width and finalize width are distinct and are owned by their own registered names. Existing checkpoint-header upgrade names stay unchanged. |
| `deposit_leaf_hash` | Private Poseidon `q_hash_many` of one `DepositLeaf` in `prove_bridge.rs`: `shield_address`, `token`, `l2_token_contract_id`, `amount`, `chain_index`, `note_commitment`, in that order. Distinct from `DepositLeaf::leaf_commit` and Solidity `_computeDepositLeafHash`. |
| `append_deposit_leaf` | Private deposit-tree frontier update in `prove_bridge.rs`: writes the leaf into the frontier and returns the new Poseidon deposit-tree root. Distinct from guardian `append_leaf`. |
| Deposit prefix, `VerifiedDepositPrefix` | Authenticated per-chain deposit endpoint owned by `guardian/verify_l1.rs`: root, count, frontier, anchor, event block, prior interval endpoint and occupied partial-page hashes. The daemon retains this same tuple through its existing file references; it is not a second all-history record collection. |
| `occupied_partial_page_hashes` | Ordered hashes of the current deposit page's occupied leaves; length is `count mod 32`, zero at a full-page boundary. Together with the frontier these supply the ordinary append gadget's full old page. |
| Frozen deposit predecessor and successor | File references to the authenticated deposit prefixes before and after a frozen opening. Retry retains the predecessor; accepted endpoints advance to the successor only after durable destination completion. |
| Proved deposit count | L1 `provedDepositCount` compared with the L2 deposit-tree next index. A proved count above that L2 count, or a new session whose two counts differ, is a deposit-count mismatch, not custody. The two greater-than failures use `proved deposit count exceeds L2 deposit count`; the equality failure uses `L2 deposit count differs from proved deposit count`. |
| Reward circuit kind | Session, nine internal hierarchy nodes, the retained final adapter, and the Groth16 wrapper are distinct circuits. Kind count is not recursion depth. `REWARD_SESSION_STEP_CAPACITY` selects session step size only. No debit, ticket, closing, or re-anchor circuit is added. |
| Reward session | One proof chain for one `(economic_domain, source_checkpoint_id, user_id)`, proved by `RewardSessionCircuit`. Its terminal amount is `W`, the full sum of included jobs. Jobs omitted from it are forfeited. |
| Reward ledger key | Two path limbs, user bits then source bits. Never one Goldilocks target. Economic domain is pinned tree context, not a limb. `RewardLedgerLeafTargets` writes the occupied leaf under `PsyRewardLedger/Issued/1` and never clears it. |
| `jobs_commitment` | Session rolling Poseidon commitment. Its base is `reward_session_seed` over `PsyRewardJobs/Session/1`. `rolling_jobs_commitment` in `reward_session.rs` absorbs the step domain, the previous commitment, the counts, and each active job record. Inactive padding is excluded. Each included job contributes the configured per-claim amount; `RewardLeaf` has no amount field. |
| `SourceCheckpointRewardLeaf` | Payout leaf: economic domain, source checkpoint id, user id, amount `W`, recipient, and initialized flag. Its commit is `source_checkpoint_reward_leaf_commit` under `PsyBridge/SourceCheckpointReward/1/Leaf`. Not the per-job `RewardLeaf` and not the reward-ledger occupancy leaf. |
| Consumption key | Payout boolean, `keccak256(abi.encode(consumption_domain, economic_domain, uint256(source_checkpoint_id), uint256(user_id)))`. It does not replace reward-ledger occupancy. Distinct from the per-job `spentRewards` key. |
| `ClaimPublicationHeader` | Packed family-specific publication header. It binds the opening digest, claim root, and capacity, count, and segment context. Reward hash slots are `old_ledger_state_root` and `new_ledger_state_root`, not a stored persistent job-nullifier cursor. |
| `ClaimPublication` | StateManager registry entry authenticated by publication. Distinct from a payment record and from reward-ledger occupancy. |
| `claim_tree_root` | Keccak root over one segment's payout leaves and canonical padding. |
| `Hash4Encoding` | Explicit selector `CanonicalU64x4` or `LittleEndianU32x8`; no decoder fallback. Canonical limbs remain below the Goldilocks modulus. Keccak big-endian u32 words are a different representation. |
| `ActiveWindow` | Per-destination retained manifest and progress state. Incomplete withdrawal or reward segments block the next window. Root publication does not mark claims paid. |
| Interleaved acceptance gap | Unclosed connection from the private ledger targets to one selected publication history. Independent valid sessions and host sorting are insufficient. No wider user statement, balance, or persistent job root is adopted. |
| `W` | Checked full sum of one reward session and the payout-leaf amount. Not a balance, debit, partial prefix, or per-job `REWARD_PER_CLAIM`. |
| `applyBridgeOpening` | Current StateManager external function: `applyBridgeOpening(uint256[8] proof, bytes opening)` (`psy-contracts/src/StateManager.sol:211-244`). One proof and one opening. No old callable selector and no compatibility shim. Not the Solidity library `BridgeOpening`, the opening value `BridgeOpening`, or the proof/opening call value `BridgeOpeningCall`. |
| `BridgeOpeningCall` | Proof/opening call value: Rust `finalize_bridge.rs` struct and the Hardhat helper tuple of one `uint256[8]` proof plus one opening. Serialized fields stay `proof` and `opening`. Not the Solidity library `BridgeOpening` and not the native opening value `BridgeOpening`. |
| `buildBridgeOpeningCall` | Hardhat helper that builds one `BridgeOpeningCall`. Same concept as the Rust `BridgeOpeningCall` value. Not a second opening type. |
| `opening_call` | Relayer helper that builds one `BridgeOpeningCall` from a retained opening and its proof. Not a wire field and not `window_finalization`. |

Design contract: `docs/src/dev/bridge-design.md` is the single bridge design authority. The current StateManager entry point is `applyBridgeOpening(uint256[8] proof, bytes opening)`. The proof/opening call value is `BridgeOpeningCall`; the Hardhat builder is `buildBridgeOpeningCall`; the relayer helper is `opening_call`. The Solidity library `BridgeOpening` stays that library name. The window aggregate circuits are `WithdrawalAggregateCircuit` and `RewardAggregateCircuit` in `aggregate.rs`. The publication vocabulary is `ClaimPublicationHeader`, `ClaimPublication`, `ClaimPublicationProof`, and `build_claim_tree`. Those publication names are not the window aggregate circuits. Reward-session and reward-ledger names remain the registered vocabulary below. The current payer remains per-job. Runtime validation, setup generation, and activation remain unexecuted.

## Naming governance
The `reward` head also owns the `segment` and `merge` subdomains in `bridge-design.md` §28: authenticated source transitions and their threaded pairwise composition respectively. Their Circuit, Targets, Witness and Proof forms share those exact family stems; they are distinct responsibilities, not equivalent sibling circuit types. Registration does not authorize implementation before the design gate.

The literal `spentRewards` in bridge-design.md's payer/retry history, this document's rewardNullifierDomain/session-nullifier/consumption-key entries, and TASKS.md's stale-skip memo is a protected historical occurrence: it quotes the removed L1 mapping declared and used at `EthereumRewardPayer.sol:22,79`, not a current domain name. Preserve the exact identifier in those citations. Under the refined 2026-10-11 user ruling, `spent` is banned as a synonym-introduction violation: reuse `old_nullifier_root`, `new_nullifier_root`, `nullifier_tree`, `nullifier_key`, or the registered Consumption key according to the actual concept; do not mint another root name. The upstream comment “Spent updates are a linear transition” is a protected historical quotation only. Pseudocode shorthand does not authorize implementation names: register the actual gadgets in `bridge/gadgets/reward_nullifier.rs` before implementation. This disposition follows Naming rules5,17,18.


This section is the machinery for the `AGENTS.md` naming rules (18, 23, 24). It records dispositions and freeze state; it does not rename anything by itself.

### Rule 18 dispositions

| Occurrence | Class | Basis |
|---|---|---|
| `statement` in `reward_session.rs` (the per-step public-input statement and its accessors) | Genuine ZK statement | Rule 18 exempts a genuine ZK statement; the field roles are pinned by the `checkpoint_tree_root` entry above. |
| `old_*` (`old_root`, `old_summary`, `old_state`, `old_session_root`, `old_user_root`) | State-transition qualifier | Rule 14 state qualifier; each pairs with the `new` endpoint of one transition. |
| `old_ledger_state_root` / `new_ledger_state_root` | Registered ledger endpoints | Composite ledger-state endpoints. `nullifier` names consumed-job commitments only: the session and tag trees, plus the persistent per-user reward nullifier tree (user ruling 2026-10-10: `rewardNullifierRoot`, `old/new_nullifier_root`); ledger-state endpoints stay excluded. |
| `to_canonical_biguint` | External API | Dependency-provided method. |
| `tracing::info!` | External API | Log macro, not a symbol. |
| `SETTLEMENT`, `SETTLEMENT_EMPTY`, `SETTLEMENT_BATCH`, `SETTLEMENT_LEAF`, `SETTLEMENT_NODE` | Protected Solidity constants | Names and keccak values stay. Values are `keccak256` of `PsyBridge/TwoArtifact/2/B`, `/Empty`, `/Batch`, `/Leaf`, and `/Node`. Rule 18 retains both the names and the byte strings. |
| `canonical_scalar` (`reward_session_witness.rs:123`) | Established external domain term | ECDSA canonical scalar form. The low flag requires low-S. Keep with this basis or rename in the same cutover that touches the file. |
| `anyhow::Context` and `.context()` | External API | Dependency trait and method. Not the reward-ledger window. Do not rename these occurrences. |
| `terminal` in auth and multisig-policy error strings | Prose | Error text only. It does not name a frozen cryptographic byte string. |
| `canonical_scalar`, `canonical_bytes`, `read_canonical_hash4`, and `CanonicalU64x4` | Cryptographic encoding | Canonical field, scalar, or Hash4 encoding owned by this protocol. |
| `from_canonical_*` and `to_canonical_*` | External API | Dependency field and integer conversion methods. Do not rename them. |
| `statement` | Genuine ZK statement | The per-step public-input statement. Rule 18 exempts it. |
| `manifest` in error strings | Prose | Error text only. It is not a registered publication type. |
| `context` on a live external contract or generic JSON compatibility field | External API | Classify the occurrence as external. Do not rename it without an explicit mapping. |
| `WindowAggregateApplied` | External event topic, scheduled cutover | Event name stays in this slice. Renaming it would change topic0 and is a separate scheduled cutover, not this `applyBridgeOpening` rename. It is not `WithdrawalAggregateCircuit` or `RewardAggregateCircuit`. |
| `ClaimPublicationHeader` | External publication header | Packed header type and its Solidity twin stay. Not either window aggregate circuit. |
| `ClaimPublication` | External registry entry | StateManager registry entry and the `ClaimTreeRootPublished` event stay. Not either window aggregate circuit. |
| `ClaimPublicationProof` | External Groth16 proof codec | Proof struct in `bridge_wrap.rs` stays. Not either window aggregate circuit. |
| `build_claim_tree` | External claim-tree constructor | Native constructor in `bridge_aggregate.rs` stays. It is not the window aggregate module. |
| `aggregate` | Owned circuit module | Module `psy_plonky2_circuits/src/bridge/circuits/aggregate.rs`. Head word `aggregate` owns only `WithdrawalAggregateCircuit` and `RewardAggregateCircuit`. It does not own the header, proof, root, or claim-tree constructor above. |
| persisted JSON key `window_opening` | Local daemon state key | Relayer daemon state-file key for the window finalization opening; the state file is machine-local and purged on devnet reset. |
| `WindowProofs.window_finalization` | Persisted proof reference | Rust field name. Wire key `window` through `#[serde(rename = "window")]`. |
| artifact directory and schema key `WindowFinalization` | Fresh generated artifact path | Fresh generated artifact path and schema-2 JSON key for the window finalization aggregate. No compatibility alias. ASCII domain bytes do not change. Generation is a separate authorized package. |
| `DigestArtifact::WindowFinalization = 2` | FFI discriminant | Owned sibling enum variant. The name cuts over with its callers; numeric value 2 stays. |
| `settlement_wait_seconds`, `settlement_checkpoint_state`, `settlement_compile_evidence`, `settlement_current_compile`, `settlement_delivery_sequence`, `settlement_postmerge_audit`, `settlement_postmerge_compile`, `settlement_postmerge_evidence`, `settlement_proxy_repair` | Excluded prose | Not part of the window-finalization cutover. Do not rename these occurrences. |
| `ChainContext`, `ChainContextTarget`, `register_deposit_context`, `connect_deposit_context` | Excluded chain statement | Owned chain statement in `chain_aggregate.rs:21`, `chain_aggregate.rs:37`, `chain_aggregate.rs:62`, and `chain_aggregate.rs:66`. Excluded from the window-aggregate cutover. Do not rename them. |
| `context` on `ChainContext` and `ChainContextTarget` | Excluded chain statement | The chain statement named above. Not a window aggregate circuit name. Do not rename it in this cutover. |
| `QMetaDataStoreReaderSync` and module `qmetadata` | Existing storage API | Trait in `client_prover/psy_core/psy_data/src/traits/qdatastore/qmetadata.rs:16` and its module. Existing storage API. Excluded from this cutover. Do not rename them. |
| `custody` local in `psy_plonky2_circuits/tests/bridge_aggregate.rs:768-788`, closure parameter `entry` at line 1050, and `phase=*-entry` diagnostic strings in `aggregate.rs` | Retained test prose | Existing test fixture variable, closure parameter, and diagnostic strings. Outside the window-aggregate cutover. Not a new domain name. Do not rename them and do not change their behavior. |
| `BridgeWithdrawalPaymentTargets` and field `payments` | Different payment substructure | Recipient, amount, and nonce targets inside one withdrawal claim. Payment is not a claim-circuit sibling. |
| `child_fingerprint`, `child_common_json`, `child_verifier_json` | Serialized identity keys | JSON fields of `BridgeOpeningIdentity`. The private parameters that fill them are `claim_common` and `claim_verifier`. |
| `ClaimPublication`, `ClaimPublicationHeader`, `ClaimPublicationProof` | Workspace publication codec | Types in this workspace for the window-aggregate publication. They are not `BridgeWithdrawalClaimCircuit` or `BridgeRewardClaimCircuit`. A later publication-family cutover owns them; this claim cutover does not. |
| `prove_claim_publication`, `publication_words`, `REWARD_PUBLICATION_FAMILY`, `WITHDRAWAL_PUBLICATION_FAMILY`, `REWARD_PUBLICATION_CAPACITY` | Workspace publication constants | Constants of that same window-aggregate publication codec. Not the bridge claim circuit, and not classified as external. |
| `withdrawal_publication_header`, `reward_publication_header`, `assert_withdrawal_publication` | Workspace publication helpers | Helpers of that publication codec in `tests/bridge_aggregate.rs` and `aggregate.rs`. Not this claim module. Their publication component stays until that codec's own cutover. |
| `WithdrawalBurnRecord` and guardian request field `withdrawal_records` | Burn record | Native opening burn and the guardian request field that carries those burns. Not a claim-circuit slot. The guardian field is a request field in this workspace, not an external API. |
| `withdrawal_record_input` | Claim input constructor | Private constructor in `client_prover/psy_prover/src/local/bridge_aggregate.rs`. Its return type and `claims` field use the claim family. The function name itself remains a coupled `record` hit for the prover lane. |
| `reward_record` in `client_prover/psy_prover/src/local/bridge_aggregate.rs:78` | Reward leaf helper | Builds one reward leaf and tag witness. Its one coupled caller is `client_prover/psy_cli/psy_user_cli/src/subcommand/claim_rewards.rs:28,78`. This is a remaining claim-naming integration, not an external exemption. The function name stays until that caller and definition are renamed together. |
| `record_membership` | IMT membership field | Existing membership-proof field consumed by the withdrawal claim witness. Not a claim slot. Renaming it is outside this claim cutover. |
| `DEPOSIT_RECORD_CAPACITY` and other deposit `record` identifiers | Deferred deposit surface | Deposit opening capacity and deposit-circuit identifiers. The active sprint defers deposit D5-S work, so these are excluded from this claim cutover rather than classified as external. |
| daemon directory label `publication-nonempty` | Local fixture label | Directory string in a daemon test. It is not a frozen byte string. The CLI lane owns that file. |
| `aggregate publication` prose and `aggregate-publication` directory labels | Setup prose | Words in `regen_groth16_keystore.rs`. They do not name a claim symbol. The CLI lane owns that file. |
| `record` and `publication` in design sentences | Ordinary prose | Sentence words on changed docs that do not name a symbol. A sentence that names this claim family uses the claim spelling. |
| `batch` in `RewardClaimBatchCircuit`, `RewardClaimBatchTargets`, `RewardClaimBatchProof`, and module `reward_claim_batch.rs` | Registered batch-node vocabulary | Workspace-owned circuit naming its content: the three-mode node folding at most 32 claim statements into one root proof, sibling of the registered batch-tree vocabulary (`batchCommit`, `batch_root`, frozen label `PsyBridge/TwoArtifact/2/Batch`). Not an external API and no external protection is claimed; rule 17's `batch`->`aggregate` substitution does not apply because `aggregate` is the registered head word of the distinct `aggregate.rs` publication circuits. |
| `RewardRootStatement` | Genuine ZK statement | Rule 18 exempts a genuine ZK statement; it is the root circuit's registered 30-field public-input statement, sibling of the exempted `RewardSessionStatement`. |

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
| `PsyRewardJobs/Session/1`, `PsyRewardSession/Summary/1`, `PsyRewardLedger/{State,Window,Verifier,Node,Empty,Issued,Proof}/1`, `PsyBridge/SourceCheckpointReward/1/Leaf` | Historically unfrozen: source or authored tests may contain them, and that presence is not execution. No executed test, generated circuit artifact, or deployment was supplied. Protected for the current window-finalization cutover: do not rename these byte strings. |
| `PsyBridge/TwoArtifact/2/B`, `PsyBridge/TwoArtifact/2/Batch`, `PsyBridge/TwoArtifact/2/Leaf`, `PsyBridge/TwoArtifact/2/Empty`, `PsyBridge/TwoArtifact/2/Node` | No executed test, generated circuit artifact, or deployment was supplied for these labels. Protected for the current window-finalization cutover: do not rename these byte strings. |
| `PsyBridge/SourceCheckpointReward/1/Opening` | No executed test, generated circuit artifact, or deployment was supplied for this label. Protected for the current window-finalization cutover: preserve these bytes and do not rename them. |
| `PsyRewardAuthorization/CreditSession/1` | Frozen. Host-domain bytes were actually executed and remain protected. Do not rename that byte string. |
| `Domain::Aggregate` label `Batch` | Frozen before this cutover. The aggregate-circuit rename on 2026-10-08 does not change the byte string. No artifact regeneration is authorized by this naming cutover. |

### Module head words

A public domain name starts with its owning module's head word, and two modules never share one (AGENTS.md naming rule23). Registered head words: `reward` owns reward `inclusion`, `session`, `ledger`, `aggregate`, `segment`, `merge`, `claim` (the native opening record and the claims batch node), and `root` (claim authentication); `window_finalization` owns the joint bridge opening and aggregate circuit, with `opening`, `digest`, and `batch` sub-words; `settlement_aggregate` owns only `WithdrawalAggregateCircuit` and `RewardAggregateCircuit` in `aggregate.rs`; `bridge_claim` owns `BridgeWithdrawalClaimCircuit` and `BridgeRewardClaimCircuit` in `circuits/bridge_claim.rs`. `build_opening_digest` reconstructs the two child opening digests. Window-finalization batch helpers use the registered `batch` prefix and `chunk_count` derivation above. The existing `deposit`, `withdrawal`, and `checkpoint` families retain their heads. `ClaimPublicationHeader`, `ClaimPublicationProof`, `ClaimPublication`, and `build_claim_tree` are external registry names and are not members of `bridge_claim` or `settlement_aggregate`.

Naming governance cutover record: on 2026-10-08 the external publication vocabulary `InclusionAggregateHeader`, `InclusionAggregateRoot`, `InclusionAggregateRootPublished`, `InclusionAggregateProof`, `readInclusionAggregateHeader`, `inclusionAggregateRoot`, `build_inclusion_aggregate_tree`, `INCLUSION_AGGREGATE_CAPACITIES`, and `prove_inclusion_aggregate` was renamed to the `Settlement` family (`ClaimPublicationHeader`, `ClaimPublication`, `ClaimTreeRootPublished`, `ClaimPublicationProof`, `readClaimPublicationHeader`, `getClaimPublication`, `build_claim_tree`, `CLAIM_TREE_CAPACITIES`, `prove_claim_publication`), authorized by the user, riding the N=32 bridge-aggregate regeneration wave that already invalidates the Groth16 setup, verifier set, and Genesis artifacts. The artifact set pinned by these labels regenerates with the rename; StateManager redeployment is required and the `ClaimTreeRootPublished` topic0 differs from the prior event. Reward-family `RewardInclusionChunkCircuit` and `RewardInclusionCombineCircuit` keep the `reward` head word and were not renamed.

The existing `keccak` head owns Keccak operations, including the bridge-facing bounded stream helpers beside `keccak_prefix_words`; it introduces no new hash domain.

### Generic verifier and product identity

`bridge-design.md` F5 requires the complete ordered Goldilocks public-input vector through the generic worker and FFI interfaces. Digest bits, 128-bit packing and digest halves cannot replace that vector. Product opening reconstruction and business policy belong to the product consumers, not the generic verifier.

| Name | Meaning |
|---|---|
| `BridgeOpeningIdentity` | Product setup identity binding config hash, ordered chains, token policies, capacities, source identities and circuit fingerprints. |
| `BridgeOpeningWrapper` | Product recursive conversion of the bridge proof that preserves its complete ordered public-input vector. |


### Keccak stream helpers

| Name | Meaning |
|---|---|
| `KeccakStreamTargets` / `KeccakStreamValues` | Circuit/native siblings carrying all 25 Keccak lanes as low-u32/high-u32 pairs and `byte_offset`. The incomplete rate prefix is already XORed into the state; bytes after the offset retain the previous permutation output. Native default is the zero initial state. |
| `byte_offset` | Position of the next byte XOR, in 0 through 135, in both stream representations. Stream byte `j` occupies lane `j/8`, shift `8*(j%8)`. |
| `keccak_stream_absorb` / `keccak_stream_absorb_values` | Circuit/native bounded append of at most 136 bytes from exactly 34 big-endian u32 words, requiring a zero suffix. XOR the prefix at the offset, permute when a rate block completes, and retain the remaining partial state without padding. Native validation precedes mutation. |
| `keccak_stream_finalize` / `keccak_stream_finalize_values` | Circuit/native final digest: XOR `0x01` at the offset and `0x80` at rate byte 135, permute once, and return the first 32 lane bytes. Circuit digest words retain `Bytes32Target` big-endian byte order. |

`U32Target`, `Bytes32Target`, `keccak_f1600`, `tiny_keccak::keccakf`, and dependency `from_canonical_*` conversions retain their existing spellings. These helpers do not change cryptographic domain bytes or publication layouts.

### Registered reward vocabulary

Session, ledger, payout, and publication names below are the current spellings. Hierarchy names describe the implemented internal reward graph. They are not external aggregate segments.

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
| `SOURCE_CHECKPOINT_REWARD_OPENING_HEADER_BYTES` | Width of the source-checkpoint reward opening header in `bridge_aggregate.rs`. `aggregate.rs` imports it to bound the opening preimage. Not a cryptographic domain string. |
| `WITHDRAWAL_HEADER_BYTES` | Fixed prefix of one withdrawal `ClaimPublicationHeader` in `bridge_aggregate.rs`: family byte, config hash, window id, end checkpoint id, end checkpoint root, and the six segment counters, then `opening_digest` and `claim_tree_root`. Configured withdrawal roots follow this prefix. Not a cryptographic domain string. |
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
| `reward_ledger_proof_id` | `SHA-256(UTF8("PsyRewardLedger/Proof/1") \|\| complete user-verifier Hash4 as canonical little-endian u64 limbs \|\| canonical proof bytes)`. SHA-256, not Poseidon. The label is historically unfrozen and is protected for the current window-finalization cutover. |
| `verify_reward_ledger_step` | Host verifier of one `RewardLedgerStep` in `reward_ledger.rs`. `expected_old_root` is the store's locked trusted baseline, not a caller-selected root. It returns one `RewardLedgerTransition`. |
| `old_ledger_state_root` / `new_ledger_state_root` | Composite ledger-state endpoints in `RewardSessionStatement` fields `[26..30)` and `[30..34)`. They are not publication public inputs. Publication is the 28-word `AGGREGATE_PI_LEN` schema: `[1,7,family,0]`, then `opening_digest`, `claim_tree_root`, and `header_digest`. Host roots use canonical little-endian Hash4 bytes. |
| Origin state | `RewardLedgerStateValues` hashed by `origin_state_root()`: `ledger_window_hash` is the zero Hash4, `ledger_root` is the 64-level Poseidon two-to-one issued tree from the zero Hash4, `user_root` is the 32-level summary tree from `PsyRewardLedger/Empty/1`, and both counts are zero. A later window keeps its previous opening and resets only its working user root and working counts. |
| Reward ledger key | Two u32 path limbs, user bits then source bits. |
| `PsyRewardLedger/State/1` | Poseidon state preimage in `reward_ledger.rs`: domain, then `ledger_window_hash`, `ledger_root`, and `user_root` as canonical little-endian Hash4, then `session_count` and `unfinished_session_count` as little-endian u32. Historically unfrozen; protected for the current window-finalization cutover. |
| `PsyRewardLedger/Window/1` | Poseidon window preimage in `reward_ledger.rs`: domain, `config_hash`, `economic_domain`, `window_id`, little-endian `end_checkpoint_id`, then `end_checkpoint_root`, `start_root`, and verifier hash as canonical little-endian Hash4. Historically unfrozen; protected for the current window-finalization cutover. |
| `PsyRewardLedger/Verifier/1` | Poseidon verifier preimage in `reward_ledger.rs`: domain, `circuit_digest` as canonical little-endian Hash4, little-endian cap length, then each cap hash as canonical little-endian Hash4. Historically unfrozen; protected for the current window-finalization cutover. |
| `PsyRewardLedger/Node/1` | Poseidon node preimage in `reward_ledger.rs`: domain, height byte, then left and right hashes as canonical little-endian Hash4. Historically unfrozen; protected for the current window-finalization cutover. |
| `PsyRewardLedger/Empty/1` | Poseidon of the domain bytes alone. It is the empty summary. The empty user root repeats the node preimage above it. Historically unfrozen; protected for the current window-finalization cutover. |
| `PsyRewardLedger/Proof/1` | SHA-256 proof-id domain. Its preimage is the `reward_ledger_proof_id` entry. Not a Poseidon label. Historically unfrozen; protected for the current window-finalization cutover. |

Aggregate - publication and the internal reward hierarchy:

| Name | Meaning |
|---|---|
| `AGGREGATE_PI_LEN` | Sole owner of the 28-word publication width. |
| `aggregate_segment` | Segment arithmetic gadget for one aggregate. |
| `ClaimPublicationProof` / `prove_claim_publication` | Shared adapter proof and its constructor. |
| `RewardLedgerFinalProof`, `final_proof`, `final_state`, `ledger_final_user_root` | The window's closing ledger state, its proof, and its user tree root. |
| `reward_inclusion`, `reward_session`, `reward_aggregate` | Aggregate manager fields, one per sub-module. |
| `RewardPayoutSlot` | One of 4 payout slots in `RewardInclusionChunkCircuit`: session proof, ledger state, source checkpoint, and payout leaf. Not a slot of the final adapter. |
| `constrain_reward_payout` | Circuit constraint for one `RewardPayoutSlot` in `aggregate.rs`. |
| `REWARD_AGGREGATE_NODE_PI_LEN` | Internal node width, 131 fields. Family 13, variant 3, levels 0 through 8. Not `AGGREGATE_PI_LEN` and not the 34-field session statement. |
| `RewardInclusionChunkCircuit` | Level-0 circuit. Exactly 4 slots and one owned shared `dummy_proof` target. Proves one internal range, including an empty or partial range. Not an external segment. |
| `RewardInclusionCombineCircuit` | One combine level from 1 through 8. Both children use the constant verifier of descriptor `level-1`. No dummy business child and no skip flag. |
| `REWARD_CHUNK_ABSORB_CALLS` | The fixed count of bounded Keccak appends in one reward chunk, `ceil(S * SOURCE_CHECKPOINT_REWARD_LEAF_BYTES / 136)`, where `S` is `REWARD_CHUNK_SLOTS`. |
| `RewardAggregateNodeTargets` | The 131-field node statement: shared bindings, range, boundary users, claim subtree root, and incoming plus outgoing Keccak streams. |
| `dummy_proof` | Chunk-owned shared proof target. Every chunk witness assigns the unmodified genuine auxiliary dummy proof, including a full chunk. Inactive slot targets are separate and are not this target. |
| `registrations` | On the reward adapter, the nine internal descriptors. On `AggregateCircuits`, the sorted closed registry: nine rows currently and ten after `(14,0,1)` is added. Identity fingerprints stay `[0; 4]`. |

Payout leaf and registry:

| Name | Meaning |
|---|---|
| `source_checkpoint_reward_leaf_commit` | Keccak commit of one payout leaf under `PsyBridge/SourceCheckpointReward/1/Leaf`. |
| `SourceCheckpointRewardOpening.leaves` | The opening's payout leaves. |
| `CircuitSetRegistration`, `circuit_set_registration`, `build_registrations`, `validate_registrations`, `registrations` | One registered circuit triplet and its registry operations. |
| `build_circuit_set_registrations` | Sequential registration-only construction. It returns the same sorted closed set as the full bundle. |
| `CIRCUIT_SET_FAMILIES` | Ten-row registry, including the source width field: `(11,0,1,0), (14,0,0,90), (14,0,1,22), (15,0,0,30), (16,0,0,1029), (17,0,0,2574), (18,0,0,3846), (19,0,1,0), (19,0,2,0), (20,0,0)`. A zero marker means the width helper derives the configured-chain width. Family 16 business width is `1+32*30=961`; 1029 includes the cap-height-4 suffix. Family 20 is `8316+128*C`. Families 14 and 15 remain occupied. Wire version stays 2. Gate4 regenerates the hashes. [user-ruling: `mem_lo_hi_removed_2026_10_11`] |

Domain strings: `PsyRewardJobs/Session/1`, `PsyRewardSession/Summary/1`, `PsyRewardLedger/{State,Window,Verifier,Node,Empty,Issued,Proof}/1`, `PsyBridge/SourceCheckpointReward/1/Leaf`.

### Selected deposit-child schema

The selected child statement uses prefix `[3,11,1,0]` and deletes exactly the eight `window_id` fields. Its width is `deposit_aggregate_pi_len` above. The external opening remains version 4. Current prefix `[2,11,1,0]` and the current native window field are pre-cutover descriptions, not the target schema. Frozen cryptographic labels do not change in this schema cutover.
