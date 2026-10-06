# Bridge Merkle Settlement

> Date: 2026-10-06. Status: **Normative one-session credit contract — not implementation-ready and not activated**. `RewardSessionStatement` is the session public-input statement. One credit and one full payment exist per `(economic_domain, source_checkpoint_id, user_id)`. A reward session is local to that triple: its job nullifier is temporary across that session's steps and is not a persistent per-job bitmap. There is no balance carry, debit, ticket registry, seventh checkpoint root, or global persistent job-nullifier root. `RewardSessionCircuit` in `reward_session.rs` is the exported session constructor. No measurement, activation, migration, or independent approval is claimed.

## Terminology and Abbreviations

`TERMINOLOGY.md` owns spellings. This document owns the settlement contract. A source citation describes existing behavior; a **proposed** declaration specifies the replacement and is not a claim that the declaration exists.

| Term | Definition |
|---|---|
| PI | Circuit public input. Offsets below are zero-based, half-open. |
| Felt / Hash4 | Goldilocks field element / four ordered canonical field elements; modulus `p=18446744069414584321`. |
| L1 / L2 | Destination settlement chain / Psy execution chain. |
| ABI / API | Application binary interface / application programming interface. |
| CLI / WASM | Command-line interface / WebAssembly user proving surface. |
| HTTP / RPC / JSON | Hypertext Transfer Protocol / remote procedure call / JavaScript Object Notation. |
| QA / OOG | Quality assurance / out-of-gas. |
| SHA-256 | Retained-artifact byte digest, not proof authority. |
| BN254 | Groth16 scalar field; packed public values here are uint128 and fit it. |
| `B,d,N,K,C,D` | Inclusion capacity, its base-two depth, family leaf count, segment count, configured chain count, deposit leaf count. |
| `K_w,K_r` | Withdrawal and reward segments accepted in one publication transaction. |
| `AggregateWindow` | Process-local config, window, and authenticated endpoint context; not a wire object. |
| `opening_digest` | Hash of the artifact's precisely specified opening preimage. Not `header_digest`. |
| `header_digest` | Hash of the packed publication header under its separate domain. |
| `claim_tree_root` | Keccak payout-membership root of one inclusion segment. |
| `historical_merkle_proof` | Checkpoint-leaf membership under the selected checkpoint-tree root; not a checkpoint-header upgrade. |
| `nullifier_key` | Private session-local birth coordinate of one included job. Not a public input and not an L1 consumption key. |
| Reward session | One proof chain for one `(economic_domain, source_checkpoint_id, user_id)`, proved by `RewardSessionCircuit`. Its job root is private and is committed through the session state carried by the verified predecessor. |
| `k` | Benchmark-selected maximum real jobs per same-kind user step; not a cap on how many source checkpoints a user may credit over time. |
| `W` | The session's checked full sum. It is the payout leaf amount. It is not a partial prefix, a balance, or a debit. |
| Omitted job | A job born at the credited source and owned by the user that this session does not include. The user accepts that omission; it is forfeited and cannot be credited later. |

## Abstract

One user proof credits exactly one `(economic_domain, source_checkpoint_id, user_id)` session. Its checked amount `W` and count are the full sum and count of the jobs the user chose to include. Jobs omitted from that session are forfeited. `RewardInclusionAggregateCircuit` verifies one final `RewardSessionCircuit` proof per user, and its Groth16 wrapper publishes the payout root. These are exactly three circuit kinds, not a fixed proof depth. `WithdrawalInclusionAggregateCircuit` remains a separate pipeline. The payout leaf uses a Keccak path, with neither user Groth16 nor signatures. The session nullifier prevents the same included job from being summed twice inside that session. It is discarded with the session and is not a second payment ledger. The existing deployed payer remains the per-job payer until the source-user key replaces it.

## Motivation

The current `StateManager.applyBridgeWindow` verifies then iterates complete withdrawal/reward openings (`psy-contracts/src/StateManager.sol:205-253`). `EthereumRewardPayer.payRewards` pays `REWARD_PER_CLAIM` once per `RewardLeaf` and consumes `spentRewards[keccak256(abi.encode(rewardNullifierDomain, claimCheckpointId, nullifierIndex))]` (`psy-contracts/src/EthereumRewardPayer.sol:46-95`). That is a persistent per-job key, not one key per source and user. Inclusion publication is `WithdrawalInclusionAggregateCircuit` and `RewardInclusionAggregateCircuit`, both registering `AGGREGATE_PI_LEN` (`inclusion_aggregate.rs`). A large publication therefore requires segmentation and pull delivery rather than a larger on-chain payout loop. `PQEDCheckpointGlobalStateRoots` stays six roots.

## Table of Contents

- [Specification](#specification)
  - [1. Scope and flow](#1-scope-and-flow)
  - [2. Proof topology and public inputs](#2-proof-topology-and-public-inputs)
  - [3. One-session credit relation](#3-one-session-credit-relation)
  - [4. Canonical encoding and claim trees](#4-canonical-encoding-and-claim-trees)
  - [5. Finalize and deposit authentication](#5-finalize-and-deposit-authentication)
  - [6. Publication and delivery](#6-publication-and-delivery)
  - [7. Retention and recovery](#7-retention-and-recovery)
  - [8. Acceptance and resource bounds](#8-acceptance-and-resource-bounds)
- [Data Structures](#data-structures)
- [Core Functions](#core-functions)
- [Core Loops](#core-loops)
- [Module Changes](#module-changes)
- [File Changes](#file-changes)
- [Naming Crosswalk](#naming-crosswalk)
- [Rationale](#rationale)
- [Security Considerations](#security-considerations)
- [Review and Activation Boundary](#review-and-activation-boundary)

## Specification

### 1. Scope and flow

```mermaid
sequenceDiagram
    participant User
    participant Service
    participant Relayer
    participant Manager
    participant Payer
    User->>User: 1. Accumulate jobs using self-recursive user proofs
    User->>Service: 2. HTTP submit proof and payout leaf
    Relayer->>Service: 3. HTTP retain canonical openings and paths
    Relayer->>Relayer: 4. Verify user proofs and prove reward inclusion aggregate
    Relayer->>Manager: 5. RPC publish Groth16, headers, boundaries and finalize evidence
    Manager->>Manager: 6. Verify all evidence and atomically save roots
    User->>Payer: 7. RPC claimReward with leaf and Keccak path
    Payer->>Manager: 8. Read published claim_tree_root
    Payer-->>User: 9. Transfer the leaf amount once for that source and user
```

```text
reward:     user circuit -> reward inclusion_aggregate -> Groth16 wrap -> root registry
withdrawal: withdrawal proof -> withdrawal inclusion_aggregate -> its Groth16 wrap -> root registry
checkpoint: authenticated contiguous transitions -> finalize -> its Groth16 wrap ----+
deposit:    complete configured-chain deposit transition -> its Groth16 wrap --------+
claim:      leaf + Keccak siblings -> published root -> replay/accounting checks -> transfer
```

The user owns user proving. The aggregator verifies, aggregates and wraps; it does not generate user proofs. Guardian signing policy belongs exclusively to `bridge-relayer-multisig.md` and is unchanged. User L1 claims never call a verifier or accept signatures. Publication is proposer-only and requires Groth16 evidence.

Withdrawal preserves nonce replay, pending delay, threshold, lifetime limits, pause and force-claim behavior. Pull registration starts the delay when the pull is registered, not when its root is published; this timing change is explicit and requires product approval before deployment. Reward funding is checked at pull time, with no publication-time reserve of future source-checkpoint claims. Insufficient funding reverts only that claim and leaves it claimable. Neither policy is presented as behavior-preserving.

### 2. Proof topology and public inputs

**Required topology: exactly three circuit kinds.** Kind one is the self-recursive credit session, kind two is reward inclusion aggregation of one terminal proof per user, and kind three is its Groth16 wrapper. A user step directly constrains at most compiled `k` newly included jobs, source membership, the checked sum of those jobs, recipient binding, the rolling jobs commitment, and that session's nullifier transition. It recursively verifies the same-kind own-user predecessor and, when users interleave, the same-kind global predecessor. Depth is data-dependent, `ceil(included_job_count/k)` user steps; it is not three layers. `k` remains a benchmark-selected circuit capacity, not a lifetime, job, or checkpoint limit and not an extra circuit kind. No distinct per-job circuit, closing circuit, four signature circuits, balance circuit, debit circuit, or ticket registry is added.

Withdrawal construction and reward construction have distinct constructors, witnesses, circuits, setup identities and runtime paths. Shared pure canonical tree/encoding helpers are allowed only for identical semantics. The rejected alternative is one family-generic circuit whose runtime selector merges withdrawal and reward relations: it weakens ownership, couples fingerprints and leaves family-specific constraints implicit. A common publication envelope does not merge the proof pipelines.

#### User statement: exactly 34 fields

| Offset | Field | Role in this reward session |
|---|---|---|
| `[0..4)` | `checkpoint_tree_root` | Publication-end checkpoint-tree root. Four canonical Felt limbs in hash order. It authenticates the source checkpoint. It is not a free hash and not a seventh earned-state root. |
| `[4]` | `user_id` | u32 identity of the one user credited by this session. |
| `[5..13)` | `recipient` | Eight u32 limbs, least-significant limb first. Limbs 5, 6, and 7 are zero. The low five are the 160-bit recipient. The payout address is those five big-endian words in reverse limb order: limb 4, then 3, then 2, then 1, then 0. |
| `[13..21)` | `total_amount` | Eight u32 limbs, least-significant limb first. Checked running sum of jobs included in this session, starting at zero. The terminal value is `W`, the full payout amount. Not a balance, a debit, a lifetime total, or a delta from another source. |
| `[21]` | `count` | u32 count of jobs included in this session, starting at zero. Checked recursive addition. The finite statement range is not an unbounded integer. |
| `[22..26)` | `jobs_commitment` | Four canonical Felt limbs. The base is the session seed. Each step rolls the linear Poseidon sponge specified below. |
| `[26..30)` | `old_ledger_state_root` | Four canonical Felt limbs of the previous composite ledger-state root in `RewardSessionStatement`. The composite is the ledger window, ledger root, user root, session count, and unfinished session count. It is not the private session root. This slot equals the old state root on every step. The first step of a window binds it to that window's `start_root`. The first economic-domain window uses `origin_state_root()`. A later window uses the previous window's published `new_ledger_state_root`. This slot is not a publication public input. |
| `[30..34)` | `new_ledger_state_root` | Four canonical Felt limbs of the next composite ledger-state root in `RewardSessionStatement`. A later global predecessor's `[30..34)` equals this step's `[26..30)`. This slot is not a publication public input. |

The fields are one `RewardSessionStatement`. They do not also carry a balance, a debit amount, or a ticket count. Credit amount and payment amount are the same terminal `W`; no second amount slot reuses these offsets. All integer ranges are constrained by the session relation, not merely decoded natively. Addition uses eight u32 limbs with checked carries and final carry zero; overflow rejects. No Felt reduction or one-Felt amount remains. For amount `2^32+7`, limbs are `[7,1,0,0,0,0,0,0]`. This statement does not alter `AGGREGATE_PI_LEN`, the per-job source, the withdrawal child, or the finalize layout.

#### Publication, deposit and finalize statements

Inclusion publication has `AGGREGATE_PI_LEN` fields: `[1,7,family,0]`, then `opening_digest`, `claim_tree_root`, and `header_digest`, each digest split into eight big-endian u32 words. Family 2 is withdrawal; family 3 is reward. The wrapper emits 768 most-significant-bit-first bits, packed in order as six uint128 values: high then low half of each digest. The session statement is recursively verified inside `RewardInclusionAggregateCircuit`, not passed to the L1 verifier.

Deposit keeps prefix `[1,11,1,0]`, its own input width, 256 wrapper bits, and two uint128 halves. Finalize retains `26+9*C` inputs and its separate wrapper. Its retained 26-word prefix is not its full width. `WithdrawalInclusionAggregateCircuit` and `RewardInclusionAggregateCircuit` both register `AGGREGATE_PI_LEN` before build (`inclusion_aggregate.rs`).

`B` is exactly one of 1024, 2048, 4096 and 8192; initial compiled capacity is 1024. Count range uses `log2(B)+1` bits. The pure tree helper supports powers of two from 1 through 131072, including empty sibling paths at capacity 1; production circuits remain limited to the four listed capacities. A helper's larger range does not authorize another production setup.

`verify_reward_ledger_step` (`reward_ledger.rs`) checks one `RewardLedgerStep` against `expected_old_root`. That argument is the store's locked trusted baseline, not a caller-selected root. Section 6 states the window baseline. `reward_ledger_proof_id` is `SHA-256(UTF8("PsyRewardLedger/Proof/1") || complete user-verifier Hash4 as canonical little-endian u64 limbs || canonical proof bytes)`. It is not a Poseidon hash. The label is unfrozen. The ordinary old-state hash already binds the opening, including the origin state. The remaining gap is first-window initialization and publication of `origin_state_root()`, not another host check.

### 3. One-session credit relation

One credit proving session belongs to exactly one `(economic_domain, source_checkpoint_id, user_id)`. Its base is amount zero, count zero, and the session seed. Each included job adds its authenticated amount and one to the count. The terminal amount is `W`, and the terminal count is the number of included jobs. The payout leaf amount equals that same `W`. There is no earlier balance, no debit, no ticket, and no residual amount. A job omitted from the session is forfeited: the user accepted that omission, and no later session for the same triple can include it.

The session root is private. It starts at the canonical empty root on the first own step. Every later own step carries it inside `reward_session_summary` under `PsyRewardSession/Summary/1`, not in public PI `[26..34)`. It is never reset inside the session and never stored as a global per-job bitmap. The public roots are the composite ledger-state roots. Closing the session does not preserve the private job bits. Replay of the credit is the reward-ledger occupancy leaf plus the separate payout boolean, not either public root.

#### Session-local job identity

```text
source        = source_checkpoint_id                 u32
level         = height                               2..=21
index         = path_index                           0 <= index < 2^(level-2)
nullifier_key = (source << 31) | (level << 26) | index
```

Bits 0..25 hold index, 26..30 level, and 31..62 source; bit 63 is zero. The source is fixed by the session, so equal keys name the same job coordinate inside that session. `RewardSessionCircuit` uses this key as the index of a private zero-to-one transition (`reward_session.rs`). The old leaf value is the zero hash and the new leaf value is `[1,0,0,0]`. An inactive slot does not update the private root and contributes zero. A repeated key in the session rejects. This private root is not PI `[26..34)` and is not the L1 `spentRewards` key.

Current per-job position checks remain the source of the level and index bounds (`psy_plonky2_circuits/src/bridge/circuits/reward_inclusion.rs:57-92`). A historical source witness contains the source id, the complete source checkpoint leaf, and exactly 32 Poseidon siblings. For each least-significant-first index bit, bit zero hashes `(state,sibling)` and bit one hashes `(sibling,state)`. The resulting root equals PI `[0..4)`. The source id cannot exceed the publication end id. The checkpoint leaf hash is the existing Poseidon global-root/stats hash, and the stats open `pm_rewards_commitment.gutas_root`. This is historical membership, not `HistoricalRootMerkleProofGadget` and not a header upgrade.

Each active job opens the existing tagged-tree relation under that source's `gutas_root`: nonzero tag preimage, first element equal to `user_id`, leaf tag equal to Poseidon of the preimage with itself, and nonzero leaf tag. The tagged-tree order is the order at `reward_inclusion.rs:83-109`. A user-account path is not a substitute. `RewardLeaf` has no amount field (`bridge_aggregate.rs:207-208`). The amount added to `W` is exactly the configured `reward_per_claim`, reversed into eight little-endian u32 limbs (`reward_session.rs`). It is not read from the job leaf. A job born at another source or owned by another user rejects. The recipient is the session recipient, not a per-job amount witness. The recipient must differ from the configured payer.

#### Session seed and rolling commitment

`H(bytes)` is PoseidonHashMany of one canonical field per byte. `reward_session_seed` is `H(UTF8("PsyRewardJobs/Session/1") || economic_domain[32] || LE32(source) || LE32(user_id) || five LE32 recipient limbs || checkpoint_tree_root as four LE64 || source checkpoint leaf hash as four LE64)` (`reward_session.rs`). The base jobs commitment equals this seed. The older checkpoint-seed and O/N leaf-pair preimages are rejected.

`rolling_jobs_commitment` (`reward_session.rs`) has byte prefix `UTF8("PsyRewardJobs/Step/1") || previous commitment as four LE64 || LE32(previous_count) || LE32(step_count) || LE32(new_count)`. Each active job appends one record: source, level, index, nullifier index, owner, eight amount limbs, owner tag, and the activity bytes. Record integers are little-endian. Inactive records are excluded by the activity selector; their padding bytes do not enter the sponge. The hash is a linear Poseidon sponge: bytes are absorbed in chunks, an inactive chunk retains the previous permutation state, and the first four state elements are the commitment.

Own-user recursion carries the same user, recipient, end root, source, and seed. Current amount is the previous amount plus this step's included sum, and current count is the previous count plus this step's included count. Both start at zero. The private session root is authenticated by the predecessor summary below. The public ledger root uses the origin relation below (`reward_session.rs`).

`first_global` is `!has_global`: the first step of this window, not the first window of the economic domain. The old state root equals statement `[26..30)` on every step, so the ordinary state hash binds the opening. The first step of a window binds that slot to the trusted `start_root`. The first economic-domain `start_root` is `origin_state_root()`, the fixed protocol Poseidon hash of the origin state in `bridge_aggregate.rs`. `RewardSessionCircuit::new` calls it. The store must call it when it initializes the first window. It does not call it now, and that initialization is blocked on the configured economic domain. There is no lock. That state uses the existing `RewardLedgerStateValues` fields. `ledger_window_hash` is the zero Hash4. `ledger_root` is 64 levels of Poseidon two-to-one starting from the zero Hash4. `user_root` is the existing 32-level summary tree from `PsyRewardLedger/Empty/1`. Both counts are zero. The hash is not the zero Hash4. A later window does not replace its old opening with the origin state. Its first step resets the working user root and both working counts, then applies the ordinary open and close increments. It does not mutate the previous window's retained opening.

#### Session summary

`reward_session_summary` (`reward_session.rs`) hashes `UTF8("PsyRewardSession/Summary/1") || canonical LE64 of each PI [0..30) || seed as four LE64 || private session root as four LE64 || final-step as one byte`. Each of the public fields is split into low and high u32 values. A high half equal to `u32::MAX` requires its low half to be zero, so the field remains a canonical u64. The first own step connects the private session root to the canonical empty root. A later own step recomputes the predecessor summary with the final-step byte clear and the predecessor's private root, then requires that summary to equal the retained prior summary. A step therefore cannot reset the private root.

#### One closed credit

The terminal statement is publishable only when count is positive, `W` is positive, and the recipient is nonzero. Its payout leaf carries that exact `W`, the same user, the same source, and the same recipient. A partial prefix cannot initialize the occupied credit leaf. There is no balance leaf, no debit proof, and no ticket publication.

#### Global one-credit occupancy

One credit exists for one `(economic_domain, source_checkpoint_id, user_id)`. The economic domain is pinned in the credit-tree context and is not a key limb. The key is a 64-bit string of two u32 limbs, never one Goldilocks target:

```text
path bits 0..32  = user_id, least-significant bit first
path bits 32..64 = source_checkpoint_id, least-significant bit first
```

These are the 64 least-significant Merkle path bits: user, then source. Source fits in a u32. Packing `(source<<32)|user` into one field element is rejected. Some of those u64 values are at least the Goldilocks modulus `p=18446744069414584321`, so they are not distinct canonical field elements. This key adds no public input. The 34-field width stays unchanged.

The canonical empty leaf is the zero Hash4. The occupied value is nonzero and is `PsyRewardLedger/Issued/1`:

```text
H(economic_domain[32] || LE32(source) || LE32(user) || eight LE32 amount limbs || five LE32 recipient limbs || jobs_commitment as four LE64 || window hash as four LE64)
```

`RewardLedgerLeafTargets` (`reward_session.rs`) splits the key into user bits 0..32 and then source bits 32..64. It computes the root of the zero leaf and the root of the occupied value over the same siblings. A final step requires the zero-leaf root to equal the current ledger root and selects the occupied root. A nonfinal step leaves the current root unchanged. The occupied hash is constrained nonzero. Payment, a later window, or a spent payout boolean never clears that leaf. A second final step for the same triple therefore finds the occupied leaf and rejects.

The payout consumption boolean is a separate record. It cannot replace this occupancy proof. The current payer's per-job `spentRewards` key cannot replace it either. These targets are present in `RewardSessionCircuit`. They do not by themselves make the current L1 payer consume this key.

#### What the session statement does not close

Statement fields `[26..30)` and `[30..34)` are the composite ledger-state endpoints of `RewardSessionStatement`: ledger window, ledger root, user root, session count, and unfinished session count (`reward_session.rs`). They are not publication public inputs. Publication is the 28-word schema in `inclusion_aggregate.rs`: prefix `[1,7,family,0]`, then `opening_digest`, `claim_tree_root`, and `header_digest`, each digest as eight big-endian u32 words (`AGGREGATE_PI_LEN`). The statement endpoints are not the private session root and contain no global per-job bitmap. The private session root is carried only by `reward_session_summary`. Statement `[26..30)` equals the old state root on every step. The first step of a window binds it to `start_root`, which is `origin_state_root()` for the first economic-domain window. A later step inside one window binds it to the predecessor's statement `[30..34)`. Statement `[30..34)` is the ordinary hash of the next opening. `RewardSessionCircuit` registers its 34 statement fields. The publication consumer is `RewardInclusionAggregateCircuit`, and the connection from every selected terminal to one publication history remains the interleaved admission gap. That gap does not add a public input, a per-job bitmap, or a payout-boolean substitute.

### 4. Canonical encoding and claim trees

Existing labels retain the exact prefix `PsyBridge/TwoArtifact/1/` and suffixes `Config`, `CircuitSet`, `A`, `Batch`, `Record`, `Leaf`, `Node`, `Empty`, `Window`, `Reward`, `WithdrawalNonce`, `WithdrawalBatch`, and `RewardBatch` (`bridge_aggregate.rs:58-68`). Renaming source types does not rename these bytes. `word(x)` is one 32-byte unsigned big-endian word; upper padding must be zero. Existing word-encoded Hash4 is four such words, each containing a canonical u64 Felt.

Withdrawal opening is the existing ordered context, configured root vector and six-word records: `288+128*C+192*N` bytes. Existing per-job reward opening is `256+192*N` bytes. Its digest is the family domain plus the encoded opening (`inclusion_aggregate.rs:310-321`). A nested reward `batchRoot` digest is not a competing rule. Deposit's distinct projected `A` preimage remains unchanged.

The source-checkpoint reward protocol uses `PsyBridge/SourceCheckpointReward/1/Leaf` for the payout-leaf commit. Opening domain is `keccak256(UTF8("PsyBridge/SourceCheckpointReward/1/Opening"))`. Consumption domain is `keccak256(UTF8("PsyBridge/SourceCheckpointReward/1/Consumption"))`. It does not alias or reinterpret `PsyBridge/CumulativeReward/1/*` or `RewardBatch` bytes. `SourceCheckpointRewardLeaf` is six big-endian 32-byte words: word 0 `economic_domain`; word 1 `source_checkpoint_id` with its high bytes zero; word 2 `user_id`; word 3 `amount`; word 4 `recipient` as a right-aligned address; word 5 `initialized` as 0 or 1. The codec accepts a source id. A payable leaf requires `initialized`.

Packed `header_bytes` contains, in order, `family:u8`, config hash, window id, end id, end root, the segment counters, family-specific roots, opening digest, and claim root. All integers here are big-endian. Withdrawal-specific roots are one Hash4 per configured ordinal. Reward-specific roots are the segment's stated `old_ledger_state_root` and `new_ledger_state_root`. They are not a persistent per-job nullifier and are not chained across windows. No option tag or vector length is encoded. Header domain is `keccak256(UTF8("PsyBridge/TwoArtifact/1/AggregateHeader"))`. Header digest is Keccak of that domain and packed header bytes.

#### Typed Hash4 boundary

A native Hash4 is exactly four canonical u64 values. The alternative circuit transport representation is exactly eight u32 values, adjacent low/high pair for each same u64: `value[i]=pair[2*i]+2^32*pair[2*i+1]`, followed by `<p` validation. A decoder accepts either representation only where the interface explicitly selects `CanonicalU64x4` or `LittleEndianU32x8`; it never tries one after another on failure. User PI roots and packed headers require `CanonicalU64x4`; user amount and recipient are eight little-endian u32 integers, not Hash4. Finalize prefix slots `[4..20)` use the paired-u32 representation; all other finalize root slots use canonical u64 words. Keccak digest words are big-endian u32 and are never interpreted as little-endian Hash4 pairs. Width and encoding selector form part of source/setup identity.

#### Claim tree and segment arithmetic

The claim tree reuses the existing marker-12 Keccak construction (`bridge_aggregate.rs:649-674`) at variable capacity. Let `D(label)` be the preserved label hash above. Real node `i` is `keccak256(D(Leaf)||word(12)||word(count)||word(i)||leaf_commit[i])`; padding node is `keccak256(D(Empty)||word(12)||word(count)||word(i))`. At height `h=1..d`, parent is `keccak256(D(Node)||word(12)||word(h)||left||right)`. Tree storage has `2*B-1` nodes with root index zero and leaves starting at `B-1`. Path length is exactly `d`, ordered leaf-to-root, with ordinal bits least-significant-first.

```text
K = 0 if N=0 else ceil(N/B)
for segment_index in 0..K:
    first_ordinal = segment_index * B
    count = min(B, N-first_ordinal)               strictly positive
```

All operations reject overflow. An empty-family manifest sets all counts and indices to zero and both digests to zero. Empty withdrawal still carries authenticated configured roots. Empty reward repeats its stated ledger-state Hash4 in both slots and registers no root. Empty families supply no proof. Nonempty first manifests are byte-identical to their verified segment-zero headers in the first transaction.

### 5. Finalize and deposit authentication

A real positive-span finalize proof is mandatory for every destination transaction, including continuation. The retained prefix is `[0..4)` start root, `[4..12)` global deposit pair encoding, `[12..20)` global withdrawal pair encoding, `[20..24)` end root, `[24]` end id and `[25]` span. For configured ordinal `o`, `b=26+9*o`: `[b..b+4)` deposit root, `[b+4]` absolute deposit count, `[b+5..b+9)` withdrawal root. Count is checked u32. `C` and ordered chain indices are circuit constants. Full width is `26+9*C` (`bridge_agg_final.rs:63-69`).

Wrapper bytes retain the original 144-byte prefix: indices `[0..4)` and `[20..26)` use big-endian u64; `[4..20)` use big-endian u32 with adjacent pairs swapped. Each extension word appends big-endian u64, including the u32 count. Full length is `144+72*C`. L1 and wrapper require this exact width and hash the same bytes. Zero proof, zero span, bootstrap substitution and an unverified named end root reject.

Generated finalize verifier getter `endpointChainListHash()` is `keccak256(UTF8("PsyBridge/FinalizeChainList/1") || uint16_be(C) || raw ordered chain-index bytes)`. Installation compares it against configured chains. A same-width differently ordered chain list is not an equivalent source.

**Fingerprint prerequisite:** load the cached `GenerateRollupStateTransitionProof` fingerprint as base. Independently obtain the coordinator checkpoint-step fingerprint, then require equality before prebuild, range proving, regeneration or key setup. A missing cached base rejects; copying the coordinator fingerprint into both arguments is not a check. Pass the independently obtained values to their typed base/step positions. The finalize wrapper source carries actual finalizer common/verifier data and the finalizer's configured chain indices; it cannot be assembled from arbitrary same-width metadata. Setup validation compares source, ordered chain list, encoding and width, not width alone. Current relevant callers are `psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs:1028-1029,1108-1112` and `regen_groth16_keystore.rs:294-307`; these references describe the reviewed requirement, not completed runtime evidence.

**Checkpoint machine is separate from the three reward circuit kinds.** Current Final verifies Chain, appends 1..32 deltas, binds the chain hash to the final checkpoint proof and checks exact span (`bridge_agg_final.rs:194-319,371-374,584-634`). A proposed direct Final path is selected only when the complete checkpoint interval has span 1..32: start from authenticated start, verify every consecutive transition and final checkpoint proof, and omit the empty Chain-prefix proof. Above 32, retain the complete Chain-prefix relation and terminal Final deltas. Reward segment count or `N<=B` does not establish checkpoint span. Removing Chain validation without the direct replacement is forbidden and is not justified by the reward kind count.

Deposit aggregate remains mandatory and authenticates every configured chain's old/new deposit root and absolute count. StateManager joins each new endpoint to the matching finalize extension and joins every withdrawal-root vector to the same extension. Deposit application remains restricted to StateManager, verifies no proof itself, and preserves local custody, pending-count and transition checks. It accepts exact end-state no-op on continuation. Neither a root name nor the reserved `withdrawalSubtreeRoot` storage is withdrawal authority.

Withdrawal root witness remains private: configured ordinal u8 and exactly eight Poseidon siblings select one root from the authenticated ordered C-root vector through the height-eight lookup padded to256. Require `1<=C<=256`, exact configured membership, canonical limbs and no trailing opening bytes. No path is serialized in a withdrawal record and no additional setup is introduced. Strict opening order is `(chain_index,nonce)`; foreign-chain records never create local nonce consumption. Current source witness is `inclusion_aggregate.rs:38-49,281-307`.

Identity replay reuses the real positive-span proof, requires end id/root equal stored cursor and opening end, but does not require historical start root equal current end. It performs all endpoint joins and no cursor advance or `Finalized` emission. No previous-anchor or historical-success mapping is added.

### 6. Publication and delivery

The complete proposed publication ABI is:

```solidity
struct InclusionSegment {
    bytes headerBytes;
    uint256[8] proof;
    bytes firstLeafBytes;
    bytes32[] firstSiblings;
    bytes lastLeafBytes;
    bytes32[] lastSiblings;
}
function applyBridgeWindow(
    uint256[8] calldata finalizeProof,
    uint256[] calldata checkpointPublicInputs,
    uint256[8] calldata depositProof,
    bytes calldata depositOpening,
    bytes calldata withdrawalManifest,
    bytes calldata rewardManifest,
    InclusionSegment[] calldata withdrawalSegments,
    InclusionSegment[] calldata rewardSegments
) external;
function claimReward(bytes32 headerDigest, uint32 ordinal,
    bytes calldata leafBytes, bytes32[] calldata siblings) external;
function claimAggregateWithdrawal(bytes32 headerDigest, uint32 ordinal,
    bytes calldata leafBytes, bytes32[] calldata siblings) external;
```

This replaces the current full-opening withdrawal/reward publication parameters; it is not the current source ABI. Both claim implementations use `nonReentrant`; publication remains `onlyProposer`. Calldata arrays are bounded by compiled family counts and preflight; no arbitrary fixed two-to-four segment cap is introduced. Full openings remain off chain except the complete deposit opening. First/last witnesses are required even for a one-leaf segment and then must encode the same leaf/path.

Publication order is authorization and canonical decoding; manifests and segment/boundary validation; new-window or continuation predicate; finalize and deposit verification; per-segment Groth16 verification; then atomic deposit, registry, progress, and cursor writes. Any failure reverts the entire transaction. No transfer and no consumption-key write occurs during publication. Publication does not write a persistent job-nullifier root.

StateManager's registry unique key is `(config_hash,window_id,family,segment_index)`, with lookup by `header_digest`. New segments are consecutive per family. First and last paths use ordinals 0 and `count-1`. The previous segment's last boundary is strictly less than the next segment's first boundary. The withdrawal boundary is `(chain_index,nonce)`. The reward boundary is `user_id`, matching `ActiveWindow.rewardLastUserId`. It is not `(source_checkpoint_id,user_id)`, because that order would accept the same user twice when the source changed. The occupancy key remains `(economic_domain,source_checkpoint_id,user_id)` and is not this ordering key. Circuit sorting is internal. Identical saved-header retries are no-ops and conflicting retries revert. A reward header's two Hash4 slots bind that segment's stated admission-state endpoints. They are not the private session root, not a stored global job bitmap, and not chained from a previous window. Stale unpublished proofs return to the user for reproving. No root is edited outside a new proof.

The first transaction contains both manifests and verified segment zero for every nonempty family. It advances the checkpoint cursor once. Continuation requires identical window, end, and deposit digest, plus family common fields `(family,B,total_count,segment_count,withdrawal_roots)`. Its current cursor equals the active end and finalize is identity replay. A new window rejects until all required segments of both families are accepted. The next window's `start_root` is the previous window's published and verified `new_ledger_state_root`. The first window of an economic domain starts at `origin_state_root()`, the fixed protocol Poseidon hash of the origin state. `RewardSessionCircuit::new` calls that function. The store must call it for first-window initialization. It does not call it now, and that initialization is blocked on the configured economic domain. There is no lock. The value is not the zero Hash4 and not a store choice. Until rule 24 freezes the domain labels, changing this unfrozen value has no artifact cost. The old state root equals statement `[26..30)` on every step, so the ordinary hash already binds that opening. The remaining gap is initializing and publishing the first window at that hash. The host's locked baseline equals `start_root` on the first step of a window. Empty-window completion is immediate after mandatory finalize and deposit checks. Progress is per destination; a successful receipt on one chain is not another chain's acceptance.

#### Continuity without a persistent job root

| Check | Required relation | What it does not establish |
|---|---|---|
| Own session step | The private session root starts empty on the first own step. A later own step authenticates it through `reward_session_summary`, with amount, count, and jobs commitment. | It does not put that private root in public PI `[26..34)` and does not persist its job bits after the session closes. |
| Interleaved admission | A global predecessor orders steps from different sessions. The ledger-state connection in section 3 is the required relation when that ordering is used. | Current targets do not yet connect every selected terminal to one history. That is an integration gap, not a persistent-root requirement. |
| Segment publication | The segment index is the next consecutive index, or the saved header bytes are identical on retry. The Groth16 statement binds this header and opening. | It does not repair an unconnected admission history by storing a nullifier cursor. |

Current `StateManager.sol:205-253` has no reward-admission-root registry. The following is **design pseudocode**, not an existing implementation:

```text
applyBridgeWindow, for each supplied reward segment in canonical segment order:
    decode the typed reward header; recompute its exact header_digest
    require configured config, active window, reward family and authenticated end
    key = (config_hash, window_id, family, segment_index)
    if key is already registered:
        require supplied canonical headerBytes equals retained headerBytes byte-for-byte
        accept this segment as an idempotent retry
        do not increment the segment counter
        continue to the next supplied segment
    require segment_index equals nextRewardSegment
    if segment_index != 0:
        require segment_index - 1 is registered for this config, window and family
    verify the reward Groth16 statement binds this exact header, opening and claim root
    stage this headerBytes once
    stage nextRewardSegment = segment_index + 1
after every required proof, endpoint join, boundary check and deposit effect succeeds:
    commit all staged registry, counter and other window writes atomically
on any failure:
    revert every write in this transaction
```

`nextRewardSegment` denotes `ActiveWindow.rewardAccepted`. Canonical `headerBytes` is the sole retained header authority. No ledger-root cursor is stored beside it. This pseudocode does not make the payer consume the source-and-user key.

#### Existing payer key, stated rather than replaced

`EthereumRewardPayer.payRewards` currently consumes one boolean per job:

```text
spentRewards[keccak256(abi.encode(
    rewardNullifierDomain, claimCheckpointId, nullifierIndex))]
```

`rewardNullifierDomain` is `keccak256(abi.encode(keccak256("PsyBridge/TwoArtifact/1/Reward"), uint256(1), networkMagic, uint32(524288), chainId, ethereumIndex, payer, rewardToken))` (`EthereumRewardPayer.sol:46-81`). Each consumed leaf pays immutable `REWARD_PER_CLAIM`, not a summed `W`. `Bridge.claimedNullifiers[nonce]` is the withdrawal mapping and is unrelated. Neither mapping is a source-and-user key. Preserving already-written keys does not make those keys equal the proposed key, and this document does not change the Solidity key.

The proposed one-session key remains `keccak256(abi.encode(consumption_domain, economic_domain, uint256(source_checkpoint_id), uint256(user_id)))`. Using it on the current payer would be a different replay identity. No migration, key rewrite, or one-line substitution is claimed. Publication under either identity never transfers a reward by itself.

A proposed reward claim loads the published reward-family record, checks config and domain, decodes the 192-byte leaf, and requires `initialized=1`, `ordinal<count`, the exact path, and the bound recipient. It transfers `amount`, which the credit relation requires to equal `W`, once. If the proposed consumption key is already set, it rejects before transfer. The payer balance must decrease by `amount`, the recipient balance must increase by `amount`, and total supply must stay unchanged. Any transfer failure reverts the key write. There is no `paid_total`, no subtraction from an earlier balance, and no residual. Anyone can relay a claim; funds go only to the leaf recipient. This claim is not implemented by `payRewards`. Only configured Ethereum pays rewards; other destinations authenticate the published root and do not transfer the reward token.

Withdrawal claim loads the withdrawal registry entry, checks domain/config, six-word leaf, local chain and path, then enters existing nonce/pending/payment code. A consumed nonce rejects that claim. Publishing a root does not consume local or foreign nonces. The unchanged delay/threshold/force-claim logic stays at `Bridge.sol:643-670`; its explicit pull-time registration change remains an activation prerequisite.

Events are `InclusionAggregateRootPublished(bytes32 indexed headerDigest,uint8 indexed family,bytes32 indexed windowId,uint32 segmentIndex,bytes32 claimTreeRoot,uint32 count,uint64 endCheckpointId)` and `SourceCheckpointRewardPaid(bytes32 indexed headerDigest,uint256 indexed userId,address indexed recipient,uint64 sourceCheckpointId,uint256 amount)`. Existing `Finalized`, `WithdrawalPendingCreated`, and `WithdrawalClaimed` retain their own meanings. Root publication is never a payment event. There is no cumulative-payment event.

### 7. Retention and recovery

Before broadcast, the relayer retains canonical header/opening bytes, user-proof references, aggregate proof, complete deposit proof/opening, destination finalize evidence, ordered leaf associations, and submission state. Files are addressed by SHA-256 and a repeated digest must identify identical bytes. Missing bytes, mismatch or noncanonical encoding returns unavailable; never substitute an empty path or a changed root. Existing durable installation uses temporary file, file synchronization, rename and parent-directory synchronization (`psy_cli/psy_relayer_cli/src/bridge/daemon.rs:1817-1919`). A failed save prevents broadcast.

For each destination and exact frozen transaction: `NotSent -> Sending` is durably saved before signing/broadcast; returned transaction hash produces durable `Submitted`. A crash or send timeout after `Sending` leaves `Sending`. Missing receipt, mempool absence and operator assertion never reset it to `NotSent`. Resolve only with finalized receipt bound to chain, sender, nonce and exact calldata, canonical block hash and expected logs/state. If the hash was lost, retain evidence for manual investigation, not automatic resend. Existing source states and observation are at `daemon.rs:1338-1378,1433-1459,1633-1667`.

A reverted transaction rolls back all root/cursor effects in that transaction. It does not roll back already finalized earlier segments. Resume only at the next canonical segment/root. A reorganization rebuilds service projections from canonical receipts and state; it does not delete retained artifacts or erase canonical consumption. Projection names are `included`, `root_published`, `withdrawal_pending`, `paid`, `consumed_elsewhere`.

The proposed service endpoint is `POST /v1/bridge/inclusion-aggregates`. Required JSON shapes are defined below; unknown fields reject. Hex bytes are lowercase, `0x`-prefixed and even length; `Hex32` is exactly 32 bytes; u64 values are decimal strings and u32 values JSON integers.

```text
Receipt = {chain_id: Hex32, transaction_hash: Hex32, block_hash: Hex32,
           block_number: decimal_u64, log_index: u32}
IncludeAggregate = {kind: "include", header_bytes: HexBytes, opening_bytes: HexBytes}
ReplaceAggregate = {kind: "replace", previous_header_digest: Hex32,
                    header_bytes: HexBytes, opening_bytes: HexBytes}
ObservePublication = {kind: "publication", header_digest: Hex32, receipt: Receipt}
ObserveClaim = {kind: "claim", header_digest: Hex32, ordinal: u32, receipt: Receipt}
AggregateResponse = {header_digest: Hex32, status: "included" | "root_published" |
                     "withdrawal_pending" | "paid" | "consumed_elsewhere"}
ReplacementBlocked = {previous_header_digest: Hex32,
                      reason: "admission_evidence_required" |
                              "changed_membership_not_supported" | "predecessor_published"}
```

Inclusion reconstructs both digests and claim root from retained bytes and creates immutable `(header_digest,ordinal)` associations; retention alone is not publication authority. Receipt evidence is independently fetched and checked for success, emitter, topics, calldata, finalized block and resulting state at that block. Unknown identity returns 404, conflicting/not-yet-included identity 409, unavailable evidence 503. Identical evidence is idempotent.

Replacement is restricted to an exact leaf-identity bijection with unchanged count and segmentation. Lock predecessor and associations, require finalized registry evidence that predecessor is unpublished, verify equality, insert successor and move associations atomically. Retain predecessor bytes. Canonical concurrent predecessor publication wins; reconcile before successor publication. Changed membership returns 409 `changed_membership_not_supported`; absent finalized admission evidence returns `admission_evidence_required`; published predecessor returns `predecessor_published`. This is a deliberate fail-closed supported operation set, not an unspecified recovery mechanism.

Users or services retain source checkpoint witnesses, tagged-job openings, and the session seed inputs needed to reproduce an unfinished session. A new end root replaces checkpoint siblings only. It preserves source, user, recipient, included-job identity, and `W`. An omitted job is not retained as a later entitlement. Published payout leaf and path archives remain sufficient for an L1 claim after publication. Journal retention is not an on-chain authorization condition. No surviving copy means unavailable data, not a failed valid path.

### 8. Acceptance and resource bounds

| Capacity `B` | Depth | Segments for 100,000 users | Last segment count | Retained reward opening bytes |
|---:|---:|---:|---:|---:|
| 1024 | 10 | 98 | 672 | 16,025,088 |
| 2048 | 11 | 49 | 1696 | 16,012,544 |
| 4096 | 12 | 25 | 1696 | 16,006,400 |
| 8192 | 13 | 13 | 1696 | 16,003,328 |

Bytes are `192*N+256*K`, off chain, using the 192-byte source-checkpoint leaf. Raw publication proof plus header bytes are `K_w*(449+32*C)+K_r*513`; both manifests add `450+32*C`. Each new segment also includes two boundary leaf/path witnesses: withdrawal `384+64*log2(B)`, reward `384+64*log2(B)` bytes before ABI framing. Include actual ABI offsets, padding, finalize inputs, deposit opening, transaction intrinsic costs, storage, and logs in receipts. These formulas alone are not a gas result. Publication work includes `O(K_w*C+C+D+(K_w+K_r)*log(B))`. Pull verifies `log2(B)` Keccak levels and zero Groth16 calls.

`max_deposits<=1024`, `max_withdrawals<=131072`, `max_rewards<=131072`, with target deployment reward limit 100000. All codec, circuit and Solidity checks change together. These changes invalidate config-dependent fingerprints/setups. Transaction segment count is selected by preflight within the full gas/calldata budget; no deployment segment limit is inferred without receipts.

Required unexecuted QA:

1. Exact 34-user offsets, all u32 ranges, canonical Felt decoding, uint256 carry and overflow, and recipient upper zeros. Distinguish publication 28 and finalize `26+9*C`.
2. Exactly three reward circuit kinds on the actual construction path. Same-kind self-recursion has data-dependent depth and benchmark-selected `k`. No hidden debit, ticket, or fourth authorization circuit. Terminal authorization reuses the selected existing primitives. Separate withdrawal and reward setup identities.
3. One session per `(economic_domain,source_checkpoint_id,user_id)`, base zero and seed, checked `W` and count, private session-local zero-to-one job keys, public composite ledger-state roots, omitted-job forfeiture, and no persisted job root. Wrong source, owner, recipient, or repeated key rejects. Final-step authorization binds chain digest, recipient, source, amount, count, and jobs commitment. The ledger-history connection and the unfrozen gadget composition are reported, not treated as passed.
4. Cross-language opening, header, tree, and digest vectors; C=1 and C=256; counts 0, 1, B-1, B, and B+1; helper depths 0 and 17 accepted, 18 rejected; production widths exactly four.
5. Real-proof acceptance and zero or wrong-proof rejection; cached-base and coordinator fingerprint mismatch before any setup; same-width wrong chain-list or type rejection; direct span 1 and 32 and chained 33 boundaries with every checkpoint transition authenticated.
6. Atomic publication rollback, identity replay, duplicate or conflicting segment retry, incomplete-window blocking, empty manifests, inter-segment sorting, mixed-family continuation, canonical reorganization recovery, and indeterminate Sending retention.
7. One full `W` payment, unchanged recipient, one boolean consumption key, insufficient reserve, exact token deltas, no verifier or signature call in the claim, and unchanged withdrawal nonce and delay behavior. The current per-job `spentRewards` key is reported as a mismatch, not silently converted.
8. Keep `testFullCapacityWithdrawalAggregate`'s 30,000,000-gas fixture (`psy-contracts/test/foundry/BridgeOpening.t.sol:131-147`) and report its actual success or OOG. Independently require actual complete publication receipts with `gasUsed<=8,000,000`, including maximum configured C/D, both families, first and continuation windows, boundary witnesses and all verification/deposit effects. A reward-only or mock-verifier receipt does not qualify mixed deployment. 50,000 pull gas remains an unmeasured target.
9. Serial construction/proving/wrapping at N=1 and maximum compiled occupancy for withdrawal/reward plus configured deposit aggregate: MemoryHigh 56 GiB, MemoryMax 64 GiB, SwapMax 0, Rayon 1. Measure inclusion widths and same-kind user step capacities `k`; report depth separately from circuit-kind count. Bound failure returns to design, not silent topology or lifetime-cap changes.

Record exact artifact hashes, verifier identities, B/C/D/counts/proof counts, calldata, receipt status, transaction/block hashes, gas and resource observations. This documentation task executes none of them. Historical mock-verifier regressions are not evidence for this proposed protocol.

## Data Structures

The proposed publication types below are complete. Hash4 is `[u64;4]` with each limb `<p`; Bytes32 is `[u8;32]`. Vectors are bounded by the specification, not unbounded protocol inputs.

```rust
pub struct InclusionAggregateHeader {
    pub family: u8,
    pub config_hash: [u8; 32],
    pub window_id: [u8; 32],
    pub end_checkpoint_id: u64,
    pub end_checkpoint_root: [u64; 4],
    pub aggregate_capacity: u32,
    pub total_count: u32,
    pub segment_count: u32,
    pub segment_index: u32,
    pub first_ordinal: u32,
    pub count: u32,
    pub withdrawal_roots: Vec<[u64; 4]>,
    pub old_ledger_state_root: Option<[u64; 4]>,
    pub new_ledger_state_root: Option<[u64; 4]>,
    pub opening_digest: [u8; 32],
    pub claim_tree_root: [u8; 32],
}
pub struct SourceCheckpointRewardLeaf {
    pub economic_domain: [u8; 32],
    pub source_checkpoint_id: u64,
    pub user_id: u32,
    pub amount: [u32; 8],
    pub recipient: [u8; 20],
    pub initialized: bool,
}
pub enum Hash4Encoding { CanonicalU64x4, LittleEndianU32x8 }
```

The relayer creates headers; the respective inclusion circuit constrains every field, StateManager recomputes their hash, and the service retains the bytes. Family 2 requires exactly the configured withdrawal roots and absent ledger-state roots. Family 3 requires no withdrawal roots and both `old_ledger_state_root` and `new_ledger_state_root`. No field is defaulted on decoding. One reward leaf names one source, user, amount, recipient, and `initialized=true`. Another user in the same window may name a different source. The same user cannot appear again in that window with another source. Actual digests are calculated from the canonical bytes.

```solidity
struct InclusionAggregateRoot {
    bytes32 configHash;
    bytes headerBytes;
    bytes32 claimTreeRoot;
    bytes32 openingDigest;
    bytes32 headerDigest;
    uint64 endCheckpointId;
    uint32 count;
    uint32 aggregateCapacity;
    uint8 family;
    bool published;
}
struct ActiveWindow {
    bool initialized;
    bytes32 windowId;
    bytes32 depositOpeningDigest;
    bytes withdrawalManifest;
    bytes rewardManifest;
    bytes32 endCheckpointRoot;
    uint64 endCheckpointId;
    uint32 withdrawalAccepted;
    uint32 rewardAccepted;
    bytes32 withdrawalLastNonce;
    uint8 withdrawalLastChainIndex;
    uint32 rewardLastUserId;
}
```

`inclusionAggregateRoot` returns this struct as a derived lookup, not as a stored mirror. Stored `headerBytes` is the single header authority. `configHash`, `claimTreeRoot`, `openingDigest`, `headerDigest`, `endCheckpointId`, `count`, `aggregateCapacity`, and `family` are derived from those exact bytes on lookup and are not independently stored fields. `published` reports whether that registry key exists; it is not a second header authority.

### Reward relation subsection

#### Source membership, not a seventh root

`PQEDCheckpointGlobalStateRoots` has exactly six hashes and a 192-byte encoding: contract, deposit, user, withdrawal, user registration, and validator (`psy_data/src/v1/qdata/checkpoint.rs:320-327,362-370`). Its hash is the existing six-root hash (`checkpoint.rs:487-493`). This contract does not append a reward-accumulator root, does not define `G7`, and does not store a per-user earned leaf in a checkpoint. The source checkpoint authenticates the tagged reward tree through its existing stats. The publication-end root authenticates that source leaf. No checkpoint transition credits a balance.

#### Session witness

The private witness opens one source checkpoint under the public end root. It carries the economic domain, the source id, the user, the recipient, and the session seed from section 3. Each active slot opens one tagged job born at that source and owned by that user, then updates the session-local height-63 nullifier from zero to occupied at `nullifier_key`. Inactive slots add nothing. Checked eight-limb addition and checked u32 count addition are the only arithmetic. The terminal public amount is `W`.

Current source contains `RewardSessionTargets`, `RewardLedgerStateTargets`, `RewardLedgerWindowTargets`, `RewardPredecessorTargets`, `RewardSessionJobTargets`, and `rolling_jobs_commitment` (`reward_session.rs`). `RewardSessionCircuit` is the exported constructor. The rolling-step function is present. Its presence is not permission to infer a balance or a second amount.

#### Recipient binding

The user chooses the recipient inside that user's own terminal proof. Statement fields `[5..10)` are the five little-endian u32 limbs of the 160-bit address, and `[10..13)` are zero. The 20-byte address is those five limbs as big-endian words in reverse limb order: limb 4, then 3, then 2, then 1, then 0 (`reward_ledger.rs`). Publication inherits that address unchanged, and the relayer cannot rewrite it. L1 pays that address. No contract identifier 7, recipient-storage import, or new signature circuit is allocated.

Recipient binding is not sender authorization. The included job still requires the existing owner-preimage relation: nonzero tag preimage, first element equal to `user_id`, and leaf tag equal to Poseidon of that preimage with itself. A public recipient field alone does not prevent someone who knows the job witness from constructing another proof. That gap is closed only by the terminal authorization below.

#### Terminal authorization

The terminal credit, and only the terminal credit, inlines existing key-possession and signature constraints into the one credit circuit. It does not instantiate `RewardAuthorizationCircuits` and does not recursively verify the old per-job authorization proofs. The selected built-in primitives are exactly four (`agent://MapTerminalIdentityGadgetReuse`):

1. ZK private-key possession through `get_zk_public_key_param` (`software_defined.rs:423-462`).
2. Raw secp256k1 ECDSA through `Secp256K1Gadget::add_virtual_to` (`gadget.rs:227-307`), retaining canonical, nonzero, and low-s checks.
3. Ethereum personal-sign through `add_virtual_to_eth_personal_sign` (`gadget.rs:337-340`).
4. Mutable two-of-three multisig through the existing policy mechanism. Contract identifier 6 and its slot paths stay pinned to that existing mechanism (`MultisigPolicyTargets`, `reward_session.rs`). This is not a new multisig contract.

The identity equation is `PoseidonTwoToOne(pinned_identity_fingerprint, derived_public_key_param) == authorization_user_leaf.public_key`. On a final step, that leaf's user id equals PI `[4]` and every included job owner (`UserAuthTargets`, `reward_session.rs`). The signed preimage is `RewardSessionAuthorization` with config, economic domain, window, source, end, user, checkpoint context, authenticated nonce, jobs commitment, count, amount, and recipient. Recipient alone is not the message. The old `PsyBridge/TwoArtifact/1/RewardAuthorization` message does not bind `jobs_commitment`, amount, or count.

A nonfinal step still supplies the same authenticated end checkpoint leaf, end global roots, and end checkpoint path. It also supplies structurally valid signature padding. Those padding signatures are not authorization. The user-leaf path is bound to the end user root only when `is_final_step` is set (`reward_session.rs`). A nonfinal user path is untrusted and is not account authentication.

Unknown fingerprints fail closed. Software-defined DPN, Plonky2, and SDKey accounts exist in this repository and are not covered by these four built-ins. This contract does not map an unknown fingerprint to the ZK branch and does not claim universal account coverage. Covering one of those accounts requires that account's exact policy relation as another branch of the same credit circuit, not a fourth reward kind. This authorization prevents an unauthorized terminal credit. It does not prevent computation of an intermediate step. A free terminal boolean is not sufficient: terminal status is committed in the authenticated admission state. No review is claimed.

#### One closed consumption key

The proposed payout key is one boolean consumption record:

```text
key = keccak256(abi.encode(
    consumption_domain, economic_domain,
    uint256(source_checkpoint_id), uint256(user_id)))
```

`consumption_domain` is `keccak256(UTF8("PsyBridge/SourceCheckpointReward/1/Consumption"))`. The key contains no job index, no publication window, and no amount. Unset means the full `W` is unpaid. Set means that exact credit was paid. It is never a per-job bitmap and never a balance. This key is a proposed payout identity. It is not the key implemented by the current payer; section 6 states that mismatch.

#### Interleaving gap

Same-kind own recursion carries one session. A global predecessor can order steps from different users, but the current targets do not prove that every selected terminal belongs to one admission history. No wider statement is adopted. This is the same integration gap named in section 3, not a second relation and not a blocker that reintroduces a persistent job root.

#### Retained recovery

Retain the source checkpoint witness, tagged-job openings, session seed inputs, and the terminal proof long enough to reproduce the session. A new end root requires new checkpoint siblings and a new proof. It does not change the source, user, included-job identity, or `W`. There is no balance replay and no seventh-root replay. The existing coordinator write boundary remains `psy_node_common/src/coordinator/processor/db.rs:1228-1277`; this contract does not add reward state to it.

## Core Functions

`WithdrawalInclusionAggregateCircuit::prove` and `RewardInclusionAggregateCircuit::prove` (`inclusion_aggregate.rs`) each call `set_witness` and then the already-built circuit's `prove`. Neither appends inputs after build. `AGGREGATE_PI_LEN` is the shared publication width.

Proposed concrete shared codec functions:

```rust
pub fn build_inclusion_aggregate_tree(
    leaf_commits: &[[u8; 32]], aggregate_capacity: usize,
) -> Result<Vec<[u8; 32]>, BridgeProofError>;
pub fn read_hash4(words: &[u64], encoding: Hash4Encoding)
    -> Result<[u64; 4], BridgeProofError>;
```

`build_inclusion_aggregate_tree` validates power-of-two capacity, depth<=17 and count<=capacity, fills real/padding leaves using section 4, then hashes each parent exactly once from bottom to top; errors use existing `InvalidCount`. Output length is `2*B-1`, root index zero. It has no I/O or proof side effect. `read_hash4` checks selected width 4 or 8, validates u32 halves when selected, reconstructs each limb, checks `<p` and rejects without decoder fallback. Existing `BridgeProofError` and `Result` are at `bridge_aggregate.rs:25-50`.

The section 6 Solidity declarations are the full external source interfaces. `StateManager.applyBridgeWindow` calls canonical header/config/deposit decoders, finalize verification, deposit verification, family-specific inclusion verification and boundary-tree verification, then restricted `Bridge.applyDepositAggregate(bytes)` and registry/progress updates. Preconditions, failure rollback and no-transfer postcondition are section 6. Inclusion verification passes `[openingHigh,openingLow,rootHigh,rootLow,headerHigh,headerLow]` to the proposed interface:

```solidity
interface IInclusionAggregateVerifier {
    function verifyProof(uint256[8] calldata proof, uint256[6] calldata input) external view;
}
function inclusionAggregateRoot(bytes32 headerDigest)
    external view returns (InclusionAggregateRoot memory);
```

The existing two-half `IAggregateVerifier` stays for deposits; finalize uses its separate verification path. `claimReward` calls registry lookup, the 192-byte source-checkpoint decoder, Keccak path fold, consumption-key and recipient checks, and token balance/transfer functions. `claimAggregateWithdrawal` calls the same pure tree fold with the withdrawal leaf codec and then existing nonce/pending/payment logic. No caller passes a proof object to either claim.

## Core Loops

1. **User proving:** include at most `k` jobs of one source and user per step. Verify the own-user predecessor and any actual global predecessor, bind that source, open each included job, and update its session-local zero-to-one path. Add the checked amount and count from zero and roll the jobs commitment from the session seed. Repeat until the selected jobs are included. The terminal amount is `W`. Reject overflow, the wrong predecessor, another source or user, a duplicate key, or capacity excess. Jobs not selected are forfeited. The admission-history connection remains the section 3 gap.
2. **Segment construction:** for each family, start at ordinal zero, take `min(B,remaining)`, verify its user or withdrawal proofs, construct the opening, header, and claim tree, prove inclusion, and retain the bytes. Increase the ordinal by the count and stop at `total_count`. Reward inclusion checks each leaf's source, user, recipient, and amount against that user's terminal proof. It does not require every leaf to name one source. An error leaves earlier retained artifacts intact and submits no incomplete candidate.
3. **Publication:** wait until no Sending or Submitted transaction remains for the destination. Read the next accepted segment index, preflight the exact candidate calldata, save Sending, broadcast, and save the hash. Observe finalized evidence until it is classified. An indeterminate outcome stays retained and stops further submission. Accepted segments advance counters exactly once. Stop the window only when both families are complete.
4. **Pull:** fetch one published leaf and path, verify membership locally for user feedback, and submit the exact claim. Classify the canonical event and state. A failed transfer leaves the consumption key unset. A repeated `(economic_domain,source_checkpoint_id,user_id)` rejects. A later source is a different key and pays its own full `W`, not a delta.

## Module Changes

| Owner | Proposed responsibility | Existing evidence |
|---|---|---|
| Codec | `SourceCheckpointRewardLeaf`, its opening, the proposed consumption key, packed header, typed Hash4, and pure claim tree | `bridge_aggregate.rs:859-1148,649-687` |
| Reward session | `RewardSessionCircuit`; one source and user; base zero and seed; terminal `W`; session-local nullifier | `reward_session.rs` |
| Withdrawal inclusion circuit | Withdrawal child verification, configured-root membership, withdrawal header and tree | `WithdrawalInclusionAggregateCircuit` in `inclusion_aggregate.rs` |
| Reward inclusion circuit | One final `RewardSessionCircuit` proof per user, payout-leaf equality, and publication bindings | `RewardInclusionAggregateCircuit` in `inclusion_aggregate.rs` |
| Wrapper/setup | Artifact-specific 2-half or 6-half shapes and typed finalize source | `bridge_wrap.rs:116-148` |
| Checkpoint schema | Remains six roots and 192 bytes; no reward-root addition | `psy_data/src/v1/qdata/checkpoint.rs:320-370` |
| StateManager | Atomic per-transaction publication, complete-window progress, finalize and deposit joins; no persistent job-nullifier cursor | `StateManager.sol:205-275` |
| Payer / Bridge | Current payer is per-job `REWARD_PER_CLAIM`; proposed payer is one full `W`. Withdrawal nonce and delay stay unchanged | `EthereumRewardPayer.sol:46-95`; `Bridge.sol:643-670` |
| Relayer / service | Retained exact artifacts, family-specific proving, receipt recovery, canonical projections | `daemon.rs:1338-1459,1817-1919` |

## File Changes

This is a source-impact plan, not an applied source patch. Hunk headers below identify inspected existing ranges and proposed changes; they do not pretend unknown full implementations exist. No source, tests, generators or setup artifacts are edited by this documentation task.

| File or coordinated file set | Action and bounded change |
|---|---|
| `client_prover/psy_core/psy_data/src/bridge_aggregate.rs` | Retain deposit codec/preimages; add header/cumulative codec/typed Hash4/helper; separate deposit 1024 bound from window 131072 bound. |
| `psy_plonky2_common_circuits/src/bridge/aggregate_config.rs` | Match three native config count bounds in circuit. |
| `psy_plonky2_circuits/src/bridge/circuits/inclusion_aggregate.rs` | `WithdrawalInclusionAggregateCircuit` and `RewardInclusionAggregateCircuit` own their relations and share `AGGREGATE_PI_LEN`. |
| `psy_plonky2_circuits/src/bridge/circuits/reward_session.rs` | `RewardSessionCircuit` is the session kind from section 3. Do not add a balance, debit, ticket registry, or seventh checkpoint root. |
| `psy_plonky2_circuits/src/bridge/circuits/user_reward_aggregate.rs` | Superseded by `reward_session.rs`. The temporary mapping above records its names until the cutover lands. |
| `psy_plonky2_circuits/src/bridge/circuits/bridge_wrap.rs` | Artifact-specific inclusion width `AGGREGATE_PI_LEN` versus the deposit width; typed finalize source, exact encoding, and chain-list identity. |
| `psy_plonky2_circuits/src/bridge/circuits/bridge_agg_final.rs` | Direct span<=32 path with full transition coverage; preserve Chain prefix for larger spans. |
| `psy_cli/psy_relayer_cli/src/bridge/prove_bridge.rs`, `regen_groth16_keystore.rs` | Independent cached-base/coordinator equality guard before construction/setup and proving; artifact-specific wrapper dispatch. |
| `psy-contracts/src/BridgeOpening.sol` | Decode strict header/cumulative bytes and update window bounds without deposit preimage changes. |
| `psy-contracts/src/StateManager.sol` | Replace the full payout-opening ABI with section 6. Keep registry and progress atomic. Do not add a persistent job-nullifier cursor or a direct payout. |
| `psy-contracts/src/IInclusionAggregateVerifier.sol` | New six-half interface; do not change deposit `IAggregateVerifier.sol`. |
| `psy-contracts/src/EthereumRewardPayer.sol`, `IEthereumRewardPayer.sol` | The proposed payout is section 6's one full `W` and source-user key. Current source remains the per-job key in section 6. This row does not claim that replacement has landed. |
| `psy-contracts/src/Bridge.sol`, `IAggregateBridge.sol` | Pull membership before existing nonce/delay path; remove StateManager batch-registration callers in the same cutover. |
| `psy_cli/psy_relayer_cli/src/bridge/daemon.rs` | Ordered retained segment artifacts, manifest and receipt state; preserve crash ordering. |
| `../psy-services/src/api/handlers/inclusion_aggregate.rs`, `../psy-services/src/repositories/inclusion_aggregate.rs` | New dedicated endpoint/repository for section 7; register through existing server/module lists. Do not reuse unrelated public-transfer repository. |
| Existing adjacent aggregate/payer/checkpoint tests | Author section 8 contracts; execution only in authorized QA. Preserve named 30M fixture. |

`AGGREGATE_PI_LEN` in `inclusion_aggregate.rs` is the current publication width for both inclusion circuits. Deposit, withdrawal, and reward count bounds in `bridge_aggregate.rs` remain separate. Constructor targets, equality constraints, witness assignment, codecs, native metadata, and setup consumers cut over together. Session width, publication width, and finalize width never share a blanket replacement.

Setup generation remains gated. Operational command reference, not execution authorization: digest setup uses `psy_relayer_cli regenerate-groth16-keystore --aggregate-proofs --aggregate-config <approved-json> --output-dir <fresh-directory>`; finalize uses `regenerate-groth16-keystore --include-bridge-agg --aggregate-config <approved-json> --skip-deposit-append --skip-withdrawal-claim --keystore-dir <fresh-directory>`, then `export-solidity-verifier --finalize <fresh-directory> <output.sol>`. A fresh directory is mandatory; source/common/verifier/fingerprint, native proving/verifying keys and Solidity verifier constitute one atomic artifact set. Old setup files never validate changed layouts.

Source and service cutover reject the old per-job aggregate schema and the superseded 160-byte cumulative codec without conversion. `CumulativeRewardLeaf` is not a migration input. Archive service claims verbatim. Archived included, applied, or rejected claim-id and spent-key associations block fresh admission. Queued or refresh-required archive rows are not reinterpreted. The current payer key and the proposed source-user key are different identities, so an existing economic domain has no implicit migration. No zero root and no fabricated amount are allowed. A fresh domain starts from the canonical empty session root, never integer zero.

## Naming Crosswalk

Registered concepts only. Final spellings are those in `TERMINOLOGY.md`. This table renames no source identifier, wire field, cryptographic label, or preimage.

| Concept | Registered spelling | Protected occurrences |
|---|---|---|
| Complete withdrawal opening | `WithdrawalAggregateOpening` | Frozen label `WithdrawalBatch`. |
| Complete reward opening | `RewardAggregateOpening` | Frozen label `RewardBatch`. `SourceCheckpointRewardLeaf` is the payout codec, not a rename of this opening. |
| Opening digest | `opening_digest` | JSON/Solidity `openingDigest`; deposit `deposit_opening_digest` / `depositOpeningDigest`. Distinct from `header_digest`. |
| Publication header | `InclusionAggregateHeader` | Binds `opening_digest`, `claim_tree_root`, segment context, and family roots. Reward slots are `old_ledger_state_root` and `new_ledger_state_root`. |
| Publication registry entry | `InclusionAggregateRoot` | Derived lookup. Stored authority is `headerBytes`. Not reward-ledger occupancy. |
| Segment publication argument | `InclusionSegment` | `headerBytes`, proof, and first/last leaf paths. Not a stored registry row. |
| Window progress | `ActiveWindow` | `initialized` is window existence. Publication does not mark claims paid. |
| Claim tree | `claim_tree_root` | Marker-12 Keccak root of one segment. Not a session-nullifier root. |
| User amount | `total_amount` | Eight little-endian u32 limbs. Terminal value is `W`. The statement is `RewardSessionStatement`. |
| Session job identity | `nullifier_key` | Session-local `(source<<31)\|(level<<26)\|index`. Not persistent and not L1 `spentRewards`. |
| Checkpoint membership | `historical_merkle_proof` | Existing `claim_checkpoint_path` is the same membership. `HistoricalRootMerkleProofGadget` is a different header-upgrade operation. |
| Reward session | `RewardSessionCircuit` | One proof chain per `(economic_domain,source_checkpoint_id,user_id)`. Omitted jobs are forfeited. |
| Session seed | `jobs_commitment` | Base is `reward_session_seed` over `PsyRewardJobs/Session/1`. `rolling_jobs_commitment` absorbs the active job records. |
| Session summary | `reward_session_summary` | Binds the statement, seed, and private session root under `PsyRewardSession/Summary/1`. |
| Ledger state | `RewardLedgerStateTargets` | Window hash, `ledger_root`, `user_root`, `session_count`, and `unfinished_session_count`. |
| Ledger window | `RewardLedgerWindowTargets` | Poseidon binding over `PsyRewardLedger/Window/1`. |
| Ledger occupancy | `RewardLedgerLeafTargets` | Occupancy write at the reward ledger key under `PsyRewardLedger/Issued/1`. |
| Publication endpoints | `old_ledger_state_root`, `new_ledger_state_root` | Composite ledger-state endpoints. Not session-nullifier roots. |
| Publication width | `AGGREGATE_PI_LEN` | Sole owner of the inclusion publication width, shared by `WithdrawalInclusionAggregateCircuit` and `RewardInclusionAggregateCircuit`. |
| Claimant identity | `UserAuthTargets` | Scheme selector, registered leaf, `public_key_param`, signature gadgets, and `auth_message`. Only `is_final_step` authenticates the claimant. |
| Payout key | Consumption key | Boolean per economic domain, source, and user. Current `spentRewards` is a different per-job boolean. |
| Hash4 selector | `Hash4Encoding` | `CanonicalU64x4`, `LittleEndianU32x8`. Keccak words are not interchangeable. |
| Codec and circuit leaves | `AggregateLeaf`, `AggregateLeafTarget` | Different types. Preserve the distinction. |
| Payout leaf flag | `initialized` | `SourceCheckpointRewardLeaf` field. Solidity/JSON `initialized`. Payable only when true. |
| Registry existence | `published` | Derived from registry-key existence. Not a stored header field. |
| Window existence | `initialized` | `ActiveWindow` field. Distinct from the payout-leaf flag. |
| Circuit kinds | Reward circuit kind | `RewardSessionCircuit`, `RewardInclusionAggregateCircuit`, and the Groth16 wrapper. Depth is data-dependent and is not another kind. |
| Admission connection | Interleaved admission gap | Unclosed private-target connection. No wider statement, balance, or persistent job root is adopted. |

Temporary cutover record. Remove this table after the cutover has landed and review has accepted it.

| Current source spelling | Registered spelling |
|---|---|
| `UserRewardAggregateCircuit` | `RewardSessionCircuit` |
| `UserRewardTargets` | `RewardSessionStatement` |
| `USER_REWARD_PROOF_FIELD_COUNT` | `REWARD_SESSION_PROOF_FIELD_COUNT` |
| `USER_REWARD_STEP_CAPACITY` | `REWARD_SESSION_STEP_CAPACITY` |
| `CreditSessionTargets` | `RewardSessionTargets` |
| `credit_session_seed` | `reward_session_seed` |
| `credit_session_summary` | `reward_session_summary` |
| `CreditSessionAuthorization` | `RewardSessionAuthorization` |
| `CreditJobTargets` | `RewardSessionJobTargets` |
| `CreditJobWitness` | `RewardSessionJobWitness` |
| `credited_amount` | `job_amount` |
| `RewardLedgerStateTargets.context` / `RewardLedgerStateValues.context` | `ledger_window_hash` |
| wrapper field `context` holding the ledger window | `ledger_window` |
| `AdmissionStateTargets` | `RewardLedgerStateTargets` |
| `AdmissionContextTargets` | `RewardLedgerWindowTargets` |
| `CreditAdmissionTargets` | `RewardLedgerLeafTargets` |
| `old_nullifier_root` / `new_nullifier_root` | `old_ledger_state_root` / `new_ledger_state_root` |
| `InclusionAggregateCircuit` | `WithdrawalInclusionAggregateCircuit` and `RewardInclusionAggregateCircuit` |
| `WITHDRAWAL_PUBLICATION_PI_LEN` | `AGGREGATE_PI_LEN` |
| `PsyRewardJobs/CreditSession/1` | `PsyRewardJobs/Session/1` |
| `PsyRewardAdmission/CreditSession/1` | `PsyRewardSession/Summary/1` |
| `PsyRewardAdmission/Credit/1` | `PsyRewardLedger/Issued/1` |
| `PsyRewardAdmission/Context/1` | `PsyRewardLedger/Window/1` |
| `PsyRewardAdmission/State/1` | `PsyRewardLedger/State/1` |
| `PsyRewardAdmission/{Verifier,Node,Empty}/1` | `PsyRewardLedger/{Verifier,Node,Empty}/1` |
| `PsyBridge/SourceCheckpointReward/1/Record` | `PsyBridge/SourceCheckpointReward/1/Leaf` |
| `AdmissionRequest` / `AggregationAdmissionRequest` | `AggregationClaimRequest` |
| admission builder method | `build_aggregation_claim` |
| `Admission` enum variant | `AggregationClaim` |

## Rationale

- One session exists because one `(economic_domain,source_checkpoint_id,user_id)` has one credit and one full payment. A second session would credit omitted jobs again.
- The session seed exists because amount and count must bind the same source, user, recipient, and included jobs.
- The session nullifier exists only while the session is unfinished. It stops the same included job from being added twice. It is not a second payment ledger and is not retained.
- One boolean consumption key exists because the full `W` is paid once. A per-job payment key answers a different question and is the current payer's question.
- An omitted job is forfeited because the user chose the included set. The protocol does not keep a residual balance for the rest.
- Segmentation exists because 100,000 users exceed every allowed compiled inclusion capacity.
- Active-window manifests and boundary witnesses exist because without them omitted segments or cross-segment duplicates can be presented as a complete window.
- Distinct withdrawal and reward circuits exist because their membership, ordering, replay, and payment semantics differ. Sharing only identical pure algorithms avoids a runtime family selector.
- Typed finalize identity and base/step equality exist because a same-width wrong source or chain list can otherwise use incompatible setup metadata.
- Retained Sending exists because an unknown broadcast outcome is not evidence permitting a second transaction.
- Three circuit kinds retain one reusable credit relation while allowing data-dependent depth. A bounded step is not a lifetime cap.
- Realm-finalize output commitment `A` is an opaque value, not a job subtree and not a tagged claimable reward leaf. The circuit binds it as the value-only right child of the inner reward hash: `reward_subtree=H(root_guta.rewards_tree_value,A)`, `R63=H(reward_subtree,worker_reward_tag)`, and the registered public input is `PI=H(final_guta_header_hash,R63)` (`psy_plonky2_circuits/src/guta_v2/circuits/realm_finalize_guta.rs:690-741`; host mirror `psy_data/src/guta/realm_finalize.rs:171-173,331-363`). A's own preimage contains no `worker_tag`. This document does not claim that public `A` or that public input discloses `worker_tag`.
- No checkpoint reward root is added. The six-root checkpoint schema remains the source schema.

## Security Considerations

1. A named public root is not authenticated unless its membership reaches the verified checkpoint or finalize source.
2. The credit relation authenticates included jobs only. L1 cannot turn an omitted job into a later balance.
3. The same session key with a different user, source, or recipient rejects. A new end root never changes that identity.
4. Publication writes segment headers atomically. It does not advance a persistent job-nullifier cursor.
5. The proposed payment and exact token movement commit together. A zero amount rejects.
6. Segmented windows are not globally atomic. Incomplete progress blocks the next window, while an already published valid claim remains payable.
7. An unknown submission outcome halts resend. An administrative override does not recreate a paid credit.
8. Missing artifact availability is not proof failure and does not justify an unbound replacement witness.
9. Hash4 encoding, byte order, integer width, chain order, and verifier identity are protocol inputs, not decoder conveniences.
10. No gas, proof-capacity, runtime, or deployment success is asserted here.
11. `PQEDCheckpointGlobalStateRoots` has exactly six hashes and a 192-byte encoding (`psy_data/src/v1/qdata/checkpoint.rs:320-327,362-370`). Its hash is the six-root hash at `checkpoint.rs:487-493`. This contract does not add a seventh root.

## Review and Activation Boundary

`RewardSessionStatement` and the three circuit kinds are the adopted contract. Same-kind recursion depth is data-dependent and `REWARD_SESSION_STEP_CAPACITY` is benchmark-selected. Withdrawal and reward remain separate pipelines. No balance, debit, ticket registry, persistent per-job root, or seventh checkpoint root is part of the contract. The current L1 payer key remains the per-job key in section 6; the source-user key is not claimed to have replaced it.

Global one-credit occupancy is `RewardLedgerLeafTargets`: two u32 path limbs, user then source, empty zero leaf to occupied leaf under `PsyRewardLedger/Issued/1`. It is not the current L1 key. `reward_session_summary` binds the private session root under `PsyRewardSession/Summary/1`. `UserAuthTargets` authenticates the claimant only on `is_final_step` and fails closed on an unknown fingerprint. No exported constructor connects every selected terminal to one publication history. None of these facts adds a public input or a global per-job bitmap. Independent review under `PIPELINE.md` and the design-reviewer gate are unmet. This document does not claim GO. Product funding, withdrawal timing, and an explicit migration decision remain outside this contract.
