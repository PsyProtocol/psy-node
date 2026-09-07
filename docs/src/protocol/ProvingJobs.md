# Proving Jobs Architecture

> Updated: 2026-09-03.


## Abstract

This document describes the proving jobs architecture for both Realm and Coordinator processors, including the tree structure of different proof types and their public inputs layout.

## Table of Contents

- [1. Public Input Layouts](#1-public-input-layouts)
- [2. Realm Proving Jobs](#2-realm-proving-jobs)
- [3. Coordinator Proving Jobs](#3-coordinator-proving-jobs)
- [4. Global User Tree Aggregator Circuit Variants](#4-global-user-tree-aggregator-circuit-variants)
- [5. State Part 1](#5-state-part-1)
- [6. Checkpoint State Transition](#6-checkpoint-state-transition)
- [7. Job Dependencies and Task Graph](#7-job-dependencies-and-task-graph)
- [8. Commitment Calculation Rules](#8-commitment-calculation-rules)
- [9. Core Proving Circuits](#9-core-proving-circuits)
- [10. Proof Miner Job Statistics](#10-proof-miner-job-statistics)
- [11. Design Principles](#11-design-principles)

## 1. Public Input Layouts

**IMPORTANT**: Different circuit types have different public inputs layouts!

### Coordinator Main Circuits (19 inputs)
- **[0..4]**: commitment
- **[4..8]**: worker_public_key
- **[8..11]**: pm_jobs_completed_stats (deploy_contracts_completed, register_users_completed, gutas_completed)
- **[11..15]**: circuit_whitelist_root
- **[15..19]**: state_transition_hash

### GUTA Circuits (15 inputs)
- **[0..4]**: commitment
- **[4..8]**: worker_public_key
- **[8..11]**: pm_jobs_completed_stats
- **[11..15]**: guta_header_hash

### Special: AggUserRegistrationDeployContractsGUTA (19 inputs)
- **[0..4]**: state_transition_hash (NOT commitment!)
- **[4..8]**: hash(user_registration_commitment, user_registration_worker_pk)
- **[8..12]**: hash(deploy_contracts_commitment, deploy_contracts_worker_pk)
- **[12..16]**: hash(guta_commitment, guta_worker_pk)
- **[16..19]**: additional data

## 2. Realm Proving Jobs

> **Current source (2026-09):** Realm does **not** use circuits named `ProcessUserOp`, `AggregateUserOps`, or `RealmStateTransition`. Those names are obsolete. Authoritative circuit types live in `psy_core/src/job/job_id.rs` (`ProvingJobCircuitType`).

### EndCap → GUTA → RealmFinalize

```text
User EndCap proofs (submitted to realm edge)
        |
        v
Realm GUTA aggregation tree
  (GUTAVerifySingleEndCap / TwoEndCap / TwoGUTA / linear+upgrade variants)
        |
        v
RealmFinalizeGUTA (63)  -- proved by psy_worker_cli; root GUTA + validator-tree/fee constraints
        |
        v
P2P Proposal / Votes / Certificate --> Coordinator psy_submit_guta(..., proposal, certificate)
```

> **Currency (2026-09-08, local):** Circuit 63 no longer verifies a child `WrappedSignatureProof` (64). Wallet-signature fingerprint derivation was removed with the BLS auth cutover (`realm_finalize_guta.rs` comment at the fee/public-key section). Authorization for submission is the realm processor BLS vote + Coordinator certificate verification off-circuit; validator-tree membership and fee math remain in-circuit. Type 64 is absent from `cached_circuit_library` in this worktree. Older docs that still say “63 depends on 64” are stale.

### Realm root circuit details

| Circuit | Type u32 | Who proves | Role |
|---------|----------|------------|------|
| User EndCap family | see job_id.rs | user / prove-proxy | Leaf transitions into realm GUTA |
| GUTA aggregation variants | live cache: 7,8,10,11,13,15,55–59 (not 9/12/14/60/64) | `psy_worker_cli` | Aggregate EndCaps / GUTAs |
| RealmFinalizeGUTA | 63 | `psy_worker_cli` | Realm root submitted with P2P Proposal+Certificate |

Witness construction for finalization is `RealmGUTAPlanner::append_realm_finalize_guta` (`psy_node_common/src/guta_planner/realm_guta_planner.rs`). Circuit implementation: `psy_plonky2_circuits/src/guta_v2/circuits/realm_finalize_guta.rs`.

Ordinary GUTA public-input layout (15 inputs) in §1 still applies to aggregation GUTA jobs. RealmFinalizeGUTA carries the finalized GUTA header hash as its expected public inputs commitment; do not use the obsolete ProcessUserOp table below historically.

## 3. Coordinator Proving Jobs

### Three Main Trees + Final Aggregation

```mermaid
graph TB
    subgraph "GUTA Tree"
        subgraph "GUTA Leaves"
            GUTA1[Realm GUTA 1]
            GUTA2[Realm GUTA 2]
            GUTAN[Realm GUTA N]
        end

        subgraph "GUTA Aggregation"
            GUTA_AGG1[GUTATwoGUTA]
            GUTA_AGG2[GUTATwoGUTA]
            GUTA_CAP[GUTAVerifyToCap<br/>Optional]
        end

        GUTA1 --> GUTA_AGG1
        GUTA2 --> GUTA_AGG1
        GUTAN --> GUTA_AGG2
        GUTA_AGG1 --> GUTA_CAP
        GUTA_AGG2 --> GUTA_CAP
    end

    subgraph "Register Users Tree"
        subgraph "Register Users Leaves"
            RU1[Batch 1<br/>Circuit: BatchAppendUserRegistrationTree]
            RU2[Batch 2<br/>Circuit: BatchAppendUserRegistrationTree]
            RUN[Batch N<br/>Circuit: BatchAppendUserRegistrationTree]
        end

        subgraph "Register Users Aggregation"
            RU_AGG1[Circuit: AggStateTransition]
            RU_AGG2[Circuit: AggStateTransition]
            RU_ROOT[Root Aggregation<br/>Circuit: AggStateTransition]
        end

        RU1 --> RU_AGG1
        RU2 --> RU_AGG1
        RUN --> RU_AGG2
        RU_AGG1 --> RU_ROOT
        RU_AGG2 --> RU_ROOT
    end

    subgraph "Deploy Contracts Tree"
        subgraph "Deploy Contracts Leaves"
            DC1[Batch 1<br/>Circuit: BatchDeployContracts]
            DC2[Batch 2<br/>Circuit: BatchDeployContracts]
            DCN[Batch N<br/>Circuit: BatchDeployContracts]
        end

        subgraph "Deploy Contracts Aggregation"
            DC_AGG1[Circuit: AggStateTransition]
            DC_AGG2[Circuit: AggStateTransition]
            DC_ROOT[Root Aggregation<br/>Circuit: AggStateTransition]
        end

        DC1 --> DC_AGG1
        DC2 --> DC_AGG1
        DCN --> DC_AGG2
        DC_AGG1 --> DC_ROOT
        DC_AGG2 --> DC_ROOT
    end

    subgraph "Final Aggregation"
        STATE_PART_1[State Part 1<br/>Circuit: AggUserRegistrationDeployContractsGUTA]
        CHECKPOINT[Checkpoint State Transition<br/>Circuit: CheckpointStateTransition]
    end

    GUTA_CAP --> STATE_PART_1
    RU_ROOT --> STATE_PART_1
    DC_ROOT --> STATE_PART_1
    STATE_PART_1 --> CHECKPOINT
```

## 4. Global User Tree Aggregator Circuit Variants

The GUTA (Global User Tree Aggregator) has multiple circuit variants to handle different scenarios.

> **Live set (2026-09-08, `cached_circuit_library`):** `GUTATwoEndCap`(7), `GUTATwoGUTA`(8), `GUTALeftGUTARightEndCap`(10), `GUTASingleEndCap`(11), `GUTAVerifyToCap`(13), `GUTANoChange`(15), checkpoint/linear/LLRV upgrades (55–59), `RealmFinalizeGUTA`(63). **Absent from cache / not constructed by `QEDGUTACircuitManager`:** `GUTALeftEndCapRightGUTA`(9), `GUTARegisterUsers`(12), `GUTAOnlyRegisterUsers`(14), `GUTAVerifyLeftLeafRightLinearUpgradeCheckpoint`(60), `WrappedSignatureProof`(64). User registration is coordinator `BatchAppendUserRegistrationTree`, not a GUTA register circuit.

### GUTA Circuit Types and Usage

```mermaid
graph LR
    subgraph "Leaf Circuits (No Child Proofs)"
        GNC[GUTANoChange<br/>No state changes]
        GSE[GUTASingleEndCap<br/>Single EndCap]
    end

    subgraph "Two Children Aggregation"
        GTG[GUTATwoGUTA<br/>Two GUTA proofs]
        GTE[GUTATwoEndCap<br/>Two EndCap proofs]
        GLR[GUTALeftGUTARightEndCap<br/>GUTA + EndCap]
    end

    subgraph "Special Purpose"
        GVC[GUTAVerifyToCap<br/>Verify to tree cap]
        GLIN[GUTATwoGUTALinear<br/>+ upgrade / LLRV variants]
        GRF[RealmFinalizeGUTA<br/>type 63]
    end
```

### Additional GUTA Circuits

**Other live GUTA circuits** (also 15 inputs / rewards-header PI form — see [GUTAV2Circuits.md](./GUTAV2Circuits.md)):
- `GUTANoChange`: No state changes
- `GUTATwoEndCap`: Aggregate two EndCap proofs
- `GUTAVerifyToCap`: Verify GUTA to tree cap
- `GUTATwoGUTALinear` / `GUTATwoGUTALinearUpgradeCheckpoint`
- `GUTATwoGUTAWithCheckpointUpgrade` / `GUTAVerifyToCapWithCheckpointUpgrade`
- `GUTAVerifyLeftLinearRightLeafUpgradeCheckpoint`
- `RealmFinalizeGUTA`: Realm root (type 63)

All follow the same commitment / rewards-tag calculation rules based on their dependency count (see §1 and reward-tree docs).

## 5. State Part 1

This circuit aggregates the three main trees:

### Inputs
- Register Users proof (from aggregation root)
- Deploy Contracts proof (from aggregation root)
- GUTA proof (from aggregation root or GUTAVerifyToCap)

### Public Inputs Layout (19 total) - SPECIAL LAYOUT!
**WARNING**: This circuit has a unique layout different from other circuits!
- **[0..4]**: state_transition_hash (NOT commitment!)
- **[4..8]**: hash(register_users_commitment, register_users_worker_pk)
- **[8..12]**: hash(deploy_contracts_commitment, deploy_contracts_worker_pk)
- **[12..16]**: hash(guta_commitment, guta_worker_pk)
- **[16..19]**: additional data

### How Child Proofs Are Processed
```rust
// Extract from each child proof:
let user_registration_commitment = child_proof.public_inputs[0..4];
let user_registration_worker_pk = child_proof.public_inputs[4..8];
let user_registration_final = hash(commitment, worker_pk);

// This final hash goes into parent's public_inputs[4..8]
```

### PM Rewards Commitment
The PM (Prover/Miner) Rewards Commitment is calculated from these three roots:
```rust
PMRewardCommitment {
    register_users_root,
    deploy_contracts_root,
    gutas_root,
}
```

## 6. Checkpoint State Transition

The final circuit that creates the checkpoint proof:

### Inputs
- State Part 1 proof
- Previous checkpoint proof
- Checkpoint tree merkle proof
- Various metadata (block time, random seed, etc.)

### Public Inputs Layout (19 inputs total)
- **[0..4]**: commitment
- **[4..8]**: worker_public_key
- **[8..11]**: pm_jobs_completed_stats (from State Part 1 proof)
- **[11..15]**: old_checkpoint_tree_root
- **[15..19]**: new_checkpoint_tree_root

## 7. Job Dependencies and Task Graph

```mermaid
graph LR
    subgraph "Parallel Execution"
        RU[Register Users Jobs<br/>PM Stats: (0, N, 0)]
        DC[Deploy Contracts Jobs<br/>PM Stats: (M, 0, 0)]
        GUTA[GUTA Jobs<br/>PM Stats: (0, 0, K)]
    end

    subgraph "Sequential Dependencies"
        SP1[State Part 1<br/>PM Stats: (M, N, K)]
        CST[Checkpoint State Transition<br/>PM Stats: (M, N, K)]
        NOTIFY[Notify Block Complete]
    end

    RU --> SP1
    DC --> SP1
    GUTA --> SP1
    SP1 --> CST
    CST --> NOTIFY
```

The dependency graph shows how PM stats flow through the system:
1. **Parallel Trees**: Each tree type accumulates its specific job counts
2. **State Part 1**: Combines PM stats from all three trees
3. **Checkpoint**: Preserves the combined PM stats for final reward calculation
4. **Block Completion**: Uses PM stats to calculate and distribute rewards

## 8. Commitment Calculation Rules

The commitment calculation follows a consistent pattern across all circuits:

### 1. Leaf Circuits (No Dependencies)
```rust
commitment = worker_public_key
```
Examples: GUTANoChange, BatchDeployContracts, AppendUserRegistrationTree

### 2. Single Dependency Circuits (One Child Proof)
```rust
commitment = hash(child.commitment, worker_public_key)
```
Examples: GUTASingleEndCap, GUTAVerifyToCap, GUTAVerifyToCapWithCheckpointUpgrade

### 3. Two Dependencies Circuits (Two Child Proofs)
```rust
commitment = hash(hash(left.commitment, right.commitment), worker_public_key)
```
Examples: GUTATwoGUTA, GUTATwoGUTAWithCheckpointUpgrade, GUTATwoEndCap, GUTALeftGUTARightEndCap, AggStateTransition

### Core Design Principles

1. **Commitment Chain**: Forms a tree structure but NOT for reward distribution as originally thought
   - **ALL leaf circuits**: `commitment = hash(0, 0)` (constant value!)
   - **Aggregation circuits**: `commitment = hash(hash(child1.commit, child1.worker), hash(child2.commit, child2.worker))`

2. **Job Categories**: Three parallel proving trees
   - **User Registration**: `batch_append` → `state_transition` → final aggregation
   - **Contract Deployment**: `batch_deploy` → `state_transition` → final aggregation
   - **GUTA Tree**: Various GUTA circuits → final aggregation

3. **Special Cases**:
   - **Dummy circuits**: Used when no real work is available
   - **AggUserRegistration**: Unique layout combining all three trees
   - **Checkpoint**: Final proof creating the rollup state transition

## 9. Core Proving Circuits

### Coordinator Main Circuits (19 inputs)

| Circuit | Type | Dependencies | Commitment Calculation |
|---------|------|----------|------------------------|
| **BatchAppendUserRegistrationTree** | Leaf | None | `commitment = hash(0, 0)` |
| **BatchDeployContracts** | Leaf | None | `commitment = hash(0, 0)` |
| **AggStateTransition** | Aggregation | 2 proofs | `commitment = hash(hash(left.commit, left.worker), hash(right.commit, right.worker))` |
| **DummyAggStateTransition** | Dummy | None | `commitment = hash(0, 0)` |

**Public Inputs Layout (19 total)**:
- `[0..4]`: commitment
- `[4..8]`: worker_public_key
- `[8..11]`: pm_jobs_completed_stats
- `[11..15]`: circuit_whitelist
- `[15..19]`: state_transition_hash

### GUTA Core Circuits (15 inputs)

Live rows only (enum leftovers 9/12/14 omitted — see §4 currency note).

| Circuit | Type | Dependencies | Commitment Calculation |
|---------|------|----------|------------------------|
| **GUTASingleEndCap** | Leaf | 1 EndCap | `commitment = hash(0, 0)` |
| **GUTANoChange** | Leaf | None | `commitment = hash(0, 0)` |
| **GUTATwoGUTA** | Aggregation | 2 GUTA | `commitment = hash(hash(left.commit, left.worker), hash(right.commit, right.worker))` |
| **GUTATwoEndCap** | Aggregation | 2 EndCap | `commitment = hash(hash(left.commit, left.worker), hash(right.commit, right.worker))` |
| **GUTALeftGUTARightEndCap** | Mixed | 1 GUTA + 1 EndCap | `commitment = hash(hash(left.commit, left.worker), hash(right.commit, right.worker))` |

**Public Inputs Layout (15 total)**:
- `[0..4]`: commitment
- `[4..8]`: worker_public_key
- `[8..11]`: pm_jobs_completed_stats
- `[11..15]`: guta_header_hash

### Final Aggregation Circuits

| Circuit | Dependencies | Special Notes |
|---------|----------|---------------|
| **VerifyAggUserRegistrationDeployContractsGUTA** | 3 proofs (user_reg + deploy + guta) | **UNIQUE LAYOUT**: `[0..4]` = state_transition_hash (NOT commitment!) |
| **PsyCheckpointStateTransition** | 1 proof (state_part_1) | Standard 19-input layout |

## 10. Proof Miner Job Statistics

The PM (Proof Miner) jobs completed stats track the number of different types of jobs completed throughout the circuit hierarchy. These stats flow upward through the trees and are combined at aggregation points.

### PM Stats Components
- **deploy_contracts_completed**: Number of deploy contract jobs completed in this subtree
- **register_users_completed**: Number of user registration jobs completed in this subtree
- **gutas_completed**: Number of GUTA jobs completed in this subtree

### How Stats Flow Through the Hierarchy

#### Leaf Circuits
Leaf circuits initialize their PM stats based on the work they perform:
- **Deploy Contract leaves** (BatchDeployContracts): `pm_stats = (batch_size, 0, 0)`
- **Register Users leaves** (AppendUserRegistrationTree): `pm_stats = (0, batch_size, 0)`
- **GUTA leaves** (GUTANoChange, GUTASingleEndCap, etc.): `pm_stats = (0, 0, 0)` initially
- **Dummy circuits** (AggStateTransitionDummy): `pm_stats = (0, 0, 0)` (all zeros)

#### Aggregation Circuits
Aggregation circuits combine PM stats from their children:
```rust
// Two children aggregation (AggStateTransition, GUTATwoGUTA)
final_pm_stats = PMJobsCompletedStats {
    deploy_contracts_completed: left.pm_stats[0] + right.pm_stats[0],
    register_users_completed: left.pm_stats[1] + right.pm_stats[1],
    gutas_completed: left.pm_stats[2] + right.pm_stats[2],
}
```

#### GUTA Circuits Special Handling
GUTA circuits add 1 to their gutas_completed count:
```rust
// Single child GUTA aggregation (GUTAVerifyToCap)
final_pm_stats = PMJobsCompletedStats {
    deploy_contracts_completed: child.pm_stats[0],
    register_users_completed: child.pm_stats[1],
    gutas_completed: child.pm_stats[2] + 1, // Add 1 GUTA completion
}
```

### Final Aggregation
At the State Part 1 level (AggUserRegistrationDeployContractsGUTA), the PM stats from all three trees are combined:
```rust
final_pm_stats = register_users_proof.pm_stats +
                 deploy_contracts_proof.pm_stats +
                 guta_proof.pm_stats
```

This provides a complete count of all work performed in the current checkpoint.

## 11. Design Principles

1. **Consistent Public Inputs**: All circuits follow the same [commitment, worker_public_key, pm_jobs_completed_stats, data_hash] layout
2. **Tree Aggregation**: Each category (GUTA, Register Users, Deploy Contracts) forms its own tree
3. **Parallel Processing**: The three trees can be processed in parallel
4. **Commitment Chain**: Commitments flow up from leaves to root, enabling reward distribution
5. **Flexibility**: GUTA circuits handle various scenarios (no changes, single realm, multiple realms)
6. **Worker Tracking**: Every circuit includes the worker's public key who computed that proof
7. **PM Stats Tracking**: Job completion counts flow upward through the tree hierarchy for reward calculation
