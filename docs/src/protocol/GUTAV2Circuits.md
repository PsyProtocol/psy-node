# GUTA v2 Circuits

This protocol reference covers realm GUTA aggregation and finalization circuits, alongside the [circuit index](Circuits.md) and [gadget index](Gadgets.md).

> Updated: 2026-09-08. Source of truth: `psy_plonky2_circuits/src/guta_v2/circuits/` and `psy_plonky2_circuits/src/guta/gadgets/`.
> Currency: `TwoNCAStateTransitionGadget` is obsolete — use `DualVariableHeightStateTransitionGadget`. Circuit type IDs: [`docs/src/protocol/ProvingJobs.md`](ProvingJobs.md).
> **Live manager set:** types constructed by `QEDGUTACircuitManager` / present in `cached_circuit_library` — Single/Two EndCap, TwoGUTA, LeftGUTA+RightEndCap, VerifyToCap, NoChange, linear/LLRV/checkpoint upgrades, RealmFinalize(63). Enum leftovers **not** in cache: LeftEndCapRightGUTA(9), RegisterUsers(12), OnlyRegisterUsers(14), WrappedSignature(64).
> Shared GUTA public inputs: 4 felts = `H2(header_hash, rewards_tree_value)`.
> Core line counts exclude blank lines, `//` comments, block comments, and `#[cfg(test)]` modules.

## Abstract

Realm GUTA aggregation circuits that verify EndCaps / child GUTAs, merge state transitions, optionally upgrade checkpoint roots, and finalize a realm root (`RealmFinalizeGUTA`, type 63).

## Table of Contents

- [1. Shared gadgets](#1-shared-gadgets)
- [2. EndCap and GUTA verifiers](#2-endcap-and-guta-verifiers)
- [3. Aggregation circuits](#3-aggregation-circuits)
- [4. Checkpoint-upgrade variants](#4-checkpoint-upgrade-variants)
- [5. RealmFinalizeGUTACircuit](#5-realmfinalizegutacircuit)
- [6. Line / no-change circuits](#6-line--no-change-circuits)

## 1. Shared gadgets

### `DualVariableHeightStateTransitionGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/dual_variable_height_state_transition.rs:12-155` (core lines: ~114)
-   **Purpose:** Combine two same-level GUTA headers into a parent via dual variable-height delta (TwoNCA replacement).
-   **Constraints (pseudocode):**

    ```text
    DVH bind A/B old/new/index
    connect A.checkpoint == B.checkpoint; A.whitelist == B.whitelist; A.level == B.level
    new_level = node_level - DVH.height
    new_header = {whitelist, checkpoint, old=DVH.old_root, new=DVH.new_root, combine(stats), agg+1}
    ```

### `SingleVariableHeightStateTransitionGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/single_variable_height_state_transition.rs:16-109` (core ~83)
-   **Purpose:** Lift a single child header to an ancestor via one variable-height delta.

### `LeftLinearRightVariableHeightStateTransitionGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/left_linear_right_variable_height_state_transition.rs:12-121` (core ~88)
-   **Purpose:** Attach a right leaf/subtree under a left linear parent already at the parent index/level.

### `GUTALinearTransitionGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_linear_transition_gadget.rs:12-118` (core ~80)
-   **Purpose:** Sequentially compose two GUTA headers on the same node (`A.new == B.old`); no Merkle lift.

### `GUTAStatsGadget` / `GlobalUserTreeAggregatorHeaderGadget`

-   **Files:** `guta/gadgets/guta_stats.rs` (core ~101); `guta/gadgets/guta_header.rs` (core ~190)
-   **Purpose:** Stats aggregation and standard GUTA header (`whitelist`, `checkpoint_tree_root`, state transition, stats) with `to_hash`.

### `GUTANoChangeGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_no_change_gadget.rs` (core ~84)
-   **Purpose:** Emit a no-op GUSR transition while syncing checkpoint context.

---

## 2. EndCap and GUTA verifiers

### `VerifyEndCapProofGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_end_cap.rs:22-162` (core ~127)
-   **Purpose:** Verify user EndCap proof, bind result+stats to PIs, authenticate EndCap checkpoint root via historical proof, emit GUTA header.
-   **Constraints (pseudocode):**

    ```text
    verify_proof; fingerprint(vk) == known_end_cap_fingerprint
    expected_PI = H2(end_cap_hash, stats_hash); connect == proof.PI[0..4]
    historical.historical_root == end_cap.checkpoint_tree_root_hash
    header from end_cap leaf transition at user_id; checkpoint = historical.current_root
    ```

### `VerifyGUTAProofGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof.rs:20-153` (core ~123)
-   **Purpose:** Verify recursive GUTA proof: PI ↔ header+rewards tag; fingerprint ∈ whitelist Merkle tree.
-   **Constraints (pseudocode):**

    ```text
    verify_proof
    header.whitelist_root == whitelist_merkle.root
    expected_PI_hash == proof.PI[0..4]
    whitelist_merkle.value == fingerprint(vk)
    ```

### `VerifyGUTAProofToLineGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof_to_line.rs` (core ~82)
-   **Purpose:** Verify GUTA then propagate upward with `GUTAHeaderLineProofGadget` (`guta_line.rs`, core ~49).

---

## 3. Aggregation circuits

| Circuit                                  | File                                        | Core LOC | Transition | PI helper     |
| ---------------------------------------- | ------------------------------------------- | -------: | ---------- | ------------- |
| `GUTAVerifySingleEndCapCircuitV2`        | `guta_v2/circuits/verify_single_end_cap.rs` | ~209     | SVH        | no_children   |
| `GUTAVerifyTwoEndCapCircuitV2`           | `verify_two_end_cap.rs`                     | ~208     | DVH        | two_end_cap   |
| `GUTAVerifyTwoGUTACircuitV2`             | `verify_two_guta.rs`                        | ~205     | DVH        | two_children  |
| `GUTAVerifyLeftGUTARightEndCapCircuitV2` | `verify_left_guta_right_end_cap.rs`         | ~199     | LLRV       | right_end_cap |
| `GUTAVerifyTwoGUTALinearCircuit`         | `verify_guta_linear_transition.rs`          | ~188     | Linear     | two_children  |

**Shared pattern:**

```text
verify children (EndCap and/or GUTA)
combine headers with SVH / DVH / LLRV / Linear
PI = H2(new_header_hash, rewards_tree_value(worker_tag, child_rewards…))
```

---

## 4. Checkpoint-upgrade variants

| Circuit                                       | File                                                       | Core LOC | Pattern                       |
| --------------------------------------------- | ---------------------------------------------------------- | -------: | ----------------------------- |
| `GUTAVerifyTwoGUTAUpgradeCheckpointCircuitV2` | `verify_two_guta_upgrade_checkpoint.rs`                    | ~241     | Dual historical sync → DVH    |
| Linear upgrade                                | `verify_guta_linear_transition_upgrade_checkpoint.rs`      | ~274     | Dual historical sync → Linear |
| Left-linear right-leaf upgrade                | `verify_guta_left_linear_right_leaf_upgrade_checkpoint.rs` | ~274     | Right historical → LLRV       |

**Upgrade constraints (TwoGUTA form):**

```text
A,B = VerifyGUTA
hist_a.current_root == hist_b.current_root; current_value != 0
A/B.checkpoint == hist.historical_root
override headers.checkpoint = hist.current_root
DVH(A', B'); register two_children PI
```

---

## 5. `RealmFinalizeGUTACircuit`

-   **File:** `psy_plonky2_circuits/src/guta_v2/circuits/realm_finalize_guta.rs:203-754` (constraint body; core ~896 file excl. tests)
-   **Type:** `ProvingJobCircuitType::RealmFinalizeGUTA` (63). Proved by `psy_worker_cli`.
-   **Auth (local):** No child `WrappedSignatureProof` (64). In-circuit: validator-tree membership, rotation, fee math, root GUTA binding. Off-circuit: BLS P2P Proposal/Certificate (BLS auth cutover; see source comment in `realm_finalize_guta.rs` near fee/public-key handling). Type 64 is not in `cached_circuit_library` in this worktree.
-   **Purpose:** Finalize a realm’s root GUTA: enforce rotation/validator identity, apply DA fees into the validator user leaf, emit finalizer public-output commitment into the rewards tag tree.
-   **Public Inputs:** `H2(final_guta_header_hash, rewards_tree_value)` where  
    `rewards = H2(H2(root_guta.rewards, output_commitment), worker_reward_tag)`.
-   **Private Inputs / Witness:** Root GUTA proof/header/whitelist; checkpoint id/sub_id; anchor + current checkpoint proofs/leaves; old realm root proof; validator leaf + tree proof; validator user leaves; fee delta proof; worker reward tag; rotation schedule (build-time).
-   **Constraints (pseudocode):**

    ```text
    root = VerifyGUTA; level == coordinator_global_user_tree_height
    enforce_rotation(checkpoint_id, realm_id, sub_id, schedule, validator_sub_ids)
    prove checkpoint leaf under root.checkpoint
    prove old_realm_root at realm_id under checkpoint.user_tree_root == root.old_node
    validator_leaf_hash = Poseidon(DOMAIN, uid, node_id_limbs, bls_limbs)
    prove validator leaf under checkpoint.validator_tree_root
    prove validator user leaves; new_balance = current.balance + da_fees
    delta-update realm subtree
    final_header = {old=root.old, new=delta.new_root, index=realm_id, level=realm_level}
    bind output_commitment; PI = H2(final_header, rewards)
    ```

-   **Role:** Realm root submitted with P2P Proposal+Certificate to Coordinator `psy_submit_guta`. See [`docs/src/dev/reward-tree-circuits.md`](../dev/reward-tree-circuits.md) and `realm-finalize-bls-auth.md`.

---

## 6. Line / no-change circuits

Live in `QEDGUTACircuitManager` / `cached_circuit_library`. Shared PI: `H2(header_hash, rewards_tree_value)`.

### `GUTANoChangeCircuit` (type 15)

-   **File:** `psy_plonky2_circuits/src/guta/circuits/guta_no_change.rs` (core ~184)
-   **Gadgets:** `GUTANoChangeGadget`
-   **Purpose:** Emit a no-op GUSR transition while syncing checkpoint context (padding / empty realms).
-   **Constraints (pseudocode):**

    ```text
    header = GUTANoChangeGadget(whitelist, checkpoint_height)
    PI = H2(header.hash, rewards_tag_tree(worker_tag, /*no children*/))
    ```

### `GUTAVerifyGUTAToCapCircuit` (type 13)

-   **File:** `psy_plonky2_circuits/src/guta/circuits/verify_guta_to_cap.rs` (core ~159)
-   **Gadgets:** `VerifyGUTAProofToLineGadget` → `VerifyGUTAProofGadget` + `GUTAHeaderLineProofGadget`
-   **Purpose:** Verify child GUTA then lift header along a line proof toward the realm/coordinator cap.
-   **Constraints (pseudocode):**

    ```text
    line = VerifyGUTAProofToLine(child)
    PI = H2(line.header.hash, rewards_tree(worker_tag, child.rewards))
    ```

### `GUTAVerifyGUTAToCapUpgradeCheckpointCircuit` (type 56)

-   **File:** `psy_plonky2_circuits/src/guta/circuits/verify_guta_to_cap_upgrade_checkpoint.rs` (core ~183)
-   **Gadgets:** `VerifyGUTAProofToLineGadget` + `HistoricalRootMerkleProofGadget`
-   **Purpose:** Same as ToCap, but rewrite `checkpoint_tree_root` to a newer historical root.
-   **Constraints (pseudocode):**

    ```text
    line = VerifyGUTAProofToLine(child)
    hist.current_value != 0
    line.header.checkpoint == hist.historical_root
    line.header.checkpoint := hist.current_root
    PI = H2(line.header.hash, rewards_tree(…))
    ```

Also live (table §3–§4): Linear upgrade + LeftLinearRightLeaf upgrade under `guta_v2/circuits/`.
