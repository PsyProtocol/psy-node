# Realm & GUTA Gadgets

> **Currency note (2026-09-08):** `TwoNCAStateTransitionGadget` is obsolete. Use `DualVariableHeightStateTransitionGadget` (`psy_plonky2_circuits/src/guta/gadgets/dual_variable_height_state_transition.rs`). Full GUTA v2 circuit catalog: [GUTAV2Circuits.md](./GUTAV2Circuits.md). RealmFinalizeGUTA: `psy_plonky2_circuits/src/guta_v2/circuits/realm_finalize_guta.rs`. Actions: `psy_data/src/guta/realm_finalize.rs`.

> Updated: 2026-09-08.

## Abstract

This document describes the gadgets used by Realm and Coordinator circuits to verify End Cap and Global User Tree Aggregator proofs, merge state transitions, propagate tree paths, and represent intervals without user-state changes.

## Table of Contents

- [1. GUTA Statistics Gadget](#1-gutastatsgadget)
- [2. GUTA Header Gadget](#2-globalusertreeaggregatorheadergadget)
- [3. End Cap Verification Gadget](#3-verifyendcapproofgadget)
- [4. GUTA Verification Gadget](#4-verifygutaproofgadget)
- [5. Dual Variable-Height State Transition Gadget](#5-dualvariableheightstatetransitiongadget)
- [6. Header Line Gadget](#6-gutaheaderlineproofgadget)
- [7. Verification-to-Line Gadget](#7-verifygutaprooftolinegadget)
- [8. No-Change Gadget](#8-gutanochangegadget)
- [9. GUTA v2 circuits](#9-guta-v2-circuits)

## 1. `GUTAStatsGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_stats.rs` (core lines: ~101)
*   **Purpose:** Represents and aggregates key statistics during GUTA processing (fees, operations counts, slots modified).
*   **Technical Function:** Data structure holding targets for stats. Provides `combine_with` method for additive aggregation and `to_hash` for commitment.
*   **Inputs/Witness:** Targets for `fees_collected`, `user_ops_processed`, `total_transactions`, `slots_modified`.
*   **Outputs/Computed:** Combined stats (via `combine_with`), hash of stats (`to_hash`).
*   **Constraints:** `combine_with` uses addition constraints. `to_hash` uses packing/hashing.
*   **Assumptions:** Assumes input target values are correct.
*   **Role:** Tracks operational metrics through the aggregation tree.

---

## 2. `GlobalUserTreeAggregatorHeaderGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_header.rs` (core lines: ~190)
*   **Purpose:** Defines the standard public input structure for all GUTA-related aggregation circuits. Encapsulates the result of an aggregation step.
*   **Technical Function:** Data structure holding `guta_circuit_whitelist` root, `checkpoint_tree_root`, the `state_transition` (`SubTreeNodeStateTransitionGadget`) for the `GUSR` tree segment covered, and aggregated `stats` (`GUTAStatsGadget`). Provides `to_hash` method.
*   **Inputs/Witness:** Component targets/gadgets.
*   **Outputs/Computed:** Hash of the header (`to_hash`).
*   **Constraints:** `to_hash` combines hashes of components.
*   **Assumptions:** Assumes input components are correctly formed/verified.
*   **Role:** Standardizes the interface between recursive GUTA circuits, ensuring consistent information propagation and verification.

---

## 3. `VerifyEndCapProofGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_end_cap.rs:22-162` (core lines: ~127)
*   **Purpose:** Verifies a user's submitted End Cap proof (output of UPS Phase 1) at the entry point of the GUTA aggregation (typically within a Realm node circuit).
*   **Technical Function:** Verifies the End Cap ZK proof, checks its fingerprint against the known constant, matches public inputs against witness data (result/stats), verifies the user's claimed checkpoint root against a historical checkpoint proof, and translates the result into a `GlobalUserTreeAggregatorHeaderGadget`.
*   **Inputs/Witness:**
    *   `end_cap_result_gadget`, `guta_stats`: Witness for claimed outputs.
    *   `checkpoint_historical_merkle_proof`: Witness proving user's `checkpoint_tree_root_hash` was valid historically.
    *   `verifier_data`, `proof_target`: The End Cap proof itself and its verifier data.
    *   `known_end_cap_fingerprint_hash`: Constant parameter.
*   **Outputs/Computed:** Implements `ToGUTAHeader` to output a `GlobalUserTreeAggregatorHeaderGadget`.
*   **Constraints:**
    *   Verifies `proof_target` using `verifier_data`.
    *   Computes fingerprint from `verifier_data`, connects to `known_end_cap_fingerprint_hash`.
    *   Computes expected public inputs hash from `end_cap_result_gadget` and `guta_stats`, connects to `proof_target.public_inputs`.
    *   Verifies `checkpoint_historical_merkle_proof` using `HistoricalRootMerkleProofGadget`.
    *   Connects `historical_proof.historical_root` to `end_cap_result.checkpoint_tree_root_hash`.
    *   Constructs output GUTA header using `historical_proof.current_root` as the `checkpoint_tree_root`, deriving the state transition from `end_cap_result` (leaf hashes and user ID), and using the verified `guta_stats`.
*   **Assumptions:** Assumes witness data is valid initially. Assumes `known_end_cap_fingerprint_hash` and input `default_guta_circuit_whitelist` are correct.
*   **Role:** Securely ingests a user's proven session result into the GUTA aggregation, validating it against global rules and historical state before converting it to the standard GUTA format.

---

## 4. `VerifyGUTAProofGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof.rs:20-153` (core lines: ~123)
*   **Purpose:** Verifies a GUTA proof generated by a lower level in the aggregation hierarchy (e.g., verifying a Realm's proof at the Coordinator level, or verifying sub-realm proofs within a Realm).
*   **Technical Function:** Verifies the input GUTA ZK proof, checks its fingerprint against the GUTA circuit whitelist, and ensures its public inputs match the claimed GUTA header witness.
*   **Inputs/Witness:**
    *   `guta_proof_header_gadget`: Witness for the claimed header of the proof being verified.
    *   `guta_whitelist_merkle_proof`: Witness proving the sub-proof's circuit fingerprint is in the GUTA whitelist.
    *   `verifier_data`, `proof_target`: The GUTA proof and its verifier data.
*   **Outputs/Computed:** The verified `guta_proof_header_gadget`.
*   **Constraints:**
    *   Verifies `proof_target` using `verifier_data`.
    *   Computes fingerprint from `verifier_data`.
    *   Verifies `guta_whitelist_merkle_proof`.
    *   Connects `guta_proof_header.guta_circuit_whitelist` to `whitelist_proof.root`.
    *   Computes expected public inputs hash from `guta_proof_header`, connects to `proof_target.public_inputs`.
    *   Connects `whitelist_proof.value` to computed fingerprint.
*   **Assumptions:** Assumes witness data is valid initially.
*   **Role:** The core recursive verification step for GUTA aggregation circuits. Ensures that only valid proofs generated by allowed GUTA circuits are incorporated into higher levels of aggregation.

---

## 5. `DualVariableHeightStateTransitionGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/dual_variable_height_state_transition.rs:12-155` (core lines: ~114). Merkle engine: `psy_plonky2_common_circuits/src/hash/merkle/gadgets/dual_variable_height_delta_merkle_proof.rs:16-200` (core ~208).
*   **Purpose:** Combine two same-level GUTA headers into a parent header via dual variable-height delta. **Replaces** obsolete `TwoNCAStateTransitionGadget`.
*   **Technical Function:** Uses `DualVariableHeightDeltaMerkleProofGadget` to bind child A/B old/new values and indices; combines stats; raises node level by the proved height.
*   **Inputs/Witness:** Child A/B headers (already verified); left/right variable-height delta proofs.
*   **Outputs/Computed:** `new_guta_header` at the NCA / parent node.
*   **Constraints:**
    *   Connect A/B `checkpoint_tree_root` and `guta_circuit_whitelist`.
    *   Connect A/B `node_level` equal; `new_level = node_level - DVH.height`.
    *   Bind A/B state-transition fields to DVH child slots; `left.new_root == right.old_root` inside DVH.
    *   `new_stats = A.stats.combine_with(B.stats)`; aggregation count += 1.
*   **Assumptions:** Input headers already verified. Same checkpoint + whitelist + level.
*   **Role:** Binary tree aggregation transition for TwoGUTA / TwoEndCap / upgrade circuits. See [GUTAV2Circuits.md](./GUTAV2Circuits.md).

---

## 6. `GUTAHeaderLineProofGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_line.rs` (core lines: ~49)
*   **Purpose:** Propagates a GUTA state transition upwards along a direct path in the `GUSR` tree (when there's only one child updating that path segment).
*   **Technical Function:** Uses `SubTreeNodeTopLineGadget` to recompute the Merkle root hash from the child's transition level up to a specified higher level (e.g., Realm root or global root), using sibling hashes provided as witness.
*   **Inputs/Witness:**
    *   `child_proof_header`: The verified GUTA header from the lower level.
    *   `siblings`: Witness array of Merkle sibling hashes for the path.
    *   Height parameters.
*   **Outputs/Computed:** `new_guta_header` with the state transition updated to reflect the higher level.
*   **Constraints:** Relies on `SubTreeNodeTopLineGadget`'s internal Merkle hashing constraints.
*   **Assumptions:** Assumes `child_proof_header` is verified. Assumes `siblings` witness is correct.
*   **Role:** Efficiently moves a verified state transition up the tree hierarchy when merging (NCA) is not required.

---

## 7. `VerifyGUTAProofToLineGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof_to_line.rs` (core lines: ~82)
*   **Purpose:** Combines verifying a lower-level GUTA proof with immediately propagating its state transition upwards using a line proof.
*   **Technical Function:** Orchestrates `VerifyGUTAProofGadget` followed by `GUTAHeaderLineProofGadget`.
*   **Inputs/Witness:** Combines witnesses for both sub-gadgets (proof, header, whitelist proof, siblings).
*   **Outputs/Computed:** `new_guta_header` at the top of the line.
*   **Constraints:** Instantiates and connects the two sub-gadgets.
*   **Assumptions:** Relies on sub-gadget assumptions.
*   **Role:** A common pattern gadget simplifying the verification and upward propagation of a single GUTA proof branch.

---

*(User-registration GUTA gadgets historically named `GUTARegisterUser*` are **not** live coordinator job circuits. Live registration uses `BatchAppendUserRegistrationTree` — see [CoordinatorGadgets.md](./CoordinatorGadgets.md) and [ProvingJobs.md](./ProvingJobs.md).)*

---

## 8. `GUTANoChangeGadget`

*   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_no_change_gadget.rs` (core lines: ~84)
*   **Purpose:** Creates a GUTA header signifying that the `GUSR` tree state did *not* change for this block/subtree, while still potentially updating the referenced `checkpoint_tree_root`.
*   **Technical Function:** Verifies a checkpoint proof to get the current `checkpoint_tree_root` and the corresponding `user_tree_root` from the checkpoint leaf. Constructs a GUTA header with a "no-op" state transition (old=new=user_tree_root at level 0) and zero stats.
*   **Inputs/Witness:**
    *   `guta_circuit_whitelist`: Input constant/parameter.
    *   `checkpoint_tree_proof`: Witness proving `checkpoint_leaf` existence.
    *   `checkpoint_leaf_gadget`: Witness for the `PsyCheckpointLeafCompactWithStateRoots`.
*   **Outputs/Computed:** `new_guta_header` (indicating no GUSR change).
*   **Constraints:** Verifies checkpoint proof (`MerkleProofGadget`). Verifies consistency between proof value and leaf hash. Constructs header with no-op transition and zero stats.
*   **Assumptions:** Assumes witness proof/leaf data is valid initially. Assumes input `guta_circuit_whitelist` is correct.
*   **Role:** Allows the GUTA aggregation structure to remain consistent and synchronized with the main Checkpoint Tree advancement even during periods where no user state relevant to GUTA was modified.

---

## 9. GUTA v2 circuits

Live aggregation circuits (not hypothetical) are catalogued with public/private inputs and constraint pseudocode in [GUTAV2Circuits.md](./GUTAV2Circuits.md):

* Single/Two EndCap, TwoGUTA, LeftGUTA+RightEndCap, Linear TwoGUTA
* Checkpoint-upgrade variants
* `RealmFinalizeGUTACircuit` (type 63)

Job graph and PI layouts: [ProvingJobs.md](./ProvingJobs.md).
