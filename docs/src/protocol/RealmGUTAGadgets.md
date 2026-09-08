# Realm & GUTA Gadgets

This protocol reference covers realm and coordinator GUTA gadgets within the [gadget index](Gadgets.md), complementing the [GUTA v2 circuit catalog](GUTAV2Circuits.md).

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
- [10. Legacy user-registration gadget sketches](#10-legacy-user-registration-gadget-sketches)

## 1. `GUTAStatsGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_stats.rs` (core lines: ~101)
-   **Purpose:** Represents and aggregates key statistics during GUTA processing (fees, operations counts, slots modified).
-   **Technical Function:** Data structure holding targets for stats. Provides `combine_with` method for additive aggregation and `to_hash` for commitment.
-   **Inputs/Witness:** Targets for `fees_collected`, `user_ops_processed`, `total_transactions`, `slots_modified`.
-   **Outputs/Computed:** Combined stats (via `combine_with`), hash of stats (`to_hash`).
-   **Constraints:** `combine_with` uses addition constraints. `to_hash` uses packing/hashing.
-   **Assumptions:** Assumes input target values are correct.
-   **Role:** Tracks operational metrics through the aggregation tree.

---

## 2. `GlobalUserTreeAggregatorHeaderGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_header.rs` (core lines: ~190)
-   **Purpose:** Defines the standard public input structure for all GUTA-related aggregation circuits. Encapsulates the result of an aggregation step.
-   **Technical Function:** Data structure holding `guta_circuit_whitelist` root, `checkpoint_tree_root`, the `state_transition` (`SubTreeNodeStateTransitionGadget`) for the `GUSR` tree segment covered, and aggregated `stats` (`GUTAStatsGadget`). Provides `to_hash` method.
-   **Inputs/Witness:** Component targets/gadgets.
-   **Outputs/Computed:** Hash of the header (`to_hash`).
-   **Constraints:** `to_hash` combines hashes of components.
-   **Assumptions:** Assumes input components are correctly formed/verified.
-   **Role:** Standardizes the interface between recursive GUTA circuits, ensuring consistent information propagation and verification.

---

## 3. `VerifyEndCapProofGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_end_cap.rs:22-162` (core lines: ~127)
-   **Purpose:** Verifies a user's submitted End Cap proof (output of UPS Phase 1) at the entry point of the GUTA aggregation (typically within a Realm node circuit).
-   **Technical Function:** Verifies the End Cap ZK proof, checks its fingerprint against the known constant, matches public inputs against witness data (result/stats), verifies the user's claimed checkpoint root against a historical checkpoint proof, and translates the result into a `GlobalUserTreeAggregatorHeaderGadget`.
-   **Inputs/Witness:**
    -   `end_cap_result_gadget`, `guta_stats`: Witness for claimed outputs.
    -   `checkpoint_historical_merkle_proof`: Witness proving user's `checkpoint_tree_root_hash` was valid historically.
    -   `verifier_data`, `proof_target`: The End Cap proof itself and its verifier data.
    -   `known_end_cap_fingerprint_hash`: Constant parameter.
-   **Outputs/Computed:** Implements `ToGUTAHeader` to output a `GlobalUserTreeAggregatorHeaderGadget`.
-   **Constraints:**
    -   Verifies `proof_target` using `verifier_data`.
    -   Computes fingerprint from `verifier_data`, connects to `known_end_cap_fingerprint_hash`.
    -   Computes expected public inputs hash from `end_cap_result_gadget` and `guta_stats`, connects to `proof_target.public_inputs`.
    -   Verifies `checkpoint_historical_merkle_proof` using `HistoricalRootMerkleProofGadget`.
    -   Connects `historical_proof.historical_root` to `end_cap_result.checkpoint_tree_root_hash`.
    -   Constructs output GUTA header using `historical_proof.current_root` as the `checkpoint_tree_root`, deriving the state transition from `end_cap_result` (leaf hashes and user ID), and using the verified `guta_stats`.
-   **Assumptions:** Assumes witness data is valid initially. Assumes `known_end_cap_fingerprint_hash` and input `default_guta_circuit_whitelist` are correct.
-   **Role:** Securely ingests a user's proven session result into the GUTA aggregation, validating it against global rules and historical state before converting it to the standard GUTA format.

---

## 4. `VerifyGUTAProofGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof.rs:20-153` (core lines: ~123)
-   **Purpose:** Verifies a GUTA proof generated by a lower level in the aggregation hierarchy (e.g., verifying a Realm's proof at the Coordinator level, or verifying sub-realm proofs within a Realm).
-   **Technical Function:** Verifies the input GUTA ZK proof, checks its fingerprint against the GUTA circuit whitelist, and ensures its public inputs match the claimed GUTA header witness.
-   **Inputs/Witness:**
    -   `guta_proof_header_gadget`: Witness for the claimed header of the proof being verified.
    -   `guta_whitelist_merkle_proof`: Witness proving the sub-proof's circuit fingerprint is in the GUTA whitelist.
    -   `verifier_data`, `proof_target`: The GUTA proof and its verifier data.
-   **Outputs/Computed:** The verified `guta_proof_header_gadget`.
-   **Constraints:**
    -   Verifies `proof_target` using `verifier_data`.
    -   Computes fingerprint from `verifier_data`.
    -   Verifies `guta_whitelist_merkle_proof`.
    -   Connects `guta_proof_header.guta_circuit_whitelist` to `whitelist_proof.root`.
    -   Computes expected public inputs hash from `guta_proof_header`, connects to `proof_target.public_inputs`.
    -   Connects `whitelist_proof.value` to computed fingerprint.
-   **Assumptions:** Assumes witness data is valid initially.
-   **Role:** The core recursive verification step for GUTA aggregation circuits. Ensures that only valid proofs generated by allowed GUTA circuits are incorporated into higher levels of aggregation.

---

## 5. `DualVariableHeightStateTransitionGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/dual_variable_height_state_transition.rs:12-155` (core lines: ~114). Merkle engine: `psy_plonky2_common_circuits/src/hash/merkle/gadgets/dual_variable_height_delta_merkle_proof.rs:16-200` (core ~208).
-   **Purpose:** Combine two same-level GUTA headers into a parent header via dual variable-height delta. **Replaces** obsolete `TwoNCAStateTransitionGadget`.
-   **Technical Function:** Uses `DualVariableHeightDeltaMerkleProofGadget` to bind child A/B old/new values and indices; combines stats; raises node level by the proved height.
-   **Inputs/Witness:** Child A/B headers (already verified); left/right variable-height delta proofs.
-   **Outputs/Computed:** `new_guta_header` at the NCA / parent node.
-   **Constraints:**
    -   Connect A/B `checkpoint_tree_root` and `guta_circuit_whitelist`.
    -   Connect A/B `node_level` equal; `new_level = node_level - DVH.height`.
    -   Bind A/B state-transition fields to DVH child slots; `left.new_root == right.old_root` inside DVH.
    -   `new_stats = A.stats.combine_with(B.stats)`; aggregation count += 1.
-   **Assumptions:** Input headers already verified. Same checkpoint + whitelist + level.
-   **Role:** Binary tree aggregation transition for TwoGUTA / TwoEndCap / upgrade circuits. See [GUTAV2Circuits.md](./GUTAV2Circuits.md).

---

## 6. `GUTAHeaderLineProofGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_line.rs` (core lines: ~49)
-   **Purpose:** Propagates a GUTA state transition upwards along a direct path in the `GUSR` tree (when there's only one child updating that path segment).
-   **Technical Function:** Uses `SubTreeNodeTopLineGadget` to recompute the Merkle root hash from the child's transition level up to a specified higher level (e.g., Realm root or global root), using sibling hashes provided as witness.
-   **Inputs/Witness:**
    -   `child_proof_header`: The verified GUTA header from the lower level.
    -   `siblings`: Witness array of Merkle sibling hashes for the path.
    -   Height parameters.
-   **Outputs/Computed:** `new_guta_header` with the state transition updated to reflect the higher level.
-   **Constraints:** Relies on `SubTreeNodeTopLineGadget`'s internal Merkle hashing constraints.
-   **Assumptions:** Assumes `child_proof_header` is verified. Assumes `siblings` witness is correct.
-   **Role:** Efficiently moves a verified state transition up the tree hierarchy when merging (NCA) is not required.

---

## 7. `VerifyGUTAProofToLineGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/verify_guta_proof_to_line.rs` (core lines: ~82)
-   **Purpose:** Combines verifying a lower-level GUTA proof with immediately propagating its state transition upwards using a line proof.
-   **Technical Function:** Orchestrates `VerifyGUTAProofGadget` followed by `GUTAHeaderLineProofGadget`.
-   **Inputs/Witness:** Combines witnesses for both sub-gadgets (proof, header, whitelist proof, siblings).
-   **Outputs/Computed:** `new_guta_header` at the top of the line.
-   **Constraints:** Instantiates and connects the two sub-gadgets.
-   **Assumptions:** Relies on sub-gadget assumptions.
-   **Role:** A common pattern gadget simplifying the verification and upward propagation of a single GUTA proof branch.

---

*(User-registration GUTA gadgets historically named `GUTARegisterUser*` are **not** live coordinator job circuits. Live registration uses `BatchAppendUserRegistrationTree` — see [CoordinatorGadgets.md](./CoordinatorGadgets.md) and [ProvingJobs.md](./ProvingJobs.md).)*

---

## 8. `GUTANoChangeGadget`

-   **File:** `psy_plonky2_circuits/src/guta/gadgets/guta_no_change_gadget.rs` (core lines: ~84)
-   **Purpose:** Creates a GUTA header signifying that the `GUSR` tree state did *not* change for this block/subtree, while still potentially updating the referenced `checkpoint_tree_root`.
-   **Technical Function:** Verifies a checkpoint proof to get the current `checkpoint_tree_root` and the corresponding `user_tree_root` from the checkpoint leaf. Constructs a GUTA header with a "no-op" state transition (old=new=user_tree_root at level 0) and zero stats.
-   **Inputs/Witness:**
    -   `guta_circuit_whitelist`: Input constant/parameter.
    -   `checkpoint_tree_proof`: Witness proving `checkpoint_leaf` existence.
    -   `checkpoint_leaf_gadget`: Witness for the `PsyCheckpointLeafCompactWithStateRoots`.
-   **Outputs/Computed:** `new_guta_header` (indicating no GUSR change).
-   **Constraints:** Verifies checkpoint proof (`MerkleProofGadget`). Verifies consistency between proof value and leaf hash. Constructs header with no-op transition and zero stats.
-   **Assumptions:** Assumes witness proof/leaf data is valid initially. Assumes input `guta_circuit_whitelist` is correct.
-   **Role:** Allows the GUTA aggregation structure to remain consistent and synchronized with the main Checkpoint Tree advancement even during periods where no user state relevant to GUTA was modified.

---

## 9. GUTA v2 circuits

Live aggregation circuits (not hypothetical) are catalogued with public/private inputs and constraint pseudocode in [GUTAV2Circuits.md](./GUTAV2Circuits.md):

* Single/Two EndCap, TwoGUTA, LeftGUTA+RightEndCap, Linear TwoGUTA
* Checkpoint-upgrade variants
* `RealmFinalizeGUTACircuit` (type 63)

Job graph and PI layouts: [ProvingJobs.md](./ProvingJobs.md).

## 10. Legacy user-registration gadget sketches

These are **legacy gadget sketches**, not live proving-job circuits (cache lacks types 9/12/14; registration is coordinator `BatchAppendUserRegistrationTree`).

### `GUTARegisterUserCoreGadget`

-   **File:** `guta_register_user_core.rs`
-   **Purpose:** Handles the core logic for registering a *single* new user in the Global User Tree (`GUSR`). It verifies the update proof that inserts the new user leaf.
-   **Key Inputs/Witness:**
    -   `global_user_tree_realm_height`, `global_user_tree_height`: Parameters.
    -   `default_user_state_tree_root`: Constant.
    -   `input_height_target`: Optional target for variable height proof.
    -   `public_key`: The public key hash for the new user (can be witness or input).
    -   `DeltaMerkleProofCore`: Witness for the `GUSR` tree update.
-   **Key Outputs/Computed Values:**
    -   `user_id`: The ID (index) of the newly registered user.
    -   `user_leaf_hash`: The hash of the newly created user leaf.
    -   `state_transition`: Represents the GUTA state transition for this single registration.
-   **Core Logic/Constraints:**
    -   Instantiates `VariableHeightDeltaMerkleProofOptGadget` for the `GUSR` update.
    -   Asserts the `old_value` in the proof is the zero hash (ensuring it's an insertion into an empty slot).
    -   Creates the default `PsyUserLeafGadget` using the proof's `index` (user ID), the `public_key`, and `default_user_state_tree_root`.
    -   Computes the `user_leaf_hash`.
    -   Asserts the `new_value` in the proof matches the computed `user_leaf_hash`.
    -   Calculates the `state_transition` based on the delta proof's old/new roots, height, and computed parent index.
-   **Assumptions:** Assumes witness proof and public key (if witness) are valid. Assumes `default_user_state_tree_root` is correct.
-   **Role:** The lowest-level gadget for handling user registration state changes in GUTA.

### `GUTARegisterUserFullGadget`

-   **File:** `guta_register_user_full.rs`
-   **Purpose:** Extends the core registration by adding verification against a *user registration tree*. This tree (presumably managed off-chain or via a separate mechanism) maps user IDs to public keys. This gadget ensures the public key used for registration matches the one committed to in the registration tree.
-   **Key Inputs/Witness:**
    -   (Inherits inputs from Core gadget).
    -   `MerkleProofCore`: Witness proving the `public_key` exists at the correct `index` (user ID) in the `user_registration_tree`.
-   **Key Outputs/Computed Values:**
    -   (Inherits outputs from Core gadget).
    -   `user_registration_tree_root`: The root of the user registration tree.
-   **Core Logic/Constraints:**
    -   Instantiates `MerkleProofGadget` for the user registration tree.
    -   Maps the proof's index bits to an expected user ID.
    -   Asserts the `value` (public key) from the registration tree proof is non-zero.
    -   Instantiates `GUTARegisterUserCoreGadget`, passing the `value` from the registration proof as the `public_key`.
    -   Asserts the `user_id` from the Core gadget matches the `expected_user_id` derived from the registration proof index.
-   **Assumptions:** Relies on Core gadget assumptions. Assumes the user registration tree proof witness is valid.
-   **Role:** Adds a layer of validation, ensuring user registrations correspond to pre-committed public keys in a dedicated registration structure.

### `GUTARegisterUsersGadget`

-   **File:** `guta_register_users.rs`
-   **Purpose:** Aggregates multiple user registration operations (using `GUTARegisterUserFullGadget`) sequentially within a single circuit. Handles padding/disabling for a fixed maximum number of users.
-   **Key Inputs/Witness:**
    -   (Inherits inputs from Full gadget).
    -   `max_users`: Parameter.
    -   `GUTARegisterUserFullInput[]`: Array witness for each potential user registration (proofs).
    -   `register_user_count`: Witness target indicating the *actual* number of users being registered (<= `max_users`).
-   **Key Outputs/Computed Values:**
    -   `state_transition`: The aggregate state transition covering all registered users.
    -   `user_registration_tree_root`: Root of the registration tree (taken from the first user, checked for consistency).
-   **Core Logic/Constraints:**
    -   Instantiates `max_users` instances of `GUTARegisterUserFullGadget`.
    -   Asserts `register_user_count` is non-zero.
    -   Iterates from the second user onwards:
        -   Compares loop index `i` with `register_user_count` to determine if the current user slot `is_disabled`.
        -   If *not* disabled:
            -   Connects the current user's `old_global_user_tree_root` to the previous user's `new_global_user_tree_root`.
            -   Connects the current user's `user_registration_tree_root` to the root from the first user (ensuring consistency).
            -   Connects proof heights.
            -   Updates the aggregate `state_transition.new_node_value` to the current user's `new_global_user_tree_root`.
        -   Selects the final `new_node_value` based on the last *enabled* user's output.
-   **Assumptions:** Relies on Full gadget assumptions. Assumes witness array and count are valid. Assumes dummy inputs are used correctly for padding.
-   **Role:** Allows batching multiple user registrations into a single GUTA proof step, improving aggregation efficiency.

### `GUTAOnlyRegisterUsersGadget`

-   **File:** `guta_only_register_users_gadget.rs`
-   **Purpose:** A specialized GUTA gadget that *only* performs user registration (using `GUTARegisterUsersGadget`) and assumes *no other state changes* (zero stats).
-   **Key Inputs/Witness:**
    -   `guta_circuit_whitelist`, `checkpoint_tree_root`: Inputs (likely from a previous step or constant).
    -   (Inherits inputs for `GUTARegisterUsersGadget`).
-   **Key Outputs/Computed Values:**
    -   `new_guta_header`: The GUTA header representing *only* the registration state change.
-   **Core Logic/Constraints:**
    -   Instantiates `GUTARegisterUsersGadget`.
    -   Constructs `new_guta_header`:
        -   Uses input `guta_circuit_whitelist` and `checkpoint_tree_root`.
        -   Uses the `state_transition` from the `GUTARegisterUsersGadget`.
        -   Creates a zeroed `GUTAStatsGadget`.
-   **Assumptions:** Relies on `GUTARegisterUsersGadget` assumptions. Assumes the provided whitelist/checkpoint roots are correct for this context.
-   **Role:** Provides a dedicated gadget for GUTA steps that solely involve registering new users.

### `GUTARegisterUsersBatchGadget`

-   **File:** `guta_register_users_batch.rs`
-   **Purpose:** Combines verification of a previous GUTA proof (brought up to a certain tree level via a line proof) with a subsequent batch registration of new users.
-   **Key Inputs/Witness:**
    -   (Inherits inputs for `VerifyGUTAProofToLineGadget`).
    -   (Inherits inputs for `GUTARegisterUsersGadget`).
-   **Key Outputs/Computed Values:**
    -   `new_guta_header`: The combined GUTA header.
-   **Core Logic/Constraints:**
    -   Instantiates `VerifyGUTAProofToLineGadget` (`verify_to_line_gadget`).
    -   Instantiates `GUTARegisterUsersGadget` (`register_users_gadget`).
    -   Connects the state transitions:
        -   `line_state_transition.node_index` == `register_users_state_transiton.node_index`.
        -   `line_state_transition.node_level` == `register_users_state_transiton.node_level`.
        -   `line_state_transition.new_node_value` == `register_users_state_transiton.old_node_value` (ensures the registration starts from the state reached by the verified line proof).
    -   Constructs `new_guta_header`:
        -   Uses whitelist/checkpoint root/stats from the line proof header.
        -   Creates combined `state_transition`: `old_node_value` from line, `new_node_value` from registration, index/level from line (must match registration).
-   **Assumptions:** Relies on assumptions of sub-gadgets. Assumes witness data is valid.
-   **Role:** Handles a common GUTA pattern: verifying a previous aggregation step and then applying a batch of user registrations originating from the state achieved by that previous step.
