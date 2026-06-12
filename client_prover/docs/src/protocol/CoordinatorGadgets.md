# Coordinator Gadgets

These gadgets are components used within circuits run by the Coordinator nodes.
### `BatchAppendUserRegistrationTreeGadget`

*   **File:** `append_user_registration_tree.rs` (Gadget definition)
*   **Purpose:** Aggregates multiple "Spiderman" append proofs sequentially for the User Registration Tree (`URT`). Handles padding for a fixed maximum number of sub-tree appends.
*   **Key Inputs/Witness:**
    *   `user_registration_tree_height`, `batch_sub_tree_height`, `max_sub_trees`: Parameters.
    *   `SpidermanUpdateProof[]`: Array witness containing the append proofs for each sub-tree batch being added.
*   **Key Outputs/Computed Values:**
    *   `old_root`: The root of the `URT` *before* all appends in this gadget instance.
    *   `new_root`: The root of the `URT` *after* all appends in this gadget instance.
*   **Core Logic/Constraints:**
    *   Instantiates `max_sub_trees` instances of `SpidermanAppendProofGadget`.
    *   Connects the `new_root` of one gadget to the `old_root` of the next in sequence.
    *   Handles witness padding by setting dummy proofs for unused slots.
*   **Assumptions:** Assumes witness `SpidermanUpdateProof` array is valid initially (constraints verify internal consistency). Assumes `old_root` of the first gadget matches the tree state before this operation.
*   **Role:** Allows efficient batching of user registration appends into a single ZK proof step for the Coordinator.

### `BatchDeployContractsGadget`

*   **File:** `deploy_contract.rs` (Gadget definition)
*   **Purpose:** Handles the proof logic for appending a batch of new contracts to the Global Contract Tree (`GCON`). Verifies one Spiderman append proof and ensures the provided contract leaf data matches the appended hashes.
*   **Key Inputs/Witness:**
    *   `contract_tree_height`, `batch_sub_tree_height`: Parameters.
    *   `SpidermanUpdateProof`: Witness for the batch append operation on `GCON`.
    *   `PsyContractLeaf[]`: Array witness containing the data for each deployed contract leaf in the batch.
*   **Key Outputs/Computed Values:**
    *   `old_root`, `new_root`: Start and end roots of the `GCON` tree for this batch append (from `spiderman_gadget`).
*   **Core Logic/Constraints:**
    *   Instantiates `SpidermanAppendProofGadget`.
    *   Instantiates `PsyContractLeafGadget` for each potential leaf slot in the batch.
    *   For each leaf slot marked as added (`is_added` from Spiderman proof):
        *   Computes the hash of the corresponding `PsyContractLeafGadget` witness.
        *   Asserts this computed hash matches the `new_leaves[i]` value from the Spiderman proof.
    *   Handles witness padding for unused leaf slots.
*   **Assumptions:** Assumes witness `SpidermanUpdateProof` and `PsyContractLeaf` array are valid initially. Assumes `old_root` of the Spiderman gadget matches the `GCON` state before this operation.
*   **Role:** Securely proves the batch addition of new contracts to the global contract tree, verifying consistency between the state update and the provided contract metadata.

### `VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget`

*   **File:** `verify_agg_user_registration_deploy_guta.rs`
*   **Purpose:** Represents the combined state transitions resulting from aggregating User Registrations, Contract Deployments, and GUTA proofs. Acts as the core data structure within the Part 1 Aggregation circuit.
*   **Key Inputs/Witness:** (Typically derived from verified sub-proofs)
    *   `user_registration_tree_delta`: `AggStateTransitionGadget` for `URT`.
    *   `global_contract_tree_delta`: `AggStateTransitionGadget` for `GCON`.
    *   `global_user_tree_delta`: `GlobalUserTreeAggregatorHeaderGadget` for `GUSR`.
*   **Key Outputs/Computed Values:**
    *   `combined_hash`: A single hash representing the start/end states of all three trees and the GUTA header.
*   **Core Logic/Constraints:** Primarily a data structure. `get_combined_hash` defines the specific hashing scheme to commit to all input state transitions.
*   **Assumptions:** Assumes the input transition/header gadgets are correctly derived from verified proofs.
*   **Role:** Standardizes the output structure of the Part 1 aggregation step, providing a single hash commitment for verification by the final block circuit.

### `VerifyAggUserRegistartionDeployContractsGUTAGadget`

*   **File:** `verify_agg_user_registration_deploy_guta.rs`
*   **Purpose:** The core gadget within the Part 1 Aggregation circuit. Verifies the aggregated proofs for User Registrations, Contract Deployments, and GUTA, ensuring they are valid, used whitelisted circuits, and reference the same checkpoint state.
*   **Key Inputs/Witness:**
    *   Parameters and configuration for verifying each of the three input proofs (common data, whitelist/fingerprint configs, GUTA params).
    *   Proof objects and verifier data for each of the three input proofs.
    *   Witnesses for state transitions/headers corresponding to each proof.
    *   GUTA whitelist Merkle proof.
*   **Key Outputs/Computed Values:**
    *   `header`: A `VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget` containing the verified state transitions.
*   **Core Logic/Constraints:**
    *   Instantiates `VerifyStateTransitionProofGadget` for User Registrations, verifying the proof against its config/fingerprint.
    *   Instantiates `VerifyStateTransitionProofGadget` for Contract Deployments similarly.
    *   Instantiates `VerifyGUTAProofGadget` for the GUTA proof, verifying it against its config/fingerprint and the GUTA whitelist root.
    *   Connects the `checkpoint_tree_root` from the GUTA header to ensure consistency (implicitly assumes UserReg/Deploy proofs are for the same checkpoint, which should be enforced by job planning). *Correction: This gadget doesn't directly connect checkpoint roots; that consistency is usually handled by the job system ensuring proofs for the same checkpoint are aggregated.*
    *   Constructs the output `header` from the verified transition gadgets.
*   **Assumptions:** Assumes witness proofs, headers, and verifier data are valid initially. Assumes input configuration (common data, fingerprint configs, whitelist root) is correct.
*   **Role:** Securely combines the results of the three major parallel state update processes (User Reg, Deploy Contract, GUTA) into a single verifiable unit, discharging assumptions about their individual validity and circuit usage.

### `PsyPart1StateDeltaResultGadget`

*   **File:** `checkpoint_state_transition_proofs.rs`
*   **Purpose:** Takes the verified combined header from the Part 1 aggregation (`VerifyAggUserRegistartionDeployContractsGUTAHeaderGadget`) and combines it with previous block stats and new block info (time, randomness) to calculate the *new* Checkpoint Leaf state.
*   **Key Inputs/Witness:**
    *   `part_1_header`: Output from the Part 1 aggregation gadget.
    *   `old_stats`: `PsyCheckpointLeafStatsGadget` witness for the previous block's stats.
    *   `block_time`: Target witness for the current block's timestamp.
    *   `final_random_seed_contribution`: Hash witness for randomness.
*   **Key Outputs/Computed Values:**
    *   `old_state_roots`, `new_state_roots`: Derived directly from `part_1_header`.
    *   `new_stats`: Computed by combining GUTA stats with time, randomness, etc.
    *   `old_checkpoint_leaf`: Constructed from `old_state_roots` and `old_stats`.
    *   `new_checkpoint_leaf`: Constructed from `new_state_roots` and `new_stats`.
*   **Core Logic/Constraints:**
    *   Constructs `old_state_roots` and `new_state_roots` gadgets.
    *   Computes `new_stats` based on inputs (copying GUTA stats, hashing random seed, setting time, zeroing PM/DA stats for now).
    *   Constructs `old_checkpoint_leaf` and `new_checkpoint_leaf` gadgets.
    *   Asserts `block_time` > `old_stats.block_time`.
*   **Assumptions:** Assumes `part_1_header` is correctly verified. Assumes `old_stats`, `block_time`, `final_random_seed_contribution` witnesses are correct.
*   **Role:** Calculates the state transition specifically for the Checkpoint Leaf data based on the aggregated results from the rest of the block's activities.

### `CheckpointStateTransitionChildProofsGadget`

*   **File:** `checkpoint_state_transition_proofs.rs`
*   **Purpose:** Verifies the "Part 1" aggregation proof within the final block circuit and instantiates the gadget (`PsyPart1StateDeltaResultGadget`) that calculates the Checkpoint Leaf transition.
*   **Key Inputs/Witness:**
    *   Parameters for verifying the Part 1 proof (common data, cap height, known fingerprint).
    *   Part 1 proof object and verifier data.
    *   Witnesses needed by `PsyPart1StateDeltaResultGadget` (`old_stats`, `block_time`, `random_seed`).
*   **Key Outputs/Computed Values:**
    *   `state_delta_gadget`: The instantiated `PsyPart1StateDeltaResultGadget`.
*   **Core Logic/Constraints:**
    *   Verifies the `part_1_proof_target` against `part_1_verifier_data`.
    *   Checks the fingerprint of `part_1_verifier_data` against `known_part_1_fingerprint`.
    *   Instantiates `PsyPart1StateDeltaResultGadget`.
    *   Computes the expected public inputs hash for the Part 1 proof using the `state_delta_gadget.part_1_header`.
    *   Asserts this computed hash matches the actual public inputs from `part_1_proof_target`.
*   **Assumptions:** Assumes witness proofs, verifier data, and state delta inputs are correct initially. Assumes `known_part_1_fingerprint` constant is correct.
*   **Role:** Securely incorporates the aggregated result of UserReg/Deploy/GUTA processing (the Part 1 proof) into the final block transition calculation.

### `CheckpointStateTransitionCoreGadget`

*   **File:** `checkpoint_state_transition.rs`
*   **Purpose:** Handles the core Merkle proof logic for updating the Checkpoint Tree (`CHKP`) itself. Verifies the append operation for the new checkpoint leaf and its consistency with the previous checkpoint leaf.
*   **Key Inputs/Witness:**
    *   `checkpoint_tree_height`: Parameter.
    *   `append_checkpoint_tree_proof`: `DeltaMerkleProofCore` witness for appending the new leaf.
    *   `previous_checkpoint_proof`: `MerkleProofCore` witness proving the existence of the *previous* checkpoint leaf.
*   **Key Outputs/Computed Values:**
    *   `old_checkpoint_tree_root`, `new_checkpoint_tree_root`: Roots before/after append.
    *   `old_checkpoint_leaf_hash`, `new_checkpoint_leaf_hash`: Leaf hashes involved.
*   **Core Logic/Constraints:**
    *   Instantiates `DeltaMerkleProofGadget` for the append proof and `MerkleProofGadget` for the previous proof.
    *   Asserts `append_checkpoint_tree_proof.old_value` is zero hash (ensures append).
    *   Asserts `append_checkpoint_tree_proof.old_root` matches `previous_checkpoint_proof.root` (ensures continuity).
    *   Asserts `append_checkpoint_tree_proof.index` == `previous_checkpoint_proof.index + 1`.
*   **Assumptions:** Assumes witness Merkle proofs are valid initially.
*   **Role:** Enforces the append-only nature and sequential integrity of the main Checkpoint Tree, linking the current block's update directly to the previous block's verified state.