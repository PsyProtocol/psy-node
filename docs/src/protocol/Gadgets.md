This document details the various gadgets used within the Psy ZK circuits, primarily focusing on the User Proving Session (UPS) and Global User Tree Aggregation (GUTA) systems. Gadgets are reusable circuit components that enforce specific constraints and logic.

### UPS Gadgets (User Proving Session)

These gadgets are components used within the circuits that users run locally to prove their sequence of transactions.

#### `CorrectUPSHeaderHashesGadget`

*   **File:** `correct_header_hashes.rs`
*   **Purpose:** To hold potentially *modified* hash roots from a previous UPS step header. This is specifically used when a transaction needs to alter the *starting* state assumptions for debt trees (e.g., paying back a deferred transaction *before* processing the current transaction's main logic).
*   **Key Inputs/Witness:** Takes a `UserProvingSessionHeaderGadget` representing the *actual* previous step.
*   **Key Outputs/Computed Values:**
    *   `previous_step_deferred_tx_debt_tree_root`: The deferred debt root to *assume* as the starting point for the *next* step's logic.
    *   `previous_step_inline_tx_debt_tree_root`: The inline debt root to *assume* as the starting point for the *next* step's logic.
*   **Core Logic/Constraints:** Primarily a data structure. Its values are *used* by other gadgets (like `UPSCFCStandardStateDeltaGadget`) to override the default assumption that the starting debt roots are identical to the previous step's *ending* debt roots.
*   **Assumptions:** Assumes the input `previous_step` header gadget is correctly formed (though its values might be overridden).
*   **Role:** Enables flexible handling of transaction debt repayment within the UPS flow, allowing debts to be settled *before* the main state delta logic runs, without breaking the constraint flow.

#### `UPSVerifyCFCProofExistsAndValidGadget`

*   **File:** `ups_cfc_verify_inclusion.rs`
*   **Purpose:** To verify that a specific Contract Function Call (CFC) proof exists within the user's current UPS proof tree and that the function being called is validly registered within the global contract structure.
*   **Key Inputs/Witness:**
    *   `AttestTreeAwareProofInTreeInput`: Witness for the CFC proof's existence and validity within the UPS proof tree.
    *   `PsyCheckpointLeafCompactWithStateRoots`: Witness for the relevant checkpoint state.
    *   `PsyContractFunctionInclusionProof`: Witness proving the function's fingerprint exists in the contract's function tree.
    *   `ups_session_proof_tree_height`: Parameter.
*   **Key Outputs/Computed Values:**
    *   `attested_proof_tree_root`: The root of the UPS proof tree the CFC proof is part of.
    *   `checkpoint_leaf_hash`: Hash of the checkpoint leaf used for context.
    *   `cfc_fingerprint`: The fingerprint (verifier data hash) of the CFC proof being verified.
    *   `cfc_inner_public_inputs_hash`: The hash of the CFC proof's *internal* public inputs (before wrapping with tree awareness).
    *   `cfc_contract_id`, `cfc_method_id`, `cfc_num_inputs`, `cfc_num_outputs`: Metadata about the contract function extracted from the inclusion proof.
*   **Core Logic/Constraints:**
    *   Verifies the CFC proof using `AttestTreeAwareProofInTreeGadget`.
    *   Verifies the function's inclusion in the contract tree using `PsyContractFunctionInclusionProofGadget`.
    *   Connects the contract tree root from the inclusion proof to the one in the checkpoint state.
    *   Connects the CFC fingerprint from the proof attestation to the one in the inclusion proof.
*   **Assumptions:** Assumes the witness data provided (proofs, checkpoint state) is valid for the constraints to pass.
*   **Role:** Ensures that the CFC proof being processed corresponds to a valid, registered function and exists within the user's current session proof tree. Links the specific CFC execution to the global contract state via the checkpoint.

#### `UPSCFCStandardStateDeltaGadget`

*   **File:** `ups_standard_cfc_state_delta.rs`
*   **Purpose:** Calculates the state changes to a user's UPS header based on executing a standard CFC transaction. It updates the user's contract state tree root, transaction debt trees, transaction count, and transaction hash stack.
*   **Key Inputs/Witness:**
    *   `previous_step_header_gadget`: The header state *before* this transaction.
    *   `corrections`: Optional `CorrectUPSHeaderHashesGadget` to override starting debt tree roots.
    *   `contract_state_tree_height`: The height of the specific CSTATE tree being modified.
    *   `UPSCFCStandardStateDeltaInput`: Witness containing the transaction input context (start/end states) and proofs for tree updates (user contract tree delta, debt tree pivots).
*   **Key Outputs/Computed Values:**
    *   `new_header_gadget`: The `UserProvingSessionHeaderGadget` representing the state *after* this transaction.
    *   `cfc_inner_public_inputs_hash`: Hash of the CFC transaction input context (used for connecting to verification gadgets).
    *   `cfc_contract_id`, `cfc_method_id`, `cfc_num_inputs`, `cfc_num_outputs`: Metadata passed through.
*   **Core Logic/Constraints:**
    *   Computes the expected `cfc_inner_public_inputs_hash` from the transaction context witness.
    *   Verifies the `user_contract_tree_update_proof` (DeltaMerkleProofGadget):
        *   Checks `old_root` matches the `user_state_tree_root` in the `previous_step_header_gadget`.
        *   Checks `index` matches the `tx_in_contract_id`.
        *   Checks `old_value` consistency (handles initialization from zero hash to default root based on height).
        *   Checks `new_value` matches the `tx_in_end_contract_state_tree_root`.
    *   Verifies `deferred_tx_debt_pivot_proof` (HistoricalRootMerkleProofGadget):
        *   Checks `historical_root` matches the *corrected* `previous_step_deferred_tx_debt_tree_root`.
        *   Checks `current_root` matches `tx_in_end_deferred_tx_debt_tree_root`.
    *   Verifies `inline_tx_debt_pivot_proof` similarly.
    *   Checks consistency between previous header state (balance, event index) and transaction start context.
    *   Updates transaction count (`new_tx_count = old_tx_count + 1`).
    *   Pushes the transaction log item onto the `tx_hash_stack`.
    *   Constructs the `new_header_gadget` with updated values.
*   **Assumptions:** Assumes witness proofs and context are valid. Assumes the `previous_step_header_gadget` and `corrections` are correctly provided.
*   **Role:** The core engine for calculating user state updates resulting from a standard contract call within the UPS.

#### `UPSVerifyCFCStandardStepGadget`

*   **File:** `ups_cfc_standard.rs`
*   **Purpose:** Combines the verification of a CFC proof's existence/validity (`UPSVerifyCFCProofExistsAndValidGadget`) with the calculation of its resulting state changes (`UPSCFCStandardStateDeltaGadget`). It acts as the main gadget for processing a standard transaction step within a UPS circuit.
*   **Key Inputs/Witness:**
    *   `previous_step_header_gadget`: Header state before this step.
    *   `current_proof_tree_root`: The root of the UPS proof tree this step belongs to.
    *   `ups_session_proof_tree_height`: Parameter.
    *   `UPSVerifyCFCStandardStepInput`: Witness containing inputs for both sub-gadgets.
*   **Key Outputs/Computed Values:**
    *   `new_header_gadget`: The `UserProvingSessionHeaderGadget` representing the state *after* this transaction step.
    *   (Internal gadgets expose their outputs too).
*   **Core Logic/Constraints:**
    *   Instantiates `UPSVerifyCFCProofExistsAndValidGadget` and `UPSCFCStandardStateDeltaGadget`.
    *   Connects `current_proof_tree_root` to the `attested_proof_tree_root` of the verification gadget.
    *   Connects the `checkpoint_leaf_hash` between the verification gadget and the `previous_step_header_gadget`.
    *   Connects key metadata (`cfc_contract_id`, `cfc_method_id`, `cfc_num_inputs`, `cfc_num_outputs`, `cfc_inner_public_inputs_hash`) between the verification gadget and the state delta gadget to ensure they operate on the same transaction.
*   **Assumptions:** Relies on the assumptions of its constituent gadgets. Assumes `current_proof_tree_root` is correctly provided.
*   **Role:** Represents a complete, verifiable step for processing one standard CFC transaction within the user's local proving session.

#### `UPSVerifyPopDeferredTxStepGadget`

*   **File:** `ups_cfc_standard_pop_deferred_tx.rs`
*   **Purpose:** Processes a transaction that *pays back* a previously incurred deferred transaction debt. It verifies the removal of the debt item from the deferred debt tree and then processes the CFC transaction itself (using the standard step gadget but with a *corrected* starting deferred debt state).
*   **Key Inputs/Witness:**
    *   `previous_step_header_gadget`: Header state before this step.
    *   `current_proof_tree_root`: The root of the UPS proof tree this step belongs to.
    *   `ups_session_proof_tree_height`: Parameter.
    *   `UPSVerifyPopDeferredTxStepInput`: Witness containing inputs for the standard CFC step *and* the `DeltaMerkleProof` for removing the deferred transaction.
*   **Key Outputs/Computed Values:**
    *   (Exposes outputs from `UPSVerifyCFCStandardStepGadget`, notably the `new_header_gadget`).
*   **Core Logic/Constraints:**
    *   Instantiates `DeltaMerkleProofGadget` (`ups_pop_deferred_tx_proof`) for the deferred debt tree.
    *   Connects `ups_pop_deferred_tx_proof.old_root` to the `deferred_tx_debt_tree_root` in `previous_step_header_gadget`.
    *   Asserts `ups_pop_deferred_tx_proof.new_value` is the zero hash (proving removal).
    *   Computes the hash of the expected deferred transaction item based on the call data from the CFC being processed.
    *   Asserts `ups_pop_deferred_tx_proof.old_value` (the item removed) matches the computed hash.
    *   Creates a `CorrectUPSHeaderHashesGadget`, setting `previous_step_deferred_tx_debt_tree_root` to `ups_pop_deferred_tx_proof.new_root`.
    *   Instantiates `UPSVerifyCFCStandardStepGadget` using the *corrected* header hashes.
*   **Assumptions:** Relies on assumptions of sub-gadgets. Assumes witness data (proofs, context) is valid.
*   **Role:** Enables verifiable settlement of deferred transaction debts within the UPS, ensuring the debt removed matches the transaction being executed.

#### `PsyUserProvingSessionSignatureDataCompactGadget`

*   **File:** `ups_signature_data.rs`
*   **Purpose:** Defines the data structure that gets signed by the user's private key (or equivalent signature scheme) to authorize the end of a User Proving Session.
*   **Key Inputs/Witness:**
    *   `start_user_leaf_hash`: Hash of the user leaf at the *start* of the session.
    *   `end_user_leaf_hash`: Hash of the user leaf at the *end* of the session.
    *   `checkpoint_leaf_hash`: Hash of the checkpoint leaf the session was based on.
    *   `tx_stack_hash`: Final hash of the transaction log stack.
    *   `tx_count`: Total number of transactions processed.
*   **Key Outputs/Computed Values:**
    *   `ups_end_cap_sighash`: The final hash (part of the signature pre-image) computed from the input data combined with network magic, user ID, and nonce.
*   **Core Logic/Constraints:**
    *   Computes an intermediate hash combining start/end user leaves.
    *   Computes an intermediate hash combining tx stack and count.
    *   Computes an intermediate hash combining checkpoint leaf and user leaf combo.
    *   Computes the final data hash by combining the state context and tx combo hashes.
    *   Uses `compute_sig_action_hash_circuit` to combine this data hash with network magic, user ID, nonce, and the specific signature action code (`PSY_SIG_ACTION_SIGN_UPS_END_CAP`) to produce the final `ups_end_cap_sighash`.
*   **Assumptions:** Assumes input hashes and targets are correctly provided.
*   **Role:** Standardizes the data payload for UPS end cap signatures, ensuring all necessary state transition information is committed to before signing.

#### `UPSEndCapResultCompactGadget`

*   **File:** `ups_end_cap_result.rs`
*   **Purpose:** Defines the compact data structure representing the *result* of a completed UPS, which is submitted to the GUTA layer for aggregation.
*   **Key Inputs/Witness:**
    *   `start_user_leaf_hash`: Hash of the user leaf at the *start* of the session.
    *   `end_user_leaf_hash`: Hash of the user leaf at the *end* of the session.
    *   `checkpoint_tree_root_hash`: Root of the checkpoint tree the session was based on.
    *   `user_id`: The ID of the user.
*   **Key Outputs/Computed Values:**
    *   `end_cap_result_hash`: The hash representing this result structure.
*   **Core Logic/Constraints:**
    *   Computes an intermediate hash combining user ID, start/end user leaves, and the global user tree height constant.
    *   Computes the final `end_cap_result_hash` by hashing the intermediate hash with the `checkpoint_tree_root_hash`.
*   **Assumptions:** Assumes input hashes and targets are correctly provided.
*   **Role:** Creates the standardized, hashable output data for a completed UPS, suitable for inclusion as a public input in the end cap proof and for verification by GUTA circuits.

#### `UPSEndCapCoreGadget`

*   **File:** `ups_end_cap.rs`
*   **Purpose:** Enforces the core constraints for finalizing a User Proving Session (End Cap). It connects the final UPS state to the signature proof and prepares the final output data (result and stats).
*   **Key Inputs/Witness:**
    *   `last_header_gadget`: The header state at the *end* of the UPS (after the last transaction).
    *   `sig_proof_public_inputs_hash`: Public inputs hash from the user's signature proof.
    *   `sig_proof_fingerprint`, `sig_proof_param_hash`: Hashes related to the signature circuit's verifier data and parameters (used to derive the expected public key).
    *   `nonce`: The nonce used in the signature, provided as witness.
    *   `slots_modified`: Total storage slots modified, provided as witness.
    *   `network_magic`, `empty_deferred_tx_debt_tree_root`, `empty_inline_tx_debt_tree_root`: Constants/parameters.
*   **Key Outputs/Computed Values:**
    *   `sig_data_compact_gadget`: The computed signature data payload.
    *   `end_cap_result_gadget`: The computed end cap result structure.
    *   `guta_stats`: The computed GUTA statistics for this session.
*   **Core Logic/Constraints:**
    *   Checks nonce progression: Ensures the final `nonce` is greater than the starting nonce and updates the user leaf nonce.
    *   Verifies public key consistency:
        *   Derives the `expected_public_key` from the signature proof fingerprint/params.
        *   Asserts the start and end user leaves have the same public key.
        *   Asserts this public key matches the `expected_public_key`.
    *   Verifies user ID consistency.
    *   Instantiates `PsyUserProvingSessionSignatureDataCompactGadget` using data from the `last_header_gadget`.
    *   Computes the expected `ups_end_cap_sighash` using the signature data gadget, network magic, user ID, and nonce.
    *   Computes the expected `sig_proof_public_inputs_hash` by hashing the `ups_end_cap_sighash` with the `sig_proof_param_hash`.
    *   Asserts the computed `sig_proof_public_inputs_hash` matches the one provided as input.
    *   Instantiates `UPSEndCapResultCompactGadget` with final state data.
    *   Checks checkpoint ID progression: Ensures the final user leaf's `last_checkpoint_id` matches the session's checkpoint ID and is greater than the starting leaf's `last_checkpoint_id`.
    *   Asserts final debt trees are empty by comparing their roots in `last_header_gadget` to the provided empty tree root constants.
    *   Instantiates `GUTAStatsGadget` using the final transaction count and provided `slots_modified`.
*   **Assumptions:** Assumes input hashes, targets, and the `last_header_gadget` are correct. Assumes the signature proof itself is valid (verification happens elsewhere or is implied).
*   **Role:** The central gadget for validating the conditions required to end a UPS, linking the final state to the signature authorization and generating the outputs needed for GUTA.

#### `VerifyPreviousUPSStepProofInProofTreeGadget`

*   **File:** `verify_previous_ups_step.rs`
*   **Purpose:** Verifies a ZK proof corresponding to the *previous* step in the User Proving Session's recursive chain. It ensures the proof is valid, exists in the expected UPS proof tree, used an allowed UPS circuit, and matches the expected previous header state.
*   **Key Inputs/Witness:**
    *   `ups_session_proof_tree_height`, `ups_circuit_whitelist_tree_height`: Parameters.
    *   `VerifyPreviousUPSStepProofInProofTreeInput`: Witness containing:
        *   `AttestTreeAwareProofInTreeInput`: Witness for the previous step's proof attestation.
        *   `UserProvingSessionHeader`: Witness for the *header state* that should be the public input of the previous proof.
        *   `MerkleProof`: Witness proving the previous proof's circuit fingerprint is in the UPS circuit whitelist.
*   **Key Outputs/Computed Values:**
    *   `proof_attestation_gadget`: The underlying attestation gadget.
    *   `previous_step_header_gadget`: The header gadget representing the public inputs of the verified proof.
    *   `ups_circuit_whitelist_merkle_proof`: The whitelist proof gadget.
    *   `current_proof_tree_root`: The root of the UPS proof tree identified by the attestation proof.
    *   `ups_step_circuit_whitelist_root`: The root of the UPS circuit whitelist tree.
*   **Core Logic/Constraints:**
    *   Instantiates `AttestTreeAwareProofInTreeGadget` to verify the previous proof's existence in the tree.
    *   Instantiates `UserProvingSessionHeaderGadget` for the previous step's public inputs (header).
    *   Instantiates `MerkleProofGadget` for the circuit whitelist check.
    *   Connects the `fingerprint` from the proof attestation to the `value` in the whitelist proof.
    *   Connects the `ups_step_circuit_whitelist_root` from the previous header gadget to the `root` of the whitelist proof gadget.
    *   Computes the expected hash of the `previous_step_header_gadget`.
    *   Connects this expected hash to the `inner_public_inputs_hash` from the proof attestation gadget.
*   **Assumptions:** Assumes witness data (proofs, headers) is valid for constraints to pass.
*   **Role:** Crucial for the recursive nature of UPS. Each step verifies the *previous* step's proof, ensuring the integrity of the entire transaction chain generated locally by the user. Links the execution to the allowed set of UPS circuits.

#### `VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget`

*   **File:** `verify_previous_ups_step_partial_from_current.rs`
*   **Purpose:** Similar to the full verification gadget, but optimized for cases where the *current* header's `session_start_context` is already known and fixed within the circuit. It only needs the *previous step's state* (`UserProvingSessionCurrentStateGadget`) as witness, reconstructing the full previous header internally.
*   **Key Inputs/Witness:**
    *   `current_header`: The *current* step's header gadget (provided as input, not witness).
    *   `ups_session_proof_tree_height`, `ups_circuit_whitelist_tree_height`: Parameters.
    *   `VerifyPreviousUPSStepProofInProofTreePartialInput`: Witness containing:
        *   `AttestTreeAwareProofInTreeInput`: Witness for the previous proof attestation.
        *   `UserProvingSessionCurrentState`: Witness for the *state portion* of the previous header.
        *   `MerkleProof`: Witness for the UPS circuit whitelist proof.
*   **Key Outputs/Computed Values:** Same as `VerifyPreviousUPSStepProofInProofTreeGadget`.
*   **Core Logic/Constraints:**
    *   Similar logic to the full version, but it *constructs* the `previous_step_header_gadget` by combining the known `session_start_context` from the `current_header` with the `previous_step_state` provided as witness.
    *   Enforces the same connections for fingerprint, whitelist root, and inner public inputs hash.
    *   Adds a constraint connecting the `ups_step_circuit_whitelist_root` from the *current* header to the whitelist proof root.
*   **Assumptions:** Assumes the provided `current_header` gadget is correct. Assumes witness data is valid.
*   **Role:** An optimization for verifying previous steps within circuits where the session start context is constant (like the End Cap circuit). Reduces witness size.

#### `UPSEndCapFromProofTreeGadget`

*   **File:** `ups_end_cap_tree.rs`
*   **Purpose:** Orchestrates the entire End Cap process within a ZK circuit. It verifies the *last* UPS step proof, verifies the user's ZK signature proof, and enforces the final End Cap constraints.
*   **Key Inputs/Witness:**
    *   `ups_session_proof_tree_height`, `ups_circuit_whitelist_tree_height`: Parameters.
    *   `network_magic`: Parameter.
    *   `UPSEndCapFromProofTreeGadgetInput`: Witness containing:
        *   `VerifyPreviousUPSStepProofInProofTreeInput`: Witness for verifying the last UPS step.
        *   `AttestProofInTreeInput`: Witness for verifying the ZK signature proof.
        *   `user_public_key_param`: Hash representing signature parameters.
        *   `nonce`: The nonce used for signing.
        *   `slots_modified`: Total storage slots modified.
*   **Key Outputs/Computed Values:**
    *   `end_cap_core_gadget`: The core gadget performing final checks.
    *   `current_proof_tree_root`: The root of the UPS proof tree.
*   **Core Logic/Constraints:**
    *   Instantiates `VerifyPreviousUPSStepProofInProofTreeGadget` to verify the last UPS step.
    *   Instantiates `AttestProofInTreeGadget` to verify the ZK signature proof.
    *   Connects the `attested_proof_tree_root` from the signature proof verification to the `current_proof_tree_root` from the previous step verification (ensuring both proofs are in the same tree).
    *   Defines empty debt tree root constants.
    *   Instantiates `UPSEndCapCoreGadget`, passing outputs from the verification gadgets (`previous_step_header_gadget`, signature proof hashes) and witness values (`nonce`, `slots_modified`, `user_public_key_param`) along with constants.
*   **Assumptions:** Relies on assumptions of sub-gadgets. Assumes witness data is valid.
*   **Role:** The top-level gadget within the End Cap *circuit*, ensuring the final UPS state is valid, linked to the previous step, and properly authorized by a valid ZK signature, all within the same consistent UPS proof tree.

#### `UPSStartStepGadget`

*   **File:** `ups_start.rs`
*   **Purpose:** Initializes a User Proving Session. It takes the user's initial state (from the last finalized block's checkpoint) and sets up the starting header for the UPS circuit chain.
*   **Key Inputs/Witness:**
    *   `UPSStartStepInput`: Witness containing:
        *   `UserProvingSessionHeader`: The *expected* starting header.
        *   `PsyCheckpointLeaf`: Witness for the checkpoint leaf data.
        *   `PsyCheckpointGlobalStateRoots`: Witness for the global state roots within the checkpoint.
        *   `MerkleProof`: Proof linking the checkpoint leaf to the checkpoint tree root.
        *   `MerkleProof`: Proof linking the user's starting leaf hash to the global user tree root.
*   **Key Outputs/Computed Values:**
    *   `header_gadget`: The validated starting header gadget.
*   **Core Logic/Constraints:**
    *   **Constraint Set 1 (Start Session Context):**
        *   Verifies `checkpoint_tree_proof` consistency with `header_gadget.session_start_context` (root, leaf hash, ID).
        *   Verifies consistency between `checkpoint_leaf_gadget`, `state_roots_gadget`, and the `header_gadget` (checkpoint leaf hash, global chain root).
        *   Verifies `user_tree_proof` root matches the `user_tree_root` in `state_roots_gadget`.
        *   Verifies `user_tree_proof` value matches `header_gadget.session_start_context.start_session_user_leaf_hash`.
        *   Verifies `user_tree_proof` index matches the `user_id` in the header's start leaf.
    *   **Constraint Set 2 (Current State Initialization):**
        *   Computes the hash of the expected *current* user leaf (start leaf with `last_checkpoint_id` updated to the session's checkpoint ID).
        *   Asserts this computed hash matches the hash of the `header_gadget.current_state.user_leaf`.
        *   Asserts the `deferred_tx_debt_tree_root` and `inline_tx_debt_tree_root` in `header_gadget.current_state` match the known empty tree root constants.
        *   Asserts `tx_hash_stack` is zero hash and `tx_count` is zero.
*   **Assumptions:** Assumes the witness data (header, proofs, leaves, roots) is valid for constraints to pass. Assumes the empty tree root constants are correct.
*   **Role:** Securely bootstraps the User Proving Session, anchoring the initial state to a verified checkpoint and user leaf from the last finalized block and ensuring the session starts with clean debt trees and transaction counts.

---

### GUTA Gadgets (Global User Tree Aggregation)

These gadgets are components used within the circuits run by the decentralized proving network to aggregate proofs from multiple users into a single block proof.

#### `GUTAStatsGadget`

*   **File:** `guta_stats.rs`
*   **Purpose:** Represents and processes statistics aggregated during the GUTA process.
*   **Key Inputs/Witness:** `fees_collected`, `user_ops_processed`, `total_transactions`, `slots_modified`.
*   **Key Outputs/Computed Values:** Can compute a hash of the stats.
*   **Core Logic/Constraints:** Primarily a data structure. Includes a `combine_with` method to add stats from two gadgets together (used during aggregation). `to_hash` packs the stats into a `HashOutTarget`.
*   **Assumptions:** Assumes input target values are correct.
*   **Role:** Tracks key metrics about the aggregated user operations within a GUTA proof branch.

#### `GlobalUserTreeAggregatorHeaderGadget`

*   **File:** `guta_header.rs`
*   **Purpose:** Represents the public inputs (header) of a GUTA proof. It encapsulates the essential information about the aggregation step.
*   **Key Inputs/Witness:**
    *   `guta_circuit_whitelist`: Root hash of the allowed GUTA circuits.
    *   `checkpoint_tree_root`: Root hash of the checkpoint tree relevant to this aggregation step.
    *   `state_transition`: A `SubTreeNodeStateTransitionGadget` representing the change in the Global User Tree (`GUSR`) this proof covers.
    *   `stats`: A `GUTAStatsGadget` containing aggregated statistics.
*   **Key Outputs/Computed Values:** Computes the hash of the entire header.
*   **Core Logic/Constraints:** Data structure. `to_hash` computes the final header hash by combining hashes of `state_transition`, `stats`, `checkpoint_tree_root`, and `guta_circuit_whitelist`.
*   **Assumptions:** Assumes input targets/gadgets are correctly formed.
*   **Role:** Defines the standard public interface for all GUTA circuits, ensuring consistent information is passed and verified during recursive aggregation.

#### `VerifyEndCapProofGadget`

*   **File:** `verify_end_cap.rs`
*   **Purpose:** Verifies a user's End Cap proof within the GUTA aggregation process. It checks the proof's validity, ensures it used the correct End Cap circuit, verifies the user's claimed checkpoint root is historical, and extracts the state transition and stats.
*   **Key Inputs/Witness:**
    *   `proof_common_data`, `verifier_data_cap_height`: Parameters for proof verification.
    *   `known_end_cap_fingerprint_hash`: Constant representing the hash of the official End Cap circuit's verifier data.
    *   `UPSEndCapResultCompact`: Witness for the result claimed by the End Cap proof.
    *   `GUTAStats`: Witness for the stats claimed by the End Cap proof.
    *   `MerkleProofCore`: Witness for the historical checkpoint root proof.
    *   `ProofWithPublicInputs`: The End Cap proof itself.
    *   `VerifierOnlyCircuitData`: Verifier data matching the proof.
*   **Key Outputs/Computed Values:**
    *   (Implements `ToGUTAHeader`) Outputs a `GlobalUserTreeAggregatorHeaderGadget` representing the state transition performed by this user.
*   **Core Logic/Constraints:**
    *   Verifies the `proof_target` using the provided `verifier_data`.
    *   Computes the `proof_fingerprint` from the `verifier_data`.
    *   Asserts `proof_fingerprint` matches `known_end_cap_fingerprint_hash`.
    *   Instantiates `UPSEndCapResultCompactGadget` and `GUTAStatsGadget` from witness.
    *   Computes the expected public inputs hash by hashing the result and stats gadgets.
    *   Asserts the computed hash matches the hash derived from `proof_target.public_inputs`.
    *   Verifies the `checkpoint_historical_merkle_proof`, connecting its `historical_root` to the `checkpoint_tree_root_hash` from the end cap result gadget.
    *   Constructs the output `GlobalUserTreeAggregatorHeaderGadget`:
        *   Uses a default/input `guta_circuit_whitelist`.
        *   Uses the `current_root` from the historical proof as the `checkpoint_tree_root`.
        *   Creates a `SubTreeNodeStateTransitionGadget` using start/end user leaf hashes and user ID from the result gadget, marking the level as `GLOBAL_USER_TREE_HEIGHT`.
        *   Includes the verified `guta_stats`.
*   **Assumptions:** Assumes witness data (proofs, results, stats) is valid. Assumes `known_end_cap_fingerprint_hash` is correct.
*   **Role:** The entry point for incorporating a user's completed UPS into the GUTA aggregation tree. Verifies the user's session proof and translates its result into the standard GUTA header format for further aggregation.

#### `VerifyGUTAProofGadget`

*   **File:** `verify_guta_proof.rs`
*   **Purpose:** Verifies a GUTA proof generated by a lower level in the aggregation hierarchy. Checks the proof validity, ensures it used an allowed GUTA circuit, and extracts its header.
*   **Key Inputs/Witness:**
    *   `proof_common_data`, `verifier_data_cap_height`: Parameters.
    *   `GlobalUserTreeAggregatorHeader`: Witness for the header claimed by the proof being verified.
    *   `MerkleProof`: Witness proving the sub-proof's circuit fingerprint is in the GUTA circuit whitelist.
    *   `ProofWithPublicInputs`: The GUTA proof itself.
    *   `VerifierOnlyCircuitData`: Verifier data for the proof.
*   **Key Outputs/Computed Values:**
    *   `guta_proof_header_gadget`: The verified header gadget of the sub-proof.
*   **Core Logic/Constraints:**
    *   Verifies the `proof_target` using the provided `verifier_data`.
    *   Computes the `proof_fingerprint` from the `verifier_data`.
    *   Verifies the `guta_whitelist_merkle_proof`.
    *   Connects the `guta_proof_header_gadget.guta_circuit_whitelist` to the `guta_whitelist_merkle_proof.root`.
    *   Computes the expected public inputs hash from the `guta_proof_header_gadget`.
    *   Asserts this matches the hash derived from `proof_target.public_inputs`.
    *   Asserts the `guta_whitelist_merkle_proof.value` matches the computed `proof_fingerprint`.
*   **Assumptions:** Assumes witness data is valid.
*   **Role:** The core recursive verification step within GUTA. Allows aggregation circuits to securely incorporate results from lower-level GUTA proofs.

#### `TwoNCAStateTransitionGadget`

*   **File:** `two_nca_state_transition.rs`
*   **Purpose:** Combines the state transitions from two child GUTA proofs (`a_header`, `b_header`) that modify different parts of the Global User Tree. It uses a Nearest Common Ancestor (NCA) proof to compute the resulting state transition at their common parent node in the tree.
*   **Key Inputs/Witness:**
    *   `a_header`, `b_header`: The headers of the two child GUTA proofs.
    *   `UpdateNearestCommonAncestorProof`: Witness containing the NCA proof data.
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: The combined GUTA header representing the transition at the NCA.
*   **Core Logic/Constraints:**
    *   Instantiates `UpdateNearestCommonAncestorProofOptGadget`.
    *   Connects `a_header.checkpoint_tree_root` to `b_header.checkpoint_tree_root`.
    *   Connects `a_header.guta_circuit_whitelist` to `b_header.guta_circuit_whitelist`.
    *   Connects `a_header.state_transition` fields (old/new value, index, level) to the `child_a` fields in the NCA proof gadget.
    *   Connects `b_header.state_transition` fields similarly to `child_b`.
    *   Combines stats: `new_stats = a_header.stats.combine_with(b_header.stats)`.
    *   Constructs `new_guta_header`:
        *   Uses whitelist/checkpoint root from children (they must match).
        *   Creates `state_transition` using the `old/new_nearest_common_ancestor_value`, `index`, and `level` from the NCA proof gadget.
        *   Includes the `new_stats`.
*   **Assumptions:** Assumes input headers are valid (verified previously). Assumes the NCA proof witness is valid. Assumes children operate on the same checkpoint and whitelist.
*   **Role:** A fundamental building block for parallel aggregation. Allows merging results from independent branches of the GUTA proof tree efficiently using NCA proofs.

#### `GUTAHeaderLineProofGadget`

*   **File:** `guta_line.rs`
*   **Purpose:** Aggregates a GUTA proof state transition *upwards* along a direct line towards the root of the Global User Tree realm. Used when a node only has one child contributing to the update in that part of the tree.
*   **Key Inputs/Witness:**
    *   `global_user_tree_realm_height`, `global_user_tree_height`: Parameters.
    *   `child_proof_header`: The header of the single child GUTA proof.
    *   `siblings`: Witness containing the Merkle sibling hashes needed to recompute the root along the path.
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: The GUTA header representing the state transition at the top of the line (realm root).
*   **Core Logic/Constraints:**
    *   Instantiates `SubTreeNodeTopLineGadget`, providing the child's state transition. This gadget internally performs the Merkle path hashing using the provided siblings.
    *   Constructs `new_guta_header`:
        *   Copies whitelist/checkpoint root/stats from the child.
        *   Uses the `new_state_transition` computed by the `SubTreeNodeTopLineGadget`.
*   **Assumptions:** Assumes `child_proof_header` is valid. Assumes sibling hashes in the witness are correct.
*   **Role:** Efficiently propagates a state change up the GUTA tree when no merging (NCA) is required. Used to bring proofs to a common level before NCA or to reach the final realm root.

#### `VerifyGUTAProofToLineGadget`

*   **File:** `verify_guta_proof_to_line.rs`
*   **Purpose:** Combines verifying a lower-level GUTA proof with aggregating its state transition upwards using a line proof.
*   **Key Inputs/Witness:**
    *   `proof_common_data`, `verifier_data_cap_height`: Parameters.
    *   `global_user_tree_realm_height`, `global_user_tree_height`: Parameters.
    *   `MerkleProofCore`: GUTA whitelist proof witness.
    *   `GlobalUserTreeAggregatorHeader`: Child proof header witness.
    *   `ProofWithPublicInputs`, `VerifierOnlyCircuitData`: Child GUTA proof and verifier data witness.
    *   `top_line_siblings`: Sibling hashes for the line proof witness.
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: The final GUTA header at the top of the line.
*   **Core Logic/Constraints:**
    *   Instantiates `VerifyGUTAProofGadget` to verify the child proof.
    *   Instantiates `GUTAHeaderLineProofGadget`, using the verified header from the first gadget as input.
*   **Assumptions:** Relies on assumptions of sub-gadgets. Assumes witness data is valid.
*   **Role:** A common pattern in GUTA aggregation: verify a child proof and immediately propagate its result upwards via a line proof.

#### `GUTARegisterUserCoreGadget`

*   **File:** `guta_register_user_core.rs`
*   **Purpose:** Handles the core logic for registering a *single* new user in the Global User Tree (`GUSR`). It verifies the update proof that inserts the new user leaf.
*   **Key Inputs/Witness:**
    *   `global_user_tree_realm_height`, `global_user_tree_height`: Parameters.
    *   `default_user_state_tree_root`: Constant.
    *   `input_height_target`: Optional target for variable height proof.
    *   `public_key`: The public key hash for the new user (can be witness or input).
    *   `DeltaMerkleProofCore`: Witness for the `GUSR` tree update.
*   **Key Outputs/Computed Values:**
    *   `user_id`: The ID (index) of the newly registered user.
    *   `user_leaf_hash`: The hash of the newly created user leaf.
    *   `state_transition`: Represents the GUTA state transition for this single registration.
*   **Core Logic/Constraints:**
    *   Instantiates `VariableHeightDeltaMerkleProofOptGadget` for the `GUSR` update.
    *   Asserts the `old_value` in the proof is the zero hash (ensuring it's an insertion into an empty slot).
    *   Creates the default `PsyUserLeafGadget` using the proof's `index` (user ID), the `public_key`, and `default_user_state_tree_root`.
    *   Computes the `user_leaf_hash`.
    *   Asserts the `new_value` in the proof matches the computed `user_leaf_hash`.
    *   Calculates the `state_transition` based on the delta proof's old/new roots, height, and computed parent index.
*   **Assumptions:** Assumes witness proof and public key (if witness) are valid. Assumes `default_user_state_tree_root` is correct.
*   **Role:** The lowest-level gadget for handling user registration state changes in GUTA.

#### `GUTARegisterUserFullGadget`

*   **File:** `guta_register_user_full.rs`
*   **Purpose:** Extends the core registration by adding verification against a *user registration tree*. This tree (presumably managed off-chain or via a separate mechanism) maps user IDs to public keys. This gadget ensures the public key used for registration matches the one committed to in the registration tree.
*   **Key Inputs/Witness:**
    *   (Inherits inputs from Core gadget).
    *   `MerkleProofCore`: Witness proving the `public_key` exists at the correct `index` (user ID) in the `user_registration_tree`.
*   **Key Outputs/Computed Values:**
    *   (Inherits outputs from Core gadget).
    *   `user_registration_tree_root`: The root of the user registration tree.
*   **Core Logic/Constraints:**
    *   Instantiates `MerkleProofGadget` for the user registration tree.
    *   Maps the proof's index bits to an expected user ID.
    *   Asserts the `value` (public key) from the registration tree proof is non-zero.
    *   Instantiates `GUTARegisterUserCoreGadget`, passing the `value` from the registration proof as the `public_key`.
    *   Asserts the `user_id` from the Core gadget matches the `expected_user_id` derived from the registration proof index.
*   **Assumptions:** Relies on Core gadget assumptions. Assumes the user registration tree proof witness is valid.
*   **Role:** Adds a layer of validation, ensuring user registrations correspond to pre-committed public keys in a dedicated registration structure.

#### `GUTARegisterUsersGadget`

*   **File:** `guta_register_users.rs`
*   **Purpose:** Aggregates multiple user registration operations (using `GUTARegisterUserFullGadget`) sequentially within a single circuit. Handles padding/disabling for a fixed maximum number of users.
*   **Key Inputs/Witness:**
    *   (Inherits inputs from Full gadget).
    *   `max_users`: Parameter.
    *   `GUTARegisterUserFullInput[]`: Array witness for each potential user registration (proofs).
    *   `register_user_count`: Witness target indicating the *actual* number of users being registered (<= `max_users`).
*   **Key Outputs/Computed Values:**
    *   `state_transition`: The aggregate state transition covering all registered users.
    *   `user_registration_tree_root`: Root of the registration tree (taken from the first user, checked for consistency).
*   **Core Logic/Constraints:**
    *   Instantiates `max_users` instances of `GUTARegisterUserFullGadget`.
    *   Asserts `register_user_count` is non-zero.
    *   Iterates from the second user onwards:
        *   Compares loop index `i` with `register_user_count` to determine if the current user slot `is_disabled`.
        *   If *not* disabled:
            *   Connects the current user's `old_global_user_tree_root` to the previous user's `new_global_user_tree_root`.
            *   Connects the current user's `user_registration_tree_root` to the root from the first user (ensuring consistency).
            *   Connects proof heights.
            *   Updates the aggregate `state_transition.new_node_value` to the current user's `new_global_user_tree_root`.
        *   Selects the final `new_node_value` based on the last *enabled* user's output.
*   **Assumptions:** Relies on Full gadget assumptions. Assumes witness array and count are valid. Assumes dummy inputs are used correctly for padding.
*   **Role:** Allows batching multiple user registrations into a single GUTA proof step, improving aggregation efficiency.

#### `GUTAOnlyRegisterUsersGadget`

*   **File:** `guta_only_register_users_gadget.rs`
*   **Purpose:** A specialized GUTA gadget that *only* performs user registration (using `GUTARegisterUsersGadget`) and assumes *no other state changes* (zero stats).
*   **Key Inputs/Witness:**
    *   `guta_circuit_whitelist`, `checkpoint_tree_root`: Inputs (likely from a previous step or constant).
    *   (Inherits inputs for `GUTARegisterUsersGadget`).
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: The GUTA header representing *only* the registration state change.
*   **Core Logic/Constraints:**
    *   Instantiates `GUTARegisterUsersGadget`.
    *   Constructs `new_guta_header`:
        *   Uses input `guta_circuit_whitelist` and `checkpoint_tree_root`.
        *   Uses the `state_transition` from the `GUTARegisterUsersGadget`.
        *   Creates a zeroed `GUTAStatsGadget`.
*   **Assumptions:** Relies on `GUTARegisterUsersGadget` assumptions. Assumes the provided whitelist/checkpoint roots are correct for this context.
*   **Role:** Provides a dedicated gadget for GUTA steps that solely involve registering new users.

#### `GUTARegisterUsersBatchGadget`

*   **File:** `guta_register_users_batch.rs`
*   **Purpose:** Combines verification of a previous GUTA proof (brought up to a certain tree level via a line proof) with a subsequent batch registration of new users.
*   **Key Inputs/Witness:**
    *   (Inherits inputs for `VerifyGUTAProofToLineGadget`).
    *   (Inherits inputs for `GUTARegisterUsersGadget`).
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: The combined GUTA header.
*   **Core Logic/Constraints:**
    *   Instantiates `VerifyGUTAProofToLineGadget` (`verify_to_line_gadget`).
    *   Instantiates `GUTARegisterUsersGadget` (`register_users_gadget`).
    *   Connects the state transitions:
        *   `line_state_transition.node_index` == `register_users_state_transiton.node_index`.
        *   `line_state_transition.node_level` == `register_users_state_transiton.node_level`.
        *   `line_state_transition.new_node_value` == `register_users_state_transiton.old_node_value` (ensures the registration starts from the state reached by the verified line proof).
    *   Constructs `new_guta_header`:
        *   Uses whitelist/checkpoint root/stats from the line proof header.
        *   Creates combined `state_transition`: `old_node_value` from line, `new_node_value` from registration, index/level from line (must match registration).
*   **Assumptions:** Relies on assumptions of sub-gadgets. Assumes witness data is valid.
*   **Role:** Handles a common GUTA pattern: verifying a previous aggregation step and then applying a batch of user registrations originating from the state achieved by that previous step.

#### `GUTANoChangeGadget`

*   **File:** `guta_no_change_gadget.rs`
*   **Purpose:** Represents a GUTA step where the Global User Tree (`GUSR`) does *not* change. It primarily serves to advance the `checkpoint_tree_root` based on a new checkpoint.
*   **Key Inputs/Witness:**
    *   `guta_circuit_whitelist`: Input constant/parameter.
    *   `checkpoint_tree_height`: Parameter.
    *   `MerkleProofCore`: Witness proving a `checkpoint_leaf` exists in the `checkpoint_tree`.
    *   `PsyCheckpointLeafCompactWithStateRoots`: Witness for the checkpoint leaf data.
*   **Key Outputs/Computed Values:**
    *   `new_guta_header`: GUTA header indicating no user tree change but potentially a new checkpoint root.
*   **Core Logic/Constraints:**
    *   Verifies the `checkpoint_tree_proof` (append-only).
    *   Verifies the hash of `checkpoint_leaf_gadget` matches the `value` in the proof.
    *   Constructs `new_guta_header`:
        *   Uses input `guta_circuit_whitelist`.
        *   Uses the `checkpoint_tree_proof.root` as the `checkpoint_tree_root`.
        *   Creates a "no-op" `state_transition`: `old_node_value` and `new_node_value` are both set to the `user_tree_root` from the `checkpoint_leaf_gadget`, with index/level zero.
        *   Creates a zeroed `GUTAStatsGadget`.
*   **Assumptions:** Assumes witness proof and leaf data are valid. Assumes `guta_circuit_whitelist` is correct.
*   **Role:** Allows the GUTA aggregation to incorporate new checkpoints even if no user state changed during that period, keeping the aggregated checkpoint root up-to-date.

---

### Circuit Definition Files (Higher Level)

These files define complete ZK circuits, orchestrating various gadgets to perform end-to-end tasks like starting a session, processing transactions, or finalizing a session.

#### `UPSStartSessionCircuit`

*   **File:** `ups_start.rs` (Circuit definition wrapping `UPSStartStepGadget`)
*   **Purpose:** The circuit executed to begin a User Proving Session.
*   **Core Logic:** Primarily uses the `UPSStartStepGadget` to verify the initial state against a checkpoint and set up the starting header. Computes the final public inputs hash by wrapping the inner header hash (`start_step_gadget.header_gadget.to_hash()`) with tree awareness information (using `compute_tree_aware_proof_public_inputs`), assuming the proof tree starts empty (`empty_ups_proof_tree_root_target`).
*   **What it Proves:** That a valid starting `UserProvingSessionHeader` has been constructed, correctly anchored to a specific, verified checkpoint and user leaf state from the last finalized block, and that the session starts with empty debt trees and zero transaction count.
*   **Assumptions:** Assumes the witness (`UPSStartStepInput`) containing the starting header, proofs, and state roots is valid *before* constraints are applied. Assumes the provided `empty_ups_proof_tree_root` constant is correct.
*   **Role:** Securely initializes the recursive proof chain for a user's local transactions.

#### `UPSCFCStandardTransactionCircuit`

*   **File:** `ups_cfc_standard.rs` (Circuit definition wrapping `VerifyPreviousUPSStepProofInProofTreeGadget` and `UPSVerifyCFCStandardStepGadget`)
*   **Purpose:** Processes a single, standard Contract Function Call (CFC) transaction within an ongoing User Proving Session.
*   **Core Logic:**
    *   Uses `VerifyPreviousUPSStepProofInProofTreeGadget` to verify the proof of the *previous* UPS step.
    *   Uses `UPSVerifyCFCStandardStepGadget` (which internally uses verification and state delta gadgets) to:
        *   Verify the CFC proof exists in the current proof tree.
        *   Verify the CFC function is valid.
        *   Calculate the state changes based on the CFC execution.
    *   Connects the `current_proof_tree_root` from the previous step verification to the standard step gadget.
    *   Computes the final public inputs hash by wrapping the *new* header hash (`standard_cfc_step_gadget.new_header_gadget.to_hash()`) with tree awareness information (`current_proof_tree_root`).
*   **What it Proves:** That given a valid previous UPS step proof and header, executing the specified CFC transaction (verified to exist and be valid) correctly transitions the UPS state to the new header state.
*   **Assumptions:** Assumes the witness (`UPSCFCStandardTransactionCircuitInput`) containing the previous step proof details, the current transaction details (proofs, context), and circuit whitelist proofs is valid. Relies on the validity of the previous UPS step proof (which is verified internally).
*   **Role:** The workhorse circuit for processing most user transactions locally within the recursive UPS chain.

#### `UPSCFCDeferredTransactionCircuit`

*   **File:** `ups_cfc_deferred_tx.rs` (Circuit definition wrapping `VerifyPreviousUPSStepProofInProofTreeGadget` and `UPSVerifyPopDeferredTxStepGadget`)
*   **Purpose:** Processes a transaction that pays back a deferred transaction debt within an ongoing User Proving Session.
*   **Core Logic:**
    *   Uses `VerifyPreviousUPSStepProofInProofTreeGadget` to verify the previous UPS step proof.
    *   Uses `UPSVerifyPopDeferredTxStepGadget` to:
        *   Verify the removal of the correct deferred transaction item from the debt tree.
        *   Process the CFC itself using corrected starting state assumptions.
    *   Connects the `current_proof_tree_root` appropriately.
    *   Computes the final public inputs hash by wrapping the new header hash (`deferred_tx_cfc_step_gadget...new_header_gadget.to_hash()`) with tree awareness information.
*   **What it Proves:** That given a valid previous UPS step, the specified deferred transaction debt was correctly removed, and executing the corresponding CFC transaction correctly transitions the UPS state to the new header state.
*   **Assumptions:** Assumes the witness (`UPSCFCDeferredTransactionCircuitInput`) is valid. Relies on the validity of the previous UPS step proof.
*   **Role:** Enables the settlement of deferred transaction debts within the user's local proof chain.

#### `UPSStandardEndCapCircuit`

*   **File:** `end_cap.rs` (Circuit definition wrapping `UPSEndCapFromProofTreeGadget` and proof verification gadgets)
*   **Purpose:** The final circuit in a User Proving Session. It verifies the last UPS step, verifies the user's ZK signature proof, enforces final state conditions (e.g., empty debt trees), and generates the final public outputs (End Cap Result hash and GUTA Stats hash).
*   **Core Logic:**
    *   Uses `UPSEndCapFromProofTreeGadget` which orchestrates:
        *   Verification of the *last* UPS step proof (`VerifyPreviousUPSStepProofInProofTreeGadget`).
        *   Verification of the ZK signature proof (`AttestProofInTreeGadget`).
        *   Enforcement of final conditions via `UPSEndCapCoreGadget`.
    *   *(Original `end_cap.rs` also includes `VerifyAggProofGadget`)*: Verifies a proof about the UPS proof tree itself (e.g., ensuring the tree was built using allowed aggregation circuits). This connects the user's session to the global proof aggregation infrastructure rules.
    *   Connects the proof tree root from the UPS gadget to the state transition end of the verified aggregation proof.
    *   Connects the UPS circuit whitelist root from the UPS gadget to a known constant or input, ensuring the UPS steps used allowed circuits.
    *   Connects the proof tree aggregation circuit whitelist root to a known constant (ensuring the tree proof used allowed circuits).
    *   Computes the final public inputs hash by hashing the `end_cap_result_gadget` hash and the `guta_stats` hash.
*   **What it Proves:** That the entire User Proving Session was valid (by verifying the last step), the final state is consistent (empty debts, correct nonce/checkpoint progression), the session is authorized by a valid ZK signature corresponding to the user's key, the session used allowed UPS circuits, and the session's proof tree was built correctly using allowed aggregation circuits. It outputs the final state transition hash and stats hash.
*   **Assumptions:** Assumes the witness (`UPSEndCapFromProofTreeGadgetInput`, aggregation proof witnesses) is valid. Assumes the known whitelist root constants are correct.
*   **Role:** Securely concludes the user's local proving session, producing a verifiable proof and result ready for submission to the GUTA layer. Links the user's activity to global rules via whitelist checks.

---
---

## `Circuits.md`

This document describes the end-to-end flow of circuits involved in processing user transactions and aggregating them into a final block proof within the Psy system. It highlights the assumptions made at each stage and how they are progressively verified, ultimately enabling horizontal scalability.

### Phase 1: User Proving Session (UPS) - Local Execution

This phase happens locally on the user's device (or via a delegated prover). The user builds a recursive chain of proofs for their transactions within a single block context.

**1. `UPSStartSessionCircuit`**

*   **Purpose:** Initializes the proving session for a user based on the last finalized blockchain state.
*   **What it Proves:**
    *   The starting `UserProvingSessionHeader` is valid.
    *   This header is correctly anchored to a specific `checkpoint_leaf_hash` which exists at `checkpoint_id` within the `checkpoint_tree_root` from the *last finalized block*.
    *   The `session_start_context` within the header accurately reflects the user's state (`start_session_user_leaf_hash`, `user_id`, etc.) as found in the `user_tree_root` associated with the starting checkpoint.
    *   The `current_state` within the starting header is correctly initialized (user leaf `last_checkpoint_id` updated, debt trees empty, tx count/stack zero).
*   **Assumptions:**
    *   The witness data (`UPSStartStepInput`) provided by the user (fetching state from the last block) is correct *initially*. Constraints verify its consistency.
    *   The constant `empty_ups_proof_tree_root` (representing the start of the recursive proof tree for this session) is correct.
*   **How Assumptions are Discharged:** Internal consistency checks verify the relationships between the provided header, checkpoint leaf, state roots, user leaf, and the Merkle proofs linking them. The assumption about the *previous block's* `checkpoint_tree_root` being correct is implicitly carried forward, as this circuit uses it as the basis for initialization.
*   **Contribution to Horizontal Scalability:** Establishes a user-specific, isolated starting point based on globally finalized state, allowing this session to proceed independently of other users' sessions within the *same* new block.
*   **High-Level Functionality:** Securely starts a user's transaction batch processing.

**2. `UPSCFCStandardTransactionCircuit` (Executed potentially multiple times)**

*   **Purpose:** Processes a single standard transaction (contract call) within the user's ongoing session, extending the recursive proof chain.
*   **What it Proves:**
    *   The ZK proof for the *previous UPS step* is valid.
    *   The previous step's proof was generated by a circuit listed in the `ups_circuit_whitelist_root` specified in the previous step's header.
    *   The public inputs (header hash) of the previous step's proof match the provided `previous_step_header`.
    *   The ZK proof for the *current Contract Function Call (CFC)* exists within the current `current_proof_tree_root`.
    *   This CFC proof corresponds to a function registered in the `GCON` tree (via checkpoint context).
    *   Executing this CFC correctly transitions the state from the `previous_step_header` to the `new_header_gadget` state (updating `CSTATE`->`UCON` root, debt trees, tx count/stack).
*   **Assumptions:**
    *   The witness data (`UPSCFCStandardTransactionCircuitInput`) for this specific step (CFC proof, state delta witnesses, previous step proof info) is correct initially.
    *   The `current_proof_tree_root` provided matches the actual root of the recursive proof tree being built.
*   **How Assumptions are Discharged:**
    *   Verifies the previous step's proof using `VerifyPreviousUPSStepProofInProofTreeGadget`. This discharges the assumption about the previous step's validity and its public inputs.
    *   Verifies the CFC proof and its link to the contract state using `UPSVerifyCFCStandardStepGadget`.
    *   Verifies the state delta logic, ensuring the transition is correct based on witness data.
    *   The assumption about the `current_proof_tree_root` is passed implicitly to the *next* step or the End Cap circuit.
*   **Contribution to Horizontal Scalability:** User processes transactions locally and serially *for themselves*, maintaining self-consistency without interacting with other users' *current* block activity.
*   **High-Level Functionality:** Securely executes and proves individual smart contract interactions locally.

**3. `UPSCFCDeferredTransactionCircuit` (Executed if applicable)**

*   **Purpose:** Processes a transaction that settles a deferred debt, then executes the main CFC logic.
*   **What it Proves:** Similar to the standard circuit, but *additionally* proves:
    *   A specific deferred transaction item was removed from the `deferred_tx_debt_tree`.
    *   The item removed corresponds exactly to the call data of the CFC being executed.
    *   The subsequent CFC state transition starts from the state *after* the debt was removed.
*   **Assumptions:** Same as the standard circuit, plus assumes the witness for the deferred transaction removal proof (`DeltaMerkleProofGadget`) is correct initially.
*   **How Assumptions are Discharged:** Verifies previous step proof. Verifies the debt removal proof and its consistency with the CFC call data. Verifies the subsequent state delta.
*   **Contribution to Horizontal Scalability:** Same as standard transaction circuit (local serial execution).
*   **High-Level Functionality:** Enables settlement of asynchronous transaction debts within the local proving flow.

**4. `UPSStandardEndCapCircuit`**

*   **Purpose:** Finalizes the user's entire proving session for the block.
*   **What it Proves:**
    *   The proof for the *last UPS transaction step* is valid and used an allowed circuit.
    *   The ZK proof for the user's signature (authorizing the session) is valid and exists in the same UPS proof tree.
    *   The signature corresponds to the user's registered public key (derived from signature proof parameters).
    *   The signature payload (`PsyUserProvingSessionSignatureDataCompact`) correctly reflects the session's start/end user leaves, checkpoint, final tx stack, and tx count.
    *   The nonce used in the signature is valid (incremented).
    *   The final UPS state shows both `deferred_tx_debt_tree_root` and `inline_tx_debt_tree_root` are empty (all debts settled).
    *   The `last_checkpoint_id` in the final user leaf matches the session's `checkpoint_id` and has progressed correctly.
    *   *(If aggregation proof verification included):* The UPS proof tree itself was constructed using circuits from a known `proof_tree_circuit_whitelist_root`.
*   **Assumptions:**
    *   Witness data (`UPSEndCapFromProofTreeGadgetInput`, potentially agg proof witness) is correct initially.
    *   Known constants (`network_magic`, empty debt roots, `known_ups_circuit_whitelist_root`, `known_proof_tree_circuit_whitelist_root`) are correct.
*   **How Assumptions are Discharged:**
    *   Verifies the last UPS step proof.
    *   Verifies the ZK signature proof.
    *   Connects signature data to the final UPS header state.
    *   Checks nonce, checkpoint ID, empty debt trees.
    *   Verifies proofs against whitelists using provided roots.
    *   The *output* of this circuit (the End Cap proof) now implicitly carries the assumption that the *starting* `checkpoint_tree_root` (used in the `UPSStartSessionCircuit`) was correct. All *internal* UPS assumptions have been discharged.
*   **Contribution to Horizontal Scalability:** Creates a single, verifiable proof representing *all* of a user's activity for the block. This proof can now be processed in parallel with proofs from other users by the GUTA layer.
*   **High-Level Functionality:** Securely concludes a user's transaction batch, authorizes it, and packages it for network aggregation.

### Phase 2: Global User Tree Aggregation (GUTA) - Parallel Network Execution

The Decentralized Proving Network (DPN) takes End Cap proofs (and potentially other GUTA proofs like user registrations) from many users and aggregates them in parallel. This involves specialized GUTA circuits.

*(Note: The provided files focus heavily on UPS and GUTA *gadgets*. The exact structure of the GUTA circuits using these gadgets is inferred but follows standard recursive proof aggregation patterns.)*

**Example GUTA Circuits (Inferred):**

**5. `GUTAProcessEndCapCircuit` (Hypothetical)**

*   **Purpose:** To take a user's validated `UPSStandardEndCapCircuit` proof and integrate its state change into the GUTA proof hierarchy.
*   **Core Logic:** Uses `VerifyEndCapProofGadget`.
*   **What it Proves:**
    *   The End Cap proof is valid and used the correct circuit (`known_end_cap_fingerprint_hash`).
    *   The `checkpoint_tree_root` claimed by the user in the End Cap result existed historically.
    *   Outputs a standard `GlobalUserTreeAggregatorHeader` representing the user's `GUSR` tree state transition (start leaf hash -> end leaf hash at the user's ID index) and stats.
*   **Assumptions:**
    *   Witness (End Cap proof, result, stats, historical proof) is correct initially.
    *   The `known_end_cap_fingerprint_hash` constant is correct.
    *   A `default_guta_circuit_whitelist` root is provided or known.
*   **How Assumptions are Discharged:** Verifies the End Cap proof and historical checkpoint proof. Packages the result into a standard GUTA header. The assumption about the `default_guta_circuit_whitelist` is passed upwards. The assumption about the *current* `checkpoint_tree_root` (from the historical proof) is passed upwards.
*   **Contribution to Horizontal Scalability:** Allows individual user session results to be verified independently and prepared for parallel aggregation.
*   **High-Level Functionality:** Validates and incorporates user end-of-session proofs into the global aggregation process.

**6. `GUTARegisterUserCircuit` (Hypothetical)**

*   **Purpose:** To process the registration of one or more new users.
*   **Core Logic:** Uses `GUTAOnlyRegisterUsersGadget` (which uses `GUTARegisterUsersGadget`, `GUTARegisterUserFullGadget`, `GUTARegisterUserCoreGadget`).
*   **What it Proves:**
    *   For each registered user, their `public_key` was correctly inserted at their `user_id` index in the `GUSR` tree (transitioning from zero hash to the new user leaf hash).
    *   The `public_key` used matches an entry in the `user_registration_tree_root`.
    *   Outputs a `GlobalUserTreeAggregatorHeader` representing the aggregate `GUSR` state transition for all registered users, with zero stats.
*   **Assumptions:**
    *   Witness (registration proofs, user count) is correct initially.
    *   `guta_circuit_whitelist` and `checkpoint_tree_root` inputs are correct for this context.
    *   `default_user_state_tree_root` constant is correct.
*   **How Assumptions are Discharged:** Verifies delta proofs for `GUSR` insertion and Merkle proofs against the registration tree. Outputs a standard GUTA header, passing assumptions about whitelist/checkpoint upwards.
*   **Contribution to Horizontal Scalability:** User registration can be batched and potentially processed in parallel branches of the GUTA tree.
*   **High-Level Functionality:** Securely adds new users to the system state.

**7. `GUTAAggregationCircuit` (Hypothetical - Multiple Variants)**

*   **Purpose:** To combine the results (headers) from two or more lower-level GUTA proofs (which could be End Cap results, registrations, or previous aggregations).
*   **Core Logic:**
    *   Verifies each input GUTA proof using `VerifyGUTAProofGadget`.
    *   Ensures all input proofs used circuits from the same `guta_circuit_whitelist` and reference the same `checkpoint_tree_root`.
    *   Combines the `state_transition`s from the input proofs:
        *   If transitions are on different branches, uses `TwoNCAStateTransitionGadget` with an NCA proof.
        *   If transitions are on the same branch (e.g., one input is a line proof output), connects them directly (`old_root` of current matches `new_root` of previous).
        *   If only one input, uses `GUTAHeaderLineProofGadget` to propagate upwards.
    *   Combines the `stats` from input proofs using `GUTAStatsGadget.combine_with`.
    *   Outputs a single `GlobalUserTreeAggregatorHeader` representing the combined state transition and stats.
*   **What it Proves:** That given valid input GUTA proofs operating under the same whitelist and checkpoint context, the combined state transition and stats represented by the output header are correct.
*   **Assumptions:**
    *   Witness (input proofs, headers, NCA/sibling proofs) is correct initially.
*   **How Assumptions are Discharged:** Verifies input proofs and their headers. Verifies the logic of combining state transitions (NCA/Line/Direct). Passes the common whitelist/checkpoint root assumptions upwards.
*   **Contribution to Horizontal Scalability:** This is the core of parallel aggregation. Multiple instances of this circuit run concurrently across the DPN, merging proof branches in a tree structure (like MapReduce).
*   **High-Level Functionality:** Securely and recursively combines verified state changes from multiple sources into larger, aggregated proofs.

**8. `GUTANoChangeCircuit` (Hypothetical)**

*   **Purpose:** To handle cases where no user state changed but the checkpoint advanced.
*   **Core Logic:** Uses `GUTANoChangeGadget`.
*   **What it Proves:** That given a new `checkpoint_leaf` verified to be in the `checkpoint_tree_proof`, the `GUSR` tree root remains unchanged, and stats are zero. Outputs a GUTA header reflecting this.
*   **Assumptions:** Witness (checkpoint proof, leaf) is correct initially. Input `guta_circuit_whitelist` is correct.
*   **How Assumptions are Discharged:** Verifies checkpoint proof. Outputs a standard GUTA header passing assumptions upward.
*   **Contribution to Horizontal Scalability:** Allows the aggregation process to stay synchronized with the checkpoint tree even during periods of inactivity for certain state trees.
*   **High-Level Functionality:** Advances the aggregated checkpoint state reference.

### Phase 3: Final Block Proof

**9. Checkpoint Tree "Block" Circuit (Top-Level Aggregation)**

*   **Purpose:** The final aggregation circuit that combines proofs from the roots of all major state trees (like `GUSR` via the top-level GUTA proof, `GCON`, etc.) for the block.
*   **Core Logic:**
    *   Verifies the top-level GUTA proof (and proofs for other top-level trees if applicable).
    *   Takes the *previous block's* finalized `CHKP` root as a public input.
    *   Constructs the new `CHKP` leaf based on the newly computed roots of `GUSR`, `GCON`, etc., and other block metadata.
    *   Computes the new `CHKP` root.
    *   The *only* external assumption verified here is that the input `previous_block_chkp_root` matches the actual finalized root of the last block.
*   **What it Proves:** That the entire state transition for the block, represented by the change from the `previous_block_chkp_root` to the `new_chkp_root`, is valid, having recursively verified all constituent user transactions and aggregations according to protocol rules and circuit whitelists.
*   **Assumptions:** The *only* remaining input assumption is the hash of the previous block's `CHKP` root.
*   **How Assumptions are Discharged:** All assumptions from lower levels (circuit whitelists, internal state consistencies) have been verified recursively. The final link to the previous block state is checked against the public input.
*   **Contribution to Horizontal Scalability:** Represents the culmination of the massively parallel aggregation process, producing a single, succinct proof for the entire block's validity.
*   **High-Level Functionality:** Creates the final, verifiable proof of state transition for the entire block, linking it cryptographically to the previous block. This proof can be efficiently verified by any node or light client.