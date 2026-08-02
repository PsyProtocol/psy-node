# User Proving Session (UPS) Gadgets

These gadgets are primarily used within the circuits executed locally by users (or their delegates) to prove their transaction sequences.

---

### `CorrectUPSHeaderHashesGadget`

*   **File:** `correct_header_hashes_rs.txt`
*   **Purpose:** A data structure gadget to hold potentially *modified* starting debt tree roots for a UPS step. Used when a transaction (like debt repayment) needs to alter the context *before* the main state delta logic of that same step runs.
*   **Technical Function:** Stores `previous_step_deferred_tx_debt_tree_root` and `previous_step_inline_tx_debt_tree_root`. These values can override the corresponding roots from the actual previous step's header when passed into gadgets like `UPSCFCStandardStateDeltaGadget`.
*   **Inputs/Witness:** Takes a reference to the previous step's `UserProvingSessionHeaderGadget`.
*   **Outputs/Computed:** The overridden hash targets.
*   **Constraints:** None internally; constraints are applied where its output values are consumed.
*   **Assumptions:** Assumes the input `previous_step` header is correctly formed (though its values might be overridden).
*   **Role:** Enables flexible ordering of operations within a single UPS step, specifically allowing debt tree modifications (like popping an item) to be accounted for before the main transaction logic uses those trees.

---

### `UPSVerifyCFCProofExistsAndValidGadget`

*   **File:** `ups_cfc_verify_inclusion_rs.txt`
*   **Purpose:** Verifies two critical aspects of a Contract Function Call (CFC) within a UPS: (1) That the ZK proof for the CFC execution exists and is valid within the user's current UPS proof tree, and (2) That the specific function being called is officially registered within the contract's definition on the blockchain (via checkpoint context).
*   **Technical Function:** Combines proof attestation within the UPS tree with function inclusion verification against global contract state.
*   **Inputs/Witness:**
    *   `checkpoint_state_gadget`: Witness for `PsyCheckpointLeafCompactWithStateRoots` providing context (global roots).
    *   `verify_cfc_proof_gadget`: Witness (`AttestTreeAwareProofInTreeInput`) for the CFC proof itself, including its Merkle proof within the `session_proof_tree`.
    *   `cfc_inclusion_proof_gadget`: Witness (`PsyContractFunctionInclusionProof`) proving the function's fingerprint exists in the contract's function tree (`CFT`).
    *   `ups_session_proof_tree_height`: Parameter.
*   **Outputs/Computed:**
    *   `attested_proof_tree_root`: Root of the UPS session proof tree containing the CFC proof.
    *   `checkpoint_leaf_hash`: Hash of the contextual checkpoint leaf.
    *   `cfc_fingerprint`: The verified fingerprint (verifier data hash) of the CFC circuit.
    *   `cfc_inner_public_inputs_hash`: Hash of the CFC proof's *original* public inputs (before tree awareness wrapping).
    *   `cfc_contract_id`, `cfc_method_id`, `cfc_num_inputs`, `cfc_num_outputs`: Metadata extracted from the function inclusion proof.
*   **Constraints:**
    *   Verifies CFC proof validity and inclusion in the session tree via `AttestTreeAwareProofInTreeGadget`.
    *   Verifies function inclusion in the contract's `CFT` via `PsyContractFunctionInclusionProofGadget`.
    *   Connects `cfc_inclusion_proof.contract_inclusion_proof.contract_tree_merkle_proof.root` to `checkpoint_state_gadget.global_state_roots.contract_tree_root` (ensuring CFC inclusion is checked against the correct global contract state).
    *   Connects `cfc_inclusion_proof.function_verifier_fingerprint` to `verify_cfc_proof_gadget.fingerprint` (ensuring the proven function matches the verified CFC circuit).
*   **Assumptions:** Assumes witness data (proofs, state, inclusion proofs) is valid initially. Assumes `ups_session_proof_tree_height` is correct.
*   **Role:** Acts as a crucial security gate within UPS, ensuring that the user is proving the execution of a legitimate, registered smart contract function and that this execution proof is part of their current, consistent session proof sequence.

---

### `UPSCFCStandardStateDeltaGadget`

*   **File:** `ups_standard_cfc_state_delta_rs.txt`
*   **Purpose:** Calculates the precise changes to the user's state (`UserProvingSessionHeader`) resulting from a single, standard CFC transaction. It enforces the consistency between the transaction's claimed effects (witnessed context) and the cryptographic updates to the relevant Merkle trees.
*   **Technical Function:** Verifies delta/pivot proofs for state updates and computes the next header state.
*   **Inputs/Witness:**
    *   `previous_step_header_gadget`: Header state *before* this transaction.
    *   `corrections`: Optional `CorrectUPSHeaderHashesGadget` to override starting debt tree roots.
    *   `contract_state_tree_height`: Target specifying the height of the specific `CSTATE` tree being modified.
    *   `UPSCFCStandardStateDeltaInput`: Witness containing:
        *   `cfc_transaction_input_context`: Start (`transaction_call_start_ctx`) and end (`transaction_end_ctx`) contexts claimed by the CFC execution.
        *   `user_contract_tree_update_proof`: `DeltaMerkleProofCore` showing the change to the user's `UCON` tree (updating the root hash for the specific `contract_id`).
        *   `deferred_tx_debt_pivot_proof`, `inline_tx_debt_pivot_proof`: `MerkleProofCore` showing the start and end roots of the debt trees remain consistent (pivot proofs).
*   **Outputs/Computed:**
    *   `(Self, UserProvingSessionHeaderGadget)`: Returns the gadget instance and the *new* header state after applying the delta.
    *   `cfc_inner_public_inputs_hash`: Hash of the `cfc_transaction_input_context` (used for linking to verification).
    *   `cfc_contract_id`, `cfc_method_id`, etc.: Metadata passed through.
*   **Constraints:**
    *   **CFC Context Hash:** Computes `cfc_inner_public_inputs_hash` from witness.
    *   **UCON Update:** Verifies `user_contract_tree_update_proof`:
        *   `old_root` matches `previous_step_header.current_state.user_leaf.user_state_tree_root`.
        *   `index` matches `cfc_transaction_input_context...contract_id`.
        *   `old_value` consistency check: If zero, ensures `start_ctx.start_contract_state_tree_root` matches the *default* zero hash for the given `contract_state_tree_height`. If non-zero, ensures it matches `start_ctx.start_contract_state_tree_root`.
        *   `new_value` matches `end_ctx.end_contract_state_tree_root`.
    *   **Debt Tree Pivots:** Verifies `deferred/inline_tx_debt_pivot_proof`:
        *   `historical_root` matches the *corrected* previous step debt root (from `previous_step_header` or `corrections`).
        *   `current_root` matches the `end_ctx.end_deferred/inline_tx_debt_tree_root`.
    *   **Start State Consistency:** Connects `start_ctx` fields (balance, event index, debt roots) to the corresponding fields in the (potentially corrected) `previous_step_header`.
    *   **Counters & Stack:** Increments `tx_count`. Pushes hash of `TransactionLogStackItemGadget` onto `tx_hash_stack` using `SimpleHashStackGadget`.
    *   **Construct New Header:** Creates the output `UserProvingSessionHeaderGadget` with updated roots, counts, stack, and user leaf values (balance/event index updated based on `end_ctx`). *Note: Currently balance/event updates are disabled via constraints.*
*   **Assumptions:** Assumes witness proofs and contexts are valid initially. Assumes `previous_step_header` and `corrections` are correctly provided.
*   **Role:** The core state transition engine for UPS. It cryptographically enforces that the claimed effects of a CFC execution (start/end states) are correctly reflected in the updates to the user's persistent state trees (`UCON`, debt trees) and session metadata (tx count/stack).

---

### `UPSVerifyCFCStandardStepGadget`

*   **File:** `ups_cfc_standard_rs.txt`
*   **Purpose:** Encapsulates a complete, standard transaction processing step within UPS. It combines the verification of the CFC proof's existence and validity with the calculation and verification of the resulting state delta.
*   **Technical Function:** Orchestrates `UPSVerifyCFCProofExistsAndValidGadget` and `UPSCFCStandardStateDeltaGadget`, connecting their inputs and outputs to ensure consistency.
*   **Inputs/Witness:**
    *   `previous_step_header_gadget`: Header state before this step.
    *   `current_proof_tree_root`: Root of the UPS proof tree this step belongs to.
    *   `ups_session_proof_tree_height`: Parameter.
    *   `UPSVerifyCFCStandardStepInput`: Witness containing inputs for both sub-gadgets.
*   **Outputs/Computed:**
    *   `new_header_gadget`: The header state *after* this transaction step.
*   **Constraints:**
    *   Instantiates the verification and state delta sub-gadgets.
    *   `verify_cfc_exists_and_valid_gadget.attested_proof_tree_root` == `current_proof_tree_root`.
    *   `verify_cfc_exists_and_valid_gadget.checkpoint_leaf_hash` == `previous_step_header_gadget.session_start_context.checkpoint_leaf_hash`.
    *   Connects all key metadata (`contract_id`, `method_id`, `num_inputs/outputs`, `inner_public_inputs_hash`) between the verification and state delta gadgets, ensuring they operate on the *exact same verified transaction*.
*   **Assumptions:** Relies on sub-gadget assumptions. Assumes `current_proof_tree_root` is correct.
*   **Role:** Defines a standard, verifiable "block" within the user's local recursive proof chain, corresponding to processing one smart contract call.

---

### `UPSVerifyPopDeferredTxStepGadget`

*   **File:** `ups_cfc_standard_pop_deferred_tx_rs.txt`
*   **Purpose:** Handles transactions specifically designed to settle a previously incurred deferred transaction debt. It verifies the debt removal and then processes the corresponding CFC execution.
*   **Technical Function:** Verifies a delta proof for removing an item from the deferred debt tree, checks its consistency with the CFC being executed, and then uses `UPSVerifyCFCStandardStepGadget` with a corrected starting context.
*   **Inputs/Witness:**
    *   `previous_step_header_gadget`, `current_proof_tree_root`, `ups_session_proof_tree_height`: Same as standard step.
    *   `UPSVerifyPopDeferredTxStepInput`: Witness containing standard step inputs *plus* `ups_pop_deferred_tx_proof` (a `DeltaMerkleProofCore` for the deferred debt tree).
*   **Outputs/Computed:** Exposes outputs from the internal `standard_cfc_verify_gadget`, notably the `new_header_gadget`.
*   **Constraints:**
    *   Verifies `ups_pop_deferred_tx_proof` using `DeltaMerkleProofGadget`.
    *   `ups_pop_deferred_tx_proof.old_root` == `previous_step_header.current_state.deferred_tx_debt_tree_root`.
    *   `ups_pop_deferred_tx_proof.new_value` == `ZERO_HASH` (proves removal).
    *   Computes expected hash of the deferred item (`DeferredTransactionStackItemGadget`) based on the CFC's `call_data`.
    *   `ups_pop_deferred_tx_proof.old_value` == computed deferred item hash (ensures correct debt removed).
    *   Instantiates `CorrectUPSHeaderHashesGadget`, setting `previous_step_deferred_tx_debt_tree_root = ups_pop_deferred_tx_proof.new_root`.
    *   Instantiates `UPSVerifyCFCStandardStepGadget` using the `corrections`.
*   **Assumptions:** Relies on sub-gadget assumptions. Assumes witness delta proof is valid initially.
*   **Role:** Enables verifiable settlement of asynchronous obligations (deferred calls) generated by previous transactions within the UPS flow.

---

### `PsyUserProvingSessionSignatureDataCompactGadget`

*   **File:** `ups_signature_data_rs.txt`
*   **Purpose:** Defines the precise data structure that is cryptographically signed by the user to authorize the submission of their completed User Proving Session.
*   **Technical Function:** Aggregates key state identifiers from the start and end of the UPS into a single, hashable structure, then combines it with context (network, user, nonce) for signing.
*   **Inputs/Witness:** `start_user_leaf_hash`, `end_user_leaf_hash`, `checkpoint_leaf_hash`, `tx_stack_hash`, `tx_count`.
*   **Outputs/Computed:** `ups_end_cap_sighash` (via `get_sig_action_with_user_info`).
*   **Constraints:** Internal hashing logic (`to_hash` method) combines inputs. `get_sig_action_with_user_info` uses `compute_sig_action_hash_circuit` to combine the data hash with `network_magic`, `user_id`, `nonce`, and the `PSY_SIG_ACTION_SIGN_UPS_END_CAP` constant.
*   **Assumptions:** Assumes input hash/target values correctly represent the final UPS state.
*   **Role:** Standardizes the payload for UPS authorization, ensuring all critical state transition elements are committed to before the user signs off.

---

### `UPSEndCapResultCompactGadget`

*   **File:** `ups_end_cap_result_rs.txt`
*   **Purpose:** Defines the minimal, verifiable summary of a completed UPS, intended for submission to the GUTA layer.
*   **Technical Function:** A data structure containing the essential start/end state identifiers needed for aggregation.
*   **Inputs/Witness:** `start_user_leaf_hash`, `end_user_leaf_hash`, `checkpoint_tree_root_hash`, `user_id`.
*   **Outputs/Computed:** `end_cap_result_hash` (`to_hash` method).
*   **Constraints:** Hashing logic combines inputs with the `GLOBAL_USER_TREE_HEIGHT` constant.
*   **Assumptions:** Assumes input hash/target values correctly represent the final UPS state and context.
*   **Role:** Creates the standardized output data that represents the user's net state change for the block in a format suitable for GUTA circuits.

---

### `UPSEndCapCoreGadget`

*   **File:** `ups_end_cap_rs.txt`
*   **Purpose:** Enforces the final set of critical constraints required to validly conclude a User Proving Session, linking the final state to the user's signature authorization.
*   **Technical Function:** Verifies nonce progression, public key consistency, signature data correctness, checkpoint progression, empty debt trees, and computes final outputs (Result and Stats).
*   **Inputs/Witness:**
    *   `last_header_gadget`: Final header state of the UPS.
    *   `sig_proof_public_inputs_hash`: Public inputs hash from the user's signature proof.
    *   `sig_proof_fingerprint`, `sig_proof_param_hash`: Signature circuit identifier hashes.
    *   `nonce`, `slots_modified`: Witness targets.
    *   `network_magic`, empty debt root constants: Parameters.
*   **Outputs/Computed:** `sig_data_compact_gadget`, `end_cap_result_gadget`, `guta_stats`.
*   **Constraints:**
    *   Nonce Check: `nonce` > `start_user_leaf.nonce`. Updates final leaf nonce.
    *   PK Check: Derives expected PK from sig proof params, ensures start/end user leaves have this same PK.
    *   User ID Check: Start/End user IDs match.
    *   Sig Data Check: Instantiates `PsyUserProvingSessionSignatureDataCompactGadget`, computes expected `sig_proof_public_inputs_hash`, connects it to the input hash from the sig proof.
    *   Checkpoint Check: Ensures `end_user_leaf.last_checkpoint_id` == session `checkpoint_id` > `start_user_leaf.last_checkpoint_id`.
    *   Debt Check: Connects `last_header.current_state` debt roots to empty root constants.
    *   Output Generation: Instantiates `UPSEndCapResultCompactGadget` and `GUTAStatsGadget`.
*   **Assumptions:** Assumes input `last_header_gadget` is correct (verified by previous step). Assumes signature proof is valid (verified elsewhere). Assumes witness nonce/slots/params are correct.
*   **Role:** The final gatekeeper for UPS validity, ensuring all protocol rules for session finalization are met and linking the state transition to cryptographic authorization before generating the outputs for network submission.

---

### `VerifyPreviousUPSStepProofInProofTreeGadget`

*   **File:** `verify_previous_ups_step_rs.txt`
*   **Purpose:** Essential gadget for recursion within UPS. It verifies the ZK proof generated by the immediately preceding UPS step, ensuring the chain of proofs is unbroken and follows protocol rules.
*   **Technical Function:** Verifies a proof (`AttestTreeAwareProofInTreeGadget`), checks its circuit fingerprint against a whitelist (`MerkleProofGadget`), and confirms its public inputs match the expected previous header state hash.
*   **Inputs/Witness:**
    *   `VerifyPreviousUPSStepProofInProofTreeInput`: Contains attestation witness, `previous_step_header` witness, and whitelist Merkle proof witness.
    *   Tree height parameters.
*   **Outputs/Computed:** `previous_step_header_gadget` (representing verified public inputs), `current_proof_tree_root`, `ups_step_circuit_whitelist_root`.
*   **Constraints:**
    *   Verifies proof attestation.
    *   Verifies whitelist proof.
    *   Connects attestation fingerprint to whitelist proof value.
    *   Connects `previous_step_header.ups_step_circuit_whitelist_root` to whitelist proof root.
    *   Computes hash of `previous_step_header` witness.
    *   Connects computed hash to `proof_attestation_gadget.inner_public_inputs_hash`.
*   **Assumptions:** Assumes witness data (proofs, header, whitelist proof) is valid initially.
*   **Role:** Enforces the integrity of the recursive proof chain generated locally by the user, step by step. Ensures only allowed UPS circuits are used.

---

### `VerifyPreviousUPSStepProofInProofTreePartialFromCurrentGadget`

*   **File:** `verify_previous_ups_step_partial_from_current_rs.txt`
*   **Purpose:** An optimized version of the previous gadget, used when the `session_start_context` is constant within the verifying circuit (like the End Cap circuit). Reduces witness size.
*   **Technical Function:** Similar to the full gadget, but reconstructs the `previous_step_header_gadget` internally using the known `session_start_context` (from `current_header` input) and only requiring the `previous_step_state` portion as witness.
*   **Inputs/Witness:**
    *   `current_header`: *Input* gadget (not witness).
    *   `VerifyPreviousUPSStepProofInProofTreePartialInput`: Contains attestation witness, `previous_step_state` witness, whitelist proof witness.
*   **Outputs/Computed:** Same as the full gadget.
*   **Constraints:** Similar to full gadget, plus connects `current_header.ups_step_circuit_whitelist_root` to the whitelist proof root. Reconstructs previous header internally before hashing and connecting to attestation inner public inputs.
*   **Assumptions:** Assumes input `current_header` is correct. Assumes witness data is valid initially.
*   **Role:** Witness optimization for recursive proof verification in specific circuit contexts.

---

### `UPSEndCapFromProofTreeGadget`

*   **File:** `ups_end_cap_tree_rs.txt`
*   **Purpose:** Top-level gadget within the `UPSStandardEndCapCircuit`. Orchestrates the verification of the final UPS step, verification of the ZK signature, and enforcement of final session constraints.
*   **Technical Function:** Instantiates and connects `VerifyPreviousUPSStepProofInProofTreeGadget` (often partial), `AttestProofInTreeGadget` (for signature), and `UPSEndCapCoreGadget`.
*   **Inputs/Witness:**
    *   `UPSEndCapFromProofTreeGadgetInput`: Contains witnesses for previous step verification, signature verification, `user_public_key_param`, `nonce`, `slots_modified`.
    *   Tree height and network parameters.
*   **Outputs/Computed:** `end_cap_core_gadget`, `current_proof_tree_root`.
*   **Constraints:**
    *   Instantiates sub-gadgets.
    *   Connects `verify_zk_signature_proof_gadget.attested_proof_tree_root` to `verify_previous_ups_step_gadget.current_proof_tree_root` (ensures signature and last step are in the same proof tree).
    *   Passes verified data (previous header, signature hashes) and witnesses (nonce, slots, params) into `UPSEndCapCoreGadget` for final checks.
*   **Assumptions:** Relies on sub-gadget assumptions. Assumes witness data is valid initially.
*   **Role:** Coordinates the final verification checks within the End Cap circuit, ensuring the entire session is valid, linked, and authorized.

---

### `UPSStartStepGadget`

*   **File:** `ups_start_rs.txt`
*   **Purpose:** Core logic for the `UPSStartSessionCircuit`. Verifies the user's provided initial state against the last finalized block's checkpoint data and initializes the session header.
*   **Technical Function:** Verifies Merkle proofs linking the checkpoint leaf to the checkpoint root and the user leaf to the user tree root within that checkpoint. Ensures header consistency and correct initialization of session state (debt trees, counters).
*   **Inputs/Witness:** `UPSStartStepInput` (header witness, checkpoint leaf/roots witness, checkpoint proof, user proof).
*   **Outputs/Computed:** `header_gadget` (the validated starting header).
*   **Constraints:**
    *   Verifies consistency between `checkpoint_tree_proof` and `header_gadget.session_start_context` (root, leaf hash, ID).
    *   Verifies consistency between `checkpoint_leaf_gadget`, `state_roots_gadget`, and header data.
    *   Verifies `user_tree_proof.root` matches `state_roots_gadget.user_tree_root`.
    *   Verifies `user_tree_proof.value` matches `header_gadget.session_start_context.start_session_user_leaf_hash`.
    *   Verifies `user_tree_proof.index` matches `user_id`.
    *   Verifies `current_state` initialization (updated `last_checkpoint_id`, empty debts, zero counts/stack).
*   **Assumptions:** Assumes witness data is valid initially. Assumes empty tree root constants are correct.
*   **Role:** Securely bootstraps the UPS, ensuring it starts from a globally valid and consistent state anchor.

