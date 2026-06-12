# Psy ZK Circuit Journey: Tracing Proofs and Assumptions

This document provides a detailed walkthrough of the Zero-Knowledge proof lifecycle in Psy, starting from a user's local actions to the final, globally verifiable block proof. We meticulously track what each circuit proves and, critically, the assumptions it makes and how those assumptions are discharged by subsequent circuits.

**Goal:** Illustrate the flow of cryptographic guarantees and the progressive reduction of trust assumptions, culminating in a block proof dependent only on the previous block's established state.

**Key:**

*   **Circuit:** The specific ZK circuit being executed.
*   **High-Level Purpose:** *Why* this circuit exists in the overall architecture.
*   **Proves (Technical Detail):** Specific cryptographic guarantees and state relations enforced by the circuit's constraints.
*   **How:** Key gadgets, hashing, and constraint mechanisms employed.
*   **Assumes `[A_]`:** Inputs or states treated as correct *before* this circuit's verification.
*   **Discharges `[R_]`:** Assumptions remaining from *previous* steps that are *verified* by this circuit.
*   **Remaining `[R_]`:** Assumptions still held true *after* this circuit's verification, passed to the next stage.

---

### Phase 1: User Proving Session (UPS) - Local Execution

*(User executes transactions and builds a local proof chain)*

**Step 1: Start Session**

*   **Circuit:** `UPSStartSessionCircuit`
*   **High-Level Purpose:** To establish a cryptographically verified starting point for the user's transaction batch, ensuring it begins from a consistent and valid state relative to the last finalized global block. Prevents users from initiating proofs based on invalid or outdated personal states.
*   **Proves:**
    *   The provided `UserProvingSessionHeader` witness (`ups_header`) contains an internally consistent `session_start_context` and `current_state`.
    *   `session_start_context.checkpoint_tree_root` matches the root of the verified `checkpoint_tree_proof` witness.
    *   `session_start_context.checkpoint_leaf_hash` matches the value of the `checkpoint_tree_proof`.
    *   `session_start_context.checkpoint_id` matches the index of the `checkpoint_tree_proof`.
    *   The hash of the provided `checkpoint_leaf` witness matches `session_start_context.checkpoint_leaf_hash`.
    *   The hash of the provided `state_roots` witness (`global_chain_root`) matches `checkpoint_leaf.global_chain_root`.
    *   `state_roots.user_tree_root` matches the root of the verified `user_tree_proof` witness.
    *   `session_start_context.start_session_user_leaf.user_id` matches the index of the `user_tree_proof`.
    *   The hash of `session_start_context.start_session_user_leaf` matches the value of the `user_tree_proof`.
    *   `current_state.user_leaf` matches `session_start_context.start_session_user_leaf` except `last_checkpoint_id` is updated to `session_start_context.checkpoint_id`.
    *   `current_state.deferred_tx_debt_tree_root == EMPTY_TREE_ROOT`.
    *   `current_state.inline_tx_debt_tree_root == EMPTY_TREE_ROOT`.
    *   `current_state.tx_count == 0`.
    *   `current_state.tx_hash_stack == ZERO_HASH`.
*   **How:** `UPSStartStepGadget` uses `MerkleProofGadget`s to verify paths, `Psy...Leaf/RootsGadget`s to hash witnesses and check consistency, direct comparisons and constant checks. Public inputs calculated via `compute_tree_aware_proof_public_inputs`.
*   **Assumes:**
    *   `[A1.1]` The *root hash* used in witness Merkle proofs (`checkpoint_tree_root` in `ups_header.session_start_context`) accurately reflects the globally finalized state of the previous block.
    *   `[A1.4]` The *constant* `empty_ups_proof_tree_root` used for the tree-aware public inputs is correct for this session's start.
    *   `[A1.5]` The *constant* `ups_step_circuit_whitelist_root` embedded in the output header is the correct root for allowed UPS circuits.
    *   (Initial correctness of witness data like proofs and leaves is assumed, then verified internally).
*   **Discharges:** Internal consistency checks discharge assumptions about the relationships *between* the provided witness components (e.g., leaf data matches proof value).
*   **Remaining:**
    *   `[R1.1]` = `[A1.1]` (Correctness of previous block's `CHKP` root).
    *   `[R1.4]` = `[A1.4]` (Correctness of session's `empty_ups_proof_tree_root`).
    *   `[R1.5]` = `[A1.5]` (Correctness of `ups_step_circuit_whitelist_root`).

**Step 1.5: Execute Contract Function Circuit (CFC)**

*   **Circuit:** `DapenContractFunctionCircuit` (Specific instance per function)
*   **High-Level Purpose:** To execute the specific smart contract logic defined by the developer for a single transaction call, locally generating a proof that *this execution instance* faithfully followed the code, given its specific inputs and assumed context. This decouples logic execution from state transition verification.
*   **Proves:**
    *   The sequence of internal operations matches the compiled `DPNFunctionCircuitDefinition` (`fn_def`).
    *   Given the assumed `tx_ctx_header` witness (containing start states like `start_contract_state_tree_root`, `start_deferred_tx_debt_tree_root`, call arguments hash/length) and circuit `inputs`:
        *   The simulated state commands (reads/writes to CST, debt tree interactions via `StateReaderGadget`) produce the `end_contract_state_tree_root` and `end_deferred_tx_debt_tree_root` recorded in `tx_ctx_header.transaction_end_ctx`.
        *   The computed `outputs_hash` and `outputs_length` match those recorded in `tx_ctx_header.transaction_end_ctx`.
        *   All `assertions` within the `fn_def` hold true.
    *   The public inputs hash (combining `session_proof_tree_root` and `tx_ctx_header` hash) is correctly computed.
*   **How:** `PsyContractFunctionBuilderGadget` interprets `fn_def`, simulating execution using `SimpleDPNBuilder` and `StateReaderGadget`. Connects computed vs witnessed values in `tx_ctx_header`.
*   **Assumes:**
    *   `[A1.5.1]` The `DapenContractFunctionCircuitInput` witness (esp. `tx_input_ctx`) accurately reflects the state *before* this CFC execution (derived from the previous UPS step's output) and the correct function inputs/outputs.
    *   `[A1.5.3]` The `session_proof_tree_root` witness correctly represents the root of the user's recursive proof tree *at this point*.
*   **Discharges:** Internal consistency of the execution trace vs. the code definition (`fn_def`).
*   **Remaining:**
    *   `[R1.5.1]` Correctness of the assumed `tx_input_ctx` (start state, inputs/outputs).
    *   `[R1.5.3]` Correctness of the assumed `session_proof_tree_root`.
*   **Output:** A CFC Proof object.

**Step 2: Verify CFC & Process UPS Delta**

*   **Circuit:** `UPSCFCStandardTransactionCircuit`
*   **High-Level Purpose:** To integrate the result of a local CFC execution (Step 1.5) into the user's main proof chain. It verifies the CFC was executed correctly *and* that its claimed start/end states correctly link the previous UPS state to the next UPS state, while also proving the previous UPS step itself was valid.
*   **Proves:**
    *   **Previous Step Validity:** Proof N-1 was valid & used a whitelisted UPS circuit (`[R(N-1).5]` discharged). Public inputs match header hash.
    *   **CFC Validity:** CFC proof (from Step 1.5) is valid & exists in the same UPS proof tree as Proof N-1 (`[R1.5.3]` discharged). CFC function is registered globally (`GCON`/`CFT` check linked via `[R(N-1).1]`).
    *   **Context Link:** The *inner public inputs hash* from the verified CFC proof matches the hash of the `UPSCFCStandardStateDeltaInput` witness used to calculate state changes (`[R1.5.1]` discharged). This is the critical link ensuring the state delta matches the verified computation.
    *   **State Delta Correctness:** The UPS header transition from step N-1 to N is valid:
        *   `UCON` root updated correctly based on `user_contract_tree_update_proof`.
        *   Debt tree roots updated correctly based on `deferred/inline_tx_debt_pivot_proof`s (starting from prev step's end state).
        *   `tx_count` incremented; `tx_hash_stack` updated correctly.
*   **How:** `VerifyPreviousUPSStepProofInProofTreeGadget`, `UPSVerifyCFCStandardStepGadget` connects `cfc_inner_public_inputs_hash` between `UPSVerifyCFCProofExistsAndValidGadget` and `UPSCFCStandardStateDeltaGadget`. Delta/pivot proofs verified.
*   **Assumes:**
    *   `[A2.1]` Witness data for *this* step (attestations, state delta proofs) is correct initially.
    *   `[R(N-1).1]` (Prev Step) Last block's `CHKP` root correctness (used for CFC inclusion context).
    *   `[R(N-1).4]` (Prev Step) Session's `empty_ups_proof_tree_root` correctness (defines proof tree base).
*   **Discharges:** `[R(N-1).5]` (Prev UPS whitelist), `[R1.5.1]` (CFC Context), `[R1.5.3]` (CFC Proof Tree Root).
*   **Remaining:**
    *   `[RN.1]` = `[R(N-1).1]` (Last block's `CHKP` root).
    *   `[RN.4]` = `[R(N-1).4]` (Session's `empty_ups_proof_tree_root`).
    *   `[RN.5]` (New) Current header's `ups_step_circuit_whitelist_root` correctness.

**(Repeat Step 1.5 & 2, or deferred variant, for all user transactions)**

**Step 3: End Session**

*   **Circuit:** `UPSStandardEndCapCircuit`
*   **High-Level Purpose:** To securely conclude the user's local proving session, producing a single proof that attests to the validity of the entire sequence of transactions, authorized by the user's signature, and ready for network submission. It ensures the session ends in a clean state (no outstanding debts).
*   **Proves:**
    *   Last UPS step proof valid & used correct whitelisted circuit (`[R_Last.5]` discharged against *constant* `known_ups_circuit_whitelist_root`).
    *   ZK Signature proof valid & in same proof tree (`[R_Last.4]` discharged).
    *   Signature corresponds to user's key & authenticates `PsyUserProvingSessionSignatureDataCompact` derived from final UPS header state.
    *   Nonce incremented correctly.
    *   `last_checkpoint_id` updated correctly in final `UserLeaf`.
    *   Final debt tree roots are empty.
    *   *(Optional)* UPS proof tree aggregation used correct circuits (`known_proof_tree_circuit_whitelist_root`).
    *   Public Outputs (`end_cap_result_hash`, `guta_stats_hash`) correctly computed.
*   **How:** `UPSEndCapFromProofTreeGadget` orchestrates verification of last step & signature, `UPSEndCapCoreGadget` enforces final constraints. Optional `VerifyAggProofGadget`.
*   **Assumes:**
    *   `[A3.1]` Witness data correct initially.
    *   `[A3.2]` Constant `known_ups_circuit_whitelist_root`.
    *   `[A3.3]` Constant `known_proof_tree_circuit_whitelist_root` (if used).
    *   `[R_Last.1]` (Last tx step) Correctness of `CHKP` root used as session basis.
*   **Discharges:** `[R_Last.5]`, `[R_Last.4]`. Potentially UPS tree agg assumptions.
*   **Remaining:** `[R3.1]` = `[R_Last.1]` (Correctness of initial `CHKP` root).

**Output of Phase 1:** End Cap Proof + Public Inputs + State Deltas from user

---
### Phase 2: Network Aggregation - Parallel Execution (Realms & Coordinators)

*(The Proving Network receives End Cap proofs + state deltas from users and aggregate them to prove the change in the blockchain state root)*

**Step 4: Process End Cap Proof(s) (GUTA Entry - Realm)**

*   **Circuit(s):**
    *   `GUTAVerifySingleEndCapCircuit` (Handles a single End Cap, e.g., an odd leaf in aggregation)
    *   `GUTAVerifyTwoEndCapCircuit` (Handles pairs of End Cap proofs, typical base case)
*   **High-Level Purpose:** To securely ingest user End Cap proofs into the GUTA process, verify their validity against the protocol and historical state, and translate them into the standard `GlobalUserTreeAggregatorHeader` format needed for recursive aggregation.
*   **Proves:**
    *   Input End Cap proof(s) (`proof_target`, `child_a/b_proof`) are valid ZK proofs.
    *   The End Cap proof(s) were generated by the official End Cap circuit (fingerprint checked against `known_end_cap_fingerprint`).
    *   The public inputs of the End Cap proof(s) correctly match the claimed result/stats (`end_cap_result`, `guta_stats`) provided as witness.
    *   The `checkpoint_tree_root` claimed by the user(s) existed historically in the `CHKP` tree (verified via `checkpoint_historical_merkle_proof`).
    *   *(For TwoEndCap):* The Nearest Common Ancestor (NCA) logic correctly combines the two individual user state transitions (`start_leaf` -> `end_leaf` at user indices) into a single state transition at their parent node in the `GUSR` tree. Statistics are correctly summed.
    *   Outputs a `GlobalUserTreeAggregatorHeader` representing the state transition for the node processed (either a single user leaf or the NCA parent) and the combined stats.
*   **How:**
    *   `VerifyEndCapProofGadget`: Used internally (once or twice) to perform core End Cap proof verification, fingerprint check, public input matching, and historical checkpoint validation.
    *   `TwoNCAStateTransitionGadget` (in `GUTAVerifyTwoEndCapCircuit`): Combines the two `GUSR` leaf transitions (derived from End Cap results) using an NCA proof witness.
    *   `GUTAStatsGadget.combine_with`: Sums stats (in `GUTAVerifyTwoEndCapCircuit`).
    *   Constructs the output `GlobalUserTreeAggregatorHeader`.
*   **Assumes:**
    *   `[A4.1]` Witness data (End Cap proof(s), results, stats, historical proofs, NCA proof if applicable) is correct initially.
    *   `[A4.2]` Constant `known_end_cap_fingerprint_hash` is correct.
    *   `[A4.3]` Public Input `guta_circuit_whitelist_root_hash` is correct.
    *   `[R3.1]` (Implicit in End Cap) User session(s) based on valid past `CHKP` root.
*   **Discharges:**
    *   `[R3.1]` (via `VerifyEndCapProofGadget`'s historical proof check).
    *   Validity of the input End Cap proof(s).
*   **Remaining:**
    *   `[R4.1]` (New) Correctness of the *current block's* `checkpoint_tree_root` (established by `checkpoint_historical_merkle_proof.current_root` and passed consistently upwards).
    *   `[R4.3]` = `[A4.3]` (Correctness of `guta_circuit_whitelist` root).

**Step 5: Aggregate GUTA Proofs (Recursive - Realm/Coordinator)**

*   **Circuit(s):**
    *   `GUTAVerifyTwoGUTACircuit` (Aggregates two GUTA sub-proofs)
    *   `GUTAVerifyLeftGUTARightEndCapCircuit` (Aggregates GUTA sub-proof and a new End Cap proof)
    *   `GUTAVerifyLeftEndCapRightGUTACircuit` (Aggregates an End Cap proof and a GUTA sub-proof)
*   **High-Level Purpose:** To recursively combine verified state transitions within the GUTA hierarchy. These circuits take proofs representing changes in subtrees (either previous GUTA aggregations or newly processed End Caps) and merge them into a proof for the parent node, typically using NCA logic.
*   **Proves:**
    *   Both input proofs (Type A and Type B, where Type can be GUTA or EndCap) are valid ZK proofs.
    *   Input Proof A (if GUTA) used a whitelisted GUTA circuit (`[R(A).3]` discharged via `VerifyGUTAProofGadget`).
    *   Input Proof A (if EndCap) used the whitelisted EndCap circuit (`[A5.EndCapFingerprint]` check via `VerifyEndCapProofGadget`).
    *   Input Proof B processed similarly (`[R(B).3]` or `[A5.EndCapFingerprint]` discharged).
    *   Both input proofs' headers/results reference the *same* `checkpoint_tree_root` (`[R(A).1]` and `[R(B).1]` verified to be equal, discharging one, remaining `[RN.1]`).
    *   Both input proofs' headers reference the *same* `guta_circuit_whitelist` root (`[R(A).3]` and `[R(B).3]` verified to be equal, discharging one, remaining `[RN.3]`).
    *   Public inputs of each input proof match their respective headers/results.
    *   The NCA logic (`TwoNCAStateTransitionGadget`) correctly combines the state transitions (`SubTreeNodeStateTransition` from input GUTA headers or derived from EndCap results) based on the NCA proof witness.
    *   Statistics are correctly summed (`GUTAStatsGadget.combine_with`).
    *   Outputs a `GlobalUserTreeAggregatorHeader` for the parent NCA node.
*   **How:**
    *   `VerifyGUTAProofGadget` (for GUTA inputs).
    *   `VerifyEndCapProofGadget` (for EndCap inputs).
    *   `TwoNCAStateTransitionGadget`: Core aggregation logic using NCA proof witness.
    *   Connections ensuring consistency of `checkpoint_tree_root` and `guta_circuit_whitelist` between inputs.
*   **Assumes:**
    *   `[A5.1]` Witness data (input proofs, headers/results, whitelist proofs, NCA proof) correct initially.
    *   `[A5.EndCapFingerprint]` Constant `known_end_cap_fingerprint_hash` (if applicable).
    *   `[R(A).1]`, `[R(B).1]` (from inputs) `CHKP` root correctness.
    *   `[R(A).3]`, `[R(B).3]` (from inputs) `GUTA whitelist` correctness.
*   **Discharges:** Validity/consistency of input proofs, their whitelist usage (`[R(A/B).3]`), and consistency of their assumed `CHKP` roots (`[R(A).1]` confirmed equal to `[R(B).1]`).
*   **Remaining:**
    *   `[RN.1]` = `[R(A).1]` (Common `CHKP` root correctness).
    *   `[RN.3]` = `[R(A).3]` (Common `GUTA whitelist` correctness).

**Step 5.5: Propagate GUTA Proof Upwards (Line Proof)**

*   **Circuit:** `GUTAVerifyGUTAToCapCircuit` (May be used within Realm or by Coordinator)
*   **High-Level Purpose:** To efficiently propagate a verified state transition from a lower node up a direct path in the tree (where no merging is needed) to a higher level (e.g., the Realm root or the global root).
*   **Proves:**
    *   The input GUTA proof is valid and used a whitelisted GUTA circuit (`[R_In.3]` discharged).
    *   The input proof references the correct `CHKP` root (`[R_In.1]`).
    *   The state transition is correctly recalculated from the input proof's node level up to the target level (e.g., level 0) using the provided `top_line_siblings` witness.
    *   Outputs a `GlobalUserTreeAggregatorHeader` with the state transition reflecting the change at the target level.
*   **How:** `VerifyGUTAProofToLineGadget` (uses `VerifyGUTAProofGadget` and `GUTAHeaderLineProofGadget` which uses `SubTreeNodeTopLineGadget`).
*   **Assumes:**
    *   `[A5.5.1]` Witness data (input proof, header, whitelist proof, `top_line_siblings`) correct initially.
    *   `[R_In.1]`, `[R_In.3]` (from input proof).
*   **Discharges:** `[R_In.3]` (GUTA whitelist). Validity of input proof relative to `[R_In.1]`.
*   **Remaining:**
    *   `[R5.5.1]` = `[R_In.1]` (Common `CHKP` root correctness).
    *   `[R5.5.3]` = `[R_In.3]` (Common `GUTA whitelist` correctness).

**(Steps 5/5.5 repeat recursively until Realm roots are reached)**

**Step 5.N: Handle No GUTA Changes**

*   **Circuit:** `GUTANoChangeCircuit`
*   **High-Level Purpose:** To allow the aggregation process to incorporate the latest checkpoint root even if no user activity (relevant to GUTA) occurred in a particular block or subtree. Maintains checkpoint consistency across the aggregation structure.
*   **Proves:**
    *   A specific `checkpoint_leaf` exists in the `checkpoint_tree` at the *previous* `checkpoint_id`.
    *   The `GUSR` root remained unchanged between the previous and current checkpoint (`new_guta_header.state_transition` shows `old_node_value == new_node_value` at level 0).
    *   Statistics are zero.
    *   Outputs a `GlobalUserTreeAggregatorHeader` referencing the *current* `checkpoint_tree_root` but indicating no `GUSR` change.
*   **How:** `GUTANoChangeGadget` (uses `MerkleProofGadget` for checkpoint proof, constructs no-op transition).
*   **Assumes:**
    *   `[A5.N.1]` Witness data correct initially.
    *   `[A5.N.3]` Public Input `guta_circuit_whitelist` root is correct.
*   **Discharges:** Internal consistency of checkpoint proof/leaf.
*   **Remaining:**
    *   `[R5.N.1]` (New) Correctness of the *current* `checkpoint_tree_root` (from the witness proof).
    *   `[R5.N.3]` = `[A5.N.3]` (GUTA whitelist correctness).

**Output of Phase 2:** Aggregated GUTA proof(s) from each active Realm (or a NoChange proof), valid relative to `[R_Realm.1]` and `[R_Realm.3]`.

---

### Phase 3: Coordinator Level Aggregation - Network Execution

*(Coordinator combines proofs from Realms and global tree updates)*

**Step 6: Process User Registrations**

*   **Circuit:** `BatchAppendUserRegistrationTreeCircuit`
*   **Proves:** Correct batch append to `URT` (output root valid given input root `[A6.3]`). Respects `register_users_circuit_whitelist` (`[A6.2]`).
*   **Assumes:** `[A6.x]` (Witness, whitelist, input `URT` root).
*   **Discharges:** Internal append proof consistency.
*   **Remaining:** `[R6.2]` (Whitelist), `[R6.3]` (Input `URT` root correctness).

**Step 7: Process Contract Deployments**

*   **Circuit:** `BatchDeployContractsCircuit`
*   **Proves:** Correct batch append to `GCON` (output root valid given input root `[A7.3]`). Witness leaves match hashes. Respects `deploy_contract_circuit_whitelist` (`[A7.2]`).
*   **How:** `BatchDeployContractsGadget`.
*   **Assumes:** `[A7.x]` (Witness, whitelist, input `GCON` root).
*   **Discharges:** Internal append/leaf consistency.
*   **Remaining:** `[R7.2]` (Whitelist), `[R7.3]` (Input `GCON` root correctness).

**Step 8: Aggregate Part 1 (Combine UserReg + Deploy + GUTA)**

*   **Circuit:** `VerifyAggUserRegistartionDeployContractsGUTACircuit`
*   **Proves:** Input proofs (Agg UserReg, Agg Deploy, Agg GUTA) valid & used respective whitelisted circuits (`[R6.2]`, `[R7.2]`, `[R_GUTA.3]` discharged). All inputs based on same `CHKP` root (`[R_GUTA.1]` verified across inputs). Output header correctly combines state transitions.
*   **How:** `VerifyAggUserRegistartionDeployContractsGUTAGadget`.
*   **Assumes:**
    *   `[A8.1]` Witness data correct initially.
    *   `[R_GUTA.1]` (Implicit common `CHKP` root from inputs).
    *   `[R6.3]` (Input `URT` root correctness).
    *   `[R7.3]` (Input `GCON` root correctness).
*   **Discharges:** Whitelists (`[R6.2]`, `[R7.2]`, `[R_GUTA.3]`). Input proof validity. Consistency of `CHKP` root `[R_GUTA.1]`.
*   **Remaining:**
    *   `[R8.1]` = `[R_GUTA.1]` (`CHKP` root correctness).
    *   `[R8.3]` = `[R6.3]` (Input `URT` root correctness).
    *   `[R8.4]` = `[R7.3]` (Input `GCON` root correctness).

**Output of Phase 3:** Single "Part 1" proof, valid relative to `[R8.1]`, `[R8.3]`, `[R8.4]`.

---

### Phase 4: Final Block Proof - Network Execution

**Step 9: Final Block Transition**

*   **Circuit:** `PsyCheckpointStateTransitionCircuit`
*   **High-Level Purpose:** To generate the definitive proof for the block, verifying all aggregated work and cryptographically linking the block to its predecessor, thereby discharging all temporary assumptions made during parallel processing.
*   **Proves:**
    *   Part 1 Agg proof (Step 8) valid & used correct circuit.
    *   New `CHKP` Leaf computed correctly from Part 1 outputs (new global roots for `URT` (`[R8.3]` discharged), `GCON` (`[R8.4]` discharged), `GUSR`), stats, time, randomness.
    *   `CHKP` tree append operation correct, transitioning from `previous_checkpoint_proof.root` (`[R8.1]`) to `new_checkpoint_tree_root`.
    *   **Final Chain Link:** `previous_checkpoint_proof.root` matches the **Public Input** `previous_block_chkp_root`.
*   **How:** `CheckpointStateTransitionChildProofsGadget`, `CheckpointStateTransitionCoreGadget`.
*   **Assumes:**
    *   `[A9.1]` Witness data correct initially.
    *   `[A9.2]` **Public Input `previous_block_chkp_root` == previous block's finalized `CHKP` root.**
*   **Discharges:** `[R8.1]` (`CHKP` root correctness discharged against public input `[A9.2]`). `[R8.3]` (`URT` root correctness), `[R8.4]` (`GCON` root correctness) implicitly discharged by relying on the verified Part 1 proof output.
*   **Remaining Assumptions:** **None**.

**Output:** Final Block Proof. Its verification confirms the entire block's state transition is valid, contingent only on the validity of the previous block's state hash (`[A9.2]`) and ZKP soundness.