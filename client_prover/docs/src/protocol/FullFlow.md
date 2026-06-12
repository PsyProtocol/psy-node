# Psy Protocol Wiki: Achieving Scalability with PARTH and ZK Proofs

## 1. Introduction: The Scalability Challenge and Psy's Solution

Traditional blockchains often face a **serial execution bottleneck**. Transactions are typically processed one after another within a single state machine context. Adding more validator nodes doesn't necessarily increase the overall transaction processing capacity (TPS), as they all work on the same sequential task list. Attempts at parallel execution often introduce complexity, race conditions, and potential state inconsistencies.

Psy (Quantum Entangled Data) tackles this fundamental limitation through two core innovations:

1.  **PARTH (Parallelizable Account-based Recursive Transaction History) Architecture:** A novel way of organizing blockchain state that inherently allows for parallel processing of transactions from different users within the same block.
2.  **End-to-End Zero-Knowledge Proofs (ZKPs):** A sophisticated system of ZK circuits that rigorously verify every state transition, ensuring the security and consistency of the parallel execution enabled by PARTH.

This wiki page details the journey of a transaction from user initiation to final block inclusion, focusing on the ZK circuits involved, the assumptions they make, what they prove, and how these assumptions are systematically verified and discharged throughout the process.

## 2. The PARTH Architecture: Foundation for Parallelism

PARTH reorganizes blockchain state into a hierarchy of Merkle trees, enabling fine-grained state access and modification control:

*   **Per-User, Per-Contract State (`CSTATE`):** Each user maintains a *separate* Merkle tree (`CSTATE`) for their specific state within *each* smart contract they interact with.
*   **User Contract Tree (`UCON`):** Aggregates all `CSTATE` roots for a single user, representing their state across all contracts.
*   **Global User Tree (`GUSR`):** Aggregates all `UCON` roots, representing the state of all users.
*   **Global Contract Tree (`GCON`):** Represents the global state related to contract code definitions and metadata.
*   **User Registration Tree:** Tracks registered users and their public keys (relevant for `GUTARegisterUserCircuit`).
*   **Checkpoint Tree (`CHKP`):** The top-level tree. Its root hash serves as a cryptographic snapshot (checkpoint) of the *entire verifiable blockchain state* at a specific block height.

**Key PARTH Rules Enabling Scalability:**

1.  **Write Locally:** A transaction initiated by User A can **only modify (write to)** the state within User A's own trees (their various `CSTATE`s and subsequently their `UCON` root).
2.  **Read Globally (Previous State):** A transaction can **read** state from *any* tree (User A's, User B's, `GCON`, etc.), but it reads the state **as it was finalized at the end of the *previous* block** (anchored by the previous block's `CHKP` root).

Because write operations are isolated and reads access immutable past state, transactions from *different users* within the *same block* operate independently and cannot conflict. This architectural design is the cornerstone of Psy's horizontal scalability.

## 3. The Big Picture: End-to-End ZK Proof Flow

The process of validating transactions and building a block involves three main phases, each relying on specific ZK circuits:

1.  **Phase 1: User Proving Session (UPS) - Local Execution & Proving:** The user (or a delegated prover) executes their transactions locally and generates a chain of recursive ZK proofs culminating in a single "End Cap" proof for their activity within the block.
2.  **Phase 2: Global User Tree Aggregation (GUTA) - Parallel Network Execution:** The Psy network's Decentralized Proving Network (DPN) takes End Cap proofs (and other GUTA-related proofs like registrations) from many users and aggregates them in parallel using specialized GUTA circuits.
3.  **Phase 3: Final Block Proof Generation:** A final aggregation step combines the top-level GUTA proof (representing all user state changes) with proofs for other global state changes (like contract deployments) into a single block proof anchored to the previous block's state.

## 4. Phase 1: User Proving Session (UPS) Circuits

This phase occurs locally, building a user-specific proof chain.

### 4.1. `UPSStartSessionCircuit`

*   **Purpose:** Initializes the proving session for a user, establishing a secure starting point based on the last globally finalized block state.
*   **Core Gadget:** `UPSStartStepGadget`
*   **Input Data:** `UPSStartStepInput` (contains the target starting `UserProvingSessionHeader`, the corresponding `PsyCheckpointLeaf` and `PsyCheckpointGlobalStateRoots` from the last block, and Merkle proofs (`checkpoint_tree_proof`, `user_tree_proof`) linking them together).
*   **What it Proves:**
    *   **Consistency of Initial State:** The provided `UserProvingSessionHeader.session_start_context` is consistent with the provided `PsyCheckpointLeaf`, `PsyCheckpointGlobalStateRoots`, and the user's leaf (`start_session_user_leaf`) within the `user_tree_root` (part of `PsyCheckpointGlobalStateRoots`). It verifies that the user leaf, global roots, and checkpoint leaf all correctly correspond to the provided `checkpoint_tree_root` via the Merkle proofs.
    *   **Correct Initialization:** The `UserProvingSessionHeader.current_state` is correctly initialized based on the `session_start_context` (e.g., `user_leaf.last_checkpoint_id` is updated, `deferred_tx_debt_tree_root` and `inline_tx_debt_tree_root` are empty hashes, `tx_count` is zero, `tx_hash_stack` is an empty hash).
    *   **Header Integrity:** The hash of the entire `ups_header` is correctly computed.
    *   **Proof Tree Anchor:** The final public output hash combines the `ups_header` hash with the `empty_ups_proof_tree_root` (a known constant representing the start of this session's proof tree), using `compute_tree_aware_proof_public_inputs`.
*   **Assumptions Made:**
    1.  The witness data (`UPSStartStepInput`) provided by the user (fetched from querying the last finalized block state) is accurate *at the start of verification*.
    2.  The globally known constant `empty_ups_proof_tree_root` (hash of an empty Merkle tree of height `UPS_SESSION_PROOF_TREE_HEIGHT`) is correct.
    3.  The *previous block's* `checkpoint_tree_root` (implicitly contained within the input witness) is valid (this is the key assumption passed *into* the entire UPS).
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by the circuit's constraints, ensuring internal consistency between the header, leaf data, global roots, and Merkle proofs. If the witness data is inconsistent, proof generation fails.
    *   Assumption 2 is a system parameter.
    *   Assumption 3 is *not* discharged here; it's carried forward implicitly by using the state derived from that root as the starting point.
*   **Contribution to Horizontal Scalability:** Provides a secure, independent starting point for each user's session based on the common, finalized global state, allowing many users to start their sessions in parallel.
*   **High-Level Functionality:** Securely begins a user's batch of transactions for the current block context.

### 4.2. `UPSCFCStandardTransactionCircuit`

*   **Purpose:** Processes a standard Contract Function Call (CFC) transaction, extending the user's recursive proof chain. Executed potentially multiple times per session.
*   **Core Gadgets:** `VerifyPreviousUPSStepProofInProofTreeGadget`, `UPSVerifyCFCStandardStepGadget`
*   **Input Data:** `UPSCFCStandardTransactionCircuitInput` (contains info about the previous UPS step's proof and header (`verify_previous_ups_step`), and details for the current CFC step (`standard_cfc_step`)).
*   **What it Proves:**
    *   **Previous Step Validity:** The ZK proof (`previous_step_proof`) provided for the previous UPS step (either the `UPSStartSessionCircuit` or another `UPSCFC...Circuit`) is valid.
    *   **Previous Step Whitelist:** The previous step's proof was generated by a circuit whose fingerprint is present in the `ups_circuit_whitelist_root` specified in the `previous_step_header`.
    *   **Previous Step Linkage:** The public inputs hash of the `previous_step_proof` correctly corresponds to the provided `previous_step_header` and the `previous_proof_tree_root`.
    *   **CFC Proof Validity & Inclusion:** The ZK proof for the current CFC execution (`verify_cfc_proof_input`) is valid and is correctly included in the *current* `current_proof_tree_root`.
    *   **Contract Function Validity:** The CFC proof corresponds to a function whose details (`cfc_inclusion_proof`) are correctly included in the Global Contract Tree (`GCON`) root referenced within the session's checkpoint context (`checkpoint_state`).
    *   **State Transition Correctness:** Executing the CFC logically transitions the state represented by `previous_step_header.current_state` to the state represented by `new_header_gadget.current_state`. This includes updates to the user's `user_leaf` (specifically the `user_contract_tree_root`), potentially the `deferred_tx_debt_tree_root` or `inline_tx_debt_tree_root`, the `tx_hash_stack`, and incrementing the `tx_count`. The `session_start_context` and `ups_step_circuit_whitelist_root` remain unchanged.
    *   **Proof Tree Update:** The output public inputs correctly combine the hash of the `new_header_gadget` with the `current_proof_tree_root`.
*   **Assumptions Made:**
    1.  The witness data (`UPSCFCStandardTransactionCircuitInput`) for *this specific step* (including the previous step's proof/header, the CFC proof/details, state delta witnesses) is accurate initially.
    2.  The `current_proof_tree_root` provided as input correctly represents the root of the session's proof tree *after* including the current CFC proof.
    3.  The assumption about the original *starting* `checkpoint_tree_root` (from `UPSStartSessionCircuit`) is still carried forward implicitly.
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying the previous step's proof, the CFC proof, the contract inclusion proof, and the state delta transition logic based on the witness.
    *   Assumption 2 is *not* discharged here; it's passed implicitly to the next UPS step or the End Cap circuit, forming part of the recursive structure.
    *   Assumption 3 remains implicitly carried forward.
*   **Contribution to Horizontal Scalability:** Allows users to process their transactions sequentially *locally*, independent of other users' activities within the same block. The proof chain maintains self-consistency.
*   **High-Level Functionality:** Securely executes and proves a single smart contract interaction within the user's session.

### 4.3. `UPSCFCDeferredTransactionCircuit`

*   **Purpose:** Processes a transaction that first settles a deferred debt item and *then* executes the main CFC logic.
*   **Core Gadgets:** `VerifyPreviousUPSStepProofInProofTreeGadget`, `UPSVerifyPopDeferredTxStepGadget`
*   **Input Data:** `UPSCFCDeferredTransactionCircuitInput`
*   **What it Proves:** Everything proven by `UPSCFCStandardTransactionCircuit`, *plus*:
    *   **Debt Removal:** A specific deferred transaction was correctly removed from the `deferred_tx_debt_tree` (verified via `ups_pop_deferred_tx_proof`, a `DeltaMerkleProofCore`). The state transition reflects this removal *before* the main CFC logic is applied.
    *   **Debt-CFC Link:** The data associated with the removed debt item matches the parameters required by the subsequent CFC execution.
*   **Assumptions Made:** Same as `UPSCFCStandardTransactionCircuit`, plus assumes the witness for the `DeltaMerkleProofCore` (debt removal) is accurate initially.
*   **How Assumptions are Discharged:** Same as standard, plus verifies the debt removal proof and its consistency with the CFC witness data. The starting state assumption and proof tree root assumption are carried forward.
*   **Contribution to Horizontal Scalability:** Local serial execution, same as standard.
*   **High-Level Functionality:** Enables settlement of asynchronous/deferred transaction calls within the user's proving flow.

### 4.4. `UPSStandardEndCapCircuit`

*   **Purpose:** Finalizes the user's entire proving session for the block, verifying the signature and packaging the net result.
*   **Core Gadgets:** `UPSEndCapFromProofTreeGadget` (which uses `VerifyPreviousUPSStepProofInProofTreeGadget`, `AttestProofInTreeGadget`, `UPSEndCapCoreGadget`, `PsyUserProvingSessionSignatureDataCompactGadget`)
*   **Input Data:** `UPSEndCapFromProofTreeGadgetInput` (contains info about the last UPS step, the ZK signature proof (`verify_zk_signature_proof_input`), signature parameters (`user_public_key_param`, `nonce`), and `slots_modified`).
*   **What it Proves:**
    *   **Last Step Validity:** The proof for the *last* UPS transaction step is valid and used an allowed circuit (`verify_previous_ups_step_gadget`).
    *   **Signature Proof Validity & Inclusion:** The ZK proof for the user's signature (`verify_zk_signature_proof_gadget`) is valid and is correctly included in the *final* UPS proof tree root (`current_proof_tree_root`).
    *   **Signature Authentication:** The public key (`user_public_key_param`) used to verify the signature matches the public key stored in the `previous_step_header.current_state.user_leaf`.
    *   **Signature Payload Integrity:** The ZK signature proof attests to a specific payload hash. This circuit proves that this payload hash correctly corresponds to a `PsyUserProvingSessionSignatureDataCompact` structure containing:
        *   `start_user_leaf_hash`: Matches the `start_session_user_leaf_hash` from the `previous_step_header.session_start_context`.
        *   `end_user_leaf_hash`: Matches the hash of the `previous_step_header.current_state.user_leaf`.
        *   `checkpoint_leaf_hash`: Matches the `checkpoint_leaf_hash` from the `previous_step_header.session_start_context`.
        *   `tx_stack_hash`: Matches the `tx_hash_stack` from the `previous_step_header.current_state`.
        *   `tx_count`: Matches the `tx_count` from the `previous_step_header.current_state`.
    *   **Nonce Validity:** The `nonce` used in the signature matches the `nonce` in the `previous_step_header.current_state.user_leaf`. (The state delta within the End Cap implicitly increments the nonce in the *output* `UPSEndCapResultCompact`).
    *   **Session Completion:** The `deferred_tx_debt_tree_root` and `inline_tx_debt_tree_root` in the `previous_step_header.current_state` are both empty hashes (verified by `end_cap_core_gadget.enforce_signature_constraints`).
    *   **Checkpoint Consistency:** The `last_checkpoint_id` in the `previous_step_header.current_state.user_leaf` matches the `checkpoint_id` from the `session_start_context`.
    *   **Final Output Structure:** The public inputs of the End Cap proof hash a `UPSEndCapResultCompact` structure containing the `start_user_leaf_hash`, `end_user_leaf_hash`, `checkpoint_tree_root_hash` (all from the final `previous_step_header`), and the `user_id`.
*   **Assumptions Made:**
    1.  The witness data (`UPSEndCapFromProofTreeGadgetInput`) provided is accurate initially.
    2.  System constants like `network_magic`, `DEFERRED_TRANSACTION_TREE_HEIGHT`, `INLINE_TRANSACTION_TREE_HEIGHT` (for deriving empty roots) are correct.
    3.  The assumption about the validity of the *starting* `checkpoint_tree_root` (from `UPSStartSessionCircuit`) is *still* carried forward implicitly into the `UPSEndCapResultCompact` output.
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying the last step proof, the signature proof, and ensuring consistency between the signature payload data and the final UPS header state.
    *   Assumption 2 relies on correct system setup.
    *   Assumption 3 is *not* discharged. The End Cap proof essentially certifies: "Assuming the starting checkpoint X was valid, User Y correctly transitioned their state to Z and authorized it". All *internal* UPS assumptions (like correct proof tree construction, valid intermediate steps, correct CFC execution) have been verified and compressed into this final proof.
*   **Contribution to Horizontal Scalability:** Packages the user's entire block activity into a single, efficiently verifiable proof. This proof can be submitted to the network and processed by the GUTA layer in parallel with End Cap proofs from countless other users.
*   **High-Level Functionality:** Securely concludes and authorizes a user's transaction batch, preparing it for network-level aggregation.

## 5. Phase 2: Global User Tree Aggregation (GUTA) Circuits

The DPN receives End Cap proofs and potentially other state change proofs (like user registrations) and aggregates them in parallel using GUTA circuits. These circuits operate on `GlobalUserTreeAggregatorHeader` structures, which track state transitions within the Global User Tree (`GUSR`).

*(Note: The exact circuit implementations are inferred from the gadgets. These circuits follow standard recursive aggregation patterns.)*

### 5.1. `GUTAProcessEndCapCircuit` (Hypothetical)

*   **Purpose:** Integrates a validated user End Cap proof into the GUTA hierarchy.
*   **Core Gadget:** `VerifyEndCapProofGadget`
*   **Input:** An `UPSStandardEndCapCircuit` proof and its associated `UPSEndCapResultCompact` data. Also needs witness for `checkpoint_historical_merkle_proof` and `guta_stats`.
*   **What it Proves:**
    *   **End Cap Proof Validity:** The provided End Cap proof is valid and was generated by the correct circuit (`known_end_cap_fingerprint_hash`).
    *   **End Cap Result Consistency:** The public inputs hash of the End Cap proof matches the hash of the provided `UPSEndCapResultCompact` data.
    *   **Historical Checkpoint Validity:** The `checkpoint_tree_root_hash` claimed in the `UPSEndCapResultCompact` existed as a historical root within the `checkpoint_historical_merkle_proof.current_root` (which represents the `CHKP` root being targeted by *this* GUTA aggregation step).
    *   **GUTA Header Output:** Correctly constructs a `GlobalUserTreeAggregatorHeader` where:
        *   `guta_circuit_whitelist` is set (likely from input/config).
        *   `checkpoint_tree_root` matches `checkpoint_historical_merkle_proof.current_root`.
        *   `state_transition` reflects the change from `start_user_leaf_hash` to `end_user_leaf_hash` at the correct `user_id` index (level `GLOBAL_USER_TREE_HEIGHT`).
        *   `stats` are populated based on input witness.
*   **Assumptions Made:**
    1.  Witness data (End Cap proof, result, stats, historical proof) is accurate initially.
    2.  The `known_end_cap_fingerprint_hash` constant is correct.
    3.  The `guta_circuit_whitelist` root provided (implicitly or explicitly) is correct for this GUTA context.
    4.  The `checkpoint_historical_merkle_proof.current_root` provided accurately represents the target `CHKP` root for this aggregation level. (This implicitly carries forward the assumption about the *original* starting checkpoint root's validity).
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying the End Cap proof and the historical checkpoint proof.
    *   Assumption 2 is a system parameter.
    *   Assumptions 3 and 4 are *not* discharged; they are bundled into the output `GlobalUserTreeAggregatorHeader` and passed upwards to the next GUTA aggregation level.
*   **Contribution to Horizontal Scalability:** Allows individual user session results (already proven locally) to be independently verified against historical state and prepared as standardized GUTA inputs for parallel aggregation.
*   **High-Level Functionality:** Validates and incorporates user end-of-session proofs into the global state aggregation process.

### 5.2. `GUTARegisterUserCircuit` (Hypothetical)

*   **Purpose:** Processes the registration of new users, updating the `GUSR` tree.
*   **Core Gadgets:** `GUTAOnlyRegisterUsersGadget`, `GUTARegisterUsersGadget`, `GUTARegisterUserFullGadget`, `GUTARegisterUserCoreGadget`
*   **Input:** Data for users being registered, including proofs linking their public keys to a `user_registration_tree_root`, and delta proofs for `GUSR` updates. Also needs the target `guta_circuit_whitelist` and `checkpoint_tree_root`.
*   **What it Proves:**
    *   **Valid Registration:** Each user's provided `public_key` is present in the `user_registration_tree_root`.
    *   **Correct GUSR Insertion:** For each user, the `GUSR` tree correctly transitioned at the `user_id` index from an empty hash to the new `PsyUserLeaf` hash (initialized with the verified `public_key` and `default_user_state_tree_root`). This is verified using delta proofs.
    *   **GUTA Header Output:** Correctly constructs a `GlobalUserTreeAggregatorHeader` representing the combined state transition for all registered users. `stats` are typically zero for pure registrations. The header uses the input `guta_circuit_whitelist` and `checkpoint_tree_root`.
*   **Assumptions Made:**
    1.  Witness data (registration proofs, user data, delta proofs) is accurate initially.
    2.  The input `guta_circuit_whitelist` and `checkpoint_tree_root` are correct for this context.
    3.  The `default_user_state_tree_root` constant is correct.
    4.  The underlying assumption about the validity of the input `checkpoint_tree_root` is carried forward.
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying registration proofs and GUSR delta proofs.
    *   Assumption 2 & 4 are passed upwards via the output header.
    *   Assumption 3 is a system parameter.
*   **Contribution to Horizontal Scalability:** Allows batches of user registrations to be processed, potentially in parallel branches of the GUTA aggregation tree.
*   **High-Level Functionality:** Securely adds new users to the global system state.

### 5.3. `GUTAAggregationCircuit` (Hypothetical - Multiple Variants Possible)

*   **Purpose:** The workhorse of parallel aggregation. Combines the results (headers) from two lower-level GUTA proofs (which could originate from End Caps, registrations, or previous aggregations).
*   **Core Gadgets:** `VerifyGUTAProofGadget`, `TwoNCAStateTransitionGadget` (for combining different branches), `GUTAHeaderLineProofGadget` (for propagating up a single branch), `GUTAStatsGadget`
*   **Input:** Two input GUTA proofs (`ProofWithPublicInputs`) and their corresponding `GlobalUserTreeAggregatorHeader` data. Witness for NCA proofs if needed.
*   **What it Proves:**
    *   **Input Proof Validity:** Both input GUTA proofs are valid.
    *   **Input Proof Whitelist:** Both input proofs were generated by circuits listed in the *same* `guta_circuit_whitelist` (taken from their headers).
    *   **Input Proof Checkpoint Consistency:** Both input proofs reference the *same* `checkpoint_tree_root` (taken from their headers).
    *   **Input Header Consistency:** The public inputs hash of each input proof matches the hash of its corresponding provided `GlobalUserTreeAggregatorHeader`.
    *   **State Transition Combination Logic:** The `state_transition` in the *output* GUTA header correctly combines the `state_transition`s from the two input headers. This involves:
        *   Verifying NCA proofs if combining transitions on different branches (`TwoNCAStateTransitionGadget`).
        *   Ensuring direct linkage (`old_root` matches `new_root`) if combining transitions on the same path.
        *   Correctly propagating the transition upwards if only one input represents a change (`GUTAHeaderLineProofGadget`).
    *   **Stats Combination:** The `stats` in the output header are the correct sum of the stats from the input headers (`GUTAStatsGadget.combine_with`).
    *   **GUTA Header Output:** Correctly constructs the output `GlobalUserTreeAggregatorHeader` using the combined state transition, combined stats, and the common `guta_circuit_whitelist` and `checkpoint_tree_root` from the inputs.
*   **Assumptions Made:**
    1.  Witness data (input proofs, headers, NCA/sibling proofs) is accurate initially.
    2.  The assumptions about the validity of the common `guta_circuit_whitelist` and `checkpoint_tree_root` carried by the *input* proofs are implicitly carried forward.
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying the input proofs, their linkage to the input headers, and the logic for combining state transitions and stats.
    *   Assumption 2 is *not* discharged; these common contextual assumptions are passed upwards in the output header.
*   **Contribution to Horizontal Scalability:** This is the core mechanism enabling parallel processing. Thousands of these circuits can run concurrently on the DPN, merging branches of the GUTA proof tree structure, dramatically speeding up aggregation compared to sequential processing.
*   **High-Level Functionality:** Securely and recursively combines verified state changes from multiple independent sources into larger, aggregated proofs.

### 5.4. `GUTANoChangeCircuit`

*   **Purpose:** Handles intervals where no relevant user state changed (`GUSR` root remains the same) but the network needs to acknowledge the advancement of the `checkpoint_tree_root`.
*   **Core Gadget:** `GUTANoChangeGadget`
*   **Input:** Proof (`checkpoint_tree_proof`) that a specific `checkpoint_leaf` exists in the target `checkpoint_tree_root`. The target `guta_circuit_whitelist` root.
*   **What it Proves:**
    *   **Checkpoint Validity:** The provided `checkpoint_leaf` hash matches the value proven to be in the `checkpoint_tree_proof`.
    *   **GUSR Consistency:** The `global_state_roots.user_tree_root` within the `checkpoint_leaf` is used as both the `old_node_value` and `new_node_value` in the output header's `state_transition`.
    *   **GUTA Header Output:** Correctly constructs a `GlobalUserTreeAggregatorHeader` with the input `guta_circuit_whitelist`, the input `checkpoint_tree_root`, a state transition showing no change in the `GUSR` root (at index 0, level 0), and zeroed `stats`.
*   **Assumptions Made:**
    1.  Witness data (checkpoint proof, leaf) is accurate initially.
    2.  The input `guta_circuit_whitelist` root is correct for this context.
    3.  The assumption about the validity of the input `checkpoint_tree_root` is carried forward.
*   **How Assumptions are Discharged:**
    *   Assumption 1 is checked by verifying the checkpoint proof.
    *   Assumptions 2 and 3 are passed upwards via the output header.
*   **Contribution to Horizontal Scalability:** Ensures the GUTA aggregation process can produce valid proofs even for periods of inactivity in user state changes, keeping the aggregation synchronized with the progressing checkpoint tree.
*   **High-Level Functionality:** Allows the GUTA layer to represent a "no-op" state transition correctly anchored to an updated checkpoint.

## 6. Phase 3: Final Block Proof Generation

### 6.1. Checkpoint Tree "Block" Circuit (Top-Level Aggregation)

*   **Purpose:** The final circuit in the chain. It aggregates the ultimate proofs from the top-level state trees (the final GUTA proof for `GUSR`, proofs for `GCON` updates, etc.) and verifies the transition against the previous block's finalized state.
*   **Core Logic:** Likely uses variants of `VerifyStateTransitionProofGadget` or similar aggregation gadgets tailored for combining the top-level tree proofs. It takes the previous block's `CHKP` root as a crucial public input.
*   **Input:** The final aggregated proof from the GUTA layer (representing all `GUSR` changes), potentially proofs for `GCON` changes (e.g., new contract deployments via `VerifyAggUserRegistrationDeployGuta` logic), and the **previous block's finalized `CHKP` root hash**.
*   **What it Proves:**
    *   **Top-Level Proof Validity:** The input proofs (e.g., final GUTA proof) are valid and adhere to their respective whitelists and checkpoint contexts.
    *   **State Root Consistency:** The final roots of `GUSR`, `GCON`, etc., derived from the input proofs are correctly assembled into the `PsyCheckpointGlobalStateRoots` for the *new* block.
    *   **New Checkpoint Leaf Construction:** The new `PsyCheckpointLeaf` is correctly constructed using the new global state roots and other block metadata (e.g., block number, timestamp).
    *   **New Checkpoint Root Computation:** The new `CHKP` root hash is correctly computed based on the new leaf and its position in the Checkpoint Tree.
    *   **Final State Link:** The **critical verification**: it proves that the state transitions represented by the input proofs (originating from potentially millions of user transactions) correctly and validly transform the state anchored by the **input `previous_block_chkp_root`** into the state represented by the **computed `new_chkp_root`**.
*   **Assumptions Made:**
    1.  The **only** remaining significant external assumption is that the **public input `previous_block_chkp_root` hash is indeed the valid, finalized root hash of the immediately preceding block.**
*   **How Assumptions are Discharged:**
    *   All assumptions related to internal consistency, circuit whitelists, correct state transitions, user signatures, etc., have been recursively verified and discharged by the preceding UPS and GUTA circuit layers.
    *   Assumption 1 is discharged by the consensus mechanism or the verifier. They *know* the hash of the last finalized block and check if the proof's public input matches it. If it matches, the proof demonstrates a valid state transition between the two blocks.
*   **Contribution to Horizontal Scalability:** This final step takes the output of the massively parallel GUTA aggregation and produces a single, constant-size ZK proof for the entire block's validity. Verifying this proof is extremely fast, regardless of how many transactions were processed in parallel.
*   **High-Level Functionality:** Creates the final, succinct, and efficiently verifiable proof for the entire block, cryptographically linking it to the previous block and enabling trustless verification of the entire chain's state transition.

## 7. Assumption Reduction Summary: The Journey to Trustlessness

The Psy circuit flow demonstrates a progressive reduction and discharge of assumptions:

1.  **Start UPS:** Assumes initial state fetched from the last block is correct *locally* and that the *last block's CHKP root* was valid. Verifies local consistency.
2.  **UPS Transactions:** Assumes previous step was valid, assumes current step's witness is correct. Verifies previous proof, verifies current CFC/debt logic, verifies state delta. Passes on proof tree root assumption and the *original* starting CHKP root assumption.
3.  **UPS End Cap:** Assumes last step was valid, assumes signature proof/witness correct. Verifies last step, verifies signature proof, verifies consistency between final UPS state and signature payload. Discharges all *internal* UPS assumptions (proof tree validity, intermediate step validity). Outputs a proof carrying only the assumption about the *original* starting CHKP root.
4.  **GUTA (Process End Cap/Register User):** Assumes End Cap/Registration proof is valid, assumes historical checkpoint/whitelist context. Verifies input proof against context. Outputs a GUTA header carrying the context assumptions upwards.
5.  **GUTA (Aggregation):** Assumes input GUTA proofs are valid and share context. Verifies input proofs, verifies combination logic. Outputs an aggregated GUTA header carrying the common context assumptions upwards.
6.  **Final Block Circuit:** Assumes top-level proofs (like final GUTA) are valid. Takes the *previous block's CHKP root* as the *only* major external assumption. Verifies input proofs, verifies construction of the new CHKP root based on inputs. Discharges all remaining contextual assumptions (whitelists, checkpoints derived from the input proofs). The final proof stands as: "IF the previous CHKP root was X, THEN the new CHKP root is validly Y".

This journey transforms broad initial assumptions about state correctness into a single, verifiable dependency on the previously accepted state, underpinned by the mathematical certainty of ZK proofs.

## 8. Conclusion: Scalability Through Parallelism and Proofs

Psy achieves true horizontal scalability by combining:

1.  **PARTH Architecture:** Isolates user state modifications, enabling conflict-free parallel transaction execution *within* a block.
2.  **User Proving Sessions (UPS):** Allows users to locally prove their own transaction sequences, offloading initial proving work.
3.  **Parallel ZK Aggregation (GUTA & DPN):** Enables the network to verify and combine proofs from millions of users concurrently, overcoming the limitations of sequential processing.
4.  **Recursive Proofs:** Compresses vast amounts of computation into succinct, fixed-size proofs, making final block verification extremely efficient.
