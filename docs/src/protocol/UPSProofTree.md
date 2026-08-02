# The Psy User Proving Session (UPS) Proof Tree: Efficient Recursive Verification

## 1. Introduction: The Challenge of Recursive Verification Costs

The User Proving Session (UPS) relies on recursive ZK proofs, where each step cryptographically verifies the previous one. A naive approach might involve embedding the *entire* verification logic of the previous step's circuit *inside* the current step's circuit. However, this leads to several problems:

1.  **Variable Circuit Complexity:** Different UPS steps might verify different underlying circuits (standard CFC, deferred CFC, start session), each with varying verification costs. This makes creating fixed-size, efficient recursive circuits difficult.
2.  **Computational Bloat:** Repeatedly verifying complex proofs within recursion significantly increases the computational cost and proving time for each step.
3.  **Limited Parallelism:** Tightly coupling verification logic hinders the potential to parallelize the *proving* work, even if the *witness generation* is serial.

The **UPS Proof Tree** architecture elegantly solves these issues by **deferring the direct verification cost** and replacing it with **cheap cryptographic commitments and existence checks**.

## 2. The UPS Proof Tree: Commit, Don't Verify (Yet)

### 2.1 Core Concept: A Merkle Tree of Proof Commitments

Instead of fully verifying the previous proof *within* the current step's circuit, the UPS system commits each generated proof to a Merkle tree specific to the session.

*   **Leaf Content:** Each leaf `i` stores a hash committing to the proof's identity and context:
    *   **Standard Proofs (like ZK Signature):** `LeafValue_i = Hash(ProofFingerprint_i, PublicInputsHash_i)`
    *   **Tree-Aware Proofs (UPS Steps):** `LeafValue_i = Hash(ProofFingerprint_i, TreeAwarePublicInputsHash_i)`
        *   Where `TreeAwarePublicInputsHash_i = Hash(ProofTreeRoot_i-1, InnerPublicInputsHash_i)`

*   **Append-Only Construction:** As each proof (CFC execution proof, UPS step proof, signature proof) is generated *locally*, its corresponding `LeafValue` is computed and appended to the tree. The tree root updates with each addition.

### 2.2 Cheap In-Circuit Checks: Attesting Existence and Linkage

The core innovation lies in using specialized gadgets *instead* of full verifiers within the recursive steps:

*   **Gadget 1: `AttestProofInTreeGadget` (For non-tree-aware proofs like Signatures)**
    *   **Function:** Proves that a commitment `Hash(Fingerprint, PublicInputsHash)` exists as a leaf within a tree identified by `AttestedProofTreeRoot`.
    *   **Mechanism:** Takes `Fingerprint`, `PublicInputsHash`, and a Merkle `inclusion_proof` witness. Computes the expected leaf hash and verifies the Merkle proof against it.
    *   **Cost:** Primarily the cost of Merkle proof verification (logarithmic hashing) and a few hashes/comparisons – significantly cheaper than verifying the actual ZK proof.
    *   **Assumption:** The ZK proof corresponding to the `Fingerprint` and `PublicInputsHash` *is itself valid*. This gadget only proves *commitment existence*.

*   **Gadget 2: `AttestTreeAwareProofInTreeGadget` (For tree-aware UPS step proofs)**
    *   **Function:** Proves that a commitment for a *tree-aware* proof exists in the tree, linking it to the *correct historical state* of the tree.
    *   **Mechanism:** Takes `Fingerprint`, `InnerPublicInputsHash`, an `inclusion_proof` (in the *current* tree), and a `historical_root_proof` (pivot proof showing `Root_N-2 -> Root_N-1`). It computes the expected *tree-aware* leaf hash `Hash(Fingerprint, Hash(Root_N-1, InnerPublicInputsHash))` and verifies the `inclusion_proof` against it and the `current root`. It also verifies the `historical_root_proof`.
    *   **Cost:** Cost of two Merkle proof verifications (inclusion and historical pivot) plus hashing/comparisons – still much cheaper than full ZK proof verification.
    *   **Assumption:** The ZK proof corresponding to the `Fingerprint` and `InnerPublicInputsHash` (relative to `Root_N-1`) *is itself valid*.

### 2.3 How Recursion Works with the Tree: Deferral in Action

Consider UPS Step N verifying Step N-1:

1.  **Step N-1 Runs:** Generates its ZK proof (`Proof_N-1`) and computes its tree-aware public inputs hash `TAPH_N-1 = Hash(Root_N-2, InnerPubHash_N-1)`. Its commitment `LeafValue_N-1 = Hash(Fingerprint_N-1, TAPH_N-1)` is added to the tree, updating the root to `Root_N-1`.
2.  **Step N Circuit Runs:**
    *   **Does NOT Verify `Proof_N-1` directly.**
    *   Instead, it uses `AttestTreeAwareProofInTreeGadget`.
    *   **Assumes:** The `Proof_N-1` (whose commitment is being checked) *is valid*.
    *   **Takes Witness:** `Fingerprint_N-1`, `InnerPubHash_N-1`, `inclusion_proof` (for Leaf N-1 in tree N-1), `historical_root_proof` (Root N-2 -> Root N-1).
    *   **Verifies:** That the commitment to `Proof_N-1` exists correctly linked to `Root_N-2` within the tree state `Root_N-1`. This cryptographically confirms the sequential link.
    *   **Computes:** Its own output header hash `InnerPubHash_N`.
    *   **Generates:** Its own ZK proof (`Proof_N`) whose public inputs commit to `Hash(Root_N-1, InnerPubHash_N)`.

Crucially, the circuit for Step N has a **fixed, relatively low complexity**, dominated by the Merkle proof gadgets, regardless of the complexity of the circuit used for Step N-1. It only deals with *commitments* to proofs, not the proofs themselves.

## 3. Discharging the Assumptions: The End Cap and Beyond

Throughout the UPS, the core assumption accumulates: **"All ZK proofs committed to the tree are valid."**

*   **The End Cap's Role:** The `UPSStandardEndCapCircuit` is where this primary assumption begins to be addressed *for the UPS internal proofs*.
    *   It verifies the *last* UPS step proof's commitment using `AttestTreeAwareProofInTreeGadget`.
    *   It verifies the *ZK Signature proof's* commitment using `AttestProofInTreeGadget`.
    *   It ensures both verifications reference the *same final proof tree root*, linking the signature to the end state of the transaction sequence.
    *   **Optional (but recommended):** It often includes a `VerifyAggProofGadget` (or `VerifyAggRootGadget`). This gadget takes a ZK proof (generated *outside* the UPS circuit) that recursively verifies *all the actual proofs committed to the UPS Proof Tree*. This aggregation proof essentially proves the core assumption: "All proofs committed to the tree with root `FinalRoot` are valid". By verifying *this single aggregation proof*, the End Cap circuit discharges the validity assumption for all internal UPS steps.

*   **Deferred Verification:** The actual computationally expensive work of verifying all the individual UPS step proofs and the signature proof is bundled into generating the separate UPS Proof Tree aggregation proof. This aggregation can happen:
    *   **Locally:** After witness generation but before End Cap proving.
    *   **Remotely/Parallel:** In a future design, the witness data and tree commitments could be sent to parallel provers. They generate proofs for each step and the final aggregation proof. The End Cap circuit then only needs to verify the *single* aggregation proof.

## 4. Benefits Summary

1.  **Constant Recursive Step Cost:** The cost of verifying the previous step inside the current step's circuit is fixed and low (Merkle checks), independent of the previous step's circuit complexity. This allows for efficient recursion with consistent circuit degrees.
2.  **Deferral of Computation:** The heavy lifting of verifying the actual ZK proofs is pushed *out* of the main recursive path and consolidated into a single (optional but recommended) aggregation proof verified at the end.
3.  **Enables Parallel Proving:** By using the tree commitments as interfaces, the *proving* of individual UPS steps (and the final tree aggregation) can be parallelized across multiple workers, even if witness generation is serial. Workers only need the relevant witnesses and the expected tree roots/proofs to verify their step's link, without needing to run the *entire* previous circuit's verification logic.
4.  **Architectural Flexibility:** The system clearly separates *committing* to a proof's existence/context from *verifying* the proof's internal validity, allowing different strategies for when and how the full verification occurs.

In essence, the UPS Proof Tree acts as a highly efficient cryptographic ledger *within* the proving session, allowing circuits to cheaply attest to the existence and sequential linkage of prior computational steps, while deferring the bulk verification cost to a final, potentially parallelizable, aggregation step.