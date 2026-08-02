## Psy: Horizontally Scalable Blockchain via PARTH and ZK Proofs

### Introduction: The Serial Bottleneck

Traditional blockchains suffer from a serial execution bottleneck. They process transactions sequentially within a single state machine, meaning adding more nodes doesn't increase overall throughput (TPS). Parallel execution attempts often lead to race conditions and inconsistencies. Psy overcomes this fundamental limitation with its novel **PARTH** architecture and end-to-end Zero-Knowledge Proof (ZKP) system.

### The PARTH Architecture: Foundation for Parallelism

PARTH (Parallelizable Account-based Recursive Transaction History) redefines blockchain state organization:

1.  **Granular State:** Instead of one global state tree, Psy maintains a hierarchy of Merkle trees, most notably:
    *   **Per-User, Per-Contract State (`CSTATE`):** Each user has a *separate* Merkle tree (`CSTATE`) representing their specific state within *each* smart contract they interact with.
    *   **User Contract Tree (`UCON`):** Aggregates all `CSTATE` roots for a single user, representing their overall state across all contracts.
    *   **Global User Tree (`GUSR`):** Aggregates all `UCON` roots, representing the state of all users.
    *   **Global Contract Tree (`GCON`):** Represents the global state related to contract code/definitions.
    *   **Checkpoint Tree (`CHKP`):** The top-level tree whose root hash represents a verifiable snapshot of the *entire blockchain state* at a given block.

2.  **Controlled Interaction Rules (Key to Scalability):**
    *   **Write Locally:** A transaction initiated by a user can **only modify (write to)** the state within that specific user's own trees (primarily their `CSTATE` and `UCON` trees).
    *   **Read Globally (Previous State):** A transaction can **read** the state from *any* other user's trees (or global trees like `GCON`), but critically, it only sees the state **as it was finalized at the end of the *previous* block**.

3.  **Enabling Parallelism:** Because write operations are isolated to the sender's state trees, and read operations access the immutable, finalized state of the *last* block, transactions from *different users* within the *same* block operate independently. They cannot conflict or cause race conditions. This independence is the architectural breakthrough that allows for massive parallel processing.

### The End-to-End ZK Proof Process: Securing Parallelism

Psy uses a sophisticated system of ZK circuits and recursive proofs to verify all state transitions securely, even when processed in parallel.

**Step 1: Local Transaction Execution & Proving (User Level)**

*   **Action:** A user interacts with a dApp, triggering one or more smart contract function calls.
*   **Execution:** The logic defined in the specific **Contract Function Circuit (CFC)** associated with the smart contract is executed locally (or by a delegated prover).
*   **State Update:** This execution modifies the user's `CSTATE` tree for that contract. The Merkle root of the user's `UCON` tree is also updated to reflect this change.
*   **Proof Generation:** The user generates ZK proofs using **User Proving Session (UPS) circuits**. These proofs attest that:
    *   The contract logic (CFC) was executed correctly.
    *   The user's `CSTATE` and `UCON` trees transitioned correctly from a known previous state root to a new state root.
    *   **Assumptions:** These proofs rely on *public inputs* that declare assumptions about the state of the blockchain *before* the transaction (e.g., the user's previous `UCON` root, the relevant `GCON` root, and crucially, the `CHKP` root of the last finalized block which guarantees the validity of any global state read).
*   **Recursion:** If the user performs multiple actions, recursive proofs compress them into a single proof representing the net state change for that user within the block.

**Step 2: Parallel Proof Aggregation (Decentralized Proving Network + Realms)**
*   **Submission:** Users submit their final proofs and delta merkle proofs (representing their state transitions for the block) to their corresponding realm node on the Psy network. (see handle_recv_end_cap_from_user)
*   **Parallel Processing:** Thanks to the PARTH architecture ensuring user-transaction independence, the **Decentralized Proving Network** can take proofs from *thousands or millions* of users and begin verifying and aggregating them **in parallel**. Realms are in charge of sending the proofs to the queue to be aggregated by the proof workers
* Once all the update proofs are aggregated in a realm into a single proof, the realm sends that proof off to the block coordinator to be aggregated into a single proof of all realm updates at the end of the block.
*   **Hierarchical Aggregation:** Specialized **Aggregation Circuits** (e.g., for aggregating user contract trees, or global user trees) recursively verify batches of proofs from the layer below within the PARTH structure.
    *   Each aggregation circuit checks the validity of the input proofs it receives.
    *   It **enforces the assumptions** declared in the public inputs of the lower-level proofs. For example, a circuit aggregating user states ensures all input proofs correctly referenced the same previous global user state root.
    *   It outputs a single, smaller proof representing the validity of the entire batch it processed.

**Step 3: Final Block Proof Generation (Consensus / Block Leader)**

*   **Final Aggregation:** The parallel aggregation process continues up the hierarchy, culminating in the **Checkpoint Tree "Block" Circuit**. This final circuit aggregates proofs from the top-level trees (like `GUSR`, `GCON`).
*   **Inductive Verification:** Assumptions made by lower circuits are checked and discharged by higher circuits during the recursive process. By the time execution reaches the final "Block" circuit, the *only* remaining external assumption is the **root hash of the previous block's Checkpoint Tree (`CHKP` root)**.
*   **Trustless Link:** This final circuit verifies this previous `CHKP` root against the public input provided (which is the known, finalized root from the preceding block). This check creates a cryptographic, trustless link between consecutive blocks.
*   **Proof Singularity:** The output is a **single, succinct ZK proof** for the *entire block*, proving the validity of *all* transactions and the overall state transition from the previous `CHKP` root to the new `CHKP` root, without needing to reveal individual transaction details or re-execute anything.

**Step 4: Verification and Finalization**

*   The final block proof is broadcast and verified by consensus nodes (or potentially bridge contracts on other L1s).
*   Verification is extremely fast as it only involves checking the single ZK proof and the link to the previous block's state.
*   Once verified, the new `CHKP` root becomes the finalized, canonical state snapshot for that block.

### The Role of the Checkpoint Tree (`CHKP`) and Circuits

*   **Global State Snapshot (`CHKP`):** The `CHKP` root acts as a universal anchor. It captures a full snapshot of the entire chain and allows anyone to efficiently verify *any* piece of state information (user balance, contract variable, etc.) from *any* block by providing a Merkle proof linking that data back to the validated `CHKP` root of that block.
*   **Circuit Enforcement:** Each tree update within the PARTH structure is strictly controlled. Updates are only permitted if accompanied by a valid ZK proof generated by a pre-approved, **whitelisted circuit** designed for that specific tree transition. This constraint, enforced by the aggregation circuits above, ensures state changes adhere precisely to the defined rules (contract logic, protocol rules).

### Conclusion: Achieving Horizontal Scalability

Psy achieves true horizontal scalability through the synergy of:

1.  **PARTH Architecture:** Its granular state and specific read/write rules eliminate conflicts between transactions from different users within a block.
2.  **Parallel Proving:** This independence allows the computationally intensive task of ZK proof generation and aggregation to be massively parallelized across the Decentralized Proving Network.
3.  **Recursive ZK Proofs:** Efficiently compress and verify vast amounts of computation and state changes into a single, easily verifiable proof for each block, secured by the inductive verification up to the final Block Circuit linking to the previous state.

By processing user transactions independently and in parallel, secured by end-to-end ZK verification, Psy breaks the serial bottleneck and offers a path to blockchain performance potentially orders of magnitude higher than traditional architectures, truly scaling horizontally as more proving resources are added.



Key terms:
DPN - Dapen, the code name for the Psy rust smart contract language
UPS - User Proving Session, the process by which users prove transactions locally and generate the delta merkle proofs to be sent off to chain
End Cap - The last recursive proof which checks the signature and state deltas for a user
GUTA - Global User Tree Aggregation
