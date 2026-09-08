# Common Merkle Gadgets

This protocol reference covers the shared Merkle gadgets composed by UPS, GUTA, coordinator, and bridge circuits, alongside the [circuit index](Circuits.md) and [gadget index](Gadgets.md).

> Updated: 2026-09-08. Source of truth: local worktree.
> Two parallel stacks exist: client (`client_prover/psy_circuit/psy_common_circuit/...`) for UPS/DPN, and node (`psy_plonky2_common_circuits/...`) for GUTA/coordinator/bridge. Semantics match; prefer the stack the calling circuit imports.
> Core line counts exclude blank lines, `//` comments, block comments, and `#[cfg(test)]` modules.

## Abstract

Reusable Merkle / historical-root / Spiderman / variable-height gadgets that UPS, GUTA, coordinator, and bridge circuits compose.

## Table of Contents

- [1. MerkleProofGadget](#1-merkleproofgadget)
- [2. DeltaMerkleProofGadget](#2-deltamerkleproofgadget)
- [3. HistoricalRootMerkleProofGadget](#3-historicalrootmerkleproofgadget)
- [4. SpidermanAppendProofGadget](#4-spidermanappendproofgadget)
- [5. QVariableHeightDeltaMerkleProofGadget](#5-qvariableheightdeltamerkleproofgadget)
- [6. DualVariableHeightDeltaMerkleProofGadget](#6-dualvariableheightdeltamerkleproofgadget)
- [7. FrontierAppendGadget](#7-frontierappendgadget)
- [8. FullMerkleTreeAppendGadget](#8-fullmerkletreeappendgadget)
- [9. Client VariableHeightMerkleProofGadget](#9-client-variableheightmerkleproofgadget)
- [10. Client VariableHeightDeltaMerkleProof family](#10-client-variableheightdeltamerkleproof-family)
- [11. Client DPN/IMT helpers](#11-client-dpnimt-helpers)
- [12. Out of scope / parallel variants](#12-out-of-scope--parallel-variants)

## 1. `MerkleProofGadget`

-   **File (client):** `client_prover/psy_circuit/psy_common_circuit/src/hash/merkle/gadgets/merkle_proof.rs:30-195` (core ~214 before helpers/tests)
-   **File (node):** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/merkle_proof.rs` (core ~289)
-   **Purpose:** Fixed-height inclusion: `root = fold two_to_one_swapped(value, siblings, index_bits)`.
-   **Private Inputs / Witness:** `index`, `value`, `siblings[height]`.
-   **Constraints (pseudocode):**

    ```text
    range_check(index, height); bits = split_le(index)
    state = value
    for bit, sib in zip(bits, siblings):
      state = two_to_one_swapped(state, sib, bit)
    root = state
    ```

-   **Role:** UPS start, whitelist proofs, contract inclusion, CFC UCON, withdrawal claim inclusion.

---

## 2. `DeltaMerkleProofGadget`

-   **File (client):** `client_prover/psy_circuit/psy_common_circuit/src/hash/merkle/gadgets/delta_merkle_proof.rs:31-114` (+ variants; core ~345 API)
-   **File (node):** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/delta_merkle_proof.rs` (core ~524)
-   **Purpose:** Same siblings for old→new leaf. Variants: append-only, push-sparse, pop-right, dequeue-left.
-   **Private Inputs / Witness:** `index`, `old_value`, `new_value`, `siblings`.
-   **Constraints (pseudocode):**

    ```text
    old_root = MerkleProof(old_value)
    new_root = MerkleProof(new_value)
    // append_only: old_value == ZERO (+ sibling emptiness rules)
    ```

-   **Role:** UCON updates, deferred debt pop, checkpoint append, bridge chain deltas.

---

## 3. `HistoricalRootMerkleProofGadget`

-   **File (client):** `client_prover/psy_circuit/psy_common_circuit/src/hash/merkle/gadgets/historical_root_merkle_proof.rs:19-131` (core ~143)
-   **File (node):** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/historical_root_merkle_proof.rs` (core ~163)
-   **Purpose:** Prove an append-only tree’s `current_root` once had `historical_root` by zeroing leaves at/beyond an index (gte/gt variants).
-   **Private Inputs / Witness:** `index`, `current_value`, `siblings`.
-   **Constraints (pseudocode):**

    ```text
    current_root = fold(value, siblings, bits)
    historical starts ZERO (gte) or value (gt)
    at each level reconstruct hist left/right with level_zero_hash when path bit requires
    ```

-   **Role:** UPS deferred/inline debt pivots; GUTA checkpoint-upgrade circuits; EndCap historical checkpoint check.

---

## 4. `SpidermanAppendProofGadget`

-   **File (client):** `client_prover/psy_circuit/psy_common_circuit/src/hash/merkle/gadgets/spiderman_append_proof.rs:12-46` (core ~52)
-   **File (node):** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/spiderman_append_proof.rs:8-98` (core ~91; `allow_existing` / `allow_overwrite`)
-   **Purpose:** Batch append via top-line delta + full subtree “web” append; glue subtree root into top-line leaf.
-   **Private Inputs / Witness:** Top-line `DeltaMerkleProof` + old/new web leaves (`SpidermanUpdateProof`).
-   **Constraints (pseudocode):**

    ```text
    top.old_value == web.old_root
    top.new_value == web.new_root
    expose old_root = top.old_root, new_root = top.new_root
    ```

-   **Role:** Coordinator user-registration, deploy, update-contract batch leaves.

---

## 5. `QVariableHeightDeltaMerkleProofGadget`

-   **File:** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/q_variable_height_delta_merkle_proof.rs:18-140` (core ~169)
-   **Purpose:** Single delta Merkle proof with variable effective height ≤ max; bits beyond height skipped.
-   **Constraints (pseudocode):**

    ```text
    bit_info = VariableHeightMerkleProofIndexBitInfo (single-index)
    for each level i < max:
      hashed = two_to_one_swapped(cur, sib[i], bit[i])
      cur = select(is_bit_not_within_height[i], cur, hashed)
    ```

-   **Role:** `SingleVariableHeightStateTransitionGadget`, left-linear-right-VH GUTA gadgets.

---

## 6. `DualVariableHeightDeltaMerkleProofGadget`

-   **File:** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/dual_variable_height_delta_merkle_proof.rs:16-200` (core ~208)
-   **Purpose:** Two consecutive variable-height deltas (left then right) sharing height/bit-info; `left.new_root == right.old_root`.
-   **Constraints (pseudocode):**

    ```text
    bit_info from left+right index bits
    left_new_root == right_old_root
    old_root = left_old; intermediate = right_old; new_root = right_new
    ```

-   **Role:** Core engine under `DualVariableHeightStateTransitionGadget` (replaces obsolete `TwoNCAStateTransitionGadget`). Used by TwoGUTA / TwoEndCap / checkpoint-upgrade aggregators.

---

## 7. `FrontierAppendGadget`

-   **File:** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/frontier_append.rs` (core ~165 excl. tests)
-   **Purpose:** Append one leaf into a height-`H` Merkle tree given the **frontier** (left-spine) representation; updates frontier and root.
-   **Public Inputs:** None (embedded).
-   **Private / Witness:** `old_frontier[H]`, `leaf_hash`, `index`.
-   **Constraints (pseudocode):**

    ```text
    reconstruct old_root from frontier + index path
    write leaf at index; update frontier cells along path
    new_root from updated frontier
    ```

-   **Role:** Engine under `DepositBatchAppendCircuit` batch loop.

---

## 8. `FullMerkleTreeAppendGadget`

-   **File:** `psy_plonky2_common_circuits/src/hash/merkle/gadgets/full_merkle_tree_append.rs` (core ~229 excl. tests)
-   **Purpose:** Append using full sibling path (non-frontier) when the caller supplies complete Merkle witnesses.
-   **Role:** Alternate append primitive; prefer frontier form for deposit batching.

*(Bit helpers `merkle_proof_bits.rs` / `bits.rs` / `variable_height_delta_merkle_proof_index.rs` are support modules — covered via the gadgets above.)*


---

## 9. Client `VariableHeightMerkleProofGadget`

*   **File:** `client_prover/psy_circuit/psy_common_circuit/src/hash/merkle/gadgets/variable_height_merkle_proof.rs` (core ~219)
*   **Stack:** **Client only** (UPS/DPN). Node GUTA uses `QVariableHeightDeltaMerkleProofGadget` / `DualVariableHeightDelta…` instead (§5–§6).
*   **Purpose:** Inclusion proof with effective height `h` where `1 ≤ h ≤ max_height`; levels at/above `h` are skipped (state unchanged).
*   **Private / Witness:** `index`, `value`, `siblings[max_height]`, `height` (or constant height target).
*   **Constraints (pseudocode):**
```text
    assert 1 <= height <= max_height; range_check(index, max_height)
    bits = split_le(index, max_height)
    state = value
    for i in 0..max_height:
      hashed = two_to_one_swapped(state, sib[i], bits[i])
      state = select(i >= height, state, hashed)   // skip above effective height
    root = state
    // optional: expose subtree-root index / path direction for IMT / NCA callers
    ```
*   **Role:** DPN VM `StateReaderGadget` — `IMTExternalRead` / `IMTOtherUserRead` / `IMTContainsOtherUser` and generic `VariableHeightMerkleProof` state cmds bind contract-state slots under a variable-height path (`state_readers.rs`).

---

## 10. Client VariableHeightDeltaMerkleProof family

### `VariableHeightDeltaMerkleProofGadget`

*   **File:** `…/variable_height_delta_merkle_proof.rs` (core ~183)
*   **Purpose:** Same-sibling old→new leaf with variable effective height (`VariableHeightBitInfo`: `is_bit_not_within_height`, `is_first_bit_outside_height`).
*   **Constraints (pseudocode):**
```text
    bit_info from index bits + height
    old_root = fold_vh(old_value, siblings, bit_info)
    new_root = fold_vh(new_value, siblings, bit_info)
    ```
*   **Role:** Base client VH-delta; subtree helpers may expose parent index / right-child flags.

### `VariableHeightDeltaMerkleProofOptGadget`

*   **File:** `…/variable_height_delta_merkle_proof_opt.rs` (core ~386)
*   **Purpose:** Optimized VH-delta used by client treeprover / NCA merge (`sub_tree_top_line.rs`, `UpdateNearestCommonAncestorProofOptGadget` in `sub_tree_update_proof_opt.rs`).
*   **Role:** Client-side nearest-common-ancestor style merges (historical GUTA-adjacent helpers). Live **node** GUTA aggregation uses node `DualVariableHeightDeltaMerkleProofGadget` instead.

### `VariableHeightDeltaMerkleProofOptV2Gadget`

*   **File:** `…/variable_height_delta_merkle_proof_opt_v2.rs` (core ~212)
*   **Purpose:** Second opt revision of the same VH-delta API (tests + opt NCA path). Prefer Opt or V2 consistently with the importing caller; do not mix bit-info layouts across a single proof.

### Relation to node stack

| Client | Node (GUTA/Bridge/Coord) |
|---|---|
| `VariableHeightMerkleProofGadget` (inclusion) | Fixed `MerkleProofGadget` or VH via delta gadgets |
| `VariableHeightDeltaMerkleProofGadget` / Opt / OptV2 | `QVariableHeightDeltaMerkleProofGadget`, `DualVariableHeightDeltaMerkleProofGadget` |

---

## 11. Client DPN/IMT helpers

Used heavily by DPN `StateReaderGadget` (see [PrivacyCircuits.md](./PrivacyCircuits.md) §5).

### `SubSlotMerkleProofBatchGadget` / `SubSlotDeltaMerkleProofBatchGadget`

*   **Files:** `sub_slot_merkle_proof_batch.rs` (core ~84); `sub_slot_delta_merkle_proof_batch.rs` (core ~260)
*   **Purpose:** Batch fixed-width sub-slot inclusion / delta updates under a contract-state packing layout.
*   **Role:** DPN state cmds that touch packed sub-slots inside a user-contract tree.

### `IMTUpdateGadget` / `IMTInsertGadget` (`imt_contract_state_update.rs`)

*   **File:** `imt_contract_state_update.rs` (core ~228)
*   **Purpose:** Indexed Merkle Tree leaf update (1 delta) or insert (predecessor + new-leaf deltas) with ordered-leaf constraints (`is_qhashout_lt`).
*   **Role:** DPN IMT set/read paths composed in `state_readers.rs` (`IMTSetGadget`, `IMTReadGadget`, …).

### `UpdateNearestCommonAncestorProofGadget` / `…OptGadget`

*   **Files:** `sub_tree_update_proof.rs` (core ~124); `sub_tree_update_proof_opt.rs` (wraps Opt VH-delta)
*   **Purpose:** Merge two VH-deltas that share an NCA into one parent transition (client NCA gadget; **not** the live node `DualVariableHeightStateTransitionGadget`).
*   **Role:** Client treeprover / historical GUTA proof-input tooling.

---

## 12. Out of scope / parallel variants

Documented for inventory; **not** required reading for the live Plonky2 node+bridge audit path unless a caller is in scope:

| Path | Note |
|---|---|
| `…/sha256/` / `sha256_truncated/` / `generic/` merkle+delta | Alternate hash stacks |
| `old_historical_merkle_proof.rs` | Superseded by `HistoricalRootMerkleProofGadget` |
| `append_many_merkle_proof.rs` | **Absent** from this worktree (do not cite as empty file) |
| `merkle_array_gen.rs` | Helper for 2-bit array Merkle enforcement (DPN) |
| Client vs node `SpidermanAppendProofGadget` | Both covered in §4; node has `allow_existing` / `allow_overwrite` |
