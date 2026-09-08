# Privacy Circuits

This protocol reference covers client-side shield deposit claim and private note inclusion circuits, alongside the [circuit index](Circuits.md) and [gadget index](Gadgets.md).

> Updated: 2026-09-08. Source of truth: `client_prover/psy_circuit/psy_dpn_circuit/src/circuits/privacy/`.
> Core line counts exclude blank lines, `//` comments, block comments, and `#[cfg(test)]` modules.
> Token precompile fingerprints (`private_note_inclusion_fingerprint`, `shield_claim_fingerprint`) must match these circuits; see [`docs/src/dev/token-privacy-circuit-fingerprints.md`](../dev/token-privacy-circuit-fingerprints.md).

## Abstract

Client-side privacy circuits used by shield deposit claim and private note inclusion. Protocol alias: `DepositInclusionCircuit` ≡ `ShieldDepositClaimCircuit`.

## Table of Contents

- [1. DepositInclusionCircuit](#1-depositinclusioncircuit-shielddepositclaimcircuit)
- [2. PrivateNoteInclusionCircuit](#2-privatenoteinclusioncircuit)
- [3. SlotValueInContractStateGadget (DPN)](#3-slotvalueincontractstategadget-dpn)
- [4. DapenContractFunctionCircuit (CFC)](#4-dapencontractfunctioncircuit-cfc)

## 1. `DepositInclusionCircuit` (`ShieldDepositClaimCircuit`)

-   **File:** `client_prover/psy_circuit/psy_dpn_circuit/src/circuits/privacy/deposit_inclusion.rs` — gadget `DepositInclusionGadget` ~31–181; circuit `DepositInclusionCircuit` ~215– (file core ~384 excl. tests from ~443)
-   **Purpose:** Prove a deposit leaf (matching relayer leaf layout) is included in the deposit tree; derive nullifier and note commitment for shield claim.
-   **Public Inputs:** 4 felts = Poseidon over  
    `shield_address[4] || amount_words[8] || token_words[8] || l2_token_contract_id_words[8] || source_chain_index || deposit_root[4] || nullifier_hash[4] || note_commitment[4] || deposit_index`
-   **Private Inputs / Witness:** `nullifier_secret[4]`, `note_secret[4]`, `shield_address`, deposit Merkle siblings, token/amount/l2 words, `source_chain_index`, `deposit_index`.
-   **Constraints (pseudocode):**

    ```text
    nullifier_hash = Poseidon(nullifier_secret)
    note_commitment = Poseidon(nullifier_secret || note_secret)
    amount_words[0..6] == 0   // high limbs zero
    deposit_commitment = Poseidon(shield || token || l2 || amount || chain || note_u32x8)
    Merkle(h=32): value=deposit_commitment, index=deposit_index → deposit_root
    register Poseidon(PI_preimage)
    ```

-   **Role:** Shield deposit claim path. Leaf preimage must match `DepositBatchAppendCircuit` / L1 deposit word layout.

---

## 2. `PrivateNoteInclusionCircuit`

-   **File:** `client_prover/psy_circuit/psy_dpn_circuit/src/circuits/privacy/private_note_inclusion.rs` — gadget ~47–181; circuit `PrivateNoteInclusionCircuit` ~237– (file core ~423 excl. tests from ~533)
-   **Purpose:** Prove a private note commitment is in the token note tree bound into global user tree state, revealing owner/amount/nullifier/checkpoint metadata without the spending key.
-   **Public Inputs:** 4 felts =  
    `Poseidon([owner[4], amount, user_tree_root[4], checkpoint_id, slot_index, token_contract_id, nullifier[4]])`
-   **Private Inputs / Witness:** `nullifier_secret`, `note_secret`, note membership siblings/index, slot-value-in-contract-state witnesses.
-   **Constraints (pseudocode):**

    ```text
    value_hash = [amount, 0, 0, 0]
    inner = H2(owner, value_hash)
    note_commitment = Poseidon(nullifier_secret || note_secret)
    commitment = H2(inner, note_commitment)
    Merkle(note_tree): value=commitment → note_root
    SlotValueInContractState binds note_root into user_tree_root
    nullifier = Poseidon(nullifier_secret)
    register Poseidon(PI_preimage)
    ```

-   **Role:** Private note existence / private-transfer claim prep. Heights must match network config and token precompile fingerprints.

---

## 3. `SlotValueInContractStateGadget` (DPN)

-   **File:** `client_prover/psy_circuit/psy_dpn_circuit/src/circuits/privacy/slot_value_in_contract_state.rs` (core lines: ~105)
-   **Purpose:** Prove a contract-state slot value authenticates under a user’s leaf in the global user tree (same structural idea as the bridge gadget).
-   **Role:** Shared primitive for private note inclusion binding into GUSR.

---

## 4. `DapenContractFunctionCircuit` (CFC)

-   **File:** `client_prover/psy_circuit/psy_dpn_circuit/src/circuits/cfc.rs` (core ~137 excl. tests)
-   **Gadgets:** `PsyContractFunctionBuilderGadget` (`vm/compile.rs`) over a `DPNFunctionCircuitDefinition`
-   **Purpose:** Compile one contract method into a Plonky2 CFC circuit (VM / UCON state reads-writes) consumed by UPS standard steps.
-   **Public Inputs:** Poseidon hash over the function’s declared circuit IO (registered from builder outputs).
-   **Private / Witness:** Method inputs; contract-state Merkle witnesses; session proof-tree height parameters.
-   **Constraints (pseudocode):**

    ```text
    fn_builder = PsyContractFunctionBuilder(fn_def, heights, inputs)
    // enforces method body, UCON slot updates, IO hashing inside builder
    PI = hash(fn_builder.public_preimage)
    minifier_chain wraps base circuit (fingerprint from minifier)
    ```

-   **Role:** Per-method CFC proofs verified inside `UPSVerifyCFCProofExistsAndValidGadget`. Not a privacy-nullifier circuit; listed here because it shares the `psy_dpn_circuit` crate with privacy circuits.

## Related

* Uncompiled / non-crate: `privacy/shield_deposit_claim.rs` historical path — **not** the live circuit; use `deposit_inclusion.rs`.
* CFC execution circuit (non-privacy): `circuits/cfc.rs` + `vm/compile.rs` `PsyContractFunctionBuilderGadget`.
