# Bridge Circuits and Gadgets

> Updated: 2026-09-08. Source of truth: local worktree under `psy_plonky2_circuits/src/bridge/` and `psy_plonky2_common_circuits/src/bridge/`.
> Core line counts exclude blank lines, `//` comments, block comments, and `#[cfg(test)]` modules.

## Abstract

This document describes the Plonky2 bridge circuits that the relayer and prove-proxy use for L1 deposit batch append, bridge aggregation (Chain → Final → Wrap), and withdrawal batch claim. Groth16 wrappers produce the proofs verified by `DepositBatchVerifier.sol`, `GnarkGroth16Verifier.sol` / wrap path, and `WithdrawalClaimVerifier.sol`.

## Table of Contents

- [1. DepositBatchAppendCircuit](#1-depositbatchappendcircuit)
- [2. WithdrawalBatchClaimCircuit](#2-withdrawalbatchclaimcircuit)
- [3. BridgeAggChainCircuit](#3-bridgeaggchaincircuit)
- [4. BridgeAggFinalCircuit](#4-bridgeaggfinalcircuit)
- [5. Bridge wrap circuits](#5-bridge-wrap-circuits)
- [6. TreeRootInContractStateGadget](#6-treerootincontractstategadget)
- [7. VerifyBridgeCheckpointStateTransitionProofGadget](#7-verifybridgecheckpointstatetransitionproofgadget)
- [8. Flow](#8-flow)

## 1. `DepositBatchAppendCircuit`

*   **File:** `psy_plonky2_common_circuits/src/bridge/deposit_batch_append_circuit.rs:243-390` (core lines: ~490 file; constraint body ~148)
*   **Purpose:** Append up to 32 deposit leaves into a height-32 frontier Merkle tree and commit the batch for L1 `Bridge.batchAppend`.
*   **Public Inputs:** `keccak256` over a fixed word preimage (old/new root as u32×8 LE, from/to index, 32 leaf hashes, old/new frontiers, `bridge_user_id`, `batch_commit`), exposed as 8×u32 public targets.
*   **Private Inputs / Witness:** `frontier[32]`, `from_index`, per-slot deposit words (`shield_address`, `token`, `l2_token_contract_id`, `amount`, `chain_index`, `note_commitment`), `bridge_user_id`, `actual_batch_len`.
*   **Constraints (pseudocode):**
    ```
    assert actual_batch_len <= 32
    for i in 0..32:
      leaf_hash = Poseidon(deposit_slot_words[i])
      FrontierAppend(index=current, leaf=leaf_hash)
      if i >= actual_batch_len: zero inactive words
      else: advance index / frontier
    batch_commit = keccak(all slot words)
    PI = keccak(old_root || new_root || from || to || leaves || frontiers || bridge_uid || batch_commit)
    ```
*   **Role:** Relayer deposit-append Plonky2 circuit; wrapped by `DepositBatchWrapCircuit` before L1 verification.

---

## 2. `WithdrawalBatchClaimCircuit`

*   **File:** `psy_plonky2_common_circuits/src/bridge/withdrawal_batch_claim_circuit.rs:60-184` (core lines: ~285)
*   **Purpose:** Prove up to 32 withdrawal leaves are included under a withdrawal Merkle root and commit the claim batch for L1 `Bridge.batchClaimWithdrawal`.
*   **Public Inputs:** `withdrawal_root` (u32×8), `real_count`, `bridge_user_id`, `batch_commit` (u32×8).
*   **Private Inputs / Witness:** Per slot: `sender_user_id`, `recipient`, `token`, `amount`, `nonce`, `destination_chain_index`, `leaf_index`, siblings; shared root / bridge user / count.
*   **Constraints (pseudocode):**
    ```
    assert real_count <= 32
    for i in 0..32:
      leaf = Poseidon(sender || recipient || token || amount || nonce || dest_chain)
      MerkleProof(value=leaf, index=leaf_index) → root
      if inactive: zero fields and siblings
    batch_commit = keccak(all slot data words)
    register PI(root, real_count, bridge_user_id, batch_commit)
    ```
*   **Role:** Withdrawal claim Plonky2 circuit; wrapped by `WithdrawalClaimWrapCircuit`.

---

## 3. `BridgeAggChainCircuit`

*   **File:** `psy_plonky2_circuits/src/bridge/circuits/bridge_agg_chain.rs:78-298` (core lines: ~220 for `new`; ~481 file excl. tests)
*   **Purpose:** Cyclic recursive aggregator over append-only checkpoint-tree deltas (0..=32 slots). Builds a Poseidon chain commitment over successive checkpoint roots and leaves.
*   **Public Inputs:** Business prefix length 23, then cyclic verifier-data PIs:
    * `[0..4)` `start_chain_hash`
    * `[4..8)` `end_chain_hash`
    * `[8..12)` `start_checkpoint_tree_root`
    * `[12..16)` `end_checkpoint_tree_root`
    * `[16..20)` `end_checkpoint_leaf_hash`
    * `[20]` `num_checkpoints_aggregated`
    * `[21]` `start_checkpoint_index`
    * `[22]` `end_checkpoint_index`
    * `[23..]` cyclic verifier digest + cap
*   **Private Inputs / Witness:** `active_len`; base boundary fields; up to 32 append-only `DeltaMerkleProof` slots; previous cyclic proof when not base.
*   **Constraints (pseudocode):**
    ```
    assert 0 <= active_len <= 32
    is_base = (active_len == 0)
    start_* / rolling_* = select(!is_base, previous_PIs, base_*)
    for i in 0..32:
      when active: delta.old_root == rolling_root
                   delta.index == rolling_index + 1
      step = H2(H2(delta.new_root, delta.new_value), base_fingerprint)
      rolling_chain = select(active, H2(rolling_chain, step), rolling_chain)
      update rolling root/leaf/index/count if active
    assert (end_index - start_index) == count
    conditionally_verify_cyclic_proof(!is_base)
    ```
*   **Role:** Recursive Chain stage before Final.

---

## 4. `BridgeAggFinalCircuit`

*   **File:** `psy_plonky2_circuits/src/bridge/circuits/bridge_agg_final.rs:74-329` (core lines: ~250 for `new`; ~539 file excl. tests)
*   **Purpose:** Verify one Chain proof, append terminal 1..=32 checkpoint slots, verify the final checkpoint state-transition proof, extract deposit/withdrawal tree roots from bridge contract state for L1.
*   **Public Inputs:** Flat length 26 (not a Poseidon PI hash):
    * `[0..4)` predecessor start checkpoint tree root
    * `[4..12)` deposit tree root (8 limbs)
    * `[12..20)` withdrawal tree root
    * `[20..24)` end checkpoint tree root
    * `[24]` end checkpoint index
    * `[25]` total num checkpoints
*   **Private Inputs / Witness:** Chain proof + VK; `active_len` ∈ [1,32]; terminal deltas; checkpoint ST proof/VK; checkpoint leaf + global state roots; deposit/withdrawal `TreeRootInContractState` witnesses.
*   **Constraints (pseudocode):**
    ```
    verify Chain proof; fingerprint(Chain VK) == known
    bind Chain PI cyclic suffix to Chain VK
    for each active terminal slot: same rolling chain update as Chain
    verify checkpoint ST proof; fingerprint == known
    rolling_chain_hash == checkpoint_proof.public_inputs_hash
    Poseidon(checkpoint_leaf) == rolling_leaf
    extract deposit/withdrawal roots via TreeRootInContractState
    bridge_user_id=524288, deposit_cid=2, withdrawal_cid=3
    register 26 PIs
    ```
*   **Role:** Terminal BridgeAgg Plonky2 circuit consumed by wrap / L1 finalize.

---

## 5. Bridge wrap circuits

*   **File:** `psy_plonky2_circuits/src/bridge/circuits/bridge_wrap.rs` — `BridgeWrapCircuit` ~164-213; `DepositBatchWrapCircuit` ~252-354; `WithdrawalClaimWrapCircuit` ~357-445 (core lines: ~191 excl. helpers/tests)
*   **Purpose:** Plonky2 → gnark Groth16 wrappers. Verify inner proof + fingerprint; bit-pack public inputs for Solidity verifier endianness.
*   **Public Inputs:** Inner circuit PIs with wrap-specific limb/bit packing (Bridge wrap uses `SimpleWrapperDynamic` bit-width policy).
*   **Private Inputs / Witness:** Inner proof + verifier data; gnark keystore for prove.
*   **Constraints (pseudocode):**
    ```
    verify_proof(inner, vk, common)
    fingerprint(vk) == known
    // Deposit/Withdrawal: for each PI pair (a,b): register bits(b,32) then bits(a,32)
    prove_groth16(wrapper_proof)
    ```
*   **Role:** L1 submission wrappers. `bridge_agg.rs` is a re-export shim only (not a proving circuit).

---

## 6. `TreeRootInContractStateGadget`

*   **File:** `psy_plonky2_circuits/src/bridge/gadgets/tree_root_in_contract_state.rs:53-132` (core lines: ~117)
*   **Purpose:** Reconstruct an 8-limb Merkle tree root stored across contract slots 0 and 1 under a user’s GUSR leaf.
*   **Private Inputs / Witness:** Owner user id, contract id, user leaf, slot0/slot1 proofs, contract/user tree proofs.
*   **Constraints (pseudocode):**
    ```
    slot0 and slot1 share contract root and user_tree_root
    slot0.slot_index == 0; slot1.slot_index == 1
    tree_root limbs = slot0.value || slot1.value; range_check 32 bits each
    ```
*   **Role:** BridgeAgg Final deposit/withdrawal root extraction. Built on `SlotValueInContractStateGadget` (`slot_value_in_contract_state.rs:32-136`, core ~118).

---

## 7. `VerifyBridgeCheckpointStateTransitionProofGadget`

*   **File:** `psy_plonky2_circuits/src/bridge/gadgets/verify_checkpoint_state_transition.rs:16-74` (core lines: ~68)
*   **Purpose:** Verify a checkpoint state-transition recursive proof and pin its circuit fingerprint inside BridgeAgg Final.
*   **Constraints (pseudocode):**
    ```
    verify_proof(proof, vk, common)
    fingerprint(vk) == known_checkpoint_fingerprint
    public_inputs_hash = PI[0..4]
    ```
*   **Role:** Final checkpoint authenticity gate for bridge aggregation.

---

## 8. Flow

```text
L1 deposits recorded
  → DepositBatchAppendCircuit (+ DepositBatchWrap) → Bridge.batchAppend
L2 checkpoints progress
  → BridgeAggChainCircuit (cyclic)
  → BridgeAggFinalCircuit (extract deposit/withdrawal roots)
  → BridgeWrapCircuit → StateManager.finalize
L2 withdrawals appended
  → WithdrawalBatchClaimCircuit (+ WithdrawalClaimWrap) → Bridge.batchClaimWithdrawal
```

Leaf hash asymmetry: deposit leaf preimage on L1 uses keccak for the Solidity leaf; Plonky2 deposit batch uses Poseidon over the deposit word layout for the frontier tree. Withdrawal leaf preimage is Poseidon end-to-end. See `docs/src/dev/deposit-withdrawal.md` and `encoding` notes in memory architecture docs.
