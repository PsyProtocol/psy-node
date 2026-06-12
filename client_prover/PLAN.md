# Indexed Merkle Tree (IMT) Implementation Analysis & Plan

## Executive Summary

Both `idx1` and `idx2` implement Indexed Merkle Trees for smart contract state, replacing the flat slot-based state model with a key-value store backed by a sorted linked-list Merkle tree. Neither is production-ready — both have `todo!()` stubs in circuit constraint enforcement. The recommendation is to **combine both**, using `idx1`'s superior circuit gadgets with `idx2`'s more complete system integration.

---

## Comparative Analysis

### Architecture Comparison

| Aspect | idx1 | idx2 |
|--------|------|------|
| Files changed | 30 (+2665 lines) | 128 (+3244 lines) |
| Leaf structure | 13 felts: key(4), value(4), next_key(4), next_index(1) | Same 13 felts |
| Key ordering | MSL-first (elements[3] most significant) | Same MSL-first |
| Sentinel | Index 0, all zeros | Same |
| Hash function | Poseidon hash_n_to_hash_no_pad on 13 elements | Same |
| Tree backing | In-memory SimpleMerkleTree | KVQ-backed tree (UserContractStateTreeId) |
| Compiler type name | `ContractHashMap<K, V>` | `ContractIMTMap<T>` |
| Compiler codegen | Complete (get/insert/update methods) | Partial (type exists, no codegen for methods) |
| IDE integration | Yes (state inspector, WASM bridge) | No |
| Circuit gadgets | **Complete** (update + insert gadgets with full constraints) | **Partial** (leaf hash + comparison + non-membership only) |
| State tracker | Not implemented | **Complete** (PsyIMTLocalStateTracker with net-zero optimization) |
| Proving session | Not integrated | **Partially integrated** (tracker field added) |
| GUTA/end-cap | Minimal (imt_contract_state_updates: Vec::new()) | **Has FFS serialization** + end cap input type |
| SDK TypeScript types | None | **Complete** (auto-generated via ts-rs) |
| VM state commands | 3 commands (IMTInsert, IMTUpdate, IMTGetValue) | 4 commands (Set, GetSelfCurrent, GetSelfExternal, GetOther) |
| Circuit integration | `todo!()` in state_reader_witness, state_readers, vm/exec | `todo!()` in same locations |

### Data Model (Identical)

Both use the exact same leaf preimage structure:
```
IMTContractStateLeaf<F> {
    key:        QHashOut<F>,    // 4 field elements
    value:      QHashOut<F>,    // 4 field elements
    next_key:   QHashOut<F>,    // 4 field elements
    next_index: F,              // 1 field element
}
```
Total: 13 Goldilocks field elements, hashed via Poseidon.

### Insert/Update Algorithms (Nearly Identical)

Both implement the same core algorithm:
- **Insert**: Find predecessor via BTreeMap range query, splice new leaf into linked list, produce 2 chained DeltaMerkleProofCores
- **Update**: Look up by key, change value only, produce 1 DeltaMerkleProofCore
- **Root chaining**: Each operation's new_root feeds into the next operation's old_root

### Key Differences

**1. Tree Storage Backend**
- `idx1`: Uses in-memory `SimpleMerkleTree` — ephemeral, no persistence
- `idx2`: Uses `UserContractStateTreeId` + KVQ store — persistent, production-compatible

**2. VM Command Design**
- `idx1` has 3 commands with separate insert/update semantics. The compiler generates the correct command based on `.insert()` vs `.update()` method calls.
- `idx2` has 4 commands following the existing pattern: one write command (`SetIMT`) + three read commands (self-current, self-external, other-user). The `Set` command is an upsert that returns old+new value.

idx2's command design is better because it matches the existing slot-based command architecture and properly handles cross-contract/cross-user reads.

**3. Circuit Gadgets**
- `idx1` has **complete** gadgets: `IMTUpdateGadget` (5 constraints), `IMTInsertGadget` (10 constraints), `is_qhashout_lte/lt` comparison
- `idx2` has **partial** gadgets: `IMTContractStateLeafGadget` (leaf struct), `imt_key_less_than` comparison, `verify_imt_non_membership` (2 constraints)

idx1's circuit work is significantly more complete and includes the crucial delta Merkle proof verification for both updates and inserts.

**4. Compiler Integration**
- `idx1`: Full codegen for `.get()`, `.insert()`, `.update()` methods, limited to one hashmap per contract
- `idx2`: Type system only — `.get()` and `.set()` codegen not implemented

**5. State Tracker**
- `idx1`: Not implemented at all
- `idx2`: Complete `PsyIMTLocalStateTracker` with net-zero optimization (reverted keys are removed from tracking)

**6. End-Cap / GUTA Pipeline**
- `idx1`: `imt_contract_state_updates: Vec::new()` placeholder
- `idx2`: Has `SubmitUserEndCapIMTNonProofInput` type, FFS serialization format (161 bytes/entry), and `UPSCFCStandardIMTStateDeltaInput`

---

## Bugs & Issues Found

### idx1 Bugs

| ID | Severity | Description |
|----|----------|-------------|
| I1-1 | **HIGH** | `ensure_basic_consistency` accepts ANY IMT old_root when UCT old_value is ZERO — should require sentinel-only tree root |
| I1-2 | **HIGH** | Circuit integration incomplete (todo!() in state_reader_witness, state_readers, vm/exec) |
| I1-3 | **MEDIUM** | `InMemoryStateBackend::imt_insert` silently overwrites duplicates instead of failing |
| I1-4 | **MEDIUM** | `InMemoryStateBackend::imt_update` doesn't check key existence, returns [0;4] for missing keys |
| I1-5 | **MEDIUM** | Non-membership proof uses debug_assert instead of hard check in release builds |
| I1-6 | **LOW** | `_field_name` unused — breaks if multiple hashmaps ever supported |
| I1-7 | **LOW** | Test uses u64::MAX which wraps in Goldilocks field |

### idx2 Bugs

| ID | Severity | Description |
|----|----------|-------------|
| I2-1 | **HIGH** | Circuit integration completely unimplemented (todo!() in all paths) |
| I2-2 | **HIGH** | No circuit insert/update gadgets — only has leaf hash and comparison |
| I2-3 | **MEDIUM** | `ensure_basic_consistency` same ZERO tolerance issue as idx1 |
| I2-4 | **MEDIUM** | Potential u32 underflow in state tracker `total_keys_modified` arithmetic |
| I2-5 | **MEDIUM** | `SetIMTContractStateValue` executor may read stale old_value if effect applied before result |
| I2-6 | **LOW** | Compiler has no codegen for .get()/.set() — type system integration only |

### Shared Concerns

| ID | Severity | Description |
|----|----------|-------------|
| S1 | **INFO** | Insert gadget allows any empty slot (not just append index) — flexible but breaks append-only assumption |
| S2 | **INFO** | 64-bit comparison on Goldilocks field is sound (p < 2^64) but should be documented |
| S3 | **INFO** | Both limit to one IMT map per contract |

---

## Recommendation: Combined Implementation

Use **idx2 as the base** (better system integration) and **port idx1's circuit gadgets and compiler codegen** into it.

### What to take from idx1:
- ✅ `IMTUpdateGadget` with 5 constraints
- ✅ `IMTInsertGadget` with 10 constraints
- ✅ `is_qhashout_lte` / `is_qhashout_lt` comparison functions
- ✅ Compiler codegen for `.get()`, `.insert()`, `.update()` methods
- ✅ IDE state inspector integration
- ✅ WASM bridge for IMT

### What to take from idx2:
- ✅ VM command design (4 commands matching existing architecture)
- ✅ `PsyIMTLocalStateTracker` with net-zero optimization
- ✅ `PsyIMTContractStateTracker` per-contract tracking
- ✅ KVQ-backed tree storage
- ✅ FFS serialization format for GUTA pipeline
- ✅ `SubmitUserEndCapIMTNonProofInput` and `UPSCFCStandardIMTStateDeltaInput`
- ✅ TypeScript SDK types
- ✅ Proving session integration scaffolding

### What to build new:
- 🔧 Wire circuit gadgets into state_reader_witness.rs and state_readers.rs
- 🔧 Wire circuit gadgets into vm/exec.rs proving session path
- 🔧 Fix ensure_basic_consistency ZERO old_value check
- 🔧 Fix state tracker u32 underflow
- 🔧 Fix InMemoryStateBackend duplicate/existence checks
- 🔧 Replace debug_assert with hard checks in proof generation
- 🔧 Add circuit tests for insert/update gadgets
- 🔧 Complete the UPS CFC standard state delta gadget for IMT

---

## Implementation Plan

### Phase 1: Foundation — Merge Data Model & Tree (on main branch base)
1. Add IMT leaf structure (`imt_contract_state.rs` from idx1 / `imt_leaf.rs` from idx2 — they're equivalent)
2. Add IMT proof structures (`imt_proof.rs` — take idx2's version with FFS serialization)
3. Add in-memory IMT model (`models/imt/mod.rs` from idx1 or `models/user/indexed_merkle_tree.rs` from idx2 — idx2 has KVQ backing)
4. Fix: `ensure_basic_consistency` to require sentinel-only tree root when UCT old_value is ZERO
5. Fix: Replace `debug_assert` with `anyhow::ensure` in proof generation

### Phase 2: VM Integration
6. Add IMT state command types (from idx2: Set, GetSelfCurrent, GetSelfExternal, GetOther)
7. Add IMT state command data structures
8. Extend StateBackend trait and InMemoryStateBackend
9. Fix: Add duplicate/existence checks in InMemoryStateBackend
10. Implement executor logic for all 4 commands
11. Fix: Ensure eval_state_cmd_result reads old_value before eval_state_cmd_effect writes

### Phase 3: Circuit Gadgets
12. Port `IMTContractStateLeafGadget` (from idx1 — more complete)
13. Port `is_qhashout_lte` and `is_qhashout_lt` comparison gadgets (from idx1)
14. Port `IMTUpdateGadget` with 5 constraints (from idx1)
15. Port `IMTInsertGadget` with 10 constraints (from idx1)
16. Add `verify_imt_non_membership` gadget (from idx2 — useful standalone)
17. Wire gadgets into `state_reader_witness.rs` — implement witness generation for IMT commands
18. Wire gadgets into `state_readers.rs` — implement circuit constraint enforcement for IMT commands
19. Wire gadgets into `psy_vm/src/vm/exec.rs` — implement proving session VM path
20. Add circuit tests for all gadgets

### Phase 4: State Tracking & Proving Session
21. Add PsyIMTLocalStateTracker (from idx2)
22. Fix: u32 underflow in total_keys_modified
23. Integrate tracker into PsyLocalProvingSessionStore
24. Wire tracker notifications into executor state write path

### Phase 5: Compiler Integration
25. Add ContractIMTMap<T> type to parser (use idx2's name — clearer than ContractHashMap)
26. Add type resolution and layout computation
27. Port codegen for .get(), .set() methods (adapted from idx1's .get/.insert/.update)
28. Map compiler methods to idx2's VM commands (Set = upsert, GetSelfCurrent = read)

### Phase 6: GUTA Pipeline & End Cap
29. Add IMT update history to end_cap_input (from idx2)
30. Implement FFS serialization (from idx2)
31. Add UPSCFCStandardIMTStateDeltaInput (from idx2)
32. Wire into UPS circuit

### Phase 7: SDK & IDE
33. Add TypeScript types (from idx2)
34. Port IDE state inspector integration (from idx1)
35. Port WASM bridge (from idx1)

### Phase 8: Testing & Hardening
36. Unit tests for all data structures
37. Circuit constraint tests (positive and negative)
38. Integration tests for full insert/update/read pipeline
39. Edge case tests: tree full, key=0 rejection, sentinel protection, field boundary keys

---

## Production-Readiness Spec (Remaining Work)

### 1. Compiler: Rename ContractIMTMap → ContractHashMap with Two Generic Params

**Goal**: The user's contract syntax must compile:
```rust
pub hm: ContractHashMap<[Felt; 4], [Felt; 4]>,
// ...
self.hm.insert(h, h);
```

**Changes Required**:

| File | Change |
|------|--------|
| `tokens.rs:55` | Rename `ContractIMTMap` → `ContractHashMap` |
| `ast.rs:136-139` | Add `key_type: Box<Type>` alongside `value_type` |
| `ast.rs:373-375` | Update Display to show both generics |
| `parser.rs:510-518` | Parse `<K, V>` (two comma-separated types) |
| `layout.rs:39-43` | Add `key: Box<ResolvedType>` to `ContractIMTMap` |
| `layout.rs:171-189` | Store both key and value sizes, validate key is 4 felts |
| `layout.rs:259-264` | Resolve both key and value types |
| `context.rs:33` | Update comment |
| `context.rs:230-232` | Update error message |
| `context.rs:533-538` | No change needed (field detection by is_imt_map flag) |
| `context.rs:807-809` | Update error message |
| `context.rs:1110-1121` | No change needed (dispatch by is_imt_map flag) |
| `context.rs:1274-1321` | Fix type coercion (see #2 below) |
| `abi/mod.rs:31-36` | Add `imt_key_type` field |
| `abi/mod.rs:80-85` | Extract both key and value types |
| `resolver.rs:259-264` | Resolve both key and value types |

**Constraints to enforce**:
- Key type must be exactly 4 felts (either `Hash` or `[Felt; 4]`)
- Value type must be exactly 4 felts (either `Hash` or `[Felt; 4]`)
- Only one `ContractHashMap` per contract (existing constraint)

### 2. Compiler: Array-to-Hash Coercion in IMT Methods

**Problem**: `as_hash()` panics when called on `SymValue::Array`. When the user writes `let h = [1,2,3,4]; self.hm.insert(h, h);`, the array literal compiles to `SymValue::Array(vec![Felt, Felt, Felt, Felt])`, not `SymValue::Hash([Felt; 4])`.

**Fix**: Add `as_hash_coerce()` method to `SymValue` that handles both:
- `SymValue::Hash(h)` → returns `h` directly
- `SymValue::Array(vec)` where `vec.len() == 4` and all elements are `Felt` → converts to `[SymFeltRef; 4]`

Replace `as_hash()` calls in `compile_imt_map_method_call()` with `as_hash_coerce()`.

### 3. Compiler: Contract Methods Are Void

**Current state**: Contract methods already cannot return data to the caller in the generated circuit — method outputs are hard-coded as empty `vec![]` in compilation. The `Return` statement in method bodies is a no-op. This is correct behavior.

**Verification needed**: Ensure the type checker warns/errors if a `#[contract_method]` has a return type annotation.

### 4. DPNStateCmdWitness: Add IMT Variants

**File**: `psy_core/psy_data/src/qstore/imm/cmd_processor.rs`

Add to `DPNStateCmdWitness<F>` enum:
```rust
IMTMerkleProof(IMTMerkleProofWitness<F>),
IMTDeltaMerkleProof(IMTDeltaMerkleProofWitness<F>),
```

Where the witness types contain the delta merkle proofs and IMT leaf preimages needed by the circuit gadgets.

### 5. Circuit: state_reader_witness.rs — Witness Generation

For each of the 4 IMT commands, implement witness setting that:
- For `SetIMTContractStateValue`: Extract delta merkle proof(s) from witness, create cache keys, call `set_witness_for_key_dmp()`, increment write epoch
- For `GetSelfUserCurrentIMTContractStateValue`: Extract merkle proof from witness, set witness via cache key
- For `GetSelfUserExternalIMTContractStateValue`: Extract UCT proof + contract state proof, set both witnesses
- For `GetOtherUserIMTContractStateValue`: Extract user leaf proof + UCT proof + contract state proof, set all witnesses

### 6. Circuit: state_readers.rs — Constraint Enforcement

For each of the 4 IMT commands, build circuit constraints:
- **Set (Write)**: Create DeltaMerkleProofGadget, connect old_root to current end_state_root, verify IMT leaf hash, verify insert/update constraints using IMTUpdateGadget/IMTInsertGadget, update end_state_root
- **GetSelfUserCurrent (Read)**: Create MerkleProofGadget, connect root to current contract state root, verify leaf hash, extract value
- **GetSelfUserExternal (Read)**: Two-level proof — first verify contract in UCT, then verify key in that contract's IMT
- **GetOtherUser (Read)**: Three-level proof — user leaf, then UCT, then IMT

### 7. exec.rs: Proving Session Integration

For each of the 4 IMT commands, implement `resolve_vec` that:
- Fetches IMT merkle proofs from the proving session store
- Assembles the appropriate `DPNStateCmdWitness` variant
- Returns `PsyCmdWithInputAndWitness` with the result felts and witness

### 8. IDE: State Inspector Integration

**File**: `psy_ide/frontend/src/components/StateInspector.tsx`
- Add IMT section showing key-value entries (not slot-based)
- Call a new WASM bridge function `readIMTState(contractId, userId)` that returns `{key, value}[]`

**File**: `psy_ide/psy_wasm/src/lib.rs`
- Add `read_imt_state()` function that iterates the in-memory IMT and returns entries
- Wire up to the `InMemoryStateBackend`'s IMT store

### 9. ABI: Add IMT Key Type

**File**: `psy_compiler/src/abi/mod.rs`
- Add `imt_key_type: Option<String>` to `ABIStateField`
- Populate from the resolved key type in `ContractIMTMap`

---

## Execution Task List

1. **Compiler Token Rename**: `ContractIMTMap` → `ContractHashMap` in tokens.rs
2. **Compiler AST**: Add key_type to `Type::ContractHashMap`, update Display
3. **Compiler Parser**: Parse `ContractHashMap<K, V>` with two generic params
4. **Compiler Layout**: Add key to `ResolvedType::ContractIMTMap`, resolve, validate 4-felt keys
5. **Compiler Resolver**: Update `resolve_type` for two-param IMT map
6. **Compiler Codegen**: Add `as_hash_coerce()` to SymValue, replace `as_hash()` in IMT methods
7. **Compiler Error Messages**: Update all `ContractIMTMap` strings to `ContractHashMap`
8. **Compiler ABI**: Add imt_key_type field
9. **DPNStateCmdWitness**: Add IMT witness variants
10. **Circuit state_reader_witness.rs**: Implement 4 IMT command witnesses
11. **Circuit state_readers.rs**: Implement 4 IMT command constraints
12. **exec.rs proving session**: Implement 4 IMT command proving session integration
13. **IDE StateInspector.tsx**: Add IMT state display
14. **IDE psy_wasm**: Add read_imt_state() bridge function
15. **Build & test**: Verify zero errors, all tests pass
