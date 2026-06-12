# PSY VM Integration & Full Contract System Upgrade — Task List

Reference: [PSY_VM_INTEGRATION_SPEC.md](PSY_VM_INTEGRATION_SPEC.md)

---

## Phase 1: VM Executor Foundation (psy_vm)

### Task 1.1: Define VM Executor Core Types
**File:** `psy_vm/src/dpn/eval/executor.rs` (NEW)

- [ ] Define `ExecutionResult`, `ExecutionFailure`, `StateRead`, `StateWrite`, `StateDelta`, `ExecutionEvent`, `OpCounts`
- [ ] Define `ExecutionContext` (user_id, contract_id, caller_contract_id, checkpoint_id, nonce, public_key_hash)
- [ ] Implement `Display` / `Debug` for all types
- [ ] Add serde `Serialize`/`Deserialize` derives for JSON output

### Task 1.2: Define StateBackend Trait
**File:** `psy_vm/src/dpn/eval/state_backend.rs` (NEW)

- [ ] Define `StateBackend` trait with methods: `get_contract_slot`, `get_contract_hash`, `get_contract_range`, `get_contract_leaf`, `get_checkpoint_stats`, `get_user_public_key_hash`, `get_contract_deployer`
- [ ] Define `ContractLeafData` and `CheckpointStatsData` structs

### Task 1.3: Implement InMemoryStateBackend
**File:** `psy_vm/src/dpn/eval/state_backend.rs`

- [ ] `InMemoryStateBackend` using `HashMap<(u64, u64, u64), u64>` keyed by (user_id, contract_id, slot_index)
- [ ] Methods to pre-populate state for testing
- [ ] Methods to set contract metadata and checkpoint data
- [ ] Implement `StateBackend` trait

### Task 1.4: Implement VmExecutor Core
**File:** `psy_vm/src/dpn/eval/executor.rs`

- [ ] `VmExecutor<S: StateBackend>` struct with state backend + write overlay
- [ ] `execute()` method: initialize registers, bind inputs, process definitions, process state commands, check assertions, collect outputs
- [ ] Value arrays: targets (Vec<u64>), bools (Vec<bool>), u32s (Vec<u32>), hashes (Vec<[u64; 4]>)
- [ ] Helper: resolve `u64` encoded operand ID to concrete value from arrays
- [ ] Helper: store result into appropriate array by data type

### Task 1.5: Implement DPN Operation Evaluation
**File:** `psy_vm/src/dpn/eval/executor.rs`

- [ ] Arithmetic: Add, Sub, Mul, Div, Mod (Goldilocks field)
- [ ] U32 Arithmetic: U32Add, U32Sub, U32Mul, U32Div, U32Mod
- [ ] U32 Bitwise: U32And, U32Or, U32Xor, U32ShiftLeft, U32ShiftRight
- [ ] Boolean: BoolAnd, BoolOr, BoolNot, Xor, Nor
- [ ] Comparison: Eq, Lt, Lte, Gt, Gte
- [ ] Constants: Constant, ConstantTrue, ConstantFalse, ConstantU32
- [ ] Context: GetUserId, GetContractId, GetCallerContractId, GetCheckpointId, GetNonce, GetUserPublicKeyHash
- [ ] Hashing: HashNoPad, HashTwoToOne (use Poseidon implementation)
- [ ] Type casts: CastU32, CastFelt, CastBool
- [ ] Select: conditional value selection (cselect)

### Task 1.6: Implement State Command Processing
**File:** `psy_vm/src/dpn/eval/executor.rs`

- [ ] Read commands: GetSelfUserCurrentContractStateSlot{Hash,Single,Range}
- [ ] Read commands: GetSelfUserExternalContractStateSlot{Hash,Single,Range}
- [ ] Read commands: GetOtherUserContractStateSlot{Hash,Single,Range}
- [ ] Write commands: SetContractStateSlot{Hash,Single,Range}, ClearEntireTree
- [ ] External calls: InvokeExternalContractFunctionSync (recursive execution)
- [ ] External calls: InvokeExternalContractFunctionDeferred (record only)
- [ ] Checkpoint/Contract queries: GetCheckpointLeafStats, GetContractLeaf
- [ ] Write overlay: subsequent reads see previously written values
- [ ] Conditional write handling: evaluate condition, skip if false

### Task 1.7: Implement Assertion Checking
**File:** `psy_vm/src/dpn/eval/executor.rs`

- [ ] Process `DPNAssertEqInfoIndexed` list
- [ ] Resolve left/right sides to concrete values
- [ ] On first failure: record `ExecutionFailure` with message, values
- [ ] Continue executing (collect all failures) vs. stop-on-first mode

### Task 1.8: VM Executor Unit Tests
**File:** `psy_vm/tests/vm_executor_test.rs` (NEW)

- [ ] Test arithmetic operations (field arithmetic)
- [ ] Test U32 operations
- [ ] Test boolean operations
- [ ] Test state read/write with InMemoryStateBackend
- [ ] Test conditional writes
- [ ] Test assertion pass/fail
- [ ] Test context field access
- [ ] Test hash operations

### Task 1.9: VM Executor Integration with psy_compiler
**File:** `psy_vm/tests/vm_executor_integration_test.rs` (NEW)

- [ ] Compile simple contract, execute with VM, verify state delta
- [ ] Compile token contract, execute transfer, verify balance change
- [ ] Compile contract with require(), test assertion failure
- [ ] Compile contract with if/else, verify conditional execution
- [ ] Compile contract with ContractStateArray, verify array access
- [ ] Compile contract with cross-user read, verify read results

---

## Phase 2: Multi-File Contract Support (psy_compiler)

### Task 2.1: Add Module-Related Tokens
**File:** `psy_compiler/src/parse/tokens.rs`

- [ ] Add `Mod` token for `mod` keyword
- [ ] Add `Use` token for `use` keyword
- [ ] Add `ColonColon` token for `::` path separator (if not already present)
- [ ] Add `Glob` token for `*` in `use foo::*`

### Task 2.2: Extend AST with Module Nodes
**File:** `psy_compiler/src/parse/ast.rs`

- [ ] Add `Item::ModDecl { name, is_public, span }`
- [ ] Add `Item::UseDecl { path, is_glob, alias, span }`
- [ ] Add `ModulePath` type alias: `Vec<String>`

### Task 2.3: Implement Module Declaration Parsing
**File:** `psy_compiler/src/parse/parser.rs`

- [ ] `parse_mod_decl()`: Parse `[pub] mod name;`
- [ ] `parse_use_decl()`: Parse `use path::to::item;` and `use path::to::*;`
- [ ] Parse `::` path separators in use declarations
- [ ] Integrate into `parse_item()` dispatch

### Task 2.4: Implement Module Resolver
**File:** `psy_compiler/src/modules/resolver.rs` (NEW)

- [ ] `ModuleResolver` struct with root directory
- [ ] `resolve_crate(root_file: &Path) -> Result<ResolvedCrate>`
- [ ] `resolve_mod_decl(parent_dir, mod_name) -> Result<PathBuf>`: try `name.psy.rs`, then `name/mod.psy.rs`
- [ ] Detect circular dependencies (track resolution stack)
- [ ] `ResolvedModule`: path, source, file_path, ast, is_public
- [ ] `ResolvedCrate`: modules list, merged program

### Task 2.5: Implement Name Qualification
**File:** `psy_compiler/src/modules/resolver.rs`

- [ ] Qualify struct names with module path: `types::TokenState`
- [ ] Qualify function names with module path: `helpers::math::max`
- [ ] Qualify const names with module path
- [ ] Handle `use` imports: add unqualified aliases to scope
- [ ] Handle glob imports: `use types::*` imports all pub items
- [ ] Handle `Self::ABI` resolution to crate-root contract

### Task 2.6: Update Resolver for Cross-Module Names
**File:** `psy_compiler/src/types/resolver.rs`

- [ ] Accept qualified names in struct/type lookups
- [ ] Resolve `use` imports during name resolution
- [ ] Validate visibility (private items not accessible from other modules)
- [ ] Error on multiple `#[contract]` structs across modules
- [ ] Error on multiple `#[contract_implementation]` blocks

### Task 2.7: Implement compile_crate() API
**File:** `psy_compiler/src/lib.rs`

- [ ] `pub fn compile_crate(root_file: &Path) -> Result<ContractOutput>`
- [ ] `pub fn compile_crate_from_sources(sources: &[(Vec<String>, String)]) -> Result<ContractOutput>`
- [ ] Use ModuleResolver to load all files, merge AST, then run existing pipeline

### Task 2.8: Multi-File Unit Tests
**File:** `psy_compiler/tests/multifile_test.rs` (NEW)

- [ ] Test module resolution (file discovery)
- [ ] Test `use` import resolution
- [ ] Test glob imports
- [ ] Test visibility enforcement (private items hidden)
- [ ] Test cross-module struct usage
- [ ] Test cross-module helper function inlining
- [ ] Test cross-module const evaluation
- [ ] Test error: multiple #[contract] structs
- [ ] Test error: circular module dependency
- [ ] Test error: module file not found
- [ ] Full compilation of multi-file contract project

---

## Phase 3: Compile & Deploy Pipeline

### Task 3.1: Implement Compile CLI Command
**File:** `psy_cli/psy_user_cli/src/subcommand/compile.rs` (NEW)

- [ ] `CompileArgs` struct: source path, output_dir, abi_only flag, check flag, is_crate flag
- [ ] `run()` function: load source → compile → save artifacts
- [ ] Output: contract_code.bin (bincode), abi.json, circuit_defs.json
- [ ] Support single-file and multi-file (crate) compilation

### Task 3.2: Implement Compile-and-Deploy CLI Command
**File:** `psy_cli/psy_user_cli/src/subcommand/compile_deploy.rs` (NEW)

- [ ] `CompileAndDeployArgs` struct: source, rpc_config, private_key, fingerprint, sign_type, output_dir, dry_run, is_crate
- [ ] `run()` function:
  1. Compile source to ContractOutput
  2. Generate plonky2 circuits via `gen_contract_deploy_and_circuits_for_functions`
  3. Use compiler's `state_tree_height` (not MAX_CONTRACT_STATE_TREE_HEIGHT)
  4. Build QBCDeployContract
  5. If not dry_run: submit to coordinator
  6. Save artifacts (ABI, deploy_cmd, contract_id)

### Task 3.3: Update Existing Deploy Command
**File:** `psy_cli/psy_user_cli/src/subcommand/deploy_contract.rs`

- [ ] Accept `state_tree_height` from compiled contract (instead of hardcoded MAX)
- [ ] Accept ABI alongside contract code for richer deployment metadata
- [ ] Keep backward compatibility with JSON-based DPN function defs

### Task 3.4: Implement Simulate CLI Command
**File:** `psy_cli/psy_user_cli/src/subcommand/simulate.rs` (NEW)

- [ ] `SimulateArgs` struct: contract_id (or source), method, inputs, rpc_config, user_id, abi_path, format
- [ ] `run()` function:
  1. Load contract code (from chain or compile from source)
  2. Build ExecutionContext from RPC (user_id, checkpoint, nonce)
  3. Execute via VmExecutor with RpcStateBackend
  4. Format and display ExecutionResult
- [ ] ABI-aware output: resolve slot indices to field names
- [ ] Multiple output formats: json, table, minimal

### Task 3.5: Implement RpcStateBackend
**File:** `psy_vm/src/dpn/eval/state_backend.rs`

- [ ] `RpcStateBackend` wrapping `RpcProvider`
- [ ] Implement `StateBackend` trait using RPC calls:
  - `get_contract_slot` → `psy_get_user_contract_state_tree_leaf_hash`
  - `get_contract_range` → multiple leaf hash queries
  - `get_contract_leaf` → `psy_get_contract_leaf_data`
  - `get_checkpoint_stats` → `psy_get_checkpoint_leaf_data` (if available)
- [ ] Caching layer to avoid redundant RPC calls during single execution

### Task 3.6: Register CLI Subcommands
**File:** `psy_cli/psy_user_cli/src/subcommand/mod.rs`

- [ ] Add `Compile(CompileArgs)` to Commands enum
- [ ] Add `CompileAndDeploy(CompileAndDeployArgs)` to Commands enum
- [ ] Add `Simulate(SimulateArgs)` to Commands enum
- [ ] Wire up subcommand dispatch in main.rs

### Task 3.7: Deploy Pipeline Tests
**Files:** Various test files

- [ ] Unit test: compile source → verify ContractCodeDefinition structure
- [ ] Unit test: verify state_tree_height matches layout computation
- [ ] Unit test: simulate command with InMemoryStateBackend
- [ ] Integration test: compile → deploy_cmd → verify structure

---

## Phase 4: UPS Integration

### Task 4.1: ABI-Aware Executor
**File:** `psy_vm/src/dpn/eval/abi_executor.rs` (NEW)

- [ ] `AbiExecutor<S: StateBackend>` struct wrapping VmExecutor + ContractABI + circuit defs
- [ ] `call(method_name, params, context)`: resolve method by name, validate params against ABI, convert ParamValue to felt vec, execute
- [ ] `format_state_delta(result)`: map slot indices back to field names using ABI layout
- [ ] `ParamValue` enum: Felt, Bool, U32, Hash, Array, Struct
- [ ] `FormattedStateDelta`: human-readable field changes

### Task 4.2: Pre-Flight Simulation in Prove Flow
**File:** `psy_prover/src/session/session.rs`

- [ ] Before `prove_func()`, run VM executor simulation
- [ ] If simulation fails, return error with assertion details (skip expensive proof gen)
- [ ] Use simulation state reads to pre-fetch merkle witnesses
- [ ] This is an optional optimization path (existing flow still works without it)

### Task 4.3: Compiler Output → UPS Pipeline Bridge
**File:** `psy_prover/src/session/session.rs`

- [ ] New function: `compile_and_prove()` accepting PSY source + method + inputs
- [ ] Compile source → ContractOutput
- [ ] Register circuits → prove_func() path
- [ ] Alternative: accept pre-compiled ContractOutput

### Task 4.4: End-to-End Transaction Helper
**File:** `psy_prover/src/session/session.rs`

- [ ] `execute_transaction()` function covering full lifecycle:
  1. Compile (or load compiled contract)
  2. Simulate (dry run)
  3. Start UPS session
  4. Generate CFC proof
  5. End cap + sign
  6. Submit to coordinator
  7. Return TransactionResult
- [ ] Support both PSY source input and pre-deployed contract_id input

### Task 4.5: UPS Integration Tests
**Files:** Various test files

- [ ] Test: compile → simulate → verify result matches expected
- [ ] Test: compile → deploy → simulate against deployed contract
- [ ] Test: full prove flow with compiled contract (if test coordinator available)
- [ ] Test: multi-transaction session with multiple CFC steps
- [ ] Test: transaction with cross-contract sync call

---

## Phase 5: Testing & Documentation

### Task 5.1: Comprehensive VM Executor Test Suite
**File:** `psy_vm/tests/` (various)

- [ ] Goldilocks field arithmetic edge cases (overflow, inverse, zero)
- [ ] All DPNOpType variants coverage
- [ ] All DPNStateCmd variants coverage
- [ ] Nested external calls (sync)
- [ ] Deferred call recording
- [ ] Large contract state (many slots)
- [ ] Conditional execution (if/else branches)
- [ ] Loop unrolling verification (for-loop expansion)

### Task 5.2: Multi-File Contract Example
**Directory:** `psy_compiler/tests/fixtures/multi_file_token/` (NEW)

- [ ] `lib.psy.rs` — crate root with contract + impl
- [ ] `types.psy.rs` — struct definitions (TokenState, TokenMailbox)
- [ ] `helpers/mod.psy.rs` — helper module root
- [ ] `helpers/transfer.psy.rs` — transfer helper functions
- [ ] `constants.psy.rs` — const definitions (PSY_TOTAL_USERS)
- [ ] Integration test compiling this multi-file project

### Task 5.3: End-to-End Example Script
**File:** `psy_compiler/examples/full_lifecycle.rs` (NEW)

- [ ] Demonstrates: write contract → compile → simulate → show state delta
- [ ] Uses InMemoryStateBackend for self-contained execution
- [ ] Prints formatted results

### Task 5.4: Update Documentation
**File:** `docs/src/language/modules_and_visibility.md`

- [ ] Document full module system: `mod`, `use`, `pub mod`
- [ ] Document file resolution rules
- [ ] Document visibility rules
- [ ] Add examples of multi-file contract structure

### Task 5.5: Update PSY_COMPILER_SPEC.md
**File:** `docs/src/language/PSY_COMPILER_SPEC.md`

- [ ] Add section on multi-file support
- [ ] Add section on compile_crate() API
- [ ] Reference PSY_VM_INTEGRATION_SPEC.md for VM and deploy details

### Task 5.6: Memory File for Future Reference
**File:** `/root/.claude/projects/-home-user-qedlang-rust/memory/MEMORY.md`

- [ ] Document key architectural patterns discovered
- [ ] Document crate structure and dependencies
- [ ] Document common gotchas and important conventions

---

## Summary

| Phase | Tasks | Focus Area |
|-------|-------|------------|
| Phase 1 | 1.1–1.9 | VM Executor (non-circuit execution, state backends, testing) |
| Phase 2 | 2.1–2.8 | Multi-File Contracts (module system, name resolution, compilation) |
| Phase 3 | 3.1–3.7 | Compile & Deploy Pipeline (CLI commands, RPC backend, deploy flow) |
| Phase 4 | 4.1–4.5 | UPS Integration (ABI executor, pre-flight simulation, end-to-end flow) |
| Phase 5 | 5.1–5.6 | Testing & Documentation (comprehensive tests, examples, docs) |

**Total: 35 tasks across 5 phases**

### Dependency Graph

```
Phase 1 (VM Executor)
  ├── Task 1.1-1.3: Types and state backend (no dependencies)
  ├── Task 1.4-1.7: Core executor (depends on 1.1-1.3)
  └── Task 1.8-1.9: Tests (depends on 1.4-1.7 + psy_compiler)

Phase 2 (Multi-File)
  ├── Task 2.1-2.3: Parsing changes (no dependencies)
  ├── Task 2.4-2.6: Module resolution (depends on 2.1-2.3)
  ├── Task 2.7: API (depends on 2.4-2.6)
  └── Task 2.8: Tests (depends on 2.7)

Phase 3 (Deploy Pipeline)
  ├── Task 3.1: Compile CLI (depends on Phase 2)
  ├── Task 3.2: Compile+Deploy CLI (depends on 3.1)
  ├── Task 3.3: Deploy update (no new dependencies)
  ├── Task 3.4: Simulate CLI (depends on Phase 1)
  ├── Task 3.5: RPC backend (depends on Task 1.2)
  └── Task 3.6-3.7: Integration (depends on 3.1-3.5)

Phase 4 (UPS Integration)
  ├── Task 4.1: ABI executor (depends on Phase 1)
  ├── Task 4.2-4.3: Prove flow (depends on Phase 1 + 3)
  ├── Task 4.4: E2E helper (depends on 4.1-4.3)
  └── Task 4.5: Tests (depends on 4.4)

Phase 5 (Testing & Docs)
  └── All tasks depend on Phases 1-4
```

### Priority Order

Phases 1 and 2 can be developed **in parallel** since they are independent:
- Phase 1 (VM Executor) works with existing single-file compiler output
- Phase 2 (Multi-File) extends the compiler without touching the VM

Phase 3 (Deploy Pipeline) requires both Phase 1 (for simulate) and Phase 2 (for multi-file compile).

Phase 4 (UPS Integration) requires Phase 1 and Phase 3.

Phase 5 (Testing & Docs) runs alongside and after all other phases.
