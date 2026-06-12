# PSY VM Integration & Full Contract System Upgrade — Specification

## 1. Overview

This document specifies the upgrade of the PSY smart contract system from a compile-only pipeline to a full end-to-end contract lifecycle platform. The upgrade covers four major areas:

1. **VM Executor (non-circuit)**: An interpreter that executes `DPNFunctionCircuitDefinition` circuits against real or simulated state, producing concrete state deltas, transaction results, and execution traces — without generating ZK proofs.
2. **Compile & Deploy Pipeline**: An integrated workflow that compiles `.psy.rs` source files via the `psy_compiler`, generates `ContractCodeDefinition`, and deploys to the coordinator API.
3. **Multi-File Contract Support**: A Rust-like module system (`mod`, `use`, `pub mod`) enabling contracts to be split across multiple files.
4. **UPS Integration & End-to-End Transaction Flow**: Full integration of the contract system into the UPS (User Proving Session) pipeline, from transaction submission through proof generation and checkpoint finalization.

### 1.1 Design Principles

1. **Real backend integration**: The VM executor fetches live state from the PSY chain via `RpcProvider` / `QTreeDataStoreReaderSync`, not just mock data.
2. **Faithful execution model**: The non-circuit VM must produce identical state deltas to what the circuit would constrain — same state reads, same state writes, same assertions.
3. **Incremental adoption**: Each component can be developed and tested independently before full integration.
4. **Backward compatibility**: Existing single-file contracts, existing `DPNFunctionCircuitDefinition` formats, and existing coordinator APIs remain unchanged.

### 1.2 Architecture Overview

```
                                    ┌──────────────────────────────┐
                                    │   Multi-File Source          │
                                    │   (.psy.rs files with        │
                                    │    mod/use declarations)     │
                                    └─────────────┬────────────────┘
                                                  │
                                                  ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        PSY COMPILER (psy_compiler)                       │
│                                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐  ┌──────────┐ │
│  │ Module    │→ │ Parse    │→ │ Resolve  │→ │ Type Check│→ │ Lower    │ │
│  │ Resolver  │  │ (AST)   │  │ & Layout │  │           │  │ (DPN IR) │ │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘  └──────────┘ │
│                                                                │         │
│                                                                ▼         │
│                                                       ┌──────────────┐  │
│                                                       │ Serialize    │  │
│                                                       │ (CBOR + ABI) │  │
│                                                       └──────┬───────┘  │
└──────────────────────────────────────────────────────────────┼──────────┘
                                                               │
                              ┌─────────────────┬──────────────┼──────────────┐
                              ▼                 ▼              ▼              │
                    ┌──────────────┐   ┌──────────────┐  ┌───────────┐       │
                    │ VM Executor  │   │ Deploy to    │  │ Circuit   │       │
                    │ (non-circuit │   │ Coordinator  │  │ Compiler  │       │
                    │  simulation) │   │ API          │  │ (plonky2) │       │
                    └──────┬───────┘   └──────┬───────┘  └─────┬─────┘       │
                           │                  │                │              │
                           ▼                  ▼                ▼              │
                    ┌──────────────┐   ┌──────────────┐  ┌───────────┐       │
                    │ State Delta  │   │ Contract on  │  │ UPS Proof │       │
                    │ Report       │   │ Chain        │  │ Pipeline  │       │
                    │ (success/    │   │ (GCON tree)  │  │           │       │
                    │  fail, reads,│   └──────────────┘  └───────────┘       │
                    │  writes,     │                                          │
                    │  events)     │                                          │
                    └──────────────┘                                          │
```

---

## 2. VM Executor (Non-Circuit Execution)

### 2.1 Purpose

The VM Executor interprets a compiled `DPNFunctionCircuitDefinition` against concrete state, producing:

- **Transaction result**: Success or failure (which assertion failed, if any).
- **State delta**: All state slots read and written, with old and new values.
- **Events emitted**: All events produced during execution.
- **Execution trace**: Ordered list of operations for debugging.
- **Gas/cost estimate**: Operation counts by type (useful for fee estimation).

This is distinct from the existing `SimpleDPNExecutor` (which evaluates `SymFeltRef` chains) in that the new executor:
- Works from the serialized `DPNFunctionCircuitDefinition` (post-compilation output).
- Integrates with the real PSY backend via `RpcProvider` for state reads.
- Produces structured `ExecutionResult` output suitable for tooling.
- Supports both local (in-memory HashMap) and remote (RPC) state backends.

### 2.2 Core Types

```rust
/// Result of executing a contract function
pub struct ExecutionResult {
    /// Whether the transaction succeeded (all assertions passed)
    pub success: bool,

    /// If failed, the assertion message and index
    pub failure: Option<ExecutionFailure>,

    /// All state reads performed during execution
    pub state_reads: Vec<StateRead>,

    /// All state writes performed during execution
    pub state_writes: Vec<StateWrite>,

    /// Net state delta (merged reads + writes per slot)
    pub state_delta: Vec<StateDelta>,

    /// Events emitted during execution
    pub events: Vec<ExecutionEvent>,

    /// Operation count by category (for gas estimation)
    pub op_counts: OpCounts,

    /// Concrete output values (for functions with return values)
    pub outputs: Vec<u64>,
}

pub struct ExecutionFailure {
    pub assertion_index: usize,
    pub message: String,
    /// The concrete values of left and right sides of the failed assertion
    pub left_value: u64,
    pub right_value: u64,
}

pub struct StateRead {
    pub command_index: usize,
    pub command_type: DPNStateCommandType,
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub value: Vec<u64>,  // 1 felt for Single, 4 for Hash, N for Range
}

pub struct StateWrite {
    pub command_index: usize,
    pub command_type: DPNStateCommandType,
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub old_value: Vec<u64>,
    pub new_value: Vec<u64>,
    pub condition: bool,  // Whether the conditional write was active
}

pub struct StateDelta {
    pub user_id: u64,
    pub contract_id: u64,
    pub slot_index: u64,
    pub old_value: Vec<u64>,
    pub new_value: Vec<u64>,
}

pub struct ExecutionEvent {
    pub checkpoint_id: u64,
    pub user_id: u64,
    pub contract_id: u64,
    pub data: Vec<u64>,
}

pub struct OpCounts {
    pub total_operations: usize,
    pub arithmetic_ops: usize,
    pub boolean_ops: usize,
    pub comparison_ops: usize,
    pub hash_ops: usize,
    pub state_read_ops: usize,
    pub state_write_ops: usize,
    pub external_call_ops: usize,
}
```

### 2.3 State Backend Trait

The VM executor is generic over its state backend:

```rust
/// Trait for providing contract state to the VM executor
pub trait StateBackend {
    /// Read a single felt from a user's contract state
    fn get_contract_slot(
        &self,
        user_id: u64,
        contract_id: u64,
        slot_index: u64,
    ) -> Result<u64>;

    /// Read a hash (4 felts) from a user's contract state
    fn get_contract_hash(
        &self,
        user_id: u64,
        contract_id: u64,
        slot_index: u64,
    ) -> Result<[u64; 4]>;

    /// Read a range of felts from a user's contract state
    fn get_contract_range(
        &self,
        user_id: u64,
        contract_id: u64,
        slot_index: u64,
        length: usize,
    ) -> Result<Vec<u64>>;

    /// Get contract leaf metadata
    fn get_contract_leaf(
        &self,
        contract_id: u64,
    ) -> Result<ContractLeafData>;

    /// Get checkpoint leaf stats
    fn get_checkpoint_stats(
        &self,
        checkpoint_id: u64,
    ) -> Result<CheckpointStatsData>;

    /// Get user's public key hash
    fn get_user_public_key_hash(
        &self,
        user_id: u64,
    ) -> Result<[u64; 4]>;

    /// Get contract deployer
    fn get_contract_deployer(
        &self,
        contract_id: u64,
    ) -> Result<[u64; 4]>;
}
```

Two implementations:

1. **`InMemoryStateBackend`**: Uses `HashMap<(u64, u64, u64), u64>` keyed by `(user_id, contract_id, slot_index)`. Suitable for unit tests, local simulation, and dry-run execution.

2. **`RpcStateBackend`**: Wraps `RpcProvider` and issues `psy_get_user_contract_state_tree_leaf_hash` / `psy_get_user_contract_state_tree_merkle_proof` RPC calls. Suitable for mainnet/testnet execution against real chain state.

### 2.4 Executor Implementation

The executor processes a `DPNFunctionCircuitDefinition` step by step:

```rust
pub struct VmExecutor<S: StateBackend> {
    state: S,
    /// Tracks writes so subsequent reads see updated values
    write_overlay: HashMap<(u64, u64, u64), u64>,
}

impl<S: StateBackend> VmExecutor<S> {
    pub fn new(state: S) -> Self;

    /// Execute a contract function with the given context and inputs
    pub fn execute(
        &mut self,
        circuit: &DPNFunctionCircuitDefinition,
        context: &ExecutionContext,
        inputs: &[u64],
    ) -> Result<ExecutionResult>;
}

pub struct ExecutionContext {
    pub user_id: u64,
    pub contract_id: u64,
    pub caller_contract_id: u64,
    pub checkpoint_id: u64,
    pub nonce: u64,
    pub user_public_key_hash: [u64; 4],
}
```

**Execution algorithm:**

1. **Initialize registers**: Create value arrays for `targets`, `bools`, `u32s`, `hashes` based on circuit definition counters.
2. **Bind inputs**: Map `circuit_inputs` to the provided input values.
3. **Process definitions**: For each `DPNIndexedVarDef` in topological order:
   - Resolve input operands from the value arrays.
   - Execute the operation (matching on `DPNOpType`).
   - Store the result in the appropriate value array.
4. **Process state commands**: For each `DPNStateCmd`, ordered by `state_command_resolution_indices`:
   - Resolve operand values.
   - For reads: fetch from state backend (checking write overlay first), store result.
   - For writes: record old value, compute new value, store in write overlay.
   - For external calls: recursively execute the target contract's circuit.
5. **Check assertions**: For each `DPNAssertEqInfoIndexed`:
   - Resolve both sides.
   - If not equal, record failure.
6. **Collect outputs**: Resolve `circuit_outputs` to concrete values.
7. **Build `ExecutionResult`**.

### 2.5 External Call Handling

For `InvokeExternalContractFunctionSync`:
- Load the target contract's `ContractCodeDefinition` from the state backend.
- Find the function matching `method_id`.
- Deserialize its `DPNFunctionCircuitDefinition` from CBOR.
- Recursively execute with the resolved input arguments.
- Map outputs back to the caller's value arrays.

For `InvokeExternalContractFunctionDeferred`:
- Record the deferred call in the execution result.
- No immediate execution (deferred calls execute in separate UPS steps).

### 2.6 Conditional Execution

State writes in `DPNStateCmd` carry a condition field. The executor evaluates the condition:
- If true (or unconditional), apply the write.
- If false, skip the write but still record it in the trace with `condition: false`.

This matches circuit behavior where both branches execute but writes are conditionally selected.

### 2.7 ABI-Aware Execution Interface

A higher-level interface uses the `ContractABI` to provide named parameter binding:

```rust
pub struct AbiExecutor<S: StateBackend> {
    executor: VmExecutor<S>,
    abi: ContractABI,
    circuit_defs: Vec<DPNFunctionCircuitDefinition>,
}

impl<S: StateBackend> AbiExecutor<S> {
    /// Call a contract method by name with named parameters
    pub fn call(
        &mut self,
        method_name: &str,
        params: &[(&str, ParamValue)],
        context: &ExecutionContext,
    ) -> Result<ExecutionResult>;

    /// Format state delta using ABI field names
    pub fn format_state_delta(
        &self,
        result: &ExecutionResult,
    ) -> FormattedStateDelta;
}

pub enum ParamValue {
    Felt(u64),
    Bool(bool),
    U32(u32),
    Hash([u64; 4]),
    Array(Vec<ParamValue>),
    Struct(Vec<(String, ParamValue)>),
}

pub struct FormattedStateDelta {
    pub contract_name: String,
    pub field_changes: Vec<FormattedFieldChange>,
}

pub struct FormattedFieldChange {
    pub field_path: String,  // e.g., "token_state.balance" or "other_users[42].total_sent"
    pub old_value: String,
    pub new_value: String,
}
```

---

## 3. Multi-File Contract Support

### 3.1 Module System Design

The PSY module system follows Rust conventions:

```
my_contract/
├── lib.psy.rs          # Crate root
├── types.psy.rs        # Struct definitions
├── helpers/
│   ├── mod.psy.rs      # Module root
│   └── math.psy.rs     # Math utilities
└── abi.psy.rs          # ABI imports for cross-contract reads
```

#### 3.1.1 Module Declarations

In `lib.psy.rs` (crate root):
```rust
pub mod types;           // loads types.psy.rs
pub mod helpers;         // loads helpers/mod.psy.rs
mod abi;                 // loads abi.psy.rs (private)

use types::*;            // imports all pub items from types
use helpers::math::max;  // imports specific function

#[contract]
pub struct MyContract { ... }

#[contract_implementation]
impl MyContract { ... }
```

In `types.psy.rs`:
```rust
#[derive(FeltSized)]
pub struct TokenState {
    pub balance: Felt,
}

pub const MAX_SUPPLY: usize = 1000000;
```

In `helpers/mod.psy.rs`:
```rust
pub mod math;            // loads helpers/math.psy.rs
```

In `helpers/math.psy.rs`:
```rust
pub fn max(a: Felt, b: Felt) -> Felt {
    if a > b { a } else { b }
}
```

#### 3.1.2 Module Resolution Rules

1. `mod foo;` in file `dir/bar.psy.rs` resolves to:
   - First try: `dir/foo.psy.rs`
   - Then try: `dir/foo/mod.psy.rs`
   - Error if neither exists.

2. `pub mod foo;` makes `foo` accessible to parent modules.
3. Items without `pub` are private to their defining module.
4. `use path::to::item;` brings an item into scope.
5. `use path::to::*;` brings all `pub` items into scope (glob import).
6. `Self::ABI` always refers to the contract in the crate root.

#### 3.1.3 Visibility Rules

| Declaration | Visibility |
|-------------|-----------|
| `pub fn foo()` | Visible to all modules |
| `fn foo()` | Visible only within defining module |
| `pub struct Foo` | Type visible to all; fields follow their own `pub` |
| `pub mod foo` | Module contents accessible from parent |
| `mod foo` | Module contents only from current module |

#### 3.1.4 Constraints

- Only ONE `#[contract]` struct per crate (in the root or any module, but exactly one).
- Only ONE `#[contract_implementation]` block per crate.
- `#[contract_method]` functions can call helpers from any visible module.
- Circular module dependencies are forbidden.
- `const` values are evaluated at compile time across module boundaries.
- Generic functions are monomorphized per call site, even across modules.

### 3.2 Module Resolution Implementation

#### 3.2.1 ModuleResolver

```rust
pub struct ModuleResolver {
    /// Root directory of the contract crate
    root_dir: PathBuf,
}

pub struct ResolvedModule {
    pub path: ModulePath,       // e.g., ["helpers", "math"]
    pub source: String,         // File contents
    pub file_path: PathBuf,     // Absolute file path
    pub ast: Program,           // Parsed AST
    pub is_public: bool,
}

pub struct ResolvedCrate {
    pub modules: Vec<ResolvedModule>,
    pub merged_program: Program,  // All items merged with qualified names
}

impl ModuleResolver {
    /// Resolve all modules starting from the crate root
    pub fn resolve_crate(root_file: &Path) -> Result<ResolvedCrate>;

    /// Resolve a single module declaration
    fn resolve_mod_decl(
        &self,
        parent_dir: &Path,
        mod_name: &str,
    ) -> Result<PathBuf>;
}
```

#### 3.2.2 Name Qualification

After module resolution, all items get qualified names:

```
types::TokenState         → struct with qualified name
helpers::math::max        → function with qualified name
abi::OtherContract::ABI   → external ABI reference
```

The existing `Resolver` and `TypeChecker` operate on the merged `Program` with qualified names, unaware of the file structure.

### 3.3 AST Extensions

New AST nodes for the module system:

```rust
pub enum Item {
    // ... existing variants ...
    ModDecl {
        name: String,
        is_public: bool,
        span: Span,
    },
    UseDecl {
        path: Vec<String>,     // e.g., ["helpers", "math", "max"]
        is_glob: bool,         // true for `use foo::*`
        alias: Option<String>, // for `use foo as bar`
        span: Span,
    },
}
```

### 3.4 Compiler API Extension

The `compile()` function gains a multi-file entry point:

```rust
/// Compile a single-file contract (existing API, unchanged)
pub fn compile(source: &str) -> Result<ContractOutput>;

/// Compile a multi-file contract crate from a root file
pub fn compile_crate(root_file: &Path) -> Result<ContractOutput>;

/// Compile a multi-file contract crate from pre-loaded sources
pub fn compile_crate_from_sources(
    sources: &[(ModulePath, String)],
) -> Result<ContractOutput>;
```

---

## 4. Compile & Deploy Pipeline

### 4.1 Integrated Compilation + Deployment

The compile-and-deploy pipeline chains: source → compile → deploy in a single command.

```rust
pub struct CompileAndDeployConfig {
    /// Path to the contract source (single file or crate root)
    pub source_path: PathBuf,

    /// Whether this is a multi-file crate or single file
    pub is_crate: bool,

    /// RPC config for coordinator connection
    pub rpc_config_path: PathBuf,

    /// Deployer's private key
    pub private_key: String,

    /// ZK fingerprint (optional, auto-generated if absent)
    pub fingerprint: Option<String>,

    /// Signature type
    pub sign_type: SignType,

    /// Whether to actually deploy (vs. dry-run compile only)
    pub deploy: bool,

    /// Output path for compiled artifacts
    pub output_dir: Option<PathBuf>,
}

pub struct CompileAndDeployResult {
    /// Compilation output
    pub contract_output: ContractOutput,

    /// Generated circuits (for proof generation)
    pub circuits: Vec<DapenContractFunctionCircuit>,

    /// Deploy command (serializable)
    pub deploy_cmd: QBCDeployContract,

    /// If deployed: the contract ID on chain
    pub contract_id: Option<u64>,

    /// ABI JSON (for client use)
    pub abi_json: String,
}
```

### 4.2 Deployment Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Load source files (single or multi-file crate)              │
│  2. Run psy_compiler::compile() or compile_crate()              │
│     → ContractOutput { contract_code, circuit_defs, abi }       │
│  3. For each circuit_def:                                       │
│     → DapenContractFunctionCircuit::new(def, height, ...)       │
│     → Collect fingerprints and code hashes                      │
│  4. Build QBCDeployContract:                                    │
│     → deployer: public key hash                                 │
│     → code_definition: ContractCodeDefinition                   │
│     → function_whitelist: circuit fingerprints                  │
│     → code_root: merkle root of code hashes                    │
│  5. Submit via RpcProvider::deploy_contract()                   │
│     → Returns contract_id                                       │
│  6. Save artifacts:                                             │
│     → ABI JSON to <output_dir>/abi.json                        │
│     → Deploy CMD to <output_dir>/deploy_cmd.json               │
│     → Contract ID to <output_dir>/contract_id.txt              │
└─────────────────────────────────────────────────────────────────┘
```

### 4.3 Contract Code Definition (Existing, Unchanged)

The deployment uses the existing `ContractCodeDefinition` format:

```rust
pub struct ContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<ContractFunctionCodeDefinition>,
}

pub struct ContractFunctionCodeDefinition {
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,    // VM_TYPE_STANDARD_DAPEN_V1
    pub code: Vec<u8>,   // CBOR-serialized DPNFunctionCircuitDefinition
}
```

The compiler's `ContractOutput` already produces this. The deploy pipeline just needs to:
1. Generate plonky2 circuits from the `DPNFunctionCircuitDefinition`s.
2. Compute function whitelist fingerprints.
3. Compute code root hash.
4. Package into `QBCDeployContract` and submit.

### 4.4 State Tree Height

The `state_tree_height` from the compiler's `ContractStateLayout` is used directly in the `ContractCodeDefinition`. This is different from the current deploy_contract CLI which hardcodes `MAX_CONTRACT_STATE_TREE_HEIGHT`. The compiler computes the precise height needed:

```
state_tree_height = ceil(log2(total_virtual_felts))
```

Where `total_virtual_felts = inline_felt_size + sum(array_count * element_felt_size)`.

---

## 5. UPS Integration & End-to-End Transaction Flow

### 5.1 Transaction Lifecycle

```
┌──────────────┐     ┌──────────────┐     ┌───────────────┐
│ User creates │────▶│ VM Executor   │────▶│ If success:   │
│ transaction  │     │ dry-run       │     │ proceed to    │
│ (method +    │     │ (simulation)  │     │ proof gen     │
│  inputs)     │     └──────────────┘     └───────┬───────┘
└──────────────┘                                   │
                                                   ▼
┌──────────────────────────────────────────────────────────────┐
│                 UPS Proof Pipeline                             │
│                                                                │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌─────────┐  ┌───────┐ │
│  │ Start  │→ │ CFC    │→ │ CFC    │→ │ ...     │→ │ End   │ │
│  │ Session│  │ Step 1 │  │ Step 2 │  │         │  │ Cap   │ │
│  └────────┘  └────────┘  └────────┘  └─────────┘  └───────┘ │
│                                                                │
│  Each CFC Step:                                                │
│  1. Load contract code (ContractCodeDefinition)                │
│  2. Build DapenContractFunctionCircuit                         │
│  3. Generate witness (state reads/writes via StateReader)      │
│  4. Generate CFC proof                                         │
│  5. Produce state delta (DeltaMerkleProofCore)                │
└──────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
                          ┌──────────────────┐
                          │ Submit End Cap   │
                          │ (signature +     │
                          │  all proofs)     │
                          │ to Coordinator   │
                          └──────────────────┘
```

### 5.2 Integration Points

#### 5.2.1 Compilation Output → UPS Input

The compiler's `ContractOutput` feeds into the UPS pipeline:

1. `ContractCodeDefinition` → stored on-chain via deploy, loaded by `StateReader` at proof time.
2. `DPNFunctionCircuitDefinition` → deserialized from on-chain code, used by `DapenContractFunctionCircuit` to build plonky2 circuit.
3. `ContractABI` → used by the VM executor and client tooling for named access.

#### 5.2.2 VM Execution → Witness Generation

Before generating ZK proofs, the system must:

1. **Simulate execution** using the VM Executor to determine:
   - All state slots that will be read (need merkle proofs).
   - All state slots that will be written (need delta merkle proofs).
   - Whether assertions pass (fail fast before proof generation).

2. **Fetch witnesses** using `StateReader`:
   - For each state read: merkle proof from state tree.
   - For each state write: current value + merkle proof.
   - Cross-user reads: user tree proof + contract tree proof + state proof.

3. **Build `DapenContractFunctionCircuitInput`**:
   ```rust
   DapenContractFunctionCircuitInput {
       inputs: Vec<F>,
       outputs: Vec<F>,
       events: Vec<PsyUserEventRecord<F>>,
       cmd_witnesses: Vec<PsyCmdWithInputAndWitness<F>>,
       session_proof_tree_root: QHashOut<F>,
       tx_input_ctx: DapenCFCUserTransactionInputContext<F>,
   }
   ```

#### 5.2.3 Proving Session Flow

Using `UserProvingSessionManager` from `psy_ups_circuit`:

```rust
/// Full transaction flow: compile, simulate, prove, submit
pub async fn execute_transaction(
    source: &str,                    // or crate root path
    method_name: &str,
    inputs: Vec<u64>,
    wallet: &PsyMemoryWallet,
    rpc_provider: &RpcProvider,
    circuit_mgr: &impl UPSCircuitManager,
) -> Result<TransactionResult> {
    // 1. Compile contract
    let output = psy_compiler::compile(source)?;

    // 2. Simulate execution (dry run)
    let rpc_backend = RpcStateBackend::new(rpc_provider);
    let mut executor = VmExecutor::new(rpc_backend);
    let sim_result = executor.execute(
        &find_circuit(&output, method_name)?,
        &build_context(wallet, rpc_provider).await?,
        &inputs_to_felts(&inputs),
    )?;

    if !sim_result.success {
        return Ok(TransactionResult::SimulationFailed(sim_result));
    }

    // 3. Generate proofs via UPS pipeline
    let contract_code = output.contract_code;
    let contract_id = get_deployed_contract_id(rpc_provider, &contract_code).await?;

    // ... UPS session management, CFC proof generation, end cap submission ...

    Ok(TransactionResult::Success { ... })
}
```

### 5.3 ContractCallArgs Integration

The existing `ContractCallArgs` structure is used for transaction submission:

```rust
pub struct ContractCallArgs {
    pub contract_id: u64,
    pub method_name: String,
    pub inputs: Vec<u64>,
}
```

The PSY compiler's ABI maps method names to `method_id`s and validates input parameter counts/types.

### 5.4 Session Management

The `UserProvingSessionManager` orchestrates the full UPS flow:

1. **Start Session**: Initialize with checkpoint state, user leaf, state roots.
2. **CFC Steps**: For each contract call in the session:
   - Load contract code.
   - Register circuits with `UPSCircuitManager`.
   - Execute via `prove_func()`.
   - Collect state delta proofs.
3. **End Cap**: Finalize session with signature proof, submit to coordinator.

The new contract system integrates by:
- Using `psy_compiler` output as the `ContractCodeDefinition` source.
- Using the VM executor for pre-flight simulation.
- Using the standard `prove_func()` path for actual proof generation.

---

## 6. CLI Integration

### 6.1 New CLI Commands

The `psy_user_cli` gains new subcommands:

#### 6.1.1 `compile`

```
psy_user_cli compile [OPTIONS] <source>

Arguments:
  <source>              Path to .psy.rs file or crate root directory

Options:
  --output-dir <DIR>    Directory for compiled artifacts
  --abi-only            Only generate ABI JSON
  --check               Type-check only (no code generation)
```

Outputs:
- `<output_dir>/contract_code.bin` — Serialized `ContractCodeDefinition`
- `<output_dir>/abi.json` — Contract ABI
- `<output_dir>/circuit_defs.json` — `DPNFunctionCircuitDefinition` array

#### 6.1.2 `compile-and-deploy`

```
psy_user_cli compile-and-deploy [OPTIONS] <source>

Arguments:
  <source>              Path to .psy.rs file or crate root directory

Options:
  --rpc-config <PATH>   Network configuration file
  --private-key <KEY>   Deployer private key
  --fingerprint <FP>    ZK fingerprint (optional)
  --output-dir <DIR>    Directory for artifacts
  --dry-run             Compile only, don't deploy
```

#### 6.1.3 `simulate`

```
psy_user_cli simulate [OPTIONS] <contract-id> <method> [inputs...]

Options:
  --rpc-config <PATH>   Network configuration
  --user-id <ID>        Executing user ID
  --abi <PATH>          ABI JSON file
  --format <FMT>        Output format (json, table, minimal)
  --source <PATH>       Use source file instead of deployed contract
```

Outputs (JSON):
```json
{
  "success": true,
  "state_delta": [
    {
      "field": "token_state.balance",
      "old_value": "1000",
      "new_value": "900"
    },
    {
      "field": "other_users[42].total_sent",
      "old_value": "0",
      "new_value": "100"
    }
  ],
  "events": [],
  "op_counts": {
    "total": 47,
    "arithmetic": 12,
    "state_reads": 3,
    "state_writes": 2
  }
}
```

#### 6.1.4 `call` (enhanced)

The existing `call` command is enhanced to:
1. Accept ABI path for named parameter binding.
2. Run simulation before proof generation.
3. Display state delta before confirming submission.

---

## 7. Error Handling

### 7.1 Compilation Errors (Multi-File)

| Error | Description |
|-------|-------------|
| `ModuleNotFound` | `mod foo;` but no `foo.psy.rs` or `foo/mod.psy.rs` |
| `DuplicateModule` | Same module declared twice |
| `CircularDependency` | Module A imports from B which imports from A |
| `MultipleContracts` | More than one `#[contract]` struct in crate |
| `MultipleImplBlocks` | More than one `#[contract_implementation]` in crate |
| `UnresolvedImport` | `use foo::bar` but `bar` not found in module `foo` |
| `VisibilityError` | Accessing private item from another module |

### 7.2 VM Execution Errors

| Error | Description |
|-------|-------------|
| `AssertionFailed` | `require()` condition was false |
| `StateReadFailed` | Could not fetch state from backend |
| `InvalidMethodId` | Method ID not found in contract |
| `InvalidInputCount` | Wrong number of input parameters |
| `ArithmeticOverflow` | U32 operation overflow |
| `DivisionByZero` | Division or modulo by zero |
| `ExternalCallFailed` | Sync external call failed |
| `InvalidCircuit` | Malformed `DPNFunctionCircuitDefinition` |

### 7.3 Deploy Errors

| Error | Description |
|-------|-------------|
| `CompilationFailed` | Source code has errors |
| `CircuitGenerationFailed` | plonky2 circuit build failed |
| `RpcConnectionFailed` | Cannot reach coordinator |
| `DeployRejected` | Coordinator rejected deployment |
| `InsufficientFunds` | Not enough balance for deployment |

---

## 8. Testing Strategy

### 8.1 VM Executor Tests

1. **Unit tests**: Execute individual operations (arithmetic, comparison, boolean, hashing) against known values.
2. **State command tests**: Test each `DPNStateCmd` variant with mock state.
3. **Full contract tests**: Compile example contracts and execute all methods.
4. **Assertion failure tests**: Verify proper error reporting on `require()` failures.
5. **External call tests**: Test sync call execution with nested contract calls.
6. **State delta verification**: Compare VM-computed deltas against expected values.

### 8.2 Multi-File Tests

1. **Module resolution**: Test file discovery across directory structures.
2. **Name resolution**: Test qualified name generation and import resolution.
3. **Visibility**: Test that private items are properly hidden.
4. **Cross-module helpers**: Test helper function inlining across modules.
5. **Compilation**: Full compile of multi-file contract projects.

### 8.3 Deploy Pipeline Tests

1. **Unit test**: Mock RPC, verify deploy command structure.
2. **Integration test**: Deploy to local test coordinator.
3. **Round-trip test**: Deploy → fetch code → verify matches.

### 8.4 End-to-End Tests

1. **Full lifecycle**: Write contract → compile → deploy → simulate → prove → submit → verify state.
2. **Multi-transaction session**: Multiple CFC steps in one UPS session.
3. **Cross-contract calls**: Sync call between two deployed contracts.
4. **Deferred execution**: Deferred call setup and resolution.

---

## 9. Crate Structure Changes

### 9.1 New Module in `psy_compiler`

```
psy_compiler/
├── src/
│   ├── lib.rs              # Updated: compile() + compile_crate() + compile_crate_from_sources()
│   ├── modules/            # NEW: Multi-file module system
│   │   ├── mod.rs
│   │   └── resolver.rs     # ModuleResolver, file resolution
│   ├── parse/              # UPDATED: mod/use parsing
│   │   ├── ast.rs          # +ModDecl, +UseDecl items
│   │   ├── parser.rs       # +parse_mod_decl, +parse_use_decl
│   │   └── tokens.rs       # +Mod, +Use tokens
│   ├── types/              # UPDATED: cross-module resolution
│   │   └── resolver.rs     # Handle qualified names
│   ├── lower/              # Unchanged
│   ├── abi/                # Unchanged
│   └── output/             # Unchanged
```

### 9.2 New Module in `psy_vm`

```
psy_vm/
├── src/
│   ├── dpn/
│   │   ├── eval/
│   │   │   ├── simple.rs   # Existing DummyContextEvalInput
│   │   │   ├── traits.rs   # Existing ContextInput, EvalCache, ContextEval
│   │   │   └── executor.rs # NEW: VmExecutor, ExecutionResult, StateBackend
│   │   └── ...
│   └── ...
```

### 9.3 Updates to `psy_cli/psy_user_cli`

```
psy_user_cli/
├── src/
│   ├── subcommand/
│   │   ├── compile.rs           # NEW
│   │   ├── compile_deploy.rs    # NEW (replaces/extends deploy_contract.rs)
│   │   ├── simulate.rs          # NEW
│   │   ├── deploy_contract.rs   # UPDATED
│   │   ├── args.rs              # UPDATED: new arg structs
│   │   └── mod.rs               # UPDATED: new commands
│   └── ...
```

---

## 10. Data Flow Summary

### 10.1 Compilation Data Flow

```
Source (.psy.rs files)
  ↓ [ModuleResolver]
Merged AST (Program)
  ↓ [Parser]
Parsed AST
  ↓ [Resolver]
ResolvedProgram (constants, struct layouts, contract layout)
  ↓ [TypeChecker]
CheckedProgram (validated methods with method_ids)
  ↓ [CompilerContext + QExecContext]
DPNFunctionCircuitDefinition[] + ContractCodeDefinition + ContractABI
```

### 10.2 Execution Data Flow

```
DPNFunctionCircuitDefinition + ExecutionContext + Inputs
  ↓ [VmExecutor]
  ├── Process definitions (arithmetic, logic, hashing)
  ├── Process state commands (reads via StateBackend, writes to overlay)
  ├── Check assertions
  └── Collect outputs
  ↓
ExecutionResult { success, state_delta, events, op_counts, outputs }
```

### 10.3 Deploy Data Flow

```
ContractOutput
  ↓ [gen_contract_deploy_and_circuits_for_functions]
  ├── DapenContractFunctionCircuit[] (plonky2 circuits)
  ├── function_whitelist (circuit fingerprints)
  └── code_root (merkle root of code hashes)
  ↓
QBCDeployContract
  ↓ [RpcProvider::deploy_contract]
Contract ID on chain
```

### 10.4 Implementation Status

The following components have been implemented:

**Completed:**

1. **VM Executor** (`psy_vm/src/dpn/eval/executor.rs`):
   - `VmExecutor<S: StateBackend>` generic executor with write overlay
   - `InMemoryStateBackend` for testing
   - Full `DPNOpType` evaluation (arithmetic, boolean, comparison, hashing, context, state commands, etc.)
   - State command interleaving via resolution indices (state command results stored in separate map, definitions always evaluated)
   - Assertion checking with detailed failure reporting
   - `ExecutionResult` with state delta, events, operation counts

2. **ABI Executor** (`psy_vm/src/dpn/eval/abi_executor.rs`):
   - `AbiExecutor<S: StateBackend>` wrapping `VmExecutor` with named parameter binding
   - `ExecutorABI` mirrored from compiler ABI (avoids circular dependency)
   - `ParamValue` enum for typed parameter values
   - `FormattedStateDelta` for human-readable state change display

3. **Multi-File Support** (`psy_compiler/src/modules/resolver.rs`):
   - `ModuleResolver::resolve_crate()` for file-based crate resolution
   - `ModuleResolver::resolve_from_sources()` for in-memory source resolution
   - `mod`/`use` parsing in lexer, parser, and AST
   - Item merging with `use` glob import support

4. **CLI Commands** (`psy_cli/psy_user_cli/src/subcommand/`):
   - `compile` — Compile `.psy.rs` files (single or crate mode)
   - `compile-and-deploy` — Compile + deploy with `--dry-run` support
   - `simulate` — VM execution simulation with JSON/table/minimal output

5. **Compiler-Prover Bridge** (`psy_prover/src/session/compile_bridge.rs`):
   - `compile_contract()` and `compile_crate_contract()` functions
   - `simulate_method()` for pre-proof simulation

6. **Integration Tests** (`psy_compiler/tests/vm_executor_integration.rs`):
   - 10 tests: compile → execute → verify (set_value, require pass/fail, if/else, context access, contract state array, ABI resolution, op counts, compilation output structure, multi-file)

**Not Yet Implemented:**

- `RpcStateBackend` (requires live coordinator connection)
- Full UPS end-to-end proving flow integration
- External contract call handling in VM executor
- Enhanced `call` CLI command with ABI parameter binding

### 10.5 Transaction Data Flow

```
User Transaction Request (contract_id, method, inputs)
  ↓ [VM Executor simulation]
ExecutionResult (pre-flight check)
  ↓ [if success]
  ↓ [StateReader: fetch merkle proofs]
DapenContractFunctionCircuitInput (with witnesses)
  ↓ [DapenContractFunctionCircuit: generate proof]
CFC Proof
  ↓ [UserProvingSessionManager: UPS step]
UPS Step Proof
  ↓ [... more CFC steps ...]
  ↓ [End Cap + Signature]
SubmitUserEndCapNonProofInput + End Cap Proof
  ↓ [RpcProvider::submit_end_cap]
Transaction on chain
```
