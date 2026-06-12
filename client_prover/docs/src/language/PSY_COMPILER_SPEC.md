# PSY Smart Contract Compiler — Complete Rewrite Specification

## 1. Overview

This document specifies the complete rewrite of the PSY VM / smart contract compiler. The goal is to allow users to write smart contracts in a Rust-like DSL that compiles down to a serialized arithmetic circuit representation (`DPNFunctionCircuitDefinition`), which is then compiled to plonky2 circuits for zero-knowledge proof generation.

### 1.1 Design Goals

1. **Rust-like ergonomics**: Contracts look and feel like Rust structs + impl blocks.
2. **Deterministic compilation**: The same source always produces the same circuit.
3. **Full state exposure**: Contracts can access checkpoint leaves, global state roots, all merkle trees, UPS info, caller context, and cross-contract state.
4. **Zero-allocation state arrays**: `ContractStateArray<N, T>` compiles to merkle-proof-backed virtual arrays — no actual allocation of N slots.
5. **Arithmetic circuit target**: The compiler emits `DPNFunctionCircuitDefinition` (the existing serialized circuit IR), which the existing `psy_dpn_circuit` crate compiles to plonky2.

### 1.2 Compilation Pipeline

```
┌─────────────┐     ┌─────────┐     ┌────────────┐     ┌──────────────────────────────┐     ┌────────────┐
│  PSY DSL    │────▶│  Parse  │────▶│  Type Check │────▶│  Lower to DPN Symbolic IR    │────▶│  Serialize │
│  (.psy.rs)  │     │  (AST)  │     │  & Resolve  │     │  (QExecContext / SymFeltRef)  │     │  (CBOR)    │
└─────────────┘     └─────────┘     └────────────┘     └──────────────────────────────┘     └────────────┘
                                                                                                   │
                                                                                                   ▼
                                                                                        ┌──────────────────┐
                                                                                        │ DPNFunction      │
                                                                                        │ CircuitDefinition│
                                                                                        └────────┬─────────┘
                                                                                                 │
                                                                                                 ▼
                                                                                        ┌──────────────────┐
                                                                                        │ plonky2 Circuit  │
                                                                                        │ (existing path)  │
                                                                                        └──────────────────┘
```

---

## 2. Language Specification

### 2.1 Primitive Types

| DSL Type | Representation | Felt Count | Description |
|----------|---------------|------------|-------------|
| `Felt` | `GoldilocksField` (u64, p = 2^64 - 2^32 + 1) | 1 | Native field element |
| `Bool` | Boolean constrained to 0 or 1 | 1 | Boolean value |
| `U32` | 32-bit unsigned integer | 1 | Constrained u32 in a felt |
| `Hash` | `QHashOut<F>` = `[Felt; 4]` | 4 | Poseidon hash output (256-bit) |

### 2.2 Composite Types

#### 2.2.1 `#[derive(FeltSized)]` Structs

All user-defined structs used in contract state or as parameters must derive `FeltSized`. This trait provides:

- `const FELT_SIZE: usize` — total number of field elements the struct occupies.
- Automatic flattening to/from a `[Felt; Self::FELT_SIZE]` representation.
- Field offset computation at compile time.

```rust
#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,      // offset 0, size 1
    pub total_received: Felt,  // offset 1, size 1
}
// TokenMailbox::FELT_SIZE == 2

#[derive(FeltSized)]
pub struct UserTokenState {
    pub balance: Felt,           // offset 0, size 1
    pub padding: [Felt; 3],     // offset 1, size 3
}
// UserTokenState::FELT_SIZE == 4
```

**Rules:**
- Fields must be `Felt`, `Bool`, `U32`, `Hash`, `[Felt; N]`, or another `FeltSized` struct.
- No enums, no dynamic-length types, no references (except function parameters).
- `[T; N]` where `T: FeltSized` has `FELT_SIZE = T::FELT_SIZE * N`.

#### 2.2.2 `ContractStateArray<const N: usize, T: FeltSized>`

A virtual array of `N` entries, each of type `T`. This does **not** allocate `N * T::FELT_SIZE` slots. Instead:

- Each access `self.other_users[index]` compiles to a merkle proof read/write against the contract's state tree.
- The state tree height is `ceil(log2(total_contract_state_felts))` where the array region is mapped to contiguous leaf indices.
- Reads emit `GetSelfUserCurrentContractStateSlotRange` or `GetOtherUserContractStateSlotRange` state commands.
- Writes emit `SetContractStateSlotRange` state commands.
- The index `[index]` is a `Felt` representing the user/slot ID, resolved to a merkle path.

**Layout in state tree:**
```
Slot 0..S-1:           Inline struct fields (e.g., UserTokenState)
Slot S..S+(N*T::FELT_SIZE)-1:  ContractStateArray region
```

Where `S` = sum of FELT_SIZE of all inline (non-array) fields.

### 2.3 Contract Declaration

```rust
#[contract]
pub struct ExampleContract {
    pub token_state: UserTokenState,
    pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
}
```

The `#[contract]` attribute:

1. Computes the **state layout** — mapping each field to a range of state tree leaf indices.
2. Computes `state_tree_height` = `ceil(log2(total_state_slots))`.
3. Generates an **ABI descriptor** (`ContractABI`) containing:
   - State layout (field names, types, offsets, sizes).
   - Method signatures (method_id, parameter types, return types).
4. Generates a static `Self::ABI` reference usable in cross-contract reads.

**State Layout Computation:**

```
ExampleContract state layout:
  token_state: offset=0, size=4  (UserTokenState::FELT_SIZE)
  other_users: offset=4, stride=2 (TokenMailbox::FELT_SIZE), count=1073741824

  Total inline felts: 4
  Total virtual felts: 4 + 1073741824 * 2 = 2147483652
  state_tree_height: ceil(log2(2147483652)) = 32
```

### 2.4 Contract Implementation

```rust
#[contract_implementation]
impl ExampleContract {
    // Private helper — NOT a contract entry point
    fn transfer_helper(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        // ...
    }

    // Public entry point — generates a circuit + method_id
    #[contract_method]
    pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        self.transfer_helper(ctx, to, amount);
    }
}
```

**Rules:**

- `#[contract_method]` methods become contract entry points. Each gets:
  - A unique `method_id: u32` = `truncate_u32(sha256(method_signature))`.
  - A `DPNFunctionCircuitDefinition` with inputs = parameter felts, outputs = modified state felts.
- Non-annotated methods are **helpers** — inlined at call sites. They do NOT produce separate circuits.
- Every `#[contract_method]` must take `&mut self` and `ctx: &mut ChainContext` as the first two parameters.
- Const generics (e.g., `<const N: usize>`) are supported on helper functions and are monomorphized at compile time.

### 2.5 Parameter Types

Function parameters can be:

| Type | Felt Count | Passed As |
|------|-----------|-----------|
| `Felt` | 1 | Single circuit input |
| `Bool` | 1 | Boolean circuit input |
| `U32` | 1 | U32 circuit input |
| `Hash` | 4 | 4 circuit inputs |
| `[T; N]` where `T: FeltSized` | `T::FELT_SIZE * N` | N*size circuit inputs |
| `S` where `S: FeltSized` | `S::FELT_SIZE` | S::FELT_SIZE circuit inputs |
| `&[T; N]` | same as `[T; N]` | Reference (no semantic difference in circuits) |

### 2.6 Expressions and Operators

#### 2.6.1 Arithmetic (on `Felt`)

| Expression | DPN Op | Notes |
|-----------|--------|-------|
| `a + b` | `Add` | Field addition |
| `a - b` | `Sub` | Field subtraction |
| `a * b` | `Mul` | Field multiplication |
| `a / b` | `Div` | Field division (multiplicative inverse) |
| `a % b` | `Mod` | Modular reduction |
| `a.checked_add_no_overflow(msg)` | `Add` + overflow assertion | Adds and asserts result >= both operands (for token safety) |

#### 2.6.2 Arithmetic (on `U32`)

| Expression | DPN Op |
|-----------|--------|
| `a + b` | `U32Add` |
| `a - b` | `U32Sub` |
| `a * b` | `U32Mul` |
| `a / b` | `U32Div` |
| `a % b` | `U32Mod` |
| `a & b` | `U32And` |
| `a \| b` | `U32Or` |
| `a ^ b` | `U32Xor` |
| `a << b` | `U32ShiftLeft` |
| `a >> b` | `U32ShiftRight` |

#### 2.6.3 Comparison

| Expression | DPN Op | Result |
|-----------|--------|--------|
| `a == b` | `Eq` | `Bool` |
| `a != b` | `Eq` + `BoolNot` | `Bool` |
| `a < b` | `Lt` | `Bool` |
| `a <= b` | `Lte` | `Bool` |
| `a > b` | `Gt` | `Bool` |
| `a >= b` | `Gte` | `Bool` |

#### 2.6.4 Boolean

| Expression | DPN Op |
|-----------|--------|
| `a && b` | `BoolAnd` |
| `a \|\| b` | `BoolOr` |
| `!a` | `BoolNot` |

#### 2.6.5 Hashing

| Expression | DPN Op | Notes |
|-----------|--------|-------|
| `hash(values...)` | `HashNoPad` | Poseidon hash of arbitrary felts |
| `hash_two_to_one(left, right)` | `HashTwoToOne` | Merkle node compression |

#### 2.6.6 Assignment Operators

| Expression | Desugars To |
|-----------|-------------|
| `a += b` | `a = a + b` |
| `a -= b` | `a = a - b` |
| `a *= b` | `a = a * b` |

When the LHS is a state field (e.g., `self.token_state.balance -= amount`), the compiler:
1. Reads the current value via a state query.
2. Computes the new value.
3. Emits a `SetContractStateSlotSingle` or `SetContractStateSlotRange` command.

### 2.7 Control Flow

#### 2.7.1 `require(condition, message)`

```rust
require(self.token_state.balance >= amount, "Insufficient balance");
```

Compiles to: assert that `condition` is true. In the DPN IR, this becomes:
- Evaluate condition to a `Bool` symbolic ref.
- Push `SymRefAssertion { left: condition_ref, right: ConstantTrue, message }`.

In circuit terms, this constrains `condition == 1`.

#### 2.7.2 `if / else if / else`

```rust
if condition {
    // body
} else if other_condition {
    // body
} else {
    // body
}
```

Compiles using the existing `QExecContext` condition stack:
- `start_if_block(condition)` → pushes condition.
- All state writes in the block become conditional: `cselect(condition, new_value, old_value)`.
- `start_else_if_block(other_condition)` → condition = `!prev && other_condition`.
- `end_if_block()` → pops condition stack.

**Important:** There are no real branches in arithmetic circuits. Both paths are always evaluated; the condition selects which result is used.

#### 2.7.3 `for` Loops (Compile-Time Unrolling)

```rust
for i in 0..N {
    self.transfer_helper(ctx, transfers[i].to, transfers[i].amount);
}
```

Loops must have compile-time-known bounds. The compiler fully unrolls them:
- `for i in 0..3` → three copies of the body with `i` substituted as constants `0, 1, 2`.
- No dynamic loops allowed (circuits are fixed-size).

### 2.8 Built-in Functions

| Function | Signature | DPN Mapping |
|----------|-----------|-------------|
| `require(cond, msg)` | `(Bool, &str) -> ()` | Assert `cond == true` |
| `hash(...)` | `(Felt...) -> Hash` | `HashNoPad` |
| `hash_two_to_one(l, r)` | `(Hash, Hash) -> Hash` | `HashTwoToOne` |
| `verify_secp256k1(pk, msg, sig)` | `(...) -> Bool` | `Secp256k1Verify` |

---

## 3. Chain Context (`ChainContext`)

The `ChainContext` object provides read-only access to all blockchain state visible to the contract execution. It maps directly to DPN context operations and state commands.

### 3.1 Direct Context Fields

```rust
pub struct ChainContext {
    // --- Identity ---
    pub user_id: Felt,              // GetUserId (DPNOpType 46)
    pub contract_id: Felt,          // GetContractId (DPNOpType 47)
    pub calling_contract: Felt,     // GetCallerContractId (DPNOpType 79)
    pub nonce: Felt,                // GetNonce (DPNOpType 49)
    pub checkpoint_id: Felt,        // GetCheckpointId (DPNOpType 48)
    pub user_public_key: Hash,      // GetUserPublicKeyHash (DPNOpType 50)

    // --- Cross-User State Access ---
    pub users: UserStateAccessor,   // Accessor for other users' state

    // --- Checkpoint Data ---
    pub checkpoint: CheckpointAccessor,  // Accessor for checkpoint leaf data
}
```

### 3.2 User State Accessor (Cross-User Reads)

```rust
// Access another user's contract state (read-only)
let total_sent = ctx.users[sender]
    .contract_state::<Self::ABI>(ctx.contract_id)
    .other_users[ctx.user_id]
    .total_sent;
```

This compiles to a chain of state commands:

1. `GetOtherUserContractStateSlotRange` — reads `sender`'s state for contract `ctx.contract_id`, at the computed offset for `other_users[ctx.user_id].total_sent`.

**DPN State Command:** `DPNStateCommandType::GetOtherUserContractStateSlotHash` (32) or `GetOtherUserContractStateSlotRange` (34), depending on access width.

**Generated Witness Requirements:**
- Merkle proof of `sender`'s `user_state_tree_root` containing the contract state.
- Merkle proof within the contract state tree for the accessed slot.
- Both proofs verified in the circuit against the global user tree root.

### 3.3 Checkpoint Accessor

Provides access to the `PsyCheckpointLeaf` data for the current or specified checkpoint:

```rust
pub struct CheckpointAccessor;

impl CheckpointAccessor {
    // Current checkpoint stats (DPNStateCommandType::GetCheckpointLeafStats = 40)
    pub fn stats(&self, checkpoint_id: Felt) -> CheckpointStats;
}

pub struct CheckpointStats {
    pub guta_fees_collected: Felt,
    pub da_fees_collected: Felt,
    pub user_ops_processed: Felt,
    pub total_transactions: Felt,
    pub slots_modified: Felt,
    pub pm_jobs_completed: Felt,
    pub block_time: Felt,
    pub random_seed: Hash,
    pub pm_rewards_commitment: Hash,
    // DA challenge window (DA_CHALLENGE_WINDOW entries)
    pub da_challenges_claimed: [Felt; DA_CHALLENGE_WINDOW],
}
```

**DPN Mapping:** `GetCheckpointLeafStats` (command type 40) returns a `TargetArray` of all checkpoint leaf fields, decomposed into the struct above.

### 3.4 Contract Leaf Accessor

```rust
// Read contract deployment info
let contract_leaf = ctx.contract_leaf(some_contract_id);

pub struct ContractLeafView {
    pub deployer: Hash,              // QHashOut — deployer address
    pub function_tree_root: Hash,    // QHashOut — merkle root of functions
    pub code_root: Hash,             // QHashOut — hash of contract bytecode
    pub state_tree_height: Felt,     // Height of contract state tree
}
```

**DPN Mapping:** `GetContractLeaf` (command type 41).

### 3.5 External Contract Calls

#### 3.5.1 Synchronous Calls (Inline Execution)

```rust
let results = ctx.call_sync(
    contract_id,   // Target contract
    method_id,     // Function selector
    &args,         // Input felts
    num_outputs,   // Expected output count
);
```

**DPN Mapping:** `InvokeExternalContractFunctionSync` (command type 8). The callee's circuit is executed inline within the caller's proof. Outputs are directly available.

#### 3.5.2 Deferred Calls

```rust
let call_hash = ctx.call_deferred(
    contract_id,
    method_id,
    &args,
);
// call_hash: Hash — commitment to the deferred call
```

**DPN Mapping:** `InvokeExternalContractFunctionDeferred` (command type 9). Creates a deferred transaction that executes in a later UPS step. Returns a hash commitment.

### 3.6 Cross-Contract State Read with ABI

The most powerful state access pattern: reading another user's state for any contract, using a typed ABI:

```rust
// Read sender's state for this same contract
let total_sent_by_sender = ctx.users[sender]
    .contract_state::<Self::ABI>(ctx.contract_id)
    .other_users[ctx.user_id]
    .total_sent;
```

**Compilation steps:**

1. Resolve `Self::ABI` to the contract's state layout.
2. Compute the field offset: `other_users` base offset + `ctx.user_id * TokenMailbox::FELT_SIZE` + `total_sent` field offset within `TokenMailbox`.
3. Emit `GetOtherUserContractStateSlotRange(user_id=sender, contract_id=ctx.contract_id, offset=computed, length=1)`.
4. The result is a single `Felt` — the `total_sent` value.

For reading from a **different** contract, the user passes a different ABI:

```rust
let value = ctx.users[other_user]
    .contract_state::<OtherContract::ABI>(other_contract_id)
    .some_field;
```

The ABI is a compile-time-only construct — it provides the offset/size mapping but is not stored on-chain.

---

## 4. State Management

### 4.1 Self-State Access (Read/Write)

When the contract accesses `self.*`, it accesses the **current user's state for this contract**.

**Read:**
```rust
let bal = self.token_state.balance;
// Compiles to: GetSelfUserCurrentContractStateSlotSingle(offset=0)
// DPN: GetStateQueryResultSingle from state command
```

**Write:**
```rust
self.token_state.balance = new_value;
// Compiles to: SetContractStateSlotSingle(offset=0, value=new_value)
```

**Struct Read/Write:**
```rust
let ts = self.token_state;  // reads 4 felts at offset 0..3
self.token_state = new_ts;  // writes 4 felts at offset 0..3
// Uses GetSelfUserCurrentContractStateSlotRange / SetContractStateSlotRange
```

### 4.2 ContractStateArray Access

```rust
// Read
let mailbox = self.other_users[to];
// offset = inline_size + to * TokenMailbox::FELT_SIZE
// = 4 + to * 2
// Compiles to: GetSelfUserCurrentContractStateSlotRange(offset, TokenMailbox::FELT_SIZE)

// Field access on array element
let sent = self.other_users[to].total_sent;
// offset = 4 + to * 2 + 0  (total_sent is at offset 0 in TokenMailbox)
// Compiles to: GetSelfUserCurrentContractStateSlotSingle(offset)

// Write
self.other_users[to].total_sent = new_value;
// Compiles to: SetContractStateSlotSingle(offset, new_value)
```

**Index computation:** The index into `ContractStateArray` is a `Felt`. The compiler computes:
```
slot_offset = array_base_offset + index * element_felt_size + field_offset_within_element
```

This arithmetic is performed symbolically (it emits `Mul` and `Add` operations in the circuit) since `index` is typically a runtime value (e.g., a user ID).

### 4.3 State Delta Tracking

Every state read/write pair produces a **delta merkle proof** in the witness:
- `old_root` → `new_root` transition.
- The circuit verifies: `merkle_verify(old_root, index, old_value, siblings) == true` and `merkle_verify(new_root, index, new_value, siblings) == true` and `siblings` are the same for both.

The `DPNFunctionCircuitDefinition` tracks state commands in order, and the circuit builder (`psy_dpn_circuit`) generates the corresponding merkle proof verification gadgets.

### 4.4 State Tree Structure

```
Contract State Tree (height = state_tree_height)
├── Leaf 0: token_state.balance
├── Leaf 1: token_state.padding[0]
├── Leaf 2: token_state.padding[1]
├── Leaf 3: token_state.padding[2]
├── Leaf 4: other_users[0].total_sent
├── Leaf 5: other_users[0].total_received
├── Leaf 6: other_users[1].total_sent
├── Leaf 7: other_users[1].total_received
│   ...
└── Leaf 4 + 2*N - 1: other_users[N-1].total_received
```

Each leaf holds a single `Felt`. The tree is sparse — most leaves are zero (the merkle tree uses cached zero hashes for uninitialized regions).

---

## 5. Type System

### 5.1 `FeltSized` Trait

```rust
pub trait FeltSized {
    const FELT_SIZE: usize;

    fn to_felts(&self) -> [Felt; Self::FELT_SIZE];
    fn from_felts(felts: &[Felt]) -> Self;
    fn field_offset(field_name: &str) -> usize;
    fn field_size(field_name: &str) -> usize;
}
```

The `#[derive(FeltSized)]` macro automatically implements this by:
1. Summing field sizes in declaration order.
2. Computing cumulative offsets.
3. Generating `to_felts` / `from_felts` by concatenating/splitting field representations.

### 5.2 Type Resolution Rules

| Source Type | Circuit Type | FELT_SIZE |
|------------|-------------|-----------|
| `Felt` | `Target` | 1 |
| `Bool` | `BoolTarget` | 1 |
| `U32` | `U32Target` | 1 |
| `Hash` | `HashOutTarget` ([Target; 4]) | 4 |
| `[T; N]` | `[T::Circuit; N]` | `T::FELT_SIZE * N` |
| `S: FeltSized` | Flattened `[Target; S::FELT_SIZE]` | `S::FELT_SIZE` |

### 5.3 Checked Arithmetic

```rust
// Overflow-safe addition for token balances
let new_bal = old_bal.checked_add_no_overflow("overflow message");
```

Compiles to:
```
result = Add(old_bal, amount)
overflow_check = Gte(result, old_bal)  // result >= old_bal means no overflow
Assert(overflow_check == true, "overflow message")
```

The alternative explicit pattern is also supported:
```rust
require(self.other_users[to].balance + amount >= self.other_users[to].balance, "Overflow detected");
self.other_users[to].balance += amount;
```

---

## 6. ABI Generation

### 6.1 Contract ABI Descriptor

Each `#[contract]` struct generates a `ContractABI`:

```rust
pub struct ContractABI {
    pub contract_name: String,
    pub state_tree_height: u16,
    pub state_layout: Vec<StateFieldDescriptor>,
    pub methods: Vec<MethodDescriptor>,
}

pub struct StateFieldDescriptor {
    pub name: String,
    pub field_type: FieldType,
    pub offset: usize,          // Felt offset in state tree
    pub felt_size: usize,       // Number of felts
    pub is_array: bool,
    pub array_count: Option<usize>,
    pub element_type: Option<Box<StateFieldDescriptor>>,
}

pub struct MethodDescriptor {
    pub name: String,
    pub method_id: u32,         // sha256-truncated selector
    pub params: Vec<ParamDescriptor>,
    pub is_view: bool,          // true if no state writes
}

pub struct ParamDescriptor {
    pub name: String,
    pub param_type: FieldType,
    pub felt_size: usize,
}
```

### 6.2 Method ID Computation

```rust
fn compute_method_id(contract_name: &str, method_name: &str, param_types: &[FieldType]) -> u32 {
    let signature = format!("{}::{}({})",
        contract_name,
        method_name,
        param_types.iter().map(|t| t.canonical_name()).collect::<Vec<_>>().join(",")
    );
    let hash = sha256(signature.as_bytes());
    u32::from_be_bytes([hash[0], hash[1], hash[2], hash[3]])
}
```

---

## 7. Compiler Architecture

### 7.1 Crate Structure

```
psy_compiler/
├── Cargo.toml
├── src/
│   ├── lib.rs
│   ├── parse/              # Phase 1: Parsing
│   │   ├── mod.rs
│   │   ├── lexer.rs        # Tokenization
│   │   ├── parser.rs       # Recursive descent parser
│   │   ├── ast.rs          # AST node definitions
│   │   └── tokens.rs       # Token types
│   ├── types/              # Phase 2: Type checking
│   │   ├── mod.rs
│   │   ├── resolver.rs     # Name resolution & type inference
│   │   ├── checker.rs      # Type constraint checking
│   │   ├── layout.rs       # FeltSized layout computation
│   │   └── errors.rs       # Type error definitions
│   ├── lower/              # Phase 3: Lowering to DPN IR
│   │   ├── mod.rs
│   │   ├── context.rs      # CompilerContext wrapping QExecContext
│   │   ├── expressions.rs  # Expression lowering
│   │   ├── statements.rs   # Statement lowering
│   │   ├── state_access.rs # State read/write lowering
│   │   ├── builtins.rs     # Built-in function lowering
│   │   └── monomorphize.rs # Const generic monomorphization
│   ├── abi/                # ABI generation
│   │   ├── mod.rs
│   │   └── codegen.rs      # ABI struct generation
│   └── output/             # Phase 4: Serialization
│       ├── mod.rs
│       └── serialize.rs    # DPNFunctionCircuitDefinition emission
```

### 7.2 Phase 1: Parsing

The parser produces an AST from the PSY DSL source. Since the DSL is a subset of Rust syntax, the parser handles:

**Top-Level Items:**
- `const` declarations (compile-time constants only).
- `#[derive(FeltSized)] pub struct Name { fields }` — struct definitions.
- `#[contract] pub struct Name { fields }` — contract state definitions.
- `#[contract_implementation] impl Name { methods }` — contract implementations.

**AST Node Types:**

```rust
pub enum Item {
    ConstDecl { name: String, ty: Type, value: Expr },
    StructDef { attrs: Vec<Attribute>, name: String, fields: Vec<FieldDef>, generics: Vec<Generic> },
    ContractDef { name: String, fields: Vec<FieldDef> },
    ImplBlock { contract_name: String, methods: Vec<MethodDef> },
}

pub enum Expr {
    Literal(LiteralKind),           // 42, true, "string"
    Ident(String),                  // variable_name
    FieldAccess(Box<Expr>, String), // expr.field
    IndexAccess(Box<Expr>, Box<Expr>), // expr[index]
    BinaryOp(Box<Expr>, BinOp, Box<Expr>),
    UnaryOp(UnaryOp, Box<Expr>),
    MethodCall(Box<Expr>, String, Vec<Expr>),  // expr.method(args)
    FunctionCall(String, Vec<Expr>),           // func(args)
    ArrayLiteral(Vec<Expr>),        // [a, b, c]
    StructLiteral(String, Vec<(String, Expr)>),
    Block(Vec<Stmt>),
    // ABI-typed cross-contract access
    TypedContractAccess {
        user_expr: Box<Expr>,       // ctx.users[sender]
        abi_type: String,           // Self::ABI or OtherContract::ABI
        contract_id: Box<Expr>,     // ctx.contract_id
        access_chain: Vec<AccessStep>, // .field or [index] chain
    },
}

pub enum Stmt {
    Let { name: String, ty: Option<Type>, value: Expr },
    Assign { target: Expr, value: Expr },
    CompoundAssign { target: Expr, op: BinOp, value: Expr }, // +=, -=, *=
    Expr(Expr),
    If { condition: Expr, then_block: Vec<Stmt>, else_block: Option<Vec<Stmt>> },
    For { var: String, range: Range, body: Vec<Stmt> },
    Return(Option<Expr>),
}
```

### 7.3 Phase 2: Type Checking & Resolution

1. **Constant folding:** Evaluate all `const` declarations to literal values.
2. **Struct layout:** Compute `FELT_SIZE` and field offsets for all `FeltSized` structs.
3. **Contract layout:** Compute state tree layout, `state_tree_height`, and virtual array mappings.
4. **Name resolution:** Resolve all identifiers to their definitions. Track `self` fields vs. local variables.
5. **Type inference:** Infer types for all `let` bindings. Propagate types through expressions.
6. **Type checking:**
   - Arithmetic operators require matching types (`Felt+Felt`, `U32+U32`).
   - Comparison operators return `Bool`.
   - `require()` first argument must be `Bool`.
   - Array index must be `Felt` or `U32`.
   - Assignment target type must match value type.
7. **Monomorphization:** For each call to a generic function `fn foo<const N: usize>(...)`, create a specialized copy with concrete `N`.

### 7.4 Phase 3: Lowering to DPN Symbolic IR

The lowering phase translates the typed AST into DPN operations using `QExecContext`.

**Compiler Context:**

```rust
pub struct CompilerContext {
    pub exec: QExecContext,
    pub contract_layout: ContractStateLayout,
    pub local_vars: HashMap<String, SymValue>,   // name -> symbolic felt refs
    pub self_state_cache: HashMap<usize, SymValue>, // slot -> cached read
}

pub enum SymValue {
    Felt(SymFeltRef),
    Bool(SymFeltRef),
    U32(SymFeltRef),
    Hash([SymFeltRef; 4]),
    Struct { fields: Vec<(String, SymValue)>, layout: StructLayout },
    Array { elements: Vec<SymValue> },
}
```

**Lowering Rules:**

| AST Node | DPN IR Output |
|----------|---------------|
| `let x = a + b` | `sym_ref = exec.op_add(a_ref, b_ref)` → store in `local_vars["x"]` |
| `self.field = val` | `exec.op_set_state_felt(offset, val_ref)` |
| `self.field` (read) | `exec.op_get_state_felt(...)` |
| `self.arr[i].field` | Compute dynamic offset, emit `GetSelfUserCurrentContractStateSlotRange` |
| `require(c, m)` | `exec.assert_true(c_ref, m)` |
| `if cond { ... }` | `exec.start_if_block(cond_ref)` ... `exec.end_if_block()` |
| `for i in 0..N { ... }` | Unroll N times, substituting `i` with constants |
| `ctx.users[u].contract_state::<ABI>(c).field` | `GetOtherUserContractStateSlotRange(u, c, offset, size)` |
| `ctx.calling_contract` | `exec.get_caller_contract_id()` → `SymFeltRef(GetCallerContractId)` |
| `ctx.call_deferred(...)` | `exec.cinvoke_external_contract_function_deferred(...)` |

### 7.5 Phase 4: Serialization

After lowering, the `QExecContext` is compiled to a `DPNFunctionCircuitDefinition` using the existing `PsyCompileResult::compile()` path:

1. `PsyCompileResult::new()` — initialize.
2. `injest_sfr()` for each output/assertion ref — walk the dependency graph, assign indices.
3. `injest_state_cmd()` for each state command — resolve refs to indices.
4. `finalize()` — produce `DPNFunctionCircuitDefinition`.
5. CBOR serialize via `serde_cbor::to_vec()`.
6. Package into `ContractFunctionCodeDefinition` with `vm_type = VM_TYPE_STANDARD_DAPEN_V1`.

The per-method output:

```rust
ContractFunctionCodeDefinition {
    method_id: u32,                // sha256-truncated method signature
    num_inputs: u32,               // total input felts (params only, not self/ctx)
    num_outputs: u32,              // total output felts (usually 0 for void methods)
    vm_type: VM_TYPE_STANDARD_DAPEN_V1,
    code: Vec<u8>,                 // CBOR-encoded DPNFunctionCircuitDefinition
}
```

The contract output:

```rust
ContractCodeDefinition {
    state_tree_height: u16,
    functions: Vec<ContractFunctionCodeDefinition>,
}
```

---

## 8. Exposed Blockchain State Summary

The following blockchain state is accessible from contracts:

### 8.1 Execution Identity (Direct — No Merkle Proofs)

| Field | Type | DPN Op | Description |
|-------|------|--------|-------------|
| `ctx.user_id` | `Felt` | `GetUserId` (46) | Current executing user's ID |
| `ctx.contract_id` | `Felt` | `GetContractId` (47) | Current contract's ID |
| `ctx.calling_contract` | `Felt` | `GetCallerContractId` (79) | Contract that invoked this call (0 if user-initiated) |
| `ctx.nonce` | `Felt` | `GetNonce` (49) | Current user's transaction nonce |
| `ctx.checkpoint_id` | `Felt` | `GetCheckpointId` (48) | Current checkpoint (block) number |
| `ctx.user_public_key` | `Hash` | `GetUserPublicKeyHash` (50) | Current user's public key hash |

### 8.2 Self-User Contract State (Merkle Proofs Against User State Tree)

| Access Pattern | DPN Command | Proof Type |
|---------------|-------------|------------|
| `self.field` (read single) | `GetSelfUserCurrentContractStateSlotSingle` (17) | Merkle inclusion in user's contract state tree |
| `self.field` (read struct/range) | `GetSelfUserCurrentContractStateSlotRange` (18) | Merkle inclusion, multiple consecutive slots |
| `self.field` (read hash) | `GetSelfUserCurrentContractStateSlotHash` (16) | Merkle inclusion, 4-element hash |
| `self.field = val` (write) | `SetContractStateSlotSingle` (1) or `SetContractStateSlotRange` (2) | Delta merkle proof (old_root → new_root) |

### 8.3 Self-User, External Contract State

| Access Pattern | DPN Command | Description |
|---------------|-------------|-------------|
| `ctx.users[self].contract_state::<OtherABI>(other_id).field` | `GetSelfUserExternalContractStateSlot{Hash,Single,Range}` (24-26) | Read own state for a different contract |

### 8.4 Other User's Contract State (Cross-User Reads)

| Access Pattern | DPN Command | Proof Type |
|---------------|-------------|------------|
| `ctx.users[user].contract_state::<ABI>(contract).field` | `GetOtherUserContractStateSlot{Hash,Single,Range}` (32-34) | Merkle proof against global user tree root → user's state tree → contract state tree → slot |

### 8.5 Checkpoint Leaf Data

| Access Pattern | DPN Command | Description |
|---------------|-------------|-------------|
| `ctx.checkpoint.stats(id)` | `GetCheckpointLeafStats` (40) | Full checkpoint statistics |

**Exposed `PsyCheckpointLeaf` fields:**
- `guta_fees_collected` — Total fees from user operations
- `da_fees_collected` — Data availability fees
- `user_ops_processed` — Number of transactions processed
- `total_transactions` — Total transactions in checkpoint
- `slots_modified` — State tree slots modified
- `pm_jobs_completed` — Proof miner jobs completed
- `block_time` — Checkpoint timestamp
- `random_seed` — Verifiable random seed (Hash)
- `pm_rewards_commitment` — Proof miner rewards commitment (Hash)
- `da_challenges_claimed` — DA challenge window array

### 8.6 Contract Deployment Info

| Access Pattern | DPN Command | Description |
|---------------|-------------|-------------|
| `ctx.contract_leaf(id)` | `GetContractLeaf` (41) | Contract deployment metadata |

**Exposed `PsyContractLeaf` fields:**
- `deployer` — Deployer's public key hash (Hash)
- `function_tree_root` — Merkle root of contract function definitions (Hash)
- `code_root` — Hash of contract bytecode (Hash)
- `state_tree_height` — Height of contract state merkle tree (Felt)

### 8.7 Global State Trees

The following trees are implicitly involved in proof generation (their roots are constrained in the circuit but not directly readable as arbitrary values):

| Tree | Root Location | Purpose |
|------|--------------|---------|
| **User Tree** | `PsyCheckpointGlobalStateRoots.user_tree_root` | Maps user_id → `PsyUserLeaf` |
| **Contract Tree** | `PsyCheckpointGlobalStateRoots.contract_tree_root` | Maps contract_id → `PsyContractLeaf` |
| **User State Tree** | `PsyUserLeaf.user_state_tree_root` | Per-user: maps contract_id → contract state subtree |
| **Contract State Tree** | Per-user-contract subtree | Maps slot_index → Felt value |
| **Checkpoint Tree** | Global | Maps checkpoint_id → `PsyCheckpointLeaf` |

### 8.8 UPS (User Proving Session) Context

The UPS wraps the entire contract execution in a proving session:

```
UPS Flow:
  START → CFC_1 → CFC_2 → ... → CFC_N → END

  START: Establishes user identity, starting nonce, initial state roots
  CFC_i: Contract Function Call — one contract method execution
  END:   Verifies all state deltas chain correctly, final state roots
```

| UPS Field | Exposed Via | Description |
|-----------|------------|-------------|
| User ID | `ctx.user_id` | Proven via signature verification in START |
| Starting nonce | `ctx.nonce` | Verified in START, incremented per CFC |
| Contract ID | `ctx.contract_id` | Set per CFC step |
| Caller contract | `ctx.calling_contract` | 0 for user-initiated, contract_id for cross-contract |
| State root chain | Implicit | Each CFC's new_root becomes next CFC's old_root |

---

## 9. Arithmetic Circuit Serialization Format

The final output of the compiler is a `DPNFunctionCircuitDefinition`, which is the serialized arithmetic circuit IR. This section documents its exact structure.

### 9.1 `DPNFunctionCircuitDefinition`

```rust
pub struct DPNFunctionCircuitDefinition {
    // Metadata
    pub name: String,
    pub method_id: u32,

    // Circuit I/O
    pub circuit_inputs: Vec<u64>,    // Indexed IDs of input variables
    pub circuit_outputs: Vec<u64>,   // Indexed IDs of output variables

    // State operations
    pub state_commands: Vec<DPNStateCmd<u64>>,  // Ordered state read/write commands
    pub state_command_resolution_indices: Vec<usize>,  // Where each command resolves in definitions

    // Constraints
    pub assertions: Vec<DPNAssertEqInfoIndexed>,  // Equality constraints

    // Operation graph
    pub definitions: Vec<DPNIndexedVarDef>,  // Topologically sorted operation definitions

    // Events
    pub events: Vec<DPNEventRecord>,
}
```

### 9.2 `DPNIndexedVarDef` — Single Operation

```rust
pub struct DPNIndexedVarDef {
    pub data_type: DPNBuiltInDataType,  // Target=0, Bool=1, U32=2, Hash=3, ...
    pub index: usize,                    // Index within this data type
    pub op_type: DPNOpType,             // Operation (Add=4, Mul=6, Eq=13, ...)
    pub inputs: Vec<u64>,                // References to input operands (encoded_indexed_op_id)
}
```

**Encoded ID format:** `encode_indexed_op_id(data_type: u8, index: usize) -> u64`
- Upper 32 bits: `data_type as u32`
- Lower 32 bits: `index as u32`

### 9.3 `DPNStateCmd<u64>` — State Command

Each state command references operands by their `u64` indexed ID:

```rust
pub struct DPNStateCmd<T> {
    pub command_type: DPNStateCommandType,
    pub inputs: Vec<T>,       // Symbolic inputs (offsets, values, etc.)
    pub outputs: DPNStateCmdOutputType<T>,  // Return type
}
```

### 9.4 Serialization

The entire `DPNFunctionCircuitDefinition` is serialized with CBOR (`serde_cbor::to_vec`) and stored as the `code` field of `ContractFunctionCodeDefinition`.

---

## 10. Circuit Compilation (Existing Path)

After the compiler produces `DPNFunctionCircuitDefinition`, the existing `psy_dpn_circuit` crate compiles it to a plonky2 circuit:

### 10.1 Circuit Builder Flow

1. **Register inputs:** For each `circuit_input`, create a plonky2 `Target` / `BoolTarget` / `U32Target`.
2. **Process definitions:** For each `DPNIndexedVarDef` in topological order:
   - Look up input targets by their indexed IDs.
   - Call the corresponding plonky2 gadget (e.g., `builder.add()`, `builder.mul()`).
   - Store the result target at the definition's indexed ID.
3. **Process state commands:** For each `DPNStateCmd`:
   - Create witness slots for merkle proofs (siblings, old/new values).
   - Add merkle proof verification gadgets.
   - Connect state read results to the operation graph.
   - For writes, verify delta merkle proofs.
4. **Process assertions:** For each assertion, add `builder.connect(left, right)`.
5. **Register outputs:** Mark output targets as public inputs.

### 10.2 Witness Generation

At proof time, the prover must supply:
- Contract function input values.
- Merkle proofs for all state reads.
- Delta merkle proofs for all state writes.
- Cross-user merkle proofs (user tree → user state tree → contract state → slot).

These are provided via `UPSCFCStandardStateDeltaInput` which contains:
- `state_read_witnesses`: Merkle proof paths for reads.
- `state_write_witnesses`: Delta merkle proof paths for writes.
- `cross_user_witnesses`: Cross-user state proof paths.

---

## 11. Error Handling

### 11.1 Compile-Time Errors

| Error | Description |
|-------|-------------|
| `UndefinedType` | Reference to unknown type |
| `UndefinedVariable` | Reference to unknown variable |
| `TypeMismatch` | Incompatible types in expression |
| `NonConstantLoopBound` | `for` loop range not compile-time constant |
| `NonFeltSizedField` | Contract/struct field not `FeltSized` |
| `MissingContractMethod` | `#[contract_method]` without `&mut self` or `&mut ChainContext` |
| `InvalidStateAccess` | Writing to read-only state (other user's state) |
| `OverflowInLayout` | State tree would exceed maximum height |
| `DuplicateMethodId` | Two methods produce the same method_id hash |
| `RecursiveType` | Struct contains itself (infinite FELT_SIZE) |

### 11.2 Runtime Assertions (In-Circuit)

| Assertion | Circuit Constraint |
|-----------|-------------------|
| `require(cond, msg)` | `constrain(cond == 1)` |
| `checked_add_no_overflow` | `constrain(result >= operand)` |
| Merkle proof validity | Built-in to state access gadgets |
| Signature validity (UPS) | Built-in to UPS start circuit |

---

## 12. Complete Example: Token Contract Compilation

### 12.1 Source

```rust
const PSY_TOTAL_USERS: usize = 1073741824;

#[derive(FeltSized)]
pub struct TokenMailbox {
    pub total_sent: Felt,
    pub total_received: Felt,
}

#[derive(FeltSized)]
pub struct UserTokenState {
    pub balance: Felt,
    pub padding: [Felt; 3],
}

#[contract]
pub struct ExampleContract {
    pub token_state: UserTokenState,
    pub other_users: ContractStateArray<PSY_TOTAL_USERS, TokenMailbox>,
}

#[derive(FeltSized)]
pub struct TransferTokenParams {
    pub to: Felt,
    pub amount: Felt,
}

#[contract_implementation]
impl ExampleContract {
    fn transfer_helper(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(self.token_state.balance >= amount, "Insufficient balance");
        require(to != ctx.user_id, "cannot transfer to self");
        self.token_state.balance -= amount;
        self.other_users[to].total_sent += amount;
    }

    fn bulk_transfer_helper<const N: usize>(
        &mut self,
        ctx: &mut ChainContext,
        transfers: &[TransferTokenParams; N],
    ) {
        for i in 0..N {
            self.transfer_helper(ctx, transfers[i].to, transfers[i].amount);
        }
    }

    #[contract_method]
    pub fn transfer(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        self.transfer_helper(ctx, to, amount);
    }

    #[contract_method]
    pub fn mint(&mut self, ctx: &mut ChainContext, to: Felt, amount: Felt) {
        require(to != ctx.user_id, "cannot mint to self");
        require(ctx.calling_contract == 1337, "Unauthorized caller");
        self.other_users[to].total_sent += amount;
    }

    #[contract_method]
    pub fn claim(&mut self, ctx: &mut ChainContext, sender: Felt) {
        require(sender != ctx.user_id, "cannot claim from self");
        let previous_claimed = self.other_users[sender].total_received;
        let total_sent_by_sender = ctx.users[sender]
            .contract_state::<Self::ABI>(ctx.contract_id)
            .other_users[ctx.user_id]
            .total_sent;
        require(total_sent_by_sender > previous_claimed, "No new tokens to claim");
        let claimable_amount = total_sent_by_sender - previous_claimed;
        self.token_state.balance += claimable_amount;
        self.other_users[sender].total_received = total_sent_by_sender;
    }

    #[contract_method]
    pub fn transfer_token_3(
        &mut self,
        ctx: &mut ChainContext,
        transfers: [TransferTokenParams; 3],
    ) {
        self.bulk_transfer_helper(ctx, &transfers);
    }
}
```

### 12.2 Compiled State Layout

```
ExampleContract State Layout:
  state_tree_height: 32  (ceil(log2(4 + 1073741824 * 2)) = 32)

  Inline fields:
    token_state.balance:     slot 0  (1 felt)
    token_state.padding[0]:  slot 1  (1 felt)
    token_state.padding[1]:  slot 2  (1 felt)
    token_state.padding[2]:  slot 3  (1 felt)

  Virtual array: other_users
    base_offset: 4
    element_stride: 2 (TokenMailbox::FELT_SIZE)
    count: 1073741824

    other_users[i].total_sent:     slot 4 + i*2 + 0
    other_users[i].total_received: slot 4 + i*2 + 1
```

### 12.3 Compiled `transfer` Method — DPN IR Walkthrough

**Inputs:** `to: Felt` (input 0), `amount: Felt` (input 1)

**Operations (symbolic):**
```
// Read self.token_state.balance
CMD_0: GetSelfUserCurrentContractStateSlotSingle(slot=0)
  → target_0 = state_result_single(CMD_0)

// require(balance >= amount)
bool_0 = Gte(target_0, input_1)          // balance >= amount
ASSERT: bool_0 == true  ("Insufficient balance")

// require(to != ctx.user_id)
target_1 = GetUserId
bool_1 = Eq(input_0, target_1)           // to == user_id
bool_2 = BoolNot(bool_1)                 // to != user_id
ASSERT: bool_2 == true  ("cannot transfer to self")

// self.token_state.balance -= amount
target_2 = Sub(target_0, input_1)        // balance - amount
CMD_1: SetContractStateSlotSingle(slot=0, value=target_2)

// Compute dynamic offset for other_users[to].total_sent
target_3 = Mul(input_0, Constant(2))     // to * stride
target_4 = Add(target_3, Constant(4))    // base_offset + to * stride
// total_sent is at field offset 0 within TokenMailbox, so no additional offset

// Read other_users[to].total_sent
CMD_2: GetSelfUserCurrentContractStateSlotSingle(slot=target_4)
  → target_5 = state_result_single(CMD_2)

// other_users[to].total_sent += amount
target_6 = Add(target_5, input_1)
CMD_3: SetContractStateSlotSingle(slot=target_4, value=target_6)
```

**DPNFunctionCircuitDefinition output:**
```
name: "transfer"
method_id: 0x... (sha256 truncated)
circuit_inputs: [encode(Target, 0), encode(Target, 1)]  // to, amount
circuit_outputs: []
state_commands: [CMD_0, CMD_1, CMD_2, CMD_3]
assertions: [
  { left: encode(Bool, 0), right: encode(Bool, ConstantTrue), msg: "Insufficient balance" },
  { left: encode(Bool, 2), right: encode(Bool, ConstantTrue), msg: "cannot transfer to self" },
]
definitions: [
  // All target/bool/u32 definitions in topological order
  ...
]
```

### 12.4 Compiled `claim` Method — Cross-User Read

The `claim` method demonstrates the most complex access pattern:

```rust
let total_sent_by_sender = ctx.users[sender]
    .contract_state::<Self::ABI>(ctx.contract_id)
    .other_users[ctx.user_id]
    .total_sent;
```

**Compiles to:**
```
// Compute offset in sender's state tree
target_a = GetContractId                 // ctx.contract_id
target_b = GetUserId                     // ctx.user_id
target_c = Mul(target_b, Constant(2))    // user_id * stride(TokenMailbox)
target_d = Add(target_c, Constant(4))    // base + user_id * stride + field_offset(total_sent=0)

// Cross-user state read
CMD_X: GetOtherUserContractStateSlotSingle(
    user_id = input_0,       // sender
    contract_id = target_a,  // ctx.contract_id
    slot = target_d,         // computed offset
)
→ target_e = state_result_single(CMD_X)
```

**Witness requirements for this command:**
1. Merkle proof: global user tree root → sender's `PsyUserLeaf`
2. Merkle proof: sender's `user_state_tree_root` → contract state subtree for `ctx.contract_id`
3. Merkle proof: contract state subtree root → slot at `target_d`

All three proofs are verified in the circuit.

---

## 13. Implementation Task List

### Phase 1: Foundation (Core Types & Parsing)

1. **Create `psy_compiler` crate** with workspace integration.
2. **Define AST types** (`ast.rs`): All node types for the DSL.
3. **Implement lexer** (`lexer.rs`): Tokenize PSY DSL source.
4. **Implement parser** (`parser.rs`): Recursive-descent parser producing AST.
5. **Unit tests for parser**: Parse the example contract and verify AST.

### Phase 2: Type System & Layout

6. **Implement `FeltSized` computation** (`layout.rs`): Compute struct sizes and field offsets.
7. **Implement name resolver** (`resolver.rs`): Resolve all identifiers, build symbol table.
8. **Implement type checker** (`checker.rs`): Validate type constraints.
9. **Implement contract state layout** (`layout.rs`): Compute state tree mappings, `state_tree_height`.
10. **Implement const generic monomorphization** (`monomorphize.rs`): Specialize generic functions.
11. **Unit tests for type system**: Verify layout computation, type errors.

### Phase 3: Lowering to DPN IR

12. **Implement `CompilerContext`** (`context.rs`): Wrapper around `QExecContext` with local variable tracking.
13. **Implement expression lowering** (`expressions.rs`): Translate expressions to `SymFeltRef` operations.
14. **Implement statement lowering** (`statements.rs`): Handle assignments, let bindings, if/for.
15. **Implement state access lowering** (`state_access.rs`): Self-state, cross-user, arrays.
16. **Implement built-in lowering** (`builtins.rs`): `require`, `hash`, `checked_add_no_overflow`.
17. **Implement helper function inlining**: Inline non-`#[contract_method]` functions at call sites.
18. **Integration tests**: Compile example contract methods, verify `QExecContext` state.

### Phase 4: Output & ABI

19. **Implement ABI generation** (`abi/codegen.rs`): Produce `ContractABI` from typed AST.
20. **Implement serialization** (`output/serialize.rs`): Drive `PsyCompileResult::compile()` to produce `DPNFunctionCircuitDefinition`.
21. **Implement contract packaging**: Produce `ContractCodeDefinition` with all methods.
22. **End-to-end tests**: Compile example contract → CBOR → deserialize → verify structure.

### Phase 5: Integration & Verification

23. **Integration with `psy_dpn_circuit`**: Verify compiled output produces valid plonky2 circuits.
24. **Witness generation test**: Generate proofs for the example contract with mock state.
25. **Error message quality**: Ensure all compile errors have source locations and clear messages.
26. **Documentation**: Usage guide, DSL reference, examples.
