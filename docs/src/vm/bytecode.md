# Virtual Machine Bytecode Operations

The Psy VM uses a Data Processing Network (DPN) architecture that compiles high-level Psy language constructs into a series of low-level operations. The bytecode forms a tree-like dependency structure where inputs serve as unknown variables that get assigned values during execution, enabling computation of the entire tree to produce outputs.

## Bytecode Architecture Overview

The VM operates on a constraint-based system where each operation generates mathematical constraints that can be verified in zero-knowledge. Operations are encoded as `DPNOpType` enums with associated input parameters and output specifications.

## Tree-Based Execution Model

The bytecode represents a computational tree structure:

- **Inputs**: Tree leaves containing unknown variables (function parameters, storage values)
- **Operations**: Tree nodes that compute values based on their children
- **Outputs**: Tree root values representing function results
- **Execution**: Assigning concrete values to inputs propagates through the tree to compute all intermediate and output values

During execution, once input variables receive concrete values, the entire dependency tree can be evaluated bottom-up to produce the final outputs. This tree structure perfectly matches zero-knowledge proof systems, where each operation becomes a constraint and each variable becomes a wire in the circuit.

### Data Types

All VM operations work with these fundamental data types:

- **Target** (`Felt`): Field elements in the Goldilocks field (p = 18446744069414584321)
- **Bool**: Boolean values (0 or 1)
- **U32Target**: 32-bit unsigned integers
- **HashOut**: 4-element field arrays representing hash outputs
- **Arrays**: Collections of the above types

## Operation Categories

### 1. Arithmetic and Mathematical Operations

These operations perform basic arithmetic and mathematical computations on field elements.

#### Basic Arithmetic
```
Add = 4          // a + b
Sub = 5          // a - b  
Mul = 6          // a * b
Div = 7          // a / b (modular inverse in finite field)
```

#### Advanced Arithmetic
```
Exp = 24                 // a^b
ExpConstantPower = 25    // a^const
ExpConstantBase = 26     // const^b
Mod = 27                 // a % b
ModConstantDividend = 28 // const % b
ModConstantDivisor = 29  // a % const
DivRem4 = 30            // Division with 4-element remainder
```

#### Unary Operations
```
UnaryInverse = 64    // Modular inverse of a
UnaryNegative = 65   // -a in field arithmetic
```


### 2. Boolean Logic Operations

Operations for boolean logic and conditional expressions.

#### Basic Boolean Operations
```
BoolNot = 8      // !a
BoolAnd = 9      // a && b
BoolOr = 10      // a || b
```

#### Bitwise Operations
```
Xor = 11         // a XOR b (bitwise)
Nor = 12         // !(a || b)
```

#### Comparison Operations
```
Eq = 13          // a == b
Lte = 14         // a <= b
Gte = 15         // a >= b
Gt = 16          // a > b
Lt = 17          // a < b
```


### 3. U32 Integer Operations

Specialized operations for 32-bit unsigned integer arithmetic.

#### U32 Arithmetic
```
U32Add = 68      // 32-bit addition
U32Sub = 69      // 32-bit subtraction  
U32Mul = 70      // 32-bit multiplication
U32Div = 71      // 32-bit division
U32Mod = 75      // 32-bit modulo
U32Exp = 76      // 32-bit exponentiation
```

#### U32 Bitwise Operations
```
U32And = 32              // a & b
U32AndConstant = 33      // a & const
U32Or = 34               // a | b
U32OrConstant = 35       // a | const
U32Xor = 36              // a ^ b
U32XorConstant = 37      // a ^ const
```

#### U32 Shift Operations
```
U32ShiftLeft = 38                           // a << b
U32ShiftLeftConstantBitDistance = 40        // a << const
U32ShiftLeftConstantValue = 41              // const << b
U32ShiftRight = 42                          // a >> b
U32ShiftRightConstantBitDistance = 43       // a >> const
U32ShiftRightConstantValue = 44             // const >> b
```


### 4. Type Conversion Operations

Operations for converting between different data types.

```
CastU32 = 31     // Convert Felt to u32
CastFelt = 72    // Convert u32 to Felt
CastBool = 73    // Convert to boolean
```


### 5. Cryptographic Operations

Operations for cryptographic functions and hashing.

#### Hash Operations
```
HashNoPad = 21           // Hash without padding
HashPad = 22             // Hash with padding
HashTwoToOne = 78        // Merge two hashes into one
CalculateMerkleRoot = 45 // Calculate Merkle tree root
```

#### Digital Signature Verification
```
Secp256k1Verify = 77     // Verify secp256k1 signature
```


### 6. Blockchain State Access Operations

Operations for reading blockchain and transaction context information.

#### User and Contract Context
```
GetUserId = 46               // Current user's ID
GetContractId = 47           // Current contract ID
GetCallerContractId = 79     // Calling contract's ID
GetCheckpointId = 48         // Current checkpoint/block height
GetNonce = 49                // Current user's nonce
GetUserPublicKeyHash = 50    // User's public key hash
```

#### State Query Operations
```
GetStateQueryResult = 51           // Query blockchain state (hash result)
GetStateQueryResultSingle = 52     // Query single value from state
GetStateCommandResultHash = 53     // Get state command result as hash
GetStateCommandResultSingle = 54   // Get state command result as single value
GetStateCommandResultArray = 55    // Get state command result as array
```


### 7. Contract Storage Access Operations

State commands for reading and writing contract storage across the user tree hierarchy.

#### Current Contract Storage (Self)
```
GetSelfUserCurrentContractStateSlotHash    // Read hash from current contract slot
GetSelfUserCurrentContractStateSlotSingle  // Read single value from current contract
GetSelfUserCurrentContractStateSlotRange   // Read range of values from current contract
```

#### External Contract Storage (Same User)
```
GetSelfUserExternalContractStateSlotHash   // Read hash from other contract (same user)
GetSelfUserExternalContractStateSlotSingle // Read single value from other contract (same user)
GetSelfUserExternalContractStateSlotRange  // Read range from other contract (same user)
```

#### Cross-User Storage Access
```
GetOtherUserContractStateSlotHash    // Read hash from other user's contract
GetOtherUserContractStateSlotSingle  // Read single value from other user's contract  
GetOtherUserContractStateSlotRange   // Read range from other user's contract
```

#### Storage Write Operations
```
SetContractStateSlotHash     // Write 4-element hash to storage slot
SetContractStateSlotSingle   // Write single value to storage sub-slot
SetContractStateSlotRange    // Write array of values to storage range
ClearEntireTree             // Clear all storage for current user/contract
```


### 8. Contract Interaction Operations

Operations for invoking other contracts and managing execution flow.

```
InvokeExternalContractFunctionSync     // Synchronous contract call
InvokeExternalContractFunctionDeferred // Asynchronous contract call
```


### 9. Control Flow and Selection Operations

Operations for conditional execution and data selection.

```
Select = 23          // Conditional selection: condition ? a : b
SplitBits = 18       // Split value into bit array
SumBits = 19         // Sum bits back into value
TargetAt = 20        // Access element at index
```


### 10. Input/Output and Constants

Operations for handling program inputs and constant values.

```
InputTarget = 0      // Function input parameter (Felt)
U32InputTarget = 66  // Function input parameter (u32)
BoolInputTarget = 74 // Function input parameter (bool)
Constant = 1         // Constant Felt value
ConstantU32 = 67     // Constant u32 value  
ConstantTrue = 2     // Boolean true constant
ConstantFalse = 3    // Boolean false constant
```


### 11. Assertion Operations

Operations for runtime validation and constraint enforcement.

Assertions are not represented as DPNOpType enums but as separate `DPNAssertEqInfoIndexed` structures that enforce equality constraints during circuit execution.

```rust
// Assertion structure
pub struct DPNAssertEqInfoIndexed {
    pub left: u64,     // Left operand (variable reference)
    pub right: u64,    // Right operand (variable reference)  
    pub message: String, // Error message for failed assertion
}
```

Assertions validate that two computed values are equal, with descriptive error messages for debugging failed proofs.

### 12. Blockchain Information Access

Operations for accessing blockchain-wide information and metadata.

```
GetCheckpointLeafStats  // Get checkpoint/block statistics
GetContractLeaf         // Get contract metadata from global tree
```


## Operation Properties

Each operation has several important properties:

### Data Type Constraints
Operations specify their output data type through `get_data_type()`:
- Arithmetic ops return `Target` (Felt)
- Comparison ops return `Bool`
- U32 ops return `U32Target`
- Hash ops return `HashOut`


### Storage Access Patterns

The VM enforces the "read others, write self" security model:

1. **Read Operations**: Can access any user's storage in read-only mode
2. **Write Operations**: Can only modify current user's storage
3. **Cross-Contract**: Can read from any contract, write only to current contract
4. **Storage Slots**: Each contract has 2^32 available slots, each storing a Hash (4 Felts)

## Function-Specific Compilation

Psy opcodes are generated for each individual function during compilation. Each function compiles to a `DPNFunctionCircuitDefinition` that contains all necessary information to generate and execute the corresponding zero-knowledge circuit.

### DPNFunctionCircuitDefinition Structure

```rust
pub struct DPNFunctionCircuitDefinition {
    pub name: String,                                    // Function name
    pub method_id: u32,                                  // Unique method identifier
    pub circuit_inputs: Vec<u64>,                        // Input variable references
    pub circuit_outputs: Vec<u64>,                       // Output variable references
    pub state_commands: Vec<DPNStateCmd<u64>>,           // Storage/blockchain operations
    pub state_command_resolution_indices: Vec<usize>,    // Mapping to operation results
    pub assertions: Vec<DPNAssertEqInfoIndexed>,         // Runtime validation constraints
    pub definitions: Vec<DPNIndexedVarDef>,              // All operation definitions
    pub events: Vec<DPNEventRecord>,                     // Event emissions
}
```

#### Field Explanations

**`name: String`**
- Human-readable function name for debugging and identification
- Example: `"simple_mint"`, `"transfer"`, `"main"`

**`method_id: u32`**  
- Unique identifier for the function within the contract
- Used for contract method dispatch and cross-contract calls
- Generated deterministically from function signature

**`circuit_inputs: Vec<u64>`**
- References to input parameters in the operation definitions
- Maps to function parameters in order: `fn transfer(from: Felt, to: Felt, amount: Felt)`
- Each u64 is an encoded reference to a `DPNIndexedVarDef` entry

**`circuit_outputs: Vec<u64>`**
- References to values returned by the function
- For void functions, this is empty
- For functions with return values, contains references to final computed results

**`state_commands: Vec<DPNStateCmd<u64>>`**
- All storage read/write operations and blockchain state access
- Includes operations like `GetSelfUserCurrentContractStateSlotSingle`, `SetContractStateSlotHash`
- Each command represents interaction with the global state tree

**`state_command_resolution_indices: Vec<usize>`**
- Maps state command results to variable definitions
- When a state command executes, its result is stored at the specified index
- Enables referencing storage read results in subsequent operations

**`assertions: Vec<DPNAssertEqInfoIndexed>`**
- All `assert` and `assert_eq` statements from the source code
- Enforces runtime constraints that must be satisfied for proof validity
- Contains error messages for debugging failed assertions

**`definitions: Vec<DPNIndexedVarDef>`**
- Complete list of all operations (opcodes) in execution order
- Each entry represents one computation step
- Forms a dependency graph where later operations can reference earlier results
- See detailed explanation in the DPNIndexedVarDef section below

**`events: Vec<DPNEventRecord>`**
- Event emissions from the function execution
- Contains checkpoint_id, user_id, contract_id, and event data
- Used for off-chain indexing and monitoring

### Compilation Process

High-level Psy code goes through this compilation process:

1. **Parse**: Psy syntax → AST
2. **Semantic Analysis**: Type checking, visibility rules  
3. **DPN Generation**: AST → DPNFunctionCircuitDefinition per function
4. **Operation Encoding**: Function body → DPNIndexedVarDef operations
5. **State Command Extraction**: Storage/blockchain access → DPNStateCmd
6. **Constraint Generation**: Operations → Mathematical constraints
7. **Circuit Building**: Constraints → Plonky2 circuits
8. **Proof Generation**: Circuit execution → Zero-knowledge proofs

### Example Compilation

```psy
impl TokenContractRef {
    pub fn mint(amount: Felt) {
        let contract = TokenContractRef::new(ContractMetadata::current());
        let current_supply = contract.total_supply.get();
        assert(current_supply + amount > current_supply, "overflow");
        contract.total_supply.set(current_supply + amount);
    }
}
```

This compiles to a `DPNFunctionCircuitDefinition` containing:
- **name**: `"mint"`
- **method_id**: Hash of method signature
- **circuit_inputs**: `[amount_var_ref]`
- **circuit_outputs**: `[]` (void function)
- **state_commands**: `[GetSelfUserCurrentContractStateSlotSingle, SetContractStateSlotSingle]`
- **assertions**: `[DPNAssertEqInfoIndexed{left: overflow_check, right: true, message: "overflow"}]`
- **definitions**: All intermediate operations (TokenContractRef::new, get, add, comparison, set)

## DPNIndexedVarDef: Operation Encoding and Symbol Evaluation

The core of the VM's execution model is the `DPNIndexedVarDef` structure, which represents individual operations in a unified array format that enables efficient symbolic evaluation.

### Structure Definition

```rust
pub struct DPNIndexedVarDef {
    pub data_type: DPNBuiltInDataType,  // Output data type
    pub index: usize,                   // Position in definitions array
    pub op_type: DPNOpType,            // Operation to perform
    pub inputs: Vec<u64>,              // References to input operands
}
```

### Unified Array Storage Model

All operations within a function are stored in a single `Vec<DPNIndexedVarDef>` where:

1. **Sequential Indexing**: Each operation gets a unique index (0, 1, 2, ...)
2. **Dependency References**: Later operations reference earlier ones by index
3. **Symbolic Evaluation**: Operations form a directed acyclic graph (DAG)
4. **Memory Efficiency**: Shared intermediate results avoid recomputation

### Input Reference Encoding

The `inputs: Vec<u64>` field contains encoded references to operands:

```rust
// Encoding format: (data_type << 32) | index
pub fn encode_indexed_op_id(data_type: DPNBuiltInDataType, index: usize) -> u64 {
    ((data_type as u64) << 32) | (index as u64)
}

pub fn decode_indexed_op_id(id: u64) -> (DPNBuiltInDataType, usize) {
    (DPNBuiltInDataType::from(id >> 32), (id & 0xFFFFFFFF) as usize)
}
```

### Symbolic Evaluation Process

The VM evaluates operations in dependency order:

1. **Topological Sort**: Ensure dependencies are computed before dependent operations
2. **Lazy Evaluation**: Only compute values when needed
3. **Memoization**: Cache results to avoid duplicate computation
4. **Type Safety**: Ensure type consistency across operations

### Example: Simple Addition

```psy
let x = 5;
let y = 10;
let result = x + y;
```

Compiles to these `DPNIndexedVarDef` entries (note: in practice, constant folding optimization would evaluate this at compile time to a single constant `15`):

```rust
[
    // Index 0: Constant x = 5
    DPNIndexedVarDef {
        data_type: Target,
        index: 0,
        op_type: Constant,
        inputs: vec![5], // Constant value embedded
    },
    
    // Index 1: Constant y = 10  
    DPNIndexedVarDef {
        data_type: Target,
        index: 1,
        op_type: Constant,
        inputs: vec![10], // Constant value embedded
    },
    
    // Index 2: result = x + y
    DPNIndexedVarDef {
        data_type: Target,
        index: 2,
        op_type: Add,
        inputs: vec![
            encode_indexed_op_id(Target, 0), // Reference to x (index 0)
            encode_indexed_op_id(Target, 1), // Reference to y (index 1)
        ],
    },
]
```

### Complex Expression Example

```psy
let a = 3;
let b = 4;
let c = 5;
let result = (a + b) * c;
```

Compiles to:

```rust
[
    // Index 0: a = 3
    DPNIndexedVarDef { data_type: Target, index: 0, op_type: Constant, inputs: vec![3] },
    
    // Index 1: b = 4
    DPNIndexedVarDef { data_type: Target, index: 1, op_type: Constant, inputs: vec![4] },
    
    // Index 2: c = 5
    DPNIndexedVarDef { data_type: Target, index: 2, op_type: Constant, inputs: vec![5] },
    
    // Index 3: temp = a + b
    DPNIndexedVarDef { 
        data_type: Target, 
        index: 3, 
        op_type: Add, 
        inputs: vec![encode_indexed_op_id(Target, 0), encode_indexed_op_id(Target, 1)]
    },
    
    // Index 4: result = temp * c
    DPNIndexedVarDef { 
        data_type: Target, 
        index: 4, 
        op_type: Mul, 
        inputs: vec![encode_indexed_op_id(Target, 3), encode_indexed_op_id(Target, 2)]
    },
]
```

### Storage Operation Integration

Storage operations create dependencies between computational operations and state access:

```psy
let current_balance = contract.balance.get();  // State read
let new_balance = current_balance + amount;    // Computation  
contract.balance.set(new_balance);            // State write
```

Results in:

```rust
[
    // Index 0: amount parameter
    DPNIndexedVarDef { data_type: Target, index: 0, op_type: InputTarget, inputs: vec![] },
    
    // Index 1: Read current balance (state command result reference)
    DPNIndexedVarDef { 
        data_type: Target, 
        index: 1, 
        op_type: GetStateCommandResultSingle, 
        inputs: vec![0] // References state_commands[0]
    },
    
    // Index 2: new_balance = current_balance + amount
    DPNIndexedVarDef { 
        data_type: Target, 
        index: 2, 
        op_type: Add, 
        inputs: vec![
            encode_indexed_op_id(Target, 1), // current_balance
            encode_indexed_op_id(Target, 0), // amount
        ]
    },
    
    // State write handled separately in state_commands array
]
```

### Advantages of This Model

1. **Memory Efficiency**: Single array reduces memory fragmentation
2. **Cache Locality**: Sequential access patterns improve performance  
3. **Dependency Tracking**: Clear parent-child relationships
4. **Debugging**: Easy to trace execution and identify bottlenecks
5. **Optimization**: Compiler can perform dead code elimination and common subexpression elimination
6. **Proof Generation**: Direct mapping to constraint systems

### Type Safety and Validation

Each `DPNIndexedVarDef` includes its output data type:

```rust
pub enum DPNBuiltInDataType {
    Target = 0,        // Field element (Felt)
    Bool = 1,          // Boolean
    U32Target = 2,     // 32-bit integer
    HashOut = 3,       // 4-element hash
    TargetArray = 5,   // Array of field elements
    BoolArray = 6,     // Array of booleans
    U32TargetArray = 7,// Array of 32-bit integers
}
```

The VM enforces type consistency:
- Input types must match operation requirements
- Output types are determined by operation semantics
- Type mismatches cause compilation errors

This indexed variable definition system forms the foundation of Psy's symbolic execution model, enabling efficient zero-knowledge proof generation while maintaining clear semantics and strong type safety.


## Performance Considerations

### Operation Costs
- **Field arithmetic**: Most efficient (native to ZK circuits)
- **U32 operations**: Require range checks (higher cost)
- **Hash operations**: Expensive but necessary for storage
- **State access**: Variable cost based on tree depth
- **Contract calls**: Most expensive due to recursive proving

### Optimization Strategies
- **Constant folding**: Evaluate constant expressions at compile time
- **Operation fusion**: Combine multiple ops when possible
- **Storage batching**: Group storage operations to reduce tree traversals
- **Selective operations**: Use specialized constant variants when applicable

## Summary

The Psy VM bytecode provides a comprehensive instruction set that:

- **Arithmetic**: Full support for field and integer arithmetic
- **Logic**: Boolean operations and comparisons
- **Cryptography**: Hashing and signature verification
- **State Management**: Hierarchical storage with security guarantees
- **Blockchain Integration**: Access to user, contract, and network context
- **Performance**: Optimized for zero-knowledge proof generation

This bytecode abstraction allows high-level Psy contracts to compile down to efficient zero-knowledge circuits while maintaining the security properties required for decentralized applications.
