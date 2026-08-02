# Design Philosophy

Psy Smart Contract Language embodies a unique design philosophy specifically crafted for zero-knowledge proof systems. While drawing inspiration from modern languages like Jakt, Noir, Sway, and Cairo, Psy takes a fundamentally different approach optimized for circuit generation.

## Core Design Principles

### ZK-Native Architecture

Unlike traditional virtual machines that operate on stacks and registers, Psy compiles to DPN opcodes optimized for zkVM execution. Our primary goal is to generate efficient opcodes that produce minimal circuits during proof generation, which directly translates to:

- **Faster proof generation**
- **Lower computational overhead**
- **Reduced memory requirements**
- **Improved scalability**

### Symbolic Execution Model

At the heart of Psy's design lies **symbolic execution** rather than traditional runtime execution:

```rust
// Traditional VM approach - Simple addition
// Requires multiple stack/register operations
fn add_numbers(a: Felt, b: Felt) -> Felt {
    a + b
}
// VM execution steps:
// 1. PUSH a               (push 'a' onto stack)
// 2. PUSH b               (push 'b' onto stack)  
// 3. POP R2               (pop 'b' into register R2)
// 4. POP R1               (pop 'a' into register R1)
// 5. ADD R3, R1, R2       (add R1 + R2, store in R3)
// 6. PUSH R3              (push result back to stack)
// 7. POP result           (pop final result)
// Total: 7 VM operations + stack/register management overhead

// Psy's symbolic execution approach  
// Converts directly to a single ZK constraint
fn add_numbers(a: Felt, b: Felt) -> Felt {
    a + b  // Single arithmetic gate: result = a + b
}
// Circuit: 1 addition constraint, no VM overhead
```

### Function-to-Symbol Transformation

Every function in a Psy smart contract is transformed into a mathematical symbol or constraint system:

1. **Variables** become circuit wires
2. **Operations** become arithmetic gates  
3. **Control flow** is flattened into conditional execution using boolean arithmetic
4. **State changes** become constraint updates on state variables

#### Control Flow Flattening Example

```rust
// Psy source code with branching
fn min(a: Felt, b: Felt) -> Felt {
    if a < b {
        a
    } else {
        b
    }
}

// Compiler flattens to conditional arithmetic (no dynamic jumps)
// Both paths computed, result selected using boolean arithmetic:
fn min_flattened(a: Felt, b: Felt) -> Felt {
    let condition = (a < b) as Felt;  // 1 if true, 0 if false
    let true_path = a;
    let false_path = b;
    // Arithmetic selection instead of branching:
    condition * true_path + (1 - condition) * false_path
}
```

This transforms `if (a > 1) { execute_branch() }` into:
```
condition = (a > 1) as Felt;  // 0 or 1
execution_weight = condition;
no_execution_weight = 1 - condition;
// Both branches computed, weighted by condition
```

## Architectural Differences from Traditional Languages

### Control Flow Flattening

Traditional programming languages use dynamic control flow with jumps and branches. Psy **flattens all control structures** at compile time:

#### If-Else Flattening
```rust
// Source code
fn conditional_logic(condition: bool, a: Felt, b: Felt) -> Felt {
    if condition {
        a + b
    } else {
        a * b
    }
}

// Flattened to circuit constraints
fn conditional_logic(condition: bool, a: Felt, b: Felt) -> Felt {
    let condition_felt = condition as Felt;
    let sum = a + b;
    let product = a * b;
    // Select result based on condition using arithmetic
    sum * condition_felt + product * (1 - condition_felt)
}
```

#### Loop Unrolling
```rust
// Source code with bounded loop (simplified fibonacci)
fn fibonacci_partial() -> Felt {
    let mut a: Felt = 2;
    let mut b: Felt = 3;
    let mut i: Felt = 2;
    while i <= 5 {  // Fixed bound of 3 iterations
        let next = a + b;
        a = b;
        b = next;
        i += 1;
    }
    b
}

// Completely unrolled at compile time (3 iterations)
fn fibonacci_partial_unrolled() -> Felt {
    // Initial state
    let mut a_0: Felt = 2;
    let mut b_0: Felt = 3;
    let mut i_0: Felt = 2;
    
    // Iteration 1: i = 2, condition (2 <= 5) = true
    let next_1 = a_0 + b_0;  // 5
    let a_1 = b_0;           // 3
    let b_1 = next_1;        // 5
    let i_1 = i_0 + 1;       // 3
    
    // Iteration 2: i = 3, condition (3 <= 5) = true  
    let next_2 = a_1 + b_1;  // 8
    let a_2 = b_1;           // 5
    let b_2 = next_2;        // 8
    let i_2 = i_1 + 1;       // 4
    
    // Iteration 3: i = 4, condition (4 <= 5) = true
    let next_3 = a_2 + b_2;  // 13
    let a_3 = b_2;           // 8  
    let b_3 = next_3;        // 13
    let i_3 = i_2 + 1;       // 5
    
    // Iteration 4: i = 5, condition (5 <= 5) = true
    let next_4 = a_3 + b_3;  // 21
    let a_4 = b_3;           // 13
    let b_4 = next_4;        // 21
    let i_4 = i_3 + 1;       // 6
    
    // Iteration 5: i = 6, condition (6 <= 5) = false - exit
    b_4  // Return 21
}
```

### No Runtime Stack or Registers

Traditional VMs maintain:
- **Call stack** for function invocation
- **Registers** for temporary values
- **Memory management** with allocation/deallocation

Psy optimizes this by:
- **Static analysis** of all possible execution paths
- **Compile-time memory layout** determination
- **Compilation to DPN opcodes** which are executed by zkVM to generate contract call proofs

### Inline Function Calls by Default

Unlike traditional VMs that use call stacks, **Psy inlines all function calls by default**. Each function is compiled to its own set of DPN opcodes:

```rust
// Source code with nested function calls (from actual test)
fn add(a: Felt, b: Felt) -> Felt {
    let mut c: Felt = a + b;
    return c;
}

fn mul(a: Felt, b: Felt) -> Felt {
    let mut c: Felt = a * b;
    return c;
}

fn main() {
    // Complex nested function calls
    let mut f: Felt = add(add(1, 2), 2);        // add() called twice, nested
    let mut g: Felt = add(1 + 3, mul(2, 3));    // add() and mul() calls
}

// Each function generates its own DPN opcode sequence:
// add() -> [Constant(a), Constant(b), Add, InputTarget] opcodes
// mul() -> [Constant(x), Constant(y), Mul, InputTarget] opcodes  

// At compilation, all calls are inlined:
fn main_inlined() {
    // add(add(1, 2), 2) becomes completely flattened:
    // Inner add(1, 2):
    // - Constant(1), Constant(2), Add -> temp1 = 3
    // Outer add(temp1, 2): 
    // - Constant(3), Constant(2), Add -> f = 5
    
    // add(1 + 3, mul(2, 3)) becomes:
    // mul(2, 3):
    // - Constant(2), Constant(3), Mul -> temp2 = 6
    // add(4, temp2):
    // - Constant(4), Constant(6), Add -> g = 10
}
```

**Benefits of Default Inlining:**
- **No call overhead** - eliminates stack push/pop operations
- **Better optimization** - enables cross-function optimizations
- **Predictable circuit size** - function calls don't add dynamic overhead
- **Simplified analysis** - all execution paths are statically visible

## Circuit-First Design Benefits

### Predictable Circuit Size

Since all control flow is flattened at compile time, developers can predict exact circuit sizes:

```rust
// Circuit size is deterministic
fn deterministic_function(x: Felt, y: Felt) -> Felt {
    // Always exactly 3 arithmetic gates
    let intermediate = x + y;      // 1 gate
    let result = intermediate * 2;  // 1 gate  
    result + 1                     // 1 gate
}
```

### Optimized Constraint Systems

The compiler can perform aggressive optimizations specific to arithmetic circuits:

- **Gate merging** - Combine multiple operations
- **Constant propagation** - Eliminate unnecessary constraints
- **Dead code elimination** - Remove unused circuit paths
- **Algebraic simplification** - Reduce constraint complexity

### Zero-Knowledge Friendly Primitives

Psy provides built-in primitives that map directly to efficient ZK operations:

```rust
// Poseidon hash - ZK-friendly cryptographic hash
fn hash_example() -> Hash {
    let data: Hash = [1, 2, 3, 4];
    hash(data)  // Built-in Poseidon hash function
}

// ECDSA signature verification using secp256k1
fn signature_verification() -> bool {
    let pub_key = [4203227662u32, 540940946u32, 962567723u32, 1830567167u32, 
                   3450763808u32, 3950740017u32, 3026903052u32, 3029228469u32, 
                   1837759160u32, 825683440u32, 3630293783u32, 436568768u32, 
                   3543321651u32, 1044682747u32, 168350425u32, 936127172u32];
    
    let sig = [201339544u32, 2533129003u32, 3911198242u32, 2163032835u32, 
               2488559593u32, 2971164201u32, 3572923983u32, 3650316646u32, 
               3964687905u32, 1624041662u32, 2373224611u32, 3243422930u32, 
               1353934640u32, 2321957132u32, 2691932396u32, 1560388502u32];
    
    let msg = [6716978020874491267, 18326158388222717469, 
               7113070761591959818, 9714795267687279217];
    
    let signature_is_valid = __secp256k1_verify(pub_key, msg, sig);
    assert(signature_is_valid, "signature is not valid");
    signature_is_valid
}

// Example: Combining both primitives for authenticated operations
fn authenticated_hash(input_data: Hash, pub_key: [u32; 16], msg: [u64; 4], sig: [u32; 16]) -> Hash {
    // Verify signature first
    let signature_is_valid = __secp256k1_verify(pub_key, msg, sig);
    assert(signature_is_valid, "Invalid signature");
    
    // Then hash the authenticated data
    hash(input_data)
}
```

## Language Design Trade-offs

### What We Gain
- **Minimal circuit overhead**
- **Predictable performance**
- **Formal verification friendly**
- **Optimal proof generation**

### What We Accept
- **Static loop bounds** (no dynamic iteration)
- **Compile-time complexity** for circuit optimization
- **Limited recursion** (must be bounded and unrollable)
- **Circuit-aware programming model**

## Language Syntax Design

Psy adopts a **Rust-like syntax** that provides familiarity for developers while being optimized for ZK circuit compilation:

```rust
// Familiar Rust-style struct definitions
pub struct Person {
    pub age: Felt,
    male: bool,
}

// Rust-style implementations
impl Person {
    pub fn get_age(self: Person) -> Felt {
        return self.age;
    }
}

// Rust-style function definitions with type annotations
fn add_numbers(a: Felt, b: Felt) -> Felt {
    a + b
}

// Rust-style control flow
fn conditional_min(a: Felt, b: Felt) -> Felt {
    if a < b {
        a
    } else {
        b
    }
}
```

This familiar syntax reduces the learning curve while the compiler performs ZK-specific optimizations behind the scenes.

## The Psy Innovation

Psy's unique contribution is **ZK-optimized compilation** through symbolic execution. By treating smart contract functions as mathematical transformations and compiling to DPN opcodes, we achieve:

1. **Optimized DPN opcode generation** for zkVM execution
2. **Efficient proof generation** for contract calls
3. **Predictable circuit characteristics** 
4. **Streamlined ZK proving pipeline**

This design philosophy makes Psy particularly suitable for applications where proof generation speed and circuit size are critical, such as high-frequency DeFi operations, privacy-preserving computations, and scalable rollup systems.

## Looking Forward

As the ZK ecosystem evolves, Psy's circuit-first design positions it to take advantage of new developments in:
- **Advanced circuit optimizations**
- **Hardware acceleration**
- **Recursive proof systems**
- **Cross-chain interoperability**

The symbolic execution model ensures that improvements in the underlying proof systems automatically benefit all Psy programs without requiring language-level changes.