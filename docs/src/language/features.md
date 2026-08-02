# Language Features

Psy Smart Contract Language provides a comprehensive set of features designed for zero-knowledge circuit development. This page outlines all major language features with examples and explanations.

## Basic Types

Psy supports a range of primitive and composite types optimized for ZK circuit generation.

### Primitive Types

#### Felt
The fundamental numeric type representing a field element in the Goldilocks field.

```rust
let value: Felt = 42;
let negative: Felt = -10;
let arithmetic: Felt = value + negative * 2;
```

#### Boolean
Boolean values for logical operations.

```rust
let flag: bool = true;
let condition: bool = false;
let result: bool = flag && !condition;
```

#### u32
32-bit unsigned integer type for efficient arithmetic operations.

```rust
let count: u32 = 100u32;
let mask: u32 = 0xFFFFu32;
let shifted: u32 = count << 2;
```

### Composite Types

#### Arrays
Fixed-size arrays with compile-time known lengths.

```rust
let numbers: [Felt; 4] = [1, 2, 3, 4];
let matrix: [[Felt; 2]; 2] = [[1, 2], [3, 4]];
let element: Felt = numbers[0];
```

#### Tuples
Heterogeneous collections of values with full support for nesting, mutation, and complex access patterns.

```rust
// Basic tuple creation and access
let pair: (Felt, bool) = (42, true);
let triple: (Felt, Felt, bool) = (1, 2, false);
let first: Felt = pair.0;
let flag: bool = pair.1;

// Mutable tuples
let mut coordinates: (Felt, Felt) = (10, 20);
coordinates.0 = 15;  // Modify x coordinate
coordinates.1 = 25;  // Modify y coordinate
coordinates = (30, 40);  // Replace entire tuple

// Nested tuples
let nested: ((Felt, Felt), (Felt, Felt)) = ((1, 2), (3, 4));
let deeply_nested: (((Felt, Felt), Felt), Felt) = (((5, 6), 7), 8);

// Complex nested tuple manipulation
let mut complex_tuple: ((Felt, Felt), (Felt, Felt)) = ((9, 10), (11, 12));
complex_tuple.0.1 = 42;     // Modify first tuple's second element
complex_tuple.1 = (20, 21); // Replace entire second tuple

// Tuples in structs
struct TupleHolder {
    pub pair: (Felt, Felt),
    pub nested: ((Felt, Felt), Felt),
}

let mut holder: TupleHolder = new TupleHolder {
    pair: (22, 23),
    nested: ((24, 25), 26),
};
holder.pair.1 = 99;          // Modify tuple field in struct
holder.nested.0.0 = 88;      // Modify nested tuple in struct

// Functions returning tuples
fn create_tuple(x: Felt, y: Felt) -> (Felt, Felt) {
    (x + 1, y + 1)
}

// Functions taking tuples as parameters
fn sum_tuple(input: (Felt, Felt)) -> Felt {
    input.0 + input.1
}

let result_tuple: (Felt, Felt) = create_tuple(30, 31);
let sum_result: Felt = sum_tuple((40, 50));

// Tuples with different types
let mixed: (Felt, bool, u32) = (100, true, 42u32);
let complex_mixed: ((Felt, bool), (u32, Felt)) = ((1, false), (10u32, 2));
```

**Tuple Features:**
- **Type Safety**: Each tuple element has a specific type
- **Indexed Access**: Use `.0`, `.1`, `.2`, etc. to access elements
- **Mutation Support**: Both individual elements and entire tuples can be modified
- **Arbitrary Nesting**: Tuples can contain other tuples to any depth
- **Function Integration**: Can be passed to and returned from functions
- **Struct Fields**: Tuples can be used as struct field types

**Note**: Tuple destructuring (pattern matching like `let (x, y) = tuple`) is not currently supported, but individual element access provides full functionality.

#### Structs
User-defined composite types with named fields.

```rust
pub struct Person {
    pub age: Felt,
    male: bool,
}

let person: Person = new Person {
    age: 25,
    male: true,
};
```

#### Hash Type
Special 4-element array type for cryptographic operations.

```rust
let data: Hash = [1, 2, 3, 4];
let result: Hash = hash(data);
```

## Functions

Functions are first-class citizens with support for parameters, return types, and inlining.

### Basic Functions

```rust
fn add(a: Felt, b: Felt) -> Felt {
    a + b
}

fn greet() {
    // No return value
}
```

### Function Calls and Inlining

All function calls are **inlined by default** for optimal circuit generation.

```rust
fn multiply(x: Felt, y: Felt) -> Felt {
    x * y
}

fn complex_calculation(a: Felt, b: Felt, c: Felt) -> Felt {
    // These calls get inlined at compile time
    let product = multiply(a, b);
    add(product, c)
}
```

## Closures

Anonymous functions that can capture variables from their environment.

```rust
fn main() -> Felt {
    let multiplier: Felt = 3;
    
    let triple = |x: Felt| -> Felt {
        x * multiplier  // Captures 'multiplier' from environment
    };
    
    triple(5)  // Returns 15
}
```

## Constants

Compile-time constant values for improved optimization.

```rust
const MAX_USERS: Felt = 1000;
const PI_APPROXIMATION: Felt = 3141;
const DEFAULT_AMOUNT: Felt = 100;

fn validate_user_count(count: Felt) -> bool {
    count <= MAX_USERS
}

fn calculate_with_constant() -> Felt {
    DEFAULT_AMOUNT + PI_APPROXIMATION
}
```

## Comptime

Compile-time evaluation for constant folding and optimization.

```rust
// Complex constant expressions are evaluated at compile time
const COMPLEX_CALC: Felt = ((100 + 200) * 3 - 50) / 2 + (10 * 10);

fn use_constants() -> Felt {
    // All constant arithmetic is folded during compilation
    COMPLEX_CALC + 42
}
```

## Control Flow

### If Expressions

Conditional expressions that are flattened into arithmetic selection during compilation.

```rust
fn min(a: Felt, b: Felt) -> Felt {
    if a < b {
        a
    } else {
        b
    }
}

// Supports complex nested conditions
fn classify_number(x: Felt) -> Felt {
    if x > 100 {
        if x > 1000 {
            3  // Very large
        } else {
            2  // Large
        }
    } else {
        1  // Small
    }
}
```

### Block Expressions

Scoped code blocks that return values.

```rust
fn calculate() -> Felt {
    let result = {
        let temp1 = 10;
        let temp2 = 20;
        temp1 + temp2  // Block returns this value
    };
    result * 2
}
```

### Match Expressions

Pattern matching for control flow.

```rust
fn process_status(status: Felt) -> Felt {
    match status {
        0 => 10,        // Pending
        1 => 20,        // Processing  
        2 => 30,        // Complete
        _ => 0,         // Unknown
    }
}
```

### Loops

Bounded loops that are completely unrolled at compile time.

```rust
fn sum_range() -> Felt {
    let mut total: Felt = 0;
    let mut i: Felt = 1;
    
    while i <= 5 {  // Fixed bound - unrolled at compile time
        total += i;
        i += 1;
    }
    
    total  // Returns 15
}
```

## Modules

Code organization and namespace management.

### Module Definition

```rust
mod math {
    pub fn add(a: Felt, b: Felt) -> Felt {
        a + b
    }
    
    fn private_helper() -> Felt {
        42
    }
}
```

### Module Usage

```rust
use math::*;

fn main() -> Felt {
    add(10, 20)  // Using imported function
}
```

### Nested Modules

```rust
mod crypto {
    pub mod hash {
        pub fn poseidon(input: Hash) -> Hash {
            hash(input)
        }
    }
    
    pub mod signature {
        pub fn verify(msg: [u64; 4], sig: [u32; 16], pubkey: [u32; 16]) -> bool {
            __secp256k1_verify(pubkey, msg, sig)
        }
    }
}
```

## Traits

Interface definitions for shared behavior across types.

### Basic Traits

```rust
pub trait Arithmetic {
    fn add(self, other: Self) -> Self;
    fn multiply(self, other: Self) -> Self;
}

pub trait Display {
    fn show(self) -> Felt;
}
```

### Trait Implementation

```rust
struct Point {
    x: Felt,
    y: Felt,
}

impl Arithmetic for Point {
    fn add(self, other: Point) -> Point {
        new Point {
            x: self.x + other.x,
            y: self.y + other.y,
        }
    }
    
    fn multiply(self, other: Point) -> Point {
        new Point {
            x: self.x * other.x,
            y: self.y * other.y,
        }
    }
}
```

## Generics

Type parameters for code reuse and type safety.

### Generic Functions

```rust
fn identity<T>(value: T) -> T {
    value
}

fn pair<T, U>(first: T, second: U) -> (T, U) {
    (first, second)
}
```

### Generic Structs

```rust
struct Container<T> {
    value: T,
}

impl<T> Container<T> {
    pub fn new(value: T) -> Container<T> {
        new Container { value }
    }
    
    pub fn get(self) -> T {
        self.value
    }
}
```

### Generic Traits

```rust
trait Convert<T> {
    fn convert(self) -> T;
}

impl Convert<Felt> for u32 {
    fn convert(self) -> Felt {
        self as Felt
    }
}
```

## Type System Features

### Type Checking

Static type checking ensures type safety at compile time.

```rust
fn type_safe_function(x: Felt, y: bool) -> (Felt, bool) {
    // Compiler verifies all types match
    let result_x: Felt = x + 1;      // ✓ Felt arithmetic
    let result_y: bool = y && true;  // ✓ Boolean logic
    (result_x, result_y)
}
```

### Type Hints

Explicit type annotations for clarity and optimization.

```rust
fn with_type_hints() {
    let inferred = 42;              // Type inferred as Felt
    let explicit: Felt = 42;        // Explicit type annotation
    let tuple: (Felt, bool) = (1, true);  // Tuple type hint
}
```

### Trait Constraints

Generic type constraints using trait bounds.

```rust
fn generic_add<T: Arithmetic>(a: T, b: T) -> T {
    a.add(b)  // T must implement Arithmetic trait
}

fn display_value<T: Display + Clone>(value: T) -> Felt {
    value.show()  // T must implement both Display and Clone
}
```

## Storage and Smart Contracts

Persistent state management for blockchain applications.

### Storage Structs

```rust
#[storage]
struct TokenContract {
    // Contract state fields
}

impl TokenContract {
    pub fn mint(amount: Felt) -> Felt {
        let user_id = get_user_id();
        let current_state = get_state_hash_at(user_id);
        let current_balance = current_state[0];
        
        let new_balance = current_balance + amount;
        cset_state_hash_at(user_id, [new_balance, current_state[1], current_state[2], current_state[3]]);
        
        new_balance
    }
}
```

## Built-in Functions

ZK-optimized cryptographic and system functions.

### Cryptographic Functions

```rust
// Poseidon hash
let data: Hash = [1, 2, 3, 4];
let hash_result: Hash = hash(data);

// ECDSA signature verification
let pubkey = [/* 16 u32 values */];
let message = [/* 4 u64 values */];  
let signature = [/* 16 u32 values */];
let is_valid: bool = __secp256k1_verify(pubkey, message, signature);
```

### System Functions

```rust
// State access functions
let user_id: Felt = get_user_id();
let contract_id: Felt = get_contract_id();
let checkpoint: Felt = get_checkpoint_id();
let user_state: Hash = get_state_hash_at(user_id);
```

## Development Tools

### Dargo Package Manager

Complete project lifecycle management.

```bash
# Initialize new project
dargo init

# Create new project
dargo new my_project

# Compile contract
dargo compile --contract-name MyContract --method-names deploy transfer

# Execute with parameters  
dargo execute --contract-name MyContract --method-names mint --parameters 100

# Run tests
dargo test

# Format code
dargo fmt src/main.psy
```

### Language Server Protocol (LSP)

IDE integration for enhanced development experience.

**Supported Features:**
- **Hover** - Type information and documentation
- **Go to Definition** - Navigate to symbol definitions
- **Find References** - Locate all symbol usages
- **Code Formatting** - Automatic code formatting
- **Error Diagnostics** - Real-time error reporting

**IDE Support:**
- Visual Studio Code
- Neovim  
- RustRover/IntelliJ

### Error Reporting

Precise error diagnostics with line and column information.

```rust
// Error example
fn invalid_function() {
    let x: Felt = true;  // Type mismatch error
    //    ^^^^     ^^^^ 
    //    |        |
    //    |        Expected Felt, found bool
    //    |
    //    Variable declared as Felt
}
```

**Error Message:**
```
error[E0308]: mismatched types
 --> src/main.psy:2:19
  |
2 |     let x: Felt = true;
  |            ----   ^^^^ expected `Felt`, found `bool`
  |            |
  |            expected due to this type annotation
```

## Testing Framework

Built-in testing support with the `#[test]` attribute.

```rust
#[test]
fn test_arithmetic() {
    let result = add(2, 3);
    assert_eq(result, 5, "2 + 3 should equal 5");
}

#[test]
fn test_contract_mint() {
    // Test contract functionality
    let initial_balance = 100;
    let mint_amount = 50;
    let expected = initial_balance + mint_amount;
    
    let result = mint(mint_amount);
    assert(result > initial_balance, "Balance should increase after minting");
}
```

## Package System (Crates)

Modular code organization and dependency management.

### Dargo.toml Configuration

```toml
[package]
name = "my_contract"
version = "0.1.0"
edition = "2024"

[dependencies]
std = "0.1.0"
crypto = "0.2.0"

[lib]
name = "my_contract"
path = "src/lib.psy"
```

### Library Structure

```
my_project/
├── Dargo.toml
├── src/
│   ├── main.psy
│   ├── lib.psy
│   └── utils/
│       ├── mod.psy
│       ├── math.psy
│       └── crypto.psy
└── tests/
    └── integration_test.psy
```

## Zero-Knowledge Optimizations

All language features are designed with ZK circuit efficiency in mind:

- **Control flow flattening** - Branches become arithmetic selections
- **Loop unrolling** - Bounded loops are completely expanded
- **Function inlining** - Eliminates call overhead
- **Constant folding** - Compile-time evaluation
- **Dead code elimination** - Unused code paths removed
- **Arithmetic optimization** - Efficient field operations

This comprehensive feature set makes Psy a powerful language for developing efficient zero-knowledge smart contracts while maintaining familiar programming patterns and strong type safety.