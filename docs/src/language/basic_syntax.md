# Basic Syntax

[Psy Smart Contract Language] uses a syntax inspired by [Rust]. Here are the basics:

## Variables

Variables are declared with `let` and can be mutable with `mut`:

### Basic Type Assignment

```rust
// Felt type assignment
let a: Felt = 1;
let b = 42; // Type inference
let mut c: Felt = 0;
c = 100;

// Boolean assignment
let flag: bool = true;
let mut status = false;
status = true;

// u32 assignment  
let count: u32 = 42u32;
let mut index = 0u32;
index = 5u32;
```

### Array Assignment

```rust
// Fixed-size array assignment
let numbers: [Felt; 3] = [1, 2, 3];
let mut values: [u32; 5] = [0u32, 1u32, 2u32, 3u32, 4u32];

// Individual element assignment
values[0] = 10u32;
values[1] = 20u32;

// Nested array assignment
let mut matrix: [[Felt; 2]; 3] = [[1, 2], [3, 4], [5, 6]];
matrix[0][1] = 99;
```

### Tuple Assignment

```rust
// Tuple assignment
let point: (Felt, Felt) = (10, 20);
let mixed: (Felt, bool, u32) = (42, true, 100u32);

// Individual element assignment
let mut coordinates: (Felt, Felt) = (0, 0);
coordinates.0 = 5;
coordinates.1 = 15;

// Nested tuple assignment
let mut complex: ((Felt, Felt), (Felt, Felt)) = ((1, 2), (3, 4));
complex.0.1 = 42; // Assign to nested element
```

### Struct Assignment

```rust
struct Point {
    pub x: Felt,
    pub y: Felt,
}

// Struct creation assignment
let origin: Point = new Point { x: 0, y: 0 };

// Field assignment
let mut position: Point = new Point { x: 10, y: 20 };
position.x = 15;
position.y = 25;

// Struct with complex types
struct Container {
    pub data: [Felt; 3],
    pub coords: (Felt, Felt),
}

let mut container: Container = new Container {
    data: [1, 2, 3],
    coords: (10, 20),
};
container.data[0] = 99;
container.coords.1 = 30;
```

## Comments

Psy supports both single-line and multi-line comments:

```rust
// Single-line comment
let a: Felt = 1;

/*
 * Multi-line comment
 * across multiple lines
 */
let b: Felt = 2;

/* Single-line block comment */
let c: Felt = 3;
```

### Placement

Comments can be placed in these locations:

```rust
// Comment before struct
struct Point {
    pub x: Felt,
    // Comment between fields
    pub y: Felt,
}

// Comment before function
fn calculate(a: Felt, b: Felt) -> Felt {
    // Comment inside function
    let result = a + b;
    return result;
}

#[test]
fn test_function() {
    // Comment in test
    assert_eq(calculate(1, 2), 3, "should be 3");
}
```

### Limitations

Comments cannot be placed in these locations:

```rust
// ❌ Invalid: After attributes
#[test] // This causes an error
fn test_func() { }

// ❌ Invalid: Inside parameter lists
fn invalid_func(
    // This causes an error
    a: Felt,
    b: Felt
) -> Felt { a + b }

// ❌ Invalid: In middle of declarations  
struct InvalidStruct {
    pub /* error here */ x: Felt,
}
```
