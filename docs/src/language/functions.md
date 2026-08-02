# Functions

Functions are the building blocks of Psy programs. This chapter covers how to define functions and call them with various parameter types.

## Function Definition

Functions are defined using the `fn` keyword:

```rust
// Basic function definition
fn add(a: Felt, b: Felt) -> Felt {
    return a + b;
}

// Function without explicit return value (returns unit type)
fn validate_inputs(a: Felt, b: Felt) {
    assert(a >= 0, "a must be non-negative");
    assert(b >= 0, "b must be non-negative");
    // Implicit return of unit type
}

// Function with multiple parameters of different types
fn calculate(x: Felt, y: Felt, flag: bool, count: u32) -> Felt {
    if flag {
        x + y + (count as Felt)
    } else {
        x - y
    }
}
```

## Function Calls

### Parameter Passing

In Psy, function parameters are passed using different mechanisms depending on the data type:

**Value Types (Copy Semantics):**
- `Felt`, `u32`, `bool` - These are copied when passed to functions
- The original variable is not affected when the parameter is modified inside the function

**Reference Types (Move/Borrow Semantics):**
- Arrays `[T; N]` - Passed by reference/move
- Structs - Passed by reference/move

**Tuples - Mixed Semantics:**
- Tuples pass each member according to its own type
- `(Felt, Felt)` - Both members copied (value types)
- `(Felt, [Felt; 3])` - First member copied, second member moved
- `([Felt; 2], [Felt; 3])` - Both members moved (reference types)

```rust
fn test_parameter_passing() {
    // Value types - copied
    let x: Felt = 10;
    let flag: bool = true;
    let count: u32 = 5u32;
    
    modify_values(x, flag, count);
    // x, flag, count remain unchanged
    
    // Reference types - moved/borrowed
    let mut arr = [1, 2, 3];
    let mut point = new Point { x: 1, y: 2 };
    
    modify_references(arr, point);
    // arr and point are moved into the function
}

fn modify_values(mut a: Felt, mut b: bool, mut c: u32) {
    a = 99;    // Only affects the local copy
    b = false; // Only affects the local copy
    c = 0u32;  // Only affects the local copy
}

fn modify_references(mut arr: [Felt; 3], mut point: Point) {
    arr[0] = 99;  // Modifies the actual array
    point.x = 99; // Modifies the actual struct
}

// Examples of tuple parameter semantics
fn process_value_tuple(tuple: (Felt, Felt)) -> Felt {
    // Both members copied - original tuple unaffected
    return tuple.0 + tuple.1;
}

fn process_mixed_tuple(tuple: (Felt, [Felt; 2])) -> Felt {
    // First member copied, array moved
    return tuple.0 + tuple.1[0];
}

fn process_ref_tuple(tuple: ([Felt; 2], [Felt; 2])) -> Felt {
    // Both arrays moved
    return tuple.0[0] + tuple.1[1];
}
```

### Syntax Limitations

**Important:** Psy does not support early returns within control flow statements:

```rust
// ❌ Invalid: Early return in if statement
fn invalid_early_return(x: Felt) -> Felt {
    if x > 10 {
        return x * 2; // This causes a compilation error
    };
    return x;
}

// ✅ Valid: Use expression-based returns
fn valid_conditional_return(x: Felt) -> Felt {
    if x > 10 {
        x * 2
    } else {
        x
    }
}

// ✅ Valid: Set variable then return
fn valid_variable_return(x: Felt) -> Felt {
    let mut result = x;
    if x > 10 {
        result = x * 2;
    };
    return result;
}
```

### Basic Function Calls

```rust
fn add(a: Felt, b: Felt) -> Felt {
    return a + b;
}

fn subtract(a: Felt, b: Felt) -> Felt {
    return a - b;
}

#[test]
fn test_basic_calls() {
    // Simple function calls
    let sum = add(5, 3);
    let diff = subtract(10, 4);
    
    assert_eq(sum, 8, "5 + 3 should be 8");
    assert_eq(diff, 6, "10 - 4 should be 6");
}
```

### Function Calls with Different Parameter Types

```rust
fn process_data(value: Felt, enabled: bool, iterations: u32) -> Felt {
    let mut result = value;
    if enabled {
        for i in 0u32..iterations {
            result = result + 1;
        }
    } else {
        result = 0;
    };
    return result;
}

#[test]
fn test_mixed_parameters() {
    // Calling function with mixed parameter types
    let result1 = process_data(10, true, 3u32);
    let result2 = process_data(10, false, 3u32);
    
    assert_eq(result1, 13, "10 + 3 iterations should be 13");
    assert_eq(result2, 0, "disabled should return 0");
}
```

### Function Calls with Arrays

```rust
fn sum_array(arr: [Felt; 3]) -> Felt {
    return arr[0] + arr[1] + arr[2];
}

fn modify_array(mut arr: [Felt; 3]) -> [Felt; 3] {
    arr[0] = arr[0] * 2;
    arr[1] = arr[1] * 2;
    arr[2] = arr[2] * 2;
    return arr;
}

#[test]
fn test_array_parameters() {
    let numbers: [Felt; 3] = [1, 2, 3];
    
    // Pass array to function
    let total = sum_array(numbers);
    let doubled = modify_array(numbers);
    
    assert_eq(total, 6, "1 + 2 + 3 should be 6");
    assert_eq(doubled[0], 2, "first element doubled should be 2");
    assert_eq(doubled[1], 4, "second element doubled should be 4");
}
```

### Function Calls with Tuples

```rust
fn distance(point1: (Felt, Felt), point2: (Felt, Felt)) -> Felt {
    let dx = point2.0 - point1.0;
    let dy = point2.1 - point1.1;
    // Simplified distance calculation (not actual Euclidean distance)
    return dx + dy;
}

fn create_point(x: Felt, y: Felt) -> (Felt, Felt) {
    return (x, y);
}

#[test]
fn test_tuple_parameters() {
    let p1: (Felt, Felt) = (0, 0);
    let p2 = create_point(3, 4);
    
    let dist = distance(p1, p2);
    
    assert_eq(p2.0, 3, "x coordinate should be 3");
    assert_eq(p2.1, 4, "y coordinate should be 4");
    assert_eq(dist, 7, "distance should be 3 + 4 = 7");
}
```

### Function Calls with Structs

```rust
struct Point {
    pub x: Felt,
    pub y: Felt,
}

fn create_point_struct(x: Felt, y: Felt) -> Point {
    return new Point { x: x, y: y };
}

fn move_point(mut point: Point, dx: Felt, dy: Felt) -> Point {
    point.x = point.x + dx;
    point.y = point.y + dy;
    return point;
}

fn get_x_coordinate(point: Point) -> Felt {
    return point.x;
}

#[test]
fn test_struct_parameters() {
    let origin = create_point_struct(0, 0);
    let moved = move_point(origin, 5, 3);
    let x_coord = get_x_coordinate(moved);
    
    assert_eq(x_coord, 5, "x coordinate should be 5 after moving");
    assert_eq(moved.y, 3, "y coordinate should be 3 after moving");
}
```

## Nested Function Calls

Functions can call other functions, creating nested calls:

```rust
fn double(x: Felt) -> Felt {
    return x * 2;
}

fn square(x: Felt) -> Felt {
    return x * x;
}

fn complex_calculation(x: Felt) -> Felt {
    // Nested function calls
    let doubled = double(x);
    let squared = square(doubled);
    return squared + double(x);
}

#[test]
fn test_nested_calls() {
    let result = complex_calculation(3);
    // double(3) = 6, square(6) = 36, double(3) = 6
    // result = 36 + 6 = 42
    assert_eq(result, 42, "complex calculation should be 42");
}
```

## Function Inlining

**Important:** In Psy, functions are inlined by default during compilation. This means:

- Function calls are replaced with the function body during compilation
- Each function generates its own DPN opcodes
- There is no runtime function call overhead
- Recursive functions have limitations due to inlining

```rust
fn inline_example(x: Felt) -> Felt {
    return x + 1;
}

#[test]
fn test_inlining() {
    // This call will be inlined during compilation
    let result = inline_example(5);
    assert_eq(result, 6, "5 + 1 should be 6");
}
```
