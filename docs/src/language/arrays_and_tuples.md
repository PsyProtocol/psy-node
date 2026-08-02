# Arrays and Tuples

This chapter covers arrays and tuples in Psy, two important data structures for grouping values together.

## Arrays

Arrays in Psy are fixed-size sequences of elements of the same type. They are defined with the syntax `[T; N]` where `T` is the element type and `N` is the compile-time known size.

### Basic Array Usage

```rust
fn main() {
    // Array of 5 Felt values
    let numbers = [1, 2, 3, 4, 5];
    
    // Array with explicit type annotation
    let coordinates: [Felt; 3] = [10, 20, 30];
    
    // Array initialized with same value
    let zeros = [0; 4]; // [0, 0, 0, 0]
    
    // Accessing elements
    let first = numbers[0];
    let third = coordinates[2];
}
```

### Arrays in Structs

```rust
struct HW {
    pub height: Felt,
    pub weight: Felt,
}

struct Person {
    pub age: Felt,
    pub hw: [HW; 2],
}

fn main() {
    let hw1 = new HW { height: 180, weight: 140 };
    let hw2 = new HW { height: 175, weight: 110 };
    
    let person = new Person {
        age: 25,
        hw: [hw1, hw2],
    };
    
    // Access nested array elements
    let first_height = person.hw[0].height;
    let second_weight = person.hw[1].weight;
}
```

### Nested Arrays

```rust
fn main() {
    // 2D array (matrix)
    let matrix: [[Felt; 3]; 2] = [
        [1, 2, 3],
        [4, 5, 6]
    ];
    
    // Accessing nested elements
    let element = matrix[1][2]; // Gets 6
    
    // 3D array
    let cube: [[[Felt; 2]; 2]; 2] = [
        [[1, 2], [3, 4]],
        [[5, 6], [7, 8]]
    ];
    
    let deep_value = cube[1][0][1]; // Gets 6
}
```

### Mutable Array Operations

```rust
fn main() {
    let hw1 = new HW { height: 180, weight: 140 };
    let hw2 = new HW { height: 175, weight: 110 };
    
    let person1 = new Person { age: 8, hw: [hw1, hw1] };
    let person2 = new Person { age: 18, hw: [hw2, hw2] };
    
    let mut people: [Person; 2] = [person1, person2];
    
    // Modify array elements
    people[0].hw[1] = new HW { height: 160, weight: 110 };
    
    // Access modified values
    let total_height = people[0].hw[0].height + people[0].hw[1].height;
}
```

### Array Methods with Generics

Arrays support methods through generic implementations. However, specialized implementations for specific array types are not currently supported:

```rust
impl<T, N: u32> [T; N] {
    pub const fn len() -> u32 {
        return N;
    }
}

fn main() {
    // Call len() method on array type
    let length = <[Felt; 5]>::len(); // Returns 5
}
```

### Working with Arrays Using Functions

Since custom array methods are not currently supported, use regular functions to operate on arrays:

```rust
fn array_sum(arr: [Felt; 3]) -> Felt {
    return arr[0] + arr[1] + arr[2];
}

fn array_dot_product(a: [Felt; 3], b: [Felt; 3]) -> Felt {
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
}

fn array_max(arr: [Felt; 4]) -> Felt {
    let mut max_val = arr[0];
    if arr[1] > max_val { max_val = arr[1]; };
    if arr[2] > max_val { max_val = arr[2]; };
    if arr[3] > max_val { max_val = arr[3]; };
    return max_val;
}

fn main() {
    let v1 = [1, 2, 3];
    let v2 = [4, 5, 6];
    
    let sum = array_sum(v1); // Returns 6
    let dot = array_dot_product(v1, v2); // Returns 32
    
    let grades = [85, 92, 78, 95];
    let highest = array_max(grades); // Returns 95
}
```

## Tuples

Tuples are fixed-size sequences that can contain elements of different types. They are defined with parentheses and comma-separated values.

### Basic Tuple Usage

```rust
fn main() {
    // Basic tuple assignment
    let a: Felt = 10;
    let b: Felt = 11;
    let c: (Felt, Felt) = (12, 13);
    let d: (Felt, Felt) = (a, b);
    
    // Mutable tuple
    let mut e: (Felt, Felt) = (14, 15);
    
    // Change tuple elements
    e.0 = 16;
    e.1 = 17;
    e = (18, 19);
    
    // Accessing tuple elements
    let first = c.0;  // Gets 12
    let second = c.1; // Gets 13
}
```

### Nested Tuples

```rust
fn main() {
    // Nested tuple
    let nested_tuple: ((Felt, Felt), (Felt, Felt)) = ((1, 2), (3, 4));
    
    // Deeply nested tuple
    let deeply_nested: (((Felt, Felt), Felt), Felt) = (((5, 6), 7), 8);
    
    // Modify nested tuples
    let mut complex_tuple: ((Felt, Felt), (Felt, Felt)) = ((9, 10), (11, 12));
    complex_tuple.0.1 = 42;  // Change nested element
    complex_tuple.1 = (20, 21); // Replace entire sub-tuple
    
    // Access nested elements
    let value = nested_tuple.0.1;  // Gets 2
    let deep_value = deeply_nested.0.0.1; // Gets 6
}
```

### Tuples in Structs

```rust
struct TupleHolder {
    pub pair: (Felt, Felt),
    pub nested: ((Felt, Felt), Felt),
}

fn main() {
    let mut struct_with_tuple = new TupleHolder {
        pair: (22, 23),
        nested: ((24, 25), 26),
    };
    
    // Modify tuple fields in struct
    struct_with_tuple.pair.1 = 99;
    struct_with_tuple.nested.0.0 = 88;
    
    // Access tuple elements in struct
    let pair_first = struct_with_tuple.pair.0;
    let nested_value = struct_with_tuple.nested.1;
}
```

### Functions with Tuples

```rust
fn create_tuple(x: Felt, y: Felt) -> (Felt, Felt) {
    return (x + 1, y + 1);
}

fn sum_tuple(input: (Felt, Felt)) -> Felt {
    return input.0 + input.1;
}

fn swap_tuple(input: (Felt, Felt)) -> (Felt, Felt) {
    return (input.1, input.0);
}

fn process_nested(input: ((Felt, Felt), Felt)) -> Felt {
    return input.0.0 + input.0.1 + input.1;
}

fn main() {
    // Function returning tuple
    let returned_tuple = create_tuple(30, 31);
    // returned_tuple is (31, 32)
    
    // Function taking tuple as parameter
    let result = sum_tuple((40, 50));
    // result is 90
    
    // More complex operations
    let swapped = swap_tuple((10, 20));
    // swapped is (20, 10)
    
    let nested_result = process_nested(((1, 2), 3));
    // nested_result is 6
}
```

### Tuple Parameter Passing

Tuples follow mixed semantics based on their member types:

```rust
fn main() {
    // Tuple with only value types - passed by copy
    let simple_tuple = (1, 2, true);
    process_simple(simple_tuple);
    
    // Tuple with reference types - passed by move/reference
    let array_tuple = ([1, 2, 3], 42);
    process_complex(array_tuple);
}

fn process_simple(t: (Felt, Felt, bool)) {
    let sum = t.0 + t.1;
    let flag = t.2;
}

fn process_complex(t: ([Felt; 3], Felt)) {
    let array_sum = t.0[0] + t.0[1] + t.0[2];
    let extra = t.1;
}
```

## Current Limitations

### Tuple Destructuring

**Note**: Tuple destructuring is not currently supported:

```rust
fn main() {
    // ❌ Not supported yet
    // let (x, y) = (50, 60);
    // let ((a, b), c) = ((1, 2), 3);
    
    // ✅ Use explicit access instead
    let pair = (50, 60);
    let x = pair.0;
    let y = pair.1;
}
```

## Arrays vs Tuples

| Feature | Arrays | Tuples |
|---------|--------|--------|
| **Element Types** | Same type only | Different types allowed |
| **Size** | Fixed at compile time | Fixed at compile time |
| **Access** | Index notation `arr[0]` | Dot notation `tuple.0` |
| **Methods** | Generic methods only | No custom methods |
| **Parameter Passing** | Always by reference | Mixed based on members |
| **Destructuring** | Not supported | Not supported (yet) |
| **Mutability** | Elements can be modified | Elements can be modified |

## Complex Examples

### Game Inventory System

```rust
struct Item {
    pub id: Felt,
    pub quantity: Felt,
}

struct Player {
    pub health: Felt,
    pub position: (Felt, Felt),
    pub inventory: [Item; 5],
    pub stats: (Felt, Felt, Felt), // (strength, defense, speed)
}

fn main() {
    let sword = new Item { id: 1, quantity: 1 };
    let potion = new Item { id: 2, quantity: 3 };
    let empty_slot = new Item { id: 0, quantity: 0 };
    
    let mut player = new Player {
        health: 100,
        position: (10, 20),
        inventory: [sword, potion, empty_slot, empty_slot, empty_slot],
        stats: (15, 10, 12)
    };
    
    // Move player
    player.position.0 = player.position.0 + 5;
    player.position.1 = player.position.1 - 2;
    
    // Add item to inventory
    player.inventory[2] = new Item { id: 3, quantity: 2 };
    
    // Increase stats
    player.stats.0 = player.stats.0 + 1; // strength + 1
    
    let total_strength = player.stats.0;
    let current_x = player.position.0;
}
```

### Matrix Operations

```rust
fn matrix_multiply(a: [[Felt; 2]; 2], b: [[Felt; 2]; 2]) -> [[Felt; 2]; 2] {
    let row1_col1 = a[0][0] * b[0][0] + a[0][1] * b[1][0];
    let row1_col2 = a[0][0] * b[0][1] + a[0][1] * b[1][1];
    let row2_col1 = a[1][0] * b[0][0] + a[1][1] * b[1][0];
    let row2_col2 = a[1][0] * b[0][1] + a[1][1] * b[1][1];
    
    return [[row1_col1, row1_col2], [row2_col1, row2_col2]];
}

fn main() {
    let matrix_a: [[Felt; 2]; 2] = [[1, 2], [3, 4]];
    let matrix_b: [[Felt; 2]; 2] = [[5, 6], [7, 8]];
    
    let result = matrix_multiply(matrix_a, matrix_b);
    
    // result is [[19, 22], [43, 50]]
    let top_left = result[0][0]; // 19
    let bottom_right = result[1][1]; // 50
}
```

### Database Record Simulation

```rust
type UserRecord = (Felt, (Felt, Felt, Felt), [Felt; 3], bool);

fn create_user_record(
    user_id: Felt, 
    birth_year: Felt, 
    birth_month: Felt, 
    birth_day: Felt,
    scores: [Felt; 3], 
    is_active: bool
) -> UserRecord {
    return (user_id, (birth_year, birth_month, birth_day), scores, is_active);
}

fn get_user_age(record: UserRecord, current_year: Felt) -> Felt {
    let birth_date = record.1;
    return current_year - birth_date.0;
}

fn calculate_average_score(record: UserRecord) -> Felt {
    let scores = record.2;
    return (scores[0] + scores[1] + scores[2]) / 3;
}

fn main() {
    let user = create_user_record(12345, 1990, 5, 15, [85, 92, 78], true);
    
    let age = get_user_age(user, 2023); // 33
    let avg_score = calculate_average_score(user); // 85
    
    let is_active = user.3;
    let birth_month = user.1.1;
}
```

## Key Points

1. **Arrays**: Fixed-size, same type, indexable with `[]`, support custom methods through generics
2. **Tuples**: Fixed-size, mixed types, accessible with `.N`, elements can be modified
3. **Parameter Passing**: 
   - Arrays are always passed by reference
   - Tuples follow mixed semantics based on member types
4. **Generic Methods**: Arrays support generic methods but not specialized implementations
5. **Access Patterns**: Arrays use index notation, tuples use field notation
6. **Type Safety**: Both are statically typed with compile-time size checking
7. **Mutability**: Both arrays and tuples support mutable operations on their elements
8. **Nested Structures**: Both support arbitrary nesting levels
9. **Current Limitations**: Tuple destructuring is not yet implemented
