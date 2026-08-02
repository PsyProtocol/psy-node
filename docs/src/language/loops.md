# Loops

This chapter covers loop constructs in Psy: `while` loops and `for` loops.

## While Loops

While loops execute a block of code repeatedly as long as a condition remains true.

### Basic While Loop

```rust
fn main() -> Felt {
    let mut res = 0;
    let mut i = 0;
    while i < 10 {
        res += i;
        i += 1;
    }
    res  // Returns 45 (0+1+2+...+9)
}
```

### Fibonacci Sequence with While

```rust
fn fibonacci(a: Felt, b: Felt) -> Felt {
    let mut res = 0;
    let mut a = a;
    let mut b = b;
    let mut i = 2;
    let mut c = 0;
    
    while i <= 10 {
        let d = a + b;
        c = d;
        a = b;
        b = c;
        i += 1;
    }
    
    res = b;
    return res;
}

fn main() {
    let result = fibonacci(2, 3); // Returns 233
}
```

### While with Complex State

```rust
fn main() {
    let mut sum = 0;
    let mut count = 0;
    let mut current = 1;
    
    while current <= 100 {
        if current % 2 == 0 {  // Even numbers only
            sum += current;
            count += 1;
        } else {
            // Do nothing for odd numbers  
        };
        current += 1;
    }
    
    // sum contains sum of all even numbers from 1 to 100
    // count contains how many even numbers were found
}
```

### While with Arrays

```rust
struct Data {
    pub values: [Felt; 5],
    pub count: Felt,
}

fn process_data() -> Data {
    let mut data = new Data {
        values: [0; 5],
        count: 0,
    };
    
    let mut i = 0;
    while i < 5 {
        data.values[i] = i * i;  // Square of index
        data.count += 1;
        i += 1;
    }
    
    return data;
}
```

## For Loops

For loops provide a way to iterate over ranges with automatic index management.

### Basic For Loop

```rust
fn main() -> Felt {
    let mut sum = 0;
    for n in 0u32..100u32 {
        sum += (n as Felt);
    }
    sum  // Returns 4950 (sum of 0 to 99)
}
```

### For Loop with Arrays

```rust
struct TestSibling {
    pub value: [Felt; 4],
}

fn main() {
    let mut test_array: [TestSibling; 3] = [
        new TestSibling { value: [1, 2, 3, 4] },
        new TestSibling { value: [5, 6, 7, 8] },
        new TestSibling { value: [9, 10, 11, 12] }
    ];

    for i in 0u32..3u32 {
        let level_index = i as Felt;
        let sibling = test_array[level_index];
        let value = sibling.value;

        // Process each element
        let sum = value[0] + value[1] + value[2] + value[3];
        
        // Modify array element
        test_array[level_index] = new TestSibling {
            value: [sum, sum, sum, sum]
        };
    }
}
```

### For Loop with Conditionals

```rust
fn main() {
    let mut test_array: [TestSibling; 3] = [
        new TestSibling { value: [1, 2, 3, 4] },
        new TestSibling { value: [0, 0, 0, 0] },
        new TestSibling { value: [0, 0, 0, 0] }
    ];

    for i in 0u32..3u32 {
        let level_index = i as Felt;
        let sibling = test_array[level_index];
        let value = sibling.value;

        if level_index < 1 {
            // First element has specific values
            // value[0] == 1, value[1] == 2, etc.
        } else {
            // Other elements are zeros
            // value[0] == 0, value[1] == 0, etc.
        }
    }
}
```

### For Loop with Complex Processing

```rust
fn matrix_multiplication() {
    let matrix_a: [[Felt; 3]; 3] = [
        [1, 2, 3],
        [4, 5, 6],
        [7, 8, 9]
    ];
    
    let matrix_b: [[Felt; 3]; 3] = [
        [9, 8, 7],
        [6, 5, 4],
        [3, 2, 1]
    ];
    
    let mut result: [[Felt; 3]; 3] = [[0; 3]; 3];
    
    for i in 0u32..3u32 {
        for j in 0u32..3u32 {
            let mut sum = 0;
            for k in 0u32..3u32 {
                let ii = i as Felt;
                let jj = j as Felt;
                let kk = k as Felt;
                sum += matrix_a[ii][kk] * matrix_b[kk][jj];
            }
            result[i as Felt][j as Felt] = sum;
        }
    }
}
```

### For Loop with Accumulation

```rust
fn calculate_factorials() -> [Felt; 10] {
    let mut factorials = [0; 10];
    
    for i in 0u32..10u32 {
        let mut factorial = 1;
        let num = (i + 1u32) as Felt; // Calculate factorial of (i+1)
        
        for j in 1u32..(i + 2u32) {
            factorial *= j as Felt;
        }
        
        factorials[i as Felt] = factorial;
    }
    
    return factorials;
}
```

## Loop Patterns

### Counting Patterns

```rust
// Count up
fn count_up() {
    for i in 1u32..11u32 {  // 1 to 10
        let value = i as Felt;
        // Process value
    }
}

// Count with step
fn count_with_step() {
    for i in 0u32..10u32 {
        let value = (i * 2) as Felt;  // 0, 2, 4, 6, 8, ...
        // Process even numbers
    }
}

// Count down (using while)
fn count_down() {
    let mut i = 10;
    while i > 0 {
        // Process i
        i -= 1;
    }
}
```

### Array Processing Patterns

```rust
// Initialize array
fn initialize_array() -> [Felt; 5] {
    let mut arr = [0; 5];
    for i in 0u32..5u32 {
        arr[i as Felt] = (i + 1) as Felt;
    }
    return arr; // [1, 2, 3, 4, 5]
}

// Sum array elements
fn sum_array(arr: [Felt; 5]) -> Felt {
    let mut sum = 0;
    for i in 0u32..5u32 {
        sum += arr[i as Felt];
    }
    return sum;
}

// Find maximum
fn find_max(arr: [Felt; 5]) -> Felt {
    let mut max = arr[0];
    for i in 1u32..5u32 {
        let current = arr[i as Felt];
        if current > max {
            max = current;
        }
    }
    return max;
}
```

### Nested Loop Patterns

```rust
// Create multiplication table
fn multiplication_table() -> [[Felt; 10]; 10] {
    let mut table = [[0; 10]; 10];
    
    for i in 0u32..10u32 {
        for j in 0u32..10u32 {
            let ii = i as Felt;
            let jj = j as Felt;
            table[ii][jj] = (ii + 1) * (jj + 1);
        }
    }
    
    return table;
}

// Process 2D grid
fn process_grid() {
    let mut grid: [[Felt; 5]; 5] = [[0; 5]; 5];
    
    for row in 0u32..5u32 {
        for col in 0u32..5u32 {
            let r = row as Felt;
            let c = col as Felt;
            
            // Set diagonal elements to 1
            if r == c {
                grid[r][c] = 1;
            } else {
                grid[r][c] = r + c;
            }
        }
    }
}
```

### Search Patterns

```rust
// Linear search
fn linear_search(arr: [Felt; 10], target: Felt) -> Felt {
    for i in 0u32..10u32 {
        if arr[i as Felt] == target {
            return i as Felt;  // Return index
        }
    }
    return 10;  // Not found (return invalid index)
}

// Search with condition
fn find_first_even(arr: [Felt; 10]) -> Felt {
    for i in 0u32..10u32 {
        let value = arr[i as Felt];
        if value % 2 == 0 {
            return value;
        }
    }
    return 0;  // No even number found
}
```

## Loop Control Notes

### Range Syntax

For loops in Psy use range syntax:

```rust
// Inclusive ranges
for i in 0u32..5u32 {  // i goes from 0 to 4 (5 is excluded)
    // Loop body
}

// Must specify u32 type for ranges
for i in 1u32..10u32 {  // i goes from 1 to 9
    let value = i as Felt;  // Convert to Felt if needed
    // Process value
}
```

### Type Conversions in Loops

```rust
fn main() {
    for i in 0u32..10u32 {
        let index = i as Felt;        // Convert u32 to Felt for array indexing
        let squared = index * index;   // Felt arithmetic
        
        // Use index for array operations
        let mut arr = [0; 10];
        arr[index] = squared;
    }
}
```

### Loop Variable Scope

```rust
fn main() {
    // Loop variable 'i' is only available inside the loop
    for i in 0u32..5u32 {
        let doubled = (i * 2) as Felt;
        // 'i' and 'doubled' are available here
    }
    // 'i' is not available here
    
    let mut counter = 0;
    while counter < 5 {
        let temp = counter * 2;
        // 'counter' and 'temp' are available here
        counter += 1;
    }
    // 'counter' is still available here (declared outside loop)
    // 'temp' is not available here
}
```

## Important Considerations

### Psy vs Rust Syntax Differences

Psy has some important syntax differences from Rust:

```rust
// ❌ Psy requires explicit u32 type in arithmetic
for i in 0u32..10u32 {
    let value = (i + 1) as Felt;     // Error: type mismatch
}

// ✅ Correct: use explicit u32 literals
for i in 0u32..10u32 {
    let value = (i + 1u32) as Felt;  // Correct
}

// ❌ If statements as statements need semicolons
if condition {
    // do something
} else {
    // do something else
}
next_statement();  // Error: missing semicolon

// ✅ Correct: add semicolon after if-else statement
if condition {
    // do something  
} else {
    // do something else
};  // Required semicolon
next_statement();
```

### No Break or Continue

Psy loops do not support `break` or `continue` statements. Loop control must be managed through conditions:

```rust
// ❌ Not supported
// for i in 0u32..10u32 {
//     if condition {
//         break;
//     }
// }

// ✅ Use conditional logic instead
fn controlled_loop() {
    let mut should_continue = true;
    let mut i = 0;
    
    while i < 10 && should_continue {
        // Process logic
        if some_condition {
            should_continue = false;  // Equivalent to break
        } else {
            // Process normally
        }
        i += 1;
    }
}
```

### Loop Unrolling for ZK

Since Psy compiles to zero-knowledge circuits, loops are unrolled at compile time. This means:

1. **Fixed iterations**: Loop bounds must be known at compile time
2. **No dynamic bounds**: Cannot loop based on runtime values
3. **Resource usage**: Each loop iteration becomes part of the circuit

```rust
// ✅ Valid: Fixed bounds known at compile time
for i in 0u32..100u32 {
    // Loop body
}

// ❌ Invalid: Runtime-dependent bounds
fn invalid_loop(n: Felt) {
    // This would not work as n is not known at compile time
    // for i in 0u32..n {  
    //     // Loop body
    // }
}
```

## Key Points

1. **While loops** execute while a condition is true
2. **For loops** iterate over fixed ranges with u32 indices
3. **No break/continue** - use conditional logic instead
4. **Fixed bounds** - loop iterations must be compile-time constant
5. **Type conversion** - convert u32 loop indices to Felt for array access
6. **Nested loops** are fully supported
7. **Loop unrolling** - all loops are unrolled in the final circuit
8. **Scope rules** - loop variables have block scope
9. **Syntax differences from Rust**:
   - u32 arithmetic requires explicit `u32` literals (e.g., `i + 1u32`)
   - If-else statements used as statements need trailing semicolons
   - Empty else blocks should contain at least one statement