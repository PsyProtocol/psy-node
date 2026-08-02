# Functions and Closures

This chapter covers closures in Psy. For basic function documentation, see the [Functions](./functions.md) chapter.

## Closures

Closures in Psy are anonymous functions that can capture variables from their surrounding scope. They use the `|parameters| -> return_type { body }` syntax.

### Basic Closure Syntax

```rust
fn main() {
    // Simple closure that adds two numbers
    let add = |a: Felt, b: Felt| -> Felt {
        a + b
    };
    
    let result = add(5, 3);
    assert_eq(result, 8, "5 + 3 should equal 8");
}
```

### Closure Type Inference

Closures can often infer parameter and return types:

```rust
fn main() {
    // Explicit types
    let multiply = |x: Felt, y: Felt| -> Felt { x * y };
    
    // Type inference (when context is clear)
    let numbers = [1, 2, 3, 4, 5];
    let sum = 0;
    
    // The closure type is inferred from usage
    let add_to_sum = |n| { sum + n };
    
    assert_eq(multiply(3, 4), 12, "3 * 4 should equal 12");
}
```

### Variable Capture

Closures can capture variables from their surrounding scope:

```rust
fn main() {
    let multiplier = 10;
    let base_value = 5;
    
    // Closure captures multiplier and base_value from outer scope
    let calculate = |input: Felt| -> Felt {
        (base_value + input) * multiplier
    };
    
    let result = calculate(3);
    assert_eq(result, 80, "(5 + 3) * 10 should equal 80");
}
```

### Closures with Conditional Logic

```rust
fn main() {
    // Closure that finds maximum of two values
    let max = |a: Felt, b: Felt| -> Felt {
        if a > b {
            a
        } else {
            b
        }
    };
    
    assert_eq(max(10, 7), 10, "max of 10 and 7 should be 10");
    assert_eq(max(3, 9), 9, "max of 3 and 9 should be 9");
}
```

### Using Closures with Arrays

```rust
fn main() {
    let numbers = [1, 2, 3, 4, 5];
    let multiplier = 3;
    
    // Closure to transform array elements
    let transform = |x: Felt| -> Felt { x * multiplier };
    
    // Manual application (Psy doesn't have built-in map)
    let mut transformed = [0; 5];
    for i in 0u32..5u32 {
        transformed[i as usize] = transform(numbers[i as usize]);
    }
    
    assert_eq(transformed[0], 3, "1 * 3 should equal 3");
    assert_eq(transformed[4], 15, "5 * 3 should equal 15");
}
```

### Closures as Function Parameters

You can pass closures to functions:

```rust
// Function that takes a closure as parameter
fn apply_operation(a: Felt, b: Felt, operation: fn(Felt, Felt) -> Felt) -> Felt {
    operation(a, b)
}

fn main() {
    let add = |x: Felt, y: Felt| -> Felt { x + y };
    let multiply = |x: Felt, y: Felt| -> Felt { x * y };
    
    let sum_result = apply_operation(5, 3, add);
    let product_result = apply_operation(5, 3, multiply);
    
    assert_eq(sum_result, 8, "5 + 3 should equal 8");
    assert_eq(product_result, 15, "5 * 3 should equal 15");
}
```

### Complex Closure Examples

#### Mathematical Operations

```rust
fn main() {
    let base = 2;
    
    // Closure for power calculation
    let power = |exponent: Felt| -> Felt {
        let mut result = 1;
        for i in 0u32..(exponent as u32) {
            result = result * base;
        }
        result
    };
    
    assert_eq(power(3), 8, "2^3 should equal 8");
    assert_eq(power(4), 16, "2^4 should equal 16");
}
```

#### Validation Logic

```rust
fn main() {
    let min_value = 10;
    let max_value = 100;
    
    // Closure for range validation
    let is_in_range = |value: Felt| -> bool {
        value >= min_value && value <= max_value
    };
    
    assert(is_in_range(50), "50 should be in range");
    assert(!is_in_range(5), "5 should not be in range");
    assert(!is_in_range(150), "150 should not be in range");
}
```

### Closure Limitations

Closures in Psy have some limitations compared to other languages:

1. **No Mutable Captures**: Closures cannot mutate captured variables
2. **No Move Semantics**: Variables are captured by value, not moved
3. **Simple Type System**: Complex generic closures are not supported

```rust
fn main() {
    let mut counter = 0;
    
    // This would not work - cannot mutate captured variables:
    // let increment = || { counter = counter + 1; };
    
    // Instead, return new values:
    let next_value = |current: Felt| -> Felt { current + 1 };
    
    counter = next_value(counter);
    assert_eq(counter, 1, "Counter should be 1");
}
```

### Practical Closure Use Cases

#### Configuration-based Operations

```rust
fn main() {
    let config_multiplier = 5;
    let config_offset = 10;
    
    // Closure encapsulates configuration
    let transform_value = |input: Felt| -> Felt {
        (input * config_multiplier) + config_offset
    };
    
    let result1 = transform_value(3);  // (3 * 5) + 10 = 25
    let result2 = transform_value(7);  // (7 * 5) + 10 = 45
    
    assert_eq(result1, 25, "Transform of 3 should be 25");
    assert_eq(result2, 45, "Transform of 7 should be 45");
}
```

#### Conditional Processing

```rust
fn main() {
    let threshold = 50;
    let bonus_rate = 2;
    
    // Closure for bonus calculation
    let calculate_bonus = |base_amount: Felt| -> Felt {
        if base_amount > threshold {
            base_amount * bonus_rate
        } else {
            base_amount
        }
    };
    
    assert_eq(calculate_bonus(30), 30, "No bonus for 30");
    assert_eq(calculate_bonus(60), 120, "Double bonus for 60");
}
```

### Best Practices

1. **Keep closures simple** - Complex logic should be in named functions
2. **Use descriptive variable names** - Even in short closures
3. **Prefer explicit types** - When the closure interface is important
4. **Consider function alternatives** - For reusable logic

```rust
// Good: Simple, clear closure
fn main() {
    let double = |x: Felt| -> Felt { x * 2 };
    
    // Good: Explicit types for important interfaces
    let validator = |amount: Felt| -> bool { amount > 0 };
    
    // Consider: Named function for complex logic
    fn complex_calculation(a: Felt, b: Felt, c: Felt) -> Felt {
        if a > b {
            a * c + b
        } else {
            b * c + a
        }
    }
}
```

## Summary

Closures in Psy provide a way to create anonymous functions that can capture variables from their environment. They are useful for:

- **Simple transformations** and calculations
- **Configuration-based operations** that capture settings
- **Callback-style patterns** when passing to other functions
- **Encapsulating logic** with captured context

While more limited than closures in some languages, Psy closures are sufficient for most functional programming patterns needed in smart contract development.