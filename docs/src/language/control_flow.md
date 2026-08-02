# Conditional Statements

This chapter covers conditional control flow in Psy: `if`, `else if`, `else`, and `match` expressions.

## If Statements

### Basic If-Else

The most basic form of conditional control flow is the `if` expression:

```rust
fn min(a: Felt, b: Felt) -> Felt {
    if a < b {
        a
    } else {
        b
    }
}

fn main() {
    let x = 5;
    let y = 10;
    let result = min(x, y);
    // result is 5
}
```

### If as Expression

In Psy, `if` is an expression that returns a value:

```rust
fn main() {
    let a = 10;
    let b = 11;
    let c = 12;
    let d = 13;
    
    // If expression assigned to variable
    let basic = if a > b {
        c
    } else {
        d
    };
    
    // basic will be 13 since 10 > 11 is false
}
```

### If-Else If-Else Chains

You can chain multiple conditions using `else if`:

```rust
fn main() {
    let a = 10;
    let b = 11;
    let c = 12;
    let d = 13;
    let e = 14;
    
    let result = if a > b {
        c
    } else if b > a {
        d
    } else {
        e
    };
    
    // result will be 13 since b > a (11 > 10) is true
}
```

### Nested If Statements

If statements can be nested within other if statements:

```rust
fn middle(a: Felt, b: Felt, c: Felt) -> Felt {
    if a > b {
        if b > c {
            b
        } else if a > c {
            c
        } else {
            a
        }
    } else {
        if a > c {
            a
        } else if b > c {
            c
        } else {
            b
        }
    }
}

fn main() {
    let result = middle(5, 3, 7); // Returns 5
    let result2 = middle(1, 8, 4); // Returns 4
}
```

### Complex Nested Examples

```rust
fn main() {
    let a = 10;
    let b = 11;
    let c = 12;
    let d = 13;
    let e = 14;
    
    // Nested if with multiple else if branches
    let embedded = if a > b {
        if a > b {
            c
        } else if b > a {
            d
        } else {
            e
        }
    } else if c > d {
        if a > b {
            c
        } else if b > a {
            d
        } else {
            e
        }
    } else {
        if a > b {
            c
        } else if b > a {
            d
        } else {
            e
        }
    };
}
```

### If with Local Variables

You can declare variables inside if blocks:

```rust
fn main() {
    let a = 1;
    let b = 2;
    let c = 3;
    let d = 4;
    
    let result = if a > b {
        let tmp0 = 1;
        let tmp1 = 2;
        if tmp0 > tmp1 {
            tmp0
        } else {
            tmp1
        }
    } else if c > d {
        let tmp2 = 3;
        let tmp3 = 4;
        if tmp2 > tmp3 {
            tmp2
        } else {
            tmp3
        }
    } else {
        let tmp4 = 5;
        let tmp5 = 6;
        if tmp4 > tmp5 {
            tmp4
        } else {
            tmp5
        }
    };
}
```

### If in Function Calls

If expressions can be used as arguments to function calls:

```rust
fn process(x: Felt, y: Felt) {
    // Function body
}

fn main() {
    let n1 = 1;
    let n2 = 2;
    
    process(if n1 > n2 {
        n1
    } else {
        n2
    }, n2);
}
```

## Match Expressions

Match expressions provide a powerful way to handle multiple possible values:

### Basic Match

```rust
fn match_test_case(input: Felt) -> Felt {
    match input {
        0 => 10,
        1 => 20,
        2 => 30,
        _ => 40,  // Default case
    }
}

fn main() {
    let result1 = match_test_case(0); // Returns 10
    let result2 = match_test_case(1); // Returns 20
    let result3 = match_test_case(5); // Returns 40 (default case)
}
```

### Match with Blocks

Match arms can contain blocks for more complex logic:

```rust
fn match_with_blocks(input: Felt) -> Felt {
    let mut result = 0;
    match input {
        0 => {
            result += 10;
        },
        1 => {
            result += 20;
        },
        2 => {
            result += 30;
        },
        3 => {
            result += 40;
        },
        4 => {
            result += 40;
        },
        _ => {
            result += 50;
        },
    };
    result
}
```

### Match as Expression

Match can be used as an expression to assign values:

```rust
fn main() {
    let input = 2;
    
    let base_value = match input {
        0 => 100,
        1 => 200,
        2 => 300,
        _ => 400,
    };
    
    // base_value will be 300
}
```

### Match with Different Types

Match works with various types:

```rust
// Match with bool
fn match_bool_test(input: bool) -> Felt {
    match input {
        true => 100,
        false => 200,
    }
}

// Match with u32
fn match_u32_test(input: u32) -> Felt {
    let mut result = 0;
    match input {
        0u32 => {
            result += 5;
        },
        1u32 => {
            result += 15;
        },
        2u32 => {
            result += 25;
        },
        3u32 => {
            result += 35;
        },
        4u32 => {
            result += 45;
        },
        _ => {
            result += 55;
        },
    };
    
    let extra = match input {
        0u32 => 50,
        1u32 => 150,
        2u32 => 250,
        3u32 => 350,
        _ => 450,
    };
    
    result + extra
}

fn main() {
    let bool_result = match_bool_test(true);  // Returns 100
    let u32_result = match_u32_test(2u32);   // Returns 275 (25 + 250)
}
```

### Complex Match Example

```rust
fn complex_match_example(input: Felt) -> Felt {
    let base = match input {
        0 => {
            let temp = 10;
            temp * 2
        },
        1 => {
            let temp = 20;
            temp + 5
        },
        2 => {
            let temp = 30;
            temp - 5
        },
        _ => {
            let temp = 40;
            temp + 10
        },
    };
    
    let multiplier = match input {
        0 => 2,
        1 => 2,
        2 => 3,
        _ => 1,
    };
    
    base * multiplier
}
```


## Current Limitations

**Multiple Patterns**: Multiple patterns in match expressions (e.g., `0 | 1 => value`) are not currently supported. Use separate match arms for each pattern:

```rust
// ❌ Not supported
match value {
    0 | 1 => result1,
    2 | 3 => result2,
    _ => default,
}

// ✅ Use this instead
match value {
    0 => result1,
    1 => result1,
    2 => result2,
    3 => result2,
    _ => default,
}
```

## Important Notes

### No Early Returns in Conditionals

**Important:** Psy does not support early returns within if statements:

```rust
fn example(x: Felt) -> Felt {
    // ❌ This will cause a compilation error
    // if x > 10 {
    //     return x * 2;
    // }
    
    // ✅ Use expression-based returns instead
    if x > 10 {
        x * 2
    } else {
        x
    }
}
```

### Expression-Based Design

Both `if` and `match` are expressions in Psy, meaning they return values that can be assigned to variables or used in other expressions:

```rust
fn main() {
    let x = 5;
    
    // If as expression
    let result1 = if x > 0 { x } else { -x };
    
    // Match as expression  
    let result2 = match x {
        0 => 0,
        n => n * 2,
    };
    
    // Can be used in function calls
    process_value(if x > 0 { x } else { 0 });
}

fn process_value(value: Felt) {
    // Function implementation
}
```

## Key Points

1. **If statements** are expressions that return values
2. **Else if** allows chaining multiple conditions
3. **Nested if statements** are fully supported
4. **Match expressions** provide pattern matching capabilities
5. **No early returns** are allowed in conditional blocks
6. **All branches** of an if expression must return the same type
7. **Default case** in match expressions uses `_` wildcard
8. **Both if and match** can be used anywhere expressions are expected
