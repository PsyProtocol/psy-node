# Testing

Testing is an essential part of developing reliable smart contracts. Psy provides built-in support for writing and running tests using the `#[test]` attribute.

## Writing Tests

Tests in Psy are functions marked with the `#[test]` attribute. Create a test file (e.g., `test_math.psy`):

```rust
fn add_numbers(a: Felt, b: Felt) -> Felt {
    return a + b;
}

fn multiply_numbers(a: Felt, b: Felt) -> Felt {
    return a * b;
}

#[test]
fn test_addition() {
    let result = add_numbers(2, 3);
    assert_eq(result, 5, "2 + 3 should equal 5");
}

#[test]
fn test_multiplication() {
    let result = multiply_numbers(4, 5);
    assert_eq(result, 20, "4 * 5 should equal 20");
}

#[test]
fn test_zero_multiplication() {
    let result = multiply_numbers(0, 10);
    assert_eq(result, 0, "0 * 10 should equal 0");
}
```

## Running Tests

To run tests, use the `dargo test` command:

```bash
dargo test --file test_math.psy
```

This will execute all functions marked with `#[test]` and report the results.

## Test Assertions

Psy provides several assertion functions for testing:

- `assert(condition, "message")` - Assert that a condition is true
- `assert_eq(left, right, "message")` - Assert that two values are equal
- `assert_ne(left, right, "message")` - Assert that two values are not equal

Example:

```rust
#[test]
fn test_assertions() {
    let x = 10;
    let y = 5;
    
    assert(x > y, "x should be greater than y");
    assert_eq(x - y, 5, "difference should be 5");
    assert_ne(x, y, "x and y should not be equal");
}
```

## Current Limitations

**Important:** `dargo test` currently has the following limitations:

- **Single-file testing only**: Each test file must be run individually
- **No module-level testing**: You cannot test across multiple modules in a single command
- **No test discovery**: You must specify the exact file path

These limitations are being addressed in future releases.

## Best Practices

1. **Separate test files**: Keep tests in dedicated `.psy` files separate from your main code
2. **Descriptive names**: Use clear, descriptive names for test functions
3. **Clear messages**: Provide helpful assertion messages that explain what went wrong
4. **Test edge cases**: Include tests for boundary conditions and error cases

Example test structure:

```rust
// Functions to test
fn fibonacci(n: Felt) -> Felt {
    if n <= 1 {
        return n;
    };
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Test cases
#[test]
fn test_fibonacci_base_cases() {
    assert_eq(fibonacci(0), 0, "fib(0) should be 0");
    assert_eq(fibonacci(1), 1, "fib(1) should be 1");
}

#[test]
fn test_fibonacci_sequence() {
    assert_eq(fibonacci(2), 1, "fib(2) should be 1");
    assert_eq(fibonacci(3), 2, "fib(3) should be 2");
    assert_eq(fibonacci(4), 3, "fib(4) should be 3");
    assert_eq(fibonacci(5), 5, "fib(5) should be 5");
}
```