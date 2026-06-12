# Testing

Tests are written within modules using the `#[test]` attribute.

```rust
mod math {
    pub fn min(a: Felt, b: Felt) -> Felt {
        a * ((a < b) as Felt) + b * ((a >= b) as Felt)
    }
    mod math_tests {
        use super::*;
        #[test]
        fn test_min() {
            assert(min(2, 3) == 2, "min(2, 3) == 2");
        }
    }
}
```

run tests with [dargo] test.
