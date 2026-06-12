# Functions and Closures

## Functions

```rust
fn add(a: Felt, b: Felt) -> Felt {
    a + b
}
```

## Closures

```rust
fn main() -> Felt {
    let max = |a: Felt, b: Felt| -> Felt {
        a * ((a > b) as Felt) + b * ((a <= b) as Felt)
    };
    max(1, 2)
}
```
