# Arrays and Tuples

## Arrays

```rust
fn main() -> Felt {
    let arr: [Felt; 2] = [1, 2];
    arr[0]
}
```

## Tuples

```rust
fn main() -> Felt {
    let t: (Felt, Felt) = (1, 2);
    t.0 + t.1
}
```
