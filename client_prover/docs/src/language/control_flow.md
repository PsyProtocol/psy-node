# Control Flow

## If Statements

```rust
fn min(a: Felt, b: Felt) -> Felt {
    if a < b {
        a
    } else {
        b
    }
}
```

## While Loops

```rust
fn main() -> Felt {
    let mut res: Felt = 0;
    let mut i: Felt = 0;
    while i < 10 {
        res += i;
        i += 1;
    }
    res
}
```

## Match Expressions

```rust
fn match_test_case(input: Felt) -> Felt {
    match input {
        0 => 10,
        1 => 20,
        _ => 30,
    }
}
```
