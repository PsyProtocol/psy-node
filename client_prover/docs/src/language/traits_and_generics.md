# Traits and Generics

Traits define shared behavior, and generics allow type flexibility.

## Defining a Trait

```rust
pub trait Value {
    pub fn value() -> Felt;
}
```

## Implementing a Trait

```rust
struct Two {}
impl Value for Two {
    pub fn value() -> Felt {
        2
    }
}

fn get_value<T: Value>(value: T) -> Felt {
    T::value()
}
```


