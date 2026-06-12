# Structs and Implementations

Structs define custom data types, and `impl` blocks add methods.

## Defining a Struct

```rust
struct Person {
    pub age: Felt,
    male: bool,
}

```

## Implementing Methods

```rust
impl Person {
    pub fn get_age(self: Person) -> Felt {
        return self.age;
    }
}
```

## Usage

```rust
fn main() -> Felt {
    let p: Person = new Person { age: 20, male: true };
    p.get_age()
}
```
