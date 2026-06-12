# Modules and Visibility

Modules organize code and control visibility.

## Defining a Module

```rust
mod math {
    pub fn max(a: Felt, b: Felt) -> Felt {
        return a * ((a > b) as Felt) + b * ((a <= b) as Felt);
    }
}
```

## Using Modules
```rust
use math::*;
fn main() -> Felt {
    max(1, 2)
}
```

## Visibility
`pub`: Makes an item public.  
`No modifier`: Private to the module.
