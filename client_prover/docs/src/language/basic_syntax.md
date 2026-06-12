# Basic Syntax

[Psy Smart Contract Language] uses a syntax inspired by [Rust]. Here are the basics:

## Variables

Variables are declared with `let` and can be mutable with `mut`:

```rust
let a: Felt = 1;
let mut b: Felt = 2;
b += 1;

```

 ## Comments
 Use // for single-line comments:
 Use /* */ for single-line comments:

```rust
// This is a comment
let a: Felt = 1;
```

## Types

- Felt: A goldilocks field type.
- bool: Boolean type.
- u32: 32-bit unsigned integer.
- Array
- Tuple
- Struct

