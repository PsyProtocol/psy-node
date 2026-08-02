# Operators

This chapter covers all operators available in Psy, including arithmetic, logical, comparison, bitwise, and special operators.

## Arithmetic Operators

### Basic Arithmetic

Psy supports standard arithmetic operations for both `Felt` and `u32` types:

```rust
fn main() {
    let a = 10;
    let b = 3;
    
    // Addition
    let sum = a + b;        // 13
    
    // Subtraction
    let diff = a - b;       // 7
    
    // Multiplication
    let product = a * b;    // 30
    
    // Division
    let quotient = a / b;   // 3 (integer division)
    
    // Modulo
    let remainder = a % b;  // 1
}
```

### Exponentiation

Psy provides the exponentiation operator `**`:

```rust
fn main() {
    let base = 2;
    let exponent = 8;
    let result = base ** exponent;  // 256
    
    // u32 exponentiation
    let u32_base = 2u32;
    let u32_exp = 5u32;
    let u32_result = u32_base ** u32_exp;  // 32u32
    
    // Large numbers
    let large = 2 ** 64;  // 4294967295
}
```

### Unary Operators

```rust
fn main() {
    let positive = 5;
    let negative = -positive;  // -5
    
    // Negation of zero
    let zero = 0;
    let neg_zero = -zero;  // Still 0
}
```

## Comparison Operators

All comparison operators return `bool` values:

```rust
fn main() {
    let a = 10;
    let b = 5;
    let c = 10;
    
    // Equality
    let equal = a == c;        // true
    let not_equal = a != b;    // true
    
    // Ordering
    let less = b < a;          // true
    let less_equal = b <= a;   // true
    let greater = a > b;       // true
    let greater_equal = a >= c; // true
}
```

### Type-specific Comparisons

```rust
fn main() {
    // u32 comparisons
    let u32_a = 100u32;
    let u32_b = 50u32;
    let u32_less = u32_b < u32_a;  // true
    
    // bool comparisons
    let bool_a = true;
    let bool_b = false;
    let bool_equal = bool_a == bool_b;  // false
}
```

## Logical Operators

### Boolean Logic

Logical operators work with `bool` types:

```rust
fn main() {
    let true_val = true;
    let false_val = false;
    
    // Logical AND
    let and_result = true_val && false_val;   // false
    
    // Logical OR
    let or_result = true_val || false_val;    // true
    
    // Logical XOR
    let xor_result = true_val ^ false_val;    // true
    
    // Logical NOT
    let not_result = !false_val;              // true
}
```

### Felt Logic

For `Felt` values, logical NOT treats 0 as false and 1 as true:

```rust
fn main() {
    let zero = 0;
    let one = 1;
    
    let not_zero = !zero;  // 1 (true)
    let not_one = !one;    // 0 (false)
}
```

## Bitwise Operators (u32 only)

Bitwise operations are only available for `u32` type:

```rust
fn main() {
    let a = 0b11110000u32;  // 240
    let b = 0b00111100u32;  // 60
    
    // Bitwise AND
    let and_bits = a & b;   // 0b00110000 = 48
    
    // Bitwise OR
    let or_bits = a | b;    // 0b11111100 = 252
    
    // Bitwise XOR
    let xor_bits = a ^ b;   // 0b11001100 = 204
}
```

### Bit Shifting

```rust
fn main() {
    let value = 0b11111111u32;  // 255
    
    // Left shift
    let left_shift = value << 1u32;   // 0b11111110 = 254
    let left_shift_8 = value << 8u32; // 65280
    
    // Right shift
    let right_shift = value >> 1u32;  // 0b01111111 = 127
    let right_shift_4 = value >> 4u32; // 15
    
    // Shift by 32 or more results in zero
    let zero_result = value << 32u32;  // 0
}
```

### Advanced Bitwise Examples

```rust
fn main() {
    let max_u32 = 4294967295u32;  // 0xFFFFFFFF
    let high_bit = 2147483648u32;  // 0x80000000
    
    // Extract specific bits
    let masked = max_u32 & high_bit;  // 2147483648u32
    
    // Set all bits except high bit
    let almost_max = max_u32 ^ high_bit;  // 2147483647u32
    
    // Combine values
    let combined = high_bit | 42u32;  // 2147483690u32
}
```

## Special Operators

### Bit Manipulation Functions

Psy provides special functions for bit manipulation:

```rust
fn main() {
    let value = 12345;
    
    // Split a Felt into individual bits
    let bits = __split_bits(value, 32);  // Returns [Felt; 32]
    
    // Reconstruct from bits
    let reconstructed = __sum_bits(bits);
    // reconstructed equals original value
    
    // Working with specific bit positions
    let bit_0 = bits[0];   // Least significant bit
    let bit_15 = bits[15]; // 16th bit from right
}
```

### Advanced Bit Operations

```rust
fn main() {
    let large_number = 2 ** 32;  // 4294967296
    
    // Split into 64 bits
    let bits_64 = __split_bits(large_number, 33);  // Needs 33 bits for 2^32
    
    // Verify specific bits
    let bit_31 = bits_64[31];  // 0
    let bit_32 = bits_64[32];  // 1 (the 2^32 bit)
    
    // Reconstruct
    let sum = __sum_bits(bits_64);  // Equals large_number
}
```

## Type Casting

### Casting Between Types

```rust
fn main() {
    // bool to other types
    let bool_val = true;
    let bool_as_u32 = bool_val as u32;   // 1u32
    let bool_as_felt = bool_val as Felt;  // 1
    
    // u32 to other types
    let u32_val = 42u32;
    let u32_as_felt = u32_val as Felt;   // 42
    let u32_as_bool = 1u32 as bool;      // true (only 0 and 1 are valid)
    
    // Felt to other types
    let felt_val = 123;
    let felt_as_u32 = felt_val as u32;   // 123u32 (if in valid range)
    let felt_as_bool = 0 as bool;        // false
}
```

### Casting Constraints

```rust
fn main() {
    // Valid bool casts
    let zero_bool = 0 as bool;      // false
    let one_bool = 1 as bool;       // true
    
    // Invalid bool cast (would panic)
    // let invalid_bool = 2 as bool;  // Error: Invalid bool value
    
    // Valid u32 range
    let max_u32_felt = 4294967295;
    let valid_u32 = max_u32_felt as u32;  // 4294967295u32
    
    // Invalid u32 cast (would panic)
    // let invalid_u32 = 4294967296 as u32;  // Error: Invalid u32 value
}
```

## Field Arithmetic (Felt)

Psy operates over the Goldilocks field with prime `p = 18446744069414584321`:

```rust
fn main() {
    let zero = 0;
    let one = 1;
    let two = 2;
    
    // Field arithmetic wraps around at the prime
    let p_minus_one = zero - one;  // 18446744069414584320 (p-1)
    
    // Division in field arithmetic is multiplicative inverse
    // NOT integer division - computes x such that (divisor * x) ≡ dividend (mod p)
    let half = p_minus_one / two;  // (p-1)/2 = multiplicative inverse
    let inv_two = one / two;       // 1/2 in field arithmetic
    
    // Verify: division result times divisor equals dividend
    let verify = inv_two * two;    // Should equal 1
    
    // Multiplication
    let result = p_minus_one * p_minus_one;  // 1 (since (-1)² = 1)
}
```

### Large Number Examples

```rust
fn main() {
    // Working with large field elements
    let large = 2 ** 63;  // 9223372036854775808
    let modulo_result = large % (3 ** 35);  // 17567738638829720
    
    // Field inverse behavior
    let p = 18446744069414584321;  // Field prime
    let one = 1;
    let two = 2;
    let inv_two = one / two;  // Multiplicative inverse of 2
}
```

## Operator Precedence

Operators follow standard mathematical precedence:

1. **Unary operators**: `-`, `!`
2. **Exponentiation**: `**` (right-associative)
3. **Multiplicative**: `*`, `/`, `%`
4. **Additive**: `+`, `-`
5. **Shift**: `<<`, `>>`
6. **Bitwise AND**: `&`
7. **Bitwise XOR**: `^`
8. **Bitwise OR**: `|`
9. **Comparison**: `<`, `<=`, `>`, `>=`, `==`, `!=`
10. **Logical AND**: `&&`
11. **Logical OR**: `||`

```rust
fn main() {
    let result = 2 + 3 * 4 ** 2;  // 2 + (3 * (4 ** 2)) = 2 + 48 = 50
    let complex = 8 / 2 + 3 * 2;  // (8 / 2) + (3 * 2) = 4 + 6 = 10
    
    // Use parentheses for clarity
    let explicit = (2 + 3) * (4 ** 2);  // 5 * 16 = 80
}
```

## Type Compatibility

### Compatible Operations

```rust
fn main() {
    // Same-type operations
    let felt_result = 10 + 20;          // Felt + Felt
    let u32_result = 10u32 + 20u32;     // u32 + u32
    let bool_result = true && false;    // bool && bool
    
    // Mixed with literals
    let mixed1 = 10u32 + 5u32;          // u32 + u32 literal
    let mixed2 = 10 + 5;                // Felt + Felt literal
}
```

### Type Errors

```rust
fn main() {
    // These would cause compilation errors:
    // let invalid1 = 10 + 10u32;       // Error: Felt + u32
    // let invalid2 = true + false;     // Error: bool + bool
    // let invalid3 = 10u32 && 20u32;   // Error: u32 && u32
    
    // Use explicit casting instead:
    let valid1 = 10 + (10u32 as Felt);  // Cast u32 to Felt
    let valid2 = (10 as u32) + 10u32;   // Cast Felt to u32
}
```

## Performance Considerations

### ZK-Circuit Friendly Operations

Some operations are more efficient in zero-knowledge circuits:

```rust
fn main() {
    // Efficient: Basic arithmetic
    let efficient = a + b * c;
    
    // Less efficient: Division (requires field inversion)
    let less_efficient = a / b;
    
    // Moderately efficient: Comparisons
    let comparison = a < b;
    
    // Bit operations are expanded to constraints
    let bitwise = a_u32 & b_u32;  // Generates multiple constraints
}
```

## Key Points

1. **Arithmetic**: Standard `+`, `-`, `*`, `/`, `%`, `**` operators
2. **Comparison**: All comparison operators return `bool`
3. **Logical**: `&&`, `||`, `^`, `!` for boolean logic
4. **Bitwise**: `&`, `|`, `^`, `<<`, `>>` for `u32` only
5. **Casting**: Explicit type conversion with `as` keyword
6. **Field Arithmetic**: Operations over Goldilocks field for `Felt`
7. **Type Safety**: Operations must be between compatible types
8. **Bit Functions**: `__split_bits` and `__sum_bits` for bit manipulation
9. **Precedence**: Standard mathematical operator precedence
10. **ZK Optimization**: Some operations are more circuit-friendly than others