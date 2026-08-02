# Traits and Generics

This chapter covers traits (defining shared behavior) and generics (type flexibility) in Psy, including generic constraints and advanced patterns.

## Traits

Traits define shared behavior that can be implemented by different types. They are similar to interfaces in other languages.

### Basic Trait Definition

```rust
// Define a trait with required methods
pub trait Calculable {
    pub fn calculate() -> Felt;
    pub fn multiply(factor: Felt) -> Felt;
}
```

### Implementing Traits

```rust
pub trait Value {
    pub fn value() -> Felt;
}

// Implement the trait for a struct
struct Two {}
impl Value for Two {
    pub fn value() -> Felt {
        2
    }
}

struct Ten {}
impl Value for Ten {
    pub fn value() -> Felt {
        10
    }
}

fn main() {
    assert_eq(Two::value(), 2, "Two should return 2");
    assert_eq(Ten::value(), 10, "Ten should return 10");
}
```

### Traits with Parameters

```rust
pub trait Arithmetic {
    pub fn add(a: Felt, b: Felt) -> Felt;
    pub fn subtract(a: Felt, b: Felt) -> Felt;
    pub fn multiply(a: Felt, b: Felt) -> Felt;
}

struct Calculator {}

impl Arithmetic for Calculator {
    pub fn add(a: Felt, b: Felt) -> Felt {
        a + b
    }
    
    pub fn subtract(a: Felt, b: Felt) -> Felt {
        a - b
    }
    
    pub fn multiply(a: Felt, b: Felt) -> Felt {
        a * b
    }
}

fn main() {
    let sum = Calculator::add(5, 3);
    let product = Calculator::multiply(4, 7);
    
    assert_eq(sum, 8, "5 + 3 should equal 8");
    assert_eq(product, 28, "4 * 7 should equal 28");
}
```

### Traits with Self Parameter

```rust
pub trait Comparable {
    pub fn is_greater_than(self, other: Self) -> bool;
    pub fn is_equal_to(self, other: Self) -> bool;
}

struct Number {
    pub value: Felt,
}

impl Comparable for Number {
    pub fn is_greater_than(self, other: Self) -> bool {
        self.value > other.value
    }
    
    pub fn is_equal_to(self, other: Self) -> bool {
        self.value == other.value
    }
}

fn main() {
    let num1 = new Number { value: 10 };
    let num2 = new Number { value: 5 };
    
    assert(num1.is_greater_than(num2), "10 should be greater than 5");
    assert(!num1.is_equal_to(num2), "10 should not equal 5");
}
```

## Generics

Generics allow you to write code that works with multiple types while maintaining type safety.

### Generic Functions

```rust
// Generic function with type parameter T
fn identity<T>(value: T) -> T {
    value
}

fn main() {
    let felt_value = identity(42);
    let bool_value = identity(true);
    
    assert_eq(felt_value, 42, "Identity should return the same Felt value");
    assert(bool_value, "Identity should return the same bool value");
}
```

### Generic Structs

```rust
// Generic struct that can hold any type
struct Container<T> {
    pub item: T,
}

impl<T> Container<T> {
    pub fn new(item: T) -> Self {
        new Container { item }
    }
    
    pub fn get(self) -> T {
        self.item
    }
}

fn main() {
    let felt_container = Container::new(100);
    let bool_container = Container::new(false);
    
    assert_eq(felt_container.get(), 100, "Container should hold Felt value");
    assert(!bool_container.get(), "Container should hold bool value");
}
```

### Multiple Generic Parameters

```rust
struct Pair<T, U> {
    pub first: T,
    pub second: U,
}

impl<T, U> Pair<T, U> {
    pub fn new(first: T, second: U) -> Self {
        new Pair { first, second }
    }
    
    pub fn get_first(self) -> T {
        self.first
    }
    
    pub fn get_second(self) -> U {
        self.second
    }
}

fn main() {
    let number_pair = Pair::new(42, 84);
    let mixed_pair = Pair::new(10, true);
    
    assert_eq(number_pair.get_first(), 42, "First should be 42");
    assert_eq(number_pair.get_second(), 84, "Second should be 84");
    assert_eq(mixed_pair.get_first(), 10, "First should be 10");
    assert(mixed_pair.get_second(), "Second should be true");
}
```

## Generic Constraints (Trait Bounds)

Generic constraints allow you to specify that generic types must implement certain traits.

### Simple Trait Bounds

```rust
pub trait Valuable {
    pub fn get_value() -> Felt;
}

struct Gold {}
impl Valuable for Gold {
    pub fn get_value() -> Felt {
        1000
    }
}

struct Silver {}
impl Valuable for Silver {
    pub fn get_value() -> Felt {
        100
    }
}

// Generic function constrained to types that implement Valuable
fn calculate_total_value<T: Valuable>(items: [T; 3]) -> Felt {
    T::get_value() + T::get_value() + T::get_value()
}

fn main() {
    let gold_items = [new Gold {}, new Gold {}, new Gold {}];
    let total_gold_value = calculate_total_value(gold_items);
    
    assert_eq(total_gold_value, 3000, "Three gold items should be worth 3000");
}
```

### Multiple Trait Bounds

```rust
pub trait Addable {
    pub fn add(self, other: Self) -> Self;
}

pub trait Comparable {
    pub fn is_greater(self, other: Self) -> bool;
}

struct Number {
    pub value: Felt,
}

impl Addable for Number {
    pub fn add(self, other: Self) -> Self {
        new Number { value: self.value + other.value }
    }
}

impl Comparable for Number {
    pub fn is_greater(self, other: Self) -> bool {
        self.value > other.value
    }
}

// Function with multiple trait bounds
fn process_numbers<T: Addable + Comparable>(a: T, b: T) -> T {
    let sum = a.add(b);
    if sum.is_greater(a) {
        sum
    } else {
        a
    }
}

fn main() {
    let num1 = new Number { value: 10 };
    let num2 = new Number { value: 5 };
    let result = process_numbers(num1, num2);
    
    assert_eq(result.value, 15, "Result should be the sum: 15");
}
```

### Where Clauses

For complex constraints, you can use `where` clauses for better readability:

```rust
pub trait Convertible<T> {
    pub fn convert(self) -> T;
}

pub trait Validatable {
    pub fn is_valid(self) -> bool;
}

struct Source {
    pub data: Felt,
}

struct Target {
    pub result: Felt,
}

impl Convertible<Target> for Source {
    pub fn convert(self) -> Target {
        new Target { result: self.data * 2 }
    }
}

impl Validatable for Target {
    pub fn is_valid(self) -> bool {
        self.result > 0
    }
}

// Complex generic function with where clause
fn transform_and_validate<T, U>(source: T) -> U 
where 
    T: Convertible<U>,
    U: Validatable,
{
    let target = source.convert();
    if target.is_valid() {
        target
    } else {
        panic("Invalid conversion result")
    }
}

fn main() {
    let source = new Source { data: 10 };
    let target = transform_and_validate(source);
    
    assert_eq(target.result, 20, "Converted value should be 20");
}
```

### Generic Constraints in Struct Definitions

```rust
pub trait Numeric {
    pub fn zero() -> Self;
    pub fn add(self, other: Self) -> Self;
}

struct Counter<T: Numeric> {
    pub value: T,
}

impl<T: Numeric> Counter<T> {
    pub fn new() -> Self {
        new Counter { value: T::zero() }
    }
    
    pub fn increment(self, amount: T) -> Self {
        new Counter { value: self.value.add(amount) }
    }
}

struct Felt_{}
impl Numeric for Felt {
    pub fn zero() -> Self {
        0
    }
    
    pub fn add(self, other: Self) -> Self {
        self + other
    }
}

fn main() {
    let counter = Counter#<Felt>::new();
    let incremented = counter.increment(5);
    
    assert_eq(incremented.value, 5, "Counter should be incremented to 5");
}
```

## Advanced Generic Patterns

### Associated Types in Traits

```rust
pub trait Iterator {
    type Item;
    
    pub fn next(self) -> Self::Item;
    pub fn has_next(self) -> bool;
}

struct NumberIterator {
    pub current: Felt,
    pub max: Felt,
}

impl Iterator for NumberIterator {
    type Item = Felt;
    
    pub fn next(self) -> Self::Item {
        let current = self.current;
        self.current = self.current + 1;
        current
    }
    
    pub fn has_next(self) -> bool {
        self.current < self.max
    }
}

fn collect_items<I: Iterator>(mut iterator: I) -> [I::Item; 3] {
    let item1 = iterator.next();
    let item2 = iterator.next();
    let item3 = iterator.next();
    [item1, item2, item3]
}

fn main() {
    let iterator = new NumberIterator { current: 1, max: 10 };
    let items = collect_items(iterator);
    
    assert_eq(items[0], 1, "First item should be 1");
    assert_eq(items[1], 2, "Second item should be 2");
    assert_eq(items[2], 3, "Third item should be 3");
}
```

### Generic Trait Implementations

```rust
pub trait Serializable {
    pub fn serialize() -> [Felt; 4];
}

struct Data<T> {
    pub value: T,
}

// Generic implementation for Data<Felt>
impl Serializable for Data<Felt> {
    pub fn serialize() -> [Felt; 4] {
        [self.value, 0, 0, 0]
    }
}

// Specialized implementation for Data<bool>
impl Serializable for Data<bool> {
    pub fn serialize() -> [Felt; 4] {
        let bool_value = if self.value { 1 } else { 0 };
        [bool_value, 1, 0, 0]  // 1 indicates boolean type
    }
}

fn main() {
    let felt_data = new Data { value: 42 };
    let bool_data = new Data { value: true };
    
    let felt_serialized = felt_data.serialize();
    let bool_serialized = bool_data.serialize();
    
    assert_eq(felt_serialized[0], 42, "Felt data should serialize correctly");
    assert_eq(bool_serialized[0], 1, "Bool data should serialize correctly");
    assert_eq(bool_serialized[1], 1, "Bool type indicator should be 1");
}
```

### Default Implementations

```rust
pub trait Describable {
    pub fn name() -> [u8; 32];
    
    // Default implementation
    pub fn description() -> [u8; 64] {
        let name_bytes = Self::name();
        // Simple default description
        let mut desc = [0u8; 64];
        // Copy name to description (simplified)
        desc[0] = name_bytes[0];
        desc[1] = name_bytes[1];
        desc
    }
}

struct Product {
    pub id: Felt,
}

impl Describable for Product {
    pub fn name() -> [u8; 32] {
        // Simplified name representation
        [80u8, 114u8, 111u8, 100u8, 117u8, 99u8, 116u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8] // "Product"
    }
    
    // description() is inherited from default implementation
}

fn main() {
    let name = Product::name();
    let desc = Product::description();
    
    assert_eq(name[0], 80u8, "Name should start with 'P'");
    assert_eq(desc[0], 80u8, "Description should start with name");
}
```

## Best Practices

### 1. Use Descriptive Trait Names

```rust
// Good: Clear intent
pub trait Validateable {
    pub fn is_valid(self) -> bool;
}

pub trait Convertible<T> {
    pub fn convert(self) -> T;
}

// Avoid: Unclear purpose
pub trait Helper {
    pub fn help();
}
```

### 2. Keep Trait Interfaces Small

```rust
// Good: Single responsibility
pub trait Readable {
    pub fn read() -> [u8; 32];
}

pub trait Writable {
    pub fn write(data: [u8; 32]);
}

// Better than: Large interface
pub trait FileHandler {
    pub fn read() -> [u8; 32];
    pub fn write(data: [u8; 32]);
    pub fn delete();
    pub fn copy();
    // ... too many responsibilities
}
```

### 3. Use Generic Constraints Wisely

```rust
// Good: Specific constraints
fn process_numeric<T: Addable + Comparable>(data: T) -> T {
    // Implementation
    data
}

// Avoid: Over-constraining
fn simple_function<T: TraitA + TraitB + TraitC + TraitD>(data: T) -> T {
    // Only uses TraitA functionality
    data
}
```

### 4. Prefer Associated Types for Single Relationships

```rust
// Good: One-to-one relationship
pub trait Iterator {
    type Item;
    pub fn next() -> Self::Item;
}

// Less ideal: Generic parameter when association is clear
pub trait Iterator2<Item> {
    pub fn next() -> Item;
}
```

## Limitations

Current limitations of traits and generics in Psy:

1. **No Higher-Kinded Types**: Cannot abstract over type constructors
2. **Limited Type Inference**: Explicit type annotations often required
3. **No Conditional Compilation**: Cannot conditionally implement traits
4. **Simple Constraint Syntax**: More complex constraint expressions not supported

```rust
// This works
fn simple_generic<T: SomeTrait>(value: T) -> T {
    value
}

// This doesn't work - complex constraints not supported
// fn complex_generic<T>(value: T) -> T 
// where 
//     T: TraitA,
//     T::Associated: TraitB,
//     for<'a> &'a T: TraitC,
// {
//     value
// }
```

## Summary

Traits and generics in Psy provide:

- **Code reuse** through shared behavior definitions
- **Type safety** with compile-time type checking
- **Flexibility** through generic programming
- **Constraints** to ensure types meet requirements
- **Default implementations** for common functionality

These features enable building robust, reusable smart contract components while maintaining the security and predictability required for blockchain applications.