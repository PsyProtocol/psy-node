# Structs and Implementations

Structs define custom data types that group related data together, and `impl` blocks add methods to operate on that data. This chapter covers struct definition, implementation patterns, and method types.

## Defining Structs

### Basic Struct Definition

```rust
// Public struct with mixed field visibility
pub struct Person {
    pub age: Felt,        // Public field - accessible from anywhere
    pub name_hash: Felt,  // Public field
    is_active: bool,      // Private field - only accessible within this module
}

// Private struct - only accessible within this module
struct InternalData {
    value: Felt,          // Private field in private struct
}

pub struct Point {
    pub x: Felt,          // Public field
    pub y: Felt,          // Public field
}

pub struct Rectangle {
    pub top_left: Point,  // Public field
    pub width: Felt,      // Public field
    pub height: Felt,     // Public field
}
```

### Visibility Rules

**Struct Visibility:**
- `struct Name` - Private struct, only accessible within the same module
- `pub struct Name` - Public struct, accessible from other modules

**Field Visibility:**
- `field: Type` - Private field, only accessible within the struct's own methods
- `pub field: Type` - Public field, accessible wherever the struct is accessible

```rust
// Examples of visibility combinations
pub struct PublicStruct {
    pub public_field: Felt,    // ✅ Accessible wherever struct is accessible
    private_field: Felt,       // ❌ Only accessible within struct's own methods
}

struct PrivateStruct {
    pub public_field: Felt,    // ❌ Still not accessible outside module (struct is private)
    private_field: Felt,       // ❌ Only accessible within struct's own methods
}

// Demonstrating private field access
pub struct BankAccount {
    pub account_number: Felt,
    balance: Felt,  // Private - can only be accessed via methods
}

impl BankAccount {
    pub fn new(account_number: Felt, initial_balance: Felt) -> BankAccount {
        return new BankAccount {
            account_number: account_number,
            balance: initial_balance,  // ✅ Can access private field in constructor
        };
    }
    
    pub fn get_balance(self) -> Felt {
        return self.balance;  // ✅ Can access private field in method
    }
    
    pub fn deposit(mut self, amount: Felt) -> BankAccount {
        self.balance = self.balance + amount;  // ✅ Can modify private field in method
        return self;
    }
}
```

### Structs with Arrays and Tuples

```rust
struct Vector3D {
    pub components: [Felt; 3],
    pub magnitude: Felt,
}

struct BoundingBox {
    pub corners: (Point, Point), // (min_corner, max_corner)
    pub is_valid: bool,
}

struct Matrix2x2 {
    pub data: [[Felt; 2]; 2],
    pub determinant: Felt,
}
```

## Implementation Blocks

### Instance Methods

Instance methods operate on a specific instance of the struct. In Psy, the `self` parameter follows the same passing rules as function parameters:

**`self` Parameter Passing:**
- **Structs with only value types** (Felt, u32, bool) - Passed by copy
- **Structs with reference types** (arrays, other structs) - Passed by move/reference
- **Mixed structs** - Follow the most restrictive member (move/reference if any member requires it)

**Important:** Psy only supports `self` and `mut self` syntax, never `&self` or `&mut self`.

**Method Visibility:**
- `fn method_name` - Private method, only callable within the same module
- `pub fn method_name` - Public method, callable wherever the struct is accessible

```rust
impl Point {
    // Public instance method - accessible from anywhere
    pub fn distance_from_origin(self) -> Felt {
        // Simplified distance calculation
        return self.x + self.y;
    }
    
    // Public instance method that modifies the point
    pub fn translate(mut self, dx: Felt, dy: Felt) -> Point {
        self.x = self.x + dx;
        self.y = self.y + dy;
        return self;
    }
    
    // Public instance method that uses other structs
    pub fn distance_to(self, other: Point) -> Felt {
        return self.calculate_manhattan_distance(other);
    }
    
    // Private helper method - only usable within this module
    fn calculate_manhattan_distance(self, other: Point) -> Felt {
        let dx = if self.x > other.x { self.x - other.x } else { other.x - self.x };
        let dy = if self.y > other.y { self.y - other.y } else { other.y - self.y };
        return dx + dy;
    }
}
```

### Static Methods (Associated Functions)

Static methods don't take `self` and are called on the type itself, not an instance.

```rust
impl Point {
    // Static method - constructor
    pub fn new(x: Felt, y: Felt) -> Point {
        return new Point { x: x, y: y };
    }
    
    // Static method - create special points
    pub fn origin() -> Point {
        return new Point { x: 0, y: 0 };
    }
    
    // Static method - utility functions
    pub fn midpoint(p1: Point, p2: Point) -> Point {
        let mid_x = (p1.x + p2.x) / 2;
        let mid_y = (p1.y + p2.y) / 2;
        return new Point { x: mid_x, y: mid_y };
    }
}
```

### The `self` Parameter

**Important:** Psy only supports `self` syntax, not `&self` or `&mut self`:

```rust
impl Rectangle {
    // ✅ Valid: self moves the struct into the method
    pub fn area(self) -> Felt {
        return self.width * self.height;
    }
    
    // ✅ Valid: mut self allows modification
    pub fn scale(mut self, factor: Felt) -> Rectangle {
        self.width = self.width * factor;
        self.height = self.height * factor;
        return self;
    }
    
    // ✅ Valid: self is alias for self: Self
    pub fn perimeter(self) -> Felt {
        return 2 * (self.width + self.height);
    }
    
    // ❌ Invalid: Psy doesn't support reference syntax
    // pub fn invalid_method(&self) -> Felt { ... }
    // pub fn invalid_mut(&mut self) { ... }
}
```

## Complex Examples

### Vector3D Implementation

```rust
impl Vector3D {
    pub fn new(x: Felt, y: Felt, z: Felt) -> Vector3D {
        let components = [x, y, z];
        let magnitude = x * x + y * y + z * z; // Simplified magnitude
        return new Vector3D {
            components: components,
            magnitude: magnitude,
        };
    }
    
    pub fn dot_product(self, other: Vector3D) -> Felt {
        return self.components[0] * other.components[0] +
               self.components[1] * other.components[1] +
               self.components[2] * other.components[2];
    }
    
    pub fn scale(mut self, factor: Felt) -> Vector3D {
        self.components[0] = self.components[0] * factor;
        self.components[1] = self.components[1] * factor;
        self.components[2] = self.components[2] * factor;
        self.magnitude = self.magnitude * (factor * factor);
        return self;
    }
    
    pub fn get_x(self) -> Felt {
        return self.components[0];
    }
    
    pub fn get_y(self) -> Felt {
        return self.components[1];
    }
    
    pub fn get_z(self) -> Felt {
        return self.components[2];
    }
}
```

### Matrix2x2 Implementation

```rust
impl Matrix2x2 {
    pub fn new(a: Felt, b: Felt, c: Felt, d: Felt) -> Matrix2x2 {
        let data = [[a, b], [c, d]];
        let determinant = a * d - b * c;
        return new Matrix2x2 {
            data: data,
            determinant: determinant,
        };
    }
    
    pub fn identity() -> Matrix2x2 {
        return Matrix2x2::new(1, 0, 0, 1);
    }
    
    pub fn multiply(self, other: Matrix2x2) -> Matrix2x2 {
        let a = self.data[0][0] * other.data[0][0] + self.data[0][1] * other.data[1][0];
        let b = self.data[0][0] * other.data[0][1] + self.data[0][1] * other.data[1][1];
        let c = self.data[1][0] * other.data[0][0] + self.data[1][1] * other.data[1][0];
        let d = self.data[1][0] * other.data[0][1] + self.data[1][1] * other.data[1][1];
        
        return Matrix2x2::new(a, b, c, d);
    }
    
    pub fn apply_to_point(self, point: Point) -> Point {
        let new_x = self.data[0][0] * point.x + self.data[0][1] * point.y;
        let new_y = self.data[1][0] * point.x + self.data[1][1] * point.y;
        return new Point { x: new_x, y: new_y };
    }
}
```

## Usage Examples

```rust
#[test]
fn test_point_operations() {
    // Using static methods
    let origin = Point::origin();
    let p1 = Point::new(3, 4);
    let p2 = Point::new(6, 8);
    
    // Using instance methods
    let distance = p1.distance_from_origin();
    let moved = p1.translate(2, 1);
    let mid = Point::midpoint(p1, p2);
    
    assert_eq(distance, 7, "distance should be 3 + 4 = 7");
    assert_eq(moved.x, 5, "moved x should be 3 + 2 = 5");
    assert_eq(mid.x, 4, "midpoint x should be (3 + 6) / 2 = 4");
}

#[test]
fn test_vector_operations() {
    let v1 = Vector3D::new(1, 2, 3);
    let v2 = Vector3D::new(4, 5, 6);
    
    let dot = v1.dot_product(v2);
    let scaled = v1.scale(2);
    
    assert_eq(dot, 32, "dot product should be 1*4 + 2*5 + 3*6 = 32");
    assert_eq(scaled.get_x(), 2, "scaled x should be 1 * 2 = 2");
}

#[test]
fn test_matrix_operations() {
    let m1 = Matrix2x2::new(1, 2, 3, 4);
    let identity = Matrix2x2::identity();
    let point = Point::new(5, 7);
    
    let result = m1.multiply(identity);
    let transformed = m1.apply_to_point(point);
    
    assert_eq(result.data[0][0], 1, "identity multiplication preserves values");
    assert_eq(transformed.x, 19, "transformed x should be 1*5 + 2*7 = 19");
}
```

## Method Call Syntax

```rust
// Both syntaxes are equivalent
let p = Point::new(3, 4);

// Method syntax (recommended)
let distance1 = p.distance_from_origin();

// Function syntax (also valid)
let distance2 = Point::distance_from_origin(p);

// Static methods can only be called with :: syntax
let origin = Point::origin();
let mid = Point::midpoint(p1, p2);
```
