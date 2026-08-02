# Modules and Visibility

Modules in Psy organize code into logical units and control visibility of functions, structs, and other items. They help create clean, maintainable codebases for smart contracts.

## Module Basics

### Defining Modules

```rust
// Define a module for mathematical operations
mod math {
    pub fn max(a: Felt, b: Felt) -> Felt {
        if a > b {
            a
        } else {
            b
        }
    }
    
    pub fn min(a: Felt, b: Felt) -> Felt {
        if a < b {
            a
        } else {
            b
        }
    }
    
    // Private function - not accessible outside module
    fn internal_calculation(x: Felt) -> Felt {
        x * x + 1
    }
}
```

### Using Modules

```rust
// Import all public items from math module
use math::*;

fn main() {
    let maximum = max(10, 5);
    let minimum = min(10, 5);
    
    assert_eq(maximum, 10, "Max of 10 and 5 should be 10");
    assert_eq(minimum, 5, "Min of 10 and 5 should be 5");
}
```

### Selective Imports

```rust
mod utils {
    pub fn add(a: Felt, b: Felt) -> Felt {
        a + b
    }
    
    pub fn multiply(a: Felt, b: Felt) -> Felt {
        a * b
    }
    
    pub fn subtract(a: Felt, b: Felt) -> Felt {
        a - b
    }
}

// Import specific functions
use utils::add;
use utils::multiply;

fn main() {
    let sum = add(5, 3);
    let product = multiply(4, 7);
    
    // subtract is not imported, so this would not work:
    // let difference = subtract(10, 3);
    
    assert_eq(sum, 8, "5 + 3 should equal 8");
    assert_eq(product, 28, "4 * 7 should equal 28");
}
```

## Visibility Control

### Public vs Private Items

```rust
mod validation {
    // Public function - accessible outside module
    pub fn is_valid_amount(amount: Felt) -> bool {
        amount > 0 && amount <= MAX_AMOUNT
    }
    
    // Public function
    pub fn validate_user_id(user_id: Felt) -> bool {
        user_id > 0 && check_user_exists(user_id)
    }
    
    // Private constant - only accessible within module
    const MAX_AMOUNT: Felt = 1000000;
    
    // Private function - only accessible within module
    fn check_user_exists(user_id: Felt) -> bool {
        // Implementation details hidden
        user_id < 100000
    }
}

fn main() {
    use validation::*;
    
    // Can use public functions
    assert(is_valid_amount(500), "500 should be valid");
    assert(validate_user_id(123), "User 123 should be valid");
    
    // Cannot access private items:
    // let max = MAX_AMOUNT;  // Error: private constant
    // let exists = check_user_exists(123);  // Error: private function
}
```

### Struct and Trait Visibility

```rust
mod data {
    // Public struct with public fields
    pub struct PublicData {
        pub value: Felt,
        pub timestamp: Felt,
    }
    
    // Public struct with private fields
    pub struct PrivateData {
        value: Felt,  // Private field
        pub metadata: Felt,  // Public field
    }
    
    impl PrivateData {
        // Public constructor
        pub fn new(value: Felt, metadata: Felt) -> Self {
            new PrivateData { value, metadata }
        }
        
        // Public getter for private field
        pub fn get_value(self) -> Felt {
            self.value
        }
        
        // Private helper function
        fn validate_value(value: Felt) -> bool {
            value > 0
        }
    }
    
    // Public trait
    pub trait Processable {
        pub fn process() -> Felt;
    }
    
    // Private struct - not accessible outside module
    struct InternalData {
        secret: Felt,
    }
}

fn main() {
    use data::*;
    
    // Can create public struct with public fields
    let public_data = new PublicData {
        value: 100,
        timestamp: 12345
    };
    
    // Can access public fields
    let value = public_data.value;
    
    // Must use constructor for struct with private fields
    let private_data = PrivateData::new(50, 999);
    
    // Can access public field
    let metadata = private_data.metadata;
    
    // Must use getter for private field
    let hidden_value = private_data.get_value();
    
    // Cannot access private field directly:
    // let direct_value = private_data.value;  // Error: private field
    
    // Cannot create private struct:
    // let internal = new InternalData { secret: 123 };  // Error: private struct
}
```

## Nested Modules

```rust
mod contracts {
    pub mod token {
        pub fn mint(amount: Felt) -> Felt {
            amount
        }
        
        pub fn burn(amount: Felt) -> Felt {
            amount
        }
        
        mod internal {
            pub fn calculate_fee(amount: Felt) -> Felt {
                amount / 100
            }
        }
        
        // Can use nested private module within parent
        pub fn mint_with_fee(amount: Felt) -> Felt {
            use internal::calculate_fee;
            amount - calculate_fee(amount)
        }
    }
    
    pub mod nft {
        pub fn create_nft(metadata: Hash) -> Felt {
            // Implementation
            1
        }
        
        pub fn transfer_nft(token_id: Felt, to: Felt) -> bool {
            // Implementation
            true
        }
    }
}

fn main() {
    // Access nested module functions
    use contracts::token::*;
    use contracts::nft::*;
    
    let minted = mint(100);
    let minted_with_fee = mint_with_fee(100);
    let nft_id = create_nft([1, 2, 3, 4]);
    
    assert_eq(minted, 100, "Basic mint should return amount");
    assert_eq(minted_with_fee, 99, "Mint with fee should deduct 1%");
    assert_eq(nft_id, 1, "NFT creation should return token ID");
}
```

## Module Organization Patterns

### Separation by Functionality

```rust
// Authentication module
mod auth {
    pub fn verify_signature(signature: Hash, message: Hash, public_key: Hash) -> bool {
        // Signature verification logic
        true
    }
    
    pub fn hash_password(password: [u8; 32]) -> Hash {
        // Password hashing logic
        [0, 0, 0, 0]
    }
}

// Storage operations module
mod storage {
    pub fn store_user_data(user_id: Felt, data: Hash) {
        // Storage implementation
    }
    
    pub fn retrieve_user_data(user_id: Felt) -> Hash {
        // Retrieval implementation
        [0, 0, 0, 0]
    }
}

// Business logic module
mod logic {
    use auth::*;
    use storage::*;
    
    pub fn register_user(user_id: Felt, public_key: Hash, initial_data: Hash) -> bool {
        // Combine auth and storage operations
        store_user_data(user_id, initial_data);
        true
    }
    
    pub fn update_user_data(user_id: Felt, new_data: Hash, signature: Hash) -> bool {
        let stored_key = retrieve_user_data(user_id);
        if verify_signature(signature, new_data, stored_key) {
            store_user_data(user_id, new_data);
            true
        } else {
            false
        }
    }
}
```

### Contract-Specific Modules

```rust
mod token_contract {
    pub struct TokenState {
        pub total_supply: Felt,
        pub balances: [Felt; 1000000],
    }
    
    pub fn transfer(from: Felt, to: Felt, amount: Felt, state: TokenState) -> TokenState {
        // Transfer logic
        state
    }
    
    pub fn mint(to: Felt, amount: Felt, state: TokenState) -> TokenState {
        // Mint logic
        state
    }
}

mod governance_contract {
    pub struct Proposal {
        pub id: Felt,
        pub description_hash: Hash,
        pub votes_for: Felt,
        pub votes_against: Felt,
    }
    
    pub fn create_proposal(description_hash: Hash) -> Proposal {
        new Proposal {
            id: 1,
            description_hash,
            votes_for: 0,
            votes_against: 0
        }
    }
    
    pub fn vote(proposal: Proposal, vote_for: bool, weight: Felt) -> Proposal {
        if vote_for {
            new Proposal {
                id: proposal.id,
                description_hash: proposal.description_hash,
                votes_for: proposal.votes_for + weight,
                votes_against: proposal.votes_against
            }
        } else {
            new Proposal {
                id: proposal.id,
                description_hash: proposal.description_hash,
                votes_for: proposal.votes_for,
                votes_against: proposal.votes_against + weight
            }
        }
    }
}
```

## Module Constants and Types

```rust
mod constants {
    // Public constants
    pub const MAX_SUPPLY: Felt = 1000000;
    pub const MIN_TRANSFER: Felt = 1;
    pub const FEE_RATE: Felt = 100; // 1%
    
    // Private constants
    const INTERNAL_MULTIPLIER: Felt = 1337;
    
    pub fn get_adjusted_amount(amount: Felt) -> Felt {
        amount * INTERNAL_MULTIPLIER
    }
}

mod types {
    // Public type aliases
    pub type UserId = Felt;
    pub type TokenId = Felt;
    pub type Amount = Felt;
    
    // Public struct
    pub struct UserData {
        pub id: UserId,
        pub balance: Amount,
        pub last_activity: Felt,
    }
    
    // Public enum-like pattern
    pub struct TransferType {
        pub code: Felt,
    }
    
    impl TransferType {
        pub fn standard() -> Self {
            new TransferType { code: 0 }
        }
        
        pub fn fee_exempt() -> Self {
            new TransferType { code: 1 }
        }
    }
}

fn main() {
    use constants::*;
    use types::*;
    
    let user_data = new UserData {
        id: 123,
        balance: MAX_SUPPLY / 10,
        last_activity: 12345
    };
    
    let transfer_type = TransferType::standard();
    let adjusted = get_adjusted_amount(MIN_TRANSFER);
    
    assert_eq(user_data.balance, 100000, "User balance should be 10% of max supply");
}
```

## Module Re-exports

```rust
mod internal {
    pub mod crypto {
        pub fn hash(data: [u8; 32]) -> Hash {
            [0, 0, 0, 0]  // Simplified
        }
        
        pub fn verify(hash: Hash, signature: Hash) -> bool {
            true  // Simplified
        }
    }
    
    pub mod math {
        pub fn abs(x: Felt) -> Felt {
            if x < 0 { 0 - x } else { x }
        }
        
        pub fn sqrt(x: Felt) -> Felt {
            // Simplified square root
            x / 2
        }
    }
}

// Re-export selected functions for easier access
mod utils {
    // Re-export crypto functions
    pub use internal::crypto::hash;
    pub use internal::crypto::verify;
    
    // Re-export math functions with different names
    pub use internal::math::abs as absolute_value;
    pub use internal::math::sqrt as square_root;
    
    // Additional utility function
    pub fn combine_hash(a: Hash, b: Hash) -> Hash {
        let combined = [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]];
        hash([combined[0] as u8, combined[1] as u8, combined[2] as u8, combined[3] as u8])
    }
}

fn main() {
    use utils::*;
    
    let data = [1u8, 2u8, 3u8, 4u8];
    let hash_result = hash(data);
    let is_valid = verify(hash_result, [0, 0, 0, 0]);
    let abs_result = absolute_value(0 - 5);
    
    assert(is_valid, "Hash verification should succeed");
    assert_eq(abs_result, 5, "Absolute value of -5 should be 5");
}
```

## Best Practices

### 1. Organize by Domain

```rust
// Good: Clear domain separation
mod user_management {
    pub fn create_user() -> Felt { 1 }
    pub fn delete_user() -> bool { true }
}

mod token_operations {
    pub fn transfer_token() -> bool { true }
    pub fn mint_token() -> Felt { 1 }
}

// Avoid: Mixed responsibilities
mod helpers {
    pub fn create_user() -> Felt { 1 }
    pub fn transfer_token() -> bool { true }
    pub fn random_utility() -> Felt { 42 }
}
```

### 2. Use Clear Visibility

```rust
mod contract {
    // Public interface
    pub fn public_transfer(from: Felt, to: Felt, amount: Felt) -> bool {
        validate_transfer(from, to, amount)
    }
    
    // Private implementation
    fn validate_transfer(from: Felt, to: Felt, amount: Felt) -> bool {
        from != to && amount > 0
    }
}
```

### 3. Minimize Public Surface

```rust
mod api {
    // Expose only what's necessary
    pub fn process_transaction(tx_data: Hash) -> bool {
        let validated = validate_transaction(tx_data);
        if validated {
            execute_transaction(tx_data)
        } else {
            false
        }
    }
    
    // Keep implementation details private
    fn validate_transaction(tx_data: Hash) -> bool {
        tx_data[0] != 0
    }
    
    fn execute_transaction(tx_data: Hash) -> bool {
        true
    }
}
```

## Module Limitations

Current limitations in Psy modules:

1. **No Conditional Compilation**: Cannot conditionally include modules
2. **Static Structure**: Module structure must be defined at compile time
3. **No Dynamic Loading**: Cannot load modules at runtime
4. **Simple Namespace**: No complex namespace operations

```rust
// This works
mod simple_module {
    pub fn function() -> Felt { 42 }
}

// This doesn't work - conditional compilation not supported
// #[cfg(feature = "advanced")]
// mod advanced_module {
//     pub fn advanced_function() -> Felt { 42 }
// }
```

## Summary

Modules in Psy provide:

- **Code Organization** through logical grouping
- **Visibility Control** with pub/private access levels
- **Namespace Management** to avoid naming conflicts
- **Encapsulation** of implementation details
- **Reusability** through selective imports

Use modules to create clean, maintainable smart contract architectures that separate concerns and provide clear interfaces between different parts of your application.