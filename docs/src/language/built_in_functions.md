# Built-in Functions and Standard Library

This chapter covers Psy's built-in functions and standard library, including context functions, storage operations, memory utilities, and low-level operations.

## Standard Library Overview

Psy provides a comprehensive standard library (`psy-std`) that includes:

- **Context Functions**: Access blockchain and execution context information
- **Storage Operations**: Read and write persistent contract storage
- **Memory Utilities**: Low-level memory operations and type utilities
- **Default Trait**: Provide default values for primitive types

All standard library functions are automatically available in every module - the prelude is automatically imported without requiring manual import statements.

## Context Functions

Context functions provide access to execution environment information, including user data, contract metadata, and checkpoint information.

### User and Contract Context

```rust
fn main() {
    // Get current user ID
    let user_id = get_user_id();
    
    // Get current contract ID
    let contract_id = get_contract_id();
    
    // Get the caller contract ID (for cross-contract calls)
    let caller_id = get_caller_contract_id();
    
    // Get user's public key hash
    let user_public_key = get_user_public_key_hash();
    
    // Get last nonce used by the user
    let nonce = get_last_nonce();
}
```

### Contract Deployment Information

```rust
fn check_contract_deployer() {
    let contract_id = get_contract_id();
    
    // Get the deployer hash of a contract
    let deployer_hash = get_contract_deployer(contract_id);
    
    // Hash is [Felt; 4] representing the deployer's public key hash
}
```

### Checkpoint and State Information

Checkpoint functions provide access to blockchain state at specific checkpoints:

```rust
fn main() {
    // Get current checkpoint ID
    let checkpoint_id = get_checkpoint_id();
    
    // Get various checkpoint data
    let users_root = get_register_users_root(checkpoint_id);
    let gutas_root = get_gutas_root(checkpoint_id);
    let contracts_root = get_deploy_contracts_root(checkpoint_id);
    
    // Get checkpoint statistics
    let fees_collected = get_fees_collected(checkpoint_id);
    let ops_processed = get_user_ops_processed(checkpoint_id);
    let total_txs = get_total_transactions(checkpoint_id);
    let slots_modified = get_slots_modified(checkpoint_id);
    
    // Get completion counts
    let contracts_completed = get_deploy_contracts_completed(checkpoint_id);
    let users_completed = get_register_users_completed(checkpoint_id);
    let gutas_completed = get_gutas_completed(checkpoint_id);
}
```

### State Access Functions

**Important**: All state in Psy is user-separated. Each user has their own isolated state tree for each contract, ensuring complete data isolation between users.

```rust
fn access_state() {
    // Read state hash from CURRENT USER's storage slot in current contract
    let slot_hash = get_state_hash_at(0); // Slot 0 for current user
    
    // Read state from another contract (still current user's state in that contract)
    let contract_height = 32;
    let other_contract_id = 123;
    let other_state = get_other_contract_state_hash_at(
        contract_height,
        other_contract_id,
        0  // slot index - still current user's state
    );
    
    // Read state from ANOTHER USER's contract instance
    // This requires explicit user_id parameter for cross-user access
    let other_user_id = 456;
    let user_contract_state = get_other_user_contract_state_hash_at(
        contract_height,
        other_user_id,      // Explicit user whose state to read
        other_contract_id,  // Contract to read from
        0                   // Slot index in that user's state
    );
    
    // Set state hash in CURRENT USER's storage (returns previous value)
    let new_hash = [1, 2, 3, 4]; // Hash type is [Felt; 4]
    let old_hash = cset_state_hash_at(0, new_hash); // Updates current user's state
}

fn user_isolation_example() {
    // Each user has completely separate state trees
    let user_a_state = get_state_hash_at(0);  // User A's slot 0
    let user_b_state = get_other_user_contract_state_hash_at(
        32,
        456,  // User B's ID
        get_contract_id(),
        0     // Same slot 0, but from User B's state tree
    );
    
    // user_a_state and user_b_state are completely independent
    // even though they're from the same contract and same slot
}
```

## Storage Operations

The storage system provides persistent data storage for contracts with built-in serialization for primitive types and arrays.

**Key Principle**: All storage is user-isolated. Each user has their own separate storage space within each contract, ensuring complete data privacy and isolation between users.

### Storage Trait

All storage-compatible types implement the `Storage` trait:

```rust
// Storage trait provides size and read/write operations
pub trait Storage {
    pub fn size() -> Felt;
    pub fn read(
        contract_state_tree_height: Felt,  // Tree height (usually 32)
        user_id: Felt,                     // Target user's ID
        contract_id: Felt,                 // Target contract's ID
        offset: Felt                       // Storage slot index
    ) -> Self;
    pub fn write(
        offset: Felt,                      // Storage slot index
        value: Self                        // Value to write
    );
}
```

#### Parameter Explanations

**For `read()` function:**
- `contract_state_tree_height`: Merkle tree height for the contract state (typically 32)
- `user_id`: The ID of the user whose storage to read from
- `contract_id`: The ID of the contract whose storage to access
- `offset`: The storage slot index (starting from 0)

**For `write()` function:**
- `offset`: The storage slot index where to write the value
- `value`: The data to store in that slot

**Important**: `write()` always writes to the current user's storage in the current contract.

### Basic Storage Operations

```rust
// Storage is automatically available for primitive types
fn storage_example() {
    let metadata = ContractMetadata::current();
    
    // Write a Felt to CURRENT USER's storage slot 0
    let value: Felt = 42;
    Felt::write(
        0,      // offset: storage slot index 
        value   // value: data to store
    );
    
    // Read from CURRENT USER's storage slot 0
    let read_value = Felt::read(
        metadata.contract_state_tree_height,  // 32 (tree height)
        metadata.user_id,                     // current user's ID
        metadata.contract_id,                 // current contract ID
        0                                     // offset: slot index to read
    );
    
    // Read from ANOTHER USER's storage
    let other_user_id = 456;
    let other_value = Felt::read(
        32,                   // contract_state_tree_height
        other_user_id,        // different user's ID
        metadata.contract_id, // same contract
        0                     // same slot, but from other user's storage
    );
    
    // Each user has their own isolated storage
    // User A writing to slot 0 does not affect User B's slot 0
    
    // Works with other primitive types (still user-isolated)
    let bool_val = true;
    bool::write(1, bool_val);  // offset=1, value=true
    
    let u32_val = 123u32;
    u32::write(2, u32_val);    // offset=2, value=123u32
}
```

### Array Storage

Arrays automatically implement storage with proper serialization:

```rust
fn array_storage_example() {
    let metadata = ContractMetadata::current();
    
    // Store an array - occupies multiple consecutive slots
    let arr: [Felt; 5] = [1, 2, 3, 4, 5];
    <[Felt; 5]>::write(
        10,  // offset: starting slot (will use slots 10-14)
        arr  // value: array data
    );
    
    // Read the entire array back
    let read_arr = <[Felt; 5]>::read(
        32,                       // contract_state_tree_height
        metadata.user_id,         // user_id: current user
        metadata.contract_id,     // contract_id: current contract
        10                        // offset: starting slot (reads slots 10-14)
    );
    
    // Arrays have size() method - returns number of slots occupied
    let array_size = <[Felt; 5]>::size(); // Returns 5 (slots)
    
    // Reading from another user's array storage
    let other_user_array = <[Felt; 5]>::read(
        32,              // contract_state_tree_height
        456,             // user_id: different user
        metadata.contract_id,  // same contract
        10               // offset: same slot range, different user's data
    );
}
```

### Storage References

`StorageRef` provides convenient access to storage with automatic metadata handling:

```rust
fn storage_ref_example() {
    let metadata = ContractMetadata::current();
    
    // Create a storage reference for a single Felt at slot 0
    let storage_ref = StorageRef::<Felt, 1u32>::new(
        0,        // offset: storage slot index
        metadata  // metadata: contains user_id, contract_id, tree_height
    );
    
    // Set value through reference (writes to current user's storage)
    storage_ref.set(42);
    
    // Get value through reference (reads from metadata-specified location)
    let value = storage_ref.get();
    
    // Array storage references support indexing
    let array_ref = StorageRef::<[Felt; 10], 1u32>::new(
        20,       // offset: starting slot for array (slots 20-29)
        metadata  // metadata: specifies which user/contract
    );
    
    // Access individual array elements
    let element_ref = array_ref.index(3); // Access element at index 3 (slot 23)
    element_ref.set(99);                  // Write to that specific element
    let element_value = element_ref.get(); // Read from that specific element
    
    // Create reference for different user's storage
    let other_metadata = ContractMetadata::new(
        metadata.contract_id, // same contract
        456                   // different user_id
    );
    let other_user_ref = StorageRef::<Felt, 1u32>::new(0, other_metadata);
    let other_value = other_user_ref.get(); // Reads from user 456's slot 0
}
```

### Contract Metadata

```rust
fn metadata_example() {
    // Get current execution context metadata
    let current_metadata = ContractMetadata::current();
    // Contains: contract_state_tree_height=32, current contract_id, current user_id
    
    // Create metadata for specific contract/user combination
    let custom_metadata = ContractMetadata::new(
        123, // contract_id: target contract
        456  // user_id: target user
    );
    // Sets: contract_state_tree_height=32, contract_id=123, user_id=456
    
    // Access metadata fields
    let contract_id = current_metadata.get_contract_id(); // Returns current contract ID
    let user_id = current_metadata.get_user_id();         // Returns current user ID
    
    // Metadata is used in storage operations to specify:
    // - Which user's storage space to access
    // - Which contract's storage to read/write
    // - The merkle tree height for state verification
}
```

## Memory Utilities

Low-level memory and type utilities for advanced operations.

### Type Transmutation

```rust
fn transmute_example() {
    // Convert between compatible types
    let felt_array: [Felt; 4] = [1, 2, 3, 4];
    
    // Transmute to different representation (Hash = [Felt; 4])
    let as_hash: Hash = transmute#<Hash>(felt_array);
    
    // Note: transmute is unsafe and requires exact size matching
}
```

### Size Information

```rust
fn size_example() {
    // Get size of types in Felt units
    let felt_size = size_of#<Felt>();     // 1
    let bool_size = size_of#<bool>();     // 1
    let u32_size = size_of#<u32>();       // 1
    let array_size = size_of#<[Felt; 10]>(); // 10
}
```

## Cross-Contract Invocation

### Deferred Calls

Psy currently supports deferred contract calls. Deferred calls execute after the current function call completes.

```rust
fn deferred_call_example() {
    let target_contract = 123;
    let method_id = 456;
    let inputs = (42, true);
    
    // Deferred call - executes after current function completes
    invoke_deferred#<(Felt, bool)>(
        target_contract,
        method_id,
        inputs
    );
}
```

**Note**: Synchronous calls (`invoke_sync`) are not currently supported.

## Default Trait

Provides default values for primitive types:

```rust
fn default_example() {
    // Get default values
    let default_felt = Felt::default();   // 0
    let default_bool = bool::default();   // false
    let default_u32 = u32::default();     // 0u32
    
    // Useful for initialization
    let mut storage_value = Felt::default();
}
```

## Low-Level Built-in Functions

These functions are prefixed with `__` and provide direct access to ZK circuit operations:

### Bit Manipulation

```rust
fn bit_operations() {
    let value = 255;
    
    // Split a Felt into individual bits
    let bits = __split_bits(value, 8);  // Split into 8 bits
    
    // Reconstruct from bits
    let reconstructed = __sum_bits(bits);
    
    // bits is [Felt; 8] where each element is 0 or 1
}
```

### Context Access (Internal)

```rust
// These are internal functions wrapped by the context module
fn internal_context() {
    let user_id = __ctx_get_user_id();
    let contract_id = __ctx_get_contract_id();
    // ... other __ctx_* functions
}
```

### Storage Access (Internal)

```rust
// Internal storage functions
fn internal_storage() {
    // Single slot read/write
    let value = __storage_read(32, 1, 2, 0); // height, user, contract, slot
    __storage_write(0, 42);
    
    // Range operations for arrays
    let range_data = __storage_read_range(32, 1, 2, 0, 5); // Read 5 slots
    __storage_write_range(0, [1, 2, 3, 4, 5]);
}
```

### Memory Operations (Internal)

```rust
// Internal memory functions
fn internal_memory() {
    let size = __mem_size_of::<Felt>();
    let converted = __mem_transmute::<Hash>([1, 2, 3, 4]);
}
```

## Utility Functions

### State Management

```rust
fn state_management() {
    // Clear the entire cached modifications (dangerous operation)
    clear_entire_tree();
    
    // This function removes all stored data - use with extreme caution
}
```

## Type Aliases

Common type aliases used throughout the standard library:

```rust
// Hash represents a 4-Felt hash value (equivalent to 4 u64 values)
// This is the fundamental storage slot type - each storage slot is a Hash
pub type Hash = [Felt; 4];
```

### Storage Slot Structure

Each storage slot in Psy is a `Hash` type:

```rust
fn slot_example() {
    // Each slot can hold 4 Felt values (4 u64s)
    let slot_data: Hash = [1, 2, 3, 4];
    
    // When you read/write storage, you're working with Hash-sized slots
    let slot_hash = get_state_hash_at(0);  // Returns Hash = [Felt; 4]
    
    // Individual Felt values are packed into these 4-element slots
}
```

## Important Notes

### Storage Considerations

1. **User Isolation**: Each user has completely separate storage - User A's slot 0 is independent of User B's slot 0
2. **Slot Structure**: Each storage slot is a Hash type (`[Felt; 4]`) that can contain 4 u64 values
3. **Slot Indexing**: Storage slots are indexed by `Felt` values starting from 0 within each user's storage space
4. **Automatic Layout**: Arrays and complex types are automatically laid out in sequential slots in user's storage
5. **Size Calculation**: Use the `size()` method to determine how many slots a type occupies
6. **Cross-User Access**: Reading another user's storage requires explicit user_id and proper permissions
7. **Cross-Contract Access**: Reading from other contracts accesses the current user's state in that contract

### Performance Implications

1. **Storage Operations**: Reading/writing storage generates ZK constraints
2. **Cross-Contract Calls**: Synchronous calls can be expensive in terms of circuit size
3. **Memory Operations**: Transmute operations should be used sparingly
4. **Bit Operations**: Bit manipulation functions expand to multiple constraints

### Security Considerations

1. **Access Control**: Context functions return current execution context - ensure proper authorization
2. **State Isolation**: Each contract has isolated storage unless explicitly accessed
3. **Transmute Safety**: Type transmutation bypasses type safety - use only when necessary
4. **Clear Operations**: `clear_entire_tree()` is irreversible

## Key Points

1. **Standard Library**: Comprehensive built-in functions for blockchain operations
2. **Context Access**: Rich execution environment information available
3. **Storage System**: Automatic serialization for primitive types and arrays
4. **Storage References**: Convenient high-level interface to storage operations  
5. **Cross-Contract Calls**: Both synchronous and deferred invocation patterns
6. **Memory Utilities**: Low-level operations for advanced use cases
7. **Default Values**: Consistent initialization patterns for all primitive types
8. **Internal Functions**: Direct access to ZK circuit operations when needed
