# Storage and Contracts

This chapter covers Psy's storage system and contract development, including automatic storage generation, storage references, and contract architecture.

## Storage Architecture Overview

Psy provides a sophisticated storage system with the following characteristics:

- **Slot-based Storage**: Maximum 2^32 slots per contract, each slot is a Hash type (4 Felt values)
- **User Isolation**: Each user has completely separate storage space within each contract
- **Sequential Layout**: Data is laid out in slots according to struct field order
- **No Dynamic Types**: No dynamic arrays or mappings - all storage is statically sized
- **Automatic Code Generation**: Use `#[derive(Storage, StorageRef)]` for automated storage management

## On-Chain Storage Architecture

Psy's on-chain storage follows a hierarchical tree structure that enables scalable and isolated user state management:

### Global User Tree

At the top level, there is a **Global User Tree** that stores information for all users in the system. Each user has a **User Leaf** in this tree:

```rust
pub struct PsyUserLeaf {
    pub public_key: Hash,              // User's public key for authentication
    pub user_state_tree_root: Hash,    // Root of this user's state tree
    pub balance: Felt,                 // User's native token balance
    pub nonce: Felt,                   // Transaction nonce for replay protection
    pub last_checkpoint_id: Felt,      // Last checkpoint this user participated in
    pub event_index: Felt,             // Index for event ordering
    pub user_id: Felt,                 // Unique identifier for this user
}
```

### User Contract State Tree Structure

Each user has their own **User Contract State Tree** with the following hierarchy:

```
Global User Tree
├── User 1 Leaf
│   ├── public_key
│   ├── user_state_tree_root ──┐
│   ├── balance               │
│   ├── nonce                 │
│   ├── last_checkpoint_id    │
│   ├── event_index           │
│   └── user_id               │
├── User 2 Leaf               │
└── ...                       │
                              │
User Contract State Tree (per user) ──┘
├── Contract 1 State (2^32 slots max)
│   ├── Slot 0: [Felt; 4]
│   ├── Slot 1: [Felt; 4]
│   └── ...
├── Contract 2 State (2^32 slots max)
│   ├── Slot 0: [Felt; 4]
│   ├── Slot 1: [Felt; 4]
│   └── ...
└── ...
```

### Storage Isolation and Access

This architecture provides several key benefits:

```rust
// Example: Understanding storage isolation
fn storage_isolation_example() {
    // Each user has completely isolated storage
    let user_a_id = 123;
    let user_b_id = 456;
    let contract_id = 789;
    
    // User A and User B each have their own user leaf in the Global User Tree
    // The user leaf contains user_state_tree_root pointing to their contract state tree
    
    // Even in the same contract, users have separate storage
    let user_a_balance = get_other_user_contract_state_hash_at(
        32,           // tree height
        user_a_id,    // User A
        contract_id,  // same contract
        0             // balance slot
    )[0];
    
    let user_b_balance = get_other_user_contract_state_hash_at(
        32,           // tree height  
        user_b_id,    // User B
        contract_id,  // same contract
        0             // balance slot - completely separate from User A
    )[0];
    
    // user_a_balance and user_b_balance are independent
}
```

### Storage Access Permissions

**Read Access**: You can read from any user's storage in any contract  
**Write Access**: You can only write to your own storage

```rust
fn storage_access_permissions() {
    // Get current user's information
    let my_user_id = get_user_id();
    let my_public_key = get_user_public_key_hash();
    let my_nonce = get_last_nonce();
    
    // ✅ READ: Can read from any user's storage
    let other_user_id = 456;
    let contract_id = get_contract_id();
    let slot_index = 0;
    
    // Read from any user's contract storage
    let other_user_slot_data = get_other_user_contract_state_hash_at(
        32,              // contract_state_tree_height
        other_user_id,   // any user
        contract_id,     // any contract  
        slot_index       // any slot
    );
    
    // Read from current user's storage
    let my_slot_data = get_state_hash_at(slot_index);
    
    // ✅ WRITE: Can only write to own storage
    let new_data = [1, 2, 3, 4];
    cset_state_hash_at(slot_index, new_data); // Only writes to current user's storage
    
    // ❌ CANNOT: Write to other users' storage
    // There is no function like cset_other_user_state_hash_at()
    // The architecture prevents writing to other users' storage
}
```

### Contract Storage within User Contract State Tree

Each user's contract state tree contains their storage for all contracts:

```rust
#[contract]
#[derive(Storage, StorageRef)]
pub struct TokenContract {
    pub balance: Felt,           // Slot 0 in this user's contract state
    pub allowances: [Felt; 100], // Slots 1-100 in this user's contract state
}

fn contract_storage_in_user_tree() {
    let contract = TokenContractRef::new(ContractMetadata::current());
    
    // This accesses:
    // Global User Tree -> Current User Leaf -> User Contract State Tree Root
    // -> This Contract's State -> Specific Slots
    contract.balance.set(100);
    
    // Reading from another user requires traversing their tree:
    // Global User Tree -> Other User Leaf -> Their User Contract State Tree Root  
    // -> This Contract's State in Their Tree -> Specific Slots
    let other_contract = TokenContractRef::new(ContractMetadata::new(
        get_contract_id(),
        456  // other user's ID
    ));
    let other_balance = other_contract.balance.get();
}
```


### Storage Tree Limits

Each level has specific capacity limits:

```rust
// System limits
const MAX_USERS: u64 = 2^64;              // Global User Tree capacity
const MAX_CONTRACTS_PER_USER: u32 = 2^32; // User Contract State Tree capacity
const MAX_SLOTS_PER_CONTRACT: u32 = 2^32; // Contract Storage capacity

fn storage_limits_example() {
    // Each user can have up to 2^32 contracts
    // Each contract can have up to 2^32 slots
    // Each slot stores Hash = [Felt; 4]
    
    // Total storage per user: 2^32 contracts × 2^32 slots × 4 Felt = 2^66 Felt values
    // Global capacity: 2^64 users × 2^66 Felt per user = 2^130 total Felt values
}
```

### Contract Interaction Pattern: "Read Others, Write Self"

Psy contracts follow a "read others, write self" interaction pattern. Users can read from other users' storage but can only write to their own storage. This enables secure cross-user interactions:

```rust
impl TokenContract {
    // Transfer tokens: "read others, write self" pattern
    pub fn transfer_tokens(recipient: Felt, amount: Felt) {
        let sender_id = get_user_id();
        
        // Write to sender's own storage (current user)
        let sender_contract = TokenContractRef::new(ContractMetadata::current());
        let sender_balance = sender_contract.balance.get();
        assert(sender_balance >= amount, "insufficient balance");
        sender_contract.balance.set(sender_balance - amount);
        
        // Write transfer record to sender's storage using recipient as key
        sender_contract.transfers_sent.index(recipient).set(
            sender_contract.transfers_sent.index(recipient).get() + amount
        );
    }
    
    pub fn claim_tokens(sender: Felt) {
        let recipient_id = get_user_id();
        
        // Read from sender's storage (read others)
        let sender_contract = TokenContractRef::new(
            ContractMetadata::new(get_contract_id(), sender)
        );
        let amount_sent = sender_contract.transfers_sent.index(recipient_id).get();
        
        // Write to recipient's own storage (write self)
        let recipient_contract = TokenContractRef::new(ContractMetadata::current());
        let amount_claimed = recipient_contract.transfers_claimed.index(sender).get();
        
        let claimable = amount_sent - amount_claimed;
        assert(claimable > 0, "no tokens to claim");
        
        // Update recipient's own storage
        recipient_contract.transfers_claimed.index(sender).set(amount_sent);
        recipient_contract.balance.set(
            recipient_contract.balance.get() + claimable
        );
    }
}
```

### Cross-User Interaction Examples

```rust
#[contract]
#[derive(Storage, StorageRef)]
pub struct MessageContract {
    pub messages_sent: [Hash; 1000000],      // Messages sent to others
    pub messages_received: [Hash; 1000000],  // Messages received from others
}

impl MessageContract {
    // Send message: write to own storage with recipient as index
    pub fn send_message(recipient: Felt, message_hash: Hash) {
        let sender = MessageContractRef::new(ContractMetadata::current());
        sender.messages_sent.index(recipient).set(message_hash);
    }
    
    // Read message: read from sender's storage, write to own
    pub fn receive_message(sender: Felt) -> Hash {
        // Read from sender's storage
        let sender_contract = MessageContractRef::new(
            ContractMetadata::new(get_contract_id(), sender)
        );
        let message = sender_contract.messages_sent.index(get_user_id()).get();
        
        // Write to own storage to mark as received
        let recipient = MessageContractRef::new(ContractMetadata::current());
        recipient.messages_received.index(sender).set(message);
        
        message
    }
}
```

### Interaction Security Model

This pattern provides several security benefits:

1. **Write Isolation**: Users can only modify their own storage  
2. **Read Transparency**: Users can read from any user's storage
3. **Consent-based Transfers**: Recipients must actively claim transfers
4. **Audit Trail**: All interactions are recorded in sender's storage

```rust
impl SecureContract {
    pub fn secure_interaction_example() {
        // ✅ Allowed: Read from any user's storage
        let other_user_data = OtherContractRef::new(
            ContractMetadata::new(get_contract_id(), 456)
        ).any_field.get();
        
        // ✅ Allowed: Read from any user's any contract
        let external_data = ExternalContractRef::new(
            ContractMetadata::new(789, 456) // different contract, different user
        ).some_field.get();
        
        // ✅ Allowed: Write to own storage only
        let my_contract = MyContractRef::new(ContractMetadata::current());
        my_contract.my_data.set(42);
        
        // ❌ NOT Possible: Cannot write to another user's storage
        // The system architecture prevents this:
        // - No cset_other_user_state_hash_at() function exists
        // - Storage references only write to current user's storage
        // - Cross-user writes are architecturally impossible
    }
}
```

### State Tree Operations

Understanding the tree structure helps optimize storage operations:

```rust
impl OptimizedContract {
    // Batch operations within same user are efficient
    pub fn batch_user_operations() {
        let contract = OptimizedContractRef::new(ContractMetadata::current());
        
        // All these operations work within the same user contract state tree
        for i in 0u32..10u32 {
            contract.data.index(i as Felt).set(i as Felt);
        }
        // Efficient: single user contract tree, multiple contract slots
    }
    
    // Cross-user operations require multiple tree accesses
    pub fn cross_user_operation(other_user: Felt) {
        let my_contract = OptimizedContractRef::new(ContractMetadata::current());
        let other_contract = OptimizedContractRef::new(
            ContractMetadata::new(get_contract_id(), other_user)
        );
        
        // Less efficient: requires accessing two different user contract state trees
        let my_value = my_contract.data.index(0).get();
        let other_value = other_contract.data.index(0).get();
    }
}

### Storage Capacity

```rust
// Each contract supports up to 2^32 storage slots
// Each slot is Hash type = [Felt; 4] = 4 u64 values
const MAX_SLOTS: u32 = 2^32;
type StorageSlot = Hash; // [Felt; 4]
```

## Storage Layout

Storage fields are arranged sequentially in the order they appear in the struct:

```rust
#[derive(Storage)]
struct ExampleContract {
    pub field_a: Felt,        // Slot 0
    pub field_b: [Felt; 3],   // Slots 1-3
    pub field_c: CustomType,  // Slots 4-6 (assuming CustomType::size() == 3)
    pub field_d: bool,        // Slot 7
}

// Total storage: 8 slots (0-7)
```

## Manual Storage Operations

Developers can manually manage storage slots using low-level functions:

### Direct Slot Access

```rust
#[contract]
struct TokenContract {
}

impl TokenContract {
    pub fn manual_storage_example() {
        let user_id = get_user_id();
        
        // Read current user's balance from slot 0
        // Each slot is a Hash containing [balance, reserved1, reserved2, reserved3]
        let user_leaf: Hash = get_state_hash_at(user_id);
        let current_balance: Felt = user_leaf[0];
        
        // Update balance while preserving other fields
        let new_balance = current_balance + 100;
        cset_state_hash_at(user_id, [
            new_balance,    // New balance
            user_leaf[1],   // Preserve reserved1
            user_leaf[2],   // Preserve reserved2  
            user_leaf[3],   // Preserve reserved3
        ]);
        
        // Access another user's storage
        let other_user = 456;
        let other_leaf: Hash = get_state_hash_at(other_user);
        let other_balance: Felt = other_leaf[0];
    }
    
    pub fn cross_user_access() {
        let sender = 123;
        let recipient = get_user_id();
        let contract_id = get_contract_id();
        
        // Read sender's data from their storage in this contract
        let sender_data: Hash = get_other_user_contract_state_hash_at(
            32,           // contract_state_tree_height
            sender,       // user_id of sender
            contract_id,  // current contract
            recipient     // slot index (using recipient as slot key)
        );
        
        // sender_data[2] might contain amount sent to recipient
        let amount_sent = sender_data[2];
    }
}
```

### Manual Storage Layout Design

When using manual storage, developers design their own slot layout:

```rust
// Example: Token contract with manual slot management
// Slot layout per user:
// [balance, total_sent, total_received, reserved]

impl TokenContract {
    pub fn transfer(recipient: Felt, amount: Felt) -> Felt {
        let sender_id = get_user_id();
        
        // Read sender's state
        let sender_leaf: Hash = get_state_hash_at(sender_id);
        let sender_balance = sender_leaf[0];
        let sender_total_sent = sender_leaf[1];
        
        assert(amount <= sender_balance, "insufficient balance");
        
        // Update sender's state
        cset_state_hash_at(sender_id, [
            sender_balance - amount,      // New balance
            sender_total_sent + amount,   // Updated total sent
            sender_leaf[2],               // Preserve total received
            sender_leaf[3],               // Preserve reserved
        ]);
        
        // Read recipient's transfer tracking (from sender's perspective)
        let transfer_leaf: Hash = get_state_hash_at(recipient);
        let previous_sent_to_recipient = transfer_leaf[2];
        
        // Update transfer tracking
        cset_state_hash_at(recipient, [
            transfer_leaf[0],                         // Preserve balance
            transfer_leaf[1],                         // Preserve total sent  
            previous_sent_to_recipient + amount,      // Update sent to this recipient
            transfer_leaf[3],                         // Preserve reserved
        ]);
        
        sender_balance - amount
    }
}
```

## Automatic Storage Generation

Use `#[derive(Storage, StorageRef)]` to automatically generate storage management code:

### Storage Derive

The `#[derive(Storage)]` attribute automatically implements the Storage trait:

```rust
#[derive(Storage)]
pub struct Person {
    pub age: Felt,           // Size: 1 slot
    pub height: Felt,        // Size: 1 slot  
    pub birth_year: Felt,    // Size: 1 slot
}
// Total size: 3 slots

#[derive(Storage)]
pub struct PersonArray {
    pub people: [Person; 10], // Size: 30 slots (10 * 3)
    pub count: Felt,          // Size: 1 slot
}
// Total size: 31 slots
```

**Generated methods by #[derive(Storage)]:**
- `size() -> Felt` - Returns number of slots occupied
- `read(height: Felt, user_id: Felt, contract_id: Felt, offset: Felt) -> Self`
- `write(offset: Felt, value: Self)`

The `#[derive(Storage)]` attribute automatically implements the Storage trait by:
1. **Calculating size()**: Sums up sizes of all fields
2. **Generating read()**: Aggregates individual field reads from their slot offsets
3. **Generating write()**: Aggregates individual field writes to their slot offsets
4. **Computing offsets**: Each field gets an offset based on its position in the layout

```rust
// Example of what #[derive(Storage)] generates internally
#[derive(Storage)]
pub struct Person {
    pub age: Felt,           // Offset 0, Size 1
    pub height: Felt,        // Offset 1, Size 1  
    pub birth_year: Felt,    // Offset 2, Size 1
}
// Total size: 3 slots

// Generated implementation (simplified):
impl Storage for Person {
    pub fn size() -> Felt {
        3  // age(1) + height(1) + birth_year(1)
    }
    
    pub fn read(height: Felt, user_id: Felt, contract_id: Felt, offset: Felt) -> Self {
        // Read from slot offsets: offset+0, offset+1, offset+2
        let age = Felt::read(height, user_id, contract_id, offset + 0);
        let height_val = Felt::read(height, user_id, contract_id, offset + 1); 
        let birth_year = Felt::read(height, user_id, contract_id, offset + 2);
        
        new Person { age, height: height_val, birth_year }
    }
    
    pub fn write(offset: Felt, value: Self) {
        // Write to slot offsets: offset+0, offset+1, offset+2  
        Felt::write(offset + 0, value.age);
        Felt::write(offset + 1, value.height);
        Felt::write(offset + 2, value.birth_year);
    }
}

### StorageRef Derive

The `#[derive(StorageRef)]` attribute generates type-specific reference structs that provide `get` and `set` helper methods:

```rust
#[derive(Storage, StorageRef)]
pub struct TokenData {
    pub balance: Felt,          // Offset 0, Size 1
    pub locked_amount: Felt,    // Offset 1, Size 1
}
// Total size: 2 slots

#[contract]
#[derive(Storage, StorageRef)]  
pub struct TokenContract {
    pub total_supply: Felt,                 // Offset 0, Size 1
    pub user_data: [TokenData; 1000000],    // Offset 1, Size 2000000 (1M * 2)
    pub admin: Felt,                        // Offset 2000001, Size 1
}
// Total size: 2000002 slots

// Automatically generates TokenContractRef struct:
pub struct TokenContractRef {
    pub total_supply: StorageRef<Felt, 1u32>,
    pub user_data: StorageRef<[TokenData; 1000000], 1u32>,
    pub admin: StorageRef<Felt, 1u32>,
}

impl TokenContractRef {
    // Generated constructor
    pub fn new(metadata: ContractMetadata) -> Self {
        new TokenContractRef {
            total_supply: StorageRef::<Felt, 1u32>::new(0, metadata),          // Offset 0
            user_data: StorageRef::<[TokenData; 1000000], 1u32>::new(1, metadata), // Offset 1  
            admin: StorageRef::<Felt, 1u32>::new(2000001, metadata),           // Offset 2000001
        }
    }
}
```

**Generated reference struct features:**
- **Virtual pointer**: No data loaded until `get()` is called
- **Automatic offsets**: Each field reference points to correct slot offset
- **Field access**: Direct access to nested structure fields
- **Array indexing**: `index(i)` method for array elements
- **get()/set() helper methods**: Read and write individual values

### Using Storage References

```rust
impl TokenContractRef {
    pub fn mint(user_id: Felt, amount: Felt) {
        // Create storage reference for current contract
        let contract = TokenContractRef::new(ContractMetadata::current());
        
        // Access and modify total supply
        let current_supply = contract.total_supply.get();
        contract.total_supply.set(current_supply + amount);
        
        // Access specific user's data through array indexing
        let mut user_data = contract.user_data.index(user_id).get();
        contract.user_data.index(user_id).set(new TokenData {
            balance: user_data.balance + amount,
            locked_amount: user_data.locked_amount
        });
    }
    
    pub fn transfer(from: Felt, to: Felt, amount: Felt) {
        let contract = TokenContractRef::new(ContractMetadata::current());
        
        // Access sender's data
        let mut sender_data = contract.user_data.index(from).get();
        assert(sender_data.balance >= amount, "insufficient balance");
        
        // Update sender's balance
        contract.user_data.index(from).set(new TokenData {
            balance: sender_data.balance - amount,
            locked_amount: sender_data.locked_amount
        });
        
        // Update recipient's balance
        let mut recipient_data = contract.user_data.index(to).get();
        contract.user_data.index(to).set(new TokenData {
            balance: recipient_data.balance + amount,
            locked_amount: recipient_data.locked_amount
        });
    }
}
```

## Cross-User Storage Access

Storage references can access other users' storage:

```rust
pub fn claim_tokens(sender: Felt) {
    let current_user = get_user_id();
    let contract_id = get_contract_id();
    
    // Create reference to current user's contract storage
    let my_contract = ContractRef::new(ContractMetadata::current());
    
    // Create reference to sender's contract storage  
    let sender_metadata = ContractMetadata::new(contract_id, sender);
    let sender_contract = ContractRef::new(sender_metadata);
    
    // Read how much sender sent to current user  
    let amount_sent = sender_contract.user_data.index(current_user).get().balance;
    
    // Read how much current user has already claimed from sender
    let amount_claimed = my_contract.user_data.index(sender).get().locked_amount;
    
    let claimable = amount_sent - amount_claimed;
    assert(claimable > 0, "nothing to claim");
    
    // Update claimed amount and balance
    let mut my_data = my_contract.user_data.index(sender).get();
    my_contract.user_data.index(sender).set(new TokenData {
        balance: my_data.balance,
        locked_amount: amount_sent  // Update claimed amount
    });
    my_contract.balance.set(my_contract.balance.get() + claimable);
}
```

## Creating Storage Pointers

Storage references are virtual pointers that can be created without loading actual data:

```rust
fn storage_pointer_example() {
    // Create storage pointer for current user's contract
    let contract = ContractRef::new(ContractMetadata::current());
    
    // Create pointer for different user's storage
    let other_user_contract = ContractRef::new(ContractMetadata::new(
        get_contract_id(), // same contract
        456                // different user
    ));
    
    // Create pointer for different contract and user  
    let external_contract = ContractRef::new(ContractMetadata::new(
        789, // different contract ID
        123  // different user ID
    ));
    
    // All pointers are lightweight - no data loaded until get() is called
    let my_balance = contract.balance.get();              // Load from current user
    let other_balance = other_user_contract.balance.get(); // Load from user 456
    let external_balance = external_contract.balance.get(); // Load from user 123 in contract 789
}
```

## Contract Definition

### Contract Attributes

```rust
// Basic contract struct
#[contract]
#[derive(Storage, StorageRef)]
pub struct MyContract {
    pub state_var1: Felt,
    pub state_var2: [Felt; 100],
}

// Alternative: storage-only struct (no automatic contract generation)
#[storage] 
#[derive(Storage)]
pub struct DataStorage {
    pub data: [Felt; 1000],
}
```

### Contract Implementation

```rust
impl MyContract {
    // Constructor pattern
    pub fn new() -> Self {
        new MyContract {
            state_var1: 0,
            state_var2: [0; 100],
        }
    }
    
    // Generated getter/setter methods (when using #[derive(Storage)])
    pub fn get_state_var1(height: Felt, user_id: Felt, contract_id: Felt) -> Felt {
        // Auto-generated
    }
    
    pub fn set_state_var1(value: Felt) {
        // Auto-generated - writes to current user's storage
    }
}

impl MyContractRef {
    // Storage reference methods
    pub fn initialize() {
        let contract = MyContractRef::new(ContractMetadata::current());
        contract.state_var1.set(42);
        
        // Initialize array elements
        for i in 0u32..100u32 {
            contract.state_var2.index(i as Felt).set(i as Felt);
        }
    }
}
```

## Nested Structures and References

### Nested Structure Access

```rust
#[derive(Storage, StorageRef)]
pub struct UserProfile {
    pub name_hash: Hash,
    pub age: Felt,
    pub balance: Felt,
}

#[derive(Storage, StorageRef)]
pub struct GameData {
    pub level: Felt,
    pub score: Felt,
}

#[contract]
#[derive(Storage, StorageRef)]
pub struct UserContract {
    pub profile: UserProfile,        // Slots 0-5 (Hash=4 + Felt + Felt)
    pub game: GameData,              // Slots 6-7
    pub friends: [Felt; 10],         // Slots 8-17
}

impl UserContractRef {
    pub fn update_profile_age(new_age: Felt) {
        let user = UserContractRef::new(ContractMetadata::current());
        
        // Update profile age
        let mut profile = user.profile.get();
        profile.age = new_age;
        user.profile.set(profile);
        
        // Access nested fields  
        let mut current_profile = user.profile.get();
        current_profile.balance = current_profile.balance + 10;
        user.profile.set(current_profile);
        
        // Array access
        user.friends.index(0).set(123); // Set first friend ID
    }
}
```

### Ref Attribute for Nested Data Access

Use `#[ref]` to create references for nested data:

```rust
#[derive(Storage, StorageRef)]
pub struct NestedData {
    pub counter: Felt,
    pub last_update: Felt,
}

#[contract]
#[derive(Storage, StorageRef)]
pub struct MyContract {
    pub basic_data: Felt,
    #[ref]
    pub nested_data: NestedData,
    pub array_data: [Felt; 1000],
}

impl MyContractRef {
    pub fn increment_counter() {
        let contract = MyContractRef::new(ContractMetadata::current());
        
        // Access nested data through #[ref]
        let mut data = contract.nested_data.get();
        data.counter = data.counter + 1;
        data.last_update = get_checkpoint_id();
        contract.nested_data.set(data);
    }
}
```

## Storage Size Calculation

```rust
#[test]
fn test_storage_sizes() {
    // Primitive types
    assert_eq(Felt::size(), 1, "Felt occupies 1 slot");
    assert_eq(bool::size(), 1, "bool occupies 1 slot");
    assert_eq(Hash::size(), 4, "Hash occupies 4 slots");
    
    // Arrays
    assert_eq(<[Felt; 10]>::size(), 10, "Array size = element_count");
    assert_eq(<[Hash; 5]>::size(), 20, "Hash array: 5 * 4 = 20 slots");
    
    // Custom structures
    // Person has 3 Felt fields = 3 slots
    assert_eq(Person::size(), 3, "Person occupies 3 slots");
    
    // Contract with mixed types
    assert_eq(UserContract::size(), 18, "Total contract storage");
}
```

## Storage Best Practices

### Layout Organization

```rust
// Good: Related data together
#[derive(Storage, StorageRef)]
pub struct WellDesignedContract {
    pub balance: Felt,
    pub last_active: Felt,
    pub user_level: Felt,
    pub experience: Felt,
    pub historical_data: [Felt; 1000],
}
```

### Choosing Manual vs Automatic Storage

**Use Manual Storage When:**
- Need precise control over slot layout
- Implementing complex storage patterns
- Working with legacy storage layouts
- Optimizing for specific access patterns

```rust
// Manual storage for precise control
impl AdvancedTokenContract {
    // Custom layout: [balance, allowance, metadata, reserved]
    pub fn get_user_balance(user_id: Felt) -> Felt {
        let user_leaf = get_state_hash_at(user_id);
        user_leaf[0] // Balance is always first element
    }
}
```

**Use Automatic Storage When:**
- Developing new contracts
- Need clean, maintainable code
- Working with structured data
- Want type safety and error prevention

```rust
// Automatic storage for clean code
#[derive(Storage, StorageRef)]
pub struct CleanTokenContract {
    pub balances: [Felt; 1000000],
    pub allowances: [Hash; 1000000], // [owner, spender, amount, expiry]
    pub metadata: TokenMetadata,
}
```

## Key Points

1. **Hierarchical Storage**: Global User Tree → User Contract State Tree → Contract Storage (2^32 slots)
2. **User Leaf Structure**: Each user has a leaf containing public key, contract state tree root, balance, nonce, etc.
3. **Complete Isolation**: Each user has separate contract state trees - no cross-contamination
4. **Storage Capacity**: 2^64 users × 2^32 contracts × 2^32 slots × 4 Felt per slot
5. **Access Permissions**: Read any user's storage, write only to own storage
6. **Interaction Pattern**: "Read Others, Write Self" - enables secure cross-user interactions
7. **Security Model**: Write isolation ensures users cannot modify others' storage directly
8. **Consent-based Transfers**: Recipients must actively claim transfers from senders
9. **Two Approaches**: Manual slot management vs automatic Storage/StorageRef derives
10. **Storage References**: Virtual pointers enable efficient access without full data loading
11. **Cross-User Access**: Create ContractMetadata with different user_id for cross-user reads
12. **Type Safety**: Automatic derives provide compile-time layout validation
13. **No Dynamic Types**: All storage must be statically sized at compile time
14. **Storage Pointers**: Use `ContractRef::new(ContractMetadata)` to create lightweight virtual pointers
15. **Generated Helper Methods**: `#[derive(StorageRef)]` generates type-specific reference structs with `get` and `set` methods
