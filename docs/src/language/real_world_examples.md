# Real-World Applications

This chapter demonstrates practical applications of Psy language features through real-world smart contract examples. We'll examine actual contract implementations to show how the language concepts work together in production scenarios.

## Token Contract - Complete Implementation

Let's examine a complete token contract that demonstrates storage, user interaction patterns, and the "read others, write self" security model.

### Contract Structure

```psy
#[derive(Storage, StorageRef)]
struct OtherUserInfo {
    pub amount_sent: Felt,
    pub amount_claimed: Felt,
}

#[contract]
#[derive(Storage, StorageRef)]
struct Contract {
    pub balance: Felt,
    pub other_user_info: [OtherUserInfo; 16777216],
}
```

**Key Design Decisions:**

1. **Storage Organization**: The contract uses a simple two-level structure
   - `balance` - Current user's token balance
   - `other_user_info` - Array tracking interactions with other users

2. **User Isolation**: Each user has their own instance of this contract storage
   - User A's `balance` is completely separate from User B's `balance`
   - Cross-user interactions are tracked in the `other_user_info` array

3. **Large Array Size**: `16777216` slots allow tracking interactions with many users
   - Each slot stores `amount_sent` and `amount_claimed` for one other user
   - Uses user ID as array index for O(1) access

### Token Minting

```psy
impl ContractRef {
    pub fn simple_mint(amount: Felt) {
        let c = ContractRef::new(ContractMetadata::current());
        c.balance.set(c.balance.get() + amount);
    }
}
```

**Implementation Analysis:**

- **Storage Access**: Uses `ContractMetadata::current()` to access current user's storage
- **Atomic Operation**: Reads current balance, adds amount, writes back
- **Simplicity**: No authorization checks - any user can mint for themselves
- **Security**: Cannot mint for other users due to storage isolation

**Usage Pattern:**
```psy
ContractRef::simple_mint(100);  // Mint 100 tokens to current user
```

### Token Burning with Validation

```psy
pub fn simple_burn(amount: Felt) {
    let c = ContractRef::new(ContractMetadata::current());
    let current_balance = c.balance.get();
    assert(current_balance >= amount, "insufficient balance");
    c.balance.set(current_balance - amount);
}
```

**Key Features:**

1. **Validation**: Checks sufficient balance before burning
2. **Error Handling**: Uses descriptive assertion message
3. **Safe Arithmetic**: No underflow risk due to validation
4. **Gas Efficiency**: Single read, validate, single write pattern

**Security Considerations:**
- Only user can burn their own tokens (storage isolation)
- Prevents negative balances through validation
- Clear error messages for debugging

### Token Transfer - Cross-User Pattern

```psy
pub fn simple_transfer(recipient: Felt, amount: Felt) {
    let c = ContractRef::new(ContractMetadata::current());
    let current_balance = c.balance.get();
    assert(current_balance >= amount, "insufficient balance");

    let mut recipient_info = c.other_user_info.index(recipient).get();
    assert(recipient_info.amount_sent + amount > recipient_info.amount_sent, "amount sent overflow");

    c.other_user_info.index(recipient).set(new OtherUserInfo {
        amount_sent: recipient_info.amount_sent + amount,
        amount_claimed: recipient_info.amount_claimed
    });

    c.balance.set(current_balance - amount);
}
```

**Transfer Mechanics:**

1. **Sender Validation**: Check sender has sufficient balance
2. **Overflow Protection**: Ensure `amount_sent` doesn't overflow
3. **Record Keeping**: Update sender's record of tokens sent to recipient
4. **Balance Update**: Deduct from sender's balance

**Critical Insight - "Write Self" Pattern:**
- Sender can only update their own storage
- Transfer is recorded in sender's `other_user_info[recipient]`
- Recipient must actively claim tokens (pull pattern)

**Why This Design:**
- **Security**: Prevents unauthorized balance modifications
- **User Consent**: Recipients choose when to claim tokens
- **Audit Trail**: Complete history of all transfers in sender's storage

### Token Claiming - Cross-User Reading

```psy
pub fn simple_claim(sender: Felt) {
    let self_user_id = get_user_id();
    assert(sender != self_user_id, "you cannot claim from your self");

    let c = ContractRef::new(ContractMetadata::current());

    let sender_user_contract = ContractRef::new(ContractMetadata::new(get_contract_id(), sender));
    let sender_total_sent = sender_user_contract.other_user_info.index(self_user_id).get().amount_sent;

    let mut sender_info = c.other_user_info.index(sender).get();
    assert(sender_info.amount_claimed < sender_total_sent, "no tokens to claim from this sender");
    let claimed = sender_total_sent - sender_info.amount_claimed;

    c.other_user_info.index(sender).set(new OtherUserInfo {
        amount_sent: sender_info.amount_sent,
        amount_claimed: sender_total_sent
    });

    c.balance.set(c.balance.get() + claimed);
}
```

**Claiming Process:**

1. **Identity Validation**: Prevent self-claiming
2. **Read Others**: Access sender's storage to see amount sent
3. **Check Claimable**: Compare sent vs already claimed amounts
4. **Write Self**: Update recipient's tracking and balance

**Cross-User Storage Access:**
```psy
// Read from sender's storage
let sender_user_contract = ContractRef::new(ContractMetadata::new(get_contract_id(), sender));
let sender_total_sent = sender_user_contract.other_user_info.index(self_user_id).get().amount_sent;
```

**Security Properties:**
- **Read Transparency**: Can read any user's storage
- **Write Isolation**: Can only write to own storage  
- **Double-Spend Prevention**: Tracks `amount_claimed` to prevent re-claiming
- **User Control**: Recipients decide when to claim

### Complete Usage Example

```psy
fn main() {
    let c = ContractRef::new(ContractMetadata::current());
    
    // Mint initial tokens
    ContractRef::simple_mint(100);
    assert_eq(c.balance.get(), 100, "c.balance == 100");

    // Transfer to another user
    ContractRef::simple_transfer(10, 50);  // Send 50 tokens to user 10
    assert_eq(c.balance.get(), 50, "c.balance == 50");
    
    // Verify transfer was recorded
    assert_eq(c.other_user_info.index(10).get().amount_sent, 50, "recorded 50 tokens sent to user 10");
}
```

## Advanced Patterns

### Multi-Token Contract with Modules

```psy
mod token_types {
    pub const GOLD: Felt = 1;
    pub const SILVER: Felt = 2;
    pub const BRONZE: Felt = 3;
}

mod validation {
    use token_types::*;
    
    pub fn is_valid_token_type(token_type: Felt) -> bool {
        token_type == GOLD || token_type == SILVER || token_type == BRONZE
    }
    
    pub fn get_exchange_rate(from_type: Felt, to_type: Felt) -> Felt {
        if from_type == GOLD && to_type == SILVER {
            10  // 1 Gold = 10 Silver
        } else if from_type == SILVER && to_type == BRONZE {
            5   // 1 Silver = 5 Bronze
        } else {
            1   // 1:1 for same type
        }
    }
}

#[derive(Storage, StorageRef)]
struct TokenBalance {
    pub gold: Felt,
    pub silver: Felt,
    pub bronze: Felt,
}

#[contract]
#[derive(Storage, StorageRef)]
struct MultiTokenContract {
    pub balances: TokenBalance,
    pub exchange_history: [Felt; 1000],
}

impl MultiTokenContractRef {
    pub fn mint_token(token_type: Felt, amount: Felt) {
        use validation::*;
        use token_types::*;
        
        assert(is_valid_token_type(token_type), "invalid token type");
        
        let contract = MultiTokenContractRef::new(ContractMetadata::current());
        let mut balances = contract.balances.get();
        
        if token_type == GOLD {
            balances.gold = balances.gold + amount;
        } else if token_type == SILVER {
            balances.silver = balances.silver + amount;
        } else if token_type == BRONZE {
            balances.bronze = balances.bronze + amount;
        }
        
        contract.balances.set(balances);
    }
    
    pub fn exchange_tokens(from_type: Felt, to_type: Felt, amount: Felt) {
        use validation::*;
        
        assert(is_valid_token_type(from_type) && is_valid_token_type(to_type), "invalid token types");
        
        let rate = get_exchange_rate(from_type, to_type);
        let converted_amount = amount * rate;
        
        // Implementation would update balances accordingly
        // This demonstrates how modules organize related functionality
    }
}
```

**Module Benefits:**
- **Constants Organization**: `token_types` module centralizes token definitions
- **Validation Logic**: `validation` module provides reusable checks
- **Clean Implementation**: Contract logic focuses on business rules, not validation details

### NFT-Style Contract with Traits

```psy
pub trait Transferable {
    pub fn can_transfer(token_id: Felt, from: Felt, to: Felt) -> bool;
    pub fn transfer(token_id: Felt, to: Felt);
}

pub trait Metadata {
    pub fn get_name(token_id: Felt) -> Hash;
    pub fn get_description(token_id: Felt) -> Hash;
}

#[derive(Storage, StorageRef)]
struct TokenInfo {
    pub owner: Felt,
    pub name_hash: Hash,
    pub description_hash: Hash,
    pub transferable: bool,
}

#[contract]
#[derive(Storage, StorageRef)]
struct NFTContract {
    pub tokens: [TokenInfo; 1000000],
    pub next_token_id: Felt,
}

impl Transferable for NFTContractRef {
    pub fn can_transfer(token_id: Felt, from: Felt, to: Felt) -> bool {
        let contract = NFTContractRef::new(ContractMetadata::current());
        let token = contract.tokens.index(token_id).get();
        token.owner == from && token.transferable
    }
    
    pub fn transfer(token_id: Felt, to: Felt) {
        let from = get_user_id();
        assert(Self::can_transfer(token_id, from, to), "transfer not allowed");
        
        let contract = NFTContractRef::new(ContractMetadata::current());
        let mut token = contract.tokens.index(token_id).get();
        token.owner = to;
        contract.tokens.index(token_id).set(token);
    }
}

impl Metadata for NFTContractRef {
    pub fn get_name(token_id: Felt) -> Hash {
        let contract = NFTContractRef::new(ContractMetadata::current());
        contract.tokens.index(token_id).get().name_hash
    }
    
    pub fn get_description(token_id: Felt) -> Hash {
        let contract = NFTContractRef::new(ContractMetadata::current());
        contract.tokens.index(token_id).get().description_hash
    }
}
```

**Trait Benefits:**
- **Interface Separation**: `Transferable` and `Metadata` define clear contracts
- **Implementation Flexibility**: Different NFT contracts can implement these traits differently
- **Code Reusability**: Other contracts can implement the same traits

### Governance Contract with Generics

```psy
pub trait Votable {
    pub fn get_voting_power(user_id: Felt) -> Felt;
}

struct ProposalData<T> {
    pub id: Felt,
    pub description_hash: Hash,
    pub votes_for: Felt,
    pub votes_against: Felt,
    pub metadata: T,
}

#[contract]
#[derive(Storage, StorageRef)]
struct GovernanceContract {
    pub proposals: [ProposalData<Hash>; 10000],
    pub user_votes: [Felt; 1000000],  // Track user voting history
}

impl GovernanceContractRef {
    pub fn create_proposal(description_hash: Hash, metadata: Hash) -> Felt {
        let contract = GovernanceContractRef::new(ContractMetadata::current());
        let proposal_id = get_next_proposal_id();
        
        contract.proposals.index(proposal_id).set(new ProposalData {
            id: proposal_id,
            description_hash,
            votes_for: 0,
            votes_against: 0,
            metadata
        });
        
        proposal_id
    }
    
    pub fn vote<V: Votable>(proposal_id: Felt, vote_for: bool) {
        let user_id = get_user_id();
        let voting_power = V::get_voting_power(user_id);
        
        assert(voting_power > 0, "no voting power");
        
        let contract = GovernanceContractRef::new(ContractMetadata::current());
        let mut proposal = contract.proposals.index(proposal_id).get();
        
        if vote_for {
            proposal.votes_for = proposal.votes_for + voting_power;
        } else {
            proposal.votes_against = proposal.votes_against + voting_power;
        }
        
        contract.proposals.index(proposal_id).set(proposal);
        
        // Record user's vote to prevent double-voting
        contract.user_votes.index(user_id).set(proposal_id);
    }
}

fn get_next_proposal_id() -> Felt {
    // Implementation would increment and return next available ID
    1
}
```

**Generic Benefits:**
- **Type Flexibility**: `ProposalData<T>` can hold different metadata types
- **Constraint Power**: `V: Votable` ensures voting power can be calculated
- **Extensibility**: New voting systems can be plugged in via traits

## Design Patterns Summary

### 1. Storage Patterns

**Single-User Data:**
```psy
pub struct UserData {
    pub balance: Felt,
    pub last_activity: Felt,
}
```

**Cross-User Tracking:**
```psy
pub struct UserInteractions {
    pub sent: [Felt; MAX_USERS],
    pub received: [Felt; MAX_USERS],
}
```

**Hierarchical Data:**
```psy
pub struct ComplexData {
    pub metadata: TokenMetadata,
    pub balances: TokenBalances,
    pub history: [Transaction; 1000],
}
```

### 2. Access Patterns

**Current User Access:**
```psy
let contract = ContractRef::new(ContractMetadata::current());
let value = contract.field.get();
```

**Cross-User Reading:**
```psy
let other_contract = ContractRef::new(ContractMetadata::new(contract_id, other_user_id));
let other_value = other_contract.field.get();
```

**Safe Writing:**
```psy
// Only writes to current user's storage
let my_contract = ContractRef::new(ContractMetadata::current());
my_contract.field.set(new_value);
```

### 3. Security Patterns

**Input Validation:**
```psy
assert(amount > 0, "amount must be positive");
assert(user_id != get_user_id(), "cannot target self");
```

**Overflow Protection:**
```psy
assert(balance + amount > balance, "addition overflow");
assert(total_supply + minted > total_supply, "supply overflow");
```

**State Consistency:**
```psy
let old_state = contract.state.get();
let new_state = update_state(old_state);
contract.state.set(new_state);
```

These patterns demonstrate how Psy's language features combine to create secure, efficient smart contracts that take advantage of zero-knowledge proofs while maintaining clear, auditable code.