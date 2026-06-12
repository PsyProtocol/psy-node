# Storage and Contracts

[Psy Smart Contract Language] supports storage for persistent state, useful for blockchain applications.

## Defining a Contract

```psy
#[storage]
struct Contract {
}

impl Contract {
    pub fn simple_mint(amount: Felt) -> Felt {
        let self_user_leaf: Hash = get_state_hash_at(get_user_id());
        let current_balance: Felt = self_user_leaf[0];
        let new_balance: Felt = current_balance + amount;
        cset_state_hash_at(get_user_id(), [new_balance, self_user_leaf[1], self_user_leaf[2], self_user_leaf[3]]);
        new_balance
    }
}
```

# Explanation
`#[storage]`: Marks a struct for persistent storage.
`get_state_hash_at`: Retrieves state.
`cset_state_hash_at`: Updates state.
