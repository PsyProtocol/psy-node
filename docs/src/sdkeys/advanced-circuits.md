# Advanced Software-Defined Signatures

Beyond the built-in ZK and SECP256K1 signature schemes, Psy enables truly programmable authentication through custom zero-knowledge circuits. This allows developers to implement sophisticated signing logic with transaction introspection capabilities.

## Extended Software-Defined Keys

### Concept

Software-defined signatures enable authentication schemes that go beyond simple cryptographic signatures. Users can define custom circuits that implement complex authorization logic.

### Basic Extended Signature

**Using Psy Language:**

```psy
#[software_defined_signature]
pub fn basic_constraint_auth(
    secret: Felt,
    contract_id: Felt,
    method_id: Felt,
    inputs: &[Felt],
) -> bool {
    // Verify knowledge of secret (any unique identifier)
    let computed_identifier = hash(secret);
    let secret_valid = computed_identifier == EXPECTED_IDENTIFIER;
    
    // Constrain contract and method
    let contract_valid = contract_id == 0;
    let method_valid = method_id == 0;
    let input_valid = inputs[0] < 500;
    
    secret_valid && contract_valid && method_valid && input_valid
}
```

**Using DPNSoftwareDefinedCallData:**

```rust
// Deploy the circuit
let call_data = DPNSoftwareDefinedCallData {
    contract_id: 0,
    inputs: vec![amount, param1, param2],  // amount must be < 500
};
```

**Key Features:**
- **Flexible Authentication**: Authentication not tied to traditional private keys
- **Transaction Constraints**: Circuits can constrain transaction parameters
- **Public Authorization**: Can implement publicly verifiable authorization logic

## Use Case: Matching Bot

### Automated Market Making

A sophisticated use case is implementing an automated order matching system:

**Using Psy Language for Order Matching:**

```psy
#[software_defined_signature]
pub fn order_matching_auth(
    contract_id: Felt,
    method_name: &str,
    inputs: &[Felt],
    buy_orders_proof: MerkleProof,
    sell_orders_proof: MerkleProof,
    checkpoint_data: CheckpointData,
) -> bool {
    // Verify this is the expected protocol
    let protocol_valid = hash("QEDProtocol") == EXPECTED_PROTOCOL_HASH;
    assert(protocol_valid);
    
    // Only allow order matching contract
    let contract_valid = contract_id == ORDER_BOOK_CONTRACT_ID;
    assert(contract_valid);
    
    // Only allow match_orders method
    let method_valid = method_name == "match_orders";
    assert(method_valid);
    
    // Verify merkle proofs against checkpoint
    let buy_proof_valid = verify_merkle_proof(&checkpoint_data.tree_root, &buy_orders_proof);
    let sell_proof_valid = verify_merkle_proof(&checkpoint_data.tree_root, &sell_orders_proof);
    assert(buy_proof_valid && sell_proof_valid);
    
    // Extract order data from proofs
    let buy_orders = extract_orders_from_proof(&buy_orders_proof);
    let sell_orders = extract_orders_from_proof(&sell_orders_proof);
    
    // Implement optimal matching logic
    let (best_buy_index, best_sell_index) = find_optimal_match(&buy_orders, &sell_orders);
    
    // Verify the inputs match the optimal selection
    inputs[0] == best_buy_index && inputs[1] == best_sell_index
}

// Helper functions that would be available in the circuit
fn find_optimal_match(buy_orders: &[Order], sell_orders: &[Order]) -> (Felt, Felt) {
    // Implement matching algorithm ensuring best price execution
    let mut best_spread = Felt::MAX;
    let mut best_pair = (0, 0);
    
    for (i, buy_order) in buy_orders.iter().enumerate() {
        for (j, sell_order) in sell_orders.iter().enumerate() {
            if buy_order.price >= sell_order.price {
                let spread = buy_order.price - sell_order.price;
                if spread < best_spread {
                    best_spread = spread;
                    best_pair = (i as Felt, j as Felt);
                }
            }
        }
    }
    
    best_pair
}
```

**Deployment and Usage:**

```rust
// Register the matching bot circuit
let fingerprint = circuit_manager
    .register_dpn_software_defined_circuit(
        order_matching_auth_bytecode,
        32,  // contract_state_tree_height
    )
    .await?;

// Anyone can now trigger optimal order matching
let call_data = DPNSoftwareDefinedCallData {
    contract_id: ORDER_BOOK_CONTRACT_ID,
    inputs: vec![buy_order_index, sell_order_index],
};
```

**Capabilities:**
- **State Access**: Circuits can read and verify on-chain state
- **Algorithmic Trading**: Implement complex matching algorithms in ZK
- **Trustless Automation**: No need to trust the bot operator
- **Optimal Execution**: Prove optimal order matching on-chain

## Advanced Applications

### 1. Permissionless Bots

```psy
#[software_defined_signature]
pub fn permissionless_bot_auth(
    contract_id: Felt,
    method_name: &str,
    inputs: &[Felt],
) -> bool {
    // No secret required - anyone can execute
    // But execution is constrained by logic
    
    // Verify bot identifier
    let bot_id = hash("PermissionlessBot");
    let bot_valid = bot_id == EXPECTED_BOT_IDENTIFIER;
    assert(bot_valid);
    
    // Only allow specific method
    let method_valid = method_name == "allowed_method";
    assert(method_valid);
    
    // Minimum threshold constraint
    inputs[0] > MIN_THRESHOLD
}
```

**Use Cases:**
- **Liquidation Bots**: Anyone can liquidate, but only valid liquidations
- **Arbitrage Bots**: Permissionless arbitrage with guaranteed profitability
- **Rebalancing**: Portfolio rebalancing with constraints

### 2. Conditional Execution

```psy
#[software_defined_signature]
pub fn conditional_spending_auth(
    contract_id: Felt,
    inputs: &[Felt],
    balance_proof: MerkleProof,
    checkpoint_data: CheckpointData,
) -> bool {
    // Verify user balance from merkle proof
    let balance_proof_valid = verify_merkle_proof(&checkpoint_data.tree_root, &balance_proof);
    assert(balance_proof_valid);
    
    let user_balance = extract_balance_from_proof(&balance_proof);
    
    // Only allow transaction if balance > threshold
    let balance_sufficient = user_balance > 1000;
    assert(balance_sufficient);
    
    // Constrain transaction amount to max 50% of balance
    let transaction_amount = inputs[0];
    transaction_amount <= user_balance / 2
}
```

**Use Cases:**
- **Spending Limits**: Enforce spending limits in the signature
- **Time Locks**: Implement time-based restrictions
- **Multi-Factor**: Require multiple secrets or conditions

### 3. Cross-Chain Verification

```psy
#[software_defined_signature]
pub fn cross_chain_collateral_auth(
    contract_id: Felt,
    inputs: &[Felt],
    ethereum_proof: EthereumStateProof,
    bridge_data: BridgeVerificationData,
) -> bool {
    // Verify state from Ethereum blockchain
    let eth_proof_valid = verify_ethereum_state_proof(&ethereum_proof, &bridge_data);
    assert(eth_proof_valid);
    
    // Extract user's Ethereum balance
    let ethereum_balance = extract_balance_from_eth_proof(&ethereum_proof);
    let required_collateral = MINIMUM_COLLATERAL_RATIO;
    
    // Constrain based on external state
    let collateral_sufficient = ethereum_balance > required_collateral;
    assert(collateral_sufficient);
    
    // Allow transaction only if collateral is sufficient
    let transaction_amount = inputs[0];
    transaction_amount <= ethereum_balance
}
```

## Ultra-Programmable Signatures

### Nested Circuit Architecture

The ultimate evolution enables arbitrary computation within signatures:

**QED Software Defined Signature (Ultra):**

```
public_key_params = hash(QEDProtocol)
fingerprint = hash(verifier_data)
public_key = hash(public_key_params, fingerprint)
sig_action_hash = hash(data, network_magic, nonce)

circuit = {
  let inner_circuit = compile(verify_balance_gt_zero)
  verify_inner_circuit(private_inputs, public_inputs)
}
public_inputs = hash(public_key_params, sig_action_hash)  
private_inputs = sig_action_hash_preimage
```

### High-Level Programming

Users can write signature logic in high-level languages:

```rust
// Rust function compiled to ZK circuit
fn verify_balance_gt_zero(user_leaf: UserLeaf) -> bool {
    user_leaf.balance > 0
}

// Complex authorization logic
fn advanced_authorization(
    user_leaf: UserLeaf,
    contract_call: ContractCall,
    checkpoint_data: CheckpointData
) -> bool {
    // Implement sophisticated authorization logic
    user_leaf.balance > contract_call.amount &&
    checkpoint_data.timestamp > user_leaf.last_transaction + cooldown_period &&
    contract_call.method_id.is_whitelisted()
}
```

**Capabilities:**
- **Rust Integration**: Write circuits in Rust using macros
- **VM Integration**: Embed ZKVM for arbitrary computation  
- **Nested Proofs**: Compose multiple proof systems
- **Code Reuse**: Share and reuse authorization components

## Implementation Patterns

### 1. Account Types

**EOA (Externally Owned Account)**:
- Uses traditional private key signatures
- Simple authentication model
- Direct user control

**SDA (Software Defined Account)**:
- Uses programmable circuit-based signatures  
- Complex authorization logic
- Automated or conditional execution

### 2. Circuit Management

**Off-Chain Storage**:
```bash
# Circuits are managed off-chain by users
.signatures/
├── matching_bot.circuit
├── conditional_spending.circuit
└── multi_factor.circuit
```

**Fingerprint Mapping**:
```rust
// Map fingerprints to circuit definitions
let circuit = load_circuit_by_fingerprint(user_public_key.fingerprint)?;
let proof = generate_signature_proof(circuit, private_inputs)?;
```

### 3. Security Model

**Public Key Composition**:
- `public_key_params`: Circuit-specific identifier
- `fingerprint`: Hash of circuit verifier data  
- `public_key`: Combined hash for on-chain storage

**Privacy Guarantees**:
- Circuit logic remains private (off-chain)
- Only fingerprint is public (on-chain)
- Zero-knowledge proofs don't reveal circuit internals

## Development Workflow

### 1. Circuit Development

```rust
// Write authorization logic
#[signature_circuit]
fn my_authorization_logic(
    secret: PrivateInput<F>,
    call_data: CallData,
    checkpoint: CheckpointData,
) -> PublicOutput<F> {
    // Implement custom authorization
}
```

### 2. Deployment

```bash
# Compile circuit
psy_compiler compile-signature-circuit my_auth.rs

# Register circuit fingerprint  
psy_user_cli register-user --circuit-fingerprint <fingerprint>
```

### 3. Usage

```bash
# Sign transaction with custom circuit
psy_user_cli call \
  --signature-circuit my_auth.circuit \
  --private-inputs secret.json \
  --contract-id 0 \
  --method-name transfer
```

## Future Directions

### 1. Circuit Marketplace

- **Shared Circuits**: Community-developed authorization patterns
- **Audited Components**: Verified and audited circuit modules
- **Composable Logic**: Mix and match authorization components

### 2. Hardware Integration

- **Hardware Wallets**: Support for complex circuits in hardware
- **Secure Enclaves**: Trusted execution for sensitive authorization logic
- **Mobile Optimization**: Efficient circuits for mobile devices

### 3. Cross-Chain Integration

- **Bridge Verification**: Verify state from other blockchains
- **Multi-Chain Auth**: Authorization spanning multiple networks
- **Interoperability**: Standard interfaces for cross-chain circuits

Software-defined signatures represent a fundamental shift from fixed cryptographic primitives to programmable authentication systems, enabling new classes of applications and user experiences.