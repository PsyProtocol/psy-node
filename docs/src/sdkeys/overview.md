# SDKeys Overview

Software-Defined Keys (SDKeys) is Psy's innovative signature system that allows users to define custom cryptographic circuits as their signing scheme. Unlike traditional fixed signature schemes, SDKeys enables programmable cryptography where users can implement their own zero-knowledge proof circuits for authentication.

## Key Concepts

### Software-Defined Signatures

In traditional blockchain systems, signature schemes are hardcoded (e.g., ECDSA, EdDSA). Psy introduces **Software-Defined Keys** where users can:

- **Define Custom Circuits**: Write zero-knowledge circuits that serve as signature schemes
- **Programmable Authentication**: Create complex authentication logic using ZK circuits
- **Flexible Security Models**: Choose between different trade-offs of security, performance, and complexity

### How SDKeys Work

1. **Circuit Definition**: Define a ZK circuit that implements custom authorization logic
2. **Proof Generation**: Generate zero-knowledge proofs based on the circuit constraints
3. **Verification**: The network verifies proofs against the circuit's public parameters
4. **Authentication**: Valid proofs authorize transactions without requiring traditional private keys

### Revolutionary Features

**Beyond Private Keys**: SDKeys enable a new paradigm of public, constraint-based accounts:

- **Anyone Can Deploy**: Any developer can write a circuit and deploy it as a new "user" on the network
- **Public Execution**: Once deployed, anyone can call these circuit-based accounts 
- **Constraint-Based Authorization**: The circuit defines what calls are allowed, not who can make them
- **Programmable Logic**: Complex business logic encoded directly in the authorization layer

**Key Innovation**: 
- **From Identity to Logic**: Authentication shifts from "who you are" (private key) to "what you can prove" (circuit satisfaction)
- **Public Smart Accounts**: Create accounts that anyone can use but with built-in constraints on how they operate
- **Decentralized Services**: Deploy autonomous services that operate according to mathematical rules rather than trust

### Benefits

- **Programmable Authorization**: Define complex authorization logic in circuits
- **Trustless Automation**: Bots and agents without trusted operators
- **Quantum Resistance**: ZK-based authentication immune to quantum attacks
- **Privacy Enhancement**: Hide authorization logic while proving compliance
- **Flexible Security Models**: Choose between private keys, public constraints, or hybrid approaches

## Built-in Signature Schemes

Psy provides two built-in signature schemes for immediate use, plus support for custom circuits:

- **ZK Key**: Optimized zero-knowledge signature scheme (recommended)
- **SECP256K1**: ECDSA-compatible scheme for legacy integration
- **Custom Circuits**: User-defined authorization logic for advanced use cases

For detailed technical specifications and performance comparisons, see [Signature Schemes](signature-schemes.md).

## Use Cases

### Traditional Use Cases (With Private Keys)
- **Personal Wallets**: Fast ZK-based transaction signing
- **Enhanced Privacy**: Hide transaction patterns and amounts
- **Multi-Factor Auth**: Combine multiple secrets or conditions

### Revolutionary Use Cases (Public Circuit Deployment)

#### Deployable Public Services

**Precise Parameter Control**: SDKeys allow you to constrain not just which contracts can be called, but the exact parameters:

```psy
// Example: Public Liquidation Service
#[software_defined_signature]
pub fn liquidation_bot_auth(
    contract_id: Felt,
    inputs: &[Felt],
    position_health: PositionHealthProof,
) -> bool {
    // Only allow calling liquidation contract
    if contract_id != LENDING_CONTRACT_ID {
        return false;
    }
    
    // Verify position is actually unhealthy
    if !verify_position_health_proof(position_health) {
        return false;
    }
    
    // Constrain liquidation parameters
    let liquidation_amount = inputs[1];
    let collateral_ratio = inputs[2];
    
    liquidation_amount <= MAX_LIQUIDATION_AMOUNT &&
    collateral_ratio >= MIN_COLLATERAL_RATIO &&
    position_health.account_id == inputs[0]  // ensure correct account
}

// Example: Public Treasury Management  
#[software_defined_signature]
pub fn treasury_bot_auth(
    contract_id: Felt,
    method_name: &str,
    inputs: &[Felt],
    allocation_data: AllocationProof,
) -> bool {
    if contract_id != TREASURY_CONTRACT_ID {
        return false;
    }
    
    match method_name {
        "stake" => {
            inputs[0] <= MAX_STAKE_PER_TX &&  // limit stake amount
            is_approved_validator(inputs[1])  // only approved validators  
        },
        "rebalance" => {
            // Only allow rebalancing when allocation drifts > 5%
            let drift = abs_diff(allocation_data.current, allocation_data.target);
            drift > 0.05 && inputs[0] == allocation_data.optimal_allocation
        },
        _ => false
    }
}
```

**Real-World Applications:**
- **DeFi Protocol Automation**: Anyone can trigger protocol operations (liquidations, rebalancing) but only when mathematically justified
- **DAO Treasury Management**: Public execution of treasury decisions with built-in governance constraints
- **Cross-Chain Bridge Operations**: Automated bridge operations with safety constraints

#### Example: Public Trading Bot

**Using Psy Language (DPN Software Defined):**
```psy
// Define a software-defined signature circuit in Psy language
#[software_defined_signature]
pub fn trading_bot_auth(
    contract_id: Felt,
    method_name: &str, 
    inputs: &[Felt],
    market_data: MarketData,
) -> bool {
    // Constrain which contract can be called
    if contract_id != TRADING_CONTRACT_ID {
        return false;
    }
    
    // Constrain which methods are allowed
    match method_name {
        "buy" => {
            // Constrain buy order parameters
            inputs[0] < MAX_BUY_AMOUNT &&    // amount constraint
            inputs[1] > MIN_PRICE &&         // minimum price  
            market_data.balance > inputs[0]  // sufficient balance
        },
        "sell" => {
            // Constrain sell order parameters
            inputs[0] < market_data.holdings &&  // can't sell more than owned
            inputs[1] < MAX_SLIPPAGE             // slippage protection
        },
        _ => false  // reject other methods
    }
}
```

**Using Plonky2 Circuits (Low-level):**
```rust
// Register circuit using Plonky2 directly
let fingerprint = circuit_manager
    .register_plonky2_software_defined_circuit(32, 4)
    .await?;

// Deploy DPNSoftwareDefinedCallData
let call_data = DPNSoftwareDefinedCallData {
    contract_id: TRADING_CONTRACT_ID,
    inputs: vec![amount, price, slippage_limit, market_condition],
};
```

**After deployment, anyone can trigger trades:**
```bash
# Anyone can call this software-defined account
psy_user_cli call \
  --software-defined-call \
  --contract-id 0 \
  --inputs "[1000, 95000, 500, 1]" \
  --fingerprint <trading_bot_fingerprint>
```

#### AI Agents and Autonomous Systems
- **Portfolio Rebalancing**: Deploy rebalancing logic that anyone can trigger when portfolios drift from targets
- **Yield Optimization**: Create yield farming bots with constraints ensuring optimal allocation
- **Risk Management**: Deploy automatic position sizing based on volatility metrics

#### Conditional and Time-Based Operations
- **Scheduled Payments**: Transactions authorized only at specific times
- **Oracle-Based Logic**: Authorization based on external data feeds
- **State-Dependent Actions**: Transactions conditional on blockchain state

#### Collaborative Systems
- **Shared Treasuries**: Group fund management with programmable spending rules
- **DAO Automation**: Governance decisions executed automatically when conditions are met
- **Multi-Party Computation**: Complex operations requiring multiple participants

## Getting Started

1. **[Choose a Signature Scheme](signature-schemes.md)**: Select between built-in options
2. **[Create a Wallet](wallet-management.md)**: Generate keys using your chosen scheme
3. **[Register User](wallet-management.md#user-registration)**: Register your public key with the network
4. **[Sign Transactions](wallet-management.md#signing-transactions)**: Use your keys to authenticate operations

## Security Considerations

- **Key Storage**: Securely store private keys and circuit parameters
- **Circuit Auditing**: Ensure custom circuits are properly audited
- **Backup Strategy**: Maintain secure backups of key material
- **Upgrade Planning**: Plan for signature scheme upgrades when needed