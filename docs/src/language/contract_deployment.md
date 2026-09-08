# Contract Deployment Architecture

> Updated: 2026-09-03.

## Abstract


This document explains how Psy smart contract functions are compiled, deployed, and organized in the blockchain's state trees.

## 1. Function Compilation Pipeline

When a Psy smart contract is compiled, each function goes through the following process:

1. **Source Code** → **DPN Opcodes** → **ZK Circuit** → **Verifier Data**
2. The resulting verifier data and function metadata are stored on-chain in a hierarchical tree structure

## 2. Contract Function Tree

Each deployed contract maintains a **Contract Function Tree** that stores information about all its public functions.

### Function Storage Layout

Each function occupies **two leaves** in the Contract Function Tree:

#### Leaf 1: Function Signature
```rust
// Function metadata including name, parameters, and return types
let function_signature: FunctionSignature = FunctionSignature {
    name: "transfer",
    parameters: vec![("recipient", "Felt"), ("amount", "Felt")],
    return_type: "Felt",
    visibility: "pub",
};
```

#### Leaf 2: Verifier Data Hash
```rust
// Hash of the ZK circuit verifier data generated from DPN opcodes
let verifier_hash: QHashOut<F> = hash(circuit_verifier_data);
```

### Function Tree Organization

```text
Contract Function Tree
├── Function 0
│   ├── Leaf 0: Function Signature
│   └── Leaf 1: Verifier Data Hash
├── Function 1  
│   ├── Leaf 2: Function Signature
│   └── Leaf 3: Verifier Data Hash
├── Function 2
│   ├── Leaf 4: Function Signature
│   └── Leaf 5: Verifier Data Hash
└── ...
```

## 3. Contract Tree Structure

The Contract Function Tree root is then stored as part of a **Contract Leaf** in the higher-level **Contract Tree**.

### PsyContractLeaf Structure

```rust
pub struct PsyContractLeaf<F: RichField> {
    pub deployer: QHashOut<F>,
    pub function_tree_root: QHashOut<F>,
    pub code_root: QHashOut<F>,
    pub state_tree_height: F,
    pub state_layout_root: QHashOut<F>,
    pub state_layout_field_count: F,
    pub state_layout_slot_count: F,
}
```

#### Field Explanations

##### `deployer: QHashOut<F>`
- **Purpose**: Identifies who deployed this contract
- **Content**: The deployer's public key
- **Usage**: 
  - Access control and permissions
  - Contract ownership verification
  - Audit trails for contract deployment

##### `function_tree_root: QHashOut<F>`
- **Purpose**: Root hash of the Contract Function Tree
- **Content**: Merkle root containing all function verifier data and signatures
- **Usage**:
  - Efficient verification of function existence
  - Proof generation for function calls
  - Contract integrity validation

##### `code_root: QHashOut<F>`
- **Purpose**: Commitment to the contract's compiled code/circuit material
- **Content**: Root hash of code-related leaves used at deployment

##### `state_tree_height: F`
- **Purpose**: Defines the maximum depth/capacity of the contract's state tree
- **Content**: Height parameter determining how many state slots the contract can use
- **Usage**:
  - State tree initialization and validation
  - Memory allocation for contract state
  - Gas/resource calculation for state operations

##### `state_layout_root: QHashOut<F>`
- **Purpose**: Commitment to the contract storage layout
- **Content**: Root hash of the layout description used by storage accessors

##### `state_layout_field_count: F` / `state_layout_slot_count: F`
- **Purpose**: Layout sizing metadata for fields and slots in the contract state tree

## 4. Complete Storage Hierarchy

```text
Global Contract Tree
├── Contract 0
│   ├── deployer: QHashOut<F>
│   ├── function_tree_root: QHashOut<F>  ──┐
│   ├── code_root: QHashOut<F>             │
│   ├── state_tree_height: F               │
│   ├── state_layout_root: QHashOut<F>     │
│   ├── state_layout_field_count: F        │
│   └── state_layout_slot_count: F         │
├── Contract 1                             │
│   └── (same leaf fields)                 │
└── ...                                    │
                                           │
            ┌──────────────────────────────┘
            ▼
    Contract Function Tree (for Contract 0)
    ├── mint()
    │   ├── Function Signature
    │   └── Verifier Data Hash
    ├── transfer()  
    │   ├── Function Signature
    │   └── Verifier Data Hash
    ├── burn()
    │   ├── Function Signature
    │   └── Verifier Data Hash
    └── ...
```

## 5. Function Call Verification Process

When a function is called on-chain:

1. **Locate Contract**: Find the contract in Global Contract Tree using contract ID
2. **Verify Contract Link**: Ensure the contract is linked to the checkpoint tree root
3. **Match Function Signature**: Verify the call data matches a function signature in the Contract Function Tree
4. **Validate Circuit**: Confirm the function's compiled circuit corresponds to the verifier data hash stored in the Contract Function Tree
5. **Execute**: Verify witness satisfies circuit constraints and process the function call (handled by Psy zkVM)

## 6. Token Contract Storage Example

```rust
// Example token contract with 3 functions
contract Token {
    pub fn mint(amount: Felt) -> Felt { ... }
    pub fn transfer(to: Felt, amount: Felt) -> Felt { ... }  
    pub fn burn(amount: Felt) -> Felt { ... }
}
```

**Compiled Storage Structure:**
```text
Contract Leaf:
├── deployer: deployer_public_key
├── function_tree_root: merkle_root([
│   │   mint_signature,
│   │   mint_verifier_hash,
│   │   transfer_signature, 
│   │   transfer_verifier_hash,
│   │   burn_signature,
│   │   burn_verifier_hash
│   ])
├── code_root: code_commitment
├── state_tree_height: 8  // Supports 2^8 = 256 state slots
├── state_layout_root: layout_commitment
├── state_layout_field_count: <field count>
└── state_layout_slot_count: <slot count>
```

This architecture enables Psy to efficiently store, lookup, and verify smart contract functions while maintaining the security properties required for a trustless blockchain system.