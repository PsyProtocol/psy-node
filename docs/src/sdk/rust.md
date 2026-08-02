# Rust SDK

The Psy Rust SDK provides programmatic access to the Psy network through the `psy-rust-sdk` crate. It includes the `RpcProvider` for network communication and data types for blockchain interaction.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
psy-rust-sdk = { path = "path/to/psy_sdk/psy-rust-sdk" }
```

Or include the underlying components:

```toml
[dependencies]
psy_provider = { path = "path/to/psy_provider" }
psy_data = { path = "path/to/psy_core/psy_data" }
psy_common = { path = "path/to/psy_core/psy_common" }
psy_config = { path = "path/to/psy_config" }
```

## Core Components

### Re-exports

The `psy-rust-sdk` crate re-exports essential components:

```rust
use psy_rust_sdk::{
    psy_common,
    psy_config::network_constants,
    psy_crypto,
    provider::{RpcProvider, ProveProxyRpcProvider},
    request,
    session,
    wallet,
};
```

## Configuration

Create a `config.json` file with network endpoints:

```json
{
  "networks": {
    "localhost": {
      "coordinator_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8545"]}
      ],
      "realm_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8546"]},
        {"id": 1, "rpc_url": ["http://127.0.0.1:8547"]}
      ],
      "prove_proxy_url": ["http://127.0.0.1:9999"],
      "fees": {
        "guta_fee": 5000000000
      }
    }
  }
}
```

## RpcProvider

The `RpcProvider` is the core component for programmatic interaction with the Psy network:

```rust
#![allow(unused)]
fn main() {
use psy_provider::provider::RpcProvider;

// Create from config file
let rpc_provider = RpcProvider::new_with_config_path("config.json")?;

// Or create from network config
let rpc_provider = RpcProvider::new_with_config(&network_config)?;

// Set user context
rpc_provider.set_user_id(user_id);

// Register user
let register_request = QRegisterUserRPCRequest { /* ... */ };
let user_uuid = rpc_provider.register_user(register_request).await?;

// Deploy contract
let deploy_request = QDeployContractRPCRequest { /* ... */ };
let contract_uuid = rpc_provider.deploy_contract(deploy_request).await?;

// Submit end cap (contract call result)
let end_cap_request = QSubmitEndCapRPCRequest { /* ... */ };
let end_cap_uuid = rpc_provider.submit_end_cap_proof(end_cap_request).await?;

// Get block state
let block_state = rpc_provider.get_realm_latest_block_state().await?;
}
```

### ProveProxyRpcProvider

For proof generation operations:

```rust
use psy_provider::provider::ProveProxyRpcProvider;

let prove_provider = ProveProxyRpcProvider::new_with_config(proof_proxy_url).await?;

// Register contract circuits
prove_provider.register_contract_circuits(contract_id, &contract_code).await?;

// Prove contract call
let proof = prove_provider.prove_contract_call(contract_id, fn_id, &input).await?;

// Prove UPS operations
let ups_proof = prove_provider.prove_ups_start(&ups_input).await?;
```

## Data Types

Core data structures in `psy_data`:

```rust
use psy_rust_sdk::psy_data::qdata::{
    checkpoint::PsyCheckpointLeaf,
    contract::{PsyContractLeaf, ContractCodeDefinition},
    user::PsyUserLeaf,
    user_public_key::PsyUserPublicKeyRecord,
};
```

### PsyUserLeaf
User account state in the merkle tree:
- `public_key`: User's public key hash
- `user_state_tree_root`: Root of user's state tree  
- `balance`: User's token balance
- `nonce`: Transaction sequence number
- `user_id`: Unique user identifier

### PsyContractLeaf  
Contract state in the merkle tree:
- `deployer`: Contract deployer's public key hash
- `function_tree_root`: Root of contract function tree
- `state_tree_height`: Height of contract state tree

### ContractCodeDefinition
Contract bytecode and metadata:
- `state_tree_height`: Contract state tree configuration
- `functions`: Array of contract function definitions

### PsyCheckpointLeaf
Checkpoint state in the merkle tree:
- `global_chain_root`: Root hash of the global chain state
- `stats`: Checkpoint statistics and metadata

### PsyUserPublicKeyRecord
Public key information for users:
- Maps user IDs to their public key data

