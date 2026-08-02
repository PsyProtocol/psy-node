# User Cli Interface
This documentation organizes the three core data query interfaces implemented by `RpcProvider` (`QTreeDataStoreReaderSync<F>`, `QMetaDataStoreReaderSync<F>`, and `PsyComboDataStoreReaderSync<F>`). It includes interface functions, method details, parameter descriptions, and return value types, focusing on core data query capabilities for blockchain scenarios such as users, contracts, and checkpoints.


## Basic Information
- **Core Dependent Types**:
  - `F = GoldilocksField`: A prime field type based on Plonky2, used for blockchain data verification and hash calculation.
  - `QHashOut<F>`: Hash output result type, storing raw data after hash calculation.
  - `MerkleProofCore<QHashOut<F>>`: Core Merkle proof type, containing information such as the root, value, and sibling nodes required for proof.

## Core Structures  

### `RpcProvider`  
The foundational component for RPC communication, responsible for interacting with **Realm nodes** (user-specific data) and **Coordinator nodes** (global public data, e.g., contracts, checkpoints). It supports cross-environment use (non-WASM like servers, WASM like browser extensions).  

#### Structure Definition  
```rust
#[derive(Debug, Clone)]
pub struct RpcProvider {
    pub client: Arc<Client>,               // HTTP client (for RPC requests)
    pub realm_configs: HashMap<u64, Vec<String>>,  // Realm node config: {Realm ID → List of RPC URLs}
    pub coordinator_configs: HashMap<u64, Vec<String>>,  // Coordinator node config: {Coordinator ID → List of RPC URLs}
    pub users_per_realm: u64,              // Number of users assigned to each Realm (for user-to-Realm routing)
    pub current_user_id: u64,              // ID of the currently active user (for default data requests)
}
```

#### Key Methods  
`RpcProvider` provides methods for node routing, user/contract/data queries, and transaction submission. Core methods are categorized below:  

| Category | Method Name | Parameters | Return Value | Function Description |
|----------|-------------|------------|--------------|-----------------------|
| **Node Routing** | `get_realm_id` | `user_id: u64` | `u64` | Calculate the Realm ID for a user (via `user_id / users_per_realm`). |
| | `get_realm_url` | `user_id: u64` | `anyhow::Result<&String>` | Get a random RPC URL of the Realm node corresponding to the user (for load balancing). |
| | `get_coordinator_url` | None | `anyhow::Result<&String>` | Get a random RPC URL of the Coordinator node (for global data requests). |
| **User Operations** | `register_user` | `req: QRegisterUserRPCRequest<F>` | `anyhow::Result<()>` | Submit a user registration request to the Coordinator node. |
| | `get_user_id` | `public_key: QHashOut<F>` | `anyhow::Result<u64>` | Query the user ID corresponding to a public key from the Coordinator node. |
| **Contract Operations** | `deploy_contract` | `req: QDeployContractRPCRequest<F>` | `anyhow::Result<()>` | Submit a contract deployment request to the Coordinator node. |
| **Data Queries** | `get_realm_latest_block_state` | None | `anyhow::Result<PsyBlockState>` | Query the latest L2 block state from the current user’s Realm node. |
| | `get_claim_amount` | `checkpoint_id: u64`, `user_id: u64`, `claim_user_id: u64` | `anyhow::Result<u64>` | Calculate the available claim amount for a user by querying contract state tree leaves. |
| | `check_tx_is_confirmed` | `checkpoint_id: u64`, `user_id: u64`, `tx_hash: QHashOut<GoldilocksField>` | `anyhow::Result<bool>` | Verify if a transaction is confirmed by comparing the user leaf hash with the transaction hash. |
| **Batch Proof Query** | `get_job_proofs` | `job_infos: Vec<JobInfo>` | `anyhow::Result<Vec<(QProvingJobDataID, VariableHeightRewardMerkleProof)>>` | Batch query reward Merkle proofs for multiple jobs (routes to Realm/Coordinator based on job location). |

### Auxiliary Structures  
#### `RpcConfig` & `NetworkConfig`  
Configuration structures for node networks and proxy services, loaded from external config files:  
```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RpcConfig {
    pub users_per_realm: u64,                // Number of users per Realm
    pub global_user_tree_height: u8,         // Height of the global user Merkle tree
    pub realm_user_tree_height: u8,          // Height of the Realm-specific user Merkle tree
    pub realm_configs: Vec<RealmRpcConfig>,  // List of Realm node configs
    pub coordinator_configs: Vec<CoordinatorRpcConfig>,  // List of Coordinator node configs
    pub prove_proxy_url: Vec<String>,        // List of proof proxy service URLs
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {  // Extended config for blockchain network
    pub users_per_realm: u64,
    pub global_user_tree_height: u8,
    pub realm_user_tree_height: u8,
    pub realm_configs: Vec<RealmConfig>,     // Same as RealmRpcConfig
    pub coordinator_configs: Vec<CoordinatorConfig>,  // Same as CoordinatorRpcConfig
    pub prover_url: Option<String>,          // Optional prover service URL
    pub prove_proxy_url: Vec<String>,
    pub native_currency: String,             // Native currency symbol (e.g., "PSY")
}
```


## Merkle Tree Data Query
This interface focuses on querying roots, leaf hashes, and Merkle proofs of various Merkle trees in the blockchain, covering core scenarios such as users, contracts, checkpoints, deposits, and withdrawals.

### 1. User-Related Merkle Tree Queries
#### (1) User Contract State Tree Queries (User-Contract Internal State)
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_user_contract_state_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint<br>- `user_id: u64`: Unique identifier for the user<br>- `contract_id: u32`: Unique identifier for the contract | `QHashOut<F>` | Queries the root hash of a user's contract state tree under a specified checkpoint | Realm Node |
| `get_user_contract_state_tree_leaf_hash` | - Same as above<br>- `height: u8`: Height of the state tree<br>- `leaf_id: u64`: Unique identifier for the leaf node | `QHashOut<F>` | Queries the hash of a specified leaf node in the state tree | Realm Node |
| `get_user_contract_state_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a specified leaf node in the state tree (including verification logic) | Realm Node |

#### (2) User Contract Tree Queries (User-Contract Association)
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_user_contract_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint<br>- `user_id: u64`: Unique identifier for the user | `QHashOut<F>` | Queries the root hash of a user's contract tree under a specified checkpoint | Realm Node |
| `get_user_contract_tree_leaf_hash` | - Same as above<br>- `contract_id: u32`: Unique identifier for the contract | `QHashOut<F>` | Queries the hash of the leaf node corresponding to a contract in the user's contract tree | Realm Node |
| `get_user_contract_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a contract in the user's contract tree | Realm Node |

#### (3) User Registration Tree Queries (Global User Registration State)
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_user_registration_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of the global user registration tree under a specified checkpoint | Coordinator Node |
| `get_user_registration_tree_leaf_hash` | - Same as above<br>- `leaf_index: u64`: Leaf index | `QHashOut<F>` | Queries the hash of a leaf node at a specified index in the user registration tree | Coordinator Node |
| `get_user_registration_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a leaf node at a specified index in the user registration tree | Coordinator Node |

#### (4) User Tree Queries (Global User State)
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_user_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of the global user tree under a specified checkpoint | Coordinator Node |
| `get_user_tree_leaf_hash` | - Same as above<br>- `user_id: u64`: Unique identifier for the user | `QHashOut<F>` | Queries the hash of the leaf node corresponding to a user in the user tree | Realm Node |
| `get_user_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a user in the user tree (automatically merges subtree proofs) | Coordinator & Realm Node |
| `get_user_sub_tree_merkle_proof` | - `checkpoint_id: u64`: Unique identifier for the checkpoint<br>- `root_level: u8`: Root level<br>- `leaf_level: u8`: Leaf level<br>- `leaf_index: u64`: Leaf index | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a specified level in the user subtree | Coordinator & Realm Node |


### 2. Contract-Related Merkle Tree Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_contract_function_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint<br>- `contract_id: u32`: Unique identifier for the contract | `QHashOut<F>` | Queries the root hash of a contract's function tree under a specified checkpoint | Coordinator Node |
| `get_contract_function_tree_leaf_hash` | - Same as above<br>- `function_id: u32`: Unique identifier for the function | `QHashOut<F>` | Queries the hash of a function's leaf node in the contract function tree | Coordinator Node |
| `get_contract_function_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a function in the contract function tree | Coordinator Node |
| `get_contract_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of the global contract tree under a specified checkpoint | Coordinator Node |
| `get_contract_tree_leaf_hash` | - Same as above<br>- `contract_id: u32`: Unique identifier for the contract | `QHashOut<F>` | Queries the hash of a contract's leaf node in the contract tree | Coordinator Node |
| `get_contract_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a contract in the contract tree | Coordinator Node |


### 3. Asset-Related Merkle Tree Queries
#### (1) Deposit Tree Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_deposit_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of the global deposit tree under a specified checkpoint | Coordinator Node |
| `get_deposit_tree_leaf_hash` | - Same as above<br>- `deposit_id: u32`: Unique identifier for the deposit | `QHashOut<F>` | Queries the hash of a deposit's leaf node in the deposit tree | Coordinator Node |
| `get_deposit_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a deposit in the deposit tree | Coordinator Node |

#### (2) Withdrawal Tree Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_withdrawal_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of the global withdrawal tree under a specified checkpoint | Coordinator Node |
| `get_withdrawal_tree_leaf_hash` | - Same as above<br>- `withdrawal_id: u32`: Unique identifier for the withdrawal | `QHashOut<F>` | Queries the hash of a withdrawal's leaf node in the withdrawal tree | Coordinator Node |
| `get_withdrawal_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a withdrawal in the withdrawal tree | Coordinator Node |


### 4. Checkpoint-Related Merkle Tree Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_latest_checkpoint_tree_root` | No parameters | `QHashOut<F>` | Queries the root hash of the latest checkpoint tree | Coordinator Node |
| `get_checkpoint_tree_root` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `QHashOut<F>` | Queries the root hash of a specified checkpoint tree | Coordinator Node |
| `get_checkpoint_tree_leaf_hash` | - Same as above<br>- `leaf_checkpoint_id: u64`: Leaf checkpoint ID | `QHashOut<F>` | Queries the hash of a leaf node in the checkpoint tree | Coordinator Node |
| `get_checkpoint_tree_merkle_proof` | Same parameters as above | `MerkleProofCore<QHashOut<F>>` | Queries the Merkle proof of a leaf node in the checkpoint tree | Coordinator Node |


## Metadata Query
This interface focuses on querying core blockchain metadata, including complete leaf data for users, contracts, and checkpoints, as well as L2 block states.


### 1. User Metadata Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_user_leaf_data` | - `checkpoint_id: u64`: Unique identifier for the checkpoint<br>- `user_id: u64`: Unique identifier for the user | `PsyUserLeaf<F>` | Queries complete leaf data for a user under a specified checkpoint (including user state, hash, etc.) | Realm Node |


### 2. Contract Metadata Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_contract_leaf_data` | - `contract_id: u64`: Unique identifier for the contract | `PsyContractLeaf<F>` | Queries complete leaf data for a contract (including basic contract information, state, etc.) | Coordinator Node |
| `get_contract_code_definition` | - `contract_id: u64`: Unique identifier for the contract | `ContractCodeDefinition` | Queries the code definition of a contract (including bytecode, function list, etc.) | Coordinator Node |


### 3. Checkpoint and L2 Block State Queries
| Method Name | Parameter Description | Return Value | Function Description | Called Node |
|-------------|------------------------|--------------|----------------------|-------------|
| `get_checkpoint_leaf_data` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `PsyCheckpointLeaf<F>` | Queries complete leaf data for a specified checkpoint (including global state root, block information, etc.) | Coordinator Node |
| `get_latest_block_state` | No parameters | `PsyBlockState` | Queries the complete state of the latest L2 block (including block height, transaction count, etc.) | Coordinator Node |
| `get_block_state` | - `checkpoint_id: u64`: Unique identifier for the checkpoint | `PsyBlockState` | Queries the L2 block state corresponding to a specified checkpoint | Coordinator Node |

