# Coordinator Edge RPC Documentation

This document provides comprehensive documentation for all Coordinator Edge RPC methods defined in the `CoordinatorEdgeRpc` trait.

**RPC Namespace**: `psy`

---

## Table of Contents

1. [User Management](#user-management)
2. [Contract Management](#contract-management)
3. [Block Operations](#block-operations)
4. [GUTA Submission](#guta-submission)
5. [Checkpoint Operations](#checkpoint-operations)
6. [Checkpoint Sync](#checkpoint-sync)
7. [L2 Block State Operations](#l2-block-state-operations)
8. [User Registration Tree Operations](#user-registration-tree-operations)
9. [User Tree Operations](#user-tree-operations)
10. [Contract Function Tree Operations](#contract-function-tree-operations)
11. [Contract Tree Operations](#contract-tree-operations)
12. [Deposit Tree Operations](#deposit-tree-operations)
13. [Withdrawal Tree Operations](#withdrawal-tree-operations)
14. [Checkpoint Tree Operations](#checkpoint-tree-operations)
15. [Reward Proofs Generation](#reward-proofs-generation)
16. [Realm Status Operations](#realm-status-operations)
17. [Data Structures](#data-structures)

---

## User Management

### 1. register_user

Register a new user with ZK public key.

**Method Name**: `psy_register_user`

**Request Parameters**:
```json
{
  "public_key": {
    "fingerprint": "0x1234...",
    "public_key_param": "0x5678..."
  }
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `public_key` | `ZKPublicKeyInfo<F>` | ZK public key information |

**Response**:
```json
{
  "result": "ok"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `String` | "ok" on success |

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_register_user",
    "params": [{
      "fingerprint": "0x...",
      "public_key_param": "0x..."
    }],
    "id": 1
  }'
```

---

### 2. get_user_id

Get user ID by public key hash.

**Method Name**: `psy_get_user_id`

**Request Parameters**:
```json
{
  "public_key": "0x1234567890abcdef..."
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `public_key` | `QHashOut<F>` | User's public key hash |

**Response**:
```json
{
  "result": 12345
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `u64` | User ID |

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_id",
    "params": ["0x1234..."],
    "id": 1
  }'
```

---

## Contract Management

### 3. deploy_contract

Deploy a new smart contract.

**Method Name**: `psy_deploy_contract`

**Request Parameters**:
```json
{
  "deploy_contract": {
    "deployer": "0x1234...",
    "code_definition": {
      "state_tree_height": 10,
      "functions": [...]
    },
    "function_whitelist": ["0x..."]
  }
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `deploy_contract` | `QBCDeployContract<F>` | Contract deployment data (see [QBCDeployContract](#qbcdeploycontract)) |

**Response**:
```json
{
  "result": "ok"
}
```

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_deploy_contract",
    "params": [{
      "deployer": "0x...",
      "code_definition": {...},
      "function_whitelist": [...]
    }],
    "id": 1
  }'
```

---

### 4. get_contract_leaf_data

Get contract leaf data by contract ID (u64 parameter).

**Method Name**: `psy_get_contract_leaf_data`

**Request Parameters**:
```json
{
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `contract_id` | `u64` | The contract ID |

**Response**: See [PsyContractLeaf](#psycontractleaf)

---

### 5. get_contract_leaf_data_f

Get contract leaf data by contract ID (Field parameter).

**Method Name**: `psy_get_contract_leaf_data_f`

**Request Parameters**:
```json
{
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [PsyContractLeaf](#psycontractleaf)

---

### 6. get_contract_code_definition

Get contract code definition by contract ID (u64 parameter).

**Method Name**: `psy_get_contract_code_definition`

**Request Parameters**:
```json
{
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `contract_id` | `u64` | The contract ID |

**Response**: See [ContractCodeDefinition](#contractcodedefinition)

---

### 7. get_contract_code_definition_f

Get contract code definition by contract ID (Field parameter).

**Method Name**: `psy_get_contract_code_definition_f`

**Request Parameters**:
```json
{
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [ContractCodeDefinition](#contractcodedefinition)

---

## Block Operations

### 8. build_block

Trigger building a new block/checkpoint.

**Method Name**: `psy_build_block`

**Request Parameters**: None

**Response**:
```json
{
  "result": "ok"
}
```

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_build_block",
    "params": [],
    "id": 1
  }'
```

---

## GUTA Submission

### 9. submit_guta

Submit GUTA (Global User Tree Aggregator) result with proof.

**Method Name**: `psy_submit_guta`

**Request Parameters**:
```json
{
  "input": {
    "realm_id": 1,
    "checkpoint_id": 100,
    "guta_stats": {...},
    "top_line_proof": {...},
    "checkpoint_tree_root": "0x...",
    "proof_id": {...}
  },
  "proof": {...},
  "realm_id": 1
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | `SubmitGUTARealmResultAPINoProofInput<F>` | GUTA submission input |
| `proof` | `ProofWithPublicInputs<F, C, D>` | Zero-knowledge proof |
| `realm_id` | `u64` | Realm identifier |

**Response**:
```json
{
  "result": "ok"
}
```

---

### 10. submit_guta_v1

Submit GUTA result with serialized proof (v1 format).

**Method Name**: `psy_submit_guta_v1`

**Request Parameters**:
```json
{
  "input": {...},
  "proof": "0x...",
  "realm_id": 1
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `input` | `SubmitGUTARealmResultAPINoProofInput<F>` | GUTA submission input |
| `proof` | `Vec<u8>` | Serialized proof bytes |
| `realm_id` | `u64` | Realm identifier |

**Response**:
```json
{
  "result": null
}
```

---

### 11. submit_realm_result

Submit realm processing result to coordinator.

**Method Name**: `psy_submit_realm_result`

**Request Parameters**:
```json
{
  "realm_result": {
    "header": {
      "realm_id": 1,
      "checkpoint_id": 100,
      "start_realm_root": "0x...",
      "end_realm_root": "0x...",
      "guta_stats": {...},
      "root_job_id": {...}
    },
    "proof": "0x..."
  }
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_result` | `RealmDataForCoordinator<F>` | Realm result data |

**Response**:
```json
{
  "result": null
}
```

---

## Checkpoint Operations

### 12. get_latest_checkpoint

Get latest checkpoint information.

**Method Name**: `psy_get_latest_checkpoint`

**Request Parameters**: None

**Response**:
```json
{
  "result": {
    "checkpoint_id": 100
  }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `checkpoint_id` | `u64` | Latest checkpoint ID |

---

### 13. latest_checkpoint

Get latest checkpoint ID (simple version).

**Method Name**: `psy_latest_checkpoint`

**Request Parameters**: None

**Response**:
```json
{
  "result": 100
}
```

---

### 14. get_latest_checkpoint_id

Get latest checkpoint ID.

**Method Name**: `psy_get_latest_checkpoint_id`

**Request Parameters**: None

**Response**:
```json
{
  "result": 100
}
```

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_latest_checkpoint_id",
    "params": [],
    "id": 1
  }'
```

---

### 15. get_checkpoint_leaf_data

Get checkpoint leaf data by checkpoint ID (u64 parameter).

**Method Name**: `psy_get_checkpoint_leaf_data`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [PsyCheckpointLeaf](#psycheckpointleaf)

---

### 16. get_checkpoint_leaf_data_f

Get checkpoint leaf data by checkpoint ID (Field parameter).

**Method Name**: `psy_get_checkpoint_leaf_data_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [PsyCheckpointLeaf](#psycheckpointleaf)

---

### 17. get_checkpoint_global_state_roots

Get global state roots at a specific checkpoint.

**Method Name**: `psy_get_checkpoint_global_state_roots`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [PsyCheckpointGlobalStateRoots](#psycheckpointglobalstateroots)

---

## Checkpoint Sync

### 18. get_checkpoint_sync_info

Get checkpoint sync information for a realm.

**Method Name**: `psy_get_checkpoint_sync_info`

**Request Parameters**:
```json
{
  "realm_id": 1,
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `u32` | Realm identifier |
| `checkpoint_id` | `u64` | Checkpoint ID |

**Response**: See [CheckpointSyncInfo](#checkpointsyncinfo)

---

### 19. get_checkpoint_sync_info_compact

Get compact checkpoint sync information.

**Method Name**: `psy_get_checkpoint_sync_info_compact`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | Checkpoint ID |

**Response**: See [PsyCheckpointSyncInfoCompact](#psycheckpointsyncinfo compact)

---

## L2 Block State Operations

### 20. get_latest_block_state

Get the latest L2 block state.

**Method Name**: `psy_get_latest_block_state`

**Request Parameters**: None

**Response**: See [PsyBlockState](#psyblockstate)

**Example Response**:
```json
{
  "result": {
    "checkpoint_id": 100,
    "next_add_withdrawal_id": 50,
    "next_process_withdrawal_id": 45,
    "next_deposit_id": 200,
    "total_deposits_claimed_epoch": 180,
    "next_user_id": 1000,
    "end_balance": 5000000,
    "next_contract_id": 25
  }
}
```

---

### 21. get_block_state

Get L2 block state at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_block_state`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [PsyBlockState](#psyblockstate)

---

### 22. get_block_state_f

Get L2 block state at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_block_state_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [PsyBlockState](#psyblockstate)

---

## User Registration Tree Operations

### 23. get_user_registration_tree_root

Get user registration tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_user_registration_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 24. get_user_registration_tree_root_f

Get user registration tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_user_registration_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 25. get_user_registration_tree_leaf_hash

Get user registration tree leaf hash (u64 parameters).

**Method Name**: `psy_get_user_registration_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "leaf_index": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `leaf_index` | `u64` | The leaf index |

**Response**: See [QHashOut](#qhashout)

---

### 26. get_user_registration_tree_leaf_hash_f

Get user registration tree leaf hash (Field parameters).

**Method Name**: `psy_get_user_registration_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "leaf_index": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `leaf_index` | `F` (Field) | The leaf index as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 27. get_user_registration_tree_merkle_proof

Get Merkle proof for user registration tree (u64 parameters).

**Method Name**: `psy_get_user_registration_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "leaf_index": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `leaf_index` | `u64` | The leaf index |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 28. get_user_registration_tree_merkle_proof_f

Get Merkle proof for user registration tree (Field parameters).

**Method Name**: `psy_get_user_registration_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "leaf_index": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `leaf_index` | `F` (Field) | The leaf index as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## User Tree Operations

### 29. get_user_tree_root

Get user tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_user_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 30. get_user_tree_root_f

Get user tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_user_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 31. get_user_sub_tree_merkle_proof

Get Merkle proof for user sub-tree.

**Method Name**: `psy_get_user_sub_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "root_level": 5,
  "leaf_level": 2,
  "leaf_index": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `root_level` | `u8` | Root level of the tree |
| `leaf_level` | `u8` | Leaf level of the tree |
| `leaf_index` | `u64` | The leaf index |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 32. get_user_top_tree_merkle_proof

Get Merkle proof for user top tree.

**Method Name**: `psy_get_user_top_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "leaf_level": 2,
  "leaf_index": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `leaf_level` | `u8` | Leaf level of the tree |
| `leaf_index` | `u64` | The leaf index |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 33. get_user_top_tree_cap_root

Get user top tree cap root.

**Method Name**: `psy_get_user_top_tree_cap_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "cap_level": 3,
  "cap_index": 10
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `cap_level` | `u8` | Cap level |
| `cap_index` | `u64` | Cap index |

**Response**: See [QHashOut](#qhashout)

---

### 34. get_user_latest_top_tree_cap_root

Get latest user top tree cap root.

**Method Name**: `psy_get_user_latest_top_tree_cap_root`

**Request Parameters**:
```json
{
  "cap_level": 3,
  "cap_index": 10
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `cap_level` | `u8` | Cap level |
| `cap_index` | `u64` | Cap index |

**Response**: See [QHashOut](#qhashout)

---

### 35. get_user_leaf_data

Get user leaf data at a specific checkpoint.

**Method Name**: `psy_get_user_leaf_data`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |

**Response**: See [PsyUserLeaf](#psyuserleaf)

---

### 36. get_user_tree_merkle_proof

Get Merkle proof for user tree (u64 parameters).

**Method Name**: `psy_get_user_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 37. get_user_tree_merkle_proof_f

Get Merkle proof for user tree (Field parameters).

**Method Name**: `psy_get_user_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Contract Function Tree Operations

### 38. get_contract_function_tree_root

Get contract function tree root (u64 parameters).

**Method Name**: `psy_get_contract_function_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [QHashOut](#qhashout)

---

### 39. get_contract_function_tree_root_f

Get contract function tree root (Field parameters).

**Method Name**: `psy_get_contract_function_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 40. get_contract_function_tree_leaf_hash

Get contract function tree leaf hash (u64 parameters).

**Method Name**: `psy_get_contract_function_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "contract_id": 5,
  "function_id": 3
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `contract_id` | `u32` | The contract ID |
| `function_id` | `u32` | The function ID |

**Response**: See [QHashOut](#qhashout)

---

### 41. get_contract_function_tree_leaf_hash_f

Get contract function tree leaf hash (Field parameters).

**Method Name**: `psy_get_contract_function_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "contract_id": "5",
  "function_id": "3"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |
| `function_id` | `F` (Field) | The function ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 42. get_contract_function_tree_merkle_proof

Get Merkle proof for contract function tree (u64 parameters).

**Method Name**: `psy_get_contract_function_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "contract_id": 5,
  "function_id": 3
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `contract_id` | `u32` | The contract ID |
| `function_id` | `u32` | The function ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 43. get_contract_function_tree_merkle_proof_f

Get Merkle proof for contract function tree (Field parameters).

**Method Name**: `psy_get_contract_function_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "contract_id": "5",
  "function_id": "3"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |
| `function_id` | `F` (Field) | The function ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Contract Tree Operations

### 44. get_contract_tree_root

Get contract tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_contract_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 45. get_contract_tree_root_f

Get contract tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_contract_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 46. get_contract_tree_leaf_hash

Get contract tree leaf hash (u64 parameters).

**Method Name**: `psy_get_contract_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [QHashOut](#qhashout)

---

### 47. get_contract_tree_leaf_hash_f

Get contract tree leaf hash (Field parameters).

**Method Name**: `psy_get_contract_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 48. get_contract_tree_merkle_proof

Get Merkle proof for contract tree (u64 parameters).

**Method Name**: `psy_get_contract_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 49. get_contract_tree_merkle_proof_f

Get Merkle proof for contract tree (Field parameters).

**Method Name**: `psy_get_contract_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Deposit Tree Operations

### 50. get_deposit_tree_root

Get deposit tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_deposit_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 51. get_deposit_tree_root_f

Get deposit tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_deposit_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 52. get_deposit_tree_leaf_hash

Get deposit tree leaf hash (u64 parameters).

**Method Name**: `psy_get_deposit_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "deposit_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `deposit_id` | `u32` | The deposit ID |

**Response**: See [QHashOut](#qhashout)

---

### 53. get_deposit_tree_leaf_hash_f

Get deposit tree leaf hash (Field parameters).

**Method Name**: `psy_get_deposit_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "deposit_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `deposit_id` | `F` (Field) | The deposit ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 54. get_deposit_tree_merkle_proof

Get Merkle proof for deposit tree (u64 parameters).

**Method Name**: `psy_get_deposit_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "deposit_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `deposit_id` | `u32` | The deposit ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 55. get_deposit_tree_merkle_proof_f

Get Merkle proof for deposit tree (Field parameters).

**Method Name**: `psy_get_deposit_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "deposit_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `deposit_id` | `F` (Field) | The deposit ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Withdrawal Tree Operations

### 56. get_withdrawal_tree_root

Get withdrawal tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_withdrawal_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 57. get_withdrawal_tree_root_f

Get withdrawal tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_withdrawal_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 58. get_withdrawal_tree_leaf_hash

Get withdrawal tree leaf hash (u64 parameters).

**Method Name**: `psy_get_withdrawal_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "withdrawal_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `withdrawal_id` | `u32` | The withdrawal ID |

**Response**: See [QHashOut](#qhashout)

---

### 59. get_withdrawal_tree_leaf_hash_f

Get withdrawal tree leaf hash (Field parameters).

**Method Name**: `psy_get_withdrawal_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "withdrawal_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `withdrawal_id` | `F` (Field) | The withdrawal ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 60. get_withdrawal_tree_merkle_proof

Get Merkle proof for withdrawal tree (u64 parameters).

**Method Name**: `psy_get_withdrawal_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "withdrawal_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `withdrawal_id` | `u32` | The withdrawal ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 61. get_withdrawal_tree_merkle_proof_f

Get Merkle proof for withdrawal tree (Field parameters).

**Method Name**: `psy_get_withdrawal_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "withdrawal_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `withdrawal_id` | `F` (Field) | The withdrawal ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Checkpoint Tree Operations

### 62. get_latest_checkpoint_tree_root

Get the latest checkpoint tree root.

**Method Name**: `psy_get_latest_checkpoint_tree_root`

**Request Parameters**: None

**Response**: See [QHashOut](#qhashout)

---

### 63. get_checkpoint_tree_root

Get checkpoint tree root at a specific checkpoint (u64 parameter).

**Method Name**: `psy_get_checkpoint_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 64. get_checkpoint_tree_root_f

Get checkpoint tree root at a specific checkpoint (Field parameter).

**Method Name**: `psy_get_checkpoint_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 65. get_checkpoint_tree_leaf_hash

Get checkpoint tree leaf hash (u64 parameters).

**Method Name**: `psy_get_checkpoint_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "leaf_checkpoint_id": 95
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `leaf_checkpoint_id` | `u64` | The leaf checkpoint ID |

**Response**: See [QHashOut](#qhashout)

---

### 66. get_checkpoint_tree_leaf_hash_f

Get checkpoint tree leaf hash (Field parameters).

**Method Name**: `psy_get_checkpoint_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "leaf_checkpoint_id": "95"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `leaf_checkpoint_id` | `F` (Field) | The leaf checkpoint ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 67. get_checkpoint_tree_merkle_proof

Get Merkle proof for checkpoint tree (u64 parameters).

**Method Name**: `psy_get_checkpoint_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "leaf_checkpoint_id": 95
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `leaf_checkpoint_id` | `u64` | The leaf checkpoint ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 68. get_checkpoint_tree_merkle_proof_f

Get Merkle proof for checkpoint tree (Field parameters).

**Method Name**: `psy_get_checkpoint_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "leaf_checkpoint_id": "95"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `leaf_checkpoint_id` | `F` (Field) | The leaf checkpoint ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## Reward Proofs Generation

### 69. generate_batch_variable_height_reward_proofs

Generate batch variable height reward Merkle proofs for multiple job IDs.

**Method Name**: `psy_generate_batch_variable_height_reward_proofs`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "job_ids": [
    {
      "topic": "GenerateStandardProof",
      "goal_id": 100,
      "slot_id": 5,
      "circuit_type": "GUTATwoEndCap",
      "group_id": 1,
      "sub_group_id": 0,
      "task_index": 0,
      "data_type": "InputWitness",
      "data_index": 0
    }
  ]
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `job_ids` | `Vec<QProvingJobDataID>` | Array of proving job data IDs |

**Response**:
```json
{
  "result": [
    [
      {
        "top_siblings": [...],
        "sibling_branch": "0x...",
        "reward_leaf": "0x...",
        "proof_height": "5",
        "index": "42"
      },
      {
        "topic": "GenerateStandardProof",
        "goal_id": 100,
        ...
      }
    ]
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `Vec<(VariableHeightRewardMerkleProof, QProvingJobDataID)>` | Array of tuples containing proofs and job IDs |

---

### 70. get_graphviz

Get GraphViz representation of the job dependency graph at a specific checkpoint.

**Method Name**: `psy_get_graphviz`

**Request Parameters**:
```json
{
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |

**Response**:
```json
{
  "result": "digraph G {\n  node1 -> node2;\n  ...\n}"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `String` | GraphViz DOT format string |

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_graphviz",
    "params": [100],
    "id": 1
  }' | jq -r '.result' | dot -Tpng > graph.png
```

---

## Realm Status Operations

### 71. get_current_realm_status_on_coordinator

Get current realm status on the coordinator.

**Method Name**: `psy_get_current_realm_status_on_coordinator`

**Request Parameters**:
```json
{
  "realm_id": 1
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `u64` | Realm identifier |

**Response**: See [BasicRealmStatusOnCoordinator](#basicrealmstatusoncoordinator)

**Example Response**:
```json
{
  "result": {
    "realm_id": 1,
    "checkpoint_id": 100,
    "realm_root_hash": "0x..."
  }
}
```

---

### 72. get_current_checkpoint_id

Get current coordinator checkpoint ID.

**Method Name**: `psy_get_current_checkpoint_id`

**Request Parameters**: None

**Response**:
```json
{
  "result": 100
}
```

---

### 73. get_latest_block_updates_from_coordinator

Get latest block updates from coordinator for a realm within a checkpoint range.

**Method Name**: `psy_get_latest_block_updates_from_coordinator`

**Request Parameters**:
```json
{
  "realm_id": 1,
  "from_checkpoint": 95,
  "to_checkpoint": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `u32` | Realm identifier |
| `from_checkpoint` | `u64` | Starting checkpoint ID (inclusive) |
| `to_checkpoint` | `u64` | Ending checkpoint ID (inclusive) |

**Response**:
```json
{
  "result": [
    {
      "latest_checkpoint_id": 100,
      "description": null,
      "source_coordinator_edge_id": null,
      "sync_timestamp": 1234567890,
      "compact": {...},
      "realm_root": "0x..."
    }
  ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `Vec<GlobalBlockUpdateFromCoordinator<F>>` | Array of block updates |

---

### 74. wait_until_coordinator_completed

Wait until coordinator completes a specific checkpoint for a realm.

**Method Name**: `psy_wait_until_coordinator_completed`

**Request Parameters**:
```json
{
  "realm_id": 1,
  "checkpoint_id": 100
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `realm_id` | `u64` | Realm identifier |
| `checkpoint_id` | `u64` | Checkpoint ID to wait for |

**Response**: See [GlobalBlockUpdateFromCoordinator](#globalblockupdatefromcoordinator)

---

## Data Structures

### QHashOut

A hash output wrapper for Plonky2 field elements.

**Structure**:
```rust
pub struct QHashOut<F: Field>(pub HashOut<F>);
```

**JSON Representation**:
```json
"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
```

**Description**: 
- Wraps a Plonky2 `HashOut<F>` containing 4 field elements
- Serialized as a hexadecimal string (32 bytes)
- Represents a 256-bit hash value

---

### PsyBlockState

L2 block state information at a specific checkpoint.

**Structure**:
```rust
pub struct PsyBlockState {
    pub checkpoint_id: u64,
    pub next_add_withdrawal_id: u64,
    pub next_process_withdrawal_id: u64,
    pub next_deposit_id: u64,
    pub total_deposits_claimed_epoch: u64,
    pub next_user_id: u64,
    pub end_balance: u64,
    pub next_contract_id: u32,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint identifier |
| `next_add_withdrawal_id` | `u64` | Next withdrawal ID to be added |
| `next_process_withdrawal_id` | `u64` | Next withdrawal ID to be processed |
| `next_deposit_id` | `u64` | Next deposit ID |
| `total_deposits_claimed_epoch` | `u64` | Total deposits claimed in current epoch |
| `next_user_id` | `u64` | Next user ID to be assigned |
| `end_balance` | `u64` | Ending balance at this checkpoint |
| `next_contract_id` | `u32` | Next contract ID to be assigned |

**Example**:
```json
{
  "checkpoint_id": 100,
  "next_add_withdrawal_id": 50,
  "next_process_withdrawal_id": 45,
  "next_deposit_id": 200,
  "total_deposits_claimed_epoch": 180,
  "next_user_id": 1000,
  "end_balance": 5000000,
  "next_contract_id": 25
}
```

---

### PsyCheckpointLeaf

Checkpoint leaf data containing global chain root and statistics.

**Structure**:
```rust
pub struct PsyCheckpointLeaf<F: RichField> {
    pub global_chain_root: QHashOut<F>,
    pub stats: PsyCheckpointLeafStats<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `global_chain_root` | `QHashOut<F>` | Global chain state root hash |
| `stats` | `PsyCheckpointLeafStats<F>` | Checkpoint statistics |

---

### PsyCheckpointGlobalStateRoots

Global state roots at a specific checkpoint.

**Structure**:
```rust
pub struct PsyCheckpointGlobalStateRoots<F: RichField> {
    pub contract_tree_root: QHashOut<F>,
    pub deposit_tree_root: QHashOut<F>,
    pub user_tree_root: QHashOut<F>,
    pub withdrawal_tree_root: QHashOut<F>,
    pub user_registration_tree_root: QHashOut<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `contract_tree_root` | `QHashOut<F>` | Root of the contract tree |
| `deposit_tree_root` | `QHashOut<F>` | Root of the deposit tree |
| `user_tree_root` | `QHashOut<F>` | Root of the user tree |
| `withdrawal_tree_root` | `QHashOut<F>` | Root of the withdrawal tree |
| `user_registration_tree_root` | `QHashOut<F>` | Root of the user registration tree |

**Example**:
```json
{
  "contract_tree_root": "0x1234...",
  "deposit_tree_root": "0x5678...",
  "user_tree_root": "0x9abc...",
  "withdrawal_tree_root": "0xdef0...",
  "user_registration_tree_root": "0x1234..."
}
```

---

### PsyUserLeaf

User leaf data containing user state information.

**Structure**:
```rust
pub struct PsyUserLeaf<F: RichField> {
    pub public_key: QHashOut<F>,
    pub user_state_tree_root: QHashOut<F>,
    pub balance: F,
    pub nonce: F,
    pub last_checkpoint_id: F,
    pub event_index: F,
    pub user_id: F,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `QHashOut<F>` | User's public key hash |
| `user_state_tree_root` | `QHashOut<F>` | Root of user's state tree |
| `balance` | `F` | User's balance |
| `nonce` | `F` | User's transaction nonce |
| `last_checkpoint_id` | `F` | Last checkpoint ID where user was updated |
| `event_index` | `F` | Event index for this user |
| `user_id` | `F` | User identifier |

**Example**:
```json
{
  "public_key": "0x1234...",
  "user_state_tree_root": "0x5678...",
  "balance": "1000000",
  "nonce": "42",
  "last_checkpoint_id": "100",
  "event_index": "15",
  "user_id": "12345"
}
```

---

### MerkleProofCore

Generic Merkle proof structure.

**Structure**:
```rust
pub struct MerkleProofCore<Hash: PartialEq + Copy> {
    pub root: Hash,
    pub value: Hash,
    pub index: u64,
    pub siblings: Vec<Hash>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `root` | `Hash` | Merkle tree root hash |
| `value` | `Hash` | Leaf value being proven |
| `index` | `u64` | Leaf index in the tree |
| `siblings` | `Vec<Hash>` | Sibling hashes along the path |

**Example**:
```json
{
  "root": "0x1234...",
  "value": "0x5678...",
  "index": 42,
  "siblings": [
    "0x9abc...",
    "0xdef0...",
    "0x1234..."
  ]
}
```

---

### ZKPublicKeyInfo

Zero-knowledge public key information.

**Structure**:
```rust
pub struct ZKPublicKeyInfo<F: RichField> {
    pub fingerprint: QHashOut<F>,
    pub public_key_param: QHashOut<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `fingerprint` | `QHashOut<F>` | Public key fingerprint |
| `public_key_param` | `QHashOut<F>` | Public key parameter |

**Example**:
```json
{
  "fingerprint": "0x1234...",
  "public_key_param": "0x5678..."
}
```

---

### QBCDeployContract

Contract deployment command.

**Structure**:
```rust
pub struct QBCDeployContract<F: RichField> {
    pub deployer: QHashOut<F>,
    pub code_definition: ContractCodeDefinition,
    pub function_whitelist: Vec<QHashOut<F>>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `deployer` | `QHashOut<F>` | Deployer's public key hash |
| `code_definition` | `ContractCodeDefinition` | Contract code definition |
| `function_whitelist` | `Vec<QHashOut<F>>` | Function whitelist hashes |

**Example**:
```json
{
  "deployer": "0x1234...",
  "code_definition": {
    "state_tree_height": 10,
    "functions": [...]
  },
  "function_whitelist": ["0x5678..."]
}
```

---

### ContractCodeDefinition

Contract code definition structure.

**Structure**:
```rust
pub struct ContractCodeDefinition {
    pub state_tree_height: u16,
    pub functions: Vec<ContractFunctionCodeDefinition>,
}

pub struct ContractFunctionCodeDefinition {
    pub method_id: u32,
    pub num_inputs: u32,
    pub num_outputs: u32,
    pub vm_type: u32,
    pub code: Vec<u8>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `state_tree_height` | `u16` | Height of the contract state tree |
| `functions` | `Vec<ContractFunctionCodeDefinition>` | Contract functions |

**Function Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `method_id` | `u32` | Function method ID |
| `num_inputs` | `u32` | Number of input parameters |
| `num_outputs` | `u32` | Number of output parameters |
| `vm_type` | `u32` | VM type identifier |
| `code` | `Vec<u8>` | Function bytecode |

**Example**:
```json
{
  "state_tree_height": 10,
  "functions": [
    {
      "method_id": 12345678,
      "num_inputs": 2,
      "num_outputs": 1,
      "vm_type": 1,
      "code": [0x01, 0x02, ...]
    }
  ]
}
```

---

### PsyContractLeaf

Contract leaf data.

**Structure**:
```rust
pub struct PsyContractLeaf<F: RichField> {
    pub deployer: QHashOut<F>,
    pub function_tree_root: QHashOut<F>,
    pub state_tree_height: F,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `deployer` | `QHashOut<F>` | Deployer's public key hash |
| `function_tree_root` | `QHashOut<F>` | Root of the function tree |
| `state_tree_height` | `F` | Height of the state tree |

**Example**:
```json
{
  "deployer": "0x1234...",
  "function_tree_root": "0x5678...",
  "state_tree_height": "10"
}
```

---

### CheckpointSyncInfo

Checkpoint synchronization information.

**Structure**:
```rust
pub struct CheckpointSyncInfo<F: RichField> {
    pub latest_checkpoint_id: u64,
    pub description: Option<String>,
    pub source_coordinator_edge_id: Option<String>,
    pub sync_timestamp: u64,
    pub compact: PsyCheckpointSyncInfoCompact<F>,
    pub realm_root: QHashOut<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `latest_checkpoint_id` | `u64` | Latest checkpoint ID |
| `description` | `Option<String>` | Optional description |
| `source_coordinator_edge_id` | `Option<String>` | Source coordinator ID |
| `sync_timestamp` | `u64` | Synchronization timestamp |
| `compact` | `PsyCheckpointSyncInfoCompact<F>` | Compact sync info |
| `realm_root` | `QHashOut<F>` | Realm root hash |

---

### PsyCheckpointSyncInfoCompact

Compact checkpoint synchronization information.

**Structure**:
```rust
pub struct PsyCheckpointSyncInfoCompact<F: RichField> {
    pub block_state: PsyBlockState,
    pub stats: PsyCheckpointLeafStats<F>,
    pub state_roots: PsyCheckpointGlobalStateRoots<F>,
    pub checkpoint_tree_update_siblings: Vec<QHashOut<F>>,
    pub regsitered_users_start_pivot_siblings: Vec<QHashOut<F>>,
    pub registered_users: Vec<ZKPublicKeyInfo<F>>,
    pub old_checkpoint_leaf_hash: QHashOut<F>,
    pub slot: u64,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `block_state` | `PsyBlockState` | L2 block state |
| `stats` | `PsyCheckpointLeafStats<F>` | Checkpoint statistics |
| `state_roots` | `PsyCheckpointGlobalStateRoots<F>` | Global state roots |
| `checkpoint_tree_update_siblings` | `Vec<QHashOut<F>>` | Checkpoint tree update siblings |
| `regsitered_users_start_pivot_siblings` | `Vec<QHashOut<F>>` | User registration pivot siblings |
| `registered_users` | `Vec<ZKPublicKeyInfo<F>>` | Newly registered users |
| `old_checkpoint_leaf_hash` | `QHashOut<F>` | Previous checkpoint leaf hash |
| `slot` | `u64` | Slot number |

---

### SubmitGUTARealmResultAPINoProofInput

GUTA submission input without proof.

**Structure**:
```rust
pub struct SubmitGUTARealmResultAPINoProofInput<F: RichField> {
    pub realm_id: u64,
    pub checkpoint_id: u64,
    pub guta_stats: GUTAStats<F>,
    pub top_line_proof: DeltaMerkleProofCore<QHashOut<F>>,
    pub checkpoint_tree_root: QHashOut<F>,
    pub proof_id: QProvingJobDataID,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `realm_id` | `u64` | Realm identifier |
| `checkpoint_id` | `u64` | Checkpoint ID |
| `guta_stats` | `GUTAStats<F>` | GUTA statistics |
| `top_line_proof` | `DeltaMerkleProofCore<QHashOut<F>>` | Top-line Merkle proof |
| `checkpoint_tree_root` | `QHashOut<F>` | Checkpoint tree root |
| `proof_id` | `QProvingJobDataID` | Proving job ID |

---

### QProvingJobDataID

Proving job data identifier.

**Structure**:
```rust
pub struct QProvingJobDataID {
    pub topic: QJobTopic,
    pub goal_id: u64,
    pub slot_id: u64,
    pub circuit_type: ProvingJobCircuitType,
    pub group_id: u32,
    pub sub_group_id: u32,
    pub task_index: u32,
    pub data_type: ProvingJobDataType,
    pub data_index: u8,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `topic` | `QJobTopic` | Job topic |
| `goal_id` | `u64` | Goal identifier (usually checkpoint ID) |
| `slot_id` | `u64` | Slot identifier |
| `circuit_type` | `ProvingJobCircuitType` | Type of circuit |
| `group_id` | `u32` | Group identifier |
| `sub_group_id` | `u32` | Sub-group identifier |
| `task_index` | `u32` | Task index within the group |
| `data_type` | `ProvingJobDataType` | Data type |
| `data_index` | `u8` | Data index |

**Serialization**: Serialized as a 32-byte array.

---

### VariableHeightRewardMerkleProof

Variable height Merkle proof for reward distribution.

**Structure**:
```rust
pub struct VariableHeightRewardMerkleProof {
    pub top_siblings: Vec<VariableHeightProofSibling>,
    pub sibling_branch: QHashOut<F>,
    pub reward_leaf: QHashOut<F>,
    pub proof_height: F,
    pub index: F,
}

pub struct VariableHeightProofSibling {
    pub sibling_branch: QHashOut<F>,
    pub sibling_reward_leaf: QHashOut<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `top_siblings` | `Vec<VariableHeightProofSibling>` | Siblings at each level |
| `sibling_branch` | `QHashOut<F>` | Sibling branch hash |
| `reward_leaf` | `QHashOut<F>` | Reward leaf hash |
| `proof_height` | `F` | Height of the proof |
| `index` | `F` | Index in the tree |

---

### BasicRealmStatusOnCoordinator

Basic realm status on the coordinator.

**Structure**:
```rust
pub struct BasicRealmStatusOnCoordinator<F: RichField> {
    pub realm_id: u64,
    pub checkpoint_id: u64,
    pub realm_root_hash: QHashOut<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `realm_id` | `u64` | Realm identifier |
| `checkpoint_id` | `u64` | Current checkpoint ID |
| `realm_root_hash` | `QHashOut<F>` | Realm root hash |

**Example**:
```json
{
  "realm_id": 1,
  "checkpoint_id": 100,
  "realm_root_hash": "0x1234..."
}
```

---

### GlobalBlockUpdateFromCoordinator

Type alias for `CheckpointSyncInfo<F>`.

```rust
pub type GlobalBlockUpdateFromCoordinator<F> = CheckpointSyncInfo<F>;
```

See [CheckpointSyncInfo](#checkpointsyncinfo) for structure details.

---

### RealmDataForCoordinator

Realm data submitted to coordinator.

**Structure**:
```rust
pub struct RealmDataForCoordinator<F: RichField> {
    pub header: RealmDataForCoordinatorHeader<F>,
    pub proof: Vec<u8>,
}

pub struct RealmDataForCoordinatorHeader<F: RichField> {
    pub realm_id: u64,
    pub checkpoint_id: u64,
    pub start_realm_root: QHashOut<F>,
    pub end_realm_root: QHashOut<F>,
    pub guta_stats: GUTAStats<F>,
    pub root_job_id: QProvingJobDataID,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `header` | `RealmDataForCoordinatorHeader<F>` | Header data |
| `proof` | `Vec<u8>` | Serialized proof |

**Header Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `realm_id` | `u64` | Realm identifier |
| `checkpoint_id` | `u64` | Checkpoint ID |
| `start_realm_root` | `QHashOut<F>` | Starting realm root |
| `end_realm_root` | `QHashOut<F>` | Ending realm root |
| `guta_stats` | `GUTAStats<F>` | GUTA statistics |
| `root_job_id` | `QProvingJobDataID` | Root job ID |

---

## Field Type Notes

Throughout this API, `F` represents a field element type (typically `GoldilocksField`).

**Field Element Conversion**:
- Methods with `_f` suffix accept field elements as strings (e.g., `"12345"`)
- Methods without `_f` suffix accept native types (e.g., `12345`)
- Field elements are internally represented as `u64` values in the Goldilocks field

**Best Practices**:
- Use u64 variants for better performance when possible
- Use Field variants when working with circuit inputs/outputs
- Always validate checkpoint_id exists before querying
- Handle RPC errors gracefully (missing data, invalid parameters)

---

## Error Handling

All RPC methods return `RpcResult<T>` which can contain errors in the following format:

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Error description"
  },
  "id": 1
}
```

**Common Error Codes**:
- `-32000`: Server error (checkpoint not found, data unavailable)
- `-32602`: Invalid parameters
- `-32603`: Internal error
- `-32001`: Not found error

---

## Usage Examples

### Complete User Registration Workflow

```bash
# 1. Register a new user
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_register_user",
    "params": [{
      "fingerprint": "0x...",
      "public_key_param": "0x..."
    }],
    "id": 1
  }'

# 2. Get user ID by public key
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_id",
    "params": ["0x..."],
    "id": 2
  }'

# 3. Get user leaf data
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_leaf_data",
    "params": [100, 12345],
    "id": 3
  }'
```

### Contract Deployment Workflow

```bash
# 1. Deploy contract
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_deploy_contract",
    "params": [{
      "deployer": "0x...",
      "code_definition": {
        "state_tree_height": 10,
        "functions": [...]
      },
      "function_whitelist": [...]
    }],
    "id": 1
  }'

# 2. Get contract leaf data
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_contract_leaf_data",
    "params": [5],
    "id": 2
  }'

# 3. Get contract code definition
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_contract_code_definition",
    "params": [5],
    "id": 3
  }'
```

### Checkpoint Query Workflow

```bash
# 1. Get latest checkpoint ID
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_latest_checkpoint_id",
    "params": [],
    "id": 1
  }'

# 2. Get checkpoint leaf data
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_checkpoint_leaf_data",
    "params": [100],
    "id": 2
  }'

# 3. Get checkpoint global state roots
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_checkpoint_global_state_roots",
    "params": [100],
    "id": 3
  }'
```

---

## Method Summary

| # | Method Name | Parameters | Returns | Description |
|---|------------|------------|---------|-------------|
| 1 | `register_user` | `public_key` | `String` | Register new user |
| 2 | `get_user_id` | `public_key` | `u64` | Get user ID |
| 3 | `deploy_contract` | `deploy_contract` | `String` | Deploy contract |
| 4-5 | `get_contract_leaf_data[_f]` | `contract_id` | `PsyContractLeaf` | Get contract leaf |
| 6-7 | `get_contract_code_definition[_f]` | `contract_id` | `ContractCodeDefinition` | Get contract code |
| 8 | `build_block` | None | `String` | Trigger block building |
| 9-11 | `submit_guta[_v1]` | `input, proof, realm_id` | `String\|void` | Submit GUTA |
| 12-14 | `[get_]latest_checkpoint[_id]` | None | `LatestCheckpointResponse\|u64` | Get latest checkpoint |
| 15-16 | `get_checkpoint_leaf_data[_f]` | `checkpoint_id` | `PsyCheckpointLeaf` | Get checkpoint leaf |
| 17 | `get_checkpoint_global_state_roots` | `checkpoint_id` | `GlobalStateRoots` | Get global state roots |
| 18-19 | `get_checkpoint_sync_info[_compact]` | `realm_id?, checkpoint_id` | `CheckpointSyncInfo` | Get sync info |
| 20-22 | `get_[latest_]block_state[_f]` | `[checkpoint_id]` | `PsyBlockState` | Get L2 block state |
| 23-28 | `get_user_registration_tree_*[_f]` | Various | `QHashOut\|Proof` | Registration tree ops |
| 29-37 | `get_user_tree_*[_f]` | Various | `QHashOut\|Proof\|UserLeaf` | User tree operations |
| 38-43 | `get_contract_function_tree_*[_f]` | Various | `QHashOut\|Proof` | Function tree ops |
| 44-49 | `get_contract_tree_*[_f]` | Various | `QHashOut\|Proof` | Contract tree ops |
| 50-55 | `get_deposit_tree_*[_f]` | Various | `QHashOut\|Proof` | Deposit tree ops |
| 56-61 | `get_withdrawal_tree_*[_f]` | Various | `QHashOut\|Proof` | Withdrawal tree ops |
| 62-68 | `get_[latest_]checkpoint_tree_*[_f]` | Various | `QHashOut\|Proof` | Checkpoint tree ops |
| 69 | `generate_batch_variable_height_reward_proofs` | `checkpoint_id, job_ids` | `Vec<(Proof, JobID)>` | Batch reward proofs |
| 70 | `get_graphviz` | `checkpoint_id` | `String` | Get graph visualization |
| 71 | `get_current_realm_status_on_coordinator` | `realm_id` | `BasicRealmStatus` | Get realm status |
| 72 | `get_current_checkpoint_id` | None | `u64` | Get current checkpoint |
| 73 | `get_latest_block_updates_from_coordinator` | `realm_id, from, to` | `Vec<BlockUpdate>` | Get block updates |
| 74 | `wait_until_coordinator_completed` | `realm_id, checkpoint_id` | `BlockUpdate` | Wait for completion |

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-24  
**Total RPC Methods**: 74
