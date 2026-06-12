# Realm Edge RPC Documentation

This document provides comprehensive documentation for all Realm Edge RPC methods defined in the `RealmEdgeRpc` trait.

**RPC Namespace**: `psy`

---

## Table of Contents

1. [User Management](#user-management)
2. [User End Cap Submission](#user-end-cap-submission)
3. [Checkpoint Data Operations](#checkpoint-data-operations)
4. [L2 Block State Operations](#l2-block-state-operations)
5. [User Registration Tree Operations](#user-registration-tree-operations)
6. [Checkpoint Tree Operations](#checkpoint-tree-operations)
7. [User Leaf Data Operations](#user-leaf-data-operations)
8. [User Contract State Tree Operations](#user-contract-state-tree-operations)
9. [User Contract Tree Operations](#user-contract-tree-operations)
10. [User Tree Operations](#user-tree-operations)
11. [Batch Proof Generation](#batch-proof-generation)
12. [GraphViz Export](#graphviz-export)
13. [Data Structures](#data-structures)

---

## User Management

### 1. check_user_id_in_realm

Check if a user ID belongs to this realm.

**Method Name**: `psy_check_user_id_in_realm`

**Request Parameters**:
```json
{
  "user_id": 12345
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_id` | `u64` | The user ID to check |

**Response**:
```json
{
  "result": true
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `bool` | `true` if the user belongs to this realm, `false` otherwise |

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_check_user_id_in_realm",
    "params": [12345],
    "id": 1
  }'
```

---

## User End Cap Submission

### 2. submit_user_end_cap

Submit a user end cap proof for processing.

**Method Name**: `psy_submit_user_end_cap`

**Request Parameters**:
```json
{
  "user_ec_input": {
    "core": {
      "checkpoint_id": "123",
      "stats": { ... },
      "state_transition": { ... },
      "new_user_leaf": { ... }
    },
    "contract_state_updates": [ ... ]
  },
  "proof": { ... }
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `user_ec_input` | `SubmitUserEndCapNonProofInput<F>` | End cap input data (see [Data Structures](#submitUserEndCapNonProofInput)) |
| `proof` | `ProofWithPublicInputs<F, C, D>` | Zero-knowledge proof |

**Response**:
```json
{
  "result": "0x1234567890abcdef..."
}
```

| Field | Type | Description |
|-------|------|-------------|
| `result` | `String` | Transaction hash or job ID |

---

## Checkpoint Data Operations

### 3. get_checkpoint_leaf_data

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

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_checkpoint_leaf_data",
    "params": [100],
    "id": 1
  }'
```

---

### 4. get_checkpoint_leaf_data_f

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

## L2 Block State Operations

### 5. get_latest_block_state

Get the latest L2 block state.

**Method Name**: `psy_get_latest_block_state`

**Request Parameters**: None

**Response**: See [PsyBlockState](#psyblockstate)

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_latest_block_state",
    "params": [],
    "id": 1
  }'
```

**Response Example**:
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

### 6. get_block_state

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

### 7. get_block_state_f

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

### 8. get_user_registration_tree_root

Get the user registration tree root at a specific checkpoint.

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

**Example Response**:
```json
{
  "result": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}
```

---

## Checkpoint Tree Operations

### 9. get_latest_checkpoint_tree_root

Get the latest checkpoint tree root.

**Method Name**: `psy_get_latest_checkpoint_tree_root`

**Request Parameters**: None

**Response**: See [QHashOut](#qhashout)

---

### 10. get_checkpoint_tree_root

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

### 11. get_checkpoint_tree_root_f

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

### 12. get_checkpoint_tree_leaf_hash

Get a specific checkpoint tree leaf hash (u64 parameters).

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

### 13. get_checkpoint_tree_leaf_hash_f

Get a specific checkpoint tree leaf hash (Field parameters).

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

### 14. get_checkpoint_tree_merkle_proof

Get Merkle proof for a checkpoint tree leaf (u64 parameters).

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

### 15. get_checkpoint_tree_merkle_proof_f

Get Merkle proof for a checkpoint tree leaf (Field parameters).

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

### 16. get_checkpoint_global_state_roots

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

**Example Response**:
```json
{
  "result": {
    "contract_tree_root": "0x...",
    "deposit_tree_root": "0x...",
    "user_tree_root": "0x...",
    "withdrawal_tree_root": "0x...",
    "user_registration_tree_root": "0x..."
  }
}
```

---

## User Leaf Data Operations

### 17. get_user_leaf_data

Get user leaf data at a specific checkpoint (u64 parameters).

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

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_leaf_data",
    "params": [100, 12345],
    "id": 1
  }'
```

---

### 18. get_user_leaf_data_f

Get user leaf data at a specific checkpoint (Field parameters).

**Method Name**: `psy_get_user_leaf_data_f`

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

**Response**: See [PsyUserLeaf](#psyuserleaf)

---

## User Contract State Tree Operations

### 19. get_user_contract_state_tree_root

Get user contract state tree root (u64 parameters).

**Method Name**: `psy_get_user_contract_state_tree_root`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [QHashOut](#qhashout)

---

### 20. get_user_contract_state_tree_root_f

Get user contract state tree root (Field parameters).

**Method Name**: `psy_get_user_contract_state_tree_root_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 21. get_user_contract_state_tree_leaf_hash

Get user contract state tree leaf hash (u64 parameters).

**Method Name**: `psy_get_user_contract_state_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345,
  "contract_id": 5,
  "height": 10,
  "leaf_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |
| `contract_id` | `u32` | The contract ID |
| `height` | `u8` | The tree height |
| `leaf_id` | `u64` | The leaf ID |

**Response**: See [QHashOut](#qhashout)

---

### 22. get_user_contract_state_tree_leaf_hash_f

Get user contract state tree leaf hash (Field parameters).

**Method Name**: `psy_get_user_contract_state_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345",
  "contract_id": "5",
  "height": 10,
  "leaf_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |
| `height` | `u8` | The tree height |
| `leaf_id` | `F` (Field) | The leaf ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 23. get_user_contract_state_tree_merkle_proof

Get Merkle proof for user contract state tree (u64 parameters).

**Method Name**: `psy_get_user_contract_state_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345,
  "contract_id": 5,
  "height": 10,
  "leaf_id": 42
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |
| `contract_id` | `u32` | The contract ID |
| `height` | `u8` | The tree height |
| `leaf_id` | `u64` | The leaf ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 24. get_user_contract_state_tree_merkle_proof_f

Get Merkle proof for user contract state tree (Field parameters).

**Method Name**: `psy_get_user_contract_state_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345",
  "contract_id": "5",
  "height": 10,
  "leaf_id": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |
| `height` | `u8` | The tree height |
| `leaf_id` | `F` (Field) | The leaf ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## User Contract Tree Operations

### 25. get_user_contract_tree_root

Get user contract tree root (u64 parameters).

**Method Name**: `psy_get_user_contract_tree_root`

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

**Response**: See [QHashOut](#qhashout)

---

### 26. get_user_contract_tree_root_f

Get user contract tree root (Field parameters).

**Method Name**: `psy_get_user_contract_tree_root_f`

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

**Response**: See [QHashOut](#qhashout)

---

### 27. get_user_contract_tree_leaf_hash

Get user contract tree leaf hash (u64 parameters).

**Method Name**: `psy_get_user_contract_tree_leaf_hash`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [QHashOut](#qhashout)

---

### 28. get_user_contract_tree_leaf_hash_f

Get user contract tree leaf hash (Field parameters).

**Method Name**: `psy_get_user_contract_tree_leaf_hash_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [QHashOut](#qhashout)

---

### 29. get_user_contract_tree_merkle_proof

Get Merkle proof for user contract tree (u64 parameters).

**Method Name**: `psy_get_user_contract_tree_merkle_proof`

**Request Parameters**:
```json
{
  "checkpoint_id": 100,
  "user_id": 12345,
  "contract_id": 5
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |
| `contract_id` | `u32` | The contract ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 30. get_user_contract_tree_merkle_proof_f

Get Merkle proof for user contract tree (Field parameters).

**Method Name**: `psy_get_user_contract_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "user_id": "12345",
  "contract_id": "5"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |
| `contract_id` | `F` (Field) | The contract ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

## User Tree Operations

### 31. get_user_tree_root

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

### 32. get_user_tree_root_f

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

### 33. get_user_tree_leaf_hash

Get user tree leaf hash (u64 parameters).

**Method Name**: `psy_get_user_tree_leaf_hash`

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

**Response**: See [QHashOut](#qhashout)

---

### 34. get_user_tree_leaf_hash_f

Get user tree leaf hash (Field parameters).

**Method Name**: `psy_get_user_tree_leaf_hash_f`

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

**Response**: See [QHashOut](#qhashout)

---

### 35. get_user_bottom_tree_merkle_proof

Get Merkle proof for user bottom tree (u64 parameters).

**Method Name**: `psy_get_user_bottom_tree_merkle_proof`

**Request Parameters**:
```json
{
  "root_level": 5,
  "checkpoint_id": 100,
  "user_id": 12345
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `root_level` | `u8` | The root level of the tree |
| `checkpoint_id` | `u64` | The checkpoint ID |
| `user_id` | `u64` | The user ID |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 36. get_user_bottom_tree_merkle_proof_f

Get Merkle proof for user bottom tree (Field parameters).

**Method Name**: `psy_get_user_bottom_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "root_level": 5,
  "checkpoint_id": "100",
  "user_id": "12345"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `root_level` | `u8` | The root level of the tree |
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `user_id` | `F` (Field) | The user ID as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 37. get_user_sub_tree_merkle_proof

Get Merkle proof for user sub-tree (u64 parameters).

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
| `root_level` | `u8` | The root level of the tree |
| `leaf_level` | `u8` | The leaf level of the tree |
| `leaf_index` | `u64` | The leaf index |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 38. get_user_sub_tree_merkle_proof_f

Get Merkle proof for user sub-tree (Field parameters).

**Method Name**: `psy_get_user_sub_tree_merkle_proof_f`

**Request Parameters**:
```json
{
  "checkpoint_id": "100",
  "root_level": 5,
  "leaf_level": 2,
  "leaf_index": "42"
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `checkpoint_id` | `F` (Field) | The checkpoint ID as a field element |
| `root_level` | `u8` | The root level of the tree |
| `leaf_level` | `u8` | The leaf level of the tree |
| `leaf_index` | `F` (Field) | The leaf index as a field element |

**Response**: See [MerkleProofCore](#merkleproofcore)

---

### 39. get_user_tree_merkle_proof

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

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_tree_merkle_proof",
    "params": [100, 12345],
    "id": 1
  }'
```

---

### 40. get_user_tree_merkle_proof_f

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

**Note**: This method internally converts field parameters to u64 and calls `get_user_tree_merkle_proof`.

---

## Batch Proof Generation

### 41. generate_batch_variable_height_reward_proofs

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
| `job_ids` | `Vec<QProvingJobDataID>` | Array of proving job data IDs (see [QProvingJobDataID](#qprovingjobdataid)) |

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

**Example**:
```bash
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_generate_batch_variable_height_reward_proofs",
    "params": [100, [...]],
    "id": 1
  }'
```

---

## GraphViz Export

### 42. get_graphviz

Get GraphViz representation of the Merkle tree at a specific checkpoint.

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
  }' | jq -r '.result' | dot -Tpng > tree.png
```

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

**PsyCheckpointLeafStats Structure**:
```rust
pub struct PsyCheckpointLeafStats<F: RichField> {
    pub fees_collected: F,
    pub user_ops_processed: F,
    pub total_transactions: F,
    pub slots_modified: F,
    pub pm_jobs_completed: PMJobsCompletedStats<F>,
    pub block_time: F,
    pub random_seed: QHashOut<F>,
    pub pm_rewards_commitment: PMRewardCommitment<F>,
    pub da_challenges_claimed: [F; DA_CHALLENGE_WINDOW],
}
```

**Example**:
```json
{
  "global_chain_root": "0x...",
  "stats": {
    "fees_collected": "1000",
    "user_ops_processed": "50",
    "total_transactions": "75",
    "slots_modified": "30",
    "pm_jobs_completed": {...},
    "block_time": "1234567890",
    "random_seed": "0x...",
    "pm_rewards_commitment": {...},
    "da_challenges_claimed": [...]
  }
}
```

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

**Verification**: The proof can be verified by hashing the value with siblings along the path according to the index bits.

---

### SubmitUserEndCapNonProofInput

Input data for submitting user end cap (without proof).

**Structure**:
```rust
pub struct SubmitUserEndCapNonProofInput<F: RichField> {
    pub core: SubmitUserEndCapNonProofCoreInput<F>,
    pub contract_state_updates: Vec<PsyContractStateUpdateHistory<F>>,
}

pub struct SubmitUserEndCapNonProofCoreInput<F: RichField> {
    pub checkpoint_id: F,
    pub stats: GUTAStats<F>,
    pub state_transition: UPSEndCapResultCompact<F>,
    pub new_user_leaf: PsyUserLeaf<F>,
}
```

**Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `core` | `SubmitUserEndCapNonProofCoreInput<F>` | Core input data |
| `contract_state_updates` | `Vec<PsyContractStateUpdateHistory<F>>` | Contract state update history |

**Core Fields**:

| Field | Type | Description |
|-------|------|-------------|
| `checkpoint_id` | `F` | Checkpoint ID |
| `stats` | `GUTAStats<F>` | GUTA statistics |
| `state_transition` | `UPSEndCapResultCompact<F>` | State transition result |
| `new_user_leaf` | `PsyUserLeaf<F>` | New user leaf data |

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
| `topic` | `QJobTopic` | Job topic (e.g., GenerateStandardProof) |
| `goal_id` | `u64` | Goal identifier (usually checkpoint ID) |
| `slot_id` | `u64` | Slot identifier |
| `circuit_type` | `ProvingJobCircuitType` | Type of circuit (e.g., GUTATwoEndCap) |
| `group_id` | `u32` | Group identifier |
| `sub_group_id` | `u32` | Sub-group identifier |
| `task_index` | `u32` | Task index within the group |
| `data_type` | `ProvingJobDataType` | Data type (e.g., InputWitness) |
| `data_index` | `u8` | Data index |

**Serialization**: Serialized as a 32-byte array.

**Example**:
```json
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
```

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

**Example**:
```json
{
  "top_siblings": [
    {
      "sibling_branch": "0x1234...",
      "sibling_reward_leaf": "0x5678..."
    }
  ],
  "sibling_branch": "0x9abc...",
  "reward_leaf": "0xdef0...",
  "proof_height": "5",
  "index": "42"
}
```

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

---

## Usage Examples

### Complete Workflow Example

```bash
# 1. Check if user belongs to realm
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_check_user_id_in_realm",
    "params": [12345],
    "id": 1
  }'

# 2. Get latest L2 block state
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_latest_block_state",
    "params": [],
    "id": 2
  }'

# 3. Get user leaf data at checkpoint
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_leaf_data",
    "params": [100, 12345],
    "id": 3
  }'

# 4. Get Merkle proof for user
curl -X POST http://localhost:8545 \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "psy_get_user_tree_merkle_proof",
    "params": [100, 12345],
    "id": 4
  }'
```

---

## Method Summary

| # | Method Name | Parameters | Returns | Description |
|---|------------|------------|---------|-------------|
| 1 | `check_user_id_in_realm` | `user_id: u64` | `bool` | Check user belongs to realm |
| 2 | `submit_user_end_cap` | `input, proof` | `String` | Submit end cap proof |
| 3-4 | `get_checkpoint_leaf_data[_f]` | `checkpoint_id` | `PsyCheckpointLeaf` | Get checkpoint leaf |
| 5-7 | `get_[latest_]block_state[_f]` | `[checkpoint_id]` | `PsyBlockState` | Get L2 block state |
| 8 | `get_user_registration_tree_root` | `checkpoint_id` | `QHashOut` | Get registration tree root |
| 9-11 | `get_[latest_]checkpoint_tree_root[_f]` | `[checkpoint_id]` | `QHashOut` | Get checkpoint tree root |
| 12-15 | `get_checkpoint_tree_[leaf_hash\|merkle_proof][_f]` | `checkpoint_id, leaf_id` | `QHashOut\|Proof` | Checkpoint tree ops |
| 16 | `get_checkpoint_global_state_roots` | `checkpoint_id` | `GlobalStateRoots` | Get global state roots |
| 17-18 | `get_user_leaf_data[_f]` | `checkpoint_id, user_id` | `PsyUserLeaf` | Get user leaf data |
| 19-24 | `get_user_contract_state_tree_*[_f]` | Various | `QHashOut\|Proof` | Contract state tree ops |
| 25-30 | `get_user_contract_tree_*[_f]` | Various | `QHashOut\|Proof` | User contract tree ops |
| 31-40 | `get_user_tree_*[_f]` | Various | `QHashOut\|Proof` | User tree operations |
| 41 | `generate_batch_variable_height_reward_proofs` | `checkpoint_id, job_ids` | `Vec<(Proof, JobID)>` | Batch reward proofs |
| 42 | `get_graphviz` | `checkpoint_id` | `String` | Get tree visualization |

---

**Document Version**: 1.0  
**Last Updated**: 2025-10-24  
**Total RPC Methods**: 42
