# Coordinator Edge RPC

> Regenerated 2026-09-08 from live `psy_api_core/src/coordinator/standard_edge_rpc.rs`
> (namespace `psy` → wire names `psy_<method>`).
> Worker methods inherited via `NodeEdgeWorkerRpc` are listed at the end from
> `psy_api_core/src/worker/standard_worker_rpc.rs`.

## Abstract

JSON-RPC edge API for the Coordinator node. All methods use namespace `psy`.

## Method inventory (45 edge + 6 worker)

## User management

| RPC method | Parameters |
|---|---|
| `psy_register_user` | `public_key`: `PZKPublicKeyInfo<Hash>` |
| `psy_get_public_key_for_user_id` | `user_id`: `u64` |
| `psy_get_user_ids_for_public_key` | `public_key`: `Hash`, `start_user_id`: `u64`, `count`: `u32` |

## Contract management

| RPC method | Parameters |
|---|---|
| `psy_deploy_contract` | `deploy_contract`: `PQBCDeployContractV2<Hash>` |
| `psy_update_contract` | `update_contract`: `PQBCUpdateContract<Hash>` |
| `psy_get_contract_leaf_data` | `contract_id`: `u64` |
| `psy_get_contract_code_definition` | `contract_id`: `u64` |

## GUTA submission

| RPC method | Parameters |
|---|---|
| `psy_submit_guta` | `input`, `proof`, `realm_id`, `proposal`, `certificate`, `finalize_binding` |

## Checkpoint / L2 block

| RPC method | Parameters |
|---|---|
| `psy_get_latest_checkpoint_id` | — |
| `psy_get_checkpoint_id_for_unique_pending_id` | `unique_pending_id`: `u64` |
| `psy_get_unique_pending_id_for_checkpoint_id` | `checkpoint_id`: `u64` |
| `psy_get_checkpoint_leaf_data` | `checkpoint_id`: `u64` |
| `psy_get_job_stats` | `checkpoint_id`: `u64` |
| `psy_get_checkpoint_global_state_roots` | `checkpoint_id`: `u64` |
| `psy_get_latest_l2_block_state` | — |
| `psy_get_l2_block_state` | `checkpoint_id`: `u64` |
| `psy_get_realm_root_and_last_modified_checkpoint` | `checkpoint_id`: `u64`, `realm_id`: `u64` |
| `psy_get_latest_checkpoint_tree_root` | — |
| `psy_get_checkpoint_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_checkpoint_tree_leaf_hash` | `checkpoint_id`: `u64`, `leaf_checkpoint_id`: `u64` |
| `psy_get_checkpoint_tree_merkle_proof` | `checkpoint_id`: `u64`, `leaf_checkpoint_id`: `u64` |
| `psy_get_checkpoint_leaves_batch_raw` | `start_checkpoint_id`: `u64`, `count`: `u32` |
| `psy_get_checkpoint_state_transition_proof` | `checkpoint_id`: `u64` |

## User registration tree

| RPC method | Parameters |
|---|---|
| `psy_get_user_registration_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_user_registration_tree_leaf_hash` | `checkpoint_id`: `u64`, `leaf_index`: `u64` |
| `psy_get_user_registration_tree_leaf_hashes` | `checkpoint_id`: `u64`, `indices`: `Vec<u64>` |
| `psy_get_user_registration_tree_merkle_proof` | `checkpoint_id`: `u64`, `leaf_index`: `u64` |

## User tree

| RPC method | Parameters |
|---|---|
| `psy_get_user_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_user_sub_tree_merkle_proof` | `checkpoint_id`: `u64`, `root_level`: `u8`, `leaf_level`: `u8`, `leaf_index`: `u64` |
| `psy_get_user_top_tree_merkle_proof` | `checkpoint_id`: `u64`, `leaf_level`: `u8`, `leaf_index`: `u64` |
| `psy_get_user_top_tree_cap_root` | `checkpoint_id`: `u64`, `cap_level`: `u8`, `cap_index`: `u64` |
| `psy_get_user_latest_top_tree_cap_root` | `cap_level`: `u8`, `cap_index`: `u64` |
| `psy_get_user_leaf_data` | `checkpoint_id`: `u64`, `user_id`: `u64` |
| `psy_get_user_tree_merkle_proof` | `checkpoint_id`: `u64`, `user_id`: `u64` |

## Contract trees

| RPC method | Parameters |
|---|---|
| `psy_get_contract_tree_state_heights` | `checkpoint_id`: `u64`, `contract_ids`: `Vec<u64>` |
| `psy_get_contract_function_tree_root` | `checkpoint_id`: `u64`, `contract_id`: `u32` |
| `psy_get_contract_function_tree_leaf_hash` | `checkpoint_id`: `u64`, `contract_id`: `u32`, `function_id`: `u32` |
| `psy_get_contract_function_tree_merkle_proof` | `checkpoint_id`: `u64`, `contract_id`: `u32`, `function_id`: `u32` |
| `psy_get_contract_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_contract_tree_leaf_hash` | `checkpoint_id`: `u64`, `contract_id`: `u32` |
| `psy_get_contract_tree_merkle_proof` | `checkpoint_id`: `u64`, `contract_id`: `u32` |
| `psy_get_contract_tree_heights` | `checkpoint_id`: `u64`, `contract_ids`: `Vec<u64>` |

## Withdrawal / realm sync / rewards

| RPC method | Parameters |
|---|---|
| `psy_get_withdrawal_tree_root` | `checkpoint_id`: `u64` |
| `psy_generate_batch_proof_miner_reward_proofs` | `unique_pending_id`: `u64`, `job_ids`: `Vec<QProvingJobDataIDWithRewardPath<JobId>>` |
| `psy_get_realm_sync_info` | `checkpoint_id`: `u64`, `realm_id`: `u64` |

## Inherited worker RPC (`NodeEdgeWorkerRpc`)

| RPC method | Parameters |
|---|---|
| `psy_get_proving_work` | `signature`: `QEDCompressedSecp256K1Signature`, `request`: `SimpleTimedRequest` |
| `psy_get_proving_work_with_child_proofs` | `signature`: `QEDCompressedSecp256K1Signature`, `request`: `SimpleTimedRequest` |
| `psy_submit_proof_raw` | `signature`, `request`, `job_id`, `tag`, `proof` |
| `psy_get_realm_identifier_worker_api` | — |
| `psy_get_node_proving_state` | — |
| `psy_get_worker_reputation` | `public_key`: `Vec<u8>` |

## Notes

- Commented-out methods in source (`build_block`, `get_checkpoint_sync_info*`) are **not** exposed.
- There are **no** deposit-tree edge RPCs on the Coordinator trait in the current source.
- `submit_guta` requires `finalize_binding` plus optional P2P `proposal` / `certificate` bytes.

## Source

- `psy_api_core/src/coordinator/standard_edge_rpc.rs`
- `psy_api_core/src/worker/standard_worker_rpc.rs`
