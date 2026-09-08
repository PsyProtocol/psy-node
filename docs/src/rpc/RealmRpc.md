# Realm Edge RPC

> Regenerated 2026-09-08 from live `psy_api_core/src/realm/standard_edge_rpc.rs`
> (namespace `psy` → wire names `psy_<method>`).

## Abstract

JSON-RPC edge API for a Realm node. All methods use namespace `psy`.

## Method inventory (43 methods)

## Diagnostics

| RPC method | Parameters |
|---|---|
| `psy_get_sum` | `a`: `u64`, `b`: `u64` |

## User / EndCap

| RPC method | Parameters |
|---|---|
| `psy_check_user_id_in_realm` | `user_id`: `u64` |
| `psy_submit_user_end_cap` | `user_ec_input`: `SubmitUserEndCapNonProofInput<F`, `proof`: `Vec<u8>` |
| `psy_submit_user_end_cap_batch` | `requests`: `Vec<(SubmitUserEndCapNonProofInput<F` |
| `psy_get_user_end_cap_slot_updates` | `unique_pending_id`: `u64`, `user_id`: `u64` |

## Checkpoint / L2 block

| RPC method | Parameters |
|---|---|
| `psy_get_checkpoint_leaf_data` | `checkpoint_id`: `u64` |
| `psy_get_job_stats` | `checkpoint_id`: `u64` |
| `psy_get_latest_checkpoint_id` | — |
| `psy_get_checkpoint_id_for_unique_pending_id` | `unique_pending_id`: `u64` |
| `psy_get_unique_pending_id_for_checkpoint_id` | `checkpoint_id`: `u64` |
| `psy_get_latest_l2_block_state` | — |
| `psy_get_l2_block_state` | `checkpoint_id`: `u64` |
| `psy_get_latest_checkpoint_tree_root` | — |
| `psy_get_checkpoint_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_checkpoint_tree_leaf_hash` | `checkpoint_id`: `u64`, `leaf_checkpoint_id`: `u64` |
| `psy_get_checkpoint_tree_merkle_proof` | `checkpoint_id`: `u64`, `leaf_checkpoint_id`: `u64` |
| `psy_get_checkpoint_global_state_roots` | `checkpoint_id`: `u64` |
| `psy_get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id` | `checkpoint_id`: `u64` |

## User leaf / tree

| RPC method | Parameters |
|---|---|
| `psy_get_user_leaf_data` | `checkpoint_id`: `u64`, `user_id`: `u64` |
| `psy_get_user_leaves_batch` | `checkpoint_id`: `u64`, `user_ids`: `Vec<u64>` |
| `psy_get_user_tree_root` | `checkpoint_id`: `u64` |
| `psy_get_user_tree_leaf_hash` | `checkpoint_id`: `u64`, `user_id`: `u64` |
| `psy_get_user_tree_leaf_hashes` | `checkpoint_id`: `u64`, `user_ids`: `Vec<u64>` |
| `psy_get_user_bottom_tree_merkle_proof` | `root_level`: `u8`, `checkpoint_id`: `u64`, `user_id`: `u64` |
| `psy_get_user_sub_tree_merkle_proof` | `checkpoint_id`: `u64`, `root_level`: `u8`, `leaf_level`: `u8`, `leaf_index`: `u64` |
| `psy_get_user_tree_merkle_proof` | `checkpoint_id`: `u64`, `user_id`: `u64` |

## User contract / state trees

| RPC method | Parameters |
|---|---|
| `psy_get_user_contract_state_tree_root` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32` |
| `psy_get_user_contract_state_tree_leaf_hash` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `leaf_id`: `u64` |
| `psy_get_user_contract_state_tree_nodes` | `checkpoint_id`: `u64`, `keys`: `Vec<QMerkleStoreDoubleIdKeyWithHeight>` |
| `psy_get_user_contract_tree_nodes` | `checkpoint_id`: `u64`, `keys`: `Vec<QMerkleStoreSingleIdKey>` |
| `psy_get_user_contract_state_tree_merkle_proof` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `leaf_id`: `u64` |
| `psy_get_user_contract_tree_root` | `checkpoint_id`: `u64`, `user_id`: `u64` |
| `psy_get_user_contract_tree_leaf_hash` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32` |
| `psy_get_user_contract_tree_merkle_proof` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32` |

## IMT

| RPC method | Parameters |
|---|---|
| `psy_get_imt_leaf_preimage` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `leaf_index`: `u64` |
| `psy_get_imt_leaf_index_for_key` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `key`: `Hash` |
| `psy_find_imt_predecessor` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u64`, `key`: `Hash` |
| `psy_get_imt_next_append_index` | `user_id`: `u64`, `contract_id`: `u64` |
| `psy_get_imt_membership_proof` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `key`: `Hash` |
| `psy_get_imt_non_membership_proof` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `key`: `Hash` |
| `psy_get_imt_predecessor_info` | `checkpoint_id`: `u64`, `user_id`: `u64`, `contract_id`: `u32`, `key`: `Hash` |

## Rewards

| RPC method | Parameters |
|---|---|
| `psy_generate_batch_proof_miner_reward_proofs` | `unique_pending_id`: `u64`, `job_ids`: `Vec<QProvingJobDataIDWithRewardPath<JobId>>` |

## Other

| RPC method | Parameters |
|---|---|
| `psy_get_contract_tree_state_heights` | `checkpoint_id`: `u64`, `contract_ids`: `Vec<u64>` |

## Notes

- GraphViz / registration-tree helpers present in older docs are **absent** from the live Realm trait.
- Realm owns per-user contract state and IMT queries; Coordinator owns global registration / contract trees.

## Source

- `psy_api_core/src/realm/standard_edge_rpc.rs`
