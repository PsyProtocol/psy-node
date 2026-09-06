# Realm Edge RPC Methods

> Updated: 2026-09-07. Regenerated from `psy_api_core/src/realm/standard_edge_rpc.rs`.

## Abstract

Realm edge JSON-RPC uses namespace `psy`. Client method names are `psy_<method>` (for example `psy_get_latest_checkpoint_id`).

Source of truth: `psy_api_core/src/realm/standard_edge_rpc.rs`. Handler behavior: `psy_node_common/src/realm/edge/handler.rs`.

## Active methods

| Method | Notes |
|---|---|
| `psy_get_sum` | Health/sum helper |
| `psy_check_user_id_in_realm` | Realm membership check |
| `psy_submit_user_end_cap` | Submit one EndCap |
| `psy_submit_user_end_cap_batch` | Batch EndCap submit |
| `psy_get_checkpoint_leaf_data` | Checkpoint leaf |
| `psy_get_job_stats` | Checkpoint job stats |
| `psy_get_latest_checkpoint_id` | Tip checkpoint id (**not** `psy_latest_checkpoint`) |
| `psy_get_checkpoint_id_for_unique_pending_id` | Pending → checkpoint map |
| `psy_get_unique_pending_id_for_checkpoint_id` | Checkpoint → pending map |
| `psy_get_user_end_cap_slot_updates` | EndCap slot updates |
| `psy_get_latest_l2_block_state` / `psy_get_l2_block_state` | L2 block state |
| `psy_get_latest_checkpoint_tree_root` / `psy_get_checkpoint_tree_root` | Checkpoint tree roots |
| `psy_get_contract_tree_state_heights` | Contract tree heights |
| `psy_get_checkpoint_tree_leaf_hash` / `psy_get_checkpoint_tree_merkle_proof` | Checkpoint tree |
| `psy_get_checkpoint_global_state_roots` | Global state roots at checkpoint |
| `psy_get_user_leaf_data` / `psy_get_user_leaves_batch` | User leaves |
| `psy_get_user_contract_state_tree_*` | Per-user contract state tree |
| `psy_get_user_contract_tree_*` | Per-user contract tree |
| `psy_get_user_tree_root` | Exact-checkpoint user-tree root (spine composition) |
| `psy_get_user_tree_leaf_hash` / `psy_get_user_tree_leaf_hashes` | User tree leaves |
| `psy_get_user_bottom_tree_merkle_proof` | Realm-subtree proof; **fail-closed** if `root_level` crosses coordinator spine |
| `psy_get_user_sub_tree_merkle_proof` | Same spine fail-closed rule |
| `psy_get_user_tree_merkle_proof` | Full proof via exact spine + local subtree composition |
| `psy_generate_batch_proof_miner_reward_proofs` | Miner reward proofs |
| `psy_get_top_global_user_rewards_tree_proof_to_realm_at_checkpoint_id` | Rewards top proof (exact vintage via checkpoint→pending map) |
| `psy_get_imt_*` | Indexed Merkle tree helpers (leaf, predecessor, membership, non-membership) |

Commented-out / not live: `get_user_registration_tree_root` on the realm trait.

## Exact-vintage / spine policy

- Tip-only methods (`get_latest_*`) return the live tip.
- Checkpoint-scoped user-tree reads must not silently return max-vintage coordinator siblings.
- Subtree RPCs reject `root_level < COORDINATOR_GLOBAL_USER_TREE_HEIGHT` via `ensure_user_subtree_request_within_realm` (`handler.rs`).
- Full `get_user_tree_merkle_proof` composes local sparse subtree with the exact authenticated top spine.

## Removed / never register these names

Do not document or call: `psy_latest_checkpoint`, `psy_get_latest_block_state` (use `…_l2_block_state`), `psy_generate_batch_variable_height_reward_proofs`, field-only `*_f` variants, `psy_get_graphviz`.
