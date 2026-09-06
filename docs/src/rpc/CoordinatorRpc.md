# Coordinator Edge RPC Methods

> Updated: 2026-09-07. Regenerated from `psy_api_core/src/coordinator/standard_edge_rpc.rs`.

## Abstract

Coordinator edge JSON-RPC uses namespace `psy`. Client method names are `psy_<method>`.

Source of truth: `psy_api_core/src/coordinator/standard_edge_rpc.rs`. GUTA admission + certificate verification: `psy_node_common/src/coordinator/edge/handler.rs`.

## Active methods

| Method | Notes |
|---|---|
| `psy_register_user` | Register user |
| `psy_get_public_key_for_user_id` | User id → public key |
| `psy_get_user_ids_for_public_key` | Public key → **list** of user ids |
| `psy_deploy_contract` / `psy_update_contract` | Contract deploy/update |
| `psy_submit_guta` | Submit realm GUTA root **with optional `proposal` and `certificate` bytes** when rotation validators are configured |
| `psy_get_latest_checkpoint_id` | Tip checkpoint id |
| `psy_get_checkpoint_id_for_unique_pending_id` / `psy_get_unique_pending_id_for_checkpoint_id` | Pending maps |
| `psy_get_contract_leaf_data` / `psy_get_contract_code_definition` | Contract leaf/code |
| `psy_get_checkpoint_leaf_data` / `psy_get_job_stats` | Checkpoint leaf / job stats |
| `psy_get_checkpoint_global_state_roots` | Global roots at checkpoint |
| `psy_get_contract_tree_state_heights` | Heights |
| `psy_get_latest_l2_block_state` / `psy_get_l2_block_state` | L2 block state |
| `psy_get_user_registration_tree_*` | Registration tree |
| `psy_get_user_tree_root` / `psy_get_user_sub_tree_merkle_proof` / `psy_get_user_top_tree_*` / `psy_get_user_leaf_data` / `psy_get_user_tree_merkle_proof` | Global user tree views |
| `psy_get_realm_root_and_last_modified_checkpoint` | Realm root sync |
| `psy_get_contract_function_tree_*` / `psy_get_contract_tree_*` | Contract trees |
| `psy_get_withdrawal_tree_root` | Withdrawal tree |
| `psy_get_latest_checkpoint_tree_root` / `psy_get_checkpoint_tree_*` | Checkpoint tree |
| `psy_generate_batch_proof_miner_reward_proofs` | Miner rewards |
| `psy_get_realm_sync_info` | Realm sync |
| `psy_get_checkpoint_leaves_batch_raw` | Batch checkpoint leaves |
| `psy_get_checkpoint_state_transition_proof` | Checkpoint ST proof |

Commented-out / not live: `build_block`, `get_checkpoint_sync_info`, `get_checkpoint_sync_info_compact`.

## `psy_submit_guta` (rotation)

Signature (trait):

```text
submit_guta(
  input: GlobalUserTreeAggregatorHeaderWithTagValueAndJobType,
  proof: Vec<u8>,
  realm_id: u64,
  proposal: Option<Vec<u8>>,
  certificate: Option<Vec<u8>>,
) -> String
```

When validators are configured for the network, Proposal and Certificate are required and verified against the proof hash, realm id, chain id, and validator tree (`handler.rs` `verify_optional_guta_certificate`). Ordinary GUTA and `RealmFinalizeGUTA` (circuit type 63) are accepted as registered root job types.

## Removed / never register these names

`psy_submit_guta_v1`, `psy_submit_realm_result`, `psy_get_user_id` (use `get_user_ids_for_public_key` / registration APIs), `psy_latest_checkpoint`, deposit-tree RPC names that are not on this trait, `psy_get_graphviz`, field-only `*_f` helpers.
