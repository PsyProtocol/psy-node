# Prover Proxy RPC

> Regenerated 2026-09-08 from live `client_prover/psy_prover/src/local/native/prove_proxy.rs`
> (namespace `psy` → wire names `psy_<method>`).

## Abstract

Local proving service for UPS, contract calls, signatures, aggregation trees, and bridge Groth16 wrappers.

**Default listen address**: `0.0.0.0:9999` (process-configured).

## Method inventory (30 methods)

## UPS

| RPC method | Parameters |
|---|---|
| `psy_prove_ups_start` | `input`: `UPSStartStepInput<F>` |
| `psy_prove_ups_start_register_user` | `input`: `UPSStartStepRegisterUserInput<F>` |
| `psy_prove_ups_cfc_standard_tx` | `input`: `UPSCFCStandardTransactionCircuitInput<F>` |
| `psy_prove_ups_cfc_deferred_tx` | `input`: `UPSCFCDeferredTransactionCircuitInput<F>` |
| `psy_prove_ups_end_cap` | `end_cap_from_proof_tree_input`, `circuit_type`, `fingerprint`, `agg_header`, `proof` |

## Contract circuits

| RPC method | Parameters |
|---|---|
| `psy_get_circuits_data` | — |
| `psy_get_fn_id` | `contract_id`: `u64`, `method_name`: `String` |
| `psy_get_fn_id_and_circuit_def` | `contract_id`: `u64`, `method_name`: `String` |
| `psy_get_contract_method_common_data` | `contract_id`: `u64`, `fn_id`: `u32` |
| `psy_register_contract_circuits` | `contract_id`: `u64`, `contract_code`: `ContractCodeDefinition` |
| `psy_resolve_contract_function_by_method_name` | `contract_id`: `u64`, `contract_code`: `ContractCodeDefinition`, `method_name`: `String` |
| `psy_resolve_contract_function_by_method_id` | `contract_id`: `u64`, `contract_code`: `ContractCodeDefinition`, `method_id`: `u32` |
| `psy_prove_contract_call` | `contract_id`: `u64`, `fn_id`: `u32`, `input`: `DapenContractFunctionCircuitInput<F>` |

## Signatures / minifiers

| RPC method | Parameters |
|---|---|
| `psy_prove_zk_sign_minifier` | `inner_proof`: `String` |
| `psy_prove_private_note_inclusion_minifier` | `base_proof`: `String` |
| `psy_prove_shield_deposit_claim_minifier` | `base_proof`: `String` |
| `psy_prove_secp_sign` | `signature`: `PsyCompressedSecp256K1Signature` |
| `psy_prove_eth_personal_secp_sign` | `signature`: `PsyCompressedSecp256K1Signature` |
| `psy_prove_dpn_software_defined_sign` | `fingerprint`, `private_key`, `input`, `sig_hash` |
| `psy_prove_plonky2_software_defined_sign` | `fingerprint`, `private_key`, `input`, `sig_hash` |

## Software-defined circuits

| RPC method | Parameters |
|---|---|
| `psy_register_dpn_software_defined_circuit` | `request`: `QRegisterDPNSoftwareDefinedCircuitRPCRequest` |
| `psy_register_plonky2_software_defined_circuit` | `request`: `QRegisterPlonky2SoftwareDefinedCircuitRPCRequest` |

## Aggregation / proof tree

| RPC method | Parameters |
|---|---|
| `psy_prove_single_leaf_circuit` | `agg_circuit_whitelist_root`, `single_insert_leaf_proof`, `single_proof`, `single_verifier_data` |
| `psy_prove_two_leaf_circuit` | `agg_circuit_whitelist_root`, `left_insert_leaf_proof`, `left_proof`, `left_verifier_data`, `right_insert_leaf_proof`, `right_proof`, `right_verifier_data` |
| `psy_prove_two_agg_circuit` | `left_agg_whitelist_merkle_proof`, `left_agg_proof_header`, `left_proof`, `left_verifier_data`, `right_agg_whitelist_merkle_proof`, `right_agg_proof_header`, `right_proof`, `right_verifier_data` |
| `psy_prove_left_leaf_right_agg_circuit` | `left_insert_leaf_proof`, `left_proof`, `left_verifier_data`, `right_agg_whitelist_merkle_proof`, `right_agg_proof_header`, `right_proof`, `right_verifier_data` |
| `psy_prove_left_agg_right_leaf_circuit` | `left_agg_whitelist_merkle_proof`, `left_agg_proof_header`, `left_proof`, `left_verifier_data`, `right_insert_leaf_proof`, `right_proof`, `right_verifier_data` |

## Bridge Groth16

| RPC method | Parameters |
|---|---|
| `psy_prove_withdrawal_batch_claim_groth16` | `input`: `BridgeWithdrawalBatchWitnessInput` |
| `psy_prove_deposit_batch_append_groth16` | `input`: `BridgeDepositBatchWitnessInput` |
| `psy_prove_bridge_agg_groth16` | `deps_network`: `String`, `input`: `BridgeAggWitnessInput` |

## Removed / absent (do not use)

- `psy_prove_zk_sign`
- `psy_prove_zk_sign_inner`

Use `psy_prove_zk_sign_minifier`, `psy_prove_secp_sign`, `psy_prove_eth_personal_secp_sign`, or the software-defined sign helpers instead.

## Source

- `client_prover/psy_prover/src/local/native/prove_proxy.rs`
