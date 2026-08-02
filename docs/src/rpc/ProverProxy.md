# Prover Proxy RPC Documentation

This document provides comprehensive documentation for the Psy Prover Proxy RPC methods, which handle local zero-knowledge proof generation for various circuit types.

**RPC Namespace**: `psy`

**Default Listen Address**: `0.0.0.0:9999`

---

## Table of Contents

1. [Overview](#overview)
2. [UPS (Unified Proving System) Methods](#ups-unified-proving-system-methods)
3. [Contract Management](#contract-management)
4. [Signature Proving](#signature-proving)
5. [Software-Defined Signatures](#software-defined-signatures)
6. [Proof Tree Aggregation](#proof-tree-aggregation)
7. [Circuit Management](#circuit-management)
8. [Data Structures](#data-structures)
9. [Configuration](#configuration)
10. [Error Handling](#error-handling)

---

## Overview

The Prover Proxy is a local proving service that generates zero-knowledge proofs for various circuit types in the Psy ecosystem. It acts as a computational backend for transaction signing, contract execution, and proof aggregation.

### Key Features

- **Local Proof Generation**: Generate ZK proofs without sending sensitive data to remote servers
- **Multiple Circuit Types**: Support for UPS, contract calls, signatures, and aggregation circuits  
- **Software-Defined Signatures**: Custom circuit-based authentication schemes
- **Contract Circuit Management**: Dynamic registration and execution of contract circuits
- **Proof Tree Aggregation**: Hierarchical proof composition and verification

---

## UPS (Unified Proving System) Methods

### psy_prove_ups_start

Generate proof for UPS start step.

**Parameters**:
```json
{
  "input": "UPSStartStepInput<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Proves the initial step in the UPS proving pipeline.

---

### psy_prove_ups_start_register_user

Generate proof for user registration start step.

**Parameters**:
```json
{
  "input": "UPSStartStepRegisterUserInput<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Proves user registration within the UPS framework.

---

### psy_prove_ups_cfc_standard_tx

Generate proof for standard CFC (Contract Function Call) transaction.

**Parameters**:
```json
{
  "input": "UPSCFCStandardTransactionCircuitInput<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Proves standard contract function call transactions.

---

### psy_prove_ups_cfc_deferred_tx

Generate proof for deferred CFC transaction.

**Parameters**:
```json
{
  "input": "UPSCFCDeferredTransactionCircuitInput<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Proves deferred contract function call transactions.

---

### psy_prove_ups_end_cap

Generate proof for UPS end cap step.

**Parameters**:
```json
{
  "end_cap_from_proof_tree_input": "UPSEndCapFromProofTreeGadgetInput<F>",
  "circuit_type": "QStandardBinaryTreeCircuitType",
  "fingerprint": "QHashOut<F>",
  "agg_header": "QRecursionAggStandardHeader<F>",
  "proof": "ProofWithPublicInputs<F, C, D>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates the final proof that caps off a proof tree aggregation.

---

## Contract Management

### psy_get_circuits_data

Get information about available circuits.

**Parameters**: None

**Response**:
```json
{
  "result": "string"
}
```

**Description**: Returns serialized JSON containing circuit fingerprints and verifier configurations.

---

### psy_register_contract_circuits

Register circuits for a contract.

**Parameters**:
```json
{
  "contract_id": 123,
  "contract_code": "ContractCodeDefinition"
}
```

**Response**:
```json
{
  "result": null
}
```

**Description**: Registers and compiles circuits for all functions in a contract.

---

### psy_get_fn_id

Get function ID for a contract method.

**Parameters**:
```json
{
  "contract_id": 123,
  "method_name": "transfer"
}
```

**Response**:
```json
{
  "result": 0
}
```

**Description**: Returns the internal function ID for a named contract method.

---

### psy_get_fn_id_and_circuit_def

Get function ID and circuit definition for a contract method.

**Parameters**:
```json
{
  "contract_id": 123,
  "method_name": "transfer"
}
```

**Response**:
```json
{
  "result": [0, "DPNFunctionCircuitDefinition"]
}
```

**Description**: Returns both the function ID and the circuit definition for a method.

---

### psy_get_contract_method_common_data

Get common circuit data for a contract method.

**Parameters**:
```json
{
  "contract_id": 123,
  "fn_id": 0
}
```

**Response**:
```json
{
  "result": {
    "fingerprint": "QHashOut<F>",
    "verifier_config": "VerifierOnlyCircuitData"
  }
}
```

**Description**: Returns the circuit fingerprint and verifier configuration for a specific contract function.

---

### psy_resolve_contract_function_by_method_name

Resolve contract function by method name.

**Parameters**:
```json
{
  "contract_id": 123,
  "contract_code": "ContractCodeDefinition", 
  "method_name": "transfer"
}
```

**Response**:
```json
{
  "result": [0, "DPNFunctionCircuitDefinition"]
}
```

**Description**: Registers contract circuits and resolves function by name.

---

### psy_resolve_contract_function_by_method_id

Resolve contract function by method ID.

**Parameters**:
```json
{
  "contract_id": 123,
  "contract_code": "ContractCodeDefinition",
  "method_name": 12345678
}
```

**Response**:
```json
{
  "result": [0, "DPNFunctionCircuitDefinition"]
}
```

**Description**: Registers contract circuits and resolves function by method ID.

---

### psy_prove_contract_call

Generate proof for contract function call.

**Parameters**:
```json
{
  "contract_id": 123,
  "fn_id": 0,
  "input": "DapenContractFunctionCircuitInput<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates a ZK proof for executing a specific contract function.

---

## Signature Proving

### psy_prove_zk_sign

Generate ZK signature proof.

**Parameters**:
```json
{
  "private_key": "QHashOut<F>",
  "sig_hash": "QHashOut<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates a zero-knowledge signature proof using the built-in ZK signature scheme.

---

### psy_prove_zk_sign_inner

Generate inner ZK signature proof.

**Parameters**:
```json
{
  "private_key": "QHashOut<F>",
  "sig_hash": "QHashOut<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates the inner component of a ZK signature proof for later minification.

---

### psy_prove_zk_sign_minifier

Minify an inner ZK signature proof.

**Parameters**:
```json
{
  "inner_proof": "string"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Takes a serialized inner proof and produces a minified version for efficiency.

---

### psy_prove_secp_sign

Generate SECP256K1 signature proof.

**Parameters**:
```json
{
  "signature": "PsyCompressedSecp256K1Signature"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates a zero-knowledge proof of a valid SECP256K1 signature.

---

## Software-Defined Signatures

### psy_register_dpn_software_defined_circuit

Register a DPN software-defined signature circuit.

**Parameters**:
```json
{
  "request": "QRegisterDPNSoftwareDefinedCircuitRPCRequest"
}
```

**Response**:
```json
{
  "result": "QHashOut<F>"
}
```

**Description**: Registers a software-defined signature circuit written in Psy language.

**Status**: The RPC shape is reserved; the service rejects this registration path until implementation is enabled.

---

### psy_register_plonky2_software_defined_circuit

Register a Plonky2 software-defined signature circuit.

**Parameters**:
```json
{
  "request": "QRegisterPlonky2SoftwareDefinedCircuitRPCRequest"
}
```

**Response**:
```json
{
  "result": "QHashOut<F>"
}
```

**Description**: Registers a software-defined signature circuit written directly in Plonky2.

**Status**: The RPC shape is reserved; the service rejects this registration path until implementation is enabled.

---

### psy_prove_dpn_software_defined_sign

Generate proof for DPN software-defined signature.

**Parameters**:
```json
{
  "fingerprint": "QHashOut<F>",
  "private_key": "QHashOut<F>",
  "input": "DPNSoftwareDefinedSignatureInput",
  "sig_hash": "QHashOut<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates a proof for a custom signature circuit written in Psy language.

---

### psy_prove_plonky2_software_defined_sign

Generate proof for Plonky2 software-defined signature.

**Parameters**:
```json
{
  "fingerprint": "QHashOut<F>",
  "private_key": "QHashOut<F>",
  "input": "Plonky2SoftwareDefinedSignatureInput",
  "sig_hash": "QHashOut<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Generates a proof for a custom signature circuit written in Plonky2.

---

## Proof Tree Aggregation

The prover proxy supports hierarchical proof aggregation through various circuit types:

### psy_prove_single_leaf_circuit

Aggregate a single leaf proof.

**Parameters**:
```json
{
  "agg_circuit_whitelist_root": "QHashOut<F>",
  "single_insert_leaf_proof": "DeltaMerkleProofCore<QHashOut<F>>",
  "single_proof": "ProofWithPublicInputs<F, C, D>",
  "single_verifier_data": "AltVerifierOnlyCircuitData<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Creates an aggregation proof for a single leaf node in the proof tree.

---

### psy_prove_two_leaf_circuit

Aggregate two leaf proofs.

**Parameters**:
```json
{
  "agg_circuit_whitelist_root": "QHashOut<F>",
  "left_insert_leaf_proof": "DeltaMerkleProofCore<QHashOut<F>>",
  "left_proof": "ProofWithPublicInputs<F, C, D>",
  "left_verifier_data": "AltVerifierOnlyCircuitData<F>",
  "right_insert_leaf_proof": "DeltaMerkleProofCore<QHashOut<F>>",
  "right_proof": "ProofWithPublicInputs<F, C, D>",
  "right_verifier_data": "AltVerifierOnlyCircuitData<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Creates an aggregation proof combining two leaf proofs.

---

### psy_prove_two_agg_circuit

Aggregate two aggregation proofs.

**Parameters**:
```json
{
  "left_agg_whitelist_merkle_proof": "MerkleProofCore<QHashOut<F>>",
  "left_agg_proof_header": "QRecursionAggStandardHeader<F>",
  "left_proof": "ProofWithPublicInputs<F, C, D>",
  "left_verifier_data": "AltVerifierOnlyCircuitData<F>",
  "right_agg_whitelist_merkle_proof": "MerkleProofCore<QHashOut<F>>",
  "right_agg_proof_header": "QRecursionAggStandardHeader<F>",
  "right_proof": "ProofWithPublicInputs<F, C, D>",
  "right_verifier_data": "AltVerifierOnlyCircuitData<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Creates an aggregation proof combining two aggregation proofs.

---

### psy_prove_left_leaf_right_agg_circuit

Aggregate a leaf proof with an aggregation proof (leaf on left).

**Parameters**:
```json
{
  "left_insert_leaf_proof": "DeltaMerkleProofCore<QHashOut<F>>",
  "left_proof": "ProofWithPublicInputs<F, C, D>",
  "left_verifier_data": "AltVerifierOnlyCircuitData<F>",
  "right_agg_whitelist_merkle_proof": "MerkleProofCore<QHashOut<F>>",
  "right_agg_proof_header": "QRecursionAggStandardHeader<F>",
  "right_proof": "ProofWithPublicInputs<F, C, D>",
  "right_verifier_data": "AltVerifierOnlyCircuitData<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Creates a mixed aggregation proof with a leaf on the left and aggregation on the right.

---

### psy_prove_left_agg_right_leaf_circuit

Aggregate an aggregation proof with a leaf proof (aggregation on left).

**Parameters**:
```json
{
  "left_agg_whitelist_merkle_proof": "MerkleProofCore<QHashOut<F>>",
  "left_agg_proof_header": "QRecursionAggStandardHeader<F>",
  "left_proof": "ProofWithPublicInputs<F, C, D>",
  "left_verifier_data": "AltVerifierOnlyCircuitData<F>",
  "right_insert_leaf_proof": "DeltaMerkleProofCore<QHashOut<F>>",
  "right_proof": "ProofWithPublicInputs<F, C, D>",
  "right_verifier_data": "AltVerifierOnlyCircuitData<F>"
}
```

**Response**:
```json
{
  "result": "ProofWithPublicInputs<F, C, D>"
}
```

**Description**: Creates a mixed aggregation proof with aggregation on the left and a leaf on the right.

---

## Circuit Management

### Circuit Information

The prover proxy manages various circuit types with their fingerprints and verifier data:

- **UPS Circuits**: `ups_start`, `ups_start_register_user`, `ups_cfc_standard_tx`, `ups_cfc_deferred_tx`, `ups_end_cap`
- **Aggregation Circuits**: `single_leaf_circuit`, `two_leaf_circuit`, `two_agg_circuit`, `left_leaf_right_agg_circuit`, `left_agg_right_leaf_circuit`
- **Signature Circuits**: `zk_circuit`, `secp_circuit`
- **Software-Defined Circuits**: Dynamically registered custom circuits

### Circuit Registration

Circuits are automatically registered during prover initialization:

1. **System Circuits**: Core UPS and aggregation circuits are pre-registered
2. **Contract Circuits**: Registered on-demand when contracts are deployed
3. **Software-Defined Circuits**: Registered through dedicated RPC methods

---

## Data Structures

### Field Types

```rust
type F = <PoseidonGoldilocksConfig as GenericConfig<2>>::F;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;
```

### Common Input Types

**UPSStartStepInput**: Input for UPS start step proving
**UPSStartStepRegisterUserInput**: Input for user registration proving  
**UPSCFCStandardTransactionCircuitInput**: Input for standard contract calls
**UPSCFCDeferredTransactionCircuitInput**: Input for deferred contract calls
**DapenContractFunctionCircuitInput**: Input for contract function execution

### Proof Types

**ProofWithPublicInputs<F, C, D>**: Complete ZK proof with public inputs
**QHashOut<F>**: Hash output in the field F
**MerkleProofCore<QHashOut<F>>**: Merkle proof for hash verification
**DeltaMerkleProofCore<QHashOut<F>>**: Delta merkle proof for tree updates

### Circuit Data

**QCommonCircuitData**: Circuit fingerprint and verifier configuration
**AltVerifierOnlyCircuitData**: Alternative verifier data format
**ContractCodeDefinition**: Complete contract code with all functions
**DPNFunctionCircuitDefinition**: Function-specific circuit definition

---

## Configuration

### Server Configuration

The prover proxy is configured via `ProveProxyArgs`:

```rust
pub struct ProveProxyArgs {
    pub listen_addr: String,        // Default: "0.0.0.0:9999"
    pub rpc_config: String,         // Path to network config file
}
```

### Network Configuration

```bash
# Start prover proxy
psy_user_cli prove-proxy \
  --listen-addr "127.0.0.1:9999" \
  --rpc-config "config.json"
```

### Circuit Initialization

The prover proxy initializes with:
- Network magic number for proof validation
- RPC provider for fetching contract code
- Circuit manager for all proof types
- Session circuit info store for fingerprint tracking

---

## Error Handling

All RPC methods return `Result<T, ErrorObjectOwned>` with standardized error formats:

### Common Error Types

```json
{
  "code": 1,
  "message": "Task schedule failed",
  "data": "Thread pool task execution failed: ..."
}
```

```json
{
  "code": 1, 
  "message": "ZK proof generation failed",
  "data": "Circuit constraint violation: ..."
}
```

```json
{
  "code": 1,
  "message": "Contract not found",
  "data": "contract 123 method transfer not registered"
}
```

### Error Categories

1. **Task Scheduling Errors**: Thread pool issues during proof generation
2. **Proving Errors**: ZK proof generation failures 
3. **Registration Errors**: Circuit registration and management issues
4. **Contract Errors**: Contract code resolution and function lookup failures
5. **Deserialization Errors**: Invalid input data format

---

## Performance Considerations

### Asynchronous Proving

All proving operations use `tokio::task::spawn_blocking` to:
- Avoid blocking the async runtime during CPU-intensive proving
- Enable concurrent proof generation
- Maintain server responsiveness

### Circuit Caching

- Circuits are compiled once and reused for multiple proofs
- Contract circuits are cached by contract ID  
- Software-defined circuits are cached by fingerprint

### Memory Management

- Circuit managers use `Arc` for safe sharing across async tasks
- Large proof objects are moved into background tasks to minimize copying
- Verifier data is pre-computed and cached for efficiency

---

**Document Version**: 1.0  
**Last Updated**: 2024-12-16  
**Total RPC Methods**: 25+