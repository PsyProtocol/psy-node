# Built-in Signature Schemes

> Updated: 2026-09-21. Mutable multisig status: scoped verification completed; final review pending. Public-chain enrollment and deployment have not been exercised.

## Abstract


This guide compares the ZK and SECP256K1 signature types and mutable multisig authentication. Mutable multisig supports public-only enrollment and policy replacement without changing the account identity.

## Table of Contents

- [1. ZK Key Signature](#1-zk-key-signature)
- [2. SECP256K1 Signature](#2-secp256k1-signature)
- [3. Comparison](#3-comparison)
- [4. Choosing a Signature Type](#4-choosing-a-signature-type)
- [5. Performance Benchmarks](#5-performance-benchmarks)
- [6. Changing Signature Type](#6-changing-signature-type)
- [7. Operational Guidance](#7-operational-guidance)
- [8. Support Direction](#8-support-direction)
- [9. Mutable Multisig Authentication](#9-mutable-multisig-authentication)

## 1. ZK Key Signature

The ZK signature scheme is Psy's optimized zero-knowledge signature system.

### Characteristics

- **Signature Type**: `zk`
- **Proof Generation Time**: 2-5 seconds
- **Circuit Optimization**: Highly optimized for fast proving
- **Security Model**: Zero-knowledge proof of secret knowledge
- **Security Basis**: Proof of knowledge of the registered secret; security depends on the underlying proving system assumptions

### When to Use ZK Keys

**Use for:**
- General-purpose transaction signing
- High-frequency trading applications  
- Real-time user interactions
- Mobile and web applications requiring responsive UX
- Applications prioritizing performance

### Technical Details

**ZK signature scheme:**

```text
public_key_params = hash(private_key, private_key_constants)
fingerprint = hash(verifier_data)
public_key = hash(public_key_params, fingerprint)
sig_action_hash = hash(data, network_magic, nonce)

circuit = private_inputs.private_key.get_public_key() == public_inputs_preimage[0..4]
public_inputs = hash(public_key_params, sig_action_hash)
private_inputs = private_key
```

**Key Features:**
- **Custom Signature Logic**: Supports transaction introspection and custom constraints
- **Optimized Circuit**: Minimal constraint count for fast proving (~2-5 seconds)
- **Native Psy Identity**: Does not use secp256k1 ECDSA; see §2 for the SECP256K1 compatibility path

## 2. SECP256K1 Signature

The SECP256K1 scheme provides compatibility with existing elliptic curve tooling through zero-knowledge proofs.

### Characteristics

- **Signature Type**: `secp256k1`
- **Proof Generation Time**: 10-20 seconds
- **Circuit Complexity**: Higher constraint count
- **Security Model**: Elliptic curve discrete logarithm
- **Compatibility**: Works with existing ECDSA tooling

### Technical Details

**SECP256K1 signature scheme:**

```text
public_key_hash = hash(secp256k1_public_key)
public_key_params = public_key_hash
fingerprint = hash(verifier_data)
public_key = hash(public_key_params, fingerprint)
sig_action_hash = hash(data, network_magic, nonce)

circuit = {
  hash(private_inputs.secp256k1_public_key) == public_inputs[0..4]
  secp256k1_verify(private_inputs.secp256k1_public_key, secp256k1_signature, sig_action_hash)
}
public_inputs = hash(public_key_params, sig_action_hash)
private_inputs = secp256k1_public_key, secp256k1_signature, sig_action_hash_preimage
```

**Circuit Implementation:**
- **ECDSA Verification**: Implements SECP256K1 signature verification in ZK circuit
- **Public Key Validation**: Proves knowledge of private key without revealing it  
- **Higher Complexity**: More constraints result in longer proving times
- **Tool Compatibility**: Enables use with ECDSA systems

### When to Use SECP256K1

**Use when:**
- Migrating from existing ECDSA-based systems
- Requiring compatibility with external tools
- Working with ECDSA applications
- Development and testing scenarios

### Performance Impact

The longer proof generation time of SECP256K1 makes it less suitable for:
- Interactive applications requiring quick responses
- High-throughput systems
- Mobile applications with limited computational resources
- Real-time trading platforms

## 3. Comparison

| Feature                | ZK Key          | SECP256K1             |
|------------------------|-----------------|-----------------------|
| **Proof Time**         | 2-5 seconds     | 10-20 seconds         |
| **Performance**        | Faster          | Slower                |
| **Security**           | ZK-based        | Elliptic-curve-based  |
| **Circuit Size**       | Optimized       | Complex               |
| **Quantum Resistance** | Better prepared | Vulnerable            |
| **Tool Compatibility** | Psy native      | ECDSA compatible      |
| **Use Case**           | Primary         | Compatibility         |

## 4. Choosing a Signature Type

### ZK Key

For most applications, **ZK key (`zk`)** is the recommended choice because:

```bash
# Fast and efficient for most use cases
psy_user_cli register-user --private-key <key> --sign-type zk
```

### When SECP256K1 Might Be Needed

```bash
# Only for specific compatibility requirements
psy_user_cli register-user --private-key <key> --sign-type secp256k1
```

Consider SECP256K1 only if you have specific requirements for:
- Integration with existing ECDSA infrastructure
- Migration scenarios from traditional blockchain systems
- Development environments requiring ECDSA tooling

## 5. Performance Benchmarks

### Proof Generation Times

Based on standard hardware configurations:

**ZK Key Performance:**
- Consumer laptop: ~2-3 seconds
- Server hardware: ~1-2 seconds  
- Mobile device: ~4-5 seconds

**SECP256K1 Performance:**
- Consumer laptop: ~12-15 seconds
- Server hardware: ~8-10 seconds
- Mobile device: ~18-25 seconds

### Resource Usage

**ZK Key:**
- Memory usage: Moderate
- CPU utilization: Efficient
- Battery impact: Low (mobile)

**SECP256K1:**
- Memory usage: Higher
- CPU utilization: Intensive
- Battery impact: Significant (mobile)

## 6. Changing Signature Type

### Changing from SECP256K1 to ZK

Registering a new ZK public key creates a separate account; it does not change an existing account's signature type or preserve its `user_id`. Existing-account migration is not provided by mutable multisig.

### Backward Compatibility

Both signature schemes can coexist in the same application:
- Different users can use different schemes
- Applications can support both simultaneously
- Coexistence does not provide an in-place account migration

## 7. Operational Guidance

### For New Applications

```bash
# Always prefer ZK keys for new implementations
SIGN_TYPE=zk
psy_user_cli wallet create
psy_user_cli register-user --sign-type ${SIGN_TYPE}
```

### For Existing Systems

1. **Evaluate Requirements**: Determine if ECDSA compatibility is truly needed
2. **Performance Testing**: Measure actual proof generation times in your environment  
3. **User Experience**: Consider the impact of longer signing times
4. **Migration Planning**: Plan for eventual upgrade to ZK keys

### Development and Deployment

**Development:**
```bash
# Fast iteration with ZK keys
make register-users
```

**ECDSA compatibility testing:**
```bash
# The Makefile target registers its configured users; it does not read SIGN_TYPE.
make register-users
```

## 8. Support Direction

### Planned Work

- **Custom Circuits**: Support for user-defined signature circuits
- **Aggregated Signatures**: Batch verification optimizations  
- **Hardware Acceleration**: GPU and specialized hardware support
- **Mobile Optimization**: Further optimizations for mobile devices

### Signature-Type Focus

SECP256K1 support continues, while new features and optimizations focus on ZK-based schemes.

## 9. Mutable Multisig Authentication

### Identity and policy

`MultisigSignatureCircuit` is a separate built-in authentication circuit selected by `TraceSignCircuitSource::Multisig`, not a private-key mode of `zk` or `secp256k1`. Proving needs only public account configuration, authenticated state, and external signatures: neither a master secret nor any member's private key.

The capacity is **exactly eight member slots**. `MultisigPolicy` contains `version: u32`, `threshold: u8`, `member_count: u8`, and `member_hashes: [QHashOut<GoldilocksField>; 8]`. A valid policy has a nonzero version and `1 <= threshold <= member_count <= 8`. Active member commitments are nonzero and strictly ordered lexicographically by their four canonical unsigned 64-bit limbs; unused slots are zero. Member commitments use `hash_no_pad_compressed_public_key` over canonical compressed secp256k1 public keys, not addresses.

`MultisigAccount` contains only `contract_id: u32` and `initial_policy: MultisigPolicy`. The initial policy has version 1. Its commitment and contract location (contract identifier, slot 0, state-tree height 4) determine immutable `public_key_param`. Together with the fixed circuit fingerprint, this determines `public_key`. Replacing the current policy changes neither value nor the registered `user_id`.

The authoritative policy commitment is in the account's **own starting contract state**, not another account's state or only the ending state. Exactly the current threshold of distinct current members authorizes the whole user proving session, including any replacement. The circuit also validates the ending policy: outside bootstrap it must be unchanged or have version `current.version + 1`, without overflow. Adding members, removing members, and changing the threshold all use one complete replacement policy. For example, a current 2-of-3 policy can authorize a version-incremented 3-of-4 policy with two current-member signatures; three replacement-member signatures are not a substitute.

Type and encoding source: `client_prover/psy_vm/src/ups/multisig.rs:20-108`.

### Bootstrap and replacement

The ordinary Dargo contract example is `../psy-compiler/psy-dargo-cli/examples/multisig_policy/src/main.psy:3-18`. It exposes `set_policy(expected: Hash, next: Hash)`: require the stored commitment to equal `expected`, require `next` to be nonzero, then replace the commitment. It is not a genesis precompile or a reserved contract identifier. The authentication circuit enforces membership, threshold, and version rules; the contract stores the commitment.

Bootstrap requires a zero starting policy slot, zero starting nonce, and the default starting user-state root. The first session must call `set_policy(zero, initial_commitment)` and end with the initial commitment, authorized by initial-policy signatures. There is no unsigned initialization, empty ending policy, or re-entry into bootstrap after initialization. A replacement calls `set_policy(current_commitment, next_commitment)` and admits at most one effective version increment per session. The current quorum can restore earlier membership through a valid version-incremented replacement; this is not bootstrap. Clearing the final policy slot is rejected even if a different contract method writes it.

Contract deployment, live-network rollout, and migration of existing single-key accounts are outside this feature's scope. This guide supplies no migration or deployment command. Scoped circuit, policy, and prover checks have passed, and the contract has compiled with its storage layout verified as slot 0 and state-tree height 4. Public-chain enrollment and deployment have not been exercised. These checks do not establish product performance; the single-key timing figures above are not multisig measurements.

### Wallet and remote procedure call interfaces

The asynchronous `WalletSession` methods take `&mut self`. Here `F` is `GoldilocksField`; hash arguments and successful key returns use `QHashOut<F>`.

| Method arguments | Successful return | Effect |
|---|---|---|
| `register_multisig_user(account: MultisigAccount)` | `QHashOut<F>` | Install the public-only signer and register its public identity; return `public_key`, not `user_id`. |
| `add_multisig_user(account: MultisigAccount)` | `QHashOut<F>` | Install an already-registered account in this wallet and resolve its `user_id`; no second registration. |
| `set_multisig_policy(public_key: QHashOut<F>, current_policy: MultisigPolicy, ending_policy: MultisigPolicy)` | `()` | Supply local policy preimages for trace generation; no on-chain write. |
| `inject_multisig_signatures(public_key: QHashOut<F>, signatures: MultisigSignatures)` | `QHashOut<F>` | Retain external signatures for signing; return the unchanged `public_key`. |

Rust methods return `anyhow::Result` around these values. The local JSON remote procedure call interface exposes the same arguments under `psy_register_multisig_user`, `psy_add_multisig_user`, `psy_set_multisig_policy`, and `psy_inject_multisig_signatures`. None accepts a private key. Sources: `client_prover/psy_prover/src/session/session.rs:1718-1741` and `client_prover/psy_prover/src/local/native/mod.rs:27-57`.

**The local `set_multisig_policy` and the on-chain `set_policy` are different operations.** Supplying ending-policy preimages does not execute the contract. A replacement trace must include the contract call and matching preimages. For an ordinary session after bootstrap, supply the same policy as both current and ending.

### Saved trace, external signatures, and proving

1. Register the account, or add its original `MultisigAccount` to a fresh wallet. Keep the original initial policy even after replacement.
2. Set current and ending policy preimages locally. Generate the unsigned `TxTrace` with `WalletSession::generate_tx_trace(public_key, call_data)`, including `set_policy` for bootstrap or replacement. The trace contains `MultisigSignatureWitness`: account, policy preimages, starting and ending state proofs, signature data, sign context, starting user leaf, and nonce. It does not contain injected signatures or member secrets.
3. Give each signer the complete trace and policies for independent review. Sign the exact 32-byte prehash described below, not a displayed hash string.
4. Supply `MultisigSignatures { member_indices: Vec<u8>, signatures: Vec<PsyCompressedSecp256K1Signature> }` through `inject_multisig_signatures`. Indices must be strictly increasing and refer to the sorted current-policy members. For proving, both vectors must have exactly `current_policy.threshold` entries.
5. Call `WalletSession::prove_tx_trace(public_key, &trace)`. A fresh wallet needs `add_multisig_user` and signature injection first; it does not need `set_multisig_policy` when proving this saved trace because the trace owns the policy preimages. Saved multisig traces select `TraceSignCircuitSource::Multisig` and must match its fingerprint; they do not fall back to a ZK-key circuit.

The local remote procedure call methods are `psy_generate_tx_trace(public_key, call_data)` and `psy_prove_tx_trace(public_key, envelope_json)`. Generation returns a JSON string encoding `GeneratedTxTraceJson`; pass the saved envelope string to proving rather than substituting a Rust `TxTrace` object. Sources: `client_prover/psy_prover/src/local/native/mod.rs:32-39,137-202`; `client_prover/psy_prover/src/session/session.rs:3270-3276,3557`.

For `sighash = trace.finalization.sig_hash`, the external signing message is exactly `Hash256::from(sighash).0`. If the four canonical hash limbs are `h0`, `h1`, `h2`, `h3`, construct:

```text
B = LE64(h0) || LE64(h1) || LE64(h2) || LE64(h3)
message = reverse(B)  // exactly 32 bytes
```

Use raw secp256k1 prehash signing with no additional hash, personal-sign prefix, or text encoding. Each signature supplies that identical `message`, a canonical compressed public key, and big-endian `r || s` signature bytes with low `s`. The envelope's displayed `sig_hash` is not the byte-contract specification.

Injection checks signature encodings, vector lengths, ordered indices, and a common message; it does not authenticate a trace that has not been supplied. Signing recomputes the trace sighash and checks the account identity, exact message bytes, current-member commitments, and exact threshold count before proving. Missing signatures, another account's witness, or a mismatched message fail. Source: `client_prover/psy_prover/src/signature/users/multisig_user.rs:48-112`.