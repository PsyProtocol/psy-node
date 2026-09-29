# Built-in Signature Schemes

> Updated: 2026-09-27. Mutable multisig first-milestone status: implementation; current quality assurance (QA) pending. No runtime validation or public-chain deployment pass is claimed for this contract.

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

The first milestone is **exactly two signatures from three members**, not an adjustable threshold. `MultisigPolicy` contains `version: u32`, `threshold: u8`, `member_count: u8`, and `member_hashes: [QHashOut<GoldilocksField>; 8]`. Validation requires a nonzero version, `threshold == 2`, and `member_count == 3`. Only entries 0 through 2 are members; entries 3 through 7 must be zero padding retained by the identity encoding. The three member commitments must be nonzero and strictly ordered lexicographically by their four canonical unsigned 64-bit limbs. They use `hash_no_pad_compressed_public_key` over canonical compressed secp256k1 public keys, not addresses.

`StoredMultisigPolicy` contains `header: QHashOut<GoldilocksField>` and `members: [QHashOut<GoldilocksField>; 3]`. The account's own policy precompile has contract identifier **6** and state-tree height **4**. Slot 0 stores `[version, 2, 3, 0]`; slots 1, 2, and 3 store the three ordered member commitments. There is no stored opaque policy commitment.

`MultisigAccount` contains `contract_id: u32` and `initial_policy: MultisigPolicy`; the contract identifier must be 6 and the initial version must be 1. The derived initial-policy commitment, contract identifier, slot 0, and state-tree height 4 determine immutable `public_key_param`. Together with the fixed circuit fingerprint, this determines `public_key`. This identity commitment is distinct from the stored policy fields. Replacing members changes neither identity nor the registered `user_id`.

Current and ending policies are derived from authenticated starting and ending self-state. Each state supplies four self-slot reads and eight alternating contract-tree/slot proofs for slots 0 through 3. `MultisigSignatureWitness::policies()` validates these proofs and derives both policies; callers cannot supply independent current or ending policy preimages. Two distinct **current** members authorize the whole session, including replacement. Outside bootstrap, the ending policy must either equal the current policy or contain changed members with exactly `current.version + 1`, without overflow. A replacement-member quorum is not a substitute for the current quorum.

Sources: `client_prover/psy_vm/src/ups/multisig.rs:20-175`; `client_prover/psy_prover/src/signature/users/multisig_user.rs:66-77`.

### Bootstrap and replacement

The policy precompile exposes `get_policy() -> (Hash, [Hash; 3])` and `set_policy(expected_header: Hash, expected_members: [Hash; 3], next_members: [Hash; 3])`. The setter compares all four stored slots with the expected values, validates the next members, and writes the header and three members. It is not the commitment-only ordinary contract example. Source: `../psy-compiler/psy-precompiles/multisig_policy/src/main.psy:3-83`.

Bootstrap requires all four starting policy slots to be zero, a zero starting nonce, and the default starting user-state root. The first session calls `set_policy` with a zero expected header, three zero expected members, and the three initial-policy members. The precompile writes version 1; the authentication circuit requires the ending policy to equal the initial policy and requires two initial-member signatures. There is no unsigned initialization or re-entry into bootstrap.

Public Genesis enrollment is different from pristine bootstrap. The Genesis generator registers the public account at index 2/user 524288 and seeds contract 6 with `[1, 2, 3, 0]` plus the three initial members, together with the contract-0 fee balance. Although its user nonce starts at zero, its policy and user state are already initialized. Its first signed session therefore uses two current initial-policy members without a bootstrap `set_policy` call. Do not invoke `guardian-policy --intent bootstrap` to initialize that account again. `guardian-policy --intent bootstrap` applies only to a separately registered pristine account whose four policy slots and starting state satisfy the bootstrap rules above. Public Genesis construction and initialized-state execution QA remain pending. Source: `psy_cli/psy_dev_cli/src/subcommand/generate_genesis.rs:207-229,355-378`.

For replacement, supply the current stored header and members as the expected values and three valid next members. At least one member must change; the precompile increments the version and rejects overflow. Threshold and member count remain 2 and 3. The session permits at most one effective version increment. A current quorum can restore earlier membership only through another version-incremented replacement. Empty or partially initialized ending policies fail closed. Sources: `../psy-compiler/psy-precompiles/multisig_policy/src/main.psy:59-82`; `client_prover/psy_vm/src/ups/multisig.rs:154-175`.

Current QA is **pending** for the field-based contract, circuit, wallet, and remote procedure call interfaces. Previous checks of a commitment-only contract do not validate this contract. Contract compilation, generated method identifiers, circuit/prover execution, public-chain enrollment, and deployment are not claimed as verified here. This guide supplies no deployment or account-migration command. The single-key timing figures above are not multisig measurements.

### Wallet and remote procedure call interfaces

The three asynchronous `WalletSession` methods in this table take `&mut self`. Here `F` is `GoldilocksField`; hash arguments and successful key returns use `QHashOut<F>`.

| Method arguments | Successful return | Effect |
|---|---|---|
| `register_multisig_user(account: MultisigAccount)` | `QHashOut<F>` | Install the public-only signer and register its public identity; return `public_key`, not `user_id`. |
| `add_multisig_user(account: MultisigAccount)` | `QHashOut<F>` | Install an already-registered account in this wallet and resolve its `user_id`; no second registration. |
| `inject_multisig_signatures(public_key: QHashOut<F>, signatures: MultisigSignatures)` | `QHashOut<F>` | Retain external signatures for signing; return the unchanged `public_key`. |

Rust methods return `anyhow::Result` around these values. The local JSON remote procedure call interface exposes the same arguments under `psy_register_multisig_user`, `psy_add_multisig_user`, and `psy_inject_multisig_signatures`. None accepts a private key. There is no `set_multisig_policy` wallet method or `psy_set_multisig_policy` endpoint. Sources: `client_prover/psy_prover/src/session/session.rs:1792-1795,1836-1847`; `client_prover/psy_prover/src/local/native/mod.rs:50-55`.

For a checkpoint-pinned trace, the asynchronous wallet method is `begin_trace_build_at_checkpoint(&self, public_key: QHashOut<F>, user_id: u64, checkpoint_id: u64, expected_nonce: u64, verified_checkpoint_tree_root: QHashOut<F>) -> anyhow::Result<TraceBuildSession<'_>>`. The caller must independently authenticate the supplied checkpoint root; a signing request is not its authority. The builder exposes `required_fee(&self) -> anyhow::Result<u64>`. These are Rust interfaces, not additional local JSON endpoints. Sources: `client_prover/psy_prover/src/session/session.rs:856,2157`.

For caller-controlled endpoint routing, the asynchronous constructor is `WalletSession::new_with_provider(rpc_config: &psy_config::NetworkConfigGoldilocks, st_provider: RpcProvider) -> anyhow::Result<Self>`. Configure the provider's endpoint routing before constructing the session and use that injected provider for the pinned-checkpoint workflow above. The constructor rejects every nonblank `prove_proxy_url` entry: injected-provider sessions use local proving managers rather than a remote proving proxy. Endpoint selection does not authenticate a checkpoint root. Source: `client_prover/psy_prover/src/session/session.rs:1516-1519`.

Bridge enrollment has a separate asynchronous Rust method: `WalletSession::register_bridge_multisig_user(&mut self, account: MultisigAccount, exclusive_registration_intake: bool) -> anyhow::Result<QHashOut<F>>`. It targets registration index **2**, corresponding to user identifier **524288**, and returns the public key. This does not replace ordinary `register_multisig_user` and is not a new local JSON endpoint. The operator must exclusively control and drain registration intake before calling it, then maintain exclusive intake until inclusion. The boolean acknowledges that operational prerequisite; it does not acquire a server lock or provide a server-side compare-and-set guarantee.

If index 2 already contains the expected public key, bridge enrollment succeeds only when the key maps to exactly `[524288]`. Otherwise, it requires index 2 to be empty, the next registration index to equal 2, and no existing mapping for the public key. It submits once and waits for canonical index-2 inclusion and the exact key mapping. A submission error is ambiguous; a raced index can leave the submission queued or registered at another index. Neither failure rolls back registration or permits automatic resubmission. Inspect canonical index 2 and the public-key mapping before manual action. Source: `client_prover/psy_prover/src/session/session.rs:1797-1834`. Current QA for these interfaces remains pending.

### Saved trace, external signatures, and proving

1. Register the account, or add its original `MultisigAccount` to a fresh wallet. Keep the original initial policy even after replacement.
2. Generate the unsigned `TxTrace` with `WalletSession::generate_tx_trace(&self, public_key: QHashOut<F>, call_data: ContractCallData) -> anyhow::Result<TxTrace>`, including the precompile `set_policy` call for bootstrap or replacement. The trace owns `MultisigSignatureWitness`: `account`, `start_state`, `end_state`, `sig_data`, `sign_context`, `start_session_user_leaf`, and `nonce`. Policies are derived from the authenticated slot fields; the witness contains neither separate policy preimages nor injected signatures or member secrets.
3. Give each signer the complete trace for independent review, including the authenticated current and ending policy fields. Sign the exact 32-byte prehash described below, not a displayed hash string.
4. Supply `MultisigSignatures { member_indices: Vec<u8>, signatures: Vec<PsyCompressedSecp256K1Signature> }` through `inject_multisig_signatures`. Both vectors must contain exactly two entries. Indices must be strictly increasing and refer to members 0, 1, or 2 of the sorted current policy.
5. Call `WalletSession::prove_tx_trace(&self, public_key: QHashOut<F>, trace: &TxTrace) -> Result<QHashOut<F>, ProveError>`. A fresh wallet needs `add_multisig_user` with the original account and signature injection first; no local policy setter is required or available. Saved multisig traces select `TraceSignCircuitSource::Multisig` and must match its fingerprint; they do not fall back to a ZK-key circuit.

The local remote procedure call methods are `psy_generate_tx_trace(public_key, call_data)` and `psy_prove_tx_trace(public_key, envelope_json)`. Generation returns a JSON string encoding `GeneratedTxTraceJson`; pass that saved envelope string to proving rather than substituting a Rust `TxTrace` object. Sources: `client_prover/psy_prover/src/local/native/mod.rs:32-39`; `client_prover/psy_prover/src/session/session.rs:3395-3402,3682`; `client_prover/psy_vm/src/ups/multisig.rs:94-110`.

For `sighash = trace.finalization.sig_hash`, the external signing message is exactly `Hash256::from(sighash).0`. If the four canonical hash limbs are `h0`, `h1`, `h2`, `h3`, construct:

```text
B = LE64(h0) || LE64(h1) || LE64(h2) || LE64(h3)
message = reverse(B)  // exactly 32 bytes
```

Use raw secp256k1 prehash signing with no additional hash, personal-sign prefix, or text encoding. Each signature supplies that identical `message`, a canonical compressed public key, and big-endian `r || s` signature bytes with low `s`. The envelope's displayed `sig_hash` is not the byte-contract specification.

Injection checks signature encodings, exactly two signatures, ordered indices in 0 through 2, and a common message; it does not authenticate a trace that has not been supplied. Signing derives the current policy from the trace's authenticated fields, recomputes the trace sighash, and checks the account identity, exact message bytes, and current-member commitments before proving. Missing signatures, another account's witness, or a mismatched message fail. Source: `client_prover/psy_prover/src/signature/users/multisig_user.rs:30-99`.