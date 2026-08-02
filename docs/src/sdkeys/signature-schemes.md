# Built-in Signature Schemes

Psy provides two built-in signature schemes that serve different use cases and performance requirements.

## ZK Key Signature

The ZK signature scheme is Psy's optimized zero-knowledge signature system.

### Characteristics

- **Signature Type**: `zk`
- **Proof Generation Time**: 2-5 seconds
- **Circuit Optimization**: Highly optimized for fast proving
- **Security Model**: Zero-knowledge proof of secret knowledge
- **Quantum Resistance**: Designed with post-quantum considerations

### When to Use ZK Keys

✅ **Recommended for:**
- General-purpose transaction signing
- High-frequency trading applications  
- Real-time user interactions
- Mobile and web applications requiring responsive UX
- Applications prioritizing performance

### Technical Details

**QED ZK Signature Scheme:**

```
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
- **ECDSA Compatibility**: Can integrate with existing ECDSA infrastructure
- **Quantum Resistance**: Designed to be resistant to quantum computing attacks
- **Optimized Circuit**: Minimal constraint count for fast proving (~2-5 seconds)

## SECP256K1 Signature

The SECP256K1 scheme provides compatibility with existing elliptic curve tooling through zero-knowledge proofs.

### Characteristics

- **Signature Type**: `secp256k1`
- **Proof Generation Time**: 10-20 seconds
- **Circuit Complexity**: Higher constraint count
- **Security Model**: Elliptic curve discrete logarithm
- **Compatibility**: Works with existing ECDSA tooling

### Technical Details

**QED Software Defined Signature (SECP256K1):**

```
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
- **Backward Compatibility**: Enables migration from traditional ECDSA systems

### When to Use SECP256K1

⚠️ **Use only when:**
- Migrating from existing ECDSA-based systems
- Requiring compatibility with external tools
- Working with legacy applications
- Development and testing scenarios

### Performance Impact

The longer proof generation time of SECP256K1 makes it less suitable for:
- Interactive applications requiring quick responses
- High-throughput systems
- Mobile applications with limited computational resources
- Real-time trading platforms

## Comparison Table

| Feature | ZK Key | SECP256K1 |
|---------|--------|-----------|
| **Proof Time** | 2-5 seconds | 10-20 seconds |
| **Performance** | ⭐⭐⭐⭐⭐ | ⭐⭐ |
| **Security** | High (ZK-based) | Standard (EC-based) |
| **Circuit Size** | Optimized | Complex |
| **Quantum Resistance** | Better prepared | Vulnerable |
| **Tool Compatibility** | Psy native | ECDSA compatible |
| **Use Case** | 🎯 Primary | 🔧 Compatibility |

## Choosing the Right Scheme

### Default Choice: ZK Key

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

## Performance Benchmarks

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

## Migration Considerations

### Upgrading from SECP256K1 to ZK

If you're currently using SECP256K1 and want to upgrade:

1. Generate a new ZK key pair
2. Register the new public key
3. Update applications to use the new key
4. Gradually migrate transaction signing

### Backward Compatibility

Both signature schemes can coexist in the same application:
- Different users can use different schemes
- Applications can support both simultaneously
- Gradual migration strategies are supported

## Best Practices

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

### Development vs Production

**Development:**
```bash
# Fast iteration with ZK keys
SIGN_TYPE=zk make register-user
```

**Legacy Testing:**
```bash
# When testing ECDSA compatibility
SIGN_TYPE=secp256k1 make register-user
```

## Future Considerations

### Roadmap

- **Custom Circuits**: Support for user-defined signature circuits
- **Aggregated Signatures**: Batch verification optimizations  
- **Hardware Acceleration**: GPU and specialized hardware support
- **Mobile Optimization**: Further optimizations for mobile devices

### Deprecation Timeline

While SECP256K1 support will continue, new features and optimizations will focus on ZK-based schemes. Plan migration to ZK keys for long-term compatibility.