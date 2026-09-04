# Wallet Management

> Updated: 2026-09-04.

## Abstract


This guide covers wallet creation, keystore management, user registration, transaction signing, mining-wallet use, and failure handling for Psy signature types.

## Table of Contents

- [1. Creating Wallets](#1-creating-wallets)
- [2. Wallet Information](#2-wallet-information)
- [3. User Registration](#3-user-registration)
- [4. Signing Transactions](#4-signing-transactions)
- [5. Keystore Management](#5-keystore-management)
- [6. Multi-User Scenarios](#6-multi-user-scenarios)
- [7. Mining Wallets](#7-mining-wallets)
- [8. Security Practices](#8-security-practices)
- [9. Troubleshooting](#9-troubleshooting)

## 1. Creating Wallets

### 1.1 Create a Wallet

Generate a completely new wallet with random private key:

```bash
# Display a new wallet without writing a keystore file
psy_user_cli wallet create

# Write an encrypted keystore to an explicit path
psy_user_cli wallet create --output <home>/.psy/keystore/miner0.json
```

Without `--output`, the command displays the Ethereum address and public key but does not write a file. With `--output`, it prompts for a password unless `--password` is supplied, then writes the encrypted keystore to that path.

### 1.2 Generate Random Wallet Data

Generate a random wallet with specified signature type:

```bash
# Generate random wallet with ZK signature (recommended)
psy_user_cli wallet random --sign-type zk

# Generate random wallet with SECP256K1 signature
psy_user_cli wallet random --sign-type secp256k1
```

### 1.3 Inspect an Existing Private Key

Inspect an existing private key:

```bash
# Get wallet info from private key
psy_user_cli wallet info --private-key <your_private_key> --sign-type zk
```

## 2. Wallet Information

### 2.1 View Wallet Details

Display information about a wallet:

```bash
# View wallet info using private key
psy_user_cli wallet info --private-key <private_key> --sign-type zk

# View wallet info using keystore
psy_user_cli wallet info --keystore-path <home>/.psy/keystore/your_wallet.json
```

Output includes:
- Public key
- Address representation
- Signature type
- Key derivation information

## 3. User Registration

Before using a wallet for transactions, you must register the user with the Psy network.

### 3.1 Register with ZK Signature

```bash
# Register user with ZK signature scheme
psy_user_cli register-user --private-key <private_key> --sign-type zk

# Register using keystore file
psy_user_cli register-user --keystore-path <home>/.psy/keystore/wallet.json --sign-type zk
```

### 3.2 Register with SECP256K1 Signature

```bash
# Register user with SECP256K1 signature scheme
psy_user_cli register-user --private-key <private_key> --sign-type secp256k1

# Register using keystore file  
psy_user_cli register-user --keystore-path <home>/.psy/keystore/wallet.json --sign-type secp256k1
```

### 3.3 Registration Output

For a new registration, the command prints:

```text
registered user uuid: <uuid>
{
  "private_key": "<generated-private-key-if-created>",
  "public_key_hash": "<public-key-hash>",
  "fingerprint": "<fingerprint>",
  "public_key_param": "<public-key-parameter>"
}
```

The `private_key` field appears only when the command generated the key. If the public key is already registered, the command prints the existing user identifiers and the same key information instead of submitting another registration.

## 4. Signing Transactions

### 4.1 Contract Calls

Execute contract methods using your wallet:

```bash
# Call contract method with private key
psy_user_cli call \
  --private-key <private_key> \
  --contract-id <contract_id> \
  --method-name <method_name> \
  --inputs "[param1, param2, ...]" \
  --sign-type zk

# Call contract method with keystore
psy_user_cli call \
  --keystore-path <home>/.psy/keystore/wallet.json \
  --contract-id <contract_id> \
  --method-name <method_name> \
  --inputs "[param1, param2, ...]" \
  --sign-type zk
```

### 4.2 Token Operations

```bash
# Mint tokens
psy_user_cli call \
  --keystore-path <home>/.psy/keystore/treasury.json \
  --contract-id 0 \
  --method-name simple_mint \
  --inputs "[1000000000000]" \
  --sign-type zk

# Transfer tokens
psy_user_cli call \
  --private-key <sender_private_key> \
  --contract-id 0 \
  --method-name simple_transfer \
  --inputs "[<recipient_user_id>, 250000000000]" \
  --sign-type zk

# Claim tokens from another user
psy_user_cli call \
  --private-key <recipient_private_key> \
  --contract-id 0 \
  --method-name simple_claim \
  --inputs "[<sender_user_id>]" \
  --sign-type zk
```

## 5. Keystore Management

### 5.1 Keystore Paths

`wallet create` writes a keystore only when `--output` names the destination. `wallet list` uses `<home>/.psy/keystore` when `--keystore-dir` is omitted. For example:

```text
<home>/.psy/keystore/
├── miner0.json
├── miner1.json
├── treasury.json
└── user_wallet.json
```

### 5.2 Create a Keystore

```bash
psy_user_cli wallet create --output <home>/.psy/keystore/miner0.json
```

The command prompts for a password and writes the encrypted keystore to the explicit output path. Supply `--password` only through an appropriately protected invocation environment.

### 5.3 Use Keystore Files

```bash
# Register user using keystore
psy_user_cli register-user \
  --keystore-path <home>/.psy/keystore/miner0.json \
  --sign-type zk

# Execute transactions using keystore
psy_user_cli call \
  --keystore-path <home>/.psy/keystore/miner0.json \
  --contract-id 0 \
  --method-name simple_mint \
  --inputs "[1000]" \
  --sign-type zk
```

## 6. Multi-User Scenarios

### 6.1 Multiple Wallets for Testing

Create and register multiple users for testing:

```bash
# Create multiple test users with different signature types
psy_user_cli register-user --private-key 17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a --sign-type zk
sleep 0.5
psy_user_cli register-user --private-key f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d --sign-type zk  
sleep 0.5
psy_user_cli register-user --private-key 73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268 --sign-type zk
```

### 6.2 Cross-User Transactions

```bash
# User 0 transfers to User 1
psy_user_cli call \
  --private-key 17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a \
  --contract-id 0 \
  --method-name simple_transfer \
  --inputs "[1, 250000000000]" \
  --sign-type zk

# User 1 claims the transfer
psy_user_cli call \
  --private-key f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d \
  --contract-id 0 \
  --method-name simple_claim \
  --inputs "[0]" \
  --sign-type zk
```

## 7. Mining Wallets

### 7.1 Create Mining Wallets

For mining operations, create dedicated wallets:

```bash
# Create mining wallets at explicit paths
psy_user_cli wallet create --output <home>/.psy/keystore/miner0.json
psy_user_cli wallet create --output <home>/.psy/keystore/miner1.json

# Register mining wallets
psy_user_cli register-user --keystore-path <home>/.psy/keystore/miner0.json
psy_user_cli register-user --keystore-path <home>/.psy/keystore/miner1.json
```

### 7.2 Use Mining Wallets

```bash
# Start mining with keystore
psy_worker_cli worker \
  --config ./config.json \
  --keystore-path <home>/.psy/keystore/miner0.json \
  --user 3145728 \
  --completed-jobs-log-file worker.backup

# Claim mining rewards
psy_user_cli claim-rewards \
  --keystore-path <home>/.psy/keystore/miner0.json \
  --jobs-file worker.backup
```

## 8. Security Practices

### Key Storage

1. **Backup Keystore Files**: Keep secure copies of `<home>/.psy/keystore`.
2. **Strong Passwords**: Use strong passwords for keystore encryption
3. **Access Control**: Limit file system access to keystore files
4. **Hardware Security**: Consider hardware wallets for high-value operations

### Private Key Handling

```bash
# Use environment variables for sensitive operations
export PRIVATE_KEY="your_private_key_here"
psy_user_cli register-user --private-key $PRIVATE_KEY --sign-type zk

# Clear environment variables after use
unset PRIVATE_KEY
```

### Production Considerations

1. **Key Rotation**: Plan for periodic key rotation
2. **Multi-Signature**: Implement multi-signature schemes for critical operations
3. **Monitoring**: Monitor wallet activity and unusual transactions
4. **Backup Strategy**: Maintain secure, distributed backups

## 9. Troubleshooting

### Common Issues

**Keystore file not found:**
```bash
# Verify keystore path
psy_user_cli wallet list --keystore-dir <home>/.psy/keystore
# Ensure file exists and has correct permissions
```

**Registration fails:**
```bash
# Check network connectivity
# Verify private key format
# Ensure signature type matches
```

**Long proof generation times:**
```bash
# Switch to ZK signature type for better performance
psy_user_cli register-user --private-key <key> --sign-type zk
```

### Performance Optimization

1. **Use ZK signatures** for optimal performance
2. **Hardware considerations**: Ensure adequate CPU and memory
3. **Network latency**: Use reliable network connections
4. **Batch operations**: Group multiple transactions when possible
