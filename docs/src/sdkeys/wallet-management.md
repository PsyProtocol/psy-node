# Wallet Management

This guide covers wallet creation, management, and usage with Psy's SDKeys signature schemes.

## Creating Wallets

### Method 1: Create New Wallet

Generate a completely new wallet with random private key:

```bash
# Create a new wallet (interactive)
psy_user_cli wallet create
```

This command will:
1. Generate a new private key
2. Create an encrypted keystore file  
3. Display the wallet information
4. Save the wallet to `.wallets/` directory

### Method 2: Generate Random Wallet

Generate a random wallet with specified signature type:

```bash
# Generate random wallet with ZK signature (recommended)
psy_user_cli wallet random --sign-type zk

# Generate random wallet with SECP256K1 signature
psy_user_cli wallet random --sign-type secp256k1
```

### Method 3: Import Existing Private Key

If you have an existing private key, you can import it:

```bash
# Get wallet info from private key
psy_user_cli wallet info --private-key <your_private_key> --sign-type zk
```

## Wallet Information

### View Wallet Details

Display information about a wallet:

```bash
# View wallet info using private key
psy_user_cli wallet info --private-key <private_key> --sign-type zk

# View wallet info using keystore
psy_user_cli wallet info --keystore-path .wallets/your_wallet.json
```

Output includes:
- Public key
- Address representation
- Signature type
- Key derivation information

## User Registration

Before using a wallet for transactions, you must register the user with the Psy network.

### Register with ZK Signature (Recommended)

```bash
# Register user with ZK signature scheme
psy_user_cli register-user --private-key <private_key> --sign-type zk

# Register using keystore file
psy_user_cli register-user --keystore-path .wallets/wallet.json --sign-type zk
```

### Register with SECP256K1 Signature

```bash
# Register user with SECP256K1 signature scheme
psy_user_cli register-user --private-key <private_key> --sign-type secp256k1

# Register using keystore file  
psy_user_cli register-user --keystore-path .wallets/wallet.json --sign-type secp256k1
```

### Registration Response

Successful registration returns:
```json
{
  "user_id": 12345,
  "public_key": "0x...",
  "transaction_hash": "0x...",
  "checkpoint_id": 67890
}
```

## Signing Transactions

### Contract Calls

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
  --keystore-path .wallets/wallet.json \
  --contract-id <contract_id> \
  --method-name <method_name> \
  --inputs "[param1, param2, ...]" \
  --sign-type zk
```

### Example: Token Operations

```bash
# Mint tokens
psy_user_cli call \
  --keystore-path .wallets/treasury.json \
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

## Keystore Management

### Keystore File Format

Psy uses encrypted keystore files for secure key storage:

```bash
# Keystore files are stored in .wallets/ directory
.wallets/
├── miner0.json
├── miner1.json
├── treasury.json
└── user_wallet.json
```

### Creating Keystore from Private Key

```bash
# Create wallet and save as keystore
psy_user_cli wallet create

# This automatically creates an encrypted keystore file
# Password protection is applied during creation
```

### Using Keystore Files

```bash
# Register user using keystore
psy_user_cli register-user \
  --keystore-path .wallets/miner0.json \
  --sign-type zk

# Execute transactions using keystore
psy_user_cli call \
  --keystore-path .wallets/miner0.json \
  --contract-id 0 \
  --method-name simple_mint \
  --inputs "[1000]" \
  --sign-type zk
```

## Multi-User Scenarios

### Multiple Wallets for Testing

Create and register multiple users for testing:

```bash
# Create multiple test users with different signature types
psy_user_cli register-user --private-key 17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a --sign-type zk
sleep 0.5
psy_user_cli register-user --private-key f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d --sign-type zk  
sleep 0.5
psy_user_cli register-user --private-key 73ae514d6f69510ad778a05128d980951d9d8c097beb022471b2f50f19c41268 --sign-type zk
```

### Cross-User Transactions

```bash
# User 0 transfers to User 1
psy_user_cli call \
  --private-key 17c975c2668ebe0ca7c87f67c6414ebb7fd664f46370a0af2a3b204c8824ac5a \
  --contract-id 0 \
  --method-name batch_simple_transfer \
  --inputs "[1, 0, 0, 0, 0, 250000000000, 0, 0, 0, 0]" \
  --sign-type zk

# User 1 claims the transfer
psy_user_cli call \
  --private-key f07f91a0bdc0df4ec763285ba0eb578cb6e7a0811c3150494ab54e56f761fc1d \
  --contract-id 0 \
  --method-name simple_claim \
  --inputs "[0]" \
  --sign-type zk
```

## Mining Wallets

### Create Mining Wallets

For mining operations, create dedicated wallets:

```bash
# Create mining wallets
psy_user_cli wallet create  # Creates .wallets/miner0.json
psy_user_cli wallet create  # Creates .wallets/miner1.json

# Register mining wallets
psy_user_cli register-user --keystore-path .wallets/miner0.json --sign-type zk
psy_user_cli register-user --keystore-path .wallets/miner1.json --sign-type zk
```

### Use Mining Wallets

```bash
# Start mining with keystore
psy_node_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner0.json \
  --recipient 3145728

# Claim mining rewards
psy_user_cli claim-rewards \
  --keystore-path .wallets/miner0.json \
  --sign-type zk \
  --limit 10000
```

## Security Best Practices

### Key Storage

1. **Backup Keystore Files**: Keep secure copies of `.wallets/` directory
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

## Troubleshooting

### Common Issues

**Keystore file not found:**
```bash
# Verify keystore path
ls -la .wallets/
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

## Advanced Usage

### Custom Circuit Integration

Future versions will support custom signature circuits:

```bash
# Placeholder for future custom circuit support
psy_user_cli register-user \
  --circuit-path ./my_custom_circuit.json \
  --private-key <private_key> \
  --sign-type custom
```

### Integration with Hardware Wallets

Planning for hardware wallet integration:

```bash
# Future hardware wallet support
psy_user_cli register-user \
  --hardware-wallet ledger \
  --derivation-path "m/44'/60'/0'/0/0" \
  --sign-type zk
```