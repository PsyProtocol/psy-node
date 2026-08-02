# Miner Setup

This guide explains how to set up and operate a miner (worker) in the Psy network to generate ZK proofs and earn rewards.

## Overview

Miners in the Psy network are responsible for generating zero-knowledge proofs for user transactions and network operations. They receive proof generation jobs from the network and get rewarded for successful proof submissions.

## Prerequisites

1. Complete node installation as described in [Node Installation](../node/installation.md)
2. Have a running Psy network with coordinator and realm nodes
3. Create a wallet for mining operations

## Installation

Follow the installation process described in [Node Installation](../node/installation.md) to install the required CLI tools.

## Miner Setup

### Step 1: Create Mining Wallet

Create a new wallet for mining operations:

```bash
# Create a new wallet
psy_user_cli wallet create
```

This creates a keystore file with:
- ETH address
- Public key hash
- Private key
- Encrypted wallet file

### Step 2: Register as Miner

Register your wallet's public key with the network:

```bash
# Get your public key information
psy_user_cli get-public-key \
    --private-key=YOUR_PRIVATE_KEY \
    --sign-type=secp256k1

# Register with the network
psy_user_cli register-user \
    --private-key=YOUR_PRIVATE_KEY \
    --sign-type=secp256k1
```

### Step 3: Configure Network Settings

Create a `config.json` file with network endpoints:

```json
{
  "networks": {
    "localhost": {
      "coordinator_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8545"]}
      ],
      "realm_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8546"]},
        {"id": 1, "rpc_url": ["http://127.0.0.1:8547"]}
      ],
      "prove_proxy_url": ["http://127.0.0.1:9999"],
      "fees": {
        "guta_fee": 5000000000
      }
    }
  }
}
```

**Note**: The public testnet (regnet-coordinator.psy-protocol.xyz, regnet-realm0.psy-protocol.xyz) is currently suspended during v2 implementation. The testnet will reopen once the v2 version is completed. For now, please use localhost development setup.

**Whitelist Feature**: The current whitelist system is a temporary security measure and will be removed in future versions to allow permissionless participation.

## Mining Operations

### Start Mining

Launch your miner to begin processing proof generation jobs:

```bash
# Start mining with keystore
psy_node_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner0.json \
  --recipient 3145728

# Or start with private key directly
psy_node_cli worker \
  --config ./config.json \
  --private-key YOUR_PRIVATE_KEY
```

### Mining Process

1. **Job Discovery**: Miner polls network nodes for available proof generation jobs
2. **Job Assignment**: Edge nodes assign jobs to miners based on priority and availability
3. **Proof Generation**: Miner generates ZK proofs for assigned transactions
4. **Proof Submission**: Completed proofs are submitted back to the network
5. **Reward Tracking**: Successful proofs are recorded for reward calculation

### Monitor Mining Activity

Check miner logs and status:

```bash
# Monitor logs (if running with output redirection)
tail -f miner.log

# Check job processing status via RPC
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'
```

## Reward Management

### Claim Rewards

Claim accumulated mining rewards:

```bash
# Claim rewards using keystore
psy_user_cli claim-rewards \
  --keystore-path .wallets/miner0.json \
  --sign-type secp256k1 \
  --limit 10000

# Or using private key directly
psy_user_cli claim-rewards \
  --private-key YOUR_PRIVATE_KEY \
  --sign-type secp256k1 \
  --limit 10000
```

Parameters:
- `--keystore-path`: Path to your encrypted wallet file
- `--sign-type`: Signature type (secp256k1 for miners)
- `--limit`: Maximum number of rewards to claim in one transaction

## Performance Optimization

### Hardware Requirements

- **CPU**: 8+ cores recommended for optimal proof generation
- **Memory**: 16GB+ RAM for handling multiple concurrent jobs
- **Storage**: Fast SSD for temporary proof data
- **Network**: Stable internet connection for job coordination


## Troubleshooting

**Miner not receiving jobs**: Ensure your wallet is registered and whitelisted with the network.

**Proof generation failures**: Check system resources and ensure sufficient RAM/CPU availability.

**Reward claiming fails**: Verify your keystore file is valid and you have accumulated claimable rewards.

**Network connection issues**: Check config.json endpoints and network connectivity.

## Production Considerations

- **Backup**: Regularly backup your keystore files
- **Monitoring**: Set up automated monitoring for miner health
- **Scaling**: Run multiple miners with different wallets for increased throughput
- **Security**: Keep private keys secure and use hardware security modules for large operations