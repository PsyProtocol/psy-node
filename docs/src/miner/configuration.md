# Mining Configuration

Configuration options and optimization settings for Psy network miners.

## Basic Configuration

### Network Configuration

Miners require a `config.json` file specifying network endpoints:

```json
{
  "networks": {
    "localhost": {
      "users_per_realm": 1048576,
      "global_user_tree_height": 24,
      "realm_user_tree_height": 20,
      "group_realm_height": 2,
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
  },
  "defaultNetwork": "localhost"
}
```

### Wallet Configuration

Miners require a keystore file for identity and reward collection:

```bash
# Create new wallet
qed_user_cli wallet create --output miner_wallet

# Or use existing private key
psy_node_cli worker \
  --config ./config.json \
  --private-key 0x1234567890abcdef... \
  --recipient 3145728
```


## Network-Specific Configuration

### Local Development

```json
{
  "networks": {
    "localhost": {
      "coordinator_configs": [{"id": 0, "rpc_url": ["http://127.0.0.1:8545"]}],
      "realm_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8546"]},
        {"id": 1, "rpc_url": ["http://127.0.0.1:8547"]}
      ],
      "prove_proxy_url": ["http://127.0.0.1:9999"]
    }
  }
}
```

### Testnet Configuration

```json
{
  "network": {
    "users_per_realm": 1048576,
    "global_user_tree_height": 24,
    "realm_user_tree_height": 20,
    "group_realm_height": 1,
    "coordinator_configs": [
      {"id": 0, "rpc_url": ["https://regnet-coordinator.psy-protocol.xyz"]}
    ],
    "realm_configs": [
      {"id": 0, "rpc_url": ["https://regnet-realm0.psy-protocol.xyz"]},
      {"id": 1, "rpc_url": ["https://regnet-realm1.psy-protocol.xyz"]}
    ],
    "prove_proxy_url": ["https://regnet-prover.psy-protocol.xyz"],
    "native_currency": "tPSY",
    "fees": {
      "guta_fee": 5000000000
    }
  }
}
```

## Advanced Configuration

### Load Balancing

Configure multiple endpoints for fault tolerance:

```json
{
  "coordinator_configs": [
    {
      "id": 0, 
      "rpc_url": [
        "https://coordinator1.psy-protocol.xyz",
        "https://coordinator2.psy-protocol.xyz",
        "https://coordinator3.psy-protocol.xyz"
      ]
    }
  ],
  "realm_configs": [
    {
      "id": 0,
      "rpc_url": [
        "https://realm0-1.psy-protocol.xyz",
        "https://realm0-2.psy-protocol.xyz"
      ]
    }
  ]
}
```



## Monitoring Configuration

### Logging Setup

```bash
# Structured logging
export RUST_LOG=psy_node=info,psy_prover=debug,psy_worker=trace
export PSY_LOG_FORMAT=json
export PSY_LOG_FILE=./logs/miner.log
```

### Metrics Configuration

```bash
# Prometheus metrics
export PSY_METRICS_ENABLED=true
export PSY_METRICS_PORT=9090
export PSY_METRICS_PATH=/metrics

# Performance tracking
export PSY_TRACK_PROOF_TIMES=true
export PSY_TRACK_MEMORY_USAGE=true
export PSY_TRACK_JOB_SUCCESS_RATE=true
```


### Docker Configuration

```yaml
# docker-compose.yml for miners
version: '3.8'
services:
  psy-miner:
    image: psy-miner:latest
    environment:
      - RUST_LOG=info
    volumes:
      - ./config.json:/app/config.json
      - ./wallets:/app/wallets
    resources:
      limits:
        memory: 16G
        cpus: '8'
      reservations:
        memory: 8G
        cpus: '4'
```

## Configuration Validation

### Validate Configuration

```bash
# Test network connectivity
psy_user_cli get-latest-block-state

# Test wallet access
psy_user_cli wallet info --keystore-path ./miner_wallet.json
```

### Common Configuration Issues

**Invalid endpoints**: Ensure URLs are accessible and use correct protocols (http/https).

**Keystore permissions**: Verify wallet files have appropriate read permissions.

**Network mismatch**: Ensure all endpoints belong to the same network environment.

**Resource constraints**: Monitor system resources to prevent memory/CPU exhaustion.

## Best Practices

1. **Separate configs per environment**: Use different config files for development, testnet, and mainnet
2. **Regular backups**: Backup keystore files and configuration regularly
3. **Monitor performance**: Track proof generation times and success rates
4. **Update regularly**: Keep configuration in sync with network updates
5. **Security first**: Use encrypted keystores and secure network connections