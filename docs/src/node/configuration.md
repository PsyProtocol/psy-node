# Configuration

The Psy network uses JSON-based configuration files to manage network parameters, node settings, and deployment configurations.

## Configuration Files

### config.json - Network Configuration

The main configuration file defines network-wide parameters and multiple network environments.

#### Multi-Network Configuration

The configuration file supports multiple networks with a default network setting:

```json
{
  "networks": {
    "localhost": {
      "magic": "0x1337CF514544CF69",
      "users_per_realm": 1048576,
      // ... other localhost config
    },
    "testnet": {
      "magic": "0x2337CF514544CF69", 
      "users_per_realm": 1048576,
      // ... other testnet config
    },
    "mainnet": {
      "magic": "0x3337CF514544CF69",
      "users_per_realm": 1048576,
      // ... other mainnet config
    }
  },
  "defaultNetwork": "localhost"
}
```

Applications will use the `defaultNetwork` configuration unless explicitly switched to another network.

#### Core Network Parameters

**Tree Height Configuration:**
```json
{
  "global_user_tree_height": 24,     // Total user tree height (supports 2^24 users)
  "realm_user_tree_height": 20,     // Realm-level user tree height
  "group_realm_height": 2,          // Each group has 2^2 = 4 realms
  "users_per_realm": 1048576         // Users per realm (2^20)
}
```

**Tree Height Calculation:**
- Total realms: 2^(24-20) = 2^4 = 16 realms
- Realms per group: 2^2 = 4 realms
- Number of groups: 16/4 = 4 groups

**Fee Structure:**
```json
{
  "fees": {
    "guta_fee": 5000000000           // GUTA processing fee
  }
}
```

**Currency Configuration:**
```json
{
  "native_currency": "PSY",           // Currency symbol
  "native_currency_decimal": 9,       // Decimal places
  "native_currency_name": "PSY Token" // Full currency name
}
```

#### Node Endpoints

**Coordinator Configuration:**
```json
{
  "coordinator_configs": [
    {
      "id": 0,
      "rpc_url": ["http://127.0.0.1:8545"]
    }
  ]
}
```

**Realm Configuration:**
```json
{
  "realm_configs": [
    {
      "id": 0,
      "rpc_url": ["http://127.0.0.1:8546"]
    },
    {
      "id": 1, 
      "rpc_url": ["http://127.0.0.1:8547"]
    }
  ]
}
```

**Supporting Services:**
```json
{
  "prove_proxy_url": ["http://127.0.0.1:9999"],
  "api_services_url": ["http://127.0.0.1:3000"]
}
```

#### Genesis Configuration

**Genesis Users:**
Genesis users are pre-registered users with known public keys:

```json
{
  "genesis": {
    "users": [
      {
        "public_key_param": [/* field elements */],
        "fingerprint": [/* field elements */]
      }
    ]
  }
}
```

**Genesis Contracts:**
Pre-deployed contracts and their initial state:

```json
{
  "genesis": {
    "precompiles": [
      {
        "name": "system_contract",
        "deployer": [/* hash elements */],
        "bytecode": [/* contract bytecode */]
      }
    ]
  }
}
```

#### Security Configuration

**Whitelist (Optional):**
```json
{
  "whitelist": {
    "enabled": true,
    "secp256k1": [
      "public_key_1",
      "public_key_2"
    ]
  }
}
```


## Network Environments

### localhost
- **Purpose**: Local development and testing
- **User Registration Fee**: 0
- **Contract Deployment Fee**: 0
- **Endpoints**: Local addresses (127.0.0.1)

### testnet
- **Purpose**: Public testing environment
- **Endpoints**: Public testnet URLs

### mainnet
- **Purpose**: Production network
- **Endpoints**: Production URLs

## Key Configuration Parameters

### Tree Heights
- **Global User Tree**: 24 levels (supports 2^24 = 16.7M users)
- **Realm User Tree**: 20 levels (2^20 = 1M users per realm)
- **Total Realms**: 2^(24-20) = 16 realms
- **Group Realm Height**: 2 levels (2^2 = 4 realms per group)
- **Number of Groups**: 16/4 = 4 groups

### Performance Tuning
- **GUTA Fee**: Controls transaction batching economics
- **Realm Count**: Horizontal scaling through multiple realms
- **Worker Instances**: Parallel proof generation capacity

### Security Settings
- **Magic Number**: Network identifier for message signing
- **Whitelist**: Optional public key restrictions
- **Fee Structure**: Economic security parameters

