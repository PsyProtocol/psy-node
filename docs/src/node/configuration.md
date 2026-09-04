# Configuration

> Updated: 2026-09-03.

## Abstract

The Psy network uses JSON configuration to define network identity, tree capacity, fees, service endpoints, Genesis data, and access restrictions. The checked-in configuration contains `localhost`, `sepolia`, and `ethereum` networks.

## Table of Contents

- [1. Configuration File](#1-configuration-file)
- [2. Core Network Parameters](#2-core-network-parameters)
- [3. Service Endpoints](#3-service-endpoints)
- [4. Genesis and Security](#4-genesis-and-security)
- [5. Network Environments](#5-network-environments)
- [6. Configuration Verification](#6-configuration-verification)

## 1. Configuration File

The main `config.json` file supports multiple networks and selects one through `defaultNetwork`:

```json
{
  "networks": {
    "localhost": {
      "magic": "0x1337CF514544CF69",
      "users_per_realm": 1048576
    },
    "sepolia": {
      "magic": "0x1337CF514544C169",
      "users_per_realm": 1048576
    },
    "ethereum": {
      "magic": "0x1337CF514544C069",
      "users_per_realm": 1048576
    }
  },
  "defaultNetwork": "localhost"
}
```

Applications use `defaultNetwork` unless a network is selected explicitly. The network names and magic values are defined in `psy-genesis/config.json:3-4,71-72,139-140`.

## 2. Core Network Parameters

### 2.1 Tree capacity

```json
{
  "global_user_tree_height": 32,
  "realm_user_tree_height": 20,
  "group_realm_height": 1,
  "users_per_realm": 1048576
}
```

The resulting capacity is:

- Total realms: $2^{32-20} = 4096$.
- Realms per group: $2^1 = 2$.
- Number of groups: $4096 / 2 = 2048$.
- Users per realm: $2^{20} = 1{,}048{,}576$.

These values are defined for each configured network in `psy-genesis/config.json:5-8,73-76,141-144`.

### 2.2 Fees

```json
{
  "fees": {
    "guta_fee": 1000000000
  }
}
```

The localhost fee is defined in `psy-genesis/config.json:57-61`.

### 2.3 Currency

```json
{
  "native_currency": "0",
  "native_currency_decimal": 9,
  "native_currency_name": "Psy",
  "native_currency_symbol": "PSY"
}
```

The localhost currency fields are defined in `psy-genesis/config.json:53-56`.

## 3. Service Endpoints

### 3.1 Coordinator

```json
{
  "coordinator_configs": [
    {
      "id": 0,
      "rpc_url": ["http://127.0.0.1:1337"]
    }
  ]
}
```

### 3.2 Realms

```json
{
  "realm_configs": [
    {
      "id": 0,
      "rpc_url": [
        "http://127.0.0.1:13380",
        "http://127.0.0.1:13381"
      ]
    },
    {
      "id": 1,
      "rpc_url": [
        "http://127.0.0.1:13390",
        "http://127.0.0.1:13391"
      ]
    }
  ]
}
```

### 3.3 Supporting services

```json
{
  "prove_proxy_url": ["http://127.0.0.1:9999"],
  "api_services_url": ["http://127.0.0.1:3000"]
}
```

The complete localhost endpoint set is defined in `psy-genesis/config.json:9-43`.

## 4. Genesis and Security

### 4.1 Genesis users

Genesis users are pre-registered with public-key parameters and fingerprints:

```json
{
  "genesis": {
    "users": [
      {
        "public_key_param": ["<field-element>"],
        "fingerprint": ["<field-element>"]
      }
    ]
  }
}
```

### 4.2 Genesis contracts

Genesis contracts contain pre-deployed bytecode and initial state:

```json
{
  "genesis": {
    "precompiles": [
      {
        "name": "system_contract",
        "deployer": ["<hash-element>"],
        "bytecode": ["<contract-bytecode>"]
      }
    ]
  }
}
```

### 4.3 Whitelist

A network configuration can restrict accepted secp256k1 public keys:

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

## 5. Network Environments

| Network | Purpose | Endpoint source |
|---|---|---|
| `localhost` | Local development and testing | Loopback addresses in `psy-genesis/config.json:9-69` |
| `sepolia` | Ethereum Sepolia-backed deployment configuration | `psy-genesis/config.json:71-137` |
| `ethereum` | Ethereum-backed deployment configuration | `psy-genesis/config.json:139-204` |

The public testing deployment is suspended. The configured network selectors remain `localhost`, `sepolia`, and `ethereum`.

## 6. Configuration Verification

1. Confirm `defaultNetwork` names an entry under `networks`.
2. Confirm every endpoint for the selected network uses the intended deployment.
3. Confirm the magic value matches the selected network.
4. Confirm tree heights and fees match the deployment configuration.
5. Reject mixed endpoint sets that combine different networks.
