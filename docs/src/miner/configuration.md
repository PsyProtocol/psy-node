# Mining Configuration

> Updated: 2026-09-03.

## Abstract

A Psy worker requires a network configuration, a wallet identity, and logging through `RUST_LOG`. Endpoint lists can contain multiple URLs for rotation and fault tolerance.

## Table of Contents

- [1. Network Configuration](#1-network-configuration)
- [2. Wallet Configuration](#2-wallet-configuration)
- [3. Endpoint Rotation](#3-endpoint-rotation)
- [4. Logging](#4-logging)
- [5. Configuration Verification](#5-configuration-verification)
- [6. Failure Handling](#6-failure-handling)

## 1. Network Configuration

A localhost worker configuration uses the coordinator, realm, and prove-proxy endpoints from `psy-genesis/config.json`:

```json
{
  "networks": {
    "localhost": {
      "users_per_realm": 1048576,
      "global_user_tree_height": 32,
      "realm_user_tree_height": 20,
      "group_realm_height": 1,
      "coordinator_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:1337"]}
      ],
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
      ],
      "prove_proxy_url": ["http://127.0.0.1:9999"],
      "fees": {
        "guta_fee": 1000000000
      }
    }
  },
  "defaultNetwork": "localhost"
}
```

The values are defined in `psy-genesis/config.json:3-60`. The public testing deployment is suspended; select localhost unless another active deployment is explicitly required.

## 2. Wallet Configuration

Create an encrypted wallet (**`--output` is required** to write keystore material):

```bash
psy_user_cli wallet create --output ./miner_wallet.json
```

Start a worker against a running localhost stack (prefer `make run-all` workers). Pass API URLs; do not invent a root `./config.json`:

```bash
psy_worker_cli worker \
  --keystore-path ./miner_wallet.json \
  --user 0 \
  --realm-api-url http://127.0.0.1:13380 \
  --coordinator-api-url http://127.0.0.1:1337
```

A private key can be supplied directly:

```bash
psy_worker_cli worker \
  --private-key <miner-private-key> \
  --user 0 \
  --realm-api-url http://127.0.0.1:13380 \
  --coordinator-api-url http://127.0.0.1:1337
```

## 3. Endpoint Rotation

Each coordinator or realm configuration accepts multiple remote procedure call URLs. Keep every URL in one list on the same network:

```json
{
  "coordinator_configs": [
    {
      "id": 0,
      "rpc_url": [
        "https://coordinator-a.example",
        "https://coordinator-b.example"
      ]
    }
  ],
  "realm_configs": [
    {
      "id": 0,
      "rpc_url": [
        "https://realm-0-a.example",
        "https://realm-0-b.example"
      ]
    }
  ]
}
```

The worker also accepts repeated `--coordinator-api-url` and `--realm-api-url` inputs and a `--url-rotation-strategy` (`psy_cli/psy_worker_cli/src/subcommand.rs:46-56`).

## 4. Logging

Configure structured Rust logging through `RUST_LOG`:

```bash
export RUST_LOG=psy_worker=info
```

The current binaries do not define `PSY_METRICS_*`, `PSY_LOG_FORMAT`, `PSY_LOG_FILE`, or `PSY_TRACK_*` environment variables.

Back up keystores and configuration regularly, keep configuration synchronized with network changes, monitor proof times and success rates, and use encrypted keystores with secure network connections.

## 5. Configuration Verification

```bash
# Test network connectivity
psy_user_cli get-latest-block-state --rpc-config ./config.json

# Test wallet access
psy_user_cli wallet info --keystore-path ./miner_wallet.json
```

Verify these invariants:

1. `defaultNetwork` exists under `networks`.
2. Coordinator and realm URLs belong to the same network.
3. The wallet opens successfully before starting long-running work.
4. The worker user identifier receives mining rewards for the intended identity.
5. The completed-job backup path is writable when reward claims are required.

## 6. Failure Handling

- **Invalid endpoint:** confirm the URL scheme, host, port, and selected network.
- **Keystore error:** confirm file permissions and supply the correct wallet password when required.
- **Network mismatch:** replace the complete endpoint set rather than mixing deployments.
- **Resource exhaustion:** reduce `--batch-size` or provide more memory and CPU capacity.
