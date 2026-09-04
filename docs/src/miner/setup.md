# Miner Setup

> Updated: 2026-09-03.

## Abstract

This guide configures and runs a Psy proof worker, monitors its job processing, and claims mining rewards from the worker's completed-job backup.

## Table of Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Wallet and Registration](#2-wallet-and-registration)
- [3. Network Configuration](#3-network-configuration)
- [4. Mining Operations](#4-mining-operations)
- [5. Reward Claims](#5-reward-claims)
- [6. Performance and Security](#6-performance-and-security)
- [7. Failure Handling](#7-failure-handling)

## 1. Prerequisites

1. Complete [Node Installation](../node/installation.md).
2. Start a Psy network with coordinator and realm nodes.
3. Create a wallet for mining operations.

## 2. Wallet and Registration

### 2.1 Create a wallet

```bash
psy_user_cli wallet create
```

The wallet command creates encrypted key material and reports its public-key hash.

The wallet contains an Ethereum address, public-key hash, private key, and encrypted wallet file.

### 2.2 Inspect a worker public key

```bash
psy_worker_cli get-public-key --private-key YOUR_PRIVATE_KEY
```

### 2.3 Register the wallet

```bash
psy_user_cli register-user \
  --rpc-config ./config.json \
  --private-key YOUR_PRIVATE_KEY
```

## 3. Network Configuration

Create `config.json` with the network endpoints used by the worker:

```json
{
  "networks": {
    "localhost": {
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

The localhost values are defined in `psy-genesis/config.json:3-60`. The public testing deployment is suspended; use localhost unless another active deployment is explicitly selected.

The whitelist is a temporary security measure intended to be removed when permissionless participation is enabled.

## 4. Mining Operations

### 4.1 Start a worker

Use a keystore and retain the completed-job backup required for reward claims:

```bash
psy_worker_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner0.json \
  --user 3145728 \
  --completed-jobs-log-file worker.backup
```

A private key can be supplied directly:

```bash
psy_worker_cli worker \
  --config ./config.json \
  --private-key YOUR_PRIVATE_KEY \
  --user 3145728 \
  --completed-jobs-log-file worker.backup
```

The worker inputs are defined in `psy_cli/psy_worker_cli/src/subcommand.rs:20-57`.

### 4.2 Job flow

1. The worker polls coordinator and realm edges for proof jobs.
2. An edge assigns available work.
3. The worker generates the requested zero-knowledge proof.
4. The worker submits the completed proof.
5. The worker records the completed job in `worker.backup`.

### 4.3 Monitor activity

```bash
# Monitor redirected worker output
tail -f miner.log

# Query the coordinator checkpoint
curl -X POST http://127.0.0.1:1337 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'
```

## 5. Reward Claims

Claim rewards with the wallet source used by the worker:

```bash
psy_user_cli claim-rewards \
  --rpc-config ./config.json \
  --keystore-path .wallets/miner0.json \
  --jobs-file worker.backup
```

Or use a private key:

```bash
psy_user_cli claim-rewards \
  --rpc-config ./config.json \
  --private-key YOUR_PRIVATE_KEY \
  --jobs-file worker.backup
```

| Parameter | Meaning |
|---|---|
| `--rpc-config` | Network configuration path; defaults to `config.json` |
| `--keystore-path` or `--private-key` | Wallet source matching the worker identity |
| `--jobs-file` | Completed-job backup written by `--completed-jobs-log-file` |

The claim inputs are defined in `client_prover/psy_cli/psy_user_cli/src/subcommand/args.rs:536-544`.

## 6. Performance and Security

- Use at least 8 CPU cores and 16 GB of memory for concurrent proof work.
- Use fast storage for proof data and backups.
- Maintain stable connectivity to every configured edge.
- Back up encrypted keystores and completed-job files.
- Keep private keys out of logs and shared configuration.
- Run separate worker identities when scaling across multiple processes.

For increased throughput, run multiple workers with different wallets and use automated health monitoring. Hardware security modules are appropriate for high-value mining operations.

## 7. Failure Handling

- **No jobs:** confirm the worker identity is accepted and the coordinator and realm endpoints are reachable.
- **Proof failure:** inspect worker output and confirm sufficient memory and CPU capacity.
- **Reward claim failure:** confirm the keystore or private key matches the worker and `worker.backup` contains completed jobs.
- **Connection failure:** confirm the selected network and endpoint set match.
