# Getting Started

> Updated: 2026-09-03.

## Abstract

This guide starts a complete Psy network for local development. Use the automated lifecycle for normal operation; the manual commands describe the node components and their required runtime flags.

Before running any startup, shutdown, restart, or rollback command, read [Devnet Startup, Shutdown, Restart, and Rollback](./devnet_lifecycle.md) and [Devnet Launcher Reference](./devnet-launcher-reference.md).

## Table of Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Automated Startup](#2-automated-startup)
- [3. Required Components](#3-required-components)
- [4. Manual Node Startup](#4-manual-node-startup)
- [5. Endpoint Configuration](#5-endpoint-configuration)
- [6. Startup Order](#6-startup-order)
- [7. Verification](#7-verification)
- [8. Shutdown](#8-shutdown)
- [9. Implemented Network Capabilities](#9-implemented-network-capabilities)
- [10. Operating Tasks](#10-operating-tasks)
- [11. Failure Handling](#11-failure-handling)

## 1. Prerequisites

1. Complete [Installation](./installation.md).
2. Confirm `psy-genesis/config.json` contains the intended localhost configuration.
3. Install Docker and Docker Compose.
4. Follow the lifecycle preflight before starting the network.

## 2. Automated Startup

Run the supported launcher from `<repo-root>`:

```bash
make run-all
```

The launcher starts the configured database, coordinator, realms, workers, proving services, layer-one services, relayer, and selected application surfaces. The target is defined in `Makefile:60-66`.

## 3. Required Components

### 3.1 Infrastructure

- ScyllaDB stores persistent node state.
- Redis carries temporary state and queue data.
- NATS JetStream carries node messages.
- PostgreSQL belongs to the external `psy-services` repository when that service is enabled.

### 3.2 Coordinator

- The coordinator processor manages global state and contract data.
- The coordinator edge exposes the coordinator remote procedure call endpoint.

### 3.3 Realms

- Each realm processor handles realm state transitions.
- Each realm edge exposes user-facing remote procedure calls.
- Multiple realms provide horizontal scaling.

### 3.4 Supporting services

- Workers generate zero-knowledge proofs.
- The prove proxy assists user proof generation.
- API and indexer processes are supplied by the external `psy-services` repository.

## 4. Manual Node Startup

The lifecycle launcher is the supported supervisor. Use these component commands only when a targeted manual run is required.

### 4.1 Start infrastructure

```bash
bash dev/start_db.sh
```

The script starts Redis-compatible storage, NATS JetStream, and ScyllaDB. The launcher waits for ports 6379, 4222, and 9042 (`dev/locSetupV4.ts:3876-3878`).

### 4.2 Start the coordinator

```bash
RUST_LOG=info psy_node_cli start-coordinator-processor \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace coordinator

RUST_LOG=info psy_node_cli start-coordinator-edge \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace coordinator \
  --listen 0.0.0.0 \
  --port 1337
```

The coordinator flags are defined in `psy_cli/psy_node_cli/src/subcommand.rs:158-240`.

### 4.3 Start realm 0

Direct Realm startup requires a public runtime network config matching the local keys. Set `PSY_CONFIG_PATH` to that config before starting Realm processes; the standard devnet launcher generates the config and keys automatically.

```bash
export PSY_CONFIG_PATH=./local_checkpoints/realm_p2p/config.json

RUST_LOG=info psy_node_cli start-realm-processor \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace realm0 \
  --realm-id 0 \
  --p2p-identity-key ./local_checkpoints/realm_p2p/realm_0_sub_1_processor_identity.key \
  --p2p-bls-key ./local_checkpoints/realm_p2p/realm_0_sub_1_bls.key \
  --p2p-listen /ip4/0.0.0.0/tcp/41001 \
  --coordinator-api-urls http://127.0.0.1:1337

RUST_LOG=info psy_node_cli start-realm-edge \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace realm0 \
  --realm-id 0 \
  --listen 0.0.0.0 \
  --port 13380 \
  --p2p-identity-key ./local_checkpoints/realm_p2p/realm_0_sub_1_edge_identity.key \
  --p2p-listen /ip4/0.0.0.0/tcp/41101
```

### 4.4 Start realm 1

```bash
RUST_LOG=info psy_node_cli start-realm-processor \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace realm1 \
  --realm-id 1 \
  --p2p-identity-key ./local_checkpoints/realm_p2p/realm_1_sub_1_processor_identity.key \
  --p2p-bls-key ./local_checkpoints/realm_p2p/realm_1_sub_1_bls.key \
  --p2p-listen /ip4/0.0.0.0/tcp/41021 \
  --coordinator-api-urls http://127.0.0.1:1337

RUST_LOG=info psy_node_cli start-realm-edge \
  --scylla-db-url 127.0.0.1:9042 \
  --nats-jetstream-url nats://127.0.0.1:4222 \
  --redis-url redis://127.0.0.1:6379 \
  --db-namespace realm1 \
  --realm-id 1 \
  --listen 0.0.0.0 \
  --port 13390 \
  --p2p-identity-key ./local_checkpoints/realm_p2p/realm_1_sub_1_edge_identity.key \
  --p2p-listen /ip4/0.0.0.0/tcp/41121
```

Realm processor and edge flags are defined in `psy_cli/psy_node_cli/src/subcommand.rs:18-157`.

### 4.5 Start workers and the prove proxy

```bash
RUST_LOG=info psy_worker_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner0.json \
  --user 3145728

RUST_LOG=info psy_worker_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner1.json \
  --user 1024

RUST_LOG=info psy_user_cli prove-proxy
```

## 5. Endpoint Configuration

The localhost endpoint configuration is:

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
      "api_services_url": ["http://127.0.0.1:3000"]
    }
  }
}
```

These endpoint values are defined in `psy-genesis/config.json:9-41`.

## 6. Startup Order

1. Start Redis, NATS JetStream, and ScyllaDB.
2. Start the coordinator processor.
3. Start the coordinator edge.
4. Start realm processors.
5. Start realm edges.
6. Start workers and proving services.
7. Start external API and indexer services when required.

## 7. Verification

```bash
# Query the coordinator
curl -X POST http://127.0.0.1:1337 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'

# Query realm 0
curl -X POST http://127.0.0.1:13380 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'

# Query API services when enabled
curl http://127.0.0.1:3000/health
```

HTTP admission alone is not end-to-end acceptance. Follow the lifecycle guide for the required state-transition checks.

## 8. Shutdown

Stop the supervised stack without deleting state:

```bash
make shutdown
```

The shutdown target invokes the launcher teardown path (`Makefile:102-103`). Do not remove data directories manually.

## 9. Implemented Network Capabilities

- Peer-to-peer realm proposal and validator communication are implemented through the node peer-to-peer flags.
- Realm proposal voting and certification are implemented; see [Realm Peer-to-Peer Validators](./realm-p2p-validators.md).
- Cross-chain bridge processing is implemented by the relayer and bridge components.
- Runtime node storage uses ScyllaDB with Redis and NATS JetStream; the accepted flags are `--scylla-db-url`, `--redis-url`, and `--nats-jetstream-url` (`psy_cli/psy_node_cli/src/subcommand.rs:24-34,95-105,163-173,201-211`).

## 10. Operating Tasks

- Register users with `psy_user_cli register-user`.
- Deploy contracts with `psy_user_cli deploy-contract`.
- Submit transactions with `psy_user_cli call`.
- Monitor activity under `./logs/`.
- Storage backend optimization continues without changing the accepted runtime flags listed in Section 9.

## 11. Failure Handling

- **A service does not start:** confirm the selected ports are free and inspect the supervised service log.
- **A realm processor rejects startup:** provide at least one `--coordinator-api-urls` value.
- **A worker receives no jobs:** confirm its keystore, user identifier, and configured coordinator and realm endpoints.
- **A database connection fails:** confirm the infrastructure script is still running and ports 6379, 4222, and 9042 are reachable.
- **A restart or rollback is required:** stop and resume only through the lifecycle procedures.
