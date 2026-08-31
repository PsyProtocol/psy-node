# Getting Started

This guide walks you through starting a complete Psy network locally for development and testing.

For the current supported service lifecycle, read [Devnet Startup, Shutdown, Restart, and Rollback](./devnet_lifecycle.md) before running any command. The lifecycle guide supersedes the manual startup and cleanup examples below.

## Prerequisites

1. Complete installation as described in [Installation](./installation.md)
2. Ensure `config.json` is properly configured
3. Have Docker and Docker Compose installed

## Quick Start

For convenience, you can use the automated script:

```bash
make run-all
```

This handles initialization and starts all components automatically.

## Required Components

A complete Psy network requires these core components:

### 1. Infrastructure Services
- **Redis**: Message queuing between edge and processor
- **Database**: ScyllaDB/LMDBX/TiKV for state storage
- **PostgreSQL**: For API services and data indexing

### 2. Coordinator Services
- **Coordinator Processor**: Manages global state and contract tree
- **Coordinator Edge**: RPC endpoint for coordinator operations

### 3. Realm Services
- **Realm Processor**: Processes user transactions and state
- **Realm Edge**: RPC endpoints for user interactions
- **Multiple Realms**: Support for horizontal scaling (realm0, realm1, realm2, realm3)

### 4. Supporting Services
- **Workers**: Generate ZK proofs for submitted jobs
- **API Services**: Block explorer and data APIs
- **Watcher**: Monitors and indexes blockchain data
- **Prove Proxy**: Assists users with local proof generation

## Manual Service Startup

### Step 1: Initialize Infrastructure

Start required databases and create directories:

```bash
# Create data directories
mkdir -p ./db/coordinator ./db/realm0 ./db/realm1 ./db/realm2 ./db/realm3

# Start Redis containers
docker-compose -f ./scripts/docker-compose.db.yml up -d

# Initialize PostgreSQL for API services
cd ./psy_services
export DATABASE_URL="postgres://postgres:password@localhost/postgres"
cargo sqlx database create
cargo sqlx migrate run
cd ..
```

### Step 2: Start Coordinator

```bash
# Start coordinator processor (manages global state)
RUST_LOG=info psy_node_cli coordinator-processor \
  --database lmdbx \
  --lmdbx-path ./db/coordinator \
  --queue-biz-key coordinator

# Start coordinator edge (RPC interface) 
RUST_LOG=info psy_node_cli coordinator-edge \
  --database lmdbx \
  --lmdbx-path ./db/coordinator \
  --queue-biz-key coordinator
```

### Step 3: Start Realms

```bash
# Start realm0 processor
RUST_LOG=info psy_node_cli realm-processor \
  --redis-uri redis://127.0.0.1:6379 \
  --database lmdbx \
  --lmdbx-path ./db/realm0 \
  --queue-biz-key realm0

# Start realm0 edge (port 8546)
RUST_LOG=info psy_node_cli realm-edge \
  --redis-uri redis://127.0.0.1:6379 \
  --database lmdbx \
  --lmdbx-path ./db/realm0 \
  --queue-biz-key realm0

# Start realm1 processor
RUST_LOG=info psy_node_cli realm-processor \
  --redis-uri redis://127.0.0.1:6379 \
  --database lmdbx \
  --lmdbx-path ./db/realm1 \
  --realm-id 1 \
  --queue-biz-key realm1

# Start realm1 edge (port 8547)
RUST_LOG=info psy_node_cli realm-edge \
  --listen-addr 0.0.0.0:8547 \
  --redis-uri redis://127.0.0.1:6379 \
  --database lmdbx \
  --lmdbx-path ./db/realm1 \
  --coordinator-addr http://127.0.0.1:8545 \
  --realm-id 1 \
  --queue-biz-key realm1
```

### Step 4: Start Workers and Services

```bash
# Start proof workers
RUST_LOG=info psy_node_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner0.json \
  --recipient 3145728

RUST_LOG=info psy_node_cli worker \
  --config ./config.json \
  --keystore-path .wallets/miner1.json \
  --recipient 1024

# Start API services
RUST_LOG=info psy_node_cli api-services

# Start watchers
RUST_LOG=info psy_node_cli watcher \
  --node-id 0 \
  --node-type coordinator \
  --redis-uri redis://127.0.0.1:6379 \
  --api-endpoint http://localhost:3000 \
  --database lmdbx \
  --lmdbx-path ./db/coordinator \
  --queue-biz-key coordinator

RUST_LOG=info psy_node_cli watcher \
  --node-id 0 \
  --node-type realm \
  --redis-uri redis://127.0.0.1:6379 \
  --api-endpoint http://localhost:3000 \
  --database lmdbx \
  --lmdbx-path ./db/realm0 \
  --queue-biz-key realm0

# Start prove proxy
RUST_LOG=info psy_user_cli prove-proxy
```

## Configuration Requirements

### config.json Setup

Ensure your `config.json` contains proper endpoint configurations:

```json
{
  "networks": {
    "localhost": {
      "coordinator_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8545"]}
      ],
      "realm_configs": [
        {"id": 0, "rpc_url": ["http://127.0.0.1:8546"]},
        {"id": 1, "rpc_url": ["http://127.0.0.1:8547"]},
        {"id": 2, "rpc_url": ["http://127.0.0.1:8548"]},
        {"id": 3, "rpc_url": ["http://127.0.0.1:8549"]}
      ],
      "prove_proxy_url": ["http://127.0.0.1:9999"],
      "api_services_url": ["http://127.0.0.1:3000"]
    }
  }
}
```

## Service Dependencies

Services must start in the correct order:

1. **Infrastructure** (Redis, databases)
2. **Coordinator** (processor, then edge)
3. **Realms** (processors, then edges)
4. **Workers** (depend on edges for job discovery)
5. **API Services** (depend on watchers for data)
6. **Watchers** (depend on edges for data access)

## Verification

Check that services are running:

```bash
# Check coordinator
curl -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'

# Check realm0
curl -X POST http://127.0.0.1:8546 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"psy_latest_checkpoint","params":[],"id":1}'

# Check API services
curl http://127.0.0.1:3000/health
```

## Cleanup

Stop all services and clean up:

```bash
# Stop Docker containers
docker-compose -f ./scripts/docker-compose.db.yml down -v

# Remove data directories
rm -rf ./db logs
```

## Next Steps

Once your network is running:

1. Register users: See [User CLI documentation](../rpc/UserCli.md)
2. Deploy contracts: Use `psy_user_cli deploy-contract`
3. Submit transactions: Use `psy_user_cli call`
4. Monitor activity: Check logs in `./logs/` directory

## Storage Options

The default setup uses LMDBX for storage. For other options:

### TiKV Setup

Replace `--database lmdbx` with:
```bash
--database tikv \
--tikv-pd-endpoints 127.0.0.1:2379 \
--tikv-namespace coordinator  # or realm0, realm1, etc.
```

### ScyllaDB Setup

Replace `--database lmdbx` with:
```bash
--database scylla \
--scylla-endpoints 127.0.0.1:9042
```

## Troubleshooting

**Services won't start**: Check that config.json is valid and all required ports are available.

**Workers not processing jobs**: Ensure workers have valid keystore files in `.wallets/` directory.

**Database connection errors**: Verify Docker containers are running with `docker ps`.

## Future Features

Several components are currently under development:

- **P2P Networking**: Peer-to-peer communication between nodes (in development)
- **Consensus Mechanism**: Byzantine fault tolerance for production networks (in development)
- **Advanced Storage**: Enhanced storage backends and optimization (in development)
- **Cross-chain Bridges**: Integration with other blockchain networks (planned)