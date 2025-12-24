#!/bin/bash

# Configuration
VALKEY_NAME="valkey-server"
NATS_NAME="nats-server"
SCYLLA_NAME="scylla-server"

# Create directories for persistent data storage
mkdir -p ./db/scylla || true
mkdir -p ./db/redis || true

# Get absolute path for volume mounts
PARENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

# Set permissions to allow Docker access
chmod -R 777 ./db ./local_checkpoints 2>/dev/null || true

VALKEY_LOGS="./logs/valkey_logs.txt"
NATS_LOGS="./logs/nats_logs.txt"
SCYLLA_LOGS="./logs/scylla_logs.txt"

# Clean up any previous runs
docker stop "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" 2>/dev/null

# Function to handle Ctrl+C (SIGINT)
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Stopping containers (Graceful Shutdown)..."
    echo "-----------------------------------------------------"
    
    docker stop "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" 2>/dev/null
    
    echo "All services stopped."
    exit 0
}

# Trap SIGINT (Ctrl+C) and call cleanup
trap cleanup SIGINT

echo "Starting Local Dev Environment..."
echo "Logs are being saved to $VALKEY_LOGS, $NATS_LOGS, and $SCYLLA_LOGS"
echo "Data is persistent in $PARENT_DIR/db/"
echo "Press Ctrl+C to stop all services."
echo "-----------------------------------------------------"

# 1. Start Valkey with persistent data
echo "Redis data will be stored in: $PARENT_DIR/db/redis/"
echo "Note: Redis persists data to dump.rdb file when conditions are met"
docker run --rm --name "$VALKEY_NAME" \
    -p 6379:6379 \
    -v "$PARENT_DIR/db/redis:/data" \
    valkey/valkey 2>&1 \
    | tee "$VALKEY_LOGS" \
    | sed -u 's/^/[VALKEY] /' &

# 2. Start NATS
docker run --rm --name "$NATS_NAME" -p 4222:4222 nats -js 2>&1 \
    | tee "$NATS_LOGS" \
    | sed -u 's/^/[NATS]   /' &

# 3. Start Scylla in Developer Mode with 2 CPU cores and persistent data
echo "[SYSTEM] Starting ScyllaDB. This may take a minute..."
docker run --rm --name "$SCYLLA_NAME" \
    -p 9042:9042 \
    -v "$PARENT_DIR/db/scylla:/var/lib/scylla" \
    scylladb/scylla:latest \
    --smp 2 --developer-mode 1 --overprovisioned 1 \
    --experimental-features=lwt 2>&1 \
    | tee "$SCYLLA_LOGS" \
    | sed -u 's/^/[SCYLLA] /' &

# 4. Wait for Scylla to be healthy
echo "[SYSTEM] Waiting for ScyllaDB node to be UP and NORMAL..."
while ! docker exec "$SCYLLA_NAME" nodetool status | grep -q "UN"; do
    sleep 5
    echo "[SYSTEM] Still waiting for ScyllaDB..."
done
echo "-----------------------------------------------------"
echo "✅ ScyllaDB is ready!"
echo "✅ All services are running."
echo "-----------------------------------------------------"

# Wait for background jobs to finish or for Ctrl+C
wait
