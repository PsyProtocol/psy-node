#!/bin/bash

# Configuration
VALKEY_NAME="valkey-server"
NATS_NAME="nats-server"
SCYLLA_NAME="scylla-server"

VALKEY_LOGS="valkey_logs.txt"
NATS_LOGS="nats_logs.txt"
SCYLLA_LOGS="scylla_logs.txt"

docker stop "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" 2>/dev/null

# Function to handle Ctrl+C (SIGINT)
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Stopping containers (Graceful Shutdown)..."
    echo "-----------------------------------------------------"
    
    # Stop containers. Because we used --rm in the run command,
    # they will be automatically removed once they stop.
    docker stop "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" 2>/dev/null
    
    echo "All services stopped."
    exit 0
}

# Trap SIGINT (Ctrl+C) and call cleanup
trap cleanup SIGINT

echo "Starting Local Dev Environment..."
echo "Logs are being saved to $VALKEY_LOGS, $NATS_LOGS, and $SCYLLA_LOGS"
echo "Press Ctrl+C to stop all services."
echo "-----------------------------------------------------"

# 1. Start Valkey
# We redirect stderr to stdout (2>&1), pipe to tee (write to file + stdout), 
# then pipe to sed to add the prefix.
docker run --rm --name "$VALKEY_NAME" -p 6379:6379 valkey/valkey 2>&1 \
    | tee "$VALKEY_LOGS" \
    | sed -u 's/^/[VALKEY] /' &

# 2. Start NATS
docker run --rm --name "$NATS_NAME" -p 4222:4222 nats -js 2>&1 \
    | tee "$NATS_LOGS" \
    | sed -u 's/^/[NATS]   /' &

# 3. Start Scylla
docker run --rm --name "$SCYLLA_NAME" -p 9042:9042 scylladb/scylla 2>&1 \
    | tee "$SCYLLA_LOGS" \
    | sed -u 's/^/[SCYLLA] /' &

# Wait implies the script stays running until the background processes finish
# or untill the user hits Ctrl+C
wait

