#!/bin/bash

# Configuration
VALKEY_NAME="valkey-server"
NATS_NAME="nats-server"
SCYLLA_NAME="scylla-server"
NOSTR_NAME="nostr-relay"

VALKEY_VOLUME="psy-devnet-redis"
SCYLLA_VOLUME="psy-devnet-scylla"
SCYLLA_DATA_VOLUME="psy-devnet-scylla-data"
NATS_VOLUME="psy-devnet-nats"

# Parse --persist flag
PERSIST=false
for arg in "$@"; do
    if [ "$arg" = "--persist" ]; then
        PERSIST=true
    fi
done

# Get absolute path for repo-local logs
PARENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

# Ensure logs directory exists
mkdir -p "$PARENT_DIR/logs" || true
chmod -R 777 "$PARENT_DIR/logs" "$PARENT_DIR/local_checkpoints" 2>/dev/null || true

VALKEY_LOGS="$PARENT_DIR/logs/valkey_logs.txt"
NATS_LOGS="$PARENT_DIR/logs/nats_logs.txt"
SCYLLA_LOGS="$PARENT_DIR/logs/scylla_logs.txt"
NOSTR_LOGS="$PARENT_DIR/logs/nostr_logs.txt"

# Clean up any previous runs
docker stop -t 15 "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME" 2>/dev/null
docker rm -f "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME" 2>/dev/null || true

# Function to handle Ctrl+C (SIGINT)
cleanup() {
    echo ""
    echo "-----------------------------------------------------"
    echo "Stopping containers (Graceful Shutdown)..."
    echo "-----------------------------------------------------"

    docker stop -t 15 "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME" 2>/dev/null

    echo "All services stopped."
    if [ "$PERSIST" = "true" ]; then
        echo "Persistent data kept in Docker volumes: $VALKEY_VOLUME, $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
        echo "To delete: docker volume rm $VALKEY_VOLUME $SCYLLA_VOLUME $SCYLLA_DATA_VOLUME"
    fi
    exit 0
}

# Trap SIGINT (Ctrl+C) and SIGTERM
trap cleanup SIGINT SIGTERM

echo "Starting Local Dev Environment..."
echo "Logs are being saved to $VALKEY_LOGS, $NATS_LOGS, $SCYLLA_LOGS, and $NOSTR_LOGS"
if [ "$PERSIST" = "true" ]; then
    echo "Data is persistent in Docker volumes: $VALKEY_VOLUME, $SCYLLA_VOLUME"
else
    echo "Database containers are running without persistent volumes."
fi
echo "Press Ctrl+C to stop all services."
echo "-----------------------------------------------------"

# 1. Start Valkey
if [ "$PERSIST" = "true" ]; then
    echo "Valkey persistence: AOF enabled + RDB snapshots (Docker volume: $VALKEY_VOLUME)"
    VALKEY_VOLUME_ARGS="-v $VALKEY_VOLUME:/data"
else
    echo "Valkey persistence remains enabled inside the container, without a named volume."
    VALKEY_VOLUME_ARGS=""
fi
docker run --rm --name "$VALKEY_NAME" \
    -p 6379:6379 \
    $VALKEY_VOLUME_ARGS \
    valkey/valkey \
    valkey-server \
        --dir /data \
        --dbfilename dump.rdb \
        --appendonly yes \
        --appendfilename appendonly.aof \
        --appendfsync everysec \
        --save 60 1 \
        --save 300 10 \
        --save 900 1 2>&1 \
    | tee "$VALKEY_LOGS" \
    | sed -u 's/^/[VALKEY] /' &

# 2. Start NATS
if [ "$PERSIST" = "true" ]; then
    echo "[SYSTEM] NATS JetStream persistence: Docker volume $NATS_VOLUME mounted at /data"
    NATS_VOLUME_ARGS="-v $NATS_VOLUME:/data"
    NATS_JS_ARGS=("-js" "-sd" "/data")
else
    NATS_VOLUME_ARGS=""
    NATS_JS_ARGS=("-js")
fi
docker run --rm --name "$NATS_NAME" -p 4222:4222 $NATS_VOLUME_ARGS nats "${NATS_JS_ARGS[@]}" 2>&1 \
    | tee "$NATS_LOGS" \
    | sed -u 's/^/[NATS]   /' &

# 3. Start Scylla in Developer Mode with 2 CPU cores
echo "[SYSTEM] Starting ScyllaDB. This may take a minute..."
# Commitlog Sync Options:
# - periodic (default): Flush every commitlog-sync-period-in-ms (10000ms default)
# - batch: Flush after commitlog-sync-batch-window-in-ms (2ms default)
# For high durability, use batch mode with short window
COMMITLOG_SYNC="${SCYLLA_COMMITLOG_SYNC:-batch}"
COMMITLOG_BATCH_WINDOW="${SCYLLA_COMMITLOG_BATCH_WINDOW:-2}"
COMMITLOG_PERIOD="${SCYLLA_COMMITLOG_PERIOD:-10}"

echo "[SYSTEM] ScyllaDB Commitlog Config: sync=$COMMITLOG_SYNC, batch_window=${COMMITLOG_BATCH_WINDOW}ms, period=${COMMITLOG_PERIOD}ms"

if [ "$PERSIST" = "true" ]; then
    echo "[SYSTEM] ScyllaDB data will be stored in Docker volumes: $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
    SCYLLA_VOLUME_ARGS="-v $SCYLLA_VOLUME:/var/lib/scylla -v $SCYLLA_DATA_VOLUME:/run/udev/data"
else
    SCYLLA_VOLUME_ARGS=""
fi

docker run --rm --name "$SCYLLA_NAME" \
    --cap-add=PERFMON \
    -p 9042:9042 \
    $SCYLLA_VOLUME_ARGS \
    scylladb/scylla:latest \
    --smp 2 --developer-mode 1 --overprovisioned 1 \
    --experimental-features=lwt \
    --commitlog-sync="$COMMITLOG_SYNC" \
    --commitlog-sync-batch-window-in-ms="$COMMITLOG_BATCH_WINDOW" \
    --commitlog-sync-period-in-ms="$COMMITLOG_PERIOD" 2>&1 \
    | tee "$SCYLLA_LOGS" \
    | sed -u 's/^/[SCYLLA] /' &

# 3b. Start Nostr relay
NOSTR_DATA_DIR="$PARENT_DIR/local_checkpoints/nostr"
mkdir -p "$NOSTR_DATA_DIR" 2>/dev/null || true
cat > "$PARENT_DIR/logs/nostr_config.toml" << 'NOSTR_CONF'
[info]
name = "psy-devnet-local-nostr"

[database]
engine = "sqlite"
data_directory = "/usr/src/app/db"

[network]
address = "0.0.0.0"
port = 8081
remote_ip_header = "x-forwarded-for"

[limits]
max_event_bytes = 5242880
max_ws_message_bytes = 5242880
messages_per_sec = 20
subscriptions_per_min = 200
max_blocking_threads = 16
event_kind_allowlist = [1059]

[authorization]
nip42_auth = false
nip42_dms = false

[options]
reject_future_seconds = 1800
NOSTR_CONF

docker run --rm --name "$NOSTR_NAME" \
    -p 8081:8081 \
    -v "$NOSTR_DATA_DIR:/usr/src/app/db" \
    -v "$PARENT_DIR/logs/nostr_config.toml:/usr/src/app/config.toml" \
    scsibug/nostr-rs-relay:latest 2>&1 \
    | tee "$NOSTR_LOGS" \
    | sed -u 's/^/[NOSTR]  /' &

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
