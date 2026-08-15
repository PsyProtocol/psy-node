#!/bin/bash
set -o pipefail

# Configuration
VALKEY_NAME="valkey-server"
NATS_NAME="nats-server"
SCYLLA_NAME="scylla-server"
SCYLLA_RF3_NAMES=("scylla-server-1" "scylla-server-2" "scylla-server-3")
SCYLLA_RF3_NETWORK="psy-devnet-scylla-rf3"
SCYLLA_RF3_IMAGE="scylladb/scylla@sha256:17496f2dd6e72056d0b0d7e2bd18bd62638872d1d80a5dd9db96ba017fd426fc"
NOSTR_NAME="nostr-relay"

VALKEY_VOLUME="psy-devnet-redis"
SCYLLA_VOLUME="psy-devnet-scylla"
SCYLLA_DATA_VOLUME="psy-devnet-scylla-data"
SCYLLA_RF3_VOLUMES=("psy-devnet-scylla-1" "psy-devnet-scylla-2" "psy-devnet-scylla-3")
NATS_VOLUME="psy-devnet-nats"

# Parse runtime flags.
PERSIST=false
SCYLLA_RF3=false
for arg in "$@"; do
    if [ "$arg" = "--persist" ]; then
        PERSIST=true
    elif [ "$arg" = "--rf3" ]; then
        SCYLLA_RF3=true
    fi
done

if [ "$SCYLLA_RF3" = "true" ]; then
    SCYLLA_CONTAINER_NAMES=("${SCYLLA_RF3_NAMES[@]}")
else
    SCYLLA_CONTAINER_NAMES=("$SCYLLA_NAME")
fi
ALL_CONTAINER_NAMES=("$VALKEY_NAME" "$NATS_NAME" "${SCYLLA_CONTAINER_NAMES[@]}" "$NOSTR_NAME")

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
docker stop -t 15 "${ALL_CONTAINER_NAMES[@]}" 2>/dev/null
docker rm -f "${ALL_CONTAINER_NAMES[@]}" 2>/dev/null || true

# Reentrancy-guarded cleanup for intentional SIGINT/SIGTERM. Does NOT exit on
# its own: it stops all containers once and sets INTENTIONAL_EXIT so the
# supervision loop below can exit 0. A second signal while already cleaning up
# is ignored (no recursive cleanup). Persistent volumes are never removed here.
CLEANUP_DONE=0
INTENTIONAL_EXIT=0
cleanup() {
    if [ "$CLEANUP_DONE" = "1" ]; then
        return
    fi
    CLEANUP_DONE=1
    INTENTIONAL_EXIT=1
    echo ""
    echo "-----------------------------------------------------"
    echo "Stopping containers (Graceful Shutdown)..."
    echo "-----------------------------------------------------"

    docker stop -t 15 "${ALL_CONTAINER_NAMES[@]}" 2>/dev/null

    echo "All services stopped."
    if [ "$PERSIST" = "true" ]; then
        if [ "$SCYLLA_RF3" = "true" ]; then
            echo "Persistent Scylla data kept in Docker volumes: ${SCYLLA_RF3_VOLUMES[*]}"
        else
            echo "Persistent Scylla data kept in Docker volumes: $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
        fi
    fi
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

RUNTIME_DOCKER_RESOURCE_ARGS=()
if [ -n "${PSY_RUNTIME_CPUSET:-}" ]; then
    RUNTIME_DOCKER_RESOURCE_ARGS+=(--cpuset-cpus "$PSY_RUNTIME_CPUSET")
fi
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
    "${RUNTIME_DOCKER_RESOURCE_ARGS[@]}" \
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
VALKEY_PID=$!

# 2. Start NATS
if [ "$PERSIST" = "true" ]; then
    echo "[SYSTEM] NATS JetStream persistence: Docker volume $NATS_VOLUME mounted at /data"
    NATS_VOLUME_ARGS="-v $NATS_VOLUME:/data"
    NATS_JS_ARGS=("-js" "-sd" "/data")
else
    NATS_VOLUME_ARGS=""
    NATS_JS_ARGS=("-js")
fi
docker run --rm --name "$NATS_NAME" -p 4222:4222 "${RUNTIME_DOCKER_RESOURCE_ARGS[@]}" $NATS_VOLUME_ARGS nats "${NATS_JS_ARGS[@]}" 2>&1 \
    | tee "$NATS_LOGS" \
    | sed -u 's/^/[NATS]   /' &
NATS_PID=$!

# 3. Start Scylla with configurable resources and LWT timeouts.
echo "[SYSTEM] Starting ScyllaDB. This may take a minute..."
# Commitlog Sync Options:
# - periodic (default): Flush every commitlog-sync-period-in-ms (10000ms default)
# - batch: Flush after commitlog-sync-batch-window-in-ms (2ms default)
# For high durability, use batch mode with short window
COMMITLOG_SYNC="${SCYLLA_COMMITLOG_SYNC:-batch}"
COMMITLOG_BATCH_WINDOW="${SCYLLA_COMMITLOG_BATCH_WINDOW:-2}"
COMMITLOG_PERIOD="${SCYLLA_COMMITLOG_PERIOD:-10}"
SCYLLA_SMP="${SCYLLA_SMP:-2}"
SCYLLA_CPUSET="${SCYLLA_CPUSET:-}"
if [ "$SCYLLA_RF3" = "true" ]; then
    SCYLLA_MEMORY="${SCYLLA_RF3_MEMORY_PER_NODE:-2G}"
    SCYLLA_SMP="${SCYLLA_RF3_SMP_PER_NODE:-1}"
else
    SCYLLA_MEMORY="${SCYLLA_MEMORY:-8G}"
fi
SCYLLA_CAS_CONTENTION_TIMEOUT_MS="${SCYLLA_CAS_CONTENTION_TIMEOUT_MS:-10000}"
SCYLLA_WRITE_REQUEST_TIMEOUT_MS="${SCYLLA_WRITE_REQUEST_TIMEOUT_MS:-10000}"

for integer_setting in SCYLLA_SMP SCYLLA_CAS_CONTENTION_TIMEOUT_MS SCYLLA_WRITE_REQUEST_TIMEOUT_MS; do
    if ! [[ "${!integer_setting}" =~ ^[1-9][0-9]*$ ]]; then
        echo "[SYSTEM] ${integer_setting} must be a positive integer, received '${!integer_setting}'"
        exit 2
    fi
done

echo "[SYSTEM] ScyllaDB Commitlog Config: sync=$COMMITLOG_SYNC, batch_window=${COMMITLOG_BATCH_WINDOW}ms, period=${COMMITLOG_PERIOD}ms"
echo "[SYSTEM] ScyllaDB Runtime Config: smp=$SCYLLA_SMP, cpuset=${SCYLLA_CPUSET:-shared}, memory=$SCYLLA_MEMORY, cas_timeout=${SCYLLA_CAS_CONTENTION_TIMEOUT_MS}ms, write_timeout=${SCYLLA_WRITE_REQUEST_TIMEOUT_MS}ms"

SCYLLA_DOCKER_RESOURCE_ARGS=()
SCYLLA_RUNTIME_ARGS=(
    --smp "$SCYLLA_SMP"
    --developer-mode 1
    --experimental-features=lwt
    --cas-contention-timeout-in-ms "$SCYLLA_CAS_CONTENTION_TIMEOUT_MS"
    --write-request-timeout-in-ms "$SCYLLA_WRITE_REQUEST_TIMEOUT_MS"
    --commitlog-sync="$COMMITLOG_SYNC"
    --commitlog-sync-batch-window-in-ms="$COMMITLOG_BATCH_WINDOW"
    --commitlog-sync-period-in-ms="$COMMITLOG_PERIOD"
)
if [ -n "$SCYLLA_CPUSET" ]; then
    SCYLLA_DOCKER_RESOURCE_ARGS+=(--cpuset-cpus "$SCYLLA_CPUSET")
    SCYLLA_RUNTIME_ARGS+=(--cpuset "$SCYLLA_CPUSET" --thread-affinity 1)
else
    SCYLLA_RUNTIME_ARGS+=(--overprovisioned 1)
fi
SCYLLA_RUNTIME_ARGS+=(--memory "$SCYLLA_MEMORY")

SCYLLA_PIDS=()
if [ "$SCYLLA_RF3" = "true" ]; then
    docker network inspect "$SCYLLA_RF3_NETWORK" >/dev/null 2>&1 \
        || docker network create "$SCYLLA_RF3_NETWORK" >/dev/null
    echo "[SYSTEM] Starting three-node Scylla RF=3 cluster on host ports 9042, 9043, 9044"
    for index in 0 1 2; do
        node_number=$((index + 1))
        node_name="${SCYLLA_RF3_NAMES[$index]}"
        host_port=$((9042 + index))
        node_log="$PARENT_DIR/logs/scylla_${node_number}_logs.txt"
        node_volume_args=()
        if [ "$PERSIST" = "true" ]; then
            node_volume_args=(-v "${SCYLLA_RF3_VOLUMES[$index]}:/var/lib/scylla")
        fi
        docker run --rm --name "$node_name" \
            --hostname "$node_name" \
            --network "$SCYLLA_RF3_NETWORK" \
            --cap-add=PERFMON \
            --security-opt seccomp=unconfined \
            -p "${host_port}:9042" \
            "${SCYLLA_DOCKER_RESOURCE_ARGS[@]}" \
            "${node_volume_args[@]}" \
            "$SCYLLA_RF3_IMAGE" \
            "${SCYLLA_RUNTIME_ARGS[@]}" \
            --reactor-backend=io_uring \
            --api-address=0.0.0.0 \
            --seeds "${SCYLLA_RF3_NAMES[0]}" 2>&1 \
            | tee "$node_log" \
            | sed -u "s/^/[SCYLLA${node_number}] /" &
        SCYLLA_PIDS+=("$!")
    done
else
    SCYLLA_VOLUME_ARGS=()
    if [ "$PERSIST" = "true" ]; then
        echo "[SYSTEM] ScyllaDB data will be stored in Docker volumes: $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
        SCYLLA_VOLUME_ARGS=(-v "$SCYLLA_VOLUME:/var/lib/scylla" -v "$SCYLLA_DATA_VOLUME:/run/udev/data")
    fi
    docker run --rm --name "$SCYLLA_NAME" \
        --cap-add=PERFMON \
        -p 9042:9042 \
        "${SCYLLA_DOCKER_RESOURCE_ARGS[@]}" \
        "${SCYLLA_VOLUME_ARGS[@]}" \
        scylladb/scylla:latest \
        "${SCYLLA_RUNTIME_ARGS[@]}" 2>&1 \
        | tee "$SCYLLA_LOGS" \
        | sed -u 's/^/[SCYLLA] /' &
    SCYLLA_PIDS+=("$!")
fi

# 3b. Start Nostr relay
NOSTR_DATA_DIR="$PARENT_DIR/local_checkpoints/nostr"
mkdir -p "$NOSTR_DATA_DIR" 2>/dev/null || true
cat > "$PARENT_DIR/logs/nostr_config.toml" << 'NOSTR_CONF'
[info]
name = "psy-devnet-local-nostr"

[database]
engine = "sqlite"
data_directory = "/usr/src/app/db"
min_conn = 4
max_conn = 16

[network]
address = "0.0.0.0"
port = 8081
remote_ip_header = "x-forwarded-for"

[limits]
max_event_bytes = 5242880
max_ws_message_bytes = 5242880
max_ws_frame_bytes = 5242880
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
    "${RUNTIME_DOCKER_RESOURCE_ARGS[@]}" \
    -v "$NOSTR_DATA_DIR:/usr/src/app/db" \
    -v "$PARENT_DIR/logs/nostr_config.toml:/usr/src/app/config.toml" \
    scsibug/nostr-rs-relay:latest 2>&1 \
    | tee "$NOSTR_LOGS" \
    | sed -u 's/^/[NOSTR]  /' &
NOSTR_PID=$!
# Tracked background service pipeline PIDs and labels (used by supervision).
SERVICE_PIDS=("$VALKEY_PID" "$NATS_PID" "${SCYLLA_PIDS[@]}" "$NOSTR_PID")
if [ "$SCYLLA_RF3" = "true" ]; then
    SERVICE_NAMES=("valkey" "nats" "scylla1" "scylla2" "scylla3" "nostr")
else
    SERVICE_NAMES=("valkey" "nats" "scylla" "nostr")
fi

# 4. Wait for Scylla to be healthy (abort if any service pipeline exits first)
echo "[SYSTEM] Waiting for ScyllaDB node to be UP and NORMAL..."
while true; do
    for spid in "${SERVICE_PIDS[@]}"; do
        if ! kill -0 "$spid" 2>/dev/null; then
            echo ""
            echo "-----------------------------------------------------"
            echo "[SYSTEM] A DB service pipeline exited before ScyllaDB became healthy; aborting startup."
            echo "[SYSTEM] Stopping containers and exiting non-zero for supervisor restart."
            echo "-----------------------------------------------------"
            trap - SIGINT SIGTERM
            docker stop -t 15 "${ALL_CONTAINER_NAMES[@]}" 2>/dev/null
            exit 1
        fi
    done
    if [ "$SCYLLA_RF3" = "true" ]; then
        if [ "$(docker exec "${SCYLLA_RF3_NAMES[0]}" nodetool status 2>/dev/null | grep -c '^UN ' || true)" = "3" ]; then
            break
        fi
    elif docker exec "$SCYLLA_NAME" nodetool status | grep -q "UN"; then
        break
    fi
    sleep 5
    echo "[SYSTEM] Still waiting for ScyllaDB..."
done
echo "-----------------------------------------------------"
echo "✅ ScyllaDB is ready!"
echo "✅ All services are running."
echo "-----------------------------------------------------"

# Supervise: wait for the first background service pipeline to exit. While
# supervising, even a clean (code 0) exit is unexpected (these are long-running
# servers). Any exit stops the remaining containers once and exits non-zero so
# the TypeScript supervisor restarts the DB group. Intentional SIGINT/SIGTERM
# (cleanup above) exits 0.
EXIT_CODE=0
if wait -n; then
    EXIT_CODE=0
else
    EXIT_CODE=$?
fi

# Disable the trap so cleanup cannot run during our own container shutdown.
trap - SIGINT SIGTERM

if [ "$INTENTIONAL_EXIT" = "1" ]; then
    # cleanup() already stopped all containers gracefully.
    exit 0
fi

# Identify which service pipeline exited (for diagnostics).
EXITED_LABEL="unknown"
for i in "${!SERVICE_PIDS[@]}"; do
    if ! kill -0 "${SERVICE_PIDS[$i]}" 2>/dev/null; then
        EXITED_LABEL="${SERVICE_NAMES[$i]}"
        break
    fi
done

echo ""
echo "-----------------------------------------------------"
echo "[SYSTEM] DB service '${EXITED_LABEL}' pipeline exited unexpectedly (code=${EXIT_CODE})."
echo "[SYSTEM] Stopping remaining containers and exiting non-zero for supervisor restart."
echo "-----------------------------------------------------"
docker stop -t 15 "${ALL_CONTAINER_NAMES[@]}" 2>/dev/null
echo "[SYSTEM] Remaining containers stopped. Persistent volumes preserved."
exit 1
