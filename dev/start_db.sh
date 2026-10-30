#!/bin/bash
set -o pipefail

# Container and volume identities match resolveDevnetDbNames in
# dev/locSetupPolicy.ts. Unset or empty PSY_DEVNET_NAMESPACE keeps these
# legacy names; a namespace prefixes them and must never select the legacy set.
VALKEY_NAME="valkey-server"
NATS_NAME="nats-server"
SCYLLA_NAME="scylla-server"
NOSTR_NAME="nostr-relay"

VALKEY_VOLUME="psy-devnet-redis"
SCYLLA_VOLUME="psy-devnet-scylla"
SCYLLA_DATA_VOLUME="psy-devnet-scylla-data"
NATS_VOLUME="psy-devnet-nats"

PSY_DEVNET_NAMESPACE="${PSY_DEVNET_NAMESPACE-}"
if [ -n "${PSY_DEVNET_NAMESPACE}" ]; then
    if ! [[ "${PSY_DEVNET_NAMESPACE}" =~ ^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$ ]]; then
        echo "[SYSTEM] PSY_DEVNET_NAMESPACE is invalid." >&2
        exit 2
    fi
    VALKEY_NAME="${PSY_DEVNET_NAMESPACE}-valkey-server"
    NATS_NAME="${PSY_DEVNET_NAMESPACE}-nats-server"
    SCYLLA_NAME="${PSY_DEVNET_NAMESPACE}-scylla-server"
    NOSTR_NAME="${PSY_DEVNET_NAMESPACE}-nostr-relay"
    VALKEY_VOLUME="${PSY_DEVNET_NAMESPACE}-psy-devnet-redis"
    SCYLLA_VOLUME="${PSY_DEVNET_NAMESPACE}-psy-devnet-scylla"
    SCYLLA_DATA_VOLUME="${PSY_DEVNET_NAMESPACE}-psy-devnet-scylla-data"
    NATS_VOLUME="${PSY_DEVNET_NAMESPACE}-psy-devnet-nats"
fi

# Fresh starts never adopt existing containers or volumes. --persist is reserved
# for the explicit offline rollback database command, not launcher startup.
PERSIST=false
FRESH=false
for arg in "$@"; do
    case "$arg" in
        --fresh) FRESH=true; PERSIST=true ;;
        --persist) PERSIST=true ;;
        *) echo "[SYSTEM] Unknown database startup option." >&2; exit 2 ;;
    esac
done
if [ "$FRESH" = "true" ]; then
    containers=$(docker ps -a --format '{{.Names}}') || exit 1
    volumes=$(docker volume ls --format '{{.Name}}') || exit 1
    for name in "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME" "$VALKEY_VOLUME" "$SCYLLA_VOLUME" "$SCYLLA_DATA_VOLUME" "$NATS_VOLUME"; do
        while IFS= read -r existing; do
            if [ "$existing" = "$name" ]; then
                echo "[SYSTEM] Fresh database startup refuses an existing resource: $name" >&2
                exit 1
            fi
        done <<< "$containers
$volumes"
    done
fi

# Get absolute path for repo-local logs
PARENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && cd .. && pwd)"

# Ensure logs directory exists
mkdir -p "$PARENT_DIR/logs" || exit 1

VALKEY_LOGS="$PARENT_DIR/logs/valkey_logs.txt"
NATS_LOGS="$PARENT_DIR/logs/nats_logs.txt"
SCYLLA_LOGS="$PARENT_DIR/logs/scylla_logs.txt"
NOSTR_LOGS="$PARENT_DIR/logs/nostr_logs.txt"
# Previous runs of this identity only. Never signal by port or by another
# namespace. Stop waits for the stop signal with no SIGKILL fallback; remove
# a name only after Docker reports that it is no longer running.
stop_owned_containers() {
    docker stop -t -1 "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME" 2>/dev/null || true
}

remove_stopped_owned_containers() {
    local name=""
    local running=""
    for name in "$VALKEY_NAME" "$NATS_NAME" "$SCYLLA_NAME" "$NOSTR_NAME"; do
        if ! docker container inspect "$name" >/dev/null 2>&1; then
            continue
        fi
        running="$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)"
        if [ "$running" != "false" ]; then
            echo "[SYSTEM] Refusing to remove live container ${name}." >&2
            exit 1
        fi
        docker rm "$name" >/dev/null 2>&1 || true
    done
}

SCYLLA_IO_PROPERTIES="${SCYLLA_IO_PROPERTIES:-}"
if [ -n "$SCYLLA_IO_PROPERTIES" ]; then
    if [ -L "$SCYLLA_IO_PROPERTIES" ] || [ ! -f "$SCYLLA_IO_PROPERTIES" ]; then
        echo "[SYSTEM] SCYLLA_IO_PROPERTIES must be an existing non-symlink regular file." >&2
        exit 2
    fi
    if ! SCYLLA_IO_PROPERTIES="$(realpath -e -- "$SCYLLA_IO_PROPERTIES")"; then
        echo "[SYSTEM] SCYLLA_IO_PROPERTIES must be an existing non-symlink regular file." >&2
        exit 2
    fi
    if [[ "$SCYLLA_IO_PROPERTIES" == *:* ]]; then
        echo "[SYSTEM] SCYLLA_IO_PROPERTIES absolute path must not contain ':'." >&2
        exit 2
    fi
fi

if [ "$FRESH" != "true" ]; then
    stop_owned_containers
    remove_stopped_owned_containers
fi

# Host ports stay fixed. After our own containers are gone, an occupied port
# is a hard failure: do not kill or remap the unknown listener.
host_port_listening() {
    local port="$1"
    local listeners=""
    if command -v ss >/dev/null 2>&1; then
        listeners="$(ss -H -ltn "sport = :${port}" 2>/dev/null || true)"
    elif command -v lsof >/dev/null 2>&1; then
        listeners="$(lsof -nP -iTCP:"${port}" -sTCP:LISTEN 2>/dev/null || true)"
    else
        echo "[SYSTEM] Cannot check host port ${port}: neither ss nor lsof is available." >&2
        exit 2
    fi
    [ -n "${listeners}" ]
}

for host_port in 6379 4222 9042 8081; do
    if host_port_listening "$host_port"; then
        echo "[SYSTEM] Host port ${host_port} is already in use. Refusing to start; not killing the listener." >&2
        exit 1
    fi
done

# Reentrancy-guarded cleanup for intentional SIGINT/SIGTERM. Does NOT exit on
# its own: it stops all containers once and sets INTENTIONAL_EXIT so the
# supervision loop below can exit 0. A second signal while already cleaning up
# is ignored (no recursive cleanup). Persistent volumes are never removed here.
# A negative timeout waits for the stop signal and does not fall back to SIGKILL.
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

    stop_owned_containers

    echo "All services stopped."
    if [ "$PERSIST" = "true" ]; then
        echo "Persistent data kept in Docker volumes: $VALKEY_VOLUME, $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
        echo "To delete: docker volume rm $VALKEY_VOLUME $SCYLLA_VOLUME $SCYLLA_DATA_VOLUME"
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
SCYLLA_MEMORY="${SCYLLA_MEMORY:-8G}"
SCYLLA_CAS_CONTENTION_TIMEOUT_MS="${SCYLLA_CAS_CONTENTION_TIMEOUT_MS:-10000}"
SCYLLA_WRITE_REQUEST_TIMEOUT_MS="${SCYLLA_WRITE_REQUEST_TIMEOUT_MS:-10000}"
SCYLLA_IMAGE="scylladb/scylla@sha256:43a600f5291e55f1239dd94680c95d2b8a8be11bc0d73ced062031c978c155ca"

for integer_setting in SCYLLA_SMP SCYLLA_CAS_CONTENTION_TIMEOUT_MS SCYLLA_WRITE_REQUEST_TIMEOUT_MS; do
    if ! [[ "${!integer_setting}" =~ ^[1-9][0-9]*$ ]]; then
        echo "[SYSTEM] ${integer_setting} must be a positive integer, received '${!integer_setting}'"
        exit 2
    fi
done

echo "[SYSTEM] ScyllaDB Commitlog Config: sync=$COMMITLOG_SYNC, batch_window=${COMMITLOG_BATCH_WINDOW}ms, period=${COMMITLOG_PERIOD}ms"
echo "[SYSTEM] ScyllaDB Runtime Config: smp=$SCYLLA_SMP, cpuset=${SCYLLA_CPUSET:-shared}, memory=$SCYLLA_MEMORY, cas_timeout=${SCYLLA_CAS_CONTENTION_TIMEOUT_MS}ms, write_timeout=${SCYLLA_WRITE_REQUEST_TIMEOUT_MS}ms, io_properties=${SCYLLA_IO_PROPERTIES:-unset}"

SCYLLA_VOLUME_ARGS=()
if [ "$PERSIST" = "true" ]; then
    echo "[SYSTEM] ScyllaDB data will be stored in Docker volumes: $SCYLLA_VOLUME, $SCYLLA_DATA_VOLUME"
    SCYLLA_VOLUME_ARGS=(-v "$SCYLLA_VOLUME:/var/lib/scylla" -v "$SCYLLA_DATA_VOLUME:/run/udev/data")
fi

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
if [ -n "$SCYLLA_IO_PROPERTIES" ]; then
    SCYLLA_VOLUME_ARGS+=(-v "$SCYLLA_IO_PROPERTIES:/etc/scylla.d/io_properties.yaml:ro")
    SCYLLA_RUNTIME_ARGS+=(--io-properties-file /etc/scylla.d/io_properties.yaml)
fi

docker run --rm --name "$SCYLLA_NAME" \
    --cap-add=PERFMON \
    -p 9042:9042 \
    "${SCYLLA_DOCKER_RESOURCE_ARGS[@]}" \
    "${SCYLLA_VOLUME_ARGS[@]}" \
    "$SCYLLA_IMAGE" \
    "${SCYLLA_RUNTIME_ARGS[@]}" 2>&1 \
    | tee "$SCYLLA_LOGS" \
    | sed -u 's/^/[SCYLLA] /' &
SCYLLA_PID=$!

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
    scsibug/nostr-rs-relay:latest \
    sh -c 'exec ./nostr-rs-relay --db "$APP_DATA"' 2>&1 \
    | tee "$NOSTR_LOGS" \
    | sed -u 's/^/[NOSTR]  /' &
NOSTR_PID=$!
# Tracked background service pipeline PIDs and labels (used by supervision).
SERVICE_PIDS=("$VALKEY_PID" "$NATS_PID" "$SCYLLA_PID" "$NOSTR_PID")
SERVICE_NAMES=("valkey" "nats" "scylla" "nostr")

# 4. Wait for Scylla to be healthy (abort if any service pipeline exits first)
echo "[SYSTEM] Waiting for ScyllaDB node to be UP and NORMAL..."
while true; do
    for spid in "$VALKEY_PID" "$NATS_PID" "$SCYLLA_PID" "$NOSTR_PID"; do
        if ! kill -0 "$spid" 2>/dev/null; then
            echo ""
            echo "-----------------------------------------------------"
            echo "[SYSTEM] A DB service pipeline exited before ScyllaDB became healthy; aborting startup."
            echo "[SYSTEM] Stopping containers and exiting non-zero for supervisor restart."
            echo "-----------------------------------------------------"
            trap - SIGINT SIGTERM
            stop_owned_containers
            exit 1
        fi
    done
    if docker exec "$SCYLLA_NAME" nodetool status | grep -q "UN"; then
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
# Graceful path: wait for the stop signal. Do not fall back to SIGKILL.
stop_owned_containers
echo "[SYSTEM] Remaining containers stopped. Persistent volumes preserved."
exit 1
