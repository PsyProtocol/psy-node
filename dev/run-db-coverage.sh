#!/usr/bin/env bash
# Run one database service and crate at a time, with independent coverage gates.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"
out="$root/target/db-coverage"
mkdir -p "$out"
exec 9>"$out/.runner.lock"
flock -n 9 || { echo 'Another database coverage run is active in this worktree.' >&2; exit 1; }
containers=()
cleanup() {
    local id
    for id in "${containers[@]}"; do
        docker logs "$id" > "$out/$id.log" 2>&1 || true
        docker rm -f "$id" >/dev/null || true
    done
    containers=()
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
    local id
    id=$(docker run -d "$@")
    containers+=("$id")
    started_id="$id"
}
port() { docker port "$1" "$2" | head -1 | sed 's/.*://'; }
ready() {
    local id="$1"; shift
    for ((attempt=0; attempt<120; attempt++)); do
        if docker exec "$id" "$@" >/dev/null 2>&1; then return; fi
        if [[ $(docker inspect -f '{{.State.Running}}' "$id") != true ]]; then
            docker logs "$id" >&2; return 1
        fi
        sleep 2
    done
    echo "Service readiness timeout: $id" >&2
    return 1
}
ready_nats() {
    python3 - "$NATS_INTEGRATION_URL" <<'PY'
import socket
import sys
import time
from urllib.parse import urlparse

endpoint = urlparse(sys.argv[1])
deadline = time.monotonic() + 120
while time.monotonic() < deadline:
    try:
        with socket.create_connection((endpoint.hostname, endpoint.port), timeout=1) as connection:
            connection.sendall(b'CONNECT {"verbose":false}\r\nPING\r\n')
            response = b""
            while time.monotonic() < deadline:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"PONG\r\n" in response:
                    sys.exit(0)
    except OSError:
        pass
    time.sleep(0.2)
sys.exit("NATS readiness timeout")
PY
}

existing=false
selected=all
for arg in "$@"; do
    case "$arg" in
        --existing) existing=true ;;
        scylla|nats|redis) selected="$arg" ;;
        *) echo "Usage: $0 [scylla|nats|redis] [--existing]" >&2; exit 2 ;;
    esac
done
modules=(scylla nats redis)
if [[ "$selected" != all ]]; then modules=("$selected"); fi
export PSY_CONFIG_PATH="${PSY_CONFIG_PATH:-$root/psy-genesis/config.json}"
export RAYON_NUM_THREADS="${RAYON_NUM_THREADS:-2}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"

{
    git rev-parse HEAD
    printf 'HEAD tree: '
    git rev-parse 'HEAD^{tree}'
    git diff HEAD --stat
    printf 'Tracked changes relative to HEAD, SHA256: '
    git diff HEAD --binary | sha256sum
    rustc --version
    cargo llvm-cov --version
} > "$out/provenance.txt"
printf '| Crate | Covered lines | Total lines | Line coverage | Gate |\n|---|---:|---:|---:|---|\n' > "$out/summary.md"
status=0
# Remove obsolete workspace binaries once; reuse newly built dependencies below.
cargo llvm-cov clean --workspace
for module in "${modules[@]}"; do
    crate="psy_node_$module"
    report_dir="$out/$module"
    mkdir -p "$report_dir"
    echo "Testing $crate separately"
    if "$existing"; then
        case "$module" in
            redis) : "${REDIS_URL:?Set isolated REDIS_URL}" ;;
            nats) : "${NATS_INTEGRATION_URL:?Set isolated NATS_INTEGRATION_URL}" ;;
            scylla) : "${PSY_TEST_SCYLLA:?Set isolated PSY_TEST_SCYLLA}" ;;
        esac
    else
        case "$module" in
            redis)
                start -p 127.0.0.1::6379 redis:7.4 redis-server --save '' --appendonly no
                export REDIS_URL="redis://127.0.0.1:$(port "$started_id" 6379)"
                ready "$started_id" redis-cli ping
                ;;
            nats)
                start --tmpfs /data:rw,size=256m -p 127.0.0.1::4222 nats:2.10 -js -sd /data
                export NATS_INTEGRATION_URL="nats://127.0.0.1:$(port "$started_id" 4222)"
                ready_nats
                ;;
            scylla)
                start --tmpfs /var/lib/scylla:rw,mode=1777,size=8g -p 127.0.0.1::9042 \
                    scylladb/scylla:2026.1.5 --smp 2 --memory 4G --overprovisioned 1 \
                    --developer-mode 1 --experimental-features=lwt \
                    --cas-contention-timeout-in-ms 10000 --write-request-timeout-in-ms 10000 \
                    --commitlog-sync=batch --commitlog-sync-batch-window-in-ms=2 \
                    --critical-disk-utilization-level 1
                export PSY_TEST_SCYLLA="127.0.0.1:$(port "$started_id" 9042)"
                ready "$started_id" cqlsh -e 'SELECT release_version FROM system.local;'
                ;;
        esac
    fi
    export REDIS_URL NATS_INTEGRATION_URL PSY_TEST_SCYLLA
    # Each crate starts with clean profiles and gets its own test/report process.
    cargo llvm-cov clean --profraw-only
    test_status=0
    timeout 30m cargo llvm-cov test --locked --no-report -p "$crate" \
        --lib --tests --no-fail-fast -- --include-ignored --test-threads=1 \
        2>&1 | tee "$report_dir/tests.log" || test_status=$?
    cargo llvm-cov report -p "$crate" --json --summary-only --output-path "$report_dir/coverage.json"
    gate_status=0
    python3 dev/check-db-coverage.py "$report_dir/coverage.json" --crate "$crate" \
        | tee "$report_dir/summary.md" || gate_status=$?
    tail -n +3 "$report_dir/summary.md" >> "$out/summary.md"
    if (( test_status != 0 || gate_status != 0 )); then status=1; fi
    # Teardown completes before the next service or crate starts.
    cleanup
done
cat "$out/summary.md"
exit "$status"
